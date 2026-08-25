"""Adjudication protocol and the named ablation registry: the human-label path
to RUA refuses shortcuts, and the ablation vocabulary is fixed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pqpatch.eval.ablations import ABLATIONS, get_ablation
from pqpatch.eval.adjudicate import (
    AdjudicationError,
    pending,
    pending_proposals,
    proposal_id,
    record_labels,
    record_proposal_labels,
    trap_outcomes,
)
from pqpatch.eval.metrics import residual_unsafe_accept_rate
from pqpatch.model import Layer


def _run_dir(tmp_path: Path) -> Path:
    sites = tmp_path / "run" / "sites"
    sites.mkdir(parents=True)

    def write(trap_id: str, **fields: Any) -> None:
        rec = {"trap_id": trap_id, "ground_truth_unsafe": True, **fields}
        (sites / f"{trap_id}__seed0.json").write_text(json.dumps(rec))

    write("t-caught", full_status="reject", needs_adjudication=False,
          full_rejected_rule_id="PQ-RAND-03")
    write("t-accept-safe", full_status="accept", needs_adjudication=True)
    write("t-accept-unsafe", full_status="accept", needs_adjudication=True)
    return tmp_path / "run"


def test_rua_refused_until_every_accept_is_labeled(tmp_path: Path) -> None:
    run = _run_dir(tmp_path)
    assert sorted(pending(run)) == ["t-accept-safe", "t-accept-unsafe"]
    with pytest.raises(AdjudicationError, match="await adjudication"):
        trap_outcomes(run)


def test_labels_flow_into_rua(tmp_path: Path) -> None:
    run = _run_dir(tmp_path)
    record_labels(run, {"t-accept-safe": False, "t-accept-unsafe": True}, annotator="A")
    assert pending(run) == []

    outcomes = trap_outcomes(run)
    rua = residual_unsafe_accept_rate(outcomes)
    # one unsafe accept out of three scored traps
    assert rua.successes == 1
    assert rua.n == 3


def test_disagreement_resolves_unsafe_and_is_preserved(tmp_path: Path) -> None:
    run = _run_dir(tmp_path)
    record_labels(run, {"t-accept-safe": False, "t-accept-unsafe": True}, annotator="A")
    record_labels(run, {"t-accept-safe": True}, annotator="B")  # disagrees with A

    outcomes = {o.site_id: o for o in trap_outcomes(run)}
    assert outcomes["t-accept-safe"].ground_truth_unsafe is True  # conservative
    stored = json.loads((run / "adjudications.json").read_text())
    assert len(stored["t-accept-safe"]["labels"]) == 2  # disagreement retained


def test_protocol_refusals(tmp_path: Path) -> None:
    run = _run_dir(tmp_path)
    with pytest.raises(AdjudicationError, match="no accepted proposal"):
        record_labels(run, {"t-caught": True}, annotator="A")  # was rejected, not accepted
    record_labels(run, {"t-accept-safe": False}, annotator="A")
    with pytest.raises(AdjudicationError, match="already labeled"):
        record_labels(run, {"t-accept-safe": False}, annotator="A")  # no relabeling


def test_proposal_ids_are_stable_and_separate_draws() -> None:
    manifest = {"model_version": "model-a", "prompt_version": "v2"}
    base = {"trap_id": "trap", "seed": 0, "response_hash": "abc"}
    assert proposal_id(base, manifest) == proposal_id(dict(reversed(list(base.items()))), manifest)
    assert proposal_id(base, manifest) != proposal_id({**base, "seed": 1}, manifest)
    assert proposal_id(base, manifest) != proposal_id(
        base, {**manifest, "model_version": "model-b"}
    )


def test_status_neutral_labels_include_symbolic_rejections(tmp_path: Path) -> None:
    run = _run_dir(tmp_path)
    symbolic = {
        "trap_id": "t-symbolic",
        "seed": 0,
        "response_hash": "symbolic-response",
        "full_status": "reject",
        "l3_only_status": "accept",
        "needs_adjudication": False,
    }
    (run / "sites" / "t-symbolic__seed0.json").write_text(json.dumps(symbolic))
    pid = proposal_id(symbolic)

    assert pid in pending_proposals(run)
    record_proposal_labels(run, {pid: "unsafe"}, annotator="expert-a")
    assert pid not in pending_proposals(run)
    stored = json.loads((run / "proposal_labels.json").read_text())
    assert stored["proposals"][pid]["labels"][0]["label"] == "unsafe"
    assert stored["proposals"][pid]["trap_id"] == "t-symbolic"


def test_repeated_draws_refuse_ambiguous_legacy_label_key(tmp_path: Path) -> None:
    run = _run_dir(tmp_path)
    first = {
        "trap_id": "t-repeat",
        "seed": 0,
        "response_hash": "response-0",
        "full_status": "accept",
        "l3_only_status": "accept",
        "needs_adjudication": True,
    }
    second = {**first, "seed": 1, "response_hash": "response-1"}
    (run / "sites" / "t-repeat__seed0.json").write_text(json.dumps(first))
    (run / "sites" / "t-repeat__seed1.json").write_text(json.dumps(second))

    with pytest.raises(AdjudicationError, match="ambiguous legacy trap id"):
        record_proposal_labels(run, {"t-repeat": "unsafe"}, annotator="expert-a")

    first_id, second_id = proposal_id(first), proposal_id(second)
    record_proposal_labels(
        run,
        {first_id: "unsafe", second_id: "safe"},
        annotator="expert-a",
    )
    assert first_id != second_id


def test_ablation_registry_shape() -> None:
    assert set(ABLATIONS) == {
        "full", "remove-l2", "l3-only", "no-repair", "generic-feedback", "stock-l1",
    }
    assert get_ablation("remove-l2").enabled_layers == frozenset(
        {Layer.L1_SYNTACTIC, Layer.L3_BUILD}
    )
    assert get_ablation("no-repair").k == 1
    assert get_ablation("stock-l1").l1_mode == "stock"
    with pytest.raises(KeyError, match="unknown ablation"):
        get_ablation("remove-everything")


def test_split_vote_is_unsafe_under_any_but_safe_under_majority(tmp_path: Path) -> None:
    """The two rules disagree on a single dissent, and the default is majority.

    Nine of twenty unsafe-accepts on the real grids rest on one dissenting
    judge, so this is the difference between a 31.7% and a 17.5% pooled RUA --
    not an edge case.
    """
    from pqpatch.eval.adjudicate import _adjudicated_unsafe

    one_of_three = {"labels": [
        {"annotator": "a", "unsafe": True},
        {"annotator": "b", "unsafe": False},
        {"annotator": "c", "unsafe": False},
    ]}
    assert _adjudicated_unsafe(one_of_three, rule="any") is True
    assert _adjudicated_unsafe(one_of_three) is False  # majority is the default

    two_of_three = {"labels": [
        {"annotator": "a", "unsafe": True},
        {"annotator": "b", "unsafe": True},
        {"annotator": "c", "unsafe": False},
    ]}
    assert _adjudicated_unsafe(two_of_three) is True

    tie = {"labels": [
        {"annotator": "a", "unsafe": True},
        {"annotator": "b", "unsafe": False},
    ]}
    assert _adjudicated_unsafe(tie) is True  # ties resolve unsafe


def test_unknown_adjudication_rule_is_refused() -> None:
    from pqpatch.eval.adjudicate import AdjudicationError, _adjudicated_unsafe

    with pytest.raises(AdjudicationError, match="unknown adjudication rule"):
        _adjudicated_unsafe({"labels": [{"annotator": "a", "unsafe": True}]}, rule="plurality")
