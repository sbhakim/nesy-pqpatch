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
    record_labels,
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
