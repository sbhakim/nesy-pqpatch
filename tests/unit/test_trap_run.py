"""Trap-run scoring logic: site picking (eval/trap_run.py) and the mechanical
suite summary (eval/tables.trap_summary). Pure logic over synthetic values --
no backend, network, or Semgrep -- so the RQ2 arithmetic is pinned
independently of any live run."""

from __future__ import annotations

from typing import Any

import pytest

from pqpatch.eval.tables import trap_summary
from pqpatch.eval.trap_run import TrapSiteError, _pick_site
from pqpatch.eval.traps import load_trap
from pqpatch.model import Site, UsageClass


def _site(line: int, uc: UsageClass) -> Site:
    return Site(
        site_id=f"site-{line:04d}",
        repo="trap",
        file_path="X.java",
        line=line,
        usage_class=uc,
        matched_symbol="X.getInstance",
        detector_rule_id="pq-detect-signature",
    )


def _spec(tmp_path, usage_class: str = "kem"):
    import yaml

    data = {
        "trap_id": "t-pick",
        "usage_class": usage_class,
        "unsafe_class": "U6",
        "split": "dev",
        "provenance": "taxonomy",
        "unsafe_patch_compiles": True,
        "caught_by_l3_alone": False,
        "annotator_labels": [
            {"annotator": "A", "unsafe": True},
            {"annotator": "B", "unsafe": True},
        ],
        "ground_truth_unsafe": True,
        "scenario_path": "dev/t-pick/",
        "rationale": "r",
    }
    path = tmp_path / "t.yaml"
    path.write_text(yaml.safe_dump(data))
    return load_trap(path)


def test_pick_site_prefers_declared_class_first_by_line(tmp_path) -> None:
    spec = _spec(tmp_path, usage_class="kem")
    sites = [_site(30, UsageClass.KEM), _site(10, UsageClass.SIGN), _site(20, UsageClass.KEM)]
    assert _pick_site(spec, sites).line == 20


def test_pick_site_raises_loudly_without_a_class_match(tmp_path) -> None:
    spec = _spec(tmp_path, usage_class="envelope")
    with pytest.raises(TrapSiteError, match="no detected site of class 'envelope'"):
        _pick_site(spec, [_site(10, UsageClass.SIGN)])


def _rec(
    *,
    full: str,
    l3: str,
    bait: bool = False,
    excl: bool = False,
    layer: str | None = None,
) -> dict[str, Any]:
    return {
        "trap_id": "t",
        "full_status": full,
        "l3_only_status": l3,
        "bait_taken_confirmed": bait,
        "symbolic_exclusive": excl,
        "needs_adjudication": full == "accept",
        "full_catch_layer": layer,
        "claimed_primitive": "ML-KEM-768",
    }


def test_trap_summary_counts() -> None:
    records = [
        # caught at L1, L3-only would have accepted it: symbolic-exclusive + bait
        _rec(full="reject", l3="accept", bait=True, excl=True, layer="L1_SYNTACTIC"),
        # caught at L2, L3-only also rejects (does not compile): not exclusive
        _rec(full="reject", l3="reject", bait=True, layer="L2_DATAFLOW"),
        # accepted by both gates: joins the adjudication queue
        _rec(full="accept", l3="accept"),
        # an error record is excluded from the denominator
        {"trap_id": "e", "full_status": "error", "l3_only_status": "error"},
    ]
    ts = trap_summary(records)
    assert ts["n"] == 3
    assert ts["n_error"] == 1
    assert ts["caught"].successes == 2
    assert ts["bait_confirmed"].successes == 2
    assert ts["l3_only_accept"].successes == 2
    assert ts["symbolic_exclusive"].successes == 1
    assert ts["needs_adjudication"] == 1
    assert ts["catch_by_layer"] == {"L1_SYNTACTIC": 1, "L2_DATAFLOW": 1}


def test_trap_summary_rejects_all_error() -> None:
    with pytest.raises(ValueError, match="no non-error trap records"):
        trap_summary([{"full_status": "error"}])
