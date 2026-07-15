"""Run-manifest reader and funnel math (eval/tables.py) and the config-hash
identity (eval/run.py). Pure logic over synthetic records -- no backend,
network, or toolchain -- so the analytical code that produces the paper's
numbers is pinned independently of any live run."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pqpatch.eval.run import config_hash
from pqpatch.eval.tables import funnel, load_run, load_runs
from pqpatch.model import Layer


def _rec(*, uc: str, status: str, fa_status: str, fa_layer: int | None) -> dict[str, Any]:
    """A synthetic per-site record: `fa_*` describe its first-attempt event."""
    events = [
        {"attempt": 1, "layer": fa_layer, "status": fa_status, "rule_id": None, "timings_ms": {}}
    ]
    return {"usage_class": uc, "status": status, "seed": 0, "trace": {"events": events}}


def test_funnel_counts_first_attempt_survival() -> None:
    records = [
        # accepted on the first attempt: survives every layer
        _rec(uc="sign", status="accept", fa_status="accept", fa_layer=None),
        # rejected at L1 first attempt, but repaired to an accept: counts for
        # accept_final only, not for survive_l1 or accept_first
        _rec(uc="sign", status="accept", fa_status="reject", fa_layer=1),
        # rejected at L2 first attempt, then escalated: survives L1, not L2
        _rec(uc="kem", status="escalate", fa_status="reject", fa_layer=2),
        # rejected at L1 first attempt, escalated
        _rec(uc="kem", status="escalate", fa_status="reject", fa_layer=1),
        # an error record is excluded from the denominator entirely
        {"usage_class": "envelope", "status": "error", "seed": 0},
    ]
    fn = funnel(records)
    # denominator excludes the error record -> n = 4
    assert fn["survive_l1"].n == 4
    assert fn["survive_l1"].successes == 2  # the accept-first and the L2-rejected one
    assert fn["survive_l2"].successes == 1  # only the accept-first survives L2
    assert fn["accept_first"].successes == 1
    assert fn["accept_final"].successes == 2  # both accepts (one direct, one repaired)


def test_funnel_rejects_empty() -> None:
    with pytest.raises(ValueError, match="no non-error records"):
        funnel([{"usage_class": "sign", "status": "error", "seed": 0}])


def test_config_hash_is_stable_and_order_independent() -> None:
    base = dict(
        backend_id="backend-a",
        model_version="deepseek-v4-pro",
        k=3,
        enabled_layers=frozenset({Layer.L1_SYNTACTIC, Layer.L2_DATAFLOW, Layer.L3_BUILD}),
        corpus_id="tier2/file-signing-cli",
        prompt_version="v1",
        ruleset_version="rules-v1.0",
        policy_version="v1",
    )
    h1 = config_hash(seeds=[0, 1, 2], **base)
    h2 = config_hash(seeds=[2, 1, 0], **base)  # order must not matter
    assert h1 == h2
    # a different k is a different configuration -> different directory
    assert config_hash(seeds=[0], **{**base, "k": 1}) != config_hash(seeds=[0], **base)


def test_load_run_and_load_runs_roundtrip(tmp_path: Path) -> None:
    run_dir = tmp_path / "abc123"
    (run_dir / "sites").mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps({"config_hash": "abc123", "app": "x"}))
    rec = _rec(uc="sign", status="accept", fa_status="accept", fa_layer=None)
    (run_dir / "sites" / "s1.json").write_text(json.dumps(rec))

    run = load_run(run_dir)
    assert run["manifest"]["config_hash"] == "abc123"
    assert len(run["records"]) == 1

    runs = load_runs(tmp_path)
    assert len(runs) == 1
    # a stray non-run directory (no manifest) is ignored
    (tmp_path / "not-a-run").mkdir()
    assert len(load_runs(tmp_path)) == 1
