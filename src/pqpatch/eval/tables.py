"""LaTeX/summary table generation from run manifests.

Every number in the paper regenerates from ``runs/``; nothing is typed by hand.
With no runs present this exits nonzero -- no row is ever emitted without a
backing manifest (eval/run.py writes them). Given runs, it computes the
capability funnel (first-attempt survival by verifier layer) and end-to-end
acceptance, each with the same Wilson intervals the manuscript commits to.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from pqpatch.eval.metrics import Estimate, wilson_ci

_RUNS = Path(__file__).resolve().parents[3] / "runs"

# Trace events store the verifier layer as its IntEnum value (1..4) or null.
_L1, _L2 = 1, 2


def load_run(run_dir: Path) -> dict[str, Any]:
    """Load one run's manifest and per-site records."""
    manifest = json.loads((run_dir / "manifest.json").read_text())
    records = [json.loads(p.read_text()) for p in sorted((run_dir / "sites").glob("*.json"))]
    return {"manifest": manifest, "records": records}


def load_runs(runs_dir: Path = _RUNS) -> list[dict[str, Any]]:
    """Load every run directory that carries a manifest."""
    if not runs_dir.exists():
        return []
    return [
        load_run(p)
        for p in sorted(runs_dir.iterdir())
        if p.is_dir() and (p / "manifest.json").exists()
    ]


def _first_attempt_event(record: dict[str, Any]) -> dict[str, Any] | None:
    events = record.get("trace", {}).get("events", [])
    for event in events:
        if isinstance(event, dict) and event.get("attempt") == 1:
            return event
    return None


def funnel(records: list[dict[str, Any]]) -> dict[str, Estimate]:
    """First-attempt survival by layer plus end-to-end acceptance. Error records
    (backend/network failures) are excluded from the denominator."""
    scored = [r for r in records if r.get("status") != "error"]
    n = len(scored)
    if n == 0:
        raise ValueError("no non-error records to compute a funnel over")

    survived_l1 = survived_l2 = accepted_first = accepted_final = 0
    for rec in scored:
        if rec.get("status") == "accept":
            accepted_final += 1
        event = _first_attempt_event(rec)
        if event is None:
            continue
        if event.get("status") == "accept":
            survived_l1 += 1
            survived_l2 += 1
            accepted_first += 1
            continue
        layer = event.get("layer")
        if layer != _L1:
            survived_l1 += 1
        if layer not in (_L1, _L2):
            survived_l2 += 1

    return {
        "survive_l1": wilson_ci(survived_l1, n),
        "survive_l2": wilson_ci(survived_l2, n),
        "accept_first": wilson_ci(accepted_first, n),
        "accept_final": wilson_ci(accepted_final, n),
    }


def _pct(est: Estimate) -> str:
    return f"{100 * est.point:.1f}\\% [{100 * est.ci_low:.1f}, {100 * est.ci_high:.1f}]"


def _emit_run(run: dict[str, Any]) -> None:
    man = run["manifest"]
    records = run["records"]
    n_err = sum(1 for r in records if r.get("status") == "error")
    print(
        f"\n=== run {man['config_hash']} :: {man['backend_id']} / {man['model_version']} "
        f"on {man['app']} (k={man['k']}, seeds={man['seeds']}) ==="
    )
    print(f"records: {len(records)}  ({n_err} error)")

    fn = funnel(records)
    print("capability funnel (first attempt), Wilson 95%:")
    print(f"  survive L1     : {_pct(fn['survive_l1'])}  (n={fn['survive_l1'].n})")
    print(f"  survive L2     : {_pct(fn['survive_l2'])}")
    print(f"  accept (1st)   : {_pct(fn['accept_first'])}")
    print(f"  accept (final) : {_pct(fn['accept_final'])}  <- after repair loop")

    by_class: dict[str, list[bool]] = {}
    for rec in records:
        if rec.get("status") == "error":
            continue
        by_class.setdefault(rec["usage_class"], []).append(rec.get("status") == "accept")
    print("per usage class (final acceptance):")
    for uc in sorted(by_class):
        flags = by_class[uc]
        est = wilson_ci(sum(flags), len(flags))
        print(f"  {uc:9s}: {_pct(est)}  (n={len(flags)})")

    row = " & ".join(
        f"{100 * fn[k].point:.1f}"
        for k in ("survive_l1", "survive_l2", "accept_first", "accept_final")
    )
    print(f"LaTeX funnel row: {man['backend_id']} & {row} \\\\")


def main() -> int:
    runs = load_runs()
    if not runs:
        print(
            "NOT READY: runs/ contains no experiment output. Tables are generated "
            "exclusively from run manifests; execute a configuration first with "
            "eval.run.run_config. See docs/STATUS.md."
        )
        return 1
    for run in runs:
        _emit_run(run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
