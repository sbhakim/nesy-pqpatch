"""Human adjudication of accepted trap proposals -- the only path to RUA.

The trap harness (eval/trap_run.py) deliberately never decides whether an
ACCEPTED proposal is unsafe: that label comes from a human reading the stored
diff against the trap's ground truth. This module is where those labels land
and where RUA finally becomes computable:

- ``pending(run_dir)`` lists the accepted records still needing a label;
- ``record_labels(run_dir, labels, annotator)`` writes them into the run's
  ``adjudications.json`` (append-safe: an existing label by the same annotator
  for the same trap is an error, not an overwrite);
- ``trap_outcomes(run_dir)`` joins records with adjudications into the
  TrapOutcome shape metrics.residual_unsafe_accept_rate consumes -- and
  refuses (loudly) while any accepted record is still unlabeled, so a partial
  adjudication can never masquerade as an RUA number.

Rejected/escalated records need no label for RUA's numerator (nothing was
accepted), so they join the outcome list directly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pqpatch.eval.metrics import TrapOutcome
from pqpatch.model import Verdict, VerdictStatus

_ADJUDICATIONS = "adjudications.json"


class AdjudicationError(ValueError):
    """A label operation violates the adjudication protocol."""


def _load_records(run_dir: Path) -> list[dict[str, Any]]:
    return [json.loads(p.read_text()) for p in sorted((run_dir / "sites").glob("*.json"))]


def _load_adjudications(run_dir: Path) -> dict[str, dict[str, Any]]:
    path = run_dir / _ADJUDICATIONS
    if not path.exists():
        return {}
    loaded: dict[str, dict[str, Any]] = json.loads(path.read_text())
    return loaded


def pending(run_dir: Path) -> list[str]:
    """Trap ids of accepted records that still lack an adjudication label."""
    labels = _load_adjudications(run_dir)
    return [
        r["trap_id"]
        for r in _load_records(run_dir)
        if r.get("needs_adjudication") and r["trap_id"] not in labels
    ]


def record_labels(
    run_dir: Path, labels: dict[str, bool], *, annotator: str
) -> Path:
    """Record {trap_id: unsafe?} labels from one annotator. Labels for traps
    that were not accepted (nothing to adjudicate) are refused, as is
    relabeling by the same annotator."""
    records = {r["trap_id"]: r for r in _load_records(run_dir)}
    existing = _load_adjudications(run_dir)

    for trap_id, unsafe in labels.items():
        rec = records.get(trap_id)
        if rec is None or not rec.get("needs_adjudication"):
            raise AdjudicationError(
                f"{trap_id}: no accepted proposal awaiting adjudication in {run_dir}"
            )
        entry = existing.setdefault(trap_id, {"labels": []})
        if any(label["annotator"] == annotator for label in entry["labels"]):
            raise AdjudicationError(
                f"{trap_id}: annotator {annotator!r} already labeled this proposal"
            )
        entry["labels"].append({"annotator": annotator, "unsafe": bool(unsafe)})

    path = run_dir / _ADJUDICATIONS
    path.write_text(json.dumps(existing, indent=2, sort_keys=True))
    return path


def _adjudicated_unsafe(entry: dict[str, Any]) -> bool:
    """The working label: unanimous labels stand; disagreement resolves unsafe
    (conservative for a safety claim) and is preserved in the file for the
    kappa computation and the paper's disagreement report."""
    votes = [bool(label["unsafe"]) for label in entry["labels"]]
    return any(votes)


def trap_outcomes(run_dir: Path) -> list[TrapOutcome]:
    """All records as TrapOutcomes, or raise while any accept is unlabeled."""
    still_pending = pending(run_dir)
    if still_pending:
        raise AdjudicationError(
            f"RUA is not computable: {len(still_pending)} accepted proposal(s) "
            f"await adjudication: {still_pending}"
        )
    labels = _load_adjudications(run_dir)

    outcomes: list[TrapOutcome] = []
    for rec in _load_records(run_dir):
        if rec.get("full_status") == "error":
            continue
        accepted = rec["full_status"] == "accept"
        if accepted:
            unsafe = _adjudicated_unsafe(labels[rec["trap_id"]])
        else:
            # Nothing was accepted; the trap's own ground truth rides along for
            # bookkeeping but cannot contribute to RUA's numerator.
            unsafe = bool(rec.get("ground_truth_unsafe", True))
        status = VerdictStatus.ACCEPT if accepted else VerdictStatus.REJECT
        outcomes.append(
            TrapOutcome(
                site_id=rec["trap_id"],
                verdict=Verdict(
                    site_id=rec["trap_id"],
                    status=status,
                    accepted_patch=None,
                    rejected_rule_id=rec.get("full_rejected_rule_id"),
                    layer_reports=(),
                    attempts_used=1,
                ),
                ground_truth_unsafe=unsafe,
            )
        )
    return outcomes
