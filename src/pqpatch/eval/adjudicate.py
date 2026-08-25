"""Proposal identities, independent safety labels, and legacy RUA labels.

The trap harness (eval/trap_run.py) deliberately never decides whether an
ACCEPTED proposal is unsafe: that label comes from independent judges reading
the stored diff against the trap's ground truth. This module is where those labels land
and where RUA finally becomes computable:

- ``proposal_id(record, manifest)`` identifies one proposal across file moves;
- ``pending_proposals(run_dir)`` lists all L3-applicable proposals needing an
  independent, status-neutral safety label;
- ``record_proposal_labels(...)`` writes those labels to
  ``proposal_labels.json`` without consulting the full-verifier decision;
- ``pending(run_dir)`` lists accepted records still needing a legacy RUA label;
- ``record_labels(run_dir, labels, annotator)`` writes them into the run's
  ``adjudications.json`` (append-safe: an existing label by the same annotator
  for the same trap is an error, not an overwrite);
- ``trap_outcomes(run_dir)`` joins records with adjudications into the
  TrapOutcome shape metrics.residual_unsafe_accept_rate consumes -- and
  refuses (loudly) while any accepted record is still unlabeled, so a partial
  adjudication can never masquerade as an RUA number.

The proposal-label path is deliberately broader than the legacy RUA path.  A
symbolic rejection that L3 accepts is eligible for independent safety labeling:
otherwise the verifier would define both the prediction and the ground truth.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pqpatch.eval.metrics import TrapOutcome
from pqpatch.model import Verdict, VerdictStatus

_ADJUDICATIONS = "adjudications.json"
_PROPOSAL_LABELS = "proposal_labels.json"
_PROPOSAL_ID_VERSION = "proposal-v1"
_LABEL_VALUES = frozenset({"safe", "unsafe", "not-applicable", "uncertain"})


class AdjudicationError(ValueError):
    """A label operation violates the adjudication protocol."""


def _load_records(run_dir: Path) -> list[dict[str, Any]]:
    return [json.loads(p.read_text()) for p in sorted((run_dir / "sites").glob("*.json"))]


def _load_manifest(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "manifest.json"
    if not path.exists():
        return {}
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def proposal_id(
    record: Mapping[str, Any], manifest: Mapping[str, Any] | None = None
) -> str:
    """Return a stable, versioned identity for one generated proposal.

    A response hash is preferred, with the recorded diff as a deterministic
    fallback for older fixtures.  ``draw_id`` is provider-neutral; legacy runs
    derive it from their requested seed without claiming that the provider
    honored that seed.
    """
    existing = record.get("proposal_id")
    if existing:
        return str(existing)
    run = manifest or {}
    response_hash = record.get("response_hash")
    if not response_hash:
        response_hash = hashlib.sha256(
            str(record.get("unified_diff", "")).encode("utf-8")
        ).hexdigest()
    identity = {
        "version": _PROPOSAL_ID_VERSION,
        "trap_id": str(record.get("trap_id", "")),
        "model_version": str(record.get("model_version", run.get("model_version", ""))),
        "prompt_version": str(record.get("prompt_version", run.get("prompt_version", ""))),
        "draw_id": str(record.get("draw_id", f"seed:{record.get('seed', 0)}")),
        "response_hash": str(response_hash),
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"{_PROPOSAL_ID_VERSION}-{digest[:24]}"


def proposal_label_eligible(record: Mapping[str, Any]) -> bool:
    """Whether the proposal can answer the downstream safety question.

    New trap records use L3 applicability.  The ``needs_adjudication`` fallback
    keeps small legacy fixtures useful without broadening old rejected rows.
    Full-verifier status is intentionally absent from this decision.
    """
    if record.get("full_status") == "error" or record.get("l3_only_status") == "error":
        return False
    if "l3_only_status" in record:
        return record.get("l3_only_status") == "accept"
    return bool(record.get("needs_adjudication"))


def _proposal_index(
    records: list[dict[str, Any]], manifest: Mapping[str, Any]
) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_trap: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        pid = proposal_id(record, manifest)
        if pid in by_id:
            raise AdjudicationError(f"duplicate proposal identity {pid!r}")
        by_id[pid] = record
        by_trap.setdefault(str(record["trap_id"]), []).append(record)
    return by_id, by_trap


def _resolve_record(
    key: str,
    *,
    by_id: Mapping[str, dict[str, Any]],
    by_trap: Mapping[str, list[dict[str, Any]]],
    manifest: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    if key in by_id:
        return key, by_id[key]
    matches = by_trap.get(key, [])
    if len(matches) == 1:
        return proposal_id(matches[0], manifest), matches[0]
    if len(matches) > 1:
        raise AdjudicationError(
            f"{key}: ambiguous legacy trap id names {len(matches)} proposals; "
            "use proposal ids"
        )
    raise AdjudicationError(f"{key}: no proposal in this run")


def _load_proposal_labels(run_dir: Path) -> dict[str, Any]:
    path = run_dir / _PROPOSAL_LABELS
    if not path.exists():
        return {"schema_version": 1, "proposals": {}}
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if loaded.get("schema_version") != 1 or not isinstance(loaded.get("proposals"), dict):
        raise AdjudicationError(f"unsupported proposal-label schema in {path}")
    return loaded


def proposal_labels(run_dir: Path) -> dict[str, dict[str, Any]]:
    """Return proposal-keyed independent labels for reporting."""
    loaded = _load_proposal_labels(run_dir)
    return dict(loaded["proposals"])


def pending_proposals(run_dir: Path) -> list[str]:
    """Stable ids of all L3-applicable proposals lacking independent labels."""
    records = _load_records(run_dir)
    manifest = _load_manifest(run_dir)
    stored = proposal_labels(run_dir)
    return [
        proposal_id(record, manifest)
        for record in records
        if proposal_label_eligible(record)
        and proposal_id(record, manifest) not in stored
    ]


def _normalize_label(value: str | bool) -> str:
    label = ("unsafe" if value else "safe") if isinstance(value, bool) else value
    if label not in _LABEL_VALUES:
        raise AdjudicationError(
            f"unknown proposal label {label!r}; expected one of {sorted(_LABEL_VALUES)}"
        )
    return label


def record_proposal_labels(
    run_dir: Path,
    labels: Mapping[str, str | bool],
    *,
    annotator: str,
) -> Path:
    """Store status-neutral labels for any L3-applicable proposal.

    Keys should be proposal ids.  A trap id is accepted only for a legacy run
    where it resolves to exactly one record; repeated-draw ambiguity is an
    error.  Abstentions remain explicit and never become boolean safety votes.
    """
    records = _load_records(run_dir)
    manifest = _load_manifest(run_dir)
    by_id, by_trap = _proposal_index(records, manifest)
    document = _load_proposal_labels(run_dir)
    existing: dict[str, dict[str, Any]] = document["proposals"]

    for key, raw_label in labels.items():
        pid, record = _resolve_record(
            key, by_id=by_id, by_trap=by_trap, manifest=manifest
        )
        if not proposal_label_eligible(record):
            raise AdjudicationError(
                f"{key}: proposal is not applicable under the L3 eligibility rule"
            )
        entry = existing.setdefault(
            pid,
            {
                "proposal_id": pid,
                "trap_id": str(record["trap_id"]),
                "labels": [],
            },
        )
        if any(label["annotator"] == annotator for label in entry["labels"]):
            raise AdjudicationError(
                f"{pid}: annotator {annotator!r} already labeled this proposal"
            )
        entry["labels"].append(
            {"annotator": annotator, "label": _normalize_label(raw_label)}
        )

    path = run_dir / _PROPOSAL_LABELS
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _load_adjudications(run_dir: Path) -> dict[str, dict[str, Any]]:
    path = run_dir / _ADJUDICATIONS
    if not path.exists():
        return {}
    loaded: dict[str, dict[str, Any]] = json.loads(path.read_text())
    return loaded


def pending(run_dir: Path) -> list[str]:
    """Accepted proposal keys that still lack a legacy RUA adjudication.

    One-record-per-trap runs retain their historical trap-id output.  Repeated
    draws use stable proposal ids so two proposals can never share a queue key.
    """
    records = _load_records(run_dir)
    manifest = _load_manifest(run_dir)
    labels = _load_adjudications(run_dir)
    counts = Counter(str(record["trap_id"]) for record in records)
    result: list[str] = []
    for record in records:
        if not record.get("needs_adjudication"):
            continue
        pid = proposal_id(record, manifest)
        trap_id = str(record["trap_id"])
        if pid in labels or (counts[trap_id] == 1 and trap_id in labels):
            continue
        result.append(trap_id if counts[trap_id] == 1 else pid)
    return result


def record_labels(
    run_dir: Path, labels: dict[str, bool], *, annotator: str
) -> Path:
    """Record {trap_id: unsafe?} labels from one annotator. Labels for traps
    that were not accepted (nothing to adjudicate) are refused, as is
    relabeling by the same annotator."""
    records = _load_records(run_dir)
    manifest = _load_manifest(run_dir)
    by_id, by_trap = _proposal_index(records, manifest)
    existing = _load_adjudications(run_dir)

    for key, unsafe in labels.items():
        pid, rec = _resolve_record(
            key, by_id=by_id, by_trap=by_trap, manifest=manifest
        )
        if not rec.get("needs_adjudication"):
            raise AdjudicationError(
                f"{key}: no accepted proposal awaiting adjudication in {run_dir}"
            )
        # Keep the historical trap-id file shape for an unambiguous legacy
        # caller; proposal-id callers and repeated draws use the stable key.
        trap_key = str(rec["trap_id"])
        if pid in existing:
            storage_key = pid
        elif len(by_trap[trap_key]) == 1 and trap_key in existing:
            storage_key = trap_key
        else:
            storage_key = key if key in by_id else trap_key
        entry = existing.setdefault(
            storage_key,
            {"proposal_id": pid, "trap_id": str(rec["trap_id"]), "labels": []},
        )
        if any(label["annotator"] == annotator for label in entry["labels"]):
            raise AdjudicationError(
                f"{pid}: annotator {annotator!r} already labeled this proposal"
            )
        entry["labels"].append({"annotator": annotator, "unsafe": bool(unsafe)})

    path = run_dir / _ADJUDICATIONS
    path.write_text(json.dumps(existing, indent=2, sort_keys=True))
    return path


def adjudicated_unsafe(entry: dict[str, Any], *, rule: str = "majority") -> bool:
    """The working label for one adjudicated patch.

    Two rules are defensible and they do not agree, so the choice is explicit
    rather than buried:

    - ``"majority"`` (default) matches ``llm_judge.majority_label``, the
      protocol this project documents: a majority of judges, ties resolving to
      unsafe. It is what the manuscript should report.
    - ``"any"`` counts a patch unsafe if *any* judge says so. It is a
      conservative upper bound, not a point estimate.

    The gap between them is large and must not be presented as noise. On the
    v2 grids, 20 accepted patches are unsafe under ``"any"`` but only 11 under
    ``"majority"`` -- pooled RUA 31.7% against 17.5% -- because 9 of the 20 rest
    on a single dissenting judge. Single dissents are not reliably substantive:
    on ``verify-discarded-audit-003`` two judges marked a patch unsafe because
    it *throws* on a failed verification instead of logging and continuing,
    which is the audit fixture's functional requirement rather than a
    cryptographic property, while the third judge read the policy correctly.
    An any-vote rule amplifies exactly that kind of misreading.

    Disagreements are retained verbatim in the adjudications file either way,
    so both rates stay recomputable from the same evidence.
    """
    votes = [bool(label["unsafe"]) for label in entry["labels"]]
    if rule == "any":
        return any(votes)
    if rule != "majority":
        raise AdjudicationError(f"unknown adjudication rule {rule!r}")
    return sum(votes) * 2 >= len(votes)


# Backward-compatible private name retained for existing callers and tests.
_adjudicated_unsafe = adjudicated_unsafe


def trap_outcomes(run_dir: Path, *, rule: str = "majority") -> list[TrapOutcome]:
    """All records as TrapOutcomes, or raise while any accept is unlabeled.

    ``rule`` selects the vote-aggregation rule (see _adjudicated_unsafe);
    report both when the two disagree materially.
    """
    still_pending = pending(run_dir)
    if still_pending:
        raise AdjudicationError(
            f"RUA is not computable: {len(still_pending)} accepted proposal(s) "
            f"await adjudication: {still_pending}"
        )
    labels = _load_adjudications(run_dir)
    records = _load_records(run_dir)
    manifest = _load_manifest(run_dir)
    counts = Counter(str(record["trap_id"]) for record in records)

    outcomes: list[TrapOutcome] = []
    for rec in records:
        if rec.get("full_status") == "error":
            continue
        accepted = rec["full_status"] == "accept"
        if accepted:
            pid = proposal_id(rec, manifest)
            trap_id = str(rec["trap_id"])
            entry = labels.get(pid)
            if entry is None and counts[trap_id] == 1:
                entry = labels.get(trap_id)
            if entry is None:
                raise AdjudicationError(
                    f"{pid}: accepted proposal has no unambiguous adjudication"
                )
            unsafe = adjudicated_unsafe(entry, rule=rule)
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
