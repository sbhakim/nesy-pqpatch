"""Drive the blind judge panel over a trap run's accepted proposals.

This is the step that makes RUA computable. eval/trap_run.py deliberately
refuses to decide whether an ACCEPTED proposal is unsafe -- deciding it
mechanically would be circular -- so every accepted proposal is stored with its
diff and flagged `needs_adjudication`. Here each one is shown to the judge panel
and the verdicts are written into the run's `adjudications.json`, where
eval/adjudicate.trap_outcomes joins them into RUA.

Three properties are load-bearing and each is enforced here rather than assumed:

- **Blind.** The judge sees the pre-migration source with its leading comment
  block stripped, the candidate diff, and the policy. Trap fixtures carry their
  provenance -- id, unsafe class, target rule, the intended unsafe completion --
  in that header, so passing the raw file would hand the judge the answer. This
  is the same leak that prompt v2 had to close on the proposer side.
- **Disjoint.** assert_judges_disjoint refuses a judge that is also a proposer.
- **Refusal-tolerant.** A judge that declines is recorded as having declined and
  is not counted as a vote. A patch decided by fewer than two judges is reported
  as undecided rather than labelled by one model alone.

Nothing here silently drops a row: refusals, transport failures and undecided
patches are all written to the run directory.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from pqpatch.detector.api import detect
from pqpatch.eval.adjudicate import proposal_id, record_labels
from pqpatch.eval.llm_judge import (
    DEFAULT_JUDGE_MODELS,
    Judgment,
    assert_judges_disjoint,
    parse_judgment,
    render_judge_prompt,
)
from pqpatch.eval.traps import TrapSpec, load_trap_suite
from pqpatch.extractor.context import strip_leading_comment_block
from pqpatch.model import Policy, UsageClass

_REFUSALS = "judge_refusals.json"
_MIN_VOTES = 2


class AdjudicationRunError(RuntimeError):
    """The run cannot be adjudicated as configured."""


def _fixture_source(spec: TrapSpec, traps_root: Path) -> str:
    """The pre-migration source the judge reads, minus its provenance header."""
    scenario = traps_root / spec.scenario_path
    sites = [
        s
        for s in detect(scenario, repo_name=spec.trap_id)
        if s.usage_class == spec.usage_class
    ]
    if not sites:
        raise AdjudicationRunError(f"{spec.trap_id}: no site of its declared usage class")
    path = Path(sorted(sites, key=lambda s: s.line)[0].file_path)
    return strip_leading_comment_block(path.read_text(encoding="utf-8"))


def judge_accepted(
    run_dir: Path,
    *,
    traps_root: Path,
    policy: Policy,
    call: Callable[[str, str], str],
    judges: Sequence[str] = DEFAULT_JUDGE_MODELS,
) -> dict[str, Any]:
    """Judge every accepted proposal in `run_dir`; write labels and refusals."""
    assert_judges_disjoint(judges)
    specs = {s.trap_id: s for s in load_trap_suite(traps_root)}

    records = [json.loads(p.read_text()) for p in sorted((run_dir / "sites").glob("*.json"))]
    manifest_path = run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    accepted = [r for r in records if r.get("needs_adjudication")]

    by_judge: dict[str, dict[str, bool]] = {j: {} for j in judges}
    refusals: list[dict[str, str]] = []
    undecided: list[str] = []
    rationales: dict[str, list[dict[str, str]]] = {}

    for rec in accepted:
        trap_id = rec["trap_id"]
        pid = proposal_id(rec, manifest)
        spec = specs.get(trap_id)
        if spec is None:
            raise AdjudicationRunError(f"{trap_id}: accepted record has no trap descriptor")

        prompt = render_judge_prompt(
            fixture_source=_fixture_source(spec, traps_root),
            candidate_diff=rec.get("unified_diff", ""),
            usage_class=UsageClass(rec["usage_class"]),
            policy=policy,
        )

        votes: list[Judgment] = []
        for model in judges:
            try:
                votes.append(parse_judgment(model, call(model, prompt)))
            except Exception as exc:  # noqa: BLE001 -- refusal or transport, both recorded
                refusals.append(
                    {
                        "proposal_id": pid,
                        "trap_id": trap_id,
                        "judge": model,
                        "reason": repr(exc)[:300],
                    }
                )

        if len(votes) < _MIN_VOTES:
            # One model's opinion is not a label. Left unlabelled on purpose so
            # trap_outcomes refuses to compute RUA until it is resolved.
            undecided.append(pid)
            continue

        for judgment in votes:
            by_judge[judgment.model][pid] = judgment.unsafe
        rationales[pid] = [
            {"judge": j.model, "unsafe": str(j.unsafe), "reason": j.reason} for j in votes
        ]

    for model, labels in by_judge.items():
        if labels:
            record_labels(run_dir, labels, annotator=model)

    (run_dir / _REFUSALS).write_text(
        json.dumps(
            {"refusals": refusals, "undecided": undecided, "rationales": rationales},
            indent=2,
            sort_keys=True,
        )
    )

    return {
        "accepted": len(accepted),
        "labelled": len(accepted) - len(undecided),
        "undecided": undecided,
        "refusals": len(refusals),
        "refusal_rate_by_judge": {
            j: sum(1 for r in refusals if r["judge"] == j) / len(accepted) if accepted else 0.0
            for j in judges
        },
    }
