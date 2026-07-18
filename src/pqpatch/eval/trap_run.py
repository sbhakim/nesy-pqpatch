"""Trap-suite evaluation harness: drive a proposer over trap scenarios and
record, per trap, what the full verifier and an L3-only (build-and-test) gate
each decide about the *same* first proposal.

This produces the mechanical half of the RQ2 evidence (manuscript Table
"trap-suite results"): the L3-only-vs-full comparison, catch attribution by
rule and layer, and the symbolic-exclusive count -- unsafe proposals a build
gate accepts that the rule layers reject. Two facts are deliberately *not*
decided here, because deciding them mechanically would be circular:

- **Bait-take** is only lower-bounded: a proposal rejected by a rule of the
  trap's own unsafe class demonstrably took the bait; an accepted proposal may
  be a genuinely safe migration (bait refused) or an unsafe one the rule set
  missed. Distinguishing those is exactly the adjudication step.
- **RUA's numerator** therefore never comes from this module. Every ACCEPTED
  trap proposal is written to the run directory with its diff and flagged
  ``needs_adjudication``; a human labels it against the trap's ground truth
  before any residual-unsafe-accept number is claimed.

First-attempt scoring only: the trap table is defined over first proposals
(bait-take b_m); repair-loop behavior is RQ3's question, not this harness's.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pqpatch.detector.api import detect
from pqpatch.eval.run import _git_sha, config_hash
from pqpatch.eval.traps import TrapSpec, load_trap_suite
from pqpatch.extractor.context import extract_context
from pqpatch.model import Layer, Policy, Site, Verdict, VerdictStatus
from pqpatch.proposer.base import Backend
from pqpatch.verifier.api import DEFAULT_ENABLED_LAYERS, verify_patch

_L3_ONLY: frozenset[Layer] = frozenset({Layer.L3_BUILD})


class TrapSiteError(RuntimeError):
    """The trap scenario yields no detectable site of its declared usage class
    -- an authoring defect surfaced loudly, not skipped."""


def _pick_site(spec: TrapSpec, sites: Sequence[Site]) -> Site:
    """The scenario's vulnerable site: the first detected site (by line) whose
    usage class matches the trap's declared class."""
    matching = sorted(
        (s for s in sites if s.usage_class == spec.usage_class), key=lambda s: s.line
    )
    if not matching:
        found = [(s.usage_class.value, s.line) for s in sites]
        raise TrapSiteError(
            f"{spec.trap_id}: no detected site of class {spec.usage_class.value!r} "
            f"in {spec.scenario_path} (found: {found})"
        )
    return matching[0]


def _failing_rule(verdict: Verdict) -> tuple[str | None, str | None, str | None]:
    """(rule_id, layer name, unsafe-class value) of the first failure, if any."""
    for report in verdict.layer_reports:
        failure = report.first_failure
        if failure is not None:
            uc = failure.unsafe_class.value if failure.unsafe_class else None
            return failure.rule_id, report.layer.name, uc
    return None, None, None


def evaluate_trap(
    spec: TrapSpec,
    *,
    traps_root: Path,
    backend: Backend,
    policy: Policy,
    repo_root: Path,
    seed: int = 0,
    prompt_version: str = "v1",
) -> dict[str, Any]:
    """Propose once for one trap and score the proposal under both gates."""
    scenario_dir = traps_root / spec.scenario_path
    site = _pick_site(spec, detect(scenario_dir, repo_name=spec.trap_id))
    context = extract_context(site, repo_root=repo_root)

    patch = backend.propose(
        context, policy, feedback=None, attempt=1, seed=seed, prompt_version=prompt_version
    )
    full = verify_patch(patch, site, policy, enabled_layers=DEFAULT_ENABLED_LAYERS)
    l3_only = verify_patch(patch, site, policy, enabled_layers=_L3_ONLY)

    rule_id, catch_layer, rule_unsafe_class = _failing_rule(full)
    trap_unsafe_class = spec.unsafe_class.value if spec.unsafe_class else "unanticipated"

    full_rejected = full.status != VerdictStatus.ACCEPT
    l3_accepted = l3_only.status == VerdictStatus.ACCEPT

    # Why L3 rejected, when it did. "patch does not apply cleanly" is an
    # unapplyable diff, not the build gate seeing the flaw -- the distinction
    # the difficulty control needs, recorded now rather than inferred later.
    l3_detail = ""
    if not l3_accepted:
        for report in l3_only.layer_reports:
            failure = report.first_failure
            if failure is not None:
                l3_detail = failure.detail[:300]
                break
    return {
        "trap_id": spec.trap_id,
        "usage_class": spec.usage_class.value,
        "trap_unsafe_class": trap_unsafe_class,
        "split": spec.split.value,
        "provenance": spec.provenance.value,
        "ground_truth_unsafe": spec.ground_truth_unsafe,
        "unsafe_patch_compiles": spec.unsafe_patch_compiles,
        "seed": seed,
        "site_id": site.site_id,
        # the two gates over the same first proposal
        "full_status": full.status.value,
        "full_rejected_rule_id": rule_id,
        "full_catch_layer": catch_layer,
        "full_rule_unsafe_class": rule_unsafe_class,
        "l3_only_status": l3_only.status.value,
        "l3_only_detail": l3_detail,
        "l3_reject_was_apply_failure": "does not apply cleanly" in l3_detail,
        # mechanical scoring (see module docstring for what these do NOT claim)
        "bait_taken_confirmed": full_rejected and rule_unsafe_class == trap_unsafe_class,
        "symbolic_exclusive": full_rejected and l3_accepted,
        "needs_adjudication": full.status == VerdictStatus.ACCEPT,
        # evidence for the adjudicator / case-by-case analysis
        "claimed_primitive": patch.claimed_primitive,
        "unified_diff": patch.unified_diff,
        "response_hash": patch.response_hash,
    }


def run_trap_config(
    *,
    traps_root: Path,
    backend: Backend,
    policy: Policy,
    runs_dir: Path,
    repo_root: Path,
    split: str | None = None,
    seeds: Sequence[int] = (0,),
    prompt_version: str = "v1",
    ruleset_version: str = "rules-v1.0",
    offline: bool = False,
) -> Path:
    """Evaluate every trap under ``traps_root`` (optionally one split) and
    write a trap-run directory (manifest kind ``trap-run``); returns it."""
    specs = [
        s for s in load_trap_suite(traps_root) if split is None or s.split.value == split
    ]
    corpus_id = f"traps/{split or 'all'}"

    chash = config_hash(
        backend_id=backend.backend_id,
        model_version=backend.model_version,
        seeds=seeds,
        k=1,  # first-attempt scoring by definition
        enabled_layers=DEFAULT_ENABLED_LAYERS,
        corpus_id=corpus_id,
        prompt_version=prompt_version,
        ruleset_version=ruleset_version,
        policy_version=policy.version,
    )
    run_dir = runs_dir / chash
    sites_dir = run_dir / "sites"
    sites_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    for spec in specs:
        for seed in seeds:
            try:
                record = evaluate_trap(
                    spec,
                    traps_root=traps_root,
                    backend=backend,
                    policy=policy,
                    repo_root=repo_root,
                    seed=seed,
                    prompt_version=prompt_version,
                )
            except Exception as exc:  # noqa: BLE001 -- one trap's failure is a
                # recorded error, never a crashed suite
                record = {
                    "trap_id": spec.trap_id,
                    "usage_class": spec.usage_class.value,
                    "trap_unsafe_class": (
                        spec.unsafe_class.value if spec.unsafe_class else "unanticipated"
                    ),
                    "split": spec.split.value,
                    "provenance": spec.provenance.value,
                    "seed": seed,
                    "full_status": "error",
                    "l3_only_status": "error",
                    "error": repr(exc),
                }
            (sites_dir / f"{spec.trap_id}__seed{seed}.json").write_text(
                json.dumps(record, indent=2, sort_keys=True)
            )
            records.append(record)

    manifest = {
        "kind": "trap-run",
        "config_hash": chash,
        "corpus_id": corpus_id,
        "app": corpus_id,
        "backend_id": backend.backend_id,
        "model_version": backend.model_version,
        "seeds": list(seeds),
        "k": 1,
        "enabled_layers": sorted(layer.name for layer in DEFAULT_ENABLED_LAYERS),
        "prompt_version": prompt_version,
        "ruleset_version": ruleset_version,
        "policy_version": policy.version,
        "offline": offline,
        "git_sha": _git_sha(repo_root),
        "created_at_utc": datetime.now(UTC).isoformat(),
        "n_traps": len(specs),
        "n_records": len(records),
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return run_dir
