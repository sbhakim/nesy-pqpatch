"""The per-site repair loop: propose, verify, feed the violated rule's
rationale back, and escalate when the attempt bound is exhausted.

Corresponds line-for-line to Algorithm 1 of the accompanying manuscript.
"""

from __future__ import annotations

from pqpatch.model import (
    Context,
    Layer,
    Policy,
    Site,
    TraceEvent,
    TraceRecord,
    Verdict,
    VerdictStatus,
)
from pqpatch.proposer.base import Backend
from pqpatch.trace.canonical import finalize_trace
from pqpatch.verifier.api import DEFAULT_ENABLED_LAYERS, rejection_feedback, verify_patch

DEFAULT_K = 3  # manuscript: "We fix k=3 throughout."

# RQ3 control arm: the repair loop re-prompts after a rejection but withholds
# the violated rule's rationale. Comparing convergence under this text against
# rule-derived feedback isolates what the rationale itself contributes.
GENERIC_FEEDBACK = (
    "The previous patch was rejected by the verifier. Propose a different "
    "migration patch."
)


def _failure_layer(verdict: Verdict) -> Layer | None:
    for report in verdict.layer_reports:
        if report.first_failure is not None:
            return report.layer
    return None


def migrate_site(
    site: Site,
    context: Context,
    policy: Policy,
    backend: Backend,
    *,
    k: int = DEFAULT_K,
    enabled_layers: frozenset[Layer] = DEFAULT_ENABLED_LAYERS,
    prompt_version: str = "v1",
    seed: int = 0,
    ruleset_version: str = "unversioned",
    feedback_mode: str = "rule",
) -> tuple[Verdict, TraceRecord]:
    """Run the loop for one site; returns the final verdict and its
    finalized trace. `ruleset_version` should carry the frozen rule tag
    once one exists; "unversioned" marks pre-freeze development runs.
    `feedback_mode` selects the repair-loop arm: "rule" returns the violated
    rule's rationale (the system under test), "generic" returns a fixed
    retry sentence (RQ3's control).
    """
    if feedback_mode not in ("rule", "generic"):
        raise ValueError(f"feedback_mode must be 'rule' or 'generic', got {feedback_mode!r}")
    events: list[TraceEvent] = []
    feedback: str | None = None
    last_verdict: Verdict | None = None

    for attempt in range(1, k + 1):
        patch = backend.propose(
            context,
            policy,
            feedback=feedback,
            attempt=attempt,
            seed=seed,
            prompt_version=prompt_version,
        )
        verdict = verify_patch(patch, site, policy, enabled_layers=enabled_layers)
        timings = {report.layer.name: report.duration_ms for report in verdict.layer_reports}

        if verdict.status == VerdictStatus.ACCEPT:
            events.append(
                TraceEvent(
                    attempt=attempt, layer=None, status="accept", rule_id=None, timings_ms=timings
                )
            )
            trace = TraceRecord(
                site=site,
                usage_class=site.usage_class,
                policy_version=policy.version,
                ruleset_version=ruleset_version,
                events=tuple(events),
                verdict=verdict,
            )
            return verdict, finalize_trace(trace)

        events.append(
            TraceEvent(
                attempt=attempt,
                layer=_failure_layer(verdict),
                status="reject",
                rule_id=verdict.rejected_rule_id,
                timings_ms=timings,
            )
        )
        feedback = rejection_feedback(verdict) if feedback_mode == "rule" else GENERIC_FEEDBACK
        last_verdict = verdict

    # Attempt bound exhausted (k attempts, initial proposal included) ->
    # ESCALATE, carrying the last attempt's diagnostic evidence forward.
    escalated = Verdict(
        site_id=site.site_id,
        status=VerdictStatus.ESCALATE,
        accepted_patch=None,
        rejected_rule_id=last_verdict.rejected_rule_id if last_verdict else None,
        layer_reports=last_verdict.layer_reports if last_verdict else (),
        attempts_used=k,
        layers_evaluated=last_verdict.layers_evaluated if last_verdict else (),
    )
    trace = TraceRecord(
        site=site,
        usage_class=site.usage_class,
        policy_version=policy.version,
        ruleset_version=ruleset_version,
        events=tuple(events),
        verdict=escalated,
    )
    return escalated, finalize_trace(trace)
