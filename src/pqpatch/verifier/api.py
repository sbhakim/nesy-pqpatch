"""Verifier orchestrator: four layers applied in order, short-circuiting at
the first violation.

Layers are individually enableable so the pipeline remains usable while the
deeper layers are under construction; every verdict records which layers
actually ran, so a partial configuration is visible in the results rather
than implicit in the code.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from pqpatch.model import (
    Layer,
    LayerReport,
    Patch,
    Policy,
    RuleResult,
    RuleStatus,
    Site,
    Verdict,
    VerdictStatus,
)
from pqpatch.verifier import l3_build
from pqpatch.verifier.l4_conformance import check as l4_check
from pqpatch.verifier.rules.registry import rules_by_layer
from pqpatch.verifier.rules.spec import RuleOutcome

# L4 joins this set when its implementation lands. L2 contains the first
# production rule (PQ-VER-01); verdict provenance still records the exact set.
DEFAULT_ENABLED_LAYERS: frozenset[Layer] = frozenset(
    {Layer.L1_SYNTACTIC, Layer.L2_DATAFLOW, Layer.L3_BUILD}
)

_LAYER_ORDER: tuple[Layer, ...] = (
    Layer.L1_SYNTACTIC,
    Layer.L2_DATAFLOW,
    Layer.L3_BUILD,
    Layer.L4_CONFORMANCE,
)


def _run_rule_registry_layer(
    layer: Layer, patch: Patch, site: Site, policy: Policy
) -> LayerReport:
    """Run every registered rule for an implemented rule layer (L1 or L2)."""
    results: list[RuleResult] = []
    start = time.perf_counter()
    for spec in rules_by_layer(layer):
        rule_start = time.perf_counter()
        try:
            outcome = spec.check(patch, site, policy)
        except Exception as exc:  # noqa: BLE001 -- a broken rule becomes a recorded
            # ERROR, never a crashed run and never a silent PASS
            outcome = RuleOutcome(RuleStatus.ERROR, detail=f"rule raised: {exc!r}")
        rule_ms = (time.perf_counter() - rule_start) * 1000.0
        results.append(
            RuleResult(
                rule_id=spec.rule_id,
                layer=spec.layer,
                status=outcome.status,
                unsafe_class=spec.unsafe_class,
                rationale=spec.rationale,
                duration_ms=rule_ms,
                detail=outcome.detail,
            )
        )
        if outcome.status != RuleStatus.PASS:
            break  # this layer's own rules also short-circuit at first violation
    total_ms = (time.perf_counter() - start) * 1000.0
    return LayerReport(layer=layer, results=tuple(results), duration_ms=total_ms)


def _run_single_check_layer(
    layer: Layer,
    check_fn: Callable[[Patch, Site, Policy], RuleOutcome],
    patch: Patch,
    site: Site,
    policy: Policy,
    *,
    rule_id: str,
) -> LayerReport:
    """L3/L4's shape: one check() call, not a rule collection."""
    start = time.perf_counter()
    try:
        outcome = check_fn(patch, site, policy)
    except NotImplementedError as exc:
        outcome = RuleOutcome(RuleStatus.SKIPPED, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 -- recorded, not fatal
        outcome = RuleOutcome(RuleStatus.ERROR, detail=f"layer raised: {exc!r}")
    duration_ms = (time.perf_counter() - start) * 1000.0
    result = RuleResult(
        rule_id=rule_id,
        layer=layer,
        status=outcome.status,
        unsafe_class=None,
        rationale="",
        duration_ms=duration_ms,
        detail=outcome.detail,
    )
    return LayerReport(layer=layer, results=(result,), duration_ms=duration_ms)


def _run_layer(layer: Layer, patch: Patch, site: Site, policy: Policy) -> LayerReport:
    if layer == Layer.L1_SYNTACTIC:
        return _run_rule_registry_layer(layer, patch, site, policy)
    if layer == Layer.L2_DATAFLOW:
        return _run_rule_registry_layer(layer, patch, site, policy)
    if layer == Layer.L3_BUILD:
        return _run_single_check_layer(
            layer, l3_build.check, patch, site, policy, rule_id="<L3-build>"
        )
    if layer == Layer.L4_CONFORMANCE:
        return _run_single_check_layer(
            layer, l4_check, patch, site, policy, rule_id="<L4-conformance>"
        )
    raise ValueError(f"unknown layer: {layer!r}")  # unreachable given Layer's enum members


def _skipped_report(layer: Layer) -> LayerReport:
    """Report for a layer excluded from `enabled_layers` on this call."""
    result = RuleResult(
        rule_id=f"<{layer.name}-disabled>",
        layer=layer,
        status=RuleStatus.SKIPPED,
        unsafe_class=None,
        rationale="",
        duration_ms=0.0,
        detail="layer excluded from enabled_layers for this verification call",
    )
    return LayerReport(layer=layer, results=(result,), duration_ms=0.0)


def verify_patch(
    patch: Patch,
    site: Site,
    policy: Policy,
    *,
    enabled_layers: frozenset[Layer] = DEFAULT_ENABLED_LAYERS,
) -> Verdict:
    """Accept iff every enabled layer passes; otherwise reject at the first
    layer that does not."""
    layer_reports: list[LayerReport] = []
    layers_evaluated: list[Layer] = []

    for layer in _LAYER_ORDER:
        if layer not in enabled_layers:
            layer_reports.append(_skipped_report(layer))
            continue

        report = _run_layer(layer, patch, site, policy)
        layer_reports.append(report)
        layers_evaluated.append(layer)

        if not report.passed:
            first = report.first_failure
            return Verdict(
                site_id=patch.site_id,
                status=VerdictStatus.REJECT,
                accepted_patch=None,
                rejected_rule_id=first.rule_id if first else None,
                layer_reports=tuple(layer_reports),
                attempts_used=patch.attempt,
                layers_evaluated=tuple(layers_evaluated),
            )

    return Verdict(
        site_id=patch.site_id,
        status=VerdictStatus.ACCEPT,
        accepted_patch=patch,
        rejected_rule_id=None,
        layer_reports=tuple(layer_reports),
        attempts_used=patch.attempt,
        layers_evaluated=tuple(layers_evaluated),
    )


def rejection_feedback(verdict: Verdict) -> str | None:
    """Rationale text for the repair loop; None unless the verdict is a
    rejection whose failing rule carries one."""
    if verdict.status != VerdictStatus.REJECT:
        return None
    for report in verdict.layer_reports:
        failure = report.first_failure
        if failure is not None:
            text = failure.rationale or failure.detail
            return text or None
    return None
