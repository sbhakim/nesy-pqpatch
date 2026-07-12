"""Metrics vs. hand-computed values (codebase-plan.md §9 level 1)."""

from __future__ import annotations

import pytest

from pqpatch.eval.metrics import (
    Estimate,
    TrapDifficultyRecord,
    TrapOutcome,
    bait_take_rate,
    catch_rate_by_layer,
    ci_half_width,
    cohen_kappa,
    compiling_unsafe_fraction,
    dual_rua,
    mcnemar_exact_p,
    min_traps_for_ci_half_width,
    proportion_estimate,
    residual_unsafe_accept_rate,
    seed_variance,
    symbolic_exclusive_catches,
    wilson_ci,
)
from pqpatch.model import Layer, Patch, Verdict, VerdictStatus


def _patch(site_id: str) -> Patch:
    return Patch(
        site_id=site_id,
        attempt=1,
        unified_diff="",
        claimed_primitive="",
        claimed_parameters="",
        backend_id="t",
        prompt_version="v1",
        response_hash="0" * 64,
    )


def _verdict(site_id: str, status: VerdictStatus) -> Verdict:
    return Verdict(
        site_id=site_id,
        status=status,
        accepted_patch=_patch(site_id) if status == VerdictStatus.ACCEPT else None,
        rejected_rule_id=None,
        layer_reports=(),
        attempts_used=1,
    )


# --- Wilson CI, against hand-computed reference values ----------------------


def test_wilson_ci_47_of_50_matches_hand_computed_reference() -> None:
    """Hand-derived from the Wilson formula (see module docstring in
    metrics.py); a widely cited textbook worked example."""
    est = wilson_ci(47, 50)
    assert est.point == pytest.approx(0.94, abs=1e-9)
    assert est.ci_low == pytest.approx(0.8379, abs=5e-3)
    assert est.ci_high == pytest.approx(0.9794, abs=5e-3)


def test_wilson_ci_1_of_1_matches_hand_computed_reference() -> None:
    est = wilson_ci(1, 1)
    assert est.ci_low == pytest.approx(0.2065, abs=5e-3)
    assert est.ci_high == pytest.approx(1.0, abs=1e-6)


def test_wilson_ci_0_of_n_has_nonnegative_lower_bound() -> None:
    est = wilson_ci(0, 20)
    assert est.point == 0.0
    assert est.ci_low == pytest.approx(0.0, abs=1e-9)
    assert 0.0 <= est.ci_low <= est.ci_high <= 1.0


def test_wilson_ci_rejects_impossible_inputs() -> None:
    with pytest.raises(ValueError):
        wilson_ci(0, 0)
    with pytest.raises(ValueError):
        wilson_ci(11, 10)


def test_proportion_estimate_matches_wilson_ci() -> None:
    outcomes = [True, True, True, False]  # 3/4
    est = proportion_estimate(outcomes)
    assert est == wilson_ci(3, 4)


# --- McNemar exact test, against exact hand-computed values -----------------


def test_mcnemar_symmetric_discordance_gives_p_one() -> None:
    # b == c: perfectly symmetric disagreement is the null hypothesis exactly.
    assert mcnemar_exact_p(5, 5) == pytest.approx(1.0)


def test_mcnemar_extreme_imbalance_matches_exact_binomial_formula() -> None:
    # b=0, c=10: two-sided exact p = 2 * P(X=0 | Binomial(10, 0.5)) = 2 * 0.5**10
    expected = 2 * (0.5**10)
    assert mcnemar_exact_p(0, 10) == pytest.approx(expected, rel=1e-9)


def test_mcnemar_no_discordant_pairs_gives_p_one() -> None:
    assert mcnemar_exact_p(0, 0) == 1.0


def test_mcnemar_is_symmetric_in_b_and_c() -> None:
    assert mcnemar_exact_p(3, 17) == pytest.approx(mcnemar_exact_p(17, 3))


# --- Domain estimators -------------------------------------------------------


def test_residual_unsafe_accept_rate() -> None:
    outcomes = [
        TrapOutcome("s1", _verdict("s1", VerdictStatus.ACCEPT), ground_truth_unsafe=True),
        TrapOutcome("s2", _verdict("s2", VerdictStatus.ACCEPT), ground_truth_unsafe=False),
        TrapOutcome("s3", _verdict("s3", VerdictStatus.REJECT), ground_truth_unsafe=True),
        TrapOutcome("s4", _verdict("s4", VerdictStatus.ESCALATE), ground_truth_unsafe=True),
    ]
    # only s1 is both ACCEPTed and ground-truth unsafe -> 1/4
    est = residual_unsafe_accept_rate(outcomes)
    assert est.successes == 1
    assert est.n == 4
    assert est.point == pytest.approx(0.25)


def test_residual_unsafe_accept_rate_rejects_empty_input() -> None:
    with pytest.raises(ValueError):
        residual_unsafe_accept_rate([])


def test_bait_take_rate() -> None:
    est = bait_take_rate([True, True, False, True, False])
    assert est.point == pytest.approx(0.6)


def test_catch_rate_by_layer_rejects_empty_input() -> None:
    with pytest.raises(ValueError):
        catch_rate_by_layer([])


def test_catch_rate_by_layer() -> None:
    catching = [
        Layer.L1_SYNTACTIC,
        Layer.L1_SYNTACTIC,
        Layer.L2_DATAFLOW,
        None,  # an unsafe patch that was NOT caught by any layer
    ]
    rates = catch_rate_by_layer(catching)
    assert rates[Layer.L1_SYNTACTIC].point == pytest.approx(0.5)
    assert rates[Layer.L2_DATAFLOW].point == pytest.approx(0.25)
    assert rates[Layer.L3_BUILD].point == pytest.approx(0.0)
    assert rates[Layer.L4_CONFORMANCE].point == pytest.approx(0.0)


# --- U-B: co-primary RUA and trap-set power (refined_defined_plan.md §12.1) --


def test_ci_half_width_matches_the_estimate() -> None:
    est = wilson_ci(0, 12)  # RUA = 0 on the current held-out set size
    assert ci_half_width(est) == pytest.approx((est.ci_high - est.ci_low) / 2.0)


def test_dual_rua_reports_both_sets_and_their_divergence() -> None:
    # held-out: 1/4 unsafe-accept; full suite: that plus three clean rejects -> 1/7
    held = [
        TrapOutcome("h1", _verdict("h1", VerdictStatus.ACCEPT), ground_truth_unsafe=True),
        TrapOutcome("h2", _verdict("h2", VerdictStatus.REJECT), ground_truth_unsafe=True),
        TrapOutcome("h3", _verdict("h3", VerdictStatus.REJECT), ground_truth_unsafe=True),
        TrapOutcome("h4", _verdict("h4", VerdictStatus.REJECT), ground_truth_unsafe=True),
    ]
    full = held + [
        TrapOutcome("d1", _verdict("d1", VerdictStatus.REJECT), ground_truth_unsafe=True),
        TrapOutcome("d2", _verdict("d2", VerdictStatus.REJECT), ground_truth_unsafe=True),
        TrapOutcome("d3", _verdict("d3", VerdictStatus.REJECT), ground_truth_unsafe=True),
    ]
    d = dual_rua(held, full)
    assert d.held_out.point == pytest.approx(0.25)
    assert d.full_suite.point == pytest.approx(1 / 7)
    assert d.divergence == pytest.approx(abs(0.25 - 1 / 7))
    # more traps -> at least as tight an interval (power is the point of U-B)
    assert d.full_suite_half_width <= d.held_out_half_width


def test_min_traps_for_ci_half_width_zero_successes_reference() -> None:
    # For 0/n the Wilson half-width is z^2 / (2 (n + z^2)); at z=1.96 the
    # smallest n with half-width <= 0.15 is 9 (hand-checked: n=8 -> 0.162).
    assert min_traps_for_ci_half_width(0.15, anticipated_successes=0) == 9


def test_min_traps_for_ci_half_width_is_monotonic_in_target() -> None:
    tighter = min_traps_for_ci_half_width(0.10)
    looser = min_traps_for_ci_half_width(0.20)
    assert tighter > looser


def test_min_traps_rejects_degenerate_targets() -> None:
    with pytest.raises(ValueError):
        min_traps_for_ci_half_width(0.0)
    with pytest.raises(ValueError):
        min_traps_for_ci_half_width(1.0)


# --- U-C: Cohen's kappa on blind trap labels (plan §12.2) --------------------


def test_cohen_kappa_hand_computed_half() -> None:
    # a=[T,T,F,F], b=[T,F,F,F]: observed 3/4, expected 0.5 -> kappa 0.5
    assert cohen_kappa([True, True, False, False], [True, False, False, False]) == pytest.approx(
        0.5
    )


def test_cohen_kappa_perfect_agreement_is_one() -> None:
    assert cohen_kappa([True, False, True], [True, False, True]) == pytest.approx(1.0)


def test_cohen_kappa_degenerate_single_class_does_not_divide_by_zero() -> None:
    # both annotators label everything unsafe: chance agreement is total;
    # they do agree on every item, so kappa is defined as 1.0, not NaN.
    assert cohen_kappa([True, True, True], [True, True, True]) == 1.0


def test_cohen_kappa_rejects_mismatched_lengths() -> None:
    with pytest.raises(ValueError):
        cohen_kappa([True], [True, False])


# --- U-D: difficulty control (plan §12.2) ------------------------------------


def _diff(site_id, *, unsafe, compiles, pipeline, l3_alone) -> TrapDifficultyRecord:
    return TrapDifficultyRecord(
        site_id=site_id,
        unsafe=unsafe,
        compiles=compiles,
        caught_by_pipeline=pipeline,
        caught_by_l3_alone=l3_alone,
    )


def test_symbolic_exclusive_catches_strips_out_what_l3_alone_would_catch() -> None:
    records = [
        _diff("t1", unsafe=True, compiles=True, pipeline=True, l3_alone=False),  # exclusive
        _diff("t2", unsafe=True, compiles=True, pipeline=True, l3_alone=True),  # L3 also catches
        _diff("t3", unsafe=True, compiles=False, pipeline=False, l3_alone=False),  # missed
        _diff("t4", unsafe=False, compiles=True, pipeline=True, l3_alone=True),  # not a trap
    ]
    est = symbolic_exclusive_catches(records)
    assert est.successes == 1
    assert est.n == 3  # only the three unsafe traps are the denominator
    assert est.point == pytest.approx(1 / 3)


def test_compiling_unsafe_fraction() -> None:
    records = [
        _diff("t1", unsafe=True, compiles=True, pipeline=True, l3_alone=False),
        _diff("t2", unsafe=True, compiles=True, pipeline=True, l3_alone=True),
        _diff("t3", unsafe=True, compiles=False, pipeline=False, l3_alone=False),
    ]
    assert compiling_unsafe_fraction(records).point == pytest.approx(2 / 3)


def test_difficulty_metrics_reject_no_unsafe_traps() -> None:
    safe_only = [_diff("t1", unsafe=False, compiles=True, pipeline=True, l3_alone=True)]
    with pytest.raises(ValueError):
        symbolic_exclusive_catches(safe_only)
    with pytest.raises(ValueError):
        compiling_unsafe_fraction(safe_only)


# --- U-F: seed variance (plan §12.3) -----------------------------------------


def test_seed_variance_summary() -> None:
    sv = seed_variance([0.0, 0.1, 0.2])
    assert sv.mean == pytest.approx(0.1)
    assert sv.spread == pytest.approx(0.2)
    assert sv.minimum == 0.0
    assert sv.maximum == pytest.approx(0.2)
    assert sv.stdev == pytest.approx(0.1)  # sample stdev of {0, .1, .2}
    assert sv.n_seeds == 3


def test_seed_variance_single_seed_has_zero_stdev() -> None:
    sv = seed_variance([0.3])
    assert sv.stdev == 0.0
    assert sv.spread == 0.0


def test_seed_variance_rejects_empty() -> None:
    with pytest.raises(ValueError):
        seed_variance([])


def test_estimate_is_a_frozen_comparable_dataclass() -> None:
    a = Estimate(point=0.5, ci_low=0.3, ci_high=0.7, n=10, successes=5)
    b = Estimate(point=0.5, ci_low=0.3, ci_high=0.7, n=10, successes=5)
    assert a == b
    with pytest.raises(AttributeError):
        a.point = 0.9  # type: ignore[misc]
