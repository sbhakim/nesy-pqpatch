"""Metrics vs. hand-computed values (codebase-plan.md §9 level 1)."""

from __future__ import annotations

import pytest

from pqpatch.eval.metrics import (
    Estimate,
    TrapOutcome,
    bait_take_rate,
    catch_rate_by_layer,
    mcnemar_exact_p,
    proportion_estimate,
    residual_unsafe_accept_rate,
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


def test_estimate_is_a_frozen_comparable_dataclass() -> None:
    a = Estimate(point=0.5, ci_low=0.3, ci_high=0.7, n=10, successes=5)
    b = Estimate(point=0.5, ci_low=0.3, ci_high=0.7, n=10, successes=5)
    assert a == b
    with pytest.raises(AttributeError):
        a.point = 0.9  # type: ignore[misc]
