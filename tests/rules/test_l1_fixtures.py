"""Auto-discovered rule-fixture suite (codebase-plan.md §9 level 2).

For every registered rule: assert it has >=1 passing and >=1 violating
fixture (invariant 3), then run the rule's check() against every fixture
and assert the outcome matches the directory it lives in. A rule with no
fixtures, or whose fixtures don't exercise its own check() correctly,
fails CI -- this is the mechanism, not a promise in a docstring.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from pqpatch.model import Layer, Patch, Policy, RuleStatus, Site, UsageClass
from pqpatch.verifier.rules.registry import all_rules

_DEFAULT_SITE = Site(
    site_id="fixture-site",
    repo="fixtures",
    file_path="src/FileSigner.java",
    line=1,
    usage_class=UsageClass.KEM,
    matched_symbol="KeyAgreement.getInstance",
    detector_rule_id="pq-detect-keyagreement",
)

_DEFAULT_POLICY = Policy(
    name="fixture-default",
    version="v1",
    floors={UsageClass.KEM: "ML-KEM-768", UsageClass.SIGN: "ML-DSA-65"},
    hybrid_required={UsageClass.KEM: True},
    allowed_randomness_sources=("SecureRandom",),
)


def _patch_from_fixture(path: Path) -> Patch:
    return Patch(
        site_id=_DEFAULT_SITE.site_id,
        attempt=1,
        unified_diff=path.read_text(encoding="utf-8"),
        claimed_primitive="unspecified",
        claimed_parameters="unspecified",
        backend_id="fixture",
        prompt_version="fixture",
        response_hash="0" * 64,
    )


def _fixture_cases() -> list[tuple[str, Path, RuleStatus]]:
    cases: list[tuple[str, Path, RuleStatus]] = []
    for spec in all_rules():
        for p in spec.passing_fixtures:
            cases.append((spec.rule_id, p, RuleStatus.PASS))
        for v in spec.violating_fixtures:
            cases.append((spec.rule_id, v, RuleStatus.FAIL))
    return cases


@pytest.mark.parametrize(
    "rule_id,fixture_path,expected",
    _fixture_cases(),
    ids=lambda v: v.name if isinstance(v, Path) else str(v),
)
def test_rule_fixture_outcome(rule_id: str, fixture_path: Path, expected: RuleStatus) -> None:
    from pqpatch.verifier.rules.registry import get

    spec = get(rule_id)
    patch = _patch_from_fixture(fixture_path)
    site = _DEFAULT_SITE
    if spec.layer is Layer.L2_DATAFLOW:
        site = replace(
            site,
            file_path=str(spec.fixtures_dir / "base.java"),
            usage_class=UsageClass.VERIFY,
        )
    outcome = spec.check(patch, site, _DEFAULT_POLICY)
    assert outcome.status == expected, (
        f"{rule_id} on {fixture_path.name}: expected {expected}, "
        f"got {outcome.status} ({outcome.detail})"
    )


def test_every_rule_has_required_fixtures() -> None:
    """Invariant 3, enforced: a rule without fixtures fails this test, not
    a code review."""
    missing = [spec.rule_id for spec in all_rules() if not spec.has_required_fixtures()]
    assert not missing, f"rules missing passing+violating fixtures: {missing}"


def test_no_duplicate_rule_ids() -> None:
    ids = [spec.rule_id for spec in all_rules()]
    assert len(ids) == len(set(ids))
