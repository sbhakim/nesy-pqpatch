"""Focused semantics for the conservative L1 primitive-family check."""

from __future__ import annotations

from pqpatch.model import Patch, Policy, RuleStatus, Site, UsageClass
from pqpatch.verifier.rules.registry import get


def _site(usage_class: UsageClass) -> Site:
    return Site(
        site_id="family-site",
        repo="fixtures",
        file_path="src/Example.java",
        line=1,
        usage_class=usage_class,
        matched_symbol="getInstance",
        detector_rule_id="fixture",
    )


def _patch(added: str) -> Patch:
    unified_diff = (
        "--- a/src/Example.java\n"
        "+++ b/src/Example.java\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        f"+{added}\n"
    )
    return Patch(
        site_id="family-site",
        attempt=1,
        unified_diff=unified_diff,
        claimed_primitive="ignored",
        claimed_parameters="ignored",
        backend_id="fixture",
        prompt_version="fixture",
        response_hash="0" * 64,
    )


_POLICY = Policy(
    name="fixture",
    version="v1",
    floors={},
    hybrid_required={},
    allowed_randomness_sources=("SecureRandom",),
)


def test_signature_site_rejects_kem_only_patch() -> None:
    outcome = get("PQ-KEY-01").check(
        _patch('KeyEncapsulation.getInstance("ML-KEM-768");'),
        _site(UsageClass.SIGN),
        _POLICY,
    )
    assert outcome.status is RuleStatus.FAIL


def test_mixed_family_patch_defers_to_dataflow_layer() -> None:
    outcome = get("PQ-KEY-01").check(
        _patch(
            'use(KeyEncapsulation.getInstance("ML-KEM-768"), '
            'Signature.getInstance("ML-DSA-65"));'
        ),
        _site(UsageClass.KEM),
        _POLICY,
    )
    assert outcome.status is RuleStatus.PASS
