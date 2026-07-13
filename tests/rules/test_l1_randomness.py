"""Boundary tests for literal-seed detection at L1."""

from __future__ import annotations

from pqpatch.model import Patch, Policy, RuleStatus, Site, UsageClass
from pqpatch.verifier.rules.registry import get

_SITE = Site(
    site_id="random-site",
    repo="fixtures",
    file_path="src/Example.java",
    line=1,
    usage_class=UsageClass.KEM,
    matched_symbol="KeyPairGenerator.getInstance",
    detector_rule_id="fixture",
)

_POLICY = Policy(
    name="fixture",
    version="v1",
    floors={},
    hybrid_required={},
    allowed_randomness_sources=("SecureRandom",),
)


def _check(added: str) -> RuleStatus:
    diff = "--- a/src/Example.java\n+++ b/src/Example.java\n@@ -1 +1 @@\n-old\n+" + added + "\n"
    patch = Patch(
        site_id=_SITE.site_id,
        attempt=1,
        unified_diff=diff,
        claimed_primitive="ignored",
        claimed_parameters="ignored",
        backend_id="fixture",
        prompt_version="fixture",
        response_hash="0" * 64,
    )
    return get("PQ-RAND-02").check(patch, _SITE, _POLICY).status


def test_rejects_literal_string_seed() -> None:
    assert _check('SecureRandom r = new SecureRandom("fixed".getBytes(UTF_8));') is RuleStatus.FAIL


def test_does_not_guess_about_set_seed_without_dataflow() -> None:
    assert _check("random.setSeed(42L);") is RuleStatus.PASS
