"""Boundary semantics and orchestration for the L2 seed-provenance rule.

`classify_seed_provenance` convicts only a constant seed (literal, fixed byte
array, or `"literal".getBytes()`) that reaches a `SecureRandom` through a
variable or simple alias. The load-bearing orchestrator test shows the "beyond
tokens" contribution: L1's `PQ-RAND-02` sees only a literal *directly* in the
constructor, so a seed routed through a variable passes L1, while L2 catches it.
"""

from __future__ import annotations

from pathlib import Path

from pqpatch.model import Layer, Patch, Policy, RuleStatus, Site, UsageClass, VerdictStatus
from pqpatch.verifier.api import verify_patch
from pqpatch.verifier.l2_dataflow.java_flow import SeedFlow, classify_seed_provenance
from pqpatch.verifier.rules.registry import get
from tests.support.diffgen import make_diff

_BASE = (
    Path(__file__).resolve().parents[1].parent
    / "src"
    / "pqpatch"
    / "verifier"
    / "l2_dataflow"
    / "fixtures"
    / "PQ-RAND-03"
    / "base.java"
)


def _flow(body: str) -> SeedFlow:
    return classify_seed_provenance(
        "class C { void m(byte[] ct) throws Exception {\n" + body + "\n}}"
    )


def test_literal_seed_through_a_variable_is_convicted() -> None:
    assert (
        _flow('byte[] seed = "fixed".getBytes(); SecureRandom sr = new SecureRandom(seed);')
        is SeedFlow.LITERAL_SEEDED
    )


def test_numeric_setseed_is_convicted() -> None:
    assert (
        _flow("long s = 42L; SecureRandom sr = new SecureRandom(); sr.setSeed(s);")
        is SeedFlow.LITERAL_SEEDED
    )


def test_zero_filled_fixed_array_is_convicted() -> None:
    assert (
        _flow("byte[] seed = new byte[32]; SecureRandom sr = new SecureRandom(seed);")
        is SeedFlow.LITERAL_SEEDED
    )


def test_convicts_through_a_simple_alias() -> None:
    assert (
        _flow(
            'byte[] a = "k".getBytes(); byte[] b = a; SecureRandom sr = new SecureRandom(b);'
        )
        is SeedFlow.LITERAL_SEEDED
    )


def test_approved_entropy_source_is_clean() -> None:
    assert (
        _flow(
            "byte[] seed = SecureRandom.getInstanceStrong().generateSeed(32);"
            "SecureRandom sr = new SecureRandom(seed);"
        )
        is SeedFlow.CLEAN
    )


def test_seed_from_a_parameter_is_not_convicted() -> None:
    # a non-constant provenance is out of the bounded scope, not a false positive.
    assert _flow("SecureRandom sr = new SecureRandom(ct);") is SeedFlow.CLEAN


def test_parse_error_is_indeterminate() -> None:
    assert classify_seed_provenance("class C { void m( { oops }") is SeedFlow.INDETERMINATE


def _patch(diff: str, site: Site) -> Patch:
    return Patch(
        site_id=site.site_id,
        attempt=1,
        unified_diff=diff,
        claimed_primitive="ML-KEM-768",
        claimed_parameters="",
        backend_id="test",
        prompt_version="test",
        response_hash="0" * 64,
    )


def test_rule_errors_when_patched_source_cannot_be_parsed() -> None:
    site = Site(
        site_id="rand#err",
        repo="fixtures",
        file_path=str(_BASE),
        line=6,
        usage_class=UsageClass.KEM,
        matched_symbol="SecureRandom",
        detector_rule_id="test",
    )
    broken = (
        "--- a/base.java\n+++ b/base.java\n@@ -7,1 +7,1 @@\n"
        "-        return sr;\n+        return sr  // unterminated\n"
    )
    outcome = get("PQ-RAND-03").check(_patch(broken, site), site, _POLICY)
    assert outcome.status is RuleStatus.ERROR


_POLICY = Policy(
    name="test",
    version="v1",
    floors={UsageClass.KEM: "ML-KEM-768"},
    hybrid_required={},
    allowed_randomness_sources=("SecureRandom",),
)

_ORIGINAL = """\
class KeyGen {
    KeyPair make(byte[] entropy) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        byte[] seed = entropy;
        SecureRandom sr = new SecureRandom(seed);
        kpg.initialize(2048, sr);
        return kpg.generateKeyPair();
    }
}
"""

# Migrated to ML-KEM (PQ-MIG-01 satisfied), and the seed is a literal, but routed
# through a variable so L1's PQ-RAND-02 (which only sees a literal *directly* in
# the constructor) does not fire. L2 tracks the provenance and rejects.
_LITERAL_SEEDED = """\
class KeyGen {
    KeyPair make(byte[] entropy) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768");
        byte[] seed = "test-seed-value".getBytes();
        SecureRandom sr = new SecureRandom(seed);
        kpg.initialize(2048, sr);
        return kpg.generateKeyPair();
    }
}
"""


def test_l1_passes_the_variable_routed_seed_but_l2_rejects_it(tmp_path: Path) -> None:
    src = tmp_path / "KeyGen.java"
    src.write_text(_ORIGINAL, encoding="utf-8")
    site = Site(
        site_id="rand#1",
        repo="fixtures",
        file_path=str(src),
        line=3,
        usage_class=UsageClass.KEM,
        matched_symbol="KeyPairGenerator.getInstance",
        detector_rule_id="test",
    )
    patch = _patch(make_diff(_ORIGINAL, _LITERAL_SEEDED, str(src)), site)

    l1_only = verify_patch(patch, site, _POLICY, enabled_layers=frozenset({Layer.L1_SYNTACTIC}))
    assert l1_only.status is VerdictStatus.ACCEPT

    l1_l2 = verify_patch(
        patch,
        site,
        _POLICY,
        enabled_layers=frozenset({Layer.L1_SYNTACTIC, Layer.L2_DATAFLOW}),
    )
    assert l1_l2.status is VerdictStatus.REJECT
    assert l1_l2.rejected_rule_id == "PQ-RAND-03"
