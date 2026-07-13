"""Boundary semantics and orchestration for the L2 hybrid-completeness rule.

`classify_hybrid_flow` engages only when a method produces both a classical
(`generateSecret`) and a post-quantum (`decapsulate`) shared secret, and
convicts only when no single expression combines them. The load-bearing
orchestrator test shows the "beyond tokens" contribution: a patch whose added
text carries both an ML-KEM and an X25519 token passes L1's token-level
`PQ-HYB-01`, while L2 still catches that the flow drops the PQ component.
"""

from __future__ import annotations

from pathlib import Path

from pqpatch.model import Layer, Patch, Policy, RuleStatus, Site, UsageClass, VerdictStatus
from pqpatch.verifier.api import verify_patch
from pqpatch.verifier.l2_dataflow.java_flow import HybridFlow, classify_hybrid_flow
from pqpatch.verifier.rules.registry import get
from tests.support.diffgen import make_diff

_FIXTURE_DIR = (
    Path(__file__).resolve().parents[1].parent
    / "src"
    / "pqpatch"
    / "verifier"
    / "l2_dataflow"
    / "fixtures"
    / "PQ-HYB-02"
)
_BASE = _FIXTURE_DIR / "base.java"


def _flow(body: str) -> HybridFlow:
    src = (
        "class C { byte[] m(KeyAgreement ka, Object dec, byte[] ct) throws Exception {\n"
        + body
        + "\n}}"
    )
    return classify_hybrid_flow(src)


def test_both_secrets_into_one_combiner_is_complete() -> None:
    assert (
        _flow(
            "byte[] ec = ka.generateSecret();"
            "byte[] pq = dec.decapsulate(ct);"
            "return hkdf(concat(ec, pq));"
        )
        is HybridFlow.COMPLETE
    )


def test_dropping_the_pq_secret_is_a_downgrade() -> None:
    assert (
        _flow(
            "byte[] ec = ka.generateSecret();"
            "byte[] pq = dec.decapsulate(ct);"
            "return hkdf(ec);"
        )
        is HybridFlow.DOWNGRADED
    )


def test_pq_used_elsewhere_but_never_combined_is_still_a_downgrade() -> None:
    assert (
        _flow(
            "byte[] ec = ka.generateSecret();"
            "byte[] pq = dec.decapsulate(ct);"
            "log(pq);"
            "return hkdf(ec);"
        )
        is HybridFlow.DOWNGRADED
    )


def test_single_family_is_not_a_hybrid_context() -> None:
    # only a classical secret: this is PQ-HYB-01's token-level job at L1.
    assert _flow("byte[] ec = ka.generateSecret(); return hkdf(ec);") is HybridFlow.NOT_HYBRID


def test_combine_through_a_simple_alias_is_complete() -> None:
    assert (
        _flow(
            "byte[] ec = ka.generateSecret();"
            "byte[] a = ec;"
            "byte[] pq = dec.decapsulate(ct);"
            "return hkdf(combine(a, pq));"
        )
        is HybridFlow.COMPLETE
    )


def test_parse_error_is_indeterminate() -> None:
    assert classify_hybrid_flow("class C { void m( { oops }") is HybridFlow.INDETERMINATE


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
        site_id="hyb#err",
        repo="fixtures",
        file_path=str(_BASE),
        line=7,
        usage_class=UsageClass.KEM,
        matched_symbol="KeyAgreement",
        detector_rule_id="test",
    )
    broken = (
        "--- a/base.java\n+++ b/base.java\n@@ -8,1 +8,1 @@\n"
        "-        return hkdf(combined);\n+        return hkdf(combined  // unterminated\n"
    )
    outcome = get("PQ-HYB-02").check(_patch(broken, site), site, _POLICY)
    assert outcome.status is RuleStatus.ERROR


_POLICY = Policy(
    name="test",
    version="v1",
    floors={UsageClass.KEM: "ML-KEM-768"},
    hybrid_required={UsageClass.KEM: True},
    allowed_randomness_sources=("SecureRandom",),
)

_ORIGINAL = """\
class Hybrid {
    byte[] derive(KeyAgreement ka, Object dec, byte[] ct) throws Exception {
        byte[] ecSecret = ka.generateSecret();
        byte[] pqSecret = agree("ECDH", ct);
        return hkdf(concat(ecSecret, pqSecret));
    }
    static byte[] concat(byte[] a, byte[] b) { return a; }
    static byte[] hkdf(byte[] x) { return x; }
    static byte[] agree(String alg, byte[] ct) { return ct; }
}
"""

# Migrated so the added text carries both an ML-KEM and an X25519 token (L1's
# PQ-HYB-01 and PQ-MIG-01 are satisfied), but the flow feeds only ecSecret to the
# combiner -- the PQ contribution is silently dropped.
_DOWNGRADED = """\
class Hybrid {
    byte[] derive(KeyAgreement ka, Decapsulator dec, byte[] ct) throws Exception {
        byte[] ecSecret = ka.generateSecret();
        byte[] pqSecret = dec.decapsulate(ct); // X25519 + ML-KEM-768 hybrid
        return hkdf(concat(ecSecret, ecSecret));
    }
    static byte[] concat(byte[] a, byte[] b) { return a; }
    static byte[] hkdf(byte[] x) { return x; }
    static byte[] agree(String alg, byte[] ct) { return ct; }
}
"""


def test_l1_token_check_passes_but_l2_rejects_the_flow_downgrade(tmp_path: Path) -> None:
    src = tmp_path / "Hybrid.java"
    src.write_text(_ORIGINAL, encoding="utf-8")
    site = Site(
        site_id="hyb#1",
        repo="fixtures",
        file_path=str(src),
        line=4,
        usage_class=UsageClass.KEM,
        matched_symbol="KeyAgreement.generateSecret",
        detector_rule_id="test",
    )
    patch = _patch(make_diff(_ORIGINAL, _DOWNGRADED, str(src)), site)

    l1_only = verify_patch(patch, site, _POLICY, enabled_layers=frozenset({Layer.L1_SYNTACTIC}))
    assert l1_only.status is VerdictStatus.ACCEPT

    l1_l2 = verify_patch(
        patch,
        site,
        _POLICY,
        enabled_layers=frozenset({Layer.L1_SYNTACTIC, Layer.L2_DATAFLOW}),
    )
    assert l1_l2.status is VerdictStatus.REJECT
    assert l1_l2.rejected_rule_id == "PQ-HYB-02"
