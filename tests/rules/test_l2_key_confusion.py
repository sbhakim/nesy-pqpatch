"""Boundary semantics and orchestration for the L2 cross-family key rule.

`classify_key_flow` convicts only an unambiguous cross-family flow; the
load-bearing orchestrator test proves the L1->L2 escalation boundary the
paper claims: L1 *defers* when both families appear (PQ-KEY-01 cannot decide),
and L2 catches the actual key flow that L1 alone would accept.
"""

from __future__ import annotations

from pathlib import Path

from pqpatch.model import Layer, Patch, Policy, RuleStatus, Site, UsageClass, VerdictStatus
from pqpatch.verifier.api import verify_patch
from pqpatch.verifier.l2_dataflow.java_flow import KeyFlow, classify_key_flow
from pqpatch.verifier.rules.registry import get

_FIXTURE_DIR = (
    Path(__file__).resolve().parents[1].parent
    / "src"
    / "pqpatch"
    / "verifier"
    / "l2_dataflow"
    / "fixtures"
    / "PQ-KEY-02"
)
_BASE = _FIXTURE_DIR / "base.java"
_VIOLATING = _FIXTURE_DIR / "violating" / "kem_key_into_signature.diff"


def _flow(body: str) -> KeyFlow:
    return classify_key_flow("class C { void m() throws Exception {\n" + body + "\n}}")


def test_kem_key_into_signature_is_cross_family() -> None:
    assert (
        _flow(
            'KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();'
            'Signature sig = Signature.getInstance("ML-DSA-65");'
            "sig.initSign(kp.getPrivate());"
        )
        is KeyFlow.CROSS_FAMILY
    )


def test_signature_key_into_signature_is_consistent() -> None:
    assert (
        _flow(
            'KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65").generateKeyPair();'
            'Signature sig = Signature.getInstance("ML-DSA-65");'
            "sig.initSign(kp.getPrivate());"
        )
        is KeyFlow.CONSISTENT
    )


def test_cross_family_is_followed_through_a_simple_alias() -> None:
    assert (
        _flow(
            'KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();'
            "PrivateKey pk = kp.getPrivate();"
            'Signature sig = Signature.getInstance("ML-DSA-65");'
            "sig.initSign(pk);"
        )
        is KeyFlow.CROSS_FAMILY
    )


def test_correct_hybrid_keeps_each_key_in_its_own_family() -> None:
    assert (
        _flow(
            'KeyPair ek = KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();'
            'KeyAgreement ka = KeyAgreement.getInstance("ML-KEM-768");'
            "ka.doPhase(ek.getPublic(), true);"
            'KeyPair sk = KeyPairGenerator.getInstance("ML-DSA-65").generateKeyPair();'
            'Signature sig = Signature.getInstance("ML-DSA-65");'
            "sig.initSign(sk.getPrivate());"
        )
        is KeyFlow.CONSISTENT
    )


def test_classical_ambiguous_source_is_not_convicted() -> None:
    # "EC" is genuinely ambiguous (ECDSA vs ECDH); the bounded rule refuses to
    # guess a family for it rather than risk a false rejection.
    assert (
        _flow(
            'KeyPair kp = KeyPairGenerator.getInstance("EC").generateKeyPair();'
            'Signature sig = Signature.getInstance("ML-DSA-65");'
            "sig.initSign(kp.getPrivate());"
        )
        is KeyFlow.CONSISTENT
    )


def test_interprocedural_split_is_out_of_bounded_scope() -> None:
    src = (
        "class C {"
        '  KeyPair make() throws Exception { return KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair(); }'  # noqa: E501
        "  void use(PrivateKey pk) throws Exception {"
        '    Signature sig = Signature.getInstance("ML-DSA-65");'
        "    sig.initSign(pk);"
        "  }"
        "}"
    )
    assert classify_key_flow(src) is KeyFlow.CONSISTENT


def test_parse_error_is_indeterminate() -> None:
    assert classify_key_flow("class C { void m( { oops }") is KeyFlow.INDETERMINATE


def _patch(diff: str, site: Site) -> Patch:
    return Patch(
        site_id=site.site_id,
        attempt=1,
        unified_diff=diff,
        claimed_primitive="ML-DSA-65",
        claimed_parameters="",
        backend_id="test",
        prompt_version="test",
        response_hash="0" * 64,
    )


def _sign_site() -> Site:
    return Site(
        site_id="key-conf#1",
        repo="fixtures",
        file_path=str(_BASE),
        line=7,
        usage_class=UsageClass.SIGN,
        matched_symbol="Signature.getInstance",
        detector_rule_id="test",
    )


_POLICY = Policy(
    name="test",
    version="v1",
    floors={UsageClass.SIGN: "ML-DSA-65"},
    hybrid_required={},
    allowed_randomness_sources=("SecureRandom",),
)


def test_rule_errors_when_patched_source_cannot_be_parsed() -> None:
    site = _sign_site()
    # A diff that applies but yields unparseable Java -> ERROR, not silent PASS.
    broken = (
        "--- a/base.java\n+++ b/base.java\n@@ -9,1 +9,1 @@\n"
        "-        return sig.sign();\n+        return sig.sign(  // unterminated\n"
    )
    outcome = get("PQ-KEY-02").check(_patch(broken, site), site, _POLICY)
    assert outcome.status is RuleStatus.ERROR


def test_l1_defers_but_l1_plus_l2_rejects_the_cross_family_migration() -> None:
    """The paper's escalation boundary, made executable: with both families
    present L1 cannot decide (PQ-KEY-01 defers) and accepts, while L1+L2
    rejects the actual EC/KEM-into-signature flow at PQ-KEY-02."""
    site = _sign_site()
    patch = _patch(_VIOLATING.read_text(encoding="utf-8"), site)

    l1_only = verify_patch(patch, site, _POLICY, enabled_layers=frozenset({Layer.L1_SYNTACTIC}))
    assert l1_only.status is VerdictStatus.ACCEPT

    l1_l2 = verify_patch(
        patch,
        site,
        _POLICY,
        enabled_layers=frozenset({Layer.L1_SYNTACTIC, Layer.L2_DATAFLOW}),
    )
    assert l1_l2.status is VerdictStatus.REJECT
    assert l1_l2.rejected_rule_id == "PQ-KEY-02"
