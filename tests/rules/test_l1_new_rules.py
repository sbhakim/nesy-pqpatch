"""False-positive boundary tests for the seven L1 rules added 2026-07-14.

Each rule's fixtures prove it fires and passes; these tests pin the *edges* —
the nearby-but-legitimate shapes each rule must not convict, so growing the
rule count cannot quietly buy recall with false rejections.
"""

from __future__ import annotations

from pqpatch.model import Patch, Policy, RuleStatus, Site, UsageClass
from pqpatch.verifier.rules.registry import get

_SITE = Site(
    site_id="boundary-site",
    repo="fixtures",
    file_path="src/Example.java",
    line=1,
    usage_class=UsageClass.SIGN,
    matched_symbol="Signature.getInstance",
    detector_rule_id="fixture",
)

_POLICY = Policy(
    name="fixture",
    version="v1",
    floors={UsageClass.SIGN: "ML-DSA-65"},  # category rank 3
    hybrid_required={},
    allowed_randomness_sources=("SecureRandom",),
)


def _check(rule_id: str, added: str) -> RuleStatus:
    diff = (
        "--- a/src/Example.java\n+++ b/src/Example.java\n@@ -1 +1,"
        + str(1 + added.count("\n"))
        + " @@\n-old\n+"
        + added.replace("\n", "\n+")
        + "\n"
    )
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
    return get(rule_id).check(patch, _SITE, _POLICY).status


# --- PQ-PARAM-03 (SLH-DSA floor) --------------------------------------------


def test_slh_at_the_floor_category_passes() -> None:
    # floor ML-DSA-65 is rank 3; SLH-DSA-192 is also rank 3 -> at floor, not below
    assert _check("PQ-PARAM-03", 'Signature.getInstance("SLH-DSA-SHAKE-192f");') is RuleStatus.PASS


def test_mldsa_tokens_are_not_the_slh_rules_business() -> None:
    # below-floor ML-DSA is PQ-PARAM-01's conviction, not PQ-PARAM-03's
    assert _check("PQ-PARAM-03", 'Signature.getInstance("ML-DSA-44");') is RuleStatus.PASS


# --- PQ-PARAM-04 (nonstandard parameter set) ---------------------------------


def test_every_defined_set_is_valid() -> None:
    for token in ("ML-KEM-512", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-87"):
        assert _check("PQ-PARAM-04", f'getInstance("{token}");') is RuleStatus.PASS


def test_hallucinated_mldsa_set_is_invalid() -> None:
    assert _check("PQ-PARAM-04", 'Signature.getInstance("ML-DSA-128");') is RuleStatus.FAIL


def test_defined_slh_set_is_valid() -> None:
    assert _check("PQ-PARAM-04", 'Signature.getInstance("SLH-DSA-SHA2-192s");') is RuleStatus.PASS


# --- PQ-PARAM-05 (classical key-size downgrade) ------------------------------


def test_2048_and_above_pass() -> None:
    assert _check("PQ-PARAM-05", "kpg.initialize(2048);") is RuleStatus.PASS
    assert _check("PQ-PARAM-05", "kpg.initialize(4096, random);") is RuleStatus.PASS


def test_ec_named_curve_sizes_are_not_convicted() -> None:
    # 256/384/521 are EC curve sizes, legitimate classical margins
    assert _check("PQ-PARAM-05", "kpg.initialize(256);") is RuleStatus.PASS


def test_weak_size_with_random_argument_is_convicted() -> None:
    assert _check("PQ-PARAM-05", "kpg.initialize(1024, random);") is RuleStatus.FAIL


# --- PQ-FALL-03 (runtime toggle) ---------------------------------------------


def test_ternary_between_two_pq_sets_is_not_a_classical_fallback() -> None:
    # a PQ/PQ selection is PARAM floor territory, not a classical fallback
    assert (
        _check("PQ-FALL-03", 'String a = big ? "ML-KEM-1024" : "ML-KEM-768";') is RuleStatus.PASS
    )


def test_ternary_without_any_pq_token_is_not_this_rules_business() -> None:
    # purely classical code never migrated: PQ-MIG-01's obligation, not a toggle
    assert _check("PQ-FALL-03", 'String a = flag ? "RSA" : "AES";') is RuleStatus.PASS


def test_toggle_with_mldsa_and_rsa_is_convicted() -> None:
    assert _check("PQ-FALL-03", 'String a = legacy ? "RSA" : "ML-DSA-65";') is RuleStatus.FAIL


# --- PQ-FALL-04 (getInstance inside catch) -----------------------------------


def test_getinstance_before_the_catch_is_fine() -> None:
    added = (
        'Signature sig = Signature.getInstance("ML-DSA-65");\n'
        "try {\n"
        "    sig.initSign(key);\n"
        "} catch (InvalidKeyException e) {\n"
        "    throw new IllegalStateException(e);\n"
        "}"
    )
    assert _check("PQ-FALL-04", added) is RuleStatus.PASS


def test_even_a_pq_retry_inside_catch_is_convicted() -> None:
    added = (
        "try {\n"
        '    KeyEncapsulation.getInstance("ML-KEM-1024");\n'
        "} catch (NoSuchAlgorithmException e) {\n"
        '    KeyEncapsulation.getInstance("ML-KEM-512");\n'
        "}"
    )
    assert _check("PQ-FALL-04", added) is RuleStatus.FAIL


# --- PQ-EXC-01 (catch returns success) -----------------------------------------


def test_return_true_outside_any_catch_is_fine() -> None:
    assert _check("PQ-EXC-01", "if (ok) { return true; }") is RuleStatus.PASS


def test_catch_returning_false_fails_closed_and_passes() -> None:
    added = (
        "try {\n    return sig.verify(s);\n"
        "} catch (SignatureException e) {\n    return false;\n}"
    )
    assert _check("PQ-EXC-01", added) is RuleStatus.PASS


# --- PQ-EXC-02 (log-only swallow) ---------------------------------------------


def test_log_then_rethrow_is_not_a_swallow() -> None:
    added = (
        "try {\n"
        "    sig.update(data);\n"
        "} catch (SignatureException e) {\n"
        "    e.printStackTrace();\n"
        "    throw new IllegalStateException(e);\n"
        "}"
    )
    assert _check("PQ-EXC-02", added) is RuleStatus.PASS


def test_logger_call_only_is_a_swallow() -> None:
    added = (
        "try {\n"
        "    sig.update(data);\n"
        "} catch (SignatureException e) {\n"
        '    logger.error("verify failed", e);\n'
        "}"
    )
    assert _check("PQ-EXC-02", added) is RuleStatus.FAIL
