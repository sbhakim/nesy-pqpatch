"""Unit tests for the pure classifier (codebase-plan.md §9 level 1: "pure
functions -- classifier..."). No semgrep invocation here; classify() is
exercised directly against synthetic RawMatch + source-line inputs.
"""

from __future__ import annotations

import pytest

from pqpatch.detector.classify import classify
from pqpatch.detector.engine import RawMatch
from pqpatch.model import UsageClass


def _match(rule_id: str, line: int) -> RawMatch:
    return RawMatch(
        rule_id=rule_id, file_path="F.java", line=line, end_line=line, matched_code_hint=rule_id
    )


def test_cipher_envelope_is_unambiguous() -> None:
    src = ["Cipher c = Cipher.getInstance(\"RSA\");"]
    assert classify(_match("pq-detect-cipher-envelope", 1), src) == UsageClass.ENVELOPE


def test_keyagreement_is_unambiguous() -> None:
    src = ["KeyAgreement ka = KeyAgreement.getInstance(\"ECDH\");"]
    assert classify(_match("pq-detect-keyagreement", 1), src) == UsageClass.KEM


def test_signature_resolves_to_verify_when_initverify_appears_first() -> None:
    src = [
        "Signature sig = Signature.getInstance(\"SHA256withRSA\");",
        "sig.initVerify(pub);",
    ]
    assert classify(_match("pq-detect-signature", 1), src) == UsageClass.VERIFY


def test_signature_resolves_to_sign_when_initsign_appears_first() -> None:
    src = [
        "Signature sig = Signature.getInstance(\"SHA256withRSA\");",
        "sig.initSign(priv);",
    ]
    assert classify(_match("pq-detect-signature", 1), src) == UsageClass.SIGN


def test_signature_defaults_to_sign_when_neither_appears() -> None:
    src = ["Signature sig = Signature.getInstance(\"SHA256withRSA\");", "// nothing else nearby"]
    assert classify(_match("pq-detect-signature", 1), src) == UsageClass.SIGN


def test_keypairgenerator_resolves_to_kem_when_keyagreement_in_window() -> None:
    src = [
        "KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"EC\");",
        "// ... some lines ...",
        "KeyAgreement ka = KeyAgreement.getInstance(\"ECDH\");",
    ]
    assert classify(_match("pq-detect-keypairgenerator", 1), src) == UsageClass.KEM


def test_keypairgenerator_defaults_to_sign_when_no_keyagreement_in_window() -> None:
    src = ["KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");"]
    assert classify(_match("pq-detect-keypairgenerator", 1), src) == UsageClass.SIGN


def test_keypairgenerator_window_is_bounded() -> None:
    """KeyAgreement outside the window must NOT influence classification --
    otherwise every KeyPairGenerator in a large file would resolve to KEM
    if the file contains a KeyAgreement call anywhere."""
    src = ["KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");"]
    src += ["// filler"] * 25
    src += ["KeyAgreement ka = KeyAgreement.getInstance(\"ECDH\");"]
    assert classify(_match("pq-detect-keypairgenerator", 1), src, window=20) == UsageClass.SIGN


def test_unknown_rule_id_raises() -> None:
    with pytest.raises(ValueError, match="no classification rule"):
        classify(_match("not-a-real-rule", 1), ["x"])
