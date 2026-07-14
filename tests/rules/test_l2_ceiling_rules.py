"""Load-bearing orchestrator tests for the final three T0 L2 rules.

For each of PQ-VER-02 (U3 OR-bypass), PQ-RAND-04 (U5 constant seed before
first use), and PQ-HYB-03 (U6 raw combined secret): a realistic migration that
every L1 rule and every earlier L2 rule accepts, rejected precisely at the new
rule. These complete the T0/T1 slice at 8 L2 rules.
"""

from __future__ import annotations

from pathlib import Path

from pqpatch.model import Layer, Patch, Policy, Site, UsageClass, VerdictStatus
from pqpatch.verifier.api import verify_patch
from tests.support.diffgen import make_diff

_POLICY = Policy(
    name="test",
    version="v1",
    floors={UsageClass.KEM: "ML-KEM-768", UsageClass.VERIFY: "ML-DSA-65"},
    hybrid_required={},
    allowed_randomness_sources=("SecureRandom",),
)

_L1_ONLY = frozenset({Layer.L1_SYNTACTIC})
_L1_L2 = frozenset({Layer.L1_SYNTACTIC, Layer.L2_DATAFLOW})


def _run(tmp_path: Path, original: str, patched: str, usage: UsageClass, line: int):
    src = tmp_path / "Case.java"
    src.write_text(original, encoding="utf-8")
    site = Site(
        site_id="ceiling#1",
        repo="fixtures",
        file_path=str(src),
        line=line,
        usage_class=usage,
        matched_symbol="getInstance",
        detector_rule_id="test",
    )
    patch = Patch(
        site_id=site.site_id,
        attempt=1,
        unified_diff=make_diff(original, patched, str(src)),
        claimed_primitive="test",
        claimed_parameters="",
        backend_id="test",
        prompt_version="test",
        response_hash="0" * 64,
    )
    return (
        verify_patch(patch, site, _POLICY, enabled_layers=_L1_ONLY),
        verify_patch(patch, site, _POLICY, enabled_layers=_L1_L2),
    )


def test_or_bypass_passes_l1_and_ver01_but_fails_ver02(tmp_path: Path) -> None:
    original = """\
class Checker {
    boolean check(byte[] data, byte[] sigBytes, PublicKey key, boolean trusted)
            throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(sigBytes);
    }
}
"""
    patched = """\
class Checker {
    boolean check(byte[] data, byte[] sigBytes, PublicKey key, boolean trusted)
            throws Exception {
        Signature sig = Signature.getInstance("ML-DSA-65");
        sig.initVerify(key);
        sig.update(data);
        boolean valid = sig.verify(sigBytes);
        if (valid || trusted) {
            return true;
        }
        return false;
    }
}
"""
    l1, l1l2 = _run(tmp_path, original, patched, UsageClass.VERIFY, 4)
    assert l1.status is VerdictStatus.ACCEPT
    assert l1l2.status is VerdictStatus.REJECT
    assert l1l2.rejected_rule_id == "PQ-VER-02"


def test_constant_prng_seed_passes_all_earlier_rules_but_fails_rand04(tmp_path: Path) -> None:
    original = """\
class KeyMaker {
    byte[] make(byte[] buf) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(buf);
        return buf;
    }
}
"""
    patched = """\
class KeyMaker {
    byte[] make(byte[] buf) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("ML-KEM-768");
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(20260714L);
        sr.nextBytes(buf);
        return buf;
    }
}
"""
    l1, l1l2 = _run(tmp_path, original, patched, UsageClass.KEM, 3)
    assert l1.status is VerdictStatus.ACCEPT  # PQ-RAND-02 defers all setSeed cases
    assert l1l2.status is VerdictStatus.REJECT
    assert l1l2.rejected_rule_id == "PQ-RAND-04"


def test_raw_hybrid_concat_passes_hyb02_but_fails_hyb03(tmp_path: Path) -> None:
    original = """\
class Channel {
    byte[] shared(PrivateKey mine, PublicKey theirs) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(mine);
        ka.doPhase(theirs, true);
        return ka.generateSecret();
    }

    static byte[] concat(byte[] a, byte[] b) {
        return a;
    }
}
"""
    patched = """\
class Channel {
    byte[] shared(PrivateKey mine, PublicKey theirs, Decapsulator dec, byte[] ct)
            throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(mine);
        ka.doPhase(theirs, true);
        byte[] ec = ka.generateSecret();
        byte[] pq = dec.decapsulate(ct); // ML-KEM-768 hybrid
        return concat(ec, pq);
    }

    static byte[] concat(byte[] a, byte[] b) {
        return a;
    }
}
"""
    l1, l1l2 = _run(tmp_path, original, patched, UsageClass.KEM, 3)
    assert l1.status is VerdictStatus.ACCEPT
    # both secrets DO reach one combiner, so PQ-HYB-02 passes; the defect is
    # that the combination is returned raw, never derived.
    assert l1l2.status is VerdictStatus.REJECT
    assert l1l2.rejected_rule_id == "PQ-HYB-03"
