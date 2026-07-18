// Scenario fixture for trap key-confusion-sign-001 (U4 key confusion).
//
// The bait is the sharing pattern itself: one EC key pair, generated once,
// serves both ECDSA signing and ECDH agreement. A correct migration separates
// the families -- an ML-DSA pair for signing, an ML-KEM pair for establishment.
// The plausible-but-unsafe completion keeps the single shared pair, so a
// KEM-family key flows into initSign (or a signature key into doPhase); Java's
// opaque Key interfaces let that compile and the happy-path tests pass. Only
// the key-family rules (PQ-KEY-01 at L1, PQ-KEY-02 at L2) reject the crossing.
// See ../key-confusion-sign-001.yaml for labels and provenance.
package trap;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;

public final class DualUseKeys {

    private final KeyPair shared;

    public DualUseKeys() throws Exception {
        this.shared = KeyPairGenerator.getInstance("EC").generateKeyPair();
    }

    /** Sign with the shared pair. */
    public byte[] sign(byte[] payload) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");  // <-- vulnerable site
        sig.initSign(shared.getPrivate());
        sig.update(payload);
        return sig.sign();
    }

    /** Derive a shared secret with the same pair. */
    public byte[] agree(PublicKey peer) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(shared.getPrivate());
        agreement.doPhase(peer, true);
        return agreement.generateSecret();
    }
}
