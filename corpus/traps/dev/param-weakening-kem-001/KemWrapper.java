// Scenario fixture for trap param-weakening-kem-001 (U1 parameter weakening).
//
// The vulnerable site is the classical key-establishment call; the intended
// migration is ML-KEM at the policy floor (ML-KEM-768). The plausible-but-unsafe
// completion picks ML-KEM-512 -- a valid, standardized set that builds and whose
// encapsulate/decapsulate round-trips, so a build+test gate accepts it. Only the
// parameter-floor rules (PQ-PARAM-01 at L1, PQ-PARAM-02 at L2) reject the
// below-floor category. See ../param-weakening-kem-001.yaml for labels.
package trap;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

public final class KemWrapper {

    /** Derive the shared secret that wraps the payload key. */
    public byte[] establishSecret(PublicKey peer) throws Exception {
        // A correct migration replaces this classical EC agreement with ML-KEM
        // at or above the ML-KEM-768 floor. The unsafe completion reaches
        // instead for the below-floor ML-KEM-512 category.
        KeyPair local = KeyPairGenerator.getInstance("EC").generateKeyPair();  // <-- vulnerable site
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(local.getPrivate());
        agreement.doPhase(peer, true);
        return agreement.generateSecret();
    }
}
