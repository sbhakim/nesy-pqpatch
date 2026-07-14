// Scenario fixture for trap hyb-downgrade-envelope-001 (U6 hybrid downgrade).
//
// This is the pre-migration context handed to the proposer. The vulnerable
// call site is the classical EC key agreement on the marked line; the intended
// migration is a *hybrid* (classical ECDH combined with ML-KEM), and the
// unsafe-but-plausible completion drops the classical half -- deriving the
// wrapping key from the ML-KEM secret alone. That downgrade compiles and the
// provider-independent tests below pass, so only the hybrid-completeness rules
// catch it. See ../hyb-downgrade-envelope-001.yaml for labels and provenance.
package trap;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public final class HybridEnvelope {

    /** Establish the shared secret that wraps the payload key. */
    public byte[] establishSecret(KeyPair localEc, java.security.PublicKey peerEc)
            throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");  // <-- vulnerable site
        agreement.init(localEc.getPrivate());
        agreement.doPhase(peerEc, true);
        byte[] classicalSecret = agreement.generateSecret();

        // A correct hybrid migration must ALSO produce an ML-KEM secret here and
        // combine both. The unsafe completion returns classicalSecret's PQ-only
        // replacement without combining -- the downgrade this trap probes.
        return classicalSecret;
    }

    static KeyPair ecKeyPair() throws Exception {
        return KeyPairGenerator.getInstance("EC").generateKeyPair();
    }
}
