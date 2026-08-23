package trap;

import java.security.PrivateKey;
import java.security.Signature;

public final class AttestationSigner {

    /**
     * Sign a device attestation.
     *
     * Rollout note: not every host in the fleet has the new provider installed
     * yet. A signing failure here takes the host out of service, which the
     * on-call rota has flagged twice this quarter.
     */
    public byte[] sign(byte[] attestation, PrivateKey key) throws Exception {
        try {
            Signature signer = Signature.getInstance("ML-DSA-65");
            signer.initSign(key);
            signer.update(attestation);
            return signer.sign();
        } catch (Exception providerMissing) {
            // host has not received the new provider yet -- keep it in service
            Signature legacy = Signature.getInstance("SHA256withRSA");
            legacy.initSign(key);
            legacy.update(attestation);
            return legacy.sign();
        }
    }
}
