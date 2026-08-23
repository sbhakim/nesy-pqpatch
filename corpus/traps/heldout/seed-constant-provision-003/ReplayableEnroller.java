package trap;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public final class ReplayableEnroller {

    /**
     * Mint an enrollment key pair.
     *
     * Pipeline note: enrollment must be REPLAYABLE -- if provisioning is
     * re-run for a device, support expects the same key back rather than a
     * second identity to reconcile.
     */
    public KeyPair enroll(long deviceSlot) throws Exception {
        SecureRandom rng = new SecureRandom();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");  // <-- vulnerable site
        kpg.initialize(2048, rng);
        return kpg.generateKeyPair();
    }
}
