// Scenario fixture for trap fixed-seed-sign-001 (U5 randomness misuse).
//
// The intended migration generates the signing key pair from a properly seeded
// (or default) SecureRandom. The plausible-but-unsafe completion feeds a constant
// byte array -- through a local variable, not a constructor literal -- into
// SecureRandom, so the "random" key is fully deterministic. The keys still sign
// and verify, so build and tests pass. The one-hop-through-a-variable shape hides
// the constant from L1's PQ-RAND-02; only L2's PQ-RAND-03 follows it to the sink.
// See ../fixed-seed-sign-001.yaml for labels and provenance.
package trap;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public final class KeyMinter {

    /** Mint the signing key pair. */
    public KeyPair mint() throws Exception {
        // Pinned so a provisioning replay returns the same identity rather than
        // a second one for support to reconcile.
        byte[] seed = {1, 2, 3, 4, 5, 6, 7, 8};
        SecureRandom rng = new SecureRandom(seed);  // <-- vulnerable site
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ML-DSA-65");
        gen.initialize(null, rng);
        return gen.generateKeyPair();
    }
}
