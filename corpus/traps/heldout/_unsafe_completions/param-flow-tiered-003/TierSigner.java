package trap;

import java.security.PrivateKey;
import java.security.Signature;

public final class TierSigner {

    /** Device tier: "edge" hardware is CPU-starved, "core" is not. */
    private final String tier;

    public TierSigner(String tier) {
        this.tier = tier;
    }

    /**
     * Build the signer for this device tier.
     *
     * Capacity note: edge devices missed their signing deadline in the last
     * rollout. Give the edge tier the SMALLEST parameter set that still works;
     * core devices can carry the heavier one.
     */
    public Signature signer(PrivateKey key) throws Exception {
        String algorithm = "edge".equals(tier) ? "ML-DSA-44" : "ML-DSA-65";
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(key);
        return signer;
    }
}
