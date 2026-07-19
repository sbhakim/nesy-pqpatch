// Tier-1 case: quantum-vulnerable ECDSA verification (CryptoAPI-Bench idiom).
// A correct migration moves verification to ML-DSA and must keep acting on the
// verify() result. See case.yaml.
import java.security.PublicKey;
import java.security.Signature;

public class EcdsaVerifyExample {

    public boolean verify(byte[] data, byte[] sig, PublicKey key) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(key);
        verifier.update(data);
        boolean ok = verifier.verify(sig);
        return ok;
    }
}
