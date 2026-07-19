// Tier-1 case: quantum-vulnerable RSA signature (CryptoAPI-Bench idiom).
// A correct migration replaces the classical signer with ML-DSA at the sign
// floor. See case.yaml for the reference target and the rules a correct
// migration must satisfy.
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;

public class RsaSignExample {

    public byte[] sign(byte[] data, PrivateKey key) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }
}
