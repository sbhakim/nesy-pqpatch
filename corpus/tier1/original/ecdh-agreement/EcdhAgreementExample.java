// Tier-1 case: quantum-vulnerable ECDH key agreement (CryptoAPI-Bench idiom).
// A correct migration for a KEM/agreement site requires a hybrid construction
// (both classical and ML-KEM contributions reaching a KDF). See case.yaml.
import javax.crypto.KeyAgreement;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class EcdhAgreementExample {

    public byte[] deriveSecret(PrivateKey priv, PublicKey peer) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(priv);
        agreement.doPhase(peer, true);
        return agreement.generateSecret();
    }
}
