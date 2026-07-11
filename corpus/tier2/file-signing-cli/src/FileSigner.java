import java.security.*;
import java.util.Properties;
import javax.crypto.*;

/**
 * Tier-2 reference application #1: file-signing CLI.
 *
 * Seeded with quantum-vulnerable JCA sites across four detectable usage
 * classes (SIGN, VERIFY, KEM, ENVELOPE), plus one deliberately hard,
 * configuration-driven site that the current literal-pattern detector
 * cannot see -- ground truth for both is in sites.yaml.
 */
public class FileSigner {

    // site: SIGN (paired with initSign below -> classify.py resolves KeyPairGenerator as SIGN)
    KeyPair generateSigningKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    // site: SIGN
    byte[] signFile(byte[] data, PrivateKey key) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    // site: VERIFY
    boolean verifyFile(byte[] data, byte[] signature, PublicKey key) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(signature);
    }

    // site: ENVELOPE
    byte[] wrapSessionKey(byte[] sessionKey, PublicKey recipientKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, recipientKey);
        return cipher.doFinal(sessionKey);
    }

    // site: KEM (paired with KeyAgreement -> classify.py resolves as KEM
    // if a KeyPairGenerator were present too; here the KeyAgreement site itself
    // is the detected one)
    KeyPair generateAgreementKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    byte[] deriveSharedSecret(PrivateKey myKey, PublicKey theirKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(myKey);
        ka.doPhase(theirKey, true);
        return ka.generateSecret();
    }

    // DELIBERATELY HARD SITE (expected miss, RQ0 / Stage A):
    // the algorithm name is read from configuration at runtime, so no
    // literal "RSA"/"SHA256withRSA" string ever appears at the call site
    // for the pattern-based detector to match against.
    byte[] encryptWithConfiguredAlgorithm(byte[] data, Key key, Properties config) throws Exception {
        String algName = config.getProperty("legacy.cipher.algorithm");
        Cipher cipher = Cipher.getInstance(algName);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
}
