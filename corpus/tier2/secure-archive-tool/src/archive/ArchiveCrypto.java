package archive;

import java.security.*;
import javax.crypto.*;

/**
 * Tier-2 reference application #2: secure archive tool.
 *
 * Deliberately different in shape from app #1 (file-signing-cli): sources
 * live in a Java package (nested directory build), the seeded sites use
 * different classical algorithms (DSA, ECDSA, DH, RSA/PKCS1), and the
 * deliberately hard site hides the algorithm name behind string
 * concatenation rather than a configuration lookup. Ground truth for every
 * site is in ../../sites.yaml.
 */
public class ArchiveCrypto {

    // site: SIGN (key generation for manifest signing; no agreement nearby)
    KeyPair generateManifestKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    // site: SIGN
    byte[] signManifest(byte[] manifest, PrivateKey key) throws Exception {
        Signature sig = Signature.getInstance("SHA384withECDSA");
        sig.initSign(key);
        sig.update(manifest);
        return sig.sign();
    }

    // site: VERIFY
    boolean verifyManifest(byte[] manifest, byte[] signature, PublicKey key) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(key);
        sig.update(manifest);
        return sig.verify(signature);
    }

    // site: ENVELOPE (archive session key wrapped for the recipient)
    byte[] wrapArchiveKey(byte[] archiveKey, PublicKey recipientKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, recipientKey);
        return cipher.doFinal(archiveKey);
    }

    // site: KEM (pair generation feeding the channel agreement below)
    KeyPair generateChannelKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    // site: KEM
    byte[] deriveChannelSecret(PrivateKey myKey, PublicKey theirKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(myKey);
        ka.doPhase(theirKey, true);
        return ka.generateSecret();
    }

    // DELIBERATELY HARD SITE (expected miss, RQ0 / Stage A):
    // the algorithm name is assembled by string concatenation at runtime, so
    // no complete literal ("SHA256withECDSA") ever appears at the call site
    // for the pattern-based detector to match. A different miss mechanism
    // from app #1's configuration lookup.
    boolean verifyLegacyEntry(byte[] entry, byte[] signature, PublicKey key, String hashName)
            throws Exception {
        String algorithm = hashName + "withECDSA";
        Signature sig = Signature.getInstance(algorithm);
        sig.initVerify(key);
        sig.update(entry);
        return sig.verify(signature);
    }
}
