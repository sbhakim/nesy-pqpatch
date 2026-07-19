// Tier-2 reference app #3 (keyvault-syncd): the crypto surface.
//
// Seeds seven quantum-vulnerable sites (six detectable + one deliberate miss)
// across a DEEPER package layout than apps #1-2 (two nested packages) and a
// surface neither app uses: provider-pinned getInstance(alg, provider) idioms,
// SHA512withRSA seals, an X25519 channel agreement, and a bare RSA key-wrap.
// The deliberately hard site is a PROVIDER-PINNED SIGNATURE call: the detector
// pack matches two-arg getInstance for key-pair generators but its Signature
// patterns are single-arg, so pinning the provider hides the call -- miss
// mechanism #3 (app #1 hides one behind a config lookup, app #2 behind string
// concatenation). Ground-truth lines in ../..//sites.yaml are confirmed
// against a real detector run, never hand-counted.
package vault.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public final class SealEngine {

    /** Issue the vault's signing key pair (pinned to the stock RSA provider). */
    public KeyPair issueSigningKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
        kpg.initialize(3072);
        return kpg.generateKeyPair();
    }

    /** Seal a payload under the vault signing key. */
    public byte[] seal(byte[] payload, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA512withRSA");
        signer.initSign(key);
        signer.update(payload);
        return signer.sign();
    }

    /** Check a seal produced by {@link #seal}. */
    public boolean checkSeal(byte[] payload, byte[] sealBytes, PublicKey key) throws Exception {
        Signature verifier = Signature.getInstance("SHA512withRSA");
        verifier.initVerify(key);
        verifier.update(payload);
        return verifier.verify(sealBytes);
    }

    /** Check a legacy seal from the v1 fleet (provider-pinned ECDSA). */
    public boolean checkLegacySeal(byte[] payload, byte[] sealBytes, PublicKey key)
            throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA", "SunEC");
        verifier.initVerify(key);
        verifier.update(payload);
        return verifier.verify(sealBytes);
    }

    /** Issue the key pair for channel establishment (pinned EC provider). */
    public KeyPair issueChannelKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "SunEC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    /** Derive the sync-channel secret with the peer. */
    public byte[] deriveChannelSecret(PrivateKey mine, PublicKey peer) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(mine);
        agreement.doPhase(peer, true);
        return agreement.generateSecret();
    }

    /** Wrap a data key for a recipient vault. */
    public byte[] wrapDataKey(Key dataKey, PublicKey recipient) throws Exception {
        Cipher wrapper = Cipher.getInstance("RSA");
        wrapper.init(Cipher.WRAP_MODE, recipient);
        return wrapper.wrap(dataKey);
    }
}
