// Tier-2 reference app #5 (token-broker): the crypto surface.
//
// Seeds seven quantum-vulnerable sites (six detectable + one deliberate miss)
// with a surface the first four apps do not use: a flat single package but a
// method-return-value indirection for the hard site. Algorithms are chosen to
// spread coverage further -- SHA1withRSA (a legacy signer), an EC key pair for
// ECDSA, an X25519 broker channel, and RSA/OAEP token wrapping.
//
// MISS MECHANISM #5: the hard site obtains its algorithm from a private
// helper method's return value, so the getInstance argument is a method call,
// not a literal or a foldable constant -- invisible to the literal-matching
// pack (after config lookup #1, concatenation #2, provider pinning #3,
// array-index #4). Ground-truth lines in ../../sites.yaml are confirmed
// against a real detector run, never hand-counted.
package broker;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public final class TokenCrypto {

    /** Issue the broker's token-signing key pair. */
    public KeyPair issueSigningKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    /** Sign an issued token. */
    public byte[] signToken(byte[] token, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(token);
        return signer.sign();
    }

    /** Verify a presented token. */
    public boolean verifyToken(byte[] token, byte[] sig, PublicKey key) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(key);
        verifier.update(token);
        return verifier.verify(sig);
    }

    /** Re-verify a token under a federated partner's negotiated scheme. */
    public boolean verifyFederated(byte[] token, byte[] sig, PublicKey key) throws Exception {
        Signature verifier = Signature.getInstance(negotiatedScheme());
        verifier.initVerify(key);
        verifier.update(token);
        return verifier.verify(sig);
    }

    /** Issue the broker channel key pair. */
    public KeyPair issueChannelKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    /** Establish the broker-to-partner channel secret. */
    public byte[] establishChannel(PrivateKey mine, PublicKey peer) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(mine);
        agreement.doPhase(peer, true);
        return agreement.generateSecret();
    }

    /** Wrap a session key for a downstream service. */
    public byte[] wrapSessionKey(Key sessionKey, PublicKey service) throws Exception {
        Cipher wrapper = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        wrapper.init(Cipher.WRAP_MODE, service);
        return wrapper.wrap(sessionKey);
    }

    /** The scheme negotiated with the federated partner (default legacy). */
    private String negotiatedScheme() {
        String scheme = System.getProperty("broker.partner.scheme");
        return scheme != null ? scheme : "SHA256withRSA";
    }
}
