// Tier-2 reference app #4 (telemetry-signer): the crypto surface.
//
// Seeds seven quantum-vulnerable sites (six detectable + one deliberate miss)
// with surfaces the first three apps do not use: SIBLING top-level packages
// (collector + sealing, vs. app #3's nested pair), raw-digest ECDSA
// (NONEwithECDSA), a "DiffieHellman" key-pair generator, and OAEP key wrap.
// The deliberately hard site is MISS MECHANISM #4: the algorithm name is
// selected from a compatibility TABLE by a runtime index. A plain static
// final constant is NOT enough to hide -- Semgrep constant-folds it (our own
// perturbation probe pinned this, and a first draft of this app was caught
// exactly that way) -- but array-index indirection defeats the folding
// (after app #1's config lookup, app #2's concatenation, app #3's provider
// pinning). Ground-truth lines in ../../sites.yaml are confirmed against a
// real detector run, never hand-counted.
package sealing;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public final class SealOps {

    /** Fleet compatibility table: seal algorithm per agent protocol version. */
    private static final String[] FLEET_SEAL_ALGS = {"SHA256withRSA", "SHA384withRSA"};

    /** Issue the reporting key pair (P-384). */
    public KeyPair issueReportKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(384);
        return kpg.generateKeyPair();
    }

    /** Seal a telemetry report. */
    public byte[] sealReport(byte[] report, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA512withECDSA");
        signer.initSign(key);
        signer.update(report);
        return signer.sign();
    }

    /** Check a report seal against a pre-hashed digest (raw ECDSA). */
    public boolean checkReport(byte[] digest, byte[] seal, PublicKey key) throws Exception {
        Signature verifier = Signature.getInstance("NONEwithECDSA");
        verifier.initVerify(key);
        verifier.update(digest);
        return verifier.verify(seal);
    }

    /** Seal for a legacy fleet agent (algorithm chosen from the table). */
    public byte[] sealLegacy(byte[] report, PrivateKey key, int protocolVersion)
            throws Exception {
        Signature signer = Signature.getInstance(FLEET_SEAL_ALGS[protocolVersion]);
        signer.initSign(key);
        signer.update(report);
        return signer.sign();
    }

    /** Issue the uplink key-exchange pair. */
    public KeyPair issueExchangeKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
        return kpg.generateKeyPair();
    }

    /** Derive the uplink channel secret with the collector. */
    public byte[] deriveUplinkSecret(PrivateKey mine, PublicKey peer) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("DH");
        agreement.init(mine);
        agreement.doPhase(peer, true);
        return agreement.generateSecret();
    }

    /** Wrap a batch encryption key for the archive. */
    public byte[] wrapBatchKey(Key batchKey, PublicKey archive) throws Exception {
        Cipher wrapper = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        wrapper.init(Cipher.WRAP_MODE, archive);
        return wrapper.wrap(batchKey);
    }
}
