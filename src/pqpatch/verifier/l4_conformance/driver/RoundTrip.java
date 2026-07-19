// L4 round-trip driver, executed on a PQC-capable JDK (>= 24).
//
// args: <family: sig|kem> <algorithm-literal-from-the-patch>
//
// Exit codes are the contract with roundtrip.py:
//   0  round-trip succeeded (sign->verify + tamper-must-fail, or
//      encaps->decaps secret match)
//   1  the algorithm resolved but its round-trip FAILED
//   2  the exact literal from the patch does not resolve to any provider
//      (the hallucinated-name case) -- the patch's fault
//   3  the runtime lacks the whole family (e.g. SLH-DSA before its JDK) --
//      a harness limitation, never blamed on the patch
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import javax.crypto.KEM;

public final class RoundTrip {

    public static void main(String[] args) {
        String family = args[0];
        String alg = args[1];
        String base = family.equals("kem") ? "ML-KEM" : baseOf(alg);
        try {
            try {
                KeyPairGenerator.getInstance(base);
            } catch (NoSuchAlgorithmException e) {
                System.err.println("runtime lacks family " + base);
                System.exit(3);
            }
            KeyPairGenerator kpg = null;
            try {
                kpg = KeyPairGenerator.getInstance(alg);
            } catch (NoSuchAlgorithmException e) {
                System.err.println("algorithm literal does not resolve: " + alg);
                System.exit(2);
            }
            KeyPair kp = kpg.generateKeyPair();
            if (family.equals("kem")) {
                kemRoundTrip(kp);
            } else {
                sigRoundTrip(alg, base, kp);
            }
            System.out.println("round-trip ok: " + alg);
        } catch (Throwable t) {
            System.err.println("round-trip failed for " + alg + ": " + t);
            System.exit(1);
        }
    }

    private static String baseOf(String alg) {
        if (alg.contains("SLH-DSA")) return "SLH-DSA";
        if (alg.contains("ML-DSA")) return "ML-DSA";
        return alg;
    }

    private static Signature sigInstance(String alg, String base) throws Exception {
        try {
            return Signature.getInstance(alg);
        } catch (NoSuchAlgorithmException e) {
            // Keys carry the parameter set; the base family engine is the
            // standard way to sign with a parameterized key.
            return Signature.getInstance(base);
        }
    }

    private static void sigRoundTrip(String alg, String base, KeyPair kp) throws Exception {
        byte[] msg = "pqpatch-l4-roundtrip".getBytes();

        Signature signer = sigInstance(alg, base);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = sigInstance(alg, base);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        if (!verifier.verify(sig)) {
            throw new IllegalStateException("valid signature did not verify");
        }

        sig[0] ^= 0x01; // tamper -> must fail
        boolean rejected;
        try {
            Signature tampered = sigInstance(alg, base);
            tampered.initVerify(kp.getPublic());
            tampered.update(msg);
            rejected = !tampered.verify(sig);
        } catch (SignatureException e) {
            rejected = true;
        }
        if (!rejected) {
            throw new IllegalStateException("tampered signature verified");
        }
    }

    private static void kemRoundTrip(KeyPair kp) throws Exception {
        KEM kem = KEM.getInstance("ML-KEM");
        KEM.Encapsulated enc = kem.newEncapsulator(kp.getPublic()).encapsulate();
        byte[] shared = kem.newDecapsulator(kp.getPrivate())
                .decapsulate(enc.encapsulation()).getEncoded();
        if (!Arrays.equals(enc.key().getEncoded(), shared)) {
            throw new IllegalStateException("KEM shared secrets differ");
        }
    }
}
