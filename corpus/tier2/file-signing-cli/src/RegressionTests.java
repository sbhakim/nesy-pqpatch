import java.lang.reflect.Method;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * The project's regression suite, run by L3 (verifier/l3_build.py) after a
 * patch is applied. It guards two things a migration must preserve:
 *
 *  1. the surrounding provider-independent logic (hex + manifest framing), and
 *  2. FileSigner's public signing API -- checked reflectively, so no signature
 *     is ever actually computed and the suite needs no PQC provider at runtime.
 *
 * A migration that keeps the JCA shape (RSA -> ML-DSA is still Signature over a
 * PrivateKey) passes; one that mangles the API or fails to compile does not.
 * Exit 0 on success, 1 on the first failure.
 */
public class RegressionTests {

    private static int failures = 0;

    public static void main(String[] args) {
        hexRoundTrips();
        manifestRoundTrips();
        signingApiPreserved();
        if (failures > 0) {
            System.err.println(failures + " regression check(s) failed");
            System.exit(1);
        }
        System.out.println("all regression checks passed");
    }

    private static void hexRoundTrips() {
        byte[] original = new byte[] {0x00, 0x1f, (byte) 0xa0, (byte) 0xff, 0x42};
        byte[] round = HexCodec.decode(HexCodec.encode(original));
        check("hex round-trip", Arrays.equals(original, round));
        check("hex encoding is lower-case", HexCodec.encode(new byte[] {(byte) 0xAB}).equals("ab"));
    }

    private static void manifestRoundTrips() {
        SignatureManifest m = new SignatureManifest("ML-DSA-65", new byte[] {1, 2, 3, 4});
        SignatureManifest back = SignatureManifest.parse(m.format());
        check("manifest algorithm preserved", back.algorithm.equals("ML-DSA-65"));
        check("manifest signature preserved", Arrays.equals(back.signature, new byte[] {1, 2, 3, 4}));
    }

    private static void signingApiPreserved() {
        try {
            Class<?> signer = Class.forName("FileSigner");
            Method sign = signer.getDeclaredMethod("signFile", byte[].class, PrivateKey.class);
            check("signFile returns byte[]", sign.getReturnType().equals(byte[].class));
            signer.getDeclaredMethod("verifyFile", byte[].class, byte[].class, PublicKey.class);
            signer.getDeclaredMethod("wrapSessionKey", byte[].class, PublicKey.class);
            check("FileSigner public signing API preserved", true);
        } catch (ReflectiveOperationException e) {
            check("FileSigner public signing API preserved (" + e.getMessage() + ")", false);
        }
    }

    private static void check(String name, boolean condition) {
        if (!condition) {
            System.err.println("FAIL: " + name);
            failures++;
        }
    }
}
