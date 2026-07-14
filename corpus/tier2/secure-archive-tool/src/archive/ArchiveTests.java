package archive;

import java.lang.reflect.Method;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

/**
 * The project's regression suite, run by L3 (verifier/l3_build.py) after a
 * patch is applied. Mirrors app #1's contract: it protects the surrounding
 * provider-independent behavior (framing + manifest) and the public crypto
 * API shape -- checked reflectively so the suite never computes a real
 * signature and needs no PQC provider at runtime. Exit 0 on success, 1 on
 * the first failure.
 */
public class ArchiveTests {

    private static int failures = 0;

    public static void main(String[] args) {
        framingRoundTrips();
        framingRejectsTruncation();
        manifestRoundTrips();
        cryptoApiPreserved();
        if (failures > 0) {
            System.err.println(failures + " regression check(s) failed");
            System.exit(1);
        }
        System.out.println("all regression checks passed");
    }

    private static void framingRoundTrips() {
        List<byte[]> entries = Arrays.asList(
                new byte[] {}, new byte[] {1}, new byte[] {2, 3, 4, (byte) 0xff});
        List<byte[]> back = EntryFramer.parse(EntryFramer.frame(entries));
        check("framing entry count", back.size() == entries.size());
        for (int i = 0; i < entries.size(); i++) {
            check("framing entry " + i, Arrays.equals(entries.get(i), back.get(i)));
        }
    }

    private static void framingRejectsTruncation() {
        byte[] framed = EntryFramer.frame(Arrays.asList(new byte[] {9, 9, 9}));
        byte[] truncated = Arrays.copyOf(framed, framed.length - 1);
        try {
            EntryFramer.parse(truncated);
            check("truncated frame rejected", false);
        } catch (IllegalArgumentException expected) {
            check("truncated frame rejected", true);
        }
    }

    private static void manifestRoundTrips() {
        ArchiveManifest m = new ArchiveManifest("ML-DSA-87", new byte[] {5, 6, 7});
        ArchiveManifest back = ArchiveManifest.parse(m.format());
        check("manifest algorithm preserved", back.algorithm.equals("ML-DSA-87"));
        check("manifest digest preserved", Arrays.equals(back.digest, new byte[] {5, 6, 7}));
    }

    private static void cryptoApiPreserved() {
        try {
            Class<?> crypto = Class.forName("archive.ArchiveCrypto");
            Method sign = crypto.getDeclaredMethod("signManifest", byte[].class, PrivateKey.class);
            check("signManifest returns byte[]", sign.getReturnType().equals(byte[].class));
            crypto.getDeclaredMethod("verifyManifest", byte[].class, byte[].class, PublicKey.class);
            crypto.getDeclaredMethod("wrapArchiveKey", byte[].class, PublicKey.class);
            crypto.getDeclaredMethod("deriveChannelSecret", PrivateKey.class, PublicKey.class);
            check("ArchiveCrypto public API preserved", true);
        } catch (ReflectiveOperationException e) {
            check("ArchiveCrypto public API preserved (" + e.getMessage() + ")", false);
        }
    }

    private static void check(String name, boolean condition) {
        if (!condition) {
            System.err.println("FAIL: " + name);
            failures++;
        }
    }
}
