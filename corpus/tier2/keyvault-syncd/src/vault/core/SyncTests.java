// Tier-2 reference app #3 (keyvault-syncd): the project's own regression suite.
//
// The L3 test entrypoint (build.yaml: vault.core.SyncTests -- a two-segment
// dotted name, one level deeper than app #2's). Provider-independent by
// design: framing and manifest behavior run for real, and the crypto surface
// is checked REFLECTIVELY (the public API of vault.crypto.SealEngine must
// survive a migration patch), so a compiling API-break is caught only here.
package vault.core;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.TreeMap;

public final class SyncTests {

    private static int failures = 0;

    public static void main(String[] args) {
        framingRoundTrip();
        framingRejectsTruncation();
        manifestRoundTrip();
        manifestRejectsIllegalKey();
        sealEngineApiPreserved();
        if (failures > 0) {
            System.err.println(failures + " test(s) failed");
            System.exit(1);
        }
        System.out.println("all keyvault-syncd tests passed");
    }

    private static void check(boolean ok, String name) {
        if (!ok) {
            failures++;
            System.err.println("FAIL: " + name);
        }
    }

    private static void framingRoundTrip() {
        byte[] payload = "vault-entry".getBytes();
        byte[] back = VaultStore.unframe(VaultStore.frame(payload));
        check(java.util.Arrays.equals(payload, back), "framing round-trip");
    }

    private static void framingRejectsTruncation() {
        byte[] framed = VaultStore.frame("secret".getBytes());
        byte[] truncated = java.util.Arrays.copyOf(framed, framed.length - 2);
        boolean threw = false;
        try {
            VaultStore.unframe(truncated);
        } catch (IllegalArgumentException expected) {
            threw = true;
        }
        check(threw, "truncated frame rejected");
    }

    private static void manifestRoundTrip() {
        Map<String, String> entries = new TreeMap<>();
        entries.put("alpha", "1");
        entries.put("beta", "two");
        Map<String, String> back = VaultStore.fromManifest(VaultStore.toManifest(entries));
        check(entries.equals(back), "manifest round-trip");
        check(VaultStore.toManifest(entries).startsWith("alpha="), "manifest sorted");
    }

    private static void manifestRejectsIllegalKey() {
        boolean threw = false;
        try {
            VaultStore.toManifest(Map.of("bad=key", "v"));
        } catch (IllegalArgumentException expected) {
            threw = true;
        }
        check(threw, "illegal manifest key rejected");
    }

    /** The migration contract: these public methods must still exist. */
    private static void sealEngineApiPreserved() {
        try {
            Class<?> engine = Class.forName("vault.crypto.SealEngine");
            String[] required = {
                "issueSigningKeys", "seal", "checkSeal", "checkLegacySeal",
                "issueChannelKeys", "deriveChannelSecret", "wrapDataKey",
            };
            for (String name : required) {
                boolean present = false;
                for (Method m : engine.getMethods()) {
                    if (m.getName().equals(name)) {
                        present = true;
                        break;
                    }
                }
                check(present, "SealEngine." + name + " present");
            }
        } catch (ClassNotFoundException e) {
            failures++;
            System.err.println("FAIL: vault.crypto.SealEngine missing entirely");
        }
    }
}
