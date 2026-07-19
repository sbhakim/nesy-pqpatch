// Tier-2 reference app #3 (keyvault-syncd): provider-independent core logic.
//
// Real behavior for L3 to protect: length-prefixed entry framing and a sorted
// key=value manifest. Deliberately exercises no cryptography, so the project
// test suite passes on any JDK regardless of provider support -- runtime
// conformance of migrated primitives is L4's concern, not L3's.
package vault.core;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.TreeMap;

public final class VaultStore {

    /** Frame an entry as a 4-byte big-endian length prefix plus the payload. */
    public static byte[] frame(byte[] payload) {
        ByteBuffer buf = ByteBuffer.allocate(4 + payload.length);
        buf.putInt(payload.length);
        buf.put(payload);
        return buf.array();
    }

    /** Recover the payload from a framed entry; reject truncated frames. */
    public static byte[] unframe(byte[] framed) {
        if (framed.length < 4) {
            throw new IllegalArgumentException("frame shorter than its length prefix");
        }
        ByteBuffer buf = ByteBuffer.wrap(framed);
        int length = buf.getInt();
        if (length < 0 || length != framed.length - 4) {
            throw new IllegalArgumentException("frame length mismatch: " + length);
        }
        byte[] payload = new byte[length];
        buf.get(payload);
        return payload;
    }

    /** Serialize entries as sorted {@code key=value} lines. */
    public static String toManifest(Map<String, String> entries) {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> e : new TreeMap<>(entries).entrySet()) {
            if (e.getKey().contains("=") || e.getKey().contains("\n")) {
                throw new IllegalArgumentException("illegal manifest key: " + e.getKey());
            }
            out.append(e.getKey()).append('=').append(e.getValue()).append('\n');
        }
        return out.toString();
    }

    /** Parse a manifest produced by {@link #toManifest}. */
    public static Map<String, String> fromManifest(String manifest) {
        Map<String, String> entries = new TreeMap<>();
        for (String line : manifest.split("\n", -1)) {
            if (line.isEmpty()) {
                continue;
            }
            int eq = line.indexOf('=');
            if (eq <= 0) {
                throw new IllegalArgumentException("malformed manifest line: " + line);
            }
            entries.put(line.substring(0, eq), line.substring(eq + 1));
        }
        return entries;
    }

    /** Concatenate framed entries into one archive blob. */
    public static byte[] concat(byte[]... frames) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] f : frames) {
            out.writeBytes(f);
        }
        return out.toByteArray();
    }
}
