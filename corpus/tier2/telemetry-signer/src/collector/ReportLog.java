// Tier-2 reference app #4 (telemetry-signer): provider-independent core logic.
//
// Real behavior for L3 to protect: telemetry-record escaping/encoding and a
// running FNV-1a digest over appended records. No cryptography executes here,
// so the suite passes on any JDK -- runtime conformance is L4's concern.
package collector;

import java.util.ArrayList;
import java.util.List;

public final class ReportLog {

    private final List<String> records = new ArrayList<>();
    private long digest = 0xcbf29ce484222325L; // FNV-1a offset basis

    /** Escape a raw record: backslash, newline, and pipe are metacharacters. */
    public static String escape(String raw) {
        StringBuilder out = new StringBuilder(raw.length());
        for (char c : raw.toCharArray()) {
            if (c == '\\') {
                out.append("\\\\");
            } else if (c == '\n') {
                out.append("\\n");
            } else if (c == '|') {
                out.append("\\p");
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    /** Invert {@link #escape}; reject dangling escapes. */
    public static String unescape(String escaped) {
        StringBuilder out = new StringBuilder(escaped.length());
        for (int i = 0; i < escaped.length(); i++) {
            char c = escaped.charAt(i);
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (i + 1 >= escaped.length()) {
                throw new IllegalArgumentException("dangling escape");
            }
            char next = escaped.charAt(++i);
            if (next == '\\') {
                out.append('\\');
            } else if (next == 'n') {
                out.append('\n');
            } else if (next == 'p') {
                out.append('|');
            } else {
                throw new IllegalArgumentException("bad escape: \\" + next);
            }
        }
        return out.toString();
    }

    /** Append a record, folding it into the running FNV-1a digest. */
    public void append(String record) {
        records.add(record);
        for (byte b : record.getBytes()) {
            digest ^= (b & 0xffL);
            digest *= 0x100000001b3L;
        }
    }

    /** The batch as one pipe-delimited line of escaped records. */
    public String batchLine() {
        List<String> escaped = new ArrayList<>(records.size());
        for (String r : records) {
            escaped.add(escape(r));
        }
        return String.join("|", escaped);
    }

    public long runningDigest() {
        return digest;
    }

    public int size() {
        return records.size();
    }
}
