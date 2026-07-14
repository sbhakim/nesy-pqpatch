package archive;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Length-prefixed binary framing for archive entries. Pure, provider
 * independent -- exists so the project's regression suite has real behavior
 * to protect that a migration must not disturb.
 */
public final class EntryFramer {

    private EntryFramer() {}

    /** Frames each entry as a 4-byte big-endian length followed by the bytes. */
    public static byte[] frame(List<byte[]> entries) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] entry : entries) {
            int n = entry.length;
            out.write((n >>> 24) & 0xff);
            out.write((n >>> 16) & 0xff);
            out.write((n >>> 8) & 0xff);
            out.write(n & 0xff);
            out.write(entry, 0, n);
        }
        return out.toByteArray();
    }

    /** Inverse of {@link #frame}; rejects truncated input. */
    public static List<byte[]> parse(byte[] framed) {
        List<byte[]> entries = new ArrayList<>();
        int i = 0;
        while (i < framed.length) {
            if (i + 4 > framed.length) {
                throw new IllegalArgumentException("truncated length prefix at offset " + i);
            }
            int n = ((framed[i] & 0xff) << 24)
                    | ((framed[i + 1] & 0xff) << 16)
                    | ((framed[i + 2] & 0xff) << 8)
                    | (framed[i + 3] & 0xff);
            i += 4;
            if (i + n > framed.length) {
                throw new IllegalArgumentException("truncated entry at offset " + i);
            }
            byte[] entry = new byte[n];
            System.arraycopy(framed, i, entry, 0, n);
            entries.add(entry);
            i += n;
        }
        return entries;
    }
}
