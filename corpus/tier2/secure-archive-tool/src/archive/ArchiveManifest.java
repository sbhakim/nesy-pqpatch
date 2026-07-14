package archive;

import java.util.Base64;

/**
 * The archive's signed manifest line: algorithm name plus digest, formatted
 * as a single parseable line. Provider independent; the regression suite
 * asserts the round-trip so a migration cannot silently change the framing.
 */
public final class ArchiveManifest {

    public final String algorithm;
    public final byte[] digest;

    public ArchiveManifest(String algorithm, byte[] digest) {
        this.algorithm = algorithm;
        this.digest = digest.clone();
    }

    public String format() {
        return algorithm + ":" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    public static ArchiveManifest parse(String line) {
        int sep = line.indexOf(':');
        if (sep <= 0 || sep == line.length() - 1) {
            throw new IllegalArgumentException("malformed manifest line: " + line);
        }
        String algorithm = line.substring(0, sep);
        byte[] digest = Base64.getUrlDecoder().decode(line.substring(sep + 1));
        return new ArchiveManifest(algorithm, digest);
    }
}
