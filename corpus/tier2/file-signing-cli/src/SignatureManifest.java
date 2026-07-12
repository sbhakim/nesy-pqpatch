/**
 * The on-disk framing the CLI writes next to a signed file: the algorithm
 * name and the signature bytes, hex-encoded. Parsing and formatting are pure
 * string logic, independent of which signature primitive produced the bytes,
 * so a migration from RSA to ML-DSA must round-trip through here unchanged.
 */
final class SignatureManifest {

    final String algorithm;
    final byte[] signature;

    SignatureManifest(String algorithm, byte[] signature) {
        this.algorithm = algorithm;
        this.signature = signature;
    }

    String format() {
        return "algorithm=" + algorithm + "\n" + "signature=" + HexCodec.encode(signature) + "\n";
    }

    static SignatureManifest parse(String text) {
        String algorithm = null;
        byte[] signature = null;
        for (String line : text.split("\n")) {
            int eq = line.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String key = line.substring(0, eq);
            String value = line.substring(eq + 1);
            if (key.equals("algorithm")) {
                algorithm = value;
            } else if (key.equals("signature")) {
                signature = HexCodec.decode(value);
            }
        }
        if (algorithm == null || signature == null) {
            throw new IllegalArgumentException("manifest missing a required field");
        }
        return new SignatureManifest(algorithm, signature);
    }
}
