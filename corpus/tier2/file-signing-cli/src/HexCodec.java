/**
 * Hex encoding for signature manifests. Provider-independent by design: this
 * is the kind of surrounding code a crypto migration must not break, and the
 * L3 regression suite pins its behaviour across the patch.
 */
final class HexCodec {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private HexCodec() {}

    static String encode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(DIGITS[(b >> 4) & 0xF]);
            sb.append(DIGITS[b & 0xF]);
        }
        return sb.toString();
    }

    static byte[] decode(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("odd-length hex string");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("non-hex character");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
