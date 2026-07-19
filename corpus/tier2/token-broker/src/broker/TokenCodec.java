// Tier-2 reference app #5 (token-broker): provider-independent core logic.
//
// Real behavior for L3 to protect: base64url token encoding without padding
// and a dotted header.payload.signature token structure. No cryptography runs
// here, so the suite passes on any JDK -- runtime conformance is L4's concern.
package broker;

import java.util.Base64;

public final class TokenCodec {

    private static final Base64.Encoder ENC = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DEC = Base64.getUrlDecoder();

    /** Assemble a token as base64url(header).base64url(payload).base64url(sig). */
    public static String assemble(byte[] header, byte[] payload, byte[] sig) {
        return ENC.encodeToString(header)
                + "." + ENC.encodeToString(payload)
                + "." + ENC.encodeToString(sig);
    }

    /** The signing input for a token: header.payload (the first two segments). */
    public static String signingInput(String token) {
        int last = token.lastIndexOf('.');
        if (last <= 0 || token.indexOf('.') == last) {
            throw new IllegalArgumentException("token must have three segments");
        }
        return token.substring(0, last);
    }

    /** Recover the signature bytes (the third segment). */
    public static byte[] signatureOf(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("token must have exactly three segments");
        }
        return DEC.decode(parts[2]);
    }

    /** Recover the payload bytes (the second segment). */
    public static byte[] payloadOf(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("token must have exactly three segments");
        }
        return DEC.decode(parts[1]);
    }
}
