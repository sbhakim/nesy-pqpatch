// Tier-2 reference app #5 (token-broker): the project's own regression suite,
// the L3 entrypoint (build.yaml: broker.BrokerTests -- a single-segment
// entrypoint in a flat package, the shape apps #3-4 vary away from). Provider
// independent: base64url/token-structure logic runs for real; the crypto
// surface (broker.TokenCrypto) is checked reflectively as a migration
// contract, so a compiling API-break is caught only here.
package broker;

import java.lang.reflect.Method;
import java.util.Arrays;

public final class BrokerTests {

    private static int failures = 0;

    public static void main(String[] args) {
        assembleAndSplit();
        signingInputIsFirstTwoSegments();
        rejectsMalformedToken();
        payloadRoundTrip();
        tokenCryptoApiPreserved();
        if (failures > 0) {
            System.err.println(failures + " test(s) failed");
            System.exit(1);
        }
        System.out.println("all token-broker tests passed");
    }

    private static void check(boolean ok, String name) {
        if (!ok) {
            failures++;
            System.err.println("FAIL: " + name);
        }
    }

    private static void assembleAndSplit() {
        String token = TokenCodec.assemble(
                "h".getBytes(), "p".getBytes(), "s".getBytes());
        check(token.split("\\.", -1).length == 3, "assembled token has three segments");
        check(!token.contains("="), "base64url is unpadded");
    }

    private static void signingInputIsFirstTwoSegments() {
        String token = TokenCodec.assemble(
                "hdr".getBytes(), "pay".getBytes(), "sig".getBytes());
        String input = TokenCodec.signingInput(token);
        check(input.equals(token.substring(0, token.lastIndexOf('.'))), "signing input");
        check(input.split("\\.", -1).length == 2, "signing input is two segments");
    }

    private static void rejectsMalformedToken() {
        boolean threw = false;
        try {
            TokenCodec.signatureOf("only.two");
        } catch (IllegalArgumentException expected) {
            threw = true;
        }
        check(threw, "malformed token rejected");
    }

    private static void payloadRoundTrip() {
        byte[] payload = "the-payload-bytes".getBytes();
        String token = TokenCodec.assemble("h".getBytes(), payload, "s".getBytes());
        check(Arrays.equals(TokenCodec.payloadOf(token), payload), "payload round-trip");
    }

    /** The migration contract: these public methods must still exist. */
    private static void tokenCryptoApiPreserved() {
        try {
            Class<?> crypto = Class.forName("broker.TokenCrypto");
            String[] required = {
                "issueSigningKeys", "signToken", "verifyToken", "verifyFederated",
                "issueChannelKeys", "establishChannel", "wrapSessionKey",
            };
            for (String name : required) {
                boolean present = false;
                for (Method m : crypto.getMethods()) {
                    if (m.getName().equals(name)) {
                        present = true;
                        break;
                    }
                }
                check(present, "TokenCrypto." + name + " present");
            }
        } catch (ClassNotFoundException e) {
            failures++;
            System.err.println("FAIL: broker.TokenCrypto missing entirely");
        }
    }
}
