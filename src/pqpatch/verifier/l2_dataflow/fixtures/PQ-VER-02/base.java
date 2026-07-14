import java.security.Signature;

class BypassFixture {
    boolean check(Signature sig, byte[] input, boolean trusted) throws Exception {
        boolean valid = sig.verify(input);
        return valid;
    }
}
