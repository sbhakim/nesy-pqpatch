import java.security.SecureRandom;

class RandFixture {
    SecureRandom build(byte[] entropy) throws Exception {
        byte[] seed = entropy;
        SecureRandom sr = new SecureRandom(seed);
        return sr;
    }
}
