import java.security.SecureRandom;

class PrngFixture {
    void fill(byte[] buf, byte[] entropy) throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(entropy);
        sr.nextBytes(buf);
    }
}
