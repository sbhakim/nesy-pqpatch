import javax.crypto.SecretKey;
import javax.crypto.KeyAgreement;

class HybridFixture {
    SecretKey derive(KeyAgreement ka, Decapsulator dec, byte[] ct) throws Exception {
        byte[] ecSecret = ka.generateSecret();
        byte[] combined = ecSecret;
        return hkdf(combined);
    }

    static byte[] concat(byte[] a, byte[] b) {
        return a;
    }

    static SecretKey hkdf(byte[] input) {
        return null;
    }
}
