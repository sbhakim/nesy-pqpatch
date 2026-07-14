import javax.crypto.KeyAgreement;

class HybridUseFixture {
    byte[] derive(KeyAgreement ka, Decapsulator dec, byte[] ct) throws Exception {
        byte[] ec = ka.generateSecret();
        byte[] pq = dec.decapsulate(ct);
        return hkdf(concat(ec, pq));
    }

    static byte[] concat(byte[] a, byte[] b) {
        return a;
    }

    static byte[] hkdf(byte[] x) {
        return x;
    }
}
