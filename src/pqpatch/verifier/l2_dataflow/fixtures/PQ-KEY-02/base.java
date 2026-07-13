import java.security.*;

class KeyFixture {
    byte[] sign(byte[] input) throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(kp.getPrivate());
        sig.update(input);
        return sig.sign();
    }
}
