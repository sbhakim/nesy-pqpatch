// Tier-1 case: quantum-vulnerable RSA key transport (CryptoAPI-Bench idiom).
// A correct migration replaces RSA key wrapping with an ML-KEM encapsulation
// plus AEAD KEM-DEM. See case.yaml.
import javax.crypto.Cipher;
import java.security.Key;
import java.security.PublicKey;

public class RsaWrapExample {

    public byte[] wrap(Key dataKey, PublicKey recipient) throws Exception {
        Cipher wrapper = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        wrapper.init(Cipher.WRAP_MODE, recipient);
        return wrapper.wrap(dataKey);
    }
}
