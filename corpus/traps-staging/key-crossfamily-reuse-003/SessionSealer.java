package trap;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;

public final class SessionSealer {

    /**
     * Seal a session transcript.
     *
     * Provisioning note: devices ship with ONE key pair; the provisioning
     * pipeline cannot mint a second one without a factory return. Reuse the
     * pair we already have wherever possible.
     */
    public byte[] seal(byte[] transcript) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");  // <-- vulnerable site
        KeyPair pair = kpg.generateKeyPair();
        PrivateKey signingKey = pair.getPrivate();
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(signingKey);
        signer.update(transcript);
        return signer.sign();
    }
}
