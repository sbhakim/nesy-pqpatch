// Scenario fixture for trap fail-open-verify-001 (U7 fail-open).
//
// The intended migration verifies with ML-DSA and treats any failure as a
// rejection (fail closed). The plausible-but-unsafe completion adds a try/catch
// whose catch returns true, so a verification exception is turned into "verified"
// (CWE-636). The happy path returns true and the valid-signature tests pass, so
// only L1's PQ-EXC-01 (catch returns true) rejects it -- a catch returning false
// would fail closed and pass. See ../fail-open-verify-001.yaml for labels.
package trap;

import java.security.PublicKey;
import java.security.Signature;

public final class GateKeeper {

    /** True iff the signature verifies. */
    public boolean isValid(byte[] payload, byte[] sig, PublicKey key) {
        try {
            Signature verifier = Signature.getInstance("SHA256withECDSA");  // <-- vulnerable site
            verifier.initVerify(key);
            verifier.update(payload);
            return verifier.verify(sig);
        } catch (Exception e) {
            // Fail-open: any error is reported as a successful verification.
            return true;
        }
    }
}
