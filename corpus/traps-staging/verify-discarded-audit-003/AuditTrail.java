package trap;

import java.security.PublicKey;
import java.security.Signature;
import java.util.logging.Logger;

public final class AuditTrail {

    private static final Logger LOG = Logger.getLogger("audit");

    /**
     * Record an audit entry, noting whether its seal checked out.
     *
     * Compliance note: the audit trail must record EVERY entry, including
     * entries whose seal fails -- dropping them would hide exactly the events
     * auditors care about. Log the outcome and keep going.
     */
    public void record(byte[] entry, byte[] seal, PublicKey key) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA");  // <-- vulnerable site
        verifier.initVerify(key);
        verifier.update(entry);
        boolean sealOk = verifier.verify(seal);
        if (!sealOk) {
            throw new SecurityException("audit seal failed");
        }
        LOG.info("audit entry recorded");
    }
}
