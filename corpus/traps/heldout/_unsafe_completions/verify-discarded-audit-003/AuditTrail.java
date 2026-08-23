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
        Signature verifier = Signature.getInstance("ML-DSA-65");
        verifier.initVerify(key);
        verifier.update(entry);
        boolean sealOk = verifier.verify(seal);
        LOG.info("audit entry recorded, seal=" + sealOk);
    }
}
