// Tier-2 reference app #4 (telemetry-signer): the project's own regression
// suite -- the L3 entrypoint (build.yaml: collector.CollectorTests), reaching
// ACROSS sibling packages to check sealing.SealOps reflectively. Provider
// independent by design: escaping/digest logic runs for real; the crypto
// surface is checked as a public-API contract a migration must not break.
package collector;

import java.lang.reflect.Method;

public final class CollectorTests {

    private static int failures = 0;

    public static void main(String[] args) {
        escapeRoundTrip();
        escapeRejectsBadInput();
        digestTracksAppends();
        batchLineDelimits();
        sealOpsApiPreserved();
        if (failures > 0) {
            System.err.println(failures + " test(s) failed");
            System.exit(1);
        }
        System.out.println("all telemetry-signer tests passed");
    }

    private static void check(boolean ok, String name) {
        if (!ok) {
            failures++;
            System.err.println("FAIL: " + name);
        }
    }

    private static void escapeRoundTrip() {
        String raw = "cpu=93%|mem=71%\nnode=\\edge-7";
        check(ReportLog.unescape(ReportLog.escape(raw)).equals(raw), "escape round-trip");
        check(!ReportLog.escape(raw).contains("\n"), "escaped form is single-line");
    }

    private static void escapeRejectsBadInput() {
        boolean threw = false;
        try {
            ReportLog.unescape("trailing\\");
        } catch (IllegalArgumentException expected) {
            threw = true;
        }
        check(threw, "dangling escape rejected");
    }

    private static void digestTracksAppends() {
        ReportLog a = new ReportLog();
        ReportLog b = new ReportLog();
        a.append("x=1");
        b.append("x=1");
        check(a.runningDigest() == b.runningDigest(), "digest deterministic");
        b.append("y=2");
        check(a.runningDigest() != b.runningDigest(), "digest tracks content");
    }

    private static void batchLineDelimits() {
        ReportLog log = new ReportLog();
        log.append("a|b");
        log.append("c");
        check(log.batchLine().equals("a\\pb|c"), "batch line escapes delimiters");
        check(log.size() == 2, "batch size");
    }

    /** The migration contract: these public methods must still exist. */
    private static void sealOpsApiPreserved() {
        try {
            Class<?> ops = Class.forName("sealing.SealOps");
            String[] required = {
                "issueReportKeys", "sealReport", "checkReport", "sealLegacy",
                "issueExchangeKeys", "deriveUplinkSecret", "wrapBatchKey",
            };
            for (String name : required) {
                boolean present = false;
                for (Method m : ops.getMethods()) {
                    if (m.getName().equals(name)) {
                        present = true;
                        break;
                    }
                }
                check(present, "SealOps." + name + " present");
            }
        } catch (ClassNotFoundException e) {
            failures++;
            System.err.println("FAIL: sealing.SealOps missing entirely");
        }
    }
}
