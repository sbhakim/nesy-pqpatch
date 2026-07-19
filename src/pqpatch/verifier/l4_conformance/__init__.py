"""L4: conformance harness -- round-trip tests, NIST ACVP known-answer
tests, and cross-provider interoperability.

Minimal-but-real as of 2026-07-19: the ROUND-TRIP slice is implemented
(roundtrip.py) and runs on a PQC-capable JDK configured via
PQPATCH_L4_JAVA_HOME -- every PQ algorithm literal a patch introduces must
resolve and survive sign->verify+tamper or encaps->decaps. With no runtime
configured the layer records SKIPPED, exactly as the former stub did, so CI
and non-PQC machines stay green and the provenance stays honest. ACVP
known-answer vectors (acvp.py) and cross-provider interop (interop.py) remain
deliberate stubs pending pinned vectors and the crypto-tools container.
"""

from __future__ import annotations

from pqpatch.model import Patch, Policy, Site
from pqpatch.verifier.l4_conformance import roundtrip
from pqpatch.verifier.rules.spec import RuleOutcome


def check(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    return roundtrip.check(patch, site, policy)
