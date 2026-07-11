"""L4: conformance harness -- round-trip tests, NIST ACVP known-answer
tests, and cross-provider interoperability.

Not yet implemented; requires the pinned crypto-tools container and ACVP
vectors. The sub-check interfaces live in roundtrip.py, acvp.py, and
interop.py; the orchestrator records this layer as skipped, never passed.
"""

from __future__ import annotations

from pqpatch.model import Patch, Policy, Site
from pqpatch.verifier.rules.spec import RuleOutcome


def check(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del patch, site, policy
    raise NotImplementedError(
        "L4 conformance pends the pinned container images and ACVP vectors; "
        "see docs/STATUS.md for the implementation ledger."
    )
