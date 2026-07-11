"""L2: dataflow and typestate rules.

Not yet implemented; the engine choice is an open architecture decision
(ADR-001) and blocks rule authoring. The orchestrator records this layer
as skipped rather than passed, so its absence is visible in every verdict.
"""

from __future__ import annotations

from pqpatch.model import Patch, Policy, Site
from pqpatch.verifier.rules.spec import RuleOutcome


def check(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del patch, site, policy
    raise NotImplementedError(
        "L2 dataflow verification pends the engine decision in ADR-001; "
        "see docs/STATUS.md for the implementation ledger."
    )
