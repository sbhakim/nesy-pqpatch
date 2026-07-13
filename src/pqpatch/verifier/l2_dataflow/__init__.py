"""L2: bounded intraprocedural Java dataflow rules (ADR-001)."""

from __future__ import annotations

from pqpatch.model import Patch, Policy, Site
from pqpatch.verifier.l2_dataflow.rules import _check_verify_result
from pqpatch.verifier.rules.spec import RuleOutcome


def check(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    """Compatibility entrypoint; the orchestrator uses the rule registry."""
    return _check_verify_result(patch, site, policy)
