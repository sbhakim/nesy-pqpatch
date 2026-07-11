"""Rule specification and the fixture contract.

A rule registers only with at least one passing and one violating fixture;
the fixture suite enforces this mechanically on every commit. A rule that
cannot fail is not a rule.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pqpatch.model import Layer, Patch, Policy, RuleStatus, Site, UnsafeClass

_RULES_DIR = Path(__file__).parent


@dataclass(frozen=True, slots=True)
class RuleOutcome:
    """What a rule's check function returns: PASS, or FAIL/ERROR with detail."""

    status: RuleStatus
    detail: str = ""


CheckFn = Callable[[Patch, Site, Policy], RuleOutcome]


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """Static metadata for one rule.

    `rationale` is fed back to the proposer verbatim on rejection, so it
    must describe the violated property in actionable terms, not merely
    name the rule.
    """

    rule_id: str
    layer: Layer
    unsafe_class: UnsafeClass | None
    cwe: str
    severity: str  # "high" | "medium" | "low"
    rationale: str
    check: CheckFn
    fixtures_dir: Path

    @property
    def passing_fixtures(self) -> list[Path]:
        d = self.fixtures_dir / "passing"
        return sorted(d.glob("*.diff")) if d.exists() else []

    @property
    def violating_fixtures(self) -> list[Path]:
        d = self.fixtures_dir / "violating"
        return sorted(d.glob("*.diff")) if d.exists() else []

    def has_required_fixtures(self) -> bool:
        return len(self.passing_fixtures) >= 1 and len(self.violating_fixtures) >= 1
