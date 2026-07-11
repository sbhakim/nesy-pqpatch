"""Rule registry.

Rule modules register at import time; `load_all()` performs explicit
imports so the active rule set is greppable rather than discovered by
filesystem magic.
"""

from __future__ import annotations

from pqpatch.model import Layer
from pqpatch.verifier.rules.spec import RuleSpec

_REGISTRY: dict[str, RuleSpec] = {}


def register(spec: RuleSpec) -> RuleSpec:
    if spec.rule_id in _REGISTRY:
        raise ValueError(f"duplicate rule id: {spec.rule_id!r}")
    _REGISTRY[spec.rule_id] = spec
    return spec


def load_all() -> None:
    """Import every rule module so its rules register. Idempotent."""
    from pqpatch.verifier.l1_syntactic import rules as _l1  # noqa: F401

    del _l1


def all_rules() -> list[RuleSpec]:
    if not _REGISTRY:
        load_all()
    return list(_REGISTRY.values())


def rules_by_layer(layer: Layer) -> list[RuleSpec]:
    return [r for r in all_rules() if r.layer == layer]


def get(rule_id: str) -> RuleSpec:
    if not _REGISTRY:
        load_all()
    return _REGISTRY[rule_id]
