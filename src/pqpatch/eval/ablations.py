"""Named ablation configurations (RQ4) -- the experiment grid's vocabulary.

Each name maps to the exact pipeline knobs that arm uses, so a run script
selects an ablation by name and the settings cannot drift between scripts,
manifests, and the paper's prose. The dataclass is frozen: an ablation is a
definition, not a mutable option bag.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pqpatch.model import Layer
from pqpatch.verifier.api import DEFAULT_ENABLED_LAYERS


@dataclass(frozen=True, slots=True)
class AblationConfig:
    name: str
    enabled_layers: frozenset[Layer]
    l1_mode: str = "pq"
    feedback_mode: str = "rule"
    k: int = 3
    description: str = field(default="", compare=False)


ABLATIONS: dict[str, AblationConfig] = {
    cfg.name: cfg
    for cfg in (
        AblationConfig(
            name="full",
            enabled_layers=DEFAULT_ENABLED_LAYERS,
            description="the system under test: PQ L1 + L2 + L3, rule feedback, k=3",
        ),
        AblationConfig(
            name="remove-l2",
            enabled_layers=frozenset({Layer.L1_SYNTACTIC, Layer.L3_BUILD}),
            description="drops the dataflow layer; the paper's largest predicted regression",
        ),
        AblationConfig(
            name="l3-only",
            enabled_layers=frozenset({Layer.L3_BUILD}),
            description="the industry-default gate: accept what compiles and passes tests",
        ),
        AblationConfig(
            name="no-repair",
            enabled_layers=DEFAULT_ENABLED_LAYERS,
            k=1,
            description="first proposal only; isolates what the repair loop contributes",
        ),
        AblationConfig(
            name="generic-feedback",
            enabled_layers=DEFAULT_ENABLED_LAYERS,
            feedback_mode="generic",
            description="RQ3 control: repair loop runs but the rule rationale is withheld",
        ),
        AblationConfig(
            name="stock-l1",
            enabled_layers=DEFAULT_ENABLED_LAYERS,
            l1_mode="stock",
            description="classical-era scanner pack replaces the PQ L1 registry (RQ4)",
        ),
    )
}


def get_ablation(name: str) -> AblationConfig:
    try:
        return ABLATIONS[name]
    except KeyError:
        raise KeyError(
            f"unknown ablation {name!r}; known: {sorted(ABLATIONS)}"
        ) from None
