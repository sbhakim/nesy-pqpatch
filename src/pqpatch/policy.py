"""Policy loading: policy/*.yaml -> Policy dataclass.

This is the only place YAML policy files are parsed; every downstream
consumer (the verifier rules) receives a Policy instance, never raw dicts.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from pqpatch.model import Policy, UsageClass


def load_policy(path: Path) -> Policy:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Policy(
        name=raw["name"],
        version=raw["version"],
        floors={UsageClass(k): v for k, v in raw.get("floors", {}).items()},
        hybrid_required={UsageClass(k): v for k, v in raw.get("hybrid_required", {}).items()},
        allowed_randomness_sources=tuple(raw["allowed_randomness_sources"]),
    )
