"""Corpus statistics, computed from disk.

The paper's corpus table is generated, never typed by hand. Until the full
corpus exists this reports the actual state and exits nonzero rather than
emitting a table that would misrepresent it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

_CORPUS = Path(__file__).resolve().parents[3] / "corpus"


def main() -> int:
    tier2_apps = sorted(p for p in (_CORPUS / "tier2").iterdir() if p.is_dir())
    print("corpus state (real, from disk):")
    total_sites = 0
    for app in tier2_apps:
        sites_yaml = app / "sites.yaml"
        if sites_yaml.exists():
            data = yaml.safe_load(sites_yaml.read_text())
            n = data["counts"]["total_sites"]
            total_sites += n
            print(f"  tier2/{app.name}: {n} sites ({data['counts']['detectable']} detectable)")
    print(f"  tier2 total: {len(tier2_apps)} app(s), {total_sites} sites")

    tier1 = list((_CORPUS / "tier1" / "original").iterdir())
    traps_dev = list((_CORPUS / "traps" / "dev").iterdir())
    traps_held = list((_CORPUS / "traps" / "heldout").iterdir())
    print(
        f"  tier1/original: {len(tier1)} entries; "
        f"traps: {len(traps_dev)} dev, {len(traps_held)} held-out"
    )

    print(
        "\nNOT READY: the corpus is incomplete (target: 6 Tier-2 apps / 94 sites, "
        "extended Tier-1, 52 traps). No table will be emitted until it is. "
        "See docs/STATUS.md."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
