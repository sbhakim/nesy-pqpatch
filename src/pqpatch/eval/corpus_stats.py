"""Corpus statistics, computed from disk.

The paper's corpus table is generated, never typed by hand. Until the full
corpus exists this reports the actual state and exits nonzero rather than
emitting a table that would misrepresent it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

from pqpatch.eval.traps import load_trap_suite, summarize_suite

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

    # Traps are validated on load: a malformed descriptor is a hard error here,
    # never a miscounted row. summarize_suite reports the construct-validity
    # facts (provenance mix, compiling fraction, blind-label kappa) offline.
    specs = load_trap_suite(_CORPUS / "traps")
    stats = summarize_suite(specs)
    kappa_str = f"{stats.kappa:.3f}" if stats.kappa is not None else "n/a"
    print(
        f"  tier1/original: {len(tier1)} entries; "
        f"traps: {stats.n_dev} dev, {stats.n_heldout} held-out"
    )
    print(
        f"    trap provenance: {stats.n_taxonomy} taxonomy, {stats.n_external} external, "
        f"{stats.n_unanticipated} unanticipated"
    )
    print(
        f"    compiling-unsafe: {stats.n_compiling_unsafe}/{stats.total}; "
        f"blind-label kappa: {kappa_str}"
    )

    print(
        "\nNOT READY: the corpus is incomplete (target: 6 Tier-2 apps / 94 sites, "
        "extended Tier-1, 52 traps). No table will be emitted until it is. "
        "See docs/STATUS.md."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
