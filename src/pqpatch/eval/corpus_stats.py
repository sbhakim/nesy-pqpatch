"""Corpus statistics, computed from disk.

The paper's corpus table is generated, never typed by hand. This reports the
actual state and exits nonzero unless it meets the scope the manuscript
claims, so `make corpus-stats` cannot go green on a corpus that would
misrepresent the paper.

The targets below are the *ICC* scope: five Tier-2 applications, 35 seeded
sites, 21 traps split 9 dev / 12 held-out. They deliberately replace the
earlier ACM-draft targets (6 apps / 94 sites / 52 traps / 18 in-the-wild
projects), which described work that was never carried out; the manuscript was
edited down to the real numbers rather than the corpus being inflated up to
them. Raising a target here is a commitment to author the corpus to match, not
a way to make the check pass.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

from pqpatch.eval.traps import load_trap_suite, summarize_suite

_CORPUS = Path(__file__).resolve().parents[3] / "corpus"

# ICC scope. Each entry is (label, actual-getter description, required value).
_TARGET_TIER2_APPS = 5
_TARGET_TIER2_SITES = 35
_TARGET_TRAPS_DEV = 9
_TARGET_TRAPS_HELDOUT = 12


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
    print(
        f"  tier1/original: {len(tier1)} entries; "
        f"traps: {stats.n_dev} dev, {stats.n_heldout} held-out"
    )
    print(
        f"    trap provenance: {stats.n_taxonomy} taxonomy, {stats.n_external} external, "
        f"{stats.n_unanticipated} unanticipated"
    )
    print(f"    compiling-unsafe: {stats.n_compiling_unsafe}/{stats.total}")

    # Agreement, never kappa: the suite is unsafe by construction, so the label
    # marginals are degenerate and kappa collapses regardless of how well the
    # judges agree (see TrapSuiteStats). Both figures are printed because they
    # are different statistics and the manuscript must not conflate them.
    if stats.pct_agreement is not None:
        print(
            f"    blind labels: {stats.n_unanimous}/{stats.n_multi_labelled} unanimous "
            f"({stats.n_unanimous / stats.n_multi_labelled:.1%} of traps); "
            f"{stats.pct_agreement:.1%} agreement over all label pairs"
        )
        if stats.kappa is not None:
            print(f"      (kappa = {stats.kappa:.3f} -- degenerate marginals; do not report)")

    shortfalls = [
        (label, actual, target)
        for label, actual, target in (
            ("tier2 apps", len(tier2_apps), _TARGET_TIER2_APPS),
            ("tier2 sites", total_sites, _TARGET_TIER2_SITES),
            ("dev traps", stats.n_dev, _TARGET_TRAPS_DEV),
            ("held-out traps", stats.n_heldout, _TARGET_TRAPS_HELDOUT),
        )
        if actual < target
    ]

    if shortfalls:
        print("\nNOT READY: the corpus is short of the ICC scope the manuscript claims:")
        for label, actual, target in shortfalls:
            print(f"  {label}: {actual} < {target}")
        print("No table will be emitted until it is. See docs/STATUS.md.")
        return 1

    print(
        f"\nREADY: corpus meets the ICC scope "
        f"({_TARGET_TIER2_APPS} apps / {_TARGET_TIER2_SITES} sites / "
        f"{_TARGET_TRAPS_DEV} dev + {_TARGET_TRAPS_HELDOUT} held-out traps)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
