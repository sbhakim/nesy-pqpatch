"""The stock classical-era L1 arm (RQ4 ablation only, never the shipping gate).

Swaps the PQ-aware L1 rule registry for a classical-era scanner pass: apply the
patch, scan the patched file with the vendored classical crypto pack
(``pack/classical_crypto.yml``), and fail on any finding. The pack knows about
broken ciphers, ECB, weak hashes, and literal seeds -- and nothing about
parameter floors, hybrid completeness, key families, or the migration
obligation. The measurement is precisely what it misses: an unsafe PQ migration
(ML-KEM-512 below floor, a dropped hybrid half, a no-op patch) sails through,
so trap acceptance under this arm quantifies why classical-era rules do not
transfer.

Like a diff-aware CI scanner gate, the arm judges what the patch *introduces*:
the pack scans both the original and the patched file and fails only on
findings that are new. Pre-existing classical misuse elsewhere in a
pre-migration file is the corpus's baseline state, not the patch's fault --
without this the arm would reject every patch to any classical file and
measure nothing. An unapplyable diff is an ERROR (the check could not run),
never a PASS.
"""

from __future__ import annotations

import tempfile
from collections import Counter
from pathlib import Path

from pqpatch.detector.engine import scan_repo
from pqpatch.model import Patch, Policy, RuleStatus, Site
from pqpatch.verifier.rules.diffapply import DiffApplyError, apply_unified_diff
from pqpatch.verifier.rules.spec import RuleOutcome

_PACK_DIR = Path(__file__).parent / "pack"


def _finding_counts(source: str, filename: str) -> Counter[str]:
    with tempfile.TemporaryDirectory(prefix="pqpatch-l1stock-") as tmp:
        target = Path(tmp) / filename
        target.write_text(source, encoding="utf-8")
        matches = scan_repo(Path(tmp), pack_dir=_PACK_DIR)
    return Counter(m.rule_id for m in matches)


def check(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del policy  # classical-era rules know nothing of the migration policy
    if not patch.unified_diff.strip():
        # A no-op patch has nothing for a scanner to flag: the classical arm
        # accepts it -- exactly the blindness PQ-MIG-01 exists to close.
        return RuleOutcome(RuleStatus.PASS, detail="empty diff; classical pack sees nothing")

    original = Path(site.file_path).read_text(encoding="utf-8")
    try:
        patched = apply_unified_diff(original, patch.unified_diff)
    except DiffApplyError as exc:
        return RuleOutcome(RuleStatus.ERROR, detail=f"patch does not apply: {exc}")

    filename = Path(site.file_path).name
    before = _finding_counts(original, filename)
    after = _finding_counts(patched, filename)

    introduced = sorted(rule for rule in after if after[rule] > before.get(rule, 0))
    if introduced:
        return RuleOutcome(
            RuleStatus.FAIL,
            detail=f"classical-era pack flags findings the patch introduces: "
            f"{', '.join(introduced)}",
        )
    return RuleOutcome(
        RuleStatus.PASS, detail="classical-era pack sees nothing new in the patch"
    )
