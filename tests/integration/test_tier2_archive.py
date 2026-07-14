"""Tier-2 app #2 (secure-archive-tool): detector ground truth + packaged L3.

Two claims this app exists to test, per the corpus-growth step:

1. The detector's precision/recall generalize past the seed app: different
   classical algorithms (DSA/ECDSA/DH/PKCS1), a Java package, and a different
   deliberately-hard mechanism (concatenated algorithm string, not a config
   lookup) -- found sites must match sites.yaml exactly, and the hard site
   must actually be missed.

2. L3 project mode is not overfit to a flat source directory: the packaged
   tree (src/archive/*.java, dotted test entrypoint) must compile and run its
   own regression suite, accept a benign migration, and reject a compiling
   patch that breaks the public API.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from pqpatch.detector.api import detect
from pqpatch.model import Patch, Policy, RuleStatus
from pqpatch.verifier import l3_build
from tests.support.diffgen import make_diff

_APP_DIR = Path(__file__).resolve().parents[2] / "corpus" / "tier2" / "secure-archive-tool"


def _ground_truth() -> dict:
    return yaml.safe_load((_APP_DIR / "sites.yaml").read_text())


def test_detector_precision_and_recall_on_archive_app() -> None:
    gt = _ground_truth()
    detectable_lines = {s["line"] for s in gt["sites"] if s["detectable"]}
    all_gt_lines = {s["line"] for s in gt["sites"]}

    found = detect(_APP_DIR / "src", repo_name="secure-archive-tool")
    found_lines = {s.line for s in found}

    false_positives = found_lines - all_gt_lines
    recall = len(found_lines & all_gt_lines) / len(all_gt_lines)

    assert not false_positives, f"unexpected false positives: {false_positives}"
    assert recall < 1.0, "recall is 100%; the concatenation site was not actually hard"
    assert found_lines == detectable_lines, (
        "detector should find exactly the detectable sites, no more, no fewer"
    )


def test_detector_usage_classes_match_archive_ground_truth() -> None:
    gt = _ground_truth()
    expected = {s["line"]: s["usage_class"] for s in gt["sites"] if s["detectable"]}

    found = detect(_APP_DIR / "src", repo_name="secure-archive-tool")
    actual = {s.line: s.usage_class.value for s in found}

    assert actual == expected


# --- L3 project mode on a packaged tree -------------------------------------

pytestmark_l3 = pytest.mark.skipif(
    shutil.which("javac") is None or shutil.which("java") is None,
    reason="L3 project mode requires a JDK (javac + java) on PATH",
)

_TRIVIAL_POLICY = Policy(
    name="test", version="0", floors={}, hybrid_required={}, allowed_randomness_sources=()
)


def _sign_site():
    return next(
        s for s in detect(_APP_DIR / "src", repo_name="secure-archive-tool") if s.line == 27
    )


def _patch(original: str, patched: str, site) -> Patch:
    return Patch(
        site_id=site.site_id,
        attempt=1,
        unified_diff=make_diff(original, patched, site.file_path),
        claimed_primitive="ML-DSA-87",
        claimed_parameters="",
        backend_id="test",
        prompt_version="test",
        response_hash="0" * 64,
    )


@pytestmark_l3
def test_l3_project_mode_builds_the_packaged_tree() -> None:
    site = _sign_site()
    original = Path(site.file_path).read_text(encoding="utf-8")
    patched = original.replace("SHA384withECDSA", "ML-DSA-87")
    outcome = l3_build.check(_patch(original, patched, site), site, _TRIVIAL_POLICY)
    assert outcome.status == RuleStatus.PASS
    assert "project build + tests passed (secure-archive-tool)" in outcome.detail


@pytestmark_l3
def test_l3_rejects_api_break_via_the_packaged_test_entrypoint() -> None:
    """Renaming a public method compiles cleanly, so only the project's own
    reflective regression suite -- run through the dotted `archive.ArchiveTests`
    entrypoint -- can catch it. Proves the packaged entrypoint actually runs."""
    site = _sign_site()
    original = Path(site.file_path).read_text(encoding="utf-8")
    patched = original.replace("boolean verifyManifest(", "boolean verifyManifestRenamed(")
    outcome = l3_build.check(_patch(original, patched, site), site, _TRIVIAL_POLICY)
    assert outcome.status == RuleStatus.FAIL
    assert "tests failed" in outcome.detail
