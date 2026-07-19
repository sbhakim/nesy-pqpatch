"""Tier-2 app #3 (keyvault-syncd): detector ground truth + two-level packaged L3.

The surfaces this app varies past apps #1-2, asserted here:

1. Provider-pinned idioms: two-arg KeyPairGenerator.getInstance(alg, provider)
   sites must be DETECTED (the pack matches them), while the two-arg
   Signature.getInstance(alg, provider) site must be MISSED -- deliberate-miss
   mechanism #3 (config lookup, string concatenation, now provider pinning).

2. L3 project mode on a two-level package tree (vault.core + vault.crypto)
   with a two-segment dotted entrypoint: a benign migration passes build+tests,
   and a compiling API-break is caught only by the project's own reflective
   suite run through vault.core.SyncTests.
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

_APP_DIR = Path(__file__).resolve().parents[2] / "corpus" / "tier2" / "keyvault-syncd"


def _ground_truth() -> dict:
    return yaml.safe_load((_APP_DIR / "sites.yaml").read_text())


def test_detector_precision_and_recall_on_vault_app() -> None:
    gt = _ground_truth()
    detectable_lines = {s["line"] for s in gt["sites"] if s["detectable"]}
    all_gt_lines = {s["line"] for s in gt["sites"]}

    found = detect(_APP_DIR / "src", repo_name="keyvault-syncd")
    found_lines = {s.line for s in found}

    false_positives = found_lines - all_gt_lines
    recall = len(found_lines & all_gt_lines) / len(all_gt_lines)

    assert not false_positives, f"unexpected false positives: {false_positives}"
    assert recall < 1.0, "recall is 100%; the provider-pinned site was not actually hard"
    assert found_lines == detectable_lines, (
        "detector should find exactly the detectable sites, no more, no fewer"
    )


def test_detector_usage_classes_match_vault_ground_truth() -> None:
    gt = _ground_truth()
    expected = {s["line"]: s["usage_class"] for s in gt["sites"] if s["detectable"]}

    found = detect(_APP_DIR / "src", repo_name="keyvault-syncd")
    actual = {s.line: s.usage_class.value for s in found}

    assert actual == expected


def test_provider_pinned_kpg_detected_but_pinned_signature_missed() -> None:
    """The load-bearing surface claim: pinning a provider hides a Signature
    call from the pack but not a KeyPairGenerator call."""
    found_lines = {s.line for s in detect(_APP_DIR / "src", repo_name="keyvault-syncd")}
    assert 28 in found_lines  # KeyPairGenerator.getInstance("RSA", "SunRsaSign")
    assert 60 in found_lines  # KeyPairGenerator.getInstance("EC", "SunEC")
    assert 52 not in found_lines  # Signature.getInstance("SHA256withECDSA", "SunEC")


# --- L3 project mode on the two-level packaged tree --------------------------

pytestmark_l3 = pytest.mark.skipif(
    shutil.which("javac") is None or shutil.which("java") is None,
    reason="L3 project mode requires a JDK (javac + java) on PATH",
)

_TRIVIAL_POLICY = Policy(
    name="test", version="0", floors={}, hybrid_required={}, allowed_randomness_sources=()
)


def _seal_site():
    return next(
        s for s in detect(_APP_DIR / "src", repo_name="keyvault-syncd") if s.line == 35
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
def test_l3_project_mode_builds_the_two_level_tree() -> None:
    site = _seal_site()
    original = Path(site.file_path).read_text(encoding="utf-8")
    patched = original.replace("SHA512withRSA", "ML-DSA-87")
    outcome = l3_build.check(_patch(original, patched, site), site, _TRIVIAL_POLICY)
    assert outcome.status == RuleStatus.PASS
    assert "project build + tests passed (keyvault-syncd)" in outcome.detail


@pytestmark_l3
def test_l3_rejects_api_break_via_the_two_segment_entrypoint() -> None:
    """Renaming a public method compiles cleanly; only the reflective suite,
    run through the two-segment `vault.core.SyncTests` entrypoint, catches it."""
    site = _seal_site()
    original = Path(site.file_path).read_text(encoding="utf-8")
    patched = original.replace("public byte[] wrapDataKey(", "public byte[] wrapDataKeyV2(")
    outcome = l3_build.check(_patch(original, patched, site), site, _TRIVIAL_POLICY)
    assert outcome.status == RuleStatus.FAIL
    assert "tests failed" in outcome.detail
