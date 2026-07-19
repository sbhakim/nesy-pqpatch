"""Tier-2 app #5 (token-broker): detector ground truth + flat-package L3.

Surfaces this app varies:

1. Miss mechanism #5 -- method-return-value indirection: the algorithm from a
   private helper method's return value must be MISSED (not a literal, not a
   foldable constant).

2. L3 project mode on a FLAT single package with a single-segment entrypoint
   (broker.BrokerTests), deliberately unlike apps #3-4's nested/sibling
   layouts, so L3's project mode is exercised across three distinct shapes.
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

_APP_DIR = Path(__file__).resolve().parents[2] / "corpus" / "tier2" / "token-broker"


def _ground_truth() -> dict:
    return yaml.safe_load((_APP_DIR / "sites.yaml").read_text())


def test_detector_precision_and_recall_on_broker_app() -> None:
    gt = _ground_truth()
    detectable_lines = {s["line"] for s in gt["sites"] if s["detectable"]}
    all_gt_lines = {s["line"] for s in gt["sites"]}

    found = detect(_APP_DIR / "src", repo_name="token-broker")
    found_lines = {s.line for s in found}

    false_positives = found_lines - all_gt_lines
    recall = len(found_lines & all_gt_lines) / len(all_gt_lines)

    assert not false_positives, f"unexpected false positives: {false_positives}"
    assert recall < 1.0, "recall is 100%; the method-return-value site was not hard"
    assert found_lines == detectable_lines, (
        "detector should find exactly the detectable sites, no more, no fewer"
    )


def test_detector_usage_classes_match_broker_ground_truth() -> None:
    gt = _ground_truth()
    expected = {s["line"]: s["usage_class"] for s in gt["sites"] if s["detectable"]}

    found = detect(_APP_DIR / "src", repo_name="token-broker")
    actual = {s.line: s.usage_class.value for s in found}

    assert actual == expected


def test_method_return_value_algorithm_is_missed() -> None:
    """Mechanism #5's load-bearing claim, in isolation."""
    found_lines = {s.line for s in detect(_APP_DIR / "src", repo_name="token-broker")}
    assert 53 not in found_lines  # Signature.getInstance(negotiatedScheme())


# --- L3 project mode on a flat package ---------------------------------------

pytestmark_l3 = pytest.mark.skipif(
    shutil.which("javac") is None or shutil.which("java") is None,
    reason="L3 project mode requires a JDK (javac + java) on PATH",
)

_TRIVIAL_POLICY = Policy(
    name="test", version="0", floors={}, hybrid_required={}, allowed_randomness_sources=()
)


def _sign_site():
    return next(
        s for s in detect(_APP_DIR / "src", repo_name="token-broker") if s.line == 37
    )


def _patch(original: str, patched: str, site) -> Patch:
    return Patch(
        site_id=site.site_id,
        attempt=1,
        unified_diff=make_diff(original, patched, site.file_path),
        claimed_primitive="ML-DSA-65",
        claimed_parameters="",
        backend_id="test",
        prompt_version="test",
        response_hash="0" * 64,
    )


@pytestmark_l3
def test_l3_project_mode_builds_the_flat_package() -> None:
    site = _sign_site()
    original = Path(site.file_path).read_text(encoding="utf-8")
    patched = original.replace("SHA1withRSA", "ML-DSA-65")
    outcome = l3_build.check(_patch(original, patched, site), site, _TRIVIAL_POLICY)
    assert outcome.status == RuleStatus.PASS
    assert "project build + tests passed (token-broker)" in outcome.detail


@pytestmark_l3
def test_l3_rejects_api_break_in_flat_package() -> None:
    site = _sign_site()
    original = Path(site.file_path).read_text(encoding="utf-8")
    patched = original.replace("public byte[] wrapSessionKey(", "public byte[] wrapSessionKeyV2(")
    outcome = l3_build.check(_patch(original, patched, site), site, _TRIVIAL_POLICY)
    assert outcome.status == RuleStatus.FAIL
    assert "tests failed" in outcome.detail
