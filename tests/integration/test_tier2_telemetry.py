"""Tier-2 app #4 (telemetry-signer): detector ground truth + sibling-package L3.

The surfaces this app varies past apps #1-3, asserted here:

1. Miss mechanism #4 -- array-index indirection: the algorithm chosen from a
   compatibility table by a runtime index must be MISSED, while a simple
   static final constant would NOT hide (Semgrep constant-folds it; this
   app's first draft was caught exactly that way and the mechanism was
   changed -- eval/perturb.py pins the same asymmetry).

2. L3 project mode across SIBLING top-level packages: the entrypoint in
   `collector` reflectively guards `sealing`'s public API, so a benign
   migration passes and a compiling API-break is rejected.
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

_APP_DIR = Path(__file__).resolve().parents[2] / "corpus" / "tier2" / "telemetry-signer"


def _ground_truth() -> dict:
    return yaml.safe_load((_APP_DIR / "sites.yaml").read_text())


def test_detector_precision_and_recall_on_telemetry_app() -> None:
    gt = _ground_truth()
    detectable_lines = {s["line"] for s in gt["sites"] if s["detectable"]}
    all_gt_lines = {s["line"] for s in gt["sites"]}

    found = detect(_APP_DIR / "src", repo_name="telemetry-signer")
    found_lines = {s.line for s in found}

    false_positives = found_lines - all_gt_lines
    recall = len(found_lines & all_gt_lines) / len(all_gt_lines)

    assert not false_positives, f"unexpected false positives: {false_positives}"
    assert recall < 1.0, "recall is 100%; the table-indexed site was not actually hard"
    assert found_lines == detectable_lines, (
        "detector should find exactly the detectable sites, no more, no fewer"
    )


def test_detector_usage_classes_match_telemetry_ground_truth() -> None:
    gt = _ground_truth()
    expected = {s["line"]: s["usage_class"] for s in gt["sites"] if s["detectable"]}

    found = detect(_APP_DIR / "src", repo_name="telemetry-signer")
    actual = {s.line: s.usage_class.value for s in found}

    assert actual == expected


def test_array_indexed_algorithm_is_missed() -> None:
    """Mechanism #4's load-bearing claim, in isolation."""
    found_lines = {s.line for s in detect(_APP_DIR / "src", repo_name="telemetry-signer")}
    assert 57 not in found_lines  # Signature.getInstance(FLEET_SEAL_ALGS[protocolVersion])


# --- L3 project mode across sibling packages ---------------------------------

pytestmark_l3 = pytest.mark.skipif(
    shutil.which("javac") is None or shutil.which("java") is None,
    reason="L3 project mode requires a JDK (javac + java) on PATH",
)

_TRIVIAL_POLICY = Policy(
    name="test", version="0", floors={}, hybrid_required={}, allowed_randomness_sources=()
)


def _seal_site():
    return next(
        s for s in detect(_APP_DIR / "src", repo_name="telemetry-signer") if s.line == 40
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
def test_l3_project_mode_builds_sibling_packages() -> None:
    site = _seal_site()
    original = Path(site.file_path).read_text(encoding="utf-8")
    patched = original.replace("SHA512withECDSA", "ML-DSA-87")
    outcome = l3_build.check(_patch(original, patched, site), site, _TRIVIAL_POLICY)
    assert outcome.status == RuleStatus.PASS
    assert "project build + tests passed (telemetry-signer)" in outcome.detail


@pytestmark_l3
def test_l3_rejects_api_break_across_packages() -> None:
    """Renaming a public method in `sealing` compiles; only `collector`'s
    reflective suite, reaching across the sibling package, catches it."""
    site = _seal_site()
    original = Path(site.file_path).read_text(encoding="utf-8")
    patched = original.replace("public byte[] wrapBatchKey(", "public byte[] wrapBatchKeyV2(")
    outcome = l3_build.check(_patch(original, patched, site), site, _TRIVIAL_POLICY)
    assert outcome.status == RuleStatus.FAIL
    assert "tests failed" in outcome.detail
