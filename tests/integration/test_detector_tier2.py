"""Detector precision/recall against Tier-2 ground truth
(codebase-plan.md §1.2 "Stage A -- Detector shakeout").

Expectation, stated explicitly in the plan and asserted here: precision
should be high (the pattern-based detector should not invent sites that
aren't there) while recall should be LESS than 100% -- the deliberately
hard, configuration-driven site exists specifically to be missed. A recall
of exactly 1.0 would mean the seed app failed to seed a genuinely hard
case, which is itself a bug worth catching.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from pqpatch.detector.api import detect

_APP_DIR = Path(__file__).resolve().parents[2] / "corpus" / "tier2" / "file-signing-cli"


def _ground_truth() -> dict:
    return yaml.safe_load((_APP_DIR / "sites.yaml").read_text())


def test_detector_precision_and_recall_on_seed_app() -> None:
    gt = _ground_truth()
    detectable_lines = {s["line"] for s in gt["sites"] if s["detectable"]}
    all_gt_lines = {s["line"] for s in gt["sites"]}

    found = detect(_APP_DIR / "src", repo_name="file-signing-cli")
    found_lines = {s.line for s in found}

    true_positives = found_lines & all_gt_lines
    false_positives = found_lines - all_gt_lines

    precision = len(true_positives) / len(found_lines) if found_lines else 0.0
    recall = len(true_positives) / len(all_gt_lines)

    # Stage A decision rule (codebase-plan.md §1.2): precision > 90% or the
    # Semgrep pack is too loose; recall must be < 100% because the
    # configuration-driven site is seeded specifically to be missed.
    assert precision > 0.90, f"precision {precision:.2f} below Stage-A threshold"
    assert not false_positives, f"unexpected false positives: {false_positives}"
    assert recall < 1.0, "recall is 100%; the deliberately hard site was not actually hard"
    assert found_lines == detectable_lines, (
        "detector should find exactly the detectable sites, no more, no fewer"
    )


def test_detector_usage_classes_match_ground_truth() -> None:
    gt = _ground_truth()
    expected = {s["line"]: s["usage_class"] for s in gt["sites"] if s["detectable"]}

    found = detect(_APP_DIR / "src", repo_name="file-signing-cli")
    actual = {s.line: s.usage_class.value for s in found}

    assert actual == expected
