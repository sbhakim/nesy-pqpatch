"""RQ0: detection quality against Tier-2 exact ground truth.

Runs the real detector over every Tier-2 app that carries a ``sites.yaml`` and
scores it against the hand-confirmed labels: precision over all reported
sites, recall over the detectable ground truth, per-usage-class recall, and
the deliberate-miss check (sites seeded to be missed must actually be missed
-- a detector that "finds" one is matching something else, which would be a
labeling or rule error worth failing loudly on).

Computable offline with no model; this is the paper's Tier-1/2 half of RQ0.
Wilson intervals come from eval.metrics so the table shares the manuscript's
convention.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

from pqpatch.detector.api import detect
from pqpatch.eval.metrics import Estimate, wilson_ci

_CORPUS = Path(__file__).resolve().parents[3] / "corpus"


def score_app(app_dir: Path) -> dict[str, object]:
    """Score the detector against one app's sites.yaml ground truth."""
    truth = yaml.safe_load((app_dir / "sites.yaml").read_text(encoding="utf-8"))
    src_dir = app_dir / truth.get("source_dir", "src")
    detected = detect(src_dir, repo_name=app_dir.name)

    gt_by_line: dict[int, dict[str, object]] = {s["line"]: s for s in truth["sites"]}
    detectable_lines = {line for line, s in gt_by_line.items() if s["detectable"]}
    miss_lines = {line for line, s in gt_by_line.items() if not s["detectable"]}

    true_pos = [s for s in detected if s.line in detectable_lines]
    false_pos = [s for s in detected if s.line not in gt_by_line]
    found_deliberate_miss = [s for s in detected if s.line in miss_lines]

    class_correct = [
        s for s in true_pos if gt_by_line[s.line]["usage_class"] == s.usage_class.value
    ]

    per_class: dict[str, Estimate] = {}
    for uc in sorted({str(s["usage_class"]) for s in truth["sites"] if s["detectable"]}):
        lines = {ln for ln in detectable_lines if gt_by_line[ln]["usage_class"] == uc}
        hits = sum(1 for s in true_pos if s.line in lines)
        per_class[uc] = wilson_ci(hits, len(lines))

    return {
        "app": app_dir.name,
        "n_detected": len(detected),
        "precision": wilson_ci(len(true_pos), len(detected)) if detected else None,
        "recall": wilson_ci(len(true_pos), len(detectable_lines)),
        "class_accuracy": wilson_ci(len(class_correct), len(true_pos)) if true_pos else None,
        "per_class_recall": per_class,
        "false_positives": [f"{s.file_path}:{s.line}" for s in false_pos],
        "deliberate_miss_found": [f"{s.file_path}:{s.line}" for s in found_deliberate_miss],
        "n_deliberate_miss": len(miss_lines),
    }


def _pct(est: Estimate | None) -> str:
    if est is None:
        return "n/a"
    return (
        f"{100 * est.point:.1f}% [{100 * est.ci_low:.1f}, {100 * est.ci_high:.1f}] "
        f"({est.successes}/{est.n})"
    )


def main() -> int:
    apps = sorted(
        p
        for p in (_CORPUS / "tier2").iterdir()
        if p.is_dir() and (p / "sites.yaml").exists()
    )
    if not apps:
        print("no Tier-2 apps with sites.yaml ground truth; nothing to score")
        return 1

    failed = False
    for app_dir in apps:
        score = score_app(app_dir)
        print(f"\n=== RQ0 detection :: {score['app']} ===")
        print(f"  precision        : {_pct(score['precision'])}")  # type: ignore[arg-type]
        print(f"  recall           : {_pct(score['recall'])}")  # type: ignore[arg-type]
        print(f"  class accuracy   : {_pct(score['class_accuracy'])}")  # type: ignore[arg-type]
        per_class = score["per_class_recall"]
        assert isinstance(per_class, dict)  # narrow the dict[str, object] value
        for uc, est in per_class.items():
            print(f"    recall[{uc:9s}]: {_pct(est)}")
        print(f"  deliberate misses: {score['n_deliberate_miss']} seeded")
        if score["false_positives"]:
            failed = True
            print(f"  FALSE POSITIVES  : {score['false_positives']}")
        if score["deliberate_miss_found"]:
            failed = True
            print(
                f"  LABEL/RULE ERROR : detector found sites seeded as misses: "
                f"{score['deliberate_miss_found']}"
            )
    if failed:
        print("\nRQ0 FAILED: unexpected detections above; fix labels or rules.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
