"""LaTeX table generation from run manifests.

Every number in the paper regenerates from runs/; nothing is typed by hand.
With no runs present this exits nonzero -- no row is ever emitted without a
backing manifest.
"""

from __future__ import annotations

import sys
from pathlib import Path

_RUNS = Path(__file__).resolve().parents[3] / "runs"


def main() -> int:
    run_dirs = [p for p in _RUNS.iterdir() if p.is_dir()] if _RUNS.exists() else []
    if not run_dirs:
        print(
            "NOT READY: runs/ contains no experiment output. Tables are generated "
            "exclusively from run manifests; execute the experiment configurations "
            "first. See docs/STATUS.md."
        )
        return 1
    # Full implementation: parse manifests, compute Estimates via eval.metrics,
    # emit rows keyed to the manuscript's table labels.
    print(f"found {len(run_dirs)} run(s); table emission not yet implemented.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
