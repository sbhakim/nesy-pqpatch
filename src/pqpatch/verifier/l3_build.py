"""L3: build verification.

Current scope is a single-file compile of the patched source against the
host JDK; the production target is a containerized project build plus the
project's own test suite (ADR-002). Sufficient to reject patches that do
not compile, which is the property the pipeline needs from this layer today.
"""

from __future__ import annotations

import subprocess  # noqa: S404 -- fixed argv, no shell
import tempfile
from pathlib import Path

from pqpatch.model import Patch, Policy, RuleStatus, Site
from pqpatch.verifier.rules.diffapply import DiffApplyError, apply_unified_diff
from pqpatch.verifier.rules.spec import RuleOutcome

_JAVAC_TIMEOUT_S = 30


def check(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del policy
    try:
        original = Path(site.file_path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        return RuleOutcome(RuleStatus.ERROR, detail=f"site source file not found: {exc}")

    try:
        patched_source = apply_unified_diff(original, patch.unified_diff)
    except DiffApplyError as exc:
        return RuleOutcome(RuleStatus.FAIL, detail=f"patch does not apply cleanly: {exc}")

    class_name = Path(site.file_path).stem
    with tempfile.TemporaryDirectory(prefix="pqpatch-l3-") as tmp:
        tmp_path = Path(tmp)
        java_file = tmp_path / f"{class_name}.java"
        java_file.write_text(patched_source, encoding="utf-8")

        # javac resolves via PATH by design: the production path pins the JDK
        # at the container level, not here. Fixed argv; no user input.
        try:
            proc = subprocess.run(  # noqa: S603
                ["javac", "-d", str(tmp_path), "-Xlint:none", str(java_file)],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=_JAVAC_TIMEOUT_S,
                check=False,
            )
        except FileNotFoundError:
            return RuleOutcome(
                RuleStatus.ERROR,
                detail="javac not found on PATH; L3 cannot verify the build",
            )
        except subprocess.TimeoutExpired:
            return RuleOutcome(RuleStatus.ERROR, detail="javac timed out")

        if proc.returncode != 0:
            return RuleOutcome(
                RuleStatus.FAIL,
                detail=f"javac failed (exit {proc.returncode}):\n{proc.stderr[-1000:]}",
            )

    return RuleOutcome(RuleStatus.PASS)
