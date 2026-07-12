"""L3 build-and-test, project mode (verifier/l3_build.py, ADR-002 successor).

These tests need a real JDK on PATH; they are skipped otherwise so the suite
still runs on a machine without one. The load-bearing case is
`test_rejects_api_breaking_patch_that_still_compiles`: it proves L3 now runs
the project's tests, not merely a compile -- the patch compiles cleanly and is
rejected only because the regression suite catches the broken API.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pqpatch.detector.api import detect
from pqpatch.model import Patch, Policy, RuleStatus, UsageClass
from pqpatch.verifier import l3_build
from tests.support.diffgen import make_diff

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SEED_APP_SRC = _REPO_ROOT / "corpus" / "tier2" / "file-signing-cli" / "src"

pytestmark = pytest.mark.skipif(
    shutil.which("javac") is None or shutil.which("java") is None,
    reason="L3 project mode requires a JDK (javac + java) on PATH",
)

_TRIVIAL_POLICY = Policy(
    name="test", version="0", floors={}, hybrid_required={}, allowed_randomness_sources=()
)


def _sign_site():
    return next(s for s in detect(_SEED_APP_SRC, repo_name="file-signing-cli") if s.line == 24)


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


def test_accepts_compilable_migration_and_runs_the_project_tests():
    site = _sign_site()
    original = Path(site.file_path).read_text(encoding="utf-8")
    patched = original.replace("SHA256withRSA", "ML-DSA-65")
    outcome = l3_build.check(_patch(original, patched, site), site, _TRIVIAL_POLICY)
    assert outcome.status == RuleStatus.PASS
    assert "project build + tests passed" in outcome.detail  # project mode, not single-file


def test_rejects_patch_that_does_not_compile():
    site = _sign_site()
    original = Path(site.file_path).read_text(encoding="utf-8")
    patched = original.replace("return sig.sign();", "return sig.sign()")  # dropped semicolon
    outcome = l3_build.check(_patch(original, patched, site), site, _TRIVIAL_POLICY)
    assert outcome.status == RuleStatus.FAIL
    assert "build failed" in outcome.detail


def test_rejects_api_breaking_patch_that_still_compiles():
    """The patch compiles (it only renames a private method), so a compile-only
    L3 would wave it through. The regression suite reflectively asserts the
    signing API, so project-mode L3 must reject it -- this is the whole point of
    running tests rather than just compiling."""
    site = _sign_site()
    original = Path(site.file_path).read_text(encoding="utf-8")
    patched = original.replace("byte[] signFile(", "byte[] signFileRenamed(")
    outcome = l3_build.check(_patch(original, patched, site), site, _TRIVIAL_POLICY)
    assert outcome.status == RuleStatus.FAIL
    assert "tests failed" in outcome.detail


def test_single_file_fallback_when_no_build_descriptor(tmp_path: Path):
    """A site whose file has no build.yaml above it falls back to a standalone
    compile, honestly labelled (ADR-002)."""
    java = tmp_path / "Standalone.java"
    java.write_text("public class Standalone { int f() { return 1; } }\n", encoding="utf-8")
    site = _sign_site_at(str(java))
    original = java.read_text(encoding="utf-8")
    patched = original.replace("return 1;", "return 2;")
    outcome = l3_build.check(_patch(original, patched, site), site, _TRIVIAL_POLICY)
    assert outcome.status == RuleStatus.PASS
    assert "single-file compile only" in outcome.detail


def _sign_site_at(file_path: str):
    from pqpatch.model import Site

    return Site(
        site_id="standalone#1",
        repo="tmp",
        file_path=file_path,
        line=1,
        usage_class=UsageClass.SIGN,
        matched_symbol="x",
        detector_rule_id="test",
    )
