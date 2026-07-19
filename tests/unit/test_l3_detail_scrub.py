"""L3 failure details must not leak the randomized temp-directory path.

Details feed the repair loop as prompt text, so a random /tmp/pqpatch-l3-*
path makes prompts, cache keys, and every downstream proposal
nondeterministic across otherwise identical runs -- found live in the
ablation shakeout, where two arms diverged at attempt 3 purely because their
attempt-2 javac output named different temp directories."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pqpatch.detector.api import detect
from pqpatch.model import Patch, RuleStatus
from pqpatch.policy import load_policy
from pqpatch.verifier import l3_build
from tests.support.diffgen import make_diff

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TRAP_SRC = _REPO_ROOT / "corpus" / "traps" / "dev" / "fixed-seed-sign-001"


def test_compile_failure_detail_carries_no_tmp_path() -> None:
    if shutil.which("javac") is None:
        pytest.skip("javac not available")
    site = detect(_TRAP_SRC, repo_name="scrub-test")[0]
    original = Path(site.file_path).read_text(encoding="utf-8")
    broken = original.replace("return gen.generateKeyPair();", "return gen.noSuchMethod();")
    patch = Patch(
        site_id=site.site_id,
        attempt=1,
        unified_diff=make_diff(original, broken, site.file_path),
        claimed_primitive="ML-DSA-65",
        claimed_parameters="",
        backend_id="test",
        prompt_version="v1",
        response_hash="0" * 64,
    )

    outcome = l3_build.check(patch, site, load_policy(_REPO_ROOT / "policy" / "default.yaml"))

    assert outcome.status == RuleStatus.FAIL  # the compile genuinely fails
    assert "pqpatch-l3-" not in outcome.detail  # and the detail is deterministic
    assert "/tmp/" not in outcome.detail  # noqa: S108 -- asserting absence, not using tmp
