"""The RQ3/RQ4 baseline arms: the generic-feedback control and the
template-rewriter backend, driven against the real seed app (real detector,
real verifier, real javac) like the smoke tests."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from pqpatch.detector.api import detect
from pqpatch.extractor.context import extract_context
from pqpatch.loop import GENERIC_FEEDBACK, migrate_site
from pqpatch.model import Context, Patch, Policy, VerdictStatus
from pqpatch.policy import load_policy
from pqpatch.proposer.replay_backend import ReplayBackend
from pqpatch.proposer.template_backend import TemplateBackend
from pqpatch.settings import Settings
from tests.support.diffgen import make_diff

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SEED_APP_SRC = _REPO_ROOT / "corpus" / "tier2" / "file-signing-cli" / "src"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        offline=False,
        cache_dir=tmp_path / "cache",
        runs_dir=tmp_path / "runs",
        repo_root=_REPO_ROOT,
        backend_a_api_key=None,
        backend_b_api_key=None,
        backend_c_base_url="http://localhost:8000/v1",
    )


def _sign_site():
    return next(
        s for s in detect(_SEED_APP_SRC, repo_name="file-signing-cli") if s.line == 24
    )


class _FeedbackSpy(ReplayBackend):
    """Records the feedback text each propose() call receives."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.feedback_seen: list[str | None] = []

    def propose(
        self, context: Context, policy: Policy, *, feedback: str | None, **kwargs
    ) -> Patch:
        self.feedback_seen.append(feedback)
        return super().propose(context, policy, feedback=feedback, **kwargs)


def _two_attempt_script(site) -> dict[tuple[str, int], str]:
    original = Path(site.file_path).read_text(encoding="utf-8")
    unsafe = make_diff(
        original, original.replace("SHA256withRSA", "ML-DSA-44"), site.file_path
    )
    safe = make_diff(
        original, original.replace("SHA256withRSA", "ML-DSA-65"), site.file_path
    )
    return {
        (site.site_id, 1): unsafe + '\n{"primitive": "ML-DSA-44", "parameters": ""}',
        (site.site_id, 2): safe + '\n{"primitive": "ML-DSA-65", "parameters": ""}',
    }


def test_generic_feedback_withholds_the_rule_rationale(tmp_path: Path) -> None:
    site = _sign_site()
    context = extract_context(site)
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")

    backend = _FeedbackSpy(_settings(tmp_path), _two_attempt_script(site))
    verdict, _ = migrate_site(
        site, context, policy, backend, k=3, feedback_mode="generic"
    )

    assert verdict.status == VerdictStatus.ACCEPT
    assert backend.feedback_seen[0] is None
    assert backend.feedback_seen[1] == GENERIC_FEEDBACK  # not the PQ-PARAM-01 rationale


def test_rule_feedback_carries_the_rationale(tmp_path: Path) -> None:
    site = _sign_site()
    context = extract_context(site)
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")

    backend = _FeedbackSpy(_settings(tmp_path), _two_attempt_script(site))
    verdict, _ = migrate_site(site, context, policy, backend, k=3, feedback_mode="rule")

    assert verdict.status == VerdictStatus.ACCEPT
    assert backend.feedback_seen[1] is not None
    assert "policy floor" in backend.feedback_seen[1]  # PQ-PARAM-01's rationale text


def test_invalid_feedback_mode_rejected(tmp_path: Path) -> None:
    site = _sign_site()
    with pytest.raises(ValueError, match="feedback_mode"):
        migrate_site(
            site,
            extract_context(site),
            load_policy(_REPO_ROOT / "policy" / "default.yaml"),
            ReplayBackend(_settings(tmp_path), {}),
            feedback_mode="chatty",
        )


def test_template_backend_migrates_a_literal_sign_site(tmp_path: Path) -> None:
    """The non-neural arm handles the easy case: a literal algorithm string at
    the site line is rewritten to the policy floor and accepted end-to-end."""
    site = _sign_site()
    context = extract_context(site)
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")

    backend = TemplateBackend(_settings(tmp_path))
    verdict, trace = migrate_site(site, context, policy, backend, k=3)

    assert verdict.status == VerdictStatus.ACCEPT
    assert verdict.attempts_used == 1
    assert verdict.accepted_patch is not None
    assert 'getInstance("ML-DSA-65"' in verdict.accepted_patch.unified_diff
    assert "SHA256withRSA" not in verdict.accepted_patch.unified_diff.split("+++")[1].split("-")[0]


def test_template_backend_cannot_engage_a_nonliteral_site(tmp_path: Path) -> None:
    """The honest failure mode: no algorithm literal at the site line means an
    empty diff, which PQ-MIG-01 rejects as a no-op; templates cannot repair,
    so the site escalates -- the indirection-heavy gap RQ4 measures."""
    site = _sign_site()
    hard_site = dataclasses.replace(site, line=13)  # a line with no getInstance literal
    context = extract_context(hard_site)
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")

    backend = TemplateBackend(_settings(tmp_path))
    verdict, _ = migrate_site(hard_site, context, policy, backend, k=3)

    assert verdict.status == VerdictStatus.ESCALATE
    assert verdict.rejected_rule_id == "PQ-MIG-01"
