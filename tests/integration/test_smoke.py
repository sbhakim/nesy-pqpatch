"""End-to-end smoke test (codebase-plan.md §5 Phase-0/3 exit criterion):
detector -> extractor -> proposer(replay) -> verifier -> repair loop -> trace,
fully offline-reproducible.

This is also the project's first real demonstration of the repair loop
converging: attempt 1 proposes a patch that violates the policy floor
(PQ-PARAM-01), the verifier rejects it, rule-derived feedback is generated,
and attempt 2 (a corrected patch) is accepted -- Algorithm 1 end to end,
against real detector output and a real compile check, not mocked layers.
"""

from __future__ import annotations

from pathlib import Path

from pqpatch.detector.api import detect
from pqpatch.extractor.context import extract_context
from pqpatch.loop import migrate_site
from pqpatch.model import VerdictStatus
from pqpatch.policy import load_policy
from pqpatch.proposer.cache import CacheStore
from pqpatch.proposer.replay_backend import ReplayBackend
from pqpatch.settings import Settings
from pqpatch.trace.canonical import verify_content_hash
from tests.support.diffgen import make_diff

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SEED_APP_SRC = _REPO_ROOT / "corpus" / "tier2" / "file-signing-cli" / "src"


def _settings(cache_dir: Path, *, offline: bool) -> Settings:
    return Settings(
        offline=offline,
        cache_dir=cache_dir,
        runs_dir=cache_dir.parent / "runs",
        repo_root=_REPO_ROOT,
        backend_a_api_key=None,
        backend_b_api_key=None,
        backend_c_base_url="http://localhost:8000/v1",
    )


def _find_sign_site():
    sites = detect(_SEED_APP_SRC, repo_name="file-signing-cli")
    return next(s for s in sites if s.line == 24)  # signFile: SIGN usage class


def test_smoke_full_pipeline_with_repair_loop(tmp_path: Path) -> None:
    site = _find_sign_site()
    context = extract_context(site)
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")

    original = Path(site.file_path).read_text(encoding="utf-8")
    unsafe_patched = original.replace("SHA256withRSA", "ML-DSA-44")  # below floor
    safe_patched = original.replace("SHA256withRSA", "ML-DSA-65")  # meets floor

    unsafe_response = (
        make_diff(original, unsafe_patched, site.file_path)
        + '\n{"primitive": "ML-DSA-44", "parameters": ""}'
    )
    safe_response = (
        make_diff(original, safe_patched, site.file_path)
        + '\n{"primitive": "ML-DSA-65", "parameters": ""}'
    )
    script = {
        (site.site_id, 1): unsafe_response,
        (site.site_id, 2): safe_response,
    }

    cache_dir = tmp_path / "cache"
    settings = _settings(cache_dir, offline=False)
    backend = ReplayBackend(settings, script)

    verdict, trace = migrate_site(site, context, policy, backend, k=3, ruleset_version="smoke-v0")

    # --- repair loop actually converged, not just "returned something" ---
    assert verdict.status == VerdictStatus.ACCEPT
    assert verdict.attempts_used == 2
    assert len(trace.events) == 2
    assert trace.events[0].status == "reject"
    assert trace.events[0].rule_id == "PQ-PARAM-01"
    assert trace.events[1].status == "accept"

    # --- trace integrity ---
    assert trace.content_hash
    assert verify_content_hash(trace)

    # --- determinism boundary: identical inputs, offline, must reproduce
    # the same DECISION with zero network access and zero calls to
    # ReplayBackend._generate_raw (proven by an empty script: a genuine
    # fetch attempt would raise ScriptExhaustedError, and a cache miss
    # under PQPATCH_OFFLINE=1 would raise OfflineCacheMissError -- either
    # failure mode would fail this test loudly). ---
    #
    # NOTE: content_hash itself is NOT asserted equal across runs. It is
    # computed over the full trace including per-layer duration_ms, which
    # is real wall-clock telemetry from L1/L3 re-running their actual
    # checks each call -- the manuscript's own metadata field M (Sec. 4.2
    # "verification duration") is defined to vary run over run; that is
    # what RQ3 measures. What must be reproducible is the DECISION content
    # (accepted patch, verdict sequence), not the timing bytes.
    offline_settings = _settings(cache_dir, offline=True)
    offline_backend = ReplayBackend(offline_settings, script={})  # empty: must never be consulted
    verdict2, trace2 = migrate_site(
        site, context, policy, offline_backend, k=3, ruleset_version="smoke-v0"
    )
    assert verdict2.status == VerdictStatus.ACCEPT
    assert verdict2.attempts_used == verdict.attempts_used
    assert verdict2.accepted_patch is not None
    assert verdict.accepted_patch is not None
    assert verdict2.accepted_patch.unified_diff == verdict.accepted_patch.unified_diff
    assert [e.status for e in trace2.events] == [e.status for e in trace.events]
    assert [e.rule_id for e in trace2.events] == [e.rule_id for e in trace.events]
    assert verify_content_hash(trace2)  # each trace is still internally self-consistent


def test_smoke_escalation_when_no_safe_patch_ever_proposed(tmp_path: Path) -> None:
    """If every attempt is unsafe, the loop must ESCALATE at k, never ACCEPT."""
    site = _find_sign_site()
    context = extract_context(site)
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")
    original = Path(site.file_path).read_text(encoding="utf-8")

    always_unsafe = (
        make_diff(original, original.replace("SHA256withRSA", "ML-DSA-44"), site.file_path)
        + '\n{"primitive": "ML-DSA-44", "parameters": ""}'
    )
    script = {(site.site_id, i): always_unsafe for i in range(1, 4)}

    settings = _settings(tmp_path / "cache", offline=False)
    backend = ReplayBackend(settings, script)

    verdict, trace = migrate_site(site, context, policy, backend, k=3, ruleset_version="smoke-v0")

    assert verdict.status == VerdictStatus.ESCALATE
    assert verdict.attempts_used == 3
    assert len(trace.events) == 3
    assert all(e.status == "reject" for e in trace.events)
    assert verify_content_hash(trace)


def test_cache_is_actually_used_not_just_present(tmp_path: Path) -> None:
    """Directly exercises CacheStore to prove a second identical fetch is a
    hit, independent of the loop -- codebase-plan.md Phase 3 exit criterion:
    'a second identical run makes zero API calls.'"""
    calls = {"count": 0}

    class CountingBackend(ReplayBackend):
        def _generate_raw(self, prompt: str, *, seed: int, site_id: str, attempt: int):
            calls["count"] += 1
            return super()._generate_raw(prompt, seed=seed, site_id=site_id, attempt=attempt)

    site = _find_sign_site()
    context = extract_context(site)
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")
    original = Path(site.file_path).read_text(encoding="utf-8")
    response = (
        make_diff(original, original.replace("SHA256withRSA", "ML-DSA-65"), site.file_path)
        + '\n{"primitive": "ML-DSA-65", "parameters": ""}'
    )

    settings = _settings(tmp_path / "cache", offline=False)
    cache = CacheStore(settings.cache_dir, offline=False)
    backend = CountingBackend(settings, {(site.site_id, 1): response}, cache=cache)

    p1 = backend.propose(context, policy, feedback=None, attempt=1, seed=0)
    p2 = backend.propose(context, policy, feedback=None, attempt=1, seed=0)

    assert calls["count"] == 1, "second identical propose() must be a cache hit"
    assert p1.response_hash == p2.response_hash
