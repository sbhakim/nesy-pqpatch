"""Minimal L4 round-trip conformance on a real PQC-capable JDK.

The load-bearing test recreates the ablation-shakeout specimen: a patch whose
hallucinated composite algorithm literal satisfies every rule and compiles --
the full L1+L2+L3 stack ACCEPTS it -- and only the L4 round-trip, which must
actually resolve and exercise the algorithm, rejects it. Runtime-gated tests
skip when the pqc-jdk env is absent; the unconfigured-SKIPPED contract and the
literal extractor are tested everywhere."""

from __future__ import annotations

from pathlib import Path

import pytest

from pqpatch.detector.api import detect
from pqpatch.model import Layer, Patch, RuleStatus, VerdictStatus
from pqpatch.policy import load_policy
from pqpatch.verifier.api import DEFAULT_ENABLED_LAYERS, verify_patch
from pqpatch.verifier.l4_conformance.roundtrip import pq_literals
from tests.support.diffgen import make_diff

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SEED_APP_SRC = _REPO_ROOT / "corpus" / "tier2" / "file-signing-cli" / "src"
_PQC_JDK = Path.home() / "anaconda3" / "envs" / "pqc-jdk"

_needs_pqc_jdk = pytest.mark.skipif(
    not (_PQC_JDK / "bin" / "java").exists(),
    reason="PQC-capable JDK (conda env pqc-jdk) not installed",
)

_ALL_LAYERS = frozenset(Layer)
_L4_ONLY = frozenset({Layer.L4_CONFORMANCE})


def _site(line: int):
    return next(
        s for s in detect(_SEED_APP_SRC, repo_name="file-signing-cli") if s.line == line
    )


def _patch(site, old: str, new: str) -> Patch:
    original = Path(site.file_path).read_text(encoding="utf-8")
    return Patch(
        site_id=site.site_id,
        attempt=1,
        unified_diff=make_diff(original, original.replace(old, new), site.file_path),
        claimed_primitive=new,
        claimed_parameters="",
        backend_id="test",
        prompt_version="v1",
        response_hash="0" * 64,
    )


def test_pq_literal_extraction_keeps_composites_whole() -> None:
    diff = (
        "--- a/X.java\n+++ b/X.java\n@@ -1,3 +1,3 @@\n"
        ' context\n-old = getInstance("EC");\n'
        '+a = KeyPairGenerator.getInstance("ML-KEM-768-X25519");\n'
    )
    assert pq_literals(diff) == ["ML-KEM-768-X25519"]  # tested as written, not split
    assert pq_literals('+x = getInstance("AES");') == []  # classical ignored


def test_unconfigured_runtime_records_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PQPATCH_L4_JAVA_HOME", raising=False)
    site = _site(24)
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")
    verdict = verify_patch(
        _patch(site, "SHA256withRSA", "ML-DSA-65"), site, policy, enabled_layers=_L4_ONLY
    )
    l4_report = verdict.layer_reports[3]
    assert l4_report.results[0].status == RuleStatus.SKIPPED
    assert verdict.status == VerdictStatus.ACCEPT  # skipped-not-passed, visible in provenance
    assert "PQPATCH_L4_JAVA_HOME" in l4_report.results[0].detail


@_needs_pqc_jdk
def test_mldsa_literal_round_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PQPATCH_L4_JAVA_HOME", str(_PQC_JDK))
    site = _site(24)
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")
    verdict = verify_patch(
        _patch(site, "SHA256withRSA", "ML-DSA-65"), site, policy, enabled_layers=_L4_ONLY
    )
    assert verdict.status == VerdictStatus.ACCEPT
    assert "round-trip ok" in verdict.layer_reports[3].results[0].detail


@_needs_pqc_jdk
def test_mlkem_literal_round_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PQPATCH_L4_JAVA_HOME", str(_PQC_JDK))
    site = _site(49)  # KeyPairGenerator("EC") feeding the agreement (kem class)
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")
    verdict = verify_patch(
        _patch(site, 'KeyPairGenerator.getInstance("EC")',
               'KeyPairGenerator.getInstance("ML-KEM-768")'),
        site, policy, enabled_layers=_L4_ONLY,
    )
    assert verdict.status == VerdictStatus.ACCEPT


@_needs_pqc_jdk
def test_hallucinated_specimen_passes_l123_and_only_l4_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shakeout specimen, now a regression test: rule-clean, compiling,
    hybrid-token-satisfying -- and cryptographically nonexistent."""
    monkeypatch.setenv("PQPATCH_L4_JAVA_HOME", str(_PQC_JDK))
    site = _site(49)
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")
    patch = _patch(
        site,
        'KeyPairGenerator.getInstance("EC")',
        'KeyPairGenerator.getInstance("ML-KEM-768-X25519")',
    )

    l123 = verify_patch(patch, site, policy, enabled_layers=DEFAULT_ENABLED_LAYERS)
    assert l123.status == VerdictStatus.ACCEPT, "the gap this specimen exposed: L1-L3 accept"

    full = verify_patch(patch, site, policy, enabled_layers=_ALL_LAYERS)
    assert full.status == VerdictStatus.REJECT
    assert full.rejected_rule_id == "<L4-conformance>"
    assert "resolves to no provider" in full.layer_reports[3].results[0].detail
