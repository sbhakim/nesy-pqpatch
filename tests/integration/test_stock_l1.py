"""The stock classical-era L1 arm (RQ4 ablation): the load-bearing contrast is
that an unsafe *post-quantum* migration passes the classical pack while the PQ
registry rejects it -- and that the classical pack still fires on the classical
misuse it does know, so the arm is a real scanner, not a stub."""

from __future__ import annotations

from pathlib import Path

import pytest

from pqpatch.detector.api import detect
from pqpatch.model import Layer, Patch, VerdictStatus
from pqpatch.policy import load_policy
from pqpatch.verifier.api import verify_patch
from tests.support.diffgen import make_diff

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SEED_APP_SRC = _REPO_ROOT / "corpus" / "tier2" / "file-signing-cli" / "src"
_L1_ONLY = frozenset({Layer.L1_SYNTACTIC})


def _sign_site():
    return next(
        s for s in detect(_SEED_APP_SRC, repo_name="file-signing-cli") if s.line == 24
    )


def _patch_for(site, replacement: str) -> Patch:
    original = Path(site.file_path).read_text(encoding="utf-8")
    diff = make_diff(
        original, original.replace("SHA256withRSA", replacement), site.file_path
    )
    return Patch(
        site_id=site.site_id,
        attempt=1,
        unified_diff=diff,
        claimed_primitive=replacement,
        claimed_parameters="",
        backend_id="test",
        prompt_version="v1",
        response_hash="0" * 64,
    )


def test_below_floor_pq_patch_passes_stock_but_fails_pq_l1() -> None:
    """The measurement itself: classical-era rules cannot see a PQ parameter
    floor. ML-DSA-44 (below the sign floor) sails through the stock arm and is
    rejected by the PQ registry."""
    site = _sign_site()
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")
    patch = _patch_for(site, "ML-DSA-44")

    stock = verify_patch(patch, site, policy, enabled_layers=_L1_ONLY, l1_mode="stock")
    pq = verify_patch(patch, site, policy, enabled_layers=_L1_ONLY, l1_mode="pq")

    assert stock.status == VerdictStatus.ACCEPT
    assert pq.status == VerdictStatus.REJECT
    assert pq.rejected_rule_id == "PQ-PARAM-01"


def test_stock_arm_still_fires_on_classical_misuse() -> None:
    """The arm is a real scanner: a patch that introduces MD5 is flagged by
    the classical pack, so passes above are blindness, not brokenness."""
    site = _sign_site()
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")
    original = Path(site.file_path).read_text(encoding="utf-8")
    patched = original.replace(
        'Signature.getInstance("SHA256withRSA")',
        'Signature.getInstance("ML-DSA-65"); MessageDigest.getInstance("MD5")',
    )
    patch = Patch(
        site_id=site.site_id,
        attempt=1,
        unified_diff=make_diff(original, patched, site.file_path),
        claimed_primitive="ML-DSA-65",
        claimed_parameters="",
        backend_id="test",
        prompt_version="v1",
        response_hash="0" * 64,
    )

    verdict = verify_patch(patch, site, policy, enabled_layers=_L1_ONLY, l1_mode="stock")
    assert verdict.status == VerdictStatus.REJECT
    assert verdict.rejected_rule_id == "<L1-stock-classical>"


def test_invalid_l1_mode_rejected() -> None:
    site = _sign_site()
    policy = load_policy(_REPO_ROOT / "policy" / "default.yaml")
    with pytest.raises(ValueError, match="l1_mode"):
        verify_patch(_patch_for(site, "ML-DSA-65"), site, policy, l1_mode="modern")
