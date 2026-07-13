"""Vertical evidence that L2 catches an unsafe patch L1+L3 accepts."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pqpatch.detector.api import detect
from pqpatch.model import Layer, Patch, Policy, UsageClass, VerdictStatus
from pqpatch.verifier.api import DEFAULT_ENABLED_LAYERS, verify_patch
from tests.support.diffgen import make_diff

_ROOT = Path(__file__).resolve().parents[2]
_APP_SRC = _ROOT / "corpus" / "tier2" / "file-signing-cli" / "src"
_POLICY = Policy(
    name="test",
    version="v1",
    floors={UsageClass.VERIFY: "ML-DSA-65"},
    hybrid_required={},
    allowed_randomness_sources=("SecureRandom",),
)

pytestmark = pytest.mark.skipif(
    shutil.which("javac") is None or shutil.which("java") is None,
    reason="vertical L2/L3 comparison requires a JDK",
)


def test_l2_rejects_discarded_verify_that_l1_and_project_tests_accept() -> None:
    site = next(
        item
        for item in detect(_APP_SRC, repo_name="file-signing-cli")
        if item.usage_class is UsageClass.VERIFY
    )
    original = Path(site.file_path).read_text(encoding="utf-8")
    old_algorithm = 'Signature.getInstance("SHA256withRSA")'
    verify_occurrence = original.rfind(old_algorithm)
    assert verify_occurrence >= 0
    patched = (
        original[:verify_occurrence]
        + 'Signature.getInstance("ML-DSA-65")'
        + original[verify_occurrence + len(old_algorithm) :]
    )
    patched = patched.replace(
        "return sig.verify(signature);",
        "sig.verify(signature);\n        return true;",
    )
    patch = Patch(
        site_id=site.site_id,
        attempt=1,
        unified_diff=make_diff(original, patched, site.file_path),
        claimed_primitive="ML-DSA-65",
        claimed_parameters="",
        backend_id="test",
        prompt_version="test",
        response_hash="0" * 64,
    )

    without_l2 = verify_patch(
        patch,
        site,
        _POLICY,
        enabled_layers=frozenset({Layer.L1_SYNTACTIC, Layer.L3_BUILD}),
    )
    assert without_l2.status is VerdictStatus.ACCEPT

    with_l2 = verify_patch(patch, site, _POLICY, enabled_layers=DEFAULT_ENABLED_LAYERS)
    assert with_l2.status is VerdictStatus.REJECT
    assert with_l2.rejected_rule_id == "PQ-VER-01"
    assert with_l2.layers_evaluated == (Layer.L1_SYNTACTIC, Layer.L2_DATAFLOW)
