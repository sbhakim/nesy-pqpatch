"""Registered L2 dataflow rules."""

from __future__ import annotations

from pathlib import Path

from pqpatch.model import Layer, Patch, Policy, RuleStatus, Site, UnsafeClass, UsageClass
from pqpatch.verifier.l2_dataflow.java_flow import VerifyUse, classify_verify_uses
from pqpatch.verifier.rules.diffapply import DiffApplyError, apply_unified_diff
from pqpatch.verifier.rules.registry import register
from pqpatch.verifier.rules.spec import RuleOutcome, RuleSpec

_FIXTURES = Path(__file__).parent / "fixtures"
_PASS = RuleOutcome(RuleStatus.PASS)


def _check_verify_result(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del policy
    if site.usage_class is not UsageClass.VERIFY:
        return _PASS
    try:
        original = Path(site.file_path).read_text(encoding="utf-8")
        patched = apply_unified_diff(original, patch.unified_diff)
    except (FileNotFoundError, DiffApplyError) as exc:
        return RuleOutcome(RuleStatus.ERROR, detail=f"cannot analyze patched source: {exc}")

    uses = classify_verify_uses(patched)
    if not uses:
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="migrated verification site contains no verify() result to validate",
        )
    if VerifyUse.INDETERMINATE in uses:
        return RuleOutcome(
            RuleStatus.ERROR,
            detail="verify() result has an unsupported shape; L2 cannot prove it checked",
        )
    if VerifyUse.DISCARDED in uses:
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="verify() result is discarded or never reaches a branch/return value",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-VER-01",
        layer=Layer.L2_DATAFLOW,
        unsafe_class=UnsafeClass.U3_UNCHECKED_VERIFY,
        cwe="CWE-252",
        severity="high",
        rationale=(
            "The migrated signature verification result is discarded or does not "
            "reach a control-flow decision or explicit return. Re-propose so a "
            "failed verification cannot continue as success."
        ),
        check=_check_verify_result,
        fixtures_dir=_FIXTURES / "PQ-VER-01",
    )
)
