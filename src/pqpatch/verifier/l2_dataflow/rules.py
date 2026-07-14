"""Registered L2 dataflow rules."""

from __future__ import annotations

from pathlib import Path

from pqpatch.model import Layer, Patch, Policy, RuleStatus, Site, UnsafeClass, UsageClass
from pqpatch.verifier.l2_dataflow.java_flow import (
    HybridFlow,
    KeyFlow,
    SeedFlow,
    VerifyUse,
    classify_hybrid_flow,
    classify_key_flow,
    classify_seed_provenance,
    classify_verify_uses,
)
from pqpatch.verifier.rules.diffapply import DiffApplyError, apply_unified_diff
from pqpatch.verifier.rules.registry import register
from pqpatch.verifier.rules.spec import RuleOutcome, RuleSpec

_FIXTURES = Path(__file__).parent / "fixtures"
_PASS = RuleOutcome(RuleStatus.PASS)


def _patched_source(patch: Patch, site: Site) -> str:
    """Apply the patch to the site's source, or raise for the caller to map."""
    original = Path(site.file_path).read_text(encoding="utf-8")
    return apply_unified_diff(original, patch.unified_diff)


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


def _check_key_confusion(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    # Cross-family flow is a source-internal property; it does not gate on
    # usage_class or policy -- a key crossing families is unsafe at any site.
    del policy
    try:
        patched = _patched_source(patch, site)
    except (FileNotFoundError, DiffApplyError) as exc:
        return RuleOutcome(RuleStatus.ERROR, detail=f"cannot analyze patched source: {exc}")

    flow = classify_key_flow(patched)
    if flow is KeyFlow.CROSS_FAMILY:
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="a key generated for one algorithm family flows into an "
            "operation of the other family (cross-family key confusion)",
        )
    if flow is KeyFlow.INDETERMINATE:
        return RuleOutcome(
            RuleStatus.ERROR,
            detail="patched source did not parse; L2 cannot prove key-family separation",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-KEY-02",
        layer=Layer.L2_DATAFLOW,
        unsafe_class=UnsafeClass.U4_KEY_CONFUSION,
        cwe="CWE-327",
        severity="high",
        rationale=(
            "A key object produced for one algorithm family (ML-KEM for key "
            "establishment, or ML-DSA/SLH-DSA for signatures) is used at an "
            "operation of the other family. Re-propose so each key flows only "
            "into operations of its own family."
        ),
        check=_check_key_confusion,
        fixtures_dir=_FIXTURES / "PQ-KEY-02",
    )
)


def _check_hybrid_completeness(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    # Hybrid completeness is a source-internal flow property; it engages only
    # when both secret families are produced, so it does not gate on usage_class.
    del policy
    try:
        patched = _patched_source(patch, site)
    except (FileNotFoundError, DiffApplyError) as exc:
        return RuleOutcome(RuleStatus.ERROR, detail=f"cannot analyze patched source: {exc}")

    flow = classify_hybrid_flow(patched)
    if flow is HybridFlow.DOWNGRADED:
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="hybrid context produces both a classical and a post-quantum "
            "shared secret, but only one reaches the key-derivation combiner "
            "(hybrid downgrade)",
        )
    if flow is HybridFlow.INDETERMINATE:
        return RuleOutcome(
            RuleStatus.ERROR,
            detail="patched source did not parse; L2 cannot prove hybrid completeness",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-HYB-02",
        layer=Layer.L2_DATAFLOW,
        unsafe_class=UnsafeClass.U6_HYBRID_DOWNGRADE,
        cwe="CWE-327",
        severity="high",
        rationale=(
            "A mandated hybrid must combine both shared secrets: the classical "
            "(e.g. ECDHE) and the ML-KEM contribution must both reach the key "
            "derivation. This patch drops one component before the KDF. "
            "Re-propose so both secrets are combined into the derived key."
        ),
        check=_check_hybrid_completeness,
        fixtures_dir=_FIXTURES / "PQ-HYB-02",
    )
)


def _check_seed_provenance(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    # A constant seed makes the generator predictable at any site; the check is a
    # source-internal flow property and does not gate on usage_class.
    del policy
    try:
        patched = _patched_source(patch, site)
    except (FileNotFoundError, DiffApplyError) as exc:
        return RuleOutcome(RuleStatus.ERROR, detail=f"cannot analyze patched source: {exc}")

    flow = classify_seed_provenance(patched)
    if flow is SeedFlow.LITERAL_SEEDED:
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="a fixed/literal seed reaches SecureRandom through a variable, "
            "making key-generation randomness predictable",
        )
    if flow is SeedFlow.INDETERMINATE:
        return RuleOutcome(
            RuleStatus.ERROR,
            detail="patched source did not parse; L2 cannot prove seed provenance",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-RAND-03",
        layer=Layer.L2_DATAFLOW,
        unsafe_class=UnsafeClass.U5_RANDOMNESS_MISUSE,
        cwe="CWE-337",
        severity="high",
        rationale=(
            "Key-generation randomness is seeded from a fixed/literal value that "
            "reaches SecureRandom through a variable, so the generator is "
            "predictable. Re-propose seeding only from an approved entropy source."
        ),
        check=_check_seed_provenance,
        fixtures_dir=_FIXTURES / "PQ-RAND-03",
    )
)
