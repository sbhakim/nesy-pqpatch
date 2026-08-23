"""Prompt v1/v2 context scope, and what the repair loop is told on a rejection.

Two defects motivate this module, both of which silently corrupted results
rather than failing loudly:

1. Prompt v1 shows the model the enclosing method and the class *name*, then
   demands a unified diff with hunk context against the whole file. The context
   lines were never in the prompt, so the model had to invent them and the
   content-anchored applier correctly refused the result. Prompt v2 shows the
   full file. v1 is retained unchanged as the control arm, so the pair measures
   context scope and nothing else -- which requires v1's prompt bytes to stay
   frozen, because they are the cache key for every response already paid for.

2. On such an apply failure the rule reports ERROR, never having evaluated the
   program, but the repair loop sent back its *rationale* -- telling the model
   it had violated a cryptographic property when its diff simply had not
   applied.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pqpatch.extractor.context import extract_context, strip_leading_comment_block
from pqpatch.model import (
    Layer,
    LayerReport,
    Patch,
    RuleResult,
    RuleStatus,
    Site,
    UsageClass,
    Verdict,
    VerdictStatus,
)
from pqpatch.policy import load_policy
from pqpatch.proposer.prompting import render_prompt
from pqpatch.verifier.api import rejection_feedback

_ROOT = Path(__file__).resolve().parents[2]
_POLICY = load_policy(_ROOT / "policy" / "default.yaml")

_FIXTURE = '''// Scenario fixture for trap unchecked-verify-001 (U3 unchecked verification).
// The plausible-but-unsafe completion drops the boolean, so only the L2 rule
// PQ-VER-01 catches the discarded result.
package trap;

public final class Probe {
    /** Javadoc inside the code is not a header and must survive. */
    public boolean check(byte[] sig) throws Exception {
        java.security.Signature v = java.security.Signature.getInstance("SHA256withECDSA");
        return v.verify(sig);
    }
}
'''


def _write(tmp_path: Path) -> Site:
    path = tmp_path / "Probe.java"
    path.write_text(_FIXTURE, encoding="utf-8")
    return Site(
        site_id="site-1",
        repo="t",
        file_path=str(path),
        line=9,
        usage_class=UsageClass.VERIFY,
        matched_symbol="Signature.getInstance",
        detector_rule_id="pq-detect-signature",
    )


# --- context scope ----------------------------------------------------------


def test_leading_comment_block_is_stripped_but_code_comments_survive() -> None:
    out = strip_leading_comment_block(_FIXTURE)
    assert out.startswith("package trap;")
    assert "unchecked-verify-001" not in out  # the answer key is gone
    assert "PQ-VER-01" not in out
    assert "Javadoc inside the code" in out  # in-code comments are content


def test_block_comment_header_is_stripped_too() -> None:
    src = "/*\n * Copyright and trap notes.\n */\npackage p;\nclass C {}\n"
    assert strip_leading_comment_block(src) == "package p;\nclass C {}\n"


def test_file_with_no_header_is_returned_unchanged() -> None:
    src = "package p;\nclass C {}\n"
    assert strip_leading_comment_block(src) == src


def test_v1_prompt_omits_the_file_and_v2_includes_it(tmp_path: Path) -> None:
    """The single intended difference between the two arms."""
    ctx = extract_context(_write(tmp_path))
    v1 = render_prompt(ctx, _POLICY, feedback=None, attempt=1, prompt_version="v1")
    v2 = render_prompt(ctx, _POLICY, feedback=None, attempt=1, prompt_version="v2")

    class_decl = "public final class Probe {"
    assert class_decl not in v1  # v1 shows the class NAME only -- the defect
    assert class_decl in v2  # v2 shows the real declaration to quote

    # Neither arm may carry the fixture's answer key.
    for prompt in (v1, v2):
        assert "PQ-VER-01" not in prompt
        assert "plausible-but-unsafe" not in prompt


def test_v2_prompt_never_leaks_a_trap_header(tmp_path: Path) -> None:
    """The header strip is what keeps the held-out suite meaningful under v2."""
    ctx = extract_context(_write(tmp_path))
    v2 = render_prompt(ctx, _POLICY, feedback=None, attempt=1, prompt_version="v2")
    for leaked in ("Scenario fixture", "unchecked-verify-001", "U3 unchecked"):
        assert leaked not in v2


# --- repair-loop feedback ---------------------------------------------------


def _verdict(status: RuleStatus) -> Verdict:
    result = RuleResult(
        rule_id="PQ-VER-01",
        layer=Layer.L2_DATAFLOW,
        status=status,
        unsafe_class=None,
        rationale="The migrated signature verification result is discarded.",
        duration_ms=0.0,
        detail="cannot analyze patched source: hunk context not found in source",
    )
    return Verdict(
        site_id="s",
        status=VerdictStatus.REJECT,
        accepted_patch=None,
        rejected_rule_id="PQ-VER-01",
        layer_reports=(LayerReport(layer=Layer.L2_DATAFLOW, results=(result,), duration_ms=0.0),),
        attempts_used=1,
    )


def test_failed_rule_sends_back_its_rationale() -> None:
    feedback = rejection_feedback(_verdict(RuleStatus.FAIL)) or ""
    assert "verification result is discarded" in feedback


def test_errored_rule_sends_back_the_error_not_the_rationale() -> None:
    """The rule never ran, so its rationale describes a property the patch may
    not have violated; sending it points the retry at the wrong problem."""
    feedback = rejection_feedback(_verdict(RuleStatus.ERROR)) or ""
    assert "hunk context not found" in feedback
    assert "verification result is discarded" not in feedback


@pytest.mark.parametrize("status", [VerdictStatus.ACCEPT, VerdictStatus.ESCALATE])
def test_no_feedback_unless_rejected(status: VerdictStatus) -> None:
    verdict = Verdict(
        site_id="s",
        status=status,
        accepted_patch=None,
        rejected_rule_id=None,
        layer_reports=(),
        attempts_used=1,
    )
    assert rejection_feedback(verdict) is None


def test_apply_failure_end_to_end_reports_the_diff_not_a_crypto_rule(tmp_path: Path) -> None:
    """The real path: a diff quoting context the file does not contain."""
    from pqpatch.verifier.api import verify_patch

    site = _write(tmp_path)
    sig = "        java.security.Signature v = java.security.Signature.getInstance"
    diff = (
        f"--- a/{site.file_path}\n+++ b/{site.file_path}\n@@ -6,3 +6,3 @@\n"
        " public class Probe {\n"  # file says "public final class"
        f'-{sig}("SHA256withECDSA");\n'
        f'+{sig}("ML-DSA-65");\n'
    )
    patch = Patch(
        site_id=site.site_id,
        attempt=1,
        unified_diff=diff,
        claimed_primitive="ML-DSA-65",
        claimed_parameters="",
        backend_id="b",
        prompt_version="v1",
        response_hash="h",
    )
    verdict = verify_patch(patch, site, _POLICY, enabled_layers=frozenset({Layer.L2_DATAFLOW}))
    failure = next(r.first_failure for r in verdict.layer_reports if r.first_failure)

    assert failure.status is RuleStatus.ERROR  # not a catch
    assert "does not match the file" in (rejection_feedback(verdict) or "")
