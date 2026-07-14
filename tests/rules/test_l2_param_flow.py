"""Boundary semantics and orchestration for the L2 parameter-flow rule.

`algorithm_tokens_reaching_getinstance` collects, over the whole patched
source, every parameter token that reaches a `getInstance` argument -- directly
or through a tainted local variable / simple alias. The load-bearing
orchestrator test shows the structural gap this closes: the below-floor token
is defined *outside the diff hunks*, so it never appears in an added line and
L1's `PQ-PARAM-01` cannot see it, while L1+L2 rejects at `PQ-PARAM-02`.
"""

from __future__ import annotations

from pathlib import Path

from pqpatch.model import Layer, Patch, Policy, RuleStatus, Site, UsageClass, VerdictStatus
from pqpatch.verifier.api import verify_patch
from pqpatch.verifier.l2_dataflow.java_flow import algorithm_tokens_reaching_getinstance
from pqpatch.verifier.rules.registry import get
from tests.support.diffgen import make_diff

_BASE = (
    Path(__file__).resolve().parents[1].parent
    / "src"
    / "pqpatch"
    / "verifier"
    / "l2_dataflow"
    / "fixtures"
    / "PQ-PARAM-02"
    / "base.java"
)


def _tokens(body: str) -> frozenset[str] | None:
    return algorithm_tokens_reaching_getinstance(
        "class C { Object m(String p) throws Exception {\n" + body + "\n}}"
    )


def test_token_reaches_getinstance_through_a_variable() -> None:
    assert _tokens(
        'String alg = "ML-KEM-512"; return KeyGenerator.getInstance(alg);'
    ) == frozenset({"ML-KEM-512"})


def test_token_reaches_getinstance_through_an_alias() -> None:
    assert _tokens(
        'String a = "ML-KEM-512"; String b = a; return KeyGenerator.getInstance(b);'
    ) == frozenset({"ML-KEM-512"})


def test_token_in_an_unrelated_string_does_not_reach() -> None:
    assert _tokens('String note = "ML-KEM-512 is weak"; log(note); return null;') == frozenset()


def test_overwrite_before_the_sink_clears_the_taint() -> None:
    assert _tokens(
        'String alg = "ML-KEM-512"; alg = "ML-KEM-1024"; return KeyGenerator.getInstance(alg);'
    ) == frozenset({"ML-KEM-1024"})


def test_parameter_provenance_is_out_of_bounded_scope() -> None:
    assert _tokens("return KeyGenerator.getInstance(p);") == frozenset()


def test_parse_error_is_none() -> None:
    assert algorithm_tokens_reaching_getinstance("class C { void m( { oops }") is None


def _patch(diff: str, site: Site) -> Patch:
    return Patch(
        site_id=site.site_id,
        attempt=1,
        unified_diff=diff,
        claimed_primitive="ML-KEM-768",
        claimed_parameters="",
        backend_id="test",
        prompt_version="test",
        response_hash="0" * 64,
    )


_POLICY = Policy(
    name="test",
    version="v1",
    floors={UsageClass.KEM: "ML-KEM-768"},
    hybrid_required={},
    allowed_randomness_sources=("SecureRandom",),
)


def test_no_floor_for_the_usage_class_passes() -> None:
    site = Site(
        site_id="param#nofloor",
        repo="fixtures",
        file_path=str(_BASE),
        line=6,
        usage_class=UsageClass.ENVELOPE,  # no floor configured
        matched_symbol="Signature.getInstance",
        detector_rule_id="test",
    )
    diff = (
        "--- a/base.java\n+++ b/base.java\n@@ -5,1 +5,1 @@\n"
        '-        String algorithm = "ML-DSA-65";\n'
        '+        String algorithm = "ML-DSA-44";\n'
    )
    outcome = get("PQ-PARAM-02").check(_patch(diff, site), site, _POLICY)
    assert outcome.status is RuleStatus.PASS


def test_rule_errors_when_patched_source_cannot_be_parsed() -> None:
    site = Site(
        site_id="param#err",
        repo="fixtures",
        file_path=str(_BASE),
        line=6,
        usage_class=UsageClass.KEM,
        matched_symbol="Signature.getInstance",
        detector_rule_id="test",
    )
    broken = (
        "--- a/base.java\n+++ b/base.java\n@@ -6,1 +6,1 @@\n"
        "-        return Signature.getInstance(algorithm);\n"
        "+        return Signature.getInstance(algorithm  // unterminated\n"
    )
    outcome = get("PQ-PARAM-02").check(_patch(broken, site), site, _POLICY)
    assert outcome.status is RuleStatus.ERROR


_ORIGINAL = """\
class KemSetup {
    Object establish() throws Exception {
        String kemAlg = "ML-KEM-512";
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        return ka;
    }
}
"""

# The migration replaces the classical call with a KEM call that reuses the
# pre-existing kemAlg constant. The below-floor token sits OUTSIDE the diff
# hunks: the added lines carry only "ML-KEM" (no parameter digits), so L1's
# PQ-PARAM-01 token scan finds nothing while PQ-MIG-01's obligation is met.
_MIGRATED_BELOW_FLOOR = """\
class KemSetup {
    Object establish() throws Exception {
        String kemAlg = "ML-KEM-512";
        KeyGenerator kg = KeyGenerator.getInstance(kemAlg); // ML-KEM migration
        return kg;
    }
}
"""


def test_l1_sees_no_token_but_l2_rejects_the_below_floor_flow(tmp_path: Path) -> None:
    src = tmp_path / "KemSetup.java"
    src.write_text(_ORIGINAL, encoding="utf-8")
    site = Site(
        site_id="param#1",
        repo="fixtures",
        file_path=str(src),
        line=4,
        usage_class=UsageClass.KEM,
        matched_symbol="KeyAgreement.getInstance",
        detector_rule_id="test",
    )
    patch = _patch(make_diff(_ORIGINAL, _MIGRATED_BELOW_FLOOR, str(src)), site)

    l1_only = verify_patch(patch, site, _POLICY, enabled_layers=frozenset({Layer.L1_SYNTACTIC}))
    assert l1_only.status is VerdictStatus.ACCEPT

    l1_l2 = verify_patch(
        patch,
        site,
        _POLICY,
        enabled_layers=frozenset({Layer.L1_SYNTACTIC, Layer.L2_DATAFLOW}),
    )
    assert l1_l2.status is VerdictStatus.REJECT
    assert l1_l2.rejected_rule_id == "PQ-PARAM-02"
