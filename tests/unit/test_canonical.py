"""Golden-bytes tests for canonical trace serialization
(codebase-plan.md §9 level 1: "canonical JSON (golden bytes)").

The exact JSON string is asserted, not just "it round-trips" -- a change
that reorders keys, changes separators, or alters float formatting would
silently break cross-run/cross-machine reproducibility (invariant 1) and
must fail a test, not just "look different" in a diff someone might miss.
"""

from __future__ import annotations

from pqpatch.model import Layer, Site, TraceRecord, UsageClass, Verdict, VerdictStatus
from pqpatch.trace.canonical import (
    compute_content_hash,
    finalize_trace,
    to_canonical_json,
    verify_content_hash,
)


def _minimal_trace() -> TraceRecord:
    site = Site(
        site_id="site-abc",
        repo="demo",
        file_path="F.java",
        line=10,
        usage_class=UsageClass.SIGN,
        matched_symbol="Signature.getInstance",
        detector_rule_id="pq-detect-signature",
    )
    verdict = Verdict(
        site_id="site-abc",
        status=VerdictStatus.ACCEPT,
        accepted_patch=None,
        rejected_rule_id=None,
        layer_reports=(),
        attempts_used=1,
        layers_evaluated=(Layer.L1_SYNTACTIC,),
    )
    return TraceRecord(
        site=site,
        usage_class=UsageClass.SIGN,
        policy_version="v1",
        ruleset_version="v1",
        events=(),
        verdict=verdict,
    )


_GOLDEN_JSON = (
    '{"events":[],"policy_version":"v1","ruleset_version":"v1","site":{"detector_rule_id":'
    '"pq-detect-signature","file_path":"F.java","line":10,"matched_symbol":'
    '"Signature.getInstance","repo":"demo","site_id":"site-abc","usage_class":"sign"},'
    '"usage_class":"sign","verdict":{"accepted_patch":null,"attempts_used":1,'
    '"layer_reports":[],"layers_evaluated":[1],"rejected_rule_id":null,"site_id":"site-abc",'
    '"status":"accept"}}'
)


def test_canonical_json_is_byte_exact() -> None:
    assert to_canonical_json(_minimal_trace()) == _GOLDEN_JSON


def test_canonical_json_excludes_hash_and_signature_fields() -> None:
    assert '"content_hash"' not in to_canonical_json(_minimal_trace())
    assert '"signature"' not in to_canonical_json(_minimal_trace())


def test_content_hash_is_deterministic_across_calls() -> None:
    t = _minimal_trace()
    assert compute_content_hash(t) == compute_content_hash(t)


def test_content_hash_matches_sha256_of_golden_json() -> None:
    import hashlib

    expected = hashlib.sha256(_GOLDEN_JSON.encode("utf-8")).hexdigest()
    assert compute_content_hash(_minimal_trace()) == expected


def test_verify_content_hash_false_for_unfinalized_trace() -> None:
    """A trace that was never passed through finalize_trace() has an empty
    content_hash and must not verify -- there is nothing to check it
    against."""
    assert verify_content_hash(_minimal_trace()) is False


def test_finalize_trace_sets_content_hash_only() -> None:
    t = _minimal_trace()
    finalized = finalize_trace(t)
    assert finalized.content_hash != ""
    assert finalized.signature is None
    assert finalized.site == t.site  # everything else unchanged
