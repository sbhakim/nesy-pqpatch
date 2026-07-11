"""Unit tests for parsing a raw model response into diff + self-report
(codebase-plan.md §9 level 1: pure-function coverage)."""

from __future__ import annotations

import pytest

from pqpatch.proposer.response_format import MalformedResponseError, parse_response


def test_parses_diff_and_trailing_json() -> None:
    raw = (
        '--- a/F.java\n+++ b/F.java\n@@ -1,1 +1,1 @@\n-old\n+new\n'
        '{"primitive": "ML-DSA-65", "parameters": "category-3"}'
    )
    parsed = parse_response(raw)
    assert parsed.claimed_primitive == "ML-DSA-65"
    assert parsed.claimed_parameters == "category-3"
    assert "+new" in parsed.unified_diff
    assert '{"primitive"' not in parsed.unified_diff


def test_tolerates_trailing_blank_lines_after_json() -> None:
    raw = 'diff-content\n{"primitive": "X", "parameters": "Y"}\n\n\n'
    parsed = parse_response(raw)
    assert parsed.claimed_primitive == "X"


def test_missing_json_line_raises() -> None:
    with pytest.raises(MalformedResponseError, match="no trailing JSON"):
        parse_response("just a diff\nwith no json at the end\n")


def test_empty_response_raises() -> None:
    with pytest.raises(MalformedResponseError, match="empty response"):
        parse_response("")


def test_json_without_primitive_key_is_not_treated_as_self_report() -> None:
    """A trailing JSON object that isn't the self-report (e.g. code that
    happens to end in a JSON-looking config blob) must not be silently
    accepted as the claim."""
    with pytest.raises(MalformedResponseError):
        parse_response('diff-content\n{"unrelated": "object"}')


def test_no_diff_content_before_json_raises() -> None:
    with pytest.raises(MalformedResponseError, match="no diff content"):
        parse_response('{"primitive": "X", "parameters": "Y"}')


def test_missing_parameters_defaults_to_empty_string() -> None:
    raw = 'diff-content\n{"primitive": "X"}'
    parsed = parse_response(raw)
    assert parsed.claimed_parameters == ""
