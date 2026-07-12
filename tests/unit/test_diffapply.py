"""Unit tests for the pure diff-apply function, including the defensive
context-mismatch check added after it caused real silent corruption during
this project's own development (docs/STATUS.md)."""

from __future__ import annotations

import pytest

from pqpatch.verifier.rules.diffapply import DiffApplyError, apply_unified_diff
from tests.support.diffgen import make_diff


def test_round_trip_simple_change() -> None:
    original = "line1\nline2\nline3\n"
    patched = "line1\nCHANGED\nline3\n"
    diff = make_diff(original, patched, "f.txt")
    assert apply_unified_diff(original, diff) == patched


def test_round_trip_insertion() -> None:
    original = "a\nb\nc\n"
    patched = "a\nb\nNEW\nc\n"
    diff = make_diff(original, patched, "f.txt")
    assert apply_unified_diff(original, diff) == patched


def test_round_trip_deletion() -> None:
    original = "a\nb\nc\nd\n"
    patched = "a\nd\n"
    diff = make_diff(original, patched, "f.txt")
    assert apply_unified_diff(original, diff) == patched


def test_round_trip_against_real_seed_app() -> None:
    from pathlib import Path

    original = Path("corpus/tier2/file-signing-cli/src/FileSigner.java").read_text()
    patched = original.replace(
        'KeyAgreement.getInstance("ECDH")', 'KeyAgreement.getInstance("HYBRID")'
    )
    diff = make_diff(original, patched, "src/FileSigner.java")
    assert apply_unified_diff(original, diff) == patched


def test_wrong_hunk_offset_is_content_anchored_not_corrupted() -> None:
    """A header claiming the wrong offset (the failure mode that once silently
    duplicated content) is now anchored by content: the hunk applies at the
    unique place its context actually matches, producing the intended result
    rather than corrupting or spuriously rejecting."""
    original = "a\nb\nc\nd\ne\n"
    diff = (
        "--- a/f.txt\n+++ b/f.txt\n"
        "@@ -3,2 +3,2 @@\n"  # header says line 3; the "a\nb" context is really at line 1
        " a\n-b\n+B\n"
    )
    assert apply_unified_diff(original, diff) == "a\nB\nc\nd\ne\n"


def test_hallucinated_context_raises_never_force_applies() -> None:
    """The anti-corruption guarantee: context the file does not contain (a real
    small-model failure mode) must raise, not be force-fitted somewhere."""
    original = "a\nb\nc\nd\ne\n"
    diff = (
        "--- a/f.txt\n+++ b/f.txt\n@@ -1,2 +1,2 @@\n"
        " // a comment the model invented\n-b\n+B\n"
    )
    with pytest.raises(DiffApplyError, match="context not found"):
        apply_unified_diff(original, diff)


def test_whitespace_only_context_mismatch_still_applies() -> None:
    """The dominant real failure: the model's context differs from the file only
    in indentation. It should apply, emitting the file's real spacing."""
    original = "class C {\n    int f() {\n        return 1;\n    }\n}\n"
    diff = (
        "--- a/C.java\n+++ b/C.java\n@@ -2,2 +2,2 @@\n"
        "  int f() {\n"  # model used 2 spaces; file has 4
        "-        return 1;\n"
        "+        return 2;\n"
    )
    assert apply_unified_diff(original, diff) == (
        "class C {\n    int f() {\n        return 2;\n    }\n}\n"
    )


def test_ambiguous_context_raises() -> None:
    """When identical context sits at two equally-likely places, refuse to
    guess rather than risk applying at the wrong one."""
    original = "x\nDUP\nx\nDUP\nx\n"  # "DUP" at lines 2 and 4, symmetric to a mid hint
    diff = "--- a/f.txt\n+++ b/f.txt\n@@ -3,1 +3,1 @@\n-DUP\n+CHANGED\n"
    with pytest.raises(DiffApplyError, match="ambiguous"):
        apply_unified_diff(original, diff)


def test_no_hunk_header_raises() -> None:
    with pytest.raises(DiffApplyError, match="no hunk header"):
        apply_unified_diff("a\nb\n", "--- a/f.txt\n+++ b/f.txt\nnot a hunk\n")
