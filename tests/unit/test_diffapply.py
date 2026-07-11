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


def test_wrong_hunk_header_raises_instead_of_corrupting() -> None:
    """This is the exact failure mode a hand-typed fixture hit during
    development: a hunk header claiming the wrong offset silently
    duplicated content. It must now raise, not corrupt."""
    original = "a\nb\nc\nd\ne\n"
    bad_diff = (
        "--- a/f.txt\n+++ b/f.txt\n"
        "@@ -3,2 +3,2 @@\n"  # claims line 3 is "a", but it's actually "c"
        " a\n-b\n+B\n"
    )
    with pytest.raises(DiffApplyError, match="context mismatch"):
        apply_unified_diff(original, bad_diff)


def test_no_hunk_header_raises() -> None:
    with pytest.raises(DiffApplyError, match="no hunk header"):
        apply_unified_diff("a\nb\n", "--- a/f.txt\n+++ b/f.txt\nnot a hunk\n")
