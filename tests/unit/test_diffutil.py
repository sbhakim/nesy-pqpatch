"""Unit tests for the pure diff-line-extraction helpers used by every L1 rule."""

from __future__ import annotations

from pqpatch.verifier.rules.diffutil import added_lines, touched_files


def test_added_lines_extracts_plus_prefixed_content() -> None:
    diff = "--- a/F.java\n+++ b/F.java\n@@ -1,2 +1,2 @@\n-old1\n-old2\n+new1\n+new2\n context\n"
    assert added_lines(diff) == ["new1", "new2"]


def test_added_lines_excludes_file_header() -> None:
    diff = "+++ b/F.java\n+real content\n"
    assert added_lines(diff) == ["real content"]


def test_added_lines_empty_diff() -> None:
    assert added_lines("") == []


def test_touched_files_single_file() -> None:
    diff = "--- a/F.java\n+++ b/F.java\n@@ -1,1 +1,1 @@\n-x\n+y\n"
    assert touched_files(diff) == {"F.java"}


def test_touched_files_multiple_files() -> None:
    diff = (
        "--- a/A.java\n+++ b/A.java\n@@ -1,1 +1,1 @@\n-x\n+y\n"
        "--- a/B.java\n+++ b/B.java\n@@ -1,1 +1,1 @@\n-p\n+q\n"
    )
    assert touched_files(diff) == {"A.java", "B.java"}


def test_touched_files_ignores_dev_null() -> None:
    diff = "--- /dev/null\n+++ b/New.java\n@@ -0,0 +1,1 @@\n+content\n"
    assert touched_files(diff) == {"New.java"}
