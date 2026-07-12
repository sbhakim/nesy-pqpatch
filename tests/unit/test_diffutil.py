"""Unit tests for the pure diff-line-extraction helpers used by every L1 rule."""

from __future__ import annotations

from pqpatch.verifier.rules.diffutil import added_lines, path_in_scope, touched_files


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


# --- path_in_scope: tolerate model path spellings, reject different files -----

_SITE = "/home/u/proj/src/FileSigner.java"


def test_path_in_scope_accepts_every_spelling_of_the_same_file() -> None:
    # absolute (matches), the leading-slash-lost form real models emit, a
    # repo-relative path, and a bare basename all name the same file.
    assert path_in_scope("/home/u/proj/src/FileSigner.java", _SITE)
    assert path_in_scope("home/u/proj/src/FileSigner.java", _SITE)  # the bug case
    assert path_in_scope("src/FileSigner.java", _SITE)
    assert path_in_scope("FileSigner.java", _SITE)


def test_path_in_scope_rejects_genuinely_different_files() -> None:
    assert not path_in_scope("src/BuildConfig.java", _SITE)
    assert not path_in_scope("/etc/passwd", _SITE)
    assert not path_in_scope("Other/FileSigner.java", _SITE)  # same name, different dir
    assert not path_in_scope("", _SITE)


def test_path_in_scope_symmetric_when_site_is_relative() -> None:
    # site stored relative, model emits absolute -> still the same file
    assert path_in_scope("/abs/root/src/FileSigner.java", "src/FileSigner.java")
