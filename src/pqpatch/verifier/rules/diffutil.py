"""Diff-line helpers shared by the syntactic rules."""

from __future__ import annotations

from pathlib import PurePosixPath


def _normalized_parts(path: str) -> tuple[str, ...]:
    path = path.strip().removeprefix("a/").removeprefix("b/").lstrip("/")
    return PurePosixPath(path).parts if path else ()


def path_in_scope(touched: str, site_path: str) -> bool:
    """True iff `touched` names the same file as `site_path`, tolerant of the
    a//b/ prefixes, leading slashes, and relative-vs-absolute spellings that
    different models emit for the same file.

    Match iff the shorter path's components are a suffix of the longer's, so
    ``FileSigner.java``, ``src/FileSigner.java``, and
    ``/abs/.../src/FileSigner.java`` all match a site at
    ``/abs/.../src/FileSigner.java`` -- while ``Other.java`` or a same-named file
    in a different directory do not. This distinguishes a formatting difference
    (in scope) from a genuinely different file (out of scope), which a plain
    string compare cannot.
    """
    t = _normalized_parts(touched)
    s = _normalized_parts(site_path)
    if not t or not s:
        return False
    short, long_ = (t, s) if len(t) <= len(s) else (s, t)
    return long_[len(long_) - len(short) :] == short


def added_lines(unified_diff: str) -> list[str]:
    """Return the content of every '+' line in a unified diff, excluding the
    '+++' file-header line and the leading '+' marker itself."""
    out: list[str] = []
    for raw in unified_diff.splitlines():
        if raw.startswith("+++"):
            continue
        if raw.startswith("+"):
            out.append(raw[1:])
    return out


def removed_lines(unified_diff: str) -> list[str]:
    """Return the content of every '-' line in a unified diff, excluding the
    '---' file-header line and the leading '-' marker itself."""
    out: list[str] = []
    for raw in unified_diff.splitlines():
        if raw.startswith("---"):
            continue
        if raw.startswith("-"):
            out.append(raw[1:])
    return out


def touched_files(unified_diff: str) -> set[str]:
    """Return the set of file paths a unified diff modifies, read from '+++' headers."""
    files: set[str] = set()
    for raw in unified_diff.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            if path not in ("/dev/null",):
                # strip common a/ b/ diff prefixes if present
                path = path.removeprefix("b/")
                files.add(path)
    return files
