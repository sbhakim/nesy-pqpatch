"""Diff-line helpers shared by the syntactic rules."""

from __future__ import annotations


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
