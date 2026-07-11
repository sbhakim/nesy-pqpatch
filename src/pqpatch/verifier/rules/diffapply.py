"""Single-file unified-diff application.

PQ-SCOPE-01 guarantees any patch reaching this point touches exactly one
file, so a content-only applier suffices and no working-directory path
reconciliation is needed (ADR-003). Not a general diff engine by intent.
"""

from __future__ import annotations

import re

_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class DiffApplyError(ValueError):
    """Raised when a diff cannot be applied (malformed hunk, unparsable header)."""


def apply_unified_diff(original: str, diff_text: str) -> str:
    original_lines = original.splitlines()
    result: list[str] = []
    orig_idx = 0  # 0-based index into original_lines; next line to consume

    lines = diff_text.splitlines()
    i = 0
    while i < len(lines) and not lines[i].startswith("@@"):
        i += 1  # skip --- / +++ file headers

    if i >= len(lines):
        raise DiffApplyError("no hunk header (@@ ... @@) found in diff")

    while i < len(lines):
        m = _HUNK_HEADER.match(lines[i])
        if not m:
            i += 1
            continue
        old_start = int(m.group(1))
        i += 1

        if old_start - 1 < orig_idx:
            raise DiffApplyError(
                f"overlapping or out-of-order hunk at original line {old_start}"
            )
        while orig_idx < old_start - 1:
            result.append(original_lines[orig_idx])
            orig_idx += 1

        while i < len(lines) and not lines[i].startswith("@@"):
            line = lines[i]
            if line.startswith(" ") or line.startswith("-"):
                # Context and removal lines assert exact original content at
                # this position; a mismatch means the hunk header is wrong,
                # and applying anyway would silently corrupt the output.
                expected = line[1:]
                if orig_idx >= len(original_lines) or original_lines[orig_idx] != expected:
                    actual = (
                        original_lines[orig_idx] if orig_idx < len(original_lines) else "<EOF>"
                    )
                    raise DiffApplyError(
                        f"hunk context mismatch at original line {orig_idx + 1}: "
                        f"expected {expected!r}, found {actual!r}"
                    )
                orig_idx += 1
                if line.startswith(" "):
                    result.append(expected)
            elif line.startswith("+"):
                result.append(line[1:])
            # blank lines or stray headers inside a hunk body are ignored
            i += 1

    while orig_idx < len(original_lines):
        result.append(original_lines[orig_idx])
        orig_idx += 1

    trailing_newline = "\n" if original.endswith("\n") else ""
    return "\n".join(result) + trailing_newline
