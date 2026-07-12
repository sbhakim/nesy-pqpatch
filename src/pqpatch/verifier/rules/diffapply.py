"""Single-file unified-diff application.

PQ-SCOPE-01 guarantees any patch reaching this point touches exactly one
file, so a content-only applier suffices and no working-directory path
reconciliation is needed (ADR-003). Not a general diff engine by intent.

Real models emit hunks with wrong line numbers and off-by-a-space context
(observed against qwen2.5-coder / llama3.1 / gemma3 via Ollama), so the applier
anchors each hunk by its *content* rather than trusting the ``@@`` offset, and
tolerates leading/trailing whitespace in the matched context. It stays
deliberately conservative to protect the load-bearing safety property: a hunk is
applied only where its old block matches unambiguously, and anything else raises
rather than guess -- a mis-located patch that still compiled would be a false
accept, the one error direction this component must never take.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class DiffApplyError(ValueError):
    """Raised when a diff cannot be applied unambiguously (unlocatable,
    ambiguous, or malformed hunk). Never raised in preference to silently
    applying at the wrong place."""


@dataclass(frozen=True, slots=True)
class _Hunk:
    old_start: int  # 1-based line from the header; treated as a hint, not gospel
    lines: tuple[tuple[str, str], ...]  # (tag, text) with tag in {" ", "-", "+"}


def _parse_hunks(diff_text: str) -> list[_Hunk]:
    lines = diff_text.splitlines()
    hunks: list[_Hunk] = []
    i = 0
    while i < len(lines):
        m = _HUNK_HEADER.match(lines[i])
        if not m:
            i += 1
            continue
        old_start = int(m.group(1))
        i += 1
        body: list[tuple[str, str]] = []
        while i < len(lines) and not lines[i].startswith("@@"):
            line = lines[i]
            if line.startswith(("---", "+++")):
                i += 1
                continue
            if line and line[0] in " -+":
                body.append((line[0], line[1:]))
            # blank or stray lines inside a hunk body are ignored
            i += 1
        hunks.append(_Hunk(old_start=old_start, lines=tuple(body)))
    return hunks


def _norm(s: str) -> str:
    """Whitespace-insensitive key for context matching. Indentation and trailing
    space are exactly what small models get wrong, and neither changes a Java
    program's meaning; emitted context comes from the original file, so the file
    keeps its real spacing."""
    return s.strip()


def _locate(original: list[str], old_block: list[str], cursor: int, hint: int) -> int:
    """Return the unique start index at/after `cursor` where `old_block` matches
    (whitespace-normalized). If several positions match, disambiguate by the
    header's line hint only when one is strictly closest; otherwise raise."""
    want = [_norm(x) for x in old_block]
    n = len(want)
    matches = [
        p
        for p in range(cursor, len(original) - n + 1)
        if [_norm(original[p + j]) for j in range(n)] == want
    ]
    if not matches:
        raise DiffApplyError(
            f"hunk context not found in source (looked for {old_block[:1]!r}...); "
            "the diff does not match the file and will not be force-applied"
        )
    if len(matches) == 1:
        return matches[0]
    target = hint - 1
    matches.sort(key=lambda p: abs(p - target))
    if abs(matches[0] - target) == abs(matches[1] - target):
        raise DiffApplyError(
            f"hunk context is ambiguous ({len(matches)} equally-likely positions); "
            "refusing to guess where to apply it"
        )
    return matches[0]


def apply_unified_diff(original: str, diff_text: str) -> str:
    original_lines = original.splitlines()
    hunks = _parse_hunks(diff_text)
    if not hunks:
        raise DiffApplyError("no hunk header (@@ ... @@) found in diff")

    result: list[str] = []
    cursor = 0
    for hunk in hunks:
        old_block = [text for tag, text in hunk.lines if tag in (" ", "-")]
        if old_block:
            pos = _locate(original_lines, old_block, cursor, hunk.old_start)
        else:  # pure insertion: nothing to anchor to, fall back to the header hint
            pos = min(max(hunk.old_start - 1, cursor), len(original_lines))
        if pos < cursor:
            raise DiffApplyError(f"overlapping or out-of-order hunk near line {hunk.old_start}")

        result.extend(original_lines[cursor:pos])
        k = pos
        for tag, text in hunk.lines:
            if tag == " ":
                result.append(original_lines[k])  # keep the file's real content/spacing
                k += 1
            elif tag == "-":
                k += 1  # drop the original line
            else:  # "+"
                result.append(text)
        cursor = k

    result.extend(original_lines[cursor:])
    trailing_newline = "\n" if original.endswith("\n") else ""
    return "\n".join(result) + trailing_newline
