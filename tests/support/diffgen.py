"""Generates guaranteed-correct unified diffs for tests, using difflib
rather than hand-typed hunks. codebase-plan.md §9 -- a hand-typed diff with
a wrong hunk header is a real bug this project hit once already (see
docs/STATUS.md); every test that needs apply_unified_diff() to actually
apply should build its fixture with this helper, not by hand.
"""

from __future__ import annotations

import difflib


def make_diff(original: str, patched: str, path: str) -> str:
    # keepends=True lines already carry their own "\n"; joining with "" (not
    # "\n") avoids doubling every line break in the output, which produced
    # a diff with a spurious blank line after each hunk line on first try.
    original_lines = original.splitlines(keepends=True)
    patched_lines = patched.splitlines(keepends=True)
    diff_lines = difflib.unified_diff(
        original_lines,
        patched_lines,
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        lineterm="\n",
    )
    return "".join(diff_lines)
