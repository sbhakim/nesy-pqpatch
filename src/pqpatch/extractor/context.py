"""Context extraction for the proposer.

Enclosing method and class are recovered by a brace-depth scan, which is
sufficient for the corpus's conventional Java style. One-hop caller/callee
extraction is not yet implemented; those fields remain empty until it is
(docs/STATUS.md).
"""

from __future__ import annotations

import re
from pathlib import Path

from pqpatch.model import Context, Site

_METHOD_SIG_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*"
    r"[\w<>\[\],\s]+?\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{?\s*$"
)
_CLASS_SIG_RE = re.compile(r"^\s*(?:public\s+)?(?:final\s+)?(?:abstract\s+)?class\s+(\w+)")


def _find_enclosing_class(lines: list[str], site_line_idx: int) -> str:
    for i in range(site_line_idx, -1, -1):
        m = _CLASS_SIG_RE.match(lines[i])
        if m:
            return m.group(1)
    return "<unknown-class>"


def _find_enclosing_method(lines: list[str], site_line_idx: int) -> tuple[str, str]:
    """Return (method_name, method_source): scan upward to the nearest
    method signature, then downward to its matching close brace. Best-effort
    against conventional formatting, not a general Java grammar."""
    sig_line_idx: int | None = None
    method_name = "<unknown-method>"
    for i in range(site_line_idx, -1, -1):
        m = _METHOD_SIG_RE.match(lines[i])
        if m and "class " not in lines[i]:
            sig_line_idx = i
            method_name = m.group(1)
            break

    if sig_line_idx is None:
        return method_name, ""

    depth = 0
    started = False
    end_idx = len(lines) - 1
    for i in range(sig_line_idx, len(lines)):
        depth += lines[i].count("{")
        depth -= lines[i].count("}")
        if "{" in lines[i]:
            started = True
        if started and depth == 0:
            end_idx = i
            break

    return method_name, "\n".join(lines[sig_line_idx : end_idx + 1])


def extract_context(site: Site, *, repo_root: Path | None = None) -> Context:
    """Build a Context for `site` by reading its source file fresh.

    repo_root is accepted (and unused in v1) to keep the signature stable
    for when relative-path resolution and one-hop lookups are added.
    """
    del repo_root  # reserved for future one-hop caller/callee resolution
    source = Path(site.file_path).read_text(encoding="utf-8")
    lines = source.splitlines()
    site_idx = site.line - 1

    enclosing_class = _find_enclosing_class(lines, site_idx)
    _method_name, method_source = _find_enclosing_method(lines, site_idx)

    return Context(
        site=site,
        enclosing_method=method_source,
        enclosing_class=enclosing_class,
        caller_snippets=(),
        callee_snippets=(),
        config_excerpts=(),
    )
