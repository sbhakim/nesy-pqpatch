"""Parsing of raw model responses into a diff and a self-report.

Extraction only: the self-report is a claim for the verifier to check, so
no validation happens here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


class MalformedResponseError(ValueError):
    """Raised when a raw response has no parseable trailing JSON self-report."""


@dataclass(frozen=True, slots=True)
class ParsedResponse:
    unified_diff: str
    claimed_primitive: str
    claimed_parameters: str


def _strip_code_fences(text: str) -> str:
    """Drop Markdown code-fence marker lines (```), keeping their contents.

    Hosted and local chat models routinely wrap a diff and the JSON self-report
    in ```diff / ```json fences; the fence lines would otherwise sit between the
    JSON and the end of the response and defeat the trailing-JSON scan. Removing
    only the fence markers is content-preserving: a unified diff never contains a
    line whose first non-space characters are three backticks.
    """
    kept = [ln for ln in text.splitlines() if not ln.lstrip().startswith("```")]
    return "\n".join(kept)


def _find_trailing_self_report(text: str) -> tuple[int, dict[str, object]] | None:
    """Locate the last brace-balanced JSON object that carries a "primitive"
    field, returning its start offset and the parsed object.

    Real models emit the self-report as a single line, pretty-printed across
    several lines, or with a nested "parameters" object; a line-based scan
    handles only the first. Matching braces backward from the final `}` covers
    all three (JSON is balanced, so the scan reaches its opening `{` before any
    brace in the Java diff above it).
    """
    end = len(text)
    while True:
        close = text.rfind("}", 0, end)
        if close == -1:
            return None
        depth = 0
        for k in range(close, -1, -1):
            if text[k] == "}":
                depth += 1
            elif text[k] == "{":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[k : close + 1])
                    except json.JSONDecodeError:
                        break  # unbalanced/invalid here; fall back to an earlier `}`
                    if isinstance(obj, dict) and "primitive" in obj:
                        return k, obj
                    break
        end = close  # this `}` did not yield the self-report; try the previous one


def parse_response(raw_text: str) -> ParsedResponse:
    text = _strip_code_fences(raw_text).strip()
    if not text:
        raise MalformedResponseError("empty response")

    found = _find_trailing_self_report(text)
    if found is None:
        raise MalformedResponseError(
            "no trailing JSON self-report object with a 'primitive' field found"
        )
    start, claim = found

    diff_text = text[:start].strip()
    if not diff_text:
        raise MalformedResponseError("no diff content before the JSON self-report line")

    return ParsedResponse(
        unified_diff=diff_text,
        claimed_primitive=str(claim.get("primitive", "")),
        claimed_parameters=str(claim.get("parameters", "")),
    )
