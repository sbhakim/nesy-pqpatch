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


def parse_response(raw_text: str) -> ParsedResponse:
    lines = raw_text.rstrip().splitlines()
    if not lines:
        raise MalformedResponseError("empty response")

    # Scan from the end for the first line that parses as a JSON object
    # containing "primitive" -- tolerates trailing blank lines or minor
    # chatter after the JSON line, but not before it.
    json_line_idx: int | None = None
    claim: dict[str, str] = {}
    for i in range(len(lines) - 1, -1, -1):
        stripped = lines[i].strip()
        if not stripped:
            continue
        try:
            candidate = json.loads(stripped)
        except json.JSONDecodeError:
            break  # first non-JSON, non-blank line from the end ends the scan
        if isinstance(candidate, dict) and "primitive" in candidate:
            json_line_idx = i
            claim = candidate
        break

    if json_line_idx is None:
        raise MalformedResponseError(
            "no trailing JSON self-report line with a 'primitive' field found"
        )

    diff_text = "\n".join(lines[:json_line_idx]).strip()
    if not diff_text:
        raise MalformedResponseError("no diff content before the JSON self-report line")

    return ParsedResponse(
        unified_diff=diff_text,
        claimed_primitive=str(claim.get("primitive", "")),
        claimed_parameters=str(claim.get("parameters", "")),
    )
