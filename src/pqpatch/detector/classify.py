"""Usage-class resolution: a detector match plus surrounding source yields
one of the five usage classes.

Pure function, no I/O. Note that CONFIG-class sites (algorithm names read
from configuration at runtime) produce no match to classify; their miss
rate is a measured quantity in the evaluation, not a defect of this module.
"""

from __future__ import annotations

from pqpatch.detector.engine import RawMatch
from pqpatch.model import UsageClass

# rule ids that resolve to exactly one usage class, no context needed
_UNAMBIGUOUS: dict[str, UsageClass] = {
    "pq-detect-cipher-envelope": UsageClass.ENVELOPE,
    "pq-detect-keyagreement": UsageClass.KEM,
}

_DEFAULT_WINDOW = 20


def _window(source_lines: list[str], line: int, window: int) -> str:
    """1-indexed `line`; returns the joined text of [line, line+window)."""
    start = max(line - 1, 0)
    end = min(start + window, len(source_lines))
    return "\n".join(source_lines[start:end])


def classify(
    match: RawMatch, source_lines: list[str], *, window: int = _DEFAULT_WINDOW
) -> UsageClass:
    """Resolve a match to a usage class. `source_lines` is the full file,
    split once and shared across all matches in that file."""
    if match.rule_id in _UNAMBIGUOUS:
        return _UNAMBIGUOUS[match.rule_id]

    ctx = _window(source_lines, match.line, window)

    if match.rule_id == "pq-detect-signature":
        # Ambiguous between SIGN and VERIFY: whichever of initSign/initVerify
        # appears first in the window decides; SIGN is the default.
        sign_pos = ctx.find("initSign")
        verify_pos = ctx.find("initVerify")
        if verify_pos != -1 and (sign_pos == -1 or verify_pos < sign_pos):
            return UsageClass.VERIFY
        return UsageClass.SIGN

    if match.rule_id == "pq-detect-keypairgenerator":
        # KEM if the generated pair feeds a KeyAgreement nearby, else SIGN.
        if "KeyAgreement" in ctx:
            return UsageClass.KEM
        return UsageClass.SIGN

    raise ValueError(f"no classification rule for detector rule id: {match.rule_id!r}")
