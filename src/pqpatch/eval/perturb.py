"""Adversarial surface perturbations for probing detector robustness.

Upgrade U-F (refined_defined_plan.md §12.3): the literal-pattern detector keys
on algorithm strings like "SHA256withRSA". A semantics-preserving perturbation
that hides those strings -- without changing what the code does -- measures how
much of the detector's recall is real understanding versus surface matching.
The transforms here produce the perturbed source; an eval run then re-detects
on it and reports the recall drop against the unperturbed ground truth.

Not every surface change fools every detector, and saying which is the point.
Measured against this project's Semgrep pack (test_perturb.py):

- `split_string_literal` and simple variable concatenation are *constant-folded*
  by Semgrep and do NOT evade it -- a real, reportable robustness result for the
  detector, not a failure of the probe.
- `array_indirect_literal` routes the name through a one-element array, so it
  reaches `getInstance` as an array-index expression rather than a foldable
  constant; Semgrep does not follow it, and detection drops. This mirrors the
  seed corpus's deliberately-hard, configuration-driven site.

Every transform is a pure `str -> str` function that preserves Java semantics --
it changes surface, never behavior -- so any recall drop is attributable to the
detector, not to a different program.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass


def split_string_literal(source: str, literal: str) -> str:
    """Rewrite every `"literal"` as a two-piece concatenation, e.g.
    `"SHA256withRSA"` -> `"SHA256w" + "ithRSA"`. Java folds the pieces at
    compile time, so behavior is identical, but a detector matching the whole
    literal substring no longer sees it. A literal shorter than two characters
    cannot be split and is returned unchanged.
    """
    if len(literal) < 2:
        return source
    mid = len(literal) // 2
    replacement = f'"{literal[:mid]}" + "{literal[mid:]}"'
    return source.replace(f'"{literal}"', replacement)


def array_indirect_literal(source: str, literal: str) -> str:
    """Rewrite every `"literal"` as `new String[]{"literal"}[0]`. The value is
    unchanged, but the argument is now an array-index expression rather than a
    compile-time constant, which defeats Semgrep's constant folding (verified in
    test_perturb.py). Use this, not `split_string_literal`, when the goal is to
    actually blind a literal-pattern detector."""
    return source.replace(f'"{literal}"', f'new String[]{{"{literal}"}}[0]')


def rename_identifier(source: str, old: str, new: str) -> str:
    """Whole-word rename of a program identifier. Word boundaries keep the
    rename from corrupting `old` where it appears inside a longer name; the
    caller is responsible for choosing a name that is safe to rename globally
    (a local variable, a private helper)."""
    if not old.isidentifier() or not new.isidentifier():
        raise ValueError("both names must be valid identifiers")
    return re.sub(rf"\b{re.escape(old)}\b", new, source)


@dataclass(frozen=True, slots=True)
class Perturbation:
    """A named surface transform, so a run can report degradation per
    perturbation rather than as one opaque number."""

    name: str
    apply: Callable[[str], str]


def literal_splitter(literal: str) -> Perturbation:
    return Perturbation(
        name=f"split-literal:{literal}",
        apply=lambda src: split_string_literal(src, literal),
    )


def array_indirecter(literal: str) -> Perturbation:
    return Perturbation(
        name=f"array-indirect:{literal}",
        apply=lambda src: array_indirect_literal(src, literal),
    )


def identifier_renamer(old: str, new: str) -> Perturbation:
    return Perturbation(
        name=f"rename:{old}->{new}",
        apply=lambda src: rename_identifier(src, old, new),
    )


def apply_all(source: str, perturbations: Sequence[Perturbation]) -> str:
    """Compose perturbations left to right. Order can matter (a rename may feed
    a later split), so it is the caller's, not sorted here."""
    for p in perturbations:
        source = p.apply(source)
    return source
