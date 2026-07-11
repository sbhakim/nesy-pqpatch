"""NIST ACVP known-answer-test runner against pinned vectors
(verifier/l4_conformance/vectors/, codebase-plan.md §5 Phase 5).
Real interface, not implemented -- see package __init__.py."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AcvpResult:
    passed: bool
    vectors_checked: int
    detail: str


def run_kat(parameter_set: str, vectors_dir: Path) -> AcvpResult:
    raise NotImplementedError(
        "requires pinned ACVP vectors (see vectors/VERSION, not yet populated) "
        "and containers/crypto-tools; see codebase-plan.md §5 Phase 5"
    )
