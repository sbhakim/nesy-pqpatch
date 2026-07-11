"""Generated round-trip tests: sign->verify, encaps->decaps, tamper->must-fail
(manuscript Sec. 4.3). Real interface, not implemented -- see package
__init__.py and codebase-plan.md §5 Phase 5."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RoundtripResult:
    passed: bool
    detail: str


def sign_verify_roundtrip(patched_class_path: str, primitive: str) -> RoundtripResult:
    raise NotImplementedError("requires containers/crypto-tools; see Phase 5")


def encaps_decaps_roundtrip(patched_class_path: str, primitive: str) -> RoundtripResult:
    raise NotImplementedError("requires containers/crypto-tools; see Phase 5")


def tamper_must_fail(patched_class_path: str, primitive: str) -> RoundtripResult:
    raise NotImplementedError("requires containers/crypto-tools; see Phase 5")
