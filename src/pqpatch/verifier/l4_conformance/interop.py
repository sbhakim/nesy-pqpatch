"""Cross-provider interoperability: artifacts produced by the patched code
must verify under an independent stack (JDK24/BouncyCastle/OpenSSL,
manuscript Sec. 4.3). Real interface, not implemented -- see package
__init__.py and codebase-plan.md §5 Phase 5."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class InteropResult:
    passed: bool
    stacks_checked: tuple[str, ...]
    detail: str


def cross_provider_check(artifact_path: str, primitive: str) -> InteropResult:
    raise NotImplementedError(
        "requires containers/build-jdk24 and containers/crypto-tools; "
        "see codebase-plan.md §5 Phase 5"
    )
