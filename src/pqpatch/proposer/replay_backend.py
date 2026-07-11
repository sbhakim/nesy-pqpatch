"""A scripted, network-free backend for tests and demonstrations.

Responses still flow through the cache, so tests built on this backend
exercise the determinism boundary itself, not just the pipeline around it.
"""

from __future__ import annotations

from pqpatch.proposer.base import Backend
from pqpatch.proposer.cache import CacheStore
from pqpatch.settings import Settings


class ScriptExhaustedError(RuntimeError):
    """The script has no response for this (site_id, attempt); the test is
    wrong, and no response will be invented for it."""


class ReplayBackend(Backend):
    """`script` maps (site_id, attempt) to a raw response: a unified diff
    followed by the trailing JSON self-report line."""

    backend_id = "replay"
    model_version = "replay-v1"

    def __init__(
        self,
        settings: Settings,
        script: dict[tuple[str, int], str],
        *,
        cache: CacheStore | None = None,
    ) -> None:
        super().__init__(settings, cache=cache)
        self._script = script

    def _generate_raw(
        self, prompt: str, *, seed: int, site_id: str, attempt: int
    ) -> tuple[str, int]:
        del seed
        key = (site_id, attempt)
        if key not in self._script:
            raise ScriptExhaustedError(
                f"ReplayBackend has no scripted response for site_id={site_id!r}, "
                f"attempt={attempt}. Prompt was:\n{prompt[:200]}..."
            )
        text = self._script[key]
        return text, len(text.split())
