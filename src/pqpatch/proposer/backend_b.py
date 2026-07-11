"""Backend B: hosted model behind the Anthropic Messages API. Requires
PQPATCH_BACKEND_B_API_KEY; refuses to run a live call without one. Not
exercised by the test suite, which forbids network access.
"""

from __future__ import annotations

import httpx

from pqpatch.proposer.base import Backend
from pqpatch.settings import Settings

_DEFAULT_BASE_URL = "https://api.anthropic.com"
_DEFAULT_MODEL = "claude-fable-5"
_ANTHROPIC_VERSION = "2023-06-01"


class BackendBCredentialsError(RuntimeError):
    """Raised when PQPATCH_BACKEND_B_API_KEY is not set."""


class BackendB(Backend):
    backend_id = "backend-b"

    def __init__(
        self,
        settings: Settings,
        *,
        model: str = _DEFAULT_MODEL,
        base_url: str = _DEFAULT_BASE_URL,
        cache: object | None = None,
    ) -> None:
        super().__init__(settings, cache=cache)  # type: ignore[arg-type]
        if not settings.backend_b_api_key:
            raise BackendBCredentialsError(
                "PQPATCH_BACKEND_B_API_KEY is not set; BackendB cannot be used "
                "for a live call (cached/replayed runs do not need this)."
            )
        self._api_key = settings.backend_b_api_key
        self.model_version = model
        self._base_url = base_url

    def _generate_raw(
        self, prompt: str, *, seed: int, site_id: str, attempt: int
    ) -> tuple[str, int]:
        del site_id, attempt, seed  # Messages API has no seed parameter; determinism
        # for this backend comes solely from the cache, not from provider-side seeding.
        payload = {
            "model": self.model_version,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
        }
        with httpx.Client(base_url=self._base_url, timeout=120.0) as client:
            resp = client.post("/v1/messages", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        text = "".join(block.get("text", "") for block in data.get("content", []))
        usage = data.get("usage", {})
        token_count = int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
        return text, token_count or len(text.split())
