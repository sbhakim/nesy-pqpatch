"""Backend A: hosted model behind the OpenAI-compatible chat-completions
API. Requires PQPATCH_BACKEND_A_API_KEY; refuses to run a live call
without one. Not exercised by the test suite, which forbids network access.
"""

from __future__ import annotations

import httpx

from pqpatch.proposer.base import Backend
from pqpatch.settings import Settings

_DEFAULT_MODEL = "gpt-5.1"


class BackendACredentialsError(RuntimeError):
    """Raised when PQPATCH_BACKEND_A_API_KEY is not set."""


class BackendA(Backend):
    backend_id = "backend-a"

    def __init__(
        self,
        settings: Settings,
        *,
        model: str = _DEFAULT_MODEL,
        base_url: str | None = None,
        cache: object | None = None,
    ) -> None:
        super().__init__(settings, cache=cache)  # type: ignore[arg-type]
        if not settings.backend_a_api_key:
            raise BackendACredentialsError(
                "PQPATCH_BACKEND_A_API_KEY is not set; BackendA cannot be used "
                "for a live call (cached/replayed runs do not need this)."
            )
        self._api_key = settings.backend_a_api_key
        self.model_version = model
        # Explicit arg wins; otherwise the env-configured endpoint (settings).
        self._base_url = base_url or settings.backend_a_base_url

    def _generate_raw(
        self, prompt: str, *, seed: int, site_id: str, attempt: int
    ) -> tuple[str, int]:
        del site_id, attempt  # not part of the request; the cache key covers reproducibility
        payload = {
            "model": self.model_version,
            "messages": [{"role": "user", "content": prompt}],
            "seed": seed,
            "temperature": 0.2,
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}
        with httpx.Client(base_url=self._base_url, timeout=120.0) as client:
            resp = client.post("/chat/completions", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        text = data["choices"][0]["message"]["content"]
        token_count = int(data.get("usage", {}).get("total_tokens", len(text.split())))
        return text, token_count
