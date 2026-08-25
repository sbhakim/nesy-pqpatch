"""Backend C: any OpenAI-compatible chat-completions endpoint.

Defaults to a local open-weight server (vLLM or llama.cpp) at
PQPATCH_BACKEND_C_BASE_URL, which needs no credentials. Setting
PQPATCH_BACKEND_C_API_KEY adds a bearer header, which is what a hosted
OpenAI-compatible endpoint requires -- Gemini exposes one at
https://generativelanguage.googleapis.com/v1beta/openai. The request shape is
identical either way, so no separate adapter is needed.
"""

from __future__ import annotations

import httpx

from pqpatch.proposer.base import Backend
from pqpatch.settings import Settings

_DEFAULT_MODEL = "local-open-weight-model"


class BackendCUnreachableError(RuntimeError):
    """Raised when the local inference server cannot be reached."""


class BackendC(Backend):
    backend_id = "backend-c"

    def __init__(
        self,
        settings: Settings,
        *,
        model: str = _DEFAULT_MODEL,
        base_url: str | None = None,
        send_seed: bool = True,
        cache: object | None = None,
    ) -> None:
        super().__init__(settings, cache=cache)  # type: ignore[arg-type]
        self.model_version = model
        # Explicit arg wins; otherwise the env-configured endpoint (settings).
        self._base_url = base_url or settings.backend_c_base_url
        self._api_key = settings.backend_c_api_key
        # Not every OpenAI-compatible endpoint accepts `seed`: vLLM does,
        # Gemini's compatibility layer rejects the field outright. Where it is
        # unsupported, seed-to-seed variation is ordinary sampling noise rather
        # than provider-pinned determinism -- the cache key still includes the
        # seed, so each seed remains a distinct, separately cached draw.
        self._send_seed = send_seed

    def request_spec(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "api_style": "openai-compatible-chat-completions",
            "temperature": 0.2,
            "top_p": None,
            "max_tokens": None,
            "seed_supported": self._send_seed,
        }

    def _generate_raw(
        self, prompt: str, *, seed: int, site_id: str, attempt: int
    ) -> tuple[str, int]:
        del site_id, attempt
        payload: dict[str, object] = {
            "model": self.model_version,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
        }
        if self._send_seed:
            payload["seed"] = seed
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}
        try:
            with httpx.Client(base_url=self._base_url, timeout=180.0) as client:
                resp = client.post("/chat/completions", json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except httpx.ConnectError as exc:
            raise BackendCUnreachableError(
                f"could not reach the local inference server at {self._base_url}"
            ) from exc
        text = data["choices"][0]["message"]["content"]
        token_count = int(data.get("usage", {}).get("total_tokens", len(text.split())))
        return text, token_count
