"""Backend C: local open-weight model served through an OpenAI-compatible
endpoint (vLLM or llama.cpp server). No credentials required; needs a
running inference server at PQPATCH_BACKEND_C_BASE_URL.
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
        cache: object | None = None,
    ) -> None:
        super().__init__(settings, cache=cache)  # type: ignore[arg-type]
        self.model_version = model
        self._base_url = settings.backend_c_base_url

    def _generate_raw(
        self, prompt: str, *, seed: int, site_id: str, attempt: int
    ) -> tuple[str, int]:
        del site_id, attempt
        payload = {
            "model": self.model_version,
            "messages": [{"role": "user", "content": prompt}],
            "seed": seed,
            "temperature": 0.2,
        }
        try:
            with httpx.Client(base_url=self._base_url, timeout=180.0) as client:
                resp = client.post("/chat/completions", json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.ConnectError as exc:
            raise BackendCUnreachableError(
                f"could not reach the local inference server at {self._base_url}"
            ) from exc
        text = data["choices"][0]["message"]["content"]
        token_count = int(data.get("usage", {}).get("total_tokens", len(text.split())))
        return text, token_count
