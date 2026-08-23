"""Backend B: hosted model behind the Anthropic Messages API. Requires
PQPATCH_BACKEND_B_API_KEY; refuses to run a live call without one. Not
exercised by the test suite, which forbids network access.
"""

from __future__ import annotations

import httpx

from pqpatch.proposer.base import Backend
from pqpatch.settings import Settings

_DEFAULT_BASE_URL = "https://api.anthropic.com"
# Sonnet 5 is the default rather than the more capable Fable 5: measured
# 2026-08-23, Fable 5 returns stop_reason "refusal" (category "cyber") on the
# adversarial trap prompts this project exists to run, producing zero output
# tokens. Sonnet 5, Opus 5, and Haiku 4.5 all complete the same prompts.
_DEFAULT_MODEL = "claude-sonnet-5"
_ANTHROPIC_VERSION = "2023-06-01"


class BackendBCredentialsError(RuntimeError):
    """Raised when PQPATCH_BACKEND_B_API_KEY is not set."""


class BackendBRefusalError(RuntimeError):
    """The model declined the prompt outright (stop_reason "refusal").

    Distinct from a malformed or empty response: the request succeeded and the
    model chose not to answer. Recording it as its own outcome keeps "the
    proposer declined" from being counted as a pipeline failure.
    """


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
        if data.get("stop_reason") == "refusal":
            # A safety classifier declined the prompt (HTTP 200, no content
            # blocks). Surface it distinctly: it is a proposer outcome, not a
            # transport failure and not a malformed response.
            details = data.get("stop_details") or {}
            raise BackendBRefusalError(
                f"model {self.model_version} refused the prompt "
                f"(category={details.get('category')!r})"
            )
        text = "".join(block.get("text", "") for block in data.get("content", []))
        usage = data.get("usage", {})
        token_count = int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
        return text, token_count or len(text.split())
