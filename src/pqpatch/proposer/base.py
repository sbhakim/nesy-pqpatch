"""Proposer backend interface.

Prompt assembly, caching, and response parsing are fixed here; a concrete
backend supplies only the raw generation call. This guarantees that every
backend receives byte-identical prompts and that none can bypass the cache.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod

from pqpatch.model import Context, Patch, Policy
from pqpatch.proposer.cache import CacheStore
from pqpatch.proposer.prompting import render_prompt
from pqpatch.proposer.response_format import parse_response
from pqpatch.settings import Settings


class Backend(ABC):
    """One proposer. Subclasses implement `_generate_raw` only."""

    backend_id: str
    model_version: str

    def __init__(self, settings: Settings, *, cache: CacheStore | None = None) -> None:
        self._settings = settings
        self._cache = cache or CacheStore(settings.cache_dir, offline=settings.offline)

    @abstractmethod
    def _generate_raw(
        self, prompt: str, *, seed: int, site_id: str, attempt: int
    ) -> tuple[str, int]:
        """Perform the actual model call; returns (raw_text, token_count).

        `site_id` and `attempt` are provided for test doubles that key on
        them; network adapters ignore both, since the cache key is derived
        from the prompt alone. Only invoked on a genuine cache miss.
        """
        raise NotImplementedError

    def propose(
        self,
        context: Context,
        policy: Policy,
        *,
        feedback: str | None,
        attempt: int,
        seed: int = 0,
        prompt_version: str = "v1",
    ) -> Patch:
        prompt = render_prompt(
            context, policy, feedback=feedback, attempt=attempt, prompt_version=prompt_version
        )
        prompt_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        key = self._cache_key(prompt=prompt, seed=seed)

        cached = self._cache.get_or_fetch(
            key,
            lambda: self._generate_raw(
                prompt, seed=seed, site_id=context.site.site_id, attempt=attempt
            ),
            backend_id=self.backend_id,
            model_version=self.model_version,
            prompt_sha256=prompt_sha,
            seed=seed,
        )

        parsed = parse_response(cached.raw_text)
        response_hash = hashlib.sha256(cached.raw_text.encode("utf-8")).hexdigest()

        return Patch(
            site_id=context.site.site_id,
            attempt=attempt,
            unified_diff=parsed.unified_diff,
            claimed_primitive=parsed.claimed_primitive,
            claimed_parameters=parsed.claimed_parameters,
            backend_id=self.backend_id,
            prompt_version=prompt_version,
            response_hash=response_hash,
        )

    def _cache_key(self, *, prompt: str, seed: int) -> str:
        from pqpatch.proposer.cache import cache_key

        return cache_key(
            backend_id=self.backend_id,
            model_version=self.model_version,
            prompt=prompt,
            seed=seed,
        )
