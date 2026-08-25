"""Content-addressed response cache: the determinism boundary.

The model request is the only non-deterministic call in the pipeline. Its
response is cached here, and everything downstream must regenerate from the
cache with the network disabled. Backends call through this store, never
around it.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path


class OfflineCacheMissError(RuntimeError):
    """A cache miss under PQPATCH_OFFLINE=1. Offline mode exists to prove
    reproducibility, so a miss is a hard error, not a refetch."""


@dataclass(frozen=True, slots=True)
class CachedResponse:
    raw_text: str
    backend_id: str
    model_version: str
    prompt_sha256: str
    seed: int
    duration_ms: float
    token_count: int
    fetched_at_utc: str
    # None identifies a legacy entry whose effective request parameters were
    # not recorded; never backfill a digest by inference.
    request_spec_sha256: str | None = None


def canonical_request_spec(spec: Mapping[str, object]) -> str:
    """Canonical JSON for the effective, non-secret model request contract."""
    return json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def request_spec_digest(spec: Mapping[str, object]) -> str:
    """Stable digest used in new cache keys and run manifests."""
    return hashlib.sha256(canonical_request_spec(spec).encode("utf-8")).hexdigest()


def cache_key(
    *, backend_id: str, model_version: str, prompt: str, seed: int, extra: str = ""
) -> str:
    """Deterministic key over (backend, model, prompt bytes, seed). Fields
    are null-byte delimited to rule out concatenation collisions."""
    h = hashlib.sha256()
    for part in (backend_id, model_version, prompt, str(seed), extra):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


class CacheStore:
    """Filesystem-backed content-addressed store.

    Layout: <cache_dir>/<key[:2]>/<key>.json.gz -- sharded by the first two
    hex chars so no single directory holds tens of thousands of files.
    """

    def __init__(self, cache_dir: Path, *, offline: bool) -> None:
        self._dir = cache_dir
        self._offline = offline
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self._dir / key[:2] / f"{key}.json.gz"

    def get(self, key: str) -> CachedResponse | None:
        path = self._path(key)
        if not path.exists():
            if self._offline:
                raise OfflineCacheMissError(
                    f"cache miss for key {key} while PQPATCH_OFFLINE=1 "
                    f"(expected {path})"
                )
            return None
        with gzip.open(path, "rt", encoding="utf-8") as f:
            payload = json.load(f)
        return CachedResponse(**payload)

    def put(self, key: str, response: CachedResponse) -> None:
        if self._offline:
            # Offline mode is read-only; writing would undermine the
            # reproducibility claim it exists to support.
            raise OfflineCacheMissError(
                f"refusing to write a new cache entry for key {key} while "
                f"PQPATCH_OFFLINE=1"
            )
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with gzip.open(tmp, "wt", encoding="utf-8") as f:
            json.dump(asdict(response), f)  # asdict: CachedResponse is slots=True
        tmp.rename(path)  # atomic within the same filesystem

    def get_or_fetch(
        self,
        key: str,
        fetch: Callable[[], tuple[str, int]],
        *,
        backend_id: str,
        model_version: str,
        prompt_sha256: str,
        seed: int,
        request_spec_sha256: str | None = None,
    ) -> CachedResponse:
        """Return the cached response, invoking fetch() only on a genuine
        miss while online. fetch() returns (raw_text, token_count)."""
        cached = self.get(key)
        if cached is not None:
            return cached

        start = time.monotonic()
        raw_text, token_count = fetch()
        duration_ms = (time.monotonic() - start) * 1000.0

        response = CachedResponse(
            raw_text=raw_text,
            backend_id=backend_id,
            model_version=model_version,
            prompt_sha256=prompt_sha256,
            seed=seed,
            duration_ms=duration_ms,
            token_count=token_count,
            fetched_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            request_spec_sha256=request_spec_sha256,
        )
        self.put(key, response)
        return response
