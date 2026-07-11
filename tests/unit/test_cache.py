"""Unit tests for the content-addressed cache: key determinism, the
offline-hard-error contract, and read/write round-tripping
(codebase-plan.md §9 level 1: "cache keying")."""

from __future__ import annotations

from pathlib import Path

import pytest

from pqpatch.proposer.cache import CachedResponse, CacheStore, OfflineCacheMissError, cache_key


def test_cache_key_is_deterministic() -> None:
    k1 = cache_key(backend_id="a", model_version="m1", prompt="hello", seed=0)
    k2 = cache_key(backend_id="a", model_version="m1", prompt="hello", seed=0)
    assert k1 == k2


def test_cache_key_changes_with_any_component() -> None:
    base = cache_key(backend_id="a", model_version="m1", prompt="hello", seed=0)
    assert base != cache_key(backend_id="b", model_version="m1", prompt="hello", seed=0)
    assert base != cache_key(backend_id="a", model_version="m2", prompt="hello", seed=0)
    assert base != cache_key(backend_id="a", model_version="m1", prompt="world", seed=0)
    assert base != cache_key(backend_id="a", model_version="m1", prompt="hello", seed=1)


def test_cache_key_has_no_ambiguous_field_concatenation() -> None:
    """Guards against a classic bug: "ab" + "c" colliding with "a" + "bc"
    when fields are concatenated without a separator. cache_key() null-byte
    separates fields internally; this test proves that choice matters."""
    k1 = cache_key(backend_id="ab", model_version="c", prompt="x", seed=0)
    k2 = cache_key(backend_id="a", model_version="bc", prompt="x", seed=0)
    assert k1 != k2


def _response(text: str = "hello") -> CachedResponse:
    return CachedResponse(
        raw_text=text,
        backend_id="t",
        model_version="v1",
        prompt_sha256="0" * 64,
        seed=0,
        duration_ms=1.0,
        token_count=2,
        fetched_at_utc="2026-01-01T00:00:00Z",
    )


def test_put_then_get_round_trips(tmp_path: Path) -> None:
    store = CacheStore(tmp_path, offline=False)
    store.put("key1", _response("round trip me"))
    got = store.get("key1")
    assert got is not None
    assert got.raw_text == "round trip me"


def test_get_missing_key_returns_none_when_online(tmp_path: Path) -> None:
    store = CacheStore(tmp_path, offline=False)
    assert store.get("nope") is None


def test_get_missing_key_raises_when_offline(tmp_path: Path) -> None:
    store = CacheStore(tmp_path, offline=True)
    with pytest.raises(OfflineCacheMissError):
        store.get("nope")


def test_put_raises_when_offline(tmp_path: Path) -> None:
    store = CacheStore(tmp_path, offline=True)
    with pytest.raises(OfflineCacheMissError):
        store.put("key1", _response())


def test_get_or_fetch_only_fetches_on_miss(tmp_path: Path) -> None:
    store = CacheStore(tmp_path, offline=False)
    calls = {"n": 0}

    def fetch() -> tuple[str, int]:
        calls["n"] += 1
        return "fetched", 5

    r1 = store.get_or_fetch(
        "k", fetch, backend_id="t", model_version="v1", prompt_sha256="0" * 64, seed=0
    )
    r2 = store.get_or_fetch(
        "k", fetch, backend_id="t", model_version="v1", prompt_sha256="0" * 64, seed=0
    )
    assert calls["n"] == 1
    assert r1.raw_text == r2.raw_text == "fetched"


def test_cache_is_sharded_by_key_prefix(tmp_path: Path) -> None:
    store = CacheStore(tmp_path, offline=False)
    key = "abcdef0123456789"
    store.put(key, _response())
    assert (tmp_path / key[:2] / f"{key}.json.gz").exists()
