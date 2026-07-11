"""Canonical trace serialization and content hashing.

A trace serializes to the same bytes on any machine -- sorted keys, fixed
separators -- and its SHA-256 digest is the value that attestation signs.
The digest and signature fields are excluded from the serialization they
authenticate.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from typing import Any

from pqpatch.model import TraceRecord


def _to_jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, tuple | list):
        return [_to_jsonable(v) for v in obj]
    if isinstance(obj, dict):
        return {str(_to_jsonable(k)): _to_jsonable(v) for k, v in obj.items()}
    return obj  # str, int, float, bool, None, and StrEnum/IntEnum (str/int subtypes) pass through


def to_canonical_json(record: TraceRecord) -> str:
    """Serializes every field of `record` EXCEPT content_hash and signature
    -- those are computed from / attached to this string, so including them
    would make the hash depend on itself."""
    payload = _to_jsonable(record)
    del payload["content_hash"]
    del payload["signature"]
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_content_hash(record: TraceRecord) -> str:
    canonical = to_canonical_json(record)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def finalize_trace(record: TraceRecord) -> TraceRecord:
    """Returns a copy of `record` with content_hash populated. TraceRecord
    is frozen, so this is the only way to set it -- callers cannot
    construct an already-hashed record by hand (invariant: the hash is
    always derived, never asserted)."""
    return dataclasses.replace(record, content_hash=compute_content_hash(record))


def verify_content_hash(record: TraceRecord) -> bool:
    """Recomputes the hash and checks it against record.content_hash --
    the tamper-detection primitive (manuscript Theorem 2), usable
    independently of whether ML-DSA signing (trace/attest.py) is enabled."""
    if not record.content_hash:
        return False
    return compute_content_hash(record) == record.content_hash
