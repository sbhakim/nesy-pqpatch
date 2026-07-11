"""Optional ML-DSA attestation over a finalized trace's content hash.

liboqs-python is an optional extra (`pip install ".[attest]"`); the core
pipeline must not require a native-code dependency. Calling these functions
without the extra installed raises an explicit error, never a silent no-op.
"""

from __future__ import annotations

import dataclasses

from pqpatch.model import TraceRecord
from pqpatch.trace.canonical import compute_content_hash

_DEFAULT_ALGORITHM = "ML-DSA-65"


class AttestationUnavailableError(RuntimeError):
    """Raised when liboqs-python is not installed (extras: attest)."""


def _load_oqs() -> object:
    try:
        import oqs  # type: ignore[import-not-found]
    except ImportError as exc:
        raise AttestationUnavailableError(
            "liboqs-python is not installed. Install with "
            "`pip install -e '.[attest]'` to enable ML-DSA trace signing "
            "(codebase-plan.md package manifest)."
        ) from exc
    return oqs


def generate_keypair(algorithm: str = _DEFAULT_ALGORITHM) -> tuple[bytes, bytes]:
    """Return (public_key, secret_key). Key handling is in-memory only;
    production key management is out of scope for this artifact."""
    oqs = _load_oqs()
    with oqs.Signature(algorithm) as signer:  # type: ignore[attr-defined]
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    return public_key, secret_key


def sign_trace(
    record: TraceRecord, secret_key: bytes, *, algorithm: str = _DEFAULT_ALGORITHM
) -> TraceRecord:
    """Signs the trace's content_hash (record must already be finalized,
    i.e. content_hash populated by trace/canonical.py) and returns a copy
    with `signature` set."""
    if not record.content_hash:
        raise ValueError("cannot sign an un-finalized trace; call finalize_trace() first")
    oqs = _load_oqs()
    with oqs.Signature(algorithm, secret_key) as signer:  # type: ignore[attr-defined]
        signature = signer.sign(record.content_hash.encode("utf-8"))
    return dataclasses.replace(record, signature=signature.hex())


def verify_signature(
    record: TraceRecord, public_key: bytes, *, algorithm: str = _DEFAULT_ALGORITHM
) -> bool:
    if not record.signature or not record.content_hash:
        return False
    if compute_content_hash(record) != record.content_hash:
        return False  # content itself was tampered; do not even check the signature
    oqs = _load_oqs()
    with oqs.Signature(algorithm) as verifier:  # type: ignore[attr-defined]
        # `verifier`'s type is already Any downstream of the ignored attr-defined
        # above (oqs is loaded as `object`, per _load_oqs()'s honest return type),
        # so no further type: ignore is needed -- or accepted -- on this call.
        return bool(
            verifier.verify(
                record.content_hash.encode("utf-8"),
                bytes.fromhex(record.signature),
                public_key,
            )
        )
