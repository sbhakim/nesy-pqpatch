"""Determinism and integrity checks for the ICC development artifact."""

from __future__ import annotations

from pathlib import Path

import pytest

from pqpatch.eval.artifact import (
    ArtifactError,
    verify_archive,
    write_deterministic_archive,
)


def test_archive_is_byte_deterministic_and_verifiable(tmp_path: Path) -> None:
    members = {"code/a.py": b"print('a')\n", "evidence/run.json": b"{}\n"}
    metadata = {"selected_run_ids": ["run-a"], "release_status": "development"}
    first = write_deterministic_archive(tmp_path / "first.zip", members, metadata=metadata)
    second = write_deterministic_archive(tmp_path / "second.zip", members, metadata=metadata)
    assert first.read_bytes() == second.read_bytes()
    manifest = verify_archive(first)
    assert manifest["members"]["code/a.py"]["size"] == len(members["code/a.py"])


def test_archive_refuses_unsafe_or_secret_paths(tmp_path: Path) -> None:
    with pytest.raises(ArtifactError, match="unsafe archive member"):
        write_deterministic_archive(
            tmp_path / "bad.zip", {"../outside": b"bad"}, metadata={}
        )
    with pytest.raises(ArtifactError, match="credential-like"):
        write_deterministic_archive(
            tmp_path / "secret.zip", {"code/private.key": b"bad"}, metadata={}
        )
