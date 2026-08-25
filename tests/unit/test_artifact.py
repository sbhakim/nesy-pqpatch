"""Determinism and integrity checks for the ICC development artifact."""

from __future__ import annotations

from pathlib import Path

import pytest

from pqpatch.eval.artifact import (
    ArtifactError,
    _tier1_mutated_members,
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


def test_tier1_variants_are_generated_into_artifact(tmp_path: Path) -> None:
    case = tmp_path / "original" / "demo"
    case.mkdir(parents=True)
    (case / "Example.java").write_text(
        "public class Example { int f(int value) { return value; } }\n",
        encoding="utf-8",
    )
    descriptor = b"case_id: demo\nreference_target: ML-DSA\n"
    (case / "case.yaml").write_bytes(descriptor)

    members = _tier1_mutated_members(tmp_path / "original")
    java_names = [name for name in members if name.endswith(".java")]
    assert len(java_names) == 1
    assert java_names[0] != "code/corpus/tier1/mutated/demo/Example.java"
    assert b"class Example" not in members[java_names[0]]
    assert members["code/corpus/tier1/mutated/demo/case.yaml"] == descriptor
