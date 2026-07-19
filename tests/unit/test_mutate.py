"""Tier-1 surface mutation: semantics preserved, surface changed, deterministic.

The contamination control only works if the mutation is total surface noise
with zero semantic delta: algorithm literals untouched, unsafe-to-rename names
skipped, output stable across runs, and the result still compiles."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from pqpatch.eval.mutate import mutate_case, mutate_source

_CASE = """\
// A memorizable benchmark case.
public class WeakSigner {
    private int counter;  /* a field: its name must never be renamed */

    public byte[] sign(byte[] payload) throws Exception {
        // the algorithm literal below is the misuse under test
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        int attempts = counter + 1;
        counter = attempts;
        return payload;
    }
}
"""


def test_mutation_changes_surface_and_preserves_the_misuse() -> None:
    mutated, new_class = mutate_source(_CASE, case="t/WeakSigner.java")

    assert '"SHA256withRSA"' in mutated  # the misuse literal is sacrosanct
    assert new_class is not None and new_class != "WeakSigner"
    assert "WeakSigner" not in mutated  # class renamed everywhere
    assert "attempts" not in mutated  # local renamed
    assert "counter" in mutated  # field name blocked from renaming
    assert "memorizable" not in mutated  # comments stripped
    assert "misuse under test" not in mutated


def test_mutation_is_deterministic() -> None:
    a, _ = mutate_source(_CASE, case="t/WeakSigner.java")
    b, _ = mutate_source(_CASE, case="t/WeakSigner.java")
    assert a == b


def test_unparseable_source_is_refused() -> None:
    with pytest.raises(ValueError, match="does not parse"):
        mutate_source("public class { broken", case="t/Broken.java")


def test_mutate_case_renames_file_and_compiles(tmp_path: Path) -> None:
    if shutil.which("javac") is None:
        pytest.skip("javac not available")
    case_dir = tmp_path / "case-001"
    case_dir.mkdir()
    (case_dir / "WeakSigner.java").write_text(_CASE)

    out_dir = tmp_path / "mutated"
    written = mutate_case(case_dir, out_dir)

    java_files = [p for p in written if p.suffix == ".java"]
    assert len(java_files) == 1
    assert java_files[0].name != "WeakSigner.java"  # file follows the class

    proc = subprocess.run(  # noqa: S603 -- fixed argv over a test-authored file
        ["javac", "-d", str(tmp_path / "classes"), str(java_files[0])],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
