"""Surface perturbations for detector-robustness probing (U-F).

The unit tests pin the transforms at the string level; the integration test
proves the point of the whole exercise -- that a semantics-preserving split of
an algorithm literal actually blinds the real detector, so the recall drop a
run reports is a genuine robustness signal, not an artifact.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pqpatch.eval.perturb import (
    apply_all,
    array_indirect_literal,
    identifier_renamer,
    literal_splitter,
    rename_identifier,
    split_string_literal,
)


def test_split_string_literal_preserves_the_characters_but_breaks_the_match() -> None:
    src = 'Signature.getInstance("SHA256withRSA");'
    out = split_string_literal(src, "SHA256withRSA")
    assert '"SHA256withRSA"' not in out  # the whole literal is gone
    assert '"SHA256" + "withRSA"' in out  # split at the midpoint into two folded pieces
    # the concatenation still spells the original algorithm name
    assert "SHA256" + "withRSA" == "SHA256withRSA"


def test_split_string_literal_leaves_a_too_short_literal_alone() -> None:
    assert split_string_literal('x = "A";', "A") == 'x = "A";'


def test_array_indirect_literal_wraps_the_value_but_preserves_it() -> None:
    src = 'Signature.getInstance("SHA256withRSA");'
    out = array_indirect_literal(src, "SHA256withRSA")
    assert 'new String[]{"SHA256withRSA"}[0]' in out
    assert 'getInstance("SHA256withRSA")' not in out  # no bare literal argument left


def test_rename_identifier_is_word_bounded() -> None:
    src = "int key = 1; int keystore = key + 2;"
    out = rename_identifier(src, "key", "k")
    assert "int k = 1;" in out
    assert "keystore" in out  # not corrupted into 'kstore'
    assert "k + 2" in out


def test_rename_identifier_rejects_non_identifiers() -> None:
    with pytest.raises(ValueError):
        rename_identifier("x", "a b", "c")


def test_apply_all_composes_in_order() -> None:
    src = 'String x; Signature.getInstance("SHA256withRSA");'
    out = apply_all(
        src,
        [identifier_renamer("x", "y"), literal_splitter("SHA256withRSA")],
    )
    assert "String y;" in out
    assert '"SHA256withRSA"' not in out


_REPO_ROOT = Path(__file__).resolve().parents[2]


_SNIPPET = (
    "import java.security.Signature;\n"
    "public class Probe {\n"
    "    void m() throws Exception {\n"
    '        Signature s = Signature.getInstance("SHA256withRSA");\n'
    "    }\n"
    "}\n"
)


def _detect_source(source: str, tmp_path: Path, name: str):
    from pqpatch.detector.api import detect

    d = tmp_path / name
    d.mkdir()
    (d / "Probe.java").write_text(source, encoding="utf-8")
    return detect(d, repo_name="probe")


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="perturbation probe needs semgrep")
def test_split_literal_is_constant_folded_and_does_not_evade_semgrep(tmp_path: Path) -> None:
    """An honest negative result: Semgrep constant-folds the split concatenation,
    so this perturbation does NOT reduce recall. Reporting this is the point --
    it characterizes what the detector is robust to."""
    assert _detect_source(_SNIPPET, tmp_path, "baseline"), "baseline literal must be detected"
    split = split_string_literal(_SNIPPET, "SHA256withRSA")
    assert _detect_source(split, tmp_path, "split"), "Semgrep folds the split; still detected"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="perturbation probe needs semgrep")
def test_array_indirection_actually_blinds_the_real_detector(tmp_path: Path) -> None:
    """The array-index indirection is not constant-foldable, so the same program
    now evades the literal-pattern detector -- the genuine recall drop the U-F
    probe quantifies."""
    assert _detect_source(_SNIPPET, tmp_path, "baseline"), "baseline literal must be detected"
    indirect = array_indirect_literal(_SNIPPET, "SHA256withRSA")
    assert not _detect_source(indirect, tmp_path, "indirect")
