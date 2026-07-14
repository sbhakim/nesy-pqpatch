"""Trap loader/validator: schema enforcement and offline suite summary.

The loader is the model-free gate that guarantees every authored trap is
well-formed before any grid spend (N4). These tests pin its refusals -- a trap
that violates SCHEMA.md must raise, never load as a silently degraded record.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from pqpatch.eval.traps import (
    TrapProvenance,
    TrapSplit,
    TrapValidationError,
    load_trap,
    load_trap_suite,
    summarize_suite,
)

_CORPUS = Path(__file__).resolve().parents[2] / "corpus"

_VALID: dict[str, object] = {
    "trap_id": "t-001",
    "usage_class": "envelope",
    "unsafe_class": "U6",
    "split": "dev",
    "provenance": "taxonomy",
    "unsafe_patch_compiles": True,
    "caught_by_l3_alone": False,
    "annotator_labels": [
        {"annotator": "A", "unsafe": True},
        {"annotator": "B", "unsafe": True},
    ],
    "ground_truth_unsafe": True,
    "scenario_path": "dev/t-001/",
    "rationale": "drops the classical half of a hybrid secret",
}


def _write(tmp_path: Path, data: dict[str, object], name: str = "t.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data))
    return path


def test_valid_trap_loads(tmp_path: Path) -> None:
    spec = load_trap(_write(tmp_path, _VALID))
    assert spec.trap_id == "t-001"
    assert spec.split is TrapSplit.DEV
    assert spec.provenance is TrapProvenance.TAXONOMY
    assert spec.unsafe_class is not None and spec.unsafe_class.value == "U6"
    assert spec.is_unanticipated is False
    assert len(spec.annotator_labels) == 2


def test_unanticipated_is_a_valid_class_not_an_error(tmp_path: Path) -> None:
    data = {**_VALID, "unsafe_class": "unanticipated"}
    spec = load_trap(_write(tmp_path, data))
    assert spec.is_unanticipated is True
    assert spec.unsafe_class is None


def test_external_provenance_requires_source_ref(tmp_path: Path) -> None:
    data = {**_VALID, "provenance": "external-pr"}  # no source_ref
    with pytest.raises(TrapValidationError, match="requires a non-empty source_ref"):
        load_trap(_write(tmp_path, data))


def test_external_provenance_with_source_ref_loads(tmp_path: Path) -> None:
    data = {**_VALID, "provenance": "external-cve", "source_ref": "CVE-2024-0001"}
    spec = load_trap(_write(tmp_path, data))
    assert spec.provenance is TrapProvenance.EXTERNAL_CVE
    assert spec.source_ref == "CVE-2024-0001"


def test_fewer_than_two_annotators_rejected(tmp_path: Path) -> None:
    data = {**_VALID, "annotator_labels": [{"annotator": "A", "unsafe": True}]}
    with pytest.raises(TrapValidationError, match=r">= 2 independent labels"):
        load_trap(_write(tmp_path, data))


def test_duplicate_annotator_ids_rejected(tmp_path: Path) -> None:
    data = {
        **_VALID,
        "annotator_labels": [
            {"annotator": "A", "unsafe": True},
            {"annotator": "A", "unsafe": False},
        ],
    }
    with pytest.raises(TrapValidationError, match="distinct"):
        load_trap(_write(tmp_path, data))


def test_unknown_unsafe_class_rejected(tmp_path: Path) -> None:
    data = {**_VALID, "unsafe_class": "U9"}
    with pytest.raises(TrapValidationError, match="unsafe_class"):
        load_trap(_write(tmp_path, data))


def test_missing_required_field_rejected(tmp_path: Path) -> None:
    data = {k: v for k, v in _VALID.items() if k != "ground_truth_unsafe"}
    with pytest.raises(TrapValidationError, match="ground_truth_unsafe"):
        load_trap(_write(tmp_path, data))


def test_non_boolean_difficulty_flag_rejected(tmp_path: Path) -> None:
    data = {**_VALID, "unsafe_patch_compiles": "yes"}
    with pytest.raises(TrapValidationError, match="must be a boolean"):
        load_trap(_write(tmp_path, data))


def test_duplicate_trap_ids_across_suite_rejected(tmp_path: Path) -> None:
    _write(tmp_path, _VALID, "a.yaml")
    _write(tmp_path, _VALID, "b.yaml")  # same trap_id
    with pytest.raises(TrapValidationError, match="duplicate trap_id"):
        load_trap_suite(tmp_path)


def test_summarize_counts_split_provenance_and_kappa(tmp_path: Path) -> None:
    _write(tmp_path, _VALID, "a.yaml")
    _write(
        tmp_path,
        {
            **_VALID,
            "trap_id": "t-002",
            "split": "heldout",
            "provenance": "external-pr",
            "source_ref": "org/repo#1",
        },
        "b.yaml",
    )
    stats = summarize_suite(load_trap_suite(tmp_path))
    assert (stats.total, stats.n_dev, stats.n_heldout) == (2, 1, 1)
    assert (stats.n_taxonomy, stats.n_external) == (1, 1)
    assert stats.n_compiling_unsafe == 2
    assert stats.kappa == 1.0  # both traps: annotators agree, single class -> 1.0


def test_committed_dev_trap_is_valid() -> None:
    """The seed dev trap shipped in corpus/traps/dev/ must always validate."""
    suite = load_trap_suite(_CORPUS / "traps")
    ids = {s.trap_id for s in suite}
    assert "hyb-downgrade-envelope-001" in ids
