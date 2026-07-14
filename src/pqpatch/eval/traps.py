"""Trap-suite loader and validator.

The metrics in :mod:`pqpatch.eval.metrics` (RUA, dual-RUA, Cohen's kappa,
symbolic-exclusive catches) all consume *evaluated* trap outcomes, but nothing
turned the on-disk SCHEMA-v2 YAML into typed, validated specs. This module is
that missing piece: it parses every trap descriptor under ``corpus/traps/``,
enforces the schema's structural invariants loudly (a malformed trap is a hard
error, never a silently dropped record), and exposes the suite-level facts the
paper's construct-validity story rests on -- the dev/held-out split, the
provenance mix (taxonomy vs. external), and the two-annotator label vectors that
feed the pre-registered kappa bar.

Parsing a trap here does *not* evaluate it: producing a ``TrapOutcome`` needs a
proposer run and belongs to the grid (N4). This module is the offline,
model-free gate that guarantees the traps are well-formed before any of that
spend happens.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path

import yaml

from pqpatch.eval.metrics import cohen_kappa
from pqpatch.model import UnsafeClass, UsageClass

# The trap taxonomy allows one extra bucket beyond U1..U7: a trap whose unsafe
# property is deliberately outside the current rule set (SCHEMA.md "Field
# notes"). It is a first-class value, not an error, so generalization beyond the
# taxonomy can be measured and reported separately.
_UNANTICIPATED = "unanticipated"


class TrapSplit(enum.StrEnum):
    DEV = "dev"
    HELDOUT = "heldout"


class TrapProvenance(enum.StrEnum):
    TAXONOMY = "taxonomy"
    EXTERNAL_PR = "external-pr"
    EXTERNAL_CVE = "external-cve"


class TrapValidationError(ValueError):
    """A trap descriptor violates SCHEMA.md. Carries the offending path so a
    corpus-wide load can name exactly which file to fix."""

    def __init__(self, path: Path, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path


@dataclass(frozen=True, slots=True)
class AnnotatorLabel:
    annotator: str
    unsafe: bool


@dataclass(frozen=True, slots=True)
class TrapSpec:
    """One validated trap descriptor. Mirrors SCHEMA.md v2 one-for-one; every
    field the robustness upgrades (U-C provenance/labels, U-D difficulty) depend
    on is present and typed, none inferred after the fact."""

    trap_id: str
    usage_class: UsageClass
    unsafe_class: UnsafeClass | None  # None iff the trap is "unanticipated"
    is_unanticipated: bool
    split: TrapSplit
    provenance: TrapProvenance
    source_ref: str | None
    unsafe_patch_compiles: bool
    caught_by_l3_alone: bool
    annotator_labels: tuple[AnnotatorLabel, ...]
    ground_truth_unsafe: bool
    scenario_path: str
    rationale: str
    source_file: Path


def _require(data: dict[str, object], key: str, path: Path) -> object:
    if key not in data:
        raise TrapValidationError(path, f"missing required field {key!r}")
    return data[key]


def _require_bool(data: dict[str, object], key: str, path: Path) -> bool:
    value = _require(data, key, path)
    if not isinstance(value, bool):
        raise TrapValidationError(
            path, f"field {key!r} must be a boolean, got {type(value).__name__}"
        )
    return value


def _parse_unsafe_class(raw: object, path: Path) -> tuple[UnsafeClass | None, bool]:
    if raw == _UNANTICIPATED:
        return None, True
    try:
        return UnsafeClass(str(raw)), False
    except ValueError as exc:
        allowed = [c.value for c in UnsafeClass] + [_UNANTICIPATED]
        raise TrapValidationError(
            path, f"unsafe_class {raw!r} is not one of {allowed}"
        ) from exc


def _parse_enum(enum_cls: type[enum.StrEnum], raw: object, key: str, path: Path) -> enum.StrEnum:
    try:
        return enum_cls(str(raw))
    except ValueError as exc:
        allowed = [m.value for m in enum_cls]
        raise TrapValidationError(path, f"{key} {raw!r} is not one of {allowed}") from exc


def _parse_annotator_labels(raw: object, path: Path) -> tuple[AnnotatorLabel, ...]:
    if not isinstance(raw, list):
        raise TrapValidationError(path, "annotator_labels must be a list")
    if len(raw) < 2:
        raise TrapValidationError(
            path, f"annotator_labels needs >= 2 independent labels (U-C), got {len(raw)}"
        )
    labels: list[AnnotatorLabel] = []
    for entry in raw:
        if not isinstance(entry, dict) or "annotator" not in entry or "unsafe" not in entry:
            raise TrapValidationError(
                path, "each annotator_label needs an 'annotator' and an 'unsafe' field"
            )
        if not isinstance(entry["unsafe"], bool):
            raise TrapValidationError(path, "annotator_label 'unsafe' must be a boolean")
        labels.append(AnnotatorLabel(annotator=str(entry["annotator"]), unsafe=entry["unsafe"]))
    annotators = [label.annotator for label in labels]
    if len(set(annotators)) != len(annotators):
        raise TrapValidationError(path, f"annotator ids must be distinct, got {annotators}")
    return tuple(labels)


def load_trap(path: Path) -> TrapSpec:
    """Parse and validate one trap YAML descriptor. Raises TrapValidationError
    on any schema violation."""
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise TrapValidationError(path, "trap descriptor must be a YAML mapping")

    split = _parse_enum(TrapSplit, _require(raw, "split", path), "split", path)
    provenance = _parse_enum(
        TrapProvenance, _require(raw, "provenance", path), "provenance", path
    )
    source_ref = raw.get("source_ref")
    if provenance is not TrapProvenance.TAXONOMY and not source_ref:
        raise TrapValidationError(
            path, f"provenance {provenance.value!r} requires a non-empty source_ref"
        )

    unsafe_class, is_unanticipated = _parse_unsafe_class(
        _require(raw, "unsafe_class", path), path
    )
    usage_class = _parse_enum(
        UsageClass, _require(raw, "usage_class", path), "usage_class", path
    )
    labels = _parse_annotator_labels(_require(raw, "annotator_labels", path), path)

    return TrapSpec(
        trap_id=str(_require(raw, "trap_id", path)),
        usage_class=UsageClass(usage_class),
        unsafe_class=unsafe_class,
        is_unanticipated=is_unanticipated,
        split=TrapSplit(split),
        provenance=TrapProvenance(provenance),
        source_ref=str(source_ref) if source_ref else None,
        unsafe_patch_compiles=_require_bool(raw, "unsafe_patch_compiles", path),
        caught_by_l3_alone=_require_bool(raw, "caught_by_l3_alone", path),
        annotator_labels=labels,
        ground_truth_unsafe=_require_bool(raw, "ground_truth_unsafe", path),
        scenario_path=str(_require(raw, "scenario_path", path)),
        rationale=str(_require(raw, "rationale", path)),
        source_file=path,
    )


def load_trap_suite(traps_root: Path) -> tuple[TrapSpec, ...]:
    """Load every ``*.yaml`` trap descriptor under ``traps_root`` (recursively),
    validating each. Trap ids must be unique across the whole suite. Returns
    them sorted by trap_id for deterministic reporting."""
    specs: list[TrapSpec] = []
    for path in sorted(traps_root.rglob("*.yaml")):
        specs.append(load_trap(path))
    seen: dict[str, Path] = {}
    for spec in specs:
        if spec.trap_id in seen:
            raise TrapValidationError(
                spec.source_file,
                f"duplicate trap_id {spec.trap_id!r} (also in {seen[spec.trap_id]})",
            )
        seen[spec.trap_id] = spec.source_file
    return tuple(sorted(specs, key=lambda s: s.trap_id))


@dataclass(frozen=True, slots=True)
class TrapSuiteStats:
    """Model-free, offline summary of an authored trap suite -- exactly the
    construct-validity facts the paper reports before any grid run: the split
    sizes, the provenance mix (the antidote to taxonomy self-referentiality),
    the compiling fraction (the traps a build gate cannot see), and the
    pre-registered two-annotator kappa where labels permit it."""

    total: int
    n_dev: int
    n_heldout: int
    n_taxonomy: int
    n_external: int
    n_unanticipated: int
    n_compiling_unsafe: int
    kappa: float | None  # None when < 2 comparable annotators span the suite


def summarize_suite(specs: tuple[TrapSpec, ...]) -> TrapSuiteStats:
    """Compute the offline suite summary. Kappa is taken over the first two
    annotators of every trap that carries at least two labels, matching the
    manuscript's blind-labeling protocol (metrics.cohen_kappa)."""
    labels_a: list[bool] = []
    labels_b: list[bool] = []
    for spec in specs:
        if len(spec.annotator_labels) >= 2:
            labels_a.append(spec.annotator_labels[0].unsafe)
            labels_b.append(spec.annotator_labels[1].unsafe)

    return TrapSuiteStats(
        total=len(specs),
        n_dev=sum(1 for s in specs if s.split is TrapSplit.DEV),
        n_heldout=sum(1 for s in specs if s.split is TrapSplit.HELDOUT),
        n_taxonomy=sum(1 for s in specs if s.provenance is TrapProvenance.TAXONOMY),
        n_external=sum(1 for s in specs if s.provenance is not TrapProvenance.TAXONOMY),
        n_unanticipated=sum(1 for s in specs if s.is_unanticipated),
        n_compiling_unsafe=sum(
            1 for s in specs if s.ground_truth_unsafe and s.unsafe_patch_compiles
        ),
        kappa=cohen_kappa(labels_a, labels_b) if labels_a else None,
    )
