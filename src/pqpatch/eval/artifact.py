"""Build and verify a deterministic development artifact for the ICC study.

The archive holds the exact source snapshot, the six selected ICC runs, the
cached responses they need, and the generated manuscript inputs. It is a local
development artifact -- not an immutable public deposit, and not a DOI.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import subprocess  # noqa: S404 -- fixed git argv, no shell
import zipfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from pqpatch.eval.icc_report import _select_runs
from pqpatch.eval.mutate import mutate_source
from pqpatch.eval.run import _git_provenance
from pqpatch.eval.tables import load_runs

_ROOT = Path(__file__).resolve().parents[3]
_WORKSPACE = _ROOT.parent
_MANUSCRIPT = _WORKSPACE / "Manuscript-ICC"
_CACHE = _ROOT / "src" / "pqpatch" / "proposer" / "cache"
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_FORBIDDEN_PARTS = frozenset({".env", ".git", "__pycache__"})
_FORBIDDEN_SUFFIXES = frozenset({".key", ".pem"})


class ArtifactError(RuntimeError):
    """The evidence package is incomplete, unsafe, or internally inconsistent."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_member_name(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ArtifactError(f"unsafe archive member path {name!r}")
    if any(part in _FORBIDDEN_PARTS or "api_key" in part.lower() for part in path.parts):
        raise ArtifactError(f"secret or internal path refused: {name!r}")
    if path.suffix.lower() in _FORBIDDEN_SUFFIXES:
        raise ArtifactError(f"credential-like file refused: {name!r}")
    return path.as_posix()


def write_deterministic_archive(
    output: Path,
    members: Mapping[str, bytes],
    *,
    metadata: Mapping[str, Any],
) -> Path:
    """Write normalized members plus a checksum manifest atomically."""
    normalized: dict[str, bytes] = {}
    for name, data in members.items():
        safe_name = _safe_member_name(name)
        if safe_name == "MANIFEST.json" or safe_name in normalized:
            raise ArtifactError(f"duplicate or reserved archive member {safe_name!r}")
        normalized[safe_name] = data

    manifest = {
        "schema_version": 1,
        "artifact_kind": "icc-development-evidence",
        **metadata,
        "members": {
            name: {"sha256": _sha256(data), "size": len(data)}
            for name, data in sorted(normalized.items())
        },
    }
    normalized["MANIFEST.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with zipfile.ZipFile(
        temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, data in sorted(normalized.items()):
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, data, compresslevel=9)
    temporary.replace(output)
    return output


def verify_archive(path: Path) -> dict[str, Any]:
    """Verify safe paths, unique members, sizes, and every manifest checksum."""
    with zipfile.ZipFile(path, "r") as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ArtifactError("archive contains duplicate member names")
        for name in names:
            _safe_member_name(name)
        if "MANIFEST.json" not in names:
            raise ArtifactError("archive has no MANIFEST.json")
        manifest: dict[str, Any] = json.loads(archive.read("MANIFEST.json"))
        expected = manifest.get("members")
        if not isinstance(expected, dict):
            raise ArtifactError("manifest has no member-checksum mapping")
        actual_names = set(names) - {"MANIFEST.json"}
        if actual_names != set(expected):
            raise ArtifactError("archive member set differs from its manifest")
        for name, expected_values in expected.items():
            data = archive.read(name)
            if len(data) != expected_values.get("size"):
                raise ArtifactError(f"size mismatch for {name}")
            if _sha256(data) != expected_values.get("sha256"):
                raise ArtifactError(f"checksum mismatch for {name}")
    return manifest


def _git_source_members() -> dict[str, bytes]:
    proc = subprocess.run(  # noqa: S603
        [  # noqa: S607 -- fixed git executable and arguments
            "git",
            "-C",
            str(_ROOT),
            "ls-files",
            "-co",
            "--exclude-standard",
            "-z",
        ],
        capture_output=True,
        check=True,
        timeout=30,
    )
    members: dict[str, bytes] = {}
    for raw in sorted(part for part in proc.stdout.split(b"\0") if part):
        relative = Path(raw.decode("utf-8"))
        path = _ROOT / relative
        if path.is_symlink():
            raise ArtifactError(f"source symlink refused: {relative}")
        if path.is_file():
            members[f"code/{relative.as_posix()}"] = path.read_bytes()
    return members


def _tier1_mutated_members(
    original_root: Path = _ROOT / "corpus" / "tier1" / "original",
) -> dict[str, bytes]:
    """Generate ignored Tier-1 variants directly into the evidence archive.

    The working-tree copies are intentionally gitignored because they are
    reproducible build products.  Emitting them from the same deterministic
    transformation here prevents an archive from claiming paired artifacts
    while containing only the original benchmark surfaces.
    """
    cases = sorted(path for path in original_root.iterdir() if path.is_dir())
    if not cases:
        raise ArtifactError("Tier-1 originals are missing; cannot generate variants")

    members: dict[str, bytes] = {}
    for case_dir in cases:
        for path in sorted(case_dir.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(case_dir)
            target_name = relative.name
            if path.suffix == ".java":
                mutated, new_class = mutate_source(
                    path.read_text(encoding="utf-8"),
                    case=f"{case_dir.name}/{relative.as_posix()}",
                )
                if new_class is not None:
                    target_name = f"{new_class}.java"
                data = mutated.encode("utf-8")
            else:
                data = path.read_bytes()
            target = (
                Path("code/corpus/tier1/mutated")
                / case_dir.name
                / relative.parent
                / target_name
            )
            members[target.as_posix()] = data
    return members


def _selected_evidence_members() -> tuple[dict[str, bytes], list[str], int]:
    selected = _select_runs(load_runs(_ROOT / "runs"))
    members: dict[str, bytes] = {}
    run_ids: list[str] = []
    required_responses: set[tuple[str, str, str, int]] = set()
    for run in selected.values():
        manifest = run["manifest"]
        run_id = str(manifest["config_hash"])
        run_ids.append(run_id)
        for path in sorted(run["run_dir"].rglob("*")):
            if path.is_file():
                relative = path.relative_to(run["run_dir"]).as_posix()
                members[f"evidence/runs/{run_id}/{relative}"] = path.read_bytes()
        for record in run["records"]:
            response_hash = record.get("response_hash")
            if response_hash:
                required_responses.add(
                    (
                        str(response_hash),
                        str(manifest["backend_id"]),
                        str(manifest["model_version"]),
                        int(record["seed"]),
                    )
                )

    found: set[tuple[str, str, str, int]] = set()
    cache_count = 0
    for path in sorted(_CACHE.rglob("*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
        identity = (
            _sha256(str(payload["raw_text"]).encode("utf-8")),
            str(payload["backend_id"]),
            str(payload["model_version"]),
            int(payload["seed"]),
        )
        if identity in required_responses:
            relative = path.relative_to(_CACHE).as_posix()
            members[f"evidence/cache/{relative}"] = path.read_bytes()
            found.add(identity)
            cache_count += 1
    missing = required_responses - found
    if missing:
        raise ArtifactError(f"{len(missing)} selected response(s) are absent from the cache")
    return members, sorted(run_ids), cache_count


def _manuscript_members() -> dict[str, bytes]:
    paths = [
        _MANUSCRIPT / "main.tex",
        _MANUSCRIPT / "references.bib",
        *sorted((_MANUSCRIPT / "generated").glob("*")),
        *sorted((_MANUSCRIPT / "figures").glob("*.py")),
        _WORKSPACE / "ICC-2027-Preparation-Plan.md",
        _WORKSPACE / "improvement-plan-august.md",
    ]
    members: dict[str, bytes] = {}
    for path in paths:
        if not path.is_file():
            raise ArtifactError(f"required manuscript input is missing: {path}")
        if path.parent == _WORKSPACE:
            name = f"planning/{path.name}"
        else:
            name = f"manuscript/{path.relative_to(_MANUSCRIPT).as_posix()}"
        members[name] = path.read_bytes()
    return members


def build_artifact(output: Path) -> Path:
    source = _git_source_members()
    tier1_mutated = _tier1_mutated_members()
    evidence, run_ids, cache_count = _selected_evidence_members()
    manuscript = _manuscript_members()
    members = {**source, **tier1_mutated, **evidence, **manuscript}
    provenance = _git_provenance(_ROOT)
    return write_deterministic_archive(
        output,
        members,
        metadata={
            "release_status": "development",
            "source_provenance": provenance,
            "selected_run_ids": run_ids,
            "selected_cache_files": cache_count,
            "note": "No DOI is claimed; publish and cite an immutable deposit separately.",
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=_ROOT / "dist" / "pqpatch-icc-evidence.zip")
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args(argv)
    if args.verify:
        manifest = verify_archive(args.verify)
        print(
            f"verified {args.verify}: {len(manifest['members'])} members, "
            f"{len(manifest.get('selected_run_ids', []))} selected runs"
        )
        return 0
    path = build_artifact(args.out)
    manifest = verify_archive(path)
    print(
        f"wrote and verified {path}: {len(manifest['members'])} members; "
        f"sha256={_sha256(path.read_bytes())}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
