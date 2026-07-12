"""L3: build-and-test verification.

L3 answers one question: applied to the whole project, does the patch still
build, and do the project's existing tests still pass? Two execution modes,
chosen by what the site's project actually provides:

- **Project mode.** If a `build.yaml` descriptor sits above the site file,
  the patched project tree is compiled in full and the project's own test
  entrypoint is run. This is the real L3 -- a multi-file build plus a
  regression suite -- and it is what the manuscript's L3 claim means.
- **Single-file mode.** With no descriptor, L3 falls back to a standalone
  `javac` compile of the patched file. This catches syntax errors but is not
  a project build; the outcome detail says so, and no result that leans on it
  may be reported as a full L3 pass. See ADR-002.

Both modes short-circuit before running the LLM-independent tools on anything
but a clean patch application. Runtime conformance of the *migrated* primitive
(does ML-DSA actually sign and verify) is L4's job, not L3's -- and it needs a
PQC-capable toolchain (JDK 24 / oqs), which is why the seed project's tests
deliberately exercise provider-independent behavior only.
"""

from __future__ import annotations

import re
import shutil
import subprocess  # noqa: S404 -- fixed argv, no shell, bounded timeouts
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from pqpatch.model import Patch, Policy, RuleStatus, Site
from pqpatch.verifier.rules.diffapply import DiffApplyError, apply_unified_diff
from pqpatch.verifier.rules.spec import RuleOutcome

_JAVAC_TIMEOUT_S = 30
_DESCRIPTOR_NAME = "build.yaml"
_MAX_ROOT_WALK = 6  # bound the search up the tree; corpus apps are shallow
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


@dataclass(frozen=True, slots=True)
class BuildDescriptor:
    """A project's declarative build recipe (`build.yaml`).

    Deliberately declarative, not a command list: the runner owns the actual
    argv, so a corpus file can describe *what* to build but never inject an
    arbitrary command to run.
    """

    project: str
    language: str
    source_dir: str
    test_entrypoint: str
    compile_timeout_s: int
    test_timeout_s: int

    @staticmethod
    def load(path: Path) -> BuildDescriptor:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if data.get("language") != "java":
            raise ValueError(
                f"{path}: only language 'java' is supported today; got {data.get('language')!r}"
            )
        entry = str(data["test_entrypoint"])
        if not _IDENT_RE.match(entry):
            raise ValueError(f"{path}: test_entrypoint {entry!r} is not a plain Java class name")
        return BuildDescriptor(
            project=str(data["project"]),
            language="java",
            source_dir=str(data["source_dir"]),
            test_entrypoint=entry,
            compile_timeout_s=int(data.get("compile_timeout_s", _JAVAC_TIMEOUT_S)),
            test_timeout_s=int(data.get("test_timeout_s", _JAVAC_TIMEOUT_S)),
        )


def _find_project_root(site_file: Path) -> Path | None:
    """Walk up from the site file looking for a build descriptor; return the
    directory that holds it, or None to signal single-file fallback."""
    current = site_file.resolve().parent
    for _ in range(_MAX_ROOT_WALK):
        if (current / _DESCRIPTOR_NAME).is_file():
            return current
        if current.parent == current:
            break
        current = current.parent
    return None


def check(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del policy
    site_file = Path(site.file_path)
    root = _find_project_root(site_file)
    if root is None:
        return _single_file_compile(patch, site_file)
    return _project_build_and_test(patch, site_file, root)


# --- Project mode: real multi-file build + the project's own tests ---------


def _project_build_and_test(patch: Patch, site_file: Path, root: Path) -> RuleOutcome:
    try:
        descriptor = BuildDescriptor.load(root / _DESCRIPTOR_NAME)
    except (ValueError, KeyError) as exc:
        return RuleOutcome(RuleStatus.ERROR, detail=f"invalid build descriptor: {exc}")

    with tempfile.TemporaryDirectory(prefix="pqpatch-l3-") as tmp:
        work = Path(tmp) / root.name
        shutil.copytree(root, work)

        # Apply the patch to the target file inside the copied tree, so the
        # build sees the patched project and every other file unchanged.
        target = work / site_file.resolve().relative_to(root)
        try:
            patched = apply_unified_diff(target.read_text(encoding="utf-8"), patch.unified_diff)
        except (DiffApplyError, FileNotFoundError, ValueError) as exc:
            return RuleOutcome(RuleStatus.FAIL, detail=f"patch does not apply cleanly: {exc}")
        target.write_text(patched, encoding="utf-8")

        src_dir = work / descriptor.source_dir
        sources = sorted(str(p) for p in src_dir.rglob("*.java"))
        if not sources:
            return RuleOutcome(
                RuleStatus.ERROR, detail=f"no Java sources under {descriptor.source_dir}"
            )
        classes = work / "_classes"
        classes.mkdir()

        compiled = _run(
            ["javac", "-d", str(classes), "-Xlint:none", *sources],
            cwd=work,
            timeout=descriptor.compile_timeout_s,
        )
        if compiled is None:
            return RuleOutcome(RuleStatus.ERROR, detail="javac not found on PATH")
        if compiled.returncode != 0:
            return RuleOutcome(
                RuleStatus.FAIL,
                detail=f"project build failed (javac exit {compiled.returncode}):\n"
                f"{compiled.stderr[-1000:]}",
            )

        tested = _run(
            ["java", "-cp", str(classes), descriptor.test_entrypoint],
            cwd=work,
            timeout=descriptor.test_timeout_s,
        )
        if tested is None:
            return RuleOutcome(RuleStatus.ERROR, detail="java not found on PATH")
        if tested.returncode != 0:
            tail = (tested.stdout + tested.stderr)[-1000:]
            return RuleOutcome(
                RuleStatus.FAIL,
                detail=f"project tests failed ({descriptor.test_entrypoint} "
                f"exit {tested.returncode}):\n{tail}",
            )

    return RuleOutcome(
        RuleStatus.PASS, detail=f"project build + tests passed ({descriptor.project})"
    )


# --- Single-file fallback: a standalone compile, honestly labelled ---------


def _single_file_compile(patch: Patch, site_file: Path) -> RuleOutcome:
    try:
        original = site_file.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        return RuleOutcome(RuleStatus.ERROR, detail=f"site source file not found: {exc}")
    try:
        patched_source = apply_unified_diff(original, patch.unified_diff)
    except DiffApplyError as exc:
        return RuleOutcome(RuleStatus.FAIL, detail=f"patch does not apply cleanly: {exc}")

    class_name = site_file.stem
    with tempfile.TemporaryDirectory(prefix="pqpatch-l3-") as tmp:
        tmp_path = Path(tmp)
        java_file = tmp_path / f"{class_name}.java"
        java_file.write_text(patched_source, encoding="utf-8")
        proc = _run(
            ["javac", "-d", str(tmp_path), "-Xlint:none", str(java_file)],
            cwd=tmp_path,
            timeout=_JAVAC_TIMEOUT_S,
        )
        if proc is None:
            return RuleOutcome(
                RuleStatus.ERROR, detail="javac not found on PATH; L3 cannot verify the build"
            )
        if proc.returncode != 0:
            return RuleOutcome(
                RuleStatus.FAIL,
                detail=f"single-file javac failed (exit {proc.returncode}):\n{proc.stderr[-1000:]}",
            )
    return RuleOutcome(
        RuleStatus.PASS, detail="single-file compile only (no project descriptor; ADR-002)"
    )


def _run(argv: list[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str] | None:
    """Fixed-argv subprocess with a hard timeout; None iff the tool is absent.
    A timeout surfaces as a non-zero CompletedProcess so callers treat it as a
    build failure, not a crash."""
    try:
        return subprocess.run(  # noqa: S603
            argv,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, returncode=124, stdout="", stderr="timed out")
