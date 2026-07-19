"""L4 round-trip conformance: sign->verify + tamper->must-fail, and
encaps->decaps secret match, executed on a real PQC-capable JDK.

The minimal-but-real slice of L4 (manuscript Sec. 4.3): every post-quantum
algorithm literal the patch introduces at a ``getInstance`` site must resolve
on the configured runtime and survive its family's round-trip. This is the
layer that catches patches which are rule-clean and compile yet are
cryptographically wrong -- most concretely the hallucinated composite
algorithm name observed live in the ablation shakeout, which satisfied every
L1/L2 rule and built cleanly but resolves to no provider.

Honesty contract, three-way:

- exact literal fails but its family works       -> **FAIL** (the patch's fault)
- the runtime lacks the entire family            -> **ERROR** (harness gap --
  e.g. SLH-DSA before its JDK ships it -- never blamed on the patch)
- ``PQPATCH_L4_JAVA_HOME`` unconfigured          -> **NotImplementedError**,
  which the orchestrator records as SKIPPED with full provenance, exactly as
  the stub behaved -- CI and non-PQC machines stay green and honest.

ACVP known-answer vectors and cross-provider interop (acvp.py / interop.py)
remain deliberate stubs; this module never claims them.
"""

from __future__ import annotations

import re
import subprocess  # noqa: S404 -- fixed argv, no shell, bounded timeouts
import tempfile
from pathlib import Path

from pqpatch.model import Patch, Policy, RuleStatus, Site
from pqpatch.settings import get_settings
from pqpatch.verifier.rules.diffutil import added_lines
from pqpatch.verifier.rules.spec import RuleOutcome

_DRIVER_SRC = Path(__file__).parent / "driver" / "RoundTrip.java"
_GETINSTANCE_LITERAL = re.compile(r'getInstance\(\s*"([^"]+)"')
_PQ_FAMILY = re.compile(r"ML-KEM|ML-DSA|SLH-DSA")
_DRIVER_TIMEOUT_S = 60

# Compiled-driver cache: one javac invocation per (javac path) per process.
# The TemporaryDirectory objects are held here so the class files outlive the
# call that compiled them.
_driver_cache: dict[str, tuple[tempfile.TemporaryDirectory[str], Path]] = {}


def pq_literals(unified_diff: str) -> list[str]:
    """Every distinct PQ-family algorithm literal the diff's added lines pass
    to a getInstance call, in first-appearance order. The *full* literal is
    kept -- a composite hallucination must be tested as written, not as its
    recognizable substring."""
    seen: list[str] = []
    for line in added_lines(unified_diff):
        for literal in _GETINSTANCE_LITERAL.findall(line):
            if _PQ_FAMILY.search(literal) and literal not in seen:
                seen.append(literal)
    return seen


def _family(literal: str) -> str:
    return "kem" if "ML-KEM" in literal else "sig"


def _compiled_driver(java_home: Path) -> Path:
    """Compile RoundTrip.java with the configured JDK once per process."""
    javac = java_home / "bin" / "javac"
    key = str(javac)
    if key not in _driver_cache:
        tmp = tempfile.TemporaryDirectory(prefix="pqpatch-l4-driver-")
        classes = Path(tmp.name)
        proc = subprocess.run(  # noqa: S603
            [str(javac), "-d", str(classes), str(_DRIVER_SRC)],
            capture_output=True,
            text=True,
            timeout=_DRIVER_TIMEOUT_S,
            check=False,
        )
        if proc.returncode != 0:
            tmp.cleanup()
            raise RuntimeError(f"L4 driver failed to compile: {proc.stderr[-500:]}")
        _driver_cache[key] = (tmp, classes)
    return _driver_cache[key][1]


def check(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    """Round-trip every PQ literal the patch introduces. See module docstring
    for the three-way honesty contract."""
    del site, policy  # conformance depends only on what the patch introduces

    settings = get_settings()
    java_home = settings.l4_java_home
    if java_home is None:
        raise NotImplementedError(
            "L4 round-trip pends a PQC-capable runtime: set PQPATCH_L4_JAVA_HOME "
            "to a JDK >= 24 home (ML-KEM/ML-DSA). ACVP vectors and interop "
            "remain future work regardless."
        )
    java = java_home / "bin" / "java"
    if not java.exists() or not (java_home / "bin" / "javac").exists():
        return RuleOutcome(
            RuleStatus.ERROR,
            detail=f"PQPATCH_L4_JAVA_HOME={java_home} has no bin/java + bin/javac",
        )

    literals = pq_literals(patch.unified_diff)
    if not literals:
        return RuleOutcome(
            RuleStatus.PASS,
            detail="no PQ algorithm literal introduced at a getInstance site; "
            "round-trip has nothing to exercise (ACVP/interop deferred)",
        )

    try:
        classes = _compiled_driver(java_home)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        return RuleOutcome(RuleStatus.ERROR, detail=str(exc))

    for literal in literals:
        proc = subprocess.run(  # noqa: S603
            [str(java), "-cp", str(classes), "RoundTrip", _family(literal), literal],
            capture_output=True,
            text=True,
            timeout=_DRIVER_TIMEOUT_S,
            check=False,
        )
        stderr = proc.stderr.strip()[-300:]
        if proc.returncode == 3:
            return RuleOutcome(
                RuleStatus.ERROR,
                detail=f"runtime cannot decide {literal!r}: {stderr}",
            )
        if proc.returncode == 2:
            return RuleOutcome(
                RuleStatus.FAIL,
                detail=f"algorithm literal {literal!r} resolves to no provider "
                f"on the conformance runtime: {stderr}",
            )
        if proc.returncode != 0:
            return RuleOutcome(
                RuleStatus.FAIL,
                detail=f"round-trip failed for {literal!r}: {stderr}",
            )

    return RuleOutcome(
        RuleStatus.PASS,
        detail=f"round-trip ok for {literals} (sign/verify+tamper or "
        "encaps/decaps; ACVP/interop deferred)",
    )
