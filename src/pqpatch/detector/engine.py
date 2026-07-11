"""Detection engine: runs the Semgrep rule pack and parses its findings.

The only module that invokes Semgrep. Zero findings is a valid quiet
success; a failed invocation is an exception, never an empty result.
"""

from __future__ import annotations

import json
import subprocess  # noqa: S404 -- fixed argv, no shell
from dataclasses import dataclass
from pathlib import Path

_PACK_DIR = Path(__file__).parent / "semgrep_pack"


class SemgrepUnavailableError(RuntimeError):
    """Raised when the semgrep binary cannot be found or invoked."""


@dataclass(frozen=True, slots=True)
class RawMatch:
    """One semgrep finding, before usage-class resolution (detector/classify.py)."""

    rule_id: str
    file_path: str
    line: int
    end_line: int
    matched_code_hint: str  # short receiver.method("algo") string reconstructed from the rule id


def scan_repo(repo_path: Path, *, pack_dir: Path = _PACK_DIR) -> list[RawMatch]:
    """Run the semgrep pack against every Java file under repo_path."""
    if not pack_dir.exists():
        raise SemgrepUnavailableError(f"semgrep pack not found at {pack_dir}")

    cmd = [
        "semgrep",
        "--config",
        str(pack_dir),
        "--json",
        "--quiet",
        "--no-git-ignore",
        str(repo_path),
    ]
    try:
        proc = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=120, check=False
        )
    except FileNotFoundError as exc:
        raise SemgrepUnavailableError("semgrep binary not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise SemgrepUnavailableError(f"semgrep timed out scanning {repo_path}") from exc

    if proc.returncode not in (0, 1):  # semgrep exits 1 when findings exist under some configs
        raise SemgrepUnavailableError(
            f"semgrep exited {proc.returncode}: {proc.stderr[-500:]}"
        )

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SemgrepUnavailableError(f"could not parse semgrep JSON output: {exc}") from exc

    matches: list[RawMatch] = []
    for result in payload.get("results", []):
        check_id = result["check_id"].split(".")[-1]  # strip the pack-path prefix semgrep adds
        matches.append(
            RawMatch(
                rule_id=check_id,
                file_path=result["path"],
                line=result["start"]["line"],
                end_line=result["end"]["line"],
                matched_code_hint=check_id,
            )
        )
    return matches
