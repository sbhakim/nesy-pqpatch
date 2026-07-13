"""Detection engine: runs the Semgrep rule pack and parses its findings.

The only module that invokes Semgrep. Zero findings is a valid quiet
success; a failed invocation is an exception, never an empty result.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess  # noqa: S404 -- fixed argv, no shell
import tempfile
from dataclasses import dataclass
from pathlib import Path

_PACK_DIR = Path(__file__).parent / "semgrep_pack"
_SEMGREP_TIMEOUT_SECONDS = 120
_SEMGREP_ATTEMPTS = 2
_SCAN_CACHE: dict[tuple[str, str, str], tuple[RawMatch, ...]] = {}


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


def _content_digest(root: Path, pattern: str) -> str:
    """Hash relevant file paths and bytes so cached scans invalidate on every edit."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob(pattern)):
        if not path.is_file():
            continue
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _invoke_semgrep(cmd: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run one isolated Semgrep process and reap its whole process group on timeout."""
    proc = subprocess.Popen(  # noqa: S603
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=_SEMGREP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def _run_semgrep(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Run Semgrep with private writable state, retrying one timed-out invocation."""
    last_timeout: subprocess.TimeoutExpired | None = None
    for _attempt in range(_SEMGREP_ATTEMPTS):
        with tempfile.TemporaryDirectory(prefix="pqpatch-semgrep-") as state_dir:
            env = os.environ.copy()
            env.update(
                {
                    "XDG_CONFIG_HOME": state_dir,
                    "SEMGREP_SETTINGS_FILE": str(Path(state_dir) / "settings.yml"),
                    "SEMGREP_LOG_FILE": str(Path(state_dir) / "semgrep.log"),
                    "SEMGREP_SEND_METRICS": "off",
                }
            )
            try:
                return _invoke_semgrep(cmd, env)
            except subprocess.TimeoutExpired as exc:
                last_timeout = exc
    assert last_timeout is not None
    raise last_timeout


def scan_repo(repo_path: Path, *, pack_dir: Path = _PACK_DIR) -> list[RawMatch]:
    """Run the semgrep pack against every Java file under repo_path."""
    if not pack_dir.exists():
        raise SemgrepUnavailableError(f"semgrep pack not found at {pack_dir}")

    cache_key = (
        str(repo_path.resolve()),
        _content_digest(repo_path, "*.java"),
        _content_digest(pack_dir, "*.yml"),
    )
    cached = _SCAN_CACHE.get(cache_key)
    if cached is not None:
        return list(cached)

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
        proc = _run_semgrep(cmd)
    except FileNotFoundError as exc:
        raise SemgrepUnavailableError("semgrep binary not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise SemgrepUnavailableError(f"semgrep timed out scanning {repo_path}") from exc

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        if proc.returncode not in (0, 1):
            raise SemgrepUnavailableError(
                f"semgrep exited {proc.returncode}: {proc.stderr[-500:]}"
            ) from exc
        raise SemgrepUnavailableError(f"could not parse semgrep JSON output: {exc}") from exc

    # PySemgrep 1.169 can return 2 after a successful local scan while still
    # emitting a complete JSON report.  Treat that narrow case as success only
    # when Semgrep itself reports no scan/configuration errors.  Other nonzero
    # statuses remain hard failures, so a broken invocation can never look like
    # a clean scan with zero findings.
    reported_errors = payload.get("errors", [])
    successful_return = proc.returncode in (0, 1) or (
        proc.returncode == 2 and not reported_errors
    )
    if not successful_return:
        details = proc.stderr[-500:] or json.dumps(reported_errors)[-500:]
        raise SemgrepUnavailableError(f"semgrep exited {proc.returncode}: {details}")

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
    _SCAN_CACHE[cache_key] = tuple(matches)
    return matches
