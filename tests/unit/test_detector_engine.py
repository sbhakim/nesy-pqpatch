"""Unit tests for Semgrep process-result handling."""

from __future__ import annotations

import json
import os
import signal
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from pqpatch.detector.engine import (
    _SCAN_CACHE,
    SemgrepUnavailableError,
    _invoke_semgrep,
    _run_semgrep,
    scan_repo,
)


def _completed(
    returncode: int, payload: dict[str, object], stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["semgrep"], returncode=returncode, stdout=json.dumps(payload), stderr=stderr
    )


def test_accepts_pysemgrep_exit_two_with_valid_error_free_json(tmp_path: Path) -> None:
    payload = {
        "results": [
            {
                "check_id": "pack.pq-detect-signature",
                "path": "Example.java",
                "start": {"line": 7},
                "end": {"line": 7},
            }
        ],
        "errors": [],
    }

    with patch("pqpatch.detector.engine._run_semgrep", return_value=_completed(2, payload)):
        matches = scan_repo(tmp_path, pack_dir=tmp_path)

    assert len(matches) == 1
    assert matches[0].rule_id == "pq-detect-signature"


def test_rejects_exit_two_when_semgrep_reports_errors(tmp_path: Path) -> None:
    payload = {"results": [], "errors": [{"message": "invalid rule"}]}

    with (
        patch("pqpatch.detector.engine._run_semgrep", return_value=_completed(2, payload)),
        pytest.raises(SemgrepUnavailableError, match="invalid rule"),
    ):
        scan_repo(tmp_path, pack_dir=tmp_path)


def test_rejects_other_nonzero_exit_even_with_error_free_json(tmp_path: Path) -> None:
    payload = {"results": [], "errors": []}

    with (
        patch("pqpatch.detector.engine._run_semgrep", return_value=_completed(3, payload)),
        pytest.raises(SemgrepUnavailableError, match="semgrep exited 3"),
    ):
        scan_repo(tmp_path, pack_dir=tmp_path)


def test_scan_cache_reuses_unchanged_inputs_and_invalidates_on_edit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    pack = tmp_path / "pack"
    repo.mkdir()
    pack.mkdir()
    source = repo / "Example.java"
    source.write_text("class Example {}\n")
    (pack / "rules.yml").write_text("rules: []\n")
    completed = _completed(2, {"results": [], "errors": []})
    _SCAN_CACHE.clear()

    with patch("pqpatch.detector.engine._run_semgrep", return_value=completed) as run:
        scan_repo(repo, pack_dir=pack)
        scan_repo(repo, pack_dir=pack)
        source.write_text("class Example { int changed; }\n")
        scan_repo(repo, pack_dir=pack)

    assert run.call_count == 2


def test_run_semgrep_uses_private_writable_state_and_retries_timeout() -> None:
    completed = _completed(2, {"results": [], "errors": []})
    seen_environments: list[dict[str, str]] = []

    def invoke(_cmd: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        seen_environments.append(env)
        if len(seen_environments) == 1:
            raise subprocess.TimeoutExpired(_cmd, 120)
        return completed

    with patch("pqpatch.detector.engine._invoke_semgrep", side_effect=invoke):
        assert _run_semgrep(["semgrep"]) is completed

    assert len(seen_environments) == 2
    for env in seen_environments:
        assert env["SEMGREP_SEND_METRICS"] == "off"
        assert env["SEMGREP_SETTINGS_FILE"].startswith(env["XDG_CONFIG_HOME"])
        assert env["SEMGREP_LOG_FILE"].startswith(env["XDG_CONFIG_HOME"])
    assert seen_environments[0]["XDG_CONFIG_HOME"] != seen_environments[1]["XDG_CONFIG_HOME"]


def test_invoke_semgrep_kills_process_group_on_timeout() -> None:
    process = _FakeProcess()

    with (
        patch("pqpatch.detector.engine.subprocess.Popen", return_value=process),
        patch("pqpatch.detector.engine.os.killpg") as killpg,
        pytest.raises(subprocess.TimeoutExpired),
    ):
        _invoke_semgrep(["semgrep"], os.environ.copy())

    killpg.assert_called_once_with(4321, signal.SIGKILL)


class _FakeProcess:
    pid = 4321
    returncode = -signal.SIGKILL

    def __init__(self) -> None:
        self.calls = 0

    def communicate(self, timeout: int | None = None) -> tuple[str, str]:
        self.calls += 1
        if self.calls == 1:
            raise subprocess.TimeoutExpired(["semgrep"], timeout)
        return "", ""
