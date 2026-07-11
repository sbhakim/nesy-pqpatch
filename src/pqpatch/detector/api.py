"""Detector entry point: repository path in, classified Site objects out."""

from __future__ import annotations

import hashlib
from pathlib import Path

from pqpatch.detector.classify import classify
from pqpatch.detector.engine import RawMatch, scan_repo
from pqpatch.model import Site


def _site_id(repo: str, file_path: str, line: int, rule_id: str) -> str:
    """Deterministic identifier: stable across re-runs and machines."""
    digest = hashlib.sha256(f"{repo}:{file_path}:{line}:{rule_id}".encode()).hexdigest()
    return f"site-{digest[:16]}"


def _matched_symbol(rule_id: str) -> str:
    return {
        "pq-detect-keypairgenerator": "KeyPairGenerator.getInstance",
        "pq-detect-signature": "Signature.getInstance",
        "pq-detect-cipher-envelope": "Cipher.getInstance",
        "pq-detect-keyagreement": "KeyAgreement.getInstance",
    }.get(rule_id, rule_id)


def detect(repo_path: Path, *, repo_name: str | None = None) -> list[Site]:
    """Scan repo_path and return classified sites. A failed scan raises
    SemgrepUnavailableError; it is never reported as zero findings."""
    repo = repo_name or repo_path.name
    matches: list[RawMatch] = scan_repo(repo_path)

    # Group by file so each source file is read and split exactly once.
    by_file: dict[str, list[RawMatch]] = {}
    for m in matches:
        by_file.setdefault(m.file_path, []).append(m)

    sites: list[Site] = []
    for file_path, file_matches in by_file.items():
        source_lines = Path(file_path).read_text(encoding="utf-8").splitlines()
        for m in file_matches:
            usage_class = classify(m, source_lines)
            sites.append(
                Site(
                    site_id=_site_id(repo, file_path, m.line, m.rule_id),
                    repo=repo,
                    file_path=file_path,
                    line=m.line,
                    usage_class=usage_class,
                    matched_symbol=_matched_symbol(m.rule_id),
                    detector_rule_id=m.rule_id,
                )
            )
    return sites
