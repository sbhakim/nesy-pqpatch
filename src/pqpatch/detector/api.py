"""Detector entry point: repository path in, classified Site objects out."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path

from pqpatch.detector.classify import classify
from pqpatch.detector.engine import RawMatch, scan_repo
from pqpatch.model import Site, UsageClass

_DETECTOR_RULE_IDS = (
    "pq-detect-keypairgenerator",
    "pq-detect-signature",
    "pq-detect-cipher-envelope",
    "pq-detect-keyagreement",
)


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


def _sites_from_matches(matches: Sequence[RawMatch], *, repo_name: str) -> list[Site]:
    """Classify already-scanned matches under a stable repository identity.

    This keeps classification identical while allowing an evaluation suite to
    scan a shared corpus root once and partition its matches by scenario.
    """
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
                    site_id=_site_id(repo_name, file_path, m.line, m.rule_id),
                    repo=repo_name,
                    file_path=file_path,
                    line=m.line,
                    usage_class=usage_class,
                    matched_symbol=_matched_symbol(m.rule_id),
                    detector_rule_id=m.rule_id,
                )
            )
    return sites


def detect(repo_path: Path, *, repo_name: str | None = None) -> list[Site]:
    """Scan repo_path and return classified sites. A failed scan raises
    SemgrepUnavailableError; it is never reported as zero findings."""
    return _sites_from_matches(
        scan_repo(repo_path), repo_name=repo_name or repo_path.name
    )


def recover_recorded_site(
    repo_path: Path,
    *,
    repo_name: str,
    site_id: str,
    usage_class: UsageClass,
) -> Site:
    """Recover legacy site provenance from its deterministic recorded id.

    Older run rows stored the site id and usage class but omitted file, line,
    and detector rule. Enumerating the small scenario source reconstructs those
    fields without rerunning Semgrep. Prompt/cache and verifier replay still
    fail if the underlying source bytes have drifted.
    """
    for path in sorted(repo_path.rglob("*.java")):
        absolute = path.resolve()
        line_count = len(absolute.read_text(encoding="utf-8").splitlines())
        for line in range(1, line_count + 1):
            for rule_id in _DETECTOR_RULE_IDS:
                if _site_id(repo_name, str(absolute), line, rule_id) == site_id:
                    return Site(
                        site_id=site_id,
                        repo=repo_name,
                        file_path=str(absolute),
                        line=line,
                        usage_class=usage_class,
                        matched_symbol=_matched_symbol(rule_id),
                        detector_rule_id=rule_id,
                    )
    raise ValueError(f"could not recover recorded site {site_id!r} under {repo_path}")
