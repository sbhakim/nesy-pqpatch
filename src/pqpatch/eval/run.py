"""Experiment orchestrator: drive a proposer backend over a corpus app and
persist an immutable run under ``runs/<config-hash>/``.

Every reported number regenerates from what this writes -- eval/tables.py reads
these manifests and nothing else. A run directory is content-addressed by its
*configuration* (backend, model, seeds, k, enabled layers, corpus, and the
prompt, rule, and policy versions), so re-running the same configuration
overwrites in place instead of piling up duplicates, and a different one lands
in its own directory.

Per-site records embed the canonical decision trace, so a run is independently
auditable and re-verifiable offline without the model. A backend or network
failure on one site is recorded as an ``error`` record, never allowed to abort
the whole grid.
"""

from __future__ import annotations

import hashlib
import json
import subprocess  # noqa: S404 -- fixed argv, no shell, bounded timeout
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pqpatch.detector.api import detect
from pqpatch.extractor.context import extract_context
from pqpatch.loop import DEFAULT_K, migrate_site
from pqpatch.model import Layer, Policy, Verdict
from pqpatch.proposer.base import Backend
from pqpatch.proposer.cache import request_spec_digest
from pqpatch.trace.canonical import to_canonical_json
from pqpatch.verifier.api import DEFAULT_ENABLED_LAYERS


def _git_sha(repo_root: Path) -> str:
    try:
        proc = subprocess.run(  # noqa: S603
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return proc.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _git_provenance(repo_root: Path) -> dict[str, str | bool]:
    """Identify the exact tracked/untracked working-tree snapshot used.

    A commit SHA alone is insufficient when an experiment runs from a dirty
    tree.  Hash every tracked and non-ignored untracked file, including its
    relative path, so a later archive can prove which bytes produced a run.
    Ignored evidence directories are excluded by ``git ls-files`` itself.
    """
    sha = _git_sha(repo_root)
    try:
        status = subprocess.run(  # noqa: S603
            ["git", "-C", str(repo_root), "status", "--porcelain=v1"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        listed = subprocess.run(  # noqa: S603, S607
            [  # noqa: S607
                "git",
                "-C",
                str(repo_root),
                "ls-files",
                "-co",
                "--exclude-standard",
                "-z",
            ],
            capture_output=True,
            timeout=10,
            check=False,
        )
        digest = hashlib.sha256()
        for raw_path in sorted(path for path in listed.stdout.split(b"\0") if path):
            path = repo_root / raw_path.decode("utf-8")
            if not path.is_file():
                continue
            digest.update(raw_path)
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
        return {
            "git_sha": sha,
            "git_dirty": bool(status.stdout.strip()),
            "worktree_sha256": digest.hexdigest(),
        }
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError):
        return {"git_sha": sha, "git_dirty": True, "worktree_sha256": "unknown"}


def config_hash(
    *,
    backend_id: str,
    model_version: str,
    seeds: Sequence[int],
    k: int,
    enabled_layers: frozenset[Layer],
    corpus_id: str,
    prompt_version: str,
    ruleset_version: str,
    policy_version: str,
    l1_mode: str = "pq",
    feedback_mode: str = "rule",
    request_spec_sha256: str = "legacy-unknown",
) -> str:
    """Stable 16-hex digest of the run configuration. Deliberately excludes
    timestamps and git sha so the same experiment always maps to the same
    directory. Every knob that changes pipeline behavior must appear here --
    omitting one would let two different experiments collide into one
    directory (this bit ablation arms before the shakeout run caught it)."""
    payload = {
        "backend_id": backend_id,
        "model_version": model_version,
        "seeds": sorted(seeds),
        "k": k,
        "enabled_layers": sorted(layer.name for layer in enabled_layers),
        "corpus_id": corpus_id,
        "prompt_version": prompt_version,
        "ruleset_version": ruleset_version,
        "policy_version": policy_version,
        "l1_mode": l1_mode,
        "feedback_mode": feedback_mode,
        "request_spec_sha256": request_spec_sha256,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _catch_layer(verdict: Verdict) -> str | None:
    """The layer whose rule first rejected the last attempt, or None on accept."""
    for report in verdict.layer_reports:
        if report.first_failure is not None:
            return report.layer.name
    return None


def run_config(
    *,
    app_dir: Path,
    corpus_id: str,
    backend: Backend,
    policy: Policy,
    runs_dir: Path,
    repo_root: Path,
    seeds: Sequence[int] = (0,),
    k: int = DEFAULT_K,
    enabled_layers: frozenset[Layer] = DEFAULT_ENABLED_LAYERS,
    prompt_version: str = "v1",
    ruleset_version: str = "rules-v1.0",
    offline: bool = False,
    l1_mode: str = "pq",
    feedback_mode: str = "rule",
    ablation: str | None = None,
) -> Path:
    """Run one (backend, model, corpus) configuration across all detected sites
    and seeds; write the manifest and per-site records; return the run dir.
    `ablation` is a human-readable arm name recorded in the manifest; the
    behavioral knobs themselves are the explicit parameters."""
    src_dir = app_dir / "src"
    sites = sorted(detect(src_dir, repo_name=app_dir.name), key=lambda s: (s.file_path, s.line))

    request_spec = backend.request_spec()
    request_sha = request_spec_digest(request_spec)
    chash = config_hash(
        backend_id=backend.backend_id,
        model_version=backend.model_version,
        seeds=seeds,
        k=k,
        enabled_layers=enabled_layers,
        corpus_id=corpus_id,
        prompt_version=prompt_version,
        ruleset_version=ruleset_version,
        policy_version=policy.version,
        l1_mode=l1_mode,
        feedback_mode=feedback_mode,
        request_spec_sha256=request_sha,
    )
    run_dir = runs_dir / chash
    sites_dir = run_dir / "sites"
    sites_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    for site in sites:
        context = extract_context(site, repo_root=repo_root)
        for seed in seeds:
            try:
                verdict, trace = migrate_site(
                    site,
                    context,
                    policy,
                    backend,
                    k=k,
                    enabled_layers=enabled_layers,
                    prompt_version=prompt_version,
                    seed=seed,
                    ruleset_version=ruleset_version,
                    l1_mode=l1_mode,
                    feedback_mode=feedback_mode,
                )
                record: dict[str, Any] = {
                    "site_id": site.site_id,
                    "usage_class": site.usage_class.value,
                    "seed": seed,
                    "status": verdict.status.value,
                    "rejected_rule_id": verdict.rejected_rule_id,
                    "attempts_used": verdict.attempts_used,
                    "layers_evaluated": [layer.name for layer in verdict.layers_evaluated],
                    "catch_layer": _catch_layer(verdict),
                    "trace": json.loads(to_canonical_json(trace)),
                }
            except Exception as exc:  # noqa: BLE001 -- one site's failure is a
                # recorded error, never a crashed grid
                record = {
                    "site_id": site.site_id,
                    "usage_class": site.usage_class.value,
                    "seed": seed,
                    "status": "error",
                    "rejected_rule_id": None,
                    "attempts_used": 0,
                    "layers_evaluated": [],
                    "catch_layer": None,
                    "error": repr(exc),
                }
            out = sites_dir / f"{site.site_id}__seed{seed}.json"
            out.write_text(json.dumps(record, indent=2, sort_keys=True))
            records.append(record)

    manifest = {
        "config_hash": chash,
        "corpus_id": corpus_id,
        "app": app_dir.name,
        "backend_id": backend.backend_id,
        "model_version": backend.model_version,
        "request_spec": request_spec,
        "request_spec_sha256": request_sha,
        "draw_semantics": (
            "provider-seeded" if request_spec.get("seed_supported") else "requested-draw"
        ),
        "seeds": list(seeds),
        "k": k,
        "enabled_layers": sorted(layer.name for layer in enabled_layers),
        "prompt_version": prompt_version,
        "ruleset_version": ruleset_version,
        "policy_version": policy.version,
        "l1_mode": l1_mode,
        "feedback_mode": feedback_mode,
        "ablation": ablation,
        "offline": offline,
        **_git_provenance(repo_root),
        "created_at_utc": datetime.now(UTC).isoformat(),
        "n_sites": len(sites),
        "n_records": len(records),
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return run_dir
