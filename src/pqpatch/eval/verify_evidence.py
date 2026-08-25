"""Non-mutating offline replay of the six ICC trap grids.

For every scored proposal this command reconstructs the versioned prompt,
loads the exact content-addressed response with networking disabled, confirms
that parsing yields the stored diff, and re-runs the recorded verifier layers
plus the L3-only baseline.  It never writes a run directory.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from pqpatch.detector.api import recover_recorded_site
from pqpatch.eval.icc_report import _select_runs
from pqpatch.eval.tables import load_runs
from pqpatch.eval.trap_run import _failing_rule
from pqpatch.eval.traps import load_trap_suite
from pqpatch.extractor.context import extract_context
from pqpatch.model import Context, Layer, Patch, Site, UsageClass, Verdict
from pqpatch.policy import load_policy
from pqpatch.proposer.cache import CacheStore, cache_key
from pqpatch.proposer.prompting import render_prompt
from pqpatch.proposer.response_format import parse_response
from pqpatch.verifier.api import verify_patch

_ROOT = Path(__file__).resolve().parents[3]
_L3_ONLY = frozenset({Layer.L3_BUILD})


class EvidenceVerificationError(RuntimeError):
    """Persisted evidence does not replay under its recorded configuration."""


def _l3_apply_failure(verdict: Verdict) -> bool:
    for report in verdict.layer_reports:
        failure = report.first_failure
        if failure is not None:
            return "does not apply cleanly" in failure.detail
    return False


def verify_icc_evidence(
    *, runs_dir: Path, cache_dir: Path, traps_root: Path, policy_path: Path
) -> dict[str, int]:
    runs = _select_runs(load_runs(runs_dir))
    specs = {spec.trap_id: spec for spec in load_trap_suite(traps_root)}
    policy = load_policy(policy_path)
    cache = CacheStore(cache_dir, offline=True)

    # Legacy rows record stable site ids and usage classes but not file/line.
    # Recover those deterministic fields once per trap from the small fixture,
    # avoiding Semgrep as an unrelated precondition for cache/verifier replay.
    recorded_sites: dict[str, set[tuple[str, str]]] = {}
    for run in runs.values():
        for record in run["records"]:
            if record.get("site_id") and record.get("usage_class"):
                recorded_sites.setdefault(str(record["trap_id"]), set()).add(
                    (str(record["site_id"]), str(record["usage_class"]))
                )
    sites: dict[str, Site] = {}
    contexts: dict[str, Context] = {}
    for trap_id, spec in specs.items():
        identities = recorded_sites.get(trap_id, set())
        if len(identities) != 1:
            raise EvidenceVerificationError(
                f"{trap_id}: expected one recorded site identity, found {sorted(identities)}"
            )
        site_id, usage_class = next(iter(identities))
        site = recover_recorded_site(
            traps_root / spec.scenario_path,
            repo_name=trap_id,
            site_id=site_id,
            usage_class=UsageClass(usage_class),
        )
        if site.usage_class != spec.usage_class:
            raise EvidenceVerificationError(
                f"{trap_id}: recorded usage class {site.usage_class.value!r} "
                f"does not match descriptor {spec.usage_class.value!r}"
            )
        sites[trap_id] = site
        contexts[trap_id] = extract_context(site, repo_root=_ROOT)

    checked = 0
    skipped_error_records = 0
    for run in runs.values():
        manifest = run["manifest"]
        enabled_layers = frozenset(Layer[name] for name in manifest["enabled_layers"])
        for record in run["records"]:
            if record.get("full_status") == "error":
                skipped_error_records += 1
                continue

            trap_id = str(record["trap_id"])
            site = sites[trap_id]
            context = contexts[trap_id]
            prompt = render_prompt(
                context,
                policy,
                feedback=None,
                attempt=1,
                prompt_version=str(manifest["prompt_version"]),
            )
            key = cache_key(
                backend_id=str(manifest["backend_id"]),
                model_version=str(manifest["model_version"]),
                prompt=prompt,
                seed=int(record["seed"]),
            )
            cached = cache.get(key)
            if cached is None:  # offline CacheStore raises first; keeps type narrowing explicit
                raise EvidenceVerificationError(f"{trap_id}: missing cache key {key}")
            raw_hash = hashlib.sha256(cached.raw_text.encode("utf-8")).hexdigest()
            if raw_hash != record.get("response_hash"):
                raise EvidenceVerificationError(
                    f"{trap_id}: response hash mismatch "
                    f"({raw_hash} != {record.get('response_hash')})"
                )
            parsed = parse_response(cached.raw_text)
            if parsed.unified_diff != record.get("unified_diff"):
                raise EvidenceVerificationError(
                    f"{trap_id}: cached response parses to a different diff"
                )

            patch = Patch(
                site_id=site.site_id,
                attempt=1,
                unified_diff=parsed.unified_diff,
                claimed_primitive=parsed.claimed_primitive,
                claimed_parameters=parsed.claimed_parameters,
                backend_id=str(manifest["backend_id"]),
                prompt_version=str(manifest["prompt_version"]),
                response_hash=raw_hash,
            )
            full = verify_patch(patch, site, policy, enabled_layers=enabled_layers)
            rule_id, layer, _unsafe_class, reject_kind = _failing_rule(full)

            # When the full configuration reaches L3, reuse that exact report.
            # L3 is deterministic, so recompiling the same patch would add only
            # runtime while checking no additional evidence.  A full verdict
            # stopped by L1/L2 still needs the independent L3-only baseline.
            if Layer.L3_BUILD in full.layers_evaluated:
                l3_report = next(
                    report for report in full.layer_reports if report.layer is Layer.L3_BUILD
                )
                l3_status = "accept" if l3_report.passed else "reject"
                l3_apply_failure = _l3_apply_failure(full)
            else:
                l3 = verify_patch(patch, site, policy, enabled_layers=_L3_ONLY)
                l3_status = l3.status.value
                l3_apply_failure = _l3_apply_failure(l3)

            observed = {
                "full_status": full.status.value,
                "full_rejected_rule_id": rule_id,
                "full_catch_layer": layer,
                "full_reject_kind": reject_kind,
                "l3_only_status": l3_status,
                "l3_reject_was_apply_failure": l3_apply_failure,
            }
            for field, value in observed.items():
                if record.get(field) != value:
                    raise EvidenceVerificationError(
                        f"{manifest['config_hash']}/{trap_id}: {field} replayed as "
                        f"{value!r}, stored {record.get(field)!r}"
                    )
            checked += 1

    return {
        "runs": len(runs),
        "records_verified": checked,
        "error_records_skipped": skipped_error_records,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", type=Path, default=_ROOT / "runs")
    parser.add_argument(
        "--cache-dir", type=Path, default=_ROOT / "src" / "pqpatch" / "proposer" / "cache"
    )
    parser.add_argument("--traps-root", type=Path, default=_ROOT / "corpus" / "traps")
    parser.add_argument("--policy", type=Path, default=_ROOT / "policy" / "default.yaml")
    args = parser.parse_args(argv)
    result = verify_icc_evidence(
        runs_dir=args.runs_dir,
        cache_dir=args.cache_dir,
        traps_root=args.traps_root,
        policy_path=args.policy,
    )
    print(
        "offline replay verified: "
        f"{result['records_verified']} records across {result['runs']} ICC runs; "
        f"{result['error_records_skipped']} recorded backend error(s) skipped"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
