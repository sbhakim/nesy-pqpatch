"""Generate every ICC evaluation quantity from run evidence.

The report joins six seed-0 trap grids (three models x two prompt arms), their
blind adjudications, and the measured held-out unsafe completions.  It is the
single source for manuscript macros and figure CSVs.  In particular:

* applicability means the content-anchored L3 applier rejected the diff;
  an L2 analysis error or a compilable-but-malformed patch is not relabelled
  as an application failure;
* a symbolic-exclusive catch requires a real rule violation and an L3-only
  ACCEPT on the same proposal;
* RUA is joined to recorded judge votes and cannot be emitted while an
  accepted proposal lacks adjudication.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from pqpatch.eval.adjudicate import (
    AdjudicationError,
    adjudicated_unsafe,
    proposal_id,
    proposal_label_eligible,
    proposal_labels,
)
from pqpatch.eval.metrics import (
    SafetyConfusion,
    cluster_bootstrap_proportion,
    mcnemar_exact_p,
    safety_confusion,
    wilson_ci,
)
from pqpatch.eval.tables import load_runs
from pqpatch.eval.traps import TrapProvenance, TrapSpec, TrapSplit, load_trap_suite

_ROOT = Path(__file__).resolve().parents[3]
_RUNS = _ROOT / "runs"
_TRAPS = _ROOT / "corpus" / "traps"

MODELS: tuple[str, ...] = (
    "gemini-3.1-flash-lite",
    "claude-sonnet-5",
    "deepseek-v4-pro",
)
ARMS: tuple[str, ...] = ("v1", "v2")
MODEL_LABELS: dict[str, str] = {
    "gemini-3.1-flash-lite": "Gemini 3.1 flash-lite",
    "claude-sonnet-5": "Claude Sonnet 5",
    "deepseek-v4-pro": "DeepSeek v4-pro",
}


@dataclass(frozen=True, slots=True)
class CountEstimate:
    successes: int
    n: int
    point: float
    ci_low: float
    ci_high: float


def _count_estimate(successes: int, n: int) -> CountEstimate:
    est = wilson_ci(successes, n)
    return CountEstimate(successes, n, est.point, float(est.ci_low), float(est.ci_high))


def _records(run: dict[str, Any], *, split: str | None = None) -> list[dict[str, Any]]:
    records = [r for r in run["records"] if r.get("full_status") != "error"]
    if split is not None:
        records = [r for r in records if r.get("split") == split]
    return records


def _labels(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    path = run["run_dir"] / "adjudications.json"
    if not path.exists():
        return {}
    loaded: dict[str, dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def _rua_flags(
    run: dict[str, Any], *, split: str | None = None, rule: str = "majority"
) -> list[bool]:
    labels = _labels(run)
    records = _records(run, split=split)
    counts = Counter(str(record["trap_id"]) for record in records)
    flags: list[bool] = []
    for record in records:
        if record.get("full_status") != "accept":
            flags.append(False)
            continue
        trap_id = str(record["trap_id"])
        pid = proposal_id(record, run["manifest"])
        entry = labels.get(pid)
        if entry is None and counts[trap_id] == 1:
            entry = labels.get(trap_id)
        if entry is None:
            raise AdjudicationError(
                f"{run['run_dir']}: accepted proposal {pid!r} has no adjudication"
            )
        flags.append(adjudicated_unsafe(entry, rule=rule))
    return flags


def _estimate_flags(flags: list[bool]) -> CountEstimate:
    return _count_estimate(sum(flags), len(flags))


def _clustered_rua(
    selected: dict[tuple[str, str], dict[str, Any]],
    *,
    split: str | None = None,
) -> dict[str, Any]:
    clusters: dict[str, list[bool]] = {}
    for model in MODELS:
        run = selected[(model, "v2")]
        records = _records(run, split=split)
        flags = _rua_flags(run, split=split, rule="majority")
        for record, flag in zip(records, flags, strict=True):
            clusters.setdefault(str(record["trap_id"]), []).append(flag)
    return asdict(cluster_bootstrap_proportion(clusters))


def _rua_summary(
    selected: dict[tuple[str, str], dict[str, Any]],
    *,
    split: str | None = None,
    trap_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Summarize unconditional RUA and risk among accepted v2 proposals.

    ``trap_ids`` supports the pre-specified held-out construction buckets. The
    same joined records and majority labels feed both rates, so the conditional
    denominator cannot drift from the primary RUA evidence.
    """
    flags: list[bool] = []
    accepted = 0
    for model in MODELS:
        run = selected[(model, "v2")]
        records = _records(run, split=split)
        run_flags = _rua_flags(run, split=split, rule="majority")
        for record, flag in zip(records, run_flags, strict=True):
            if trap_ids is not None and str(record["trap_id"]) not in trap_ids:
                continue
            flags.append(flag)
            accepted += record.get("full_status") == "accept"
    if not flags:
        raise ValueError("RUA summary selected no scored records")
    unsafe = sum(flags)
    return {
        "rua": asdict(_count_estimate(unsafe, len(flags))),
        "accepted": accepted,
        "unsafe_given_accept": (
            asdict(_count_estimate(unsafe, accepted)) if accepted else None
        ),
    }


def _authored_symbolic(specs: list[TrapSpec]) -> dict[str, Any]:
    if not specs:
        raise ValueError("authored symbolic summary selected no traps")
    caught = sum(
        spec.measured_full_verifier == "reject" and not spec.caught_by_l3_alone
        for spec in specs
    )
    return asdict(_count_estimate(caught, len(specs)))


def _consensus_label(entry: dict[str, Any]) -> str | None:
    """Resolved binary expert label; disagreements require a third vote."""
    votes = [
        str(item.get("label"))
        for item in entry.get("labels", [])
        if item.get("label") in {"safe", "unsafe"}
    ]
    if len(votes) < 2:
        return None
    safe = votes.count("safe")
    unsafe = votes.count("unsafe")
    if safe == unsafe:
        return None
    return "unsafe" if unsafe > safe else "safe"


def _rate(successes: int, n: int) -> dict[str, Any] | None:
    return asdict(_count_estimate(successes, n)) if n else None


def _confusion_payload(matrix: SafetyConfusion) -> dict[str, Any]:
    return {
        "true_positive": matrix.true_positive,
        "false_positive": matrix.false_positive,
        "false_negative": matrix.false_negative,
        "true_negative": matrix.true_negative,
        "n_binary": matrix.n_binary,
        "abstained": matrix.abstained,
        "sensitivity": _rate(
            matrix.true_positive, matrix.true_positive + matrix.false_negative
        ),
        "specificity": _rate(
            matrix.true_negative, matrix.true_negative + matrix.false_positive
        ),
        "precision": _rate(
            matrix.true_positive, matrix.true_positive + matrix.false_positive
        ),
        "unsafe_given_accept": _rate(
            matrix.false_negative, matrix.false_negative + matrix.true_negative
        ),
    }


def _proposal_safety_report(
    selected: dict[tuple[str, str], dict[str, Any]]
) -> dict[str, Any]:
    rows: list[tuple[dict[str, Any], str | None]] = []
    entries_present = 0
    for model in MODELS:
        run = selected[(model, "v2")]
        stored = proposal_labels(run["run_dir"])
        for record in _records(run):
            if not proposal_label_eligible(record):
                continue
            entry = stored.get(proposal_id(record, run["manifest"]))
            if entry is not None:
                entries_present += 1
            rows.append((record, _consensus_label(entry) if entry else None))

    eligible = len(rows)
    consensus = sum(label is not None for _, label in rows)
    report: dict[str, Any] = {
        "population": "v2 proposals accepted by L3",
        "eligible": eligible,
        "entries_present": entries_present,
        "consensus_binary": consensus,
        "coverage": consensus / eligible if eligible else None,
        "status": (
            "not-applicable"
            if not eligible
            else "complete"
            if consensus == eligible
            else "pending-neutral-labels"
        ),
        "pipeline_action_confusion": None,
        "rule_detection_confusion": None,
        "end_to_end_unsafe_accept": None,
    }
    # Partial labels are vulnerable to selection bias and are never promoted
    # into a primary effect estimate.
    if not eligible or consensus != eligible:
        return report

    labels = [str(label) for _, label in rows]
    action = safety_confusion(
        [record.get("full_status") != "accept" for record, _ in rows], labels
    )
    detection = safety_confusion(
        [_genuine_symbolic(record) for record, _ in rows], labels
    )
    total_v2 = sum(len(_records(selected[(model, "v2")])) for model in MODELS)
    report["pipeline_action_confusion"] = _confusion_payload(action)
    report["rule_detection_confusion"] = _confusion_payload(detection)
    report["end_to_end_unsafe_accept"] = _rate(action.false_negative, total_v2)
    return report


def _select_runs(all_runs: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    selected: dict[tuple[str, str], dict[str, Any]] = {}
    for run in all_runs:
        manifest = run["manifest"]
        if manifest.get("kind") != "trap-run" or manifest.get("corpus_id") != "traps/all":
            continue
        model = manifest.get("model_version")
        arm = manifest.get("prompt_version")
        if model not in MODELS or arm not in ARMS or manifest.get("seeds") != [0]:
            continue
        key = (str(model), str(arm))
        if key in selected:
            raise ValueError(
                f"duplicate ICC run for {key}: "
                f"{selected[key]['run_dir']} and {run['run_dir']}"
            )
        selected[key] = run
    missing = [(model, arm) for model in MODELS for arm in ARMS if (model, arm) not in selected]
    if missing:
        raise ValueError(f"missing seed-0 ICC trap runs: {missing}")
    return selected


def _application_flags(run: dict[str, Any]) -> dict[tuple[str, int], bool]:
    return {
        (str(r["trap_id"]), int(r["seed"])): bool(r.get("l3_reject_was_apply_failure"))
        for r in _records(run)
    }


def _mcnemar(v1: dict[str, Any], v2: dict[str, Any]) -> dict[str, float | int]:
    before = _application_flags(v1)
    after = _application_flags(v2)
    paired = sorted(before.keys() & after.keys())
    b = sum(before[key] and not after[key] for key in paired)
    c = sum(not before[key] and after[key] for key in paired)
    return {"n": len(paired), "b": b, "c": c, "p": mcnemar_exact_p(b, c)}


def _genuine_symbolic(record: dict[str, Any]) -> bool:
    return (
        record.get("full_reject_kind") == "rule-violation"
        and record.get("l3_only_status") == "accept"
    )


def build_report(
    *, runs_dir: Path = _RUNS, traps_root: Path = _TRAPS
) -> dict[str, Any]:
    selected = _select_runs(load_runs(runs_dir))

    applicability_rows: list[dict[str, Any]] = []
    rua_rows: list[dict[str, Any]] = []
    for model in MODELS:
        for arm in ARMS:
            run = selected[(model, arm)]
            records = _records(run)
            apply = _estimate_flags(
                [bool(r.get("l3_reject_was_apply_failure")) for r in records]
            )
            applicability_rows.append(
                {"model": model, "arm": arm, "run": run["manifest"]["config_hash"], **asdict(apply)}
            )
            for rule in ("majority", "any"):
                rua = _estimate_flags(_rua_flags(run, rule=rule))
                rua_rows.append(
                    {"model": model, "arm": arm, "rule": rule, **asdict(rua)}
                )

    pooled_apply: dict[str, dict[str, Any]] = {}
    pooled_rua: dict[str, dict[str, dict[str, Any]]] = {}
    for arm in ARMS:
        apply_flags = [
            bool(r.get("l3_reject_was_apply_failure"))
            for model in MODELS
            for r in _records(selected[(model, arm)])
        ]
        pooled_apply[arm] = asdict(_estimate_flags(apply_flags))
        pooled_rua[arm] = {}
        for rule in ("majority", "any"):
            flags = [
                flag
                for model in MODELS
                for flag in _rua_flags(selected[(model, arm)], rule=rule)
            ]
            pooled_rua[arm][rule] = asdict(_estimate_flags(flags))

    heldout_specs = [
        spec for spec in load_trap_suite(traps_root) if spec.split is TrapSplit.HELDOUT
    ]
    rule_targeted_specs = [
        spec
        for spec in heldout_specs
        if spec.provenance is TrapProvenance.TAXONOMY and spec.target_rule is not None
    ]
    external_specs = [
        spec
        for spec in heldout_specs
        if spec.provenance is TrapProvenance.EXTERNAL_CVE
    ]
    bucket_ids = {spec.trap_id for spec in rule_targeted_specs + external_specs}
    if bucket_ids != {spec.trap_id for spec in heldout_specs}:
        raise ValueError(
            "held-out traps must belong to exactly one report bucket: "
            "rule-targeted taxonomy or external provenance"
        )

    pooled_v2_summary = _rua_summary(selected)
    heldout_v2_summary = _rua_summary(selected, split=TrapSplit.HELDOUT.value)
    heldout_buckets = {
        "rule_targeted": {
            "n_traps": len(rule_targeted_specs),
            "authored_symbolic": _authored_symbolic(rule_targeted_specs),
            "proposal": _rua_summary(
                selected,
                split=TrapSplit.HELDOUT.value,
                trap_ids={spec.trap_id for spec in rule_targeted_specs},
            ),
        },
        "external": {
            "n_traps": len(external_specs),
            "authored_symbolic": _authored_symbolic(external_specs),
            "proposal": _rua_summary(
                selected,
                split=TrapSplit.HELDOUT.value,
                trap_ids={spec.trap_id for spec in external_specs},
            ),
        },
    }

    real_records = [
        record for model in MODELS for record in _records(selected[(model, "v2")])
    ]
    real_symbolic = sum(_genuine_symbolic(record) for record in real_records)
    application_rejected = sum(
        bool(record.get("l3_reject_was_apply_failure")) for record in real_records
    )
    compile_rejected = sum(
        record.get("l3_only_status") != "accept"
        and not record.get("l3_reject_was_apply_failure")
        for record in real_records
    )
    real_rua_flags = [
        flag
        for model in MODELS
        for flag in _rua_flags(selected[(model, "v2")], rule="majority")
    ]
    real_unsafe = sum(real_rua_flags)
    real_accepted = sum(record.get("full_status") == "accept" for record in real_records)

    authored = _authored_symbolic(heldout_specs)

    return {
        "schema_version": 3,
        "design": {
            "models": list(MODELS),
            "arms": list(ARMS),
            "draw_id": "legacy-seed:0",
            "unit_of_clustering": "trap_id",
        },
        "applicability": {
            "rows": applicability_rows,
            "pooled": pooled_apply,
            "mcnemar": {
                model: _mcnemar(selected[(model, "v1")], selected[(model, "v2")])
                for model in MODELS
            },
        },
        "rua": {
            "rows": rua_rows,
            "pooled": pooled_rua,
            "heldout_v2_majority": heldout_v2_summary["rua"],
            "unsafe_given_accept": {
                "pooled_v2_majority": pooled_v2_summary["unsafe_given_accept"],
                "heldout_v2_majority": heldout_v2_summary["unsafe_given_accept"],
            },
            "clustered": {
                "pooled_v2_majority": _clustered_rua(selected),
                "heldout_v2_majority": _clustered_rua(
                    selected, split=TrapSplit.HELDOUT.value
                ),
            },
        },
        "heldout_buckets": heldout_buckets,
        "proposal_safety": _proposal_safety_report(selected),
        "validity_gap": {
            "authored": {
                **authored,
                "application_rejected": 0,
                "compile_rejected": 0,
                "accepted_safe_or_missed": len(heldout_specs) - authored["successes"],
                "accepted_unsafe": 0,
            },
            "real": {
                **asdict(_count_estimate(real_symbolic, len(real_records))),
                "application_rejected": application_rejected,
                "compile_rejected": compile_rejected,
                "accepted_safe_or_missed": real_accepted - real_unsafe,
                "accepted_unsafe": real_unsafe,
            },
        },
    }


def _pct(value: float, digits: int = 1) -> str:
    return f"{100 * value:.{digits}f}"


def _write_macros(report: dict[str, Any], path: Path) -> None:
    rows = {(row["model"], row["arm"]): row for row in report["applicability"]["rows"]}
    rua_rows = {
        (row["model"], row["arm"], row["rule"]): row for row in report["rua"]["rows"]
    }
    pooled_apply = report["applicability"]["pooled"]
    pooled_rua = report["rua"]["pooled"]
    heldout = report["rua"]["heldout_v2_majority"]
    clustered = report["rua"]["clustered"]
    conditional = report["rua"]["unsafe_given_accept"]
    buckets = report["heldout_buckets"]
    authored = report["validity_gap"]["authored"]
    real = report["validity_gap"]["real"]

    if (
        conditional["pooled_v2_majority"] is None
        or conditional["heldout_v2_majority"] is None
    ):
        raise ValueError("ICC report requires accepted v2 proposals for conditional risk")

    rule_authored = buckets["rule_targeted"]["authored_symbolic"]
    external_authored = buckets["external"]["authored_symbolic"]
    rule_rua = buckets["rule_targeted"]["proposal"]["rua"]
    external_rua = buckets["external"]["proposal"]["rua"]
    heldout_conditional = conditional["heldout_v2_majority"]
    pooled_conditional = conditional["pooled_v2_majority"]

    values = {
        "ICCApplyVOnePooled": _pct(pooled_apply["v1"]["point"]),
        "ICCApplyVTwoPooled": _pct(pooled_apply["v2"]["point"]),
        "ICCApplyVOneCount": str(pooled_apply["v1"]["successes"]),
        "ICCApplyVOneTotal": str(pooled_apply["v1"]["n"]),
        "ICCApplyVTwoCount": str(pooled_apply["v2"]["successes"]),
        "ICCApplyVTwoTotal": str(pooled_apply["v2"]["n"]),
        "ICCApplyVOneGemini": _pct(rows[(MODELS[0], "v1")]["point"]),
        "ICCApplyVTwoGemini": _pct(rows[(MODELS[0], "v2")]["point"]),
        "ICCApplyVOneSonnet": _pct(rows[(MODELS[1], "v1")]["point"]),
        "ICCApplyVTwoSonnet": _pct(rows[(MODELS[1], "v2")]["point"]),
        "ICCApplyVOneDeepSeek": _pct(rows[(MODELS[2], "v1")]["point"]),
        "ICCApplyVTwoDeepSeek": _pct(rows[(MODELS[2], "v2")]["point"]),
        "ICCRUAVOneMajority": _pct(pooled_rua["v1"]["majority"]["point"]),
        "ICCRUAVTwoMajority": _pct(pooled_rua["v2"]["majority"]["point"]),
        "ICCRUAVTwoAny": _pct(pooled_rua["v2"]["any"]["point"]),
        "ICCRUAVTwoMajorityCount": str(pooled_rua["v2"]["majority"]["successes"]),
        "ICCRUAVTwoMajorityTotal": str(pooled_rua["v2"]["majority"]["n"]),
        "ICCRUAVTwoAnyCount": str(pooled_rua["v2"]["any"]["successes"]),
        "ICCRUAVTwoMajorityLow": _pct(pooled_rua["v2"]["majority"]["ci_low"], 0),
        "ICCRUAVTwoMajorityHigh": _pct(pooled_rua["v2"]["majority"]["ci_high"], 0),
        "ICCRUAHeldout": _pct(heldout["point"]),
        "ICCRUAHeldoutCount": str(heldout["successes"]),
        "ICCRUAHeldoutTotal": str(heldout["n"]),
        "ICCRUAHeldoutLow": _pct(heldout["ci_low"], 1),
        "ICCRUAHeldoutHigh": _pct(heldout["ci_high"], 1),
        "ICCRUAHeldoutClusterLow": _pct(
            clustered["heldout_v2_majority"]["ci_low"], 1
        ),
        "ICCRUAHeldoutClusterHigh": _pct(
            clustered["heldout_v2_majority"]["ci_high"], 1
        ),
        "ICCRUAVTwoClusterLow": _pct(
            clustered["pooled_v2_majority"]["ci_low"], 1
        ),
        "ICCRUAVTwoClusterHigh": _pct(
            clustered["pooled_v2_majority"]["ci_high"], 1
        ),
        "ICCRUAVTwoGemini": _pct(rua_rows[(MODELS[0], "v2", "majority")]["point"]),
        "ICCRUAVTwoSonnet": _pct(rua_rows[(MODELS[1], "v2", "majority")]["point"]),
        "ICCRUAVTwoDeepSeek": _pct(rua_rows[(MODELS[2], "v2", "majority")]["point"]),
        "ICCRealSymbolicCount": str(real["successes"]),
        "ICCRealTotal": str(real["n"]),
        "ICCRealSymbolicPct": _pct(real["point"]),
        "ICCAuthoredSymbolicCount": str(authored["successes"]),
        "ICCAuthoredTotal": str(authored["n"]),
        "ICCAuthoredSymbolicPct": _pct(authored["point"]),
        "ICCAuthoredRuleBucketCount": str(rule_authored["successes"]),
        "ICCAuthoredRuleBucketTotal": str(rule_authored["n"]),
        "ICCAuthoredRuleBucketPct": _pct(rule_authored["point"]),
        "ICCAuthoredExternalBucketCount": str(external_authored["successes"]),
        "ICCAuthoredExternalBucketTotal": str(external_authored["n"]),
        "ICCAuthoredExternalBucketPct": _pct(external_authored["point"]),
        "ICCRUARuleBucketCount": str(rule_rua["successes"]),
        "ICCRUARuleBucketTotal": str(rule_rua["n"]),
        "ICCRUARuleBucketPct": _pct(rule_rua["point"]),
        "ICCRUAExternalBucketCount": str(external_rua["successes"]),
        "ICCRUAExternalBucketTotal": str(external_rua["n"]),
        "ICCRUAExternalBucketPct": _pct(external_rua["point"]),
        "ICCUnsafeAcceptedHeldoutCount": str(heldout_conditional["successes"]),
        "ICCUnsafeAcceptedHeldoutTotal": str(heldout_conditional["n"]),
        "ICCUnsafeAcceptedHeldoutPct": _pct(heldout_conditional["point"]),
        "ICCUnsafeAcceptedFullCount": str(pooled_conditional["successes"]),
        "ICCUnsafeAcceptedFullTotal": str(pooled_conditional["n"]),
        "ICCUnsafeAcceptedFullPct": _pct(pooled_conditional["point"]),
        "ICCMcNemarGemini": f"{report['applicability']['mcnemar'][MODELS[0]]['p']:.3f}",
        "ICCMcNemarSonnet": f"{report['applicability']['mcnemar'][MODELS[1]]['p']:.5f}",
        "ICCMcNemarDeepSeek": f"{report['applicability']['mcnemar'][MODELS[2]]['p']:.2f}",
    }
    lines = ["% Generated by python -m pqpatch.eval.icc_report; do not edit."]
    lines.extend(f"\\newcommand{{\\{name}}}{{{value}}}" for name, value in values.items())
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_report(report: dict[str, Any], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "icc_results.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    independence = out_dir / "independence.csv"
    app_rows = {(row["model"], row["arm"]): row for row in report["applicability"]["rows"]}
    rua = report["rua"]["pooled"]
    with independence.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("label", "v1", "v2", "kind"))
        writer.writeheader()
        for model in reversed(MODELS):
            writer.writerow(
                {
                    "label": MODEL_LABELS[model],
                    "v1": _pct(app_rows[(model, "v1")]["point"]),
                    "v2": _pct(app_rows[(model, "v2")]["point"]),
                    "kind": "applicability",
                }
            )
        writer.writerow(
            {
                "label": "Pooled",
                "v1": _pct(report["applicability"]["pooled"]["v1"]["point"]),
                "v2": _pct(report["applicability"]["pooled"]["v2"]["point"]),
                "kind": "applicability",
            }
        )
        writer.writerow(
            {
                "label": "Residual unsafe accepts",
                "v1": _pct(rua["v1"]["majority"]["point"]),
                "v2": _pct(rua["v2"]["majority"]["point"]),
                "kind": "rua",
            }
        )

    validity = out_dir / "validity_gap.csv"
    with validity.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "distribution",
                "n",
                "symbolic_exclusive",
                "application_rejected",
                "compile_rejected",
                "accepted_safe_or_missed",
                "accepted_unsafe",
            ),
        )
        writer.writeheader()
        for key, label in (("real", "Real proposals"), ("authored", "Authored unsafe")):
            row = report["validity_gap"][key]
            writer.writerow(
                {
                    "distribution": label,
                    "n": row["n"],
                    "symbolic_exclusive": row["successes"],
                    "application_rejected": row["application_rejected"],
                    "compile_rejected": row["compile_rejected"],
                    "accepted_safe_or_missed": row["accepted_safe_or_missed"],
                    "accepted_unsafe": row["accepted_unsafe"],
                }
            )

    macros = out_dir / "icc_results.tex"
    _write_macros(report, macros)
    return [json_path, independence, validity, macros]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", type=Path, default=_RUNS)
    parser.add_argument("--traps-root", type=Path, default=_TRAPS)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    report = build_report(runs_dir=args.runs_dir, traps_root=args.traps_root)
    for path in write_report(report, args.out_dir):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
