# ADR-004: Evaluation-robustness upgrades (U-A … U-F)

**Status:** accepted; partially implemented (see the ledger below)
**Date:** 2026-07-12

## Context

A pre-run adversarial critique of the design (`refined_defined_plan.md` §12)
identified six ways the headline result — the residual unsafe-accept rate (RUA)
and the "symbolic layer catches what compile+test misses" claim — could be
attacked as inflated or underpowered. This ADR records what was implemented in
code now versus what is deferred, and why deferral is honest rather than a gap
papered over.

The governing principle is unchanged from ADR-002 and `docs/STATUS.md`: a
documented deferral does not outrank an honest status page. Nothing here reports
a number; these are apparatus changes that make future numbers defensible.

## Decision — ledger

| Id | Upgrade | State | Where |
|----|---------|-------|-------|
| U-A | L3 becomes a real multi-file project build + the project's own tests, single-file compile only as a labelled fallback | **Implemented** | `verifier/l3_build.py`, seed app `build.yaml` + `HexCodec`/`SignatureManifest`/`RegressionTests`, `tests/integration/test_l3_build.py`; supersedes ADR-002 in part |
| U-B | Co-primary RUA (held-out + full suite) with CI half-width, and a Wilson-consistent trap-set sizing helper | **Implemented** | `metrics.dual_rua`, `ci_half_width`, `min_traps_for_ci_half_width` |
| U-C | Construct validity: blind-labeling agreement, provenance split, unanticipated-class bucket | **Partial** — metric + schema landed; external traps and human annotation are content work | `metrics.cohen_kappa`, `corpus/traps/SCHEMA.md` |
| U-D | Difficulty control: symbolic-exclusive catch, compiling-trap fraction | **Implemented** | `metrics.symbolic_exclusive_catches`, `compiling_unsafe_fraction`, `TrapDifficultyRecord` |
| U-E | Replace the strawman template baseline with a modern structural tool (OpenRewrite / Semgrep autofix) | **Deferred** | tracked here; no such tool in this environment |
| U-F | Seed-variance reporting + adversarial detector perturbation | **Implemented** | `metrics.seed_variance`, `eval/perturb.py`, `tests/unit/test_perturb.py` |

## Consequences

- **U-A** removes the single-file-compile strawman that inflated the symbolic
  layers' apparent contribution. Its own test
  (`test_rejects_api_breaking_patch_that_still_compiles`) proves L3 now *runs
  tests*, not just compiles. What remains deferred is runtime **conformance** of
  the migrated primitive (ML-KEM/ML-DSA actually running), which needs JDK 24 /
  oqs in `containers/crypto-tools` and is L4's job, not L3's.
- **U-F** produced a genuine, reportable robustness finding rather than a
  convenient one: this project's Semgrep pack constant-folds a split string
  literal and simple variable concatenation, so those perturbations do **not**
  evade it; only non-foldable array-index indirection does. Both facts are
  pinned by tests, and both belong in the paper.
- **U-C** and **U-E** are the honest boundary of a code-only session. The κ
  estimator and the v2 trap schema are in place, but sourcing external
  PR/CVE-derived traps and running a two-annotator blind-labeling pass are
  data-collection tasks, and the held-out suite is deliberately unfrozen until
  the rule set is (authoring it now would overfit it — §12.2's circularity
  warning). U-E needs a tool not present here.

## Alternatives considered

1. **Fabricate a held-out trap suite and a baseline number now.** Rejected —
   it would violate the project's no-fabricated-results invariant and overfit
   traps to an unfinished rule set.
2. **Defer U-A with the others.** Rejected — U-A is the single highest-leverage
   fix (it changes what the headline comparison *means*), and it was achievable
   with tools present (JDK 11 `javac`/`java`), so it was done first.
