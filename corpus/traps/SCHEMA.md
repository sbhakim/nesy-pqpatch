# Trap schema (v2 — evaluation-robustness upgrades)

Each trap is a scenario in which the *plausible* completion is unsafe. v2 adds
the fields the robustness upgrades in `refined_defined_plan.md` §12 depend on,
so a trap carries enough metadata for the difficulty control (U-D), the blind
labeling (U-C), and the provenance split (U-C) without any of it being inferred
after the fact.

```yaml
trap_id: hyb-downgrade-tls-003
usage_class: config              # one of: sign | verify | kem | envelope | config
unsafe_class: U6                 # U1..U7, or "unanticipated" (see below)
split: heldout                   # dev | heldout  (heldout is authored post-freeze)

# --- provenance (U-C: break trap self-referentiality) --------------------
provenance: external-pr          # taxonomy | external-pr | external-cve
source_ref: "github.com/org/repo#1234"   # required unless provenance == taxonomy

# --- difficulty control (U-D) --------------------------------------------
unsafe_patch_compiles: true      # does the bad completion survive a build?
caught_by_l3_alone: false        # would build+test alone have rejected it?

# --- blind labeling (U-C: construct validity) ----------------------------
annotator_labels:                # >= 2 independent unsafe/safe labels
  - annotator: A
    unsafe: true
  - annotator: B
    unsafe: true
ground_truth_unsafe: true        # adjudicated label; kappa is computed over the
                                 # annotator_labels across the whole suite

scenario_path: heldout/hyb-downgrade-tls-003/   # the code + context fixture
rationale: >
  Dropping the hybrid group still compiles and passes the project tests, so
  only the L1 hybrid-required rule (PQ-HYB-01) or an L2 dataflow check rejects it.
```

## Field notes

- **`unsafe_class: unanticipated`** — a trap whose unsafe property is *not*
  covered by any current rule. These measure whether the rule set generalizes
  beyond its own taxonomy (U-C). Catch rate on this bucket is reported
  separately; a low number here is the honest ceiling of the approach and
  belongs in Threats to Validity, not hidden.
- **`provenance`** — `taxonomy` traps are authored from the rule taxonomy and
  risk measuring the rules against themselves. `external-pr` / `external-cve`
  traps come from real unsafe patterns in the wild and are the antidote; the
  headline suite must contain a reported fraction of them.
- **`caught_by_l3_alone`** feeds `metrics.symbolic_exclusive_catches`: the
  cleanest evidence the symbolic layers are load-bearing is the count of
  *compiling* traps that L3-alone misses and the full verifier catches.
- **`annotator_labels`** feed `metrics.cohen_kappa`. A trap whose annotators
  disagree is adjudicated (and the disagreement retained) rather than silently
  relabeled; the pre-registered construct-validity bar is kappa >= ~0.7.

## Current state

The rule set is not yet frozen (6 of 14 L1 rules; L2 pending ADR-001), so the
held-out suite is deliberately *not* authored yet — authoring it now would
overfit it to an unfinished taxonomy, exactly the circularity §12.2 warns
against. `metrics.min_traps_for_ci_half_width` sizes the held-out set: the
target is the smallest set whose Wilson half-width on a zero-residual outcome is
defensible (≈25–30, versus the ~12 the manuscript currently commits to).
