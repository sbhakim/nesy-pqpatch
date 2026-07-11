# ADR-001: L2 dataflow/typestate engine selection

**Status:** proposed, NOT yet decided
**Date:** 2026-07-11 (opened); decision deadline per codebase-plan.md §5 Phase 2
exit criterion is end of week 2 of implementation -- this session did not reach
that point in wall-clock development time, so the ADR remains open rather than
being force-closed with an unverified choice.

## Context

The manuscript commits to 22 L2 dataflow/typestate rules (Manuscript-ACM/main.tex
Table 3) covering U3 (unchecked verify), U4 (key confusion), U5 (randomness
sourcing beyond what pattern-matching can see), and U6 (hybrid downgrade beyond
the syntactic subset already implemented at L1). These properties are
genuinely control-/data-flow properties -- "does the boolean result of
`verify()` reach a branch," "does a key object flow into an incompatible
API" -- and cannot be correctly decided by scanning diff lines the way the six
L1 rules in this session's `verifier/l1_syntactic/rules.py` do.

codebase-plan.md §13 identifies this engine choice as the project's
**critical path** and prescribes a hard timebox: spike CogniCrypt's ability to
ingest custom PQC rules; if it does not work cleanly by the deadline, fall
back to CodeQL taint/typestate queries or a Soufflé/Datalog implementation
over tree-sitter-extracted facts, and never revisit the choice afterward.

This session did not run that spike. Building it honestly (actually
installing CogniCrypt, actually authoring a trial PQC rule, actually
measuring whether it ingests cleanly) is real, multi-hour infrastructure
work that was out of scope for the vertical-slice build completed here
(Phases 0-3: skeleton, detector, L1 rules, proposer/cache/loop, verifier
orchestrator, trace, metrics -- see docs/STATUS.md).

## Decision

**Not made.** `verifier/l2_dataflow/__init__.py` exists with the real,
documented interface (`check(patch, site, policy) -> RuleOutcome`) the
future implementation must satisfy, and raises `NotImplementedError` with a
message pointing back to this ADR. The verifier orchestrator
(`verifier/api.py`) treats L2 as an explicitly excluded layer
(`DEFAULT_ENABLED_LAYERS = {L1_SYNTACTIC, L3_BUILD}`) rather than silently
passing it, and every `Verdict` records `layers_evaluated` so no result can
be mistaken for a full four-layer verification.

## Consequences

- Every Verdict/Trace produced by this session's code is honestly partial:
  `layers_evaluated` never contains `Layer.L2_DATAFLOW`.
- `eval/metrics.py`'s `catch_rate_by_layer` will correctly show zero L2
  catches until this ADR is resolved and rules exist -- that is accurate,
  not a bug to paper over.
- The de-scoping valve from codebase-plan.md §13 remains available: if,
  once this spike runs, CodeQL/Soufflé prove slower to rule-author than
  planned, ship fewer than 22 rules and update the manuscript's committed
  count in the same commit, rather than let the rule count silently drift
  out of sync with what Table 3 claims.

## Alternatives considered (to be evaluated when the spike runs)

1. **CogniCrypt/CrySL.** Native fit for the rule *style* the manuscript
   describes ("CrySL-style rules"), but academic-maintenance risk is real;
   must be spiked, not assumed.
2. **CodeQL.** Mature, well-documented taint/typestate query support for
   Java; commercial licensing terms for redistributing custom query packs
   in a public artifact must be checked before committing (codebase-plan.md
   §13 "CodeQL licensing must be verified before ADR-001").
3. **Soufflé/Datalog over tree-sitter facts.** No licensing risk, full
   control, but requires hand-building the fact extractor -- costed in
   codebase-plan.md §13 at roughly one additional week versus the other two
   options.
