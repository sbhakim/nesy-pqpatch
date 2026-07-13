# ADR-001: L2 dataflow/typestate engine selection

**Status:** accepted; structural frontend adopted for the first bounded vertical slice
**Date:** 2026-07-11 (opened); 2026-07-12 (decision); 2026-07-13 (frontend revision)

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

The environment contains neither CodeQL nor Soufflé, and introducing either
before establishing the first load-bearing rule would add installation,
licensing, and fact-extraction risk. CogniCrypt likewise remains an
infrastructure spike rather than an available dependency. The first rule is
small enough to test the required semantics without committing the artifact to
one of those external runtimes.

## Decision

Use a purpose-built, intraprocedural Java fact/def-use slice for the initial L2
rules, beginning with `PQ-VER-01`, with Tree-sitter Java as its structural
frontend. The engine applies the candidate diff to the real source file and
extracts invocation, assignment, branch, and return facts from the syntax tree.
It recognizes direct branch/return use, local boolean assignment, ordered simple
aliases, and intervening overwrites. Parse errors, unsupported expression shapes,
lambda boundaries, and ambiguous same-name redeclarations are indeterminate
rather than silently accepted. Nested method and class facts are kept out of the
containing method. This is not presented as a general Java type resolver,
control-flow graph, or interprocedural analysis.

`PQ-VER-01` accepts verification results that reach a local branch or are
explicitly returned to the caller, and rejects discarded/dead results. L2 now
runs through the same registered-rule machinery as L1 and is enabled by default;
each verdict records that it ran and attributes rejection to the concrete rule.

The structural frontend removes the immediate regex/parsing risk but does not
provide symbol resolution or path-sensitive control flow. Before implementing
key-family, randomness-provenance, or hybrid-secret rules, each rule must prove
that the bounded facts are sufficient; otherwise the project must add a typed
frontend/CFG or revise the manuscript scope rather than infer semantics from
names.

## Consequences

- Verdicts produced under the default configuration now include
  `Layer.L2_DATAFLOW`; configurations that remove L2 remain explicit ablations.
- The current L2 count is **1 of the planned 22**. No result may describe this
  vertical slice as the complete L2 rule set.
- A regression test demonstrates the intended scientific contrast: a patch that
  discards `verify()`, compiles, and passes the seed project's tests is accepted
  by L1+L3 but rejected by L2 as `PQ-VER-01`.
- Runtime dependencies are bounded to `tree-sitter` 0.26.x and
  `tree-sitter-java` 0.23.x in `pyproject.toml`; CI installs them through the
  normal package installation path.
- The de-scoping valve from codebase-plan.md §13 remains available: if,
  once this spike runs, CodeQL/Soufflé prove slower to rule-author than
  planned, ship fewer than 22 rules and update the manuscript's committed
  count in the same commit, rather than let the rule count silently drift
  out of sync with what Table 3 claims.

## Alternatives considered

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
