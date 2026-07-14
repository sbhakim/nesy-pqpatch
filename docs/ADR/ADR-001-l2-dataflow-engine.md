# ADR-001: L2 dataflow/typestate engine selection

**Status:** accepted; structural frontend adopted; 5 T0 rules shipped covering U1/U3/U4/U5/U6 (PQ-VER-01, PQ-KEY-02, PQ-HYB-02, PQ-RAND-03, PQ-PARAM-02)
**Date:** 2026-07-11 (opened); 2026-07-12 (decision); 2026-07-13 (frontend revision + the five T0 rules)

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

### PQ-KEY-02 feasibility spike (2026-07-13)

The first application of that gate. Question: can the bounded structural facts
decide U4 key confusion (a key object crossing algorithm families) without a
Java type resolver? Answer: **yes, for the unambiguous case**, which is shipped
as `PQ-KEY-02`. Family is anchored on two facts already in reach -- the
algorithm string literal at a key-producing `getInstance`
(`KeyPairGenerator`/`KeyGenerator`/`KeyEncapsulation`) and the method name at a
key-consuming sink (`initSign`/`initVerify` = signature; `doPhase` = agreement).
An ML-KEM key reaching a signature sink, or an ML-DSA/SLH-DSA key reaching an
agreement sink, is convicted; simple aliases are followed. The **bounded scope,
recorded honestly**: a classical/ambiguous literal (`"EC"` is ECDSA *or* ECDH),
an interprocedural source, or a shadowed redeclaration is *not* convicted -- the
rule refuses to guess a family rather than risk a false rejection, exactly the
`PQ-VER-01` philosophy. Resolving those cases would need declared-type/symbol
resolution; that requirement is now documented rather than approximated, and it
scopes what a future typed frontend must add for the remaining U4/U5/U6 rules.

`PQ-HYB-02` (U6, 2026-07-13) confirmed the pattern generalizes: two shared
secrets (classical `generateSecret`, PQ `decapsulate`) converging on one
combiner is the same flow-to-sink shape as `PQ-KEY-02`, and it too decides at
T0. It catches the hybrid downgrade L1's token-level `PQ-HYB-01` cannot see (both
algorithm tokens can be present while the flow still drops one secret).
`PQ-RAND-03` (U5, 2026-07-13) is the same shape once more: a constant seed
(literal, fixed byte array, or `"…".getBytes()`) tainting a variable that reaches
`SecureRandom`, catching the seed provenance L1's `PQ-RAND-02` cannot follow past
a direct literal. `PQ-PARAM-02` (U1, 2026-07-13) closes the last purely
structural gap: a below-floor parameter token reaching `getInstance` through a
variable -- including a token defined *outside the diff hunks*, which never
appears in an added line and is therefore invisible to L1's token scan by
construction. Its rank comparison shares one table with PQ-PARAM-01
(`verifier/rules/ranks.py`) so the two layers cannot drift. Five T0 rules now
cover U1/U3/U4/U5/U6. The honest ceiling for this bounded frontend is roughly
8 L2 rules; the U7 and U2 reachability rules need an intraprocedural control-flow
graph and the U4 tail needs declared-type resolution -- a project-level frontend
decision, not another per-rule spike.

## Consequences

- Verdicts produced under the default configuration now include
  `Layer.L2_DATAFLOW`; configurations that remove L2 remain explicit ablations.
- The current L2 count is **5 of the planned 22** (`PQ-VER-01`, `PQ-KEY-02`,
  `PQ-HYB-02`, `PQ-RAND-03`, `PQ-PARAM-02`), each decided by the same bounded
  intraprocedural def-use. No result may describe this vertical slice as the
  complete L2 rule set.
- Five regression tests demonstrate the intended scientific contrast. (a) A patch
  that discards `verify()`, compiles, and passes the seed project's tests is
  accepted by L1+L3 but rejected by L2 as `PQ-VER-01`. (b) A migration that puts
  both algorithm families in scope makes L1's `PQ-KEY-01` *defer*, so L1 accepts,
  while L1+L2 rejects the ML-KEM-key-into-signature flow as `PQ-KEY-02`. (c) A
  hybrid migration whose added text carries both an ML-KEM and an X25519 token
  passes L1's token-level `PQ-HYB-01`, while L1+L2 rejects it as `PQ-HYB-02`
  because the flow feeds only one shared secret to the KDF. (d) A migration that
  routes a literal seed through a variable into `SecureRandom` passes L1's
  `PQ-RAND-02` (which only sees a literal directly in the constructor), while
  L1+L2 rejects it as `PQ-RAND-03`. (e) A migration that reuses a pre-existing
  below-floor algorithm constant defined outside the diff passes L1's
  `PQ-PARAM-01` token scan (no token in any added line), while L1+L2 rejects it
  as `PQ-PARAM-02`. Each is the "beyond tokens" L1->L2 escalation boundary, made
  executable.
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
