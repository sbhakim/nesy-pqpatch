# Status: what is real, what is a documented stub

Honest ledger, per codebase-plan.md's own principle: "a fixed number does
not outrank the schedule," applied here as "a documented gap does not
outrank an honest status page." Last updated 2026-07-11, at the end of the
first implementation session.

## Environment

Built and verified in the `quantum` conda environment (Python 3.11.15).
All commands below were actually run, not assumed:

```
ruff check src tests        -> All checks passed!
mypy                          -> Success: no issues found in 64 source files
pytest tests/                -> 75 passed
```

External tools used for real (not mocked): `semgrep` 1.169.0 (installed
this session), `javac`/`java` 11.0.31 (system JDK), `git`, `patch` (present,
ultimately not used -- see ADR-003), `docker` (present, not yet used --
containerized builds are Phase 4/5).

## Phase-by-phase (codebase-plan.md §5)

| Phase | Scope | Status |
|---|---|---|
| 0 | Skeleton, pyproject, CI, `model.py` | **Real.** Package installs editable, imports, CLI runs. |
| 1 | Detector + seed Tier-2 app | **Real.** Semgrep pack (4 rules) + `classify.py` verified against `corpus/tier2/file-signing-cli`: precision 100%, recall 6/7 (the 7th site is deliberately undetectable by design, per Stage A). |
| 2 | Rule metadata + fixtures + L1 rules | **Real, reduced count.** 6 L1 rules (`PQ-PARAM-01`, `PQ-FALL-01`, `PQ-FALL-02`, `PQ-RAND-01`, `PQ-HYB-01`, `PQ-SCOPE-01`) with 12 fixtures, all passing. Manuscript Table 3 commits to 14 L1 rules; this session shipped 6. The gap is the remaining 8 (additional U1/U4/U7 coverage), not a change in kind. |
| 3 | Proposer, cache, repair loop | **Real.** `Backend` ABC, content-addressed `CacheStore`, `ReplayBackend` test double, `loop.py` implementing Algorithm 1 exactly. Demonstrated end to end: a REJECT (policy-floor violation) followed by rule-derived feedback followed by ACCEPT, and a full-exhaustion ESCALATE. `backend_a.py`/`backend_b.py`/`backend_c.py` are real, documented-API-shape adapters (OpenAI-compatible / Anthropic Messages / local OpenAI-compatible) that raise a clean credentials error rather than fabricate a response -- **not exercised**, no API keys in this environment. |
| Verifier orchestrator | Eq. (1) short-circuit composition | **Real.** `verify_patch()` runs L1 then L3 (L2/L4 explicitly excluded via `DEFAULT_ENABLED_LAYERS`, not silently skipped -- every `Verdict.layers_evaluated` records the truth). |
| L2 (dataflow/typestate) | 22 rules per manuscript Table 3 | **Not implemented.** Real interface, `NotImplementedError`, ADR-001 open. This is the project's critical path (codebase-plan.md §13). |
| L3 (build) | Containerized Maven/Gradle + project tests | **Reduced-scope real implementation.** Single-file `javac` compile against a real JDK. See ADR-002. Genuinely catches syntax errors (verified with a deliberately broken patch during development). |
| L4 (conformance) | Round-trip + ACVP KATs + tri-stack interop | **Not implemented.** Real interfaces in `roundtrip.py`/`acvp.py`/`interop.py`, all raise `NotImplementedError`. Requires `containers/crypto-tools` and pinned ACVP vectors, neither built this session. |
| Trace + metrics | Canonical hashing, attestation, RUA/Wilson/McNemar | **Real.** Golden-bytes-tested canonical JSON, working tamper detection (a mutated field is correctly detected), optional ML-DSA signing behind a guarded import (`liboqs-python` not installed; raises a clear error, not a silent no-op). All five metrics functions verified against hand-computed reference values, not just round-trip tests. |
| 6-8 | Full corpora, held-out traps, ablations, paper-scale runs | **Not started.** Zero fabricated numbers exist anywhere in this repository; `Manuscript-ACM/main.tex`'s `XX.X%` placeholders remain placeholders. |

## Real bugs found and fixed during this session (evidence the tests are doing work)

1. **`PQ-FALL-01` false positive on the migrated primitive itself.** The
   classical-fallback rule's token list included the bare substring `"DSA"`,
   which matched inside `"ML-DSA-65"` -- the *safe* migrated algorithm was
   being flagged as an unsafe classical fallback. Caught by the rule's own
   fixture test. Fixed with a negative lookbehind excluding an `ML-` prefix,
   then a second iteration fixed because naive `\b` word-boundary regexes
   don't match JCA's fused compound identifiers (`SHA256withRSA` has no
   boundary between `with` and `RSA`).
2. **`Verdict` dataclass field ordering.** A defaulted field
   (`layers_evaluated`) was placed before non-defaulted fields, which is a
   `TypeError` at class-definition time in Python dataclasses. Caught before
   any test ran, by re-reading the file.
3. **`apply_unified_diff` silently corrupting output on a bad hunk header.**
   A hand-typed fixture diff's `@@ -24,6 +24,10 @@` header claimed an offset
   one line off from the real file, and the applier -- trusting the header --
   duplicated a method signature instead of failing. Fixed by adding context-
   line verification that raises `DiffApplyError` on any mismatch, and this
   exact failure mode is now a regression test.
4. **`CachedResponse.__dict__` on a `slots=True` dataclass.** `slots=True`
   dataclasses have no `__dict__`; `cache.py` was calling `response.__dict__`
   to serialize. Fixed with `dataclasses.asdict()`. Caught by the smoke test.
5. **Wrong assertion, not a code bug, in the smoke test itself.** The first
   version of `test_smoke_full_pipeline_with_repair_loop` asserted exact
   `content_hash` equality between two runs of the same site. This is
   incorrect: the hash legitimately incorporates real `duration_ms` timing
   telemetry from L1/L3, which varies run to run by design (the manuscript
   itself treats verification duration as measured metadata, not a
   constant). Fixed by asserting the properties that *should* be
   deterministic (decision content, accepted patch, event sequence) instead
   of the ones that legitimately are not.
6. **A ground-truth authoring error in `sites.yaml`, not a code bug.** Line
   49 of the seed app (a `KeyPairGenerator("EC")` call) was hand-labeled
   `sign`, but the actual data flow feeds an ECDH key agreement a few lines
   later -- the true label is `kem`. Caught by running the real detector and
   comparing its (correct) output against the (wrong) hand-authored label,
   rather than assuming the hand-authored label was ground truth.

## What a future session should do first

1. Run ADR-001's spike (CogniCrypt vs. CodeQL vs. Soufflé) and close it.
2. Grow the L1 rule set from 6 to the manuscript's committed 14, or update
   the manuscript's committed count in the same commit if that count
   changes (codebase-plan.md §13's own rule).
3. Build `containers/build-jdk24` and `containers/crypto-tools`, and
   upgrade `l3_build.py` from single-file `javac` to a real containerized
   project build + test run (ADR-002).
4. Add the remaining five Tier-2 reference applications.
