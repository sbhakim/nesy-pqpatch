# Status: what is real, what is a documented stub

Honest ledger, per the project principle "a documented gap does not outrank an
honest status page." Last updated 2026-07-13, after the third L2 rule (PQ-HYB-02).

## Environment

Built and verified in the `quantum` conda environment (Python 3.11.15).
All commands below were actually run, not assumed:

```
ruff check src tests        -> All checks passed!
mypy                          -> Success: no issues found in 95 source files
pytest tests/                -> 185 passed
```

(Earlier in the project this read 64 files / 75 tests, then 67 / 104 after the
evaluation-robustness upgrades — ADR-004, U-A…U-F; then 82 / 142 after the
live-pilot fixes below; then 85 / 153, 88 / 163, and 91 / 174 as the L2 rules
landed; the latest increase is the `PQ-PARAM-02` L2 rule.)

External tools used for real (not mocked): `semgrep` 1.169.0, `javac`/`java`
11.0.31 (system JDK), `git`, `docker` (present, not yet used). **Live local
models** were served via **Ollama** (`qwen2.5-coder:7b`, `llama3.1:8b`,
`gemma3:12b`, `qwen2.5:7b-instruct`) over its OpenAI-compatible endpoint and
driven through the real proposer for the first time this session. Hosted API
keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) are present in the environment but
were **not** used — a paid, outward-facing call needs explicit authorization.

## Phase-by-phase

| Phase | Scope | Status |
|---|---|---|
| 0 | Skeleton, pyproject, CI, `model.py` | **Real.** Package installs editable, imports, CLI runs. |
| 1 | Detector + seed Tier-2 app | **Real.** Semgrep pack (4 rules) + `classify.py` verified against `corpus/tier2/file-signing-cli`: precision 100%, recall 6/6 detectable (= 6/7 seeded; the 7th is deliberately undetectable by design). |
| 2 | Rule metadata + fixtures + L1 rules | **Real, reduced count.** **9** L1 rules with fixtures, including `PQ-KEY-01` (unambiguous primitive-family mismatch) and `PQ-RAND-02` (literal-seeded `SecureRandom`). Manuscript Table 3 commits to 14 L1 rules; ambiguous flow remains assigned to L2 rather than guessed at L1. |
| 3 | Proposer, cache, repair loop | **Real, now exercised on live models.** `Backend` ABC, content-addressed `CacheStore`, `ReplayBackend` test double, `loop.py` implementing Algorithm 1. `backend_c` (local OpenAI-compatible) was driven end-to-end against **Ollama** for the first time — real proposals, cached and reproducible. `backend_a`/`backend_b` (hosted) remain unexercised pending authorization to spend. |
| Verifier orchestrator | Eq. (1) short-circuit composition | **Real.** `verify_patch()` runs L1, the implemented L2 registry, then L3 by default; L4 remains explicitly excluded, and every `Verdict.layers_evaluated` records the truth. |
| L2 (dataflow/typestate) | 22 rules per manuscript Table 3 | **Real vertical slice: 5/22**, all on one bounded Tree-sitter Java def-use frontend (ADR-001), together covering five of the seven unsafe classes (U1/U3/U4/U5/U6). `PQ-VER-01` (U3) rejects discarded/dead/overwritten `verify()` results while accepting branch use, ordered aliases, and explicit return. `PQ-KEY-02` (U4) convicts an unambiguous cross-family key flow (ML-KEM key → signature `initSign`/`initVerify`, or ML-DSA/SLH-DSA key → agreement `doPhase`). `PQ-HYB-02` (U6) engages when a method produces both a classical (`generateSecret`) and a PQ (`decapsulate`) shared secret, and convicts when no single expression combines them — the hybrid downgrade L1's token-level `PQ-HYB-01` cannot see. `PQ-RAND-03` (U5) convicts a fixed/literal seed that reaches `SecureRandom` through a variable or alias — the seed provenance L1's `PQ-RAND-02` (literal *directly* in the constructor) cannot see. `PQ-PARAM-02` (U1) convicts a below-floor parameter token that reaches `getInstance` through a variable in the patched source — including a token defined *outside the diff hunks*, which never appears in an added line and is therefore invisible to L1's `PQ-PARAM-01` (rank tables shared in `rules/ranks.py` so the floor comparison cannot drift between layers). Across all five: interprocedural/non-constant sources, fields, parameters, and shadowed redeclarations are deliberately *not* convicted (documented bounded scope); parse errors fail closed. Five load-bearing tests prove the contrast — L1(+L3) accepts what L2 rejects at each rule. This is not the complete promised L2 set; the honest T0/T1 ceiling on this frontend is roughly 8 L2 rules (the rest need a control-flow graph or declared-type resolution). |
| L3 (build) | Containerized Maven/Gradle + project tests | **Real project build + tests (U-A / ADR-004).** When a `build.yaml` sits above the site, L3 copies the tree, applies the patch (via a content-anchored diff applier that tolerates the wrong line numbers / whitespace real models emit, while refusing to force-apply an ambiguous or unmatched hunk), compiles *all* sources, and runs the project's own test entrypoint; single-file `javac` remains a labelled fallback. Still deferred: third-party dependency resolution and JDK 24 PQC *runtime* (L4's job). Supersedes ADR-002 in part. |
| L4 (conformance) | Round-trip + ACVP KATs + tri-stack interop | **Not implemented.** Real interfaces in `roundtrip.py`/`acvp.py`/`interop.py`, all raise `NotImplementedError`. Requires `containers/crypto-tools` and pinned ACVP vectors, neither built this session. |
| Trace + metrics | Canonical hashing, attestation, RUA/Wilson/McNemar | **Real.** Golden-bytes-tested canonical JSON, working tamper detection (a mutated field is correctly detected), optional ML-DSA signing behind a guarded import (`liboqs-python` not installed; raises a clear error, not a silent no-op). Every metric verified against hand-computed reference values, not just round-trip tests. |
| Eval robustness (U-B…U-F) | Co-primary RUA, difficulty control, κ, seed variance, detector perturbation | **Real (metrics + harness), ADR-004.** `metrics.dual_rua` / `min_traps_for_ci_half_width` (U-B), `symbolic_exclusive_catches` / `compiling_unsafe_fraction` (U-D), `cohen_kappa` (U-C), `seed_variance` (U-F), and `eval/perturb.py` — the perturbation probe found a genuine result: Semgrep constant-folds a split literal (not evaded) but not array-index indirection (evaded), both pinned by tests. External/PR-CVE traps, human annotation (U-C) and a modern structural baseline (U-E) are deferred as data/tooling work. |
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

## Live-model pilot (2026-07-12): what the first real run taught us

Running the pipeline against real local models (not the `ReplayBackend` double)
surfaced four defects the scripted tests could not, each now fixed with tests:

7. **Response parsing was too strict for real output.** Models wrap the diff and
   JSON self-report in ```` ```diff ````/```` ```json ```` fences and pretty-print
   or nest the JSON across lines. `response_format.py` now strips fences and
   locates the self-report as the last brace-balanced object.
8. **`PQ-SCOPE-01` false-rejected correctly-scoped patches.** It compared diff
   paths to `site.file_path` by exact string, but models spell the same file as a
   basename, a repo-relative, or an absolute path with varying `a//b/` prefixes
   and leading slashes. `diffutil.path_in_scope` now matches by normalized path
   components — the exact "verifier over-conservatism / false-rejection" the
   manuscript names, caught in the wild.
9. **The diff applier was too brittle.** It trusted the model's `@@` line numbers
   and required byte-exact context; real diffs have wrong offsets and off-by-a-
   space indentation. It now anchors each hunk by content (whitespace-tolerant)
   and applies only on an unambiguous match, still raising rather than risk a
   mis-located (false-accept) patch.
10. **The verifier accepted no-op patches.** Every rule was a *prohibition*, so a
    patch that changed nothing passed them all — real models produced vacuous
    diffs that were ACCEPTED while leaving the vulnerable call in place. **`PQ-MIG-01`**
    now supplies the missing obligation: a patch must introduce a permitted PQ
    primitive and remove the classical one, or it is rejected.

**The honest pilot result** (3 local models × 6 seed-app sites, cached, offline):
after `PQ-MIG-01`, **0 of 18 genuine migrations** — the 7–12B local models do not
produce real, applyable, correct PQC migrations; every earlier "accept" was
vacuous. Crucially, **residual unsafe-accept rate = 0/18**: the gate let nothing
unsafe (including no-ops) through. Safety holds; local-model *capability* is the
gap. No paper-scale numbers exist; the manuscript's `XX.X%` remain placeholders.

## What a future session should do first

1. Five L2 rules now anchor the slice (5/22: `PQ-VER-01`, `PQ-KEY-02`,
   `PQ-HYB-02`, `PQ-RAND-03`, `PQ-PARAM-02`), each decided by the same bounded
   intraprocedural def-use and together covering U1/U3/U4/U5/U6. The remaining
   T0/T1 candidates before the ceiling (~8) are a second `verify()`-shape (U3),
   a `setSeed`-ordering variant (U5), and a second hybrid combiner shape (U6).
   Beyond those, U7 fail-open and the U2 reachability rules need an
   intraprocedural CFG, and most of U4's remainder needs declared-type
   resolution — those are project-level decisions, not per-rule spikes. Record any
   such requirement in ADR-001 before building.
2. Grow the L1 rule set from 9 to the manuscript's committed 14 (or edit the
   committed count in the same commit if it changes).
3. Add the remaining five Tier-2 reference applications — each with a
   `build.yaml` and a real test suite so project-mode L3 applies to all of them.
4. Once the rule set is frozen, author the held-out trap suite under
   `traps/SCHEMA.md` v2 (size from `metrics.min_traps_for_ci_half_width`, ≈25–30),
   with external PR/CVE-provenance traps and two-annotator blind labels (U-C).
5. To get a non-zero *capability* number, run a stronger proposer (a cheap hosted
   model, with explicit spend authorization) — the local models are too weak.
