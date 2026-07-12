# ADR-002: L3 build scope — from single-file compile to project build + tests

**Status:** amended 2026-07-11 (see "Amendment" below). The original decision
(single-file `javac` only) held for the first session; L3 now runs a real
multi-file project build plus the project's own test suite when the site's
project ships a `build.yaml` descriptor, and falls back to the single-file
compile only when it does not.
**Date:** 2026-07-11

## Amendment (upgrade U-A, refined_defined_plan.md §12.1)

The single-file compile was the load-bearing weakness in the evaluation: the
headline result compares the full verifier against an "L3-only build+test"
baseline, and a single-file compile makes that baseline a strawman, inflating
the apparent contribution of L1/L2. L3 (`verifier/l3_build.py`) now has two
modes:

- **Project mode.** When a `build.yaml` sits above the site file, the patched
  tree is copied, the patch is applied inside the copy, *every* `.java` source
  under `source_dir` is compiled together, and the project's declared test
  entrypoint is run. PASS requires both the build and the tests to succeed.
  The descriptor is declarative (project / source_dir / test_entrypoint /
  timeouts) — the runner owns the `javac`/`java` argv, so a corpus file can
  never inject a command.
- **Single-file mode.** No descriptor → the original standalone compile,
  labelled as such in the outcome detail so no reader mistakes it for a build.

The seed Tier-2 app (`corpus/tier2/file-signing-cli`) now ships a real build:
`FileSigner.java` plus provider-independent `HexCodec`/`SignatureManifest`
helpers and a `RegressionTests` suite. The suite deliberately exercises only
provider-independent behavior (hex/manifest framing) and reflectively asserts
that the migration preserves `FileSigner`'s public signing API — so it passes
on any JDK and needs no PQC provider at runtime. A dedicated test
(`test_rejects_api_breaking_patch_that_still_compiles`) proves the tests
actually run: a method-rename patch compiles cleanly yet is correctly rejected
because the regression suite fails.

**What is still deferred (and why it is honest to defer it):** project mode
resolves no third-party dependencies (no Maven/Gradle in this environment) and
runs on JDK 11, so it cannot *execute* migrated ML-KEM/ML-DSA code — that is
runtime **conformance**, which is L4's job (round-trip + ACVP KATs on a
PQC-capable toolchain in `containers/crypto-tools`), not L3's regression job.
L3's contract is "the patch builds and the project's existing tests still
pass," and project mode now meets it.

## Context

The manuscript's L3 ("build and test") means: build the patched project in a
pinned container and run its existing test suite (Manuscript-ACM/main.tex
Sec. 4.3, "L3 (build and test)"). codebase-plan.md targets JDK 24 in a
pinned `containers/build-jdk24` image (§5 Phase 4, §12 package manifest).

This environment has JDK 11 (`javac -version` -> `11.0.31`), Docker is
present but no JDK-24 image was built this session, and the Tier-2 seed
app (`corpus/tier2/file-signing-cli`) has no Maven/Gradle descriptor and no
test suite yet -- those land in Phase 6 ("Reference Applications... each
ships a real test suite," codebase-plan.md §5).

## Decision (original session — superseded in part by the Amendment above)

Implement L3 (`verifier/l3_build.py`) as: apply the patch in-memory to the
site's source file (`verifier/rules/diffapply.py`, a pure-Python unified-diff
applier -- see ADR-003), write it to a temp directory, and run a real,
single-file `javac` compile. PASS iff `javac` exits 0.

This is real and useful today -- it genuinely rejects patches with syntax
errors (verified directly: see `docs/STATUS.md`'s worked example) -- but it
is a strict subset of the manuscript's L3 claim. It does not resolve
project dependencies, does not run any test suite, and uses JDK 11 rather
than JDK 24.

## Consequences

- `verify_patch()`'s `DEFAULT_ENABLED_LAYERS` includes `Layer.L3_BUILD`,
  and every `Verdict.layer_reports` entry for that layer is real (not
  `SKIPPED`) -- but a reader must understand "L3 passed" as "this file
  compiles standalone," not "this project builds and its tests pass."
- Once Tier-2 apps have real build descriptors and JDK 24 is containerized
  (Phase 4/5), `l3_build.py` should be rewritten to invoke the container
  and the project's own test command, and this ADR should be marked
  superseded.
- No manuscript-scale result should be reported from this reduced L3
  without explicitly noting the substitution, exactly as this ADR does.

## Alternatives considered

1. **Containerize JDK 24 + a real Maven build now.** Correct target, but
   real multi-hour infrastructure work (Dockerfile, Maven POM per Tier-2
   app, test authoring) out of scope for this session's vertical slice.
2. **Skip L3 entirely (SKIPPED, like L2/L4).** Rejected: a real,
   inexpensive compile check was achievable with tools already present
   (`javac`) and materially strengthens the smoke-test's evidentiary
   value (it genuinely catches a broken patch, not just a rule violation).
