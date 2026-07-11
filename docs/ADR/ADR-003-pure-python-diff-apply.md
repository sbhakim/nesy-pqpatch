# ADR-003: Pure-Python unified-diff applier instead of `patch -p1`/`git apply`

**Status:** accepted
**Date:** 2026-07-11

## Context

L3 (ADR-002) and any future L4 conformance check need to materialize a
patched file from a `Patch.unified_diff` string before compiling/testing
it. Two off-the-shelf options exist and were confirmed present on this
machine: the POSIX `patch` utility and `git apply`. Both are path-prefix
sensitive (`-p1`, `a/`/`b/` stripping) relative to a working directory, and
`Site.file_path` in this codebase is whatever path the detector happened to
scan from (potentially a long relative or absolute path), while diff
headers in prompts/fixtures use short-form paths like `src/FileSigner.java`.
Reconciling these two path conventions robustly for an arbitrary corpus
(Tier 1/2/3, arbitrary repo layouts) was judged more fragile, for this
session's time budget, than solving the problem a different way.

`verifier/rules/spec.py`'s `PQ-SCOPE-01` rule already guarantees (and is
fixture-tested to guarantee) that any patch reaching L3 touches exactly one
file. That guarantee makes a **single-file, content-only** diff applier
sufficient -- no path resolution is needed at all if the function operates
on `(original_content: str, diff_text: str) -> patched_content: str`
rather than on paths and a working directory.

## Decision

Implement `verifier/rules/diffapply.py::apply_unified_diff()` as a small,
dependency-free unified-diff-hunk applier operating purely on strings. It
was built with a defensive property `patch -p1` does not enforce by
default: every context (`" "`) and removal (`"-"`) line in a hunk is
verified against the actual original content at that position before being
consumed, and a mismatch raises `DiffApplyError` rather than silently
producing corrupted output.

That defensive check was not a speculative "nice to have" -- it was added
*after* a hand-typed test fixture with an incorrect hunk header
(`@@ -24,6 +24,10 @@` against content actually starting at line 23)
silently duplicated a method signature in the applied output during this
session's own development (see `docs/STATUS.md` and
`tests/unit/test_diffapply.py::test_wrong_hunk_header_raises_instead_of_corrupting`,
which encodes exactly that failure mode as a regression test).

## Consequences

- `tests/support/diffgen.py` (a `difflib.unified_diff`-based generator) is
  now the required way to construct any diff intended to be *applied* in a
  test; hand-typed diffs remain valid for the L1 rule fixtures (which only
  ever scan `+` lines via `added_lines()` and never call `apply_unified_diff`),
  but must not be reused for L3/L4-style tests without verifying they apply.
- This applier does not handle multi-file diffs, renames, or binary
  content. That is an intentional scope limit, not an oversight -- PQ-SCOPE-01
  makes it structurally unnecessary for this pipeline's patches.
- When containerized L4 conformance work begins (Phase 5), the same
  function can be reused verbatim; it has no dependency on L3's javac path.

## Alternatives considered

1. **`git apply --directory=... -p1`.** Rejected for this session: requires
   reconciling `Site.file_path` with diff header path conventions across
   an eventual multi-corpus (Tier 1/2/3) layout; deferred until that
   reconciliation is actually needed.
2. **POSIX `patch -p1`.** Same path-prefix fragility as `git apply`, plus
   weaker error reporting on context mismatches than the explicit check
   built here.
