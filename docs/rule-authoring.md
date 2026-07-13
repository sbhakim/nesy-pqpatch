# How to author a verifier rule

Applies to L1 and to the bounded L2 registry selected by ADR-001.

## 1. Pick the unsafe class

Every rule maps to one of U1-U7 (`Manuscript-ACM/main.tex` Sec. 3.1,
`pqpatch.model.UnsafeClass`), or `None` for a structural/scope check that
isn't itself one of the seven classes (see `PQ-SCOPE-01`).

## 2. Write the check function

Signature (fixed, do not deviate -- `verifier/api.py` calls every rule this
way):

```python
def _check_my_property(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    ...
    return RuleOutcome(RuleStatus.PASS)  # or RuleStatus.FAIL with a detail=
```

- Use `verifier.rules.diffutil.added_lines(patch.unified_diff)` for L1
  (syntactic) checks -- never re-parse `patch.unified_diff` by hand.
- Never read `patch.claimed_primitive`/`claimed_parameters` as evidence.
  They are the proposer's self-report; treat them as a claim to check, if
  you check them at all (invariant 2, codebase-plan.md §2).
- If a rule needs the applied source (not just the diff), use
  `verifier.rules.diffapply.apply_unified_diff` -- see ADR-003 for why this
  exists instead of `patch -p1`/`git apply`.

## 3. Register it

```python
register(
    RuleSpec(
        rule_id="PQ-XXXX-NN",       # unique, grep-able, matches manuscript naming
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U1_PARAM_WEAKENING,
        cwe="CWE-...",
        severity="high",             # "high" | "medium" | "low"
        rationale="...",             # fed back to the proposer verbatim on REJECT;
                                      # must describe the violated property in terms
                                      # a model can act on, not just name the rule
        check=_check_my_property,
        fixtures_dir=_FIXTURES / "PQ-XXXX-NN",
    )
)
```

## 4. Write fixtures -- mandatory, not optional

Invariant 3 (codebase-plan.md §2): a rule without both a passing and a
violating fixture fails CI (`tests/rules/test_l1_fixtures.py`), full stop.

```
fixtures/PQ-XXXX-NN/
  passing/at_least_one.diff
  violating/at_least_one.diff
```

Each `.diff` is a plain unified diff (`---`/`+++`/`@@`/`+`/`-` lines).
`added_lines()`-based rules do not need hunk headers to be numerically
correct against any real file -- only the `+` lines matter. If you intend
to also feed a fixture through `apply_unified_diff` (e.g. to build an L3
test), generate it with `tests/support/diffgen.make_diff()` instead of
typing it by hand -- see `docs/STATUS.md` item 3 for why a hand-typed hunk
header caused real silent corruption during this project's own development.

## 5. Run the fixture suite before committing

```
make rules-test
```

A rule that cannot fail its own violating fixture is not a rule -- it is
decoration. If a fixture doesn't make the check function return the status
you expect, the check function is wrong, not the fixture (unless the
fixture itself is not actually violating the property -- verify by reading
it).
