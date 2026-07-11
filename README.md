# pqpatch

**Rule-verified neuro-symbolic migration of cryptographic code to post-quantum
standards.**

`pqpatch` couples a language-model patch proposer with a layered symbolic
verifier. The model proposes source-level migrations of quantum-vulnerable
cryptographic call sites (RSA, ECDSA, ECDH) to NIST-standardized primitives
(ML-KEM, ML-DSA, SLH-DSA); the verifier decides whether each patch is accepted,
rejected with rule-derived feedback for bounded re-proposal, or escalated to a
human. Every decision is recorded as a canonical, hashable trace that can be
attested with ML-DSA signatures.

The design premise is that the interesting question is not whether a model can
write a migration patch, but whether the pipeline can refuse the wrong one. A
patch that compiles and passes tests can still weaken parameters, fall back
silently to classical algorithms, or drop verification entirely. The verifier
exists to make those failures unshippable, and the evaluation measures how
often it succeeds.

This repository accompanies the manuscript *Catching Unsafe Patches: A
Rule-Verified Neuro-Symbolic Pipeline for Post-Quantum Cryptographic Code
Migration*.

## Architecture

```
detect ──► extract context ──► propose (LLM, cached) ──► verify ──► trace
                                    ▲                      │
                                    └── rule rationale ◄───┘  (≤ 3 attempts,
                                                               then escalate)
```

The verifier applies four layers in order, short-circuiting at the first
violation: **L1** syntactic rules over the patch, **L2** dataflow/typestate
rules over the patched program, **L3** build and test execution, **L4**
conformance against NIST test vectors and cross-provider interoperation.
Model responses are content-addressed and cached; in offline mode the cache is
read-only and a miss is a hard error, so published results reproduce without
network access.

## Quick start

Requires Python ≥ 3.11, `semgrep`, and a JDK on `PATH`.

```bash
pip install -e ".[dev]"
make smoke        # end-to-end pipeline on the seed corpus, offline
make test         # unit + rule-fixture suites
make lint typecheck
```

## Repository layout

| Path | Contents |
|---|---|
| `src/pqpatch/` | The pipeline: detector, extractor, proposer, verifier, trace, metrics |
| `policy/` | Migration policies (per-usage-class targets, floors, hybrid obligations) |
| `corpus/` | Evaluation corpora and the adversarial trap suite (see its README) |
| `experiments/` | Declarative experiment configurations |
| `containers/` | Pinned build environments for verification layers L3/L4 |
| `docs/` | Architecture decision records and the implementation status ledger |

## Status

This is a research artifact under active development. `docs/STATUS.md` is the
authoritative ledger of what is implemented versus specified; architecture
decisions, including those still open, are recorded in `docs/ADR/`. No
experimental results exist in this repository yet, by design: results are
generated exclusively from `runs/` manifests, and the table generator refuses
to emit rows it cannot back.

## License

MIT. Corpus entries retain the licenses of their upstream projects, recorded
in `corpus/tier3/manifest.yaml`.
