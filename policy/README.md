# Migration policies

A policy defines, per usage class, the permitted post-quantum target, the
minimum parameter set (the "floor"), whether a hybrid classical+PQ
construction is mandatory, and the approved randomness sources. Policies are
versioned YAML validated against `schema.json`; the pipeline consumes them
only through `pqpatch.policy.load_policy`, never as raw dictionaries.

Policies are inputs, not constants. Changing an organization's floor from
category 1 to category 3 is an edit to one file followed by re-verification —
this is the operational meaning of crypto-agility in this system, and the
`default.yaml` / `strict.yaml` pair exists so that the policy's effect on
verification outcomes is itself measurable.

Verifier rules read the policy at check time; no rule may hard-code a
parameter floor.
