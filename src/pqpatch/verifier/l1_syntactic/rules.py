"""L1 syntactic rules.

Everything decidable from the patch's added lines alone: parameter floors,
fallback shapes, randomness sources, hybrid presence, and diff scope.
Properties that require dataflow belong to L2. Six of the planned fourteen
rules are implemented; docs/STATUS.md tracks the remainder.
"""

from __future__ import annotations

import re
from pathlib import Path

from pqpatch.model import Layer, Patch, Policy, RuleStatus, Site, UnsafeClass
from pqpatch.verifier.rules.diffutil import added_lines, touched_files
from pqpatch.verifier.rules.registry import register
from pqpatch.verifier.rules.spec import RuleOutcome, RuleSpec

_FIXTURES = Path(__file__).parent / "fixtures"

_PASS = RuleOutcome(RuleStatus.PASS)

# --- PQ-PARAM-01: U1 parameter weakening -----------------------------------

_KEM_RANK = {"ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5}
_SIG_RANK = {"ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5}
_TOKEN_RE = re.compile(r"ML-(?:KEM|DSA)-\d{2,4}")


def _floor_rank(floor: str) -> int | None:
    return _KEM_RANK.get(floor) or _SIG_RANK.get(floor)


def _token_rank(token: str) -> int | None:
    return _KEM_RANK.get(token) or _SIG_RANK.get(token)


def _check_param_weakening(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    floor = policy.floors.get(site.usage_class)
    if floor is None:
        return _PASS
    floor_rank = _floor_rank(floor)
    if floor_rank is None:
        return _PASS

    for line in added_lines(patch.unified_diff):
        for token in _TOKEN_RE.findall(line):
            token_rank = _token_rank(token)
            if token_rank is not None and token_rank < floor_rank:
                return RuleOutcome(
                    RuleStatus.FAIL,
                    detail=f"parameter {token} (category rank {token_rank}) is below "
                    f"the policy floor {floor} (category rank {floor_rank})",
                )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-PARAM-01",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U1_PARAM_WEAKENING,
        cwe="CWE-326",
        severity="high",
        rationale=(
            "The proposed patch selects a post-quantum parameter set below the "
            "security category required by the migration policy for this usage "
            "class. Re-propose using a parameter set that meets or exceeds the "
            "policy floor."
        ),
        check=_check_param_weakening,
        fixtures_dir=_FIXTURES / "PQ-PARAM-01",
    )
)

# --- PQ-FALL-01: U2 classical fallback --------------------------------------

# JCA algorithm names are fused identifiers ("SHA256withRSA"), so word
# boundaries cannot separate the classical token; substring matching is
# required. The one collision that matters is "DSA" inside "ML-DSA" -- the
# migrated primitive itself -- excluded via negative lookbehind.
_CLASSICAL_TOKEN_PATTERNS = {
    "RSA": re.compile(r"RSA"),
    "ECDSA": re.compile(r"(?<!ML-)ECDSA"),
    "DSA": re.compile(r"(?<!ML-)DSA"),
    "DES": re.compile(r"DES"),
    "3DES": re.compile(r"3DES"),
    "DiffieHellman": re.compile(r"DiffieHellman"),
}


def _check_classical_fallback(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del site, policy
    lines = added_lines(patch.unified_diff)
    has_catch = any("catch" in line for line in lines)
    if not has_catch:
        return _PASS
    for line in lines:
        for name, pattern in _CLASSICAL_TOKEN_PATTERNS.items():
            if pattern.search(line):
                return RuleOutcome(
                    RuleStatus.FAIL,
                    detail=f"added code contains both an exception handler and the "
                    f"classical primitive token {name!r}, consistent with a "
                    f"silent classical fallback path",
                )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-FALL-01",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U2_CLASSICAL_FALLBACK,
        cwe="CWE-757",
        severity="high",
        rationale=(
            "The proposed patch introduces an exception handler alongside a "
            "classical cryptographic primitive, consistent with a reachable "
            "fallback to classical crypto. Re-propose without a classical "
            "fallback path; failures must propagate, not silently downgrade."
        ),
        check=_check_classical_fallback,
        fixtures_dir=_FIXTURES / "PQ-FALL-01",
    )
)

# --- PQ-FALL-02: U7 fail-open error handling --------------------------------

_EMPTY_CATCH_RE = re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}", re.DOTALL)


def _check_fail_open(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del site, policy
    joined = "\n".join(added_lines(patch.unified_diff))
    if _EMPTY_CATCH_RE.search(joined):
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="added code contains an empty catch block; cryptographic "
            "exceptions must not be silently swallowed",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-FALL-02",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U7_FAIL_OPEN,
        cwe="CWE-390",
        severity="high",
        rationale=(
            "The proposed patch contains an empty exception handler around "
            "cryptographic operations, making failure indistinguishable from "
            "success. Re-propose with the exception logged and re-thrown or "
            "otherwise handled explicitly."
        ),
        check=_check_fail_open,
        fixtures_dir=_FIXTURES / "PQ-FALL-02",
    )
)

# --- PQ-RAND-01: U5 randomness misuse ---------------------------------------

_DISALLOWED_RANDOM_RE = re.compile(r"new\s+Random\s*\(|Math\.random\s*\(")


def _check_randomness(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del site, policy
    for line in added_lines(patch.unified_diff):
        if _DISALLOWED_RANDOM_RE.search(line):
            return RuleOutcome(
                RuleStatus.FAIL,
                detail=f"added line uses a non-cryptographic randomness source: {line.strip()!r}",
            )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-RAND-01",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U5_RANDOMNESS_MISUSE,
        cwe="CWE-338",
        severity="high",
        rationale=(
            "The proposed patch seeds key material or nonces from a "
            "non-cryptographic randomness source (java.util.Random or "
            "Math.random). Re-propose using an approved SecureRandom source."
        ),
        check=_check_randomness,
        fixtures_dir=_FIXTURES / "PQ-RAND-01",
    )
)

# --- PQ-HYB-01: U6 hybrid downgrade -----------------------------------------

_CLASSICAL_KEX_RE = re.compile(r"X25519(?!MLKEM)|ECDH")
_MLKEM_RE = re.compile(r"ML-KEM|MLKEM")


def _check_hybrid_downgrade(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    if not policy.hybrid_required.get(site.usage_class, False):
        return _PASS
    lines = added_lines(patch.unified_diff)
    joined = "\n".join(lines)
    has_mlkem = bool(_MLKEM_RE.search(joined))
    has_classical_kex = bool(_CLASSICAL_KEX_RE.search(joined))
    if has_mlkem and not has_classical_kex:
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="policy requires a hybrid construction for this usage class, but "
            "the added code contains only the post-quantum component "
            "(no classical X25519/ECDH contribution)",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-HYB-01",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U6_HYBRID_DOWNGRADE,
        cwe="CWE-327",
        severity="high",
        rationale=(
            "The migration policy requires a hybrid classical+post-quantum "
            "construction for this usage class, but the proposed patch drops "
            "the classical component. Re-propose retaining both key-exchange "
            "contributions."
        ),
        check=_check_hybrid_downgrade,
        fixtures_dir=_FIXTURES / "PQ-HYB-01",
    )
)

# --- PQ-SCOPE-01: diff scope integrity (no specific U-class) ----------------


def _check_scope(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del policy
    files = touched_files(patch.unified_diff)
    unexpected = files - {site.file_path}
    if unexpected:
        return RuleOutcome(
            RuleStatus.FAIL,
            detail=f"patch modifies file(s) outside the permitted scope: {sorted(unexpected)}",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-SCOPE-01",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=None,
        cwe="CWE-668",
        severity="medium",
        rationale=(
            "The proposed patch modifies files outside the migration site's "
            "own file. Re-propose a patch scoped only to the target file."
        ),
        check=_check_scope,
        fixtures_dir=_FIXTURES / "PQ-SCOPE-01",
    )
)
