"""L1 syntactic rules.

Everything decidable from the patch's added lines alone: parameter floors,
fallback shapes, randomness sources, hybrid presence, and diff scope.
Properties that require dataflow belong to L2. Nine of the planned fourteen
rules are implemented; docs/STATUS.md tracks the remainder.
"""

from __future__ import annotations

import re
from pathlib import Path

from pqpatch.model import Layer, Patch, Policy, RuleStatus, Site, UnsafeClass, UsageClass
from pqpatch.verifier.rules.diffutil import (
    added_lines,
    path_in_scope,
    removed_lines,
    touched_files,
)
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

# --- PQ-KEY-01: U4 primitive-family mismatch -------------------------------
#
# This is intentionally narrower than key-confusion dataflow analysis, which
# belongs to L2.  L1 can still reject the unambiguous surface case where a KEM
# site introduces only a signature primitive, or a signature site introduces
# only a KEM primitive.  If both families occur, the patch may be implementing
# a legitimate composed protocol and this rule defers rather than guessing.

_KEM_PRIMITIVE_RE = re.compile(r"ML-(?:KEM)(?:-\d{3,4})?|MLKEM(?:\d{3,4})?")
_SIGNATURE_PRIMITIVE_RE = re.compile(
    r"ML-(?:DSA)(?:-\d{2})?|MLDSA(?:\d{2})?|SLH-(?:DSA)|SLHDSA"
)


def _check_primitive_family(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del policy
    joined = "\n".join(added_lines(patch.unified_diff))
    has_kem = bool(_KEM_PRIMITIVE_RE.search(joined))
    has_signature = bool(_SIGNATURE_PRIMITIVE_RE.search(joined))

    if site.usage_class in {UsageClass.KEM, UsageClass.ENVELOPE} and has_signature and not has_kem:
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="key-establishment site introduces only a signature primitive; "
            "ML-KEM is required for KEM/envelope usage",
        )
    if site.usage_class in {UsageClass.SIGN, UsageClass.VERIFY} and has_kem and not has_signature:
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="signature site introduces only a key-establishment primitive; "
            "ML-DSA or SLH-DSA is required for sign/verify usage",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-KEY-01",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U4_KEY_CONFUSION,
        cwe="CWE-327",
        severity="high",
        rationale=(
            "The proposed patch uses a post-quantum primitive from the wrong "
            "algorithm family for this site: ML-KEM is for key establishment, "
            "while ML-DSA and SLH-DSA are for signatures. Re-propose using the "
            "family required by the detected usage class."
        ),
        check=_check_primitive_family,
        fixtures_dir=_FIXTURES / "PQ-KEY-01",
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

# --- PQ-RAND-02: U5 literal SecureRandom seed -------------------------------
#
# Only self-contained literal seeds are rejected here.  A setSeed(...) call is
# not enough evidence at L1: whether it is the sole source of entropy depends on
# object construction and call order, so that case is deliberately left to L2.

_LITERAL_SECURE_RANDOM_SEED_RE = re.compile(
    r"new\s+SecureRandom\s*\(\s*(?:"
    r"new\s+byte\s*\[\s*\]\s*\{|"
    r'"(?:[^"\\]|\\.)*"\s*\.\s*getBytes\s*\('
    r")",
    re.DOTALL,
)


def _check_literal_secure_random_seed(
    patch: Patch, site: Site, policy: Policy
) -> RuleOutcome:
    del site, policy
    joined = "\n".join(added_lines(patch.unified_diff))
    if _LITERAL_SECURE_RANDOM_SEED_RE.search(joined):
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="SecureRandom is constructed from a fixed literal seed; "
            "key generation must obtain entropy from the platform source",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-RAND-02",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U5_RANDOMNESS_MISUSE,
        cwe="CWE-337",
        severity="high",
        rationale=(
            "The proposed patch constructs SecureRandom from a fixed literal "
            "seed, making generated cryptographic material reproducible. "
            "Re-propose using a platform-seeded SecureRandom without literal "
            "seed material."
        ),
        check=_check_literal_secure_random_seed,
        fixtures_dir=_FIXTURES / "PQ-RAND-02",
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
    # Match by normalized path, not exact string: a correctly scoped patch may
    # spell the target file as a basename, a repo-relative path, or an absolute
    # one depending on the model, and a//b/ prefixes and leading slashes vary.
    # path_in_scope treats those as the same file while still rejecting a
    # genuinely different one (see diffutil.path_in_scope).
    unexpected = sorted(
        f for f in touched_files(patch.unified_diff) if not path_in_scope(f, site.file_path)
    )
    if unexpected:
        return RuleOutcome(
            RuleStatus.FAIL,
            detail=f"patch modifies file(s) outside the permitted scope: {unexpected}",
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

# --- PQ-MIG-01: migration obligation (no specific U-class) ------------------
#
# Every other rule is a prohibition ("do not weaken / fall back / drop
# verification"); a patch that changes nothing satisfies all of them. This rule
# supplies the missing positive obligation from the formal task -- the detected
# vulnerable primitive must actually be replaced by a permitted post-quantum one
# -- so a vacuous or misdirected patch cannot be accepted while leaving the
# quantum-vulnerable call in place. (Found by a real run: local models produced
# no-op patches the verifier accepted.)

_PQ_PRIMITIVE_RE = re.compile(r"ML-KEM|ML-DSA|SLH-DSA")
# Classical primitives whose removal marks a genuine migration at the site.
# (?<!ML-) keeps the migrated primitive itself from matching as "classical".
_CLASSICAL_AT_SITE_RE = re.compile(r'RSA|ECDSA|(?<!ML-)DSA|ECDH|DiffieHellman|3?DES|"EC"')


def _check_migration_obligation(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del site, policy
    if not any(_PQ_PRIMITIVE_RE.search(line) for line in added_lines(patch.unified_diff)):
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="patch introduces no permitted post-quantum primitive "
            "(ML-KEM/ML-DSA/SLH-DSA); the vulnerable site is not migrated",
        )
    if not any(_CLASSICAL_AT_SITE_RE.search(line) for line in removed_lines(patch.unified_diff)):
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="patch removes no classical primitive; the migration is vacuous "
            "(the quantum-vulnerable call is left in place)",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-MIG-01",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=None,
        cwe="CWE-327",
        severity="high",
        rationale=(
            "The proposed patch does not actually migrate the site: it must "
            "replace the classical primitive with a permitted post-quantum one "
            "(ML-KEM, ML-DSA, or SLH-DSA), not merely edit around it."
        ),
        check=_check_migration_obligation,
        fixtures_dir=_FIXTURES / "PQ-MIG-01",
    )
)
