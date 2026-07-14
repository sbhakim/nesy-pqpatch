"""L1 syntactic rules.

Everything decidable from the patch's added lines alone: parameter floors and
validity, fallback shapes, exception discipline, randomness sources, hybrid
presence, diff scope, and the migration obligation. Properties that require
dataflow belong to L2. All fourteen class-mapped rules plus the two
cross-cutting ones (scope, obligation) are implemented; docs/STATUS.md is the
ledger.
"""

from __future__ import annotations

import re
from pathlib import Path

from pqpatch.model import Layer, Patch, Policy, RuleStatus, Site, UnsafeClass, UsageClass
from pqpatch.verifier.rules import ranks
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
# Ranks and the token pattern live in rules/ranks.py, shared with the L2 flow
# check (PQ-PARAM-02) so the floor comparison cannot drift between layers.

_TOKEN_RE = ranks.TOKEN_RE
_floor_rank = ranks.floor_rank
_token_rank = ranks.token_rank


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

# --- PQ-PARAM-03: U1 SLH-DSA parameter floor ---------------------------------
#
# PQ-PARAM-01 ranks only the ML-KEM/ML-DSA token grammar; SLH-DSA (FIPS 205)
# has its own ("SLH-DSA-SHA2-128s") and needs its own floor check.


def _check_slh_param_floor(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    floor = policy.floors.get(site.usage_class)
    if floor is None:
        return _PASS
    floor_rank = ranks.floor_rank(floor)
    if floor_rank is None:
        return _PASS

    for line in added_lines(patch.unified_diff):
        for match in ranks.SLH_TOKEN_RE.finditer(line):
            token_rank = ranks.SLH_CATEGORY_RANK.get(match.group(1))
            if token_rank is not None and token_rank < floor_rank:
                return RuleOutcome(
                    RuleStatus.FAIL,
                    detail=f"SLH-DSA parameter set {match.group(0)!r} (category rank "
                    f"{token_rank}) is below the policy floor {floor} "
                    f"(category rank {floor_rank})",
                )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-PARAM-03",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U1_PARAM_WEAKENING,
        cwe="CWE-326",
        severity="high",
        rationale=(
            "The proposed patch selects an SLH-DSA parameter set below the "
            "security category required by the migration policy. Re-propose "
            "using an SLH-DSA parameter set that meets or exceeds the floor."
        ),
        check=_check_slh_param_floor,
        fixtures_dir=_FIXTURES / "PQ-PARAM-03",
    )
)

# --- PQ-PARAM-04: U1 nonstandard PQ parameter set ----------------------------
#
# Models hallucinate parameter sets ("ML-KEM-256", "ML-DSA-128") that the
# standards do not define. PQ-PARAM-01 ranks only known tokens, so an unknown
# set slips past the floor check entirely; here it is rejected as invalid
# rather than merely unranked.

_MLKEM_SET_RE = re.compile(r"ML-KEM-(\d{2,4})")
_MLDSA_SET_RE = re.compile(r"ML-DSA-(\d{2,4})")
_SLH_SET_RE = re.compile(r"SLH-DSA-(?:SHA2|SHAKE)-(\d{2,4})")


def _check_nonstandard_param(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del site, policy
    for line in added_lines(patch.unified_diff):
        for pattern, valid, family in (
            (_MLKEM_SET_RE, ranks.VALID_MLKEM_SETS, "ML-KEM"),
            (_MLDSA_SET_RE, ranks.VALID_MLDSA_SETS, "ML-DSA"),
            (_SLH_SET_RE, ranks.VALID_SLH_SETS, "SLH-DSA"),
        ):
            for match in pattern.finditer(line):
                if match.group(1) not in valid:
                    return RuleOutcome(
                        RuleStatus.FAIL,
                        detail=f"{match.group(0)!r} is not a parameter set the {family} "
                        f"standard defines; the token is invalid, not merely weak",
                    )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-PARAM-04",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U1_PARAM_WEAKENING,
        cwe="CWE-327",
        severity="high",
        rationale=(
            "The proposed patch names a post-quantum parameter set that the "
            "FIPS standards do not define. Re-propose using a defined parameter "
            "set (ML-KEM-512/768/1024, ML-DSA-44/65/87, or SLH-DSA at category "
            "128/192/256)."
        ),
        check=_check_nonstandard_param,
        fixtures_dir=_FIXTURES / "PQ-PARAM-04",
    )
)

# --- PQ-PARAM-05: U1 classical key-size downgrade ----------------------------
#
# A migration patch that also *weakens the classical side* (e.g. re-keys the
# hybrid's RSA/DH component at 1024 bits) is a parameter downgrade even though
# no PQ token is involved. Only unambiguous sub-2048 modulus sizes are
# convicted; EC named-curve sizes (256/384/521) are not in the set.

_WEAK_KEYSIZE_RE = re.compile(r"\.initialize\s*\(\s*(512|768|1024)\s*[,)]")


def _check_classical_keysize_downgrade(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del site, policy
    for line in added_lines(patch.unified_diff):
        match = _WEAK_KEYSIZE_RE.search(line)
        if match:
            return RuleOutcome(
                RuleStatus.FAIL,
                detail=f"added code initializes key generation at {match.group(1)} bits, "
                f"below any accepted classical margin for a migration-era hybrid",
            )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-PARAM-05",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U1_PARAM_WEAKENING,
        cwe="CWE-326",
        severity="medium",
        rationale=(
            "The proposed patch initializes classical key generation below "
            "2048 bits. A migration must not weaken the classical component it "
            "retains; re-propose keeping classical parameters at or above "
            "current accepted margins."
        ),
        check=_check_classical_keysize_downgrade,
        fixtures_dir=_FIXTURES / "PQ-PARAM-05",
    )
)

# --- PQ-FALL-03: U2 runtime classical/PQ toggle ------------------------------
#
# PQ-FALL-01 needs a catch to fire. A conditional that selects between a PQ and
# a classical algorithm string at runtime is the same downgrade path without an
# exception handler: the classical branch stays reachable by flag.

_TERNARY_LITERALS_RE = re.compile(r'\?\s*"([^"]+)"\s*:\s*"([^"]+)"')
_PQ_TOKEN_ANY_RE = re.compile(r"ML-KEM|ML-DSA|SLH-DSA")
_CLASSICAL_LITERAL_RE = re.compile(r"RSA|(?<!ML-)ECDSA|(?<!ML-)(?<!SLH-)DSA|ECDH|DiffieHellman")


def _check_runtime_toggle(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del site, policy
    for line in added_lines(patch.unified_diff):
        for match in _TERNARY_LITERALS_RE.finditer(line):
            literals = (match.group(1), match.group(2))
            has_pq = any(_PQ_TOKEN_ANY_RE.search(lit) for lit in literals)
            has_classical = any(_CLASSICAL_LITERAL_RE.search(lit) for lit in literals)
            if has_pq and has_classical:
                return RuleOutcome(
                    RuleStatus.FAIL,
                    detail="added code selects between a post-quantum and a classical "
                    "algorithm at runtime; the classical branch remains reachable "
                    f"({line.strip()!r})",
                )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-FALL-03",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U2_CLASSICAL_FALLBACK,
        cwe="CWE-757",
        severity="high",
        rationale=(
            "The proposed patch chooses between a post-quantum and a classical "
            "algorithm with a runtime condition, leaving a reachable classical "
            "path behind a flag. Re-propose with the post-quantum primitive "
            "unconditional."
        ),
        check=_check_runtime_toggle,
        fixtures_dir=_FIXTURES / "PQ-FALL-03",
    )
)

# --- PQ-FALL-04: U2 algorithm retry inside a handler -------------------------
#
# Acquiring *any* algorithm inside a catch block is a downgrade-on-failure
# path, even when the retried algorithm is itself post-quantum (e.g. catching
# and retrying with ML-KEM-512). Only simple, brace-free catch bodies are
# convicted at L1; nested shapes are control-flow and belong to a future CFG.

_GETINSTANCE_IN_CATCH_RE = re.compile(
    r"catch\s*\([^)]*\)\s*\{[^{}]*getInstance", re.DOTALL
)


def _check_retry_in_catch(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del site, policy
    joined = "\n".join(added_lines(patch.unified_diff))
    if _GETINSTANCE_IN_CATCH_RE.search(joined):
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="added code acquires an algorithm inside an exception handler; "
            "retrying a different algorithm on failure is a downgrade path",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-FALL-04",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U2_CLASSICAL_FALLBACK,
        cwe="CWE-757",
        severity="high",
        rationale=(
            "The proposed patch calls getInstance inside a catch block, so a "
            "failure of the migrated primitive silently retries another "
            "algorithm. Re-propose letting the failure propagate instead of "
            "downgrading."
        ),
        check=_check_retry_in_catch,
        fixtures_dir=_FIXTURES / "PQ-FALL-04",
    )
)

# --- PQ-EXC-01: U7 catch that returns success --------------------------------

_RETURN_TRUE_IN_CATCH_RE = re.compile(
    r"catch\s*\([^)]*\)\s*\{[^{}]*return\s+true", re.DOTALL
)


def _check_catch_returns_success(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del site, policy
    joined = "\n".join(added_lines(patch.unified_diff))
    if _RETURN_TRUE_IN_CATCH_RE.search(joined):
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="added catch block returns true; a cryptographic failure is "
            "converted into a success result",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-EXC-01",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U7_FAIL_OPEN,
        cwe="CWE-636",
        severity="high",
        rationale=(
            "The proposed patch returns success from an exception handler, so "
            "a failed cryptographic operation is indistinguishable from a "
            "successful one. Re-propose with failures propagated or reported "
            "as failures."
        ),
        check=_check_catch_returns_success,
        fixtures_dir=_FIXTURES / "PQ-EXC-01",
    )
)

# --- PQ-EXC-02: U7 log-only exception swallow --------------------------------
#
# The classic swallow: a catch whose entire body is one logging statement, so
# execution continues as if the operation had succeeded. Only single-statement
# bodies are convicted; a body that also throws or returns is not a swallow.

_LOG_ONLY_CATCH_RE = re.compile(
    r"catch\s*\([^)]*\)\s*\{\s*"
    r"(?:[A-Za-z_][\w.]*\.)?(?:printStackTrace|println|print|log|warn|info|error|debug)"
    r"[^;{}]*;\s*\}",
    re.DOTALL,
)


def _check_log_only_swallow(patch: Patch, site: Site, policy: Policy) -> RuleOutcome:
    del site, policy
    joined = "\n".join(added_lines(patch.unified_diff))
    if _LOG_ONLY_CATCH_RE.search(joined):
        return RuleOutcome(
            RuleStatus.FAIL,
            detail="added catch block only logs and continues; the cryptographic "
            "failure is swallowed and execution proceeds as success",
        )
    return _PASS


register(
    RuleSpec(
        rule_id="PQ-EXC-02",
        layer=Layer.L1_SYNTACTIC,
        unsafe_class=UnsafeClass.U7_FAIL_OPEN,
        cwe="CWE-390",
        severity="high",
        rationale=(
            "The proposed patch catches a cryptographic exception, logs it, and "
            "continues, so failure does not stop the operation. Re-propose "
            "rethrowing or failing closed after logging."
        ),
        check=_check_log_only_swallow,
        fixtures_dir=_FIXTURES / "PQ-EXC-02",
    )
)
