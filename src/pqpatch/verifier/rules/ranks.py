"""Security-category ranks for post-quantum parameter tokens.

Shared by the L1 token check (PQ-PARAM-01) and the L2 flow check (PQ-PARAM-02)
so the floor comparison can never drift between layers. Ranks follow the NIST
security categories (1/3/5); ML-DSA-44 sits at category 2.
"""

from __future__ import annotations

import re

KEM_RANK = {"ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5}
SIG_RANK = {"ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5}
TOKEN_RE = re.compile(r"ML-(?:KEM|DSA)-\d{2,4}")

# SLH-DSA (FIPS 205) has its own token grammar: SLH-DSA-<hash>-<category><s|f>,
# e.g. "SLH-DSA-SHA2-128s". Security category follows the digit group.
SLH_TOKEN_RE = re.compile(r"SLH-DSA-(?:SHA2|SHAKE)-(\d{3})[sfSF]")
SLH_CATEGORY_RANK = {"128": 1, "192": 3, "256": 5}

# The parameter sets the standards actually define. Anything else spelled in a
# PQ token shape (e.g. a hallucinated "ML-KEM-256") is invalid, not merely weak.
VALID_MLKEM_SETS = frozenset({"512", "768", "1024"})
VALID_MLDSA_SETS = frozenset({"44", "65", "87"})
VALID_SLH_SETS = frozenset({"128", "192", "256"})


def floor_rank(floor: str) -> int | None:
    return KEM_RANK.get(floor) or SIG_RANK.get(floor)


def token_rank(token: str) -> int | None:
    return KEM_RANK.get(token) or SIG_RANK.get(token)


def slh_token_rank(token: str) -> int | None:
    """Category rank of one SLH-DSA token, or None if it is not one."""
    match = SLH_TOKEN_RE.search(token)
    if match is None:
        return None
    return SLH_CATEGORY_RANK.get(match.group(1))
