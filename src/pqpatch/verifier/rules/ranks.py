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


def floor_rank(floor: str) -> int | None:
    return KEM_RANK.get(floor) or SIG_RANK.get(floor)


def token_rank(token: str) -> int | None:
    return KEM_RANK.get(token) or SIG_RANK.get(token)
