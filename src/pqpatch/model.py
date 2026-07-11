"""Core data model.

All cross-module payloads are frozen dataclasses defined here. Immutability
is load-bearing: the trace recorder hashes these values, so nothing
downstream may revise a fact after it has been recorded.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path


class UsageClass(enum.StrEnum):
    """The five usage classes of Manuscript-ACM/main.tex Sec. 4 (Formal Task Definition)."""

    SIGN = "sign"
    VERIFY = "verify"
    KEM = "kem"
    ENVELOPE = "envelope"
    CONFIG = "config"


class UnsafeClass(enum.StrEnum):
    """The seven unsafe-patch classes U1-U7 (Manuscript-ACM/main.tex Sec. 3.1)."""

    U1_PARAM_WEAKENING = "U1"
    U2_CLASSICAL_FALLBACK = "U2"
    U3_UNCHECKED_VERIFY = "U3"
    U4_KEY_CONFUSION = "U4"
    U5_RANDOMNESS_MISUSE = "U5"
    U6_HYBRID_DOWNGRADE = "U6"
    U7_FAIL_OPEN = "U7"


class Layer(enum.IntEnum):
    """Verifier layers in evaluation order (manuscript Eq. 1)."""

    L1_SYNTACTIC = 1
    L2_DATAFLOW = 2
    L3_BUILD = 3
    L4_CONFORMANCE = 4


class RuleStatus(enum.StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"  # the check itself failed to run; must never be conflated with PASS
    SKIPPED = "skipped"  # layer not active in this configuration; see Verdict.layers_evaluated


class VerdictStatus(enum.StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    ESCALATE = "escalate"
    ERROR = "error"  # per-site pipeline failure; codebase-plan.md §4 "errors are records"


@dataclass(frozen=True, slots=True)
class Site:
    """A detected quantum-vulnerable call site."""

    site_id: str
    repo: str
    file_path: str
    line: int
    usage_class: UsageClass
    matched_symbol: str
    detector_rule_id: str


@dataclass(frozen=True, slots=True)
class Context:
    """Extracted context handed to the proposer (extractor/context.py)."""

    site: Site
    enclosing_method: str
    enclosing_class: str
    caller_snippets: tuple[str, ...] = field(default_factory=tuple)
    callee_snippets: tuple[str, ...] = field(default_factory=tuple)
    config_excerpts: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class Policy:
    """Migration policy Pi: usage-class -> permitted target, floor, hybrid obligation.

    Loaded from policy/*.yaml via policy_from_dict(); this type is what every
    downstream module actually consumes, never the raw YAML.
    """

    name: str
    version: str
    floors: dict[UsageClass, str]  # e.g. {UsageClass.KEM: "ML-KEM-768"}
    hybrid_required: dict[UsageClass, bool]
    allowed_randomness_sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Patch:
    """A candidate migration patch proposed by a Backend."""

    site_id: str
    attempt: int
    unified_diff: str
    claimed_primitive: str
    claimed_parameters: str
    backend_id: str
    prompt_version: str
    response_hash: str  # sha256 of the raw cached response; see proposer/cache.py


@dataclass(frozen=True, slots=True)
class RuleResult:
    """The outcome of a single rule evaluated against a single patch."""

    rule_id: str
    layer: Layer
    status: RuleStatus
    unsafe_class: UnsafeClass | None
    rationale: str  # natural-language text fed back to the proposer on REJECT
    duration_ms: float
    detail: str = ""


@dataclass(frozen=True, slots=True)
class LayerReport:
    """All rule results produced while evaluating one layer against one patch."""

    layer: Layer
    results: tuple[RuleResult, ...]
    duration_ms: float

    @property
    def passed(self) -> bool:
        """True if no rule failed or errored. SKIPPED does not block the
        next layer, but it is a distinct recorded fact; consumers must not
        read an accept built on skipped layers as a full verification."""
        return all(r.status in (RuleStatus.PASS, RuleStatus.SKIPPED) for r in self.results)

    @property
    def skipped(self) -> bool:
        return any(r.status == RuleStatus.SKIPPED for r in self.results)

    @property
    def first_failure(self) -> RuleResult | None:
        for r in self.results:
            if r.status in (RuleStatus.FAIL, RuleStatus.ERROR):
                return r
        return None


@dataclass(frozen=True, slots=True)
class Verdict:
    """Outcome of verifying one patch, or of the whole per-site loop.

    `layers_evaluated` records which layers actually ran. An accept backed
    by fewer than all four layers is a partial verification, and every
    aggregation in eval/ must consult this field before counting it.
    """

    site_id: str
    status: VerdictStatus
    accepted_patch: Patch | None
    rejected_rule_id: str | None
    layer_reports: tuple[LayerReport, ...]
    attempts_used: int
    layers_evaluated: tuple[Layer, ...] = ()


@dataclass(frozen=True, slots=True)
class TraceEvent:
    """One entry in a site's canonical decision trace (trace/canonical.py)."""

    attempt: int
    layer: Layer | None
    status: str
    rule_id: str | None
    timings_ms: dict[str, float]


@dataclass(frozen=True, slots=True)
class TraceRecord:
    """The full canonical, hashable, optionally ML-DSA-signed decision trace."""

    site: Site
    usage_class: UsageClass
    policy_version: str
    ruleset_version: str
    events: tuple[TraceEvent, ...]
    verdict: Verdict
    content_hash: str = ""  # populated by trace/canonical.py, never set by callers
    signature: str | None = None


@dataclass(frozen=True, slots=True)
class RunManifest:
    """Written beside every runs/<config-hash>/ directory (codebase-plan.md invariant 4)."""

    config_hash: str
    config_path: Path
    git_sha: str
    created_at_utc: str
    offline: bool
    seeds: tuple[int, ...]
    backend_ids: tuple[str, ...]
