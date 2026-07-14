"""Tree-sitter-backed intraprocedural Java def-use.

The frontend extracts structural invocation, assignment, branch, and return
events. Two analyses are built on it: verification-result use (``PQ-VER-01``)
and cross-family key flow (``PQ-KEY-02``). The analysis remains deliberately
local: unsupported syntax and parse errors are indeterminate, never silently
accepted as proof.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Iterator
from dataclasses import dataclass

import tree_sitter_java
from tree_sitter import Language, Node, Parser


class VerifyUse(enum.StrEnum):
    CHECKED = "checked"
    DISCARDED = "discarded"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class _Event:
    position: int
    kind: str
    left: str | None = None
    right: str | None = None
    used_names: frozenset[str] = frozenset()
    declaration: bool = False


_LANGUAGE = Language(tree_sitter_java.language())


def _walk(node: Node) -> Iterator[Node]:
    yield node
    for child in node.named_children:
        yield from _walk(child)


def _walk_method(method: Node) -> Iterator[Node]:
    """Walk one executable body without leaking facts from nested scopes."""
    excluded_scopes = {
        "class_body",
        "class_declaration",
        "constructor_declaration",
        "enum_declaration",
        "interface_declaration",
        "lambda_expression",
        "method_declaration",
        "record_declaration",
    }
    yield method

    def visit(node: Node) -> Iterator[Node]:
        for child in node.named_children:
            if child.type in excluded_scopes:
                continue
            yield child
            yield from visit(child)

    yield from visit(method)


def _text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8")


def _method_ancestor(node: Node) -> Node | None:
    current: Node | None = node
    while current is not None:
        if current.type == "lambda_expression":
            return None
        if current.type in {"method_declaration", "constructor_declaration"}:
            return current
        current = current.parent
    return None


def _contains(container: Node | None, child: Node) -> bool:
    return bool(
        container is not None
        and container.start_byte <= child.start_byte
        and child.end_byte <= container.end_byte
    )


def _identifier_names(source: bytes, node: Node | None) -> frozenset[str]:
    if node is None:
        return frozenset()
    return frozenset(_text(source, item) for item in _walk(node) if item.type == "identifier")


def _simple_identifier(source: bytes, node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type == "identifier":
        return _text(source, node)
    if node.type == "unary_expression":
        identifiers = [item for item in _walk(node) if item.type == "identifier"]
        if len(identifiers) == 1:
            return _text(source, identifiers[0])
    return None


def _verify_context(source: bytes, invocation: Node, method: Node) -> tuple[str, str | None]:
    current = invocation.parent
    while current is not None and current != method:
        if current.type == "return_statement":
            return "sink", None
        if current.type in {
            "if_statement",
            "while_statement",
            "do_statement",
            "for_statement",
            "ternary_expression",
        } and _contains(current.child_by_field_name("condition"), invocation):
            return "sink", None
        if current.type == "variable_declarator":
            return "assigned", _text(source, current.child_by_field_name("name"))
        if current.type == "assignment_expression":
            left = current.child_by_field_name("left")
            if left is not None and left.type == "identifier":
                return "assigned", _text(source, left)
            return "indeterminate", None
        if current.type == "expression_statement":
            return "discarded", None
        current = current.parent
    return "indeterminate", None


def _events_after(source: bytes, method: Node, position: int) -> list[_Event]:
    events: list[_Event] = []
    for node in _walk_method(method):
        if node.start_byte <= position:
            continue
        if node.type == "variable_declarator":
            left = _text(source, node.child_by_field_name("name"))
            right = _simple_identifier(source, node.child_by_field_name("value"))
            events.append(
                _Event(
                    node.start_byte,
                    "assign",
                    left=left,
                    right=right,
                    declaration=True,
                )
            )
        elif node.type == "assignment_expression":
            left_node = node.child_by_field_name("left")
            if left_node is not None and left_node.type == "identifier":
                events.append(
                    _Event(
                        node.start_byte,
                        "assign",
                        left=_text(source, left_node),
                        right=_simple_identifier(source, node.child_by_field_name("right")),
                    )
                )
        elif node.type in {
            "if_statement",
            "while_statement",
            "do_statement",
            "for_statement",
            "ternary_expression",
        }:
            condition = node.child_by_field_name("condition")
            events.append(
                _Event(
                    node.start_byte,
                    "sink",
                    used_names=_identifier_names(source, condition),
                )
            )
        elif node.type == "return_statement":
            events.append(
                _Event(
                    node.start_byte,
                    "sink",
                    used_names=_identifier_names(source, node),
                )
            )
    return sorted(events, key=lambda event: event.position)


def _assigned_result_use(
    source: bytes,
    method: Node,
    invocation: Node,
    root: str,
) -> VerifyUse:
    tracked = {root}
    for event in _events_after(source, method, invocation.end_byte):
        if event.kind == "sink" and tracked.intersection(event.used_names):
            return VerifyUse.CHECKED
        if event.kind != "assign" or event.left is None:
            continue
        if event.declaration and event.left in tracked:
            # A same-named declaration is a shadowing boundary. This bounded
            # analysis deliberately refuses to infer lexical symbol identity.
            return VerifyUse.INDETERMINATE
        source_was_tracked = event.right in tracked
        tracked.discard(event.left)
        if source_was_tracked:
            tracked.add(event.left)
        if not tracked:
            return VerifyUse.DISCARDED
    return VerifyUse.DISCARDED


def classify_verify_uses(source: str) -> list[VerifyUse]:
    """Classify every structurally parsed Java ``verify`` invocation."""
    source_bytes = source.encode("utf-8")
    tree = Parser(_LANGUAGE).parse(source_bytes)
    if tree.root_node.has_error:
        return [VerifyUse.INDETERMINATE]

    outcomes: list[VerifyUse] = []
    for node in _walk(tree.root_node):
        if node.type != "method_invocation":
            continue
        if _text(source_bytes, node.child_by_field_name("name")) != "verify":
            continue
        method = _method_ancestor(node)
        if method is None:
            outcomes.append(VerifyUse.INDETERMINATE)
            continue
        context, assigned_name = _verify_context(source_bytes, node, method)
        if context == "sink":
            outcomes.append(VerifyUse.CHECKED)
        elif context == "discarded":
            outcomes.append(VerifyUse.DISCARDED)
        elif context == "assigned" and assigned_name:
            outcomes.append(_assigned_result_use(source_bytes, method, node, assigned_name))
        else:
            outcomes.append(VerifyUse.INDETERMINATE)
    return outcomes


# --- PQ-KEY-02: cross-family key flow --------------------------------------
#
# The L1 rule (PQ-KEY-01) rejects the unambiguous single-family surface case and
# defers when both families appear. This analysis handles the deferred case
# structurally: a key object produced for one algorithm family must not flow into
# an operation of the other family. Family is anchored on two facts already in
# reach without Java type resolution -- the algorithm string literal at a
# key-producing getInstance, and the method name at a key-consuming sink. Only an
# unambiguous cross-family flow is convicted; classical/ambiguous literals and
# interprocedural sources stay unconvicted (the bounded scope, documented in
# ADR-001), and a parse error is indeterminate.


class KeyFlow(enum.StrEnum):
    CONSISTENT = "consistent"
    CROSS_FAMILY = "cross_family"
    INDETERMINATE = "indeterminate"


class _Family(enum.StrEnum):
    KEM = "kem"
    SIG = "sig"


_KEM_LITERAL_RE = re.compile(r"ML-?KEM")
_SIG_LITERAL_RE = re.compile(r"ML-?DSA|SLH-?DSA")
# Receivers whose getInstance produces a key or key-pair (not a Signature/Cipher).
_KEY_SOURCE_RECEIVERS = frozenset({"KeyPairGenerator", "KeyGenerator", "KeyEncapsulation"})
# Key-consuming sinks whose method name unambiguously reveals the family.
_SIG_SINKS = frozenset({"initSign", "initVerify"})
_KEM_SINKS = frozenset({"doPhase"})


def _family_of_literals(text: str) -> _Family | None:
    """The definite PQC family named by a fragment of source, or None."""
    kem = bool(_KEM_LITERAL_RE.search(text))
    sig = bool(_SIG_LITERAL_RE.search(text))
    if kem and not sig:
        return _Family.KEM
    if sig and not kem:
        return _Family.SIG
    return None


def _key_source_family(source: bytes, rhs: Node | None) -> _Family | None:
    """Family of the key an assignment right-hand side produces, if determinable.

    Definite only when the RHS contains a key-producing ``getInstance`` whose
    receiver is a known key source and whose arguments name exactly one PQC
    family. Anything else (a Signature.getInstance, a classical literal, no
    literal) is not a definite key source.
    """
    if rhs is None:
        return None
    for node in _walk(rhs):
        if node.type != "method_invocation":
            continue
        if _text(source, node.child_by_field_name("name")) != "getInstance":
            continue
        receiver = _text(source, node.child_by_field_name("object"))
        if receiver not in _KEY_SOURCE_RECEIVERS:
            continue
        family = _family_of_literals(_text(source, node.child_by_field_name("arguments")))
        if family is not None:
            return family
    return None


@dataclass(frozen=True, slots=True)
class _FlowStep:
    position: int
    kind: str  # "assign" | "sink"
    # assign:
    left: str | None = None
    source_family: _Family | None = None
    alias_names: frozenset[str] = frozenset()
    # sink:
    sink_family: _Family | None = None
    used_names: frozenset[str] = frozenset()


def _flow_steps(source: bytes, method: Node) -> list[_FlowStep]:
    steps: list[_FlowStep] = []
    for node in _walk_method(method):
        if node.type == "variable_declarator":
            left = _text(source, node.child_by_field_name("name"))
            rhs = node.child_by_field_name("value")
            steps.append(
                _FlowStep(
                    node.start_byte,
                    "assign",
                    left=left,
                    source_family=_key_source_family(source, rhs),
                    alias_names=_identifier_names(source, rhs),
                )
            )
        elif node.type == "assignment_expression":
            left_node = node.child_by_field_name("left")
            if left_node is not None and left_node.type == "identifier":
                rhs = node.child_by_field_name("right")
                steps.append(
                    _FlowStep(
                        node.start_byte,
                        "assign",
                        left=_text(source, left_node),
                        source_family=_key_source_family(source, rhs),
                        alias_names=_identifier_names(source, rhs),
                    )
                )
        elif node.type == "method_invocation":
            name = _text(source, node.child_by_field_name("name"))
            sink_family = (
                _Family.SIG if name in _SIG_SINKS else _Family.KEM if name in _KEM_SINKS else None
            )
            if sink_family is not None:
                steps.append(
                    _FlowStep(
                        node.start_byte,
                        "sink",
                        sink_family=sink_family,
                        used_names=_identifier_names(source, node.child_by_field_name("arguments")),
                    )
                )
    return sorted(steps, key=lambda step: step.position)


def _analyze_key_flow(source: bytes, method: Node) -> KeyFlow:
    tracked: dict[str, _Family] = {}
    for step in _flow_steps(source, method):
        if step.kind == "sink" and step.sink_family is not None:
            for name in step.used_names:
                family = tracked.get(name)
                if family is not None and family != step.sink_family:
                    return KeyFlow.CROSS_FAMILY
            continue
        # assignment: establish, inherit via alias, or untrack on overwrite.
        if step.left is None:
            continue
        family = step.source_family
        if family is None:
            inherited = {tracked[n] for n in step.alias_names if n in tracked and n != step.left}
            family = next(iter(inherited)) if len(inherited) == 1 else None
        if family is not None:
            tracked[step.left] = family
        else:
            tracked.pop(step.left, None)
    return KeyFlow.CONSISTENT


def classify_key_flow(source: str) -> KeyFlow:
    """Classify cross-family key flow across every structurally parsed method."""
    source_bytes = source.encode("utf-8")
    tree = Parser(_LANGUAGE).parse(source_bytes)
    if tree.root_node.has_error:
        return KeyFlow.INDETERMINATE

    for node in _walk(tree.root_node):
        if node.type in {"method_declaration", "constructor_declaration"}:
            if _analyze_key_flow(source_bytes, node) is KeyFlow.CROSS_FAMILY:
                return KeyFlow.CROSS_FAMILY
    return KeyFlow.CONSISTENT


# --- PQ-HYB-02: hybrid completeness ----------------------------------------
#
# L1's PQ-HYB-01 checks, at the token level, that both a classical KEX and an
# ML-KEM primitive appear. This L2 rule goes past tokens to the flow: in a
# structurally hybrid context -- one method that produces both a classical shared
# secret (`KeyAgreement.generateSecret`) and a PQ shared secret (KEM
# `decapsulate`) -- both secrets must reach a common combiner (the KDF), or one
# component has been silently dropped. "Reaches a common combiner" is detected
# structurally as a single expression whose arguments name a classical-tainted
# and a PQ-tainted variable (through simple aliases). If both secrets are produced
# but no expression combines them, the hybrid is downgraded. A method that
# produces only one family is not a hybrid context here (that missing-token case
# is PQ-HYB-01's job at L1). Parse errors are indeterminate.


class HybridFlow(enum.StrEnum):
    COMPLETE = "complete"
    DOWNGRADED = "downgraded"
    NOT_HYBRID = "not_hybrid"
    INDETERMINATE = "indeterminate"


_CLASSICAL_SECRET_METHODS = frozenset({"generateSecret"})
_PQ_SECRET_METHODS = frozenset({"decapsulate"})


def _rhs_calls_any(source: bytes, rhs: Node | None, names: frozenset[str]) -> bool:
    if rhs is None:
        return False
    for node in _walk(rhs):
        if node.type != "method_invocation":
            continue
        if _text(source, node.child_by_field_name("name")) in names:
            return True
    return False


def _assignments_in_order(source: bytes, method: Node) -> list[tuple[str, Node | None]]:
    steps: list[tuple[int, str, Node | None]] = []
    for node in _walk_method(method):
        if node.type == "variable_declarator":
            steps.append(
                (node.start_byte, _text(source, node.child_by_field_name("name")),
                 node.child_by_field_name("value"))
            )
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left is not None and left.type == "identifier":
                steps.append(
                    (node.start_byte, _text(source, left), node.child_by_field_name("right"))
                )
    return [(left, rhs) for _, left, rhs in sorted(steps, key=lambda s: s[0])]


def _analyze_hybrid(source: bytes, method: Node) -> HybridFlow:
    classical: set[str] = set()
    pq: set[str] = set()
    for left, rhs in _assignments_in_order(source, method):
        if _rhs_calls_any(source, rhs, _CLASSICAL_SECRET_METHODS):
            classical.add(left)
            pq.discard(left)
        elif _rhs_calls_any(source, rhs, _PQ_SECRET_METHODS):
            pq.add(left)
            classical.discard(left)
        else:
            ids = _identifier_names(source, rhs)
            in_c, in_p = bool(ids & classical), bool(ids & pq)
            classical.discard(left)
            pq.discard(left)
            # a pure alias inherits its single family; a var built from both is a
            # combiner value, left untainted (the combiner scan sees the expression).
            if in_c and not in_p:
                classical.add(left)
            elif in_p and not in_c:
                pq.add(left)

    if not (classical and pq):
        return HybridFlow.NOT_HYBRID

    for node in _walk_method(method):
        if node.type not in {"method_invocation", "object_creation_expression"}:
            continue
        args = node.child_by_field_name("arguments")
        ids = _identifier_names(source, args if args is not None else node)
        if ids & classical and ids & pq:
            return HybridFlow.COMPLETE
    return HybridFlow.DOWNGRADED


def classify_hybrid_flow(source: str) -> HybridFlow:
    """Classify hybrid-secret completeness across every structurally parsed method."""
    source_bytes = source.encode("utf-8")
    tree = Parser(_LANGUAGE).parse(source_bytes)
    if tree.root_node.has_error:
        return HybridFlow.INDETERMINATE

    result = HybridFlow.NOT_HYBRID
    for node in _walk(tree.root_node):
        if node.type in {"method_declaration", "constructor_declaration"}:
            outcome = _analyze_hybrid(source_bytes, node)
            if outcome is HybridFlow.DOWNGRADED:
                return HybridFlow.DOWNGRADED
            if outcome is HybridFlow.COMPLETE:
                result = HybridFlow.COMPLETE
    return result


# --- PQ-RAND-03: seed provenance -------------------------------------------
#
# L1's PQ-RAND-02 rejects a `SecureRandom` constructed directly from a literal
# seed. This L2 rule handles the flow case L1 defers: a fixed/constant seed that
# reaches `SecureRandom` *through a variable* (or a simple alias). A constant seed
# is a string/byte/numeric literal, a literal or fixed-size byte array (`new
# byte[32]` is a zero seed), or `"literal".getBytes(...)`. If such a value reaches
# a `new SecureRandom(seed)` constructor or a `setSeed(seed)` call, the generator
# is predictable (CWE-337). Seeds drawn from a method, parameter, or field are not
# constant here and are not convicted (bounded scope); parse errors are
# indeterminate.


class SeedFlow(enum.StrEnum):
    CLEAN = "clean"
    LITERAL_SEEDED = "literal_seeded"
    INDETERMINATE = "indeterminate"


_SEED_LITERAL_TYPES = frozenset(
    {
        "string_literal",
        "decimal_integer_literal",
        "hex_integer_literal",
        "octal_integer_literal",
        "binary_integer_literal",
        "character_literal",
        "array_initializer",
        "array_creation_expression",
    }
)
_SEED_SINK_METHODS = frozenset({"setSeed"})


def _is_constant_seed(source: bytes, node: Node | None) -> bool:
    if node is None:
        return False
    if node.type in _SEED_LITERAL_TYPES:
        return True
    if node.type == "method_invocation":
        if _text(source, node.child_by_field_name("name")) == "getBytes":
            return _is_constant_seed(source, node.child_by_field_name("object"))
    return False


def _is_secure_random_ctor(source: bytes, node: Node) -> bool:
    return node.type == "object_creation_expression" and "SecureRandom" in _text(
        source, node.child_by_field_name("type")
    )


def _analyze_seed(source: bytes, method: Node) -> SeedFlow:
    @dataclass(frozen=True, slots=True)
    class _Step:
        position: int
        kind: str
        left: str | None = None
        constant: bool = False
        alias: str | None = None
        used_names: frozenset[str] = frozenset()

    steps: list[_Step] = []
    for node in _walk_method(method):
        if node.type in {"variable_declarator", "assignment_expression"}:
            is_decl = node.type == "variable_declarator"
            left_node = node.child_by_field_name("name" if is_decl else "left")
            rhs = node.child_by_field_name("value" if is_decl else "right")
            if left_node is not None and left_node.type == "identifier":
                steps.append(
                    _Step(
                        node.start_byte,
                        "assign",
                        left=_text(source, left_node),
                        constant=_is_constant_seed(source, rhs),
                        alias=_simple_identifier(source, rhs),
                    )
                )
        elif node.type == "object_creation_expression" and _is_secure_random_ctor(source, node):
            steps.append(
                _Step(
                    node.start_byte,
                    "sink",
                    used_names=_identifier_names(source, node.child_by_field_name("arguments")),
                )
            )
        elif node.type == "method_invocation" and (
            _text(source, node.child_by_field_name("name")) in _SEED_SINK_METHODS
        ):
            steps.append(
                _Step(
                    node.start_byte,
                    "sink",
                    used_names=_identifier_names(source, node.child_by_field_name("arguments")),
                )
            )

    tainted: set[str] = set()
    for step in sorted(steps, key=lambda s: s.position):
        if step.kind == "sink":
            if step.used_names & tainted:
                return SeedFlow.LITERAL_SEEDED
            continue
        if step.left is None:
            continue
        if step.constant or (step.alias is not None and step.alias in tainted):
            tainted.add(step.left)
        else:
            tainted.discard(step.left)
    return SeedFlow.CLEAN


def classify_seed_provenance(source: str) -> SeedFlow:
    """Classify constant-seed flow into a randomness source across every method."""
    source_bytes = source.encode("utf-8")
    tree = Parser(_LANGUAGE).parse(source_bytes)
    if tree.root_node.has_error:
        return SeedFlow.INDETERMINATE

    for node in _walk(tree.root_node):
        if node.type in {"method_declaration", "constructor_declaration"}:
            if _analyze_seed(source_bytes, node) is SeedFlow.LITERAL_SEEDED:
                return SeedFlow.LITERAL_SEEDED
    return SeedFlow.CLEAN
