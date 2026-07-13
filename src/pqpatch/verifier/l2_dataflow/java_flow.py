"""Tree-sitter-backed intraprocedural Java def-use for verification results.

The frontend extracts structural invocation, assignment, branch, and return
events. The analysis remains deliberately local: unsupported syntax and parse
errors are indeterminate, never silently accepted as proof.
"""

from __future__ import annotations

import enum
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
