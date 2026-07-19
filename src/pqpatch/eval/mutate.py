"""Tier-1 surface mutation: semantics-preserving, contamination-controlling.

Public benchmarks are plausibly memorized, so every Tier-1 case also exists in
a mutated-surface variant and results are reported on both surfaces side by
side (manuscript, Tier 1). This module produces that variant deterministically:

- **class + file rename** -- the class identifier and its ``.java`` file get a
  new name derived from a stable digest of (case, old name);
- **conservative local-identifier rename** -- local variables and parameters
  are renamed only when the name is not *also* declared as a field, method, or
  class anywhere in the file (a scope-naive rewrite of such a name could change
  semantics, so those names are skipped, never guessed at);
- **comment stripping** -- line and block comments are removed.

What it deliberately never touches: **string literals** (the algorithm strings
are the misuse under test -- neutralizing those would change the case, not its
surface) and any identifier it cannot rename safely. Mutation is total surface
noise, zero semantic delta; ``javac`` equivalence is the test suite's check.

Rewrites are token-exact: only ``identifier`` AST nodes are rewritten, by byte
span, so occurrences inside strings and comments are untouched by the rename
pass. Deterministic by construction -- no randomness, only digests -- so the
mutated corpus regenerates byte-identically on any machine.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import tree_sitter_java
from tree_sitter import Language, Node, Parser

_LANGUAGE = Language(tree_sitter_java.language())

_CORPUS_TIER1 = Path(__file__).resolve().parents[3] / "corpus" / "tier1"

# Declaration kinds whose presence makes a name unsafe to rename wholesale.
_BLOCKING_DECLS = {"field_declaration", "method_declaration", "class_declaration"}
_RENAMABLE_DECLS = {"local_variable_declaration", "formal_parameter"}


def _walk(node: Node) -> list[Node]:
    out = [node]
    for child in node.named_children:
        out.extend(_walk(child))
    return out


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8")


def _new_name(case: str, old: str, prefix: str) -> str:
    digest = hashlib.sha256(f"{case}:{old}".encode()).hexdigest()[:6]
    return f"{prefix}{digest}"


def _declared_names(root: Node, source: bytes) -> tuple[set[str], set[str], str | None]:
    """(renamable local/param names, blocked names, primary class name)."""
    renamable: set[str] = set()
    blocked: set[str] = set()
    class_name: str | None = None
    for node in _walk(root):
        if node.type in _RENAMABLE_DECLS or node.type in _BLOCKING_DECLS:
            for child in _walk(node):
                if child.type == "identifier":
                    name = _text(child, source)
                    if node.type == "class_declaration":
                        if class_name is None:
                            class_name = name
                        blocked.add(name)
                    elif node.type in _BLOCKING_DECLS:
                        blocked.add(name)
                    else:
                        renamable.add(name)
                    break  # first identifier under the declaration is its name
    return renamable, blocked, class_name


def mutate_source(source_text: str, *, case: str) -> tuple[str, str | None]:
    """Return (mutated source, new class name or None). Raises ValueError on
    a source Tree-sitter cannot parse cleanly -- a broken mutation input is an
    authoring error, never silently passed through."""
    source = source_text.encode("utf-8")
    parser = Parser(_LANGUAGE)
    tree = parser.parse(source)
    if tree.root_node.has_error:
        raise ValueError(f"{case}: source does not parse; refusing to mutate")

    renamable, blocked, class_name = _declared_names(tree.root_node, source)
    rename = {
        name: _new_name(case, name, "v")
        for name in sorted(renamable - blocked)
    }
    new_class = None
    if class_name is not None:
        new_class = "C" + _new_name(case, class_name, "")
        rename[class_name] = new_class

    edits: list[tuple[int, int, str]] = []  # (start, end, replacement)
    for node in _walk(tree.root_node):
        if node.type == "identifier":
            name = _text(node, source)
            if name in rename:
                edits.append((node.start_byte, node.end_byte, rename[name]))
        elif node.type in ("line_comment", "block_comment"):
            edits.append((node.start_byte, node.end_byte, ""))

    out = bytearray(source)
    for start, end, replacement in sorted(edits, reverse=True):
        out[start:end] = replacement.encode("utf-8")
    return out.decode("utf-8"), new_class


def mutate_case(case_dir: Path, out_dir: Path) -> list[Path]:
    """Mutate every .java file of one Tier-1 case into out_dir; returns the
    written paths. Non-Java files are copied through unchanged."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for path in sorted(case_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(case_dir)
        if path.suffix == ".java":
            mutated, new_class = mutate_source(
                path.read_text(encoding="utf-8"), case=f"{case_dir.name}/{rel}"
            )
            name = f"{new_class}.java" if new_class else rel.name
            target = out_dir / rel.parent / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(mutated, encoding="utf-8")
        else:
            target = out_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
        written.append(target)
    return written


def main() -> int:
    original = _CORPUS_TIER1 / "original"
    mutated = _CORPUS_TIER1 / "mutated"
    cases = sorted(p for p in original.iterdir() if p.is_dir()) if original.exists() else []
    if not cases:
        print(
            "tier1/original holds no cases yet; nothing to mutate. Intake Tier-1 "
            "cases first (progress ledger N2), then re-run."
        )
        return 1
    for case_dir in cases:
        written = mutate_case(case_dir, mutated / case_dir.name)
        print(f"mutated {case_dir.name}: {len(written)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
