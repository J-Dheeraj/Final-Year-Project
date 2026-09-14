"""Reachability-filtered call graph construction for C/C++ and Go sources,
using real tree-sitter ASTs (not a regex/brace-counting heuristic).

Methodology follows OpenAnt (arXiv:2606.19149): parse a codebase into
functions, build a call graph, then do a breadth-first traversal from
attacker-reachable entry points so that downstream LLM analysis only ever
looks at code that can actually be reached from the outside. On real
projects OpenAnt reports 94-97% reduction in analysis units; the exact
number here depends on the codebase, but the filtering step is what makes
a bounded LLM budget viable on large codebases instead of scanning every
function blindly.

This module previously parsed with a hand-rolled regex + brace-counting
heuristic. That was honestly documented as the project's biggest caveat
("not a replacement for a proper AST-based call graph") and is now
replaced with `tree-sitter` grammars for C, C++, and Go - a real parser,
not a pattern matcher. Two concrete correctness wins this gets for free
that the regex version could not: (1) a `void (*cb)(int) = 0;` function-
pointer variable declaration is unambiguously NOT a `function_definition`
node, so it can never be misparsed as a function the way an ad-hoc
signature regex risked; (2) a call site's target is read from the parser's
own `function`/`field` AST fields, not by scanning for "identifier(" text,
so it can't be fooled by an identifier that merely happens to precede an
unrelated parenthesis.

Go support exists specifically for free5GC (a real, standards-compliant
5G core network, Go throughout) - the FYP's "5G" framing had otherwise
only ever touched it via the general "Linux kernel underlies telecom
infra" argument, not literal 5G-stack source. C++ support was added
alongside C/Go since tree-sitter-cpp was already available and its
`function_definition`/`call_expression` node shapes are a superset of
C's - free functions and class methods are both found by an unrestricted
recursive walk (see `_parse_file`), though (same limitation as the old
parser) same-named methods on different classes still collide by name,
since the call graph is keyed on bare function name, not a qualified
symbol.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Language, Node, Parser
import tree_sitter_c
import tree_sitter_cpp
import tree_sitter_go

from .preprocess import CompileCommand, find_command, preprocess_source

_C_LANGUAGE = Language(tree_sitter_c.language())
_CPP_LANGUAGE = Language(tree_sitter_cpp.language())
_GO_LANGUAGE = Language(tree_sitter_go.language())

# Extension -> (Language, function-definition node types, "how to find the
# name" strategy). C and C++ share the same declarator-unwrapping approach
# (see _declarator_name_node); Go declarations expose a `name` field
# directly, so no unwrapping is needed.
_LANG_BY_EXT: dict[str, tuple[Language, str]] = {
    ".c": (_C_LANGUAGE, "c"),
    ".h": (_C_LANGUAGE, "c"),
    ".cc": (_CPP_LANGUAGE, "cpp"),
    ".cpp": (_CPP_LANGUAGE, "cpp"),
    ".cxx": (_CPP_LANGUAGE, "cpp"),
    ".hpp": (_CPP_LANGUAGE, "cpp"),
    ".go": (_GO_LANGUAGE, "go"),
}

_FUNC_NODE_TYPES = {
    "c": {"function_definition"},
    "cpp": {"function_definition"},
    "go": {"function_declaration", "method_declaration"},
}


@dataclass
class Function:
    name: str
    file: str
    start_line: int
    signature: str
    body: str
    calls: set[str] = field(default_factory=set)

    @property
    def loc(self) -> int:
        return self.body.count("\n") + 1


@dataclass
class CallGraph:
    functions: dict[str, Function]

    def reachable_from(self, entrypoints: list[str]) -> "ReachabilityResult":
        missing = [e for e in entrypoints if e not in self.functions]
        frontier = [e for e in entrypoints if e in self.functions]
        visited: set[str] = set(frontier)
        depth: dict[str, int] = {e: 0 for e in frontier}
        order: list[str] = []
        i = 0
        while i < len(frontier):
            name = frontier[i]
            i += 1
            order.append(name)
            fn = self.functions[name]
            for callee in sorted(fn.calls):
                if callee not in self.functions or callee in visited:
                    continue
                visited.add(callee)
                depth[callee] = depth[name] + 1
                frontier.append(callee)

        total = len(self.functions)
        reached = len(order)
        reduction = 0.0 if total == 0 else 100.0 * (1 - reached / total)
        return ReachabilityResult(
            graph=self,
            reachable=[self.functions[n] for n in order],
            depth=depth,
            missing_entrypoints=missing,
            total_functions=total,
            reduction_pct=reduction,
        )


@dataclass
class ReachabilityResult:
    graph: CallGraph
    reachable: list[Function]
    depth: dict[str, int]
    missing_entrypoints: list[str]
    total_functions: int
    reduction_pct: float


def _declarator_name_node(declarator: Node | None) -> Node | None:
    """C/C++: unwrap a (possibly pointer-/parenthesized-) declarator down
    to its `identifier`/`field_identifier`, e.g. `struct foo *bar(int x)`'s
    declarator is `pointer_declarator > function_declarator > identifier`.
    Recurses through children generically (rather than hardcoding every
    declarator wrapper type C/C++ grammars define) so it isn't brittle
    against declarator shapes not explicitly tested; skips `parameter_list`
    subtrees so it can't return a parameter's name instead of the
    function's own name."""
    if declarator is None:
        return None
    if declarator.type in ("identifier", "field_identifier"):
        return declarator
    for child in declarator.children:
        if child.type == "parameter_list":
            continue
        found = _declarator_name_node(child)
        if found is not None:
            return found
    return None


def _called_name(fn_node: Node | None) -> str | None:
    """Given a `call_expression`'s `function` field, return the name being
    called: the bare identifier for `foo(...)`, or the rightmost member
    name for `obj.foo(...)` / `obj->foo(...)` / Go's `s.Method(...)` (all
    represented as a `field_expression`/`selector_expression` with a
    `field` field pointing at the member's identifier)."""
    if fn_node is None:
        return None
    if fn_node.type in ("identifier", "field_identifier"):
        return fn_node.text.decode("utf-8", errors="replace")
    field_node = fn_node.child_by_field_name("field")
    if field_node is not None:
        return field_node.text.decode("utf-8", errors="replace")
    return None


def _extract_calls(body_node: Node, self_name: str) -> set[str]:
    called: set[str] = set()

    def walk(node: Node) -> None:
        if node.type == "call_expression":
            fn_node = node.child_by_field_name("function")
            name = _called_name(fn_node)
            if name and name != self_name:
                called.add(name)
        for child in node.children:
            walk(child)

    walk(body_node)
    return called


def _parse_file(path: Path, parser: Parser, lang: str) -> tuple[list[Function], dict[str, Node]]:
    """Parse a file from disk. Thin wrapper over `_parse_source` so the
    same walk serves both on-disk files and preprocessor output held in
    memory (see preprocess.py)."""
    try:
        source = path.read_bytes()
    except OSError:
        return [], {}
    return _parse_source(source, path, parser, lang)


def _parse_source(source: bytes, path: Path, parser: Parser,
                   lang: str) -> tuple[list[Function], dict[str, Node]]:
    """Single walk that both builds the Function list and captures each
    function's body Node (needed separately for call-site extraction,
    since Function.body stores decoded text, not the live AST node).

    `path` is only used to label the resulting Functions, so preprocessed
    source still reports the real file it came from.
    """
    tree = parser.parse(source)
    func_types = _FUNC_NODE_TYPES[lang]
    funcs: list[Function] = []
    body_nodes: dict[str, Node] = {}

    def walk(node: Node) -> None:
        if node.type in func_types:
            body_node = node.child_by_field_name("body")
            if lang == "go":
                name_node = node.child_by_field_name("name")
            else:
                name_node = _declarator_name_node(node.child_by_field_name("declarator"))
            if name_node is not None and body_node is not None:
                name = name_node.text.decode("utf-8", errors="replace")
                start_line = node.start_point[0] + 1
                body_text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                sig_text = source[node.start_byte:body_node.start_byte].decode("utf-8", errors="replace").strip()
                funcs.append(Function(name=name, file=str(path), start_line=start_line,
                                       signature=sig_text, body=body_text))
                body_nodes[name] = body_node
            # Deliberately do NOT recurse into this function's own subtree
            # for further top-level function_definitions - C/Go don't nest
            # function definitions, and for C++ this avoids treating a
            # local lambda's body as a second top-level unit.
            return
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return funcs, body_nodes


def _parse_preprocessed(path: Path, parser: Parser, lang: str,
                         compile_commands: dict[str, CompileCommand],
                         ) -> tuple[list[Function], dict[str, Node]]:
    """Preprocess one file with its real build flags and parse the result.
    Returns empty results (never raises) when the file isn't in the
    compilation database or the preprocessor can't run - the caller then
    simply keeps whatever the raw parse found."""
    cc = find_command(compile_commands, path)
    if cc is None:
        print(f"warning: {path} is not in the compilation database; "
              f"macro-generated functions in it will not be visible",
              file=sys.stderr)
        return [], {}
    result = preprocess_source(cc)
    if not result.ok:
        print(f"warning: preprocessing {path} failed ({result.reason}); "
              f"falling back to raw parsing",
              file=sys.stderr)
        return [], {}
    return _parse_source(result.source.encode("utf-8"), path, parser, lang)


def build_call_graph(root: Path, extensions: tuple[str, ...] | None = None,
                      compile_commands: dict[str, CompileCommand] | None = None) -> CallGraph:
    """Build the call graph for `root` (a file or a directory tree).

    When `compile_commands` is supplied, each C translation unit found in
    it is ALSO preprocessed with its real build flags and parsed again,
    and any function the raw parse could not see - macro-generated ones,
    above all the kernel's `SYSCALL_DEFINE*` entry points - is added.
    The raw definition always wins where both parses find the same name,
    since expanded source is noisier to read and no more accurate; see
    preprocess.py's module docstring for the measurements behind that.
    """
    if extensions is None:
        extensions = tuple(_LANG_BY_EXT)

    files: list[Path]
    if root.is_file():
        files = [root]
    else:
        files = sorted(p for p in root.rglob("*") if p.suffix in extensions)

    all_funcs: dict[str, Function] = {}
    all_body_nodes: dict[str, Node] = {}
    for f in files:
        entry = _LANG_BY_EXT.get(f.suffix)
        if entry is None:
            continue
        language, lang = entry
        parser = Parser(language)
        funcs, body_nodes = _parse_file(f, parser, lang)
        for fn in funcs:
            # Last definition wins on name clashes; fine for a prototype.
            all_funcs[fn.name] = fn
        all_body_nodes.update(body_nodes)

        if compile_commands is not None and lang == "c":
            expanded_funcs, expanded_nodes = _parse_preprocessed(
                f, parser, lang, compile_commands)
            for fn in expanded_funcs:
                if fn.name in all_funcs:
                    continue  # raw parse wins - see docstring
                all_funcs[fn.name] = fn
                node = expanded_nodes.get(fn.name)
                if node is not None:
                    all_body_nodes[fn.name] = node

    for fn in all_funcs.values():
        body_node = all_body_nodes.get(fn.name)
        fn.calls = _extract_calls(body_node, fn.name) if body_node is not None else set()

    return CallGraph(functions=all_funcs)
