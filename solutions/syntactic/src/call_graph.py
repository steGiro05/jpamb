""" Call Graph for JPAMB.

This script finds which Java methods call other methods by reading the
compiled bytecode. The idea is to help the static analysis and fuzzer
see which methods can reach each other.

Scope: the graph is built only from the classes of ONE source file (the file
of the target, nested classes included). Both the forward expansion and the
backward search from the sinks stay inside that file.

How it works:
1. Pick the file of the target and read its classes from target/decompiled.
2. Connect each method to the methods it invokes (invoke instructions).
3. Some calls have a target chosen at runtime (reflection such as
   Class.forName, or deserialization such as readObject), so a plain call
   graph has no edge there. We over-approximate:
     a. start from the sinks and collect every method that can reach one
        (backward closure);
     b. link every dynamic site to the entry points (<init>, <clinit>) of
        that closure.
   Each added edge records its kind, "reflection" or "deserialization", so
   the fuzzer knows whether to build class names or serialized payloads.
4. Print what the target reaches, as JSON or Graphviz DOT.

The TARGET is required. It can be a JPAMB method ID, a method name, or the
file of a class (.java, .json or .class):

  # Only what is reachable from one method (full ID or just the name)
  uv run python solutions/syntactic/src/call_graph.py whitelist_deserialization
  uv run python solutions/syntactic/src/call_graph.py 'jpamb.cases.Vulnerable.whitelist_deserialization:(Ljava/lang/String;)V'

  # Everything reachable from the methods of a file
  uv run python solutions/syntactic/src/call_graph.py src/main/java/jpamb/cases/Vulnerable.java

  # Write the JSON to call-graph.json (or to a path of your choice)
  uv run python solutions/syntactic/src/call_graph.py whitelist_deserialization --write-json
  uv run python solutions/syntactic/src/call_graph.py whitelist_deserialization --output=out/graph.json

  # Export as DOT (dynamic edges are dashed and labelled with their kind)
  uv run python solutions/syntactic/src/call_graph.py Vulnerable.java --format dot

  # Choose the sinks and declare mocks of dynamic mechanisms
  uv run python solutions/syntactic/src/call_graph.py Vulnerable.java \\
      --sink '__CANARY__Command.<init>' --stub deserialization=simulateReadObject

Output (JSON):
  {
    "graph":         {caller: [callees]},              # includes dynamic edges
    "dynamic_edges": [{caller, callee, kind}, ...],    # only the added ones
    "sinks":         [method IDs]
  }

Notes:
- This is a static call graph: possible calls, not guaranteed execution.
- Dynamic edges are an over-approximation: they can add paths that cannot
  happen, but they do not miss paths to a sink inside the file.
- Classes defined in other files are not seen: sinks and gadget classes must
  be in the same file as the target.
- A stub (e.g. a mock of readObject) loses its own outgoing edges, which are
  replaced by the dynamic ones, so the result does not depend on the mock.
- Put TARGET before --output, or write --output=PATH.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable


PRIMITIVES = {
    "boolean": "Z",
    "byte": "B",
    "char": "C",
    "double": "D",
    "float": "F",
    "int": "I",
    "long": "J",
    "short": "S",
    "void": "V",
}

# ---------------------------------------------------------------------------
# Configuration of dynamic mechanisms
# ---------------------------------------------------------------------------

# External methods whose target class is chosen at runtime:
# (owner in internal form, method name) -> kind of dynamic link.
DYNAMIC_SITES = {
    ("java/lang/Class", "forName"): "reflection",
    ("java/lang/Class", "newInstance"): "reflection",
    ("java/lang/ClassLoader", "loadClass"): "reflection",
    ("java/lang/reflect/Constructor", "newInstance"): "reflection",
    ("java/io/ObjectInputStream", "readObject"): "deserialization",
}

# Defined methods that stand for a dynamic mechanism (mocks of readObject...).
# The key is a method name, "Class.name" or a full method ID.
DEFAULT_STUBS = {"simulateReadObject": "deserialization"}

# A method is a sink when one of these strings is contained in its ID.
DEFAULT_SINKS = ("__CANARY__Command.<init>",)

# Dynamic sites are linked to these methods of the backward closure.
ENTRY_POINT_NAMES = ("<init>", "<clinit>")

KINDS = ("reflection", "deserialization")
DEFAULT_JSON_OUTPUT = "call-graph.json"


def type_descriptor(value: Any) -> str:
    """Encode a JVM2JSON type as a JVM type descriptor.

    Method declarations wrap types in ``{'type': ...}`` whereas invocations
    usually use primitive strings, or ``{'kind': 'class', 'name': ...}``.
    """
    if value is None:
        return "V"
    if isinstance(value, str):
        if value in PRIMITIVES:
            return PRIMITIVES[value]
        if value.startswith("[") or (value.startswith("L") and value.endswith(";")):
            return value
        # Reference class name (internal JVM slash form or dotted form).
        return f"L{value.replace('.', '/')};"
    if not isinstance(value, dict):
        raise ValueError(f"Unsupported JVM2JSON type: {value!r}")

    if "base" in value:
        return type_descriptor(value["base"])
    if value.get("kind") == "array":
        return "[" + type_descriptor(value["type"])
    if value.get("kind") == "class" or "name" in value:
        name = value["name"]
        return f"L{name.replace('.', '/')};"
    if "type" in value:
        return type_descriptor(value["type"])
    raise ValueError(f"Unknown JVM2JSON type structure: {value!r}")


def method_id(class_name: str, name: str, args: Iterable[Any], returns: Any) -> str:
    """Use JPAMB method IDs, e.g. jpamb.cases.Calls.fib:(I)I."""
    owner = class_name.replace("/", ".")
    signature = "".join(type_descriptor(arg) for arg in args)
    return f"{owner}.{name}:({signature}){type_descriptor(returns)}"


def split_method_id(mid: str) -> tuple[str, str]:
    """Split a method ID into (owner class, method name)."""
    owner, _, name = mid.split(":(", 1)[0].rpartition(".")
    return owner, name


def _method_definition_id(owner: str, method: dict[str, Any]) -> str:
    params = (param["type"] for param in method.get("params", []))
    returns = method.get("returns")
    if isinstance(returns, dict):
        returns = returns.get("type")
    return method_id(owner, method["name"], params, returns)


def _invoked_method_id(inst: dict[str, Any]) -> str | None:
    if inst.get("opr") != "invoke":
        return None
    method = inst.get("method")
    if not isinstance(method, dict):
        # An invokedynamic without a statically named method is unresolved.
        return None
    ref = method.get("ref")
    if not isinstance(ref, dict) or ref.get("kind") != "class":
        return None
    if not isinstance(ref.get("name"), str) or not isinstance(method.get("name"), str):
        return None
    return method_id(
        ref["name"], method["name"], method.get("args", []), method.get("returns")
    )


def build_call_graph_from_classes(
    classes: Iterable[dict[str, Any]], *, include_external: bool = False
) -> dict[str, list[str]]:
    """Extract caller -> [callee, ...] from already-loaded JVM2JSON classes.

    Every defined method is a key, even if it makes no calls. By default,
    edges to methods not defined in the supplied classes are excluded. Use
    ``include_external=True`` to retain calls into Java libraries.
    """
    class_data = list(classes)
    graph: dict[str, set[str]] = {}
    for cls in class_data:
        owner = cls["name"]
        for method in cls.get("methods", []):
            caller = _method_definition_id(owner, method)
            if caller in graph:
                raise ValueError(f"Duplicate method definition: {caller}")
            graph[caller] = set()

    known_methods = set(graph)
    for cls in class_data:
        owner = cls["name"]
        for method in cls.get("methods", []):
            caller = _method_definition_id(owner, method)
            code = method.get("code") or {}
            for inst in code.get("bytecode", []):
                callee = _invoked_method_id(inst)
                if callee and (include_external or callee in known_methods):
                    graph[caller].add(callee)

    return {caller: sorted(callees) for caller, callees in sorted(graph.items())}


def load_classes(decompiled_root: str | Path = "target/decompiled") -> list[dict[str, Any]]:
    """Read all decompiled JSON class files."""
    root = Path(decompiled_root)
    if not root.is_dir():
        raise FileNotFoundError(
            f"No decompiled bytecode directory at {root}. "
            "Run 'uv run jpamb build' in the JPAMB repository first."
        )
    files = sorted(root.rglob("*.json"))
    if not files:
        raise FileNotFoundError(f"No JSON class files found under {root}")
    classes = []
    for path in files:
        with path.open(encoding="utf-8") as file:
            data = json.load(file)
        if isinstance(data, dict) and "name" in data and "methods" in data:
            classes.append(data)
    if not classes:
        raise ValueError(f"No JVM2JSON class structures found under {root}")
    return classes


def build_call_graph(
    decompiled_root: str | Path = "target/decompiled", *, include_external: bool = False
) -> dict[str, list[str]]:
    """Read all decompiled JSON class files and construct the call graph."""
    return build_call_graph_from_classes(
        load_classes(decompiled_root), include_external=include_external
    )


def reachable_methods(graph: dict[str, list[str]], entry: str) -> list[str]:
    """Find transitive callees (including entry), handling recursion safely."""
    if entry not in graph:
        raise KeyError(f"Unknown method: {entry}")
    visited: set[str] = set()
    worklist = deque([entry])
    while worklist:
        method = worklist.popleft()
        if method in visited:
            continue
        visited.add(method)
        worklist.extend(graph.get(method, []))
    return sorted(visited)


# ---------------------------------------------------------------------------
# Dynamic edges (reflection, deserialization)
# ---------------------------------------------------------------------------


def _dynamic_kind(inst: dict[str, Any]) -> str | None:
    """Kind of dynamic mechanism invoked by an instruction, if any."""
    if inst.get("opr") != "invoke":
        return None
    method = inst.get("method")
    if not isinstance(method, dict):
        return None
    ref = method.get("ref")
    if not isinstance(ref, dict) or not isinstance(ref.get("name"), str):
        return None
    owner = ref["name"].replace(".", "/")
    return DYNAMIC_SITES.get((owner, method.get("name")))


def find_dynamic_sites(classes: Iterable[dict[str, Any]]) -> dict[str, set[str]]:
    """Methods that invoke a dynamic mechanism -> kinds they use.

    This must run on the bytecode, not on the graph: external calls such as
    Class.forName are dropped from the graph unless include_external is set.
    """
    sites: dict[str, set[str]] = defaultdict(set)
    for cls in classes:
        for method in cls.get("methods", []):
            caller = _method_definition_id(cls["name"], method)
            for inst in (method.get("code") or {}).get("bytecode", []):
                kind = _dynamic_kind(inst)
                if kind:
                    sites[caller].add(kind)
    return dict(sites)


def find_stubs(graph: dict[str, list[str]], stubs: dict[str, str]) -> dict[str, str]:
    """Defined methods that stand for a dynamic mechanism -> kind."""
    found = {}
    for mid in graph:
        owner, name = split_method_id(mid)
        for key in (mid, f"{owner}.{name}", name):
            if key in stubs:
                found[mid] = stubs[key]
                break
    return found


def find_sinks(graph: dict[str, list[str]], specs: Iterable[str]) -> list[str]:
    """Methods whose ID contains one of the sink specifications."""
    specs = list(specs)
    return sorted(mid for mid in graph if any(spec in mid for spec in specs))


def callers_closure(graph: dict[str, list[str]], sinks: Iterable[str]) -> set[str]:
    """Every method from which a sink is reachable (sinks included)."""
    callers: dict[str, set[str]] = defaultdict(set)
    for caller, callees in graph.items():
        for callee in callees:
            callers[callee].add(caller)
    seen: set[str] = set()
    worklist = deque(sinks)
    while worklist:
        method = worklist.popleft()
        if method in seen:
            continue
        seen.add(method)
        worklist.extend(callers[method])
    return seen


def add_dynamic_edges(
    graph: dict[str, list[str]],
    sites: dict[str, set[str]],
    stubs: dict[str, str],
    sinks: Iterable[str],
) -> tuple[dict[str, list[str]], list[dict[str, str]]]:
    """Link every dynamic site to the entry points that can reach a sink.

    Order matters: stubs lose their own edges first, then the closure is
    computed, then the dynamic edges are added. Otherwise the result would
    depend on the mock.
    """
    new_graph = {
        method: ([] if method in stubs else list(callees))
        for method, callees in graph.items()
    }
    closure = callers_closure(new_graph, sinks)
    entries = sorted(m for m in closure if split_method_id(m)[1] in ENTRY_POINT_NAMES)

    kinds: dict[str, set[str]] = defaultdict(set)
    for method, site_kinds in sites.items():
        kinds[method] |= site_kinds
    for method, kind in stubs.items():
        kinds[method].add(kind)

    dynamic_edges: list[dict[str, str]] = []
    for caller in sorted(kinds):
        if caller not in new_graph:
            continue
        for kind in sorted(kinds[caller]):
            for callee in entries:
                if callee != caller:
                    dynamic_edges.append(
                        {"caller": caller, "callee": callee, "kind": kind}
                    )
        linked = {e["callee"] for e in dynamic_edges if e["caller"] == caller}
        new_graph[caller] = sorted(set(new_graph[caller]) | linked)
    return new_graph, dynamic_edges


# ---------------------------------------------------------------------------
# Selecting the target
# ---------------------------------------------------------------------------

FILE_SUFFIXES = {".java", ".json", ".class"}


def class_name_from_file(path: Path) -> str:
    """Class name (dotted) of a .java, decompiled .json or .class file."""
    if path.suffix == ".java" and path.is_file():
        text = path.read_text(encoding="utf-8")
        match = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.MULTILINE)
        if match:
            return f"{match.group(1)}.{path.stem}"
    if path.suffix == ".json" and path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("name"), str):
            return data["name"].replace("/", ".")
    # Fallback (.class, or a file we cannot read): use the package path.
    parts = list(path.with_suffix("").parts)
    if "jpamb" in parts:
        parts = parts[parts.index("jpamb"):]
    return ".".join(parts)


def top_level(class_name: str) -> str:
    """Dotted name of the top-level class (the source file) of a class."""
    return class_name.replace("/", ".").split("$")[0]


def select_scope(
    classes: list[dict[str, Any]], target: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """Classes of the file(s) of the target, and the entry methods.

    The target is a method ID, a method name (optionally qualified) or a
    class file. Only classes of the same top-level class are kept.
    """
    defined = {
        _method_definition_id(cls["name"], method): top_level(cls["name"])
        for cls in classes
        for method in cls.get("methods", [])
    }

    path = Path(target)
    if target in defined:
        entries = [target]
    elif ":(" not in target and (path.suffix in FILE_SUFFIXES or path.is_file()):
        top = top_level(class_name_from_file(path))
        entries = [m for m, owner in defined.items() if owner == top]
        if not entries:
            raise KeyError(f"No methods of class {top} (from file {target})")
    else:
        # Method name, optionally qualified (Class.name or package.Class.name).
        wanted = target.split(":(", 1)[0]
        entries = [
            m
            for m in defined
            if m.split(":(", 1)[0] == wanted or m.split(":(", 1)[0].endswith("." + wanted)
        ]
        if not entries:
            raise KeyError(f"Unknown method: {target}")

    tops = {defined[m] for m in entries}
    return [c for c in classes if top_level(c["name"]) in tops], entries


def _dot(graph: dict[str, list[str]], dynamic_edges: Iterable[dict[str, str]] = ()) -> str:
    def quote(node: str) -> str:
        return json.dumps(node, ensure_ascii=False)

    dynamic: dict[tuple[str, str], set[str]] = defaultdict(set)
    for edge in dynamic_edges:
        dynamic[(edge["caller"], edge["callee"])].add(edge["kind"])

    out = ["digraph call_graph {"]
    for caller, callees in sorted(graph.items()):
        if not callees:
            out.append(f"  {quote(caller)};")
        for callee in callees:
            kinds = dynamic.get((caller, callee))
            style = ""
            if kinds:
                label = "/".join(sorted(kinds))
                style = f' [style=dashed, label="{label}"]'
            out.append(f"  {quote(caller)} -> {quote(callee)}{style};")
    out.append("}")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="JPAMB bytecode call graph (one source file)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        help="JPAMB method ID, method name, or class file (.java, .json, .class). "
        "The graph is built from the file of the target.",
    )
    parser.add_argument(
        "--decompiled",
        default="target/decompiled",
        type=Path,
        help="Directory containing decompiled JVM2JSON classes",
    )
    parser.add_argument("--format", choices=("json", "dot"), default="json")
    parser.add_argument("--output", type=Path, help="Write output to file instead of stdout")
    parser.add_argument(
        "--write-json",
        action="store_true",
        help=f"Write the JSON output to a file (default {DEFAULT_JSON_OUTPUT}, "
        "or the path given with --output)",
    )
    parser.add_argument(
        "--sink",
        action="append",
        metavar="TEXT",
        help="Sink: any method whose ID contains TEXT (repeatable, "
        f"default {', '.join(DEFAULT_SINKS)})",
    )
    parser.add_argument(
        "--stub",
        action="append",
        metavar="KIND=NAME",
        help="Declare a method as a stub of a dynamic mechanism; KIND is "
        "reflection or deserialization, NAME is a method name, Class.name or "
        "a full method ID (repeatable)",
    )
    args = parser.parse_args(argv)

    if args.write_json:
        if args.format != "json":
            parser.error("--write-json cannot be combined with --format dot")
        if args.output is None:
            args.output = Path(DEFAULT_JSON_OUTPUT)

    stubs = dict(DEFAULT_STUBS)
    for spec in args.stub or []:
        kind, sep, name = spec.partition("=")
        if not sep or kind not in KINDS or not name:
            parser.error(f"--stub expects KIND=NAME with KIND in {KINDS}, got {spec!r}")
        stubs[name] = kind

    try:
        # Only the classes of the target's file: forward and backward both stay here.
        scope, entries = select_scope(load_classes(args.decompiled), args.target)
        graph = build_call_graph_from_classes(scope)

        sinks = find_sinks(graph, args.sink or DEFAULT_SINKS)
        if not sinks:
            print("call_graph: warning: no sink in this file, no dynamic edges added",
                  file=sys.stderr)
        graph, dynamic_edges = add_dynamic_edges(
            graph, find_dynamic_sites(scope), find_stubs(graph, stubs), sinks
        )

        reached: set[str] = set()
        for entry in entries:
            reached.update(reachable_methods(graph, entry))
        graph = {node: [c for c in graph[node] if c in reached] for node in sorted(reached)}
        dynamic_edges = [
            e for e in dynamic_edges if e["caller"] in reached and e["callee"] in reached
        ]

        if args.format == "dot":
            output = _dot(graph, dynamic_edges)
        else:
            output = (
                json.dumps(
                    {"graph": graph, "dynamic_edges": dynamic_edges, "sinks": sinks},
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(f"call_graph: wrote {args.output}", file=sys.stderr)
        else:
            print(output, end="")
        return 0
    except (FileNotFoundError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"call_graph: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())