""" Call Graph for JPAMB.

This script finds which Java methods call other methods by reading the
compiled bytecode. The idea is to help the static analysis and fuzzer
see which methods can reach each other.

How it works:
1. Read the decompiled Java bytecode from target/decompiled.
2. Find method invocation instructions (invoke).
3. Connect each calling method to its possible callees.
4. Print the call graph as JSON or Graphviz DOT.

Commands (run from the jpamb folder):

  # Generate a graph
  uv run python solutions/syntactic/src/call_graph.py

  # Save the graph as JSON
  uv run python solutions/syntactic/src/call_graph.py --output call-graph.json

  # Export as DOT
  uv run python solutions/syntactic/src/call_graph.py --format dot

  # Run tests
  uv run pytest -q tests/test_call_graph.py

Notes:
- This is a static call graph.
- It identifies possible method calls, not guaranteed runtime execution.
- The graph can be used by the static analysis and fuzzer.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
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


def build_call_graph(
    decompiled_root: str | Path = "target/decompiled", *, include_external: bool = False
) -> dict[str, list[str]]:
    """Read all decompiled JSON class files and construct the call graph."""
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
    return build_call_graph_from_classes(classes, include_external=include_external)


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


def _dot(graph: dict[str, list[str]]) -> str:
    def quote(node: str) -> str:
        return json.dumps(node, ensure_ascii=False)

    out = ["digraph call_graph {"]
    for caller, callees in sorted(graph.items()):
        if not callees:
            out.append(f"  {quote(caller)};")
        for callee in callees:
            out.append(f"  {quote(caller)} -> {quote(callee)};")
    out.append("}")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="JPAMB bytecode call graph")
    parser.add_argument(
        "--decompiled",
        default="target/decompiled",
        type=Path,
        help="Directory containing decompiled JVM2JSON classes",
    )
    parser.add_argument("--entry", help="Optional JPAMB method ID to trace")
    parser.add_argument(
        "--include-external",
        action="store_true",
        help="Keep JDK and other external targets",
    )
    parser.add_argument("--format", choices=("json", "dot"), default="json")
    parser.add_argument("--output", type=Path, help="Write output to file instead of stdout")
    args = parser.parse_args(argv)

    try:
        graph = build_call_graph(args.decompiled, include_external=args.include_external)
        if args.entry:
            reached = reachable_methods(graph, args.entry)
            graph = {node: graph[node] for node in reached if node in graph}
            # In the exported subgraph, remove targets outside the selected set.
            for node in graph:
                graph[node] = [callee for callee in graph[node] if callee in reached]
        output = (
            _dot(graph)
            if args.format == "dot"
            else json.dumps(graph, indent=2, ensure_ascii=False) + "\n"
        )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    except (FileNotFoundError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"call_graph: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())