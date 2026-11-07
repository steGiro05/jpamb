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
import re
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable

PRIMITIVES = {
    "boolean": "Z", "byte": "B", "char": "C", "double": "D",
    "float": "F", "int": "I", "long": "J", "short": "S", "void": "V",
}
KINDS = ("reflection", "deserialization")
ENTRY_POINT_NAMES = ("<init>", "<clinit>")
FILE_SUFFIXES = {".java", ".json", ".class"}
DEFAULT_JSON_OUTPUT = "call-graph.json"

def load_config(config_path: Path) -> tuple[list[str], dict[str, str], dict[tuple[str, str], str]]:
    """Load sinks, stubs, and dynamic sites from an external JSON configuration file."""
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
    with config_path.open(encoding="utf-8") as f:
        data = json.load(f)
        
    sinks = []
    stubs = {}
    dynamic_sites = {}
    
    config = data.get("analyzer_config", {})
    for vuln in config.get("vulnerabilities", []):
        if vuln.get("enabled", False):
            sinks.extend(vuln.get("sinks", []))
            stubs.update(vuln.get("stubs", {}))
            
            for site in vuln.get("dynamic_sites", []):
                owner = site["class_name"].replace(".", "/")
                dynamic_sites[(owner, site["method_name"])] = site["kind"]
            
    return sinks, stubs, dynamic_sites

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

def _dynamic_kind(
    inst: dict[str, Any], dynamic_sites: dict[tuple[str, str], str] | None = None
) -> str | None:
    """Identify a runtime-selected call; optional config overrides built-in rules."""
    if inst.get("opr") != "invoke":
        return None
    method = inst.get("method")
    if not isinstance(method, dict):
        return None
    name = method.get("name")
    ref = method.get("ref")
    owner = ref.get("name", "") if isinstance(ref, dict) else ""
    owner = owner.replace(".", "/") if isinstance(owner, str) else ""

    if dynamic_sites is not None:
        return dynamic_sites.get((owner, name))
    if name == "simulateReadObject":
        return "deserialization"
    if owner == "java/io/ObjectInputStream" and name == "readObject":
        return "deserialization"
    if owner == "java/lang/Class" and name in ("forName", "newInstance"):
        return "reflection"
    if owner == "java/lang/reflect/Constructor" and name == "newInstance":
        return "reflection"
    return None

def find_constructors(graph):

    # Reverse the graph
    reverse = {m: set() for m in graph}

    for caller, callees in graph.items():
        for callee in callees:
            if callee in reverse:
                reverse[callee].add(caller)

    # Find the sink
    sinks = [
        m for m in graph
        if ".<init>:" in m
        and m.split(".<init>:", 1)[0].replace("$", ".").split(".")[-1]
        == "__CANARY__Command"
    ]

    # Search backwards
    visited = set()
    stack = sinks[:]

    while stack:
        method = stack.pop()

        if method in visited:
            continue

        visited.add(method)
        stack.extend(reverse.get(method, []))

    # Return constructors that can reach the sink
    return [
        m for m in visited
        if ".<init>:" in m
    ]

def build_call_graph_from_classes(
    classes: Iterable[dict[str, Any]], 
    *,
      include_external: bool = False,
      dynamic: bool = False,
      dynamic_edges: list | None = None,
      dynamic_sites: dict[tuple[str, str], str] | None = None,
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
    dynamic_calls = []

    # Step 1: Build the normal call graph
    for cls in class_data:
        owner = cls["name"]

        for method in cls.get("methods", []):
            caller = _method_definition_id(owner, method)
            if dynamic and method["name"] == "simulateReadObject":
                continue
            code = method.get("code") or {}

            for inst in code.get("bytecode", []):
                kind = _dynamic_kind(inst, dynamic_sites) if dynamic else None

                if kind:
                    dynamic_calls.append((caller, kind))
                    continue

                callee = _invoked_method_id(inst)

                if callee and (include_external or callee in known_methods):
                    graph[caller].add(callee)
    # Connect dynamic calls to constructors
    if dynamic:
        constructors = find_constructors(graph)

        for caller, kind in dynamic_calls:
            for constructor in constructors:
                graph[caller].add(constructor)

                if dynamic_edges is not None:
                    edge = {
                        "caller": caller,
                        "callee": constructor,
                        "kind": kind
                    }

                    if edge not in dynamic_edges:
                        dynamic_edges.append(edge)

    return {caller: sorted(callees) for caller, callees in sorted(graph.items())}

def load_classes(decompiled_root: str | Path = "target/decompiled") -> list[dict[str, Any]]:
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
    decompiled_root: str | Path = "target/decompiled",
      *,
        include_external: bool = False,
        dynamic: bool = False,
        dynamic_edges: list | None = None,
        dynamic_sites: dict[tuple[str, str], str] | None = None,

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
    return build_call_graph_from_classes(
        classes,
        include_external=include_external,
        dynamic=dynamic,
        dynamic_edges=dynamic_edges,
        dynamic_sites=dynamic_sites,
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

def split_method_id(mid: str) -> tuple[str, str]:
    owner, _, name = mid.split(":(", 1)[0].rpartition(".")
    return owner, name

def find_dynamic_sites(classes: Iterable[dict[str, Any]], dynamic_sites: dict[tuple[str, str], str]) -> dict[str, set[str]]:
    sites: dict[str, set[str]] = defaultdict(set)
    for cls in classes:
        for method in cls.get("methods", []):
            caller = _method_definition_id(cls["name"], method)
            for inst in (method.get("code") or {}).get("bytecode", []):
                kind = _dynamic_kind(inst, dynamic_sites)
                if kind:
                    sites[caller].add(kind)
    return dict(sites)

def find_stubs(graph: dict[str, list[str]], stubs: dict[str, str]) -> dict[str, str]:
    found = {}
    for mid in graph:
        owner, name = split_method_id(mid)
        for key in (mid, f"{owner}.{name}", name):
            if key in stubs:
                found[mid] = stubs[key]
                break
    return found

def find_sinks(graph: dict[str, list[str]], specs: Iterable[str]) -> list[str]:
    specs = list(specs)
    return sorted(mid for mid in graph if any(spec in mid for spec in specs))

def callers_closure(graph: dict[str, list[str]], sinks: Iterable[str]) -> set[str]:
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

def class_name_from_file(path: Path) -> str:
    if path.suffix == ".java" and path.is_file():
        text = path.read_text(encoding="utf-8")
        match = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.MULTILINE)
        if match:
            return f"{match.group(1)}.{path.stem}"
    if path.suffix == ".json" and path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("name"), str):
            return data["name"].replace("/", ".")
    parts = list(path.with_suffix("").parts)
    if "jpamb" in parts:
        parts = parts[parts.index("jpamb"):]
    return ".".join(parts)

def top_level(class_name: str) -> str:
    return class_name.replace("/", ".").split("$")[0]

def select_scope(
    classes: list[dict[str, Any]], target: str
) -> tuple[list[dict[str, Any]], list[str]]:
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
    parser = argparse.ArgumentParser(description="JPAMB bytecode call graph")
    parser.add_argument("target", nargs="?", help="Optional JPAMB target method ID or class file")
    parser.add_argument("--config", type=Path, help="Fuzzer configuration JSON")
    parser.add_argument("--decompiled", type=Path, default=Path("target/decompiled"))
    parser.add_argument("--entry", help="Filter the legacy graph from a method ID")
    parser.add_argument("--include-external", action="store_true")
    parser.add_argument("--dynamic", action="store_true")
    parser.add_argument("--format", choices=("json", "dot", "detailed-json"), default="json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--write-json", action="store_true", help="Write to call-graph.json")
    parser.add_argument("--sink", action="append", help="Sink method substring (repeatable)")
    parser.add_argument("--stub", action="append", help="KIND=NAME (repeatable)")
    args = parser.parse_args(argv)

    if args.write_json:
        if args.format == "dot":
            parser.error("--write-json cannot be combined with --format dot")
        if args.output is None:
            args.output = Path(DEFAULT_JSON_OUTPUT)

    try:
        config_sinks: list[str] = []
        stubs: dict[str, str] = {}
        config_sites: dict[tuple[str, str], str] | None = None
        if args.config is not None:
            config_sinks, stubs, config_sites = load_config(args.config)

        sink_specs = args.sink if args.sink else config_sinks
        for spec in args.stub or []:
            kind, sep, name = spec.partition("=")
            if not sep or kind not in KINDS or not name:
                raise ValueError(f"--stub expects KIND=NAME, KIND in {KINDS}: {spec!r}")
            stubs[name] = kind

        if args.target:
            # Project fuzzer mode: positional target, --config, and rich JSON.
            if not sink_specs:
                raise ValueError("Target mode needs sinks via --config or --sink")
            classes = load_classes(args.decompiled)
            scope, entries = select_scope(classes, args.target)
            graph = build_call_graph_from_classes(scope)
            sinks = find_sinks(graph, sink_specs)
            if not sinks:
                print("call_graph: warning: no sink in this source file", file=sys.stderr)

            if config_sites is None:
                # Allow --sink-only invocation with the original built-in sites.
                configured = {
                    ("java/lang/Class", "forName"): "reflection",
                    ("java/lang/Class", "newInstance"): "reflection",
                    ("java/lang/reflect/Constructor", "newInstance"): "reflection",
                    ("java/io/ObjectInputStream", "readObject"): "deserialization",
                }
            else:
                configured = config_sites
            sites = find_dynamic_sites(scope, configured)
            graph, dynamic_edges = add_dynamic_edges(
                graph, sites, find_stubs(graph, stubs), sinks
            )
            reached: set[str] = set()
            for entry in entries:
                reached.update(reachable_methods(graph, entry))
            graph = {
                method: [callee for callee in graph[method] if callee in reached]
                for method in sorted(reached)
                if method in graph
            }
            dynamic_edges = [
                edge for edge in dynamic_edges
                if edge["caller"] in graph and edge["callee"] in graph
            ]
            payload = {"graph": graph, "dynamic_edges": dynamic_edges, "sinks": sinks}
        else:
            # Keep the original CLI and its plain-JSON output intact.
            dynamic_edges = []
            graph = build_call_graph(
                args.decompiled,
                include_external=args.include_external,
                dynamic=args.dynamic or bool(args.config),
                dynamic_edges=dynamic_edges,
                dynamic_sites=config_sites,
            )
            if args.entry:
                reached = set(reachable_methods(graph, args.entry))
                graph = {
                    method: [callee for callee in callees if callee in reached]
                    for method, callees in graph.items() if method in reached
                }
                dynamic_edges = [
                    edge for edge in dynamic_edges
                    if edge["callee"] in graph.get(edge["caller"], [])
                ]
            sinks = find_sinks(graph, sink_specs) if sink_specs else [
                method for method in graph
                if ".<init>:" in method
                and method.split(".<init>:", 1)[0].replace("$", ".").split(".")[-1]
                == "__CANARY__Command"
            ]
            payload = {"graph": graph, "dynamic_edges": dynamic_edges, "sinks": sinks}

        if args.format == "dot":
            output = _dot(graph, dynamic_edges)
        elif args.target or args.format == "detailed-json":
            output = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        else:
            output = json.dumps(graph, indent=2, ensure_ascii=False) + "\n"

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
