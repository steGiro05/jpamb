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

# Dynamic sites are linked to these methods of the backward closure.
ENTRY_POINT_NAMES = ("<init>", "<clinit>")

KINDS = ("reflection", "deserialization")
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
    """Encode a JVM2JSON type as a JVM type descriptor."""
    if value is None:
        return "V"
    if isinstance(value, str):
        if value in PRIMITIVES:
            return PRIMITIVES[value]
        if value.startswith("[") or (value.startswith("L") and value.endswith(";")):
            return value
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
    owner = class_name.replace("/", ".")
    signature = "".join(type_descriptor(arg) for arg in args)
    return f"{owner}.{name}:({signature}){type_descriptor(returns)}"


def split_method_id(mid: str) -> tuple[str, str]:
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
    return build_call_graph_from_classes(
        load_classes(decompiled_root), include_external=include_external
    )


def reachable_methods(graph: dict[str, list[str]], entry: str) -> list[str]:
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


def _dynamic_kind(inst: dict[str, Any], dynamic_sites: dict[tuple[str, str], str]) -> str | None:
    if inst.get("opr") != "invoke":
        return None
    method = inst.get("method")
    if not isinstance(method, dict):
        return None
    ref = method.get("ref")
    if not isinstance(ref, dict) or not isinstance(ref.get("name"), str):
        return None
    owner = ref["name"].replace(".", "/")
    return dynamic_sites.get((owner, method.get("name")))


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


# ---------------------------------------------------------------------------
# Selecting the target
# ---------------------------------------------------------------------------

FILE_SUFFIXES = {".java", ".json", ".class"}


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
        "--config",
        type=Path,
        help="Path to a JSON configuration file containing vulnerabilities, sinks, dynamic sites, and stubs.",
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
        help="Sink: any method whose ID contains TEXT (repeatable). "
        "Overrides config file if provided.",
    )
    parser.add_argument(
        "--stub",
        action="append",
        metavar="KIND=NAME",
        help="Declare a method as a stub of a dynamic mechanism. "
        "Overrides config file if provided.",
    )
    args = parser.parse_args(argv)

    if args.write_json:
        if args.format != "json":
            parser.error("--write-json cannot be combined with --format dot")
        if args.output is None:
            args.output = Path(DEFAULT_JSON_OUTPUT)

    config_sinks = []
    config_stubs = {}
    config_dynamic_sites = {}

    if args.config:
        try:
            config_sinks, config_stubs, config_dynamic_sites = load_config(args.config)
        except Exception as e:
            parser.error(f"Error loading config file: {e}")

    sinks_list = args.sink if args.sink else config_sinks
    if not sinks_list:
        parser.error("No sinks provided. Supply them via --config or --sink.")

    stubs = dict(config_stubs)
    for spec in args.stub or []:
        kind, sep, name = spec.partition("=")
        if not sep or kind not in KINDS or not name:
            parser.error(f"--stub expects KIND=NAME with KIND in {KINDS}, got {spec!r}")
        stubs[name] = kind

    try:
        scope, entries = select_scope(load_classes(args.decompiled), args.target)
        graph = build_call_graph_from_classes(scope)

        sinks = find_sinks(graph, sinks_list)
        if not sinks:
            print("call_graph: warning: no sink in this file, no dynamic edges added",
                  file=sys.stderr)
        
        sites = find_dynamic_sites(scope, config_dynamic_sites)
        graph, dynamic_edges = add_dynamic_edges(
            graph, sites, find_stubs(graph, stubs), sinks
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