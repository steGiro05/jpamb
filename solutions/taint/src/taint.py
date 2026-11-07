"""Executable integration point for the JPAMB taint analysis."""

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import jpamb
import jvm

from taint_analysis import TaintAnalyzer, analysis_hints, call_graph_from_json

def _debug_log(*args, **kwargs):
    with open('debug.log', 'a', encoding='utf-8') as f:
        print(*args, file=f, **kwargs)

DEFAULT_CONFIG = Path("solutions/dynamic/src/config.json")


def load_call_graph(path: Path) -> Mapping[str, Any]:
    """Read a call graph previously produced by the syntactic stage."""

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"call graph file not found: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"call graph file is not valid JSON: {path}") from error
    if not isinstance(data, Mapping):
        raise ValueError("call graph JSON must be an object")
    return data


def request_call_graph(
    entry_method: jvm.AbsMethodID,
    *,
    config_path: Path | None = None,
) -> Mapping[str, Any]:
    """Run the syntactic call graph and decode its JSON result."""

    if config_path is None:
        configured = os.environ.get("JPAMB_ANALYZER_CONFIG")
        config_path = Path(configured) if configured else DEFAULT_CONFIG

    completed = subprocess.run(
        [
            "call-graph", 
            entry_method.encode(),
            "--config",
            str(config_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "unknown call-graph error"
        raise RuntimeError(f"call graph failed: {detail}")

    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("call graph did not produce valid JSON") from error
    if not isinstance(data, Mapping):
        raise ValueError("call graph JSON must be an object")
    return data


def obtain_call_graph(entry_method: jvm.AbsMethodID) -> Mapping[str, Any]:
    """Prefer the shared syntactic artifact, with a standalone fallback."""

    precomputed = os.environ.get("JPAMB_CALL_GRAPH_PATH")
    if precomputed:
        return load_call_graph(Path(precomputed))
    return request_call_graph(entry_method)


def analyze_with_call_graph(
    program: jpamb.Bytecode,
    entry_method: jvm.AbsMethodID,
    call_graph_data: Mapping[str, Any],
) -> dict[str, Any]:
    """Run the fixpoint analysis and return JSON-compatible fuzzer hints."""

    call_graph = call_graph_from_json(call_graph_data)
    result = TaintAnalyzer(program, call_graph).analyze(entry_method)
    return analysis_hints(entry_method, result)


def analyse() -> int:
    """JPAMB command producing static taint hints for one entry method."""

    entry_method = jpamb.getmethodid(
        "taint",
        "0.1.0",
        "DTU Project Group 8",
        ["static", "taint", "python", "interprocedural"],
        for_science=True,
    )
    suite, effect = jpamb.setup()
    program = jpamb.Bytecode(suite, effect, {})

    try:
        call_graph_data = obtain_call_graph(entry_method)
        hints = analyze_with_call_graph(program, entry_method, call_graph_data)
    except (RuntimeError, ValueError, KeyError, NotImplementedError) as error:
        print(f"taint-analysis: {error}", file=sys.stderr)
        return 1

    _debug_log(json.dumps(hints, indent=2, sort_keys=True))
    print(json.dumps(hints, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(analyse())