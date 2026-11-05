"""Conversion from syntactic call-graph JSON to taint-analysis types."""

from collections import deque
from collections.abc import Mapping
from typing import Any

import jvm
from jvm.state import PC

from taint_analysis.analyzer import CallGraph


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def _method_id(value: Any, name: str) -> jvm.AbsMethodID:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a method ID string")
    try:
        return jvm.AbsMethodID.decode(value)
    except ValueError as error:
        raise ValueError(f"invalid method ID in {name}: {value!r}") from error


def _method_graph(
    data: Mapping[str, Any],
) -> dict[jvm.AbsMethodID, tuple[jvm.AbsMethodID, ...]]:
    raw_graph = _mapping(data.get("graph"), "graph")
    graph: dict[jvm.AbsMethodID, tuple[jvm.AbsMethodID, ...]] = {}
    for caller_code, raw_callees in raw_graph.items():
        caller = _method_id(caller_code, "graph key")
        if not isinstance(raw_callees, list):
            raise ValueError(f"callees of {caller} must be a list")
        graph[caller] = tuple(
            _method_id(callee, f"callee of {caller}") for callee in raw_callees
        )
    return graph


def _exploit_targets(data: Mapping[str, Any]) -> tuple[jvm.AbsMethodID, ...]:
    raw_targets = data.get("exploit_targets")
    if raw_targets is None:
        # Transitional compatibility with the current syntactic output.
        raw_targets = data.get("sinks")
    if not isinstance(raw_targets, list):
        raise ValueError("exploit_targets must be a list")
    return tuple(_method_id(target, "exploit target") for target in raw_targets)


def _distances_to_targets(
    graph: Mapping[jvm.AbsMethodID, tuple[jvm.AbsMethodID, ...]],
    targets: tuple[jvm.AbsMethodID, ...],
) -> dict[jvm.AbsMethodID, int]:
    callers: dict[jvm.AbsMethodID, set[jvm.AbsMethodID]] = {}
    for caller, callees in graph.items():
        for callee in callees:
            callers.setdefault(callee, set()).add(caller)

    distances = {target: 0 for target in targets}
    worklist = deque(targets)
    while worklist:
        callee = worklist.popleft()
        for caller in callers.get(callee, ()):
            if caller not in distances:
                distances[caller] = distances[callee] + 1
                worklist.append(caller)
    return distances


def _call_site_edges(
    data: Mapping[str, Any],
) -> dict[PC, tuple[jvm.AbsMethodID, ...]]:
    raw_sites = data.get("call_sites")
    if not isinstance(raw_sites, list):
        raise ValueError("call_sites must be a list")

    edges: dict[PC, tuple[jvm.AbsMethodID, ...]] = {}
    for index, raw_site in enumerate(raw_sites):
        site = _mapping(raw_site, f"call_sites[{index}]")
        caller = _method_id(site.get("caller"), f"call_sites[{index}].caller")
        instruction_index = site.get("instruction_index")
        if not isinstance(instruction_index, int) or instruction_index < 0:
            raise ValueError(
                f"call_sites[{index}].instruction_index must be a non-negative integer"
            )

        raw_callees = site.get("resolved_callees")
        if raw_callees is None:
            raw_callees = site.get("callees")
        if not isinstance(raw_callees, list):
            raise ValueError(
                f"call_sites[{index}].resolved_callees must be a list"
            )

        pc = PC(caller, instruction_index)
        if pc in edges:
            raise ValueError(f"duplicate call-site entry for {pc}")
        edges[pc] = tuple(
            _method_id(callee, f"resolved callee at {pc}")
            for callee in raw_callees
        )
    return edges


def call_graph_from_json(data: Mapping[str, Any]) -> CallGraph:
    """Build the taint call graph from the syntactic analysis output."""

    graph = _method_graph(data)
    targets = _exploit_targets(data)
    return CallGraph(
        edges=_call_site_edges(data),
        distances_to_exploit_target=_distances_to_targets(graph, targets),
    )
