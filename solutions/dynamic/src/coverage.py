import math
from collections import deque

def compute_distances(call_graph_data: dict) -> dict[str, int]:
    graph = call_graph_data.get('graph', {})
    sinks = set(call_graph_data.get('sinks', []))
    callers: dict[str, set[str]] = {}
    for (caller, callees) in graph.items():
        for callee in callees:
            callers.setdefault(callee, set()).add(caller)
    distances = {sink: 0 for sink in sinks}
    queue = deque(sinks)
    while queue:
        node = queue.popleft()
        for caller in callers.get(node, ()):
            if caller not in distances:
                distances[caller] = distances[node] + 1
                queue.append(caller)
    return distances

def closest_node(distances: dict[str, int], visited: set[str]) -> tuple[float, str | None]:
    (best_distance, best_node) = (math.inf, None)
    for node in visited:
        d = distances.get(node)
        if d is None:
            continue
        if d < best_distance or (d == best_distance and node < best_node):
            (best_distance, best_node) = (d, node)
    return (best_distance, best_node)