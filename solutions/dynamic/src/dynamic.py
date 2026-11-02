import json
import os
import random
import subprocess
from collections import deque
from itertools import islice, product 

import jpamb
import jvm

from interpreter import run, interpret  # noqa: F401

def _debug_log(*args, **kwargs):
    with open("debug.log", "a", encoding="utf-8") as f:
        print(*args, file=f, **kwargs)

# ============================================================
# FUZZING
# - Every call-graph node has a distance to its closest sink.
# - The search always has a *target node* (initially the starting method).
#   For the target we build its string dictionary and mutate class names
#   with the same rules as before (generate_parameter), i.e. according to
#   the comparisons made in that node.
# - Coverage based: inputs that cover new methods are kept in a corpus and
#   only their strings are mutated.
# - If a run enters a node that is closer to a sink, that node becomes the
#   new target and the search restarts on it.
# - Dead end (no more mutations / no progress): generic strategy
#   (`fuzz_values`: interesting values, then random).
# ============================================================

SYSTEMATIC_TRIALS = 80
NODE_ATTEMPTS = 30
INF = float("inf")

INTERESTING_INTS = [
    0, 1, -1, 2, -2, 3, -3, 5, -5, 10, -10, 42, -42, 100, -100,
    10054202, 10054203, 10054204, -10054202, -10054203, -10054204,
    2147483647, -2147483648,
]

INTERESTING_INT_ARRAYS = [
    [], [0], [1], [-1], [0, 0], [1, 2, 3], [-1, 0, 1], [42], [100],
]

INTERESTING_CHAR_ARRAYS = ["", "a", "x", "hello", "Hello", "test"]

LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
SERIAL_PREFIX = "SER"
SERIAL_SEPARATOR = "|"
PARAM_SEPARATOR = ","
OBJECT_PARAM_INTS = [1, 0, -1, 9999, 42, 2147483647, -2147483648]
OBJECT_PARAM_STRINGS = ["", "x", "test"]
MAX_PARAM_COMBINATIONS = 12

class OutOfBudget(Exception):
    """Raised when the global cap on interpreter runs is reached."""


def is_string(param: jvm.Type) -> bool:
    return isinstance(param, jvm.Object) and param.name == jvm.ClassName(
        "java.lang.String"
    )

def fuzz_values(
    rand: random.Random,
    methodid: jvm.AbsMethodID,
    trial: int,
    string_pool: list[str],
) -> tuple[list, dict[int, str]]:
    values = []
    strings: dict[int, str] = {}
    string_position = 0

    if not string_pool:
        string_pool = ["", "__CANARY__"]

    for position, param in enumerate(methodid.extension.params):
        match param:
            case _ if is_string(param):
                index = (trial // (len(string_pool) ** string_position)) % len(
                    string_pool
                )
                value = string_pool[index]
                values.append(jpamb.case.String(value))
                strings[position] = value
                string_position += 1

            case jvm.Int():
                if trial < SYSTEMATIC_TRIALS:
                    index = (trial // (len(INTERESTING_INTS) ** position)) % len(
                        INTERESTING_INTS
                    )
                    value = INTERESTING_INTS[index]
                else:
                    value = rand.randint(-(1 << 31), (1 << 31) - 1)
                values.append(jpamb.case.Int(value))

            case jvm.Boolean():
                values.append(jpamb.case.Boolean(bool((trial // (2**position)) % 2)))

            case jvm.Array(contains=jvm.Int()):
                if trial < SYSTEMATIC_TRIALS:
                    array = INTERESTING_INT_ARRAYS[
                        trial % len(INTERESTING_INT_ARRAYS)
                    ]
                else:
                    length = rand.randint(0, 6)
                    array = [rand.choice(INTERESTING_INTS) for _ in range(length)]
                values.append(jpamb.case.Array(jvm.Int(), array))

            case jvm.Array(contains=jvm.Char()):
                if trial < SYSTEMATIC_TRIALS:
                    chars = INTERESTING_CHAR_ARRAYS[
                        trial % len(INTERESTING_CHAR_ARRAYS)
                    ]
                else:
                    length = rand.randint(0, 8)
                    chars = "".join(rand.choice(LOWERCASE) for _ in range(length))
                values.append(jpamb.case.Array(jvm.Char(), chars))

            case _:
                raise NotImplementedError(f"Unsupported input type: {param!r}")

    return values, strings


def build_call_graph(methodid: jvm.AbsMethodID) -> dict | None:
    result = subprocess.run(
        [
            "uv",
            "run",
            "python",
            "solutions/syntactic/src/call_graph.py",
            str(methodid),
            "--config",
            "solutions/dynamic/src/config.json"
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return json.loads(result.stdout)


def build_dictionary(methodid: jvm.AbsMethodID) -> list[dict]:
    result = subprocess.run(
        ["uv", "run", "python", "solutions/syntactic/src/string_dictionary.py", str(methodid)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []


def compute_distances(call_graph_data: dict) -> dict[str, int]:
    graph = call_graph_data.get("graph", {})
    sinks = set(call_graph_data.get("sinks", []))

    callers: dict[str, set[str]] = {}
    for caller, callees in graph.items():
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
    best_distance, best_node = INF, None
    for node in visited:
        d = distances.get(node)
        if d is None:
            continue
        if d < best_distance or (d == best_distance and node < best_node):
            best_distance, best_node = d, node
    return best_distance, best_node

def parse_descriptor(descriptor: str) -> list[str]:
    """Parameter types of a JVM descriptor: "(ILjava/lang/String;)V" -> ["I", "Ljava/lang/String;"]."""
    params = descriptor[descriptor.index("(") + 1 : descriptor.index(")")]
    types, i = [], 0
    while i < len(params):
        j = i
        while params[j] == "[":
            j += 1
        if params[j] == "L":
            j = params.index(";", j)
        types.append(params[i : j + 1])
        i = j + 1
    return types

def generate_object_params(param_types: list[str]) -> list[str]:
    """Serialized `params` field for a constructor, from interesting values per type."""
    if not param_types:
        return [""]

    options = []
    for t in param_types:
        if t in ("I", "J", "S", "B"):
            options.append([str(v) for v in OBJECT_PARAM_INTS])
        elif t == "Z":
            options.append(["true", "false"])
        elif t in ("D", "F"):
            options.append(["1.0", "0.0", "-1.0"])
        elif t == "C":
            options.append(["a"])
        elif t == "Ljava/lang/String;":
            options.append(OBJECT_PARAM_STRINGS)
        else:
            options.append([""])

    combinations = islice(product(*options), MAX_PARAM_COMBINATIONS)
    return [PARAM_SEPARATOR.join(c) for c in combinations]

def dynamic_payloads(call_graph_data: dict) -> list[str]:
    names = []
    
    for edge in call_graph_data.get("dynamic_edges", []):
        kind = edge.get("kind")
        callee = edge.get("callee", "")
        if not callee or ":(" not in callee:
            continue
            
        method_part, rest = callee.split(":(", 1)
        full_class_name = method_part.rsplit(".", 1)[0]
        
        short_class_name = full_class_name.split("$")[-1].split(".")[-1]
        
        if kind == "reflection":
            names.append(short_class_name)
            
        elif kind == "deserialization":
            param_types = parse_descriptor("(" + rest)
            
            for params in generate_object_params(param_types):
                payload = f"{SERIAL_PREFIX}{SERIAL_SEPARATOR}{short_class_name}{SERIAL_SEPARATOR}{params}"
                names.append(payload)

    return list(dict.fromkeys(names))


def generate_parameter(operation: str, strings: list[str], base_payload: str) -> list[str]:
    generated = []
    
    if operation == "concatenation":
        stripped_payload = base_payload
        for s in strings:
            if isinstance(s, str):
                stripped_payload = stripped_payload.replace(s, "")
        generated.append(stripped_payload)
        
        for s in strings:
            if isinstance(s, str):
                generated.append(base_payload.replace(s, ""))
                
    else:
        for s in strings:
            if not isinstance(s, str):
                continue
                
            if operation == "equals":
                generated.append(s)
                generated.append("")
                
            elif operation == "equalsIgnoreCase":
                generated.append(s.lower())
                generated.append(s.upper())
                
            elif operation == "startsWith" or operation == "contains":
                generated.append(s + base_payload)
                generated.append(base_payload)
                
            elif operation == "endsWith":
                generated.append(base_payload + s)
                generated.append(base_payload)
            
    return generated


class NodeSearch:
    def __init__(
        self,
        rand: random.Random,
        start: str,
        distances: dict[str, int],
        base_payloads: list[str],
        attempts: int = NODE_ATTEMPTS,
    ):
        self.rand = rand
        self.distances = distances
        self.base_payloads = base_payloads
        self.attempts = attempts

        self.covered: set[str] = set()
        self.all_pool: list[str] = []
        self._dictionaries: dict[str, list[dict]] = {}

        self._retarget(start, distances.get(start, INF), None, None)


    def _node_pool(self, node: str) -> list[str]:
        if node not in self._dictionaries:
            self._dictionaries[node] = build_dictionary(node)

        payload_targets = self.base_payloads if self.base_payloads else [""]
        raw = list(self.base_payloads)

        for base_payload in payload_targets:
            for entry in self._dictionaries[node]:
                operation = entry.get("method")
                strings = entry.get("strings", [])
                if operation and strings:
                    raw.extend(generate_parameter(operation, strings, base_payload))

        pool = list(dict.fromkeys(raw))
        self.all_pool = list(dict.fromkeys(self.all_pool + pool))
        return pool

    def _retarget(self, node, distance, values, strings):
        self.target = node
        self.target_distance = distance
        self.pool = self._node_pool(node)
        self.corpus = [(values, strings)] if values is not None else []
        self.tried: set[tuple[int, int, str]] = set()
        self.left = self.attempts

    def next_candidate(self):
        if self.left <= 0:
            return None

        options = [
            (ci, index, s)
            for ci, (_, strings) in enumerate(self.corpus)
            for index in strings
            for s in self.pool
            if s != strings[index] and (ci, index, s) not in self.tried
        ]
        if not options:
            self.left = 0
            return None

        self.left -= 1
        ci, index, s = self.rand.choice(options)
        self.tried.add((ci, index, s))

        values, strings = self.corpus[ci]
        new_values = list(values)
        new_values[index] = jpamb.case.String(s)
        return new_values, {**strings, index: s}

    def generic_pool(self) -> list[str]:
        return self.all_pool

    def observe(self, values, strings, visited) -> None:
        distance, node = closest_node(self.distances, visited)

        if node is not None and distance < self.target_distance:
            self.covered |= visited
            self._retarget(node, distance, values, strings)
            return

        if visited - self.covered:
            self.covered |= visited
            self.corpus.append((values, strings))
            self.left = self.attempts


def analyse():
    methodid = jpamb.getmethodid(
        "dynamic",
        "1.0",
        "bests analyzers ",
        ["dynamic", "python", "fuzzing", "random", "dictionary", "syntatic"],
        for_science=True,
    )

    suite, eff = jpamb.setup()
    bc = jpamb.Bytecode(suite, eff, {})

    start = str(methodid)

    call_graph_data = build_call_graph(methodid) or {}
    distances = compute_distances(call_graph_data)

    rand = random.Random(0)
    base_payloads = dynamic_payloads(call_graph_data)
    _debug_log(f"Base payloads: {base_payloads}")
    MAX_STEPS = 200
    MAX_TESTS = 100
    MAX_TOTAL_RUNS = 500
    
    search = NodeSearch(rand, start, distances, base_payloads)
    has_params = len(methodid.extension.params) > 0
    n_trials = MAX_TESTS if has_params else 1

    behaviors = set()
    runs = 0

    def execute(values) -> set[str]:
        nonlocal runs
        if runs >= MAX_TOTAL_RUNS:
            raise OutOfBudget
        runs += 1

        outcome, visited_methods = run(bc, methodid, jpamb.case.Input(values), MAX_STEPS)

        if outcome is not None:
            behaviors.add(outcome)
        elif not has_params:
            behaviors.add("*")

        return {str(m) for m in (visited_methods or ())}

    trial = 0
    try:
        while trial < n_trials:
            candidate = search.next_candidate()

            if candidate is None:
                values, strings = fuzz_values(rand, methodid, trial, search.generic_pool())
                trial += 1
            else:
                values, strings = candidate

            search.observe(values, strings, execute(values))
    except OutOfBudget:
        pass

    for query in jpamb.QUERIES:
        print(f"{query};{'found' if query in behaviors else 'not-found'}")