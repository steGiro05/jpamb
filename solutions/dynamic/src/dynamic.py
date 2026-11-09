import json, os, random, subprocess, sys, math
from collections.abc import Mapping
from pathlib import Path
from dataclasses import dataclass

import jpamb, jvm
from interpreter import run, interpret # interpret import needed for the framework
from fuzzer import generate_parameter, dynamic_payloads, fuzz_values, is_string
from coverage import closest_node, compute_distances
from settings import NODE_ATTEMPTS, SYSTEMATIC_TRIALS

DEFAULT_CONFIG = Path("solutions/dynamic/src/config.json")

# ----------------------------------------------------------------- taint config
# Role of a tainted parameter = what the sink expects as input.
ROLE_CLASS_NAME = 'class_name'    # Class.forName(...)         -> plain class name
ROLE_SERIALIZED = 'serialized'    # simulateReadObject(...)    -> serialized payload
ROLE_ANY = 'any'                  # unknown sink               -> every payload

# Role -> kind of dynamic edge in the call graph that produces its payloads.
ROLE_KIND = {
    ROLE_CLASS_NAME: 'reflection',
    ROLE_SERIALIZED: 'deserialization',
}

TAINTED_WEIGHT = 8      # a tainted parameter is picked 8x more often than an untainted one
MAX_DICT_BASES = 20     # cap on base strings fed to the dictionary operations
MAX_DICT_SOURCES = 25   # cap on visited methods whose dictionary feeds the pool

def _debug_log(*args, **kwargs):
    with open('debug.log', 'a', encoding='utf-8') as f:
        print(*args, file=f, **kwargs)

class OutOfBudget(Exception):
    """Raised when the global cap on interpreter runs is reached."""

def load_call_graph(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"call graph file not found: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"call graph file is not valid JSON: {path}") from error
    if not isinstance(data, Mapping):
        raise ValueError("call graph JSON must be an object")
    return dict(data)

def request_call_graph(entry_method: jvm.AbsMethodID, *, config_path: Path | None = None) -> dict:
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
        _debug_log(f"Call graph request failed for {entry_method}: {completed.stderr.strip()}")
        return {}
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {}
    return dict(data) if isinstance(data, Mapping) else {}

def obtain_call_graph(entry_method: jvm.AbsMethodID) -> dict:
    precomputed = os.environ.get("JPAMB_CALL_GRAPH_PATH")
    if precomputed:
        try:
            return load_call_graph(Path(precomputed))
        except ValueError:
            pass
    return request_call_graph(entry_method)


def load_dictionary(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return data

def request_dictionary(entry_method: jvm.AbsMethodID) -> list[dict]:
    completed = subprocess.run(
        [
            "string-dictionary", 
            entry_method.encode(),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        _debug_log(f"Dictionary request failed for {entry_method}: {completed.stderr.strip()}")
        return []
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []

def obtain_dictionary(entry_method: jvm.AbsMethodID) -> list[dict]:
    precomputed = os.environ.get("JPAMB_STRING_DICTIONARY_PATH")
    if precomputed:
        data = load_dictionary(Path(precomputed))
        if data:
            return data
    return request_dictionary(entry_method)

# ------------------------------------------------------------------------ taint

@dataclass(frozen=True)
class TaintHints:
    """Which parameters reach a taint_sink, and what the sink expects (param -> roles)."""
    roles: dict[int, frozenset[str]]

def sink_role(taint_sink: str) -> str | None:
    """from the taint_sink decide whether the input is a class name or a serialized object."""
    name = taint_sink.split(':(')[0]
    if name.endswith(('.forName', '.loadClass')):
        return ROLE_CLASS_NAME
    if name.endswith(('.simulateReadObject', '.readObject')):
        return ROLE_SERIALIZED
    return None

def parse_hints(raw: Mapping) -> TaintHints:
    roles: dict[int, set[str]] = {}
    for finding in raw.get('findings', []):
        role = sink_role(finding.get('taint_sink', '')) or ROLE_ANY
        for param in finding.get('relevant_parameters', []):
            if isinstance(param, int):
                roles.setdefault(param, set()).add(role)
    return TaintHints({param: frozenset(r) for (param, r) in roles.items()})

def obtain_taint_hints(bc, methodid: jvm.AbsMethodID, call_graph_data: dict) -> dict:
    precomputed = os.environ.get("JPAMB_TAINT_HINTS_PATH")
    if precomputed:
        try:
            data = json.loads(Path(precomputed).read_text(encoding="utf-8"))
            if isinstance(data, Mapping):
                return dict(data)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
    try:
        from taint import analyze_with_call_graph
        return dict(analyze_with_call_graph(bc, methodid, call_graph_data))
    except Exception as error:
        _debug_log(f'Taint analysis unavailable: {error!r}')
        return {}

def payloads_by_role(call_graph_data: dict, distances: dict[str, int]) -> dict[str, list[str]]:
    """
    STEP: base payloads per role.
    Only classes that can reach a sink (finite distance) are kept and they are sorted by
    distance, so the class closest to the sink comes first.
    """
    edges = [e for e in call_graph_data.get('dynamic_edges', []) if e.get('callee')]
    reachable = [e for e in edges if e['callee'] in distances]
    if not reachable:               
        _debug_log("Callee name not matching the distance.")
        reachable = edges
    reachable.sort(key=lambda e: distances.get(e['callee'], math.inf)) 

    result: dict[str, list[str]] = {}
    for (role, kind) in ROLE_KIND.items():
        subset = [e for e in reachable if e.get('kind') == kind]
        result[role] = dynamic_payloads({'dynamic_edges': subset})
    return result

# ----------------------------------------------------------------------- search

@dataclass(frozen=True)
class Seed:
    """Already tried input + strings in the form (parameter_position -> value)."""
    values: list
    strings: dict[int, str]


@dataclass(frozen=True)
class Mutation:
    """Substitute tainted string parameter `param` of seed `seed_idx` with `new_value`."""
    seed_idx: int
    param: int
    new_value: str


class NodeSearch:
    """
    Taint-guided, coverage based fuzzing.

    Parameters are split in two groups:
      - tainted strings  : fuzzed with the payload/dictionary pool of the target node
      - everything else  : fuzzed with the generic logic of fuzzer.fuzz_values
    A tainted parameter is picked TAINTED_WEIGHT times more often than the others.

    Untainted strings are fuzzed with the dictionary too, but with an EMPTY base: no class name
    or payload makes sense for them, so the generator only emits the constants the checks compare
    against (equals "admin" -> "admin", startsWith "x" -> "x", ...).

    Dictionary sources: the strings come from the dictionary of the target node, of the entry
    method AND of every visited method (even those with no distance to the sink, e.g. a helper
    like buildClassName that holds a constant used in a concatenation). A method contributes
    only after an input has actually reached it.

    Cycle:
      1. fallback_candidate() builds the first seeds (tainted strings from the pool, the rest generic).
      2. next_candidate() mutates ONE parameter (any type) of a corpus seed.
      3. The caller executes and passes visited nodes to observe().
      4. observe() checks if the new input is:
           - closer to the target -> new target, corpus reset to the seed that reached it
           - nodes never seen before -> the input enters the corpus, budget renewed
           - otherwise -> no effect, the budget continues to decrease
    """

    def __init__(self, rand: random.Random, methodid: jvm.AbsMethodID, start: str,
                 distances: dict[str, int], hints: TaintHints,
                 role_payloads: dict[str, list[str]], attempts: int = NODE_ATTEMPTS):
        self.rand = rand
        self.methodid = methodid
        self.distances = distances
        self.role_payloads = role_payloads
        self.attempts = attempts

        self.param_types = list(methodid.extension.params)
        string_params = {i for (i, t) in enumerate(self.param_types) if is_string(t)}
        hinted = {p for p in hints.roles if 0 <= p < len(self.param_types)}
        self.roles = hints.roles
        self.tainted: set[int] = hinted or string_params
        self.pooled: set[int] = self.tainted & string_params   # mutated with the pool
        self.plain: set[int] = string_params - self.tainted    # untainted strings: dictionary, empty base

        self.covered: set[str] = set() # globally visited nodes
        self.all_pool: list[str] = [] # all strings ever generated for any node, for the generic pool
        self._dictionaries: dict[str, list[dict]] = {}
        self.sources: list[str] = [start]   # methods whose dictionary feeds the pool, in discovery order

        self.target: str
        self.target_distance: float
        self.corpus: list[Seed]
        self.pools: dict[int, list[str]]
        self.tried: set[Mutation]
        self.left: int

        self._retarget(start, distances.get(start, math.inf), seed=None)

    # ------------------------------------------------------------------ target

    def _retarget(self, node: str, distance: float, seed: Seed | None) -> None:
        self.target = node
        self.target_distance = distance
        self.corpus = [seed] if seed else [] # register the seed that reached the new target, if any
        self._refresh_pools()
        self.tried = set()
        self.left = self.attempts # reset the budget for the new target

    def _refresh_pools(self) -> None:
        """Rebuild the pools for the current target. `tried` stays valid (a mutation is keyed by its value)."""
        self.pools = {param: self._param_pool(self.target, param) for param in self.pooled}
        if self.plain:
            plain_pool = self._plain_pool(self.target)
            self.pools.update({param: plain_pool for param in self.plain})
        for pool in self.pools.values():
            self.all_pool = list(dict.fromkeys(self.all_pool + pool))

    # -------------------------------------------------------------------- pool

    def _dictionary(self, node: str) -> list[dict]:
        if node not in self._dictionaries:
            try:
                self._dictionaries[node] = obtain_dictionary(jvm.AbsMethodID.decode(node))
            except Exception:
                self._dictionaries[node] = []
        return self._dictionaries[node]

    def _add_sources(self, nodes: set[str]) -> bool:
        """Newly visited methods become dictionary sources if their dictionary has something to give."""
        added = False
        for node in sorted(nodes):   # sorted: sets of str iterate in a different order on every run
            if len(self.sources) >= MAX_DICT_SOURCES:
                break
            if '@' in node:   # instruction ids ("method@offset") are coverage points, not methods
                continue
            if node not in self.sources and self._dictionary(node):
                self.sources.append(node)
                added = True
                _debug_log(f"New dictionary source: {node}")
        return added

    def _dictionary_entries(self, node: str) -> list[tuple[str, list]]:
        """Dictionary operations of the target, then of the entry and of the visited methods.
        Deduplicated: with a precomputed dictionary file every node returns the same entries."""
        unique: dict[tuple[str, str], tuple[str, list]] = {}
        for source in dict.fromkeys([node] + self.sources):
            for entry in self._dictionary(source):
                operation = entry.get('method')
                
                strings = entry.get('strings', [])
                if not strings and 'string' in entry:
                    strings = [entry['string']]
                    
                if operation and strings:
                    unique.setdefault((operation, repr(strings)), (operation, strings))
        return list(unique.values())

    def _payloads_for(self, param: int) -> list[str]:
        """Base payloads matching the role(s) of the parameter (class names vs serialized objects)."""
        roles = self.roles.get(param, frozenset({ROLE_ANY}))
        if ROLE_ANY in roles:
            roles = frozenset(self.role_payloads)
        merged: list[str] = []
        for role in sorted(roles):
            merged.extend(self.role_payloads.get(role, []))
        return list(dict.fromkeys(merged))

    def _param_pool(self, node: str, param: int) -> list[str]:
        """Candidates for one tainted parameter: its role payloads + dictionary variants of node."""
        payloads = self._payloads_for(param)
        bases = [seed.strings[param] for seed in self.corpus if param in seed.strings]
        bases += payloads or ['']
        bases = list(dict.fromkeys(bases))[:MAX_DICT_BASES]

        entries = self._dictionary_entries(node)
        candidates = list(payloads)
        for base in bases:
            for (operation, strings) in entries:
                candidates.extend(generate_parameter(operation, strings, base))
        return list(dict.fromkeys(candidates))

    def _plain_pool(self, node: str) -> list[str]:
        """Candidates for untainted strings: dictionary operations applied to the empty string,
        i.e. just the constants the checks compare against (plus the empty string itself)."""
        candidates = ['']
        for (operation, strings) in self._dictionary_entries(node):
            candidates.extend(generate_parameter(operation, strings, ''))
        return list(dict.fromkeys(candidates))

    def generic_pool(self) -> list[str]:
        return self.all_pool

    # ------------------------------------------------------------ first inputs

    def fallback_candidate(self, trial: int) -> tuple[list, dict[int, str]]:
        """
        Used while the guided search has nothing to mutate.
        Untainted non-string parameters: generic fuzz_values logic.
        Untainted strings: random pick from the dictionary pool (empty base).
        Tainted strings: systematic enumeration of their pool (payloads closest to the sink first).
        """
        (values, strings) = fuzz_values(self.rand, self.methodid, trial, self.generic_pool())
        for (k, param) in enumerate(sorted(self.pooled)):
            pool = self.pools.get(param) or []
            if not pool:
                continue
            value = pool[trial // len(pool) ** k % len(pool)]
            values[param] = jpamb.case.String(value)
            strings[param] = value
        for param in sorted(self.plain):
            pool = self.pools.get(param) or []
            if pool:   # random pick: the tainted enumeration above already uses the trial index
                value = self.rand.choice(pool)
                values[param] = jpamb.case.String(value)
                strings[param] = value
        return (values, strings)

    # --------------------------------------------------------------- Mutations

    def _mutate_pooled(self, seed_idx: int, seed: Seed, param: int) -> tuple[list, dict[int, str]] | None:
        """Tainted string: replace it with an untried candidate from its pool."""
        current = seed.strings.get(param)
        options = [s for s in self.pools.get(param, [])
                   if s != current and Mutation(seed_idx, param, s) not in self.tried]
        if not options:
            return None
        new_value = self.rand.choice(options)
        self.tried.add(Mutation(seed_idx, param, new_value))
        values = list(seed.values)
        values[param] = jpamb.case.String(new_value)
        return (values, {**seed.strings, param: new_value})

    def _mutate_generic(self, seed: Seed, param: int) -> tuple[list, dict[int, str]]:
        """Any other parameter: take a fresh value from the generic fuzz_values logic."""
        trial = self.rand.randrange(2 * SYSTEMATIC_TRIALS)  # half systematic, half random values
        (fresh_values, fresh_strings) = fuzz_values(self.rand, self.methodid, trial, self.generic_pool())
        values = list(seed.values)
        values[param] = fresh_values[param]
        strings = dict(seed.strings)
        if param in fresh_strings:
            strings[param] = fresh_strings[param]
        return (values, strings)

    def next_candidate(self) -> tuple[list, dict[int, str]] | None:
        if self.left <= 0 or not self.corpus:
            return None

        seed_order = list(range(len(self.corpus)))
        self.rand.shuffle(seed_order)
        for seed_idx in seed_order:
            seed = self.corpus[seed_idx]
            remaining = list(range(len(self.param_types)))
            while remaining:
                # budget per parameter: tainted ones are drawn more often
                weights = [TAINTED_WEIGHT if p in self.tainted else 1 for p in remaining]
                param = self.rand.choices(remaining, weights=weights)[0]
                remaining.remove(param)
                if param in self.pools:   # tainted AND untainted strings
                    candidate = self._mutate_pooled(seed_idx, seed, param)
                else:
                    candidate = self._mutate_generic(seed, param)
                if candidate is not None:
                    self.left -= 1
                    return candidate

        self.left = 0
        return None

    # ---------------------------------------------------------------- feedback

    def observe(self, values: list, strings: dict[int, str], visited: set[str]) -> None:
        new_nodes = visited - self.covered
        self.covered |= visited
        grew = self._add_sources(new_nodes)   # new methods may bring new constants
        seed = Seed(values, strings)

        distance, node = closest_node(self.distances, visited)
        if node is not None and distance < self.target_distance:
            self._retarget(node, distance, seed)   # rebuilds the pools, new sources included
        elif new_nodes:
            self.corpus.append(seed)
            self.left = self.attempts
            if grew:
                self._refresh_pools()              # keeps corpus, tried and budget

# ------------------------------------------------------------------------ debug
# JPAMB_FUZZ_DEBUG=1                     writes a trace of the search to debug.log
# JPAMB_FUZZ_PROBE=__CANARY__,admin      also reports which pools contain these strings
FUZZ_DEBUG = True
PROBES = [p for p in os.environ.get('JPAMB_FUZZ_PROBE', '').split(',') if p]

def _short(node: str) -> str:
    return node.split(':(')[0].rsplit('.', 1)[-1]

def _fmt(value) -> str:
    """jpamb.case values as plain python values (String/Int/Boolean -> value, Array -> values)."""
    inner = getattr(value, 'value', None)
    if inner is None:
        inner = getattr(value, 'values', value)
    return repr(inner)

def _probe_report(search: 'NodeSearch') -> str:
    rows = []
    for probe in PROBES:
        where = sorted(p for (p, pool) in search.pools.items() if probe in pool)
        rows.append(f"{probe!r} in pools of params {where or 'NONE'}")
    return '; '.join(rows)

def _trace_setup(methodid, start, distances, hints, role_payloads, search: 'NodeSearch') -> None:
    _debug_log('=== FUZZ DEBUG: setup ===')
    _debug_log(f'params           : {[str(t) for t in search.param_types]}')
    _debug_log(f'distance(start)  : {distances.get(start, math.inf)}')
    _debug_log(f'taint roles      : {hints.roles}')
    _debug_log(f'tainted / pooled / plain : {sorted(search.tainted)} / {sorted(search.pooled)} / {sorted(search.plain)}')
    for (role, payloads) in role_payloads.items():
        _debug_log(f'payloads[{role}] ({len(payloads)}): {payloads[:8]}')
    for (param, pool) in search.pools.items():
        _debug_log(f'pool p{param} ({len(pool)}): {pool[:40]}')
    if PROBES:
        _debug_log(f'probes           : {_probe_report(search)}')

def _trace_run(n: int, phase: str, start: str, values: list, outcome, visited: set[str],
               search: 'NodeSearch') -> None:
    entry_offsets = [int(v.rsplit('@', 1)[1]) for v in visited if v.startswith(start + '@')]
    n_instr = sum('@' in v for v in visited)
    new = len(visited - search.covered)
    _debug_log(f'run {n:3d} {phase:8s} out={outcome!s:16} entry_depth={max(entry_offsets, default=-1):3d} '
               f'methods={len(visited) - n_instr:2d} instr={n_instr:3d} new={new:3d} '
               f'corpus={len(search.corpus)} left={search.left} target={_short(search.target)}')
    _debug_log(f'        in=({", ".join(_fmt(v) for v in values)})')

def _trace_end(runs: int, trial: int, behaviors: set, search: 'NodeSearch') -> None:
    methods = sorted(v for v in search.covered if '@' not in v)
    _debug_log('=== FUZZ DEBUG: end ===')
    _debug_log(f'runs={runs} fallback_trials={trial} behaviors={sorted(map(str, behaviors))}')
    _debug_log(f'dictionary sources: {[_short(s) for s in search.sources]}')
    _debug_log(f'covered methods   : {[_short(m) for m in methods]}')
    for (param, pool) in search.pools.items():
        _debug_log(f'final pool p{param} ({len(pool)}): {pool[:40]}')
    if PROBES:
        _debug_log(f'probes           : {_probe_report(search)}')

def analyse() -> int:
    methodid = jpamb.getmethodid('dynamic', '0.1.0', 'DTU Project Group 8', ['dynamic', 'python', 'fuzzing', 'random', 'dictionary', 'syntactic', 'taint'], for_science=True)
    (suite, eff) = jpamb.setup()
    bc = jpamb.Bytecode(suite, eff, {})
    start = str(methodid)
    
    call_graph_data = obtain_call_graph(methodid)
    distances = compute_distances(call_graph_data)

    raw_hints = obtain_taint_hints(bc, methodid, call_graph_data)
    hints = parse_hints(raw_hints)
    role_payloads = payloads_by_role(call_graph_data, distances)

    rand = random.Random(0)
    MAX_STEPS = 200
    MAX_TESTS = 100
    MAX_TOTAL_RUNS = 500
    search = NodeSearch(rand, methodid, start, distances, hints, role_payloads)
    if FUZZ_DEBUG:
        _trace_setup(methodid, start, distances, hints, role_payloads, search)
    has_params = len(methodid.extension.params) > 0
    n_trials = MAX_TESTS if has_params else 1
    behaviors = set()
    runs = 0

    last_outcome = None

    def execute(values) -> set[str]:
        nonlocal runs, last_outcome
        if runs >= MAX_TOTAL_RUNS:
            raise OutOfBudget
        runs += 1
        (outcome, visited_methods) = run(bc, methodid, jpamb.case.Input(values), MAX_STEPS)
        last_outcome = outcome   # None = MAX_STEPS exhausted (or no termination)
        if outcome is not None:
            behaviors.add(outcome)
        elif not has_params:
            behaviors.add('*')
        return {str(m) for m in visited_methods or ()}
    trial = 0
    try:
        while trial < n_trials:
            phase = 'guided'
            candidate = search.next_candidate()
            if candidate is None:
                phase = 'fallback'
                (values, strings) = search.fallback_candidate(trial)
                trial += 1
            else:
                (values, strings) = candidate
            visited = execute(values)
            if FUZZ_DEBUG:
                _trace_run(runs, phase, start, values, last_outcome, visited, search)
            search.observe(values, strings, visited)
    except OutOfBudget:
        pass
    if FUZZ_DEBUG:
        _trace_end(runs, trial, behaviors, search)
    for query in jpamb.QUERIES:
        print(f"{query};{('found' if query in behaviors else 'not-found')}")
        
    return 0

if __name__ == "__main__":
    raise SystemExit(analyse())