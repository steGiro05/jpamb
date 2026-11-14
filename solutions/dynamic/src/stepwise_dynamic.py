import random
import sys
import os
import jpamb

from interpreter import run

from steps.base import Fuzzer, _debug_log
from steps.naive import NaiveFuzzer
from steps.dictionary import DictFuzzer
from steps.graph import GraphFuzzer
from steps.taint_fuzzer import TaintFuzzer

def analyse() -> int:
    methodid = jpamb.getmethodid(
        'dynamic', '0.1.0', 'DTU Project Group 8', 
        ['dynamic', 'python', 'fuzzing', 'random', 'dictionary', 'syntactic', 'taint'], 
        for_science=True
    )
    suite, eff = jpamb.setup()
    bc = jpamb.Bytecode(suite, eff, {})
    
    # rand = random.Random(0)
    rand = random.Random()
    MAX_STEPS = 200
    MAX_TESTS = 50000
    # After the first assertion error, keep fuzzing for some trials
    EXTRA_TRIALS = 200

    n_trials = MAX_TESTS
    behaviors = set()
    witnesses = {}
    last_outcome = None

    fuzzer_map = {
        "naive": NaiveFuzzer,
        "dictionary": DictFuzzer,
        "graph": GraphFuzzer,
        "taint": TaintFuzzer
    }
    
    mode = os.environ.get("FUZZER_MODE", "naive").lower()
    fuzzer_class = fuzzer_map.get(mode, NaiveFuzzer)
    fuzzer = fuzzer_class(rand, methodid, bc, suite, MAX_TESTS)

    def execute(values) -> set[str]:
        nonlocal last_outcome
        
        test_input = jpamb.case.Input(values)
        outcome, visited = run(bc, methodid, test_input, MAX_STEPS)
        
        last_outcome = outcome 
        if outcome is not None:
            behaviors.add(outcome)
            witnesses.setdefault(outcome, jpamb.Case(jpamb.Experiment(methodid, test_input), outcome))

        return visited

    trial = 0
    visited = set()
    stop_at = n_trials
    # The taint analysis proved no input reaches a sink: answer ok without fuzzing
    if getattr(fuzzer, "is_unflagged", None) and fuzzer.is_unflagged():
        _debug_log("skipping fuzzing: taint classification=unflagged")
        behaviors.add("ok")
        stop_at = 0
    while trial < stop_at:
        values = fuzzer.generate_values(trial, visited)
        new = execute(values) - visited
        if new:
            _debug_log(f"trial {trial}: {values} -> +{len(new)} coverage, outcome={last_outcome}")
        visited.update(new)
        if "assertion error" in behaviors:
            stop_at = min(stop_at, trial + 1 + EXTRA_TRIALS)
        trial += 1
        
    for query in jpamb.QUERIES:
        print(f"{query};{('found' if query in behaviors else 'not-found')}")

    if path := os.environ.get("JPAMB_WITNESS_PATH"):
        with open(path, "a") as f:
            f.writelines(f"{case.encode()}\n" for case in witnesses.values())

    return 0

if __name__ == "__main__":
    sys.exit(analyse())