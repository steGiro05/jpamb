import random
import sys
import os
import jpamb

from interpreter import run

from steps.base import Fuzzer, _debug_log
from steps.naive import NaiveFuzzer
from steps.dictionary import DictFuzzer
class GraphFuzzer(Fuzzer):
    def generate_values(self, trial: int) -> list:
        return []

class TaintFuzzer(Fuzzer):
    def generate_values(self, trial: int) -> list:
        return []

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
    MAX_TESTS = 1000

    n_trials = MAX_TESTS
    behaviors = set()
    last_outcome = None

    fuzzer_map = {
        "naive": NaiveFuzzer,
        "dictionary": DictFuzzer,
        "graph": GraphFuzzer,
        "taint": TaintFuzzer
    }
    
    mode = os.environ.get("FUZZER_MODE", "dictionary").lower()
    fuzzer_class = fuzzer_map.get(mode, NaiveFuzzer)
    fuzzer = fuzzer_class(rand, methodid, bc, suite, MAX_TESTS)

    def execute(values) -> None:
        nonlocal last_outcome
        
        test_input = jpamb.case.Input(values)
        outcome, _ = run(bc, methodid, test_input, MAX_STEPS)
        
        last_outcome = outcome 
        if outcome is not None:
            behaviors.add(outcome)

    trial = 0
    while trial < n_trials:
        values = fuzzer.generate_values(trial)
        execute(values)
        _debug_log(f"trial n. f{trial}, generated values: [f{values}]")
        trial += 1
        
    for query in jpamb.QUERIES:
        print(f"{query};{('found' if query in behaviors else 'not-found')}")
        
    return 0

if __name__ == "__main__":
    sys.exit(analyse())