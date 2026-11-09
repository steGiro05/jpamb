import random
import sys
import jvm
import os
import jpamb
import tree_sitter
import tree_sitter_java

from dataclasses import dataclass
from interpreter import run
from typing import List, Tuple
from pathlib import Path
from enum import Enum

def _debug_log(*args, **kwargs):
    with open('debug.log', 'a', encoding='utf-8') as f:
        print(*args, file=f, **kwargs)

class OutOfBudget(Exception):
    """Raised when the global cap on interpreter runs is reached."""

# --- DATACLASSES and ENUMS---
class VulnFamily(Enum):
    CWE470 = "CWE470"
    CWE502 = "CWE502"

@dataclass
class ClassInfo:
    shortname: str
    params: List[Tuple[int, str]]  # (order, type_string)

# --- FUZZER CLASSES ---

class Fuzzer:
    def __init__(self, rand: random.Random, methodid, bc, suite):
        self.rand = rand
        self.methodid = methodid
        self.bc = bc
        self.suite = suite

    def generate_values(self, trial: int) -> list:
        raise NotImplementedError("Subclasses must implement this method")

class NaiveFuzzer(Fuzzer):
    INTERESTING_INTS = [0] + [x for i in range(1, 11) for x in (i, -i)] + [
        2147483647, -2147483648
    ]
    
    INTERESTING_STRINGS = [
        "", "hello", "not hello", "Hello", "x", "a", "test", "null", "hello world"
    ]
    
    INTERESTING_INT_ARRAYS = [
        [], [0], [1], [-1], [0, 0], [1, 2, 3], [-1, 0, 1], [42], [100]
    ]
    
    INTERESTING_CHAR_ARRAYS = [
        "", "a", "x", "hello", "Hello", "test"
    ]

    def __init__(self, rand, methodid, bc, suite, max_tests):
        super().__init__(rand, methodid, bc, suite)
        self.class_names: List[ClassInfo] | None = None
        self.vuln_type: VulnFamily | None = None
        self.max_tests = max_tests

    def _load_vuln_type(self, srcfile: Path):
        filename = srcfile.name.upper()
        if filename.startswith("CWE470"):
            self.vuln_type = VulnFamily.CWE470
        elif filename.startswith("CWE502"):
            self.vuln_type = VulnFamily.CWE502
        else:
            raise ValueError(f"Cannot determine vuln type from file: {filename}")
        
    def _collect_dictionary(self):
        int_dict, string_dict = [], []
        method = self.bc.getmethod(self.methodid)

        for opr in method.opcodes:
            match opr:
                case jvm.Push(type=jvm.Int(), value=val):
                    if val not in int_dict:
                        int_dict.append(val)
                case jvm.Push(type=t, value=val) if isinstance(t, jvm.Object) and t.name == jvm.ClassName("java.lang.String"):
                    if val not in string_dict:
                        string_dict.append(val)
        
        return int_dict, string_dict

    def _build_file_path(self) -> Path:
        return self.suite.sourcefile(self.methodid.classname).relative_to(Path.cwd())
    
    def _load_classnames_from_file(self, srcfile: Path):
        JAVA_LANGUAGE = tree_sitter.Language(tree_sitter_java.language())
        parser = tree_sitter.Parser(JAVA_LANGUAGE)
        
        with open(srcfile, "rb") as f:
            tree = parser.parse(f.read())

        classes = []

        def traverse(node):
            if node.type == "class_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    shortname = name_node.text.decode("utf8")
                    
                    params_list = []
                    body = node.child_by_field_name("body")
                    if body:
                        for member in body.children:
                            if member.type == "constructor_declaration":
                                param_node = member.child_by_field_name("parameters")
                                if param_node:
                                    order = 0
                                    for p in param_node.children:
                                        if p.type == "formal_parameter":
                                            p_type = p.child_by_field_name("type")
                                            t_str = p_type.text.decode("utf8") if p_type else "Object"
                                            params_list.append((order, t_str))
                                            order += 1
                                break 
                    
                    classes.append(ClassInfo(
                        shortname=shortname, 
                        params=params_list
                    ))
                    
                    if body:
                        for member in body.children:
                            traverse(member)
            else:
                for child in node.children:
                    traverse(child)

        traverse(tree.root_node)
        self.class_names = classes

    def _generate_serialized_classes(self, int_dict: list, string_dict: list) -> list:
        serialized_payloads = []
        header = "SER"
        
        all_ints = list(dict.fromkeys(self.INTERESTING_INTS + int_dict))
        all_strings = list(dict.fromkeys(self.INTERESTING_STRINGS + string_dict))
        
        for c in self.class_names:
            classname = c.shortname
            
            if not c.params:
                serialized_payloads.append(f"{header}|{classname}|")
            else:
                first_param_type = c.params[0][1]
                
                if first_param_type in ("int", "Integer"):
                    for val in all_ints:
                        serialized_payloads.append(f"{header}|{classname}|{val}")
                        
                elif "String" in first_param_type:
                    for val in all_strings:
                        serialized_payloads.append(f"{header}|{classname}|{val}")
                        
                else:
                    serialized_payloads.append(f"{header}|{classname}|")
                    
        return list(dict.fromkeys(serialized_payloads))

    def generate_values(self, trial: int) -> list:
        if not self.class_names:
            self._load_classnames_from_file(self._build_file_path())

        if not self.vuln_type:
            self._load_vuln_type(self._build_file_path())

        pragmatic_cases = int(0.8 * self.max_tests)

        int_dict, string_dict = self._collect_dictionary()
        
        int_values = self.INTERESTING_INTS + [v for v in int_dict if v not in self.INTERESTING_INTS]
        if (self.vuln_type == VulnFamily.CWE470):
            all_strings = self.INTERESTING_STRINGS + string_dict + [c.shortname for c in self.class_names]
        elif (self.vuln_type == VulnFamily.CWE502):
            serialized_classes = self._generate_serialized_classes(int_dict, string_dict)
            all_strings = self.INTERESTING_STRINGS + string_dict + [c for c in serialized_classes]

        string_values = list(dict.fromkeys(all_strings))

        values = []

        for position, param in enumerate(self.methodid.extension.params):
            match param:
                
                # --- INT ---
                case jvm.Int():
                    if trial < pragmatic_cases:
                        val = int_values[(trial // (len(int_values) ** position)) % len(int_values)]
                    else:
                        val = self.rand.randint(-(1 << 31), (1 << 31) - 1)
                    values.append(jpamb.case.Int(val))

                # --- BOOLEAN ---
                case jvm.Boolean():
                    val = bool((trial // (2 ** position)) % 2)
                    values.append(jpamb.case.Boolean(val))

                # --- STRING ---
                case jvm.Object(name=classname) if classname == jvm.ClassName("java.lang.String"):
                    if trial < pragmatic_cases:
                        val = string_values[trial % len(string_values)]
                    else:
                        length = self.rand.randint(0, 10)
                        val = "".join(self.rand.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(length))
                    values.append(jpamb.case.String(val))

                # --- INT ARRAY ---
                case jvm.Array(contains=jvm.Int()):
                    if trial < pragmatic_cases:
                        arr = self.INTERESTING_INT_ARRAYS[trial % len(self.INTERESTING_INT_ARRAYS)]
                    else:
                        length = self.rand.randint(0, 6)
                        arr = [self.rand.choice(int_values) for _ in range(length)]
                    values.append(jpamb.case.Array(jvm.Int(), arr))

                # --- CHAR ARRAY ---
                case jvm.Array(contains=jvm.Char()):
                    if trial < pragmatic_cases:
                        val = self.INTERESTING_CHAR_ARRAYS[trial % len(self.INTERESTING_CHAR_ARRAYS)]
                    else:
                        length = self.rand.randint(0, 8)
                        val = "".join(self.rand.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(length))
                    values.append(jpamb.case.Array(jvm.Char(), val))

                case _:
                    raise NotImplementedError(f"Unsupported input type: {param!r}")

        return values

class DictionaryFuzzer(Fuzzer):
    def generate_values(self, trial: int) -> list:
        return []

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
    
    rand = random.Random(0)
    MAX_STEPS = 200
    MAX_TESTS = 1000

    n_trials = MAX_TESTS
    behaviors = set()
    last_outcome = None

    fuzzer_map = {
        "naive": NaiveFuzzer,
        "dictionary": DictionaryFuzzer,
        "graph": GraphFuzzer,
        "taint": TaintFuzzer
    }
    
    mode = os.environ.get("FUZZER_MODE", "naive").lower()
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
        # _debug_log(f"trial n. f{trial}, generated values: [f{values}]")
        trial += 1
        
    for query in jpamb.QUERIES:
        print(f"{query};{('found' if query in behaviors else 'not-found')}")
        
    return 0

if __name__ == "__main__":
    sys.exit(analyse())