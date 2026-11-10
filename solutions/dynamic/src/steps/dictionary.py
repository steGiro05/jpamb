import jvm
import tree_sitter
import tree_sitter_java
import jpamb
import os
import subprocess
import json

from itertools import permutations
from typing import List
from pathlib import Path

from steps.base import Fuzzer, ClassInfo, VulnFamily, _debug_log

class DictFuzzer(Fuzzer):
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
    
    SEPARATORS = ["", ":"]

    # Composizione di token: max token usati e max lunghezza della sequenza
    MAX_COMPOSE_TOKENS = 12
    MAX_COMPOSE_LEN = 3

    def __init__(self, rand, methodid, bc, suite, max_tests):
        super().__init__(rand, methodid, bc, suite)
        self.class_names: List[ClassInfo] | None = None
        self.vuln_type: VulnFamily | None = None
        self.max_tests = max_tests
        
        self.cached_int_values = None
        self.cached_string_values = None

    def _build_file_path(self) -> Path:
        return self.suite.sourcefile(self.methodid.classname).relative_to(Path.cwd())

    def _load_vuln_type(self, srcfile: Path):
        filename = srcfile.name.upper()
        if filename.startswith("CWE470"):
            self.vuln_type = VulnFamily.CWE470
        elif filename.startswith("CWE502"):
            self.vuln_type = VulnFamily.CWE502
        else:
            raise ValueError(f"Cannot determine vuln type from file: {filename}")
        
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
                    
                    classes.append(ClassInfo(shortname=shortname, params=params_list))
                    
                    if body:
                        for member in body.children:
                            traverse(member)
            else:
                for child in node.children:
                    traverse(child)

        traverse(tree.root_node)
        self.class_names = classes

    def _collect_dictionary(self):
        int_dict = []
        method = self.bc.getmethod(self.methodid)

        for opr in method.opcodes:
            if isinstance(opr, jvm.Push) and isinstance(opr.type, jvm.Int):
                if opr.value not in int_dict:
                    int_dict.append(opr.value)
        return int_dict

    def _obtain_dictionary(self, entry_method: jvm.AbsMethodID) -> list[dict]:
        precomputed = os.environ.get("JPAMB_STRING_DICTIONARY_PATH")
        if precomputed:
            try:
                data = json.loads(Path(precomputed).read_text(encoding="utf-8"))
                if data and isinstance(data, list):
                    return data
                if data and isinstance(data, dict):
                    return data
            except (FileNotFoundError, json.JSONDecodeError):
                pass
        
        completed = subprocess.run(
            ["string-dictionary", entry_method.encode()],
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
        return data

    def _generate_serialized_classes(self, int_dict: list) -> list:
        serialized_payloads = []
        header = "SER"
        
        all_ints = list(dict.fromkeys(self.INTERESTING_INTS + int_dict))
        all_strings = list(dict.fromkeys(self.INTERESTING_STRINGS))
        
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

    def _build_composed_pool(self, dict_entries: list, class_pool: list) -> list[str]:
        dict_tokens = list(dict.fromkeys(
            s for e in dict_entries
            for s in e.get("strings", [])
            if isinstance(s, str) and s != ""
        ))
        extra_tokens = [c for c in dict.fromkeys(class_pool)
                        if c not in dict_tokens and c != ""]

        room = max(0, self.MAX_COMPOSE_TOKENS - len(dict_tokens))
        if len(extra_tokens) > room:
            extra_tokens = self.rand.sample(extra_tokens, room)
        tokens = dict_tokens[: self.MAX_COMPOSE_TOKENS] + extra_tokens

        composed = set()
        for k in range(1, self.MAX_COMPOSE_LEN + 1):
            if k > len(tokens):
                break
            for perm in permutations(tokens, k):
                for sep in self.SEPARATORS:
                    composed.add(sep.join(perm))
        return list(composed)

    def generate_values(self, trial: int) -> list:
        if self.cached_string_values is None:
            srcfile = self._build_file_path()
            if not self.class_names:
                self._load_classnames_from_file(srcfile)
            if not self.vuln_type:
                self._load_vuln_type(srcfile)

            int_dict = self._collect_dictionary()
            self.cached_int_values = list(dict.fromkeys(self.INTERESTING_INTS + int_dict))
            
            if self.vuln_type == VulnFamily.CWE470:
                class_pool = [c.shortname for c in self.class_names]
            elif self.vuln_type == VulnFamily.CWE502:
                class_pool = self._generate_serialized_classes(int_dict)
            else:
                class_pool = []

            raw_dict = self._obtain_dictionary(self.methodid) 
            dict_entries = []
            if isinstance(raw_dict, list):
                dict_entries = raw_dict
            elif isinstance(raw_dict, dict):
                target_key = self.methodid.encode()
                dict_entries = raw_dict.get(target_key, [])

            composed = self._build_composed_pool(dict_entries, class_pool)
            composed_set = set(composed)

            mutated_set = set(self.INTERESTING_STRINGS + class_pool)

            self.rand.shuffle(dict_entries)
            
            for entry in dict_entries:
                op = entry.get('method')
                strings_to_use = entry.get('strings', [])
                
                new_additions = set()
                for s in strings_to_use:
                    if not isinstance(s, str):
                        continue
                    new_additions.add(s)
                    
                    for current_str in mutated_set:
                        for sep in self.SEPARATORS:
                            if op == 'startsWith':
                                new_additions.add(f"{s}{sep}{current_str}")
                            elif op == 'endsWith':
                                new_additions.add(f"{current_str}{sep}{s}")
                            elif op in ('contains', 'equals', 'equalsIgnoreCase'):
                                new_additions.add(f"{s}{sep}{current_str}")
                                new_additions.add(f"{current_str}{sep}{s}")
                                new_additions.add(f"{s}{sep}{current_str}{sep}{s}")

                mutated_set.update(new_additions)

            rest = [s for s in mutated_set if s not in composed_set]
            self.rand.shuffle(composed)
            self.rand.shuffle(rest)

            self.cached_string_values = composed + rest

        int_values = self.cached_int_values
        string_values = self.cached_string_values
        
        pragmatic_cases = int(0.8 * self.max_tests)
        values = []

        for position, param in enumerate(self.methodid.extension.params):
            match param:
                case jvm.Int():
                    if trial < pragmatic_cases:
                        val = int_values[(trial // (len(int_values) ** position)) % len(int_values)]
                    else:
                        val = self.rand.randint(-(1 << 31), (1 << 31) - 1)
                    values.append(jpamb.case.Int(val))

                case jvm.Boolean():
                    val = bool((trial // (2 ** position)) % 2)
                    values.append(jpamb.case.Boolean(val))

                case jvm.Object(name=classname) if classname == jvm.ClassName("java.lang.String"):
                    if trial < pragmatic_cases:
                        if string_values:
                            val = string_values[(trial // (len(string_values) ** position)) % len(string_values)]
                        else:
                            val = ""
                    else:
                        length = self.rand.randint(0, 10)
                        val = "".join(self.rand.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(length))
                    values.append(jpamb.case.String(val))

                case jvm.Array(contains=jvm.Int()):
                    if trial < pragmatic_cases:
                        arr = self.INTERESTING_INT_ARRAYS[trial % len(self.INTERESTING_INT_ARRAYS)]
                    else:
                        length = self.rand.randint(0, 6)
                        arr = [self.rand.choice(int_values) for _ in range(length)]
                    values.append(jpamb.case.Array(jvm.Int(), arr))

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