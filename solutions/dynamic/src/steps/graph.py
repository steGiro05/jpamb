import jvm
import tree_sitter
import tree_sitter_java
import jpamb
import os
import subprocess
import json

from pathlib import Path

from steps.base import Fuzzer, ClassInfo, _debug_log


class GraphFuzzer(Fuzzer):
    INTS = [0] + [x for i in range(1, 11) for x in (i, -i)] + [2147483647, -2147483648]
    STRINGS = [""]
    INT_ARRAYS = [[], [0], [1], [-1], [0, 0], [1, 2, 3], [-1, 0, 1], [42], [100]]
    CHAR_ARRAYS = ["", "a", "x", "hello", "Hello", "test"]
    SEPARATORS = ["", ":"]
    INITIAL_CORPUS = 20

    def __init__(self, rand, methodid, bc, suite, max_tests):
        super().__init__(rand, methodid, bc, suite)
        self.max_tests = max_tests
        self.corpus = []      # inputs that advanced coverage
        self.seeds = []       # initial inputs, consumed first
        self.pools = {}       # per-type value pools
        self.last = None      # last returned input (raw python values)
        self.seen = 0         # coverage size at last trial
        self.known_methods = {
            "jpamb.cases.advanced.CWE502_Dict.simulateResolveClassName:(Ljava/lang/String;)Ljava/lang/String;", # remove stubs from methods to visit
            "jpamb.cases.advanced.CWE502_Dict.simulateReadObject:(Ljava/lang/String;)Ljava/lang/Object;",
            "jpamb.cases.advanced.CWE502_Naive.simulateReadObject:(Ljava/lang/String;)Ljava/lang/Object;",
            "jpamb.cases.advanced.CWE502_Naive.simulateReadObject:(Ljava/lang/String;)Ljava/lang/Object;",
            "jpamb.cases.advanced.CWE502_Graph.simulateReadObject:(Ljava/lang/String;)Ljava/lang/Object;",
            "jpamb.cases.advanced.CWE502_Graph.simulateReadObject:(Ljava/lang/String;)Ljava/lang/Object;",
        }
    # ---------- pools ----------
    def _classes(self, srcfile: Path):
        parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_java.language()))
        tree = parser.parse(srcfile.read_bytes())
        classes = []

        def walk(n):
            if n.type == "class_declaration":
                body = n.child_by_field_name("body")
                ctor = next((m for m in body.children if m.type == "constructor_declaration"), None)
                params = []
                if ctor:
                    ps = [p for p in ctor.child_by_field_name("parameters").children
                          if p.type == "formal_parameter"]
                    params = [(i, p.child_by_field_name("type").text.decode()) for i, p in enumerate(ps)]
                classes.append(ClassInfo(shortname=n.child_by_field_name("name").text.decode(), params=params))
            for c in n.children:
                walk(c)

        walk(tree.root_node)
        return classes

    def _dictionary_strings(self, method_id: str) -> list:
        data = []
        path = os.environ.get("JPAMB_STRING_DICTIONARY_PATH")
        try:
            if path:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
            else:
                out = subprocess.run(["string-dictionary", method_id],
                                     capture_output=True, text=True, check=True).stdout
                data = json.loads(out)
        except Exception as e:
            _debug_log(f"Dictionary request failed for {method_id}: {e}")
        if isinstance(data, dict):
            data = data.get(method_id, [])
        return [s for e in data for s in e.get("strings", []) if isinstance(s, str) and s]

    def _build_pools(self):
        srcfile = self.suite.sourcefile(self.methodid.classname).relative_to(Path.cwd())
        classes = self._classes(srcfile)
        ints = list(dict.fromkeys(self.INTS + [
            o.value for o in self.bc.getmethod(self.methodid).opcodes
            if isinstance(o, jvm.Push) and isinstance(o.type, jvm.Int)]))
        base = list(dict.fromkeys(self.STRINGS + self._dictionary_strings(self.methodid.encode())))

        if srcfile.name.upper().startswith("CWE502"):  # serialized objects: SER|Class|args
            def arg(t):
                return str(self.rand.choice(ints)) if t in ("int", "Integer") else \
                    self.rand.choice(base) if "String" in t else ""
            classpool = [f"SER|{c.shortname}|" + "|".join(arg(t) for _, t in c.params)
                         for c in classes for _ in range(3)]
        else:  # CWE470: plain class names
            classpool = [c.shortname for c in classes]

        self.pools = {"int": ints, "str": list(dict.fromkeys(base + classpool)),
                      "bool": [True, False], "ia": self.INT_ARRAYS, "ca": self.CHAR_ARRAYS}

    def _pool(self, param) -> list:
        match param:
            case jvm.Int(): return self.pools["int"]
            case jvm.Boolean(): return self.pools["bool"]
            case jvm.Object(name=n) if n == jvm.ClassName("java.lang.String"): return self.pools["str"]
            case jvm.Array(contains=jvm.Int()): return self.pools["ia"]
            case jvm.Array(contains=jvm.Char()): return self.pools["ca"]
        raise NotImplementedError(f"Unsupported input type: {param!r}")

    def _case(self, param, val):
        match param:
            case jvm.Int(): return jpamb.case.Int(val)
            case jvm.Boolean(): return jpamb.case.Boolean(val)
            case jvm.Array(contains=jvm.Int()): return jpamb.case.Array(jvm.Int(), val)
            case jvm.Array(contains=jvm.Char()): return jpamb.case.Array(jvm.Char(), val)
        return jpamb.case.String(val)

    # ---------- corpus / mutation ----------
    def _mutate(self, values: list, params: list) -> list:
        values = list(values)
        for i in self.rand.sample(range(len(params)), min(2, len(params))):
            pool = self._pool(params[i])
            if isinstance(params[i], jvm.Object):  # String: 1-3 tokens from scratch
                parts = [self.rand.choice(pool) for _ in range(self.rand.randint(1, 3))]
                values[i] = self.rand.choice(self.SEPARATORS).join(parts)
            else:
                values[i] = self.rand.choice(pool)
        return values

    def generate_values(self, trial: int, visited: set) -> list:
        params = self.methodid.extension.params
        if not self.pools:
            self._build_pools()
            self.seeds = [[self.rand.choice(self._pool(p)) for p in params]
                          for _ in range(self.INITIAL_CORPUS)]
            self.corpus = list(self.seeds)

        if self.last is not None and len(visited) > self.seen:  # coverage advanced
            self.corpus.append(self.last)
            for m in {v for v in visited if "@" not in v} - self.known_methods:
                _debug_log("new method discovered: ",m)
                self.known_methods.add(m)
                self.pools["str"] += [s for s in self._dictionary_strings(m)
                                      if s not in self.pools["str"]]
        self.seen = len(visited)

        if self.seeds:
            self.last = self.seeds.pop()
        elif params:
            self.last = self._mutate(self.rand.choice(self.corpus), params)
        else:
            self.last = []
        return [self._case(p, v) for p, v in zip(params, self.last)]