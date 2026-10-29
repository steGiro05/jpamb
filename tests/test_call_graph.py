"""Self-contained tests for the JPAMB bytecode call graph (stdlib only)."""

import json
import tempfile
import unittest
from pathlib import Path

from call_graph import (
    build_call_graph, build_call_graph_from_classes, method_id,
    reachable_methods, type_descriptor, main,
)


def definition(name, params=(), returns=None, instructions=()):
    return {
        "name": name,
        "params": [{"type": param} for param in params],
        "returns": {"type": returns},
        "code": {"bytecode": list(instructions)},
    }


def invoke(owner, name, args=(), returns=None, access="static"):
    return {
        "opr": "invoke", "access": access,
        "method": {
            "ref": {"kind": "class", "name": owner},
            "name": name, "args": list(args), "returns": returns,
        },
    }


class CallGraphTests(unittest.TestCase):
    def setUp(self):
        self.calls = {
            "name": "jpamb/cases/Calls",
            "methods": [
                definition("run", instructions=[invoke("jpamb/cases/Calls", "fib", ["int"], "int"), invoke("java/io/PrintStream", "println", ["int"])]),
                definition("fib", params=[{"base": "int"}], returns={"base": "int"},
                           instructions=[invoke("jpamb/cases/Calls", "fib", ["int"], "int")]),
                definition("noCalls"),
                definition("overload", params=[{"base": "int"}]),
                definition("overload", params=[{"base": "boolean"}]),
                definition("other", instructions=[invoke("jpamb/cases/Other", "help")]),
            ],
        }
        self.other = {"name": "jpamb/cases/Other", "methods": [definition("help")]}

    def test_descriptor_primitives_objects_arrays(self):
        self.assertEqual(type_descriptor(None), "V")
        self.assertEqual(type_descriptor({"base": "boolean"}), "Z")
        self.assertEqual(type_descriptor({"kind": "class", "name": "java/lang/String"}), "Ljava/lang/String;")
        self.assertEqual(type_descriptor({"kind": "array", "type": {"base": "char"}}), "[C")
        self.assertEqual(method_id("a/B", "m", ["int", "boolean"], "int"), "a.B.m:(IZ)I")

    def test_finds_calls_and_recursion(self):
        graph = build_call_graph_from_classes([self.calls, self.other])
        self.assertEqual(graph["jpamb.cases.Calls.run:()V"], ["jpamb.cases.Calls.fib:(I)I"])
        self.assertEqual(graph["jpamb.cases.Calls.fib:(I)I"], ["jpamb.cases.Calls.fib:(I)I"])
        self.assertEqual(graph["jpamb.cases.Calls.noCalls:()V"], [])
        self.assertEqual(graph["jpamb.cases.Calls.other:()V"], ["jpamb.cases.Other.help:()V"])

    def test_retains_external_when_requested(self):
        graph = build_call_graph_from_classes([self.calls], include_external=True)
        self.assertIn("java.io.PrintStream.println:(I)V", graph["jpamb.cases.Calls.run:()V"])

    def test_overloads_do_not_collide(self):
        graph = build_call_graph_from_classes([self.calls])
        self.assertIn("jpamb.cases.Calls.overload:(I)V", graph)
        self.assertIn("jpamb.cases.Calls.overload:(Z)V", graph)

    def test_reachable_handles_cycle(self):
        graph = build_call_graph_from_classes([self.calls, self.other])
        self.assertEqual(reachable_methods(graph, "jpamb.cases.Calls.run:()V"), [
            "jpamb.cases.Calls.fib:(I)I", "jpamb.cases.Calls.run:()V",
        ])

    def test_reads_realistic_decompiled_layout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "target" / "decompiled"
            folder = root / "jpamb" / "cases"
            folder.mkdir(parents=True)
            (folder / "Calls.json").write_text(json.dumps(self.calls), encoding="utf-8")
            (folder / "Other.json").write_text(json.dumps(self.other), encoding="utf-8")
            graph = build_call_graph(root)
            self.assertEqual(graph["jpamb.cases.Calls.other:()V"], ["jpamb.cases.Other.help:()V"])

    def test_cli_json_and_dot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "target" / "decompiled"
            root.mkdir(parents=True)
            (root / "Calls.json").write_text(json.dumps(self.calls), encoding="utf-8")
            json_path = Path(temp) / "call-graph.json"
            dot_path = Path(temp) / "call-graph.dot"
            self.assertEqual(main(["--decompiled", str(root), "--output", str(json_path)]), 0)
            self.assertIn("jpamb.cases.Calls.fib:(I)I", json.loads(json_path.read_text()))
            self.assertEqual(main(["--decompiled", str(root), "--format", "dot", "--output", str(dot_path)]), 0)
            self.assertIn('"jpamb.cases.Calls.run:()V" -> "jpamb.cases.Calls.fib:(I)I"', dot_path.read_text())

    def test_project_style_bytecode_example(self):
        # Uses the JVM2JSON shapes present in the project branch's Calls.json.
        cls = {
            "name": "jpamb/cases/Calls",
            "methods": [
                definition(
                    "callsAssertIf",
                    params=[{"annotations": [], "base": "boolean"}],
                    instructions=[
                        invoke("jpamb/cases/Calls", "assertIf", ["boolean"]),
                    ],
                ),
                definition("assertIf", params=[{"base": "boolean"}]),
                definition(
                    "generatePrimeArray",
                    params=[{"base": "int"}],
                    returns={"kind": "array", "type": {"base": "int"}},
                ),
            ],
        }
        graph = build_call_graph_from_classes([cls])
        self.assertEqual(
            graph["jpamb.cases.Calls.callsAssertIf:(Z)V"],
            ["jpamb.cases.Calls.assertIf:(Z)V"],
        )
        self.assertIn("jpamb.cases.Calls.generatePrimeArray:(I)[I", graph)

    def test_duplicate_calls_have_one_edge_and_missing_dynamic_ref_is_ignored(self):
        call = invoke("jpamb/cases/Calls", "callee")
        cls = {
            "name": "jpamb/cases/Calls",
            "methods": [
                definition("caller", instructions=[call, call, {"opr": "invoke", "method": {"name": "dynamic"}}]),
                definition("callee"),
            ],
        }
        graph = build_call_graph_from_classes([cls])
        self.assertEqual(
            graph["jpamb.cases.Calls.caller:()V"],
            ["jpamb.cases.Calls.callee:()V"],
        )

    def test_missing_dir_returns_error(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(main(["--decompiled", str(Path(temp) / "missing")]), 1)


if __name__ == "__main__":
    unittest.main()
