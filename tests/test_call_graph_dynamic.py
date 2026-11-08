"""Tests for reflection and deserialization edges in the call graph."""

import json
import tempfile
import unittest
from pathlib import Path

from call_graph import build_call_graph_from_classes, main


BASE = "jpamb/cases/Vulnerable"
PREFIX = "jpamb.cases.Vulnerable"
CANARY = BASE + "$__CANARY__Command"
WRAPPER = BASE + "$SafeWrapperCommand"
LIBRARY = BASE + "$UpdatedLibrary"
BENIGN = BASE + "$SafeCommand"


def method(name, *instructions):
    return {
        "name": name,
        "params": [],
        "returns": {"type": None},
        "code": {"bytecode": list(instructions)},
    }


def invoke(owner, name):
    return {
        "opr": "invoke",
        "method": {
            "ref": {"kind": "class", "name": owner},
            "name": name,
            "args": [],
            "returns": None,
        },
    }


def classes():
    return [
        {"name": BASE, "methods": [
            method("reflect", invoke("java/lang/Class", "forName")),
            method("deserialize", invoke(BASE, "simulateReadObject")),
            # This stub contains a fake hard-coded constructor call.
            method("simulateReadObject", invoke(BENIGN, "<init>")),
            method("unrelated", invoke("example/Helper", "forName")),
        ]},
        {"name": CANARY, "methods": [method("<init>")]},
        {"name": WRAPPER, "methods": [method("<init>", invoke(CANARY, "<init>"))]},
        {"name": LIBRARY, "methods": [method("<init>", invoke(WRAPPER, "<init>"))]},
        {"name": BENIGN, "methods": [method("<init>")]},
    ]


class DynamicCallGraphTests(unittest.TestCase):
    def test_static_graph_is_unchanged_by_default(self):
        graph = build_call_graph_from_classes(classes())
        self.assertIn(f"{PREFIX}.simulateReadObject:()V", graph[f"{PREFIX}.deserialize:()V"])
        self.assertIn(f"{PREFIX}$SafeCommand.<init>:()V", graph[f"{PREFIX}.simulateReadObject:()V"])

    def test_reflection_reaches_sink_through_constructors(self):
        edges = []
        graph = build_call_graph_from_classes(classes(), dynamic=True, dynamic_edges=edges)
        caller = f"{PREFIX}.reflect:()V"
        expected = {
            f"{PREFIX}$__CANARY__Command.<init>:()V",
            f"{PREFIX}$SafeWrapperCommand.<init>:()V",
            f"{PREFIX}$UpdatedLibrary.<init>:()V",
        }
        self.assertEqual(set(graph[caller]), expected)
        self.assertEqual(
            {(edge["callee"], edge["kind"]) for edge in edges if edge["caller"] == caller},
            {(constructor, "reflection") for constructor in expected},
        )
        self.assertEqual(graph[f"{PREFIX}.unrelated:()V"], [])

    def test_deserialization_ignores_mock_implementation(self):
        edges = []
        graph = build_call_graph_from_classes(classes(), dynamic=True, dynamic_edges=edges)
        caller = f"{PREFIX}.deserialize:()V"
        mock = f"{PREFIX}.simulateReadObject:()V"
        self.assertEqual(graph[mock], [])
        self.assertIn(f"{PREFIX}$UpdatedLibrary.<init>:()V", graph[caller])
        self.assertNotIn(f"{PREFIX}$SafeCommand.<init>:()V", graph[caller])
        self.assertTrue(any(edge["caller"] == caller and edge["kind"] == "deserialization"
                            for edge in edges))

    def test_cli_exports_dynamic_edge_types(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for index, cls in enumerate(classes()):
                (root / f"{index}.json").write_text(json.dumps(cls), encoding="utf-8")
            output = root / "graph.json"
            result = main(["--decompiled", str(root), "--dynamic",
                           "--format", "detailed-json", "--output", str(output)])
            self.assertEqual(result, 0)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertIn("graph", data)
            self.assertEqual({edge["kind"] for edge in data["dynamic_edges"]},
                             {"reflection", "deserialization"})

    def test_real_dynamic_invokes_keep_separate_opcode_indices(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sample = classes()
            sample[0]["methods"].append(method(
                "threeSites",
                {"opr": "push", "offset": 90},
                invoke("java/lang/Class", "forName"),
                {"opr": "push", "offset": 150},
                invoke("java/lang/Class", "forName"),
                invoke("java/io/ObjectInputStream", "readObject"),
            ))
            for index, cls in enumerate(sample):
                (root / f"{index}.json").write_text(json.dumps(cls), encoding="utf-8")
            config = root / "config.json"
            config.write_text(json.dumps({"analyzer_config": {"vulnerabilities": [{
                "enabled": True,
                "exploit_targets": ["__CANARY__Command.<init>"],
                "dynamic_sites": [
                    {"class_name": "java.lang.Class", "method_name": "forName", "kind": "reflection"},
                    {"class_name": "java.io.ObjectInputStream", "method_name": "readObject",
                     "kind": "deserialization"},
                ],
                "stubs": {"simulateReadObject": "deserialization"},
            }]}}), encoding="utf-8")
            out = root / "out.json"
            self.assertEqual(main([f"{PREFIX}.threeSites:()V", "--decompiled", str(root),
                                   "--config", str(config), "--output", str(out)]), 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            caller = f"{PREFIX}.threeSites:()V"
            edges = [e for e in payload["dynamic_edges"] if e["caller"] == caller]
            self.assertTrue(edges)
            self.assertEqual({(e["kind"], e["instruction_index"]) for e in edges},
                             {("reflection", 1), ("reflection", 3), ("deserialization", 4)})
            callsites = [s for s in payload["call_sites"] if s["caller"] == caller]
            self.assertEqual([s["instruction_index"] for s in callsites], [1, 3, 4])
            self.assertTrue(all(s["resolved_callees"] == [] for s in callsites))

    def test_stub_dynamic_edges_have_no_misleading_opcode_index(self):
        from call_graph import add_dynamic_edges
        graph = build_call_graph_from_classes(classes())
        mock = f"{PREFIX}.simulateReadObject:()V"
        canary = f"{PREFIX}$__CANARY__Command.<init>:()V"
        _, edges = add_dynamic_edges(graph, {}, {mock: "deserialization"}, [canary])
        stub_edges = [e for e in edges if e["caller"] == mock]
        self.assertTrue(stub_edges)
        self.assertTrue(all("instruction_index" not in e for e in stub_edges))

    def test_legacy_dynamic_edges_also_use_opcode_index(self):
        edges = []
        graph = build_call_graph_from_classes(classes(), dynamic=True, dynamic_edges=edges)
        caller = f"{PREFIX}.reflect:()V"
        self.assertIn(caller, graph)
        self.assertTrue(any(e["caller"] == caller and e["instruction_index"] == 0
                            and e["kind"] == "reflection" for e in edges))



if __name__ == "__main__":
    unittest.main()