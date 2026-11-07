"""Regression checks for the project-branch fuzzer's call graph CLI contract."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from call_graph import load_config, main, build_call_graph_from_classes
BASE = "jpamb/cases/Vulnerable"
PREFIX = "jpamb.cases.Vulnerable"
CANARY = BASE + "$__CANARY__Command"
WRAPPER = BASE + "$SafeWrapperCommand"
LIBRARY = BASE + "$UpdatedLibrary"
BENIGN = BASE + "$SafeCommand"


def method(name, *instructions):
    return {"name": name, "params": [], "returns": {"type": None},
            "code": {"bytecode": list(instructions)}}


def invoke(owner, name):
    return {"opr": "invoke", "method": {
        "ref": {"kind": "class", "name": owner}, "name": name,
        "args": [], "returns": None}}


def classes():
    return [
        {"name": BASE, "methods": [
            method("reflect", invoke("java/lang/Class", "forName")),
            method("deserialize", invoke(BASE, "simulateReadObject")),
            method("simulateReadObject", invoke(BENIGN, "<init>")),
        ]},
        {"name": CANARY, "methods": [method("<init>")]},
        {"name": WRAPPER, "methods": [method("<init>", invoke(CANARY, "<init>"))]},
        {"name": LIBRARY, "methods": [method("<init>", invoke(WRAPPER, "<init>"))]},
        {"name": BENIGN, "methods": [method("<init>")]},
    ]


CONFIG = {
    "analyzer_config": {
        "version": "1.0",
        "vulnerabilities": [
            {
                "enabled": True,
                "sinks": ["__CANARY__Command.<init>"],
                "dynamic_sites": [
                    {"class_name": "java.lang.Class", "method_name": "forName", "kind": "reflection"},
                    {"class_name": "java.lang.reflect.Method", "method_name": "invoke", "kind": "reflection"},
                    {"class_name": "java.lang.ClassLoader", "method_name": "loadClass", "kind": "reflection"},
                ],
            },
            {
                "enabled": True,
                "sinks": ["__CANARY__Command.<init>"],
                "dynamic_sites": [
                    {"class_name": "java.io.ObjectInputStream", "method_name": "simulateReadObject", "kind": "deserialization"},
                ],
                "stubs": {"simulateReadObject": "deserialization"},
            },
            {
                "enabled": False,
                "sinks": ["not-a-real-sink"],
                "dynamic_sites": [
                    {"class_name": "java.lang.System", "method_name": "exit", "kind": "reflection"}
                ],
            },
        ]
    }
}


class FuzzerCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.decompiled = self.root / "decompiled"
        self.decompiled.mkdir()
        data = classes()
        data[0]["methods"].append(method("reflectViaMethod", invoke("java/lang/reflect/Method", "invoke")))
        data[0]["methods"].append(method("loadClass", invoke("java/lang/ClassLoader", "loadClass")))
        # Unrelated classes are excluded by the fuzzer's single-source-file scope.
        data.append({"name": "some/Other", "methods": [method("outside", invoke(CANARY, "<init>"))]})
        for i, cls in enumerate(data):
            (self.decompiled / f"{i}.json").write_text(json.dumps(cls), encoding="utf-8")
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps(CONFIG), encoding="utf-8")

    def run_target(self, target):
        output = self.root / "result.json"
        result = main([target, "--config", str(self.config), "--decompiled", str(self.decompiled), "--output", str(output)])
        self.assertEqual(result, 0)
        return json.loads(output.read_text(encoding="utf-8"))

    def test_fuzzer_deserialization_contract_and_stub(self):
        data = self.run_target(f"{PREFIX}.deserialize:()V")
        self.assertEqual(set(data), {"graph", "dynamic_edges", "sinks"})
        mock = f"{PREFIX}.simulateReadObject:()V"
        caller = f"{PREFIX}.deserialize:()V"
        canary = f"{PREFIX}$__CANARY__Command.<init>:()V"
        wrapper = f"{PREFIX}$SafeWrapperCommand.<init>:()V"
        self.assertEqual(data["graph"][caller], [mock])
        self.assertIn(canary, data["sinks"])
        self.assertIn(wrapper, data["graph"][mock])
        self.assertNotIn(f"{PREFIX}$SafeCommand.<init>:()V", data["graph"][mock])
        self.assertTrue(any(e == {"caller": mock, "callee": wrapper, "kind": "deserialization"} for e in data["dynamic_edges"]))
        self.assertNotIn("some.Other.outside:()V", data["graph"])

    def test_fuzzer_reflection_contract(self):
        data = self.run_target(f"{PREFIX}.reflect:()V")
        self.assertEqual({e["kind"] for e in data["dynamic_edges"]}, {"reflection"})
        self.assertIn(f"{PREFIX}$UpdatedLibrary.<init>:()V", data["graph"][f"{PREFIX}.reflect:()V"])
        self.assertIn(f"{PREFIX}$__CANARY__Command.<init>:()V", data["sinks"])

    def test_additional_configured_reflection_methods(self):
        for name in ("reflectViaMethod", "loadClass"):
            data = self.run_target(f"{PREFIX}.{name}:()V")
            self.assertTrue(any(e["kind"] == "reflection" for e in data["dynamic_edges"]))

    def test_config_loader_skips_disabled_rules(self):
        sinks, stubs, sites = load_config(self.config)
        self.assertNotIn("not-a-real-sink", sinks)
        self.assertNotIn(("java/lang/System", "exit"), sites)
        self.assertEqual(stubs["simulateReadObject"], "deserialization")

    def test_old_legacy_cli_plain_json(self):
        output = self.root / "old.json"
        rc = main(["--decompiled", str(self.decompiled), "--output", str(output)])
        self.assertEqual(rc, 0)
        data = json.loads(output.read_text(encoding="utf-8"))
        self.assertIn(f"{PREFIX}.reflect:()V", data)
        self.assertNotIn("dynamic_edges", data)

    def test_subprocess_stdout_is_machine_readable_json(self):
        script = Path(__file__).resolve().parents[1] / "solutions" / "syntactic" / "src" / "call_graph.py"
        result = subprocess.run(
            [sys.executable, str(script), f"{PREFIX}.reflect:()V",
             "--config", str(self.config), "--decompiled", str(self.decompiled)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(set(payload), {"graph", "dynamic_edges", "sinks"})

    def test_legacy_builder_accepts_dynamic_site_config(self):
        graph = build_call_graph_from_classes(classes(), dynamic=True, dynamic_sites={
            ("java/lang/Class", "forName"): "reflection",
        })
        self.assertIn(f"{PREFIX}$UpdatedLibrary.<init>:()V", graph[f"{PREFIX}.reflect:()V"])

    def test_missing_config_is_error(self):
        rc = main([f"{PREFIX}.reflect:()V", "--decompiled", str(self.decompiled),
                   "--config", str(self.root / "missing.json")])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
