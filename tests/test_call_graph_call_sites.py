"""Tests for the opcode-indexed call-site interface used by taint analysis."""
import json
import tempfile
import unittest
from pathlib import Path

from call_graph import collect_call_sites, build_call_graph_from_classes, load_config, main

ENTRY = "example/Entry"
PREFIX = "example.Entry"
HELPER = ENTRY + "$Helper"
CANARY = ENTRY + "$Canary"
BENIGN = ENTRY + "$Benign"


def invoke(owner, name):
    return {"opr": "invoke", "method": {"ref": {"kind": "class", "name": owner},
                                      "name": name, "args": [], "returns": None}}


def method(name, *bytecode):
    return {"name": name, "params": [], "returns": {"type": None},
            "code": {"bytecode": list(bytecode)}}


def fixture():
    return [
        {"name": ENTRY, "methods": [
            method("twoCalls", {"opr": "push"}, invoke(HELPER, "left"),
                   {"opr": "return"}, invoke(HELPER, "right"),
                   invoke("java/io/PrintStream", "println")),
            method("dynamic", {"opr": "push"}, invoke("java/lang/Class", "forName"),
                   {"opr": "return"}, invoke("java/io/ObjectInputStream", "readObject"),
                   invoke(ENTRY, "simulateReadObject")),
            method("simulateReadObject", invoke(BENIGN, "<init>")),
        ]},
        {"name": HELPER, "methods": [method("left", invoke(CANARY, "<init>")), method("right")]},
        {"name": CANARY, "methods": [method("<init>")]},
        {"name": BENIGN, "methods": [method("<init>")]},
    ]


CONFIG = {"analyzer_config": {"vulnerabilities": [{
    "enabled": True,
    "exploit_targets": ["Canary.<init>"],
    "sinks": ["should not win over exploit_targets"],
    "dynamic_sites": [
        {"class_name": "java.lang.Class", "method_name": "forName", "kind": "reflection"},
        {"class_name": "java.io.ObjectInputStream", "method_name": "readObject", "kind": "deserialization"},
    ],
    "stubs": {"simulateReadObject": "deserialization"},
}]}}


class CallSiteContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for i, cls in enumerate(fixture()):
            (self.root / f"{i}.json").write_text(json.dumps(cls), encoding="utf-8")
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps(CONFIG), encoding="utf-8")

    def run_target(self, name):
        output = self.root / "output.json"
        rc = main([f"{PREFIX}.{name}:()V", "--decompiled", str(self.root),
                   "--config", str(self.config), "--output", str(output)])
        self.assertEqual(rc, 0)
        return json.loads(output.read_text(encoding="utf-8"))

    def test_each_invoke_uses_opcode_position_not_bytecode_offset(self):
        data = self.run_target("twoCalls")
        caller = f"{PREFIX}.twoCalls:()V"
        sites = [s for s in data["call_sites"] if s["caller"] == caller]
        self.assertEqual([s["instruction_index"] for s in sites], [1, 3, 4])
        self.assertEqual(sites[0]["declared_callee"], f"{PREFIX}$Helper.left:()V")
        self.assertEqual(sites[0]["resolved_callees"], [f"{PREFIX}$Helper.left:()V"])
        self.assertEqual(sites[1]["resolved_callees"], [f"{PREFIX}$Helper.right:()V"])
        self.assertEqual(sites[2]["resolved_callees"], [])

    def test_dynamic_and_stub_sites_are_distinct_and_fake_edges_ignored(self):
        data = self.run_target("dynamic")
        caller = f"{PREFIX}.dynamic:()V"
        sites = {s["instruction_index"]: s for s in data["call_sites"] if s["caller"] == caller}
        self.assertEqual(set(sites), {1, 3, 4})
        canary = f"{PREFIX}$Canary.<init>:()V"
        # These sites select class names or deserialize payloads; the JVM
        # actually invokes library methods, not the candidate constructors.
        for ix in (1, 3):
            self.assertEqual(sites[ix]["resolved_callees"], [])
            self.assertNotIn(canary, sites[ix]["resolved_callees"])
        self.assertIn(canary, data["graph"][caller])
        self.assertEqual({e["kind"] for e in data["dynamic_edges"] if e["caller"] == caller},
                         {"reflection", "deserialization"})
        self.assertEqual(sites[4]["resolved_callees"], [f"{PREFIX}.simulateReadObject:()V"])
        mock_sites = [s for s in data["call_sites"] if s["caller"] == f"{PREFIX}.simulateReadObject:()V"]
        self.assertEqual(len(mock_sites), 1)
        self.assertEqual(mock_sites[0]["resolved_callees"], [])
        self.assertNotIn(f"{PREFIX}$Benign.<init>:()V", data["graph"].get(f"{PREFIX}.simulateReadObject:()V", []))

    def test_retains_exploit_targets_and_legacy_sinks(self):
        data = self.run_target("dynamic")
        self.assertEqual(data["exploit_targets"], [f"{PREFIX}$Canary.<init>:()V"])
        self.assertEqual(data["sinks"], data["exploit_targets"])
        self.assertIn("dynamic_edges", data)

    def test_config_loads_new_exploit_target_field(self):
        sinks, stubs, sites = load_config(self.config)
        self.assertEqual(sinks, ["Canary.<init>"])
        self.assertEqual(stubs["simulateReadObject"], "deserialization")
        self.assertEqual(sites[("java/io/ObjectInputStream", "readObject")], "deserialization")

    def test_legacy_plain_json_unchanged(self):
        out = self.root / "plain.json"
        self.assertEqual(main(["--decompiled", str(self.root), "--output", str(out)]), 0)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertNotIn("call_sites", data)
        self.assertIn(f"{PREFIX}.twoCalls:()V", data)

    def test_detailed_json_includes_call_sites(self):
        out = self.root / "detailed.json"
        self.assertEqual(main(["--decompiled", str(self.root), "--format", "detailed-json",
                               "--output", str(out)]), 0)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertIn("call_sites", data)
        self.assertIn("exploit_targets", data)
        self.assertIn("dynamic_edges", data)


if __name__ == "__main__":
    unittest.main()
