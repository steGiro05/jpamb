import jvm
from jvm.state import PC

from taint import analyze_with_call_graph, load_call_graph
from taint_analysis import SIMULATE_READ_OBJECT


class Program:
    def __init__(self, methods: list[jvm.Method]):
        self.methods = {method.id: method for method in methods}

    def getmethod(self, methodid: jvm.AbsMethodID) -> jvm.Method:
        return self.methods[methodid]

    def __getitem__(self, pc: PC) -> jvm.Opcode:
        return self.methods[pc.method].opcodes[pc.offset]


def method(method_id: str, opcodes: list[jvm.Opcode], max_locals: int) -> jvm.Method:
    return jvm.Method(jvm.AbsMethodID.decode(method_id), opcodes, max_locals)


def test_pipeline_connects_call_sites_fixpoint_and_fuzzer_hints() -> None:
    entry = method(
        "example.Entry.run:(Ljava/lang/String;)V",
        [
            jvm.Load(offset=0, type=jvm.Reference(), index=0),
            jvm.InvokeStatic(
                offset=1,
                method=jvm.AbsMethodID.decode(
                    "example.Helper.pass:"
                    "(Ljava/lang/String;)Ljava/lang/String;"
                ),
            ),
            jvm.InvokeStatic(offset=2, method=SIMULATE_READ_OBJECT),
            jvm.Store(offset=3, type=jvm.Reference(), index=1),
            jvm.Return(offset=4, type=None),
        ],
        max_locals=2,
    )
    helper = method(
        "example.Helper.pass:(Ljava/lang/String;)Ljava/lang/String;",
        [
            jvm.Load(offset=0, type=jvm.Reference(), index=0),
            jvm.Return(offset=1, type=jvm.Reference()),
        ],
        max_locals=1,
    )
    exploit_target = "example.Canary.<init>:()V"
    data = {
        "graph": {
            entry.id.encode(): [helper.id.encode()],
            helper.id.encode(): [exploit_target],
            exploit_target: [],
        },
        "call_sites": [
            {
                "caller": entry.id.encode(),
                "instruction_index": 1,
                "declared_callee": helper.id.encode(),
                "resolved_callees": [helper.id.encode()],
            }
        ],
        "exploit_targets": [exploit_target],
    }

    hints = analyze_with_call_graph(Program([entry, helper]), entry.id, data)

    assert hints["classification"] == "flagged_unverified"
    assert hints["findings"][0]["category"] == "CWE-502"
    assert hints["findings"][0]["relevant_parameters"] == [0]
    assert hints["findings"][0]["distance_to_exploit_target"] == 2


def test_precomputed_call_graph_can_be_loaded_as_a_shared_artifact(tmp_path) -> None:
    path = tmp_path / "call-graph.json"
    path.write_text(
        '{"graph": {}, "call_sites": [], "exploit_targets": []}',
        encoding="utf-8",
    )

    data = load_call_graph(path)

    assert data["call_sites"] == []
    assert data["exploit_targets"] == []
