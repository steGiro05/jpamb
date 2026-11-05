from taint_analysis import (
    SIMULATE_READ_OBJECT,
    CallGraph,
    TaintAnalyzer,
    TaintValue,
    sanitizer_summary,
)

import jvm
from jvm.state import PC


class Program:
    def __init__(self, methods: list[jvm.Method]):
        self.methods = {method.id: method for method in methods}

    def getmethod(self, methodid: jvm.AbsMethodID) -> jvm.Method:
        return self.methods[methodid]

    def __getitem__(self, pc: PC) -> jvm.Opcode:
        return self.methods[pc.method].opcodes[pc.offset]


def method(method_id: str, opcodes: list[jvm.Opcode], max_locals: int) -> jvm.Method:
    return jvm.Method(jvm.AbsMethodID.decode(method_id), opcodes, max_locals)


def test_analyzer_propagates_taint_through_call_and_finds_sink() -> None:
    entry = method(
        "jpamb.cases.Entry.run:(Ljava/lang/String;)V",
        [
            jvm.Load(offset=0, type=jvm.Reference(), index=0),
            jvm.InvokeStatic(
                offset=1,
                method=jvm.AbsMethodID.decode(
                    "jpamb.cases.Helper.pass:"
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
        "jpamb.cases.Helper.pass:(Ljava/lang/String;)Ljava/lang/String;",
        [
            jvm.Load(offset=0, type=jvm.Reference(), index=0),
            jvm.Return(offset=1, type=jvm.Reference()),
        ],
        max_locals=1,
    )
    call_site = PC(entry.id, 1)
    graph = CallGraph(
        edges={call_site: (helper.id,)},
        distances_to_sink={entry.id: 1},
    )

    result = TaintAnalyzer(Program([entry, helper]), graph).analyze(entry.id)

    assert len(result.findings) == 1
    assert result.findings[0].relevant_parameters == (0,)
    assert result.findings[0].category == "CWE-502"


def test_analyzer_joins_branch_states_at_fixpoint() -> None:
    entry = method(
        "jpamb.cases.Entry.choose:(II)V",
        [
            jvm.Load(offset=0, type=jvm.Int(), index=0),
            jvm.Ifz(offset=1, condition=jvm.CmpOpr.Eq, target=4),
            jvm.Load(offset=2, type=jvm.Int(), index=0),
            jvm.Goto(offset=3, target=5),
            jvm.Load(offset=4, type=jvm.Int(), index=1),
            jvm.Store(offset=5, type=jvm.Int(), index=2),
            jvm.Return(offset=6, type=None),
        ],
        max_locals=3,
    )

    result = TaintAnalyzer(Program([entry]), CallGraph()).analyze(entry.id)

    labels = result.states[PC(entry.id, 6)].locals[2]
    assert labels is not None
    assert labels.labels.labels == {
        *TaintValue.parameter(0).labels.labels,
        *TaintValue.parameter(1).labels.labels,
    }


def test_analyzer_terminates_when_a_loop_reaches_fixpoint() -> None:
    entry = method(
        "jpamb.cases.Entry.loop:(I)V",
        [
            jvm.Load(offset=0, type=jvm.Int(), index=0),
            jvm.Store(offset=1, type=jvm.Int(), index=1),
            jvm.Goto(offset=2, target=0),
        ],
        max_locals=2,
    )

    result = TaintAnalyzer(Program([entry]), CallGraph()).analyze(entry.id)

    assert result.findings == ()
    assert len(result.states) == 3


def test_analyzer_rejects_an_internal_call_without_a_call_graph_edge() -> None:
    helper_id = jvm.AbsMethodID.decode("jpamb.cases.Helper.run:()V")
    entry = method(
        "jpamb.cases.Entry.run:()V",
        [jvm.InvokeStatic(offset=0, method=helper_id)],
        max_locals=0,
    )

    try:
        TaintAnalyzer(Program([entry]), CallGraph()).analyze(entry.id)
    except ValueError as error:
        assert "no target" in str(error)
    else:
        raise AssertionError("a missing call-graph edge must stop the analysis")


def test_analyzer_accepts_an_explicit_sanitizer_configuration() -> None:
    cleaner = jvm.AbsMethodID.decode(
        "example.Trusted.clean:(Ljava/lang/String;)Ljava/lang/String;"
    )
    entry = method(
        "jpamb.cases.Entry.run:(Ljava/lang/String;)V",
        [
            jvm.Load(offset=0, type=jvm.Reference(), index=0),
            jvm.InvokeStatic(offset=1, method=cleaner),
            jvm.Store(offset=2, type=jvm.Reference(), index=1),
            jvm.Return(offset=3, type=None),
        ],
        max_locals=2,
    )
    analyzer = TaintAnalyzer(
        Program([entry]),
        CallGraph(),
        summaries={cleaner: sanitizer_summary(cleaner)},
    )

    result = analyzer.analyze(entry.id)

    cleaned = result.states[PC(entry.id, 3)].locals[1]
    assert cleaned is not None
    assert cleaned.labels == TaintValue.untainted().labels
