from taint_analysis import (
    CLASS_FOR_NAME,
    CLASS_NEW_INSTANCE,
    SIMULATE_READ_OBJECT,
    SIMULATE_RESOLVE_CLASS,
    TaintState,
    TaintValue,
    apply_summary,
    builtin_summary,
    inspect_sinks,
    sanitizer_summary,
)

import jvm
from jvm.state import PC


CALLER = jvm.AbsMethodID.decode("jpamb.cases.Example.run:(Ljava/lang/String;)V")


def pc(offset: int = 0) -> PC:
    return PC(CALLER, offset)


def static_call(offset: int, method: jvm.AbsMethodID) -> jvm.InvokeStatic:
    return jvm.InvokeStatic(offset=offset, method=method)


def test_simulated_deserialization_summary_propagates_payload_taint() -> None:
    instruction = static_call(3, SIMULATE_READ_OBJECT)
    state = TaintState(locals=(), stack=(TaintValue.external_reference(0),))
    summary = builtin_summary(instruction)

    assert summary is not None
    result = apply_summary(pc(3), instruction, state, summary)

    assert result.state.stack[0].labels == TaintValue.parameter(0).labels
    assert result.state.stack[0].is_reference


def test_resolve_class_name_summary_propagates_payload_taint() -> None:
    instruction = static_call(3, SIMULATE_RESOLVE_CLASS)
    state = TaintState(locals=(), stack=(TaintValue.external_reference(0),))
    summary = builtin_summary(instruction)

    assert summary is not None
    result = apply_summary(pc(3), instruction, state, summary)

    assert result.state.stack[0].labels == TaintValue.parameter(0).labels


def test_reflection_summary_propagates_class_name_to_class_object() -> None:
    instruction = static_call(4, CLASS_FOR_NAME)
    state = TaintState(locals=(), stack=(TaintValue.external_reference(0),))
    summary = builtin_summary(instruction)

    assert summary is not None
    class_result = apply_summary(pc(4), instruction, state, summary)
    class_value = class_result.state.stack[0]

    new_instance = jvm.InvokeVirtual(offset=5, method=CLASS_NEW_INSTANCE)
    instance_summary = builtin_summary(new_instance)
    assert instance_summary is not None
    object_result = apply_summary(
        pc(5), new_instance, TaintState(locals=(), stack=(class_value,)), instance_summary
    )

    assert object_result.state.stack[0].labels == TaintValue.parameter(0).labels


def test_string_check_is_not_treated_as_a_sanitizer() -> None:
    method = jvm.AbsMethodID.decode(
        "java.lang.String.startsWith:(Ljava/lang/String;)Z"
    )
    instruction = jvm.InvokeVirtual(offset=2, method=method)
    state = TaintState(
        locals=(),
        stack=(TaintValue.external_reference(0), TaintValue.reference([])),
    )
    summary = builtin_summary(instruction)

    assert summary is not None
    result = apply_summary(pc(2), instruction, state, summary)

    assert result.state.stack == (TaintValue.parameter(0),)


def test_sanitizer_must_be_explicit_and_removes_return_taint() -> None:
    method = jvm.AbsMethodID.decode(
        "example.Trusted.clean:(Ljava/lang/String;)Ljava/lang/String;"
    )
    instruction = static_call(2, method)
    state = TaintState(locals=(), stack=(TaintValue.external_reference(0),))

    result = apply_summary(pc(2), instruction, state, sanitizer_summary(method))

    assert result.state.stack[0].labels == TaintValue.untainted().labels


def test_tainted_deserialization_input_creates_a_finding() -> None:
    instruction = static_call(8, SIMULATE_READ_OBJECT)
    state = TaintState(locals=(), stack=(TaintValue.external_reference(0),))

    findings = inspect_sinks(
        pc(8), instruction, state, call_graph_distance=2
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "CWE-502"
    assert finding.relevant_parameters == (0,)
    assert finding.call_graph_distance == 2


def test_untainted_sink_input_does_not_create_a_finding() -> None:
    instruction = static_call(8, CLASS_FOR_NAME)
    state = TaintState(locals=(), stack=(TaintValue.reference([]),))

    assert inspect_sinks(pc(8), instruction, state, call_graph_distance=0) == ()


def test_canary_is_not_a_static_security_sink() -> None:
    canary = jvm.AbsMethodID.decode(
        "jpamb.cases.advanced.CWE502.canary:()V"
    )
    instruction = static_call(9, canary)

    assert inspect_sinks(
        pc(9), instruction, TaintState(locals=()), call_graph_distance=0
    ) == ()
