from taint_analysis import (
    ExternalTarget,
    SourceLabel,
    TaintHeap,
    TaintSet,
    TaintValue,
    initial_entry_state,
)

import jvm


def method(signature: str, max_locals: int) -> jvm.Method:
    method_id = jvm.AbsMethodID.decode(f"jpamb.cases.Example.{signature}")
    return jvm.Method(method_id, [], max_locals)


def test_initial_state_labels_primitive_parameters() -> None:
    state = initial_entry_state(method("run:(IZC)V", max_locals=4))

    assert state.locals == (
        TaintValue.parameter(0),
        TaintValue.parameter(1),
        TaintValue.parameter(2),
        None,
    )
    assert state.stack == ()
    assert state.heap == TaintHeap()


def test_initial_state_gives_reference_parameters_external_targets() -> None:
    state = initial_entry_state(
        method("run:(Ljava/lang/String;[IA)V", max_locals=4)
    )

    for parameter_index in range(3):
        value = state.locals[parameter_index]
        assert value is not None
        assert value.labels == TaintSet.for_parameter(parameter_index)
        assert value.references is not None
        assert value.references.targets == frozenset(
            {ExternalTarget(SourceLabel(parameter_index))}
        )

    assert state.locals[3] is None


def test_initial_state_respects_two_slot_parameters() -> None:
    state = initial_entry_state(method("run:(JLjava/lang/String;D)V", max_locals=6))

    assert state.locals == (
        TaintValue.parameter(0),
        None,
        TaintValue.external_reference(1),
        TaintValue.parameter(2),
        None,
        None,
    )


def test_initial_state_rejects_too_few_local_slots() -> None:
    try:
        initial_entry_state(method("run:(J)V", max_locals=1))
    except ValueError as error:
        assert "enough local slots" in str(error)
    else:
        raise AssertionError("an invalid max_locals value should be rejected")
