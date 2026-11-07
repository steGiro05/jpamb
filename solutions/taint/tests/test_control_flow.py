from taint_analysis import (
    MethodReturn,
    Successor,
    TaintState,
    TaintValue,
    transfer_control_flow,
)

import jvm
from jvm.state import PC


METHOD_ID = jvm.AbsMethodID.decode("jpamb.cases.Example.run:()V")


def pc(offset: int = 0) -> PC:
    return PC(METHOD_ID, offset)


def test_goto_has_only_its_target_as_successor() -> None:
    state = TaintState(locals=())

    results = transfer_control_flow(
        pc(2), jvm.Goto(offset=2, target=9), state
    )

    assert results == (Successor(pc(9), state),)


def test_ifz_keeps_both_paths_and_consumes_condition() -> None:
    state = TaintState(locals=(), stack=(TaintValue.parameter(0),))

    results = transfer_control_flow(
        pc(2),
        jvm.Ifz(offset=2, condition=jvm.CmpOpr.Eq, target=9),
        state,
    )

    after = TaintState(locals=())
    assert results == (
        Successor(pc(9), after),
        Successor(pc(3), after),
    )


def test_if_keeps_both_paths_and_consumes_both_operands() -> None:
    state = TaintState(
        locals=(),
        stack=(TaintValue.parameter(0), TaintValue.parameter(1)),
    )

    results = transfer_control_flow(
        pc(4),
        jvm.If(offset=4, condition=jvm.CmpOpr.Lt, target=12),
        state,
    )

    after = TaintState(locals=())
    assert results == (
        Successor(pc(12), after),
        Successor(pc(5), after),
    )


def test_void_return_has_no_value() -> None:
    state = TaintState(locals=(TaintValue.parameter(0),))

    results = transfer_control_flow(
        pc(), jvm.Return(offset=0, type=None), state
    )

    assert results == (MethodReturn(state),)


def test_value_return_preserves_taint_and_removes_value_from_stack() -> None:
    value = TaintValue.parameter(0)
    state = TaintState(locals=(), stack=(value,))

    results = transfer_control_flow(
        pc(), jvm.Return(offset=0, type=jvm.Int()), state
    )

    assert results == (MethodReturn(TaintState(locals=()), value),)
