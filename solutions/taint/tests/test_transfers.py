from taint_analysis import (
    NULL_TARGET,
    AllocationSite,
    TaintState,
    TaintValue,
    transfer_base,
)

import jvm
from jvm.state import PC


METHOD_ID = jvm.AbsMethodID.decode("jpamb.cases.Example.run:()V")


def pc(offset: int = 0) -> PC:
    return PC(METHOD_ID, offset)


def test_primitive_constant_is_untainted() -> None:
    instruction = jvm.Push(offset=0, type=jvm.Int(), value=42)

    result = transfer_base(pc(), instruction, TaintState(locals=()))

    assert result.stack == (TaintValue.untainted(),)


def test_null_constant_is_an_untainted_null_reference() -> None:
    instruction = jvm.Push(offset=0, type=jvm.Reference(), value=0)

    result = transfer_base(pc(), instruction, TaintState(locals=()))

    assert result.stack[0].labels == TaintValue.untainted().labels
    assert result.stack[0].references is not None
    assert result.stack[0].references.targets == frozenset({NULL_TARGET})


def test_string_literal_is_an_untainted_reference_at_its_load_site() -> None:
    instruction = jvm.Push(
        offset=3,
        type=jvm.Object(jvm.ClassName("java.lang.String")),
        value="safe",
    )

    result = transfer_base(pc(3), instruction, TaintState(locals=()))

    assert result.stack == (TaintValue.reference([AllocationSite(pc(3))]),)


def test_load_and_store_copy_taint_without_changing_it() -> None:
    initial = TaintState(locals=(TaintValue.parameter(0), None))
    loaded = transfer_base(
        pc(), jvm.Load(offset=0, type=jvm.Int(), index=0), initial
    )
    stored = transfer_base(
        pc(1), jvm.Store(offset=1, type=jvm.Int(), index=1), loaded
    )

    assert loaded.stack == (TaintValue.parameter(0),)
    assert stored.locals == (TaintValue.parameter(0), TaintValue.parameter(0))
    assert stored.stack == ()


def test_binary_operation_joins_operand_labels() -> None:
    initial = TaintState(
        locals=(),
        stack=(TaintValue.parameter(0), TaintValue.parameter(1)),
    )
    instruction = jvm.Binary(
        offset=0,
        type=jvm.Int(),
        operant=jvm.BinaryOpr.Add,
    )

    result = transfer_base(pc(), instruction, initial)

    expected = TaintValue(
        labels=TaintValue.parameter(0).labels | TaintValue.parameter(1).labels
    )
    assert result.stack == (expected,)


def test_unary_operations_preserve_taint() -> None:
    initial = TaintState(locals=(), stack=(TaintValue.parameter(0),))

    negated = transfer_base(
        pc(), jvm.Negate(offset=0, type=jvm.Int()), initial
    )
    cast = transfer_base(
        pc(1),
        jvm.Cast(offset=1, from_=jvm.Int(), to_=jvm.Short()),
        negated,
    )

    assert cast.stack == (TaintValue.parameter(0),)


def test_checkcast_preserves_reference_taint_and_targets() -> None:
    value = TaintValue.external_reference(0)
    initial = TaintState(locals=(), stack=(value,))

    result = transfer_base(
        pc(),
        jvm.CheckCast(offset=0, type=jvm.Object(jvm.ClassName("java.lang.String"))),
        initial,
    )

    assert result.stack == (value,)


def test_increment_preserves_local_taint() -> None:
    initial = TaintState(locals=(TaintValue.parameter(0),))

    result = transfer_base(pc(), jvm.Incr(offset=0, index=0, amount=7), initial)

    assert result == initial


def test_dup_copies_the_top_stack_value() -> None:
    initial = TaintState(locals=(), stack=(TaintValue.parameter(0),))

    result = transfer_base(pc(), jvm.Dup(offset=0, words=1), initial)

    assert result.stack == (TaintValue.parameter(0), TaintValue.parameter(0))
