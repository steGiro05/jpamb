from taint_analysis import (
    ArrayContentsLocation,
    CallRequest,
    Continuation,
    ExternalTarget,
    MethodReturn,
    SourceLabel,
    Successor,
    TaintHeap,
    TaintState,
    TaintValue,
    prepare_calls,
    resume_call,
)

import jvm
from jvm.state import PC


CALLER_ID = jvm.AbsMethodID.decode("jpamb.cases.Caller.run:(II)I")


def method(method_id: str, max_locals: int) -> jvm.Method:
    return jvm.Method(jvm.AbsMethodID.decode(method_id), [], max_locals)


def pc(offset: int = 0) -> PC:
    return PC(CALLER_ID, offset)


def test_static_call_copies_arguments_to_callee_locals() -> None:
    callee = method("jpamb.cases.Helper.add:(II)I", max_locals=3)
    instruction = jvm.InvokeStatic(offset=4, method=callee.id)
    prefix = TaintValue.untainted()
    state = TaintState(
        locals=(None, None),
        stack=(prefix, TaintValue.parameter(0), TaintValue.parameter(1)),
    )

    requests = prepare_calls(pc(4), instruction, state, [callee])

    caller_after = TaintState(locals=(None, None), stack=(prefix,))
    assert requests == (
        CallRequest(
            callee_pc=PC(callee.id, 0),
            callee_state=TaintState(
                locals=(TaintValue.parameter(0), TaintValue.parameter(1), None)
            ),
            continuation=Continuation(pc(5), caller_after, expects_value=True),
        ),
    )


def test_instance_call_places_receiver_in_local_zero() -> None:
    declared = jvm.AbsMethodID.decode("jpamb.api.Worker.run:(I)V")
    callee = method("jpamb.impl.WorkerImpl.run:(I)V", max_locals=3)
    instruction = jvm.InvokeVirtual(offset=2, method=declared)
    receiver = TaintValue.external_reference(0)
    argument = TaintValue.parameter(1)
    state = TaintState(locals=(), stack=(receiver, argument))

    (request,) = prepare_calls(pc(2), instruction, state, [callee])

    assert request.callee_state.locals == (receiver, argument, None)
    assert not request.continuation.expects_value


def test_call_graph_may_produce_multiple_callee_requests() -> None:
    declared = jvm.AbsMethodID.decode("jpamb.api.Worker.run:(I)V")
    first = method("jpamb.impl.First.run:(I)V", max_locals=2)
    second = method("jpamb.impl.Second.run:(I)V", max_locals=2)
    instruction = jvm.InvokeVirtual(offset=2, method=declared)
    state = TaintState(
        locals=(),
        stack=(TaintValue.external_reference(0), TaintValue.parameter(1)),
    )

    requests = prepare_calls(pc(2), instruction, state, [first, second])

    assert {request.callee_pc.method for request in requests} == {
        first.id,
        second.id,
    }


def test_call_preserves_shared_heap() -> None:
    callee = method("jpamb.cases.Helper.read:([I)V", max_locals=1)
    instruction = jvm.InvokeStatic(offset=4, method=callee.id)
    target = ExternalTarget(SourceLabel(0))
    heap = TaintHeap().weak_store(
        ArrayContentsLocation(target), TaintValue.parameter(0)
    )
    state = TaintState(
        locals=(),
        stack=(TaintValue.external_reference(0),),
        heap=heap,
    )

    (request,) = prepare_calls(pc(4), instruction, state, [callee])

    assert request.callee_state.heap == heap
    assert request.continuation.caller_state.heap == heap


def test_resume_call_pushes_return_value_and_uses_callee_heap() -> None:
    continuation = Continuation(
        return_pc=pc(5),
        caller_state=TaintState(locals=(None,), stack=(TaintValue.untainted(),)),
        expects_value=True,
    )
    target = ExternalTarget(SourceLabel(0))
    changed_heap = TaintHeap().weak_store(
        ArrayContentsLocation(target), TaintValue.parameter(0)
    )
    returned = MethodReturn(
        state=TaintState(locals=(), heap=changed_heap),
        value=TaintValue.parameter(1),
    )

    result = resume_call(continuation, returned)

    assert result == Successor(
        pc(5),
        TaintState(
            locals=(None,),
            stack=(TaintValue.untainted(), TaintValue.parameter(1)),
            heap=changed_heap,
        ),
    )


def test_prepare_calls_rejects_a_missing_call_graph_target() -> None:
    callee_id = jvm.AbsMethodID.decode("jpamb.cases.Helper.run:()V")
    instruction = jvm.InvokeStatic(offset=0, method=callee_id)

    try:
        prepare_calls(pc(), instruction, TaintState(locals=()), [])
    except ValueError as error:
        assert "no target" in str(error)
    else:
        raise AssertionError("a missing call-graph edge must not be ignored")
