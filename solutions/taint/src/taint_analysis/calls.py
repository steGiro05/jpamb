"""Taint propagation across resolved interprocedural calls."""

from collections.abc import Iterable
from dataclasses import dataclass

import jvm
from jvm.state import PC

from taint_analysis.abstractions import TaintState, TaintValue
from taint_analysis.control_flow import MethodReturn, Successor


@dataclass(frozen=True, slots=True)
class Continuation:
    """Caller state to resume after a callee returns."""

    return_pc: PC
    caller_state: TaintState
    expects_value: bool


@dataclass(frozen=True, slots=True)
class CallRequest:
    """One call-graph target together with its abstract entry state."""

    callee_pc: PC
    callee_state: TaintState
    continuation: Continuation


type InternalInvokeInstruction = (
    jvm.InvokeStatic | jvm.InvokeVirtual | jvm.InvokeInterface | jvm.InvokeSpecial
)
type InvokeInstruction = InternalInvokeInstruction | jvm.InvokeDynamic


@dataclass(frozen=True, slots=True)
class InvocationOperands:
    receiver: TaintValue | None
    arguments: tuple[TaintValue, ...]
    state_after_pop: TaintState


def _local_width(value_type: jvm.Type) -> int:
    return 2 if isinstance(value_type, (jvm.Long, jvm.Double)) else 1


def _is_instance_call(instruction: InvokeInstruction) -> bool:
    return isinstance(
        instruction, (jvm.InvokeVirtual, jvm.InvokeInterface, jvm.InvokeSpecial)
    )


def pop_invocation_operands(
    instruction: InvokeInstruction, state: TaintState
) -> InvocationOperands:
    """Pop receiver and arguments according to the invocation descriptor."""

    parameter_count = len(instruction.method.methodid.params)
    operand_count = parameter_count + int(_is_instance_call(instruction))
    operands, after = state.pop(operand_count)

    if _is_instance_call(instruction):
        receiver = operands[0]
        if not receiver.is_reference:
            raise TypeError("an instance-call receiver must be a reference")
        arguments = operands[1:]
    else:
        receiver = None
        arguments = operands
    return InvocationOperands(receiver, arguments, after)


def _same_descriptor(declared: jvm.AbsMethodID, resolved: jvm.AbsMethodID) -> bool:
    return declared.methodid.encode().split(":", 1)[1] == (
        resolved.methodid.encode().split(":", 1)[1]
    )


def _callee_state(
    method: jvm.Method,
    receiver: TaintValue | None,
    arguments: tuple[TaintValue, ...],
    caller_after: TaintState,
) -> TaintState:
    locals_: list[TaintValue | None] = [None] * method.max_locals
    local_index = 0

    if receiver is not None:
        if not receiver.is_reference:
            raise TypeError("an instance-call receiver must be a reference")
        if not locals_:
            raise ValueError("callee does not have a local slot for its receiver")
        locals_[0] = receiver
        local_index = 1

    parameters = method.id.methodid.params
    if len(arguments) != len(parameters):
        raise ValueError("argument count does not match the resolved callee")

    for argument, parameter_type in zip(arguments, parameters, strict=True):
        if local_index >= method.max_locals:
            raise ValueError("callee does not have enough local slots")
        locals_[local_index] = argument
        local_index += _local_width(parameter_type)

    if local_index > method.max_locals:
        raise ValueError("callee does not have enough local slots")

    return TaintState(locals=tuple(locals_), heap=caller_after.heap)


def prepare_calls(
    pc: PC,
    instruction: InternalInvokeInstruction,
    state: TaintState,
    resolved_callees: Iterable[jvm.Method],
) -> tuple[CallRequest, ...]:
    """Create one abstract call request for every call-graph target."""

    callees = tuple(resolved_callees)
    if not callees:
        raise ValueError("the call graph supplied no target for this invocation")

    operands = pop_invocation_operands(instruction, state)
    receiver = operands.receiver
    arguments = operands.arguments
    caller_after = operands.state_after_pop

    continuation = Continuation(
        return_pc=pc + 1,
        caller_state=caller_after,
        expects_value=instruction.method.methodid.return_type is not None,
    )

    requests = []
    for callee in callees:
        if not _same_descriptor(instruction.method, callee.id):
            raise ValueError("call-graph target has an incompatible method descriptor")
        requests.append(
            CallRequest(
                callee_pc=PC(callee.id, 0),
                callee_state=_callee_state(
                    callee, receiver, arguments, caller_after
                ),
                continuation=continuation,
            )
        )
    return tuple(requests)


def resume_call(continuation: Continuation, returned: MethodReturn) -> Successor:
    """Resume a caller with the heap and optional value produced by a callee."""

    if continuation.expects_value != (returned.value is not None):
        raise ValueError("callee return value does not match the invocation descriptor")

    caller = continuation.caller_state.with_heap(returned.state.heap)
    if returned.value is not None:
        caller = caller.push(returned.value)
    return Successor(continuation.return_pc, caller)
