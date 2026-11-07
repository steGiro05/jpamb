"""Transfer functions for JVM control-flow instructions."""

from dataclasses import dataclass

import jvm
from jvm.state import PC

from taint_analysis.abstractions import TaintState, TaintValue


@dataclass(frozen=True, slots=True)
class Successor:
    """A state that may reach another program counter."""

    pc: PC
    state: TaintState


@dataclass(frozen=True, slots=True)
class MethodReturn:
    """The state and optional value produced when a method returns."""

    state: TaintState
    value: TaintValue | None = None


type ControlFlowResult = Successor | MethodReturn


def transfer_control_flow(
    pc: PC,
    instruction: jvm.Opcode,
    state: TaintState,
) -> tuple[ControlFlowResult, ...]:
    """Apply one branch, jump, or return instruction.

    Both outcomes of a conditional are retained. Condition labels are consumed
    with their stack operands but are not copied into either successor because
    the initial analysis deliberately excludes implicit control dependencies.
    """

    match instruction:
        case jvm.Goto(target=target):
            return (Successor(pc % target, state),)

        case jvm.Ifz(target=target):
            _, after = state.pop()
            return (
                Successor(pc % target, after),
                Successor(pc + 1, after),
            )

        case jvm.If(target=target):
            _, after = state.pop(2)
            return (
                Successor(pc % target, after),
                Successor(pc + 1, after),
            )

        case jvm.Return(type=None):
            return (MethodReturn(state),)

        case jvm.Return():
            (value,), after = state.pop()
            return (MethodReturn(after, value),)

        case _:
            raise NotImplementedError(
                f"no control-flow taint transfer function for "
                f"{type(instruction).__name__}"
            )
