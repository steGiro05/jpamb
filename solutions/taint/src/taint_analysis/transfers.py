"""Transfer functions for basic, straight-line JVM instructions."""

import jvm
from jvm.state import PC

from taint_analysis.abstractions import AllocationSite, TaintState, TaintValue


def _constant_value(pc: PC, instruction: jvm.Push) -> TaintValue:
    """Abstract a constant pushed by the bytecode."""

    match instruction.type:
        case jvm.Reference():
            # Push represents aconst_null when its type is Reference.
            return TaintValue.null_reference()
        case jvm.Object(classname) if classname == jvm.ClassName("java.lang.String"):
            # A string literal is an untainted reference. Its load site gives it
            # a finite abstract identity, just as an allocation site does.
            return TaintValue.reference([AllocationSite(pc)])
        case _:
            return TaintValue.untainted()


def transfer_base(pc: PC, instruction: jvm.Opcode, state: TaintState) -> TaintState:
    """Apply one supported straight-line instruction to ``state``.

    Control flow, heap access, allocation, and calls are intentionally handled
    by later transfer-function groups. Unsupported instructions fail loudly so
    the analysis cannot silently lose a dependency.
    """

    match instruction:
        case jvm.Push():
            return state.push(_constant_value(pc, instruction))

        case jvm.Load(index=index):
            return state.push(state.load(index))

        case jvm.Store(index=index):
            (value,), after = state.pop()
            return after.store(index, value)

        case jvm.Binary():
            (left, right), after = state.pop(2)
            if left.is_reference or right.is_reference:
                raise TypeError("binary arithmetic requires non-reference values")
            return after.push(TaintValue(labels=left.labels | right.labels))

        case jvm.Negate() | jvm.Cast():
            (value,), after = state.pop()
            if value.is_reference:
                raise TypeError("numeric conversion requires a non-reference value")
            return after.push(value)

        case jvm.CheckCast():
            (value,), after = state.pop()
            if not value.is_reference:
                raise TypeError("checkcast requires a reference value")
            return after.push(value)

        case jvm.Incr(index=index):
            value = state.load(index)
            if value.is_reference:
                raise TypeError("increment requires a non-reference local")
            return state.store(index, value)

        case jvm.Dup(words=1):
            (value,), after = state.pop()
            return after.push(value).push(value)

        case jvm.Dup(words=words):
            raise NotImplementedError(f"dup with {words} words is not supported")

        case _:
            raise NotImplementedError(
                f"no basic taint transfer function for {type(instruction).__name__}"
            )
