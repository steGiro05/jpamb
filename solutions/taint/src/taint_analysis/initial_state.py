"""Construction of the abstract state at a JPAMB entry method."""

import jvm

from taint_analysis.abstractions import TaintState, TaintValue


def _is_reference_type(parameter_type: jvm.Type) -> bool:
    """Return whether a JVM parameter is represented by a reference."""

    return isinstance(parameter_type, (jvm.Array, jvm.Object, jvm.Reference))


def _local_width(parameter_type: jvm.Type) -> int:
    """Return the number of JVM local-variable slots used by a parameter."""

    return 2 if isinstance(parameter_type, (jvm.Long, jvm.Double)) else 1


def initial_entry_state(method: jvm.Method) -> TaintState:
    """Create the taint state at the start of a static JPAMB entry method.

    Parameter ``i`` receives source label ``pi``. Reference parameters also
    point to the synthetic target ``EXTERNAL_pi``. JPAMB entry methods are
    static, so local slot zero contains the first declared parameter rather
    than a ``this`` reference.
    """

    locals_: list[TaintValue | None] = [None] * method.max_locals
    local_index = 0

    for parameter_index, parameter_type in enumerate(method.id.methodid.params):
        if local_index >= method.max_locals:
            raise ValueError("method does not have enough local slots for its parameters")

        if _is_reference_type(parameter_type):
            value = TaintValue.external_reference(parameter_index)
        else:
            value = TaintValue.parameter(parameter_index)

        locals_[local_index] = value
        local_index += _local_width(parameter_type)

    if local_index > method.max_locals:
        raise ValueError("method does not have enough local slots for its parameters")

    return TaintState(locals=tuple(locals_))
