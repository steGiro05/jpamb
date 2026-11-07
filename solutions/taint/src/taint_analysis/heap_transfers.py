"""Transfer functions for allocations, fields, and arrays."""

from collections.abc import Iterable

import jvm
from jvm.state import PC

from taint_analysis.abstractions import (
    AllocationSite,
    ArrayContentsLocation,
    FieldLocation,
    StaticFieldLocation,
    TaintHeap,
    TaintSet,
    TaintState,
    TaintValue,
)


def _is_reference_type(value_type: jvm.Type) -> bool:
    return isinstance(value_type, (jvm.Array, jvm.Object, jvm.Reference))


def _default_value(value_type: jvm.Type) -> TaintValue:
    if _is_reference_type(value_type):
        return TaintValue.null_reference()
    return TaintValue.untainted()


def _with_labels(value: TaintValue, labels: TaintSet) -> TaintValue:
    return TaintValue(labels=labels, references=value.references)


def _join_values(values: Iterable[TaintValue], default: TaintValue) -> TaintValue:
    result = default
    for value in values:
        result = result | value
    return result


def transfer_heap(pc: PC, instruction: jvm.Opcode, state: TaintState) -> TaintState:
    """Apply one allocation or heap-access instruction."""

    match instruction:
        case jvm.New():
            return state.push(TaintValue.reference([AllocationSite(pc)]))

        case jvm.NewArray(type=element_type, dim=dimensions):
            if dimensions < 1:
                raise ValueError("an array must have at least one dimension")
            sizes, after = state.pop(dimensions)
            labels = TaintSet.bottom()
            for size in sizes:
                if size.is_reference:
                    raise TypeError("array dimensions must be non-reference values")
                labels = labels | size.labels

            target = AllocationSite(pc)
            heap = after.heap.weak_store(
                ArrayContentsLocation(target), _default_value(element_type)
            )
            return after.with_heap(heap).push(TaintValue.reference([target], labels))

        case jvm.ArrayStore():
            (reference, index, value), after = state.pop(3)
            if not reference.is_reference or index.is_reference:
                raise TypeError("invalid operands for an array store")

            stored = _with_labels(
                value, reference.labels | index.labels | value.labels
            )
            heap = after.heap
            assert reference.references is not None
            for target in reference.references.heap_targets:
                heap = heap.weak_store(ArrayContentsLocation(target), stored)
            return after.with_heap(heap)

        case jvm.ArrayLoad(type=element_type):
            (reference, index), after = state.pop(2)
            if not reference.is_reference or index.is_reference:
                raise TypeError("invalid operands for an array load")

            assert reference.references is not None
            values = (
                value
                for target in reference.references.heap_targets
                if (value := after.heap.get(ArrayContentsLocation(target))) is not None
            )
            loaded = _join_values(values, _default_value(element_type))
            labels = loaded.labels | reference.labels | index.labels
            return after.push(_with_labels(loaded, labels))

        case jvm.ArrayLength():
            (reference,), after = state.pop()
            if not reference.is_reference:
                raise TypeError("arraylength requires a reference")
            return after.push(TaintValue(labels=reference.labels))

        case jvm.Put(static=True, field=field):
            (value,), after = state.pop()
            heap = after.heap.weak_store(StaticFieldLocation(field), value)
            return after.with_heap(heap)

        case jvm.Put(static=False, field=field):
            (reference, value), after = state.pop(2)
            if not reference.is_reference:
                raise TypeError("putfield requires a reference")

            stored = _with_labels(value, reference.labels | value.labels)
            heap = after.heap
            assert reference.references is not None
            for target in reference.references.heap_targets:
                heap = heap.weak_store(FieldLocation(target, field), stored)
            return after.with_heap(heap)

        case jvm.Get(static=True, field=field):
            loaded = state.heap.get(StaticFieldLocation(field))
            if loaded is None:
                loaded = _default_value(field.fieldid.type)
            return state.push(loaded)

        case jvm.Get(static=False, field=field):
            (reference,), after = state.pop()
            if not reference.is_reference:
                raise TypeError("getfield requires a reference")

            assert reference.references is not None
            values = (
                value
                for target in reference.references.heap_targets
                if (value := after.heap.get(FieldLocation(target, field))) is not None
            )
            loaded = _join_values(values, _default_value(field.fieldid.type))
            return after.push(
                _with_labels(loaded, loaded.labels | reference.labels)
            )

        case _:
            raise NotImplementedError(
                f"no heap taint transfer function for {type(instruction).__name__}"
            )
