from collections.abc import Iterable

from hypothesis import given
from hypothesis import strategies as st
from taint_analysis import (
    NULL_TARGET,
    AllocationSite,
    ArrayContentsLocation,
    ExternalTarget,
    FieldLocation,
    ReferenceTargets,
    SourceLabel,
    TaintHeap,
    TaintSet,
    TaintState,
    TaintValue,
)

import jvm
from jvm.state import PC


def labels(*indices: int) -> TaintSet:
    return TaintSet(frozenset(SourceLabel(index) for index in indices))


def pc(offset: int) -> PC:
    method = jvm.AbsMethodID.decode("jpamb.cases.Example.run:()V")
    return PC(method, offset)


def field(name: str = "value") -> jvm.AbsFieldID:
    return jvm.AbsFieldID.decode(f"jpamb.cases.Example.{name}:I")


@st.composite
def taint_sets(draw: st.DrawFn) -> TaintSet:
    indices: Iterable[int] = draw(st.sets(st.integers(min_value=0, max_value=5)))
    return labels(*indices)


@given(taint_sets(), taint_sets(), taint_sets())
def test_taint_set_is_a_lattice(a: TaintSet, b: TaintSet, c: TaintSet) -> None:
    assert a <= a  # noqa: PLR0124 - verifies reflexivity of the domain order
    assert (a | b) == (b | a)
    assert (a | a) == a
    assert ((a | b) | c) == (a | (b | c))
    assert (a & b) == (b & a)
    assert (a & a) == a
    assert a <= (a | b)
    assert (a & b) <= a


def test_taint_set_bottom_and_entry_dependent_top() -> None:
    universe = [SourceLabel(0), SourceLabel(1), SourceLabel(2)]
    value = labels(0, 2)

    assert (value | TaintSet.bottom()) == value
    assert (value | TaintSet.top(universe)) == TaintSet.top(universe)


def test_reference_join_preserves_null_and_allocation_sites() -> None:
    site = AllocationSite(pc(15))
    joined = ReferenceTargets.null() | ReferenceTargets(frozenset({site}))

    assert joined.targets == frozenset({NULL_TARGET, site})
    assert joined.may_be_null
    assert joined.heap_targets == frozenset({site})


def test_external_reference_has_source_label_and_synthetic_target() -> None:
    value = TaintValue.external_reference(0)

    assert value.labels == labels(0)
    assert value.references == ReferenceTargets(
        frozenset({ExternalTarget(SourceLabel(0))})
    )


def test_joining_reference_values_unions_labels_and_targets() -> None:
    left = TaintValue.reference([AllocationSite(pc(15))], labels(0))
    right = TaintValue.reference([AllocationSite(pc(27))], labels(1))

    result = left | right

    assert result.labels == labels(0, 1)
    assert result.references == ReferenceTargets(
        frozenset({AllocationSite(pc(15)), AllocationSite(pc(27))})
    )


def test_reference_and_non_reference_values_cannot_be_joined() -> None:
    try:
        TaintValue.untainted() | TaintValue.null_reference()
    except TypeError as error:
        assert "reference" in str(error)
    else:
        raise AssertionError("joining different JVM value kinds should fail")


def test_heap_uses_distinct_field_and_array_content_cells() -> None:
    target = AllocationSite(pc(15))
    field_location = FieldLocation(target, field())
    array_location = ArrayContentsLocation(target)
    heap = (
        TaintHeap()
        .weak_store(field_location, TaintValue.parameter(0))
        .weak_store(array_location, TaintValue.parameter(1))
    )

    assert heap.get(field_location) == TaintValue.parameter(0)
    assert heap.get(array_location) == TaintValue.parameter(1)


def test_weak_heap_update_preserves_all_possible_dependencies() -> None:
    location = FieldLocation(AllocationSite(pc(15)), field())
    heap = (
        TaintHeap()
        .weak_store(location, TaintValue.parameter(0))
        .weak_store(location, TaintValue.parameter(1))
    )

    assert heap.get(location) == TaintValue(labels(0, 1))


def test_state_join_is_component_wise() -> None:
    location = ArrayContentsLocation(AllocationSite(pc(15)))
    left = TaintState(
        locals=(TaintValue.parameter(0), None),
        stack=(TaintValue.parameter(0),),
        heap=TaintHeap().weak_store(location, TaintValue.parameter(0)),
    )
    right = TaintState(
        locals=(TaintValue.parameter(1), TaintValue.untainted()),
        stack=(TaintValue.parameter(1),),
        heap=TaintHeap().weak_store(location, TaintValue.parameter(1)),
    )

    joined = left | right

    assert joined.locals == (TaintValue(labels(0, 1)), TaintValue.untainted())
    assert joined.stack == (TaintValue(labels(0, 1)),)
    assert joined.heap.get(location) == TaintValue(labels(0, 1))
    assert left <= joined
    assert right <= joined


def test_state_stack_and_locals_operations_are_immutable() -> None:
    initial = TaintState((TaintValue.parameter(0), None))
    stored = initial.store(1, TaintValue.parameter(1))
    pushed = stored.push(stored.load(1))
    values, popped = pushed.pop()

    assert initial.locals[1] is None
    assert values == (TaintValue.parameter(1),)
    assert popped == stored
