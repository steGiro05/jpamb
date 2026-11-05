from taint_analysis import (
    AllocationSite,
    ArrayContentsLocation,
    FieldLocation,
    StaticFieldLocation,
    TaintState,
    TaintValue,
    transfer_heap,
)

import jvm
from jvm.state import PC


METHOD_ID = jvm.AbsMethodID.decode("jpamb.cases.Example.run:()V")


def pc(offset: int = 0) -> PC:
    return PC(METHOD_ID, offset)


def field(name: str = "value", type_code: str = "I") -> jvm.AbsFieldID:
    return jvm.AbsFieldID.decode(f"jpamb.cases.Example.{name}:{type_code}")


def test_put_opcode_can_be_loaded_from_jvm_json() -> None:
    instruction = jvm.Opcode.from_json(
        {
            "opr": "put",
            "offset": 4,
            "static": False,
            "field": {
                "class": "jpamb/cases/Example",
                "name": "value",
                "type": "int",
            },
        }
    )

    assert instruction == jvm.Put(offset=4, static=False, field=field())


def test_new_pushes_an_untainted_allocation_site_reference() -> None:
    state = TaintState(locals=())
    instruction = jvm.New(offset=3, classname=jvm.ClassName("jpamb.cases.Example"))

    result = transfer_heap(pc(3), instruction, state)

    assert result.stack == (TaintValue.reference([AllocationSite(pc(3))]),)


def test_new_array_depends_on_its_size_and_initializes_contents() -> None:
    state = TaintState(locals=(), stack=(TaintValue.parameter(0),))
    instruction = jvm.NewArray(offset=5, type=jvm.Int(), dim=1)

    result = transfer_heap(pc(5), instruction, state)

    reference = TaintValue.reference(
        [AllocationSite(pc(5))], TaintValue.parameter(0).labels
    )
    assert result.stack == (reference,)
    assert result.heap.get(ArrayContentsLocation(AllocationSite(pc(5)))) == (
        TaintValue.untainted()
    )


def test_array_store_and_load_combine_value_reference_and_index_labels() -> None:
    target = AllocationSite(pc(5))
    reference = TaintValue.reference([target], TaintValue.parameter(0).labels)
    state = TaintState(
        locals=(),
        stack=(reference, TaintValue.parameter(1), TaintValue.parameter(2)),
    )

    stored = transfer_heap(
        pc(6), jvm.ArrayStore(offset=6, type=jvm.Int()), state
    )
    loaded = transfer_heap(
        pc(7),
        jvm.ArrayLoad(offset=7, type=jvm.Int()),
        stored.push(reference).push(TaintValue.parameter(1)),
    )

    expected_labels = (
        TaintValue.parameter(0).labels
        | TaintValue.parameter(1).labels
        | TaintValue.parameter(2).labels
    )
    assert stored.heap.get(ArrayContentsLocation(target)) == TaintValue(
        labels=expected_labels
    )
    assert loaded.stack == (TaintValue(labels=expected_labels),)


def test_array_length_depends_on_the_array_reference() -> None:
    reference = TaintValue.external_reference(0)
    state = TaintState(locals=(), stack=(reference,))

    result = transfer_heap(pc(), jvm.ArrayLength(offset=0), state)

    assert result.stack == (TaintValue.parameter(0),)


def test_instance_field_store_and_load_use_the_same_heap_cell() -> None:
    target = AllocationSite(pc(3))
    reference = TaintValue.reference([target])
    value = TaintValue.parameter(0)
    field_id = field()
    state = TaintState(locals=(), stack=(reference, value))

    stored = transfer_heap(
        pc(4), jvm.Put(offset=4, static=False, field=field_id), state
    )
    loaded = transfer_heap(
        pc(5),
        jvm.Get(offset=5, static=False, field=field_id),
        stored.push(reference),
    )

    assert stored.heap.get(FieldLocation(target, field_id)) == value
    assert loaded.stack == (value,)


def test_static_field_store_and_load_use_a_static_cell() -> None:
    field_id = field("shared")
    value = TaintValue.parameter(0)
    state = TaintState(locals=(), stack=(value,))

    stored = transfer_heap(
        pc(), jvm.Put(offset=0, static=True, field=field_id), state
    )
    loaded = transfer_heap(
        pc(1), jvm.Get(offset=1, static=True, field=field_id), stored
    )

    assert stored.heap.get(StaticFieldLocation(field_id)) == value
    assert loaded.stack == (value,)
