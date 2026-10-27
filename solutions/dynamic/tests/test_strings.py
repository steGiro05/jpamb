"""Tests for the string support of the dynamic interpreter."""

from pathlib import Path

import pytest

import dynamic
import jpamb
import jvm

# Run from any folder: the suite lives three folders above this file
suite = jpamb.Suite.from_workdir(Path(__file__).resolve().parents[3])
bc = jpamb.Bytecode(suite, jpamb.Effect(None), {})


def run(method: str, value: str, steps: int):
    """Start a method with one string argument and run a few steps."""
    methodid = jvm.AbsMethodID.decode(method)
    state = dynamic.initial(bc, methodid, jpamb.Input((jpamb.case.String(value),)))
    for _ in range(steps):
        _, state = dynamic.step(bc, state)
    return state


@pytest.mark.parametrize(
    "value, expected",
    [
        ("Safe", "jpamb.cases.Vulnerable$SafeCommand"),
        ("__CANARY__", "jpamb.cases.Vulnerable$__CANARY__Command"),
        ("", "jpamb.cases.Vulnerable$Command"),
        # The placeholder in the input must not be replaced again
        ("a\u0001b", "jpamb.cases.Vulnerable$a\u0001bCommand"),
    ],
)
def test_concat_with_constants(value, expected):
    # Step 1: load ctl; step 2: invokedynamic makeConcatWithConstants
    state = run(
        "jpamb.cases.Vulnerable.unsafe_dispatcher:(Ljava/lang/String;)V", value, 2
    )
    ref = state.frames.peek().stack.pop()
    assert state.heap[ref].content == expected

WEAK = "jpamb.cases.Vulnerable.weak_dispatcher:(Ljava/lang/String;)V"
STRICT = "jpamb.cases.Vulnerable.strict_safe_dispatcher:(Ljava/lang/String;)V"


@pytest.mark.parametrize(
    "value, expected", [("Safe", 1), ("SafeWrapper", 1), ("Unsafe", 0), ("", 0)]
)
def test_starts_with(value, expected):
    # load ctl; push "Safe"; invokevirtual startsWith
    state = run(WEAK, value, 3)
    assert state.frames.peek().stack.pop().value == expected


@pytest.mark.parametrize("value, expected", [("Safe", 1), ("SafeWrapper", 0), ("safe", 0)])
def test_equals(value, expected):
    # push "Safe"; load ctl; invokevirtual equals
    state = run(STRICT, value, 3)
    assert state.frames.peek().stack.pop().value == expected


def test_null_receiver_is_null_pointer():
    methodid = jvm.AbsMethodID.decode(WEAK)
    state = dynamic.initial(bc, methodid, jpamb.Input((jpamb.case.String(""),)))
    state.frames.peek().locals[0] = dynamic.jvmc.StackReference(0)
    for _ in range(3):
        _, state = dynamic.step(bc, state)
    assert state == "null pointer"


def test_null_argument_to_equals_is_false():
    # "Safe".equals(null) is false, it does not throw
    methodid = jvm.AbsMethodID.decode(STRICT)
    state = dynamic.initial(bc, methodid, jpamb.Input((jpamb.case.String(""),)))
    state.frames.peek().locals[0] = dynamic.jvmc.StackReference(0)
    for _ in range(3):
        _, state = dynamic.step(bc, state)
    assert state.frames.peek().stack.pop().value == 0


@pytest.mark.parametrize(
    "string, regex, limit, expected",
    [
        # Results checked against Java's String.split
        ("SER|DummyButton|", r"\|", -1, ["SER", "DummyButton", ""]),
        ("SER|DummyButton|", r"\|", 0, ["SER", "DummyButton"]),
        ("SER|DownGradableLibrary|1", r"\|", -1, ["SER", "DownGradableLibrary", "1"]),
        ("a|b|c", r"\|", 2, ["a", "b|c"]),
        ("a|b|c", r"\|", 1, ["a|b|c"]),
        ("", r"\|", 0, [""]),
        ("|", r"\|", 0, []),
        ("no separator", r"\|", -1, ["no separator"]),
    ],
)
def test_split(string, regex, limit, expected):
    assert dynamic.string_split(string, regex, limit) == expected


@pytest.mark.parametrize(
    "name, args, expected",
    [
        ("contains", ["__CANARY__Command", "CANARY"], True),
        ("contains", ["UpdatedLibrary", "__CANARY__Command"], False),
        ("endsWith", ["SafeCommand", "Command"], True),
        ("equalsIgnoreCase", ["SAFE", "safe"], True),
        ("equalsIgnoreCase", ["SAFE", None], False),
        ("isEmpty", [""], True),
        ("isEmpty", ["x"], False),
        ("length", ["Safe"], 4),
        ("charAt", ["Safe", 0], ord("S")),
    ],
)
def test_string_methods(name, args, expected):
    assert dynamic.STRING_METHODS[name](*args) == expected


@pytest.mark.parametrize("index", [-1, 4])
def test_char_at_out_of_bounds(index):
    with pytest.raises(IndexError):
        dynamic.string_char_at("Safe", index)

BLACKLIST = "jpamb.cases.Vulnerable.blacklist_deserialization:(Ljava/lang/String;)V"


def test_array_load_of_strings_pushes_reference():
    # Start at the aaload of blacklist_deserialization, with a String[] ready
    methodid = jvm.AbsMethodID.decode(BLACKLIST)
    offset = next(
        i
        for i, op in enumerate(bc.getmethod(methodid).opcodes)
        if isinstance(op, jvm.ArrayLoad) and isinstance(op.type, jvm.Reference)
    )
    state = dynamic.initial(bc, methodid, jpamb.Input((jpamb.case.String(""),)))
    frame = state.frames.peek()
    frame.pc = dynamic.jvmc.PC(methodid, offset)

    first = state.heap.new(dynamic.jvmc.HeapString("__CANARY__Command"))
    second = state.heap.new(dynamic.jvmc.HeapString("SafeWrapperCommand"))
    string = jvm.Object(jvm.ClassName("java.lang.String"))
    array = state.heap.new(dynamic.jvmc.HeapArray(string, [first.value, second.value]))
    frame.stack.push(array)
    frame.stack.push(dynamic.jvmc.StackInt(1))

    _, state = dynamic.step(bc, state)

    loaded = state.frames.peek().stack.pop()
    assert isinstance(loaded, dynamic.jvmc.StackReference)
    assert state.heap[loaded].content == "SafeWrapperCommand"

@pytest.mark.parametrize(
    "string, expected",
    [
        # Results checked against Java's Integer.parseInt
        ("1", 1),
        ("-0", 0),
        ("+5", 5),
        ("007", 7),
        ("2147483647", 2147483647),
        ("-2147483648", -2147483648),
    ],
)
def test_parse_int(string, expected):
    assert dynamic.integer_parse_int(string) == expected


@pytest.mark.parametrize(
    "string",
    ["", " 1", "1 ", "1_0", "+", "-", "0x10", "2147483648", "-2147483649", "\u0661", None],
)
def test_parse_int_number_format_exception(string):
    with pytest.raises(ValueError):
        dynamic.integer_parse_int(string)


READ_OBJECT = "jpamb.cases.Vulnerable.simulateReadObject:(Ljava/lang/String;)Ljava/lang/Object;"


def test_invoke_parse_int():
    # Start at the invokestatic Integer.parseInt of simulateReadObject
    methodid = jvm.AbsMethodID.decode(READ_OBJECT)
    offset = next(
        i
        for i, op in enumerate(bc.getmethod(methodid).opcodes)
        if isinstance(op, jvm.InvokeStatic) and op.method.extension.name == "parseInt"
    )
    state = dynamic.initial(bc, methodid, jpamb.Input((jpamb.case.String(""),)))
    frame = state.frames.peek()
    frame.pc = dynamic.jvmc.PC(methodid, offset)
    frame.stack.push(state.heap.new(dynamic.jvmc.HeapString("1")))

    _, state = dynamic.step(bc, state)

    assert state.frames.peek().stack.pop() == dynamic.jvmc.StackInt(1)