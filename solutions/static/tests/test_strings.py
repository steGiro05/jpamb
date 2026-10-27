"""Tests for the string support of the static analysis."""

from pathlib import Path

import jpamb
import jvm
import static
from static import AbstractInterpreter, AbstractReference

# Run from any folder: the suite lives three folders above this file
suite = jpamb.Suite.from_workdir(Path(__file__).resolve().parents[3])
bc = jpamb.Bytecode(suite, jpamb.Effect(None), {})

SAY_HELLO = "jpamb.cases.Strings.sayHello:(Ljava/lang/String;)V"
UNSAFE = "jpamb.cases.Vulnerable.unsafe_dispatcher:(Ljava/lang/String;)V"


def analyse(method: str, inputs=None):
    """Run the analysis until the fixpoint, or until an unsupported opcode."""
    ai = AbstractInterpreter.initial(bc, jvm.AbsMethodID.decode(method), inputs)
    finals = set()
    try:
        while ai.worklist:
            finals |= ai.step()[1]
    except NotImplementedError:
        pass
    return ai, finals


def test_say_hello():
    # equals can be true or false, so both outcomes are possible
    ai, finals = analyse(SAY_HELLO)
    assert not ai.worklist
    assert finals == {"assertion error", "ok"}


def test_say_hello_with_string_input():
    ai, finals = analyse(SAY_HELLO, jpamb.Input((jpamb.case.String("hello"),)))
    assert finals == {"assertion error", "ok"}


def test_concat_pushes_reference():
    # The analysis stops at Class.forName; the concatenated name is on the stack
    methodid = jvm.AbsMethodID.decode(UNSAFE)
    ai, _ = analyse(UNSAFE)
    offset = next(
        i
        for i, op in enumerate(bc.getmethod(methodid).opcodes)
        if isinstance(op, jvm.InvokeStatic) and op.method.extension.name == "forName"
    )
    top = ai.states[static.PC(methodid, offset)].stack[-1]
    assert isinstance(top.inner_value, AbstractReference)