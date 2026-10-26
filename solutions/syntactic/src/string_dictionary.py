"""String Dictionary for JPAMB.

This script finds strings used in Java comparisons, such as equals(),
startsWith() and contains(). The idea is to give the fuzzer some useful
strings to try, instead of only trying random inputs.

How it works:
1. Read the compiled Java method from JPAMB.
2. Track string values through the stack, local variables and simple arrays.
3. Save the strings that reach a String comparison.
4. Print the result as JSON.

Commands (run from the jpamb folder):

  # Analyse one method
  uv run python solutions/syntactic/src/string_dictionary.py 'jpamb.cases.Strings.sayHello:(Ljava/lang/String;)V'

  # Analyse one class (results grouped by method name)
  uv run python solutions/syntactic/src/string_dictionary.py --class jpamb.cases.Vulnerable

  # Get one list of strings from all benchmark classes
  uv run python solutions/syntactic/src/string_dictionary.py --all

  # Get strings for each method, using full method IDs
  uv run python solutions/syntactic/src/string_dictionary.py --per-method

  # Save the per-method dictionary to a file for the fuzzer
  uv run python solutions/syntactic/src/string_dictionary.py --per-method > string-dictionary.json

  # Run our tests
  uv run pytest -q tests/test_string_dictionary.py

Notes:
- --all and --per-method only use classes inside jpamb.cases.
- We do not read the @Case test inputs or expected results.
- Finding a string does not mean we found a vulnerability. The fuzzer still
  needs to try inputs and check what happens.
"""

import argparse
import json
from collections import deque
from dataclasses import dataclass, field

import jpamb
import jvm


COMPARISON_METHODS = {
    "equals",
    "equalsIgnoreCase",
    "startsWith",
    "endsWith",
    "contains",
}


@dataclass(frozen=True)
class Value:
    """Possible string constants and array identities held by one value."""

    strings: frozenset[str] = frozenset()
    arrays: frozenset[int] = frozenset()

    def join(self, other):
        return Value(self.strings | other.strings, self.arrays | other.arrays)


UNKNOWN = Value()


@dataclass
class State:
    stack: tuple[Value, ...] = ()
    locals: dict[int, Value] = field(default_factory=dict)
    arrays: dict[int, frozenset[str]] = field(default_factory=dict)


def merge_states(old, new):
    """Conservatively combine possible states from different paths."""
    if len(old.stack) == len(new.stack):
        stack = tuple(a.join(b) for a, b in zip(old.stack, new.stack))
    else:
        # Stack shapes differ: do not guess which values align.
        stack = ()

    local_keys = old.locals.keys() | new.locals.keys()
    locals_ = {
        key: old.locals.get(key, UNKNOWN).join(new.locals.get(key, UNKNOWN))
        for key in local_keys
    }

    array_keys = old.arrays.keys() | new.arrays.keys()
    arrays = {
        key: old.arrays.get(key, frozenset())
        | new.arrays.get(key, frozenset())
        for key in array_keys
    }
    return State(stack, locals_, arrays)


def is_string_comparison(instruction):
    if instruction.get("opr") != "invoke":
        return False

    method = instruction.get("method") or {}
    reference = method.get("ref") or {}
    return (
        reference.get("name") == "java/lang/String"
        and method.get("name") in COMPARISON_METHODS
    )


def execute_instruction(bytecode, position, state, discovered):
    """Apply the supported bytecode instructions to one abstract state."""
    inst = bytecode[position]
    op = inst.get("opr")
    stack = list(state.stack)
    locals_ = state.locals.copy()
    arrays = state.arrays.copy()

    def pop():
        return stack.pop() if stack else UNKNOWN

    if op == "push":
        literal = inst.get("value") or {}
        if literal.get("type") == "string":
            stack.append(Value(strings=frozenset({literal["value"]})))
        else:
            stack.append(UNKNOWN)

    elif op == "load":
        stack.append(locals_.get(inst["index"], UNKNOWN))

    elif op == "store":
        locals_[inst["index"]] = pop()

    elif op == "incr":
        locals_[inst["index"]] = UNKNOWN

    elif op == "newarray":
        pop()  # Length
        array_id = position  # Unique allocation site within this method
        arrays.setdefault(array_id, frozenset())
        stack.append(Value(arrays=frozenset({array_id})))

    elif op == "dup":
        if stack:
            stack.append(stack[-1])

    elif op == "array_store":
        value = pop()
        pop()  # Index
        array = pop()
        for array_id in array.arrays:
            arrays[array_id] = arrays.get(array_id, frozenset()) | value.strings

    elif op == "array_load":
        pop()  # Index
        array = pop()
        possible = frozenset().union(
            *(arrays.get(array_id, frozenset()) for array_id in array.arrays)
        )
        stack.append(Value(strings=possible))

    elif op == "arraylength":
        pop()
        stack.append(UNKNOWN)

    elif op == "invoke":
        method = inst.get("method") or {}
        args = [pop() for _ in method.get("args", [])]
        receiver = UNKNOWN
        if inst.get("access") not in {"static", "dynamic"}:
            receiver = pop()

        if is_string_comparison(inst):
            discovered.update(receiver.strings)
            for argument in args:
                discovered.update(argument.strings)

        if method.get("returns") is not None:
            stack.append(UNKNOWN)

    elif op == "get":
        if not inst.get("static"):
            pop()
        stack.append(UNKNOWN)

    elif op == "put":
        pop()
        if not inst.get("static"):
            pop()

    elif op in {"checkcast", "nop", "goto", "return"}:
        pass

    elif op in {"ifz", "throw", "pop", "monitorenter", "monitorexit"}:
        pop()

    elif op == "if":
        pop()
        pop()

    elif op in {"binary", "compare"}:
        pop()
        pop()
        stack.append(UNKNOWN)

    elif op in {"unary", "cast", "instanceof"}:
        pop()
        stack.append(UNKNOWN)

    elif op == "new":
        stack.append(UNKNOWN)

    else:
        # Unsupported opcode: forget stack values to avoid false provenance.
        stack.clear()

    return State(tuple(stack), locals_, arrays)


def successors(bytecode, position):
    """Return possible next instruction indexes, including branch targets."""
    inst = bytecode[position]
    op = inst.get("opr")
    n = len(bytecode)

    if op in {"return", "throw"}:
        return []

    if op == "goto":
        destinations = [inst.get("target")]
    elif op in {"if", "ifz"}:
        destinations = [position + 1, inst.get("target")]
    else:
        destinations = [position + 1]

    return [p for p in destinations if isinstance(p, int) and 0 <= p < n]


def extract_comparison_strings(bytecode):
    """Collect possible comparison strings using a bounded data-flow pass."""
    if not bytecode:
        return []

    discovered = set()
    incoming = {0: State()}
    queue = deque([0])
    iterations = 0
    limit = max(1000, len(bytecode) * 100)

    while queue:
        position = queue.popleft()
        iterations += 1
        if iterations > limit:
            raise RuntimeError("Data-flow analysis did not converge")

        outgoing = execute_instruction(
            bytecode, position, incoming[position], discovered
        )

        for next_position in successors(bytecode, position):
            previous = incoming.get(next_position)
            merged = (
                outgoing if previous is None else merge_states(previous, outgoing)
            )
            if previous is None or merged != previous:
                incoming[next_position] = merged
                queue.append(next_position)

    return sorted(discovered)


def iter_case_methods(suite, eff, target_class=None):
    """Yield compiled benchmark methods, excluding JPAMB infrastructure."""
    for class_name in suite.classes(eff=eff):
        name = class_name.dotted()
        if not name.startswith("jpamb.cases."):
            continue
        if target_class is not None and name != target_class:
            continue

        class_data = suite.findclass(class_name, eff=eff)
        for method in class_data.get("methods", []):
            bytecode = (method.get("code") or {}).get("bytecode", [])
            if bytecode:
                yield name, method, bytecode


def type_descriptor(type_):
    """Convert a JPAMB decompiled type into a JVM type descriptor."""
    if type_ is None:
        return "V"
    if isinstance(type_, str):
        return {"boolean": "Z", "byte": "B", "char": "C",
                "double": "D", "float": "F", "int": "I",
                "long": "J", "short": "S", "void": "V"}.get(type_, type_)
    if type_.get("kind") == "array":
        return "[" + type_descriptor(type_["type"])
    if type_.get("kind") == "class":
        return "L" + type_["name"] + ";"
    if "base" in type_:
        return type_descriptor(type_["base"])
    raise ValueError(f"Unsupported JVM type: {type_}")


def method_id(class_name, method):
    """Generate an unambiguous JPAMB method ID (including parameter types)."""
    params = "".join(type_descriptor(p["type"]) for p in method["params"])
    returns = type_descriptor(method["returns"]["type"])
    return f"{class_name}.{method['name']}:({params}){returns}"


def extract_suite_strings(suite, eff):
    strings = set()
    for _, _, bytecode in iter_case_methods(suite, eff):
        strings.update(extract_comparison_strings(bytecode))
    return sorted(strings)


def extract_class_dictionaries(suite, eff, target_class):
    dictionaries = {}
    for class_name, method, bytecode in iter_case_methods(suite, eff, target_class):
        strings = extract_comparison_strings(bytecode)
        if strings:
            # Preserve the simple method-name output; use --per-method to
            # distinguish overloads with full descriptors.
            dictionaries[method["name"]] = strings
    return dictionaries


def extract_per_method_dictionaries(suite, eff):
    dictionaries = {}
    for class_name, method, bytecode in iter_case_methods(suite, eff):
        strings = extract_comparison_strings(bytecode)
        if strings:
            dictionaries[method_id(class_name, method)] = strings
    return dict(sorted(dictionaries.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("method", nargs="?", help="JPAMB METHOD_ID")
    choice.add_argument("--class", dest="class_name", metavar="CLASS")
    choice.add_argument("--all", action="store_true")
    choice.add_argument("--per-method", action="store_true")
    args = parser.parse_args()

    suite, eff = jpamb.setup()
    if args.all:
        dictionary = extract_suite_strings(suite, eff)
    elif args.per_method:
        dictionary = extract_per_method_dictionaries(suite, eff)
    elif args.class_name:
        dictionary = extract_class_dictionaries(suite, eff, args.class_name)
    else:
        method = suite.findmethod(jvm.AbsMethodID.decode(args.method), eff=eff)
        dictionary = extract_comparison_strings(method["code"]["bytecode"])

    print(json.dumps(dictionary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
