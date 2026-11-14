"""String Dictionary for JPAMB.

This script finds strings used in Java comparisons, such as equals(),
startsWith() and contains(), and in string concatenations. The idea is to give
the fuzzer some useful strings to try, instead of only trying random inputs.

How it works:
1. Read the compiled Java method from JPAMB.
2. Track string values through the stack, local variables and simple arrays.
3. Save every String comparison together with its kind (equals, startsWith...)
   and every concatenation that mixes constants with a non-constant part
   (for example "prefix" + input + "suffix").
4. Print the result as JSON.

Output entries:
  {"method": "startsWith", "string": "Safe", "side": "argument"}
      side tells where the constant is for asymmetric comparisons:
      "argument" for input.startsWith("Safe"), "receiver" for
      "Safe".startsWith(input). It is omitted for equals/equalsIgnoreCase.
  {"method": "concatenation",
   "strings": ["jpamb.cases.advanced.CWE470$", "Command"],
   "parts":   ["jpamb.cases.advanced.CWE470$", null, "Command"]}
      strings are the constant parts in order, parts also marks (null) where
      the non-constant, possibly tainted, value sits.

Commands (run from the jpamb folder). The optional TARGET can be a JPAMB
method ID, a method name, or the file of a class (.java, .json or .class):

  # Analyse one method (list of entries)
  uv run python solutions/syntactic/src/string_dictionary.py 'jpamb.cases.Strings.sayHello:(Ljava/lang/String;)V'

  # Analyse every method with that name (results grouped by method ID)
  uv run python solutions/syntactic/src/string_dictionary.py unsafe_dispatcher
  
  # Analyse a class using its Java file
  uv run python solutions/syntactic/src/string_dictionary.py cases/jpamb/cases/advanced/CWE470.java

  # Analyse one class by name (results grouped by method name)
  uv run python solutions/syntactic/src/string_dictionary.py --class jpamb.cases.advanced.CWE470

  # Get one list of entries from all benchmark classes
  uv run python solutions/syntactic/src/string_dictionary.py --all

  # Get entries for each method, using full method IDs
  uv run python solutions/syntactic/src/string_dictionary.py --per-method

  # Write the JSON to string-dictionary.json (or to a path of your choice)
  uv run python solutions/syntactic/src/string_dictionary.py --per-method --write-json
  uv run python solutions/syntactic/src/string_dictionary.py unsafe_dispatcher --output out/dict.json

  # Run our tests
  uv run pytest -q tests/test_string_dictionary.py

Notes:
- --all and --per-method only use classes inside jpamb.cases.
- We do not read the @Case test inputs or expected results.
- Finding a string does not mean we found a vulnerability. The fuzzer still
  needs to try inputs and check what happens.
- Put TARGET before --output, or write --output=PATH.
"""

import argparse
import json
import re
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import jpamb
import jvm


COMPARISON_METHODS = {
    "equals",
    "equalsIgnoreCase",
    "startsWith",
    "endsWith",
    "contains",
}

# For these it matters whether the constant is the receiver or the argument.
ASYMMETRIC_COMPARISONS = {"startsWith", "endsWith", "contains"}

# javac compiles "a" + x + "b" to an invokedynamic of this method.
CONCAT_METHOD = "makeConcatWithConstants"

DEFAULT_JSON_OUTPUT = "string-dictionary.json"
FILE_SUFFIXES = {".java", ".json", ".class"}


@dataclass(frozen=True)
class Value:
    """Possible string constants, arrays and unknown values."""

    strings: frozenset[str] = frozenset()
    arrays: frozenset[int] = frozenset()
    may_be_unknown: bool = False

    def join(self, other):
        return Value(
            strings=self.strings | other.strings,
            arrays=self.arrays | other.arrays,
            may_be_unknown=self.may_be_unknown or other.may_be_unknown,
        )


UNKNOWN = Value(may_be_unknown=True)


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


def bootstrap_table(class_data):
    """Static arguments of the bootstrap methods of a class, by index.

    An invokedynamic only stores the index of its bootstrap method; the recipe
    of a concatenation lives in the class.
    """
    table = {}
    for bsm in class_data.get("bootstrapmethods", []):
        table[bsm["index"]] = (bsm.get("method") or {}).get("args", [])
    return table


def _constant(arg):
    return arg.get("value") if isinstance(arg, dict) else arg


def concat_parts(instruction, args, bootstrap):
    """Ordered parts of a concatenation: constants as str, the rest as None.

    Returns None when there is nothing useful: the recipe is unknown, or the
    concatenation has no constant part or no non-constant part.
    """
    bootstrap_args = (bootstrap or {}).get(instruction.get("index"))
    if not bootstrap_args:
        return None

    # The recipe has one \u0001 for each dynamic argument and one \u0002
    # for each extra constant of the bootstrap method.
    recipe = str(_constant(bootstrap_args[0]) or "")
    extra = iter(_constant(a) for a in bootstrap_args[1:])
    dynamic = iter(args)

    parts = []

    def add(piece):
        if piece is None:
            parts.append(None)
        elif parts and isinstance(parts[-1], str):
            parts[-1] += piece  # merge adjacent constants
        else:
            parts.append(piece)

    for char in recipe:
        if char == "\u0001":
            value = next(dynamic, UNKNOWN)

            # Only use a constant if there are no unknown possibilities.
            if len(value.strings) == 1 and not value.may_be_unknown:
                add(next(iter(value.strings)))
            else:
                add(None)
        elif char == "\u0002":
            add(str(next(extra, "")))
        else:
            add(char)

    has_constant = any(isinstance(p, str) for p in parts)
    has_hole = any(p is None for p in parts)
    return tuple(parts) if has_constant and has_hole else None


def execute_instruction(bytecode, position, state, discovered, bootstrap=None):
    """Apply the supported bytecode instructions to one abstract state.

    `discovered` collects tuples:
      ("comparison", method, string, side)  with side in {None, "receiver", "argument"}
      ("concatenation", parts)
    """
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
        # Popped last-argument-first; reverse to get source order.
        args = [pop() for _ in method.get("args", [])][::-1]
        receiver = UNKNOWN
        if inst.get("access") not in {"static", "dynamic"}:
            receiver = pop()

        if is_string_comparison(inst):
            name = method["name"]
            asymmetric = name in ASYMMETRIC_COMPARISONS
            for string in receiver.strings:
                discovered.add(
                    ("comparison", name, string, "receiver" if asymmetric else None)
                )
            for argument in args:
                for string in argument.strings:
                    discovered.add(
                        ("comparison", name, string, "argument" if asymmetric else None)
                    )

        elif inst.get("access") == "dynamic" and method.get("name") == CONCAT_METHOD:
            parts = concat_parts(inst, args, bootstrap)
            if parts:
                discovered.add(("concatenation", parts))

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


def _analyse(bytecode, bootstrap=None):
    """Bounded data-flow pass; returns the set of raw discovered tuples."""
    if not bytecode:
        return set()

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
            bytecode, position, incoming[position], discovered, bootstrap
        )

        for next_position in successors(bytecode, position):
            previous = incoming.get(next_position)
            merged = (
                outgoing if previous is None else merge_states(previous, outgoing)
            )
            if previous is None or merged != previous:
                incoming[next_position] = merged
                queue.append(next_position)

    return discovered

def _entry_to_json(entry):
    if entry[0] == "comparison":
        _, method, string, side = entry
        result = {"method": method, "string": string, "strings": [string]}
        if side:
            result["side"] = side
        return result
    _, parts = entry
    return {
        "method": "concatenation",
        "strings": [p for p in parts if p is not None],
        "parts": list(parts),
    }

def extract_entries(bytecode, bootstrap=None):
    """Comparisons (with their kind) and concatenations found in a method."""
    raw = sorted(_analyse(bytecode, bootstrap), key=lambda e: (e[0], repr(e[1:])))
    return [_entry_to_json(entry) for entry in raw]


def extract_comparison_strings(bytecode):
    """Only the strings that reach a comparison (plain list, no kinds)."""
    return sorted(
        {entry[2] for entry in _analyse(bytecode) if entry[0] == "comparison"}
    )


def iter_case_classes(suite, eff, target_class=None):
    """Yield (dotted name, class data) of benchmark classes, excluding JPAMB infrastructure."""
    for class_name in suite.classes(eff=eff):
        name = class_name.dotted()
        if not name.startswith("jpamb.cases."):
            continue
        if target_class is not None and name != target_class:
            continue
        yield name, suite.findclass(class_name, eff=eff)


def iter_case_methods(suite, eff, target_class=None):
    """Yield compiled benchmark methods, excluding JPAMB infrastructure."""
    for name, class_data in iter_case_classes(suite, eff, target_class):
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


def _iter_methods(suite, eff, target_class=None):
    """Yield (class name, method, bytecode, bootstrap table)."""
    for name, class_data in iter_case_classes(suite, eff, target_class):
        bootstrap = bootstrap_table(class_data)
        for method in class_data.get("methods", []):
            bytecode = (method.get("code") or {}).get("bytecode", [])
            if bytecode:
                yield name, method, bytecode, bootstrap


def _dedupe(entries):
    seen, result = set(), []
    for entry in entries:
        key = json.dumps(entry, sort_keys=True)
        if key not in seen:
            seen.add(key)
            result.append(entry)
    return result


def extract_suite_strings(suite, eff):
    """Entries (comparisons and concatenations) from all benchmark classes."""
    entries = []
    for _, _, bytecode, bootstrap in _iter_methods(suite, eff):
        entries.extend(extract_entries(bytecode, bootstrap))
    return sorted(_dedupe(entries), key=lambda e: json.dumps(e, sort_keys=True))


def extract_class_dictionaries(suite, eff, target_class):
    dictionaries = {}
    for _, method, bytecode, bootstrap in _iter_methods(suite, eff, target_class):
        entries = extract_entries(bytecode, bootstrap)
        if entries:
            # Preserve the simple method-name output; use --per-method to
            # distinguish overloads with full descriptors.
            dictionaries[method["name"]] = entries
    return dictionaries


def extract_per_method_dictionaries(suite, eff, name_filter=None):
    """Entries by full method ID. name_filter(method_id) can restrict the methods."""
    dictionaries = {}
    for class_name, method, bytecode, bootstrap in _iter_methods(suite, eff):
        mid = method_id(class_name, method)
        if name_filter is not None and not name_filter(mid):
            continue
        entries = extract_entries(bytecode, bootstrap)
        if entries:
            dictionaries[mid] = entries
    return dict(sorted(dictionaries.items()))


def class_name_from_file(path):
    """Class name (dotted) of a .java, decompiled .json or .class file."""
    if path.suffix == ".java" and path.is_file():
        text = path.read_text(encoding="utf-8")
        match = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.MULTILINE)
        if match:
            return f"{match.group(1)}.{path.stem}"
    if path.suffix == ".json" and path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("name"), str):
            return data["name"].replace("/", ".")
    # Fallback (.class, or a file we cannot read): use the package path.
    parts = list(path.with_suffix("").parts)
    if "jpamb" in parts:
        parts = parts[parts.index("jpamb"):]
    return ".".join(parts)


def analyse_target(suite, eff, target):
    """Method ID -> list of entries; class file -> dict by method name;
    method name -> dict by method ID."""
    if ":(" in target:
        methodid = jvm.AbsMethodID.decode(target)
        method = suite.findmethod(methodid, eff=eff)
        class_data = suite.findclass(methodid.classname, eff=eff)
        return extract_entries(
            method["code"]["bytecode"], bootstrap_table(class_data)
        )

    path = Path(target)
    if path.suffix in FILE_SUFFIXES or path.is_file():
        return extract_class_dictionaries(suite, eff, class_name_from_file(path))

    # Method name, optionally qualified (Class.name or package.Class.name).
    def matches(mid):
        head = mid.split(":(", 1)[0]
        return head == target or head.endswith("." + target)

    return extract_per_method_dictionaries(suite, eff, matches)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument(
        "target",
        nargs="?",
        help="JPAMB METHOD_ID, method name, or class file (.java, .json, .class)",
    )
    choice.add_argument("--class", dest="class_name", metavar="CLASS")
    choice.add_argument("--all", action="store_true")
    choice.add_argument("--per-method", action="store_true")
    parser.add_argument(
        "--output", type=Path, help="Write the JSON to this file instead of stdout"
    )
    parser.add_argument(
        "--write-json",
        action="store_true",
        help=f"Write the JSON to a file (default {DEFAULT_JSON_OUTPUT}, "
        "or the path given with --output)",
    )
    args = parser.parse_args(argv)

    if args.write_json and args.output is None:
        args.output = Path(DEFAULT_JSON_OUTPUT)

    suite, eff = jpamb.setup()
    if args.all:
        dictionary = extract_suite_strings(suite, eff)
    elif args.per_method:
        dictionary = extract_per_method_dictionaries(suite, eff)
    elif args.class_name:
        dictionary = extract_class_dictionaries(suite, eff, args.class_name)
    else:
        dictionary = analyse_target(suite, eff, args.target)

    text = json.dumps(dictionary, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
        print(f"string_dictionary: wrote {args.output}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
