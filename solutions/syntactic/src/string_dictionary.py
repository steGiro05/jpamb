
import json
import sys

import jpamb
import jvm


COMPARISON_METHODS = {
    "equals",
    "equalsIgnoreCase",
    "startsWith",
    "endsWith",
    "contains",
}


def is_string_literal(instruction):
    """Check if an instruction pushes a string constant."""
    value = instruction.get("value")

    return (
        instruction.get("opr") == "push"
        and isinstance(value, dict)
        and value.get("type") == "string"
    )


def extract_strings(bytecode):
    """Extract all string literals from a method."""
    strings = set()

    for instruction in bytecode:
        if is_string_literal(instruction):
            strings.add(instruction["value"]["value"])

    return sorted(strings)


def is_string_comparison(instruction):
    """Check if an instruction calls a String comparison method."""
    if instruction.get("opr") != "invoke":
        return False

    method = instruction.get("method", {})
    reference = method.get("ref") or {}

    return (
        reference.get("name") == "java/lang/String"
        and method.get("name") in COMPARISON_METHODS
    )


def extract_comparison_strings(bytecode):
    """Find string literals near String comparison calls."""
    strings = set()

    for i, instruction in enumerate(bytecode):
        if not is_string_comparison(instruction):
            continue

        # Check the instruction immediately before the call.
        if i >= 1 and is_string_literal(bytecode[i - 1]):
            strings.add(bytecode[i - 1]["value"]["value"])

        # Also handle a literal followed by a variable load.
        if (
            i >= 2
            and is_string_literal(bytecode[i - 2])
            and bytecode[i - 1].get("opr") == "load"
        ):
            strings.add(bytecode[i - 2]["value"]["value"])

    return sorted(strings)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: string_dictionary.py METHOD_ID")

    method_id = jvm.AbsMethodID.decode(sys.argv[1])

    suite, eff = jpamb.setup()
    method = suite.findmethod(method_id, eff=eff)

    bytecode = method["code"]["bytecode"]

    dictionary = extract_comparison_strings(bytecode)

    print(json.dumps(dictionary, indent=2))


if __name__ == "__main__":
    main()
