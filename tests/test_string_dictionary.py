"""Tests for the JPAMB string dictionary (comparisons and concatenations)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from solutions.syntactic.src.string_dictionary import (
    State,
    Value,
    UNKNOWN,
    merge_states,
    concat_parts,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "solutions/syntactic/src/string_dictionary.py"
CWE470 = "jpamb.cases.advanced.CWE470"
CWE502 = "jpamb.cases.advanced.CWE502"
STRING_ARG = ":(Ljava/lang/String;)V"


# Expected concatenation in CWE470: "...CWE470$" + ctl + "Command".
REFLECTION_CONCAT = {
    "method": "concatenation",
    "strings": ["jpamb.cases.advanced.CWE470$", "Command"],
    "parts": ["jpamb.cases.advanced.CWE470$", None, "Command"],
}


def run_cli(*args):
    """Run the real script, as the fuzzer does."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *map(str, args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )


def run_dictionary(*args):
    return json.loads(run_cli(*args).stdout)


def method_id(class_name, method):
    return f"{class_name}.{method}{STRING_ARG}"


@pytest.mark.parametrize(
    "method,expected",
    [
        ("sayHello", {"method": "equals", "string": "hello"}),
        ("sayHello2", {"method": "startsWith", "string": "good", "side": "argument"}),
        ("sayHello2", {"method": "contains", "string": "morning", "side": "argument"}),
        ("sayHello3", {"method": "endsWith", "string": "night", "side": "argument"}),
        ("checkExtension", {"method": "endsWith", "string": ".pdf", "side": "argument"}),
        ("checkComplexSequence", {"method": "contains", "string": "B", "side": "argument"}),
    ],
)
def test_string_comparisons(method, expected):
    result = run_dictionary(method_id("jpamb.cases.Strings", method))
    assert expected in result


def test_unsafe_dispatcher_concatenation():
    # This method has no String comparison, but still needs a dictionary entry.
    result = run_dictionary(method_id(CWE470, "unsafe_dispatcher"))
    assert result == [REFLECTION_CONCAT]


def test_weak_dispatcher():
    result = run_dictionary(method_id(CWE470, "weak_dispatcher"))
    assert {"method": "startsWith", "string": "Safe", "side": "argument"} in result
    assert REFLECTION_CONCAT in result


def test_strict_safe_dispatcher():
    result = run_dictionary(method_id(CWE470, "strict_safe_dispatcher"))
    assert {"method": "equals", "string": "Safe"} in result
    assert REFLECTION_CONCAT in result


@pytest.mark.parametrize(
    "method,expected",
    [
        ("simulateResolveClassName", {"method": "equals", "string": "SER"}),
        ("simulateReadObject", {"method": "equals", "string": "DummyButton"}),
        ("blacklist_deserialization", {"method": "contains", "string": "__CANARY__Command", "side": "argument"}),
        ("blacklist_deserialization", {"method": "contains", "string": "SafeWrapperCommand", "side": "argument"}),
        ("whitelist_deserialization", {"method": "equals", "string": "DownGradableLibrary"}),
    ],
)
def test_deserialization_strings(method, expected):
    result = run_dictionary(method_id(CWE502, method))
    assert expected in result


def test_method_without_comparisons_or_concatenations():
    result = run_dictionary(f"{CWE470}.canary:()V")
    assert result == []


def test_class_dictionary():
    result = run_dictionary("--class", CWE470)
    assert REFLECTION_CONCAT in result["unsafe_dispatcher"]
    assert {"method": "startsWith", "string": "Safe", "side": "argument"} in result["weak_dispatcher"]
    assert {"method": "equals", "string": "Safe"} in result["strict_safe_dispatcher"]


def test_class_dictionary_cwe502():
    result = run_dictionary("--class", CWE502)
    assert {"method": "equals", "string": "SER"} in result["simulateResolveClassName"]
    assert {"method": "equals", "string": "DownGradableLibrary"} in result["whitelist_deserialization"]


def test_class_from_source_file():
    source = "cases/jpamb/cases/advanced/CWE470.java"
    assert run_dictionary(source) == run_dictionary("--class", CWE470)


def test_method_name_lookup():
    result = run_dictionary("unsafe_dispatcher")
    assert result[method_id(CWE470, "unsafe_dispatcher")] == [REFLECTION_CONCAT]


def test_full_method_ids_for_fuzzer():
    result = run_dictionary("--per-method")
    assert REFLECTION_CONCAT in result[method_id(CWE470, "unsafe_dispatcher")]
    assert {"method": "equals", "string": "hello"} in result[
        method_id("jpamb.cases.Strings", "sayHello")
    ]
    assert {"method": "equals", "string": "DownGradableLibrary"} in result[
        method_id(CWE502, "whitelist_deserialization")
    ]


def test_entire_suite():
    entries = run_dictionary("--all")
    assert entries
    assert all(isinstance(entry, dict) and "method" in entry for entry in entries)

    strings = {
        entry["string"] for entry in entries if "string" in entry
    }
    assert {"hello", "Safe", "SER", "DummyButton", "DownGradableLibrary"} <= strings
    assert REFLECTION_CONCAT in entries

    # The same entry should not be reported twice in the suite-wide output.
    serialized = [json.dumps(entry, sort_keys=True) for entry in entries]
    assert len(serialized) == len(set(serialized))
    assert serialized == sorted(serialized)


def test_write_json(tmp_path):
    output = tmp_path / "dictionary.json"
    run_cli("--per-method", "--write-json", "--output", output)

    assert output.is_file()
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved == run_dictionary("--per-method")

@pytest.mark.parametrize("reverse", [False, True])
def test_merge_states_keeps_unknown_branch(reverse):
    # One path has a known string, the other has an unknown value.
    known = State(
        locals={0: Value(strings=frozenset({"Safe"}))}
    )
    unknown = State(
        locals={0: UNKNOWN}
    )

    # Merging should work the same way in both orders.
    if reverse:
        merged = merge_states(unknown, known)
    else:
        merged = merge_states(known, unknown)

    value = merged.locals[0]

    # We still know that "Safe" is one possible value.
    assert value.strings == frozenset({"Safe"})

    # But the value could also be something unknown.
    assert value.may_be_unknown is True

    # The concatenation should keep the variable part.
    instruction = {"index": 0}
    bootstrap = {0: [{"value": "pre-\u0001-post"}]}

    parts = concat_parts(instruction, [value], bootstrap)

    assert parts == ("pre-", None, "-post")


def test_merge_states_two_known_strings():
    # Both paths have known strings.
    first = State(
        locals={0: Value(strings=frozenset({"Safe"}))}
    )
    second = State(
        locals={0: Value(strings=frozenset({"Other"}))}
    )

    merged = merge_states(first, second)
    value = merged.locals[0]

    # Both known values should be kept.
    assert value.strings == frozenset({"Safe", "Other"})

    # No unknown value was introduced.
    assert value.may_be_unknown is False