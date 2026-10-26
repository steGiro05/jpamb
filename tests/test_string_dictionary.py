"""Integration tests for the JPAMB String Dictionary CLI."""

import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "solutions/syntactic/src/string_dictionary.py"


def run_dictionary(*arguments):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize(
    "method_id, expected",
    [
        (
            "jpamb.cases.Strings.sayHello:(Ljava/lang/String;)V",
            ["hello"],
        ),
        (
            "jpamb.cases.Vulnerable.weak_dispatcher:(Ljava/lang/String;)V",
            ["Safe"],
        ),
        (
            "jpamb.cases.Vulnerable.strict_safe_dispatcher:(Ljava/lang/String;)V",
            ["Safe"],
        ),
        (
            "jpamb.cases.Vulnerable.blacklist_deserialization:(Ljava/lang/String;)V",
            ["SafeWrapperCommand", "__CANARY__Command"],
        ),
        (
            "jpamb.cases.Vulnerable.whitelist_deserialization:(Ljava/lang/String;)V",
            ["DownGradableLibrary"],
        ),
    ],
)
def test_individual_methods(method_id, expected):
    assert run_dictionary(method_id) == expected


def test_entire_suite():
    dictionary = run_dictionary("--all")

    for item in [
        "hello", "Safe", "SER", "DummyButton",
        "SafeWrapperCommand", "DownGradableLibrary",
    ]:
        assert item in dictionary

    assert "Suspicious input detected." not in dictionary
    assert ")" not in dictionary
    assert "ok" not in dictionary
    assert "out of bounds" not in dictionary
    assert dictionary == sorted(set(dictionary))


def test_vulnerable_class_dictionary():
    result = run_dictionary("--class", "jpamb.cases.Vulnerable")
    assert result["weak_dispatcher"] == ["Safe"]
    assert result["strict_safe_dispatcher"] == ["Safe"]
    assert result["simulateResolveClassName"] == ["SER"]
    assert "DummyButton" in result["simulateReadObject"]
    assert result["blacklist_deserialization"] == [
        "SafeWrapperCommand", "__CANARY__Command"
    ]
    assert result["whitelist_deserialization"] == ["DownGradableLibrary"]


def test_full_method_ids_for_fuzzer():
    result = run_dictionary("--per-method")

    assert result[
        "jpamb.cases.Vulnerable.weak_dispatcher:(Ljava/lang/String;)V"
    ] == ["Safe"]

    assert result[
        "jpamb.cases.Vulnerable.blacklist_deserialization:(Ljava/lang/String;)V"
    ] == ["SafeWrapperCommand", "__CANARY__Command"]

    assert result[
        "jpamb.cases.Strings.sayHello:(Ljava/lang/String;)V"
    ] == ["hello"]
