
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "solutions/syntactic/src/string_dictionary.py"


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
    ],
)
def test_string_dictionary(method_id, expected):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), method_id],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    dictionary = json.loads(result.stdout)

    assert dictionary == expected
