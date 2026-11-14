"""End-to-end check: the generated tests must reproduce the JVM's own outcomes."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import synthesis

ROOT = Path(__file__).resolve().parents[3]
IMAGE = "ghcr.io/kalhauge/jvm2json:jdk-latest"


@pytest.mark.skipif(shutil.which("docker") is None, reason="needs docker")
def test_synthesized_tests_pass_on_the_suite(tmp_path):
    # cases.txt is the ground truth computed by the JVM, so every check must pass
    witnesses = synthesis.load_witnesses(ROOT / "target/stats/cases.txt")
    (tmp_path / "SynthesizedTests.java").write_text(synthesis.synthesize(witnesses))

    # The same JDK image that jpamb build uses; --user keeps the files ours
    result = subprocess.run(
        ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
         "-v", f"{ROOT}:/workspace", "-v", f"{tmp_path}:/out", "-w", "/workspace", IMAGE,
         "sh", "-c", "javac -cp target/classes -d /out /out/SynthesizedTests.java"
                     " && java -cp target/classes:/out SynthesizedTests"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
