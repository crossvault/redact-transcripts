# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Runs every console block in README.md that is marked ``<!-- readme-test -->``.

The command after ``$`` runs in bash, from a scratch directory that holds a copy of
``examples/``; stdout and stderr together must equal the lines that follow it.
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from redact_transcripts.cli import PROG

ROOT = Path(__file__).resolve().parent.parent
BLOCK = re.compile(r"<!-- readme-test -->\n```console\n\$ (?P<cmd>[^\n]+)\n(?P<out>.*?)```", re.DOTALL)
EXAMPLES = [
    pytest.param(m.group("cmd"), m.group("out"), id=m.group("cmd")[:60])
    for m in BLOCK.finditer((ROOT / "README.md").read_text(encoding="utf-8"))
]


def test_readme_has_tested_examples():
    assert len(EXAMPLES) >= 4


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize("cmd,expected", EXAMPLES)
def test_readme_example(cmd, expected, tmp_path):
    shutil.copytree(ROOT / "examples", tmp_path / "examples")
    shim = f'{PROG}() {{ PYTHONPATH="{ROOT / "src"}" "{sys.executable}" -m redact_transcripts "$@"; }}\n'
    proc = subprocess.run(
        ["bash", "-c", shim + cmd], cwd=tmp_path, capture_output=True, text=True, check=False
    )
    assert proc.stderr + proc.stdout == expected or proc.stdout + proc.stderr == expected, (
        proc.stdout,
        proc.stderr,
    )
