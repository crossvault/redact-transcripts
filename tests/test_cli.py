# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from redact_transcripts.cli import main

GH = "ghp_FAKEEXAMPLE000000000000000000000000"
SRC = str(Path(__file__).resolve().parent.parent / "src")


class _Std:
    def __init__(self, data=b""):
        self.buffer = io.BytesIO(data)

    def write(self, text):
        self.buffer.write(text.encode())


def _run(monkeypatch, argv, stdin=b""):
    out, err = _Std(), io.StringIO()
    monkeypatch.setattr(sys, "stdin", _Std(stdin))
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    code = main(argv)
    return code, out.buffer.getvalue(), err.getvalue()


def test_stdin_to_stdout(monkeypatch):
    code, out, err = _run(monkeypatch, ["-"], f"key {GH}\n".encode())
    assert code == 0 and out == b"key [REDACTED:secret.github_token]\n" and err == ""


def test_report_counts_per_rule(monkeypatch, tmp_path):
    f = tmp_path / "t.log"
    f.write_text(f"{GH}\n{GH} jane@mail.test\n")
    code, out, err = _run(monkeypatch, [str(f), "--report"])
    assert code == 0 and GH.encode() not in out
    assert "secret.github_token  2" in err and "pii.email" in err and GH not in err


def test_report_json(monkeypatch, tmp_path):
    f = tmp_path / "t.jsonl"
    f.write_text(json.dumps({"sessionId": "s", "msg": GH}) + "\n")
    code, _, err = _run(monkeypatch, [str(f), "--report", "--report-format", "json"])
    rep = json.loads(err)
    assert code == 0 and rep["format"] == "claude-code" and rep["rules"] == {"secret.github_token": 1}


def test_check_exit_codes(monkeypatch, tmp_path):
    dirty, pii, clean = tmp_path / "d", tmp_path / "p", tmp_path / "c"
    dirty.write_text(f"token={GH}\n")
    pii.write_text("mail jane@mail.test\n")
    clean.write_text("nothing here\n")
    assert _run(monkeypatch, ["--check", str(dirty)])[:2] == (1, b"")
    assert _run(monkeypatch, ["--check", str(clean)])[0] == 0
    assert _run(monkeypatch, ["--check", str(pii)])[0] == 0
    assert _run(monkeypatch, ["--check", "--strict", str(pii)])[0] == 1
    assert _run(monkeypatch, ["--check", "--disable", "secret", str(dirty)])[0] == 0


def test_output_file_and_refuse_overwrite(monkeypatch, tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_text(f"{GH}\n")
    assert _run(monkeypatch, [str(src), "-o", str(dst)])[0] == 0
    assert dst.read_text() == "[REDACTED:secret.github_token]\n"
    assert _run(monkeypatch, [str(src), "-o", str(src)])[0] == 2
    assert src.read_text() == f"{GH}\n"


def test_keep_key_and_extra_rule(monkeypatch, tmp_path):
    f = tmp_path / "t.jsonl"
    f.write_text(json.dumps({"ref": "203.0.113.9", "note": "acme_FAKEEXAMPLE0000000000"}) + "\n")
    code, out, _ = _run(
        monkeypatch,
        [str(f), "-f", "jsonl", "--keep-key", "ref", "--rule", r"secret.acme=\bacme_[A-Za-z0-9]{16,}"],
    )
    assert code == 0 and json.loads(out) == {"ref": "203.0.113.9", "note": "[REDACTED:secret.acme]"}


def test_errors(monkeypatch, tmp_path):
    assert _run(monkeypatch, [str(tmp_path / "missing")])[0] == 2
    assert _run(monkeypatch, ["-", "--rule", "noequals"])[0] == 2
    assert _run(monkeypatch, ["-", "--rule", "x=("])[0] == 2
    with pytest.raises(SystemExit):
        _run(monkeypatch, ["-", "-f", "nope"])


def test_list_rules(monkeypatch):
    code, out, _ = _run(monkeypatch, ["--list-rules", "-"])
    assert code == 0 and b"secret.github_token" in out and b"secret.keyed_value" in out


def test_module_entry_point_streams_text():
    proc = subprocess.run(
        [sys.executable, "-m", "redact_transcripts", "-f", "text", "-"],
        input=f"a {GH}\nb\n".encode(),
        capture_output=True,
        env={"PYTHONPATH": SRC},
        check=False,
    )
    assert proc.returncode == 0 and proc.stdout == b"a [REDACTED:secret.github_token]\nb\n"


def test_streamed_text_report_is_not_identical_when_redacted(monkeypatch):
    code, _, err = _run(
        monkeypatch, ["-f", "text", "-", "--report", "--report-format", "json"], f"key {GH}\n".encode()
    )
    rep = json.loads(err)
    assert code == 0 and rep["identical"] is False and rep["input_sha256"] != rep["output_sha256"]
    assert rep["input_sha256"] and rep["output_sha256"]
    code, _, err = _run(monkeypatch, ["-f", "text", "-", "--report", "--report-format", "json"], b"clean\n")
    rep = json.loads(err)
    assert rep["identical"] is True and rep["input_sha256"] == rep["output_sha256"] != ""


def test_unknown_disable_is_an_error(monkeypatch):
    code, _, err = _run(monkeypatch, ["--disable", "secret.github", "-"], b"x\n")
    assert code == 2 and "no such rule" in err
    assert (
        _run(monkeypatch, ["--disable", "secret.github_token", "-"], f"{GH}\n".encode())[1]
        == f"{GH}\n".encode()
    )


def test_flag_misuse(monkeypatch):
    with pytest.raises(SystemExit):
        _run(monkeypatch, ["--strict", "-"])
    with pytest.raises(SystemExit):
        _run(monkeypatch, ["--check", "-o", "x", "-"])


def test_list_rules_includes_extra_rules(monkeypatch):
    code, out, _ = _run(monkeypatch, ["--list-rules", "--rule", "secret.acme=acme_x", "-"])
    assert code == 0 and b"secret.acme\n" in out
