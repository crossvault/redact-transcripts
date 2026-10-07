# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
import json
import subprocess
import sys

import pytest

from redact_transcripts import ODYSSEUS, OdysseusFormat, detect_format, redact_bytes

GH = "ghp_" + "FAKEEXAMPLE" + "0" * 25
AWS = "AKIA" + "FAKE0000EXAMPLE0"
EXPORTED = "2026-01-01T09:00:00.123456"


def _export(**kw):
    doc = {
        "name": "Deploy help for jane.doe@mail.test",
        "model": "qwen3:8b",
        "exported": EXPORTED,
        "messages": [
            {"role": "user", "content": f"my token is {GH}, why does the deploy fail?"},
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": f"Rotate it. Also seen in the log: {AWS}"},
                    {"type": "text", "text": "nothing secret here"},
                ],
            },
            {"role": "user", "content": "thanks"},
        ],
    }
    doc.update(kw)
    return doc


def _redact(doc, indent=2, **kw):
    raw = (json.dumps(doc, indent=indent) + "\n").encode()
    out, report = redact_bytes(raw, format="odysseus", **kw)
    return raw, out, report


def test_pretty_export_redacts_content_and_keeps_structure():
    _, out, report = _redact(_export())
    assert GH not in out.decode() and AWS not in out.decode()
    assert "jane.doe@mail.test" not in out.decode()
    doc = json.loads(out)
    assert doc["model"] == "qwen3:8b"
    assert doc["exported"] == EXPORTED
    assert [m["role"] for m in doc["messages"]] == ["user", "assistant", "user"]
    assert [p["type"] for p in doc["messages"][1]["content"]] == ["text", "text"]
    assert doc["messages"][1]["content"][1]["text"] == "nothing secret here"
    assert doc["messages"][2]["content"] == "thanks"
    assert report.format == "odysseus"
    assert report.secrets_found() >= 2
    assert out.endswith(b"\n") and out.split(b"\n")[1].startswith(b'  "name"')


def test_compact_export_stays_compact():
    raw = json.dumps(_export(), separators=(",", ":")).encode()
    out, _ = redact_bytes(raw, format="odysseus")
    assert b"\n" not in out
    assert GH.encode() not in out
    assert json.loads(out)["model"] == "qwen3:8b"


def test_clean_export_is_byte_identical():
    clean = _export(name="Plain title", messages=[{"role": "user", "content": "hello"}])
    for indent in (None, 2, 4):
        raw = json.dumps(clean, indent=indent).encode()
        out, report = redact_bytes(raw, format="odysseus")
        assert out == raw
        assert report.as_dict()["identical"]


def test_idempotent():
    _, once, _ = _redact(_export())
    twice, report = redact_bytes(once, format="odysseus")
    assert twice == once
    assert report.total == 0


def test_secret_under_structural_key_is_still_redacted():
    _, out, _ = _redact(_export(model=GH))
    assert GH not in out.decode()


def test_off_shape_structural_value_is_redacted_like_content():
    _, out, _ = _redact(_export(exported="exported by jane.doe@mail.test"))
    assert "jane.doe@mail.test" not in out.decode()


def test_list_of_exports_and_jsonl_of_exports():
    docs = [_export(), _export(model="llama3.1")]
    raw = json.dumps(docs, indent=2).encode()
    out, _ = redact_bytes(raw, format="odysseus")
    assert [d["model"] for d in json.loads(out)] == ["qwen3:8b", "llama3.1"]
    assert GH not in out.decode()

    jsonl = ("\n".join(json.dumps(d) for d in docs) + "\n").encode()
    out, report = redact_bytes(jsonl, format="odysseus")
    lines = out.decode().splitlines()
    assert len(lines) == 2 and report.lines_total == 2
    assert all(json.loads(x)["exported"] == EXPORTED for x in lines)
    assert GH not in out.decode()


def test_bom_is_preserved():
    raw = b"\xef\xbb\xbf" + json.dumps(_export(), indent=2).encode()
    out, _ = redact_bytes(raw, format="odysseus")
    assert out.startswith(b"\xef\xbb\xbf")
    assert json.loads(out[3:])["model"] == "qwen3:8b"


@pytest.mark.parametrize("indent", [None, 2])
def test_auto_detects_odysseus(indent):
    raw = json.dumps(_export(), indent=indent).encode()
    assert detect_format(raw) is ODYSSEUS
    out, report = redact_bytes(raw)
    assert report.format == "odysseus"
    assert GH not in out.decode()


def test_auto_detection_unchanged_for_other_inputs():
    assert detect_format(b'{\n  "a": 1\n}\n').name == "text"
    assert detect_format(b'{"a": 1}\n').name == "jsonl"
    assert detect_format(b'{"messages": [], "name": "x"}\n').name == "jsonl"


def test_keep_key_copy_keeps_odysseus_shapes():
    fmt = ODYSSEUS.with_structural_keys(["session_id"])
    assert isinstance(fmt, OdysseusFormat)
    raw = json.dumps(_export(session_id="abc_123")).encode()
    out, _ = redact_bytes(raw, format=fmt)
    doc = json.loads(out)
    assert doc["session_id"] == "abc_123" and doc["model"] == "qwen3:8b"


def test_cli_format_odysseus(tmp_path):
    src = tmp_path / "export.json"
    src.write_text(json.dumps(_export(), indent=2))
    dst = tmp_path / "out.json"
    res = subprocess.run(
        [sys.executable, "-m", "redact_transcripts", "-f", "odysseus", str(src), "-o", str(dst), "--report"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, res.stderr
    assert "format=odysseus" in res.stderr
    assert GH not in dst.read_text()


def test_built_in_fields_get_no_exemption():
    assert not ODYSSEUS.keeps("model", "qwen3:8b")
    assert not ODYSSEUS.keeps("role", "user")


@pytest.mark.parametrize("value", ["jane.doe@mail.test", "10.1.2.3"])
def test_pii_and_infra_under_field_names_are_redacted_at_any_depth(value):
    doc = _export(model=value)
    doc["messages"][1]["content"].append({"type": "tool_use", "input": {"model": value, "role": value}})
    _, out, _ = _redact(doc)
    assert value not in out.decode()
    assert json.loads(out)["messages"][1]["content"][2]["type"] == "tool_use"


DEEP = "[\n" + "[" * 100_000 + json.dumps(GH) + "]" * 100_001 + "\n"


@pytest.mark.parametrize("fmt", ["auto", "odysseus"])
def test_too_deeply_nested_input_falls_back_to_text(fmt):
    out, report = redact_bytes(DEEP.encode(), format=fmt)
    assert GH not in out.decode()
    assert report.secrets_found() == 1


def test_deeply_nested_line_falls_back_to_text():
    raw = ("[" * 100_000 + json.dumps(GH) + "]" * 100_000 + "\n").encode()
    out, _ = redact_bytes(raw, format="odysseus")
    assert GH not in out.decode()


def test_cli_survives_deep_input(tmp_path):
    src = tmp_path / "deep.json"
    src.write_text(DEEP)
    res = subprocess.run(
        [sys.executable, "-m", "redact_transcripts", str(src)], capture_output=True, text=True
    )
    assert res.returncode == 0, res.stderr[-500:]
    assert GH not in res.stdout


def test_tab_indent_and_crlf_are_kept():
    raw = json.dumps(_export(), indent="\t").replace("\n", "\r\n").encode() + b"\r\n"
    out, report = redact_bytes(raw, format="odysseus")
    assert report.secrets_found() >= 1
    assert out.endswith(b"\r\n")
    lines = out.split(b"\r\n")
    assert all(not line.endswith(b"\r") and b"\n" not in line for line in lines)
    assert lines[1].startswith(b'\t"name"')
    assert json.loads(out)["model"] == "qwen3:8b"


@pytest.mark.parametrize(
    "raw",
    [
        "[\n" + "[" * 599 + json.dumps(GH) + "]" * 600 + "\n",
        "[" * 600 + json.dumps(GH) + "]" * 600 + "\n",
        "[" * 1200 + json.dumps(GH) + "]" * 1200 + "\n",
    ],
    ids=["list-600-deep", "line-600-deep", "line-1200-deep"],
)
def test_auto_mode_survives_deep_lists(raw, tmp_path):
    out, report = redact_bytes(raw.encode())
    assert GH not in out.decode()
    assert report.secrets_found() == 1
    src = tmp_path / "deep.json"
    src.write_text(raw)
    res = subprocess.run(
        [sys.executable, "-m", "redact_transcripts", str(src)], capture_output=True, text=True
    )
    assert res.returncode == 0, res.stderr[-500:]
    assert GH not in res.stdout and "[REDACTED:secret.github_token]" in res.stdout


def test_list_of_exports_is_checked_one_level_only():
    assert detect_format(json.dumps([[_export()]]).encode()).name == "jsonl"


@pytest.mark.parametrize("fmt", ["jsonl", "claude-code", "auto"])
def test_very_deep_second_line_is_redacted_as_text(fmt, tmp_path):
    raw = '{"a": 1}\n' + "[" * 100_000 + json.dumps(GH) + "]" * 100_000 + "\n"
    out, report = redact_bytes(raw.encode(), format=fmt)
    assert GH not in out.decode()
    assert report.secrets_found() == 1
    src = tmp_path / "deep.jsonl"
    src.write_text(raw)
    res = subprocess.run(
        [sys.executable, "-m", "redact_transcripts", "-f", fmt, str(src)], capture_output=True, text=True
    )
    assert res.returncode == 0, res.stderr[-500:]
    assert GH not in res.stdout and "[REDACTED:secret.github_token]" in res.stdout
