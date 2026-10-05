# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
import json

import pytest

from redact_transcripts import (
    CLAUDE_CODE,
    JSONL,
    TEXT,
    JsonlFormat,
    Redactor,
    detect_format,
    get_format,
    redact_bytes,
    register_format,
)

GH = "ghp_FAKEEXAMPLE000000000000000000000000"
AWS = "AKIAFAKE0000EXAMPLE0"


def _line(**kw):
    rec = {
        "type": "user",
        "sessionId": "00000000-0000-4000-8000-00000000000a",
        "uuid": "00000000-0000-4000-8000-00000000000b",
        "parentUuid": "00000000-0000-4000-8000-00000000000c",
        "timestamp": "2026-01-01T00:00:00Z",
        "message": {"role": "user", "content": "hello"},
    }
    rec.update(kw)
    return json.dumps(rec)


def test_claude_code_transcript_stays_resumable():
    lines = [
        _line(),
        _line(message={"role": "user", "content": f"use {GH}"}),
        _line(
            type="assistant",
            message={
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_01FAKE",
                        "name": "Bash",
                        "input": {"command": "env", "env": {"GITHUB_TOKEN": "plain-FAKE-value"}},
                    }
                ],
            },
        ),
        _line(
            message={
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "toolu_01FAKE", "content": f"AWS {AWS}"}],
            }
        ),
    ]
    raw = ("\n".join(lines) + "\n").encode()
    out, rep = redact_bytes(raw, format="claude-code")
    text = out.decode()
    assert GH not in text and "plain-FAKE-value" not in text and AWS not in text
    recs = [json.loads(ln) for ln in text.splitlines()]
    for a, b in zip([json.loads(ln) for ln in lines], recs):
        for k in ("sessionId", "uuid", "parentUuid", "timestamp", "type"):
            assert a[k] == b[k]
    assert recs[2]["message"]["content"][0]["id"] == "toolu_01FAKE"
    assert recs[3]["message"]["content"][0]["tool_use_id"] == "toolu_01FAKE"
    assert text.splitlines()[0] == lines[0]  # untouched line keeps its exact bytes
    assert rep.lines_changed == 3 and rep.changed_lines == [2, 3, 4]
    assert rep.rules["secret.keyed_value"] == 1
    dumped = json.dumps(rep.as_dict())
    assert GH not in dumped and "plain-FAKE-value" not in dumped and not rep.as_dict()["identical"]


def test_generic_jsonl_has_no_structural_keys_but_can_get_them():
    raw = (json.dumps({"id": "203.0.113.9", "msg": "x"}) + "\n").encode()
    out, _ = redact_bytes(raw, format="jsonl")
    assert "203.0.113.9" not in out.decode()
    out, rep = JSONL.with_structural_keys(["id"]).redact_bytes(raw, Redactor())
    assert out == raw and rep.total == 0
    # a kept key never protects a secret
    raw = (json.dumps({"id": GH}) + "\n").encode()
    out, rep = JSONL.with_structural_keys(["id"]).redact_bytes(raw, Redactor())
    assert GH not in out.decode() and rep.rules == {"secret.github_token": 1}


@pytest.mark.parametrize("key", ["id", "type", "model", "version", "role", "level", "tool_use_id", "uuid"])
@pytest.mark.parametrize("secret", [GH, "password=FAKE-hunter2", "Bearer FAKE-EXAMPLE-0000-token"])
def test_structural_key_names_do_not_protect_secrets_at_any_depth(key, secret):
    nested = {"type": "tool_use", "id": "toolu_01FAKE", "input": {key: secret, "deeper": [{key: secret}]}}
    raw = (_line(message={"role": "assistant", "content": [nested]}, **{key: secret}) + "\n").encode()
    out, rep = redact_bytes(raw, format="claude-code")
    text = out.decode()
    assert secret not in text and rep.total >= 3
    rec = json.loads(text)
    assert rec["message"]["content"][0]["id"] == "toolu_01FAKE"  # real structure is still kept


def test_structural_values_with_the_expected_shape_are_kept():
    line = _line(model="claude-example-1", version="2.0.14", requestId="req_FAKE0001", level="info")
    raw = (line + "\n").encode()
    out, rep = redact_bytes(raw, format="claude-code")
    assert out == raw and rep.total == 0


def test_numeric_and_list_values_under_secret_keys():
    raw = (
        json.dumps(
            {
                "password": 12345678,
                "pin": 7,
                "port": 5432,
                "tokens": ["a"],
                "token": ["FAKE-tok-1", "FAKE-tok-2"],
                "api_key": True,
            }
        )
        + "\n"
    ).encode()
    out, rep = redact_bytes(raw, format="jsonl")
    rec = json.loads(out)
    assert rec["password"] == "[REDACTED:secret.keyed_value]"
    assert rec["token"] == ["[REDACTED:secret.keyed_value]"] * 2
    assert rec["pin"] == 7 and rec["port"] == 5432 and rec["tokens"] == ["a"] and rec["api_key"] is True
    assert rep.rules == {"secret.keyed_value": 3}


def test_custom_format_registration():
    class TraceFormat(JsonlFormat):
        def is_structural(self, key):
            return key.endswith("_id") or key == "span"

    fmt = register_format(TraceFormat(name="my-traces"))
    assert get_format("my-traces") is fmt
    raw = (json.dumps({"trace_id": "abc", "span": "203.0.113.9", "note": "203.0.113.9"}) + "\n").encode()
    out, _ = redact_bytes(raw, format="my-traces")
    assert json.loads(out) == {"trace_id": "abc", "span": "203.0.113.9", "note": "[REDACTED:infra.ipv4]"}


def test_keys_are_redacted_too():
    raw = (json.dumps({"sessionId": "s", "data": {"203.0.113.3": "host"}}) + "\n").encode()
    out, rep = redact_bytes(raw, format="claude-code")
    assert "203.0.113.3" not in out.decode() and rep.rules == {"infra.ipv4": 1}


def test_clean_file_is_byte_identical_and_idempotent():
    raw = ("\n".join([_line(), _line()]) + "\n").encode()
    out, rep = redact_bytes(raw)
    assert out == raw and rep.as_dict()["identical"] and rep.lines_changed == 0
    dirty = ("not json " + GH + "\r\n" + _line(message={"content": "x@corp.test"}) + "\r\n").encode()
    once, rep1 = redact_bytes(dirty, format="claude-code")
    twice, rep2 = redact_bytes(once, format="claude-code")
    assert once == twice and rep2.lines_changed == 0 and rep1.non_json_lines == 1
    assert once.count(b"\r\n") == 2


def test_undecodable_bytes_survive():
    raw = b"caf\xe9 " + GH.encode() + b"\n"
    out, _ = redact_bytes(raw, format="text")
    assert out == b"caf\xe9 [REDACTED:secret.github_token]\n"


@pytest.mark.parametrize(
    "raw,fmt",
    [
        (b"", TEXT),
        (b"hello\n", TEXT),
        (b'{"a":1}\n', JSONL),
        (b'\n{"sessionId":"x"}\n', CLAUDE_CODE),
        (b"[1,2]\n", JSONL),
    ],
)
def test_detect_format(raw, fmt):
    assert detect_format(raw) is fmt


def test_unknown_format():
    with pytest.raises(ValueError, match="unknown format"):
        get_format("nope")
