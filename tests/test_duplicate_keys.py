# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Every occurrence of a duplicate JSON key is scanned and written back."""

import json

import pytest

from redact_transcripts import redact_bytes
from redact_transcripts.engine import DuplicateKeyObject, json_dumps, json_object_pairs

TOKEN = "ghp_" + "FAKEfake0123456789Zz" + "QqRr9876WwXx54Yy"


@pytest.mark.parametrize("fmt", ["jsonl", "claude-code"])
def test_token_in_the_first_occurrence_is_redacted(fmt):
    line = '{"type":"user","c":"key ' + TOKEN + '","c":"plain text"}\n'
    out, report = redact_bytes(line.encode(), format=fmt)
    assert TOKEN.encode() not in out
    assert report.rules.get("secret.github_token") == 1
    assert b'"c":"plain text"' in out
    assert out.count(b'"c":') == 2


@pytest.mark.parametrize("fmt", ["jsonl", "claude-code"])
def test_token_in_a_nested_first_occurrence_is_redacted(fmt):
    line = '{"message":{"content":[{"text":"' + TOKEN + '","text":"ok"}]}}\n'
    out, _ = redact_bytes(line.encode(), format=fmt)
    assert TOKEN.encode() not in out


@pytest.mark.parametrize("fmt", ["jsonl", "claude-code"])
def test_duplicate_keys_without_a_secret_keep_the_line_byte_for_byte(fmt):
    line = '{"a": "one", "a": "two"}\r\n'
    out, report = redact_bytes(line.encode(), format=fmt)
    assert out == line.encode() and not report.rules


def test_secret_named_duplicate_key_redacts_every_value():
    line = '{"password":"hunter2hunter2","password":"other-secret-1"}\n'
    out, _ = redact_bytes(line.encode(), format="jsonl")
    assert b"hunter2" not in out and b"other-secret" not in out
    assert out.count(b'"password":') == 2


def test_hook_and_writer():
    obj = json.loads('{"a":1,"b":[{"x":"y","x":"z"}],"a":2}', object_pairs_hook=json_object_pairs)
    assert isinstance(obj, DuplicateKeyObject) and obj["a"] == 2
    assert json_dumps(obj) == '{"a":1,"b":[{"x":"y","x":"z"}],"a":2}'
    plain = json.loads('{"a":"ü","b":[1.5,true,null]}', object_pairs_hook=json_object_pairs)
    assert type(plain) is dict
    assert json_dumps(plain) == json.dumps(plain, ensure_ascii=False, separators=(",", ":"))


@pytest.mark.parametrize("fmt", ["jsonl", "claude-code", "auto"])
def test_a_line_nested_2000_deep_never_aborts_the_file(fmt):
    deep = '{"a":' * 2000 + '"key ' + TOKEN + '"' + "}" * 2000
    raw = (deep + "\n" + '{"c":"' + TOKEN + '"}\n').encode()
    out, _ = redact_bytes(raw, format=fmt)
    assert TOKEN.encode() not in out
    assert out.count(b"\n") == 2


def test_a_deep_line_with_duplicate_keys_never_aborts():
    deep = '{"a":' * 1500 + '{"c":"' + TOKEN + '","c":"x"}' + "}" * 1500
    out, _ = redact_bytes((deep + "\n").encode(), format="jsonl")
    assert TOKEN.encode() not in out
