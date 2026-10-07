# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Vendor token shapes in every position: after ``_`` or a URL escape, after a literal ``\\n`` escape,
glued onto text, followed by ``_<word>``; identifier-shaped names stay; binary data is never touched.

Every token below is synthetic (FAKE / repeated filler) and assembled at runtime, so no file in this
repository holds a token-shaped string.
"""

import base64
import json
import time

import pytest

from redact_transcripts import Redactor, redact_bytes
from redact_transcripts.rules import binary_spans

M = "FAKEfake0123456789Zz" + "QqRr9876WwXx54Yy"  # 36 characters, mixed case and digits
UP = "FAKEFAKE" + "01234567"  # 16 characters, AWS key-id alphabet
XOX = "123456789012-1234567890123-" + "AbCdEfGh0123IjKlMn4567"

CLASSIC = {
    **{p: p + M for p in ("gh" + c + "_" for c in "pousr")},
    "github_pat_": "github_" + "pat_" + "11FAKEFAKE0123456789ab" + "_" + M + "AbCd0123456789Zz9876Qqw",
    "sk-": "sk" + "-" + M + "AbCd0123QqRr",
    "sk-ant-": "sk" + "-ant-" + "api03-" + M + "-" + M[:20] + "AA",
    **{p: p + XOX for p in ("xo" + "x" + c + "-" for c in "bpars")},
    "AKIA": "AK" + "IA" + UP,
    "ASIA": "AS" + "IA" + UP,
    "sk_live_": "sk_" + "live_" + M[:24],
    "sk_test_": "sk_" + "test_" + M[:24],
    "rk_live_": "rk_" + "live_" + M[:24],
    "whsec_": "wh" + "sec_" + M[:32],
}
V2 = {
    "sk-proj-": "sk" + "-proj-" + M + "AbCd0123",
    "sk-or-v1-": "sk" + "-or-v1-" + ("0123456789abcdef" * 4),
    "AIza": "AI" + "za" + M[:35],
    "ya29.": "ya" + "29." + M + "-" + M[:10],
    "1//": "1" + "//0" + M + M[:6],
    "GOCSPX-": "GOC" + "SPX-" + M[:28],
    "gsk_": "gs" + "k_" + M + M[:16],
    "xai-": "xa" + "i-" + M + M[:16],
}
KEYS = {**CLASSIC, **V2}

FORMS = {
    "after-space": ("key ", " done"),
    "followed-by-underscore-word": ("key ", "_word tail"),
    "end-of-line": ("key ", "_word\nnext"),
    "url-query": ("https://x.example/p?k=", "_word&a=1"),
    "after-underscore": ("CONF_", " done"),
    "after-url-escape": ("https://x.example/?k=%20", "&a=1"),
    "after-literal-newline-escape": ('{"c":"line\\n', '"}'),
}
GLUED_FORMS = {"glued": ("notes", " tail"), "glued-and-underscore": ("notes", "_word tail")}
GLUED = [k for k in CLASSIC] + ["sk-proj-"]


def _cases():
    for name, key in KEYS.items():
        for form, (lead, tail) in FORMS.items():
            if name in V2 and form == "followed-by-underscore-word":
                continue  # a newer-shape key may contain `_`: the tail is part of its body
            yield pytest.param(key, lead, tail, id=f"{name}-{form}")
    for name in GLUED:
        for form, (lead, tail) in GLUED_FORMS.items():
            yield pytest.param(KEYS[name], lead, tail, id=f"{name}-{form}")


def redact(text):
    return Redactor().redact_text(text)


@pytest.mark.parametrize("key,lead,tail", list(_cases()))
def test_token_is_redacted_in_every_position(key, lead, tail):
    out = redact(lead + key + tail)
    assert key[-12:] not in out and key[-24:-12] not in out, out
    assert "[REDACTED:secret." in out, out
    assert out.startswith(lead[:4]), out
    assert redact(out) == out


@pytest.mark.parametrize("key,lead,tail", list(_cases()))
def test_jsonl_value_is_redacted(key, lead, tail):
    raw = (json.dumps({"c": lead + key + tail}) + "\n").encode()
    out, _ = redact_bytes(raw, format="jsonl")
    assert key[-12:].encode() not in out


@pytest.mark.parametrize("lead", ["x_xo" + "xb-notes-for-", "CONF_sk" + "-aaaaaaaaaaaaaaaaaaaaaaaa_", "id "])
@pytest.mark.parametrize("name", ["ghp_", "sk_live_", "whsec_", "github_pat_"])
def test_next_token_after_underscore_keeps_its_start(lead, name):
    key = KEYS[name]
    out = redact(lead + key + "_word done")
    assert key[-12:] not in out, out


NAMES = [
    "storage_read_bytes",
    "page_emit_events_now",
    "task_live_results",
    "disk_test_runner_config",
    "whsec_handler_name",
    "my_ghp_counter_value",
    "ghs_and_lows_chart",
    "sk-learn_examples",
    "risk-assessment_report",
    "xo" + "xb-notes_for_docs",
    "AKIA_PLACEHOLDER",
    "thighs_and_laughs_",
    "the_sk_live_mode_flag",
    "sk_" + "test_" + "abcdefghijklmnopqrstuvwx_name",
    "slack_xo" + "xb-tokens-and-scopes-guide",
    "my_sk" + "-ant-api-key-placeholder",
    "see docs.x.ai/xa" + "i-api-reference-v2-2024-guide",
    "my_gs" + "k_client_settings_for_tests",
    "https://example.com/xa" + "i-2024-10-07-release-notes",
]


NAMES += [
    "n = 1//batch_size_per_device_for_training_run",
    "steps = total_items 1//0 if x else 1//per_device_train_batch_size_value",
    "pip install xa" + "i-grok-sdk-python-integration-helpers",
    "pip install gs" + "k_client_settings_for_tests_helper",
    "0123456789abcdef0123456789abcdef.localdomainhostx",
]


@pytest.mark.parametrize("line", NAMES)
def test_identifier_shaped_names_stay(line):
    assert redact(line) == line


def _png_like(n):
    raw = bytes((i * 37 + 11) % 256 for i in range(n))
    return base64.b64encode(raw).decode()


# Only shapes made of base64 characters can sit inside base64 data.
@pytest.mark.parametrize("key", [KEYS["AIza"], KEYS["1//"], KEYS["AKIA"], KEYS["sk-or-v1-"][9:]])
def test_binary_data_is_never_rewritten(key):
    blob = _png_like(600)
    for lead in ("+", "/", "A"):
        data = "data:image/png;base64," + blob[:300] + lead + key + blob[300:]
        assert redact(data) == data
        run = blob[:300] + "+" + key + blob[300:]
        assert redact(run) == run


def test_wrapped_base64_with_escaped_line_breaks_is_binary():
    blob = _png_like(400)
    lines = [blob[i : i + 76] for i in range(0, 76 * 4, 76)]
    lines[2] = "AI" + "za" + lines[2][4:]
    text = "\\n".join(lines)
    assert binary_spans(text)
    assert redact(text) == text


def test_a_token_next_to_binary_data_is_still_redacted():
    blob = _png_like(600)
    text = "data:image/png;base64," + blob + " key " + KEYS["ghp_"]
    out = redact(text)
    assert KEYS["ghp_"][-12:] not in out and blob in out


def test_adversarial_runs_stay_linear():
    blob = (
        ("ghp_" + "a" * 60 + "_") * 400
        + ("xo" + "xb-" + "1" * 30 + "-" + "a" * 60 + "_") * 200
        + ("notesAK" + "IA" + "A" * 40 + "_") * 300
        + ("sk" + "-proj-" + "a" * 300 + "_x ") * 100
        + ("a_sk" + "-proj-") * 2000
        + ("%20AI" + "za") * 2000
        + ("\\n1" + "//") * 2000
    )
    t0 = time.perf_counter()
    redact(blob)
    assert time.perf_counter() - t0 < 5.0


NEW_V2 = ["ya29.", "1//", "GOCSPX-", "gsk_", "xai-"]


@pytest.mark.parametrize("tail", ["/rotate", "+x", "=", "=="])
@pytest.mark.parametrize("lead", ["key ", "https://api.example/keys/", "CONF_", "?k=%20"])
@pytest.mark.parametrize("name", NEW_V2)
def test_newer_shapes_end_before_slash_plus_equals(name, lead, tail):
    key = KEYS[name]
    out = redact(lead + key + tail)
    assert key[-12:] not in out, out
    assert out.endswith(tail), out
