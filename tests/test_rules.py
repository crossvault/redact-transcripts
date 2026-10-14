# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
import re

import pytest

from redact_transcripts import Config, Redactor, Rule, default_rules, redact_text


def test_counts_only_real_changes():
    counts = {}
    out = Redactor().redact_text("token: ${X} and token=FAKE-value-1", counts)
    assert out == "token: ${X} and token=[REDACTED:secret.assignment]"
    assert counts == {"secret.assignment": 1}


def test_disable_by_name_and_prefix():
    text = "ssh 203.0.113.5 as jane@mail.test"
    assert Redactor(disable=["infra.ipv4"]).redact_text(text) == "ssh 203.0.113.5 as [REDACTED:pii.email]"
    assert Redactor(disable=["pii", "infra"]).redact_text(text) == text


def test_custom_rule_and_marker():
    rules = [*default_rules(), Rule.simple("secret.acme_token", r"\bacme_[A-Za-z0-9]{16,}")]
    r = Redactor(rules=rules, config=Config(marker_template="<{rule}>"))
    assert r.redact_text("key acme_FAKEEXAMPLE000000") == "key <secret.acme_token>"


def test_keep_lists_are_configurable():
    cfg = Config(email_keep_domains=("corp.test",), ipv4_keep=frozenset({"203.0.113.1"}))
    r = Redactor(config=cfg)
    assert (
        r.redact_text("a@corp.test b@sub.corp.test 203.0.113.1") == "a@corp.test b@sub.corp.test 203.0.113.1"
    )
    assert r.redact_text("c@example.com") == "[REDACTED:pii.email]"


def test_text_is_redacted_line_by_line():
    # The text format streams line by line, so a key with no value on its own line keeps the next line.
    # One string (a JSON value, redact_text) is redacted whole, as the reference rules do: there the
    # value may sit on the next line.
    from redact_transcripts import redact_bytes

    out, _ = redact_bytes(b"password:\n  user: x\n", format="text")
    assert out == b"password:\n  user: x\n"
    assert redact_text("Authorization:\n  Bearer FAKE-EXAMPLE-0000-token") == (
        "Authorization:\n  Bearer [REDACTED:secret.auth_header]"
    )


def test_rule_names_are_unique_and_dotted():
    names = [r.name for r in default_rules()]
    assert len(names) == len(set(names))
    reported = [n for r in default_rules() for n in r.names]
    assert all(re.match(r"^(secret|pii|infra)\.[a-z0-9_]+$", n) for n in names + reported)


def test_vendor_tokens_are_reported_and_disabled_per_vendor():
    text = "a ghp_FAKEEXAMPLE000000000000000000000000 b AKIAFAKEEXAMPLE00000"
    counts = {}
    out = Redactor().redact_text(text, counts)
    assert counts == {"secret.github_token": 1, "secret.aws_key_id": 1}, out
    kept = Redactor(disable=["secret.github_token"]).redact_text(text)
    assert "ghp_FAKEEXAMPLE" in kept and "AKIAFAKE" not in kept
    assert "secret.github_token" not in Redactor(disable=["secret.github_token"]).rule_names


@pytest.mark.parametrize("text", ["", "plain", "a\nb\n", "[REDACTED:secret.jwt]"])
def test_trivial_inputs(text):
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "tokensUsed: 12345",
        "tokens_used=12345",
        "secretCount: 4096",
        "password_length: 16",
        "passwordAttempts: 1000",
        "mapping: 1234",
        "spinner=5000",
    ],
)
def test_numeric_counters_and_metrics_are_kept(text):
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "text,rule",
    [
        ("db_password=40961234", "secret.assignment"),
        ("client_secret: 99887766", "secret.assignment"),
        ("pin: 4711", "secret.pin"),
        ("userPin=4321", "secret.pin"),
        ("passcode: 887766", "secret.pin"),
        ("otp_code=123456", "secret.pin"),
    ],
)
def test_numeric_passwords_and_pins_are_redacted(text, rule):
    counts = {}
    out = Redactor().redact_text(text, counts)
    assert not any(ch.isdigit() for ch in out.split(":", 1)[-1].split("=", 1)[-1]) and rule in counts


@pytest.mark.parametrize("text", ["token: 12345678", "api_key=12345678"])
def test_eight_digit_values_under_a_secret_key_are_redacted(text):
    # in step with the reference rules: 8+ characters under a token or API-key name are a value
    assert "12345678" not in redact_text(text)


def test_numeric_json_values_by_key():
    import json

    from redact_transcripts import redact_bytes

    rec = {
        "tokensUsed": 12345,
        "inputTokens": 4096,
        "secretCount": 1200,
        "token_count": 2048,
        "password": 40961234,
        "pin": 1234,
        "userPin": "4321",
        "client_secret": "99887766",
    }
    out, rep = redact_bytes((json.dumps(rec) + "\n").encode(), format="jsonl")
    got = json.loads(out)
    for k in ("tokensUsed", "inputTokens", "secretCount", "token_count"):
        assert got[k] == rec[k]
    for k in ("password", "pin", "userPin", "client_secret"):
        assert got[k] == "[REDACTED:secret.keyed_value]"
    assert rep.rules == {"secret.keyed_value": 4}
