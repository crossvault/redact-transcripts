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


def test_rules_never_span_lines_except_private_key():
    for rule in default_rules():
        if rule.name == "secret.private_key":
            continue
        assert r"\s*[:=]" not in rule.pattern.pattern, rule.name
    assert redact_text("password:\n  user: x") == "password:\n  user: x"


def test_rule_names_are_unique_and_dotted():
    names = [r.name for r in default_rules()]
    assert len(names) == len(set(names))
    assert all(re.match(r"^(secret|pii|infra)\.[a-z0-9_]+$", n) for n in names)


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
        "token: 12345678",
        "api_key=12345678",
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
