# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Redaction rules: a name, a regular expression and a replacement.

Every rule is *bound* to a :class:`~redact_transcripts.engine.Redactor` before use, so a rule can
read the redactor's configuration (marker format, keep-lists) and, for the base64 rule, call back
into the other rules.

Rule names are dotted: ``secret.*`` for credentials, ``pii.*`` for personal data and ``infra.*``
for infrastructure details. Reports and ``--disable`` use these names.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from .engine import Redactor

Replacer = Callable[["re.Match[str]"], str]

# Separators never span a newline ("[ \t]" instead of "\s"). This keeps every rule except the
# multi-line private-key block line-local, which is what makes streaming redaction equal to
# whole-text redaction.
_SP = r"[ \t]"


@dataclass(frozen=True)
class Rule:
    """A redaction rule.

    ``keep_group``: if set, that capture group is kept verbatim in front of the marker
    (e.g. ``"Bearer "``), and the rest of the match is replaced.
    """

    name: str
    pattern: "re.Pattern[str]"
    keep_group: Optional[int] = None

    def bind(self, redactor: "Redactor") -> Replacer:
        marker = redactor.marker(self.name)
        if self.keep_group is None:
            return lambda m: marker
        g = self.keep_group
        return lambda m: m.group(g) + marker

    @classmethod
    def simple(cls, name: str, regex: str, flags: int = 0) -> "Rule":
        """Build a rule that replaces the whole match. Handy for vendor-specific token shapes."""
        return cls(name, re.compile(regex, flags))


# Values that look like an assignment but are clearly not a secret. Short numbers (``port: 22``)
# are listed here; a longer all-digit value under a secret-named key (a PIN, a numeric password)
# *is* redacted.
NOT_A_SECRET_VALUE = re.compile(
    r"^(?:\d{1,3}|true|false|null|none|undefined|bearer|basic|token|digest|api-?key|key|sso-key|ssws"
    r"|negotiate|ntlm|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|<[^>]*>|\*+|x+|\.\.\.)$",
    re.IGNORECASE,
)

SECRET_KEY_WORDS = (
    r"password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|client[_-]?secret|credentials?|authorization|auth_?token"
)

#: Matches an object key or variable name that names a secret, e.g. ``GITHUB_TOKEN``.
SECRET_KEY = re.compile(r"(?i)(?:" + SECRET_KEY_WORDS + r")")

#: Keys that contain a secret word but name metadata, not a secret (``tokenizer``, ``max_tokens``,
#: ``password_policy`` ...).
NOT_A_SECRET_KEY = re.compile(
    r"(?i)(?:tokeni[sz]|tokens(?![a-z])|token_?(?:count|limit|usage|budget|type)"
    r"|(?:password|passwd|secret|token|credentials?)_?(?:policy|length|hint|name|names|path|file"
    r"|ttl|expiry|expires(?:_at)?|rotation))"
)


def is_secret_key(key: str) -> bool:
    """True if ``key`` names a secret (``GITHUB_TOKEN``) and not metadata (``max_tokens``)."""
    return bool(SECRET_KEY.search(key)) and not NOT_A_SECRET_KEY.search(key)


_NUMERIC_SECRET_WORDS = frozenset(
    {"password", "passwd", "passphrase", "passcode", "pwd", "secret", "pin", "pincode", "otp", "cvv", "cvc"}
)
_COUNTER_WORDS = frozenset(
    {
        "count",
        "counts",
        "used",
        "total",
        "num",
        "number",
        "max",
        "min",
        "limit",
        "size",
        "length",
        "len",
        "ttl",
        "seconds",
        "secs",
        "sec",
        "ms",
        "millis",
        "id",
        "index",
        "idx",
        "version",
        "rate",
        "usage",
        "budget",
        "remaining",
        "left",
        "attempts",
        "retries",
        "tokens",
        "age",
        "expiry",
        "expires",
        "timeout",
    }
)


def _key_words(key: str) -> List[str]:
    """``FAKE_DB_PASSWORD`` -> fake, db, password; ``tokensUsed`` -> tokens, used."""
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key.strip("\\\"' \t"))
    return [w for w in re.split(r"[^A-Za-z0-9]+", key.lower()) if w]


def is_numeric_secret_key(key: str) -> bool:
    """True if an all-digit value under ``key`` is a secret: the key names a password, secret or
    PIN (``db_password``, ``userPin``, ``client_secret``) and no word marks it as a counter or
    metric (``tokensUsed``, ``secretCount``, ``password_length``)."""
    words = _key_words(key)
    if any(w in _COUNTER_WORDS for w in words):
        return False
    return any(w in _NUMERIC_SECRET_WORDS or w.startswith(("password", "secret")) for w in words)


def is_secret_value(value: str) -> bool:
    """True if ``value`` (found under a secret-looking key) should be redacted."""
    return (
        len(value) >= 3
        and not NOT_A_SECRET_VALUE.match(value)
        and not value.startswith(("[REDACTED", "<", "$"))
    )


class AssignmentRule(Rule):
    """``password=...``, ``"api_key": "..."``, ``export DB_TOKEN=...`` and JSON-escaped forms.

    A quoted value is redacted up to its closing quote, spaces included.
    """

    def bind(self, redactor: "Redactor") -> Replacer:
        marker = redactor.marker(self.name)

        def rep(m: "re.Match[str]") -> str:
            for q, v in (("q1", "v1"), ("q2", "v2"), ("q3", "v3"), ("q4", "v4")):
                if m.group(v) is not None:
                    quote, value = m.group(q) or "", m.group(v)
                    break
            if not is_secret_value(value) or NOT_A_SECRET_KEY.search(m.group("key")):
                return m.group(0)
            if value.isdigit() and not is_numeric_secret_key(m.group("key")):
                return m.group(0)  # a counter or metric (tokensUsed: 12345), not a password
            close = quote if v != "v4" else ""
            return m.group("key") + m.group("sep") + quote + marker + close

        return rep


class NumericPinRule(Rule):
    """``pin: 1234``, ``passcode=887766``: digits under a PIN-like key (whole key words only, so
    ``mapping: 1234`` or ``spinner=5000`` are left alone)."""

    def bind(self, redactor: "Redactor") -> Replacer:
        marker = redactor.marker(self.name)

        def rep(m: "re.Match[str]") -> str:
            if not is_numeric_secret_key(m.group(1)):
                return m.group(0)
            return m.group(1) + marker

        return rep


class EmailRule(Rule):
    def bind(self, redactor: "Redactor") -> Replacer:
        marker = redactor.marker(self.name)
        keep = redactor.config.email_keep_domains

        def rep(m: "re.Match[str]") -> str:
            domain = m.group(0).rsplit("@", 1)[1].lower()
            if any(domain == d or domain.endswith("." + d) for d in keep):
                return m.group(0)
            return marker

        return rep


class IPv4Rule(Rule):
    def bind(self, redactor: "Redactor") -> Replacer:
        marker = redactor.marker(self.name)
        keep = redactor.config.ipv4_keep

        def rep(m: "re.Match[str]") -> str:
            ip = m.group(0)
            if ip in keep or any(int(o) > 255 for o in ip.split(".")):
                return ip
            return marker

        return rep


class HomeDirRule(Rule):
    """Replace the user name in ``/home/<user>``, ``/Users/<user>`` and ``C:\\Users\\<user>``."""

    def bind(self, redactor: "Redactor") -> Replacer:
        user = redactor.config.home_dir_placeholder
        return lambda m: m.group(1) + user


class Base64Rule(Rule):
    """Redact a base64 blob whose *decoded* text contains a secret that another rule recognises.

    Only ``secret.*`` rules are applied to the decoded text, and only one level deep.
    """

    def bind(self, redactor: "Redactor") -> Replacer:
        marker = redactor.marker(self.name)

        def rep(m: "re.Match[str]") -> str:
            blob = m.group(0)
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
                text = decoded.decode("utf-8")
            except (binascii.Error, ValueError):
                return blob
            if not all(c.isprintable() or c in "\r\n\t" for c in text):
                return blob
            if redactor.contains_secret(text):
                return marker
            return blob

        return rep


def default_rules() -> List[Rule]:
    """The built-in rule set, in order. Specific token shapes run before generic ones, so a known
    token is reported under its own rule rather than as a generic assignment."""
    return [
        Rule(
            "secret.private_key",
            re.compile(
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
                re.DOTALL,
            ),
        ),
        Rule("secret.anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{10,}")),
        Rule("secret.openai_key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}")),
        Rule(
            "secret.github_token",
            re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
        ),
        Rule("secret.gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
        Rule("secret.slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
        Rule("secret.aws_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        Rule("secret.google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
        Rule("secret.stripe_key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}")),
        Rule("secret.jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
        Base64Rule(
            "secret.base64_encoded",
            re.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=_\-])"),
        ),
        Rule(
            "secret.bearer", re.compile(r"(?i)(\bbearer" + _SP + r"+)[A-Za-z0-9._~+/\-]{12,}=*"), keep_group=1
        ),
        Rule(
            "secret.basic_auth",
            re.compile(r"(?i)(\bbasic" + _SP + r"+)[A-Za-z0-9+/]{12,}={0,2}"),
            keep_group=1,
        ),
        Rule(
            "secret.url_credentials",
            re.compile(
                r"(?i)((?<![a-z0-9+.\-])[a-z][a-z0-9+.\-]{0,31}://)(?!\[REDACTED)[^/\s:@\"']{1,256}:[^/\s@\"']{1,256}(?=@)"
            ),
            keep_group=1,
        ),
        Rule(
            # https://<token>@host: a token as the whole userinfo (common git remote form). Must be
            # 16+ characters with letters and digits and no dot, so "git@" or "first.last@" pass.
            "secret.url_token",
            re.compile(
                r"(?i)((?<![a-z0-9+.\-])[a-z][a-z0-9+.\-]{0,31}://)"
                r"(?=[A-Za-z0-9_\-]{0,255}[0-9])(?=[A-Za-z0-9_\-]{0,255}[A-Za-z])[A-Za-z0-9_\-]{16,256}(?=@)"
            ),
            keep_group=1,
        ),
        Rule(
            "secret.cli_flag",
            re.compile(
                r"(?i)(--(?:password|passwd|token|api-key|apikey|secret)(?:=|"
                + _SP
                + r")"
                + _SP
                + r"*)(?!-)[^\s\"']{3,}"
            ),
            keep_group=1,
        ),
        Rule("secret.user_percent_pass", re.compile(r"(-U" + _SP + r"+[^\s%]+%)[^\s\"']+"), keep_group=1),
        Rule(
            # "Authorization: token X" and other non-Bearer/Basic schemes (GitHub, Gitea, DRF ...).
            "secret.auth_header",
            re.compile(
                r"(?i)((?<![A-Za-z0-9_\-])(?:proxy-)?authorization\\?[\"']?"
                + _SP
                + r"{0,8}[:=]"
                + _SP
                + r"{0,8}\\?[\"']?(?:token|digest|api-?key|key|sso-key|ssws|negotiate|ntlm)"
                + _SP
                + r"{1,8})[A-Za-z0-9._~+/=\-]{8,4096}"
            ),
            keep_group=1,
        ),
        AssignmentRule(
            "secret.assignment",
            # Bounded quantifiers and a lookbehind instead of \b keep this linear on long runs of
            # identifier characters (no ReDoS).
            re.compile(
                r"(?i)(?P<key>(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]{0,64}(?:" + SECRET_KEY_WORDS + r")"
                r"[A-Za-z0-9_.\-]{0,64}\\?[\"']?)"
                r"(?P<sep>" + _SP + r"{0,8}[:=]" + _SP + r"{0,8})"
                r"(?:(?P<q1>\")(?P<v1>[^\"\\\n]{1,512})\""
                r"|(?P<q2>')(?P<v2>[^'\\\n]{1,512})'"
                r"|(?P<q3>\\\")(?P<v3>(?:[^\"\\\n]|\\[^\"\n]){1,512})\\\""
                r"|(?P<q4>\\?[\"']?)(?P<v4>(?:[^\s\"'`,;{}()\[\]\\]|\\(?![\"'])){3,512}))"
            ),
        ),
        NumericPinRule(
            "secret.pin",
            re.compile(
                r"(?i)((?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]{0,32}(?:pin|pincode|passcode|otp)[A-Za-z0-9_.\-]{0,32}"
                r"\\?[\"']?" + _SP + r"{0,8}[:=]" + _SP + r"{0,8}\\?[\"']?)\d{4,12}(?!\d)"
            ),
        ),
        EmailRule(
            "pii.email",
            re.compile(
                r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b"
            ),
        ),
        IPv4Rule("infra.ipv4", re.compile(r"(?<![\d.])\b(?:\d{1,3}\.){3}\d{1,3}\b(?!\.?\d)")),
        HomeDirRule(
            "pii.home_dir",
            re.compile(r"((?:/home/|/Users/|[A-Za-z]:\\\\?Users\\\\?)(?!\[REDACTED))[^/\\\s\"']+"),
        ),
    ]
