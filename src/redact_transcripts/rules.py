# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Redaction rules: a name, a regular expression and a replacement.

Every rule is *bound* to a :class:`~redact_transcripts.engine.Redactor` before use, so a rule can
read the redactor's configuration (marker format, keep-lists) and, for the base64 rule, call back
into the other rules.

Rule names are dotted: ``secret.*`` for credentials, ``pii.*`` for personal data and ``infra.*``
for infrastructure details. Reports and ``--disable`` use these names.

The built-in rules are the reference rule set (:mod:`redact_transcripts._scrub_rules`), in its order
and with its false-positive guards, plus a few rules of this package's own (``secret.gitlab_token``,
a newer vendor key before ``+more``, ``secret.basic_auth``, ``secret.url_credentials``,
``secret.url_token``, ``secret.cli_token_flag``, ``secret.pin`` and ``secret.base64_encoded``).
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Dict, FrozenSet, List, Optional, Tuple

from . import _scrub_rules as _sr

if TYPE_CHECKING:  # pragma: no cover
    from .engine import Redactor

Replacer = Callable[["re.Match[str]"], str]
#: ``check(match)`` of a :class:`SpanRule`: the ``(start, end)`` span to replace, or None to keep it.
Check = Callable[["re.Match[str]"], Optional[Tuple[int, int]]]

# Separators never span a newline ("[ \t]" instead of "\s") in this package's own rules.
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

    @property
    def names(self) -> Tuple[str, ...]:
        """The names this rule reports under (one, except for :class:`VendorTokenRule`)."""
        return (self.name,)

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


@dataclass(frozen=True)
class SpanRule(Rule):
    """A rule whose ``check`` picks the span to replace inside a match (the value after ``password=``,
    the user after ``/home/``), or rejects the match. Only that span becomes the marker.

    ``precheck``: lower-case substrings, one of which every match contains; text with none of them
    is skipped without a regex scan. ``binary_safe``: never fires inside base64 or a ``data:`` URI.
    """

    check: Optional[Check] = None
    precheck: Tuple[str, ...] = ()
    binary_safe: bool = False

    def span(self, m: "re.Match[str]", redactor: "Redactor") -> Optional[Tuple[int, int]]:
        return self.check(m) if self.check is not None else m.span()

    def bind(self, redactor: "Redactor") -> Replacer:
        # Used only by callers that apply the rule with ``pattern.sub``; the engine calls ``span``.
        marker = redactor.marker(self.name)

        def rep(m: "re.Match[str]") -> str:
            sp = self.span(m, redactor)
            if sp is None or sp[1] > m.end():
                return m.group(0)
            s = m.string
            return s[m.start() : sp[0]] + marker + s[sp[1] : m.end()]

        return rep


_AUTH_BEFORE = re.compile(
    r"(?i)authorization\\?[\"']?[ \t]{0,8}[:=][ \t]{0,8}(?:\r?\n[ \t]{0,8})?\\?[\"']?\Z"
)


def _bare_basic(m: "re.Match[str]") -> Optional[Tuple[int, int]]:
    if _AUTH_BEFORE.search(m.string, max(0, m.start() - 40), m.start()):
        return None  # the header form: the reference's auth_header rule decides
    return m.span("v") if _sr.sr_basic_credential(m.group("v")) else None


# The vendor of a token by its prefix (most specific first).
_VENDORS: Tuple[Tuple["re.Pattern[str]", str], ...] = tuple(
    (re.compile(p), n)
    for p, n in (
        (r"sk-ant-", "secret.anthropic_key"),
        (r"sk-or-v1-", "secret.openrouter_key"),
        (r"sk-", "secret.openai_key"),
        (r"gh[pousr]_|github_pat_", "secret.github_token"),
        (r"xox[baprs]-", "secret.slack_token"),
        (r"A[KS]IA", "secret.aws_key_id"),
        (r"AIza", "secret.google_api_key"),
        (r"ya29\.|1//", "secret.google_oauth_token"),
        (r"GOCSPX-", "secret.google_oauth_client_secret"),
        (r"gsk_", "secret.groq_key"),
        (r"xai-", "secret.xai_key"),
        (r"[rs]k_(?:live|test)_", "secret.stripe_key"),
        (r"whsec_", "secret.stripe_webhook_secret"),
        (r"[0-9a-f]{32}\.", "secret.zai_key"),
    )
)
VENDOR_RULE_NAMES: Tuple[str, ...] = tuple(dict.fromkeys(n for _p, n in _VENDORS))


def vendor_of(token: str) -> str:
    """The ``secret.*`` name of a vendor token (``secret.github_token`` for ``ghp_…``)."""
    for p, n in _VENDORS:
        if p.match(token):
            return n
    return "secret.openai_key"  # pragma: no cover - every token match starts with a known prefix


@dataclass(frozen=True)
class VendorTokenRule(SpanRule):
    """Every vendor token shape in one pass (the reference ``token`` rule), reported per vendor
    (``secret.github_token``, ``secret.aws_key_id`` …). ``enabled``: the vendor names still on."""

    enabled: FrozenSet[str] = frozenset(VENDOR_RULE_NAMES)

    @property
    def names(self) -> Tuple[str, ...]:
        return tuple(n for n in VENDOR_RULE_NAMES if n in self.enabled)

    def hit_name(self, m: "re.Match[str]", span: Tuple[int, int]) -> str:
        return vendor_of(m.string[span[0] : span[1]])

    def span(self, m: "re.Match[str]", redactor: "Redactor") -> Optional[Tuple[int, int]]:
        sp = _sr._sr_check_token(m)
        if sp is None or self.hit_name(m, sp) not in self.enabled:
            return None
        return sp


@dataclass(frozen=True)
class VendorPlusTailRule(VendorTokenRule):
    """A newer-shape key (``sk-proj-``, ``AIza``, ``ya29.``, ``1//``, ``GOCSPX-``, ``gsk_``, ``xai-``)
    followed by ``+`` and more text (``?q=gsk_<key>+more+words``), which the reference rule leaves alone
    because ``+`` continues a base64 run. Only a random-looking body outside binary data counts."""

    def span(self, m: "re.Match[str]", redactor: "Redactor") -> Optional[Tuple[int, int]]:
        tok = m.group("v")
        p = _sr._SR_V2_PFX_RE.match(tok)
        if p is None or not _sr._sr_random_body(tok[p.end() :]):
            return None
        if _sr.sr_in_binary(_sr.sr_binary_spans(m.string), m.start("v"), m.end("v")):
            return None
        sp = m.span("v")
        return sp if self.hit_name(m, sp) in self.enabled else None


_PLUS_TAIL = re.compile(
    r"(?:(?<![A-Za-z0-9+/_-])|(?<=[/_-])|(?<=%[0-9A-Fa-f]{2}))(?P<v>"
    + _sr._SR_V2_KEYS
    + r")(?=\+[A-Za-z0-9])"
)


class _Keep:
    """Checks that wrap a reference check with this package's keep-lists (``Config``)."""

    @staticmethod
    def email(check: Check) -> Callable[["re.Match[str]", "Redactor"], Optional[Tuple[int, int]]]:
        def span(m: "re.Match[str]", redactor: "Redactor") -> Optional[Tuple[int, int]]:
            sp = check(m)
            if sp is None:
                return None
            domain = m.string[sp[0] : sp[1]].rsplit("@", 1)[-1].lower()
            keep = redactor.config.email_keep_domains
            if any(domain == d or domain.endswith("." + d) for d in keep):
                return None
            return sp

        return span

    @staticmethod
    def ipv4(check: Check) -> Callable[["re.Match[str]", "Redactor"], Optional[Tuple[int, int]]]:
        def span(m: "re.Match[str]", redactor: "Redactor") -> Optional[Tuple[int, int]]:
            sp = check(m)
            if sp is None or m.string[sp[0] : sp[1]] in redactor.config.ipv4_keep:
                return None
            return sp

        return span

    @staticmethod
    def home(check: Check) -> Callable[["re.Match[str]", "Redactor"], Optional[Tuple[int, int]]]:
        def span(m: "re.Match[str]", redactor: "Redactor") -> Optional[Tuple[int, int]]:
            sp = check(m)
            # the placeholder from an earlier run (`/home/[USER]/x`) is not a user name
            if sp is None or m.string[sp[0] : sp[1]] == redactor.config.home_dir_placeholder:
                return None
            return sp

        return span


@dataclass(frozen=True)
class ConfiguredSpanRule(SpanRule):
    """A :class:`SpanRule` whose check also reads the redactor's configuration (keep-lists)."""

    configured: Optional[Callable[["re.Match[str]", "Redactor"], Optional[Tuple[int, int]]]] = None

    def span(self, m: "re.Match[str]", redactor: "Redactor") -> Optional[Tuple[int, int]]:
        assert self.configured is not None
        return self.configured(m, redactor)


@dataclass(frozen=True)
class PrivateKeyRule(Rule):
    """PEM private-key blocks (multi-line), and a key printed as a quoted list of its lines. Runs once,
    before every other rule; a key split over several JSON strings is handled by the JSONL formats."""


# --- this package's own helpers, kept for callers of earlier versions ----------------------------

# Values that look like an assignment but are clearly not a secret.
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


def secret_key_kind(key: str) -> Optional[str]:
    """What a JSON key's value is if the key names a secret (``"secret"``, ``"password"``, ``"pin"``,
    ``"auth"``, ``"cookie"``, ``"pwd"``), or None (``max_tokens``, ``token_type``, ``tokensUsed``)."""
    return _sr.sr_key_kind(key) if isinstance(key, str) else None


def is_secret_key(key: str) -> bool:
    """True if ``key`` names a secret (``GITHUB_TOKEN``) and not metadata (``max_tokens``)."""
    return secret_key_kind(key) is not None


def is_numeric_secret_key(key: str) -> bool:
    """True if an all-digit value under ``key`` is a secret (a password, secret or PIN key that is
    not a counter or metric such as ``tokensUsed`` or ``password_length``)."""
    return secret_key_kind(key) in ("password", "pin", "secret", "pwd", "auth")


def is_secret_value(value: str) -> bool:
    """True if ``value`` (found under a secret-named key) should be redacted."""
    return (
        len(value) >= 3
        and not NOT_A_SECRET_VALUE.match(value)
        and not value.startswith(("[REDACTED", "<", "$"))
    )


class NumericPinRule(Rule):
    """``pin: 1234``, ``passcode=887766``: digits under a PIN-like key (whole key words only, so
    ``mapping: 1234`` or ``spinner=5000`` are left alone)."""

    def bind(self, redactor: "Redactor") -> Replacer:
        marker = redactor.marker(self.name)

        def rep(m: "re.Match[str]") -> str:
            words = re.split(r"[^a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", m.group("k")).lower())
            if not any(w in ("pin", "pincode", "passcode", "otp") for w in words):
                return m.group(0)
            if any(w in _sr._SR_NOT_SECRET_WORDS for w in words):
                return m.group(0)
            return m.group(1) + marker

        return rep


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


def binary_spans(text: str) -> List[Tuple[int, int]]:
    """Sorted, disjoint ``(start, end)`` spans of base64 / data-URI binary data in ``text``."""
    return _sr.sr_binary_spans(text)


# --- the rule set --------------------------------------------------------------------------------

#: Reference rule name -> this package's rule name (the reference's ``token`` is reported per vendor).
REFERENCE_NAMES: Dict[str, str] = {
    "token_tail": "secret.token_tail",
    "auth_header": "secret.auth_header",
    "bearer": "secret.bearer",
    "digest": "secret.digest",
    "aws_signature": "secret.aws_signature",
    "quoted_assignment": "secret.quoted_assignment",
    "json_assignment": "secret.json_assignment",
    "nested_assignment": "secret.nested_assignment",
    "assignment": "secret.assignment",
    "weakpass": "secret.weakpass",
    "inline_userpass": "secret.user_percent_pass",
    "cmd_password": "secret.cli_flag",
    "cmd_userpass": "secret.cmd_userpass",
    "pass_assignment": "secret.pass_assignment",
    "mysql_password": "secret.mysql_password",
    "jwt": "secret.jwt",
    "secret.gsheet": "secret.gsheet",
    "infra.mac": "infra.mac",
    "infra.ipv6": "infra.ipv6",
    "infra.ip": "infra.ipv4",
    "infra.keyfile": "infra.keyfile",
    "pii.email": "pii.email",
    "pii.homedir": "pii.home_dir",
}

#: The reference rules that never fire inside binary data (personal data, IPs and paths).
_BINARY_SAFE = frozenset(REFERENCE_NAMES[n] for n in _sr.SR_PII_RULES)


def _shared(name: str, pattern: "re.Pattern[str]", check: Check) -> SpanRule:
    return SpanRule(
        REFERENCE_NAMES[name],
        pattern,
        check=check,
        precheck=tuple(_sr.SR_PRECHECK.get(name, ()) or _sr.SR_EXTRA_PRECHECK.get(name, ())),
        binary_safe=REFERENCE_NAMES[name] in _BINARY_SAFE,
    )


def default_rules() -> List[Rule]:
    """The built-in rule set, in order. Specific token shapes run before generic ones, so a known
    token is reported under its own rule rather than as a generic assignment; a bare JWT runs last."""
    secret = {n: (p, c) for n, p, c in _sr.sr_rules(raw_json=False)}
    extra = {n: (p, c) for n, p, c, _mark in _sr.sr_extra_rules(raw_json=False)}

    def ref(name: str) -> SpanRule:
        return _shared(name, *(secret.get(name) or extra[name]))

    token_pattern, _ = secret["token"]
    email_p, email_c = extra["pii.email"]
    ip_p, ip_c = extra["infra.ip"]
    home_p, home_c = extra["pii.homedir"]
    return [
        PrivateKeyRule("secret.private_key", _sr.SR_PEM_BEGIN),
        VendorTokenRule("secret.vendor_token", token_pattern),
        Rule("secret.gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,4096}")),
        ref("token_tail"),
        VendorPlusTailRule("secret.vendor_token_plus", _PLUS_TAIL),
        ref("auth_header"),
        ref("bearer"),
        SpanRule(
            # A bare `Basic <credential>` with no header name (`secret.auth_header` owns the header form),
            # judged like the header's value.
            "secret.basic_auth",
            re.compile(
                r"(?i)\bbasic" + _SP + r"+(?!\[REDACTED)(?P<v>[A-Za-z0-9+/]{12,4096}={0,2})(?![A-Za-z0-9+/=])"
            ),
            check=_bare_basic,
            precheck=("basic",),
        ),
        Rule(
            "secret.url_credentials",
            re.compile(
                r"(?i)((?<![a-z0-9+.\-])[a-z][a-z0-9+.\-]{0,31}://)(?!\[REDACTED)"
                r"[^/\s:@\"'\\]{1,256}:[^/\s@\"'\\]{1,256}(?=@)"
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
        ref("digest"),
        ref("aws_signature"),
        ref("quoted_assignment"),
        ref("json_assignment"),
        ref("nested_assignment"),
        ref("assignment"),
        ref("weakpass"),
        ref("inline_userpass"),
        ref("cmd_password"),
        Rule(
            # `--token X`, `--api-key=X`, `--secret X` (the password flags are the rule above).
            "secret.cli_token_flag",
            re.compile(
                r"(?i)((?<![A-Za-z0-9_-])--(?:token|api-key|apikey|secret)(?:=|"
                + _SP
                + r")"
                + _SP
                + r"*)(?!-|\[REDACTED)[^\s\"']{3,}"
            ),
            keep_group=1,
        ),
        ref("cmd_userpass"),
        ref("pass_assignment"),
        ref("mysql_password"),
        NumericPinRule(
            "secret.pin",
            re.compile(
                r"(?i)((?<![A-Za-z0-9_.\-])(?P<k>[A-Za-z0-9_.\-]{0,32}(?:pin|pincode|passcode|otp)"
                r"[A-Za-z0-9_.\-]{0,32})\\?[\"']?"
                + _SP
                + r"{0,8}[:=]"
                + _SP
                + r"{0,8}\\?[\"']?)\d{4,12}(?!\d)"
            ),
        ),
        Base64Rule(
            "secret.base64_encoded",
            re.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=_\-])"),
        ),
        ref("secret.gsheet"),
        ref("infra.mac"),
        ref("infra.ipv6"),
        ConfiguredSpanRule(
            "infra.ipv4", ip_p, precheck=(".",), binary_safe=True, configured=_Keep.ipv4(ip_c)
        ),
        ref("infra.keyfile"),
        ConfiguredSpanRule(
            "pii.email",
            email_p,
            precheck=_sr.SR_EXTRA_PRECHECK["pii.email"],
            binary_safe=True,
            configured=_Keep.email(email_c),
        ),
        ConfiguredSpanRule(
            "pii.home_dir",
            home_p,
            precheck=_sr.SR_EXTRA_PRECHECK["pii.homedir"],
            binary_safe=True,
            configured=_Keep.home(home_c),
        ),
        ref("jwt"),
    ]
