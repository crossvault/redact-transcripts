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
import bisect
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, List, Optional, Tuple

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


# --- Vendor token shapes -------------------------------------------------------------------------
#
# A vendor token is recognised in five positions (the named groups of a VendorKeyRule):
#
# * ``plain``: after a word boundary (prose, ``key=…``, a JSON string);
# * ``us``: right after ``_`` (``CONF_ghp_…``) or a URL escape (``?k=%20AKIA…``), where ``\b`` never fires;
# * ``sep``: right after ``+``, ``/`` or a URL escape (the newer, ``v2`` shapes only);
# * ``esc``: right after a literal ``\n``, ``\r`` or ``\t`` escape (a token at the start of a line in
#   raw JSON text), whose letter is a word character;
# * ``glued``: glued straight onto a letter or digit (``notesghp_…``), exact vendor shape only.
#
# Outside ``plain`` the surroundings look like an identifier, so the body must look random (mixed
# case, or digit-dense): ``slack_xoxb-tokens-and-scopes-guide`` stays a name. A classic token may end
# right before ``_`` (``ghp_…_notes``) unless that ``_`` opens the next token; one followed by ``_``
# must look random too, so ``sk_test_mode_runner_config`` stays a name. Nothing inside base64 or a
# ``data:`` URI is redacted, so binary data is never corrupted.
#
# Every body run is bounded and followed by something it cannot contain, so each rule stays linear.

_CLASSIC_PFX = r"gh[pousr]_|github_pat_|sk-|xox[abposr]-|AKIA|ASIA|(?:sk|rk)_(?:live|test)_|whsec_"
_V2_PFX = r"sk-(?:proj|svcacct|admin|or-v1)-|AIza|ya29\.|1//|GOCSPX-|gsk_|xai-"
_US_BODY = r"(?:[A-Za-z0-9-]|_(?!" + _CLASSIC_PFX + "|" + _V2_PFX + r"))"
_V2_US_BODY = r"(?:[A-Za-z0-9-]|_(?!" + _V2_PFX + r"))"
# Where a classic token ends: a word boundary, or right before ``_`` unless that ``_`` opens the next
# token together with the letters before it (``xoxb-notes-ghp_…``).
_CLS_END = r"(?:\b|(?=_)(?!(?<=gh[pousr])_|(?<=github)_pat_|(?<=[sr]k)_(?:live|test)_|(?<=whsec)_|(?<=gsk)_))"
# A newer-shape body never contains `/`, `+` or `=`, so a token may end right before one
# (`…/keys/gsk_<key>/rotate`). Binary data is excluded by `binary_spans`, not by this end.
_V2_END = r"(?![A-Za-z0-9_-])"
_PFX_RE = re.compile(_CLASSIC_PFX + "|" + _V2_PFX)
_WORDY_PFX = re.compile(r"xox[abposr]-|sk-ant-|github_pat_")
_UPPER = re.compile(r"[A-Z]")
_LOWER = re.compile(r"[a-z]")
_DIGIT = re.compile(r"[0-9]")


def _v2_body_like_key(body: str) -> bool:
    """A newer-shape key body, not a word run: it mixes upper and lower case, or it is a digit-dense
    run without ``-``/``_`` (4+ digits that make up a quarter of it). A URL path such as
    ``xai-api-reference-v2-2024-guide`` stays a word."""
    if _UPPER.search(body) and _LOWER.search(body):
        return True
    if "-" in body or "_" in body:
        return False
    d = len(_DIGIT.findall(body))
    return d >= 4 and d * 4 >= len(body)


def _classic_body_like_key(body: str) -> bool:
    """A classic key body: any upper-case letter, or 4+ digits making up a quarter of its letters and
    digits. Only an all-lower-case, digit-light run (``notes-for-docs``) stays a name."""
    if _UPPER.search(body):
        return True
    alnum = len(body) - body.count("-") - body.count("_")
    d = len(_DIGIT.findall(body))
    return d >= 4 and d * 4 >= alnum


_V2_PFX_RE = re.compile(_V2_PFX)


def _strip_prefix(token: str, pfx: "re.Pattern[str]" = _PFX_RE) -> str:
    p = pfx.match(token)
    return token[p.end() :] if p else token


# Binary data: a ``data:…;base64,`` URI, a 200+ character base64 run, or base64 wrapped at 64 or 76
# columns with escaped line breaks (``\n`` inside a JSON string). Real line breaks are not joined, so
# redacting a stream line by line gives the same result as redacting the whole text.
_DATA_URI = re.compile(r"data:[A-Za-z0-9.+/-]{1,64}(?:;[A-Za-z0-9=._-]{1,64}){0,4};base64,[A-Za-z0-9+/=]*")
_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{200,}")
_PATH_PREFIX = re.compile(r"(?:/[A-Za-z0-9+=]{1,64}){1,32}/")
_WRAP_SEP = r"(?:(?:\\{1,2}r)?\\{1,2}n)"


def _wrapped(w: int) -> str:
    line, sep = "[A-Za-z0-9+/]{" + str(w) + "}", _WRAP_SEP
    tail = "(?:" + sep + "[A-Za-z0-9+/]{0," + str(w - 1) + "}={1,2})?"
    last = line + tail + "|[A-Za-z0-9+/]{" + str(w - 1) + "}=|[A-Za-z0-9+/]{" + str(w - 2) + "}=="
    return "(?:" + line + sep + "){2,}(?:" + last + ")(?![A-Za-z0-9+/=])"


_B64_WRAPPED = re.compile(
    r"(?:(?<![A-Za-z0-9+/=])|(?<=\\n)|(?<=\\r))(?:" + _wrapped(76) + "|" + _wrapped(64) + ")"
)


def _looks_binary(run: str) -> bool:
    return bool(_UPPER.search(run) and _LOWER.search(run) and _DIGIT.search(run))


def binary_spans(text: str) -> List[Tuple[int, int]]:
    """Sorted, disjoint ``(start, end)`` spans of base64 / data-URI binary data in ``text``."""
    spans = [m.span() for m in _DATA_URI.finditer(text)]
    for m in _B64_RUN.finditer(text):
        run, start = m.group(0), m.start()
        if run[0] == "/":  # a leading path (``/home/user/<base64 name>``) is not binary data
            pm = _PATH_PREFIX.match(run)
            if pm:
                run, start = run[pm.end() - 1 :], start + pm.end() - 1
                if len(run) < 200:
                    continue
        if "+" in run and run.count("/") * 16 < len(run) and _looks_binary(run):
            spans.append((start, m.end()))
    for m in _B64_WRAPPED.finditer(text):
        run = m.group(0)
        if ("+" in run or "/" in run) and _looks_binary(run):
            spans.append(m.span())
    spans.sort()
    merged: List[Tuple[int, int]] = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged


def _in_spans(spans: List[Tuple[int, int]], s: int, e: int) -> bool:
    i = bisect.bisect_right(spans, (s, float("inf"))) - 1
    return i >= 0 and spans[i][1] >= e


_POSITIONS = ("plain", "us", "sep", "esc", "glued", "usc", "escc")
# ``usc``/``escc``: the classic-kind alternatives (``sk-<alnum>``) of a newer-kind rule.
_CLASSIC_ALT = {"usc": "us", "escc": "esc"}


@dataclass(frozen=True)
class VendorKeyRule(Rule):
    """A vendor token shape, recognised in every position listed above. ``kind`` is ``classic`` or
    ``v2`` and picks the body test for the identifier-like positions."""

    kind: str = "classic"
    #: ``v2``: the body after the newer-shape prefix must look random in every position, plain
    #: included (shapes that also read as code or a package name: ``1//``, ``xai-``, ``gsk_`` …).
    #: ``dot``: the part after the last ``.`` must look random (``<32 hex>.<16 chars>``).
    strict: str = ""

    def accepts(self, m: "re.Match[str]", group: str) -> bool:
        token = m.group(group)
        body = _strip_prefix(token)
        if group == "glued":
            return _classic_body_like_key(body)
        if self.strict == "v2" and not _v2_body_like_key(_strip_prefix(token, _V2_PFX_RE)):
            return False
        if self.strict == "dot" and not _v2_body_like_key(token.rsplit(".", 1)[-1]):
            return False
        if self.kind != "classic" and group not in _CLASSIC_ALT:
            return group not in ("us", "sep") or _v2_body_like_key(_strip_prefix(token, _V2_PFX_RE))
        group_name, group = group, _CLASSIC_ALT.get(group, group)
        if m.string[m.end(group_name) : m.end(group_name) + 1] == "_" and not _classic_body_like_key(body):
            return False
        if group == "us":
            w = _WORDY_PFX.match(token)
            if w and not _classic_body_like_key(token[w.end() :]):
                return False
        return True

    def bind(self, redactor: "Redactor") -> Replacer:
        marker = redactor.marker(self.name)
        # The binary spans of the last text seen: one pass per text, keyed by identity, never held.
        cache: List[Tuple[Tuple[int, int, int], List[Tuple[int, int]]]] = []

        def rep(m: "re.Match[str]") -> str:
            group = next(g for g in _POSITIONS if m.groupdict().get(g) is not None)
            if not self.accepts(m, group):
                return m.group(0)
            s = m.string
            key = (id(s), len(s), hash(s))
            if not cache or cache[0][0] != key:
                cache[:] = [(key, binary_spans(s))]
            if _in_spans(cache[0][1], m.start(group), m.end(group)):
                return m.group(0)
            return s[m.start() : m.start(group)] + marker + s[m.end(group) : m.end()]

        return rep


def _vendor(
    name: str,
    *,
    kind: str,
    plain: str,
    us: Optional[str] = None,
    sep: Optional[str] = None,
    esc: Optional[str] = None,
    glued: Optional[str] = None,
    us_classic: Optional[str] = None,
    esc_classic: Optional[str] = None,
    strict: str = "",
) -> VendorKeyRule:
    """Build a :class:`VendorKeyRule`. ``plain`` carries its own start and end; the other shapes get
    the start of their position and the end of their kind."""
    end = _CLS_END if kind == "classic" else _V2_END
    parts = [r"(?P<plain>" + plain + r")"]
    if us:
        parts.append(r"(?:(?<=_)|(?<=%[0-9A-Fa-f]{2}))(?P<us>" + us + r")" + end)
    if sep:
        parts.append(r"(?:(?<=[+/])|(?<=%[0-9A-Fa-f]{2}))(?P<sep>" + sep + r")" + end)
    if esc:
        parts.append(r"(?<=\\[nrt])(?P<esc>" + esc + r")" + end)
    if glued:
        parts.append(r"(?<=[A-Za-z0-9])(?P<glued>" + glued + r")(?![A-Za-z0-9])")
    if us_classic:
        parts.append(r"(?:(?<=_)|(?<=%[0-9A-Fa-f]{2}))(?P<usc>" + us_classic + r")" + _CLS_END)
    if esc_classic:
        parts.append(r"(?<=\\[nrt])(?P<escc>" + esc_classic + r")" + _CLS_END)
    return VendorKeyRule(name, re.compile("|".join(parts)), kind=kind, strict=strict)


def _v2_plain(shape: str) -> str:
    return r"(?<![A-Za-z0-9+/_-])(?:" + shape + r")" + _V2_END


def vendor_rules() -> List[VendorKeyRule]:
    """The vendor token shapes, most specific first (``sk-ant-`` before ``sk-or-v1-`` before ``sk-``)."""
    return [
        _vendor(
            "secret.anthropic_key",
            kind="classic",
            plain=r"\bsk-ant-[A-Za-z0-9_\-]{10,4096}",
            us=r"sk-ant-" + _US_BODY + r"{12,256}",
            esc=r"sk-ant-[A-Za-z0-9_-]{12,4096}",
            glued=r"sk-ant-(?:api|admin|oat|ort)[0-9]{2}-[A-Za-z0-9_-]{40,256}",
        ),
        _vendor(
            "secret.openrouter_key",
            kind="v2",
            plain=_v2_plain(r"sk-or-v1-[A-Za-z0-9_-]{20,4096}"),
            us=r"sk-or-v1-" + _V2_US_BODY + r"{20,256}",
            sep=r"sk-or-v1-[A-Za-z0-9_-]{20,4096}",
            esc=r"sk-or-v1-[A-Za-z0-9_-]{20,4096}",
            glued=r"sk-or-v1-[A-Za-z0-9_-]{40,256}",
        ),
        _vendor(
            "secret.openai_key",
            kind="v2",
            plain=r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,4096}",
            us=r"sk-(?:proj|svcacct|admin)-" + _V2_US_BODY + r"{20,256}",
            sep=r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,4096}",
            esc=r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,4096}",
            us_classic=r"sk-[A-Za-z0-9]{20,4096}",
            esc_classic=r"sk-[A-Za-z0-9]{20,4096}",
            glued=r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,256}|sk-[A-Za-z0-9]{48}",
        ),
        _vendor(
            "secret.github_token",
            kind="classic",
            plain=r"\b(?:gh[pousr]_[A-Za-z0-9]{20,4096}|github_pat_[A-Za-z0-9_]{20,4096})" + _CLS_END,
            us=r"gh[pousr]_[A-Za-z0-9]{20,4096}|github_pat_" + _US_BODY + r"{20,256}",
            esc=r"gh[pousr]_[A-Za-z0-9]{20,4096}|github_pat_[A-Za-z0-9_]{20,4096}",
            glued=r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
        ),
        _vendor("secret.gitlab_token", kind="classic", plain=r"\bglpat-[A-Za-z0-9_\-]{20,4096}"),
        _vendor(
            "secret.slack_token",
            kind="classic",
            plain=r"\bxox[abposr]-[A-Za-z0-9\-]{10,4096}",
            us=r"xox[abposr]-[A-Za-z0-9-]{10,4096}",
            esc=r"xox[abposr]-[A-Za-z0-9-]{10,4096}",
            glued=r"xox[abposr]-[0-9]{1,16}-[A-Za-z0-9-]{10,256}",
        ),
        _vendor(
            "secret.aws_key_id",
            kind="classic",
            plain=r"\b(?:AKIA|ASIA)[0-9A-Z]{16}" + _CLS_END,
            us=r"(?:AKIA|ASIA)[0-9A-Z]{16}",
            esc=r"(?:AKIA|ASIA)[0-9A-Z]{16}",
            glued=r"(?:AKIA|ASIA)[0-9A-Z]{16}",
        ),
        _vendor(
            "secret.google_api_key",
            kind="v2",
            plain=r"\bAIza[0-9A-Za-z_\-]{35}",
            us=r"AIza" + _V2_US_BODY + r"{35}",
            sep=r"AIza[0-9A-Za-z_-]{35}",
            esc=r"AIza[0-9A-Za-z_-]{35}",
        ),
        _vendor(
            "secret.google_oauth_token",
            kind="v2",
            # Refresh tokens start `1//0`; `n = 1//batch_size` is floor division.
            plain=_v2_plain(r"ya29\.[0-9A-Za-z_-]{20,4096}|1//0[0-9A-Za-z_-]{30,4096}"),
            us=r"ya29\." + _V2_US_BODY + r"{20,4096}|1//0" + _V2_US_BODY + r"{30,4096}",
            sep=r"ya29\.[0-9A-Za-z_-]{20,4096}|1//0[0-9A-Za-z_-]{30,4096}",
            esc=r"ya29\.[0-9A-Za-z_-]{20,4096}|1//0[0-9A-Za-z_-]{30,4096}",
            strict="v2",
        ),
        _vendor(
            "secret.google_oauth_client_secret",
            kind="v2",
            plain=_v2_plain(r"GOCSPX-[0-9A-Za-z_-]{20,256}"),
            us=r"GOCSPX-" + _V2_US_BODY + r"{20,256}",
            sep=r"GOCSPX-[0-9A-Za-z_-]{20,256}",
            esc=r"GOCSPX-[0-9A-Za-z_-]{20,256}",
            strict="v2",
        ),
        _vendor(
            "secret.groq_key",
            kind="v2",
            plain=_v2_plain(r"gsk_[A-Za-z0-9_-]{20,4096}"),
            us=r"gsk_" + _V2_US_BODY + r"{20,256}",
            sep=r"gsk_[A-Za-z0-9_-]{20,4096}",
            esc=r"gsk_[A-Za-z0-9_-]{20,4096}",
            strict="v2",
        ),
        _vendor(
            "secret.xai_key",
            kind="v2",
            plain=_v2_plain(r"xai-[A-Za-z0-9_-]{20,4096}"),
            us=r"xai-" + _V2_US_BODY + r"{20,256}",
            sep=r"xai-[A-Za-z0-9_-]{20,4096}",
            esc=r"xai-[A-Za-z0-9_-]{20,4096}",
            strict="v2",
        ),
        _vendor(
            "secret.stripe_key",
            kind="classic",
            plain=r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,4096}" + _CLS_END,
            us=r"[rs]k_(?:live|test)_[A-Za-z0-9]{16,4096}",
            esc=r"[rs]k_(?:live|test)_[A-Za-z0-9]{16,4096}",
            glued=r"[rs]k_(?:live|test)_[A-Za-z0-9]{24,256}",
        ),
        _vendor(
            "secret.stripe_webhook_secret",
            kind="classic",
            plain=r"\bwhsec_[A-Za-z0-9]{16,4096}" + _CLS_END,
            us=r"whsec_[A-Za-z0-9]{16,4096}",
            esc=r"whsec_[A-Za-z0-9]{16,4096}",
            glued=r"whsec_[A-Za-z0-9]{32,256}",
        ),
        _vendor(
            "secret.zai_key",
            kind="classic",
            plain=r"\b[0-9a-f]{32}\.[A-Za-z0-9]{16}" + _CLS_END,
            us=r"[0-9a-f]{32}\.[A-Za-z0-9]{16}",
            esc=r"[0-9a-f]{32}\.[A-Za-z0-9]{16}",
            strict="dot",
        ),
    ]


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
        *vendor_rules(),
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
