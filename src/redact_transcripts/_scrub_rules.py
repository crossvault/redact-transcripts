# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""The reference rule set: the transcript scrubber that a4sx runs, ported with its rules, their order
and their false-positive guards unchanged (see ``tests/test_parity.py``).

:mod:`redact_transcripts.rules` wraps these as :class:`~redact_transcripts.rules.Rule` objects and
:mod:`redact_transcripts.engine` applies them; nothing here is public API.

`sr_rules(raw_json)` builds the secret rules for one of two inputs:

- `raw_json=False`: plain text, or one string decoded from a JSONL transcript (what this package uses);
- `raw_json=True`: the raw bytes of a JSONL line. A redaction may then never cut a JSON escape in half
  or swallow a quote: value runs stop at a backslash (or take a JSON escape whole), and a quote inside a
  JSON string is matched in its escaped `\\"` form.

Each rule is (name, pattern, check). `check(match)` returns the (start, end) span of the secret, or
None when the match is not a secret after all (a placeholder, a counter key, prose). The caller
replaces only that span and keeps everything else, so a scheme word, a key and its quotes survive.
`sr_extra_rules(...)` adds the Sheet-id, personal-data, IP and path rules, as
(name, pattern, check, marker).

Every pattern is linear-time: bounded quantifiers only, no nested unbounded groups, and each rule
starts at a literal anchor (a keyword or a quote). There are no possessive quantifiers or atomic
groups (those need Python 3.11).

Where the comments say "develop", "the reference run" or "the earlier rule", they mean the rule set
as it was before a later refinement; the name-exemption reconciliation (sr_name_reconciled) runs both.
"""

# ruff: noqa
# This file is kept as close to the reference as possible (so a later sync is a diff, not a rewrite);
# it is excluded from the formatter and the linter in pyproject.toml.

import base64 as _sr_base64
import binascii as _sr_binascii
import bisect as _sr_bisect
import functools as _sr_functools
import json as _sr_json
import re as _sr_re
import threading as _sr_threading

SR_VALUE_MAX = 65536    # longest value a rule redacts whole; bounded so every rule stays linear
_SR_N = str(SR_VALUE_MAX)
# An existing redaction marker: `[REDACTED]`, `[REDACTED-SECRET]`, `[REDACTED-USER]` ..., or this
# package's default marker, which names its rule (`[REDACTED:secret.github_token]`).
_SR_MARK = r"\[REDACTED(?:[A-Z-]{0,24}|:[a-z0-9_.]{1,64})\]"
# A marker a SECRET rule left (token_tail continues a key after it, never after a personal-data marker).
_SR_SECRET_MARK = r"\[REDACTED(?:-SECRET)?\]|\[REDACTED:secret\.[a-z0-9_.]{1,64}\]"

# --- key names ------------------------------------------------------------------------------------
# A key NAMES a secret if its words (`FAKE_DB_PASSWORD` -> fake db password, `tokensUsed` -> tokens
# used) end in a secret suffix or a short secret word, and no word marks it as a counter or metadata
# (`max_token`, `input_tokens`, `token_type`, `next_page_token`, `password_length`, `api_key_env`).
_SR_SECRET_SUFFIXES = ("password", "passwords", "passwd", "passphrase", "passcode", "secret", "secrets",
                       "token", "apikey", "apikeys",
                       "accesskey", "privatekey", "secretkey", "signingkey", "credential", "credentials")
_SR_NUMERIC_WORDS = frozenset({"password", "passwd", "passphrase", "passcode", "pass", "pwd", "secret",
                               "cvv", "cvc"})
_SR_NOT_SECRET_WORDS = frozenset({
    "count", "counts", "used", "total", "num", "number", "max", "min", "limit", "size", "length", "len",
    "ttl", "seconds", "secs", "sec", "ms", "index", "idx", "version", "rate", "usage", "budget",
    "remaining", "left", "attempts", "retries", "tokens", "age", "expiry", "expires", "timeout", "type",
    "next", "page", "cursor", "policy", "hint", "name", "names", "path", "file", "rotation", "has", "is"})
# Compound key words the text assignment rules also start at (the keyword alone is followed by
# `_KEY`, not by `=`): Django's `SECRET_KEY=`, `AWS_SECRET_ACCESS_KEY=`, `SIGNING_KEY=`.
_SR_KEY_WORDS = ("secret_key", "secret-key", "secretkey", "secret_access_key", "signing_key", "signing-key")
_SR_KEY_PRE = ("pass", "secret", "token", "key", "cred", "auth", "pwd", "pin", "otp", "cookie")
_SR_CAMEL = _sr_re.compile(r"([a-z0-9])([A-Z])")
_SR_NON_ALNUM = _sr_re.compile(r"[^a-z0-9]+")


def sr_is_path_key(key: str) -> bool:
    """An absolute or home path used as a key (`/srv/app/.aws/credentials`, `~/x`, `C:\\x`): DATA, not
    a secret's name. A relative path is a path only in context (see the JSONL formats' trackedFileBackups)."""
    return (key[:1] in ("/", "~", "\\") or key[:2] in ("./", "..") or "://" in key
            or (len(key) > 2 and key[1] == ":" and key[2] in "\\/"))


@_sr_functools.lru_cache(maxsize=8192)
def sr_key_kind(key: str):
    """What a key's value is, if the key names a secret: None (not a secret key), "secret",
    "password" (all-digit values are secrets too), "pwd" (`pwd`: a path value is a directory),
    "pin" (only digits are secrets), "auth" (only credential-shaped values) or "cookie" (only
    `name=value` values). Cached: a transcript repeats the same few hundred keys."""
    if len(key) > 128 or sr_is_path_key(key):
        return None
    low = key.lower()
    if not any(p in low for p in _SR_KEY_PRE):
        return None
    words = [w for w in _SR_NON_ALNUM.split(_SR_CAMEL.sub(r"\1 \2", key).lower()) if w]
    if not words or any(w in _SR_NOT_SECRET_WORDS for w in words):
        return None
    last, joined = words[-1], "".join(words)
    if last in ("pin", "otp"):
        return "pin"
    if joined.endswith(_SR_SECRET_SUFFIXES):
        return "password" if any(w in _SR_NUMERIC_WORDS or w.startswith(("password", "secret"))
                                 for w in words) else "secret"
    if joined.endswith("authorization") or last == "auth":
        return "auth"
    if last in ("cookie", "cookies"):
        return "cookie"
    if last == "pwd":
        return "pwd"
    if last == "pass":
        return "password"
    return None


# --- values ---------------------------------------------------------------------------------------
_SR_NOT_A_VALUE = frozenset({"true", "false", "null", "none", "nil", "undefined", "***", "...", "bearer",
                             "basic", "digest", "token"})
_SR_PLACEHOLDER = _sr_re.compile(
    r"\$\{[^{}\n]{1,128}\}|\$[A-Z_][A-Z0-9_]{1,127}|\{\{[^{}\n]{1,128}\}\}|<[^<>\n]{1,128}>"
    r"|%\([A-Za-z0-9_]{1,64}\)s|[*x.\u2022_-]{3,64}"
    r"|(?i:your|insert|enter|replace)[_ -][A-Za-z0-9_ .-]{1,64}"
    # an environment-variable NAME, not its value: OPENAI_API_KEY, GITHUB_TOKEN, YOUR_API_KEY
    r"|[A-Z][A-Z0-9]{0,31}(?:_[A-Z0-9]{1,31}){0,7}_(?:API_?KEY|KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|PWD"
    r"|CREDENTIALS?)")
_SR_CRED = _sr_re.compile(r"[A-Za-z0-9._~+/=:\-]{6,65536}")
_SR_SCHEME = _sr_re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,19}")
_SR_KNOWN_SCHEMES = frozenset({"bearer", "token", "bot", "apikey", "api-key", "key", "sso-key", "jwt",
                               "dpop", "hmac", "negotiate", "ntlm", "oauth", "pat"})


def sr_is_placeholder(value: str) -> bool:
    """A value that stands in for a secret: `${SECRET_KEY}`, `$TOKEN`, `<your token>`, `{{ token }}`,
    `****`, `YOUR_API_KEY`, `OPENAI_API_KEY` (the variable's NAME), `true`/`null`, or a marker."""
    v = value.strip()
    return (v.lower() in _SR_NOT_A_VALUE or v.startswith("[REDACTED")
            or _SR_PLACEHOLDER.fullmatch(v) is not None)


def sr_basic_credential(value: str) -> bool:
    """A `Basic` credential: base64 with an upper-case letter, digit or `+/=` after its first
    character (`dXNlcjpwYXNz`; `Authentication` has only its capital), or base64 that decodes to
    `user:pass` (an all-lower-case one)."""
    if not _sr_re.fullmatch(r"[A-Za-z0-9+/=]{8,65536}", value):
        return False
    if _sr_re.search(r"[A-Z0-9+/=]", value[1:]):
        return True
    return sr_b64_userpass(value)


def sr_b64_userpass(value: str) -> bool:
    """Base64 that decodes to printable `user:pass`: a Basic credential written without its scheme
    (`Authorization: dXNlcjpwYXNz`, `{"auth": "dXNlcjpwYXNz"}`). An English word almost never does."""
    if not _sr_re.fullmatch(r"[A-Za-z0-9+/=]{8,65536}", value):
        return False
    try:
        raw = _sr_base64.b64decode(value + "=" * (-len(value) % 4), validate=True).decode("ascii")
    except (_sr_binascii.Error, ValueError):
        return False
    user, sep, pw = raw.partition(":")
    return bool(sep and user and pw and raw.isprintable())


def sr_auth_value(value: str) -> bool:
    """An Authorization (or `auth`) value that holds a credential, not prose: `user:pass`, a single
    credential-shaped token (a digit, a colon or 20+ characters), `<scheme> <credential>`, or a Digest
    or AWS4 parameter list. `required`, `see RFC 7235` and `Bearer` alone are prose."""
    parts = value.split()
    if not parts or sr_is_placeholder(value):
        return False
    head = parts[0].lower()
    if len(parts) == 1:
        t = parts[0]
        return (_SR_CRED.fullmatch(t) is not None
                and (any(c.isdigit() for c in t) or len(t) >= 20 or (":" in t[1:-1] and len(t) >= 3)
                     or sr_b64_userpass(t)))
    if head == "digest" or head.startswith("aws4-"):
        return "=" in value
    if len(parts) != 2 or not _SR_SCHEME.fullmatch(parts[0]) or sr_is_placeholder(parts[1]):
        return False
    if head == "basic":
        return sr_basic_credential(parts[1])
    t = parts[1]
    if _SR_CRED.fullmatch(t) is None:
        return False
    return len(t) >= 8 if head in _SR_KNOWN_SCHEMES else (any(c.isdigit() for c in t) or len(t) >= 20)


def sr_secret_value(kind, value) -> bool:
    """Whether a scalar under a key of this `kind` (see sr_key_kind) is the secret itself."""
    if kind is None or isinstance(value, bool):
        return False
    if isinstance(value, int):
        value = str(abs(value))
    if not isinstance(value, str):
        return False
    v = value.strip()
    if v.isdigit():                     # `token: 4096` is a count; a PIN or a numeric password is not
        need = {"secret": 12, "auth": 6}.get(kind, 4)
        return len(v) >= need
    if kind == "pin" or len(v) < 3 or sr_is_placeholder(v):
        return False
    if kind == "auth":
        return sr_auth_value(v)
    if kind == "cookie":
        return "=" in v
    if kind == "pwd" and v.startswith(("/", "~")):
        return False
    return True


# --- rules ----------------------------------------------------------------------------------------
# Values that are code rather than data (secret.assignment): typing names only when followed by `[`,
# `,`, `)`, `|`, `=` or the end of the value, and identifier references that END in a secret word
# (`read_token`), so a weak real password like `mysecret` is still redacted.
SR_TYPING_VALUE = (r"(?!(?:typing\.)?(?:Optional|Union|List|Dict|Tuple|Set|Any|Callable|Mapping|Sequence|"
                   r"Literal|Annotated|str|bytes|int|bool|None)(?:\[|[,)|=\s]|$))")
SR_CODE_VALUE = SR_TYPING_VALUE[:-1] + (r"|(?:[a-z0-9]{1,64}_){1,16}(?:api_?key|key|secret|token|passwd|password|"
                                        r"credential|creds?)s?(?![A-Za-z0-9._\-/+]))")


def _sr_span(*groups):
    def check(m):
        for g in groups:
            if m.group(g) is not None:
                return m.span(g)
        return None
    return check


_SR_V2_PFX = r"sk-(?:proj|svcacct|admin|or-v1)-|AIza|ya29\.|1//|GOCSPX-|gsk_|xai-"
_SR_CLASSIC_PFX = r"gh[pousr]_|github_pat_|sk-|xox[baprs]-|A[KS]IA|(?:sk|rk)_(?:live|test)_|whsec_"
# a classic key body never runs into a newer key's letter-led prefix written right after
# it (`ghp_<36>AIza…`, `sk_live_<24>ya29.…`): the body ends there and the newer key keeps its own start.
# The lookahead is a fixed set of short literals, so each step stays constant-time.
# only where a whole newer key starts (prefix plus its minimum body). A newer
# prefix's letters inside a random classic body (`github_pat_…AIza…`) no longer cut it short. Bounded.
# an `AIza` key's 35 body characters hold no other newer key's prefix with a `-`/`_`.
# `AIza<8>` at the end of a `ya29.` body, followed by `sk-proj-…`, is body: the `ya29.` body used to stop at
# it and leave those 12 characters behind. Bounded (35 steps, each a few literals).
_SR_V2_HEADS = (r"sk-(?:proj|svcacct|admin|or-v1)-[A-Za-z0-9_-]{20}|"
                r"AIza(?:(?!sk-(?:proj|svcacct|admin|or-v1)-|GOCSPX-|gsk_|xai-)[0-9A-Za-z_-]){35}|"
                r"ya29\.[0-9A-Za-z_-]{20}|1//[0-9A-Za-z_-]{30}|GOCSPX-[0-9A-Za-z_-]{20}|gsk_[A-Za-z0-9_-]{20}|"
                r"xai-[A-Za-z0-9_-]{20}")
_SR_NOT_V2 = r"(?!" + _SR_V2_HEADS + r")"


def _sr_cb(cls):
    return "(?:" + _SR_NOT_V2 + "[" + cls + "])"


def _sr_cbr(cls, lo, hi):
    """A classic body of lo..hi characters whose first lo never stop: a newer key's letters inside the
    minimum body (`sk-<3>AIza…`) are body, not the start of a glued key."""
    return "[" + cls + "]{" + str(lo) + "}" + _sr_cb(cls) + "{0," + str(hi - lo) + "}"


# past its minimum, a newer key's body ends where another whole newer key
# starts (`sk-proj-<120>ya29.<120>`: the body used to take `ya29` and leave `.<body>` half-matched).
_SR_V2_KEYS = (r"sk-(?:proj|svcacct|admin|or-v1)-" + _sr_cbr("A-Za-z0-9_-", 20, 4096) + r"|AIza[0-9A-Za-z_-]{35}|"
               r"ya29\." + _sr_cbr("0-9A-Za-z_-", 20, 4096) + r"|1//" + _sr_cbr("0-9A-Za-z_-", 30, 4096) +
               r"|GOCSPX-" + _sr_cbr("0-9A-Za-z_-", 20, 256) + r"|gsk_" + _sr_cbr("A-Za-z0-9_-", 20, 4096) +
               r"|xai-" + _sr_cbr("A-Za-z0-9_-", 20, 4096))
_SR_CLASSIC_KEYS = (r"gh[pousr]_" + _sr_cbr("A-Za-z0-9", 20, 4096) + r"|github_pat_" + _sr_cbr("A-Za-z0-9_", 20, 4096)
                    + r"|sk-ant-" + _sr_cbr("A-Za-z0-9_-", 12, 4096) + r"|sk-" + _sr_cbr("A-Za-z0-9", 20, 4096)
                    + r"|xox[baprs]-" + _sr_cbr("A-Za-z0-9-", 10, 4096) + r"|"
                    r"A[KS]IA[0-9A-Z]{16}|(?:sk|rk)_(?:live|test)_" + _sr_cbr("A-Za-z0-9", 16, 4096) + r"|"
                    r"whsec_" + _sr_cbr("A-Za-z0-9", 16, 4096) + r"|"
                    r"[0-9a-f]{32}\.[A-Za-z0-9]{16}")
# a key glued straight onto a letter or digit (`notesghp_…`, `idAKIA…`) has no `\b` before its
# prefix, so it gets its own start (`v8`), but only with the exact vendor shape (fixed literal starts,
# so linear) and a body that passes _sr_glued_key_like.
_SR_GLUED = (r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|"
             r"sk-(?:proj|svcacct|admin|or-v1)-[A-Za-z0-9_-]{40,256}|"
             r"sk-ant-(?:api|admin|oat|ort)[0-9]{2}-[A-Za-z0-9_-]{40,256}|sk-[A-Za-z0-9]{48}|"
             r"xox[baprs]-[0-9]{1,16}-[A-Za-z0-9-]{10,256}|A[KS]IA[0-9A-Z]{16}|"
             r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,256}|whsec_[A-Za-z0-9]{32,256}")
# The classic shapes right after `_` or a URL escape (`CONF_ghp_…`, `?k=%20AKIA…`), group `v7`:
# `\b` never fires there. A body `_` that opens another key prefix ends the body (linear, as in
# _SR_V2_KEYS_US below).
_SR_CLS_US_BODY = r"(?:" + _SR_NOT_V2 + r"[A-Za-z0-9-]|_(?!" + _SR_CLASSIC_PFX + "|" + _SR_V2_PFX + r"))"
_SR_CLASSIC_KEYS_US = (r"gh[pousr]_" + _sr_cbr("A-Za-z0-9", 20, 4096) + r"|github_pat_" + _SR_CLS_US_BODY
                       + r"{20,256}|sk-ant-" + _SR_CLS_US_BODY + r"{12,256}|sk-" + _sr_cbr("A-Za-z0-9", 20, 4096)
                       + r"|xox[baprs]-" + _sr_cbr("A-Za-z0-9-", 10, 4096) + r"|A[KS]IA[0-9A-Z]{16}|"
                       r"(?:sk|rk)_(?:live|test)_" + _sr_cbr("A-Za-z0-9", 16, 4096) + r"|whsec_" + _sr_cbr("A-Za-z0-9", 16, 4096)
                       + r"|[0-9a-f]{32}\.[A-Za-z0-9]{16}")
# After `_` a start can sit INSIDE a body run (`a_sk-proj-a_sk-proj-…`). A `_` that opens another key
# prefix ends the body, so each start scans only up to the next start and the rule stays linear
# (the earlier plain body re-scanned up to 256 characters per start: ~30x slower on that shape). The bodies
# whose prefix is all body characters stay capped at 256 (real keys are shorter).
_SR_V2_US_BODY = r"(?:[A-Za-z0-9-]|_(?!" + _SR_V2_PFX + r"))"
_SR_V2_KEYS_US = (r"sk-(?:proj|svcacct|admin|or-v1)-" + _SR_V2_US_BODY + r"{20,256}|AIza" + _SR_V2_US_BODY
                  + r"{35}|ya29\." + _SR_V2_US_BODY + r"{20,4096}|1//" + _SR_V2_US_BODY + r"{30,4096}|GOCSPX-"
                  + _SR_V2_US_BODY + r"{20,256}|gsk_" + _SR_V2_US_BODY + r"{20,256}|xai-" + _SR_V2_US_BODY
                  + r"{20,256}")
# a newer-shape key followed by `_word`, `-x` or a short path (`AIza<35>_word`, `…/x`). The
# base64-aware end (`v2`/`v6`) refuses those and there is no shorter match, so the key leaked whole.
# `v9`/`v10` end the key there instead; the body must be key-like (_sr_key_like_body) and outside
# binary data, and a `/` tail must be a short path (at most 8 segments of 64 path characters) that
# ends at a non-base64 character, so a base64 run (`…AIza…/AbC+…`) is still left alone.
# or the cut-off end of a base64-style value (`AIza<35>+`, `xai-…==`): one to three `+`/`=`
# that no letter or digit follows, so a base64 run (`…AIza…+AbC…`) still ends nowhere.
# or a marker an earlier rule put right after it (`AIza<35>-[REDACTED]`: the classic
# key next to a newer one may already be a marker).
_SR_V2_TAIL = (r"(?=[_-][A-Za-z0-9]|(?:/[A-Za-z0-9._~-]{1,64}){1,8}(?![A-Za-z0-9+/=])|[+=]{1,3}(?![A-Za-z0-9])"
               r"|_?(?:" + _SR_CLASSIC_PFX + "|" + _SR_V2_PFX + r")|[0-9a-f]{32}\.[A-Za-z0-9]{16}|[_-]?\[REDACTED)")
# The `v9`/`v10` body never runs into another key's prefix (`sk-or-v1-<hex>ghp_…/x`): a run through
# it fails the key-like check and the rejected match would hide both keys. Prefixes are
# literal, so the lookahead is bounded and the rule stays linear.
# only where a whole key starts (an exact glued classic shape or a newer key's
# head). A prefix's letters inside a random body (`…<52>sk-<11>/x`, ~1 key in 300) no longer cut it short
# and leave the rest behind. The lookahead is bounded (at most ~260 characters, tried only after a literal).
# A glued classic stops the body only where it ends the key run: `…Wsk-<48>_B6Qd…` inside a random body is
# body, not `sk-<48>` plus an `_ident` tail that would stay after its marker.
_SR_V2_NB_BODY = (r"(?:(?!_?(?:(?:" + _SR_GLUED + r")(?![A-Za-z0-9_-])|" + _SR_V2_HEADS + r"))"
                  r"[A-Za-z0-9_-])")
_SR_V2_KEYS_NB = (r"sk-(?:proj|svcacct|admin|or-v1)-" + _SR_V2_NB_BODY + r"{20,4096}|AIza" + _SR_V2_NB_BODY
                  + r"{35}|ya29\." + _SR_V2_NB_BODY + r"{20,4096}|1//" + _SR_V2_NB_BODY + r"{30,4096}|GOCSPX-"
                  + _SR_V2_NB_BODY + r"{20,256}|gsk_" + _SR_V2_NB_BODY + r"{20,4096}|xai-" + _SR_V2_NB_BODY
                  + r"{20,4096}")
_SR_KEY_RUN = _sr_re.compile(r"[A-Za-z0-9_-]*")
_SR_V2_PFX_RE = _sr_re.compile(_SR_V2_PFX)
_SR_UPPER = _sr_re.compile(r"[A-Z]")
_SR_LOWER = _sr_re.compile(r"[a-z]")
_SR_DIGIT = _sr_re.compile(r"[0-9]")


def _sr_key_like_body(body):
    """A key body, not a word run: it mixes upper and lower case (base64url / alnum keys),
    or it is a digit-dense run with no `-`/`_` in it (4+ digits that make up a quarter of it). The
    second arm keeps single-case keys such as OpenRouter's `sk-or-v1-<64 lowercase hex>` (~60% digits),
    while a URL path or an identifier stays a word: one with a version number
    (`xai-api-reference-v2-2024-guide`, ~16%) or a date or hash between separators
    (`xai-2024-10-07-release-notes`)."""
    if _SR_UPPER.search(body) and _SR_LOWER.search(body):
        return True
    if "-" in body or "_" in body:
        return False
    d = len(_SR_DIGIT.findall(body))
    return d >= 4 and d * 4 >= len(body)


# the classic shapes whose body can be a run of words. Right after `_` or a URL escape (`v7`)
# `slack_xoxb-tokens-and-scopes-guide` or `my_sk-ant-api-key-placeholder` is a name, not a key. Real
# keys of these shapes are random: they mix upper and lower case (`sk-ant-api03-…`, `github_pat_11…`,
# the last part of `xoxb-…`) or are digit-dense (`xoxp-<numbers>-<lowercase hex>`), with `-`/`_`
# allowed between the parts. The other classic shapes (`AKIA…`, `ghp_…`, `sk_live_…`)
# have no word-shaped body and keep matching as before.
_SR_CLS_WORDY = _sr_re.compile(r"xox[baprs]-|sk-ant-|github_pat_")


def _sr_cls_key_like(body):
    """A classic key body: ANY upper-case letter, or 4+ digits making up a quarter of its letters
    and digits. A rejected match is consumed whole, so the test is deliberately loose: a key glued into
    the body (`x_sk-ant-NOTES-FOR-AKIA…`, `x_xoxb-notes-ghp_…`) brings an upper-case letter or its digits
    with it and the whole run redacts. Only an all-lower-case, digit-light run stays a name."""
    if _SR_UPPER.search(body):
        return True
    alnum = len(body) - body.count("-") - body.count("_")
    d = len(_SR_DIGIT.findall(body))
    return d >= 4 and d * 4 >= alnum


# where a classic key ends. `\b` as before, or right before `_` (`ghp_…_notes`, where `\b` never
# fires) unless that `_` opens the next key together with the letters before it (`xoxb-notes-ghp_…`):
# then the body backs off to its last `\b`, as before, and the next key keeps its own start.
# or right before the next key's prefix (`AKIA<16>ghp_…`, written back to back): a fixed-length
# body (`AKIA…`) has no `\b` there; a longer body takes the prefix letters and the rest is `token_tail`'s.
_SR_CLS_END = (r"(?:\b|(?=_)(?!(?<=gh[pousr])_|(?<=github)_pat_|(?<=[sr]k)_(?:live|test)_|(?<=whsec)_"
               r"|(?<=gsk)_)"
               r"|(?=" + _SR_CLASSIC_PFX + "|" + _SR_V2_PFX + r"|[0-9a-f]{32}\.[A-Za-z0-9]{16}))")
_SR_CLASSIC_PFX_RE = _sr_re.compile(_SR_CLASSIC_PFX + "|" + _SR_V2_PFX)


def _sr_glued_key_like(tok):
    """a classic key that ends right before `_` (`ghp_…_notes`) or starts right after a letter or
    digit (`notesAKIA…`). The trailing `_` makes it look like an identifier, so it counts only as a
    real key: a body that passes _sr_cls_key_like. `storage_read_bytes` stays a name."""
    p = _SR_CLASSIC_PFX_RE.match(tok)
    return _sr_cls_key_like(tok[p.end():] if p else tok)
# The binary spans of the last text a key was found in: one span pass per text. The text is keyed by
# (id, length, hash), never held: a module global must not keep raw, unscrubbed text alive.
# A str caches its hash, so the key costs one pass per text, not one per match.
_SR_BIN_CACHE = [None]


def _sr_first_key_cut(tok, pfx):
    """The first `_`/`-` at least 20 characters into the body where the body before it passes
    _sr_key_like_body. One pass with running counts, so a rejected run stays linear (no cap)."""
    up = lo = dg = 0
    sep = False
    n = 0
    for i in range(pfx, len(tok)):
        c = tok[i]
        if c in "_-":
            if n >= 20 and ((up and lo) or (not sep and dg >= 4 and dg * 4 >= n)):
                return i
            sep = True
        elif c.isupper():
            up += 1
        elif c.islower():
            lo += 1
        elif c.isdigit():
            dg += 1
        n += 1
    return None


def _sr_plain_base64_run(s, start, end):
    """True when s[start:end] and the base64 run before it (up to 256 characters) hold no `-`/`_`.
    Standard base64 has neither, so `…q1//<30+>` at the end of a short unpadded base64 line is data
    ; a key glued onto another key almost always has one in a prefix or body."""
    if "-" in s[start:end] or "_" in s[start:end]:
        return False
    i = start - 1
    lo = max(0, start - 256)
    while i >= lo:
        c = s[i]
        if c in "-_":
            return False
        if not (c.isascii() and (c.isalnum() or c in "+/=")):
            break
        i -= 1
    return True


def _sr_token_source(C, K, KUS, CUS, NB, plain=True):
    """The `token` rule's pattern (sr_rules) from its key shapes: the classic keys `C` (`CUS` after `_`), the
    newer keys `K` (`KUS` after `_`) and their prefix-stopped form `NB`. `plain` adds the earlier `v14`-`v17`."""
    s = (r"\b(?P<v>" + C + r")" + _SR_CLS_END +
         r"|(?<![A-Za-z0-9+/_-])(?P<v2>" + K + r")(?![A-Za-z0-9+/=_-])"
         r"|(?:(?<=[+/])|(?<=%[0-9A-Fa-f]{2}))(?P<v3>" + K + r")(?![A-Za-z0-9+/=_-])"
         r"|(?<=_)(?P<v4>" + KUS + r")(?![A-Za-z0-9+/=_-])"
         r"|\\[nrt](?:(?P<v5>" + C + r")" + _SR_CLS_END + r"|(?P<v6>" + K + r")(?![A-Za-z0-9+/=_-]))"
         r"|(?:(?<=_)|(?<=%[0-9A-Fa-f]{2}))(?P<v7>" + CUS + r")" + _SR_CLS_END +
         r"|(?<=[A-Za-z0-9])(?P<v8>" + _SR_GLUED + r")(?![A-Za-z0-9])"
         r"|(?<![A-Za-z0-9+/_-])(?P<v9>" + NB + r")" + _SR_V2_TAIL +
         r"|\\[nrt](?P<v10>" + NB + r")" + _SR_V2_TAIL +
         # a newer-shape key as a URL path segment or after `+`/a URL escape with a
         # tail (`/v1/<key>/next`, `/<key>_x`): `v3` needs a base64-free end there, `v9` refuses `/`.
         r"|(?:(?<=[+/])|(?<=%[0-9A-Fa-f]{2}))(?P<v11>" + NB + r")" + _SR_V2_TAIL +
         # a newer key right after `-` (`X-Api-Key-AIza…`, `<classic>-ya29.…`)
         # or after `_` with a `+`/`=`/path tail (`CONF_AIza<35>+`): `v4` needs a base64-free end.
         r"|(?<=[-_])(?P<v12>" + NB + r")(?:(?![A-Za-z0-9+/=_-])|" + _SR_V2_TAIL + r")"
         # A random base64url body can itself contain a prefix's letters (`…Tsk--…`, `…ghp_…`): the `v9`
         # body stops there, too short, and the key leaked whole when another key followed (`1//<b>1//<b>`).
         # `v13` takes the plain body with the same tails; it is only tried where `v9` failed to match.
         r"|(?<![A-Za-z0-9+/_-])(?P<v13>" + K + r")" + _SR_V2_TAIL)
    if plain:
        # the same for the other starts. A random base64url body that holds a
        # prefix's letters (`…sk-…`, `…ghr_…`, `…AKIA…`; about 1 key in 300) stopped the prefix-stopped
        # body too early and the whole key leaked: after `/`/`+`/a URL escape (`v14`), after `-`/`_`
        # (`v15`), after a literal `\n`/`\r`/`\t` (`v16`). `v17`: a newer key glued straight onto a
        # letter or digit, i.e. the end of another key (`<xai><1//…>`), matched in the same pass so a key
        # shape inside its body cannot split it first. Each is tried only where the earlier groups did
        # not match, and each must pass _sr_random_body (_sr_token_span).
        s += (r"|(?:(?<=[+/])|(?<=%[0-9A-Fa-f]{2}))(?P<v14>" + K + r")" + _SR_V2_TAIL +
              r"|(?<=[-_])(?P<v15>" + K + r")(?:(?![A-Za-z0-9+/=_-])|" + _SR_V2_TAIL + r")"
              r"|\\[nrt](?P<v16>" + K + r")" + _SR_V2_TAIL +
              r"|(?<=[A-Za-z0-9])(?P<v17>" + K + r")(?:(?![A-Za-z0-9+/=_-])|" + _SR_V2_TAIL + r")")
    return s


# the key shapes before an earlier refinement, whose bodies stop at any prefix's
# letters (`_SR_NOT_V2_PREV`, `_SR_V2_NB_BODY_PREV`). _sr_check_token compares each match with what this
# rule makes at the same place: where the newer, longer bodies change a match, the body must be random,
# and where it is not, this rule's matches there stand instead. So a run of words matches as it did.
_SR_NOT_V2_PREV = r"(?!AIza|ya29\.|1//|GOCSPX-|gsk_|xai-|sk-(?:proj|svcacct|admin|or-v1)-)"


def _sr_cb_prev(cls):
    return "(?:" + _SR_NOT_V2_PREV + "[" + cls + "])"


_SR_V2_KEYS_PREV = (r"sk-(?:proj|svcacct|admin|or-v1)-[A-Za-z0-9_-]{20,4096}|AIza[0-9A-Za-z_-]{35}|"
                    r"ya29\.[0-9A-Za-z_-]{20,4096}|1//[0-9A-Za-z_-]{30,4096}|GOCSPX-[0-9A-Za-z_-]{20,256}|"
                    r"gsk_[A-Za-z0-9_-]{20,4096}|xai-[A-Za-z0-9_-]{20,4096}")
_SR_CLASSIC_KEYS_PREV = (
    r"gh[pousr]_" + _sr_cb_prev("A-Za-z0-9") + r"{20,4096}|github_pat_" + _sr_cb_prev("A-Za-z0-9_")
    + r"{20,4096}|sk-ant-" + _sr_cb_prev("A-Za-z0-9_-") + r"{12,4096}|sk-" + _sr_cb_prev("A-Za-z0-9")
    + r"{20,4096}|xox[baprs]-" + _sr_cb_prev("A-Za-z0-9-") + r"{10,4096}|"
    r"A[KS]IA[0-9A-Z]{16}|(?:sk|rk)_(?:live|test)_" + _sr_cb_prev("A-Za-z0-9") + r"{16,4096}|"
    r"whsec_" + _sr_cb_prev("A-Za-z0-9") + r"{16,4096}|"
    r"[0-9a-f]{32}\.[A-Za-z0-9]{16}")
_SR_CLS_US_BODY_PREV = (r"(?:" + _SR_NOT_V2_PREV + r"[A-Za-z0-9-]|_(?!" + _SR_CLASSIC_PFX + "|" + _SR_V2_PFX
                        + r"))")
_SR_CLASSIC_KEYS_US_PREV = (
    r"gh[pousr]_" + _sr_cb_prev("A-Za-z0-9") + r"{20,4096}|github_pat_" + _SR_CLS_US_BODY_PREV
    + r"{20,256}|sk-ant-" + _SR_CLS_US_BODY_PREV + r"{12,256}|sk-" + _sr_cb_prev("A-Za-z0-9")
    + r"{20,4096}|xox[baprs]-" + _sr_cb_prev("A-Za-z0-9-") + r"{10,4096}|A[KS]IA[0-9A-Z]{16}|"
    r"(?:sk|rk)_(?:live|test)_" + _sr_cb_prev("A-Za-z0-9") + r"{16,4096}|whsec_" + _sr_cb_prev("A-Za-z0-9")
    + r"{16,4096}|[0-9a-f]{32}\.[A-Za-z0-9]{16}")
_SR_V2_NB_BODY_PREV = r"(?:(?!_?(?:" + _SR_CLASSIC_PFX + "|" + _SR_V2_PFX + r"))[A-Za-z0-9_-])"
_SR_V2_KEYS_NB_PREV = (
    r"sk-(?:proj|svcacct|admin|or-v1)-" + _SR_V2_NB_BODY_PREV + r"{20,4096}|AIza" + _SR_V2_NB_BODY_PREV
    + r"{35}|ya29\." + _SR_V2_NB_BODY_PREV + r"{20,4096}|1//" + _SR_V2_NB_BODY_PREV + r"{30,4096}|GOCSPX-"
    + _SR_V2_NB_BODY_PREV + r"{20,256}|gsk_" + _SR_V2_NB_BODY_PREV + r"{20,4096}|xai-" + _SR_V2_NB_BODY_PREV
    + r"{20,4096}")
_SR_TOKEN = _sr_re.compile(_sr_token_source(_SR_CLASSIC_KEYS, _SR_V2_KEYS, _SR_V2_KEYS_US, _SR_CLASSIC_KEYS_US,
                                            _SR_V2_KEYS_NB))
_SR_TOKEN_PREV = _sr_re.compile(_sr_token_source(_SR_CLASSIC_KEYS_PREV, _SR_V2_KEYS_PREV, _SR_V2_KEYS_US,
                                                 _SR_CLASSIC_KEYS_US_PREV, _SR_V2_KEYS_NB_PREV, plain=False))


_SR_KEY_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_SR_SEP = _sr_re.compile(r"[-_]")


def _sr_word_before(s, i):
    """the newer prefix at s[i], glued onto a letter or digit, continues a word: `sk-admin-`
    in `flask-admin-…`, `sk-svcacct-` in `mask-svcacct-…`, `xai-` in `relaxai-…`, `1//` in `api/v1//…`,
    `gsk_` in `Bigsk_…`. The up to 64 key characters before it are words: each part between `-`/`_` is
    letters only or digits only. The end of a random key (`<xai key><1//…>`) mixes letters and digits."""
    j, lo = i, max(0, i - 64)
    while j > lo and s[j - 1] in _SR_KEY_CHARS:
        j -= 1
    return all(p.isalpha() or p.isdigit() or not p for p in _SR_SEP.split(s[j:i]))


# A part of a name between `-`/`_`: CamelCase or lower-case words, then capitals, then digits (`ModelView2`,
# `Akia`, `v2`, `Q4`, `2024`, `API`).
_SR_WORD_PART = _sr_re.compile(r"[a-z]*(?:[A-Z][a-z]+)*[A-Z]*[0-9]*")


def _sr_random_body(body):
    """the body has a random key's shape, not a run of words (`key_v2_Pat_gsk_Akia_v2`).
    Upper case, lower case and digits (or OpenRouter's lower-case hex: _sr_key_like_body's second arm);
    the character class (upper/lower/digit) changes at 3 of 10 steps or more inside a `-`/`_` part (a
    random base64url body: about 6 of 10; words about once a word, `ModelView2-Extensions` 0.28,
    `Planning-Board-Q4-2024` 0.20); and not every part reads as a word (_SR_WORD_PART). A random
    base64url body fails it about 1 time in 130 at 28 characters, 1 in 500 at 35, 1 in 10^5 at 64.
    Only a match that the earlier longer bodies changed needs it (_sr_check_token); a rejected one falls back
    to the earlier rule's matches."""
    up = lo = dg = tr = steps = 0
    prev = -1
    for c in body:
        if c == "-" or c == "_":
            prev = -1
            continue
        k = 0 if "A" <= c <= "Z" else 1 if "a" <= c <= "z" else 2
        if k == 0:
            up += 1
        elif k == 1:
            lo += 1
        else:
            dg += 1
        if prev >= 0:
            steps += 1
            tr += k != prev
        prev = k
    if not (up and lo and dg) and ("-" in body or "_" in body or dg < 4 or dg * 4 < len(body)):
        return False
    if tr * 10 < steps * 3:
        return False
    return not all(_SR_WORD_PART.fullmatch(p) for p in _SR_SEP.split(body))


def _sr_name_body(body):
    """a run of CamelCase words (`GrokModelConfigurationLoader`, `Model_View2-Loader`): upper and
    lower case, and every `-`/`_` part reads as a word (_SR_WORD_PART: each capital starts a lower-case
    word or a final capital run, digits only at a part's end), and the character class (upper/lower/digit)
    changes at fewer than 2 of 5 steps inside a part (a name: twice a word; a random body: about 6
    of 10). A random base64url body passes about 1 time in 2,000 at 20 characters, 1 in 30,000 at 28 and
    1 in 500,000 at 35, so the callers use it only below every real body length (_sr_name_short).
    A one-case or digit-dense body (OpenRouter hex) is never a name here."""
    if _SR_UPPER.search(body) is None or _SR_LOWER.search(body) is None:
        return False
    tr = steps = 0
    prev = -1
    for c in body:
        if c == "-" or c == "_":
            prev = -1
            continue
        k = 0 if "A" <= c <= "Z" else 1 if "a" <= c <= "z" else 2
        if prev >= 0:
            steps += 1
            tr += k != prev
        prev = k
    return tr * 5 < steps * 2 and all(_SR_WORD_PART.fullmatch(p) for p in _SR_SEP.split(body))


# a name body is shorter than every real key body (`AIza` 35, `gsk_` 52, `xai-` 80, `sk-proj-`
# ~150, `ya29.`/`1//` ~100; `GOCSPX-` 28 is gated by its caller), so a random real-length key is never kept
# as a name, whatever its shape or tail. The deliberate trade-off: a name-shaped body under 35 characters
# (shorter than any real key of that vendor) stays.
_SR_NAME_MAX = 35


def _sr_name_short(body):
    return len(body) < _SR_NAME_MAX and _sr_name_body(body)


def _sr_name_exempt(tok, pfx, s, span):
    """the `token` match `tok` (prefix length `pfx`, at `span` in `s`) is a name, not a key:
    its body reads as one (_sr_name_short) and the WHOLE key run from the prefix stays below every real
    body length (`GOCSPX-` below its real 28). A body cut short by an inner head (`xai-<name 20>gsk_<56>`) or
    a tail (`AIza<35>_word`) is measured with the rest of its run, and a run that ends at an earlier marker
    (`<name>_[REDACTED]`, the inner key already redacted) is a key's, as on develop.
    These checks only narrow it; what makes it safe is sr_name_reconciled: a kept name never keeps any other
    character that the scrub without the exemption (develop's behaviour) redacts."""
    if _SR_EXEMPT.off:
        return False
    limit = 28 if tok.startswith("GOCSPX-") else _SR_NAME_MAX
    room = limit - (span[1] - span[0] - pfx)
    if room <= 0:
        return False
    # Only up to the limit: a long run (`_xai-` x 240k) must not be rescanned at every start (linear).
    end = _SR_KEY_RUN.match(s, span[1], span[1] + room).end()
    if end - span[1] >= room:
        return False
    if s.startswith("[REDACTED", end):
        return False
    if _sr_glued_after_run(s, end):
        return False
    if not (_sr_name_short(tok[pfx:]) and not _sr_glued_head(tok, s, span[0])):
        return False
    if _SR_EXEMPT.log is not None:
        _SR_EXEMPT.log.append(tok)
    return True


# the name exemption, safe by construction. Shape checks alone kept opening holes (a key in
# front of the name losing the marker that ended it, a JSON-escaped `1\\/\\/` head behind it), so a scrub that
# kept a name is run a second time WITHOUT the exemption (the
# reference run), and each line of the first run is used only when it keeps nothing the reference line
# redacts except the names the exemption kept: with every marker and every kept name of the line as a
# wildcard, its remaining text must stand in the reference line, piece by piece, in order
# (_sr_line_within). Otherwise the reference line is used. So the output never keeps a character the reference
# run redacts, except the characters of a kept name, and where the first run redacts more it is used.
class _SrExemptState(_sr_threading.local):
    off = False       # no name exemption (the reference run)
    ref = False       # unused here (kept so a sync stays a plain diff)
    log = None        # the names kept by the exemption in the current run (a list), or None


_SR_EXEMPT = _SrExemptState()


# A cut candidate: a marker, or a newer key's prefix where a kept name may start (every name the exemption keeps
# is a `token` match, so it starts with one of these prefixes).
_SR_RECON_CUT = _sr_re.compile(_SR_MARK + "|" + _SR_V2_PFX)


def _sr_pieces(a, names, lens):
    """`a` split at its markers and at the kept `names` (a set; `lens` their distinct lengths, longest first):
    like re.split with an alternation of the marker and every name, longest name first, but linear whatever the
    number of names: only where a prefix starts, at most one set lookup per distinct length.
    Linearity invariant: a kept name is a `token` match whose body is under _SR_NAME_MAX (35) characters after a
    prefix of at most 11 (`sk-svcacct-`), so a name is at most ~45 characters and there are at most ~45 distinct
    lengths: each prefix position costs O(45) bounded slices and set lookups, whatever the number of names. A
    longer kept name would break that bound (_sr_name_exempt never keeps one)."""
    pieces, start, pos = [], 0, 0
    find = _SR_RECON_CUT.search
    while True:
        m = find(a, pos)
        if m is None:
            break
        i = m.start()
        if a[i] == "[":
            end = m.end()
        else:
            end = next((i + n for n in lens if a[i:i + n] in names), -1)
            if end < 0:
                pos = i + 1
                continue
        pieces.append(a[start:i])
        start = pos = end
    pieces.append(a[start:])
    return pieces


def _sr_line_within(pieces, b):
    """The line split into `pieces` (_sr_pieces) has every piece in line `b`, in order: the first piece at the
    start and the last at the end unless the line starts/ends with a cut. One forward pass of str.find over `b`
    (linear)."""
    if len(pieces) == 1:
        return pieces[0] == b
    first, last = pieces[0], pieces[-1]
    if not b.startswith(first):
        return False
    pos = len(first)
    for piece in pieces[1:-1]:
        if piece:
            k = b.find(piece, pos)
            if k < 0:
                return False
            pos = k + len(piece)
    return len(b) - pos >= len(last) and b.endswith(last)


def sr_name_reconcile(a, ref, names):
    """Per line: the first run `a` when it is within the reference run `ref` (develop's behaviour), with its
    markers and the kept `names` as wildcards (_sr_line_within), else the reference line. Returns (text, every
    line from `a`). A line count that differs takes the whole reference."""
    la, lr = a.split("\n"), ref.split("\n")
    if len(la) != len(lr):
        return ref, False
    nameset = frozenset(names)
    lens = sorted({len(n) for n in nameset}, reverse=True)
    out, all_a = [], True
    for x, y in zip(la, lr):
        if x == y or _sr_line_within(_sr_pieces(x, nameset, lens), y):
            out.append(x)
        else:
            all_a = False
            out.append(y)
    return "\n".join(out), all_a


def sr_name_reconciled(run, alt_rules=False):
    """`run()` -> (text, ...): one whole scrub of a text. If the name exemption kept a name (or `alt_rules`), the
    reference run is made as well:
    no exemption (`off`), and with `alt_rules` also develop's rules (`ref`). The result is reconciled per line
    (sr_name_reconcile), with the first run's other results when every line came from it, else the develop
    reference run's. A nested call (the outer scrub reconciles) runs once."""
    st = _SR_EXEMPT
    if st.off or st.log is not None:
        return run()
    st.log = []
    try:
        a = run()
        names = st.log
    finally:
        st.log = None
    if not names and not alt_rules:
        return a
    # One reference run: no exemption.
    st.off = True
    try:
        st.ref = alt_rules
        ref = run()
    finally:
        st.off = st.ref = False
    out, all_a = sr_name_reconcile(a[0], ref[0], names)
    if all_a:
        return a
    return (out,) + tuple(ref[1:])


# what develop makes of a run that ends at `.`/`//` once the key before it is a marker
# (`token_tail`, without the marker). The run starts at the run end, so no text is copied or rescanned.
_SR_RUN_TAIL = _sr_re.compile(r"(?P<sep>\.|//)(?P<v>[A-Za-z0-9_-]{6," + _SR_N + r"})")
_SR_ZAI_AT = _sr_re.compile(r"[0-9a-f]{32}\.[A-Za-z0-9]{16}")
_SR_ZAI_HEAD = _sr_re.compile(r"[0-9a-f]{32}\.")
_SR_MARKER_END = _sr_re.compile(r"\[REDACTED(?:[A-Z-]*|:[a-z0-9_.]{1,64})\]$")


def _sr_glued_head(tok, s, i):
    """a body behind a `1//`, `_1//`, `ya29.` or `_ya29.` head, or behind a z.ai head
    (`<32 hex>.`), is never a name, whatever its length, shape or what stands before the head: develop's rule
    for that head decides it. (Telling `id-ya29.<name>` from `<key>-ya29.<name>` needs the run before to be
    words, and a random run of letters reads as words too: the review-3 corpus leaked through every such
    test.) Neither is any name right after a marker, or after `-`/`_` that ends a run which is not words (the
    end of a key). Only a newer-vendor name that stands on its own (after a space, `/`, a quote, or `-`/`_`
    after words: `id-xai-GrokModelConfigLoader`) can be kept."""
    if tok.startswith(("1//", "ya29.")):
        return True
    if i <= 0:
        return False
    b = s[i - 1]
    # After `-`/`_` the run before must be words (`id-`, `X-Api-Key-`, `my_`, `CONF_`): after the end of a key
    # (`<key>-xai-<name>`, `AIza<30>_gsk_<name>`) the name is the next key glued on (_sr_word_before, 64 chars).
    if b in "-_" and not _sr_word_before(s, i - 1):
        return True
    # Right after a marker an earlier pass put there (`[REDACTED-SECRET]xai-<name>`, `…]_gsk_<name>`): the rest of a
    # key glued on, as the run-end marker check in _sr_name_exempt sees it from the other side.
    j = i - 1 if b in "_-" else i
    if j > 0 and s[j - 1] == "]" and _SR_MARKER_END.search(s, max(0, j - 80), j):
        return True
    return b == "." and i >= 33 and _SR_ZAI_HEAD.match(s, i - 33) is not None


def _sr_glued_after_run(s, end):
    """the key run of a name-shaped match ends at `end`, at a `.` or `//` (the run stops at
    `/` and `.`). A key may be glued on there: a whole `1//`/`_1//`/`ya29.`/`_ya29.` or z.ai head whose first
    characters close the run (`xai-<name>1//<64>`, `xai-<name>ya29.<70>`), or any random run after the `.`/`//`.
    Develop redacts the name as a key and then that key, or the run behind its marker (`token_tail`); an
    exempt name would leave the key glued onto a word, which every rule refuses. So the name stays only when
    develop's `token_tail` would keep the run after it too (`id-xai-GrokModelConfigLoader.getInstance`,
    `….java`, a sentence's full stop). Bounded: two literal checks and one match at `end`."""
    c = s[end:end + 1]
    if c == "\\":
        # a JSON-escaped `/` (`<name>1\/\/…`, `<name>\/…`): no exemption (review 4, F2)
        return s.startswith("\\/", end)
    if c == "/":
        if not s.startswith("//", end):
            return False
        if s[end - 1:end] == "1":
            return True
    elif c == ".":
        if s[end - 4:end] == "ya29" or (end >= 32 and _SR_ZAI_AT.match(s, end - 32)):
            return True
    else:
        return False
    m = _SR_RUN_TAIL.match(s, end)
    return m is not None and _sr_check_token_tail(m) is not None


_SR_TOKEN_GROUPS = ("v", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
                    "v16", "v17")
_SR_CHECKED_GROUPS = frozenset(("v3", "v4", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16"))
_SR_PLAIN_ONLY = frozenset(("v14", "v15", "v16", "v17"))


def _sr_exact_v2(tok, pfx, s, end):
    """ class A: a whole `AIza<35>` or `GOCSPX-<28>` that ends the key run. After a space
    (`v2`) that shape is a key whatever its body; after `-`, `_` or `/` it is one too, even with a body of
    one case plus digits (`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`), where _sr_key_like_body sees a word."""
    n = len(tok) - pfx
    if not ((n == 35 and tok.startswith("AIza")) or (n == 28 and tok.startswith("GOCSPX-"))):
        return False
    return end >= len(s) or s[end] not in _SR_KEY_CHARS


def _sr_group(m):
    return next(k for k in _SR_TOKEN_GROUPS if m.group(k) is not None)


def _sr_token_span(m, g, fresh):
    """The span to redact for a `token` match in group `g`, or None. `fresh`: the earlier longer bodies made this
    match (_sr_check_token), so its body must be random (_sr_random_body)."""
    span = m.span(g)
    s = m.string
    tok = m.group(g)
    if g == "v17":
        # glued onto a letter or digit, a newer key counts only with a random body and
        # not as the end of a word (`pip install flask-admin-ModelView-Extensions`). Standard base64 has no
        # `-`/`_`/`.`, so only `1//` and `AIza` can sit inside a plain base64 run.
        pfx = _SR_V2_PFX_RE.match(tok).end()
        if _sr_word_before(s, span[0]) or not _sr_random_body(tok[pfx:]):
            return None
        if tok[0] in "1A" and _sr_plain_base64_run(s, span[0], span[1]):
            return None
    elif g in _SR_CHECKED_GROUPS:
        # In a URL path or an identifier (`docs.x.ai/xai-sdk-guide-v2`, `my_gsk_client_settings`) the key
        # shape is a word, not a key; see _sr_key_like_body. The same for a key with a tail.
        pfx = _SR_V2_PFX_RE.match(tok).end()
        if _sr_exact_v2(tok, pfx, s, span[1]):
            pass
        elif _sr_name_exempt(tok, pfx, s, span):
            # a CamelCase name after `-`/`_`/`/` (`id-xai-GrokModelConfigLoader`)
            # mixes case, so _sr_key_like_body took it for a key body. Only while the WHOLE key run from the
            # prefix stays below every real body length (`GOCSPX-` below its real 28), not just this match: a
            # body cut short by an inner head (`xai-<name 20>gsk_<56>`) or a tail (`AIza<35>_word`) would
            # otherwise exempt a real-length key whole.
            return None
        elif fresh:
            if not _sr_random_body(tok[pfx:]):
                return None
        elif not _sr_key_like_body(tok[pfx:]):
            # a body may run on into a `_word`/`-x` tail (`/v1/<key>_word/next`, `/v1/<key>-x HTTP`);
            # the rejected run would hide the key, and `re.sub` never retries a later group at that
            # start. Cut at the first `_`/`-` whose body before it is key-like; the
            # tail is left for the next pass.
            cut = _sr_first_key_cut(tok, pfx)
            if cut is None:
                return None
            span = (span[0], span[0] + cut)
    elif fresh and g != "v8":
        p = (_SR_V2_PFX_RE if g in ("v2", "v6") else _SR_CLASSIC_PFX_RE).match(tok)
        if not _sr_random_body(tok[p.end():] if p else tok):
            return None
    if g == "v8" and not _sr_glued_key_like(tok):
        return None
    if g in ("v", "v5", "v7") and s[m.end(g):m.end(g) + 1] == "_" and not _sr_glued_key_like(tok):
        return None
    if g == "v7":
        w = _SR_CLS_WORDY.match(tok)
        if w and not _sr_cls_key_like(tok[w.end():]):
            return None
    # Never inside binary data: a wrapped base64 line can start `1//…` or `AIza…` right
    # after a line break, where the plain start (`v2`) or the escape-led one (`v6`) fires.
    key = (id(s), len(s), hash(s))
    c = _SR_BIN_CACHE[0]
    if c is None or c[0] != key:
        c = (key, sr_binary_spans(s))
        _SR_BIN_CACHE[0] = c
    if sr_in_binary(c[1], span[0], span[1]):
        return None
    return span


def _sr_check_token(m):
    """a match the shapes before an earlier refinement make the same way
    (_SR_TOKEN_PREV, same group and span) is checked as before. Any other match comes from the longer
    bodies or the groups `v14`-`v17`: its body must be random. If it is rejected, the earlier rule's matches
    inside it stand instead: a rejected match is consumed whole, so a key inside it (`x1//<30>AKIA<16>`, the
    `AKIA…` that `v8` takes) or the earlier rule's own match (a run of words) would otherwise be lost."""
    g = _sr_group(m)
    s = m.string
    if m.re is _SR_TOKEN_PREV:
        return _sr_token_span(m, g, False)
    if g not in _SR_PLAIN_ONLY:
        p = _SR_TOKEN_PREV.match(s, m.start())
        if p is not None and p.end() == m.end() and _sr_group(p) == g:
            return _sr_token_span(m, g, False)
    span = _sr_token_span(m, g, True)
    if span is not None:
        return span
    # The earlier rule's scan from this match's start, as far as its end. A scan cut off there can see a
    # match that the whole text does not have (its end condition looks past the cut), so each one is
    # matched again on the whole text; after a few such, the rest of the run is left (bounded work).
    # The first of its matches that its own check accepts is redacted.
    end, pos, retries = m.end(), m.start(), 4
    while pos < end:
        c = _SR_TOKEN_PREV.search(s, pos, end)
        if c is None:
            break
        p = _SR_TOKEN_PREV.match(s, c.start())
        if p is None:
            if retries:
                retries -= 1
                pos = c.start() + 1
            else:
                pos = max(c.end(), c.start() + 1)
            continue
        span = _sr_token_span(p, _sr_group(p), False)
        if span is not None and span[0] < end:
            # a match that runs on past this one (`GOCSPX-<28>GOCSPX-<28>` after a space, `v2`) is cut at its
            # end; the rest, now after a marker, is the next pass's
            return span[0], min(span[1], end)
        if p.end() > end:
            break
        pos = max(p.end(), c.start() + 1)
    return None


_SR_ALNUM_SEG = _sr_re.compile(r"[A-Za-z0-9]{16,}")


def _sr_identifier_run(body):
    """a name, not a key body: no capital at all (`abcdefghijklmnop1`), or every
    capital starts a lower-case word of 2+ letters and digits only end a word (`HelperClassFactory2024`).
    A random key body of 20+ characters practically never has that shape."""
    if not any(c.isupper() for c in body):
        return True
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c.isupper():
            j = i + 1
            while j < n and body[j].islower():
                j += 1
            if j - i < 3:
                return False
            i = j
        elif c.isdigit():
            j = i
            while j < n and body[j].isdigit():
                j += 1
            if j < n and body[j] not in "_-":
                return False
            i = j
        else:
            i += 1
    return True


def _sr_check_token_tail(m):
    """the run after a secret marker is the rest of a glued key when it looks random: one unbroken
    letter-and-digit segment of 16+ characters with a digit and a letter (or 20+ in mixed case).
    Identifiers stay (`[REDACTED]_helper_name`, `[REDACTED]_HelperName2024`, `[REDACTED]-ConfigLoader`).
    A run followed by `+` or `=` is the cut-off rest of a base64-style key body and goes whatever its
    shape (6+ letters and digits). The marker is replaced together with the run: one marker remains."""
    body = m.group("v")
    sep = m.group("sep")
    # A z.ai key's 16-character part after its eaten hex (`[REDACTED].<16>`) always goes; anything else
    # after `.`/`//` stays when it reads as a name (`[REDACTED].HelperClassFactory2024`, review).
    zai = sep == "." and len(body) >= 16 and body[:16].isalnum() and (len(body) == 16 or body[16] in "_-")
    if zai:
        # a z.ai key's 16-character part may have no digit (~5%); after its
        # eaten hex (`[REDACTED].<16>`) it goes whatever its shape.
        return m.span()
    if sep and _sr_identifier_run(body):
        return None
    # the marker took a `ya29.`/`1//` token's prefix letters (`…ya29` then
    # `.<body>`, `…1` then `//<body>`), and a short body with no digit and no 20-character mixed segment
    # (`aaaaAaAa-aaAAaAaAa_AA`) passed every test below. After `.`/`//` a 20+ run in mixed case is that body
    # unless it is a name: _sr_identifier_run above, or after `.` a run of words shorter than any real body
    # (`FAKE_key_from_the_docs`, _sr_name_short). After `//` (a 20-character `1//` body such as
    # `uTF-cksfwkl_H_qqQwTi` passes _sr_name_body) only a comment of plain words stays: every `-`/`_` part
    # all capitals or a name by itself (`TODO_fix_this_later_please`).
    if sep and len(body) >= 20 and _SR_UPPER.search(body) and _SR_LOWER.search(body):
        if sep == "//":
            if not all(p.isupper() or _sr_identifier_run(p) for p in _SR_SEP.split(body) if p):
                return m.span()
        elif not _sr_name_short(body):
            return m.span()
    nxt = m.string[m.end():m.end() + 1]
    if nxt in ("+", "=") and sum(c.isalnum() for c in body) >= 6:
        return m.span()
    for seg in _SR_ALNUM_SEG.findall(body):
        has_d = _SR_DIGIT.search(seg) is not None
        mixed = _SR_UPPER.search(seg) is not None and _SR_LOWER.search(seg) is not None
        if (has_d and (_SR_UPPER.search(seg) or _SR_LOWER.search(seg))) or (mixed and len(seg) >= 20):
            return m.span()
    # A body split by `-`/`_` (base64url keys): random case and digits throughout, unlike an identifier
    # (`HelperName2024`: two capitals, `v2_migration_script`: one digit).
    up = len(_SR_UPPER.findall(body))
    lo = len(_SR_LOWER.findall(body))
    dg = len(_SR_DIGIT.findall(body))
    if up + lo + dg >= 12 and dg and ((up >= 3 and lo >= 3) or dg * 10 >= (up + lo + dg) * 3 and up + lo):
        return m.span()
    return None


def _sr_check_auth(m):
    # not a call (`Basic base64(user:pass)`); a `Basic` value must be base64 (sr_basic_credential);
    # any other short value with no digit (`required`) is a credential only as base64 `user:pass`
    v = m.group("v")
    if m.string[m.end("v"):m.end("v") + 1] == "(":
        return None
    if m.group("basic") is not None:
        return m.span("v") if sr_basic_credential(v) else None
    if len(v) < 20 and not any(c.isdigit() for c in v) and not sr_b64_userpass(v):
        return None
    return m.span("v")


# a bare JWT (JWS `header.payload.signature`, or a 5-part JWE) with no key name or scheme around it.
# The header is unpadded base64url JSON, so it opens with `{"` (`eyJ`), or `{` and a space, a tab or a
# line break (`eyA`, `ewk`, `ewo`, `ew0`). The token is taken only if the header decodes to a JSON object
# that names `alg` (or, not strict JSON, opens with `{` and holds `"alg"`): dotted base64 data, version
# strings, module paths and host names never do. The signature may be empty (`alg: none`); the two extra
# JWE segments are taken only when the header also names `enc` (every JWE header does).
_SR_JWT_HEAD = r"e(?:yJ|yA|wk|wo|w0)"
# A segment may be longer than SR_VALUE_MAX: an `x5c` certificate chain in the header runs to tens of KB.
# Still bounded (1 MiB per segment), and a segment never holds a `.`, so the scan stays linear.
_SR_JWT_SEG = "1048576"


def sr_jose_header(seg):
    """None when `seg` (one base64url segment, padding optional) is no JOSE header naming `alg`; else
    whether it also names `enc` (a JWE)."""
    seg = seg.rstrip("=")
    if len(seg) % 4 == 1:
        return None
    try:
        txt = _sr_base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode("utf-8")
    except (ValueError, _sr_binascii.Error):
        return None
    try:
        obj = _sr_json.loads(txt)
    except ValueError:
        t = txt.lstrip()
        return ('"enc"' in t) if t.startswith("{") and '"alg"' in t else None
    return ("enc" in obj) if isinstance(obj, dict) and "alg" in obj else None


def sr_jwt_header(seg):
    """True when `seg` decodes to a JOSE header naming `alg` (sr_jose_header)."""
    return sr_jose_header(seg) is not None


def _sr_check_jwt(m):
    """The whole token: header to signature, or to the fifth segment of a JWE. The match itself is only
    the header (the other segments sit in a lookahead), so the span ends PAST the match: a caller replaces
    up to the span's end and skips any later match that starts inside it. A rejected header consumes only
    itself, so a real JWT right after it (`<no-alg header>.<jwt>`) is still found."""
    enc = sr_jose_header(m.group("h"))
    if enc is None:
        return None
    return m.start("h"), (m.end("e5") if enc and m.group("e5") is not None else m.end("s"))


# Shell or code syntax in a "value" that opens with whitespace: a pipe, `$VAR`/`$(`, `&&`, `;`, a
# redirect, a backtick, or a path (` /srv`, ` ./x`, ` ~/x`).
_SR_CODE_AFTER_STRING = _sr_re.compile(r"[|`;<>]|\$[A-Za-z_({]|&&|(?:^|\s)(?:\\t)?[.~]{0,2}/")
# a space-led value whose words neither start with code syntax nor is a path is a password
# with special characters (`password=" a;b"`, `" x|y9"`, `" Hunter 2;x"`), not code after a closed string.
# Such code opens with the operator or a path (` ;echo`, ` .env | cut`, ` /srv`) or has a word that IS an
# operator (` x | grep y`, ` $(cat f)`). A plain split and first-character checks: linear.
_SR_CODE_FIRST = frozenset(";|&<>`)$/~.,+(")
_SR_CODE_WORD = frozenset("|;&<>`$(")


def _sr_space_led_value(v):
    words = v.replace("\\t", " ").split()
    return (bool(words) and words[0][0] not in _SR_CODE_FIRST
            and all(w[0] not in _SR_CODE_WORD for w in words[1:])
            # a word that ENDS a command (` app.conf; echo `) or pipes (` a|b c`) is code, not a password word
            and all(w[-1] not in ";|&" and "|" not in w for w in words[:-1]))


# a space-led value that _sr_space_led_value calls code (` a; b`, ` ;x`, ` .x`) is still a password
# when the keyword is NOT inside a string opened earlier on its line. Code after a closed string always
# has the keyword inside one (`grep "password=" app.conf; echo "x"`: the quote before the keyword opens
# the string, the one after `=` closes it). Paths and command substitution stay code. Bounded look-back.
_SR_LOOKBACK = 512
_SR_SUBST = _sr_re.compile(r"\$[A-Za-z_({]|`")


def _sr_json_string_start(s, lo, start):
    """In raw JSONL: the index just after the opening quote of the JSON string that holds `start` (the
    last `"` before it not escaped by an odd run of backslashes), or -1 if none lies in [lo, start)."""
    p = start
    while True:
        p = s.rfind("\"", lo, p)
        if p < 0:
            return -1
        b = p
        while b > lo and s[b - 1] == "\\":
            b -= 1
        if (p - b) % 2 == 0:
            return p + 1


def _sr_key_in_open_string(m, g, raw_json=False):
    """Whether the keyword sits inside a string opened earlier on its line. In raw JSONL the "line" is
    the decoded JSON string value, so the look-back also stops at that string's opening quote (the same
    window the decoded string has). Fails SAFE: when the window cannot reach the line start,
    quote parity is unknown, so the answer is False and the value is treated as a password (redacted)."""
    s, start = m.string, m.start()
    lo = max(0, start - _SR_LOOKBACK)
    real_nl = s.rfind("\n", lo, start)              # a line break in text
    esc_nl = s.rfind("\\n", lo, start) if raw_json else -1      # an escaped one inside raw JSONL
    str_open = _sr_json_string_start(s, lo, start) if raw_json else -1
    if real_nl < 0 and esc_nl < 0 and str_open < 0 and lo > 0:
        return False
    cut = max(real_nl + 1 if real_nl >= 0 else lo, esc_nl + 2 if esc_nl >= 0 else lo, str_open)
    seg = s[cut:start]
    if g == "v2":
        quote = "'"
    else:
        quote = "\\\"" if s[m.start(g) - 2:m.start(g)] == "\\\"" else "\""   # raw JSONL quotes are `\"`
    n = seg.count(quote)
    if quote == "\"":
        n -= seg.count("\\\"")      # an escaped quote inside a string does not open or close it
    if quote in s[start:m.start("sep")]:
        n -= 1                      # `"password": ...`: the quote before the keyword belongs to the key
    return n % 2 == 1


def _sr_space_led_password(m, g, v, raw_json=False):
    if _sr_key_in_open_string(m, g, raw_json):
        return False
    first = v.replace("\\t", " ").split()[:1]
    if not first or _SR_SUBST.search(v):
        return False
    w = first[0]
    return not (w.startswith(("/", "~/", "./", "../")) or w in (".", "..", "~"))


def _sr_check_quoted(raw_json):
    return lambda m: _sr_check_quoted_m(m, raw_json)


def _sr_check_quoted_m(m, raw_json):
    for g in ("v", "v2", "v3", "v4"):
        v = m.group(g)
        if v is not None:
            # Not a value but code between two strings: the "value" opens with `,` `+` `)` `;` (the
            # quote CLOSED a string: `"token:", fn(x),`), or it spans lines and opens with a space,
            # or it spans more lines than a password plausibly would. A TRIPLE-quoted value after `=`
            # may open with a line break: the usual Python form (`password = """\n...\n"""`). After
            # `:` such a value is more likely code after a docstring (`"""Return the token: """`).
            if sr_is_placeholder(v) or v[:1] in (",", "+", ")", ";", "]", "}"):
                return None
            # A one-line quoted value that opens with whitespace AND holds shell or code syntax is code
            # after a CLOSED string: `grep "^SECRET_KEY=" .env | cut ...` (the `"` after `=` ends
            # the pattern). A password that merely opens with a space (`" FAKE x"`) is still a value.
            if (g in ("v", "v2") and (v[:1] in (" ", "\t") or v[:2] == "\\t")
                    and _SR_CODE_AFTER_STRING.search(v) and not _sr_space_led_value(v)
                    and not _sr_space_led_password(m, g, v, raw_json)):
                return None
            if "\n" in v or "\\n" in v:
                lead = v[:1].isspace() or v[:2] == "\\n"
                if len(v) > 4096 or (lead and not (g in ("v3", "v4") and m.group("sep") == "=")):
                    return None
            return m.span(g)
    return None


def _sr_check_json(raw_json):
    def check(m):
        kind = sr_key_kind(m.group("k"))
        if kind is None:
            return None
        if m.group("v3") is not None:
            # A bare number. In raw JSONL only inside an escaped (JSON-in-a-string) object: a real
            # JSON number cannot become a marker without breaking the line.
            if raw_json and not m.group("kq"):
                return None
            return m.span("v3") if sr_secret_value(kind, int(m.group("v3"))) else None
        for g in ("v", "v2", "v4"):
            if m.group(g) is not None:
                return m.span(g) if sr_secret_value(kind, m.group(g)) else None
        return None
    return check


_SR_NOT_CODE_VALUE = _sr_re.compile(SR_CODE_VALUE)
# A shell expansion, not a value: `GH_TOKEN="$tok"`, `"${TOKEN:-}"`, `"$(cat token.txt)"`, backticks.
_SR_SHELL_REF = _sr_re.compile(r"\$[A-Za-z_{(]|`")


def _sr_nested_key(m):
    """nested_assignment's whole key: the rule's `k` group starts at a secret word, so walk back over
    the rest of the identifier (`DB_PASSWORD`, `x.api_key`), but not into an escape (`\\nDB_PASSWORD`)."""
    s, i = m.string, m.start("k")
    j = i
    while j > 0 and i - j < 128 and (s[j - 1].isalnum() or s[j - 1] in "_.-") and s[j - 1].isascii():
        j -= 1
    if j and s[j - 1] == "\\" and s[j - 1:j + 1] in ("\\n", "\\t", "\\r") and j < i:
        j += 1                          # `\nDB_PASSWORD=`: the `n` belongs to the escape, not the key
    return s[j:m.end("k")]


def _sr_check_nested(m):
    """the value under a secret-named key, unless it is a placeholder, an env-var name or a
    code reference (`read_api_key`, `Optional[str]`)."""
    kind = sr_key_kind(_sr_nested_key(m))
    v = m.group("v")
    if (kind is None or not sr_secret_value(kind, v) or not _SR_NOT_CODE_VALUE.match(v.strip())
            or _SR_SHELL_REF.match(v.strip())):
        return None
    # Code between two strings, not a value (as in quoted_assignment): `token = ", fn(x), "`,
    # `TOKEN=" | grep -A "`, `key = " + x + "`. A secret neither opens with a space, `,;)]}` or
    # `+ ` nor is a spaced run of shell syntax (a base64 secret may open with `+`; a password may hold
    # `&&` or `|`, code between strings has spaces). A quoted key (`"password": "…"`) is JSON or a
    # dict literal: data, whatever the value holds.
    if not m.group("kq") and (v[:1].isspace() or v[:1] in ",;)]}" or (v[:1] == "+" and v[1:2].isspace())
                              or (" " in v and _SR_CODE_AFTER_STRING.search(v))):
        return None
    return m.span("v")


# values that are ordinary words in code and prose (`credentials: "include"`, `token = "expired"`).
# Kept under every secret-named key at depth 0, except `password` under a password-type key and
# `secret` under any key but `auth` (; see _sr_depth0_word).
_SR_DEPTH0_WORDS = frozenset((
    "include", "omit", "same-origin", "same_origin", "cors", "no-cors", "navigate", "expired", "invalid",
    "valid", "missing", "required", "optional", "success", "failure", "failed", "error", "ok", "true",
    "false", "null", "nil", "none", "undefined", "bearer", "basic", "digest", "token", "password", "secret",
    "key", "hidden", "text", "string", "number", "boolean", "object", "default", "auto", "manual", "on",
    "off", "yes", "no", "enabled", "disabled", "pending", "active", "inactive", "unknown", "redacted"))
_SR_VOWELS = frozenset("aeiouyAEIOUY")


def _sr_depth0_secret_shape(value):
    """whether a value is shaped like a secret rather than like words.

    A value is word-shaped when it is made only of letter runs that read like words (each run all
    lower, Title or all upper case, a vowel unless it is an abbreviation of 3 letters or fewer, no run
    of 5 consonants, at most 20 letters), joined by `-`, `_`, `.` or spaces. Anything else (a digit, a
    symbol, camelCase, more than 20 letters in a run) is secret-shaped. This is a weak filter: 12-54%
    of random single-case letter strings of 8-20 letters pass as words, so it is applied only under
    `auth`-kind keys (see _sr_depth0_word)."""
    w = value.strip()
    if not w:
        return False
    run = ""
    for c in w + " ":
        if c.isascii() and c.isalpha():
            run += c
            continue
        if c not in "-_. ":
            return True
        if run:
            if (len(run) > 20 or not (run.islower() or run.isupper() or run.istitle())
                    or (len(run) > 3 and not any(x in _SR_VOWELS for x in run))):
                return True
            cons = 0
            for x in run.lower():
                cons = 0 if x in _SR_VOWELS else cons + 1
                if cons >= 5:
                    return True
        run = ""
    return False


def _sr_depth0_word(kind, value):
    """whether a DEPTH-0 (plain text) nested_assignment value under a key of this `kind`
    is an ordinary word rather than the secret.

    - A word on _SR_DEPTH0_WORDS, under any kind (`credentials: "include"`, `token = "expired"`,
      `pass: "success"`), except two that are common real passwords: `password` under a password-type
      key (`pass: "password"`) and `secret` under any key but `auth` (`SECRET_KEY = "secret"`).
    - Any word-shaped value (_sr_depth0_secret_shape), but only under an `auth`-kind key (`auth`,
      `authorization`, `x-auth`: a mode word such as `auth: "session"`). Under password, pwd, secret,
      token, api/access/private key and credential keys a word IS the secret (`passphrase =
      "correct-horse-battery-staple"`, `secret = "letmein"`, `access_key = "FQAGQLEWRAYQJUCWIQLF"`).

    Known limitation: under an `auth`-kind key, a credential made only of single-case letters in
    word-like runs (`auth: "FQAGQLEWRAYQJUCWIQLF"`, `auth: "LYHR-RYQK-UHTZ-ZYGZ"`) is not redacted at
    depth 0, as before. sr_auth_value still catches the usual shapes (a digit, a colon, mixed-case
    base64, `<scheme> <cred>` with a digit or mixed case), and depth >= 1 is unaffected."""
    low = value.strip().lower()
    if low in _SR_DEPTH0_WORDS:
        if low == "secret":
            return kind == "auth"
        return not (low == "password" and kind in ("password", "pwd"))
    return kind == "auth" and not _sr_depth0_secret_shape(value)


def _sr_check_nested_depth(raw_json):
    """nested_assignment's check: _sr_check_nested, plus the ordinary-word test at depth 0,
    i.e. no escape before the opening quote on decoded text, the line's own one in raw JSONL. Deeper
    matches (escaped JSON in a tool result, what the rule is for) are unchanged."""
    top = 1 if raw_json else 0

    def check(m):
        span = _sr_check_nested(m)
        if (span is not None and len(m.group("q")) <= top
                and _sr_depth0_word(sr_key_kind(_sr_nested_key(m)), m.group("v"))):
            return None
        return span
    return check


def _sr_ci(*words):
    """A case-insensitive alternation of `words` spelled per character, its first letter a single
    class: `[PpTt](?:(?<=[Pp])[Aa][Ss][Ss]|(?<=[Tt])[Oo][Kk][Ee][Nn])`. The regex engine skips ahead to
    a possible first letter only when a pattern starts with ONE class (not with (?i) or a branch),
    which makes a scan of long text several times faster."""
    def spell(w):
        return "".join("[" + c.upper() + c.lower() + "]" if c.isalpha() else _sr_re.escape(c) for c in w)
    groups = {}
    for w in words:
        groups.setdefault(w[0].lower(), []).append(w[1:])
    firsts = "".join(c.upper() + c for c in groups)
    tails = "|".join("(?<=[" + c.upper() + c + "])(?:" + "|".join(spell(x) for x in tl) + ")"
                     for c, tl in groups.items())
    return "[" + firsts + "](?:" + tails + ")"


# Necessary lower-case substrings: a rule can only match text whose lower-cased form contains one
# of its entries, so a caller may skip the rule (or the lines) without one. Most text has none.
SR_PRECHECK = {
    "token_tail": ("[redacted",),
    "jwt": ("eyj", "eya", "ewk", "ewo", "ew0"),
    "auth_header": ("authorization",),
    "bearer": ("bearer",),
    "digest": ("response", "cnonce"),
    "aws_signature": ("signature", "security-token"),
    "quoted_assignment": ("key", "secret", "token", "passw", "passphrase", "credential"),
    "json_assignment": ("pass", "secret", "token", "key", "cred", "auth", "pwd", "pin", "otp", "cookie"),
    "nested_assignment": ("pass", "secret", "token", "key", "cred", "auth", "pwd"),
    "assignment": ("key", "secret", "token", "passw", "bearer", "credential"),
    "weakpass": ("passw",),
    "inline_userpass": ("-u",),
    "cmd_password": ("pass", "pwd"),
    "cmd_userpass": ("-u",),
    "pass_assignment": ("pass", "pwd"),
    "mysql_password": ("mysql", "mariadb"),
}


@_sr_functools.lru_cache(maxsize=2)
def sr_rules(raw_json=False):
    """[(name, pattern, check)] -- see the module docstring. The caller picks the order.

    No possessive quantifiers or atomic groups: those need Python 3.11.
    Each value run is either the last thing in its pattern or followed by something it cannot
    contain (its closing quote, a non-hex character), so backtracking never yields a shorter match
    and costs at most one pass over the run."""
    n = _SR_N
    # An optional backslash before a quote (`\\"`, a quote inside a JSON string). In raw JSONL it may
    # only be taken when a quote follows: a bare `\\?` also eats the backslash of `\\n` or `\\t` and
    # the redaction then leaves a broken escape (`token:\\[REDACTED]`, review).
    bq = r"(?:\\(?=[\"']))?" if raw_json else r"\\?"
    q = bq if raw_json else ""
    bs = "\\\\" if raw_json else ""          # value runs stop at a backslash in raw JSONL
    nl = r"(?:\\r)?\\n" if raw_json else r"\r?\n"
    ws = r"[ \t]" if raw_json else r"\s"      # raw JSONL has no real line breaks inside a value
    cls = r"A-Za-z0-9._~+/=:\-"
    rules = [
        # Known token shapes (GitHub, OpenAI, Anthropic, Slack, AWS, Stripe, Google, Groq, xAI, z.ai key).
        # The `sk-` alternative is OpenAI's HYPHEN form and matches none of Stripe's; a live webhook
        # signing secret was missed because of that gap. `pk_` is absent on
        # purpose: publishable keys are public by design. Every run is token characters only, so it
        # is JSON-safe. The caller runs it before weakpass, so a password that IS a vendor token keeps
        # no tail.
        # Group `v2`: OpenAI's newer keys carry `_`/`-` in the body after a fixed
        # infix (`sk-proj-`, `sk-svcacct-`, `sk-admin-`; OpenRouter `sk-or-v1-`), Google API keys,
        # OAuth access/refresh tokens and client secrets, Groq `gsk_` and xAI `xai-` keys. These use
        # a BASE64-AWARE boundary instead of `\b`: never preceded by a base64/base64url character and
        # never followed by one, so a run inside image or file data (`…+1//ab…`) is not a key. `=`
        # may precede (`key=AIza…`) because base64 padding only ends a run. A value that is followed
        # by a token character does not match at all (no shorter match), so backtracking is bounded.
        # right after `/`, `+`, `_` or a URL escape (`%20`, `%3D`) the same shapes are keys too
        # (`https://x/?q=…&k=%20AIza…`, `CONF_sk-proj-…`), groups `v3`/`v4`, but only OUTSIDE binary data
        # (sr_binary_spans): there those characters are base64 and a key-like run is image bytes.
        # in raw JSONL a key that starts a line or follows a tab sits right after the escape
        # `\\n`/`\\r`/`\\t`, whose letter is a word/body character, so neither start above fires there.
        # One branch led by the literal backslash (groups `v5`/`v6`) covers it: it fails at once
        # everywhere else, so the scan stays fast. It runs on plain text too, where `\\n` is literal
        # text (code, a quoted log), so both inputs agree.
        # a classic key may also end right before `_` (_SR_CLS_END; `ghp_…_notes` used to fail `\b`
        # and leak); one followed by `_` must pass _sr_glued_key_like (_sr_check_token).
        ("token", _SR_TOKEN, _sr_check_token),
        # keys written back to back (`sk-<48>sk-<48>`, `ghp_<36>xoxb-…`). A variable-length body
        # takes the next key's prefix letters (`…sk`, `…ghp`), so the next key's body is left right
        # after the marker (`[REDACTED]-<48>`). A key-like run glued to a secret marker is redacted
        # with it. Runs after the `token` rule, so the marker exists.
        # the previous body may also take the next key's prefix up to its `.`/`//`
        # (`…ya29` then `.<body>`, `…1` then `//<body>`, a z.ai key's hex then `.<16>`), so one `.` or
        # `//` may sit between the marker and the run; there a name stays (_sr_identifier_run).
        ("token_tail", _sr_re.compile(
            r"(?:" + _SR_SECRET_MARK + r")(?P<sep>\.|//)?(?P<v>[A-Za-z0-9_-]{6," + n + r"})"), _sr_check_token_tail),
        # `Authorization: <scheme> <credential>` (and `Proxy-Authorization`), any scheme or none, the
        # value on the same line or the next. The scheme word is kept. The value must look like a
        # credential (a digit, or 20+ characters; `Basic`: see sr_basic_credential) and not be a call
        # (`base64(...)`), so prose ("Authorization: header must be set") is left alone. The header
        # name is spelled per character so the engine can skip ahead to an `a`.
        ("auth_header", _sr_re.compile(
            r"[Aa](?<![A-Za-z0-9_][Aa])[Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]" + bq + r"[\"']?[ \t]{0,8}[:=]"
            r"[ \t]{0,8}(?:" + nl + r"[ \t]{0,8})?" + bq + r"[\"']?"
            r"(?:(?P<basic>(?i:basic)[ \t]{1,8})"
            r"|(?:[A-Za-z][A-Za-z0-9_-]{0,19}[ \t]{1,8})?"
            r"(?=[" + cls + r"]{0,4095}?[0-9]|[" + cls + r"]{20}|[A-Za-z0-9+/]{8}))"
            r"(?!(?i:bearer|basic|token|digest|negotiate|ntlm)\b|" + _SR_MARK + r")"
            r"(?P<v>[" + cls + r"]{6,4096})"), _sr_check_auth),
        # A bare `Bearer <token>` with no header name before it (a curl line split across lines, a
        # log, a doc). 16+ token characters, so "the bearer of bad news" is left alone.
        ("bearer", _sr_re.compile(
            r"[Bb][Ee][Aa][Rr][Ee][Rr][ \t]{1,8}(?!" + _SR_MARK + r")"
            r"(?P<v>[A-Za-z0-9._~+/-]{16," + n + r"}={0,2})"), _sr_span("v")),
        # HTTP Digest: the `response=` hash and the client nonce. `nonce`, `realm`, `uri` are public.
        ("digest", _sr_re.compile(
            r"[RrCc](?<![A-Za-z0-9_][RrCc])"
            r"(?:(?<=[Rr])[Ee][Ss][Pp][Oo][Nn][Ss][Ee][ \t]{0,4}=[ \t]{0,4}" + bq + r"[\"']?(?P<v>[0-9a-fA-F]{16,128})(?![0-9A-Za-z])"
            r"|(?<=[Cc])[Nn][Oo][Nn][Cc][Ee][ \t]{0,4}=[ \t]{0,4}" + bq + r"[\"']?(?P<v2>[A-Za-z0-9+/=._-]{8,1024}))"),
         _sr_span("v", "v2")),
        # AWS SigV4 `Signature=<hex>` (the header and `X-Amz-Signature=` in a presigned URL), a SigV2
        # base64 `Signature=`, and the `X-Amz-Security-Token=` session token. A code name such as
        # `signature=hmac_sha256` has no upper-case letter and is left alone.
        ("aws_signature", _sr_re.compile(
            r"[SsXx](?<![A-Za-z0-9_][SsXx])"
            r"(?:(?<=[Ss])[Ii][Gg][Nn][Aa][Tt][Uu][Rr][Ee][ \t]{0,4}=[ \t]{0,4}" + bq + r"[\"']?"
            r"(?:(?P<v>[0-9a-fA-F]{32,128})(?![0-9A-Za-z%+/_-])"
            r"|(?=[A-Za-z0-9%+/_-]{0,1023}?[0-9%])(?=[A-Za-z0-9%+/_-]{0,1023}?[A-Z])"
            r"(?P<v2>[A-Za-z0-9%+/_-]{16,1024}={0,2}))"
            r"|(?<=[Xx])-[Aa][Mm][Zz]-[Ss][Ee][Cc][Uu][Rr][Ii][Tt][Yy]-[Tt][Oo][Kk][Ee][Nn][ \t]{0,4}=[ \t]{0,4}"
            r"(?P<v3>[A-Za-z0-9%+/_-]{16," + n + r"}={0,2}))"), _sr_span("v", "v2", "v3")),
    ]
    # A QUOTED secret assignment whose value the assignment rules would cut short: it contains
    # whitespace (`password = "two word phrase"`, a multi-line value), the other quote or an escaped
    # quote, or it is triple-quoted. The whole value is replaced and the quotes are kept. Starts at
    # the keyword; every branch is bounded and stops at its own closing quote.
    kw = _sr_ci("api_key", "api-key", "apikey", "secret", "token", "passwd", "password", "passphrase",
                "credential", "private_key", "private-key", "privatekey", *_SR_KEY_WORDS)
    if raw_json:
        # Raw JSONL: the quotes around the value are JSON-escaped (`\"`), and a JSON escape inside it
        # (`\n`, `\\`) is taken whole, so the span never cuts one in half; `\"` ends the value.
        ve = r"(?:[^\"\\\n]|\\[^\"\n])"
        ve1 = r"(?:[^'\"\\\n]|\\[^'\"\n])"      # inside '...': a JSON escape (`\t`) is taken whole
        quoted = (r"(?:\\\"\\\"\\\"(?P<v3>" + ve + r"{1," + n + r"})\\\"\\\"\\\""
                  r"|\\\"(?=" + ve + r"{0," + n + r"}?(?:[ \t']|\\[nrt]))(?!" + _SR_MARK + r")"
                  r"(?P<v>" + ve + r"{1," + n + r"})\\\""
                  r"|'''(?P<v4>(?:[^'\"\\\n]|\\[^\"\n]|'(?!'')){1," + n + r"})'''"
                  r"|'(?=" + ve1 + r"{0," + n + r"}?(?:[ \t]|\\[nrt]))(?!" + _SR_MARK + r")(?P<v2>" + ve1
                  + r"{1," + n + r"})')")
    else:
        quoted = (r"(?:\"\"\"(?P<v3>(?:[^\"\\]|\\[\s\S]|\"(?!\"\")){1," + n + r"})\"\"\""
                  r"|'''(?P<v4>(?:[^'\\]|\\[\s\S]|'(?!'')){1," + n + r"})'''"
                  r"|\"(?=[^\"]{0," + n + r"}?[\s'\\])(?!" + _SR_MARK + r")"
                  r"(?P<v>(?:[^\"\\]|\\[\s\S]){1," + n + r"})\""
                  r"|'(?=[^']{0," + n + r"}?[\s\"])(?!" + _SR_MARK + r")(?P<v2>[^']{1," + n + r"})')")
    rules.append(("quoted_assignment", _sr_re.compile(
        kw + q + r"[\"']?[ \t]{0,8}(?P<sep>[:=])[ \t]{0,8}" + quoted), _sr_check_quoted(raw_json)))
    # JSON (or a Python dict) embedded in TEXT: `{"api_key": "X"}`, `'password': 'X'`, escaped
    # `{\"secret\": \"X\"}`, a bare number (`{\"pin\": 4821}`). The assignment rule needs `[:=]` right
    # after the keyword, and the quote that closes the key sits in between. Starts only at a quote.
    # Whether the key names a secret and the value is one (not `${SECRET_KEY}`, `<your token>`,
    # `OPENAI_API_KEY`) is decided by sr_key_kind and sr_secret_value, the same functions that
    # judge decoded JSONL keys.
    sq = "\"" if raw_json else ""             # in raw JSONL a bare `"` ends the JSON string
    rules.append(("json_assignment", _sr_re.compile(
        r"[\"'](?=[A-Za-z0-9_.:/~\-]{0,128}?"
        + _sr_ci("pass", "secret", "token", "key", "cred", "auth", "pwd", "pin", "otp", "cookie") + ")"
        r"(?P<k>[A-Za-z0-9_.:/~\-]{1,128})(?P<kq>\\?)[\"'][ \t]{0,8}[:=][ \t]{0,8}"
        r"(?:\"(?!" + _SR_MARK + r")(?P<v>(?:[^\"\\\n]|\\[^\n]){1," + n + r"})\""
        r"|\\\"(?!" + _SR_MARK + r")(?P<v4>[^\"\\\n]{1," + n + r"})\\\""
        r"|(?P<e2>\\?)'(?!" + _SR_MARK + r")(?P<v2>[^'\\\n" + sq + r"]{1," + n + r"})(?P=e2)'"
        r"|(?P<v3>-?[0-9]{4,64})(?![0-9A-Za-z_.]))"), _sr_check_json(raw_json)))
    # a secret-named assignment whose value sits in ESCAPED double quotes, at any nesting depth:
    # `PASSWORD = \"…\"` / `{\"password\": \"…\"}` in a tool result that is itself JSON text, or
    # `\\\"…\\\"` one string deeper. The closing quote must carry the same backslash run as the
    # opening one. Only deeper than the rules above reach: one escape or more on a decoded string,
    # three or more in a raw JSONL line (one is the line's own quoting). The key and value are judged
    # by sr_key_kind and sr_secret_value, as for a JSON key, so `${DB_PASSWORD}`, `<your token>` and
    # an env-var name stay. Starts AT a key word (a glued prefix, `DB_`, is read back by the check),
    # so the engine skips to candidate letters; every part is bounded.
    rules.append(("nested_assignment", _sr_re.compile(
        r"(?P<k>" + _sr_ci("pass", "secret", "token", "key", "cred", "auth", "pwd")
        + r"[A-Za-z0-9_.\-]{0,128})(?P<kq>\\{0,64}[\"'])?[ \t]{0,8}[:=][ \t]{0,8}"
        r"(?P<q>\\{" + ("1" if raw_json else "0") + r",64})\"(?!" + _SR_MARK + r")"
        r"(?P<v>[^\"\\\n\r]{1," + n + r"})(?P=q)\""), _sr_check_nested_depth(raw_json)))
    # A weakpass value character (see that rule below). never a backslash that starts an
    # escaped quote (`PASSWORD = \\\"…\\\"` two strings deep): taking it would break the JSON it sits in.
    v = (r"(?:[^\s'\"," + bs + r";\\]|\\(?!\\{0,64}\"))" if not raw_json else r"[^\s'\"," + bs + r";]")
    weak_more = _sr_re.compile(v + r"|[,;]" + v)
    # key/token/password/secret assignments. The keyword may be GLUED to a prefix (LC_APIKEY=...,
    # MY_TOKEN: ...); the match starts AT the keyword and a glued prefix stays in place, outside it.
    # (The old `\b[A-Za-z0-9_]{0,64}?` prefix tried 64 starts per word,.) A password value that
    # goes on past this rule's characters (`Abcd1234!tail`) is left to the weakpass rule below, which
    # takes it whole; cutting it here would leave the tail.
    def check_assignment(m):
        if m.group("k")[:4].lower() == "pass" and weak_more.match(m.string, m.end("v")):
            return None
        return m.span("v")
    rules.append(("assignment", _sr_re.compile(
        r"(?P<k>" + _sr_ci("api_key", "api-key", "apikey", "secret", "token", "passwd", "password", "bearer",
                           "credential", "private_key", "private-key", "privatekey", *_SR_KEY_WORDS) + r")"
        + ws + r"{0,64}[:=]" + ws + r"{0,64}" + q + r"['\"]?(?i:" + SR_CODE_VALUE + ")" +
        r"(?P<v>[A-Za-z0-9._\-/+]{8," + n + r"})" + q + r"(?:['\"](?!" + v + r"))?"), check_assignment))
    # A password/passwd assignment with a SHORT or special-character value (`password=123qwe@`).
    # Quote/space-free, so prose like `password = **"pali"**` is not swept up. A `,` or `;` ends the
    # value unless more value follows it (`a,b`), so `password=x, user=bob` keeps its comma. A value
    # that is a whole marker is never touched again, so a second pass changes nothing; a marker with a
    # tail (`[REDACTED-SECRET]-FAKEtail`: a vendor-token rule ran first) is redacted whole. A closing
    # quote is consumed only when nothing follows it, so no tail can end up glued to the marker.
    # Placeholders (`${DB_PASSWORD}`, `<your password>`) are left alone.
    def check_weakpass(m):
        val = m.group("v")
        if not val.startswith("[REDACTED") and (sr_is_placeholder(val) or val.startswith(("${", "<", "{{"))):
            return None
        return m.span("v")
    rules.append(("weakpass", _sr_re.compile(
        r"(?P<k>" + _sr_ci("passwd", "password") + r")" + ws + r"{0,64}[:=]" + ws + r"{0,64}" + q + r"['\"]?"
        + "(?i:" + SR_TYPING_VALUE + ")(?!" + _SR_MARK + r"(?:\)|(?!" + v + r"|[,;]" + v + r")))"
        r"(?P<v>(?:" + v + r"|[,;](?=" + v + r")){3," + n + r"})" + q + r"(?:['\"](?!" + v + r"))?"),
        check_weakpass))
    # An inline `user%pass` credential (smbclient/curl `-U 'user%pass'`): no keyword, so the
    # assignment rules can't see it. Only the password half is replaced; the user is kept.
    rules.append(("inline_userpass", _sr_re.compile(
        r"-U" + ws + r"{1,64}" + bq + r"['\"]?[^\s'\"%" + bs + r"]{0,1024}%"
        r"(?P<v>[^\s'\"" + bs + r"]{1," + n + r"})"), _sr_span("v")))
    # --- passwords given on a command line ---------------------------------
    # Each rule starts at a literal anchor (the flag, `-u`, the key, the client's name) and replaces
    # only the value; the flag, the user and any quotes stay. A marker is never matched again, so a
    # second pass changes nothing.
    val = _sr_cmd_value(raw_json)
    # `--password X`, `--password=X`, `--db-password 'X'`, `--pass X`, `--pwd X`. (`--password=X` is
    # usually taken by weakpass first; this rule then sees the marker and leaves it.)
    rules.append(("cmd_password", _sr_re.compile(
        _sr_lb("A-Za-z0-9_-", raw_json) + r"--(?:[A-Za-z0-9]{1,32}-){0,3}"
        + _sr_ci("password", "passwd", "pass", "pwd") + r"(?![A-Za-z0-9_-])(?:=|[ \t]{1,8})" + val),
        _sr_check_cmd("flag", raw_json)))
    # `curl -u user:X`, `--user user:X`, `-u 'user:X'`, `-u "user:p w"`, glued `-uuser:X`: the password
    # half; the user is kept, even when it equals the password (`admin:admin` is a real default
    # credential). Only a numeric `uid:gid` (`docker run -u 1000:1000`) is left alone.
    if raw_json:
        dq = (r"\\\"(?P<u>[^\"\\\n:]{0,256}):(?!" + _SR_MARK + r")(?P<v1>(?:[^\"\\\n]|\\[^\"\n]){1," + n
              + r"})\\\"")
    else:
        dq = r"\"(?P<u>[^\"\n:]{0,256}):(?!" + _SR_MARK + r")(?P<v1>[^\"\n]{1," + n + r"})\""
    rules.append(("cmd_userpass", _sr_re.compile(
        _sr_lb("A-Za-z0-9_-", raw_json)
        + r"(?:-u(?:=|[ \t]{1,8}|(?=[^\s'\":" + bs + r"]{1,256}:))|--user(?:=|[ \t]{1,8}))"
        r"(?:" + dq + r"|'(?P<u2>[^'\n:" + bs + r"]{0,256}):(?!" + _SR_MARK + r")(?P<v2>[^'\n" + bs + r"]{1,"
        + n + r"})'|" + bq + r"[\"']?(?P<u3>[^\s'\":" + bs + r"]{0,256}):(?!" + _SR_MARK + r")"
        r"(?P<v3>[^\s'\"`;&|<>()" + bs + r"]{1," + n + r"}))"), _sr_check_cmd("user", raw_json)))
    # `db_pass=X`, `DB_PASS=X`, `pass=X`, `pwd=X`: a key that ends in `pass` or `pwd` (not `bypass`,
    # `pass_file`, `password`, which other rules own). `pwd=` with a path value (`pwd=/home/x`,
    # `PWD=~/src`, `pwd=src/app`, `pwd=$(pwd)`) is a working directory and is left alone. YAML
    # `db_pass: X` only with a prefixed key (a bare `pass:` is prose), never `obj.pass = X` (code).
    rules.append(("pass_assignment", _sr_re.compile(
        _sr_lb("A-Za-z", raw_json) + r"(?P<k>" + _sr_ci("pass", "pwd") + r")(?![A-Za-z0-9_])"
        + ws + r"{0,8}(?P<sep>[:=])" + ws + r"{0,8}" + val), _sr_check_cmd("key", raw_json)))
    # `mysql -u root -pX db`, `mysqldump -p'X'`, `mariadb -pX`: a password GLUED to `-p`, only on a
    # mysql/mariadb command line (elsewhere `-p` is a port, `mkdir -p`, `-pthread`, ...).
    rules.append(("mysql_password", _sr_re.compile(
        _sr_lb("A-Za-z0-9_", raw_json) + r"(?:mysql|mariadb)[A-Za-z-]{0,16}(?![A-Za-z0-9_])"
        + (r"(?:[^\n|;&\\]|\\[^nr]){0,256}?" if raw_json else r"[^\n|;&]{0,256}?")   # `-e "q"`: an escaped quote
        + r"[ \t]-p" + val), _sr_check_cmd("mysql", raw_json)))
    # a bare JWT, redacted whole (sr_jose_header, _sr_check_jwt). Callers run it LAST, after every
    # other rule (the personal-data rules too): a JWT glued onto a key name, a host or
    # an email (`<jwt>password=X`, `<jwt>user@x.co`) would otherwise take those letters into its signature,
    # and the rule that owns them, left without its anchor, would keep the value. Run last, that value is
    # already a marker. A keyed JWT (`token=<jwt>`, `Bearer <jwt>`) is taken whole by its keyed rule.
    # The match is the HEADER only; payload, signature and the JWE's two extra segments are captured in a
    # lookahead. It starts where a base64url run starts, right after a `\\n`/`\\r`/`\\t` escape, or right
    # after a URL escape (`%3D<jwt>`, `Bearer%20<jwt>`). Not caught: a JWT glued onto other letters or
    # digits (`abc<jwt>`, `id_<jwt>`; as for the vendor keys), and one wrapped across lines (no secret rule
    # joins lines). A JWT spelled with JSON escapes (`\\u002e`) is found in the decoded view
    # (sr_escaped_spans).
    js = _SR_JWT_SEG
    rules.append(("jwt", _sr_re.compile(
        r"(?:" + _sr_lb("A-Za-z0-9_-", raw_json) + r"|(?<=\\[nrt])|(?<=%[0-9A-Fa-f]{2}))"
        r"(?P<h>" + _SR_JWT_HEAD + r"[A-Za-z0-9_-]{8," + js + r"})"
        r"(?=\.(?P<p>[A-Za-z0-9_-]{0," + js + r"})\.(?P<s>[A-Za-z0-9_-]{0," + js + r"})(?![A-Za-z0-9_-])"
        r"(?:\.(?P<e4>[A-Za-z0-9_-]{0," + js + r"})\.(?P<e5>[A-Za-z0-9_-]{1," + js + r"})(?![A-Za-z0-9_-]))?)"),
        _sr_check_jwt))
    return rules


def _sr_lb(cls, raw_json):
    """A match-start guard: not right after a character of `cls`. In raw JSONL a match may also start
    right after a JSON escape (`\\n`, `\\t`, `\\"`, `\\\\`, `\\u00e9`), where the decoded string has a
    boundary, and never ON an escape's letter (that would leave a dangling backslash)."""
    if not raw_json:
        return "(?<![" + cls + "])"
    return ("(?:(?<![\\\\" + cls + "])|(?<=\\\\[bfnrt/\"\\\\])|(?<=\\\\u[0-9A-Fa-f]{4}))")


def _sr_wb(raw_json):
    """`\\b` before a word character; the raw-JSONL form also treats a JSON escape as a boundary."""
    return r"\b" if not raw_json else _sr_lb("\\w", True)


def _sr_cmd_value(raw_json):
    """A command-line value: quoted (`"..."`, `'...'`) or a bare run up to whitespace, a quote or a
    shell operator. Never an existing marker. Groups v1 (double), v2 (single), v3 (bare)."""
    n = _SR_N
    if raw_json:
        return (r"(?:\\\"(?!" + _SR_MARK + r")(?P<v1>(?:[^\"\\\n]|\\[^\"\n]){1," + n + r"})\\\""
                r"|'(?!" + _SR_MARK + r")(?P<v2>[^'\"\\\n]{1," + n + r"})'"
                r"|(?![\"'\\]|" + _SR_MARK + r")(?P<v3>[^\s'\"`;&|<>()\\]{1," + n + r"}))")
    # a bare value never takes a backslash that opens an escaped quote (`db_pass=\"…\"` in a
    # string that is itself JSON): replacing it would break that JSON.
    return (r"(?:\"(?!" + _SR_MARK + r")(?P<v1>[^\"\n]{1," + n + r"})\""
            r"|'(?!" + _SR_MARK + r")(?P<v2>[^'\n]{1," + n + r"})'"
            r"|(?![\"']|" + _SR_MARK + r")(?P<v3>(?:[^\s'\"`;&|<>()\\]|\\(?!\\{0,64}\")){1," + n + r"}))")


# prose after a flag name is not its value: "use the --password flag", "--password is required"
_SR_CMD_PROSE = frozenset({"flag", "flags", "option", "options", "argument", "arguments", "arg", "args",
                           "parameter", "param", "switch", "and", "or", "is", "are", "was", "to", "the",
                           "a", "an", "with", "for", "in", "on", "of", "if", "you", "when", "prompt",
                           "instead", "only", "not", "will", "must", "should", "can", "here", "below",
                           "above", "value", "values"})
_SR_CMD_PATH = _sr_re.compile(r"[/~\\.]|[A-Za-z]:[\\/]")
_SR_TYPE_NAME = _sr_re.compile(r"(?:typing\.)?(?:Optional|Union|List|Dict|Any|str|bytes|int|bool|None|SecretStr)\b")


# a container runtime's OWN `-u`/`--user` is `user[:group]`, never a password
# (`docker run -u node:node`, `podman exec --user app:app`). Exempt only when, in the same command segment
# (back to a line break, `;`, `&` or `|`, at most 512 characters), the runtime and its subcommand come first
# and EVERY token between the subcommand and this `-u` is one of the runtime's options (a value-taking
# option consumes the next token). The first non-option token is the image or container: what follows it is
# the command the container runs (`docker run img curl -u admin:pw`), and its `-u` stays a password. An
# unknown option counts as a flag, so its value ends the option list early: the safe side. The value must
# be a POSIX user/group name or a number. A bounded token scan, no regex.
_SR_CONTAINER_RT = frozenset({"docker", "podman", "nerdctl"})
_SR_CONTAINER_SUB = frozenset({"run", "exec", "create"})
_SR_CONTAINER_GROUP = frozenset({"compose", "container"})       # `docker compose run`, `docker container run`
_SR_CONTAINER_VALUE_OPTS = frozenset({
    "-a", "--attach", "--add-host", "--annotation", "--blkio-weight", "-c", "--cpu-shares", "--cap-add",
    "--cap-drop", "--cgroup-parent", "--cgroupns", "--cidfile", "--cpus", "--cpuset-cpus", "--cpuset-mems",
    "--detach-keys", "--device", "--dns", "--dns-option", "--dns-search", "--domainname", "-e", "--env",
    "--env-file", "--entrypoint", "--expose", "--gpus", "--group-add", "--health-cmd", "--health-interval",
    "--health-retries", "--health-start-period", "--health-timeout", "-h", "--hostname", "--ip", "--ip6",
    "--ipc", "--isolation", "-l", "--label", "--label-file", "--link", "--log-driver", "--log-opt",
    "--mac-address", "-m", "--memory", "--memory-reservation", "--memory-swap", "--mount", "--name",
    "--network", "--net", "--network-alias", "--oom-score-adj", "-p", "--publish", "--pid", "--pids-limit",
    "--platform", "--pull", "--restart", "--runtime", "--security-opt", "--shm-size", "--stop-signal",
    "--stop-timeout", "--storage-opt", "--sysctl", "--tmpfs", "--ulimit", "-u", "--user", "--userns",
    "--uts", "-v", "--volume", "--volume-driver", "--volumes-from", "-w", "--workdir"})
# `exec` has its own, short option list: there `-l` is podman's `--latest` FLAG (it was read as `run`'s
# `--label <value>`, which swallowed the container name, so `podman exec -l curl -u admin:pw` kept the
# password,). `--preserve-fds` (podman) and `--index` (compose) take a value.
_SR_CONTAINER_EXEC_VALUE_OPTS = frozenset({
    "-e", "--env", "--env-file", "--detach-keys", "-u", "--user", "-w", "--workdir", "--preserve-fds",
    "--index"})
_SR_GROUP_NAME = _sr_re.compile(r"[a-z_][a-z0-9_-]{0,31}\$?|[0-9]{1,10}")


def _sr_container_user(st, start, raw_json, group):
    if not _SR_GROUP_NAME.fullmatch(group):
        return False
    seg = st[max(0, start - 512):start]
    for sep in ("\n", ";", "&", "|") + (("\\n",) if raw_json else ()):
        i = seg.rfind(sep)
        if i >= 0:
            seg = seg[i + len(sep):]
    toks = seg.split()
    i, n = 0, len(toks)
    while i < n:
        name = toks[i].lstrip("\"'`(\\").rsplit("/", 1)[-1]    # `"docker` in a JSON string, `$(docker`
        i += 1
        if name not in _SR_CONTAINER_RT:
            continue
        if i < n and toks[i] in _SR_CONTAINER_GROUP:
            i += 1
        if i >= n or toks[i] not in _SR_CONTAINER_SUB:
            continue
        vopts = _SR_CONTAINER_EXEC_VALUE_OPTS if toks[i] == "exec" else _SR_CONTAINER_VALUE_OPTS
        i += 1
        while i < n:                                     # the runtime's own option list
            t = toks[i]
            if t == "--" or not t.startswith("-") or t == "-":
                break                                    # the image/container (or `--`): options end
            i += 1
            if "=" not in t and t in vopts:
                i += 1                                   # `-v /x:/y`, `--name web`: skip the value
        if i == n:
            return True                                  # every token before this -u was an option
    return False


def _sr_check_cmd(kind, raw_json=False):
    """The value span of a command-line password, or None for what is not one: a placeholder
    (`$DB_PASS`, `${X}`, `<pw>`, `%PW%`, `$(cat f)`), another flag, prose, a numeric `uid:gid` or a
    container runtime's `user:group` (`-u`), a working directory (`pwd=`), or a key that is a path segment (hash-named
    trackedFileBackups keys must survive resume). In raw JSONL a backslash that opens a JSON escape
    (`\\ndb_pass=`) is a line break, not a path separator."""
    def check(m):
        g = next((x for x in ("v1", "v2", "v3") if x in m.re.groupindex and m.group(x) is not None), None)
        if g is None:
            return None
        v = m.group(g)
        if sr_is_placeholder(v) or v[:1] in ("$", "%", "=", "-") or v.lower() in _SR_CMD_PROSE:
            return None
        if kind == "user":
            u = next((m.group(x) for x in ("u", "u2", "u3") if m.group(x) is not None), "")
            if v.isdigit() and (not u or u.isdigit()):     # a numeric uid:gid, not a password
                return None
            if _sr_container_user(m.string, m.start(), raw_json, v):   # `docker run -u node:node`
                return None
        elif kind == "key":
            st, a = m.string, m.start("k")
            j = a
            while j > 0 and a - j < 64 and (st[j - 1].isalnum() or st[j - 1] in "_-"):
                j -= 1
            if j > 0 and st[j - 1] in "/.":     # a path segment, or an attribute (`obj.pass = x`)
                return None
            if j > 0 and st[j - 1] == "\\":
                k = j
                while k > 0 and st[k - 1] == "\\":
                    k -= 1
                if not (raw_json and (j - k) % 2 == 1 and st[j] in "bfnrtu"):
                    return None
                j += 1                          # the escape's letter is not part of the name
            # a path (`/x`, `~/x`, `src/app`), or a drive letter whose `\` ends the bare run (`pwd=C:\work`)
            if m.group("k").lower() == "pwd" and (_SR_CMD_PATH.match(v + m.string[m.end(g):m.end(g) + 1])
                                                  or "/" in v or "\\" in v):
                return None
            if m.group("sep") == ":" and (j == a or _SR_TYPE_NAME.match(v)):
                return None             # `pass: 3` is prose; `db_pass: str` is a type annotation
            if j == a and v.isdigit():          # a bare `pass=3 fail=0` is a test count
                return None
        return m.span(g)
    return check


# --- Sheet ids, personal data, IPs, paths (sr_extra_rules) ---------------------------------------
# `sr_extra_rules(raw_json)` returns [(name, pattern, check, marker)]: replace check(m)'s span with `marker`.
# The raw-JSONL build only swaps each match-start guard for one that treats a JSON escape as a boundary
# (_sr_lb), so `\\n10.0.0.1` and `\\tuser@example.com` are caught and no match starts on an escape's letter.
SR_PII_RULES = frozenset({"infra.mac", "infra.ipv6", "infra.ip", "infra.keyfile", "pii.email", "pii.homedir"})
SR_EXTRA_PRECHECK = {
    "secret.gsheet": ("sheet", "spreadsheet", "gdoc", "document/d/"),
    "infra.keyfile": (".pem", "id_rsa", "id_ed25519", "id_ecdsa", ".json"),
    "pii.email": ("@",),
    # + the URL-encoded forms (`%2Fhome%2F`, `%252Fhome%252F`, `Users%5C`), the mixed ones (`%2Fhome/`,
    # `/home%2F`,), a WSL UNC path (`\\home\\`) and Claude Code's project-folder names (`-home-`,
    # `-Users-`, `C--Users-`), lower-cased.
    "pii.homedir": ("/home/", "/users/", "users\\", "2fhome%", "2fusers%", "users%5c", "users%255c",
                    "2fhome/", "2fusers/", "/home%", "/users%", "\\home\\", "-home-", "-users-",
                    # a drive's `\` then `/` or `%2F` (`C:\users/bob`, `c%3A%5Cusers%2Fbob`,)
                    "\\users/", "users%2f", "users%252f"),
}


def _sr_whole(m):
    return m.span()


def _sr_after1(m):
    return m.end(1), m.end()


# A URL-encoded `/` and `\` (`%2F`, `%5C`, either hex case), also encoded twice (`%252F`, `%255C`), and a
# URL-encoded `:` (`%3A`, `%253A`). A home path in a URL (`?path=%2Fhome%2Falice%2Fsrc`, `file:///c%3A/…`,
# a VS Code `vscode-remote://…%2Fhome%2Falice`) loses its user the same way as the plain form.
_SR_ENC_SL = r"%(?:25)?2[Ff]"
_SR_ENC_BS = r"%(?:25)?5[Cc]"
_SR_ENC_COLON = r"%(?:25)?3[Aa]"
# Either separator form, independently on each side (mixed encodings, `%2Fhome/alice`,
# `/home%2Falice`, `C%3A\Users\bob`, `C:\Users%5Cbob`).
_SR_HOME_SL = "(?:/|" + _SR_ENC_SL + ")"
_SR_HOME_BS = r"(?:\\+|(?:" + _SR_ENC_BS + "){1,2})"
# A home path separator in raw JSONL, where a `\` is written `\\`: whole pairs only, so the separator never
# takes the backslash of the `\u00e9` that starts the user (`C:\\Users\\\u00e9mile`,).
_SR_HOME_BS_RAW = r"(?:(?:\\\\)+|(?:" + _SR_ENC_BS + "){1,2})"
# Either separator after a drive letter: `C:\Users\bob`, and `C:/users/bob` or `file:///c:/users/bob`.
_SR_HOME_WSEP = "(?:" + _SR_HOME_BS + "|" + _SR_HOME_SL + ")"
_SR_HOME_WSEP_RAW = "(?:" + _SR_HOME_BS_RAW + "|" + _SR_HOME_SL + ")"
# Non-ASCII letters a user name may hold (`/home/jürgen`, `C:\Users\Zoë`, `/home/张伟`): Latin-1 and
# Latin Extended letters, IPA, combining accents (a decomposed `ü`), Greek, Cyrillic, Armenian, Hebrew,
# Arabic (with its vowel marks), Devanagari, Thai, Georgian, Vietnamese, kana, CJK and Hangul. adds Greek
# Extended (`Ἀ`), Bengali, Tamil and the other Indic scripts up to Sinhala, Lao, CJK compatibility ideographs,
# CJK Extension B and beyond (U+20000-U+3FFFF), fullwidth Latin and digits, and halfwidth kana. Explicit
# code-point ranges rather than `\w`, so the raw-JSONL form (a `\u00fc` escape, _sr_hex4; a surrogate pair
# `\ud840\udc0b` above U+FFFF) takes exactly the same characters as the decoded text: both inputs
# agree on where a user name ends. Punctuation and spaces (`→`, NBSP, `»`, `・`, U+3000) stay outside and
# end the name.
_SR_ULETTER_RANGES = ((0x00C0, 0x00D6), (0x00D8, 0x00F6), (0x00F8, 0x02AF), (0x0300, 0x036F),
                      (0x0386, 0x0386), (0x0388, 0x03FF), (0x0400, 0x0481), (0x048A, 0x052F),
                      (0x0531, 0x0556), (0x0561, 0x0587), (0x05D0, 0x05EA), (0x0620, 0x0669),
                      (0x066E, 0x06D3), (0x0900, 0x0963), (0x0966, 0x0DFF), (0x0E01, 0x0E3A),
                      (0x0E40, 0x0E4E), (0x0E81, 0x0EDF), (0x10D0, 0x10FA), (0x1E00, 0x1FBC),
                      (0x1FC2, 0x1FCC), (0x1FD0, 0x1FDB), (0x1FE0, 0x1FEC), (0x1FF2, 0x1FFC),
                      (0x3041, 0x3096), (0x30A1, 0x30FA), (0x30FC, 0x30FF), (0x3400, 0x4DBF),
                      (0x4E00, 0x9FFF), (0xAC00, 0xD7A3), (0xF900, 0xFAFF), (0xFF10, 0xFF19),
                      (0xFF21, 0xFF3A), (0xFF41, 0xFF5A), (0xFF66, 0xFF9F), (0x20000, 0x3FFFF))
# what may come BEFORE a name's first character (a run of them): the zero-width space, (non-)joiner
# and the direction marks, the embeddings and overrides, the word joiner and the isolates, variation
# selectors, the BOM, and emoji (U+2600-U+27BF, U+1F000-U+1FBFF), so `/home/\u200fAlice` and `/home/🙂bob`
# lose the whole name. After the name they still end it, as before. The review added the soft hyphen
# U+00AD, the Arabic letter mark U+061C, the Hangul fillers, the emoji-presentation symbols outside those
# blocks (`⌚`, `⏩`, `◽`, `⬛`, `⭐`, `⭕`) and the tag block U+E0000-U+E03FF (a flag's tag sequence, and the
# variation selectors supplement).
_SR_ULEAD_RANGES = ((0x00AD, 0x00AD), (0x061C, 0x061C), (0x115F, 0x1160), (0x200B, 0x200F), (0x202A, 0x202E),
                    (0x2060, 0x2069), (0x231A, 0x231B), (0x23E9, 0x23F3), (0x23F8, 0x23FA), (0x25FD, 0x25FE),
                    (0x2600, 0x27BF), (0x2B1B, 0x2B1C), (0x2B50, 0x2B50), (0x2B55, 0x2B55), (0x3164, 0x3164),
                    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0x1F000, 0x1FBFF), (0xE0000, 0xE03FF))
# a zero-width non-joiner or joiner INSIDE a name (`م‌ریم`, a Devanagari conjunct) belongs to it when a
# non-ASCII character follows (_SR_NONASCII_NEXT); before an ASCII character or at the end it ends the name,
# as before.
_SR_UJOIN = "\u200c\u200d"


def _sr_ranges_cls(ranges):
    """A character class body for the code-point ranges."""
    return "".join(("\\u%04x-\\u%04x" if b <= 0xFFFF else "\\U%08x-\\U%08x") % (a, b) for a, b in ranges)


_SR_ULETTER = _sr_ranges_cls(_SR_ULETTER_RANGES)
_SR_ULEAD = _sr_ranges_cls(_SR_ULEAD_RANGES)


def _sr_hexd(a, b):
    """A character class for the hex digits a..b (0-15), in either case; one decimal digit is itself (
    review: the shortest form, which keeps the compile time down)."""
    if a == b and a < 10:
        return "%d" % a
    lo, hi = [c for c in range(a, b + 1) if c < 10], [c for c in range(a, b + 1) if c >= 10]
    s = (("%d" % lo[0] if len(lo) == 1 else "%d-%d" % (lo[0], lo[-1])) if lo else "") + (
        ("%x%X" % (hi[0], hi[0]) if len(hi) == 1 else "%x-%x%X-%X" % (hi[0], hi[-1], hi[0], hi[-1])) if hi else "")
    return "[" + s + "]"


def _sr_hex4(lo, hi, w=4):
    """A regex for the `w`-digit hex codes lo..hi (either case): fixed width, so constant time per try."""
    if w == 0:
        return ""
    q = 16 ** (w - 1)
    (lh, ll), (hh, hl) = divmod(lo, q), divmod(hi, q)
    if lh == hh:
        return _sr_hexd(lh, lh) + _sr_hex4(ll, hl, w - 1)
    parts = []
    if ll:
        parts.append(_sr_hexd(lh, lh) + _sr_hex4(ll, q - 1, w - 1))
        lh += 1
    tail = None
    if hl != q - 1:
        tail = _sr_hexd(hh, hh) + _sr_hex4(0, hl, w - 1)
        hh -= 1
    if lh <= hh:
        parts.append(_sr_hexd(lh, hh) + ("[0-9A-Fa-f]{%d}" % (w - 1) if w > 1 else ""))
    if tail:
        parts.append(tail)
    return parts[0] if len(parts) == 1 else "(?:" + "|".join(parts) + ")"


# The same characters as a JSON `\uXXXX` escape in raw JSONL (`ensure_ascii` transcripts). A
# code point above U+FFFF is a surrogate pair (`\ud83d\ude00`); the astral ranges are whole blocks of 1024
# (every low surrogate), so a pair is its high surrogate's range then any low surrogate.
def _sr_ranges_esc(ranges):
    return (r"\\u(?:" + "|".join(_sr_hex4(a, b) for a, b in ranges if b <= 0xFFFF)
            + "|(?:" + "|".join(_sr_hex4(0xD800 + ((a - 0x10000) >> 10), 0xD800 + ((b - 0x10000) >> 10))
                              for a, b in ranges if b > 0xFFFF)
            + r")\\u" + _sr_hex4(0xDC00, 0xDFFF) + ")")


_SR_ULETTER_ESC = _sr_ranges_esc(_SR_ULETTER_RANGES)
_SR_ULEAD_ESC = _sr_ranges_esc(_SR_ULEAD_RANGES)
_SR_UJOIN_ESC = r"\\u200[CcDd]"
# What a joiner must be followed by: any non-ASCII character (a cheap superset of a letter; the letter test
# would double the compiled size), in raw JSONL also as an escape of one.
_SR_NONASCII_NEXT = r"(?=[^\x00-\x7f])"
_SR_NONASCII_NEXT_RAW = r"(?=[^\x00-\x7f]|\\u(?!00[0-7])[0-9A-Fa-f]{4})"


def _sr_uchar(cls, raw_json):
    """One character of `cls` or a non-ASCII letter, or a ZWNJ/ZWJ right before a non-ASCII character; in raw
    JSONL also as their `\\uXXXX` escapes. The alternatives start with different characters (the class holds
    no `\\`) or are fixed-width escapes that differ in their hex digits: linear."""
    one = "[" + _SR_ULETTER + cls + "]"            # `cls` last: its trailing `-` stays a literal
    if not raw_json:
        return "(?:" + one + "|[" + _SR_UJOIN + "]" + _SR_NONASCII_NEXT + ")"
    return ("(?:" + one + "|" + _SR_ULETTER_ESC + "|(?:[" + _SR_UJOIN + "]|" + _SR_UJOIN_ESC + ")"
            + _SR_NONASCII_NEXT_RAW + ")")


def _sr_ulead(raw_json):
    """A run of the characters that may come before a user name (_SR_ULEAD_RANGES); none is needed."""
    return "(?:[" + _SR_ULEAD + "]" + ("|" + _SR_ULEAD_ESC if raw_json else "") + ")*"


# A drive's home prefix in any case and with either separator (`C:\Users\`, `c:/users/`, `C%3A%5CUsers%5C`).
def _sr_drive_users(raw_json, glued=False):
    """`Users` between a drive's separators (the part after `C:`). GLUED after a user
    (`glued`: _sr_home_user, _sr_home_dash_user), a WSL UNC home path right after it
    (`/home/xC:\\Users\\\\\\wsl$\\Ubuntu\\home\\alice`) belongs to the prefix, so the UNC path's user is the
    next user; the separator alone took the UNC's backslashes and `wsl` as the user, and `alice` leaked.
    A drive path that starts a match is unchanged."""
    wsep = _SR_HOME_WSEP_RAW if raw_json else _SR_HOME_WSEP
    if not glued:
        return wsep + "(?i:Users)" + wsep
    return wsep + "(?i:Users)(?:" + _SR_HOME_UNC + (r"(?:\\\\)+" if raw_json else r"\\+") + "|" + wsep + ")"


def _sr_drive_home(raw_json, glued=False):
    return "[A-Za-z](?::|" + _SR_ENC_COLON + ")" + _sr_drive_users(raw_json, glued)


# A project-folder name's home prefix (`-home-`, `-Users-`, `C--Users-`, `-mnt-c-Users-`).
_SR_DASH_HOME = r"-(?:home|Users)-|[A-Za-z]--(?i:Users)-|-mnt-[A-Za-z]-(?i:Users)-"


# The user segment of a path form: up to the next separator, including an `@` (`john@corp`, an AD/SSSD
# account) and the escapes of `@ . - _` (`john%40corp`, `%2540` encoded twice); any other escape ends it
# (the user was cut at `%`, leaving `%40corp`). Non-ASCII letters belong to it, and so do a
# leading run of invisible characters or emoji and a ZWNJ/ZWJ between letters. it ends right
# before a drive's home prefix or a `file://`/`vscode-remote://` home URI that a user follows (in
# `/home/xc:\users\bob` or `%2FUsers%2Füc:\users\Zoë` the first user took the drive letter, so the second one
# leaked); with `glued`, that path and its user join the match (any number of them), so the span runs from
# the first user to the last and nothing the first user held is left visible. A prefix that no user follows
# is taken as user characters, as before (`/home/xc:\users\→` keeps the `c` redacted). so is a
# project-folder prefix (`-home-`, `C--Users-`, `-mnt-c-Users-`): the user took it as user characters
# anyway, but a user after it that starts with an invisible character or emoji
# (`/home/x-home-\u200fmallory`) was cut there and leaked. Without `glued` (the `/users/` form, which must
# be followed by a home folder, and a path glued after a folder name's user) the user is a plain run, but
# for such a folder prefix that an invisible character or emoji follows (`C:\Users\x-home-\u200fmallory`).
# The lookaheads fail on their first characters except where such a prefix starts, and each user character
# is taken once: linear.
def _sr_home_user(raw_json, glued=True):
    unit = "(?:" + _sr_uchar("A-Za-z0-9._@-", raw_json) + "|%(?:25)?(?:40|2[EeDd]|5[Ff]))"
    nxt = ("(?:" + _sr_drive_home(raw_json, glued=True) + "|" + _SR_HOME_URI + _SR_HOME_SL + "(?:home|Users)"
           + _SR_HOME_SL + "|" + _SR_DASH_HOME + r")(?!\[REDACTED)")
    if not glued:
        dash = "(?:" + _SR_DASH_HOME + r")(?!\[REDACTED)"
        lead1 = "[" + _SR_ULEAD + "]" + ("|" + _SR_ULEAD_ESC if raw_json else "")
        return (_sr_ulead(raw_json) + "(?:(?!" + dash + "(?:" + lead1 + "))" + unit + "|" + dash + _sr_ulead(raw_json)
                + ")+")
    return (_sr_ulead(raw_json) + "(?:(?!" + nxt + _sr_ulead(raw_json) + unit + ")" + unit + "|" + nxt
            + _sr_ulead(raw_json) + ")+")


# a lower-case (or upper-case) POSIX `/users/<name>` is only a home directory when the path goes on
# into one: a top-level home folder (`/users/bob/Documents`, `/users/bob/AppData/…`, macOS `Library`), a
# dot-entry (`/users/bob/.ssh`, `/users/bob/.bashrc`), or a file (`/users/bob/notes.txt`,
# `/users/bob/src/app/main.py`: a path of up to 8 more ASCII segments that ends in a name with an extension,
# or in a well-known file without one, `/users/bob/proj/Makefile`, review).
# An API route (`GET /users/bob`, `/users/42/repos`, `/users/bob/followers`) has none of these. # in a filesystem context, right after a blank (a space, tab or line break), a quote, `=` or `(`
# (_sr_fs_ctx), any further segment is enough (`cd /users/bob/myrepo`, `(/users/bob/go/bin/tool)`); at the
# very start of a string it is not, since a bare route (`/users/bob/repos`) looks the same. The Git Bash
# form with lower-case `users` (`/c/users/bob`) follows the same rules (a bare `/r/users/top` or
# `/v/users/42/settings` is kept, `cd /c/users/bob/src` is not); with `Users` it is a home directory as is.
# Besides, the path must not be part of a web URL (_sr_in_web_path) or follow an HTTP verb
# (`GET /users/bob/avatar.png`), and, like every path form, not follow an ASCII word character, `.` or `-`
# (`/api/users/bob/Documents`).
# The capitalised macOS `/Users/<name>` is a home directory without any of this.
_SR_LUSERS_DIRS = ("(?i:desktop|documents|downloads|pictures|music|videos|movies|library|appdata|onedrive"
                   "|applications|dropbox|source)(?![A-Za-z0-9_-])")
_SR_LUSERS_SEG = "[A-Za-z0-9._-]{1,64}"
_SR_LUSERS_FILES = ("(?:[Mm]akefile|GNUmakefile|Dockerfile|Containerfile|Jenkinsfile|Vagrantfile|Gemfile|Rakefile"
                    "|Procfile|Brewfile|Justfile|Pipfile|Podfile|Caddyfile|Snakefile|Earthfile|Tiltfile|README"
                    "|LICENSE|LICENCE|CHANGELOG|NOTICE|AUTHORS|CODEOWNERS|COPYING)")
_SR_LUSERS_NEXT = (_SR_HOME_SL + "(?:" + _SR_LUSERS_DIRS + r"|\.[A-Za-z0-9_]|(?:" + _SR_LUSERS_SEG + _SR_HOME_SL
                   + "){0,8}(?:[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}\\.[A-Za-z][A-Za-z0-9]{0,7}|" + _SR_LUSERS_FILES
                   + ")(?![A-Za-z0-9_.%/-]))")


def _sr_fs_ctx(raw_json):
    """a filesystem context right before a path: a blank, a quote, `=` or `(`. In raw JSONL a
    blank or a quote inside a string is an escape (`\\n`, `\\t`, `\\"`) after an odd run of backslashes (up to
    15: each escaped backslash before it is a literal one); the JSON string's own quote is the start of
    the text, which is no such context."""
    if not raw_json:
        return "(?<=[ \t\n\r\"'`=(])"
    return ("(?:(?<=[ '`=(])|" + "|".join(r"(?<=(?<!\\)" + r"\\\\" * k + r"\\[nrt\"])" for k in range(8))
            + ")")


def _sr_lusers_seg(raw_json):
    """The first character of a further path segment: an ASCII name character or a non-ASCII one."""
    return "(?:[A-Za-z0-9._~@+-]|[^\\x00-\\x7f]" + (r"|\\u(?!00[0-7])[0-9A-Fa-f]{4})" if raw_json else ")")


# An HTTP verb and blanks right before the path (also after a JSON escape, as in `\tGET`, in raw JSONL).
_SR_HTTP_VERB = _sr_re.compile(r"(?:(?<![A-Za-z])|(?<=\\[bfnrt])|(?<=\\u[0-9A-Fa-f]{4}))"
                               r"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)(?:[ \t]|\\t)+\Z")


# Right after a home path's user segment (1-64 characters, an escape counted by its characters): fixed-width
# lookbehinds, tried only where a home prefix follows, so the cost per position stays constant. One family
# for the plain, encoded and mixed forms (`/home/a%2Fhome%2Fb`): one pass stays the fixed point. The first
# separator is checked by its last character only (`/`, or the `F` of `%2F`), which keeps the count at 384.
# A non-ASCII letter counts (`/home/jürgen/home/bob`,); in raw JSONL so does a `\`, the start of its
# `\u00fc` escape (an escape counted by its characters, like `%40`). The class is every non-ASCII character
# plus the ASCII user characters, written as a negated ASCII class (cheap to compile, unlike 384 copies of
# _SR_ULETTER or of a `\U0010ffff` range; it was `\w`, and a combining mark, a ZWNJ or an emoji in the
# user is no `\w`), a superset: _sr_chain_ok checks a window with a non-ASCII character or a `\` exactly.
def _sr_home_chain(raw_json):
    cls = r"[^\x00-\x24\x26-\x2c\x2f\x3a-\x3f\x5b" + ("" if raw_json else r"\x5c") + r"\x5d\x5e\x60\x7b-\x7f]"
    return ("(?=" + _SR_HOME_SL + "(?:home|Users)" + _SR_HOME_SL + ")(?:" + "|".join(
        "(?<=[/Ff]" + w + s2 + cls + "{" + str(k) + "})"
        for w in ("home", "Users") for s2 in ("/", "%2[Ff]", "%252[Ff]") for k in range(1, 65)) + ")")


# The dash twin of _sr_home_chain for Claude Code project-folder names (`-home-a-home-b`): every non-ASCII
# character, an ASCII word character, `.` and (raw JSONL) `\`.
def _sr_home_chain_dash(raw_json):
    cls = r"[^\x00-\x2d\x2f\x3a-\x40\x5b" + ("" if raw_json else r"\x5c") + r"\x5d\x5e\x60\x7b-\x7f]"
    return ("(?=-(?:home|Users)-)(?:" + "|".join(
        "(?<=-home-%s{%d})|(?<=-Users-%s{%d})" % (cls, k, cls, k) for k in range(1, 65)) + ")")


# A URI that names a host (or a WSL distro) before the home path: `file://host/home/alice`,
# `vscode-remote://ssh-remote%2Bbox/home/alice` (the form VS Code writes to workspace.json),
# `vscode-remote://wsl+Ubuntu/home/alice`, `file://wsl.localhost/Ubuntu/home/alice`, `file://wsl%24/…`
#. Only these schemes take a host: a web URL's path (`https://host/home/x`) is not a home directory.
_SR_HOME_URI_HOST = (r"(?:(?i:wsl(?:\.localhost|\$|%24))/[A-Za-z0-9._-]{1,64}|[A-Za-z0-9.%+@_-]{1,253})"
                     r"(?=" + _SR_HOME_SL + "(?:home|Users)" + _SR_HOME_SL + ")")
_SR_HOME_URI = r"(?i:file|vscode-remote)://" + _SR_HOME_URI_HOST
# A WSL distro's home as a Windows UNC path: `\\wsl.localhost\Ubuntu\home\alice`, `\\wsl$\Ubuntu\home\alice`.
# In raw JSONL the last separator takes whole `\\` pairs only, as _SR_HOME_BS_RAW (`home\\\u00e9mile`,).
_SR_HOME_UNC = r"\\+(?i:wsl(?:\.localhost|\$))\\+[A-Za-z0-9._-]{1,64}\\+home"
# A whole folder-name segment that is (nearly always) a directory right under the home directory. The dash
# form cannot tell `john.doe` (written `john-doe`) from `alice` + a project `proj`; when a second segment is
# followed by one of these (`-home-john-doe-workspace-x`), it is part of the user.
_SR_HOME_DASH_DIRS = (r"(?:[Ww]orkspaces?|[Pp]rojects|[Rr]epos|[Dd]ocuments|Desktop|Downloads|Developer"
                      r"|[Cc]ode|git|github|gitlab)")


def _sr_home_dash_user(raw_json):
    """The user in a project-folder name: one segment, or two when a top-level home folder follows. A
    segment takes non-ASCII letters too (`-home-jürgen-proj`,), and the user a leading run of
    invisible characters or emoji.

    and the a user that ends in the letter of a drive's home path takes that path and
    its user too, as a folder name (`-home-bobἈC--Users-alice-proj`) or as a path (`-Users-ລາüC:\\Users\\x`,
    `-home-xC%3A%5CUsers%5Cbob`), so that user is redacted (it leaked once `Ἀ` or `ລາ` became a letter) and
    the drive letter stays redacted; so does a `file://` or `vscode-remote://` home URI whose scheme the user
    took (`-home-⭐vscode-remote://box/home/alice`). It chains any number of times
    (`-Users-bobC:\\Users\\🙂C:\\Users\\alice`, `-home-aC--Users-bC:\\Users\\c`): folder names first (each
    one segment, the last one also two before a home folder), then paths, whose user is a plain path user
    (_sr_home_user without `glued`, which takes the rest of a folder name). The letter is no `\\uXXXX`
    escape's last digit. Each character is taken once: linear."""
    c = _sr_uchar("A-Za-z0-9._", raw_json)
    stop = _SR_HOME_DASH_DIRS + "(?!" + c + ")"
    letter = r"(?<=[A-Za-z])(?<!\\u[0-9A-Fa-f]{3}[A-Za-z])"
    user = _sr_home_user(raw_json, glued=False)
    path = (r"(?:" + letter + "(?::|" + _SR_ENC_COLON + ")" + _sr_drive_users(raw_json, glued=True)
            + r"|(?:(?<=(?i:file))|(?<=(?i:vscode-remote))|(?<=(?i:vscode))(?i:-remote))://" + _SR_HOME_URI_HOST
            + _SR_HOME_SL + "(?:home|Users)" + _SR_HOME_SL + r")(?!\[REDACTED)" + user)
    return (_sr_ulead(raw_json) + c + "+(?:" + letter + r"--(?i:Users)-(?!\[REDACTED)" + _sr_ulead(raw_json) + c
            + "+)*(?:-(?!" + stop + ")" + c + "+(?=-" + stop + ")|(?:" + path + ")*)")


# The scan for a web URL's path ends at these (a query, a fragment, the end of the URL or of a JSON string,
# or a `)`, `,`, `;` or `|` that closes or separates it in prose), and at a non-ASCII character (a URL
# path has none, only `%XX` escapes; in raw JSONL its `\u00e9` escape ended the scan at the `\`, so the raw
# form redacted where the decoded form kept it).
_SR_WEB_PATH_END = _sr_re.compile(r"[\s\"'<>?#\\),;|]|[^\x00-\x7f]")


def _sr_in_web_path(st, a):
    """`st[a]` lies in the path of an http(s) URL (`https://host/a%20/home/docs`): a `scheme://` within
    512 characters before it, with no query, fragment, space, quote, backslash, `)`, `,`, `;` or `|` in
    between. Bounded."""
    seg = st[max(0, a - 512):a]
    i = seg.rfind("://")
    if i < 0 or not seg[max(0, i - 5):i].lower().endswith(("http", "https")):
        return False
    return _SR_WEB_PATH_END.search(seg, i + 3) is None


# A glued home path's predecessor, checked exactly (_sr_chain_ok): a home prefix, then a user segment whose
# `\uXXXX` escapes are all letters (_SR_ULETTER_ESC), up to the start of the next match.
_SR_CHAIN_PFX = _sr_re.compile("[/Ff](?:home|Users)(?:/|%2[Ff]|%252[Ff])")
_SR_CHAIN_WIN = _sr_re.compile(_sr_ulead(True) + "(?:" + _sr_uchar("A-Za-z0-9._@%-", True) + ")+")
_SR_CHAIN_PFX_DASH = _sr_re.compile("-(?:home|Users)-")
_SR_CHAIN_WIN_DASH = _sr_re.compile(_sr_ulead(True) + "(?:" + _sr_uchar("A-Za-z0-9._", True) + ")+")
_SR_ESC_BEFORE = _sr_re.compile(r"\\(?:[bfnrt/\"\\]|u[0-9A-Fa-f]{4})")
_SR_CHAIN_EXACT = _sr_re.compile(r"[^\x00-\x5b\x5d-\x7f]")         # a non-ASCII character or a `\`
_SR_LB_PATH = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_SR_LB_DASH = _SR_LB_PATH | frozenset("([:,")


def _sr_chain_ok(st, a, blocked, pfx, win):
    """A match that starts at `a` right after a character of `blocked` got there through the glued-path
    lookbehinds. Those take any `\\w` character and, in raw JSONL, a `\\` (the start of a `\\u00fc` escape,
    which they cannot tell from `\\n` or `\\u00a0`), so a window with a non-ASCII character or a `\\` is
    checked exactly here: only the letters of _SR_ULETTER, plain or escaped, continue a user segment. An
    ASCII window without a `\\` was exact already. Bounded (75 chars)."""
    if a == 0 or st[a - 1] not in blocked or not _SR_CHAIN_EXACT.search(st, max(0, a - 64), a):
        return True
    if (a >= 3 and st[a - 3] == "%") or (a >= 5 and st[a - 5:a - 2] == "%25"):
        return True                                  # a `%XX` boundary (only the path forms take it)
    if _SR_ESC_BEFORE.fullmatch(st, max(0, a - 2), a) or _SR_ESC_BEFORE.fullmatch(st, max(0, a - 6), a):
        return True                                  # right after a JSON escape: a boundary in raw JSONL
    return any(1 <= a - p.end() <= 64 and win.fullmatch(st, p.end(), a)
               for p in pfx.finditer(st, max(0, a - 75), a))


def _sr_after_home(m):
    """pii.homedir: the user after whichever prefix matched (group 1: a path, group 2: a folder name).
    A plain `/home/…` whose boundary is a `%XX` escape inside a web URL's path is a web path, not a home
    directory (`https://example.com/a%20/home/docs`,); in a query (`?cmd=ls%20/home/alice`) it is.
    A glued path whose predecessor holds a character that is no user letter is not glued (_sr_chain_ok)."""
    st = m.string
    if m.group("lu") is not None:                    # a POSIX `/users/` in any case but `Users`
        a = m.start("lu")
        if _sr_in_web_path(st, a) or _SR_HTTP_VERB.search(st, max(0, a - 24), a):
            return _sr_nested_home(m, m.end("lu"))
        return m.end("lu"), m.end()
    if m.group(1) is None:
        a = m.start(2)
        if st[a] == "-" and not _sr_chain_ok(st, a, _SR_LB_DASH, _SR_CHAIN_PFX_DASH, _SR_CHAIN_WIN_DASH):
            return _sr_nested_home(m, m.end(2))
        return m.end(2), m.end()
    a = m.start(1)
    if st[a] in "/%" and not _sr_chain_ok(st, a, _SR_LB_PATH, _SR_CHAIN_PFX, _SR_CHAIN_WIN):
        return _sr_nested_home(m, m.end(1))
    if (st[a] == "/" and ((a >= 3 and st[a - 3] == "%") or (a >= 5 and st[a - 5:a - 2] == "%25"))
            and _sr_in_web_path(st, a)):
        return _sr_nested_home(m, m.end(1))          # a home path inside its user still counts
    return m.end(1), m.end()


def _sr_nested_home(m, e):
    """A rejected glued match (_sr_chain_ok) has already taken its user segment, `m.string[e:m.end()]`, and
    the scan goes on after it. A folder name may start inside it, right after a non-ASCII letter
    (`/home/a→b/home/ü-home-carol`): it is found here, so the rejection loses nothing. More than one is
    a contrived input; their union is the span (the text between them is redacted too). Linear: the
    segments of rejected matches never overlap."""
    spans = [sp for n in m.re.finditer(m.string, e, m.end()) for sp in (_sr_after_home(n),) if sp]
    return (spans[0][0], spans[-1][1]) if spans else None


def _sr_dash_lb(raw_json):
    """Where a project-folder name may start: not right after an ASCII word character, `.` or `-` (inside a
    hyphenated word, `--home-dir`), and not after `(`, `[`, `:` or `,`, where `-home-x` is a flag or a
    word. Every other character is a boundary (`|`, `**`, `>`, `;`, `{`, `~`, `!`, non-ASCII),
    a non-ASCII letter too (`中-home-alice-x`).
    Residual leak, stated: `(-home-alice-proj)` keeps the user."""
    return _sr_lb(r"A-Za-z0-9_.\-(\[:,", raw_json)


@_sr_functools.lru_cache(maxsize=8)
def sr_extra_rules(raw_json=False, keyfile_names="", keyfile_json_words=""):
    """[(name, pattern, check, marker)] in the reference order. No possessive quantifier: a captured
    lookahead plus a backreference (`(?=(?P<x>a+))(?P=x)`) is the same atomic run on any python3."""
    wb = _sr_wb(raw_json)
    bq = r"(?:\\(?=[\"']))?" if raw_json else ""
    sp = r"[ \t]" if raw_json else r"\s"
    wsep = _SR_HOME_WSEP_RAW if raw_json else _SR_HOME_WSEP
    return [
        # Google Sheet/Drive ids: a leaked spreadsheet/doc id grants access. The prefix is kept.
        ("secret.gsheet", _sr_re.compile(
            r"(?i)" + wb + r"((?:g?sheets?|spreadsheets?|gdoc)(?:[ _-]?id)?" + sp + r"*[:=]" + sp + r"*"
            + bq + r"[`'\"]?|spreadsheets?/(?:d/)?|document/d/)([A-Za-z0-9_-]{25,})"),
         lambda m: m.span(2), "[REDACTED-SHEETID]"),
        # MAC addresses, before IPv6 so they keep the MAC label.
        ("infra.mac", _sr_re.compile(wb + r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"), _sr_whole,
         "[REDACTED-MAC]"),
        # IPv6: 4-8 groups or a `::` form with a hex letter; never inside a longer word/hex/colon run
        # (a grep line's `file.py:26:`), and an IPv4-mapped tail is left to the IPv4 rule.
        ("infra.ipv6", _sr_re.compile(
            _sr_lb("0-9a-z:", raw_json) + r"(?=[0-9a-f:]*[a-f])"
            r"(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){3,7}"
            r"|(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?)"
            r"(?![0-9a-z:]|\.\d)", _sr_re.I), _sr_whole, "[REDACTED-IP6]"),
        # ALL IPv4 (four octets); a three-part version string does not match.
        ("infra.ip", _sr_re.compile(wb + r"(?:\d{1,3}\.){3}\d{1,3}\b"), _sr_whole, "[REDACTED-IP]"),
        # Private-key / credential file references (the path is recon even without the key). Bounded
        # runs that start only where a path-ish run starts.
        ("infra.keyfile", _sr_re.compile(
            r"(?i)(?:" + _sr_lb("\\w./-", raw_json) + r"[\w./-]{0,1024}/|" + wb + ")"
            r"(?:" + (keyfile_names + "|" if keyfile_names else "")
            + r"(?=(?P<kf1>[\w-]{1,128}))(?P=kf1)\.pem|id_(?:rsa|ed25519|ecdsa)(?:\.pub)?|"
            r"(?=(?P<kf2>[\w-]{1,128}))(?=(?P=kf2)\.json)(?=[\w-]{0,64}?(?:"
            + (keyfile_json_words + "|" if keyfile_json_words else "") + r"service[_-]?account|"
            r"credential|gserviceaccount|-sa))(?P=kf2)\.json)\b"), _sr_whole, "[REDACTED-KEYFILE]"),
        # Emails: the local part starts only where its run starts and is taken whole.
        ("pii.email", _sr_re.compile(
            _sr_lb("A-Za-z0-9._%+\\-", raw_json) + r"(?=(?P<el>[A-Za-z0-9._%+\-]+))(?P=el)"
            r"@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), _sr_whole, "[REDACTED-EMAIL]"),
        # The account name in a home-directory path (/home/alice, /Users/alice, C:\Users\alice), as a
        # value or a map KEY; the prefix and the rest of the path are kept. A home path GLUED to the end of
        # another one (`/home/a/home/b`) is matched in the same pass (_sr_home_chain), so one pass is a
        # fixed point however many are glued. The same paths URL-encoded once or twice (`%2Fhome%2Falice`,
        # `C%3A%5CUsers%5Calice`, `%252FUsers%252Falice`), with mixed encodings (`%2Fhome/alice`,
        # `C%3A\Users\bob`), in a `file://` or `vscode-remote://` URI with a host or a WSL distro
        # (`file://host/home/alice`, `vscode-remote://ssh-remote%2Bbox/home/alice`,
        # `file://wsl.localhost/Ubuntu/home/alice`) and as a WSL UNC path (`\\wsl$\Ubuntu\home\alice`) lose
        # the user too, with the same marker. The user runs to the next separator, `@` and `%40` included.
        # A `%XX` escape right before the path is a boundary (`file:///c%3A/Users/alice`,
        # `=%22%2Fhome%2Falice`, `%252F%252FUsers`), except before a plain `/home/` in a web URL's path
        # (_sr_after_home); a word character is not (`src%2Fhome%2Fx` is the relative `src/home/x`, kept
        # like its plain form). Only those URI schemes take a host: a web URL's path
        # (`https://host/home/x`) is not a home directory. A Windows `Users` folder in any case (`C:\users\bob`,),
        # after a drive with either separator (`C:/users/bob`, `file:///c:/users/bob`, `c%3A%2Fusers%2Fbob`).
        # A user name may hold non-ASCII letters (`/home/jürgen`, `C:\Users\张伟`; in raw JSONL also as
        # `\u00fc` escapes, _sr_uchar), and only an ASCII word character, `.` or `-` before a path blocks it.
        # Claude Code's project-folder name (`~/.claude/projects/-home-alice-proj`, `-Users-bob-x`,
        # `C--Users-bob-x`, `c--users-bob-x`: every non-alphanumeric character became `-`) loses the user too,
        # but only as a token of its own (not after an ASCII word character, `.` or `-`; nor after `(`,
        # `[`, `:` or `,`, where `-home-x` is a flag or a word, so `(-home-alice-x)` is a stated residual
        # leak), never inside a hyphenated word (`stay-at-home-mom`, `--home-dir`). There the user ends at the
        # next `-`, or takes a second segment when a top-level home folder follows (_sr_home_dash_user); glued
        # folder names (`-home-a-home-b`) chain in one pass (_sr_home_chain_dash).
        # a Windows home through a WSL mount (`/mnt/c/Users/bob`, `/mnt/D/users/bob`, also as the
        # folder name `-mnt-c-Users-bob-proj`) or Git Bash / MSYS (`/c/Users/bob`, `/c/users/bob`), any drive
        # letter and `Users` in any case; a POSIX `/users/bob` in another case than `Users` only when a home
        # folder, a dot-entry or a file follows and it is no API route (_SR_LUSERS_NEXT, group 3).
        ("pii.homedir", _sr_re.compile(
            "(?:(?:" + _sr_lb("A-Za-z0-9_.-", raw_json) + "|(?<=%[0-9A-Fa-f]{2})|(?<=%25[0-9A-Fa-f]{2})|"
            + _sr_home_chain(raw_json) + ")"
            r"((?:" + _SR_HOME_URI + r")?" + _SR_HOME_SL + r"(?:home|Users)" + _SR_HOME_SL
            + r"|" + _sr_drive_home(raw_json)
            + r"|" + _SR_HOME_UNC + (r"(?:\\\\)+" if raw_json else r"\\+")
            + r"|" + _SR_HOME_SL + r"mnt" + _SR_HOME_SL + r"[A-Za-z]" + _SR_HOME_SL + r"(?i:Users)" + _SR_HOME_SL
            + r"|" + _SR_HOME_SL + r"[A-Za-z]" + _SR_HOME_SL + r"Users" + _SR_HOME_SL + r")(?!\[REDACTED)"
            + _sr_home_user(raw_json)
            + "|(?:" + _sr_dash_lb(raw_json) + "|" + _sr_home_chain_dash(raw_json) + ")"
            r"(" + _SR_DASH_HOME + r")(?!\[REDACTED)"
            + _sr_home_dash_user(raw_json)
            + "|(?:" + _sr_lb("A-Za-z0-9_.-", raw_json) + "|(?<=%[0-9A-Fa-f]{2})|(?<=%25[0-9A-Fa-f]{2}))"
            "(?:" + _sr_fs_ctx(raw_json) + "(?P<lfs>)|)"
            "(?P<lu>(?:" + _SR_HOME_SL + "[A-Za-z](?=" + _SR_HOME_SL + "))?" + _SR_HOME_SL + "(?!Users)(?i:users)"
            + _SR_HOME_SL + r")(?!\[REDACTED)" + _sr_home_user(raw_json, glued=False)
            + "(?=" + _SR_LUSERS_NEXT + "|(?(lfs)" + _SR_HOME_SL + _sr_lusers_seg(raw_json) + "|(?!))))"),
         _sr_after_home, "[REDACTED-USER]"),
    ]


# Binary data: the personal-data, host, IP and path rules never fire INSIDE a `data:` URI's payload or a long base64 run: 200+ characters of the
# standard alphabet with a `+`, an upper- and a lower-case letter and a digit, and far fewer `/` than a
# path has (a path has one every few characters, base64 one in 64). A path, even 300 characters of glued
# `/home/<user>` segments, is not such a run, and a run's leading path segments (`/home/alice/` before a
# base64-like file name) are cut off it. A match must lie wholly inside a span to be kept; one that
# only touches its edge still redacts. The secret rules are not limited (a long one-line key is a secret).
_SR_DATA_URI = _sr_re.compile(
    r"data:[A-Za-z0-9.+/-]{1,64}(?:;[A-Za-z0-9=._-]{1,64}){0,4};base64,[A-Za-z0-9+/=]*")
_SR_B64_RUN = _sr_re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{200,}")
_SR_PATH_PREFIX = _sr_re.compile(r"(?:/[A-Za-z0-9+=]{1,64}){1,32}/")
_SR_B64_UPPER, _SR_B64_LOWER, _SR_B64_DIGIT = (_sr_re.compile(c) for c in ("[A-Z]", "[a-z]", "[0-9]"))
# base64 WRAPPED at 64 or 76 columns (`base64 file.png`, MIME, PEM-style output): 3+ full lines of
# exactly that width, joined by a line break: a real one (text), the JSON escape `\n` (raw JSONL) or a
# literal backslash-n (`\\n`, raw `\\\\n`). Each line is under 200 characters, so _SR_B64_RUN never
# sees it, and a line that starts `1//…` or `AIza…` read as a key. Only FULL-width lines are guarded:
# a short last line joins the block only in base64's padded tail form (`…=`, `…==`). Any other short
# line after a block (`base64 f; echo $KEY`) is scanned normally, so a key alone on it still redacts.
# An unpadded tail (data length divisible by 3) is scanned too; it reads as a key only by chance
# (measured).
_SR_WRAP_SEP = r"(?:\r?\n|(?:\\{1,2}r)?\\{1,2}n)"
_SR_B64_WRAPPED = _sr_re.compile(
    r"(?:(?<![A-Za-z0-9+/=])|(?<=\\n)|(?<=\\r))(?:"
    + "|".join(r"(?:[A-Za-z0-9+/]{%d}%s){2,}(?:[A-Za-z0-9+/]{%d}(?:%s[A-Za-z0-9+/]{0,%d}={1,2})?"
               r"|[A-Za-z0-9+/]{%d}=|[A-Za-z0-9+/]{%d}==)(?![A-Za-z0-9+/=])"
               % (w, _SR_WRAP_SEP, w, _SR_WRAP_SEP, w - 1, w - 1, w - 2) for w in (76, 64)) + ")")


# --- a private key split over JSON strings ---------------------------------------------
# A key whose lines sit in SEPARATE strings: an array of line strings (`["-----BEGIN … PRIVATE KEY-----",
# "MIIE…", …, "-----END …"]`), or BEGIN in one JSONL record and the rest in the next. Each string alone
# holds only part of the key, so the per-string block rules leave the rest. A string that ENDS inside a
# key (a private BEGIN marker followed only by key lines: sr_pem_opens) opens a carry; the following
# strings in document order (sr_pem_walk: array elements, later fields, the next JSONL record) give up
# their leading run of key lines (sr_pem_continue) up to the END marker. A continuation must start with
# a full base64 key line (40-76 characters) or a PEM header, so prose, ids and single-line base64 (an
# image, a data URI) never match; a carry ends at END, at the first non-key line after key lines, after
# SR_PEMC_MAX_LINES / SR_PEMC_MAX_BYTES, or after a whole record that held none. Only a PRIVATE key opens
# one: public keys and certificates are untouched. Strings are replaced, never merged or dropped.
# Right after BEGIN or a header line (`Proc-Type:`/`DEK-Info:` of an encrypted PKCS#1 key, `Version:` of a
# PGP block) one blank line is part of the key (`hdr`); headers make the carry a key, not a mention.
# A carry opened by a BEGIN marker with no key line after it in its own string (a Grep pattern, prose
# ending in the marker, an array element) is EMPTY: it takes the following key-shaped string (or run of
# array elements) only when that run reaches the matching END, starts with `Proc-Type:`/`DEK-Info:`, or
# its first body line starts the way this kind of key's body does (_sr_pemc_body_start: DER `M[A-I]`,
# OpenSSH `b3BlbnNzaC1rZXktdjE`, PGP secret-key packet `l[A-Q]`/`x[Q-d]`); any other key-shaped string
# (wrapped base64 of an image: `iVBORw0KGgo`, `/9j/`, `R0lGOD`, `UklGR`,) drops it untouched. A
# `Version:`/`Comment:` line only counts when a key body follows it.
# A string the carry does not continue is still checked for the tail of a key (sr_pem_orphan_end).
_SR_PEMC_BEGIN = _sr_re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----", _sr_re.I)
_SR_PEMC_END = _sr_re.compile(r"-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----", _sr_re.I)
_SR_PEMC_LONG = _sr_re.compile(r"[A-Za-z0-9+/]{40,76}={0,2}")
_SR_PEMC_SHORT = _sr_re.compile(r"[A-Za-z0-9+/]{1,76}={0,2}|=[A-Za-z0-9+/]{4}")
_SR_PEMC_HDR = _sr_re.compile(r"[A-Za-z][A-Za-z0-9-]{1,31}: [^\n]{0,200}")
_SR_PEMC_PEMHDR = _sr_re.compile(r"(?:Proc-Type|DEK-Info): [^\n]{0,200}", _sr_re.I)
# How the base64 body of a private key starts, by the marker's label: DER is a SEQUENCE (0x30, then any
# length: `MA`…`MH` short form, `MIG`/`MII`/`MIJ`… long form: PKCS#1, PKCS#8, SEC1 EC, DSA, encrypted
# PKCS#8); OpenSSH is the magic `openssh-key-v1`; PGP is a secret-key packet (tag 5, old format 0x94/0x95
# -> `l[A-Q]`, new format 0xC5 -> `x[Q-d]`). No image or archive magic starts like these.
_SR_PEMC_BODY = (("PGP", _sr_re.compile(r"l[A-Q]|x[Q-d]")),
                 ("OPENSSH", _sr_re.compile(r"b3BlbnNzaC1rZXktdjE")))
_SR_PEMC_BODY_DER = _sr_re.compile(r"M[A-I]")
SR_PEMC_MAX_LINES = 200
SR_PEMC_MAX_BYTES = 65536
SR_PEMC_MARK = "[REDACTED-PRIVATE-KEY]"


class SrPemCarry:
    """The open key carried from string to string (and from record to record). `started`: a body line
    was taken (short lines and blanks are key lines from then on); `hdr`: right after BEGIN or a header,
    where one blank separator line may come; `empty`: opened by a BEGIN marker with nothing after it;
    `kind`: the marker's label (`RSA PRIVATE KEY`), which an empty carry's END must match."""
    __slots__ = ("open", "started", "hdr", "empty", "kind", "lines", "nbytes", "seen", "hits")

    def __init__(self):
        self.open = self.started = self.hdr = self.empty = self.seen = False
        self.kind = ""
        self.lines = self.nbytes = self.hits = 0

    def begin(self, kind="", started=False, hdr=True, empty=False):
        self.open, self.started, self.hdr, self.empty, self.kind = True, started, hdr, empty, kind
        self.lines = self.nbytes = 0
        self.seen = True

    def close(self):
        self.open = self.started = self.hdr = self.empty = False

    def end_record(self):
        """After a JSONL record: a carry that took nothing from it (and was not opened in it) ends."""
        if self.open and not self.seen:
            self.close()
        self.seen = self.started = False   # a record's own fields come before its key text


def _sr_pemc_line(core, started):
    return bool(_SR_PEMC_LONG.fullmatch(core) or _SR_PEMC_HDR.fullmatch(core)
                or (started and (core == "" or _SR_PEMC_SHORT.fullmatch(core))))


def _sr_pemc_step(core, started, hdr):
    """(`core` is a key line, started, hdr) after the line `core` (see SrPemCarry)."""
    if _SR_PEMC_LONG.fullmatch(core):
        return True, True, False
    if _SR_PEMC_HDR.fullmatch(core):
        return True, started, True
    if core == "":
        return (True, started, False) if started or hdr else (False, started, hdr)
    if started and _SR_PEMC_SHORT.fullmatch(core):
        return True, True, False
    return False, started, hdr


def sr_pem_opens(text):
    """The key that `text` ends inside (its last private BEGIN marker, with no END after it and only key
    lines or nothing after it, so the key goes on in the next string), as (start of the marker, its label,
    started, hdr, holds a key line), else None."""
    if "-----" not in text:
        return None
    last = None
    for last in _SR_PEMC_BEGIN.finditer(text):
        pass
    if last is None or _SR_PEMC_END.search(text, last.end()):
        return None
    rest = text[last.end():].split("\n")
    if len(rest) > SR_PEMC_MAX_LINES or rest[0].rstrip("\r").strip(" \t"):
        return None                  # the marker must end its line (`grep for <BEGIN> please` is prose)
    if len(rest) > 1 and not rest[-1]:
        rest.pop()                   # a final newline ends the last line; it is no blank line
    started, hdr, got = False, True, False
    for ln in rest[1:]:
        core = ln.rstrip("\r").strip(" \t")
        ok, started, hdr = _sr_pemc_step(core, started, hdr)
        if not ok:
            return None
        got = got or bool(core)
    return last.start(), last.group(0)[11:-5].upper(), started, hdr, got


def _sr_pemc_body_start(core, kind):
    for word, pat in _SR_PEMC_BODY:
        if word in kind:
            return pat.match(core) is not None
    return _SR_PEMC_BODY_DER.match(core) is not None


def _sr_pemc_lines(text):
    """The lines of `text`, lazily (a lookahead stops early; it need not split the whole string)."""
    i = 0
    while True:
        j = text.find("\n", i)
        if j < 0:
            yield text[i:]
            return
        yield text[i:j]
        i = j + 1


def _sr_pemc_completes(texts, carry):
    """Whether the strings `texts` (one string, or the array elements that follow) are the rest of the
    key an EMPTY carry opened: True when their run of key lines starts with `Proc-Type:`/`DEK-Info:`, its
    first body line starts like the body of this kind of key, or it reaches the END marker of the same
    kind; None when they do not start with a key line (left alone, the carry goes on); False otherwise
    (key-shaped, but not this key: the carry is dropped)."""
    started, hdr, n, nb = carry.started, carry.hdr, 0, 0
    for t in texts:
        if not isinstance(t, str):
            break
        for ln in _sr_pemc_lines(t):
            core = ln.rstrip("\r").strip(" \t")
            m = _SR_PEMC_END.match(core)
            if m:
                return n > 0 and m.group(0)[9:-5].upper() == carry.kind
            if n == 0 and _SR_PEMC_PEMHDR.fullmatch(core):
                return True
            was = started
            ok, started, hdr = _sr_pemc_step(core, started, hdr)
            if not ok:
                return False if n else None
            if started and not was and _sr_pemc_body_start(core, carry.kind):
                return True
            n += bool(core)
            nb += len(ln) + 1
            if n >= SR_PEMC_MAX_LINES or nb >= SR_PEMC_MAX_BYTES:
                return False
    return False if n else None


def _sr_pemc_mark(text, end):
    return SR_PEMC_MARK + "".join(c for c in text[:end] if c in "\r\n") + text[end:]


def sr_pem_continue(text, carry):
    """`text` with its leading run of key lines (through an END marker) replaced by the marker, while
    `carry` is open. A string that does not start with key lines (blank lines alone are none) is left
    alone and keeps the carry; one whose key lines give way to anything else, or that reaches END or the
    bound, closes it. An empty carry takes only a string that completes it (_sr_pemc_completes)."""
    if carry.empty:
        ok = _sr_pemc_completes((text,), carry)
        if not ok:
            if ok is False:
                carry.close()
            return text
        carry.empty = False
    started, hdr = carry.started, carry.hdr
    pos = n = nb = body = 0
    for ln in text.split("\n"):
        core = ln.rstrip("\r").strip(" \t")
        m = _SR_PEMC_END.match(core)
        if m:
            mention = not started and carry.lines + n == 0
            carry.close()
            if mention:                  # BEGIN … END with no key line between: a mention, not a key
                return text
            carry.seen = True
            return _sr_pemc_mark(text, pos + ln.index(m.group(0)) + len(m.group(0)))
        ok, started, hdr = _sr_pemc_step(core, started, hdr)
        if not ok:
            if body:
                carry.close()
                return _sr_pemc_mark(text, pos - 1)
            if carry.started:
                carry.close()            # key lines were interrupted: the key ended (or was cut off)
            return text
        n += 1
        nb += len(ln) + 1
        pos += len(ln) + 1
        body += bool(core)
        if carry.lines + n >= SR_PEMC_MAX_LINES or carry.nbytes + nb >= SR_PEMC_MAX_BYTES:
            carry.close()
            return _sr_pemc_mark(text, min(pos, len(text))) if body else text
    if not body:
        return text                      # nothing but blank lines: nothing taken, the carry goes on
    carry.started, carry.hdr, carry.seen = started, hdr, True
    carry.lines += n
    carry.nbytes += nb
    return _sr_pemc_mark(text, len(text))


def sr_pem_orphan_end(text):
    """A string that holds the END of a key whose BEGIN is elsewhere (the second half of a key split over
    two records): the run of key lines right before the END marker, with the marker, is replaced. Needs
    at least one full key line, so a lone END marker (e.g. in code) stays."""
    if "-----" not in text:
        return text
    m = _SR_PEMC_END.search(text)
    if m is None or _SR_PEMC_BEGIN.search(text, 0, m.start()):
        return text
    head = text[:m.start()]
    nl = head.rfind("\n")
    if head[nl + 1:].strip(" \t\r"):
        return text                  # END is not at the start of its line
    start, full, pos, n = nl + 1, False, nl, 0
    while pos > 0 and n < SR_PEMC_MAX_LINES:
        prev = head.rfind("\n", 0, pos)
        core = head[prev + 1:pos].rstrip("\r").strip(" \t")
        if not _sr_pemc_line(core, True):
            break
        full = full or bool(_SR_PEMC_LONG.fullmatch(core))
        start, pos, n = prev + 1, prev, n + 1
    if not full:
        return text
    return text[:start] + _sr_pemc_mark(text[start:], m.end() - start)


def sr_pem_walk(node, carry):
    """`node` (decoded JSON) with every key line that belongs to a key split over strings replaced, in
    document order; `carry` holds the open key across calls (one call per JSONL record). Returns the new
    node; `carry.hits` counts the strings changed."""
    if isinstance(node, str):
        out = node
        if carry.open:
            out = sr_pem_continue(node, carry)
        if out == node and "-----" in node:
            # also when a carry is open but this string did not take it on (the tail after prose, or after
            # a Codex `Exit code: … Output:` preamble): it is redacted just as without a carry
            out = sr_pem_orphan_end(node)
            if out != node:
                carry.close()
        o = sr_pem_opens(node)
        if o is not None:
            at, kind, started, hdr, got = o
            carry.begin(kind, started, hdr, empty=not got)
            # the key's first part, from its BEGIN marker to the end of this string, when it holds key
            # lines or headers (a lone marker stays: it is not secret, and may be a mention)
            cut = len(out) - (len(node) - at)
            if got and cut >= 0 and out[cut:] == node[at:]:
                out = out[:cut] + _sr_pemc_mark(out[cut:], len(out) - cut)
        if out != node:
            carry.hits += 1
        return out
    if isinstance(node, list):
        out = []
        for i, v in enumerate(node):
            if carry.open and carry.empty and isinstance(v, str):
                # an empty carry and an array of lines: the elements from here on must be the rest of the key
                ok = _sr_pemc_completes((node[j] for j in range(i, len(node))), carry)
                if ok:
                    carry.empty = False
                elif ok is False:
                    carry.close()
            out.append(sr_pem_walk(v, carry))
        return out
    if isinstance(node, dict):
        return {k: sr_pem_walk(v, carry) for k, v in node.items()}
    return node


def _sr_pemc_list_body(text, elems, kind):
    """Elements after a BEGIN element with no END: a key only when they hold a `Proc-Type:`/`DEK-Info:`
    header or their first full line starts like this kind of key's body (not an image's base64,)."""
    for a, z in elems[1:]:
        core = text[a:z].strip(" \t")
        if _SR_PEMC_PEMHDR.fullmatch(core):
            return True
        if _SR_PEMC_LONG.fullmatch(core):
            return _sr_pemc_body_start(core, kind)
    return False


def sr_pem_list_redact(text):
    """A key printed as a quoted list inside one string (`['-----BEGIN … PRIVATE KEY-----', 'MIIE…', …]`,
    or the same with `\\"`-escaped quotes in raw JSONL): every element from the BEGIN element through the
    END element is replaced, quotes and commas kept. Returns (text, keys found)."""
    if "-----" not in text:
        return text, 0
    out, pos, found = [], 0, 0
    for b in _SR_PEMC_BEGIN.finditer(text):
        if b.start() < pos:
            continue
        i = b.start()
        q0 = i - 1
        while q0 > 0 and text[q0 - 1] == "\\":
            q0 -= 1
        if i == 0 or text[i - 1] not in "\"'":
            continue
        qtok = text[q0:i]
        if not text.startswith(qtok, b.end()):
            continue
        elems = [(b.start(), b.end())]
        k, closed, total = b.end() + len(qtok), False, 0
        while len(elems) <= SR_PEMC_MAX_LINES and total < SR_PEMC_MAX_BYTES:
            sep = k
            while sep < len(text) and text[sep] in " \t\r\n,":
                sep += 1
            if sep == k or "," not in text[k:sep] or not text.startswith(qtok, sep):
                break
            s0 = sep + len(qtok)
            s1 = text.find(qtok, s0, s0 + 300)
            if s1 < 0:
                break
            core = text[s0:s1].strip(" \t")
            if _SR_PEMC_END.fullmatch(core):
                elems.append((s0, s1))
                closed = True
                break
            if not (_sr_pemc_line(core, len(elems) > 1) or (core == "" and len(elems) == 1)):
                break                    # (one blank element may follow BEGIN: a PGP block)
            elems.append((s0, s1))
            total += s1 - s0
            k = s1 + len(qtok)
        if len(elems) < 2 or not (closed or _sr_pemc_list_body(text, elems, b.group(0)[11:-5].upper())):
            continue
        for a, z in elems:
            out.append(text[pos:a])
            out.append(SR_PEMC_MARK)
            pos = z
        found += 1
    if not found:
        return text, 0
    out.append(text[pos:])
    return "".join(out), found


def sr_binary_spans(text):
    """Sorted, disjoint (start, end) spans of binary data in `text` (linear: each run is read once)."""
    spans = [m.span() for m in _SR_DATA_URI.finditer(text)]
    for m in _SR_B64_RUN.finditer(text):
        r, start = m.group(0), m.start()
        if r[0] == "/":                       # a leading path (`/home/alice/<base64 name>`) is not binary
            pm = _SR_PATH_PREFIX.match(r)
            if pm:
                r, start = r[pm.end() - 1:], start + pm.end() - 1
                if len(r) < 200:
                    continue
        if ("+" in r and r.count("/") * 16 < len(r) and _SR_B64_UPPER.search(r)
                and _SR_B64_LOWER.search(r) and _SR_B64_DIGIT.search(r)):
            spans.append((start, m.end()))
    for m in _SR_B64_WRAPPED.finditer(text):
        r = m.group(0)
        if (("+" in r or "/" in r) and _SR_B64_UPPER.search(r) and _SR_B64_LOWER.search(r)
                and _SR_B64_DIGIT.search(r)):
            spans.append(m.span())
    spans.sort()
    merged = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged


def sr_in_binary(spans, s, e):
    """The match [s, e) lies wholly inside one of `spans` (from sr_binary_spans)."""
    i = _sr_bisect.bisect_right(spans, (s, float("inf"))) - 1
    return i >= 0 and spans[i][1] >= e


# a credential whose characters are JSON string escapes (`\u0067hp_…`, `1\/\/…`) inside a string
# that is itself JSON text (a tool's output or arguments, a nested record), at any depth up to
# SR_ESC_DEPTH. The rules see the escape text, not the key. sr_escaped_spans decodes one level of escapes
# at a time and maps what a rule finds in the decoded view back to the escaped text, where the whole
# escaped run is replaced: a marker has no quote or backslash, so the text stays valid JSON at every level.
SR_ESC_DEPTH = 5            # a key escaped 3 strings deep in a raw JSONL line
# Only an escape that can stand for a key's own character (letters, digits, `+-./:=_`) can hide one; any
# other escape (`\n`, `\"`, Go's `\u003c`) leaves the key's characters as they are, and the plain rules
# already see them.
_SR_ESC_HIDES = _sr_re.compile(r"\\(?:u00(?:3[0-9AaDd]|[4-7][0-9A-Fa-f]|2[BbDdEeFf])|/)")
_SR_ESC = _sr_re.compile(r"\\(?:u([0-9A-Fa-f]{4})|([\"\\/bfnrt]))")
_SR_ESC_CH = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _sr_unescape(s):
    """One level of JSON string-escape decoding: (view, segs). segs holds (view position, source start,
    source length) for each escape, in order; the characters between escapes map one to one."""
    out, segs, pos, vlen = [], [], 0, 0
    for m in _SR_ESC.finditer(s):
        if m.start() > pos:
            out.append(s[pos:m.start()])
            vlen += m.start() - pos
        segs.append((vlen, m.start(), m.end() - m.start()))
        out.append(chr(int(m.group(1), 16)) if m.group(1) else _SR_ESC_CH[m.group(2)])
        vlen += 1
        pos = m.end()
    out.append(s[pos:])
    return "".join(out), segs


def _sr_esc_src(segs, keys, p):
    """The source range [start, end) of view character p."""
    i = _sr_bisect.bisect_right(keys, p) - 1
    if i < 0:
        return p, p + 1
    v, s, n = segs[i]
    if v == p:
        return s, s + n
    q = s + n + (p - v - 1)
    return q, q + 1


def sr_escaped_spans(text, find):
    """Spans of `text` to redact for credentials hidden by JSON escapes. `find(view)` returns (start, end)
    spans of credentials in a decoded view. A span counts only where its escaped text differs from the
    decoded one (an escape stood for one of its characters); a span with no escape in it the plain rules
    have already judged. One decode and one `find` per level, so linear in len(text) per level."""
    if not _SR_ESC_HIDES.search(text):
        return []
    levels, view, found = [], text, []
    for _ in range(SR_ESC_DEPTH):
        view, segs = _sr_unescape(view)
        if not segs:
            break
        levels.append((segs, [v for v, _s, _n in segs]))
        for a, b in find(view):
            if a >= b:
                continue
            s, s_end = a, b - 1
            for segs_, keys in reversed(levels):
                s = _sr_esc_src(segs_, keys, s)[0]
                s_end = _sr_esc_src(segs_, keys, s_end)[1] - 1
            if text[s:s_end + 1] != view[a:b]:
                found.append((s, s_end + 1))
        if not _SR_ESC_HIDES.search(view):
            break
    found.sort()
    merged = []
    for s, e in found:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged


def sr_escaped_views(text):
    """The decoded views of `text`, one per escape level (at most SR_ESC_DEPTH), for a credential check;
    empty when no escape in it can hide a key's character."""
    if not _SR_ESC_HIDES.search(text):
        return []
    out, view = [], text
    for _ in range(SR_ESC_DEPTH):
        view, segs = _sr_unescape(view)
        if not segs:
            break
        out.append(view)
        if not _SR_ESC_HIDES.search(view):
            break
    return out


# --- Private-key blocks ----------------------------------------------------------------------
# A block runs from a BEGIN marker over characters that can occur in a key body or in a line prefix a tool puts in
# front of each key line (a fixed set), up to the nearest END marker. A BARE `"`, a brace
# or any other character outside that set ends the candidate, so a block never leaves its string or
# crosses a JSONL record. With no END before that stop (a truncated or pasted key), the block runs to
# the stop or the end of the string. Linear: END starts are found once, each BEGIN either lies inside
# the previous block or scans for a stop, and a scan resumes where the last stop-free scan ended, so no
# character is scanned twice (even for back-to-back blocks with no stop character between them).
#
# Fails safe: EVERY BEGIN marker opens a key, also a lone marker in code (a regex, a
# `startswith("-----BEGIN … PRIVATE KEY-----")` check), and an unterminated BEGIN followed by prose
# redacts that prose up to the first stop character (an apostrophe, a quote, a bracket). Line breaks
# and JSON validity are kept.
SR_PEM_BEGIN = _sr_re.compile(r'-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----', _sr_re.I)
SR_PEM_END = _sr_re.compile(r'-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----', _sr_re.I)
_SR_PEM_STOP = _sr_re.compile('[^A-Za-z0-9+/=:,.\\- \t\r\n\\\\→│┃║|#>*<;]')
SR_PEM_MAX_BODY = 32768
SR_PEM_MARK = "[REDACTED-PRIVATE-KEY]"


def sr_pem_spans(text: str) -> list:
    """(start, end) of every private-key block in `text`: BEGIN through the nearest END, or through
    the key body when no END follows (see above). A lone BEGIN marker, e.g. in code, is always a span
    (fails safe).
    Linear time with a small constant, also for many BEGIN…END pairs with no stop character between."""
    if "-----" not in text:
        return []
    begins = list(SR_PEM_BEGIN.finditer(text))
    if not begins:
        return []
    end_ms = list(SR_PEM_END.finditer(text))
    end_starts = [m.start() for m in end_ms]
    spans: list = []
    pos = 0
    known_stop = -1            # a stop character found earlier: no stop lies between there and here
    clean = -1                 # [previous scan start, clean) was scanned and holds no stop character
    for b in begins:
        if b.start() < pos:
            continue
        limit = min(len(text), b.end() + SR_PEM_MAX_BODY)
        if b.end() <= known_stop:
            stop = min(known_stop, limit)
        else:
            # Resume after the stop-free run already scanned, so back-to-back blocks with no stop
            # character between them never rescan the same 32 KiB window.
            stop_m = _SR_PEM_STOP.search(text, max(b.end(), clean), limit)
            if stop_m:
                stop = known_stop = stop_m.start()
            else:
                stop = clean = limit
        i = _sr_bisect.bisect_left(end_starts, b.end())
        if i < len(end_ms) and end_starts[i] < stop:
            end = end_ms[i].end()
        else:
            end = stop
            # a BEGIN marker always opens a key: if the body run is empty, still drop the marker
        spans.append((b.start(), end))
        pos = end
    return spans


def sr_redact_pem(text: str) -> tuple:
    """`text` with every private-key block replaced by SR_PEM_MARK, plus the block count. The raw line
    breaks inside a block are kept, so the line count never changes."""
    spans = sr_pem_spans(text)
    if not spans:
        return text, 0
    out, pos = [], 0
    for s0, e0 in spans:
        breaks = "".join(c for c in text[s0:e0] if c in "\r\n")
        out.append(text[pos:s0])
        out.append(SR_PEM_MARK + breaks)
        pos = e0
    out.append(text[pos:])
    return "".join(out), len(spans)
