# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""The reference client's own pass ("CLI mode"), ported: the reference rules in their raw-JSONL build,
run on a string as it is written inside a JSONL line (``json.dumps(s)[1:-1]``), plus the client's own
key rules (``sk-ant-``, ``ge_sess_``, ``ghp_``, ``AKIA``, URL credentials) in the client's order.

The decoded-string rules (``_scrub_rules.sr_rules(raw_json=False)``) and this pass differ where a JSON
escape is a boundary: ``--password X`` right after a literal ``\\n``, ``pwd=X`` before ``C:\\Users\\…``, a
lower-case ``/users/<user>/`` right after a literal ``\\t``, or an ``AKIA…`` key id glued onto a JWT. The
engine runs both, so everything either redacts is redacted. Nothing here is public API.

Its private-key pass is ported too (:func:`pem_spans`): on the encoded string a key written as quoted
string concatenation (``"-----BEGIN …\\n" "MIIE…\\n" …`` in Python, ``"…\\n" +`` in JS or Go) is one
block of escaped quotes and ``\\n`` escapes, which the decoded-string pass cannot see as a key. Not ported:
the client's product-domain host rule.
"""

from __future__ import annotations

import bisect
import re
from typing import Callable, Dict, List, NamedTuple, Optional, Tuple

from . import _scrub_rules as _sr

Check = Callable[["re.Match[str]"], Optional[Tuple[int, int]]]


class CliRule(NamedTuple):
    name: str  # the reference client's rule name
    pattern: "re.Pattern[str]"
    check: Optional[Check]  # None: replace the whole match
    develop: Optional["re.Pattern[str]"]  # the pattern for the reference run (sr_name_reconciled)
    binary_guarded: bool
    pii: bool
    precheck: Tuple[str, ...]


_PCT_BEFORE = re.compile(r"%[0-9A-Fa-f]{2}")


def _check_anthropic_key(m: "re.Match[str]") -> Optional[Tuple[int, int]]:
    """Right after `_` or a URL escape a word-shaped body (`my_sk-ant-api-key-placeholder`) is a name."""
    s, i = m.string, m.start()
    after_sep = (i > 0 and s[i - 1] == "_") or (i >= 3 and _PCT_BEFORE.fullmatch(s, i - 3, i))
    if after_sep and not _sr._sr_cls_key_like(m.group(0)[len("sk-ant-") :]):
        return None
    return m.span()


def _check_url_cred(m: "re.Match[str]") -> Tuple[int, int]:
    return m.start() + len(m.group(1)), m.end() - len(m.group(2))


def _check_url_token(m: "re.Match[str]") -> Tuple[int, int]:
    return m.start() + len(m.group(1)), m.end()


def cli_rules() -> List[CliRule]:
    """The client's rules, in its order (its own key rules first, then the shared rules, then the
    personal-data rules, a bare JWT last)."""
    shared = {n: (p, c) for n, p, c in _sr.sr_rules(raw_json=True)}
    cb = _sr._sr_cb("A-Za-z0-9_-")
    own: List[Tuple[str, "re.Pattern[str]", Optional[Check], Optional["re.Pattern[str]"], bool]] = [
        (
            "anthropic_key",
            re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{12}" + cb + "*"),
            _check_anthropic_key,
            re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{12,}"),
            True,
        ),
        (
            "session_token",
            re.compile(r"(?<![A-Za-z0-9_-])ge_sess_[A-Za-z0-9_-]{6}" + cb + "*"),
            None,
            re.compile(r"(?<![A-Za-z0-9_-])ge_sess_[A-Za-z0-9_-]{6,}"),
            True,
        ),
        (
            "github_token",
            re.compile(
                r"(?<![A-Za-z0-9_-])(?:ghp_|github_pat_)(?:(?!AIza|ya29\.|1//|GOCSPX-|gsk_|xai-)[A-Za-z0-9_]){10,}"
            ),
            None,
            None,
            True,
        ),
        ("bearer", shared["bearer"][0], shared["bearer"][1], None, False),
        # `A[KS]IA`: this package also takes `ASIA…` session key ids
        ("aws_akid", re.compile(r"(?<![A-Za-z0-9_-])A[KS]IA[0-9A-Z]{16}"), None, None, True),
        ("url_cred", re.compile(r'(https?://[^/\s:@"\\]+:)[^/\s@"\\]+(@)'), _check_url_cred, None, False),
        ("auth_header", shared["auth_header"][0], shared["auth_header"][1], None, False),
        (
            "url_token",
            re.compile(
                r"([Hh](?<![A-Za-z0-9+.-][Hh])[Tt][Tt][Pp][Ss]?://)(?=[A-Za-z0-9_-]{0,255}[0-9])"
                r"(?=[A-Za-z0-9_-]{0,255}[A-Za-z])[A-Za-z0-9_-]{16,256}(?=@)"
            ),
            _check_url_token,
            None,
            False,
        ),
    ]
    names = {o[0] for o in own}
    out = [CliRule(n, p, c, d, g, False, tuple(_sr.SR_PRECHECK.get(n, ()))) for n, p, c, d, g in own]
    out += [
        CliRule(n, p, c, None, False, False, tuple(_sr.SR_PRECHECK.get(n, ())))
        for n, (p, c) in shared.items()
        if n not in names
    ]
    pii = {n.split(".", 1)[1] for n in _sr.SR_PII_RULES}
    for full, p, c, _mark in _sr.sr_extra_rules(True):
        n = full.split(".", 1)[1]
        out.append(CliRule(n, p, c, None, False, n in pii, tuple(_sr.SR_EXTRA_PRECHECK.get(full, ()))))
    return [r for r in out if r.name != "jwt"] + [r for r in out if r.name == "jwt"]


# --- private-key blocks, as the client finds them in a raw JSONL line ---------------------------------
# A block runs from a BEGIN marker to the nearest END marker when everything between could be key body
# (base64, PEM headers, spaces, line breaks or escaped `\n` inside a JSON string), or a line prefix a tool
# or a quote puts in front of each key line (`     1→`, `cat -n`, `> `, `# `, `* `, `│ `, `; `, `<br>`), or
# an ESCAPED quote (a key written as string concatenation inside a JSON string), but not an escaped quote
# followed by `,` or `:` (an inner JSON field boundary). A bare `"` ends the candidate, so a block never
# leaves its JSON string. Linear: END starts are found once, and each stretch is scanned at most once.
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----", re.I)
_PEM_END = re.compile(r"-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----", re.I)
_PEM_STOP = re.compile("[^A-Za-z0-9+/=:,.\\- \t\r\n\\\\\u2192\u2502\u2503\u2551|#>*<;]")
_PEM_FIELD_SEP = re.compile(r"[ \t]*[,:]")
_PEM_MAX_BODY = 32768


def _is_escaped(text: str, i: int) -> bool:
    """True when text[i] follows an odd run of backslashes (an escaped character in a JSON string)."""
    j = i
    while j > 0 and text[j - 1] == "\\":
        j -= 1
    return (i - j) % 2 == 1


def pem_spans(text: str) -> List[Tuple[int, int]]:
    """(start, end) of every private-key block in a raw JSONL line (or a JSON-encoded string), BEGIN
    through the nearest END."""
    if "-----" not in text:
        return []
    ends = list(_PEM_END.finditer(text))
    if not ends:
        return []
    end_starts = [m.start() for m in ends]
    spans: List[Tuple[int, int]] = []
    skip = clean = 0
    for b in _PEM_BEGIN.finditer(text):
        if b.start() < skip:
            continue
        i = bisect.bisect_left(end_starts, b.end())
        if i == len(ends):
            break
        e = ends[i]
        if e.start() - b.end() > _PEM_MAX_BODY:
            continue
        lo = max(b.end(), clean)
        s = _PEM_STOP.search(text, lo, e.start()) if lo < e.start() else None
        while (
            s
            and text[s.start()] == '"'
            and _is_escaped(text, s.start())
            and not _PEM_FIELD_SEP.match(text, s.start() + 1)
        ):
            s = _PEM_STOP.search(text, s.start() + 1, e.start())
        if s:
            skip = clean = s.start()
            continue
        clean = e.start()
        spans.append((b.start(), e.end()))
        skip = e.end()
    return spans


#: A replaced span must not cut a JSON escape in half or contain a bare quote (the string stays JSON).
_JSON_SAFE = re.compile(r'(?:[^"\\]|\\[\s\S])*')


def json_safe_span(text: str, s0: int, e0: int) -> bool:
    """The span holds only whole JSON escapes and no bare quote, and does not start inside an escape."""
    k = s0
    while k > 0 and text[k - 1] == "\\":
        k -= 1
    return (s0 - k) % 2 == 0 and _JSON_SAFE.fullmatch(text, s0, e0) is not None


MAX_PASSES = 4

#: Marks a span for a rule: ``mark(rule_name, match, span) -> replacement or None`` (None keeps it).
Mark = Callable[[CliRule, "re.Match[str]", Tuple[int, int]], Optional[str]]


def run(
    text: str, rules: List[CliRule], mark: Mark, escaped_mark: Optional[str], counts: Dict[str, int]
) -> str:
    """One client pass over ``text`` (a JSON-encoded string, without its quotes): the rules in order,
    repeated until nothing changes, then credentials hidden by JSON escapes. ``counts`` is keyed by
    the client's rule names."""
    ref = _sr._SR_EXEMPT.ref
    low: Optional[str] = None
    for _ in range(MAX_PASSES):
        before = text
        for rule in rules:
            pat = rule.develop if ref and rule.develop is not None else rule.pattern
            if rule.precheck:
                if low is None:
                    low = text.lower()
                if not any(s in low for s in rule.precheck):
                    continue
            out: List[str] = []
            pos = 0
            bins = None
            for m in pat.finditer(text):
                if m.start() < pos:
                    continue
                if rule.pii or rule.binary_guarded:
                    if bins is None:
                        bins = _sr.sr_binary_spans(text)
                    if _sr.sr_in_binary(bins, m.start(), m.end()):
                        continue
                span = rule.check(m) if rule.check is not None else m.span()
                if span is None or not json_safe_span(text, span[0], span[1]):
                    continue
                rep = mark(rule, m, span)
                if rep is None:
                    continue
                end = max(m.end(), span[1])
                out += [text[pos : span[0]], rep, text[span[1] : end]]
                pos = end
                counts[rule.name] = counts.get(rule.name, 0) + 1
            if out:
                out.append(text[pos:])
                text, low = "".join(out), None
        if text == before:
            break
    if escaped_mark is not None:
        text = _escaped(text, rules, escaped_mark, counts)
    return text


def _escaped(text: str, rules: List[CliRule], escaped_mark: str, counts: Dict[str, int]) -> str:
    def find(view: str) -> List[Tuple[int, int]]:
        spans = []
        for rule in rules:
            if rule.pii or rule.name == "gsheet":
                continue
            for m in rule.pattern.finditer(view):
                sp = rule.check(m) if rule.check is not None else m.span()
                if sp is not None:
                    spans.append(sp)
        return spans

    spans = [(s, e) for s, e in _sr.sr_escaped_spans(text, find) if json_safe_span(text, s, e)]
    if not spans:
        return text
    counts["escaped_secret"] = counts.get("escaped_secret", 0) + len(spans)
    out, pos = [], 0
    for s, e in spans:
        out += [text[pos:s], escaped_mark]
        pos = e
    return "".join(out) + text[pos:]
