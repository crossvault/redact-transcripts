# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""The redaction engine: apply rules to text, to decoded JSON values, and to a text stream."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from . import _scrub_rules as _sr
from .people import DEFAULT_TEMPLATE, KEYED_PERSON, RULE_NAMES, People
from .rules import (
    Base64Rule,
    PrivateKeyRule,
    Rule,
    SpanRule,
    VendorTokenRule,
    default_rules,
    secret_key_kind,
)

#: Pseudo-rule for a JSON value stored under a key that names a secret (``{"password": "..."}``).
KEYED_VALUE = "secret.keyed_value"
#: Pseudo-rule for a credential spelled with JSON escapes inside a string that is itself JSON text
#: (``\\u0067hp_…``, ``1\\/\\/…``): found in the decoded view, the whole escaped run is replaced.
ESCAPED = "secret.escaped"
#: Pseudo-rule for a JSONL line nested too deeply to decode: every string in it is replaced.
DEEP_NESTING = "secret.deep_nesting"

_PEM_BEGIN = _sr.SR_PEM_BEGIN
_PEM_END = _sr.SR_PEM_END
_PRIVATE_KEY = "secret.private_key"
# A marker already in the text (this package's, or one the reference rules write): never redacted again.
_ANY_MARK = re.compile(_sr._SR_MARK)
#: A redaction can create a match for an EARLIER rule (a marker is a new boundary next to an adjacent
#: token), so the rules are repeated on a string that changed, at most this many passes; then
#: ``redact_text(redact_text(x)) == redact_text(x)``.
MAX_PASSES = 4
# Maps keyed by file PATH, not by schema (Claude Code's file-history snapshots): such a key is data,
# never a secret's name.
_PATH_KEYED_MAPS = frozenset({"trackedFileBackups"})


@dataclass(frozen=True)
class Config:
    """Settings shared by all rules.

    ``email_keep_domains``: e-mail addresses at these domains (and their subdomains) are kept.
    ``ipv4_keep``: IPv4 addresses that are kept verbatim.
    ``marker_template``: the replacement text; ``{rule}`` is the rule name.
    ``keep_people``: with ``third_parties`` on, identities that are never redacted: the author's
    own handles, names and full e-mail addresses, or extra bot accounts.
    ``person_template``: the placeholder for a third party; ``{n}`` is its number.
    """

    email_keep_domains: Tuple[str, ...] = ("example.com", "example.org", "example.net")
    ipv4_keep: FrozenSet[str] = frozenset({"127.0.0.1", "0.0.0.0", "255.255.255.255"})
    home_dir_placeholder: str = "[USER]"
    marker_template: str = "[REDACTED:{rule}]"
    keep_people: Tuple[str, ...] = ()
    person_template: str = DEFAULT_TEMPLATE


def _enabled(name: str, disable: Iterable[str]) -> bool:
    for d in disable:
        if name == d or name.startswith(d.rstrip(".") + "."):
            return False
    return True


def _select(rules: Sequence[Rule], disable: Sequence[str]) -> List[Rule]:
    out: List[Rule] = []
    for r in rules:
        if isinstance(r, VendorTokenRule):
            on = frozenset(n for n in r.enabled if _enabled(n, disable)) if _enabled(r.name, disable) else ()
            if on:
                out.append(dataclasses.replace(r, enabled=frozenset(on)))
        elif _enabled(r.name, disable):
            out.append(r)
    return out


_Bound = Tuple[Rule, Optional[Callable[["re.Match[str]"], str]]]


class Redactor:
    """Applies an ordered list of :class:`~redact_transcripts.rules.Rule` objects.

    >>> Redactor().redact_text("token=hunter2hunter2")
    'token=[REDACTED:secret.assignment]'

    ``disable`` takes rule names or prefixes, e.g. ``("pii", "infra.ipv4")``.

    The rules run in order, and again on a string that changed (at most :data:`MAX_PASSES` times),
    so redacting twice changes nothing. A private-key block is replaced before every other rule, and
    a credential spelled with JSON escapes is found after them (``secret.escaped``).

    ``third_parties=True`` also replaces other people's handles and attributed names with
    numbered placeholders (the ``person.*`` rules, see :mod:`redact_transcripts.people`):

    >>> r = Redactor(third_parties=True)
    >>> r.redact_text("thanks @fake-reviewer, see @fake-reviewer's note")
    "thanks @[PERSON-1], see @[PERSON-1]'s note"

    With ``third_parties`` on, a redactor numbers people across every call until :meth:`reset`;
    the formats and :class:`StreamRedactor` reset it at the start of each transcript. Use one
    redactor per transcript at a time.
    """

    def __init__(
        self,
        rules: Optional[Sequence[Rule]] = None,
        config: Optional[Config] = None,
        disable: Iterable[str] = (),
        third_parties: bool = False,
    ) -> None:
        self.config = config or Config()
        disable = tuple(disable)
        self.rules: List[Rule] = _select(list(default_rules() if rules is None else rules), disable)
        self.keyed_value_enabled = _enabled(KEYED_VALUE, disable)
        self.escaped_enabled = _enabled(ESCAPED, disable)
        self.deep_nesting_enabled = _enabled(DEEP_NESTING, disable)
        self.private_key_enabled = any(isinstance(r, PrivateKeyRule) for r in self.rules)
        self.people: Optional[People] = None
        if third_parties:
            self.people = People(
                keep=self.config.keep_people,
                template=self.config.person_template,
                enabled=[n for n in RULE_NAMES if _enabled(n, disable)],
            )
        self._bound: List[_Bound] = [
            (r, None if isinstance(r, (SpanRule, PrivateKeyRule)) else r.bind(self)) for r in self.rules
        ]
        self._secret_only = [
            b for b in self._bound if b[0].name.startswith("secret.") and not isinstance(b[0], Base64Rule)
        ]

    @property
    def rule_names(self) -> List[str]:
        names = [n for r in self.rules for n in r.names]
        if self.keyed_value_enabled:
            names.append(KEYED_VALUE)
        if self.escaped_enabled:
            names.append(ESCAPED)
        if self.people is not None:
            names.extend(n for n in RULE_NAMES if n in self.people.enabled)
        return list(dict.fromkeys(names))

    def reset(self) -> None:
        """Start a new transcript: forget the third-party placeholders handed out so far."""
        if self.people is not None:
            self.people.reset()

    def marker(self, rule: str) -> str:
        return self.config.marker_template.format(rule=rule)

    # --- applying the rules ----------------------------------------------------------------------

    def _span_sub(self, rule: SpanRule, text: str, counts: Dict[str, int]) -> str:
        """One :class:`SpanRule` over ``text``: each accepted match's span becomes the marker."""
        out: List[str] = []
        pos = 0
        bins: Optional[List[Tuple[int, int]]] = None
        vendor = isinstance(rule, VendorTokenRule)
        for m in rule.pattern.finditer(text):
            if m.start() < pos:
                continue  # inside a span an earlier match replaced past its own end
            if rule.binary_safe:
                if bins is None:
                    bins = _sr.sr_binary_spans(text)
                if _sr.sr_in_binary(bins, m.start(), m.end()):
                    continue
            sp = rule.span(m, self)
            if sp is None:
                continue
            end = max(m.end(), sp[1])  # a span may end past the match (a JWT's lookahead)
            name = rule.hit_name(m, sp) if vendor else rule.name  # type: ignore[attr-defined]
            mark = self.marker(name) if name != "pii.home_dir" else self.config.home_dir_placeholder
            if text[sp[0] : sp[1]] == mark or _ANY_MARK.fullmatch(text, sp[0], sp[1]):
                continue  # already a marker (a rule whose value may be one): nothing to redact
            out.append(text[pos : sp[0]])
            out.append(mark)
            out.append(text[sp[1] : end])
            pos = end
            counts[name] = counts.get(name, 0) + 1
        if not out:
            return text
        out.append(text[pos:])
        return "".join(out)

    @staticmethod
    def _sub(name: str, pattern: "re.Pattern[str]", replace, text: str, counts: Dict[str, int]) -> str:
        hits = 0

        def counted(m: "re.Match[str]") -> str:
            nonlocal hits
            out = replace(m)
            if out != m.group(0):
                hits += 1
            return out

        text = pattern.sub(counted, text)
        if hits:
            counts[name] = counts.get(name, 0) + hits
        return text

    def _pass(self, bound: Sequence[_Bound], text: str, counts: Dict[str, int]) -> str:
        low: Optional[str] = None
        for rule, replace in bound:
            if isinstance(rule, PrivateKeyRule):
                continue
            if isinstance(rule, SpanRule):
                if rule.precheck:
                    if low is None:
                        low = text.lower()
                    if not any(p in low for p in rule.precheck):
                        continue
                new = self._span_sub(rule, text, counts)
            else:
                new = self._sub(rule.name, rule.pattern, replace, text, counts)
            if new != text:
                text, low = new, None
        return text

    def _private_keys(self, text: str, counts: Dict[str, int]) -> str:
        """A key printed as a quoted list of its lines, then whole blocks (their line breaks kept)."""
        mark = self.marker(_PRIVATE_KEY)
        out, n0 = _sr.sr_pem_list_redact(text)
        if n0:
            out = out.replace(_sr.SR_PEMC_MARK, mark)
        spans = _sr.sr_pem_spans(out)
        if spans:
            parts, pos = [], 0
            for s, e in spans:
                parts += [out[pos:s], mark, "".join(c for c in out[s:e] if c in "\r\n")]
                pos = e
            out = "".join(parts) + out[pos:]
        if len(spans) + n0:
            counts[_PRIVATE_KEY] = counts.get(_PRIVATE_KEY, 0) + len(spans) + n0
        return out

    def _escaped_spans(self, bound: Sequence[_Bound], view: str) -> List[Tuple[int, int]]:
        """Spans of credentials in a decoded view (see :data:`ESCAPED`): the ``secret.*`` rules only."""
        spans: List[Tuple[int, int]] = list(_sr.sr_pem_spans(view)) if self.private_key_enabled else []
        for rule, replace in bound:
            if not rule.name.startswith("secret.") or isinstance(rule, (PrivateKeyRule, Base64Rule)):
                continue
            for m in rule.pattern.finditer(view):
                if isinstance(rule, SpanRule):
                    sp = rule.span(m, self)
                elif replace is not None and replace(m) != m.group(0):
                    sp = (m.end(rule.keep_group), m.end()) if rule.keep_group else m.span()
                else:
                    sp = None
                if sp is not None:
                    spans.append(sp)
        return spans

    def _run(self, bound: Sequence[_Bound], text: str, counts: Dict[str, int]) -> str:
        out = text
        if self.private_key_enabled:
            out = self._private_keys(out, counts)
        for _ in range(MAX_PASSES):
            before = out
            out = self._pass(bound, out, counts)
            if out == before:
                break
        if self.escaped_enabled:
            spans = _sr.sr_escaped_spans(out, lambda view: self._escaped_spans(bound, view))
            if spans:
                counts[ESCAPED] = counts.get(ESCAPED, 0) + len(spans)
                parts, pos = [], 0
                for s, e in spans:
                    parts += [out[pos:s], self.marker(ESCAPED)]
                    pos = e
                out = "".join(parts) + out[pos:]
        return out

    def _redact(self, bound: Sequence[_Bound], text: str, counts: Optional[Dict[str, int]]) -> str:
        def run() -> Tuple[str, Dict[str, int]]:
            c: Dict[str, int] = {}
            return self._run(bound, text, c), c

        # A vendor-key-shaped NAME the rules keep (`id-xai-GrokModelConfigLoader`) never keeps any other
        # character that a run without that exemption redacts (see _scrub_rules.sr_name_reconciled).
        out, c = _sr.sr_name_reconciled(run)
        if counts is not None:
            for k, v in c.items():
                counts[k] = counts.get(k, 0) + v
        return out

    def redact_text(self, text: str, counts: Optional[Dict[str, int]] = None) -> str:
        """Apply every rule to one string. ``counts`` (if given) is incremented per rule."""
        text = self._redact(self._bound, text, counts)
        if self.people is not None:
            text = self.people.redact(text, counts)
        return text

    def contains_secret(self, text: str) -> bool:
        """True if a ``secret.*`` rule (other than the base64 rule) would change ``text``."""
        counts: Dict[str, int] = {}
        self._redact(self._secret_only, text, counts)
        return bool(counts)

    # --- decoded JSON ------------------------------------------------------------------------------

    def redact_value(self, value, counts: Dict[str, int], keep: Optional[Callable[[str, str], bool]] = None):
        """Redact a decoded JSON value (dict / list / str / number ...) and return a new value.

        Object keys are redacted too. ``keep(key, value)`` may return True for a string that is
        structure, not content (a UUID under ``uuid``, say); such a value is kept only if no
        ``secret.*`` rule matches it as well, so a secret under a structural-looking key at any
        depth is still redacted. Everything under a key that names a secret (``{"token": …}``,
        ``{"credentials": {"v": …}}``) is judged against that key (``secret.keyed_value``).
        """
        return self._value(value, counts, keep, False)

    def _value(self, value, counts: Dict[str, int], keep, path_keyed: bool):
        if isinstance(value, str):
            return self.redact_text(value, counts)
        if isinstance(value, list):
            return [self._value(x, counts, keep, False) for x in value]
        if isinstance(value, dict):
            return self._object(value, counts, keep, path_keyed, None)
        return value

    def _object(self, obj: dict, counts: Dict[str, int], keep, path_keyed: bool, kind: Optional[str]):
        pairs = obj.pairs if isinstance(obj, DuplicateKeyObject) else list(obj.items())
        out: List[Tuple[str, object]] = []
        taken = set()
        for k, x in pairs:
            nk = self.redact_text(k, counts)
            if not isinstance(obj, DuplicateKeyObject):
                while nk in taken:  # two keys redacted to the same marker: keep both
                    nk += "_"
                taken.add(nk)
            out.append((nk, self._member(k, x, obj, counts, keep, path_keyed, kind)))
        return DuplicateKeyObject(out) if isinstance(obj, DuplicateKeyObject) else dict(out)

    def _member(self, k: str, x, obj, counts: Dict[str, int], keep, path_keyed: bool, kind: Optional[str]):
        """The redacted value of the member ``k: x`` of the JSON object ``obj``."""
        if (
            kind is None
            and isinstance(x, str)
            and keep is not None
            and keep(k, x)
            and not self.contains_secret(x)
        ):
            return x
        if isinstance(x, str) and self.people is not None and (person := self.people.keyed(k, x, obj.keys())):
            counts[KEYED_PERSON] = counts.get(KEYED_PERSON, 0) + 1
            return person
        if self.keyed_value_enabled and not path_keyed:
            kind = secret_key_kind(k) or kind
        if kind is not None:
            return self._keyed(kind, x, counts, keep)
        if isinstance(x, dict):
            return self._object(x, counts, keep, k in _PATH_KEYED_MAPS, None)
        return self._value(x, counts, keep, False)

    def _keyed(self, kind: str, node, counts: Dict[str, int], keep):
        """Everything under a secret-named key: every scalar leaf that qualifies (in lists and objects
        too), judged against that key or a secret-named key nearer the leaf; other leaves get the
        normal rules."""
        if isinstance(node, list):
            return [self._keyed(kind, v, counts, keep) for v in node]
        if isinstance(node, dict):
            return self._object(node, counts, keep, False, kind)
        if _sr.sr_secret_value(kind, node):
            counts[KEYED_VALUE] = counts.get(KEYED_VALUE, 0) + 1
            return self.marker(KEYED_VALUE)
        return self.redact_text(node, counts) if isinstance(node, str) else node


class DuplicateKeyObject(dict):
    """A JSON object that repeats a key. As a dict it holds the last value of each key, which is what
    :func:`json.loads` returns; :attr:`pairs` keeps every member in order, so every occurrence is
    scanned and written back."""

    def __init__(self, pairs: List[Tuple[str, object]]) -> None:
        super().__init__(pairs)
        self.pairs = list(pairs)


def json_object_pairs(pairs: List[Tuple[str, object]]) -> dict:
    """``object_pairs_hook`` for :func:`json.loads` that scans every occurrence of duplicate JSON
    keys: a plain dict, or a :class:`DuplicateKeyObject` when a key repeats."""
    obj = dict(pairs)
    return obj if len(obj) == len(pairs) else DuplicateKeyObject(pairs)


class RawNumber:
    """A JSON number literal that does not survive a round trip through float (``1e400`` is infinite):
    kept as its original token, so a rewritten line says ``1e400`` again, never the non-JSON
    ``Infinity``. Not a str, so no rule ever touches it."""

    __slots__ = ("token",)

    def __init__(self, token: str) -> None:
        self.token = token


def json_parse_float(token: str):
    """``parse_float`` for :func:`json.loads`: a float, or a :class:`RawNumber` when it overflows."""
    f = float(token)
    return f if math.isfinite(f) else RawNumber(token)


def _dumps_scalar(value) -> str:
    if isinstance(value, RawNumber):
        return value.token
    out = json.dumps(value, ensure_ascii=False)
    if isinstance(value, str):
        try:
            out.encode("utf-8", "surrogateescape")
        except UnicodeEncodeError:  # a lone surrogate from a `\\ud800` escape: write it escaped again
            out = json.dumps(value, ensure_ascii=True)
    return out


def json_dumps(value) -> str:
    """Compact JSON (``separators=(",", ":")``, no ASCII escaping) that writes out every member of a
    :class:`DuplicateKeyObject`."""
    if isinstance(value, DuplicateKeyObject):
        members = value.pairs
    elif isinstance(value, dict):
        members = list(value.items())
    elif isinstance(value, list):
        return "[" + ",".join(json_dumps(x) for x in value) + "]"
    else:
        return _dumps_scalar(value)
    return "{" + ",".join(_dumps_scalar(k) + ":" + json_dumps(x) for k, x in members) + "}"


@dataclass
class Report:
    """What a redaction run changed. Names rules and line numbers only, never a matched value."""

    format: str = ""
    lines_total: int = 0
    lines_changed: int = 0
    rules: Dict[str, int] = field(default_factory=dict)
    changed_lines: List[int] = field(default_factory=list)  # 1-based, first line of each change
    non_json_lines: int = 0
    input_sha256: str = ""
    output_sha256: str = ""

    def add(self, line_no: int, counts: Dict[str, int]) -> None:
        if not counts:
            return
        self.lines_changed += 1
        self.changed_lines.append(line_no)
        for k, n in counts.items():
            self.rules[k] = self.rules.get(k, 0) + n

    @property
    def total(self) -> int:
        return sum(self.rules.values())

    def secrets_found(self) -> int:
        return sum(n for k, n in self.rules.items() if k.startswith("secret."))

    def as_dict(self, max_lines: int = 50) -> dict:
        return {
            "format": self.format,
            "lines_total": self.lines_total,
            "lines_changed": self.lines_changed,
            "rules": dict(sorted(self.rules.items())),
            "changed_lines": self.changed_lines[:max_lines],
            "changed_lines_truncated": len(self.changed_lines) > max_lines,
            "non_json_lines": self.non_json_lines,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "identical": self.input_sha256 == self.output_sha256,
        }


def opens_private_key(text: str) -> bool:
    """True if ``text`` contains a private-key BEGIN line without a matching END after it."""
    pos = 0
    while True:
        b = _PEM_BEGIN.search(text, pos)
        if not b:
            return False
        e = _PEM_END.search(text, b.end())
        if not e:
            return True
        pos = e.end()


class StreamRedactor:
    """Redact text that arrives in chunks (a log tail, a streamed model response, a pipe).

    Output is released line by line. A secret split across chunks is therefore still caught,
    as long as it does not span a newline. The one multi-line shape, a PEM private-key block,
    is held back until its END line arrives. For any chunking, the concatenated output equals
    ``redactor.redact_text(whole_input)``, with one exception: a line longer than
    ``max_buffer`` characters, or a key block longer than that, is flushed early; a
    still-unterminated key block is then redacted to its end and the following lines are
    dropped until the END line.

    >>> s = StreamRedactor(Redactor())
    >>> s.feed("key ghp_FAKE") + s.feed("FAKEFAKEFAKEFAKEFAKE00\\n") + s.close()
    'key [REDACTED:secret.github_token]\\n'
    """

    def __init__(
        self, redactor: Optional[Redactor] = None, max_buffer: int = 1 << 20, report: Optional[Report] = None
    ) -> None:
        self.redactor = redactor or Redactor()
        self.max_buffer = max_buffer
        self.report = report if report is not None else Report(format="text")
        self.redactor.reset()
        self._buf = ""
        self._held = ""
        self._held_start = 0
        self._swallow = False
        self._closed = False
        self._in_hash = hashlib.sha256()
        self._out_hash = hashlib.sha256()

    def _out(self, text: str) -> str:
        self._out_hash.update(text.encode("utf-8", "surrogateescape"))
        return text

    def _emit(self, seg: str, line_no: int) -> str:
        counts: Dict[str, int] = {}
        out = self.redactor.redact_text(seg, counts)
        self.report.add(line_no, counts)
        return out

    def _line(self, line: str) -> str:
        self.report.lines_total += 1
        line_no = self.report.lines_total
        if self._swallow:
            m = _PEM_END.search(line)
            if not m:
                return ""
            self._swallow = False
            line = line[m.end() :]
            if not line:
                return ""
        if self._held:
            self._held += line
            if not opens_private_key(self._held):
                seg, self._held = self._held, ""
                return self._emit(seg, self._held_start)
            if len(self._held) > self.max_buffer:
                seg, self._held = self._held, ""
                self._swallow = True
                return self._emit(seg, self._held_start)
            return ""
        if opens_private_key(line):
            self._held, self._held_start = line, line_no
            return ""
        return self._emit(line, line_no)

    def feed(self, chunk: str) -> str:
        """Add a chunk; return the redacted text that is safe to release now."""
        if self._closed:
            raise ValueError("feed() after close()")
        self._in_hash.update(chunk.encode("utf-8", "surrogateescape"))
        self._buf += chunk
        out: List[str] = []
        start = 0
        while True:
            nl = self._buf.find("\n", start)
            if nl < 0:
                break
            out.append(self._line(self._buf[start : nl + 1]))
            start = nl + 1
        self._buf = self._buf[start:]
        if len(self._buf) > self.max_buffer:
            seg, self._buf = self._buf, ""
            out.append(self._line(seg))
        return self._out("".join(out))

    def close(self) -> str:
        """Flush everything still buffered (an unterminated key block is redacted to its end)."""
        if self._closed:
            return ""
        self._closed = True
        out = ""
        if self._buf:
            seg, self._buf = self._buf, ""
            out += self._line(seg)
        if self._held:
            seg, self._held = self._held, ""
            out += self._emit(seg, self._held_start)
        out = self._out(out)
        self.report.input_sha256 = self._in_hash.hexdigest()
        self.report.output_sha256 = self._out_hash.hexdigest()
        return out
