# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""The redaction engine: apply rules to text, to decoded JSON values, and to a text stream."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from .rules import Base64Rule, Rule, default_rules, is_numeric_secret_key, is_secret_key, is_secret_value

#: Pseudo-rule for a JSON value stored under a key that names a secret (``{"password": "..."}``).
KEYED_VALUE = "secret.keyed_value"

_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")


@dataclass(frozen=True)
class Config:
    """Settings shared by all rules.

    ``email_keep_domains``: e-mail addresses at these domains (and their subdomains) are kept.
    ``ipv4_keep``: IPv4 addresses that are kept verbatim.
    ``marker_template``: the replacement text; ``{rule}`` is the rule name.
    """

    email_keep_domains: Tuple[str, ...] = ("example.com", "example.org", "example.net")
    ipv4_keep: FrozenSet[str] = frozenset({"127.0.0.1", "0.0.0.0", "255.255.255.255"})
    home_dir_placeholder: str = "[USER]"
    marker_template: str = "[REDACTED:{rule}]"


def _enabled(name: str, disable: Iterable[str]) -> bool:
    for d in disable:
        if name == d or name.startswith(d.rstrip(".") + "."):
            return False
    return True


class Redactor:
    """Applies an ordered list of :class:`~redact_transcripts.rules.Rule` objects.

    >>> Redactor().redact_text("token=hunter2hunter2")
    'token=[REDACTED:secret.assignment]'

    ``disable`` takes rule names or prefixes, e.g. ``("pii", "infra.ipv4")``.
    """

    def __init__(
        self,
        rules: Optional[Sequence[Rule]] = None,
        config: Optional[Config] = None,
        disable: Iterable[str] = (),
    ) -> None:
        self.config = config or Config()
        disable = tuple(disable)
        rules = list(default_rules() if rules is None else rules)
        self.rules: List[Rule] = [r for r in rules if _enabled(r.name, disable)]
        self.keyed_value_enabled = _enabled(KEYED_VALUE, disable)
        self._bound: List[Tuple[str, "re.Pattern[str]", Callable]] = [
            (r.name, r.pattern, r.bind(self)) for r in self.rules
        ]
        self._secret_only = [
            b
            for b, r in zip(self._bound, self.rules)
            if r.name.startswith("secret.") and not isinstance(r, Base64Rule)
        ]

    @property
    def rule_names(self) -> List[str]:
        names = [r.name for r in self.rules]
        if self.keyed_value_enabled:
            names.append(KEYED_VALUE)
        return names

    def marker(self, rule: str) -> str:
        return self.config.marker_template.format(rule=rule)

    @staticmethod
    def _apply(bound, text: str, counts: Optional[Dict[str, int]]) -> str:
        for name, pattern, replace in bound:
            hits = 0

            def counted(m: "re.Match[str]", _replace=replace) -> str:
                nonlocal hits
                out = _replace(m)
                if out != m.group(0):
                    hits += 1
                return out

            text = pattern.sub(counted, text)
            if hits and counts is not None:
                counts[name] = counts.get(name, 0) + hits
        return text

    def redact_text(self, text: str, counts: Optional[Dict[str, int]] = None) -> str:
        """Apply every rule to one string. ``counts`` (if given) is incremented per rule."""
        return self._apply(self._bound, text, counts)

    def contains_secret(self, text: str) -> bool:
        """True if a ``secret.*`` rule (other than the base64 rule) would change ``text``."""
        counts: Dict[str, int] = {}
        self._apply(self._secret_only, text, counts)
        return bool(counts)

    def redact_value(self, value, counts: Dict[str, int], keep: Optional[Callable[[str, str], bool]] = None):
        """Redact a decoded JSON value (dict / list / str / number ...) and return a new value.

        Object keys are redacted too. ``keep(key, value)`` may return True for a string that is
        structure, not content (a UUID under ``uuid``, say); such a value is kept only if no
        ``secret.*`` rule matches it as well, so a secret under a structural-looking key at any
        depth is still redacted.
        """
        if isinstance(value, str):
            return self.redact_text(value, counts)
        if isinstance(value, list):
            return [self.redact_value(x, counts, keep) for x in value]
        if isinstance(value, dict):
            out = {}
            for k, x in value.items():
                nk = self.redact_text(k, counts)
                while nk in out:  # two keys redacted to the same marker: keep both
                    nk += "_"
                if isinstance(x, str) and keep is not None and keep(k, x) and not self.contains_secret(x):
                    out[nk] = x
                elif self.keyed_value_enabled and _keyed_secret(k, x):
                    counts[KEYED_VALUE] = counts.get(KEYED_VALUE, 0) + 1
                    out[nk] = self.marker(KEYED_VALUE)
                elif self.keyed_value_enabled and is_secret_key(k) and isinstance(x, list):
                    out[nk] = [self._keyed_item(k, i, counts, keep) for i in x]
                else:
                    out[nk] = self.redact_value(x, counts, keep)
            return out
        return value

    def _keyed_item(self, key: str, item, counts: Dict[str, int], keep):
        if _keyed_secret(key, item):
            counts[KEYED_VALUE] = counts.get(KEYED_VALUE, 0) + 1
            return self.marker(KEYED_VALUE)
        return self.redact_value(item, counts, keep)


def _keyed_secret(key: str, value) -> bool:
    """A scalar under ``key`` that should be redacted: a string under a secret-named key that passes
    :func:`is_secret_value` (all-digit strings only in a password/secret/PIN context), or an
    integer of 4+ digits under a password/secret/PIN key that is not a counter or metric."""
    if isinstance(value, str):
        if value.isdigit():
            return len(value) >= 4 and is_numeric_secret_key(key)
        return is_secret_key(key) and is_secret_value(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return len(str(abs(value))) >= 4 and is_numeric_secret_key(key)
    return False


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
