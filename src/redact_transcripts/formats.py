# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Input formats (adapters).

A format decides how raw bytes are split into records and which fields are *structure* that must
never be rewritten. Built-ins:

``text``         Plain text, redacted line by line (streams).
``jsonl``        One JSON value per line. Values and object keys are redacted; no field is
                 treated as structural unless you pass ``structural_keys``.
``claude-code``  A Claude Code session transcript (``~/.claude/projects/<dir>/<session>.jsonl``).
                 Ids, parent links, timestamps and type tags are kept, so the redacted file can
                 still be resumed.

Write your own by subclassing :class:`JsonlFormat` (override :meth:`JsonlFormat.is_structural`
for path-free key checks) or :class:`Format`, then :func:`register_format` it.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

from . import _scrub_rules as _sr
from .engine import (
    DEEP_NESTING,
    Config,
    DuplicateKeyObject,
    Redactor,
    Report,
    StreamRedactor,
    json_dumps,
    json_object_pairs,
    json_parse_float,
    opens_private_key,
)

#: Default shape for a structural value: a short identifier without spaces, ``=`` or ``:``.
IDENTIFIER_SHAPE = r"[A-Za-z0-9_.\-]{1,128}"

_ENC = "utf-8"
_ERRORS = "surrogateescape"  # undecodable bytes survive the round trip unchanged


class Format:
    """Base class. Subclasses implement :meth:`redact_bytes`."""

    name = "base"
    description = ""
    #: Extra e-mail domains that are never redacted in this format (merged into the default
    #: :class:`Config` when the caller does not pass its own redactor).
    email_keep_domains: Tuple[str, ...] = ()

    def default_redactor(
        self, disable: Iterable[str] = (), third_parties: bool = False, keep_people: Iterable[str] = ()
    ) -> Redactor:
        base = Config()
        cfg = Config(
            email_keep_domains=base.email_keep_domains + tuple(self.email_keep_domains),
            keep_people=tuple(keep_people),
        )
        return Redactor(config=cfg, disable=disable, third_parties=third_parties)

    def redact_bytes(self, raw: bytes, redactor: Redactor) -> Tuple[bytes, Report]:
        raise NotImplementedError


class TextFormat(Format):
    name = "text"
    description = "plain text, redacted line by line"

    def redact_bytes(self, raw: bytes, redactor: Redactor) -> Tuple[bytes, Report]:
        report = Report(format=self.name, input_sha256=hashlib.sha256(raw).hexdigest())
        stream = StreamRedactor(redactor, report=report)
        text = stream.feed(raw.decode(_ENC, _ERRORS)) + stream.close()
        out = text.encode(_ENC, _ERRORS)
        report.output_sha256 = hashlib.sha256(out).hexdigest()
        return out, report


class JsonlFormat(Format):
    """JSON Lines. A line that is not JSON is redacted as plain text; a private-key block that
    starts on such a line is collected up to its END line, whatever lies in between."""

    def __init__(
        self,
        name: str = "jsonl",
        structural_keys: "Iterable[str] | Mapping[str, str]" = (),
        description: str = "JSON Lines; keys and values are redacted",
        email_keep_domains: Tuple[str, ...] = (),
    ) -> None:
        self.name = name
        if isinstance(structural_keys, Mapping):
            shapes = dict(structural_keys)
        else:
            shapes = {k: IDENTIFIER_SHAPE for k in structural_keys}
        self.structural_shapes: Dict[str, "re.Pattern[str]"] = {k: re.compile(v) for k, v in shapes.items()}
        self.structural_keys: FrozenSet[str] = frozenset(shapes)
        self.description = description
        self.email_keep_domains = tuple(email_keep_domains)

    def is_structural(self, key: str) -> bool:
        """True if ``key`` names a structural field (ids, links, type tags)."""
        return key in self.structural_keys

    def keeps(self, key: str, value: str) -> bool:
        """True if ``value`` under ``key`` is structure that must not be rewritten.

        Both conditions must hold: the key is structural, and the value has that field's expected
        shape (a UUID, an identifier, a timestamp ...). The engine additionally redacts the value
        if any ``secret.*`` rule matches it.
        """
        if not self.is_structural(key):
            return False
        shape = self.structural_shapes.get(key)
        return (shape or re.compile(IDENTIFIER_SHAPE)).fullmatch(value) is not None

    def with_structural_keys(self, keys: Iterable[str]) -> "JsonlFormat":
        """A copy of this format that also keeps identifier-shaped values under ``keys``."""
        shapes = {k: p.pattern for k, p in self.structural_shapes.items()}
        shapes.update({k: IDENTIFIER_SHAPE for k in keys if k not in shapes})
        return JsonlFormat(self.name, shapes, self.description, self.email_keep_domains)

    def redact_bytes(self, raw: bytes, redactor: Redactor) -> Tuple[bytes, Report]:
        report = Report(format=self.name, input_sha256=hashlib.sha256(raw).hexdigest())
        redactor.reset()
        text = raw.decode(_ENC, _ERRORS)
        lines = text.split("\n")
        trailing_newline = text.endswith("\n")
        if trailing_newline:
            lines.pop()
        # A private key whose lines sit in separate strings (an array of lines, or BEGIN in one record
        # and the rest in the next): the carry follows it from string to string and record to record.
        pem = _sr.SrPemCarry() if redactor.private_key_enabled else None
        out: List[str] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            i += 1
            report.lines_total += 1
            line_no = report.lines_total
            if not line.strip():
                out.append(line)
                continue
            body, cr = (line[:-1], "\r") if line.endswith("\r") else (line, "")
            counts: Dict[str, int] = {}
            try:
                if too_deep(body):
                    raise RecursionError("nesting over MAX_JSON_DEPTH")  # never decoded
                obj = json.loads(body, object_pairs_hook=json_object_pairs, parse_float=json_parse_float)
            except RecursionError:
                new = redact_deep(body, redactor, counts, pem) + cr
            except ValueError:
                report.non_json_lines += 1
                block = [line]
                while opens_private_key("\n".join(block)) and i < len(lines):
                    block.append(lines[i])
                    i += 1
                    report.lines_total += 1
                new = redactor.redact_text("\n".join(block), counts)
                if pem is not None:
                    pem.close()
            else:
                try:
                    if pem is not None and (pem.open or "-----" in line):
                        pem.hits = 0
                        obj = _pem_walk(obj, pem, redactor.marker(_PRIVATE_KEY))
                        if pem.hits:
                            counts[_PRIVATE_KEY] = counts.get(_PRIVATE_KEY, 0) + pem.hits
                    if pem is not None:
                        pem.end_record()
                    redacted = redactor.redact_value(obj, counts, self.keeps)
                    new = line if not counts else json_dumps(redacted) + cr
                except RecursionError:  # a walk ran out of stack below the depth cap: fail closed
                    counts = {}
                    new = redact_deep(body, redactor, counts, pem) + cr
            report.add(line_no, counts)
            out.append(new)
        result = ("\n".join(out) + ("\n" if trailing_newline else "")).encode(_ENC, _ERRORS)
        report.output_sha256 = hashlib.sha256(result).hexdigest()
        return result, report


_PRIVATE_KEY = "secret.private_key"


def _pem_walk(node, carry: "_sr.SrPemCarry", mark: str):
    """:func:`_scrub_rules.sr_pem_walk` that keeps every member of a :class:`DuplicateKeyObject` and
    writes this package's marker."""
    if isinstance(node, DuplicateKeyObject):
        return DuplicateKeyObject([(k, _pem_walk(v, carry, mark)) for k, v in node.pairs])
    if isinstance(node, dict):
        return {k: _pem_walk(v, carry, mark) for k, v in node.items()}
    if isinstance(node, list):
        out = []
        for i, v in enumerate(node):
            if carry.open and carry.empty and isinstance(v, str):
                ok = _sr._sr_pemc_completes((node[j] for j in range(i, len(node))), carry)
                if ok:
                    carry.empty = False
                elif ok is False:
                    carry.close()
            out.append(_pem_walk(v, carry, mark))
        return out
    out = _sr.sr_pem_walk(node, carry)
    return out.replace(_sr.SR_PEMC_MARK, mark) if out != node else out


#: The deepest bracket nesting a JSONL line may have to be decoded. A deeper line is not decoded (the
#: decoder and the walk would run out of stack); it is redacted fail-closed by :func:`redact_deep`.
MAX_JSON_DEPTH = 600
_JSON_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"?', re.S)
_JSON_BRACKET = re.compile(r"[\[\]{}]")
# A string literal (+ a following `:` when it is a key), or any bare run outside strings.
_JSON_SCALAR = re.compile(r'("[^"\\]*(?:\\.[^"\\]*)*"?)(\s*:)?|[^\s\[\]{}:,"]+', re.S)
_JSON_LITERALS = frozenset(("true", "false", "null"))
_PLAIN_KEY = re.compile(r'"[A-Za-z0-9_.\- ]{1,64}"')


def too_deep(line: str, limit: int = MAX_JSON_DEPTH) -> bool:
    """Linear pre-parse check: the bracket nesting outside string literals exceeds ``limit``."""
    if line.count("[") + line.count("{") <= limit:
        return False
    stripped = _JSON_STRING.sub("", line)
    if stripped.count("[") + stripped.count("{") <= limit:
        return False
    depth = 0
    for m in _JSON_BRACKET.finditer(stripped):
        if m.group() in "[{":
            depth += 1
            if depth > limit:
                return True
        else:
            depth -= 1
    return False


def redact_deep(line: str, redactor: Redactor, counts: Dict[str, int], pem=None) -> str:
    """Fail-closed redaction of a line too deep to decode: every string value becomes the
    ``secret.deep_nesting`` marker and every other bare run ``0`` (numbers; raw text when the line is
    not JSON); only ``true``/``false``/``null`` and plain, clean keys stay. Valid JSON in, valid JSON
    out, at full depth. The text rules still run once over the line, for the report."""
    redactor.redact_text(line, counts)
    if not redactor.deep_nesting_enabled:
        return redactor.redact_text(line, {})
    counts[DEEP_NESTING] = counts.get(DEEP_NESTING, 0) + 1
    mark = json.dumps(redactor.marker(DEEP_NESTING))
    clean: Dict[str, bool] = {}

    def sub(m: "re.Match[str]") -> str:
        s, colon = m.group(1), m.group(2)
        if s is None:
            return m.group(0) if m.group(0) in _JSON_LITERALS else "0"
        if colon is None:
            return mark
        ok = clean.get(s)
        if ok is None:
            ok = clean[s] = bool(_PLAIN_KEY.fullmatch(s)) and redactor.redact_text(s, {}) == s
        return (s if ok else mark) + colon

    out = _JSON_SCALAR.sub(sub, line)
    if pem is not None:
        # The record's strings are all gone: a key the record before opened took its part here; one this
        # record opens (a private BEGIN with no END after it) carries into the next.
        begins = list(_sr._SR_PEMC_BEGIN.finditer(line))
        last = begins[-1] if begins else None
        if last is not None and not _sr._SR_PEMC_END.search(line, last.end()):
            pem.begin(kind=last.group(0)[11:-5].upper())
        elif _sr._SR_PEMC_END.search(line):
            pem.close()
        elif pem.open:
            pem.seen = True
        pem.end_record()
    return out


_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_ID = r"[A-Za-z0-9_\-]{1,128}"
_WORD = r"[A-Za-z][A-Za-z0-9_\-]{0,63}"

#: Fields Claude Code needs to rebuild a conversation on ``--resume``, each with the shape its
#: value must have to be kept. A value of any other shape is redacted like content.
CLAUDE_CODE_STRUCTURAL_KEYS: Dict[str, str] = {
    "sessionId": _UUID,
    "uuid": _UUID,
    "parentUuid": _UUID,
    "leafUuid": _UUID,
    "logicalParentUuid": _UUID,
    "requestId": _ID,
    "messageId": _ID,
    "id": _ID,
    "tool_use_id": _ID,
    "toolUseID": _ID,
    "parentToolUseID": _ID,
    "timestamp": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+\-]\d{2}:?\d{2})?",
    "type": _WORD,
    "role": _WORD,
    "subtype": _WORD,
    "stop_reason": _WORD,
    "userType": _WORD,
    "level": _WORD,
    "model": r"<synthetic>|[A-Za-z0-9][A-Za-z0-9._:/@\[\]\-]{0,127}",
    "version": r"\d{1,4}(?:\.\d{1,6}){0,3}(?:[\-+][0-9A-Za-z.\-]{1,32})?",
}

TEXT = TextFormat()
JSONL = JsonlFormat()
CLAUDE_CODE = JsonlFormat(
    name="claude-code",
    structural_keys=CLAUDE_CODE_STRUCTURAL_KEYS,
    description="Claude Code session transcript; ids/links/timestamps kept so it still resumes",
    email_keep_domains=("anthropic.com",),  # "Co-Authored-By: Claude <noreply@anthropic.com>"
)

_REGISTRY: Dict[str, Format] = {}


def register_format(fmt: Format) -> Format:
    """Make ``fmt`` available by name (to :func:`get_format` and the CLI ``--format``)."""
    _REGISTRY[fmt.name] = fmt
    return fmt


for _f in (TEXT, JSONL, CLAUDE_CODE):
    register_format(_f)


def get_format(name: str) -> Format:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise ValueError(f"unknown format {name!r}; known: {', '.join(format_names())}") from None


def format_names() -> List[str]:
    return sorted(_REGISTRY)


_CLAUDE_CODE_HINTS = ("sessionId", "parentUuid")


def detect_format(raw: bytes) -> Format:
    """Guess the format from the first non-empty line."""
    for line in raw.decode(_ENC, _ERRORS).split("\n"):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except RecursionError:
            return JSONL
        except ValueError:
            return TEXT
        if isinstance(obj, dict) and any(k in obj for k in _CLAUDE_CODE_HINTS):
            return CLAUDE_CODE
        return JSONL
    return TEXT


def redact_bytes(
    raw: bytes,
    format: "str | Format" = "auto",
    redactor: Optional[Redactor] = None,
    *,
    third_parties: bool = False,
    keep_people: Iterable[str] = (),
) -> Tuple[bytes, Report]:
    """Redact ``raw`` in the given format (``"auto"`` detects it). Returns (output, report).

    ``third_parties`` and ``keep_people`` configure the default redactor; they are ignored when
    you pass your own ``redactor``.
    """
    if isinstance(format, Format):
        fmt = format
    elif format == "auto":
        fmt = detect_format(raw)
    else:
        fmt = get_format(format)
    if redactor is None:
        redactor = fmt.default_redactor(third_parties=third_parties, keep_people=keep_people)
    return fmt.redact_bytes(raw, redactor)
