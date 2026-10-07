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

from .engine import Config, Redactor, Report, StreamRedactor, opens_private_key

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
                obj = json.loads(body)
            except ValueError:
                report.non_json_lines += 1
                block = [line]
                while opens_private_key("\n".join(block)) and i < len(lines):
                    block.append(lines[i])
                    i += 1
                    report.lines_total += 1
                new = redactor.redact_text("\n".join(block), counts)
            else:
                try:
                    redacted = redactor.redact_value(obj, counts, self.keeps)
                    new = (
                        line
                        if not counts
                        else (json.dumps(redacted, ensure_ascii=False, separators=(",", ":")) + cr)
                    )
                except RecursionError:  # nests too deeply to walk: redact the line as text
                    counts = {}
                    report.non_json_lines += 1
                    new = redactor.redact_text(line, counts)
            report.add(line_no, counts)
            out.append(new)
        result = ("\n".join(out) + ("\n" if trailing_newline else "")).encode(_ENC, _ERRORS)
        report.output_sha256 = hashlib.sha256(result).hexdigest()
        return result, report


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

#: Fields of an Odysseus session export (``{"name", "model", "exported", "messages":
#: [{"role", "content"}]}``) whose normal values (``user``, ``text``, ``qwen3:8b``, an ISO time)
#: no rule matches, so they pass through unchanged. They get no exemption: a value under one of
#: these keys, at any position, is redacted whenever a rule of any kind (secret, PII, infra)
#: matches it. The session ``name`` is a user-written title and is redacted like content.
ODYSSEUS_FIELDS: Tuple[str, ...] = ("role", "type", "model", "exported")


def _is_export_dict(obj) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("messages"), list) and "exported" in obj


def _is_odysseus_export(obj) -> bool:
    """One export, or a flat list of exports (one level only, so depth cannot recurse)."""
    if isinstance(obj, list):
        return bool(obj) and all(_is_export_dict(x) for x in obj)
    return _is_export_dict(obj)


def _loads_document(text: str):
    """``json.loads`` for a whole document; None if it is not JSON or nests too deeply."""
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _json_indent(text: str) -> "int | str | None":
    """The indent of a pretty-printed JSON document (a width, or the literal tab/space string),
    or None if it is on one line."""
    lines = text.strip().split("\n")
    if len(lines) < 2:
        return None
    second = lines[1].rstrip("\r")
    lead = second[: len(second) - len(second.lstrip(" \t"))]
    if not lead:
        return 2
    return len(lead) if set(lead) == {" "} else lead


class OdysseusFormat(JsonlFormat):
    """An Odysseus session export: one JSON document (pretty-printed or compact), a list of
    them, or one export per line.

    Every value is redacted like content; see :data:`ODYSSEUS_FIELDS` for why roles, part
    types, the model and the export time still come out unchanged. ``structural_keys`` (the CLI's
    ``--keep-key``) adds identifier-shaped fields to keep, as in ``jsonl``. The export holds the
    conversation only, so there is no system prompt or tool schema in it.
    """

    def __init__(
        self,
        name: str = "odysseus",
        structural_keys: "Iterable[str] | Mapping[str, str]" = (),
        description: str = "Odysseus session export; roles, part types, model and export time unchanged",
        email_keep_domains: Tuple[str, ...] = (),
    ) -> None:
        super().__init__(name, structural_keys, description, email_keep_domains)

    def with_structural_keys(self, keys: Iterable[str]) -> "OdysseusFormat":
        shapes = {k: p.pattern for k, p in self.structural_shapes.items()}
        shapes.update({k: IDENTIFIER_SHAPE for k in keys if k not in shapes})
        return OdysseusFormat(self.name, shapes, self.description, self.email_keep_domains)

    def redact_bytes(self, raw: bytes, redactor: Redactor) -> Tuple[bytes, Report]:
        text = raw.decode(_ENC, _ERRORS)
        body = text[1:] if text.startswith("﻿") else text
        obj = _loads_document(body)
        if not isinstance(obj, (dict, list)):
            try:
                return super().redact_bytes(raw, redactor)  # one export per line, or not JSON
            except RecursionError:
                return _as_text(raw, redactor, self.name)  # a line nests too deeply
        report = Report(format=self.name, input_sha256=hashlib.sha256(raw).hexdigest())
        redactor.reset()
        report.lines_total = body.count("\n") + (0 if body.endswith("\n") else 1)
        counts: Dict[str, int] = {}
        try:
            redacted = redactor.redact_value(obj, counts, self.keeps)
        except RecursionError:
            return _as_text(raw, redactor, self.name)
        report.add(1, counts)
        if not counts:
            out = raw
        else:
            indent = _json_indent(body)
            if indent is None:
                new = json.dumps(redacted, ensure_ascii=False, separators=(",", ":"))
            else:
                new = json.dumps(redacted, ensure_ascii=False, indent=indent)
            if "\r\n" in body.rstrip():
                new = new.replace("\n", "\r\n")
            trailing = body[len(body.rstrip()) :]
            out = (text[: len(text) - len(body)] + new + trailing).encode(_ENC, _ERRORS)
        report.output_sha256 = hashlib.sha256(out).hexdigest()
        return out, report


def _as_text(raw: bytes, redactor: Redactor, name: str) -> Tuple[bytes, Report]:
    out, report = TextFormat().redact_bytes(raw, redactor)
    report.format = name
    return out, report


TEXT = TextFormat()
JSONL = JsonlFormat()
CLAUDE_CODE = JsonlFormat(
    name="claude-code",
    structural_keys=CLAUDE_CODE_STRUCTURAL_KEYS,
    description="Claude Code session transcript; ids/links/timestamps kept so it still resumes",
    email_keep_domains=("anthropic.com",),  # "Co-Authored-By: Claude <noreply@anthropic.com>"
)

ODYSSEUS = OdysseusFormat()

_REGISTRY: Dict[str, Format] = {}


def register_format(fmt: Format) -> Format:
    """Make ``fmt`` available by name (to :func:`get_format` and the CLI ``--format``)."""
    _REGISTRY[fmt.name] = fmt
    return fmt


for _f in (TEXT, JSONL, CLAUDE_CODE, ODYSSEUS):
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
    """Guess the format from the first non-empty line (or the whole input, for one JSON document
    spread over several lines)."""
    text = raw.decode(_ENC, _ERRORS)
    for line in text.split("\n"):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except RecursionError:
            return TEXT
        except ValueError:
            whole = _loads_document(text[1:] if text.startswith("\ufeff") else text)
            return ODYSSEUS if _is_odysseus_export(whole) else TEXT
        if isinstance(obj, dict) and any(k in obj for k in _CLAUDE_CODE_HINTS):
            return CLAUDE_CODE
        if _is_odysseus_export(obj):
            return ODYSSEUS
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
