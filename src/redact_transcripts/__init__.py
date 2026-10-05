# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Redact secrets and personal data from transcripts, JSONL logs and plain text.

A regex backstop, not a guarantee: it catches common credential shapes, it does not understand
meaning. See the README for what it misses.
"""

from __future__ import annotations

from .engine import KEYED_VALUE, Config, Redactor, Report, StreamRedactor
from .formats import (
    CLAUDE_CODE,
    JSONL,
    TEXT,
    Format,
    JsonlFormat,
    TextFormat,
    detect_format,
    format_names,
    get_format,
    redact_bytes,
    register_format,
)
from .rules import Rule, default_rules

__version__ = "0.1.0"


def redact_text(text: str) -> str:
    """Redact one string with the default rules."""
    return Redactor().redact_text(text)


__all__ = [
    "CLAUDE_CODE",
    "Config",
    "Format",
    "JSONL",
    "JsonlFormat",
    "KEYED_VALUE",
    "Redactor",
    "Report",
    "Rule",
    "StreamRedactor",
    "TEXT",
    "TextFormat",
    "__version__",
    "default_rules",
    "detect_format",
    "format_names",
    "get_format",
    "redact_bytes",
    "redact_text",
    "register_format",
]
