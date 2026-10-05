# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Pathological inputs must stay fast (no catastrophic backtracking / ReDoS)."""

import time

import pytest

from redact_transcripts import Redactor

SIZE = 200_000  # characters per input, on a single line
LIMIT = 2.0  # seconds; a linear scan takes well under 0.2 s

PATTERNS = {
    "dotted-run": "a.",
    "dashed-run": "a-",
    "digit-dots": "1.",
    "a.b": "a.b",
    "keyword-run": "token",
    "assignment-run": "password=",
    "quote-open": 'password="',
    "escaped-quote": 'password=\\"',
    "at-run": "a@",
    "dotted-at": "a.a@",
    "scheme-run": "a://",
    "userinfo-run": "https://a:",
    "auth-header-run": "authorization: token ",
    "bearer-run": "bearer ",
    "home-run": "/Users/",
    "base64-run": "A",
    "pem-begin-run": "-----BEGIN PRIVATE KEY-----",
    "jwt-run": "eyJ",
}


@pytest.mark.parametrize("name", sorted(PATTERNS))
def test_pathological_line_is_linear(name):
    unit = PATTERNS[name]
    text = unit * (SIZE // len(unit))
    redactor = Redactor()
    start = time.perf_counter()
    redactor.redact_text(text)
    elapsed = time.perf_counter() - start
    assert elapsed < LIMIT, f"{name}: {elapsed:.2f}s for {len(text)} chars"
