# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Parity with the reference scrubber (the a4sx transcript scrubber these rules are ported from).

tests/data/parity_fixtures.json.gz holds inputs from the reference's own regression and fuzz tests, each
with the reference's output. Every input is synthetic (random or FAKE/EXAMPLE values, made-up names and
paths); inputs and outputs are stored base64-encoded, so no file holds a token-shaped string.

- ``redact``: the reference redacts something. Nothing it removed may survive here: every run of three
  or more letters or digits it replaced must be gone from this package's output as well (the markers
  differ, and this package may redact more).
- ``keep``: the reference leaves the input unchanged, and so does this package (its false-positive
  guards hold here too).

Both run with empty keep-lists (``email_keep_domains``, ``ipv4_keep``), as the reference has none.

To check the stored outputs against a reference implementation, set ``REDACT_REFERENCE`` to
``module:function`` (``function(text, kind) -> str``, ``kind`` is ``"text"`` or ``"line"``).
"""

import base64
import difflib
import gzip
import importlib
import json
import os
import re
from pathlib import Path

import pytest

from redact_transcripts import Config, Redactor, redact_bytes

DATA = json.loads(gzip.decompress((Path(__file__).parent / "data" / "parity_fixtures.json.gz").read_bytes()))
R = Redactor(config=Config(email_keep_domains=(), ipv4_keep=frozenset()))
CHUNK = 250
_MARK = re.compile(r"\[REDACTED:[a-z0-9_.]+\]")
_NOT_CONTENT = re.compile(r"\\[nrtbf\"\\/]|\\u[0-9A-Fa-f]{4}|[^A-Za-z0-9]")


def _d(s):
    return base64.b64decode(s).decode("utf-8", "surrogatepass")


def run(text, kind):
    if kind == "line":
        out, _ = redact_bytes(text.encode("utf-8", "surrogatepass"), format="jsonl", redactor=R)
        return out.decode("utf-8", "surrogatepass")
    return R.redact_text(text)


def kept_by_us(src, ref, ours):
    """The runs the reference replaced that survive in ``ours`` (more often than in ``ref``)."""
    ours = _MARK.sub("[R]", ours)
    left = []
    for op, i1, i2, _j1, _j2 in difflib.SequenceMatcher(None, src, ref, autojunk=False).get_opcodes():
        if op in ("replace", "delete"):
            core = src[i1:i2].strip("\\\"' ")
            if len(_NOT_CONTENT.sub("", core)) >= 3 and ours.count(core) > ref.count(core):
                left.append(core)
    return left


def _chunks(cases):
    return [pytest.param(i, id=f"{i}-{i + CHUNK}") for i in range(0, len(cases), CHUNK)]


def test_fixtures_are_not_empty():
    assert len(DATA["redact"]) >= 1000 and len(DATA["keep"]) >= 500


@pytest.mark.parametrize("start", _chunks(DATA["redact"]))
def test_everything_the_reference_redacts_is_redacted(start):
    bad = []
    for case in DATA["redact"][start : start + CHUNK]:
        src, ref = _d(case["in"]), _d(case["ref"])
        left = kept_by_us(src, ref, run(src, case["kind"]))
        if left:
            bad.append(f"{src!r}: kept {left[:3]!r}")
    assert not bad, f"{len(bad)} case(s); first: " + "\n".join(bad[:5])


@pytest.mark.parametrize("start", _chunks(DATA["keep"]))
def test_what_the_reference_keeps_is_kept(start):
    bad = []
    for case in DATA["keep"][start : start + CHUNK]:
        src = _d(case["in"])
        if run(src, case["kind"]) != src:
            bad.append(repr(src))
    assert not bad, f"{len(bad)} case(s); first: " + "\n".join(bad[:5])


@pytest.mark.skipif(not os.environ.get("REDACT_REFERENCE"), reason="set REDACT_REFERENCE=module:function")
def test_stored_outputs_match_the_reference():
    module, _, name = os.environ["REDACT_REFERENCE"].partition(":")
    reference = getattr(importlib.import_module(module), name)
    bad = [c for c in DATA["redact"] if reference(_d(c["in"]), c["kind"]) != _d(c["ref"])]
    bad += [c for c in DATA["keep"] if reference(_d(c["in"]), c["kind"]) != _d(c["in"])]
    assert not bad, f"{len(bad)} stored case(s) differ from the reference"
