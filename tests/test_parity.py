# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Parity with the reference scrubber (the a4sx transcript scrubber these rules are ported from).

tests/data/parity_fixtures.json.gz holds inputs from the reference's own regression and fuzz tests, each
with the reference's output, in two modes: ``server`` (the rules on a decoded string, or a JSONL line
decoded value by value) and ``cli`` (the reference client's pass over a raw JSONL line). Every input
is synthetic (random or FAKE/EXAMPLE values, made-up names and paths); inputs and outputs are stored
base64-encoded, so no file holds a token-shaped string.

- ``redact``: the reference redacts something. Nothing it removed may survive here: every run of three
  or more letters or digits it replaced must be gone from this package's output as well (the markers
  differ, and this package may redact more).
- ``keep``: the reference leaves the input unchanged, and so does this package (its false-positive
  guards hold here too).

Both run with empty keep-lists (``email_keep_domains``, ``ipv4_keep``), as the reference has none.

The fixtures are pinned: tests/data/parity_fixtures.lock.json records their digest, counts and the
reference revision they were made from, and CI fails if the file changes without the lock. To check (or
refresh) them against a reference implementation, set ``REDACT_REFERENCE`` to ``module:function``
(``function(text, kind, mode) -> str``; ``kind`` is ``"text"`` or ``"line"``, ``mode`` ``"server"`` or
``"cli"``) and run this test, or ``python tests/regen_parity_fixtures.py --reference module:function``.
"""

import base64
import difflib
import gzip
import hashlib
import importlib
import importlib.util
import json
import os
import re
from pathlib import Path

import pytest

from redact_transcripts import Config, Redactor, redact_bytes

FIXTURES = Path(__file__).parent / "data" / "parity_fixtures.json.gz"
LOCK = json.loads((Path(__file__).parent / "data" / "parity_fixtures.lock.json").read_text(encoding="utf-8"))
DATA = json.loads(gzip.decompress(FIXTURES.read_bytes()))
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
    assert {c["mode"] for c in DATA["redact"]} == {"server", "cli"}


def test_fixtures_match_their_lock():
    """The fixtures are exactly the pinned ones: a change needs a regenerated lock (and a reference run)."""
    assert hashlib.sha256(FIXTURES.read_bytes()).hexdigest() == LOCK["sha256"]
    assert {"redact": len(DATA["redact"]), "keep": len(DATA["keep"])} == LOCK["counts"]


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


@pytest.mark.skipif(
    not os.environ.get("REDACT_REFERENCE"),
    reason=f"fixtures pinned to reference revision {LOCK['reference_revision']}; "
    "set REDACT_REFERENCE=module:function to check them against a live reference",
)
def test_stored_outputs_match_the_reference():
    module, _, name = os.environ["REDACT_REFERENCE"].partition(":")
    reference = getattr(importlib.import_module(module), name)
    bad = [c for c in DATA["redact"] if reference(_d(c["in"]), c["kind"], c["mode"]) != _d(c["ref"])]
    for c in DATA["keep"]:
        src = _d(c["in"])
        line = src if c["kind"] == "line" else json.dumps({"c": src})
        if reference(src, c["kind"], "server") != src or reference(line, "line", "cli") != line:
            bad.append(c)
    assert not bad, f"{len(bad)} stored case(s) differ from the reference"


def _published_cli():
    """The published reference client (``REDACT_REFERENCE_CLI``: a path to its downloaded file), or None.
    With ``REDACT_REQUIRE_REFERENCE`` set (the scheduled drift job, and every release), a missing or
    unloadable client is a failure, never a skip."""
    path = os.environ.get("REDACT_REFERENCE_CLI")
    if not path:
        if os.environ.get("REDACT_REQUIRE_REFERENCE"):
            pytest.fail("REDACT_REQUIRE_REFERENCE is set but REDACT_REFERENCE_CLI is not")
        return None
    spec = importlib.util.spec_from_file_location("redact_reference_cli", path)
    if spec is None or spec.loader is None:
        pytest.fail(f"cannot load the reference client from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "scrub", None)):
        pytest.fail("the reference client has no scrub(text) function")
    return module


def test_published_cli_matches_the_fixtures():
    """Drift check against the published reference client: every stored ``cli`` output is what it makes
    today, and what the fixtures keep it keeps. A difference means the reference changed: regenerate the
    fixtures (tests/regen_parity_fixtures.py) and port the change."""
    cli = _published_cli()
    if cli is None:
        pytest.skip(
            f"fixtures pinned to reference revision {LOCK['reference_revision']}; the scheduled "
            "reference-drift workflow runs this against the published client"
        )
    bad = []
    for c in DATA["redact"]:
        if c["mode"] == "cli":
            src = _d(c["in"])
            if cli.scrub(src)[0] != _d(c["ref"]):
                bad.append(src)
    for c in DATA["keep"]:
        src = _d(c["in"])
        line = src if c["kind"] == "line" else json.dumps({"c": src})
        if cli.scrub(line)[0] != line:
            bad.append(line)
    assert not bad, (
        f"reference drift: {len(bad)} case(s) differ from the published client; first: {bad[:3]!r}"
    )
