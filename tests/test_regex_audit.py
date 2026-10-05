# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Adversarial timing audit of every regular expression in ``people.py`` (the ``person.*`` rules).

Exponential backtracking shows up on short inputs, so every pattern is run with ``search``,
``match`` and ``fullmatch`` on crafted lines of 8, 40 and 200 bytes. Polynomial blow-ups show up
on long inputs, so the whole third-party pass runs on the same shapes at 8, 40 and 200 KB and
must grow about linearly. Every test has a hard timeout, so a regression fails instead of hanging.
"""

import re
import signal
import time
from contextlib import contextmanager

import pytest

from redact_transcripts import Redactor, people

PATTERNS = {name: obj for name, obj in sorted(vars(people).items()) if isinstance(obj, re.Pattern)}

# Line starts that put a pattern into its "interesting" state.
PREFIXES = [
    "",
    "ls",
    "$ more",
    "sudo cat",
    "Co-authored-by: ",
    "author:\t",
    "assignees: ",
    "On ",
    "Am ",
    "schrieb ",
    '{"login": "',
    '"name": "',
    "SELECT ",
    "UPDATE ",
    "EXEC ",
    "https://",
    "x.com/",
]
# Repeated units: shapes that fit two alternatives at once, long runs of one class, separators.
UNITS = [
    " -/",
    " -.",
    " ./",
    " -",
    " a/",
    " a.b",
    "a",
    "A",
    "Ab ",
    "a.",
    "a-",
    "a'",
    ".a",
    "@",
    "@a",
    "@a.",
    "@a ",
    " @a",
    "a@",
    "a@b.",
    "/@",
    "a/@",
    " ",
    "\t",
    ",",
    "a,",
    ", a",
    ":",
    " :",
    "<",
    "<a",
    "(",
    "x,",
    '"',
    '\\"',
    "1",
    "1 ",
    "de ",
    "Ab de ",
    "A-b ",
    "SELECT ",
    "FROM ",
    " wrote",
    " commented on ",
    "github.com/",
    "a.b/",
]
SUFFIXES = ["", " (@x", ":", "!"]
BYTE_SIZES = (8, 40, 200)
KB_SIZES = (8_000, 40_000, 200_000)
CALL_LIMIT = 0.05  # seconds for one call on at most ~220 characters


@contextmanager
def hard_timeout(seconds):
    """Fail (not hang) if the block runs longer than ``seconds``. Needs SIGALRM (not Windows)."""
    if not hasattr(signal, "setitimer"):
        yield
        return

    def boom(signum, frame):
        raise TimeoutError(f"exceeded the hard timeout of {seconds}s")

    old = signal.signal(signal.SIGALRM, boom)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _line(prefix, unit, size, suffix=""):
    body = unit * (max(0, size - len(prefix) - len(suffix)) // len(unit) + 1)
    return (prefix + body)[: max(size - len(suffix), len(prefix))] + suffix


def test_every_pattern_is_audited():
    assert len(PATTERNS) >= 25, sorted(PATTERNS)


@pytest.mark.parametrize("name", sorted(PATTERNS))
def test_pattern_on_short_adversarial_lines(name):
    """search / match / fullmatch on every prefix x unit x suffix at 8, 40 and 200 bytes."""
    pattern = PATTERNS[name]
    worst, worst_input = 0.0, ""
    with hard_timeout(60):
        for prefix in PREFIXES:
            for unit in UNITS:
                for suffix in SUFFIXES:
                    for size in BYTE_SIZES:
                        text = _line(prefix, unit, size, suffix)
                        t0 = time.perf_counter()
                        pattern.search(text)
                        pattern.match(text)
                        pattern.fullmatch(text)
                        dt = time.perf_counter() - t0
                        if dt > worst:
                            worst, worst_input = dt, text
    assert worst < CALL_LIMIT, (name, worst, worst_input)


def test_shell_tokenizer_and_full_pass_on_short_lines():
    worst, worst_input = 0.0, ""
    with hard_timeout(60):
        for prefix in PREFIXES:
            for unit in UNITS:
                for suffix in SUFFIXES:
                    for size in BYTE_SIZES:
                        text = _line(prefix, unit, size, suffix)
                        t0 = time.perf_counter()
                        people._shell_argument_position(text)
                        Redactor(third_parties=True).redact_text(text)
                        dt = time.perf_counter() - t0
                        if dt > worst:
                            worst, worst_input = dt, text
    assert worst < CALL_LIMIT, (worst, worst_input)


# The exact reproduction from the review of 0.2.0: `ls` + 40 x ` -/` + ` (@fakeuser` (a 134-byte
# line with its newline) took more than 30 s with the first shell-prefix regex.
REVIEW_REPRO = "ls" + " -/" * 40 + " (@fakeuser\n"


def test_review_repro_is_fast():
    assert len(REVIEW_REPRO.encode()) == 134
    with hard_timeout(5):
        t0 = time.perf_counter()
        out = Redactor(third_parties=True).redact_text(REVIEW_REPRO)
        dt = time.perf_counter() - t0
    assert dt < CALL_LIMIT, dt
    assert "fakeuser" not in out  # `(@x` is not a file argument


def _best_of(text, n):
    best = float("inf")
    for _ in range(n):
        r = Redactor(third_parties=True)
        t0 = time.perf_counter()
        r.redact_text(text)
        best = min(best, time.perf_counter() - t0)
    return best


# Long inputs: each unit after a few representative prefixes, as one line and as many lines.
LONG_PREFIXES = ["", "ls", "Co-authored-by: ", '{"login": "']


@pytest.mark.parametrize("unit", UNITS, ids=[repr(u) for u in UNITS])
def test_full_pass_is_linear_on_long_inputs(unit):
    with hard_timeout(120):
        for prefix in LONG_PREFIXES:
            for shape in (unit, unit + " (@x\n" + prefix):
                texts = [_line(prefix, shape, size, " (@x") for size in KB_SIZES]
                # One run of the 200 KB input keeps the suite fast; on a suspect result, measure
                # again as best of 3 (a GC pause or a busy CI box only ever adds time).
                times = [_best_of(texts[0], 3), _best_of(texts[1], 3), _best_of(texts[2], 1)]
                if not _linear(times):
                    times = [_best_of(t, 3) for t in texts]
                assert times[2] < 2.0, (prefix, shape, times)
                assert _linear(times), (prefix, shape, times)


def _linear(times):
    """5x and 25x the input: allow 25x and 100x the time (timer noise), far below quadratic."""
    t8, t40, t200 = times
    return t200 < 100 * max(t8, 0.002) and t40 < 25 * max(t8, 0.002)
