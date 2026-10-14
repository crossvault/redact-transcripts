# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Vendor keys in random positions: glued, back to back, after `-`/`_`/`/`, before `_word`/`-x`/`+`/`=`,
as path segments, with a z.ai key glued on, or with another prefix's letters inside a random body.

The fixed corpus (tests/data/keygen_leakers.json) is every (generator, seed) that leaked a key body in an
earlier version of the reference rules; the seeded fuzz draws fresh cases. A case is a seed, never key
text: tests/_keygen.py rebuilds it from random letters and digits; none is a real credential.

Replay one fuzz run: REDACT_FUZZ_SEED=<seed> [REDACT_FUZZ_N=<draws per generator>].
"""

import hashlib
import json
import os
import random
from pathlib import Path

import pytest

from redact_transcripts import Redactor, redact_bytes

from . import _keygen as gen

CORPUS = json.loads((Path(__file__).parent / "data" / "keygen_leakers.json").read_text(encoding="utf-8"))
FUZZ_SEED = int(os.environ.get("REDACT_FUZZ_SEED", "9510081026"))
FUZZ_N = int(os.environ.get("REDACT_FUZZ_N", "300"))
R = Redactor()


def text(t):
    return R.redact_text(t)


def jsonl(t):
    out, _ = redact_bytes((json.dumps({"c": t}) + "\n").encode(), format="jsonl")
    return json.loads(out)["c"]


def _leaks(scrub, g, seeds):
    bad = []
    for sd in seeds:
        desc, t, bodies = gen.draw(g, sd)
        if gen.leaked(scrub(t), bodies):
            bad.append(f"{g} seed={sd} {desc}")
    return bad


@pytest.mark.parametrize("g", [g for g, v in CORPUS["seeds"].items() if v])
def test_corpus_generator_unchanged(g):
    cases = "\n".join(desc + "\t" + t for desc, t, _ in (gen.draw(g, sd) for sd in CORPUS["seeds"][g]))
    assert hashlib.sha256(cases.encode()).hexdigest()[:16] == CORPUS["case_sha256"][g]


@pytest.mark.parametrize("scrub", [text, jsonl], ids=["text", "jsonl"])
@pytest.mark.parametrize("g", [g for g, v in CORPUS["seeds"].items() if v])
def test_corpus_no_leak(scrub, g):
    bad = _leaks(scrub, g, CORPUS["seeds"][g])
    assert not bad, f"{len(bad)} leak, first: " + "; ".join(bad[:10])


@pytest.mark.parametrize("g", gen.GENS, ids=[f"{g}-seed{FUZZ_SEED}" for g in gen.GENS])
def test_seeded_fuzz(g):
    base = random.Random(f"{FUZZ_SEED}:{g}").randrange(1 << 48)
    bad = _leaks(text, g, range(base, base + FUZZ_N))
    assert not bad, f"REDACT_FUZZ_SEED={FUZZ_SEED} n={FUZZ_N}: {len(bad)} leak, first: " + "; ".join(bad[:10])
