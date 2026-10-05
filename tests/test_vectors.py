# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Runs every vector in vectors/*.json (the CC0 corpus) against the library."""

import base64
import json
from pathlib import Path

import pytest

from redact_transcripts import Config, Redactor, StreamRedactor, redact_bytes

VECTOR_DIR = Path(__file__).resolve().parent.parent / "vectors"
EXPECTS = {"redacted", "unchanged", "known_miss"}
MODES = {"text", "stream", "jsonl", "claude-code"}


def _load():
    out = []
    for path in sorted(VECTOR_DIR.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        for vec in doc["vectors"]:
            out.append(pytest.param(vec, id=f"{doc['category']}/{vec['id']}"))
    return out


VECTORS = _load()


# Persons in third_party.json are fictional: every name or handle contains FAKE or EXAMPLE, except
# this well-known placeholder name (the Japanese equivalent of "John Doe").
PLACEHOLDER_NAMES = {"山田 太郎"}


def _options(vec):
    return {"third_parties": False, "keep_people": (), **vec.get("options", {})}


def _redactor(vec):
    o = _options(vec)
    return Redactor(config=Config(keep_people=tuple(o["keep_people"])), third_parties=o["third_parties"])


def _run(vec):
    if vec["mode"] == "stream":
        s = StreamRedactor(_redactor(vec))
        out = "".join(s.feed(c) for c in vec["chunks"]) + s.close()
        return "".join(vec["chunks"]), out, s.report.rules
    raw = vec["input"].encode("utf-8")
    out, report = redact_bytes(raw, format=vec["mode"], **_options(vec))
    return vec["input"], out.decode("utf-8"), report.rules


def test_corpus_is_not_empty():
    assert len(VECTORS) >= 50


@pytest.mark.parametrize("vec", VECTORS)
def test_vector(vec):
    assert vec["expect"] in EXPECTS and vec["mode"] in MODES and vec["description"]
    original, out, rules = _run(vec)
    if vec["expect"] == "redacted":
        assert out != original
        for rule in vec.get("rules", []):
            assert rule in rules, (rule, rules)
        for needle in vec.get("absent", []):
            assert needle not in out
        if "output" in vec:
            assert out == vec["output"]
        # running again changes nothing
        _, again, again_rules = _run({**vec, "input": out, "chunks": [out]})
        assert again == out and not again_rules
    else:  # unchanged, and documented known misses
        assert out == original
        assert not rules


@pytest.mark.parametrize("vec", [v for v in VECTORS if v.values[0]["mode"] in ("text", "stream")])
def test_stream_equals_whole_text_for_every_split_point(vec):
    text = "".join(vec["chunks"]) if vec["mode"] == "stream" else vec["input"]
    whole = _redactor(vec).redact_text(text)
    for cut in range(len(text) + 1):
        s = StreamRedactor(_redactor(vec))
        got = s.feed(text[:cut]) + s.feed(text[cut:]) + s.close()
        assert got == whole, cut


@pytest.mark.parametrize("vec", VECTORS)
def test_secret_vectors_are_obviously_synthetic(vec):
    """Every secret in the corpus carries a FAKE/EXAMPLE marker, directly or once decoded."""
    if vec["expect"] != "redacted" or not any(r.startswith("secret.") for r in vec.get("rules", [])):
        return
    if "decodes_to" in vec:
        assert any(m in vec["decodes_to"] for m in ("FAKE", "EXAMPLE"))
        for needle in vec["absent"]:
            assert vec["decodes_to"] in base64.b64decode(needle).decode()
        return
    for needle in vec["absent"]:
        # an all-digit needle cannot be a credential on its own (numeric-password vectors)
        assert "FAKE" in needle or "EXAMPLE" in needle or "NOTAREALKEY" in needle or needle.isdigit(), needle


@pytest.mark.parametrize("vec", VECTORS)
def test_person_vectors_are_obviously_fictional(vec):
    """Every person a third-party vector redacts is marked fake (or is a placeholder name)."""
    if not any(r.startswith("person.") for r in vec.get("rules", [])):
        return
    for needle in vec["absent"]:
        low = needle.lower()
        assert "fake" in low or "example" in low or needle in PLACEHOLDER_NAMES or needle.isdigit(), needle
