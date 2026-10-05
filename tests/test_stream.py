# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
import random

import pytest

from redact_transcripts import Redactor, StreamRedactor

PEM = "-----BEGIN PRIVATE KEY-----\nFAKEEXAMPLE\nNOTAREALKEY\n-----END PRIVATE KEY-----"
DOC = (
    f"a ghp_FAKEEXAMPLE000000000000000000000000 b\nx {PEM} y\nAuthorization: Bearer FAKE-EXAMPLE-0000\n"
    "two -----BEGIN EC PRIVATE KEY-----\nFAKE\n-----END EC PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----\n"
    "NOTAREALKEY\n-----END PRIVATE KEY----- tail 203.0.113.8\n"
)


@pytest.mark.parametrize("seed", range(25))
def test_random_chunking_matches_whole_text(seed):
    rng = random.Random(seed)
    whole = Redactor().redact_text(DOC)
    s = StreamRedactor()
    out, i = [], 0
    while i < len(DOC):
        n = rng.randint(1, 9)
        out.append(s.feed(DOC[i : i + n]))
        i += n
    out.append(s.close())
    assert "".join(out) == whole
    assert "NOTAREALKEY" not in whole and "FAKEEXAMPLE0000" not in whole


def test_output_is_released_per_line():
    s = StreamRedactor()
    assert s.feed("first line\nsecond") == "first line\n"
    assert s.feed(" part\n") == "second part\n"


def test_key_block_is_held_until_end():
    s = StreamRedactor()
    assert s.feed("-----BEGIN PRIVATE KEY-----\nAAAA\n") == ""
    assert s.feed("-----END PRIVATE KEY-----\n") == "[REDACTED:secret.private_key]\n"


def test_oversized_key_block_is_cut_and_swallowed():
    s = StreamRedactor(max_buffer=64)
    out = s.feed("-----BEGIN PRIVATE KEY-----\n")
    for _ in range(20):
        out += s.feed("NOTAREALKEYNOTAREALKEY\n")
    out += s.feed("-----END PRIVATE KEY----- after\nnext\n") + s.close()
    assert "NOTAREALKEY" not in out
    assert out.endswith(" after\nnext\n")


def test_feed_after_close():
    s = StreamRedactor()
    s.close()
    with pytest.raises(ValueError):
        s.feed("x")
