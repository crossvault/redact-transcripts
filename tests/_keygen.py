# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Random synthetic key cases for the vendor-token fuzz tests (ported from the reference scrubber's
test suite, unchanged so its recorded seeds still mean the same cases).

`draw(gen, seed)` builds one case from its own `random.Random(seed)`, so a (gen, seed) pair is the whole
case: the corpus in tests/data/keygen_leakers.json stores no key text, only seeds. Every value is random
letters and digits made at runtime; none is a real credential.
"""

from __future__ import annotations

import random
import string

AN = string.ascii_letters + string.digits
NEWER = ["sk-proj", "sk-admin", "sk-svcacct", "sk-or-v1", "AIza", "ya29", "1//", "GOCSPX", "gsk", "xai"]
CLASSIC = ["ghp", "github_pat", "sk", "xoxb", "xoxp", "sk_live", "whsec"]
GENS = [
    "glued",
    "pathseg",
    "b64tail",
    "eaten",
    "dash",
    "classicdash",
    "underscore",
    "orpath",
    "climarked",
    "zaitail",
    "embedded",
    "orsep",
]


def _shapes(R: random.Random):
    def rnd(n):
        while True:
            x = "".join(R.choice(AN) for _ in range(n))
            if any(c.isdigit() for c in x) and any(c.isupper() for c in x) and any(c.islower() for c in x):
                return x

    def b64u(n):
        b = list(rnd(n))
        for i in R.sample(range(2, n - 2), 3):
            b[i] = R.choice("-_")
        return "".join(b)

    def low(n, al):
        return "".join(R.choice(al) for _ in range(n))

    sh = {
        "ghp": lambda: ("gh" + "p_", rnd(36)),
        "github_pat": lambda: ("github" + "_pat_", rnd(22) + "_" + rnd(59)),
        "sk": lambda: ("sk" + "-", rnd(48)),
        "xoxb": lambda: ("xo" + "xb-", low(12, string.digits) + "-" + low(12, string.digits) + "-" + rnd(24)),
        "xoxp": lambda: ("xo" + "xp-", low(12, string.digits) + "-" + rnd(24)),
        "sk_live": lambda: ("sk_" + "live_", rnd(24)),
        "whsec": lambda: ("wh" + "sec_", rnd(32)),
        "zhipu": lambda: (low(32, "0123456789abcdef") + ".", rnd(16)),
        "sk-proj": lambda: ("sk-" + "proj-", b64u(120)),
        "sk-admin": lambda: ("sk-" + "admin-", b64u(80)),
        "sk-svcacct": lambda: ("sk-" + "svcacct-", b64u(100)),
        "sk-or-v1": lambda: ("sk-" + "or-v1-", low(64, "0123456789abcdef")),
        "AIza": lambda: ("AI" + "za", b64u(35)),
        "ya29": lambda: ("ya" + "29.", b64u(120)),
        "1//": lambda: ("1/" + "/", b64u(64)),
        "GOCSPX": lambda: ("GOC" + "SPX-", b64u(28)),
        "gsk": lambda: ("gs" + "k_", rnd(52)),
        "xai": lambda: ("xa" + "i-", rnd(80)),
    }
    return sh, low


def draw(gen: str, seed: int):
    """(description, text, key bodies) for one case."""
    R = random.Random(seed)
    SH, low = _shapes(R)

    def key(n):
        p, b = SH[n]()
        return p + b, b

    names = list(SH)
    if gen == "glued":
        a, b = R.choice(names), R.choice([*NEWER, "zhipu"])
        ctx = R.choice(["see {} here", '{{"t":"{}"}}', "https://h.example/a?key={}&y=1"])
        (k1, b1), (k2, b2) = key(a), key(b)
        return f"{a}+{b}|{ctx}", ctx.format(k1 + k2), [b1, b2]
    if gen == "pathseg":
        n = R.choice(NEWER)
        t = R.choice(["", "_word", "-x", "_notes_v2", "-final", "+"])
        k, b = key(n)
        return f"{n}|{t}", "https://h.example/v1/" + k + t + "/next", [b]
    if gen == "b64tail":
        n = R.choice(["AIza", "gsk", "xai", "sk-or-v1"])
        t = R.choice(["+", "=", "==", "/longer/path/to/file.txt"])
        ctx = R.choice(["see {} here", "k={}", "({}", "x\n{}"])
        k, b = key(n)
        return f"{n}|{t}|{ctx!r}", ctx.format(k + t), [b]
    if gen == "eaten":
        a = R.choice(["ghp", "sk", "sk_live", "whsec", "xoxp", "zhipu", "sk-proj", "xai"])
        c = R.choice(["ya29", "1//", "zhipu"])
        (k1, b1), (k2, b2) = key(a), key(c)
        return f"{a}+{c}", "k " + k1 + k2 + " z", [b1, b2]
    if gen == "dash":
        n = R.choice(NEWER)
        lead = R.choice(["val -", "X-Api-Key-", "token-"])
        t = R.choice(
            [
                "",
                "/x",
                "/long/path/to/some/resource.json",
                "+",
                "=",
                "==",
                "_word",
                ".",
                "-x",
                "/v2/next_page",
            ]
        )
        k, b = key(n)
        return f"{lead}{n}|{t}", lead + k + t + " end", [b]
    if gen == "classicdash":
        a, c = R.choice(CLASSIC), R.choice(["ya29", "1//"])
        t = R.choice(["", "/x", "+", "_word"])
        (k1, b1), (k2, b2) = key(a), key(c)
        return f"{a}-{c}|{t}", "k " + k1 + "-" + k2 + t + " z", [b1, b2]
    if gen == "underscore":
        n = R.choice(NEWER)
        lead = R.choice(["CONF_", "x_"])
        t = R.choice(["+", "=", "==", "/x", "/long/path/to/file.json"])
        k, b = key(n)
        return f"{lead}{n}|{t}", "see " + lead + k + t + " end", [b]
    if gen == "orpath":
        t = R.choice(["-x", "_word", "", ".", "+"])
        sec = R.choice([None, "sk-or-v1", "zhipu", "ghp", "sk", "whsec"])
        j = R.choice(["", "-", "_"])
        k1, b1 = key("sk-or-v1")
        bodies, s_ = [b1], k1
        if sec:
            k2, b2 = key(sec)
            s_ += j + k2
            bodies.append(b2)
        return f"or{j}{sec}|{t}", "GET https://api.example.com/v1/" + s_ + t + " HTTP/1.1", bodies
    if gen == "climarked":
        a, c = R.choice(["AIza", "sk-or-v1", "xai", "gsk"]), R.choice(["ghp", "github_pat"])
        j = R.choice(["-", "_"])
        ctx = R.choice(["k {} z", "https://h.example/v1/{}/x"])
        (k1, b1), (k2, b2) = key(a), key(c)
        return f"{a}{j}{c}|{ctx}", ctx.format(k1 + j + k2), [b1, b2]
    if gen == "zaitail":
        a = R.choice(["sk", "ghp", "whsec"])
        t = R.choice(["_word", "-x"])
        k1, b1 = key(a)
        part = low(16, string.ascii_lowercase + string.digits)
        z = low(32, "0123456789abcdef") + "." + part
        return f"{a}+zai(lower)|{t}", "k " + k1 + z + t + " z", [b1, part]
    if gen == "embedded":
        inner = R.choice(["sk" + "-", "gh" + "p_", "AK" + "IA", "xo" + "xb-", "wh" + "sec_"])
        a = R.choice(["1//", "ya29", "sk-proj", "xai"])
        c = R.choice(["1//", "ya29", "AIza"])
        p1, b1 = SH[a]()
        b1 = b1[:7] + "Q" + inner + b1[8 + len(inner) :]
        k2, b2 = key(c)
        return f"{a}[{inner}]+{c}", "see " + p1 + b1 + k2 + " here", [b1, b2]
    if gen == "orsep":
        k, b = key("sk-or-v1")
        return "orsep", "/v1/" + k + "".join(f"-p{i}" for i in range(20)) + "/next", [b]
    raise ValueError(gen)


def leaked(out: str, bodies) -> bool:
    """Any 8-character piece of any key body left in the output."""
    return any(b[i : i + 8] in out for b in bodies for i in range(len(b) - 7))
