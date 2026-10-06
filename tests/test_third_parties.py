# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""The opt-in third-party pass (``person.*`` rules). Every name and handle here is fictional."""

import io
import json
import sys
import time

import pytest

from redact_transcripts import Config, People, Redactor, StreamRedactor, redact_bytes, redact_text
from redact_transcripts.cli import main

AUTHOR = ("ada-fakeauthor", "Ada Fakeauthor", "ada@fakeauthor.example")


def tp(text, keep=()):
    return Redactor(config=Config(keep_people=tuple(keep)), third_parties=True).redact_text(text)


# --- opt-in ---------------------------------------------------------------------------------


def test_off_by_default():
    text = "thanks @fake-mira\nCo-authored-by: Dora Fakename\n"
    assert redact_text(text) == text
    assert "person.handle" not in Redactor().rule_names


def test_on_lists_its_rules():
    names = Redactor(third_parties=True).rule_names
    assert {"person.handle", "person.name", "person.email_local", "person.profile_url"} <= set(names)


# --- placeholders ---------------------------------------------------------------------------


def test_placeholders_are_stable_within_a_transcript():
    out = tp("@fake-a asked @fake-b\n@fake-b replied to @fake-a\n")
    assert out == "@[PERSON-1] asked @[PERSON-2]\n@[PERSON-2] replied to @[PERSON-1]\n"


def test_numbering_restarts_per_transcript():
    r = Redactor(third_parties=True)
    a, _ = redact_bytes(b"cc @fake-x\n", format="text", redactor=r)
    b, _ = redact_bytes(b"cc @fake-y\n", format="text", redactor=r)
    assert a == b == b"cc @[PERSON-1]\n"


def test_handle_case_and_email_local_part_share_a_number():
    assert tp("@Fake-Mira and @fake-mira, fake-mira@example.org") == (
        "@[PERSON-1] and @[PERSON-1], [PERSON-1]@example.org"
    )


def test_custom_template():
    r = Redactor(config=Config(person_template="<person {n}>"), third_parties=True)
    assert r.redact_text("thanks @fake-mira") == "thanks @<person 1>"


@pytest.mark.parametrize("bad", ["PERSON-{n}", "[PERSON]", "[{n}@x]", "{0}", " {n}"])
def test_template_that_could_match_again_is_rejected(bad):
    with pytest.raises(ValueError):
        Redactor(config=Config(person_template=bad), third_parties=True)


# --- allow-lists ----------------------------------------------------------------------------


def test_author_identity_is_kept():
    text = "Signed-off-by: Ada Fakeauthor\ncc @ada-fakeauthor, see github.com/ada-fakeauthor"
    assert tp(text, AUTHOR) == text


def test_keep_is_exact_and_case_insensitive():
    assert tp("thanks @ADA-FAKEAUTHOR", AUTHOR) == "thanks @ADA-FAKEAUTHOR"
    assert tp("thanks @ada-fakeauthor2", AUTHOR) == "thanks @[PERSON-1]"


def test_email_keeps_only_the_full_address_not_its_local_part():
    """Anyone can register fake-victim@attacker.example; that must not exempt @fake-victim."""
    out = tp("cc @fake-victim", ["fake-victim@attacker.example"])
    assert out == "cc @[PERSON-1]"


def test_bots_and_groups_are_kept():
    text = "@dependabot rebase\nrenovate[bot] commented on Oct 3\n@here ship it\nCo-authored-by: Claude"
    assert tp(text) == text


def test_extra_bot_via_keep_people():
    assert tp("@fake-ci-runner retry", ["fake-ci-runner"]) == "@fake-ci-runner retry"


def test_without_keep_the_author_is_redacted_too():
    assert tp("cc @ada-fakeauthor") == "cc @[PERSON-1]"


# --- disable --------------------------------------------------------------------------------


def test_disable_one_person_rule():
    r = Redactor(third_parties=True, disable=["person.email_local"])
    assert r.redact_text("@fake-a, fake-a@example.org") == "@[PERSON-1], fake-a@example.org"
    assert "person.email_local" not in r.rule_names


# --- idempotence, streaming, JSON -----------------------------------------------------------

SAMPLE = (
    "Co-authored-by: Dora Fakename <dora@corp.example>\n"
    "author:\tfake-mk\n"
    'json: {"login": "fake-hs", "name": "Hiro Fakesato"}\n'
    "Elena Fakepetrova approved these changes\n"
    "fakealice (Alice Fakesmith) wrote:\n"
    "> please split it\n"
    "thanks @fake-mk, ping fake-mk@example.com and https://github.com/fake-rg\n"
    "<@481516234281234567> see x.com/fake_ab/status/1 and medium.com/@fake.w\n"
    "@dataclass\nclass X: ...\n"
)


def test_idempotent():
    once = tp(SAMPLE)
    assert once != SAMPLE
    assert tp(once) == once
    r = Redactor(third_parties=True)  # the same redactor (numbering carried over) too
    first = r.redact_text(SAMPLE)
    assert r.redact_text(first) == first


@pytest.mark.parametrize(
    "text",
    [
        "ssh fake-user@fakehost.example.com",
        "mail fake.user@sub.example.org and fake-b@example.com",
        "[PERSON-1]@fakehost.example.com",
        "[PERSON-12]@fake.example.net!",
        "x [PERSON-3]@[PERSON-4] y",
        "<@[PERSON-2]> and @[PERSON-5]",
        "github.com/[PERSON-6] and medium.com/@[PERSON-7]",
    ],
)
@pytest.mark.parametrize("template", ["[PERSON-{n}]", "<person {n}>", "{{p{n}}}", "(P{n})"])
def test_idempotent_on_placeholder_forms(text, template):
    def scrub(x):
        return Redactor(config=Config(person_template=template), third_parties=True).redact_text(x)

    once = scrub(text)
    assert scrub(once) == once, (once, scrub(once))


def test_idempotent_on_jsonl():
    raw = (
        json.dumps({"login": "fake-a", "msg": "thanks @fake-b", "name": "X", "email": "x@corp.example"})
        + "\n"
    ).encode()
    once, _ = redact_bytes(raw, format="jsonl", third_parties=True)
    twice, report = redact_bytes(once, format="jsonl", third_parties=True)
    assert twice == once and not report.rules


def test_stream_equals_whole_text_including_numbers():
    whole = tp(SAMPLE)
    for size in (1, 3, 7, 64):
        s = StreamRedactor(Redactor(third_parties=True))
        out = "".join(s.feed(SAMPLE[i : i + size]) for i in range(0, len(SAMPLE), size)) + s.close()
        assert out == whole, size


def test_claude_code_transcript_keeps_structure():
    rec = {
        "type": "user",
        "sessionId": "00000000-0000-4000-8000-000000000001",
        "uuid": "00000000-0000-4000-8000-000000000002",
        "parentUuid": None,
        "message": {"role": "user", "content": "Reviewed-by: Kofi Fakemensah\nthanks @fake-mk"},
    }
    out, report = redact_bytes((json.dumps(rec) + "\n").encode(), format="claude-code", third_parties=True)
    got = json.loads(out)
    assert got["uuid"] == rec["uuid"] and got["sessionId"] == rec["sessionId"]
    assert got["message"]["content"] == "Reviewed-by: [PERSON-1]\nthanks @[PERSON-2]"
    assert report.rules == {"person.name": 1, "person.handle": 1}


def test_keyed_name_needs_a_person_sibling():
    raw = b'{"name": "Fake Committer", "email": "fc@corp.example"}\n{"name": "Build And Test"}\n'
    out, _ = redact_bytes(raw, format="jsonl", third_parties=True)
    lines = out.decode().splitlines()
    assert json.loads(lines[0])["name"] == "[PERSON-1]"
    assert json.loads(lines[1])["name"] == "Build And Test"


def test_reports_carry_counts_not_names():
    _, report = redact_bytes(b"thanks @fake-mira and @fake-bo\n", format="text", third_parties=True)
    assert report.rules == {"person.handle": 2}
    assert "fake" not in json.dumps(report.as_dict())


def test_people_class_directly():
    p = People(keep=["fake-me"])
    assert p.redact("@fake-me thanks @fake-you") == "@fake-me thanks @[PERSON-1]"
    p.reset()
    assert p.placeholder("someone-fake") == "[PERSON-1]"


# --- prose that merely contains code words (review of 0.2.0) -------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "UPDATE: thanks @fakeuser for the fix",
        "DELETE this later, thanks @fakeuser",
        "Thanks @fakeuser, SET as default",
        "FROM the thread, @fakeuser said",
        "SELECT the best option, as @fakeuser said FROM experience",
        "more context from @fakeuser below",
        "code review by @fakeuser",
        "open question for @fakeuser",
        "file a bug and ping @fakeuser",
        "find @fakeuser on chat",
        "rm the stale branch, thanks @fakeuser",
        "thanks @fake.user!",
        "hi @fakeuser.bsky.social",
    ],
)
def test_mentions_on_prose_lines_with_code_words(line):
    out = tp(line)
    assert "fakeuser" not in out and "fake.user" not in out, out


@pytest.mark.parametrize(
    "line",
    [
        "SELECT * FROM t WHERE id = @id AND s = @status",
        "UPDATE t SET a = @a WHERE id = @id",
        "INSERT INTO t (a, b) VALUES (@a, @b);",
        "DELETE FROM t WHERE owner IN (@owner)",
        "DECLARE @total INT",
        "EXEC dbo.report @year = 2026",
        "ls @foo",
        "ls -la @foo",
        "$ cat -n @rules.txt | wc -l",
        "$ more @notes.txt",
        "cp a/b.txt @dest",
        "Use the @login_required decorator",
        "add `@shared_task` and `@SpringBootApplication`",
        "the @fakescope scope",
        "use @app.route to register",
        "@implementation FakeView",
        "@cursor please fix, @devin too",
        "Python wrote: Traceback",
    ],
)
def test_code_and_tools_stay(line):
    assert tp(line) == line


# --- terminal padding and wide spacing (re-review 2 of 0.2.0) -----------------------------

SP, TABS = " " * 120, "\t" * 9


@pytest.mark.parametrize(
    "line, gone",
    [
        ("Author: Fake Person" + SP, "Fake Person"),
        ("Author: Fake Person <fp@corp.example>" + SP, "Fake Person"),
        ("Author: Fake Person" + "\t" * 50 + "\r", "Fake Person"),
        ("Author:" + " " * 12 + "Fake Person", "Fake Person"),
        ("Co-authored-by:" + TABS + "Fake Person <fp@corp.example>", "Fake Person"),
        ("Signed-off-by: Fake Person" + " " * 20 + "<fp@corp.example>" + SP, "Fake Person"),
        ("assignees:" + " " * 12 + "fakeuser", "fakeuser"),
        ("assignees: fake-one," + " " * 12 + "fake-two" + SP, "fake-two"),
        ('"login":' + " " * 12 + '"fakeuser"', "fakeuser"),
        ('"login"' + " " * 12 + ':"fakeuser"', "fakeuser"),
        ('{"login": "fake-hs",' + " " * 12 + '"name":' + " " * 12 + '"Hiro Fakesato"}', "Fakesato"),
        ("fakeuser commented" + " " * 12 + "on Oct 3", "fakeuser"),
        ("fakeuser commented 12345 days ago", "fakeuser"),
        ("Fake Person approved these changes" + SP, "Fake Person"),
        ("On Tue, 29 Sep 2026," + " " * 12 + "Fake Person wrote:", "Fake Person"),
        ("Fake Person" + " " * 12 + "wrote:" + SP, "Fake Person"),
        ("Am 29.09.2026 schrieb" + " " * 12 + "Fake Person:", "Fake Person"),
        ("thanks @fakeuser" + SP, "fakeuser"),
    ],
)
def test_padding_and_wide_spacing(line, gone):
    out = tp(line)
    assert gone not in out, out
    # the padding itself is kept byte for byte
    assert out.endswith(line[len(line.rstrip(" \t\r")) :])


def test_padding_kept_in_stream_and_whole_text():
    text = "Author: Fake Person" + SP + "\nthanks @fakeuser" + TABS + "\n"
    whole = tp(text)
    assert whole == "Author: [PERSON-1]" + SP + "\nthanks @[PERSON-2]" + TABS + "\n"
    s = StreamRedactor(Redactor(third_parties=True))
    assert "".join(s.feed(c) for c in text) + s.close() == whole


# --- command line ---------------------------------------------------------------------------


class _Std:
    def __init__(self, data=b""):
        self.buffer = io.BytesIO(data)

    def write(self, text):
        self.buffer.write(text.encode())


def _cli(monkeypatch, argv, stdin=b""):
    out, err = _Std(), io.StringIO()
    monkeypatch.setattr(sys, "stdin", _Std(stdin))
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    code = main(argv)
    return code, out.buffer.getvalue(), err.getvalue()


def test_cli_flag(monkeypatch):
    stdin = b"Co-authored-by: Dora Fakename\ncc @fake-mira @ada-fakeauthor\n"
    code, out, err = _cli(monkeypatch, ["-", "--third-parties", "--keep-person", "ada-fakeauthor"], stdin)
    assert code == 0 and err == ""
    assert out == b"Co-authored-by: [PERSON-1]\ncc @[PERSON-2] @ada-fakeauthor\n"


def test_cli_without_flag_is_unchanged(monkeypatch):
    stdin = b"cc @fake-mira\n"
    assert _cli(monkeypatch, ["-"], stdin)[1] == stdin


def test_cli_keep_person_needs_the_flag(monkeypatch):
    with pytest.raises(SystemExit) as e:
        _cli(monkeypatch, ["-", "--keep-person", "x"])
    assert e.value.code == 2


def test_cli_list_and_disable_person_rules(monkeypatch):
    code, out, _ = _cli(monkeypatch, ["--list-rules", "--third-parties", "-"])
    assert code == 0 and b"person.handle" in out
    code, out, _ = _cli(monkeypatch, ["--list-rules", "-"])
    assert code == 0 and b"person." not in out
    code, out, _ = _cli(
        monkeypatch, ["-", "--third-parties", "--disable", "person.handle"], b"cc @fake-mira\n"
    )
    assert code == 0 and out == b"cc @fake-mira\n"
    assert _cli(monkeypatch, ["-", "--disable", "person.handle"], b"x\n")[0] == 2


# --- linear time ----------------------------------------------------------------------------
# Adversarial lines for every person rule, at 8, 40 and 200 KB. A quadratic rule would take
# 625x longer at 200 KB than at 8 KB; a linear one about 25x.

ADVERSARIAL = {
    "mentions": "hi @fake-alice ",
    "mention-per-line": "@fake-alice says hi\n",
    "at-run": "@",
    "at-letters": "@a",
    "digit-handle": "@" + "1" * 50 + " ",
    "decorator-lines": "@deco\n" + "x" * 500 + "\n",
    "trailer-long": "Co-authored-by: " + "A" * 60 + " ",
    "trailer-lines": "Co-authored-by: Fake Person <f@example.com>\n",
    "on-wrote": "On " + "x," * 40 + " ",
    "wrote-lines": "On Mon, 1 Jan, Fake Person <f@x.example> wrote:\n",
    "gh-header": "author:\tfake-x\n--\n",
    "assignees": "assignees: " + "fake-a, " * 30,
    "json-login": '{"login":"fake-a","name":"Fake B"}',
    "json-name-open": '"name": "',
    "name-tokens": "Ab " * 30 + "\n",
    "capitalised-run": "Ab ",
    "profile": "x.com/" + "a" * 40 + " ",
    "github-run": "github.com/",
    "at-path": "a.b/@",
    "dotted-host": "a.",
    "email-run": "a@b.",
    "email-local-run": "fake." * 20 + "@example.com ",
    "discord": "<@" + "1" * 30,
    "commented": "fake commented on ",
    "sql-select-run": "SELECT ",
    "sql-mentions": "SELECT a FROM t WHERE x = @fake AND y = @fake ",
    "sql-keyword-prose": "UPDATE: thanks @fake-user ",
    "shell-paths": "ls a/b ",
    "shell-path-mentions": "ls a.b @fake ",
    "shell-prompt-flags": "$ more -n ",
    "dotted-handles": "hi @fake.user.name.x ",
    "dotted-decorator-calls": "x @app.route.get.post(",
    "code-noun": "@fake-x decorator ",
    "shell-args-dash-slash": "ls" + " -/" * 99 + " (@x\n",
    "shell-args-dash-dot": "ls" + " -." * 99 + " (@x\n",
    "shell-args-one-line": " -/",
    "padded-trailer-lines": "Author: Fake Person" + " " * 150 + "\n",
    "padded-trailer-one-line": "Author: Fake Person ",
    "wide-header": "Co-authored-by:" + " " * 199 + "Fake Person" + " " * 199 + "<f@x.example>\n",
    "wide-wrote": "On a," + " " * 199 + "Fake Person" + " " * 199 + "wrote:\n",
    "wide-wrote-fail": "On a," + " " * 199 + "Fake Person" + " " * 199 + "x\n",
    "wide-json": '"login":' + " " * 199 + ":" + " " * 199,
    "wide-commented": "fakeuser commented" + " " * 199 + "on ",
    "space-run": " " * 64,
    "tab-run": "\t",
}
SIZES = (8_000, 40_000, 200_000)
LIMIT = 2.0  # seconds at 200 KB; a linear pass takes a small fraction of that


def _best_of(text, n=3):
    best = float("inf")
    for _ in range(n):
        r = Redactor(third_parties=True)
        t0 = time.perf_counter()
        r.redact_text(text)
        best = min(best, time.perf_counter() - t0)
    return best


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_adversarial_input_is_linear(name):
    unit = ADVERSARIAL[name]
    times = [_best_of(unit * (size // len(unit) + 1)) for size in SIZES]
    t8, t40, t200 = times
    assert t200 < LIMIT, (name, times)
    # 25x the input: allow 100x the time (timer noise on small inputs), far below quadratic.
    assert t200 < 100 * max(t8, 0.002), (name, times)
    assert t40 < 25 * max(t8, 0.002), (name, times)
