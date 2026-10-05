# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Opt-in redaction of third parties: other people's handles and attributed names.

A transcript carries people who never agreed to be in it: a reviewer's ``@handle``, a
``Co-authored-by:`` trailer, an ``Author:`` line from ``git log``, an "On Mon, Bob wrote:" mail
quote, a ``"login": "…"`` field in pasted API output. This module finds them by **context**, not
by name recognition: a token is treated as a person only where the text itself says so (an ``@``
mention, an attribution header, a commit trailer, a login field, a profile URL).

It does not find a bare name in running prose ("I asked Alice about it"); that needs a
name-recognition model. See the README section "What it misses".

Every person is replaced by a numbered placeholder (``[PERSON-1]``, ``[PERSON-2]`` …). Numbers are
assigned in order of first appearance and stay the same for the rest of the transcript, so the
text stays readable ("@[PERSON-1] asked [PERSON-2] to rebase").

All rules work on one line at a time and use bounded patterns only, so the scan is linear in the
input size and streaming output equals whole-text output.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, FrozenSet, Iterable, List, Optional, Tuple

HANDLE = "person.handle"
NAME = "person.name"
EMAIL_LOCAL = "person.email_local"
PROFILE_URL = "person.profile_url"
KEYED_PERSON = "person.keyed_value"

#: Rule names, in the order they run on a line (``person.keyed_value`` applies to JSON fields).
RULE_NAMES: Tuple[str, ...] = (PROFILE_URL, NAME, HANDLE, EMAIL_LOCAL, KEYED_PERSON)

DEFAULT_TEMPLATE = "[PERSON-{n}]"

# `@word` that is code, docs markup, a package scope or a plain English "at": never a person.
_AT_STOP = frozenset(
    """
param params arg argument returns return type typedef property prop throws throw exception example
see deprecated since link linkcode linkplain author version license override todo fixme internal
private public protected readonly template callback default module namespace class constructor
extends implements interface enum const function member memberof method name inheritdoc ignore
fileoverview file overview jsx jsximportsource flow format summary remarks typeparam satisfies
media import keyframes font-face supports layer apply tailwind charset container page use forward
mixin include extend each if else for while content debug warn error at-root screen variants
config plugin theme utility custom-variant source reference
ts-ignore ts-expect-error ts-nocheck ts-check vite-ignore vitest-environment jest-environment
latest next beta canary alpha rc stable lts head
staticmethod classmethod dataclass abstractmethod abstractproperty cached_property cache lru_cache
wraps contextmanager asynccontextmanager pytest fixture mark parametrize patch app router
validator field_validator model_validator root_validator computed_field total_ordering
overload final unique singledispatch njit jit torch tf functools typing
test before after beforeeach aftereach beforeall afterall autowired component injectable input
output get post put delete entity column bean service controller configuration
requestmapping getmapping postmapping pathvariable requestbody responsebody restcontroller
suppresswarnings functionalinterface nullable nonnull notnull jsonproperty jsonignore data value
builder getter setter slf4j transactional repository table id generatedvalue manytoone onetomany
jvmstatic jvmfield jvmoverloads composable preview inject provides singleton hilt
objc escaping mainactor state published binding observedobject environment environmentobject
available discardableresult frozen sendable stateobject observable valid nested
here everyone channel all
echo user username host hostname domain org owner repo someone me you
seller buyer admin admins maintainer maintainers reviewer reviewers team staff mods moderators
support customer client
personal home work office school uni lunch dinner breakfast noon night midnight morning evening
afternoon today tonight tomorrow yesterday weekend weekday least most best first last once
scale runtime startup boot build deploy install login signup checkout launch release prod staging
local remote anytime any every some the a an my your our their his her its this that
click dblclick submit change keydown keyup keypress blur focus mouseenter mouseleave mouseover
scroll load touchstart wheel
server resource path filename files folder dir url uri mention mentions handle agent agents tool
types babel angular nestjs vue vitejs sveltejs remix-run tanstack trpc prisma emotion mui chakra-ui
radix-ui headlessui heroicons fortawesome storybook testing-library playwright vitest jest eslint
typescript-eslint swc rollup esbuild nx turbo changesets octokit actions aws-sdk azure google-cloud
firebase supabase vercel netlify cloudflare sentry datadog opentelemetry grpc apollo graphql-tools
anthropic-ai openai langchain huggingface modelcontextprotocol xenova mistralai
endif endforeach endfor endwhile endsection endpush endphp endauth endguest endisset endempty
endswitch endunless endverbatim foreach forelse section yield csrf auth guest isset empty
switch case break unless verbatim php props livewire vite stack push
""".split()
)

#: Accounts that are never a person: bots, CI services, AI assistants, group mentions.
DEFAULT_KEEP: FrozenSet[str] = frozenset(
    {
        "claude",
        "codex",
        "copilot",
        "gemini",
        "github",
        "github-actions",
        "dependabot",
        "renovate",
        "renovatebot",
        "codecov",
        "sonarcloud",
        "vercel",
        "netlify",
        "coderabbitai",
        "mergify",
        "imgbot",
        "allcontributors",
        "pre-commit-ci",
        "here",
        "everyone",
        "channel",
        "all",
    }
)
_BOT_SUFFIX = re.compile(r"(?:\[bot\]|[-_]bot)$")

# Names an attribution header can carry that are not third-party people.
_NAME_STOP = frozenset(
    {
        "i",
        "we",
        "you",
        "it",
        "he",
        "she",
        "they",
        "this",
        "that",
        "someone",
        "somebody",
        "everyone",
        "nobody",
        "user",
        "the user",
        "assistant",
        "the assistant",
        "model",
        "bot",
        "author",
        "reviewer",
        "maintainer",
        "the maintainer",
        "the reviewer",
        "the author",
        "me",
        "us",
        "anonymous",
        "unknown",
        "none",
        "null",
        "n/a",
        "tbd",
        "todo",
    }
)

# Role mailboxes: the local part names a function, not a person.
_ROLE_MAILBOX = re.compile(
    r"(?:no-?reply|do-?not-?reply|notifications?|mailer-daemon|postmaster|hostmaster|webmaster|abuse"
    r"|security|privacy|support|help|info|contact|hello|sales|billing|admin|root|team|git|bounces?"
    r"|noc|ops|jobs|careers|press|legal|dmarc)(?:[+._-][^@]*)?",
    re.IGNORECASE,
)

# A person reference: 1-5 Unicode word tokens ("Jürgen Fakeström", "Zoë", "山田 太郎") or a login. The
# pattern is loose (any letters); `_person_ok` decides: in a multi-token name every token that is
# not a particle must start with a non-lowercase letter, so "the docs wrote:" is not a person.
# Bounded repetition only (linear time).
_TOK = r"[^\W\d_][^\W_]{0,40}(?:['\u2019.-][^\W_]{1,40}){0,3}"
_PERSON = rf"(?:{_TOK}(?:[ \u00A0]{_TOK}){{0,4}})"
_LOGIN = r"[^\W_](?:[\w.-]{0,37}[^\W_])?(?:\[bot\])?"
_WHO = rf"(?:{_PERSON}|{_LOGIN})"
_PARTICLES = frozenset(
    "van von de der den da di do dos das du le la del della y bin ibn al el ter ten".split()
)


def _person_ok(who: str) -> bool:
    toks = who.split()
    if len(toks) <= 1:
        return True  # a single token: a login or a given name
    return all(t.lower() in _PARTICLES or not t[0].islower() for t in toks)


def normalize(identity: str) -> str:
    """Lower-cased identity with a leading ``@`` dropped and inner whitespace collapsed."""
    return " ".join(identity.strip().lstrip("@").split()).lower()


# --- patterns ----------------------------------------------------------------------------------
# `@` NOT preceded by a word char / `.` / `$` / `@` / `\` / `{` / `<` / `-`: that excludes
# user@host, pkg@1.2.3, image@sha256, $@, {@link}, HEAD@{1}, <@id>. Then a letter-bearing handle
# (at most 39 chars), not followed by what makes it code: `/x` (npm @scope/pkg; but `@a/@b` is two
# people), `(` (decorator call), `.ident` (@app.route), `{` (BibTeX), an assignment.
_AT = re.compile(
    r"(?<![\w.$@\\{<-])@(?=[\w-]{0,38}[^\W\d_])([^\W_][\w-]{0,38})"
    r"(?![\w({@-]|/(?!@)|\.[^\W\d]|[ \t]{0,8}(?:=(?!=)|\|\|=|\+=))"
)
_CAMEL = re.compile(r"[a-z]+[A-Z]")  # lowerCamelCase: an identifier, not a handle
_TIMESTAMP = re.compile(r"\d{4}-\d{2}")  # `@2026-09-30T13:35Z`: "at" a time
# A shell command that takes FILE arguments (`ls @foo`): its `@word` is a path. Deliberately not
# git/gh/echo/curl, whose arguments carry messages that can mention people.
_CODE_LINE = re.compile(
    r"^\s*(?:[$#%>]\s+)?(?:sudo\s+)?(?:ls|ll|cat|bat|cp|mv|rm|cd|find|fd|tar|zip|unzip|chmod|chown|mkdir"
    r"|rmdir|touch|less|more|head|tail|stat|du|file|open|xdg-open|code|vim|vi|nano|scp|rsync|source|ln"
    r"|wc|diff|tree)\b"
    r"|\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|VALUES|DECLARE|EXEC|SET|FROM)\b"
)
# Discord mention markup `<@123…>` / `<@!123…>`.
_DISCORD_MENTION = re.compile(r"(<@!?)(\d{15,22})(>)")

_GH_RESERVED = frozenset(
    """
about apps blog collections contact customer-stories enterprise events explore features
issues login logout marketplace new notifications orgs organizations pricing pulls readme
search security settings site sponsors topics trending users codespaces discussions
home i intent share hashtag messages compose tos privacy explore
""".split()
)
# A bare profile URL: github.com/<login>, x.com/<user> (followed by the end of the URL), and
# x.com/<user>/status/<id> (a post names its author).
_PROFILE = re.compile(
    r"(?<![\w.-])((?:https?://)?(?:www\.|mobile\.)?(?:github|gitlab|x|twitter)\.com/)"
    r"([A-Za-z0-9_-]{1,39})"
    r"(?=/?(?:[\s)\]>\"'`,;:!?]|\.(?!\w)|$)|/status(?:es)?/\d)"
)
# `/@user` profile paths on any host (Medium, Mastodon, YouTube …), bsky.app profiles, Discord
# user pages.
_AT_PATH = re.compile(
    r"(?<![\w.-])((?:https?://)?[\w-]{1,63}(?:\.[\w-]{1,63}){0,5}\.[a-z]{2,24}/@)"
    r"([^\W_](?:[\w.-]{0,37}[^\W_])?)"
)
_BSKY = re.compile(r"(?<![\w.-])((?:https?://)?bsky\.app/profile/)([\w.:-]{1,100}[\w])")
_DISCORD_USER = re.compile(
    r"(?<![\w.-])((?:https?://)?(?:ptb\.|canary\.)?discord(?:app)?\.com/users/)(\d{6,22})"
)

# Commit / patch trailers and `git log` headers: `Co-authored-by: Name <mail>`, `Author: Name`.
_TRAILER = re.compile(
    r"^([ \t>*#/;-]{0,12}(?i:co-authored-by|signed-off-by|reviewed-by|acked-by|tested-by|reported-by"
    r"|suggested-by|helped-by|approved-by|requested-by|author|committer|reviewer)"
    r"[ \t]*:[ \t]+)(" + _WHO + r")([ \t]*<[^>\n]{0,200}>)?"
    r"([ \t]+(?:#|//|--|/\*)[^\n]{0,200})?([ \t]*\r?\n?)$"
)
# `gh pr view --comments` style headers with a list of logins: `assignees:\talice, bob`.
_GH_HEADER = re.compile(
    r"^([ \t]{0,12}(?:author|reviewer|commenter|assignees?|reviewers?)[ \t]*:[ \t]*)"
    r"(" + _LOGIN + r"(?:,[ \t]*" + _LOGIN + r"){0,20})([ \t]*\r?\n?)$"
)
# API JSON, also one level backslash-escaped: `"login": "alice"`, `"author_name": "…"`.
_JSON_LOGIN = re.compile(
    r'(\\?"(?:login|username|user_name|author_name|committer_name|display_name|global_name|'
    r'author|reviewer|assignee|committer|nickname|screen_name|handle)\\?"[ \t]*:[ \t]*\\?")('
    + _WHO
    + r')(\\?")'
)
# JSON `"name": "…"` is a person next to person-shaped fields on the same line; otherwise only a
# clearly person-shaped full name is (2-4 capitalised letter-only tokens; "my-app", "Bash" stay).
_JSON_NAME = re.compile(r'(\\?"name\\?"[ \t]*:[ \t]*\\?")(' + _WHO + r')(\\?")')
_JSON_PERSON_CTX = re.compile(
    r'"(?:login|email|author|committer|user|reviewer|assignee|owner|sender|creator|username|'
    r'avatar_url|global_name)\\?"[ \t]*:'
)
_FULL_NAME = re.compile(
    r"(?:[^\W\d_a-z][^\W\d_]{0,30}(?:['\u2019-][^\W\d_]{1,30})?"
    r"(?: (?:van|von|de|der|den|da|di|du|le|la|del|y|bin|al) )?"
    r"[ ]?){2,4}\Z"
)
_NOT_NAME_WORDS = frozenset(
    """
and or of for the to with on in at by from test tests build deploy run release check checks lint job
step setup install update main default production staging service server client api app web worker
cache node python docker image upload download publish sync backup restore migrate generate config
""".split()
)
# Web UI and mail headers: "alice commented on Oct 3", "Bob Example approved these changes".
_UI_ACTION = re.compile(
    r"^([ \t>*_-]{0,12})(" + _WHO + r")([ \t]+(?:(?:commented|reviewed)(?=[ \t]+(?:on[ \t]+)?"
    r"(?:[A-Z][a-z]{2}[ \t]+\d|\d+[ \t]+\w+[ \t]+ago|yesterday|last[ \t]|now\b|this\b))|"
    r"approved these changes|requested changes|left a comment|left review comments|"
    r"requested a review|suggested changes|merged commit|merged \d+ commits?|closed this|"
    r"reopened this|opened this|mentioned this|added the \S+ label|self-assigned this)\b)"
)
# "On Tue, 29 Sep 2026, Bob <…> wrote:", "alice (Alice Example) wrote:", "Bob schrieb:".
_WROTE = re.compile(
    r"^([ \t>*_-]{0,12}(?:On [^\n]{3,80}?,[ \t]*)?)("
    + _WHO
    + r")([ \t]*)(<[^>\n]{0,200}>|\([^)\n]{0,120}\))?"
    r"([ \t]+(?:wrote|commented|replied|schrieb|kommentierte|antwortete)[ \t]*:)"
)
# German mail clients put the verb first: "Am 29.09.2026 um 14:02 schrieb Bob <…>:".
_SCHRIEB = re.compile(
    r"^([ \t>*_-]{0,12}(?:Am [^\n]{3,80}?[ \t])?schrieb[ \t]+)(" + _WHO + r")([ \t]*)"
    r"(<[^>\n]{0,200}>|\([^)\n]{0,120}\))?([ \t]*:)"
)
# The same shape as the `pii.email` rule: only addresses that survived it reach this rule.
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]{1,64})(@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24})\b"
)
_GH_NOREPLY_LOCAL = re.compile(r"\d{1,12}\+([A-Za-z0-9-]{1,39})")

#: JSON keys whose string value is a person (``person.keyed_value``).
PERSON_KEYS = frozenset(
    {
        "login",
        "username",
        "user_name",
        "author_name",
        "committer_name",
        "display_name",
        "global_name",
        "nickname",
        "screen_name",
        "handle",
        "author",
        "reviewer",
        "assignee",
        "committer",
    }
)
# A `"name"` key holds a person when the same object also has one of these keys.
_PERSON_SIBLINGS = frozenset({"login", "email", "username", "avatar_url", "html_url", "global_name"})
_WHO_FULL = re.compile(_WHO)

_UI_HINTS = (
    "commented",
    "reviewed",
    "approved",
    "requested",
    "left ",
    "suggested",
    "merged",
    "closed",
    "opened",
    "mentioned",
    "added the",
    "self-assigned",
)
_WROTE_HINTS = ("wrote", "commented", "replied", "schrieb", "kommentierte", "antwortete")


def check_template(template: str) -> None:
    """Raise ValueError unless ``template`` makes a placeholder that no person rule can match
    again (needed for idempotence): it contains ``{n}``, no ``@``, and starts with a character
    that is not a letter, digit, underscore, space or ``@``."""
    try:
        sample = template.format(n=1)
    except (KeyError, IndexError, ValueError):
        raise ValueError(f"person template {template!r}: use {{n}} for the number") from None
    if "{n}" not in template or "@" in sample or not re.match(r"[^\w\s@]", sample):
        raise ValueError(
            f"person template {template!r} must contain {{n}}, no '@', and start with a "
            "punctuation character such as '[' or '<'"
        )


class People:
    """Finds third parties in text and maps each one to a stable placeholder.

    One instance covers one transcript: :meth:`reset` starts the numbering again. ``keep`` is the
    allow-list: identities (handles, names, full e-mail addresses) that are never redacted, such
    as the transcript author's own. Matching is case-insensitive and ignores a leading ``@``. An
    e-mail address keeps only that exact address, never its local part as a handle.
    """

    def __init__(
        self,
        keep: Iterable[str] = (),
        template: str = DEFAULT_TEMPLATE,
        enabled: Iterable[str] = RULE_NAMES,
        keep_defaults: bool = True,
    ) -> None:
        check_template(template)
        self.template = template
        self.keep: FrozenSet[str] = frozenset(
            n for n in (normalize(k) for k in keep if isinstance(k, str)) if 0 < len(n) <= 200
        )
        self.keep_defaults = keep_defaults
        self.enabled: FrozenSet[str] = frozenset(enabled)
        self._ids: Dict[str, int] = {}
        self._code_line: Tuple[Optional[str], bool] = (None, False)
        rules: List[Tuple[str, "re.Pattern[str]", Callable[["re.Match[str]"], str], Tuple[str, ...]]] = [
            (PROFILE_URL, _PROFILE, self._profile, (".com/",)),
            (PROFILE_URL, _AT_PATH, self._url_handle, ("/@",)),
            (PROFILE_URL, _BSKY, self._url_handle, ("bsky.app/",)),
            (PROFILE_URL, _DISCORD_USER, self._discord_user, ("/users/",)),
            (NAME, _TRAILER, self._name_group(2, cased=False), (":",)),
            (HANDLE, _GH_HEADER, self._gh_header, (":",)),
            (HANDLE, _JSON_LOGIN, self._name_group(2, cased=False), ('"',)),
            (NAME, _JSON_NAME, self._json_name, ('"name',)),
            (NAME, _UI_ACTION, self._name_group(2), _UI_HINTS),
            (NAME, _WROTE, self._wrote, _WROTE_HINTS),
            (NAME, _SCHRIEB, self._wrote, ("schrieb",)),
            (HANDLE, _DISCORD_MENTION, self._discord_mention, ("<@",)),
            (HANDLE, _AT, self._at, ("@",)),
            (EMAIL_LOCAL, _EMAIL, self._email, ("@",)),
        ]
        self._rules = [r for r in rules if r[0] in self.enabled]

    # -- identities ------------------------------------------------------------------------------
    def reset(self) -> None:
        """Forget the placeholders handed out so far (call before a new transcript)."""
        self._ids.clear()

    def placeholder(self, identity: str) -> str:
        key = normalize(identity)
        n = self._ids.get(key)
        if n is None:
            n = self._ids[key] = len(self._ids) + 1
        return self.template.format(n=n)

    def is_kept(self, who: str, cased: bool = True) -> bool:
        """True if ``who`` is not a third party: allow-listed, a bot / group / pronoun, already a
        placeholder, or (when ``cased``, i.e. in prose rather than a field that only holds a
        person) not name-shaped."""
        n = normalize(who)
        if not n or n in self.keep or n in _NAME_STOP or not (n[0].isalnum()):
            return True
        if self.keep_defaults and (n in DEFAULT_KEEP or _BOT_SUFFIX.search(n)):
            return True
        return bool(cased and not _person_ok(who.strip()))

    # -- the scan --------------------------------------------------------------------------------
    def redact(self, text: str, counts: Optional[Dict[str, int]] = None) -> str:
        """Redact third parties in ``text``, one line at a time."""
        if not self._rules or not text:
            return text
        lines = text.split("\n")
        for i, line in enumerate(lines):
            if line:
                lines[i] = self._line(line, counts)
        return "\n".join(lines)

    def _line(self, line: str, counts: Optional[Dict[str, int]]) -> str:
        for name, pattern, replace, hints in self._rules:
            if not any(h in line for h in hints):
                continue
            hits = 0

            def counted(m: "re.Match[str]", _replace=replace) -> str:
                nonlocal hits
                out = _replace(m)
                if out != m.group(0):
                    hits += 1
                return out

            line = pattern.sub(counted, line)
            if hits and counts is not None:
                counts[name] = counts.get(name, 0) + hits
        return line

    def keyed(self, key: str, value: str, siblings: Iterable[str] = ()) -> Optional[str]:
        """The placeholder for a JSON string ``value`` stored under a person key (``"login"``,
        ``"author_name"`` …, or ``"name"`` next to a ``"login"``/``"email"`` key), else None."""
        if KEYED_PERSON not in self.enabled:
            return None
        k = key.lower()
        if k not in PERSON_KEYS and not (k == "name" and _PERSON_SIBLINGS.intersection(siblings)):
            return None
        v = value.strip()
        if not v or len(v) > 200 or not _WHO_FULL.fullmatch(v) or self.is_kept(v, cased=False):
            return None
        return self.placeholder(v)

    # -- replacers -------------------------------------------------------------------------------
    def _name_group(self, gi: int, cased: bool = True) -> Callable[["re.Match[str]"], str]:
        """Replace group ``gi`` (the person) unless kept; keep every other group."""

        def rep(m: "re.Match[str]") -> str:
            who = m.group(gi)
            if self.is_kept(who, cased):
                return m.group(0)
            return "".join(
                self.placeholder(who) if i == gi else (m.group(i) or "") for i in range(1, m.re.groups + 1)
            )

        return rep

    def _wrote(self, m: "re.Match[str]") -> str:
        """``alice (Alice Example) wrote:``: the login and a parenthetical real name both go."""
        who, paren = m.group(2), m.group(4) or ""
        if self.is_kept(who):
            return m.group(0)
        person = self.placeholder(who)
        if paren.startswith("(") and not self.is_kept(paren[1:-1], cased=False):
            paren = "(" + self.placeholder(paren[1:-1]) + ")"
        return m.group(1) + person + m.group(3) + paren + m.group(5)

    def _json_name(self, m: "re.Match[str]") -> str:
        s, who = m.string, m.group(2)
        if self.is_kept(who, cased=False):
            return m.group(0)
        window = s[max(0, m.start() - 200) : m.end() + 200]  # bounded: linear overall
        if not _JSON_PERSON_CTX.search(window) and (
            not _FULL_NAME.match(who) or any(t.lower() in _NOT_NAME_WORDS for t in who.split())
        ):
            return m.group(0)  # a package, job, tool or step name
        return m.group(1) + self.placeholder(who) + m.group(3)

    def _gh_header(self, m: "re.Match[str]") -> str:
        names = [n.strip() for n in m.group(2).split(",")]
        if all(self.is_kept(n) for n in names):
            return m.group(0)
        return (
            m.group(1) + ", ".join(n if self.is_kept(n) else self.placeholder(n) for n in names) + m.group(3)
        )

    def _profile(self, m: "re.Match[str]") -> str:
        login = m.group(2)
        if login.lower() in _GH_RESERVED or self.is_kept(login):
            return m.group(0)
        return m.group(1) + self.placeholder(login)

    def _url_handle(self, m: "re.Match[str]") -> str:
        if self.is_kept(m.group(2)):
            return m.group(0)
        return m.group(1) + self.placeholder(m.group(2))

    def _discord_user(self, m: "re.Match[str]") -> str:
        return m.group(1) + self.placeholder("discord:" + m.group(2))

    def _discord_mention(self, m: "re.Match[str]") -> str:
        return m.group(1) + self.placeholder("discord:" + m.group(2)) + m.group(3)

    def _is_code_line(self, line: str) -> bool:
        cached, value = self._code_line
        if cached is not line:
            value = bool(_CODE_LINE.search(line))
            self._code_line = (line, value)
        return value

    def _at(self, m: "re.Match[str]") -> str:
        login = m.group(1)
        if login.lower() in _AT_STOP or self.is_kept(login) or _TIMESTAMP.match(login):
            return m.group(0)
        s, start = m.string, m.start()
        first = len(s) - len(s.lstrip())
        if start == first:  # `@` opens the line
            if s.startswith("\t"):
                return m.group(0)  # a Makefile recipe line (`\t@mkdir -p out`)
            rest = s[m.end() :].strip()
            if not rest or rest.startswith(("#", "//")):
                return m.group(0)  # `@name` alone on its line: a decorator or annotation
        if s[start - 1 : start] == "`" and _CAMEL.match(login):
            return m.group(0)  # `` `@dsCard` ``: an identifier in a code span
        tail = s[max(0, start - 8) : start].rstrip()
        if tail.endswith(("<!--", "/*", "/**")):
            return m.group(0)  # `<!-- @foo -->`, `/** @foo */`
        if start - first <= 8 and s[first:start].strip() in ("*", "//", "///"):
            return m.group(0)  # a doc-comment tag line: ` * @foo`
        if tail.endswith("=") or (tail.endswith("(") and tail[-2:-1].isalnum()):
            return m.group(0)  # `x = @id`, `fn(@x)`
        if self._is_code_line(s):
            return m.group(0)  # SQL `WHERE id = @id`; shell `ls @foo` (a path)
        return "@" + self.placeholder(login)

    def _email(self, m: "re.Match[str]") -> str:
        local, domain = m.group(1), m.group(2)
        address = local + domain
        if normalize(address) in self.keep or _ROLE_MAILBOX.fullmatch(local):
            return address
        gh = _GH_NOREPLY_LOCAL.fullmatch(local)  # 12345+login@users.noreply.github.com
        who = gh.group(1) if gh else local
        if self.is_kept(who, cased=False):
            return address
        return self.placeholder(who) + domain
