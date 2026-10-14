<!--
SPDX-FileCopyrightText: 2026 crossVault GmbH
SPDX-License-Identifier: Apache-2.0
-->

# redact-transcripts

[Repository](https://github.com/crossvault/redact-transcripts) · [Issues](https://github.com/crossvault/redact-transcripts/issues)

Redact secrets and personal data from AI-agent transcripts, JSONL logs and plain text, **without
breaking the file's structure**. A redacted Claude Code session still parses, keeps its ids and
parent links, and can be shared or archived. (Paths such as `cwd` do lose the user name, see `pii.home_dir`.)

- **Stdlib only**, Python 3.9+. No dependencies, no network.
- **Structure-aware.** JSONL is parsed and redacted *after* decoding, so JSON escaping cannot hide
  a secret, and the output is always valid JSON. Lines with nothing to redact keep their exact bytes.
- **Pluggable formats.** Built in: `claude-code`, `jsonl`, `text`. Add your own in a few lines.
- **Streams.** Redact a log tail or a streamed response chunk by chunk; a secret cut in half by a
  chunk boundary is still caught.
- **Reports never contain secrets**, only rule names, counts and line numbers.
- **Third parties, opt-in.** `--third-parties` replaces other people's `@handles` and attributed
  names (commit trailers, `Author:` lines, "X wrote:", login fields) with stable placeholders such
  as `[PERSON-1]`.
- **A public test corpus** (`vectors/`, CC0) of synthetic secret shapes, tricky encodings and
  near-misses that must *not* be redacted. Reuse it to test your own scanner.

> **This is a regex backstop, not a guarantee.** It catches common credential shapes. It does not
> understand meaning. See [What it misses](#what-it-misses) before you rely on it.

## Quickstart (5 minutes)

```console
$ pip install redact-transcripts
```

<!-- readme-test -->
```console
$ redact-transcripts --version
redact-transcripts 0.2.0
```

The examples below run from a checkout of this repository, and the test suite checks them
(`tests/test_readme.py`). Redact a file to stdout, or to a new file with `-o`:

<!-- readme-test -->
```console
$ redact-transcripts examples/session.jsonl -o session.redacted.jsonl --report
redact-transcripts: format=claude-code lines=4 changed=4 redacted=9
  infra.ipv4              2
  pii.email               1
  pii.home_dir            4
  secret.github_token     1
  secret.url_credentials  1
```

For your own sessions, point it at `~/.claude/projects/<project-dir>/<session-id>.jsonl`.
Use it in a pipe (`-` reads stdin):

<!-- readme-test -->
```console
$ echo 'curl -H "Authorization: Bearer FAKE-EXAMPLE-0000-token" https://api.example.com' | redact-transcripts -
curl -H "Authorization: Bearer [REDACTED:secret.auth_header]" https://api.example.com
```

Gate a commit or a CI job on it. `--check` writes nothing and exits 1 if a `secret.*` rule
matches (`--strict` also fails on `pii.*` and `infra.*`):

<!-- readme-test -->
```console
$ redact-transcripts --check examples/session.jsonl || echo "secrets found"
redact-transcripts: format=claude-code lines=4 changed=4 would redact=9
  infra.ipv4              2
  pii.email               1
  pii.home_dir            4
  secret.github_token     1
  secret.url_credentials  1
secrets found
```

### A real example

[`examples/session.jsonl`](examples/session.jsonl) is a short, synthetic Claude Code session in
which the agent ran `env` and printed a token and a database URL. One of its lines:

```json
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01EXAMPLE","content":"GITHUB_TOKEN=ghp_FAKEEXAMPLE000000000000000000000000\nDATABASE_URL=postgres://app:FAKE-PASSWORD@203.0.113.10:5432/shop"}]}, "uuid":"…0003","parentUuid":"…0002", …}
```

After `redact-transcripts examples/session.jsonl`:

```json
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01EXAMPLE","content":"GITHUB_TOKEN=[REDACTED:secret.github_token]\nDATABASE_URL=postgres://[REDACTED:secret.url_credentials]@[REDACTED:infra.ipv4]:5432/shop"}]}, "uuid":"…0003","parentUuid":"…0002", …}
```

`uuid`, `parentUuid`, `sessionId`, `tool_use_id` and `timestamp` are untouched, so the
conversation tree is intact. A structural field is kept only when its value has the expected
shape (a UUID, an identifier, a timestamp) **and** no secret rule matches it, so a token stored
under a key like `id` or `model` anywhere in a tool's input is still redacted.

### Python API

```python
from redact_transcripts import Redactor, StreamRedactor, redact_bytes, redact_text

redact_text("export DB_PASSWORD=FAKE-hunter2")
# 'export DB_PASSWORD=[REDACTED:secret.assignment]'

with open("session.jsonl", "rb") as f:
    out, report = redact_bytes(f.read(), format="claude-code")  # or "auto", "jsonl", "text"
print(report.as_dict()["rules"])  # counts per rule, no values

stream = StreamRedactor()  # e.g. for a streamed model response
for chunk in chunks:
    send(stream.feed(chunk))  # released line by line
send(stream.close())
```

## Third parties (opt-in, since 0.2.0)

A transcript also carries people who never agreed to be in it: a reviewer's `@handle`, a
`Co-authored-by:` trailer, an `Author:` line from `git log`, a mail quote header, a `"login"` field
in pasted API output. `--third-parties` (Python: `Redactor(third_parties=True)`) replaces each of
them with a numbered placeholder. A person keeps the same number for the whole transcript, so the
text stays readable:

<!-- readme-test -->
```console
$ printf 'Co-authored-by: Dora Fakename <dora@corp.example>\nthanks @fake-mira, cc @my-own-handle\n' | redact-transcripts - --third-parties --keep-person my-own-handle
Co-authored-by: [PERSON-1] <[REDACTED:pii.email]>
thanks @[PERSON-2], cc @my-own-handle
```

It works by **context, not by name recognition**: a word is treated as a person only where the text
itself says so.

The rules are the a4sx transcript scrubber's, in its order and with its false-positive guards
(`tests/test_parity.py` pins that), plus a few of this package's own (marked *own*). Each string runs
through them twice, as the reference does on its two paths: once as decoded text, and once as it is
written inside a JSONL line ("CLI mode": the reference client's raw-JSONL rules and its own key rules, where
a JSON escape such as a literal `\n` before `--password X` is a boundary). Everything either pass finds is
redacted; `--disable cli_mode` turns the second pass off. A scheduled CI job
(`.github/workflows/reference-drift.yml`, weekly and before every release) checks the parity fixtures
against the published reference client and fails when the reference has changed.

| Rule | Catches |
|---|---|
| `secret.private_key` | PEM `-----BEGIN … PRIVATE KEY-----` blocks (any label, PGP too; the block's line breaks are kept): a plain block, one behind line prefixes (`cat -n`, the Read tool's `1→`, `> `, `# `, `│ `), a key in one string with escaped `\n`, a key written as quoted string concatenation (Python `"…\n" "…\n"`, JS and Go `"…\n" +`, one line or many), a key printed as a quoted list of its lines, and in the JSONL formats a key split over several strings or records; a lone BEGIN marker is redacted too. Not: a key in a template literal or heredoc whose lines carry other characters |
| `secret.anthropic_key`, `secret.openrouter_key`, `secret.openai_key`, `secret.github_token`, `secret.slack_token`, `secret.aws_key_id`, `secret.google_api_key`, `secret.google_oauth_token`, `secret.google_oauth_client_secret`, `secret.groq_key`, `secret.xai_key`, `secret.stripe_key`, `secret.stripe_webhook_secret`, `secret.zai_key` | vendor token shapes, also right after `_`, `-`, `/`, a URL escape (`%20`) or a literal `\n`, glued onto text (exact shape), written back to back, and followed by `_<word>`, `-x`, a path or `+`/`=`; an identifier-shaped run (`slack_xoxb-tokens-and-scopes-guide`, `id-xai-GrokModelConfigLoader`) is kept, and nothing inside base64 or a `data:` URI is rewritten |
| `secret.token_tail` | the rest of a key glued onto a key that was just redacted (`<key><key>`) |
| `secret.prefixed_api_token`, `secret.a4sx_session` | a4sx platform tokens: bare-prefix API tokens (`tok_…`, `pol_…`, `pt_…`, `emit_…`, also glued to an upper-case name, `FOO_tok_…`), `ge_tok_…`/`ge_emit_…`-style tokens, and `ge_sess_…` session tokens |
| `secret.gitlab_token` (*own*) | `glpat-…` |
| `secret.jwt` | a bare JWT (or 5-part JWE) whose header decodes to a JOSE header naming `alg`; runs last |
| `secret.auth_header` | `Authorization:` / `Proxy-Authorization:` with any scheme (`Bearer`, `Basic`, `token`, `Digest` …) or none, the value also on the next line |
| `secret.bearer`, `secret.basic_auth` (*own*) | a bare `Bearer …` / `Basic …` credential (the scheme is kept) |
| `secret.url_credentials`, `secret.url_token` (*own*) | `scheme://user:password@host`, and `scheme://<token>@host` (a 16+ character token as the whole userinfo, git remotes) |
| `secret.digest` | HTTP Digest `response=` and `cnonce=` |
| `secret.aws_signature` | AWS SigV4 `Signature=` / `X-Amz-Signature=` (presigned URLs), SigV2 `Signature=`, `X-Amz-Security-Token=` |
| `secret.quoted_assignment` | a quoted value under a secret-named key that holds spaces, quotes or line breaks, or is triple-quoted (`password = "two word phrase"`) |
| `secret.json_assignment` | JSON or a Python dict inside text: `{"api_key": "…"}`, `'password': '…'`, `{\"pin\": 4821}` |
| `secret.nested_assignment` | a secret-named key whose value sits in escaped quotes at any depth (`PASSWORD = \"…\"`, `{\\\"token\\\": \\\"…\\\"}`) |
| `secret.assignment` | `password=…`, `api_key: …`, `export X_TOKEN=…`, `SECRET_KEY=…` (a glued prefix such as `MY_` stays) |
| `secret.weakpass` | a short or special-character password (`password=123qwe@`) |
| `secret.user_percent_pass` | `-U user%password` (smbclient style) |
| `secret.cli_flag` | `--password X`, `--db-password=X`, `--pass X`, `--pwd X` (not `--password flag`, `$VAR`, a path) |
| `secret.cli_token_flag` (*own*) | `--token X`, `--api-key=X`, `--secret X` |
| `secret.cmd_userpass` | `curl -u user:password`, `--user user:password` (a numeric `uid:gid` and `docker run -u node:node` are kept) |
| `secret.pass_assignment` | `db_pass=…`, `DB_PASS=…`, `pwd=…` (not `pwd=/home/x`, a working directory) |
| `secret.mysql_password` | `mysql -u root -pPASSWORD`, `mysqldump -p'…'`, `mariadb -p…` |
| `secret.pin` (*own*) | `pin: 4711`, `userPin=4321`, `passcode: 887766` (whole key words, so `mapping: 1234` is kept) |
| `secret.base64_encoded` (*own*) | a base64 blob whose decoded text contains one of the secrets above (one level) |
| `secret.gsheet` | Google Sheet / Doc ids (`spreadsheets/d/<id>`, `sheet_id: <id>`) |
| `secret.escaped` | any of the secrets above spelled with JSON escapes inside a string that is itself JSON (`\u0067hp_…`, `1\/\/…`), up to 5 levels deep |
| `secret.keyed_value` | JSON formats: every value under a key that names a secret (`{"GITHUB_TOKEN": "…"}`, `{"credentials": {"v": "…"}}`, `{"token": ["…"]}`); a number only under a password, secret or PIN key; env-var names and placeholders are kept |
| `secret.deep_nesting` | JSONL formats: a line nested more than 600 deep is not decoded; every string in it is replaced |
| `infra.mac` | MAC addresses |
| `infra.ipv6` | IPv6 addresses (not `file.py:26:`-style colon runs) |
| `infra.ipv4` | IPv4 addresses (except loopback/any; configurable) |
| `infra.keyfile` | private-key and credential file names (`id_rsa`, `deploy.pem`, `my-service-account.json`) |
| `pii.email` | e-mail addresses (except `example.com/.org/.net`, plus `anthropic.com` in the `claude-code` format so `Co-Authored-By` trailers survive; configurable) |
| `pii.home_dir` | the user name in a home path → `[USER]`: `/home/<user>`, `/Users/<user>`, `C:\Users\<user>` (any case, either separator), `/mnt/c/Users/<user>` (WSL), `/c/Users/<user>` (Git Bash), `\\wsl$\Ubuntu\home\<user>`, URL-encoded (`%2Fhome%2F<user>`), in `file://` and `vscode-remote://` URIs, and in Claude Code project-folder names (`~/.claude/projects/-home-<user>-proj`) |

Values that are clearly not secrets are left alone: `${VAR}` and `$VAR` references, `<placeholder>`,
`****`, `true/false/null`, numbers except under a password, secret or PIN key, counters and metrics (`tokensUsed: 12345`, `secretCount`, `password_attempts`), and metadata keys such as `max_tokens`, `tokenizer` or
`password_policy`.

Turn rules off with `--disable NAME` or a prefix (`--disable pii`), or in Python with
`Redactor(disable=["pii"])`. An unknown name is an error. Add your own shapes:

```console
$ redact-transcripts --rule 'secret.acme_token=\bacme_[A-Za-z0-9]{24,}' notes.txt
```

```python
from redact_transcripts import Config, Redactor, Rule, default_rules

redactor = Redactor(
    rules=[*default_rules(), Rule.simple("secret.acme_token", r"\bacme_[A-Za-z0-9]{24,}")],
    config=Config(email_keep_domains=("example.com", "mycompany.example"), marker_template="‹{rule}›"),
)
```

## Formats

| `--format` | Use for | Structural fields (never rewritten) |
|---|---|---|
| `auto` (default) | picks one of the below from the first non-empty line | |
| `claude-code` | Claude Code session transcripts | `sessionId`, `uuid`, `parentUuid`, `id`, `tool_use_id`, `timestamp`, `type`, `role`, `model`, …, each only with its expected value shape |
| `jsonl` | any JSON Lines file | none; `--keep-key KEY` keeps identifier-shaped values under KEY |
| `text` | logs, notes, anything else; streams from stdin | n/a |

In the JSON formats both values **and object keys** are redacted, and a line that is not JSON is
redacted as text. A raw private key pasted across several non-JSON lines is collected up to its END
line.

Your own format is a subclass:

```python
from redact_transcripts import JsonlFormat, redact_bytes, register_format


class MyTraces(JsonlFormat):
    def is_structural(self, key: str) -> bool:
        return key.endswith("_id") or key in {"span", "ts"}


register_format(MyTraces(name="my-traces"))  # now available by name
out, report = redact_bytes(raw, format="my-traces")
```

For a non-JSON format, subclass `Format` and implement `redact_bytes(raw, redactor)`.

## What it misses

Known gaps, each pinned by a vector in [`vectors/known_misses.json`](vectors/known_misses.json):

- a token **split across two records or two lines** (each half is too short to recognise); a
  private key split over several JSON strings or records *is* caught;
- secrets in **prose** ("the password is hunter2"), and anything whose sensitivity is about meaning:
  names, customer data, confidential code;
- **hostnames**, internal URLs and project names (there is no rule for them; add `--rule`s);
- encodings other than one level of base64 and JSON string escapes: hex, double base64, zero-width
  characters (URL-encoding is decoded for home paths only);
- base64 variants: the URL-safe alphabet;
- `npm_` / `hf_` tokens, and bare AWS secret access keys without a key name;
- a lower-case Git Bash or Cygwin home path with nothing after the user (`/c/users/<user>`), and a
  project-folder name right after `(`, `[`, `:` or `,` (`(-home-<user>-proj)`);
- shapes the reference keeps as well: a bare `C:\Users` with no user, `\/home\/<user>` (JSON-escaped
  slashes) in arbitrary strings, `~user/` paths, a URL-encoded SigV4 signature;
- CLI mode leaves out the reference client's product-domain host rule;
- in streaming mode a line longer than 1 MiB is cut into pieces, and a secret across the cut is missed;
- vendor token shapes that are not in the rule table. Report missing shapes, see below.

It also has false positives on code: a long name after `1//` or a newer key prefix
(`n = 1//batch_size_per_device`, `pip install xai-grok-sdk-…`), `999.10.10.10`, or `token: 12345678`.

### What the third-party pass misses

`--third-parties` reduces how many other people a shared transcript names. It does **not** make a
transcript anonymous, and it is no privacy or GDPR guarantee. Read the output before you share it.
Known gaps (several are pinned in [`vectors/third_party.json`](vectors/third_party.json) as
`known_miss`):

- **names in running prose** ("I asked Marta Fakeova about it"): there is no name recognition, only context;
- an `@handle` **alone on its line**, which looks like a decorator or annotation;
- names without a field label, e.g. a `git log --format` line such as `a1b2c3d Fix (Jane Fakedoe, 3 days ago)`,
  and lower-case multi-word names in prose headers (`jane fakedoe wrote:`);
- **what people said**: quoted comment text (`> …` blocks, comment bodies) stays; only the
  attribution goes. A stricter opt-in level that also removes quoted text may come later; it is
  not part of `--third-parties`;
- **other mentions of a person already found**: once `@fake-user` became `[PERSON-1]`, the same
  login is *not* replaced elsewhere, e.g. in repository URLs (`github.com/fake-user/repo`,
  `git@github.com:fake-user/repo.git`, gists), `owner/repo` strings and `"full_name"` fields, a
  later `@fake-user` alone on its line, or a bare `fake-user` in prose or a table, so a reader can
  often re-identify a placeholder;
- **`Name <email>` outside a recognised header**: in `To:`, `Cc:`, `From:`, `Thanks-to:`,
  `Reported by:` (with a space), author lists (`authors = ["Fake Person <…>"]`), a JSON
  `"author": "Fake Person <…>"` value, or on a line of its own, the address goes (`pii.email`) but
  the name stays; names of more than five words are not caught either;
- links to issue, pull-request or chat threads are kept, although the page they point to names people;
- a `"name"` field in JSON text is redacted only next to a login or e-mail field on the same line, or
  when it looks like a capitalised full name;
- names in other scripts and conventions are caught only in the contexts above, and a name split
  across lines or JSON records is not caught;
- e-mail addresses that `pii.email` already redacted are not numbered, so an address and a handle
  of the same person are linked only when the address was kept.

It also over-matches: `github.com/<org>` is redacted like a person's profile, and an ordinary word
after `@` that is not on the built-in stop list ("meet me @fakecafe") becomes a placeholder, as
can a decorator, CSS at-rule or annotation that is not on the stop list when it is named in prose
outside a code span. Lines that are SQL statements or shell commands keep `@word`s in parameter or
file-argument position only.

`--keep-person` never keeps an e-mail address from `pii.email`: your own address is still
redacted (the safe direction). Keep a whole domain with `Config(email_keep_domains=...)` or turn
the rule off with `--disable pii.email`.

Performance: about 4–5 MB/s. The `auto`, `jsonl` and `claude-code` formats read the whole input
into memory; `--format text` streams.

Review redacted output before you share it.

## Test vectors

`vectors/*.json` holds the corpus the test suite runs: `positive`, `negative` (must stay
byte-identical), `split` (chunk and line boundaries), `encoded` (JSON-escaped, `\u` escapes,
base64), `known_misses` and `third_party` (people, run with `--third-parties`). Every secret in it
is synthetic and marked `FAKE`/`EXAMPLE`, and every person is fictional. The corpus
is CC0, so copy it into any project. Format: [`vectors/README.md`](vectors/README.md).

## Development

```console
$ git clone <repo-url> && cd redact-transcripts
$ python -m venv .venv && . .venv/bin/activate
$ pip install -e '.[dev]'
$ pytest              # offline; also runs the vector corpus and doctests
$ ruff check . && ruff format --check . && reuse lint
```

## Contributing

Contributions are welcome under the [Developer Certificate of Origin](https://developercertificate.org/):
sign off every commit (`git commit -s`). See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md) (how to report a missed secret shape).

Parts of this project were developed with AI assistance (Claude).

## Release checklist (maintainers)

- [ ] DCO GitHub App installed on the repository, private vulnerability reporting enabled, branch
      protection on `main`.
- [ ] CI green on GitHub for Python 3.9-3.13; release date in CHANGELOG; tag `v<version>`; PyPI via
      trusted publishing.

## About

`redact-transcripts` is maintained by [crossVault GmbH](https://session-exchange.com), the team behind **a4sx** ([session-exchange.com](https://session-exchange.com)), a marketplace for AI agent work sessions. It grew out of the transcript scrubbing in our own agent tooling.

## License

Code: [Apache-2.0](LICENSE), Copyright 2026 crossVault GmbH. Test vectors in `vectors/`:
[CC0-1.0](vectors/LICENSE). Licensing per file is declared in [REUSE.toml](REUSE.toml).
