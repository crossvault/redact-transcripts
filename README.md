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
redact-transcripts 0.1.0
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
curl -H "Authorization: Bearer [REDACTED:secret.bearer]" https://api.example.com
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

## Rules

`redact-transcripts --list-rules` prints them. Each match is replaced by `[REDACTED:<rule>]`.

| Rule | Catches |
|---|---|
| `secret.private_key` | PEM `-----BEGIN … PRIVATE KEY-----` blocks (multi-line) |
| `secret.anthropic_key`, `secret.openai_key`, `secret.github_token`, `secret.gitlab_token`, `secret.slack_token`, `secret.aws_key_id`, `secret.google_api_key`, `secret.stripe_key`, `secret.jwt` | vendor token shapes |
| `secret.base64_encoded` | a base64 blob whose decoded text contains one of the secrets above (one level) |
| `secret.bearer`, `secret.basic_auth` | `Bearer …` / `Basic …` credentials (the scheme is kept) |
| `secret.auth_header` | `Authorization: token …` and other schemes (`digest`, `apikey`, `key`, `sso-key` …) |
| `secret.url_credentials` | `scheme://user:password@host` |
| `secret.url_token` | `scheme://<token>@host`: a 16+ character token as the whole userinfo (git remotes) |
| `secret.cli_flag` | `--password X`, `--token=X`, `--api-key X` … |
| `secret.user_percent_pass` | `-U user%password` (smbclient style) |
| `secret.assignment` | `password=…`, `api_key: "…"` (the whole quoted value, spaces included), `export X_TOKEN=…`, one level of backslash-escaped JSON |
| `secret.keyed_value` | JSON formats: a string, or the items of a list stored under a secret-named key (`{"GITHUB_TOKEN": "…"}`); a number of 4+ digits only under a password, secret or PIN key |
| `secret.pin` | `pin: 4711`, `userPin=4321`, `passcode: 887766` (whole key words, so `mapping: 1234` is kept) |
| `pii.email` | e-mail addresses (except `example.com/.org/.net`, plus `anthropic.com` in the `claude-code` format so `Co-Authored-By` trailers survive; configurable) |
| `pii.home_dir` | the user name in `/home/<user>`, `/Users/<user>`, `C:\Users\<user>` → `[USER]` |
| `infra.ipv4` | IPv4 addresses (except loopback/any; configurable) |

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

- a secret **split across two records or two lines** (each half is too short to recognise);
- secrets in **prose** ("the password is hunter2"), and anything whose sensitivity is about meaning:
  names, customer data, confidential code;
- **hostnames**, internal URLs and project names (there is no rule for them; add `--rule`s);
- encodings other than one level of base64: hex, double base64, URL-encoding, zero-width characters;
- base64 variants: the URL-safe alphabet, MIME line-wrapped base64;
- more than one level of escaping (`\\"password\\"`, `\/`-escaped slashes in URLs);
- `mysql -pPASSWORD`, PGP private key blocks, `npm_` / `hf_` tokens, and bare AWS secret access
  keys without a key name;
- in streaming mode a line longer than 1 MiB is cut into pieces, and a secret across the cut is missed;
- vendor token shapes that are not in the rule table. Report missing shapes, see below.

It also has false positives on code: `token = get_token()` loses `get_token`, for example.

Performance: about 4–5 MB/s. The `auto`, `jsonl` and `claude-code` formats read the whole input
into memory; `--format text` streams.

Review redacted output before you share it.

## Test vectors

`vectors/*.json` holds the corpus the test suite runs: `positive`, `negative` (must stay
byte-identical), `split` (chunk and line boundaries), `encoded` (JSON-escaped, `\u` escapes,
base64) and `known_misses`. Every secret in it is synthetic and marked `FAKE`/`EXAMPLE`. The corpus
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
- [ ] CI green on GitHub for Python 3.9-3.13; release date in CHANGELOG; tag `v0.1.0`; PyPI via
      trusted publishing.

## About

`redact-transcripts` is maintained by [crossVault GmbH](https://session-exchange.com), the team behind **a4sx** ([session-exchange.com](https://session-exchange.com)), a marketplace for AI agent work sessions. It grew out of the transcript scrubbing in our own agent tooling.

## License

Code: [Apache-2.0](LICENSE), Copyright 2026 crossVault GmbH. Test vectors in `vectors/`:
[CC0-1.0](vectors/LICENSE). Licensing per file is declared in [REUSE.toml](REUSE.toml).
