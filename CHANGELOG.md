# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Vendor token shapes: `secret.openrouter_key`, `secret.google_oauth_token` (access and refresh
  tokens), `secret.google_oauth_client_secret`, `secret.groq_key`, `secret.xai_key`,
  `secret.stripe_webhook_secret`, `secret.zai_key`.

### Changed
- Vendor tokens are also recognised right after `_` or a URL escape (`CONF_ghp_…`, `?k=%20AKIA…`),
  right after a literal `\n`/`\r`/`\t` escape, glued onto preceding text (exact vendor shape only),
  and when followed by `_<word>`. In these identifier-like positions the token body must look random,
  so names such as `storage_read_bytes` or `slack_xoxb-tokens-and-scopes-guide` are kept.
- Vendor token rules never rewrite text inside base64 data or a `data:` URI. A key id that sits
  inside such data (an `AKIA…` run joined by `+` in a long base64 run) is therefore kept.
- The newer shapes (`ya29.`, `1//0`, `GOCSPX-`, `gsk_`, `xai-`) need a random-looking body in every
  position and may end right before `/`, `+` or `=`; Google refresh tokens must start `1//0`, and
  `secret.zai_key` needs a random-looking part after the `.`.
- Scan every occurrence of duplicate JSON keys.

### Reference rule set (a4sx scrubber, as of 2026-10-14, with its `prefixed_api_token` rename)
The built-in rules are now the a4sx transcript scrubber's rules, in its order and with its
false-positive guards (`src/redact_transcripts/_scrub_rules.py`), on both of its paths: decoded text,
and the client's raw-JSONL pass ("CLI mode", `src/redact_transcripts/_cli_mode.py`).
`tests/test_parity.py` checks that everything the reference redacts on its own test corpus is redacted
here too, and that what it keeps is kept; the fixtures are pinned by a lock file and refreshed with
`tests/regen_parity_fixtures.py`. Not ported: the client's own private-key pass and its product-domain
host rule (see README, What it misses).

#### Added
- CLI mode: each string is also redacted as it is written inside a JSONL line, with the reference
  client's raw-JSONL rules and its own key rules (`--password X` after a literal `\n`, `pwd=X` before
  `C:\Users\…`, `/users/<user>/` after a literal `\t`, `AKIA…` glued onto a JWT). `--disable cli_mode`
  turns it off.
- `secret.prefixed_api_token` (`tok_`, `pol_`, `pt_`, `emit_` and `ge_tok_`/`ge_emit_`-style platform
  tokens, also glued to an upper-case name) and `secret.a4sx_session` (`ge_sess_…`).
- Rules: `secret.token_tail` (the rest of a key glued onto a redacted one), `secret.digest` (HTTP
  Digest `response=`/`cnonce=`), `secret.aws_signature` (`X-Amz-Signature=`, `Signature=`,
  `X-Amz-Security-Token=`), `secret.quoted_assignment`, `secret.json_assignment`,
  `secret.nested_assignment` (escaped quotes at any depth), `secret.weakpass`, `secret.cmd_userpass`
  (`curl -u user:pw`), `secret.pass_assignment` (`db_pass=`), `secret.mysql_password` (`mysql -pPW`),
  `secret.gsheet`, `infra.mac`, `infra.ipv6`, `infra.keyfile`, and the pseudo-rules `secret.escaped`
  (a credential spelled with JSON escapes, `\u0067hp_…`, `1\/\/…`) and `secret.deep_nesting` (a JSONL
  line nested over 600 deep is redacted fail-closed instead of decoded).
- `pii.home_dir`: URL-encoded paths (`%2Fhome%2F<user>`), `file://` and `vscode-remote://` URIs, WSL
  (`/mnt/c/Users/<user>`, `\\wsl$\<distro>\home\<user>`), Git Bash (`/c/Users/<user>`), lower-case
  `C:\users\<user>` and `/users/<user>/<home folder>`, non-ASCII user names, glued paths, and Claude Code
  project-folder names (`~/.claude/projects/-home-<user>-proj`, `C--Users-<user>-…`).
- `secret.jwt` takes a bare JWT (or 5-part JWE) whole, only when its header decodes to a JOSE header
  naming `alg`; it runs last.
- `secret.private_key`: a key printed as a quoted list of its lines, a key split over several JSON
  strings or JSONL records, PGP blocks; a lone BEGIN marker is redacted too.
- Vendor keys written back to back, after `-`, as URL path segments, before `-x`/`/path`/`+`/`=`
  tails, or with another prefix's letters inside a random body.

#### Changed
- Vendor tokens are found by one rule and reported per vendor, as before. Names that read as words
  after a vendor prefix (`id-xai-GrokModelConfigLoader`) are kept; some code shapes are redacted
  now, as in the reference (`n = 1//batch_size_…`, `pip install xai-grok-sdk-…`, `<md5>.<word>`).
- `Authorization:` headers (any scheme, value also on the next line) are reported as
  `secret.auth_header`; `--password` flags as `secret.cli_flag`, `--token`/`--api-key`/`--secret` as
  `secret.cli_token_flag`; a bare `Basic …` needs a credential-shaped value.
- Values under a secret-named JSON key are judged as in the reference: nested objects and lists are
  redacted too; env-var names (`OPENAI_API_KEY`), placeholders and metadata keys
  (`private_key_id`, `api_key_env`) are kept.
- A private-key block keeps its line breaks, so line numbers in a report stay true.
- The rules repeat on a string that changed (at most 4 passes): redacting twice changes nothing.
- IPv4: every dotted quad is redacted (`999.10.10.10` too); the keep-list still applies.
- `token: 12345678` / `api_key=12345678` are redacted (8+ characters under a secret key).
- Rewritten JSONL lines stay valid JSON with overflowing numbers (`1e400`) and lone surrogates.

## [0.2.0] - unreleased (date set at release)

### Added
- Opt-in third-party redaction: `--third-parties` on the command line, `Redactor(third_parties=True)`
  or `redact_bytes(..., third_parties=True)` in Python. Other people's `@handles`, commit trailers
  (`Co-authored-by:`, `Signed-off-by:` …), `Author:` lines, "X wrote:" and web-UI headers, login
  fields, profile URLs and e-mail local parts are replaced with numbered placeholders
  (`[PERSON-1]`) that stay stable within a transcript. Five new rules: `person.handle`,
  `person.name`, `person.email_local`, `person.profile_url`, `person.keyed_value`.
- Allow-list: `--keep-person` / `Config(keep_people=...)` keeps the author's own handles, names and
  full e-mail addresses; bots, CI services, AI assistants and group mentions are always kept.
- `Config(person_template=...)` for the placeholder; `Redactor.reset()` starts a new transcript.
- `vectors/third_party.json`: fictional people, code near-misses and known misses (CC0).
- Dotted handles (`@fake.user`, `@name.bsky.social`) are recognised.
- Timing tests: an audit runs every `person.*` regular expression on adversarial lines of 8, 40
  and 200 bytes, and the whole pass at 8, 40 and 200 KB, each with a hard timeout.

### Changed
- `Redactor` keeps per-transcript state when `third_parties` is on; the formats and
  `StreamRedactor` reset it at the start of each transcript. Without `third_parties` output is
  unchanged.

## [0.1.0] - 2026-10-05

First public release.

### Added
- Rule engine with 23 built-in rules (`secret.*`, `pii.*`, `infra.*`) plus `secret.keyed_value`
  for secret-named JSON keys (strings, numbers of 4+ digits, list items); rules can be disabled by
  name or prefix (unknown names are rejected), and custom rules added.
- `secret.auth_header` (`Authorization: token …` and other non-Bearer/Basic schemes) and
  `secret.url_token` (`https://<token>@host`), and `secret.pin` (numeric PINs and passcodes).
- All-digit values are redacted only under password, secret or PIN keys; counters and metrics
  such as `tokensUsed` or `secretCount` are kept.
- `secret.assignment` redacts a whole quoted value, spaces included, and all-digit values of 4+
  digits; metadata keys such as `tokenizer`, `max_tokens` and `password_policy` are skipped.
  Its pattern is bounded, so matching stays linear on crafted input.
- `secret.base64_encoded`: redacts a base64 blob whose decoded text contains a known secret.
- Pluggable formats: `claude-code` (keeps ids, parent links and timestamps when their values have
  the expected shape and contain no secret), generic `jsonl` (with `--keep-key`), and `text`;
  `auto` detection; `register_format()`.
- `StreamRedactor`: chunk-by-chunk redaction whose output equals whole-text redaction; private-key
  blocks are held until their END line; reports carry input and output hashes.
- `redact-transcripts` command line tool with `--report`, `--check` / `--strict`,
  `--disable`, `--rule`, `--keep-key`, `-o`.
- CC0 test-vector corpus in `vectors/` (positive, negative, split, encoded, known misses).
