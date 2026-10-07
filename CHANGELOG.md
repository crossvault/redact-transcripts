# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `odysseus` format for Odysseus session exports (`{"name", "model", "exported", "messages"}`):
  one JSON document (pretty-printed or compact), a list of them, or one per line. Every value
  is redacted like content, with no structural exemption; roles, part types, the model tag and
  the export time come out unchanged because no rule matches their normal values. A clean file
  comes out byte-identical; otherwise indentation (spaces or tabs), line endings and BOM are
  kept. Example: `examples/odysseus-export.json`.

### Changed
- `--format auto` recognises an Odysseus export, including a pretty-printed one (which it used
  to treat as plain text). A JSON Lines file whose first line looks like an export (a `messages`
  list and an `exported` key) is now detected as `odysseus` instead of `jsonl`; its redaction is
  the same. A multi-line input that is not JSON is still detected as `text`.

### Fixed
- Input nested too deeply to parse or walk (a `RecursionError`) no longer aborts the run, in any
  JSON format and in `--format auto`: the whole input, or the one affected line, is redacted as
  plain text instead.

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
