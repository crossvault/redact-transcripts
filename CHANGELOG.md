# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - unreleased (date set at release)

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
