# Test vectors (CC0-1.0)

A corpus of **synthetic** secret-shaped strings for testing redaction and secret scanners. Released
under [CC0 1.0](LICENSE): copy, adapt and use it anywhere, no attribution needed.

**Every value is fake.** Each secret contains `FAKE` or `EXAMPLE` (or `NOTAREALKEY` in key
bodies), directly or after one base64 decode, and the test suite enforces this. None of them is,
or was derived from, a real credential. Please keep it that way in contributions.

## Files

| File | Content | Expectation |
|---|---|---|
| `positive.json` | one vector per rule | redacted |
| `negative.json` | near-misses: placeholders, metadata keys, hashes, versions, short prefixes | byte-identical |
| `split.json` | secrets cut by chunk boundaries, multi-line key blocks, CRLF | redacted |
| `encoded.json` | double-encoded JSON, `\u` escapes, escaped JSON in text, base64 | redacted |
| `known_misses.json` | shapes this library deliberately does not catch | byte-identical (documents the gap) |

## Schema

```json
{
  "$schema_version": 1,
  "category": "positive",
  "vectors": [
    {
      "id": "github-classic-pat",
      "description": "secret.github_token shape in prose",
      "mode": "text | stream | jsonl | claude-code",
      "input": "… (for mode=stream: \"chunks\": [\"…\", \"…\"] instead)",
      "expect": "redacted | unchanged | known_miss",
      "rules": ["rule names that must fire"],
      "absent": ["substrings that must not survive"],
      "output": "optional exact expected output",
      "decodes_to": "optional: the plaintext behind a base64 vector"
    }
  ]
}
```

Rule names and the `[REDACTED:<rule>]` marker are specific to this library; another tool can use
`absent` and `expect` alone.
