# Contributing

Thanks for helping. Bug reports, new token shapes, test vectors and fixes are all welcome.

## Developer Certificate of Origin (DCO)

Every commit must be signed off. By signing off you certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change,
or otherwise have the right to submit it under this project's licences.

```console
$ git commit -s -m "Add rule for <vendor> API keys"
```

This adds a line like `Signed-off-by: Your Name <you@example.com>` with your real name. Pull
requests with unsigned commits cannot be merged; `git commit --amend -s` or
`git rebase --signoff main` fixes them. There is no CLA.

Contributions to `vectors/` are released under CC0-1.0; everything else under Apache-2.0.

## AI-assisted contributions

You may use AI tools. You are responsible for the change as if you wrote it: you have read every
line, you can explain it, and the sign-off is yours. Say in the PR description if a tool wrote a
significant part of it.

## Adding a rule or a vector

1. **Never paste a real secret**, not even a revoked one, and never copy strings from real
   transcripts or logs. Build a synthetic value that has the right shape and contains `FAKE` or
   `EXAMPLE` (the test suite checks this).
2. Add a positive vector to `vectors/positive.json` (or `split.json` / `encoded.json`) and, where a
   rule could over-match, a near-miss to `vectors/negative.json`.
3. Add the rule to `src/redact_transcripts/rules.py`. Specific vendor shapes go before the generic
   rules. Separators must not cross a newline (use `[ \t]`, not `\s`); the streaming tests rely on it.
4. If the shape is one we deliberately do not catch, put it in `vectors/known_misses.json` and say
   why in its `description`.

## Checks

```console
$ pip install -e '.[dev]'
$ pytest
$ ruff check . && ruff format --check .
$ reuse lint
```

CI runs the same on Python 3.9 to 3.13. New source files need the SPDX header:

```python
# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
```

(Use your own copyright line if you prefer; the licence identifier stays.)

## Pull requests

Keep them small and focused, include tests, and add a line to `CHANGELOG.md` under *Unreleased*.
