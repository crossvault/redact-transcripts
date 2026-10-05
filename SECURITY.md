# Security policy

## Scope

This library is a **regex backstop**. A secret shape it does not catch is a missing feature, not a
vulnerability, unless the library claims to catch it. Things we treat as security issues:

- a secret that a documented rule should redact but does not (a **false negative**), including
  through an encoding the README says is handled (JSON escaping, `\u` escapes, one level of base64,
  chunk boundaries);
- a matched value appearing in a report, an error message or any output other than the redacted text;
- redacted output that is no longer valid JSON in a JSON format, or that changes a structural field;
- crashes or catastrophic slowdowns (ReDoS) on crafted input.

Shapes listed under "What it misses" in the README and in `vectors/known_misses.json` are known
and are not security issues; feature requests for them are welcome as normal issues.

## Reporting

**Never include a real secret in a report.** Send a synthetic value of the same shape (mark it `FAKE`).

- Preferred: GitHub private vulnerability reporting on this repository ("Report a vulnerability"
  under the Security tab).
- E-mail: info@session-exchange.com

We aim to acknowledge reports within 3 working days and to ship a fix for a confirmed false negative
in a documented rule within 30 days. The rules are public by design; a fix is a new rule or vector,
released with a changelog entry that credits the reporter unless they prefer otherwise.

## Supported versions

Only the latest release receives fixes.
