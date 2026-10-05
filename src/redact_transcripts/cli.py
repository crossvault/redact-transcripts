# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Command line: ``redact-transcripts <file|->``.

Exit status: 0 ok; 1 ``--check`` found something; 2 usage or I/O error.
"""

from __future__ import annotations

import argparse
import codecs
import dataclasses
import json
import os
import re
import sys
from typing import BinaryIO, List, Optional, Sequence

from . import __version__
from .engine import KEYED_VALUE, Redactor, Report, StreamRedactor
from .formats import JsonlFormat, TextFormat, detect_format, format_names, get_format
from .people import RULE_NAMES as PERSON_RULES
from .rules import Rule, default_rules

_CHUNK = 64 * 1024
PROG = "redact-transcripts"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description="Redact secrets and personal data from a transcript, JSONL log or text file. "
        "Writes the redacted copy to stdout (or -o). A regex backstop, not a "
        "guarantee.",
    )
    p.add_argument("input", metavar="FILE", help="input file, or - for stdin")
    p.add_argument(
        "-f",
        "--format",
        default="auto",
        choices=["auto", *format_names()],
        help="input format (default: auto-detect from the first line)",
    )
    p.add_argument("-o", "--output", metavar="PATH", help="write here instead of stdout")
    p.add_argument(
        "--report", action="store_true", help="print counts per rule to stderr (never the matched values)"
    )
    p.add_argument("--report-format", choices=["text", "json"], default="text")
    p.add_argument(
        "--check", action="store_true", help="write no output; exit 1 if any secret.* rule matches"
    )
    p.add_argument(
        "--strict", action="store_true", help="with --check: also fail on pii.* and infra.* matches"
    )
    p.add_argument(
        "--disable",
        action="append",
        default=[],
        metavar="RULE",
        help="turn off a rule or a prefix, e.g. --disable infra.ipv4 --disable pii (repeatable)",
    )
    p.add_argument(
        "--keep-key",
        action="append",
        default=[],
        metavar="KEY",
        help="JSON formats: never rewrite values under this key (repeatable)",
    )
    p.add_argument(
        "--rule",
        action="append",
        default=[],
        metavar="NAME=REGEX",
        help="add a rule that redacts every match of REGEX, e.g. "
        "'secret.acme_token=\\bacme_[A-Za-z0-9]{24,}' (repeatable)",
    )
    p.add_argument(
        "--third-parties",
        action="store_true",
        help="also replace other people's @handles and attributed names (commit trailers, "
        "'Author:' lines, 'X wrote:', login fields, profile URLs) with [PERSON-n] placeholders",
    )
    p.add_argument(
        "--keep-person",
        action="append",
        default=[],
        metavar="NAME",
        help="with --third-parties: never redact this handle, name or full e-mail address, e.g. "
        "your own (repeatable)",
    )
    p.add_argument("--list-rules", action="store_true", help="list rule names and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _extra_rules(specs: Sequence[str]) -> List[Rule]:
    out = []
    for spec in specs:
        name, sep, regex = spec.partition("=")
        if not sep or not name or not regex:
            raise ValueError(f"--rule expects NAME=REGEX, got {spec!r}")
        try:
            out.append(Rule.simple(name.strip(), regex))
        except re.error as e:
            raise ValueError(f"--rule {name}: bad regex: {e}") from None
    return out


def _write_report(report: Report, fmt: str, check: bool) -> None:
    err = sys.stderr
    if fmt == "json":
        err.write(json.dumps(report.as_dict(), indent=2) + "\n")
        return
    verb = "would redact" if check else "redacted"
    err.write(
        f"{PROG}: format={report.format} lines={report.lines_total} "
        f"changed={report.lines_changed} {verb}={report.total}\n"
    )
    width = max((len(k) for k in report.rules), default=0)
    for name, n in sorted(report.rules.items()):
        err.write(f"  {name:<{width}}  {n}\n")


def _read_all(stream: BinaryIO) -> bytes:
    return stream.read()


def _stream_text(src: BinaryIO, dst: Optional[BinaryIO], redactor: Redactor) -> Report:
    report = Report(format="text")
    stream = StreamRedactor(redactor, report=report)
    decoder = codecs.getincrementaldecoder("utf-8")("surrogateescape")
    read = getattr(src, "read1", src.read)
    while True:
        chunk = read(_CHUNK)
        out = stream.feed(decoder.decode(chunk, final=not chunk))
        if not chunk:
            out += stream.close()
        if dst is not None and out:
            dst.write(out.encode("utf-8", "surrogateescape"))
            dst.flush()
        if not chunk:
            return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.strict and not args.check:
        parser.error("--strict only applies with --check")
    if args.output and args.check:
        parser.error("--check writes no output; drop -o")
    if args.keep_person and not args.third_parties:
        parser.error("--keep-person only applies with --third-parties")
    try:
        rules = default_rules() + _extra_rules(args.rule)
    except ValueError as e:
        sys.stderr.write(f"{PROG}: {e}\n")
        return 2
    known = [r.name for r in rules] + [KEYED_VALUE]
    if args.third_parties:
        known += list(PERSON_RULES)
    for d in args.disable:
        d = d.rstrip(".")
        if not any(n == d or n.startswith(d + ".") for n in known):
            sys.stderr.write(f"{PROG}: --disable {d}: no such rule or prefix (see --list-rules)\n")
            return 2
    if args.list_rules:
        sys.stdout.write("\n".join(known) + "\n")
        return 0

    src: BinaryIO
    try:
        src = sys.stdin.buffer if args.input == "-" else open(args.input, "rb")
    except OSError as e:
        sys.stderr.write(f"{PROG}: cannot read {args.input}: {e.strerror}\n")
        return 2
    if (
        args.output
        and args.input != "-"
        and os.path.exists(args.output)
        and os.path.samefile(args.input, args.output)
    ):
        sys.stderr.write(f"{PROG}: refusing to overwrite the input file; write elsewhere\n")
        return 2

    dst: Optional[BinaryIO] = None
    try:
        with src:
            raw = b""
            if args.format == "auto":
                raw = _read_all(src)
                fmt = detect_format(raw)
            else:
                fmt = get_format(args.format)
            if args.keep_key and isinstance(fmt, JsonlFormat):
                fmt = fmt.with_structural_keys(args.keep_key)
            base = fmt.default_redactor()
            config = dataclasses.replace(base.config, keep_people=tuple(args.keep_person))
            redactor = Redactor(
                rules=rules, config=config, disable=args.disable, third_parties=args.third_parties
            )

            if not args.check:
                dst = open(args.output, "wb") if args.output else sys.stdout.buffer
            if isinstance(fmt, TextFormat) and args.format != "auto":
                report = _stream_text(src, dst, redactor)
            else:
                if args.format != "auto":
                    raw = _read_all(src)
                out, report = fmt.redact_bytes(raw, redactor)
                if dst is not None:
                    dst.write(out)
                    dst.flush()
    except BrokenPipeError:
        # The reader went away (e.g. "| head"): stop quietly, like other Unix filters, and point
        # stdout at /dev/null so the interpreter's final flush does not raise again.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError, AttributeError):  # not a real file descriptor (tests)
            pass
        return 0
    except OSError as e:
        sys.stderr.write(f"{PROG}: I/O error: {e}\n")
        return 2
    finally:
        if dst is not None and args.output:
            dst.close()

    if args.report or args.check:
        _write_report(report, args.report_format, args.check)
    if args.check:
        found = report.total if args.strict else report.secrets_found()
        return 1 if found else 0
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
