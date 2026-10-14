# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Refresh tests/data/parity_fixtures.json.gz and its lock from a reference implementation.

    python tests/regen_parity_fixtures.py --reference module:function --revision "<label>"

``function(text, kind, mode) -> str`` is the reference scrubber (see tests/test_parity.py). Every stored
input is run through it again: an input it now redacts moves to (or stays in) ``redact`` with the new
output, one it keeps in both modes moves to ``keep``. Then the lock is rewritten. Review the change in
tests/test_parity.py's results before committing: a case this package does not follow is a parity gap.
"""

import argparse
import base64
import gzip
import hashlib
import importlib
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"


def _d(s):
    return base64.b64decode(s).decode("utf-8", "surrogatepass")


def _e(s):
    return base64.b64encode(s.encode("utf-8", "surrogatepass")).decode()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--reference", required=True, help="module:function")
    ap.add_argument("--revision", required=True, help="a label for the reference revision")
    args = ap.parse_args()
    module, _, name = args.reference.partition(":")
    ref = getattr(importlib.import_module(module), name)
    path = DATA_DIR / "parity_fixtures.json.gz"
    doc = json.loads(gzip.decompress(path.read_bytes()))
    redact, keep = [], []
    inputs = {(c["kind"], c["mode"], c["in"]) for c in doc["redact"]}
    for c in doc["keep"]:
        src = _d(c["in"])
        inputs.add((c["kind"], "server", c["in"]))
        if c["kind"] == "text":
            inputs.add(("line", "cli", _e(json.dumps({"c": src}))))
        else:
            inputs.add(("line", "cli", c["in"]))
    kept = set()
    for kind, mode, enc in sorted(inputs):
        src = _d(enc)
        out = ref(src, kind, mode)
        if out != src:
            redact.append({"kind": kind, "mode": mode, "in": enc, "ref": _e(out)})
        elif mode == "server":
            kept.add((kind, enc))
    for kind, enc in sorted(kept):
        src = _d(enc)
        line = src if kind == "line" else json.dumps({"c": src})
        if ref(line, "line", "cli") == line:
            keep.append({"kind": kind, "in": enc})
    doc["redact"], doc["keep"] = redact, keep
    raw = gzip.compress(json.dumps(doc, separators=(",", ":")).encode(), 9, mtime=0)
    path.write_bytes(raw)
    lock = {
        "reference_revision": args.revision,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "counts": {"redact": len(redact), "keep": len(keep)},
    }
    (DATA_DIR / "parity_fixtures.lock.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(lock))


if __name__ == "__main__":
    main()
