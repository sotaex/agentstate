#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L10 audit chain verifier.

Usage: python tools/verify_chain.py [audit-dir-or-file]
Replays the hash chain over every .jsonl record: each record must carry
prev == previous record's hash (last 16 hex) and
hash == sha256(prev + canonical_json(record-without-hash)).
Exit 0 = chain intact; 2 = tamper detected (prints the first broken line).
"""
import glob
import hashlib
import json
import os
import sys


def canon(rec):
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def verify_file(path):
    prev = ""
    n = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            n += 1
            rec = json.loads(line)
            if rec.get("prev", "") != prev[-16:]:
                return False, "line %d: prev linkage broken (expected %s...)" % (ln, prev[-16:])
            h = hashlib.sha256((prev + canon(rec)).encode("utf-8")).hexdigest()
            if h != rec.get("hash"):
                return False, "line %d: hash mismatch (content edited)" % ln
            prev = rec.get("hash", "")
    return True, "%d records verified" % n


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.getcwd(), ".psl", "audit")
    files = [target] if os.path.isfile(target) else sorted(
        glob.glob(os.path.join(target, "*.jsonl")))
    if not files:
        print("no audit files under", target)
        return 1
    for fp in files:
        ok, msg = verify_file(fp)
        print(("OK  " if ok else "TAMPERED  ") + fp + "  " + msg)
        if not ok:
            return 2
    print("chain intact: %d file(s)" % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
