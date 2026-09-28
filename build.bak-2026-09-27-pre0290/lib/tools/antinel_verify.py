#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""antinel verify (A-8, v1.40 §8.7) - status derivation for a judgment record.

Compares the CURRENT bytes of every file covered by a judgment's `digests`
against the recorded digests, and derives the record status:

    current     every covered file hashes to its recorded value
    superseded  at least one covered file differs (auto-derived, V7 rule 1)
    unreadable  a covered file is missing (also a supersession, named apart)

The record itself is never modified: `status` here is DERIVED, not written
(V7 rule 3: the original credential is append-only). Any third party can run
this against a clone of the repo - no trust in us required.

Usage:
  python tools/antinel_verify.py                    # verify <pkg>/psl/judgment.json digests
  python tools/antinel_verify.py path/to/judgment.json
  python tools/antinel_verify.py --manifest         # verify ALL files in psl/manifest.json (0.17.0, P-B1)
  python tools/antinel_verify.py --json

Exit codes: 0 = current, 1 = superseded/unreadable, 2 = cannot verify.
Python 3.10+, stdlib only, no network.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
DEFAULT = PKG / "psl" / "judgment.json"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Derive the status of an Antinel judgment record")
    ap.add_argument("judgment", nargs="?", default=str(DEFAULT),
                    help="path to judgment.json (default: <pkg>/psl/judgment.json)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--manifest", action="store_true",
                    help="verify every file listed in psl/manifest.json instead of the "
                         "judgment digests (closes the 16-file verification gap, audit N6)")
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    jpath = Path(a.judgment)
    try:
        rec = json.loads(jpath.read_text(encoding="utf-8"))
    except Exception as e:
        print(json.dumps({"status": "error", "reason": "judgment unreadable: %s" % e}))
        return 2

    if a.manifest:
        mpath = PKG / "psl" / "manifest.json"
        try:
            man = json.loads(mpath.read_text(encoding="utf-8"))
        except Exception as e:
            print(json.dumps({"status": "error", "reason": "manifest unreadable: %s" % e}))
            return 2
        digests = man.get("files") or {}
        base = mpath.resolve().parent.parent
        scope = "manifest (%d files)" % len(digests)
    else:
        digests = rec.get("digests") or {}
        base = jpath.resolve().parent.parent          # digests are package-relative
        scope = "judgment digests (%d files)" % len(digests)
    if not digests:
        print(json.dumps({"status": "error", "reason": "no digests to verify (%s)" % scope}))
        return 2
    changed, missing, checked = [], [], 0
    for rel, want in sorted(digests.items()):
        f = base / rel
        checked += 1
        if not f.is_file():
            missing.append(rel)
            continue
        got = "sha256:" + hashlib.sha256(f.read_bytes()).hexdigest()
        if got != want:
            changed.append({"file": rel, "recorded": want[:23], "live": got[:23]})
    if changed:
        status, reason = "superseded", "%d of %d covered files differ (%s)" % (
            len(changed), checked, scope)
    elif missing:
        status, reason = "superseded", "%d of %d covered files are missing (%s)" % (
            len(missing), checked, scope)
    else:
        status, reason = "current", "all %d covered files hash to their recorded digests (%s)" % (
            checked, scope)
    out = {"status": status, "reason": reason, "checked": checked,
           "mode": "manifest" if a.manifest else "judgment",
           "changed": changed, "missing": missing,
           "record_verdict": rec.get("verdict"),
           "rule": "any failed verification supersedes the record (append-only; "
                   "this tool never edits the credential)"}
    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=1))
    else:
        mark = {"current": "OK", "superseded": "SUPERSEDED"}.get(status, status.upper())
        print("[%s] %s" % (mark, reason))
        for c in changed:
            print("  changed: %s\n    recorded %s...\n    live     %s..." % (c["file"], c["recorded"], c["live"]))
        for m in missing:
            print("  missing: %s" % m)
    return 0 if status == "current" else 1


if __name__ == "__main__":
    sys.exit(main())
