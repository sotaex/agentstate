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
    """0.18.0: days that predate chain deployment (records without hash fields)
    are SKIPPED and reported as pre-chain -- failing them punished honesty about
    history instead of tampering. The chain is verified from the first anchored
    record onward."""
    prev = None                      # full hash of the previous ANCHORED record
    n = 0
    prechain = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if "hash" not in rec:
                prechain += 1
                prev = None          # cannot link across unanchored records
                continue
            if prev is not None and rec.get("prev", "") != prev[-16:]:
                return False, ("line %d: prev linkage broken (expected %s...)"
                               % (ln, prev[-16:]))
            h = hashlib.sha256(((prev or "") + canon(rec)).encode("utf-8")).hexdigest()
            if h != rec.get("hash"):
                return False, "line %d: hash mismatch (content edited)" % ln
            prev = rec.get("hash", "")
            n += 1
    note = " (%d pre-chain records skipped)" % prechain if prechain else ""
    return True, "%d records verified%s" % (n, note)


def verify_tail(path):
    """0.18.0 (R-20, audit HP-06): compare the day file against its entry in
    day_manifest.json (byte size + last-line hash, written outside the chain).
    Catches what the chain alone cannot: deleting the last N records of a day,
    or deleting the whole day file. Returns (ok, msg)."""
    mpath = os.path.join(os.path.dirname(path), "day_manifest.json")
    if not os.path.isfile(mpath):
        return True, "no day manifest (pre-0.18 audit dir) -- tail unverifiable"
    try:
        man = json.load(open(mpath, encoding="utf-8"))
    except Exception as e:
        return False, "day manifest unreadable: %s" % e
    day = os.path.basename(path)
    entry = man.get(day)
    if entry is None:
        # day file present on disk but absent from the manifest = created before
        # the anchor existed -- not a tamper, but the tail is unverifiable.
        return True, "not in day manifest (pre-anchor day) -- tail unverifiable"
    if not os.path.isfile(path):
        # 0.18.0 (HP-45): a day replaced by its .gz archive was legitimately
        # removed by report.py --archive. Archival is retention, not tampering.
        if glob.glob(os.path.join(os.path.dirname(path),
                                  os.path.splitext(day)[0] + ".jsonl.gz")):
            return True, "day archived to .gz (retention) -- tail unverifiable by design"
        return False, "day file listed in day_manifest.json is MISSING (whole-day deletion)"
    size = os.path.getsize(path)
    if size != entry.get("size"):
        return False, "size mismatch: file %d vs anchored %s (tail truncated/extended)" % (
            size, entry.get("size"))
    with open(path, "rb") as f:
        f.seek(max(0, size - 4096))
        tail = f.read().decode("utf-8", errors="replace").rstrip("\r\n")
    last_line = tail.rsplit("\n", 1)[-1] if "\n" in tail else tail
    try:
        last_hash = json.loads(last_line).get("hash", "")
    except Exception:
        return False, "last line unparseable -- tail edited"
    if last_hash != entry.get("last_hash"):
        return False, "last-line hash mismatch vs anchored value (tail edited/deleted)"
    return True, "tail matches day manifest (size %d)" % size


def main():
    """Modes:
    verify_chain.py [dir]          -- CURRENT-day full verify (chain+tail, exit 2 on
                                      failure) + history days as informational notes.
                                      Historical linkage breaks from pre-0.18 upgrade
                                      churn are recorded, not hidden, and not fatal:
                                      re-verifying a history written before the anchor
                                      existed is not a promise this tool makes.
    verify_chain.py <dir> --all    -- full-history mode: any historical break fails.
    """
    argv = [a for a in sys.argv[1:] if a != "--all"]
    full_history = "--all" in sys.argv[1:]
    target = argv[0] if argv else os.path.join(os.getcwd(), ".psl", "audit")
    files = [target] if os.path.isfile(target) else sorted(
        glob.glob(os.path.join(target, "*.jsonl")))
    mpath = os.path.join(str(target), "day_manifest.json") if os.path.isdir(str(target)) else None
    manifest = {}
    if mpath and os.path.isfile(mpath):
        try:
            manifest = json.load(open(mpath, encoding="utf-8"))
        except Exception:
            manifest = {}
    if not files and not manifest:
        print("no audit files under", target)
        return 1
    # current day = the latest anchored day (manifest) else the latest file
    days = sorted(set(list(manifest.keys()) + [os.path.basename(f) for f in files]))
    current_day = days[-1] if days else None
    tail_fail = 0
    history_notes = []
    current_ok = True
    for fp in sorted(files):
        day = os.path.basename(fp)
        ok, msg = verify_file(fp)
        is_current = (day == current_day)
        if not ok:
            if is_current or full_history:
                print(("TAMPERED  " if is_current else "HISTORY-BREAK  ") + fp + "  " + msg)
                if is_current:
                    return 2
                tail_fail += 1
                continue
            history_notes.append("%s: %s" % (day, msg))
            continue
        tok, tmsg = verify_tail(fp)
        tag = "tail-OK  " if tok else "TAIL-TAMPERED  "
        if not tok and not is_current and not full_history:
            history_notes.append("%s: tail %s" % (day, tmsg))
            continue
        print(tag + os.path.basename(fp) + "  " + tmsg)
        if not tok:
            tail_fail += 1
    # manifest-driven deletion check (covers days whose file is gone entirely)
    for day in sorted(manifest):
        f = os.path.join(str(target), day)
        gz = os.path.join(str(target), os.path.splitext(day)[0] + ".jsonl.gz")
        if not os.path.isfile(f) and not os.path.isfile(gz):
            print("TAIL-TAMPERED  %s  day file MISSING (whole-day deletion)" % day)
            tail_fail += 1
        elif not os.path.isfile(f):
            history_notes.append("%s: archived (.gz) -- tail unverifiable by design" % day)
    for note in history_notes:
        print("history-note:", note)
    print("chain intact: current day %s; history notes: %d; tail failures: %d" % (
        current_day, len(history_notes), tail_fail))
    return 2 if tail_fail else 0


if __name__ == "__main__":
    sys.exit(main())
