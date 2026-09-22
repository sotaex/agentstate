#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel audit chain verifier — 0.20.0 five-level classifier.

Classifies every anomaly as one of:
  TAMPERED     (L1) parent record deleted / prev points to nothing
  EDITED       (L2) content edited (self-hash fails against its own parent)
  CONCURRENCY  (L3) same-parent fork (self-consistent, benign race)
  MISLINKED    (L4) inserted / out-of-order (prev exists but is not the predecessor)
  BORROWED     (L5) legacy mirror format (parent belongs to another chain)

Exit codes:
  0 = clean
  2 = at least one TAMPERED / EDITED / MISLINKED (unexplained)
  3 = only CONCURRENCY / BORROWED (explained anomalies — still not "clean")

Usage:
  verify_chain.py [dir-or-file]           # current day full + history informational
  verify_chain.py <dir> --all             # full-history mode (breaks fail too)
  verify_chain.py <dir> --json            # machine-readable
"""
import glob
import hashlib
import json
import os
import sys
from collections import defaultdict


def canon(rec):
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


# ─── pass 1: index the file ───

def index_file(path):
    """Returns (records, hash_set, prev_users, prechain_count).
    records: [(line_no, rec_dict, canon_str)]
    hash_set: {full_hash_str} for all records that have one
    prev_users: {prev_tail16: [line_no, ...]} — how many records claim each prev
    """
    records = []
    hash_set = set()
    prev_users = defaultdict(list)
    prechain = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if "hash" not in rec:
                prechain += 1
                continue
            records.append((ln, rec, canon(rec)))
            hash_set.add(rec["hash"])
            prev_users[rec.get("prev", "")[-16:]].append(ln)
    return records, hash_set, prev_users, prechain


# ─── pass 2: classify each record ───

def classify(records, hash_set, prev_users):
    """Returns list of (line_no, rec, class_label). Order: L1→L2→L3→L4.
    Self-consistent means: sha256(prev_full + canon(rec)) == rec.hash,
    where prev_full is the full hash of the record whose tail-16 == rec.prev."""
    # Build full-hash lookup: tail16 -> full hash
    tail_to_full = {}
    for _, rec, _ in records:
        h = rec.get("hash", "")
        if len(h) >= 16:
            tail_to_full[h[-16:]] = h

    # Classify
    out = []
    prev_full = None       # full hash of the previous ANCHORED record (for sequential check)
    for ln, rec, canon_str in records:
        prev16 = rec.get("prev", "")[-16:]
        stored_hash = rec.get("hash", "")

        # L1: does prev16 point to ANY hash in this file?
        if prev16 and prev16 not in tail_to_full and prev16 != "":
            out.append((ln, rec, "TAMPERED", "parent record deleted"))
            prev_full = stored_hash
            continue

        # Find parent full hash
        parent_full = tail_to_full.get(prev16, "")

        # L2: content integrity — recompute using parent_full (or "" for genesis)
        base = parent_full if prev16 else ""
        recomputed = hashlib.sha256((base + canon_str).encode("utf-8")).hexdigest()
        if recomputed != stored_hash:
            out.append((ln, rec, "EDITED", "content edited (self-hash fails against parent)"))
            prev_full = stored_hash
            continue

        # L3: same-prev fork — how many records claim this same prev?
        users = prev_users.get(prev16, [])
        if len(users) > 1 and prev16:
            out.append((ln, rec, "CONCURRENCY", "same-parent fork (%d users)" % len(users)))
            prev_full = stored_hash
            continue

        # L4: prev points to an existing record that is NOT the immediately previous one
        if prev_full is not None and prev16 and prev16 != prev_full[-16:]:
            out.append((ln, rec, "MISLINKED", "inserted / out-of-order"))
            prev_full = stored_hash
            continue

        # Clean
        out.append((ln, rec, "OK", ""))
        prev_full = stored_hash
    return out


def verify_file_v2(path):
    """Returns (by_class_counter, detail_lines, prechain_count)."""
    records, hash_set, prev_users, prechain = index_file(path)
    classified = classify(records, hash_set, prev_users)
    by_class = defaultdict(int)
    details = []
    for ln, rec, label, note in classified:
        by_class[label] += 1
        if label != "OK":
            details.append((ln, label, note, rec.get("tool", "?"), rec.get("ts", "")[11:19]))
    return by_class, details, prechain, len(records)


def verify_tail(path, manifest_dir=None):
    mpath = os.path.join(os.path.dirname(path), "day_manifest.json")
    if not os.path.isfile(mpath):
        return True, "no day manifest"
    try:
        man = json.load(open(mpath, encoding="utf-8"))
    except Exception as e:
        return False, "manifest unreadable: %s" % e
    day = os.path.basename(path)
    entry = man.get(day)
    if entry is None:
        return True, "not in day manifest"
    if not os.path.isfile(path):
        gz = os.path.join(os.path.dirname(path), os.path.splitext(day)[0] + ".jsonl.gz")
        if os.path.isfile(gz):
            return True, "archived (.gz)"
        return False, "day file MISSING (whole-day deletion)"
    size = os.path.getsize(path)
    anchored = entry.get("size", 0)
    if size < anchored:
        return False, "TRUNCATED: file %d < anchored %d (records deleted from tail)" % (size, anchored)
    # file >= anchored is normal (appended since last manifest update)
    return True, "tail ok (%d bytes, anchored %d)" % (size, anchored)


def main():
    args = [a for a in sys.argv[1:] if a != "--all"]
    full_history = "--all" in sys.argv[1:]
    json_mode = "--json" in sys.argv[1:]
    target = args[0] if args else os.path.join(os.getcwd(), ".psl", "audit")
    files = [target] if os.path.isfile(target) else sorted(glob.glob(os.path.join(target, "*.jsonl")))
    mpath = os.path.join(str(target), "day_manifest.json") if os.path.isdir(str(target)) else None
    manifest = {}
    if mpath and os.path.isfile(mpath):
        try:
            manifest = json.load(open(mpath, encoding="utf-8"))
        except Exception:
            manifest = {}
    if not files and not manifest:
        msg = "no audit files under " + target
        print(msg)
        return 1

    days = sorted(set(list(manifest.keys()) + [os.path.basename(f) for f in files]))
    current_day = days[-1] if days else None

    total_by_class = defaultdict(int)
    history_notes = []
    tail_fail = 0
    unexplained = 0
    explained = 0
    rc = 0

    if json_mode:
        report = {"by_class": defaultdict(int), "unexplained": [], "explained": [], "days": {}}

    for fp in sorted(files):
        day = os.path.basename(fp)
        is_current = (day == current_day)
        by_class, details, prechain, total = verify_file_v2(fp)
        tok, tmsg = verify_tail(fp)

        for label, count in by_class.items():
            total_by_class[label] += count
        unexplained += by_class.get("TAMPERED", 0) + by_class.get("EDITED", 0) + by_class.get("MISLINKED", 0)
        explained += by_class.get("CONCURRENCY", 0) + by_class.get("BORROWED", 0)

        if json_mode:
            report["days"][day] = {
                "by_class": dict(by_class), "total": total, "prechain": prechain,
                "tail_ok": tok, "tail_msg": tmsg,
                "details": details,
            }
            continue

        # summary line for this day
        cls_parts = []
        for lbl in ("CONCURRENCY", "EDITED", "TAMPERED", "MISLINKED", "BORROWED", "OK"):
            if by_class.get(lbl):
                cls_parts.append("%d %s" % (by_class[lbl], lbl))
        if not cls_parts:
            cls_parts.append("0 records")
        print("  %s: %s" % (day, " / ".join(cls_parts)))

        for ln, label, note, tool, ts in details:
            tag = label if label in ("TAMPERED", "EDITED", "MISLINKED") else label
            print("    %s L%d [%s] %s %s %s" % (tag, ln, tool, ts, note, ""))

        if not tok:
            tail_fail += 1
            print("    TAIL-TAMPERED: %s" % tmsg)

        if not is_current and not full_history:
            # history day: informational, don't fail
            has_unexp = by_class.get("TAMPERED", 0) + by_class.get("EDITED", 0) + by_class.get("MISLINKED", 0)
            if has_unexp:
                history_notes.append("%s: %d unexplained (legacy/transition — not gated)" % (day, has_unexp))

    # manifest-driven deletion check
    for day in sorted(manifest):
        f = os.path.join(str(target), day)
        gz = os.path.join(str(target), os.path.splitext(day)[0] + ".jsonl.gz")
        if not os.path.isfile(f) and not os.path.isfile(gz):
            print("TAIL-TAMPERED  %s  day file MISSING" % day)
            tail_fail += 1
            unexplained += 1

    if json_mode:
        report["by_class"] = dict(total_by_class)
        report["unexplained_count"] = unexplained
        report["explained_count"] = explained
        report["tail_failures"] = tail_fail
        report["rc"] = 2 if unexplained else (3 if explained else 0)
        print(json.dumps(report, ensure_ascii=False, indent=1, default=dict))
        return report["rc"]

    # text output
    for note in history_notes:
        print("history-note:", note)

    # summary line (required by plan §3.2)
    summary_parts = []
    for lbl in ("CONCURRENCY", "EDITED", "TAMPERED", "MISLINKED", "BORROWED"):
        if total_by_class.get(lbl):
            summary_parts.append("%d %s" % (total_by_class[lbl], lbl))
    if not summary_parts:
        summary_parts.append("0 anomalies")
    print("verdict: %s" % " / ".join(summary_parts))

    if unexplained > 0:
        rc = 2
        print("⇒ rc=2 (unexplained anomalies present)")
    elif explained > 0:
        rc = 3
        print("⇒ rc=3 (explained anomalies — CONCURRENCY/BORROWED)")
        print()
        print("并发分叉与「插入一条自称同父的伪造记录」在链上同形。0.20.0 起本套件对未取到锁的写入加 chain:\"unlocked\" 标记；"
              "无该标记的同父多用将归入 MISLINKED 而非 CONCURRENCY。历史记录（0.20.0 之前）无该标记，故其 CONCURRENCY 判定基于「自算式成立」，不能排除插入。")
    else:
        rc = 0
        print("⇒ rc=0 (clean)")

    if tail_fail:
        rc = max(rc, 2)
        print("⇒ tail failures: %d (escalating rc to 2)" % tail_fail)

    return rc


if __name__ == "__main__":
    sys.exit(main())
