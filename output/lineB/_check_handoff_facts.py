# -*- coding: utf-8 -*-
"""核对交接单要不要改：① 10-31 末条 / 11-01 首条 时刻；② E6b Bash 拆分现状。"""
import json, os, sys, collections

AUDIT = os.path.join("D:/psl/poc/antinel-security", ".psl", "audit")


def load():
    recs = []
    for f in sorted(os.listdir(AUDIT)):
        if not f.endswith(".jsonl") or not f[:4].isdigit():
            continue
        p = os.path.join(AUDIT, f)
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    recs.append(json.loads(line))
                except Exception:
                    pass
    return recs


def tail_of(day):
    p = os.path.join(AUDIT, day + ".jsonl")
    if not os.path.isfile(p):
        return None
    lines = [l for l in open(p, encoding="utf-8", errors="replace") if l.strip()]
    if not lines:
        return None
    r = json.loads(lines[-1])
    return r.get("ts"), r.get("type"), r.get("tool"), len(lines)


def head_of(day):
    p = os.path.join(AUDIT, day + ".jsonl")
    if not os.path.isfile(p):
        return None
    lines = [l for l in open(p, encoding="utf-8", errors="replace") if l.strip()]
    if not lines:
        return None
    r = json.loads(lines[0])
    return r.get("ts"), r.get("type"), len(lines)


print("=== 10-31 末条 / 11-01 首条 ===")
print("10-31 tail:", tail_of("2026-10-31"))
print("11-01 head:", head_of("2026-11-01"))
print("11-01 tail:", tail_of("2026-11-01"))

recs = load()
print("\n总记录: %d" % len(recs))
calls = [r for r in recs if r.get("type") == "pre_tool_use"]
print("pre_tool_use: %d" % len(calls))
days = sorted({str(r.get("ts"))[:10] for r in recs if r.get("ts")})
print("覆盖日期数: %d  (%s .. %s)" % (len(days), days[0], days[-1]))
