# SPDX-License-Identifier: CC-BY-SA-4.0
# -*- coding: utf-8 -*-
"""一次性量具：查清「弹窗」到底是谁在弹。

三条线：
  A 今天审计流里 action/decision 的分布（有没有 block/alert 在弹）
  B 最近 N 条记录的 rule_id 排行（哪条规则最活跃）
  C 近 30 分钟内的事件时间线（弹窗是"反复"出现的，要看频率）

不做任何判断，只出数。判定留给调用方。
"""
import json
import os
import sys
import time
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUD = os.path.join(ROOT, ".psl", "audit")


def load_day(path):
    rows = []
    bad = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except Exception:
                bad += 1
    return rows, bad


def main():
    today = time.strftime("%Y-%m-%d")
    path = os.path.join(AUD, today + ".jsonl")
    if not os.path.exists(path):
        print("NO FILE:", path)
        return 2
    rows, bad = load_day(path)
    print("FILE      :", path)
    print("ROWS      :", len(rows), " PARSE_FAIL:", bad)
    if not rows:
        return 0

    print("\n--- A 字段结构（首条 keys） ---")
    print(sorted(rows[0].keys()))

    print("\n--- B decision 分布（今天全量） ---")
    for k, v in Counter(str(r.get("decision")) for r in rows).most_common(20):
        print("  %-24s %6d" % (k, v))

    print("\n--- C action 分布（今天全量） ---")
    for k, v in Counter(str(r.get("action")) for r in rows).most_common(20):
        print("  %-24s %6d" % (k, v))

    print("\n--- D rule_id 排行（今天全量，前 25） ---")
    for k, v in Counter(str(r.get("rule_id")) for r in rows).most_common(25):
        print("  %-24s %6d" % (k, v))

    # 只看有实质处置的（非空 action 且不是 allow/pass/none）
    NOOP = {"", "None", "allow", "pass", "none", "log", "logged"}
    acted = [r for r in rows if str(r.get("action")) not in NOOP]
    print("\n--- E 有实质 action 的记录：%d / %d ---" % (len(acted), len(rows)))
    for k, v in Counter(str(r.get("action")) for r in acted).most_common(20):
        print("  %-24s %6d" % (k, v))
    print("  按 rule_id：")
    for k, v in Counter(str(r.get("rule_id")) for r in acted).most_common(20):
        print("    %-22s %6d" % (k, v))

    print("\n--- F 最近 15 条（时间线，看频率） ---")
    for r in rows[-15:]:
        ts = r.get("ts") or r.get("time") or r.get("timestamp") or "?"
        print("  %-22s %-10s %-10s %-10s %s" % (
            str(ts)[:19], str(r.get("rule_id"))[:10],
            str(r.get("decision"))[:10], str(r.get("action"))[:10],
            str(r.get("tool_name") or r.get("tool") or "")[:30]))

    print("\n--- G 近 60 分钟按分钟聚合（弹窗若反复出现，这里会有峰） ---")
    now = time.time()
    per_min = Counter()
    for r in rows:
        ts = r.get("ts") or r.get("time") or r.get("timestamp")
        if not ts:
            continue
        s = str(ts).replace("T", " ")[:19]
        try:
            t = time.mktime(time.strptime(s, "%Y-%m-%d %H:%M:%S"))
        except Exception:
            continue
        if now - t <= 3600:
            per_min[s[:16]] += 1
    if not per_min:
        print("  （近 60 分钟无事件，或时间字段解析不了）")
    for k in sorted(per_min):
        print("  %s  %4d  %s" % (k, per_min[k], "#" * min(60, per_min[k])))

    return 0


if __name__ == "__main__":
    sys.exit(main())
