# -*- coding: utf-8 -*-
"""核对跨日间隔是否异常：heartbeat 的常规间隔分布 vs 23:58:43→00:08:44 这 10 分钟。"""
import json, os, datetime as dt, collections

AUDIT = os.path.join("D:/psl/poc/antinel-security", ".psl", "audit")


def ts(s):
    try:
        return dt.datetime.fromisoformat(s)
    except Exception:
        return None


hb = []
for f in sorted(os.listdir(AUDIT)):
    if not f.endswith(".jsonl") or not f[:4].isdigit():
        continue
    for line in open(os.path.join(AUDIT, f), encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("type") == "host_shield_heartbeat":
            t = ts(r.get("ts"))
            if t:
                hb.append(t)

hb.sort()
print("heartbeat 记录 %d 条，从 %s 到 %s" % (len(hb), hb[0], hb[-1]))

gaps = [(b - a).total_seconds() for a, b in zip(hb, hb[1:])]
gaps_sorted = sorted(gaps)
n = len(gaps_sorted)
print("\n间隔分布（秒）：min=%.0f  p50=%.0f  p90=%.0f  p99=%.0f  max=%.0f"
      % (gaps_sorted[0], gaps_sorted[n // 2], gaps_sorted[int(n * 0.9)],
         gaps_sorted[int(n * 0.99)], gaps_sorted[-1]))

buckets = collections.Counter()
for g in gaps:
    if g <= 120:
        buckets["<=2min"] += 1
    elif g <= 600:
        buckets["2-10min"] += 1
    elif g <= 3600:
        buckets["10-60min"] += 1
    else:
        buckets[">1h"] += 1
for k in ["<=2min", "2-10min", "10-60min", ">1h"]:
    print("  %-10s %d" % (k, buckets[k]))

# 跨日那一段具体在哪
print("\n=== 跨日相邻对 ===")
for a, b in zip(hb, hb[1:]):
    if a.date() != b.date():
        print("  %s → %s  间隔 %.0f 秒（%.1f 分钟）" % (a, b, (b - a).total_seconds(),
                                                    (b - a).total_seconds() / 60))
