# SPDX-License-Identifier: CC-BY-SA-4.0
# 一次性量具：量清两件事，然后删（不进发布包，不进 antinel/）
#   1. (type, decision, action) 三元组的真实分布 —— 协同说明坑 1/2
#   2. 「日锚」到底是什么字段 —— 协同说明坑 4（31/33 天）
# 只读，零写入。
import collections
import json
import os
import sys

ROOT = ".psl/audit"


def day_files(root):
    out = []
    for n in sorted(os.listdir(root)):
        if n.endswith(".jsonl") and len(n) == 16 and n[4] == "-":
            out.append(os.path.join(root, n))
    return out


def iter_recs(root):
    for p in day_files(root):
        day = os.path.basename(p)[:10]
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for ln, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if isinstance(r, dict):
                    yield day, ln, r


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    tri = collections.Counter()
    keys_seen = collections.Counter()
    per_day_keys = collections.defaultdict(set)
    n = 0
    for day, _ln, r in iter_recs(ROOT):
        n += 1
        for k in r:
            keys_seen[k] += 1
            per_day_keys[day].add(k)
        tri[(r.get("type"), r.get("decision"), r.get("action"))] += 1

    print("=== 总记录 %d ===" % n)
    print()
    print("=== 字段出现次数（前 30）===")
    for k, v in keys_seen.most_common(30):
        print("  %-24s %7d" % (k, v))

    print()
    print("=== (type, decision, action) 分布 ===")
    for (t, d, a), c in tri.most_common(60):
        print("  %-18s decision=%-10s action=%-8s %7d" % (t, d, a, c))

    print()
    print("=== 每个日文件的字段集合（找「日锚」候选）===")
    days = sorted(per_day_keys)
    for day in days:
        ks = per_day_keys[day]
        has = [k for k in ("session_dna", "dna", "anchor", "day_anchor", "day_hash",
                           "prev_hash", "chain_hash", "manifest") if k in ks]
        print("  %s  nkeys=%2d  %s" % (day, len(ks), ",".join(has) if has else "-"))


if __name__ == "__main__":
    main()
