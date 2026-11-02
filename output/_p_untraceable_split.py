#!/usr/bin/env python
# SPDX-License-Identifier: CC-BY-SA-4.0
"""一次性量具（不进随包面）：把「不可回指的裁决」拆开，看它到底是什么。

上一个量具的发现：2033 条裁决里 1029 条（50.6%）不带规则号。
样本显示它们是 host_shield_spawn_failed / host_shield_tamper ——
即**宿主盾自己起不来**，不是规则命中。两者都写作 decision=deny，
但语义完全相反：一个是「守住了」，一个是「守卫没上班」。

铁律 44：同值不同义，比不同值更难发现。
"""
from __future__ import annotations

import glob
import json
import os
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(ROOT, ".psl", "audit")
VERDICTS = {"block", "deny"}


def main() -> None:
    types_all = Counter()
    types_d = Counter()
    actions_d = Counter()
    sev_d = Counter()
    by_day_d = Counter()
    # 工具故障类 vs 规则命中类
    fault_like = Counter()
    samples = defaultdict(list)

    for path in sorted(glob.glob(os.path.join(LEDGER, "*.jsonl"))):
        day = os.path.basename(path)[:10]
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if not isinstance(rec, dict):
                    continue
                t = rec.get("type", "?")
                types_all[t] += 1
                if rec.get("decision") not in VERDICTS:
                    continue
                has_rule = bool(
                    rec.get("rules_hit")
                    or rec.get("hits")
                    or rec.get("rule_id")
                )
                if has_rule:
                    continue
                types_d[t] += 1
                actions_d[rec.get("action")] += 1
                sev_d[rec.get("severity")] += 1
                by_day_d[day] += 1
                fault_like[t] += 1
                if len(samples[t]) < 2:
                    samples[t].append(
                        {
                            "day": day,
                            "line": lineno,
                            "type": t,
                            "decision": rec.get("decision"),
                            "action": rec.get("action"),
                            "severity": rec.get("severity"),
                            "reason": str(rec.get("reason"))[:160],
                            "tool": rec.get("tool"),
                            "host": rec.get("host"),
                        }
                    )

    total_d = sum(types_d.values())
    print(f"不可回指的裁决：{total_d} 条")
    print()
    print("【A】按 type 拆")
    for k, v in types_d.most_common():
        print(f"   {k:>34} {v:>6}   {v / max(total_d, 1) * 100:>5.1f}%")
    print()
    print("【B】按 action（null 表示没有这个字段）")
    for k, v in actions_d.most_common():
        print(f"   {str(k):>10} {v:>6}")
    print()
    print("【C】按 severity")
    for k, v in sev_d.most_common():
        print(f"   {str(k):>10} {v:>6}")
    print()
    print("【D】最近 8 天每天的不可回指裁决数")
    for day in sorted(by_day_d)[-8:]:
        print(f"   {day}  {by_day_d[day]:>5}")
    print()
    print("【E】样本（每类 2 条）")
    for t, ss in samples.items():
        for s in ss:
            print(f"   [{t}] {json.dumps(s, ensure_ascii=False)}")
    print()
    print("【F】全期 type 分布 top 12（对照：裁决只是其中一小类）")
    for k, v in types_all.most_common(12):
        print(f"   {k:>34} {v:>7}")
    print()
    print("这条量具不能证明什么：")
    print("  · 不能证明 host_shield 故障应该出现在一页纸里（那是产品判断）。")
    print("  · 能证明的只有一句：同写着 decision=deny，一半是「规则挡住了」，")
    print("    一半是「守卫自己没上班」——只按 decision 统计会把两者混成同一个数。")


if __name__ == "__main__":
    main()
