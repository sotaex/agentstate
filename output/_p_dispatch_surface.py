#!/usr/bin/env python
# SPDX-License-Identifier: CC-BY-SA-4.0
"""一次性量具（不进随包面）：把「今天真的挡下了什么」拆到可行动粒度。

用途：支撑《报告形态：七问的天花板与替代方案》的实证基础。
本量具只描述账本里有什么，不主张 C 线「应该」读它们（那是产品判断）。

三件事：
  1. 三种「挡下」记录形态各自有多少（字段名不同，统计口径易漏）。
  2. 11-02 当天的 43 次挡下，去重到「规则 × 动作 × 可回指」后还剩多少条。
  3. 如果按「同一规则同一会话同一天聚成一条」，一页纸装得下吗。
"""
from __future__ import annotations

import glob
import json
import os
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(ROOT, ".psl", "audit")

#: 裁决＝动作真的没执行（block / deny 两种拼法）
VERDICTS = {"block", "deny"}


def iter_records(root: str):
    for path in sorted(glob.glob(os.path.join(root, "*.jsonl"))):
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
                if isinstance(rec, dict):
                    yield day, lineno, rec


def rule_ids(rec: dict) -> list:
    """把三种形态的规则号取出来，统一成列表。

    形态 A（pre_tool_use）：      rules_hit: ["AN-010"]
    形态 B（pre_tool_use_summary）：hits: [{"rule_id": ...}]
    形态 C（command_deletion_permission）：rule_id: "AN-009"
    """
    out = []
    for rid in rec.get("rules_hit") or []:
        if isinstance(rid, str):
            out.append(rid)
        elif isinstance(rid, dict) and rid.get("rule_id"):
            out.append(str(rid["rule_id"]))
    for h in rec.get("hits") or []:
        if isinstance(h, dict) and h.get("rule_id"):
            out.append(str(h["rule_id"]))
    rid = rec.get("rule_id")
    if isinstance(rid, str) and rid:
        out.append(rid)
    seen = []
    for r in out:
        if r not in seen:
            seen.append(r)
    return seen


def shape_of(rec: dict) -> str:
    if "hits" in rec:
        return "B_summary"
    if "rules_hit" in rec:
        return "A_pre_tool_use"
    if "rule_id" in rec:
        return "C_deletion"
    return "D_no_rule_field"


def main() -> None:
    print("账本目录：", LEDGER)
    day_files = sorted(
        os.path.basename(p)[:10]
        for p in glob.glob(os.path.join(LEDGER, "*.jsonl"))
    )
    total = 0
    decision_c = Counter()
    shape_c = Counter()
    verdict_by_day = Counter()
    verdict_total = 0
    verdict_traceable = 0
    verdict_shapes = Counter()
    rule_c = Counter()
    # 形态 A 与 B 是同一次裁决的两条记录（事件 + 汇总），需去重
    pair_key_c = Counter()
    sample = []

    for day, lineno, rec in iter_records(LEDGER):
        total += 1
        d = rec.get("decision")
        if d:
            decision_c[d] += 1
        if d in VERDICTS:
            verdict_total += 1
            verdict_by_day[day] += 1
            s = shape_of(rec)
            verdict_shapes[s] += 1
            shape_c[s] += 1
            rids = rule_ids(rec)
            if rids:
                verdict_traceable += 1
                for r in rids:
                    rule_c[r] += 1
            # 去重键：同一天 + 同会话 + 同一组规则 + 同一动作
            key = (
                day,
                rec.get("session", ""),
                rec.get("action") or d,
                ",".join(sorted(rids)),
                (rec.get("match_snippet") or rec.get("reason") or "")[:80],
            )
            pair_key_c[key] += 1
            if len(sample) < 6:
                sample.append(
                    {
                        "day": day,
                        "line": lineno,
                        "type": rec.get("type"),
                        "shape": s,
                        "decision": d,
                        "action": rec.get("action"),
                        "rules": rids,
                        "traceable": bool(rids),
                    }
                )

    print(f"日文件：{len(day_files)} 个（{day_files[0]} .. {day_files[-1]}）｜记录：{total} 条")
    print()
    print("【口径 1】decision 分布（全期）")
    for k, v in decision_c.most_common():
        mark = "←裁决" if k in VERDICTS else ""
        print(f"   {k:>8} {v:>8} {mark}")
    print()
    print("【口径 2】裁决记录的三种形态")
    for k, v in verdict_shapes.most_common():
        print(f"   {k:>16} {v:>8}")
    print(f"   合计 {verdict_total} 条｜可回指（带规则号）{verdict_traceable} 条"
          f" = {verdict_traceable / max(verdict_total, 1) * 100:.1f}%")
    print()
    print("【口径 3】最近 10 天每天的裁决数")
    for day in sorted(verdict_by_day)[-10:]:
        print(f"   {day}  {verdict_by_day[day]:>6}")
    print()
    print("【口径 4】裁决命中的规则（去重前，按条）")
    for k, v in rule_c.most_common(15):
        print(f"   {k:>12} {v:>6}")
    print()
    print("【口径 5】去重后（天×会话×动作×规则×片段 相同视为一次）")
    print(f"   原始裁决记录 {verdict_total} 条 → 去重后 {len(pair_key_c)} 条")
    dup = Counter(pair_key_c.values())
    print(f"   重复分布：{dict(sorted(dup.items()))}")
    print()
    print("【口径 6】按「规则 × 天」聚合（≈ 每条规则每天一条）")
    agg = set()
    for key in pair_key_c:
        agg.add((key[0], key[3]))
    print(f"   规则×天 组合数：{len(agg)}")
    print()
    print("【样本】")
    for s in sample:
        print("  ", json.dumps(s, ensure_ascii=False))
    print()
    print("这条量具不能证明什么：")
    print("  · 不能证明这些 block/deny 是真发现（可能含夹具、可能重复计数）。")
    print("  · 不能证明 C 线「应该」读它们（那是产品判断，属创始人拍板）。")
    print("  · 能证明的只有一句：它们在账本里，且多数带规则号、行号与会话号。")


if __name__ == "__main__":
    main()
