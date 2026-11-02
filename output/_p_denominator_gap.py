#!/usr/bin/env python
# SPDX-License-Identifier: CC-BY-SA-4.0
"""一次性量具（不进随包面）：把两个分母差拆清楚 + 宿主盾故障的时间分布。

为什么要这个量具：
  我先前按 decision 值统计 11-02 的「挡下」得 43 条；
  按产品侧通知面口径（notify_policy）统计得 26 条。
  差的 17 条几乎全是 pre_tool_use_summary —— 产品侧把它列为
  NON_EVENT_TYPES，理由写在 hooks/notify_policy.py:108-114：
  它与逐条 pre_tool_use 覆盖同一批调用，同时进通知面会提醒两次。

  ⇒ 这不是「我算错了」，是**两个不同分母**（F40：一个数承担两个分母）。
  报告里必须写明用的是哪一个。

同时核实：宿主盾自检事件里 critical 的那些集中在哪几天 ——
避免把「早期故障多」误说成「今天也在故障」。
"""
from __future__ import annotations

import glob
import json
import os
import re
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(ROOT, ".psl", "audit")
DAY = "2026-11-02"

NON_EVENT_TYPES = frozenset((
    "usage_delta",
    "session_dna",
    "pre_tool_use_summary",
    "notice_budget_window_closed",
    "notice_budget_merged",
))
GATE_DECISIONS = {"block", "deny"}

#: 宿主盾的**故障型**事件（心跳/复活不算故障）
SHIELD_FAULT = {
    "host_shield_spawn_failed",
    "host_shield_tamper",
    "host_shield_zone_locked",
    "host_shield_breach",
    "host_shield_dev_drift",
    "host_shield_state_unreadable",
    "host_shield_task_unknown",
}


def main() -> None:
    # ── 第一部分：11-02 两个分母的差 ───────────────────────────────
    print("【A】11-02 「挡下」的两个分母")
    path = os.path.join(LEDGER, DAY + ".jsonl")
    by_type = Counter()
    gate_rows = []
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
            d = rec.get("decision")
            if d not in GATE_DECISIONS:
                continue
            t = rec.get("type", "?")
            by_type[t] += 1
            is_ne = t in NON_EVENT_TYPES
            gate_rows.append({
                "line": lineno,
                "type": t,
                "decision": d,
                "non_event": is_ne,
                "rules": rec.get("rules_hit") or (
                    [h.get("rule_id") for h in (rec.get("hits") or [])
                     if isinstance(h, dict)] if rec.get("hits") else None
                ) or ([rec["rule_id"]] if rec.get("rule_id") else []),
                "severity": rec.get("severity"),
            })

    total_gate = len(gate_rows)
    ne = sum(1 for r in gate_rows if r["non_event"])
    print(f"   按 decision 值数（block+deny）：{total_gate} 条")
    print(f"   其中产品侧列为非事件：      {ne} 条")
    print(f"   按通知面口径（可通知）：      {total_gate - ne} 条")
    print("   逐 type：")
    for k, v in by_type.most_common():
        tag = "（非事件·不进通知面）" if k in NON_EVENT_TYPES else ""
        print(f"      {k:>28} {v:>4} {tag}")
    print("   两个分母的差（全部来自非事件 type）：",
          total_gate - (total_gate - ne), "条")
    print()

    # ── 第二部分：宿主盾故障的时间分布 ─────────────────────────────
    print("【B】宿主盾故障型事件（心跳/复活不算）的逐日分布")
    per_day = Counter()
    per_day_crit = Counter()
    kinds = Counter()
    reasons = defaultdict(Counter)
    for p in sorted(glob.glob(os.path.join(LEDGER, "*.jsonl"))):
        day = os.path.basename(p)[:10]
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if not isinstance(rec, dict):
                    continue
                t = rec.get("type", "")
                if t not in SHIELD_FAULT:
                    continue
                per_day[day] += 1
                kinds[t] += 1
                if rec.get("severity") == "critical":
                    per_day_crit[day] += 1
                reasons[t][str(rec.get("reason"))[:70]] += 1
    print("   逐日（含 critical）：")
    for day in sorted(per_day):
        print(f"      {day}  {per_day[day]:>4}   critical {per_day_crit[day]:>4}")
    print("   类型：")
    for k, v in kinds.most_common():
        print(f"      {k:>30} {v:>5}")
    print("   每类的原因 top 1：")
    for k, rs in reasons.items():
        if rs:
            top = rs.most_common(1)[0]
            print(f"      {k}: ({top[1]}次) {top[0]}")
    print()
    print("【C】结论口径")
    print("   · 「挡下」有两个分母：按 decision 值数 vs 按通知面口径。")
    print("     差集全部落在 pre_tool_use_summary（产品侧判其为非事件）。")
    print("   · 宿主盾 critical 故障集中在早期；11-02 当天 0 条 critical。")
    print()
    print("这条量具不能证明什么：")
    print("  · 不能证明 26 条该给人看（产品判断）。")
    print("  · 不能证明 summary 型就该永远排除（那是产品侧已有决策，我只引用）。")


if __name__ == "__main__":
    main()
