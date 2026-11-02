#!/usr/bin/env python
# SPDX-License-Identifier: CC-BY-SA-4.0
"""一次性量具（不进随包面）：算「主动性线真正面对的分母」。

要回答四件事：
  1. 11-02 当天到底发生了多少事？（真实分母，不是报告里的 4 条）
  2. 按通知面（产品侧 notify_policy 的口径）分流后，各档多少？
  3. 「需要人看一眼」如果按 规则×会话×天 聚合，一天有几簇？
  4. 宿主盾自检事件（守卫自己没上班）有没有被"守住了"误读？

口径全部照抄产品侧现成实现，不自造：
  · 通知面回退表：hooks/notify_policy.py 的 _NOTIFY_OF_DECISION
  · 非事件排除表：hooks/notify_policy.py 的 NON_EVENT_TYPES
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

# ── 产品侧现成口径（逐字照抄 hooks/notify_policy.py）────────────────────
_NOTIFY_OF_DECISION = {
    "block": "GATE",
    "deny": "GATE",
    "alert": "TOAST",
    "warn": "TOAST",
    "config_fallback": "TOAST",
    "config_rejected": "TOAST",
    "finding": "TOAST",
    "config_refresh": "NONE",
    "allow": "NONE",
}
NON_EVENT_TYPES = frozenset((
    "usage_delta",
    "session_dna",
    "pre_tool_use_summary",
    "notice_budget_window_closed",
    "notice_budget_merged",
))
NON_VERDICT_DECISION = {"config_refresh", "config_fallback"}
# ───────────────────────────────────────────────────────────────────────

RULE_RE = re.compile(r"\b([A-Z]{2,5}-\d{2,3})\b")
TYPE_FAM_RE = re.compile(r"^(dst\d+|an|sec|ctx|gov)_", re.IGNORECASE)


def rule_ids(rec: dict) -> list:
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


def main() -> None:
    path = os.path.join(LEDGER, DAY + ".jsonl")
    total = 0
    type_c = Counter()
    notify_c = Counter()
    non_event = 0
    gate_cl = Counter()          # 通知面 GATE 的簇（规则×会话×天）
    toast_cl = Counter()
    shield_events = Counter()
    shield_critical = 0
    shield_samples = []
    gate_samples = []
    toast_samples = []

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
            total += 1
            t = rec.get("type", "?")
            type_c[t] += 1

            # 宿主盾自检事件（守卫自己没上班）
            if str(t).startswith("host_shield_"):
                shield_events[t] += 1
                if rec.get("severity") == "critical":
                    shield_critical += 1
                if len(shield_samples) < 3:
                    shield_samples.append({
                        "line": lineno, "type": t,
                        "decision": rec.get("decision"),
                        "severity": rec.get("severity"),
                        "reason": str(rec.get("reason"))[:110],
                    })
                continue

            # 通知面：先排非事件 type
            if t in NON_EVENT_TYPES:
                non_event += 1
                continue
            d = rec.get("decision")
            if d in NON_VERDICT_DECISION:
                continue
            if d is None:
                continue
            face = _NOTIFY_OF_DECISION.get(d)
            if face is None:
                continue
            if face == "NONE":
                continue
            notify_c[face] += 1

            rids = rule_ids(rec)
            fam = TYPE_FAM_RE.match(str(t))
            key_rule = ",".join(sorted(rids)) if rids else (
                fam.group(0).upper() if fam else "<无规则号>")
            sess = str(rec.get("session", ""))[:8]
            cl = (sess, key_rule)
            if face == "GATE":
                gate_cl[cl] += 1
                if len(gate_samples) < 3:
                    gate_samples.append({
                        "line": lineno, "tool": rec.get("tool"),
                        "decision": d, "action": rec.get("action"),
                        "severity": rec.get("severity"),
                        "rules": rids or [key_rule],
                        "reason": str(rec.get("reason"))[:100],
                    })
            else:
                toast_cl[cl] += 1
                if len(toast_samples) < 3:
                    toast_samples.append({
                        "line": lineno, "tool": rec.get("tool"),
                        "decision": d, "rules": rids or [key_rule],
                    })

    print(f"账本日文件：{DAY}.jsonl")
    print(f"【1】当天记录总数（真实分母）：{total} 条")
    print()
    print("【2】通知面分流（照抄产品侧 notify_policy 口径）")
    print(f"   GATE（挡下，必须让人知道）：{notify_c['GATE']}")
    print(f"   TOAST（提醒，但没拦）：    {notify_c['TOAST']}")
    print(f"   非事件 type（结构上不是事件）：{non_event}")
    print()
    print("【3】按「会话 × 规则」聚合后要装几簇")
    print(f"   GATE  {len(gate_cl)} 簇（原 {notify_c['GATE']} 条）")
    print(f"   TOAST {len(toast_cl)} 簇（原 {notify_c['TOAST']} 条）")
    print(f"   合计 {len(gate_cl) + len(toast_cl)} 簇"
          f"  ← 一页纸的候选量")
    print()
    print("【4】宿主盾自检事件（『守卫自己没上班』，不是『守住了』）")
    for k, v in shield_events.most_common():
        print(f"   {k:>28} {v:>5}")
    print(f"   合计 {sum(shield_events.values())} 条｜其中 critical {shield_critical}")
    for s in shield_samples:
        print("   ", json.dumps(s, ensure_ascii=False))
    print()
    print("【5】GATE 样本（真挡下，带规则号）")
    for s in gate_samples:
        print("   ", json.dumps(s, ensure_ascii=False))
    print()
    print("【6】TOAST 样本（提醒但放行）")
    for s in toast_samples:
        print("   ", json.dumps(s, ensure_ascii=False))
    print()
    print("这条量具不能证明什么：")
    print("  · 不能证明这些该给人看（产品判断，属创始人拍板）。")
    print("  · 聚合键「会话×规则」是我选的一种，不是唯一正确分法。")
    print("  · 能证明的只有一句：当天真实分母是几万条量级，"
          "一页纸的候选量是几十簇量级，而报告里的分母是 4。")


if __name__ == "__main__":
    main()
