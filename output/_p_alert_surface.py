#!/usr/bin/env python
# SPDX-License-Identifier: CC-BY-SA-4.0
"""一次性量具（不进随包面）：全期「值得人看一眼」的记录到底有多少，怎么聚。

三个问题：
  1. 规则号还有哪些来源？已知 rules_hit / hits[].rule_id / rule_id；
     但 type 名里可能自带规则（如 dst02_bash_path_suspect），
     还有 reason 文本里可能带规则号。漏掉它们＝分母错（铁律 22）。
  2. alert（告警但放行）侧有多少？C 线现在一条不读。
  3. 聚到「同规则 × 同会话 × 同天」后，一页纸装得下吗？
"""
from __future__ import annotations

import glob
import json
import os
import re
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(ROOT, ".psl", "audit")

#: type 名里自带规则族的形态
TYPE_RULE_RE = re.compile(r"^(?:dst\d+|an|sec|ctx|gov)_", re.IGNORECASE)
#: reason / match_snippet 里出现的规则号
TEXT_RULE_RE = re.compile(r"\b([A-Z]{2,4}-\d{2,4})\b")


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


def text_rules(rec: dict) -> list:
    blob = " ".join(
        str(rec.get(k, "")) for k in ("reason", "match_snippet", "snippet", "subkind")
    )
    return sorted(set(TEXT_RULE_RE.findall(blob)))


def type_family(rec: dict) -> str:
    t = str(rec.get("type", ""))
    m = TYPE_RULE_RE.match(t)
    return m.group(0).upper() if m else ""


def main() -> None:
    decision_c = Counter()
    # 规则号来源覆盖
    src_c = Counter()
    alert_trace = Counter()
    alert_rules = Counter()
    alert_types = Counter()
    # 聚合格
    alert_cluster = Counter()
    block_cluster = Counter()
    all_verdict_trace = Counter()

    for path in sorted(glob.glob(os.path.join(LEDGER, "*.jsonl"))):
        day = os.path.basename(path)[:10]
        with open(path, encoding="utf-8") as fh:
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
                d = rec.get("decision")
                if d:
                    decision_c[d] += 1
                rids = rule_ids(rec)
                if rids:
                    src_c["结构化字段"] += 1
                if type_family(rec):
                    src_c["type 名带族"] += 1
                tr = text_rules(rec)
                if tr:
                    src_c["文本含规则号"] += 1
                if d == "alert":
                    alert_types[rec.get("type", "?")] += 1
                    if rids or tr or type_family(rec):
                        alert_trace["可回指"] += 1
                    else:
                        alert_trace["不可回指"] += 1
                    for r in (rids or tr or ([type_family(rec)] if type_family(rec) else [])):
                        alert_rules[r] += 1
                    alert_cluster[
                        (
                            day,
                            rec.get("session", "")[:8],
                            ",".join(sorted(rids or tr or [type_family(rec)])),
                        )
                    ] += 1
                if d in ("block", "deny"):
                    all_verdict_trace[
                        (
                            day,
                            rec.get("session", "")[:8],
                            ",".join(sorted(rids or tr or [type_family(rec)] or ["<无>"])),
                        )
                    ] += 1

    print("【1】decision 分布（全期）")
    for k, v in decision_c.most_common():
        print(f"   {k:>18} {v:>8}")
    print()
    print("【2】规则号来源覆盖（同一记录可多来源，故合计 > 记录数）")
    for k, v in src_c.most_common():
        print(f"   {k:>14} {v:>8}")
    print()
    print("【3】alert（告警但放行）侧 —— C 线今天一条不读")
    tot_alert = alert_trace["可回指"] + alert_trace["不可回指"]
    print(f"   总计 {tot_alert} 条｜可回指 {alert_trace['可回指']}"
          f" = {alert_trace['可回指'] / max(tot_alert, 1) * 100:.1f}%")
    print("   alert 的 type top 8：")
    for k, v in alert_types.most_common(8):
        print(f"      {k:>32} {v:>6}")
    print("   alert 命中的规则 top 12：")
    for k, v in alert_rules.most_common(12):
        print(f"      {k:>16} {v:>6}")
    print()
    print("【4】聚合后一天要装几条（规则×会话×天）")
    by_day = Counter()
    for (day, sess, rid), n in alert_cluster.items():
        by_day[day] += 1
    recent = sorted(by_day)[-8:]
    print("   alert 聚合后，每天条数：")
    for day in recent:
        print(f"      {day}  {by_day[day]:>5}")
    if recent:
        vals = [by_day[d] for d in recent]
        print(f"   近 8 天：中位 {sorted(vals)[len(vals)//2]}｜最大 {max(vals)}｜最小 {min(vals)}")
    print()
    print("【5】裁决侧聚合（规则×会话×天）")
    bday = Counter()
    for (day, sess, rid), n in block_cluster.items() or []:
        bday[day] += 1
    bday = Counter()
    for (day, sess, rid), n in all_verdict_trace.items():
        bday[day] += 1
    print("   近 8 天：")
    for day in sorted(bday)[-8:]:
        print(f"      {day}  {bday[day]:>5}")
    print()
    print("这条量具不能证明什么：")
    print("  · 不能证明 alert 应该给人看（产品判断）。")
    print("  · 「type 名带族」与「文本含规则号」是启发式抽取，可能误命中。")
    print("  · 能证明的只有一句：分母不是 4，是几千；而且它们可以按规则聚。")


if __name__ == "__main__":
    main()
