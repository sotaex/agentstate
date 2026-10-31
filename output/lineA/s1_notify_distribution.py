#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""S1 验收：拿真实账本全量跑 `notify_of()`，输出可逐桶对账的分布。

★ 为什么需要这一步
  单测用的是合成样本（穷举取值）。合成样本能证明「函数照表办事」，
  不能证明「真数据过一遍不会崩、分布合理」。本项目的假绿第二族就是
  「夹具合成形状」—— 只有真账本能排掉它。

★ 自证（不做就不知道 0 是不是失明）
  ① 打印「读到几个文件、几条记录、跳过几条为什么跳过」；
  ② 打印 action×decision 全部实际组合，证明扫描面真的覆盖到矛盾记录；
  ③ 打印 `notify_of` 抛异常的次数（必须 0，且 0 也要自证跑过）。

用法（在 a064 树里跑，账本指回主树）：
    P=/c/Users/大马/.workbuddy/binaries/python/versions/3.13.12/python
    "$P" -E -X utf8 output/lineA/s1_notify_distribution.py \
        --audit-dir /d/psl/poc/antinel-security/.psl/audit

只读：不写账本、不改任何产品文件。
"""

import argparse
import collections
import glob
import importlib.util
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_POLICY = os.path.join(os.path.dirname(os.path.dirname(HERE)), "hooks", "notify_policy.py")


def load_policy(path):
    spec = importlib.util.spec_from_file_location("notify_policy_audit", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def is_daily_name(path):
    """只认 YYYY-MM-DD.jsonl —— `lock_events.jsonl` 不是日文件（按日期解析会读错）。"""
    base = os.path.basename(path)
    if not base.endswith(".jsonl"):
        return False
    stem = base[:-6]
    if len(stem) != 10 or stem[4] != "-" or stem[7] != "-":
        return False
    return stem[:4].isdigit() and stem[5:7].isdigit() and stem[8:].isdigit()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit-dir", required=True)
    ap.add_argument("--policy", default=DEFAULT_POLICY)
    ap.add_argument("--top", type=int, default=20)
    args = ap.parse_args()

    if not os.path.isdir(args.audit_dir):
        print("✗ 账本目录不存在：%s" % args.audit_dir)
        return 2
    if not os.path.isfile(args.policy):
        print("✗ 找不到 notify_policy：%s" % args.policy)
        return 2

    np = load_policy(args.policy)
    read_at = time.strftime("%Y-%m-%d %H:%M:%S")

    all_files = sorted(glob.glob(os.path.join(args.audit_dir, "*.jsonl")))
    daily = [p for p in all_files if is_daily_name(p)]
    skipped = [os.path.basename(p) for p in all_files if p not in daily]

    n_rec = 0
    n_bad_json = 0
    n_raise = 0
    by_notify = collections.Counter()
    by_type_notify = collections.Counter()
    by_pair = collections.Counter()          # (action, decision) 实际组合
    pair_notify = collections.Counter()      # (action, decision) -> notify
    non_event_hits = collections.Counter()
    raise_samples = []

    for p in daily:
        try:
            fh = open(p, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    n_bad_json += 1
                    continue
                n_rec += 1
                try:
                    nv = np.notify_of(rec)
                except Exception as exc:                     # 不许静默：记样本
                    n_raise += 1
                    if len(raise_samples) < 3:
                        raise_samples.append("%s: %r" % (type(exc).__name__, exc))
                    continue
                by_notify[nv] += 1
                t = rec.get("type") or "(none)"
                by_type_notify[(t, nv)] += 1
                key = (str(rec.get("action")), str(rec.get("decision")))
                by_pair[key] += 1
                pair_notify[(key, nv)] += 1
                if t in np.NON_EVENT_TYPES:
                    non_event_hits[t] += 1

    print("=" * 78)
    print("S1 真账本对账 —— 读取时刻 %s" % read_at)
    print("=" * 78)
    print("账本目录 : %s" % args.audit_dir)
    print("日文件   : %d 个（排除非日文件 %d 个%s）"
          % (len(daily), len(skipped),
             ("：" + ", ".join(skipped[:4])) if skipped else ""))
    print("记录     : %d 条（坏 JSON %d 条）" % (n_rec, n_bad_json))
    print("异常     : notify_of 抛出 %d 次%s"
          % (n_raise, ("  样本：" + " | ".join(raise_samples)) if raise_samples else "（0 次＝没有崩）"))
    print()

    print("[notify 分布]")
    for k in ("gate", "toast", "none"):
        n = by_notify.get(k, 0)
        pct = (100.0 * n / n_rec) if n_rec else 0.0
        print("  %-6s %8d  %6.2f%%" % (k, n, pct))
    other = sum(v for k, v in by_notify.items() if k not in ("gate", "toast", "none"))
    if other:
        print("  ★ 出现非三档取值 %d 条 —— 说明实现漏了归一" % other)
    print("  合计   %8d" % sum(by_notify.values()))
    print()

    print("[非事件 type 命中情况（应全部落在 none）]")
    for t in np.non_event_types():
        n = non_event_hits.get(t, 0)
        nv = collections.Counter({k[1]: v for k, v in by_type_notify.items() if k[0] == t})
        print("  %-30s %7d 条  →  %s" % (t, n, dict(nv) if nv else "（本次账本无此类）"))
    print()

    print("[action × decision 实际组合 → notify]（这张表是 S4 验收的基线）")
    print("  %-8s %-18s %8s   %s" % ("action", "decision", "条数", "notify"))
    for (a, d), c in sorted(by_pair.items(), key=lambda x: -x[1]):
        nv = pair_notify.get(((a, d), "gate"), 0)
        nv_t = pair_notify.get(((a, d), "toast"), 0)
        nv_n = pair_notify.get(((a, d), "none"), 0)
        parts = []
        if nv:
            parts.append("gate:%d" % nv)
        if nv_t:
            parts.append("toast:%d" % nv_t)
        if nv_n:
            parts.append("none:%d" % nv_n)
        print("  %-8s %-18s %8d   %s" % (a, d, c, ", ".join(parts)))
    print()

    print("[按 type 的通知面貌似（前 %d，只列会打扰的）]" % args.top)
    rows = [(t, nv, c) for (t, nv), c in by_type_notify.items() if nv in ("gate", "toast")]
    rows.sort(key=lambda x: -x[2])
    print("  %-32s %-6s %8s" % ("type", "notify", "条数"))
    for t, nv, c in rows[:args.top]:
        print("  %-32s %-6s %8d" % (t[:32], nv, c))
    print()

    # 矛盾组合专项：契约 §3 说收敛后要归位，这里给出归位后的事实
    print("[矛盾组合归位核对]")
    for key, label in (((("alert"), ("allow")), "action=alert + decision=allow"),
                       ((("block"), ("deny")), "action=block + decision=deny")):
        c = by_pair.get(key, 0)
        if not c:
            print("  %-38s 本次账本 0 条" % label)
            continue
        nv = pair_notify.get((key, "gate"), 0)
        nv_t = pair_notify.get((key, "toast"), 0)
        nv_n = pair_notify.get((key, "none"), 0)
        print("  %-38s %6d 条 → gate %d / toast %d / none %d" % (label, c, nv, nv_t, nv_n))
    print()
    print("★ 结论口径：本表所有数字都是 %s 那一刻的读数；账本 30 天滚动，重算请重跑本脚本。" % read_at)
    return 0


if __name__ == "__main__":
    sys.exit(main())
