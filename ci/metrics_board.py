# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""双一等指标看板（A5，2026-10-15）—— 取代 PASS 数做头行指标。

依据机制论文档 §5 跨层元机制行「复发间隔仪表：唯一常驻高层」与
§8 行动清单第 5 条「双一等指标挂牌：同族复发间隔＋机制总数并列看板」。

两个一等指标（为什么是它们，而不是 PASS 数）：
  ① 同族复发间隔 —— 类型学 v1.3 S3：总量收敛 ⇔ 判据固化率 > 新类型产生率；
     「同族复发不是新 bug，是判据固化失败的信号」。PASS 数只说明今天没红，
     不说明失效在变稀；复发间隔说明失效在变稀。
  ② 机制总数（套件数）—— 类型学 v1.3 §13/BT-62：复杂度-效率反转的对账量；
     机制只增不减时效率暗降，这个数让「合并轮」有数可依。

★ 口径声明（F40：百分比一律带分母，多组并列各给各的口径）：
  · 复发间隔按 T 类型分组、按日期排序求相邻差；**同日批登**（间隔 0 天）
    与**剔同日**两种口径分别给数 —— 本仓 10-12→14 是三个批次日，同日间隔 0
    是批登形态不是复发语义，混在一个口径里会把「批量工作」读成「天天复发」。
  · 机制总数给两个数：常驻口径（inbox_guards_*＋guard_*，A2 上限 29 的那个）
    与总登记口径（SUITES 全部 34 条，含 JDG/PCM/selfcheck/version/regression
    五条基础设施项）。

★ 为什么这个文件不是判据套件：它是仪表（instrument），不是闸门 ——
  不产绿红、不进 SUITES、不占 A2 的 29 常驻预算。把它做成套件会让
  「指标变红」变成又一次要修的产品红，恰是 B2（古德哈特高危指标做验收）
  禁止的形态。它只报数；数难看时的动作（合并轮/退休）走 A2 退休登记簿。

用法：
  python ci/metrics_board.py            # 人读看板（stdout）
  python ci/metrics_board.py --out F    # 同时写文件（默认 output/metrics_board.txt）
"""
import argparse
import datetime
import io
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import defect_types as dt                                    # noqa: E402
import delivery_gate as dg                                    # noqa: E402


def _inst_date(inst):
    try:
        return datetime.date.fromisoformat(str(inst.get("date", "")))
    except ValueError:
        return None


def recurrence_intervals():
    """同族复发间隔：按 T 类型分组的相邻实例日差（天）。

    返回 {type: {"raw": [间隔...], "dedup_same_day": [间隔...], "n": 实例数}}
    raw     含同日间隔 0（批登形态）
    dedup   同日多例只留一条后再求间隔（更接近复发语义）
    """
    bytype = defaultdict(list)
    for inst in dt.INSTANCES:
        d = _inst_date(inst)
        if d is not None:
            bytype[inst["type"]].append(d)
    out = {}
    for t, dates in bytype.items():
        ds = sorted(dates)
        raw = [(ds[i + 1] - ds[i]).days for i in range(len(ds) - 1)]
        uniq = sorted(set(ds))
        dedup = [(uniq[i + 1] - uniq[i]).days for i in range(len(uniq) - 1)]
        out[t] = {"n": len(ds), "raw": raw, "dedup_same_day": dedup,
                  "first": ds[0].isoformat(), "last": ds[-1].isoformat()}
    return out


def board(today=None):
    today = today or datetime.date.today()
    ri = recurrence_intervals()
    all_raw = sorted(x for v in ri.values() for x in v["raw"])
    all_dedup = sorted(x for v in ri.values() for x in v["dedup_same_day"])
    resident = dg.resident_suite_count()
    total = len(dg.SUITES)
    opens = [i for i in dt.INSTANCES if i.get("status") == "open"]
    wb = dt.watch_board(today)
    active = sum(1 for _i, _w, s in wb if s == "active")
    expired = sum(1 for _i, _w, s in wb if s == "expired")
    recur = dt.watch_recurrences(today)
    ledger = dg._load_retirement_ledger()
    pending_retire = sum(1 for r in ledger.get("retirements", [])
                         if r.get("status") == "pending")
    L = []
    L.append("=" * 72)
    L.append("Antinel 双一等指标看板 —— 取数时点 %s" % today.isoformat())
    L.append("（头行指标：取代 PASS 数；PASS 数只说明今天没红，不说明失效在变稀）")
    L.append("=" * 72)
    L.append("")
    L.append("【一等指标 1】同族复发间隔（天）")
    L.append("  同类相邻实例日差，两种口径各给（F40：不混分母）：")
    L.append("    · 含同日批登口径：%d 个间隔，中位数 %s，最大 %s，最小 %s"
             % (len(all_raw), _med(all_raw), max(all_raw) if all_raw else "-",
                min(all_raw) if all_raw else "-"))
    L.append("    · 剔同日口径  ：%d 个间隔，中位数 %s，最大 %s，最小 %s"
             % (len(all_dedup), _med(all_dedup),
                max(all_dedup) if all_dedup else "-",
                min(all_dedup) if all_dedup else "-"))
    L.append("  ⚠ 诚实边界：登记簿 2026-10-12 才开簿，前三日的间隔由批登节奏"
             "主导；该指标在历史累积超过两个看守期（14 天）后才有趋势意义。")
    L.append("  按类型明细（n=实例数，first→last，剔同日间隔）：")
    for t in sorted(ri):
        v = ri[t]
        L.append("    %-6s n=%-2d %s→%s  间隔 %s"
                 % (t, v["n"], v["first"], v["last"],
                    v["dedup_same_day"] or "（单实例，无间隔）"))
    L.append("")
    L.append("【一等指标 2】机制总数（套件数）")
    L.append("    常驻口径 %d / 上限 %d（A2：inbox_guards_*＋guard_*）"
             % (resident, dg.RESIDENT_SUITE_CAP))
    L.append("    总登记口径 %d 条（含 JDG/PCM/selfcheck/version/regression"
             " 五条基础设施项）" % total)
    L.append("    退休登记簿 pending %d 条（超限的唯一合法途径）" % pending_retire)
    L.append("")
    L.append("【伴随数】登记簿 %d 实例：open %d；看守期在守 %d / 期满 %d；"
             "期内同族复发 %d" % (len(dt.INSTANCES), len(opens), active,
                            expired, len(recur)))
    if recur:
        L.append("  ★ 期内同族复发（红判据不红产品，A3）：")
        for a, b in recur:
            L.append("    %s（%s）⇒ %s（%s）" % (a["id"], a["type"],
                                            b["id"], b["type"]))
    L.append("")
    L.append("【读法】指标 1 变短 ＝ 判据固化在失败（查判据不查产品）；"
             "指标 2 逼近上限 ＝ 先走 A6 合并审计再谈新增。")
    return "\n".join(L), {
        "ts": today.isoformat(),
        "recurrence_intervals_raw": all_raw,
        "recurrence_intervals_dedup": all_dedup,
        "resident_suites": resident,
        "resident_cap": dg.RESIDENT_SUITE_CAP,
        "total_registered": total,
        "pending_retirements": pending_retire,
        "instances": len(dt.INSTANCES), "open": len(opens),
        "watch_active": active, "watch_expired": expired,
        "watch_recurrences": len(recur),
        "by_type": ri,
    }


def _med(xs):
    if not xs:
        return "-"
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def main():
    ap = argparse.ArgumentParser(description="双一等指标看板（A5）")
    ap.add_argument("--out", default="",
                    help="同时写盘的文件路径（默认 output/metrics_board.txt）")
    a = ap.parse_args()
    text, data = board()
    print(text)
    out = a.out or os.path.join(ROOT, "output", "metrics_board.txt")
    try:
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with io.open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text + "\n")
        with io.open(out + ".json", "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        print("\n[看板已写盘] %s（附 .json）" % out)
    except OSError as e:
        print("\n[!!] 看板写盘失败 %r —— 数仍在 stdout" % (e,))
    return 0


if __name__ == "__main__":
    sys.exit(main())
