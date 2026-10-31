# -*- coding: utf-8 -*-
"""B-1 · 链外日历：从日文件集合推出「缺日区间」。

出处：方案书 §7.2 步 4「引入链外日历：心跳连续性 ⇒ 缺一天报一条」。
背景实测：`heartbeat.json` 只有 `{pid, ts}`，**不是日粒度日历** ⇒ 步 4 没有现成基础，
本模块就是补这个基础。

★ 为什么是"链外"：日文件本身就在账本里，若用日文件自己证明"我没缺"，缺掉的那天
  恰恰不会说话。日历必须由**另一条路径**（文件系统枚举 ＋ 心跳连续段）给出。
★ 判据口径：**缺口＝窗口内应有而没有的日**，不等于"文件不存在"——
  文件存在但 0 条记录（空壳）同样是缺口，且更危险（看起来有证据）。
"""
import datetime
import io
import json
import os
import sys


def _daily_files(d):
    """窗口内的日文件：`YYYY-MM-DD.jsonl`。其余文件（`lock_events.jsonl` 等）不算账本。"""
    out = {}
    for fn in os.listdir(d):
        if not fn.endswith(".jsonl"):
            continue
        stem = fn[:-6]
        try:
            day = datetime.date.fromisoformat(stem)
        except ValueError:
            continue                      # 不是日文件名 ⇒ 另一套 schema，不进本日历
        out[day] = os.path.join(d, fn)
    return out


def _count(path):
    n = 0
    try:
        for line in io.open(path, encoding="utf-8", errors="replace"):
            if line.strip():
                n += 1
    except OSError:
        return -1
    return n


def missing_days(audit_dir, start=None, end=None):
    """返回 (缺口列表, 空壳列表, 窗口, 日文件数)。

    缺口 = 窗口内无日文件；空壳 = 有文件但 0 条记录。
    """
    files = _daily_files(audit_dir)
    if not files:
        return None, None, None, 0
    lo = start or min(files)
    hi = end or max(files)
    gaps, shells = [], []
    cur = lo
    while cur <= hi:
        p = files.get(cur)
        if p is None:
            gaps.append(cur)
        elif _count(p) == 0:
            shells.append(cur)
        cur += datetime.timedelta(days=1)
    return gaps, shells, (lo, hi), len(files)


def _ranges(days):
    """把日列表压成区间串：['09-30','10-01','10-02'] -> '2026-09-30 ~ 2026-10-02'。"""
    if not days:
        return "（无）"
    out, i = [], 0
    while i < len(days):
        j = i
        while j + 1 < len(days) and (days[j + 1] - days[j]).days == 1:
            j += 1
        out.append(days[i].isoformat() if i == j
                   else "%s ~ %s" % (days[i].isoformat(), days[j].isoformat()))
        i = j + 1
    return "、".join(out)


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    audit = os.path.join(root, ".psl", "audit")
    gaps, shells, win, n = missing_days(audit)
    print("=" * 66)
    print("账本目录 :", audit)
    if gaps is None:
        print("★ 一条日文件都没读到 —— 不是「没有缺口」，是**没读到账本**（先查路径）")
        return 2
    print("日文件数 :", n, " 窗口 :", win[0].isoformat(), "~", win[1].isoformat())
    print("缺口(天) :", len(gaps), "→", _ranges(gaps))
    print("空壳(天) :", len(shells), "→", _ranges(shells))
    print("-" * 66)
    print("★ 读法：缺 0 天 ≠ 证据充分；本日历只证明「日文件齐」，不证明「那天真在值守」")
    print("  —— 后者要靠心跳连续段（步 4 的后半段），本版未做。")
    hb = os.path.join(audit, "heartbeat.json")
    if os.path.exists(hb):
        try:
            d = json.load(io.open(hb, encoding="utf-8"))
            print("heartbeat.json 顶层条目 %d ｜ 样例键 %s"
                  % (len(d), (list(d)[:2] if isinstance(d, dict) else "list")))
            print("  ⇒ 只有 pid/ts 这类**瞬时**字段时，它撑不起日粒度日历（本版实测确认）")
        except Exception as e:                                # noqa: BLE001
            print("heartbeat.json 读不出：%s" % type(e).__name__)
    return 0 if not gaps else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
