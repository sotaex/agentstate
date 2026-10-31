# SPDX-License-Identifier: CC-BY-SA-4.0
# -*- coding: utf-8 -*-
"""0.64 前置 F5 + F6：两个账本面的 decision 分布，以及消费点各自读哪个面。

为什么必须分两个面量：
  契约草案 §4 给的 18,815 来自 `~/.antinel/ledger/daily.jsonl`；
  而 B 线／C 线一直在读 `.psl/audit/*.jsonl`（162,000+ 条）。
  这是**两个不同的账本**。若 0.64 的回退表只改一处却要覆盖两个面，
  就会出现「账本改对了、页面还是老数字」——即「读数源≠写入源」。

自证腿：
  L1 每个面打印「读到几个文件／几条记录／读取时刻」——没有这个，「0 条」就是失明
  L2 正控：造两个临时面（一个含 decision，一个不含），必须分别数对
  L3 负控：`lock_events.jsonl` 必须被排除（它不是日文件，混进来会污染分母）
"""
import collections
import glob
import io
import json
import os
import shutil
import sys
import tempfile
import time


def parse_lines(paths, label):
    """返回 (records, per_value, bad, files_used)。"""
    recs = 0
    bad = 0
    vals = collections.Counter()
    types = collections.Counter()
    files_used = []
    for p in paths:
        if not os.path.isfile(p):
            continue
        files_used.append(p)
        try:
            fh = io.open(p, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    bad += 1
                    continue
                if not isinstance(r, dict):
                    bad += 1
                    continue
                recs += 1
                vals[str(r.get("decision"))] += 1
                types[str(r.get("type"))] += 1
    return recs, vals, bad, files_used, types


def is_daily_name(name):
    """面 B 的约定：日分片，只认 YYYY-MM-DD.jsonl。lock_events.jsonl 不是日文件。"""
    base = os.path.basename(name)
    if not base.endswith(".jsonl"):
        return False
    stem = base[:-6]
    if len(stem) != 10 or stem[4] != "-" or stem[7] != "-":
        return False
    return stem[:4].isdigit() and stem[5:7].isdigit() and stem[8:].isdigit()


def is_ledger_file(name):
    """面 A 的约定：单文件累积账（daily.jsonl），不是日分片。

    ★ 这里踩过一次现成的坑：第一版拿 is_daily_name 去筛面 A，
      结果 daily.jsonl 被判成「非日文件」，整个面读成 0 条。
      两个账本**形态本就不同**，不能共用一把尺子。
    """
    base = os.path.basename(name)
    if not base.endswith(".jsonl"):
        return False
    if base.startswith("lock_events"):
        return False
    if ".lock.away" in base or ".away-" in base:
        return False
    return True


def self_check():
    ok = True
    tmp = tempfile.mkdtemp(prefix="probe_f5_")
    try:
        # L2 正控：一个面有 decision，一个面没有
        a = os.path.join(tmp, "2026-01-01.jsonl")
        with io.open(a, "w", encoding="utf-8") as fh:
            fh.write('{"decision":"alert","type":"t1"}\n')
            fh.write('{"decision":"block","type":"t1"}\n')
            fh.write('{"type":"no_decision"}\n')
        recs, vals, bad, _fu, _ty = parse_lines([a], "pos")
        if recs != 3 or vals.get("alert") != 1 or vals.get("block") != 1 or vals.get("None") != 1:
            print("[L2 正控] 失败：recs=%d vals=%s bad=%d" % (recs, dict(vals), bad))
            ok = False
        else:
            print("[L2 正控] 通过：3 条被数对，缺失字段归入 None 一档")

        # L3 负控：lock_events 必须被判为非日文件
        if is_daily_name("lock_events.jsonl"):
            print("[L3 负控] 失败：把 lock_events.jsonl 当成日文件")
            ok = False
        elif not is_daily_name("2026-10-31.jsonl"):
            print("[L3 负控] 失败：把真正的日文件排除了")
            ok = False
        else:
            print("[L3 负控] 通过：lock_events 被排除、日期名被接受")
        return ok
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    print("=" * 70)
    print("0.64 前置 F5 + F6：两个账本面的 decision 分布（只读）")
    print("读取时刻:", time.strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 70)
    print()
    print("[L2/L3 自证腿]")
    if not self_check():
        print("⇒ 探针不可信，读数作废")
        return 2
    print()

    home = os.path.expanduser("~")
    faces = []

    # 面 A：~/.antinel/ledger/daily.jsonl（契约草案 §4 的取数面）
    a_dir = os.path.join(home, ".antinel", "ledger")
    a_files = sorted(glob.glob(os.path.join(a_dir, "*.jsonl")))
    a_daily = [p for p in a_files if is_ledger_file(p)]
    a_other = [p for p in a_files if p not in a_daily]
    faces.append(("A  ~/.antinel/ledger/daily.jsonl（单文件累积账）", a_daily))
    print("[面 A 目录内容]")
    for p in a_files:
        kind = "账本" if p in a_daily else "排除"
        mt = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(p)))
        print("   %-28s %9d B  %s  %s" % (os.path.basename(p), os.path.getsize(p), mt, kind))
    print()

    # 面 B：仓内 .psl/audit/*.jsonl（B 线／C 线一直读的面）
    b_dir = os.path.join(".psl", "audit")
    b_files = sorted(glob.glob(os.path.join(b_dir, "*.jsonl"))) if os.path.isdir(b_dir) else []
    b_daily = [p for p in b_files if is_daily_name(p)]
    b_other = [p for p in b_files if p not in b_daily]
    faces.append(("B  仓内 .psl/audit/*.jsonl", b_daily))
    print("[面 B 目录内容]")
    print("   日文件 %d 个；非日文件 %d 个（%s）"
          % (len(b_daily), len(b_other), ", ".join(os.path.basename(x) for x in b_other[:3]) or "无"))
    print()

    for label, paths in faces:
        print("-" * 70)
        print("[%s]" % label)
        recs, vals, bad, used, types = parse_lines(paths, label)
        print("  读到文件 %d 个，记录 %d 条，不可解析 %d 条" % (len(used), recs, bad))
        if recs == 0:
            print("  ⇒ 该面为空，下面的比例无意义")
            print()
            continue
        print("  decision 分布：")
        for k, c in vals.most_common():
            print("    %-18s %7d  %5.1f%%" % (k, c, 100.0 * c / recs))
        need = sum(c for k, c in vals.items()
                   if k in {"alert", "warn", "block", "deny", "config_fallback", "config_rejected"})
        print("  「需要人看」按值粗算（alert+warn+block+deny+config_*）: %d 条" % need)
        print("  记录类型前 6：")
        for k, c in types.most_common(6):
            print("    %-24s %7d" % (k, c))
        print()

    print("=" * 70)
    print("两个面若有数字差异，不是版本差异，是**两个不同的账本**。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
