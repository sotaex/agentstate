#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""B-5 · 读侧留痕覆盖（方案书 §3.3 第 5 段 G10）

要回答的问题（方案书原文：「33 类记录里，记『谁读过账本』的 0 种 —— ❌ 从未看过」）：
  Q1 账本里现在一共有多少类记录？（现取现报，不抄方案书的数）
  Q2 其中有几类是「读账本」这个动作留下的？
  Q3 「0 类」是因为真的没有，还是因为探针根本没扫到？

Q3 是本工具的**主要产出**。只有 Q1 读得出、且关键词表有牙，「0」才是结论；
否则「0」只是失明。故配三条腿：

  腿 1（基础读数）  扫目录，列出 (type, 条数)，证明读得到已知存在的写入类记录
  腿 2（正控）      在 TEMP 副本里**人造**一条 ledger_read 记录 ⇒ 必须被算作读侧
  腿 3（负控）      同副本里 pre_tool_use 一条 ⇒ 必须**不**被算作读侧

纪律：
  · 只读 `.psl/audit`，仓库零字节写入；夹具建在系统 TEMP（D 盘禁 unlink）。
  · 扫描面**显式遍历**，不用 glob 通配（`*.jsonl` 会把 `.jsonl.lock`、
    `.away-<ts>` 一起卷进来，那是假绿族的第 ⑩ 条）。
  · 判据不用子串包含，用 type 全集 + 精确成员判定。

用法：
  python output/lineB/b5_ledger_read_coverage.py [--audit <dir>]
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import shutil
import sys
import tempfile

# 账本日文件名的**唯一形态**。★ 为什么必须卡死：`.psl/audit/` 里还躺着
#   `lock_events.jsonl`（并发锁事件，不是审计记录）—— 只按 `.jsonl` 后缀扫
#   会把它当第 35 类记录的一部分算进分母，读数就脏了（B-6 实测在同一目录
#   上直接抛 `Invalid isoformat string: 'lock_events'` 才暴露出来）。
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.jsonl$")

# 读侧动作的**动词表**：账本里出现这些词，说明这条记录是「读」留下的痕，
# 而不是「写」留下的。刻意收窄 —— 宁可漏判也不许把写入当读取。
READ_VERBS = (
    "ledger_read", "audit_read", "report_generated", "report_read",
    "verify_run", "verify_read", "export_read", "export_created",
    "audit_export", "audit_query", "ledger_query", "ledger_view",
)

# 扫描面排除族（与仓内 `_dir_excluded()` 同口径：裸名 / .away-<ts> / 前缀族）
_AWAY_PREFIX = ".away-"


def _is_excluded(name: str) -> bool:
    if name.endswith(".lock"):          # 并发锁文件，不是记录
        return True
    if _AWAY_PREFIX in name:            # 让开档（改名留证）
        return True
    return False


def iter_day_files(root: str):
    """显式遍历（不用 glob）：返回 [(basename, abspath)]，按名排序。"""
    out = []
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if not os.path.isfile(p):
            continue
        if not name.endswith(".jsonl"):
            continue
        if not _DAY_RE.match(name):      # lock_events.jsonl 之类，不是审计记录
            continue
        if _is_excluded(name):
            continue
        out.append((name, p))
    return out


def scan(root: str):
    """返回 (types Counter, total, per_day dict, bad_lines)。"""
    types = collections.Counter()
    per_day = {}
    total = 0
    bad = 0
    for name, p in iter_day_files(root):
        c = 0
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    bad += 1
                    continue
                total += 1
                c += 1
                t = r.get("type")
                types[t if isinstance(t, str) and t else "(无 type)"] += 1
        per_day[name] = c
    return types, total, per_day, bad


def classify(types) -> tuple[list, list]:
    """把 type 全集按**精确成员判定**分成读侧 / 写侧。不许子串包含。"""
    read = [t for t in types if t in READ_VERBS]
    write = [t for t in types if t not in READ_VERBS]
    return sorted(read), sorted(write)


def _mk_fixture(dirpath: str, records) -> None:
    with open(os.path.join(dirpath, "2099-01-01.jsonl"), "w",
              encoding="utf-8", newline="") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", default=os.path.join(".psl", "audit"))
    a = ap.parse_args()
    root = a.audit
    if not os.path.isdir(root):
        print("★ 账本目录不存在：%s" % root)
        return 2

    print("=" * 74)
    print("B-5 · 读侧留痕覆盖 ｜ 扫描面 %s" % os.path.abspath(root))
    print("=" * 74)

    types, total, per_day, bad = scan(root)
    files = iter_day_files(root)
    print("\n[腿 1] 基础读数（必须读得到，否则后面两个 0 都是失明）")
    print("  日文件 %d 个 ｜ 记录 %d 条 ｜ 坏行 %d ｜ 类型 %d 类"
          % (len(files), total, bad, len(types)))
    if total == 0:
        print("  ❌ 一条都没读到 —— 探针失明，后面的结论全部无效")
        return 1
    print("  ✅ 读得到（对照：最大一类 %s = %d 条）"
          % (types.most_common(1)[0][0], types.most_common(1)[0][1]))

    read, write = classify(types)
    print("\n[结论 Q2] 读侧类型：%d 类 ｜ 写侧类型：%d 类" % (len(read), len(write)))
    if read:
        for t in read:
            print("    READ  %-30s %d 条" % (t, types[t]))
    else:
        print("    （0 类 —— 但先看完腿 2／腿 3 的证词再下结论）")

    # ---- 腿 2 / 腿 3：在系统 TEMP 里造副本，证明关键词表有牙 ----
    tmp = tempfile.mkdtemp(prefix="b5_fixture_")
    try:
        _mk_fixture(tmp, [
            {"type": "pre_tool_use", "session": "fx", "tool": "Bash"},
            {"type": "ledger_read", "session": "fx", "tool": "report",
             "by": "report.py"},
        ])
        f_types, f_total, _, _ = scan(tmp)
        f_read, _ = classify(f_types)

        print("\n[腿 2] 正控：人造 1 条 ledger_read ⇒ 必须被算作读侧")
        ok_pos = ("ledger_read" in f_read) and f_total == 2
        print("  %s 副本读到 %d 条、读侧 %s"
              % ("✅" if ok_pos else "❌", f_total, f_read or "（空）"))

        print("\n[腿 3] 负控：同副本里的 pre_tool_use ⇒ 必须**不**被算作读侧")
        ok_neg = ("pre_tool_use" not in f_read) and ("pre_tool_use" in f_types)
        print("  %s 读侧里含 pre_tool_use = %s"
              % ("✅" if ok_neg else "❌", "pre_tool_use" in f_read))

        teeth = ok_pos and ok_neg
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "-" * 74)
    if not teeth:
        print("判定：❌ 关键词表没有牙（正控或负控未过）—— 不许报「0 类读侧」")
        return 1
    print("判定：探针有牙（正控命中、负控不误判）")
    print("G10 实测：%d 类记录 ／ %d 类读侧 ／ 总记录 %d 条"
          % (len(types), len(read), total))
    print("含义：账本能证明「某个动作被记下来了」，不能证明「某份账被谁看过」。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
