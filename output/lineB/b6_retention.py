#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""B-6 · 保留期与销毁（方案书 §3.3 第 7 段）

方案书原文：「**零**：`audit_chain.py` 无任何删除/轮转逻辑 ⇒ **保留期＝永久，不是 7 天**」
—— 这一句是**断言**，没有实测支撑。本工具把它变成可复算的读数：

  Q1 磁盘上实际保留了多少天、多少条、多少字节？（现取现报，带读取时刻）
  Q2 代码里到底有没有删除／轮转路径？（AST 扫，不靠读注释）

★ Q2 的探针必须自证有牙，否则「0 处删除」等于「我没找对文件」：
   腿 1  真实目标文件上扫一遍（读得到才算数）
   腿 2  正控：人造一个含 `os.remove` / `shutil.rmtree` 的样本 ⇒ 必须检出
   腿 3  负控：人造一个只读样本 ⇒ 必须 0 命中

只读；夹具在系统 TEMP（D 盘禁 unlink）。不改产品、不写账本。

用法：
  python output/lineB/b6_retention.py [--audit <dir>] [--root <dir>]
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import os
import re
import shutil
import sys
import tempfile

# 账本日文件名的唯一形态（`.psl/audit/lock_events.jsonl` 不是审计记录，
# 混进来会让 `date.fromisoformat('lock_events')` 直接崩 —— 实测撞过一次）
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.jsonl$")

# 删除/轮转的**语法指纹**：调用名（属性形态）+ 模块名
DESTRUCTIVE_CALLS = {
    "remove", "unlink", "rmdir", "removedirs", "rmtree",
    "rename", "replace", "truncate", "move",
}
DESTRUCTIVE_MODS = {"os", "shutil", "pathlib", "send2trash"}

# 轮转/保留期关键词（只在**字符串常量**里找，属弱证据，单列）
ROTATE_KEYWORDS = ("retention", "rotate", "prune", "purge")

CANDIDATES = (
    "audit_chain.py",
    "hooks/audit_chain.py",
    "psl/audit_chain.py",
    "tools/audit_chain.py",
)


def _resolve_target(root: str):
    for rel in CANDIDATES:
        p = os.path.join(root, rel.replace("/", os.sep))
        if os.path.isfile(p):
            return rel, p
    return None, None


def scan_ast(path: str):
    """返回 (强证据 hits, 弱证据 hits)，各为 [(lineno, 描述)]。"""
    src = open(path, encoding="utf-8", errors="replace").read()
    tree = ast.parse(src, filename=path)
    strong, weak = [], []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            base = node.func.value
            modname = base.id if isinstance(base, ast.Name) else (
                base.attr if isinstance(base, ast.Attribute) else None)
            attr = node.func.attr
            if attr in DESTRUCTIVE_CALLS and (modname in DESTRUCTIVE_MODS or modname is None):
                strong.append((node.lineno, "%s.%s(...)" % (modname or "?", attr)))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in DESTRUCTIVE_CALLS:
                strong.append((node.lineno, "%s(...)" % node.func.id))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            for kw in ROTATE_KEYWORDS:
                if kw in low:
                    weak.append((node.lineno, "字符串含 %r" % kw))
                    break
    return strong, weak


def _write_sample(dirpath: str, name: str, body: str) -> str:
    p = os.path.join(dirpath, name)
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write(body)
    return p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", default=os.path.join(".psl", "audit"))
    ap.add_argument("--root", default=".")
    a = ap.parse_args()

    root = a.root
    audit = a.audit if os.path.isdir(a.audit) else os.path.join(root, a.audit)

    print("=" * 74)
    print("B-6 · 保留期与销毁 ｜ 读取时刻 %s"
          % dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 74)

    if not os.path.isdir(audit):
        print("★ 账本目录不存在：%s" % audit)
        return 2

    # ---------- Q1：磁盘实况 ----------
    days = []
    total_lines = total_bytes = 0
    skipped = []
    for name in sorted(os.listdir(audit)):
        p = os.path.join(audit, name)
        if not os.path.isfile(p) or not name.endswith(".jsonl"):
            continue
        if not _DAY_RE.match(name):
            skipped.append(name)
            continue
        if name.endswith(".lock") or ".away-" in name:
            skipped.append(name)
            continue
        n = 0
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    n += 1
        sz = os.path.getsize(p)
        total_lines += n
        total_bytes += sz
        days.append((name[:-6], n, sz))

    if not days:
        print("❌ 一个日文件都没读到 —— 读数无效")
        return 1

    days.sort()
    first, last = days[0][0], days[-1][0]
    span = (dt.date.fromisoformat(last) - dt.date.fromisoformat(first)).days + 1
    print("\n[Q1] 磁盘实况")
    print("  日文件 %d 个 ｜ 覆盖 %s → %s（日历跨度 %d 天）｜ 记录 %d 条 ｜ %.1f MB"
          % (len(days), first, last, span, total_lines, total_bytes / 1048576.0))
    print("  实有天数 %d ＝ 跨度 %d − 空洞 %d" % (len(days), span, span - len(days)))
    if skipped:
        print("  已排除（非记录）：%s" % ", ".join(skipped[:6]))
    biggest = max(days, key=lambda d: d[2])
    print("  最大一天：%s ｜ %d 条 ｜ %.1f MB"
          % (biggest[0], biggest[1], biggest[2] / 1048576.0))
    print("  ⇒ 实际保留＝全部历史：最早 %s，距今 %d 天（不是 7 天）"
          % (first, (dt.date.today() - dt.date.fromisoformat(first)).days))

    # ---------- Q2：代码里的删除/轮转 ----------
    rel, path = _resolve_target(root)
    print("\n[Q2] 代码里的删除／轮转路径")
    if not path:
        print("  ❌ 找不到 audit_chain.py（候选：%s）—— 不许据此说「零删除」" % (CANDIDATES,))
        return 1
    print("  被测文件：%s（%d 字节）" % (rel, os.path.getsize(path)))

    strong, weak = scan_ast(path)
    print("  强证据（删除/改名调用）%d 处 ｜ 弱证据（关键词字符串）%d 处"
          % (len(strong), len(weak)))
    for ln, desc in strong[:15]:
        print("    L%-5d %s" % (ln, desc))
    if len(strong) > 15:
        print("    …… 另 %d 处" % (len(strong) - 15))
    for ln, desc in weak[:5]:
        print("    L%-5d [弱] %s" % (ln, desc))

    # ---------- 腿 2 / 腿 3：探针有牙 ----------
    tmp = tempfile.mkdtemp(prefix="b6_fixture_")
    try:
        pos = _write_sample(tmp, "pos.py", (
            "import os, shutil\n"
            "def f(p):\n"
            "    os.remove(p)\n"
            "    shutil.rmtree(p)\n"
        ))
        neg = _write_sample(tmp, "neg.py", (
            "def f(p):\n"
            "    return open(p).read()\n"
        ))
        pos_strong, _ = scan_ast(pos)
        neg_strong, _ = scan_ast(neg)
        print("\n[腿 2] 正控：人造 os.remove ＋ shutil.rmtree ⇒ 必须检出")
        print("  %s 命中 %d 处 %s"
              % ("✅" if len(pos_strong) >= 2 else "❌", len(pos_strong),
                 [d for _, d in pos_strong]))
        print("\n[腿 3] 负控：纯读样本 ⇒ 必须 0 命中")
        print("  %s 命中 %d 处" % ("✅" if not neg_strong else "❌", len(neg_strong)))
        teeth = len(pos_strong) >= 2 and not neg_strong
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "-" * 74)
    if not teeth:
        print("判定：❌ 探针没有牙 —— 「零删除」不可作为结论")
        return 1
    print("判定：探针有牙（正控命中、负控 0）")
    if not strong:
        print("结论：`%s` 里 **0 处** 删除／轮转调用 ⇒ 保留期在新代码落地前等同永久。"
              % rel)
        print("     与方案书 §3.3 第 7 段的断言一致，但现在是**可复算读数**，不是引用。")
    else:
        print("结论：`%s` 里有 %d 处删除／轮转调用 —— 需逐处判定是「轮转」还是「误删风险」。"
              % (rel, len(strong)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
