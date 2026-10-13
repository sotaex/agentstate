#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""C3（2026-10-13）：before 基线**出声**工具 —— 开工前没登记 baseline tag 时提醒。

★★ 由来（交接件 §6.1 / 遗留问题 C3）：
  §6.1 白纸黑字：「**开工前**先打 tag `pre-console-<日期>`（与 merge 前的
  `pre-merge-<日期>` 同型），改动前的 8 帧从该 tag 渲染备查 ——
  **没有 before 就没有「提升」的证据**」。
  实测这一轮**没打**：before 证据只能拿 pre-task commit（`2e4e68f`）的 worktree
  补渲染 —— **等价但迟到**。迟到的代价是真的：before 与 after 之间若混进半成品改动，
  「提升」就证明不了（**T-09 同一事实两套口径**：同一批改动有两份起点）。
  病型归 **T-10 静默降级**：**「少做了 before 基线」这件事没有任何输出说明它发生了**，
  账面（8 帧截图）看起来与「有 before 对照」一样。

★★ 本工具的定位：**只出声，不做裁决** —— 这是设计，不是偷懒：
  `git tag` **不区分用途**，所以机器**无法**判断「本批是否已登记自己的开工基线」——
  `pre-merge-20261012` 是别的批次留下的，它同样是 HEAD 的祖先。
  ⇒ 任何"检测到违规就报红"的写法都会**时红时绿**（本仓铁律：
     「一个时红时绿的量具比恒红的更坏」）。
  所以本工具做的是：**每次产品提交都把这件事念一遍**，直到你把它登记下来；
  提醒**永远不拦截**（rc 恒 0）。裁决权留给**人**与 §6.1 的截图清单。

★ 用法：
    python ci/baseline_tag.py --remind [--root <dir>]   # 有产品改动 ⇒ 出声；否则静默
    python ci/baseline_tag.py --json   [--root <dir>]   # 机器可读（判据 D-37 用）
  由提交钩子 `ci/git-hooks/pre-commit` 调用（**非拦截**，见钩子注释）。

★ 纪律：本工具是**纯只读**（不写仓、不打 tag、不改索引）—— 它只报告，
  真正的动作（`git tag`）由人执行，避免"工具替人做决定"。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

#: 非产品路径（改了它们**不该**触发提醒 —— 否则机制变噪音，人就会绕开它）：
#: 开发侧目录、开发侧产物、探针。
_NON_PRODUCT_DIRS = {"ci", "docs", ".workbuddy-ai", ".workbuddy", ".psl",
                     ".git", "__pycache__", ".github"}
_NON_PRODUCT_SUFFIX = (".md", ".log", ".pyc", ".tmp", ".orig", ".rej")
_NON_PRODUCT_PREFIX = ("_p_",)

#: 基线 tag 的命名约定（§6.1：与 `pre-merge-20261012` 同型）。
BASELINE_TAG_GLOB = "pre-*"


def _git(root, *args):
    """跑只读 git 命令。返回 `(rc, stdout)`；git 起不来 ⇒ `(None, "")`。"""
    try:
        r = subprocess.run(["git", "-C", str(root)] + list(args),
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=30)
    except Exception:                                     # noqa: BLE001
        return None, ""
    return r.returncode, (r.stdout or "")


def is_product_path(path):
    """这条改动路径算不算**产品文件**（会被打进包的东西）。

    ★ 口径：**排除法** —— 开发侧的目录/产物一律不算，剩下的都算。
      为什么用排除法而不是"照 manifest 白名单"：manifest 是**发布快照**，
      新加的产品文件还不在里面 ⇒ 白名单会漏报，而**漏报就是提醒失效**。
      提醒宁可多报（多报只是多一句嘴），**绝不能漏报**。
    """
    p = (path or "").replace("\\", "/").strip()
    if not p:
        return False
    parts = [x for x in p.split("/") if x not in ("", ".")]
    if any(x in _NON_PRODUCT_DIRS for x in parts):
        return False
    base = parts[-1] if parts else p
    if base.startswith(_NON_PRODUCT_PREFIX):
        return False
    return not base.endswith(_NON_PRODUCT_SUFFIX)


def _parse_porcelain(out):
    """`git status --porcelain` → 改动路径列表（重命名取**新**路径）。"""
    paths = []
    for line in (out or "").splitlines():
        if len(line) < 4:
            continue
        body = line[3:].strip()
        if " -> " in body:                                # 重命名：R  old -> new
            body = body.split(" -> ", 1)[1]
        body = body.strip().strip('"')
        if body:
            paths.append(body)
    return paths


def probe(root="."):
    """只读探测。返回 dict（**永不抛** —— 出问题也要变成可打印的事实）。"""
    out = {"root": os.path.abspath(str(root)), "is_repo": False,
           "product_changes": [], "baseline_tags": [], "note": ""}
    rc, _ = _git(out["root"], "rev-parse", "--is-inside-work-tree")
    if rc != 0:
        out["note"] = ("查不到 git 工作树（`git rev-parse` rc=%r）—— "
                       "**这不是「没有产品改动」，是盲区**：本工具这次什么都没查"
                       % (rc,))
        return out
    out["is_repo"] = True

    rc, so = _git(out["root"], "status", "--porcelain")
    if rc != 0:
        out["note"] = ("查不到 `git status`（rc=%r）—— 盲区，不折叠成「无改动」"
                       % (rc,))
        return out
    out["product_changes"] = sorted({p for p in _parse_porcelain(so)
                                     if is_product_path(p)})

    rc, so = _git(out["root"], "tag", "-l", BASELINE_TAG_GLOB)
    out["baseline_tags"] = sorted(x.strip() for x in (so or "").splitlines()
                                  if x.strip())
    return out


def reminder(root="."):
    """有产品改动 ⇒ 返回提醒文本；否则（或查不到）返回 `None`。

    ★ **不判违规**（见模块 docstring 的诚实登记）：只把「开工基线」这件事摆到台面上。
    """
    p = probe(root)
    if not p["is_repo"] or not p["product_changes"]:
        return None
    chg = p["product_changes"]
    show = "、".join(chg[:6]) + ("…（共 %d 个）" % len(chg) if len(chg) > 6 else "")
    tags = p["baseline_tags"]
    if tags:
        cand = ("可用基线候选：%s（**须自行确认它早于本批第一次改动**）"
                % "、".join(tags[-3:]))
    else:
        cand = "仓里**一个 `pre-*` 基线 tag 都没有** —— before 证据此刻无从取得"
    return (
        "[baseline] ⚠ 本批有产品改动，请确认**已登记本批的开工基线**（§6.1）：\n"
        "[baseline]    改动：%s\n"
        "[baseline]    %s\n"
        "[baseline]    建议动作：`git tag pre-<批次名>-YYYYMMDD <开工点 commit>`"
        "（动手**前**打；打完这条提醒自然消失）\n"
        "[baseline]    ★ 本提醒**不拦截**，也不判违规 —— git tag 不区分用途，"
        "机器判不了「本批有没有自己的基线」（诚实登记，见 ci/baseline_tag.py 头）\n"
        % (show, cand))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="before 基线出声工具（§6.1 / 遗留问题 C3）—— 只提醒，不拦截")
    ap.add_argument("--remind", action="store_true",
                    help="有产品改动 ⇒ 打印提醒；否则静默")
    ap.add_argument("--json", action="store_true", help="机器可读（判据用）")
    ap.add_argument("--root", default=".", help="仓根（判据可在 fixture 上跑）")
    args = ap.parse_args(argv)

    p = probe(args.root)

    if args.json:
        print(json.dumps(p, ensure_ascii=False, indent=1))
        return 0                                            # ★ 恒 0：本工具不裁决

    if p["note"]:
        # 出声：查不到 ≠ 没有（T-08）。但**仍然不拦截**。
        sys.stderr.write("[baseline] %s\n" % p["note"])

    msg = reminder(args.root)
    if msg:
        sys.stderr.write(msg)
    return 0                                                # ★ 恒 0：不拦截


if __name__ == "__main__":
    sys.exit(main())
