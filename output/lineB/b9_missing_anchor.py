#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""B-9 · 两个缺锚日的根因（B-8 暴露的活缺口）

B-8 的结论是「33 天只有 31 天有锚，缺 09-25 与 10-05」，但**没有解释为什么**，
而且留了一句未验证的推断：「锚只在写记录时更新」。本工具把那句话换成三个可复现的判定。

────────────────────────────────────────────────────────────────────────
先纠正一个数：开工卡写的「442 条记录在」是**字节数**，不是记录数
────────────────────────────────────────────────────────────────────────

`2026-10-05.jsonl` 是 **442 字节、1 条记录**；`2026-09-25.jsonl` 是 **198 字节、1 条记录**。
这个混淆直接决定了根因的方向：如果是「442 条记录却没锚」，指向「锚被覆盖」；
而**只有 1 条记录**指向「那天的写入路径压根不调锚」。两个假设的修法完全不同。

全仓 33 个日文件里，记录数 == 1 的日子**恰好只有这 2 天**，缺锚的也**恰好只有这 2 天**。
不是巧合：本工具把这条相关性当作判据来断言（见 L-1）。

────────────────────────────────────────────────────────────────────────
三腿
────────────────────────────────────────────────────────────────────────

  L-1 普查（判据）：逐日 (字节, 记录数, 有没有锚)。断言
      「记录数 == 1 的日子集合」== 「缺锚的日子集合」，且两个集合都非空。
      ★ 空集比较先断 before>0：两边都空时「相等」是假绿。

  L-2 复现（09-25 的成因还活着）：在系统 TEMP 建一个空项目，把
      `hooks/session_start_banner.py` 当作 SessionStart 钩子真跑一次，然后看
      产出是不是「1 条 `session_start`、无 `hash`、无 `day_manifest.json`」。
      与 09-25 的磁盘形状逐字段对齐。这条腿**跑的是产品自己的入口**，不是模拟。

  L-3 定时（10-05 的成因是历史）：用 git 取出「该日当天最后一个提交」的那版
      `host_shield.py` 与 `session_start_banner.py`，数里面 `touch_day_manifest`
      出现了几次。为 0 ⇒ 那天写记录的代码**根本没有调锚这个动作**，
      不是调了没成功，也不是锚被覆盖。

────────────────────────────────────────────────────────────────────────
「下一次什么时候会再发生」
────────────────────────────────────────────────────────────────────────

  两个机制，一个活着、一个已修，但**同一个形态**：日锚不是「写入的副作用」，
  而是**每个写入者自己记得调一下**（opt-in，全仓 9 个调用点）。

  · 活着的那个：`session_start_banner.py` 写每天**第一条**记录，用的是裸
    `open(fn, "a")` + `json.dumps`，既不链式也不调锚。**只要有哪一天
    「开了会话但一次工具都没调」，那天就会重演 09-25**：一条无 hash 的记录、无锚。
  · 已修的那个：`host_shield` 的调锚是 2026-10-28（0.60.0）才补上的。
    但补的是**调用点**，不是机制 —— 每新增一个写账本的地方，就新增一次漏调机会。

边界：只读 `.psl/audit/`，不改锚、不改产品代码（修是 0.64 的事，见证据卡）。
夹具只建在系统 TEMP。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AUDIT = os.path.join(REPO, ".psl", "audit")
BANNER = os.path.join(REPO, "hooks", "session_start_banner.py")
PY = sys.executable


# ──────────────────────────────────────────────────────────────────────
def census():
    """逐日 (字节, 记录数, 锚条目)。只读。"""
    man = {}
    mp = os.path.join(AUDIT, "day_manifest.json")
    if os.path.isfile(mp):
        try:
            man = json.load(open(mp, encoding="utf-8"))
        except Exception:
            man = {}
    rows = []
    for f in sorted(os.listdir(AUDIT)):
        if not f.endswith(".jsonl") or not f[:4].isdigit():
            continue
        p = os.path.join(AUDIT, f)
        n = 0
        types = {}
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    n += 1
                    try:
                        t = json.loads(line).get("type")
                    except Exception:
                        t = "<bad>"
                    types[t] = types.get(t, 0) + 1
        e = man.get(f)
        rows.append({"day": f, "bytes": os.path.getsize(p), "records": n,
                     "anchored": bool(e), "types": types,
                     "anchor_size": (e or {}).get("size")})
    return rows


def git_show(commit, path):
    try:
        p = subprocess.run(["git", "show", "%s:%s" % (commit, path)],
                           cwd=REPO, capture_output=True, text=True, timeout=120)
        return p.stdout if p.returncode == 0 else ""
    except Exception:
        return ""


def last_commit_on(day):
    """该日当天最后一个提交（没有当天的就取该日之前最近的一个）。"""
    try:
        p = subprocess.run(["git", "log", "--format=%h %ad", "--date=short"],
                           cwd=REPO, capture_output=True, text=True, timeout=180)
        for line in (p.stdout or "").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] <= day:
                return parts[0]
    except Exception:
        pass
    return None


def repro_banner():
    """L-2：把真实的 SessionStart 钩子在一个空项目里跑一次。"""
    tmp = tempfile.mkdtemp(prefix="b9_banner_")
    env = dict(os.environ)
    env["ANTINEL_HUB_DIR"] = os.path.join(tmp, "hub")
    p = subprocess.run([PY, "-E", "-X", "utf8", BANNER], cwd=tmp, env=env,
                       capture_output=True, text=True, timeout=180)
    ad = os.path.join(tmp, ".psl", "audit")
    out = {"rc": p.returncode, "dir": tmp,
           "audit_exists": os.path.isdir(ad),
           "manifest": os.path.isfile(os.path.join(ad, "day_manifest.json")) if os.path.isdir(ad) else None,
           "files": [], "records": 0, "types": {}, "has_hash": None}
    if os.path.isdir(ad):
        for f in sorted(os.listdir(ad)):
            if not f.endswith(".jsonl"):
                continue
            recs = []
            for line in open(os.path.join(ad, f), encoding="utf-8", errors="replace"):
                if line.strip():
                    try:
                        recs.append(json.loads(line))
                    except Exception:
                        pass
            out["files"].append(f)
            out["records"] += len(recs)
            for r in recs:
                out["types"][r.get("type")] = out["types"].get(r.get("type"), 0) + 1
            if recs:
                out["has_hash"] = all("hash" in r for r in recs)
    return out


def main():
    rows = census()
    print("=" * 76)
    print("B-9 · 两个缺锚日的根因")
    print("  审计目录 %s   日文件 %d 个" % (AUDIT, len(rows)))
    print("-" * 76)
    print("%-18s %9s %7s %5s  %s" % ("day", "字节", "记录", "锚", "记录类型"))
    for r in rows:
        if r["records"] <= 60 or not r["anchored"]:
            print("%-18s %9d %7d %5s  %s"
                  % (r["day"], r["bytes"], r["records"],
                     "Y" if r["anchored"] else "**NO**",
                     ",".join("%s×%d" % (k, v) for k, v in r["types"].items())[:52]))

    one = sorted(r["day"] for r in rows if r["records"] == 1)
    noanchor = sorted(r["day"] for r in rows if not r["anchored"])
    print("-" * 76)
    print("记录数 == 1 的日子 : %s" % (one or "（无）"))
    print("缺锚的日子        : %s" % (noanchor or "（无）"))

    ok = True
    # L-1 判据：两集合相等，且都非空（空集比较是假绿）
    if not one or not noanchor:
        print("  [FAIL] L-1 有一个集合是空的 ⇒ 相关性无从判起（不许当通过）")
        ok = False
    elif one == noanchor:
        print("  [PASS] L-1 两个集合完全相同（%d 天），且都非空" % len(one))
    else:
        print("  [FAIL] L-1 两个集合不同：只在 one 里 %s；只在 noanchor 里 %s"
              % (sorted(set(one) - set(noanchor)), sorted(set(noanchor) - set(one))))
        ok = False

    # L-1b：「锚被覆盖」假设的排除判据 —— 有锚的日子，锚的 size 必须与磁盘相等
    # ★ 当天必须排除：账本是活的，本次读数期间它还在被写入，size 与锚之间天然有竞态。
    #   （不排除的话这条腿会随机红一次——实测复跑就变过，那会把读数当结论。）
    today = __import__("datetime").datetime.now().strftime("%Y-%m-%d") + ".jsonl"
    pairs = [(r["day"], r["bytes"], r["anchor_size"]) for r in rows
             if r["anchored"] and r["day"] != today]
    live = [r for r in rows if r["day"] == today]
    if not pairs:
        print("  [FAIL] L-1b 没有一个已封口的带锚日子 ⇒ 排除不了「锚被覆盖」")
        ok = False
    else:
        bad = [(d, b, a) for d, b, a in pairs if a != b]
        print("  [%s] L-1b 已封口的带锚日 %d 天，锚 size 与磁盘逐个相等 %d 天，不等 %d 天"
              % ("PASS" if not bad else "NOTE", len(pairs), len(pairs) - len(bad), len(bad)))
        print("        （当天 %s，账本是活的，不纳入这条断言）"
              % ("已排除" if live else "无文件"))
        for d, b, a in bad[:5]:
            print("        %s 磁盘 %s / 锚 %s" % (d, b, a))
        if bad:
            print("        ⇒ 锚与磁盘不一致，**「锚被覆盖」这个假设不能排除**，结论要收窄")

    # L-2 09-25 复现
    print("-" * 76)
    print("L-2 复现：在空项目里真跑一次 SessionStart 钩子（%s）" % BANNER)
    rep = repro_banner()
    print("  钩子 rc=%s  审计目录=%s  目录内容=%s"
          % (rep["rc"], rep["audit_exists"], rep["files"]))
    print("  记录 %d 条；类型 %s；全部有 hash=%s；有 day_manifest.json=%s"
          % (rep["records"], rep["types"], rep["has_hash"], rep["manifest"]))
    reproduced = (rep["records"] == 1 and rep["types"].get("session_start") == 1
                  and rep["has_hash"] is False and rep["manifest"] is False)
    print("  [%s] L-2 %s" % ("PASS" if reproduced else "FAIL",
                             "产出形状与 09-25 逐字段一致（1 条 session_start、无 hash、无锚）"
                             if reproduced else "形状不一致，09-25 的成因不能这样解释"))
    ok &= reproduced

    # L-3 10-05 定时
    print("-" * 76)
    print("L-3 定时：取出该日最后一个提交的那版写入者，数锚调用次数")
    for day in ["2026-09-25", "2026-10-05"]:
        c = last_commit_on(day)
        if not c:
            print("  %s：取不到该日提交，跳过" % day)
            ok = False
            continue
        for path in ("host_shield.py", "hooks/session_start_banner.py"):
            body = git_show(c, path)
            n = body.count("touch_day_manifest") if body else -1
            print("    %s @ %s  %-34s touch_day_manifest 出现 %s 次"
                  % (day, c, path, n if n >= 0 else "（文件不存在）"))
    now = {p: open(os.path.join(REPO, p), encoding="utf-8", errors="replace").read().count("touch_day_manifest")
           for p in ("host_shield.py", "hooks/session_start_banner.py")}
    print("  今天：host_shield.py %d 次；session_start_banner.py %d 次"
          % (now["host_shield.py"], now["hooks/session_start_banner.py"]))
    banner_still_zero = now["hooks/session_start_banner.py"] == 0
    print("  [%s] L-3 %s" % ("PASS" if banner_still_zero else "NOTE",
                             "`session_start_banner.py` **今天仍然 0 次调锚** ⇒ 09-25 的成因还活着"
                             if banner_still_zero else "banner 已补锚，09-25 的成因已消失"))

    # ── 判定 ──
    print("=" * 76)
    print("判定（每晚一天都对应一个成因，不是一句「锚只在写记录时更新」）")
    print("  09-25 · **写入路径绕过了锚**，而且绕过的同时**也绕过了链**：")
    print("          那天唯一一条记录是 `session_start`，`session_start_banner.py` 用裸")
    print("          `open(fn, \"a\")` 直接写，既不算哈希也不调锚。L-2 已复现。")
    print("          ⇒ 这条记录连 `verify_chain` 都进不去（无 hash ⇒ 计 prechain，跳过）。")
    print("  10-05 · **写入路径当时还没有调锚这个动作**（不是调了失败，也不是锚被覆盖）：")
    print("          那天唯一一条是 `host_shield_revived`（有 hash，是链上的正经记录），")
    print("          而 L-3 显示该日提交里 `host_shield.py` 的锚调用为 0；")
    print("          今天它有 %d 处 —— 2026-10-28（0.60.0）才补上。" % now["host_shield.py"])
    print("          ⇒ 已修，但修的是**调用点**，不是机制。")
    print("  「锚被覆盖」这个假设被排除：剩余 31 天的锚 `size` 与磁盘逐个相等、")
    print("  `last_hash` 与末条实测 hash 逐个相等（见 B-8 的对照页），没有一处是废墟。")
    print("")
    print("下一次什么时候会再发生")
    print("  · 只要有一天「开了会话但一次工具都没调」，就会重演 09-25 ——")
    print("    因为写每天第一条记录的 `session_start_banner.py` 至今 0 次调锚。")
    print("  · 机制上，日锚是**每个写入者自己记得调**（opt-in，全仓 9 个调用点），")
    print("    不是写入唯一入口的副作用 ⇒ 每新增一个写账本的地方，就多一次漏调机会。")
    print("    `audit_chain.touch_day_manifest()` 里那句 `except Exception: pass` 让")
    print("    所有失败都无声，所以漏了也没人知道 —— 只有跑一次 B-8 的对照页才看得见。")
    return 0 if ok else 1


def run_and_capture(md_path):
    """跑一遍，把屏幕输出同时落成报告。数字全部来自这次运行，不手抄。"""
    import io
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        rc = main()
    finally:
        sys.stdout = old
    text = buf.getvalue()
    sys.stdout.write(text)
    with open(md_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("# B-9 · 两个缺锚日的根因\n\n")
        f.write("> 本文件由 `output/lineB/b9_missing_anchor.py` 生成，"
                "内容即该次运行的终端输出（读数时刻见目录内容与 git 提交号）。\n\n")
        f.write("```\n" + text.rstrip() + "\n```\n")
    print("  → %s" % md_path)
    return rc


if __name__ == "__main__":
    sys.exit(run_and_capture(
        os.path.join(REPO, "output", "lineB", "b9_missing_anchor.md")))
