# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""主动性 v2 · watchman 负控（NC1 / NC2 / NC3）

──────────────────────────────────────────────────────────────────────────
它解决什么问题
──────────────────────────────────────────────────────────────────────────
「压噪声」和「压掉真线索」在报告上**长得一模一样**：两者都让条数变少。
今晚的降噪改了六个判据，如果没有这三条负控，明早无法回答：

    少的那些，是噪声，还是真线索？

NC4（--no-benign 时全部回来）只证明「可撤销」，不证明「没压过头」。
本文件补后者。

──────────────────────────────────────────────────────────────────────────
三条臂
──────────────────────────────────────────────────────────────────────────
NC1  合成账本里**只有**一条罕见规则配对  → 必须报出来
NC2  合成账本里**只有**噪声（常见命令/域名/短间隙）→ 必须报 0 条
NC3  在 NC1 的账本上**删掉**配对记录      → 必须报 0 条（不能凭空造）

★ 夹具全部自造，**不读真实账本** —— 真实账本每天都在变，用它做断言等于
  把「昨天绿今天红」变成常态（记忆里的坑：负控夹具不许依赖实时数据）。

用法：
    python output/_p_watchman_negctl.py
    python output/_p_watchman_negctl.py --keep    # 保留夹具目录以便排查
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LINE_C = os.path.join(os.path.dirname(HERE), "linec")
WATCHMAN = os.path.join(LINE_C, "watchman.py")
FIXTURE = os.path.join(HERE, "_p_fixture_nc")


def fixture_dir(mode: str) -> str:
    """每个臂一个独立目录。

    ★ 不许三臂共用目录再 rmtree 重建：Windows 上子进程刚读完的文件句柄
      可能还没释放，`shutil.rmtree` 会报 WinError 5，于是负控**自己崩在
      重建夹具这一步**，看起来像「被测代码坏了」。夹具的问题要和被测的
      问题分开——这条是记忆里「夹具污染长得和检测器灵敏一模一样」的同族。
    """
    return os.path.join(FIXTURE, mode)

#: 夹具用的两个合法规则号。从规则库读，读不到就跳过本项（不许硬编码一个可能不存在的号）
def pick_rule_ids(n: int = 2) -> list:
    path = os.path.join(ROOT, "rules", "default.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f).get("rules", [])
        ids = [r["id"] for r in rules if isinstance(r, dict) and r.get("id")]
        return ids[:n]
    except Exception:
        return []


def rec(ts: datetime, typ: str = "pre_tool_use", **kw) -> dict:
    d = {"ts": ts.strftime("%Y-%m-%dT%H:%M:%S+08:00"), "type": typ}
    d.update(kw)
    return d


def write_day(root: str, day: str, rows: list) -> None:
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, f"{day}.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def build(root: str, mode: str, a: str, b: str) -> None:
    """造 9 天账本：前 8 天打底，第 9 天（今天）按 mode 造线索。

    mode = "pair"   → 今天形成一条罕见配对（NC1）
    mode = "nopair" → 同样打底，但今天没有配对（NC3）
    mode = "noise"  → 今天只有噪声（NC2）
    """
    if os.path.isdir(root):
        for fn in os.listdir(root):
            try:
                os.remove(os.path.join(root, fn))
            except OSError:
                pass
    os.makedirs(root, exist_ok=True)
    base = datetime(2026, 10, 20, 9, 0, 0)
    days = [(base + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(8)]
    today = (base + timedelta(days=8)).strftime("%Y-%m-%d")

    for i, d in enumerate(days):
        t0 = datetime.strptime(d, "%Y-%m-%d") + timedelta(hours=9)
        rows = []
        # 打底：每天各 10 条普通动作，保证 baseline / absent 有基线
        for k in range(10):
            rows.append(rec(t0 + timedelta(minutes=k * 3)))
        # 规则 A、B 各自每天命中 1 次（让 solo >= min_each=3）
        rows.append(rec(t0 + timedelta(hours=1), rules_hit=[a], session=f"s{i}"))
        rows.append(rec(t0 + timedelta(hours=2), rules_hit=[b], session=f"s{i}"))
        write_day(root, d, rows)

    t0 = datetime.strptime(today, "%Y-%m-%d") + timedelta(hours=9)
    rows = []
    for k in range(10):
        rows.append(rec(t0 + timedelta(minutes=k * 3)))

    if mode == "pair":
        # 同一会话内 A 之后 2 分钟命中 B ⇒ 罕见配对（此前从未配对）
        rows.append(rec(t0 + timedelta(hours=1), rules_hit=[a], session="today"))
        rows.append(rec(t0 + timedelta(hours=1, minutes=2), rules_hit=[b], session="today"))
    elif mode == "nopair":
        # 有 A 有 B，但**不在同一会话**，间隔也超窗 ⇒ 不该形成配对
        rows.append(rec(t0 + timedelta(hours=1), rules_hit=[a], session="x"))
        rows.append(rec(t0 + timedelta(hours=3), rules_hit=[b], session="y"))
    elif mode == "noise":
        # 只有噪声：常见命令、常见域名。
        # ★ 条数与时间分布都必须与打底日**完全对齐**（10 条、09:00 起每 3 分钟），
        #   否则会触发 baseline 偏离 —— 那是夹具的错，不是被测代码的错。
        #   这一条第一次写漏了（多造了 12 条），NC2 因此红在 baseline 上，
        #   看起来像「降噪没生效」，实际是夹具自己制造了偏离。
        rows.clear()
        for k in range(10):
            m = k % 3
            if m == 0:
                rows.append(rec(t0 + timedelta(minutes=k * 3),
                                input={"command": "chmod +x run.sh", "content_len": 0}))
            elif m == 1:
                rows.append(rec(t0 + timedelta(minutes=k * 3),
                                input={"command": "curl https://www.baidu.com/", "content_len": 0}))
            else:
                rows.append(rec(t0 + timedelta(minutes=k * 3)))
    write_day(root, today, rows)


def run_watch(root: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-E", "-X", "utf8", WATCHMAN,
         "--root", root, "--cap", "100", "--json"],
        capture_output=True,
        cwd=ROOT,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "watchman 退出 %d：%s"
            % (proc.returncode, proc.stderr.decode("utf-8", "replace")[:400])
        )
    return json.loads(proc.stdout.decode("utf-8", "replace"))


def kinds(data: dict, kind: str) -> list:
    return [c for c in (data.get("clues") or []) if c.get("kind") == kind]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="watchman 负控 NC1/NC2/NC3")
    ap.add_argument("--keep", action="store_true", help="保留夹具目录")
    args = ap.parse_args(argv)

    ids = pick_rule_ids(2)
    if len(ids) < 2:
        print("[跳过] 规则库里取不到两个合法规则号 ⇒ 本项不可判定")
        return 2
    a, b = ids

    fails = []

    def check(name: str, ok: bool, detail: str) -> None:
        print("  %-4s %s%s" % ("✅" if ok else "❌", name, ("  " + detail) if detail else ""))
        if not ok:
            fails.append(name)

    print("=" * 70)
    print("watchman 负控 · 规则号 %s / %s" % (a, b))
    print("=" * 70)

    # ---- NC1：只有一条罕见配对，必须报 ----
    fx1 = fixture_dir("pair")
    build(fx1, "pair", a, b)
    d1 = run_watch(fx1)
    pairs1 = kinds(d1, "rule_pair")
    check("NC1 罕见配对必须报出来", len(pairs1) >= 1,
          "报了 %d 条 rule_pair" % len(pairs1))

    # ---- NC3：同样的账本但删掉配对，必须报 0 ----
    fx3 = fixture_dir("nopair")
    build(fx3, "nopair", a, b)
    d3 = run_watch(fx3)
    pairs3 = kinds(d3, "rule_pair")
    check("NC3 没有配对时不许凭空造", len(pairs3) == 0,
          "报了 %d 条 rule_pair" % len(pairs3))

    # ---- NC2：只有噪声，必须报 0 ----
    fx2 = fixture_dir("noise")
    build(fx2, "noise", a, b)
    d2 = run_watch(fx2)
    total2 = len(d2.get("clues") or [])
    check("NC2 只有噪声时不许报", total2 == 0,
          "报了 %d 条：%s" % (
              total2,
              "；".join((c.get("subject") or "")[:40] for c in (d2.get("clues") or [])[:3]),
          ))

    if not args.keep and os.path.isdir(FIXTURE):
        shutil.rmtree(FIXTURE, ignore_errors=True)
    print("=" * 70)
    if fails:
        print("结论：红 %d 项 —— %s" % (len(fails), "、".join(fails)))
        return 1
    print("结论：3/3 通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
