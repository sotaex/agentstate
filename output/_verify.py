#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""A 线验证总入口 —— 一条命令跑全部判据，并行，**只报与预期的差异**。

## 为什么要有它（效率的三个成本项，按「贵」排序）

### ③ 信号可不可信 —— 最贵，也是最容易被忽略的一项

现在有 **4 处恒红／恒 SKIP**：A4 的 `N7-b`（#56b 设计缺口）、A6 的 `G1`（#59a）
与 `H`（#59h）、0353 的 `P12 判据不起真监理`（#62，活体相关）。
它们**每次都混在日志里** ⇒ 每跑一次我都要**读一遍日志再判断**「这是新红还是旧红」。
而这个判断一旦出错，代价不是几分钟，是**返工**：A4 的 S08 违规在树上躺了三轮，
就是因为每轮我只跑了自己的探针、没跑既有判据（#60a）。

⇒ 本文件把「预期」变成**数据**（`TARGETS` 里的 `known`），运行后**只打印差异**：
    `= 预期` / `! 新红` / `~ 预期红消失`。判断从「读日志」变成「读一行」。

### ① 跑多慢

三条全仓扫描型实测：`0372` 8.6s ＋ `0353` 54.6s ＋ `0490` 57.0s ≈ **120s 串行**。
它们互不共享可变状态 ⇒ 并行后 ≈ 57s（**实测**：并行与串行的绿/红数与红项逐字相同）。

### ② 该跑哪些

`0364` 是**定向**的（只读 `inbox_model.py`／`psl/manifest.json`／`host_shield.py`，
全仓扫描调用点 0 处）⇒ 改 `situation.py` 时它**不可能**红，默认不跑（`--all` 才跑）。
反之 `0372`／`0353`／`0490` 有全仓扫描调用点（1／9／2 处）⇒ **任何 .py 改动都必须跑**。

## 三档回路（按改动面选，不要每次都用最重的那档）

    --fast     只跑四条探针（秒级）        ← 改完一个函数后的内环
    （默认）   探针 ＋ 三条扫描型（~60s）  ← 提交前
    --all      再加 0364（定向，subject 变了才需要）
    交付前     `ci/delivery_gate.py`（20-25min，**不在本文件里跑**）

## 判定与退出码

    0  与预期一致（可能带 `~ 预期红消失` 提示 —— **那不是失败**，是环境变了）
    1  新增红 / rc 漂移 / 摘要漂移
    2  本工具自身失效（`--selftest` 用）

## 纪律

★ 本文件**只编排、不判**：不新增任何判据逻辑，只调既有探针与套件。
  一旦它开始自己判，就变成了第二个真源 —— 而 §5.1 的病灶（`ci/_situation_cases.py`
  在 `ci/` 里却零消费者）正是「判据长在了闸门外」。Z 步把探针迁进 `ci/` 之后，
  本文件应当退化为「调 `delivery_gate.py --only`」的薄壳。
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

#: 两条 worktree 的根：探针在 design，产品代码与套件在 impl。
DESIGN = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = r"D:\psl\poc\antinel-security\.worktrees\impl"
PY = sys.executable

#: 每条目标的「预期」。`known` 是**已知红**（每项都要能说出是谁的账），
#: `known_skip` 是**已知 SKIP**。二者都参与**双向**比对：
#:   预期里没有的红 ⇒ `! 新红`（失败）；预期里的红不见了 ⇒ `~ 消失`（提示，不是失败）。
TARGETS = [
    # ── 四条探针（A 线验收，全在闸门外 —— 这是 §5.2 的结构性风险，Z 步才迁）──
    dict(key="A3", kind="probe_cases", cwd=DESIGN, script="output/_p_axes_81.py",
         verdict="PROBE-PASS", known=(), known_skip=(), timeout=300, tier="fast",
         what="四轴映射：81 格反查 ＋ 63 格灯/成因 0 diff ＋ 31 行夹具"),
    dict(key="A4", kind="probe_cases", cwd=DESIGN, script="output/_p_cases_run.py",
         verdict="PROBE-PARTIAL", known=("N7-b",),
         known_skip=("N12-a", "N12-b", "N12-c"), timeout=300, tier="fast",
         what="57 行夹具 ＋ 四条结构判据（天数/档位/gaps/表外来源）"),
    dict(key="A5", kind="probe_cases", cwd=DESIGN, script="output/_p_presence.py",
         verdict="PROBE-PASS", known=(), known_skip=(), timeout=300, tier="fast",
         what="在场证明：切片口径 ＋ 空档判定"),
    dict(key="A6", kind="probe_disclosure", cwd=DESIGN, script="output/_p_disclosure.py",
         verdict="PROBE-PARTIAL", known=("G1", "H"), known_skip=(), timeout=300, tier="fast",
         what="披露句：逐字溯源 ＋ 宽度复算 ＋ 状态词网"),
    # ── 三条全仓扫描型（任何 .py 改动都可能踩到，必须跑）──
    # ★ `green_min` 是**下界**不是等值：别条线往同一套件里加判据是**增长**，
    #   不是回归。钉成等值会让 B 线一合并就误报 —— 而误报会训练出「忽略它」。
    #   绿数**掉下来**才报（说明某条判据不见了）；涨上去只提示。
    dict(key="0372", kind="suite", cwd=IMPL, script="ci/inbox_guards_0372.py",
         green_min=28, red=0, known=(), timeout=600, tier="scan",
         what="灯态词/事件词单源（S08）＋ 心跳链 ＋ 光梯次序"),
    dict(key="0490", kind="suite", cwd=IMPL, script="ci/inbox_guards_0490.py",
         green_min=138, red=0, known=(), timeout=600, tier="scan",
         what="U 系列细节修订判据"),
    dict(key="0353", kind="suite", cwd=IMPL, script="ci/inbox_guards_0353.py",
         green_min=215, red=1, known=("P12 判据不起真监理",), timeout=600, tier="scan",
         what="inbox 全量判据（含 P12 渲染与保活权威）"),
    # ── 定向型（只读三个文件，默认不跑）──
    dict(key="0364", kind="suite", cwd=IMPL, script="ci/inbox_guards_0364.py",
         green_min=24, red=0, known=(), timeout=600, tier="opt",
         what="定向：只读 inbox_model.py／psl/manifest.json／host_shield.py"),
]

#: 0353 那条已知红的**账**（写在这里，避免下一个人以为是新红）。
KNOWN_NOTE = {
    "N7-b": "#56b：partial_read 缺「落点」字段 ⇒ 受监管截断与非核心截断在 facts 层不可区分",
    "G1": "#59a：新模型 9 个状态词里 7 个在 glossary.TERMS 没有词条（上线阻塞）",
    "H": "#59h：冻结件自身两处账句不一致（「处理完了」vs「处理完成了」），待裁定",
    "P12 判据不起真监理": "#62：负控被活体状态挡死（sentinel_alive=True ⇒ 不 spawn）；"
                          "**红的方向错了**，是实现被怀疑而实际是负控自身失效",
}

_SUM = re.compile(r"(\d+)\s*(?:绿|green)\s*/\s*(\d+)\s*(?:红|red)")
_VERDICT = re.compile(r"PROBE-(PASS|PARTIAL|FAIL)")
#: 0353 的红行：`RED  P12 判据不起真监理 ［负控］`
_RED_LINE = re.compile(r"^\s*(?:RED|❌|\[FAIL\])\s+(.+?)(?:\s{2,}|［|$)")
#: A4 的 `RED  N7-b    lamp：…` / `SKIP N12-a   …`
_CASE_LINE = re.compile(r"^\s*(RED|SKIP)\s+(\S+)")
#: A6 的 `红项 3 处：G1／H`
_RED_AGG = re.compile(r"红项\s*\d+\s*处[：:]\s*(.+)$")


# ────────────────────────────────── 运行 ──────────────────────────────────
def _run(t):
    """跑一条目标，返回 `(rc, 输出, 耗时)`。**不让一条崩掉拖垮整批。**"""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"          # 子进程一律 UTF-8，免 GBK 乱码
    env.setdefault("TMPDIR", r"D:\_tmp")
    t0 = time.time()
    try:
        p = subprocess.run([PY, "-u", t["script"]], cwd=t["cwd"], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           encoding="utf-8", errors="replace",
                           timeout=t.get("timeout", 600))
        return p.returncode, p.stdout or "", time.time() - t0
    except subprocess.TimeoutExpired as e:
        out = e.output or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return 124, out + "\n[本工具判定：超时 %ss]" % t.get("timeout"), time.time() - t0
    except Exception as e:                                    # noqa: BLE001
        return 125, "[本工具判定：起不来 %r]" % (e,), time.time() - t0


# ────────────────────────────────── 解析 ──────────────────────────────────
def _parse_probe_cases(text):
    """A3／A4／A5：`PROBE-xxx` ＋ `RED <id>` / `SKIP <id>` 行。"""
    m = _VERDICT.search(text)
    reds, skips = set(), set()
    for line in text.splitlines():
        mm = _CASE_LINE.match(line)
        if not mm:
            continue
        (reds if mm.group(1) == "RED" else skips).add(mm.group(2))
    return {"verdict": ("PROBE-" + m.group(1)) if m else None,
            "reds": reds, "skips": skips}


def _parse_probe_disclosure(text):
    """A6：`PROBE-xxx` ＋ 汇总行 `红项 N 处：G1／H`（优先）＋ `[FAIL] <id>` 兜底。"""
    m = _VERDICT.search(text)
    reds = set()
    agg = _RED_AGG.search(text)
    if agg:
        reds |= {x.strip() for x in re.split(r"[／/、]", agg.group(1)) if x.strip()}
    else:
        for line in text.splitlines():
            mm = _RED_LINE.match(line)
            if mm:
                reds.add(mm.group(1).strip())
    return {"verdict": ("PROBE-" + m.group(1)) if m else None,
            "reds": reds, "skips": set()}


def _parse_suite(text):
    """套件：末条 `N 绿 / M 红`（或 `N green / M red`）＋ 红行标签。"""
    hits = _SUM.findall(text)
    reds = set()
    for line in text.splitlines():
        if _SUM.search(line) and re.match(r"^\s*\d+\s*(?:绿|green)", line):
            continue                                          # 摘要行不是红项
        mm = _RED_LINE.match(line)
        if mm:
            reds.add(mm.group(1).strip())
    if not hits:
        return {"green": None, "red": None, "reds": reds}
    g, r = hits[-1]
    return {"green": int(g), "red": int(r), "reds": reds}


_PARSERS = {"probe_cases": _parse_probe_cases,
            "probe_disclosure": _parse_probe_disclosure,
            "suite": _parse_suite}


# ────────────────────────────────── 比对 ──────────────────────────────────
def compare(t, rc, text):
    """返回 `(status, lines)`。status ∈ SAME／NEW_RED／RED_GONE／DRIFT。

    ★ 这是本文件唯一的判断逻辑，且它判的是**「与预期是否一致」**，
      不是「实现对不对」—— 后者归探针与套件。这条边界不许越过。
    """
    got = _PARSERS[t["kind"]](text)
    lines, hard, gone = [], False, False

    if t["kind"] in ("probe_cases", "probe_disclosure"):
        want = t["verdict"]
        if got["verdict"] != want:
            hard = True
            lines.append("结论 %r ≠ 预期 %r（rc=%s）" % (got["verdict"], want, rc))
        new = got["reds"] - set(t["known"])
        missing = set(t["known"]) - got["reds"]
        new_skip = got["skips"] - set(t["known_skip"])
        missing_skip = set(t["known_skip"]) - got["skips"]
        for x in sorted(new):
            hard = True
            lines.append("新红 %s（不在预期清单里）" % x)
        for x in sorted(missing):
            gone = True
            lines.append("预期红消失 %s —— %s" % (x, KNOWN_NOTE.get(x, "")))
        for x in sorted(new_skip):
            hard = True
            lines.append("新 SKIP %s（预期外）" % x)
        for x in sorted(missing_skip):
            gone = True
            lines.append("预期 SKIP 消失 %s（依赖已就位？）" % x)
        if rc not in (0, 3) and not hard:
            hard = True
            lines.append("rc=%s 不在探针约定里（0=全绿 / 3=只有已知红）" % rc)
    else:
        g, r = got["green"], got["red"]
        gmin = t["green_min"]
        # ① 红数**必须**等值：多一条就是新红，少一条是判据丢了
        if r != t["red"]:
            hard = True
            lines.append("红数 %r ≠ 预期 %d（%r）" % (r, t["red"], sorted(got["reds"])))
        # ② 绿数只钉**下界**：掉下来＝有判据不见了（硬）；涨上去＝别条线加判据（提示）
        if g is None:
            hard = True
            lines.append("读不到摘要行（`N 绿 / M 红`）—— 套件可能提前崩了")
        elif g < gmin:
            hard = True
            lines.append("绿数 %d < 下界 %d ⇒ 有判据**不见了**（不是「变红」，是「没跑」）"
                         % (g, gmin))
        elif g > gmin:
            lines.append("判据增长 +%d（绿 %d > 下界 %d）—— 通常是别条线新增，不是问题"
                         % (g - gmin, g, gmin))
        # ③ 红项**具名**比对：只有数对了、名不对，说明换了一条红 —— 必须报
        if r is not None and r > 0:
            new = got["reds"] - set(t["known"])
            missing = set(t["known"]) - got["reds"]
            for x in sorted(new):
                hard = True
                lines.append("新红 %r（不在预期清单里）" % x)
            for x in sorted(missing):
                gone = True
                lines.append("预期红消失 %r" % x)
        if rc not in (0, 1) and not hard:
            hard = True
            lines.append("rc=%s 不在套件约定里（0=全绿 / 1=有红）" % rc)

    if hard:
        return "NEW_RED", lines
    if gone:
        return "RED_GONE", lines
    return "SAME", lines


# ────────────────────────────────── 自检 ──────────────────────────────────
def selftest():
    """本工具自身的负控 —— 证明「比对器有牙」，而不是恒绿。

    ★ 为什么要：本文件的失效形状是**它自己恒报 `= 预期`**。
      那时它会把我对红噪声的容忍度变成对**所有红**的容忍度，
      比没有这个工具更坏。所以它必须有负控。
    """
    bad = []
    cases = [
        # (标签, 目标, rc, 假输出, 期望 status)
        ("新红必须报",
         dict(kind="probe_cases", verdict="PROBE-PARTIAL", known=("N7-b",),
              known_skip=("N12-a", "N12-b", "N12-c")),
         3, "PROBE-PARTIAL 只有已知红\nRED  N7-b  x\nRED  N99  y\nSKIP N12-a  z\n"
            "SKIP N12-b  z\nSKIP N12-c  z\n", "NEW_RED"),
        ("预期红消失必须报",
         dict(kind="probe_cases", verdict="PROBE-PARTIAL", known=("N7-b",),
              known_skip=("N12-a", "N12-b", "N12-c")),
         3, "PROBE-PARTIAL 只有已知红\nSKIP N12-a  z\nSKIP N12-b  z\nSKIP N12-c  z\n",
         "RED_GONE"),
        ("与预期一致必须 SAME",
         dict(kind="probe_cases", verdict="PROBE-PARTIAL", known=("N7-b",),
              known_skip=("N12-a", "N12-b", "N12-c")),
         3, "PROBE-PARTIAL 只有已知红\nRED  N7-b  x\nSKIP N12-a  z\n"
            "SKIP N12-b  z\nSKIP N12-c  z\n", "SAME"),
        ("套件红项换名必须报",
         dict(kind="suite", green_min=215, red=1, known=("P12 判据不起真监理",)),
         1, "  RED  P12 别的一条  x\n  215 绿 / 1 红\n", "NEW_RED"),
        ("套件摘要漂移必须报",
         dict(kind="suite", green_min=28, red=0, known=()),
         1, "  27 绿 / 1 红\n", "NEW_RED"),
        # ★ 绿数只钉下界：掉下来是「判据不见了」（硬），涨上去是「别条线加判据」（提示）
        ("绿数掉下下界必须报",
         dict(kind="suite", green_min=28, red=0, known=()),
         0, "  27 绿 / 0 红\n", "NEW_RED"),
        ("绿数增长必须 SAME（别条线加判据不是回归）",
         dict(kind="suite", green_min=28, red=0, known=()),
         0, "  31 绿 / 0 红\n", "SAME"),
        ("读不到摘要行必须报",
         dict(kind="suite", green_min=28, red=0, known=()),
         0, "Traceback (most recent call last):\nImportError: x\n", "NEW_RED"),
    ]
    for tag, t, rc, text, want in cases:
        st, lines = compare(t, rc, text)
        if st != want:
            bad.append("%s：得 %r，应 %r（%r）" % (tag, st, want, lines))
    if bad:
        print("SELFTEST-FAIL 比对器自身失效：")
        for b in bad:
            print("  · " + b)
        return 2
    print("SELFTEST-PASS 比对器 %d 条负控全真红／全真绿" % len(cases))
    return 0


# ────────────────────────────────── 主流程 ──────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--fast", action="store_true", help="只跑四条探针（秒级内环）")
    ap.add_argument("--all", action="store_true", help="连定向型 0364 一起跑")
    ap.add_argument("--only", default="", help="逗号分隔的 key（A3,0372…）")
    ap.add_argument("--selftest", action="store_true", help="只跑本工具自身的负控")
    ap.add_argument("--jobs", type=int, default=4, help="并行度（默认 4）")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    only = {x.strip() for x in args.only.split(",") if x.strip()}
    picked = []
    for t in TARGETS:
        if only and t["key"] not in only:
            continue
        if not only:
            if args.fast and t["tier"] != "fast":
                continue
            if not args.all and t["tier"] == "opt":
                continue
        picked.append(t)

    print("=" * 86)
    print("A 线验证总入口　目标 %d 条　并行度 %d　模式 %s"
          % (len(picked), args.jobs,
             "fast（探针）" if args.fast else ("all" if args.all else "默认")))
    print("=" * 86)

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
        futs = [(t, ex.submit(_run, t)) for t in picked]
        raw = [(t, f.result()) for t, f in futs]
    wall = time.time() - t0

    hard_bad, soft = [], []
    print("%-6s %-8s %-5s %-13s %s" % ("目标", "耗时", "rc", "判定", "说明"))
    print("-" * 86)
    for t, (rc, text, dt) in raw:
        st, lines = compare(t, rc, text)
        tag = {"SAME": "= 预期", "RED_GONE": "~ 消失",
               "NEW_RED": "! 偏离", "DRIFT": "! 偏离"}[st]
        print("%-6s %-8s %-5s %-13s %s"
              % (t["key"], "%.1fs" % dt, rc, tag, t["what"][:34]))
        for ln in lines:
            print("        %s %s" % ("!" if st == "NEW_RED" else "~", ln))
        if st == "NEW_RED":
            hard_bad.append((t["key"], lines))
        elif st == "RED_GONE":
            soft.append((t["key"], lines))

    print("-" * 86)
    print("墙钟 %.1fs（串行预估 %.1fs）"
          % (wall, sum(dt for _t, (_rc, _x, dt) in raw)))
    if hard_bad:
        print("VERIFY-FAIL 与预期不符 %d 条：%s"
              % (len(hard_bad), "／".join(k for k, _l in hard_bad)))
        for k, lines in hard_bad:
            print("  · %s" % k)
            for ln in lines:
                print("      " + ln)
        return 1
    if soft:
        print("VERIFY-PASS 与预期一致（另有 %d 处预期红/SKIP 消失 —— 不是失败，值得看一眼）"
              % len(soft))
        return 0
    print("VERIFY-PASS 与预期完全一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
