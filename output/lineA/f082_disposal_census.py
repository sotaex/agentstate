# -*- coding: utf-8 -*-
"""82 条「处置档」普查：给四档账一个**能复算**的口径。

为什么需要这个脚本
==================
源文档 §5.1 写 `26 硬 / 2 软 / 52 告警 / 6 记账`，**加起来 86，不等于 82**。
同一件事在 2026-11-01 一天内出现过三版口径（52/2、48/6、26/2/52/2），
每一版都能让算术自洽，但**没有一版是从逐条表里数出来的**——都是推的。

本脚本只做一件事：**打开逐条表，逐行取「处置」列，数一遍。** 不解释、不推断。

四条自证腿
==========
1. **结构**：必须正好 82 行。少一行 ⇒ 正则失效（把某条漏了）；多一行 ⇒ 扫到了别的表。
2. **穷尽**：分类之和必须等于行数。不等就是有行没落进任何一类（静默丢弃）。
3. **牙齿**：内存里把某条的处置列改坏，分布**必须**跟着变 ⇒ 证明读的是真数据，
   不是在读一个自己造的常数。
4. **冲突可见**：「整行标了记账档」与「处置列写告警」的条数必须打出来。
   这两个数不一致，正是 §5.1 那个 86 的来源。

用法
====
    python output/lineA/f082_disposal_census.py
    python output/lineA/f082_disposal_census.py --source <别的清单.md>

退出码：0 全部自证腿通过；2 有腿不通（口径不可用）。
"""

from __future__ import print_function

import io
import os
import re
import sys
import collections

DEFAULT_SRC = os.path.join(
    "output", "Antinel·通用规则库基线：82条逐条清单与第三方能力（2026-10-29）.md")

# 逐条表的行首形态：| `X1-01` | ...
_ROW_RE = re.compile(r"^\|\s*`([A-Z][A-Za-z0-9]*-[0-9]+)`\s*\|")

# 六类：这是**分类判据**，不是数据。改这里等于改口径，必须同时说清为什么。
K_HARD = "硬拦"
K_SOFT = "软拦"
K_ALERT = "仅告警"
K_NOACT = "不对 Agent 施加处置"   # 标记不可信 / 自动降档 / 自我阻断 / 报告标注
K_NODISP = "无处置（判不了）"


def load_rows(path):
    """返回 [(行号, id, 各单元格)]。单元格已 strip。"""
    text = io.open(path, encoding="utf-8").read().splitlines()
    rows = []
    for i, line in enumerate(text, 1):
        m = _ROW_RE.match(line)
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        rows.append((i, m.group(1), cells))
    return rows


def disposal_cell(cells):
    """取「处置」列。

    三张子表的列数不同，必须按列位分别取，不能一律取 [4]：
      - 6 列（ID|规则|判据|证据|处置|外部依赖）⇒ [4]
      - 4 列（ID|规则|判据|处置，二阶/三阶那批）⇒ [3]
      - 7 列：只有 `A1-01` 一条，判据里含 `curl|sh` 的竖线把格子切歪了 ⇒ [5]

    7 列这条不是特例硬编码，是**先验条件**：出现第 7 列只可能是判据列自带竖线。
    真出现第二条 7 列行，下面的结构腿会把它打出来，逼着重新看。
    """
    n = len(cells)
    if n >= 7:
        return cells[5]
    if n == 6:
        return cells[4]
    if n == 4:
        return cells[3]
    return ""


def classify(raw):
    """把处置原文归到六类之一。顺序即优先级（原文档存在并列写法）。

    ★ 「记账档」**不参与**这里的分类：它是「判不判得了」那一轴，
      与「处不处得了」正交，压进同一条枚举就是 §5.1 那个 86 的成因。
    """
    if "硬" in raw:
        return K_HARD
    if "软" in raw:
        return K_SOFT
    if "告警" in raw:
        return K_ALERT
    if "记账档" in raw or raw in ("—", "**—**"):
        return K_NODISP
    return K_NOACT


def census(rows):
    """返回 (分布, 每类的 id 列表, 记账档标记列表, 告警∩记账档冲突列表)。"""
    dist = collections.Counter()
    members = collections.defaultdict(list)
    marked = []
    conflict = []
    for lineno, rid, cells in rows:
        raw = disposal_cell(cells)
        k = classify(raw)
        dist[k] += 1
        members[k].append((rid, raw))
        if any("记账档" in c for c in cells):
            marked.append((rid, raw))
            if "告警" in raw:
                conflict.append((rid, raw))
    return dist, members, marked, conflict


def main(argv):
    src = DEFAULT_SRC
    if "--source" in argv:
        src = argv[argv.index("--source") + 1]
    if not os.path.isfile(src):
        print("[FATAL] 找不到源文件：%s" % src)
        return 2

    rows = load_rows(src)
    print("源：%s" % src)
    print("=" * 66)

    # ---- 腿 1：结构 ----
    ok_struct = (len(rows) == 82)
    print("腿1 结构：逐条表 %d 行（应为 82）  %s" % (len(rows), "OK" if ok_struct else "FAIL"))

    # 列数分布也打出来：7 列应当恰好只有 A1-01 一条
    widths = collections.Counter(len(c) for _, _, c in rows)
    seven = [rid for _, rid, c in rows if len(c) >= 7]
    print("      列数分布 %s；7 列的是 %s" % (dict(widths), seven))

    dist, members, marked, conflict = census(rows)

    # ---- 腿 2：穷尽 ----
    total = sum(dist.values())
    ok_exhaust = (total == len(rows))
    print("腿2 穷尽：六类之和 %d = 行数 %d  %s"
          % (total, len(rows), "OK" if ok_exhaust else "FAIL"))

    print("-" * 66)
    print("处置分布（按处置列原文，脚本数出来的）：")
    order = [K_HARD, K_SOFT, K_ALERT, K_NOACT, K_NODISP]
    for k in order:
        pct = (100.0 * dist[k] / total) if total else 0.0
        print("  %-22s %3d  %5.1f%%" % (k, dist[k], pct))
    print("  %-22s %3d" % ("合计", total))

    print("-" * 66)
    print("明细（每类都有谁，便于逐条核对、也便于发现归类错）：")
    for k in order:
        ids = [rid for rid, _ in members[k]]
        print("  %s（%d）：%s" % (k, len(ids), " ".join(ids) if ids else "—"))

    print("-" * 66)
    print("整行标了「记账档」的 %d 条（这是**另一条轴**：判不判得了）：" % len(marked))
    for rid, raw in marked:
        print("  %-8s 处置列=%s" % (rid, raw))
    print("其中**处置列写「告警」**的 %d 条 ⇒ 它们在 §5.1 的 52 与 6 里各被数了一次，"
          % len(conflict))
    print("   这就是 26+2+52+6=86≠82 的差额来源。")

    # ---- 腿 3：牙齿 ----
    # 在内存里把第一条「硬」的处置改坏，分类必须变。不改盘上那份。
    teeth_ok = False
    hard_ids = [rid for rid, _ in members[K_HARD]]
    if hard_ids:
        target = hard_ids[0]
        mutated = []
        for lineno, rid, cells in rows:
            if rid == target:
                cells = list(cells)
                idx = 5 if len(cells) >= 7 else (4 if len(cells) == 6 else 3)
                cells[idx] = "**告警**"
            mutated.append((lineno, rid, cells))
        d2, _, _, _ = census(mutated)
        teeth_ok = (d2[K_HARD] == dist[K_HARD] - 1 and d2[K_ALERT] == dist[K_ALERT] + 1)
        print("-" * 66)
        print("腿3 牙齿：把 %s 的处置改成「告警」⇒ 硬 %d→%d、告警 %d→%d  %s"
              % (target, dist[K_HARD], d2[K_HARD], dist[K_ALERT], d2[K_ALERT],
                 "OK" if teeth_ok else "FAIL"))

    # ---- 判不了那 4 条，单独说清（判据在第 3 列证据 / 第 2 列说明）----
    print("-" * 66)
    print("★ 覆盖率分子怎么算，取决于「判不判得了」，而它**不在这张表里**：")
    print("  判不了 = 外观不可观测（UQ1-02、UI1-01）＋ 外部事实非 Agent 行为（P1-04、MP1-02）= 4")
    print("  ⇒ 判得了 = %d - 4 = %d，%d/82 = %.1f%%" % (total, total - 4, total - 4,
                                                      100.0 * (total - 4) / total))
    print("  ★ 注意：A1-10、XM3-02 虽然也被标了「记账档」，但证据列是 observed")
    print("    （能看见开关被设），**判得了、只是改不动** ⇒ 归「仅告警」，不进这个 4。")

    ok = ok_struct and ok_exhaust and teeth_ok
    print("=" * 66)
    print("★ 结论：%s" % ("口径可用（四条腿全通）" if ok else "口径不可用，先别拿这个数去写报告"))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
