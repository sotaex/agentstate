# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""C 线总闸门：一条命令证明「跑的是这份代码，且这份代码自检通过」。

──────────────────────────────────────────────────────────────────────────
它解决九维六（运行态确认）在 C 线上的特殊形态
──────────────────────────────────────────────────────────────────────────
九维六原话是「改了代码，怎么知道新代码真的在跑」。对**常驻服务**，这靠
「重启后看版本号 / 看心跳」；而 C 线全是**一次性只读脚本**，没有常驻态——
但这不等于「不适用」：它退化成一个更基础的问题——

    **这次跑出来的结论，是哪份代码算的？**

如果答不出来，那么「昨天绿、今天红」就无法归因：可能是账本变了，也可能是
代码变了，还可能是我跑的是一份旧的 `.pyc`。三种情况在报告里长得一样。

所以本文件做两件事：
  1. 把参与计算的**每个源文件**的 sha256 打出来，并算一个**组指纹**；
  2. 跑全部自检与负控，**任一项红就整体红**。

★ 组指纹可以直接写进报告页脚：「本报告由代码组 <指纹> 生成」。
  这样一份归档的报告永远能回答「它当时是被哪份代码算出来的」。

──────────────────────────────────────────────────────────────────────────
它同时是 P2（负控统一）
──────────────────────────────────────────────────────────────────────────
负控原来散在四个脚本里，各跑各的。这里统一成一个入口：
**红一项就停不下来，但会把全部项跑完再报**——因为「修一个红，又冒一个红」
比「一次看全」贵得多。

──────────────────────────────────────────────────────────────────────────
它不做什么
──────────────────────────────────────────────────────────────────────────
不跑 `ci/delivery_gate.py`（那是产品面的闸门，属 A 线领地，20+ 分钟）。
不写任何文件。不改任何账本。
"""

import os
import subprocess
import sys
import time
from typing import List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
#: 本文件就在 lineC 里。★ 这里踩过一次：写成 os.path.join(HERE, "lineC") 就会多一层，
#: 于是「源文件全部缺失」——而它看起来像「文件真的没了」。同一个错在 redteam.py 也犯过，
#: 两次都是「凭直觉拼路径」而不是「看一眼 HERE 到底是什么」。
LINE_C = HERE if os.path.basename(HERE) == "lineC" else os.path.join(HERE, "lineC")
OUTPUT = os.path.dirname(LINE_C)
sys.path.insert(0, LINE_C)

#: ★ 源文件清单与指纹算法**只有一处真源**：`codeid.py`。
#: 报告页脚（onepager）与本闸门都从那里取。两份清单一定会漂，而漂了以后
#: 两个指纹仍然都是「看起来正常」的十六进制串——错的东西长得和正确的东西一样。
import codeid as CID  # noqa: E402

SOURCES = CID.SOURCES

#: 检查项：(名字, 命令, 期望退出码, 超时秒)。
#: ★ 2026-11-02 加第四列：原来所有项共用一个 600s 上限，而账本长到 151MB 后
#:   `负控 C-2 30 臂` 实测已经超过 600s（同批 `C-2 5 臂` 从 94s 涨到 207s，
#:   `账本端到端` 从 143s 涨到 464s ⇒ 整机与账本都在变重）。
#:   于是闸门会**永远红**，而红的原因与代码毫无关系 —— 恒红项等于没有项。
#:   **超时不是失败**：它是「没量完」。两者在报告上长得一样，正是本仓最忌讳的
#:   「零与不可判同貌」，所以既要把预算分开给，也要在汇总里分开印。
CHECKS: List[Tuple[str, List[str], int, int]] = [
    ("codeid --selfcheck", [os.path.join(LINE_C, "codeid.py"), "--selfcheck"], 0, 600),
    ("evidence --selfcheck", [os.path.join(LINE_C, "evidence.py"), "--selfcheck"], 0, 600),
    ("citecheck --selfcheck", [os.path.join(LINE_C, "citecheck.py"), "--selfcheck"], 0, 600),
    ("onepager --selfcheck", [os.path.join(LINE_C, "onepager.py"), "--selfcheck"], 0, 600),
    ("corrections --selfcheck", [os.path.join(LINE_C, "corrections.py"), "--selfcheck"], 0, 600),
    ("report --selfcheck", [os.path.join(LINE_C, "report.py"), "--selfcheck"], 0, 600),
    ("负控 evidence 19 臂", [os.path.join(OUTPUT, "_p_evid_negctl.py")], 0, 900),
    ("端到端负控 7 臂", [os.path.join(OUTPUT, "_p_e2e_negctl.py")], 0, 600),
    # C-2 的 30 臂每臂都复制一份账本做夹具，成本随账本线性涨：
    # 账本 151MB 时实测 5 臂要 207s ⇒ 30 臂约 1250s。预算给到 2400s。
    ("负控 C-2 30 臂", [os.path.join(OUTPUT, "_p_c2_negctl.py")], 0, 2400),
    ("负控 更正端到端 11 臂", [os.path.join(OUTPUT, "_p_corr_e2e.py")], 0, 600),
    ("红队 C-1 6 臂", [os.path.join(LINE_C, "redteam.py")], 0, 600),
    ("红队 C-2 5 臂", [os.path.join(LINE_C, "redteam_c2.py")], 0, 900),
    # ★ 2026-11-02 新增：watchman 降噪负控。它回答的是「少掉的那些，是噪声还是真线索」——
    #   这个区别在报告上完全看不出来（两者都只是「条数变少」）。缺了这条，
    #   降噪就等于「以看不见的方式减少输出」，而报告仍然是绿的。
    ("负控 watchman 3 臂", [os.path.join(OUTPUT, "_p_watchman_negctl.py")], 0, 600),
    # ★ 2026-11-02 新增：线索账本。`--selfcheck` 验函数，`_p_ledger_e2e.py` 验接线。
    #   两者不能互相替代 —— 接入当天两条 bug 都是「函数对、接线错」：
    #   一条把一次性历史事件写成恒红状态，一条在正确静默的同时说了句假话
    #   （「没有需要你看的」，而那 4 条是「今天说过了」）。
    ("账本 --selfcheck", [os.path.join(LINE_C, "clue_ledger.py"), "--selfcheck"], 0, 600),
    # ★ 2026-11-02 深夜补：**第三只腿原来不在闸门里**。
    #   它 11-02 深夜才落地，而 `CHECKS` 当时已经是 16 项 ⇒ 新模块默认不受闸门保护，
    #   闸门仍然全绿 —— 这正是「加了一条腿，闸门不知道」。
    #   它的产物（`held`／`no_response` 两档）直接进一页纸首屏，
    #   所以它自检红了必须让整份报告变红。
    ("第三只腿 --selfcheck", [os.path.join(LINE_C, "verdict_leg.py"), "--selfcheck"], 0, 600),
    # 它跑 5 次 watchman，成本随账本线性涨：143s（11-02 上午）→ 464s（同日晚）。
    ("负控 账本端到端 5 臂", [os.path.join(OUTPUT, "_p_ledger_e2e.py")], 0, 1200),
    # ★ 2026-11-02 新增：打分器**量具自检**（不是打分）。它只验「还认得金标准」，
    #   不验「分数达标」—— 后者现在就是红的（精确率 50% < 66.7%），
    #   把它放进闸门会让闸门永远红，而恒红项等于没有项（铁律 41）。
    #   为什么必须有这一条：11-02 把 subject 里的规则号换成中文标签后，
    #   打分器 12 条**全部错配成「金标准外」**，精确率与召回同时归零。
    #   没有任何东西报警 —— 因为「分数难看」会被当成结论讨论，
    #   而「量具坏掉」只会被当成事实。这两者在输出上长得一样。
    ("打分器量具自检 6 臂", [os.path.join(OUTPUT, "_p_score_noise.py"), "--selfcheck"], 0, 600),
]


def main() -> int:
    t0 = time.time()
    print("=" * 78)
    print("C 线总闸门 · 代码指纹 ＋ 全部自检／负控")
    print("=" * 78)

    # ---- 1 代码指纹 ----
    print("\n[代码指纹] 参与计算的源文件：")
    fp = CID.compute()
    for name, h in fp.items:
        p = os.path.join(LINE_C, name)
        mtime = time.strftime("%m-%d %H:%M", time.localtime(os.path.getmtime(p)))
        print("  %-18s sha256:%s  %7d B  %s"
              % (name, h[:12], os.path.getsize(p), mtime))
    if not fp.ok:
        print("\n[停] 有源文件缺失：%s ⇒ 指纹不完整，不许当凭据用。"
              % "、".join(fp.missing))
        return 2
    gid = fp.gid
    print("\n  组指纹 **%s**" % fp.short)
    print("  ⇒ 报告页脚印的就是这个值（同一处真源：codeid.py）。")
    print("  ⇒ 它回答「这份结论是哪份代码算的」，**不回答「结论对不对」**。")

    # ---- 2 全部检查 ----
    print("\n[检查] 逐项跑（全部跑完再报，不中途停）：")
    fails: List[Tuple[str, int, str, List[str]]] = []
    timeouts: List[Tuple[str, int]] = []
    for name, cmd, want, tmo in CHECKS:
        full = [sys.executable, "-E", "-X", "utf8"] + cmd
        t = time.time()
        timed_out = False
        try:
            p = subprocess.run(full, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=tmo)
            rc, out, err = p.returncode, p.stdout or "", p.stderr or ""
        except subprocess.TimeoutExpired:
            rc, out, err = -1, "", "超时 %ds" % tmo
            timed_out = True
        except Exception as exc:                       # noqa: BLE001
            rc, out, err = -1, "", "%s: %s" % (type(exc).__name__, exc)
        dt = time.time() - t
        ok = (rc == want) and not timed_out
        # 取最后一行有内容的结果当摘要
        lines = [ln.strip() for ln in (out + "\n" + err).splitlines() if ln.strip()]
        tail = lines[-1] if lines else ""
        # ★ `flush=True` 不是洁癖：整个闸门要跑十几分钟，重定向到文件时
        #   stdout 是块缓冲 ⇒ 十几分钟里文件是**空的**。空文件和「进程挂了」
        #   在观感上完全一样 —— 实测就因为这个以为它卡死，白等了一刻钟。
        #   零与不可判同貌，这次是「没输出」与「没有进展」同貌。
        # ★ 超时印 `TO` 而不是 `XX`：**超时是「没量完」，失败是「量出坏结果」**。
        #   两者混印成 `XX` 的后果，是让人去修一个可能根本没坏的项
        #   （本轮实测：C-2 30 臂因账本变重而超时，看起来像 C-2 坏了）。
        mark = "TO" if timed_out else ("OK" if ok else "XX")
        print("  [%s] %-26s %5.1fs  %s" % (mark, name, dt, tail[:60]), flush=True)
        if timed_out:
            timeouts.append((name, tmo))
        elif not ok:
            # ★ 红的时候只留最后一行是不够的：负控的「合计 19 臂 18 通过」
            #   说不出是哪一臂红的，于是「去修」变成「去猜」。红项要留尾巴。
            fails.append((name, rc, tail, lines[-12:]))

    # ---- 3 汇总 ----
    print("\n" + "-" * 78)
    n_ok = len(CHECKS) - len(fails) - len(timeouts)
    print("合计 %d 项：通过 %d ／ 失败 %d ／ 超时 %d ｜ 总耗时 %.1fs ｜ 组指纹 %s"
          % (len(CHECKS), n_ok, len(fails), len(timeouts), time.time() - t0, gid[:16]))
    if timeouts:
        # 超时**不算通过**，也不许算失败：它没给出结论。单独印，并给出该给的预算。
        print("\n超时项（**没量完，不是量出坏结果**）：")
        for name, tmo in timeouts:
            print("  · %s：预算 %ds 不够。先看它历史耗时再调预算，"
                  "不要先怀疑被测对象。" % (name, tmo))
    if fails:
        print("\n失败项（修完再跑，不要只跑红的那一项——红可能互相掩盖）：")
        for name, rc, tail, tail_lines in fails:
            print("\n  · %s（退出码 %d）：%s" % (name, rc, tail))
            for ln in tail_lines:
                print("      | %s" % ln[:160])
        return 1
    if timeouts:
        # 有超时就不许说「全绿」—— 那是把「没量」当成「量好了」。
        return 1

    print("\n全绿。**这只说明「这份代码自洽」，不说明「它算出来的结论是对的」**——")
    print("结论对不对要看账本本身，那是 redteam.py 反复证明抓不住的那部分（L0 边界）。")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sys.exit(main())
