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

#: 检查项：(名字, 命令, 期望退出码)
CHECKS: List[Tuple[str, List[str], int]] = [
    ("codeid --selfcheck", [os.path.join(LINE_C, "codeid.py"), "--selfcheck"], 0),
    ("evidence --selfcheck", [os.path.join(LINE_C, "evidence.py"), "--selfcheck"], 0),
    ("citecheck --selfcheck", [os.path.join(LINE_C, "citecheck.py"), "--selfcheck"], 0),
    ("onepager --selfcheck", [os.path.join(LINE_C, "onepager.py"), "--selfcheck"], 0),
    ("corrections --selfcheck", [os.path.join(LINE_C, "corrections.py"), "--selfcheck"], 0),
    ("负控 evidence 18 臂", [os.path.join(OUTPUT, "_p_evid_negctl.py")], 0),
    ("负控 C-2 30 臂", [os.path.join(OUTPUT, "_p_c2_negctl.py")], 0),
    ("负控 更正端到端 11 臂", [os.path.join(OUTPUT, "_p_corr_e2e.py")], 0),
    ("红队 C-1 6 臂", [os.path.join(LINE_C, "redteam.py")], 0),
    ("红队 C-2 5 臂", [os.path.join(LINE_C, "redteam_c2.py")], 0),
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
    for name, cmd, want in CHECKS:
        full = [sys.executable, "-E", "-X", "utf8"] + cmd
        t = time.time()
        try:
            p = subprocess.run(full, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=600)
            rc, out, err = p.returncode, p.stdout or "", p.stderr or ""
        except subprocess.TimeoutExpired:
            rc, out, err = -1, "", "超时 600s"
        except Exception as exc:                       # noqa: BLE001
            rc, out, err = -1, "", "%s: %s" % (type(exc).__name__, exc)
        dt = time.time() - t
        ok = rc == want
        # 取最后一行有内容的结果当摘要
        lines = [ln.strip() for ln in (out + "\n" + err).splitlines() if ln.strip()]
        tail = lines[-1] if lines else ""
        print("  [%s] %-26s %5.1fs  %s" % ("OK" if ok else "XX", name, dt, tail[:60]))
        if not ok:
            # ★ 红的时候只留最后一行是不够的：负控的「合计 18 臂 17 通过」
            #   说不出是哪一臂红的，于是「去修」变成「去猜」。红项要留尾巴。
            fails.append((name, rc, tail, lines[-12:]))

    # ---- 3 汇总 ----
    print("\n" + "-" * 78)
    n_ok = len(CHECKS) - len(fails)
    print("合计 %d 项：通过 %d ／ 失败 %d ｜ 总耗时 %.1fs ｜ 组指纹 %s"
          % (len(CHECKS), n_ok, len(fails), time.time() - t0, gid[:16]))
    if fails:
        print("\n失败项（修完再跑，不要只跑红的那一项——红可能互相掩盖）：")
        for name, rc, tail, tail_lines in fails:
            print("\n  · %s（退出码 %d）：%s" % (name, rc, tail))
            for ln in tail_lines:
                print("      | %s" % ln[:160])
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
