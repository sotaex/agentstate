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

import hashlib
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

#: 参与计算的源文件（顺序即报告里的显示顺序）。
#: ★ 只列**会进入结论**的文件。把测试脚本也算进来会让指纹随测试变动而漂，
#:   那指纹就不再是「结论的来源」了。
SOURCES = [
    os.path.join(LINE_C, "tsnorm.py"),
    os.path.join(LINE_C, "auditor.py"),
    os.path.join(LINE_C, "watchman.py"),
    os.path.join(LINE_C, "evidence.py"),
    os.path.join(LINE_C, "citecheck.py"),
    os.path.join(LINE_C, "onepager.py"),
    os.path.join(LINE_C, "corrections.py"),
    os.path.join(LINE_C, "redteam.py"),
]

#: 检查项：(名字, 命令, 期望退出码)
CHECKS: List[Tuple[str, List[str], int]] = [
    ("evidence --selfcheck", [os.path.join(LINE_C, "evidence.py"), "--selfcheck"], 0),
    ("citecheck --selfcheck", [os.path.join(LINE_C, "citecheck.py"), "--selfcheck"], 0),
    ("onepager --selfcheck", [os.path.join(LINE_C, "onepager.py"), "--selfcheck"], 0),
    ("corrections --selfcheck", [os.path.join(LINE_C, "corrections.py"), "--selfcheck"], 0),
    ("负控 evidence 18 臂", [os.path.join(OUTPUT, "_p_evid_negctl.py")], 0),
    ("负控 C-2 30 臂", [os.path.join(OUTPUT, "_p_c2_negctl.py")], 0),
    ("负控 更正端到端 11 臂", [os.path.join(OUTPUT, "_p_corr_e2e.py")], 0),
    ("红队 6 臂", [os.path.join(LINE_C, "redteam.py")], 0),
]


def sha_file(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def group_fingerprint(items: List[Tuple[str, str]]) -> str:
    """组指纹：`名字:sha256` 排序后拼接再哈希。

    ★ 用**名字 + 内容**而不是只有内容：否则「两个文件互换内容」算出的组指纹
      不变，而那是两套不同的代码。
    """
    basis = "\n".join("%s:%s" % (n, h) for n, h in sorted(items))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def main() -> int:
    t0 = time.time()
    print("=" * 78)
    print("C 线总闸门 · 代码指纹 ＋ 全部自检／负控")
    print("=" * 78)

    # ---- 1 代码指纹 ----
    print("\n[代码指纹] 参与计算的源文件：")
    items: List[Tuple[str, str]] = []
    missing: List[str] = []
    for p in SOURCES:
        name = os.path.basename(p)
        h = sha_file(p)
        if not h:
            missing.append(name)
            print("  %-18s 缺失" % name)
            continue
        items.append((name, h))
        mtime = time.strftime("%m-%d %H:%M", time.localtime(os.path.getmtime(p)))
        print("  %-18s sha256:%s  %7d B  %s"
              % (name, h[:12], os.path.getsize(p), mtime))
    if missing:
        print("\n[停] 有源文件缺失：%s ⇒ 指纹不完整，不许当凭据用。" % "、".join(missing))
        return 2
    gid = group_fingerprint(items)
    print("\n  组指纹 **%s**" % gid[:16])
    print("  ⇒ 把它写进报告页脚，就能回答「这份报告是哪份代码算的」。")

    # ---- 2 全部检查 ----
    print("\n[检查] 逐项跑（全部跑完再报，不中途停）：")
    fails: List[Tuple[str, int, str]] = []
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
        tail = ""
        for ln in reversed((out + "\n" + err).splitlines()):
            if ln.strip():
                tail = ln.strip()
                break
        print("  [%s] %-26s %5.1fs  %s" % ("OK" if ok else "XX", name, dt, tail[:60]))
        if not ok:
            fails.append((name, rc, tail))

    # ---- 3 汇总 ----
    print("\n" + "-" * 78)
    n_ok = len(CHECKS) - len(fails)
    print("合计 %d 项：通过 %d ／ 失败 %d ｜ 总耗时 %.1fs ｜ 组指纹 %s"
          % (len(CHECKS), n_ok, len(fails), time.time() - t0, gid[:16]))
    if fails:
        print("\n失败项（修完再跑，不要只跑红的那一项——红可能互相掩盖）：")
        for name, rc, tail in fails:
            print("  · %s（退出码 %d）：%s" % (name, rc, tail))
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
