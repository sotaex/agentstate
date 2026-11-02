# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""线索账本 · 端到端负控（E1–E5）

──────────────────────────────────────────────────────────────────────────
它解决什么问题
──────────────────────────────────────────────────────────────────────────
`clue_ledger.py --selfcheck` 验的是**账本自己的函数**。它不能回答：

    账本接进 watchman 以后，人看到的报告还对不对？

两者会分家。真事两件（都发生在接入当天）：

  · 第一版把 `key_version` 变更写成 `ledger_error` ⇒ 账本被判「不可用」
    ⇒ 不记账 ⇒ 不保存 ⇒ 提示**每一遍都重复**。自检 8/8 全绿，
    因为自检根本不经过 watchman 的 `main()`。
  · 第一版同日重跑正确静默了，但报告首句仍写「**没有需要你看的**」——
    那 4 条不是「没有」，是「今天说过了」。数字对了，话说错了。

⇒ 这两件都不是「函数算错了」，是**接线的语义错了**。
  所以必须有一条从命令行进去、从报告文本出来的负控。

──────────────────────────────────────────────────────────────────────────
五臂
──────────────────────────────────────────────────────────────────────────
E1  账本里每条都「已说满 3 次」     → 本次必须一条都不说（静默生效）
E2  把静默期改到昨天（已到期）      → 必须回来说一次（占空比，不是永久闭嘴）
E3  `--no-ledger`                   → 必须全部回来说（退回一次性，可撤销）
E4  账本文件不存在                  → 必须全当新的，且跑完要建出文件
E5  连跑两遍                        → 第二遍必须一条不说（幂等）

★ 夹具用**真账本的一份拷贝**，但断言只看「说几条」这个相对量，
  不看具体哪几条 —— 账本每天在变，钉死内容会让「昨天绿今天红」变成常态。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LINE_C = os.path.join(HERE, "lineC")
WATCH = os.path.join(LINE_C, "watchman.py")
LEDGER = os.path.join(LINE_C, "_watchman_ledger.json")


def run_watch(ledger: str | None, extra: list[str] | None = None) -> str:
    # ★ 不许用 sys.executable：它是绝对路径，会被本仓钩子 SIGTERM 掉
    #   （TOOLPIT 第 2 条：绝对路径调 python 一律被杀）。用字面量 python。
    cmd = ["python", "-E", "-X", "utf8", WATCH]
    if ledger:
        cmd += ["--ledger", ledger]
    cmd += extra or []
    p = subprocess.run(cmd, cwd=os.path.dirname(HERE), capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=600)
    if p.returncode != 0:
        raise RuntimeError("watchman 退出码 %d：%s" % (p.returncode, (p.stderr or "")[-300:]))
    return p.stdout


def said_n(out: str) -> int:
    """从「—— 账本 ——」那一行读「本次说 N 条」。**只读报告，不读内部状态。**"""
    for ln in out.splitlines():
        if ln.startswith("—— 账本 ——"):
            for seg in ln.split("｜"):
                seg = seg.strip()
                if seg.startswith("本次说"):
                    return int(seg.split("本次说")[1].split("条")[0].strip())
    raise AssertionError("报告里没有「本次说 N 条」—— 披露缺失，不能靠猜")


def numbered_n(out: str) -> int:
    """报告里真正印出来的编号条目数（1. 2. 3. …）。"""
    n = 0
    for ln in out.splitlines():
        head = ln.split(". ", 1)[0]
        if head.isdigit() and ln[len(head) + 2:len(head) + 3] != " ":
            n += 1
    return n


def main() -> int:
    if not os.path.exists(LEDGER):
        # 没有真账本就先跑一遍造出来。**不跳过** —— 跳过会让这条负控
        # 在干净机器上「通过」，而那正是它该失败的时候。
        run_watch(None)

    tmp = tempfile.mkdtemp(prefix="ledger-e2e-")
    ok = 0
    bad: list[str] = []

    def arm(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        if cond:
            ok += 1
            print("  [OK] %s %s" % (name, detail))
        else:
            bad.append(name)
            print("  [XX] %s %s" % (name, detail))

    base = json.load(open(LEDGER, encoding="utf-8"))
    keys = sorted(base.get("entries") or {})
    if not keys:
        print("[停] 真账本里一条都没有，这条负控没有意义 —— 先跑一次 watchman")
        return 2

    # —— E1 事件类：跨日重跑、内容没变 ⇒ 不说 ——
    # ★ 2026-11-02 改。旧臂是「说满 3 次 ⇒ 静默」，依赖 `SILENT_AFTER=3`。
    #   新语义下事件类**说一次就够**，而故障类永不静默 —— 那个 3 已经不决定行为了。
    #   新臂验的是真正的不变量：**同一件事内容没变，就不该再说第二遍。**
    #   做法：从真账本起 → 先跑一遍（记下今天的指纹）→ 把「今天说过」改成「昨天说过」
    #   → 再跑。内容没变 ⇒ 一条都不该说。
    p1 = os.path.join(tmp, "muted.json")
    shutil.copyfile(LEDGER, p1)
    run_watch(p1)                                  # 第一遍：记下指纹与 n_told_total
    d = json.load(open(p1, encoding="utf-8"))
    for e in d["entries"].values():
        e["last_told_day"] = "2000-01-01"          # 假装是昨天说的
    json.dump(d, open(p1, "w", encoding="utf-8"), ensure_ascii=False)
    out1 = run_watch(p1)
    arm("E1 内容没变跨日也不说", said_n(out1) == 0 and numbered_n(out1) == 0,
        "本次说 %d／印出 %d 条" % (said_n(out1), numbered_n(out1)))

    # —— E2 内容变了 ⇒ 重开（ack / 静默都不是永久失明）——
    # 把「上次见到的内容」伪造成一个不同的指纹，等价于「这件事变了」。
    p2 = os.path.join(tmp, "reopened.json")
    shutil.copyfile(p1, p2)
    d = json.load(open(p2, encoding="utf-8"))
    for e in d["entries"].values():
        e["fingerprint"] = "000000000000"
    json.dump(d, open(p2, "w", encoding="utf-8"), ensure_ascii=False)
    out2 = run_watch(p2)
    arm("E2 内容变了会重开", said_n(out2) > 0,
        "本次说 %d 条（变了必须开口，否则静默就是永久闭嘴）" % said_n(out2))

    # —— E3 --no-ledger ⇒ 全部回来 ——
    out3 = run_watch(None, ["--no-ledger"])
    arm("E3 关掉账本全部回来", numbered_n(out3) >= said_n(out1) and numbered_n(out3) > 0,
        "印出 %d 条（静默臂只印 %d 条）" % (numbered_n(out3), numbered_n(out1)))

    # —— E4 账本不存在 ⇒ 全当新的，且跑完建出文件 ——
    p4 = os.path.join(tmp, "fresh.json")
    out4 = run_watch(p4)
    arm("E4 无账本时全当新的", said_n(out4) > 0 and os.path.exists(p4),
        "本次说 %d 条｜账本已建=%s" % (said_n(out4), os.path.exists(p4)))

    # —— E5 连跑两遍 ⇒ 第二遍一条不说（幂等）——
    p5 = os.path.join(tmp, "idem.json")
    out5a = run_watch(p5)
    out5b = run_watch(p5)
    arm("E5 同日重跑幂等", said_n(out5a) > 0 and said_n(out5b) == 0,
        "第一遍 %d 条／第二遍 %d 条" % (said_n(out5a), said_n(out5b)))

    print("\n  结论：%d/5 通过%s" % (ok, "" if not bad else "，失败：" + "、".join(bad)))
    print("  夹具目录（可自行清理）：%s" % tmp)
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
