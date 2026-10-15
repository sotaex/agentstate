# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""L2 品质触发层执行程序 —— 违和自问／月度评审／48h 沉淀队列（A4，2026-10-15）。

依据 `docs/Antinel·L2品质触发层 v1.0（2026-10-15）.md`（机制论文档 §5 L2 行）。
设计原则（机制论文档 §5 原文）：**机制保证「人判必然发生且留痕」，不代替人判**。

★ 为什么这个文件不是判据套件：
  品质判据做成「不过就红」会把 AI 的优化对象从品质变成判据（古德哈特），
  且 R3「说不出的不对」永远不在判据里。⇒ 本程序不进 SUITES、不写 @check、
  不占 29 常驻预算、不产机器绿红；它是触发器＋记录器，判定归人。

用法：
  python ci/l2_wenhe_selfask.py                # 交付前：打印违和自问＋UX 洁癖清单并留痕
  python ci/l2_wenhe_selfask.py --note "..."   # 自问发现违和：进 48h 沉淀队列
  python ci/l2_wenhe_selfask.py --monthly      # 月度品质评审：打印模板并留痕
  python ci/l2_wenhe_selfask.py --pending      # 48h 沉淀队列：超时未分类条目

记录：ci/l2_feedback.jsonl（每行 {"ts","kind","text","settled"}）。
"""
import argparse
import datetime
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOG = os.path.join(HERE, "l2_feedback.jsonl")
SETTLE_HOURS = 48

WENHE = [
    "一个不认识这个项目的人第一眼看到它，会觉得「这是什么」还是「这又是另一个工具」？",
    "界面/文案/结构有没有「每处都对、放一起不对」的组合违和（术语跨模块不一致、符号混用、"
    "同一动作两种叫法）？",
    "数字有没有「说不出的不对」——分母换了、口径混了、时点没标？",
    "交互有没有让用户等一个没有反馈的瞬间（静默降级）？",
    "这次交付把什么变复杂了？新人要重读多少才能接手？",
]

UX = [
    "去星号：正文不裸用 ** ＊ 等强调符",
    "去杂符号：不堆叠 → ⇒ · ◆ 等装饰符；不用 emoji 充当状态词",
    "去英文变量名：面向用户的文字不出现 run_id / fail-open / byte-budget 等裸术语；"
    "必须出现时首次给一句平实解释",
    "去过度 jargon：每个技术词能回答「它指向哪个字段/哪类现象」，答不出就回源字段直述",
    "平实语言：短句、主动语态、说人话；不用空转词",
]

MONTHLY = [
    "抽 Q1–Q18 中本期被动过的维度（其余标「休眠＋唤醒条件」）",
    "本月 l2_feedback.jsonl 未沉淀条目清零？",
    "同族复发间隔曲线（A5 看板取数）",
    "机制总数（A5 看板）＋退休登记簿 pending 是否过期",
    "交付违和自问执行率（应交付次数 vs 实际记录次数）",
    "R3 反馈沉淀：本月每条反馈是否 48h 内分类？",
]


def _append(kind, text):
    rec = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
           "kind": kind, "text": text, "settled": None}
    with io.open(LOG, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def _load():
    if not os.path.isfile(LOG):
        return []
    out = []
    with io.open(LOG, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                try:
                    out.append(json.loads(ln))
                except ValueError:
                    continue
    return out


def _pending(now=None):
    now = now or datetime.datetime.now()
    out = []
    for r in _load():
        if r.get("settled"):
            continue
        try:
            ts = datetime.datetime.fromisoformat(r["ts"])
        except (KeyError, ValueError):
            continue
        if (now - ts) > datetime.timedelta(hours=SETTLE_HOURS):
            out.append(r)
    return out


def main():
    ap = argparse.ArgumentParser(description="L2 品质触发层执行程序")
    ap.add_argument("--note", default="",
                    help="自问中发现的违和（进 48h 沉淀队列）")
    ap.add_argument("--monthly", action="store_true", help="月度品质评审模式")
    ap.add_argument("--pending", action="store_true",
                    help="只看 48h 沉淀队列（超时未分类）")
    a = ap.parse_args()

    if a.pending:
        p = _pending()
        print("48h 沉淀队列：超时未分类 %d 条" % len(p))
        for r in p:
            print("   %s [%s] %s" % (r["ts"], r["kind"], r["text"]))
        return 1 if p else 0

    if a.monthly:
        print("=" * 66)
        print("月度品质评审（L2 采样）—— 逐项过，双票：代理指标＋终局人判")
        print("=" * 66)
        for i, m in enumerate(MONTHLY, 1):
            print("  %d. %s" % (i, m))
        _append("monthly", "月度品质评审执行")
        print("\n[留痕] 已记录到 %s" % LOG)
        return 0

    print("=" * 66)
    print("交付前违和自问（R3 触发）—— 逐条过；有违和用 --note 留痕")
    print("=" * 66)
    for i, q in enumerate(WENHE, 1):
        print("  %d. %s" % (i, q))
    print("-" * 66)
    print("创始人 UX 洁癖清单：")
    for i, u in enumerate(UX, 1):
        print("  %d. %s" % (i, u))
    print("-" * 66)
    if a.note:
        rec = _append("wenhe", a.note)
        print("[留痕] 违和已进 48h 沉淀队列：%s" % rec["ts"])
        print("       48 小时内按四岔分类（可机械化/可 checklist/可外部化/不可沉淀），"
              " settled 字段闭环。")
    else:
        _append("wenhe", "交付前违和自问执行（无 --note）")
        print("[留痕] 自问执行已记录（无违和条目）。发现违和请重跑并加 --note。")
    print("\n[记录文件] %s" % LOG)
    return 0


if __name__ == "__main__":
    sys.exit(main())
