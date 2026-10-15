# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""L2 品质触发层执行程序 —— 违和自问／月度评审／48h 沉淀队列（A4，2026-10-15；v1.1 加固）。

依据 `docs/Antinel·L2品质触发层 v1.1（2026-10-15）.md`（机制论文档 §5 L2 行）。
设计原则（机制论文档 §5 原文）：**机制保证「人判必然发生且留痕」，不代替人判**。

★ 为什么这个文件不是判据套件：
  品质判据做成「不过就红」会把 AI 的优化对象从品质变成判据（古德哈特），
  且 R3「说不出的不对」永远不在判据里。⇒ 本程序不进 SUITES、不写 @check、
  不占 29 常驻预算、不产机器绿红；它是触发器＋记录器，判定归人。
  ★ v1.1 补的 `--guard` 同样**只出声不裁决**（rc 恒 0，D-37 同型）：
    做成红就会有人为让灯绿而批量生成自问记录，把活性探针变成表演。

v1.1 变更（与文档 v1.1 一一对应）：
  ① `--guard` 元守护探针：四件事只打印（jsonl 活性／48h 积压／执行率（分母机械定义）／四岔分布）；
  ② `settled` 改四岔枚举值（mech/checklist/external/unsettleable）——自由文本无法机械分组，
     则 M1-b 沉淀率算不出来；存量自由文本条目单列「无法判定」，不计入 M1-b 分母；
  ③ 违和自问清单增第 6 条反向问题（检测清单自身活性，G4）；
  ④ 「一次对外交付」按文档 §5 的机械定义计数（git log 路径分类），分母不再靠人工估。

用法：
  python ci/l2_wenhe_selfask.py                # 交付前：打印违和自问＋UX 洁癖清单并留痕
  python ci/l2_wenhe_selfask.py --note "..."   # 自问发现违和：进 48h 沉淀队列
  python ci/l2_wenhe_selfask.py --monthly      # 月度品质评审：打印模板并留痕
  python ci/l2_wenhe_selfask.py --pending      # 48h 沉淀队列：超时未分类条目
  python ci/l2_wenhe_selfask.py --guard        # 元守护探针：四件事只打印，rc 恒 0（v1.1）

记录：ci/l2_feedback.jsonl（每行 {"ts","kind","text","settled"}）。
"""
import argparse
import datetime
import io
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOG = os.path.join(HERE, "l2_feedback.jsonl")
SETTLE_HOURS = 48
GUARD_WINDOW_DAYS = 30

# ---- v1.1：settled 四岔枚举（与文档 §1.3 四岔分类一致）----
# 存量自由文本条目无法机械分组 ⇒ 归 "legacy-free"，只报数、不计入沉淀率分母。
SETTLED_KINDS = ("mech", "checklist", "external", "unsettleable", "legacy-free")

WENHE = [
    "一个不认识这个项目的人第一眼看到它，会觉得「这是什么」还是「这又是另一个工具」？",
    "界面/文案/结构有没有「每处都对、放一起不对」的组合违和（术语跨模块不一致、符号混用、"
    "同一动作两种叫法）？",
    "数字有没有「说不出的不对」——分母换了、口径混了、时点没标？",
    "交互有没有让用户等一个没有反馈的瞬间（静默降级）",
    "这次交付把什么变复杂了？新人要重读多少才能接手？",
    "本月有没有出现上面五条都没覆盖的违和？有 ⇒ 进 48h 队列（第②类 checklist 或第①类机械化）",
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
    "本月 l2_feedback.jsonl 未沉淀条目清零？（M1-a 分类率；--guard 第 ② 项可提前看）",
    "同族复发间隔曲线（A5 看板取数）",
    "机制总数（A5 看板）＋退休登记簿 pending 是否过期",
    "交付违和自问执行率（--guard 第 ③ 项出数与分母口径；分母＝git 提交中命中产品/文档路径者）",
    "R3 反馈沉淀：本月每条反馈是否 48h 内分类？重点看 M1-b（--guard 第 ④ 项四岔分布）",
]


# ---------------------------------------------------------------- 记录层

def _append(kind, text, settled=None):
    rec = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
           "kind": kind, "text": text, "settled": settled}
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


def _pending(recs=None, now=None):
    now = now or datetime.datetime.now()
    out = []
    for r in (recs if recs is not None else _load()):
        if r.get("settled"):
            continue
        try:
            ts = datetime.datetime.fromisoformat(r["ts"])
        except (KeyError, ValueError):
            continue
        if (now - ts) > datetime.timedelta(hours=SETTLE_HOURS):
            out.append(r)
    return out


def _parse_ts(r):
    try:
        return datetime.datetime.fromisoformat(r["ts"])
    except (KeyError, ValueError):
        return None


def _in_window(r, now, days=GUARD_WINDOW_DAYS):
    ts = _parse_ts(r)
    return ts is not None and (now - ts) <= datetime.timedelta(days=days)


def _settled_class(r):
    """settled 归五类之一；返回值是 tuple (kind, 明细)。

    无法判定的（含 v1.1 前的自由文本）归 "legacy-free" —— 只报数，不进 M1-b 分母。
    """
    s = r.get("settled")
    if not s:
        return ("unsettled", "")
    s = str(s).strip()
    for k in SETTLED_KINDS:
        if s == k or s.startswith(k + ":") or s.startswith(k + "：") or s.startswith(k + " "):
            return (k, s[len(k):].lstrip(":： "))
    return ("legacy-free", s[:40])


# ------------------------------------------------- v1.1：交付的机械定义

#: 文档 v1.1 §5 口径的三条形：计入哪些／不计入哪些／一次提交算一次交付。
_INCLUDE_PREFIX = ("antinel", "inbox_", "host_shield", "hooks/", "rules/",
                   "assets/", "scripts/", "ci/", "docs/")
_INCLUDE_SUFFIX = (".md", ".json")
_EXCLUDE_PREFIX = (".workbuddy-ai/", "out/", "_uxtest2/", "_p_")
_EXCLUDE_NAME = ("psl/manifest.json", "psl/workspace_facts.json",
                 "psl/judgment.json", "psl/SKILL.md")


def _is_delivery_path(p):
    """判定单个路径是否为「一次对外交付」的计入路径（文档 §5 口径 1/2）。"""
    p = p.replace("\\", "/").strip()
    if not p:
        return False
    if p.startswith(_EXCLUDE_PREFIX):
        return False
    if p in _EXCLUDE_NAME:
        return False
    if p.endswith(_EXCLUDE_PREFIX) or "/_p_" in p:
        return False
    if p.startswith(_INCLUDE_PREFIX):
        return True
    if p.endswith(_INCLUDE_SUFFIX) and not p.startswith(("psl/", "dist/", "build/")):
        return True
    return False


def _deliveries(days=GUARD_WINDOW_DAYS):
    """统计近 N 天的「对外交付」提交数。返回 (count, note)；读不到 ⇒ (None, 原因)。

    ★ 读不到必须返回 None 并说明原因 —— 不许返回 0（「查不出来」≠「查出来是零次」）。
    """
    if not os.path.isdir(os.path.join(ROOT, ".git")):
        return None, "非 git 工作树（无法按文档 §5 定义取数）"
    try:
        out = subprocess.run(
            ["git", "log", "--since=%d days ago" % days,
             "--name-only", "--pretty=format:%H"],
            cwd=ROOT, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return None, "git log 失败：%s" % e
    if out.returncode != 0:
        return None, "git log rc=%d：%s" % (out.returncode, (out.stderr or "")[:80])
    n = 0
    cur_has = False
    for ln in out.stdout.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        if re.fullmatch(r"[0-9a-f]{7,40}", ln):        # 新提交头
            if cur_has:
                n += 1
            cur_has = False
        elif _is_delivery_path(ln):
            cur_has = True
    if cur_has:                                        # 最后一段
        n += 1
    return n, ""


# ------------------------------------------------------ v1.1：元守护探针

def _guard():
    """四件事只打印，rc 恒 0。绝不产绿红（§4.3：做成红就会有人为让灯绿而批量生成记录）。"""
    now = datetime.datetime.now()
    recs = _load()
    print("=" * 70)
    print("L2 元守护探针（v1.1）—— 只出声、不裁决；rc 恒 0，永不影响闸门结论")
    print("=" * 70)

    # ① jsonl 活性
    if not recs:
        print("① 活性：** jsonl 不存在或为空 ** —— 本层从未被跑过，或记录文件被清。")
        print("        ⇒ 这是唯一真事故：修复动作是跑一次 `python ci/l2_wenhe_selfask.py`。")
    else:
        win = [r for r in recs if _in_window(r, now)]
        newest = max((_parse_ts(r) for r in recs if _parse_ts(r)), default=None)
        ago = (now - newest).days if newest else None
        print("① 活性：总记录 %d 条；近 %d 天 %d 条；最新一条 %s 前"
              % (len(recs), GUARD_WINDOW_DAYS, len(win),
                 ("%d 天" % ago) if ago is not None else "（时间戳不可读）"))
        if not win:
            print("        ⇒ 近 %d 天零记录 ⇒ 本层已停摆（不红，只报）。" % GUARD_WINDOW_DAYS)

    # ② 48h 积压
    p = _pending(recs, now)
    print("② 48h 积压：超时未分类 %d 条" % len(p))
    for r in p[:5]:
        print("     - %s [%s] %s" % (r.get("ts"), r.get("kind"), str(r.get("text"))[:40]))
    if len(p) > 5:
        print("     …其余 %d 条见 --pending" % (len(p) - 5))

    # ③ 执行率（分母机械定义）
    dcount, dnote = _deliveries()
    if dcount is None:
        print("③ 执行率：分母不可算（%s）⇒ **不填数、不估算**。" % dnote)
        print("        ⇒  F40 纪律：读不出来的分母不许人工估后当数填。")
    else:
        ran = sum(1 for r in recs
                  if r.get("kind") == "wenhe" and _in_window(r, now))
        print("③ 执行率：近 %d 天对外交付 %d 次（文档 §5 机械定义）／自问执行 %d 次"
              % (GUARD_WINDOW_DAYS, dcount, ran))
        if dcount:
            print("        执行率 = %d/%d（%.0f%%）—— 分母为交付数、分子为自问留痕数"
                  % (ran, dcount, 100.0 * ran / dcount))
        else:
            print("        分母为 0（近 %d 天无计入路径的提交）⇒ 执行率不可算，不等于 0%%。"
                  % GUARD_WINDOW_DAYS)

    # ④ 四岔分布（M1-b 沉淀率的实时形态）
    winrecs = [r for r in recs if _in_window(r, now)]
    dist = {}
    for r in winrecs:
        if r.get("kind") not in ("wenhe",):
            continue
        k, _ = _settled_class(r)
        dist[k] = dist.get(k, 0) + 1
    total = sum(v for k, v in dist.items() if k != "unsettled")
    settled_productive = sum(v for k, v in dist.items()
                             if k in ("mech", "checklist", "external"))
    print("④ 四岔分布（近 %d 天 wenhe 条目）：%s"
          % (GUARD_WINDOW_DAYS, dist if dist else "（无 wenhe 条目）"))
    if total:
        print("        M1-b 沉淀率 = %d/%d（%.0f%%）——只 ①②③ 计，判④只计记录不计沉淀"
              % (settled_productive, total, 100.0 * settled_productive / total))
        if dist.get("legacy-free"):
            print("        ⚠ 有 %d 条自由文本 settled（v1.1 前的旧格式）⇒ 单列不计入分母。"
                  % dist["legacy-free"])
        if dist.get("unsettleable", 0) == total and total >= 3:
            print("        ⚠ 全部判④「不可沉淀」⇒ 分类率虽满，沉淀实际为零（M1 拆分母要防的正是这个）。")
    print("\n（本探针 rc 恒 0。上面每一项都只是观察，不是判定。）")
    return 0


# ------------------------------------------------------------------ 主入口

def main():
    ap = argparse.ArgumentParser(description="L2 品质触发层执行程序")
    ap.add_argument("--note", default="",
                    help="自问中发现的违和（进 48h 沉淀队列）")
    ap.add_argument("--monthly", action="store_true", help="月度品质评审模式")
    ap.add_argument("--pending", action="store_true",
                    help="只看 48h 沉淀队列（超时未分类）")
    ap.add_argument("--guard", action="store_true",
                    help="元守护探针（v1.1）：四件事只打印，rc 恒 0")
    a = ap.parse_args()

    if a.guard:
        return _guard()

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
              " settled 字段取枚举值：mech｜checklist｜external｜unsettleable。")
    else:
        _append("wenhe", "交付前违和自问执行（无 --note）")
        print("[留痕] 自问执行已记录（无违和条目）。发现违和请重跑并加 --note。")
    print("\n[记录文件] %s" % LOG)
    return 0


if __name__ == "__main__":
    sys.exit(main())
