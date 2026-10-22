#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""状态机四轴矩阵 —— **独立参照实现**（对拍用的第二把尺子）。

★★ 这份文件的唯一价值是「**独立**」。它不 import 任何产品模块，也不 import
   `situation.py`。一旦它开始 import 产品，它就退化成「自己跟自己比」，
   0 diff 变成恒真，判据随之空转。

## 它从哪来

搬运自主树 `output/_p_state_matrix.py`（336 行，设计期探针，**git 未跟踪**）。
搬运理由：设计件 §7.2 要求 DAG-1 的映射表与它的 `ref_lamp`/`ref_cause`
**逐格 0 diff**，而那个文件在 `output/` 下、不受版本控制 —— 主树随时可能被
清空，验收参照物会消失。参照物必须进仓，否则「0 diff」是跟一个会消失的东西比。

## 搬运时做的唯一改动（其余逐字）

原文件 `prove_completeness()` / `tally()` 的 docstring 写「54 格」，
但代码用 `itertools.product(MODES, DUTIES, TRUSTS, HARMS)` 实际枚举
**3×3×3×3 = 81 格**。54 是错数（可能是把 trust 当两值时的旧版残留）。
⇒ 本文件把「54」更正为「81」，并在 `--selftest` 里把两个数字都钉住：
   · 枚举数必须 == 81（四轴全笛卡尔积）
   · 逻辑可达数必须 == 31（与地基件 §5.2 的 31 行、`ci/_situation_cases.py`
     的 31 行基线**同数**）
   两个数任一不符即自证失败 —— 这样「81 / 31 / 31」三个数字被钉成一致，
   不会再出现「文档写 54、代码跑 81」这种口径混装（F40）。

## 用法

    python ci/_state_matrix_ref.py --selftest     # 自证：81 格 / 31 可达 / 六条不变量
    from _state_matrix_ref import ref_lamp        # 判据侧 import 它做 0 diff 对拍
"""

import itertools
import sys

# ───────────────────────── 一、四轴取值（封闭集） ─────────────────────────
#: 模式层 —— 决定「这个结论代不代表生产担保」。**不是运行态**。
MODE_UNARMED, MODE_DRILL, MODE_ARMED = "unarmed", "drill", "armed"
MODES = (MODE_UNARMED, MODE_DRILL, MODE_ARMED)

#: 轴一 值勤：此刻有没有人在守。
#:   on      ＝在岗
#:   at-risk＝在岗但即将失去（粮将尽 / 心跳将断）—— 这是 Ls 的正确定位：**预告**，不是损失
#:   off     ＝不在岗
DUTY_ON, DUTY_RISK, DUTY_OFF = "on", "at-risk", "off"
DUTIES = (DUTY_ON, DUTY_RISK, DUTY_OFF)

#: 轴二 可信：我能不能证明我在守。**与"在不在岗"正交**。
#:   · unbounded ＝ 无界无知：核心判定受影响（自检／链完整性）⇒ 红
#:   · bounded   ＝ 有界无知：核心没受影响，只是某一项查不到 ⇒ 黄
#:   理由：一个无关探针抖动就让首屏红，三次之后用户不看灯了
#:   —— 那正是"长期红的守卫＝没守卫"的另一种形态。
TRUST_SOUND, TRUST_BOUNDED, TRUST_UNBOUNDED = "sound", "bounded", "unbounded"
TRUSTS = (TRUST_SOUND, TRUST_BOUNDED, TRUST_UNBOUNDED)

#: 轴三 后果：有没有**尚未修复**的缺口。判据不是时间窗，是 `recovered`
#:   与 `state ∈ CLOSED_STATES` —— 「已恢复」才是过去时，「发生在昨天」不是。
HARM_NONE, HARM_SOME, HARM_UNKNOWN = "none", "some", "unknown"
HARMS = (HARM_NONE, HARM_SOME, HARM_UNKNOWN)

#: 灯（对外唯一的视觉维）—— 四值，各对应**一个动作类**（见 ACTION_OF）。
LAMP_GREY, LAMP_GREEN, LAMP_YELLOW, LAMP_RED = "grey", "green", "yellow", "red"
LAMPS = (LAMP_GREY, LAMP_GREEN, LAMP_YELLOW, LAMP_RED)

#: 成因（红/黄的分支）—— 对外状态词由成因决定，不由灯决定。
#:   ★ 这是本模型与旧模型最大的差别：旧模型的词挂在**灯**上（一个词装三件事），
#:     新模型的词挂在**成因**上（一个词一件事）。
#:
#:   ★★ 合并的唯一标准是**动作是否相同**，不是"处境是否相同"。
#:     第一版按"处境"细分，造出了 `blind` 与 `unknown-harm` 两个成因 ——
#:     那是**同一件事的两个名字**：不可信的定义就是"我统计不出后果"。
#:     ⇒ 删除 `unknown-harm`：后果说不清**就是**看不清，一个词一件事。
CAUSES = {
    "unarmed":  "未启用",
    "absent":   "失守",       # 不在岗 ∧ 有损失 —— 唯一配用「失守」的一格
    "breach":   "有缺口",     # 在岗 ∧ 有损失（守了但漏了 / 门是缺的）
    "blind":    "看不清",     # 证明不了自己在守（无界无知）
    "partial":  "有一项没查到",  # 有界无知：核心判定没受影响，只是某一项查不到
    "paused":   "暂停中",     # 不在岗 ∧ 无损失
    "draining": "快没粮了",   # 在岗 ∧ 即将失去 ∧ 无损失
    "ok":       "值守中",
}

#: 成因 → 动作等价类（I4 的唯一真源）。**每类动作只出现一次**，不允许两件事
#: 共用一个动作（那就是"两个成因"的证据）。
ACTION_OF = {
    "unarmed":  "arm",               # 装配（或明确不装配）
    "absent":   "revive+assess",     # 先拉起，再查损失
    "breach":   "fix-listed",        # 按清单逐项修
    "blind":    "verify-reinstall",  # 核对/重装
    "partial":  "check-item",        # 只查那一项（范围明确，不必重装）
    "paused":   "revive",            # 拉起
    "draining": "topup",             # 补粮
    "ok":       "none",
}


# ───────────────────────── 二、参考实现（纯函数） ─────────────────────────
def ref_lamp(mode, duty, trust, harm):
    """灯 = f(模式, 值勤, 可信, 后果)。**纯函数、红优先、互斥完备**。

    规则的先后就是优先级，读完这六行就能预测任何一格：

      1. 未装配        ⇒ 灰（灯不供电：没装配就没有担保可给，任何颜色都是编的）
      2. 有后果/未知   ⇒ 红（后果说不清时按最坏算 —— fail-closed 只在这里出现）
      3. 无界无知      ⇒ 红（核心判定受影响：我证明不了我在守）
      4. 值勤受损或有界无知 ⇒ 黄（**无损失**时才允许黄）
      5. 其余          ⇒ 绿
    """
    if mode == MODE_UNARMED:
        return LAMP_GREY
    if harm in (HARM_SOME, HARM_UNKNOWN):
        return LAMP_RED
    if trust == TRUST_UNBOUNDED:
        return LAMP_RED
    if trust == TRUST_BOUNDED or duty in (DUTY_RISK, DUTY_OFF):
        return LAMP_YELLOW
    return LAMP_GREEN


def ref_cause(mode, duty, trust, harm):
    """成因 = 灯之下的**唯一**分支。先决定灯，再在灯内按动作紧急度选成因。"""
    lamp = ref_lamp(mode, duty, trust, harm)
    if lamp == LAMP_GREY:
        return "unarmed"
    if lamp == LAMP_RED:
        # 顺序即优先级：没人守且有损失 > 有人守但有缺口 > 其余（不可信）
        if duty == DUTY_OFF and harm == HARM_SOME:
            return "absent"
        if harm == HARM_SOME:
            return "breach"
        # ★ 走到这里只有两种输入：trust=unbounded（真实可达），
        #   或 trust=sound|bounded ∧ harm=unknown（逻辑不可达的矛盾输入 —— 能证明
        #   在守就一定统计得出后果）。后者归「看不清」不算撒谎：连后果都报不出来，
        #   本来也说不清自己在守什么。
        return "blind"
    if lamp == LAMP_YELLOW:
        # 顺序即优先级：没人在守 > 即将失去 > 只是某一项没查到
        if duty == DUTY_OFF:
            return "paused"
        if duty == DUTY_RISK:
            return "draining"
        return "partial"
    return "ok"


def ref_verdict(mode, duty, trust, harm):
    """一格的全部输出：灯 / 成因 / 状态词 / 动作。"""
    c = ref_cause(mode, duty, trust, harm)
    return ref_lamp(mode, duty, trust, harm), c, CAUSES[c], ACTION_OF[c]


def logically_reachable(mode, duty, trust, harm):
    """这一格在真实运行中**会不会出现**。

    ★ 不可达不等于"可以不处理"：代码仍须能兜住（集合外显式降级、绝不打绿）。
      这里只为把"防御性分支"与"真实分支"分开数，避免用完备性冒充必要性。
    """
    if mode == MODE_UNARMED:
        # 未装配时没有任何探针在跑 ⇒ 三轴无观测值；只有"没装"这一个事实。
        return duty == DUTY_OFF and trust == TRUST_SOUND and harm == HARM_NONE
    if trust == TRUST_UNBOUNDED:
        # 无界无知 ⇒ 后果统计不出来（这正是"无界"的含义）
        return harm == HARM_UNKNOWN
    # sound（能证明）与 bounded（只是某一项查不到，核心判定没受影响）
    # 都能统计出后果 ⇒ 不会是 unknown
    return harm != HARM_UNKNOWN


# ───────────────────────── 三、网格与完备性证明 ─────────────────────────
def all_cells():
    """四轴全笛卡尔积 ＝ **81 格**（3×3×3×3）。顺序固定，判据按此顺序报差异。"""
    return list(itertools.product(MODES, DUTIES, TRUSTS, HARMS))


def reachable_cells():
    """逻辑可达格 —— **31 格**（与地基件 §5.2 的 31 行同数，可交叉验证）。

    分解：unarmed 27 格里只有 1 格可达（off/sound/none）；
    armed 与 drill 各 15 格（unbounded×3 ＋ sound×6 ＋ bounded×6）。
    1 + 15 + 15 = 31。
    """
    return [c for c in all_cells() if logically_reachable(*c)]


def prove_completeness():
    """遍历 **81 格**，验六条不变量（I1–I6 的可执行版）。

    返回 `(bad, seen)`：`bad` 为空才算全绿；`seen` 是 格 → (灯, 成因, 词, 动作)。
    """
    bad = []
    seen = {}
    for mode, duty, trust, harm in all_cells():
        cell = (mode, duty, trust, harm)
        lamp, cause, word, action = ref_verdict(*cell)
        seen[cell] = (lamp, cause, word, action)

        # I1 互斥：一格只给一个灯（纯函数天然满足，此处验"灯在封闭集内"）
        if lamp not in LAMPS:
            bad.append("I1 %s 灯 %r 不在封闭集" % (cell, lamp))
        # I2 完备：每格都有成因与词，不许留空
        if not cause or not word or not action:
            bad.append("I2 %s 有字段为空" % (cell,))
        # I5 看不清不许折叠：无界无知必红（在 armed/drill 下）
        if mode != MODE_UNARMED and trust == TRUST_UNBOUNDED and lamp != LAMP_RED:
            bad.append("I5 %s 无界无知却非红" % (cell,))
        # ★★ P7：有界无知不许落在红灯上（否则"有界"又变成了噪音）
        #   注意只在 harm=none 时成立 —— 有后果时红是 harm 给的，不是 trust 给的。
        if (mode != MODE_UNARMED and trust == TRUST_BOUNDED
                and harm == HARM_NONE and lamp == LAMP_RED):
            bad.append("P7 %s 有界无知被误判成红" % (cell,))
        # 未装配绝不打绿（"没开"不许冒充"没事"）
        if mode == MODE_UNARMED and lamp != LAMP_GREY:
            bad.append("假绿 %s 未装配却给 %s" % (cell, lamp))

    # I3 每个灯至少有一个可达成因（没有"空灯"）
    for lamp in LAMPS:
        hits = [c for c, (l, _c, _w, _a) in seen.items()
                if l == lamp and logically_reachable(*c)]
        if not hits:
            bad.append("I3 灯 %s 没有任何逻辑可达格" % lamp)

    # I4 动作分派：一个动作类只服务一个成因，且每个成因都有动作
    by_action = {}
    for cause, action in ACTION_OF.items():
        by_action.setdefault(action, []).append(cause)
    for action, causes in by_action.items():
        if len(causes) > 1:
            bad.append("I4 动作 %s 被 %d 个成因共用：%s"
                       % (action, len(causes), causes))

    # 「失守」只许出现在 absent 这一格（2026-10-06 裁定的精确落实）
    for cause, word in CAUSES.items():
        if word == "失守" and cause != "absent":
            bad.append("词归位 失守被用于 %s" % cause)

    # 每个灯都必须出现（四色都要有活路，不许有装饰色）
    used = {l for (l, _c, _w, _a) in seen.values()}
    for lamp in LAMPS:
        if lamp not in used:
            bad.append("灯 %s 在 81 格里一次都没出现（装饰色）" % lamp)
    return bad, seen


def tally(seen):
    """统计：每盏灯在全网格里的格数、其中逻辑可达多少。"""
    out = {}
    for lamp in LAMPS:
        allc = [c for c, v in seen.items() if v[0] == lamp]
        reac = [c for c in allc if logically_reachable(*c)]
        out[lamp] = (len(allc), len(reac))
    return out


# ───────────────────────── 四、自证（--selftest） ─────────────────────────
#: 三个必须一致的数字（本文件存在的意义就是把它们钉死，防口径混装 F40）：
#:   81 ＝ 四轴全笛卡尔积；31 ＝ 逻辑可达；31 ＝ 地基件 §5.2 的夹具行数。
N_CELLS = 81
N_REACHABLE = 31


def selftest():
    """返回 (ok, 说明行列表)。**本函数不 import 任何产品模块。**"""
    lines = []
    ok = True

    cells = all_cells()
    if len(cells) != N_CELLS:
        ok = False
        lines.append("✗ 枚举数 %d ≠ %d（四轴 3×3×3×3 应为 81）"
                     % (len(cells), N_CELLS))
    else:
        lines.append("✓ 枚举 %d 格（3×3×3×3）" % len(cells))

    reac = reachable_cells()
    if len(reac) != N_REACHABLE:
        ok = False
        lines.append("✗ 逻辑可达 %d 格 ≠ %d（应与地基件 §5.2 的 31 行同数）"
                     % (len(reac), N_REACHABLE))
    else:
        lines.append("✓ 逻辑可达 %d 格（与夹具 31 行基线同数）" % len(reac))

    bad, seen = prove_completeness()
    if bad:
        ok = False
        for b in bad:
            lines.append("✗ " + b)
    else:
        lines.append("✓ 六条不变量（I1 互斥／I2 完备／I3 无空灯／I4 动作单射／"
                     "词归位／四色有活路）全过")

    t = tally(seen)
    lines.append("  灯分布（全网格 / 逻辑可达）：" +
                 "  ".join("%s=%d/%d" % (k, v[0], v[1]) for k, v in t.items()))

    # 成因覆盖：八个成因都必须至少被一格取到（否则是死词）
    used_causes = {v[1] for v in seen.values()}
    if used_causes != set(CAUSES):
        ok = False
        lines.append("✗ 成因覆盖不全 —— 多 %r / 少 %r"
                     % (sorted(used_causes - set(CAUSES)),
                        sorted(set(CAUSES) - used_causes)))
    else:
        lines.append("✓ 八个成因全部被取到（无死词）")

    return ok, lines


def main(argv):
    if "--selftest" not in argv:
        print(__doc__.strip().splitlines()[0])
        print("用法：python ci/_state_matrix_ref.py --selftest")
        return 2
    ok, lines = selftest()
    print("=" * 70)
    print("状态机四轴参照实现 · 自证")
    print("=" * 70)
    for ln in lines:
        print("  " + ln)
    print("-" * 70)
    print("  SELFTEST-PASS" if ok else "  SELFTEST-FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
