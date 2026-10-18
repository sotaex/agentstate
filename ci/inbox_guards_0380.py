#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.39.x 判据 —— **灯＝此刻** ＋ **术语表口径**（不许拿历史账冒充"当前状态"）。

★★ 这一份判据是创始人 2026-10-09 第二句「机制上解决」的直接产物：

    「一定要让Antinel 监理反应当前的准确状态，没有失守却显示失守，就是错误的，
      请修正，并且要从机制上修正，防范再犯。」

  ⇒ 修好一处不难，难的是**没人能再改回去**。本文件把这条从"注释里的约定"
    变成"会报红、有负控的机制"：

    S10 灯＝此刻：`light_explain().state ≡ current_state()`，与 24h 账**无关**；
    S11 账不丢：账仍被如实表达（`ledger_bad` ＋ 原因句），而灯不因此变色 ——
        修"假红"不许修成"藏事"，这两者**只差一步**；
    S12 入口堵死：渲染层**不许**直接调 `light()`（它答的不是"此刻"）；
    S13 真警报仍能亮：`down`/`warn` ⇒ R0、粮低 ⇒ Ls ——
        改"此刻"不许把真警报一起改没；
    S14 接线：顶部条**确实**读 `light_explain` 的 `label`
        （负控换成一个独有词，它必须跟着变 —— 证明是"真读"，不是"恰好一样"）；
    S15 六态**逐态可达**：穷举「姿态 × 账 × 粮」，缺任何一态即红 ——
        0.39.0 第一版"纯此刻"曾让 `L2 拦截` 不可达（实测抓到的回归）；
    S16 失守**不回溯**：此刻在岗 ＋ 历史失守账 ⇒ 灯**不得**是 R0；
    S17 术语表口径＝来源分工：页面「灯」词条**不得**退回旧的"对称合并读"说法
        （实现改了、释义没改 ⇒ 术语表就成了新的假来源）。
    S18 说明＝实现：`guard_posture()` 的 docstring 规则句必须与 `POSTURE_LABEL` 同口径 ——
        这是把 S17 那条纪律从"只锁术语表"**扩到关键函数的规则句**。0.39.1 修的是
        术语表的同型错，而 `guard_posture()` 的 docstring **同型复发且当时无人管**；
    S19-380 版本行归一化：改 `hooks/pre_tool_use.py` 的 `_ANTINEL_VERSION` **值** ⇒ 哈希不变；
        改该行**行内注释**或**别的任何一行** ⇒ 哈希照变；且所有算这个文件哈希的
        消费方**只能有一个实现**（只改一侧 ⇒ 哈希**恒失配**，比不改更糟）。

  ★ 编写纪律（沿用本仓惯例，见 `inbox_guards_0372.py` 头部）：
    · 每条判据配负控；**只查行为**；**绝不写盘** —— 负控全部走
      **内存变异 ＋ 还原**（monkeypatch），因此可以进打包前的 fast 档闸门。
"""
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (ROOT, os.path.join(ROOT, "ci")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

RESULTS = []


def check(name):
    """★ 判据**必须真会红** —— 返回说明串一律转成抛异常（0490/0470 同款）。

    ★★ 0.51.0 修（本轮**审核抓到的 Sev-0**）：此前本文件的 `check` **不包装**，
      而全部判据都是 `return "问题说明"` 的写法 ⇒ `main()` 把返回串**照 ✅ 计数**
      ⇒ **本套件 29 条判据从来不可能红**（"写在纸上的守卫"）。
      文件自己的注释（`_EXPECT` 上方）早就承认过这个形状
      （「它报了'负控失效'却被计为绿 ⇒ 判据本身失效」），却从未修 harness。
      ⇒ 与 0490 的 `check` 对齐：非 `True`/`None` 一律 `raise AssertionError`。
    """
    def deco(fn):
        def wrapper():
            r = fn()
            if r is True or r is None:
                return True
            raise AssertionError(r if isinstance(r, str) else repr(r))
        RESULTS.append((name, wrapper))
        return fn
    return deco


#: 真源在 `host_shield.POSTURE_ALL`；这里写死一份**故意不同源** —— 与本目录
#: 既有纪律一致（两边同源则"有人加了第七个姿态"时判据跟着变，等于没守）。
_POSTURES = ("down", "warn", "guarding", "interrupted", "unknown", "off", "dev")


def _g():
    """复用 0.37.3 族里的条目构造器与 HTML 工具（**不二次实现**）。"""
    import inbox_guards_0372 as G
    return G


# ═══════════════════════════════════════════ S10 灯＝此刻 ═══════════════════
#: ★ 姿态 → 期待灯态（**写死在这里，故意不取自 `current_state`**）。
#:   为什么：若期望值也来自被测函数，负控一旦把那个函数变异，**期望会跟着变**
#:   ⇒ 两边一起错 ⇒ 判据永远绿。★ 本判据族**第一版就踩了这个坑**，
#:   是 `N-S10` 把它抓出来的（它报了"负控失效"却被计为绿 ⇒ 判据本身失效）。
_EXPECT = {
    "down": "R0",        # 防线此刻确实不在岗，而且有东西没人管
    "warn": "R0",        # 出厂码不符且非研发 ⇒ fail-closed
    "guarding": "L0",    # ★ **有账也必须是 L0** —— 本文件存在的唯一理由
    "interrupted": "L1",
    "unknown": "L1",
    "off": "L0",
    # ★★ 0.51.0（规格 v1.2 §2.1）：`dev` 姿态的主灯是 **L0**（"监理在岗、
    #   此刻没查出缺口"）—— 研发**身份**移**徽标**（`badges()`）；
    #   主灯不再为"研发中"单独留一档（0.36.4 的彻底化：两个通道各说各的）。
    "dev": "L0",
}


def _light_equals_now(items, granary=None):
    """真跑：七姿态 × 给定记录集 ⇒ 返回与**写死的**期待值不一致的清单。"""
    import inbox_model as M
    bad = []
    for ps in _POSTURES:
        p = {"state": ps, "why": "判据构造"}
        try:
            got = M.light_explain(p, items, granary=granary)["state"]
        except Exception as e:                                  # noqa: BLE001
            bad.append((ps, "light_explain 抛 %s" % type(e).__name__))
            continue
        if got != _EXPECT[ps]:
            bad.append((ps, got, _EXPECT[ps]))
    return bad


@check("S10 主灯＝此刻：light_explain().state 恒等于此刻态（与 24h 账无关）")
def s10():
    import inbox_model as M
    G = _g()
    r0 = [G._mk_item(state="unread")]           # 窗口内未处理的 R0
    done = [G._mk_item(state="done")]           # 已处理（不该画灯）
    old = [G._mk_item(hours_ago=48)]            # 窗口外
    for items in ([], r0, done, old, r0 * 5):
        bad = _light_equals_now(items)
        if bad:
            return "有账时灯偏离了此刻：items=%d ⇒ %r" % (len(items), bad)
    # ★★ 0.51.0 重签：粮低 **不再抬主灯** —— 主灯保持 L0，缺粮改挂**徽标**。
    ex = M.light_explain({"state": "guarding", "why": "x"}, r0,
                         granary={"state": "low", "why": "粮快见底了"})
    if ex["state"] != M.STATE_L0:
        return ("监理在岗 ＋ 粮低 ⇒ 主灯应 L0（缺粮是徽标不是灯），实际 %s"
                % ex["state"])
    if "granary" not in [b[0] for b in ex["badges"]]:
        return "监理在岗 ＋ 粮低 ⇒ 缺粮徽标必须亮：badges=%r" % (ex["badges"],)
    return True


@check("N-S10 负控：让灯重新取合并读 ⇒ S10 必须报红")
def n_s10():
    import inbox_model as M
    G = _g()
    r0 = [G._mk_item(state="unread")]
    orig = M.current_state

    def folded(ps, granary=None, items=None, now=None, hours=None):   # 退回 0.38.0 的旧语义
        return M.light(ps, r0, granary=granary)[0]

    M.current_state = folded
    try:
        bad = _light_equals_now(r0)
    finally:
        M.current_state = orig
    if not bad:
        return "负控失效：灯退回合并读后 S10 仍然绿"
    return True


# ═══════════════════════════════════════════ S11 账不丢 ═════════════════════
@check("S11 账不丢：24h 未处理账仍被如实表达（ledger_bad ＋ 原因句），而灯不因此变色")
def s11():
    import inbox_model as M
    G = _g()
    r0 = [G._mk_item(state="unread")]
    none = M.light_explain({"state": "guarding", "why": "监理在岗"}, [], granary=None)
    some = M.light_explain({"state": "guarding", "why": "监理在岗"}, r0, granary=None)
    if none["ledger_bad"] is not False:
        return "无账却 ledger_bad=%r" % (none["ledger_bad"],)
    if some["ledger_bad"] is not True:
        return "有账却 ledger_bad=%r（账被藏了）" % (some["ledger_bad"],)
    if "没处理" not in some["reason"]:
        return "有账但原因句没提：%r" % some["reason"]
    if "灯这样报" in some["reason"]:
        return "原因句还在用旧语义（此刻好却说'灯这样报'）：%r" % some["reason"]
    if some["state"] != M.STATE_L0:
        return "此刻在岗 ＋ 有账 ⇒ 灯应 L0，实际 %s" % some["state"]
    return True


@check("N-S11 负控：让 24h 账恒为空（把事藏起来）⇒ S11 必须报红")
def n_s11():
    import inbox_model as M
    orig = M._window_open
    M._window_open = lambda *a, **k: []
    try:
        r = s11()
    finally:
        M._window_open = orig
    if r is True:
        return "负控失效：账被藏起来后 S11 仍然绿"
    return True


# ═══════════════════════════════════════════ S12 入口堵死 ═══════════════════
def _direct_light_lines(src):
    """`src` 里**直接**调 `light()` 的行号（注释行不算；`light_explain(` 不算）。

    ★ 为什么堵"入口"而不是多写几条断言：漂移的入口就是"又有人拿 `light()`
      当灯用"（它答的是"此刻＋账合起来最该提哪一档"，不是"现在怎么样"）。
      把入口堵死，比在每个出口巡逻更省事、也更难绕过。
    """
    out = []
    for i, ln in enumerate(src.splitlines(), 1):
        code = ln.split("#", 1)[0]
        if "M.light(" in code:
            out.append(i)
    return out


def _read_server():
    with open(os.path.join(ROOT, "inbox_server.py"), encoding="utf-8") as f:
        return f.read()


@check("S12 入口堵死：渲染层（inbox_server.py）不许直接调 light()")
def s12():
    hits = _direct_light_lines(_read_server())
    if hits:
        return ("inbox_server.py 第 %r 行直接调 light() —— 灯必须走 "
                "current_state()/light_explain()" % hits)
    return True


@check("N-S12 负控：往渲染层插一行 M.light( ⇒ S12 的检查必须报红")
def n_s12():
    mutated = _read_server() + "\n_x = M.light('guarding', [])\n"
    if not _direct_light_lines(mutated):
        return "负控失效：插了直接调用却查不出来"
    return True


# ═══════════════════════════════════════ S13 真警报仍能亮 ═══════════════════
@check("S13 真警报仍能亮：down/warn ⇒ R0、粮低 ⇒ **缺粮徽标**（改'此刻'不许把真警报改没）")
def s13():
    import inbox_model as M
    bad = []
    for ps in ("down", "warn"):
        st = M.light_explain({"state": ps, "why": "x"}, [], granary=None)["state"]
        if st != M.STATE_R0:
            bad.append((ps, st))
    # ★★ 0.51.0 重签（规格 v1.2 §2.1）：粮低**不抬主灯**，改挂「缺粮」徽标。
    #   判据仍咬住"真警报不许被改没"：主灯必须是干净的 L0（不是被压成别的），
    #   而"缺粮"这件事必须**在徽标通道上确实亮着** —— 通道换了，事实不许丢。
    ex = M.light_explain({"state": "guarding", "why": "x"}, [],
                         granary={"state": "low", "why": "粮快见底了"})
    if ex["state"] != M.STATE_L0:
        bad.append(("guarding+低粮", "主灯应 L0（缺粮是徽标），得 %s" % ex["state"]))
    if "granary" not in [b[0] for b in ex["badges"]]:
        bad.append(("guarding+低粮", "缺粮徽标没亮：%r" % (ex["badges"],)))
    if M.light_explain({"state": "guarding", "why": "x"}, [],
                       granary={"state": "ok"})["state"] != M.STATE_L0:
        bad.append(("guarding+粮足", "非 L0"))
    # ★ 反向：**不在岗不该报缺粮** —— 徽标通道同样受这条约束。
    ex_off = M.light_explain({"state": "off", "why": "x"}, [],
                             granary={"state": "low"})
    if ex_off["state"] != M.STATE_L0:
        bad.append(("off+低粮", "未在岗主灯应 L0，得 %s" % ex_off["state"]))
    if "granary" in [b[0] for b in ex_off["badges"]]:
        bad.append(("off+低粮", "未在岗不该报缺粮（徽标亮了）"))
    if M.light_explain({"state": "interrupted", "why": "x"}, [],
                       granary=None)["state"] != M.STATE_L1:
        bad.append(("interrupted", "非 L1"))
    if bad:
        return "真警报丢失：%r" % bad
    return True


@check("N-S13 负控：让 current_state 恒返回 L0 ⇒ S13 必须报红")
def n_s13():
    import inbox_model as M
    orig = M.current_state
    M.current_state = (lambda ps, granary=None, items=None, now=None, hours=None:
                       M.STATE_L0)
    try:
        r = s13()
    finally:
        M.current_state = orig
    if r is True:
        return "负控失效：真警报全被压平后 S13 仍然绿"
    return True


# ═══════════════════════════════════════════ S14 接线 ═══════════════════════
def _bar_with_label(label):
    """把 `light_explain` 换成一个只改 `label` 的替身，渲染顶部条并剥详情。"""
    import inbox_model as M
    import inbox_server as SV
    G = _g()
    orig = M.light_explain

    def fake(p, items, now=None, hours=None, granary=None):
        return {"state": M.STATE_L0, "label": label, "now_text": "x",
                "now_bad": False, "ledger_bad": False, "reason": "r"}

    M.light_explain = fake
    try:
        h = SV._bar([], "TOKEN", posture={"state": "guarding", "why": "x"},
                    now=None, view="inbox")
    finally:
        M.light_explain = orig
    return G._strip_details(h)


@check("S14 接线：顶部条确实读 light_explain 的 label（此刻在岗 ⇒ 说「值守中」）")
def s14():
    txt = _bar_with_label("值守中")
    if "值守中" not in txt:
        return "顶部条没有采用 light_explain 的 label"
    return True


@check("N-S14 负控：label 换成一个独有词 ⇒ 顶部条必须跟着变（证明是真读）")
def n_s14():
    word = "ZZZ-独有词-9f3a"
    txt = _bar_with_label(word)
    if word not in txt:
        return "负控失效：顶部条没读 light_explain.label"
    return True


# ═══════════════════════════ S15 六态逐态可达 ═══════════════════════════════
#: 穷举「此刻姿态 × 账 × 粮」的组合。
#: ★ 为什么这条必须有：0.39.0 **第一版**把灯写成"纯此刻"，`L2 拦截` 因此
#:   **永远亮不起来** —— 六态里少了一个**可达态**。这是实测探针抓到的
#:   （不是推演），所以必须有一条判据把它钉死：**任何一态点不亮 ⇒ 报红**。
#: ★★ 0.51.0 重签（规格 v1.2 §2）：显示模型改**三通道** ⇒ 可达性也分通道 ——
#:   主灯只该有 R0/L2/L1/L0 四态可及（dev/Ls 不再是灯），而 dev/Ls 必须
#:   在**徽标通道**上可及。两个集合都**写死**（不取自 `M.LIGHT_STATES`／
#:   `M.STATE_LABEL`）—— 与本族纪律一致：期望取自被测对象则负控一变异就跟着变。
_LAMP_REACH = ("R0", "L2", "L1", "L0")
_BADGE_REACH = ("dev", "granary")
_COMBOS = [
    ("down", 0, False), ("warn", 0, False), ("guarding", 0, False),
    ("interrupted", 0, False), ("unknown", 0, False), ("off", 0, False),
    ("dev", 0, False),
    ("guarding", 1, False),      # + 历史失守账（R0 不抬灯）
    ("guarding", 2, False),      # + 刚发生的拦截账（info 桶，保持期内）
    ("guarding", 3, False),      # + 两者都有
    ("guarding", 4, False),      # + 刚发生的注意账（info 桶，保持期内）
    ("guarding", 0, True),       # + 粮低
    ("off", 2, False),
]


def _combo_items(items_n):
    G = _g()
    if items_n == 0:
        return []
    if items_n == 1:
        return [G._mk_item(kind="host_shield_breach")]        # R0 事件
    if items_n == 2:
        return [G._mk_item(kind="tool_call_blocked")]         # L2 事件
    if items_n == 4:
        return [G._mk_item(kind="host_shield_revived")]       # L1 事件（info 桶）
    return [G._mk_item(kind="host_shield_breach"),
            G._mk_item(kind="tool_call_blocked")]


def _reach_table():
    """穷举上表 ⇒ `{(posture, n_items, gran): 主灯态}`。"""
    import inbox_model as M
    low = {"state": "low", "why": "x"}
    out = {}
    for ps, n, g in _COMBOS:
        out[(ps, n, g)] = M.light_explain(
            {"state": ps, "why": "x"}, _combo_items(n),
            granary=(low if g else None))["state"]
    return out


def _badge_reach():
    """穷举「版本对 × 粮」⇒ 徽标键集合（分通道可达性的另一半）。"""
    import inbox_model as M
    seen = set()
    for loc, pub in (("9.9.9", "1.0.0"), ("1.0.0", "1.0.0"),
                     ("1.0.0", "9.9.9"), (None, None)):
        for gran in (None, {"state": "low", "why": "x"}):
            for k, _n, _w in M.badges("guarding", gran, [],
                                      versions=(loc, pub)):
                seen.add(k)
    return seen


@check("S15 主灯四态 ＋ 徽标两态**逐态可达**（分通道，缺任何一态即红）")
def s15():
    seen = set(_reach_table().values())
    missing = [s for s in _LAMP_REACH if s not in seen]
    if missing:
        return ("有**主灯**态点不亮（不可达）：%r —— 每态都必须有能点亮它的"
                "真实组合（实测集 %r）" % (missing, sorted(seen)))
    # ★ 反向：dev/Ls **不该**再出现在主灯上（它们已移徽标通道）。
    leaked = [s for s in ("dev", "Ls") if s in seen]
    if leaked:
        return ("主灯上出现了已移出主灯的态 %r —— dev/Ls 应只在徽标通道"
                "（规格 v1.2 §2）" % leaked)
    bseen = _badge_reach()
    bmiss = [s for s in _BADGE_REACH if s not in bseen]
    if bmiss:
        return ("有**徽标**态点不亮（不可达）：%r —— dev/Ls 必须能在徽标通道上"
                "点亮（实测集 %r）" % (bmiss, sorted(bseen)))
    return True


@check("N-S15 负控：砍掉'事件'这一路（灯退回纯此刻）⇒ L2 不可达，S15 必须报红")
def n_s15():
    import inbox_model as M
    orig = M.current_state

    def pure_now(ps, granary=None, items=None, now=None, hours=None):
        lv, _ = M.base_state(ps)
        gl = M._granary_level(granary, ps)
        if gl is not None and M.PRIORITY.get(gl, 0) > M.PRIORITY.get(lv, 0):
            lv = gl
        return lv

    M.current_state = pure_now
    try:
        r = s15()
    finally:
        M.current_state = orig
    if r is True:
        return "负控失效：灯退回纯此刻后 L2 仍然可达"
    return True


@check("S16 失守**不回溯**：此刻在岗 ＋ 历史失守账 ⇒ 灯不得是 R0")
def s16():
    import inbox_model as M
    G = _g()
    r0 = [G._mk_item(kind="host_shield_breach")]
    st = M.light_explain({"state": "guarding", "why": "监理在岗"}, r0,
                         granary=None)["state"]
    if st == M.STATE_R0:
        return "历史失守把灯染红了（这正是创始人裁定的那个错）：%s" % st
    if st != M.STATE_L0:
        return "此刻在岗 ＋ 仅历史失守账 ⇒ 应为 L0，实际 %s" % st
    return True


@check("N-S16 负控：把 R0 也放回'事件'那一路（失守可回溯）⇒ S16 必须报红")
def n_s16():
    import inbox_model as M
    orig = M.current_state

    def with_r0(ps, granary=None, items=None, now=None, hours=None):
        lv, _ = M.base_state(ps)
        ev = ([it.level for it in M._window_open(items, hours, now)]
              if items else [])
        if ev:
            top = max(ev, key=lambda x: M.PRIORITY.get(x, 0))
            if M.PRIORITY.get(top, 0) > M.PRIORITY.get(lv, 0):
                lv = top
        gl = M._granary_level(granary, ps)
        if gl is not None and M.PRIORITY.get(gl, 0) > M.PRIORITY.get(lv, 0):
            lv = gl
        return lv

    M.current_state = with_r0
    try:
        r = s16()
    finally:
        M.current_state = orig
    if r is True:
        return "负控失效：失守可回溯后 S16 仍然绿"
    return True


# ═══════════════════════ S17 术语表口径＝来源分工 ═══════════════════════════
#: ★ 为什么单立这一条（0.39.1）：灯的**实现**按来源分工修好之后，术语表那条
#:   「灯」词条的**释义**仍停在 0.37.2 的旧话（「此刻 × 24h 两个读数合起来取最重」
#:   ＋「它答的是该不该紧张，**不是**此刻哨兵好不好」）—— 而后者在新设计下
#:   **恰是说反了**（灯的状态部分**就是**"此刻"）。释义不改 ⇒ 页面「口径」一栏
#:   仍在教旧规则 ⇒ 术语表成了**新的假来源**（0.37.2 注释自己警告过的形状）。
#: ★★ 0.51.0 重签（规格 v1.2 §7.4）：显示模型改**三通道** ⇒ 词条必须点明
#:   「缺粮不点灯、只挂徽标」；旧措辞「失守、**缺粮**只认此刻」（把缺粮当成
#:   灯的一档）**已不成立**，故从 MUST 拆出并列入 FORBID。
#: ★ 期望短语／禁语都**写死在这里**（不取自 `glossary` 对象）—— 与本族纪律一致：
#:   期望若取自被测对象，负控一变异它就跟着变，判据永远绿。
_GL_MUST = ("失守只认此刻", "拦截／注意", "徽标")   # 灯只认此刻/刚发生；并存态是徽标
_GL_FORBID = ("两个读数", "不是「此刻监理好不好」",  # 旧口径的两处特征措辞
              "缺粮只认此刻")                       # 0.51.0：缺粮已不在灯上


def _gl_light_plain():
    """术语表「灯」词条的纯文本（拼全字段 ＋ 去 HTML 标签）。"""
    import re
    import glossary as GL
    t = GL.TERMS["light"]
    raw = " ".join(str(t.get(k, "")) for k in ("w", "one", "inc", "exc", "unit"))
    return re.sub(r"<[^>]+>", "", raw)


@check("S17 术语表口径＝来源分工：'灯'词条必须与 current_state 的判据自洽")
def s17():
    txt = _gl_light_plain()
    hit = [p for p in _GL_FORBID if p in txt]
    if hit:
        return ("术语表还在用旧口径 %r —— 它与 current_state 的来源分工相反"
                "（灯已不再'两个读数取最重'，也不再'不是此刻'）" % hit)
    miss = [p for p in _GL_MUST if p not in txt]
    if miss:
        return ("术语表没点明来源分工（缺 %r）—— '灯'的释义必须写明"
                "「失守/缺粮只认此刻」「拦截由账给」" % miss)
    return True


@check("N-S17 负控：把'灯'词条退回旧口径 ⇒ S17 必须报红")
def n_s17():
    import glossary as GL
    _o = GL.TERMS["light"]
    try:
        GL.TERMS["light"] = {
            "w": "顶部这盏灯",
            "one": "把此刻和最近 24 小时两个读数合起来，取最重的一档。",
            "inc": "此刻＝监理在不在岗。",
            "exc": "它答的是「我现在该不该紧张」，不是「此刻监理好不好」。",
            "unit": "不计数；取两个读数里最重的一个。",
        }
        r = s17()
    finally:
        GL.TERMS["light"] = _o
    if r is True:
        return "负控失效：词条退回旧口径后 S17 仍然绿"
    return True


# ═══════════════════ S18 说明＝实现（docstring 规则句）═══════════════════════════
#: ★ 为什么单立这一条（0.39.2）：0.39.1 修掉的是**术语表**那条同型错
#:   （实现改了、释义没改 ⇒ 术语表成了新的假来源），并把它变成判据 S17。
#:   但**同一形状在 `guard_posture()` 的 docstring 里原样复发**：
#:     实现 `warn ⇒ R0（失守）`，docstring 规则③仍写"存疑（黄）"，
#:     而 `POSTURE_LABEL[POSTURE_WARN]="失守"` 注释自己承认了这个改动却没回写 docstring。
#:   ⇒ S17 只锁了术语表 ⇒ **这条没有任何判据管它** ⇒ 机制没闭合。
#:   ★ 期望词／禁词都**写死在这里**（不取自 host_shield 的任何文案）—— 与本族纪律一致。
_DOC_FORBID = ("存疑", "查不到")          # 8 态灯时代的旧说法
_DOC_MUST = ("正面断言", "失守")           # 分档轴名 ＋ 结论词（wrap⇒R0）


def _doc_rule_fails(doc):
    """纯函数：给一段 docstring 文本，返回问题清单（空 = 通过）。负控直接复用它。"""
    if not doc:
        return ["guard_posture() 没有 docstring —— 规则只活在别人的记忆里"]
    bad = []
    hit = [t for t in _DOC_FORBID if t in doc]
    if hit:
        bad.append("docstring 仍用旧说法 %r（与 POSTURE_LABEL['warn']='失守' 打架；"
                   "实现改了、说明没改＝假来源）" % (hit,))
    miss = [t for t in _DOC_MUST if t not in doc]
    if miss:
        bad.append("docstring 没点明分档轴（缺 %r）" % (miss,))
    return bad


@check("S18 说明＝实现：guard_posture() 的 docstring 必须与 POSTURE_LABEL 同口径")
def s18():
    import host_shield as H
    doc = H.guard_posture.__doc__ or ""
    bad = _doc_rule_fails(doc)
    # 与**实现**绑定（不是只查字符串）：warn 的实际标签必须出现在 docstring 里。
    wa = (getattr(H, "POSTURE_LABEL", {}) or {}).get(getattr(H, "POSTURE_WARN", "warn"))
    if wa and wa not in doc:
        bad = bad + ["docstring 没点名 warn 的实际标签 %r（标签改了、说明没跟）" % wa]
    if bad:
        return "；".join(bad)
    return True


@check("N-S18 负控：docstring 退回旧口径（'存疑（黄）'）⇒ S18 必须报红")
def n_s18():
    old = ("③ armed 且监理在岗、心跳新鲜，但自检不符 ⇒ 存疑（黄）。"
           "'我认不出守门的是不是出厂那份' ≠ '此刻没在守'。")
    if not _doc_rule_fails(old):
        return "负控失效：旧口径 docstring 未被抓出"
    return True


# ═══════════════════ S19-380 版本行归一化（唯一实现）════════════════════════════════
def _norm_selfcheck(norm, raw):
    """纯函数：给**一个归一化实现** ＋ `hooks/pre_tool_use.py` 的原始字节，返回问题清单。

    ★ 负控直接换 `norm` 复用它 —— 与 S17 的 `_gl_light_plain()` 同法。
    ★ 期望值全是"相等／不等"，不取自任何被测对象。
    """
    problems = []
    idx = raw.find(b"_ANTINEL_VERSION")
    if idx < 0:
        return ["hooks/pre_tool_use.py 里找不到 `_ANTINEL_VERSION` 行 —— 版本承载件不成立"]
    nl = raw.find(b"\n", idx)
    if nl < 0:
        nl = len(raw)
    line = raw[idx:nl]
    m = re.search(rb'"[^"]*"', line)
    if not m:
        return ["版本行里没有引号值 ⇒ 归一化正则与实际写法已分叉（摘不掉版本）"]
    # ①正相：只改**版本值**
    v2 = raw[:idx] + line[:m.start()] + b'"9.9.9"' + line[m.end():] + raw[nl:]
    if norm(v2) != norm(raw):
        problems.append("① 只改版本**值**，归一化结果却变了 ⇒ 版本行没被摘干净")
    # ②负控：改该行**行内注释**（防"整行替换"把注释一起吞掉）
    c2 = raw[:nl] + b"  # g0380-extra" + raw[nl:]
    if norm(c2) == norm(raw):
        problems.append("② 改版本行**行内注释**后归一化结果没变 ⇒ 归一化吞掉了整行（白送一处盲区）")
    # ③负控：改**别的行**
    o2 = raw.replace(b"import os", b"import os  # g0380", 1)
    if o2 != raw and norm(o2) == norm(raw):
        problems.append("③ 改**别的行**后归一化结果没变 ⇒ 保护面变松了")
    return problems


@check("S19-380 版本行归一化：改版本值不动哈希；改注释/别的行照变；消费方只有一个实现")
def s19():
    import host_shield as H
    p = os.path.join(ROOT, "hooks", "pre_tool_use.py")
    try:
        with open(p, "rb") as f:
            raw = f.read()
    except OSError as e:
        return "读不到 hooks/pre_tool_use.py：%r" % (e,)
    probs = _norm_selfcheck(H.norm_version_bytes, raw)
    if probs:
        return "；".join(probs)
    # ★★★ 结构纪律（交接件 §6.5：只改一侧 ⇒ 哈希恒失配）：
    #   算这个文件哈希的消费方**必须**消费 host_shield 的唯一实现，不许各自再写一份。
    bad = []
    hs_src = ""
    try:
        with open(os.path.join(ROOT, "host_shield.py"), encoding="utf-8") as f:
            hs_src = f.read()
    except OSError as e:
        bad.append("读不到 host_shield.py：%r" % (e,))
    if hs_src and "def norm_version_bytes" not in hs_src:
        bad.append("host_shield.py 里没有 `norm_version_bytes` 定义（唯一真源不见了）")
    for rel in ("scripts/build_package.py", "scripts/run_harness.py",
                "tools/antinel_verify.py"):
        try:
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                src = f.read()
        except OSError as e:
            bad.append("%s 读不到：%r" % (rel, e))
            continue
        if "host_shield" not in src:
            bad.append("%s 没有消费 host_shield ⇒ 它可能自己实现了一份归一化" % rel)
        if re.search(r"re\.(?:compile|sub)\([^)\n]*_ANTINEL_VERSION", src):
            bad.append("%s 里出现了自己的 `_ANTINEL_VERSION` 归一化正则（必须只有一个实现）" % rel)
    if bad:
        return "；".join(bad)
    return True


@check("N-S19-380 负控：把归一化换成'恒等'（等于不归一化）⇒ S19-380 ①必须报红")
def n_s19():
    p = os.path.join(ROOT, "hooks", "pre_tool_use.py")
    with open(p, "rb") as f:
        raw = f.read()
    if not _norm_selfcheck(lambda b: b, raw):
        return "负控失效：恒等归一化（＝不归一化）下 S19-380 ①仍然绿"
    return True


@check("N-S19b 负控：把归一化改成'整行替换'（连行尾注释一起吞）⇒ S19-380 ②必须报红")
def n_s19b():
    p = os.path.join(ROOT, "hooks", "pre_tool_use.py")
    with open(p, "rb") as f:
        raw = f.read()
    whole = lambda b: re.sub(rb"(?m)^[ \t]*_ANTINEL_VERSION[^\r\n]*", b"X", b)   # noqa: E731
    probs = _norm_selfcheck(whole, raw)
    if not any("②" in x for x in probs):
        return "负控失效：整行替换（吞掉行尾注释）未被 S19-380 ② 抓出"
    return True


# ══════════ S100–S103 三通道（0.51.0 规格 v1.2 §2／§3／§7.2）═══════════
#: ★ 为什么并入本套件而不是新开一套（机制层 A2）：常驻套件上限 29，新开一套
#:   就得先退休一个。这四条守的正是本套件同一对象（主灯／灯态语义与它的
#:   渲染出口），并进 0380 是**同域聚合**，不是"为了躲上限"。

@check("S100 保持期：info 桶事件只在**未读 ∧ 刚发生**时抬主灯；已读／超期转待阅")
def s100():
    import inbox_model as M
    G = _g()
    H = M.LAMP_HOLD_MINUTES
    bad = []
    # ① info 桶（`tool_call_blocked` 在"自动处理"黑名单里 ⇒ info）
    for name, kw, want in (
            ("刚发生·未读", {"hours_ago": 0.0}, "L2"),
            ("H 内·未读", {"hours_ago": (H - 1) / 60.0}, "L2"),
            ("超 H·未读", {"hours_ago": (H + 1) / 60.0}, "L0"),
            ("刚发生·已读", {"hours_ago": 0.0, "state": "read"}, "L0"),
            ("刚发生·已处理", {"hours_ago": 0.0, "state": "done"}, "L0")):
        got = M.light_explain({"state": "guarding", "why": "x"},
                              [G._mk_item(kind="tool_call_blocked", **kw)])["state"]
        if got != want:
            bad.append((name, got, want))
    # ② ★ action 桶**不适用保持期**：待办不是新闻，窗口内未关闭即持续抬灯。
    #   今天没有 L2/L1 的 action kind ⇒ 用 monkeypatch 造一个（规格 §7.2 记的手法）：
    #   把 `tool_call_blocked` 暂时移出"自动处理"黑名单 ⇒ 它变成"只有你能解决"。
    old = M.AUTO_HANDLED_KINDS
    M.AUTO_HANDLED_KINDS = frozenset(old - {"tool_call_blocked"})
    try:
        got_a = M.light_explain(
            {"state": "guarding", "why": "x"},
            [G._mk_item(kind="tool_call_blocked", hours_ago=1.0)])["state"]
        got_r = M.light_explain(
            {"state": "guarding", "why": "x"},
            [G._mk_item(kind="tool_call_blocked", hours_ago=1.0,
                        state="read")])["state"]
    finally:
        M.AUTO_HANDLED_KINDS = old
    if got_a != "L2":
        bad.append(("action·1h·未读（应持续抬灯）", got_a, "L2"))
    if got_r != "L2":
        bad.append(("action·1h·已读（待办不许被'看过'消掉）", got_r, "L2"))
    if bad:
        return "保持期不对：%r" % bad
    return True


@check("N-S100 负控：拿掉保持期（info 一律抬灯）⇒ S100 必须报红")
def n_s100():
    import inbox_model as M
    orig = M._event_lamp_level

    def no_hold(items, hours=None, now=None):          # ← MUTANT：无新鲜度条件
        best = None
        for it in M._window_open(items, hours or M.WINDOW_HOURS, now):
            if it.level not in (M.STATE_L2, M.STATE_L1):
                continue
            if M.PRIORITY.get(it.level, 0) > M.PRIORITY.get(best, 0):
                best = it.level
        return best

    M._event_lamp_level = no_hold
    try:
        r = s100()
    finally:
        M._event_lamp_level = orig
    if r is True:
        return "负控失效：拿掉保持期后 S100 仍然绿"
    return True


@check("S101 研发徽标：版本四态（> / = / < / 取不到）＋ **数值**比较（0.9.0 vs 0.10.0）")
def s101():
    import inbox_model as M
    bad = []
    for name, vp, want in (("本机更新", ("9.9.9", "1.0.0"), True),
                           ("相同", ("1.0.0", "1.0.0"), False),
                           ("本机更旧", ("1.0.0", "9.9.9"), False),
                           ("取不到", (None, None), False)):
        if M.is_ahead_of_published(*vp) is not want:
            bad.append(("is_ahead_of_published %s" % name,
                        M.is_ahead_of_published(*vp), want))
        has = "dev" in [k for k, _n, _w in M.badges("guarding", None, [],
                                                    versions=vp)]
        if has is not want:
            bad.append(("徽标 %s" % name, has, want))
    # ★ F47/F54 同族的"看起来对、其实错"：**字符串**比较下 0.9.0 > 0.10.0 为真。
    if M.is_ahead_of_published("0.9.0", "0.10.0"):
        bad.append(("0.9.0 vs 0.10.0（字符串比较的陷阱）", True, False))
    # ★ 降级不假阳：已发布版本取不到 ⇒ 不亮徽标
    if M.badges("guarding", None, [], versions=(None, "0.1.0")):
        bad.append(("published 取不到却亮了徽标", M.badges(
            "guarding", None, [], versions=(None, "0.1.0")), "不亮"))
    if bad:
        return "研发徽标判据不对：%r" % bad
    return True


@check("N-S101 负控：把版本比较退回**字符串** ⇒ 0.9.0 vs 0.10.0 当场误判 ⇒ 必须红")
def n_s101():
    import inbox_model as M
    orig = M._ver_tuple
    M._ver_tuple = lambda s: s                        # ← MUTANT：字符串比较
    try:
        r = s101()
    finally:
        M._ver_tuple = orig
    if r is True:
        return "负控失效：退回字符串比较后 S101 仍然绿"
    return True


@check("S102 三通道**并存**：研发徽标 ＋ R0 主灯不抬 ＋ 要处理计数 同时为真")
def s102():
    import inbox_model as M
    G = _g()
    ex = M.light_explain({"state": "guarding", "why": "监理在岗"},
                         [G._mk_item(kind="host_shield_breach", state="unread")],
                         granary={"state": "low", "why": "粮快见底了"},
                         versions=("9.9.9", "1.0.0"))
    bad = []
    if ex["state"] != M.STATE_L0:
        bad.append(("主灯", ex["state"], "L0（R0 绝不由账给）"))
    keys = [k for k, _n, _w in ex["badges"]]
    for want in ("dev", "granary"):
        if want not in keys:
            bad.append(("徽标缺 %s" % want, keys, "含 %s" % want))
    if ex["action_count"] < 1:
        bad.append(("要处理件事数", ex["action_count"], ">=1"))
    # ★ 立规：action>0 时**禁止**说"此刻是好的"（只有你能解决的事还在）
    if "此刻是好的" in ex["reason"]:
        bad.append(("原因句", ex["reason"][:40], "action>0 禁说'此刻是好的'"))
    if bad:
        return "三通道没同时成立（并存被压平？）：%r" % bad
    return True


@check("N-S102 负控：让徽标恒为空 ⇒ S102 必须红（证明并存靠徽标通道承重）")
def n_s102():
    import inbox_model as M
    orig = M.badges
    M.badges = lambda *a, **k: []                      # ← MUTANT
    try:
        r = s102()
    finally:
        M.badges = orig
    if r is True:
        return "负控失效：徽标恒空后 S102 仍然绿"
    return True


@check("S103 原因句：主灯原因 ＋ 待办提示进句；徽标原因**不进**主行但徽标须在（缺一即红）")
def s103():
    import inbox_model as M
    G = _g()
    bad = []
    # ① 空账：先说此刻，且以句号收尾（多段拼接不许漏标点）
    ex = M.light_explain({"state": "guarding", "why": "监理在岗"}, [],
                         versions=("1.0.0", "9.9.9"))
    if "此刻" not in ex["reason"]:
        bad.append(("空账缺'此刻'", ex["reason"]))
    if not ex["reason"].rstrip().endswith("。"):
        bad.append(("空账未以句号收尾", ex["reason"]))
    # ② 有账：必须提"没处理"（账不许被藏）
    ex2 = M.light_explain({"state": "guarding", "why": "监理在岗"},
                          [G._mk_item(kind="host_shield_breach")],
                          versions=("1.0.0", "9.9.9"))
    if "没处理" not in ex2["reason"]:
        bad.append(("有账缺'没处理'", ex2["reason"]))
    # ③ 徽标原因**不进主行**，但徽标本身必须在（FZ-004 冻结契约）
    #    ★ 原断言是「'研发' 必须出现在 reason 里」。FZ-004（创始人 2026-10-16
    #      截图 #4「啰嗦、浓重机器味」⇒ 2026-10-17 冻结）把徽标原因句**移出**
    #      主行后，这条旧断言开始把**正确实现判红** —— 与 U-13 同型的过期判据：
    #      判据守着一条已被推翻的口径，就会反过来逼人把缺陷改回来。
    #    新口径双向：主行**不许**出现徽标原因（否则啰嗦复发）＋ 徽标**必须**
    #      还在 badges 里且带完整原因（不许用「删掉徽标」让主行变干净——那是
    #      信息丢失，FZ-004 只许挪位置）。「版号出现在 title／点开可见」那一腿
    #      由 FZ-004 的 j_reason_line_budget 三腿守着，本条不重复实现。
    ex3 = M.light_explain({"state": "guarding", "why": "监理在岗"}, [],
                          versions=("9.9.9", "1.0.0"))
    if "研发" in ex3["reason"]:
        bad.append(("徽标原因又拼进主行（FZ-004 已禁）", ex3["reason"]))
    _dev_badges = [b for b in (ex3.get("badges") or [])
                   if isinstance(b, (list, tuple)) and b and b[0] == "dev"]
    if not _dev_badges:
        bad.append(("研发中徽标整个不见了（只许挪位置，不许删信息）",
                    ex3.get("badges")))
    elif not (len(_dev_badges[0]) > 2 and "9.9.9" in str(_dev_badges[0][2])):
        bad.append(("研发中徽标缺完整原因（版号要留得住）", _dev_badges[0]))
    # ④ 旧语义不许回来
    if "灯这样报" in ex2["reason"]:
        bad.append(("退回旧语义'灯这样报'", ex2["reason"]))
    if bad:
        return "原因句三元组不对：%r" % bad
    return True


@check("N-S103 负控：让分桶恒为归档（待办看不见）⇒ S103 必须红")
def n_s103():
    import inbox_model as M
    orig = M.bucket_of
    M.bucket_of = lambda *a, **k: M.BUCKET_ARCHIVE     # ← MUTANT
    try:
        r = s103()
    finally:
        M.bucket_of = orig
    if r is True:
        return "负控失效：待办被藏起来后 S103 仍然绿"
    return True


def main():
    print("=" * 78)
    print("0.39.x 判据 —— 灯＝此刻 ＋ 术语表口径（不许拿历史账冒充'当前状态'；"
          "全部内存变异，不写盘）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                why = ""
            print("  ✅ %-58s %s" % (name, why or ""))
            ok += 1
        except AssertionError as e:
            print("  ❌ %-58s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-58s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
