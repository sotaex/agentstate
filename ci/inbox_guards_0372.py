#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""0.37.3 判据 —— **六态封闭** ＋ **已敲定的词表不再漂移**。

★★ 这一份判据是创始人 2026-10-09 那三句「一定要机制上解决」的直接产物：

    「哨兵状态是 LOGO 五态加上开发态一共六态，这个要从机制上钉死，
      不要再杜撰其他什么态，一定要机制上解决，机制上解决，机制上解决。
      其他类似地方，敲定的内容，就不要再发生漂移，也是要从机制上解决，
      机制上解决，机制上解决。」

  ⇒ 过去的做法是**把结论写在注释里**，然后指望每一轮（可能是另一个模型、
    另一个上下文）都记得它。实测这条路走不通：0.36.0–0.36.4 之间，"8 个派生
    灯态"（失守/中断·无损失/存疑/研发中/值守中·需你处理/值守中/未启用/查不到）
    就是**AI 自己长出来的**，没有一条判据看得见它们。
  ⇒ 本文件把三件事从"注释里的约定"变成"可执行、会报红、有负控的机制"：
    ① 六态是**闭集**：多一个少一个都报红（S01/S02）；
    ② 状态词是**封闭词表**：杜撰的词进不了用户面（S03/S04）；
    ③ 敲定的分工是**单源**：哨兵唯一角色、护盾只能作为它的工具出现一处、
       顶部灯的说明只能由 `light_explain()` 拼（S05/S06/S07）；
    ④ 六态**名**与**次序**也单源：名只能在 `inbox_model.py` 定义一份、
       其余模块一律派生（S08）；次序量的是「离终结有多近」（S09）。

★★ 本文件的编写纪律（沿用本仓惯例）：
  · **每条判据都配负控**：把被测的机制故意改坏，判据必须报红。
    没有负控的判据只是一段会执行的代码。
  · **判据只查行为**：真跑产品函数、真渲染页面；不靠正则去猜源码意图。
  · ★★★ **本文件绝不写盘**（不改任何产品文件）。
    理由（0.36.5 的教训）：会临时改坏产品文件的负控**不能进打包前的闸门** ——
    打包进程中途被杀/断电，变异的代码会随包发出去。
    ⇒ 本文件的负控全部走**内存变异 + 还原**（monkeypatch / 属性替换），
      因此它可以安全地留在 `--quick` 都会被跑到的 fast 档。
"""
from __future__ import annotations

import os
import re
import sys
import html as _H
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

RESULTS = []


def check(name):
    def deco(fn):
        RESULTS.append((name, fn))
        return fn
    return deco


# ══════════════════════════════════════════════════════════ 真源常量 ══════════
#: ★ 六态，**逐字**（创始人：LOGO 五态 ＋ 开发态）。判据自己写死一份，
#:   **故意不 import `inbox_model` 取它** —— 若两边都取自同一个常量，
#:   那么"有人把 inbox_model 里的六态改成七态"时，判据会跟着变，等于没守。
#:   写死在这里，两边不一致就报红。
SIX_STATES = ("R0", "L2", "L1", "Ls", "L0", "dev")
SIX_LABELS = {"R0": "失守", "L2": "拦截", "L1": "注意",
              "Ls": "缺粮", "L0": "值守中", "dev": "研发中"}
#: L0 的灰变体（未启用与值守中同属 L0，差别只在"有没有在守"）。
L0_VARIANT = "未启用"

#: 条目状态机（`inbox_model.STATES`）—— **不是**灯态。0.37.1 曾把六态集合
#: 命名成 `STATES` 覆盖掉它，页面上所有「知道了/忽略」按钮静默失效。
ITEM_STATES = ("unread", "read", "done", "ignored")

#: ★ 禁用词表。这些词**不许出现在用户看得见的正文里**（`<details>` 里的
#:   术语释义除外 —— 那是定义本身，护盾要在那里说明"我是工具"）。
#:   每一项都写明它为什么被禁，避免下一轮有人"觉得这词挺好"又加回来。
BANNED_IN_CHROME = {
    "存疑": "8 态灯时代 AI 自造的派生态；创始人 2026-10-07「计划外状态，不允许」",
    "门闸": "记录层的历史写法（链记录原文不改写）；人类面一律用「哨兵」",
    "护盾": "它是哨兵手里的**工具**，不是并列角色；只许在 `sentinel` 词条里出现",
    "查不到": "8 态灯时代的派生状态词；盲区现在的说法是「注意」",
    "中断·无损失": "把两件事挤进一个标签；姿态词现在是「中断」",
    "需你处理": "8 态灯时代的派生状态词；现在是「要处理」（分档词，不是灯态）",
}

#: 术语正文里也**一律不许**出现的词（比上面更窄：`护盾` 在 `sentinel` 词条里
#: 是必须出现的，所以不能进这一张表）。
BANNED_IN_TERMS = ("存疑", "查不到", "中断·无损失", "需你处理")


# ══════════════════════════════════════════════════════════ 工具 ══════════
def _strip_details(html_text):
    """剥掉**所有** `<details>`（术语词条/词表）—— 得到"正文"。

    ★ 口径沿用 `0360` 的 W06：`<details>` 默认收起＝要点开才看得见，
      因而不算"堆在界面上的正文"。本判据关心的正是"不点开也躲不掉的字"。
    ★ 必须用**平衡匹配**的剥离器，不能只删开合标签：
      `chip()` 生成的 details **内部还嵌着** `<div class="tdef">` 与 `<b>`，
      只删标签会把词条正文留在原地（那正是被禁的词藏身之处）。
    """
    html_text = re.sub(r"<script\b.*?</script>", "", html_text or "", flags=re.S)
    html_text = re.sub(r"<style\b.*?</style>", "", html_text, flags=re.S)
    out, i, n = [], 0, len(html_text)
    while i < n:
        j = html_text.find("<details", i)
        if j < 0:
            out.append(html_text[i:])
            break
        out.append(html_text[i:j])
        depth, k = 0, j
        while k < n:
            m = re.compile(r"<details\b|</details>").search(html_text, k)
            if not m:
                k = n
                break
            if m.group(0).startswith("</"):
                depth -= 1
                k = m.end()
                if depth == 0:
                    break
            else:
                depth += 1
                k = m.end()
        i = k
    text = "".join(out)
    text = re.sub(r"<[^>]+>", " ", text)
    return _H.unescape(text)


def _pkg_root():
    import inbox_server as SV
    return SV._pkg_root()


def _posture_cases():
    """★ 用**真 `guard_posture()`** 造出全部七个姿态（每个带它自己的 `why`）。

    ★★ 为什么必须"真跑"而不是自己编七个 dict（这是本判据的关键）：
      被禁的词恰好藏在 `guard_posture()` 的**返回文案**里，而那些文案只有在
      对应分支被走到时才生成（例：「防护开着，但哨兵进程不在岗」只在缺岗时）。
      自己编 dict ⇒ 判据永远看不到真实分支的文案 ⇒ 又一次"对不存在的缺陷做检查"。
    ★ 只替换**被探值**（在不在岗/心跳/自检/后果），不替换分支逻辑本身。
    ★ 全部在内存里做，结束无条件还原；不碰盘。
    """
    import host_shield as HS
    names = ("armed_state", "sentinel_alive", "sentinel_heartbeat_age",
             "_sentinel_uptime", "self_check", "_outage_consequences",
             "is_dev_build", "load_state")
    saved = {k: getattr(HS, k, None) for k in names}
    iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    cases = [
        ("off",         dict(armed=False)),
        ("guarding",    dict()),
        ("dev",         dict(sc=(False, ["MUTANT: 判据自造的哈希不符"]), dev=(True, "代码比登记新"))),
        ("warn",        dict(sc=(False, ["MUTANT: 判据自造的哈希不符"]), dev=(False, ""))),
        ("interrupted", dict(alive=False, cons=[])),
        ("down",        dict(alive=False, cons=[{"text": "（判据注入的损失示例）"}])),
        ("unknown",     dict(load_raises=True)),
    ]
    out = []
    try:
        for name, st in cases:
            # ★ 每个替身都用 `_st=st` 默认参数**绑住当前这一轮**的注入值 ——
            #   否则闭包会全部指向循环结束后剩下的那一个（本轮第一次就踩到）。
            HS.armed_state = lambda *a, _st=st, **k: _st.get("armed", True)
            HS.sentinel_alive = lambda *a, _st=st, **k: _st.get("alive", True)
            HS.sentinel_heartbeat_age = (
                lambda *a, _st=st, **k: _st.get("hb", (30.0, iso)))
            HS._sentinel_uptime = lambda *a, _st=st, **k: _st.get("up", 3600.0)
            HS.self_check = lambda *a, _st=st, **k: _st.get("sc", (True, []))
            HS._outage_consequences = lambda *a, _st=st, **k: _st.get("cons", [])
            HS.is_dev_build = lambda *a, _st=st, **k: _st.get("dev", (False, ""))
            if st.get("load_raises"):
                def _boom():
                    raise RuntimeError("MUTANT: 判据自造的探针异常")
                HS.load_state = _boom
            else:
                HS.load_state = saved["load_state"]
            p = HS.guard_posture(_pkg_root())
            got = p.get("state")
            if got != name:
                raise AssertionError(
                    "造不出姿态 %r（拿到 %r）—— 判据的注入点与产品脱钩了，"
                    "必须同步，否则本判据是在验一个不存在的场景" % (name, got))
            out.append((name, p))
    finally:
        for k, v in saved.items():
            setattr(HS, k, v)
    return out


def _chrome_of(posture, items=None, views=("inbox", "report", "health", "ledger")):
    """把四个栏目渲染一遍，返回 `{view: 正文文本}`（已剥 details）。

    ★ `items` 缺省是**空列表**：这样正文里的一切都只能来自**页面本身的文案**，
      与"这台机器上恰好有哪些记录"解耦 —— 判据因此在这台机器、别的机器、
      以及 CI 上得到同一个结论。
    """
    import inbox_report as R
    import inbox_server as SV
    items = [] if items is None else items
    # ★ 复用同一份 rep：`daily_report` 会逐条复算整条审计链（本机实测 5.4s），
    #   七个姿态各算一次就是 38s。传空链文件 ⇒ 0.24s，且正文照样渲染。
    rep = R.daily_report(chain_files=[], items=items)
    out = {}
    for v in views:
        h = SV.render_page(view=v, root=None, token="TOKEN", items=items,
                           posture=posture, rep=rep)
        out[v] = _strip_details(h)
    return out


# ══════════════════════════════════ S01 六态是闭集 ══════════════════════════
def _six_state_set_ok(lights, label, logo, var):
    """六态闭集的**纯函数**版本（判据与负控共用同一段判断）。"""
    if tuple(lights) != SIX_STATES:
        return ("灯态集合不是逐字六态 —— 多 %s / 少 %s / 顺序 %r"
                % (sorted(set(lights) - set(SIX_STATES)),
                   sorted(set(SIX_STATES) - set(lights)), tuple(lights)))
    for nm, tb in (("STATE_LABEL", label), ("STATE_LOGO", logo), ("STATE_VAR", var)):
        if set(tb) != set(SIX_STATES):
            return ("%s 的键与六态不一致 —— 多 %s / 少 %s"
                    % (nm, sorted(set(tb) - set(SIX_STATES)),
                       sorted(set(SIX_STATES) - set(tb))))
    if dict(label) != SIX_LABELS:
        bad = {k: (label.get(k), SIX_LABELS[k]) for k in SIX_STATES
               if label.get(k) != SIX_LABELS[k]}
        return "灯态的人话标签被改过：%r" % bad
    # 未启用必须是 L0 的**变体**，不许自成一个态
    if L0_VARIANT in set(label.values()):
        return "「%s」被写进了 STATE_LABEL —— 它是 L0 的灰变体，不是第七态" % L0_VARIANT
    return True


@check("S01 六态是逐字的闭集（灯态表与其键完全一致）")
def s01():
    import inbox_model as M
    r = _six_state_set_ok(M.LIGHT_STATES, M.STATE_LABEL, M.STATE_LOGO, M.STATE_VAR)
    if r is not True:
        return _raise(r)
    return "LIGHT_STATES=%s；LABEL/LOGO/VAR 三表键与之逐字一致" % (list(M.LIGHT_STATES),)


@check("N-S01 负控：多一个第七态必须被 S01 抓到")
def n_s01():
    import inbox_model as M
    # 真做变异：把六态加上一个自造态，S01 的逻辑必须报错
    lights = tuple(M.LIGHT_STATES) + ("attention",)
    label = dict(M.STATE_LABEL)
    label["attention"] = "需你处理"
    r = _six_state_set_ok(lights, label, M.STATE_LOGO, M.STATE_VAR)
    if r is True:
        return _raise("往灯态集合加一个自造态，S01 仍判通过 ⇒ 闭集没守住")
    # 再验一次"改键"也能抓到（加深一态）
    label2 = {k: v for k, v in M.STATE_LABEL.items() if k != "dev"}
    r2 = _six_state_set_ok(M.LIGHT_STATES, label2, M.STATE_LOGO, M.STATE_VAR)
    if r2 is True:
        return _raise("删掉一个灯态标签，S01 仍判通过 ⇒ 判据只看数量不只看内容")
    return "第七态/改键两种变异都被抓到"


# ══════════════════════════════════ S02 穷举不越界 ══════════════════════════
#: 计划外输入（含不可哈希、None、数字、带空白/换行的串）—— 一律不许抛异常，
#: 也**绝不许**落到六态之外（尤其不许打绿）。
BAD_INPUTS = [None, "", "banana", "研发", "计划外", 0, 3.5, True, [], {},
              b"x", "OK", "ok ", " guardING", "guarding\n", 0xDEAD, ("t",)]


def _item_ts():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _mk_item(kind="host_shield_breach", state="unread", hours_ago=0.0, **kw):
    import inbox_model as M
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z",
                       time.localtime(time.time() - hours_ago * 3600))
    al = M.Alert.build(ts=ts, kind=kind, reason="判据构造", **kw)
    return M.Item(alert=al, state=state)


def _sweep_six_state():
    """真跑穷举。返回问题清单（空＝全过）。"""
    import host_shield as HS
    import inbox_model as M
    allowed_labels = set(SIX_LABELS.values()) | {L0_VARIANT}
    item_sets = [
        [],
        [_mk_item(state="unread")],                            # 窗口内 R0 未处理
        [_mk_item(state="done")],                              # 已处理
        [_mk_item(state="ignored")],
        [_mk_item(kind="tool_call_blocked", state="unread")],  # L2 已拦（Autinel 干完）
        [_mk_item(hours_ago=48)],                              # 窗口外
        [_mk_item(hours_ago=h, state="unread") for h in (0, 1, 5, 12, 23)],
    ]
    bad = []
    for st in list(HS.POSTURE_ALL) + BAD_INPUTS:
        for items in item_sets:
            try:
                lg, why = M.light(st, items)
            except Exception as e:                             # noqa: BLE001
                bad.append("light(%r) 抛 %s" % (st, type(e).__name__))
                continue
            if lg not in M.LIGHT_STATES:
                bad.append("light(%r) → %r（六态之外）" % (st, lg))
            lab = M.state_label(lg, st)
            if lab not in allowed_labels:
                bad.append("state_label(%r,%r) → %r（词表之外）" % (lg, st, lab))
            try:
                bs, _ = M.base_state(st)
            except Exception as e:                             # noqa: BLE001
                bad.append("base_state(%r) 抛 %s" % (st, type(e).__name__))
                continue
            if bs not in M.LIGHT_STATES:
                bad.append("base_state(%r) → %r（六态之外）" % (st, bs))
            blab = M.state_label(bs, st)
            if blab not in allowed_labels:
                bad.append("state_label(%r,%r) → %r（词表之外）" % (bs, st, blab))
        if bad:
            break
    return bad


@check("S02 穷举：七姿态 × 多组记录 × 坏输入，灯态恒在六态内且不抛异常")
def s02():
    bad = _sweep_six_state()
    if bad:
        return _raise("；".join(bad[:5]))
    return ("%d 组输入（7 姿态 + %d 计划外输入）× %d 组记录，"
            "灯态与标签全域封闭" % (7 + len(BAD_INPUTS), len(BAD_INPUTS), 7))


@check("N-S02 负控：让六态集合少一个（灯能返回集合外的值）⇒ S02 必须抓到")
def n_s02():
    import inbox_model as M
    orig = M.LIGHT_STATES
    try:
        # 真做变异：从集合里摘掉 dev ⇒ `light("dev")` 会返回集合外的 "dev"
        M.LIGHT_STATES = tuple(s for s in orig if s != "dev")
        bad = _sweep_six_state()
        if not bad:
            return _raise("摘掉一个灯态后穷举仍全过 ⇒ S02 对'越界'零分辨力")
    finally:
        M.LIGHT_STATES = orig
    # 还原后必须回绿（还原链路坏掉比负控失效更险）
    if _sweep_six_state():
        return _raise("还原 LIGHT_STATES 后穷举仍报错 ⇒ 还原链路坏了")
    return "摘掉 dev ⇒ 越界被抓；还原 ⇒ 回绿"


# ══════════════════════════════════ S03 用户面没有杜撰的态 ══════════════════
def _scan_banned(chrome_texts):
    """在正文文本里找禁用词。返回 `[(视图, 词, 出处)]`。"""
    hits = []
    for view, text in chrome_texts.items():
        for w in BANNED_IN_CHROME:
            if w in text:
                i = text.find(w)
                hits.append("%s 正文出现「%s」：…%s…"
                            % (view, w, text[max(0, i - 22):i + 22].strip()))
    return hits


@check("S03 用户可见正文里没有杜撰的状态词/角色词（七姿态 × 四栏目）")
def s03():
    hits = []
    for name, p in _posture_cases():
        ch = _chrome_of(p)
        h = _scan_banned(ch)
        hits += ["[姿态 %s] %s" % (name, x) for x in h]
    if hits:
        return _raise("；".join(hits[:5]))
    return "七种姿态 × 四个栏目，正文均无 %s" % ("、".join(sorted(BANNED_IN_CHROME)))


@check("N-S03 负控：把一个禁用语塞进姿态文案 ⇒ S03 必须抓到")
def n_s03():
    poisoned = {"state": "interrupted", "label": "中断",
                "why": "护盾开着，但门闸此刻没人守（MUTANT，存疑）。",
                "can_fix": True, "fix": "revive", "fix_hint": "马上修复",
                "consequences": []}
    ch = _chrome_of(poisoned)
    h = _scan_banned(ch)
    if not h:
        return _raise("把「护盾/门闸/存疑」写进姿态文案，S03 仍判干净 ⇒ 扫描器空转")
    # 至少三个词都得抓到（否则扫描器只认一个词）
    got = {w for w in BANNED_IN_CHROME if any(w in x for x in h)}
    need = {"护盾", "门闸", "存疑"}
    if not need <= got:
        return _raise("露出来的词没全抓到：%s（希望 %s）" % (sorted(got), sorted(need)))
    return "注入 3 个禁用语 ⇒ 全被抓到"


# ══════════════════════════════════ S04 姿态词表封闭 ════════════════════════
def _posture_label_ok(table, allowed):
    over = sorted(set(table.values()) - set(allowed))
    if over:
        return "姿态标签出现词表外的词：%r（允许：%s）" % (over, sorted(allowed))
    return True


@check("S04 姿态标签的值落在封闭词表内（六态标签 ＋ 未启用 ＋ 中断）")
def s04():
    import host_shield as HS
    if not hasattr(HS, "POSTURE_LABEL_ALLOWED"):
        return _raise("host_shield 没有 POSTURE_LABEL_ALLOWED —— 词表没有真源，"
                      "下一轮又会有人往 POSTURE_LABEL 里加一个自造态")
    miss = set(HS.POSTURE_ALL) - set(HS.POSTURE_LABEL)
    if miss:
        return _raise("姿态 %s 没有标签（UI 取不到会空白）" % sorted(miss))
    # 词表本身也必须只含六态标签 + 两个具名例外 —— 否则"允许集"自己会漂
    expected = set(SIX_LABELS.values()) | {L0_VARIANT, "中断"}
    if set(HS.POSTURE_LABEL_ALLOWED) != expected:
        return _raise("词表内容被改过：多 %s / 少 %s"
                      % (sorted(set(HS.POSTURE_LABEL_ALLOWED) - expected),
                         sorted(expected - set(HS.POSTURE_LABEL_ALLOWED))))
    r = _posture_label_ok(HS.POSTURE_LABEL, HS.POSTURE_LABEL_ALLOWED)
    if r is not True:
        return _raise(r)
    return "七个姿态标签 ⊆ %s" % sorted(HS.POSTURE_LABEL_ALLOWED)


@check("N-S04 负控：往姿态标签里塞一个自造态 ⇒ S04 必须抓到")
def n_s04():
    import host_shield as HS
    t = dict(HS.POSTURE_LABEL)
    t[HS.POSTURE_WARN] = "存疑"
    if _posture_label_ok(t, HS.POSTURE_LABEL_ALLOWED) is True:
        return _raise("把 warn 的标签改回「存疑」，S04 仍判通过 ⇒ 词表没守住")
    return "自造态「存疑」被词表挡住"


# ══════════════════════════════════ S05 术语单源 ════════════════════════════
@check("S05 「哨兵」是唯一的守护角色；「护盾」只作为它的工具出现一处")
def s05():
    import glossary as GL
    if "shield" in GL.TERMS:
        return _raise("术语表里又有并列的 `shield` 词条了 —— 创始人 2026-10-09："
                      "「不要制造并列的护盾加哨兵两个概念，哨兵一个概念足矣」")
    sent = GL.TERMS.get("sentinel")
    if not sent:
        return _raise("没有 `sentinel` 词条 —— 「哨兵」这个唯一角色没有定义")
    body = " ".join(str(sent.get(k, "")) for k in ("one", "inc", "exc", "unit"))
    if "护盾" not in body:
        return _raise("`sentinel` 词条里没交代「护盾」是什么 ⇒ 用户读到「护盾」"
                      "会以为它是另一个角色（这正是要禁的并列概念）")
    if "工具" not in body:
        return _raise("`sentinel` 词条提到了「护盾」但没说它是**工具** ⇒ "
                      "读者仍会把两者当成两个平行的东西")
    # 护盾**只许**在 sentinel 词条里定义（别处出现就是第二个角色）
    others = [k for k, t in GL.TERMS.items() if k != "sentinel"
              and "护盾" in " ".join(str(v) for v in t.values())]
    if others:
        return _raise("「护盾」还出现在其它词条里：%s ⇒ 它又被写成了并列概念"
                      % others)
    # 术语正文里也不许有杜撰的状态词
    hits = []
    for k, t in GL.TERMS.items():
        blob = " ".join(str(v) for v in t.values())
        for w in BANNED_IN_TERMS:
            if w in blob:
                hits.append("%s 词条含「%s」" % (k, w))
    if hits:
        return _raise("；".join(hits))
    return "哨兵唯一角色；护盾仅作为其工具在 `sentinel` 词条里出现一次"


@check("N-S05 负控：把并列的 `shield` 词条加回去 ⇒ S05 必须抓到")
def n_s05():
    import glossary as GL
    if "shield" in GL.TERMS:
        return _raise("`shield` 已在表里 —— 本负控要验的是「加回去会被抓到」")
    GL.TERMS["shield"] = {"w": "护盾", "one": "另一个守护角色。",
                          "inc": "x", "exc": "y", "unit": "z"}
    caught = False
    try:
        try:
            s05()
        except AssertionError:
            caught = True
    finally:
        del GL.TERMS["shield"]
    if not caught:
        return _raise("把 `shield` 并列词条加回去，S05 仍判通过 ⇒ 单源没守住")
    try:
        s05()
    except AssertionError as e:
        return _raise("还原后 S05 仍判红 ⇒ 还原链路坏了：%s" % e)
    return "并列词条 `shield` 被 S05 抓到；还原后回绿"


# ══════════════════════════════════ S06 顶部灯说明单源 ══════════════════════
@check("S06 顶部条的原因句只能来自 light_explain()（不许页面自己拼）")
def s06():
    import inbox_model as M
    import inbox_server as SV
    orig = M.light_explain
    probe = "判据探针：这句话只可能来自 light_explain（S06）。"
    posture = {"state": "guarding", "label": "值守中", "why": "哨兵在岗",
               "can_fix": False, "fix": None, "fix_hint": "", "consequences": []}
    try:
        M.light_explain = lambda *a, **k: {
            "state": "R0", "label": "失守", "now_text": "X",
            "now_bad": True, "ledger_bad": False, "reason": probe}
        bar = SV._bar([], "TOKEN", posture=posture, view="inbox")
        if probe not in bar:
            return _raise("_bar 没有用 light_explain() 的 reason ⇒ "
                          "页面自己拼了第二套说明（两套必然漂移）")
    finally:
        M.light_explain = orig
    # 还原后必须回到正常实现（真跑一次，看说明句还在不在）
    bar2 = SV._bar([], "TOKEN", posture=posture, view="inbox")
    if not bar2.strip():
        return _raise("还原 light_explain 后 _bar 渲染为空 ⇒ 还原链路坏了")
    return "注入探针句 ⇒ 页面原样出现；还原 ⇒ 正常渲染"


@check("N-S06 负控：让 _bar 自己拼一句原因 ⇒ S06 必须抓到")
def n_s06():
    import inbox_model as M
    import inbox_server as SV
    orig = M.light_explain
    probe = "判据探针：这句话只可能来自 light_explain（S06）。"
    posture = {"state": "guarding", "label": "值守中", "why": "哨兵在岗",
               "can_fix": False, "fix": None, "fix_hint": "", "consequences": []}
    try:
        M.light_explain = lambda *a, **k: {
            "state": "R0", "label": "失守", "now_text": "X",
            "now_bad": True, "ledger_bad": False, "reason": probe}
        # 变异：让 `_bar` 不理 light_explain，自己拼（模拟"二次实现"）
        orig_bar = SV._bar

        def mut_bar(*a, **k):
            return orig_bar(*a, **k).replace(probe, "（页面自己拼的原因）")
        SV._bar = mut_bar
        try:
            bar = SV._bar([], "TOKEN", posture=posture, view="inbox")
            if probe in bar:
                return _raise("变异没生效 ⇒ 本负控无效（不是判据生效）")
        finally:
            SV._bar = orig_bar
    finally:
        M.light_explain = orig
    return "页面自己拼原因时，探针句消失 ⇒ S06 的分辨力成立"


# ══════════════════════════════════ S07 条目状态机未被覆盖 ══════════════════
@check("S07 六态不许覆盖条目状态机（STATES 仍是 unread/read/done/ignored）")
def s07():
    import inbox_model as M
    if tuple(M.STATES) != ITEM_STATES:
        return _raise("inbox_model.STATES = %r（应当是 %r）—— 0.37.1 就是这里被"
                      "六态集合覆盖掉，导致全部「知道了/忽略」按钮静默失效"
                      % (tuple(M.STATES), ITEM_STATES))
    if set(M.LIGHT_STATES) == set(M.STATES):
        return _raise("灯态集合与条目状态集合相同 ⇒ 其中一个被另一个覆盖了")
    if not M.can_transition("unread", "done"):
        return _raise("unread→done 被判非法 ⇒ 状态机被改坏了")
    if not M.can_transition("done", "read"):
        return _raise("done→read（撤销手滑）被判非法 ⇒ 状态机被改坏了")
    if M.can_transition("done", "unread"):
        return _raise("done→unread 被判合法 ⇒ 迁移表被悄悄放宽了")
    # ★ 未知状态名必须**抛错**，不许静默返回 False —— 静默 False 会让
    #   "状态名写错"表现得像"这个动作不允许"，两种故障分不开。
    for a, b in (("banana", "read"), ("read", "banana")):
        try:
            M.can_transition(a, b)
        except M.BadState:
            continue
        return _raise("未报错地接受了未知状态 %r ⇒ 状态机不再校验" % (a,))
    return "四态状态机与六态灯态互不干扰"


@check("N-S07 负控：把六态集合改名覆盖 STATES ⇒ S07 必须抓到")
def n_s07():
    import inbox_model as M
    orig = M.STATES
    caught = False
    try:
        M.STATES = M.LIGHT_STATES          # ← MUTANT：重演 0.37.1 真实的那个错误
        try:
            s07()
        except AssertionError:
            caught = True
    finally:
        M.STATES = orig
    if not caught:
        return _raise("把 STATES 换成六态后 S07 仍判通过 ⇒ 这条守不住")
    try:
        s07()
    except AssertionError as e:
        return _raise("还原后 S07 仍判红 ⇒ 还原链路坏了：%s" % e)
    return "重演 `STATES` 被覆盖 ⇒ 被抓到；还原后回绿"


# ══════════════════════════════ S08 六态名只有一个出处 ══════════════════════
#: 态名只许在 `inbox_model.py` 定义一份（本判据自己写死的那份是"对照样"，
#: 不是源码声明）。其余模块（术语表 / CLI / 日报 / 筛选条 / 托盘 / 页面）一律派生。
#: ★ 为什么挡"第二份"而不是"多写几条断言"：漂移的**入口**就是"又抄了一份" ——
#:   0.37.3 前同一个 Ls 态同时叫过 预算 / 额度 / 额度提示，就是抄了三份的结果。
#:   堵住入口，比在每个出口巡逻更省事、也更难绕过。
ALLOWED_DECL_FILES = ("inbox_model.py", "inbox_guards_0372.py")

#: 一份"态名声明"长什么样：`"<六态键>": "<含中文的值>"`。
#: 值里必须是中文，才排除掉 `STATE_VAR = {"R0": "--r0"}`、`LEVEL_TO_BUCKET = {"R0": "r0"}`
#: 这类**合法**的同键表（它们填的是 CSS 变量名 / 桶名，不是人话名）。
_STATE_DECL_RE = re.compile(
    r'"(R0|L2|L1|Ls|L0|dev)"\s*:\s*"([^"]*[\u4e00-\u9fff][^"]*)"')

#: 值（去掉尾部 `（XX）`）若等于下列任何一个，就认定这是一份"态名声明"。
#: 后半段是**历史别名** —— 它们曾各占一方；收进来是为了"老的错名不许回来"，
#: 不是为了继续使用。句子（如「有过失守」「一切正常」）不在表内 ⇒ 不误报。
_STATE_NAME_TOKENS = frozenset(
    list(SIX_LABELS.values()) + [L0_VARIANT, "中断"]              # 现行名＋合法变体
    + ["预算", "额度", "额度提示", "值守", "值守正常", "已拦截"])   # 历史别名


def _core_state_name(v):
    """去掉尾部 `（R0）`/`（Ls）` 这类括注，得到"名"本身。"""
    m = re.match(r"^(.*?)\s*（[A-Za-z0-9$]+）\s*$", v.strip())
    return (m.group(1).strip() if m else v.strip())


def _decl_scan(files):
    """`files` = [(相对路径, 源码文本)]；返回问题清单。

    ★ 纯函数（文本进、清单出）—— 这样负控可以喂**合成文本**来验分辨力，
      不必往盘上写一个假的源文件（本判据绝不写盘）。
    """
    bad = []
    for rel, text in files:
        if os.path.basename(rel) in ALLOWED_DECL_FILES:
            continue
        for m in _STATE_DECL_RE.finditer(text):
            key, val = m.group(1), m.group(2)
            if _core_state_name(val) not in _STATE_NAME_TOKENS:
                continue
            line = text[:m.start()].count("\n") + 1
            bad.append("%s:%d 又写了一份态名（%s → %r）" % (rel, line, key, val))
    return bad


def _skip_dir(name):
    """构建产物/缓存/归档副本/点目录 —— 都不是"现行源码"，不该被单源扫描看见。

    ★ 归档副本尤其要排：本仓习惯把旧件改名成 `<名字>.away-<序号>` 保留在
      原地，它们**必然**含有改名前的旧态名 —— 不排掉就会天天报红，
      然后有人会为了"让它绿"而把判据删掉（假阳性最坏的结局）。
    """
    return (name.startswith(".") or name in ("__pycache__", "_uxtest", "assets", "ci")
            or name.startswith("build") or name.startswith("dist")
            or name.startswith("_buildjunk") or ".away" in name)


def _source_files():
    """全仓产品源码（跳过构建产物/缓存/归档副本/测试导出/本判据目录）。"""
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
        for fn in filenames:
            if not fn.endswith(".py") or ".away" in fn or fn.startswith("_p_"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                out.append((os.path.relpath(p, ROOT), open(p, encoding="utf-8").read()))
            except Exception:                                   # noqa: BLE001
                pass
    return out


@check("S08 六态名只有一个出处（其余模块一律派生，第二份声明即报红）")
def s08():
    bad = _decl_scan(_source_files())
    if bad:
        return _raise("；".join(bad[:6]))
    return "全仓只有 inbox_model.py 定义六态名，其余模块全部派生"


@check("N-S08 负控：往别的文件写第二份态名要抓到；散文不许误报")
def n_s08():
    fake = [("inbox_server.py", 'X = {"R0": "失守", "Ls": "预算"}\n')]
    if not _decl_scan(fake):
        return _raise("在别的文件里写第二份态名，S08 仍判干净 ⇒ 扫描器空转")
    # 反向：句子（不是态名）不许被误判 —— 假阳性会逼人关掉这条判据
    prose = [("inbox_tray.py", 'X = {"R0": "有过失守"}\nY = {"L0": "一切正常"}\n')]
    if _decl_scan(prose):
        return _raise("把散文误判成态名声明 ⇒ 扫描器有假阳性")
    # 现行源必须干净（判据与源码不一致时先报出来）
    bad = _decl_scan(_source_files())
    if bad:
        return _raise("现行源码里仍有第二份声明：%s" % bad[:3])
    return "第二份声明被抓到；散文不误报；现行源干净"


# ══════════════════════════════ S09 光梯次序＝离终结的距离 ═══════════════════
#: 品牌动效语法 v1.2 §一.3「绿→浅黄→明黄→橙都是『领地有事、越来越急』；
#: 红色是另一回事——哨兵没了」＋ §三 扫描周期 12→8→5.5→3.5→**停摆**。
#: ⇒ 这把尺量的是「**离终结有多近**」，不是"事件多严重"。
EXPECTED_PRIORITY = {"L0": 1, "L1": 2, "L2": 3, "Ls": 4, "R0": 5}


def _priority_ok(prio):
    if dict(prio) != EXPECTED_PRIORITY:
        return ("光梯次序不是「离终结的距离」：拿到 %r，应为 %r"
                "（L0 值守中 < L1 注意 < L2 拦截 < Ls 缺粮 < R0 失守）"
                % (dict(prio), EXPECTED_PRIORITY))
    return True


@check("S09 光梯次序＝离终结的距离（Ls 紧贴 R0）＋ 派生面与真源逐字一致")
def s09():
    import glossary as GL
    import inbox_cli as CLI
    import inbox_model as M
    import inbox_server as SV
    r = _priority_ok(M.PRIORITY)
    if r is not True:
        return _raise(r)
    canon = dict(M.STATE_LABEL)
    problems = []
    for k in ("R0", "L2", "L1", "Ls", "L0"):
        want = canon[k]
        got = {"state_short": M.state_short(k),
               "filter_label": M.filter_label("lv:" + k),
               "LEVEL_NAME": SV.LEVEL_NAME.get(k),
               "glossary.w": _core_state_name(GL.TERMS[k]["w"]),
               "_fmt_level": _core_state_name(CLI._fmt_level(k))}
        off = {n: v for n, v in got.items() if v != want}
        if off:
            problems.append("%s 应叫 %r，但这些面是 %r" % (k, want, off))
    if problems:
        return _raise("；".join(problems))
    want_txt = " > ".join(canon[k] for k in sorted(
        EXPECTED_PRIORITY, key=lambda x: -EXPECTED_PRIORITY[x]))
    if M.PRIORITY_ORDER_TEXT != want_txt:
        return _raise("次序人话 %r ≠ 由 PRIORITY 算出的 %r"
                      % (M.PRIORITY_ORDER_TEXT, want_txt))
    return "五处派生面逐字一致；次序人话＝%s" % M.PRIORITY_ORDER_TEXT


@check("N-S09 负控：Ls 压回最低 / 某处派生面掉队 ⇒ S09 必须抓到")
def n_s09():
    import inbox_model as M
    import inbox_server as SV
    orig = M.PRIORITY
    try:
        M.PRIORITY = {"R0": 5, "L2": 4, "L1": 3, "Ls": 2, "L0": 1}     # ← MUTANT
        if _priority_ok(M.PRIORITY) is True:
            return _raise("把 Ls 压回最低，S09 仍判通过 ⇒ 次序没守住")
    finally:
        M.PRIORITY = orig
    if _priority_ok(M.PRIORITY) is not True:
        return _raise("还原 PRIORITY 后仍判红 ⇒ 还原链路坏了")
    orig_n = dict(SV.LEVEL_NAME)
    try:
        SV.LEVEL_NAME["Ls"] = "预算"                                    # ← MUTANT
        caught = False
        try:
            s09()
        except AssertionError:
            caught = True
        if not caught:
            return _raise("把 LEVEL_NAME 改回旧名，S09 仍判通过 ⇒ 派生面没守住")
    finally:
        SV.LEVEL_NAME.clear()
        SV.LEVEL_NAME.update(orig_n)
    try:
        s09()
    except AssertionError as e:
        return _raise("还原 LEVEL_NAME 后 S09 仍判红 ⇒ 还原链路坏了：%s" % e)
    return "Ls 压最低 / 派生面掉队，两种变异都被抓到；还原后回绿"


# ══════════════════════════════════ 运行 ═══════════════════════════════════
def _raise(msg):
    """把"说明性失败"统一抛成 AssertionError（main 里照常报红＋打明细）。"""
    raise AssertionError(msg)


def main():
    print("=" * 78)
    print("0.37.3 判据 —— 六态封闭 ＋ 已敲定词表不漂移（全部内存变异，不写盘）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                why = ""
            print("  ✅ %-52s %s" % (name, why or ""))
            ok += 1
        except AssertionError as e:
            print("  ❌ %-52s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-52s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
