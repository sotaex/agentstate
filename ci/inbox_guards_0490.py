#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.48.5 值守台细节修订判据（交接件 v1.1 §5.7）—— 编号 U-01…U-15。

★★ 由来：交接件 v1.1（2026-10-12）§5.2 的 19 条产品修订，逐条四件套
   （正判据／反向对照／连带对照／可观测）。本文件是它们的**判据落点**
   （与 0360/0372/0380/0470 同型），**按批次生长**：

     批次 1（甲2/甲3/甲4 ＋ 丙1/丙2）→ U-01 / U-03 / U-08（已落地，commit 049fc7c）
     批次 2（丁2/丁3/丁4/丁5）        → U-10 / U-11 / U-05（已落地，commit 9337bc4）
     批次 3（乙1~乙4）                → U-04 / U-06（本 commit）
     批次 4（戊1/戊2/戊4 ＋ 戊3 重排）→ U-13 / U-15
     批次 5（W-01 ＋ W-02 边界项）    → 单独 commit（认窗白名单）

   编号与 19 条**稳定映射**：U-02/U-07/U-09/U-12/U-14 是并入项与视觉项
   预留的空档，不是漏写（§5.7 表头原话）。红不了的（视觉排布）登记为
   截图验收，不许假装有判据。

★ 编写纪律（沿用 0360/0470）：
  · 每条判据配负控，且负控**真的会红**（先验注入真生效，再验变异后翻面）；
  · 断言打在**行为/结构**上（渲染产物、可见文本、调用点），不查行号；
  · **不写任何产品文件**：变异只发生在内存字符串／模块属性上；
    账本与链都落临时目录（`ANTINEL_HUB_DIR` 在 import 产品模块**之前**设好）；
  · 判据不许二次实现：口径一律 import 产品模块（`M.reading_note()` 等），
    不在本文件另写一份事实。
"""
from __future__ import annotations

import io
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ★★ 必须在 import 产品模块**之前**把中枢换到临时目录（0470 同款教训）：
#   否则渲染路径上的 posture_now / 账本读取会碰真实中枢的 notify_state.json。
_HUB = tempfile.mkdtemp(prefix="g0490_hub_")
os.environ["ANTINEL_HUB_DIR"] = _HUB
os.environ.pop("ANTINEL_AUDIT_DIRS", None)

import inbox_model as M                                          # noqa: E402
import inbox_server as SV                                        # noqa: E402
import glossary as GL                                            # noqa: E402

RESULTS = []

_SERVER_REL = "inbox_server.py"
_MODEL_REL = "inbox_model.py"


def check(name):
    """★ 判据**必须真会红** —— 返回说明串一律转成抛异常（0470 同款）。"""
    def deco(fn):
        def wrapper():
            r = fn()
            if r is True or r is None:
                return True
            raise AssertionError(r if isinstance(r, str) else repr(r))
        RESULTS.append((name, wrapper))
        return fn
    return deco


def _src(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _load(src, tag, rel):
    """把（可能被变异过的）源码在**内存**里加载成模块（磁盘一字节不动）。

    ★★ 为什么按文件加载而不是 import：负控要测的是**变异后的这份源码**。
       若走 `import`，变异版与真仓模块同名，Python 会返回已加载的真身
       —— 量具就测错了对象（regression_gate D-27 同款事故的根因）。
    """
    import types
    mod = types.ModuleType(tag)
    mod.__file__ = os.path.join(ROOT, rel)
    sys.modules[tag] = mod
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)          # noqa: S102
    return mod


def _ago(hours=1.0):
    """相对现在的 ISO 时点 —— **不许写死日期**（0470 0.48.4 时间炸弹教训）。"""
    return (datetime.now().astimezone() - timedelta(hours=hours)).replace(
        microsecond=0).isoformat()


#: 姿态一律显式注入：守卫不许依赖真实中枢的当前 posture（否则判据时红时绿）。
_POSTURE = {"state": "guarding", "label": "值守中", "why": "在岗"}


def _mk(level="R0", state="unread", i=0, hours_ago=1.0,
        kind="host_shield_breach"):
    """夹具：一条记录。**kind 决定分档**（AUTO_HANDLED_KINDS 之外的进要处理）。"""
    a = M.Alert(id="u0490_%s_%d" % (level, i), ts=_ago(hours_ago),
                level=level, kind=kind, title="t")
    return M.Item(alert=a, state=state)


def _items():
    """混合夹具：三个档位都有数，且「要处理」是**件事**（≠记录条数）。

    action  ＝ 2 件 / 3 条（两条同因 breach 合成一件 ＋ 一条 tamper）
    info    ＝ 2 条（tool_call_blocked，Antinel 已自己拦下）
    archive ＝ 1 条（30 小时前的无后果记录，滑出 24h 窗口）
    all     ＝ 6 条
    """
    return [
        _mk("R0", "unread", 1, 1.0),                    # 要处理（件事 A）
        _mk("R0", "unread", 2, 2.0),                    # 要处理（件事 A，同因）
        _mk("R0", "unread", 3, 1.5, kind="host_shield_tamper"),   # 件事 B
        _mk("L2", "unread", 4, 1.0, kind="tool_call_blocked"),
        _mk("L2", "unread", 5, 3.0, kind="tool_call_blocked"),
        _mk("L1", "unread", 6, 30.0, kind="host_shield_changed"),
    ]


#: 合成日报数据（0353 同款形状；账本页要读 `ledger` 键，一并给全）
_REP = {
    "day": "2026-10-06", "levels": {"R0": 1, "L2": 2, "L1": 3, "Ls": 0},
    "window_levels": {"R0": 1, "L2": 2, "L1": 3, "Ls": 0}, "window_hours": 24,
    "buckets": {"action": 2, "info": 2, "archive": 1},
    "action_groups": 2, "revived_window": 0,
    "posture": dict(_POSTURE),
    "rules": [{"rule_id": "DST-01", "count": 2}],
    "chain": {"status": "ok", "files": 1, "records": 2, "broken": 0,
              "unchained": 0, "reason": ""},
    "ledger": {"days": 0, "streak_days": 0, "blocked": 0, "noticed": 0,
               "breached": 0, "acked": 0},
}

_VIEWS = ("inbox", "report", "health", "ledger")
_TABS = (M.BUCKET_ACTION, M.BUCKET_INFO, M.BUCKET_ARCHIVE, "all")


def _page(view, filt=None, mod=SV, items=None, rep=None):
    """渲染一整页（items/rep/posture 全注入，不依赖真实中枢与真实时间）。"""
    return mod.render_page(view=view, filt=filt,
                           root=tempfile.mkdtemp(prefix="g0490_r_"),
                           token="T", items=_items() if items is None else items,
                           rep=_REP if rep is None else rep,
                           posture=_POSTURE)


#: 术语浮层（`<details class=term|gloss>` … `</details>`，含乙1 的 `term mk`）。
#: 为什么能非贪婪：`glossary.render()` 只放行 b/code 两个内联标签
#: （见该函数 docstring），块内不会嵌套第二个 details。
#: ★ 0.48.5 乙1 起 class 值有 `term mk` 形态（裸「？」芯片）—— 判据只认
#:   精确 `class="term"` 会漏剥整族芯片（首跑实测：U-03 因此误红，
#:   芯片展开体口径行里的「分母」漏出了剥离层）。
_TERM_BLOCK = re.compile(
    r'<details class="[^"]*\b(?:term|gloss)\b[^"]*"[^>]*>.*?</details>', re.S)


def _body_without_terms(html):
    """剥掉术语浮层后的**正文**（丙2 的口径：「分母」只许留在词条口径行里）。"""
    return _TERM_BLOCK.sub("", html or "")


def _tabs(page):
    """筛选条四个 tab 的 [(值, 可见文本, title 属性)] —— 可见文本＝剥标签后。

    ★ 0.48.5 乙1 起不能再用 `<div class="filters">…</div>` 圈定范围：
      芯片（`details.tdef`）里带 `</div>`，非贪婪匹配会被它截断
      （首跑实测：tab 数从 4 掉成 1）。⇒ 改按**行为特征**找 tab：
      四个筛选标签就是页面上 title 以「单位：」开头的那几个链接
      （芯片是 details 不是链接，天然不在候选里）。
    """
    out = []
    for attrs, inner in re.findall(r"<a ([^>]*)>(.*?)</a>", page, re.S):
        tip = re.search(r'title="(单位：[^"]*)"', attrs)
        if not tip:
            continue
        f = re.search(r'[?&]f=([^&"]+)', attrs)
        if not f:
            continue
        out.append((f.group(1),
                    re.sub(r"<[^>]+>", "", inner),
                    tip.group(1)))
    return out


def _note_calls(src):
    """数**真实调用点**（不是注释里的字面）。

    ★ 判据先自证：`M.reading_note()` 这八个字在注释里也会出现（解释改动的
      来龙去脉本来就要写清）—— 数源码文本会把注释算成调用点（首跑实测：
      2 次调用 ＋ 2 处注释 ＝ 4）。⇒ 只数调用语法：`M.reading_note()` 后面
      紧跟 ASCII 右括号（`_esc(...)` 的收尾），注释里是全角「）」，天然区分。
    """
    return len(re.findall(r"M\.reading_note\(\)\)", src or ""))


# ════════════════════════════ U-01 · 甲2（＋甲3 并入）════════════════
@check("U-01 ★ 甲2：读数口径不承诺活的（新措辞在位；分钟前/分母均为 零出现）")
def u01():
    """甲2：「最近 24 小时」窗口冻结，不随时间滚动 —— 页面却把它说成活的。

    v1.1 定性（§5.3）：**措辞降级，不本版加自动刷新**（常驻页自动重渲染会打断
    阅读：展开的词条被打收、滚动位置丢失 —— 那是增加处理，不是减少）。
    新措辞走唯一实现 `M.reading_note()`，两个调用点同源（维一）。
    甲3（Web 页无陈旧守卫）**并入本判据**：本版不建陈旧守卫；若将来做刷新，
    陈旧守卫与刷新同一批做（§5.3）。

    断言面：四页 ＋ 收件箱各 tab 的**渲染产物**（不打行号、不打函数名）。
    """
    src = _src(_SERVER_REL)
    # ① 入口唯一（维一）：两个调用点都走 reading_note；旧名零残留
    if _note_calls(src) != 2:
        return "inbox_server 里 reading_note 真实调用点 = %d，应为 2（两处同源）" \
            % _note_calls(src)
    if "window_note" in src:
        return "inbox_server 里仍有 window_note 残留（入口唯一性破裂）"
    if hasattr(M, "window_note"):
        return "inbox_model 里 window_note 仍在（旧措辞的实现没删，会被复用）"
    # ② 渲染面：四页 + 各 tab 都不含旧承诺；note 页含新措辞
    for view in _VIEWS:
        page = _page(view)
        for bad in ("分钟前", "分母均为"):
            if bad in page:
                return "%s 页仍含 %r（承诺维持不住的口径／冻结读数）" % (view, bad)
    for tab in _TABS:
        page = _page("inbox", filt=tab)
        if "不随页面停留刷新" not in page:
            return "收件箱 tab=%s 缺新措辞「不随页面停留刷新」" % tab
        if M.reading_note() not in page:
            return "收件箱 tab=%s 的口径行 ≠ M.reading_note()（唯一实现漂移）" % tab
    page = _page("report")
    if "不随页面停留刷新" not in page:
        return "日报页缺新措辞（第二处调用点没接上）"
    return True


@check("N-U01 负控：调用点改回旧串／函数改回旧串 ⇒ U-01 必须红")
def n_u01():
    """反向对照（维二）：两个层面各注入一次「旧措辞回潮」。

    ① 调用点层面：把筛选条那行改回旧内联串 ⇒ 只 U-01 红
       （日报页不受影响 —— 专打第一个调用点）；
    ② 函数层面：`M.reading_note()` 返回旧串 ⇒ U-01 红。
       ★ 同源连坐（如实登记）：这会**同时**打红 U-03 —— 两处调用点同一个
       实现，改源必然两头生效，这正是维一要的「同源」，不是负控失准。
    ③ 连回正判据（夹具不成立即负控失效）：真实现下新措辞必须在场。
    """
    src = _src(_SERVER_REL)
    anchor = ('            + ("<div class=\\"note\\" style=\\"margin:0 0 8px\\">%s</div>"\n'
              '               % _esc(M.reading_note()))')
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(
        anchor,
        '            + ("<div class=\\"note\\" style=\\"margin:0 0 8px\\">%s</div>"\n'
        '               % _esc("最近 %d 小时 · 以上数字的分母均为本次载入的 %d 条记录"\n'
        '                      % (M.WINDOW_HOURS, n_all)))'),
        "is0490_nu01", _SERVER_REL)
    page = mut.render_page(view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu01_"),
                           token="T", items=_items(), posture=_POSTURE)
    if "不随页面停留刷新" in page:
        return "负控失效：调用点改回旧串后新措辞仍在（%r）" % page[:80]
    if "分母均为" not in page:
        return "负控失效：旧串没渲染出来（注入没生效）"
    # ③ 连回正判据：真实现下必须含新措辞、且不含旧串
    live = _page("inbox", filt=M.BUCKET_ACTION)
    if "不随页面停留刷新" not in live or "分母均为" in live:
        return "夹具不成立：真实现本身就不满足 U-01 ⇒ 负控无分辨力"
    return True


# ════════════════════════════ U-03 · 甲4（＋丙2 并入）════════════════
_NOTE_CALL_SERVER = ('            + ("<div class=\\"note\\" style=\\"margin:0 0 8px\\">'
                     '%s</div>"\n'
                     '               % _esc(M.reading_note()))')
_NOTE_CALL_REPORT = ('    _win_note = ("<div class=\\"note\\" style=\\"margin:0 0 8px'
                     '\\">%s</div>"\n'
                     '                 % _esc(M.reading_note()))')


@check("U-03 ★ 甲4：口径说明两处同源；正文零「分母」；每 tab 可见单位（丙2 并入）")
def u03():
    """甲4：旧说明「以上数字的分母均为本次载入的 N 条记录」对四个 tab 至少
    三个是假的（要处理＝件事、归档＝无时间上限，glossary 自述四个分母不同），
    且日报页另有第二份内联说明不走唯一实现（919-921，维一）。

    丙2 并入：「分母」二字在**正文渲染**里零出现 —— 它只留在术语词条的
    口径行里（那才是它的定义处，TERMS 的 unit 字段明写「分母＝…」）。
    """
    src = _src(_SERVER_REL)
    # ① 两处调用点同源（维一）：note 的真实调用＝2，且日报页不再有内联旧句
    if _note_calls(src) != 2:
        return "reading_note 真实调用点 = %d，应为 2（筛选条 ＋ 日报页同源）" \
            % _note_calls(src)
    if "以下数字的分母均为窗口内" in src:
        return "日报页仍有内联口径说明（第二处实现，维一破裂）"
    note = M.reading_note()
    rep_page = _page("report")
    if note not in rep_page:
        return "日报页口径行 ≠ M.reading_note()（两处不同源）"
    # ② 正文零「分母」（剥术语浮层后；定义处不许被禁）
    for view in _VIEWS:
        body = _body_without_terms(_page(view))
        if "分母" in body:
            return "%s 页正文仍出现「分母」（丙2：只许留在术语词条口径行）" % view
    # ③ 每 tab 带可见单位（件/条）—— 丙1 的甲4 侧面
    want = {M.BUCKET_ACTION: "件", M.BUCKET_INFO: "条",
            M.BUCKET_ARCHIVE: "条", "all": "条"}
    tabs = {v: (vis, tip) for v, vis, tip in _tabs(_page("inbox"))}
    for v, unit in want.items():
        if v not in tabs:
            return "筛选条缺 tab=%s" % v
        vis, _tip = tabs[v]
        if not vis.rstrip().endswith(unit):
            return "tab=%s 的可见文本 %r 不带可见单位 %r（ hover 里的字不算）" % (
                v, vis, unit)
    return True


@check("N-U03a 负控：日报页说明行改回内联旧串 ⇒ 只 U-03 红（专打第二调用点）")
def n_u03a():
    """反向对照（维二）：把 919-921 那处改回旧内联写法。

    ★ 这一条**专打维一**：旧缺陷的形状正是「第二处调用点不走唯一实现」。
      注入后筛选条不受影响（U-01 仍绿），只有 U-03 红 —— 精确归因。
    """
    src = _src(_SERVER_REL)
    if _NOTE_CALL_REPORT not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(_NOTE_CALL_REPORT,
                            '    _win_note = ("<div class=\\"note\\" style=\\"margin:0 0 8px\\">'
                            '%s</div>"\n'
                            '                 % _esc("最近 %d 小时 · 以下数字的分母均为窗口内的 '
                            '%d 条记录"\n'
                            '                        % (hrs, _win_total)))'),
                "is0490_nu03a", _SERVER_REL)
    page = mut.render_page(view="report",
                           root=tempfile.mkdtemp(prefix="g0490_nu03a_"),
                           token="T", items=_items(), rep=_REP,
                           posture=_POSTURE)
    if M.reading_note() in page and "分母均为" not in _body_without_terms(page):
        return "负控失效：改回旧串后日报页仍同源且无「分母」"
    if "分母" not in _body_without_terms(page):
        return "负控失效：旧内联串没渲染出来（注入没生效）"
    # 连回正判据：真实现下日报页必须同源且正文无「分母」
    live = _page("report")
    if M.reading_note() not in live or "分母" in _body_without_terms(live):
        return "夹具不成立：真实现本身就不满足 U-03 ⇒ 负控无分辨力"
    return True


@check("N-U03b 负控：当日行「共 N 条」改回「分母 N」⇒ U-03② 必须红")
def n_u03b():
    """反向对照（维二）：丙2 的字面禁现注入（日报当日行 956 那处）。"""
    src = _src(_SERVER_REL)
    anchor = '" ｜ 共 %d 条"'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, '" ｜ 分母 %d"'),
                "is0490_nu03b", _SERVER_REL)
    page = mut.render_page(view="report",
                           root=tempfile.mkdtemp(prefix="g0490_nu03b_"),
                           token="T", items=_items(), rep=_REP,
                           posture=_POSTURE)
    if "分母" not in _body_without_terms(page):
        return "负控失效：写回「分母」后正文仍零出现（注入没生效）"
    return True


# ════════════════════════════ U-08 · 丙1（可见单位）═══════════════════
@check("U-08 ★ 丙1：筛选条单位**可见**（件/条在可见文本里，不止 hover title）")
def u08():
    """丙1：筛选条「要处理」＝件事、其余＝条记录，并排无可见标识
    （单位只在 hover title 里，鼠标不在上面就看不见）—— 读者会拿
    1+82+712 直接比大小，那是**异质单位做比较**（F54 同型）。
    核验日实测：真实差 1（要处理实为 2 条、按事由归并显示 1）。
    ★ 注意：这不是算错，是单位异质被并排。

    判据打在**可见文本**上：剥掉标签后仍能读到「件」与「条」——
    title 属性里的字随标签一起被剥掉，天然区分「可见」与「hover 才有」。
    """
    tabs = _tabs(_page("inbox"))
    if len(tabs) != 4:
        return "筛选条 tab 数 = %d，应为 4" % len(tabs)
    vis_all = "".join(v for _f, v, _t in tabs)
    if "件" not in vis_all or "条" not in vis_all:
        return "可见文本里缺「件」或「条」（单位还只住在 hover title 里）"
    # hover 口径行保留（丙1 是「可见化」不是「搬走」—— 每个 tab 的 title
    # 仍带它的单位说明；_tabs 只收 title 以「单位：」开头的链接，这条断言
    # 因此按 tab 核具体词：要处理说「件事」，其余说「条记录」）。
    want_tip = {M.BUCKET_ACTION: "件事", M.BUCKET_INFO: "条记录",
                M.BUCKET_ARCHIVE: "条记录", "all": "条记录"}
    for v, vis, tip in tabs:
        if want_tip[v] not in tip:
            return "tab=%s 的 hover 口径行缺 %r（丙1：hover 保留，不是搬走）" % (
                v, want_tip[v])
    # ① 数出来的事由件数必须真的 ≠ 记录条数（夹具要能暴露单位混谈）
    items = _items()
    n_act = M.count_groups(M.filter_items(items, M.BUCKET_ACTION))
    if n_act == len(M.filter_items(items, M.BUCKET_ACTION)):
        return "夹具失效：件事数 == 记录条数，本判据失去分辨力"
    return True


@check("N-U08 负控：删掉可见单位（退回只放 title）⇒ U-08 必须红")
def n_u08():
    """反向对照（维二）：把单位 span 从筛选条删掉 —— 正是丙1 描述的旧形状。"""
    src = _src(_SERVER_REL)
    anchor = ('                "<span class=\\"unit\\">%s</span></a>"\n'
              '                % (v, _esc(token), cls, _esc(tip), _esc(label), n, _esc(unit)))')
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor,
                            '                "</a>"\n'
                            '                % (v, _esc(token), cls, _esc(tip), _esc(label), n))'),
                "is0490_nu08", _SERVER_REL)
    page = mut.render_page(view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu08_"),
                           token="T", items=_items(), posture=_POSTURE)
    vis = "".join(v for _f, v, _t in _tabs(page))
    if "件" in vis or "条" in vis:
        return "负控失效：删掉单位 span 后可见文本仍带单位"
    # 连回正判据：真实现下单位必须可见
    live = "".join(v for _f, v, _t in _tabs(_page("inbox")))
    if "件" not in live or "条" not in live:
        return "夹具不成立：真实现本身单位就不可见 ⇒ 负控无分辨力"
    return True


# ════════════════════ U-97 · 连带对照（维四：既有保护一条都不许松）════════
@check("U-97 ★ 连带对照：分母纪律／术语表／页面名／认窗基线 全部仍绿")
def u97():
    """本批动的是「口径说明」与「单位可见化」—— 改前先问：哪条既有保证会松？

    ① 0.47.0 步三的**分母纪律**不因换措辞而松：`count_text` 仍带分母与窗口
       （顶部条钻取后缀、日报 `/ N`、托盘 tip 都走它）；
    ② 丙2 只禁**正文**，术语词条口径行里的「分母」是定义处，必须仍在
       （否则用户点开「？」也看不到口径 —— 那是把定义一起删了）；
    ③ `PAGE_TITLES` 四键不动（0360 硬锁的基线；W-01 批次才会动标题）；
    ④ 认窗基线：四个页面名标题仍认得出（W-01 批次要动白名单，先留底）；
    ⑤ 渲染页无未登记术语（`GL.unknown` 零命中）。
    """
    # ① 分母纪律：count_text 格式仍在（钻取后缀的分母不丢）
    ct = M.count_text(3, 128)
    if "/ 128" not in ct or "最近 %d 小时" % M.WINDOW_HOURS not in ct:
        return "count_text 丢了分母/窗口：%r" % ct
    bar = SV._bar(_items(), "T", posture=_POSTURE, view="report")
    if M.count_text(2, 6) not in bar:
        return "顶部条钻取后缀不带分母（0.47.0 步三回潮）"
    # ② 术语表的定义处仍在（丙2 不禁定义）。
    #   ★ 只对 action/info/all 三个断言「分母」—— archive 的口径行写的是
    #     「没有时间上限，但受现在还读得到的文件限制」（glossary 原文），
    #     本就不含「分母」二字，不把它算进来（判据先自证事实，再断言）。
    for k in ("action", "info", "all"):
        if "分母" not in GL.TERMS[k]["unit"]:
            return "术语 %s 的口径行丢了「分母」（定义被误删）" % k
    if "没有时间上限" not in GL.TERMS["archive"]["unit"]:
        return "术语 archive 的口径行被改动（它的分母事实是「没有时间上限」）"
    # ③ 页面名四键
    if set(SV.PAGE_TITLES) != {"inbox", "report", "health", "ledger"}:
        return "PAGE_TITLES 四键被改动：%r" % (sorted(SV.PAGE_TITLES),)
    # ④ 认窗基线（0360 的真实判定，不在这里二次实现）
    import inbox_window as IW
    if not IW.is_console_title("收件箱 · 值守台#abc123", "abc123"):
        return "页面名标题认不出了（认窗基线被破坏）"
    if IW.is_console_title("请给我一个 · 值守台#a8276c", "a8276c"):
        return "用户窗口形状被误认（G-05 红线）"
    # ⑤ 无未登记术语
    for view in _VIEWS:
        unk = GL.unknown(_page(view))
        if unk:
            return "%s 页有未登记术语：%r" % (view, unk)
    return True


# ════════════════════════════ U-10 · 丁2/丁3（who 块删、口号变证据）═════
@check("U-10 ★ 丁2/丁3：who 块零出现（四页）；运行状态页有回环证据行")
def u10():
    """丁2：「本机 · 127.0.0.1」零信息量（回环地址每台机器一样）；
    丁3：「数据不出门」是定位宣言混进状态栏 —— 口号不是证据。

    v1.1 定性：删除，且**不是一删了之** —— 它承诺的事实搬进运行状态页作
    证据（「监听地址：仅本机回环——服务不接受外部连接」），而那句证据由
    `_check_bind` 的硬校验背书（非回环直接抛错）。判据同时断言三件事：
    删干净、证据在、后盾真（行为级，不只查文案）。
    """
    for view in _VIEWS:
        page = _page(view)
        for bad in ("本机 · 127.0.0.1", "数据不出门"):
            if bad in page:
                return "%s 页仍含 %r（丁2/丁3：零信息量块没删干净）" % (view, bad)
    health = _page("health")
    for want in ("仅本机回环", "服务不接受外部连接"):
        if want not in health:
            return "运行状态页缺回环证据 %r（口号删了，证据没补上）" % want
    # 后盾（行为级）：非回环地址不许起服务 —— 证据行这句话有人兑底
    try:
        SV._check_bind("0.0.0.0")
        return "_check_bind 放行了 0.0.0.0 ⇒「仅本机回环」这句证据是空的"
    except Exception:                                         # noqa: BLE001
        pass
    return True


@check("N-U10 负控：who 块加回顶部条 ⇒ U-10 必须红")
def n_u10():
    """反向对照（维二）：把删掉的 who 块原样加回 _bar 的返回串。"""
    src = _src(_SERVER_REL)
    anchor = '        "%s%s<div class=\\"spacer\\"></div></header>"'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(
        anchor,
        '        "%s%s<div class=\\"spacer\\"></div>"\n'
        '        "<div class=\\"who\\">本机 · 127.0.0.1<br>数据不出门</div></header>"'),
        "is0490_nu10", _SERVER_REL)
    page = mut.render_page(view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu10_"),
                           token="T", items=_items(), posture=_POSTURE)
    if "本机 · 127.0.0.1" not in page:
        return "负控失效：who 块加回后页面仍不含它（注入没生效）"
    live = _page("inbox", filt=M.BUCKET_ACTION)
    if "本机 · 127.0.0.1" in live:
        return "夹具不成立：真实现本身还带 who 块 ⇒ 负控无分辨力"
    return True


# ════════════════════════════ U-11 · 丁4（title 收缩到 ≤20 字）════════
@check("U-11 ★ 丁4：收件箱页全部 title 属性 ≤ 20 字（工程说明归词条）")
def u11():
    """丁4：药丸 title 塞 40+ 字工程说明（「括号里是按事由归并后的件数，
    点进去看全部明细」）—— hover 是消歧用的，不是说明书。
    判据锁**全部** title 属性（不只是药丸那一处）：锁一处就会在别处复发。
    解释移交「？」词条（U-04，批次 3）后信息不丢失。

    ★ 计数口径：`len()` 原文长度，**空格也算** —— 文档目标串「最近 24 小时
      的记录数（自本次载入起算）」脚本点数 21 字，超自己的 ≤20 限，
      同义收作「自载入起算」（19 字）才落地。数字必须脚本点数，不许心算。
    """
    page = _page("inbox")
    titles = re.findall(r'title="([^"]*)"', page)
    if not titles:
        return "一个 title 都没抽到 —— 正则坏了（量具自失效）"
    for t in titles:
        if len(t) > 20:
            return "title 超 20 字（%d 字）：%r" % (len(t), t)
    return True


@check("N-U11 负控：40 字工程串加回药丸 title ⇒ U-11 必须红")
def n_u11():
    """反向对照（维二）：把丁4 描述的那个 40+ 字工程 title 原样加回。"""
    src = _src(_SERVER_REL)
    anchor = ('        return ("<a title=\\"最近 %d 小时的记录数（自载入起算）\\" "')
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(
        anchor,
        '        return ("<a title=\\"最近 %d 小时的记录数；括号里是按事由归并后的件数，'
        '点进去看全部明细\\" "'),
        "is0490_nu11", _SERVER_REL)
    page = mut.render_page(view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu11_"),
                           token="T", items=_items(), posture=_POSTURE)
    if not any(len(t) > 20 for t in re.findall(r'title="([^"]*)"', page)):
        return "负控失效：加回 40 字串后全部 title 仍 ≤20（注入没生效）"
    live_titles = re.findall(r'title="([^"]*)"', _page("inbox"))
    if any(len(t) > 20 for t in live_titles):
        return "夹具不成立：真实现本身就有 >20 字的 title ⇒ 负控无分辨力"
    return True


#: §5.6 乙2 定稿的六串全集（U-05 的断言集；批次 2 先落两族，批次 3 补齐）
_U05_OLD = ("点开查看", "点开看每一次", "点规则名看具体是哪几条",
            "点开可整组处置", "点进去看全部明细", "点一类看单条")


# ════════════════════════════ U-05 · 丁5（删替用户描述动作的句子）══════
@check("U-05 ★ 丁5：渲染页零「点开看每一次」「点规则名看具体是哪几条」")
def u05():
    """丁5：「（点开看每一次）」类句子**替用户描述他即将做的动作** ——
    链接的可点性由下划线承担（CSS 已有），写出来是重复用户的动作
    （W08 判据立意，0.37.2 删过同型句，本次 rules/revived 两族复发）。
    ★ 断言集＝§5.6 乙2 定稿的**六串全集**（丁5 批次先落两族，乙2 批次 3
      补齐）：点开查看 / 点开看每一次 / 点规则名看具体是哪几条 /
      点开可整组处置 / 点进去看全部明细 / 点一类看单条。
      其中「点开可整组处置」已按能力句改写为「可整组一次性处置」——
      能力保留（整组处置），动作描述词删（W08）。
    """
    for view in ("report", "health", "inbox"):
        page = _page(view)
        for bad in _U05_OLD:
            if bad in page:
                return "%s 页仍含 %r（替用户描述他的动作）" % (view, bad)
    return True


@check("N-U05 负控：「（点开看每一次）」加回 ⇒ U-05 必须红")
def n_u05():
    """反向对照（维二）：把丁5 删掉的句子原样加回日报页调用点。"""
    src = _src(_SERVER_REL)
    anchor = ('                     "%d 次</a> / %d"\n'
              '                     % (hrs, _esc(token), _revived, _win_total))')
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(
        anchor,
        '                     "%d 次</a> / %d（点开看每一次）"\n'
        '                     % (hrs, _esc(token), _revived, _win_total))'),
        "is0490_nu05", _SERVER_REL)
    page = mut.render_page(view="report",
                           root=tempfile.mkdtemp(prefix="g0490_nu05_"),
                           token="T", items=_items(), rep=_REP,
                           posture=_POSTURE)
    if "点开看每一次" not in page:
        return "负控失效：加回后渲染页仍不含（注入没生效）"
    live = _page("report")
    if "点开看每一次" in live or "点规则名看具体是哪几条" in live:
        return "夹具不成立：真实现本身还带旧句 ⇒ 负控无分辨力"
    return True


# ════════════════════════════ U-04 · 乙1（铺「？」芯片，8 个落点）════════
@check("U-04 ★ 乙1：8 个裸「？」芯片落位（筛选条4 + 药丸3 + 顶部灯1）")
def u04():
    """乙1：日报页每个重要词都可点开看定义，收件箱页却一个「？」都没有
    （实测 term 芯片数 0）—— 同一个词两个页面两种待遇。

    形态（§5.6 定稿）：芯片作**兄弟节点**紧贴链接之后，**不嵌套**
    （`<a>` 内嵌 interactive 内容是坏味道）；summary 只有一个「？」
    （`.term.mk` 关掉 ::after 徽章防「？？」）；词本名进展开体首行。
    词条清单 8 个：筛选条 action/info/archive/all（4）＋ 药丸 R0/L2/L1（3）
    ＋ 顶部灯 light（1）。词条文字一律不动（0380 S17 钉死，只加落点）。
    """
    page = _page("inbox")
    chips = re.findall(r'<details class="term mk" data-t="([^"]+)"', page)
    want = {"action", "info", "archive", "all", "R0", "L2", "L1", "light"}
    if set(chips) != want:
        return "mk 芯片集合 ≠ 8 词条：实到 %r" % (sorted(set(chips)),)
    if len(chips) != 8:
        return "mk 芯片数 = %d，应为 8（有重复落点）" % len(chips)
    # ① summary 只能是「？」一个（「？？」＝ CSS 没关干净）
    if not re.search(r'<summary>？</summary>', page):
        return "mk 芯片的 summary 不是单个「？」（防止「？？」失败）"
    # ② 芯片不许被塞进链接里（兄弟节点，不是嵌套）
    for m in re.finditer(r"<a [^>]*>(.*?)</a>", page, re.S):
        if "<details" in m.group(1):
            return "芯片嵌套在 <a> 里（链接内嵌 interactive 是坏味道）"
    # ③ 展开体首行带词本名（复用 head 机制，不另写一套）
    for key in want:
        if ('data-t="%s"><summary>？</summary><div class="tdef"><b>' % key) \
                not in page:
            return "芯片 %s 的展开体首行缺词本名（head 机制没接上）" % key
    # ④ 未登记术语零命中（rendered 自动覆盖新芯片）
    if GL.unknown(page):
        return "页面有未登记术语：%r" % (GL.unknown(page),)
    return True


@check("N-U04 负控：摘掉顶部灯那颗芯片 ⇒ U-04 必须红")
def n_u04():
    """反向对照（维二）：8 个落点里摘掉一个 —— 精确集合立刻不满。"""
    src = _src(_SERVER_REL)
    anchor = 'label, GL.chip("light", mk=True), suffix,'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, 'label, "", suffix,'),
                "is0490_nu04", _SERVER_REL)
    page = mut.render_page(view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu04_"),
                           token="T", items=_items(), posture=_POSTURE)
    if "light" in re.findall(r'<details class="term mk" data-t="([^"]+)"',
                             page):
        return "负控失效：摘掉 light 芯片后它仍在（注入没生效）"
    live = re.findall(r'<details class="term mk" data-t="([^"]+)"',
                      _page("inbox"))
    if len(live) != 8:
        return "夹具不成立：真实现本身就不是 8 个芯片 ⇒ 负控无分辨力"
    return True


# ════════════════════════════ U-06 · 乙3（收件箱页补 h2）═══════════════
@check("U-06 ★ 乙3：收件箱页有 <h2>，文本 == PAGE_TITLES[\"inbox\"]（唯一真源）")
def u06():
    """乙3：收件箱页无 `<h2>` 页面名，其余三页都有 —— 同一页三个身份
    （title「收件箱 · 值守台#hash」/ 选项卡「收件箱」/ 无 h2）。
    文案取 `PAGE_TITLES`（唯一真源，0360:741 硬锁四键 —— 加了状态词那种
    字段立刻红，所以这里只许读它，不许另写）。"""
    page = _page("inbox")
    heads = re.findall(r"<h2>([^<]*)</h2>", page)
    if not heads:
        return "收件箱页没有 <h2>"
    if heads[0] != SV.PAGE_TITLES["inbox"]:
        return "h2 文本 %r ≠ PAGE_TITLES[\"inbox\"]=%r（不许另写一份）" % (
            heads[0], SV.PAGE_TITLES["inbox"])
    if len(heads) != 1:
        return "h2 出现 %d 次（页面名只许一处）" % len(heads)
    return True


@check("N-U06 负控：删掉收件箱页 h2 ⇒ U-06 必须红")
def n_u06():
    """反向对照（维二）：把刚补的 h2 删回去。"""
    src = _src(_SERVER_REL)
    anchor = "    head = ('<h2>%s</h2>' % PAGE_TITLES[\"inbox\"]\n"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, "    head = (\"\"\n"),
                "is0490_nu06", _SERVER_REL)
    page = mut.render_page(view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu06_"),
                           token="T", items=_items(), posture=_POSTURE)
    if re.findall(r"<h2>([^<]*)</h2>", page):
        return "负控失效：删掉 h2 后页面仍有 h2（注入没生效）"
    live = re.findall(r"<h2>([^<]*)</h2>", _page("inbox"))
    if not live or live[0] != SV.PAGE_TITLES["inbox"]:
        return "夹具不成立：真实现本身就没有合规 h2 ⇒ 负控无分辨力"
    return True


def main():
    print("=" * 78)
    print("0.48.5 值守台细节修订判据（交接件 v1.1 §5.7）—— 批次 1：U-01/U-03/U-08")
    print("（变异只在内存，账本与链只落临时目录，不写任何产品文件）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                why = ""
            print("  ✅ %-64s %s" % (name, why or ""))
            ok += 1
        except AssertionError as e:
            print("  ❌ %-64s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-64s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
