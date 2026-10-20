#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.48.5 Antinel 监理细节修订判据（交接件 v1.1 §5.7）—— 编号 U-01…U-15。

★★ 由来：交接件 v1.1（2026-10-12）§5.2 的 19 条产品修订，逐条四件套
   （正判据／反向对照／连带对照／可观测）。本文件是它们的**判据落点**
   （与 0360/0372/0380/0470 同型），**按批次生长**：

     批次 1（甲2/甲3/甲4 ＋ 丙1/丙2）→ U-01 / U-03 / U-08（已落地，commit 049fc7c）
     批次 2（丁2/丁3/丁4/丁5）        → U-10 / U-11 / U-05（已落地，commit 9337bc4）
     批次 3（乙1~乙4）                → U-04 / U-06（已落地，commit 264c67b）
     批次 4（戊1/戊2/戊4 ＋ 戊3 重排）→ U-13 / U-15（已落地，commit 461b4ef）
     批次 5（W-01 ＋ W-02 边界项）    → W-01 / W-02（本 commit —— 认窗白名单
                                        单独提交，可单独回滚；G-05 锚点未动）
     批次 6（W-03 · 遗留问题 A2）     → W-03（托盘与 Web 状态词同源）
     批次 7（W-04 · 遗留问题 B1）     → W-04（Antinel 监理常驻：同端口/口令自恢复）
     批次 8（W-05 · 遗留问题 B2）     → W-05（端口漂移不再静默：出声＋落盘＋托盘带端口）
     批次 9（W-06 · 遗留问题 B3）     → W-06（口令不进 URL：HttpOnly cookie ＋ 链接零 t=）
     批次 10（C1 · 负控模板化）        → C-01（渲染型负控走 `_mut_render` 两步法）
     批次 11（C2 · 判据扫渲染产物）    → 统一口径 `ci/page_caliber.py`（本批**不含新判据**：
                                        它是「编写纪律」的机制化，由元判据 **S48**
                                        在 `ci/guard_instrument_selfaudit.py` 里守）
     批次 12（C5 问号同形 ＋ C4 落位） → **U-16**（问号全站同形：字隐藏、徽章保留）＋
                                        **W-07**（一次性调用方自己等窗就位，真进程实测）
     批次 15（0.51.0 账本四问）        → **T-04 / T-04b / T-04c**（＋ 三条负控）：
                                        账本按天明细（银行流水模式）—— 最近 7 天＋
                                        按月折叠、无记录天不许渲染成 0、`closed:<日期>`
                                        按关闭日收件（账准侧判据在 0353）

   ★ 批次 12 两条都是**存量/本轮自查缺陷**，不是 19 条里的新项：
     · C4：`_place_if_needed` 的 daemon 线程随一次性进程死 ⇒ 落位从未执行
           且无任何输出（T-10 静默降级；根因提交 `aa3eeff` 0.36.8，非本轮引入）。
     · C5：0.48.5 乙1（`264c67b`）**本轮自己引入** —— 实现比交接件 §5.6 定稿
           多做一步（关掉 ::after 徽章），8 个新落点退化成裸文字「？」。

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
import json
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
import page_caliber as PC                                        # noqa: E402

RESULTS = []

_SERVER_REL = "inbox_server.py"
_MODEL_REL = "inbox_model.py"
_WINDOW_REL = "inbox_window.py"


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


_G15_CACHE = []


def _g15():
    """共享尺子（品牌哨点/ico 结构）—— **只此一份**，从 0515 import。

    ★ 为什么不在本文件再写一段 circle 解析：品牌哨点这条事实**已有一处实现**
      （`ci/inbox_guards_0515.py` 的 `_svg_dot`/`_ico_judge`，FZ-005 冻结执法
      也 import 它）。同一个事实写两份＝迟早不一致，而不一致时往往两份都判绿
      —— 那正是「判据看着很多、缺陷照样复发」的由来。
    """
    if _G15_CACHE:
        return _G15_CACHE[0]
    try:
        import inbox_guards_0515 as G15                             # noqa: E402
    except Exception:                                               # noqa: BLE001
        import importlib.util as _ilu
        _p = os.path.join(ROOT, "ci", "inbox_guards_0515.py")
        _spec = _ilu.spec_from_file_location("inbox_guards_0515", _p)
        G15 = _ilu.module_from_spec(_spec)
        sys.modules.setdefault("inbox_guards_0515", G15)
        _spec.loader.exec_module(G15)
    _G15_CACHE.append(G15)
    return G15


def _mut_render(src_mutated, tag, rel, **kw):
    """C1 两步法 · **第一步**：变异模块必须「**能 import ＋ 最小渲染不抛**」。

    返回 `(page, None)`；任一步抛异常 ⇒ `(None, 说明串)`，调用方**必须**
    `if _why: return _why` —— 那是**量具故障**（变异写坏了源码／少给了参数），
    **不是产品问题**，也**不算通过**。

    ★★ 要防的复发（C1 交接件 §C1，本轮实测）：
      N-U13 首跑 💥 —— 把头部 mp4 形态加回时 `args` 少给一个 `M.STATE_VAR[st]`，
      变异渲染抛 `TypeError: not enough arguments for format string`。
      负控的职责是「证明**正判据**会红」，结果它**自己先崩了** ⇒
      **量具故障伪装成了产品问题**（而人得读 traceback 才分辨得出）。
      ⇒ 模板化成两步：① 这一步（能 import ＋ 最小渲染不抛）；
        ② 行为断言（变异可观测 ＋ 真实现不带该形状）。两步都绿，负控才算有效。

    ★ 判据纪律：**判据不许二次实现** —— 这里只做"跑一次 ＋ 把异常分类成说明串"，
      不重写任何渲染逻辑。
    """
    try:
        mut = _load(src_mutated, tag, rel)
    except Exception as e:                                          # noqa: BLE001
        return None, ("负控自身失效：变异模块**加载就抛** %s: %s —— "
                      "量具故障（变异把源码写坏了），不是产品问题，不算通过"
                      % (type(e).__name__, e))
    try:
        return mut.render_page(**kw), None
    except Exception as e:                                          # noqa: BLE001
        return None, ("负控自身失效：变异模块**渲染抛** %s: %s —— "
                      "量具故障（多半是变异少给了参数），不是产品问题，不算通过"
                      % (type(e).__name__, e))


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


#: ★★ C2（2026-10-13）：剥除口径**不再在这里各写一份** —— 统一走
#:   `ci/page_caliber.py`（`body` / `body_without_terms` / `chrome` / `raw`），
#:   由元判据 S48 守（`ci/guard_instrument_selfaudit.py`）。
#:   由来：本文件原先自带的剥除只剥术语浮层，**不剥 `<style>`** ——
#:   U-10 因此被 CSS 注释里的「本机 · 127.0.0.1」**误红**（正文里早删干净了）。
#:   一句话：**判据扫渲染产物时必须显式选层**，不许拿整页原文当正文。


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
    """数**真实调用点**（不是注释里的字面）—— 走 **AST**，不走文本正则。

    ★★ C2（2026-10-13）机制修正：原先写
      `len(re.findall(r"M\\.reading_note\\(\\)\\)", src))` —— 那是**就地打补丁**
      （把正则收窄到「紧跟 ASCII 右括号」才勉强把注释排除掉）。文本层永远
      追不上注释的写法（换行、空格、全角括号都会让它翻面）。
      现在**逐字取自磁盘 ＋ AST 抽取**：`M.reading_note()` 是一个
      `ast.Call(func=Attribute(value=Name('M'), attr='reading_note'))`，
      注释在 AST 里根本不存在 ⇒ 结构事实取代文本巧合（维三）。
    ★ 由元判据 S48② 守（`ci/guard_instrument_selfaudit.py`）：判据不许用
      `len(re.findall(<调用语法>))` 数调用点。
    """
    import ast as _ast
    n = 0
    for node in _ast.walk(_ast.parse(src or "")):
        if not isinstance(node, _ast.Call):
            continue
        f = node.func
        if (isinstance(f, _ast.Attribute) and f.attr == "reading_note"
                and isinstance(f.value, _ast.Name) and f.value.id == "M"):
            n += 1
    return n


# ════════════════════════════ U-01 · 甲2（＋甲3 并入）════════════════
def _note_matches(page_body):
    """U-01 的口径行比对 —— **唯一落点**（两侧先归一刻载入时刻，再逐字比静态文案）。

    ★★ 为什么单独抽出来（2026-10-16）：负控 N-U01b / N-U01c **要直接调用它**，
      才能证明「修法是否还在承重」。若负控只是"再写一遍比对去比字符串"，那
      把这里的归一删掉、退回逐字比对，负控照样绿 ⇒ **纸负控**。
      抽成函数后，负控打的与正判据用的是同一个比对（维一：不许二次实现）。
    """
    return PC.note_text(M.reading_note()) in PC.note_text(page_body)


@check("U-01 ★ 甲2：读数口径不承诺活的（新措辞在位；分钟前/分母均为 零出现）")
def u01():
    """甲2：「最近 24 小时」窗口冻结，不随时间滚动 —— 页面却把它说成活的。

    v1.1 定性（§5.3）：**措辞降级，不本版加自动刷新**（常驻页自动重渲染会打断
    阅读：展开的词条被打收、滚动位置丢失 —— 那是增加处理，不是减少）。
    新措辞走唯一实现 `M.reading_note()`，两个调用点同源（维一）。
    甲3（Web 页无陈旧守卫）**并入本判据**：本版不建陈旧守卫；若将来做刷新，
    陈旧守卫与刷新同一批做（§5.3）。

    断言面：四页 ＋ 收件箱各 tab 的**渲染产物**（不打行号、不打函数名）。

    ★★ 2026-10-16 修（**判据自身时变**，非产品漂移）：
      0.50.4（Q-22）给 `M.reading_note()` 加了**实时**载入时刻（`载入于 HH:MM`）。
      本条原先「渲染之后**再调一次**该函数逐字比对」—— 两次独立读数**跨分钟即伪红**
      （满载单页渲染实测可达秒级 ⇒ 每 tab 约数 % 概率翻面；全量复跑实测撞到一次）。
      ⇒ 比对改走 `PC.note_text(...)`（先把两侧时刻归一，再逐字比静态文案）。
      **断言强度未降**：静态文案仍须逐字来自唯一实现，回潮旧串照样红
      （N-U01c 反证归一没吞掉真漂移；N-U01b 反证「只差时刻」不再伪红）。
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
    # ★ C2：一律经 `PC.body(...)`（剥 `<style>`/HTML 注释）—— 中文文案只许来自正文层。
    for view in _VIEWS:
        page = _page(view)
        for bad in ("分钟前", "分母均为"):
            if bad in PC.body(page):
                return "%s 页仍含 %r（承诺维持不住的口径／冻结读数）" % (view, bad)
    for tab in _TABS:
        page = _page("inbox", filt=tab)
        body = PC.body(page)
        if "不随页面停留刷新" not in body:
            return "收件箱 tab=%s 缺新措辞「不随页面停留刷新」" % tab
        if not _note_matches(body):
            return "收件箱 tab=%s 的口径行 ≠ M.reading_note()（唯一实现漂移）" % tab
    page = _page("report")
    if "不随页面停留刷新" not in PC.body(page):
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
    page, _why = _mut_render(src.replace(
        anchor,
        '            + ("<div class=\\"note\\" style=\\"margin:0 0 8px\\">%s</div>"\n'
        '               % _esc("最近 %d 小时 · 以上数字的分母均为本次载入的 %d 条记录"\n'
        '                      % (M.WINDOW_HOURS, n_all)))'),
        "is0490_nu01", _SERVER_REL,
                             view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu01_"),
                           token="T", items=_items(), posture=_POSTURE)
    if _why:
        return _why
    if "不随页面停留刷新" in PC.body(page):
        return "负控失效：调用点改回旧串后新措辞仍在（%r）" % page[:80]
    if "分母均为" not in PC.body(page):
        return "负控失效：旧串没渲染出来（注入没生效）"
    # ③ 连回正判据：真实现下必须含新措辞、且不含旧串
    live = _page("inbox", filt=M.BUCKET_ACTION)
    if "不随页面停留刷新" not in PC.body(live) or "分母均为" in PC.body(live):
        return "夹具不成立：真实现本身就不满足 U-01 ⇒ 负控无分辨力"
    return True


# ═══════════ N-U01b / N-U01c · U-01「瞬间读数的时钟」这对负控 ═══════════
#   ★★ 由来（2026-10-16 实测，**判据自身时变**不是产品漂移）：
#     0.50.4（Q-22）给 `M.reading_note()` 加了**实时**载入时刻。U-01 原先渲染后
#     **再调一次**该函数逐字比对 ⇒ 两次独立读数跨分钟即伪红。全量复跑实测撞到。
#     修法＝两侧先归一刻载入时刻（`PC.note_text`），比对落在**唯一落点**
#     `_note_matches()`。这两条负控**直接打在 `_note_matches()` 上**（同 N-S48
#     直接调 S48 的检测函数那一招）—— 不是"再写一遍比对"，所以修法若被回退，
#     负控会当场转红；只会背书的负控是纸负控。
@check("N-U01b ★ 负控：口径行**只差载入时刻**不得红（0.50.4 实时钟竞态，2026-10-16）")
def n_u01b():
    """反向对照（维二）：复现**旧口径的伪红**，并证明归一修法有效。

    步骤（**只动内存里的模块属性，磁盘一字节不动**）：
      ① 真渲染一页 —— 页面上的口径行 ＝ 该次渲染真产出的那一串（时刻 A）；
      ② 把 `M.reading_note` 换成"**只差时刻**"的版本（时刻 B，静态文案一字不动），
         模拟"渲染与比对是两次独立读数、期间跨了一分钟"；
      ③ 旧口径（逐字比对）在这一步**必红** —— 这是事故的复现，不是产品缺陷；
      ④ 新口径 `_note_matches()`（两侧归一后比静态文案）**必须绿**。
         若有人把 `_note_matches()` 回退成逐字比对，本条当场红 ⇒ 负控在承重。
    """
    orig = M.reading_note
    body = PC.body(_page("inbox", filt=M.BUCKET_ACTION))
    if "不随页面停留刷新" not in body:
        return "夹具不成立：真实现渲染页里没有口径行 ⇒ 负控无分辨力"
    live = orig()
    mm = re.search(r"载入于\s*(\d{1,2}):(\d{2})", live)
    if not mm:
        return ("夹具不成立：`reading_note()` 产物里找不到 `载入于 HH:MM` —— "
                "要么产品改了形态（需同步本负控），要么时钟已被移除")
    hh, mi = int(mm.group(1)), int(mm.group(2))          # 造一个**保证不同**的时刻
    stale_clock = "%02d:%02d" % ((hh + (mi + 1) // 60) % 24, (mi + 1) % 60)
    stale = live[:mm.start(1)] + stale_clock + live[mm.end(2):]
    # ③ 旧口径（逐字）必须红 —— 把曾发生的事故钉成可复跑的证据
    if stale in body:
        return ("夹具不成立：改写时刻后的串仍在页面里（%r）⇒ "
                "时刻不是页面里的唯一可变量，本负控测不出竞态" % stale_clock)
    # ④ 新口径必须绿（**打在 U-01 真正用的那个比对函数上**）
    M.reading_note = lambda: stale
    try:
        if not _note_matches(body):
            return ("负控失效：渲染与比对**只差载入时刻**时 `_note_matches()` "
                    "不通过 ⇒ 修法没生效（U-01 跨分钟仍会伪红）")
    finally:
        M.reading_note = orig
    return True


@check("N-U01c ★ 负控：口径行**静态文案**漂移必须仍红（时刻归一无掩蔽）")
def n_u01c():
    """反向对照（维二）：证明「归一刻」没有把 U-01 变成纸糊的。

    ① 真渲染一页；② 把 `M.reading_note` 换成**静态文案**漂移版
       （`本次载入时` → `本次载入前`，时刻形态不变）；③ `_note_matches()` **必须红**
       —— 否则说明归一顺手把"页面自造/回潮旧串"这类真漂移也吞了（修法过宽）。
    ★ 与 N-U01 分工：N-U01 打**调用点**回潮（页面侧），本条打**静态文案**漂移
      （实现侧）；两面都不许被归一掩蔽。
    """
    orig = M.reading_note
    body = PC.body(_page("inbox", filt=M.BUCKET_ACTION))
    live = orig()
    if not _note_matches(body):
        return "夹具不成立：真实现下 U-01 的比对不通过 ⇒ 负控无分辨力"
    if "本次载入时" not in live:
        return ("夹具不成立：唯一实现产物的静态文案里没有「本次载入时」"
                "（产品又改了措辞 ⇒ 本负控的注入点需同步）")
    M.reading_note = lambda: live.replace("本次载入时", "本次载入前")
    try:
        if _note_matches(body):
            return ("负控失效：静态文案漂移后 `_note_matches()` 仍通过 ⇒ "
                    "`PC.note_text` 把真漂移一起吞掉了（U-01 变纸糊）")
    finally:
        M.reading_note = orig
    # 变异-红-还原：还原后必须回绿
    if not _note_matches(body):
        return "负控失效：还原唯一实现后比对仍不通过 ⇒ 变异没清干净"
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
    if note not in PC.body(rep_page):
        return "日报页口径行 ≠ M.reading_note()（两处不同源）"
    # ② 正文零「分母」（剥术语浮层后；定义处不许被禁）
    for view in _VIEWS:
        body = PC.body_without_terms(_page(view))
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
    page, _why = _mut_render(src.replace(_NOTE_CALL_REPORT,
                            '    _win_note = ("<div class=\\"note\\" style=\\"margin:0 0 8px\\">'
                            '%s</div>"\n'
                            '                 % _esc("最近 %d 小时 · 以下数字的分母均为窗口内的 '
                            '%d 条记录"\n'
                            '                        % (hrs, _win_total)))'),
                "is0490_nu03a", _SERVER_REL,
                             view="report",
                           root=tempfile.mkdtemp(prefix="g0490_nu03a_"),
                           token="T", items=_items(), rep=_REP,
                           posture=_POSTURE)
    if _why:
        return _why
    if M.reading_note() in PC.body(page) and "分母均为" not in PC.body_without_terms(page):
        return "负控失效：改回旧串后日报页仍同源且无「分母」"
    if "分母" not in PC.body_without_terms(page):
        return "负控失效：旧内联串没渲染出来（注入没生效）"
    # 连回正判据：真实现下日报页必须同源且正文无「分母」
    # ★ 2026-10-16：T-01 上线首日抓到的第三处存量（修 U-01/S95 时漏了这）——
    #   同一时钟竞态：渲染与判据两侧独立读「载入于 HH:MM」，跨分钟 ⇒ 此处伪报
    #   「夹具不成立」。两侧归一（U-01 同法）。
    live = _page("report")
    if (PC.note_text(M.reading_note()) not in PC.note_text(PC.body(live))
            or "分母" in PC.body_without_terms(live)):
        return "夹具不成立：真实现本身就不满足 U-03 ⇒ 负控无分辨力"
    return True


@check("N-U03b 负控：当日行「共 N 条」改回「分母 N」⇒ U-03② 必须红")
def n_u03b():
    """反向对照（维二）：丙2 的字面禁现注入（日报当日行 956 那处）。"""
    src = _src(_SERVER_REL)
    anchor = '" ｜ 共 %d 条"'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    page, _why = _mut_render(src.replace(anchor, '" ｜ 分母 %d"'),
                "is0490_nu03b", _SERVER_REL,
                             view="report",
                           root=tempfile.mkdtemp(prefix="g0490_nu03b_"),
                           token="T", items=_items(), rep=_REP,
                           posture=_POSTURE)
    if _why:
        return _why
    if "分母" not in PC.body_without_terms(page):
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
    # ★ 0.48.6（B3）：锚点同步 —— 筛选标签链接不再挂 `&t=%s`，参数表少收 `_esc(token)`。
    anchor = ('                "<span class=\\"unit\\">%s</span></a>"\n'
              '                % (v, cls, _esc(tip), _esc(label), n, _esc(unit)))')
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    page, _why = _mut_render(src.replace(anchor,
                            '                "</a>"\n'
                            '                % (v, cls, _esc(tip), _esc(label), n))'),
                "is0490_nu08", _SERVER_REL,
                             view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu08_"),
                           token="T", items=_items(), posture=_POSTURE)
    if _why:
        return _why
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
    ③ `PAGE_TITLES` 基线（0.53.0 T0 起**五键**：新增 `health_exam`＝体检第五 TAB；
       本条基线随 T0 同批更新 —— 旧四键基线会挡住这次有意变更）；
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
    # ③ 页面名基线（0.53.0 T0：四键 → 五键，新增 health_exam）
    if set(SV.PAGE_TITLES) != {"inbox", "report", "health", "ledger",
                               "health_exam"}:
        return "PAGE_TITLES 五键基线被改动：%r" % (sorted(SV.PAGE_TITLES),)
    # ④ 认窗基线（0360 的真实判定，不在这里二次实现）
    #   ★ 0.51.1 反转（W-01 退休、FZ-002 冻结）：窗口标题恒为品牌形态
    #     「Antinel 监理#<6hex>」⇒ 基线夹具换品牌形态。
    import inbox_window as IW
    if not IW.is_console_title("Antinel 监理#abc123", "abc123"):
        return "品牌形态标题认不出了（认窗基线被破坏）"
    if IW.is_console_title("请给我一个 · Antinel 监理#a8276c", "a8276c"):
        return "用户窗口形状被误认（G-05 红线）"
    # ⑤ 无未登记术语
    for view in _VIEWS:
        unk = GL.unknown(_page(view))
        if unk:
            return "%s 页有未登记术语：%r" % (view, unk)
    return True


# ════════════════════════════ U-10 · 丁2/丁3（who 块删、口号变证据）═════
@check("U-10 ★ 丁2/丁3：who 块零出现（四页）；运行状态页有回环证据行")
def u10(mod=SV):
    """丁2：「本机 · 127.0.0.1」零信息量（回环地址每台机器一样）；
    丁3：「数据不出门」是定位宣言混进状态栏 —— 口号不是证据。

    v1.1 定性：删除，且**不是一删了之** —— 它承诺的事实搬进运行状态页作
    证据（「监听地址：仅本机回环——服务不接受外部连接」），而那句证据由
    `_check_bind` 的硬校验背书（非回环直接抛错）。判据同时断言三件事：
    删干净、证据在、后盾真（行为级，不只查文案）。

    ★ 0.50.2：加 `mod` 参数（默认真模块）—— 负控才能**拿变异模块跑同一条
      正判据**，从而证明"正判据真的会翻面"，而不是只证明"变异看得见"。
    """
    for view in _VIEWS:
        page = _page(view, mod=mod)
        for bad in ("本机 · 127.0.0.1", "数据不出门"):
            # ★ C2：经 `PC.body(...)` —— 剥掉 `<style>` 后，CSS 注释里复述过的
            #   同一串不再冒充正文（U-10 曾因此**误红**，见交接件 §C2）。
            if bad in PC.body(page):
                return "%s 页仍含 %r（丁2/丁3：零信息量块没删干净）" % (view, bad)
    health = _page("health", mod=mod)
    for want in ("仅本机回环", "服务不接受外部连接"):
        if want not in PC.body(health):
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
    """反向对照（维二）：把删掉的 who 块加回 `_bar` 的产出。

    ★ 0.50.2：改用**行为变异**（换掉 `_bar` 的产出），不再做源码文本替换 ——
      老锚点 `"%s%s<div class=\\"spacer\\"></div></header>"` 在 0.50.0 加了
      收缩钮（`<button class="collbtn">` ＋ `.collst`）之后就成了死字符串，
      负控连着报"变异锚点未找到（源码已变，需更新负控）"。
      **锚点跟着源码形状走 = 每改一次产品就得修一次尺子** ⇒ 变异打在行为上，
      产品怎么重排都不腐化。两步法不变：先证明变异真生效，再证明正判据翻面。
    """
    try:
        mut = _load(_src(_SERVER_REL), "is0490_nu10", _SERVER_REL)
    except Exception as e:                                          # noqa: BLE001
        return ("负控自身失效：变异模块加载就抛 %s: %s —— 量具故障，不算通过"
                % (type(e).__name__, e))
    orig_bar = mut._bar
    mut._bar = lambda *a, **k: orig_bar(*a, **k).replace(
        "</header>",
        '<div class="who">本机 · 127.0.0.1<br>数据不出门</div></header>')
    page = _page("inbox", filt=M.BUCKET_ACTION, mod=mut)
    if "本机 · 127.0.0.1" not in PC.body(page):
        return "负控失效：who 块加回后页面仍不含它（注入没生效）"
    live = _page("inbox", filt=M.BUCKET_ACTION)
    if "本机 · 127.0.0.1" in PC.body(live):
        return "夹具不成立：真实现本身还带 who 块 ⇒ 负控无分辨力"
    if u10(mod=mut) is True:
        return "负控失效：who 块回来了 U-10 仍判合格 —— 这条判据是装饰"
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


@check("N-U11 负控：40 字工程串加回标题栏 title ⇒ U-11 必须红")
def n_u11():
    """反向对照（维二）：把丁4 描述的那个 40+ 字工程 title 原样加回。

    ★★ 0.53.0（T3.2）重锚：原锚点是**药丸**的 title（「最近 24 小时的
      记录数（自载入起算）」）—— 那排随顶部 24h 计数排一起撤了（U20），
      锚点消失 ⇒ 负控报「变异锚点未找到」。新锚点选**顶部收缩钮**的
      title：它每个视图都渲染、且是 U-11 同一把尺子（「全部 title ≤20 字」
      **不只是药丸那一处**，docstring 早写明要防「别处复发」）。
      注入的仍是丁4 原句，断言不降。
    """
    src = _src(_SERVER_REL)
    anchor = ('        "title=\\"收缩成漂浮哨标 · 点它再展开\\" '
              'aria-label=\\"收缩成漂浮哨标\\">%s"')
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    page, _why = _mut_render(
        src.replace(anchor,
                    '        "title=\\"最近 24 小时的记录数；括号里是按事由归并后的'
                    '件数，点进去看全部明细\\" aria-label=\\"收缩成漂浮哨标\\">%s"'),
        "is0490_nu11", _SERVER_REL,
        view="inbox", filt=M.BUCKET_ACTION,
        root=tempfile.mkdtemp(prefix="g0490_nu11_"),
        token="T", items=_items(), posture=_POSTURE)
    if _why:
        return _why
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
            if bad in PC.body(page):
                return "%s 页仍含 %r（替用户描述他的动作）" % (view, bad)
    return True


@check("N-U05 负控：「（点开看每一次）」加回 ⇒ U-05 必须红")
def n_u05():
    """反向对照（维二）：把丁5 删掉的句子原样加回日报页调用点。"""
    src = _src(_SERVER_REL)
    # ★ 0.48.6（B3）：锚点同步 —— 拉起次数链接不再挂 `&t=%s`，参数表少收 `_esc(token)`。
    # ★ 0.50.4（Q-03）：源码把「%d 次</a> / %d」改成「%d 次</a>；同期记录 %d 条」
    #   （次数与条数是异质单位，不再相除）⇒ 锚点**同步更新**，否则注入不生效、
    #   负控失效（那才是真危险：负控失效＝本条防线形同没有）。
    anchor = ('                     "%d 次</a>；同期记录 %d 条"\n'
              '                     % (hrs, _revived, _win_total))')
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    page, _why = _mut_render(src.replace(
        anchor,
        '                     "%d 次</a>；同期记录 %d 条（点开看每一次）"\n'
        '                     % (hrs, _revived, _win_total))'),
        "is0490_nu05", _SERVER_REL,
                             view="report",
                           root=tempfile.mkdtemp(prefix="g0490_nu05_"),
                           token="T", items=_items(), rep=_REP,
                           posture=_POSTURE)
    if _why:
        return _why
    if "点开看每一次" not in PC.body(page):
        return "负控失效：加回后渲染页仍不含（注入没生效）"
    live = _page("report")
    if "点开看每一次" in PC.body(live) or "点规则名看具体是哪几条" in PC.body(live):
        return "夹具不成立：真实现本身还带旧句 ⇒ 负控无分辨力"
    return True


# ════════════════════════════ U-04 · 乙1（铺「？」芯片，8 个落点）════════
@check("U-04 ★ 乙1：基线 5 芯片落位（筛选条4+灯1）＋ 徽标芯片按 BADGE_STATE 齐备")
def u04():
    """乙1：日报页每个重要词都可点开看定义，收件箱页却一个「？」都没有
    （实测 term 芯片数 0）—— 同一个词两个页面两种待遇。

    形态（§5.6 定稿）：芯片作**兄弟节点**紧贴链接之后，**不嵌套**
    （`<a>` 内嵌 interactive 内容是坏味道）；summary 只放一个「？」
    （屏幕上的「？」由 CSS `::after` 徽章渲染，summary 自身的字由
    `.term.mk>summary{font-size:0}` 藏掉 —— 徽章**不许**关掉去"消重复"，
    那是 C5 的错法，由 **U-16** 锁）；词本名进展开体首行。
    基线词条 5 个：筛选条 action/info/archive/all（4）＋ 顶部灯 light（1）。
    ★★ 0.53.0（T3.2）：**基线 8 → 5**，撤掉的是药丸 R0/L2/L1 三颗。
      这三颗随**顶部 24h 计数排**一起撤（同口径两个落点即红）；它们的
      词条落点没有消失，而是跟着指标搬到**日报页四指标**（`metric()` 里
      `GL.chip(k)`）—— 术语 100% 有落点由 0353 P13（四视图并集）守，
      本判据守的是**收件箱页这一页**的落位，两边分层各守一层。
      ⇒ 这不是降强度：删除的是"同一份计数在第二处出现"，芯片总数在
      四视图并集里不减（P13 会红）。
    ★★ 0.51.0（四态问号小窗方案 v1.1 拍板点三）：**徽标芯片**加入 ——
      顶栏每枚徽标（研发中/缺粮）旁各带对应态的问号芯片（`BADGE_STATE`
      派生）。同步规则：**基线 5 全在（强度不降）**；出现陌生词条芯片 ⇒ 红；
      有徽标无芯片 ⇒ 红；重复落点 ⇒ 红。
    """
    page = _page("inbox")
    chips = re.findall(r'<details class="term mk" data-t="([^"]+)"', page)
    base = {"action", "info", "archive", "all", "light"}
    if not base <= set(chips):
        return "基线 5 芯片缺：%r" % sorted(base - set(chips))
    # ★ 0.51.0：徽标 → 芯片派生断言（出现徽标必有对应芯片；陌生芯片即红）
    bks = re.findall(r'<span class="bdg ([\w-]+)"', page)
    for bk in bks:
        st = M.BADGE_STATE.get(bk)
        if not st:
            return "徽标 %s 未登记 BADGE_STATE（有徽标没解释）" % bk
        if st not in chips:
            return "徽标 %s 旁缺「？」芯片（应指向词条 %s）" % (bk, st)
    expect = base | {M.BADGE_STATE[b] for b in bks if b in M.BADGE_STATE}
    if not set(chips) <= expect:
        return "mk 芯片出现陌生词条：%r" % sorted(set(chips) - expect)
    if len(chips) != len(set(chips)):
        return "mk 芯片有重复落点（实到 %d 个标签）" % len(chips)
    # ① summary 只能是「？」一个（"？？"＝ summary 自身的字没藏干净，见 U-16）
    if not re.search(r'<summary>？</summary>', page):
        return "mk 芯片的 summary 不是单个「？」（屏幕上会出现「？？」）"
    # ② 芯片不许被塞进链接里（兄弟节点，不是嵌套）
    for m in re.finditer(r"<a [^>]*>(.*?)</a>", page, re.S):
        if "<details" in m.group(1):
            return "芯片嵌套在 <a> 里（链接内嵌 interactive 是坏味道）"
    # ③ 展开体首行带词本名（复用 head 机制，不另写一套）
    #    ★ U-19（0.50.4）：发射器现带 name="term"（互斥小窗），子串随之更新
    #      —— 断言强度不变（head／summary／tdef 仍逐字在场）。
    for key in set(chips):
        if ('data-t="%s" name="term"><summary>？</summary>'
                '<div class="tdef"><b>' % key) \
                not in page:
            return "芯片 %s 的展开体首行缺词本名（head 机制没接上）" % key
    # ④ 未登记术语零命中（rendered 自动覆盖新芯片）
    if GL.unknown(page):
        return "页面有未登记术语：%r" % (GL.unknown(page),)
    return True


@check("N-U04 负控：摘掉顶部灯那颗芯片 ⇒ U-04 必须红")
def n_u04():
    """反向对照（维二）：5 个落点里摘掉一个 —— 精确集合立刻不满。

    ★ 0.53.0（T3.2）：基线随药丸撤销 8 → 5，期望集合同批改（否则「夹具
      不成立」腿会先红，负控自己失效）。
    """
    src = _src(_SERVER_REL)
    anchor = 'label, GL.chip("light", mk=True), suffix,'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    page, _why = _mut_render(src.replace(anchor, 'label, "", suffix,'),
                "is0490_nu04", _SERVER_REL,
                             view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu04_"),
                           token="T", items=_items(), posture=_POSTURE)
    if _why:
        return _why
    if "light" in re.findall(r'<details class="term mk" data-t="([^"]+)"',
                             page):
        return "负控失效：摘掉 light 芯片后它仍在（注入没生效）"
    live = re.findall(r'<details class="term mk" data-t="([^"]+)"',
                      _page("inbox"))
    live_bks = re.findall(r'<span class="bdg ([\w-]+)"', _page("inbox"))
    expect = ({"action", "info", "archive", "all", "light"}
              | {M.BADGE_STATE[b] for b in live_bks if b in M.BADGE_STATE})
    if set(live) != expect:
        return ("夹具不成立：真实现芯片集 %r ≠ 期望 %r ⇒ 负控无分辨力"
                % (sorted(set(live)), sorted(expect)))
    return True


# ══════════════ U-19 · 术语小窗互斥（0.50.4，创始人 2026-10-15 判定）══════════════
def _u19_offenders(page):
    """U-19 的唯一尺子（正负判据共用，不许二次实现）：
    返回 (缺 name 的术语芯片标记串列表, 术语芯片总数)。"""
    tags = re.findall(r'<details class="term[^"]*"[^>]*>', page or "")
    return [t for t in tags if 'name="term"' not in t], len(tags)


@check("U-19 ★ 术语小窗互斥：四视图每个术语芯片都带 name=\"term\"（原生互斥手风琴）")
def u19():
    """创始人 2026-10-15 判定「点开下一个问号小窗，上一个必须自动关闭」。

    机制层修法＝WHATWG HTML `<details name>` **原生互斥手风琴**：同名即同组
    （散在全页也算同组），开一个、浏览器**原生保证**关掉组里其它 open 的
    —— 零 JS、零状态（Edge 120+／2023-12 起；旧引擎退回多开＝渐进增强）。
    病根：`.term>.tdef` 是 fixed 视口定位（_FLIP_JS fit()），同时 open 两个
    就叠两个窗 ⇒ 互斥后同时至多一个。范围只锁 `GL.chip()` 的术语芯片；
    details.where／item／rem 等**行内**展开不进组（多开无害）。
    ★ 0.36.1 的 CSS 注释早就宣称这个行为（「点开别的词条会收起上一个」），
      但机制从未存在 —— 本判据钉的就是「这次真的在」。
    """
    bad, grand = [], 0
    for view in ("inbox", "report", "health", "ledger"):
        miss, total = _u19_offenders(_page(view))
        grand += total
        if miss:
            bad.append("%s: %d/%d 缺 name，如 %r" % (view, len(miss), total, miss[0]))
    if grand == 0:
        bad.append("四视图合计 0 个术语芯片（发射器疑似整体失效）")
    if bad:
        return "；".join(bad)
    return True


@check("N-U19 负控：发射器被剥掉 name ⇒ U-19 必须红")
def n_u19():
    """反向对照（维二）：把 `GL.chip` 的输出剥掉 ` name="term"` 再渲染。

    变异落在**发射器**上（import 后 monkeypatch GL.chip；_load 内存加载，
    磁盘一字节不动）。用完在 finally 里**还原共享模块** —— 量具不许给
    后续判据留脏状态。两步法走 `_mut_render`（C-01）。
    """
    src = _src(_SERVER_REL)
    if "import glossary as GL" not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    patch = ("\n# [N-U19] 变异：发射器不再输出 name\n"
             "GL.chip = (lambda _orig: lambda *a, **k: "
             "_orig(*a, **k).replace(' name=\"term\"', '', 1))(GL.chip)\n")
    import glossary as _gl
    _orig = _gl.chip
    try:
        page, _why = _mut_render(src + patch, "is0490_nu19", _SERVER_REL,
                                 view="inbox",
                                 root=tempfile.mkdtemp(prefix="g0490_nu19_"),
                                 token="T", items=_items(), posture=_POSTURE)
        if _why:
            return _why
        miss, total = _u19_offenders(page)
        if total == 0 or not miss:
            return "负控失效：剥掉 name 后 U-19 仍绿（注入没生效）"
    finally:
        _gl.chip = _orig
    live_miss, live_total = _u19_offenders(_page("inbox"))
    if live_total == 0 or live_miss:
        return "夹具不成立：真实现本身缺 name ⇒ 负控无分辨力"
    return True


# ════════════════════════════ U-06 · 乙3（收件箱页补 h2）═══════════════
@check("U-06 ★ 乙3：收件箱页有 <h2>，文本 == PAGE_TITLES[\"inbox\"]（唯一真源）")
def u06():
    """乙3：收件箱页无 `<h2>` 页面名，其余三页都有 —— 同一页三个身份
    （title「收件箱 · Antinel 监理#hash」/ 选项卡「收件箱」/ 无 h2）。
    文案取 `PAGE_TITLES`（唯一真源，0360:741 硬锁四键 —— 加了状态词那种
    字段立刻红，所以这里只许读它，不许另写）。
    ★ 0.51.1 反转注记（2026-10-16，W-01 退休、FZ-002 冻结）：上文
      「title『收件箱 · Antinel 监理#hash』」是**过场引用**（记录当时
      的页面身份三件套）—— 反转后 `<title>` 恒为「Antinel 监理#hash」，
      页面名只剩选项卡＋h2 两处（正是乙3 补 h2 的延续：页面名去标题化）。
      本条断言（h2 == PAGE_TITLES["inbox"]）不受影响，照跑。"""
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
    page, _why = _mut_render(src.replace(anchor, "    head = (\"\"\n"),
                "is0490_nu06", _SERVER_REL,
                             view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu06_"),
                           token="T", items=_items(), posture=_POSTURE)
    if _why:
        return _why
    if re.findall(r"<h2>([^<]*)</h2>", page):
        return "负控失效：删掉 h2 后页面仍有 h2（注入没生效）"
    live = re.findall(r"<h2>([^<]*)</h2>", _page("inbox"))
    if not live or live[0] != SV.PAGE_TITLES["inbox"]:
        return "夹具不成立：真实现本身就没有合规 h2 ⇒ 负控无分辨力"
    return True


# ════════════════════════════ U-13 · 戊1（头部 logo.svg）＋ 戊2 机械部分 ══
@check("U-13 ★ 戊1：头部用 logo.svg、零 mp4；品牌哨点必须在场且可辨（戊2 已反转）")
def u13(mod=SV):
    """戊1：768×768 → 46×46 的 mp4 缩放下发虚（607 KB 换一个模糊角标）
    ⇒ 头部改用矢量 `logo.svg`；mp4 留给托盘（16×16 合理，不动），
    favicon.ico 不变（U-13 只查头部，不碰托盘与 favicon）。

    ★★ 戊2 已**反转**（2026-10-17 创始人裁定，截图原话「0.48.5 那个是 AI
       幻觉裁定的，请取消，回复小黄球」）：0.48.5（461b4ef）那条「svg 内部
       不许有 circle」所依据的理由（"与 `.dot` 是两套点语言、抢读"）**查无出处**，
       定稿图 R4 从来就有这颗哨点 ⇒ 该断言是**幻觉裁定的固化**，本次撤除。
       新契约：品牌哨点**必须在场且肉眼可辨** —— 与 FZ-005 资产层冻结同一条。
       **不在这里另写判定**：直接调 0515 的共享尺子 `_ico_judge`（同一事实
       两处副本＝迟早不一致）；删圆/刷像素的负控由 FZ-005 三臂探针守着，
       本条不再重复登记负控。
       教训：判据注释里写「两套语言/抢读」这类**设计理由**时，必须能指到
       签发件或定稿图；指不到的就是幻觉，而幻觉一旦写成判据，就会反过来
       把正确实现判红（本轮实测：正确的球被 U-13 判红了一整批）。

    ★ 0.50.2：加 `mod` 参数（默认真模块），负控才能拿变异模块跑同一条正判据。
    """
    page = _page("inbox", mod=mod)
    head = re.search(r'<header class="bar">.*?</header>', page, re.S)
    if not head:
        return "抽不到 <header class=\"bar\">"
    h = head.group(0)
    if "/assets/logo.svg" not in h:
        return "头部没用 logo.svg（戊1）"
    if ".mp4" in h:
        return "头部仍引用 mp4（戊1：mp4 留给托盘，favicon.ico 不变）"
    if "<img" not in h:
        return "头部图标不是 <img>（戊1 要的是矢量位）"
    # 戊2（反转后）：品牌哨点必须在场，且能过资产层共享尺子（色可辨＋ico 一致）
    svg = _src("assets/logo/logo.svg")
    if "<circle" not in svg:
        return ("logo.svg 里没有品牌哨点（2026-10-17 裁定：小黄球必须在场；"
                "0.48.5 的「去哨点」是幻觉裁定，已作废）")
    ico_path = os.path.join(ROOT, "assets", "logo", "antinel.ico")
    if not os.path.exists(ico_path):
        return "assets/logo/antinel.ico 缺失（品牌资产不全）"
    with open(ico_path, "rb") as f:
        ico = f.read()
    why = _g15()._ico_judge(svg, ico)
    if why:
        return "品牌哨点不合格（共享尺子 _ico_judge）：%s" % why
    return True


@check("N-U13 负控：头部换回 mp4 ⇒ U-13 必须红")
def n_u13():
    """反向对照（维二）：把头部图标换回 state 专属 mp4（戊1 前的形状）。

    ★ 0.50.2：改用**行为变异**（换掉 `_logo_mark` 的产出），不再做源码文本替换。
      老锚点 `"<div class=\\"logo\\"><img alt=\\"Antinel\\" …>"` 在 0.49.0
      换成内联动效 SVG（＋`<noscript>` 退回图）时就死了 —— 负控连着两轮报
      "变异锚点未找到（源码已变，需更新负控）"，也就是**尺子自己先失效**。
      锚点绑源码形状 ⇒ 产品每改一次形状就得修一次尺子。变异打在行为上，
      无论头部怎么重排都不会腐化；而且 U-13 认的本来就是"头部这份图标是什么"
      这个行为，不是某一行字面量。
    """
    try:
        mut = _load(_src(_SERVER_REL), "is0490_nu13", _SERVER_REL)
    except Exception as e:                                          # noqa: BLE001
        return ("负控自身失效：变异模块加载就抛 %s: %s —— 量具故障，不算通过"
                % (type(e).__name__, e))
    mut._logo_mark = lambda st, label="Antinel": (
        '<video autoplay loop muted playsinline src="/assets/%s.mp4"></video>'
        % M.STATE_LOGO.get(st, "L0"))
    page = _page("inbox", filt=M.BUCKET_ACTION, mod=mut)
    head = re.search(r'<header class="bar">.*?</header>', page, re.S)
    if not head or ".mp4" not in head.group(0):
        return "负控失效：换回 mp4 后头部仍无 mp4（注入没生效）"
    live = re.search(r'<header class="bar">.*?</header>', _page("inbox"), re.S)
    if ".mp4" in live.group(0):
        return "夹具不成立：真实现本身头部就带 mp4 ⇒ 负控无分辨力"
    if u13(mod=mut) is True:
        return "负控失效：头部是 mp4 时 U-13 仍判合格 —— 这条判据是装饰"
    return True


# ════════════════════════════ U-15 · 戊4（词/解释权重倒挂）══════════════
@check("U-15 ★ 戊4：状态词 16px 随态色、解释 13px 常规色（旧声明不在）")
def u15():
    """戊4：旧形状「词 17px 粗体（继承黑）／解释 12px 灰」—— 信息量大的
    那句（为什么是这个态）被压成次要，权重倒挂。新形状：词 16px 粗体
    **色随态**（与 `.dot` 同一个 `M.STATE_VAR`）、解释 13px 常规色。

    形状判据（登记为例外，§5.8）：锁**旧 CSS 声明不在源码** ＋ 新声明在位
    ＋ 渲染页 `<b>` 真带随态色内联（三条合起来才叫改完，不是只剩删除）。
    """
    src = _src(_SERVER_REL)
    if ".state span{font-size:12px;color:var(--muted)}" in src:
        return "旧 CSS 声明还在（戊4：解释句 12px 灰 —— 权重倒挂复发）"
    if ".state b{font-size:16px" not in src:
        return "缺 `.state b{font-size:16px`（状态词 16px）"
    if ".state span{font-size:13px;color:var(--fg)}" not in src:
        return "缺 `.state span{font-size:13px;color:var(--fg)}`（解释 13px 常规色）"
    # 渲染面：<b> 真带随态色（行内 var 出自 M.STATE_VAR，不是写死的色值）
    page = _page("inbox")
    if not re.search(r'<b style="color:var\(--[a-z0-9]+\)">', page):
        return "渲染页的状态词 <b> 没带随态色内联（权重倒挂只改了一半）"
    # 连带：深色模式偏好仍在（--fg 两套主题都定义，解释句不会在深色下不可读）
    if "prefers-color-scheme" not in src:
        return "深色模式偏好块不见了（戊4 连带：--fg 的可读性没人守）"
    return True


@check("N-U15 负控：旧声明加回 ⇒ U-15 必须红")
def n_u15():
    """反向对照（维二）：把戊4 点名的那条旧声明原样加回 CSS。"""
    src = _src(_SERVER_REL)
    anchor = ".state span{font-size:13px;color:var(--fg)}"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    page, _why = _mut_render(src.replace(anchor,
                            ".state span{font-size:12px;color:var(--muted)}"),
                "is0490_nu15", _SERVER_REL,
                             view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu15_"),
                           token="T", items=_items(), posture=_POSTURE)
    if _why:
        return _why
    # CSS 在渲染产物里 ⇒ 旧声明回潮必须能在渲染页观察到
    # ★ C2：这是**样式层**断言 ⇒ 显式 `PC.chrome(...)`（只取 `<style>` 内容）。
    if ".state span{font-size:12px;color:var(--muted)}" not in PC.chrome(page):
        return "负控失效：加回旧声明后渲染页观察不到（注入没生效）"
    live = _page("inbox")
    if ".state span{font-size:12px;color:var(--muted)}" in PC.chrome(live):
        return "夹具不成立：真实现本身就还带旧声明 ⇒ 负控无分辨力"
    return True


# ══════════ W-01 / W-02 · 丁1 + 状态词标题（§5.5 边界项，单独 commit）══════════
#: ★★ 这一批动的是 `inbox_window._mark_at_tail()` 的认窗白名单 ——
#:   0.36.5 硬化过的「不许误关/误移用户窗口」边界（T-05 / G-05）。
#:   ⇒ 单独 commit；负控实测见过红；连回检查盯着 G-05 注入锚点两行。
#: ★★ 0.51.1 反转（2026-10-16，创始人需求反转）：**W-01 已退休**
#:   （去处：ci/suite_retirement.json 的 retirements[0]；墓碑见下方
#:   W-01 段）；**W-02 保留照跑**（正文零 #hex 与标题形态无关）。
#:   G-05 负控锚点已随反转迁移到 `_mark_at_tail` 的 rest 检查两行
#:   （旧锚点 `if page not in names` 随 page 前缀概念退役）。


def _state_words():
    """标题状态词的封闭词表 —— 唯一真源 `host_shield.POSTURE_LABEL_ALLOWED`。

    ★ 不写死、不抄第二份：判据与被判对象必须同一个源（S04 同型纪律）。
    """
    import host_shield as _HS
    return set(_HS.POSTURE_LABEL_ALLOWED)


# ══════════ W-01 / N-W01 · 已退休（2026-10-16，创始人需求反转）══════════
#: ★★ w01()＋n_w01() 已随**标题形态反转**整体退休（不是删除即完事 ——
#:   记录去处见 ci/suite_retirement.json 的 retirements[0]）：
#:   0.48.5 原话「标题该显示的是状态」作废，创始人新话「只要保留
#:   Antinel 监理加上编号就行了」⇒ 标题恒为「Antinel 监理#<6hex>」
#:   （新契约冻结为 FZ-002，kind=output，check=window_title_format，
#:   由 D-38 执法）。w01 的四条断言（is_console_title 旧形态夹具／
#:   渲染四页 <title> 正则＋与头部同词／状态词词表覆盖／PAGE_TITLES
#:   连带）全部建立在旧形态上，逐条作废；n_w01 负控（白名单缩维 ⇒
#:   状态词翻面）同批退休。
#: ★ 连带：`_state_words()`（本档上方）随 w01 退休失去唯一消费者 ——
#:   保留（注释已注明退役原因）：它是 §5.5 词表的记忆载体，下一个人
#:   考古时不该面对一个凭空消失的函数。
#: ★ 别再复活它们 —— 旧形态的形状（「状态词 · Antinel 监理#…」）在
#:   新认窗判据（品牌开头＋其后只允许身份串）下**全部认不出**，复活
#:   即假红；legacy 窗口**本版不认领**（诚实缓建：`_mark_at_tail_any`
#:   只服务 logo/bubble 窗，console 无 legacy 路径；无分发⇒无升级
#:   人口，分发前须补 LEGACY 认领 —— 见 inbox_window.is_console_title
#:   docstring 的缓建注记）。
#:
# def w01(): ...（原文 2026-10-13 交接件 §5.5 定稿，2026-10-16 退休）
# def n_w01(): ...（负控，同批退休）


@check("W-02 ★ 丁1：正文（除 <title>）零 #hex6 —— hash 只在标题尾")
def w02():
    """丁1 的判据化落点：渲染四页，body 里不许出现 `#<6 位小写 hex>`。

    ★ 扫描范围只取 `<body>` 之后 —— `<head>` 里的 CSS 有色值（如
      `#0a1a12`），扫全会冤判（交接件「先确认无冤判」的落地）。
    ★ `<title>` 整段先剥掉：hash 合法地只住在那（认窗必需，不能删）。
    """
    for view in ("inbox", "report", "health", "ledger"):
        page = _page(view)
        # ★ C2：这是**结构断言**（`<body>` 是纯 ASCII 标记，不会出现在中文注释里）
        #   ⇒ 显式 `PC.raw(...)` 声明「我确实要看整页」。
        if "<body>" not in PC.raw(page):
            return "%s 页没有 <body> 起始标记（判据扫的范围没了）" % view
        body = page.split("<body>", 1)[-1]
        m = re.search(r"#[0-9a-f]{6}", body)
        if m:
            return ("%s 页正文出现 %s —— 丁1：hash 只在标题尾，"
                    "正文置回 run_id 是回潮" % (view, m.group(0)))
    return True


@check("N-W02 负控：正文置回 run_id ⇒ W-02 必须红")
def n_w02():
    """反向对照（维二）：丁1 原貌 ＝ hash 在正文可见。

    ★★ 0.51.1 行为变异版（2026-10-16）：`_head` 重构后（`shown = tail if
      tail else title` ＋ 格式元组 3 参→2 参），旧源码锚点
      `'% (_esc(title), tail, CSS))'` 成死串 —— 负控连报「变异锚点未找到」，
      也就是**尺子自己先失效**（0.50.2 N-U13 踩过的同族坑）。按那次的
      先例改**行为变异**：变异补丁追加在模块尾部，包一层 `_head` —— 从
      渲染出的 `<title>` 里把**真实身份串**（`#<run_id>`，6 位小写 hex）
      复制一份进正文起始：与「run_id 回潮正文」同一条路径、同一个真串，
      不是另编一个假串。补丁只认函数名 `_head`，不绑任何源码行形状 ——
      产品以后怎么重排这个函数都不腐化；`_head` 若改名 ⇒ 加载即抛
      NameError ⇒ `_mut_render` 报「量具故障」，诚实红，不冒充产品红。
    ★★ 0.53.0（T0）再修一次同型：产品给 `_head` 加了口令外的第三参
      `extra_css`（体检页挂 EXAM_CSS）⇒ 两参包装器当场 TypeError
      （「变异模块渲染抛」—— 量具故障伪装成产品红）。包装器改
      `**kw` 透传：连**签名**也不绑了，产品再加参它也不腐化。
    """
    src = _src(_SERVER_REL)
    patch = (
        "\n# [N-W02] 变异：正文置回 run_id（0.51.1 行为变异版）\n"
        "_orig_head_0490 = _head\n"
        "def _head(title, token, **kw):\n"
        "    h = _orig_head_0490(title, token, **kw)\n"
        "    m = re.search(r\"<title>(.*?)</title>\", h)\n"
        "    if not m:\n"
        "        return h\n"
        "    return h.replace(\"</head><body>\",\n"
        "                    \"</head><body><span>%s</span>\" % m.group(1))\n"
    )
    page, _why = _mut_render(src + patch, "is0490_nw02", _SERVER_REL,
                             view="inbox", filt=M.BUCKET_ACTION,
                             root=tempfile.mkdtemp(prefix="g0490_nw02_"),
                             token="T", items=_items(), posture=_POSTURE)
    if _why:
        return _why
    body = page.split("<body>", 1)[-1]
    if not re.search(r"#[0-9a-f]{6}", body):
        return "负控失效：正文置回 run_id 后渲染页观察不到（注入没生效）"
    live_body = _page("inbox").split("<body>", 1)[-1]
    if re.search(r"#[0-9a-f]{6}", live_body):
        return "夹具不成立：真实现正文本身就带 #hex6 ⇒ 负控无分辨力"
    return True


# ══════════ W-03 · A2（托盘与 Web 状态词同源，遗留问题清单 2026-10-13）══════════
#: ★★ 盯的已修缺陷：**A2 两套口径** —— 同一枢纽、同一时刻，托盘 tip 走旧合并读
#:   （24h 账里的历史 R0 抬灯，实测「有过失守 · 哨兵在岗」），Web 头部自 0.39.0
#:   走 `current_state()`（历史 R0 一律不抬灯，实测「拦截」）—— §6.2.4
#:   「两个界面不许各说各话」实测不过。
#:   修法（产品侧 inbox_tray.py）：`sync_from_items` 的事件态/状态词改取
#:   `M.light_explain()`（页面同一次调用的唯一实现），`label` 逐字进 tray.json。


def _w03_assert():
    """W-03 正判据的纯判断（正/负控共用）。返回 None＝过，否则说明串。

    四个现场（都注入 guarding 姿态），三个维度都盯：
      ① 账内 R0 × 2 条（同因一件） ⇒ 页面「值守中」（0.39.0：历史 R0 不抬灯），
         旧合并读会给「失守」—— A2 实测的就是这一对；
      ② 账内 L2 一条（已拦下）**刚发生**（0.1h，在保持期内）⇒ 页面「拦截」——
         防"同源"被做反成"谁都不抬灯"（负向也要同源）。
      ③ 账内 L2 一条**过了保持期**（1.0h > `LAMP_HOLD_MINUTES`=30min）⇒
         页面「值守中」—— ★ 0.51.0 规格 v1.2 §2.1：info 桶只在**未读 ∧ 刚发生**
         时抬灯，超期只进「待阅 N」。把「拦截」钉成**禁用词**＝谁把保持期拆掉
         （退回 v1.1 的"info 一律抬灯"）这条就红。
      ④ 账内 L2 一条**已读**（刚发生）⇒ 页面「值守中」—— 已读＝已知情，
         保持期**提前结束**（0.35.3「你知情即可」的机制化）。

    ★ 四个现场的 `count`/`total` 一律不变（0/1 或 1/2）：本条判据只管**状态词
      同源**，件数/分母口径由 W-01/U-06 等另管 —— 不许一条判据同时改两个口径。
    """
    import inbox_tray as TR
    posture = _POSTURE                   # guarding：哨兵在岗
    cases = [
        ("账内 R0", [_mk("R0", "unread", 1, 1.0), _mk("R0", "unread", 2, 2.0)],
         "值守中", "失守", 1, 2, "L0"),
        ("账内 L2（保持期内）",
         [_mk("L2", "unread", 4, 0.1, kind="tool_call_blocked")],
         "拦截", None, 0, 1, "L2"),
        ("账内 L2（过保持期）",
         [_mk("L2", "unread", 5, 1.0, kind="tool_call_blocked")],
         "值守中", "拦截", 0, 1, "L0"),
        ("账内 L2（已读）",
         [_mk("L2", "read", 6, 0.1, kind="tool_call_blocked")],
         "值守中", "拦截", 0, 1, "L0"),
    ]
    for name, items, want_word, banned, want_count, want_total, want_st in cases:
        hub = tempfile.mkdtemp(prefix="g0490_w03_")
        # ① 页面侧：状态词＝页面**自己**算出来的（render_page 内部同一调用）
        #   ★ 0.51.1 反转（W-01 退休、FZ-002 冻结）：标题不再带状态词
        #     （整串恒为「Antinel 监理#<6hex>」）⇒ 状态词同源的观测点
        #     从 <title> 迁移到顶部条 .state 块内首个 <b>（ex["label"]
        #     的唯一可见位；w01 旧 ② 的"标题与头部同词"断言已随 W-01
        #     退休）。**意图不变**：页面状态词必须＝该 items 算出来的。
        page = _page("inbox", items=items, rep=_REP)
        st = re.search(r'<div class="state">.*?<b[^>]*>(.*?)</b>', page, re.S)
        if not st:
            return "%s：页面没有 .state 状态词（判据扫的锚点没了）" % name
        page_word = st.group(1)
        # ② 夹具自检（把 0.39.0 铁律钉进来：R0 绝不由账给）
        if page_word != want_word:
            return ("%s：页面状态词应 %r，实得 %r —— current_state 口径变了"
                    % (name, want_word, page_word))
        if banned is not None and page_word == banned:
            return "%s：页面把历史 R0 抬成了 %r（假失守复发）" % (name, banned)
        # ③ 托盘侧：同夹具、同姿态
        payload = TR.sync_from_items(items, root=hub, posture=posture)
        if payload.get("label") != page_word:
            return ("%s：托盘 label %r ≠ 页面状态词 %r —— 两套口径复发（A2）"
                    % (name, payload.get("label"), page_word))
        if not (payload.get("tip") or "").startswith(page_word):
            return ("%s：托盘 tip 开头不是页面那个状态词：%r"
                    % (name, payload.get("tip") or ""))
        # ④ 连带：件数/分母/哨兵态/图标态不受本批影响
        if (payload.get("count") != want_count
                or payload.get("total") != want_total):
            return ("%s：件数/分母口径被带坏：count=%r total=%r（应 %d / %d）"
                    % (name, payload.get("count"), payload.get("total"),
                       want_count, want_total))
        if payload.get("shield") != TR.SHIELD_ONPOSTURE:
            return "%s：guarding 的监理态不是 on：%r" % (name, payload.get("shield"))
        if payload.get("state") != want_st:
            return "%s：图标态应为 %r，实得 %r" % (name, want_st,
                                                payload.get("state"))
    return None


@check("W-03 ★ A2：托盘状态词与 Web 标题/头部逐字同源（同一 light_explain）")
def w03():
    r = _w03_assert()
    if r is not None:
        return r
    return True


@check("N-W03 负控：托盘改回旧合并读（历史 R0 抬灯）⇒ W-03 必须红")
def n_w03():
    """反向对照（维二）：把托盘的状态词源换回 0.48.5 前的旧合并读。

    变异体＝A2 缺陷本身（console_state 抬历史 R0 ⇒ label「失守」）——
    不是随便改坏：必须让**那个真缺陷**重新现形，再被 W-03 抓到。
    还原后必须回绿（还原链路坏掉比负控失效更险）。
    """
    import inbox_tray as TR
    import inbox_model as M

    class _OldM:                        # ← MUTANT：旧合并读口径
        def __init__(self, real):
            self._real = real

        def __getattr__(self, k):
            return getattr(self._real, k)

        def light_explain(self, posture, items, **kw):
            st = self._real.console_state(items)        # ← MUTANT
            return {"state": st, "label": self._real.state_label(st),
                    "now_text": "", "reason": "",
                    "ledger_bad": True, "now_bad": True}
    saved = TR.M
    TR.M = _OldM(M)
    try:
        r = _w03_assert()
        if r is None:
            return "托盘改回旧合并读，W-03 仍判通过 ⇒ 判据没在看同源性"
        if "账内 R0" not in r:
            return ("负控咬错了地方：红的应是「账内 R0」现场（A2 那一对），"
                    "实得 %r" % r[:60])
    finally:
        TR.M = saved
    if _w03_assert() is not None:
        return "还原 TR.M 后 W-03 仍红 ⇒ 还原链路坏了"
    return True


# ══════════ W-04 · B1（Antinel 监理常驻：同端口/口令自恢复，遗留问题清单）══════════
#: ★★ 盯的已修缺陷：**B1 无常驻入口** —— Antinel 监理服务原来是"会话里拉的前台进程"，
#:   会话一结束就没了；托盘与守护进程都不负责把它拉回来（窗口开着、点一下全失败）。
#:   B1 验收：**杀掉服务进程后 60 秒内自行恢复，端口与 URL 不变**。
#:   修法（产品侧）：`inbox_server` 落盘 `url.json`（端口/口令/pid/url）＋
#:   `console_status()` 两轴判活 ＋ `ensure_console()` 按记录原样重拉；
#:   `inbox_daemon.run(supervise=True)` 到点去 ensure；`antinel.cmd` 一键入口。
#:   ★ 判据全部**不真起常驻进程**：用真 HTTP 服务（临时端口，内存线程）＋
#:     注入的假 spawner 验决策链 —— 真端到端自恢复在运行态验收里做（维六）。


def _w04_serve_inline(token, port=0):
    """在**内存里**起一个真 HTTP 服务（`port=0` ⇒ 临时端口）。返回 `(httpd, port)`。

    ★ 不落产品文件、不留常驻进程（daemon 线程，判据结束即随进程退）。
    """
    import threading
    import inbox_server as SV
    httpd, _tok = SV.make_server(port=port, token=token)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _w04_status_ok():
    """① `console_status()` 两轴判活：pid 活着 **且** 端口在听。"""
    import inbox_server as SV
    hub = tempfile.mkdtemp(prefix="g0490_w04a_")
    alive, rec, why = SV.console_status(root=hub)
    if alive:
        return "没有落盘记录却判成「在跑」"
    # pid 已死 + 端口没人听
    SV.write_console_record(8791, "tok-dead", pid=999999, root=hub)
    alive, _rec, _why = SV.console_status(root=hub)
    if alive:
        return "登记进程已死、端口也没人听，仍判成「在跑」"
    # pid 活着（本进程）但端口没人听 ⇒ 不许判活，且 why 要点明端口
    SV.write_console_record(8791, "tok-x", pid=os.getpid(), root=hub)
    alive, _rec, why = SV.console_status(root=hub)
    if alive:
        return "端口没人听却判成「在跑」（只看 pid 不看端口）"
    if "端口" not in (why or ""):
        return "判死的理由没点明端口：%r" % (why,)
    # 真起一个服务 ⇒ 判活
    httpd, port = _w04_serve_inline("tok-live")
    try:
        SV.write_console_record(port, "tok-live", pid=os.getpid(), root=hub)
        alive, _rec, why = SV.console_status(root=hub)
        if not alive:
            return "真服务在跑却判成「不在」：%s" % why
    finally:
        httpd.shutdown()
    return None


def _w04_ensure_ok():
    """② `ensure_console()` 重拉时**沿用记录里的端口与口令**（URL 不变）＋ ③ 幂等。"""
    import inbox_server as SV
    hub = tempfile.mkdtemp(prefix="g0490_w04b_")
    # 借一个真空闲端口号（绑完立刻放掉），保证记录里的端口可用且可被占
    probe, _ = SV.make_server(port=0)
    free_port = probe.server_address[1]
    probe.server_close()
    want_url = "http://127.0.0.1:%d/?t=TOK-KEEP" % free_port
    SV.write_console_record(free_port, "TOK-KEEP", pid=999999, root=hub)
    seen = {}
    started_httpd = []

    def fake_spawn(port, token, root):
        """假 spawner：按传进来的端口/口令真起一个服务并落盘（模拟子进程的 serve）。"""
        seen["port"], seen["token"] = port, token
        httpd, _p = _w04_serve_inline(token, port=port)     # ★ 必须绑**它给的端口**
        started_httpd.append(httpd)
        SV.write_console_record(port, token, pid=os.getpid(), root=hub)
    try:
        rec, started = SV.ensure_console(root=hub, spawner=fake_spawn, wait_sec=3)
        if not started:
            return "记录里进程已死，`ensure_console` 却没去重拉"
        if seen.get("port") != free_port:
            return ("重拉用了别的端口：%r（应沿用记录里的 %d）—— 端口一变，"
                    "用户手上的 URL 就失效" % (seen.get("port"), free_port))
        if seen.get("token") != "TOK-KEEP":
            return ("重拉换了新口令：%r（应沿用记录里的）—— 口令一变 URL 必变"
                    % (seen.get("token"),))
        if (rec or {}).get("url") != want_url:
            return "重拉后的 url 与记录不一致：%r（应 %r）" % (
                (rec or {}).get("url"), want_url)
        # ③ 幂等：已经在跑 ⇒ 不再 spawn
        calls = []
        _rec2, started2 = SV.ensure_console(
            root=hub, spawner=lambda *a: calls.append(a), wait_sec=1)
        if started2 or calls:
            return "服务已在跑，`ensure_console` 又去重拉了一次（幂等破了）"
    finally:
        for h in started_httpd:
            h.shutdown()
    return None


def _w04_daemon_ok():
    """④ 守护进程监督开关（默认关；开了到点去 ensure）＋ ⑤ 单例 ＋ 一键入口在位。"""
    import inbox_daemon as DM
    hub = tempfile.mkdtemp(prefix="g0490_w04c_")
    calls = []
    n = DM.Daemon(root=hub).run(max_ticks=1, interval=0, supervise=True,
                                ensure=lambda *a, **k: calls.append(a),
                                supervise_every=0)
    if n != 1 or len(calls) != 1:
        return ("supervise=True 时守护进程没去确保Antinel 监理（tick=%r，ensure 调用 %d 次）"
                % (n, len(calls)))
    calls2 = []
    DM.Daemon(root=hub).run(max_ticks=1, interval=0, supervise=False,
                            ensure=lambda *a, **k: calls2.append(a))
    if calls2:
        return "supervise=False 时仍去 ensure（默认关的语义破了）"
    # ⑤ 单例：已有**别的**活守护进程 ⇒ 不跑
    _orig = DM.daemon_alive
    DM.daemon_alive = lambda *a, **k: (True, 424242)
    try:
        ticks, why = DM.run_daemon(root=hub, max_ticks=1, supervise=False)
    finally:
        DM.daemon_alive = _orig
    if ticks != 0 or why != "already-running":
        return "已有活守护进程仍启动了第二份：%r/%r" % (ticks, why)
    # 一键入口：`antinel.cmd` 在位，且真的指向两个入口（不是空壳）
    p = os.path.join(ROOT, "antinel.cmd")
    if not os.path.exists(p):
        return "仓根没有 antinel.cmd（一键入口不存在）"
    txt = io.open(p, encoding="utf-8", errors="replace").read()
    for need in ("inbox daemon", "inbox window"):
        if need not in txt:
            return "antinel.cmd 没调用 `%s`（空壳入口）" % need
    return None


@check("W-04 ★ B1：Antinel 监理常驻 —— 两轴判活 / 同端口同口令重拉 / 守护进程监督")
def w04():
    for fn in (_w04_status_ok, _w04_ensure_ok, _w04_daemon_ok):
        r = fn()
        if r is not None:
            return r
    return True


@check("N-W04 负控：换新口令 / 只看 pid / 去掉监督 ⇒ W-04 必须红")
def n_w04():
    """反向对照（维二）：三个变异体＝B1 的三个真缺陷形状，逐个必须被 W-04 抓到。

    ① `ensure_console` 重拉时**另生成口令**（URL 必变 ⇒ 用户手上的链接失效）；
    ② `console_status` 只看 pid、不看端口（别的程序占了端口也判"在跑"）；
    ③ `run_daemon` 去掉单例判定（双击两次就有两份守护进程）。
    """
    # ① 换新口令
    src = _src(_SERVER_REL)
    a_keep = '    want_token = (rec or {}).get("token") or secrets.token_urlsafe(24)'
    a_new = "    want_token = secrets.token_urlsafe(24)                # ← MUTANT"
    if a_keep not in src:
        return "变异锚点未找到（ensure_console 已变）—— 负控自身失效，不算通过"
    mut = _load(src.replace(a_keep, a_new), "is0490_nw04a", _SERVER_REL)
    saved = _sv_patch(mut)
    try:
        r = _w04_ensure_ok()
        if r is None:
            return "重拉换新口令，W-04 仍判通过 ⇒ 判据没在看「URL 不变」"
    finally:
        saved()
    # ② 只看 pid
    a_two = "    if alive_pid and listening:\n        return True, rec, \"在跑\""
    a_one = "    if alive_pid:\n        return True, rec, \"在跑\"          # ← MUTANT"
    if a_two not in src:
        return "变异锚点未找到（console_status 已变）—— 负控自身失效，不算通过"
    mut2 = _load(src.replace(a_two, a_one), "is0490_nw04b", _SERVER_REL)
    saved2 = _sv_patch(mut2)
    try:
        r = _w04_status_ok()
        if r is None:
            return "只看 pid 不看端口，W-04 仍判通过 ⇒ 判据没在看端口那一轴"
    finally:
        saved2()
    # ③ 去掉单例判定
    dsrc = _src("inbox_daemon.py")
    b_check = '    if alive and pid != os.getpid():\n        return 0, "already-running"'
    b_gone = "    if False:\n        return 0, \"already-running\"        # ← MUTANT"
    if b_check not in dsrc:
        return "变异锚点未找到（run_daemon 已变）—— 负控自身失效，不算通过"
    dmut = _load(dsrc.replace(b_check, b_gone), "is0490_nw04c", "inbox_daemon.py")
    import inbox_daemon as DM
    saved3 = (DM.daemon_alive, DM.run_daemon)
    DM.daemon_alive, DM.run_daemon = dmut.daemon_alive, dmut.run_daemon
    try:
        hub = tempfile.mkdtemp(prefix="g0490_nw04_")
        ticks, why = DM.run_daemon(root=hub, max_ticks=1, supervise=False)
        if ticks == 0 and why == "already-running":
            return "去掉单例判定后仍拦住了第二份 ⇒ 变异没生效"
    finally:
        DM.daemon_alive, DM.run_daemon = saved3
    return True


def _mod_patch(name, mod):
    """把 `mod`（内存里加载的变异体）临时顶到 `name` 名下。返回还原函数。

    ★ 为什么必须这样：判据里 `import <name>` 拿的是**真身**；要验的是
      **变异后的那份源码**，所以得让真名指向变异体（`sys.modules` 换掉），
      结束再换回来（regression_gate D-27 同款纪律）。
    """
    real = sys.modules.get(name)
    sys.modules[name] = mod

    def _restore():
        if real is not None:
            sys.modules[name] = real
        else:
            sys.modules.pop(name, None)
    return _restore


def _sv_patch(mod):
    """把 `mod`（内存里加载的 inbox_server 变异体）临时顶到 `inbox_server` 名下。"""
    return _mod_patch("inbox_server", mod)


# ══════════ W-05 · B2（端口漂移不再静默：出声 + 落盘 + 托盘带实际端口）══════════
#: ★★ 盯的已修缺陷：**B2 端口漂移静默换端口** —— `_bind_first_free(8790)` 在被占时
#:   静默改用系统临时端口，用户手输 `127.0.0.1:8790` 打不开、也无从得知实际端口
#:   （本轮 before/after 对比时同时开过 5 个实例，全靠读 url 文件）。
#:   修法（产品侧）：① `_bind_first_free()` 多返回 `drift`（want/got/owner）；
#:   ② `_serve_setup()` 把漂移**说到 stderr**（话由 `console_drift_note()` 唯一实现）
#:      ＋ 把 `want_port` 落进 `url.json`（stderr 随终端消失，落盘不会）；
#:   ③ 托盘提示带**实际端口**（读同一份落盘，唯一真源）；没有记录 ⇒ **不编**。
#:   ★ 占用方 pid 由 `_port_owner()` 查（Windows `netstat -ano` / POSIX `lsof`）。
#:     判据用**本进程**占端口 ⇒ 占用方 pid 必＝本进程，可强断言（不依赖机器天气）。


#: W-05 夹具自证的**重试轮数**（机器天气兜底，不是放宽判据）。
#:   ★ 上界是有意压低的：`_port_owner` 单次最多等 5s（`timeout=5`），
#:     3 轮 × 2 次探针 = 最坏 30s 额外耗时，只在**仪表真的不通**时才会走到。
_W05_TRIES = 3
#: 「占用方 pid」这一项的**标记串**：**只有它**是可重试的机器天气；
#:   其余各项（没报漂移／端口记错／托盘不带端口）都是真缺陷，一次即红。
_W05_OWNER_MARK = "占用方进程号"
#: 「夹具失效」的识别串：`_w05_assert()` 报夹具故障时用它开头。
_W05_FIXTURE_DEAD = "夹具失效"


def _w05_owner_probe(port, tries=2, gap=0.15):
    """**夹具自证**（X-019）：`_port_owner()` 这台仪表此刻真的查得到占用方吗。

    返回 `(live, value)`，`live = (value is not None)`。

    ★★ 为什么必须有（2026-10-13 实测撞到，不是推演）：
      `_port_owner()` 走**外部子进程**（Windows `netstat -ano` / POSIX `lsof`），
      机器高负载时查询取不到 ⇒ `owner=None` ⇒ 断言 `owner == 本进程` **假红**
      （实测：「漂移没点出占用方进程号：owner=None（应 26332）」）。
      **与 X-017 同一类**（T-08 复发在量具层）：量具把「取不到信号」
      当成了「裁决错误」——**把机器天气说成产品缺陷**。
    ★ 方向（关键）：**只在始终取不到时**判「仪表失效」；**一旦取到值（哪怕值不对），
      判定权立刻交回判据** —— 值不对是**真缺陷**，该红。
    ★ `import` 在函数内做：负控用 `_mod_patch` 换掉 `sys.modules["inbox_server"]`，
      这里必须拿到**当轮**那个模块（否则探针测的是真身，不是变异体）。
    """
    import time
    import inbox_server as SV
    n = max(1, int(tries))
    val = None
    for i in range(n):
        try:
            val = SV._port_owner(port)
        except Exception:                                  # noqa: BLE001
            val = None
        if val is not None:
            return True, val
        if i + 1 < n:
            time.sleep(gap)
    return False, val


def _w05_bind_attempt(SV, held, hub):
    """① 的**一次**尝试。返回 `(说明串 or None)`；`None` ＝ 这一轮过了。"""
    httpd, _tok, got, drift = SV._bind_first_free(held, hub)
    try:
        if got == held:
            return "首选端口被占，却仍绑在同一个端口上（漂移没发生）"
        if not drift:
            return "换了端口却**没报漂移** —— 静默换端口（B2 那个缺陷本身）"
        if drift.get("want") != held or drift.get("got") != got:
            return "漂移记录端口不对：%r（应 want=%r got=%r）" % (drift, held, got)
        if drift.get("owner") != os.getpid():
            return ("漂移没点出占用方进程号：owner=%r（应 %d —— 端口是本进程占的）"
                    % (drift.get("owner"), os.getpid()))
        return None
    finally:
        httpd.server_close()


def _w05_assert():
    """W-05 正判据（正/负控共用）。返回 None＝过，否则说明串。

    三个现场：
      ① `_bind_first_free` 在首选端口被占时**报出漂移**（want/got/owner 三值齐）；
      ② `_serve_setup()` 把这件事**说到 stderr**，那句话点名两个端口与占用方 pid，
         并把 `want_port` 落进 `url.json`；
      ③ 托盘提示带**实际端口**（从 `url.json` 读，唯一真源）；没有记录 ⇒ 不编。

    ★★ X-019（2026-10-13）：①② 里凡**依赖「占用方 pid」**的那一项，都改成
      **条件断言** —— 仪表（`_port_owner` 走外部子进程）取不到 ⇒ 报
      **「夹具失效」**（`_W05_FIXTURE_DEAD` 开头），**不许**把量具故障说成产品缺陷。
      非天气项（没报漂移／端口记错／托盘不带端口）照旧一次即红。
    """
    import contextlib
    import inbox_server as SV
    import inbox_tray as TR
    hub = tempfile.mkdtemp(prefix="g0490_w05_")
    holder, held = _w04_serve_inline("tok-holder")      # 本进程占住 held
    try:
        # ① 漂移必须被**报出来**（不是静默换掉）
        #   ★★ X-019：只有「占用方 pid 取不到」是**可重试的机器天气**；
        #     红在这一项时**当场**再问一次仪表 —— 仪表此刻通 ⇒ 是真缺陷；
        #     不通 ⇒ 这一轮算天气，重试。始终不通 ⇒ 报「夹具失效」。
        why, instrument_live = None, False
        for _i in range(_W05_TRIES):
            why = _w05_bind_attempt(SV, held, hub)
            if why is None:
                break
            if _W05_OWNER_MARK not in why:
                break                       # 真缺陷（非天气项）⇒ 一次即红
            live, _probe = _w05_owner_probe(held)
            instrument_live = instrument_live or live
            if live:
                break                       # 仪表通、产品却没报 ⇒ **真缺陷**
        if why is not None:
            if _W05_OWNER_MARK in why and not instrument_live:
                return ("%s：`_port_owner(%d)` 连 %d 轮都取不到占用方"
                        "（Windows `netstat -ano` / POSIX `lsof`，是**外部子进程**，"
                        "高负载下会取不到）—— **这是量具失效，不是产品缺陷**；"
                        "本条**测不出**，不许报通过，请重跑。"
                        % (_W05_FIXTURE_DEAD, held, _W05_TRIES))
            return why
        # ② 出声（stderr）＋ 落盘（url.json 带 want_port）
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            h2, _t2, got2, drift2 = SV._serve_setup(held, hub, token="T2")
        try:
            if not drift2:
                return "`_serve_setup` 没把漂移传出来（判据拿不到观测点）"
            msg = buf.getvalue()
            for need in (str(held), str(got2), str(os.getpid())):
                if need not in msg:
                    # ★★ X-019：三项里**只有「占用方 pid」**可能是**仪表失效**
                    #   （`console_drift_note` 查不到占用方时会明说「进程号没查到」）。
                    #   此刻仪表不通 ⇒ 报「夹具失效」，**不许**算产品缺陷。
                    if need == str(os.getpid()):
                        live, _p = _w05_owner_probe(held)
                        if not live:
                            return ("%s：`_port_owner(%d)` 此刻取不到占用方 ⇒ "
                                    "stderr 那句话里没有 pid **不能算产品缺陷**"
                                    "（量具失效，本条测不出，请重跑）"
                                    % (_W05_FIXTURE_DEAD, held))
                    return ("端口被占时 stderr 那句话没说全（缺 %r）：%r"
                            % (need, msg))
            rec = SV.read_console_record(hub)
            if (rec or {}).get("port") != got2:
                return "落盘记录里的端口不是实际端口：%r" % (rec,)
            if (rec or {}).get("want_port") != held:
                return ("落盘记录没留下「想要哪个端口」（want_port=%r）—— "
                        "漂移在盘上没痕迹" % ((rec or {}).get("want_port"),))
        finally:
            h2.server_close()
        # ③ 托盘提示带实际端口（读同一份落盘）
        SV.write_console_record(8799, "tok-tip", pid=os.getpid(), root=hub)
        payload = TR.sync_from_items([_mk("R0", "unread", 1, 1.0)], root=hub,
                                     posture=_POSTURE)
        if "8799" not in (payload.get("tip") or ""):
            return "托盘提示没带实际端口：%r" % (payload.get("tip") or "")
        # 没有落盘记录 ⇒ **不编**一个端口
        hub2 = tempfile.mkdtemp(prefix="g0490_w05b_")
        payload2 = TR.sync_from_items([_mk("R0", "unread", 1, 1.0)], root=hub2,
                                      posture=_POSTURE)
        if "端口" in (payload2.get("tip") or ""):
            return "没有落盘记录却编了一个端口：%r" % (payload2.get("tip") or "")
    finally:
        holder.shutdown()
    return None


def _w05_negctl_guard(r):
    """负控子块的前置闸：**夹具失效时不许继续判「咬没咬对地方」**（X-019）。

    ★★ 为什么（2026-10-13）：`_w05_assert()` 报「夹具失效」时，N-W05 的职责
      **不是**继续比 `"没说全" not in r` —— 那会把**量具故障**说成
      **负控设计错误**（T-08「查不到就下结论」复发在负控层），
      而且更坏：夹具失效时那几条断言**照样"命中"**，负控于是**假装通过了**。
      ⇒ 返回非空串 ⇒ 直接当 N-W05 的结论（本条**测不出**，不许报通过）；
        返回 `None` ⇒ 夹具活着，继续按原逻辑判。
    """
    if r is not None and _W05_FIXTURE_DEAD in r:
        return ("夹具失效（**不是**负控设计问题）：`_port_owner()` 取不到占用方 —— "
                "本条负控**测不出**，不许报通过；请重跑。")
    return None


@check("W-05 ★ B2：端口被占不再静默 —— 报漂移 / stderr 出声 / 落盘 / 托盘带端口")
def w05():
    r = _w05_assert()
    if r is not None:
        return r
    return True


@check("N-W05 负控：静默漂移 / 不说占用方 / 托盘不带端口 ⇒ W-05 必须红")
def n_w05():
    """反向对照（维二）：三个变异体＝B2 的三个真缺陷形状，逐个必须被 W-05 抓到。

    ① `_bind_first_free` 换了端口却**不报 drift**（＝B2 缺陷本身：静默换端口）；
    ② `console_drift_note()` 说「被占用」但**不点占用方 pid**（说了等于没说）；
    ③ 托盘提示**不带实际端口**（用户手输 8790 打不开，还是不知道点哪）。

    ★★ X-019：每个子块先过 `_w05_negctl_guard()` —— 夹具失效（仪表取不到占用方）
      时**直接判测不出**，不许让"夹具坏了"冒充"负控咬错了地方"（更不许冒充通过）。
    """
    src = _src(_SERVER_REL)
    # ① 静默漂移：把 drift 一律抹成 None
    a_keep = ('    if drift is not None:\n        drift["got"] = int(real_port)\n'
              '    return httpd, token, real_port, drift')
    a_mut = '    return httpd, token, real_port, None          # ← MUTANT（静默换端口）'
    if a_keep not in src:
        return "变异锚点未找到（_bind_first_free 已变）—— 负控自身失效，不算通过"
    mut = _load(src.replace(a_keep, a_mut), "is0490_nw05a", _SERVER_REL)
    saved = _mod_patch("inbox_server", mut)
    try:
        r = _w05_assert()
        _dead = _w05_negctl_guard(r)
        if _dead:
            return _dead
        if r is None:
            return "换了端口却不报 drift，W-05 仍判通过 ⇒ 判据没在看「漂移有没有被报出来」"
        if "没报漂移" not in r:
            return "负控咬错了地方：红的应是「漂移没被报出来」，实得 %r" % r[:60]
    finally:
        saved()
    # ② 出声但不点占用方 pid
    b_keep = ('    who = ("被 PID %d 占用" % owner) if owner else '
              '"已被别的程序占用（占用方进程号没查到）"')
    b_mut = '    who = "已被占用"          # ← MUTANT（不说占用方 pid）'
    if b_keep not in src:
        return "变异锚点未找到（console_drift_note 已变）—— 负控自身失效，不算通过"
    mut2 = _load(src.replace(b_keep, b_mut), "is0490_nw05b", _SERVER_REL)
    saved2 = _mod_patch("inbox_server", mut2)
    try:
        r = _w05_assert()
        _dead = _w05_negctl_guard(r)
        if _dead:
            return _dead
        if r is None:
            return "漂移出声不点占用方 pid，W-05 仍判通过 ⇒ 判据没在看那句话说了什么"
        if "没说全" not in r:
            return "负控咬错了地方：红的应是「stderr 那句没说全」，实得 %r" % r[:60]
    finally:
        saved2()
    # ③ 托盘提示不带实际端口
    tsrc = _src("inbox_tray.py")
    c_keep = ('    if tip is not None:\n        _port = console_port(root)\n'
              '        if _port:\n            tip = "%s · 端口 %d" % (tip, _port)')
    c_mut = '    pass          # ← MUTANT（托盘提示不带实际端口）'
    if c_keep not in tsrc:
        return "变异锚点未找到（sync_from_items 已变）—— 负控自身失效，不算通过"
    tmut = _load(tsrc.replace(c_keep, c_mut), "is0490_nw05c", "inbox_tray.py")
    saved3 = _mod_patch("inbox_tray", tmut)
    try:
        r = _w05_assert()
        _dead = _w05_negctl_guard(r)
        if _dead:
            return _dead
        if r is None:
            return "托盘提示不带实际端口，W-05 仍判通过 ⇒ 判据没在看托盘提示"
        if "托盘提示没带实际端口" not in r:
            return "负控咬错了地方：红的应是「托盘提示没带端口」，实得 %r" % r[:60]
    finally:
        saved3()
    return True


@check("N-W05b 夹具自证：仪表恒盲 ⇒ 报「夹具失效」；仪表通而值错 ⇒ 报真缺陷（X-019）")
def n_w05b():
    """反向对照（X-019）：**量具故障不许冒充产品缺陷，真缺陷也不许被当成天气放过**。

    三条对照，全是**行为**（不查行号、不看字面）：
      ① **仪表恒盲**（源变异：`_port_owner` 一律返回 None ＝ 高负载下 netstat/lsof
         取不到信号的形状）⇒ `_w05_assert()` 必须报**「夹具失效」**，
         **不许**报「漂移没点出占用方进程号」—— 后者正是 X-019 的缺陷本体
         （把机器天气说成产品缺陷）。
      ② **仪表通而值错**（源变异：恒返回一个错 pid）⇒ 必须回到**真缺陷红**
         （「占用方进程号」），**不许**报「夹具失效」—— 否则条件断言把真缺陷一起放过了。
      ③ **负控闸** `_w05_negctl_guard()` 三条：夹具失效 ⇒ 拦住（不许继续判"咬错地方"、
         更不许假装通过）；`None`（夹具正常）⇒ 不拦；**真缺陷串 ⇒ 不拦**。

    ★ 为什么不在这里跑整条 `n_w05()` 去验「夹具失效时负控不许报通过」：
      `n_w05()` 的变异体是**从磁盘原始源现造**的（自带一份好的 `_port_owner`），
      所以它这一轮本来就**该**正常通过 —— 拿它来验"夹具失效"是**测错对象**
      （本仓已犯过两次的同型错）。⇒ 直接验那道闸本身，判的是同一件事。
    """
    src = _src(_SERVER_REL)
    # 锚点：`_port_owner` 的开头三行（`if not port` / `try` / `if os.name == "nt"`）
    keep = ('    if not port:\n        return None\n    try:\n'
            '        if os.name == "nt":')
    if keep not in src:
        return "变异锚点未找到（_port_owner 已变）—— 负控自身失效，不算通过"

    # ① 仪表恒盲
    blind = _load(src.replace(keep, "    return None      # ← MUTANT（仪表恒盲）\n" + keep, 1),
                  "is0490_nw05b_blind", _SERVER_REL)
    saved = _mod_patch("inbox_server", blind)
    try:
        r = _w05_assert()
    finally:
        saved()
    if not isinstance(r, str) or _W05_FIXTURE_DEAD not in r:
        return ("仪表恒盲时 W-05 没报「夹具失效」，实得 %r —— "
                "**这正是 X-019**：量具故障被当成产品缺陷"
                % (r if r is None else r[:70],))

    # ② 仪表通而值错（不是天气）
    wrong = _load(src.replace(keep, "    return 999999    # ← MUTANT（仪表通但值错）\n" + keep, 1),
                  "is0490_nw05b_wrong", _SERVER_REL)
    saved2 = _mod_patch("inbox_server", wrong)
    try:
        r2 = _w05_assert()
    finally:
        saved2()
    if not isinstance(r2, str) or _W05_OWNER_MARK not in r2 or _W05_FIXTURE_DEAD in r2:
        return ("仪表通而值错时 W-05 没报真缺陷（实得 %r）—— "
                "条件断言把真缺陷一起放过了" % (r2 if r2 is None else r2[:70],))

    # ③ 负控闸三条对照
    g1 = _w05_negctl_guard("夹具失效：`_port_owner(1234)` 连 3 轮都取不到占用方 —— 请重跑。")
    if not g1 or _W05_FIXTURE_DEAD not in g1:
        return ("「夹具失效」的结论喂给负控闸时没被拦住（实得 %r）—— "
                "负控会在夹具坏掉时继续判「咬错地方」，甚至假装通过" % (str(g1)[:70],))
    if _w05_negctl_guard(None) is not None:
        return "负控闸把「夹具正常（结论 None）」也拦住了 ⇒ 正常路径被误伤"
    if _w05_negctl_guard("漂移没点出占用方进程号：owner=999999（应 123）") is not None:
        return "负控闸把「真缺陷红」也拦住了 ⇒ 真缺陷会被当成夹具失效放过"
    return True


# ════════════════════ W-06 · 遗留问题 B3（口令不进 URL）════════════════
#: ★★ 盯的已修缺陷：**B3 口令在 URL query 里** —— 主 URL `/?t=<口令>`、每个页签
#:   链接 `/?v=…&t=<口令>`、favicon/logo 的 `?t=<口令>`。口令因此进了浏览器历史、
#:   Referer、地址栏与截图；点一次按钮（303 重定向）还会把它写回地址栏。
#:   修法（产品侧 inbox_server.py）：首字节带 `?t=` 的那次下发一枚
#:   `HttpOnly; SameSite=Strict; Path=/` 的 cookie，此后**所有**站内导航与
#:   子资源都靠它；页面上**不再有任何带口令的 URL**。旧 URL `/?t=…` 继续可用
#:   （维八：不破旧账 —— 书签/`url.json` 里的老链接照常打开）。


def _w06_http(port, path, headers=None):
    """发一个**真** HTTP 请求，返回 `(status, headers_lower, body_text)`。"""
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        return (r.status, {k.lower(): v for k, v in r.getheaders()},
                r.read().decode("utf-8", "replace"))
    finally:
        c.close()


def _w06_assert():
    """W-06 正判据（正/负控共用）。返回 `None`＝过，否则说明串。

    四个现场：
      ① **渲染页里零「带口令的 URL」**：四个视图的 `href`/`src` 都不含 `t=`
         （表单 hidden `t` 与 JS 的 `data-token` 是 **POST body**，不算 URL，
         不在范围内 —— B3 的题面就是"口令在 URL query 里"）；
      ② **旧 URL 继续可用**（维八）：`/?t=<口令>` 仍返回 200；
      ③ **cookie 能过守卫**：用 ② 拿到的 cookie（不带 `?t=`／不带请求头／
         不带 body）请求别的页 ⇒ 200；
      ④ **首次下发的是 `HttpOnly; SameSite=Strict; Path=/`**；且**不带任何
         凭证**的请求被拒且**出声**（不是干看着）。
    """
    import inbox_server as SV
    # ① 四个视图：链接里零口令（★ 用**当前** `sys.modules` 里的那份 —— 负控要靠它）
    bad = []
    for v in _VIEWS:
        h = _page(v, mod=SV)
        for m in re.finditer(r'(?:href|src)="([^"]*)"', h):
            if re.search(r"[?&]t=", m.group(1)):
                bad.append("%s: %s" % (v, m.group(1)[:60]))
    if bad:
        return "渲染页里仍有带口令的 URL：%s" % "; ".join(bad[:3])
    # ②③④ 真起服务走一遍
    tok = "w06-tok"
    httpd, port = _w04_serve_inline(tok)
    try:
        st, hd, _b = _w06_http(port, "/?t=%s" % tok)
        if st != 200:
            return "旧 URL（`/?t=…`）不再可用：HTTP %d（维八：不破旧账）" % st
        sc = hd.get("set-cookie") or ""
        if not sc:
            return "首字节没下发 Set-Cookie —— 链接里摘掉口令后就没有凭证了"
        low = sc.replace(" ", "").lower()
        if "httponly" not in low:
            return "Set-Cookie 缺 HttpOnly（脚本读得到 ⇒ XSS 可偷）：%r" % sc
        if "samesite=strict" not in low:
            return "Set-Cookie 缺 SameSite=Strict（跨站请求会带上 ⇒ CSRF）：%r" % sc
        if "path=/" not in low:
            return "Set-Cookie 缺 Path=/（站内子路径收不到）：%r" % sc
        ck = sc.split(";")[0].strip()
        st2, _h2, b2 = _w06_http(port, "/?v=report", headers={"Cookie": ck})
        if st2 != 200:
            return "带 cookie 请求其它页没通过：HTTP %d（cookie 没被认）" % st2
        if '<header class="bar">' not in b2:
            return "带 cookie 拿到的不是Antinel 监理页面"
        st3, _h3, b3 = _w06_http(port, "/?v=report")
        if st3 != 403:
            return "不带任何凭证的请求没被拒：HTTP %d" % st3
        if "口令" not in b3:
            return "被拒页面没说清原因（应点明口令/凭证）"
    finally:
        httpd.shutdown()
    return None


@check("W-06 ★ B3：口令不进 URL —— 链接零 t= / cookie 能过 / 首次下发 HttpOnly")
def w06():
    r = _w06_assert()
    if r is not None:
        return r
    return True


@check("N-W06 负控：链接放回 t= / 不认 cookie / 去掉 HttpOnly ⇒ W-06 必须红")
def n_w06():
    """反向对照（维二）：三个变异体＝B3 要修的那三个形状，逐个必须被 W-06 抓到。

    ① 把 `&t=` 放回页签链接（＝B3 缺陷本身：口令跟着 URL 走）；
    ② `_guard` 不认 cookie（只剩 query/请求头/body ⇒ 链接摘了口令就进不去）；
    ③ 下发的 cookie 去掉 `HttpOnly`（脚本读得到 ⇒ XSS 可偷）。
    """
    src = _src(_SERVER_REL)
    # ① 页签链接放回 `&t=`
    a_keep = '        return "<a href=\\"/?v=%s\\"%s>%s</a>" % (v, cls, label)'
    a_mut = ('        return "<a href=\\"/?v=%s&t=%s\\"%s>%s</a>"'
             ' % (v, _esc(token), cls, label)')
    if a_keep not in src:
        return "变异锚点未找到（_tabs 已变）—— 负控自身失效，不算通过"
    mut = _load(src.replace(a_keep, a_mut), "is0490_nw06a", _SERVER_REL)
    saved = _mod_patch("inbox_server", mut)
    try:
        r = _w06_assert()
        if r is None:
            return "链接放回 `&t=`，W-06 仍判通过 ⇒ 判据没在看「URL 里有没有口令」"
        if "带口令的 URL" not in r:
            return "负控咬错了地方：红的应是「链接里带口令」，实得 %r" % r[:60]
    finally:
        saved()
    # ② 不认 cookie（`_guard` 只剩 query/请求头/body 三个来源）
    b_keep = '_cookie_token(self.headers.get("Cookie"))'
    b_mut = '""'
    if b_keep not in src:
        return "变异锚点未找到（_guard 已变）—— 负控自身失效，不算通过"
    mut2 = _load(src.replace(b_keep, b_mut), "is0490_nw06b", _SERVER_REL)
    saved2 = _mod_patch("inbox_server", mut2)
    try:
        r = _w06_assert()
        if r is None:
            return "不认 cookie，W-06 仍判通过 ⇒ 判据没在真发一个 cookie 请求"
        if "cookie" not in r:
            return "负控咬错了地方：红的应是「cookie 没被认」，实得 %r" % r[:60]
    finally:
        saved2()
    # ③ 去掉 HttpOnly
    c_keep = '"%s=%s; HttpOnly; SameSite=Strict; Path=/"'
    c_mut = '"%s=%s; SameSite=Strict; Path=/"'
    if c_keep not in src:
        return "变异锚点未找到（_send 的 Set-Cookie 已变）—— 负控自身失效，不算通过"
    mut3 = _load(src.replace(c_keep, c_mut), "is0490_nw06c", _SERVER_REL)
    saved3 = _mod_patch("inbox_server", mut3)
    try:
        r = _w06_assert()
        if r is None:
            return "去掉 HttpOnly，W-06 仍判通过 ⇒ 判据没在看 Set-Cookie 的属性"
        if "HttpOnly" not in r:
            return "负控咬错了地方：红的应是「缺 HttpOnly」，实得 %r" % r[:60]
    finally:
        saved3()
    return True


# ══════════════ C1 · 负控模板化（守「量具的量具」）══════════════
def _c1_scan(text):
    """扫出**负控块里裸渲染变异模块**的地方。返回违规负控名列表。

    ★ 为什么扫源码文本：这是**元判据**（守量具的量具），与 D-31（守登记簿）、
      D-27/D-28（守量具）同族。
    ★★ 为什么用 `ast` 而不是正则（2026-10-13 实测踩到）：
      正则会**把字符串字面量里**的 `mut.render_page(` 也当成真调用 ——
      N-C-01 的变异文本里正有这一句，于是 C-01 **把自己人咬了**（首跑 2 红）。
      `ast` 只看**真的 Call 节点**，字符串里的文本不算。
    ★ 只扫 `@check("N-…")` 装饰的函数 —— 正判据里的 `_page(...)` 是**真实现**渲染，
      本来就该直调；`_mut_render` 自己的函数体不带 `@check`，天然不在扫描范围。
    """
    import ast as _ast
    tree = _ast.parse(text)
    offenders = []
    for node in tree.body:
        if not isinstance(node, _ast.FunctionDef):
            continue
        name = None
        for dec in node.decorator_list:
            if (isinstance(dec, _ast.Call) and isinstance(dec.func, _ast.Name)
                    and dec.func.id == "check" and dec.args
                    and isinstance(dec.args[0], _ast.Constant)):
                name = dec.args[0].value
        if not isinstance(name, str) or not name.startswith("N-"):
            continue
        for sub in _ast.walk(node):
            if (isinstance(sub, _ast.Call)
                    and isinstance(sub.func, _ast.Attribute)
                    and sub.func.attr == "render_page"):
                offenders.append(name.split()[0])
                break
    return offenders


@check("C-01 ★ 负控模板化：渲染型负控必须走 _mut_render（两步法第一步）")
def c1_01():
    """★★ C1（2026-10-13）：负控的变异渲染必须经 `_mut_render`。

    要防的复发（C1 交接件 §C1）：负控把**自己的**故障（变异写坏参数 ⇒ 渲染抛
    `TypeError`）报成了**产品红** —— 量具故障伪装成产品问题，人得读 traceback
    才分辨得出。两步法第一步「能 import ＋ 最小渲染不抛」不过 ⇒ 明确判
    「负控自身失效，不算通过」。

    ★ 断言（**结构**，不查文案）：本文件里**任何**负控块都不许出现裸的
      `mut.render_page(`／`mut2.render_page(` —— 必须全部经 `_mut_render`。
    """
    me = io.open(os.path.abspath(__file__), encoding="utf-8").read()
    if "_mut_render(" not in me:
        return "找不到 `_mut_render` —— C1 的两步模板被删了（负控又会把量具故障当产品红）"
    bad = _c1_scan(me)
    if bad:
        return ("这些负控仍**直接**渲染变异模块（未经 _mut_render 的前置断言）：%s"
                % "、".join(bad))
    return True


@check("N-C-01 负控：把一处 _mut_render 换回裸 mut.render_page ⇒ C-01 必须红")
def n_c1_01():
    """反向对照（维二）：把一条负控的 `_mut_render(...)` 换回**裸渲染** ⇒
    元判据必须抓到。★ 证明 `_c1_scan` 真的会响（不是永远绿的装饰）。

    ★ 注入：把**第一处** `page, _why = _mut_render(` 换回 `page = mut.render_page(`
      —— 正是 C1 之前那 12 处的原貌（`_why` 那行仍在，但本判据只扫文本，不影响）。
    """
    me = io.open(os.path.abspath(__file__), encoding="utf-8").read()
    anchor = "    page, _why = _mut_render("
    if anchor not in me:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut_src = me.replace(anchor, "    page = mut.render_page(", 1)
    if _c1_scan(me):
        return "夹具不成立：真源本身就有裸渲染 ⇒ 负控无分辨力"
    if not _c1_scan(mut_src):
        return ("负控失效：换回裸渲染后 `_c1_scan` 仍报无违规 ⇒ 元判据是装饰"
                "（C1 的守护没人真守）")
    return True


# ══════════════ U-16 · C5（问号全站同形：字隐藏、徽章保留）══════════════
#: ★★ 盯的已修缺陷：**C5 —— 本轮自己引入**（0.48.5 乙1，commit `264c67b`）：
#:   铺裸「？」芯片时，实现写成 `.term.mk>summary::after{content:none;display:none}`
#:   —— **把徽章整个关掉**，比交接件 §5.6 定稿（"summary 只渲染 CSS 的「？」徽章"）
#:   多做了一步。后果：8 个新落点退化成**裸文字「？」**（无圆圈、字号继承容器：
#:   药丸 12px／顶部灯 16px 粗体／筛选条 12px），与页内原有「词名＋小圆徽章」
#:   **同屏两种形状**。实测四页并存：收件箱 0+8／日报 8+4／运行状态 4+4／账本 7+4。
#:   创始人判定「原先更小又有圆背景的更好」。
#:   修法（产品侧）：`font-size:0` 藏掉 summary 自身的字（**不占宽度**、不出字距空洞），
#:   `::after` 徽章照旧（14×14 圆、10px、写死字号）⇒ **全站同一种形状**。
#:   ★ 两个相邻错法也一并锁（修好一个又搞出另一个，正是本轮在防的事）：
#:     · 用 `display:none` 藏字 ⇒ `<summary>` 整个消失，芯片**点不开**；
#:     · 用 `color:transparent` 藏字 ⇒ 字仍占宽度，「？」与徽章之间多个字距空洞。
_U16_TERM_AFTER = re.compile(r"([^{}]*summary::after)\{([^{}]*)\}")
_U16_MK_SUM = re.compile(r"(\.term\.mk>summary)\{([^{}]*)\}")
_U16_BASE_AFTER = re.compile(r"\.term>summary::after\{([^{}]*)\}")


def _u16_findings(page):
    """问号形状契约的**全部**违规点（空 list ＝ 合规）。

    ★ 为什么抽成共用尺子：`u16`（正判据）与 `n_u16`（负控）必须量**同一份**
      契约 —— 各写一套就会出现"正判据说红、负控说没红"的各说各话，
      **量具之间不一致比量具不存在更坏**（本仓铁律）。
    ★ 样式断言一律经 `PC.chrome(...)`（C2 纪律；它已剥 CSS 注释 ——
      U-16 的说明文字里就复述着 C5 的旧缺陷原文，不剥会被自己人误红）。
    """
    css = PC.chrome(page)
    bad = []
    # ① 徽章不许被关掉：管 term summary ::after 的规则，content 必须是"？"
    for sel, body in _U16_TERM_AFTER.findall(css):
        if "term" not in sel:
            continue
        flat = body.replace(" ", "").replace("\n", "")
        if "content:none" in flat or "display:none" in flat:
            bad.append("徽章被关掉：%s{%s} ⇒ mk 芯片退化成裸文字「？」"
                       % (sel.strip(), flat[:60]))
        elif 'content:"？"' not in flat:
            bad.append("term 的 ::after 不渲染「？」徽章：%s{%s}"
                       % (sel.strip(), flat[:60]))
    # ② mk summary 自身的字必须藏掉（否则屏幕「？？」：自身一个字 ＋ 徽章一个字）
    mk = _U16_MK_SUM.findall(css)
    if not mk:
        bad.append("缺 `.term.mk>summary{...}` —— mk 芯片的自身字没藏 ⇒「？？」")
    for _sel, body in mk:
        flat = body.replace(" ", "").replace("\n", "")
        if "display:none" in flat:
            bad.append("`.term.mk>summary` 用 display:none 藏字 ⇒ summary 整个消失，"
                       "芯片点不开了：%s" % flat[:60])
        elif "font-size:0" not in flat:
            # 没藏字 ⇒ 屏幕「？？」。**指名到姓**：只换 color:transparent 的话，
            # 字看不见但仍占宽度，「？」与徽章之间会多出一个字距空洞。
            if "color:transparent" in flat:
                bad.append("没藏字：只用 color:transparent ⇒ 字仍占宽度，"
                           "「？」与徽章之间有字距空洞：%s" % flat[:60])
            else:
                bad.append("没藏字（缺 font-size:0）⇒ 屏幕「？？」：%s" % flat[:60])
    # ③ 基础徽章形态契约：**只准一处定义**，且必须是 14×14 圆 ＋ 10px ＋ 圆背景
    #    （创始人判定的"更小又有圆背景"）；`.term[open]` 换色那条是**同源**，不算第二处。
    base = _U16_BASE_AFTER.findall(css)
    if len(base) != 1:
        bad.append("基础徽章 `.term>summary::after` 有 %d 处定义（应恰好 1 处）"
                   % len(base))
    else:
        flat = base[0].replace(" ", "").replace("\n", "")
        for need in ('content:"？"', "width:14px", "height:14px",
                     "font-size:10px", "border-radius:50%"):
            if need not in flat:
                bad.append("基础徽章缺 %s（14×14 圆、10px、圆背景是定稿形态）"
                           % need)
    # ④ 渲染面：芯片真的在页面上（否则上面的 CSS 断言是对空气打分）
    chips = re.findall(r'<details class="term mk"[^>]*><summary>([^<]*)</summary>',
                       page)
    if not chips:
        bad.append("页面上一颗 mk 芯片都没有 ⇒ CSS 契约空转（U-04 的落点丢了）")
    elif any(c != "？" for c in chips):
        bad.append("mk 芯片的 summary 不是单个「？」：%r" % (sorted(set(chips)),))
    return bad


@check("U-16 ★ C5：问号全站同形 —— 字隐藏、徽章保留（14×14 圆 / 10px）")
def u16():
    """C5（本轮自己引入）：见本节表头。四页全扫 —— 每页都有自己的芯片集，
    只测一页的话，另外三页的落点退化了也没人知道（实测它本来就是四页并存）。
    """
    bad = []
    for view in _VIEWS:
        for f in _u16_findings(_page(view)):
            bad.append("%s 页：%s" % (view, f))
    if bad:
        return "问号形状不合规 %d 处：%s" % (len(bad), "；".join(bad[:3]))
    return True


@check("N-U16 负控：关徽章 / 不藏字 / 用 display:none ⇒ U-16 必须各各红")
def n_u16():
    """反向对照（维二）：**撤销修复即变红**，三个变体逐一实测。

    ★ 为什么必须三个臂：C5 本体是"关掉徽章"，但同一处契约还有两个相邻错法
      （字不藏 ⇒「？？」；display:none 藏 ⇒ 点不开）。只测一个臂，
      另外两个错法就没有尺子量 —— "修好旧问题又搞出新问题"正是这么发生的。
    ★ 另加**夹具自证**：真实现必须本来就不合规（否则负控无分辨力）。
    """
    src = _src(_SERVER_REL)
    anchor = (".term.mk>summary{font-size:0;line-height:0;"
              "color:transparent;letter-spacing:0}")
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    kw = dict(view="inbox", filt=M.BUCKET_ACTION,
              root=tempfile.mkdtemp(prefix="g0490_nu16_"),
              token="T", items=_items(), posture=_POSTURE)
    # ① C5 原貌：把徽章关掉（content:none + display:none 原样加回）
    arms = [
        ("关掉徽章（C5 原貌）",
         src.replace(anchor,
                     ".term.mk>summary::after{content:none;display:none}\n"
                     + anchor, 1),
         "徽章被关掉"),
        # ② 字不藏：去掉 font-size:0（保留其余 ⇒ 只撤掉"藏字"这一味药）
        ("不藏字（「？？」）",
         src.replace(anchor,
                     ".term.mk>summary{line-height:0;color:transparent;"
                     "letter-spacing:0}", 1),
         "没藏字"),
        # ③ 换错药：用 display:none 藏 ⇒ 芯片点不开
        ("用 display:none 藏字",
         src.replace(anchor, ".term.mk>summary{display:none}", 1),
         "display:none"),
    ]
    live = _u16_findings(_page("inbox"))
    if live:
        return "夹具不成立：真实现本身就不合规（C5 复发或判据写错）：%r" % (live[:2],)
    for i, (name, mutated, want_sub) in enumerate(arms):
        if mutated == src:
            return "负控 %d（%s）注入没生效：变异后源码一字未变" % (i + 1, name)
        page, _why = _mut_render(mutated, "is0490_nu16_%d" % i, _SERVER_REL, **kw)
        if _why:
            return _why
        got = _u16_findings(page)
        if not any(want_sub in g for g in got):
            return ("负控失效：%s 之后尺子仍报合规（应命中 %r，实得 %r）"
                    % (name, want_sub, got[:3]))
    return True


# ══════════════ W-07 · C4（一次性调用方自己等窗就位，真进程实测）══════════════
#: ★★ 盯的已修缺陷：**C4（T-10 静默降级）** —— `_place_if_needed()` 把落位放在
#:   `daemon=True` 线程里。对**长命**进程（服务自己开窗：`threading.Timer(0.6,
#:   open_console)`）没问题；对**一次性**调用方是致命的：`inbox_cli.py window`
#:   （＝`antinel.cmd` 一键入口）进程 2 秒就退 ⇒ daemon 线程随进程死，
#:   而 Edge 建窗实测要 1–2.5s ⇒ **落位从未执行**，且屏幕上什么都不说。
#:   两臂探针实证（只差进程寿命）：CLI 形状 `place_all` **0** 次／长命 **1** 次。
#:   根因提交 `aa3eeff`（0.36.8）—— **存量缺陷，非本轮引入**。
#:   修法（产品侧）：`open_console_settled()` —— 开窗、轮询等它出现、落位、
#:   回读校验，回一份如实报告；`open_console()` 契约一字不改（服务路径不受影响）。

#: 判据侧的夹具参数（与 `_W07_CHILD` 里的假窗口**逐字对应**；探针会把它们
#: 回传，判据先核对再断言 —— 漂移就大声报，不许默默对空气打分）。
_W07_RECT = (100, 100, 520, 640)
_W07_APPEAR = 2.5


_W07_CHILD = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""W-07 探针：在**一次性进程**里走Antinel 监理开窗路径，验"落位真的被执行"。

用法：w07_child.py <ROOT> <MODE> <WAIT_SEC> <URL>
  MODE=settled  走 `open_console_settled`（C4 修法；`inbox_cli window` 用的就是它）
  MODE=bare     只调 `open_console` 就退（C4 **原貌**：落位在 daemon 线程里）
  MODE=never    窗口永不出现 ⇒ 必须如实报"没看到"，不许谎报成功
stdout 最后一行是 JSON：{"rep":…, "calls":…, "fixture":…}

★★ 为什么必须起**真进程**（而不是在判据自己进程里调）：
   C4 的病型**只在进程寿命短时发作** —— 落位跑在 daemon 线程里，进程一死
   线程跟着死。判据自己的进程是长命的，在那里调 `open_console_settled`，
   daemon 线程不会死 ⇒ **缺陷被掩盖**，量具永远绿（比恒红更坏的那类）。
   ⇒ 子进程打完报告**立刻 `os._exit`**，与 `antinel inbox window` 同形状。
★★ 为什么假窗口要**延迟 2.5 秒**才出现（`_p_c4_probe.py` 首版教训：
   fixtures 不忠实比没有 fixtures 更坏）：第一次轮询就在的话，负控臂
   （bare）也可能"碰巧"落位 ⇒ 尺子失去分辨力。延迟出现 ⇒ bare 臂在窗口
   出现之前就退，落位必 0 次，正负两臂才真正只差"有没有等它就位"。
"""
import json
import os
import sys
import tempfile
import time
import types

ROOT, MODE, WAIT = sys.argv[1], sys.argv[2], float(sys.argv[3])
URL = sys.argv[4]
sys.path.insert(0, ROOT)
os.environ.pop("ANTINEL_AUDIT_DIRS", None)
os.environ["ANTINEL_HUB_DIR"] = tempfile.mkdtemp(prefix="w07hub_")

RECT = (100, 100, 520, 640)
APPEAR_AFTER = 2.5
CALLS = {"find": 0, "place": 0, "rect": 0, "popen": 0,
         "first_find_empty": None}
_T0 = [0.0]


def console_geometry():
    return {"ok": True, "rect": RECT, "reason": ""}


def console_profile_dir():
    return None


def build_run_id(token):
    return "w07probe"


def console_title_suffix(run_id):
    return "#w07probe"


def close_console_windows():
    return 0


def wait_console_windows_gone():
    return True, 0


def window_size_str(rect):
    return "%d,%d" % (rect[2], rect[3])


def window_position_str(rect):
    return "%d,%d" % (rect[0], rect[1])


def find_console_windows(suffix=None, run_id=None):
    CALLS["find"] += 1
    up = time.time() - _T0[0] >= APPEAR_AFTER
    if CALLS["first_find_empty"] is None:
        CALLS["first_find_empty"] = not up
    if MODE == "never":
        return []
    return [0x1001] if up else []


def place_all(hwnds, rect):
    CALLS["place"] += 1
    return True, "已落到 %r" % (rect,)


def window_rect_of(h):
    CALLS["rect"] += 1
    return RECT


_fake = types.ModuleType("inbox_window")
for _k in ("console_geometry", "console_profile_dir", "build_run_id",
           "console_title_suffix", "close_console_windows",
           "wait_console_windows_gone", "window_size_str",
           "window_position_str", "find_console_windows", "place_all",
           "window_rect_of"):
    setattr(_fake, _k, globals()[_k])
sys.modules["inbox_window"] = _fake

import inbox_server as SV                                  # noqa: E402


class _Popen(object):
    """只记录"真的被请求开窗了"，绝不起真浏览器。"""

    def __init__(self, *a, **k):
        CALLS["popen"] += 1


SV.subprocess = types.SimpleNamespace(
    Popen=_Popen, DEVNULL=-3, CREATE_NO_WINDOW=0)
SV.webbrowser = types.SimpleNamespace(open=lambda url: True)

_T0[0] = time.time()
if MODE == "settled":
    rep = SV.open_console_settled(URL, wait_sec=WAIT)
elif MODE == "bare":
    rep = {"opened": SV.open_console(URL), "placed": False, "want": None,
           "got": [], "why": "（负控臂：只调 open_console，不等就退 —— C4 原貌）"}
else:
    rep = SV.open_console_settled(URL, wait_sec=WAIT)
sys.stdout.write(json.dumps({"rep": rep, "calls": CALLS,
                             "fixture": {"rect": list(RECT),
                                         "appear_after": APPEAR_AFTER}}) + "\n")
sys.stdout.flush()
os._exit(0)
'''


def _run_w07_child(mode, wait):
    """起一个**真进程**跑 W-07 探针。返回 {"rep","calls","fixture","err"}。

    `err` 非空 ⇒ **量具故障**（子进程崩了/没吐 JSON/夹具漂移/预算不够），
    调用方必须当红上报，**不许**当成"探针说没问题"。
    """
    import json
    import subprocess
    # ★ never 臂**故意**让窗口不出现，预算小于"出现时刻"正是它的形状；
    #   其余两臂（要等到窗口）的预算必须宽于 2.5s，否则量表自己把答案截断了。
    if mode != "never" and wait <= _W07_APPEAR + 0.5:
        return {"err": "预算 %.1fs 不够（窗口 %.1fs 才出现）—— 判据自己把量表设小了"
                % (wait, _W07_APPEAR)}
    d = tempfile.mkdtemp(prefix="g0490_w07_")
    child = os.path.join(d, "w07_child.py")
    with io.open(child, "w", encoding="utf-8") as f:
        f.write(_W07_CHILD)
    env = dict(os.environ)
    env["ANTINEL_HUB_DIR"] = d                       # 隔离：子进程别碰真中枢
    try:
        r = subprocess.run(
            [sys.executable, child, ROOT, mode, "%.1f" % wait,
             "http://127.0.0.1:8790/?t=w07"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=120, env=env, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return {"err": "探针子进程超时（>120s）—— 量具故障，不算通过也不算红"}
    if r.returncode != 0:
        return {"err": "探针子进程 rc=%d：%s"
                % (r.returncode, (r.stderr or "")[-300:])}
    try:
        st = json.loads((r.stdout or "").strip().splitlines()[-1])
    except Exception as e:                                  # noqa: BLE001
        return {"err": "探针子进程没吐出 JSON（%s: %s）：%r"
                % (type(e).__name__, e, (r.stdout or "")[-200:])}
    if not isinstance(st, dict) or "rep" not in st or "calls" not in st:
        return {"err": "探针 JSON 形状不对：%r" % (st,)}
    fix = st.get("fixture") or {}
    if (tuple(fix.get("rect") or ()) != _W07_RECT
            or fix.get("appear_after") != _W07_APPEAR):
        return {"err": "夹具与判据漂移：子进程 fixture=%r，判据期望 rect=%r appear=%r"
                " —— 先对齐再断言，不许对空气打分" % (fix, _W07_RECT, _W07_APPEAR)}
    st["err"] = None
    return st


def _w07_settled():
    """正臂：`open_console_settled` 真去轮询、真落位、真回读（calls 与 rep 互证）。"""
    st = _run_w07_child("settled", 6.0)
    if st["err"]:
        return st["err"]
    rep, calls = st["rep"], st["calls"]
    if rep.get("opened") not in ("app", "browser"):
        return ("开窗这一步就没走通（opened=%r，why=%r）—— 后面的断言都无从谈起"
                % (rep.get("opened"), rep.get("why")))
    if rep.get("opened") == "app" and calls.get("popen", 0) < 1:
        return "声称走了 app 模式，却一次 Popen 都没有（夹具把开窗也吞了？）"
    if not calls.get("first_find_empty"):
        return ("夹具不忠实：窗口**第一次轮询就出现** —— 那不是 Edge 的节奏"
                "（真机实测建窗 1–2.5s）；这样的夹具会把 C4 掩藏起来")
    if calls.get("find", 0) < 1:
        return "一次轮询都没有（find=%d）—— 它根本没在等窗口" % calls.get("find", 0)
    if calls.get("place", 0) < 1:
        return ("落位一次都没执行（place_all=%d 次）—— C4 复发：一次性调用方"
                "没等窗就位，daemon 线程随进程死了" % calls.get("place", 0))
    if calls.get("rect", 0) < 1:
        return ("没有独立回读（window_rect_of=%d 次）—— placed 就不是回读说了算"
                % calls.get("rect", 0))
    if rep.get("placed") is not True:
        return ("报告说没就位（placed=%r，why=%r）—— 不谎报的原则下这就是红"
                % (rep.get("placed"), rep.get("why")))
    if rep.get("want") != list(_W07_RECT):
        return "want 不是目标矩形：%r（应 %r）" % (rep.get("want"), list(_W07_RECT))
    if rep.get("got") != [list(_W07_RECT)]:
        return "回读到的矩形不对：%r（应 %r）" % (rep.get("got"), [list(_W07_RECT)])
    return True


def _w07_never():
    """负形状臂：窗口永不出现 ⇒ 必须如实报"没看到"，且一次落位都不许发。"""
    st = _run_w07_child("never", 2.0)
    if st["err"]:
        return st["err"]
    rep, calls = st["rep"], st["calls"]
    if rep.get("placed") is not False:
        return ("窗口根本没出现，报告却称已就位（placed=%r）—— 谎报成功比 C4 更坏"
                % (rep.get("placed"),))
    if "没看到" not in (rep.get("why") or ""):
        return ("没就位却没说「没看到」（why=%r）—— 失败再次静默，C4 的另一半"
                % (rep.get("why"),))
    if calls.get("place", 0) != 0:
        return ("窗口不存在却调了落位（place_all=%d 次）—— 它会去搬**别人**的窗口"
                % calls.get("place", 0))
    return True


def _func_calls(src, func):
    """函数体内的**调用点名集合**（AST）—— 找不到该函数返回 None。

    ★★ 为什么必须 AST 而不是 `re.search(r"\\bopen_console\\(", seg)`：
       2026-10-13 实测 —— `cmd_window` 的 **docstring** 里复述着旧实现
       "旧实现只 `open_console(url)` 就返回"，正则把它当成真调用 ⇒ **自己写的
       说明文字把自己误红**（与 U-16 踩的 CSS 注释、U-10 踩的 CSS 注释、
       S48② 立的"数调用点必须 AST"**同一族**：把非代码层当代码层）。
       本仓铁律：假红比恒红更坏。
    """
    import ast
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == func:
            out = []
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    if isinstance(sub.func, ast.Attribute):
                        out.append(sub.func.attr)
                    elif isinstance(sub.func, ast.Name):
                        out.append(sub.func.id)
            return out
    return None


def _func_literals(src, func):
    """函数体内的**字面量字符串集合**（AST，跳过 docstring）—— 同上理由。

    用于"它真的把结果打到屏上了吗"这类可观测断言：只看**代码里**的串，
    注释/docstring 里复述的不算。
    """
    import ast
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == func:
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body = body[1:]
            out = set()
            for sub in ast.walk(ast.Module(body=body, type_ignores=[])):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    out.add(sub.value)
            return out
    return None


def _w07_entry():
    """入口与可观测（维一/维四）：一键入口真改了调用点，且把结果打到屏上。"""
    src = _src("inbox_cli.py")
    calls = _func_calls(src, "cmd_window")
    if calls is None:
        return "inbox_cli.py 里没有 cmd_window（一键入口的锚点没了）"
    if "open_console_settled" not in calls:
        return "cmd_window 没走 open_console_settled —— C4 修法没接上一键入口"
    if "open_console" in calls:
        return "cmd_window 还在裸调 open_console（等它就位那一步被绕开了）"
    lits = _func_literals(src, "cmd_window") or set()
    if not any("[window] 已就位" in s for s in lits):
        return ("cmd_window 不打「已就位」 —— 落位结果不可观测（维四："
                "「今天生效了吗」这个问题答不上来）")
    if not any("没能就位" in s for s in lits):
        return ("cmd_window 没有「没能就位」分支 —— 失败会再次静默"
                "（C4 的另一半）")
    return True


def _w07_linked():
    """维三连带：这次修法会让哪条保证变松？三条都必须还在（AST 看调用点）。"""
    src = _src(_SERVER_REL)
    oc = _func_calls(src, "open_console")
    if oc is None:
        return "找不到 open_console 的定义（C4 要修的锚点没了）"
    if "_place_if_needed" not in oc:
        return ("连带变松：open_console 不再起后台落位线程 —— 服务自己开窗的长命"
                "路径被改坏（C4 不能靠删服务路径来「修」）")
    ocs = _func_calls(src, "open_console_settled")
    if ocs is None:
        return "找不到 open_console_settled —— C4 的修法本身没了"
    if "close_window" in ocs or "close_console_windows" in ocs:
        return ("连带变松：open_console_settled 里出现关窗调用（0.36.4 立的规矩："
                "落位失败不关窗 —— 面板就是主人要看的內容）")
    if "place_all" not in ocs:
        return "连带变松：open_console_settled 不走 place_all —— 落位的唯一实现被绕过"
    return True


@check("W-07 ★ C4：一次性调用方自己等窗就位（真进程：开窗→轮询→落位→回读）")
def w07():
    """C4（T-10 静默降级）：见本节表头。四组合起来才叫修完：
       ① 真进程里确实轮询到、落位了、回读了（`_w07_settled`）；
       ② 窗口不出现时如实说"没看到"，且一次落位都不发（`_w07_never`）；
       ③ 一键入口真改了调用点，并把结果打到屏上（`_w07_entry`）；
       ④ 服务路径与"不关窗"的旧保证一条都没松（`_w07_linked`）。
    """
    for part in (_w07_settled, _w07_never, _w07_entry, _w07_linked):
        r = part()
        if r is not True:
            return r
    return True


@check("N-W07 负控：只调 open_console 不等就退（C4 原貌）⇒ 落位 0 次必红")
def n_w07():
    """反向对照（维二）：**撤销修复即变红** —— 在**同一套子进程夹具**下，
    把 cmd_window 的做法换回 C4 原貌（只 `open_console(url)`，不等就退），
    落位必须 0 次。★ 这一臂同时是**尺子的分辨力证明**：bare 臂若也能落位，
    说明夹具把缺陷掩藏了（窗口一上来就在），那上面的正判据就是空转。
    """
    st = _run_w07_child("bare", 6.0)
    if st["err"]:
        return st["err"]
    rep, calls = st["rep"], st["calls"]
    if rep.get("opened") not in ("app", "browser"):
        return ("夹具不成立：bare 臂连窗都没「开出来」（opened=%r）⇒ 落位 0 次"
                "是平凡的，负控无分辨力" % (rep.get("opened"),))
    if calls.get("place", 0) != 0:
        return ("负控失效：只调 open_console 也落位了 %d 次 —— 要么夹具不忠实"
                "（窗口一上来就在），要么 C4 已用别的方式修好（那 W-07 的说法要改）"
                % calls.get("place", 0))
    return True


# ════════════ T-01 · 时变产物消费点审计（2026-10-16，机制层方案 v1.0 §2）════════════
#   ★ 病灶（本判据存在的理由）：0.50.4（Q-22）给 `M.reading_note()` 加了实时
#     「载入于 HH:MM」之后，**消费它的判据**若逐字比对（渲染后独立再调一次），
#     两次读数跨分钟即伪红——同日全量复跑实测撞上（U-01），0470 S95 同病。
#     修法是两侧经 `PC.note_text()` 归一（见本文件 `_note_matches`），但那只是
#     修了两处存量——**没有尺子守着「今后不许再出现裸逐字比对」**。
#   ★ P1 频率×损失：每次给时变实现加字段/每轮全量复跑都可能触发，伪红一轮浪费
#     一轮分类（本仓已实测两次）；P2 二值可判定：AST 结构比对，无观感成分；
#     P3 咽喉点：消费点唯一入口是 ci/ 套件目录，可枚举；P4 自检闭环：N-T01
#     双向实测（裸必红/归一必绿）；P5 扩展优先：reading_note 的家就在本套件，
#     并入不新建（常驻上限 29 不动）。
#   ★ 口径（**方向判定**是本尺子的灵魂）：
#     · `not in` / `!=` ＝「不等就判红」——时变产物两侧读数跨分钟必然不等
#       ⇒ 伪红 ⇒ 记问题；
#     · `in` / `==` ＝正向在场检查——时刻错过只会让该红的当轮不红（负控分辨力
#       弱化），**不会把好的判红** ⇒ 豁免（本判据刻意做窄，防伪红不防弱分辨）；
#     · 任何一侧经 `*.note_text(...)` 包裹 ＝ 已归一 ＝ 合规。
#   ★ 名单 `_TIME_BARE_ATTRS` 刻意只有已知的时变唯一实现；给新实现加实时读数时
#     **扩名单要过 L2 自问**（方案 §2 边界：本尺子只盯已知名单）。
_TIME_BARE_ATTRS = ("reading_note",)


def _time_consumption_problems(src, rel):
    """AST 尺子：时变产物出现在「不等就红」方向的**裸**比对 ⇒ 问题串列表。

    正判据与 N-T01 负控共用**同一把尺子**（不复制逻辑）。解析失败按问题报
    （解析不了的东西守不了）。
    """
    import ast as _ast
    try:
        tree = _ast.parse(src)
    except SyntaxError as e:
        return ["%s 源码解析失败：%s" % (rel, e)]
    probs = []

    def _bare_time_call(operand):
        """返回 None=与本审计无关；False=时变调用但已归一；True=**裸**时变调用。"""
        call = operand
        wrapped = False
        if (isinstance(call, _ast.Call) and isinstance(call.func, _ast.Attribute)
                and call.func.attr == "note_text"):
            if not call.args:
                return None                       # note_text() 无参——形态怪，不判
            call, wrapped = call.args[0], True
        if not isinstance(call, _ast.Call):
            return None
        f = call.func
        if isinstance(f, _ast.Attribute) and f.attr in _TIME_BARE_ATTRS:
            return not wrapped
        return None

    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Compare):
            continue
        risky = any(isinstance(op, (_ast.NotIn, _ast.NotEq)) for op in node.ops)
        if not risky:
            continue
        for operand in [node.left] + list(node.comparators):
            verdict = _bare_time_call(operand)
            if verdict:
                probs.append("%s:L%d 时变产物 %s() 出现在裸「不等」比对里 —— 跨分钟必伪红，"
                             "两侧须经 PC.note_text 归一（U-01 事故同型）"
                             % (rel, getattr(node, "lineno", 0),
                                _TIME_BARE_ATTRS[0]))
    return probs


@check("T-01 ★ 时变产物消费点审计：全部套件里 reading_note() 不许裸身出现在「不等」比对")
def t_01():
    """正判据：扫 ci/ 全部套件源码（含本文件），裸比对 ⇒ 红。"""
    cdir = os.path.join(ROOT, "ci")
    names = sorted(n for n in os.listdir(cdir)
                   if n.startswith(("inbox_guards_", "guard_")) and n.endswith(".py"))
    names.append("regression_gate.py")
    all_probs = []
    for n in names:
        p = os.path.join(cdir, n)
        if not os.path.isfile(p):
            continue
        all_probs += _time_consumption_problems(
            io.open(p, encoding="utf-8").read(), "ci/" + n)
    if all_probs:
        return "；".join(all_probs[:4])
    return True


@check("N-T01 ★ 负控：裸「不等」比对必须被 T-01 的尺子抓到；归一后必须放过")
def n_t01():
    """内建负控（同尺双喂）：①裸形态 ⇒ 尺子必须报；②归一形态 ⇒ 必须空。

    少了②，归一可能只是「把一切吞掉」的纸糊；少了①，尺子可能根本没牙。
    """
    naked = ("from x import inbox_model as M, page_caliber as PC\n"
             "def judge(page):\n"
             "    if M.reading_note() not in page:\n"
             "        return '红'\n"
             "    return True\n")
    p1 = _time_consumption_problems(naked, "负控-裸")
    if not p1:
        return "负控失效：裸「不等」比对没被抓到 ⇒ T-01 没牙（U-01 事故会重演）"
    wrapped = ("from x import inbox_model as M, page_caliber as PC\n"
               "def judge(page):\n"
               "    if PC.note_text(M.reading_note()) not in PC.note_text(page):\n"
               "        return '红'\n"
               "    return True\n")
    p2 = _time_consumption_problems(wrapped, "负控-归一")
    if p2:
        return "负控失效：归一后的形态仍被抓 ⇒ 尺子过宽（会把 U-01 的修法也判掉）：%r" % p2
    # 正向在场检查必须豁免（方向判定的一半，不测就等于没定方向）
    fwd = ("from x import inbox_model as M\n"
           "def judge(page):\n"
           "    if M.reading_note() in page:\n"
           "        return '红'\n"
           "    return True\n")
    p3 = _time_consumption_problems(fwd, "负控-正向")
    if p3:
        return "负控失效：正向 in 比对不该被抓（它不伪红）：%r" % p3
    return True


@check("T-02 ★ 四态词条内容派生审计：R0/L1 事件类型层逐字派生 · "
       "L2 规则层同源（总数/行数/说明）· 类别中文名与徽标映射完备")
def t_02():
    """0.51.0 四态问号小窗方案 v1.1 动作二/三（2026-10-16）。

    病灶：手写清单必漂（实测 R0 漏「安全区加锁失败」、L1 漏「研发迭代中」）；
    拦截态内容全集在规则层（37 条），kind 只是投影容器。本判据钉死三件事：
    ① R0/L1 的 inc 与 `glossary._kinds_of` 派生**逐字相等**（手写回潮即红）；
    ② L2 的概述句数字、全表行数、每行说明与 `inbox_report.rule_table()`
      **同源**（写死 37 即红）；
    ③ 类别中文名映射（`_CATEGORY_ZH`）与徽标→词条映射（`BADGE_STATE`）
      **完备**（新增类别/徽标没登记 ⇒ 红）。
    """
    import glossary as GL
    import inbox_report as R
    # ── ① R0/L1：事件类型层逐字派生 ──
    # ★★ 0.53.2（T10）：模板去掉末尾的「具体是哪一件事，看收件箱每条记录的
    #   原因。」—— 那是**导航**（指路到别处），不是释义，而且读者此刻就在
    #   收件箱里。**断言强度不变**：仍要求 `inc` 与 `_kinds_of()` 逐字相等，
    #   手写回潮照样红。
    for st in ("R0", "L1"):
        want = "%s。" % GL._kinds_of(st)
        got = GL.TERMS[st]["inc"]
        if got != want:
            return "%s 词条 inc 与派生不一致（手写回潮？）：%r" % (st, got[:60])
    # 派生本身必须覆盖真源里的每个 kind（防 _kinds_of 与真源脱节）
    for st in ("R0", "L1"):
        for kind, lv in M.LEVEL_OF_KIND.items():
            if lv != st:
                continue
            t = M.TITLE_OF_KIND.get(kind) or kind
            seg = t.split("：", 1)[1] if "：" in t else t
            if seg not in GL.TERMS[st]["inc"]:
                return "%s 派生清单漏 %s（%s）" % (st, kind, seg)
    # ── ② L2：规则层同源 ──
    rows = R.rule_table()
    if not rows:
        return "规则表为空 —— 正常环境（安装态/仓根态）必带 rules/default.json"
    inc = GL.TERMS["L2"]["inc"]
    # ★★ 0.53.2（T10）：数字的落点从 `inc` 换到规则全表的展开标题。
    #   理由：`inc` 是**释义**，报"装着 N 条规则分 M 类"答不了"拦截是什么"
    #   （那是统计）。断言强度**加强**而非放松 —— 变成两条：
    #     ① 释义里**不许**出现规则统计（写了就红）；
    #     ② 全表标题里的条数必须与 `rule_table()` 同源（写死就红）。
    #   旧断言只查"这个数字出现在 inc 里"，那正好是"永不更新的真数字"的温床。
    if ("%d 条" % len(rows)) in inc or "条拦截规则" in inc:
        return "L2 释义里又报了规则统计（统计不是释义）：%r" % inc[:60]
    lh = GL.TERMS["L2"]["list_html"] or ""
    if ("展开看全部 %d 条规则" % len(rows)) not in lh:
        return "L2 规则全表的标题条数与 rule_table() 不同源（写死数字？）：%r" % lh[:60]
    n_rows = lh.count('class="rrow"')
    if n_rows != len(rows):
        return "L2 全表行数(%d) != 规则表条数(%d)" % (n_rows, len(rows))
    for r in rows:
        if (">%s</span>" % r["id"]) not in lh:
            return "L2 全表缺规则 %s" % r["id"]
        zh = r.get("description_zh")
        if zh and zh not in lh:
            return "L2 全表规则 %s 的中文说明缺失（写死/漏译？）" % r["id"]
    # ── ③ 类别中文名完备（fail-loud 的正向面）──
    for r in rows:
        try:
            GL._cat_zh(r.get("category") or "?")
        except GL.UnknownTerm as e:
            return "类别中文名未登记：%s" % e
    # ── ④ 徽标 → 态词条映射完备（缺粮＝Ls、研发中＝dev）──
    for bk in M.BADGE_LABEL:
        st = M.BADGE_STATE.get(bk)
        if not st:
            return "徽标 %s 未登记 BADGE_STATE（页面将不出问号芯片）" % bk
        if st not in GL.TERMS:
            return "徽标 %s 指向的词条 %s 不存在" % (bk, st)
    return True


@check("N-T02 ★ 负控：假 kind 入清单 / 假 category 抛错 / 假规则改总数与空表降级")
def n_t02():
    """同尺三喂：证明清单是**派生**不是手写、fail-loud 真有牙、还原后回绿。"""
    import glossary as GL
    import inbox_report as R
    # ── ① 假 kind 注入 → 清单必须跟上（派生的证据；手写串不会变）──
    orig_lk = dict(M.LEVEL_OF_KIND)
    orig_tk = dict(M.TITLE_OF_KIND)
    try:
        M.LEVEL_OF_KIND["host_shield_xxx"] = "R0"
        M.TITLE_OF_KIND["host_shield_xxx"] = "失守：判据自造的假问题"
        if "判据自造的假问题" not in GL._kinds_of("R0"):
            return "负控失效：注入假 kind 后清单没跟上 ⇒ 清单不是派生（手写回潮）"
    finally:
        M.LEVEL_OF_KIND.clear()
        M.LEVEL_OF_KIND.update(orig_lk)
        M.TITLE_OF_KIND.clear()
        M.TITLE_OF_KIND.update(orig_tk)
    if "判据自造的假问题" in GL._kinds_of("R0"):
        return "还原链路坏：还原 LEVEL_OF_KIND 后假条目仍在"
    # ── ② 未登记类别 ⇒ _cat_zh 必须抛（不静默露英文）──
    try:
        GL._cat_zh("alien_cat")
        return "负控失效：未登记类别没抛错 ⇒ fail-loud 失守（页面会露英文）"
    except GL.UnknownTerm:
        pass
    # ── ③ 假规则夹具：概述句总数/全表跟着变；含假类别 ⇒ 抛错；空表 ⇒ 降级真话 ──
    #   （概述句与全表**都**要过类别映射 ⇒ 夹具分三段：全合法类别验证派生、
    #    含未登记类别验证抛错、空表验证降级 —— 混在一段会让抛错提前、测不到派生。）
    orig_rt = R.rule_table
    fake_ok = [{"id": "FAKE-01", "category": "secrets", "description_zh": "判据自造的假规则"},
               {"id": "FAKE-02", "category": "secrets", "description_zh": "假规则二"}]
    fake_bad = [{"id": "FAKE-03", "category": "alien_cat", "description_zh": "假规则三"}]
    try:
        R.rule_table = lambda: fake_ok
        # ★ 0.53.2（T10）：读得到时概述句返回空串（统计已移出释义）；
        #   分辨力由紧接着的「全表跟着变」承担 —— 两条合起来才完整。
        if GL._shield_overview() != "":
            return "负控失效：规则表读得到时概述句应该不说话（统计已移出释义）"
        _lh = GL._shield_list_html()
        if _lh.count('class="rrow"') != 2 or "判据自造的假规则" not in _lh:
            return "负控失效：夹具 2 条 ⇒ 全表没跟着变（行数写死或漏派生）"
        R.rule_table = lambda: fake_bad
        try:
            GL._shield_overview()
            return "负控失效：未登记类别 alien_cat ⇒ 未抛错（fail-loud 失守）"
        except GL.UnknownTerm:
            pass
        R.rule_table = lambda: []
        if "读不到" not in GL._shield_overview():
            return "负控失效：空表 ⇒ 概述句没有降级真话（会编清单或装没事）"
        if GL._shield_list_html() != "":
            return "负控失效：空表 ⇒ list_html 应为空串（chip 跳过全表）"
    finally:
        R.rule_table = orig_rt
    if GL._shield_overview() != "":
        return "还原链路坏：还原 rule_table 后概述句与真源不一致"
    return True


# ══════════════ T-03 · 排行行形态（0.51.0 日报页品质审查，拍板点 3/4）══════════════
_RANK_ROWS = [
    {"rule_id": "DST-04", "count": 2,
     "zh": "建立持久化机制（计划任务/系统服务/启动项/注册表 Run 键）",
     "label": "设置开机自动启动"},
    {"rule_id": "SEC-01", "count": 1,
     "zh": "读取 .env 文件可能泄露 API 密钥与机密配置",
     "label": "读取密钥配置文件"},
]


def _t03_core(page):
    """排行行形态断言本体（T-03 与 N-T03 共用 —— 负控证明这把尺子会咬）。

    ★ 剥层用 `body_without_terms`（C2 纪律：显式选层）：排行行不在词条里，
      短名与 rid 保留；L2 问号全表（details 词条，同为 .rrow/.rid 形态）
      必须剥掉 —— 它装 description_zh 全文是**设计如此**（学习场景），
      不剥会跟排行行的「全文不许上屏」断言打架。
    """
    body = re.sub(r"\x00+", " ", re.sub(
        r"<[^>]+>", "\x00", PC.body_without_terms(page)))
    # ↑ 分层（剥 style/script/词条浮层）之后**再剥标签**取纯可见文本 ——
    #   body 层保留标签，title 属性里的 hover 全文会混进来冒充可见文本
    #   （首跑实测：zh 在 title 里被误判「上屏」）。与 0360 W06 同口径。
    # ① 主显示＝上屏短名（label）；审计全文（zh）不得出现在可见文本
    #    （zh 只住 hover title —— title 属性随标签一起被剥，天然区分）。
    for r in _RANK_ROWS:
        if r["label"] not in body:
            return "排行行主显示缺短名 %r（label → zh → 规则号 退链断了？）" % r["label"]
        if r["zh"] in body:
            return "排行行可见文本出现审计全文 %r…（受众错配回潮）" % r["zh"][:24]
    # ② 规则号淡显索引位在（.rid），且是**唯一**的编号出现形态：
    #    剥掉 rid 后可见文本不许再有任何规则号（裸 rule_id 兜底回潮即红 ——
    #    Q-04 自违反形态，2026-10-16 查证实锤过）。
    if not re.search(r'<span class="rid">[A-Z]{2,4}-\d{2}</span>', page):
        return "排行行缺淡显编号（.rid）—— 收件箱记录「规则 SEC-01」对不上号"
    bare = re.sub(r"\x00+", " ", re.sub(r"<[^>]+>", "\x00", PC.body_without_terms(
        re.sub(r'<span class="rid">[A-Za-z0-9-]*</span>', " ", page))))
    if re.search(r"[A-Z]{2,4}-\d{2}", bare):
        return "剥掉 .rid 后可见文本仍有规则号（裸 rule_id 兜底上了主显示）"
    # ③ 命中次数在（排行卡的数）
    if "命中 2 次" not in body:
        return "排行行缺命中次数"
    return True


@check("T-03 ★ 排行行形态：短名主显示＋编号淡显＋审计全文退 hover")
def t03():
    """0.51.0（品质审查拍板点 3/4，创始人 2026-10-16 截图指认）：Q-04 退编号
    方向没错，但替代品 description_zh 是审计受众全文（最长 60 字、DST-10 内嵌
    「——DST-09」自引用）⇒ 上屏挤成三四行、编号从数据后门回来。
    新形态锁三件事：① 主显示＝label_zh（≤14 字，品质由 0360 W15/INV-4 锁）；
    ② 规则号淡显 .rid（与问号全表同视觉语言，收件箱「规则 SEC-01」可对号）；
    ③ rid 是可见文本里**唯一**的编号形态（zh 全文退 hover、裸 rule_id 兜底
    不许上主显示）。
    """
    page = _page("report", rep=dict(_REP, rules=_RANK_ROWS))
    return _t03_core(page)


@check("N-T03 ★ 负控：主显示退回 zh 全文（Q-04 前旧形态回潮）⇒ T-03 必须红")
def n_t03():
    """C1 两步法：变异＝渲染退链里删掉 label ⇒ 短名消失、全文上屏，
    _t03_core 必须报「出现审计全文」。"""
    src = _src(_SERVER_REL)
    anchor = '               _esc(r.get("label") or r.get("zh") or r["rule_id"]),'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    page, _why = _mut_render(
        src.replace(anchor, '               _esc(r.get("zh") or r["rule_id"]),'),
        "is0490_nt03", _SERVER_REL, view="report",
        rep=dict(_REP, rules=_RANK_ROWS),
        root=tempfile.mkdtemp(prefix="g0490_nt03_"),
        token="T", items=_items(), posture=_POSTURE)
    if _why:
        return _why
    r = _t03_core(page)
    if r is True or r is None:
        return "负控失效：主显示退回 zh 全文 ⇒ T-03 没红"
    # 连回正判据：真实现必须全绿
    if _t03_core(_page("report", rep=dict(_REP, rules=_RANK_ROWS))) is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True


# ======================================================================
# 批 15 · T-04 族：账本页**明细**（0.51.0 四问，创始人 2026-10-16 截图指认）
# ----------------------------------------------------------------------
# ★ 四问里的第四问（「汇总看不了明细，体验糟」）＋ 追加问（「日期太多怎么办」）
#   的判据落点。设计定稿见《Antinel·账本页明细设计 v1.1》。
# ★ 三条硬约束（都是"不许把没查渲染成没事"的同族护栏）：
#   ① 无记录的天/月**淡显「无记录」**，绝不渲染成 0；
#   ② 月行**默认收起**（页高不随历史增长：1 年后＝7 日行＋12 月行）；
#   ③ 每格数字与深链**同源**于 `M.day_counts`（F40：页面数与点进去对得上）。
# ======================================================================

def _ledger_items():
    """账本明细夹具（**不写死任何日期** —— 0470 0.48.4 时间炸弹教训）。

    今天 4 条（拦截 2 / 注意 1 / 缺口 1）· 3 天前 1 条（已老去，未关闭）·
    3 天前 1 条（当天关闭）· 2 天前发生、**今天**才关闭 1 条（发生日≠关闭日，
    供 `closed:` 证明它按关闭日收）· 75 天前 1 条（当天关闭，撑出月区）。
    """
    now = datetime.now().astimezone()

    def ts(days_ago, hour):
        return (now - timedelta(days=days_ago)).replace(
            hour=hour, minute=0, second=0, microsecond=0).isoformat()

    def mk(id_, days, hour, level, kind, state="unread", closed=None):
        a = M.Alert(id=id_, ts=ts(days, hour), level=level, kind=kind, title="t")
        return M.Item(alert=a, state=state, closed_at=closed)

    return [
        mk("u0490_L1", 0, 9, "L2", "tool_call_blocked"),        # 今天 · 拦截
        mk("u0490_L2", 0, 10, "L2", "tool_call_blocked"),       # 今天 · 拦截
        mk("u0490_L3", 0, 11, "L1", "host_shield_changed"),     # 今天 · 注意
        mk("u0490_L4", 0, 12, "R0", "host_shield_breach"),      # 今天 · 缺口
        mk("u0490_L5", 3, 8, "L1", "host_shield_changed"),      # 已老去 · 未关闭
        mk("u0490_L6", 3, 9, "L2", "tool_call_blocked",
           state="done", closed=ts(3, 10)),                     # 发生日＝关闭日
        mk("u0490_L7", 2, 8, "L2", "tool_call_blocked",
           state="done", closed=ts(0, 13)),                     # 发生日≠关闭日
        mk("u0490_L8", 75, 8, "L2", "tool_call_blocked",
           state="done", closed=ts(75, 9)),                     # 撑出月区
    ]


def _ledger_rep(items=None):
    """账本页要读的 `ledger` 键 —— **由 `M.day_counts` 现算**，不手写数字。

    ★ 判据不许二次实现：汇总与明细必须是同一份口径，否则页面数与点进去对不上
      （F40 病灶；日报族已栽过一次）。
    """
    items = _ledger_items() if items is None else items
    idx = M.day_counts(items)
    today = datetime.now().astimezone().date().isoformat()
    tot = {k: sum(int(e.get(k) or 0) for e in idx.values()) for k in M.LEDGER_KEYS}
    led = {"days": len(idx), "streak_days": 1, "today": idx.get(today) or {}}
    led.update(tot)
    return dict(_REP, ledger=led)


def _ledger_page(mod=SV, items=None, rep=None):
    items = _ledger_items() if items is None else items
    return mod.render_page(view="ledger", root=tempfile.mkdtemp(prefix="g0490_l_"),
                           token="T", items=items,
                           rep=_ledger_rep(items) if rep is None else rep,
                           posture=_POSTURE)


def _t04_core(page, items):
    """区一（**过去 7 天，起点＝昨天**）＋头部零卡片＋每格深链同源。

    ★★ 0.53.0（T4.2/T4.3）重写三条 —— **不是放松**：删掉的是已被撤走的
      结构（头部四指标卡），补上的是新契约的三条断言，护栏一条不减。
      · 头部四指标卡撤了（数字的家是日报）⇒「当天四个数可点」没有对象了，
        换成「头部零卡片」＋「今天有一行深链去日报」；
      · 区一窗口改「昨天起 7 个日历天」⇒ 今天**不许**出现在区一里
        （同一屏两个"今天"，读者会以为账本与日报是两笔账）；
      · 「无记录天淡显」与「有记录天每格深链」**逐字不动**（这是护栏，
        不随版式改）。
    """
    body = PC.body(page)
    idx = M.day_counts(items)
    today = datetime.now().astimezone().date()
    today_s = today.isoformat()
    w7 = [(today - timedelta(days=k)).isoformat() for k in range(1, 8)]

    # ① 头部**零指标卡**（撤卡后不许换个名字把同一份数搬回来）
    if 'class="metric"' in body:
        return "账本头部还有指标卡 —— 与日报同口径两个落点（T4.2 已撤）"
    # ② 今天：一行深链到日报（今天的数在这里没有第二份）
    if "今天的数在" not in body or 'href="/?v=report"' not in body:
        return "头部没有「今天的数在日报」深链 —— 今天的数没有去处"
    # ③ 区一在，窗口＝昨天起 7 个日历天（**今天不在区一**）
    if "过去 7 天" not in body:
        return "账本页没有「过去 7 天」区（明细区没了）"
    i = body.index("过去 7 天")
    j = body.find('<div class="card">', i)
    sec = body[i:j if j > 0 else len(body)]
    if today_s in sec:
        return "区一里出现了今天（%s）—— 今天应在日报，明细只列过完的日子" % today_s
    missing = [d for d in w7 if d not in sec]
    if missing:
        return "过去 7 天缺日历天（窗口是承诺，不许只列有数的天）：%s" % missing
    # ④ ★ 无记录天：淡显「当天无记录」，**不许渲染成 0**
    n_empty = sum(1 for d in w7
                  if not any(int((idx.get(d) or {}).get(k) or 0)
                             for k in M.LEDGER_KEYS))
    got_empty = sec.count("当天无记录")
    if got_empty != n_empty:
        return ("无记录天渲染数不对：页面 %d / 现算 %d —— 要么把「没查」渲染成了数字，"
                "要么漏了天（0.37.2 同款护栏：没查≠查过没事）" % (got_empty, n_empty))
    # ⑤ 有记录的天：四格数字与深链**同源**（F40）
    for d in w7:
        e = idx.get(d) or {}
        n = {k: int(e.get(k) or 0) for k in M.LEDGER_KEYS}
        if not any(n.values()):
            continue
        # ★ 0.53.0 **根治（不是同步硬编码）**：期望词从六态表 `M.STATE_LABEL` 派生 ——
        #   判据与产品同源：改六态名，产品与判据一起动，不存在"改了一边忘了另一边"。
        #   原来的写法把「防护缺口」直接写进判据 ⇒ 产品与判据**同时**停在旧词上，
        #   这条判据反过来还替旧词背书（正是它让 0.53.0 看起来全绿）。
        for key, lv in (("blocked", "L2"), ("noticed", "L1"), ("breached", "R0")):
            word = M.STATE_LABEL[lv]
            if n[key] and ('f=day:%s:lv:%s">%s %d</a>' % (d, lv, word, n[key])) not in body:
                return "%s 的「%s」格数字或深链不对（现算 %d）" % (d, word, n[key])
        if n["acked"] and ('f=closed:%s">已处理 %d</a>' % (d, n["acked"])) not in body:
            return "%s 的「已处理」格数字或深链不对（现算 %d）" % (d, n["acked"])
    # ⑥ 四个词的定义仍可点开（撤卡不能把词条落点一起弄没）
    for k in ("ledger_blocked", "ledger_noticed", "ledger_breached", "ledger_acked"):
        if ('data-t="%s"' % k) not in page:
            return "撤卡后词条 %s 没有落点了 —— 术语表 100% 有落点（P13）会红" % k
    # ⑦ 累计行已撤（创始人 2026-10-16 拍板）
    if "有记录以来" in body:
        return "「有记录以来 N 天累计」那一行回来了 —— 明细区已给出同一批数的来龙去脉"
    return True


def _t04b_core(page, items):
    """区二（更早 · 按月）：默认收起 ＋ 页高不变量 ＋ 月行自报有记录天数。"""
    body, raw = PC.body(page), PC.raw(page)
    if "更早 · 按月" not in body:
        return "账本页没有「更早 · 按月」区"
    # ① 月行**默认收起**（页高不变量的前提）
    if 'details class="month" open' in raw:
        return "月行默认展开了 ⇒ 页高会随历史增长（1 年后 12 个月全摊开）"
    idx = M.day_counts(items)
    rec = {d: e for d, e in idx.items()
           if any(int(e.get(k) or 0) for k in M.LEDGER_KEYS)}
    if not rec:
        return "夹具不成立：没有任何有记录的天"
    # ② 有记录的月＝一个可展开行；月数＝从最早有记录月到当月（**不缺月**）
    months = sorted({d[:7] for d in rec}, reverse=True)
    n_details = body.count('details class="month"')
    if n_details != len(months):
        return "可展开月行 %d ≠ 有记录月数 %d（%s）" % (n_details, len(months), months)
    y, mth = datetime.now().astimezone().year, datetime.now().astimezone().month
    n_all = 0
    while True:
        ym = "%04d-%02d" % (y, mth)
        n_all += 1
        if ym <= min(rec)[:7]:
            break
        mth -= 1
        if mth == 0:
            y, mth = y - 1, 12
    n_rows = n_details + body.count("当月无记录")
    if n_rows != n_all:
        return "月区总行数 %d ≠ 应有月数 %d（从 %s 到当月）—— 页高不变量破了" % (
            n_rows, n_all, min(rec)[:7])
    # ③ 月行自报「有记录 N 天」（不跳转，只展开 ⇒ 报告的是天数不是数字）
    for ym in months:
        n = len([d for d in rec if d[:7] == ym])
        if ("有记录 %d 天" % n) not in body:
            return "%s 月行没自报「有记录 %d 天」" % (ym, n)
    return True


@check("T-04 ★ 账本明细区一：过去 7 天（起点昨天）＋无记录天不许渲染成 0＋每格深链")
def t04():
    """创始人 2026-10-16 第四问「汇总看不了明细」＋追加问「日期太多怎么办」。

    明细的唯一实现在收件箱（归并/处置/筛选都在那边），账本只做**一击直达**
    的深链 —— 所以这里断言的是「数字与链接同源」，不是把明细抄一份过来。
    """
    items = _ledger_items()
    return _t04_core(_ledger_page(items=items), items)


@check("N-T04 ★ 负控：无记录天改回渲染 0 ⇒ T-04 必须红")
def n_t04():
    """C1 两步法：变异＝淡显文案换成 0。这是第四问最危险的回潮 ——
    「没查」被渲染成「查过，是 0」，用户据此以为那天平安无事。"""
    src = _src(_SERVER_REL)
    anchor = "—（当天无记录）"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    items = _ledger_items()
    page, _why = _mut_render(
        src.replace(anchor, "拦截 0 ｜ 注意 0 ｜ 失守 0 ｜ 已处理 0"),
        "is0490_nt04", _SERVER_REL, view="ledger",
        root=tempfile.mkdtemp(prefix="g0490_nt04_"), token="T", items=items,
        rep=_ledger_rep(items), posture=_POSTURE)
    if _why:
        return _why
    if _t04_core(page, items) is True:
        return "负控失效：无记录天渲染成 0 后 T-04 没红"
    if _t04_core(_ledger_page(items=items), items) is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True


#: 退休的态名（六态表的历史旧称）。**登记即永久**：退休词不许回潮。
#: 真需要用到这些字（例如"资金缺口"）时，必须在本表旁边登记例外并写清
#: 「为何它不会被读成态名」—— 否则这条闸会替旧词开路。
_RETIRED_STATE_WORDS = (
    ("防护缺口", "0.51.0 定名「失守」后退役（0.48 旧称）"),
    ("缺口", "同上；裸用会被读成第四种态（账本月行曾用它简称失守）"),
)


def _retired_state_core(pages):
    """尺子：喂 `[(页名, 可见文本)]`，命中退休态名即红。"""
    for view, body in pages:
        for w, why in _RETIRED_STATE_WORDS:
            if w in body:
                return "%s 页出现退休态名 %r（%s）" % (view, w, why)
    return True


@check("T-04e ★ 退休态名不许回潮：五页可见文本出现「防护缺口」/「缺口」即红")
def t04e():
    """0.53.0（创始人 2026-10-18）：「六态是封闭集合，态名只许一处定义」。

    ★ 这条闸治的不是"写错了一个词"，而是**判据替旧词背书**这个结构性缺陷：
      0.53.0 的账本写「防护缺口」／月行写「缺口」／六态表写「失守」—— 三个词
      指同一个事实；而 T-04 把「防护缺口」**硬编码成期望值** ⇒ 判据与产品一起
      停在旧词上，两边"一致"、全绿，谁也没发现。
      现在产品与 T-04 都改成从 `M.STATE_LABEL` **派生**，这条闸负责堵住旧词
      从**任何别的渲染路径**回来（新增页面、历史文案、注释式复述都算）。
    """
    pages = []
    for view in ("inbox", "report", "health", "ledger", "health_exam"):
        try:
            p = SV.render_page(view=view, root=tempfile.mkdtemp(prefix="g0490_t04d_"),
                               token="T", items=_items(), rep=_REP, posture=_POSTURE)
        except Exception as e:                                  # noqa: BLE001
            return ("渲染 %s 失败：%s: %s —— 量具故障，不算通过"
                    % (view, type(e).__name__, e))
        pages.append((view, PC.body(p)))
    return _retired_state_core(pages)


@check("N-T04e 负控：把退休态名喂进页面文本 ⇒ T-04e 必须红")
def n_t04e():
    """尺子自证：不是"真实现里没这词"就算过，而是"出现就必红；合法词不许误伤"。"""
    if _retired_state_core([("账本", "拦截 1 ｜ 防护缺口 2 ｜ 已处理 0")]) is True:
        return "负控失效：退休态名「防护缺口」喂进去仍判绿（尺子没有分辨力）"
    if _retired_state_core([("月行", "拦截 115 · 注意 226 · 缺口 189")]) is True:
        return "负控失效：月行形态的「缺口」喂进去仍判绿"
    if _retired_state_core([("账本", "拦截 1 ｜ 失守 2 ｜ 已处理 0")]) is not True:
        return "负控方向异常：合法文本「失守」被判红 —— 尺子误伤真实现"
    return True


#: 文案主语纪律（创始人 2026-10-19 拍板）：用户可见文案**不许出现「我们」**。
#:   理由不是"文风"，是**读者不知道这句话是谁说的**：读者是被监理的那一方，
#:   「我们」可能是开发方、可能是那个 AI 工具、也可能是电脑本身 —— 而这一句
#:   要说清的恰恰是**谁查的／谁没查到／谁的能力到哪儿**。一律以「监理」作主语。
#: ★ 与退休态名闸同型（T-04e）：**登记即永久**，新文案撞上就红。
_VOICE_BANNED = (
    ("我们", "开发方视角；主语必须是「监理」（谁查的／谁没查到／能力到哪儿）"),
)

#: 用户可见文案的载体（产品侧）。判据自身与一次性脚本不在内 —— 它们不面向用户。
_VOICE_SRC_FILES = ("antinel.py", "ui_server.py", "inbox_server.py",
                    "inbox_model.py", "inbox_daemon.py", "inbox_window.py",
                    "host_shield.py", "inbox_store.py")


def _voice_core(pages):
    """尺子：喂 `[(页名, 可见文本)]`，命中禁用主语即红。"""
    for view, body in pages:
        for w, why in _VOICE_BANNED:
            if w in body:
                return "%s 页出现禁用主语 %r（%s）" % (view, w, why)
    return True


def _voice_render_pages():
    """用户可见文案的**全部渲染入口**：监理五页 ＋ `antinel ui` 索引页（TPL）。

    ★ 索引页为什么必须在内：ui_server 那段边界声明写在**三引号模板**里 ——
      它既不在监理五页里，也不在「同一行成对引号」里 ⇒ 两条腿**都照不到**，
      只扫五页就是本仓最忌的那个形状：**查不到的那一半天然全绿**。
    """
    pages = []
    for view in ("inbox", "report", "health", "ledger", "health_exam"):
        try:
            p = SV.render_page(view=view, root=tempfile.mkdtemp(prefix="g0490_t04f_"),
                               token="T", items=_items(), rep=_REP, posture=_POSTURE)
        except Exception as e:                                  # noqa: BLE001
            return None, ("渲染 %s 失败：%s: %s —— 量具故障，不算通过"
                          % (view, type(e).__name__, e))
        pages.append((view, PC.body(p)))
    try:
        import ui_server as _U
        pages.append(("antinel ui 索引页", PC.body(_U._index_page("T"))))
    except Exception as e:                                      # noqa: BLE001
        return None, ("渲染 ui 索引页失败：%s: %s —— 量具故障，不算通过"
                      % (type(e).__name__, e))
    return pages, None


@check("T-04f ★ 文案主语：五页可见文本不许出现「我们」（一律以「监理」作主语）")
def t04f():
    """0.53.0（创始人 2026-10-19）：「我们的能力」「我们没查到」这种口吻不对。

    ★ 撞出来的样子：体检页边界写着「所以我们读不到」「那是我们没走到的地方」，
      而读者是被监理的那一方 —— 他不知道「我们」是谁。
    ★ 与 T-04e 同一条结构性教训：**文案纪律不进机器检查 ⇒ 迟早回潮**。
      这次改的是 12 处；闸不立，下一次改文案的人看不见这条纪律。
    """
    pages, why = _voice_render_pages()
    if why:
        return why
    return _voice_core(pages)


@check("N-T04f 负控：把「我们」喂进页面文本 ⇒ T-04f 必须红；「监理」不许误伤")
def n_t04f():
    """尺子自证：出现就必红 ＋ 合法主语判绿（缺后者 ⇒ 尺子会误伤真文案）。"""
    for bad in ("有 3 个地方我们没查到", "我们的能力只到「读它写下的字」",
                "那是我们没走到的地方"):
        if _voice_core([("体检", bad)]) is True:
            return "负控失效：%r 喂进去仍判绿（尺子没有分辨力）" % bad
    for ok in ("有 3 个地方监理没查到", "监理的能力只到「读它写下的字」",
               "那是监理没走到的地方"):
        if _voice_core([("体检", ok)]) is not True:
            return "负控方向异常：合法主语文本 %r 被判红 —— 尺子误伤真实现" % ok
    return True


def _voice_scan_text(src, rel):
    """扫**一份源码**里的文案字面量；命中 ⇒ 红。★ 唯一实现（正判据与负控共用）。

    ★ 只认**同一行内成对引号包住**的中文字面量 ⇒ 行注释里的「我们」不算
      （不面向用户），而 `print("…我们…")` 与模块级文案常量都在网里。
    """
    pat = re.compile(r'"[^"\n]*%s[^"\n]*"' % _VOICE_BANNED[0][0])
    for i, line in enumerate(src.splitlines(), 1):
        if pat.search(line):
            return "%s:%d 的文案字面量里出现 %r —— 主语改「监理」" % (
                rel, i, _VOICE_BANNED[0][0])
    return True


def _voice_src_core():
    """第二腿：扫产品源码的文案字面量 —— 页面渲染不到的那一半
    （终端人读输出，如 `host-scan` 的「这一项我们没查」）。
    """
    for rel in _VOICE_SRC_FILES:
        try:
            src = _src(rel)
        except Exception:                                      # noqa: BLE001
            continue
        why = _voice_scan_text(src, rel)
        if why is not True:
            return why
    return True


@check("T-04g ★ 文案主语（第二腿）：产品源码的文案字面量里不许出现「我们」")
def t04g():
    """★ 为什么要有第二腿：T-04f 只看**渲染得出来**的那五页；终端人读输出
    （`antinel host-scan`、`--verify` 那句「不需要相信我们」）不在任何页面里，
    第一腿永远照不到它 —— 只守一腿就是「查不到的那一半天然全绿」。
    """
    return _voice_src_core()


@check("N-T04g 负控：源码里塞回一句「我们…」⇒ T-04g 必须红")
def n_t04g():
    """变异＝把真源码里一处「监理」字面量换回「我们」（C1 两步法，磁盘一字节不动）。

    ★ 顺带自证：真实现喂同一把尺子必须是绿的（否则这条闸在误伤，不是守卫）。
    """
    src = _src(_SERVER_REL)
    anchor = "也可能是监理没找到"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    if _voice_scan_text(src.replace(anchor, "也可能是我们没找到"),
                        _SERVER_REL) is True:
        return "负控失效：字面量换回「我们」后 T-04g 没红（第二腿是装饰）"
    if _voice_scan_text(src, _SERVER_REL) is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True


@check("T-04b ★ 账本明细区二：按月折叠（默认收起）＋页高不变量＋月行自报天数")
def t04b():
    """「日期太多怎么办」的裁决落点：**不引入滚动条**（页高无界、零信息指向）、
    **不引入按周**（第三套词汇无增益），用**按月折叠**把页高压成
    「7 日行 ＋ 12 月行/年」—— 5 年后仍一屏内。
    """
    items = _ledger_items()
    return _t04b_core(_ledger_page(items=items), items)


@check("N-T04b ★ 负控：月行默认展开 ⇒ T-04b 必须红")
def n_t04b():
    """C1 两步法：变异＝给 `<details class="month">` 加 `open`。
    这是「日期太多」最省事的写法，也是页高不变量的死法。"""
    src = _src(_SERVER_REL)
    anchor = '<details class=\\"month\\">'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    items = _ledger_items()
    page, _why = _mut_render(
        src.replace(anchor, '<details class=\\"month\\" open>'),
        "is0490_nt04b", _SERVER_REL, view="ledger",
        root=tempfile.mkdtemp(prefix="g0490_nt04b_"), token="T", items=items,
        rep=_ledger_rep(items), posture=_POSTURE)
    if _why:
        return _why
    if _t04b_core(page, items) is True:
        return "负控失效：月行默认展开后 T-04b 没红"
    if _t04b_core(_ledger_page(items=items), items) is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True


def _t04c_core(mod):
    """`closed:<日期>` ＝ 按**关闭日**收已关闭件（`mod` 可换成变异模块）。"""
    items = _ledger_items()
    today = datetime.now().astimezone().date().isoformat()
    want = [it for it in items if it.state in M.CLOSED_STATES
            and str(it.closed_at or "")[:10] == today]
    if not want:
        return "夹具不成立：今天没有任何已关闭件"
    got = mod.filter_items(items, "closed:" + today)
    if len(got) != len(want):
        return "closed:%s 收到 %d 条，按关闭日应为 %d 条" % (today, len(got), len(want))
    return True


@check("T-04c ★ `closed:<日期>` 过滤器：按关闭日收件（账本「已处理」格的深链）")
def t04c():
    """★ 为什么必须有它：`day:<d>:archive` 的归档桶混着「已老去、无后果、
    **从未被关闭**」的记录（实测 2026-10-14：归档收 [a,b]，`closed:` 只收 [b]）
    ⇒ 账本「已处理」格点进去会看到对不上数的一页。
    """
    items = _ledger_items()
    r = _t04c_core(M)
    if r is not True:
        return r
    today = datetime.now().astimezone().date().isoformat()
    # ① 口径必须是**关闭日**，不是发生日：夹具里至少有一件「发生日≠关闭日」
    cross = [it for it in items if it.state in M.CLOSED_STATES
             and str(it.closed_at or "")[:10] == today and str(it.ts)[:10] != today]
    if not cross:
        return "夹具不成立：没有「发生日≠关闭日」的件 ⇒ 判据无分辨力"
    # ② 链接必须被认（否则会被 `known_filter` 挡回默认档，点了等于没点）
    if not M.known_filter("closed:" + today):
        return "known_filter 不认 closed:<日期> ⇒ 深链会被当非法值挡回默认档"
    if M.filter_items(items, "closed:2026-13-45"):
        return "坏日期没有返回空集（静默当「全部」＝口径污染）"
    # ③ 与旧过滤器不是一回事（否则新增它就没有独立语义）
    days = sorted({str(it.ts)[:10] for it in items})
    differ = [d for d in days
              if {i.id for i in M.filter_items(items, "day:%s:archive" % d)}
              != {i.id for i in M.filter_items(items, "closed:" + d)}]
    if not differ:
        return "closed:<d> 与 day:<d>:archive 在每个日子都完全相同 ⇒ 新过滤器没有独立语义"
    return True


@check("N-T04c ★ 负控：closed: 退化成按**发生日**收 ⇒ T-04c 必须红")
def n_t04c():
    """变异＝把 `closed_at` 换成 `ts`。这正是当初"顺手复用 day::archive"的写法，
    也是账本「已处理」与收件箱对不上的老根。"""
    src = _src(_MODEL_REL)
    anchor = '                and str(it.closed_at or "")[:10] == filt[7:]]'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    try:
        mut = _load(src.replace(anchor,
                                "                and str(it.ts)[:10] == filt[7:]]"),
                    "is0490_nt04c", _MODEL_REL)
    except Exception as e:                                          # noqa: BLE001
        return "负控自身失效：变异模块**加载就抛** %s: %s" % (type(e).__name__, e)
    if _t04c_core(mut) is True:
        return "负控失效：closed: 改成按发生日后 T-04c 没红"
    if _t04c_core(M) is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True


def _t04d_core(page, items):
    """账本页头部的**跨元素一致性**（创始人 2026-10-17 截图三问）。

    三条断言的共同点：**都在验同一页里两处说法是否一致**，而不是"某个结构
    在不在"。已有判据（T-04/T-04b）卡的是结构存在 —— 所以「下列四个数」
    下面并排摆六张卡、头部 11 天与月行 8 天打架，都没人报红。
    """
    body = PC.body(page)
    idx = M.day_counts(items)
    rec = {d: e for d, e in idx.items()
           if any(int(e.get(k) or 0) for k in M.LEDGER_KEYS)}
    today = datetime.now().astimezone().date().isoformat()
    if not rec:
        return "夹具不成立：没有有记录的天 ⇒ 判据无分辨力"
    # ① 撤卡后**不许留下指向卡片的文案**（三问之一的反面）：
    #   0.53.0（T4.2）头部四指标卡撤了 ⇒「下列 N 个数」这类数量词若还在，
    #   就是在指一个不存在的结构。三问之一的病根（文案与结构无引用关系）
    #   在这一版的具体形态就是「撤结构没撤文案」。
    n_card = body.count('class="metric"')
    if n_card:
        return "账本头部还有 %d 张指标卡 —— T4.2 已撤，数字的家是日报" % n_card
    if re.search(r"下列(.)个数", body):
        return "头部还留着「下列 N 个数」——卡片已撤，这句在指空气"
    # ② 同页天数**同源**：头部＝链现算，月行当月天数＝链现算（三问之三）
    m = re.search(r"有记录 <b>(\d+)</b> 天", body)
    if not m:
        return "头部没有「有记录 N 天」（历史覆盖信息丢了）"
    if int(m.group(1)) != len(rec):
        return ("头部「有记录 %s 天」≠ 链现算 %d 天 ⇒ 同页两个口径（三问之三）"
                % (m.group(1), len(rec)))
    for ym in sorted({d[:7] for d in rec}):
        n = sum(1 for d in rec if d[:7] == ym)
        if ("有记录 %d 天" % n) not in body:
            return ("%s 月行天数 ≠ 链现算 %d 天 ⇒ 页面上两个天数打架（三问之三）"
                    % (ym, n))
    # ③ 连续与总数**相等时只说一次**（三问之二：11 天出现两次）
    import ledger as L
    st = L._streak(set(rec), today=today)
    if st >= len(rec):
        if "连续至今" not in body:
            return "连续＝有记录天数时没走「连续至今」⇒ 同页会出现两个同数（三问之二）"
        if re.search(r"连续 \d+ 天", body):
            return "既说「连续至今」又报「连续 N 天」—— 同数并列没消掉"
    else:
        if ("当前连续 %d 天" % st) not in body:
            return "有断档时没报「当前连续 %d 天」（现算 %d）" % (st, st)
    return True


@check("T-04d ★ 头部：撤卡后零卡片零旧文案 ＋ 同页天数同源 ＋ 不重复同数")
def t04d():
    """创始人 2026-10-17 截图三问（账本页头部）：
      ① 「下列四个数」下面摆了六张卡；
      ② 「连续有记录 11 天」与「有记录的天数 11」同页并列；
      ③ 头部「11 天」与月行「有记录 8 天」打架（头部走旧快照、明细走链现算）。
    """
    items = _ledger_items()
    r = _t04d_core(_ledger_page(items=items), items)
    if r is not True:
        return r
    # ③' 把「连续＝总数」那一支也走到：连续三天都有记录 ⇒ 必须只说一次
    now2 = datetime.now().astimezone()

    def _ts(d, h):
        return (now2 - timedelta(days=d)).replace(
            hour=h, minute=0, second=0, microsecond=0).isoformat()

    cont = [M.Item(alert=M.Alert(id="t04d_c%d" % k, ts=_ts(k, 9), level="L2",
                                 kind="tool_call_blocked", title="t"))
            for k in range(3)]
    if "连续至今" not in PC.body(_ledger_page(items=cont)):
        return "连续三天都有记录时没出现「连续至今」⇒ 那就会同屏显示两个 3"
    return True


@check("N-T04d ★ 负控：撤卡后把「下列四个数」塞回头部 ⇒ T-04d 必须红")
def n_t04d():
    """反向对照：模拟「撤了结构没撤文案」—— 头部塞回一句「下列四个数」。

    ★★ 0.53.0（T4.2）重锚：旧锚点是 `% _zh_num(len(_cards))`（卡片的派生
      数量词）—— 卡片整块撤掉后该表达式不复存在 ⇒ 负控自己会报「锚点未找到」。
      新锚点选**仍然存在的头部小字行**（`_meta`），往里前置一句旧文案。
      ★ 教训延续（0.51.2 记过一次）：负控锚点要跟着**仍存在的结构**走，
        不能挂在会被整块删掉的东西上。
    """
    src = _src(_SERVER_REL)
    anchor = ('    _meta = ("<p class=\\"note\\">%s 有记录 <b>%d</b> 天 · %s %s</p>"')
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    items = _ledger_items()
    page, _why = _mut_render(
        src.replace(anchor,
                    '    _meta = ("<p class=\\"note\\">下列四个数：%s 有记录 '
                    '<b>%d</b> 天 · %s %s</p>"'),
        "is0490_nt04d", _SERVER_REL, view="ledger",
        root=tempfile.mkdtemp(prefix="g0490_nt04d_"), token="T", items=items,
        rep=_ledger_rep(items), posture=_POSTURE)
    if _why:
        return _why
    if _t04d_core(page, items) is True:
        return "负控失效：塞回旧文案后 T-04d 没红"
    if _t04d_core(_ledger_page(items=items), items) is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True


@check("N-T04d-b ★ 负控：头部天数与链现算脱钩（+1）⇒ T-04d 必须红")
def n_t04d_b():
    """变异＝头部「有记录 N 天」的 N 改成 `_n_days + 1`。
    模拟的正是三问之三的老形态：头部一个口径（旧快照）、明细另一个口径（链现算），
    同一页两个数，读者不知道信哪个。"""
    src = _src(_SERVER_REL)
    anchor = '% (GL.chip("days"), _n_days, GL.chip("streak"), _streak_txt))'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    items = _ledger_items()
    page, _why = _mut_render(
        src.replace(anchor,
                    '% (GL.chip("days"), _n_days + 1, GL.chip("streak"), _streak_txt))'),
        "is0490_nt04db", _SERVER_REL, view="ledger",
        root=tempfile.mkdtemp(prefix="g0490_nt04db_"), token="T", items=items,
        rep=_ledger_rep(items), posture=_POSTURE)
    if _why:
        return _why
    if _t04d_core(page, items) is True:
        return "负控失效：头部天数与链现算脱钩后 T-04d 没红"
    if _t04d_core(_ledger_page(items=items), items) is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True


# ============================================== 体检页四组（0.53.0 P6 二）====
# 施工单 v1.0 S2.1：H3 / H4b / H7 / H3-c2，各配一条负控。
# ★ 数据源全部来自 payload（details / egress / observations），**零新增采集**。
# ★ 六档与译文一律 `import antinel` 取真源，判据不许二次实现。

_H_TITLES = [
    "① 我电脑上有哪些 AI 工具",
    "② 我的哪些项目被打包过",
    "③ 此刻谁在往外连",
    "④ 别处还有什么",
]
_HEALTH_REL = "ui_server.py"


def _h_scan(n_tools=17, details=None, obs=None, **cov):
    """合成体检 payload。

    ★ 数字刻意取**不可能自然撞上**的值（17 / 991 / 992 / 993）：
      若页面只渲染其中一个口径，另一个口径的数就不会出现 ⇒ 断言不会误绿。
      （v1.11 §36.3：页面用 59、终端用 41，两个数都合法且**互不包含**，
      用户两边看会对不上 —— 本判据就是把「两个都必须出现」钉成机器守的事实。）
    """
    c = {"registered_roots": 991, "present": 992, "scanned": 992,
         "unscanned": 0, "added_by_registry": 993, "absent": 5,
         "armed_hosts": 1, "unarmed_hosts": 23}
    c.update(cov)
    return {
        "generated_at": "2026-10-17T00:00:00+08:00",
        "tools": [{"name": "t%02d" % i, "host": "h%02d" % i,
                   "path": "D:/t/%02d" % i, "root": "D:/t/%02d" % i,
                   "verdict": "CLEAN", "ev": [], "files": []}
                  for i in range(n_tools)],
        "details": details or {},
        "coverage": c,
        "counts_by_verdict": {"PACK": 0, "SENT": 0, "SYNC": 0,
                              "CLEAN": n_tools, "NA": 0},
        "observations": obs if obs is not None else {},
    }


def _h_egress(with_ghost=True, findings=None):
    """合成 egress payload。

    ★ `Ghost.exe` **只在 `longest_by_proc` 里**（账本有 49.4 小时证据、此刻已退出，
      `conns` 里没有）⇒ 只取 `conns` 就会把它弄丢。
      v1.11 §36.1 实测：本机 `AutoClaw.exe` 正是这么被漏掉的 ——
      「有证据却不显示」比显示错更糟。

    ★ `findings` 默认空（C 组判据不关心它）；H8 族显式传入。
    """
    lg = {"A.exe": 162.5 * 3600, "B.exe": 32.9 * 3600}
    if with_ghost:
        lg["Ghost.exe"] = 49.4 * 3600
    return {"snapshot": {"ok": True, "conns": [
                {"proc": "A.exe", "pid": 11}, {"proc": "A.exe", "pid": 11},
                {"proc": "A.exe", "pid": 11},
                {"proc": "B.exe", "pid": 22}, {"proc": "B.exe", "pid": 22}]},
            "findings": findings if findings is not None else [],
            "longest_by_proc": lg,
            "days_with_data": 7,
            "coverage_seconds": 601268.0,
            "sample_failed": 1}


def _h_proj_details(ws_bytes, enc_bytes, accepted=True, fail=None, ws="D:/proj"):
    """合成 B 组数据源。**键名与本机实测逐字一致**（2026-10-17 实读）：

      workspacePath / lastCompressedSize.workspaceSizeBytes /
      lastCompressedSize.encryptedSizeBytes / lastCompressedSize.recordedAt /
      lastAcceptedManifestHash / failureCount（仅 D:\\2026\\PSL 有，值 3）

    ★ 四个项目目录同在 `C:\\Users\\大马\\.zcode` **一个键下的多个块**里
      ⇒ B 组必须遍历**块**，不能只遍历键（否则只剩一行）。
    """
    items = [
        {"kpath": "workspacePath", "kind": "context", "value": ws},
        {"kpath": "lastCompressedSize.workspaceSizeBytes", "kind": "context",
         "value": ws_bytes},
        {"kpath": "lastCompressedSize.encryptedSizeBytes", "kind": "mark",
         "value": enc_bytes},
        {"kpath": "lastCompressedSize.recordedAt", "kind": "context",
         "value": 1788827124448},
    ]
    if accepted:
        items.append({"kpath": "lastAcceptedManifestHash", "kind": "mark",
                      "value": "c8b5bb31ed38014c"})
    if fail is not None:
        items.append({"kpath": "failureCount", "kind": "mark", "value": fail})
    return {"C:/u/.zcode": [{"file": ".zcode/v2/checkpoints/x/state.json",
                             "items": items}]}


def _health_render(scan, egress=None, src=None, tag="is0490_health"):
    """跑一次体检页渲染。返回 `(page, None)` 或 `(None, 说明串)`。

    ★ 与 C1 的 `_mut_render` 同型：**量具故障（抛异常）与产品红必须分开**，
      否则「负控自己崩了」会被读成「产品有缺陷」。
    """
    import antinel                                                 # noqa: E402
    res = {"scan": scan, "egress": egress if egress is not None else {}}
    try:
        if src is None:
            import ui_server as U                                  # noqa: E402
            return U._result_html(res, antinel.VERDICTS, antinel._ev_human), None
        mod = _load(src, tag, _HEALTH_REL)
        return mod._result_html(res, antinel.VERDICTS, antinel._ev_human), None
    except Exception as e:                                         # noqa: BLE001
        return None, ("量具故障：渲染抛 %s: %s —— 不是产品问题，不算通过"
                      % (type(e).__name__, e))


def _h_mut(anchor, repl, tag, scan, egress=None):
    """负控两步法第一步：注入必须**真的生效**（锚点不存在 ⇒ 负控自身失效）。"""
    src = _src(_HEALTH_REL)
    if anchor not in src:
        return None, ("变异锚点未找到（源码已变，需更新负控）—— "
                      "负控自身失效，不算通过：%r" % anchor[:60])
    return _health_render(scan, egress, src=src.replace(anchor, repl), tag=tag)


def _h3_core(page):
    miss = [t for t in _H_TITLES if t not in page]
    if miss:
        return "页面缺少组标题：%s" % "、".join(miss)
    return True


@check("H3 ★ 体检页四组标题齐全（①AI 工具／②被打包项目／③此刻外连／④别处还有什么）")
def h3():
    """★ 四组是创始人 2026-10-17 定的明细单骨架（v1.11 §27.3）。

    判据只断言**标题存在且在渲染产物里**，不查行号、不查实现细节 ——
    组里填什么由 H4b／H7／H3-c2／H5 各自守。
    """
    page, why = _health_render(_h_scan())
    return why or _h3_core(page)


@check("N-H3 ★ 负控：D 组的渲染被摘掉 ⇒ H3 必须红")
def n_h3():
    # ★ 锚点是**组标题字面量**：它随四组一起落地，且不在别处出现
    #   （0490 N-T04d 的教训：锚在会被重构掉的字面量上，重构一次负控就失效）。
    page, why = _h_mut('"<h2>④ 别处还有什么</h2>"', '""',
                       "is0490_nh3", _h_scan())
    if why:
        return why
    if _h3_core(page) is True:
        return "负控失效：D 组被摘掉后 H3 没红"
    if _h3_core(_health_render(_h_scan())[0]) is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True


def _h4b_core(page, scan):
    c = scan["coverage"]
    need = {"扫到数(%d)" % len(scan["tools"]): str(len(scan["tools"])),
            "登记数(%d)" % c["registered_roots"]: str(c["registered_roots"]),
            "存在数(%d)" % c["present"]: str(c["present"]),
            "登记表补上(%d)" % c["added_by_registry"]: str(c["added_by_registry"])}
    miss = [k for k, v in need.items() if v not in page]
    if miss:
        return ("L0 双口径缺数：%s —— 只给一个口径，用户拿页面与终端对账时会对不上"
                % "、".join(miss))
    return True


@check("H4b ★ L0 双口径：扫到 N ＋ 登记/存在/登记表补上 各自带分母（只给一个即红）")
def h4b():
    scan = _h_scan()
    page, why = _health_render(scan)
    return why or _h4b_core(page, scan)


@check("N-H4b ★ 负控：第二口径被第一口径顶掉（登记数写成 len(tools)）⇒ H4b 必须红")
def n_h4b():
    """变异模拟的正是 v1.11 §36.3 撞出的病：**两口径互不包含，却被写成一个**。"""
    page, why = _h_mut("int(cov.get(\"registered_roots\") or 0)",
                       "len(tools)", "is0490_nh4b", _h_scan())
    if why:
        return why
    scan = _h_scan()
    if _h4b_core(page, scan) is True:
        return "负控失效：登记数被顶掉后 H4b 没红"
    if _h4b_core(_health_render(scan)[0], scan) is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True


def _h7_core(page, want):
    if want in page:
        return True
    return ("B 组没渲染出压缩倍数 %s —— 取数不是 details 里的 "
            "workspaceSizeBytes／encryptedSizeBytes" % want)


@check("H7 ★ B 组同源：压缩倍数取自 details（143378975/242231⇒591；88144362/46224⇒1906）")
def h7():
    """★ 负控方向：改成另一份 size（encryptedSizeBytes）⇒ 倍数变 ⇒ 必红。
    两个真值都测，防「只对一组数碰巧成立」。"""
    scan1 = _h_scan(details=_h_proj_details(143378975, 242231))
    page1, why1 = _health_render(scan1)
    if why1:
        return why1
    r = _h7_core(page1, "591")
    if r is not True:
        return r
    scan2 = _h_scan(details=_h_proj_details(88144362, 46224))
    page2, why2 = _health_render(scan2)
    if why2:
        return why2
    return _h7_core(page2, "1906")


@check("N-H7 ★ 负控：取数换成 encryptedSizeBytes（也是 size，口径错）⇒ H7 必须红")
def n_h7():
    """★ 锚点选**结构性字面量**而不是文案（0490 N-T04d 的教训：
    锚在会被重构掉的文案上，重构一次负控就失效）。"""
    scan = _h_scan(details=_h_proj_details(143378975, 242231))
    page, why = _h_mut('"lastCompressedSize.workspaceSizeBytes"',
                       '"lastCompressedSize.encryptedSizeBytes"',
                       "is0490_nh7", scan)
    if why:
        return why
    if _h7_core(page, "591") is True:
        return "负控失效：取数换成加密后大小后 H7 没红（倍数应变成 1.0）"
    if _h7_core(_health_render(scan)[0], "591") is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True


def _h3c2_core(page):
    return True if "Ghost.exe" in page else (
        "页面上没有 `Ghost.exe` —— 它只在 `longest_by_proc` 里（账本有 49.4 小时证据、"
        "此刻已退出）；只取 `conns` 就会把这条证据弄丢")


@check("H3-c2 ★ C 组行集合＝longest_by_proc 键 ∪ conns 进程（只取 conns 即红）")
def h3c2():
    page, why = _health_render(_h_scan(), _h_egress())
    return why or _h3c2_core(page)


@check("N-H3-c2 ★ 负控：行集合退回只取 conns ⇒ Ghost.exe 消失 ⇒ H3-c2 必须红")
def n_h3c2():
    scan, eg = _h_scan(), _h_egress()
    page, why = _h_mut(
        'procs = list((eg.get("longest_by_proc") or {}).keys())',
        'procs = []', "is0490_nh3c2", scan, eg)
    if why:
        return why
    if _h3c2_core(page) is True:
        return "负控失效：只取 conns 后 H3-c2 没红"
    if _h3c2_core(_health_render(scan, eg)[0]) is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True


# ═════════ 批18 · H8（findings 的 lines 必须上页面）═════════
# 施工单 v1.2 第一件（0.53.0 收尾）：S10 实测 egress.run(as_json=True) 的 findings
#   10 条，每条**只有 `kind` 和 `lines`**（`label` 恒不存在），`lines` 恒 3 行。
#   而旧渲染 `<li>{label or kind}</li>` ⇒ 页面上 10 条只有「空闲期外连」「长连接」
#   两个词在重复 —— **外框写着「值得看一眼的 10 条」，实质内容一行没有**。
# ★ 编号为什么是 H8 不是 F1：`F1` 已被 `0364` 占（"泡泡真身是气泡通道"），
#   0515 的 UID15-b（跨套件重名折叠检测）当场判红 —— 新判据编号**必须先查重名**。
_F_LINES = [
    "你已空闲 7777 小时；这期间 Probe.exe 新建 8642 条外部连接",
    "远端：10.0.0.1:443, 10.0.0.2:443",
    "→ 若是你主动发起的任务或后台更新，忽略即可。",
]
#: ★ 四个串都取**不可能自然撞上**的值（7777／8642／10.0.0.1），
#:   且**分别来自 lines 的三行** ⇒ 任一行丢了都会被抓到（不是只对一行碰巧成立）。
_F_NEED = ["Probe.exe", "8642", "10.0.0.1", "忽略即可"]


def _h_findings(n=2):
    """合成 findings。**键与实测逐字一致**（`kind` + `lines`，无 `label`）。"""
    return [{"kind": "长连接", "lines": list(_F_LINES)} for _ in range(n)]


def _h8_core(page):
    miss = [s for s in _F_NEED if s not in page]
    if miss:
        return ("页面上找不到 findings 的实质内容（缺 %s）—— 每条只渲染了 `kind`"
                "（类别名），而 `label` 实测恒不存在 ⇒ 10 条里只有两个词在重复"
                % "、".join(miss))
    return True


@check("H8 ★ findings 的 lines 三行必须上页面（只显示 kind ⇒ 有内容等于没内容）")
def h8():
    """★ 与「四组明细」同病：payload 里有内容，页面把内容显示成了没有。

    判据只断言 **lines 的三行都出现在渲染产物里**，不查行号、不查实现细节。
    """
    eg = _h_egress(findings=_h_findings(2))
    page, why = _health_render(_h_scan(), eg)
    return why or _h8_core(page)


@check("N-H8 ★ 负控：渲染退回只显示 kind（lines 全丢）⇒ H8 必须红")
def n_h8():
    """★ 锚点选**新代码里的结构性字面量**（N-T04d 教训：锚在会被重构掉的文案上，
    重构一次负控就失效）。变异形态 = 把取 lines 的那一步换成空列表。"""
    eg = _h_egress(findings=_h_findings(2))
    page, why = _h_mut('(f.get("lines") or [])', '[]',
                       "is0490_nf1", _h_scan(), eg)
    if why:
        return why
    if _h8_core(page) is True:
        return "负控失效：lines 全丢后 H8 没红"
    if _h8_core(_health_render(_h_scan(), eg)[0]) is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True


# ═════════ 批19 · T0（第五 TAB：体检进控制台，0.53.0 第一优先）═════════
# 施工单 v1.3 T0.6；创始人 2026-10-18 03:18 截图交办（四个 TAB 变五个）。
# 设计 v1.11 §21.2（接触点 2/4）／§21.3（三态写死）／§20.2（局部边界）／§20.4（版面）。
# ★ 编号：H 族续 H8（体检页）；H9/H10/H11 全树无重名 —— 0353 里的"H9"只在
#   docstring，登记名是「P16 体检留得下本机存档」（0515 UID15-b 按登记名折叠）。
# ★ 注入点：体检页 GET **从不触发采集**（host-scan 4～9 分钟）⇒ 判据渲染
#   零子进程，结果经模块级缓存 `_EXAM` 注入（state="done" + 合成 payload）。
_EXAM_RES = {"scan": _h_scan(), "egress": _h_egress()}
#: 首启引导条原文（设计 §21.2 写死）—— 判据独立持一份，产品那边写错即红
_EXAM_GUIDE = "这是第一次打开监理。先做一次体检吧——它只读，不会改任何东西。"
_VERDICT_KEYS = ("PACK", "SENT", "SYNC", "CLEAN", "BLIND", "NA")


def _exam_inject(mod=SV, res=None):
    """把模块的体检缓存置为「已跑完」，返回原状态（调用方 try/finally 还原）。"""
    old = dict(getattr(mod, "_EXAM", None) or {})
    if not hasattr(mod, "_EXAM"):
        return old          # 旧代码没有体检缓存 ⇒ 无从注入（页面落回收件箱 ⇒ H9 红）
    mod._EXAM.update(state="done", result=res if res is not None else _EXAM_RES,
                     stage="", error="", saved="x", started=1.0, finished=2.0)
    return old


def _exam_restore(mod, old):
    if hasattr(mod, "_EXAM"):
        mod._EXAM.clear()
        mod._EXAM.update(old)


def _exam_page(mod=SV, res=None):
    """渲染体检页（第五 TAB；结果注入 + 用完还原）。"""
    old = _exam_inject(mod, res)
    try:
        return _page("health_exam", mod=mod)
    finally:
        _exam_restore(mod, old)


def _exam_mut(src, tag, res=None):
    """C1 两步法 · **体检版**：变异源码 → 内存加载 → 注入体检缓存 → 渲染。

    与 `_mut_render` 同一契约（加载抛／渲染抛 ⇒ 明确判「负控自身失效，
    不算通过」—— 量具故障不许伪装成产品问题），多一步 `_EXAM` 注入：
    体检页 GET 从不触发采集，结果只在进程内缓存里，不注入就渲染不出四组
    （负控会因「缺标题」这种错原因翻红，证明不了想证明的那件事）。
    ★ 为什么不像 `_mut_render` 那样只收 kw：注入点在加载之后、渲染之前，
      `_mut_render` 的「加载即渲染」插不进这一步；两步契约逐字保持一致。
    """
    try:
        mod = _load(src, tag, _SERVER_REL)
    except Exception as e:                                     # noqa: BLE001
        return None, ("负控自身失效：变异模块**加载就抛** %s: %s —— "
                      "量具故障（变异把源码写坏了），不算通过"
                      % (type(e).__name__, e))
    old = _exam_inject(mod, res)
    try:
        return mod.render_page(view="health_exam", token="T",
                               root=tempfile.mkdtemp(prefix="g0490_%s_" % tag),
                               items=[], posture=_POSTURE), None
    except Exception as e:                                     # noqa: BLE001
        return None, ("负控自身失效：变异模块**渲染抛** %s: %s —— "
                      "量具故障（多半是变异少给了参数），不算通过"
                      % (type(e).__name__, e))
    finally:
        _exam_restore(mod, old)


def _fresh_hub():
    """换一个临时中枢，返回 (dir, 旧值) —— 判据动环境必须 try/finally 还原。"""
    d = tempfile.mkdtemp(prefix="g0490_exam_")
    old = os.environ.get("ANTINEL_HUB_DIR")
    os.environ["ANTINEL_HUB_DIR"] = d
    return d, old


def _restore_hub(old):
    if old is None:
        os.environ.pop("ANTINEL_HUB_DIR", None)
    else:
        os.environ["ANTINEL_HUB_DIR"] = old


def _snap(days_ago, hub):
    """在临时中枢写一份体检快照（console-exam 形状，与产品写入同构）。"""
    d = os.path.join(hub, "health")
    os.makedirs(d, exist_ok=True)
    ts = (datetime.now().astimezone() - timedelta(days=days_ago)).replace(
        microsecond=0)
    p = os.path.join(d, "audit-%s-000.json" % ts.strftime("%Y%m%d-%H%M%S"))
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"schema": "antinel.health/1", "generated_at": ts.isoformat(),
                   "source": "console-exam", "tools": 3,
                   "verdicts": {"PACK": 0, "SENT": 0, "SYNC": 0, "CLEAN": 3,
                                "BLIND": 0, "NA": 0},
                   "conns": 0}, f, ensure_ascii=False)
    return p


def _nav(page):
    """导航选项卡 [(view, 可见文本)] —— 按 <nav class="tabs"> 圈定。

    ★ 与 `_tabs()`（筛选项）不是一回事：那个按 `title="单位："` 认筛选条，
      这是页面顶部的视图导航（第五 TAB 加在这里）。
    """
    m = re.search(r'<nav class="tabs">(.*?)</nav>', page, re.S)
    if not m:
        return None
    return re.findall(r'<a href="/\?v=([a-z_]+)"[^>]*>([^<]*)</a>', m.group(1))


def _h9_core(page):
    nav = _nav(page)
    if nav is None:
        return "页面上没有选项卡条 —— 第五 TAB 无从谈起"
    if len(nav) != 5:
        return "选项卡是 %d 个（应为 5）：%s" % (len(nav), "／".join(
            t for _v, t in nav))
    if ("health_exam", "体检") not in nav:
        return "第五个选项卡不是「体检」（v=health_exam）：%r" % (nav,)
    # 四组标题与 H3 共用 `_H_TITLES`（不另写一份尺子）
    miss = [t for t in _H_TITLES if t not in page]
    if miss:
        return ("体检正文缺四组标题：%s —— 渲染没有复用 ui_server._result_html？"
                % "、".join(miss))
    return True


@check("H9 ★ 第五 TAB「体检」落地：选项卡恰 5 项＋正文含四组标题（H3 同一把尺子）")
def h9():
    """★ T0 第一优先（创始人 03:18 截图：四个 TAB 变五个，多一个体检）。

    断言打在**行为**上（渲染产物），不查行号；视图名不与运行状态（health）
    撞车由 N-H9 守；第二份六档由 H11 守。
    """
    page = _exam_page()
    return _h9_core(PC.body(page))


@check("N-H9 ★ 负控：第五 TAB 的视图名撞上 health（运行状态）⇒ H9 必须红")
def n_h9():
    """★ 锚点选**结构性字面量** `a("health_exam", "体检")`（随 T0 一起落地；
    N-T04d 教训：不锚在会被重构掉的文案上）。变异形态＝视图名改成 health：
    两个 TAB 指向同一页，体检入口消失（用户点「体检」落到运行状态）。"""
    src = _src(_SERVER_REL)
    anchor = 'a("health_exam", "体检")'
    if anchor not in src:
        return ("变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，"
                "不算通过：%r" % anchor)
    page, why = _exam_mut(src.replace(anchor, 'a("health", "体检")'),
                          "is0490_nh9")
    if why:
        return why
    page = PC.body(page)
    if _h9_core(page) is True:
        return "负控失效：视图名撞上 health 后 H9 没红"
    if _h9_core(PC.body(_exam_page())) is not True:
        return "夹具不成立：真实现本身就红 ⇒ 负控无分辨力"
    return True

@check("H10 ★ 首启落体检页＋引导条逐字；有快照后引导条消失＋「上次体检：N 天前」")
def h10():
    """设计 §21.2 接触点 2／§21.4／§20.4。四件事全落在**行为**上：
    默认落点（default_view）、引导条逐字在/不在、「上次体检」行的数与三态互斥。"""
    dv = getattr(SV, "default_view", None)
    if dv is None:
        return "inbox_server 没有 default_view（T0.2 首启落点未实现）"
    # ① 无快照：默认落点＝体检页；引导条逐字在；不许出现「上次体检」
    hub, old = _fresh_hub()
    try:
        if dv() != "health_exam":
            return "无快照时默认落点是 %r（应为 health_exam）" % (dv(),)
        page = PC.body(_exam_page())
        if _EXAM_GUIDE not in page:
            return "首启引导条不在页面上（逐字：%s）" % _EXAM_GUIDE
        if "上次体检" in page:
            return "首装空态出现了「上次体检」—— §21.3 明令不显示那一行"
        # ② 有快照（3 天前）：默认回落收件箱；引导条消失；行在且数对
        _snap(3, hub)
        if dv() != "inbox":
            return "有快照后默认落点仍是 %r（引导条会永远在）" % (dv(),)
        page2 = PC.body(_exam_page())
        if _EXAM_GUIDE in page2:
            return "快照存在后引导条仍在（§21.4：完成一次体检后永久消失）"
        if "上次体检：3 天前" not in page2:
            return "有快照但页面上没有「上次体检：3 天前」（T0.3 一行版）"
    finally:
        _restore_hub(old)
    # ③ 当天的快照 ⇒ 「刚刚」（换个新中枢，不删任何文件）
    hub, old = _fresh_hub()
    try:
        _snap(0, hub)
        page3 = PC.body(_exam_page())
        if "上次体检：刚刚" not in page3:
            return "当天的快照没有渲染成「刚刚」（T0.3：当天＝刚刚）"
    finally:
        _restore_hub(old)
    return True


@check("N-H10 ★ 负控：空态编「上次体检：0 天前」/ 没查成说成「没问题」⇒ 必须红")
def n_h10():
    """三态互斥（§21.3）的两把尺子，各配一个变异证明尺子有牙：
    ① 空态不许出现「上次体检」—— 变异：空态分支值从 "" 换成 "0 天前"；
    ② 没查成不许说「都没问题」—— 变异：在没查成句尾追加"不过其它都没问题"。
    ★ 排除词扫 `<div class="err">` **单句**，不扫全页 —— 边界声明里逐字含
      「不要当成"没问题"」（§20.2 TPL 原文），全页扫会把**正确的页面**判红
      （「文案自带禁词把尺子废掉」同族：2026-10-17 `_OBS_NOT_CONFIGURED`）。"""
    src = _src(_SERVER_REL)
    a1 = 'if reports else ""'
    if a1 not in src:
        return ("变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，"
                "不算通过：%r" % a1)
    hub, old = _fresh_hub()
    try:
        page, why = _exam_mut(src.replace(a1, 'if reports else "0 天前"'),
                              "is0490_nh10a")
    finally:
        _restore_hub(old)
    if why:
        return why
    page = PC.body(page)
    if "上次体检" not in page:
        return "负控失效：空态编出「0 天前」后尺子没红"
    # 尺子②：没查成态（tools 缺失）的 err 单句排除 affirmative 干净话
    a2 = '结果不算数。"'
    if a2 not in src:
        return ("变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，"
                "不算通过：%r" % a2)
    page2, why = _exam_mut(src.replace(a2, '结果不算数。不过其它都没问题。"', 1),
                           "is0490_nh10b",
                           res={"scan": {}, "egress": _h_egress()})
    if why:
        return why
    page2 = PC.body(page2)
    err = re.search(r'<div class="err">(.*?)</div>', page2, re.S)
    if not err:
        return "夹具不成立：没查成态没有渲染 err 单句 ⇒ 尺子②无对象"
    if not any(w in err.group(1) for w in ("都没问题", "全部干净", "一切正常",
                                           "没有发现问题")):
        return "负控失效：没查成句追加「都没问题」后尺子②没红"
    # 连回正判据：真实现的没查成态 err 单句必须不含那些话
    real = PC.body(_exam_page(res={"scan": {}, "egress": _h_egress()}))
    err2 = re.search(r'<div class="err">(.*?)</div>', real, re.S)
    if not err2:
        return "夹具不成立：真实现的没查成态没有 err 单句"
    if any(w in err2.group(1) for w in ("都没问题", "全部干净", "一切正常",
                                        "没有发现问题")):
        return "真实现的没查成句自带干净话：%r" % err2.group(1)
    return True


def _verdict_titles():
    """六档人话标题（真源 antinel.VERDICTS）—— 判据不手抄，产品改词尺子跟着走。"""
    import antinel as _A
    return tuple(str(v.get("title") or "") for v in _A.VERDICTS.values())


def _h11_core(src_server, src_ui):
    """体检渲染路径上不许有第二份六档（VERDICTS 必须 import，不许写字面量）。

    ★ 两把尺子（AST，不是正则）：
      ① 六键齐全且**值为字典**的 dict 字面量＝表格形状的副本
         （ui_server `_tiles` 里的键→**颜色**表值是字符串，是排版不是第二份六档，放行）；
      ② 六键齐全且有值命中六档标题＝扁平副本（能渲染的最小抄法）。
    """
    import ast
    titles = set(_verdict_titles())
    bad = []
    for rel, src in ((_SERVER_REL, src_server), (_HEALTH_REL, src_ui)):
        try:
            tree = ast.parse(src)
        except SyntaxError as e:
            bad.append("%s 解析失败：%s" % (rel, e))
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            keys = {k.value for k in node.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)}
            if not set(_VERDICT_KEYS) <= keys:
                continue
            if any(isinstance(v, ast.Dict) for v in node.values):
                bad.append("%s 里有六键齐全且值为字典的字面量（第二份六档表）" % rel)
                break
            vals = {v.value for v in node.values
                    if isinstance(v, ast.Constant) and isinstance(v.value, str)}
            if vals & titles:
                bad.append("%s 里有六键齐全且值命中六档标题的字面量（第二份六档）" % rel)
                break
    return "；".join(bad) if bad else True


@check("H11 ★ 体检渲染不出现第二份六档：VERDICTS 是 import 不是写字面量（AST）")
def h11():
    """设计 §20.1「六档一律 import，禁止第二份实现」的控制台侧落点。

    ★ 为什么必须是源码尺子：一份抄来的六档**渲染结果与真源逐字一样**
      （同一批标题/图标/次序）⇒ 行为断言分辨不出来，只有 AST 能抓到。
    """
    return _h11_core(_src(_SERVER_REL), _src(_HEALTH_REL))


def _verdicts_copy_src():
    """一份**形状兼容**的六档副本（负控注入用）—— 字段与真源逐字一致，
    渲染结果与真源完全相同 ⇒ 证明该缺陷只有源码尺子抓得到。"""
    import antinel as _A
    rows = []
    for k, v in sorted(_A.VERDICTS.items(), key=lambda kv: kv[1].get("order", 9)):
        rows.append('"%s": {"key": "%s", "icon": "%s", "title": "%s", '
                    '"order": %d, "short": "%s"}'
                    % (k, v["key"], v["icon"], v["title"],
                       int(v.get("order", 9)),
                       str(v.get("short") or "").replace("\\", "\\\\").replace('"', '\\"')))
    return "{\n    " + ",\n    ".join(rows) + "}"


@check("N-H11 ★ 负控：往体检渲染里塞一份形状兼容的六档副本 ⇒ H11 必须红")
def n_h11():
    """★ 变异＝`_view_exam` 改用模块级副本 `_EXAM_VERDICTS_COPY`（抄真源形状）。
    两步都验：① 变异页**照样渲染出四组标题**（副本形状兼容 ⇒ 缺陷在行为上
    不可见）；② H11 的源码尺子在变异源码上必须红。"""
    src = _src(_SERVER_REL)
    anchor = "_U._result_html(res, _A.VERDICTS, _A._ev_human)"
    if anchor not in src:
        return ("变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，"
                "不算通过：%r" % anchor)
    mut_src = src.replace(
        anchor, "_U._result_html(res, _EXAM_VERDICTS_COPY, _A._ev_human)")
    mut_src = mut_src.replace(
        "def _view_exam(",
        "_EXAM_VERDICTS_COPY = %s\n\n\ndef _view_exam(" % _verdicts_copy_src(), 1)
    # ① 变异页照样渲染（副本形状兼容）—— 否则是量具故障不是产品缺陷证明
    page, why = _exam_mut(mut_src, "is0490_nh11")
    if why:
        return why
    page = PC.body(page)
    miss = [t for t in _H_TITLES if t not in page]
    if miss:
        return ("夹具不成立：副本形状不兼容，四组标题缺 %s —— "
                "变异没模拟出「行为上看不见」的缺陷" % "、".join(miss))
    # ② 源码尺子必须红
    if _h11_core(mut_src, _src(_HEALTH_REL)) is True:
        return "负控失效：塞了六档副本后 H11 没红"
    if _h11_core(_src(_SERVER_REL), _src(_HEALTH_REL)) is not True:
        return "夹具不成立：真实现本身就被 H11 判红 ⇒ 负控无分辨力"
    return True


# ═════════ 批20 · T1.1（诱饵文件状态进体检 ③ 组，0.53.0 P6 收尾）═════════
# 施工单 v1.3/v1.4 T1.1；设计 v1.11 §14.7 二段（外传与布防：egress 摘要＋诱饵文件）
# ／§20.3 术语表（页面一律「诱饵文件」，CLI 命令名 antinel canary 不动）。
# ★ 数据流：`antinel.canary_summary()`（唯一实现）→ payload `res["canary"]`
#   → `ui_server._canary_html` 渲染。判据经 `_result_html` 直接渲染，不起服务。
# ★ 五态不许混（文案地基）：没登记项目 ≠ 没放诱饵 ≠ 放了没被读 ≠ 被读过 ≠
#   带出去过。`observed` 是唯一强证据，「被读」不许渲染成「出事」。


def _canary_render(c, src=None, tag="is0490_h12"):
    """带诱饵 payload 跑一次体检页渲染（其余组用最小干净背景）。"""
    import antinel                                                 # noqa: E402
    res = {"scan": _h_scan(1), "egress": _h_egress(False), "canary": c}
    try:
        if src is None:
            import ui_server as U                                  # noqa: E402
            return U._result_html(res, antinel.VERDICTS,
                                  antinel._ev_human), None
        mod = _load(src, tag, _HEALTH_REL)
        return mod._result_html(res, antinel.VERDICTS,
                                antinel._ev_human), None
    except Exception as e:                                         # noqa: BLE001
        return None, ("量具故障：渲染抛 %s: %s —— 不是产品问题，不算通过"
                      % (type(e).__name__, e))


#: 五态夹具（数字取不可能自然撞上的值；planted 用 marker 名）
_C_NO_PROJ = {"projects": 0, "planted": [], "read": 0, "observed": 0}
_C_NONE_PLANTED = {"projects": 2, "planted": [], "read": 0, "observed": 0}
_C_UNREAD = {"projects": 2, "planted": ["CANARY-a-1", "CANARY-a-2"],
             "read": 0, "observed": 0}
_C_READ = {"projects": 2, "planted": ["CANARY-a-1", "CANARY-a-2"],
           "read": 3, "observed": 0}
_C_LEAKED = {"projects": 2, "planted": ["CANARY-a-1"], "read": 3,
             "observed": 2}


def _h12_core(render):
    """H12 尺子本体（正判据与负控共用同一把；render＝payload→页面的调用）。"""
    # 态①没登记项目：说「没查」，**不许**说成「没有」
    p, why = render(_C_NO_PROJ)
    if why:
        return why
    t = PC.body(p)
    if "还没有登记过项目" not in t:
        return "态①（没登记项目）没有自己的话——「没查」被渲染成了别的"
    if "一个诱饵文件都没有" in t:
        return "态①把「没查」说成了「没有」（本仓铁律：没查过≠查过没有）"
    # 态②没放过：给放置入口
    p, why = render(_C_NONE_PLANTED)
    if why:
        return why
    if "还没有放过诱饵文件" not in PC.body(p):
        return "态②（没放过）没有自己的话"
    if "antinel canary plant" not in p:
        return "态②没给放置入口（CLI 命令名）"
    # 态③放了没被读
    p, why = render(_C_UNREAD)
    if why:
        return why
    t = PC.body(p)
    if "放了 2 个诱饵文件" not in t or "都还没有被任何工具读过" not in t:
        return "态③（放了没被读）数量或措辞不对：%r" % t[-120:]
    # 态④被读过：必须带「被读不等于出事」的澄清
    p, why = render(_C_READ)
    if why:
        return why
    t = PC.body(p)
    if "被读过 3 次" not in t:
        return "态④（被读过）没报次数"
    if "被读不等于出事" not in t:
        return "态④没澄清「被读不等于出事」——会把观察证据说成事故"
    # 态⑤带出去过（唯一强证据）：标记出现在输出里
    p, why = render(_C_LEAKED)
    if why:
        return why
    t = PC.body(p)
    if "有 2 次诱饵标记出现在工具输出里" not in t:
        return "态⑤（强证据）没报次数"
    if "确有内容被带出去过的证据" not in t:
        return "态⑤没点明「这是确有内容被带出去过的证据」"
    # 术语：页面零「金丝雀」（与 0360 H6 同一条禁令，这里守新块自身）
    for name, c in (("①", _C_NO_PROJ), ("②", _C_NONE_PLANTED),
                    ("③", _C_UNREAD), ("④", _C_READ), ("⑤", _C_LEAKED)):
        p, why = render(c)
        if why:
            return why
        # ★ 0.53.0（S48 存量红，本批顺手清）：这里原先直接扫裸渲染变量 ——
        #   裸串里含 <style> 与术语浮层（「金丝雀」正是术语浮层的词），
        #   于是"页面上没有金丝雀"既可能被 CSS 注释误判、也可能被浮层掩盖。
        if "金丝雀" in PC.body(p):
            return "态%s渲染里有「金丝雀」—— 页面词必须是「诱饵文件」" % name
    # 数据缺失（老 payload/夹具）⇒ 不渲染、不谎报
    p, why = render(None)
    if why:
        return why
    if "诱饵文件" in PC.body(p):
        return "没带诱饵数据却渲染了诱饵块——空数据不许产出文案"
    # 明确取失败 ⇒ 说「没查到」，不许说成「没有问题」
    p, why = render({"failed": True})
    if why:
        return why
    t = PC.body(p)
    if "没查到" not in t or "不要当成「没有问题」" not in t:
        return "取失败态没说清「没查到≠没有问题」：%r" % t[-120:]
    return True


@check("H12 ★ 诱饵文件五态不混：没登记/没放过/没被读/被读过/带出去过 各有其词")
def h12():
    """T1.1 的判据落点（渲染→0490）。与 0360 H6 的分工：H6 守**整页**禁词，
    本判据守**五态措辞不互相塌陷**（「没查」不许说成「没有」这类）。"""
    return _h12_core(lambda c: _canary_render(c))


@check("N-H12 ★ 负控：把「没登记」说成「没有」／删掉强证据句 ⇒ H12 必须红")
def n_h12():
    """两变异各验一边（都走两步法：先证注入生效，再证尺子红）：

    ① 态①文案塌陷成「一个诱饵文件都没有」—— 把「没查」说成「没有」；
    ② 态⑤删掉「确有内容被带出去过的证据」—— 强证据降级成普通观察。
    """
    src = _src(_HEALTH_REL)
    a1 = "还没有登记过项目，无从查起——这不是「没有诱饵」，是「没查」。"
    if a1 not in src:
        return ("变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，"
                "不算通过：%r" % a1)
    mut1 = src.replace(a1, "一个诱饵文件都没有。")
    r1 = _h12_core(lambda c: _canary_render(c, src=mut1, tag="is0490_nh12a"))
    if r1 is True:
        return "负控①失效：态①塌陷成「没有」后 H12 没红"
    if "态①" not in str(r1):
        return "负控①方向不对：红的原因不是态①（%s）—— 量具打偏" % r1
    a2 = "——这是确有内容被带出去过的证据。"
    if a2 not in src:
        return ("变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，"
                "不算通过：%r" % a2)
    mut2 = src.replace(a2, "。")
    r2 = _h12_core(lambda c: _canary_render(c, src=mut2, tag="is0490_nh12b"))
    if r2 is True:
        return "负控②失效：删掉强证据句后 H12 没红"
    if "态⑤" not in str(r2):
        return "负控②方向不对：红的原因不是态⑤（%s）—— 量具打偏" % r2
    if _h12_core(lambda c: _canary_render(c)) is not True:
        return "夹具不成立：真实现本身就被 H12 判红 ⇒ 负控无分辨力"
    return True


# ══════════════════ U20 · 0.53.0 T3.2（撤顶部 24h 计数排；设计 §14.3 判据）══════════════════════
#: ★ 由来（设计 §14.3 第 1 条）：顶部条曾挂一排「最近 24 小时：失守 N
#:   （已归并为 M 件事）· 拦截 N · 注意 N」**按级**计数 —— 与**日报四指标**
#:   （R0/L2/L1 按级 ＋ 要处理按桶，同一 24h 窗口）同口径 ⇒ 同一个数两个
#:   落点（「重复即红」）。T3.2 撤这一排；24h 按级计数的**唯一家**是
#:   日报四指标（其钻取链接由 0353 `c_report_drill_links` 守、数字与链
#:   现算一致由 0353 P14 守）。
#: ★ 为什么**四视图都查**：顶部条是共享 chrome（`_bar` 四个视图都渲染
#:   一遍）—— 只查收件箱页的话，报表页留着照样是"同页两份"。
def _u20_offenders(page):
    """U20 的唯一尺子（正负判据共用，不许二次实现）：
    返回页面上「第二份 24h 按级计数」的形态标记列表（空 ＝ 干净）。"""
    out = []
    # ① 排头字面：「最近 24 小时：」＋**冒号**是药丸排的专用形状。
    #    报表页自己的「最近 24 小时被拉起过」行、顶部后缀的
    #    「（最近 24 小时）」、口径说明的「四个数都只数最近 24 小时。」
    #    都不带这个冒号形状 —— 不误伤（尺子窄而准，不做全站正则）。
    if "最近 %d 小时：" % M.WINDOW_HOURS in page:
        out.append("顶部 24h 计数排头（「最近 %d 小时：」）" % M.WINDOW_HOURS)
    # ② 药丸的链接形状：`f=win:24:lv:R0">失守 <b>`（日报四指标的链接
    #    后面跟的是裸数字，不是「失守 <b>」—— 两种形状分得开）。
    for m in re.finditer(
            r'f=win:%d:lv:(R0|L2|L1)">(?:失守|拦截|注意) <b>' % M.WINDOW_HOURS,
            page):
        out.append("药丸计数链接（%s）" % m.group(1))
    return out


@check("U20 ★ T3.2：四视图顶部条无第二份 24h 按级计数（唯一家在日报四指标）")
def u20():
    for view in _VIEWS:
        bad = _u20_offenders(_page(view))
        if bad:
            return "%s 视图还有第二份 24h 计数：%s" % (view, "；".join(bad[:3]))
    # 家的存在性：撤的是**第二份**，不是把数杀干净 —— 日报四指标的钻取
    # 链接必须在（否则"唯一家"名存实亡）。
    rep = _page("report")
    for lvl in ("R0", "L2", "L1"):
        if ('f=win:%d:lv:%s' % (M.WINDOW_HOURS, lvl)) not in rep:
            return "日报页缺 %s 指标的 24h 钻取链接 —— 唯一家没了" % lvl
    return True


@check("N-U20 负控：把药丸计数排加回顶部条 ⇒ U20 必须红")
def n_u20():
    """反向对照（C1 两步法）：往 `_bar` 的返回里注回一排药丸形态的计数。

    ★ 变异锚点选 `collst` 那一行：它在 `_bar` 返回串的拼接里，前插一串
      字面量即成新的一"排"—— 与真药丸同形（排头冒号 ＋ 级链接 ＋ <b> 数）。
    """
    src = _src(_SERVER_REL)
    anchor = '        "<span class=\\"collst\\" id=\\"collst\\"></span>"'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    pills = ('        "<span class=\\"pill\\">最近 %d 小时：'
             '<a href=\\"/?v=inbox&f=win:%d:lv:R0\\">失守 <b>9</b>'
             '（已归并为 1 件事）</a> · '
             '<a href=\\"/?v=inbox&f=win:%d:lv:L2\\">拦截 <b>9</b></a> · '
             '<a href=\\"/?v=inbox&f=win:%d:lv:L1\\">注意 <b>9</b></a></span>"\n'
             % (M.WINDOW_HOURS, M.WINDOW_HOURS, M.WINDOW_HOURS, M.WINDOW_HOURS))
    page, why = _mut_render(src.replace(anchor, pills + anchor),
                            "is0490_nu20", _SERVER_REL,
                            view="inbox", filt=M.BUCKET_ACTION,
                            root=tempfile.mkdtemp(prefix="g0490_nu20_"),
                            token="T", items=_items(), posture=_POSTURE)
    if why:
        return why
    bad = _u20_offenders(page)
    if not bad:
        return "负控失效：加回药丸排后 U20 仍判绿（这条判据是装饰）"
    if _u20_offenders(_page("inbox")):
        return "夹具不成立：真实现本身还带药丸排 ⇒ 负控无分辨力"
    return True


def _u21_fixture(hosts, same_topic=True):
    """T3.3 夹具：每条带显式 `host`（空串＝0.33.1 前的旧记录）。

    ★ `same_topic=True` ⇒ 全部落进**一个归并行**（考"归并行尾部的分布"）；
      `False` ⇒ 每条各成一组，退回**明细行**（考"行内徽标"）。
    ★ 时间用 `_ago()` 相对现在 —— 不写死日期（0.48.4 时间炸弹教训）。
    """
    out = []
    for i, h in enumerate(hosts):
        a = M.Alert(id="u0490_u21_%d" % i, ts=_ago(1.0 + i * 0.1),
                    level="R0", kind="host_shield_breach", title="t",
                    detail="d%d" % i,
                    topic="same" if same_topic else "t%d" % i,
                    host=h, host_confidence=("high" if h else ""))
        out.append(M.Item(alert=a, state="unread"))
    return out


def _u21_core(render):
    """U21/T3.3 的唯一尺子（`render` 可注入 ⇒ 负控喂变异模块，P18/P19 同型）。

    四条腿，各守一个"显示位 → 事实"的对应：
      ① 双工具 ＋ 归并成一行 ⇒ 归并行尾部有「工具：」且**每个工具都在、都带条数**；
      ② 单工具 ⇒ **零徽标零分布**（单工具机器上每行重复同一句＝v0 的噪声错法）；
      ③ 双工具 ＋ 不归并 ⇒ **每条明细行**都有徽标，且名字与记录对得上；
      ④ 旧记录（无 host）⇒ **不显示成任何工具**（不写「未知 N 条」，P18 同纪律）。
    """
    def _r(items, filt):
        return render(view="inbox", filt=filt,
                      root=tempfile.mkdtemp(prefix="g0490_u21_"),
                      token="T", items=items, rep=_REP, posture=_POSTURE)

    # ① 双工具归并行（workbuddy 2 条 ＋ qoder 1 条：条数必须算对，不只列名字）
    # ★ 0.53.0（T6.1）：宿主有了人话名（`WorkBuddy` / `Qoder`）⇒ 名字比对**不区大小写**。
    #   这里守的是"哪个工具、几条"，不是"品牌名怎么写"（后者由 0515 的
    #   宿主表判据守，见 `c_host_names_cover_detector_labels`）。
    page = _r(_u21_fixture(["workbuddy", "workbuddy", "qoder"]), M.BUCKET_ACTION)
    m = re.search(r'工具：[^<]*', page)
    if not m:
        return "双工具机器上，归并行尾部没有工具分布 —— 归因在页面上不存在"
    dist = m.group(0)
    low = dist.lower()
    for nm in ("workbuddy", "qoder"):
        if nm not in low:
            return "工具分布漏了 %s（实际 %r）" % (nm, dist[:50])
    if "workbuddy 2 条" not in low or "qoder 1 条" not in low:
        return "工具分布的条数算错了（实际 %r；应为 workbuddy 2 条 · qoder 1 条）" % dist[:50]
    # ② 单工具 ⇒ 两处都不许出现
    one = _r(_u21_fixture(["workbuddy", "workbuddy"]), M.BUCKET_ACTION)
    if 'class="hbadge"' in one:
        return "单工具机器上仍渲染了工具徽标 —— 每行重复同一个工具名（v0 错法）"
    if "工具：" in one:
        return "单工具机器上仍渲染了工具分布 —— 同上，纯噪声"
    # ③ 明细行徽标（不归并 ⇒ 每条一行）
    rows = _r(_u21_fixture(["workbuddy", "qoder"], same_topic=False), "all")
    names = re.findall(r'<span class="hbadge">([^<]*)</span>', rows)
    if len(names) != 2:
        return ("双工具明细行的工具徽标数 %d ≠ 2（实到 %r）—— 行内归因没接上"
                % (len(names), names))
    if sorted(n.strip().lower() for n in names) != ["qoder", "workbuddy"]:
        return "行内徽标的工具名对不上记录（实到 %r）" % (names,)
    # ④ 旧记录（无 host）：不冒充
    legacy = _r(_u21_fixture(["", ""], same_topic=False), "all")
    if 'class="hbadge"' in legacy or "工具：" in legacy:
        return "旧记录（无归因）被显示成了某个工具 —— 不知道被说成了知道"
    if "generic" in legacy:
        return "页面出现了 generic 兜底标签 —— 那是检测失败的内部标记"
    return True


@check("U21 ★ T3.3：工具徽标只在 ≥2 工具时出现＋归并行尾部有工具分布")
def u21():
    """设计 §14.3 第 3／6 条。

    ★ 为什么必须靠**夹具**自证：本机近 8 天 100% workbuddy ⇒ 真实数据里
      这个功能**永远不会出现**，只靠现网样本＝与死判据同型（永远没人执行）。
    """
    return _u21_core(SV.render_page)


@check("N-U21 负控：把「≥2 工具」的开关打掉（恒真）⇒ U21 必须红")
def n_u21():
    """反向对照：`_show_host` 恒为 True ⇒ 单工具机器上也会渲染徽标/分布。"""
    src = _src(_SERVER_REL)
    anchor = "    _show_host = M.host_count(items) >= 2"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    try:
        mut = _load(src.replace(anchor, "    _show_host = True"),
                    "is0490_nu21", _SERVER_REL)
    except Exception as e:                                      # noqa: BLE001
        return ("负控自身失效：变异模块加载就抛 %s: %s —— 量具故障，不算通过"
                % (type(e).__name__, e))
    why = _u21_core(mut.render_page)
    if why is True:
        return "负控失效：开关恒真后 U21 仍判绿（单工具腿是摆设）"
    if "单工具" not in str(why):
        return "方向不对：红因不是「单工具也渲染」（%s）—— 量具打偏" % str(why)[:60]
    return True


# ---------------------------------------------------------------- T5.2（0.53.0）----
#: 「工具识别」那一行的值（只取这一格，避免把 CSS/术语浮层里的英文算进去）
_U22_ROW = re.compile(r'<span class="k">工具识别</span><span class="([a-z]+)">([^<]*)</span>')


def _u22_items(rows):
    """T5.2 夹具：`(host, host_confidence, 几小时前)` —— 时间全部相对现在。

    ★ 不写死日期（0.48.4 时间炸弹教训）：收件箱/日报按窗口筛，夹具一旦过期
      就"不在页面里"，正判据对空页面打分＝假绿，负控还会报"夹具失效"。
    """
    out = []
    for i, (h, c, hrs) in enumerate(rows):
        a = M.Alert(id="u0490_u22_%d" % i, ts=_ago(hrs), level="L1",
                    kind="pre_tool_use", host=h, host_confidence=c)
        out.append(M.Item(alert=a, state="unread"))
    return out


def _u22_row(render, rows):
    """渲染运行状态页，返回 `(css 类, 值文本)`；这一行不存在 ⇒ `(None, None)`。"""
    page = render(view="health", root=tempfile.mkdtemp(prefix="g0490_u22_"),
                  token="T", items=_u22_items(rows), rep=_REP, posture=_POSTURE)
    m = _U22_ROW.search(page)
    return (m.group(1), m.group(2)) if m else (None, None)


def _u22_core(render):
    """U22/T5.2 的唯一尺子（`render` 可注入 ⇒ 负控喂变异模块，U21 同型）。

    五条腿，对应设计 §4.4-1／§14.6-2 的三样要求（判定方式／成功数／说不清提醒）：
      ① 双工具 ＋ 一条旧记录 ⇒ 分母＝窗口内总条数、成功数、说不清数与占比**逐字对**；
      ② 全说不清 ⇒ 出「说不清偏多」提醒（这是这个块存在的理由）；
      ③ 全认得出 ⇒ **不出**提醒（否则提醒常亮＝噪声，和"永远红"的报警器一样没用）；
      ④ 空记录 ⇒ 给真话、**不许渲染 0%**（"没查"不是"查过没事"）；
      ⑤ 8 天前的记录不计入 7 天分母（窗口真的按 7 天算，不是"全部记录"）。
    """
    # ① 双工具：workbuddy 2 条（直接证据）＋ qoder 1 条（间接线索）＋ 旧记录 1 条
    css, val = _u22_row(render, [("workbuddy", "high", 2), ("workbuddy", "high", 3),
                                 ("qoder", "medium", 4), ("", "none", 5)])
    if val is None:
        return "运行状态页没有「工具识别」这一格 —— 这块在页面上不存在"
    if "近 7 天 4 条记录里" not in val:
        return "分母不对：应为窗口内全部 4 条记录（实际 %r）" % val[:60]
    if "3 条认得出是哪个工具" not in val:
        return "成功数不对：应为 3 条认得出（实际 %r）" % val[:60]
    if "有直接证据 2 条" not in val or "间接线索 1 条" not in val:
        return "置信度分布不对或没上屏（实际 %r）" % val[:80]
    # ①b（0.53.0，创始人 2026-10-18 当场质问）：**必须点名是哪个工具**。
    #   设计 §6 要的是「工具名（env 铁证）」；只说"认得出是哪个工具"却不给名字，
    #   等于承诺了答案又不给 —— 0.53.0 的现网句子正是这样，而当时五条腿全绿。
    #   ★ 期望名走 `SV._host_label` **派生**，不在判据里硬编码品牌：
    #     宿主改名/换品牌时判据不必跟着改，也就不会因"判据没改"而误红或假绿。
    _lb = SV._host_label
    for _h in ("workbuddy", "qoder"):
        if _lb(_h) not in val:
            return ("句子没点名是哪个工具（缺 %r，实际 %r）—— 只说「认得出」"
                    "不给名字，读者永远看不到答案" % (_lb(_h), val[:90]))
    if "1 条说不清（25%）" not in val:
        return "说不清条数/占比不对：应为 1 条（25%）（实际 %r）" % val[:80]
    if "线索取工具自己报的环境信息" not in val:
        return "缺「判定方式」—— 读者不知道这个数是怎么来的（实际 %r）" % val[:80]
    for en in ("high", "medium", "low", "none"):
        if en in val:
            return "页面出现了英文置信度 %r —— 那是内部值" % en
    if css != "warn":
        return "25%% 说不清应标 warn（实际 %r）" % css

    # ② 全说不清（旧记录机器）⇒ 必须提醒
    css2, val2 = _u22_row(render, [("", "none", 2), ("", "none", 3)])
    if "说不清偏多" not in (val2 or ""):
        return "占比 100%% 时没有「说不清偏多」提醒 —— 这个块等于没做（实际 %r）" % (val2 or "")[:60]
    if css2 != "warn":
        return "占比 100%% 时未标 warn（实际 %r）" % css2

    # ③ 全认得出 ⇒ 不许提醒（防"常亮报警器"）
    css3, val3 = _u22_row(render, [("workbuddy", "high", 1)] * 5)
    if "说不清偏多" in (val3 or ""):
        return "0%% 说不清时仍出提醒 —— 提醒会常亮，等于噪声（实际 %r）" % (val3 or "")[:60]
    if "5 条记录里，5 条认得出" not in (val3 or ""):
        return "5/5 口径不对（实际 %r）" % (val3 or "")[:60]
    if SV._host_label("workbuddy") not in (val3 or ""):
        return "单工具时没点名是哪一个（实际 %r）" % (val3 or "")[:60]

    # ④ 空记录 ⇒ 真话，且不出现 0%
    css4, val4 = _u22_row(render, [])
    if val4 is None:
        return "空机器上连这一格都没有 —— 空态不许整块消失"
    if "近 7 天没有记录" not in val4:
        return "空机器上没有说真话（实际 %r）" % val4[:60]
    if "%" in val4:
        return "空机器上渲染了百分比 —— 「没查」被说成了「查过没事」（实际 %r）" % val4[:60]

    # ⑤ 8 天前那条不计入 7 天
    css5, val5 = _u22_row(render, [("workbuddy", "high", 2), ("workbuddy", "high", 3),
                                   ("qoder", "medium", 4), ("", "none", 5),
                                   ("workbuddy", "high", 8 * 24)])
    if "近 7 天 4 条记录里" not in (val5 or ""):
        return ("8 天前的记录被算进了 7 天分母（实际 %r）—— 窗口不是 7 天"
                % (val5 or "")[:60])
    return True


@check("U22 ★ T5.2：运行状态「工具识别」行（分母／成功数／说不清占比／判定方式）")
def u22():
    """设计 §4.4-1、§14.6-2（最小版）。

    ★ 为什么必须夹具自证：本机近 8 天 100% workbuddy、且旧记录占比可能为 0——
      现网样本既碰不到"双工具"也碰不到"说不清偏多"，只靠真数据＝与死判据同型。
    """
    return _u22_core(SV.render_page)


@check("N-U22 负控：「说不清偏多」提醒关掉 ⇒ U22 必须红（且红在提醒那条腿）")
def n_u22():
    src = _src(_SERVER_REL)
    anchor = ('        if _hs["unclear_ratio"] ' + ">" + ' 0.05:')
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    try:
        mut = _load(src.replace(anchor, "        if False:"), "is0490_nu22", _SERVER_REL)
    except Exception as e:                                      # noqa: BLE001
        return ("负控自身失效：变异模块加载就抛 %s: %s —— 量具故障，不算通过"
                % (type(e).__name__, e))
    why = _u22_core(mut.render_page)
    if why is True:
        return "负控失效：提醒关掉后 U22 仍判绿（提醒那条腿是摆设）"
    # ★ 方向判断放宽到"提醒 或 warn 那两条腿"：`if` 被关掉时**同一分支**同时失去
    #   提醒句与 warn 颜色 —— ① 腿先撞到颜色，② 腿才撞到句子。要求"必须红在句子"
    #   等于要求变异只改一半，那是把量具写死（本轮实测撞到，故记在这里）。
    if "提醒" not in str(why) and "warn" not in str(why):
        return "方向不对：红因不是「提醒缺失/warn 消失」（%s）—— 量具打偏" % str(why)[:60]
    return True


@check("N-U22c 负控：把工具名从句子摘掉 ⇒ U22 必须红（点名那条腿）")
def n_u22_c():
    """变异＝`_dist = []`（句子退回"只说认得出、不给名字"）。

    ★ 为什么必须有这条：0.53.0 的 U22 五条腿**全部放过**这种句子 —— 本机现网
      就长这样（"104 条认得出是哪个工具（有直接证据 104 条）"），读起来像漏了
      名字，而判据全绿。创始人 2026-10-18 一句"要求指明哪个 AI 编程工具，但是
      我没看到"把它抓了出来 ⇒ 尺子缺一条腿。
    """
    src = _src(_SERVER_REL)
    anchor = "_dist = M.host_distribution(_win7, label_of=_host_label)"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    try:
        mut = _load(src.replace(anchor, "_dist = []"), "is0490_nu22c", _SERVER_REL)
    except Exception as e:                                      # noqa: BLE001
        return ("负控自身失效：变异模块加载就抛 %s: %s —— 量具故障，不算通过"
                % (type(e).__name__, e))
    why = _u22_core(mut.render_page)
    if why is True:
        return "负控失效：工具名摘掉后 U22 仍判绿（点名那条腿是摆设）"
    if "点名" not in str(why):
        return "方向不对：红因不是「没点名工具」（%s）—— 量具打偏" % str(why)[:60]
    return True


@check("N-U22b 负控：7 天窗口改成 30 天 ⇒ U22 必须红（分母那条腿）")
def n_u22_b():
    src = _src(_SERVER_REL)
    anchor = "M.host_attribution_stats(items or [], days=7)"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    try:
        mut = _load(src.replace(anchor, "M.host_attribution_stats(items or [], days=30)"),
                    "is0490_nu22b", _SERVER_REL)
    except Exception as e:                                      # noqa: BLE001
        return ("负控自身失效：变异模块加载就抛 %s: %s —— 量具故障，不算通过"
                % (type(e).__name__, e))
    why = _u22_core(mut.render_page)
    if why is True:
        return "负控失效：窗口改成 30 天后 U22 仍判绿（窗口那条腿是摆设）"
    if "分母" not in str(why) and "7 天" not in str(why):
        return "方向不对：红因不是「分母/窗口」（%s）—— 量具打偏" % str(why)[:60]
    return True


#: 施工单 T5.2 给的逐字告警句（0 文件那种输入下的形态）
_U23_ALARM = "这次没核验成：0 个文件被检查——结果不算数"


def _u23_rep(status, files, records=0):
    rep = dict(_REP)
    rep["chain"] = {"status": status, "files": files, "records": records,
                    "broken": 0, "bad_lines": 0, "unchained": 0,
                    "first_bad": "", "reason": ""}
    return rep


def _u23_page(view, status, files, records=0):
    return SV.render_page(view=view, root=tempfile.mkdtemp(prefix="g0490_u23_"),
                          token="T", items=_items(),
                          rep=_u23_rep(status, files, records), posture=_POSTURE)


@check("U23 ★ T5.2：链检「没查成」说告警句，不许再显示中性词「未能核验」")
def u23():
    """设计 §4.4-3、§14.6-4（废弃口径 §9-6）。

    ★ 为什么这不是文字洁癖：中性状态词会被读成"暂时没数据"，而真相是
      **这次检查一条结论都没产出** —— 同页别处的"没问题"因此不能算数。
    """
    # ① 没查成（0 文件）⇒ 逐字告警句，且中性词消失
    # ★ 0.53.0：断言一律打在 `PC.body()` 上（S48 纪律：判据扫渲染产物必须显式选层，
    #   裸变量里有 <style>/术语浮层，会让"页面上没有某词"这种断言变成假绿）。
    h = PC.body(_u23_page("health", "unknown", 0))
    if _U23_ALARM not in h:
        return "运行状态页没有逐字告警句：%r" % _U23_ALARM
    if "未能核验" in h:
        return "运行状态页仍出现中性词「未能核验」—— 没查成被说成了状态"
    # ② 查成了 ⇒ 原句不许被顺手改掉（上版两处单位修正都在那半句里）
    ok_page = PC.body(_u23_page("health", "ok", 1, 2))
    if "完整（检查了 1 个文件、2 条记录，被改 0）" not in ok_page:
        return "查成了的原句被改动了（应逐字保留「完整（检查了 …）」）"
    # ③ 日报页链卡同一句（两处落点同源）
    r = PC.body(_u23_page("report", "unknown", 0))
    if _U23_ALARM not in r:
        return "日报页链卡仍显示中性词 —— 两个落点不同源"
    # ④ 有文件但一条可校验记录都没有 ⇒ 另说一句，不许谎报「0 个文件」
    alt = SV.R.chain_unverified(3)
    if "0 个文件" in alt:
        return "3 个文件却报了「0 个文件」—— 数字没从 files 派生（F40 同型）"
    if "3 个文件里没有一条可校验的记录" not in alt:
        return "另一种没查成的形态没有自己的说法（实际 %r）" % alt
    return True


@check("N-U23 负控：把告警句改回「未能核验」⇒ U23 必须红")
def n_u23():
    src = _src(_SERVER_REL)
    anchor = '    return R.chain_unverified((ch or {}).get("files", 0))'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    # ★ 走 `_mut_render` 两步法（C-01 守的就是这条）：变异模块能 import ＋ 渲染不抛
    #   才算"量具没问题"；否则量具故障会被读成产品问题。
    h, why = _mut_render(src.replace(anchor, '    return "未能核验"'),
                         "is0490_nu23", _SERVER_REL,
                         view="health", root=tempfile.mkdtemp(prefix="g0490_nu23_"),
                         token="T", items=_items(),
                         rep=_u23_rep("unknown", 0), posture=_POSTURE)
    if why:
        return why
    hv = PC.body(h)                       # S48：断言必须打在显式选层上
    if _U23_ALARM in hv:
        return "负控失效：改回「未能核验」后页面仍有告警句（那条腿是摆设）"
    if "未能核验" not in hv:
        return "负控自身失效：变异没有生效（页面既无告警句也无中性词）"
    return True


# ======================================================================
# 批 25 · L-01/L-02 族（0.53.2，创始人 2026-10-20「账本有记录永远是 8 天，
#   从来不会增长」）
# ----------------------------------------------------------------------
# ★ 根因不是"数算错了"，是**取数窗口把口径封了顶**：
#   `discover_chain_files(days=7)` ⇒ cutoff＝今天−7 ⇒ 最早能读到今天−7
#   ⇒ 「有记录多少天」**恒等于窗口长度**（含今天恰好 8 天）。读者看到的是
#   **取数参数**，不是数据。实测本机：窗口 7 天 ⇒ 8 天；全量 ⇒ 39 天
#   （2026-09-10 → 2026-10-20，1929 条 vs 463 条）。
# ★ 三条腿，缺一条就会以别的形状复发：
#   ① 窗口**能**放开（真值：远古文件能被发现）；
#   ② `load_items_all` **真的**用无窗口取数（行为，不是看源码里写了什么）；
#   ③ 账本页**接的是**全量入口（AST 结构 ＋ 负控变异）。
#   ★ 只改一处而另两处不动 ⇒ 另两处天然全绿（§42 同型病）。
# ★ L-02 是性能腿：缓存上限小于一次全量扫描的文件数 ⇒ 缓存 100% 未命中
#   （实测 64 vs 107 个文件：连续两次全量各 6.6s / 5.5s）。窗口在参数上放开了、
#   实际每次仍重投影 21 万行 ⇒ 账本仍然没人敢点 —— 那是"修了一半"。
# ======================================================================

#: 故意写死一个**远古**日期：语义就是"比任何合理窗口都早"。
#: ★ 为什么可以写死：0470 时间炸弹教训针对的是"把今天算进去"的夹具；
#:   这里的断言恰好相反 —— 要的就是"它足够早，绝不该被任何窗口留下"。
_L01_ANCIENT_DAY = "2020-01-01"


def _l01_root():
    """临时 hub：rollup 里放一个远古链文件 ＋ 一个今天的。不写任何产品文件。"""
    root = tempfile.mkdtemp(prefix="g0490_l01_")
    roll = os.path.join(root, "rollup")
    os.makedirs(roll, exist_ok=True)
    today = datetime.now().astimezone().date().isoformat()
    for name in (_L01_ANCIENT_DAY, today):
        with io.open(os.path.join(roll, name + ".jsonl"), "w",
                     encoding="utf-8") as f:
            f.write("{}\n")          # 内容无关：发现只按**文件名日期**过滤
    return root


@check("L-01a 取数窗口能放开：`days=WINDOW_ALL` 收全部链文件（远古文件不许被窗口吃掉）")
def c_l01_window_can_open():
    S = SV.S
    root = _l01_root()
    recent = S.discover_chain_files(days=S.WINDOW_RECENT_DAYS, root=root)
    every = S.discover_chain_files(days=S.WINDOW_ALL, root=root)
    ancient = os.path.normpath(
        os.path.join(root, "rollup", _L01_ANCIENT_DAY + ".jsonl"))
    if ancient not in every:
        return ("`days=WINDOW_ALL` 没收到 %s —— 窗口根本没放开，账本的天数"
                "会被窗口封顶（这就是「永远是 8 天」的形状）" % _L01_ANCIENT_DAY)
    # 判别力自检：同一个夹具在默认窗口下**必须**看不到它，否则这条判据是装饰
    if ancient in recent:
        return ("判别力失效：默认窗口也能看到 %s ⇒ 夹具没造出差异，"
                "这条判据永远绿" % _L01_ANCIENT_DAY)
    if not set(recent) <= set(every):
        return "全量集合竟然不含窗口集合 —— 放开窗口反而丢了文件（越放越窄）"
    return True


@check("N-L01a 负控：把 WINDOW_ALL 换回 7 天窗口 ⇒ 远古文件必须消失（判据不是装饰）")
def n_l01_window_can_open():
    S = SV.S
    root = _l01_root()
    ancient = os.path.normpath(
        os.path.join(root, "rollup", _L01_ANCIENT_DAY + ".jsonl"))
    # 面①：显式传 7 天 —— 远古文件必须看不到
    if ancient in S.discover_chain_files(days=7, root=root):
        return "负控失效：7 天窗口下远古文件仍被收进来（窗口根本没在过滤）"
    # 面②：把常量本身换成 7 —— 走全量的那个入口必须跟着一起变窄
    saved = S.WINDOW_ALL
    try:
        S.WINDOW_ALL = 7
        if os.path.basename(ancient) in [
                os.path.basename(p) for p in
                S.discover_chain_files(days=S.WINDOW_ALL, root=root)]:
            return "负控失效：WINDOW_ALL 改成 7 之后仍能收到远古文件"
    finally:
        S.WINDOW_ALL = saved
    return True


@check("L-01b `load_items_all` 真走无窗口取数（行为断言：抓它实际传给发现的 days）")
def c_l01_all_entry_uses_no_window():
    S = SV.S
    seen = {}
    orig = S.discover_chain_files

    def spy(days=S.WINDOW_RECENT_DAYS, root=None, include_projects=True):
        seen["days"] = days
        seen["root"] = root
        return orig(days=days, root=root, include_projects=include_projects)

    S.discover_chain_files = spy
    try:
        S.load_items_all(root=tempfile.mkdtemp(prefix="g0490_l01b_"))
    finally:
        S.discover_chain_files = orig
    if "days" not in seen:
        return "`load_items_all` 根本没调 `discover_chain_files` —— 判据锚点失效"
    if seen["days"] is not S.WINDOW_ALL:
        return ("`load_items_all` 传给发现层的 days=%r（应为 WINDOW_ALL=%r）"
                " —— 名字叫 all 却仍带窗口，账本天数会被重新封顶"
                % (seen["days"], S.WINDOW_ALL))
    return True


@check("N-L01b 负控：`load_items_all` 退回带窗口取数 ⇒ L-01b 必须红")
def n_l01_all_entry_uses_no_window():
    S = SV.S
    seen = {}
    orig = S.discover_chain_files
    # ★★ 两个都要存，**各还原各的**。曾经写错成 `saved = S.load_items`
    #   并在 finally 里 `S.load_items_all = saved` ⇒ 负控跑完之后
    #   `load_items_all` 被永久指向带窗口的 `load_items`，后面的判据（L-02）
    #   因此拿到 7 天窗口的结果而红 —— 红的是负控的残留，不是产品。
    saved_all = S.load_items_all
    saved_find = S.discover_chain_files

    def spy(days=S.WINDOW_RECENT_DAYS, root=None, include_projects=True):
        seen["days"] = days
        return orig(days=days, root=root, include_projects=include_projects)

    try:
        # 变异：把 load_items_all 换成"带默认窗口"的旧形状（内存，不落盘）
        S.discover_chain_files = spy
        S.load_items_all = (lambda root=None, kinds=None:
                            S.load_items(root=root, kinds=kinds))
        S.load_items_all(root=tempfile.mkdtemp(prefix="g0490_nl01b_"))
    finally:
        S.discover_chain_files = saved_find
        S.load_items_all = saved_all
    if seen.get("days") == S.WINDOW_ALL:
        return "负控失效：退回带窗口取数后，days 仍等于 WINDOW_ALL（变异没生效）"
    if seen.get("days") is None:
        return "负控失效：变异后根本没走到发现层，负控无分辨力"
    return True


def _l01c_problem(src):
    """账本页在 `items is None` 时**必须**走 `load_items_all`（AST，不看注释）。

    ★ 为什么用 AST 而不是文本 `in`：`if "load_items_all" in src` 会被
      注释里的同一串字骗过（本仓已栽过：注释与实现相反、判据却绿）。
    """
    import ast
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return "inbox_server.py 解析失败（判据锚点失效）：%s" % e
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "render_page"), None)
    if fn is None:
        return "找不到 render_page —— 判据锚点失效（改名了？）"
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        # `items is None` 这一支
        if not (isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "items"):
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                if sub.func.attr == "load_items_all":
                    return None
    return ("render_page 的 `items is None` 分支里没有调 `load_items_all`"
            " —— 账本又回到 7 天窗口，「有记录多少天」会重新被封顶在 8 天")


@check("L-01c 账本页接的是全量入口（AST：`render_page` 的 items 空分支调 load_items_all）")
def c_l01c():
    with io.open(os.path.join(ROOT, "inbox_server.py"), encoding="utf-8") as f:
        return _l01c_problem(f.read())


@check("N-L01c 负控：把账本分支改回 `S.load_items` ⇒ L-01c 必须红")
def n_l01c():
    with io.open(os.path.join(ROOT, "inbox_server.py"), encoding="utf-8") as f:
        src = f.read()
    if _l01c_problem(src) is not None:
        return "负控前置失败：当前生产实现没通过 L-01c"
    mut = src.replace("S.load_items_all(root=root)", "S.load_items(root=root)", 1)
    if mut == src:
        return "负控夹具不成立：没找到 load_items_all 调用点"
    if _l01c_problem(mut) is None:
        return "负控失效：账本分支改回带窗口的 load_items 仍判合格"
    return True


#: 夹具文件数：**约 6~7 个月的逐日链文件**。为什么是 200 而不是"当前真实文件数"：
#:   本套件导入时就把 hub 指到临时目录（隔离，不碰真机），真实文件数在这里恒为 0
#:   —— 拿它比就是一条永远绿的假判据。用固定夹具 ⇒ 断言变成可复现的**行为**：
#:   「全量扫完 200 个文件，这 200 个的投影必须**都还在**缓存里」。
#:   ★ 淘汰是 FIFO（挤最早那个），夹具的 200 个最后插入 ⇒ 它们存活 ⟺ 上限 ≥ 200。
_L02_FIXTURE_N = 200


def _l02_root(n):
    """临时 hub：连续 n 天的链文件（内容与本判据无关，发现只按文件名日期）。"""
    root = tempfile.mkdtemp(prefix="g0490_l02_")
    roll = os.path.join(root, "rollup")
    os.makedirs(roll, exist_ok=True)
    today = datetime.now().astimezone().date()
    for k in range(n):
        d = (today - timedelta(days=k)).isoformat()
        with io.open(os.path.join(roll, d + ".jsonl"), "w", encoding="utf-8") as f:
            f.write("{}\n")
    return root


def _l02_missing(cap):
    """在**干净缓存**上做一次全量扫描，返回 `(丢了几个, 一共几个)`。

    ★★ 为什么必须先把缓存清空（实测踩到，不是防御性设计）：
      `_project_file` 的淘汰是"插入一个之前先挤掉最早一个" ⇒ 缓存**只增不减**，
      长度永远停在历史最大值。于是同一段代码在"缓存已有 200 条"和"缓存为空"
      两种前提下，**结论相反**（实测：前者 0 丢、后者 190 丢）。
      判据若吃这个前提，就会变成一条**随执行顺序变脸**的假判据 —— 比没有更坏
      （绿的时候你以为守住了）。⇒ 本函数自带干净前提，用完还原。
    ★ 清空是安全的：`_PROJ_CACHE` 是**纯记忆化**（键含 mtime_ns/size，内容一变
      就必然重算），丢掉它只会变慢，不会算错。
    """
    S = SV.S
    saved_cap, saved_cache = S._PROJ_CACHE_MAX, dict(S._PROJ_CACHE)
    try:
        S._PROJ_CACHE.clear()
        S._PROJ_CACHE_MAX = cap
        root = _l02_root(_L02_FIXTURE_N)
        S.load_items_all(root=root)
        paths = S.discover_chain_files(days=S.WINDOW_ALL, root=root)
        have = {k[0] for k in S._PROJ_CACHE}
        return (sum(1 for p in paths if os.path.normpath(p) not in have),
                len(paths))
    finally:
        S._PROJ_CACHE.clear()
        S._PROJ_CACHE.update(saved_cache)
        S._PROJ_CACHE_MAX = saved_cap


@check("L-02 全量扫描后每个文件的投影都还在缓存里（缓存不许被自己挤空）")
def c_l02():
    missing, total = _l02_missing(SV.S._PROJ_CACHE_MAX)
    if total != _L02_FIXTURE_N:
        return "判据夹具不成立：只发现 %d 个文件（应 %d）" % (total, _L02_FIXTURE_N)
    if missing:
        return ("全量扫完 %d 个文件后，缓存里丢了 %d 个（`_PROJ_CACHE_MAX`=%d）"
                " —— 每读一个新文件就挤掉一个旧的，缓存**必然**全部未命中"
                "（实测 64 vs 107：连续两次全量各 6.6s / 5.5s）⇒ 账本每次开都要"
                "重投影 21 万行，窗口放开了但没人敢点 —— 那是「修了一半」"
                % (total, missing, SV.S._PROJ_CACHE_MAX))
    return True


@check("N-L02 负控：把上限压到 10（远小于 200 个文件）⇒ 必然丢缓存，L-02 必须红")
def n_l02():
    if _l02_missing(SV.S._PROJ_CACHE_MAX)[0]:
        return "负控前置失败：当前生产实现没通过 L-02"
    missing, total = _l02_missing(10)
    if total != _L02_FIXTURE_N:
        return "负控夹具不成立：只发现 %d 个文件（应 %d）" % (total, _L02_FIXTURE_N)
    if not missing:
        return ("负控失效：上限压到 10 之后 %d 个文件一个都没丢 ⇒ L-02 永远绿，"
                "这条判据是装饰" % total)
    return True


# ═══════════ 批25 · 0.53.4 日报细节（编号前缀位／同字号／布局／同义句／本次明细问号） ═══════════
#: 链卡夹具：带**逐文件明细**（问号展开体的数据源）。数字全部派生自本夹具，
#: 判据不写死任何计数（写死＝判据与产品各说各话）。
_CH_FILES = [{"name": "2026-10-18", "records": 21011, "unchained": 48},
             {"name": "2026-10-19", "records": 21033, "unchained": 47},
             {"name": "2026-10-20", "records": 21245, "unchained": 47}]
_REP_0534 = dict(_REP, rules=_RANK_ROWS,
                 chain=dict(_REP["chain"], files=3, records=63289,
                            unchained=142, file_list=_CH_FILES))


def _css_rule(src, sel):
    """取一条 CSS 规则的声明体（`sel{...}` ⇒ `...`）。找不到 ⇒ None。"""
    m = re.search(re.escape(sel) + r"\{([^}]*)\}", src or "")
    return m.group(1) if m else None


def _css_font_px(body):
    m = re.search(r"font-size:\s*(\d+)px", body or "")
    return int(m.group(1)) if m else None


def _rid_prefix_problem(page):
    """规则号在短名**之前**（前缀位）。唯一尺子，正负控共用。"""
    for r in _RANK_ROWS:
        m = re.search(r'<a href="/\?v=inbox&f=day:[^"]*:rule:%s"[^>]*>(.*?)</a>'
                      % re.escape(r["rule_id"]), page, re.S)
        if not m:
            return "找不到规则 %s 的排行行（夹具或模板形状变了）" % r["rule_id"]
        inner = m.group(1)
        i_rid = inner.find('<span class="rid">%s</span>' % r["rule_id"])
        i_lab = inner.find(r["label"])
        if i_rid < 0:
            return "规则 %s 行内没有 .rid 编号" % r["rule_id"]
        if i_lab < 0:
            return "规则 %s 行内没有上屏短名 %r" % (r["rule_id"], r["label"])
        if i_rid > i_lab:
            return ("规则号又退到短名后面（前缀位回潮）—— 创始人 2026-10-20："
                    "「规则代号是否放在前边更好」")
    return None


@check("T-05 规则号前缀位：rid 在短名之前（与收件箱「规则 SEC-01」同序）")
def t05():
    return _rid_prefix_problem(_page("report", rep=_REP_0534))


@check("N-T05 负控：把 rid 挪回短名后面（0.51.0 旧序）⇒ T-05 必须判红")
def n_t05():
    page = _page("report", rep=_REP_0534)
    if _rid_prefix_problem(page) is not None:
        return "夹具不成立：现行渲染就判红 —— 负控无分辨力"
    dead = page.replace(
        '<span class="rid">DST-04</span>设置开机自动启动',
        '设置开机自动启动<span class="rid">DST-04</span>')
    if dead == page:
        return "夹具不成立：摘不到规则行的 rid＋短名（结构已变）"
    if _rid_prefix_problem(dead) is None:
        return "负控失效：rid 挪回后面仍判合格（这把尺子没分辨力）"
    return True


def _t06_problem(src):
    """规则号字号＝正文字号、不是脚注（字号小＋灰＋后缀间距三件事一起锁）。"""
    rid_body = _css_rule(src, ".rows .rid")
    if not rid_body:
        return "找不到 .rows .rid 规则（编号索引位没了）"
    fs_row = _css_font_px(_css_rule(src, ".row{"))
    fs_rid = _css_font_px(rid_body)
    if fs_rid is None:
        return ".rows .rid 没有写字号"
    if fs_row and fs_rid < fs_row:
        return ("规则号字号 %dpx 小于正文 %dpx —— 创始人 2026-10-20："
                "「不要那么小，字号大一些，跟旁边一样大」" % (fs_rid, fs_row))
    if "margin-left" in rid_body:
        return "规则号还在用 margin-left（后缀位的残留间距 —— 它现在在前面）"
    if "margin-right" not in rid_body:
        return "规则号前缀位没有与短名的间距（margin-right 没了）"
    if "color:var(--muted)" in rid_body:
        return "规则号又是脚注灰 —— 放前面就是主显示的一部分，不是脚注"
    return None


@check("T-06 规则号同字号：.rows .rid 字号＝正文、非脚注灰、前缀间距")
def t06():
    return _t06_problem(_src(_SERVER_REL))


@check("N-T06 负控：.rid 退回 0.51.0 旧形态（11px 灰＋margin-left）⇒ T-06 必须判红")
def n_t06():
    src = _src(_SERVER_REL)
    if _t06_problem(src) is not None:
        return "夹具不成立：现行源码就判红 —— 负控无分辨力"
    dead = src.replace(
        ".rows .rid{display:inline-block;min-width:52px;margin-right:8px;\n"
        "  font-family:var(--mono);font-size:13px;font-weight:400;color:inherit}",
        ".rows .rid{display:inline-block;min-width:52px;margin-left:6px;\n"
        "  font-family:var(--mono);font-size:11px;font-weight:400;color:var(--muted)}")
    if dead == src:
        return "夹具不成立：摘不到 .rows .rid 现行规则（源码已变，需更新负控）"
    if _t06_problem(dead) is None:
        return "负控失效：退回 11px 脚注灰仍判合格（这把尺子没分辨力）"
    return True


def _t07_problem(page, src):
    """日报两卡 label 按内容撑开（不写死 150px），值列紧随。

    ★ 锚必须落在 `</h2>` 之后：页内 CSS 注释里有一句
      「必须滚动才看得到『规则命中排行』和『有没有被改过』两张卡」——
      按片名 split 会切在注释上（首跑实测就是这么红的），按结构锚不踩。
    """
    n = page.count('</h2><div class="rows fit">')
    if n != 2:
        return ("日报两卡只有 %d 个用 rows fit（应 2：规则命中排行＋链卡）—— "
                "label 又会被 150px 挤到内部换行、值被孤零零留在行尾"
                "（0.53.4 截图病：左边挤得换行、右边大片空缺）" % n)
    k = _css_rule(src, ".rows.fit .row .k")
    if not k:
        return "没有 .rows.fit .row .k 规则（fit 是空壳 class）"
    if re.search(r"width:\s*\d+px", k):
        return "fit 的 k 又写死像素宽度：%r" % k
    if "width:auto" not in k:
        return "fit 的 k 不是 width:auto（按内容撑开）"
    v = _css_rule(src, ".rows.fit .row>span:last-child")
    if not v or "min-width:0" not in v:
        return "fit 的值列没有 min-width:0（长值会反挤 label，换行病从另一边回来）"
    return None


@check("T-07 日报两卡布局：rows fit ＋ label 不写死宽度 ＋ 值列 min-width:0")
def t07():
    page = _page("report", rep=_REP_0534)
    return _t07_problem(page, _src(_SERVER_REL))


@check("N-T07 负控：fit 的 k 加回 width:150px／卡片退回普通 rows ⇒ T-07 必须判红")
def n_t07():
    page = _page("report", rep=_REP_0534)
    src = _src(_SERVER_REL)
    if _t07_problem(page, src) is not None:
        return "夹具不成立：现行实现就判红 —— 负控无分辨力"
    # 面①：CSS 把写死宽度加回去（尺子必须咬 CSS）
    dead_css = src.replace(
        ".rows.fit .row .k{flex:0 1 auto;width:auto;min-width:0}",
        ".rows.fit .row .k{flex:0 1 auto;width:150px;min-width:0}")
    if dead_css == src:
        return "夹具不成立：摘不到 fit 的 k 规则（源码已变，需更新负控）"
    if _t07_problem(page, dead_css) is None:
        return "负控失效①：width:150px 加回去仍判合格（CSS 那条腿没分辨力）"
    # 面②：卡片退回普通 rows（尺子必须咬 HTML 接线）
    dead_html = page.replace('class="rows fit"', 'class="rows"')
    if dead_html == page:
        return "夹具不成立：摘不到 rows fit（HTML 已变，需更新负控）"
    if _t07_problem(dead_html, src) is None:
        return "负控失效②：卡片退回普通 rows 仍判合格（HTML 那条腿没分辨力）"
    return True


def _t08_problem(page):
    """unchained 行：值不许带同义括号句；圈问号必须挂在数字后侧。"""
    # 剥层口径与 0360 W06 一致：默认收起区块整块剥掉，再剥标签取可见文本
    vis = re.sub(r"<details\b.*?</details>", " ", page, flags=re.S)
    vis = re.sub(r"\x00+", " ", re.sub(r"<[^>]+>", "\x00", vis))
    if "本来就不参与比对" in vis:
        return ("值列又带同义括号句「本来就不参与比对」—— 为什么没纳入比对由"
                "行左词条问号（概念）＋值后圈问号（本次）答，一句话不说三遍（STE）")
    n = _REP_0534["chain"]["unchained"]
    if ('<span>%d<details class="qsum">' % n) not in page:
        return ("圈问号没挂在「%d」后侧 —— 创始人 2026-10-20：「在 142 后侧"
                "也挂个圈问号的方式」" % n)
    return None


@check("T-08 unchained 行无同义括号句 ＋ 圈问号挂在数字后侧")
def t08():
    return _t08_problem(_page("report", rep=_REP_0534))


@check("N-T08 负控：同义句加回值列／圈问号摘掉 ⇒ T-08 必须各自判红")
def n_t08():
    page = _page("report", rep=_REP_0534)
    if _t08_problem(page) is not None:
        return "夹具不成立：现行渲染就判红 —— 负控无分辨力"
    # 面①：把同义括号句加回值列（0.53.3 旧形态）
    n = _REP_0534["chain"]["unchained"]
    dead = page.replace('<span>%d<details class="qsum">' % n,
                        '<span>%d（本来就不参与比对）<details class="qsum">' % n)
    if dead == page:
        return "夹具不成立：摘不到 unchained 行的值（结构已变）"
    if _t08_problem(dead) is None:
        return "负控失效①：同义句加回值列仍判合格（这条腿没分辨力）"
    # 面②：圈问号摘掉（用户要的"142 后侧的问号"没了）
    dead2 = re.sub(r'<details class="qsum">.*?</details>', "", page, flags=re.S)
    if dead2 == page:
        return "夹具不成立：摘不到 qsum（结构已变）"
    if _t08_problem(dead2) is None:
        return "负控失效②：圈问号摘掉仍判合格（这条腿没分辨力）"
    return True


def _t09_problem(page):
    """圈问号展开体给**本次**明细：逐文件＋条数＋起止＋不带指纹数，全部派生。"""
    ch = _REP_0534["chain"]
    m = re.search(r'<div class="qbody">(.*?)</div></details>', page, re.S)
    if not m:
        return "找不到 qbody 展开体（问号是个空壳？）"
    body = m.group(1)
    fl = ch["file_list"]
    for d in fl:
        if d["name"] not in body:
            return "展开体缺文件 %s —— 用户问的就是「检查了哪些文件」" % d["name"]
        if ("%d 条" % d["records"]) not in body:
            return "展开体缺文件 %s 的记录条数" % d["name"]
    if ("本次核对了 %d 个文件" % len(fl)) not in body:
        return "展开体的文件数与 file_list 不同源（写死数字了？）"
    if ("从 %s 到 %s" % (fl[0]["name"], fl[-1]["name"])) not in body:
        return "展开体缺起止日期（从哪份到哪份）"
    if ("%d 条不带指纹" % ch["unchained"]) not in body:
        return "展开体的不带指纹数与 chain 不同源（写死数字了？）"
    return None


@check("T-09 圈问号展开体＝本次明细：逐文件／条数／起止全部从 chain 派生")
def t09():
    return _t09_problem(_page("report", rep=_REP_0534))


@check("N-T09 负控：文件名抹掉／文件数写死 30 ⇒ T-09 必须各自判红")
def n_t09():
    page = _page("report", rep=_REP_0534)
    if _t09_problem(page) is not None:
        return "夹具不成立：现行渲染就判红 —— 负控无分辨力"
    # 面①：抹掉中间那个文件名（"核对了哪些文件"答不全）
    dead = page.replace("2026-10-19", "20XX-XX-XX")
    if dead == page:
        return "夹具不成立：摘不到文件名（结构已变）"
    if _t09_problem(dead) is None:
        return "负控失效①：少列一个文件仍判合格（明细那条腿没分辨力）"
    # 面②：文件数写死 30（与 file_list 脱钩 —— 数据换了页面不换）
    dead2 = page.replace("本次核对了 3 个文件", "本次核对了 30 个文件")
    if dead2 == page:
        return "夹具不成立：摘不到文件数句（结构已变）"
    if _t09_problem(dead2) is None:
        return "负控失效②：文件数写死仍判合格（派生那条腿没分辨力）"
    return True


def main():
    print("=" * 78)
    print("0.48.5 Antinel 监理细节修订判据（交接件 v1.1 §5.7）—— "
          "批1 U-01/U-03/U-08 · 批2 U-10/U-11/U-05 · 批3 U-04/U-06 · "
          "批4 U-13/U-15 · 批5 W-01/W-02（认窗白名单，单独 commit）· "
          "批6 W-03（A2）· 批7 W-04（B1）· 批8 W-05（B2）· 批9 W-06（B3）· "
          "批10 C1（负控模板化：渲染型负控走 _mut_render 两步法）· "
          "批11 C2（扫渲染产物统一走 page_caliber，由元判据 S48 守）· "
          "批12 C5/U-16（问号同形）＋ C4/W-07（一次性调用方等窗就位，真进程实测）· "
          "批13 T-02/N-T02（四态词条内容派生审计：R0/L1 事件类型层、L2 规则层、"
          "类别中文名与徽标映射；U-04 同步徽标芯片）· "
          "批14 T-03/N-T03（排行行形态：短名主显示＋编号淡显＋审计全文退 hover）· "
          "批15 T-04/T-04b/T-04c（账本按天明细：最近 7 天＋按月折叠＋无记录天"
          "不渲染成 0＋closed: 按关闭日收件）· "
          "批16 T-04d（头部跨元素一致性：文案数量词＝卡片数、同页天数同源、"
          "连续与总数相等时只说一次）· "
          "批17 H3/H4b/H7/H3-c2（0.53.0 体检页四组：标题齐全、L0 双口径、"
          "B 组取 details、C 组行集合＝longest_by_proc ∪ conns）· "
          "批18 H8/N-H8（0.53.0 收尾：findings 的 lines 三行必须上页面，"
          "只显示类别名＝有内容等于没内容）· "
          "批19 T0/H9-H11（0.53.0 第一优先：第五 TAB 体检进控制台 —— "
          "选项卡恰 5 项＋四组标题、首启落体检页＋引导条逐字＋上次体检一行、"
          "渲染不出现第二份六档）· "
          "批20 H12/N-H12（0.53.0 T1.1：诱饵文件五态不混 —— 没登记/没放过/"
          "没被读/被读过/带出去过各有其词；「没查」不许说成「没有」）· "
          "批21 U20/N-U20（0.53.0 T3.2：撤顶部 24h 计数排 —— 四视图顶部条"
          "无第二份按级计数，唯一家在日报四指标）· "
          "批22 U21/N-U21（0.53.0 T3.3：工具归因显示 —— 徽标只在 ≥2 工具时"
          "出现、归并行尾部带工具分布、旧记录不冒充任何工具）· "
          "批23 T-04 族重写（0.53.0 T4.2/T4.3：账本撤头部四指标卡、区一起点"
          "改昨天、今天改一行深链日报；撤卡后旧文案「下列四个数」必须一起撤）· "
          "批24 U22/N-U22/N-U22b/U23/N-U23（0.53.0 T5.2：运行状态「工具识别」"
          "最小版 —— 分母＝窗口内全部记录、提醒不许常亮、空态不渲染 0%；"
          "链检「没查成」说告警句，中性词「未能核验」在页面上退场）· "
          "批25 T-05/N-T05/T-06/N-T06/T-07/N-T07/T-08/N-T08/T-09/N-T09"
          "（0.53.4 日报细节，创始人 2026-10-20 截图：规则号移到短名之前"
          "＋字号跟正文一样大；日报两卡 label 按内容撑开不写死宽度；"
          "删「本来就不参与比对」同义句；「没纳入比对的记录」数字后侧挂"
          "圈问号，展开体给本次核对的逐文件明细 —— 派生，不写死）")
    print("（变异只在内存，账本与链只落临时目录，不写任何产品文件；"
          "戊2/戊3 视觉项无判据，走 §6.1 截图验收 —— U-13 只含戊2 机械部分）")
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
