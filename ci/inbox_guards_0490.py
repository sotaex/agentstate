#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.48.5 值守台细节修订判据（交接件 v1.1 §5.7）—— 编号 U-01…U-15。

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
     批次 7（W-04 · 遗留问题 B1）     → W-04（值守台常驻：同端口/口令自恢复）
     批次 8（W-05 · 遗留问题 B2）     → W-05（端口漂移不再静默：出声＋落盘＋托盘带端口）
     批次 9（W-06 · 遗留问题 B3）     → W-06（口令不进 URL：HttpOnly cookie ＋ 链接零 t=）
     批次 10（C1 · 负控模板化）        → C-01（渲染型负控走 `_mut_render` 两步法）
     批次 11（C2 · 判据扫渲染产物）    → 统一口径 `ci/page_caliber.py`（本批**不含新判据**：
                                        它是「编写纪律」的机制化，由元判据 **S48**
                                        在 `ci/guard_instrument_selfaudit.py` 里守）
     批次 12（C5 问号同形 ＋ C4 落位） → **U-16**（问号全站同形：字隐藏、徽章保留）＋
                                        **W-07**（一次性调用方自己等窗就位，真进程实测）

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
    # ★ C2：一律经 `PC.body(...)`（剥 `<style>`/HTML 注释）—— 中文文案只许来自正文层。
    for view in _VIEWS:
        page = _page(view)
        for bad in ("分钟前", "分母均为"):
            if bad in PC.body(page):
                return "%s 页仍含 %r（承诺维持不住的口径／冻结读数）" % (view, bad)
    for tab in _TABS:
        page = _page("inbox", filt=tab)
        if "不随页面停留刷新" not in PC.body(page):
            return "收件箱 tab=%s 缺新措辞「不随页面停留刷新」" % tab
        if M.reading_note() not in PC.body(page):
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
    live = _page("report")
    if M.reading_note() not in PC.body(live) or "分母" in PC.body_without_terms(live):
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
            # ★ C2：经 `PC.body(...)` —— 剥掉 `<style>` 后，CSS 注释里复述过的
            #   同一串不再冒充正文（U-10 曾因此**误红**，见交接件 §C2）。
            if bad in PC.body(page):
                return "%s 页仍含 %r（丁2/丁3：零信息量块没删干净）" % (view, bad)
    health = _page("health")
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
    """反向对照（维二）：把删掉的 who 块原样加回 _bar 的返回串。"""
    src = _src(_SERVER_REL)
    anchor = '        "%s%s<div class=\\"spacer\\"></div></header>"'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    page, _why = _mut_render(src.replace(
        anchor,
        '        "%s%s<div class=\\"spacer\\"></div>"\n'
        '        "<div class=\\"who\\">本机 · 127.0.0.1<br>数据不出门</div></header>"'),
        "is0490_nu10", _SERVER_REL,
                             view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu10_"),
                           token="T", items=_items(), posture=_POSTURE)
    if _why:
        return _why
    if "本机 · 127.0.0.1" not in PC.body(page):
        return "负控失效：who 块加回后页面仍不含它（注入没生效）"
    live = _page("inbox", filt=M.BUCKET_ACTION)
    if "本机 · 127.0.0.1" in PC.body(live):
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
    page, _why = _mut_render(src.replace(
        anchor,
        '        return ("<a title=\\"最近 %d 小时的记录数；括号里是按事由归并后的件数，'
        '点进去看全部明细\\" "'),
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
    anchor = ('                     "%d 次</a> / %d"\n'
              '                     % (hrs, _revived, _win_total))')
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    page, _why = _mut_render(src.replace(
        anchor,
        '                     "%d 次</a> / %d（点开看每一次）"\n'
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
@check("U-04 ★ 乙1：8 个裸「？」芯片落位（筛选条4 + 药丸3 + 顶部灯1）")
def u04():
    """乙1：日报页每个重要词都可点开看定义，收件箱页却一个「？」都没有
    （实测 term 芯片数 0）—— 同一个词两个页面两种待遇。

    形态（§5.6 定稿）：芯片作**兄弟节点**紧贴链接之后，**不嵌套**
    （`<a>` 内嵌 interactive 内容是坏味道）；summary 只放一个「？」
    （屏幕上的「？」由 CSS `::after` 徽章渲染，summary 自身的字由
    `.term.mk>summary{font-size:0}` 藏掉 —— 徽章**不许**关掉去"消重复"，
    那是 C5 的错法，由 **U-16** 锁）；词本名进展开体首行。
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
    # ① summary 只能是「？」一个（"？？”＝ summary 自身的字没藏干净，见 U-16）
    if not re.search(r'<summary>？</summary>', page):
        return "mk 芯片的 summary 不是单个「？」（屏幕上会出现「？？」）"
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
@check("U-13 ★ 戊1：头部用 logo.svg、零 mp4；svg 内部哨点已去（戊2 机械部分）")
def u13():
    """戊1：768×768 → 46×46 的 mp4 缩放下发虚（607 KB 换一个模糊角标）
    ⇒ 头部改用矢量 `logo.svg`；mp4 留给托盘（16×16 合理，不动），
    favicon.ico 不变（U-13 只查头部，不碰托盘与 favicon）。

    戊2 的机械部分并在这里断言（视觉部分走截图验收，§5.8）：
    svg 内部那颗橙色哨点已去 —— 它与顶部条 `.dot` 是两套「点」语言，
    状态由 `.dot` 独占（单一真源）。
    """
    page = _page("inbox")
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
    # 戊2 机械部分：svg 里不再有 circle（状态点只由 CSS .dot 出）
    svg = _src("assets/logo/logo.svg")
    if "<circle" in svg:
        return "logo.svg 内部哨点还在（戊2：两套点语言，状态归 .dot 独占）"
    return True


@check("N-U13 负控：头部换回 mp4 ⇒ U-13 必须红")
def n_u13():
    """反向对照（维二）：把 img 换回 state 专属 mp4（戊1 前的形状）。"""
    src = _src(_SERVER_REL)
    # ★ 0.48.6（B3）：锚点同步 —— 头部 img 的 `src` 不再挂 `?t=%s`（口令走
    #   HttpOnly cookie），`_bar` 的参数表也不再收 `_esc(token)`。变异本身不变
    #   （仍是"把 img 换回 state 专属 mp4"，且 mp4 那条仍带 `?t=%s` —— 于是
    #   参数表要多收两个，与下面的替换严格配对）。
    a_img = ('        "<div class=\\"logo\\"><img alt=\\"Antinel\\" '
             'src=\\"/assets/logo.svg\\"></div>"')
    a_args = "        % (M.STATE_VAR[st], M.STATE_VAR[st],"
    if a_img not in src or a_args not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    page, _why = _mut_render(src.replace(
        a_img,
        '        "<div class=\\"logo\\"><video autoplay loop muted playsinline "\n'
        '        "src=\\"/assets/%s.mp4?t=%s\\"></video></div>"').replace(
        a_args,
        "        % (_esc(M.STATE_LOGO[st]), _esc(token), M.STATE_VAR[st],"
        " M.STATE_VAR[st],"),
        "is0490_nu13", _SERVER_REL,
                             view="inbox", filt=M.BUCKET_ACTION,
                           root=tempfile.mkdtemp(prefix="g0490_nu13_"),
                           token="T", items=_items(), posture=_POSTURE)
    if _why:
        return _why
    head = re.search(r'<header class="bar">.*?</header>', page, re.S)
    if not head or ".mp4" not in head.group(0):
        return "负控失效：换回 mp4 后头部仍无 mp4（注入没生效）"
    live = re.search(r'<header class="bar">.*?</header>', _page("inbox"), re.S)
    if ".mp4" in live.group(0):
        return "夹具不成立：真实现本身头部就带 mp4 ⇒ 负控无分辨力"
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


def _state_words():
    """标题状态词的封闭词表 —— 唯一真源 `host_shield.POSTURE_LABEL_ALLOWED`。

    ★ 不写死、不抄第二份：判据与被判对象必须同一个源（S04 同型纪律）。
    """
    import host_shield as _HS
    return set(_HS.POSTURE_LABEL_ALLOWED)


@check("W-01 ★ 状态词标题：四条认窗断言 ＋ 标题形态 ＋ 词表覆盖")
def w01():
    """§5.5 定稿落地：标题恒用状态词（`<状态词> · 值守台#<hash>`）。

    ① 四条 `is_console_title` 断言（逐字取自交接件 §5.5「四条负控」）：
       状态词 True / 用户形状 False / 挂程序 False / 页面名 True；
    ② 渲染四页：`<title>` ＝ 状态词 · 值守台#<6hex>，且与头部 `<b>` **同词**
       （标题与头部不许两种说法）；
    ③ 覆盖：`STATE_LABEL` ∪ ｢未启用｣ ⊆ 认窗白名单 —— 漏一个词，
       那个态的窗口就认不出、落位失效（§5.5 原话警告）。
    """
    import inbox_window as WIN
    four = (
        ("拦截 · 值守台#abc123", "abc123", True,
         "状态词标题认不出（W-01 前提不成立）"),
        ("请给我一个 · 值守台#a8276c", "a8276c", False,
         "用户窗口形状被误认（0.36.5 实测形状，绝不许放行）"),
        ("记事本 - 拦截 · 值守台#abc123", "abc123", False,
         "挂了别的程序的标题被误认"),
        ("收件箱 · 值守台#abc123", "abc123", True,
         "页面名标题认不出（四页导航保底失效）"),
    )
    for t, rid, want, why in four:
        got = WIN.is_console_title(t, rid)
        if got is not want:
            return "%s（期望 %s，实得 %s）" % (why, want, got)
    # ② 渲染面：标题形态 + 标题与头部同词（四页逐页验）
    words = _state_words()
    for view in ("inbox", "report", "health", "ledger"):
        page = _page(view)
        m = re.search(r"<title>([^<]+)</title>", page)
        if not m:
            return "%s 页没有 <title>（判据扫的锚点没了）" % view
        tm = re.match(r"^(.+) · 值守台#[0-9a-f]{6}$", m.group(1))
        if not tm:
            return ("%s 页标题形态不对：%r（应为「状态词 · 值守台#<6hex>」）"
                    % (view, m.group(1)))
        word = tm.group(1)
        if word not in words:
            return ("%s 页标题状态词 %r 不在 POSTURE_LABEL_ALLOWED 封闭词表里"
                    "—— 那个态的窗口认不出" % (view, word))
        bm = re.search(r'<b style="color:var\(--[a-z0-9]+\)">([^<]+)</b>', page)
        if not bm or bm.group(1) != word:
            return ("%s 页标题状态词与头部不是同一个（标题 %r / 头部 %r）"
                    % (view, word, bm.group(1) if bm else None))
    # ③ 覆盖：头部可达的每个状态词，认窗白名单都必须接纳
    reachable = set(M.STATE_LABEL.values()) | {"未启用"}
    if not reachable <= words:
        return ("有状态词不在认窗白名单里：%s —— 那个态的窗口认不出、落位失效"
                % sorted(reachable - words))
    # 连带：PAGE_TITLES 四键没被本批动过（0360 硬锁的对象）
    if set(SV.PAGE_TITLES.keys()) != {"inbox", "report", "health", "ledger"}:
        return "PAGE_TITLES 键变了（W-01 不许动它）: %s" % sorted(SV.PAGE_TITLES)
    return True


@check("N-W01 负控：认窗白名单缩回「仅页面名」⇒ W-01 必须红")
def n_w01():
    """反向对照（维二）：把 §5.5 点名的那一跳改回 0.48.5 前的形状。

    注入点逐字取自磁盘（`names = … | set(_HS.POSTURE_LABEL_ALLOWED)`），
    缩成 `names = set(_SV.PAGE_TITLES.values())`。期望：**只有** ① 的
    状态词断言翻面（用户形状/挂程序/页面名三条不受影响 —— 白名单只少一维，
    不是整层拆掉，那由回归闸门 G-05 专守）。
    """
    src = _src(_WINDOW_REL)
    a_union = ("        names = set(_SV.PAGE_TITLES.values())"
               " | set(_HS.POSTURE_LABEL_ALLOWED)")
    a_only = "        names = set(_SV.PAGE_TITLES.values())"
    if a_union not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    # 连回：G-05 注入锚点两行必须仍在（regression_gate 的 G-05 负控指着它们）
    if "    if page not in names:\n        return False" not in src:
        return ("G-05 注入锚点两行不在了 —— regression_gate 的 G-05 负控"
                "会失配，「不许误关用户窗口」的保护悄悄失效")
    mut = _load(src.replace(a_union, a_only), "is0490_nw01", _WINDOW_REL)
    if mut.is_console_title("拦截 · 值守台#abc123", "abc123") is not False:
        return "负控失效：缩回仅页面名后状态词标题仍被认出（注入没生效）"
    if mut.is_console_title("收件箱 · 值守台#abc123", "abc123") is not True:
        return "负控失效：缩回仅页面名后页面名标题反而认不出（变异改错了地方）"
    # 连回正判据：真实现下状态词必须认得出（否则负控无分辨力）
    import inbox_window as WIN
    if WIN.is_console_title("拦截 · 值守台#abc123", "abc123") is not True:
        return "夹具不成立：真实现本身状态词标题就认不出 ⇒ 负控无分辨力"
    return True


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

    注入点逐字取自磁盘 `_head()`：把 mark（`#<run_id>`，**真实哈希**）
    再加进 body 起始 —— 与「run_id 回潮正文」同一条路径、同一个变量，
    不是另编一个假串。
    """
    src = _src(_SERVER_REL)
    # ★ 0.48.6（B3）：锚点同步 —— `_head` 的 favicon 不再挂 `?t=%s`，
    #   于是参数表少收一个 `_esc(token)`（变异体也同步少收一个）。
    a_body = ('            "<style>%s</style></head><body>"\n'
              '            % (_esc(title), mark, CSS))')
    if a_body not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    page, _why = _mut_render(src.replace(
        a_body,
        '            "<style>%s</style></head><body><span>%s</span>"\n'
        '            % (_esc(title), mark, CSS, mark))'),
        "is0490_nw02", _SERVER_REL,
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

    两个现场（都注入 guarding 姿态，专盯 A2 那一对矛盾）：
      ① 账内 R0 × 2 条（同因一件） ⇒ 页面「值守中」（0.39.0：历史 R0 不抬灯），
         旧合并读会给「失守」—— A2 实测的就是这一对；
      ② 账内 L2 一条（已拦下）     ⇒ 页面「拦截」（事件级 L2 照常抬灯）——
         防"同源"被做反成"谁都不抬灯"（负向也要同源）。
    """
    import inbox_tray as TR
    posture = _POSTURE                   # guarding：哨兵在岗
    cases = [
        ("账内 R0", [_mk("R0", "unread", 1, 1.0), _mk("R0", "unread", 2, 2.0)],
         "值守中", "失守", 1, 2, "L0"),
        ("账内 L2", [_mk("L2", "unread", 4, 1.0, kind="tool_call_blocked")],
         "拦截", None, 0, 1, "L2"),
    ]
    for name, items, want_word, banned, want_count, want_total, want_st in cases:
        hub = tempfile.mkdtemp(prefix="g0490_w03_")
        # ① 页面侧：标题状态词＝页面**自己**算出来的（render_page 内部同一调用）
        page = _page("inbox", items=items, rep=_REP)
        tm = re.search(r"<title>([^<]+)</title>", page)
        if not tm:
            return "%s：页面没有 <title>（判据扫的锚点没了）" % name
        pm = re.match(r"^(.+) · 值守台#[0-9a-f]{6}$", tm.group(1))
        if not pm:
            return "%s：标题形态不对：%r" % (name, tm.group(1))
        page_word = pm.group(1)
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
            return "%s：guarding 的哨兵态不是 on：%r" % (name, payload.get("shield"))
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


# ══════════ W-04 · B1（值守台常驻：同端口/口令自恢复，遗留问题清单）══════════
#: ★★ 盯的已修缺陷：**B1 无常驻入口** —— 值守台服务原来是"会话里拉的前台进程"，
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
        return ("supervise=True 时守护进程没去确保值守台（tick=%r，ensure 调用 %d 次）"
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


@check("W-04 ★ B1：值守台常驻 —— 两轴判活 / 同端口同口令重拉 / 守护进程监督")
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
            return "带 cookie 拿到的不是值守台页面"
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
"""W-07 探针：在**一次性进程**里走值守台开窗路径，验"落位真的被执行"。

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


def main():
    print("=" * 78)
    print("0.48.5 值守台细节修订判据（交接件 v1.1 §5.7）—— "
          "批1 U-01/U-03/U-08 · 批2 U-10/U-11/U-05 · 批3 U-04/U-06 · "
          "批4 U-13/U-15 · 批5 W-01/W-02（认窗白名单，单独 commit）· "
          "批6 W-03（A2）· 批7 W-04（B1）· 批8 W-05（B2）· 批9 W-06（B3）· "
          "批10 C1（负控模板化：渲染型负控走 _mut_render 两步法）· "
          "批11 C2（扫渲染产物统一走 page_caliber，由元判据 S48 守）· "
          "批12 C5/U-16（问号同形）＋ C4/W-07（一次性调用方等窗就位，真进程实测）")
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
