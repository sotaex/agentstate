# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""一页纸渲染：把 Bundle 变成一份可以打印、可以归档、可以被核对的 HTML。

出处：方案书 §5.2（三种读者＝三种报告）、§5.4（第一份报告必须交付「我们看见了
什么」）、§5.7（每句结论都要能回指）。

──────────────────────────────────────────────────────────────────────────
准入三问（作业单 §0.5）
──────────────────────────────────────────────────────────────────────────
1. 需求：**A（主动去看）**。渲染不做判断，只把已有证据换个排法。
2. 决策器档：**档 0**（纯模板，无模型、无网络、无 JS）。
3. 裁量位置：**观测侧**。唯一裁量是「5 条里放哪 5 条」，见 §pick()，
   且它必须自报「砍了哪些、按什么砍」——裁量不许隐形。

──────────────────────────────────────────────────────────────────────────
零 JS 是硬要求，不是偏好
──────────────────────────────────────────────────────────────────────────
这份报告要能被归档、被邮件转发、被企业微信预览、被打印签字。任何依赖 JS 的
交互在那些场景里都会静默失效，而**失效的报告比没有报告更危险**——它看起来
是完整的。所以折叠用原生 `<details>`，不用脚本。

──────────────────────────────────────────────────────────────────────────
视觉基线：抄 inbox_server.py，不抄 scripts/report.py
──────────────────────────────────────────────────────────────────────────
第一版设计稿抄错了对象（抄了 `scripts/report.py` 的 bootstrap 色 `#dc3545` 那套），
那是**静态审计报告**的样式。真正的产品界面是 `inbox_server.py:124-131` 的
`:root`（`--brand:#145a72` 那套，含暗色模式）。本文件逐字照抄那一组变量。

四档强度**借产品的色、不借形状**：产品六态灯是**圆点**（表示「此刻态势」），
证据档是**方形徽标**（表示「结论强度」）。形状不同 + 旁边永远带文字 ⇒
不会有人把「已记录未判定」误读成「灯灭了」。

──────────────────────────────────────────────────────────────────────────
渲染契约（citecheck.py 依赖它，改这里要同步改那边）
──────────────────────────────────────────────────────────────────────────
每个证据条目：

    <div class="ev" data-eid="…" data-strength="…" data-cites="day:lineno,…"
         [data-rule="…"]>

缺任何一项，`citecheck` 会报「没法校验」而不是「通过」——两者都是没报错，
但一个是盲区、一个是结论（铁律 1／45）。
"""

import html
import os
import sys
from typing import Dict, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import evidence as E  # noqa: E402
import corrections as C  # noqa: E402
import codeid as CID  # noqa: E402

#: 强度排序：越小越靠前。**这是产品判断，不是格式**。
#:   挡下      —— 动作真的没执行，用户最该先知道
#:   没守住    —— 防线失效（C-3 暂不产出，留给规则侧）
#:   提醒      —— 告警了但放行了
#:   已发现无法处置 —— 发现了没手段，比「只是记录」重
#:   已记录未判定 —— 只记账
#:   已核对    —— 账本自洽性检查，是分母不是结论，永远排最后
PRIORITY: Dict[str, int] = {
    E.K_HELD: 0,
    E.K_ALERT: 2,
    E.K_NO_RESPONSE: 3,
    E.K_LOG_ONLY: 4,
    E.K_CHECKED: 5,
}

#: 徽标用的产品色变量名（与 inbox_server.py 的 `--r0/--l2/...` 对应）。
#: **借色值，不借形状**：灯是圆点，这里是方徽标。
BADGE_VAR: Dict[str, str] = {
    E.K_HELD: "var(--l2)",          # 橙：产品里 L2 就是「拦截」
    E.K_ALERT: "var(--l1)",         # 黄褐
    E.K_NO_RESPONSE: "var(--ls)",   # 蓝
    E.K_LOG_ONLY: "var(--lgrey)",   # 灰
    E.K_CHECKED: "var(--l0)",       # 绿
}

#: 默认读者＝用户自己（方案书 §5.2 唯一默认档）。一页纸 3~5 条。
DEFAULT_CAP = 5

CSS = """
:root{--bg:#fff;--panel:#f6f8fa;--fg:#14212b;--muted:#465866;--line:#d6dee4;
--brand:#145a72;--brand-dark:#0f4559;--r0:#9b2226;--l2:#c2410c;--l1:#8a6100;
--ls:#2a5db0;--l0:#226b4a;--lgrey:#5f5e5a;
--sans:system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
--mono:ui-monospace,SFMono-Regular,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0f1417;--panel:#161d21;--fg:#e7edf1;
--muted:#9fb0bb;--line:#2a353b;--brand:#5fb4cf;--brand-dark:#8fd0e4}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 var(--sans)}
main{max-width:1000px;margin:0 auto;padding:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:11px 16px;margin-bottom:9px}
h1{font-size:19px;margin:0 0 4px}
h2{font-size:15px;margin:20px 0 10px}
.meta{color:var(--muted);font-size:12.5px;margin-bottom:14px}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
gap:12px;margin-bottom:6px}
.metric{background:var(--panel);border-radius:10px;padding:11px}
.metric .k{font-size:12px;color:var(--muted)}
.metric .v{font-size:26px;font-weight:700}
.metric .unit{font-size:13px;font-weight:600;color:var(--muted)}
.ev{border:1px solid var(--line);border-left-width:4px;border-radius:10px;
padding:10px 14px;margin-bottom:10px}
.ev.st-held{border-left-color:var(--l2)}.ev.st-alert{border-left-color:var(--l1)}
.ev.st-no_response{border-left-color:var(--ls)}
.ev.st-log_only{border-left-color:var(--lgrey)}
.ev.st-checked{border-left-color:var(--l0)}
.badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:12px;
font-weight:700;color:#fff;white-space:nowrap}
.claim{margin-top:6px}
.note{color:var(--muted);font-size:12.5px;margin-top:4px}
.cite{font-family:var(--mono);font-size:12px;color:var(--brand);text-decoration:none;
border-bottom:1px dotted var(--brand)}
.daylevel{font-family:var(--mono);font-size:12px;color:var(--muted);font-style:italic}
details{margin:6px 0}
details.folded{border:1px solid var(--line);border-radius:10px;padding:6px 12px;margin-top:12px}
details.folded summary{font-size:13px}
summary{cursor:pointer;font-size:12.5px;color:var(--brand)}
pre.raw{background:var(--bg);border:1px solid var(--line);border-radius:6px;
padding:8px 10px;font-family:var(--mono);font-size:11.5px;overflow-x:auto;
margin:6px 0;white-space:pre-wrap;word-break:break-all}
.rows{border:1px solid var(--line);border-radius:10px;overflow:hidden}
.row{display:flex;gap:12px;padding:8px 15px;border-bottom:1px solid var(--line);
font-size:13px}
.row:last-child{border-bottom:0}
.row .k{flex:none;width:170px;color:var(--muted)}
.undecide{border:1px dashed var(--l1);background:var(--panel);border-radius:10px;
padding:10px 14px;margin-bottom:9px;font-size:13px}
.zero{border:1px solid var(--line);background:var(--panel);border-radius:10px;
padding:10px 14px;font-size:13px;color:var(--muted)}
/* ---- 更正（设计 §4）：作废用中性色，不用红 ---- */
/* 作废不等于「出事了」，它是「这一版不再有效」。红色会让读者以为发现了安全问题，
   而实际可能只是口径修正。颜色的含义必须稳定，否则同一个红在两种意思之间摇摆。 */
.void{border:1px solid var(--line);border-left:5px solid var(--lgrey);
background:var(--panel);border-radius:10px;padding:12px 16px;margin-bottom:16px}
.void .t{font-weight:700;margin-bottom:4px}
.supersedes{border:1px dashed var(--line);border-radius:10px;padding:8px 14px;
font-size:12.5px;color:var(--muted);margin-bottom:14px}
/* 被取代的条目：整条加删除线 + 左侧灰边，但仍在原位置、不折叠、不隐藏 */
.ev.superseded{border-left-color:var(--lgrey)}
.ev.superseded .claim{text-decoration:line-through;
text-decoration-color:var(--muted);text-decoration-thickness:1.5px;opacity:.75}
.supnote{border-left:3px solid var(--lgrey);padding:6px 10px;margin:0 0 7px;
font-size:12.5px;color:var(--muted);background:var(--bg);border-radius:0 6px 6px 0}
.footer{color:var(--muted);font-size:12px;margin-top:28px;
border-top:1px solid var(--line);padding-top:8px}
/* 代码组指纹：页脚里唯一一个跨版本可比的字段，所以给它等宽字体 + 加粗，
   让「两份报告是不是同一份代码算的」可以靠眼睛扫出来 */
.fp{font-family:var(--mono);font-weight:700;color:var(--brand);
letter-spacing:.5px;user-select:all}
.fppairs{font-family:var(--mono);font-size:11px;word-break:break-all}
.fpbad{border:1px solid var(--r0);border-radius:8px;padding:7px 10px;margin:6px 0;
color:var(--r0);font-size:12px}
@media print{body{margin:0}.ev,.undecide,.zero{break-inside:avoid}}
"""


def _e(x) -> str:
    return html.escape(str(x), quote=True)


def _cites_attr(cites: Sequence[E.Cite]) -> str:
    """`data-cites` 的值。**契约字段**，citecheck 靠它定位。"""
    return ",".join("%s:%d" % (c.day, c.lineno) for c in cites)


def _cite_html(c: E.Cite) -> str:
    if c.day_level:
        # 天粒度必须写「整天」。写成 `2026-10-05:0` 会被读成「第 0 行」，
        # 而第 0 行不存在，读者会以为回指坏了（其实是我们表达得不对）。
        return '<span class="daylevel">%s（整天 · 该日无行号可指）</span>' % _e(c.day)
    return '<span class="cite">%s:%d</span>' % (_e(c.day), c.lineno)


def pick(evs: Sequence[E.Evidence], cap: int = DEFAULT_CAP
         ) -> Tuple[List[E.Evidence], List[E.Evidence], str]:
    """挑出这一页要显示的 N 条。返回 `(显示, 折叠, 取舍规则说明)`。

    ★ 裁量必须自报。方案书 §5.4 要求「交付我们看见了什么」，但如果悄悄砍掉
      15 条只留 5 条，读者会以为「就这 5 件事」——那是用排版制造错觉。
      所以本函数**必须**同时返回「按什么砍的」，渲染层必须把它印出来。

    ★ 排序不用「时间新鲜度」：`Cite` 里只有 (day, lineno)，没有事件时刻；
      拿行号当新鲜度是拿量具冒充结论（行号大 ≠ 更近）。宁可只按强度排，
      也不编一个看起来更聪明的规则。
    """
    order = sorted(evs, key=lambda e: (PRIORITY.get(e.strength, 9), e.eid))
    shown, folded = order[:cap], order[cap:]
    if not folded:
        rule = "全部 %d 条都在这一页（未折叠）" % len(shown)
    else:
        rule = (
            "共 %d 条，这里显示 %d 条、折叠 %d 条。排序规则：按结论强度"
            "（挡下 → 提醒 → 已发现无法处置 → 已记录未判定 → 已核对），"
            "同强度按证据 id 字典序。**折叠的不代表不重要，只代表这一页放不下。**"
            % (len(evs), len(shown), len(folded))
        )
    return shown, folded, rule


def _ev_html(e: E.Evidence, corr: Optional["C.Correction"] = None) -> str:
    """一条证据的 HTML。**必须带齐四个 data-* 契约属性。**

    `corr` 非空表示这条**已被取代**：整条加删除线 + 前置一行说明，
    但 `data-eid` / `data-strength` 保持原值——被取代的是「结论的效力」，
    不是「当时说过什么」。改掉原强度等于篡改历史。
    """
    cls = "ev st-%s" % _e(e.strength)
    sup_attr = ""
    sup_note = ""
    if corr is not None:
        cls += " superseded"
        sup_attr = ' data-superseded="%s"' % _e(corr.new_eid or corr.new_report)
        sup_note = ('<div class="supnote">此条已被 %s 的报告取代：%s'
                    '（请以 %s 为准）</div>'
                    % (_e(corr.at[:10]), _e(corr.reason),
                       _e(corr.new_eid or corr.new_report)))
    attrs = 'class="%s" data-eid="%s" data-strength="%s" data-cites="%s"%s' % (
        cls, _e(e.eid), _e(e.strength), _e(_cites_attr(e.cites)), sup_attr)
    if e.rule_id:
        attrs += ' data-rule="%s"' % _e(e.rule_id)
    if e.status:
        # 上游状态随契约出去：citecheck 靠它做一条行为判据
        # （标了 WARN 的条目，页面上必须有「偏离」两个字）。
        attrs += ' data-status="%s"' % _e(e.status)
    cite_s = " ".join(_cite_html(c) for c in e.cites[:4])
    more = " 等 %d 处" % len(e.cites) if len(e.cites) > 4 else ""
    blind = ('<div class="note">这条看不见什么：%s</div>' % _e(e.blind)) if e.blind else ""

    # ★ WARN 不许印成和 PASS 一样的绿徽标。auditor 的四档里，PASS 与 WARN 在
    #   强度词表里是**同一个词**（「已核对」），但它们对读者的意思相反：
    #   一个是「核过了，一致」，一个是「核过了，有性质偏离，只是不算篡改」。
    #   真账本上 A3（历史缺锚）与 A4（495 处倒序）都是 WARN，第一版把两条都印成
    #   绿色「已核对」—— 读者一眼扫过去，而那正是最该停一下的两条。
    #   强度档不动（对外强度不变，铁律 21），只把「偏离」这个事实显式化。
    word = e.word()
    badge_var = BADGE_VAR.get(e.strength, "var(--muted)")
    if e.status == "WARN":
        word = "%s·有偏离" % word
        badge_var = "var(--l1)"

    return (
        '<div %s>'
        '%s'
        '<span class="badge" style="background:%s">%s</span>'
        '<div class="claim">%s</div>'
        '<div class="note">%s</div>'
        '%s'
        '<div class="note">%s%s</div>'
        '</div>'
    ) % (attrs, sup_note, badge_var, _e(word),
         _e(e.claim), _e(e.strength_note()), blind, cite_s, more)


def _folded_html(folded: Sequence[E.Evidence]) -> str:
    """折叠的条目：**显示但不占主视觉**。不许藏起来，也不许丢掉出处。

    ★ 第一版把折叠条目渲染成「只有徽标词 ＋ 结论」的行，**没有 data-cites**。
      后果不是排版问题，是报告直接出不来：`report.produce` 把**上游条数**
      当分母传给 citecheck，而 citecheck 只认 class="ev" 的条目 ——
      6 条证据里折叠 1 条，它就报「渲染丢了 1 条」并拒绝落盘。
      **只要某天真账本产出 6 条证据，报告就再也写不出来了**，而这件事在
      5 条以内永远看不到。实测 2026-11-01：端到端负控 e2／e3 两条臂同时红。

    ★ 修法不是改分母，是让折叠条目**照样带出处**：折叠用原生 <details>
      （本来就是这个设计），里面仍是完整的 .ev 条目。首屏还是 5 条，
      但每一条被折叠的结论照样能回指（§5.7：回指不到 ⇒ 不许写）。
      改分母等于承认「折叠的结论不需要出处」—— 那是把预算问题说成口径问题。
    """
    if not folded:
        return ""
    items = "".join(_ev_html(e) for e in folded)
    return ('<details class="folded"><summary>另有 %d 条'
            '（展开看全部，每条都带出处）</summary>%s</details>'
            % (len(folded), items))


def render(bundle: E.Bundle, *, cap: int = DEFAULT_CAP,
           resolved: Optional["C.Resolved"] = None,
           code_fp: Optional[CID.Fingerprint] = None) -> str:
    """渲染一页纸。**首屏必须是「这次看见了什么」，不是「未发现异常」。**

    `code_fp` 不给就现算（`codeid.compute()`）。自检要能注入一个**残缺**指纹，
    才能验出「不完整时页脚会明说」——否则那条分支永远是没跑过的代码。
    """
    by = bundle.by_strength()
    n_need = sum(len(by.get(k, [])) for k in (E.K_HELD, E.K_ALERT, E.K_NO_RESPONSE))
    n_log = len(by.get(E.K_LOG_ONLY, []))
    n_chk = len(by.get(E.K_CHECKED, []))

    shown, folded, rule = pick(bundle.evidence, cap)

    parts: List[str] = []
    parts.append("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
    parts.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    parts.append("<title>Antinel 监理报告 · %s</title>" % _e(bundle.read_at))
    parts.append("<style>%s</style></head><body><main>" % CSS)

    parts.append("<h1>Antinel 监理 · 一页纸</h1>")
    parts.append('<div class="meta">读数时刻 %s ｜ 账本 %s</div>'
                 % (_e(bundle.read_at),
                    _e(bundle.denominators.get("账本", "（未取到）"))))

    # ---- 作废横幅：**必须在首屏**（设计 §4.2 红线 2），不许挪到页脚 ----
    # 第三方拿到一份作废报告而没看到横幅，等于被误导。所以它排在标题之后、
    # 一切正文之前，且用中性色——作废不等于「出事了」。
    if resolved is not None and resolved.void is not None:
        v = resolved.void
        parts.append(
            '<div class="void"><div class="t">本报告已于 %s 作废</div>'
            '原因：%s<br>请以 <b>%s</b> 为准。</div>'
            % (_e(v.at[:10]), _e(v.reason), _e(v.new_report)))

    # ---- 反向指认（设计 §4.2 红线 3）：只单向会让读者在旧报告里找不到新结论 ----
    if resolved is not None and resolved.supersedes:
        parts.append(
            '<div class="supersedes">本报告取代了 %s。'
            '被取代的报告仍然可查——它们说的是「当时判断的是什么」，'
            '不是「现在的结论」。</div>'
            % _e("、".join(resolved.supersedes)))

    if resolved is not None:
        for w in resolved.warnings:
            parts.append('<div class="undecide">%s</div>' % _e(w))

    # ---- 四个数字（不写分数：C 线不出「安全分」，那是判定侧的事）----
    parts.append('<div class="metrics">')
    for label, val, unit in (
        ("结论", bundle.count(), "条"),
        ("需要你看一眼", n_need, "条"),
        ("只是记录", n_log, "条"),
        ("账本自洽检查", n_chk, "条"),
    ):
        parts.append('<div class="metric"><div class="k">%s</div>'
                     '<div class="v">%d<span class="unit">%s</span></div></div>'
                     % (_e(label), val, _e(unit)))
    parts.append("</div>")

    # ★ 「需要你看一眼 0 条」必须自己解释这个 0。
    #   四个数字排在一起，0 会被读成「没事」——而 C 线读的是**账本**、不是规则库，
    #   所以「挡下」「提醒」这两档今天**结构上就产不出来**（见 evidence 模块头）。
    #   这个 0 不是「查了没有危险」，是「这一层的判据还没接上」。
    #   ★ 自检里那条「不许出现『未发现异常』」守的是**字面**，守不住**读起来一个意思**：
    #     字面没写那四个字，效果一样。这是本轮实测撞出来的第一类盲区。
    #   ★ 解释来自 evidence.need_zero_note()，不由本层自己编 —— 0 至少有三种来源
    #     （真没有／判据没接上／工具没跑），页面上只有一个 0。
    if n_need == 0 and bundle.evidence:
        parts.append('<div class="zero">%s</div>' % _e(E.need_zero_note()))

    # ---- 正文 ----
    if shown:
        parts.append("<h2>这次看见了什么</h2>")
        parts.append('<div class="note" style="margin-bottom:10px">%s</div>' % _e(rule))
        parts.extend(
            _ev_html(e, resolved.superseded.get(e.eid) if resolved else None)
            for e in shown)
        parts.append(_folded_html(folded))
    else:
        # 没有证据 ≠ 一切正常。要说清是「查了没有」还是「没查成」。
        if bundle.undecidable:
            parts.append("<h2>这次什么也没查成</h2>")
            parts.append('<div class="undecide">两条检查都没跑成，'
                         '本报告不含任何结论。原因见下方「不可判」。</div>')
        else:
            parts.append("<h2>这次看见了什么</h2>")
            parts.append('<div class="zero">两条检查都跑成了，都没有发现变化。'
                         '<b>这是「查了，没有」，不是「没查」。</b>'
                         '分母见页脚。</div>')

    # ---- 不可判（必须在页脚之前；与「0 条」视觉不同）----
    if bundle.undecidable:
        parts.append("<h2>不可判（%d 项）</h2>" % len(bundle.undecidable))
        for u in bundle.undecidable:
            parts.append('<div class="undecide">%s</div>' % _e(u))
        parts.append('<div class="note">这些项目<b>没有跑成</b>。'
                     '它们既不是「通过」，也不是「没有异常」。</div>')

    # ---- 不适用（与「没跑成」分成两块，理由见下）----
    # ★ 合成一块的代价：真账本上 A5（未给 --declare）被印在「不可判」里，
    #   紧跟着一句「这些项目没有跑成」。而 A5 不是没跑成 —— 它跑了，明确判了
    #   「本维度不适用」。把一条**已知的适用边界**说成**未知的故障**，方向正好相反。
    #   更贵的是：A5 是唯一能抓「删记录」的量具，它不适用＝删记录不可见，
    #   这是这份报告最重要的一条盲区，却被写成了一句故障脚注。
    if bundle.not_applicable:
        parts.append("<h2>不适用（%d 项）</h2>" % len(bundle.not_applicable))
        for u in bundle.not_applicable:
            parts.append('<div class="undecide">%s</div>' % _e(u))
        parts.append('<div class="note">这些项目<b>问了，但这把尺子量不到这件事</b>。'
                     '它既不是故障，也不是「通过」——它是一条<b>已知的适用边界</b>：'
                     '这里没有结论，不等于这里没有问题。</div>')

    # ---- 盲区（默认展开，不许折叠）----
    if bundle.blind:
        parts.append("<h2>这份报告看不见什么</h2>")
        parts.append('<div class="rows">')
        for b in bundle.blind:
            title, _, rest = b.partition(" —— ")
            parts.append('<div class="row"><span class="k">%s</span><span>%s</span></div>'
                         % (_e(title), _e(rest or title)))
        parts.append("</div>")

    # ---- 更正（若有）----
    if resolved is not None and (resolved.superseded or resolved.void is not None):
        n = len(resolved.superseded) + (1 if resolved.void else 0)
        parts.append("<h2>更正记录（%d 条）</h2>" % n)
        parts.append('<div class="rows">')
        if resolved.void is not None:
            v = resolved.void
            parts.append('<div class="row"><span class="k">%s</span>'
                         '<span>整份作废 → %s：%s</span></div>'
                         % (_e(v.at[:10]), _e(v.new_report), _e(v.reason)))
        for eid in sorted(resolved.superseded):
            c = resolved.superseded[eid]
            parts.append('<div class="row"><span class="k">%s</span>'
                         '<span>%s → %s：%s</span></div>'
                         % (_e(c.at[:10]), _e(eid), _e(c.new_eid), _e(c.reason)))
        parts.append("</div>")
        parts.append('<div class="note">被更正的条目<b>仍然显示在上文</b>，'
                     '只加了删除线与说明。报告不改旧内容——'
                     '改过的错会让人怀疑全部记录。</div>')

    # ---- 页脚 ----
    parts.append('<div class="footer">')
    rid = resolved.report_id if resolved is not None else C.report_id(bundle)
    parts.append("报告编号 <b>%s</b>（要更正它，就用这个号指名）<br>" % _e(rid))
    id_note = C.report_id_note(bundle)
    if id_note:
        parts.append("%s<br>" % _e(id_note))
    for k, v in sorted(bundle.denominators.items()):
        parts.append("%s：%s<br>" % (_e(k), _e(v)))
    parts.append("本报告由 Antinel 监理生成 ｜ 读数时刻 %s ｜ "
                 "回指以该时刻为准（当天文件的行号在此之后仍会变）" % _e(bundle.read_at))

    # ---- 代码组指纹：这份报告是哪份代码算的（九维六在报告层的落地）----
    #
    # ★ 报告编号回答「要更正哪一份」，指纹回答「它当时是被哪份代码算出来的」。
    #   两者**不能合并**：编号要稳定（更正靠它指名），而指纹必须随代码变——
    #   一份归档报告如果只能回答前者，事后就无法区分「账本变了」与「代码变了」。
    fp = code_fp if code_fp is not None else CID.compute()
    if fp.ok:
        parts.append("<br>代码组指纹 <b class=\"fp\" data-codefp=\"%s\">%s</b>"
                     "（%d 个源文件）<br>"
                     % (_e(fp.gid), _e(fp.short), len(fp.items)))
        parts.append("<span class=\"fppairs\">%s</span><br>" % _e(fp.pairs()))
        parts.append("核对办法：跑 <code>python output/lineC/selfproof.py</code>，"
                     "它打出的组指纹必须与上面一致；不一致 ⇒ 这份报告不是当前代码"
                     "算的，结论要重算。<br>%s" % _e(fp.note()))
    else:
        # 缺文件时**不许**打一个残缺指纹。残缺指纹看起来是完整的 64 位串，
        # 而它证明不了任何事——这就是「零与不可判同貌」在指纹上的形态。
        parts.append('<div class="fpbad">代码组指纹 <b>不完整</b>（缺 %d 个：%s）'
                     '—— 这份报告的出处无法核对，<b>不该被当作归档凭据</b>。%s</div>'
                     % (len(fp.missing), _e("、".join(fp.missing)), _e(fp.note())))
    parts.append("</div>")

    parts.append("</main></body></html>")
    return "\n".join(parts)


def write(bundle: E.Bundle, out_path: str, **kw) -> str:
    """落盘。目录不存在就建（报告是产物，不是产品状态）。"""
    d = os.path.dirname(os.path.abspath(out_path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    text = render(bundle, **kw)
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return out_path


def _selfcheck() -> int:
    """量具自检：先证明这份模板守住了四条红线，再拿它渲染真账本。"""
    fails: List[str] = []

    ev = E.Evidence(eid="AUD-test01", claim="测试结论", strength=E.K_LOG_ONLY,
                    cites=(E.Cite("2026-11-01", 3),), source="t",
                    read_at="2026-11-01 03:00:00", blind="看不见 X")
    b = E.Bundle(read_at="2026-11-01 03:00:00", root="")
    b.evidence.append(ev)
    b.denominators["账本"] = "33 个日文件 / 100 条"

    h = render(b)

    # 红线 4：每条结论必须有可点出处（契约属性齐全）
    for attr in ('data-eid="AUD-test01"', 'data-strength="log_only"',
                 'data-cites="2026-11-01:3"'):
        if attr not in h:
            fails.append("渲染契约缺属性：%s" % attr)

    # 红线 2：不可判与 0 条必须不同貌
    b2 = E.Bundle(read_at="t", root="")
    b2.undecidable.append("auditor 没跑成：模拟")
    h2 = render(b2)
    if "undecide" not in h2:
        fails.append("有不可判却没有 undecide 区块")
    if "查了，没有" in h2:
        fails.append("有不可判却说了「查了，没有」—— 零与不可判同貌")

    b3 = E.Bundle(read_at="t", root="")
    h3 = render(b3)
    if "查了，没有" not in h3:
        fails.append("真的空账本没有说「查了，没有」")

    # 红线 1：首屏不许是「未发现异常」
    if "未发现异常" in h:
        fails.append("产物里出现了「未发现异常」—— 用户眼里等于「没用」")

    # 红线 3：盲区不许折叠
    b4 = E.Bundle(read_at="t", root="")
    b4.blind = ("账本以外的一切 —— 没被钩子拦到的不进账本",)
    h4 = render(b4)
    if "看不见什么" not in h4:
        fails.append("有盲区却没有盲区块")
    if "<details" in h4.split("看不见什么")[1][:400]:
        fails.append("盲区被折叠了（details）—— 折叠盲区＝隐藏「我不知道」")

    # XSS：证据内容里的尖括号必须被转义
    ev_x = E.Evidence(eid="X", claim="<script>alert(1)</script>",
                      strength=E.K_LOG_ONLY, cites=(E.Cite("2026-11-01", 1),),
                      source="t", read_at="t")
    bx = E.Bundle(read_at="t", root="")
    bx.evidence.append(ev_x)
    if "<script>" in render(bx):
        fails.append("证据内容未转义 —— 命令原文里带尖括号会注入页面")

    # 裁量自报：折叠了就必须说明按什么砍
    many = [E.Evidence(eid="E%02d" % i, claim="结论%d" % i, strength=E.K_LOG_ONLY,
                       cites=(E.Cite("2026-11-01", i + 1),), source="t", read_at="t")
            for i in range(12)]
    bm = E.Bundle(read_at="t", root="")
    bm.evidence.extend(many)
    hm = render(bm, cap=5)
    if "折叠 7 条" not in hm or "排序规则" not in hm:
        fails.append("折叠了却没自报「砍了哪些、按什么砍」")

    # 折叠的条目**也必须带齐契约属性** —— 否则 report.produce 会以
    # 「渲染丢了 N 条」拒绝落盘（真账本一旦超过 cap 就再也出不来报告）。
    # 实测 2026-11-01：端到端负控 e2／e3 同时红才撞出来，5 条以内永远看不到。
    if hm.count('data-eid="') != 12:
        fails.append("折叠的条目没带 data-eid（抽出 %d 条，应为 12）—— "
                     "超过 cap 时报告会被自己的回指校验拒收"
                     % hm.count('data-eid="'))
    if "details" not in hm:
        fails.append("折叠没用 <details>（零 JS 的原生折叠）")

    # ---- 更正（设计 §6 验收 1／2／6）----
    bc = E.Bundle(read_at="2026-11-01 03:00:00", root="")
    bc.evidence.append(E.Evidence(
        eid="AUD-corr01", claim="原来那条结论", strength=E.K_LOG_ONLY,
        cites=(E.Cite("2026-11-01", 5),), source="t",
        read_at="2026-11-01 03:00:00"))
    rid_c = C.report_id(bc)
    corr = C.Correction(at="2026-11-01T04:00:00+08:00", by="C-3",
                        kind=C.K_SUPERSEDE, target_report=rid_c,
                        target_eid="AUD-corr01", reason="该日机制当时不存在",
                        new_eid="AUD-new001")
    hc = render(bc, resolved=C.resolve(bc, [corr]))
    # 验收 1：被更正的条目**仍然出现在产物里**（不许隐藏、不许折叠、不许移出原位）
    if 'data-eid="AUD-corr01"' not in hc:
        fails.append("被更正的条目从产物里消失了 —— 藏起来等于事后没人知道这里错过")
    if "superseded" not in hc or "此条已被" not in hc:
        fails.append("被更正的条目没有换长相（删除线／说明行）")

    # 验收 2：作废横幅必须在**首屏**（正文之前、页脚之前）
    void = C.Correction(at="2026-11-01T05:00:00+08:00", by="C-3",
                        kind=C.K_VOID, target_report=rid_c,
                        reason="整份基于错误读数", new_report="R-new000000001")
    hv = render(bc, resolved=C.resolve(bc, [void]))
    if "本报告已于" not in hv:
        fails.append("整份作废却没有横幅")
    else:
        i_banner = hv.find("本报告已于")
        i_body = hv.find("这次看见了什么")
        i_foot = hv.find('<div class="footer">')
        if i_body < 0 or i_foot < 0:
            fails.append("作废横幅定位失败（找不到正文或页脚）")
        elif not (i_banner < i_body < i_foot):
            fails.append("作废横幅不在首屏（横幅 %d／正文 %d／页脚 %d）"
                         % (i_banner, i_body, i_foot))

    # 验收 6：新报告**反向指认**旧报告
    bn = E.Bundle(read_at="2026-11-01 05:00:00", root="")
    bn.evidence.append(E.Evidence(
        eid="AUD-new001", claim="新结论", strength=E.K_LOG_ONLY,
        cites=(E.Cite("2026-11-01", 6),), source="t",
        read_at="2026-11-01 05:00:00"))
    rid_n = C.report_id(bn)
    c2 = C.Correction(at="2026-11-01T06:00:00+08:00", by="C-3",
                      kind=C.K_SUPERSEDE, target_report=rid_c,
                      target_eid="AUD-corr01", reason="r",
                      new_report=rid_n, new_eid="AUD-new001")
    hn = render(bn, resolved=C.resolve(bn, [c2]))
    if rid_c not in hn:
        fails.append("新报告没有反向指认旧报告 —— 旧报告归档后读者找不到新结论")

    # ---- 代码组指纹（九维六在报告层）----
    # 验收 10：页脚必须印出**当前这份代码**的指纹，且值必须真等于现算的结果
    # （只检查「有个十六进制串」是不够的——那可能是个写死的常量）
    cur = CID.compute()
    h10 = render(b)
    if not cur.ok:
        fails.append("自检环境本身算不出代码指纹：缺 %s" % "、".join(cur.missing))
    if 'data-codefp="%s"' % cur.gid not in h10:
        fails.append("页脚没有印出当前代码组指纹 —— 归档报告无法回答「哪份代码算的」")
    # 验收 11：指纹必须在页脚里（正文里出现＝读者在读到结论前就被编号干扰；
    # 页脚之后出现＝它可能被当成另一份文档的）
    i_fp = h10.find('data-codefp=')
    i_foot2 = h10.find('<div class="footer">')
    i_end = h10.rfind("</div>")
    if i_fp < 0 or i_foot2 < 0:
        fails.append("指纹定位失败（找不到 data-codefp 或页脚）")
    elif not (i_foot2 < i_fp < i_end):
        fails.append("代码指纹不在页脚内（页脚 %d／指纹 %d／末尾 %d）"
                     % (i_foot2, i_fp, i_end))
    # 验收 12：残缺指纹必须**明说不完整**，且不许冒出一个 data-codefp
    broken = CID.compute([os.path.join(HERE, "codeid.py"),
                          os.path.join(HERE, "__nope__.py")])
    if broken.ok:
        fails.append("自检构造的残缺指纹竟然 ok —— 夹具失效，验不到这条分支")
    h12 = render(b, code_fp=broken)
    if "fpbad" not in h12 or "不完整" not in h12:
        fails.append("指纹残缺却没说「不完整」—— 残缺值会被当成完整值用")
    if 'data-codefp="' in h12:
        fails.append("指纹残缺却仍打出了 data-codefp —— 机器会读到一个假指纹")

    # ---- 性质偏离不许印成通过（WARN 与 PASS 在强度词表里是同一个词）----
    bw = E.Bundle(read_at="t", root="")
    bw.evidence.append(E.Evidence(
        eid="AUD-warn01", claim="A3 日清单：有历史缺锚", strength=E.K_CHECKED,
        cites=(E.Cite("2026-11-01", 1),), source="auditor", read_at="t",
        status="WARN"))
    hw = render(bw)
    if "偏离" not in hw:
        fails.append("WARN 的徽标没有「偏离」—— 性质偏离被印成了通过")
    if 'data-status="WARN"' not in hw:
        fails.append("WARN 没有随契约出去（缺 data-status）—— citecheck 的判据会瞎")

    # ---- 「不适用」不许被说成「没有跑成」----
    bn2 = E.Bundle(read_at="t", root="")
    bn2.evidence.append(ev)
    bn2.not_applicable.append("A5 总量 不适用：未给 --declare")
    hn2 = render(bn2)
    if "不适用（1 项）" not in hn2:
        fails.append("有不适用项却没有「不适用」区块")
    if "没有跑成" in hn2:
        fails.append("只有「不适用」却说了「没有跑成」—— 把已知的适用边界说成了未知故障")

    # ---- 「需要你看一眼 0 条」必须自己解释这个 0 ----
    # b 里只有一条 log_only ⇒ n_need == 0。字面没写「未发现异常」，
    # 但读者看到的仍然是一个 0 —— 自检守字面，守不住「读起来一个意思」。
    if "结构上产不出来" not in h:
        fails.append("「需要你看一眼」为 0 却没解释这个 0 —— 读者会读成「没事」")

    # ---- 产物里不许出现 `**` ----
    # 注意范围：**含 CSS 注释**。第一版只想到「正文里别写星号」，实测产物里
    # 四处 `**` 全在 CSS 注释里 —— 读者看不见，但它确实随文件出去了，
    # 而这份文件是要被归档、被转发的。「看不见」不等于「不在产物里」。
    if "**" in h:
        fails.append("产物里出现了 `**` —— 散文的 Markdown 强调外泄到了产物（含 CSS 注释）")

    for f in fails:
        print("[自检失败] %s" % f, file=sys.stderr)
    if fails:
        return 1
    print("[自检] 十七条全部生效（契约属性／零与不可判／首屏／盲区不折叠／转义／"
          "裁量自报／折叠条目也带出处／被更正条目仍在／作废横幅在首屏／反向指认／"
          "指纹在页脚／指纹值真等于现算／残缺即明说不完整／WARN 不印成通过／"
          "不适用≠没跑成／0 条必须自己解释／产物无星号）")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="一页纸渲染（只读，档 0，零 JS）")
    ap.add_argument("--root", default=".psl/audit")
    ap.add_argument("--out", help="写到这个文件；不给就打到 stdout")
    ap.add_argument("--cap", type=int, default=DEFAULT_CAP)
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if args.selfcheck:
        return _selfcheck()
    if not os.path.isdir(args.root):
        print("[停] 目录不存在：%s" % args.root, file=sys.stderr)
        return 2

    b = E.collect(args.root)

    # 更正记录：**读不出来要停**，不许静默当成「没有更正」。
    # 「没有更正」与「不知道有没有更正」是两件事——这就是零与不可判同貌。
    try:
        items = C.Ledger(args.root).load()
    except (ValueError, OSError) as exc:
        print("[停] 更正记录读不出来：%s" % exc, file=sys.stderr)
        return 2
    res = C.resolve(b, items)

    # 代码指纹：算一次、传下去，别在 render 里各算一遍（两次之间文件可能被改，
    # 那就会出现「页脚印的指纹」与「实际渲染的代码」不是同一份）。
    fp = CID.compute()

    if args.out:
        if not fp.ok:
            # ★ 不写盘。一份出处无法核对的一页纸，看起来和正常报告一模一样——
            #   它会被归档、被转发、被当成凭据。宁可不出，也不出一份假凭据。
            print("[停] 代码指纹不完整（缺 %s），不写报告：出处无法核对的报告"
                  "不该存在。" % "、".join(fp.missing), file=sys.stderr)
            return 2
        write(b, args.out, cap=args.cap, resolved=res, code_fp=fp)
        print("已写出：%s（%d 条证据，报告编号 %s，代码组指纹 %s）"
              % (args.out, b.count(), res.report_id, fp.short))
    else:
        sys.stdout.write(render(b, cap=args.cap, resolved=res, code_fp=fp))
    return 0


if __name__ == "__main__":
    sys.exit(main())
