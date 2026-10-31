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
.footer{color:var(--muted);font-size:12px;margin-top:28px;
border-top:1px solid var(--line);padding-top:8px}
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


def _ev_html(e: E.Evidence) -> str:
    """一条证据的 HTML。**必须带齐四个 data-* 契约属性。**"""
    attrs = 'class="ev st-%s" data-eid="%s" data-strength="%s" data-cites="%s"' % (
        _e(e.strength), _e(e.eid), _e(e.strength), _e(_cites_attr(e.cites)))
    if e.rule_id:
        attrs += ' data-rule="%s"' % _e(e.rule_id)
    cite_s = " ".join(_cite_html(c) for c in e.cites[:4])
    more = " 等 %d 处" % len(e.cites) if len(e.cites) > 4 else ""
    blind = ('<div class="note">这条看不见什么：%s</div>' % _e(e.blind)) if e.blind else ""
    return (
        '<div %s>'
        '<span class="badge" style="background:%s">%s</span>'
        '<div class="claim">%s</div>'
        '<div class="note">%s</div>'
        '%s'
        '<div class="note">%s%s</div>'
        '</div>'
    ) % (attrs, BADGE_VAR.get(e.strength, "var(--muted)"), _e(e.word()),
         _e(e.claim), _e(e.strength_note()), blind, cite_s, more)


def _folded_html(folded: Sequence[E.Evidence]) -> str:
    """折叠的条目：**显示但不占主视觉**。不许藏起来。"""
    if not folded:
        return ""
    items = "".join(
        '<div class="row"><span class="k">%s</span><span>%s</span></div>'
        % (_e(e.word()), _e(e.claim)) for e in folded)
    return ('<h2>另有 %d 条（未在本页展开）</h2>'
            '<div class="rows">%s</div>' % (len(folded), items))


def render(bundle: E.Bundle, *, cap: int = DEFAULT_CAP,
           corrections: Optional[Sequence[Dict[str, str]]] = None) -> str:
    """渲染一页纸。**首屏必须是「这次看见了什么」，不是「未发现异常」。**"""
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

    # ---- 正文 ----
    if shown:
        parts.append("<h2>这次看见了什么</h2>")
        parts.append('<div class="note" style="margin-bottom:10px">%s</div>' % _e(rule))
        parts.extend(_ev_html(e) for e in shown)
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
    if corrections:
        parts.append("<h2>更正记录（%d 条）</h2>" % len(corrections))
        parts.append('<div class="rows">')
        for c in corrections:
            parts.append(
                '<div class="row"><span class="k">%s</span><span>%s → %s：%s</span></div>'
                % (_e(c.get("at", "")), _e(c.get("target_eid", "")),
                   _e(c.get("new_eid", "（作废）")), _e(c.get("reason", ""))))
        parts.append("</div>")
        parts.append('<div class="note">被更正的条目<b>仍然显示在上文</b>，'
                     '只加了标注。报告不改旧内容——改过的错会让人怀疑全部记录。</div>')

    # ---- 页脚 ----
    parts.append('<div class="footer">')
    for k, v in sorted(bundle.denominators.items()):
        parts.append("%s：%s<br>" % (_e(k), _e(v)))
    parts.append("本报告由 Antinel 监理生成 ｜ 读数时刻 %s ｜ "
                 "回指以该时刻为准（当天文件的行号在此之后仍会变）" % _e(bundle.read_at))
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

    for f in fails:
        print("[自检失败] %s" % f, file=sys.stderr)
    if fails:
        return 1
    print("[自检] 六条全部生效（契约属性／零与不可判／首屏／盲区不折叠／转义／裁量自报）")
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
    if args.out:
        write(b, args.out, cap=args.cap)
        print("已写出：%s（%d 条证据）" % (args.out, b.count()))
    else:
        sys.stdout.write(render(b, cap=args.cap))
    return 0


if __name__ == "__main__":
    sys.exit(main())
