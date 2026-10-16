#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""判据扫「渲染产物」的**统一口径**（遗留问题 C2 的机制落点，2026-10-13）。

★★ 为什么必须统一（不是洁癖，是实测踩出来的）：
  判据断言「页面上有没有这句话」时，若扫的是**整页原文**，就会把
  量具不该算的东西一并算进来 —— 于是断言**时红时绿**：

    · `<style>` 里的 CSS 注释。实测：U-10 断言「本机 · 127.0.0.1」零出现，
      正文里早删干净了，可 CSS 注释里复述过一遍 ⇒ **误红**。
    · 术语浮层的词条口径行（`<details class="term|gloss">` 里的 `<div class="tdef">`）。
      实测：U-03 的「分母」从词条口径行漏出剥离层 ⇒ **误红**。
    · HTML 注释。
    · 源码注释／docstring（同族，见下）。

  这与 D-30（docstring 里的路径）、S45（`ast.dump` 结果做子串匹配）**同族**：
  **把非正文层当正文**。本仓铁律「一个时红时绿的量具比恒红的更坏」。

★★ 解法：把「扫哪一层」从**隐含**变成**显式**。三层口径：

    body(html)                 正文层 —— 剥 `<style>` ＋ HTML 注释。
                               词条浮层**保留**（它的 `<summary>` 是可见标签）。
    body_without_terms(html)   正文层再剥术语浮层 —— 用于「正文不得复述
                               词条口径」这类断言（丙2/U-03 的口径）。
    chrome(html)               样式层 —— 只取 `<style>` 内容，并**剥掉 CSS 注释**
                               （断言「CSS 里有这条规则」时用它）。
    raw(html)                  原始整页 —— 只有**结构断言**（纯 ASCII 标记，
                               如 `data-id=`、`f=action`、`<body>`）才可以用。

★★ 谁守这件事：`ci/guard_instrument_selfaudit.py` 的 **S48**（元判据）——
  对渲染产物做**文案断言**（左操作数可能含中文）时，右操作数**必须**是
  `page_caliber.body(...)` 或 `page_caliber.body_without_terms(...)`；
  裸变量、`raw()`、`chrome()` 一律报红（中文文案只能来自正文层）。

★ 位置纪律：本模块是**纯函数**（无 I/O、无全局态），判据与元判据都可 import。
"""
from __future__ import annotations

import re

#: 三层口径的名字（S48 按名字识别「这是显式口径调用」）。
LAYERS = ("raw", "body", "body_without_terms", "chrome")

#: **文案断言**（左操作数可能含中文）允许的口径 —— 只有正文层两种。
#: 中文文案不该来自 `<style>`（那是 CSS 注释）或整页原文（含注释/隐藏词条体）。
TEXT_LAYERS = ("body", "body_without_terms")

_STYLE_BLOCK = re.compile(r"<style\b[^>]*>.*?</style>", re.S | re.I)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
#: CSS 注释（`/* … */`）。**注释不是规则**（2026-10-13 U-16 实测教训）：
#:   我在 `inbox_server.py` 的 CSS 注释里复述过旧缺陷原文
#:   （`.term.mk>summary::after{content:none;display:none}`），判据用正则查
#:   真规则时被**自己写的说明文字**命中 ⇒ 假红。与 S48 同族（把非目标层
#:   当目标层）：剥除层必须连注释一起剥，否则"复述缺陷"本身就是误红源。
_CSS_COMMENT = re.compile(r"/\*.*?\*/", re.S)

#: 术语浮层（`<details class=term|gloss>` … `</details>`，含 0.48.5 乙1 的 `term mk`）。
#: 为什么能非贪婪：`glossary.render()` 只放行 b/code 两个内联标签，块内不嵌套 details。
#: ★ class 值有 `term mk` 形态（裸「？」芯片）—— 只认精确 `class="term"` 会漏剥整族。
_TERM_BLOCK = re.compile(
    r'<details class="[^"]*\b(?:term|gloss)\b[^"]*"[^>]*>.*?</details>', re.S)


def raw(html):
    """原始整页 —— **显式声明**「我要看整页」。只给结构断言（纯 ASCII 标记）用。"""
    return html or ""


def body(html):
    """正文层：剥 `<style>` 与 HTML 注释；术语浮层**保留**（其 summary 是可见标签）。"""
    h = _STYLE_BLOCK.sub("", html or "")
    return _HTML_COMMENT.sub("", h)


def body_without_terms(html):
    """正文层再剥术语浮层 —— 「正文不得复述词条口径」类断言用它。"""
    return _TERM_BLOCK.sub("", body(html))


def chrome(html):
    """样式层：只取 `<style>` 的内容，并**剥掉 CSS 注释**。

    ★★ 为什么剥注释（2026-10-13 U-16 实测踩到，不是推演）：
      我在 `inbox_server.py` 的 CSS 注释里复述过 C5 旧缺陷的原文
      （`.term.mk>summary::after{content:none;display:none}`），
      写判据时正则第一条就命中它 ⇒ **自己写的说明文字把自己误红**。
      注释不是规则：断言「CSS 里有/没有这条规则」时，注释必须不在场。
      （与正文层剥 HTML 注释同一个道理 —— S48 的同族，只是发生在样式层。）
    """
    return "\n".join(_CSS_COMMENT.sub("", blk)
                     for blk in _STYLE_BLOCK.findall(html or ""))


#: `reading_note()` 产物的**载入时刻**。自 0.50.4（Q-22）起该实现含
#: `载入于 HH:MM`（页面诚实声明"不随页面停留刷新"，就得给出这是哪一刻的快照）。
_NOTE_CLOCK = re.compile(r"载入于\s*\d{1,2}:\d{2}")


def note_text(s):
    """把口径行里的**载入时刻**归一（`载入于 10:23` → `载入于 <时刻>`）。

    ★★ 为什么必须归一（2026-10-16 实测伪红，不是推演）：
      0.50.4 给 `M.reading_note()` 加了**实时**载入时刻后，两条判据
      （0490 U-01 / 0470 S95）的写法是「渲染之后**再调一次**该函数去逐字比对」。
      渲染与比对是**两次独立读数**：跨分钟即不等 ⇒ 伪红。
      满载时单页渲染实测可达秒级 ⇒ 每 tab 约数 % 概率翻面。
      （铁律「一个时红时绿的量具比恒红的更坏」—— 这正是其作案现场。）
      ⇒ 真值只能是「**这一页渲染时真正产出的那一串**」的静态部分；
        时刻本身**不是**判据的断言对象（它就该随分钟变）。

    ★ 不变弱断言：归一只吃掉时刻，**静态文案仍须逐字来自唯一实现** ——
      页面若自造/回潮旧串（如「分母均为」），归一后照样不匹配 ⇒ 仍红。
      分辨力由 0490 的 N-U01b（只差时刻不得红）/ N-U01c（静态漂移必须红）守。
    """
    return _NOTE_CLOCK.sub("载入于 <时刻>", s or "")
