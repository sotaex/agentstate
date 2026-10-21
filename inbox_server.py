# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Antinel 监理 · 本地页（**只在你自己的电脑上开**）。

★★ 为什么必须本地：静态站跑在别人的服务器上，读不到你机器上的链。
  真正的"看"必须发生在**本机**，结果页也开在本机，**一个字节都不出本机**。

★ 安全范式（**照抄 `ui_server.py` 的既有纪律**，不另立一套）：
  1. **只监听回环**（`_check_bind` 硬校验，非回环直接抛错）；
  2. **一次性 token**（每次启动新生成，`hmac.compare_digest` 比对）；
  3. **Host 头校验**（防 DNS rebinding / 别的站点来问）；
  4. **零外部资源**（CSS/JS 全内联，页面不发起任何对外请求）；
  5. **全量转义**（所有动态内容走 `html.escape`，防注入）；
  6. **静态资源白名单**（只允许指定文件名，杜绝路径穿越）。

★ 判据不许二次实现：状态聚合调 `inbox_model`，日报调 `inbox_report.daily_report()`，
  账本调 `ledger.summary()`，态势调 `host_shield.guard_posture()` —— 页面只排版。

★★ 0.35.3 四条改动（创始人 2026-10-06 拍板，逐条对应）：
  ① 取消「标为已读」按钮（点开即自动已读，页内内联脚本）
  ② 窗口默认 **24 小时**（顶部那排数字与首屏口径）
  ③ **无后果的记录归档**（三档：要处理 / 看一眼 / 归档；"看一眼/归档"按类型归并）
  ④ **失守＝当前态势**（`guard_posture()` 现探）+ 失守时页面就地给「马上修复」
"""
from __future__ import annotations

import html
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import threading

#: markdown 加粗标记（**…**）。页面不解释 markdown ⇒ 必须在渲染前剥掉，
#: 否则审计链里任何旧版本写下的 `**` 都会原样露给用户（0.42.0 实测）。
_MD_STARS = re.compile(r"\*\*")
import time
import webbrowser
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import inbox_model as M
import inbox_report as R
import inbox_store as S
import glossary as GL
import ledger as L

DEFAULT_PORT = 8790
ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")

#: Windows：起子进程时**不新建控制台**。★ 0353 P12 专守这条 —— 哨兵/Antinel 监理
#: 是 `DETACHED_PROCESS` 拉起的（**没有控制台**），它们再起控制台程序
#: （netstat/tasklist/powershell…）时若不显式给这个标志，Windows 会**新建一个
#: 控制台** ⇒ 用户看到黑窗一闪。`host_shield`/`egress` 同款常量，不在本文件另立口径。
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
# ★ 2026-10-14（创始人实证「起得来、活不久」）：**app 窗口/紧急提醒窗的浏览器
#   必须与调用方进程树分离**。实测（两臂对照，同一台机同一条命令）：
#     命令内：窗口 t+0、t+5 都在；命令结束、下一个调用：窗口没了。
#   ⇒ Popen 只带 _CREATE_NO_WINDOW 时，msedge 挂在调用方（CLI／一次性
#     脚本／CI runner）进程树下 ⇒ 调用方一退出，进程树被连带清理，
#     窗口秒死 ⇒ `inbox window` 如实报「已就位」，然后窗口消失。
#   ★ 服务进程（`spawn_console`）一直是 DETACHED，所以服务活得久、
#     窗口活不久——同一个文件里两种寿命，这就是漏洞的形状。
#   DETACHED_PROCESS(0x8)｜CREATE_NEW_PROCESS_GROUP(0x200)：窗口与调用方
#   寿命解耦。与「关窗不停服务」是同一原则的反方向：调用方死，也不关窗。
_DETACHED_FLAGS = (_CREATE_NO_WINDOW | 0x00000008 | 0x00000200) if os.name == "nt" else 0

def _brand_favicon_rel():
    """`/assets/favicon.ico` 指向哪个文件 —— **从品牌图标唯一真源实时派生**。

    ★★★ 0.53.1（创始人 2026-10-19 截图「LOGO 又又又被改了，完整的LOGO呢」）：
      这一格原来是 `"favicon.ico": "icons/L0.ico"` —— 拿**姿态灯**当品牌标。
      而 `inbox_window.brand_icon_path()` 的注释里早就写着这条纪律：
      「状态灯是**会随态势变的**，拿来当品牌标等于把"当前没事"写进图标
        —— 那是假陈述。宁可没有图标。」
      纪律修在桌面快捷方式那条路上，favicon 这条路上**没修** ⇒ 修在一条腿上。
      → 后果不只是"图标不好看"：favicon 写死 L0 ⇒ **失守时标题栏仍显示值守灯**，
        等于对用户撒谎（而这正是本产品最不该犯的错）。
      → 复发机制：`B-15` 只守「链接同源」，**没守「解析到哪个文件」** ——
        一条腿绿了，另一条腿天然全绿。0.53.1 起补 `B-15b` 守解析结果本身。

    ★ 派生而不是再抄一份 `logo/antinel.ico`：抄了就是"一个事实两个来源"，
      换品牌文件时必然再次分叉 —— 那就是本条的复发机制本身。

    ★ 只在**请求时**调用（不在模块顶层）：顶层派生要把 `inbox_window` 拖进
      服务启动路径，重；而且服务已经跑起来之后 import 才不会碰循环导入。

    ★ 派生失败 ⇒ 回落**品牌**路径（不是 L0），并由判据钉住回落值与
      `inbox_window.BRAND_ICON_REL` 一致。
    """
    try:
        import inbox_window as _iw
        rel = str(_iw.BRAND_ICON_REL).replace("\\", "/")
        if rel.startswith("assets/"):
            return rel[len("assets/"):]
    except Exception:                                            # noqa: BLE001
        pass
    return "logo/antinel.ico"


# 允许对外提供的静态文件名（白名单 —— 杜绝路径穿越）
# ★ `favicon.ico` **刻意不在本表**：它不是「可按名请求的姿态资源」，而是
#   **品牌图标**。放进本表就意味着品牌标有了第二份来源（值抄一遍），
#   换品牌文件时必然分叉 —— 见 `_brand_favicon_rel()` 的说明。
ASSET_WHITELIST = {
    "L0.mp4": "logo/L0.mp4", "L1.mp4": "logo/L1.mp4", "L2.mp4": "logo/L2.mp4",
    "Ls.mp4": "logo/Ls.mp4", "R0.mp4": "logo/R0.mp4", "logo.svg": "logo/logo.svg",
    "L0.ico": "icons/L0.ico", "L1.ico": "icons/L1.ico", "L2.ico": "icons/L2.ico",
    "Ls.ico": "icons/Ls.ico", "R0.ico": "icons/R0.ico",
}
_MIME = {".mp4": "video/mp4", ".svg": "image/svg+xml", ".ico": "image/x-icon",
         ".png": "image/png"}

LEVEL_VAR = {"R0": "--r0", "L2": "--l2", "L1": "--l1", "Ls": "--ls", "L0": "--l0"}
#: 态短名（**派生**，不写第二份；真源＝`inbox_model.STATE_LABEL`，见 0372 S08）。
LEVEL_NAME = {k: M.state_short(k) for k in ("R0", "L2", "L1", "Ls", "L0")}

CSS = """
:root{--bg:#fff;--panel:#f6f8fa;--fg:#14212b;--muted:#465866;--line:#d6dee4;
--brand:#145a72;--brand-dark:#0f4559;--r0:#9b2226;--l2:#c2410c;--l1:#8a6100;
--ls:#2a5db0;--l0:#226b4a;
--sans:system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
--mono:ui-monospace,SFMono-Regular,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0f1417;--panel:#161d21;--fg:#e7edf1;
--muted:#9fb0bb;--line:#2a353b;--brand:#5fb4cf;--brand-dark:#8fd0e4}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 var(--sans)}
a{color:var(--brand)}
button{font:inherit;cursor:pointer}
/* ★ 0.50.4（Q-17/Q-18）：顶部条内边距 12px→9px —— 灯块在四个页签都渲染一
   遍，内容最少的「运行状态」页上它吃掉 61% 的可见文本量。压它的**留白**
   而不是删它的内容（灯的口径与词条落点一件不动）。 */
.bar{display:flex;align-items:center;gap:16px;padding:9px 20px;border-bottom:1px solid var(--line);background:var(--panel);flex-wrap:wrap}
.logo{width:48px;height:48px;border-radius:12px;overflow:hidden;background:#0a1a12;flex:none}
.logo video,.logo img,.logo svg{width:100%;height:100%;display:block;object-fit:cover}
/* ★ 0.48.5（交接件 §5.4 戊4）：状态词 16px 粗体（色随态，行内 style 走
   `M.STATE_VAR` —— 与 `.dot` 同一个真源）；解释句 13px 常规色 `var(--fg)`。
   旧形状是「词 17px  inherited 黑／解释 12px 灰」—— 信息量大的那句
   （为什么是这个态）被压成次要，权重倒挂；判据 U-15 锁旧声明不许回来。 */
.state b{font-size:16px;font-weight:700}
.state span{font-size:13px;color:var(--fg)}
.pill{display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid var(--line)}
.dot{width:8px;height:8px;border-radius:50%}
/* ★ 0.50.0（创始人「值守台应该有一个能漂浮的最小态……哨兵很多时候不要
   碍事，只要在，就行了」）：收缩入口。★★ 0.50.7（2026-10-16 创始人截图
   「左上角 LOGO 与右上角收缩钮是同一枚图形、两个入口」）起**合并进
   LOGO 本体** —— 点这枚动效哨标，Antinel 监理就收缩成屏幕上那枚漂浮哨标，
   所见即所得，不用猜符号；右上角那枚重复的 SVG 删除（全页只一枚
   lgmark，判据 J1 守）。判据 FLO-05 锁：入口在、用的是 `_logo_mark`
   （不是静态图）、title 说人话、POST 的是 `op=collapse`。
   ★ 按钮形态：全局 `button{font:inherit;cursor:pointer}` 已给手势；
     `*{box-sizing:border-box}` 已在位 ⇒ 内边距/边框归零后仍是 48px
     方框（`.logo` 的尺寸/圆角/深底照旧）；line-height:0 防空行盒撑高；
     hover 用 inset 阴影（不改布局，与旧 collbtn 的描边变体同效果）。 */
button.logo{padding:0;border:none;line-height:0}
button.logo:hover{box-shadow:inset 0 0 0 1px var(--brand)}
button.logo:focus-visible{outline:2px solid var(--brand);outline-offset:2px}
.collst{font-size:12px;color:var(--muted);margin-left:8px;align-self:center}
.spacer{flex:1}
/* ★ 0.48.5（交接件 §5.4 丁2/丁3）：顶部条右侧那个零信息量块连同类规则一起删
   （回环地址每台机器一样；另一半是口号不是证据）。证据搬到运行状态页的
   「监听地址」行，由 `_check_bind` 硬校验背书 —— 判据 U-10 同时断言
   删干净、证据在、后盾真。本注释刻意不复述被删的两串字面：判据扫的正是
   渲染产物，在这里写例子会自己踩自己（D-30 同款教训）。 */
.tabs{display:flex;gap:4px;padding:10px 20px 0;border-bottom:1px solid var(--line);flex-wrap:wrap}
.tabs a{padding:9px 14px;color:var(--muted);font-weight:600;text-decoration:none;border-bottom:2px solid transparent}
.tabs a.on{color:var(--brand);border-bottom-color:var(--brand)}
/* ★ 2026-10-21（TAB 切换卡顿根治·方案 E）：切页**细进度条**。2px、贴顶、
   随 var(--brand) 换色；`pointer-events:none` ⇒ 永不抢点击。JS 不可用
   （或没点 TAB）时 width 恒 0 ⇒ 什么都不显示，不是占位的假条。 */
.tabprog{position:fixed;top:0;left:0;height:2px;width:0;z-index:60;pointer-events:none;background:var(--brand)}
.tabprog.run{animation:tabprog 1.1s .05s ease-out forwards}
@keyframes tabprog{from{width:0}to{width:88%}}
main{max-width:1000px;margin:0 auto;padding:20px}
/* ★ 0.50.4（Q-17）：卡片内边距 14px→11px、卡片间距 12px→9px —— 日报页原先
   必须滚动才看得到「规则命中排行」和「有没有被改过」两张卡。 */
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:11px 16px;margin-bottom:9px}
h2{font-size:15px;margin:0 0 12px}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.filters a{padding:5px 11px;border-radius:999px;border:1px solid var(--line);font-size:12px;font-weight:600;color:var(--muted);text-decoration:none}
.filters a.on{background:var(--brand);border-color:var(--brand);color:#fff}
.item{border:1px solid var(--line);border-left-width:4px;border-radius:10px;margin-bottom:10px;background:transparent}
.item.r0{border-left-color:var(--r0)}.item.l2{border-left-color:var(--l2)}
.item.l1{border-left-color:var(--l1)}.item.ls{border-left-color:var(--ls)}
.item.done,.item.ignored{opacity:.55}
.badge{flex:none;width:44px;text-align:center;font-family:var(--mono);font-size:12px;font-weight:700;padding:4px 0;border-radius:6px;color:#fff}
.badge.r0{background:var(--r0)}.badge.l2{background:var(--l2)}
.badge.l1{background:var(--l1)}.badge.ls{background:var(--ls)}
/* ★★ 0.53.0（T3.3，设计 §14.3 第 3 条）：行内**工具徽标**——**只在观测到
   ≥2 个工具时**才渲染（单工具机器上每行都挂一个工具名＝几百次重复的噪声）。
   与 `.badge`（级别，等宽方牌、满色）刻意不同形：这是**归属**信息，浅边框
   胶囊、弱色，绝不抢级别的颜色。 */
.hbadge{flex:none;font-size:11px;font-weight:600;padding:1px 7px;border-radius:999px;
  border:1px solid var(--line);color:var(--muted);margin-left:6px;white-space:nowrap}
/* ★★ 0.51.0（规格 v1.2 §2.4）：**并存徽标**（研发中／缺粮）—— 与主灯**不争位**、
   可多枚常驻同屏。★ 用纯 `span`（不接 `GL.chip()` 的「？」芯片）：芯片数量是
   全站被逐个数过的锚（0490 U-04 / 0514 J1），徽标是**条件出现**的，加芯片会让
   那个"数量"随之浮动、锚点当场失效；解释改由 `title` 承担。 */
.badges{display:inline-flex;gap:4px;margin-left:6px;vertical-align:middle}
.bdg{font-size:11px;font-weight:700;padding:1px 7px;border-radius:999px;
  border:1px solid currentColor;font-family:inherit}
.bdg.dev{color:var(--brand)}
.bdg.granary{color:var(--ls)}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px}
/* ★ 0.50.4（Q-17）：同上，数字卡内边距 14px→11px。 */
.metric{background:var(--panel);border-radius:10px;padding:11px}
.metric .k{font-size:12px;color:var(--muted)}
.metric .v{font-size:26px;font-weight:700}
.metric a{text-decoration:none}
/* ★ 0.51.0（品质审查拍板点 1）：四卡撤分母后，单位「条／件」小号灰显跟上 ——
   单位可见（U-08 立意），但不与数字抢 26px 的视觉权重。 */
.metric .unit{font-size:13px;font-weight:600;color:var(--muted)}
/* ★ 0.51.0（拍板点 3）：排行行规则号**上屏**（索引位）—— 与问号全表
   `.tdef .rrow .rid` 同一视觉语言；收件箱记录「规则 SEC-01」能对号入座。
   ★★ 0.53.4（创始人 2026-10-20 截图：「规则代号是否放在前边更好？不要那么小，
   字号大一些，跟旁边一样大」）：规则号**移到短名之前**（前缀位，与收件箱
   「规则 SEC-01」同序），字号 11px→13px（＝`.row` 正文字号，不再淡小），
   颜色收回正文色（放前面就是主显示的一部分，不是脚注）。
   间距 margin-left→margin-right：它在前面，后面跟文字。 */
.rows .rid{display:inline-block;min-width:52px;margin-right:8px;
  font-family:var(--mono);font-size:13px;font-weight:400;color:inherit}
/* ★ 0.53.4（创始人 2026-10-20 截图：日报两卡「右边大片空缺，左边有的都挤得
   换行了」）：`.k` 原写死 width:150px ⇒ 含编号/长标签的行**内部换行**，
   值被孤零零留在行尾（左两行、右一截，中间一大片空）。
   ⇒ label 按内容撑开（basis:auto，放得下就不换行；极端窄才退化），
   值列紧随其后（flex:1;min-width:0 ⇒ 长值自己换行，不反挤 label）。
   只给日报两卡（`.rows.fit`）—— 其他页保持 150px 对齐列，不外溢。 */
.rows.fit .row .k{flex:0 1 auto;width:auto;min-width:0}
.rows.fit .row>span:last-child{flex:1 1 auto;min-width:0}
/* ★ 0.53.4：行内「圈问号」—— **本次数据**的总结说明（不是术语词条：词条答
   "这是什么"，它答"这次是什么"）。徽章与 `.term` 的「？」**同一种形状**
   （14×14 圆、10px、写死字号，U-16 立意），不进 name="term" 互斥组。
   ★★ 0.53.4 二次修订：第二形态 `.qinfo` —— 答"**这类东西是什么**"（记录的
   来龙去脉），与 `.qsum`（答"这一次是些什么"）**同形不同义**。两者共用同
   一套样式规则（形状必须一致，否则同屏两种问号），但**类名分开**：
   判据各锁各的落点，混用一个类会让"问号答错了问题"这条永远查不出来。 */
.qsum,.qinfo{display:inline-block;position:relative;vertical-align:baseline;margin-left:6px}
.qsum>summary,.qinfo>summary{cursor:pointer;list-style:none;display:inline-block;width:14px;height:14px;
  font-size:0;line-height:0;color:transparent;letter-spacing:0}
.qsum>summary::-webkit-details-marker,.qinfo>summary::-webkit-details-marker{display:none}
.qsum>summary::after,.qinfo>summary::after{content:"？";position:absolute;top:0;left:0;
  width:14px;height:14px;line-height:14px;text-align:center;border-radius:50%;
  background:var(--line);color:var(--muted);font-size:10px;font-weight:700}
.qsum[open]>summary::after,.qinfo[open]>summary::after{background:var(--brand);color:#fff}
/* ★ 落点不在这里：`top/left` 只是**无 JS 时的兜底**（会停在页顶）。真定位由
   `_FLIP_JS` 的 `fit()` 现算 —— 与术语词条 `.tdef` **同一段代码、同一把尺子**
   （0.53.4 四次修订：旧版 fit 只认 `.tdef`，于是 `.qbody` 永远停在 top:8px，
   用户看到的就是「说明框弹到天花板上」）。 */
.qsum>.qbody,.qinfo>.qbody{position:fixed;z-index:60;top:8px;left:8px;right:auto;width:max-content;
  max-width:min(560px,calc(100vw - 16px));min-width:min(260px,calc(100vw - 16px));
  max-height:calc(100vh - 16px);overflow:auto;
  margin:0;padding:12px 14px;font-size:12.5px;line-height:1.75;color:var(--fg);
  background:var(--bg,#fff);border:1px solid var(--line);border-left:3px solid var(--brand);
  border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.16);font-weight:400;
  white-space:normal;text-align:left}
/* ---- 0.36.1：术语词条改成**浮层**（创始人截图三）----
   ★ 原形状的病：`.term{display:inline}` 把详情块塞进 `.metrics` 的
     140px 窄格里 ⇒ 展开后宽度只有卡片那么宽 ⇒ 中文逐字换行，
     变成一条极细长、极难读的竖条（用户实测截图三）。
   ⇒ 改法：词条本体仍是 `<summary>` 小标签；展开内容**脱离文档流**，
     用 `position:absolute` 浮在页面之上，宽度取 `min(560px, 视口-32px)`
     —— 窄面板里也能正常成段阅读。
   ★ 为什么不用 `position:fixed`：会脱离滚动容器，长页面展开时飘在别处。
   ★ 关闭行为交给原生 `<details>`（点外面不关；点开别的词条会收起上一个）。
     ★★ 0.50.4 更正＋补机制：0.36.1 写下这句时**机制并不存在** —— HTML 的
     同名 details 从未自动互斥，那是把愿望写成了事实（创始人 2026-10-15
     实测多开叠压）。真机制是 WHATWG `<details name>` **原生互斥手风琴**
     （Edge 120+，2023-12）：`glossary.chip()` 现给每颗芯片带
     `name="term"`，由判据 **U-19** 钉住。 */
.term{position:relative;display:inline-block}
.term>summary{cursor:pointer;list-style:none}
.term>summary::-webkit-details-marker{display:none}
.term>summary::after{content:"？";display:inline-block;margin-left:3px;
  width:14px;height:14px;line-height:14px;text-align:center;border-radius:50%;
  background:var(--line);color:var(--muted);font-size:10px;font-weight:700}
.term[open]>summary::after{content:"？";background:var(--brand);color:#fff}
/* ★ 0.48.5（交接件 §5.6 乙1）：裸「？」芯片（mk）—— summary 自带一个「？」，
   ::after 徽章再补一个就成「？？」⇒ mk 形态**隐藏 summary 自身的字**，
   徽章照旧渲染 ⇒ 全站「？」**同一种形状**（14×14 圆、10px、写死字号）。
   ★★ 2026-10-13 修（C5，本轮自己引入的缺陷）：上一版写成
   `.term.mk>summary::after{content:none;display:none}` —— **把徽章整个关掉**，
   于是 8 个新落点退化成**裸文字「？」**（无圆圈、字号继承所在容器：
   药丸 12px／顶部灯 16px 粗体／筛选条 12px），与页内原有的
   「词名＋小圆徽章」**同屏两种形状**。实测：日报 8+4／运行状态 4+4／
   账本 7+4 三种页面并存。创始人判定「原先更小又有圆背景的更好」，
   **且交接件 §5.6 定稿写的本就是"summary 只渲染 CSS 的「？」徽章"**
   —— 是实现比定稿多做了一步。⇒ 现在改回定稿意图：字隐藏、徽章保留。
   ★ 为什么用 `font-size:0` 而不是 `color:transparent`：后者只让字看不见，
   仍占宽度 ⇒ 「？」与徽章之间会多出一个字距空洞。`::after` 自带
   `width/height/font-size`，不受父级 0 字号影响。 */
.term.mk>summary{font-size:0;line-height:0;color:transparent;letter-spacing:0}
.tdef{position:absolute;z-index:60;top:calc(100% + 6px);left:0;
  width:max-content;max-width:min(560px,calc(100vw - 16px));min-width:min(260px,calc(100vw - 16px));
  max-height:calc(100vh - 16px);overflow:auto;
  margin:0;padding:12px 14px;font-size:12.5px;line-height:1.75;color:var(--fg);
  background:var(--bg,#fff);border:1px solid var(--line);border-left:3px solid var(--brand);
  border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.16);font-weight:400;
  white-space:normal;text-align:left}
/* ★ 0.50.3 截图复发：浮层只能翻边不能保证完整。统一用视口坐标定位，
   即使词条贴近视口中部、浮层比左侧余量宽，也不会按锚点右对齐后跑到屏幕外。 */
.term>.tdef{position:fixed;top:8px;left:8px;right:auto;width:max-content;
  max-width:min(560px,calc(100vw - 16px));min-width:min(260px,calc(100vw - 16px));
  max-height:calc(100vh - 16px);overflow:auto}
/* 表单动作回执：让「马上修复/试一下」的结果就地可见，而不是只落在后台 stdout。 */
.notice{margin:0 0 12px;padding:10px 12px;border:1px solid var(--line);
  border-left:4px solid var(--brand);border-radius:8px;background:var(--panel);color:var(--fg)}
/* 旧 flipx 类保留为兼容标记；定位由 _FLIP_JS 用固定视口坐标统一计算。 */
.term.flipx>.tdef{left:8px;right:auto}
/* 0.50.6：术语词条的补充行（原「包含/不含/口径」三行徽章退场 ——
   创始人「能大白话就大白话，用户体验第一」）。无标签，内容自己会说话；
   顺序由 glossary.chip() 保证：先说"有什么"，再说"不是什么"，最后说"怎么数"。 */
.tsup{margin-top:6px;padding-top:6px;border-top:1px dashed var(--line);color:var(--fg)}
.tsup:first-of-type{margin-top:8px}
.tdef b{color:var(--brand)}
/* ★ 0.51.0（四态问号小窗）：拦截词条内的规则全表（嵌套折叠）。**不带
   name 属性** —— 不是术语芯片，不进 name="term" 互斥组；展开体自带限高
   滚动，外层小窗不被 37 行撑爆。规则编号淡显等宽，供与收件箱记录上的
   「规则 SEC-01」对号入座（索引位；0.50.4 Q-04 退编号的是日报排行主显示位，
   职责不同）。 */
.tdef .rlist{margin:6px 0 0 0;font-size:12px}
.tdef .rlist>summary{cursor:pointer;list-style:none;color:var(--muted);user-select:none}
.tdef .rlist>summary::-webkit-details-marker{display:none}
.tdef .rlist>summary::before{content:"\\25be  "}
.tdef .rlist[open]>summary::before{content:"\\25b4  "}
.tdef .rbody{margin-top:4px;max-height:45vh;overflow:auto;
  border-top:1px dashed var(--line);padding-top:4px}
.tdef .rrow{padding:1px 0}
.tdef .rrow .rid{display:inline-block;min-width:56px;
  font-family:var(--mono);font-size:10px;color:var(--muted)}
/* 「账本存在哪个文件里」这类**补充细节**：默认收起，不占版面 */
details.where{margin-top:8px;font-size:12px;color:var(--muted)}
details.where>summary{cursor:pointer;list-style:none}
details.where>summary::-webkit-details-marker{display:none}
details.where>summary::before{content:"\\25be  "}
details.where[open]>summary::before{content:"\\25b4  "}
details.where>.tdef{position:static;width:auto;min-width:0;max-width:none;
  margin-top:6px;padding:10px 12px;background:var(--panel);border:1px solid var(--line);
  border-radius:8px;box-shadow:none;color:var(--fg)}
details.where code{font-family:var(--mono);font-size:11.5px;word-break:break-all}
@media (max-width:620px){
  .tdef{max-width:calc(100vw - 16px);min-width:min(260px,calc(100vw - 16px));
    max-height:calc(100vh - 16px);font-size:12px;line-height:1.7}
  .term{width:100%}
  .term>.tdef,.term.flipx>.tdef{left:8px;right:auto;width:max-content}
}
.rows{border:1px solid var(--line);border-radius:10px;overflow:hidden}
/* ★ 0.50.4（Q-17）：行高 11px→8px（原先一行约 55px，四张卡就把日报页
   顶出了首屏；压完日报首屏能同时见到四张数字卡与当日合计）。 */
.row{display:flex;gap:12px;padding:8px 15px;border-bottom:1px solid var(--line);font-size:13px}
.row:last-child{border-bottom:0}
.row .k{flex:none;width:150px;color:var(--muted)}
.ok{color:var(--l0);font-weight:700}.warn{color:var(--l1);font-weight:700}.bad{color:var(--r0);font-weight:700}.neutral{color:var(--muted);font-weight:700}.dev{color:var(--brand);font-weight:700}
.empty{text-align:center;padding:40px;color:var(--muted)}
.note{font-size:12px;color:var(--muted)}
/* ★ 0.50.7（创始人截图二「失守后换行」）：灯的五态枚举的原子单元 ——
   每个态包一层 span 且 nowrap，窄面板下也只会在态与态之间的「·」处
   折行，绝不再把「失守」「拦截」这类短词切成一截。
   ★ 0.53.3：改名 —— 它描述的是页面上**这一行**（对外），不是内部灯态
     表；叫错会让后来的人以为页面上应该有六个（创始人原话：研发态只是
     内部用，不用告诉用户，用户是没有这个态的）。 */
.sixit{white-space:nowrap}
.unread-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--brand);margin-right:6px;vertical-align:middle}
/* ---- 0.35.3：三档 + 可展开卡片（创始人 2026-10-06 四条意见）---- */
.fixbtn{border:1px solid var(--r0);background:var(--r0);color:#fff;border-radius:8px;
  padding:7px 13px;font-weight:700;font-size:13px}
.fixbtn:hover{filter:brightness(1.08)}
/* 失守但**就地修不了**时，给一条「怎么解决」（不是按钮 —— 点了没用的按钮就是假按钮） */
.fixnote{font-size:12px;line-height:1.5;max-width:420px;color:var(--fg);
  border-left:3px solid var(--r0);padding:4px 10px;background:rgba(220,60,60,.07);border-radius:6px}
.fixnote b{color:var(--r0)}
.cons{font-size:12px;line-height:1.6;max-width:560px;color:var(--fg);
  border-left:3px solid var(--r0);padding:4px 10px;background:rgba(220,60,60,.07);border-radius:6px}
.cons b{color:var(--r0)}
.cons ul{margin:2px 0 0;padding-left:18px}
.cons li{margin:1px 0}
.pill.sm{font-size:11px;padding:2px 8px}
a.pill{text-decoration:none}
details.item{display:block;padding:0}
details.item>summary{display:flex;gap:12px;align-items:center;padding:12px 15px;
  cursor:pointer;list-style:none}
details.item>summary::-webkit-details-marker{display:none}
details.item>summary::after{content:"\\25be";color:var(--muted);font-size:12px;flex:none}
details.item[open]>summary::after{content:"\\25b4"}
details.item>summary .t{flex:1;min-width:0;font-weight:700;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
details.item .when{flex:none;color:var(--muted);font-size:12px;font-family:var(--mono)}
details.item .det{padding:0 15px 14px 71px}
details.item .det .m{font-size:12px;color:var(--muted);word-break:break-word;margin:6px 0 0}
details.item .act{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}
details.item .act button,details.item .act a.btn{border:1px solid var(--line);
  background:transparent;color:var(--fg);border-radius:7px;padding:6px 13px;font-size:12px;
  text-decoration:none;display:inline-block}
details.item .act button.ok{border-color:var(--l0);color:var(--l0);font-weight:700}
details.grp>summary .t{font-weight:600}
/* ---- 0.36.0：失守归因面板（「为什么 & 怎么办」按钮展开的内容）----
   ★ 存在的理由（创始人 2026-10-07）：「要让用户知道是什么原因造成了这个失守，
     有什么办法能解决，如果没办法，如何做到不造成实际损失，
     总之要让用户能有机会不断改进，**不能无法改进，只能看**。」
   ⇒ 一个只能看的失守就是产品失败。面板固定四段：根因／多严重／能做什么／代价。 */
details.rem[open]>summary .t{color:var(--r0)}.rem{border:1px solid var(--line);border-radius:8px;margin:10px 0 0;background:var(--panel)}
/* ---- 0.51.0：账本明细（银行流水模式：最近 7 天 ＋ 更早按月折叠）----
   月行用原生 <details>（与词条芯片同款互斥思路的行内版：多开无害，不进 term 组）。
   无记录的天/月整体淡显（.dim）—— 「没查」≠「查过没事」，不许渲染成 0。 */
.row.dim{color:var(--muted)}
.row.dim .k{color:var(--muted)}
details.month{display:block;border-bottom:1px solid var(--line)}
details.month:last-child{border-bottom:0}
details.month>summary{display:flex;gap:12px;align-items:baseline;padding:9px 15px;
  cursor:pointer;list-style:none;font-size:13px}
details.month>summary::-webkit-details-marker{display:none}
details.month>summary::after{content:"\\25be";color:var(--muted);font-size:12px;
  flex:none;margin-left:auto}
details.month[open]>summary::after{content:"\\25b4"}
details.month>summary .k{flex:none;color:var(--muted)}
details.month[open]>summary{border-bottom:1px solid var(--line)}
details.month>.rows{border:0;border-radius:0}
.rem>summary{display:flex;gap:10px;align-items:center;padding:8px 12px;cursor:pointer;
  list-style:none;font-size:13px}
.rem>summary::-webkit-details-marker{display:none}
.rem>summary::after{content:"\\25be";color:var(--muted);font-size:11px;flex:none}
.rem[open]>summary::after{content:"\\25b4"}
.rem>summary .why{font-weight:700;color:var(--r0)}
.rem .body{padding:0 12px 12px;font-size:13px;line-height:1.65}
.rem .seg{margin:10px 0 0;padding:9px 11px;border-radius:8px;background:var(--bg);
  border-left:3px solid var(--line)}
.rem .seg.root{border-left-color:var(--r0)}
.rem .seg.sev{border-left-color:var(--r1)}
.rem .seg.act{border-left-color:var(--brand)}
.rem .seg h4{margin:0 0 4px;font-size:12px;color:var(--muted);font-weight:700;
  text-transform:none}
.rem .seg p{margin:0}
.rem .seg .note{font-size:11px;color:var(--muted);margin-top:5px}
/* ★ 0.53.0 T4：动作行（原 `<ol><li>` 编号制）—— 编号是自问自答，
   按钮本身就是祈使句，说一遍"你能做什么"是同义重复 ⇒ 换成普通行块。 */
.rem .arow{margin:9px 0 0}
.rem .arow>b{display:block;font-size:12px;color:var(--muted)}
.rem .arow .why{font-size:12px;color:var(--muted);margin-top:2px}
.rem .bclass{display:inline-block;font-size:11px;padding:2px 8px;border-radius:99px;
  background:rgba(220,60,60,.12);color:var(--r0);border:1px solid var(--r0);
  margin-left:8px;white-space:nowrap}
.rem .pick{display:flex;gap:8px;flex-wrap:wrap;margin-top:7px}
.rem .pick button{border:1px solid var(--line);background:transparent;color:var(--fg);
  border-radius:7px;padding:5px 12px;font-size:12px}
.rem .pick button.go{border-color:var(--l0);color:var(--l0);font-weight:700}
.rem .pick button.drop{border-color:var(--l1);color:var(--l1)}
.rem .pick button.risk{border-color:var(--r0);color:var(--r0)}
.rem .why{color:var(--muted);font-size:12px;line-height:1.55;margin-top:4px}
/* 0.36.0：窄面板（520px）下指标卡与详情必须收窄，否则一行放不下、字被挤断 */
@media (max-width:620px){
  .metrics{grid-template-columns:repeat(auto-fit,minmax(104px,1fr));gap:8px}
  .metric{padding:10px}.metric .v{font-size:21px}
  .row .k{width:104px}
  details.item .det{padding-left:15px}
  main{padding:12px}
}
/* 禁用态按钮（规格 §5.6「认领到账号（未启用）」）：必须**看起来**就是点不动，
   而不是一个长得能点、点了没反应的按钮 —— 后者是最典型的「看见疑问无法得到答案」。 */
button[disabled]{opacity:.55;cursor:not-allowed;border-style:dashed !important;
  border-color:var(--line) !important;color:var(--muted) !important}
/* 顶部口径说明：它必须**小而弱** —— 它的作用是消歧，不是抢注意力。 */
/* ★ 0.48.5（交接件 §5.4 丙1）：`.unit` 原先只给 `.pill` 准备、零使用；
   筛选条的单位可见化复用它（件/条小字紧跟数字），一处定义两处受益。 */
.pill .unit,.filters .unit{opacity:.6;font-size:11px;margin-left:4px}
.sect{margin:22px 0 10px;font-size:13px;color:var(--muted);font-weight:700}
.hint{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:14px 16px;margin-bottom:14px;font-size:13px}
.hint b{font-size:15px}
/* ---- 0.36.1：术语词条的呈现规则已上移到 `.metrics` 附近（浮层方案）。
   ★ 这里原有的 `.term{display:inline}` + `.tdef{display:block}` 一组已**删除** ——
     正是它把详情块压进 140px 的卡片窄格、逼成逐字换行的细长条
     （创始人 2026-10-07 截图三）。留在后面还会**覆盖**新规则。 */
.gloss{margin:0 0 12px;font-size:12px}
.gloss>summary{cursor:pointer;color:var(--brand);font-weight:600;list-style:none;
  display:inline-block}
.gloss>summary::-webkit-details-marker{display:none}
.gloss>summary::before{content:"\\25be  "}
.gloss[open]>summary::before{content:"\\25b4  "}
/* 「一行式术语入口」里的详情块**不浮起**：它本来就在正常文档流里、
   独占整行，浮起来反而会遮住下面的内容。 */
.gloss>.tdef{padding:10px 13px;background:var(--panel);border:1px solid var(--line);
  border-radius:8px;margin-top:6px;position:static;width:auto;min-width:0;
  box-shadow:none;max-width:none}
.gloss>.tdef{padding:10px 13px;background:var(--panel);border:1px solid var(--line);
  border-radius:8px;margin-top:6px}
.trow{padding:5px 0;border-bottom:1px dashed var(--line)}
.trow:last-child{border-bottom:0}
"""

#: ★ 0.53.0（T0）：体检页（第五 TAB）专用样式。**为什么单开一份**：体检正文是
#:   `ui_server._result_html` 的产物（唯一实现，禁第二份渲染），它用的类名
#:   （blind/warn/tiles/row/pt/ev/fold/evo…）与本站有**真实冲突** ——
#:   `.row` 本站是「标签+值」横排、体检是逐条堆叠；`.warn` 本站是文字色、
#:   体检是提示盒。整份灌进来会互相污染 ⇒ 一律 `.exam` 作用域移植，
#:   本站全局规则一字节不动（非必要不能动）。
EXAM_CSS = """
.exam .blind{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:12px 0}
.exam .warn{background:#fff8e6;border:1px solid #f0d38a;border-radius:10px;padding:12px 14px;margin:12px 0;color:var(--fg)}
.exam .err{background:#fdecec;border:1px solid #f0b4b4;border-radius:10px;padding:12px 14px;margin:12px 0;color:#8a1f1f}
.exam .guide{background:var(--panel);border:1px solid var(--brand);border-radius:10px;padding:12px 14px;margin:0 0 12px}
.exam .muted{color:var(--muted)}
.exam .small{font-size:12px}
.exam .tiles{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0 4px}
.exam .tile{flex:1 1 168px;min-width:168px;border:1px solid var(--line);border-radius:10px;padding:12px 14px;background:var(--bg)}
.exam .tile .n{font-size:24px;font-weight:600;line-height:1.2}
.exam .tile .t{font-size:14px;font-weight:600;margin-top:2px}
.exam .tile .d{font-size:12px;color:var(--muted);margin-top:4px;line-height:1.45}
.exam .row{border-top:1px solid var(--line);padding:10px 0;display:block}
.exam .row .nm{font-weight:600}
.exam .row .pt{font-size:12px;color:var(--muted);word-break:break-all;margin-top:2px}
.exam .row .ev{font-size:13px;margin-top:5px}
.exam .tag{display:inline-block;font-size:12px;padding:1px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted);background:var(--panel);margin-left:8px}
.exam .ev{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:12px 14px;margin-top:8px}
.exam .ev .l1{font-size:14px;line-height:1.7}
.exam .ev .mean{font-size:13px;color:var(--fg);background:var(--bg);border-radius:7px;padding:9px 11px;margin-top:10px;line-height:1.65}
.exam .orig{font-size:11px;margin-top:7px;word-break:break-all;color:var(--muted)}
.exam .nums{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.exam .num{flex:1 1 108px;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:7px 10px}
.exam .num .k{font-size:11px;color:var(--muted)}
.exam .num .v{font-size:14px;font-weight:500;margin-top:2px;word-break:break-all}
.exam .one{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 11px;margin-top:10px;font-size:14px}
.exam details.fold{margin-top:11px}
.exam details.fold>summary{cursor:pointer;font-size:13px;color:var(--brand);user-select:none;padding:5px 0}
.exam details.fold>summary:hover{text-decoration:underline}
.exam table.evo{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px;table-layout:fixed}
.exam table.evo th{text-align:left;color:var(--muted);font-weight:500;padding:5px 7px;border-bottom:1px solid var(--line);font-size:11px}
.exam table.evo td{padding:5px 7px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-all}
.exam table.evo td.kd{width:9%;color:var(--muted);font-size:11px}
.exam table.evo td.kp{width:33%;font-family:var(--mono);font-size:11px;color:var(--muted)}
.exam table.evo td.tm{width:17%;color:var(--muted);font-size:11px;white-space:nowrap}
.exam table.evo tr.mark td{background:#fffafa}
.exam code{background:var(--panel);border-radius:4px;padding:1px 5px;font-size:13px}
.exam hr{border:0;border-top:1px solid var(--line);margin:20px 0}
/* 2026-10-21 体检页优化（创始人拍板 A1/B/C）：汇总卡／分组／紧凑行／锚点条 */
.exam .sum{border-left:4px solid var(--brand);background:var(--bg)}
.exam .sum .sumh{font-size:16px;font-weight:600;margin-bottom:6px}
.exam .sum .sumline{font-size:15px;line-height:1.7;margin-bottom:4px}
.exam .grp{margin-top:4px}
.exam .gh{font-size:14px;font-weight:600;margin:16px 0 2px}
.exam .crow{border-top:1px solid var(--line);padding:7px 0}
.exam .crow .nm{font-weight:500}
.exam .jump{background:var(--bg);border:1px solid var(--line);border-radius:10px;
 padding:9px 14px;margin:14px 0 4px;font-size:13px}
.exam .jump a{color:var(--brand);text-decoration:none;margin:0 2px}
.exam .jump a:hover{text-decoration:underline}
.exam .lnk{background:none;border:0;color:var(--brand);font-size:13px;cursor:pointer;
 padding:2px 6px}
.exam .lnk:hover{text-decoration:underline}
"""

#: ★★ 0.50.3：术语浮层按**视口坐标**完整落位，不是「溢出右边就翻到左边」。
#:   旧法只看 `r.right` 并给 `.flipx` 加 `right:0`：锚点在视口中部、浮层宽于
#:   锚点左侧余量时，右对齐会把整个浮层推到视口左边之外（2026-10-14 截图）。
#:   新法：按视口最大宽高约束内容，再用实际 DOM 几何量 clamp x/y；下方放不下
#:   先尝试上方，否则夹在视口内并由浮层自身滚动。滚动/缩放时重算。
#:   唯一定位口径是浏览器实际 `getBoundingClientRect()`，判据不另写一套布局公式。
_FLIP_JS = """
<script>
(function(){
  var PAD = 8;
  function clamp(v, lo, hi){ return Math.max(lo, Math.min(v, Math.max(lo, hi))); }
  // ★★ 0.53.4 四次修订（创始人 2026-10-20 13:04 截图：「点击 150 后边的问号时，
  //   说明框弹出到天花板上了，位置不对」）：浮层的**体**有两种 —— 术语词条
  //   `.tdef`、行内圈问号 `.qbody`。旧版只认 `.tdef`，`.qbody` 因此从来没被
  //   定位过，停在自己 CSS 里那个写死的 `top:8px` 上（＝天花板），与锚点毫无
  //   关系。⇒ 定位**只有这一份实现**：谁打开就量谁，两种体走同一段坐标计算。
  //   新增浮层只加类名到这里，不许再写第二套坐标（第二套必然漂）。
  function boxOf(d){
    return d.querySelector('.tdef') || d.querySelector('.qbody');
  }
  // ★★ 同一张截图里的第三个问题（「之前的问号说明框不会关掉」）：术语词条靠
  //   `<details name="term">` 原生手风琴互斥，`.qsum`／`.qinfo` **刻意不进**
  //   那个组（它们不是词条，U-19/T-09 分得很清）⇒ 三类之间没有任何互斥，
  //   于是能叠一屏。⇒ 互斥也收成一份实现：**同屏最多一个浮层**，开一个就关掉
  //   其它所有（三类同一口径）。按类名判断，新增浮层照样覆盖。
  function overlays(){
    return document.querySelectorAll(
      'details.term[open],details.qsum[open],details.qinfo[open]');
  }
  function fit(d){
    if (!d.classList) return;
    var box = boxOf(d);
    var anchor = d.querySelector('summary');
    if (!box || !anchor) return;
    var root = document.documentElement;
    var vw = root.clientWidth, vh = root.clientHeight;
    if (!vw || !vh) return;
    // fixed 定位以视口为坐标原点；先放到安全点再量真实宽高。
    box.style.left = PAD + 'px';
    box.style.top = PAD + 'px';
    var r = box.getBoundingClientRect();
    var a = anchor.getBoundingClientRect();
    var left = clamp(a.left, PAD, vw - r.width - PAD);
    var below = a.bottom + 6;
    var above = a.top - r.height - 6;
    var top;
    if (below + r.height <= vh - PAD) top = below;
    else if (above >= PAD) top = above;
    else top = clamp(below, PAD, vh - r.height - PAD);
    box.style.left = left + 'px';
    box.style.top = top + 'px';
  }
  function fitOpen(){
    overlays().forEach(fit);
  }
  document.addEventListener('toggle', function(e){
    var d = e.target;
    if (!d.classList || !d.open) return;
    var isOverlay = d.classList.contains('term') ||
                    d.classList.contains('qsum') ||
                    d.classList.contains('qinfo');
    if (!isOverlay) return;
    overlays().forEach(function(o){ if (o !== d) o.open = false; });
    fit(d);
  }, true);
  window.addEventListener('resize', fitOpen);
  window.addEventListener('scroll', fitOpen, true);
  if (document.readyState === 'loading')
    document.addEventListener('DOMContentLoaded', fitOpen);
  else
    fitOpen();
})();
</script>
"""

#: 点开即已读（创始人拍板①：取消「标为已读」按钮）。
#  ★ 内联脚本，零外部资源；JS 不可用时只是少一次"已读"记录，**不影响任何功能**
#    （"未处理"只看 done/ignored，不看 read）。
_READ_JS = """
<script>
document.addEventListener('toggle', function(e){
  var d = e.target;
  if (!d.classList || !d.classList.contains('item') || !d.open) return;
  if (d.dataset.readed === '1') return;
    d.dataset.readPending = '1';
  var t = d.dataset.token, id = d.dataset.id, ids = d.dataset.ids;
  if (!t || (!id && !ids)) { delete d.dataset.readPending; return; }
  var body = 't=' + encodeURIComponent(t) + '&op=read';
  body += ids ? ('&ids=' + encodeURIComponent(ids))
              : ('&id=' + encodeURIComponent(id));
  fetch('/action', {method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded',
             'X-Antinel-Read':'1'}, body:body})
    .then(function(r){
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    })
    .then(function(j){
      if (!j || !j.ok) throw new Error('read rejected');
      d.dataset.readed = '1';
      delete d.dataset.readPending;
      var x=d.querySelector('.unread-dot'); if(x) x.remove();
    })
    .catch(function(){ delete d.dataset.readPending; });
}, true);
</script>
"""


# ------------------------------------------------------------- 安全 ----
def _check_bind(addr):
    """★ 只允许回环。非回环 ⇒ 抛错（判据 J6 的落点）。"""
    if str(addr) not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("本地页只允许监听回环地址，拒绝绑定 %r" % (addr,))


#: ★★ 0.48.6（遗留问题 B3）：口令的 **cookie 名**。
#:   首字节带 `?t=` 的那次响应下发一个 httpOnly cookie，此后站内**所有**
#:   导航与子资源都靠它 —— URL 里不再出现口令（浏览器历史 / Referer /
#:   地址栏 / 截图 都干净）。旧 URL（`/?t=…`）**继续可用**（维八：不破旧账）。
_COOKIE = "antinel_t"


def _cookie_token(cookie_header):
    """从 `Cookie:` 头里取口令。

    ★ 取不到 ⇒ 返回 `""`（空串），**不是 `None`** —— 调用方只关心"有没有"，
      与 `_guard` 里 `q.get("t") or …` 的短路链天然对齐。
    ★ 只做**取值**，不做比对：口令比对永远只有 `_guard` 一处（维一 · 入口唯一）。
    """
    for part in (cookie_header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == _COOKIE:
            return v
    return ""


def _esc(s):
    return html.escape("" if s is None else str(s), quote=True)


def _zh_num(n):
    """数字 → 中文小写（0–10），超范围退回阿拉伯数字。

    ★★ 存在的理由（机制层，创始人 2026-10-17「这个能上升到机制层就好了」）：
      页面文案里的**指向性数量词**（「下列四个数」）必须能**派生**自结构；
      中文文案写「四个」比「4 个」自然 ⇒ 派生需要一个「数 → 中文」转换。
      手抄数量词与结构脱钩是**必然出错**的结构（账本页三问之一的成因），
      所以这个函数是「数量词派生」纪律的配套件，不是排版偏好。
    """
    zh = "零一二三四五六七八九十"
    n = int(n)
    return zh[n] if 0 <= n <= 10 else str(n)


def _ts_hm(s):
    """时间戳的**唯一短式**：`MM-DD HH:MM`（★ 0.50.4 / Q-07，唯一实现）。

    ★★ 为什么单立一个函数（2026-10-15 品质扫描实测）：归并行同一个分组里
       并列出现过两种写法 —— `2026-10-15T00:18`（`str(ts)[:16]`）与
       `10-15T00:18`（`str(ts)[5:16]`）。前者带年份后者不带，跨年时前者的
       「今年还是去年」无从判断；且 ISO 的 `T` 分隔符对非技术读者是噪声。
       ⇒ 全站一律 `MM-DD HH:MM`（年份在页级日期里已给，不重复）。
    ★ 短于 16 字符的原样返回（不截断出半个时间，也不编造）。
    """
    t = "" if s is None else str(s)
    return t[5:16].replace("T", " ") if len(t) >= 16 else t


def _vis(s):
    """★ 0.42.0：**用户可见文本**的出口 —— 先去 markdown 星号，再 HTML 转义。

    ★★ 为什么必须有这一层（2026-10-09 实测，我自己的回归）：

      0.41.0 我把 `zone_locked` 的失败文案写成
      「…（可核：icacls 该目录）；**不等于**有进程在对抗门闸」—— 用了 markdown
      加粗。而这里的渲染**只做 HTML 转义、不解释 markdown** ⇒ 那对 `**`
      原样吐给用户，页面上就是一对裸星号。`0360 W01`（页面无 markdown 星号）
      当场抓住。

      ★ 只改**写侧文案**不够：审计链是 append-only 的，用户机器上躺着
        **各个旧版本写下的记录**。清掉本地那 1 条，只治了本机；
        换个用户、换条旧记录，星号照样露。
      ⇒ 正解是**读侧免疫**：不管记录是哪一版写的，渲染时都不露星号。
        这才是"修得彻底、不复发"—— 与 0.41.0 修 `is_denied()` 同一条思路
        （换 oracle，而不是把某一次的结果改对）。

    ★ 口径：`**X**` → `X`（删掉成对的加粗标记，语义不变）。
    """
    # ★ 0.43.0：去星号的**唯一实现**移到 `inbox_model.visible_text`
    #   —— 命令行那条路要共用它（此前只有网页免疫，CLI 照样吐裸星号）。
    return _esc(M.visible_text(s))


def _allowed_host(host, port):
    h = str(host or "")
    return h in ("127.0.0.1:%d" % port, "localhost:%d" % port,
                 "[::1]:%d" % port, "127.0.0.1", "localhost")


def _pkg_root():
    """本文件所在目录 ＝ 包根（`guard_posture()` 要靠它找门闸的链）。"""
    return os.path.dirname(os.path.abspath(__file__))


def posture_now():
    """现探门闸态势（页面顶部灯的输入）。★ 探不到 ⇒ `unknown`，**绝不返回"值守中"**。"""
    try:
        import host_shield as hs
        return hs.guard_posture(_pkg_root())
    except Exception as e:                          # noqa: BLE001
        return {"state": "unknown", "label": "查不到",
                "why": "读不到监理状态：%r" % (e,), "evidence": {},
                "can_fix": False, "fix": None, "fix_hint": ""}


# ------------------------------------------------------------- 页面 ----
#: 页面图标（**监理五页与紧急提醒窗共用这一枚**）。
#: ★ 0.53.0 T3（创始人 2026-10-19 截图）：小窗原先没有图标链接 ⇒ app 窗标题栏
#:   只能落浏览器默认的网格球，与监理的圆环并排像两个产品。图标只有一份定义，
#:   两处都引它 —— 换图标时不会只换一半。
#: ★★ 2026-10-20（创始人截图「三个地方统一换成 LOGO」）：href 带**内容指纹**。
#:   为什么必须有（这是"改了没效果"的机制级根因，不是锦上添花）：
#:     favicon 有**独立于页面的缓存**，同一个 URL `/assets/favicon.ico`
#:     的内容从姿态灯换成品牌 LOGO 之后，Edge 仍然渲染旧图 —— 产品改了、
#:     用户看到没改，于是被当成"死灰复燃"。URL 随内容变，缓存自然失效，
#:     不依赖用户手动清缓存，也不指望 Ctrl+F5。
def _favicon_href():
    """favicon 的 href：`/assets/favicon.ico?v=<内容 sha8>`。

    取不到品牌文件 ⇒ 退回不带指纹的裸 URL（仍是同一个文件，只是缓存不刷新）；
    **不编造一个指纹** —— 编出来的指纹会让缓存永远命中错内容。
    """
    try:
        p = os.path.join(ASSETS_DIR, _brand_favicon_rel())
        with open(p, "rb") as f:
            return "/assets/favicon.ico?v=%s" % hashlib.sha256(
                f.read()).hexdigest()[:8]
    except OSError:
        return "/assets/favicon.ico"


FAVICON_LINK = '<link rel="icon" href="%s">' % _favicon_href()


def _head(title, token, extra_css=""):
    """页面 `<head>`。

    ★ 0.53.0（T0）：加 `extra_css` —— 体检页要挂 `EXAM_CSS`（`.exam` 作用域）。
      为什么不走全局 CSS：体检正文的类名与本站有真实冲突（见 `EXAM_CSS` 注释），
      整份灌进来会互相污染；只在这一视图注入，其它四页一字节不变。

    ★★ 0.36.2：标题末尾注入**本次运行的窗口身份串**（`#<run_id>`）。
      这不是装饰，是**窗口能被唯一认领的机制**（详见 `inbox_window`）：
      落位/收旧窗都靠它把"本次的窗口"与"用户自己的窗口"、
      与"上次运行残留的窗口"**在结构上分开**。
      注入点选在**服务端渲染**（不是 JS 改 `document.title`）——
      JS 改标题会**晚于**开窗，落位那一刻读到的仍是旧标题；
      服务端渲染则是**首字节就带**，窗口一出现就带着身份。
    """
    try:
        import inbox_window as WIN
        rid = WIN.build_run_id(token)
        # ★ 0.50.4（B7）：标题后缀**收编为 inbox_window 常量派生** —— 原先这里
        #   自造 `"%s · Antinel 监理%s"`，与 inbox_window 是**两处实现**（先于改名
        #   存在的 T-09 隐患；改名会让两处各改各的）。现在走既有派生 API
        #   `console_title_suffix()`（唯一真源）；import 失败 ⇒ tail 退空
        #   （不假造标题，也不留第二个会腐烂的兜底串）。
        tail = WIN.console_title_suffix(rid)
    except Exception:                                       # noqa: BLE001
        rid = ""
        tail = ""
    # ★ 0.51.1（W-01 反转，创始人 2026-10-16 拍板）：标题＝身份后缀**本体**
    #   （`Antinel 监理#<run_id>`，0.48.5 的状态词前缀作废）。`tail` 正常时
    #   整串就是它；`title` 参数降级为 **fallback** —— 只有 inbox_window
    #   注入失败（认窗机制整体不可用）才退回页面名：人话可读、不假造。
    shown = tail if tail else title
    return ("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>%s</title>%s"
            "<style>%s</style>%s</head><body>"
            % (_esc(shown), FAVICON_LINK, CSS,
               ("<style>%s</style>" % extra_css) if extra_css else ""))


def _tabs(view, token):
    """选项卡。★ 0.37.1：**不再挂数字徽章** —— 首页实测「同一件事的 4 件」

    在 tabs 徽章、顶部条后缀、筛选条、说明行里出现了 5 次（创始人 2026-10-08
    点名）。数字现在只属于内容区：收件箱页在筛选条，其他页在顶部条后缀。
    选项卡只负责「去哪儿」。
    ★ 0.48.6（B3）：链接**不再挂口令** —— 靠首字节下发的那枚 httpOnly cookie
      （见 `_COOKIE`）。页签是"导航"，它的 URL 会进浏览器历史。
    """
    def a(v, label):
        cls = " class=\"on\"" if v == view else ""
        return "<a href=\"/?v=%s\"%s>%s</a>" % (v, cls, label)
    return ("<nav class=\"tabs\">" + a("inbox", "收件箱")
            + a("report", "日报") + a("health", "运行状态") + a("ledger", "账本")
            + a("health_exam", "体检")
            + "</nav>")


def _bar(items, token, posture=None, now=None, view="inbox", ex=None):
    """顶部条。★★ 灯＝**六态之一**（2026-10-08 换代，创始人拍板）。

    旧实现（0.36.0–0.36.4）把「姿态 × 24h 历史」两轴**派生**出了 8 个灯态
    （失守/中断·无损失/存疑/研发中/值守中·需你处理/值守中/未启用/查不到）。
    创始人定性：「那 8 态是之前的 AI 主观臆想的，要去掉；六态就应该是
    LOGO 五态加上开发态」。⇒ 现在灯态只有 `inbox_model.LIGHT_STATES` 六个：
    R0 失守 / L2 拦截 / L1 注意 / Ls 预算 / L0 值守中 / dev 研发中，
    判读顺序：防线没生效或不可信 ⇒ R0；24h 未处理事件 ⇒ 取最高级；
    缺口（缺岗无损失/探不到）⇒ L1；未启用 ⇒ L0 灰；研发无事件 ⇒ dev。

    ★★ 数字**只出现一次**（0.37.1 去重 —— 创始人实测「同一件事的 4 件
      在首页出现了 5 次」）：
      · 24h 按级计数（失守/拦截/注意）：唯一家在**日报四指标** ——
        0.53.0 T3.2 撤掉了顶栏那排（同窗口同口径两个落点即红）；
      · 收件箱页：件数只在**筛选条**（「要处理 N」），本行不重复；
      · 日报/运行状态/账本页：件数只在本行后缀（`M.count_text` 的
        「N 件 / 分母（最近 24 小时）」—— 0.48.5 删掉了其中的动作描述词），
        一键落到「要处理」清单（创始人 2026-10-06 第四条：看到「有事」
        必须能落到具体内容）；选项卡上**不再挂数字徽章**。
    ★ 状态词只出现一次：旧版把灯态标签与姿态标签**各写一遍**
      （`<b>存疑</b>` ＋ 药丸「存疑」），同一个词两种叫法还可能不一致。
    """
    p = posture or posture_now()
    # ★★ 0.37.2：灯的说明走 `M.light_explain()`（唯一实现）——
    #   它把「此刻」与「24 小时账」**两个维度写在同一句话里**。
    #   旧版只吐 `light()` 的 why（"24 小时内有未处理事项（最高 R0）"），
    #   于是本机实测出现"此刻哨兵在岗、心跳 0 分钟前，灯却是红的失守"——
    #   用户点进去才发现此刻是好的，等于灯骗了一次。
    # ★ 0.48.5（交接件 §5.5 W-01）：`ex` 由 `render_page` 传入 —— 标题要用
    #   **同一个**状态词，两次 `light_explain()` 可能读到不同时刻的姿态
    #   ⇒ 标题与头部说两个词。不传 ⇒ 自己算（老调用方行为不变）。
    ex = ex or M.light_explain(p, items, now=now, granary=M.granary_now())
    st = ex["state"]
    label = _esc(ex["label"])
    state_reason = _esc(ex["reason"])
    suffix = ""
    # 「有事」要能落到具体内容：**非收件箱页**给钻取后缀（收件箱页由筛选条承担）。
    # ★★ 这是**契约**不是装饰（创始人 2026-10-06 第四条：看到「有事」必须能
    #   落到具体内容），P12 判据按它验收。日报页曾试过去掉它以省掉一个重复数字，
    #   P12 立刻报红 ⇒ 记下这个次序：**契约先于精简**。
    #   （日报页因此会有两处"要处理件数"：这里是导航，卡上是数字。）
    if view != "inbox":
        action_items = [it for it in items
                        if M.bucket_of(it, now=now) == M.BUCKET_ACTION]
        action_groups = M.count_groups(action_items)
        if action_groups:
            # ★★ 0.47.0（方案 v3.0 §5 步三）：**告警数必带窗口与分母**。
            #   旧写法是一个光秃秃的「（%d 件，点开查看）」—— 只有分子。
            #   分母＝本次载入的全部记录条数；格式走 `M.count_text`（唯一实现）。
            # ★ 0.48.5（交接件 §5.6 乙2）：「，点开查看」删 —— 后缀是链接，
            #   可点性由下划线/样式承担，写出来是**替用户描述他即将做的动作**
            #   （W08 立意）；钻取本身不删（P12 契约先于精简）。
            suffix = ("<a href=\"/?v=inbox&amp;f=action\" "
                      "style=\"color:inherit;text-decoration:none\">（%s）</a>"
                      % (_esc(M.count_text(action_groups, len(items))),))
    fix = ""
    if p.get("can_fix"):
        fix = ("<form method=\"post\" action=\"/action\" style=\"margin:0\">"
               "<input type=hidden name=t value=\"%s\">"
               "<input type=hidden name=op value=\"fix\">"
               "<button class=\"fixbtn\">%s</button></form>"
               % (_esc(token), _esc(p.get("fix_hint") or "马上修复")))
    elif p.get("state") in ("down", "warn", "interrupted") and (p.get("fix_hint") or ""):
        # ★ 失守/认不出/缺岗时必须**给得出下一步** —— 能就地修就给按钮；不能就地修，
        #   就把"去哪儿做"明确写在页面上。**绝不留一个点了没反应的按钮**。
        fix = ("<span class=\"fixnote\"><b>怎么解决：</b>%s</span>"
               % _esc(p.get("fix_hint")))
    # ★★ 把"监理不在岗的后果"逐条摆出来（创始人 2026-10-06：
    #   「如果真失守不会带来明显不利后果，那就跟假失守没啥区别」）。
    # ★★ 2026-10-21 文案重写（创始人截图：这块红「让人紧张，但是又没法操作」）：
    #   旧标题「失守的损失：以下 N 项（此刻实况，非计数）」三处毛病：
    #   ① 「失守的损失」是**档位名＋内部词**，用户看到的是"我损失了什么"，
    #      而他其实什么都没损失，只是监理暂时不在岗；
    #   ② 「（此刻实况，非计数）」是写给**判据**看的口径说明（0.47.0 为了不被
    #      当成"无分母的告警数"）—— 用户不关心"这是不是计数"，这是内部口径外溢；
    #   ③ 整块红**没有动作**（截图那一格：dev 姿态 `can_fix=False`），
    #      被吓到却无从下手。
    #   ⇒ 新标题说**事实**（监理不在岗 ⇒ 这几件事现在没人管），口径说明撤掉；
    #     动作仍由下面的 `fix`（按钮 or 「怎么解决」）紧跟其后，
    #     **"红块必须带得出下一步"由 `0353 c_consequences_has_action` 守着**。
    cons = p.get("consequences") or []
    if cons:
        lis = "".join("<li>%s</li>" % _esc(c.get("text") if isinstance(c, dict) else c)
                      for c in cons)
        fix = ('<span class="cons"><b>监理不在岗，这几件事现在没人管：</b>'
               "<ul>%s</ul></span>" % lis) + fix
    # ★★ 0.53.0（T3.2，设计 §14.3 第 1 条）：**撤顶部 24h 计数排**。
    #   撤掉的是什么：原「最近 24 小时：失守 N（已归并为 M 件事）· 拦截 N ·
    #   注意 N」一排按级计数（原 `_pill` ×3 ＋ `nums` 整排，含 R0/L2/L1
    #   三枚「？」芯片）。
    #   为什么撤：与**日报四指标**（R0/L2/L1 按级 ＋ 要处理按桶，同一 24h
    #   窗口）同口径 ⇒ 同一个数两个落点（「重复即红」—— 0.37.1「数字只
    #   出现一次」纪律的彻底执行）。
    #   信息去哪了：24h 按级计数的**唯一家**＝日报四指标，其钻取链接
    #   （`f=win:24:lv:X`）与可见单位照旧；R0/L2/L1 的「？」芯片随指标留
    #   在日报页（术语表 100% 有落点由 P13 四视图并集守）。收件箱页顶部条
    #   只剩灯／状态词／徽标／修复入口 —— 计数归筛选条（三档按**桶**，
    #   量与日报四指标不同，不是同一份数的搬家）。
    #   判据：0490 U20（四视图无第二份）＋ 0353 P14（家的数字与链现算
    #   一致）；减法留账三列见施工单 v1.6 登记簿第 1 笔。
    # ★★ 0.51.0（规格 v1.2 §2.4）：**并存徽标**行（研发中／缺粮）。
    #   与主灯**不争位**：主灯互斥、徽标可多枚常驻 —— "研发中的机器此刻失守"
    #   就是 R0 主灯 ＋ 研发中徽标同屏，两个事实都显示，谁也不掩盖谁。
    #   ★ `ex.get("badges")`（不是 `["badges"]`）：判据 S06/S14 会注入**只含
    #     老键的替身 dict**（证明"真读 light_explain"）—— 缺键必须当"没有徽标"，
    #     不许 KeyError。
    #   ★★ 0.51.0 出包前实测（0490 U-11 判红，**我自己引入的**）：
    #     第一版把 `why`（完整原因句，38 字）塞进了芯片的 `title=`，
    #     而 U-11 锁的是**收件箱页全部 title 属性 ≤ 20 字**（丁4 立规：
    #     工程说明归词条，hover 只给一句人话）。⇒ 这里改用短提示
    #     `M.BADGE_TIP`（模型层与 `BADGE_LABEL` 同处，仍是**唯一真源**）；
    #     **完整原因句走顶栏可见的那句**（`light_explain()["reason"]` 的
    #     「另外：…」段），不靠 hover 兜。
    # ★★ 0.51.0（四态问号小窗方案 v1.1 拍板点三，2026-10-16）：每枚徽标后跟
    #   一个裸「？」芯片（兄弟节点，不塞进 span —— 与药丸问号同构）。徽标 →
    #   态词条键走 `M.BADGE_STATE`；未知徽标键 ⇒ **不加芯片**（.get 判空 ——
    #   判据 S06/S14 会注入替身 dict，缺键当"没有"，不许 KeyError）。
    _chip_parts = []
    for k, name, why in (ex.get("badges") or []):
        _st = M.BADGE_STATE.get(k)
        # ★★ FZ-004（2026-10-17）：版本差已从顶栏主行移走，**关键信息（哪两版）
        #   不能跟着丢** ⇒ 悬停提示带上具体版本号（原句 `why` 开头就是
        #   「研发中——本机这一版（0.51.2）比已发布的（0.51.1）新，还没发出去」，
        #   而 `BADGE_TIP` 是静态短句）。
        #   ★ 但仍受 U-11 约束（title ≤ 20 字）⇒ 只取**括号里的两版号**，
        #     拼成「本机0.51.2/发布0.51.1」这种最省字的形态（19 字；实测
        #     带空格的「本机 0.51.2 / 发布 0.51.1」＝ 21 字，越 U-11 上限）。
        #     取不到版本号 ⇒ 退回静态 `BADGE_TIP`（绝不编造）。
        _tip = M.BADGE_TIP.get(k, name)
        _vs = re.findall(r"（([0-9][0-9A-Za-z.\-]*)）", why or "")
        if k == M.BADGE_DEV and len(_vs) >= 2:
            _cand = "本机%s/发布%s" % (_vs[0], _vs[1])
            if len(_cand) <= 20:
                _tip = _cand
        _chip_parts.append(
            "<span class=\"bdg %s\" title=\"%s\">%s</span>%s"
            % (_esc(k), _esc(_tip), _esc(name),
               GL.chip(_st, mk=True) if _st else ""))
    _chips = "".join(_chip_parts)
    badge_html = ("<span class=\"badges\">%s</span>" % _chips) if _chips else ""
    return (
        "<header class=\"bar\">"
        # ★★ 0.49.0：图标恢复动效（五态动法，规格《品牌动效报警语法 v1.2》，
        #   实现基线 motion-demo-v2 的产品化移植；矢量 SVG  ⇒ 48px 不发虚，
        #   也解决了 0.48.5 戊1 换静态图的理由）。JS 不在时 `<noscript>` 里
        #   退回静态矢量（认得出是 Antinel，只是不动 —— **不假装能动**）。
        # ★★ 0.50.7（2026-10-16，创始人截图「左上角 LOGO 与右上角收缩钮是
        #   同一枚图形、两个入口，重复了」）：**去重复**（L2 触发层 UX 洁癖
        #   清单第 6 条）—— 收缩入口合并进 LOGO 本体：点这枚钮＝收缩成
        #   漂浮哨标（title 说人话）。右上角那枚同款 SVG 一并删除，全页
        #   只一枚 lgmark（判据 J1 守去重）。判据 FLO-05 随设计更新
        #   （追随规格，不是放松）：锁入口在／用 `_logo_mark`／title 说
        #   人话／op=collapse 链三处，不再锁 `collbtn` 类名。
        #   ⚠️ SVG 走 `%s` 占位（**不能**用 `+` 拼进来）：`%` 的优先级高于
        #   `+`，`+` 会把字面量组切断 ⇒ `%` 只作用到末尾没有占位符的片段
        #   ⇒ "not all arguments converted"（本仓踩过）。
        #   ⚠️⚠ 0.50.7 实测近失（同族第二形态）：**占位符顺序必须跟着布局
        #   顺序走** —— 按钮从条尾移到条首时，实参元组忘了同步 ⇒ SVG 落进
        #   状态行后面、按钮里被塞进 `var(--l0)`。页面照渲染、不抛错、
        #   静默错位（比抛错更坏）。FLO-05 的「入口内嵌动效哨标」断言
        #   当场抓住 —— 判据先于眼睛。
        "<button class=\"logo\" type=\"button\" data-coll=\"1\" "
        "title=\"收缩成漂浮哨标 · 点它再展开\" aria-label=\"收缩成漂浮哨标\">%s"
        "<noscript><img alt=\"Antinel\" src=\"/assets/logo.svg\"></noscript></button>"
        # ★ 0.48.5（交接件 §5.6 乙1）：顶部灯的「？」芯片跟在 `<b>` 后
        #   （灯不是链接，芯片可以直接挨着；0.53.0 T3.2 起本页共 5 个落点 ——
        #   药丸那 3 颗随顶部计数排撤走，U-04 逐个数）。
        # ★ 0.48.5（交接件 §5.4 戊4）：状态词 16px 粗体、**色随态**
        #   （与 `.dot` 同一个 `M.STATE_VAR` —— 单一真源）；解释句降为
        #   13px 常规色（信息量大的那句占主导，见 U-15）。
        "<div class=\"state\"><span class=\"dot\" style=\"background:var(%s)\"></span>"
        "<b style=\"color:var(%s)\">%s</b>%s%s%s<br><span>%s</span></div>"
        "%s"
        # ★★ 0.50.0：收缩入口的**状态行**（漂浮最小态）——请求失败/起不来时
        #   **就地如实说**，绝不静默（用户点了没反应＝本项目最恨的形状）。
        "<span class=\"collst\" id=\"collst\"></span>"
        "<div class=\"spacer\"></div></header>"
        # ⚠️ 实参顺序 ＝ 占位符在串里出现的顺序（布局变了就同步改这里）：
        #   按钮的 SVG 在最前 ⇒ `_logo_mark(st)` 也在最前。
        #   ★ 0.53.0（T3.2）：原第 9 个实参 `nums`（24h 计数排）随药丸整排
        #   撤掉，格式串里的 `"%s%s"` 同步收成 `"%s"`（占位符与实参一对多
        #   少 ⇒ `not all arguments converted`，本仓踩过）。
        % (_logo_mark(st), M.STATE_VAR[st], M.STATE_VAR[st],
           label, GL.chip("light", mk=True), suffix, badge_html,
           state_reason, fix))


#: ★★ 0.49.0（2026-10-14，创始人「现在的图标好了，但是'死了'，让它继续动」）：
#:   头部图标恢复**动效**。五态动法的唯一规格在 PSL 仓
#:   《Antinel 品牌动效报警语法 v1.2（2026-09-27）》——「代码即规格」的
#:   实现基线是 `antinel-motion-demo-v2.html`（SVG＋rAF 状态机），本块是它的
#:   **产品化移植**（去掉演示按钮/巡演/键盘交互），参数逐项照抄规格表：
#:     色相梯度 绿→浅黄→明黄→橙（越黄越重）｜扫描周期 12→8→5.5→3.5s（越快越重）
#:     ｜涟漪波幅 0→45→70→105px（波越大越重）｜R0 停摆波止（讣告＝梯度断裂）
#:   ★ 为什么不再用 mp4（0.48.5 戊1 的理由直接消解）：那次换静态 logo.svg 的
#:     依据是「768² 视频缩到 46² 发虚、607KB 换一个模糊角标」——**内联 SVG
#:     是矢量，48px 下任意清晰，体积按字节算**。两条老纪律都保住了：
#:       ① 不发虚；② 渐进增强：JS 不执行时退回 `<noscript>` 静态 logo.svg。
#:   ★ 规格参数**只在这里写一遍**：JS 里的 STYLE 由本字典渲染 ⇒ 判据 U-17
#:     拿它对着规格表逐项锁（漂移即红），不会出现"页面一套、规格一套"。
#:   ★ `dev`（研发态）不在五态语法里：哨兵在岗、只是代码比登记的新 ⇒ 按
#:     最静的 L0 动（**不编一个新的动法**，也不演成失守）。
LOGO_MOTION = {
    "L0": {"c": (126, 155, 132), "lap": 12.0, "ringO": 1.0,
           "amberO": 0.35, "ringRed": 0.0, "waveR": 0, "waveO": 0.0},
    "L1": {"c": (205, 194, 154), "lap": 8.0, "ringO": 1.0,
           "amberO": 1.0, "ringRed": 0.0, "waveR": 45, "waveO": 0.30},
    "L2": {"c": (224, 180, 85), "lap": 5.5, "ringO": 1.0,
           "amberO": 1.0, "ringRed": 0.0, "waveR": 70, "waveO": 0.45},
    #: 规格表里的 `L$`（预算态）在灯态里叫 `Ls` —— 动法里沿用规格的 `LD` 键。
    "LD": {"c": (232, 163, 61), "lap": 3.5, "ringO": 1.0,
           "amberO": 1.0, "ringRed": 0.0, "waveR": 105, "waveO": 0.65},
    "R0": {"c": (178, 84, 84), "lap": 0.0, "ringO": 0.45,
           "amberO": 0.85, "ringRed": 1.0, "waveR": 0, "waveO": 0.0},
}

#: 环的领地色（常态绿 → R0 暗红），规格 §二 色值总表
LOGO_RING_GREEN = (91, 130, 101)
LOGO_RING_DARKRED = (74, 38, 38)

#: 灯态 → 动法键（`dev` → `L0`，见上注）
LOGO_MODE = {"L0": "L0", "L1": "L1", "L2": "L2", "Ls": "LD", "R0": "R0",
             "dev": "L0"}

#: 画布几何 —— **唯一真源**：`_logo_mark` 的 viewBox 与 `_LOGO_JS` 里的
#: `CX/CY/R/W_BEAM` 是同一份规格。判据 U-18 拿 `_LOGO_JS` 源码逐项比对，
#: 任一处漂移即红（否则"页面一套、规格一套"）。
LOGO_CANVAS = 1024
LOGO_CX = 512
LOGO_CY = 512
LOGO_R = 215          #: 探针环半径（画布单位）
LOGO_RING_W = 46      #: 探针环宽（画布单位）
LOGO_AMBER_R = 24     #: 灯头（哨点）半径（画布单位；`_LOGO_JS` 的 AMBER_R）
#: 灯头（哨点）填充色 —— **固定琥珀，与光束色解耦**（FZ-001：创始人 2026-10-16
#:   截图 #1「橙色小球弄丢了，AI 对此毫无意识」—— 原实现 fill 跟 V.beamC 走，
#:   绿态下小球与光束同色、肉眼不可辨）。静态骨架与状态机赋值**同取此常量**
#:   （单一真源；灯色判据 lamp_color_contract 从它派生期望值，不二次实现）。
LOGO_AMBER_FILL = "#E8A33D"
LOGO_WAVE_GAP = 8     #: 涟漪起始半径 = 灯头半径 ＋ 这个缝（`_LOGO_JS` 的 `+8`）
LOGO_BEAM_LEN = 200   #: 波束长度（`_LOGO_JS` 的 L_BEAM）
LOGO_BEAM_W = 11      #: 波束宽度（`_LOGO_JS` 的 W_BEAM）

#: ★★ 0.50.2（2026-10-14，创始人截图：「LOGO 是活了，但是旧病复发，变得
#:   太小了，需要变回最新的尺寸」）：环外缘应占**画布半宽**的比例。
#:   取值 = 定稿 `assets/logo/logo.svg` 的比例（环 R 23.5 ＋ 半环宽 3.5
#:   = 27，画布半宽 32 ⇒ 27/32 = 0.84375）—— 这样「JS 开着看到的内联
#:   SVG」与「JS 关掉退回的 `<noscript>` logo.svg」**一样大**：渐进增强
#:   不跳变（判据 U-18 同时锁这条等式）。
#:   ★ 病根（可核）：demo `antinel-motion-demo-v2.html` 把 1024 画布直出，
#:     那里 SVG 显示 340–620px，内边距不显；同一份 viewBox 搬进 48px 方框
#:     后，环只占 0.465 —— 比定稿小 45%，看着就是"缩水了"。
#:   ★ 修法：**只收紧 viewBox**（下面 `_logo_viewbox` 反算），动法几何
#:     （CX/CY/R/环宽/波幅/速度）一个数不动 ⇒ 动效不退化。
LOGO_BOX_RATIO = 27.0 / 32.0

#: ★★★ 0.50.3（2026-10-14，创始人截图：「冒泡的 LOGO 不完整」）：
#:   0.50.2 把 viewBox 收紧到**环**以后，涟漪被方框裁掉了 —— 涟漪的圆心在
#:   半径 `LOGO_R` 的灯头上，半径最大 `LOGO_AMBER_R + LOGO_WAVE_GAP + waveR`
#:   ＝ 24＋8＋105 ＝ 137 ⇒ 离画布中心 215＋137 ＝ **352**，而方框半宽只有
#:   **282.074** ⇒ 波的最外缘被切掉（实测：Ls 态渲染图上涟漪在下沿/左沿
#:   被切出一道直边）。
#:   ★ 根因不是"viewBox 收得太紧"，是**两条规格互不相容**：
#:     · 定稿 `logo.svg` 规定环外缘占方框半宽的 **0.844**（0.50.2 已按此定死）；
#:     · 动效规格 v1.2 的波幅 45/70/105 是在**环只占 0.465** 的 demo 画布上
#:       标定的 —— 那时环小、波放得下。
#:     把环放大到 0.844 之后，留给波的空间只剩 `half − R − (AMBER_R+8)`
#:     ≈ **35** 个画布单位。
#:   ★ 取舍（明写，不藏）：**方框＝定稿 logo 的方形轮廓**，它装得下的才算
#:     logo 的一部分 ⇒ 波幅**按可用空间归一**（`_logo_wave_scale()`），
#:     环仍是定稿尺寸（创始人第 4 条明确要的"最新尺寸"），波**永不被裁**。
#:     波幅三档的**相对梯度**（0/45/70/105 的比值）原样保留 ⇒ 「波越大越重」
#:     这条语义没变，变的只是它在 48px 方框里的绝对尺度。
LOGO_WAVE_MARGIN = 2.0   #: 波最外缘距方框内缘的余量（画布单位）

#: ★★ 0.53.1：动效状态机的**动画常量**从 `_LOGO_JS` 里写死的数字提升为
#:   Python 常量（单一真源）。为什么必须提升：漂浮哨标（tools/logo.ps1，
#:   PowerShell）要照**同一份**动法动，它 import 不了 Python —— 规格经
#:   `tray.json` 的 `logo` 块下发（`logo_motion_spec()`）。这些数字若仍写死在
#:   JS 里，就会出现「页面一套、哨标一套」两份，迟早漂（U-18b 同族）。
#:   本块的值经占位符注入 `_LOGO_JS_TMPL` ⇒ 渲染出的 JS 与提升前**逐字一致**
#:   （唯一有意改动：reduced-motion 静态帧，见 `_LOGO_JS_TMPL` 内注）。
LOGO_TRAIL_N = 5          #: 拖尾段数
LOGO_TRAIL_STEP = 3       #: 相邻拖尾段的角度差（度）
LOGO_TRAIL_OPA = (0.38, 0.27, 0.18, 0.11, 0.06)   #: 各段不透明度（由头到尾）
LOGO_TRAIL_FRAC = 0.42    #: 拖尾内端占波束长度的比例
LOGO_TRAIL_INSET = 6      #: 拖尾外端比波束端短多少（画布单位）
LOGO_TRAIL_COLOR = "#7E9B84"   #: 拖尾静态骨架色（运行时随光束色走）
LOGO_WAVE_PERIOD = 1.4    #: 单枚涟漪的周期（秒）
LOGO_WAVE_W0 = 7.0        #: 涟漪线宽（起始，画布单位）
LOGO_WAVE_W1 = 5.0        #: 涟漪线宽随相位的缩减量（⇒ 消散端 2）
LOGO_BEAM_A0 = 315        #: 波束标称角（度，自正北顺时针；规格 demo 的 A_P）
LOGO_BEAM_START = 205.0   #: 初始相位（度）＝ A0 − 110（demo 的起步角）
LOGO_SEG_GAP = 10         #: 环四段之间的缝（度）
LOGO_BREATH_BASE = 0.94   #: 呼吸中位（环不透明度 = base + amp·sin）
LOGO_BREATH_AMP = 0.06    #: 呼吸幅度 ⇒ 0.88…1.00
LOGO_BREATH_PERIOD = 4.0  #: 呼吸周期（秒）
LOGO_XFADE = 0.4          #: 换态的渐变时长（秒）
LOGO_L0_DELAY = 0.15      #: L0 起步前的停顿（秒）
LOGO_L0_RAMP = 0.35       #: L0 从半速匀到全速的时长（秒）
LOGO_R0_SLIDE = 20.0      #: R0 滑行角度（度）—— 滑完永停（讣告）
LOGO_R0_SLIDE_T = 0.8     #: R0 滑行时长（秒）


def _logo_half():
    """方框半宽（画布单位）—— 环外缘占半宽的比例恰为 `LOGO_BOX_RATIO`。"""
    return (LOGO_R + LOGO_RING_W / 2.0) / LOGO_BOX_RATIO


def _logo_viewbox():
    """按定稿比例反算 viewBox（正方形、以 CX/CY 为中心）。

    环外缘半径 = `LOGO_R` ＋ `LOGO_RING_W`/2；让它占画布半宽的比例恰为
    `LOGO_BOX_RATIO`。⇒ 环外缘**正好贴到方框的定稿内边距**上。
    """
    half = _logo_half()
    return "%g %g %g %g" % tuple(
        round(v, 3) for v in (LOGO_CX - half, LOGO_CY - half, 2 * half, 2 * half))


def _logo_wave_scale():
    """涟漪波幅的**归一系数**（规格值 → 方框内可用的画布单位）。

    ★ 为什么必须有（0.50.3）：见 `LOGO_WAVE_MARGIN` 上面那段 —— 环按定稿放到
      0.844 之后，波幅 45/70/105 会伸出方框，最外缘被裁成直边（"LOGO 不完整"）。
      这里把"方框内还剩多少给波"算出来，除以规格里的最大波幅 ⇒ 系数。
    ★ 单一真源：分子分母全部来自上面的几何常量与 `LOGO_MOTION`（规格表），
      不另写一份数字。判据 U-18c 拿它反算，负控（把规格值直接塞进渲染表）
      必须红。
    """
    room = (_logo_half() - LOGO_R - (LOGO_AMBER_R + LOGO_WAVE_GAP)
            - LOGO_WAVE_MARGIN)
    spec_max = max(float(v["waveR"]) for v in LOGO_MOTION.values())
    return room / spec_max


def _logo_motion_render():
    """**渲染用**动法表 = 规格表 × 波幅归一系数（派生，不手写第二份）。

    ★ `LOGO_MOTION` 是**规格表**（U-17a 逐项锁它，是"代码即规格"的那一份），
      本表是它在**这个方框几何**下的渲染投影。两者的差**只有** `waveR` 一栏，
      且差值由 `_logo_wave_scale()` 算出 —— 判据 U-18c 同时锁这两件事。
    """
    k = _logo_wave_scale()
    out = {}
    for name, v in LOGO_MOTION.items():
        w = dict(v)
        w["waveR"] = round(float(v["waveR"]) * k, 3)
        out[name] = w
    return out


LOGO_MOTION_RENDER = _logo_motion_render()


def _hex_rgb(s):
    """`"#RRGGBB"` → `(r, g, b)`。规格色值在 Python 侧是 hex 字面量，
    下发协议（JSON 数字）与判据比对都要三元组 —— 一处转换，不写第二份。"""
    h = str(s).lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def logo_motion_spec():
    """**漂浮哨标的动效规格**（0.53.1）—— 单一真源，全部由上面常量派生。

    ★ 为什么需要它：哨标是 PowerShell 脚本（tools/logo.ps1），import 不了
      Python。规格经 `tray.json` 的 `logo` 块下发（`inbox_tray.write_state`
      每次写状态都带上），哨标照它画**与主窗口同一份动法**（环/光束/灯头/
      涟漪/拖尾/呼吸，规格 v1.2）⇒ 页面与哨标永远同源，不会"页面一套、
      哨标一套"。
    ★ 波幅用**渲染表** `LOGO_MOTION_RENDER`（规格 × 归一系数）：哨标窗与
      页面方框同几何（`half`），照抄规格表的 45/70/105 会伸出框外 ——
      0.50.3「冒泡的 LOGO 不完整」那条缺陷在 46px 哨标上一样会发生。
    ★ 判据 FLO-10c 拿它对着 `LOGO_MOTION_RENDER` 与几何常量逐项锁；负控
      把一份手写的未归一一波幅塞进来必须红（与 U-18c 同一族）。
    """
    return {
        "v": 1,
        "geom": {"cx": LOGO_CX, "cy": LOGO_CY, "r": LOGO_R,
                 "ringW": LOGO_RING_W, "amberR": LOGO_AMBER_R,
                 "waveGap": LOGO_WAVE_GAP, "beamLen": LOGO_BEAM_LEN,
                 "beamW": LOGO_BEAM_W, "boxRatio": LOGO_BOX_RATIO,
                 "half": round(_logo_half(), 3)},
        "colors": {"ringGreen": list(LOGO_RING_GREEN),
                   "ringDarkRed": list(LOGO_RING_DARKRED),
                   "amber": list(_hex_rgb(LOGO_AMBER_FILL)),
                   "trail": list(_hex_rgb(LOGO_TRAIL_COLOR))},
        "anim": {"trailN": LOGO_TRAIL_N, "trailStep": LOGO_TRAIL_STEP,
                 "trailOpa": list(LOGO_TRAIL_OPA),
                 "trailFrac": LOGO_TRAIL_FRAC, "trailInset": LOGO_TRAIL_INSET,
                 "wavePeriod": LOGO_WAVE_PERIOD, "waveW0": LOGO_WAVE_W0,
                 "waveW1": LOGO_WAVE_W1, "beamA0": LOGO_BEAM_A0,
                 "beamStart": LOGO_BEAM_START, "segGap": LOGO_SEG_GAP,
                 "breathBase": LOGO_BREATH_BASE, "breathAmp": LOGO_BREATH_AMP,
                 "breathPeriod": LOGO_BREATH_PERIOD, "xfade": LOGO_XFADE,
                 "l0Delay": LOGO_L0_DELAY, "l0Ramp": LOGO_L0_RAMP,
                 "r0Slide": LOGO_R0_SLIDE, "r0SlideT": LOGO_R0_SLIDE_T},
        "motion": {k: {"c": list(v["c"]), "lap": v["lap"],
                       "ringO": v["ringO"], "amberO": v["amberO"],
                       "ringRed": v["ringRed"], "waveR": v["waveR"],
                       "waveO": v["waveO"]}
                    for k, v in LOGO_MOTION_RENDER.items()},
        "modes": dict(LOGO_MODE),
    }


def _logo_mark(state, label="Antinel"):
    """动效图标：内联 SVG（骨架）＋ `_LOGO_JS` 状态机点亮。

    ★ 为什么用 `data-p` 而不是 `id`：同一页/同一时刻可能有多个哨标
      （面板头部、紧急提醒窗……），`id` 全局唯一会互相踩；`data-p` 在各自的
      `<svg>` 作用域内查询，天然不串。
    ★ viewBox 由 `_logo_viewbox()` 反算（0.50.2），**不写死 1024 画布**
      —— 写死就会在 48px 方框里缩成一半（创始人截图的那条）。
    """
    mode = LOGO_MODE.get(state, "L0")
    return (
        '<svg class="lgmark" viewBox="%s" data-logo="1" data-mode="%s"'
        ' role="img" aria-label="%s">'
        '<g data-p="trail" stroke="#7E9B84" stroke-width="11" stroke-linecap="butt"></g>'
        '<g data-p="ring" fill="none" stroke="#5B8265" stroke-width="46">'
        '<path data-p="seg0"></path><path data-p="seg1"></path>'
        '<path data-p="seg2"></path><path data-p="seg3"></path></g>'
        '<circle data-p="wave0" fill="none" stroke="#7E9B84" opacity="0"></circle>'
        '<circle data-p="wave1" fill="none" stroke="#7E9B84" opacity="0"></circle>'
        '<line data-p="beam" x1="512" y1="512" x2="512" y2="312" stroke="#7E9B84"'
        ' stroke-width="11" stroke-linecap="butt"></line>'
        '<circle data-p="amber" r="24" fill="%s"></circle>'
        "</svg>" % (_logo_viewbox(), mode, _esc(label), LOGO_AMBER_FILL))


#: 状态机（`antinel-motion-demo-v2.html` 的产品化移植）。
#: ★ `__STYLE__`/`__RING_*__`/`__*__`（几何与动画常量）由服务端从
#:   `LOGO_MOTION_RENDER`（规格表 × 波幅归一系数）与上面的 Python 常量渲染
#:   —— 规格参数单一真源（U-17 锁规格表、U-18b/c 锁几何与归一关系、
#:   FLO-10d 锁"JS 文本里的常量 == Python 常量"，防有人手改 JS 文本）。
#: ★ 无外部资源、无依赖；`dt` 钳制 0.05s（规格 §四：无头/卡顿时不静默跳变）。
_LOGO_JS_TMPL = """
<script>
(function(){
"use strict";
var STYLE=__STYLE__;
var RING_GREEN=__RING_GREEN__, RING_DARKRED=__RING_DARKRED__;
var DEG=Math.PI/180, CX=__CX__, CY=__CY__, R=__R__, W_BEAM=__BEAM_W__, L_BEAM=__BEAM_LEN__, AMBER_R=__AMBER_R__, GAP=__SEG_GAP__;
var TRAIL_N=__TRAIL_N__, TRAIL_STEP=__TRAIL_STEP__, TRAIL_OPA=[__TRAIL_OPA__], TRAIL_FRAC=__TRAIL_FRAC__, TRAIL_INSET=__TRAIL_INSET__, WAVE_PERIOD=__WAVE_PERIOD__, WAVE_W0=__WAVE_W0__, WAVE_W1=__WAVE_W1__;
function px(a,r){return [CX+r*Math.sin(a*DEG), CY-r*Math.cos(a*DEG)];}
function mod(a){return ((a%360)+360)%360;}
var SEGS=[[GAP/2,90-GAP/2],[90+GAP/2,180-GAP/2],[180+GAP/2,270-GAP/2],[270+GAP/2,360-GAP/2]];
function arcPath(a0,a1,r){var x0=px(a0,r), x1=px(a1,r);
  return "M"+x0[0].toFixed(1)+" "+x0[1].toFixed(1)+" A"+r+" "+r+" 0 0 1 "+x1[0].toFixed(1)+" "+x1[1].toFixed(1);}
function clamp(x,a,b){return Math.max(a,Math.min(b,x));}
function lerp(a,b,t){return a+(b-a)*t;}
function mix(a,b,t){return [lerp(a[0],b[0],t),lerp(a[1],b[1],t),lerp(a[2],b[2],t)];}
function css(c){return "rgb("+Math.round(c[0])+","+Math.round(c[1])+","+Math.round(c[2])+")";}
function easeOut(t){return 1-Math.pow(1-t,3);}
function easeInOut(t){return t<.5?4*t*t*t:1-Math.pow(-2*t+2,3)/2;}
function q(el,n){return el.querySelector('[data-p="'+n+'"]');}
function boot(svg){
  var mode=svg.getAttribute("data-mode")||"L0";
  if(!STYLE[mode]){mode="L0";}
  var V={theta:__BEAM_START__, beamC:STYLE.L0.c.slice(), ringO:1, amberO:.35, ringRed:0, breath:1};
  var snap=null, mt=0, last=0, trail=[];
  for(var i=0;i<TRAIL_N;i++){
    var l=document.createElementNS("http://www.w3.org/2000/svg","line");
    l.setAttribute("stroke-width",W_BEAM);
    q(svg,"trail").appendChild(l);
    trail.push(l);
  }
  for(var s=0;s<4;s++){ q(svg,"seg"+s).setAttribute("d", arcPath(SEGS[s][0],SEGS[s][1],R)); }
  function update(dt){
    mt+=dt;
    var st=STYLE[mode], k=easeOut(clamp(mt/.4,0,1));
    V.beamC=mix(snap.beamC, st.c, k);
    V.ringO=lerp(snap.ringO, st.ringO, k);
    V.amberO=lerp(snap.amberO, st.amberO, k);
    V.ringRed=lerp(snap.ringRed, st.ringRed, k);
    V.breath=.94+.06*Math.sin(mt*2*Math.PI/4);
    if(mode==="L0"){
      if(mt>0.15){ var w=clamp((mt-0.15)/.35,0,1);
        V.theta=mod(snap.theta+(mt-0.15)*360/st.lap*lerp(.5,1,easeOut(w))); }
      else { V.theta=snap.theta; }
    } else if(st.lap>0){
      V.theta=mod(snap.theta+mt*360/st.lap);
    } else {
      V.theta=mod(snap.theta+20*easeInOut(clamp(mt/.8,0,1)));
    }
  }
  function render(){
    var showTrail=(mode==="L0");
    for(var i=0;i<TRAIL_N;i++){
      var a=mod(V.theta-(i+1)*TRAIL_STEP);
      var r0=L_BEAM*(1-TRAIL_FRAC), r1=L_BEAM-TRAIL_INSET;
      var p0=px(a,r0), p1=px(a,r1), l=trail[i];
      l.setAttribute("x1",p0[0]); l.setAttribute("y1",p0[1]);
      l.setAttribute("x2",p1[0]); l.setAttribute("y2",p1[1]);
      l.setAttribute("opacity", showTrail? String(TRAIL_OPA[i]) : "0");
    }
    var tg=q(svg,"trail");
    tg.setAttribute("stroke", css(V.beamC));
    tg.setAttribute("stroke-width", String(W_BEAM));
    var bp=px(V.theta,L_BEAM), beam=q(svg,"beam");
    beam.setAttribute("x2",bp[0]); beam.setAttribute("y2",bp[1]);
    beam.setAttribute("stroke", css(V.beamC));
    var ringC=mix(RING_GREEN, RING_DARKRED, V.ringRed);
    for(var g=0;g<4;g++){
      var el=q(svg,"seg"+g);
      el.setAttribute("stroke", css(ringC));
      el.setAttribute("opacity", String(clamp(V.ringO*V.breath,0,1)));
    }
    var ap=px(V.theta,R), amber=q(svg,"amber");
    amber.setAttribute("cx",ap[0]); amber.setAttribute("cy",ap[1]);
    amber.setAttribute("fill", __AMBER_FILL__);
    amber.setAttribute("opacity", String(V.amberO));
    var on=(mode==="L1"||mode==="L2"||mode==="LD");
    for(var wv=0;wv<2;wv++){
      var wl=q(svg,"wave"+wv);
      if(!on){ wl.setAttribute("opacity","0"); continue; }
      var st=STYLE[mode];
      var ph=((mt+wv*WAVE_PERIOD/2)%WAVE_PERIOD)/WAVE_PERIOD;
      wl.setAttribute("cx",ap[0]); wl.setAttribute("cy",ap[1]);
      wl.setAttribute("r", String(AMBER_R+8+ph*st.waveR));
      wl.setAttribute("stroke", css(V.beamC));
      wl.setAttribute("stroke-width", String(WAVE_W0-WAVE_W1*ph));
      wl.setAttribute("opacity", String(st.waveO*(1-ph)*(1-ph)));
    }
  }
  function setMode(m){ mode=m; mt=0; snap=JSON.parse(JSON.stringify(V)); }
  function loop(now){
    var dt=last?Math.min(.05,(now-last)/1000):0; last=now;
    update(dt); render();
    requestAnimationFrame(loop);
  }
  setMode(mode);
  // ★ 0.50.4（Q-20）：响应系统的「减少动态效果」偏好。
  //   顶部哨标是常驻动效（扫描周期 3.5-12s ＋ 涟漪 45-105px），晕动敏感用户
  //   在常驻窗口里没有退路 —— 全仓原先零处 `prefers-reduced-motion`。
  //   ⇒ 命中时**只画一帧静态**就停：色相与形状照旧（状态照样认得出），
  //     只是不动。★ 不假装"已经减少了动效"，是真的停掉 rAF 循环。
  // ★★★ 0.53.1 修（移植哨标时实测发现的同源缺陷）：静态帧必须
  //   `update(__XFADE__)`（跨完整段渐变），**不能** `update(0)` ——
  //   update(0) 会让 V 停在**启动态**（L0 绿）：R0 页在减少动效下会渲染成
  //   一枚**绿环**（环色/灯头透明度全是 L0 的），状态读错。判据 FLO-10e
  //   拿 Node 真跑这条（reduce=true ⇒ R0 必须是暗红）。
  // ★ `typeof window` 必须先判：判据 `ci/inbox_guards_0514.py` U-17c/U-18d
  //   把这段 JS **抽出来在 Node 里真跑**（验动效规格），那里没有 `window`
  //   —— 直接取 `window.matchMedia` 会 ReferenceError 判红（本轮实测踩到）。
  var _reduce = (typeof window !== "undefined") && window.matchMedia
      && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (_reduce) { update(__XFADE__); render(); }
  else { requestAnimationFrame(loop); }
}
var list=document.querySelectorAll("svg[data-logo]");
for(var i=0;i<list.length;i++){ boot(list[i]); }
})();
</script>
"""

def _jsnum(v):
    """JS 数字字面量：整数不带小数点，小数去掉前导 0（`.38`）。

    ★ 为什么讲究逐字一致：占位符替换后的 `_LOGO_JS` 与提升前（数字写死在
      模板里）必须**逐字相同** —— 否则"提升常量"这件事本身就构成一次未经验
      证的渲染变更（U-17c/U-18d 的 Node 真跑、以及任何人肉眼比对都依赖它）。
    """
    if isinstance(v, bool):
        raise TypeError("bool 不是 JS 数字")
    f = float(v)
    if f.is_integer():
        return str(int(f))
    return ("%g" % f).lstrip("0") or "0"


_LOGO_JS = (_LOGO_JS_TMPL
            .replace("__STYLE__", json.dumps(LOGO_MOTION_RENDER, ensure_ascii=False))
            .replace("__RING_GREEN__", json.dumps(list(LOGO_RING_GREEN)))
            .replace("__RING_DARKRED__", json.dumps(list(LOGO_RING_DARKRED)))
            .replace("__AMBER_FILL__", json.dumps(LOGO_AMBER_FILL))
            .replace("__CX__", _jsnum(LOGO_CX))
            .replace("__CY__", _jsnum(LOGO_CY))
            .replace("__R__", _jsnum(LOGO_R))
            .replace("__BEAM_W__", _jsnum(LOGO_BEAM_W))
            .replace("__BEAM_LEN__", _jsnum(LOGO_BEAM_LEN))
            .replace("__AMBER_R__", _jsnum(LOGO_AMBER_R))
            .replace("__SEG_GAP__", _jsnum(LOGO_SEG_GAP))
            .replace("__TRAIL_N__", _jsnum(LOGO_TRAIL_N))
            .replace("__TRAIL_STEP__", _jsnum(LOGO_TRAIL_STEP))
            .replace("__TRAIL_OPA__", ",".join(_jsnum(v) for v in LOGO_TRAIL_OPA))
            .replace("__TRAIL_FRAC__", _jsnum(LOGO_TRAIL_FRAC))
            .replace("__TRAIL_INSET__", _jsnum(LOGO_TRAIL_INSET))
            .replace("__WAVE_PERIOD__", _jsnum(LOGO_WAVE_PERIOD))
            .replace("__WAVE_W0__", _jsnum(LOGO_WAVE_W0))
            .replace("__WAVE_W1__", _jsnum(LOGO_WAVE_W1))
            .replace("__BEAM_START__", _jsnum(LOGO_BEAM_START))
            .replace("__XFADE__", _jsnum(LOGO_XFADE)))


#: ★★ 0.49.0（2026-10-14，创始人截图 3/4/5）：术语浮层**突破窗口边界**。
#:   实测：浮层（`.tdef`）被Antinel 监理窗口的**右缘/下缘**裁掉 ——「注意 1」的
#:   问号点开，右侧看不见；日报页底部词条，下沿被截。
#:   ★ 为什么页内修不了：HTML **画不出自己窗口的外面**。0.36.1 的 `.flipx`
#:     只是"改成从左边展开"，宽浮层照样出界；`max-width:calc(100vw-40px)`
#:     也只是让浮层不超过视口 —— 视口本身就是那条边界。
#:   ⇒ 唯一能"扩大可见区域"的是**窗口本身**：JS 量出溢出量 → 报给服务端 →
#:     服务端把窗口**平移**（不改变布局，露出的正是缺的像素）；贴到工作区
#:     边平移不动了才**撑开**右/下沿（会 reflow，如实记 grew）。
#:   ★ 关窗即还原：最后一个术语浮层收起时，窗口搬回原矩形；**若期间用户
#:     手动搬过窗口，就不搬回**（用户的手动摆放优先，不与用户抢方向盘）。
#:   ★ 全程如实报告：`left`（仍没露出的余量）> 0 时**不说"已露出"**，
#:     DOM 上留 `data-escape="partial"` 供判据与用户感知。
_ESCAPE_JS_TMPL = """
<script>
(function(){
"use strict";
function terms(){ return document.querySelectorAll("details.term[open]"); }
function esc(){
  var open = terms(), need = null;
  for (var i=0;i<open.length;i++){
    var b = open[i].querySelector(".tdef"); if (!b) continue;
    var r = b.getBoundingClientRect();
    var dr = r.right - document.documentElement.clientWidth;
    var db = r.bottom - document.documentElement.clientHeight;
    if (dr > 0 || db > 0){
      need = {dr: Math.ceil(Math.max(0, dr)), db: Math.ceil(Math.max(0, db))};
    }
  }
  return need;
}
function post(op, extra, cb){
  var body = "op=" + op + "&t=" + encodeURIComponent("__TOKEN__");
  for (var k in extra){ body += "&" + k + "=" + encodeURIComponent(extra[k]); }
  fetch("/action", {method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:body})
    .then(function(r){ return r.json(); })
    .then(cb)
    .catch(function(){ /* 请求失败：浮层照常显示（可能被裁），不假装成功 */ });
}
document.addEventListener("toggle", function(e){
  var d = e.target;
  if (!d.classList || !d.classList.contains("term")) return;
  if (d.open){
    var need = esc();
    if (!need) return;
    post("winfit", need, function(j){
      // 撑开过 ⇒ 视口宽高变了 ⇒ 翻转判定（flipx）要重算
      window.dispatchEvent(new Event("resize"));
      if (d.setAttribute){
        d.setAttribute("data-escape",
          (j && j.ok && !(j.left && (j.left[0] || j.left[1]))) ? "full" : "partial");
      }
    });
  } else if (!terms().length){
    post("winrestore", {}, function(){});
  }
}, true);
})();
</script>
"""


def _escape_js(token):
    """浮层出界逃逸脚本（`__TOKEN__` 由本页口令填充 —— W-06 的纪律：站内自带）。"""
    return _ESCAPE_JS_TMPL.replace("__TOKEN__", _esc(token))


#: ★★ 0.50.0（漂浮最小态）：收缩钮的脚本。为什么不用 `<form>` 直接 POST 303：
#:   收缩会**关掉这个窗口**（服务端 `close_console_windows`）⇒ 表单跳转的
#:   响应大概率没人渲染；而我们仍要把"成了/没成、为什么"**就地写给用户看**
#:   （`#collst`）—— 哪怕窗口随后被关，日志里也有 `[console] collapse`。
#:   请求失败（服务没响应）⇒ 如实说"没动"，**不假装收缩成功**。
_COLLAPSE_JS_TMPL = """
<script>
(function(){
"use strict";
var btn = document.querySelector("[data-coll]");
if (!btn) return;
function say(t){ var s = document.getElementById("collst");
  if (s) { s.textContent = t; } }
btn.addEventListener("click", function(){
  say("正在收缩……");
  var body = "op=collapse&t=" + encodeURIComponent("__TOKEN__");
  fetch("/action", {method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:body})
    .then(function(r){ return r.json(); })
    .then(function(j){
      if (j && j.ok){ say("已收缩成漂浮哨标 —— 点它再展开"); }
      else { say("收缩失败：" + ((j && j.why) || "服务端没说原因")); }
    })
    .catch(function(){ say("请求没发到服务（服务没响应）：Antinel 监理没动，哨标也没起"); });
});
})();
</script>
"""


def _collapse_js(token):
    return _COLLAPSE_JS_TMPL.replace("__TOKEN__", _esc(token))


#: ★ 2026-10-21（TAB 切换卡顿根治·方案 E，创始人拍板"顺带做"）：
#:   切 TAB 的**即时反馈**三件 —— 点击即高亮、顶部细进度条、悬停预取。
#:   治的是"等好久"的**心理时长**（真时长由方案 A/B/C 在服务端修），
#:   本文件零计算变化、零新请求类型。
#:   ★ 渐进增强：`_tabs` 的 href 是真的 ⇒ 禁用 JS 时导航照旧；本脚本
#:     只加一层反馈，删掉它页面一个字节都不少。
#:   ★ 悬停预取打的是**同一个 GET**（`/?v=…`）：0.48.6 B3 起口令在
#:     httpOnly cookie 里，`same-origin` 默认带上 ⇒ 服务端把该视图的
#:     缓存温热，真点击时几乎命中。100ms 是**意图阈值**（鼠标划过不算）；
#:     失败静默（`.catch`）—— 预取是优化，不是功能。
#:   ★ 只 GET 只读视图、不碰任何带副作用的按钮；账本视图的记账已被
#:     方案 C 节流（45s 一次）⇒ 预取不会造成重复落账。
#:   ★ 修饰键/中键＝新窗打开：不动当前页的高亮与进度条（点了却给
#:     当前页换高亮＝假的即时反馈）。
_TAB_JS = """
<script>
(function(){
"use strict";
var bar = document.getElementById('tabprog');
var links = document.querySelectorAll('.tabs a');
function activate(a){
  if (bar) bar.classList.add('run');
  for (var i = 0; i < links.length; i++) links[i].classList.remove('on');
  a.classList.add('on');
}
for (var i = 0; i < links.length; i++) {
  (function(a){
    var tid = null;
    a.addEventListener('click', function(e){
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
      activate(a);
    });
    a.addEventListener('mouseenter', function(){
      if (tid) clearTimeout(tid);
      tid = setTimeout(function(){
        tid = null;
        fetch(a.href, {credentials:'same-origin'}).catch(function(){});
      }, 100);
    });
    a.addEventListener('mouseleave', function(){
      if (tid) { clearTimeout(tid); tid = null; }
    });
  })(links[i]);
}
window.addEventListener('pageshow', function(){
  if (bar) bar.classList.remove('run');
});
})();
</script>
"""


#: 浮层逃逸的当前状态（原矩形/调整后矩形/窗口标识）。**只有一次调整是活的**：
#: 连续开两个浮层时，第二次先还原再调（不会叠床架屋）。
_WINFIT_STATE = {"orig": None, "adj": None, "run_id": None}
_WINFIT_LOCK = threading.Lock()


def _winfit_apply(dr, db, token):
    """把本次Antinel 监理窗口平移/撑开，使右/下沿各多露出 `dr`/`db` 像素。

    返回 dict **如实报告**：`ok`（落位并回读一致）、`moved`（平移量）、
    `grew`（撑开量）、`left`（仍没露出的余量，>0 不许说成"露出了"）、
    `windows`（动了几个窗口）。窗口中找不到 ⇒ `ok=False` 且说清原因。
    ★ 平移优先：不改布局（视口宽高不变 ⇒ 浮层相对位置不变，露出的正是缺的）；
      贴边后才撑开。还露不出来（工作区就到边）⇒ `left` 如实留下余量。
    ★ 还原条件：当前矩形仍等于我们调整后的矩形（用户没手动搬过）。
    """
    import inbox_window as WIN
    with _WINFIT_LOCK:
        try:
            rid = WIN.build_run_id(token)
        except Exception as e:                              # noqa: BLE001
            return {"ok": False, "why": "算不出本次窗口标识：%s" % e}
        hwnds = WIN.find_console_windows(run_id=rid)
        if not hwnds:
            return {"ok": False,
                    "why": "没找到带本次标识（#%s）的 Antinel 监理窗口 —— 不出声假装成功" % rid}
        cur = [WIN.window_rect_of(h) for h in hwnds]
        if any(r is None for r in cur):
            return {"ok": False, "why": "读不到当前窗口矩形"}
        work = WIN.pick_work_area(None)
        base = tuple(cur[0])
        dr, db = max(0, int(dr)), max(0, int(db))
        nl, nt, nw, nh = base
        moved = [0, 0]
        grew = [0, 0]
        if dr:
            room = max(0, base[0] - work.left)
            step = min(dr, room)
            nl -= step
            moved[0], dr = step, dr - step
        if db:
            room = max(0, base[1] - work.top)
            step = min(db, room)
            nt -= step
            moved[1], db = step, db - step
        if dr:
            step = min(dr, max(0, work.right - (nl + nw)))
            nw += step
            grew[0], dr = step, dr - step
        if db:
            step = min(db, max(0, work.bottom - (nt + nh)))
            nh += step
            grew[1], db = step, db - step
        new = (nl, nt, nw, nh)
        ok, why = WIN.place_all(hwnds, new, skip_if_placed=False)
        got = [tuple(WIN.window_rect_of(h)) for h in hwnds]
        placed = ok and all(g == new for g in got)
        if placed:
            _WINFIT_STATE["orig"] = base
            _WINFIT_STATE["adj"] = new
            _WINFIT_STATE["run_id"] = rid
        return {"ok": bool(placed), "moved": moved, "grew": grew,
                "left": [dr, db], "windows": len(hwnds),
                "why": why if not placed else ""}


def _winfit_restore(token):
    """把窗口搬回调整前的矩形。**用户手动搬过就不搬** —— 不与用户抢方向盘。"""
    import inbox_window as WIN
    with _WINFIT_LOCK:
        orig, adj = _WINFIT_STATE.get("orig"), _WINFIT_STATE.get("adj")
        rid = _WINFIT_STATE.get("run_id")
        if not orig or not adj:
            return {"ok": True, "why": "没有待还原的调整"}
        hwnds = WIN.find_console_windows(run_id=rid or WIN.build_run_id(token))
        if not hwnds:
            _WINFIT_STATE.update(orig=None, adj=None, run_id=None)
            return {"ok": False, "why": "要还原时窗口已经不在了"}
        cur = WIN.window_rect_of(hwnds[0])
        if cur is not None and tuple(cur) != tuple(adj):
            # 用户（或别的东西）把窗口搬走了 ⇒ 尊重那个位置
            _WINFIT_STATE.update(orig=None, adj=None, run_id=None)
            return {"ok": False,
                    "why": "窗口被手动搬动过（当前 %s ≠ 调整后 %s），不强行搬回"
                           % (tuple(cur), tuple(adj))}
        ok, why = WIN.place_all(hwnds, orig, skip_if_placed=False)
        _WINFIT_STATE.update(orig=None, adj=None, run_id=None)
        return {"ok": bool(ok), "why": "" if ok else why}


def _bubble_fit(dh, token):
    """把紧急提醒窗**按内容实需**长高（下沿不动，往上长）；返回 dict 如实。

    ★★★ 0.50.1（创始人 2026-10-14 截图「泡泡下沿没露出来」）：
      为什么需要它 —— 落位（`place_all`）只保证"窗口落在目标矩形上"，
      它**不知道内容有没有被裁掉**：BUBBLE_H=148 时落位回读是**一致**的，
      可下沿照样看不见。⇒ "回读一致"不等于"看得见"，缺的正是这条**内容↔窗口**
      的闭环。
      做法与 `_winfit_apply` **同一套机制**（页面量、服务端动窗、回读校验、
      余量如实）：页面量出 `scrollHeight - clientHeight` 报上来，这里只**加高**
      （绝不缩，避免与用户的拖拽打架），锚点在下沿 ⇒ `top` 上移、`h` 增加。

    ★ 边界（不猜、如实）：
      · 找不到本次的紧急提醒窗 ⇒ `ok=False` + 说清（**不假成功**）；
      · 上方已到工作区上沿 ⇒ 长不了多少就长多少，剩下的记在 `left` 里
        （**绝不把"没露全"说成"露全了"**）；
      · 单次最多 `FIT_MAX` 像素 —— 防止页面量错时窗口无限长高。
    """
    import inbox_window as WIN
    FIT_MAX = 240
    try:
        dh = int(float(dh))
    except (ValueError, TypeError, OverflowError):
        return {"ok": False, "why": "缺高度不是有限数字"}
    if dh <= 0:
        return {"ok": True, "grew": 0, "left": 0, "why": "没有要补的高度"}
    try:
        rid = WIN.build_run_id(token)
    except Exception as e:                                  # noqa: BLE001
        return {"ok": False, "why": "算不出紧急提醒窗口身份：%s" % e}
    hs = WIN.find_bubble_windows(run_id=rid)
    if not hs:
        return {"ok": False,
                "why": "没找到带本次标识（#%s）的紧急提醒窗 —— 不出声假装加高了" % rid}
    cur = WIN.window_rect_of(hs[0])
    if cur is None:
        return {"ok": False, "why": "读不到紧急提醒窗当前矩形"}
    l, t, w, h = tuple(cur)
    work = WIN.pick_work_area(None)
    room = max(0, t - work.top)                 # 上方还剩多少可以长
    step = min(int(dh), FIT_MAX, room)
    left = int(dh) - step
    if step <= 0:
        return {"ok": True, "grew": 0, "left": left,
                "why": "上方已到工作区上沿，加不了高（还缺 %d px）" % left}
    new = (l, t - step, w, h + step)
    ok, why = WIN.place_all(hs, new, skip_if_placed=False)
    got = WIN.window_rect_of(hs[0])
    placed = bool(ok) and got is not None and tuple(got) == new
    return {"ok": placed, "grew": step if placed else 0, "left": left,
            "rect": list(new), "windows": len(hs),
            "why": "" if placed else (why or "落位回读不一致")}


def _form(token, op, iid="", note="", label="", cls="", ids=""):
    """一个动作按钮（口令走 hidden 字段 —— 0.35.2 修过的那条：按钮从上线起就 403）。

    ★ 0.35.3：加 `ids`（逗号分隔）—— 「要处理」按事由归并后，
      整组一次性处置（少动作），不必点开一条一条来。
    """
    extra = ("<input type=hidden name=ids value=\"%s\">" % _esc(ids)) if ids else ""
    return ("<form method=\"post\" action=\"/action\">"
            "<input type=hidden name=t value=\"%s\">"
            "<input type=hidden name=id value=\"%s\">"
            "<input type=hidden name=op value=\"%s\">"
            "<input type=hidden name=note value=\"%s\">%s"
            "<button%s>%s</button></form>"
            % (_esc(token), _esc(iid), _esc(op), _esc(note), extra,
               (" class=\"%s\"" % _esc(cls)) if cls else "", _esc(label)))


def _host_label(h):
    """工具标签 → 页面显示名（显示名真源＝`host_shield.host_names()`，本处只兜底）。

    ★ 0.53.0（T3.3）：为什么不在本文件另立一张名表 —— 那就是第二份实现，
      而 `rules/hosts/*.json` 的读取权归登记表宿主模块。宿主没写 `name`
      就**照实显示标签**（`host_display_name` 的语义），绝不编。
    """
    h = str(h or "").strip()
    if not h:
        return ""
    try:
        import host_shield as _hs
        return _hs.host_display_name(h)
    except Exception:                                       # noqa: BLE001
        return h


def _item_html(it, token, posture=None, show_host=False):
    """一条记录：★ 收起时**一个按钮都没有**，点开才给两个动作。

    ★ 创始人 2026-10-06：「每一条右侧都是三个按钮，占地方不说，太多了也不会有人去点」
      ⇒ 行内 0 按钮、展开后 2 个（知道了 / 忽略）。
    ★「标为已读」**已取消**（创始人拍板①）—— 点开**自动**记为已读（见 `_READ_JS`）。
    ★★ 0.53.0（T3.3，设计 §14.3 第 3 条）：`show_host` 由调用方按
      「本次载入的记录里观测到 ≥2 个工具」判定，**单工具机器上不渲染** ——
      否则同一句话在每一行重复几百次，信息量为 0。
    """
    if it.state in M.OPEN_STATES:
        acts = (_form(token, "done", it.id, label="知道了", cls="ok")
                + _form(token, "ignored", it.id, note="判断无需动作", label="忽略"))
    else:
        acts = _form(token, "read", it.id, label="重开")
    dot = "<span class=\"unread-dot\"></span>" if it.state == "unread" else ""
    # ★★ 0.51.2 **第二轮**（创始人 2026-10-17 四张截图，裁定见
    #   docs/Antinel·界面文案问题清单 v1.0）：
    #   第一轮改完仍是鸟语——规则编号写两遍、「（哪条防护规则拦下它的）」看不懂、
    #   「命中「os.remove」」不告诉用户删什么、裸 ISO 时间、64 位核对号。
    #   ⇒ 详情行（第二行）**整体重做**，唯一实现是 `M.record_meta(it)`：
    #     「执行文件或目录删除命令，目标 _dbg_logo.txt · 规则 DST-01 · 北京时间 10-17 09:23」
    #   规则编号只出现一次；时间走时区命名（海外机器显示美西/美东时间）。
    #   行内时间（`.when`）保持 MM-DD HH:MM 短式（全站唯一短式 `_ts_hm`）。
    meta = M.record_meta(it)
    # ★ 0.53.0（T3.3）：工具徽标（条件渲染 —— 见 docstring）
    _hb = ""
    if show_host:
        _hn = _host_label(getattr(it, "host", ""))
        if _hn:
            _hb = "<span class=\"hbadge\">%s</span>" % _esc(_hn)
    return ("<details class=\"item %s %s\" data-id=\"%s\" data-token=\"%s\">"
            "<summary><span class=\"badge %s\">%s</span>%s"
            "<span class=\"t\">%s%s</span><span class=\"when\">%s</span></summary>"
            "<div class=\"det\"><p class=\"m\">%s</p>%s"
            "<div class=\"act\">%s</div></div></details>"
            % (_esc(it.level.lower()), _esc(it.state), _esc(it.id), _esc(token),
               _esc(it.level.lower()), _esc(it.level), _hb, dot, _vis(it.title),
               _esc(_ts_hm(it.ts)), _vis(meta),
               _rem_html(it, token, posture), acts))


# --------------------------------------------------------------------------
# 0.36.0：失守归因面板
# --------------------------------------------------------------------------
def _rem_html(it, token, posture=None):
    """失守条目的「为什么 & 怎么办」面板（R0 才有；L1/L2 不给）。

    ★ 为什么只给 R0：L2 是「已拦下的操作」，L1 是「知情即可」，
      它们**不需要归因**—— 归因面板是给"防线没生效"的。
    ★ 展开态才渲染（`<details>` 默认收起）—— 245 条记录全渲染会让
      窄面板一打开就是几万字节，而用户通常只看前几行。
    """
    if str(getattr(it, "level", "")).upper() != "R0":
        return ""
    try:
        import remediation as RM
        # ★ 0.51.2 第二轮：**态势穿线** —— 归因模块据此决定「现在能做什么」
        # ★ 0.53.0 T4：缺省就地现探 —— 0.51.2 那条穿线只在调用方记得传时
        #   成立；"调用方忘了传"正是本轮那个死灰复燃按钮的成因。到点消费前
        #   解析，比要求每个调用方都记得更牢靠。
        posture = posture or posture_now()
        a = RM.attribute(it, posture=posture)
    except Exception as e:                                   # noqa: BLE001
        # ★ 归因模块坏了也不能让整页500 —— 如实说"这一项算不出来"，
        #   并**仍然给一步可做的**（去运行状态页看现探）。
        a = {"kind": "unknown", "title": "这一项归因算不出来",
             "b_class": False, "by_text": False,
             "cause": "归因模块报错，这一项的原因算不出来。",
             "severity": "",
             "severity_note": "",
             "actions": [{"op": "info", "label": "看运行状态页",
                          "cmd": "", "hint": "",
                          "href": "/?v=health", "ack": False}],
             "cost": ""}

    # ★★ 0.37.1：归因文案走 `GL.render()`（**不是** `_esc`）——
    #   归因作者习惯写 markdown 的 `**重点**`，而 `_esc` 只是转义，
    #   星号会原样出现在屏幕上（2026-10-09 实测：首页每一条失守的"为什么"
    #   里都带着 `**`，8 个归因类无一幸免）。`GL.render()` 既吃 markdown
    #   又只放行 `<b>/<code>`，且仍会转义用户输入 ⇒ 两头都安全。
    def _tx(s):
        # ★★ 0.51.2（创始人 2026-10-17「都在说鸟语」）：归因面板的文案除了
        #   markdown（`GL.render`），还要**过一遍机器腔人话化** ——
        #   因为 `cause` 段会把**原始 detail**（含 `pid=` / `self-check-failed:`
        #   等）嵌进句子里，而这里走的是 `GL.render` 而非 `_vis` ⇒
        #   不补这一步，面板里就漏出鸟语。
        #   `humanize` 内部已保护文件名/路径/反引号内容（不会改坏命令）。
        return GL.render(M.humanize(str(s or "")))

    badge = ('<span class="bclass">修不了根因 · 请选一条路</span>'
             if a.get("b_class") else "")
    txt = ("<span class=\"why\">这一条是靠记录文案认出来的</span>"
           if a.get("by_text") else "")

    # ★★ 0.53.0 T4（创始人 2026-10-19 截图裁定「把违和、废话都清理」）：
    #   四段制 → 两段制，动作不再单列一段：
    #     ① 发生了什么   —— 当时的事
    #     ② 有多严重     —— 后果 ＋ 需要时的「现在实测」一句
    #     然后直接是动作（能做的才上屏）
    #   删掉的：
    #     · ③ 你能做什么 —— 标题与编号是自问自答；按钮本身就是祈使句，
    #       再说一遍"你能做什么"是同义重复（ASD-STE100：不多余）。
    #     · ④ 不做的后果 —— 创始人定性「完全是废话」：它把 ② 已经说过的
    #       后果换个说法再说一遍，且通篇是"你什么都不做就会…"的恐吓式预告。
    #     · 每个动作下面的说明段（"点这个会当场重试并复测；不会假绿"）——
    #       讲的是产品怎么实现，不是用户要办的事。
    segs = [
        '<div class="seg root"><h4>① 发生了什么</h4><p>%s</p>%s</div>'
        % (_tx(a.get("cause")), txt),
    ]
    sev = _tx(a.get("severity") or "")
    note = _tx(a.get("severity_note") or "")
    if sev or note:
        segs.append('<div class="seg sev"><h4>② 有多严重</h4>%s%s</div>'
                    % (('<p>%s</p>' % sev) if sev else "",
                       ('<p class="note">%s</p>' % note) if note else ""))

    # 动作 —— **只上真能做的**：ack（纯"收下这条通知"）不上屏，
    #   条目底部已经有「知道了」，同一张卡片里出现两次就是噪音。
    items_html = []
    for act in a.get("actions") or []:
        if act.get("ack"):
            continue
        op = act.get("op")
        cls = {"fix": "go", "retry": "go", "rearm": "go",
               "drop": "drop", "accept": "risk", "info": ""}.get(op, "")
        why = act.get("hint") or ""
        why_html = ('<div class="why">%s</div>' % _tx(why)) if why else ""
        items_html.append(
            '<div class="arow"><b>%s</b>%s<div class="pick">%s</div></div>'
            % (_tx(act.get("label") or op), why_html,
               _rem_pick_buttons(it, token, op, cls, act)))
    if items_html:
        segs.append('<div class="seg act">%s</div>' % "".join(items_html))

    # ★ badge 放在**body 第一段**（不是 summary 里）——
    #   `_rem_panel_only()`给归并行复用时只取 body，badge 放summary 会被丢掉。
    #   实测踩过：归并行的三选一按钮都出来了，badge 却0 个。
    head = ('<p>%s</p>' % badge) if badge else ""
    # ★ 0.53.0 T4：收起壳的标题 —— 「为什么 & 怎么办」里的 `&` 是半个英文
    #   符号，且"怎么办"在动作区已改成不单列（按钮本身就是祈使句）
    #   ⇒ 收成「为什么、怎么办」。
    return ("<details class=\"rem\"><summary><span class=\"why\">"
            "为什么、怎么办</span>"
            "<span class=\"t\">%s</span></summary>"
            "<div class=\"body\">%s%s</div></details>"
            % (_tx(a.get("title")), head, "".join(segs)))


#: 三类动作 → 按钮文案。★ B 类三选一必须**都在**页面上（创始人拍板）。
#: ★ 0.51.2 第二轮：去掉 `rearm`（「按正规入口重新布防」）—— 研发/运维动作
#:   不进用户面板（创始人：用户不会修，我也不会让用户修）。
_PICK = {
    "fix": ("试一下，看能不能修好", "go"),
    # ★ 0.52.0（剃刀，裁定 #4）：按钮文案与动作标题分工 —— 标题讲
    #   「这是什么选项」（remediation 的 ACT_RETRY label「重新拉起监理」），
    #   按钮是点下去的那一下。旧版两者同文（「重新拉起监理」×2）＝
    #   同一行里同一个意思出现两次，与 0.37.2 accept 的同型教训一致。
    "retry": ("现在重新拉起", "go"),
    "drop": ("承认打不赢，移出监管", "drop"),
    # ★ 0.37.2：「就这样，我不处理」⇒「我不处理，我担着」——
    #   上面那条选项标题彼时是「就这样放着，我自己盯着」（0.53.5 STE100 起
    #   为「…我自己守着」），按钮再写"就这样"⇒ 同一行两个"就这样"；
    #   且"我担着"点出这是**签字担责**（红按钮的本意）。
    "accept": ("我不处理，我担着", "risk"),
    "info": ("知道了", ""),
}


def _rem_pick_buttons(it, token, op, cls, act):
    """一个动作对应的一组按钮。

    ★ 关键：**点任何按钮都会留下一条 `remediation` 记录**
      （走既有 `/action` 通道），所以"我处理过什么"在链上可查——
      不做成"点完就没"的假按钮。
    ★ 两条**不执行**的动作（drop / accept）只记录决定，不动防线：
      擅自「移出监管名单」= 擅自放弃保护，不是产品该替用户做的选择。
    """
    label, bcls = _PICK.get(op, (act.get("label") or op, cls))
    n = [0]

    def form(o):
        n[0] += 1
        return _form(token, o, it.id, note=(act.get("label") or o),
                     label=label, cls=bcls)
    if op in ("fix", "retry"):
        return form("guard_fix")
    if op == "drop":
        return form("remediation_drop") + _form(
            token, "remediation_ack", it.id, note="我已知代价，先放着",
            label="先不处理，只记一笔", cls="risk")
    if op == "info":
        # ★★ 0.53.0 T4：info 行**不再画「知道了」按钮** ——
        #   · 纯告知动作（看原文/查是谁动的）没有"点一下"的必要，
        #     卡片底部已有「知道了」；
        #   · 真要指路（看运行状态页）就给一条真链接，不拿按钮冒充动作
        #     （按钮点了只记一笔，链接才真到那里）。
        h = str(act.get("href") or "")
        return ('<a class="btn" href="%s">%s</a>'
                % (_esc(h), _esc(act.get("label") or "打开")) ) if h else ""
    if op == "accept":
        return form("remediation_ack")
    return form("remediation_ack")


def _group_html(g, token, bucket=None, total=None, posture=None, host_dist=""):
    """一类/一事归并成一行。

    ★ 0.47.0：`total` ＝ 这一档的**记录总条数**（分母）。归并行上的「×N」是
      "这一事由发生了几次"，它是**分子** ⇒ 必带分母（方案 §5 步三）。
      取不到分母时传 `None` —— 判据会把它抓出来，所以调用方**必须**给。

    ★ 0.35.3 修正（**真回退**，被 P3 XSS 与 P12 按钮两条判据当场抓出来）：
      旧版归并行**只渲染标题** ⇒ 一旦「要处理」档也归并，
      ① 原因(detail)整条不见（XSS 转义串因此从页面上消失）；
      ② 「知道了/忽略」按钮全没了。
      ⇒ 那等于**把事藏起来**，正好违背创始人「要处理要看得见、要能动手」。
      现在：**原因必出**；「要处理」档额外给**批量动作**＋**钻取**（看这 N 条）。
    """
    lv = str(g["level"]).lower()
    n = int(g.get("count") or 0)
    ids = ",".join(str(x) for x in (g.get("ids") or []))
    drill_q = urlencode({"v": "inbox", "f": "ids:" + ids})
    drill = ("<a class=\"btn\" href=\"/?%s\">看这 %d 条</a>"
             % (drill_q, n))
    if bucket == M.BUCKET_ACTION:
        # ★ 同一事由 ⇒ 一件事：给「一次性处置」，用户不必点开 13 次。
        acts = (_form(token, "done_all", label="知道了（全部 %d 条）" % n, ids=ids)
                + drill)
    else:
        acts = drill
    # ★★ 0.51.2 第二轮：归并行的说明行**也走** `M.record_meta`（不带时间——
    #   行内另有「最近/最早」时间段）⇒ 归并行不再露出「规则 X · 命中「Y」」
    #   那串机器腔（创始人「全覆盖无遗漏」，归并行同病）。
    _fi = g.get("first_item")
    scene = (M.record_meta(_fi, with_time=False) if _fi is not None
             else (g.get("detail") or "").strip())
    meta = " ｜ ".join(x for x in (
        scene,
        "最近 %s" % _ts_hm(g["last_ts"]),
        ("最早 %s" % _ts_hm(g["first_ts"])) if n > 1 else "",
        # ★★ 0.53.0（T3.3，设计 §14.3 第 6 条）：**归并行尾部**给工具分布，
        #   **不新增小节** —— 另开一节＝同一页两套计数（「重复即红」）。
        #   组内全无归因（旧记录）⇒ 空串，位置上什么都不出现（不写「未知 N 条」：
        #   那会把"不知道"说成一种工具，P18 同一条纪律）。
        host_dist,
    ) if x)
    # ★ 0.36.0：归并行也要有归因面板 —— 「要处理」档走的是这条路，
    #   而用户看到的正是这个档；只有单条有面板的话，归并后的 R0
    #   反而拿不到"为什么"，等于功能在最主要的入口上缺席。
    #   用组里**第一条**归因（同因记录根因相同 —— 归并键本身就是按事由分的）。
    rem = ""
    if lv == "r0":
        try:
            import remediation as RM
            first = g.get("first_item") or g.get("items")[0]
            rem = _rem_panel_only(first, token, posture)
        except Exception:                                   # noqa: BLE001
            rem = ""
    return ("<details class=\"item grp %s\" data-ids=\"%s\" data-token=\"%s\">"
            "<summary>"
            "<span class=\"badge %s\">%s</span>"
            "<span class=\"t\">%s</span>"
            "<span class=\"pill sm\">%s</span>"
            "<span class=\"when\">%s</span></summary>"
            "<div class=\"det\"><p class=\"m\">%s</p>%s"
            "<div class=\"act\">%s</div></div></details>"
            % (_esc(lv), _esc(ids), _esc(token), _esc(lv), _esc(g["level"]),
               _vis(g["title"]),
               # ★ 0.47.0：×N 是分子 ⇒ 带上分母（该档总条数）。
               # ★ 0.50.4（Q-05）：`×11 / 13 条` 不再用乘号 —— 中文语境里
               #   「×11」不是「共 11 条」，与后面的「/ 13 条」连读更像算式。
               #   ⇒ 直述「11 条（这一档共 13 条）」，分子分母各自带单位。
               # ★ 0.53.5（STE100 体检 S-10）：「这一档共」→「本级共」——
               #   读者没有"档"这个概念，行标题已经说了是哪一级。
               _esc("%d 条（本级共 %d 条）" % (n, int(total or 0))),
               _esc(_ts_hm(g["last_ts"])),
               _vis(meta), rem, acts))


def _rem_panel_only(it, token, posture=None):
    """只渲染归因面板本体（不给外层 `<details class="rem">` 的收起壳）。

    归并行已经有自己的收起壳（`details.item.grp`），再套一层会双层折叠。
    """
    full = _rem_html(it, token, posture)
    if not full:
        return ""
    i = full.find("<div class=\"body\">")
    j = full.rfind("</div></details>")
    if i < 0 or j < 0:
        return ""
    return full[i:j].replace("<div class=\"body\">", "<div class=\"rem\">", 1)


def _view_inbox(items, token, filt, now=None, posture=None):
    """收件箱。★ 三档（要处理 / 看一眼 / 归档），窗口默认 24 小时。

    ★★ 0.53.0 T4：`posture` 缺省就地现探（**不许把 None 往下传**）——
      上一轮正是"调用方忘了传"让归因面板的按钮门控退化成恒真。
      到点消费前解析一次，是"一个事实只从一个地方取"的收口。

    ★★ 0.35.3（创始人 2026-10-06「**尽可能少让人处理**」）：
      · 「要处理」＝**只有你本人动手才能解决**的事（`needs_owner`）。
        Antinel 自己已经处理掉的（拦下 / 自愈 / 状态变更）都在「看一眼」——
        你知情即可，不用动手。
      · 「要处理」**按事由归并**：14 条同因记录 = **1 件事**。
        实测本机 24 小时窗口内「要处理 37 条」其实是 **3 件事**。
        用户看到 37 条 → 37 条一起被忽略；看到 3 件事 → 会去做。
    """
    act_rows = M.filter_items(items, M.BUCKET_ACTION, now=now)
    n_act = M.count_groups(act_rows)          # ★ 显示的是**件事数**，不是记录条数
    b = M.counts_by_bucket(items, now=now)
    n_all = len(items)
    posture = posture or posture_now()

    def f(v, label, n, tip, unit):
        # ★ 0.37.2：四个数字**单位不同**（要处理＝件事，其余＝条记录），
        #   并排摆在一起却不说明，读者会拿 4 与 44、293 直接比大小 ——
        #   那是异质单位做比较（本项目 F54）。当时把单位只放 hover title。
        # ★★ 0.48.5（交接件 §5.4 丙1）：单位**可见化** —— hover 里的字
        #   鼠标不在上面就看不见，而并排比较恰恰发生在看见的那一刻。
        #   现在单位紧跟数字（`.unit` 小字弱化，不抢数字），口径归「？」词条。
        #   ★ 注意：这不是算错，是**单位异质被并排**（F54 同型，判据 U-08 守）。
        cls = " class=\"on\"" if v == filt else ""
        return ("<a href=\"/?v=inbox&f=%s\"%s title=\"%s\">%s <b>%d</b>"
                "<span class=\"unit\">%s</span></a>"
                % (v, cls, _esc(tip), _esc(label), n, _esc(unit)))

    # ★★ 0.48.5（交接件 §5.6 乙3）：补 `<h2>` —— 收件箱页此前无页面名，
    #   而其余三页都有（同一页三个身份：title/选项卡/无 h2 —— 乙4 的组成
    #   部分之一）。文案取 `PAGE_TITLES`（唯一真源，0360 硬锁四键不动）。
    # ★★ 0.48.5（§5.6 乙1）：四个筛选标签后各跟一个**裸「？」芯片** ——
    #   标签本身是链接（塞不进 details），芯片作**兄弟节点**紧随其后，
    #   不嵌套（`<a>` 内嵌 interactive 内容是坏味道）。
    head = ('<h2>%s</h2>' % PAGE_TITLES["inbox"]
            + "<div class=\"filters\">"
            + f(M.BUCKET_ACTION, "要处理", n_act,
                "单位：件事（同一事由的多条记录合成一件）", "件")
            + GL.chip(M.BUCKET_ACTION, mk=True)
            + f(M.BUCKET_INFO, "看一眼", b[M.BUCKET_INFO],
                "单位：条记录（不做归并，一条算一条）", "条")
            + GL.chip(M.BUCKET_INFO, mk=True)
            + f(M.BUCKET_ARCHIVE, "归档", b[M.BUCKET_ARCHIVE],
                "单位：条记录（不做归并，一条算一条）", "条")
            + GL.chip(M.BUCKET_ARCHIVE, mk=True)
            + f("all", "全部记录", n_all,
                "单位：条记录（这次读到的全部条目）", "条")
            + GL.chip("all", mk=True) + "</div>"
            # ★★ 0.48.5（交接件 §5.3 甲2 / §5.4 甲4）：一排数字的口径说明走
            #   `M.reading_note()`（唯一实现）—— 旧句承诺「分母均为 N 条」，
            #   对四个 tab 至少三个是假的（要处理按件事归并、归档无时间上限），
            #   「最近 24 小时」也不随页面停留滚动。删谎，不删口径本身：
            #   分母与单位下沉到每 tab 可见单位 ＋「？」词条口径行（U-03/U-08 守）。
            + ("<div class=\"note\" style=\"margin:0 0 8px\">%s</div>"
               % _esc(M.reading_note()))
            # ★★ 0.50.4（Q-25 ＋ Q-11，2026-10-15 品质扫描，创始人点头）：
            #   原先这里挂了一整块折叠入口「页面上的词都是什么意思（点开看）」，
            #   **本版删掉**。三条理由，都可复核：
            #   ① 它列的 14 个词里 `Ls`／`granary`／`L0` 三个**在页面任何位置
            #      都不出现**（脚本逐 key 查 `GL.chip` 落点：均为 0）—— 给页面上
            #      没有的东西配定义，等于把说明书摆进界面（与 Q-14 同型）；
            #   ② 其余 11 个词**各自都有「？」落点**：筛选条 4 ＋ 级别药丸 3 ＋
            #      顶部灯 1 ＋ 各处 `GL.chip`（0.53.0 T3.2 起药丸那 3 颗随顶部计数排
            #      撤走，R0/L2/L1 的落点改在日报四指标 —— U-04 基线随之 8→5）。
            #      同一页两套入口 ⇒ 一屏十几个「？」；
            #      在安全语境里，用户第一反应是「有十几处有问题」（Q-11 双入口）；
            #   ③ 创始人原话：「根本没必要写，应直接去掉」。
            #   ⇒ 删它**不减**任何曾在页面出现过的词的可达性：U-04 数的是
            #     `class="term mk"` 落点（当时 8 个；0.53.0 起 5 个），这里删的是
            #     `GL.line` 整块。
            )
    rows = M.filter_items(items, filt, now=now)
    # ★★ 0.53.0（T3.3，设计 §14.3 第 3 条）：工具徽标的开关＝**本次载入的
    #   全部记录**里观测到 ≥2 个工具（＝设计原话"本机观测"）。刻意**不按
    #   当前筛选**算：否则按工具筛一次、徽标自己就消失了 —— 同一个事实
    #   在两种筛选下两种显示。单工具机器上恒不出现（那才是 v0 的错法：
    #   每行重复几百次同一个工具名）。
    _show_host = M.host_count(items) >= 2
    if not rows:
        if filt == M.BUCKET_ACTION:
            empty_title = "当前读取到的记录里，没有要你处理的事。"
        elif filt == M.BUCKET_INFO:
            empty_title = "当前「看一眼」中没有记录。"
        elif filt == M.BUCKET_ARCHIVE:
            empty_title = "当前「归档」中没有记录。"
        elif filt == "all":
            empty_title = "本次载入的记录为空。"
        else:
            empty_title = "当前筛选「%s」没有匹配记录。" % _esc(M.filter_label(filt))
        return head + (
            "<div class=\"hint\"><b>%s</b>"
            "<p class=\"note\">「要处理」只放只有你本人动手才能解决的事。"
            "Antinel 自己已挡下或自愈的事项在「看一眼」。更早的事项只会在其链文件仍被读取时显示在「归档」；"
            "本页不是永久全历史清单。</p></div>" % empty_title)
    # ★ 「要处理」按**事由**归并（同因 14 条 = 1 件事）；
    #   "看一眼/归档"按类型归并；只有「全部」和钻取视图才一张一条。
    #   ★ 单条的分组**退回普通条目**：不藏原因、不藏按钮（真回退的修法）。
    if filt == M.BUCKET_ACTION:
        groups = M.group_items(rows)
        by_id = {it.id: it for it in rows}
        parts = []
        for g in groups:
            if g["count"] == 1 and g["ids"] and g["ids"][0] in by_id:
                parts.append(_item_html(by_id[g["ids"][0]], token, posture,
                                        show_host=_show_host))
            else:
                parts.append(_group_html(
                    g, token, bucket=M.BUCKET_ACTION, total=len(rows),
                    posture=posture,
                    # ★ 与徽标同一个开关：单工具机器上这行分布恒等于"全部那一
                    #   个工具"，每行再说一遍就是 v0 的噪声错法。见 `_show_host`。
                    host_dist=(M.host_phrase([by_id[i] for i in g["ids"]
                                              if i in by_id],
                                             label_of=_host_label)
                               if _show_host else "")))
        # ★ 0.37.1 去重：归并说明**不重复数字**（件数已在筛选条、24h 各级
        #   口径已在顶部条那排药丸各显示一次），这里只说"怎么读这些行"。
        # ★ 0.37.2 精简（创始人 2026-10-09「解释放注释里，点问号看」）：
        #   原句 36 字，把"每行都带原因""钻到单条"也写上了 —— 那是解释，
        #   不是读法。主界面只留**一句怎么读**，其余归词条。
        # ★ 0.48.5（交接件 §5.6 乙2）：原句「同一事由已合成一行；点开可整组
        #   处置。」的后半是**替用户描述他的动作**（W08），但前半传达的是
        #   **能力**（整组处置）⇒ 保留能力、只删「点开」，改写为能力表述。
        note = ("<div class=\"note\" style=\"margin:0 0 10px\">"
                "同一事由已合成一行，可整组一次性处置。</div>")
        return head + note + "".join(parts)
    if filt in (M.BUCKET_INFO, M.BUCKET_ARCHIVE):
        groups = M.group_by_kind(rows)
        by_id2 = {it.id: it for it in rows}
        # ★ 0.53.0（T3.3）：工具分布同样挂在归并行尾部（同一函数，不另写）
        return (head
                # ★ 0.37.2 去重：「共 N 条」的 N 与筛选条上同一个 tab 的数字
                #   **逐字相同**（两者都是 `filter_items` 的条数）⇒ 同一屏
                #   出现两遍。筛选条是导航（随身可见），这里只留"怎么读这些行"。
                # ★ 0.48.5（交接件 §5.6 乙2）：「，点一类看单条」删 ——
                #   替用户描述他即将做的动作；链接本身可点（P12 钻取不删）。
                + ("<div class=\"note\" style=\"margin:0 0 10px\">"
                   "%s：按类型归并。"
                   "</div>" % _esc(M.filter_label(filt)))
                + "".join(_group_html(
                    g, token, bucket=filt, total=len(rows), posture=posture,
                    host_dist=(M.host_phrase(
                        [by_id2[i] for i in (g.get("ids") or []) if i in by_id2],
                        label_of=_host_label) if _show_host else ""))
                          for g in groups))
    if filt not in ("action", "all"):
        head += ("<div class=\"note\" style=\"margin:0 0 10px\">"
                 # ★ 0.47.0：筛选结果是分子 ⇒ 分母＝本次载入的全部条数。
                 "筛选：<b>%s</b> · %d / %d 条（<a href=\"/?v=inbox&f=all\">"
                 "返回已载入记录</a>）"
                 "</div>" % (_esc(M.filter_label(filt)), len(rows), n_all))
    return head + "".join(_item_html(i, token, posture, show_host=_show_host)
                          for i in rows)


def _view_report(rep, token, items=None):
    """日报。★ 每个数字都可点钻取（创始人第四条意见："我却无法看到具体情况"）。

    ★ 0.37.1：`items` 由调用方传入（`daily_report` 本身不带），供「现在」行
      走与首页**同一套**六态灯态算法（`M.light`）—— 否则日报与首页会各算
      各的，同一时刻显示两个状态词。
    """
    Lv = rep["levels"]
    W = rep.get("window_levels") or {}
    hrs = rep.get("window_hours", 24)

    def metric(k, n, var, filt, note=""):
        """★ 0.35.3：标签本身是**可点开的术语**（定义只有一份，见 `glossary`）。

        ★ 0.36.1 文字修订（创始人截图二）：
          原标题写「拦截（L2）？（最近 24 小时）」，四张卡片各写一遍 ——
          同一个限定词重复四次，标题反而被撑到换行、字挤成一列。
          ⇒ 时间范围**只在小节标题里说一次**，卡片只留档位名。
          ⇒ 数字下面的说明也删掉：数字本身是链接（有下划线），
            还要再写一句「点数字看是哪几条」是**重复用户的动作**。
        """
        scoped_filter = "win:%d:%s" % (hrs, filt)
        # ★ 0.47.0（方案 §5 步三）：这个数是分子 ⇒ 同行带分母（窗口内总记录数）。
        # ★★ 0.53.5（STE100 体检 S-03）：卡片标题数的是**过去 24 小时**的事
        #   ⇒ 显示词走 `event_short()`（出事/挡下/提醒），不再用只认此刻的
        #   灯态词（旧标题「失守（R0）」把状态词当事件词数，与术语表词条
        #   「失守只认此刻」自相矛盾）。词条本名与定义进展开体首行
        #   （`chip()` 的 head 机制，data-t 落点不变 ⇒ P13 照绿）。
        return ("<div class=\"metric\"><div class=\"k\">%s</div>"
                "<div class=\"v\" style=\"color:var(%s)\">"
                # ★ 0.50.4（Q-02）：给分母带上**单位**（条）—— 单位可见（U-08
                #   的立意：只放 hover title 不算可见）。
                # ★★ 0.51.0（品质审查拍板点 1，2026-10-16）：**撤「/ N 条」分母**
                #   —— 三无数（无落点/无就地口径），需要页头一整句解释才看得懂
                #   ＝显示自证失败；失守卡「0 / 47」误导（失守不是从记录里抽样）；
                #   要处理卡件数除条数＝Q-03 自己批判的同型。⇒ 只留绝对数＋单位
                #   （`.unit` 小号灰显）；占比参照由「当日合计 · 共 N 条」承担。
                #   分母纪律在顶部条后缀/拉起行/托盘照旧（0470 S95、U-97 不动）。
                "<a href=\"/?v=inbox&f=%s\">%d</a>"
                "<span class=\"unit\"> 条</span></div>"
                "</div>"
                % (GL.chip(k, text=M.event_short(k)), var, _esc(scoped_filter), n))

    #: ★ 0.48.5（交接件 §5.4 甲4）：这一排四个数字的口径说明走
    #   `M.reading_note()` —— 与收件箱筛选条**同一个唯一实现**（旧版这里另写
    #   一句内联说明，两处同源破裂；那句还带着「分母均为」的假承诺 ——
    #   四个数的分母其实是窗口内三档之和，不是「本次载入的全部记录」）。
    #: ★ 0.47.0 步三的分母仍在：`_win_total` ＝ 窗口内三档记录之和，
    #   继续供四个 metric 的 `/ N` 与拉起次数行使用（判据 U-97 连带守）。
    _win_total = sum(int(W.get(k, 0) or 0) for k in ("R0", "L2", "L1"))
    _win_note = ("<div class=\"note\" style=\"margin:0 0 8px\">%s</div>"
                 % _esc(M.reading_note()))

    # ★ 0.37.2：顺序改**由重到轻**（失守 → 拦截 → 注意 → 要处理）。
    #   旧版是「拦截 · 注意 · 失守 · 要处理」—— 最重的排在第三位，
    #   与顶部条药丸、收件箱归并列表的"重在前"不一致。
    m = (_win_note + "<div class=\"metrics\">"
         + metric("R0", W.get("R0", 0), "--r0", "lv:R0")
         + metric("L2", W.get("L2", 0), "--l2", "lv:L2")
         + metric("L1", W.get("L1", 0), "--l1", "lv:L1")
         + "<div class=\"metric\"><div class=\"k\">%s</div><div class=\"v\">"
           "<a href=\"/?v=inbox&f=action\">%d</a>"
           "<span class=\"unit\"> 件</span></div></div></div>"
         % (GL.chip("action"), rep.get("action_groups", 0)))

    # ★★ 0.37.2：**删掉「现在的防线状态」整张卡**。
    #   理由不是"它没用"，而是它**与顶部条重复且会打架**：
    #   顶部条已给出状态词（六态，且把"此刻"这一维与"24h 账"那一维
    #   **分句**写在同一条副标题里），日报页这张卡再给一个状态词 ⇒ 同屏两个状态词
    #   （实测：顶部「失守」＋卡内「值守中」），用户不知道信哪个 ——
    #   这正是创始人点名的"违和感"。
    #   ⇒ 状态词只留顶部那一处；日报页只放**日报自己的数**。
    _revived = rep.get("revived_window", 0)
    # ★ 措辞与运行状态页统一（旧版日报写「10 次（查看记录）」、
    #   运行状态写「10 次（点数字看每一次）」—— 同一件事两种说法）。
    # ★ 0.47.0：拉起次数是分子 ⇒ 分母＝窗口内总记录数。
    # ★★ 0.50.4（Q-03）：**不再写成「2 次 / 13」**。分子单位是「次」、分母单位是
    #   「条记录」，两个不同质的量摆成一条斜杠＝做了没有意义的除法（同型：
    #   「要处理 0 件 / 13 条」）。⇒ 各自带自己的单位、用分号分开，不再相除。
    _revived_link = ("<a href=\"/?v=inbox&f=win:%d:kind:host_shield_revived\">"
                     "%d 次</a>；同期记录 %d 条"
                     % (hrs, _revived, _win_total))
    _day = _esc(rep["day"])
    # ★ 0.47.0：当日三档各是分子 ⇒ 分母＝当日全部记录条数（当日 ＝ 24 小时窗口）。
    _day_total = sum(int(Lv.get(k, 0) or 0) for k in ("R0", "L2", "L1"))
    # ★★ 0.53.5（STE100 体检 S-02）：这里数的是**过去**的事 ⇒ 词走
    #    `event_short()`（出事/挡下/提醒），不再用只认此刻的灯态词。
    #    旧写法「失守 3」把状态词当事件词数，与术语表词条自相矛盾。
    _today_levels = ("<a href=\"/?v=inbox&f=day:%s:lv:R0\">%s %d</a> ｜ "
                     "<a href=\"/?v=inbox&f=day:%s:lv:L2\">%s %d</a> ｜ "
                     "<a href=\"/?v=inbox&f=day:%s:lv:L1\">%s %d</a>"
                     # ★ 0.48.5（交接件 §5.4 丙2）：「分母 N」改成直述「共 N 条」——
                     #   「分母」是术语词条里的词（口径行才是它的定义处），
                     #   正文里裸它是把术语当时尚词；意思一点没少。
                     " ｜ 共 %d 条"
                     % (_day, M.event_short("R0"), Lv["R0"], _day, M.event_short("L2"), Lv["L2"],
                        _day, M.event_short("L1"), Lv["L1"], _day_total))
    pr = ("<div class=\"card\"><div class=\"rows fit\">"
          "<div class=\"row\"><span class=\"k\">最近 %d 小时%s</span><span>%s</span></div>"
          "<div class=\"row\"><span class=\"k\">%s 当日合计</span><span>%s</span></div>"
          "</div></div>"
          % (hrs, GL.chip("sentinel", "监理被拉起过"), _revived_link,
             _day, _today_levels))

    rules = ""
    if rep["rules"]:
        mx = max(r["count"] for r in rep["rules"]) or 1
        # ★ 0.37.2：**不画条形图** —— 实测本机 3 条规则各命中 1 次，
        #   `int(6*1/1)=6` ⇒ 三条都是满格 ██████，"1 次"被画成"最多"。
        #   条形图在小样本上**系统性说谎**（分母＝样本最大值，不是绝对量），
        #   而它旁边明明就写着数字 ⇒ 图与数打架。数字已经排序，图是多余的。
        # ★ 0.47.0：命中次数是分子 ⇒ 分母＝当日**全部**规则的命中总数，
        #   窗口＝当日（24 小时）。格式走 `M.count_text`（唯一实现）。
        # ★ 0.50.4（Q-10）：总量**上移到卡片标题**（可见单位），行内只留次数 ——
        #   原先把「1 次 / 1（最近 24 小时）」摆进行里：分母是当日全部规则命中
        #   总数，与分子同质却看不出来，而「1 / 1」天然被读成占比。窗口口径
        #   本页页头已声明一次（U-05 不许行内再挂「点开看每一次」那类旧句）。
        _rule_total = sum(int(r["count"]) for r in rep["rules"])
        # ★★ 0.53.0（T5.1，设计 §14.4 第 3 条）：**行尾**给工具分布，
        #   不新增小节（另开一节＝同页两套计数）。开关与收件箱徽标同一条：
        #   本机只观测到一个工具时恒等于"全是它"，每行再说一遍是纯噪声。
        #   ★ 每条规则只取**当天**、**该规则**的记录 —— 与行里的"命中 N 次"
        #     同一个集合（否则就是两个口径摆在一行）。
        _show_host_dist = M.host_count(items or []) >= 2

        def _rule_host(r):
            if not _show_host_dist:
                return ""
            sub = [it for it in (items or [])
                   if it.rule_id == r["rule_id"]
                   and str(it.ts)[:10] == str(rep.get("day"))[:10]]
            return M.host_phrase(sub, limit=2, label_of=_host_label)
        rows = "".join(
            # ★ 0.50.4（Q-04）：显示规则**人话名**；规则号退到 hover —— 工程串
            #   不上主界面。★★ 0.51.0（品质审查拍板点 3/4，2026-10-16）：Q-04 的
            #   替代品 description_zh 是审计受众的全文（最长 60 字）⇒ 挤成三四行，
            #   且 DST-10 的 zh 自带「——DST-09」内部自引用（编号从数据后门回来）。
            #   ⇒ 主显示改**上屏短名**（`label_zh`，≤14 字，INV-4 强制），
            #   规则号**上屏**（`.rid`，与问号全表同一视觉语言 —— 收件箱记录
            #   「规则 SEC-01」能对号入座），全文 zh 退到 hover title。
            #   退链 label → zh → 规则号（不编造、不用英文 `name` 充数）。
            # ★★ 0.53.4（创始人 2026-10-20 截图）：「规则代号放在前边、字号跟
            #   旁边一样大」—— 规则号移到短名**之前**（前缀位，与收件箱
            #   「规则 SEC-01」同序），字号收到正文 13px、颜色收回正文色。
            "<div class=\"row\"><span class=\"k\">"
            "<a href=\"/?v=inbox&f=day:%s:rule:%s\" title=\"%s\">"
            "<span class=\"rid\">%s</span>%s</a></span>"
            "<span>命中 %d 次%s</span></div>"
            % (_esc(rep["day"]), _esc(r["rule_id"]),
               _esc(r.get("zh") or r["rule_id"]),
               _esc(r["rule_id"]),
               _esc(r.get("label") or r.get("zh") or r["rule_id"]),
               int(r["count"]),
               (" ｜ " + _esc(_rule_host(r))) if _rule_host(r) else "")
            for r in rep["rules"][:10])
        rules = ("<div class=\"card\"><h2>规则命中排行 · 当日共 %d 次"
                 "</h2><div class=\"rows fit\">%s</div></div>" % (_rule_total, rows))

    # ★★ 0.53.4（创始人 2026-10-20「这些好像不属于日报，放在日报里合适吗？」）：
    #   **链卡整张搬去运行状态页**（`_chain_card`）。搬走的理由不是它不重要，
    #   而是：① 它答的是「证据本身可靠不可靠」，与"今天发生了什么"不是同一件事；
    #   ② 它每天的数几乎不变（同一批文件），放日报等于每天重复同一句；
    #   ③ 它要三行才说得清，放进日报就挤掉了日报自己那两卡的位置。
    # ★★ 2026-10-21 再撤一步（创始人「把日报最后一行去掉」）：连那句
    #   「记录在运行状态页」的**指路句**也不留。机制层的理由 ——
    #   **跨页指路是页签的活，不是正文的活**：顶部五个页签已经能到任何一页，
    #   正文里再写一遍"在某某页"＝把导航说两遍；而且这类句子会**随搬家腐烂**
    #   （东西搬走了，句子还指着旧地方）。⇒ 不留指路句，靠页签导航。
    #   ★ 减法留账：链的三个词条（防篡改记录／有没有被改过／没纳入比对的记录）
    #     全部只在运行状态页落点；日报连提都不再提，由 T-10 ⑥' 守。
    # ★ 0.36.1：时间范围只在**小节标题**里说一次（原来四张卡片各写一遍）。
    # ★ 0.37.1：页面名与 `<title>`/选项卡统一取 `PAGE_TITLES`（唯一真源）——
    #   旧版这里写「今日值守 · 日期」，而浏览器标签与选项卡都写「日报」，
    #   同一页三个名字（创始人问的"违和感"之一）。
    # ★ 0.37.2 精简：原句还带"点数字可以看是哪几条" —— 数字本身已可点（下划线），
    #   再写一遍就是**重复用户的动作**（同 W08 判据的立意）。只留窗口口径。
    # ★ 0.50.4（Q-02）：页头这句补上「斜杠右边那个数是什么」—— 卡片上那个斜杠
    #   右边的数是**同一时间窗内的记录条数**（＝失守＋拦截＋注意三档之和）。原先
    #   全页无一处说明，读者只能把「11 / 13」读成占比。
    #   ★ 不写「分母」二字：那是术语词，正文裸它会被 U-03 判红（口径行才是
    #     它的定义处）。
    #   ★ 也不写「/ N」：那个 N 是**裸英文词**，正文可见文本里出现它会被
    #     0360 W06 判红（「页面正文露出英文词 'N'」）—— 2026-10-15 实测撞到，
    #     是 Q-02 自己引入的。
    # ★★ 0.51.0（品质审查拍板点 1，2026-10-16）：斜杠解释句随分母一起撤 ——
    #   「需要一整句话才能解释的显示，本身就是显示失败」（Q-02 补丁即自供状）；
    #   四卡只留绝对数＋单位，时间口径保留（W07：说一次，且不许整句删掉）。
    return ("<h2>%s · %s</h2>"
            "<p class=\"note\">四个数都只数<b>最近 %d 小时</b>。</p>%s%s%s"
            % (PAGE_TITLES["report"], _esc(rep["day"]), hrs, m, pr, rules))


def _chain_ok_state(ch):
    """这次链检到底**查成了**没有（除 `status` 之外任何地方不许各判一次）。"""
    return str((ch or {}).get("status") or "") != "unknown"


def _chain_verdict(ch):
    """「校验结果」这一格该显示什么：查成了给中文状态词，没查成给告警句。

    ★ 0.53.0（T5.2／设计 §4.4-3、§14.6-4）：原来"没查成"显示的是「未能核验」——
      那是**状态**，读起来像"暂时没数据"，而真相是这次检查一条结论都没产出
      （页面别处的绿色因此不能算数）。⇒ 换成 `R.chain_unverified()` 的告警句。
    ★ 两处落点（运行状态页、日报页链卡）都走本函数，**不许各写一份**。
    """
    if _chain_ok_state(ch):
        return R.chain_status_label((ch or {}).get("status"))
    return R.chain_unverified((ch or {}).get("files", 0))


#: 无指纹记录的类型 → 上屏人话。**只做翻译**：类型取自数据（`chain["types"]`），
#: 这里不预设数据里有什么；表里没有的类型 ⇒ 走通用句（不编人话）。
_UNCHAINED_TYPE_ZH = {
    "session_start": "开始一次对话时留下的记录",
}


def _qsum_html(ch):
    """「没纳入比对的记录」行**值后**的圈问号展开体：这次是些什么记录。

    ★ 0.53.4 修订（创始人 2026-10-20 10:18 截图：「对不上 147 这个数啊……
      这种明细不仅对不上，用户也看不懂。让用户知道具体情况就行，把用户的
      问号拉直就行，体验还是第一位的。还有上边 32 个文件也是。」）：
      初版展开体列了 32 个文件、每个文件跟一个「N 条」—— 那个 N 是**该文件
      带指纹的记录数**，与 147（不带指纹的记录数）是两个口径 ⇒ 怎么加都对
      不上；而且逐文件是内部实现细节，用户读不懂。⇒ 明细整段退役，只答
      两件事：这些记录是什么（类型从数据派生）、核对范围（日期从文件派生）。
    ★ 与术语词条分工：行左 `unchained` 芯片答"为什么没纳入比对"（概念，
      静态）；这个问号答"这次是些什么"（本日数据）—— 点哪个都看得懂。
    ★ 单类型且有已知人话 ⇒ 直说「都是…」；混合/未知 ⇒ 只说"不带指纹"，
      不把一类说成全部（对外强度不许超过数据能支撑的）。
    ★ 数字与范围全部派生：`ch["unchained"]` / `ch["types"]` /
      `ch["first_day"]` / `ch["last_day"]`，不写死。
    """
    ch = ch or {}
    n = int(ch.get("unchained") or 0)
    if n <= 0:
        return ""                               # 没有带问号的数，就不挂问号
    types = ch.get("types") or {}
    head = ""
    if len(types) == 1:
        _only = next(iter(types))
        _zh = _UNCHAINED_TYPE_ZH.get(_only)
        if _zh:
            head = "这 %d 条都是%s。" % (n, _zh)
    body = ("%s它们不带指纹，不算被改过。" % head) if head else \
        ("这 %d 条记录不带指纹，不算被改过。" % n)
    # ★★ 0.53.4 三次修订：**删掉「核对范围是 A 到 B 的链文件」这一句**。
    #   链卡搬到运行状态页后，紧挨着的上一行就是「检查范围：A 到 B，共 N 条
    #   记录」—— 同屏两处同一段日期，正是 STE 要灭的「一句话说两遍」。
    #   （搬卡前这句是**唯一**给出日期的地方，所以它在当时是对的；前提变了。）
    return ("<details class=\"qsum\"><summary>？</summary><div class=\"qbody\">"
            "%s</div></details>" % body)


#: 「记录」是什么 —— 圈问号 `.qinfo` 的展开体（创始人 2026-10-20：
#: 「65119 条记录……这些记录是啥？什么形式存在？我需要了解清楚，我相信
#: 用户也会有这样的疑问的」）。
#: ★ 写法按 ASD-STE100：一句话一个意思、主动语态、现在时、不用缩略语、
#:   不写路径与英文词（`jsonl` / `sha256` 一个都不上屏 —— 它们是**实现**，
#:   用户问的是"这东西是什么、存在哪、存了什么"）。
#: ★ 四句各答一问，顺序＝读者会问的顺序：是什么 → 什么形式 → 放哪 → 存什么。
#:   "存什么"放最后且**明说不存什么**：隐私是这里唯一的真风险点，
#:   说"只有摘要"而不说"没有文件内容"，读者仍然会担心。
_RECORD_WHAT = (
    "一条记录就是发生过的一件事。开一次对话、拦一次操作，都会留下一条。"
    "每条记录是一行文字，写在记录文件的末尾，前面的行不改。"
    "记录文件放两处：本机汇总一处，各项目目录一处。"
    "记录里只有摘要：命令里认出密钥就遮住，文件只留内容指纹，没有文件内容。"
)


def _qinfo_html(text):
    """行内圈问号的**第二形态**：答「这类东西是什么」（静态概念）。

    ★ 与 `.qsum` 分工（两者同形不同义，类名分开）：
      `.qsum`  答"**这一次**是些什么记录"（数字/类型/范围全部派生自本次数据）；
      `.qinfo` 答"**这类东西**是什么、存在哪、存了什么"（与本次数据无关）。
    ★ 不进 `name="term"` 互斥组：它不是术语词条（没有 `data-t`），
      与术语表 24 条不共享开关状态。
    """
    return ("<details class=\"qinfo\"><summary>？</summary><div class=\"qbody\">"
            "%s</div></details>" % _esc(text))


def _chain_card(ch):
    """运行状态页第二张小节卡「记录」（0.53.4 从日报搬来）。

    ★ 为什么搬：创始人 2026-10-20「这些好像不属于日报，放在日报里合适吗？」
      —— 日报答"今天发生了什么"，而"记录有没有被改过"答的是**证据本身可靠
      不可靠**，与当天的账无关；而且它每天的数几乎不变（同一批文件），
      放进日报等于每天重复同一句。

    ★ 三行（创始人拍板「这张表就三行吧，漏掉的重要信息都补上」）：
      ① 结论：逐条对过多少条、有没有被改过（直答，不再给"完整"这种状态词）
      ② 检查范围：日期区间 ＋ 记录总数（总数含没纳入比对的，否则读者
         拿 64972 去对账永远少 147 —— 这正是 10:18 那条"对不上"的根）
      ③ 没纳入比对的记录：0 条时**整行不列**（列一个 0 只会生出"那是啥"）
    ★ 有问题时才追加「第一个问题出在哪」；没查成时**只留告警句一行**——
      此时范围/总数都还不存在，硬凑三行就是拿 0 冒充数据。
    ★ 末挂一行边界注：没有这句，卡片读起来像"整机全查过了"。
    """
    ch = ch or {}
    css = {"ok": "ok", "broken": "bad", "unknown": "warn"}.get(
        str(ch.get("status") or ""), "warn")
    recs = int(ch.get("records") or 0)
    unch = int(ch.get("unchained") or 0)
    bad = int(ch.get("bad_lines") or 0)
    rows = []
    if _chain_ok_state(ch):
        # ★ 直答：数字从 records 派生，结论词从 `chain_status_label` 派生
        #   （唯一实现，不在此另写一份中文字面）。
        rows.append('<div class="row"><span class="k">%s</span>'
                    '<span class="%s">%d 条逐条对过，%s</span></div>'
                    % (GL.chip("chain_check"), css, recs,
                       _esc(R.chain_status_label(ch.get("status")))))
        total = recs + unch + bad
        fd, ld = ch.get("first_day") or "", ch.get("last_day") or ""
        # ★ 范围句两形态都派生：读得出日期 ⇒ 「A 到 B，共 N 条记录」；
        #   读不出（项目级文件名不一定带日期）⇒ 只说条数，不编日期。
        scope = ("%s 到 %s，共 %d 条记录" % (_esc(fd), _esc(ld), total)
                 if fd and ld else "共 %d 条记录" % total)
        rows.append('<div class="row"><span class="k">检查范围</span>'
                    '<span>%s%s</span></div>' % (scope, _qinfo_html(_RECORD_WHAT)))
        if unch > 0:
            rows.append('<div class="row"><span class="k">%s</span>'
                        '<span>%d%s</span></div>'
                        % (GL.chip("unchained"), unch, _qsum_html(ch)))
        if ch.get("first_bad"):
            rows.append('<div class="row"><span class="k">第一个问题出在哪</span>'
                        '<span>%s</span></div>' % _esc(ch["first_bad"]))
        elif str(ch.get("status")) == "broken":
            rows.append('<div class="row"><span class="k">第一个问题出在哪</span>'
                        '<span>存在无法读取的链记录；当前没能定位到具体文件</span>'
                        '</div>')
    else:
        rows.append('<div class="row"><span class="k">%s</span>'
                    '<span class="%s">%s</span></div>'
                    % (GL.chip("chain_check"), css, _esc(_chain_verdict(ch))))
        # ★ 没查成时，**只有「读到了文件却一条都校验不了」这种才追加原因**：
        #   `chain_health` 的三条 `reason` 路径互斥 —— files==0 ⇒ 原因是
        #   「没有可校验的链文件」，而告警句已经说了「0 个文件被检查」，
        #   再说一遍是废话（STE）；files>0 且 reason 非空 ⇒ 只可能是
        #   「拿不到校验器：…」，这句是**唯一**能说清原因的地方，必须留。
        if ch.get("reason") and int(ch.get("files") or 0) > 0:
            rows.append('<div class="row"><span class="k">说明</span>'
                        '<span>%s</span></div>' % _esc(ch["reason"]))
    # ★ 小节标题走 `chain` 词条芯片（「防篡改记录」）—— 它既是这一节的**名字**，
    #   也是这个词条唯一的落点（日报撤卡后 `chain` 芯片不能再只剩在旧卡里，
    #   否则术语表 100% 有落点那条判据会红）。
    # ★ 显式结构边界（`id="chainrec"` 起、`<!-- chainrec:end -->` 止）：
    #   判据取段锚在标记上，卡里加行减行、改句子都不碰尺子。
    # ★ 边界注两件事：① 这条链**查不到**什么（整份替换）；② 哪一类记录**根本
    #   没法比**（没指纹的那几类）。
    # ★★ 0.53.4 四次修订（创始人 2026-10-20 13:04 截图：「没有纳入比对的记录
    #   重复了，请去掉下边那条」）：② 的芯片**只在第三行缺席时出现**。
    #   病根——上一版为了让「没纳入比对的记录」在 0 条的机器上也有术语落点
    #   （P13），无条件把它挂进了边界注；可 0 条只是**一种**情形，常见情形
    #   （有 150 条）第三行本来就在，边界注再写一遍＝同屏同一个词两次。
    #   修法不是删词条、也不是把 0 行加回来，而是**让落点跟着缺位走**：
    #   行在，芯片就在行上；行不在，芯片才落到注里。两个情形各有一处、且只有
    #   一处。※ 机制教训：给判据补落点时，要问「这个落点在**别的分支**里会
    #   不会变成重复」，不能只问「这样判据还绿不绿」。
    _landing = (GL.chip("unchained") if unch <= 0 else "")
    _note2 = ("没指纹的记录没法比对，单独算一类：%s" % _landing) if _landing else ""
    return ('<h2 id="chainrec">%s</h2><div class="rows fit">%s</div>'
            '<p class="note" style="margin:8px 2px 2px">只比对本机读得到的记录：'
            '单条被改能查出来；整份文件缺失、整份被替换，看不出来。%s</p>'
            '<!-- chainrec:end -->'
            % (GL.chip("chain"), "".join(rows), _note2))


def _view_health(rep, token, items=None):
    """★ 0.36.1 文字修订：这一页原先把**已生成的 HTML 整段转义**，
    于是术语词条的 `<details>` 在用户屏幕上显示成一串标签文本
    （创始人 2026-10-07 截图一）。根因是白名单判定写成
    `k.startswith("<details")` —— 而「哨兵被拉起」那行的 key 是
    `"最近 %d 小时" + GL.chip(...)`，前面多了四个字 ⇒ 判定为假 ⇒ 整段被 `_esc`。
    ★ 教训：**「以标签开头」判不出「是不是我们生成的 HTML」** ——
      生成方与消费方隔了字符串拼接，白名单就必然漏。
      改成显式的 `trusted=True` 标记（我们自己产出的才放行）。

    ★★ 0.37.2：本页**不再输出状态词** —— 旧版第一行是「此刻这一次：
      值守中」，而顶部条同一时刻写「失守」⇒ 同屏两个相反的状态词、
      没有任何说明（创始人点名的"违和感"）。现在状态词全站只在顶部条
      一处，本页只放顶部条没有的证据（哨兵活力 / 记录有没有被改过 /
      钩子 / 边界）。
    """
    ch = rep["chain"]
    _hrs = rep.get("window_hours", 24)
    _revived_count = rep.get("revived_window", 0)
    # ★ 0.47.0：拉起次数是分子 ⇒ 分母＝窗口内总记录数（与日报页同一口径）。
    # ★★ 0.50.4（Q-03）日报页已改成「；同期记录 %d 条」（次数单位是「次」、
    #   条数单位是「条」，两个异质量的量摆成一条斜杠＝没意义的除法）——
    #   **本页漏改**，实测仍是「54 次 / 54」（创始人截图五：裸分母连单位
    #   都没有）。本条注释原写「与日报页同一口径」而渲染是两套 —— 把愿望
    #   写成了事实（T-11 同族）。现在两处逐字同形。
    _win_total_h = sum(int((rep.get("window_levels") or {}).get(k, 0) or 0)
                       for k in ("R0", "L2", "L1"))
    _revived_value = ("<a href=\"/?v=inbox&f=win:%d:kind:host_shield_revived\">"
                      "%d 次</a>；同期记录 %d 条"
                      % (_hrs, _revived_count, _win_total_h))
    # ★★ 0.37.2：**删掉本页第一行「此刻这一次」**（旧版 `GL.chip("posture",
    #   "此刻这一次")` + 值「值守中 —— 哨兵在岗…」）。
    #   顶部条已给出同一个状态词，并且 0.37.2 起把「此刻」与「24h 账」
    #   写在**同一句话**里（比本页这一行更全）。这里再给一次 ⇒
    #   同屏两个状态词、两种说法 —— 实测日报页正是这个形状，
    #   是创始人点名"违和感"的头号来源。
    #   ⇒ 状态词全站只有**顶部条**一处；本页只放顶部条没有的证据。
    # (标签, 值, 颜色样式, 值是否可信 HTML)
    # ★ 标签一律 trusted=True：`GL.chip()` 是我们自己生成的 HTML。
    # ★★ 0.53.4（创始人 2026-10-20「这些好像不属于日报，放在日报里合适吗？」）：
    #   链检那行**搬出本块**，成为本页第二张小节卡（见 `_chain_card`）——
    #   它要答三件事（结论／范围／没纳入比对），塞进这行只会变成
    #   「一句话里三个数」的旧形状；而它答的问题（记录有没有被改过）
    #   与本节其余各行（哨兵／监听地址／工具识别／钩子／边界）不是同一类。
    #   减法留账：「一句话塞三个数」这个形状**不回来**，由 T-10 守。
    # ★ 0.53.0（T5.2／设计 §4.4-1、§14.6-2）：工具识别**最小版**（一行，不另开小节）。
    #   三样：判定方式（哪条线索）／近 7 天认得出几条／说不清占比超 5% 提醒。
    #   ★ 不做「旧记录分代」（v1.5 划到非目标：分代钻取）。
    #   ★ 百分比同句给分母（F40）：句子里先有「N 条记录」，再有「（X%）」。
    #   ★ `total` 为零不许渲染成「0% 说不清」—— 那是"没查"，不是"查过没事"。
    _hs = M.host_attribution_stats(items or [], days=7)
    if _hs["total"] <= 0:
        _host_value = "近 7 天没有记录——暂时看不出它认不认得工具"
        _host_css = "neutral"
    else:
        _conf = []
        for _k in ("high", "medium", "low"):
            _n = _hs["by_conf"].get(_k, 0)
            if _n:
                _conf.append("%s %d 条" % (M.HOST_CONF_ZH[_k], _n))
        if not _conf:                       # host 有值但没留置信度 ⇒ 照实说线索不明
            _conf = ["线索不明 %d 条" % _hs["by_conf"].get("none", 0)]
        _pct = int(round(_hs["unclear_ratio"] * 100))
        # ★★ 0.53.1（创始人 2026-10-18 质问「要求指明哪个 AI 编程工具，可我没看到」）：
        #   原句只给置信度（"有直接证据 104 条"），**从不给工具名** —— 读者看到
        #   "认得出是哪个工具"，却永远得不到那个名字。设计 §6 要的正是「工具名」。
        #   工具名走 `M.host_distribution`（唯一实现，不在这里另算一份）；
        #   置信度留在括号里当「判定方式」，两者不能互相顶替。
        #   ★ 单工具时说「全是 X」而不是「X 104 条」：全量与总量并列会被读成占比。
        _win7 = [it for it in (items or ()) if M.within_hours(it.ts, 7 * 24)]
        _dist = M.host_distribution(_win7, label_of=_host_label)
        if len(_dist) == 1:
            _who = "——全是 %s" % _dist[0][0]
        elif _dist:
            _who = "——" + "、".join("%s %d 条" % (_nm, _n) for _nm, _n in _dist[:3])
            if len(_dist) > 3:
                _who += " 等 %d 种" % len(_dist)
        else:
            _who = ""
        _host_value = ("近 7 天 %d 条记录里，%d 条认得出是哪个工具%s，"
                       "%d 条说不清（%d%%）。"
                       "线索取工具自己报的环境信息（%s）。"
                       % (_hs["total"], _hs["attributed"], _who,
                          _hs["unclear"], _pct, "、".join(_conf)))
        if _hs["unclear_ratio"] > 0.05:
            _host_value += "说不清偏多——多半是记录太旧，或换过工具。"
            _host_css = "warn"
        else:
            _host_css = "ok"
    rows = [
        (GL.chip("sentinel", "最近 %d 小时被拉起过" % _hrs),
         _revived_value, "warn" if _revived_count else "ok", True),
        # ★ 0.48.5（交接件 §5.4 丁2/丁3）：who 块从顶部条删除后，把它承诺的
        #   事实搬来本页作**证据**（口号变证据）—— 这句由 `_check_bind` 的
        #   硬校验背书：非回环地址 make_server 直接抛错，不是嘴上说回环。
        ("监听地址", "仅本机回环——服务不接受外部连接", "ok", False),
        # ★ 0.36.1：原先直接输出 `ch["status"]`，那是英文变量
        #   （ok / broken / unknown）—— 页面上冒出英文变量词。
        #   ⇒ 一律走 `chain_status_label()` 的中文。
        # ★ 0.53.0（T5.2）：句子的**拼装**提到 `rows` 之前（见上）——因为"没查成"
        #   时它换成告警句，而告警句自带文件数，不再套那层括号。
        # ★★ 0.53.4：这一行已搬成独立小节卡 `_chain_card()`（本元组里不再有它）。
        # ★ 0.50.4（Q-16）：原正文「本页没查这台电脑的实际安装情况」与 `hook`
        #   词条的 exc「这一页没查你这台电脑的实际安装情况」**是同一句出现两次**
        #   ⇒ 正文改成讲**结论**（它装在哪个环节），否证交给词条（定义处只讲一次）。
        ("工具识别", _host_value, _host_css, False),
        (GL.chip("hook"), "工具调用前先过规则；本页不查它装没装", "neutral", False),
        (GL.chip("boundary"), "浏览器里的操作、没接进来的工具，Antinel 管不到",
         "warn", False),
    ]
    body = "".join("<div class=\"row\"><span class=\"k\">%s</span>"
                   "<span class=\"%s\">%s</span></div>"
                   % (k, css, value if trusted_v else _esc(value))
                   for k, value, css, trusted_v in rows)
    # ★ 0.37.1：页面名统一（同 `_view_report`）；日期补齐 ——
    #   日报页有日期、运行状态页没有，同一套页面两个样。
    # ★ 底部提示由 3 行长句压成一句：原来一段带破折号的自我辩护，
    #   读起来像旁白，不像产品说的话。
    # ★★ 0.50.4（Q-25 连带）：这一行是 `Ls`／`L0` 两个词条的**落点** ——
    #   删掉底部总入口后，六态里这两态在页面上再没有落点（判据 P13 要术语表
    #   100% 有落点），而它们又**不能撤**（0372 S09 拿 `TERMS[k]["w"]` 当六态
    #   词名的比对真源，撤键 ⇒ KeyError，本轮实测踩到）。⇒ 给一行真实落点，
    #   两条判据同时守住。
    #   ★ 次序由 `M.PRIORITY` 派生、词名由 `GL`／`M.state_short` 取 —— **不手写
    #     第二份次序**（六态次序漂移正是由这条纪律挡住的）。
    #   ★★ 0.53.3（创始人 2026-10-20 截图「五态只有两个态有问号」）：
    #     上一版只给 Ls/L0 挂问号，理由是「其余三态的落点在顶部药丸」。
    #     那个理由站不住：读者读的是**这一行**，不会为了问"失守是什么"
    #     再跑到顶部去找一枚长得一样的「？」；顶栏那枚问号答的是"灯上这个
    #     词叫什么"，与"这一档是什么意思"不是同一个问题。⇒ 五态全挂。
    #     ★ Q-11（"一屏十几个「？」像十几处有问题"）的边界：那一屏十几个
    #       指的是**散落各处**的问号；这里是**同一行枚举里各一枚**，形态
    #       一致、数量等于枚举项数，读者读到的是"每一项都能查"，不是
    #       "有五处问题"。刻意推翻 Q-11 的这条推论，记在此处。
    #   ★★ 0.53.3：对外只说**五态**。六态是内部口径（五态＋研发态）—— 用户
    #     机器上永远见不到研发态那一档，写六态等于让他去找一个不存在的位置
    #     （创始人原话：「研发态只是内部用，不用告诉用户，用户是没有这个态
    #     的」）。研发态**不是**灯的一档，`light.exc` 里的"不点灯、只挂徽标"
    #     那句仍保留 —— 它说的正是"徽标≠灯的档位"，与此处不冲突。
    _order = sorted(("R0", "Ls", "L2", "L1", "L0"), key=lambda k: -M.PRIORITY[k])
    # ★★ 0.50.7（创始人截图二「失守后换行」＋截图三「缺粮（Ls）括号不一致」）：
    #   ① 断行确定性化：标签独占一行（显式 `<br>`），各态包原子
    #     `<span class="sixit">`（white-space:nowrap）—— 旧形状是单行
    #     `<p>`＋自然换行，断点落在哪全看窗口宽度，实测断在「失守」后。
    #     且旧写法把 `<details>` 芯片塞进 `<p>`：details 会**隐式闭合**
    #     `<p>`（HTML 解析规则）⇒ 枚举从第一枚芯片处断成两截、其后的
    #     「·」分隔符还丢了 `.note` 样式 —— 改 `<div>` 一并修掉。
    #   ② 码进词条：Ls/L0 的 summary 原显示「缺粮（Ls）」「值守中（L0）」
    #     （`GL.chip` 默认取 `TERMS[w]`＝`_wl()` 带码形态），与其余三态的
    #     裸词「失守 · 拦截 · 注意」同屏两种写法。传 `text=M.state_short(k)`
    #     后 summary 只显示词（单一真源，不手写第二份），码留在词条展开体
    #     首行（`chip()` 的 head 机制自动补 `<b>缺粮（Ls）</b>：）——
    #     P13 落点（`data-t`）不变。
    # ★★ 0.53.3：这一行自带**显式边界**（`id` 起、`<!-- lightorder:end -->`
    #   止）。旧版判据的收尾锚是文字「`</div>` 后面跟一个 `<p class="note">`」
    #   —— 那是把尺子绑在**文案**上：删掉下面那句尾注，尺子当场瞎掉。
    #   锚在结构标记上，这一段里加什么减什么都不影响判据。
    _lorder = ("<div class=\"note sixline\" id=\"lightorder\">灯的五态由重到轻：<br>"
               + " · ".join("<span class=\"sixit\">%s</span>"
                            % GL.chip(k, text=M.state_short(k)) for k in _order)
               + "</div><!-- lightorder:end -->")
    # ★★ 0.53.3（创始人 2026-10-20 截图末句）：删掉尾注
    #   「全绿不等于安全：也可能是检查压根没跑。」三条理由：
    #     ① **结构错位**：它挂在五态枚举下面，读者会当成第六档的说明；
    #     ② **同一件事说第二遍**："检查没跑成"已有唯一告警句 —— 链读不到
    #        时 `chain_check` 那行整行换成 `R.chain_unverified()` 的告警
    #        （见 `_chain_value`），这里再说一遍没有新信息；
    #     ③ **认领了不该认领的职责**：它把「安全」这个词引进页面，而监理
    #        不承担安全、也实质上承担不了（创始人原话）。一句免责声明换来
    #        一个它根本不该碰的词 —— 用户读完会问"那你到底管不管安全"，
    #        这个问题原本不存在。
    #   ★ 减法留账：删的是**这句话**，不是"没查成必须告警"这条规矩 ——
    #     后者仍在 `_chain_value`，判据 J8 同时锁住"这句不许回来"。
    return ("<h2>%s · %s</h2><div class=\"rows\">%s</div>%s%s"
            % (PAGE_TITLES["health"], _esc(rep.get("day") or ""), body,
               _chain_card(ch), _lorder))


def _view_ledger(rep, token, items=None):
    # ★★ 0.51.1（创始人 2026-10-17 截图三问）：头部**只留当天四个指标**，
    #   历史元信息（连续/有记录天数）降为一行小字。三问逐条修：
    #     ① 「下列四个数」下面摆了**六张卡**（当天四指标＋连续＋有记录天数）
    #        ⇒ 文案与结构自相矛盾。根因：当天指标与历史元信息混在同一排卡里。
    #        （0.50.4 起就是这样，本批只改了后半句，漏了「四个数」这个数量词。）
    #     ② 「连续有记录 11 天」与「有记录的天数 11」同页并列，有记录天数等于
    #        连续天数时**必然**出现两个同数 ⇒ 创始人原话「11天显示两次，为什么要两次」。
    #     ③ 六卡取 `ledger.summary()`（**旧快照** daily.jsonl），明细区取
    #        `M.day_counts`（**链现算**）⇒ 同页两个口径，实测卡片「有记录 11 天」
    #        与月行「有记录 8 天」当场打架（快照有整天漏记/历史少记的旧缺陷）。
    #   ⇒ 三条一起落：卡＝当天四指标（**链现算**、可点深链）；连续/有记录合成
    #     **一行小字**，且**两数相等时只说一次**（「连续至今」）—— 同页永不出现
    #     两个同数；文案「下列四个数」如今名副其实。
    #   ★ 口径唯一：连续天数用 `ledger._streak`（与 `daily_report` 同一实现），
    #     输入是 `M.day_counts` 现算出来的有记录日集合 —— 全页一份口径。
    #   ★ 旧快照仍由 `ledger.summary()` 承载（导出/认领与 P1 判据用它），只是不上屏。
    _today = datetime.now().astimezone().strftime("%Y-%m-%d")
    idx = M.day_counts(items or [])
    _rec = {d: e for d, e in idx.items()
            if any(int(e.get(k) or 0) for k in M.LEDGER_KEYS)}
    _n_days = len(_rec)
    has_data = bool(_n_days)
    _streak = L._streak(set(_rec), today=_today) if _rec else 0
    # ★★ 0.53.0（T4.2，设计 §14.5 第 1 条）：**撤头部四指标卡**。
    #   撤掉的是什么：当天「拦截 / 注意 / 防护缺口 / 已处理」四张卡（带当天的数）。
    #   为什么撤：这四个数的家是**日报**（同一 24 小时窗口、同一口径）——
    #     同口径两个落点＝重复（U20 是同一条纪律）。账本这页的职责是**历史**。
    #   信息去哪了：① 今天 → 下方一行深链直达日报（数不在这里再抄一份）；
    #     ② 任一历史日的四个数仍在按天明细行里，且每个数都是可点深链；
    #     ③ 四个词的定义仍可点开 —— 「？」芯片随卡片一起消失就会让词条无落点
    #        （P13 术语 100% 有落点），故**移**到「过去 7 天」小节的读法行。
    #   ★ 减法留账三列见施工单 v1.6 登记簿第 2 笔。
    # 历史覆盖：**一行**（不再占两张卡）；连续与总数相等时只说一次 ——
    # 「11 天、11 天」这种同数并列会让读者以为是 bug（创始人三问之二）。
    # ★★ 这一行**无条件渲染**（2026-10-17 复跑抓到）：`days`/`streak` 两个
    #   词条的芯片此前只在 `has_data` 为真时出现 ⇒ 一台**还没有可计数事件**
    #   的机器上，两个术语就没有任何落点（0353「四栏目都能点开定义」当场翻红）。
    #   旧版六卡无论有无数据都渲染（只是显示「—」），芯片落点因此从未丢过 ——
    #   这是本批改造引入的**回归**，判据抓到了它。
    if has_data:
        _streak_txt = ("连续至今" if _streak >= _n_days
                       else "当前连续 %d 天" % _streak)
    else:
        _streak_txt = "尚未开始"
    _meta = ("<p class=\"note\">%s 有记录 <b>%d</b> 天 · %s %s</p>"
             % (GL.chip("days"), _n_days, GL.chip("streak"), _streak_txt))
    # ★★ 0.37.2（创始人 2026-10-09 截图）：账本页**只留数字 ＋ 一处「？」**。
    #   页面上原先堆了三段解释（"这份账本在这台电脑上…"整卡、
    #   "账本存在哪个文件里"折叠块、"认领到账号"下的说明段）—— 创始人原话：
    #   「这些全是解释，不要放在账本主界面上……只需要第一次出现的『账本』
    #     二字上标准问号，跟那些数字一样，用户自己会点开看。」
    #   ⇒ 落法：标题里的「账本」直接放一个 `GL.chip("ledger")` —— 与六个
    #     数字标签**同一个交互、同一个「？」**；解释全部并进那个词条。
    #   ★ 唯一保留的一段：**没有数据**时的告警 —— 它不是解释，是
    #     「不许把'没查'渲染成'没问题'」的护栏（判据 0353 据此验收）。
    #   ★ 规格 §5.6 的两件仍在：①「这份账本在哪里＋可导出/可迁移」搬进
    #     `ledger` 词条（页面 HTML 里仍含这两句，判据语义不变）；
    #     ② 底部**禁用态**「认领到账号（未启用）」按钮保留。
    warn = ("<p class=\"note\">账本尚无可核对记录；这表示还没有可统计的记录，"
            "不是确认累计为零。</p>" if not has_data else "")
    # ★ 0.53.0（T4.3，设计 §14.5 第 2 条）：**今天不在这一页出数** ——
    #   一行深链到日报。刻意**不**把今天的四个数搬过来：搬过来就是同一事实
    #   两个落点，而两个落点迟早不同源（本仓 F40 的经典作案现场）。
    # ★★ 0.53.5（STE100 体检 S-05）：①「今天」换成**具体日期**（相对时间词
    #   会随阅读日期漂移——页面开着跨过午夜就指错天）；②「同一口径」换成
    #   「两边算法一样」（「口径」是工程词，读者没有这个概念）。
    _today_line = ('<p class="note">%s 的数在 <a href="/?v=report">日报</a>'
                   '（两边算法一样，这里不重复）；下面是已经过完的日子。</p>'
                   % _esc(rep.get("day") or "")
                   if has_data else "")
    # ────────────────────────────────────────────────────────────────
    # ★★ 0.51.0 明细区（银行流水模式，v1.1 设计）：区一「最近 7 天」＋
    #   区二「更早 · 按月」折叠。数据源＝store 现算（`M.day_counts`，唯一实现），
    #   不用旧快照 —— 快照有整天漏记/历史少记的缺陷（0.51.0 record_day
    #   账准修复后才与现算合一）。无记录的天**不许渲染成 0**：
    #   「没查」≠「查过没事」（0.37.2 同款护栏），缺口与真零必须可区分。
    #   ★ `idx` / `_rec` 在函数开头就现算了（头部四个数**必须**与这里同一份），
    #     此处不再二次计算 —— 二次实现正是 F40 的作案现场。

    def _day_cells(d, e):
        out = []
        # ★★ 0.53.1（创始人 2026-10-18 质问）：这里原写「防护缺口」—— 它是 0.48
        #   时代的旧词，不在六态表里（`M.STATE_LABEL`：R0＝**失守**）。同一个事实
        #   在本页曾有三个名字：词条「防护缺口」／月行「缺口」／六态表「失守」。
        # ★★ 根治：**词从六态表派生，不在这里写死** —— 写死就是第二份命名源，
        #   六态一改名就必然漏掉这一处（0.51.0 定名「失守」而账本留「防护缺口」，
        #   就是这么发生的，且没有任何判据能发现）。派生后改六态名，账本自动跟。
        for key, lv in (("blocked", "L2"), ("noticed", "L1"), ("breached", "R0")):
            # ★ 0.53.5（STE100 体检 S-02）：日行格子数的是**过去**的事 ⇒ 词走
            #   `event_short()`，与「当日合计」行同一份事件词源。
            word = M.event_short(lv)
            n = int(e.get(key) or 0)
            # 当天没有事件的级别显示 0 但**不可点**（点了是空页，纯噪音）。
            out.append(('<a href="/?v=inbox&f=day:%s:lv:%s">%s %d</a>' % (d, lv, word, n))
                       if n else "%s 0" % word)
        a = int(e.get("acked") or 0)
        out.append(('<a href="/?v=inbox&f=closed:%s">已处理 %d</a>' % (d, a))
                   if a else "已处理 0")
        return " ｜ ".join(out)

    def _day_row(d, e):
        if not any(int(e.get(k) or 0) for k in M.LEDGER_KEYS):
            return ("<div class=\"row dim\"><span class=\"k\">%s</span>"
                    "<span>—（当天无记录）</span></div>" % d)
        return ("<div class=\"row\"><span class=\"k\">"
                "<a href=\"/?v=inbox&f=day:%s\">%s</a></span>"
                "<span>%s</span></div>" % (d, d, _day_cells(d, e)))

    # ★★ 0.53.0（T4.2）：四个词的**读法行无条件渲染** —— 撤掉头部四卡后，
    #   这四颗「？」是 `ledger_blocked/noticed/breached/acked` 四条词条在本页的
    #   唯一落点。若把它挂在 `if _rec`（有记录才渲染）里，一台**还没有可计数
    #   事件**的机器上这四个词就没有任何落点 —— 0353 P13（术语表 100% 有落点）
    #   会当场翻红（本批实测踩到一次；0.51.2 同型：`has_data` 变严把术语芯片
    #   一起弄没）。
    _legend = ("<div class=\"note\">每天依次是：%s ｜ %s ｜ %s ｜ %s"
               "（单位：条）。</div>"
               % (GL.chip("ledger_blocked"), GL.chip("ledger_noticed"),
                  GL.chip("ledger_breached"), GL.chip("ledger_acked")))
    sections = ""
    if _rec:
        # 区一：固定 7 个日历天（含今天），新→旧。没开机的日子也出现在这里，
        # 淡显示「当天无记录」—— 7 天窗口是承诺，有数的行才可点。
        # ★★ 0.53.0（T4.3）：起点改**昨天**（昨天起 7 个日历天）—— 今天在
        #   日报，这里只列过完的日子；含今天会让同一屏两个"今天"。
        _w7 = [(datetime.now().astimezone().date() - timedelta(days=k)).isoformat()
               for k in range(1, 8)]
        _rows7 = "".join(_day_row(d, idx.get(d) or {}) for d in _w7)
        sections += ("<div class=\"card\"><h2>过去 7 天</h2>"
                     "<div class=\"rows\">%s</div></div>" % _rows7)
        # 区二：从最早有记录的月份到当月，每月一行（新→旧）——**整月完整**，
        # 不扣最近 7 天已列的天（宁重复 ≤7 行，不做边界算术）。月行只展开
        # 不跳转（展开后日行自带全部深链）。**默认全部收起**：页高不随历史
        # 增长 —— 1 年后＝7 日行＋12 月行，5 年后 7＋60，仍一屏内。
        first_ym = min(_rec)[:7]
        _y, _mth = int(_today[:4]), int(_today[5:7])
        yms = []
        while True:
            ym = "%04d-%02d" % (_y, _mth)
            yms.append(ym)
            if ym <= first_ym:
                break
            _mth -= 1
            if _mth == 0:
                _y, _mth = _y - 1, 12

        def _mlabel(ym):
            return "%s 年 %d 月" % (ym[:4], int(ym[5:7]))

        mrows = []
        for ym in yms:
            mdays = {d: e for d, e in _rec.items() if d[:7] == ym}
            if not mdays:
                mrows.append("<div class=\"row dim\"><span class=\"k\">%s</span>"
                             "<span>—（当月无记录）</span></div>" % _mlabel(ym))
                continue
            tot = {k: sum(int(e.get(k) or 0) for e in mdays.values())
                   for k in M.LEDGER_KEYS}
            body_rows = "".join(_day_row(d, mdays[d])
                                for d in sorted(mdays, reverse=True))
            mrows.append(
                "<details class=\"month\"><summary><span class=\"k\">%s</span>"
                # ★ 0.53.1：月行的格子名同样从六态表派生（与日行同一份词源）。
                # ★ 0.53.5（STE100 体检 S-02）：但**事件词**走第二真源
                #   `event_short()`（出事/挡下/提醒）—— 月行数的全是过去的事。
                "<span>%s %d · %s %d · %s %d · 已处理 %d ｜ 有记录 %d 天</span></summary>"
                "<div class=\"rows\">%s</div></details>"
                % (_mlabel(ym), M.event_short("L2"), tot["blocked"],
                   M.event_short("L1"), tot["noticed"],
                   M.event_short("R0"), tot["breached"],
                   tot["acked"], len(mdays), body_rows))
        sections += ("<div class=\"card\"><h2>更早 · 按月</h2>"
                     "<div class=\"rows\">%s</div></div>" % "".join(mrows))
    return ("<h2>%s · 本地摘要</h2>%s%s%s%s"
            "<div class=\"card\"><button class=\"btn\" disabled "
            "title=\"将来上线账号后才可用，现在没有这个能力\">"
            "认领到账号（未启用）</button></div>"
            % (GL.chip("ledger"), _today_line, _meta, _legend + sections, warn))


# ═════════════════════════ 体检页（第五 TAB · 0.53.0 T0）════════════════════════
#: 创始人 2026-10-18 03:18 截图交办：四个 TAB 变五个，多一个「体检」。
#: ★ 接入不是新建（设计 §20.1）：渲染与采集**全部复用 ui_server**（唯一实现），
#:   本模块只做四件控制台侧的事 —— 入口（第五 TAB）、进程内缓存、
#:   快照（设计 §21.2 接触点 4）、三态与边界（§21.3／§20.2 原文）。
#: ★★ GET 从不触发采集：host-scan 要 4～9 分钟，每次翻页都跑会把页面拖死
#:   （0.35.2 同款事故：日报无条件复算审计链 7.8s）⇒ 只有用户点「开始体检」
#:   （POST op=exam）才起后台线程；线程里跑 ui_server 的**同一对**采集器
#:   （同一子进程命令＝同一数据路径，禁第二份）。
_EXAM = {"state": "idle", "stage": "", "error": "", "result": None,
         "saved": "", "started": 0.0, "finished": 0.0}
_EXAM_LOCK = threading.Lock()

#: 三态原文（设计 §21.3 写死，不许临场编；负控 N-H10 守互斥）
_EXAM_FIRST = "首次体检，还没有对比基线。"
_EXAM_FAILED = "这次没查成：0 个地方被检查——结果不算数。"
_EXAM_NO_TOOLS = ("这台电脑上没找到 AI 工具。这可能是好事，也可能是监理没找到。"
                  "可以跑 <code>antinel host-scan</code> 复查。")
#: 首启引导条（设计 §21.2 接触点 2，逐字）
_EXAM_GUIDE = "这是第一次打开监理。先做一次体检吧——它只读，不会改任何东西。"
#: 边界声明（设计 §20.2）：前四行＝ui_server TPL 原文（控制台版逐字保留），
#:   后四行＝本节新增的局部边界（写在首屏，挡「体检过了＝我安全了」这个误解）
_EXAM_BOUND = (
    # ★★ 2026-10-21 创始人 09:56：「**开头这段文字，我认为太长、看上去乱，
    #   可能还有啰嗦等问题。用 ASD-STE100 改写精炼一版**」。
    #   改写口径（STE100）：一句一事、单句 ≤40 字、小标题分行、不用长破折号句、
    #   不用「这不只是……而是……」这类修辞。**信息一条不丢**（逐条对照见
    #   设计稿 §20.2 的留账表）：查得到什么／读不到 ≠ 干净／每档带「自认」／
    #   「没查到」当空白读／只是局部体检＋不查什么／要全面体检得用别的工具。
    "<p class=\"muted small\"><b>先说清楚能查到什么、查不到什么。</b></p>"
    "<p class=\"muted small\"><b>能查到</b><br>"
    "· 你装了哪些 AI 工具。<br>"
    "· 这些工具自己有没有承认往外送过东西。比如它记了「上次上传」。<br>"
    "· 工具不会写下偷偷做的事。所以监理读不到，只说明它没说，"
    "不说明它干净。</p>"
    "<p class=\"muted small\"><b>看结果时注意</b><br>"
    # ★ 0.53.5（STE100 体检 S-11）：「每档」→「每条结果」—— 读者没有
    #   "档"这个概念；行标题已经说了是哪一级。
    "· 每条结果都带「自认」：这是工具自己承认的部分。<br>"
    # ★ 0.53.5（同 S-11）：「单独一档」→「单独一类」。
    "· 「没查到」单独一类：这是监理没走到的地方。请当空白读，"
    "不要当成「没问题」。</p>"
    "<p class=\"muted small\"><b>这次体检只是局部的</b><br>"
    "不查代码漏洞、病毒、性能、别的软件、有没有被入侵。"
    "要查这些，需要另外的工具。</p>")


def default_view():
    """首启默认落点（设计 §21.2 接触点 2）：从未体检过 ⇒ 先落体检页。

    ★ 读不出快照状态时落收件箱（老行为）—— 不拿用户的首屏赌一个可能误判的默认值。
    """
    try:
        import host_shield as _hs
        seen = bool(_hs.health_reports())
    except Exception:                                         # noqa: BLE001
        seen = True
    return "inbox" if seen else "health_exam"


#: 路由白名单（0.53.0 T0 起五把视图；`bubble` 在 handler 里单独分支，不走这里）
_VIEWS_ALLOWED = ("inbox", "report", "health", "ledger", "health_exam")


def _resolve_view(view):
    """URL 里的视图名 → 真视图名。空 ⇒ 首启落点；不在白名单 ⇒ 收件箱。

    ★ 不静默当成"全部"：坏视图名落回收件箱，与坏筛选值落默认档同一条纪律
      （用户以为自己看到了某个页，其实看到的是另一个）。
    """
    if not view:
        return default_view()
    return view if view in _VIEWS_ALLOWED else "inbox"


def _exam_dt(doc):
    """从**已读出的存档**取 `generated_at`（`datetime`）；解析不出 ⇒ `None`。

    ★ 时刻解析的**唯一实现**（页头一行、回看标注、同趟分组三处都走它）。
      分组是第三处要时刻的地方 —— 不在这一层收口，就会出现第四份解析。
    ★ 解析不出 ⇒ `None`，**不猜**：拿文件名（写入时刻）当第二来源，
      两份事实迟早对不上。
    """
    try:
        return datetime.fromisoformat(str((doc or {}).get("generated_at") or ""))
    except Exception:                                         # noqa: BLE001
        return None


def _exam_when_doc(doc):
    """`(相对, 绝对时刻)` —— 如 `("1 天前", "10-18 18:01")`。

    ★ 相对与绝对**同一次算出**：页头一行与回看标注若各算一遍，迟早对不上。
    """
    dt = _exam_dt(doc)
    if dt is None:
        return ("时间不详", "")
    n = (datetime.now().astimezone().date() - dt.date()).days
    return ("刚刚" if n <= 0 else "%d 天前" % n, dt.strftime("%m-%d %H:%M"))


def _exam_when(path):
    """同 `_exam_when_doc`，但从**路径**读（存档里的时间是唯一事实）。"""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except Exception:                                         # noqa: BLE001
        return ("时间不详", "")
    return _exam_when_doc(doc)


def _exam_ago(path):
    """「上次体检：N 天前」—— 当天＝「刚刚」（设计 §20.4 一行版；§20.5：对比不展开）。

    ★ 唯一实现＝`_exam_when`（本函数只取相对那一半，不第二份算）。
    """
    return _exam_when(path)[0]


def _exam_replay_note(path):
    """回看标注（设计 §30.2）：说清这是**存档里那一次**，不是刚跑的。

    ★ 只给**绝对时刻**：若这里也算一遍相对天数，在「最近一份是命令行体检」
      时会与页头那句互相打脸（页头 2 天前／标注 1 天前）——两句话讲同一件事
      却给出两个数，是本节要防的病。
    """
    _rel, _abs = _exam_when(path)
    # ★ 2026-10-21 STE100 精炼：两句并一句半，保留「不是刚跑的」——
    #   0353 `c_exam_replay_note` 钉的就是这四个字（判据锚点，不许改）。
    return ("这是本机存档里上一次体检的结果（%s），不是刚跑的。"
            "工具当时写下的原文也在里面。" % (_abs or _rel))


#: 同一次体检的判定（分钟）：两次体检**间隔不到这个值** ⇒ 同一趟（重跑），
#: 「历次体检」里只列一次。
#:
#: ★ 为什么是 30（实测推出来的，不是拍的）：体检跑完要几分钟；跑完看结果、
#:   发现不对再跑一次，这一整套来回实测落在 35 分钟内 —— 创始人 2026-10-19
#:   那一趟三条：03:58 → 04:20 → 04:32，间隔 22／12 分钟。
#: ★ 窗口再大就会吞掉真正分两次的体检（隔一小时该分列，见判据 P22-2）。
#: ★ 合并不了就**不合并**（保守方向）：读不出时刻（`None`）⇒ 各自算一次。
EXAM_SAME_RUN_MIN = 30


def _exam_group_runs(items):
    """把**升序**的体检存档并成「一次体检」的组：`[[{...}], [{...}, {...}]]`。

    ★ 纯函数（不读盘、不写盘）⇒ 判据可以直接喂形状，负控可以直接换掉它
      （可替换是判据能打到它的前提）。
    ★ 组内顺序保持升序 ⇒ 定稿＝组内最后一份（`_exam_run_kept`）。
    """
    groups = []
    for it in items:
        prev = groups[-1][-1] if groups else None
        _a, _b = (prev or {}).get("dt"), it.get("dt")
        if (_a is not None and _b is not None
                and 0 <= (_b - _a).total_seconds() < EXAM_SAME_RUN_MIN * 60):
            groups[-1].append(it)
        else:
            groups.append([it])
    return groups


def _exam_run_kept(group):
    """一趟体检里「历次」**列哪一份**：定稿＝组内**最新**那份。

    ★ 取最旧那份的后果（实测）：同趟里明明有一份带明细，页面却说「没存明细」
      —— 有证据却报没证据，正是本仓最忌的形状：
      **没查／没存 与 查了没事 显示成同一个样子**（判据 N-P22-3 守这条）。
    """
    return group[-1]


def _exam_history():
    """历次**体检**（**倒序**，最近在前）。每项 `{"path","base","when","ok"}`。

    ★★ 0.53.0（T2 追加，设计 §38.5）：**同一趟里的重跑只算一次**。
      体检要跑几分钟，跑完看结果、再跑一遍是同一件事 —— 列三条就是把一次
      体检冒充成三次（创始人 2026-10-19 原话：「实际上这就是一次」）。
      合并窗口＝`EXAM_SAME_RUN_MIN`，一趟里列**最新那份**（定稿）。
    ★ `ok`＝**能回看**（存档里带明细）。旧存档 `ok=False` ⇒ 列表里标「没存明细」，
      **不生成链接**（点进去也没东西，那是骗点击）。
    ★ 只读，不写、不改：被并掉的那几份字节仍在磁盘上（零删除），只是不再
      单列 —— 合并是**列表口径**，不是销毁。
    """
    import host_shield as _hs
    items = []
    for p in _hs.health_reports():
        try:
            with open(p, encoding="utf-8") as f:
                doc = json.load(f)
        except Exception:                                     # noqa: BLE001
            continue
        # ★ 只认控制台体检：命令行体检（host-audit）形状不同，喂给体检页的
        #   渲染函数会渲染出别的页面 —— 合并逻辑也不许把它并进同一趟。
        if not isinstance(doc, dict) or doc.get("source") != "console-exam":
            continue
        _rel, _abs = _exam_when_doc(doc)
        items.append({"path": p, "base": os.path.basename(p),
                      "when": _abs or _rel, "dt": _exam_dt(doc),
                      "ok": bool(isinstance(doc.get("report"), dict)
                                 and doc.get("report"))})
    groups = _exam_group_runs(items)
    return [_exam_run_kept(g) for g in reversed(groups)]


def _exam_pick(hist, pick):
    """从历次里挑出要看的那一次；挑不出 ⇒ 最近一次**能回看**的。

    ★★ `pick` 只认**档案自己的文件名**，绝不拿它拼路径：它来自 URL 查询串，
      任何拼路径的写法都是路径穿越。挑不到就退回默认（不报错、不渲染空页）。
    """
    if pick:
        for h in hist:
            if h["base"] == pick and h["ok"]:
                return h
    for h in hist:
        if h["ok"]:
            return h
    return None


def _exam_doc_by_base(base):
    """按**档案文件名**取体检存档。返回 `(doc, path)`；取不到 ⇒ `(None, "")`。

    ★ 与 `_exam_pick` 同一纪律：`base` 来自 URL ⇒ **绝不拼路径**，
      只在 `host_shield.health_reports()` 列出的真档案里按 basename 认。
    ★ 只认控制台体检（`source == "console-exam"`）：命令行体检
      （host-audit）形状不同，导出它会得到另一份东西 —— 与
      `_exam_history` 同一条口径。
    """
    import host_shield as _hs
    if not base or os.path.basename(base) != base or base in (".", ".."):
        return None, ""
    for p in _hs.health_reports():
        if os.path.basename(p) != base:
            continue
        try:
            with open(p, encoding="utf-8") as f:
                doc = json.load(f) or {}
        except Exception:                                     # noqa: BLE001
            return None, ""
        if not isinstance(doc, dict) or doc.get("source") != "console-exam":
            return None, ""
        return doc, p
    return None, ""


def _exam_export_base(_arch, chosen, st):
    """导出来源（档案文件名）。★ 优先**当前正在看的那一份**：

    · 回看旧档 ⇒ 导出旧档（不许偷偷导成最新一次 —— 读者以为自己在存这一份）；
    · 刚跑完、存档已落盘 ⇒ 导这一份；
    · 两者都没有（内存结果没存下来／旧存档没明细）⇒ 空串 ⇒ 页面上不给链接
      （没有可导出的东西却画一个下载按钮，就是「点了没反应」的源头）。
    """
    if _arch:
        return os.path.basename(_arch)
    if chosen and chosen.get("ok"):
        return str(chosen.get("base") or "")
    saved = (st or {}).get("saved") or ""
    return os.path.basename(saved) if saved else ""


def _exam_export_links(base):
    """导出入口（2026-10-21 体检页优化·创始人拍板 D1/E）。

    ★ 两个链接指**同一份存档**：默认脱敏版（分享用）＋完整版（自己留）。
    ★ 脱敏态写进可见文字，也写进下载文件名 —— 给错版本要在文件名层
      就能发现（§10.3：选错文件＝静默给错版本，与「没说＝没有」同族）。
    ★ 不带 `?t=` 也照旧工作：0.48.6 B3 起站内口令走 httpOnly cookie
      （与历次体检链接同一条路）。
    ★★ 2026-10-21（创始人「下载能做成 PDF 而不是 HTML 吗」）：
      **默认给 PDF**（转发给别人时 PDF 才是通用格式），HTML 原件仍留一个入口 ——
      它是唯一「接收方可以读源码逐个核对数字」的形态（附件化三边界的信任属性）。
      三种都指**同一份存档**，格式只换壳、不换数（`fmt` 只决定打包方式）。
    """
    b = _esc(base)
    # ★★ 2026-10-21：**没有可导出的东西就不给链接**。`_exam_export_base` 的
    #   文档串早就这么承诺（"空串 ⇒ 页面上不给链接"），但本函数此前没守 ——
    #   `base` 为空时照样画出 `?e=&san=1&fmt=pdf`，点下去是 404。
    #   「点了没反应」的源头就在这里，与 §10.3「没说＝没有」同族。
    if not b:
        return ""
    # ★ 2026-10-21 活体实测：Edge 打印一次 3～20 秒（机器负载高时更久）⇒
    #   把预期写在句子裡，否则十几秒没反应会被当成坏了、还可能连点
    #   （每次连点都会再起一个 Edge，排在锁后面等）。
    return ("<div class=\"note\">把这份结果存成一份文件"
            "（PDF 要十几秒生成，别重复点）："
            "<a href=\"/exam-export?e=%s&amp;san=1&amp;fmt=pdf\">PDF（脱敏）</a>"
            "（用户名已替换，可转给他人）｜"
            "<a href=\"/exam-export?e=%s&amp;san=0&amp;fmt=pdf\">PDF（完整）</a>"
            "（含本机路径与用户名，只适合自己留着）｜"
            "<a href=\"/exam-export?e=%s&amp;san=1\">HTML 原件</a>"
            "（可逐个核对数字）</div>" % (b, b, b))


#: PDF 打印用的 Edge 候选路径（本机实测只有 Edge；不装 Python PDF 库的理由见
#: `_exam_pdf_bytes` 文档串）。
_EDGE_CANDIDATES = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)
_EXAM_PDF_LOCK = threading.Lock()


def _edge_exe():
    """本机可用的 Edge 可执行文件；没有 ⇒ 空串（**不猜、不静默**）。"""
    for p in _EDGE_CANDIDATES:
        try:
            if os.path.isfile(p):
                return p
        except OSError:
            continue
    return ""


def _wait_fresh_file(path, before, timeout=90.0, interval=0.25):
    """等一个**比 `before` 新**、且**大小稳定**的文件出现。

    ★★ 为什么必须等（2026-10-21 实测，时红时绿的真因）：Edge 的无头打印
      **进程退出 ≠ PDF 写完** —— 实测同一台机器上，进程返回后 PDF 还要
      3～18 秒才落盘（机器负载高时更久）。旧实现「进程一返回就看文件」
      ⇒ 同一份代码时成时败（预览实例那次碰巧快、活体那次慢），
      正是本仓铁律 2 最忌的形状。
    ★ 判据是**两件事**：① mtime 前进（不是"文件在不在"——旧文件会把失败
      伪装成成功）；② 大小连续两次不变（否则可能读到写了一半的 PDF）。
    """
    deadline = time.time() + float(timeout)
    last = -1
    stable = 0
    while time.time() < deadline:
        try:
            if os.path.getmtime(path) > before:
                size = os.path.getsize(path)
                if size > 0 and size == last:
                    stable += 1
                    if stable >= 2:
                        return True
                else:
                    stable, last = 0, size
        except OSError:
            pass
        time.sleep(interval)
    return False


def _exam_pdf_bytes(html_txt, root=None, timeout=90):
    """导出 HTML → PDF（本机 Edge 的**无头打印**）。返回 `(pdf_bytes, 原因)`。

    ★★ 为什么不是 Python PDF 库：本仓「零运行时依赖」是产品论点的一部分（wheel
      纯 stdlib，装完就能跑）。为一种导出格式塞 reportlab／weasyprint，等于给
      自己的论点拆台 —— 而 Edge 是 Windows 自带、也正是用户此刻打开监理用的那个
      浏览器。转不出来时**如实说**，不退回 HTML 冒充 PDF（格式给错与「选错文件」
      同族：§10.3「静默给错版本」）。
    ★ 落盘固定在自家中枢 `<hub>/console/export-tmp/`，**覆盖写、不删除**：
      宿主的删除动作会走回收站（单次近 10s，本仓踩过）；`mtime` 前进才认新产物，
      不靠「文件在不在」判断成功（旧文件会把失败伪装成成功）。
    """
    import inbox_config as _C
    exe = _edge_exe()
    if not exe:
        return None, "这台机器上没找到 Edge（PDF 由它打印，本仓不带 PDF 依赖）"
    d = os.path.join(_C.console_dir(root), "export-tmp")
    try:
        os.makedirs(d, exist_ok=True)
        src = os.path.join(d, "exam.html")
        out = os.path.join(d, "exam.pdf")
        with open(src, "w", encoding="utf-8", newline="\n") as f:
            f.write(html_txt)
    except OSError as e:
        return None, "临时文件写不进去（%s）" % e
    before = os.path.getmtime(out) if os.path.exists(out) else 0.0
    cmd = [exe, "--headless", "--disable-gpu", "--no-first-run",
           "--user-data-dir=" + os.path.join(d, "edgeprof").replace("\\", "/"),
           "--print-to-pdf=" + out.replace("\\", "/"),
           "file:///" + src.replace("\\", "/")]
    try:
        with _EXAM_PDF_LOCK:                      # Edge 实例串行：并发打印会互相踢
            subprocess.run(cmd, timeout=timeout, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=0x08000000 if os.name == "nt" else 0)
    except Exception as e:                        # noqa: BLE001
        return None, "Edge 打印没跑完（%s: %s）" % (type(e).__name__, e)
    # ★ 进程退出 ≠ 写完（实测 3～18s 才落盘）⇒ 等文件真出现再读
    if not _wait_fresh_file(out, before, timeout=timeout):
        return None, ("Edge 打印进程回来了，但 %d 秒内没等到 PDF 落盘"
                      % int(timeout))
    try:
        with open(out, "rb") as f:
            data = f.read()
    except OSError as e:
        return None, "PDF 读不回来（%s）" % e
    if not data.startswith(b"%PDF-"):
        return None, "Edge 产出的东西不是 PDF"
    return data, ""


def _exam_pdf_fail_html(base, why):
    """PDF 转不出来时的**人话页**（带 HTML 入口，不让人走进死胡同）。"""
    return ("<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\">"
            "<title>PDF 没转出来</title>"
            "<div style=\"font:15px/1.7 system-ui;padding:24px;max-width:680px\">"
            "<h2>PDF 没转出来</h2><p>%s。</p>"
            "<p>HTML 那一份仍然可以下载："
            "<a href=\"/exam-export?e=%s&amp;san=1\">下载 HTML 原件</a></p>"
            "<p style=\"color:#666\">PDF 由本机 Edge 打印生成 —— "
            "本仓不带 PDF 依赖（装完就能跑，不额外拉库）。</p></div></html>"
            % (_esc(why), _esc(base)))


def _exam_history_html(hist, chosen):
    """「历次体检」一行：能回看的给链接，不能回看的**只给字、不给链接**。

    ★ 只有一次时不显示（品质性：不啰嗦 —— 一行只有一个选项的列表是噪音）。
    ★ 当前那一次加粗、**不给链接**（它已经是这一页）。
    """
    if len(hist) < 2:
        return ""
    items = []
    for h in hist:
        if not h["ok"]:
            items.append("<span class=\"muted\">%s（没存明细）</span>" % _esc(h["when"]))
        elif chosen and h["base"] == chosen["base"]:
            items.append("<b>%s</b>" % _esc(h["when"]))
        else:
            items.append("<a href=\"/?v=health_exam&e=%s\">%s</a>"
                         % (h["base"], _esc(h["when"])))
    return "<div class=\"note\">历次体检：%s</div>" % " ｜ ".join(items)


def _exam_stale_note(path):
    """旧存档（0.53.0 T2 之前）的如实说明：那次**只存了汇总**，明细没存下来。

    ★ 不许写成「还没体检」——体检做过，只是当时的实现没把明细落盘。
      把「没存下明细」说成「没体检过」，就是本仓最忌的那件事：
      **没查/没存 与 查了没事 显示成同一个样子**。
    """
    _rel, _abs = _exam_when(path)
    return ("本机存档里有一次体检（%s），但那次只存了汇总数字，明细没存下来。"
            "要看明细得重跑一次。" % (_abs or _rel))


def _exam_absorb(res):
    """体检跑完把结论收成一份存档（设计 §30.1：存档＝可回看的报告）。

    ★★ 0.53.0（T2，创始人 2026-10-19 拍板）**存档里要有能回看的细节**：
      旧版只存 6 个汇总数（实测 245 字节）⇒ 服务重启后内存一空，用户看到的是
      「上次体检：1 天前」配「这次打开还没跑过体检」——**同一页两句相反的话**，
      而那次的结论一个字都找不回来。存档因此**连带存整份结果**（含每个工具
      自己写下的原文），回看时走同一个渲染函数，不写第二套。

    ★ 边界（如实写，不许含糊）：存的是**工具自己写下的字段原文**（它自认的
      那部分），不是用户项目文件的内容。这条边界由判据 H9d 的键白名单守。

    ★ 写失败返回 None ⇒ 引导条照旧显示（「完成一次体检」这件事没留下证据），
      **不许**把没存下来渲染成存下来了。
    """
    import antinel as _A
    import host_shield as _hs
    scan = (res or {}).get("scan") or {}
    eg = (res or {}).get("egress") or {}
    vc = scan.get("counts_by_verdict") or {}
    doc = {"schema": "antinel.health/1",
           "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
           "source": "console-exam",
           "tools": len(scan.get("tools") or []),
           "verdicts": {k: int(vc.get(k, 0) or 0) for k in _A.VERDICTS},
           "conns": len(((eg.get("snapshot") or {}).get("conns")) or []),
           # ★ 回看的唯一来源：整份结果原样存，回看时不裁剪、不重算。
           "report": res or {}}
    try:
        return _hs.save_health_report(doc)
    except Exception:                                         # noqa: BLE001
        return None


def _exam_last_report(require_report=True):
    """最近一份控制台体检存档，返回 `(doc, path)`；没有 ⇒ `(None, "")`。

    ★ 只看 `source == "console-exam"`：命令行体检那份（host-audit）形状不同，
      喂给体检页的渲染函数会渲染出别的页面。
    ★ `require_report=True`（默认）＝只要**能回看**的（带 `report`）；
      传 False ＝也要**不能回看的旧存档**（0.53.0 T2 之前存的只有汇总数字），
      页面用它来如实说「那次的明细没存下来」，而不是掉进
      「这次打开还没跑过体检」——后者与页头「上次体检：1 天前」自相矛盾。
    ★ 只读，不写、不改。
    """
    import host_shield as _hs
    for p in reversed(_hs.health_reports()):
        try:
            with open(p, encoding="utf-8") as f:
                doc = json.load(f)
        except Exception:                                     # noqa: BLE001
            continue
        if not isinstance(doc, dict) or doc.get("source") != "console-exam":
            continue
        if require_report and not (isinstance(doc.get("report"), dict)
                                   and doc.get("report")):
            continue
        return doc, p
    return None, ""


def _exam_start():
    """起一次体检（幂等：正在跑就不再起一条）。返回是否真的起了。"""
    with _EXAM_LOCK:
        if _EXAM.get("state") == "running":
            return False
        _EXAM.update(state="running", stage="正在看有没有程序在往外发数据…",
                     error="", started=time.time(), finished=0.0)
    threading.Thread(target=_exam_job, daemon=True).start()
    return True


def _exam_job():
    """后台跑一次体检：先快后慢（与 ui_server._job 同一次序）。

    ★ 跑完收快照（`_exam_absorb`）—— 存档只增不改，超量由 host_shield 轮转。
    ★ 诱饵文件状态走 `antinel.canary_summary`（唯一实现），取不到说「没查到」，
      **不许**静默变成「没有诱饵文件」。
    """
    import ui_server as _U
    try:
        eg = _U._run_egress(_pkg_root())
        with _EXAM_LOCK:
            _EXAM["stage"] = "正在逐个检查你电脑上的 AI 工具…（这一步通常要几分钟）"
        scan = _U._run_host_scan(_pkg_root())
        res = {"scan": scan, "egress": eg,
               "canary": _U._canary_data(_pkg_root())}
        saved = _exam_absorb(res)
        with _EXAM_LOCK:
            _EXAM.update(state="done", result=res, stage="", saved=saved or "",
                         finished=time.time())
    except Exception as e:                                     # noqa: BLE001
        with _EXAM_LOCK:
            _EXAM.update(state="error",
                         error="%s: %s" % (type(e).__name__, e),
                         finished=time.time())


def _view_exam(token="", pick=None):
    """体检页（第五个 TAB）。★ 接入不是新建：渲染复用 `ui_server._result_html`
    （唯一实现），本函数只做入口、缓存读取、快照行、三态与边界。

    ★ `pick`＝要看哪一次（档案文件名）。**每一次体检都能回看**，不是只最近一次
      （创始人 2026-10-19 追加要求）。
    """
    import ui_server as _U
    import antinel as _A
    import host_shield as _hs
    out = []
    reports = _hs.health_reports()
    with _EXAM_LOCK:
        st = dict(_EXAM)
    res = st.get("result")
    hist = _exam_history()
    chosen = _exam_pick(hist, pick)
    # ★★ 0.53.0（T2）：内存里没有（服务重启过）⇒ **读本机存档**，不落到
    #   「这次打开还没跑过体检」。旧版在这里直接掉进空态 ⇒ 页头写着
    #   「上次体检：1 天前」、正文写着「还没跑过」，同一页两句相反的话
    #   （创始人 2026-10-19 实测）。存档是回看的唯一来源，不是装饰。
    _arch = ""
    if res is None and st.get("state") not in ("running", "error"):
        if chosen is not None:
            try:
                with open(chosen["path"], encoding="utf-8") as f:
                    res = (json.load(f) or {}).get("report") or None
                _arch = chosen["path"]
            except Exception:                                 # noqa: BLE001
                res, _arch = None, ""
    # ---- 页头：标题 ＋「上次体检」一行（§20.4；空态不显示那一行，§21.3）----
    _last = _exam_ago(reports[-1]) if reports else ""
    if _last:
        out.append("<h2>%s · 上次体检：%s</h2>"
                   % (PAGE_TITLES["health_exam"], _last))
    else:
        out.append("<h2>%s</h2>" % PAGE_TITLES["health_exam"])
        out.append("<div class=\"note\">%s</div>" % _EXAM_FIRST)
    # ---- 首启引导条（§21.2 接触点 2，逐字；快照存在后永久消失，§21.4）----
    if not reports:
        out.append("<div class=\"guide\"><b>%s</b></div>" % _EXAM_GUIDE)
    # ---- 边界（§20.2：TPL 原文逐字保留 ＋ 局部边界新增，写在首屏）----
    out.append(_EXAM_BOUND)
    # ---- 触发／进行中／结果 ----
    if st.get("state") == "running":
        out.append("<div class=\"note\">体检正在进行：%s"
                   "　<a href=\"/?v=health_exam\">刷新这一页看看</a></div>"
                   % _esc(st.get("stage") or ""))
    elif st.get("state") == "error":
        out.append("<div class=\"err\">这次没查成：%s——结果不算数，"
                   "不要当成「全部干净」。</div>"
                   % _esc(st.get("error") or "原因不详"))
        out.append(_form(token, "exam", label="重新体检"))
    elif res:
        if _arch:
            # ★ 回看标注必须在报告**之前**：读者先知道这是旧的、是哪一次的，
            #   再看内容。放后面 ⇒ 有人会把旧结果当成刚跑的。
            out.append("<div class=\"note\">%s</div>" % _exam_replay_note(_arch))
        scan = res.get("scan") or {}
        tools = scan.get("tools")
        if tools is None:
            out.append("<div class=\"err\">%s</div>" % _EXAM_FAILED)
        else:
            if not tools:
                out.append("<div class=\"warn\">%s</div>" % _EXAM_NO_TOOLS)
            # ★ 渲染唯一实现＝`_U._result_html`（与刚跑完同一条路，不写第二套）
            # ★★ 2026-10-21 创始人 09:41：「PDF下载在哪儿呢？应该放在前边文字区吧？」
            #   导出入口经 `after_card` 插槽落在**结论卡正下方**（首屏内），
            #   不再挂在 59 条明细的末尾 —— 想存一份的时刻就在看完结论那一刻。
            out.append(_U._result_html(
                res, _A.VERDICTS, _A._ev_human,
                after_card=_exam_export_links(
                    _exam_export_base(_arch, chosen, st))))
        if _arch:
            pass                      # 回看时不谈「这次存没存下来」
        elif not st.get("saved"):
            out.append("<div class=\"note\">这次体检的结果没能存成本机档案"
                       "（目录不可写？）——下次打开还会提醒你做一次。</div>")
        out.append(_form(token, "exam", label="重新体检"))
    else:
        # ★ 有旧存档（没明细）⇒ **如实说它没明细**，不许说「还没跑过体检」——
        #   页头正写着「上次体检：1 天前」，这两句摆一起就是自相矛盾。
        _doc0, _p0 = _exam_last_report(require_report=False)
        if _p0:
            out.append("<div class=\"note\">%s</div>" % _exam_stale_note(_p0))
        else:
            out.append("<div class=\"note\">这次打开还没跑过体检。跑一次只要几分钟，"
                       "全程只读，不改你电脑上的任何文件。</div>")
        out.append(_form(token, "exam", label="开始体检"))
    # ---- 导出入口已上移到结论卡正下方（见 `after_card` 插槽，2026-10-21 09:41）----
    # ★ 留账（设计 §23.3）：这里**撤掉了**原来挂在页尾的 `_exam_export_links`，
    #   去处＝结论卡正下方；不是"删了不管"，同一份链接换了位置。
    # ---- 历次体检（归档导航，放最后；只有一次时不显示，不啰嗦）----
    out.append(_exam_history_html(hist, chosen))
    return "<div class=\"exam\">%s</div>" % "".join(out)


#: ★ 0.36.5 **页面名的唯一真源**（从 `render_page` 体内提为模块级）。
#:   为什么提上来：`inbox_window._mark_at_tail()` 要用同一份页面名来判
#:   「这个窗口标题是不是我们自己开的」—— 那份映射若留在函数体里，
#:   窗口侧就只能**再抄一遍**，抄出来的必然漂移（这已是本轮第二次同型事故：
#:   上一次是 `_matches_title` 的注释与实现相反）。
#:   ⇒ 唯一真源在这里，窗口侧 **import 它**，不二次实现。
PAGE_TITLES = {"inbox": "收件箱", "report": "日报", "health": "运行状态",
               "ledger": "账本", "health_exam": "体检"}

#: ★ 2026-10-21（TAB 切换卡顿根治·方案 C，创始人拍板）：账本页 GET 的
#:   **进程内节流**参数与状态缝。
#:   为什么（只读轮实测 R3）：旧版每次打开账本页都同步跑 `record_day()`
#:   ——14 天窗口逐日比对＋持锁追加，实测单次追加 6 个变更多天、每笔
#:   0.4–1.0s；而它是**幂等**的（数字没变一行都不写）⇒ 重复跑的收益
#:   是零、成本全付。实测账本页空闲 9.88s vs 运行状态 0.79s 的 9 秒差
#:   大头就在这里。
#:   ★ 语义不变（0.51.0 账准修复的承诺不破）：daemon `tick()` 照旧每轮
#:     **直调** `record_day`（不经过本函数，守护进程一个字节都没动）；
#:     这里只节流"用户打开账本页"这一路。首次打开必然触发一次
#:     （`t=None`），GAP 内重复打开跳过；守护进程没跑的日子，第一次
#:     打开仍然补记 —— 0.51.0 修复的核心场景不受影响。
#:   ★ 状态缝可注入可复位（判据 Lesson：进程级可变状态必须能让量具
#:     复位，否则同进程内前序检查的残留会让后一条判据假红/假绿）。
_RECORD_DAY_MIN_GAP = 45.0
_RECORD_DAY_STATE = {"t": None}


def _maybe_record_day(items=None, root=None, now=None):
    """账本页 GET 的记账入口：进程内 N 秒内只跑一次（方案 C）。

    返回 `record_day` 的结果；被节流跳过 ⇒ None。`now` 可注入（判据
    专用；生产不传，走 `time.monotonic()` —— 跨进程只在本进程内有效，
    换进程（重启监理服务）后第一次打开必然重新触发）。
    """
    import inbox_daemon as _DM
    t = time.monotonic() if now is None else now
    last = _RECORD_DAY_STATE["t"]
    if last is not None and (t - last) < _RECORD_DAY_MIN_GAP:
        return None
    _RECORD_DAY_STATE["t"] = t
    return _DM.record_day(items=items, root=root)


def render_page(view="inbox", filt=None, root=None, token="", items=None, rep=None,
                posture=None, now=None, record_ledger=False, notice="", exam=None):
    """渲染整页。可注入 items/rep/posture（测试用）。

    ★★ 0.35.2 修（真缺陷，创始人 2026-10-06「点开像卡死」）：
      旧版**无条件**算 `daily_report()`，而日报里 `chain_health()` 会**逐条复算整条审计链**
      （本机实测 40101 条 ≈ 7.8s）。收件箱页（默认视图）**根本不用 rep**
      ⇒ 每次点开都白等 7.8s，四个视图实测各 7.7–9.6s。
      ⇒ 现在**只有真要用日报的视图**才算，收件箱页不再算。

    ★★ 0.35.3：视图名默认改 `action`（要处理），并且**每个视图都不再默认"全部历史"**。
    """
    if items is None:
        # ★★ 0.53.2（创始人 2026-10-20「账本有记录永远是 8 天，从来不会增长」）：
        #   账本＝**历史全量**，收件箱／日报＝"最近"。旧版五个视图共用一句
        #   `S.load_items(root=root)`，而它默认 `days=7` ⇒ 账本的「有记录多少天」
        #   **恒等于窗口长度**（含今天恰好 8 天），读者看到的是取数参数不是数据。
        #   实测本机：窗口 7 天 ⇒ 8 天；全量 ⇒ **39 天**（2026-09-10 → 10-20）。
        #   ★ 只改账本这一个视图 —— 收件箱「看一眼」本就是近期口径，动它会把
        #     一批既有计数判据一起改掉（那是另一个问题，不在本轮）。
        items = (S.load_items_all(root=root) if view == "ledger"
                 else S.load_items(root=root))
    # ★ 0.35.3：打开账本页时，用当前可读到的链记录刷新当日快照。
    #   旧版只有显式运行 `inbox daemon` 才写 ledger；正常打开 server 无人写，
    #   因而账本文件不存在、数字一直全零。写入委托给 daemon 唯一实现；只在
    #   用户打开账本页时采样，不让普通收件箱 GET 多做持久化。
    if record_ledger and view == "ledger":
        # ★ 2026-10-21（方案 C）：改走节流入口 `_maybe_record_day` ——
        #   每打开一次账本页就全量重跑 14 天窗口是白付（幂等：没变一行
        #   不写）。daemon tick 的记账**不走这里**（它直调 record_day）。
        _maybe_record_day(items=items, root=root)
    # ★ 非法/缺省筛选值 ⇒ 默认「要处理」（**不静默当成"全部"** —— 那会让用户以为
    #   自己看到的是筛选结果，其实是一整条历史）。
    if not filt or not M.known_filter(filt):
        filt = M.BUCKET_ACTION
    # ★ 2026-10-21（体检页优化·C）：折叠开关脚本**只用这一份定义**
    #   （`ui_server._EXAM_FOLD_JS`；本地页与控制台共用一个来源，
    #   不许在两侧各抄一份 —— 抄了就漂）。
    _fold_js = ""
    if view == "health_exam":
        import ui_server as _U
        _fold_js = "<script>%s</script>" % _U._EXAM_FOLD_JS
    # ★★ 0.48.5（交接件 §5.5 W-01）：标题**恒用状态词**，与顶部条同一个词
    #   （`M.light_explain()` 是唯一实现 —— 标题与头部不许两种说法）。
    #   创始人原话：「标题该显示的是状态——那是 Alt-Tab / 任务栏里唯一
    #   不用开窗就能看到的一行，用户要的是『拦截/值守中/失守』，不是
    #   『收件箱』、更不是 #96a621」。页面名归选项卡 + h2（乙3 已补，
    #   零损失）；hash 只留在标题尾（认窗必需，正文零 hash 由 W-02 锁）。
    #   状态词取值必然落在 `host_shield.POSTURE_LABEL_ALLOWED` 内
    #   （`STATE_LABEL` ∪ ｢未启用｣ 是它的子集 —— W-01 判据逐词断言）
    #   ⇒ 窗口在任何可达灯态下都认得出、落位不失效。
    # ★★ 0.51.1 反转（创始人 2026-10-16 拍板；W-01 退休入
    #   suite_retirement.json，新契约冻结为 FZ-002）：上面 0.48.5 原话
    #   **作废**——创始人新话「只要保留 Antinel 监理加上编号就行了」。
    #   标题恒为「Antinel 监理#<6hex>」（身份串由 `_head` 注入：无状态词、
    #   无页面名前缀）。状态词的可见位移到页面内顶部条（`_bar` 的 light
    #   状态块，`ex["label"]` 原样在那里）；Alt-Tab 一行的信息密度让位
    #   于**窗口唯一可认领性**（认窗 `_mark_at_tail` 只认品牌开头形态）。
    #   title 参数降级为 fallback：`_head` 的 inbox_window 注入失败时退回
    #   页面名（人话可读、不假造标题）。旧形态断言随退休走 D-38 冻结
    #   执法（`window_title_format`）。
    p = posture or posture_now()
    ex = M.light_explain(p, items, now=now, granary=M.granary_now())
    title = PAGE_TITLES.get(view, "收件箱")
    if view in ("report", "health", "ledger"):
        # ★ 2026-10-21（TAB 切换卡顿根治·方案 A，创始人拍板）：旧版
        #   `daily_report()` **函数体内又自算一次** `guard_posture`（入参经
        #   核实与本函数 `posture_now()` 是同一目录、同一函数）⇒ report/
        #   health/ledger 每页把同一件事实算两遍（满载实测 ~1.2s/页，另加
        #   心跳链 15MB 双读）。现在把上面已现探的 `p` 注入进去：**一个事实
        #   一个变量，页面从头到尾同一份态势**（0.53.0 T4 纪律的延伸）；
        #   `daily_report` 的 `posture` 默认 None ⇒ 不自算时行为不变
        #   （CLI 日报/邮件/判据零影响）。判据：TP-A1（0514 套件）。
        rep = (R.daily_report(root=root, items=items, posture=p)
               if rep is None else rep)
        if view == "report":
            body = _view_report(rep, token, items)
        elif view == "health":
            body = _view_health(rep, token, items)
        else:
            body = _view_ledger(rep, token, items)
    elif view == "health_exam":
        # ★ 0.53.0（T0）：体检页**不算日报**（不白等 7.8s 复算审计链）——
        #   它要的数据由 _view_exam 里的进程内缓存负责，GET 从不触发采集。
        body = _view_exam(token, pick=exam)
    else:
        # ★★ 0.53.0 T4（创始人 2026-10-19「这种超级违和还能死灰复燃」）：
        #   旧版这里传的是**入参 `posture`**，而 `p = posture or posture_now()`
        #   在上面 —— 不注入时（＝每一次真实打开）整页拿到 None ⇒ 归因模块的
        #   态势门控走 `posture is None` 那条兜底路径 ⇒ 值守中照样渲染
        #   「现在重新拉起」。判据 W-SPK10 只注入姿态跑，走不到这条路 ⇒ 假绿。
        #   ⇒ 传 `p`：**一个事实一个变量**，页面从头到尾同一份态势。
        body = _view_inbox(items, token, filt, now=now, posture=p)
    if notice:
        body = ('<div class="notice" role="status"><b>操作回执：</b>%s</div>'
                % _esc(str(notice)[:800])) + body
    return (_head(title, token,
                  extra_css=EXAM_CSS if view == "health_exam" else "")
            + _bar(items, token, posture=p, now=now, view=view, ex=ex)
            + _tabs(view, token)
            # ★ 2026-10-21（方案 E）：切页细进度条的挂点（fixed 定位，
            #   JS 给它加 .run 才动；无 JS 时 width 恒 0 不可见）。
            + "<div class=\"tabprog\" id=\"tabprog\"></div>"
            + "<main>" + body + "</main>"
            + _FLIP_JS + _READ_JS + _LOGO_JS + _escape_js(token)
            + _collapse_js(token)
            + _TAB_JS
            + _fold_js
            + "</body></html>")


# ------------------------------------------------------------- 服务 ----
def _make_handler(token, root):
    class H(BaseHTTPRequestHandler):
        server_version = "AntinelConsole"
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):                  # 不写日志文件（避免把内容落盘）
            pass

        # ---- 公共校验 ----
        def _deny(self, msg):
            """拒绝时给一个**能回去**的页面。

            ★ 0.35.2：旧版回纯文本 ⇒ 浏览器停在白底文字上，创始人实测「退不回去」。
              口令错误时**绝不能**把正确口令回给调用方（那等于自己泄密），
              所以只给「返回上一页」，不给带 token 的链接。
            """
            if urlparse(self.path).path.startswith("/api/"):
                return self._send(403, "text/plain; charset=utf-8", msg.encode("utf-8"))
            html_ = ("<!doctype html><meta charset=utf-8><title>访问被拒</title>"
                     "<style>body{font:14px/1.7 system-ui,sans-serif;padding:40px;color:#333}"
                     "a{color:#06c}</style>"
                     "<h3>%s</h3>"
                     "<p>如果你是从 Antinel 监理页面点过来的，说明这个按钮的请求没带上访问口令 ——"
                     "那是程序缺陷，请把它报出来。</p>"
                     # ★ 0.48.6（B3）：口令改由一枚 HttpOnly cookie 在站内携带
                     #   （URL 里不再有），于是"浏览器禁用了 Cookie"也会走到这里
                     #   —— 得让用户知道该去开什么，而不是干看着 403。
                     "<p>另一种可能：你的浏览器<b>禁用了 Cookie</b>。本页的口令靠一枚"
                     " HttpOnly cookie 在站内携带；禁用后页面能打开，"
                     "但点任何链接/按钮都会被拒。请在浏览器设置里允许本站使用 Cookie。</p>"
                     "<p><a href=\"javascript:history.back()\">← 返回上一页</a></p>" % _esc(msg))
            return self._send(403, "text/html; charset=utf-8", html_.encode("utf-8"))

        def _read_body_form(self):
            """读并解析 POST body（上限 64KB）。★ 必须**先读 body 再校验口令**。"""
            try:
                n = int(self.headers.get("Content-Length") or 0)
                n = max(0, min(n, 64 * 1024))
                return parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
            except Exception:                                   # noqa: BLE001
                return {}

        def _guard(self, body_form=None):
            port = self.server.server_address[1]
            if not _allowed_host(self.headers.get("Host"), port):
                self._deny("Host 不被允许")
                return False
            # ★ 0.48.6（B3）：口令来源按**优先级**排 —— query `?t=`（首字节那次）
            #   → 请求头（测试/CLI 用）→ **cookie**（此后所有站内导航与子资源）。
            #   比对仍然只有下面那一处（维一 · 入口唯一）。
            self._set_token_cookie = False
            q = parse_qs(urlparse(self.path).query)
            q_tok = (q.get("t") or [""])[0]
            got = (q_tok
                   or (self.headers.get("X-Antinel-Token") or "")
                   or _cookie_token(self.headers.get("Cookie")))
            # ★ 0.35.2：**口令也可能在 POST body 里**。
            #   页面上的每个按钮都是
            #     `<form method=post action="/action"><input type=hidden name=t …>`
            #   —— 口令走 **body**，而旧版 _guard 只看 query 与请求头 ⇒
            #   **每一次点击都 403**，也就是"全部已读/已处理/已忽略"这些按钮
            #   从上线起就没生效过。
            #   实测（2026-10-06 创始人报障）：点「全部已读」得到
            #   「action / 缺少或错误的访问口令」的纯文本页，且退不回去。
            #   ★ 为什么 64 条守卫没抓到：测试用 `req(token=…)` 把口令塞进
            #     **X-Antinel-Token 请求头**，而浏览器塞的是 **body** ——
            #     测试覆盖的是"我以为的请求"，不是"页面真的发出的请求"。
            #     配套新增判据 `c_forms_replay`：把页面上每个 form **原样重放**。
            if not got and body_form:
                got = (body_form.get("t") or [""])[0]
            if not secrets.compare_digest(str(got), str(token)):
                self._deny("缺少或错误的访问口令")
                return False
            # ★★ 0.48.6（B3）：只要"这次请求**自己**带了口令"（query `?t=` 或 POST body）
            #   就续上 cookie。此后页面里的链接/子资源**都不再带口令**（见 `_COOKIE`），
            #   靠这枚 cookie 即可。★ 来自 cookie / 请求头的不重复下发（没有新信息，
            #   白占响应头）；★ 走不到这里说明口令错/缺，那已由上面的 `_deny` 拦下。
            if q_tok or (body_form and (body_form.get("t") or [""])[0]):
                self._set_token_cookie = True
            return True

        def _send(self, code, ctype, body, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            # ★ 0.48.6（B3）：首字节那次下发口令 cookie。
            #   `HttpOnly` ⇒ 页面脚本读不到（XSS 偷不走）；
            #   `SameSite=Strict` ⇒ 跨站请求不带（CSRF 打不进来）；
            #   `Path=/` ⇒ 站内所有路径都带（含 /assets 与 /api）。
            if getattr(self, "_set_token_cookie", False):
                self.send_header("Set-Cookie",
                                 "%s=%s; HttpOnly; SameSite=Strict; Path=/"
                                 % (_COOKIE, token))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        # ---- 路由 ----
        def do_GET(self):
            if not self._guard():
                return
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path.startswith("/assets/"):
                return self._asset(u.path[len("/assets/"):])
            if u.path == "/api/items":
                rows = [i.to_dict() for i in S.load_items(root=root)]
                return self._json(rows)
            if u.path == "/api/report":
                return self._json(R.daily_report(root=root))
            if u.path == "/api/posture":
                return self._json(posture_now())
            if u.path == "/api/health":
                return self._json({"ok": True, "bind": self.server.server_address[0]})
            # ★ 2026-10-21 体检页优化·创始人拍板（D1/E）：体检结果导出。
            #   只读、不起采集（GET 语义保持纯净）—— 与体检页同一个 `_guard`。
            if u.path == "/exam-export":
                return self._exam_export(u.query)
            if u.path in ("/", "/index.html"):
                # ★ 0.53.0（T0）：没带 v 时按首检状态落点（无快照 ⇒ 体检页）；
                #   坏视图名落回收件箱（_resolve_view，不静默当成"全部"）。
                view = (q.get("v") or [""])[0]
                filt = (q.get("f") or [M.BUCKET_ACTION])[0]
                # ★ 0.49.0：`v=bubble` 是紧急提醒窗（「需要人工介入马上处理」的
                #   通知页）—— 与面板同源同 CSS，但**没有 tab、没有收件箱**，
                #   只有事由＋「知道了/打开Antinel 监理」。事由走 query（一次性渲染）。
                if view == "bubble":
                    import inbox_bubble as BB
                    try:
                        import inbox_window as _W
                        _rid = _W.build_run_id(token)
                    except Exception:                       # noqa: BLE001
                        _rid = ""
                    # ★ 0.50.3：渲染这一枚紧急提醒的**那一刻**，Antinel 监理是不是已经开着。
                    #   开着 ⇒ 不再画「打开Antinel 监理」按钮（点了它本来就该只是"切过去"，
                    #   画一个"打开"按钮是在说一件不成立的事）。判不出来 ⇒ 照旧画
                    #   （宁可多一个按钮，也不让用户点了没反应）。
                    try:
                        import host_shield as _hs
                        _cop = _hs.console_is_visible()
                    except Exception:                       # noqa: BLE001
                        _cop = None
                    page = BB.render((q.get("bt") or ["需要你处理"])[0],
                                     (q.get("bb") or [""])[0],
                                     (q.get("bl") or ["R0"])[0],
                                     token, run_id=_rid,
                                     kind=(q.get("bk") or ["R0"])[0],
                                     console_open=(_cop is True))
                    return self._send(200, "text/html; charset=utf-8",
                                      page.encode("utf-8"))
                # ★ 0.53.0（T0）：白名单从四把扩到五把（health_exam）；
                #   空/坏视图名的归落一律走 _resolve_view（唯一决策点）。
                view = _resolve_view(view)
                # ★ 非法筛选值 ⇒ 退回默认档（**不静默当成"全部"** —— 那会让用户
                #   以为自己看到的是筛选结果，其实是一整条历史）。
                if not M.known_filter(filt):
                    filt = M.BUCKET_ACTION
                # ★ 0.53.0（T2）：`e`＝要看哪一次体检（档案文件名）。
                #   只作为**挑选键**用，绝不拼进路径（`_exam_pick` 里兜着）。
                _epick = (q.get("e") or [""])[0]
                page = render_page(view=view, filt=filt, root=root, token=token,
                                   record_ledger=(view == "ledger"), exam=_epick)
                return self._send(200, "text/html; charset=utf-8", page.encode("utf-8"))
            return self._send(404, "text/plain; charset=utf-8", "没有这个页面".encode("utf-8"))

        def do_POST(self):
            # ★ 0.35.2：**先读 body，再校验口令** —— 页面表单把口令放在 hidden 字段里，
            #   旧版先校验（只看 query/请求头）再读 body ⇒ 每个按钮都 403。
            form = self._read_body_form()
            if not self._guard(body_form=form):
                return
            u = urlparse(self.path)
            if u.path != "/action":
                return self._send(404, "text/plain; charset=utf-8", b"no")
            op = (form.get("op") or [""])[0]
            _notice = ""
            try:
                if op == "fix":
                    # ★ 0.35.3：失守时就地修好（创始人第四条："应该有地方可以马上解决"）。
                    #   `guard_fix` 修不了会**如实说修不了**，不谎报。
                    import host_shield as _hs
                    _ok, _msg = _hs.guard_fix(_pkg_root())
                    print("[console] fix -> %s: %s" % (_ok, _msg))
                    _notice = ("已执行修复：" if _ok else "未能修复：") + str(_msg)
                elif op == "guard_fix":
                    # ★ 0.36.0：归因面板的「试一下/ 重新拉起 / 重新布防」。
                    #   复用 `guard_fix`（**唯一实现**），不二次实现修的动作。
                    #   ★ **当场复测**：修完再探一次，把结果如实显示 ——
                    #   不点完就显示"已修复"，那是本项目最恨的假绿形状。
                    import host_shield as _hs
                    _ok, _msg = _hs.guard_fix(_pkg_root())
                    # ★★ 0.37.1 修（0.35.3 同型漏改的**第四个**调用点）：
                    #   复测原来调 `_hs.guard_posture()` **不传包根** ⇒
                    #   `pkg_root=None` ⇒ 读**中枢 rollup 链**而不是本包审计链
                    #   （0.35.3 实测同一时刻相差 27202 秒 vs 160 秒）⇒
                    #   修好了也可能显示一个过时的「失守」，用户以为没修好。
                    #   ★ 标签一并改六态：姿态 label 里有「存疑」这个已被
                    #     创始人禁用的词（2026-10-07「计划外状态，不允许」）。
                    _p = _hs.guard_posture(_pkg_root())
                    # ★★ 0.39.0：与灯**同一份**口径（`current_state`）。
                    #   旧版这里调 `M.light(state, [])` —— 空账让它**恰好**
                    #   等价于此刻态，但"灯走 current_state、复测走 light"
                    #   是两个入口，迟早漂移。统一到唯一真源。
                    _pst = M.current_state(_p.get("state"))
                    _plabel = M.state_label(_pst, _p.get("state"))
                    _again = _hs.self_check()
                    if _ok:
                        print("[console] guard_fix -> 成功: %s" % _msg)
                        _note = "%s｜修完复测：%s（自检%s）" % (
                            _msg, _plabel,
                            "通过" if _again[0] else "不通过：" + "; ".join(_again[1]))
                    else:
                        # ★ 修不了**就把修不了的原因给回去**，不许只说"失败"
                        print("[console] guard_fix -> 失败: %s" % _msg)
                        # ★ 0.36.1：`<b>` 不是 `**` —— 页面是 HTML，
                        #   markdown 星号会原样显示给用户（创始人截图一）。
                        _note = "<b>没修好</b>：%s｜此刻仍是：%s" % (
                            _msg, _plabel)
                    _notice = re.sub(r"<[^>]*>", "", _note)
                elif op in ("remediation_drop", "remediation_ack"):
                    # ★ 0.36.0：B 类失守的处置**记录**。
                    #   ⚠️ **不执行任何降损动作** —— "移出监管名单"＝擅自放弃保护，
                    #   不是产品该替用户做的选择。这里只把用户的**决定**留痕，
                    #   真正改配置要走明确的 `host-shield` 命令（并可回滚）。
                    #   为什么要留痕：决定了不处理，后果是被记录的，
                    #   否则"我处理过什么"在链上查不到。
                    _iid = (form.get("id") or [""])[0]
                    _note0 = (form.get("note") or [""])[0]
                    print("[console] remediation(%s) id=%s note=%s"
                          % (op, _iid, _note0))
                    if op == "remediation_ack":
                        # 只在用户明确说"不处理"时把它标记已读，不直接关掉 ——
                        # 关掉会让这条失守从视野消失，那正是「只能看」的另一种形式。
                        try:
                            S.set_state(_iid, "read", root=root)
                        except M.InboxError:
                            pass
                elif op == "read_all":
                    # ★ 0.35.3：创始人拍板取消「标为已读」——页面已无此按钮，
                    #   服务端也不再受理（免得留一个没人用的后门动作）。
                    raise M.BadState("「全部已读」已取消（点开即自动已读）")
                elif op == "done_all":
                    # ★ 0.35.3：同一事由归并成一行 ⇒ 整组一次性「知道了」（少动作）。
                    #   单条失败（已是终态）**不拖垮整批** —— 幂等、按条计。
                    ids = [x for x in (form.get("ids") or [""])[0].split(",") if x]
                    if not ids:
                        raise M.BadState("批量处置没有指定对象")
                    lv = {it.id: it.level for it in S.load_items(root=root)}
                    for iid in ids:
                        if iid not in lv:
                            continue
                        try:
                            S.set_state(iid, "done", root=root, level=lv[iid])
                        except M.InboxError:
                            pass
                elif op == "bubble_vis":
                    # ★ 0.53.0 T3（创始人 2026-10-19 截图）：小窗在**后来**才被
                    #   拉开监理时，也要撤掉「打开 Antinel 监理」。渲染那一刻判一次
                    #   不够 —— 那一枚按钮是在承诺"点了我给你打开"，而窗已经开着。
                    #   只读：不看、不关、不动任何窗口；判不出来回 null，页面照旧
                    #   留着按钮（宁可多一个入口，也不让用户点了没反应）。
                    try:
                        import host_shield as _hsvis
                        _v = _hsvis.console_is_visible()
                    except Exception:                       # noqa: BLE001
                        _v = None
                    return self._json({"ok": _v is not None, "vis": _v})
                elif op in ("bubble_ack", "bubble_open"):
                    # ★ 0.49.0：紧急提醒窗的两个按钮。
                    #   `bubble_ack` ＝用户说「知道了」—— 只记确认时间
                    #     （同类 ACK_QUIET 秒内不再冒），**不**代用户把事标成
                    #     已处理（那会篡夺用户的决定，也把台账改假）。
                    #   `bubble_open` ＝把完整Antinel 监理开出来（复用 C4 那条
                    #     「谁开窗谁等它就位」的路，不另起一套）。
                    import inbox_bubble as BB
                    if op == "bubble_ack":
                        _kind = (form.get("kind") or [""])[0] or "R0"
                        _ok, _why = BB.ack(kind=_kind, root=root)
                        print("[bubble] ack(%s) -> %s %s" % (_kind, _ok, _why))
                        return self._json({"ok": _ok, "why": _why})
                    # ★★★ 0.50.3：三条出路全在 `bubble_open_route()` 里（**唯一决策点**，
                    #   可注入 ⇒ 判据能打在行为上）。这里只做路由与回 JSON。
                    _rep = bubble_open_route(root=root, token=token)
                    return self._json(_rep)
                elif op == "collapse":
                    # ★ 0.50.0：收缩成漂浮哨标（最小态）。全链只有一处实现
                    #   （`inbox_logo.collapse_console`）——本段只做路由与如实打印。
                    #   ★ 顺序安全：哨标没起来 ⇒ **不关面板窗**（用户不至于
                    #     点一下收缩，Antinel 监理没了、哨标也没起）。
                    #   ★ 关的是**本面板窗**（按 token 派生 run_id 严格匹配），
                    #     不是枚举批量关。
                    import inbox_logo as IL
                    import inbox_window as _W2
                    _rid = _W2.build_run_id(token)
                    _rep = IL.collapse_console(root=root, run_id=_rid,
                                               verbose=False)
                    print("[console] collapse run=%s -> %s" % (_rid, _rep))
                    return self._json(_rep)
                elif op == "bubblefit":
                    # ★★★ 0.50.1（创始人截图「泡泡下沿没露出来」）：紧急提醒窗
                    #   按**内容实需**长高。为什么单开一条路而不是调 BUBBLE_H：
                    #   常量是"出生差不多对"，而**内容长度是变的**（事由长短、
                    #   确认后文案变化）⇒ 只有"页面量、服务端动窗、回读校验"
                    #   这条闭环能保证"看得见"。与 `winfit` 同一套机制。
                    #   不是表单动作 ⇒ 回 JSON 不回 303。
                    _dh = (form.get("dh") or ["0"])[0]
                    _rep = _bubble_fit(_dh, token)
                    print("[bubble] fit dh=%s -> %s"
                          % (_dh, {k: _rep.get(k) for k in ("ok", "grew", "left")}))
                    return self._json(_rep)
                elif op in ("winfit", "winrestore"):
                    # ★ 0.49.0：术语浮层突破窗口边界（截图 3/4/5）。
                    #   JS 量出溢出量送来；这里动**窗口**（平移优先、撑开兜底），
                    #   回读校验后如实报告。不是表单动作 ⇒ 回 JSON 不回 303。
                    if op == "winfit":
                        _dr = (form.get("dr") or ["0"])[0]
                        _db = (form.get("db") or ["0"])[0]
                        try:
                            _dr, _db = int(float(_dr)), int(float(_db))
                        except (ValueError, OverflowError):
                            return self._json({"ok": False, "why": "溢出量不是有限数字"})
                        _rep = _winfit_apply(_dr, _db, token)
                    else:
                        _rep = _winfit_restore(token)
                    print("[console] %s dr/db -> %s"
                          % (op, {k: _rep.get(k) for k in ("ok", "moved", "grew",
                                                          "left", "windows")}))
                    return self._json(_rep)
                elif op == "exam":
                    # ★ 0.53.0（T0）：体检入口。GET 从不触发采集（host-scan
                    #   4～9 分钟）—— 只有点了「开始体检」才起后台线程；线程里
                    #   跑 ui_server 的同一对采集器（同一子进程命令＝同一数据
                    #   路径，禁第二份）。正在跑 ⇒ 幂等忽略（不叠第二条线程）。
                    if _exam_start():
                        print("[console] exam -> started")
                    else:
                        print("[console] exam -> already running")
                else:
                    iid = (form.get("id") or [""])[0]
                    ids = [x for x in (form.get("ids") or [""])[0].split(",") if x]
                    note = (form.get("note") or [""])[0]
                    if op not in M.STATES:
                        raise M.BadState("未知操作 %r" % (op,))
                    if ids:
                        # 「点开即已读」对归并行同样生效（整组记已读）。
                        lv = {it.id: it.level for it in S.load_items(root=root)}
                        for _i in ids:
                            if _i not in lv:
                                continue
                            try:
                                S.set_state(_i, op, note=note, root=root, level=lv[_i])
                            except M.InboxError:
                                pass
                    else:
                        S.set_state(iid, op, note=note, root=root)
                if op in ("fix", "guard_fix"):
                    _page = render_page(view="inbox", filt=M.BUCKET_ACTION,
                                        root=root, token=token,
                                        items=S.load_items(root=root),
                                        notice=_notice)
                    return self._send(200, "text/html; charset=utf-8",
                                      _page.encode("utf-8"))
            except M.InboxError as e:
                return self._send(409, "text/plain; charset=utf-8",
                                  ("操作被拒：%s" % e).encode("utf-8"))
            if op == "read":
                # 点开即已读由页面 fetch 调用；回 JSON 让页面只在**写入成功**后
                # 撤掉未读点。303 后再 GET 会因 cookie 禁用造成「实际已写、UI 误报」。
                return self._json({"ok": True})
            # ★ 0.53.0（T0）：体检动作落回体检页（其余动作照旧回收件箱）。
            _back = "/?v=health_exam" if op == "exam" else "/?v=inbox"
            return self._send(303, "text/plain; charset=utf-8", b"",
                              extra={"Location": _back})

        def _exam_export(self, query):
            """GET `/exam-export?e=<档案名>&san=1|0[&lv=1..3]` —— 导出一份体检结果。

            ★ 只读、**不起采集**：渲染走 `ui_server._exam_export_html`
              （与版面同一批取数函数、自己的框皮 —— 附件化三边界之一：
              **版面零耦合**）。
            ★ 默认脱敏（`san` 缺省即 1，`lv` 缺省即 1＝用户名）——
              创始人 2026-10-21 拍板「默认脱敏、一键完整版」。
            ★ `e` 只认**档案自己的文件名**（与 `_exam_pick`／`_exam_doc_by_base`
              同一条纪律：URL 来的任何拼路径都是路径穿越）⇒ 对不上就 404，
              不猜、不退回最新一份（那会把旧档导成新的，正好是反方向）。
            """
            import ui_server as _U
            import antinel as _A
            q = parse_qs(query)
            base = (q.get("e") or [""])[0]
            san = (q.get("san") or ["1"])[0] not in ("0", "false", "no")
            try:
                lv = int((q.get("lv") or ["1"])[0])
            except Exception:                                 # noqa: BLE001
                lv = 1
            lv = 0 if not san else max(1, min(3, lv))
            doc, path = _exam_doc_by_base(base) if base else (None, "")
            if doc is None:
                with _EXAM_LOCK:
                    res = _EXAM.get("result")
                    saved = _EXAM.get("saved") or ""
                if res is not None:
                    doc, path = {"report": res}, saved
            rep = (doc or {}).get("report") or None
            if not rep:
                return self._send(404, "text/plain; charset=utf-8",
                                  "没有可导出的体检结果 —— 先跑一次体检".encode("utf-8"))
            scan = rep.get("scan") or {}
            ws = [str(r.get("ws") or "")
                  for r in _U._proj_rows(scan.get("details"))]
            meta = {"version": getattr(_A, "VERSION", ""),
                    "scan_at": scan.get("generated_at") or "",
                    "made_at": datetime.now().astimezone().isoformat(
                        timespec="seconds"),
                    "archive": os.path.basename(path) if path else "",
                    "level": lv}
            html_txt = _U._exam_export_html(rep, _A.VERDICTS,
                                            _A._ev_human, meta)
            html_txt, masked = _U._exam_sanitize(html_txt, lv, extra=ws)
            fn = _U._exam_export_filename(meta)
            # ★★ 2026-10-21（创始人：「下载能做成 PDF 而不是 HTML 吗」）：
            #   `fmt=pdf` ⇒ 用**同一份**导出 HTML 交给本机 Edge 无头打印
            #   （闸五 同源：格式只换壳，数还是那一份，不写第二个模板）。
            #   转不出来 ⇒ 503 ＋ 人话页 ＋ HTML 入口；**绝不拿 HTML 冒充 PDF**。
            if (q.get("fmt") or ["html"])[0].lower() == "pdf":
                pdf, why = _exam_pdf_bytes(html_txt, root=root)
                if pdf is None:
                    print("[console] exam-export pdf failed: %s" % why)
                    return self._send(503, "text/html; charset=utf-8",
                                      _exam_pdf_fail_html(base, why).encode("utf-8"))
                fn = os.path.splitext(fn)[0] + ".pdf"
                print("[console] exam-export -> %s (lv=%d, masked=%s, pdf %dB)"
                      % (fn, lv, masked, len(pdf)))
                return self._send(200, "application/pdf", pdf,
                                  extra={"Content-Disposition":
                                         "attachment; filename=\"%s\"" % fn})
            print("[console] exam-export -> %s (lv=%d, masked=%s)"
                  % (fn, lv, masked))
            return self._send(200, "text/html; charset=utf-8",
                              html_txt.encode("utf-8"),
                              extra={"Content-Disposition":
                                     "attachment; filename=\"%s\"" % fn})

        def _json(self, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            return self._send(200, "application/json; charset=utf-8", body)

        def _asset(self, name):
            # ★ 2026-10-20：先剥查询串。favicon 的 href 带内容指纹
            #   （`?v=<sha8>`，见 `_favicon_href`），而白名单按**文件名**查表；
            #   不剥的话 basename 会带着 `?v=…`，白名单必然查不中 ⇒ 404。
            base = os.path.basename(name).split("?", 1)[0]
            # ★ favicon **实时问品牌真源**（0.53.1）：不许再从姿态灯表里取。
            rel = _brand_favicon_rel() if base == "favicon.ico" \
                else ASSET_WHITELIST.get(base)
            if not rel:
                return self._send(404, "text/plain; charset=utf-8", b"no asset")
            p = os.path.join(ASSETS_DIR, rel)
            try:
                with open(p, "rb") as f:
                    body = f.read()
            except OSError:
                return self._send(404, "text/plain; charset=utf-8", b"missing")
            ctype = _MIME.get(os.path.splitext(p)[1].lower(), "application/octet-stream")
            return self._send(200, ctype, body)
    return H


def _port_busy(port, host="127.0.0.1", timeout=0.35):
    """端口上是不是**已经有人在听**。★ 只探本机回环，不联网。

    ★★ 为什么需要它（0.35.2，Windows 特有，实测）：
      `ThreadingHTTPServer` 默认 `allow_reuse_address = 1`，而 **Windows 的
      `SO_REUSEADDR` 语义等于「允许两个进程绑同一个端口」** ⇒ 端口明明被占，
      `bind()` **照样成功、不抛 `OSError`**。
      后果：两个Antinel 监理抢同一端口、**口令各不相同** ⇒ 开出来的窗口一半请求 403。
      ⇒ 先主动探一下，占了就直接换临时端口，别指望 `OSError`。
    """
    if not port:
        return False
    import socket as _sk
    s = _sk.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _port_owner(port):
    """端口上**正在听的那个进程号**。查不到 ⇒ `None`（**不编**）。

    ★★ 为什么需要它（0.48.5 B2，遗留问题清单）：
      `_bind_first_free` 在首选端口被占时静默换临时端口 —— 用户手输
      `127.0.0.1:8790` 打不开，也无从得知**是谁占了**。"被占"必须出声，
      出声就得点得出占用方；这个函数是那件事的**唯一实现**（不在别处再查一遍）。
    ★ 只查本机、**不联网**：Windows 走 `netstat -ano`，POSIX 走 `lsof`。
      ★ 不按地址过滤：`0.0.0.0:8790` 与 `127.0.0.1:8790` 都算（`_port_busy`
        本来就是 connect 到回环，能连上就是有人听）。
    """
    if not port:
        return None
    try:
        if os.name == "nt":
            # ★ 必须按**字节**收、再自己解码：中文 Windows 的 `netstat` 输出是
            #   GBK（实测 `text=True` 按 UTF-8 解 ⇒ `UnicodeDecodeError` 抛在
            #   subprocess 的读取线程里 ⇒ 整个查询悄悄失败、`owner` 恒 None）。
            #   我们只取 ASCII 的数字列，`errors="replace"` 足够且不会崩。
            raw = subprocess.run(["netstat", "-ano", "-p", "tcp"],
                                 capture_output=True, timeout=5,
                                 creationflags=_CREATE_NO_WINDOW).stdout
            out = raw.decode("gbk", "replace")
            # 形如： TCP    127.0.0.1:8790    0.0.0.0:0    LISTENING    12345
            #   ★ 状态列在中文 Windows 上仍是英文（LISTENING），据此定位。
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 5 or "LISTENING" not in line.upper():
                    continue
                if parts[1].endswith(":%d" % int(port)):
                    return int(parts[-1])
        else:
            for cmd in (["lsof", "-nP", "-iTCP:%d" % int(port), "-sTCP:LISTEN", "-t"],
                        ["ss", "-ltnpH", "sport = :%d" % int(port)]):
                try:
                    out = subprocess.run(cmd, capture_output=True,
                                         timeout=5,
                                         creationflags=_CREATE_NO_WINDOW
                                         ).stdout.decode("utf-8", "replace")
                except OSError:
                    continue
                m = re.search(r"pid=(\d+)", out) or re.match(r"\s*(\d+)", out)
                if m:
                    return int(m.group(1))
    except Exception:                                   # noqa: BLE001
        return None
    return None


def _bind_first_free(port, root, token=None):
    """按「首选端口 → 临时端口」的顺序绑一个能用的。

    返回 `(httpd, token, real_port, drift)`。

    ★ 0.48.5（B1）：`token` 可传入 —— 重启时**复用记录里的口令**，
      URL 才可能"不变"（口令每次重生成，URL 必变）。
    ★★ 0.48.5（B2）：多返回一个 `drift` —— **"换了端口"这件事本身**。
      `None` ＝ 没换；换了则是 `{"want": 首选端口, "got": 实际端口,
      "owner": 占用方 pid|None}`。**不许静默**：用户手输首选端口打不开时，
      总得有个地方说得出"它跑到哪去了、谁占了原来的"。
      ★ 它只**报事实**，不出声也不落盘 —— 出声由 `_serve_setup()` 做，
        落盘由 `write_console_record(want_port=…)` 做（各自唯一入口）。
    """
    drift = None
    want = int(port) if port else 0
    busy = bool(want) and _port_busy(port)
    if busy:
        drift = {"want": want, "got": None, "owner": _port_owner(port)}
    try:
        httpd, token = make_server(port=(0 if busy else port),
                                   root=root, token=token)
    except OSError:
        # ★ 预探测漏掉、bind 才抛（0.35.2 记过 Windows 的 SO_REUSEADDR 陷阱）：
        #   退临时端口同样算漂移，一样要报出来。
        httpd, token = make_server(port=0, root=root, token=token)
        if drift is None and want:
            drift = {"want": want, "got": None, "owner": _port_owner(port)}
    real_port = httpd.server_address[1]
    if drift is not None:
        drift["got"] = int(real_port)
    return httpd, token, real_port, drift


def console_drift_note(drift):
    """端口漂移的**人话**（唯一实现：`_serve_setup()` 与判据都看它）。

    例：`默认端口 8790 被 PID 12345 占用，已改用 51234 —— 实际地址见下`
    """
    if not drift:
        return ""
    want, got, owner = drift.get("want"), drift.get("got"), drift.get("owner")
    who = ("被 PID %d 占用" % owner) if owner else "已被别的程序占用（占用方进程号没查到）"
    return "默认端口 %s %s，已改用 %s —— 实际地址见下" % (want, who, got)


def make_server(port=DEFAULT_PORT, root=None, token=None, bind="127.0.0.1"):
    """建服务器（不启动）。返回 `(httpd, token)`。★ `port=0` ⇒ 随机空闲端口。"""
    _check_bind(bind)
    token = token or secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer((bind, port), _make_handler(token, root))
    httpd.daemon_threads = True
    return httpd, token


#: 独立窗口的**兜底**尺寸（创始人 2026-10-06：「窗口太长了，默认不要这么长」）。
#: ★ 0.36.0 起这**不再是实际尺寸** —— 实际尺寸按工作区实算（见 `inbox_window`）。
#:   这个常量只在"探不到屏幕尺寸"时兜底，且不再是 `1024,720`：
#:   那个尺寸实测开出来是 1050×1932，占满整屏高度（见下）。
#: ★★ 0.49.0：兜底值也要**高于 CSS 窄屏断点 620px**（与 `inbox_window.MAX_W`
#:   同源）—— 探不到屏幕时给 520 宽，等于让面板在最不该凑合的时候凑合
#:   （创始人 2026-10-14 截图：520 宽 ⇒ 顶行折行压字，"乱样"）。
WINDOW_SIZE = "720,640"


def _app_window_cmd(url, geometry=None):
    """返回能开「**独立窗口**」的命令（app 模式：无地址栏/无标签页/无书签栏）；没有则 None。

    ★ 为什么必须 app 模式（0.35.2）：创始人 2026-10-06 明确要求
      「我希望Antinel 监理界面看上去是**一个独立的界面**」。
      浏览器普通标签页带着地址栏与标签栏，看着就是"一个网页"；
      Edge/Chrome 的 `--app=URL` 开出来的窗口只有页面本身，像独立应用。
    ★ 0.35.3：加 `--window-size` —— 默认窗口太高，一屏看不完反而显得"内容很长"。
      ★ 参数顺序：`--app=URL` **放最后**。不是功能需要，而是既有判据
        （`c_console_app_window` / `c_console_real_branch`）按「最后一个参数是
        `--app=`」来判"是不是 app 模式" —— 把 `--window-size` 追加在后面会让
        那两条判据**误红**。顺序在这里没有语义差别，选不破坏既有判据的那种。
    ★ 0.36.0（创始人「别占屏幕太大面积，哨兵不能在舞台中央」）：加
      `--window-position`，并把尺寸改为**按工作区实算**。
      实测此前本机开出来是 **1050×1932、位置 (10,10)** ⇒ 高度占工作区 99%、
      占屏幕面积 16%，且紧贴左上角，把右边的主工作区（WorkBuddy 2337×1887、
      Edge 1681×1709）挤掉了 —— 哨兵站了舞台中央。
      改法：**唯一几何实现 = `inbox_window.console_geometry()`**，
      本函数不自己算一遍。实测该模块在 3000×1952 工作区上给出
      `(2440,1264,520,640)`，且 `--window-position` 实测**精确生效**
      （请求值与实测矩形 dx/dy/dw/dh 全为 +0）。
    ★ 屏幕小到开不下 ⇒ `geometry['ok']` 为假 ⇒ **只给size、不给position**
      （让浏览器自己决定），并把原因留在 `console_geometry()['reason']`
      里由调用方如实转述。**不硬挤**一个盖住任务栏的窗口。
    ★ 不引依赖：只探测本机**已有**的 msedge / chrome；
      都没有 ⇒ 返回 None，由调用方**诚实降级**成默认浏览器（不假装成功）。

    ★★★★ 0.36.4 **根治：给值守台自己的 `--user-data-dir`**（创始人
      「落位失败就关窗不是彻底的解决办法」——这是 0.36.0–0.36.3 补丁链的**断根**）：
      本函数此前只是"把几何参数**报上去**"，而实测（E3）证明：
      窗口若由**用户的 Edge 复用旧进程**开出来，这些参数**被完全忽略**
      ⇒ 参数是"请求"，不是"事实" ⇒ 0.36.0 才被迫加落位补救，
      而补救必须有兜底 ⇒ 0.36.3 才被迫"落位失败就关窗"。
      ⇒ 现在**换掉那个前置条件**：加 `--user-data-dir` 让Antinel 监理成为
        **独立浏览器进程**，参数即刻生效（实测本机，Δ 全 0）：
          · E1 独立 profile 首次冷启动 ⇒ 520×640 @(2440,1264)
          · E2 同一 profile **第二次**（进程已在跑）⇒ 仍然精确
            ⇒ **不是"必须冷启动"，是这个 profile 的进程是自己的就生效**
          · E4 全新 profile 不加 `--no-first-run` ⇒ 仍精确，无额外可见窗口
          · E5 稳定 profile 连开 3 次 ⇒ 3/3 精确，**不退化**
          · E7 关窗后该 profile 进程**完全回落**（Δ=0），不留后台浏览器
      ⇒ 结果：窗口**出生即正确**，`place_all` 退化为"兜底复核"
        （已对齐就一条 `SetWindowPos` 都不发，见 `inbox_window.place_all`）。
      ★ 取不到 profile 目录时（`console_profile_dir()` 返回 None）
        ⇒ **如实降级**：不加这个参数，仍走"参数 + 落位兜底"老路。
        **绝不假装拿到了独立 profile**（那会让日志说谎）。
      ★ 参数顺序不变：`--app=URL` 仍放**最后**（见上方 0.35.2 的理由）。
    """
    import shutil as _sh
    cands = []
    if os.name == "nt":
        cands = [("msedge.exe", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
                 ("msedge.exe", r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
                 ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                 ("chrome.exe", r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")]
    for name, hard in cands:
        exe = _sh.which(name) or (hard if os.path.isfile(hard) else None)
        if not exe:
            continue
        cmd = [exe]
        # ── 0.36.4 根治第一步：Antinel 监理**自己的**浏览器 profile ──
        # 有了它，app 窗口由**独立进程**开出来 ⇒ 命令行几何即刻生效（实测 Δ=0）。
        # 取不到（如非 Windows / 无 LOCALAPPDATA）⇒ 不加，如实走落位兜底老路。
        try:
            import inbox_window as WIN
            _prof = WIN.console_profile_dir()
        except Exception:                                    # noqa: BLE001
            _prof = None
        if _prof:
            cmd.append("--user-data-dir=" + _prof)
            cmd.extend(WIN.CONSOLE_PROFILE_FLAGS)
        if geometry is None:
            try:
                import inbox_window as WIN
                geometry = WIN.console_geometry()
            except Exception:                              # noqa: BLE001
                geometry = None
        rect = (geometry or {}).get("rect")
        if rect:
            import inbox_window as WIN
            cmd.append("--window-size=" + WIN.window_size_str(rect))
            cmd.append("--window-position=" + WIN.window_position_str(rect))
        else:
            # ★ 屏幕不合适 ⇒ **不给 position**：让浏览器自己挑一个
            #   不至于盖住任务栏的位置，好过硬指定一个越界的。
            cmd.append("--window-size=" + WINDOW_SIZE)
        cmd.append("--app=" + url)
        return cmd
    return None


def _place_if_needed(placer=None, tries=24, interval=0.35, run_id=None,
                     title=None, verbose=True):
    """开窗后**后台**落位，返回是否已安排上落位（不等待）。

    ★ 为什么不在这里直接落位：`open_console` 是 `threading.Timer` 里调的，
      窗口刚起时还没成型，直接查必然查不到 ⇒ 落位会假失败。
      所以改成"起一个守护线程，轮询等窗口出现"，
      **不阻塞** `open_console` 返回，也不阻塞 `serve_forever`。

    ★ 落位失败**不抛、不重试到死**：最多 `tries` 次，
      仍找不到就打到 stderr 如实说，绝不假装成功。
    ★ `placer` 注入时（判据）**同步执行一次**并返回，
      让判据能确定性地验"落位被调用了"而不必 sleep 等窗口。

    ★★ 0.36.2 三处机制性改动（治"窗口出现在旧位置旧尺寸"这个根）：
      ① 认窗口**只认本次运行的**（`#<run_id>` 后缀）——
         旧版用通用后缀，会命中**用户自己的普通浏览器窗口**
         （实测本机 Edge 标题「收件箱 · Antinel 监理 和另外 14 个页面…」）
         并把它 `SetWindowPos` 搬走。错方向是**破坏用户环境**。
      ② 落位**全量**且**逐个回读校验**（`place_all`）——
         旧版只取第一个同名窗口；同标题有多个时（旧的+新的）
         挪走旧的、新的原地不动 ⇒ 用户看到"修复没生效"，
         而日志打的是"已落到"（量的是别的窗口）。
      ③ **不把"找到窗口"当成功**：落位后必须回读实测矩形，
         全部相符才算成功（`place_one` 里已有）。

    ★★★★ 0.36.4 **本函数的角色降级**（创始人「落位失败就关窗不是彻底的
      解决办法」）—— 这是断补丁链的关键一步：
      0.36.0–0.36.3 里，落位是**唯一**能产出正确几何的手段
      （因为窗口由用户 Edge 复用旧进程开出来，命令行参数被忽略，实测 E3），
      所以它是"必须成功"的关键路径 ⇒ 关键路径必须有兜底 ⇒ 有了 0.36.3 的关窗。
      ⇒ 现在 `_app_window_cmd` 给了Antinel 监理**自己的 `--user-data-dir`**
        （实测 E1/E2/E4/E5：窗口**出生即正确**，Δ 全 0，且连开 3 次不退化），
        **落位从"关键路径"降级为"兜底复核"**：
          · `place_all` 先回读，**已对齐就一条 SetWindowPos 都不发**
            （`skip_if_placed=True`，默认开）⇒ 正常路径零移动、零误伤机会。
          · 只有"出生没对齐"才真的搬它，且搬完仍逐个回读校验。
      ⇒ **失败路径同时改掉**：重试耗尽**不再关窗**。
        理由（也是 0.36.3 那版的错处）：落位失败只说明"这次没搬成"，
        而那个窗口**就是Antinel 监理面板**、**完全正常**，主人正要看的正是它。
        为"位置不对"杀掉"内容"＝手段颠倒目的；而且杀掉之后
        "为什么没搬成"这条线索**连同窗口一起消失** ⇒ 根因被永久掩盖。
        ⇒ 现在如实上报，**面板留在它该在的地方、由用户决定关不关**。
    """
    try:
        import inbox_window as WIN
    except Exception as e:                                   # noqa: BLE001
        print("[place] 取不到窗口几何模块，未落位：%r" % (e,), file=sys.stderr)
        return False
    geo = WIN.console_geometry()
    rect = geo.get("rect")
    suffix = WIN.console_title_suffix(run_id)

    def run():
        last = "未知原因"
        for _ in range(tries):
            if rect is None:
                if verbose:
                    print("[place] %s" % geo.get("reason", "屏幕放不下"),
                          file=sys.stderr)
                return
            try:
                # ★★ 严格模式：**只动本次运行**的窗口（带 `#run_id`）。
                #   宽泛模式（认任何Antinel 监理窗口）在这里是**危险的** ——
                #   它可能命中用户自己的浏览器窗口并把它搬走。
                hwnds = WIN.find_console_windows(suffix=suffix, run_id=run_id)
            except Exception as e:                           # noqa: BLE001
                last = "枚举窗口出错（%s）" % (type(e).__name__,)
                time.sleep(interval)
                continue
            if not hwnds:
                last = "还没看到带本次标识（%s）的 Antinel 监理窗口" % (suffix,)
                time.sleep(interval)
                continue
            ok, why = WIN.place_all(hwnds, rect)
            if ok:
                if verbose:
                    print("[place] %s" % why, file=sys.stderr)
                return
            last = why
            time.sleep(interval)
        # ★★★★ 0.36.4：**到此为止，如实上报，不关窗。**
        #   （0.36.3 在这里调 `WIN.close_window(_left)` 把面板杀掉 ——
        #    那是补丁链的最后一环，也是创始人这次要求拆掉的那一环。
        #    依据与实测见 `inbox_window.close_window` 的 0.36.4 改写说明。）
        #   ★ 独立 profile 已让"落位失败"变成**罕见**路径（实测正常路径
        #     `place_all` 直接报"出生即正确，一个都没搬"）；
        #     真走到这里，说明有别的问题（如窗口被用户拖走后又还原、
        #     或权限异常）—— 那正是**需要留现场**的时候。
        if verbose:
            print("[place] 未能对齐到 %dx%d @(%d,%d)：%s"
                  % (rect[2], rect[3], rect[0], rect[1], last),
                  file=sys.stderr)
            print("[place] Antinel 监理面板仍在屏幕上，没有被关掉。"
                  "它就是面板，由你决定关不关。",
                  file=sys.stderr)
        return False

    if placer is not None:
        return run()                        # 判据路径：同步跑完，行为可确定
    th = threading.Thread(target=run, name="inbox-place", daemon=True)
    th.start()
    return True


#: 一次性调用方等窗口就位的默认预算（秒）。★ 为什么需要它见 `open_console_settled`。
DEFAULT_SETTLE_SEC = 12.0


def open_console_settled(url, wait_sec=DEFAULT_SETTLE_SEC, token=None, verbose=True,
                         root=None):
    """开独立窗口，**并等它就位**（一次性调用方专用；服务路径仍走 `_place_if_needed`）。

    ★★ 为什么必须有这个函数（C4，2026-10-13 **实测**抓到的真缺陷，不是推演）：
      `_place_if_needed()` 把落位放在 `daemon=True` 线程里 —— 对**长命**进程
      （服务自己开窗：`threading.Timer(0.6, open_console)`）没问题；
      但对**一次性**调用方是致命的：`inbox_cli.py window`（＝`antinel.cmd`
      一键入口，创始人日常就该用这个）进程 **2 秒就返回** ⇒ daemon 线程
      随进程一起死，而 Edge 建窗实测要 1–2.5s ⇒ 线程根本轮不到那一刻
      ⇒ **落位从未执行**。
      实测现象：窗口出生 676×640（比目标宽 156px），屏幕上一个字都没说。
      两臂探针（`_p_c4_probe.py`，只差进程寿命）：CLI 臂 `place_all` **0** 次／
      长命臂 **1** 次。
      ⇒ 病型＝**T-10 静默降级**：该做的事没做，且没有任何输出说明它没做。

    ★ 为什么这样修（而不是把 `_place_if_needed` 改成非 daemon）：
      职责分层 —— **谁开窗，谁负责等它就位**。
      · 服务是长命进程 ⇒ 后台落位线程是对的（不阻塞 `serve_forever`）；
      · CLI 是一次性进程 ⇒ 它**自己**同步等 + 回读校验，并把结果打到屏上。
      两边共用同一个 `inbox_window.place_all`（落位的唯一实现，不另写一套）。
      这样 `open_console()` 的既有契约**一字不改** ⇒ 既有判据
      （`c_console_app_window` / `c_console_real_branch`，都走注入路径）
      一行都不用动，不会出现"为了容纳新产品代码而放松旧判据"。

    ★ 返回 dict，**如实**，不谎报（`placed` 只能由**回读**说了算）：
      `{"opened": "app"/"browser"/"none", "placed": bool, "want": rect|None,
        "got": [实测矩形...], "why": 人话}`
    ★ 纪律：**落位失败不关窗**（0.36.4 立的规矩：面板就是主人要看的內容，
      为"位置不对"杀"內容"＝手段颠倒目的，而且会把"为什么没搬成"的线索
      连同窗口一起抹掉）。只如实上报，关不关由人决定。
    """
    import inbox_window as WIN
    out = {"opened": "none", "placed": False, "want": None, "got": [], "why": ""}
    ret = open_console(url, token=token, verbose=verbose)
    out["opened"] = ret
    try:
        geo = WIN.console_geometry()
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "取不到目标几何：%s: %s" % (type(e).__name__, e)
        return out
    rect = geo.get("rect")
    out["want"] = list(rect) if rect else None
    if not rect:
        out["why"] = geo.get("reason") or "屏幕放不下，未落位"
        return out
    if token is None and url:
        try:
            from urllib.parse import parse_qs, urlparse
            token = (parse_qs(urlparse(url).query).get("t") or [None])[0]
        except Exception:                                   # noqa: BLE001
            token = None
    try:
        run_id = WIN.build_run_id(token)
        suffix = WIN.console_title_suffix(run_id)
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "算不出本次窗口身份：%s: %s" % (type(e).__name__, e)
        return out

    # ── 等本次运行的窗口出现（严格模式：只认带 #run_id 的，绝不碰用户窗口）──
    deadline = time.time() + float(wait_sec)
    hwnds, last = [], "没看到带本次标识（%s）的 Antinel 监理窗口" % suffix
    while time.time() < deadline:
        try:
            hwnds = WIN.find_console_windows(run_id=run_id)
        except Exception as e:                              # noqa: BLE001
            last = "枚举窗口出错（%s）" % type(e).__name__
            time.sleep(0.2)
            continue
        if hwnds:
            break
        time.sleep(0.25)
    if not hwnds:
        out["why"] = "%s（等了 %.1fs）" % (last, float(wait_sec))
        return out

    # ── 落位（`place_all` 内部**先回读**：已对齐就一条 SetWindowPos 都不发）──
    try:
        ok, why = WIN.place_all(hwnds, rect)
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "落位抛异常：%s: %s" % (type(e).__name__, e)
        return out
    out["why"] = why
    # ★ 不信"应该对了"——**再回读一次**独立取证（本仓铁律：查出来是好的才算好）。
    try:
        out["got"] = [list(WIN.window_rect_of(h)) for h in hwnds]
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "%s；且回读失败：%s" % (why, e)
        return out
    out["placed"] = bool(ok) and all(tuple(g) == tuple(rect) for g in out["got"])
    # ★ 0.50.0：Antinel 监理展开 ⇒ 屏幕上那枚漂浮哨标该退场（用户从托盘/紧急提醒/
    #   CLI 展开时也会走到这里）。★ 0.52.0：退场＝**hide（藏起待命）**，
    #   不再 retire —— 哨标进程常驻，下一次收缩才能毫秒级唤出。
    #   藏起失败只影响"多漂着一枚"，不拖垮开窗 ⇒ 如实记
    #   进 why 尾部，不抛。
    try:
        import inbox_logo as _IL
        _r = _IL.hide(root=root, verbose=False)
        if _r.get("acted") and not _r.get("ok"):
            out["why"] = "%s｜漂浮哨标藏起没成（%s）" % (out["why"], _r.get("why", ""))
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "%s｜漂浮哨标藏起查询失败：%s: %s" % (
            out["why"], type(e).__name__, e)
    return out


def open_console_via_daemon(url, wait_sec=DEFAULT_SETTLE_SEC, token=None,
                            verbose=True, root=None):
    """经**守护进程**开独立窗口，并等它就位（调用方短命时的唯一活路）。

    ★★★★ 为什么必须有这条路（2026-10-14 创始人实测「起得来、活不久」）：
      CLI 直起（`open_console_settled`）时 msedge 挂在 **CLI 进程树**下。
      在「调用方寿命短于窗口寿命」的环境（agent 沙箱／CI runner／一次性
      脚本），调用方一退出，进程树连带清理 ⇒ **窗口秒死**，而 CLI 已如实
      报过「已就位」——用户看到的是"报了功、窗没了"。
      同机同命令**四路实证**（全部起出窗口、命令内回读全对）：
        · `Popen(CREATE_NO_WINDOW)`            ⇒ 跨边界死
        · `Popen(DETACHED｜NEW_GROUP)`        ⇒ 跨边界死
        · `cmd /c start`                       ⇒ 跨边界死
        · **daemon（长命进程）Popen**          ⇒ **跨边界存活**
      ⇒ 病根不是"起法不对"，是"**谁来起**"：必须由**活得比窗口久**的
        进程起。daemon 正是那个进程（supervise 单例，实测跨小时存活）。
    ★ 实现走**既有机制**，不新造接口：推托盘 `open` 动作（`push_action`），
      daemon tick（2s）消费 ⇒ `open_console_now` ⇒ `open_console` 开窗。
      这里只做「等窗 + 落位 + 回读」，与 `open_console_settled` **同一把尺**
      （同一个 `place_all`、同一个回读取证），不另写一套。
    ★ 身份匹配：daemon 用**同一个 token** 派生 run_id（`build_run_id`
      是确定性派生）⇒ 这里按同一 run_id 严格匹配，绝不碰用户窗口。
    ★ 失败**如实降级**：daemon 不在／没开出 ⇒ `opened="none"` 加人话，
      由调用方决定是否降级直起（`cmd_window` 会降级，**不假装成功**）。
    """
    import inbox_window as WIN
    import inbox_tray as TR
    out = {"opened": "none", "placed": False, "want": None, "got": [],
           "why": "", "via": "daemon"}
    try:
        geo = WIN.console_geometry()
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "取不到目标几何：%s: %s" % (type(e).__name__, e)
        return out
    rect = geo.get("rect")
    out["want"] = list(rect) if rect else None
    if not rect:
        out["why"] = geo.get("reason") or "屏幕放不下，未开"
        return out
    if token is None and url:
        try:
            from urllib.parse import parse_qs, urlparse
            token = (parse_qs(urlparse(url).query).get("t") or [None])[0]
        except Exception:                                   # noqa: BLE001
            token = None
    try:
        run_id = WIN.build_run_id(token)
        suffix = WIN.console_title_suffix(run_id)
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "算不出本次身份：%s: %s" % (type(e).__name__, e)
        return out
    try:
        TR.push_action("open", root=root)
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "推动作失败（daemon 可能没起）：%s: %s" % (type(e).__name__, e)
        return out
    deadline = time.time() + float(wait_sec)
    # ★ 通用后缀匹配（**不是** run_id 严格匹配）：daemon 的 `open_console_now`
    #   在自己进程内 `ensure_background` ⇒ 可能用**另一个服务实例**（端口
    #   漂移，实测 daemon 19704 自听 14305）开窗 ⇒ 窗口 run_id 与本次不同。
    #   「服务多开」是独立缺陷（已单独记账，今天不混进来修）；这里只保证
    #   **窗口跨边界存活**这件主事，匹配放宽到通用后缀。
    hwnds, last = [], "daemon 没开出 Antinel 监理窗口（通用后缀也没匹配到）"
    while time.time() < deadline:
        try:
            hwnds = WIN.find_console_windows()
        except Exception as e:                              # noqa: BLE001
            last = "枚举窗口出错（%s）" % type(e).__name__
            time.sleep(0.2)
            continue
        if hwnds:
            break
        time.sleep(0.25)
    if not hwnds:
        out["why"] = "%s（等了 %.1fs；daemon 在跑吗？）" % (last, float(wait_sec))
        return out
    out["opened"] = "app"
    try:
        ok, why = WIN.place_all(hwnds, rect)
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "落位抛异常：%s: %s" % (type(e).__name__, e)
        return out
    out["why"] = why
    try:
        out["got"] = [list(WIN.window_rect_of(h)) for h in hwnds]
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "%s；且回读失败：%s" % (why, e)
        return out
    out["placed"] = bool(ok) and all(tuple(g) == tuple(rect) for g in out["got"])
    try:
        import inbox_logo as _IL
        _r = _IL.hide(root=root, verbose=False)
        if _r.get("acted") and not _r.get("ok"):
            out["why"] = "%s｜漂浮哨标藏起没成（%s）" % (out["why"], _r.get("why", ""))
    except Exception:                                       # noqa: BLE001
        pass
    return out


def bubble_open_route(root=None, token=None, vis=None, finder=None,
                      focuser=None, opener=None, probe=None):
    """紧急提醒窗「打开 Antinel 监理」的**唯一决策点**。返回与页面 JSON 同形的 dict。

    ★★★ 为什么抽成一个函数（创始人 2026-10-14：「点击打开值守台后，之前的
      关闭了，打开了新的……点完了按钮显示'打开Antinel 监理'按钮好像不对吧，
      Antinel 监理打开着呢」）：
      旧链路只有一条动作 —— `open_console_settled()`，而它**先收旧窗、再开新窗**
      （那条路是为「没有窗、要开一个」设计的）。⇒ 面板**本来就开着**时点一下，
      用户看到的是"窗闪了一下、内容从头来"（而且新窗刚加载，状态读数是重新算的
      —— 那正是他说的"状态不对了"）。而他要的只是**切过去**。

      ⇒ 三条出路，按「用户此刻真的看得见Antinel 监理吗」分流：
        · 看得见（`vis is True`）⇒ **只切到前面**（`inbox_window.focus_windows`，
          不关、不开、不重建）⇒ `opened="existing"`；
        · 看不见（`vis is False`）⇒ 走老路 `open_console_settled()` 开一个；
        · **判不出来**（`vis is None`）⇒ 走老路开窗 —— 方向往"宁可多开一个窗"
          偏，绝不让用户点了没反应（"漏做"比"多做"坏）。

    ★ 为什么抽出来：判据要能**打在行为上**（三条分流的**调用顺序与返回值**），
      而不是去查源码里有没有某个 `if`。⇒ 五个注入点（`vis`/`probe`/`finder`/`focuser`/
      `opener`）让判据**不起真浏览器、不动真窗口**就能验全三条路
      （与 `pop(opener=…)`、`open_console(opener=…)` 同一套纪律）。
      `vis` 直接给定就跳过探测；`vis=None` 时走 `probe()`（默认＝真探测）——
      这样"判不出来"那一路也能被夹具覆盖（否则它永远测不到）。
    ★ 不二次实现：可见性走 `host_shield.console_is_visible()`（唯一实现）、
      枚举走 `inbox_window.find_console_windows()`、切换走
      `inbox_window.focus_windows()`、开窗走 `open_console_settled()`。
    """
    rec = read_console_record(root) or {}
    url = rec.get("url") or ""
    if not url:
        return {"ok": False, "opened": "none",
                "why": "没有 Antinel 监理记录（URL），开不出来"}
    if vis is None:
        try:
            if probe is not None:
                vis = probe()
            else:
                import host_shield as _hs
                vis = _hs.console_is_visible()
        except Exception:                                   # noqa: BLE001
            vis = None
    if vis is True:
        import inbox_window as _W
        find = finder or _W.find_console_windows
        try:
            hwnds = find()
        except Exception as e:                              # noqa: BLE001
            hwnds = []
            print("[bubble] 枚举 Antinel 监理窗口失败：%s" % type(e).__name__)
        ok, why = (focuser or _W.focus_windows)(hwnds)
        print("[bubble] 已在 Antinel 监理 -> focus=%s %s" % (ok, why))
        return {"ok": bool(ok), "opened": "existing", "why": why}
    rep = (opener or open_console_settled)(url, token=token, verbose=False)
    print("[bubble] open -> %s" % rep)
    return {"ok": bool(rep.get("placed")), "opened": rep.get("opened"),
            "why": rep.get("why", "")}


def open_bubble_window(url, geometry=None, wait_sec=6.0, token=None, verbose=True):
    """开一枚**紧急提醒窗**并等它就位、置顶；返回如实 dict（不谎报）。

    ★ 与 `open_console_settled` 的分工：那个等的是 **Antinel 监理** 窗口
      （`find_console_windows`＋`console_geometry`），这个等的是**紧急提醒**窗
      （`find_bubble_windows`＋`bubble_geometry`，且**置顶**）。
      共用的都是 `inbox_window` 的同一批原语（命令构造／枚举／落位／置顶）——
      窗口语义只有一份，这里只是紧急提醒自己的编排。
    ★ 为什么不合并成一个函数：两者的标题标记、几何来源、置顶诉求都不同，
      硬合并要靠一串开关分发，那是把简单事情绕复杂。
    ★ 纪律同 C4：等窗→落位→**回读取证**；失败不关窗、如实上报。
    """
    import inbox_window as WIN
    out = {"opened": "none", "placed": False, "topmost": False,
           "want": None, "got": [], "why": ""}
    try:
        geo = WIN.bubble_geometry() if geometry is None else geometry
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "取不到紧急提醒几何：%s: %s" % (type(e).__name__, e)
        return out
    rect = (geo or {}).get("rect")
    out["want"] = list(rect) if rect else None
    if not rect:
        out["why"] = geo.get("reason") or "屏幕放不下紧急提醒窗，未开"
        return out
    cmd = _app_window_cmd(url, geo)
    if not cmd:
        out["why"] = "找不到可用的 app 浏览器（Edge/Chrome）"
        return out
    try:
        subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=_DETACHED_FLAGS)
        out["opened"] = "app"
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "起浏览器失败：%s: %s" % (type(e).__name__, e)
        return out
    try:
        run_id = WIN.build_run_id(token)
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "算不出本次紧急提醒身份：%s: %s" % (type(e).__name__, e)
        return out
    deadline = time.time() + float(wait_sec)
    hwnds, last = [], "没看到带本次标识的紧急提醒窗"
    while time.time() < deadline:
        try:
            hwnds = WIN.find_bubble_windows(run_id=run_id)
        except Exception as e:                              # noqa: BLE001
            last = "枚举窗口出错（%s）" % type(e).__name__
            time.sleep(0.2)
            continue
        if hwnds:
            break
        time.sleep(0.25)
    if not hwnds:
        out["why"] = "%s（等了 %.1fs；浏览器可能正冷启动）" % (last, float(wait_sec))
        return out
    try:
        ok, why = WIN.place_all(hwnds, rect, skip_if_placed=False)
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "落位抛异常：%s: %s" % (type(e).__name__, e)
        return out
    out["why"] = why
    try:
        out["got"] = [list(WIN.window_rect_of(h)) for h in hwnds]
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "%s；且回读失败：%s" % (why, e)
        return out
    out["placed"] = bool(ok) and all(tuple(g) == tuple(rect) for g in out["got"])
    try:
        tok, _tw = WIN.set_topmost(hwnds, True)
        out["topmost"] = bool(tok)
    except Exception as e:                                  # noqa: BLE001
        out["why"] = (out["why"] + "；" if out["why"] else "") \
                     + "置顶失败：%s: %s" % (type(e).__name__, e)
    if verbose:
        print("[bubble-window] opened=%s placed=%s topmost=%s %s"
              % (out["opened"], out["placed"], out["topmost"], out["why"]))
    return out


def open_console(url, opener=None, placer=None, token=None, verbose=True):
    """把Antinel 监理打开成**一个独立窗口**（app 模式）；拿不到 app 浏览器就退回默认浏览器。

    ★ `opener` 是可测性注入点：判据要能在**不起任何进程**的前提下，
      验「拿到的是 app 模式命令」与「拿不到时退回浏览器」两条路。
    ★ `placer` 同理：落位这一步要能在**不碰真实桌面**的前提下验。
    ★ `token` 是**本次服务的口令**：派生出窗口身份串（`#<run_id>`），
      让落位只认本次的窗口。不给时按 `url` 里的 `t=` 兜底。
    返回 "app" / "browser" / "none"（**如实返回走了哪条**，不谎报）。

    ★★ 0.35.2 修（真缺陷，创始人 2026-10-06 实测「还开在浏览器标签页」）：
      本函数真身分支要 `subprocess.Popen`，而本模块**从未 `import subprocess`**
      ⇒ 抛 `NameError`，又被下面的 `except Exception: pass` **静默吞掉**
      ⇒ app 独立窗口**从来没成功过**，每次都悄悄降级成普通标签页。
      ★ 为什么 68 条守卫没抓到：`c_console_app_window` 走的是 `opener=` 注入分支，
        **替身把真身那行盖住了** —— 判据测的是替身，不是真身。
        配套新增判据 `c_console_real_branch`（不注入 opener，直接验真身）。
      ⇒ 现在失败**不再静默**：把原因打到 stderr（不落盘），供现场诊断。

    ★★ 0.36.0 修（真缺陷，本轮**实测**抓到，不是推演）：
      只下发 `--window-size` / `--window-position` **不够** —— 本机开出来
      仍是 **1050×1932 @(10,10)**（= 0.35.3 的旧形状，新参数被完全忽略）。
      根因：Edge/Chrome **已有运行实例**时 app 窗口由旧进程接管，
      命令行上的 size/position 不生效（对照实测：换独立 `--user-data-dir`
      冷启动，参数立刻精确生效 ⇒ 证实是"复用旧进程"）。
      ⇒ 加落位：**开窗之后**用 `SetWindowPos` 强制落到目标矩形。
        命令行参数是"请求"，`SetWindowPos` 才是"事实"。

    ★★★ 0.36.2 修（创始人 2026-10-07 再测「窗口出现在旧位置而且变成了
      旧尺寸」——**根治**，不是再打一个补丁）。逐条根因与修法：

      根因 ①（**直接原因**）：0.36.1 的「开窗前收旧窗」**一次都没成功过**。
        `inbox_window.close_console_windows` 函数体第一行是 `if closer is None:`，
        而 `closer` 既不是参数也没定义 ⇒ 每次调用必然 `UnboundLocalError`，
        被这里的 `except Exception` 兜住、只往 stderr 打一行 ⇒ **静默失效**。
        实测复现：`close_console_windows()` → `UnboundLocalError`。
        后果：旧窗口留在屏幕上，而落位只认"第一个同名窗口" ⇒
        挪走旧的、新的留在旧位置旧尺寸 ⇒ **正是用户看到的现象**。

      根因 ②：落位**只取第一个**同名窗口。同标题同时存在多个时
        （旧残留 + 新开的），"第一个"由枚举顺序决定，不可控。

      根因 ③：落位认窗口的判据**可能命中用户自己的浏览器窗口**。
        实测本机 Edge 普通窗口标题为
        「收件箱 · Antinel 监理 和另外 14 个页面 - 个人 - Microsoft Edge」，
        它**含有**面板标题；一旦被 `SetWindowPos` 命中，
        错的方向是**把用户的浏览器搬到右下角 520×640**。

      ⇒ 三条机制性修法（合起来才叫"杜绝复发"）：
        A. **窗口带身份**：服务端渲染时把 `#<run_id>` 注入标题
           （`_head`）⇒ 落位只认**本次运行**的窗口，
           根因 ③ 在**结构上**不再可能（用户的窗口没有这个串）。
        B. **全量落位 + 逐个回读校验**（`place_all`）⇒ 根因 ② 消除；
           局部成功不算成功。
        C. **开窗前等旧窗真的消失**（`wait_console_windows_gone`）⇒
           `WM_CLOSE` 是异步的，不等就会在"两个同名窗口"的时刻继续往下走；
           等不到就**如实说**，不假装清干净了。

    ★★★★ 0.36.4 **根因被真正拔掉**（创始人 2026-10-07：
      「落位失败就关窗，不是彻底的解决办法，好好想想，拿出真正的根治方法」）：
      上面三条**全部是补丁**，因为它们都建立在一个仍然失效的前提上：
      **窗口由用户的 Edge 复用旧进程开出来 ⇒ 浏览器不认命令行几何参数**
      （实测 E3：给足 `--window-size=520,640 --window-position=2440,1264`，
      窗口仍开成 1050×1932 @(10,10)，dx/dy/dw/dh 全错）。
      ⇒ 参数既然是"请求"，落位就成了唯一救命稻草；
        而救命稻草必须有兜底 ⇒ 才有 0.36.3 的"落位失败就关窗"。
        **关窗不是设计选择，是补丁链的必然产物。**
      ⇒ **根治 = 换掉那个前提**（不是再打一层补丁）：
        `_app_window_cmd` 现在给Antinel 监理**自己的 `--user-data-dir`**
        （`inbox_window.console_profile_dir()`），它因此成为
        **独立浏览器进程** ⇒ 命令行几何**即刻生效**，窗口**出生即正确**。
        本机实测（Δ = 实测矩形 − 请求矩形，全 0 即完全精确）：
          · E1 独立 profile 首次冷启动            ⇒ Δ 全 0
          · E2 同一 profile **第二次**（进程已在跑）⇒ Δ 全 0 ★ 最关键
          · E4 全新 profile 不加 `--no-first-run`  ⇒ Δ 全 0，无额外可见窗口
          · E5 稳定 profile 连开 3 次              ⇒ **3/3 Δ 全 0**，不退化
          · E7 关窗后该 profile 进程完全回落       ⇒ Δ=+0，不留后台浏览器
        ★ E2 这一条决定了它不是"靠冷启动的一次巧合"：
          **只要这个 profile 的进程是自己的，参数就一直生效。**
      ⇒ 于是职责彻底分层（三者不再互相顶替）：
        · **独立 profile** = 主路径（几何从出生就正确，零移动）
        · **`place_all`**   = 兜底复核（先回读；已对齐就一条消息都不发）
        · **`close_window`**= 只用于**收旧窗**（残留窗口），
          **不再是落位失败的兜底**（0.36.3 那条路径已删）
      ⇒ 用户可预期的结果：**面板永远不会被程序杀掉**，
        正常路径下**一次 SetWindowPos 都不会发**。
    """
    try:
        import inbox_window as WIN
    except Exception:                                       # noqa: BLE001
        WIN = None
    # 本次运行的窗口身份（页面标题里带的就是它）
    if token is None and url:
        try:
            from urllib.parse import parse_qs, urlparse
            token = (parse_qs(urlparse(url).query).get("t") or [None])[0]
        except Exception:                                   # noqa: BLE001
            token = None
    run_id = WIN.build_run_id(token) if WIN is not None else None
    suffix = WIN.console_title_suffix(run_id) if WIN is not None else None

    cmd = _app_window_cmd(url)
    if cmd:
        try:
            # ── 步骤 1：收掉已开着的Antinel 监理窗口（旧的 / 上次运行的）──
            #   只关标题后缀匹配的，绝不误关用户窗口（见 close_console_windows）。
            #   这里用**通用后缀**（不带本次 run_id）⇒ 连"上次运行"的残留
            #   也一并收掉；那正是要清的对象。
            # ★★ 顺序很重要：**先收旧窗并等它们消失，再开新的**。
            #   `WM_CLOSE` 只是投信，浏览器何时销毁窗口不受我们控制；
            #   不等 ⇒ 那一刻屏幕上有两个「· Antinel 监理」窗口，
            #   后续任何"取第一个"都可能抓到正在退场的旧窗口
            #   ⇒ 落位落到旧窗上（用户看到"修复没生效"）。
            if WIN is not None:
                try:
                    _n = WIN.close_console_windows()
                    if _n and verbose:
                        print("[open_console] 已收掉 %d 个上次的 Antinel 监理窗口。"
                              "（服务重启后没人喂它们的残留窗口）" % _n,
                              file=sys.stderr)
                except Exception as e:                      # noqa: BLE001
                    print("[open_console] 收旧窗口失败（不影响开新窗）：%r" % (e,),
                          file=sys.stderr)
                # ── 步骤 2：**等它们真的消失**再开新的 ──
                if verbose:
                    _gone, _left = WIN.wait_console_windows_gone()
                    if not _gone:
                        print("[open_console] 警告：仍有 %d 个旧窗口没消失，"
                              "继续开新窗。落位会覆盖全部匹配窗口" % _left,
                              file=sys.stderr)
            # ── 步骤 3：开窗 ──
            if opener is not None:
                opener(cmd)
            else:
                subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 creationflags=_DETACHED_FLAGS)
            # ── 步骤 4：开窗之后落位。参数是"请求"，这一步才是"事实" ──
            #   落位自己起守护线程（窗口刚起还没成型，不能同步等），
            #   失败只打到 stderr —— 不影响"窗口开出来了"这个返回值。
            _place_if_needed(placer, run_id=run_id, verbose=verbose)
            return "app"
        except Exception as e:                  # noqa: BLE001
            # ★ 不再静默：起不来就说清楚为什么（留痕只在 stderr，不写文件）
            print("[open_console] app 模式起不来，降级浏览器：%r" % (e,), file=sys.stderr)
    try:
        if opener is not None:
            opener(["--browser--", url])
        else:
            webbrowser.open(url)
        return "browser"
    except Exception as e:                      # noqa: BLE001
        print("[open_console] 浏览器也起不来：%r" % (e,), file=sys.stderr)
        return "none"


#: 后台Antinel 监理的单例（守护进程「打开Antinel 监理」用；幂等复用，不重复绑端口）
_BG = {"httpd": None, "url": None}


def ensure_background(port=DEFAULT_PORT, root=None):
    """确保Antinel 监理在**后台**跑着。**幂等**：已经在跑就复用。返回 `(url, started)`。

    ★ 为什么需要它（0.35.2）：托盘菜单「Open console」/左键点图标写出的 `open`
      动作**必须有消费点** —— 旧版只把 `open_console=True` 塞进 tick 结果，
      **全仓无人读**，于是点了托盘什么都不会发生（创始人 2026-10-06 实测）。
    ★ 只监听 127.0.0.1，口令一次性生成，与前台 `serve` 同一套 make_server。
    ★★ 0.35.2：首选端口被占时**改用系统分配的临时端口**，而不是抛错。
    """
    if _BG["httpd"] is not None and _BG["url"]:
        return _BG["url"], False
    # ★ 0.48.5（B2）：`_bind_first_free` 现多返回一个 drift —— 这条路（进程内后台）
    #   的"明说"就是**返回的 url**（它已带实际端口）；stderr 那句留给 `serve()`
    #   （手动/一键入口那条路，终端看得见）。这里不重复出声，免得守护进程 tick 刷屏。
    httpd, token, real_port, _drift = _bind_first_free(port, root)
    url = "http://127.0.0.1:%d/?t=%s" % (real_port, token)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    _BG["httpd"], _BG["url"] = httpd, url
    return url, True


def stop_background():
    """停掉后台Antinel 监理（测试/退出用）。没在跑 ⇒ 返回 False。"""
    h = _BG.get("httpd")
    if h is None:
        return False
    try:
        h.shutdown()
    except Exception:                           # noqa: BLE001
        pass
    _BG["httpd"], _BG["url"] = None, None
    return True


# --------------------------------------------------- Antinel 监理常驻（0.48.5 B1）----
#: ★★ 为什么要这一族（遗留问题清单 2026-10-13 B1，实测证据）：
#:   Antinel 监理服务原来是"代理会话里拉的前台进程"—— 会话结束就没了，托盘与守护
#:   进程**都不负责把它拉回来**。用户看到的是"窗口开着，点一下全是失败"。
#:   B1 验收：**杀掉服务进程后 60 秒内自行恢复，端口与 URL 不变**。
#:   三件套：
#:     ① `url.json` 落盘（端口/口令/pid/启动时刻/url）—— 重拉时**沿用同一个
#:        端口与口令**，URL 才可能不变（口令若每次重生成，URL 必变）；
#:     ② `console_status()` 判活 —— pid 活着 **且** 端口在听，两条都要；
#:     ③ `ensure_console()` 死了就按记录原样重拉（同端口同口令，幂等）。
#:   ★ 口令落盘是**本机回环**下的便利取舍（文件在用户自己的中枢目录里）；
#:     0.48.5 B3 会把口令从 URL 里拿掉（httpOnly cookie），届时 URL 只含端口。
#:   ★ 为什么必须**另起进程**：`ensure_background()` 是在**本进程**里起线程，
#:     命令一返回/进程一退服务就没了（0.35.2 已记过这条）。


def console_record_path(root=None):
    """Antinel 监理"开在哪"的落盘位置（`<中枢>/console/url.json`）。"""
    import inbox_config as _C
    return os.path.join(_C.console_dir(root), "url.json")


def write_console_record(port, token, pid=None, root=None, started_at=None,
                         want_port=None):
    """把"Antinel 监理开在哪"落盘（临时文件 + 原子替换）。返回写下的 dict。

    ★ 0.48.5（B2）：`want_port` ＝ 这次**想要**的端口。它与 `port` 不同
      ⇒ 说明发生了漂移 —— 留一份在盘上（stderr 那句随终端一起消失，落盘不会）。
      ★ 相同（或没给）⇒ **不写** `want_port` 字段（记录不掺冗余，读到没有即没漂移）。
    """
    p = console_record_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    rec = {"port": int(port), "token": str(token),
           "pid": int(pid if pid is not None else os.getpid()),
           "url": "http://127.0.0.1:%d/?t=%s" % (int(port), token),
           "started_at": started_at or time.strftime("%Y-%m-%dT%H:%M:%S")}
    # ★ 0.53.2（T3）：**出生时**的版本与代码指纹。写在这里而不是心跳里：
    #   它回答"这个进程跑的是哪份代码"，不是"现在的代码是什么"。
    stamp_runtime(rec)
    if want_port is not None and int(want_port) != int(port):
        rec["want_port"] = int(want_port)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rec, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, p)
    return rec


def read_console_record(root=None):
    """读"Antinel 监理开在哪"。没有 / 读坏 / 缺端口或缺口令 ⇒ `None`（**不编默认值**）。"""
    try:
        with open(console_record_path(root), encoding="utf-8") as f:
            d = json.load(f)
    except Exception:                                   # noqa: BLE001
        return None
    if not isinstance(d, dict) or not d.get("port") or not d.get("token"):
        return None
    return d


# ------------------------------------------------ 版本戳（0.53.2，T3）----
# ★★ 病（0.53.1 交付后实测）：`tray.json` 长时间没有 `logo` 块；代码是新的，
#   写状态的是**早上启动的旧进程**。重启 serve 无效 ⇒ 用户看到旧行为，
#   排查方向被带偏（以为新功能没写，其实旧进程没换）。
#   根因是「长驻进程」与「仓里的代码」是两个独立演化的东西，而**没有任何
#   出口把两者摆在一起**——用户只能靠猜。
# ★ 口径（刻意窄）：
#   · 戳只记**启动那一刻**的版本与代码指纹，之后不再刷新（它描述的是
#     "这个进程跑的是哪份代码"，不是"现在的代码是什么"）；
#   · 「现在的代码」由**读的人**现算（`code_identity()`），因为旧进程算不了
#     未来的代码 —— 两边必须来自两个不同时刻，这条差异才有信息量；
#   · 不新建第二份状态文件：console 的戳进 `url.json`（它本来就是"这个进程
#     是谁"的落盘），daemon 的戳进 `<pid 文件>.meta.json`（同目录、同前缀，
#     读它的地方本来就在读 pid）。
#   · **不自动杀进程**：那是用户的机器。只把话说清楚 + 给一条可复制的修法。

def code_version():
    """仓里（本包根）的版本号。读不到 ⇒ `None`（不编）。"""
    try:
        import antinel as _A
        v = str(getattr(_A, "VERSION", "") or "").strip()
        return v or None
    except Exception:                                   # noqa: BLE001
        return None


def code_identity():
    """「现在这份代码」的身份：`{version, mtime}`。`mtime` 取写规格的那个源文件。

    ★ 为什么取 `inbox_server.py` 自己的 mtime：它就是规格（`logo_motion_spec`）
      与页面（`_LOGO_JS`）的所在地 —— 0.53.1 那次"改了没效果"的正是这个文件。
      取包根目录的 mtime 会被任何无关文件干扰（`output/` 里落个探针就变）。
    """
    me = os.path.abspath(__file__)
    try:
        mt = os.path.getmtime(me)
    except OSError:
        mt = None
    return {"version": code_version(), "mtime": mt, "file": os.path.basename(me)}


def version_drift(running, current=None):
    """**这一个判断，全仓只有一处**。返回人话差异；一致 ⇒ `None`。

    `running` 是长驻进程启动时落下的戳。三种情形分清，不许合并：
      · 没有记录（`None`）⇒ **没有证据** ⇒ `None` —— 「没跑着」不是「版本不一致」，
        把它报成黄的，等于每次没人跑时报一次狼来了；
      · 有记录但**没有版本戳** ⇒ **是差异**（0.53.1 及更早的进程在跑，
        它们永远不会用上新代码）；
      · 有戳但版本不同 ⇒ 差异，文案里两边的版本号都要在（只说"不一致"
        等于把人又推回猜）。
    """
    cur = code_identity() if current is None else current
    if running is None:
        return None                     # 没有记录：没有证据，不编差异
    if not isinstance(running, dict):
        return None
    rv = running.get("code_version")
    cv = cur.get("version")
    # ★★ 0.53.2（2026-10-20 实测纠正）：修法文案**必须按进程分开说**。
    #   原来两条分支都写「重启一次即可：`antinel inbox window`」——
    #   而 `inbox window` 只重启**监理服务**，根本不动守护进程。
    #   后果不是"文案不精确"，是**自检永远归不了零**：用户照着做，
    #   下一次 `daemon status` 仍把守护进程报成旧进程 ⇒ 一条修好了、
    #   一条永远红 ⇒ 真差异再来时没人看（狼来了的另一种写法）。
    #   `_who` 从记录本身判，不许调用方各传一份（同 §42「只守一条腿」）。
    #   ★ 进程名不拼进正文：两个出口（`daemon status` 行 / `_runtime_lines`）
    #     都已经在行首写了进程名，正文再写一遍就是「监理服务跑的是…」这种叠字。
    _fix = _restart_hint(running)[1]
    if not rv:
        # ★ 行首调用方已经写了进程名 ⇒ 这里用「它」衔接，不重复「监理服务跑的是」
        # ★ 0.53.5（STE100 族六）：文案是**纯文本出口**（daemon status 直接
        #   上终端），源头就不写 markdown 加粗 —— 去星号不能只靠读侧。
        return ("它跑的是没有版本戳的旧进程（0.53.0 及更早），仓里是 %s。"
                "旧进程不会用新代码 —— %s" % (cv or "?", _fix))
    if rv != cv:
        return ("它跑的是 %s，仓里是 %s —— 旧进程不会用新代码。%s"
                % (rv, cv or "?", _fix))
    return None


def _restart_hint(rec, pid=None):
    """从运行时记录判「这是哪个长驻进程」并给出**真的能重启它**的做法。

    ★ 判定依据只有记录本身（`inbox_daemon.write_daemon_stamp` 写的是 pid/
      started_at/code_version/code_mtime，与 `url.json` 同形），所以**不靠**
      调用方传名字 —— 调用方传名字就会有人传错，而传错的表现是"用户照着做
      没效果"，比不报还糟。
    ★★ 为什么不写「`antinel inbox daemon restart`」（2026-10-20 实测纠正）：
      **这条子命令不存在**。给一条不存在的命令，比说"请重启"更坏 ——
      用户照抄、报"invalid choice"，然后认定整个自检是坏的。
      而 `ensure_daemon` 是**幂等**的（活着就复用，绝不重启）⇒ 外部
      没有任何一条命令能让旧守护进程换血，只能由用户自己结束它。
      ⇒ 文案给**用户真能做的两步**：结束旧进程 → 重开。不说"自动"。
    ★ 返回 `(进程名, 修法)`；进程名由**记录形状**判，修法里不再重复它
      （调用方已经在行首写了进程名，正文再说一遍就是"监理服务跑的是…"
      这种叠字）。
    """
    keys = set(rec or {})
    if "port" in keys or "url" in keys:
        return ("监理服务", "重启一次即可：antinel inbox window")
    _pid = pid if pid is not None else (
        rec.get("pid") if isinstance(rec, dict) else None)
    # ★ 顺序不可交换：`run_daemon` 是**单例**（`daemon_alive` 为真就返回
    #   `already-running` 直接退出）⇒ 不先结束旧的，跑 `daemon` 是空操作，
    #   用户会以为重启过了。所以文案把顺序写死：**先结束 → 再拉**。
    return ("守护进程",
            "它是常驻进程，没有内建重启命令（inbox window 只重启监理服务，"
            "不动它）。换血两步，顺序不能反：① 先在任务管理器结束 %s；"
            "② 再开一个终端跑 antinel inbox daemon --supervise。"
            "不先结束旧的，这一步会因单例直接退出、什么都不做"
            % (("pid %s" % _pid) if _pid else "这个进程"))




def stamp_runtime(rec, current=None):
    """给一份运行时记录补上版本戳（就地改并返回）。启动时调用一次。

    ★ 只在字段**缺**时写：这是一次性的"我出生时是什么"，不是心跳。
    """
    cur = code_identity() if current is None else current
    if rec is not None and cur.get("version"):
        rec.setdefault("code_version", cur.get("version"))
        rec.setdefault("code_mtime", cur.get("mtime"))
    return rec


def console_status(root=None, rec=None):
    """Antinel 监理此刻在不在。返回 `(alive, rec, why)` —— 守护进程与判据共用一处。

    ★ 判活**两条都要**：
      · 只看 pid ⇒ pid 会被复用（判活看的是"那个进程"，不是"那个号"）；
      · 只看端口 ⇒ 别的程序占了 8790 也会被当成"Antinel 监理在跑"。
    """
    rec = read_console_record(root) if rec is None else rec
    if not rec:
        return False, None, "还没有 Antinel 监理的落盘记录（没起过）"
    pid, port = rec.get("pid"), int(rec.get("port"))
    alive_pid = False
    try:
        import audit_chain as _AC
        alive_pid = bool(pid) and bool(_AC.pid_alive(int(pid)))
    except Exception:                                   # noqa: BLE001
        alive_pid = False
    listening = _port_busy(port)
    if alive_pid and listening:
        return True, rec, "在跑"
    if not alive_pid and not listening:
        return False, rec, "进程与端口都不在了"
    if not alive_pid:
        return False, rec, "登记的服务进程已不在（端口 %d 另有其在听）" % port
    return False, rec, "服务进程在，但端口 %d 没人在听" % port


def _console_spawn_cmd(port, token, root=None):
    """重拉Antinel 监理要跑的命令（**唯一实现**：守护进程与判据都看它，不各拼一份）。"""
    entry = os.path.join(os.path.dirname(os.path.abspath(__file__)), "antinel.py")
    cmd = [sys.executable, entry, "inbox", "serve",
           "--port", str(int(port)), "--token", str(token)]
    if root:
        cmd += ["--root", str(root)]
    return cmd


def spawn_console(port, token, root=None):
    """按给定端口/口令**另起一个进程**跑Antinel 监理（分离、无窗）。返回 `Popen`。"""
    flags = 0
    if os.name == "nt":
        flags = 0x00000008 | _CREATE_NO_WINDOW   # DETACHED_PROCESS | CREATE_NO_WINDOW
    return subprocess.Popen(_console_spawn_cmd(port, token, root),
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=flags)


def _daemon_spawn_cmd(root=None):
    """重拉守护进程要跑的命令（**唯一实现**：入口与判据都看它，不各拼一份）。

    ★ 带 `--supervise`：daemon 不能只是躺着，还要顺带维持服务 ——
      否则「窗口有了宿主」但「服务没人管」，用户刷新还是白屏。
    ★ 不带 `--root`：`daemon` 子命令的 parser 目前没有这个参数（只有 `serve`
      有）。root 只用于**判活**与判据注入 spawner，不往命令行塞不存在的开关。
    """
    entry = os.path.join(os.path.dirname(os.path.abspath(__file__)), "antinel.py")
    return [sys.executable, entry, "inbox", "daemon", "--supervise"]


def spawn_daemon(root=None):
    """另起一个**守护进程**（分离、无窗）。返回 `Popen`。`root` 仅为签名一致。"""
    flags = 0
    if os.name == "nt":
        flags = 0x00000008 | _CREATE_NO_WINDOW   # DETACHED_PROCESS | CREATE_NO_WINDOW
    return subprocess.Popen(_daemon_spawn_cmd(root),
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=flags)


def ensure_daemon(root=None, spawner=None, wait_sec=6.0):
    """确保守护进程在跑（**幂等**）。返回 `(alive, pid, started, why)`。

    ★★★★ 为什么窗口入口必须先过这一关（2026-10-18 创始人「点图标看不到」）：
      窗口归**启动它的进程**所有。CLI 直起的窗口挂在本次命令名下，命令一退
      窗口就死（2026-10-14 四路实证：`Popen`／`DETACHED`／`cmd start` 全死，
      只有 **daemon（长命进程）起的活**）。所以「daemon 在不在」不是优化项，
      是**开窗的前置条件**。
      旧 `cmd_window` 只在开窗**失败后**降级，从不检查 daemon 在不在 ——
      于是「已就位」和「窗口秒死」可以同时成立，而两条判据各自都绿。

    ★ 成功判定**只认回读**：`spawner` 返回一个 Popen 不算数，必须
      `daemon_alive` 为真。与 `ensure_console` 同一条纪律 ——
      **报成功不许由「走了哪个分支」决定**。
    """
    import inbox_daemon as DM
    alive, pid = DM.daemon_alive(root)
    if alive:
        return True, pid, False, "已在跑"
    try:
        (spawner or spawn_daemon)(root)
    except Exception as e:                                  # noqa: BLE001
        return False, None, True, "拉不起来：%s: %s" % (type(e).__name__, e)
    deadline = time.time() + float(wait_sec)
    while time.time() < deadline:
        alive2, pid2 = DM.daemon_alive(root)
        if alive2:
            return True, pid2, True, "已重拉"
        time.sleep(0.15)
    return False, None, True, ("拉不起来：%.1f 秒内没登记到守护进程"
                               "（多半是命令跑起来就退了）" % float(wait_sec))


def ensure_console(port=DEFAULT_PORT, root=None, spawner=None, wait_sec=8.0):
    """确保Antinel 监理在跑（**幂等**）。返回 `(rec|None, started: bool)`。

    ★ 0.48.5（B1）验收口径：被杀掉后重拉时**端口与口令都沿用记录里的**
      （URL 不变）；没有记录（从没起过）才用默认端口 + 新口令。
    ★ `spawner` 可注入：判据用假 spawner 验决策链，不去真起进程。
    """
    alive, rec, _why = console_status(root)
    if alive:
        return rec, False
    want_port = int(rec.get("port")) if rec else int(port)
    want_token = (rec or {}).get("token") or secrets.token_urlsafe(24)
    (spawner or spawn_console)(want_port, want_token, root)
    deadline = time.time() + float(wait_sec)
    while time.time() < deadline:
        if _port_busy(want_port):
            break
        time.sleep(0.2)
    _alive2, rec2, why2 = console_status(root)
    # ★★ 0.53.0：**成功只由回读说了算** —— spawn 分支走过 ≠ 服务起来了。
    #   旧实现 `rec2 or rec`：没起来时把**旧记录**还回去，调用方据此打印
    #   「已重拉」，而端口根本没开。本机实测：`console.log` 连打 7 次
    #   「已重拉」，`netstat` 里 8790 一次都没出现过 —— 用户看到的是
    #   「报了功、窗没了」，一刷新还是白屏。
    #   以旧充新 = **报成功不由事实决定**，与 0.53.0 T-04e 抓到的态名分裂
    #   是同一族毛病（判据替实现背书）。⇒ 没起来就返回 None，让调用方
    #   如实说「没起来」并给原因（`console_status` 的 why）。
    if not _alive2:
        return None, True
    return rec2, True


def _serve_setup(port, root, token=None, record=True):
    """`serve()` 的**非阻塞前半段**：绑端口 → 被占就出声 → 落盘。

    返回 `(httpd, token, real_port, drift)`。

    ★★ 为什么抽出来（0.48.5 B2）：`serve()` 的后半段是 `serve_forever()`（**阻塞**），
      判据没法在里头验「端口被占时有没有出声」。前半段无阻塞、可测 ——
      于是"明说"这件事有了**行为判据**，而不是只靠源码字面。
    """
    httpd, token, real_port, drift = _bind_first_free(port, root, token=token)
    if drift:
        # ★★ 0.48.5（B2）：被占时**出声**（原来静默换端口 ⇒ 用户手输 8790
        #   打不开、也不知道它跑到哪去了）。话由 `console_drift_note()` 唯一实现。
        print("!! " + console_drift_note(drift), file=sys.stderr)
    if record:
        try:
            write_console_record(real_port, token, pid=os.getpid(), root=root,
                                 want_port=(drift or {}).get("want"))
        except Exception as e:                          # noqa: BLE001
            # ★ 落盘失败**出声**：它失败 ⇒ 守护进程判不出活、也就不会重拉
            #   （"保护在起作用却没人看得见"是本仓点名禁止的形状）。
            print("!! Antinel 监理落盘记录没写成（%r）—— 守护进程将无法判活/重拉" % (e,),
                  file=sys.stderr)
    return httpd, token, real_port, drift


#: ★ 0.52.0：哨标 `open` 动作的**服务端消费节拍**（秒）。
#:   为什么服务端也要消费（而不仅是守护进程/托盘）：点哨标写出的 `open`
#:   原来只有 daemon/tray 会读 —— 只开Antinel 监理服务（B1 常驻）时**没人消费**，
#:   实测（创始人 2026-10-17）点击哨标后它自毁、Antinel 监理永远开不出来。
#:   服务是收缩↔展开循环里**必然活着**的那一方 ⇒ 它必须会消费。
#:   消费仍走 `inbox_daemon.handle_actions()`（**唯一实现**，改名消费原子，
#:   与 daemon/tray 并存也不会双开）。0.5s ≈ 哨标点击后的可感延迟下限。
CONSUME_INTERVAL_SEC = 0.5


def _consume_actions_loop(root=None, console_url=None, stop=None,
                          interval=CONSUME_INTERVAL_SEC, consumer=None):
    """服务端消费托盘动作的循环（0.52.0，跑在后台线程里）。

    ★ 动作语义**不二次实现**：默认调 `inbox_daemon.handle_actions()`，
      并把**自己的 URL** 作为 `console_url` 传入 —— 否则 `open_console_now`
      会在本进程里再起一个后台服务实例（端口漂移同款病）。
    ★ `consumer` 可注入（判据不起真服务、不真开窗）；一轮出错不许打死循环。
    ★ stop 是 threading.Event；None ⇒ 永跑（daemon 线程随进程退）。
    """
    import inbox_daemon as DM
    fn = consumer or DM.handle_actions
    while not (stop is not None and stop.is_set()):
        try:
            fn(root=root, console_url=console_url)
        except Exception:                       # noqa: BLE001
            pass
        stop.wait(float(interval)) if stop is not None else time.sleep(float(interval))


def _prewarm_logo_once(root=None):
    """预埋隐藏常驻哨标（0.52.0，只此一处调用：`serve()` 起来后后台跑）。

    ★ 为什么服务起来就预热：不预热的话，每次开机后的第一次收缩仍要冷启
      PowerShell（慢一次）。失败只打 stderr —— 预热是优化，冷启路径兜底。
    """
    try:
        import inbox_logo as IL
        rep = IL.prewarm(root=root, verbose=False)
        if not rep.get("ok"):
            print("[logo] 预热没成（不影响使用，首次收缩会冷启）：%s"
                  % rep.get("why", ""), file=sys.stderr)
    except Exception as e:                      # noqa: BLE001
        print("[logo] 预热失败（不影响使用）：%s: %s" % (type(e).__name__, e),
              file=sys.stderr)


def serve(port=DEFAULT_PORT, root=None, open_browser=False, token=None, record=True):
    """前台起服务（Ctrl+C 停）。★ 首选端口被占 ⇒ 自动换临时端口（Windows 上
    光靠 `OSError` 发现不了，见 `_port_busy`）。

    ★ 0.48.5（B1）：`token` 可传入（重拉时沿用旧口令，URL 不变）；
      `record=True` 把"开在哪"落盘（`url.json`）—— 守护进程靠它判活与重拉。
    ★ 0.48.5（B2）：被占时**不再静默** —— `_serve_setup()` 会把"换了端口"
      说到 stderr，并把 `want_port` 一并落盘。
    ★★ 0.52.0：起服务即 ① 起后台线程**消费托盘动作**（点哨标 ⇒ 开Antinel 监理，
      不再依赖 daemon/tray 是否在跑）＋ ② 预埋隐藏常驻哨标（首次收缩也瞬时）。
    """
    httpd, token, real_port, _drift = _serve_setup(port, root, token=token,
                                                   record=record)
    url = "http://127.0.0.1:%d/?t=%s" % (real_port, token)
    print("Antinel 监理已开在：%s" % url)
    print("（只监听本机；关掉这个窗口就停）")
    # ★ 0.52.0 ①：动作消费线程（daemon 线程，随进程退；与 daemon/tray 的
    #   消费并存不双开 —— `poll_actions` 的改名消费是原子的）
    threading.Thread(target=_consume_actions_loop, daemon=True,
                     kwargs={"root": root, "console_url": url}).start()
    # ★ 0.52.0 ②：预埋哨标（后台线程 —— PowerShell 冷启不该拖住开服）
    threading.Thread(target=_prewarm_logo_once, daemon=True,
                     kwargs={"root": root}).start()
    if open_browser:
        # ★ 0.35.2：开成**独立窗口**（app 模式），不再塞进浏览器标签页。
        threading.Timer(0.6, lambda: open_console(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    return url
