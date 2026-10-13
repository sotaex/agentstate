# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""值守台 · 本地页（**只在你自己的电脑上开**）。

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
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import inbox_model as M
import inbox_report as R
import inbox_store as S
import glossary as GL
import ledger as L

DEFAULT_PORT = 8790
ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")

#: Windows：起子进程时**不新建控制台**。★ 0353 P12 专守这条 —— 哨兵/值守台
#: 是 `DETACHED_PROCESS` 拉起的（**没有控制台**），它们再起控制台程序
#: （netstat/tasklist/powershell…）时若不显式给这个标志，Windows 会**新建一个
#: 控制台** ⇒ 用户看到黑窗一闪。`host_shield`/`egress` 同款常量，不在本文件另立口径。
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# 允许对外提供的静态文件名（白名单 —— 杜绝路径穿越）
ASSET_WHITELIST = {
    "L0.mp4": "logo/L0.mp4", "L1.mp4": "logo/L1.mp4", "L2.mp4": "logo/L2.mp4",
    "Ls.mp4": "logo/Ls.mp4", "R0.mp4": "logo/R0.mp4", "logo.svg": "logo/logo.svg",
    "L0.ico": "icons/L0.ico", "L1.ico": "icons/L1.ico", "L2.ico": "icons/L2.ico",
    "Ls.ico": "icons/Ls.ico", "R0.ico": "icons/R0.ico",
    "favicon.ico": "icons/L0.ico",
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
.bar{display:flex;align-items:center;gap:16px;padding:12px 20px;border-bottom:1px solid var(--line);background:var(--panel);flex-wrap:wrap}
.logo{width:48px;height:48px;border-radius:12px;overflow:hidden;background:#0a1a12;flex:none}
.logo video,.logo img{width:100%;height:100%;display:block;object-fit:cover}
/* ★ 0.48.5（交接件 §5.4 戊4）：状态词 16px 粗体（色随态，行内 style 走
   `M.STATE_VAR` —— 与 `.dot` 同一个真源）；解释句 13px 常规色 `var(--fg)`。
   旧形状是「词 17px  inherited 黑／解释 12px 灰」—— 信息量大的那句
   （为什么是这个态）被压成次要，权重倒挂；判据 U-15 锁旧声明不许回来。 */
.state b{font-size:16px;font-weight:700}
.state span{font-size:13px;color:var(--fg)}
.pill{display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid var(--line)}
.dot{width:8px;height:8px;border-radius:50%}
.spacer{flex:1}
/* ★ 0.48.5（交接件 §5.4 丁2/丁3）：顶部条右侧那个零信息量块连同类规则一起删
   （回环地址每台机器一样；另一半是口号不是证据）。证据搬到运行状态页的
   「监听地址」行，由 `_check_bind` 硬校验背书 —— 判据 U-10 同时断言
   删干净、证据在、后盾真。本注释刻意不复述被删的两串字面：判据扫的正是
   渲染产物，在这里写例子会自己踩自己（D-30 同款教训）。 */
.tabs{display:flex;gap:4px;padding:10px 20px 0;border-bottom:1px solid var(--line);flex-wrap:wrap}
.tabs a{padding:9px 14px;color:var(--muted);font-weight:600;text-decoration:none;border-bottom:2px solid transparent}
.tabs a.on{color:var(--brand);border-bottom-color:var(--brand)}
main{max-width:1000px;margin:0 auto;padding:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:12px}
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
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px}
.metric{background:var(--panel);border-radius:10px;padding:14px}
.metric .k{font-size:12px;color:var(--muted)}
.metric .v{font-size:26px;font-weight:700}
.metric a{text-decoration:none}
/* ---- 0.36.1：术语词条改成**浮层**（创始人截图三）----
   ★ 原形状的病：`.term{display:inline}` 把详情块塞进 `.metrics` 的
     140px 窄格里 ⇒ 展开后宽度只有卡片那么宽 ⇒ 中文逐字换行，
     变成一条极细长、极难读的竖条（用户实测截图三）。
   ⇒ 改法：词条本体仍是 `<summary>` 小标签；展开内容**脱离文档流**，
     用 `position:absolute` 浮在页面之上，宽度取 `min(560px, 视口-32px)`
     —— 窄面板里也能正常成段阅读。
   ★ 为什么不用 `position:fixed`：会脱离滚动容器，长页面展开时飘在别处。
   ★ 关闭行为交给原生 `<details>`（点外面不关，但点开别的词条会收起上一个，
     因为同名 details 在同一父节点下互斥——这也是选原生控件的原因）。 */
.term{position:relative;display:inline-block}
.term>summary{cursor:pointer;list-style:none}
.term>summary::-webkit-details-marker{display:none}
.term>summary::after{content:"？";display:inline-block;margin-left:3px;
  width:14px;height:14px;line-height:14px;text-align:center;border-radius:50%;
  background:var(--line);color:var(--muted);font-size:10px;font-weight:700}
.term[open]>summary::after{content:"？";background:var(--brand);color:#fff}
/* ★ 0.48.5（交接件 §5.6 乙1）：裸「？」芯片（mk）—— summary 自带一个「？」，
   ::after 徽章再补一个就成「？？」⇒ mk 形态把 ::after 整个关掉
   （content:none ＋ display:none 双保险：只留 content 会渲染一个空圆圈）。 */
.term.mk>summary::after{content:none;display:none}
.tdef{position:absolute;z-index:60;top:calc(100% + 6px);left:0;
  width:max-content;max-width:min(560px,calc(100vw - 32px));min-width:260px;
  margin:0;padding:12px 14px;font-size:12.5px;line-height:1.75;color:var(--fg);
  background:var(--bg,#fff);border:1px solid var(--line);border-left:3px solid var(--brand);
  border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.16);font-weight:400;
  white-space:normal;text-align:left}
/* 贴着屏幕右边时改为右对齐，避免浮层被裁掉 */
.term.flipx>tdef{left:auto;right:0}
/* 三行结构（包含/不含/口径）改成**成对列**，不再挤成一长条 */
.tr{margin-top:6px;padding-top:6px;border-top:1px dashed var(--line);color:var(--fg)}
.tr:first-of-type{margin-top:8px}
.tl{display:inline-block;min-width:34px;margin-right:6px;padding:1px 6px;
  border-radius:4px;background:var(--line);color:var(--muted);
  font-size:11px;font-weight:700;vertical-align:1px;text-align:center}
.tdef b{color:var(--brand)}
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
  .tdef{max-width:calc(100vw - 24px);min-width:0;font-size:12px;line-height:1.7}
  .term{width:100%}
  .term>tdef,.term.flipx>tdef{left:0;right:auto;width:calc(100vw - 40px)}
}
.rows{border:1px solid var(--line);border-radius:10px;overflow:hidden}
.row{display:flex;gap:12px;padding:11px 15px;border-bottom:1px solid var(--line);font-size:13px}
.row:last-child{border-bottom:0}
.row .k{flex:none;width:150px;color:var(--muted)}
.ok{color:var(--l0);font-weight:700}.warn{color:var(--l1);font-weight:700}.bad{color:var(--r0);font-weight:700}.neutral{color:var(--muted);font-weight:700}.dev{color:var(--brand);font-weight:700}
.empty{text-align:center;padding:40px;color:var(--muted)}
.note{font-size:12px;color:var(--muted)}
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
details.rem[open]>summary .t{color:var(--r0)}
.rem{border:1px solid var(--line);border-radius:8px;margin:10px 0 0;background:var(--panel)}
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
.rem .seg.cost{border-left-color:var(--muted)}
.rem .seg h4{margin:0 0 4px;font-size:12px;color:var(--muted);font-weight:700;
  text-transform:none}
.rem .seg p{margin:0}
.rem .seg .note{font-size:11px;color:var(--muted);margin-top:5px}
.rem .bclass{display:inline-block;font-size:11px;padding:2px 8px;border-radius:99px;
  background:rgba(220,60,60,.12);color:var(--r0);border:1px solid var(--r0);
  margin-left:8px;white-space:nowrap}
.rem ol{margin:6px 0 0;padding-left:20px}
.rem ol li{margin:7px 0}
.rem .cmd{display:block;font-family:var(--mono);font-size:12px;background:var(--bg);
  border:1px solid var(--line);border-radius:6px;padding:6px 9px;margin:5px 0;
  user-select:all}
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

#: ★ 0.36.1：术语浮层的**贴边翻转**（创始人截图三的连带问题）。
#   浮层默认从词条右边展开；可它在窄面板里往往靠右 ⇒ 会被视口裁掉。
#   ⇒ 展开时量一下右边缘，超出视口就改成右对齐（加 `.flipx`）。
#   ★ 为什么不用 JS 测量文字宽度：CSS `max-width` 已经够，
#     JS 只决定"往哪边开"，这是测量**位置**而非内容，判定稳定。
#   ★ 零依赖、渐进增强：JS 不执行时只是浮层可能靠右，仍然可读。
_FLIP_JS = """
<script>
(function(){
  function fit(d){
    if (!d.classList) return;
    var box = d.querySelector('.tdef');
    if (!box) return;
    d.classList.remove('flipx');
    var r = box.getBoundingClientRect();
    if (r.right > document.documentElement.clientWidth - 8) {
      d.classList.add('flipx');
    }
  }
  document.addEventListener('toggle', function(e){
    var d = e.target;
    if (d.classList && d.classList.contains('term') && d.open) fit(d);
  }, true);
  window.addEventListener('resize', function(){
    document.querySelectorAll('details.term[open]').forEach(fit);
  });
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
  d.dataset.readed = '1';
  var t = d.dataset.token, id = d.dataset.id, ids = d.dataset.ids;
  if (!t || (!id && !ids)) return;
  var body = 't=' + encodeURIComponent(t) + '&op=read';
  body += ids ? ('&ids=' + encodeURIComponent(ids))
              : ('&id=' + encodeURIComponent(id));
  fetch('/action', {method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:body})
    .then(function(){ var x=d.querySelector('.unread-dot'); if(x) x.remove(); })
    .catch(function(){});
}, true);
</script>
"""


# ------------------------------------------------------------- 安全 ----
def _check_bind(addr):
    """★ 只允许回环。非回环 ⇒ 抛错（判据 J6 的落点）。"""
    if str(addr) not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("本地页只允许监听回环地址，拒绝绑定 %r" % (addr,))


def _esc(s):
    return html.escape("" if s is None else str(s), quote=True)


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
                "why": "读不到哨兵状态：%r" % (e,), "evidence": {},
                "can_fix": False, "fix": None, "fix_hint": ""}


# ------------------------------------------------------------- 页面 ----
def _head(title, token):
    """页面 `<head>`。

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
    except Exception:                                       # noqa: BLE001
        rid = ""
    mark = ("#" + rid) if rid else ""
    return ("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>%s · 值守台%s</title><link rel=\"icon\" href=\"/assets/favicon.ico?t=%s\">"
            "<style>%s</style></head><body>"
            % (_esc(title), mark, _esc(token), CSS))


def _tabs(view, token):
    """选项卡。★ 0.37.1：**不再挂数字徽章** —— 首页实测「同一件事的 4 件」

    在 tabs 徽章、顶部条后缀、筛选条、说明行里出现了 5 次（创始人 2026-10-08
    点名）。数字现在只属于内容区：收件箱页在筛选条，其他页在顶部条后缀。
    选项卡只负责「去哪儿」。
    """
    def a(v, label):
        cls = " class=\"on\"" if v == view else ""
        return "<a href=\"/?v=%s&t=%s\"%s>%s</a>" % (v, _esc(token), cls, label)
    return ("<nav class=\"tabs\">" + a("inbox", "收件箱")
            + a("report", "日报") + a("health", "运行状态") + a("ledger", "账本")
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
            suffix = ("<a href=\"/?v=inbox&amp;f=action&amp;t=%s\" "
                      "style=\"color:inherit;text-decoration:none\">（%s）</a>"
                      % (_esc(token),
                         _esc(M.count_text(action_groups, len(items)))))
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
    # ★★ 把"失守的损失"逐条摆出来（创始人 2026-10-06：
    #   「如果真失守不会带来明显不利后果，那就跟假失守没啥区别」）。
    cons = p.get("consequences") or []
    if cons:
        lis = "".join("<li>%s</li>" % _esc(c.get("text") if isinstance(c, dict) else c)
                      for c in cons)
        # ★ 0.47.0：这一处是**后果清单**（此刻实况），**不是告警计数** ——
        #   分母对它没有意义（它没有"来自哪个总量"这回事）。
        #   按方案 §5 步三的口径，给它标注**范围**（此刻）并说明它不是计数，
        #   判据对它有显式豁免（写明理由），不许被当成"无分母的告警数"蒙混过去。
        fix = ("<span class=\"cons\"><b>失守的损失：以下 %d 项（此刻实况，"
               "非计数）：</b><ul>%s</ul></span>"
               % (len(cons), lis)) + fix
    # ★ 0.35.3：三个数字**各自带上自己的事由件数**，口径写明；点进去仍是全部明细。
    #   记录数/件事数成对同源（`window_levels` ＋ `window_level_groups`，
    #   0.37.1 起不再手抄一遍分组逻辑）。
    wl = M.window_levels(items, now=now)
    wg = M.window_level_groups(items, now=now)

    def _pill(label, level):
        n, g = wl.get(level, 0), wg.get(level, 0)
        same = (n == g)
        # ★ 0.37.2：括号**每一页都显示**（旧版收件箱页不显示 —— 于是同一排
        #   数字在收件箱页和其他页**长得不一样**：首页「失守 104」、
        #   日报页「失守 104（4 件事）」。跨页不一致本身就是违和感）。
        #   它防的是「104 条记录被当成 104 件事」（P14 判据的实测依据：
        #   R0 有 80 条、只有 8 种原因）；件数与「要处理 N」是**两个不同的量**
        #   （前者＝该级别的事由件数，后者＝需要你动手的件数），
        #   只是本机此刻恰好同值 —— 量不同就不算重复，不许为了省数字把口径藏掉。
        show_groups = not same
        # ★ 0.48.5（交接件 §5.4 丁4）：title 从 40+ 字工程说明收缩到一句人话
        #   （判据 U-11 锁 title ≤ 20 字，**含空格脚本点数** —— 文档目标串
        #   「最近 24 小时的记录数（自本次载入起算）」实测 21 字超限，同义
        #   收作「自载入起算」19 字）。「按事由归并后的件数」的解释归「？」
        #   词条的口径行；旧 title 后半句还是替用户描述他的动作（W08 立意）。
        return ("<a title=\"最近 %d 小时的记录数（自载入起算）\" "
                "href=\"/?v=inbox&f=win:%d:lv:%s&t=%s\">%s <b>%d</b>%s</a>"
                % (M.WINDOW_HOURS, M.WINDOW_HOURS, level, _esc(token), label, n,
                   "" if not show_groups else "（%d 件事）" % g))

    # ★ 0.37.2：顺序改为**由重到轻**（失守 → 拦截 → 注意）。
    #   旧版是「拦截 · 注意 · 失守」—— 最重的排在最后，读起来像"越读越轻"，
    #   与页面其余处（收件箱归并列表、日报卡片）按级别倒序排的规矩相反。
    # ★ 0.48.5（交接件 §5.6 乙1）：每个药丸后跟一个**裸「？」芯片**
    #   （兄弟节点，不塞进 `<a>` —— 链接里嵌 interactive 是坏味道）。
    nums = ("<span class=\"pill\">最近 %d 小时：%s · %s · %s</span>"
            % (M.WINDOW_HOURS,
               _pill("失守", "R0") + GL.chip("R0", mk=True),
               _pill("拦截", "L2") + GL.chip("L2", mk=True),
               _pill("注意", "L1") + GL.chip("L1", mk=True)))
    return (
        "<header class=\"bar\">"
        # ★★ 0.48.5（交接件 §5.4 戊1）：头部图标改用 `logo.svg`（矢量，48px
        #   任意尺寸不发虚）—— 旧版 state 专属 mp4 在 768×768 → 46×46 的
        #   缩放下发虚（607 KB 换一个模糊角标）；mp4 留给托盘（16×16 合理）。
        #   状态不再靠图标区分：状态由灯（`.dot` ＋ 状态词随态色）独占。
        "<div class=\"logo\"><img alt=\"Antinel\" src=\"/assets/logo.svg?t=%s\"></div>"
        # ★ 0.48.5（交接件 §5.6 乙1）：顶部灯的「？」芯片跟在 `<b>` 后
        #   （灯不是链接，芯片可以直接挨着；全站共 8 个落点，U-04 逐个数）。
        # ★ 0.48.5（交接件 §5.4 戊4）：状态词 16px 粗体、**色随态**
        #   （与 `.dot` 同一个 `M.STATE_VAR` —— 单一真源）；解释句降为
        #   13px 常规色（信息量大的那句占主导，见 U-15）。
        "<div class=\"state\"><span class=\"dot\" style=\"background:var(%s)\"></span>"
        "<b style=\"color:var(%s)\">%s</b>%s%s<br><span>%s</span></div>"
        "%s%s<div class=\"spacer\"></div></header>"
        % (_esc(token), M.STATE_VAR[st], M.STATE_VAR[st],
           label, GL.chip("light", mk=True), suffix, state_reason, nums, fix))


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


def _item_html(it, token):
    """一条记录：★ 收起时**一个按钮都没有**，点开才给两个动作。

    ★ 创始人 2026-10-06：「每一条右侧都是三个按钮，占地方不说，太多了也不会有人去点」
      ⇒ 行内 0 按钮、展开后 2 个（知道了 / 忽略）。
    ★「标为已读」**已取消**（创始人拍板①）—— 点开**自动**记为已读（见 `_READ_JS`）。
    """
    if it.state in M.OPEN_STATES:
        acts = (_form(token, "done", it.id, label="知道了", cls="ok")
                + _form(token, "ignored", it.id, note="判断无需动作", label="忽略"))
    else:
        acts = _form(token, "read", it.id, label="重开")
    dot = "<span class=\"unread-dot\"></span>" if it.state == "unread" else ""
    # ★ "每次报警信息要齐"：原因(detail)、规则、命中、时间、链引用、备注一个都不能少
    meta = " · ".join(x for x in (
        it.detail,
        ("规则 " + it.rule_id) if it.rule_id else "",
        ("命中「%s」" % it.snippet) if it.snippet else "",
        it.ts, ("链 " + it.chain_ref[:10]) if it.chain_ref else "",
        ("备注：" + it.note) if it.note else "") if x)
    return ("<details class=\"item %s %s\" data-id=\"%s\" data-token=\"%s\">"
            "<summary><span class=\"badge %s\">%s</span>"
            "<span class=\"t\">%s%s</span><span class=\"when\">%s</span></summary>"
            "<div class=\"det\"><p class=\"m\">%s</p>%s"
            "<div class=\"act\">%s</div></div></details>"
            % (_esc(it.level.lower()), _esc(it.state), _esc(it.id), _esc(token),
               _esc(it.level.lower()), _esc(it.level), dot, _vis(it.title),
               _esc(str(it.ts)[5:16]), _vis(meta), _rem_html(it, token), acts))


# --------------------------------------------------------------------------
# 0.36.0：失守归因面板
# --------------------------------------------------------------------------
def _rem_html(it, token):
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
        a = RM.attribute(it)
    except Exception as e:                                   # noqa: BLE001
        # ★ 归因模块坏了也不能让整页500 —— 如实说"这一项算不出来"，
        #   并**仍然给一步可做的**（去运行状态页看现探）。
        a = {"kind": "unknown", "title": "这一项归因算不出来",
             "b_class": False, "by_text": False,
             "cause": "归因模块报错（%s）——不编一个听起来合理的原因。" % e,
             "severity": "算不出来。",
             "severity_note": "（这是产品故障，不是你的操作问题。）",
             "actions": [{"op": "info", "label": "回运行状态页看现探",
                          "cmd": "", "hint": "那里有此刻的实测态势。"}],
             "cost": "归因失败 ⇒ 你只能看到「失守」，拿不到「为什么」。"}

    # ★★ 0.37.1：归因文案走 `GL.render()`（**不是** `_esc`）——
    #   归因作者习惯写 markdown 的 `**重点**`，而 `_esc` 只是转义，
    #   星号会原样出现在屏幕上（2026-10-09 实测：首页每一条失守的"为什么"
    #   里都带着 `**`，8 个归因类无一幸免）。`GL.render()` 既吃 markdown
    #   又只放行 `<b>/<code>`，且仍会转义用户输入 ⇒ 两头都安全。
    def _tx(s):
        return GL.render(str(s or ""))

    badge = ('<span class="bclass">修不了根因 · 请选一条路</span>'
             if a.get("b_class") else "")
    txt = ("<span class=\"why\">这一条是靠记录文案认出来的</span>"
           if a.get("by_text") else "")

    segs = [
        '<div class="seg root"><h4>① 根因是什么</h4><p>%s</p>%s</div>'
        % (_tx(a.get("cause")), txt),
        '<div class="seg sev"><h4>② 现在有多严重</h4><p>%s</p>'
        '<p class="note">%s</p></div>'
        % (_tx(a.get("severity")), _tx(a.get("severity_note"))),
    ]

    # ③ 能做什么 —— **按「可执行性」排序**，命令型排最前
    items_html = []
    for act in a.get("actions") or []:
        op = act.get("op")
        cls = {"fix": "go", "retry": "go", "rearm": "go",
               "drop": "drop", "accept": "risk", "info": ""}.get(op, "")
        cmd = act.get("cmd") or ""
        cmd_html = ('<code class="cmd">%s</code>' % _esc(cmd)) if cmd else ""
        why = act.get("hint") or ""
        why_html = ('<div class="why">%s</div>' % _tx(why)) if why else ""
        items_html.append(
            "<li><b>%s</b>%s%s"
            '<div class="pick">%s</div></li>'
            % (_tx(act.get("label") or op), cmd_html, why_html,
               _rem_pick_buttons(it, token, op, cls, act)))
    segs.append('<div class="seg act"><h4>③ 你现在能做什么</h4><ol>%s</ol></div>'
                % "".join(items_html))

    segs.append('<div class="seg cost"><h4>④ 如果什么都不做</h4><p>%s</p></div>'
                % _tx(a.get("cost")))

    # ★ badge 放在**body 第一段**（不是 summary 里）——
    #   `_rem_panel_only()`给归并行复用时只取 body，badge 放summary 会被丢掉。
    #   实测踩过：归并行的三选一按钮都出来了，badge 却0 个。
    head = ('<p>%s</p>' % badge) if badge else ""
    return ("<details class=\"rem\"><summary><span class=\"why\">"
            "为什么 &amp; 怎么办</span>"
            "<span class=\"t\">%s</span></summary>"
            "<div class=\"body\">%s%s</div></details>"
            % (_tx(a.get("title")), head, "".join(segs)))


#: 三类动作 → 按钮文案。★ B 类三选一必须**都在**页面上（创始人拍板）。
_PICK = {
    "fix": ("试一下，看能不能修好", "go"),
    "retry": ("重新拉起哨兵", "go"),
    "rearm": ("按正规入口重新布防", "go"),
    "drop": ("承认打不赢，移出监管", "drop"),
    # ★ 0.37.2：「就这样，我不处理」⇒「我不处理，我担着」——
    #   上面那条选项标题已经是「就这样放着，我自己盯着」，按钮再写"就这样"
    #   ⇒ 同一行两个"就这样"；且"我担着"点出这是**签字担责**（红按钮的本意）。
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
    if op in ("fix", "retry", "rearm"):
        return form("guard_fix")
    if op == "drop":
        return form("remediation_drop") + _form(
            token, "remediation_ack", it.id, note="我已知代价，先放着",
            label="先不处理，只记一笔", cls="risk")
    if op == "accept":
        return form("remediation_ack")
    return form("remediation_ack")


def _group_html(g, token, bucket=None, total=None):
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
    drill = ("<a class=\"btn\" href=\"/?v=inbox&f=kind:%s&t=%s\">看这 %d 条</a>"
             % (_esc(g["kind"]), _esc(token), n))
    if bucket == M.BUCKET_ACTION:
        # ★ 同一事由 ⇒ 一件事：给「一次性处置」，用户不必点开 13 次。
        acts = (_form(token, "done_all", label="知道了（全部 %d 条）" % n, ids=ids)
                + drill)
    else:
        acts = drill
    meta = " ｜ ".join(x for x in (
        (g.get("detail") or "").strip(),
        "最近 %s" % str(g["last_ts"])[:16],
        ("最早 %s" % str(g["first_ts"])[:16]) if n > 1 else "",
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
            rem = _rem_panel_only(first, token)
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
               _esc("×%d / %d 条" % (n, int(total or 0))),
               _esc(str(g["last_ts"])[5:16]),
               _vis(meta), rem, acts))


def _rem_panel_only(it, token):
    """只渲染归因面板本体（不给外层 `<details class="rem">` 的收起壳）。

    归并行已经有自己的收起壳（`details.item.grp`），再套一层会双层折叠。
    """
    full = _rem_html(it, token)
    if not full:
        return ""
    i = full.find("<div class=\"body\">")
    j = full.rfind("</div></details>")
    if i < 0 or j < 0:
        return ""
    return full[i:j].replace("<div class=\"body\">", "<div class=\"rem\">", 1)


def _view_inbox(items, token, filt, now=None):
    """收件箱。★ 三档（要处理 / 看一眼 / 归档），窗口默认 24 小时。

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

    def f(v, label, n, tip, unit):
        # ★ 0.37.2：四个数字**单位不同**（要处理＝件事，其余＝条记录），
        #   并排摆在一起却不说明，读者会拿 4 与 44、293 直接比大小 ——
        #   那是异质单位做比较（本项目 F54）。当时把单位只放 hover title。
        # ★★ 0.48.5（交接件 §5.4 丙1）：单位**可见化** —— hover 里的字
        #   鼠标不在上面就看不见，而并排比较恰恰发生在看见的那一刻。
        #   现在单位紧跟数字（`.unit` 小字弱化，不抢数字），口径归「？」词条。
        #   ★ 注意：这不是算错，是**单位异质被并排**（F54 同型，判据 U-08 守）。
        cls = " class=\"on\"" if v == filt else ""
        return ("<a href=\"/?v=inbox&f=%s&t=%s\"%s title=\"%s\">%s <b>%d</b>"
                "<span class=\"unit\">%s</span></a>"
                % (v, _esc(token), cls, _esc(tip), _esc(label), n, _esc(unit)))

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
            # ★ 0.35.3：页面上出现的**每个重要词都可点开看定义**。
            #   档位本身是链接（塞不进 details），级别徽章也没有落点 ⇒ 统一给
            #   **一个**折叠入口，而不是把定义平铺在页面上等人读完。
            # ★ 0.37.2：`light`（顶部这盏灯）放在**第一位** —— 它是页面上
            #   最需要先被读懂的那个词，只有在这里露面，用户才点得到。
            #   ★ 0.39.1：它的定义已按**来源分工**重写（状态只看此刻、事件只看账、
            #   **失守不回溯**）—— 判据 `ci/inbox_guards_0380.py` S17 钉死术语表，
            #   不得退回旧的"两个读数取最重"说法。
            # ★ 0.37.2：词表里**不再并列 `shield`** —— 护盾降为哨兵手里的工具，
            #   对用户的解释统一收在 `sentinel` 一条里（创始人 2026-10-09：
            #   「哨兵一个概念足矣」）。两个词条并排＝把工具说成了另一个角色。
            + GL.line(("light",) + GL.BUCKET_KEYS
                      + ("R0", "L2", "L1", "Ls", "granary", "L0", "sentinel"),
                      "页面上的词都是什么意思（点开看）"))
    rows = M.filter_items(items, filt, now=now)
    if not rows:
        return head + (
            "<div class=\"hint\"><b>当前读取到的记录里，没有要你处理的事。</b>"
            "<p class=\"note\">「要处理」只放只有你本人动手才能解决的事。"
            "Antinel 自己已拦下或自愈的事项在「看一眼」。更早的事项只会在其链文件仍被读取时显示在「归档」；"
            "本页不是永久全历史清单。</p></div>")
    # ★ 「要处理」按**事由**归并（同因 14 条 = 1 件事）；
    #   "看一眼/归档"按类型归并；只有「全部」和钻取视图才一张一条。
    #   ★ 单条的分组**退回普通条目**：不藏原因、不藏按钮（真回退的修法）。
    if filt == M.BUCKET_ACTION:
        groups = M.group_items(rows)
        by_id = {it.id: it for it in rows}
        parts = []
        for g in groups:
            if g["count"] == 1 and g["ids"] and g["ids"][0] in by_id:
                parts.append(_item_html(by_id[g["ids"][0]], token))
            else:
                parts.append(_group_html(g, token, bucket=M.BUCKET_ACTION,
                                         total=len(rows)))
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
        return (head
                # ★ 0.37.2 去重：「共 N 条」的 N 与筛选条上同一个 tab 的数字
                #   **逐字相同**（两者都是 `filter_items` 的条数）⇒ 同一屏
                #   出现两遍。筛选条是导航（随身可见），这里只留"怎么读这些行"。
                # ★ 0.48.5（交接件 §5.6 乙2）：「，点一类看单条」删 ——
                #   替用户描述他即将做的动作；链接本身可点（P12 钻取不删）。
                + ("<div class=\"note\" style=\"margin:0 0 10px\">"
                   "%s：按类型归并。"
                   "</div>" % _esc(M.filter_label(filt)))
                + "".join(_group_html(g, token, bucket=filt, total=len(rows))
                          for g in groups))
    if filt not in ("action", "all"):
        head += ("<div class=\"note\" style=\"margin:0 0 10px\">"
                 # ★ 0.47.0：筛选结果是分子 ⇒ 分母＝本次载入的全部条数。
                 "筛选：<b>%s</b> · %d / %d 条（<a href=\"/?v=inbox&f=all&t=%s\">"
                 "返回已载入记录</a>）"
                 "</div>" % (_esc(M.filter_label(filt)), len(rows), n_all,
                             _esc(token)))
    return head + "".join(_item_html(i, token) for i in rows)


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
        return ("<div class=\"metric\"><div class=\"k\">%s</div>"
                "<div class=\"v\" style=\"color:var(%s)\">"
                "<a href=\"/?v=inbox&f=%s&t=%s\">%d</a>"
                "<span class=\"den\"> / %d</span></div>"
                "</div>"
                % (GL.chip(k), var, _esc(scoped_filter), _esc(token), n, _win_total))

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
           "<a href=\"/?v=inbox&f=action&t=%s\">%d</a>"
           "<span class=\"den\"> / %d</span></div></div></div>"
         % (GL.chip("action"), _esc(token), rep.get("action_groups", 0),
            _win_total))

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
    _revived_link = ("<a href=\"/?v=inbox&f=win:%d:kind:host_shield_revived&t=%s\">"
                     "%d 次</a> / %d"
                     % (hrs, _esc(token), _revived, _win_total))
    _day = _esc(rep["day"])
    # ★ 0.47.0：当日三档各是分子 ⇒ 分母＝当日全部记录条数（当日 ＝ 24 小时窗口）。
    _day_total = sum(int(Lv.get(k, 0) or 0) for k in ("R0", "L2", "L1"))
    _today_levels = ("<a href=\"/?v=inbox&f=day:%s:lv:R0&t=%s\">失守 %d</a> ｜ "
                     "<a href=\"/?v=inbox&f=day:%s:lv:L2&t=%s\">拦截 %d</a> ｜ "
                     "<a href=\"/?v=inbox&f=day:%s:lv:L1&t=%s\">注意 %d</a>"
                     # ★ 0.48.5（交接件 §5.4 丙2）：「分母 N」改成直述「共 N 条」——
                     #   「分母」是术语词条里的词（口径行才是它的定义处），
                     #   正文里裸它是把术语当时尚词；意思一点没少。
                     " ｜ 共 %d 条"
                     % (_day, _esc(token), Lv["R0"], _day, _esc(token), Lv["L2"],
                        _day, _esc(token), Lv["L1"], _day_total))
    pr = ("<div class=\"card\"><div class=\"rows\">"
          "<div class=\"row\"><span class=\"k\">最近 %d 小时%s</span><span>%s</span></div>"
          "<div class=\"row\"><span class=\"k\">%s 当日合计</span><span>%s</span></div>"
          "</div></div>"
          % (hrs, GL.chip("sentinel", "哨兵被拉起过"), _revived_link,
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
        _day_total = sum(int(r["count"]) for r in rep["rules"])
        rows = "".join(
            "<div class=\"row\"><span class=\"k\">"
            "<a href=\"/?v=inbox&f=day:%s:rule:%s&t=%s\">%s</a></span>"
            "<span>%s</span></div>"
            % (_esc(rep["day"]), _esc(r["rule_id"]), _esc(token), _esc(r["rule_id"]),
               _esc(M.count_text(r["count"], _day_total, hours=24, unit="次")))
            for r in rep["rules"][:10])
        rules = ("<div class=\"card\"><h2>规则命中排行"
                 "</h2><div class=\"rows\">%s</div></div>" % rows)

    ch = rep["chain"]
    cls = {"ok": "ok", "broken": "bad", "unknown": "warn"}.get(ch["status"], "warn")
    if ch["status"] == "broken" and not ch.get("first_bad"):
        ch = dict(ch)
        ch["first_bad"] = "存在无法读取的链记录；当前未能定位具体文件/行"
    # ★ 0.37.2：词条不再传 `text=`（旧版传「记录有没有被改过」，而术语本名是
    #   「有没有被改过」⇒ 展开后正文开头又补一遍本名，读成
    #   「记录有没有被改过 有没有被改过：」，同一个意思叠两层）。
    # ★「被改过的地方 / 坏行 0 / 0」⇒ 拆成两行（旧版把一个标签对两个数）。
    chain = ("<div class=\"card\"><h2>%s（本日报能读取到的链文件）</h2><div class=\"rows\">"
             "<div class=\"row\"><span class=\"k\">校验结果</span><span class=\"%s\">%s</span></div>"
             "<div class=\"row\"><span class=\"k\">检查了几个文件 / 多少条记录</span><span>%d / %d</span></div>"
             "<div class=\"row\"><span class=\"k\">%s 被改过几处</span><span>%d</span></div>"
             "<div class=\"row\"><span class=\"k\">坏了几行</span><span>%d</span></div>"
             "<div class=\"row\"><span class=\"k\">%s</span><span>%d（本来就不参与比对）</span></div>%s%s</div></div>"
             % (GL.chip("chain_check"), cls, _esc(R.chain_status_label(ch["status"])),
                ch["files"], ch["records"],
                GL.chip("chain"), ch["broken"], ch.get("bad_lines", 0),
                GL.chip("unchained"), ch.get("unchained", 0),
                ("<div class=\"row\"><span class=\"k\">第一个问题出在哪</span><span>%s</span></div>"
                 % _esc(ch["first_bad"])) if ch.get("first_bad") else "",
                ("<div class=\"row\"><span class=\"k\">说明</span><span>%s</span></div>"
                 % _esc(ch["reason"])) if ch.get("reason") else ""))
    # ★ 0.36.1：时间范围只在**小节标题**里说一次（原来四张卡片各写一遍）。
    # ★ 0.37.1：页面名与 `<title>`/选项卡统一取 `PAGE_TITLES`（唯一真源）——
    #   旧版这里写「今日值守 · 日期」，而浏览器标签与选项卡都写「日报」，
    #   同一页三个名字（创始人问的"违和感"之一）。
    # ★ 0.37.2 精简：原句还带"点数字可以看是哪几条" —— 数字本身已可点（下划线），
    #   再写一遍就是**重复用户的动作**（同 W08 判据的立意）。只留窗口口径。
    return ("<h2>%s · %s</h2>"
            "<p class=\"note\">四个数都只数<b>最近 %d 小时</b>。</p>%s%s%s%s"
            % (PAGE_TITLES["report"], _esc(rep["day"]), hrs, m, pr, rules, chain))


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
    cls = {"ok": "ok", "broken": "bad", "unknown": "warn"}.get(ch["status"], "warn")
    _hrs = rep.get("window_hours", 24)
    _revived_count = rep.get("revived_window", 0)
    # ★ 0.47.0：拉起次数是分子 ⇒ 分母＝窗口内总记录数（与日报页同一口径）。
    _win_total_h = sum(int((rep.get("window_levels") or {}).get(k, 0) or 0)
                       for k in ("R0", "L2", "L1"))
    _revived_value = ("<a href=\"/?v=inbox&f=win:%d:kind:host_shield_revived&t=%s\">"
                      "%d 次</a> / %d"
                      % (_hrs, _esc(token), _revived_count, _win_total_h))
    # ★★ 0.37.2：**删掉本页第一行「此刻这一次」**（旧版 `GL.chip("posture",
    #   "此刻这一次")` + 值「值守中 —— 哨兵在岗…」）。
    #   顶部条已给出同一个状态词，并且 0.37.2 起把「此刻」与「24h 账」
    #   写在**同一句话**里（比本页这一行更全）。这里再给一次 ⇒
    #   同屏两个状态词、两种说法 —— 实测日报页正是这个形状，
    #   是创始人点名"违和感"的头号来源。
    #   ⇒ 状态词全站只有**顶部条**一处；本页只放顶部条没有的证据。
    # (标签, 值, 颜色样式, 值是否可信 HTML)
    # ★ 标签一律 trusted=True：`GL.chip()` 是我们自己生成的 HTML。
    rows = [
        (GL.chip("sentinel", "最近 %d 小时被拉起过" % _hrs),
         _revived_value, "warn" if _revived_count else "ok", True),
        # ★ 0.48.5（交接件 §5.4 丁2/丁3）：who 块从顶部条删除后，把它承诺的
        #   事实搬来本页作**证据**（口号变证据）—— 这句由 `_check_bind` 的
        #   硬校验背书：非回环地址 make_server 直接抛错，不是嘴上说回环。
        ("监听地址", "仅本机回环——服务不接受外部连接", "ok", False),
        (GL.chip("chain_check"),
         "%s（检查了 %d 个文件、%d 条记录，被改 %d）"
         # ★ 0.36.1：原先直接输出 `ch["status"]`，那是英文变量
         #   （ok / broken / unknown）—— 页面上冒出英文变量词。
         #   ⇒ 一律走 `chain_status_label()` 的中文。
         % (R.chain_status_label(ch["status"]), ch["files"],
            ch["records"], ch["broken"]), cls, False),
        (GL.chip("hook"), "本页没查这台电脑的实际安装情况", "neutral", False),
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
    return ("<h2>%s · %s</h2><div class=\"rows\">%s</div>"
            "<p class=\"note\">全绿不等于安全：也可能是检查压根没跑。</p>"
            % (PAGE_TITLES["health"], _esc(rep.get("day") or ""), body))


def _view_ledger(rep, token):
    led = rep["ledger"]
    has_data = bool(led.get("days", 0))
    values = ([led.get("streak_days", 0), led.get("blocked", 0),
               led.get("noticed", 0), led.get("breached", 0),
               led.get("acked", 0), led.get("days", 0)] if has_data else ["—"] * 6)
    m = ("<div class=\"metrics\">"
         "<div class=\"metric\"><div class=\"k\">%s</div><div class=\"v\">%s<small> 天</small></div></div>"
         "<div class=\"metric\"><div class=\"k\">%s</div><div class=\"v\">%s</div></div>"
         "<div class=\"metric\"><div class=\"k\">%s</div><div class=\"v\">%s</div></div>"
         "<div class=\"metric\"><div class=\"k\">%s</div><div class=\"v\">%s</div></div>"
         "<div class=\"metric\"><div class=\"k\">%s</div><div class=\"v\">%s</div></div>"
         "<div class=\"metric\"><div class=\"k\">%s</div><div class=\"v\">%s</div></div></div>"
         % (GL.chip("streak"), str(values[0]),
            GL.chip("ledger_blocked"), str(values[1]),
            GL.chip("ledger_noticed"), str(values[2]),
            GL.chip("ledger_breached"), str(values[3]),
            GL.chip("ledger_acked"), str(values[4]),
            GL.chip("days"), str(values[5])))
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
    warn = ("<p class=\"note\">账本尚无可核对记录；这表示还没有可统计的事件，"
            "不是确认累计为零。</p>" if not has_data else "")
    return ("<h2>%s · 本地摘要</h2>%s%s"
            "<div class=\"card\"><button class=\"btn\" disabled "
            "title=\"将来上线账号后才可用，现在没有这个能力\">"
            "认领到账号（未启用）</button></div>"
            % (GL.chip("ledger"), m, warn))


#: ★ 0.36.5 **页面名的唯一真源**（从 `render_page` 体内提为模块级）。
#:   为什么提上来：`inbox_window._mark_at_tail()` 要用同一份页面名来判
#:   「这个窗口标题是不是我们自己开的」—— 那份映射若留在函数体里，
#:   窗口侧就只能**再抄一遍**，抄出来的必然漂移（这已是本轮第二次同型事故：
#:   上一次是 `_matches_title` 的注释与实现相反）。
#:   ⇒ 唯一真源在这里，窗口侧 **import 它**，不二次实现。
PAGE_TITLES = {"inbox": "收件箱", "report": "日报", "health": "运行状态",
               "ledger": "账本"}


def render_page(view="inbox", filt=None, root=None, token="", items=None, rep=None,
                posture=None, now=None, record_ledger=False):
    """渲染整页。可注入 items/rep/posture（测试用）。

    ★★ 0.35.2 修（真缺陷，创始人 2026-10-06「点开像卡死」）：
      旧版**无条件**算 `daily_report()`，而日报里 `chain_health()` 会**逐条复算整条审计链**
      （本机实测 40101 条 ≈ 7.8s）。收件箱页（默认视图）**根本不用 rep**
      ⇒ 每次点开都白等 7.8s，四个视图实测各 7.7–9.6s。
      ⇒ 现在**只有真要用日报的视图**才算，收件箱页不再算。

    ★★ 0.35.3：视图名默认改 `action`（要处理），并且**每个视图都不再默认"全部历史"**。
    """
    items = S.load_items(root=root) if items is None else items
    # ★ 0.35.3：打开账本页时，用当前可读到的链记录刷新当日快照。
    #   旧版只有显式运行 `inbox daemon` 才写 ledger；正常打开 server 无人写，
    #   因而账本文件不存在、数字一直全零。写入委托给 daemon 唯一实现；只在
    #   用户打开账本页时采样，不让普通收件箱 GET 多做持久化。
    if record_ledger and view == "ledger":
        import inbox_daemon as _DM
        _DM.record_day(items=items, root=root)
    # ★ 非法/缺省筛选值 ⇒ 默认「要处理」（**不静默当成"全部"** —— 那会让用户以为
    #   自己看到的是筛选结果，其实是一整条历史）。
    if not filt or not M.known_filter(filt):
        filt = M.BUCKET_ACTION
    # ★★ 0.48.5（交接件 §5.5 W-01）：标题**恒用状态词**，与顶部条同一个词
    #   （`M.light_explain()` 是唯一实现 —— 标题与头部不许两种说法）。
    #   创始人原话：「标题该显示的是状态——那是 Alt-Tab / 任务栏里唯一
    #   不用开窗就能看到的一行，用户要的是『拦截/值守中/失守』，不是
    #   『收件箱』、更不是 #96a621」。页面名归选项卡 + h2（乙3 已补，
    #   零损失）；hash 只留在标题尾（认窗必需，正文零 hash 由 W-02 锁）。
    #   状态词取值必然落在 `host_shield.POSTURE_LABEL_ALLOWED` 内
    #   （`STATE_LABEL` ∪ ｢未启用｣ 是它的子集 —— W-01 判据逐词断言）
    #   ⇒ 窗口在任何可达灯态下都认得出、落位不失效。
    p = posture or posture_now()
    ex = M.light_explain(p, items, now=now, granary=M.granary_now())
    title = ex["label"]
    if view in ("report", "health", "ledger"):
        rep = (R.daily_report(root=root, items=items) if rep is None else rep)
        if view == "report":
            body = _view_report(rep, token, items)
        elif view == "health":
            body = _view_health(rep, token, items)
        else:
            body = _view_ledger(rep, token)
    else:
        body = _view_inbox(items, token, filt, now=now)
    return (_head(title, token)
            + _bar(items, token, posture=p, now=now, view=view, ex=ex)
            + _tabs(view, token)
            + "<main>" + body + "</main>" + _FLIP_JS + _READ_JS + "</body></html>")


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
                     "<p>如果你是从值守台页面点过来的，说明这个按钮的请求没带上访问口令 ——"
                     "那是程序缺陷，请把它报出来。</p>"
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
            q = parse_qs(urlparse(self.path).query)
            got = (q.get("t") or [""])[0] or (self.headers.get("X-Antinel-Token") or "")
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
            return True

        def _send(self, code, ctype, body, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
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
            if u.path in ("/", "/index.html"):
                view = (q.get("v") or ["inbox"])[0]
                filt = (q.get("f") or [M.BUCKET_ACTION])[0]
                if view not in ("inbox", "report", "health", "ledger"):
                    view = "inbox"
                # ★ 非法筛选值 ⇒ 退回默认档（**不静默当成"全部"** —— 那会让用户
                #   以为自己看到的是筛选结果，其实是一整条历史）。
                if not M.known_filter(filt):
                    filt = M.BUCKET_ACTION
                page = render_page(view=view, filt=filt, root=root, token=token,
                                   record_ledger=(view == "ledger"))
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
            try:
                if op == "fix":
                    # ★ 0.35.3：失守时就地修好（创始人第四条："应该有地方可以马上解决"）。
                    #   `guard_fix` 修不了会**如实说修不了**，不谎报。
                    import host_shield as _hs
                    _ok, _msg = _hs.guard_fix(_pkg_root())
                    print("[console] fix -> %s: %s" % (_ok, _msg))
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
            except M.InboxError as e:
                return self._send(409, "text/plain; charset=utf-8",
                                  ("操作被拒：%s" % e).encode("utf-8"))
            return self._send(303, "text/plain; charset=utf-8", b"",
                              extra={"Location": "/?t=%s" % token})

        def _json(self, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            return self._send(200, "application/json; charset=utf-8", body)

        def _asset(self, name):
            rel = ASSET_WHITELIST.get(os.path.basename(name))
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
      后果：两个值守台抢同一端口、**口令各不相同** ⇒ 开出来的窗口一半请求 403。
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
WINDOW_SIZE = "520,640"


def _app_window_cmd(url, geometry=None):
    """返回能开「**独立窗口**」的命令（app 模式：无地址栏/无标签页/无书签栏）；没有则 None。

    ★ 为什么必须 app 模式（0.35.2）：创始人 2026-10-06 明确要求
      「我希望值守台界面看上去是**一个独立的界面**」。
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
      ⇒ 现在**换掉那个前置条件**：加 `--user-data-dir` 让值守台成为
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
        # ── 0.36.4 根治第一步：值守台**自己的**浏览器 profile ──
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
         （实测本机 Edge 标题「收件箱 · 值守台 和另外 14 个页面…」）
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
      ⇒ 现在 `_app_window_cmd` 给了值守台**自己的 `--user-data-dir`**
        （实测 E1/E2/E4/E5：窗口**出生即正确**，Δ 全 0，且连开 3 次不退化），
        **落位从"关键路径"降级为"兜底复核"**：
          · `place_all` 先回读，**已对齐就一条 SetWindowPos 都不发**
            （`skip_if_placed=True`，默认开）⇒ 正常路径零移动、零误伤机会。
          · 只有"出生没对齐"才真的搬它，且搬完仍逐个回读校验。
      ⇒ **失败路径同时改掉**：重试耗尽**不再关窗**。
        理由（也是 0.36.3 那版的错处）：落位失败只说明"这次没搬成"，
        而那个窗口**就是值守台面板**、**完全正常**，主人正要看的正是它。
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
                #   宽泛模式（认任何值守台窗口）在这里是**危险的** ——
                #   它可能命中用户自己的浏览器窗口并把它搬走。
                hwnds = WIN.find_console_windows(suffix=suffix, run_id=run_id)
            except Exception as e:                           # noqa: BLE001
                last = "枚举窗口出错（%s）" % (type(e).__name__,)
                time.sleep(interval)
                continue
            if not hwnds:
                last = "还没看到带本次标识（%s）的值守台窗口" % (suffix,)
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
            print("[place] 值守台面板**仍在屏幕上**，没有被关掉"
                  "（它就是面板，由你决定关不关）。",
                  file=sys.stderr)
        return False

    if placer is not None:
        return run()                        # 判据路径：同步跑完，行为可确定
    th = threading.Thread(target=run, name="inbox-place", daemon=True)
    th.start()
    return True


def open_console(url, opener=None, placer=None, token=None, verbose=True):
    """把值守台打开成**一个独立窗口**（app 模式）；拿不到 app 浏览器就退回默认浏览器。

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
        「收件箱 · 值守台 和另外 14 个页面 - 个人 - Microsoft Edge」，
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
        `_app_window_cmd` 现在给值守台**自己的 `--user-data-dir`**
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
            # ── 步骤 1：收掉已开着的值守台窗口（旧的 / 上次运行的）──
            #   只关标题后缀匹配的，绝不误关用户窗口（见 close_console_windows）。
            #   这里用**通用后缀**（不带本次 run_id）⇒ 连"上次运行"的残留
            #   也一并收掉；那正是要清的对象。
            # ★★ 顺序很重要：**先收旧窗并等它们消失，再开新的**。
            #   `WM_CLOSE` 只是投信，浏览器何时销毁窗口不受我们控制；
            #   不等 ⇒ 那一刻屏幕上有两个「· 值守台」窗口，
            #   后续任何"取第一个"都可能抓到正在退场的旧窗口
            #   ⇒ 落位落到旧窗上（用户看到"修复没生效"）。
            if WIN is not None:
                try:
                    _n = WIN.close_console_windows()
                    if _n and verbose:
                        print("[open_console] 已收掉 %d 个上次的值守台窗口"
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
                              "继续开新窗（落位会覆盖全部匹配窗口）" % _left,
                              file=sys.stderr)
            # ── 步骤 3：开窗 ──
            if opener is not None:
                opener(cmd)
            else:
                subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 creationflags=_CREATE_NO_WINDOW)
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


#: 后台值守台的单例（守护进程「打开值守台」用；幂等复用，不重复绑端口）
_BG = {"httpd": None, "url": None}


def ensure_background(port=DEFAULT_PORT, root=None):
    """确保值守台在**后台**跑着。**幂等**：已经在跑就复用。返回 `(url, started)`。

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
    """停掉后台值守台（测试/退出用）。没在跑 ⇒ 返回 False。"""
    h = _BG.get("httpd")
    if h is None:
        return False
    try:
        h.shutdown()
    except Exception:                           # noqa: BLE001
        pass
    _BG["httpd"], _BG["url"] = None, None
    return True


# --------------------------------------------------- 值守台常驻（0.48.5 B1）----
#: ★★ 为什么要这一族（遗留问题清单 2026-10-13 B1，实测证据）：
#:   值守台服务原来是"代理会话里拉的前台进程"—— 会话结束就没了，托盘与守护
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
    """值守台"开在哪"的落盘位置（`<中枢>/console/url.json`）。"""
    import inbox_config as _C
    return os.path.join(_C.console_dir(root), "url.json")


def write_console_record(port, token, pid=None, root=None, started_at=None,
                         want_port=None):
    """把"值守台开在哪"落盘（临时文件 + 原子替换）。返回写下的 dict。

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
    if want_port is not None and int(want_port) != int(port):
        rec["want_port"] = int(want_port)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rec, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, p)
    return rec


def read_console_record(root=None):
    """读"值守台开在哪"。没有 / 读坏 / 缺端口或缺口令 ⇒ `None`（**不编默认值**）。"""
    try:
        with open(console_record_path(root), encoding="utf-8") as f:
            d = json.load(f)
    except Exception:                                   # noqa: BLE001
        return None
    if not isinstance(d, dict) or not d.get("port") or not d.get("token"):
        return None
    return d


def console_status(root=None, rec=None):
    """值守台此刻在不在。返回 `(alive, rec, why)` —— 守护进程与判据共用一处。

    ★ 判活**两条都要**：
      · 只看 pid ⇒ pid 会被复用（判活看的是"那个进程"，不是"那个号"）；
      · 只看端口 ⇒ 别的程序占了 8790 也会被当成"值守台在跑"。
    """
    rec = read_console_record(root) if rec is None else rec
    if not rec:
        return False, None, "还没有值守台的落盘记录（没起过）"
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
    """重拉值守台要跑的命令（**唯一实现**：守护进程与判据都看它，不各拼一份）。"""
    entry = os.path.join(os.path.dirname(os.path.abspath(__file__)), "antinel.py")
    cmd = [sys.executable, entry, "inbox", "serve",
           "--port", str(int(port)), "--token", str(token)]
    if root:
        cmd += ["--root", str(root)]
    return cmd


def spawn_console(port, token, root=None):
    """按给定端口/口令**另起一个进程**跑值守台（分离、无窗）。返回 `Popen`。"""
    flags = 0
    if os.name == "nt":
        flags = 0x00000008 | _CREATE_NO_WINDOW   # DETACHED_PROCESS | CREATE_NO_WINDOW
    return subprocess.Popen(_console_spawn_cmd(port, token, root),
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=flags)


def ensure_console(port=DEFAULT_PORT, root=None, spawner=None, wait_sec=8.0):
    """确保值守台在跑（**幂等**）。返回 `(rec|None, started: bool)`。

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
    _alive, rec2, _why2 = console_status(root)
    # ★ 起没起来都**如实返回**：拿不到记录就返回 None（不编一个"看起来好了"的）
    return (rec2 or rec), True


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
            print("!! 值守台落盘记录没写成（%r）—— 守护进程将无法判活/重拉" % (e,),
                  file=sys.stderr)
    return httpd, token, real_port, drift


def serve(port=DEFAULT_PORT, root=None, open_browser=False, token=None, record=True):
    """前台起服务（Ctrl+C 停）。★ 首选端口被占 ⇒ 自动换临时端口（Windows 上
    光靠 `OSError` 发现不了，见 `_port_busy`）。

    ★ 0.48.5（B1）：`token` 可传入（重拉时沿用旧口令，URL 不变）；
      `record=True` 把"开在哪"落盘（`url.json`）—— 守护进程靠它判活与重拉。
    ★ 0.48.5（B2）：被占时**不再静默** —— `_serve_setup()` 会把"换了端口"
      说到 stderr，并把 `want_port` 一并落盘。
    """
    httpd, token, real_port, _drift = _serve_setup(port, root, token=token,
                                                   record=record)
    url = "http://127.0.0.1:%d/?t=%s" % (real_port, token)
    print("值守台已开在：%s" % url)
    print("（只监听本机；关掉这个窗口就停）")
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
