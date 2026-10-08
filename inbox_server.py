# -*- coding: utf-8 -*-
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
import secrets
import subprocess
import sys
import threading
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
LEVEL_NAME = {"R0": "失守", "L2": "拦截", "L1": "注意", "Ls": "预算", "L0": "值守"}

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
.logo{width:46px;height:46px;border-radius:12px;overflow:hidden;background:#0a1a12;flex:none}
.logo video,.logo img{width:100%;height:100%;display:block;object-fit:cover}
.state b{font-size:17px}
.state span{font-size:12px;color:var(--muted)}
.pill{display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid var(--line)}
.dot{width:8px;height:8px;border-radius:50%}
.spacer{flex:1}
.who{font-size:12px;color:var(--muted);text-align:right}
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
.ok{color:var(--l0);font-weight:700}.warn{color:var(--l1);font-weight:700}.bad{color:var(--r0);font-weight:700}.neutral{color:var(--muted);font-weight:700}
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
.pill .unit{opacity:.6;font-size:11px;margin-left:4px}
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
                "why": "读不到门闸状态：%r" % (e,), "evidence": {},
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


def _tabs(view, token, counts):
    def a(v, label, n=None):
        cls = " class=\"on\"" if v == view else ""
        badge = " <b>%d</b>" % n if n else ""
        return "<a href=\"/?v=%s&t=%s\"%s>%s%s</a>" % (v, _esc(token), cls, label, badge)
    return ("<nav class=\"tabs\">" + a("inbox", "收件箱", counts.get("action", 0))
            + a("report", "日报") + a("health", "运行状态") + a("ledger", "账本")
            + "</nav>")


def _bar(items, token, posture=None, now=None):
    """顶部条。★★ 灯＝**当前态势**（现探），不是历史攒的（创始人 2026-10-06 拍板）。

    旧版把**所有未处理项**的最高级当灯色 ⇒ 8 天前一条已自愈的记录让今天永远红。
    创始人原话：「用户看到的都是失守状态，但又不是真正的事实，很快就没人用了，
    因为太假。」⇒ 现在：
      · 红 = 防线**此刻**确实不在岗（`host_shield.guard_posture()` 现探）
      · 未启用 = 灰（默认态，不是故障）
      · 值守中 = 绿；24 小时内有未处理的事 = 橙
      · 失守时**就地给一个「马上修复」按钮**（创始人第四条：应该有地方马上解决）
    右侧那排数字是**最近 24 小时**的（创始人第二条：窗口默认 24 小时）。
    """
    p = posture or posture_now()
    lg, _why = M.light(p.get("state"), items, now=now)
    state_title = _esc(M.LIGHT_LABEL[lg])
    state_reason = _esc(p.get("why") or "")
    if lg == M.LIGHT_ATTENTION:
        action_items = [it for it in items
                        if M.bucket_of(it, now=now) == M.BUCKET_ACTION]
        action_groups = M.count_groups(action_items)
        # ★ 用户看到「有事」必须能落到具体内容：同一判据 `bucket_of` 的件事数，
        #   并直接钻入「要处理」列表；否则不显示这类提示。
        state_title = ("<a href=\"/?v=inbox&amp;f=action&amp;t=%s\" "
                       "style=\"color:inherit;text-decoration:none\">%s（%d 件，点开查看）</a>"
                       % (_esc(token), _esc(M.LIGHT_LABEL[lg]), action_groups))
        state_reason = _esc(_why)
    wc = M.window_levels(items, now=now)
    # ★★ 0.35.3（创始人第四条 · 奥卡姆剃刀，本轮实测）：
    #   顶部原来只报「失守 69」这样的**记录条数**。实测本机 R0 共 80 条，
    #   但只有 **8 种不同原因**，其中最大一支 37 次（同一个钩子哈希不匹配被
    #   反复记录）⇒ 按事由归并只有 **4 件事**。
    #   用户看到 69 会以为"有 69 个问题待办"，实际只需要处理 4 件。
    #   ⇒ 三个数字**各自带上自己的事由件数**，口径写明；点进去仍是全部明细。
    #   这是 F40 的正面处理：不是把一个数藏起来，而是把**两个分母都摆出来**。
    _win = [it for it in items
            if M.within_hours(it.ts, M.WINDOW_HOURS, now)]

    def _grp(level):
        sel = [it for it in _win if it.level == level]
        return len(sel), M.count_groups(sel)
    n_l2, g_l2 = _grp("L2")
    n_l1, g_l1 = _grp("L1")
    n_r0, g_r0 = _grp("R0")

    def _pill(label, level, n, g):
        # 记录数 == 事由件数 时不重复写"=N 件事"，避免无意义的赘述
        same = (n == g)
        return ("<a href=\"/?v=inbox&f=win:%d:lv:%s&t=%s\">%s <b>%d</b>%s</a>"
                % (M.WINDOW_HOURS, level, _esc(token), label, n,
                   "" if same else "（%d 件事）" % g))

    nums = ("<span class=\"pill\">最近 %d 小时：%s · %s · %s"
            "<span class=\"unit\" title=\"括号里是按事由归并后的件数；"
            "点进去看的是全部明细记录\">（条数／括号内为件事数）</span></span>"
            % (M.WINDOW_HOURS,
               _pill("拦截", "L2", n_l2, g_l2),
               _pill("注意", "L1", n_l1, g_l1),
               _pill("失守", "R0", n_r0, g_r0)))
    fix = ""
    if p.get("can_fix"):
        fix = ("<form method=\"post\" action=\"/action\" style=\"margin:0\">"
               "<input type=hidden name=t value=\"%s\">"
               "<input type=hidden name=op value=\"fix\">"
               "<button class=\"fixbtn\">%s</button></form>"
               % (_esc(token), _esc(p.get("fix_hint") or "马上修复")))
    elif p.get("state") in ("down", "warn") and (p.get("fix_hint") or ""):
        # ★ 0.35.3（创始人第四条：「如果当前确实是失守状态，应该有地方可以马上解决」）：
        #   失守时**必须给得出下一步** —— 能就地修就给按钮；不能就地修，
        #   就把"去哪儿做"明确写在页面上。**绝不留一个点了没反应的按钮**。
        fix = ("<span class=\"fixnote\"><b>怎么解决：</b>%s</span>"
               % _esc(p.get("fix_hint")))
    # ★★ 0.35.3：**把"失守的损失"逐条摆出来**（创始人 2026-10-06：
    #   「如果真失守不会带来明显不利后果，那就跟假失守没啥区别」）。
    #   `_outage_consequences()` 产出的清单必须**有消费点**，否则就是本仓点名的
    #   「登记了却不会被查」的假守卫。说不出损失 ⇒ 根本不进这一档（在 host_shield
    #   里已降为「中断·无损失」）。
    cons = p.get("consequences") or []
    if cons:
        lis = "".join("<li>%s</li>" % _esc(c.get("text") if isinstance(c, dict) else c)
                      for c in cons)
        fix = ("<span class=\"cons\"><b>失守的损失（%d 条）：</b><ul>%s</ul></span>"
               % (len(cons), lis)) + fix
    return (
        "<header class=\"bar\">"
        "<div class=\"logo\"><video autoplay loop muted playsinline "
        "src=\"/assets/%s.mp4?t=%s\"></video></div>"
        "<div class=\"state\"><b>%s</b><br><span>%s</span></div>"
        "<span class=\"pill\"><span class=\"dot\" style=\"background:var(%s)\"></span>%s</span>"
        "%s%s<div class=\"spacer\"></div>"
        "<div class=\"who\">本机 · 127.0.0.1<br>数据不出门</div></header>"
        % (_esc(M.LIGHT_LOGO[lg]), _esc(token), state_title,
           state_reason, M.LIGHT_VAR[lg], _esc(p.get("label") or ""),
           nums, fix))


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
               _esc(it.level.lower()), _esc(it.level), dot, _esc(it.title),
               _esc(str(it.ts)[5:16]), _esc(meta), _rem_html(it, token), acts))


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

    badge = ('<span class="bclass">修不了根因 · 请选一条路</span>'
             if a.get("b_class") else "")
    txt = ("<span class=\"why\">这一条是靠记录文案认出来的</span>"
           if a.get("by_text") else "")

    segs = [
        '<div class="seg root"><h4>① 根因是什么</h4><p>%s</p>%s</div>'
        % (_esc(a.get("cause") or ""), txt),
        '<div class="seg sev"><h4>② 现在有多严重</h4><p>%s</p>'
        '<p class="note">%s</p></div>'
        % (_esc(a.get("severity") or ""), _esc(a.get("severity_note") or "")),
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
        why_html = ('<div class="why">%s</div>' % _esc(why)) if why else ""
        items_html.append(
            "<li><b>%s</b>%s%s"
            '<div class="pick">%s</div></li>'
            % (_esc(act.get("label") or op), cmd_html, why_html,
               _rem_pick_buttons(it, token, op, cls, act)))
    segs.append('<div class="seg act"><h4>③ 你现在能做什么</h4><ol>%s</ol></div>'
                % "".join(items_html))

    segs.append('<div class="seg cost"><h4>④ 如果什么都不做</h4><p>%s</p></div>'
                % _esc(a.get("cost") or ""))

    # ★ badge 放在**body 第一段**（不是 summary 里）——
    #   `_rem_panel_only()`给归并行复用时只取 body，badge 放summary 会被丢掉。
    #   实测踩过：归并行的三选一按钮都出来了，badge 却0 个。
    head = ('<p>%s</p>' % badge) if badge else ""
    return ("<details class=\"rem\"><summary><span class=\"why\">"
            "为什么 &amp; 怎么办</span>"
            "<span class=\"t\">%s</span></summary>"
            "<div class=\"body\">%s%s</div></details>"
            % (_esc(a.get("title") or ""), head, "".join(segs)))


#: 三类动作 → 按钮文案。★ B 类三选一必须**都在**页面上（创始人拍板）。
_PICK = {
    "fix": ("试一下，看能不能修好", "go"),
    "retry": ("重新拉起哨兵", "go"),
    "rearm": ("按正规入口重新布防", "go"),
    "drop": ("承认打不赢，移出监管", "drop"),
    "accept": ("就这样，我不处理", "risk"),
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


def _group_html(g, token, bucket=None):
    """一类/一事归并成一行。

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
            "<span class=\"pill sm\">×%d</span>"
            "<span class=\"when\">%s</span></summary>"
            "<div class=\"det\"><p class=\"m\">%s</p>%s"
            "<div class=\"act\">%s</div></div></details>"
            % (_esc(lv), _esc(ids), _esc(token), _esc(lv), _esc(g["level"]),
               _esc(g["title"]), n, _esc(str(g["last_ts"])[5:16]),
               _esc(meta), rem, acts))


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

    def f(v, label, n):
        cls = " class=\"on\"" if v == filt else ""
        return ("<a href=\"/?v=inbox&f=%s&t=%s\"%s>%s <b>%d</b></a>"
                % (v, _esc(token), cls, _esc(label), n))

    head = ("<div class=\"filters\">"
            + f(M.BUCKET_ACTION, "要处理", n_act)
            + f(M.BUCKET_INFO, "看一眼", b[M.BUCKET_INFO])
            + f(M.BUCKET_ARCHIVE, "归档", b[M.BUCKET_ARCHIVE])
            + f("all", "全部记录", n_all) + "</div>"
            # ★ 0.35.3：页面上出现的**每个重要词都可点开看定义**。
            #   档位本身是链接（塞不进 details），级别徽章也没有落点 ⇒ 统一给
            #   **一个**折叠入口，而不是把定义平铺在页面上等人读完。
            + GL.line(GL.BUCKET_KEYS + ("R0", "L2", "L1", "Ls", "L0",
                                        "shield", "sentinel"),
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
                parts.append(_group_html(g, token, bucket=M.BUCKET_ACTION))
        return (head
                + ("<div class=\"note\" style=\"margin:0 0 10px\">"
                   "要处理：<b>%d 件事</b>（共 %d 条记录，同一事由已归并；"
                   "每行都带原因，点开可一次处置或钻到单条）。"
                   "</div>" % (len(groups), len(rows)))
                + "".join(parts))
    if filt in (M.BUCKET_INFO, M.BUCKET_ARCHIVE):
        groups = M.group_by_kind(rows)
        return (head
                + ("<div class=\"note\" style=\"margin:0 0 10px\">"
                   "%s：共 <b>%d</b> 条，按类型归并（点一类看单条）。"
                   "</div>" % (_esc(M.filter_label(filt)), len(rows)))
                + "".join(_group_html(g, token, bucket=filt) for g in groups))
    if filt not in ("action", "all"):
        head += ("<div class=\"note\" style=\"margin:0 0 10px\">"
                 "筛选：<b>%s</b> · 共 %d 条（<a href=\"/?v=inbox&f=all&t=%s\">返回已载入记录</a>）"
                 "</div>" % (_esc(M.filter_label(filt)), len(rows), _esc(token)))
    return head + "".join(_item_html(i, token) for i in rows)


def _view_report(rep, token):
    """日报。★ 每个数字都可点钻取（创始人第四条意见："我却无法看到具体情况"）。"""
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
        return ("<div class=\"metric\"><div class=\"k\">%s</div>"
                "<div class=\"v\" style=\"color:var(%s)\">"
                "<a href=\"/?v=inbox&f=%s&t=%s\">%d</a></div>"
                "</div>"
                % (GL.chip(k), var, _esc(scoped_filter), _esc(token), n))

    m = ("<div class=\"metrics\">"
         + metric("L2", W.get("L2", 0), "--l2", "lv:L2")
         + metric("L1", W.get("L1", 0), "--l1", "lv:L1")
         + metric("R0", W.get("R0", 0), "--r0", "lv:R0")
         + "<div class=\"metric\"><div class=\"k\">%s</div><div class=\"v\">"
           "<a href=\"/?v=inbox&f=action&t=%s\">%d</a></div></div></div>"
         % (GL.chip("action"), _esc(token), rep.get("action_groups", 0)))

    p = rep.get("posture") or {}
    _cons = p.get("consequences") or []
    _cons_txt = ("；".join(str((c or {}).get("text") if isinstance(c, dict) else c)
                           for c in _cons)) if _cons else "（无）"
    _pcls = ("bad" if p.get("state") == "down" else
             ("warn" if p.get("state") in ("unknown", "warn", "interrupted") else
              ("neutral" if p.get("state") == "off" else "ok")))
    _revived = rep.get("revived_window", 0)
    _revived_link = ("<a href=\"/?v=inbox&f=win:%d:kind:host_shield_revived&t=%s\">%d 次（查看记录）</a>"
                     % (hrs, _esc(token), _revived))
    _day = _esc(rep["day"])
    _today_levels = ("<a href=\"/?v=inbox&f=day:%s:lv:L2&t=%s\">拦截 %d</a> ｜ "
                     "<a href=\"/?v=inbox&f=day:%s:lv:L1&t=%s\">注意 %d</a> ｜ "
                     "<a href=\"/?v=inbox&f=day:%s:lv:R0&t=%s\">失守 %d</a>"
                     % (_day, _esc(token), Lv["L2"], _day, _esc(token), Lv["L1"],
                        _day, _esc(token), Lv["R0"]))
    pr = ("<div class=\"card\"><h2>%s</h2><div class=\"rows\">"
          "<div class=\"row\"><span class=\"k\">现在</span><span class=\"%s\">%s</span></div>"
          "<div class=\"row\"><span class=\"k\">说明</span><span>%s</span></div>"
          "<div class=\"row\"><span class=\"k\">%s</span><span>%s</span></div>"
          "<div class=\"row\"><span class=\"k\">最近 %d 小时%s</span><span>%s"
          "（每次＝门闸中断过一小段）</span></div>"
          "<div class=\"row\"><span class=\"k\">%s 当日合计</span><span>%s</span></div>"
          "</div></div>"
          % (GL.chip("posture"), _pcls, _esc(p.get("label") or "查不到"),
             _esc(p.get("why") or ""), GL.chip("R0"), _esc(_cons_txt), hrs,
             GL.chip("sentinel", "哨兵被拉起"), _revived_link, _day, _today_levels))

    rules = ""
    if rep["rules"]:
        mx = max(r["count"] for r in rep["rules"]) or 1
        rows = "".join(
            "<div class=\"row\"><span class=\"k\">"
            "<a href=\"/?v=inbox&f=day:%s:rule:%s&t=%s\">%s</a></span>"
            "<span>%s %d</span></div>"
            % (_esc(rep["day"]), _esc(r["rule_id"]), _esc(token), _esc(r["rule_id"]),
               "█" * max(1, int(6 * r["count"] / mx)), r["count"])
            for r in rep["rules"][:10])
        rules = ("<div class=\"card\"><h2>规则命中排行"
                 "<span class=\"note\">（点规则名看具体是哪几条）</span></h2>"
                 "<div class=\"rows\">%s</div></div>" % rows)

    ch = rep["chain"]
    cls = {"ok": "ok", "broken": "bad", "unknown": "warn"}.get(ch["status"], "warn")
    if ch["status"] == "broken" and not ch.get("first_bad"):
        ch = dict(ch)
        ch["first_bad"] = "存在无法读取的链记录；当前未能定位具体文件/行"
    chain = ("<div class=\"card\"><h2>%s（本日报能读取到的链文件）</h2><div class=\"rows\">"
             "<div class=\"row\"><span class=\"k\">校验结果</span><span class=\"%s\">%s</span></div>"
             "<div class=\"row\"><span class=\"k\">检查了几个文件 / 多少条记录</span><span>%d / %d</span></div>"
             "<div class=\"row\"><span class=\"k\">%s / 坏行</span><span>%d / %d</span></div>"
             "<div class=\"row\"><span class=\"k\">%s</span><span>%d（本来就不参与比对）</span></div>%s%s</div></div>"
             % (GL.chip("chain_check"), cls, _esc(R.chain_status_label(ch["status"])),
                ch["files"], ch["records"],
                GL.chip("chain", "被改过的地方"), ch["broken"], ch.get("bad_lines", 0),
                GL.chip("unchained"), ch.get("unchained", 0),
                ("<div class=\"row\"><span class=\"k\">第一个问题出在哪</span><span>%s</span></div>"
                 % _esc(ch["first_bad"])) if ch.get("first_bad") else "",
                ("<div class=\"row\"><span class=\"k\">说明</span><span>%s</span></div>"
                 % _esc(ch["reason"])) if ch.get("reason") else ""))
    # ★ 0.36.1：时间范围只在**小节标题**里说一次（原来四张卡片各写一遍）。
    return ("<h2>今日值守 · %s</h2>"
            "<p class=\"note\">下面四个数字都只统计<b>最近 %d 小时</b>，"
            "点数字可以看具体是哪几条。</p>%s%s%s%s"
            % (_esc(rep["day"]), hrs, m, pr, rules, chain))


def _view_health(rep, token):
    """★ 0.36.1 文字修订：这一页原先把**已生成的 HTML 整段转义**，
    于是术语词条的 `<details>` 在用户屏幕上显示成一串标签文本
    （创始人 2026-10-07 截图一）。根因是白名单判定写成
    `k.startswith("<details")` —— 而「哨兵被拉起」那行的 key 是
    `"最近 %d 小时" + GL.chip(...)`，前面多了四个字 ⇒ 判定为假 ⇒ 整段被 `_esc`。
    ★ 教训：**「以标签开头」判不出「是不是我们生成的 HTML」** ——
      生成方与消费方隔了字符串拼接，白名单就必然漏。
      改成显式的 `trusted=True` 标记（我们自己产出的才放行）。
    """
    ch = rep["chain"]
    cls = {"ok": "ok", "broken": "bad", "unknown": "warn"}.get(ch["status"], "warn")
    p = rep.get("posture") or {}
    pcls = {"guarding": "ok", "down": "bad",
            "off": "neutral", "unknown": "warn", "warn": "warn",
            "interrupted": "warn"}.get(p.get("state"), "warn")
    _hrs = rep.get("window_hours", 24)
    _revived_count = rep.get("revived_window", 0)
    _revived_value = ("<a href=\"/?v=inbox&f=win:%d:kind:host_shield_revived&t=%s\">"
                      "%d 次</a>（点数字看每一次）"
                      % (_hrs, _esc(token), _revived_count))
    # (标签, 值, 颜色样式, 值是否可信 HTML)
    # ★ 标签一律 trusted=True：`GL.chip()` 是我们自己生成的 HTML。
    rows = [
        (GL.chip("posture"), "%s —— %s" % (p.get("label") or "查不到",
                                          p.get("why") or ""), pcls, False),
        (GL.chip("sentinel", "最近 %d 小时被拉起过" % _hrs),
         _revived_value, "warn" if _revived_count else "ok", True),
        (GL.chip("chain_check", "记录有没有被改过"),
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
    return ("<h2>值守是否真的在跑</h2><div class=\"rows\">%s</div>"
            "<p class=\"note\">「全绿」本身反而要当心：它分不清「真的没问题」"
            "和「检查本身没在跑」。所以这一页同时给两样东西 —— "
            "<b>活力证据</b>（判据自己有没有真的抓过）和<b>标本覆盖</b>"
            "（该抓的地方抓全了没有）。</p>"
            % body)


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
    state_note = ("账本尚无可核对记录；这表示还没有可统计的事件，不是确认累计为零。"
                  if not has_data else
                  "只统计本地审计链中的可核对事件；记录天数从本账本首次有事件起算。")
    # ★ 0.35.3：定义**只有一份**（`glossary`），页面不再自己抄一遍 —— 抄两份必漂。
    # ★ 规格 §5.6 明确要求两件此前缺失的东西：
    #   ①「这份账本在哪里」＋ 可导出/可迁移（一个文件，将来可认领合并）；
    #   ② 底部一个**禁用态**的「认领到账号（未启用）」—— 给将来留位，但现在不能点。
    #   缺了它，创始人看到的只是"一个只读数字页"，不知道这份账本能不能带走。
    return ("<h2>本机事件账本</h2>%s"
            "<p class=\"note\">%s</p>%s"
            # ★ 0.36.1：文件路径**收进可展开的细节**里。
            #   原先直接把 `~/.antinel/ledger/daily.jsonl` 摆在正文 ——
            #   对不懂技术的用户是纯噪音（"这跟我有什么关系"），
            #   而它其实只需要回答"存不存在、能不能带走"。
            #   路径本身对需要的人是重要的，所以保留在 `<details>` 里备查。
            "<div class=\"card\"><p class=\"note\">账本只存在<b>你这台电脑上</b>，"
            "不上传、不联网。它不是 AI 工具的积分余额，"
            "不可转让、不可兑换、不与拉人头挂钩、不承诺任何收益。</p>"
            "<p class=\"note\">这份账本在<b>这里</b>：上面每个数字都由本机的记录逐日算出，"
            "不带任何联网成分。它是<b>一个文件</b>，可以整体导出带走 —— "
            "将来若上线账号，可用它「认领合并」，而不是从零开始。"
            "（导出的也只是这份本地摘要，不是记录文件本身。）"
            "</p>"
            "<details class=\"where\"><summary>账本存在哪个文件里？（一般不用管）</summary>"
            "<div class=\"tdef\">你电脑上：<code>~/.antinel/ledger/daily.jsonl</code><br>"
            "换句话说，它在你自己的用户目录下，Antinel 只往这里写。"
            "这个文件可以自己打开看，也可以整个复制走。</div></details>"
            "</div>"
            "<div class=\"card\"><button class=\"btn\" disabled "
            "title=\"将来上线账号后才可用，现在没有这个能力\">认领到账号（未启用）</button>"
            "<p class=\"note\">现在不能点，也点不出错。将来上线账号后，"
            "这里会把上面这份本地账本合并进你的账号；在此之前它只属于这台电脑。"
            "</p></div>"
            % (m, _esc(state_note),
               GL.line(("ledger",), "「账本」到底记的是什么（点开看）")))


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
    title = PAGE_TITLES.get(view, PAGE_TITLES["inbox"])
    if view in ("report", "health", "ledger"):
        rep = (R.daily_report(root=root, items=items) if rep is None else rep)
        if view == "report":
            body = _view_report(rep, token)
        elif view == "health":
            body = _view_health(rep, token)
        else:
            body = _view_ledger(rep, token)
    else:
        body = _view_inbox(items, token, filt, now=now)
    tab_counts = M.counts_by_bucket(items, now=now)
    tab_counts[M.BUCKET_ACTION] = M.count_groups(
        [it for it in items if M.bucket_of(it, now=now) == M.BUCKET_ACTION])
    return (_head(title, token)
            + _bar(items, token, posture=posture, now=now)
            + _tabs(view, token, tab_counts)
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
                    _p = _hs.guard_posture()
                    _again = _hs.self_check()
                    if _ok:
                        print("[console] guard_fix -> 成功: %s" % _msg)
                        _note = "%s｜修完复测：%s（自检%s）" % (
                            _msg, _p.get("label") or "?",
                            "通过" if _again[0] else "不通过：" + "; ".join(_again[1]))
                    else:
                        # ★ 修不了**就把修不了的原因给回去**，不许只说"失败"
                        print("[console] guard_fix -> 失败: %s" % _msg)
                        # ★ 0.36.1：`<b>` 不是 `**` —— 页面是 HTML，
                        #   markdown 星号会原样显示给用户（创始人截图一）。
                        _note = "<b>没修好</b>：%s｜此刻仍是：%s" % (
                            _msg, _p.get("label") or "?")
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


def _bind_first_free(port, root):
    """按「首选端口 → 临时端口」的顺序绑一个能用的。返回 `(httpd, token, real_port)`。"""
    try:
        httpd, token = make_server(port=(0 if _port_busy(port) else port), root=root)
    except OSError:
        httpd, token = make_server(port=0, root=root)
    return httpd, token, httpd.server_address[1]


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
                                 creationflags=0x08000000 if os.name == "nt" else 0)
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
    httpd, token, real_port = _bind_first_free(port, root)
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


def serve(port=DEFAULT_PORT, root=None, open_browser=False):
    """前台起服务（Ctrl+C 停）。★ 首选端口被占 ⇒ 自动换临时端口（Windows 上
    光靠 `OSError` 发现不了，见 `_port_busy`）。"""
    httpd, token, real_port = _bind_first_free(port, root)
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
