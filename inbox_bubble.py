# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Antinel 监理 · 紧急提醒（0.49.0）：「需要人工介入马上处理」的通知窗。

★★ 起点（创始人 2026-10-14 夜间三条意见之一）：
  「以前默认的冒泡，会当时弹出来，还有声音。当出现需要人工介入马上处理的
    问题时，还是需要用到的，不过不能一闪而过，要有『确认』按钮，用户处理
    过了手工关掉最好；界面需要保持跟Antinel 监理一致，要有图标，让用户感觉是
    Antinel 监理的一部分。」

★ 为什么不是旧气泡（`ShowBalloonTip`）也不是现在的 WinRT Toast：
  · 旧气泡 15 秒就没 ⇒ **一闪而过**（急事被漏掉的那个老毛病）；
  · WinRT Toast 落操作中心，但**放不下「确认」按钮**，界面也由 Windows 画，
    与Antinel 监理两张皮。
  ⇒ 本模块用**Antinel 监理自己的 app 小窗**（Edge `--app`，与面板同一个浏览器
    profile、同一套 CSS、同一枚动效哨标）承载紧急提醒：置顶、不自动消失、
    带「知道了（去处理）」确认钮，点确认才关。**界面就是Antinel 监理的一部分。**

★ 三条纪律（与全仓同构）：
  ① **闸**：Antinel 监理窗口正开着（用户自己正看着）⇒ 不弹（0.36.8 立的
     `console_is_visible`，不变式 I4；宁可多弹不可漏报 ⇒ 判不出时照弹）。
  ② **节流只节门铃不节台账**：同类 `MIN_INTERVAL` 秒内不重复弹；
     用户确认过（`ack`）的同类 `ACK_QUIET_SEC` 秒内不再弹。
     收件箱照记（那条路归 `inbox_daemon`，与本模块无关）。
  ③ **如实**：起不来服务、找不到浏览器、窗口没就位 —— 全部原样写进
     返回 dict 的 `why`，不许有一步假装成功。
"""
from __future__ import annotations

import os
import subprocess
import time
from urllib.parse import urlencode

import inbox_config as C
import inbox_model as M

#: 紧急提醒触达的级别：**要你马上动手**的事。其余级别走 `inbox_notify`（toast）。
URGENT_LEVELS = ("R0", "L2")

#: 同类两次紧急提醒的最小间隔（秒）—— 与 `inbox_notify.MIN_INTERVAL` 同值同源。
MIN_INTERVAL = 1800
#: 用户「知道了」之后，同类多久不再提醒（秒）。
ACK_QUIET_SEC = 1800

#: 事由正文最大长度（URL 里带着它，别把查询串撑爆；截断处加省略号）。
BODY_MAX = 220


# ---------------------------------------------------------------- 声音 ----
def sound_path(root=None):
    """提示音文件（构建期产物，`tools/mk_sound.py` 生成）。"""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "assets", "sounds", "alert.wav")


def play_sound(root=None):
    """响一声。返回 `(响了没, 用的什么)` —— 失败不静默。

    ★ 非 Windows（无 `winsound`）⇒ 返回 `(False, 原因)`，**不模拟**。
    ★ 自建铃声缺失 ⇒ 退回系统提示音（`MessageBeep`），并如实说退了。
    """
    if os.name != "nt":
        return False, "非 Windows，没有提示音通道"
    try:
        import winsound
    except Exception as e:                                  # noqa: BLE001
        return False, "本机没有 winsound：%s" % e
    p = sound_path(root)
    try:
        if os.path.isfile(p):
            winsound.PlaySound(p, getattr(winsound, "SND_FILENAME", 0)
                               | getattr(winsound, "SND_ASYNC", 0))
            return True, "自建提示音"
        winsound.MessageBeep(getattr(winsound, "MB_ICONASTERISK", 0x40))
        return True, "系统提示音（自建铃声缺失，如实退回）"
    except Exception as e:                                  # noqa: BLE001
        return False, "播放失败：%s: %s" % (type(e).__name__, e)


# ---------------------------------------------------------------- 页面 ----
def _url(base, title, body, level, state, kind):
    """紧急提醒页 URL（事由走 query —— 一次性渲染，不进任何历史）。"""
    q = urlencode({"v": "bubble", "bt": title, "bb": body,
                   "bl": level, "bs": state, "bk": kind})
    sep = "&" if "?" in base else "?"
    return base + sep + q


def render(title, body, level, token, run_id="", kind="R0", console_open=False):
    """紧急提醒页 HTML：**Antinel 监理同一套 CSS ＋ 同一枚动效哨标**（ founder 要求）。

    `console_open`：渲染这一刻Antinel 监理**已经开着**（`host_shield.console_is_visible()`
      的当场读数）⇒ **不画**「打开Antinel 监理」按钮，改画一句"它开着"的状态。
      ★ 为什么不画（创始人 2026-10-14：「点完了按钮显示'打开值守台'按钮好像
        不对吧，Antinel 监理打开着呢」）：按钮上的字是一个**承诺**（"点了我给你打开"），
        而它已经开着 ⇒ 那个承诺不成立；且旧链路上点它会**关掉旧窗再开新窗**
        （见 `inbox_server` 的 `bubble_open` 分支），用户看到的是"窗闪了一下、
        内容从头来"。⇒ 如实说"开着"，并把它**切到前面**。
    """
    import inbox_server as SV
    import inbox_window as _WIN
    st = level if level in M.STATE_VAR else "R0"
    # ★ 0.50.6（T-09 收编）：标题只从 `inbox_window` **派生**，不在此硬编码第二份。
    # ★★ 0.53.0 T3（创始人 2026-10-19）：「标题栏修成跟监理同样格式 ——
    #   Antinel 监理（编号）点 紧急提醒」。整串由 `bubble_title()` 生成
    #   （品牌段与监理窗同一真源），这里不再自己拼「事由 + 标记 + #编号」。
    full_title = _WIN.bubble_title(run_id)
    body_txt = str(body or "")[:BODY_MAX] + ("…" if len(str(body or "")) > BODY_MAX
                                              else "")
    css = SV.CSS + """
/* ---- 0.49.0 紧急提醒窗（与Antinel 监理同源：同一份 CSS，只加紧急提醒自己的几行）---- */
/* ★★★ 0.50.1（创始人截图一「泡泡下沿没露出来」）：
   `height:100%` 把文档钉死在视口高度上 ⇒ 内容超出时只能被**裁掉**，
   而且页面**量不出**自己缺多少。改 `min-height` ⇒ 内容能撑开文档，
   `scrollHeight - clientHeight` 才是个真读数（`bubblefit` 靠它）。 */
html,body{min-height:100%}
body.bubpage{margin:0;background:var(--bg)}
.bub{display:flex;gap:12px;padding:14px 15px 12px;align-items:flex-start;
     box-sizing:border-box;min-height:100%}
.bub .logo{width:44px;height:44px;border-radius:11px;flex:none}
.bub-main{flex:1;min-width:0}
.bub-head{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.bub-title{font-weight:700;font-size:13.5px;line-height:1.4}
/* ★ 0.50.1：正文按 3 行截断，但**显式给省略号**。旧版是
   `max-height:52px;overflow:hidden` ⇒ 字被**硬切**在半个字上
   （创始人截图一里「知道了（去处理）」那句就是被切掉的）。
   截断可以，但必须看得出来"还有" —— 不许把事藏起来（W08 立意）。 */
.bub-body{margin:5px 0 9px;font-size:12.5px;line-height:1.6;color:var(--fg);
  display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
/* ★ 0.50.1：三个元素都不许折行。旧版一窄就把「打开Antinel 监理」折成
   「打开值 / 守台」（创始人截图二），按钮折行整行就垮了；
   放不下应该换行（flex-wrap），不该拆字。 */
.bub-act{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.bub-ok{border:1px solid var(--r0);background:var(--r0);color:#fff;
        border-radius:8px;padding:6px 13px;font-weight:700;font-size:12.5px;
        cursor:pointer;white-space:nowrap}
.bub-open{border:1px solid var(--line);background:transparent;color:var(--brand);
          border-radius:8px;padding:6px 12px;font-size:12.5px;cursor:pointer;
          white-space:nowrap}
.bub-note{font-size:11px;color:var(--muted);margin-left:auto;white-space:nowrap}
/* ★★★ 0.50.1（创始人截图二「点了按钮之后就这样不动了」）：
   确认之后**不该再是一个按钮**。旧版把确认钮的 textContent 换成 20+ 字长句、
   又留着 `disabled` ⇒ 得到"灰色虚线边框、里面塞四行小字、点不动"的东西
   —— 那既像坏了，又让人以为还能点。确认是**一次性动作**，做完就该
   **退场换状态**：按钮消失，留一行状态文字（并且状态色不用危险红）。 */
.bub-done{font-size:12px;color:var(--brand);font-weight:600}
/* ★ 0.50.3：Antinel 监理**已经开着**时，那个位置不再是按钮，而是一句状态 ——
   按钮上写着"打开"，而它本来就开着 ⇒ 那是一个**不成立的承诺**
   （创始人 2026-10-14 截图二）。样式与 `.bub-done` 同族（状态色，不用危险红）。 */
.bub-has{font-size:12px;color:var(--brand);font-weight:600;white-space:nowrap}
"""
    js = """
<script>
(function(){
"use strict";
function post(op, extra, done){
  var body = "op=" + op + "&t=" + encodeURIComponent(document.body.dataset.tok || "");
  if (extra) { body += "&" + extra; }
  fetch("/action", {method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:body})
    .then(function(r){ return r.json(); })
    .then(function(j){ done(j); })
    .catch(function(){ done(null); });
}
/* ★★★ 0.50.1（创始人截图一「泡泡下沿没露出来」）：把"还差多少高度"量出来
   上报给服务端，由服务端**按内容把窗口长高**（下沿不动、往上长、回读校验）。
   为什么必须这么绕：窗口矩形是浏览器在管，页面改不了自己窗口的大小；
   而 `place_all` 只保证"窗落在目标矩形上"，**不知道内容有没有被裁掉**
   —— 148 高时落位回读是**一致**的，可下沿照样看不见。
   `asked` 记住上次报过的量，防止"长高 → 再量 → 再长"来回打转。 */
var asked = -1;
function fit(){
  var d = document.documentElement;
  var need = Math.max(d.scrollHeight, document.body.scrollHeight) - d.clientHeight;
  if (need <= 1 || Math.abs(need - asked) < 2) { return; }
  asked = need;
  post("bubblefit", "dh=" + need, function(j){
    if (j && j.ok) { setTimeout(fit, 120); }
  });
}
window.addEventListener("load", function(){ setTimeout(fit, 60); });
var ok = document.querySelector(".bub-ok");
ok.addEventListener("click", function(){
  ok.disabled = true;
  post("bubble_ack",
       "kind=" + encodeURIComponent(document.body.dataset.kind || "R0"),
       function(j){
    if (!j || !j.ok) {
      ok.disabled = false;
      ok.textContent = "没记上：" + ((j && j.why) || "未知原因") + "—— 再点一次";
      setTimeout(fit, 30);
      return;
    }
    /* 不替用户标记「已处理」，也不自动关窗：确认≠处理，处理完由用户手动关。
       ★★ 但**按钮要退场**（见 `.bub-done` 的注释）：换一行状态文字，
       不留一个"点不动的按钮"（那正是创始人截图二看到的形状）。
       ★ 0.50.6（STE）：状态行 28 字缩到 22 字 —— 三个事实一个不少：
       「已确认」（知悉）、「还没标记处理」（≠已处理）、
       「点右上角 × 关」（手工关）。判据 B-03 锚点同步（逐字串替换）。 */
    var s = document.createElement("span");
    s.className = "bub-done";
    s.textContent = "已确认，还没标记处理 · 处理后点右上角 × 关";
    ok.replaceWith(s);
    setTimeout(fit, 30);
  });
});
var op = document.querySelector(".bub-open");
/* ★ 0.53.0 T3（创始人 2026-10-19 截图）：小窗弹出之后，用户可能自己把监理
   拉起来了 —— 那一刻起，按钮上的"打开"就成了不成立的承诺（而服务端只在
   渲染时判过一次）。⇒ 页面自己复查：加载后、窗口获得焦点时、以及每 10 秒，
   问一次 `bubble_vis`（只读，不抢占焦点、不动窗口）。
   判不出来（null）⇒ 什么都不做，按钮留着（宁可多一个入口，不许点了没反应）。
   按钮一旦撤掉，下一次复查在第一行就返回 ⇒ 轮询自动停。 */
function syncOpen(){
  var b = document.querySelector(".bub-open");
  if (!b) { return; }
  post("bubble_vis", "", function(j){
    if (!j || j.vis !== true) { return; }
    var s = document.createElement("span");
    s.className = "bub-has";
    s.textContent = "Antinel 监理开着（在那边看）";
    var cur = document.querySelector(".bub-open");
    if (cur) { cur.replaceWith(s); setTimeout(fit, 30); }
  });
}
window.addEventListener("load", function(){ setTimeout(syncOpen, 80); });
window.addEventListener("focus", syncOpen);
setInterval(syncOpen, 10000);
/* ★ 0.50.3：`console_open` 为真时服务端**根本不画**这个按钮 ⇒ 这里必须容忍 null
   （旧版直接 `op.addEventListener` ⇒ 没按钮时整段 JS 抛错，
   连带把上面的 `fit()` 与"知道了"那条链一起打死）。 */
if (op) {
op.addEventListener("click", function(){
  op.disabled = true;
  post("bubble_open", "", function(j){
    /* ★★★ 0.50.3（创始人 2026-10-14：「点击打开值守台后，之前的关闭了，
       打开了新的……点完了按钮显示'打开Antinel 监理'按钮好像不对吧，Antinel 监理打开着呢」）：
       服务端先问「用户此刻真的看得见Antinel 监理吗」——
         · 看得见 ⇒ 只把它**切到前面**（`opened === "existing"`），
           一个窗口都不关、不重建 ⇒ 按钮**退场**换一句状态
           （与"知道了"那条同一形状：一次性动作做完就退场，不留一个
            点不动的按钮 —— 那正是创始人截图二看到的东西）；
         · 没开着 ⇒ 才走"开一个新窗"（`app`/`browser`），文案照旧。 */
    var st = j && j.opened;
    if (st === "existing") {
      var s = document.createElement("span");
      s.className = "bub-has";
      s.textContent = j.ok ? "Antinel 监理开着（已切到它）"
                           : "Antinel 监理开着，但没能切到前面：" + (j.why || "请手动找窗口");
      op.replaceWith(s);
      setTimeout(fit, 30);
      return;
    }
    if (st === "app" || st === "browser") {
      op.textContent = j.ok ? "Antinel 监理已打开" :
        "Antinel 监理已打开，定位未完成：" + (j.why || "请手动找窗口");
      return;
    }
    op.disabled = false;
    op.textContent = "没打开：" + ((j && j.why) || "未知");
    setTimeout(fit, 30);
  });
});
}
})();
</script>
"""
    # ★ 0.50.3：Antinel 监理开着 ⇒ 那个位置不画按钮，改一句状态（见 docstring）。
    #   ★★ 0.50.4 命名变更注记（D4，创始人 2026-10-15 签发）：「值守台」在用户
    #      可见面退休 ⇒ 按钮「打开值守台」→「**打开 Antinel 监理**」、状态句
    #      同步换词；同一份 JS 模板里 CSS/JS **注释**中的旧名是当时的决策记录，
    #      按「记录原文不改写」保留。新文案长 4 字 ⇒ 气泡三元素不折行已列
    #      真机复核（0.50.1 案）。
    act_open = ("<span class=\"bub-has\">Antinel 监理开着（在那边看）</span>"
                if console_open else
                "<button class=\"bub-open\" type=\"button\">打开 Antinel 监理</button>")
    # ★ 0.53.0 T3：图标与监理**同一枚**（同一 favicon 链接）。没有它，app 窗
    #   标题栏只能显示浏览器默认的网格球（创始人截图里就是那个球）——
    #   两扇窗一个圆环一个球，读者会以为是两个产品。
    return (
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>%s</title>%s<style>%s</style></head>"
        "<body class=\"bubpage\" data-tok=\"%s\" data-kind=\"%s\">"
        "<div class=\"bub\">"
        "<div class=\"logo\">%s</div>"
        "<div class=\"bub-main\">"
        "<div class=\"bub-head\"><b style=\"color:var(%s)\">%s</b>"
        "<span class=\"bub-title\">%s</span></div>"
        "<div class=\"bub-body\">%s</div>"
        "<div class=\"bub-act\">"
        "<button class=\"bub-ok\" type=\"button\">知道了</button>"
        "%s"
        # ★ 0.50.5（B-2/B-3 文字品质）：两处改的都是「说给用户听的利益」，
        #   不是「讲我们怎么实现的机制」。
        #   ① 「知道了（去处理）」→「知道了」：括号把**两件事**绑成一个动作，
        #      而代码立场明确是「确认 ≠ 处理」（bubble_ack 不代用户标已处理）
        #      ⇒ 原按钮文案与代码立场相反。确认态里的「还没标记处理 /
        #      点右上角 × 关」已经把后一步说清了。
        #   ② 「不自动消失 · 处理完手工关」→「会一直留着，直到你处理完」：
        #      前半句在讲机制，后半句「手工关」是口语；改后直接说用户利益。
        "<span class=\"bub-note\">会一直留着，直到你处理完</span>"
        "</div></div></div>%s%s</body></html>"
        % (SV._esc(full_title), SV.FAVICON_LINK, css, SV._esc(token),
           SV._esc(kind), SV._logo_mark(st), M.STATE_VAR[st],
           SV._esc(M.state_label(st)), SV._esc(title), SV._esc(body_txt),
           act_open, SV._LOGO_JS, js))


# ---------------------------------------------------------------- 紧急提醒 ----
def _throttled(kind, root, now):
    """同类是否在静默期（刚弹过 / 用户刚确认过）。返回 `(该不该跳过, 原因)`。"""
    import inbox_notify as NT
    th = NT.throttle_state(root) or {}
    last = th.get("bubble:" + str(kind))
    if isinstance(last, (int, float)) and now - last < MIN_INTERVAL:
        return True, "同类 %d 秒内已提醒过（门铃节流，台账照记）" % MIN_INTERVAL
    acked = th.get("bubble-ack:" + str(kind))
    if isinstance(acked, (int, float)) and now - acked < ACK_QUIET_SEC:
        return True, "你 %d 秒前确认过同类，先不打扰" % ACK_QUIET_SEC
    return False, ""


def pop(title, body, level="R0", state=None, root=None, kind=None, force=False,
        now=None, sound=True, port=None, opener=None, verbose=True, cfg=None,
        console=None):
    """弹一枚紧急提醒。返回 dict **如实报告**（`ok` 只在窗口真就位时为 True）。

    ★ 闸（不变式 I4）：Antinel 监理窗口正开着 ⇒ 不弹（用户自己正看着，
      再弹就是「右下角又冒小泡泡」那个老毛病）。
    ★ 一次只留一枚：先收旧的，再开新的（不许叠成一串）。
    ★ `opener` 可注入：判据不起真浏览器也能验这条链。
    ★ `bubbler` 之外的第二个注入点是 `cfg`：`bubble=false` 时一声不响。
    """
    rep = {"ok": False, "opened": "none", "placed": False, "topmost": False,
           "sound": False, "why": "", "closed_old": 0}
    now = time.time() if now is None else float(now)
    kind = kind or level
    if level not in URGENT_LEVELS:
        rep["why"] = "级别 %s 不走紧急提醒（紧急提醒只给 %s）" % (level, "/".join(URGENT_LEVELS))
        return rep
    on, _why = cfg_bubble_on(cfg, root)
    if not on:
        rep["why"] = _why
        return rep

    # ① 闸：用户正开着面板 ⇒ 不打扰（判不出 ⇒ 照弹，宁可多弹不可漏报）
    if not force:
        try:
            import host_shield as HS
            vis = HS.console_is_visible()
        except Exception as e:                              # noqa: BLE001
            vis = None
        if vis is True:
            rep["why"] = "Antinel 监理窗口正开着，不重复打扰（面板里能看见）"
            return rep
        if vis is None and not force:
            rep["why"] = "（探不到面板可见性，按「宁可多弹」继续）"

    # ② 节流（同类刚弹过 / 刚确认过）
    skip, why = _throttled(kind, root, now)
    if skip:
        rep["why"] = why
        return rep

    # ③ 承载页面 = Antinel 监理服务 ⇒ 先确保它在跑（沿用守护进程那套幂等）。
    #   ★ `console` 是第二个注入点：判据要能在**不绑端口、不起进程**的
    #     前提下验「服务起不来 ⇒ 如实说发不出」这条路。
    import inbox_server as SV
    _ensure = console or SV.ensure_console
    rec, _started = _ensure(port if port is not None else SV.DEFAULT_PORT, root)
    if not rec:
        rep["why"] = "Antinel 监理服务起不来，紧急提醒没有承载页面（急事仍在收件箱里）"
        return rep
    base = rec.get("url") or ""
    if not base:
        rep["why"] = "Antinel 监理记录里没有 URL，紧急提醒发不出去"
        return rep

    # ④ 一次只留一枚：收旧窗
    import inbox_window as WIN
    try:
        n_closed, _why = WIN.close_bubble_windows()
        rep["closed_old"] = int(n_closed)
    except Exception as e:                                  # noqa: BLE001
        rep["why"] = "收旧窗失败：%s: %s" % (type(e).__name__, e)

    # ⑤ 开窗 + 等它就位 + 置顶
    url = _url(base, str(title), str(body), level, state or level, str(kind))
    try:
        rid = WIN.build_run_id(rec.get("token"))
    except Exception as e:                                  # noqa: BLE001
        rep["why"] = "算不出紧急提醒窗口身份：%s: %s" % (type(e).__name__, e)
        return rep
    if opener is not None:
        rep.update(opener(url) or {})
        rep["ok"] = bool(rep.get("placed"))
    else:
        rep.update(SV.open_bubble_window(url, token=rec.get("token")))
        rep["ok"] = bool(rep.get("placed") and rep.get("opened") == "app")

    # ⑥ 声音（响了才算响；失败如实记，不假装）
    if sound:
        _ok, _how = play_sound(root)
        rep["sound"] = bool(_ok)
        if not _ok:
            rep["why"] = (rep["why"] + "；" if rep["why"] else "") + "没响：" + _how

    # ⑦ 记账（门铃节流；台账不节 —— 收件箱照记，归守护进程）
    try:
        import inbox_notify as NT
        NT.throttle_set("bubble:" + str(kind), root=root, now=now)
    except Exception as e:                                  # noqa: BLE001
        rep["why"] = (rep["why"] + "；" if rep["why"] else "") + "节流记账失败：%s" % e
    if verbose:
        print("[bubble] %s -> ok=%s %s" % (str(title)[:40], rep["ok"],
                                           rep["why"]))
    return rep


def ack(kind=None, root=None, now=None):
    """用户点了「知道了」：记下确认时间，同类 `ACK_QUIET_SEC` 秒内不再冒。"""
    import inbox_notify as NT
    now = time.time() if now is None else float(now)
    k = "bubble-ack:" + str(kind or "R0")
    try:
        NT.throttle_set(k, root=root, now=now)
        return True, "已记录确认（%s）" % k
    except Exception as e:                                  # noqa: BLE001
        return False, "确认没记上：%s: %s" % (type(e).__name__, e)


def cfg_bubble_on(cfg=None, root=None):
    """配置开关（默认开：创始人要它回来）。返回 `(开不开, 原因)`。"""
    cfg = cfg if cfg is not None else C.load(root)
    if not bool(cfg.get("bubble", True)):
        return False, "配置里关掉了紧急提醒（bubble=false）"
    return True, ""
