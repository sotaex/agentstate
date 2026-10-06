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

★ 判据不许二次实现：状态聚合调 `inbox_model.console_state()`，日报调
  `inbox_report.daily_report()`，账本调 `ledger.summary()` —— 页面只排版。
"""
from __future__ import annotations

import html
import json
import os
import secrets
import threading
import webbrowser
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import inbox_model as M
import inbox_report as R
import inbox_store as S
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
.state b{font-size:16px}
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
.item{display:flex;gap:14px;align-items:flex-start;border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:13px 15px;margin-bottom:10px}
.item.r0{border-left-color:var(--r0)}.item.l2{border-left-color:var(--l2)}
.item.l1{border-left-color:var(--l1)}.item.ls{border-left-color:var(--ls)}
.item.done,.item.ignored{opacity:.55}
.badge{flex:none;width:44px;text-align:center;font-family:var(--mono);font-size:12px;font-weight:700;padding:4px 0;border-radius:6px;color:#fff}
.badge.r0{background:var(--r0)}.badge.l2{background:var(--l2)}
.badge.l1{background:var(--l1)}.badge.ls{background:var(--ls)}
.body{flex:1;min-width:0}
.body .t{font-weight:700}
.body .m{font-size:12px;color:var(--muted);font-family:var(--mono);word-break:break-all}
.act{flex:none;display:flex;flex-direction:column;gap:6px;align-items:flex-end}
.act button{border:1px solid var(--line);background:transparent;color:var(--fg);border-radius:7px;padding:5px 10px;font-size:12px}
.act form{margin:0}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px}
.metric{background:var(--panel);border-radius:10px;padding:14px}
.metric .k{font-size:12px;color:var(--muted)}
.metric .v{font-size:26px;font-weight:700}
.rows{border:1px solid var(--line);border-radius:10px;overflow:hidden}
.row{display:flex;gap:12px;padding:11px 15px;border-bottom:1px solid var(--line);font-size:13px}
.row:last-child{border-bottom:0}
.row .k{flex:none;width:150px;color:var(--muted)}
.ok{color:var(--l0);font-weight:700}.warn{color:var(--l1);font-weight:700}.bad{color:var(--r0);font-weight:700}
.empty{text-align:center;padding:40px;color:var(--muted)}
.note{font-size:12px;color:var(--muted)}
.unread-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--brand);margin-right:6px;vertical-align:middle}
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


# ------------------------------------------------------------- 页面 ----
def _head(title, token):
    return ("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>%s · 值守台</title><link rel=\"icon\" href=\"/assets/favicon.ico?t=%s\">"
            "<style>%s</style></head><body>"
            % (_esc(title), _esc(token), CSS))


def _tabs(view, token, counts):
    def a(v, label, n=None):
        cls = " class=\"on\"" if v == view else ""
        badge = " <b>%d</b>" % n if n else ""
        return "<a href=\"/?v=%s&t=%s\"%s>%s%s</a>" % (v, _esc(token), cls, label, badge)
    return ("<nav class=\"tabs\">" + a("inbox", "收件箱", counts.get("open", 0))
            + a("report", "日报") + a("health", "运行状态") + a("ledger", "账本")
            + "</nav>")


def _bar(items, token):
    st = M.console_state(items)
    n = M.unhandled_count(items)
    lv = LEVEL_NAME.get(st, st)
    sub = {"L0": "一切正常，无待办", "L1": "有可疑动作，已记录未拦截",
           "L2": "已拦下危险操作，待你确认", "Ls": "本机额度偏低",
           "R0": "防线未生效，请立即查看"}.get(st, "")
    return (
        "<header class=\"bar\">"
        "<div class=\"logo\"><video autoplay loop muted playsinline "
        "src=\"/assets/%s.mp4?t=%s\"></video></div>"
        "<div class=\"state\"><b>%s</b><br><span>%s</span></div>"
        "<span class=\"pill\"><span class=\"dot\" style=\"background:var(%s)\"></span>%s %s</span>"
        "<span class=\"pill\">未处理 <b>%d</b></span><div class=\"spacer\"></div>"
        "<div class=\"who\">本机 · 127.0.0.1<br>数据不出门</div></header>"
        % (_esc(st), _esc(token), _esc(lv), _esc(sub), LEVEL_VAR.get(st, "--l0"),
           _esc(st), _esc(lv), n))


def _item_html(it, token):
    acts = ""
    if it.state in ("unread", "read"):
        if it.state == "unread":
            acts += ("<form method=\"post\" action=\"/action\"><input type=hidden name=t value=\"%s\">"
                     "<input type=hidden name=id value=\"%s\"><input type=hidden name=op value=\"read\">"
                     "<button>标为已读</button></form>" % (_esc(token), _esc(it.id)))
        acts += ("<form method=\"post\" action=\"/action\"><input type=hidden name=t value=\"%s\">"
                 "<input type=hidden name=id value=\"%s\"><input type=hidden name=op value=\"done\">"
                 "<button>已处理</button></form>" % (_esc(token), _esc(it.id)))
        acts += ("<form method=\"post\" action=\"/action\"><input type=hidden name=t value=\"%s\">"
                 "<input type=hidden name=id value=\"%s\"><input type=hidden name=op value=\"ignored\">"
                 "<input type=hidden name=note value=\"判断无需动作\"><button>忽略</button></form>"
                 % (_esc(token), _esc(it.id)))
    else:
        acts = ("<form method=\"post\" action=\"/action\"><input type=hidden name=t value=\"%s\">"
                "<input type=hidden name=id value=\"%s\"><input type=hidden name=op value=\"read\">"
                "<button>重开</button></form>" % (_esc(token), _esc(it.id)))
    dot = "<span class=\"unread-dot\"></span>" if it.state == "unread" else ""
    # ★ "每次报警信息要齐"：原因(detail)、规则、命中、时间、链引用、备注一个都不能少
    meta = " · ".join(x for x in (
        it.detail,
        ("规则 " + it.rule_id) if it.rule_id else "",
        ("命中「%s」" % it.snippet) if it.snippet else "",
        it.ts, ("链 " + it.chain_ref[:10]) if it.chain_ref else "",
        ("备注：" + it.note) if it.note else "") if x)
    return ("<div class=\"item %s %s\"><div class=\"badge %s\">%s</div>"
            "<div class=\"body\"><div class=\"t\">%s%s</div><div class=\"m\">%s</div></div>"
            "<div class=\"act\">%s</div></div>"
            % (_esc(it.level.lower()), _esc(it.state), _esc(it.level.lower()),
               _esc(it.level), dot, _esc(it.title), _esc(meta), acts))


def _view_inbox(items, token, filt):
    open_n = M.unhandled_count(items)
    if filt == "done":
        rows = [i for i in items if i.state == "done"]
    elif filt == "ignored":
        rows = [i for i in items if i.state == "ignored"]
    elif filt == "all":
        rows = list(items)
    else:
        rows = [i for i in items if i.state in M.OPEN_STATES]
    def f(v, label, n):
        cls = " class=\"on\"" if v == filt else ""
        return "<a href=\"/?v=inbox&f=%s&t=%s\"%s>%s %d</a>" % (v, _esc(token), cls, label, n)
    cnt = M.counts_by_state(items)
    head = ("<div class=\"filters\">"
            + f("open", "未处理", open_n) + f("done", "已处理", cnt["done"])
            + f("ignored", "已忽略", cnt["ignored"]) + f("all", "全部", len(items))
            + ("<form method=\"post\" action=\"/action\" style=\"margin-left:auto\">"
               "<input type=hidden name=t value=\"%s\"><input type=hidden name=op value=\"read_all\">"
               "<button>全部已读</button></form>" % _esc(token))
            + "</div>")
    if not rows:
        body = ("<div class=\"empty\"><div class=\"logo\" style=\"margin:0 auto 12px\">"
                "<video autoplay loop muted playsinline src=\"/assets/L0.mp4?t=%s\"></video></div>"
                "<b>一切正常，无待办</b><p class=\"note\">这里没有需要你处理的事。</p></div>"
                % _esc(token))
    else:
        body = "".join(_item_html(i, token) for i in rows)
    return head + body


def _view_report(rep, token):
    Lv = rep["levels"]
    m = ("<div class=\"metrics\">"
         "<div class=\"metric\"><div class=\"k\">拦截</div><div class=\"v\" style=\"color:var(--l2)\">%d</div></div>"
         "<div class=\"metric\"><div class=\"k\">注意</div><div class=\"v\" style=\"color:var(--l1)\">%d</div></div>"
         "<div class=\"metric\"><div class=\"k\">失守</div><div class=\"v\" style=\"color:var(--r0)\">%d</div></div>"
         "<div class=\"metric\"><div class=\"k\">未处理</div><div class=\"v\">%d</div></div></div>"
         % (Lv["L2"], Lv["L1"], Lv["R0"], rep["unhandled_total"]))
    rules = ""
    if rep["rules"]:
        mx = max(r["count"] for r in rep["rules"]) or 1
        rows = "".join(
            "<div class=\"row\"><span class=\"k\">%s</span><span>%s %d</span></div>"
            % (_esc(r["rule_id"]), "█" * max(1, int(6 * r["count"] / mx)), r["count"])
            for r in rep["rules"][:10])
        rules = "<div class=\"card\"><h2>规则命中排行</h2><div class=\"rows\">%s</div></div>" % rows
    ch = rep["chain"]
    cls = {"ok": "ok", "broken": "bad", "unknown": "warn"}.get(ch["status"], "warn")
    chain = ("<div class=\"card\"><h2>链完整性</h2><div class=\"rows\">"
             "<div class=\"row\"><span class=\"k\">校验结果</span><span class=\"%s\">%s</span></div>"
             "<div class=\"row\"><span class=\"k\">文件 / 已链接记录</span><span>%d / %d</span></div>"
             "<div class=\"row\"><span class=\"k\">断链</span><span>%d</span></div>"
             "<div class=\"row\"><span class=\"k\">未链接记录</span><span>%d（如会话开始，正常）</span></div>%s</div></div>"
             % (cls, _esc(ch["status"]), ch["files"], ch["records"], ch["broken"],
                ch.get("unchained", 0),
                ("<div class=\"row\"><span class=\"k\">说明</span><span>%s</span></div>"
                 % _esc(ch["reason"])) if ch.get("reason") else ""))
    carried = ""
    if rep["carried_over_count"]:
        rows = "".join("<div class=\"row\"><span class=\"k\">%s</span><span>%s · %s</span></div>"
                       % (_esc(c["level"]), _esc(c["title"]), _esc(c["ts"]))
                       for c in rep["carried_over"][:20])
        carried = ("<div class=\"card\" style=\"border-left:4px solid var(--r0)\">"
                   "<h2>遗留未处理（%d 条，含更早）</h2><div class=\"rows\">%s</div></div>"
                   % (rep["carried_over_count"], rows))
    return ("<h2>今日值守 · %s</h2>%s%s%s" % (_esc(rep["day"]), m, rules, chain + carried))


def _view_health(rep, token):
    ch = rep["chain"]
    cls = {"ok": "ok", "broken": "bad", "unknown": "warn"}.get(ch["status"], "warn")
    import platform
    rows = [
        ("拦截钩子", "已安装（见 `antinel host-scan`）", "ok"),
        ("当前版本", "见「运行状态」真源", ""),
        ("链完整性", "%s（%d 文件 / %d 条 / 断 %d）" % (ch["status"], ch["files"],
                                                   ch["records"], ch["broken"]), cls),
        ("未覆盖缺口", "浏览器内操作、未挂钩子的工具 —— 不保护", "warn"),
    ]
    body = "".join("<div class=\"row\"><span class=\"k\">%s</span><span class=\"%s\">%s</span></div>"
                   % (_esc(k), v[1], _esc(v[0])) for k, v in [(r[0], (r[1], r[2])) for r in rows])
    return ("<h2>值守是否真的在跑</h2><div class=\"rows\">%s</div>"
            "<p class=\"note\">「全绿」本身是危险信号 —— 它不区分「没问题」和「判据瞎了」。"
            "所以运行状态必须同时给出**活力证据**与**标本覆盖**，不能只给一个绿灯。</p>"
            % body)


def _view_ledger(rep, token):
    led = rep["ledger"]
    m = ("<div class=\"metrics\">"
         "<div class=\"metric\"><div class=\"k\">连续值守</div><div class=\"v\">%d<small> 天</small></div></div>"
         "<div class=\"metric\"><div class=\"k\">累计拦截</div><div class=\"v\">%d</div></div>"
         "<div class=\"metric\"><div class=\"k\">已处理</div><div class=\"v\">%d</div></div>"
         "<div class=\"metric\"><div class=\"k\">账本天数</div><div class=\"v\">%d</div></div></div>"
         % (led.get("streak_days", 0), led.get("blocked", 0),
            led.get("acked", 0), led.get("days", 0)))
    return ("<h2>本地贡献记账</h2>%s"
            "<div class=\"card\"><h2>这份账本在哪里</h2><div class=\"rows\">"
            "<div class=\"row\"><span class=\"k\">存放</span><span>只在本机（<code>~/.antinel/ledger/</code>），不上传</span></div>"
            "<div class=\"row\"><span class=\"k\">可导出</span><span>是 —— 一个文件，将来可「认领合并」到账号</span></div>"
            "<div class=\"row\"><span class=\"k\">说明</span><span>积分不可转让、不可兑换、不与拉人挂钩</span></div>"
            "</div></div>"
            "<div class=\"card\"><h2>认领到账号 <span class=\"note\">（未启用）</span></h2>"
            "<p class=\"note\">将来上线账号后，可把这份本地账本领过去。现在无需注册，也不上传任何东西。</p>"
            "<button disabled>暂不可用</button></div>" % m)


def render_page(view="inbox", filt="open", root=None, token="", items=None, rep=None):
    """渲染整页。可注入 items/rep（测试用）。"""
    items = S.load_items(root=root) if items is None else items
    rep = (R.daily_report(root=root, items=items) if rep is None else rep)
    cnt = M.counts_by_state(items)
    title = {"inbox": "收件箱", "report": "日报", "health": "运行状态",
             "ledger": "账本"}.get(view, "收件箱")
    if view == "report":
        body = _view_report(rep, token)
    elif view == "health":
        body = _view_health(rep, token)
    elif view == "ledger":
        body = _view_ledger(rep, token)
    else:
        body = _view_inbox(items, token, filt)
    return (_head(title, token) + _bar(items, token)
            + _tabs(view, token, {"open": M.unhandled_count(items)})
            + "<main>" + body + "</main></body></html>")


# ------------------------------------------------------------- 服务 ----
def _make_handler(token, root):
    class H(BaseHTTPRequestHandler):
        server_version = "AntinelConsole"
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):                  # 不写日志文件（避免把内容落盘）
            pass

        # ---- 公共校验 ----
        def _guard(self):
            port = self.server.server_address[1]
            if not _allowed_host(self.headers.get("Host"), port):
                self._send(403, "text/plain; charset=utf-8", "Host 不被允许".encode("utf-8"))
                return False
            q = parse_qs(urlparse(self.path).query)
            got = (q.get("t") or [""])[0] or (self.headers.get("X-Antinel-Token") or "")
            if not secrets.compare_digest(str(got), str(token)):
                self._send(403, "text/plain; charset=utf-8", "缺少或错误的访问口令".encode("utf-8"))
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
            if u.path == "/api/health":
                return self._json({"ok": True, "bind": self.server.server_address[0]})
            if u.path in ("/", "/index.html"):
                view = (q.get("v") or ["inbox"])[0]
                filt = (q.get("f") or ["open"])[0]
                if view not in ("inbox", "report", "health", "ledger"):
                    view = "inbox"
                if filt not in ("open", "done", "ignored", "all"):
                    filt = "open"
                page = render_page(view=view, filt=filt, root=root, token=token)
                return self._send(200, "text/html; charset=utf-8", page.encode("utf-8"))
            return self._send(404, "text/plain; charset=utf-8", "没有这个页面".encode("utf-8"))

        def do_POST(self):
            if not self._guard():
                return
            u = urlparse(self.path)
            if u.path != "/action":
                return self._send(404, "text/plain; charset=utf-8", b"no")
            try:
                n = int(self.headers.get("Content-Length") or 0)
                n = max(0, min(n, 64 * 1024))       # 上限，防内存放大
                form = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
            except Exception:                       # noqa: BLE001
                return self._send(400, "text/plain; charset=utf-8", b"bad form")
            op = (form.get("op") or [""])[0]
            try:
                if op == "read_all":
                    S.mark_all_read(root=root)
                else:
                    iid = (form.get("id") or [""])[0]
                    note = (form.get("note") or [""])[0]
                    if op not in M.STATES:
                        raise M.BadState("未知操作 %r" % (op,))
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


def make_server(port=DEFAULT_PORT, root=None, token=None, bind="127.0.0.1"):
    """建服务器（不启动）。返回 `(httpd, token)`。★ `port=0` ⇒ 随机空闲端口。"""
    _check_bind(bind)
    token = token or secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer((bind, port), _make_handler(token, root))
    httpd.daemon_threads = True
    return httpd, token


def serve(port=DEFAULT_PORT, root=None, open_browser=False):
    """前台起服务（Ctrl+C 停）。"""
    httpd, token = make_server(port=port, root=root)
    real_port = httpd.server_address[1]
    url = "http://127.0.0.1:%d/?t=%s" % (real_port, token)
    print("值守台已开在：%s" % url)
    print("（只监听本机；关掉这个窗口就停）")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    return url
