# -*- coding: utf-8 -*-
"""本地体检页 —— 在**你自己电脑的浏览器**里点一下，就把这台电脑查一遍（只读）。

★★ 为什么必须做成「本地网页」而不是「网站上的按钮」：
    静态站跑在别人的服务器上，浏览器沙箱不让它读你的硬盘。
    一个网页如果点一下就告诉你「你的电脑很干净」、而你本机并没有运行任何程序，
    那它一定在撒谎 —— 而**把「没查」渲染成「清白」**正是本项目最反对的那件事
    （比不做还危险：用户会把它当体检合格证用）。
    ⇒ 所以诚实的分工是：网站只负责说服与给入口；**真正去查的是你电脑上的这个程序**；
      结果页也开在你本机的浏览器里，一个字节都不出本机。

★ 判据不许二次实现（本仓纪律）：
    六档定义（VERDICTS）与证据译文（ev_human）**由 antinel.py 传入**，
    本文件只做**取数与排版** —— 不重新判定、不重新翻译、不自己再翻一遍证据。
    扫描结果里的 `verdict` 字段也是 antinel.py 用同一个 `classify()` 算好的。

★ 只读（硬约束）：
    只跑 `host-scan --json`（**不带 --arm ／ --survey** ⇒ 不登记、不布防、不上锁）
    与 `egress --json`（账本采样；它会往本机账本追加一条快照事件，页面上明说）。
★ 零外部资源：CSS／JS 全内联，页面不发起任何对外网络请求。
★ 只监听 127.0.0.1，且带一次性 token ＋ Host 头校验（防 DNS rebinding／别的站点来问）。
"""
import html
import json
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_PORT = 8787
SCAN_TIMEOUT = 1800          # host-scan 冷跑实测 528 s，给 30 min 上限
EGRESS_TIMEOUT = 120

# ---- 作业状态（单任务；本页就是给一个人点一次用的） ----
_LOCK = threading.Lock()
_JOB = {
    "state": "idle",        # idle | running | done | error
    "stage": "",
    "started": 0.0,
    "finished": 0.0,
    "result": None,
    "error": "",
}


# --------------------------------------------------------------- 取数 ----
def _tail_json(text):
    """从「人类可读输出 ＋ 尾部 JSON」里取出那段 JSON。

    ★ 为什么不能 `json.loads(stdout)`：host-scan --json 的 JSON 是**追加在
      几百行人类可读输出之后**的（见 antinel.py 的 `if getattr(args,"json",…)` 段）。
      直接 loads 必然抛错 ⇒ 抠出来解析，抠不到就报错、绝不猜。
    """
    if not text:
        raise ValueError("命令没有任何输出")
    i = text.rfind("\n{")
    if i < 0:
        i = text.find("{")
    if i < 0:
        raise ValueError("输出里找不到 JSON")
    dec = json.JSONDecoder()
    while i >= 0:
        try:
            obj, _end = dec.raw_decode(text[i:].lstrip())
            return obj
        except ValueError:
            i = text.rfind("\n{", 0, i)
    raise ValueError("输出里的 JSON 解析失败")


def _run_host_scan(antinel_dir):
    """跑 `python -m antinel host-scan --json`，返回结构化 dict。

    ★ 用 subprocess 而不是直接调用：扫描要 4～9 分钟且是 CPU/IO 密集，
      进程隔离才不会拖住页面；同时它天然保证跑的是**同一个** antinel。
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = antinel_dir + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["ANTINEL_FORCE_HOST"] = env.get("ANTINEL_FORCE_HOST", "")
    cmd = [sys.executable, "-m", "antinel", "host-scan", "--json"]
    p = subprocess.run(cmd, cwd=antinel_dir, env=env, capture_output=True,
                       text=True, encoding="utf-8", errors="replace",
                       timeout=SCAN_TIMEOUT)
    if p.returncode != 0:
        raise RuntimeError("host-scan 退出码 %d：%s"
                           % (p.returncode, (p.stderr or "").strip()[:400]))
    return _tail_json(p.stdout)


def _run_egress(antinel_dir):
    """跑外传账本。直接 import 调用（秒级，且 egress.run 返回的就是纯 JSON 串）。"""
    sys.path.insert(0, antinel_dir)
    import egress as eg
    out = eg.run(days=eg.LEDGER_DAYS, all_proc=False, do_resolve=False,
                 as_json=True)
    try:
        return json.loads(out)
    except Exception:
        return {"_raw": out}        # 非 Windows 会返回一句话，原样呈现，不假装是数据


def _job(verdicts, ev_human, antinel_dir):
    """工作线程：先快后慢，边跑边更新阶段。"""
    try:
        _set(stage="正在看有没有程序在往外发数据…", state="running", started=time.time())
        eg = _run_egress(antinel_dir)
        _set(stage="正在逐个检查你电脑上的 AI 工具…（这一步通常要几分钟）")
        scan = _run_host_scan(antinel_dir)
        _set(state="done", finished=time.time(), stage="",
             result={"scan": scan, "egress": eg})
    except subprocess.TimeoutExpired:
        _set(state="error", error="检查超时（超过 %d 秒还没跑完）。"
             % SCAN_TIMEOUT)
    except Exception as e:
        _set(state="error", error="%s: %s" % (type(e).__name__, e))


def _set(**kw):
    with _LOCK:
        _JOB.update(kw)


def _snapshot():
    with _LOCK:
        j = dict(_JOB)
    j["elapsed"] = ((j["finished"] or time.time()) - j["started"]) if j["started"] else 0.0
    return j


# --------------------------------------------------------------- 排版 ----
def _md_bold(s):
    """把 `**强调**` 变成 <b>；先转义再替换，防注入。"""
    e = html.escape(str(s))
    out, on = [], True
    for part in e.split("**"):
        out.append(("<b>%s</b>" % part) if not on else part)
        on = not on
    return "".join(out)


CSS = """
*{box-sizing:border-box}
body{margin:0;background:#f6f7f9;color:#1f2328;
 font:15px/1.65 -apple-system,"Segoe UI","Microsoft YaHei",system-ui,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:28px 20px 64px}
h1{font-size:22px;font-weight:600;margin:0 0 6px}
h2{font-size:17px;font-weight:600;margin:30px 0 10px}
.sub{color:#5f6672;font-size:14px;margin:0 0 18px}
.card{background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:20px 22px;
 margin-bottom:16px}
.btn{display:inline-block;background:#1f6feb;color:#fff;border:0;border-radius:10px;
 padding:14px 30px;font-size:16px;font-weight:600;cursor:pointer}
.btn:hover{background:#1a5fd0}
.btn:disabled{background:#9aa4b2;cursor:default}
.muted{color:#5f6672;font-size:13px}
.small{font-size:13px}
ul{padding-left:20px;margin:8px 0}
li{margin:3px 0}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0 4px}
.tile{flex:1 1 168px;min-width:168px;border:1px solid #e4e7ec;border-radius:10px;
 padding:12px 14px}
.tile .n{font-size:24px;font-weight:600;line-height:1.2}
.tile .t{font-size:14px;font-weight:600;margin-top:2px}
.tile .d{font-size:12px;color:#5f6672;margin-top:4px;line-height:1.45}
.row{border-top:1px solid #eef0f3;padding:12px 0}
.row:first-child{border-top:0}
.row .nm{font-weight:600}
.row .pt{font-size:12px;color:#6b7280;word-break:break-all;margin-top:2px}
.row .ev{font-size:13px;margin-top:5px}
.tag{display:inline-block;font-size:12px;padding:1px 8px;border-radius:999px;
 border:1px solid #d7dbe1;color:#3d444d;background:#f6f7f9;margin-left:8px}
.warn{background:#fff8e6;border:1px solid #f0d38a;border-radius:10px;
 padding:14px 16px;margin:14px 0}
.blind{background:#f1f2f4;border:1px solid #d3d7dd;border-radius:10px;
 padding:14px 16px;margin:14px 0}
.err{background:#fdecec;border:1px solid #f0b4b4;border-radius:10px;
 padding:14px 16px;color:#8a1f1f}
.spin{display:inline-block;width:13px;height:13px;border:2px solid #c8cfd8;
 border-top-color:#1f6feb;border-radius:50%;vertical-align:-2px;margin-right:8px;
 animation:sp .8s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
hr{border:0;border-top:1px solid #eceff3;margin:26px 0}
code{background:#f2f4f7;border-radius:4px;padding:1px 5px;font-size:13px}
"""

JS = """
var busy=false;
function poll(){
  fetch('/api/status?t=TOK').then(function(r){return r.json()}).then(function(d){
    var box=document.getElementById('out');
    if(d.state==='running'){
      box.innerHTML='<div class="card"><div><span class="spin"></span>'+
        d.stage+'</div><div class="muted" style="margin-top:8px">已用时 '+
        d.elapsed+' 秒</div></div>';
      document.getElementById('go').disabled=true;
      setTimeout(poll,1500);
    } else if(d.state==='done'){
      box.innerHTML=d.html; document.getElementById('go').disabled=false;
    } else if(d.state==='error'){
      box.innerHTML='<div class="err"><b>这次没跑完。</b><br>'+
        String(d.error||'').replace(/</g,'&lt;')+'</div>';
      document.getElementById('go').disabled=false;
    }
  }).catch(function(e){setTimeout(poll,2500)});
}
function go(){
  if(busy)return; busy=true;
  document.getElementById('out').innerHTML='<div class="card"><div>'+
    '<span class="spin"></span>正在启动检查…</div></div>';
  fetch('/api/start?t=TOK',{method:'POST'}).then(function(){busy=false;poll()});
}
"""

TPL = """<!doctype html><meta charset="utf-8">
<title>查一查我的电脑 · Antinel</title><style>%s</style>
<div class="wrap">
<h1>查一查我的电脑</h1>
<p class="sub">这个页面<b>只在你自己的电脑上运行</b>。
点了下面的按钮，它会把你电脑上装过的 AI 工具逐个查一遍，
看它们有没有在自己写下的记录里承认过「打包过／往外发过」。<br>
<b>结果只显示在这个页面里，不会上传到任何地方。</b></p>
<div class="card">
<button class="btn" id="go" onclick="go()">开始检查</button>
<span class="muted" style="margin-left:14px">只读：不会改动、不会拦截、不会上传</span>
</div>
<div id="out"></div>
<hr>
<p class="muted small">
<b>先说清楚它能查到什么、查不到什么：</b><br>
· 它读的是<b>工具自己写下来的字段</b>（比如某个工具在自己的文件里记了「上次上传」）。
会偷的工具不会写，所以我们读不到 —— 这不是"它干净"，是"它没说"。<br>
· 下面每一档都带「<b>自认</b>」二字，就是这个意思：我们看到的是它自己承认的部分。<br>
· 「<b>没查到</b>」会单独列出来 —— 那是我们<b>没走到</b>的地方，
请当空白读，<b>不要</b>当成"没问题"。
</p>
</div>
<script>%s</script>
"""


def _index_page(token):
    return TPL % (CSS, JS.replace("TOK", token))


# ---- 六档：定义与译文全部来自产品（VERDICTS / ev_human），这里只排版 ----
def _tiles(vc, verdicts, blind_n):
    order = sorted(verdicts.values(), key=lambda v: v.get("order", 9))
    parts = []
    for v in order:
        k = v["key"]
        n = blind_n if k == "BLIND" else int(vc.get(k, 0))
        col = {"PACK": "#b3261e", "SENT": "#a15c00", "SYNC": "#7a5d00",
               "CLEAN": "#4b5563", "BLIND": "#111827", "NA": "#6b7280"}.get(k, "#374151")
        parts.append(
            '<div class="tile"><div class="n" style="color:%s">%s %d</div>'
            '<div class="t">%s %s</div><div class="d">%s</div></div>'
            % (col, v["icon"], n, v["icon"], html.escape(v["title"]),
               _md_bold(v["short"])))
    return '<div class="tiles">%s</div>' % "".join(parts)


def _rows_html(tools, verdicts, ev_human):
    """逐条列出。★ 顺序＝档位严重度（PACK>SENT>SYNC>CLEAN>NA），与产品同一口径。"""
    rank = {v["key"]: v.get("order", 9) for v in verdicts.values()}
    rows = sorted(tools, key=lambda r: (rank.get(r.get("verdict"), 9),
                                        str(r.get("name", "")).lower()))
    out = []
    for r in rows:
        v = verdicts.get(r.get("verdict"), {})
        evs = r.get("ev") or []
        ev_html = ""
        if evs:
            lis = "".join("<li>%s　<span class='muted'>（原文 %s）</span></li>"
                          % (_md_bold(ev_human(kw)), html.escape(str(kw)))
                          for _fp, kw in evs[:4])
            ev_html = "<div class='ev'>它自己写下的记录：<ul>%s</ul></div>" % lis
        elif r.get("excl"):
            ev_html = "<div class='ev muted'>未检查：%s</div>" % html.escape(str(r["excl"]))
        else:
            ev_html = "<div class='ev muted'>扫过了，这次没找到它自己写下的外传记录" \
                      " —— <b>不等于它没有</b>。</div>"
        out.append(
            "<div class='row'><span class='nm'>%s %s</span>"
            "<span class='tag'>%s %s</span>"
            "<div class='pt'>%s　·　%.1f MB ／ %d 个文件%s</div>%s</div>"
            % (v.get("icon", ""), html.escape(str(r.get("name", ""))),
               v.get("icon", ""), html.escape(str(v.get("title", r.get("verdict", "")))),
               html.escape(str(r.get("path", ""))),
               (r.get("size") or 0) / 1048576, int(r.get("files") or 0),
               "　·　扫描被截断（没看完）" if r.get("trunc") else "",
               ev_html))
    return "".join(out)


def _egress_html(eg):
    if not isinstance(eg, dict) or eg.get("_raw"):
        return "<p class='muted'>%s</p>" % html.escape(str(eg.get("_raw") if isinstance(eg, dict) else eg))
    snap = eg.get("snapshot") or {}
    findings = eg.get("findings") or []
    days = eg.get("days_with_data")
    cov = eg.get("coverage_seconds")
    parts = []
    if not snap.get("ok"):
        parts.append("<p class='muted'>这一次没能取到当前的网络连接快照"
                     "（采样失败 %s 次）—— 这一项是<b>没查到</b>，请当空白读。</p>"
                     % int(eg.get("sample_failed") or 0))
    else:
        parts.append("<p>此刻正在往外连的连接 <b>%d</b> 条。"
                     "账本已记录 <b>%s</b> 天%s。</p>"
                     % (len(snap.get("conns") or []),
                        html.escape(str(days if days is not None else "不足 1")),
                        ("（覆盖约 %.1f 小时）" % (cov / 3600.0)) if cov else ""))
    if findings:
        lis = "".join("<li>%s</li>" % _md_bold(f.get("label") or f.get("kind") or str(f))
                      for f in findings[:12])
        parts.append("<p><b>值得看一眼的 %d 条</b>（只标记，<b>不下结论</b>）：</p><ul>%s</ul>"
                     % (len(findings), lis))
    else:
        parts.append("<p class='muted'>账本里没有需要特别标记的连接。"
                     "注意：这只是<b>没记到值得看的</b>，不等于<q>没有外传</q>。</p>")
    parts.append("<p class='muted small'>说明：外传账本每采样一次会往<b>你自己电脑上的</b>"
                 "账本追加一条记录（这是它的本职），同样不会上传到任何地方。</p>")
    return "".join(parts)


def _result_html(res, verdicts, ev_human):
    scan = res.get("scan") or {}
    tools = scan.get("tools") or []
    vc = scan.get("counts_by_verdict") or {}
    cov = scan.get("coverage") or {}
    blind_n = int(cov.get("unscanned") or 0)

    head = []
    # ★★★ 最高纪律：「没查到」必须与「没发现」长得不一样，且首屏就报。
    if blind_n:
        head.append(
            "<div class='blind'><b>⚫ 有 %d 个地方我们没查到。</b><br>"
            "它们登记过、你电脑上也确实存在，但这次扫描没走到 —— "
            "<b>请把它们当空白读，不要当成「没问题」。</b></div>" % blind_n)
    else:
        head.append("<div class='warn'>登记过的落点这次<b>全部走到了</b>"
                    "（没查到 0 个）。</div>")

    n_ev = int(vc.get("PACK", 0)) + int(vc.get("SENT", 0)) + int(vc.get("SYNC", 0))
    if n_ev:
        head.append("<div class='warn'><b>有 %d 个工具在自己的文件里写下了"
                    "「打包／上传／推送／同步」这类字样。</b><br>"
                    "那是<b>它自己承认</b>的，不是我们抓到它在发 —— "
                    "我们的能力只到「读它写下的字」。</div>" % n_ev)

    body = [
        "<h2>总共查了 %d 个落点</h2>" % len(tools),
        _tiles(vc, verdicts, blind_n),
        "<p class='muted small'>六档是这么分的：🔴 自认打包过 ＞ 🟠 自认往外发过 ＞ "
        "🟡 自认在同步 ＞ ⚪ 查过、没发现记录 ＞ ⚫ 没查到 ＞ · 不适用。</p>",
        "<h2>逐个看</h2>",
        _rows_html(tools, verdicts, ev_human),
        "<h2>有没有程序在往外发数据</h2>",
        _egress_html(res.get("egress")),
    ]
    gen = html.escape(str(scan.get("generated_at") or ""))
    return ("".join(head) + "".join(body)
            + "<hr><p class='muted small'>生成时刻 %s　·　"
              "本次为<b>只读</b>检查：没有登记、没有布防、没有上锁。</p>" % gen)


# --------------------------------------------------------------- 服务 ----
def _free_port(start):
    for p in range(start, start + 30):
        try:
            s = socket.socket()
            s.bind(("127.0.0.1", p))
            s.close()
            return p
        except OSError:
            continue
    raise RuntimeError("找不到可用端口（%d-%d 都占着）" % (start, start + 29))


def serve(verdicts, ev_human, antinel_dir, port=DEFAULT_PORT, open_browser=True):
    """起本地服务并（可选）自动开浏览器。阻塞，直到 Ctrl-C。"""
    token = "%08x" % (int(time.time() * 1000) & 0xFFFFFFFF)
    port = _free_port(port)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _ok(self, body, ctype="text/html; charset=utf-8"):
            b = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b)

        def _json(self, obj):
            self._ok(json.dumps(obj, ensure_ascii=False),
                     "application/json; charset=utf-8")

        def _guard(self):
            """★ 只认本机来的、且带一次性 token 的请求。"""
            host = (self.headers.get("Host") or "").split(":")[0]
            if host not in ("127.0.0.1", "localhost", "::1"):
                self._ok("这个页面只接受来自你自己电脑的访问",
                         "text/plain; charset=utf-8")
                return False
            if ("t=" + token) not in (self.path or ""):
                self._ok("链接已失效，请重新运行本命令", "text/plain; charset=utf-8")
                return False
            return True

        def do_GET(self):
            if not self._guard():
                return
            if self.path.startswith("/api/status"):
                j = _snapshot()
                out = {"state": j["state"], "stage": j["stage"],
                       "elapsed": int(j["elapsed"]), "error": j["error"]}
                if j["state"] == "done" and j["result"]:
                    out["html"] = _result_html(j["result"], verdicts, ev_human)
                self._json(out)
            else:
                self._ok(_index_page(token))

        def do_POST(self):
            if not self._guard():
                return
            if self.path.startswith("/api/start"):
                with _LOCK:
                    if _JOB["state"] == "running":
                        self._json({"ok": False, "msg": "已经在跑了"})
                        return
                    _JOB.update({"state": "running", "stage": "正在启动…",
                                 "started": time.time(), "finished": 0.0,
                                 "result": None, "error": ""})
                threading.Thread(target=_job, args=(verdicts, ev_human, antinel_dir),
                                 daemon=True).start()
                self._json({"ok": True})
            else:
                self._json({"ok": False})

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    url = "http://127.0.0.1:%d/?t=%s" % (port, token)
    print("体检页已启动：%s" % url)
    print("（这个页面只在你自己的电脑上，不会上传到任何地方。按 Ctrl-C 结束。）")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception as e:
            print("自动打开浏览器失败：%r —— 请手动打开上面的地址" % (e,))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        srv.server_close()
    return 0
