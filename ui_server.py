# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

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
                       timeout=SCAN_TIMEOUT,
                       creationflags=0x08000000 if os.name == "nt" else 0)
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


def _canary_data(antinel_dir):
    """体检 payload 的诱饵文件一块（`antinel.canary_summary` 唯一实现）。

    ★ 取不到 ⇒ `{"failed": True}`，页面说「没查到」——**不许**静默变成
      「没有诱饵文件」（没查过与查过没有是两件事）。
    """
    try:
        sys.path.insert(0, antinel_dir)
        import antinel as _A
        return _A.canary_summary()
    except Exception:                                        # noqa: BLE001
        return {"failed": True}


def _job(verdicts, ev_human, antinel_dir):
    """工作线程：先快后慢，边跑边更新阶段。"""
    try:
        _set(stage="正在看有没有程序在往外发数据…", state="running", started=time.time())
        eg = _run_egress(antinel_dir)
        _set(stage="正在逐个检查你电脑上的 AI 工具…（这一步通常要几分钟）")
        scan = _run_host_scan(antinel_dir)
        _set(state="done", finished=time.time(), stage="",
             result={"scan": scan, "egress": eg,
                     "canary": _canary_data(antinel_dir)})
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
.ev{background:#fbfcfd;border:1px solid #eceff3;border-radius:9px;padding:12px 14px;
 margin-top:8px}
.ev .l1{font-size:14px;line-height:1.7}
.ev .mean{font-size:13px;color:#3d444d;background:#f6f7f9;border-radius:7px;
 padding:9px 11px;margin-top:10px;line-height:1.65}
.nums{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.num{flex:1 1 108px;background:#fff;border:1px solid #e4e7ec;border-radius:8px;
 padding:7px 10px}
.num .k{font-size:11px;color:#6b7280}
.num .v{font-size:14px;font-weight:500;margin-top:2px;word-break:break-all}
details.fold{margin-top:11px}
details.fold>summary{cursor:pointer;font-size:13px;color:#1f6feb;user-select:none;
 padding:5px 0}
details.fold>summary:hover{text-decoration:underline}
table.evo{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px;
 table-layout:fixed}
table.evo th{text-align:left;color:#6b7280;font-weight:500;padding:5px 7px;
 border-bottom:1px solid #e4e7ec;font-size:11px}
table.evo td{padding:5px 7px;border-bottom:1px solid #f1f3f5;vertical-align:top;
 word-break:break-all}
table.evo td.kd{width:9%;color:#6b7280;font-size:11px}
table.evo td.kp{width:33%;font-family:var(--font-mono,monospace);font-size:11px;
 color:#3d444d}
table.evo td.tm{width:17%;color:#6b7280;font-size:11px;white-space:nowrap}
table.evo tr.mark td{background:#fffafa}
table.evo tr.mark td.kd{color:#a32d2d;font-weight:500}
.one{background:#fff;border:1px solid #e4e7ec;border-radius:8px;padding:8px 11px;
 margin-top:10px;font-size:14px}
.orig{font-size:11px;margin-top:7px;word-break:break-all}
/* 折叠区内是"证据原文"，允许横向滚动，绝不撑破整页布局 */
details.fold{overflow-x:auto}
table.evo{min-width:520px}
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
会偷的工具不会写，所以监理读不到 —— 这不是"它干净"，是"它没说"。<br>
· 下面每一档都带「<b>自认</b>」二字，就是这个意思：监理看到的是它自己承认的部分。<br>
· 「<b>没查到</b>」会单独列出来 —— 那是监理<b>没走到</b>的地方，
请当空白读，<b>不要</b>当成"没问题"。
</p>
</div>
<script>%s</script>
"""


def _index_page(token):
    return TPL % (CSS, JS.replace("TOK", token))


# ---- 六档：定义与译文全部来自产品（VERDICTS / ev_human），这里只排版 ----
def _tiles(vc, verdicts, blind_n, total=None):
    """六档计数块。

    ★ 0.47.0（方案 v3.0 §5 步三）：每一档的数是**分子** ⇒ 同行带分母
      （分母＝这次一共查了几个落点）。`total=None` ⇒ 分母未知，显示为
      `/ ?` —— **不许**给一个光秃秃的分子假装它自己就是全部。
    """
    order = sorted(verdicts.values(), key=lambda v: v.get("order", 9))
    parts = []
    for v in order:
        k = v["key"]
        n = blind_n if k == "BLIND" else int(vc.get(k, 0))
        col = {"PACK": "#b3261e", "SENT": "#a15c00", "SYNC": "#7a5d00",
               "CLEAN": "#4b5563", "BLIND": "#111827", "NA": "#6b7280"}.get(k, "#374151")
        parts.append(
            '<div class="tile"><div class="n" style="color:%s">%s %d / %s</div>'
            '<div class="t">%s %s</div><div class="d">%s</div></div>'
            % (col, v["icon"], n, (html.escape(str(total)) if total is not None else "?"),
               v["icon"], html.escape(v["title"]),
               _md_bold(v["short"])))
    return '<div class="tiles">%s</div>' % "".join(parts)


def _rows_html(tools, verdicts, ev_human, details=None):
    """逐条列出。★ 顺序＝档位严重度（PACK>SENT>SYNC>CLEAN>NA），与产品同一口径。"""
    details = details or {}
    rank = {v["key"]: v.get("order", 9) for v in verdicts.values()}
    rows = sorted(tools, key=lambda r: (rank.get(r.get("verdict"), 9),
                                        str(r.get("name", "")).lower()))
    out = []
    for r in rows:
        v = verdicts.get(r.get("verdict"), {})
        evs = r.get("ev") or []
        ev_html = _evidence_html(r, details.get(r.get("path") or "") or [],
                                 verdicts, ev_human, r.get("verdict"))
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


# ------------------------------------------------- 单条证据：三段式 + 法庭区 ----
# ★★ 排版纪律（创始人 2026-09-27）：
#   「不要写得太专业 —— 有很多非专业老板和高管也会检查自己电脑的，
#     要让他们看得懂…特别是这第一次」。同时：「尽可能把细节参数都加上…特别
#     是可能作为法庭证据」。两者不矛盾 ⇒ **分层**：老板看前两行，技术人点开看证据。
#   三段：① 一句话讲发生了什么（带时间）② 关键数字（打包多大/上传多少）
#         ③ 一句"这意味着什么" ④ 折叠区：完整证据（键路径/值/原文）
def _pick_value(items, *name_frags):
    """在证据项里挑一个值（按键路径片段匹配，返回可读字符串）。"""
    for it in items:
        kp = str(it.get("kpath", "")).lower()
        if any(f in kp for f in name_frags):
            return it
    return None


def _fmt_bytes(n):
    """字节 → 人话。★ 产品里有同名实现（antinel._fmt_bytes）—— 展示层**引用**它，
    不自己再写一份（本仓纪律：判据/译文不许二次实现）。取不到时退化为原始字节数。"""
    try:
        import antinel as _A
        f = getattr(_A, "_fmt_bytes", None)
        if f:
            return f(n)
    except Exception:
        pass
    return "%d 字节" % int(n)


def _evidence_html(r, detail, verdicts, ev_human, verdict):
    evs = r.get("ev") or []
    if r.get("excl"):
        return ("<div class='ev muted'>未检查：%s</div>"
                % html.escape(str(r["excl"])))
    if not evs:
        return ("<div class='ev muted'>扫过了，这次没找到它自己写下的外传记录"
                " —— <b>不等于它没有</b>。</div>")

    items = []
    for d in (detail or []):
        items.extend(d.get("items") or [])

    # ---- ① 一句话：什么时候 + 做了什么 ----
    ts_ms, ts_txt = None, None
    for it in items:
        if it.get("ts_ms"):
            ts_ms, ts_txt = it["ts_ms"], it["ts_text"]
            break
    for d in (detail or []):                      # 退而用文件最后改动时间
        if not ts_ms and d.get("mtime_ms"):
            ts_ms, ts_txt = d["mtime_ms"], d["mtime_text"]

    # ★ 措辞纪律：一句话里**只强调一个事实**，别把"自己记下/承认/它说"叠三层。
    #   （创始人 2026-09-27：「输出结果尽可能格式化，别乱」——句子也是排版。）
    what = {"PACK": "打包过你电脑上的文件",
            "SENT": "往外发送过东西",
            "SYNC": "在跟服务器同步"}.get(verdict, "留下了外传相关的记录")
    if ts_txt:
        line1 = "它自己记下：<b>%s</b> 它%s。" % (html.escape(ts_txt), what)
    else:
        line1 = "它自己记下：它%s（记录里没写具体时间）。" % what

    # ---- ② 关键数字：打包多大 / 打了多少文件 / 传给谁 ----
    # ★ 排版的硬要求：**卡片要么都排齐、要么不出现**。一条证据如果只有 1 项，
    #   一列孤零零地漂着最难看 ⇒ 少于 2 项时改为**一行文字**，不摆卡片。
    nums = []
    ws = _pick_value(items, "workspacesize")
    if ws and isinstance(ws.get("value"), (int, float)):
        nums.append(("打了多大", _fmt_bytes(ws["value"])))
    enc = _pick_value(items, "compressedsize", "encryptedsize")
    if enc and isinstance(enc.get("value"), (int, float)):
        nums.append(("压缩加密后", _fmt_bytes(enc["value"])))
    wp = _pick_value(items, "workspacepath", "workspacekey")
    if wp and isinstance(wp.get("value"), str):
        nums.append(("打包的是这个目录", wp["value"]))
    if _pick_value(items, "lastacceptedmanif"):
        nums.append(("服务器收下了吗", "收下了"))
    if ts_txt:
        nums.append(("打包时间", ts_txt))

    if len(nums) >= 2:
        tiles = ("<div class='nums'>%s</div>"
                 % "".join("<div class='num'><div class='k'>%s</div>"
                           "<div class='v'>%s</div></div>"
                           % (html.escape(k), html.escape(str(v))) for k, v in nums))
    elif len(nums) == 1:
        tiles = "<div class='one'><b>%s</b>　%s</div>" % (
            html.escape(nums[0][0]), html.escape(str(nums[0][1])))
    else:
        tiles = ""

    # ---- ③ 这意味着什么（老板看得懂的一句话） ----
    meaning = {
        "PACK": "要不要紧，就看上面「服务器收下了吗」——<b>收下了，说明这包已经发出去过</b>；"
                "没提，说明只在你电脑上打了包。",
        "SENT": "它发的是什么，展开下面能看到它自己写的记录。",
        "SYNC": "<b>同步不等于上传整个项目</b>，但说明你的数据有一条往外走的通道。",
    }.get(verdict, "")

    # ---- ④ 折叠区：完整证据（法庭可引用） ----
    # ★ 措辞：`mark`/`ctx` 是**内部词**，用户不该看见。译成"关键字段 / 说明"。
    KIND_CN = {"mark": "关键", "context": "说明"}
    rows = []
    for d in sorted((detail or []), key=lambda x: (x.get("items") or []) and 0 or 1):
        if not d.get("items"):
            continue
        for it in d["items"]:
            v = it.get("value")
            vs = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
            rows.append(
                "<tr class='%s'><td class='kd'>%s</td><td class='kp'>%s</td>"
                "<td class='vv'>%s</td><td class='tm'>%s</td></tr>"
                % (html.escape(it.get("kind", "")),
                   html.escape(KIND_CN.get(it.get("kind", ""), "")),
                   html.escape(str(it.get("kpath", ""))),
                   html.escape(str(vs))[:300],
                   html.escape(it.get("ts_text") or "")))
    if not rows:
        rows_html = ("<p class='muted small'>这一条没有更细的字段记录"
                     "（工具只写下一个标记，没写内容）—— 这本身就是一项证据。</p>")
    else:
        rows_html = ("<table class='evo'><tr><th>类别</th><th>它写的字段</th>"
                     "<th>值（逐字抄下）</th><th>时间</th></tr>%s</table>"
                     "<p class='muted small'>这四列是从它自己的文件里<b>逐字抄下来的</b>，"
                     "没有加工 —— 需要时可作为证据引用。</p>" % "".join(rows))

    return ("<div class='ev'>"
            "<div class='l1'>%s</div>%s%s"
            "<details class='fold'><summary>看它的原始记录（技术细节，可作证据）"
            "</summary>%s</details>"
            "<div class='orig muted small'>从这些文件里读到：%s</div>"
            "</div>") % (
        line1, tiles, ("<div class='mean'>%s</div>" % meaning) if meaning else "",
        rows_html,
        "；".join(html.escape(str(d.get("file", ""))) for d in (detail or [])[:3])
        or "；".join(html.escape(str(fp)) for fp, _k in evs[:2]))


def _finding_li(f):
    """一条 finding 怎么显示 —— `lines` 三行**都要上页面**（0.53.0 收尾）。

    ★ 实测（施工单 v1.2 S10，真跑 `egress.run(as_json=True)`）：
      `findings` 每条**只有 `kind` 与 `lines`**，而 `label` **恒不存在**；
      `lines` 恒 3 行 —— 第 1 行主句（进程名 ＋ 数字）、第 2 行补充（远端／样本）、
      第 3 行处置提示（恒以 `→ ` 开头）。
      ⇒ 旧写法 `<li>{label or kind}</li>` 实际渲染的就是**类别名**，
      本机 10 条里只有「空闲期外连」「长连接」两个词在重复：
      **外框写着「值得看一眼的 10 条」，实质内容一行也没有**。
      这与「四组明细」是同一种病：有内容，但被显示成了没内容。

    ★ 第 1 行走 `_md_bold`（与旧行为同款，**它内部已先转义**）；
      第 2 行起用小字，因为它们是对第 1 行的补充，不该跟主句抢分量。
    """
    lines = [str(x).strip() for x in (f.get("lines") or []) if str(x).strip()]
    if not lines:
        return "<li>%s</li>" % _md_bold(f.get("label") or f.get("kind") or str(f))
    out = ["<li>", _md_bold(lines[0])]
    for ln in lines[1:]:
        out.append("<div class='muted small'>%s</div>" % html.escape(ln))
    out.append("</li>")
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
        # ★ 0.47.0：这是**此刻**的实况读数（窗口＝此刻），不是"一段时间里的告警数"
        #   ⇒ 把范围写清（"此刻"），读者就不会拿它跟 24 小时口径的数比大小。
        parts.append("<p>此刻正在往外连的连接 <b>%d</b> 条。"
                     "账本已记录 <b>%s</b> 天%s。</p>"
                     % (len(snap.get("conns") or []),
                        html.escape(str(days if days is not None else "不足 1")),
                        ("（覆盖约 %.1f 小时）" % (cov / 3600.0)) if cov else ""))
    if findings:
        lis = "".join(_finding_li(f) for f in findings[:12])
        # ★ 0.47.0：总数是分母、列出数是分子 ⇒ 两个都给，读者才知道看的是不是全部。
        parts.append("<p><b>值得看一眼的 %d 条</b>（下面列出前 %d 条；"
                     "只标记，<b>不下结论</b>）：</p><ul>%s</ul>"
                     % (len(findings), min(12, len(findings)), lis))
    else:
        parts.append("<p class='muted'>账本里没有需要特别标记的连接。"
                     "注意：这只是<b>没记到值得看的</b>，不等于<q>没有外传</q>。</p>")
    parts.append("<p class='muted small'>说明：外传账本每采样一次会往<b>你自己电脑上的</b>"
                 "账本追加一条记录（这是它的本职），同样不会上传到任何地方。</p>")
    return "".join(parts)


#: 未配置（payload 为 `null`）时的说法。**不许**渲染成 0 —— 那是把「没查」写成
#: 「查过、没有」（v1.11 §37.2：本机只有 `index_dirs` 是这个态）。
#: ★ 这句话里**不许出现「0 处」字样**：判据 H5 用「该行不含 0」区分三态，
#:   文案自带 0 会让判据永远分不开（自己把自己的尺子废掉）。
#: ★ 主语用「监理」（文案主语纪律）：「我们」是开发方视角，读者是**被监理的人**，
#:   看到「我们」不知道是谁 —— 而这一句要说清的正是**谁没查**。
_OBS_NOT_CONFIGURED = "这一类监理还没配，所以没查 —— 不是「查过、没有」。"

#: 十类观察项：人话名 ／ 单位 ／ 备注（要说清的那句）
_OBS_META = {
    "crash_dumps":       ("崩溃转储文件", "个", ""),
    "crash_report_dirs": ("崩溃上报目录", "处", ""),
    "residue_dirs":      ("残留目录", "处", ""),
    "index_dirs":        ("索引/向量类", "处", ""),
    "ime_dirs":          ("输入法词库", "处", "词库＝你打过什么字。"),
    "im_stores":         ("聊天/邮件本地库", "处", "只报存在与体积。"),
    "sync_dirs":         ("云盘同步目录", "处",
                          "写进去＝客户端自动上传。"),
    "share_targets":     ("系统分享目标", "个",
                          "影子通道：点一下分享内容就出去，"
                          "全程不经 Agent 工具。"),
    "cross_device":      ("跨设备平台", "处", ""),
    "print_spool":       ("打印后台", "条", ""),
}

_OBS_MAX_ROWS = 5          #: 组内最多摊几条，其余折叠为「还有 N 条」


def _obs_norm(key, val):
    """十类观察项 → 一个 5 元组 `(人话名, 条目数 or None, 字节, 单位, 备注)`。

    ★★ 归一的目的：payload 里这十个键是**五种形状**
      （`list[dict]`／`list[str]`／单 `dict`／`null`／以及 `crash_dumps` 用 `count`
       而非 `entries`）。渲染层**不许**写十段 `if key == "..."` ——
      十份实现迟早不一致，而不一致时往往还都判绿。

    口径（实测逐类核对）：
      · `null`        ⇒ 条目数 None（**没配**，不是 0）
      · `list`        ⇒ 条目数＝**几个这样的地方**（`share_targets` 是字符串列表，
                          名称即内容，也用容器数）
      · 单 `dict`     ⇒ 条目数＝它里面的 `entries`（`print_spool` 的 0 就是这么来的）
    """
    name, unit, note = _OBS_META.get(key, (key, "处", ""))
    if val is None:
        return (name, None, None, unit, _OBS_NOT_CONFIGURED)
    if isinstance(val, dict):
        n, b = val.get("entries"), val.get("bytes")
    elif isinstance(val, list):
        n = len(val)
        b = sum(int(x.get("bytes") or 0) for x in val if isinstance(x, dict))
    else:
        n, b = None, None
    try:
        n = int(n) if n is not None else None
    except Exception:
        n = None
    return (name, n, b, unit, note)


def _obs_row(item, inner=None):
    """**唯一**的观察项模板。渲染层不许为某个键另写一份。"""
    name, n, b, unit, note = item
    if n is None:
        q = "<span class='muted'>%s</span>" % html.escape(note)
    else:
        q = "<b>%d %s</b>" % (n, unit)
        if b:
            q += "（%s）" % html.escape(str(_fmt_bytes(b)))
        if note:
            q += "　<span class='muted'>%s</span>" % html.escape(note)
    out = ("<div class='row'><div class='pn'>%s</div><div class='pt'>%s</div>"
           % (html.escape(name), q))
    for t in (inner or []):
        out += "<div class='pt muted'>%s</div>" % html.escape(str(t))
    return out + "</div>"


def _obs_html(observations):
    """④ 别处还有什么（数据源 `scan["observations"]`，**零新增采集**）。

    ★ 这一组**只看「这里有什么、有多大」**，不读任何文件内容，也不替用户下
      「这是外传」的结论 —— 组头免责句一个字不许压。
    ★ 三态计数（有几类有东西／几类空着正常／几类没查到）**由数据现算**，
      不许写死（本机实测 7／2／1，换个机器就不是这三个数）。
    """
    obs = observations or {}
    items = []
    for key, val in obs.items():
        name, n, _b, _u, _note = _obs_norm(key, val)
        items.append((key, val, (name, n, _b, _u, _note)))
    # 有东西的在前（按条目数降序）→ 空着的 → **没查到的排最后**
    # ★ 排序键第一项是「态」：0 有东西 ／ 1 空着 ／ 2 没查到（None）
    items.sort(key=lambda x: (2 if x[2][1] is None else (1 if x[2][1] == 0 else 0),
                              -(x[2][1] or 0)))
    have = sum(1 for it in items if it[2][1])
    empty = sum(1 for it in items if it[2][1] == 0)
    miss = sum(1 for it in items if it[2][1] is None)

    out = ["<p class='muted small'>观察项不读文件内容：它告诉你"
           "「这里有什么、有多大」，不替你下「这是外传」的结论。</p>"]
    out.append("<p class='muted small'>看了 %d 类：<b>%d 类有东西</b>　"
               "·　%d 类空着（空＝正常）　·　%d 类这次没查到。</p>"
               % (len(items), have, empty, miss))
    for key, val, item in items:
        inner = []
        if isinstance(val, list):
            names = [x if isinstance(x, str)
                     else (x.get("path") or x.get("label") or "")
                     for x in val]
            names = [x for x in names if x]
            if len(names) > _OBS_MAX_ROWS:
                inner = (names[:_OBS_MAX_ROWS]
                         + ["还有 %d 条" % (len(names) - _OBS_MAX_ROWS)])
            else:
                inner = names
        elif isinstance(val, dict) and val.get("path"):
            inner = [val.get("path")]
        out.append(_obs_row(item, inner))
    return "".join(out)


def _conns_html(eg):
    """③ 此刻谁在往外连 —— 逐进程表（数据源 `egress`，**零新增采集**）。

    ★★ 行集合＝`longest_by_proc` 的键 **∪** `conns` 里的进程，**不是后者**。
      `conns` 只答「此刻谁连着」；`longest_by_proc` 答「账本里谁连得久」。
      只取 `conns` 会漏掉**已退出但账本里有长连接**的进程 ——
      实测本机 `AutoClaw.exe`（≥49.4 小时）就是这么被漏掉的：
      **有证据却不显示，比显示错更糟**（v1.11 §36.1）。

    ★ 「最长」是**下界**（`egress.py` 原文注释：账本只知道从第一次看见它算起）
      ⇒ 每格必须带 `≥`；缺值时显示 `—`，**不许显示 0 小时**（那是把没算读成 0）。
      且必须与账本覆盖时长**挨着**，否则会被读成「一条连接连了 6.8 天」。
    """
    if not isinstance(eg, dict) or eg.get("_raw"):
        return ""
    snap = eg.get("snapshot") or {}
    longest = eg.get("longest_by_proc") or {}
    n_by = {}
    for c in (snap.get("conns") or []):
        p = str(c.get("proc") or "?")
        n_by[p] = n_by.get(p, 0) + 1
    procs = list((eg.get("longest_by_proc") or {}).keys())
    for p in n_by:
        if p not in procs:
            procs.append(p)
    if not procs:
        return ("<p class='muted'>这次没取到任何进程的连接记录"
                " —— 这一项是<b>没查到</b>，请当空白读。</p>")
    procs.sort(key=lambda p: -float(longest.get(p) or 0))

    rows = []
    for p in procs:
        _n = n_by.get(p)
        _lg = longest.get(p)
        _cnt = ("%d 条连接" % _n) if _n else "此刻没有连接"
        try:
            _tail = ("最长 ≥ %.1f 小时" % (float(_lg) / 3600.0)
                     ) if _lg is not None else "最长 —"
        except Exception:
            _tail = "最长 —"
        rows.append("<div class='row'><div class='pn'>%s</div>"
                    "<div class='pt'>%s　%s</div></div>"
                    % (html.escape(str(p)),
                       html.escape(_cnt), html.escape(_tail)))

    _cov = eg.get("coverage_seconds")
    # ★ 单位必须与上一组（`_egress_html`）**完全一致**：那里写「覆盖约 144.4 小时」，
    #   这里若写成「6.01 天」，同一页就出现两个不一样的数（一个按小时、一个按天），
    #   读者会去对账而对不上 —— 正是本项目禁止的「同页两处不同口径」。
    _age = ("，这次账本覆盖总时长约 %.1f 小时" % (_cov / 3600.0)) if _cov else ""
    out = list(rows)
    out.append("<p class='muted'>「最长」只能算个下限：账本只知道从第一次看见它算起，"
               "可能更早就在了%s。它接近这个总时长时，说的是"
               "「账本开始记的时候它就在了」，不是「一条连接连了那么久」。</p>" % _age)
    if int(eg.get("sample_failed") or 0):
        out.append("<p class='muted'>⚠ 本窗口有 %d 次采样失败"
                   "（<b>未采到 ≠ 没问题</b>）。</p>"
                   % int(eg.get("sample_failed") or 0))
    out.append("<p class='muted small'>AI 工具正常工作时本来就在往外发"
               " ⇒ 有连接 ≠ 有问题。</p>")
    return "".join(out)


def _canary_html(c):
    """③ 组尾：诱饵文件状态（放了几枚、有没有被读过）。

    ★ 术语：页面一律「诱饵文件」——CLI 命令名 `antinel canary` 不动
      （v1.11 §20.3 术语表；0360 H6 禁词盯着）。
    ★ 五态不许混（文案地基，与 `antinel.canary_summary` 的三态注释同一套）：
      没登记项目 ≠ 没放诱饵 ≠ 放了没被读 ≠ 被读过 ≠ 带出去过。
      「带出去过」只有 `observed` 一种证据，**不许**把"被读"说成"出事"。
    ★ 数据不在 payload 里（测试夹具/老调用方）⇒ 返回空串，不渲染、不谎报。
    """
    if not isinstance(c, dict):
        return ""
    if c.get("failed"):
        return ("<p class='muted small'>诱饵文件状态这次没查到"
                "——请当空白读，不要当成「没有问题」。</p>")
    projects = int(c.get("projects") or 0)
    if not projects:
        return ("<p class='muted small'><b>诱饵文件：</b>"
                "还没有登记过项目，无从查起——这不是「没有诱饵」，是「没查」。</p>")
    planted = c.get("planted") or []
    read = int(c.get("read") or 0)
    observed = int(c.get("observed") or 0)
    out = ["<p class='muted small'><b>诱饵文件：</b>"]
    if not planted:
        out.append("还没有放过诱饵文件。想查「有没有东西被带出去」，"
                   "在项目里跑一次 <code>antinel canary plant</code> 就能放一个。")
    elif read == 0:
        out.append("放了 %d 个诱饵文件，都还没有被任何工具读过。" % len(planted))
    else:
        out.append("放了 %d 个诱饵文件，被读过 %d 次。被读不等于出事"
                   "——但要是哪个工具的标记出现在输出里，"
                   "那就是确有内容被带出去过。" % (len(planted), read))
    if observed:
        out.append("<br><b>⚠ 有 %d 次诱饵标记出现在工具输出里</b>"
                   "——这是确有内容被带出去过的证据。" % observed)
    out.append("</p>")
    return "".join(out)


def _proj_rows(details):
    """取数：从 `details` 里抽出「打包过哪些项目目录」，每个目录一行。

    ★ 与渲染分开：组标题要显示「几个」，渲染要显示明细 ——
      各算一遍就会出现两处口径（本项目明令禁止的同源纪律）。
    """
    rows = []
    seen = set()
    for _path in sorted(details or {}):
        for blk in (details.get(_path) or []):
            kv = {it.get("kpath"): it.get("value")
                  for it in (blk.get("items") or [])}
            ws = kv.get("workspacePath")
            if not ws:
                continue
            ws = str(ws)
            if ws in seen:
                continue
            seen.add(ws)
            rows.append({
                "ws": ws,
                "raw": kv.get("lastCompressedSize.workspaceSizeBytes"),
                "enc": kv.get("lastCompressedSize.encryptedSizeBytes"),
                "accepted": bool(kv.get("lastAcceptedManifestHash")),
                "ts": kv.get("lastCompressedSize.recordedAt"),
                "fail": kv.get("failureCount"),
            })
    rows.sort(key=lambda r: -float(r.get("raw") or 0))
    return rows


def _proj_html(rows):
    """② 我的哪些项目被打包过。

    ★ 数据源**只有** `scan["details"]`（`host-scan --json` 里就有），**零新增采集**。
      填的是工具自己记下的**打包快照**：上次打包那一刻的工作区大小、加密后多大、
      服务器有没有确认收到、什么时候打的。

    ★★ 两个数**不许并排成一句**：`workspaceSizeBytes` 是**上次打包那一刻**的快照，
      而「这个目录现在有多少条目」是另一条轴（需实时遍历目录）⇒ 并排会被读成
      「X MB 由 N 个文件组成」（v1.11 §36.1 T-1）。条目数**不在本组**，
      组尾给终端命令指路（减法留账第三列：信息去哪了）。

    ★ 四个项目目录同在 `C:\\Users\\<你>\\.zcode` **一个键下的多个块**里
      ⇒ 必须遍历**块**，不能只遍历键（只遍历键会只剩一行）。
    """
    if not rows:
        return ("<p class='muted'>这次没找到「打包过项目」的记录"
                " —— <b>不等于没打包过</b>。</p>")
    out = ["<p class='muted small'>这一组只读工具自己记下的打包快照，"
           "不看你的项目内容。</p>"]
    for r in rows:
        ws = r["ws"]
        try:
            raw_n, enc_n = float(r.get("raw") or 0), float(r.get("enc") or 0)
        except Exception:
            continue
        row = "<div class='row'><div class='pn'>%s</div>" % html.escape(ws)
        if not raw_n:
            out.append(row + "<div class='pt muted'>这次没读到它打包时多大。"
                             "</div></div>")
            continue
        _ratio = ("（压缩 <b>%.1f</b> 倍）" % (raw_n / enc_n)) if enc_n else ""
        row += ("<div class='pt'>上次打包时 %s　→　加密后 %s%s"
                % (html.escape(str(_fmt_bytes(raw_n))),
                   html.escape(str(_fmt_bytes(enc_n))), _ratio))
        if r.get("accepted"):
            row += "　·　服务器收下了"
        else:
            row += ("　·　<b>服务器没有确认收到</b>"
                    " —— 这包可能没发出去")
        _ts = r.get("ts")
        if _ts:
            try:
                # ★ 用 time 而不是 datetime —— 本文件已 import time，
                #   不为一次日期格式化新增一个 import。
                row += "　·　打包于 %s" % time.strftime(
                    "%Y-%m-%d", time.localtime(float(_ts) / 1000.0))
            except Exception:
                pass
        row += "</div>"
        if r.get("fail"):
            row += "<div class='pt muted'>它试了 %d 次才成。</div>" % int(r["fail"])
        row += ("<div class='pt muted'>传出去的是压缩后的包，"
                "不是你的明文源码。</div></div>")
        out.append(row)
    out.append("<p class='muted small'>想看每个目录现在有多少条目，"
               "在终端跑：<code>antinel host-audit</code></p>")
    return "".join(out)


def _result_html(res, verdicts, ev_human):
    scan = res.get("scan") or {}
    # ★ details 的键是工具根路径 —— 与 tools[].path 对齐（见 antinel.py 的 JSON 段）。
    scan.setdefault("details", scan.get("details") or {})
    tools = scan.get("tools") or []
    vc = scan.get("counts_by_verdict") or {}
    cov = scan.get("coverage") or {}
    blind_n = int(cov.get("unscanned") or 0)

    head = []
    # ★★★ 最高纪律：「没查到」必须与「没发现」长得不一样，且首屏就报。
    if blind_n:
        # ★ 0.47.0：分子（没查到几个）＋ 分母（一共查了几个）⇒ 读者才知道"没查到"占多大。
        head.append(
            "<div class='blind'><b>⚫ 有 %d 个地方监理没查到"
            "（这次一共查了 %d 个地方）。</b><br>"
            "它们登记过、你电脑上也确实存在，但这次扫描没走到 —— "
            "<b>请把它们当空白读，不要当成「没问题」。</b></div>"
            % (blind_n, len(tools)))
    else:
        head.append("<div class='warn'>登记过的地方这次<b>全部走到了</b>"
                    "（没查到 0 个）。</div>")

    n_ev = int(vc.get("PACK", 0)) + int(vc.get("SENT", 0)) + int(vc.get("SYNC", 0))
    if n_ev:
        head.append("<div class='warn'><b>有 %d 个工具"
                    "（这次一共查了 %d 个地方）在自己的文件里"
                    "写下了「打包／上传／推送／同步」这类字样。</b><br>"
                    "那是<b>它自己承认</b>的，不是监理抓到它在发 —— "
                    "监理的能力只到「读它写下的字」。</div>" % (n_ev, len(tools)))

    # ★ 0.53.0（T-8）：**两个口径都给，各自标分母**。
    #   甲＝这次扫出来多少条（页面原本就只用它）；乙＝登记表写了多少、本机存在多少
    #   （终端 `host-scan` 的人读输出用这一套）。两个数**互不包含**（实测：59 vs 43/41），
    #   只给一个 ⇒ 用户拿页面与终端对账时对不上，而两边都没说错。
    #   ⇒ 这里一句里同时给，是唯一不用读者自己折算的做法。
    if int(cov.get("registered_roots") or 0):
        _walked = ("这次<b>全部走到了</b> —— 没查到 0 个。" if not blind_n
                   else "这次<b>还有 %d 个没走到</b>。" % blind_n)
        head.append(
            "<p>这次扫到 <b>%d</b> 个 AI 工具（其中 <b>%d</b> 个是靠登记表补上的）；"
            "登记表里写的 <b>%d</b> 个位置，你电脑上存在 <b>%d</b> 个，%s</p>"
            % (len(tools), int(cov.get("added_by_registry") or 0),
               int(cov.get("registered_roots") or 0),
               int(cov.get("present") or 0), _walked))

    _projs = _proj_rows(scan.get("details"))
    body = [
        "<h2>① 我电脑上有哪些 AI 工具（%d 个）</h2>" % len(tools),
        _tiles(vc, verdicts, blind_n, total=len(tools)),
        "<p class='muted small'>六档是这么分的：🔴 自认打包过 ＞ 🟠 自认往外发过 ＞ "
        "🟡 自认在同步 ＞ ⚪ 查过、没发现记录 ＞ ⚫ 没查到 ＞ · 不适用。</p>",
        "<h2>逐个看</h2>",
        _rows_html(tools, verdicts, ev_human, scan.get("details")),
        "<h2>② 我的哪些项目被打包过（%d 个）</h2>" % len(_projs),
        _proj_html(_projs),
        "<h2>③ 此刻谁在往外连</h2>",
        _egress_html(res.get("egress")),
        _conns_html(res.get("egress")),
        _canary_html(res.get("canary")),
        "<h2>④ 别处还有什么</h2>",
        _obs_html(scan.get("observations")),
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
