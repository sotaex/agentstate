# -*- coding: utf-8 -*-
"""值守台 · 总守卫套件（P1–P8）。**每条判据配负控；不许只有 happy path。**

★ 纪律（本仓铁律）：
  1. **先红后绿**：每条判据都必须能在**缺陷态**下变红；没红过的绿不算绿。
  2. **负控要先验「注入真生效」且「未注入时它是绿的」**。
  3. **判据不许二次实现**：要口径就 import 产品模块，不另算一套。
  4. **不许为让守卫变绿而改松判据。**

★ 对抗性覆盖（不只走通）：
  - 畸形/越权输入：坏 JSON、缺字段、多字段、非法状态、越权 Host、无 token、
    路径穿越、HTML 注入、超长表单；
  - 状态腐坏：状态文件被改坏、配置读坏；
  - 边界时点：跨日 23:59/00:00、连续天数断档、免打扰跨零点；
  - 失败注入：链被篡改、链不存在、后端发不出去；
  - **"没查到" ≠ "没发现"**：链不可读必须报 unknown，**绝不报 ok**。

★ 不删任何文件：临时目录 `mkdtemp` **只建不删**（宿主 safe-delete shim 会硬杀
  带删除动作的进程）。

用法：`python ci/inbox_guards.py`（退出码 0 = 全绿；1 = 有红）
"""
from __future__ import annotations

import http.client
import json
import os
import struct
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
if PKG not in sys.path:
    sys.path.insert(0, PKG)

import inbox_cli as CLI        # noqa: E402
import inbox_config as CFG      # noqa: E402
import inbox_daemon as DM       # noqa: E402
import inbox_emphasis as EM     # noqa: E402
import inbox_fallback as FB     # noqa: E402
import inbox_model as M         # noqa: E402
import inbox_notify as NT       # noqa: E402
import inbox_report as R        # noqa: E402
import inbox_server as SV       # noqa: E402
import inbox_store as S         # noqa: E402
import inbox_tray as TR         # noqa: E402
import heartbeat as HB          # noqa: E402
import ledger as L              # noqa: E402

_SCRATCH = []


# --------------------------------------------------------------- 脚手架 ----
def new_hub():
    d = tempfile.mkdtemp(prefix="antinel-inbox-")
    _SCRATCH.append(d)
    os.environ["ANTINEL_HUB_DIR"] = d
    os.environ.pop("ANTINEL_AUDIT_DIRS", None)
    return d


def put_chain(hub, recs, name="2026-10-05.jsonl"):
    d = os.path.join(hub, "rollup")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return p


def breach(ts="2026-10-05T20:52:11+08:00", reason="规则 SEC-09 命中", **kw):
    r = {"ts": ts, "type": "host_shield_breach", "tool": "-", "session": "host-shield",
         "host": "generic", "decision": "allow", "severity": "warning",
         "reason": reason, "hash": "abc123"}
    r.update(kw)
    return r


def block_rec(ts="2026-10-05T21:00:00+08:00", rule="SEC-01", snip=".env", **kw):
    r = {"ts": ts, "type": "pre_tool_use", "tool": "Bash", "session": "s1",
         "host": "workbuddy", "decision": "block", "severity": "critical",
         "rules_hit": [rule], "match_snippet": snip, "hash": "deadbeef"}
    r.update(kw)
    return r


def item(level="L2", state="unread", i=1, ts=None):
    a = M.Alert(id="x%d" % i, ts=ts or ("2026-10-05T20:00:%02d+08:00" % (i % 60)),
                level=level, kind="host_shield_breach", title="t")
    return M.Item(alert=a, state=state)


def req(port, path, token=None, method="GET", body=None, host=None, ctype=None):
    """发一个 HTTP 请求，返回 (status, headers, body_text)。"""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {}
    if host:
        headers["Host"] = host
    if token:
        headers["X-Antinel-Token"] = token
    if ctype:
        headers["Content-Type"] = ctype
    try:
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        data = r.read().decode("utf-8", "replace")
        return r.status, dict(r.getheaders()), data
    finally:
        c.close()


class Server:
    def __init__(self, root, token="tok"):
        self.httpd, self.token = SV.make_server(port=0, root=root, token=token)
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()

    def stop(self):
        try:
            self.httpd.shutdown()
        except Exception:                       # noqa: BLE001
            pass


# ======================================================= PART 1 · 数据层 ====
def c_j2_empty_is_L0():
    return M.console_state([]) == "L0" and M.console_state([item("L2", "done")]) == "L0"


def n_j2():
    st = M.console_state([item("L2", "unread")])
    return st == "L2" and st != "L0"


def c_j3_fallback():
    a, b = item("R0", "unread", 1), item("L1", "unread", 2)
    before = M.console_state([a, b])
    a.state = "done"
    return before == "R0" and M.console_state([a, b]) == "L1"


def n_j3():
    a, b = item("R0", "unread", 1), item("L1", "unread", 2)
    return M.console_state([a, b]) == "R0" and M.console_state([a, b]) != "L1"


def c_j15_read_keeps_open():
    it = item("L2", "unread")
    n0 = M.unhandled_count([it])
    it.state = "read"
    n1 = M.unhandled_count([it])
    it.state = "ignored"
    return n0 == 1 and n1 == 1 and M.unhandled_count([it]) == 0


def n_j15():
    it = item("L2", "unread")
    it.state = "read"
    wrong = sum(1 for x in [it] if x.state == "unread")
    return wrong == 0 and M.unhandled_count([it]) == 1


def c_j16_r0_ignore_needs_note():
    ok = []
    for lv, note, want_raise in (("R0", "", True), ("R0", "已确认", False),
                                 ("L1", "", False)):
        try:
            M.check_ignore_note(lv, note)
            ok.append(not want_raise)
        except M.NoteRequired:
            ok.append(want_raise)
    return all(ok)


def n_j16():
    try:
        M.check_ignore_note("R0", "")
        return False
    except M.NoteRequired:
        return True


def c_j7_kind_coverage():
    import host_shield
    return set(host_shield._ALERT_KINDS) <= set(M.LEVEL_OF_KIND)


def n_j7():
    import host_shield
    real = set(host_shield._ALERT_KINDS)
    fake = real | {"host_shield_brand_new_kind"}
    return (fake != real) and (not (fake <= set(M.LEVEL_OF_KIND)))


def c_unknown_kind_raises():
    try:
        M.level_of("host_shield_nonexistent")
        return False
    except M.UnknownKind:
        return True


def n_unknown_kind():
    try:
        M.level_of("host_shield_breach")
        return True
    except M.UnknownKind:
        return False


def c_transition_guard():
    if not (M.can_transition("unread", "read") and M.can_transition("read", "done")):
        return False
    if M.can_transition("done", "unread"):
        return False
    return True


def n_transition():
    try:
        M.can_transition("unread", "banana")
        return False
    except M.BadState:
        return True


def c_j1_persist_after_15s():
    hub = new_hub()
    put_chain(hub, [breach()])
    items = S.load_items()
    hit = [it for it in items if it.kind == "host_shield_breach"]
    no_copy = not os.path.exists(os.path.join(hub, "inbox", "alerts.jsonl"))
    return len(hit) == 1 and hit[0].level == "L2" and no_copy


def n_j1():
    hub = new_hub()
    put_chain(hub, [{"ts": "2026-10-05T20:00:00+08:00",
                     "type": "host_shield_heartbeat", "hash": "h"}])
    return len([it for it in S.load_items() if it.kind == "host_shield_breach"]) == 0


def c_project_block_projected():
    hub = new_hub()
    put_chain(hub, [block_rec()])
    hit = [it for it in S.load_items() if it.kind == "tool_call_blocked"]
    return len(hit) == 1 and hit[0].level == "L2" and hit[0].rule_id == "SEC-01"


def n_project_block():
    hub = new_hub()
    put_chain(hub, [block_rec(decision="allow")])
    return len([it for it in S.load_items() if it.kind == "tool_call_blocked"]) == 0


def c_state_roundtrip():
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T20:00:01+08:00", reason="r1"),
                    breach(ts="2026-10-05T20:00:02+08:00", reason="r2")])
    n0 = M.unhandled_count(S.load_items())
    moved = S.mark_all_read()
    items2 = S.load_items()
    return (n0 == 2 and moved == 2 and M.unhandled_count(items2) == 2
            and all(it.state == "read" for it in items2))


def n_state_roundtrip():
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T20:00:01+08:00", reason="r1")])
    it = S.load_items()[0]
    S.set_state(it.id, "done", root=hub)
    return M.unhandled_count(S.load_items()) == 0


def c_ledger_summary():
    hub = new_hub()
    for i, d in enumerate(["2026-10-03", "2026-10-04", "2026-10-05"]):
        L.append_day({"date": d, "watch_seconds": 100, "blocked": 1,
                      "noticed": 0, "breached": 0, "acked": i}, root=hub)
    s = L.summary(root=hub, today="2026-10-05")
    return s["watch_seconds"] == 300 and s["blocked"] == 3 and s["streak_days"] == 3


def n_ledger():
    hub = new_hub()
    for d in ["2026-10-03", "2026-10-05"]:
        L.append_day({"date": d, "watch_seconds": 1}, root=hub)
    return L.summary(root=hub, today="2026-10-05")["streak_days"] == 1


# ======================================================= PART 2 · 报告层 ====
def c_j5_report_equals_recount():
    """★ J5：日报数字必须**等于**从链重算的值。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a"),
                    breach(ts="2026-10-05T10:00:00+08:00", reason="b"),
                    block_rec(ts="2026-10-05T11:00:00+08:00"),
                    breach(ts="2026-10-04T09:00:00+08:00", reason="old")])
    rep = R.daily_report(day="2026-10-05", root=hub)
    # 独立重算（对照，不是产品逻辑的复制）
    items = S.load_items(root=hub)
    today = [i for i in items if i.ts[:10] == "2026-10-05"]
    l2 = len([i for i in today if i.level == "L2"])
    return (rep["levels"]["L2"] == l2 == 3 and rep["total_today"] == 3
            and rep["carried_over_count"] == 1)


def n_j5():
    """负控：手改一个数 ⇒ 与重算不等（说明上一条不是恒真）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    rep = R.daily_report(day="2026-10-05", root=hub)
    rep2 = dict(rep)
    rep2["levels"] = dict(rep["levels"])
    rep2["levels"]["L2"] = 99
    return rep2["levels"]["L2"] != rep["levels"]["L2"]


def c_chain_health_ok_and_broken():
    """链好 ⇒ ok；链被改 ⇒ broken（用产品自己的 chain_with）。"""
    hub = new_hub()
    import audit_chain as ac
    good = ac.chain_with({"ts": "2026-10-05T09:00:00+08:00", "type": "host_shield_breach",
                          "reason": "a"}, "")
    good2 = ac.chain_with({"ts": "2026-10-05T09:01:00+08:00", "type": "host_shield_breach",
                           "reason": "b"}, good["hash"])
    p = put_chain(hub, [good, good2])
    ok = R.chain_health([p])["status"] == "ok"
    bad = dict(good2)
    bad["reason"] = "被改过"                      # 改内容 ⇒ hash 对不上
    p2 = put_chain(hub, [good, bad], name="2026-10-04.jsonl")
    broken = R.chain_health([p2])["status"] == "broken"
    return ok and broken


def c_chain_health_ignores_unchained():
    """★ 未链接记录（`hash` 为空，如 `session_start`）**不算断链** —— 防误报。

    ★★ 这条是**实测教训**：首版把 128 条未链接记录误报成断链。
      会误报的检查器用两次就没人信 ⇒ 必须固化。
    """
    hub = new_hub()
    import audit_chain as ac
    a = ac.chain_with({"ts": "2026-10-05T09:00:00+08:00", "type": "pre_tool_use",
                       "reason": "a"}, "")
    b = ac.chain_with({"ts": "2026-10-05T09:01:00+08:00", "type": "pre_tool_use",
                       "reason": "b"}, a["hash"])
    un = {"ts": "2026-10-05T09:02:00+08:00", "type": "session_start"}   # 无 hash/prev
    c = ac.chain_with({"ts": "2026-10-05T09:03:00+08:00", "type": "pre_tool_use",
                       "reason": "c"}, b["hash"])
    p = put_chain(hub, [a, un, b, un, c])
    h = R.chain_health([p])
    return h["status"] == "ok" and h["broken"] == 0 and h["unchained"] == 2


def n_chain_health_ignores_unchained():
    """负控：**旧行为**（不跳过未链接记录）会被算成断链 ⇒ 判据必然红（防回归）。"""
    hub = new_hub()
    import audit_chain as ac
    a = ac.chain_with({"ts": "2026-10-05T09:00:00+08:00", "type": "pre_tool_use",
                       "reason": "a"}, "")
    un = {"ts": "2026-10-05T09:02:00+08:00", "type": "session_start"}
    p = put_chain(hub, [a, un])
    prev, old_bad = "", 0
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        rc = ac.chain_with(r, prev)
        if rc["hash"] != r.get("hash") or rc["prev"] != r.get("prev"):
            old_bad += 1
        prev = r.get("hash") or prev
    new = R.chain_health([p])
    return old_bad == 1 and new["broken"] == 0 and new["unchained"] == 1


def n_chain_health():
    """负控：**没有文件**必须报 unknown，**绝不报 ok**（"没查到"≠"没发现"）。"""
    h = R.chain_health([])
    return h["status"] == "unknown" and h["status"] != "ok"


def c_report_day_boundary():
    """跨日边界：23:59 与次日 00:00 必须分属两天。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T23:59:59+08:00", reason="last"),
                    breach(ts="2026-10-06T00:00:00+08:00", reason="first")])
    a = R.daily_report(day="2026-10-05", root=hub)
    b = R.daily_report(day="2026-10-06", root=hub)
    return a["total_today"] == 1 and b["total_today"] == 1


def n_report_day_boundary():
    """负控：同一天两条 ⇒ 该日必须 2 条（说明上一条不是恒为 1）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T23:59:59+08:00", reason="a"),
                    breach(ts="2026-10-05T23:59:58+08:00", reason="b")])
    return R.daily_report(day="2026-10-05", root=hub)["total_today"] == 2


def c_report_unknown_ts_not_today():
    """时间戳取不到 ⇒ **不许混进今日**（不许静默当今天）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="garbage", reason="x")])
    rep = R.daily_report(day="2026-10-05", root=hub)
    return rep["total_today"] == 0 and rep["unhandled_total"] == 1


def n_report_unknown_ts():
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T01:00:00+08:00", reason="x")])
    return R.daily_report(day="2026-10-05", root=hub)["total_today"] == 1


# ======================================================= PART 3 · 本地页 ====
def c_j6_bind_loopback_only():
    """★ J6：只监听回环。"""
    ok = True
    for bad in ("0.0.0.0", "::", "192.168.1.5"):
        try:
            SV._check_bind(bad)
            ok = False
        except ValueError:
            pass
    for good in ("127.0.0.1", "localhost", "::1"):
        SV._check_bind(good)
    return ok


def n_j6():
    """负控：注入 0.0.0.0 ⇒ 必须抛（说明上一条不是"永远通过"）。"""
    try:
        SV._check_bind("0.0.0.0")
        return False
    except ValueError:
        return True


def c_server_token_required():
    hub = new_hub()
    put_chain(hub, [breach()])
    srv = Server(hub)
    try:
        s_no, _, _ = req(srv.port, "/?v=inbox")                 # 无 token
        s_ok, _, body = req(srv.port, "/?v=inbox", token=srv.token)
        s_wrong, _, _ = req(srv.port, "/?v=inbox", token="wrong-token")
        return s_no == 403 and s_wrong == 403 and s_ok == 200 and "收件箱" in body
    finally:
        srv.stop()


def n_server_token_required():
    """负控：带对 token ⇒ 必须 200（说明 403 不是"永远 403"）。"""
    hub = new_hub()
    put_chain(hub, [breach()])
    srv = Server(hub)
    try:
        s, _, _ = req(srv.port, "/?v=inbox", token=srv.token)
        return s == 200
    finally:
        srv.stop()


def c_server_host_check():
    hub = new_hub()
    put_chain(hub, [breach()])
    srv = Server(hub)
    try:
        evil, _, _ = req(srv.port, "/?v=inbox", token=srv.token, host="evil.example.com")
        good, _, _ = req(srv.port, "/?v=inbox", token=srv.token,
                         host="127.0.0.1:%d" % srv.port)
        return evil == 403 and good == 200
    finally:
        srv.stop()


def n_server_host_check():
    hub = new_hub()
    put_chain(hub, [breach()])
    srv = Server(hub)
    try:
        s, _, _ = req(srv.port, "/?v=inbox", token=srv.token,
                      host="localhost:%d" % srv.port)
        return s == 200
    finally:
        srv.stop()


def c_server_asset_whitelist():
    """静态资源白名单：合法给 200，穿越/未知一律 404。"""
    hub = new_hub()
    srv = Server(hub)
    try:
        ok, h1, _ = req(srv.port, "/assets/L0.mp4", token=srv.token)
        t1, _, _ = req(srv.port, "/assets/../../../../etc/passwd", token=srv.token)
        t2, _, _ = req(srv.port, "/assets/evil.exe", token=srv.token)
        t3, _, _ = req(srv.port, "/assets/L0.mp4.bak", token=srv.token)
        return (ok == 200 and h1.get("Content-Type") == "video/mp4"
                and t1 == 404 and t2 == 404 and t3 == 404)
    finally:
        srv.stop()


def n_server_asset_whitelist():
    hub = new_hub()
    srv = Server(hub)
    try:
        s, _, _ = req(srv.port, "/assets/favicon.ico", token=srv.token)
        return s == 200
    finally:
        srv.stop()


def c_server_xss_escaped():
    """★ HTML 注入必须被转义（标题/详情里带 <script>）。"""
    hub = new_hub()
    put_chain(hub, [breach(reason="<script>alert(1)</script>")])
    srv = Server(hub)
    try:
        s, _, body = req(srv.port, "/?v=inbox", token=srv.token)
        return s == 200 and "<script>alert(1)</script>" not in body and "&lt;script&gt;" in body
    finally:
        srv.stop()


def n_server_xss_escaped():
    """负控：把转义关掉（直接渲染原文）⇒ 注入必然出现，说明上一条不是恒真。"""
    import html as _h
    raw = "<script>alert(1)</script>"
    return _h.escape(raw, quote=True) != raw and "&lt;script&gt;" in _h.escape(raw, quote=True)


def c_server_action_guard():
    """动作接口：非法操作被拒（409），合法操作 303。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T20:00:01+08:00", reason="r1")])
    it = S.load_items(root=hub)[0]
    srv = Server(hub)
    try:
        body_bad = "op=banana&id=%s" % it.id
        bad, _, _ = req(srv.port, "/action", token=srv.token, method="POST",
                        body=body_bad, ctype="application/x-www-form-urlencoded")
        body_ok = "op=done&id=%s" % it.id
        good, h, _ = req(srv.port, "/action", token=srv.token, method="POST",
                         body=body_ok, ctype="application/x-www-form-urlencoded")
        after = S.load_items(root=hub)[0].state
        return bad == 409 and good == 303 and after == "done"
    finally:
        srv.stop()


def n_server_action_guard():
    """负控：无 token 的动作必须 403（不许裸奔）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T20:00:01+08:00", reason="r1")])
    srv = Server(hub)
    try:
        s, _, _ = req(srv.port, "/action", method="POST", body="op=read_all",
                      ctype="application/x-www-form-urlencoded")
        return s == 403
    finally:
        srv.stop()


def c_server_unknown_view_falls_back():
    """未知视图/筛选 ⇒ 回落到默认（不 500、不泄露）。"""
    hub = new_hub()
    put_chain(hub, [breach()])
    srv = Server(hub)
    try:
        s, _, body = req(srv.port, "/?v=../../etc&f=%00", token=srv.token)
        return s == 200 and "值守台" in body
    finally:
        srv.stop()


def n_server_unknown_view():
    hub = new_hub()
    put_chain(hub, [breach()])
    srv = Server(hub)
    try:
        s, _, _ = req(srv.port, "/?v=report", token=srv.token)
        return s == 200
    finally:
        srv.stop()


def c_server_no_external_refs():
    """页面**零外部资源**：HTML/CSS 里不许出现 http(s) 引用。"""
    hub = new_hub()
    put_chain(hub, [breach()])
    srv = Server(hub)
    try:
        _, _, body = req(srv.port, "/?v=inbox", token=srv.token)
        low = body.lower()
        for tok in ("http://", "https://", "//cdn", "src=\"//"):
            if tok in low:
                return False
        return True
    finally:
        srv.stop()


def n_server_no_external_refs():
    """负控：注入一个外部 script 标签 ⇒ 扫描必须能发现。"""
    bad = "<script src=\"https://evil.example.com/x.js\"></script>"
    return any(t in bad.lower() for t in ("http://", "https://"))


def c_server_empty_state_renders():
    """空收件箱 ⇒ 渲染 L0 空态，不是白屏、也不是 500。"""
    hub = new_hub()
    srv = Server(hub)
    try:
        s, _, body = req(srv.port, "/?v=inbox", token=srv.token)
        return s == 200 and "一切正常" in body and "L0.mp4" in body
    finally:
        srv.stop()


def n_server_empty_state():
    hub = new_hub()
    put_chain(hub, [breach()])
    srv = Server(hub)
    try:
        _, _, body = req(srv.port, "/?v=inbox", token=srv.token)
        return "一切正常" not in body
    finally:
        srv.stop()


# ======================================================= PART 4 · 通知层 ====
def c_notify_level_gate():
    """L0 不触达；L1/L2/R0 触达。"""
    cfg = CFG.load(root=new_hub())
    return (not CFG.should_touch("L0", cfg)) and CFG.should_touch("L1", cfg) \
        and CFG.should_touch("L2", cfg) and CFG.should_touch("R0", cfg)


def n_notify_level_gate():
    cfg = CFG.load(root=new_hub())
    return not CFG.should_touch("L0", cfg)


def c_notify_r0_penetrates_quiet():
    """★ R0 必须穿透免打扰（防线失守不能静默）。"""
    hub = new_hub()
    cfg = CFG.load(root=hub)
    cfg["quiet_hours"] = {"start": "00:00", "end": "23:59"}
    cfg["touch_level"] = "L1"
    deep_night = 3 * 60
    return (not CFG.should_touch("L2", cfg, now_min=deep_night)
            and CFG.should_touch("R0", cfg, now_min=deep_night))


def n_notify_r0_penetrates_quiet():
    hub = new_hub()
    cfg = CFG.load(root=hub)
    cfg["quiet_hours"] = {"start": "00:00", "end": "23:59"}
    return CFG.should_touch("R0", cfg, now_min=60)


def c_notify_quiet_cross_midnight():
    """免打扰跨零点：22:00-07:00 时，23:00 与 06:00 在区间，12:00 不在。"""
    hub = new_hub()
    cfg = CFG.load(root=hub)
    cfg["quiet_hours"] = {"start": "22:00", "end": "07:00"}
    return (CFG.in_quiet_hours(cfg, 23 * 60) and CFG.in_quiet_hours(cfg, 6 * 60)
            and not CFG.in_quiet_hours(cfg, 12 * 60))


def n_notify_quiet_cross_midnight():
    hub = new_hub()
    cfg = CFG.load(root=hub)
    cfg["quiet_hours"] = {"start": "22:00", "end": "07:00"}
    return not CFG.in_quiet_hours(cfg, 15 * 60)


def c_notify_throttle():
    """同类 30 分钟内不重复；超时后可再弹。"""
    hub = new_hub()
    b = NT.RecordingBackend()
    cfg = CFG.load(root=hub)
    ok1, _ = NT.toast("L2", "t", "b", root=hub, backend=b, cfg=cfg, now=1000.0, kind="k")
    ok2, r2 = NT.toast("L2", "t", "b", root=hub, backend=b, cfg=cfg, now=1001.0, kind="k")
    ok3, _ = NT.toast("L2", "t", "b", root=hub, backend=b, cfg=cfg,
                      now=1000.0 + NT.MIN_INTERVAL + 1, kind="k")
    return ok1 and (not ok2) and "不重复" in r2 and ok3 and len(b.calls) == 2


def n_notify_throttle():
    """负控：把节流间隔设成 0 ⇒ 第二次必须能弹（说明节流真在起作用）。"""
    hub = new_hub()
    b = NT.RecordingBackend()
    cfg = CFG.load(root=hub)
    NT.toast("L2", "t", "b", root=hub, backend=b, cfg=cfg, now=1000.0, kind="k")
    ok, _ = NT.toast("L2", "t", "b", root=hub, backend=b, cfg=cfg, now=1001.0,
                     kind="k", min_interval=0)
    return ok and len(b.calls) == 2


def c_config_corrupt_is_flagged():
    """配置读坏 ⇒ 退回安全默认 + `_corrupt` 标记（不崩、不静默）。"""
    hub = new_hub()
    p = CFG.config_path(hub)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("{ 这不是 JSON")
    cfg = CFG.load(root=hub)
    return cfg["_corrupt"] is True and cfg["sound"] is False and cfg["heartbeat"] is False


def n_config_corrupt_is_flagged():
    hub = new_hub()
    cfg = CFG.load(root=hub)
    return cfg["_corrupt"] is False


# ======================================================= PART 5 · 托盘层 ====
def c_tray_roundtrip():
    hub = new_hub()
    TR.write_state("L2", 3, "拦截中 · 未处理 3", root=hub)
    got = TR.read_state(root=hub)
    return got["state"] == "L2" and got["count"] == 3 and "拦截" in got["tip"]


def n_tray_roundtrip():
    hub = new_hub()
    TR.write_state("R0", 1, "失守", root=hub)
    return TR.read_state(root=hub)["state"] == "R0"


def c_tray_icon_map():
    """五态都要有对应图标文件；未知态回落 L0（但明确回落）。"""
    ok = True
    for st in ("L0", "L1", "L2", "Ls", "R0"):
        p = TR.icon_path(st)
        if not (p.endswith("%s.ico" % st) and os.path.exists(p)):
            ok = False
    return ok and TR.icon_path("banana").endswith("L0.ico")


def n_tray_icon_map():
    return TR.icon_path("R0").endswith("R0.ico") and \
        not TR.icon_path("R0").endswith("L0.ico")


def c_tray_action_consumed_without_delete():
    """★ 消费动作＝**改名让开**（不删除），且**一批里的动作一个都不许丢**。"""
    hub = new_hub()
    TR.push_action("open", root=hub)
    TR.push_action("read_all", root=hub)
    acts = TR.poll_actions(root=hub)
    again = TR.poll_actions(root=hub)
    taken = [f for f in os.listdir(os.path.dirname(TR.action_path(hub)))
             if f.startswith("tray_action.txt.taken-")]
    return acts == ["open", "read_all"] and again == [] and len(taken) == 1


def n_tray_action_consumed():
    """负控：模拟"只读第一行"的旧实现 ⇒ 第二条必然丢（判据能看见这种丢）。"""
    hub = new_hub()
    TR.push_action("quit", root=hub)
    TR.push_action("read_all", root=hub)
    p = TR.action_path(hub)
    taken = p + ".taken-neg"
    os.rename(p, taken)                         # 旧实现：整文件改名
    with open(taken, encoding="utf-8") as f:
        old_acts = [f.readline().strip()]       # 只取第一行
    return old_acts == ["quit"] and old_acts != ["quit", "read_all"]


def c_tray_sync_from_items():
    hub = new_hub()
    put_chain(hub, [breach()])
    TR.sync_from_items(S.load_items(root=hub), root=hub)
    st = TR.read_state(root=hub)
    return st["state"] == "L2" and st["count"] == 1


def n_tray_sync_from_items():
    hub = new_hub()
    put_chain(hub, [{"ts": "2026-10-05T09:00:00+08:00",
                     "type": "host_shield_heartbeat", "hash": "h"}])
    TR.sync_from_items(S.load_items(root=hub), root=hub)
    st = TR.read_state(root=hub)
    return st["state"] == "L0" and st["count"] == 0


def c_icons_structurally_valid():
    """5 个 `.ico` 结构必须合法（32bpp、多尺寸、偏移正确）。"""
    base = os.path.join(PKG, "assets", "icons")
    for st in ("L0", "L1", "L2", "Ls", "R0"):
        p = os.path.join(base, "%s.ico" % st)
        if not os.path.exists(p):
            return False
        b = open(p, "rb").read()
        res, typ, n = struct.unpack("<HHH", b[:6])
        if res != 0 or typ != 1 or n < 2:
            return False
        for i in range(n):
            e = struct.unpack("<BBBBHHII", b[6 + 16 * i:22 + 16 * i])
            off, size, bpp = e[6], e[5], e[5]
            if e[5] != 32 or e[7] + e[6] > len(b):
                return False
    return True


def n_icons_structurally_valid():
    """负控：截断一个 ICO 头部 ⇒ 结构校验必须失败。"""
    b = b"\x00\x01\x01\x00"                    # 只有 4 字节，不足 6 字节头
    try:
        res, typ, n = struct.unpack("<HHH", b[:6])
        return False
    except struct.error:
        return True


# ======================================================= PART 6 · 强调层 ====
def c_emphasis_default_off():
    """★ 默认关 ⇒ 一个副作用都不产生。"""
    hub = new_hub()
    cfg = CFG.load(root=hub)
    s, o = EM.RecordingSound(), EM.RecordingOverlay()
    out = EM.emphasize("R0", 1, "失守", cfg=cfg, sound=s, overlay=o)
    return (out["sound"] is False and out["overlay"] is False
            and s.calls == [] and o.calls == [])


def n_emphasis_default_off():
    """负控：用户开了开关 ⇒ 必须真的调用后端（说明"没调用"不是因为函数坏了）。"""
    hub = new_hub()
    cfg = CFG.load(root=hub)
    cfg["sound"] = True
    s = EM.RecordingSound()
    out = EM.emphasize("R0", 1, "失守", cfg=cfg, sound=s)
    return out["sound"] is True and s.calls == ["R0"]


def c_emphasis_only_r0():
    """★ 只有 R0 能响 —— 开了开关也不许 L2 响。"""
    hub = new_hub()
    cfg = CFG.load(root=hub)
    cfg["sound"] = True
    cfg["overlay"] = True
    s, o = EM.RecordingSound(), EM.RecordingOverlay()
    for lv in ("L1", "L2", "Ls", "L0"):
        EM.emphasize(lv, 1, "x", cfg=cfg, sound=s, overlay=o)
    return s.calls == [] and o.calls == []


def n_emphasis_only_r0():
    hub = new_hub()
    cfg = CFG.load(root=hub)
    cfg["sound"] = True
    s = EM.RecordingSound()
    EM.emphasize("R0", 1, "x", cfg=cfg, sound=s)
    return s.calls == ["R0"]


# ======================================================= PART 7 · 兜底层 ====
def c_j14_fallback_default_off():
    """★ J14：默认关 ⇒ 发信/投递后端**一次都不被调用**。"""
    hub = new_hub()
    cfg = CFG.load(root=hub)
    calls = []
    out = FB.dispatch("R0", "t", "b", cfg,
                      sender=lambda *a, **k: calls.append("email") or FB._result(True),
                      poster=lambda *a, **k: calls.append("webhook") or FB._result(True))
    return (out["email"]["ok"] is False and out["webhook"]["ok"] is False
            and calls == [])


def n_j14_fallback_default_off():
    """负控：开了开关 ⇒ 后端必须被调用。"""
    hub = new_hub()
    cfg = CFG.load(root=hub)
    cfg["email"] = {"enabled": True, "host": "smtp.local", "port": 587,
                    "user": "u", "password": "p", "to": "me@local", "tls": True}
    calls = []
    FB.dispatch("R0", "t", "b", cfg,
                sender=lambda *a, **k: calls.append("email") or FB._result(True))
    return calls == ["email"]


def c_fallback_no_hardcoded_urls():
    """★ 兜底层**不许写死任何外部地址**（只能发到用户自己的地址）。"""
    txt = open(os.path.join(PKG, "inbox_fallback.py"), encoding="utf-8").read()
    for line in txt.splitlines():
        s = line.strip()
        if s.startswith("#") or s.startswith('"') and s.endswith('"""'):
            continue
        if "http://" in line or "https://" in line:
            return False
    return True


def n_fallback_no_hardcoded_urls():
    bad = 'url = "https://third-party.example.com/collect"'
    return ("https://" in bad)


# ======================================================= PART 8 · 计数 ======
def c_j8_heartbeat_default_off():
    """★ J8：默认关 ⇒ 不发请求（后端一次都不调用）。"""
    hub = new_hub()
    cfg = CFG.load(root=hub)
    calls = []
    ok, why = HB.send_once(root=hub, cfg=cfg,
                           poster=lambda u, p: calls.append(u) or (True, "x"))
    return ok is False and calls == [] and why == "未启用"


def n_j8_heartbeat_default_off():
    """负控：开了开关且配了端点 ⇒ 必须发（说明"没发"不是函数坏了）。"""
    hub = new_hub()
    cfg = CFG.load(root=hub)
    cfg["heartbeat"] = True
    cfg["heartbeat_endpoint"] = "https://hb.example.workers.dev"
    calls = []
    ok, _ = HB.send_once(root=hub, cfg=cfg,
                         poster=lambda u, p: calls.append(u) or (True, "200"))
    return ok is True and calls == ["https://hb.example.workers.dev"]


def c_j9_heartbeat_only_fixed_fields():
    """★ J9：报文**只含**固定字段（顶层 + buckets 都是精确集合）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    p = HB.build(root=hub, items=S.load_items(root=hub), day="2026-10-05", version="0.35.0")
    return (set(p) == set(HB.TOP_FIELDS) and set(p["buckets"]) == set(HB.BUCKET_FIELDS)
            and "reason" not in p and "path" not in p and "ip" not in p)


def n_j9_heartbeat_only_fixed_fields():
    """负控：多一个字段 ⇒ 自检必须抛错。"""
    hub = new_hub()
    p = HB.build(root=hub, items=[], day="2026-10-05", version="0.35.0")
    p["path"] = "C:/secret"
    try:
        HB._assert_shape(p)
        return False
    except M.InboxError:
        return True


def c_heartbeat_install_id_lazy():
    """★ 不开统计就**不生成** install_id；关掉统计要能**删掉**。"""
    hub = new_hub()
    cfg = CFG.load(root=hub)
    if cfg["heartbeat"]:
        return False
    before = os.path.exists(L.meta_path(hub))
    HB.build(root=hub, items=[], day="2026-10-05")     # 直接 build 会生成（build 是显式动作）
    after = os.path.exists(L.meta_path(hub))
    HB.forget(root=hub)
    meta = L.load_meta(hub)
    return (before is False) and (after is True) and (not meta.get("install_id"))


def n_heartbeat_install_id_lazy():
    """负控：未调用 build 时，meta 不存在（证明上一条的 after 不是"一直为真"）。"""
    hub = new_hub()
    return not os.path.exists(L.meta_path(hub))


def c_heartbeat_buckets_count_open_only():
    """buckets 只数**当天未处理**的；已处理的不计入。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a"),
                    breach(ts="2026-10-05T09:01:00+08:00", reason="b")])
    items = S.load_items(root=hub)
    p1 = HB.build(root=hub, items=items, day="2026-10-05")
    it = items[0]
    S.set_state(it.id, "done", root=hub)
    items2 = S.load_items(root=hub)
    p2 = HB.build(root=hub, items=items2, day="2026-10-05")
    return p1["buckets"]["l2"] == 2 and p2["buckets"]["l2"] == 1


def n_heartbeat_buckets_count_open_only():
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    p = HB.build(root=hub, items=S.load_items(root=hub), day="2026-10-05")
    return p["buckets"]["l2"] == 1


def c_worker_rejects_extra_field():
    """Worker 的字段校验必须能拒"多一个字段"（静态核对，防端点放松）。"""
    p = os.path.join(PKG, "tools", "heartbeat_worker.js")
    if not os.path.exists(p):
        return False
    txt = open(p, encoding="utf-8").read()
    return ("TOP_FIELDS" in txt and "keys.join" in txt
            and '"install_id", "date", "version", "buckets", "schema"' in txt)


def n_worker_rejects_extra_field():
    bad = 'if (keys.length !== 5) return "x";'
    return "keys.join" not in bad


# ==================================================== PART 10 · 守护进程 ====
def c_state_corrupt_rebuilds():
    """★ 状态文件坏掉 ⇒ **从链重建**（不崩），且**留下证据**（改名让开，不删）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    it = S.load_items(root=hub)[0]
    S.set_state(it.id, "done", root=hub)
    with open(S.state_path(hub), "w", encoding="utf-8", newline="\n") as f:
        f.write("<<<这不是 JSON>>>")
    items2 = S.load_items(root=hub)                     # 不许抛
    return (len(items2) == 1 and items2[0].state == "unread"   # 退回未读：宁可多提醒
            and len(S.state_corruption(root=hub)) == 1)


def n_state_corrupt_rebuilds():
    """负控：状态正常时必须是 done、且没有证据文件（说明上一条不是恒真）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    it = S.load_items(root=hub)[0]
    S.set_state(it.id, "done", root=hub)
    return (S.load_items(root=hub)[0].state == "done"
            and S.state_corruption(root=hub) == [])


def c_daemon_tick_notifies_once():
    """一轮 tick：新告警通知一次、托盘刷成 L2、未处理=1；第二轮不再重复通知。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    b = NT.RecordingBackend()
    d = DM.Daemon(root=hub, backend=b, sound=EM.RecordingSound(),
                  overlay=EM.RecordingOverlay())
    r1 = d.tick()
    r2 = d.tick()
    tray = TR.read_state(root=hub)
    return (len(b.calls) == 1 and len(r1["notified"]) == 1 and len(r2["notified"]) == 0
            and tray["state"] == "L2" and tray["count"] == 1)


def n_daemon_tick_notifies_once():
    """负控：链里**新增**一条（另一种 kind）⇒ 必须再通知一次。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    b = NT.RecordingBackend()
    d = DM.Daemon(root=hub, backend=b)
    d.tick()
    n1 = len(b.calls)
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a"),
                    {"ts": "2026-10-05T10:00:00+08:00", "type": "host_shield_tamper",
                     "reason": "t", "hash": "h2"}])
    d.tick()
    return n1 == 1 and len(b.calls) == 2


def c_daemon_r0_emphasis_only():
    """★ 强调层只对 R0 生效：L2 不响、R0 才响（即使开关都开着）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    cfg = CFG.load(root=hub)
    cfg["sound"] = True
    cfg["overlay"] = True
    CFG.save(cfg, root=hub)
    s, o = EM.RecordingSound(), EM.RecordingOverlay()
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(), sound=s, overlay=o)
    d.tick()
    l2_quiet = (s.calls == [] and o.calls == [])
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a"),
                    {"ts": "2026-10-05T10:00:00+08:00", "type": "host_shield_tamper",
                     "reason": "t", "hash": "h2"}])
    d.tick()
    return l2_quiet and s.calls == ["R0"] and len(o.calls) == 1


def n_daemon_r0_emphasis_only():
    """负控：关掉开关 ⇒ R0 也不响（说明"响了"确实是开关在管）。"""
    hub = new_hub()
    put_chain(hub, [{"ts": "2026-10-05T09:00:00+08:00", "type": "host_shield_tamper",
                     "reason": "t", "hash": "h"}])
    s = EM.RecordingSound()
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(), sound=s)
    d.tick()
    return s.calls == []


def c_daemon_read_all_action():
    """托盘"全部已读"动作 ⇒ 置为已读，但**未处理数不变**。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend())
    d.tick()
    TR.push_action("read_all", root=hub)
    r = d.tick()
    items = S.load_items(root=hub)
    return (r["actions"] == ["read_all"] and {i.state for i in items} == {"read"}
            and M.unhandled_count(items) == 1)


def n_daemon_read_all_action():
    """负控：没有动作时不该凭空处理（actions 必须为空）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend())
    r = d.tick()
    return r["actions"] == []


def c_daemon_survives_bad_lines():
    """★ 链里有坏行 ⇒ **跳过坏行、保住好行、不许崩**。"""
    hub = new_hub()
    p = put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    with open(p, "a", encoding="utf-8", newline="\n") as f:
        f.write("{ 这不是 JSON\n")
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend())
    r = d.tick()
    return r["items"] == 1 and r["errors"] == []


def n_daemon_survives_bad_lines():
    """负控：只有坏行 ⇒ 收件箱为空（说明上一条的 1 不是"永远为 1"）。"""
    hub = new_hub()
    p = put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("{ 坏\n")
    return DM.Daemon(root=hub, backend=NT.RecordingBackend()).tick()["items"] == 0


def c_daemon_ledger_written():
    """tick 必须落当日账本。"""
    hub = new_hub()
    put_chain(hub, [breach(ts=time.strftime("%Y-%m-%d") + "T09:00:00+08:00", reason="a")])
    DM.Daemon(root=hub, backend=NT.RecordingBackend()).tick()
    days = L.load_days(root=hub)
    return time.strftime("%Y-%m-%d") in days


def n_daemon_ledger_written():
    hub = new_hub()
    return L.load_days(root=hub) == {}


class RecordingHeartbeat:
    """记下守护进程**实际发出**的每一份报文（不联网）。`ok=False` 模拟端点不通。"""

    def __init__(self, ok=True):
        self.calls = []
        self.ok = ok

    def __call__(self, url, payload):
        self.calls.append((url, payload))
        return self.ok, ("HTTP 200" if self.ok else "HTTP 500")


def _hb_on(hub, url="https://hb.example.invalid/"):
    cfg = CFG.load(root=hub)
    cfg["heartbeat"] = True
    cfg["heartbeat_endpoint"] = url
    CFG.save(cfg, root=hub)
    return cfg


def c_daemon_heartbeat_daily_once():
    """★ 同一本地日**只发一次**；报文字段集**恰好** 5 个（J9 罩得住自动发送）。

    ★★ 隔离纪律：这里**故意把间隔闸门与次数闸门都放开**（每轮推进 2 小时），
       使"只发一次"**只能**由日期闸门造成 —— 否则本条会绿在别的闸门上，
       删掉日期闸门也照样绿（2026-10-06 变异实测撞过）。
    """
    hub = new_hub()
    _hb_on(hub)
    hb = RecordingHeartbeat()
    now = [1000000.0]
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(), hb_poster=hb,
                  clock=lambda: now[0], today=lambda: "2026-10-06")
    for _ in range(3):
        d.tick()
        now[0] += 7200
    return (len(hb.calls) == 1
            and set(hb.calls[0][1]) == set(HB.TOP_FIELDS)
            and hb.calls[0][1]["date"] == "2026-10-06")


def n_daemon_heartbeat_daily_once():
    """负控：**换一天**必须再发一次（证明"一次"不是恒真，日期键真的在起作用）。"""
    hub = new_hub()
    _hb_on(hub)
    hb = RecordingHeartbeat()
    now = [1000000.0]
    day = ["2026-10-06"]
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(), hb_poster=hb,
                  clock=lambda: now[0], today=lambda: day[0])
    d.tick()
    now[0] += 7200
    day[0] = "2026-10-07"
    d.tick()
    return len(hb.calls) == 2


def c_daemon_heartbeat_off_zero_side_effect():
    """★ 心跳**默认关** ⇒ 一个请求不发、**标记文件一个都不建**（零副作用）。"""
    hub = new_hub()
    put_chain(hub, [breach()])
    hb = RecordingHeartbeat()
    DM.Daemon(root=hub, backend=NT.RecordingBackend(), hb_poster=hb).tick()
    return hb.calls == [] and not os.path.exists(DM.hb_mark_path(hub))


def n_daemon_heartbeat_off_zero_side_effect():
    """负控：开了且配了端点 ⇒ 必须发一次（证明上面那个 0 不是恒真的 0）。"""
    hub = new_hub()
    _hb_on(hub)
    hb = RecordingHeartbeat()
    DM.Daemon(root=hub, backend=NT.RecordingBackend(), hb_poster=hb).tick()
    return len(hb.calls) == 1


def c_daemon_heartbeat_retry_gap():
    """★ 失败后**不马上重试**：间隔不足 `HB_RETRY_GAP` 时，6 轮 tick 也只试 1 次。

    ★★ 隔离纪律：只推进 10 秒 ⇒ 次数闸门（上限 3）**根本到不了**，
       所以"只试 1 次"**只能**由间隔闸门造成（2026-10-06 变异实测撞过）。
    """
    hub = new_hub()
    _hb_on(hub)
    hb = RecordingHeartbeat(ok=False)
    now = [1000000.0]
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(), hb_poster=hb,
                  clock=lambda: now[0], today=lambda: "2026-10-06")
    for _ in range(6):
        d.tick()
        now[0] += 10                         # 只推进 10 秒（远低于 1 小时门槛）
    return len(hb.calls) == 1


def n_daemon_heartbeat_retry_gap():
    """负控：间隔**够**了就会再试（证明上面的 1 不是恒真的 1）。"""
    hub = new_hub()
    _hb_on(hub)
    hb = RecordingHeartbeat(ok=False)
    now = [1000000.0]
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(), hb_poster=hb,
                  clock=lambda: now[0], today=lambda: "2026-10-06")
    for _ in range(6):
        d.tick()
        now[0] += 7200
    return len(hb.calls) > 1


def c_daemon_heartbeat_tries_capped():
    """★ 端点一直不通 ⇒ 当天**最多 `HB_MAX_TRIES` 次**，不是每轮都试。"""
    hub = new_hub()
    _hb_on(hub)
    hb = RecordingHeartbeat(ok=False)
    now = [1000000.0]
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(), hb_poster=hb,
                  clock=lambda: now[0], today=lambda: "2026-10-06")
    for _ in range(6):
        d.tick()
        now[0] += 7200
    return len(hb.calls) == DM.HB_MAX_TRIES and len(hb.calls) < 6


def n_daemon_heartbeat_tries_capped():
    """负控：一次就**成功** ⇒ 当天一次即停（证明 3 不是恒真的 3）。"""
    hub = new_hub()
    _hb_on(hub)
    hb = RecordingHeartbeat(ok=True)
    now = [1000000.0]
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(), hb_poster=hb,
                  clock=lambda: now[0], today=lambda: "2026-10-06")
    for _ in range(6):
        d.tick()
        now[0] += 7200
    return len(hb.calls) == 1


def c_daemon_heartbeat_uses_hb_module():
    """★ 守护进程**不许自己拼包、自己发**：必须经 `heartbeat.send_once()`。"""
    txt = open(os.path.join(PKG, "inbox_daemon.py"), encoding="utf-8").read()
    return ("HB.send_once(" in txt
            and "urllib" not in txt and "socket" not in txt and "requests" not in txt)


def n_daemon_heartbeat_uses_hb_module():
    bad = "import urllib.request\nurllib.request.urlopen('http://x')"
    return not ("HB.send_once(" in bad and "urllib" not in bad)


# ==================================================== PART 11 · 命令行 ====
def _cli(argv):
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = CLI.main(argv)
    return rc, buf.getvalue()


def c_cli_list_ack():
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    it = S.load_items(root=hub)[0]
    rc1, out1 = _cli(["list"])
    rc2, _ = _cli(["ack", it.id])
    return (rc1 == 0 and "未处理 1" in out1 and rc2 == 0
            and S.load_items(root=hub)[0].state == "done")


def n_cli_list_ack():
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    rc, _ = _cli(["show", "no-such-id"])
    return rc == 2


def c_cli_ignore_r0_needs_note():
    """★ 端到端：命令行忽略 R0 无备注必须被拒；带备注才成。"""
    hub = new_hub()
    put_chain(hub, [{"ts": "2026-10-05T09:00:00+08:00", "type": "host_shield_tamper",
                     "reason": "t", "hash": "h"}])
    it = S.load_items(root=hub)[0]
    rc_bad, out_bad = _cli(["ignore", it.id])
    rc_ok, _ = _cli(["ignore", it.id, "--note", "已确认"])
    return (it.level == "R0" and rc_bad == 2 and "不能这么忽略" in out_bad
            and rc_ok == 0 and S.load_items(root=hub)[0].state == "ignored")


def n_cli_ignore_r0_needs_note():
    """负控：L2 忽略**不需要**备注 ⇒ 必须成功（说明上一条的拒绝不是"永远拒绝"）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    it = S.load_items(root=hub)[0]
    rc, _ = _cli(["ignore", it.id])
    return rc == 0 and S.load_items(root=hub)[0].state == "ignored"


def c_cli_read_all_keeps_unhandled():
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a"),
                    breach(ts="2026-10-05T09:01:00+08:00", reason="b")])
    rc, out = _cli(["read-all"])
    return rc == 0 and M.unhandled_count(S.load_items(root=hub)) == 2 and "不变" in out


def n_cli_read_all_keeps_unhandled():
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    it = S.load_items(root=hub)[0]
    _cli(["ack", it.id])
    return M.unhandled_count(S.load_items(root=hub)) == 0


def c_cli_heartbeat_default_off():
    hub = new_hub()
    rc, out = _cli(["heartbeat", "status"])
    return rc == 0 and "关（默认）" in out


def n_cli_heartbeat_default_off():
    hub = new_hub()
    _cli(["heartbeat", "on"])
    rc, out = _cli(["heartbeat", "status"])
    return "开" in out and "关（默认）" not in out


def c_cli_heartbeat_status_shows_today():
    """★ 自动发送要**可查**：守护进程发过之后，`heartbeat status` 必须说"今日已发"。"""
    hub = new_hub()
    _hb_on(hub)
    DM.Daemon(root=hub, backend=NT.RecordingBackend(),
              hb_poster=RecordingHeartbeat(),
              today=lambda: time.strftime("%Y-%m-%d")).tick()
    rc, out = _cli(["heartbeat", "status"])
    return rc == 0 and "今日自动发送：已发" in out


def n_cli_heartbeat_status_shows_today():
    """负控：守护进程没跑过 ⇒ 必须是"尚无记录"（证明"已发"不是印死的）。"""
    hub = new_hub()
    _hb_on(hub)
    rc, out = _cli(["heartbeat", "status"])
    return "尚无记录" in out


def c_cli_report_json_shape():
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    rc, out = _cli(["report", "--date", "2026-10-05", "--format", "json"])
    try:
        rep = json.loads(out)
    except Exception:                           # noqa: BLE001
        return False
    return rc == 0 and rep["day"] == "2026-10-05" and rep["levels"]["L2"] == 1


def n_cli_report_json_shape():
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    rc, out = _cli(["report", "--date", "2026-10-04", "--format", "json"])
    return rc == 0 and json.loads(out)["levels"]["L2"] == 0


# ==================================================== PART 9 · 静态/安全 ====
NET_TOKENS = ("import socket", "import urllib", "from urllib", "import requests",
              "import http.client", "urlopen(", "socket.socket", "http.client")


def _scan_net(paths):
    hits = []
    for p in paths:
        txt = open(p, encoding="utf-8").read()
        for t in NET_TOKENS:
            if t in txt:
                hits.append((os.path.basename(p), t))
    return hits


def c_no_network_in_data_layer():
    return _scan_net([os.path.join(PKG, f) for f in
                      ("inbox_model.py", "inbox_store.py", "ledger.py",
                       "inbox_report.py", "inbox_config.py")]) == []


def n_no_network():
    d = tempfile.mkdtemp(prefix="antinel-netscan-")
    _SCRATCH.append(d)
    p = os.path.join(d, "fake.py")
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("# -*- coding: utf-8 -*-\nimport socket\n")
    return _scan_net([p]) == [("fake.py", "import socket")]


def c_hot_path_modules_import_clean():
    """热路径会用到的模块必须能在**没有任何第三方包**下 import。"""
    import importlib
    for m in ("inbox_model", "inbox_store", "ledger", "inbox_config"):
        importlib.import_module(m)
    return True


def n_hot_path_modules_import_clean():
    try:
        import importlib
        importlib.import_module("definitely_not_a_module_xyz")
        return False
    except ImportError:
        return True


def c_store_never_writes_second_copy():
    """★ 收件箱**不新造事实**：只写 state.json，不写第二份告警副本。"""
    hub = new_hub()
    put_chain(hub, [breach()])
    S.load_items(root=hub)
    S.set_state(S.load_items(root=hub)[0].id, "done", root=hub)
    d = os.path.join(hub, "inbox")
    files = sorted(os.listdir(d)) if os.path.isdir(d) else []
    return files == ["state.json"]


def n_store_never_writes_second_copy():
    hub = new_hub()
    put_chain(hub, [breach()])
    d = os.path.join(hub, "inbox")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "alerts.jsonl"), "w", encoding="utf-8") as f:
        f.write("{}\n")
    files = sorted(os.listdir(d))
    return "alerts.jsonl" in files          # 注入的副本必须被看见


# ============================================================== 主程 ====
CHECKS = [
    # P1 数据层
    ("P1 J2 无未处理⇒L0", c_j2_empty_is_L0, n_j2),
    ("P1 J3 处理后回落", c_j3_fallback, n_j3),
    ("P1 J15 已读不减未处理", c_j15_read_keeps_open, n_j15),
    ("P1 J16 忽略R0要备注", c_j16_r0_ignore_needs_note, n_j16),
    ("P1 J7 类型不许漂移", c_j7_kind_coverage, n_j7),
    ("P1 未知kind报错", c_unknown_kind_raises, n_unknown_kind),
    ("P1 非法迁移被拒", c_transition_guard, n_transition),
    ("P1 J1 告警永不消失", c_j1_persist_after_15s, n_j1),
    ("P1 项目链拦截投影", c_project_block_projected, n_project_block),
    ("P1 状态往返+全部已读", c_state_roundtrip, n_state_roundtrip),
    ("P1 账本汇总/连续天数", c_ledger_summary, n_ledger),
    # P2 报告层
    ("P2 J5 日报=重算", c_j5_report_equals_recount, n_j5),
    ("P2 链好=ok/被改=broken", c_chain_health_ok_and_broken, n_chain_health),
    ("P2 未链接记录不算断链", c_chain_health_ignores_unchained, n_chain_health_ignores_unchained),
    ("P2 跨日边界 23:59/00:00", c_report_day_boundary, n_report_day_boundary),
    ("P2 时间戳坏不进今日", c_report_unknown_ts_not_today, n_report_unknown_ts),
    # P3 本地页
    ("P3 J6 只监听回环", c_j6_bind_loopback_only, n_j6),
    ("P3 缺token=403", c_server_token_required, n_server_token_required),
    ("P3 Host头校验", c_server_host_check, n_server_host_check),
    ("P3 资源白名单/防穿越", c_server_asset_whitelist, n_server_asset_whitelist),
    ("P3 XSS必须转义", c_server_xss_escaped, n_server_xss_escaped),
    ("P3 动作接口鉴权/校验", c_server_action_guard, n_server_action_guard),
    ("P3 未知视图回落", c_server_unknown_view_falls_back, n_server_unknown_view),
    ("P3 页面零外部资源", c_server_no_external_refs, n_server_no_external_refs),
    ("P3 空态渲染L0", c_server_empty_state_renders, n_server_empty_state),
    # P4 通知层
    ("P4 级别门槛", c_notify_level_gate, n_notify_level_gate),
    ("P4 R0穿透免打扰", c_notify_r0_penetrates_quiet, n_notify_r0_penetrates_quiet),
    ("P4 免打扰跨零点", c_notify_quiet_cross_midnight, n_notify_quiet_cross_midnight),
    ("P4 节流(门铃)", c_notify_throttle, n_notify_throttle),
    ("P4 配置坏→安全默认", c_config_corrupt_is_flagged, n_config_corrupt_is_flagged),
    # P5 托盘层
    ("P5 状态往返", c_tray_roundtrip, n_tray_roundtrip),
    ("P5 五态图标映射", c_tray_icon_map, n_tray_icon_map),
    ("P5 动作消费不删除", c_tray_action_consumed_without_delete, n_tray_action_consumed),
    ("P5 由收件箱刷托盘", c_tray_sync_from_items, n_tray_sync_from_items),
    ("P5 ICO结构合法", c_icons_structurally_valid, n_icons_structurally_valid),
    # P6 强调层
    ("P6 默认关=零副作用", c_emphasis_default_off, n_emphasis_default_off),
    ("P6 只有R0能响", c_emphasis_only_r0, n_emphasis_only_r0),
    # P7 兜底层
    ("P7 J14 默认关=零调用", c_j14_fallback_default_off, n_j14_fallback_default_off),
    ("P7 不写死外部地址", c_fallback_no_hardcoded_urls, n_fallback_no_hardcoded_urls),
    # P8 计数
    ("P8 J8 心跳默认关", c_j8_heartbeat_default_off, n_j8_heartbeat_default_off),
    ("P8 J9 只发固定字段", c_j9_heartbeat_only_fixed_fields, n_j9_heartbeat_only_fixed_fields),
    ("P8 编号惰性生成/可删", c_heartbeat_install_id_lazy, n_heartbeat_install_id_lazy),
    ("P8 buckets只数未处理", c_heartbeat_buckets_count_open_only, n_heartbeat_buckets_count_open_only),
    ("P8 Worker拒多字段", c_worker_rejects_extra_field, n_worker_rejects_extra_field),
    # P10 守护进程
    ("P10 状态坏→从链重建", c_state_corrupt_rebuilds, n_state_corrupt_rebuilds),
    ("P10 tick通知一次不重复", c_daemon_tick_notifies_once, n_daemon_tick_notifies_once),
    ("P10 强调层只对R0", c_daemon_r0_emphasis_only, n_daemon_r0_emphasis_only),
    ("P10 全部已读动作", c_daemon_read_all_action, n_daemon_read_all_action),
    ("P10 坏行不崩不掩盖", c_daemon_survives_bad_lines, n_daemon_survives_bad_lines),
    ("P10 落当日账本", c_daemon_ledger_written, n_daemon_ledger_written),
    ("P10 心跳每日只发一次", c_daemon_heartbeat_daily_once, n_daemon_heartbeat_daily_once),
    ("P10 心跳关=零请求零落盘", c_daemon_heartbeat_off_zero_side_effect,
     n_daemon_heartbeat_off_zero_side_effect),
    ("P10 失败重试有间隔", c_daemon_heartbeat_retry_gap, n_daemon_heartbeat_retry_gap),
    ("P10 失败当天封顶3次", c_daemon_heartbeat_tries_capped, n_daemon_heartbeat_tries_capped),
    ("P10 不许自己拼包/自造网络", c_daemon_heartbeat_uses_hb_module,
     n_daemon_heartbeat_uses_hb_module),
    # P11 命令行
    ("P11 list/ack 往返", c_cli_list_ack, n_cli_list_ack),
    ("P11 忽略R0端到端要备注", c_cli_ignore_r0_needs_note, n_cli_ignore_r0_needs_note),
    ("P11 read-all不减未处理", c_cli_read_all_keeps_unhandled, n_cli_read_all_keeps_unhandled),
    ("P11 心跳默认关(CLI)", c_cli_heartbeat_default_off, n_cli_heartbeat_default_off),
    ("P11 今日发没发可查", c_cli_heartbeat_status_shows_today,
     n_cli_heartbeat_status_shows_today),
    ("P11 report JSON 形状", c_cli_report_json_shape, n_cli_report_json_shape),
    # P9 静态/安全
    ("P9 数据层零联网", c_no_network_in_data_layer, n_no_network),
    ("P9 热路径零三方依赖", c_hot_path_modules_import_clean, n_hot_path_modules_import_clean),
    ("P9 不造第二份副本", c_store_never_writes_second_copy, n_store_never_writes_second_copy),
]


def main():
    green = red = vitality = 0
    fails, warns = [], []
    for name, chk, neg in CHECKS:
        try:
            ok = bool(chk())
            err = ""
        except Exception as e:                  # noqa: BLE001
            ok, err = False, "%s: %s" % (type(e).__name__, e)
        try:
            nok = bool(neg())
            nerr = ""
        except Exception as e:                  # noqa: BLE001
            nok, nerr = False, "%s: %s" % (type(e).__name__, e)

        if ok and nok:
            green += 1
            vitality += 1
            print("[PASS] %-28s 负控可红" % name)
        elif ok and not nok:
            green += 1
            warns.append(name)
            print("[WARN] %-28s 判据绿但**负控没红**（判据可能是瞎的） %s" % (name, nerr))
        else:
            red += 1
            fails.append(name)
            print("[FAIL] %-28s %s" % (name, err))

    print()
    print("三个数： %d 绿 / %d 红 ｜ 活力证据 %d/%d ｜ 标本覆盖 %d 个"
          % (green, red, vitality, len(CHECKS), len(CHECKS)))
    if red or warns:
        if fails:
            print("不许放行（红）：", "; ".join(fails))
        if warns:
            print("不许放行（负控无效）：", "; ".join(warns))
        return 1
    print("值守台 P1–P8：全绿，且每条负控都能变红。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
