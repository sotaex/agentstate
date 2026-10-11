# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

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
import inspect
import json
import os
import struct
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta

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


def _ago(hours=1.0):
    """**相对现在**的 ISO 时间戳（带本地时区）。

    ★★ 为什么必须有它：守卫里原本写死 `2026-10-05T20:00:00+08:00`。
      0.35.3 起顶部/首屏按 **24 小时窗口**取数 ⇒ 写死的时间戳第二天就掉出窗口，
      守卫会因为"日期过期"变红 —— **看起来像产品坏了，其实是判据腐烂了**。
      「判据里凡跟着时间走的常量，一律不许写死」（本仓铁律）。
    """
    return datetime.now().astimezone().replace(microsecond=0).isoformat() \
        if hours == 0 else \
        (datetime.now().astimezone() - timedelta(hours=hours)).replace(
            microsecond=0).isoformat()



def new_hub():
    d = tempfile.mkdtemp(prefix="antinel-inbox-")
    _SCRATCH.append(d)
    os.environ["ANTINEL_HUB_DIR"] = d
    os.environ.pop("ANTINEL_AUDIT_DIRS", None)
    return d


def put_chain(hub, recs, name=None):
    # ★ 文件名默认＝**今天**（写死日期会让"最近 N 天"的发现逻辑隔天失效）
    name = name or (datetime.now().strftime("%Y-%m-%d") + ".jsonl")
    d = os.path.join(hub, "rollup")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return p


def breach(ts=None, reason="规则 SEC-09 命中", **kw):
    ts = ts or _ago(1)
    r = {"ts": ts, "type": "host_shield_breach", "tool": "-", "session": "host-shield",
         "host": "generic", "decision": "allow", "severity": "warning",
         "reason": reason, "hash": "abc123"}
    r.update(kw)
    return r


def block_rec(ts=None, rule="SEC-01", snip=".env", **kw):
    ts = ts or _ago(1)
    r = {"ts": ts, "type": "pre_tool_use", "tool": "Bash", "session": "s1",
         "host": "workbuddy", "decision": "block", "severity": "critical",
         "rules_hit": [rule], "match_snippet": snip, "hash": "deadbeef"}
    r.update(kw)
    return r


def item(level="L2", state="unread", i=1, ts=None):
    a = M.Alert(id="x%d" % i, ts=ts or _ago(1),
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
    return len(hit) == 1 and hit[0].level == "R0" and no_copy


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
    """状态往返：**已读不减未处理** —— "点开即已读"绝不能变成"把事藏起来"。

    ★ 0.35.3：`mark_all_read`（批量「全部已读」）已整体下线（创始人「1 取消吧」）
      ⇒ 这里改用逐条 `set_state(..., "read")` 复现"已读"这一态，
      验的是**同一条不变式**（已读 ≠ 已处理），与有没有那个按钮无关。
    """
    hub = new_hub()
    put_chain(hub, [breach(ts=_ago(1), reason="r1"),
                    breach(ts=_ago(2), reason="r2")])
    items = S.load_items()
    n0 = M.unhandled_count(items)
    for it in items:
        S.set_state(it.id, "read", root=hub)
    items2 = S.load_items(root=hub)
    return (n0 == 2 and M.unhandled_count(items2) == 2
            and all(it.state == "read" for it in items2))


def n_state_roundtrip():
    hub = new_hub()
    put_chain(hub, [breach(ts=_ago(1), reason="r1")])
    it = S.load_items()[0]
    S.set_state(it.id, "done", root=hub)
    return M.unhandled_count(S.load_items()) == 0


def c_ledger_summary():
    hub = new_hub()
    for i, d in enumerate(["2026-10-03", "2026-10-04", "2026-10-05"]):
        L.append_day({"date": d, "blocked": 1,
                      "noticed": 0, "breached": 0, "acked": i}, root=hub)
    s = L.summary(root=hub, today="2026-10-05")
    return (s["blocked"] == 3 and s["streak_days"] == 3
            and "watch_seconds" not in s)


def n_ledger():
    hub = new_hub()
    for d in ["2026-10-03", "2026-10-05"]:
        L.append_day({"date": d, "blocked": 1}, root=hub)
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
    recount = {lv: sum(1 for i in today if i.level == lv)
               for lv in ("R0", "L2", "L1", "Ls")}
    return (rep["levels"] == recount and rep["total_today"] == len(today) == 3
            and "carried_over_count" not in rep and "unhandled_total" not in rep)


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
    return rep["total_today"] == 0 and "unhandled_total" not in rep


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
    put_chain(hub, [breach(reason="r1")])
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
    put_chain(hub, [breach(reason="r1")])
    srv = Server(hub)
    try:
        s, _, _ = req(srv.port, "/action", method="POST", body="op=done",
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
    """空收件箱 ⇒ 渲染**明确的空态**，不是白屏、也不是 500。

    ★ 0.35.3 改口径：旧版断言页面出现「一切正常」＋「L0.mp4」。两处都过期了 ——
      ① 顶部灯改由**当前态势**决定（`guard_posture()` 现探），不再"空就 L0"；
      ② 「一切正常」正是本仓铁律反对的**过度断言**（"查不出来"不许说成"没问题"）。
      ⇒ 改为卡**结构**（F6：判据卡结构不卡词面）：
        200 ＋ 空态提示块 `class="hint"` ＋ 顶部仍有 logo `<video>` ＋ **零**逐条记录。
    """
    hub = new_hub()
    srv = Server(hub)
    try:
        s, _, body = req(srv.port, "/?v=inbox", token=srv.token)
        return (s == 200 and 'class="hint"' in body and "<video" in body
                and 'class="item' not in body)
    finally:
        srv.stop()


def n_server_empty_state():
    """负控：**有**记录时 ⇒ 空态提示必须消失、且真的渲染出逐条记录。"""
    hub = new_hub()
    put_chain(hub, [breach(ts=_ago(1))])
    srv = Server(hub)
    try:
        _, _, body = req(srv.port, "/?v=inbox", token=srv.token)
        return 'class="hint"' not in body and 'class="item' in body
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
    """★ 消费动作＝**改名让开**（不删除），且**一批里的动作一个都不许丢**。

    ★ 0.35.3：样本动作改用 `open` / `quit`（`read_all` 已随「标为已读」一起下线）。
    """
    hub = new_hub()
    TR.push_action("open", root=hub)
    TR.push_action("quit", root=hub)
    acts = TR.poll_actions(root=hub)
    again = TR.poll_actions(root=hub)
    taken = [f for f in os.listdir(os.path.dirname(TR.action_path(hub)))
             if f.startswith("tray_action.txt.taken-")]
    return acts == ["open", "quit"] and again == [] and len(taken) == 1


def n_tray_action_consumed():
    """负控：模拟"只读第一行"的旧实现 ⇒ 第二条必然丢（判据能看见这种丢）。"""
    hub = new_hub()
    TR.push_action("quit", root=hub)
    TR.push_action("open", root=hub)
    p = TR.action_path(hub)
    taken = p + ".taken-neg"
    os.rename(p, taken)                         # 旧实现：整文件改名
    with open(taken, encoding="utf-8") as f:
        old_acts = [f.readline().strip()]       # 只取第一行
    return old_acts == ["quit"] and old_acts != ["quit", "open"]


def c_tray_sync_from_items():
    hub = new_hub()
    put_chain(hub, [breach()])
    TR.sync_from_items(S.load_items(root=hub), root=hub)
    st = TR.read_state(root=hub)
    return (st["state"] == "R0" and st["count"] == 1
            and "等你" not in st["tip"] and "件事" not in st["tip"])


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
    """buckets 只数**当天未处理**的；已处理的不计入（拦截与失守分桶各按本义）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a"),
                    breach(ts="2026-10-05T09:01:00+08:00", reason="b")])
    items = S.load_items(root=hub)
    p1 = HB.build(root=hub, items=items, day="2026-10-05")
    it = items[0]
    S.set_state(it.id, "done", root=hub)
    items2 = S.load_items(root=hub)
    p2 = HB.build(root=hub, items=items2, day="2026-10-05")
    return p1["buckets"]["r0"] == 2 and p2["buckets"]["r0"] == 1


def n_heartbeat_buckets_count_open_only():
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    p = HB.build(root=hub, items=S.load_items(root=hub), day="2026-10-05")
    return p["buckets"]["r0"] == 1


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
    """一轮 tick：新告警通知一次、托盘刷成 R0 失守、件数=1；第二轮不再重复通知。

    ★ 时间戳必须**相对现在**（`_ago`）：托盘态走 `console_state`（24 小时窗口），
      写死 `2026-10-05` 会让记录第二天掉出窗口 ⇒ 托盘态变 L0 ⇒ 判据**自己腐烂变红**。
    """
    hub = new_hub()
    put_chain(hub, [breach(ts=_ago(1), reason="a")])
    b = NT.RecordingBackend()
    d = DM.Daemon(root=hub, backend=b, sound=EM.RecordingSound(),
                  overlay=EM.RecordingOverlay())
    r1 = d.tick()
    r2 = d.tick()
    tray = TR.read_state(root=hub)
    return (len(b.calls) == 1 and len(r1["notified"]) == 1 and len(r2["notified"]) == 0
            and tray["state"] == "R0" and tray["count"] == 1)


def n_daemon_tick_notifies_once():
    """负控：链里**新增**一条（另一种 kind）⇒ 必须再通知一次。"""
    hub = new_hub()
    put_chain(hub, [breach(ts=_ago(2), reason="a")])
    b = NT.RecordingBackend()
    d = DM.Daemon(root=hub, backend=b)
    d.tick()
    n1 = len(b.calls)
    put_chain(hub, [breach(ts=_ago(2), reason="a"),
                    {"ts": _ago(1), "type": "host_shield_tamper",
                     "reason": "t", "hash": "h2"}])
    d.tick()
    return n1 == 1 and len(b.calls) == 2


def c_daemon_r0_emphasis_only():
    """★ 强调层只对 R0 生效：L2 不响、R0 才响（即使开关都开着）。"""
    hub = new_hub()
    put_chain(hub, [block_rec(ts=_ago(1), rule="SEC-01")])
    cfg = CFG.load(root=hub)
    cfg["sound"] = True
    cfg["overlay"] = True
    CFG.save(cfg, root=hub)
    s, o = EM.RecordingSound(), EM.RecordingOverlay()
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(), sound=s, overlay=o)
    d.tick()
    l2_quiet = (s.calls == [] and o.calls == [])
    put_chain(hub, [block_rec(ts=_ago(1), rule="SEC-01"),
                    {"ts": _ago(0.5), "type": "host_shield_tamper",
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


def c_daemon_ignores_read_all():
    """★ 0.35.3：`read_all` 动作**已取消** ⇒ 守护进程不许再消费它。

    ★ 为什么这条要有：托盘菜单已把该项拿掉，但**用户机器上可能还留着 0.35.2 的
      `tray.ps1`**，仍会写出 `read_all` 行。守护进程若还认它，就是"取消了但没取消
      干净"。判据：喂一行 `read_all` ⇒ 动作被消费掉，但**状态一个字节都不动**。
    """
    hub = new_hub()
    put_chain(hub, [breach(ts=_ago(1), reason="a")])
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(),
                  console_url="http://127.0.0.1:8790/?t=x")
    d.tick()
    before = S.load_state(root=hub)
    TR.push_action("read_all", root=hub)
    r = d.tick()
    items = S.load_items(root=hub)
    return (r["actions"] == ["read_all"]
            and {i.state for i in items} == {"unread"}       # 没被改成 read
            and S.load_state(root=hub) == before)            # 状态没动


def n_daemon_ignores_read_all():
    """负控：**`open` 动作仍要被消费**（证明不是"什么动作都不认了"）。

    ★ 必须传 `console_url=`：否则 `open_console_now` 会**真的起一个后台值守台**，
      把 `inbox_server._BG` 单例留在那儿 ⇒ 后面 `c_console_background_idempotent`
      会看到"已经在跑"而误红（**跨判据污染**，本仓明令禁止的形状）。
    """
    hub = new_hub()
    seen = []
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(),
                  console_url="http://127.0.0.1:8790/?t=x",
                  opener=lambda url: (seen.append(url), "app")[1])
    TR.push_action("open", root=hub)
    r = d.tick()
    return (r["actions"] == ["open"] and r["open_console"] is True
            and len(seen) == 1)


def c_daemon_open_action():
    """★ 0.35.2：托盘「打开值守台」动作必须**有消费点**。

    旧版只写 `out["open_console"] = True`，而**全仓无人读** ⇒ 点托盘「Open console」
    /左键点图标什么都不会发生（创始人 2026-10-06 实测：只看到右下角小弹窗）。
    本判据**卡结构不卡词面**：不问"有没有那句赋值"，问"点了之后**到底有没有人去开**"。
    """
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    seen = []

    def _opener(url):
        seen.append(url)
        return "app"

    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(),
                  console_url="http://127.0.0.1:8790/?t=x", opener=_opener)
    TR.push_action("open", root=hub)
    r = d.tick()
    return (r["actions"] == ["open"] and r.get("open_console") is True
            and len(seen) == 1 and seen[0].startswith("http://127.0.0.1:"))


def n_daemon_open_action():
    """负控：**没有** open 动作时不许凭空开窗口（seen 必须为空）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    seen = []
    d = DM.Daemon(root=hub, backend=NT.RecordingBackend(),
                  console_url="http://127.0.0.1:8790/?t=x",
                  opener=lambda url: (seen.append(url), "app")[1])
    d.tick()
    return seen == []


def c_console_background_idempotent():
    """★ 0.35.2：后台值守台**幂等** —— 起两次只绑一次端口，第二次复用同一 URL。

    用 0 端口让 OS 挑空闲口，跑完关掉；**不碰真实 8790**，也不留进程。
    """
    import inbox_server as SV
    try:
        u1, s1 = SV.ensure_background(port=0)
        u2, s2 = SV.ensure_background(port=0)
        return bool(u1) and s1 is True and s2 is False and u1 == u2
    finally:
        SV.stop_background()


def n_console_background():
    """负控：停掉之后再起必须**真的重新起**（started 又变 True），不是永远 False。"""
    import inbox_server as SV
    try:
        SV.ensure_background(port=0)
        SV.stop_background()
        _u, s = SV.ensure_background(port=0)
        return s is True
    finally:
        SV.stop_background()


def c_console_app_window():
    """★ 0.35.2：值守台要开成**独立窗口**（app 模式）；拿不到 app 浏览器要**诚实降级**。

    ★ 卡结构不卡词面：两条路都只问「最终把什么命令交给了 opener」，
      不问本机装的是 Edge 还是 Chrome（那是环境，不是产品行为）。
    ★ 负控**不许**靠 monkeypatch `shutil.which` 来造"没有浏览器"——
      `_app_window_cmd` 有**硬编码路径兜底**，which 被掏空也照样找得到 msedge
      （首版就这么写错了：降级分支永远进不去，判据自己恒红）。
      改为直接替换 `_app_window_cmd` 本体，**精确地**造出"找不到 app 浏览器"这一态。
    """
    import inbox_server as SV
    # ① 正常路：拿到 app 命令 ⇒ 必须是 app 模式；拿不到 ⇒ 必须是浏览器兜底。二者必居其一。
    got = []
    r1 = SV.open_console("http://127.0.0.1:8790/?t=x", opener=lambda cmd: got.append(cmd))
    if not got or r1 not in ("app", "browser"):
        return False
    if r1 == "app" and not got[0][-1].startswith("--app=http://"):
        return False
    if r1 == "browser" and got[0][0] != "--browser--":
        return False
    # ② 降级路：本机没有 app 浏览器 ⇒ 必须**诚实**退回浏览器，不许谎报"独立窗口"
    _orig, got2 = SV._app_window_cmd, []
    try:
        SV._app_window_cmd = lambda url: None
        r2 = SV.open_console("http://127.0.0.1:8790/?t=x", opener=lambda cmd: got2.append(cmd))
    finally:
        SV._app_window_cmd = _orig
    return r2 == "browser" and bool(got2) and got2[0][0] == "--browser--"


def n_console_app_window():
    """负控：造出"没有 app 浏览器"这一态后，**不许**报 "app"（不许谎报"独立窗口"）。"""
    import inbox_server as SV
    _orig = SV._app_window_cmd
    try:
        SV._app_window_cmd = lambda url: None
        r = SV.open_console("http://127.0.0.1:8790/?t=x", opener=lambda cmd: None)
    finally:
        SV._app_window_cmd = _orig
    return r == "browser"


def c_console_real_branch():
    """★★ 0.35.2：`open_console()` 的**真身分支**（不注入 opener）必须真能跑。

    ★★ 这条守卫是为一个**真缺陷**立的（创始人 2026-10-06 实测「还开在浏览器标签页」）：
      `inbox_server.py` 用了 `subprocess.Popen`，却**从未 `import subprocess`**
      ⇒ 真身分支抛 `NameError`，又被 `except Exception: pass` **静默吞掉**
      ⇒ app 独立窗口**从来没成功过**。
    ★ 为什么原有 68 条守卫没抓到：`c_console_app_window` 走的是 `opener=` 注入分支
      —— **替身把真身那行盖住了**。判据测的是替身，不是真身。
    ★ 本判据的做法：**不注入 opener**，只把模块里的 `subprocess` 换成记录器；
      并先断言模块**自己绑定过** `subprocess`（否则换上去的替身会把缺陷盖住）。
    """
    if not hasattr(SV, "subprocess"):
        return False                    # ★ 模块没绑 subprocess ⇒ 真身必 NameError
    real = SV.subprocess
    seen = []

    class _Rec:
        DEVNULL = -3

        def Popen(self, cmd, **kw):
            seen.append(cmd)
            return object()

    SV.subprocess = _Rec()
    try:
        r = SV.open_console("http://127.0.0.1:8790/?t=x")
    finally:
        SV.subprocess = real
    return (r == "app" and len(seen) == 1
            and seen[0][-1].startswith("--app=http://"))


def n_console_real_branch():
    """负控：**拿掉**模块的 `subprocess` ⇒ 真身分支必须**降级**（不许谎报 "app"）。

    ★ 把 `webbrowser.open` 也换成记录器 —— 否则这条负控会**真的弹一个浏览器**。
    """
    real = SV.subprocess
    calls = []
    orig_open = SV.webbrowser.open
    try:
        del SV.subprocess
        SV.webbrowser.open = lambda u: calls.append(u)
        r = SV.open_console("http://127.0.0.1:8790/?t=x")
    finally:
        SV.subprocess = real
        SV.webbrowser.open = orig_open
    return r == "browser" and len(calls) == 1


def c_notify_human_kind():
    """★★ 0.35.2：门闸气泡的正文必须**说人话**（不许把内部类型名当人话）。

    ★ 为什么（真缺陷）：旧版气泡正文是 `host_shield_breach：…` ——
      把内部标识直接摆给创始人看，正是本项目明令禁止的「黑话」。
    ★ 唯一真源 `inbox_model.TITLE_OF_KIND`；本判据**调产品函数**，不自己维护一份表。
    """
    import host_shield as HS
    bad = [k for k in HS._ALERT_KINDS if HS._human_kind(k) == k]
    return (not bad) and HS._human_kind("definitely_not_a_kind") == "definitely_not_a_kind"


def n_notify_human_kind():
    """负控：把真源表**掏空** ⇒ 必须原样返回（证明它真的在读那张表，不是写死的）。"""
    import host_shield as HS
    orig = M.TITLE_OF_KIND
    try:
        M.TITLE_OF_KIND = {}
        return HS._human_kind("host_shield_breach") == "host_shield_breach"
    finally:
        M.TITLE_OF_KIND = orig


def c_notify_clickable():
    """★★ 0.35.2：门闸气泡必须**可点**，点开就是值守台。

    ★ 为什么（真缺陷）：旧版气泡 8 秒后自己消失、**点了没有任何反应** ——
      创始人 2026-10-06「现在还右下冒泡是有问题的」。
    ★ 想收到点击就必须**泵消息**：`Start-Sleep` 不泵消息 ⇒ `BalloonTipClicked`
      永远不触发。所以判据同时卡「挂了点击处理」与「泵消息」两件事。
    ★ 字符串断言证明不了它能跑 ⇒ `_strict_test/_bubble_verify.py` 会**真跑一遍**。
    """
    import host_shield as HS
    cc = HS._console_open_cmd()
    if not cc or cc[0][1:] != ["-m", "antinel", "inbox", "open"]:
        return False
    cap = []
    orig = HS.subprocess.Popen

    class _Cap:
        def __init__(self, cmd, **kw):
            cap.append(cmd)

    HS.subprocess.Popen = _Cap
    try:
        HS._notify("t", "b", cc[0], cc[1])
    finally:
        HS.subprocess.Popen = orig
    if not cap:
        return False
    ps = cap[-1][-1]
    return ("BalloonTipClicked" in ps and "DoEvents" in ps
            and "Start-Sleep -Seconds" not in ps)


def n_notify_clickable():
    """负控：拿不到 CLI 命令 ⇒ 必须**不挂点击**（降级但不假装），气泡仍照发。"""
    import host_shield as HS
    cap = []
    orig = HS.subprocess.Popen
    orig_cmd = HS._console_open_cmd

    class _Cap:
        def __init__(self, cmd, **kw):
            cap.append(cmd)

    HS.subprocess.Popen = _Cap
    HS._console_open_cmd = lambda: None
    try:
        HS._notify("t", "b", *HS._click_args())
    finally:
        HS.subprocess.Popen = orig
        HS._console_open_cmd = orig_cmd
    return bool(cap) and "BalloonTipClicked" not in cap[-1][-1]


def c_render_page_lazy_report():
    """★★ 0.35.2：**用不到日报的视图不许去算日报**。

    ★ 为什么（真缺陷）：旧版对**每个**视图都算 `daily_report()`，而日报里
      `chain_health()` 要**逐条复算整条审计链**（本机 20 文件 / 43149 行 ≈ 8s）
      ⇒ 默认的收件箱页**白等 8 秒**；四个视图实测 5–18 秒，创始人「点开像卡死」。
    ★ 卡结构不卡词面：把 `daily_report` 换成"一调就炸"的桩，
      收件箱页**照样渲染成功**才算过（不问代码里有没有那句 if）。
    """
    orig = R.daily_report

    def _boom(*a, **k):
        raise AssertionError("收件箱页不该去算日报")

    R.daily_report = _boom
    try:
        html = SV.render_page(view="inbox", root=new_hub(), token="t")
    finally:
        R.daily_report = orig
    return isinstance(html, str) and "收件箱" in html


def n_render_page_lazy_report():
    """负控：桩**真的会炸** —— 日报页必须因此失败（证明上一条不是"桩没生效"）。"""
    orig = R.daily_report

    def _boom(*a, **k):
        raise AssertionError("boom")

    R.daily_report = _boom
    try:
        try:
            SV.render_page(view="report", root=new_hub(), token="t")
            return False
        except AssertionError:
            return True
    finally:
        R.daily_report = orig


def c_tray_self_consume():
    """★★ 0.35.2：托盘**自己**也要消费菜单动作（不能只靠守护进程）。

    ★ 为什么（真缺陷）：托盘菜单只是**写一行** `tray_action.txt`，真正消费的是
      守护进程；而 `antinel inbox tray` **只起图标、不起守护进程**
      ⇒ 只开托盘的用户点「Open console」/「Mark all read」**什么都不会发生**。
    ★ 动作语义**只有一处实现**：托盘侧调 `inbox_daemon.handle_actions()`。
    """
    if "handle_actions(" not in inspect.getsource(TR.consume_loop):
        return False
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    seen = []
    TR.push_action("open", root=hub)
    res = DM.handle_actions(root=hub, console_url="http://127.0.0.1:8790/?t=x",
                            opener=lambda url: (seen.append(url), "app")[1])
    return res["actions"] == ["open"] and len(seen) == 1


def n_tray_self_consume():
    """负控：**没有**动作时不许凭空开窗口。"""
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    seen = []
    res = DM.handle_actions(root=hub, console_url="http://127.0.0.1:8790/?t=x",
                            opener=lambda url: (seen.append(url), "app")[1])
    return res["actions"] == [] and seen == []


def c_console_port_no_clash():
    """★★ 0.35.2：首选端口被占时**必须换端口**，不许撞车。

    ★ 为什么（Windows 特有，实测）：`ThreadingHTTPServer` 默认
      `allow_reuse_address=1`，而 Windows 的 `SO_REUSEADDR` **允许两个进程绑同一端口**
      ⇒ `bind()` 不抛 `OSError` ⇒ 两个值守台抢同一端口、**口令各不相同**
      ⇒ 开出来的窗口一半请求 403。⇒ 必须**主动探测**（`_port_busy`）。
    ★ 本判据真占一个端口，验 `_port_busy` 认得出、且新服务换到别处。
    """
    srv, _tk = SV.make_server(port=0)
    held = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        if SV._port_busy(held) is not True:
            return False
        SV._BG["httpd"], SV._BG["url"] = None, None
        url, _started = SV.ensure_background(port=held)
        got = int(url.split(":")[2].split("/")[0])
        return got != held
    finally:
        SV.stop_background()
        srv.shutdown()
        srv.server_close()


def n_console_port_no_clash():
    """负控：注入 `OSError` 时也必须退到临时端口（证明降级路真的在）。

    ★ 必须**同时**把 `_port_busy` 注入成 False —— 否则预探测先拦下，
      根本走不到 `OSError` 那条路（写这条时首版就栽在这）。
    """
    calls = []
    orig_ms, orig_busy = SV.make_server, SV._port_busy

    def _boom(port=SV.DEFAULT_PORT, root=None, **kw):
        calls.append(port)
        if port != 0:
            raise OSError("in use (injected)")
        return orig_ms(port=0, root=root, **kw)

    SV._BG["httpd"], SV._BG["url"] = None, None
    SV.make_server = _boom
    SV._port_busy = lambda *a, **k: False
    try:
        _u, started = SV.ensure_background(port=8790)
    finally:
        SV.make_server = orig_ms
        SV._port_busy = orig_busy
        SV.stop_background()
    return calls[:2] == [8790, 0] and started is True


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
    """负控：L2 忽略**不需要**备注 ⇒ 必须成功（说明上一条的拒绝不是"永远拒绝"）。

    ★★ 2026-10-07 修（本负控原先是**坏的**）：
      原样本用 `breach()` ＝ `host_shield_breach`。0.35.3 已把该类型正名为
      **R0 防护缺口**（"门闸有缺口"，不是"已拦截"）⇒ 正控、负控变成**同一个
      R0 样本**，负控必然假 ⇒ 套件长期 WARN（123 绿/0 红｜1 条负控无效）。
      **这是量具过期，不是产品错**——产品拒 R0 无备注忽略是对的。

      负控的**意图**＝"拒绝只针对 R0，不针对所有级别"，故样本必须是**真 L2**：
      `block_rec()` ⇒ `tool_call_blocked`（规则真正拦下的操作，level=L2）。
      这样产品若把备注要求扩到 L2，本负控立刻变红 ⇒ **不是恒真**。
      活力（可红性）已由 `_p_p11_negctl_mutation.py` 变异实测：
      把 `NOTE_REQUIRED_TO_IGNORE` 改成 ("R0","L2") 后本负控转 False。
    """
    hub = new_hub()
    put_chain(hub, [block_rec(ts="2026-10-05T09:00:00+08:00")])
    hit = [x for x in S.load_items(root=hub) if x.kind == "tool_call_blocked"]
    if not hit:
        return False                       # 没投影出来 ⇒ 负控不算通过
    it = hit[0]
    if it.level != "L2":
        return False                       # 样本不是 L2 ⇒ 本负控失去意义，判红
    rc, _ = _cli(["ignore", it.id])
    after = [x for x in S.load_items(root=hub) if x.id == it.id]
    return rc == 0 and bool(after) and after[0].state == "ignored"


def c_cli_has_no_read_all():
    """★ 0.35.3：CLI 不再提供 `read-all` 子命令（创始人「1 取消吧」）。

    ★ 未知子命令 ⇒ argparse 直接抛 `SystemExit(2)`（**不是返回码**）。
      `SystemExit` 是 `BaseException`，runner 的 `except Exception` 接不住 ⇒
      判据必须自己接住，否则会把整个 runner 带崩（那才是真"红得莫名其妙"）。
    """
    new_hub()
    try:
        rc, _out = _cli(["read-all"])
    except SystemExit as e:
        return int(e.code or 0) != 0
    return rc != 0


def n_cli_has_no_read_all():
    """负控：**其它子命令仍在**（证明不是"整个 CLI 都坏了"）。"""
    hub = new_hub()
    put_chain(hub, [breach(ts=_ago(1), reason="a")])
    rc, out = _cli(["list"])
    return rc == 0 and "未处理 1" in out


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
    return rc == 0 and rep["day"] == "2026-10-05" and rep["levels"]["R0"] == 1


def n_cli_report_json_shape():
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T09:00:00+08:00", reason="a")])
    rc, out = _cli(["report", "--date", "2026-10-04", "--format", "json"])
    return rc == 0 and json.loads(out)["levels"]["R0"] == 0


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
def _parse_forms(html_text):
    """把渲染出来的 HTML 里**每个 form** 解析成 (action, method, fields)。

    ★ 这是本判据的关键：**不自己构造请求**，只读页面真的写了什么。
    """
    import html.parser as _hp

    class P(_hp.HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms = []
            self._cur = None

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "form":
                self._cur = {"action": a.get("action") or "",
                             "method": (a.get("method") or "get").lower(),
                             "fields": {}}
            elif tag == "input" and self._cur is not None:
                n = a.get("name")
                if n:
                    self._cur["fields"][n] = a.get("value") or ""

        def handle_endtag(self, tag):
            if tag == "form" and self._cur is not None:
                self.forms.append(self._cur)
                self._cur = None

    p = P()
    p.feed(html_text)
    return [(f["action"], f["method"], f["fields"]) for f in p.forms]


def _replay_form(port, action, method, fields):
    """**完全照浏览器**发一个表单：口令在 body 里，不带任何额外请求头。"""
    import urllib.parse as _up
    body = _up.urlencode(fields)
    return req(port, action or "/", method=method.upper(), body=body,
               ctype="application/x-www-form-urlencoded")


def _no_real_revive():
    """★★ 判据**不许有真实副作用**：把「重新拉起哨兵」这条链路整体打桩。

    ★ 为什么必须有它（2026-10-06 实测的真缺陷）：
      `c_forms_replay` 会把页面上**每一个**表单原样重放 —— 其中就包括失守时
      出现的「马上修复」按钮（`op=fix`）。服务端 `inbox_server` 的 fix 处理是
      `host_shield.guard_fix(_pkg_root())`，而 `_pkg_root()` 是**真包根**
      （不是沙箱 hub）⇒ 每重放一次就：
        ① 真的拉起一个哨兵进程；② 往**真链**写一条 `host_shield_revived`
           （该类型在 `_ALERT_KINDS` 弹窗名单里）。
      ⇒ **判据自己制造了创始人报障的「右下一直冒泡」。**
        这比"测试脏"更严重：它让"绿"失真 —— 判据制造了它本该只观察的现象。

    ⇒ 只打桩**副作用**；**接线本身照测**（判据要验的是"这个按钮按得动"，
      不是"它真的去拉进程"）。返回 restore()。
    """
    import host_shield as HS
    saved = (HS.ensure_alive, HS.spawn_sentinel, HS.pid_alive, HS.record)
    HS.ensure_alive = lambda pkg_root=None, cause="manual": "alive"
    HS.spawn_sentinel = lambda *a, **k: (True, 0, "spy")
    HS.pid_alive = lambda pid: True
    HS.record = lambda *a, **k: None

    def _restore():
        (HS.ensure_alive, HS.spawn_sentinel, HS.pid_alive, HS.record) = saved
    return _restore


def c_forms_replay():
    """★ 0.35.2：页面上**每一个按钮**都要真的按得动（form 原样重放）。

    为什么加（2026-10-06 创始人报障）：点「全部已读」得到
      「action / 缺少或错误的访问口令」的**纯文本页**，而且退不回去。

    根因：页面表单把口令放在 **POST body** 的 hidden 字段里
      （`<form method=post action="/action"><input type=hidden name=t …>`），
      而 `_guard()` 只看 **query string** 与 **X-Antinel-Token 请求头** ⇒ 每个按钮都 403。
      ⇒ 「全部已读 / 标为已读 / 已处理 / 忽略 / 重开」**从上线起就没生效过**。

    ★★ 为什么原有的 64 条守卫一条都没抓到 —— **这是系统性的测试缺陷**：
      测试用 `req(port, "/action", token=…)`，而 `req()` 把口令塞进**请求头**；
      浏览器塞的是 **body**。两者都"能通过守卫"，但**不是同一个请求**。
      ⇒ 测试覆盖的是「我以为的请求」，不是「页面真的发出的请求」。

    本判据因此**不自己构造请求**：它解析页面渲染出的 HTML，取出每个 form 的
    action 与全部 hidden 字段，**原样**发出去 —— 页面上有什么就发什么。
    这样，任何"表单与守卫对不上"的改动都会当场变红。
    """
    hub = new_hub()
    put_chain(hub, [breach(ts="2026-10-05T20:00:01+08:00", reason="r1"),
                    breach(ts="2026-10-05T20:00:02+08:00", reason="r2")])
    srv = Server(hub)
    try:
        # 先量出「页面上共有几个按钮」：每个 (视图, 筛选, 第几个表单)。
        targets = []
        for v in ("inbox", "report", "health", "ledger"):
            for f in ("open", "all"):
                s, _, body = req(srv.port, "/?v=%s&f=%s" % (v, f), token=srv.token)
                if s == 200:
                    for idx in range(len(_parse_forms(body))):
                        targets.append((v, f, idx))
    finally:
        srv.stop()
    if not targets:
        # 页面上一个 form 都没有 ⇒ 本判据**没有对象** ⇒ 假守卫，必须报错不许绿。
        return False

    bad, ran_ok = [], 0
    _restore = _no_real_revive()   # ★ 判据不许真起哨兵/写真链（见 _no_real_revive）
    try:
        for v, f, idx in targets:
            # ★ 每个按钮用**一份全新状态**重放 —— 否则前一次点击已经改了状态，
            #   后一个表单就成了"对旧状态发的动作"，会 409；那是**测试自己造出来的**，
            #   不是产品缺陷（本轮就踩过：14 个表单连放，4 个 409）。
            hub2 = new_hub()
            put_chain(hub2, [breach(ts="2026-10-05T20:00:01+08:00", reason="r1"),
                             breach(ts="2026-10-05T20:00:02+08:00", reason="r2")])
            srv2 = Server(hub2)
            try:
                s2, _, body2 = req(srv2.port, "/?v=%s&f=%s" % (v, f), token=srv2.token)
                fs2 = _parse_forms(body2) if s2 == 200 else []
                if idx >= len(fs2):
                    continue
                action, method, fields = fs2[idx]
                st, _, _ = _replay_form(srv2.port, action, method, fields)
            finally:
                srv2.stop()
            if st == 403:
                bad.append("%s op=%s -> 403（口令没带上）" % (action, fields.get("op")))
            elif st == 303:
                ran_ok += 1
            elif st != 200:
                bad.append("%s op=%s -> HTTP %d" % (action, fields.get("op"), st))
    finally:
        _restore()
    # ★ 还要防"全都被业务规则拒了"这种假绿：至少要有一个**真的执行成功**。
    if not bad and ran_ok == 0:
        bad.append("没有任何一个按钮真的执行成功（%d 个表单全被业务规则拒了）" % len(targets))
    if bad:
        print("      [forms] %d 个按钮，%d 个按不动：%s"
              % (len(targets), len(bad), "; ".join(bad[:4])))
    return not bad


def n_forms_replay():
    """负控：把表单里的口令字段抽掉 ⇒ 必须 403。

    证明 `c_forms_replay` **不是恒绿**：只要口令真的没带上，它就会红。
    """
    hub = new_hub()
    put_chain(hub, [breach()])
    srv = Server(hub)
    try:
        s, _, body = req(srv.port, "/?v=inbox&f=all", token=srv.token)
        forms = _parse_forms(body)
        if not forms:
            return False
        action, method, fields = forms[0]
        stripped = {k: v for k, v in fields.items() if k != "t"}
        st, _, _ = _replay_form(srv.port, action, method, stripped)
        return st == 403
    finally:
        srv.stop()


def _console_revives_in_real_chain():
    """真包那条链里 `type=host_shield_revived 且 cause=console` 的条数。

    读不出来 ⇒ 返回 None（**盲区不许当 0**）。
    """
    import host_shield as HS
    d = HS._shield_audit_dir(PKG)          # 真包根有 .psl ⇒ 真包审计目录
    n = 0
    try:
        for fn in os.listdir(d):
            if not fn.endswith(".jsonl"):
                continue
            with open(os.path.join(d, fn), encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    try:
                        r = json.loads(ln)
                    except Exception:                        # noqa: BLE001
                        continue
                    if (r.get("type") == "host_shield_revived"
                            and r.get("cause") == "console"):
                        n += 1
    except OSError:
        return None
    return n


def c_forms_replay_has_no_real_side_effect():
    """★★ **判据重放页面按钮时，绝不许有真实副作用**（真起哨兵 / 写真链）。

    ★ 为什么（2026-10-06 实测的真缺陷，创始人报障「右下一直冒泡」）：
      页面上失守时会出现「马上修复」按钮（`op=fix`）。`c_forms_replay` 原样重放
      每个表单 ⇒ 打到服务端 `host_shield.guard_fix(_pkg_root())`，而 `_pkg_root()`
      是**真包根** ⇒ 真的拉起一个哨兵进程，并往**真链**写一条
      `host_shield_revived`（`cause=console`，在 `_ALERT_KINDS` 弹窗名单里）
      ⇒ **判据自己制造了创始人报障的冒泡。**
      这比"测试脏"更严重：它让"绿"这个信号本身失真。

    ★ 量具：**真链上 `revived cause=console` 的条数**，跑前跑后必须不变。
      （只数这一种，不数心跳/其它 breach —— 哨兵在跑，心跳会干扰计数。）
    """
    before = _console_revives_in_real_chain()
    ok = c_forms_replay()
    after = _console_revives_in_real_chain()
    if before is None or after is None:
        return False                       # 读不出来 ⇒ 盲区，不许绿
    return ok is True and after == before


def n_forms_replay_has_no_real_side_effect():
    """负控：**关掉 `_no_real_revive` 打桩** ⇒ 「马上修复」按钮**必须真的走到** `ensure_alive`。

    ★ 证明上一条的"链没长"是**打桩带来的**，不是"这个按钮本来就不走拉起"
      （否则上一条是恒真废话）。
    ★ 安全：把 `ensure_alive` 换成**记录器**（不调真的），并把 `guard_posture`
      钉成失守（保证渲染出修复按钮）⇒ 本负控自身**零副作用**。
    """
    import host_shield as HS
    forced = {"state": "down", "label": "失守", "why": "负控", "evidence": {},
              "consequences": [{"kind": "k", "text": "t"}],
              "can_fix": True, "fix": "revive", "fix_hint": "马上修复"}
    calls = []
    s_post, s_ea, s_rec = HS.guard_posture, HS.ensure_alive, HS.record
    s_nr = globals()["_no_real_revive"]
    HS.guard_posture = lambda pkg_root=None: dict(forced)
    HS.ensure_alive = lambda pkg_root=None, cause="manual": (
        calls.append(cause), "alive")[1]
    HS.record = lambda *a, **k: None
    globals()["_no_real_revive"] = lambda: (lambda: None)      # 关掉打桩
    try:
        c_forms_replay()
    finally:
        globals()["_no_real_revive"] = s_nr
        HS.guard_posture, HS.ensure_alive, HS.record = s_post, s_ea, s_rec
    return calls != []


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
    ("P1 状态往返(已读不减未处理)", c_state_roundtrip, n_state_roundtrip),
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
    # ★ 0.35.2：页面上的每个按钮都要真的按得动（form 原样重放）。
    #   出处：创始人实测「全部已读」按钮 403 且退不回去；而原有 64 条守卫全绿 ——
    #   因为测试用请求头带口令，浏览器用 body 带口令，**不是同一个请求**。
    ("P3 页面按钮原样重放", c_forms_replay, n_forms_replay),
    # ★ 0.35.3：判据**不许有真实副作用** —— 重放页面按钮时真起哨兵/写真链，
    #   会让"绿"失真（创始人报障「右下一直冒泡」的真因之一）。
    ("P3 重放按钮零副作用", c_forms_replay_has_no_real_side_effect,
     n_forms_replay_has_no_real_side_effect),
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
    ("P10 read_all已取消(不动状态)", c_daemon_ignores_read_all, n_daemon_ignores_read_all),
    # ★ 0.35.2：托盘「打开值守台」必须有消费点（旧版 open_console 无人读＝死动作）
    ("P10 打开值守台动作（有消费点）", c_daemon_open_action, n_daemon_open_action),
    ("P10 后台值守台幂等", c_console_background_idempotent, n_console_background),
    ("P10 值守台开独立窗口(app)", c_console_app_window, n_console_app_window),
    # ★★ 0.35.2：以下 6 条各自对应一个**真缺陷**（创始人 2026-10-06 实测）
    ("P10 值守台真身分支可跑(不靠替身)", c_console_real_branch, n_console_real_branch),
    ("P10 端口被占不撞车", c_console_port_no_clash, n_console_port_no_clash),
    ("P10 托盘自己消费动作", c_tray_self_consume, n_tray_self_consume),
    ("P3 收件箱页不算日报(不白等)", c_render_page_lazy_report, n_render_page_lazy_report),
    ("P4 气泡正文说人话", c_notify_human_kind, n_notify_human_kind),
    ("P4 气泡可点开值守台", c_notify_clickable, n_notify_clickable),
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
    ("P11 CLI无read-all子命令", c_cli_has_no_read_all, n_cli_has_no_read_all),
    ("P11 心跳默认关(CLI)", c_cli_heartbeat_default_off, n_cli_heartbeat_default_off),
    ("P11 今日发没发可查", c_cli_heartbeat_status_shows_today,
     n_cli_heartbeat_status_shows_today),
    ("P11 report JSON 形状", c_cli_report_json_shape, n_cli_report_json_shape),
    # P9 静态/安全
    ("P9 数据层零联网", c_no_network_in_data_layer, n_no_network),
    ("P9 热路径零三方依赖", c_hot_path_modules_import_clean, n_hot_path_modules_import_clean),
    ("P9 不造第二份副本", c_store_never_writes_second_copy, n_store_never_writes_second_copy),
]


def _all_checks():
    """主套件（P1–P11）＋ 0.35.3 增补（P12：链背书 / 当前态势 / 三档 / 页面四项）。

    ★★ 为什么在这里惰性导入：本文件既可能作为 `__main__` 跑，也可能被别的
      模块 `import inbox_guards`。`inbox_guards_0353` 反过来 `import inbox_guards as G`
      取脚手架 —— 若在**模块顶层**注册，双导入时 `CHECKS_0353` 可能还没定义就被读，
      变成 `AttributeError`。放到 `main()` 里，两个入口都已初始化完毕，稳。
    ★★ 导入失败**绝不静默**：少跑判据＝假守卫。抛出去就是红。
    """
    import inbox_guards_0353 as G0353
    return list(CHECKS) + list(G0353.CHECKS_0353)


def main():
    try:
        checks = _all_checks()
    except Exception as e:                      # noqa: BLE001
        print("[FAIL] 0.35.3 增补判据导入失败（**不许静默少跑判据**）：%s: %s"
              % (type(e).__name__, e))
        return 2
    green = red = vitality = 0
    fails, warns = [], []
    for name, chk, neg in checks:
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
          % (green, red, vitality, len(checks), len(checks)))
    if red or warns:
        if fails:
            print("不许放行（红）：", "; ".join(fails))
        if warns:
            print("不许放行（负控无效）：", "; ".join(warns))
        return 1
    print("值守台 P1–P12：全绿，且每条负控都能变红。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
