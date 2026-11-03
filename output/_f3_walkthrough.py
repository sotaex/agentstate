# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""F3-2/3/6/7 机械化走查：在**隔离中枢**上把五个视图与页面按钮真跑一遍。

★ 这不是"看图"的替代品 —— 位置、观感、气泡弹出仍需人眼。
  它替代的是"点了会怎样"：每个 form 按页面**发出的原样**重放（同 `c_forms_replay`
  的判据思想），并回读状态断言"真的变了"。人眼负责剩下的一半。

用法：
  python output/_f3_walkthrough.py                 # 全部
  python output/_f3_walkthrough.py --only views    # 只跑视图
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
sys.path.insert(0, PKG)

HUB = os.path.join(os.environ.get("TEMP") or "/tmp", "antinel_f3_hub")
os.environ["ANTINEL_HUB_DIR"] = HUB

import inbox_server as SV          # noqa: E402
import inbox_store as S            # noqa: E402
import inbox_model as M            # noqa: E402

PORT = int(os.environ.get("F3_PORT") or 8799)
TOKEN = "f3walkthrough0123456789abcdef"
OUT = os.path.join(HERE, "_f3_shots")
os.makedirs(OUT, exist_ok=True)

VIEWS = ("inbox", "report", "health", "ledger", "health_exam")
FAIL = []
NOTE = []


def bad(what, detail):
    FAIL.append("%s —— %s" % (what, detail))
    print("  [红] %s —— %s" % (what, detail))


def ok(what, detail=""):
    print("  [绿] %s%s" % (what, (" —— " + detail) if detail else ""))


def fetch(path, data=None, timeout=90, auth=True):
    """发请求。`auth=False` ⇒ **一个口令都不带**（负控腿专用）。

    ★ 为什么单开一个开关（本轮第一次跑的教训）：负控原来只把 body 里的 `t` 清空，
      而 `fetch` 默认还带着 `X-Antinel-Token` 请求头 ⇒ 口令照样通过，
      返回的是 409（"批量处置没有指定对象"）而不是 403。
      **负控没打到门上**，报出来的红是我的量具错，不是产品错。
    """
    url = "http://127.0.0.1:%d%s" % (PORT, path)
    body = urllib.parse.urlencode(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body)
    if auth:
        req.add_header("X-Antinel-Token", TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)


# ------------------------------------------------------------------ 视图 ----
ANCHORS = {
    "inbox": ("要处理", "<form"),
    "report": ("日报", "<main>"),
    "health": ("体检", "<main>"),
    "ledger": ("账本", "<main>"),
    "health_exam": ("体检", "<main>"),
}


def visible_text(html):
    """页面**可见文本**（去样式表、脚本、HTML 注释）。

    ★ 为什么不能直接扫全文（本轮第一次跑就撞上的量具错）：页面 `<style>` 里
      有成段的中文注释，注释里带 markdown 星号 ⇒ 扫全文报「102 处星号」，
      而用户在屏幕上一个都看不见。判 D10/U-27 必须扫**看得见的那部分**。
    """
    h = re.sub(r"(?s)<style.*?</style>", " ", html)
    h = re.sub(r"(?s)<script.*?</script>", " ", h)
    h = re.sub(r"(?s)<!--.*?-->", " ", h)
    h = re.sub(r"(?s)<[^>]+>", " ", h)
    return re.sub(r"[ \t]+", " ", h)


def read_views():
    print("\n== 五视图 ==")
    pages = {}
    for v in VIEWS:
        t0 = time.time()
        st, body, hdr = fetch("/?t=%s&v=%s" % (TOKEN, v))
        dt = time.time() - t0
        open(os.path.join(OUT, "view_%s.html" % v), "w", encoding="utf-8").write(body)
        pages[v] = body
        if st != 200:
            bad("视图 %s" % v, "HTTP %d" % st)
            continue
        miss = [a for a in ANCHORS[v] if a not in body]
        if miss:
            bad("视图 %s" % v, "缺少锚点 %r" % (miss,))
        else:
            ok("视图 %s" % v, "HTTP 200 · %d 字节 · %.1fs" % (len(body), dt))
        if "**" in visible_text(body):
            n = visible_text(body).count("**")
            bad("视图 %s 的页面文本" % v, "可见文本里出现 %d 处 markdown 星号（D10/U-27 禁）" % n)
    return pages


def read_buckets():
    """三个桶各看一次，并读**页面自己印的数字**。

    ★ 第一版这里用"表单按钮个数"当条目数 —— 那是**代理量**，当场就错：
      按钮 4 个，而页面写着「要处理 2 件 / 看一眼 8 条 / 归档 5 条」。
      「看一眼」的条目本来就没有按钮（看一眼不用动手）⇒ 用按钮数量条目，
      会把"info 桶是空的"这种假结论印出来。⇒ 改读页面上的 `>要处理 <b>N</b>`。
    """
    print("\n== 三个桶 ==")
    counts = {}
    for f in ("action", "info", "archive"):
        st, body, _ = fetch("/?t=%s&v=inbox&f=%s" % (TOKEN, f))
        open(os.path.join(OUT, "bucket_%s.html" % f), "w", encoding="utf-8").write(body)
        if st != 200:
            bad("桶 %s" % f, "HTTP %d" % st)
            continue
        got = {}
        for name in ("要处理", "看一眼", "归档", "全部记录"):
            m = re.search(r">%s\s*<b>(\d+)</b>" % name, body)
            got[name] = int(m.group(1)) if m else None
        counts[f] = got
        ok("桶 %s" % f, "要处理 %s 件 · 看一眼 %s 条 · 归档 %s 条 · 全部 %s 条"
           % (got["要处理"], got["看一眼"], got["归档"], got["全部记录"]))
    act = counts.get("action", {}).get("要处理")
    if not act:
        bad("桶 action", "「要处理」是 %r —— 满态夹具下不该为空或读不到" % (act,))
    for name in ("看一眼", "归档"):
        v = counts.get("action", {}).get(name)
        if not v:
            bad("桶 %s" % name, "读数是 %r —— 满态夹具下三个桶都该有东西" % (v,))
    return counts


FORMS = re.compile(r'<form[^>]*action="/action"[^>]*>(.*?)</form>', re.S)
HID = re.compile(r'<input type=hidden name=(\w+) value="([^"]*)">')


def parse_forms(body):
    out = []
    for m in FORMS.finditer(body):
        d = dict(HID.findall(m.group(1)))
        label = re.search(r"<button[^>]*>(.*?)</button>", m.group(1), re.S)
        d["_label"] = label.group(1) if label else ""
        out.append(d)
    return out


#: 走查白名单：只碰"改收件箱状态"和"体检受理"这两类。
#: 其余动到**真实窗口/真实产品文件**的动作（collapse / winfit / bubble_open /
#: fix / guard_fix）**不在这里重放** —— 它们是 F3-4/5 的人工项，机械重放会
#: 关掉创始人正在看的窗口、或替他改产品文件。
SAFE_OPS = ("done", "ignored", "read", "done_all", "remediation_ack",
            "remediation_drop", "exam", "bubble_ack")


def states():
    return {it.id: it.state for it in S.load_items_all(root=HUB)}


def replay_buttons(pages):
    print("\n== 页面按钮重放（按页面发出的原样）==")
    body = pages.get("inbox") or ""
    forms = parse_forms(body)
    ops = {}
    for f in forms:
        ops[f.get("op", "")] = ops.get(f.get("op", ""), 0) + 1
    print("  页面上的动作按钮：%s" % json.dumps(ops, ensure_ascii=False, sort_keys=True))
    skipped = sorted(set(ops) - set(SAFE_OPS))
    if skipped:
        NOTE.append("未重放的动作（动真实窗口/产品文件，留给人工）：%s" % "、".join(skipped))

    before = states()
    # —— 单条「忽略」——
    ig = next((f for f in forms if f.get("op") == "ignored"), None)
    if ig is None:
        bad("按钮「忽略」", "页面上没有这个按钮")
    else:
        iid = ig.get("id", "")
        st, resp, _ = fetch("/action", {
            "t": TOKEN, "op": "ignored", "id": iid,
            "note": ig.get("note") or "走查：判断无需动作", "ids": ""})
        after = states()
        if after.get(iid) != "ignored":
            bad("按钮「忽略」", "点了之后状态是 %r，不是 ignored" % (after.get(iid),))
        else:
            ok("按钮「忽略」", "HTTP %d · %s → ignored" % (st, iid[:8]))
        # —— 同一条「重开」——
        st2, _r2, _ = fetch("/action", {"t": TOKEN, "op": "read", "id": iid,
                                        "note": "", "ids": ""})
        back = states().get(iid)
        if back == "ignored":
            bad("按钮「重开」", "点了之后仍是 ignored —— 手滑了撤不回来")
        else:
            ok("按钮「重开」", "HTTP %d · %s → %s" % (st2, iid[:8], back))

    # —— 批量「知道了」——
    da = next((f for f in forms if f.get("op") == "done_all"), None)
    if da:
        ids = (da.get("ids") or "").split(",")
        st, _r, _ = fetch("/action", {"t": TOKEN, "op": "done_all",
                                      "id": "", "ids": ",".join(ids), "note": ""})
        after = states()
        still = [i for i in ids if i and after.get(i) in M.OPEN_STATES]
        if still:
            bad("按钮「知道了（全部）」", "%d 条仍是未处理" % len(still))
        else:
            ok("按钮「知道了（全部）」", "HTTP %d · %d 条一次处置" % (st, len(ids)))
    else:
        NOTE.append("页面上没有「知道了（全部）」按钮 —— 本轮「要处理」的行数不足以触发归并批量")

    # —— 体检入口（只验受理，不等采集跑完）——
    ex = next((f for f in forms if f.get("op") == "exam"), None)

    # —— 口令缺失必须被拒（负控：证明上面的绿不是"门根本没关"）——
    st, txt, _ = fetch("/action", {"op": "done_all", "ids": ""}, auth=False)
    if st != 403:
        bad("负控：不带口令的按钮请求", "返回 %d，本应 403" % st)
    else:
        ok("负控：不带口令的按钮请求", "403（门是关着的）")
    return ex


def exam_view(ex_btn):
    print("\n== health_exam ==")
    st, body, _ = fetch("/?t=%s&v=health_exam" % TOKEN, timeout=120)
    if st != 200:
        bad("体检页", "HTTP %d" % st)
        return
    has_btn = ("开始体检" in body) or ("重新体检" in body)
    if not has_btn:
        bad("体检页", "既没有「开始体检」也没有「重新体检」按钮 —— 无处可点")
    else:
        ok("体检页按钮", "在（%s）" % ("开始体检" if "开始体检" in body else "重新体检"))
    if ex_btn is not None:
        t0 = time.time()
        st2, _r, _ = fetch("/action", {"t": TOKEN, "op": "exam", "id": "",
                                       "note": "", "ids": ""}, timeout=120)
        if st2 not in (200, 303):
            bad("体检按钮受理", "HTTP %d" % st2)
        else:
            ok("体检按钮受理", "HTTP %d · %.1fs（采集在后台线程，不等它跑完）"
               % (st2, time.time() - t0))
    # 导出入口（只读，不触发采集）
    st3, body3, _ = fetch("/exam-export?fmt=json", timeout=120)
    if st3 == 200 and body3.strip().startswith(("{", "[")):
        ok("体检导出", "HTTP 200 · 是合法 JSON 的开头")
    elif st3 == 404 and "先跑一次体检" in body3:
        # ★ 第一次跑走查时这里被我判成红 —— 判据错：这个 404 是**人话**，
        #   意思是"还没有结果可导出"，与"导出坏了"是两件事。
        ok("体检导出", "HTTP 404 且说人话（还没跑过体检，无处可导）")
        NOTE.append("体检导出这条要等真跑过一次体检后才有 200 可验")
    else:
        bad("体检导出", "HTTP %d · 开头 %r" % (st3, body3[:40]))


def anomalies():
    print("\n== 异常路径 ==")
    # ① 端口被占：不许静默 —— 必须换一个空闲端口并**说出来**
    #   ★ 第一次跑我用"同端口能不能再 bind 一次"来判，结果报红：本机的
    #     `ThreadingHTTPServer` 带 `SO_REUSEADDR`，能重绑。那是**我的测法错**，
    #     产品真正的处置在 `_serve_setup()`（它自己探占用、换口、并把原因说出来）。
    #     ⇒ 直接打产品那条路，判"换了口 + 说了原因"。
    try:
        httpd2, _tok, real_port, drift = SV._serve_setup(
            PORT, HUB, token=TOKEN, record=False)
        try:
            if real_port == PORT:
                bad("端口被占", "占用时仍拿到同一个端口 %d（说明它没发现占用）" % PORT)
            elif not drift:
                bad("端口被占", "换到了 %d 却**没说为什么**（静默换口）" % real_port)
            else:
                ok("端口被占", "换到 %d 并说出了原因（want=%s）"
                   % (real_port, drift.get("want")))
        finally:
            httpd2.server_close()
    except Exception as e:                                  # noqa: BLE001
        bad("端口被占", "整条路抛了 %r" % (e,))

    # ② 时钟：一条落在**未来**的记录（系统时钟被改 / 跨时区回拨的真实形状）
    import audit_chain as AC
    from datetime import datetime, timedelta
    fut = (datetime.now().astimezone() + timedelta(days=2)).isoformat(timespec="seconds")
    fn = os.path.join(HUB, "rollup", (datetime.now().astimezone()
                                      + timedelta(days=2)).date().isoformat() + ".jsonl")
    AC.append_chained(fn, {"schema": "1.19", "ts": fut, "type": "host_shield_changed",
                           "reason": "走查：一条来自未来的记录（时钟被改）"})
    st, body, _ = fetch("/?t=%s&v=inbox&f=action" % TOKEN)
    open(os.path.join(OUT, "anomaly_clock.html"), "w", encoding="utf-8").write(body)
    if st != 200:
        bad("时钟异常：未来记录", "收件箱页 HTTP %d —— 一条未来记录把整页弄挂了" % st)
    else:
        ok("时钟异常：未来记录", "收件箱页仍 200（%d 字节）" % len(body))

    # ③ 读坏的状态文件：必须**让开并继续**，不许把整箱带崩
    sp = S.state_path(root=HUB)
    keep = open(sp, encoding="utf-8").read() if os.path.exists(sp) else "{}"
    with open(sp, "w", encoding="utf-8") as f:
        f.write("{ 这不是 json")
    st, body, _ = fetch("/?t=%s&v=inbox" % TOKEN)
    if st != 200:
        bad("坏状态文件", "HTTP %d —— 状态坏了整箱打不开" % st)
    elif "corrupt" not in "".join(os.listdir(os.path.dirname(sp))):
        bad("坏状态文件", "页开了，但坏文件没有被改名让开（证据丢了）")
    else:
        ok("坏状态文件", "页照开，坏文件改名留在盘上")
    with open(sp, "w", encoding="utf-8") as f:
        f.write(keep)

    # ④ 断点续看：状态在盘上，重启后还在（不重启进程，只重读）
    before = states()
    S._PROJ_CACHE.clear()
    after = states()
    if before != after:
        bad("断点续看", "清掉投影缓存后状态变了 %d → %d 条" % (len(before), len(after)))
    else:
        ok("断点续看", "%d 条的已读/已处置痕迹全部还在" % len(after))


def main():
    if not os.path.isdir(HUB):
        raise SystemExit("夹具不在（先跑 output/_f3_make_hub.py）")
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), SV._make_handler(TOKEN, HUB))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print("走查服务：http://127.0.0.1:%d/  （中枢 %s）" % (PORT, HUB))
    try:
        pages = read_views()
        read_buckets()
        ex = replay_buttons(pages)
        exam_view(ex)
        anomalies()
    finally:
        httpd.shutdown()
    print("\n==== 结果 ====")
    for n in NOTE:
        print("  备注：%s" % n)
    if FAIL:
        print("  红 %d 条" % len(FAIL))
        for f in FAIL:
            print("   - %s" % f)
        return 1
    print("  全绿（无红项）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
