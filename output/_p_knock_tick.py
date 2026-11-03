# -*- coding: utf-8 -*-
"""第①项的 tick 接线验证：注入一条 L1 item，走完整一轮 tick。

用法：python _probe_knock_tick.py <repo> <tmp_root>
期望：
  · 第 1 轮：knock_daily 里 1 条（真的去敲了），quiet 里没有「已敲过」
  · 第 2 轮：knock_daily 空，quiet 里出现「本日窗口用完」
  · knock_daily=False：两轮都不敲
  · 跨日（today 变了）：又敲一次
"""
import os
import sys
import types

REPO = os.path.abspath(sys.argv[1])
TMPROOT = os.path.abspath(sys.argv[2])
sys.path.insert(0, REPO)

import inbox_daemon as D  # noqa: E402
import inbox_model as M  # noqa: E402

fails = []


def fake_item(tag="a1"):
    """用真的 Alert/Item 造一条，别用 SimpleNamespace —— 缺字段会在
    console_state 的桶计算里炸，看起来像被测代码坏了（实际是夹具不真）。

    ★ `tag` 必须每个场景不同：`tick` 里 `fresh = [it for it in items if it.id
      not in seen]`，同一个 id 第二轮就不再是"新事"，整段通知逻辑都不走。
      用同一个 id 测「同日第二次」，测到的是 seen 去重，**不是**每日额度 ——
      两件事同貌，但一个意味着"额度没生效"，另一个意味着"额度根本没被问到"。
    """
    a = M.Alert(id="fake-l1-" + tag, ts="2026-11-03T00:05:00+08:00", level="L1",
                kind="w1_probe_kind", title="试用：主动敲一次", detail="",
                severity="warning")
    return M.Item(alert=a)


def set_item(tag):
    D.S.load_items = lambda **kw: [fake_item(tag)]


def make_daemon(root, cfg, today):
    calls = []

    def bubbler(**kw):
        calls.append(kw)
        return {"ok": True, "opened": "app", "why": "注入"}

    d = D.Daemon(root=root, cfg=cfg, today=lambda: today,
                 bubbler=bubbler, console_url="http://127.0.0.1:1/x",
                 opener=lambda u: "none")
    return d, calls


def fresh(name):
    d = os.path.join(TMPROOT, name)
    os.makedirs(os.path.join(d, ".psl", "state"), exist_ok=True)
    os.makedirs(os.path.join(d, ".psl", "audit"), exist_ok=True)
    return d


# 打桩：目录里没有真审计链，直接给一条 item
_orig_load = D.S.load_items

root = fresh("t1")
daemon, calls = make_daemon(root, {"knock_daily": True, "heartbeat": False},
                            "2026-11-03")
set_item("a1")
r1 = daemon.tick()
print("第1轮 knock_daily=%d 次 bubbler 调用  quiet=%s"
      % (len(r1.get("knock_daily") or []), [q.get("why") for q in r1.get("quiet") or []][:3]))
if len(r1.get("knock_daily") or []) != 1:
    fails.append("第1轮应敲 1 次，实测 %d" % len(r1.get("knock_daily") or []))
if len(calls) != 1:
    fails.append("第1轮 bubbler 应被调 1 次，实测 %d" % len(calls))

set_item("a2")
r2 = daemon.tick()
_q2 = [q.get("why") for q in r2.get("quiet") or []]
print("第2轮 knock_daily=%d 次  quiet=%s"
      % (len(r2.get("knock_daily") or []), _q2[:3]))
if len(r2.get("knock_daily") or []) != 0:
    fails.append("第2轮不应再敲，实测 %d" % len(r2.get("knock_daily") or []))
if len(calls) != 1:
    fails.append("第2轮 bubbler 不应再被调，实测累计 %d" % len(calls))
if not any("不再重复" in (w or "") for w in _q2):
    fails.append("第2轮 quiet 里应有「不再重复」，实测 %s" % _q2[:3])

# 跨日 ⇒ 再敲一次
daemon2, calls2 = make_daemon(root, {"knock_daily": True, "heartbeat": False},
                              "2026-11-04")
set_item("a3")
r3 = daemon2.tick()
print("跨日轮 knock_daily=%d 次" % len(r3.get("knock_daily") or []))
if len(r3.get("knock_daily") or []) != 1:
    fails.append("跨日应再敲 1 次，实测 %d" % len(r3.get("knock_daily") or []))

# 开关关掉 ⇒ 一次都不敲（回退位）
root2 = fresh("t2")
daemon3, calls3 = make_daemon(root2, {"knock_daily": False, "heartbeat": False},
                              "2026-11-03")
set_item("a4")
r4 = daemon3.tick()
_q4 = [q.get("why") for q in r4.get("quiet") or []]
print("关闭轮 knock_daily=%d 次  quiet=%s"
      % (len(r4.get("knock_daily") or []), _q4[:2]))
if calls3:
    fails.append("knock_daily=False 时不应敲，实测 bubbler 被调 %d 次" % len(calls3))
if not any("knock_daily 关闭" in (w or "") for w in _q4):
    fails.append("关闭时 quiet 应写明原因，实测 %s" % _q4[:2])

D.S.load_items = _orig_load
print()
if fails:
    for f in fails:
        print("FAIL", f)
    sys.exit(1)
print("接线全过（首轮敲 1 次 / 同日不重敲 / 跨日重开 / 开关可停）")
