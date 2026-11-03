# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""D-1 接线判据腿：守护进程「到点自己起巡检」的四条腿 ＋ 两条不变量。

用法：python _p_linec_wiring.py <repo> <tmp_root>
期望：
  · 到点未跑 ⇒ 该跑；没到点 ⇒ 不跑；今天跑过 ⇒ 不跑
  · 该起 ⇒ 真的起（脚本路径对）、起失败 ⇒ 必须留痕（不许静默）
  · 不该跑 ⇒ 不写台账（否则每 2 秒一条会淹掉台账）
  · `run(linec=True)` 会去起；`run()` 默认不起（既有调用方行为不变）

★ 为什么这是独立探针而不是套件里的内联断言：它要起子进程、要设置
  `ANTINEL_HUB_DIR` 之后再 import 产品模块 —— 这两件事必须发生在**独立进程**里，
  否则会污染调用它的套件（`_paths` 与 `host_shield` 的中枢在 import 期就定了）。
"""
import json
import os
import sys
from datetime import datetime

REPO = os.path.abspath(sys.argv[1])
TMPROOT = os.path.abspath(sys.argv[2])

sys.path.insert(0, REPO)

HUB = os.path.join(TMPROOT, "hub")
os.makedirs(HUB, exist_ok=True)
os.environ["ANTINEL_HUB_DIR"] = HUB

import inbox_daemon as DM            # noqa: E402
import linec.nightwatch as NW        # noqa: E402

fails = []


def case(name, cond, detail=""):
    if cond:
        print("  OK  %-44s %s" % (name, detail))
    else:
        fails.append("%s｜%s" % (name, detail))
        print("  XX  %-44s %s" % (name, detail))


print("中枢 =", HUB)
print("状态 =", NW.default_state_path())
print("台账 =", DM.linec_spawn_log_path())

at_1000 = datetime(2026, 11, 3, 10, 0, 0)

# ---- ① 到点未跑 ⇒ 该跑 ----
due, why = DM.linec_due(now=at_1000)
case("① 到点未跑 ⇒ 该跑", due is True, why)

# ---- ② 没到点 ⇒ 不该跑 ----
due_early, why_early = DM.linec_due(now=datetime(2026, 11, 3, 8, 0, 0))
case("② 没到点 ⇒ 不跑", due_early is False, why_early)

# ---- ③ 今天已跑 ⇒ 不该跑 ----
NW.save_state(NW.default_state_path(), {
    "last_run_date": "2026-11-03", "last_run_at": "2026-11-03T09:00:05",
    "last_result": "ok", "why": "first-run-today"})
due_ran, why_ran = DM.linec_due(now=at_1000)
case("③ 今天已跑 ⇒ 不跑", due_ran is False, why_ran)

# ---- ④ 该起 ⇒ 真起（替身，不真跑 13 秒）----
NW.save_state(NW.default_state_path(), {})
seen = {}


def fake_spawn(script):
    seen["script"] = script
    seen["exists"] = os.path.isfile(script)
    return 4242


d = DM.Daemon().linec_once(now=at_1000, spawn=fake_spawn)
case("④ 该起 ⇒ 起了且脚本对",
     bool(d["started"]) and d["pid"] == 4242 and seen.get("exists") is True,
     "script=…%s" % (seen.get("script", "?")[-20:],))

logp = DM.linec_spawn_log_path()
ents = []
if os.path.isfile(logp):
    with open(logp, encoding="utf-8") as fh:
        ents = (json.load(fh).get("entries") or [])
case("④b 台账记了这一次", bool(ents) and ents[-1].get("started") is True,
     "%d 条" % len(ents))

# ---- ⑤ 起失败 ⇒ 必须留痕（"什么都没发生"与"起了但失败"不许同貌）----
NW.save_state(NW.default_state_path(), {})
n_before = len(ents)


def boom(script):
    raise OSError("policy-blocked")


d2 = DM.Daemon().linec_once(now=at_1000, spawn=boom)
with open(logp, encoding="utf-8") as fh:
    ents2 = (json.load(fh).get("entries") or [])
case("⑤ 起失败 ⇒ 有 error", bool(d2["error"]) and d2["started"] is False,
     (d2["error"] or "")[:36])
case("⑤b 起失败 ⇒ 台账带 error",
     len(ents2) == n_before + 1 and "policy-blocked" in (ents2[-1].get("error") or ""),
     "条数 %d→%d" % (n_before, len(ents2)))

# ---- ⑥ 不该跑 ⇒ 不写台账 ----
n_before2 = len(ents2)
NW.save_state(NW.default_state_path(), {
    "last_run_date": "2026-11-03", "last_run_at": "x", "last_result": "ok"})
d3 = DM.Daemon().linec_once(now=at_1000, spawn=fake_spawn)
with open(logp, encoding="utf-8") as fh:
    ents3 = (json.load(fh).get("entries") or [])
case("⑥ 不该跑 ⇒ 台账不增", (not d3["due"]) and len(ents3) == n_before2,
     "条数 %d→%d" % (n_before2, len(ents3)))

# ---- ⑦ run(linec=True) 真的会问 ----
calls1 = []


def counting(script):
    calls1.append(script)
    return 1


NW.save_state(NW.default_state_path(), {})
DM.Daemon(cfg={"touch_level": "L1"}).run(max_ticks=1, interval=0.01,
                                         linec=True, linec_spawn=counting)
case("⑦ run(linec=True) 会去起", len(calls1) == 1, "起 %d 次" % len(calls1))

# ---- ⑧ run 默认不起（既有行为一个字不变）----
calls2 = []


def never(script):
    calls2.append(script)
    return 2


NW.save_state(NW.default_state_path(), {})
DM.Daemon(cfg={"touch_level": "L1"}).run(max_ticks=1, interval=0.01)
case("⑧ run 默认不起", len(calls2) == 0, "起 %d 次" % len(calls2))

print()
if fails:
    for f in fails:
        print("FAIL", f)
    sys.exit(1)
print("接线全过（到点该跑 / 没到点不跑 / 跑过不跑 / 起失败留痕 / 默认不变）")
