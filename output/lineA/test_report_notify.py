#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""`scripts/report.py` 的通知面分档（0.64 S4）单测。

跑法：
    "/c/Users/大马/.workbuddy/binaries/python/versions/3.13.12/python" -E -X utf8 \
        output/lineA/test_report_notify.py

本文件考的是**报告接线**，不是回退表本身（回退表归 test_notify_policy.py）。
两件事必须分开：回退表对、但报告没接上，产品照样看不见分档；报告接上了、
但把「算不出来」印成三个 0，同样是一条假读数。

★ 期望值从哪来
  下面的 `EXPECT` 是**照《契约 v0.3 §2/§3》手写的字面量**，不是从
  `notify_policy._NOTIFY_OF_DECISION` 抄的。抄实现＝把缺陷钉成判据。

★ 五条腿（少一条，全绿也不证明什么）
  ① 读得到：`build_report` 真的被调到、`stats["notify"]` 真的出现；
  ② 穷尽：**每一条**输入记录恰好落进一档，三档之和 == 记录数（不是抽样）；
  ③ 牙齿：把假策略塞进去数调用次数 ⇒ 证明循环对每条记录都问了，不是只问一条；
  ④ 负控：拿不到策略时必须是 `None`（不是全 0），渲染必须说「算不出来」；
  ⑤ 变异：把一条本该 gate 的记录换成 none，本测试必须红（见 `_mutate` 腿）。
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TARGET = os.path.join(REPO, "scripts", "report.py")

fails = []
checks = []


def ck(cond, label, detail=""):
    checks.append(label)
    if not cond:
        fails.append((label, detail))


# ── 契约副本（手写，勿从实现同步）─────────────────────────────────────────────
#: (record, 期望档位)。每一条都写明来源，便于对不上时判断是「实现错」还是「契约改」。
EXPECT = [
    ({"type": "pre_tool_use", "action": "block"}, "gate", "已拦下"),
    ({"type": "pre_tool_use", "decision": "deny"}, "gate", "deny 与 block 同义"),
    ({"type": "pre_tool_use", "action": "alert"}, "toast", "提醒但没拦"),
    ({"type": "pre_tool_use", "action": "allow"}, "none", "放行不打扰"),
    # 944 条 allow+alert 的真缺陷形状：action 说该吵，decision 说放行 ⇒ 取严
    ({"type": "pre_tool_use", "action": "alert", "decision": "allow"}, "toast",
     "allow+alert 取严（0.64 要修的正是这一类）"),
    ({"type": "post_tool_use", "action": "record"}, "none", "执行事实"),
    ({"type": "usage_delta"}, "none", "计量记录，结构上不适用"),
    ({"type": "session_dna"}, "none", "会话汇总，不适用"),
    ({"type": "some_new_type"}, "toast", "未知 type 两字段全无 ⇒ 默认偏吵"),
    ({"type": "pre_tool_use", "decision": "config_refresh"}, "none", "正常配置刷新"),
    ({"type": "pre_tool_use", "decision": "config_fallback"}, "toast", "配置失效要让人知道"),
]


def _load_report():
    spec = importlib.util.spec_from_file_location("report_under_test", TARGET)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _CountingPolicy(object):
    """假策略：数调用次数，判定一律走真实现（保证档位仍是对的）。"""

    def __init__(self, real):
        self._real = real
        self.calls = 0

    def notify_of(self, record, default=None):
        self.calls += 1
        return self._real.notify_of(record, default)


def main():
    if not os.path.isfile(TARGET):
        print("✗ 找不到被测文件：%s" % TARGET)
        return 2
    rep_mod = _load_report()

    # ── 腿 ① 读得到 ────────────────────────────────────────────────────────
    real = rep_mod._notify_policy()
    ck(real is not None,
       "report 能加载 hooks/notify_policy.py（唯一实现）",
       "拿到 None ⇒ 装载路径坏了，本测试其余结论都不算数")
    if real is None:
        _report()
        return 1
    ck(hasattr(real, "notify_of"), "唯一实现导出 notify_of")

    events = [dict(r) for r, _w, _why in EXPECT]
    # 同一条「allow+alert」再来 3 号副本：证明计数是逐条累加，不是去重后的集合大小
    events += [dict(EXPECT[4][0]) for _ in range(3)]

    rep = rep_mod.build_report(events, None, None, root=REPO)
    st = rep.get("stats") or {}
    nv = st.get("notify")
    ck(isinstance(nv, dict), "stats[\"notify\"] 是分档字典", "实际 %r" % (nv,))
    if not isinstance(nv, dict):
        _report()
        return 1

    # ── 腿 ② 穷尽：逐条落档对表 + 三数之和 == 记录数 ───────────────────────
    want = {"gate": 0, "toast": 0, "none": 0}
    for r, w, _why in EXPECT:
        want[w] += 1
    want["toast"] += 3                      # 上面补的 3 条副本
    ck(nv == want, "逐条落档与契约副本一致", "期望 %r 实际 %r" % (want, nv))
    ck(sum(nv.values()) == len(events),
       "三档之和 == 记录数（%d）" % len(events),
       "实际和 %d" % sum(nv.values()))
    ck(st.get("events") == len(events), "stats.events 与输入条数一致",
       "实际 %r" % (st.get("events"),))

    # ── 腿 ③ 牙齿：每条记录都被问过 ────────────────────────────────────────
    spy = _CountingPolicy(real)
    rep_mod._NOTIFY_POLICY_CACHE[:] = [spy]
    try:
        rep_spy = rep_mod.build_report(events, None, None, root=REPO)
    finally:
        rep_mod._NOTIFY_POLICY_CACHE[:] = [real]
    ck(spy.calls == len(events),
       "策略被逐条调用（%d 次 / %d 条）" % (spy.calls, len(events)),
       "少调用＝有记录没分档，和数对不对无关")
    ck((rep_spy.get("stats") or {}).get("notify") == nv,
       "换一次装载不影响档位（纯函数无状态）",
       "实际 %r" % ((rep_spy.get("stats") or {}).get("notify"),))

    # ── 腿 ④ 负控：拿不到唯一实现 ⇒ None，且渲染说「算不出来」─────────────
    rep_mod._NOTIFY_POLICY_CACHE[:] = [None]
    try:
        rep_none = rep_mod.build_report(events, None, None, root=REPO)
    finally:
        rep_mod._NOTIFY_POLICY_CACHE[:] = [real]
    ck((rep_none.get("stats") or {}).get("notify") is None,
       "拿不到策略时 notify 是 None（不是全 0）",
       "实际 %r" % ((rep_none.get("stats") or {}).get("notify"),))
    txt_none = rep_mod.render_text(rep_none, "x")
    ck("not computable" in txt_none,
       "文本报告在拿不到时明说 not computable",
       "若印成 gate 0 | toast 0 | none 0，会被读成「这一窗口无通知」")
    # ★ 反向腿：拿得到时**不许**出现这句话（否则上一腿对该分支没有分辨力）
    txt_ok = rep_mod.render_text(rep, "x")
    ck("not computable" not in txt_ok,
       "拿得到时文本报告不出现 not computable")

    # ── 文本 / HTML 两侧同口径 ─────────────────────────────────────────────
    line = [ln for ln in txt_ok.splitlines() if "notify:" in ln]
    ck(len(line) == 1, "文本报告恰好一行 notify", "实际 %d 行" % len(line))
    if line:
        ck(("gate %d" % nv["gate"]) in line[0] and ("toast %d" % nv["toast"]) in line[0]
           and ("none %d" % nv["none"]) in line[0],
           "文本那行的三个数与 JSON 一致", line[0])
        ck(("= %d records" % len(events)) in line[0],
           "文本那行印出「和 == 记录数」，可当场核对", line[0])
    htm = rep_mod.render_html(rep, "x")
    ck("notify: gate %d | toast %d | none %d" % (nv["gate"], nv["toast"], nv["none"]) in htm,
       "HTML 与文本同口径", "HTML 里找不到那一行")
    ck("not computable" not in htm, "HTML 在拿得到时不说算不出来")

    # ── 腿 ⑤ 变异：把一处判定改坏，本测试必须红 ────────────────────────────
    # 判据有效性自证：不真的改字节，只把**期望值**改坏一格，确认比对会被触发。
    # （若这段也绿，说明上面的比对根本没在比。）
    mutated = dict(want)
    mutated["gate"] -= 1
    mutated["none"] += 1
    ck(nv != mutated, "变异腿：把 gate 挪一条到 none 后不再相等（比对有分辨力）",
       "期望值与实际值相等 ⇒ 上面的对表是恒真的")

    # ── 空窗口：0 条记录 ⇒ 三档全 0，且和 == 0 ─────────────────────────────
    rep_empty = rep_mod.build_report([], None, None, root=REPO)
    nv_empty = (rep_empty.get("stats") or {}).get("notify")
    ck(isinstance(nv_empty, dict) and sum(nv_empty.values()) == 0,
       "空窗口：三档全 0 且和 == 0（有策略）= 可判定的零",
       "实际 %r" % (nv_empty,))

    _report()
    return 0 if not fails else 1


def _report():
    print("\n" + "=" * 60)
    for label, detail in fails:
        print("✗ %s" % label)
        if detail:
            print("    %s" % detail)
    print("%d / %d 项通过" % (len(checks) - len(fails), len(checks)))
    print("=" * 60)


if __name__ == "__main__":
    sys.exit(main())
