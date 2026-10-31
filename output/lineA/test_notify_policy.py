#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""`hooks/notify_policy.py` 的单测（0.64 S1）。

跑法：
    "/c/Users/大马/.workbuddy/binaries/python/versions/3.13.12/python" -E -X utf8 \
        output/lineA/test_notify_policy.py

★ 期望值从哪来
  下面的 `SPEC_DECISION_TO_NOTIFY` 是**照《契约 v0.3 §3 回退表》手写的字面量**，
  不是从 `notify_policy._NOTIFY_OF_DECISION` 抄的。抄实现等于把缺陷钉成判据
  （本项目假绿第一族：期望值从实现现状取）。两边不一致时，本测试红，
  然后由人判断是「实现错了」还是「契约改了」。

★ 四条自证腿（不做的话，全绿也不证明任何事）
  ① 读得到：模块真的 import 成功，且回退表非空、非事件集非空；
  ② 穷举：回退表里**每一个** decision 键都被本测试考到（不靠手抄漏掉）；
  ③ 负控：四类「不该发生」的判定必须真的不成立；
  ④ 变异：把实现改坏一处，本测试必须报红（证明它有分辨力，不是恒绿）。
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TARGET = os.path.join(REPO, "hooks", "notify_policy.py")


def _load(path, name="notify_policy_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── 契约 v0.3 §3 的独立副本（手写，勿从实现同步）───────────────────────────
SPEC_DECISION_TO_NOTIFY = {
    "block": "gate",
    "deny": "gate",
    "alert": "toast",
    "warn": "toast",
    "config_fallback": "toast",
    "config_rejected": "toast",
    "finding": "toast",
    "config_refresh": "none",
    "allow": "none",
}

#: 结构上不是事件的 type（契约 §2 白名单 ＋ 实测补的三类，见模块头注释）
SPEC_NON_EVENT = {
    "usage_delta",
    "session_dna",
    "pre_tool_use_summary",
    "notice_budget_window_closed",
    "notice_budget_merged",
}

fails = []
checks = []


def ck(cond, label, detail=""):
    checks.append(label)
    if not cond:
        fails.append((label, detail))


def main():
    if not os.path.isfile(TARGET):
        print("✗ 找不到被测文件：%s" % TARGET)
        return 2
    np = _load(TARGET)

    # ── 自证腿 ① 读得到 ────────────────────────────────────────────────────
    ck(hasattr(np, "notify_of"), "模块导出 notify_of")
    ck(hasattr(np, "decision_of"), "模块导出 decision_of")
    ck(hasattr(np, "explain"), "模块导出 explain")
    ck(set(np.NOTIFY_LEVELS) == {"gate", "toast", "none"},
       "三档集合恰为 gate/toast/none", str(getattr(np, "NOTIFY_LEVELS", None)))
    ck(np.NOTIFY_DEFAULT == "toast", "默认档是 toast（偏吵）", str(np.NOTIFY_DEFAULT))

    table = dict(getattr(np, "_NOTIFY_OF_DECISION", {}) or {})
    ck(len(table) >= 9, "回退表至少 9 条", "实际 %d" % len(table))
    ck(len(np.NON_EVENT_TYPES) >= 5, "非事件集至少 5 类",
       "实际 %d" % len(np.NON_EVENT_TYPES))

    # ── 自证腿 ② 穷举：实现里每个 decision 键都被考到 ──────────────────────
    missing_in_spec = sorted(set(table) - set(SPEC_DECISION_TO_NOTIFY))
    ck(not missing_in_spec,
       "实现里的每个 decision 键在契约副本里都有对应行",
       "缺失：%s" % missing_in_spec)
    missing_in_impl = sorted(set(SPEC_DECISION_TO_NOTIFY) - set(table))
    ck(not missing_in_impl,
       "契约副本里的每行实现都覆盖了",
       "实现缺：%s" % missing_in_impl)

    # ── 逐 decision 对表（用最小 record，只给 decision）────────────────────
    for dec, want in sorted(SPEC_DECISION_TO_NOTIFY.items()):
        got = np.notify_of({"type": "pre_tool_use", "decision": dec})
        ck(got == want, "decision=%-16s ⇒ %-5s" % (dec, want), "实际 %r" % got)

    # ── action 四值与「取严」──────────────────────────────────────────────
    # 用「action 与 decision 故意打架」的 record，验证取更重的那个。
    # ★ 这里曾写错一次：第一版把 action=allow + decision=alert 期望成 none
    #   （默认了「action 优先」）。实测全量交叉表里不存在这个反方向，
    #   但规则改成取严后它是 toast —— 期望跟着规格改，不是跟着实现改。
    cases_action = [
        ({"action": "block", "decision": "allow"}, "gate", "action=block 压过 decision=allow"),
        ({"action": "alert", "decision": "allow"}, "toast", "action=alert 压过 decision=allow"),
        ({"action": "allow", "decision": "alert"}, "toast", "decision=alert 压过 action=allow（取严）"),
        ({"action": "allow", "decision": "block"}, "gate", "decision=block 压过 action=allow（取严）"),
        ({"action": "record", "decision": None}, "none", "action=record ⇒ 执行事实"),
    ]
    for rec, want, label in cases_action:
        rec = dict(rec, type="pre_tool_use")
        got = np.notify_of(rec)
        ck(got == want, label, "实际 %r" % got)

    # ── 安全腿：allow + 高 severity 必须升级（333 条 critical+allow 的修法）──
    for sev in ("critical", "warning"):
        got = np.notify_of({"type": "pre_tool_use", "action": "allow", "severity": sev})
        ck(got == "toast", "action=allow + severity=%-9s ⇒ toast（不许静默）" % sev,
           "实际 %r" % got)
    for sev in ("none", "info", None):
        got = np.notify_of({"type": "pre_tool_use", "action": "allow", "severity": sev})
        ck(got == "none", "action=allow + severity=%-9s ⇒ none" % str(sev),
           "实际 %r" % got)

    # ── 配置面不被 action 覆盖 ─────────────────────────────────────────────
    for dec, want in (("config_refresh", "none"), ("config_fallback", "toast"),
                      ("config_rejected", "toast"), ("finding", "toast")):
        got = np.notify_of({"type": "rules_snapshot_refreshed", "action": "alert",
                            "decision": dec})
        ck(got == want, "配置面 decision=%-16s 不被 action=alert 覆盖 ⇒ %s" % (dec, want),
           "实际 %r" % got)

    # ── deny 归一成 block（同义合并，S5）──────────────────────────────────
    ck(np.decision_of(None, None, "deny") == "block", "decision_of 把 deny 归一为 block",
       str(np.decision_of(None, None, "deny")))
    ck(np.notify_of({"type": "host_shield_breach", "decision": "deny"}) == "gate",
       "历史 deny 记录 ⇒ gate")

    # ── 非事件 type 全覆盖（负控：一个都不许误报）────────────────────────
    for t in sorted(SPEC_NON_EVENT):
        got = np.notify_of({"type": t, "action": "alert", "decision": "alert"})
        ck(got == "none", "非事件 type=%-28s ⇒ none（不许误报）" % t, "实际 %r" % got)
    impl_only = sorted(set(np.NON_EVENT_TYPES) - SPEC_NON_EVENT)
    ck(not impl_only, "实现没偷偷多白名单 type", "多出：%s" % impl_only)

    # ── 默认偏吵（负控的反面：不能因为没见过就静音）──────────────────────
    ck(np.notify_of({"type": "brand_new_type"}) == "toast",
       "未知 type 且字段全无 ⇒ toast（偏吵）",
       str(np.notify_of({"type": "brand_new_type"})))
    ck(np.notify_of({"type": "pre_tool_use", "decision": "some_new_value"}) == "toast",
       "未知 decision 值 ⇒ toast（偏吵）",
       str(np.notify_of({"type": "pre_tool_use", "decision": "some_new_value"})))
    ck(np.notify_of(None) == "toast", "record 为 None ⇒ toast", str(np.notify_of(None)))
    ck(np.notify_of("not-a-dict") == "toast", "record 不是 dict ⇒ toast")
    ck(np.notify_of({}) == "toast", "空 record ⇒ toast")
    ck(np.notify_of({"type": "pre_tool_use", "decision": "  allow  "}) == "none",
       "decision 两侧空白被裁掉")

    # ── explain 与实际判定一致（对账用，不能另说一套）─────────────────────
    for rec in ({"type": "pre_tool_use", "decision": "block"},
                {"type": "usage_delta"},
                {"type": "brand_new_type"}):
        n, d, why = np.explain(rec)
        ck(n == np.notify_of(rec), "explain 与 notify_of 对 %s 一致" % rec.get("type"),
           "%r vs %r" % (n, np.notify_of(rec)))
        ck(isinstance(why, str) and why, "explain 给出非空理由")

    # ── 自证腿 ④ 变异：把实现改坏，检查必须报红 ───────────────────────────
    # 做法：在临时副本里把 block 的档位改成 none，再用**同一套检查**跑一遍，
    # 必须至少出现一条红。全程不写仓内文件。
    import tempfile
    import shutil
    tmpd = tempfile.mkdtemp(prefix="np_mut_")
    try:
        src = open(TARGET, encoding="utf-8").read()
        needle = '"block": GATE,'
        if needle not in src:
            ck(False, "变异腿：找到变异锚点", "锚点 %r 不存在" % needle)
        else:
            mut = src.replace(needle, '"block": NONE,', 1)
            ck(mut != src, "变异腿：确实改到了字节")
            mp = os.path.join(tmpd, "notify_policy_mut.py")
            with open(mp, "w", encoding="utf-8") as f:
                f.write(mut)
            m = _load(mp, "notify_policy_mut")
            got = m.notify_of({"type": "pre_tool_use", "decision": "block"})
            ck(got != SPEC_DECISION_TO_NOTIFY["block"],
               "变异腿：block→none 后与契约不符（检查有分辨力）",
               "变异后仍得 %r，说明检查恒绿" % got)
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)

    # ── 汇总 ───────────────────────────────────────────────────────────────
    print("=" * 74)
    print("notify_policy 单测 —— %d 项检查" % len(checks))
    print("=" * 74)
    if fails:
        for label, detail in fails:
            print("  ✗ %-58s %s" % (label, detail))
        print("-" * 74)
        print("★ FAIL：%d / %d 不通过" % (len(fails), len(checks)))
        return 1
    print("  ✅ 全部通过（含穷举、四类负控、变异腿）")
    print("  读数：回退表 %d 个 decision ／ 非事件集 %d 类"
          % (len(table), len(np.NON_EVENT_TYPES)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
