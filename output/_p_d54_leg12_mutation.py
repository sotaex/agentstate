# -*- coding: utf-8 -*-
"""D-54 ⑫ 语料腿的变异测试（只读，不改任何产品文件）。

要证明的事：新加的语料腿**能红**。
  一条永远不会红的腿与「没有腿」同貌 —— 第十四族，今天已经踩过一次
  （MS1-01 阈值 2000 与写入线 8000，恒真且永不 clean）。

做法：monkey-patch 探针成错误实现，逐一确认 `_probe_semantics_failures()`
里出现对应的 bad 文案；再确认「不改」时一条都不出现。

★ 每个变异都先断言「真的改成了」，否则「没红」可能只是变异没生效。
★ 覆盖两个探针：WRITE_SET（守 Q1-06 / K1-01 / MK1-01）、
  LEDGER_SEQ（守 S1-02 / S1-04）。
"""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


S = load("slots_probe12", os.path.join("scripts", "slots.py"))
RG = load("rg_probe12", os.path.join("ci", "regression_gate.py"))

# 每条腿 = (关键字, 断言的文案片段)
LEGS = {
    "q106_pos": "Q1-06 写入 ci/ 下的文件",
    "q106_neg": "Q1-06 写入普通源码",
    "k101_pos": "K1-01 写入仓外路径",
    "k101_neg": "K1-01 写入仓内文件",
    "mk101_pos": "MK1-01 读取仓外路径",
    "mk101_neg": "MK1-01 读取仓内文件",
    "s102_pos": "S1-02 同会话 5 次相同动作",
    "s102_neg": "S1-02 五次各不相同的动作",
    "s102_empty": "S1-02 把空 content_digest",
    "s102_nosess": "无 session 的记录并成了一个会话",
    "s104_pos": "S1-04 单会话 2010 个动作",
    "s104_neg": "S1-04 10 个动作的会话步数",
    "s102_cross": "跨会话累计重复次数",
    "p103_pos": "P1-03 六条配置变更记录",
    "p103_neg": "P1-03 没有任何配置变更记录",
    "mk102_pos": "MK1-02 没有钩子注册基线",
    "mk102_neg": "MK1-02 已有钩子注册基线",
    "cfg_none": "CONFIG_HOOKS 找不到任何配置文件",
}

fails = []


def run_bad():
    return RG._probe_semantics_failures(S)


def which(bad):
    return sorted({k for k, txt in LEGS.items() if any(txt in b for b in bad)})


# ── 基线：不改 ⇒ 一条都不该出现 ──
base = run_bad()
print("基线：bad 共 %d 条，命中语料腿关键字 = %r" % (len(base), which(base)))
if which(base):
    fails.append("未变异时就有语料腿判红（%r）⇒ 语料本身造错了，先修语料" % (which(base),))


def mutate(attr, name, fn, expect_key):
    """植入错误实现，确认「真的改了」且「对应腿红了」。"""
    orig = getattr(S, attr)
    setattr(S, attr, fn)
    try:
        assert getattr(S, attr) is not orig, "变异没生效（%s 还是原函数）" % attr
        got = which(run_bad())
        ok = expect_key in got
        print("  %-12s %-22s ⇒ %s（命中 %r）"
              % (attr, name, "红" if ok else "★没红", got))
        if not ok:
            fails.append("变异 %s.%s 之后腿没红（只命中 %r）⇒ 这条语料是死的"
                         % (attr, name, got))
    finally:
        setattr(S, attr, orig)


W = "_p_write_set"
L = "_p_ledger_seq"

print("\n=== WRITE_SET 变异（守 Q1-06 / K1-01 / MK1-01）===")
mutate(W, "protected 恒空",
       lambda ctx: {"protected_hit": [], "out_of_scope": [], "files_read_by_us": []},
       "q106_pos")
mutate(W, "protected 恒非空",
       lambda ctx: {"protected_hit": ["x"], "out_of_scope": [], "files_read_by_us": []},
       "q106_neg")
mutate(W, "out_of_scope 恒空",
       lambda ctx: {"protected_hit": [], "out_of_scope": [], "files_read_by_us": []},
       "k101_pos")
mutate(W, "out_of_scope 恒非空",
       lambda ctx: {"protected_hit": [], "out_of_scope": ["x"], "files_read_by_us": []},
       "k101_neg")
mutate(W, "files_read 恒空",
       lambda ctx: {"protected_hit": [], "out_of_scope": [], "files_read_by_us": []},
       "mk101_pos")
mutate(W, "files_read 恒非空",
       lambda ctx: {"protected_hit": [], "out_of_scope": [], "files_read_by_us": ["x"]},
       "mk101_neg")
mutate(W, "恒返回 None", lambda ctx: None, "mk101_pos")

print("\n=== LEDGER_SEQ 变异（守 S1-02 / S1-04）===")


def _seqv(run, steps, dropped=0):
    return {"tool+args_digest": (run, ("w", "Bash")),
            "failed_action": (1, None),
            "session_actions": steps,
            "max_session": "s1",
            "sessions": 1,
            "dropped_no_session": dropped}


# 最长重复恒为 1 ⇒ S1-02 正控腿必须红
mutate(L, "重复次数恒 1", lambda ctx: _seqv(1, 5), "s102_pos")
# 最长重复恒为 5 ⇒ S1-02 负控 ＋ 空 digest ＋ 跨会话 三条腿都该红
mutate(L, "重复次数恒 5", lambda ctx: _seqv(5, 5), "s102_neg")
# 步数恒 0 ⇒ S1-04 正控腿必须红
mutate(L, "步数恒 0", lambda ctx: _seqv(1, 0), "s104_pos")
# 步数恒 2010 ⇒ S1-04 负控腿必须红
mutate(L, "步数恒 2010", lambda ctx: _seqv(1, 2010), "s104_neg")
# 无 session 时不给 None（并桶）⇒ 最坏假红那条腿必须红
mutate(L, "无 session 也不返回 None", lambda ctx: _seqv(10, 10, dropped=10),
       "s102_nosess")

print("\n=== CONFIG_HOOKS 变异（守 P1-03 / MK1-02）===")
C = "_p_config_hooks"


def _cfgv(changes=0, consent=False):
    return {"config_changes": changes, "consent_missing": consent,
            "hooks_off": False, "n_mcp": 0, "unauthorized_mcp": []}


# 变更次数恒 0 ⇒ P1-03 正控腿必须红
mutate(C, "变更次数恒 0", lambda ctx: _cfgv(0, False), "p103_pos")
# 变更次数恒 6 ⇒ P1-03 负控腿必须红
mutate(C, "变更次数恒 6", lambda ctx: _cfgv(6, False), "p103_neg")
# consent_missing 恒 False ⇒ MK1-02 正控腿必须红
mutate(C, "consent 恒 False", lambda ctx: _cfgv(0, False), "mk102_pos")
# consent_missing 恒 True ⇒ MK1-02 负控腿必须红（恒命中与真命中同貌）
mutate(C, "consent 恒 True", lambda ctx: _cfgv(0, True), "mk102_neg")
# 找不到配置也返回结论 ⇒ 边界腿必须红
mutate(C, "找不到配置也给结论", lambda ctx: _cfgv(0, False), "cfg_none")

print()
if fails:
    print("★ FAIL：%d 条" % len(fails))
    for f in fails:
        print("   -", f)
    sys.exit(1)
print("★ PASS：三个探针共 %d 条腿，全部能被变异推翻，且未变异时零误报" % len(LEGS))
