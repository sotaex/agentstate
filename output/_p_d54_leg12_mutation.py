# -*- coding: utf-8 -*-
"""D-54 ⑫ 语料腿的变异测试（只读，不改任何产品文件）。

要证明的事：新加的 WRITE_SET 语料腿**能红**。
  一条永远不会红的腿与「没有腿」同貌 —— 这是第十四族，今天已经踩过一次
  （MS1-01 阈值 2000 与写入线 8000，恒真且永不 clean）。

做法：monkey-patch `slots._p_write_set` 成四种错误实现，逐一确认
`regression_gate._probe_semantics_failures()` 里出现对应的 bad 文案；
再确认「不改」时一条都不出现。

★ 每个变异都先断言「真的改成了」，否则「没红」可能只是变异没生效。
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

ORIG = S._p_write_set

KEYWORDS = {
    "q106_pos": "Q1-06 写入 ci/ 下的文件",
    "q106_neg": "Q1-06 写入普通源码",
    "k101_pos": "K1-01 写入仓外路径",
    "k101_neg": "K1-01 写入仓内文件",
    "mk101_pos": "MK1-01 读取仓外路径",
    "mk101_neg": "MK1-01 读取仓内文件",
}


def run_bad():
    return RG._probe_semantics_failures(S)


def which(bad):
    return sorted({k for k, txt in KEYWORDS.items()
                   if any(txt in b for b in bad)})


fails = []

# ── 基线：不改 ⇒ 这六条一条都不该出现 ──
base = run_bad()
hit = which(base)
print("基线：bad 共 %d 条，命中语料腿关键字 = %r" % (len(base), hit))
if hit:
    fails.append("未变异时就有语料腿判红（%r）⇒ 语料本身造错了，先修语料" % (hit,))


def mutate(name, fn, expect_key):
    """植入错误实现，确认「真的改了」且「对应腿红了」。"""
    S._p_write_set = fn
    try:
        assert S._p_write_set is not ORIG, "变异没生效（还是原函数）"
        got = which(run_bad())
        print("  变异 %-22s ⇒ 命中 %r（期望含 %s）" % (name, got, expect_key))
        if expect_key not in got:
            fails.append("变异 %s 之后腿没红（只命中 %r）⇒ 这条语料是死的"
                         % (name, got))
    finally:
        S._p_write_set = ORIG


print("\n=== 四种变异 ===")

# ① protected_hit 恒空 ⇒ Q1-06 正控腿必须红
mutate("protected 恒空",
       lambda ctx: {"protected_hit": [], "out_of_scope": [],
                    "files_read_by_us": []},
       "q106_pos")

# ② protected_hit 恒非空 ⇒ Q1-06 负控腿必须红
mutate("protected 恒非空",
       lambda ctx: {"protected_hit": ["x"], "out_of_scope": [],
                    "files_read_by_us": []},
       "q106_neg")

# ③ out_of_scope 恒空 ⇒ K1-01 正控腿必须红
mutate("out_of_scope 恒空",
       lambda ctx: {"protected_hit": [], "out_of_scope": [],
                    "files_read_by_us": []},
       "k101_pos")

# ④ files_read_by_us 恒非空 ⇒ MK1-01 负控腿必须红
mutate("files_read 恒非空",
       lambda ctx: {"protected_hit": [], "out_of_scope": [],
                    "files_read_by_us": ["x"]},
       "mk101_neg")

# ⑤ out_of_scope 恒非空 ⇒ K1-01 负控腿必须红
#   ★ 这条是补的：上面 ③ 只证明了正控（该报时报），没证明负控（不该报时不报）。
#     只有正控的判据与「恒命中」同貌 —— 每次编辑都报范围漂移，读数的人会关掉它。
mutate("out_of_scope 恒非空",
       lambda ctx: {"protected_hit": [], "out_of_scope": ["x"],
                    "files_read_by_us": []},
       "k101_neg")

# ⑥ files_read_by_us 恒空 ⇒ MK1-01 正控腿必须红
mutate("files_read 恒空",
       lambda ctx: {"protected_hit": [], "out_of_scope": [],
                    "files_read_by_us": []},
       "mk101_pos")

# ⑤ 只有读时返回 None ⇒ 边界腿必须红
S._p_write_set = lambda ctx: None
try:
    assert S._p_write_set is not ORIG
    bad5 = run_bad()
    got5 = any("只有读、没有写" in b for b in bad5)
    print("  变异 %-22s ⇒ 边界腿红=%s" % ("恒返回 None", got5))
    if not got5:
        fails.append("变异「恒返回 None」之后边界腿没红 ⇒ 那条语料是死的")
finally:
    S._p_write_set = ORIG

assert S._p_write_set is ORIG, "清理失败：函数没还原"

print()
if fails:
    print("★ FAIL：%d 条" % len(fails))
    for f in fails:
        print("   -", f)
    sys.exit(1)
print("★ PASS：六条语料腿全部能被变异推翻，且未变异时不误报")
