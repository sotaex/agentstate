# -*- coding: utf-8 -*-
"""D-54 ⑫ 语料腿第二组变异测试（只读，不改任何产品文件）。

要证明的事：A4 新加的 18 条语料腿**能红**。

  一条永远不会红的腿与「没有腿」同貌 —— 第十四族。第一组
  （`_p_d54_leg12_mutation.py`）证明的是 WRITE_SET / LEDGER_SEQ / CONFIG_HOOKS；
  这一组证明 EXIT_CODE / ARTIFACT_PATH / CMD_TEXT / LEDGER_ACTIONS。

做法：monkey-patch 探针成错误实现，逐一确认 `_probe_semantics_failures()`
里出现对应的 bad 文案；再确认「不改」时一条都不出现。

★ 每个变异都先断言「真的改成了」，否则「没红」可能只是变异没生效。
★ 一条变异可以要求**多条腿同时红**（`expect` 传列表）：那说明这条变异
  同时违反了两件事，两条腿都得说话 —— 只红一条才是漏。
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


S = load("slots_probe12b", os.path.join("scripts", "slots.py"))
RG = load("rg_probe12b", os.path.join("ci", "regression_gate.py"))

# 每条腿 = (关键字, 断言的文案片段)
LEGS = {
    # EXIT_CODE ── Q1-01
    "q101_pos": "Q1-01 构建命令退出 1",
    "q101_neg": "Q1-01 构建命令退出 0",
    "q101_scope": "把非构建类命令（ls）",
    "q101_noexit": "记录里没有 exit_code",
    # ARTIFACT_PATH ── Q1-05
    "q105_pos": "Q1-05 声称写的文件确实还在",
    "q105_neg": "Q1-05 声称写的文件已经不存在",
    "q105_bash": "把 Bash 记录里的 file_path",
    "q105_read": "把 Read 记录里的 file_path",
    # CMD_TEXT ── A1-01 / A1-05 / K1-02
    "a101_cats": "规则表读不出来",
    "a101_missing": "规则表缺类",
    "a101_pos": "命中 destructive 规则",
    "a101_neg": "一条规则都没命中",
    "a101_slice": "只命中 secret 规则",
    "a101_rev": "只命中 destructive 规则，却报 secret_hit",
    "a101_root": "规则表读不到却给了结论",
    # LEDGER_ACTIONS ── I1-01
    "i101_pos": "post 侧多出一个 digest",
    "i101_split": "两个方向被并成了一个字段",
    "i101_neg": "两侧完全配对",
    "i101_rev": "pre 侧多出一个 digest",
    "i101_empty": "把空 content_digest 当成了配对依据",
    "i101_none": "没有一条记录时给了结论",
}

fails = []
#: 被变异「翻红」过的腿。★ 最后必须等于 LEGS 全集 —— 否则某个关键字拼错时，
#: 它永远不会被检查，而总结照样印「21 条腿全部能被推翻」。那就是假绿。
seen = set()


def run_bad():
    return RG._probe_semantics_failures(S)


def which(bad):
    return sorted({k for k, txt in LEGS.items() if any(txt in b for b in bad)})


# ── 基线：不改 ⇒ 一条都不该出现 ──
base = run_bad()
print("基线：bad 共 %d 条，命中语料腿关键字 = %r" % (len(base), which(base)))
if which(base):
    fails.append("未变异时就有语料腿判红（%r）⇒ 语料本身造错了，先修语料" % (which(base),))


def mutate(attr, name, fn, expect):
    """植入错误实现，确认「真的改了」且「对应腿全红」。"""
    want = [expect] if isinstance(expect, str) else list(expect)
    orig = getattr(S, attr, None)
    setattr(S, attr, fn)
    try:
        assert getattr(S, attr) is not orig, "变异没生效（%s 还是原函数）" % attr
        got = which(run_bad())
        seen.update(got)
        missing = [k for k in want if k not in got]
        print("  %-18s %-24s ⇒ %s（命中 %r）"
              % (attr, name, "红" if not missing else "★没红:%r" % missing, got))
        if missing:
            fails.append("变异 %s.%s 之后这些腿没红 %r（本次只命中 %r）"
                         % (attr, name, missing, got))
    finally:
        if orig is None:
            delattr(S, attr)
        else:
            setattr(S, attr, orig)


# ══════════ EXIT_CODE（守 Q1-01）══════════
print("\n=== EXIT_CODE 变异（守 Q1-01 构建失败）===")
E = "_p_exit_code"
_ok = {"build_failed": False, "build_runs": 1, "build_failures": 0, "worst": []}
_bad = {"build_failed": True, "build_runs": 1, "build_failures": 1, "worst": []}

mutate(E, "永远报不失败", lambda ctx: dict(_ok), "q101_pos")
mutate(E, "永远报失败", lambda ctx: dict(_bad), "q101_neg")
# 范围放大：任何输入都给结论（`ls` 非零退出也被算成构建）
mutate(E, "范围放大（恒给结论）", lambda ctx: dict(_bad), "q101_scope")
# 恒报一次失败 ⇒ 缺 exit_code 那条腿必须红
mutate(E, "恒报一次失败", lambda ctx: dict(_bad), "q101_noexit")

# ══════════ ARTIFACT_PATH（守 Q1-05）══════════
print("\n=== ARTIFACT_PATH 变异（守 Q1-05 声称产物消失）===")
A = "_p_artifact_path"
_art_ok = {"missing_artifact": False, "claimed": 1, "n_missing": 0, "missing": []}
_art_bad = {"missing_artifact": True, "claimed": 1, "n_missing": 1, "missing": ["x"]}

mutate(A, "永远报还在", lambda ctx: dict(_art_ok), "q105_neg")
mutate(A, "永远报消失", lambda ctx: dict(_art_bad), "q105_pos")
# 不看工具名：任何带 file_path 的记录都算「声称产物」
mutate(A, "不看工具名（Bash 也算）", lambda ctx: dict(_art_ok), ["q105_bash", "q105_read"])

# ══════════ CMD_TEXT（守 A1-01 / A1-05 / K1-02）══════════
print("\n=== CMD_TEXT 变异（守 A1-01 危险动作）===")
C = "_p_cmd_text"


def _cmdv(dang=False, sec=False, priv=False, n=1):
    return {"dangerous_hit": dang, "secret_hit": sec, "privilege_hit": priv,
            "n_pre": n, "n_dangerous": 1 if dang else 0,
            "n_secret": 1 if sec else 0, "n_privilege": 1 if priv else 0,
            "samples": []}


mutate(C, "危险恒 False", lambda ctx: _cmdv(False, False), "a101_pos")
mutate(C, "危险恒 True", lambda ctx: _cmdv(True, False), "a101_neg")
# 三类切片并成一类：secret 命中被算进 dangerous（A1-01 的真语义就在这里）
mutate(C, "三类切片并成一类", lambda ctx: _cmdv(True, True), "a101_slice")
# secret 恒 True ⇒ 反向切片腿必须红
mutate(C, "secret 恒 True", lambda ctx: _cmdv(False, True), "a101_rev")
# 规则表读不到也给结论 ⇒ 边界腿必须红
mutate(C, "规则读不到也给结论", lambda ctx: _cmdv(False, False), "a101_root")
# 规则表读不出来（`_p_rules_categories` 恒 None）⇒ 那条腿必须红
mutate("_p_rules_categories", "规则表恒读不到", lambda ctx: None, "a101_cats")
# 规则号恒空 ⇒ 「缺类」那条腿必须红
#   （这条同时会让 CMD_TEXT 自己返回 None，所以只要求 a101_missing 红）
mutate("_rule_ids", "规则号恒空", lambda rows, name_has=None: set(), "a101_missing")

# ══════════ LEDGER_ACTIONS（守 I1-01）══════════
print("\n=== LEDGER_ACTIONS 变异（守 I1-01 决策无留痕）===")
L = "_p_ledger_actions"


def _ledv(unpaired=0, post=0, pre=0):
    return {"pre": 2, "post": 2, "pre_digests": 2, "post_digests": 2,
            "unpaired": unpaired, "unpaired_sample": [],
            "unpaired_post": post, "unpaired_post_sample": [],
            "ledger_records": 4, "pair_ratio": (1, 2), "pre_only": pre}


mutate(L, "unpaired_post 恒 0", lambda ctx: _ledv(0, 0), "i101_pos")
# 两方向合并成一个字段（I1-01 与 I1-02 会对同一事实给出相反结论）
mutate(L, "两方向合并", lambda ctx: _ledv(1, 1), "i101_split")
mutate(L, "两向恒 1", lambda ctx: _ledv(1, 1), "i101_neg")
# 方向对调：unpaired 取了 post-pre
mutate(L, "方向对调", lambda ctx: _ledv(0, 1), "i101_rev")
# 空 digest 也当配对依据 ⇒ 空串相等被读成「配对成功」
mutate(L, "空 digest 也算配对", lambda ctx: _ledv(0, 0), "i101_empty")
# 空集也给结论 ⇒ 「没有记录」被读成「配对完美」
mutate(L, "空集也给结论", lambda ctx: _ledv(0, 0), "i101_none")

print()
# ★ 自证：每个登记的关键字都必须真的被某条变异翻红过。
#   没有这一步，「21 条腿全部能被推翻」只是脚本自己说的 —— 拼错一个关键字，
#   它就再也不会被检查，而总结照样绿。
never = sorted(set(LEGS) - seen)
if never:
    fails.append("这些腿从来没被任何变异翻红过 %r ⇒ 要么关键字拼错、要么语料是死的"
                 % (never,))
print("自证：%d/%d 条腿被至少一条变异翻红过%s"
      % (len(seen), len(LEGS), "" if not never else "（缺 %r）" % (never,)))

if fails:
    print("★ FAIL：%d 条" % len(fails))
    for f in fails:
        print("   -", f)
    sys.exit(1)
print("★ PASS：四个探针共 %d 条语料腿，全部能被变异推翻，且未变异时零误报"
      % len(LEGS))
