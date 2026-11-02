# -*- coding: utf-8 -*-
"""验证 D-54 ⑩ 腿的「覆盖缺口」那一条断言真的能红。

做法：临时把 `scripts/report.py` 里渲染 coverage 的那一行摘掉
（`_cg = st.get("coverage_gap")` → `_cg = None`），跑 D-54，要求它变红；
然后原样写回。

★ 为什么要这么测：新加一条断言，如果它永远为真，与「没有这条断言」同貌。
  断言 `assert "coverage:" in 文本` 本身很容易被别的东西天然满足，
  所以必须让它**在正确的缺失下**变红。
★ 恢复用 finally 保证；最后再比一次文件字节长度，确认真的还原了。
"""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RP = os.path.join(ROOT, "scripts", "report.py")

TARGET = '_cg = st.get("coverage_gap")'
BROKEN = '_cg = None  # 变异：临时摘掉，验证断言会红'

orig = open(RP, encoding="utf-8", newline="").read()
assert TARGET in orig, "没找到目标行，先核对 report.py 是否已改"


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def run_d54():
    """每次重新加载 regression_gate，让它重新 exec report.py。"""
    for k in ("rg_cov_probe", "antinel_report_gate"):
        sys.modules.pop(k, None)
    RG = load("rg_cov_probe", os.path.join("ci", "regression_gate.py"))
    return RG.j_slots_registry_and_evaluator()


fails = []
try:
    ok, msg = run_d54()
    print("基线（未变异）: ok=%s" % ok)
    if not ok:
        fails.append("未变异时 D-54 就失败：%s" % msg)

    # 植入变异
    broken = orig.replace(TARGET, BROKEN, 1)
    assert broken != orig, "替换没生效"
    with open(RP, "w", encoding="utf-8", newline="") as f:
        f.write(broken)

    ok2, msg2 = run_d54()
    print("变异（摘掉 coverage 行）: ok=%s" % ok2)
    print("  报错: %s" % str(msg2)[:160])
    if ok2:
        fails.append("摘掉 coverage 渲染行之后 D-54 仍然通过 ⇒ ⑩ 腿新增的"
                     "那条断言是死的，永远为真")
    elif "覆盖缺口" not in str(msg2):
        fails.append("变红的原因不是「覆盖缺口」那一行（实际: %s）⇒ 断言位置错了"
                     % (str(msg2)[:120],))
finally:
    with open(RP, "w", encoding="utf-8", newline="") as f:
        f.write(orig)

now = open(RP, encoding="utf-8", newline="").read()
print()
print("恢复校验: 字节数 %d → %d，内容一致=%s"
      % (len(orig), len(now), now == orig))
if now != orig:
    fails.append("report.py 没有还原干净！必须手动检查")

if fails:
    print("\n★ FAIL：%d 条" % len(fails))
    for f in fails:
        print("   -", f)
    sys.exit(1)
print("\n★ PASS：⑩ 腿的 coverage 断言在正确的缺失下会红，未变异时通过")
