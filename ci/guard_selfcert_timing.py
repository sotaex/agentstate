#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.42.0 判据 —— **自证卡的刷新点必须在 harness 之后**（S43–S45 ＋ 三条负控）。

★★ 这条判据为什么必须存在（2026-10-09 本班一道结构性死锁）：

  改了受覆盖文件（0.42.0 改了 `scripts/report.py`，它在 COVERED 里）
    ⇒ 旧判定记录描述的是**上一次的字节** ⇒ digests 必然不符
    ⇒ 装配时 `_verification_evidence()` 只能返回 false ⇒ 自证卡写成 false
    ⇒ `_merge(pkg, final)` 把这个 false **覆盖回源码仓**（final 就是仓本身），
      而 `_reconcile_src` 只看守 `run_harness.py` 一个文件 ⇒ **无人发现**
    ⇒ harness 跑完、shipped 记录确实描述本次字节了，但自证卡**没有回头刷新**
    ⇒ 闸门 version/regression 读仓库 SKILL.md ⇒ 红 ⇒ 构建被拦
    ⇒ harness 不跑 ⇒ 记录不刷新 ⇒ **死锁**。

  0.41.0 那轮我是**手工**破的局（手动 Edit SKILL.md）。按"修了又复发"的教训，
  本套件把刷新点钉死：**必须在 harness 之后**，且**harness 失败时不许刷**。

  ★ 全部判据走 AST / 源码比对，**不跑真实构建、不写产品文件**。
  ★ 与 S38/S39（dist 卫生）、S40–S42（发布入口）分工：那两条守"出包前"，
    本条守"harness 后"—— 四个时辰各有一个守卫，不许有没人看的时段。

  ★ S45-selfcert（2026-10-15，0.50.4 改名批新增）：刷新还必须**覆盖插件副本**。
    插件构建（build_plugin）排在 harness **之前**，拷走的是装配时的自证卡；
    若刷新只改 pkg/final，发给用户的插件就停在旧卡（"NOT VERIFIED" 或上一轮
    true）—— 在立信誉的地方说反话。0.48.4 修过 psl/SKILL.md 这一个副本，
    当年漏的是插件。判据结构查：build() 里的刷新调用必须传第四个参数（plug）。
    ★ ID 带 `-selfcert` 后缀的原因：裸 `S45` 与 `guard_instrument_selfaudit.py`
      的同号判据跨套件重名（`0515 UID15-b` ＋ `regression D-31` 双双判红）。
"""
from __future__ import annotations

import ast
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REL = "scripts/build_package.py"
# ★ 0.50.4：刷新调用签名单一真源（第四参 plug ＝ 插件副本也要一起刷，见 S45-selfcert）。
#   本套件多处引用它（S43 存在性/排序、N-S43 变异/排序、N-S45-selfcert 变异）——
#   2026-10-15 实测：改产品调用形状时漏改负控侧一处字面量 ⇒ 负控当场失效。
#   教训同 N-S44 注释那条：判据正反两侧必须同时改，且不许各写一份字面量。
CALL = "_refresh_skill_selfcert(pkg, final, rc, plug)"

PASSED = []
FAILED = []


def check(name):
    def deco(fn):
        try:
            r = fn()
        except Exception as e:                       # noqa: BLE001
            r = "判据自身异常：%r" % (e,)
        (PASSED if r is True else FAILED).append((name, r))
        return fn
    return deco


def _src():
    return io.open(os.path.join(ROOT, REL), encoding="utf-8").read()


def _tree():
    return ast.parse(_src())


def _func(tree, name):
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    return None


def _lineno_of_call(tree, fname, callee):
    """某个函数体内，对 `callee` 的**首次调用行号**（None = 没调用）。"""
    f = _func(tree, fname)
    if f is None:
        return None
    best = None
    for n in ast.walk(f):
        if isinstance(n, ast.Call):
            nm = getattr(n.func, "id", None)
            if nm == callee:
                if best is None or n.lineno < best:
                    best = n.lineno
    return best


# ══════════ S43 · 刷新点必须在 harness 之后、reconcile 之前 ═══════════════
@check("S43 自证卡刷新点在 harness 之后、_reconcile_src 之前")
def s43():
    tree = _tree()
    if _func(tree, "_refresh_skill_selfcert") is None:
        return "找不到 _refresh_skill_selfcert() —— 自证卡刷新函数不存在"
    src = _src()
    # 调用必须存在（0.50.4 起带第四参 plug：连插件副本一起刷，见 S45）
    if CALL not in src:
        return "build() 里没有 `_refresh_skill_selfcert(pkg, final, rc, plug)` 这个调用"
    # 顺序：harness(final) < 刷新 < reconcile
    ln_harness = None
    ln_refresh = None
    ln_reconcile = None
    for i, line in enumerate(src.split("\n"), 1):
        if "harness(final, shipped record) exit" in line and ln_harness is None:
            ln_harness = i
        if ln_refresh is None and CALL in line:
            ln_refresh = i
        if ln_reconcile is None and ln_harness and "_reconcile_src(_SRC_WATCH)" in line:
            ln_reconcile = i
    if not (ln_harness and ln_refresh and ln_reconcile):
        return "三个锚点没找全（harness=%s refresh=%s reconcile=%s）" % (
            ln_harness, ln_refresh, ln_reconcile)
    if not (ln_harness < ln_refresh < ln_reconcile):
        return ("顺序错：harness@%d < refresh@%d < reconcile@%d 不成立 —— "
                "刷新点挪到 harness 之前就回到了装配时那次（必然 false）"
                % (ln_harness, ln_refresh, ln_reconcile))
    return True


@check("N-S43 负控：把刷新调用挪到 _reconcile_src 之后 ⇒ S43 必须报红")
def n_s43():
    src = _src()
    call = "        " + CALL + "\n"
    rec = "        _reconcile_src(_SRC_WATCH)\n"
    if call not in src or rec not in src:
        return "负控无效：找不到可供变异的调用/对账行"
    mut = src.replace(call, "", 1)
    mut = mut.replace(rec, rec + call, 1)
    if mut == src:
        return "负控无效：变异没产生任何变化"
    # 用同款逻辑判顺序（喂变异后的源码）
    ln_h = ln_r = ln_c = None
    for i, line in enumerate(mut.split("\n"), 1):
        if "harness(final, shipped record) exit" in line and ln_h is None:
            ln_h = i
        if ln_r is None and CALL in line:
            ln_r = i
        if ln_c is None and ln_h and "_reconcile_src(_SRC_WATCH)" in line:
            ln_c = i
    if not (ln_h and ln_r and ln_c):
        return "负控失效：变异后锚点缺失（应报红但原因不对）"
    if ln_h < ln_r < ln_c:
        return "负控失效：刷新点被挪到 reconcile 之后，顺序判据仍然绿"
    return True


# ══════════ S44 · harness 失败时不许刷成 true ════════════════════════════
@check("S44 harness rc != 0 时必须保持 false（不拿失败的运行背书）")
def s44():
    tree = _tree()
    f = _func(tree, "_refresh_skill_selfcert")
    if f is None:
        return "找不到 _refresh_skill_selfcert()"
    # ★ 查参数名要**结构**查，不要 `"harness_rc" in ast.dump(f)`：
    #   文本匹配对 AST 是脆弱的（docstring 里提一句同名就假绿）。
    argnames = [a.arg for a in f.args.args] + [a.arg for a in f.args.kwonlyargs]
    if "harness_rc" not in argnames:
        return "_refresh_skill_selfcert() 不再接收 harness_rc —— 无法分辨成功/失败"
    # 必须有一个对 harness_rc 的比较（!= 0 或 == 0）
    has_cmp = any(isinstance(n, ast.Compare) for n in ast.walk(f))
    if not has_cmp:
        return "_refresh_skill_selfcert() 里没有对 harness_rc 的比较 ⇒ 失败也会刷成 true"
    # ★ `return False` 在 AST 里是 `Return(Constant(value=False))`，
    #   **不是**字符串 "return False" ⇒ 判 dump 里有没有那个字面量永远为假。
    #   （本套件第一版正踩过：用文本匹配代替结构匹配。）
    has_ret_false = any(isinstance(n, ast.Return)
                        and isinstance(n.value, ast.Constant) and n.value.value is False
                        for n in ast.walk(f))
    if not has_ret_false:
        return "harness 失败分支没有 `return False`（早退）"
    return True


@check("N-S44 负控：摘掉 harness_rc 判断 ⇒ S44 必须报红")
def n_s44():
    src = _src()
    anchor = '    if harness_rc != 0:\n        print("!! SKILL.md 自证卡不刷新'
    if anchor not in src:
        return "负控无效：找不到 harness_rc 判断块可供变异"
    i = src.index(anchor)
    # 摘掉整个 if 块（到该块的 return False 行为止）
    j = src.index("return False", i)
    j = src.index("\n", j)
    mut = src[:i] + src[j + 1:]
    try:
        tree = ast.parse(mut)
    except SyntaxError as e:
        return "负控无效：变异造成语法错误 %r" % (e,)
    f = _func(tree, "_refresh_skill_selfcert")
    if f is None:
        return "负控失效：变异后找不到函数"
    has_cmp = any(isinstance(n, ast.Compare) for n in ast.walk(f))
    # ★ `return False` 必须**结构**查（`Return(Constant(False))`）。
    #   本套件第一版在 S44 里用 `"return False" in dump` —— 被 S45 抓到，
    #   而**负控里同一句忘了改**：正向改了、负控没改，两侧不同步。
    #   ⇒ 教训：判据的正反两侧必须同时改，负控不是正向的复制品那么便宜。
    has_ret_false = any(isinstance(n, ast.Return)
                        and isinstance(n.value, ast.Constant) and n.value.value is False
                        for n in ast.walk(f))
    if has_cmp and has_ret_false:
        return "负控失效：判断被摘掉后 S44 仍然绿"
    return True


# ══════════ S45-selfcert · 刷新必须覆盖插件副本（0.50.4 新增） ═════════════
# ★★ 2026-10-15（0.50.4）：本判据原写作裸 `S45` —— 与 `guard_instrument_selfaudit.py`
#   的 `S45`（「不许把 ast.dump 结果做子串匹配」）**跨套件重名**，被 `0515 UID15-b`
#   与 `regression D-31` 双双判红。判据 ID 的跨套件唯一性由 `defect_types._declared_ids`
#   只取**首 token** 实现 ⇒ 同名即病（登记簿 guards 只写裸 ID，说不清守它的是哪一套）。
#   本仓惯例：同号不同批次加**套件后缀**（`S47-selfaudit`／`S48-release`）。
#   ⇒ 本套件的 S45 一律带 `-selfcert`；正负控同套共用同号是惯例（内部重复不算重名）。
def _call_nodes(tree, fname, callee):
    """某个函数体内对 `callee` 的全部调用节点（结构查，不靠文本）。"""
    f = _func(tree, fname)
    if f is None:
        return []
    return [n for n in ast.walk(f)
            if isinstance(n, ast.Call) and getattr(n.func, "id", None) == callee]


@check("S45-selfcert 自证卡刷新必须连插件副本一起刷（调用传 plug）")
def s45():
    tree = _tree()
    calls = _call_nodes(tree, "build", "_refresh_skill_selfcert")
    if not calls:
        return "build() 里找不到 _refresh_skill_selfcert 调用"
    if len(calls[0].args) != 4:
        return ("刷新调用只有 %d 个位置参数 —— 第四个参数（plug，插件根）没传 ⇒ "
                "skills/<NAME>/SKILL.md 与 skills/<NAME>/psl/SKILL.md 不随自证卡"
                "刷新，发给用户的插件停在装配时的旧卡（0.50.4 实测形状："
                "在立信誉的地方说反话）" % len(calls[0].args))
    return True


@check("N-S45-selfcert 负控：刷新调用丢掉 plug 参数 ⇒ S45-selfcert 必须报红")
def n_s45():
    src = _src()
    call = "        " + CALL
    if call not in src:
        return "负控无效：找不到可供变异的四参调用"
    mut = src.replace(call, "        _refresh_skill_selfcert(pkg, final, rc)", 1)
    if mut == src:
        return "负控无效：变异没产生任何变化"
    try:
        tree = ast.parse(mut)
    except SyntaxError as e:                       # noqa: BLE001
        return "负控无效：变异造成语法错误 %r" % (e,)
    calls = _call_nodes(tree, "build", "_refresh_skill_selfcert")
    if not calls:
        return "负控失效：变异后找不到调用"
    if len(calls[0].args) == 4:
        return "负控失效：丢掉 plug 后 S45-selfcert 仍然绿"
    return True


def main():
    print("=" * 74)
    print("0.42.0 判据 —— 自证卡刷新点必须在 harness 之后（S43–S45-selfcert）")
    print("=" * 74)
    for n, r in PASSED:
        print("  ✅ %s" % n)
    for n, r in FAILED:
        print("  ❌ %s\n       → %s" % (n, r))
    print("-" * 74)
    print("  通过 %d / 失败 %d" % (len(PASSED), len(FAILED)))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
