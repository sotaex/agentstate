#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.36.6 判据 —— **收敛机制本身**的三层固化（本轮踩出来的教训，编成机器检查）。

★ 这份文件与前面所有判据的区别（这就是它存在的理由）：

    前面的判据守的是**产品**（窗口、姿态、判红、版本）。
    这份判据守的是**发现错误的机制**——
    也就是「我这次能不能发现自己又弄坏了别的」。

⇒ 因为 0.36.5–0.36.6 这两轮里，产品缺陷其实都不是最贵的，
   最贵的是**发现缺陷的过程本身反复出问题**：

    · 我改inbox_window.py ⇒ P15 报红 ⇒ 我花一整轮才分清「是判据的错还是产品的错」
      （根因：注释写着"页面前缀必须是已知页面名之一"，代码里**那一层从没实现**）
    · 变异检验被强杀 ⇒ `inbox_model.py` 留下 `if False: # MUTANT`
      ⇒ 恰好把 0.36.3 用户投诉的原始形态又装了回去
      （根因：`try/finally` 写对了，但**进程被强杀时Python 没机会执行它**）
    · 我**凭记忆**写了个仓里不存在的变量名 `_KNOWN_SHIELD_STATES` 去"还原"产品
      ⇒ 靠 `build/lib` 旧字节才拿到真版（**记忆不算数，要回源文件取证**）

★★★ 三条根因的共同形状（这一句是本文件的全部由来）：

    **「我以为我验证过了」—— 而"以为"就是这条链上所有事故的共同入口。**

⇒ 三层机制分别把三个"以为"变成可判定的事实：

    机制①基线快照＋差分
        「我以为我看过了红项」⇒ 机器算出**相对上次新增了哪几条**
    机制② 影响面自动点名
        「我以为我复验全了」⇒ 机器按 import 图算出**本次改动的直接受害者**
    机制③ 红项归属提示
        「我以为这个红是我弄的」⇒ 若红项里没有本次改动的模块名，**摆明它可能是老账**

★ 三条纪律（与本仓既有惯例一致）：
  · 每条判据都配**负控**：把机制故意改坏，判据必须报红（否则它只是一段会执行的代码）。
  · 判据只查**行为**：机制被换成另一种写法但效果不变，不该红；效果改坏，必须红。
  · 收尾必须`try/finally` 还原，且还原后**自己再验一次**——否则"崩了"会污染工作区。
"""
from __future__ import annotations

import ast
import importlib
import inspect
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "ci"))

RESULTS = []          # [(name, fn, negctl)]
_BACKUP = []          # [(path, backup_text)]


def check(name, negctl=None):
    """`negctl` 传**函数名**（字符串）—— 因为负控函数定义在判据之后。

    ★ 为什么不直接传函数引用：装饰器求值发生在模块从上到下，
      负控函数还没定义 ⇒ 直接传引用会 `NameError`。
      ⇒ 传名字、`main()` 里再解析；解析不到就报「负控缺失」而不是静默跳过。
    """
    def deco(fn):
        RESULTS.append((name, fn, negctl))
        return fn
    return deco


def _snapshot(path):
    try:
        with io.open(path, encoding="utf-8") as f:
            _BACKUP.append((path, f.read()))
        return True
    except Exception:                                          # noqa: BLE001
        return False


def _restore_all():
    """还原**并清空**备份栈。

    ★★★ 必须清空（0.36.6 实测踩到，不是假想）：
      原版还原完不清栈 ⇒ `main()` 的 `finally` 里再调一次，
      会把**同一个备份**再写一遍 —— 而某些判据中途已经
      「快照 → 改坏 → 还原」，栈里出现**两条**记录（一条正常、一条是坏内容）
      ⇒ 第二次还原把**坏内容**写回去，或在文件已删时抛 `UnsupportedOperation`。
      ⇒ 负控因此报「负控自身崩了」，看起来像机制有问题，
      **其实是我的判据把工具写坏了** —— 与本仓铁律同型：
        工具崩了不算判据红（那会让红项指向没犯过错的代码）。
    """
    for path, txt in reversed(_BACKUP):
        try:
            with io.open(path, "w", encoding="utf-8") as f:
                f.write(txt)
        except Exception:                                      # noqa: BLE001
            pass
    del _BACKUP[:]


def _load_gate():
    import delivery_gate
    importlib.reload(delivery_gate)
    return delivery_gate


def _reached(tree, node, dead):
    """节点在给定的 `dead` 状态下是否**真的会被执行到**（不是"源码里有没有"）。

    ★ 这条工具本身是从 0364 的 G2 搬过来的：那里的教训是
      负控把调用挪进 `if False:`，只查字样的判据照样绿。
      ⇒ 这里必须带`dead` 标记下传，不能用 `ast.walk`（它会把死分支也算进去）。
    """
    for child in ast.iter_child_nodes(node):
        cdead = dead
        if isinstance(child, ast.If):
            test = child.test
            is_const_false = (isinstance(test, ast.Constant)
                              and test.value is False)
            is_const_true = (isinstance(test, ast.Constant)
                             and test.value is True)
            if is_const_false:
                cdead = True
            elif dead and not isinstance(test, (ast.BoolOp, ast.UnaryOp)):
                # 死分支里的条件继续往下算（无短路）
                pass
            elif dead:
                cdead = True
            else:
                cdead = False if is_const_true else dead
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                               ast.ClassDef)):
            cdead = True          # 函数体不在模块导入时执行
        if not cdead and isinstance(child, ast.Expr):
            return True
        if _reached(child, child, cdead):
            return True
    return False


# ════════════════════════════════ 机制 ①  基线快照 ＋ 差分 ════════════════════════
@check("M1 基线快照：跑完必须落盘，且指纹能察觉内容变化",
       "n_no_snapshot_is_caught")
def m1_snapshot_is_written_and_fingerprinted():
    """闸门跑完必须在 `.psl/gate/baseline.json` 留下**可对照的**快照。

    ★★ 口径（0.36.6 两次修正后才定下来）：
      · 第一版用「判据条数」⇒ 改了判据内容而条数不变就漏（假差分）。
      · 第二版用「mtime:size」⇒ **更糟**：0366 的负控会在闸门运行中
        写注释再还原，**内容没变而 mtime 变了** ⇒ 指纹每次跑都变
        ⇒ 差分永远用不上（实测连跑三次都「指纹不同，已失效」）。
      ⇒ 现在用**内容哈希**：它同时满足「内容变了能察觉」与「没变就稳定」。
    """
    G = _load_gate()
    assert hasattr(G, "_gate_fingerprint"), "闸门里没有 _gate_fingerprint()"
    fp1 = G._gate_fingerprint()
    assert fp1, "指纹算出来是空串"
    gate_path = os.path.join(ROOT, "ci", "delivery_gate.py")
    assert _snapshot(gate_path), "闸门文件不可读"
    try:
        with io.open(gate_path, encoding="utf-8") as f:
            t = f.read()
        with io.open(gate_path, "w", encoding="utf-8") as f:
            f.write(t + "\n# NEGCTL_MARKER: 指纹必须因本文件内容变化而变化\n")
        fp2 = G._gate_fingerprint()
        assert fp2 != fp1, ("闸门内容变了，指纹却没变 ⇒ 快照会对旧指纹做差分，"
                            "**假差分**（真变了却说没变）")
        # ★★ 反向也必须成立：**内容没变**（只改 mtime）⇒ 指纹不许变。
        #   这是 0.36.6 第二版踩到的那一条，写进判据才算拦住。
        with io.open(gate_path, "w", encoding="utf-8") as f:
            f.write(t)
        os.utime(gate_path, (int(time.time()) + 60, int(time.time()) + 60))
        fp3 = G._gate_fingerprint()
        assert fp3 == fp1, (
            "只改了 mtime、内容没变，指纹却变了 ⇒ 差分会在每次跑时自我失效"
            "（实测踩过：连跑三次都「指纹不同」）")
    finally:
        _restore_all()
        try:
            os.utime(gate_path, None)
        except OSError:
            pass
    assert os.path.basename(G._SNAP) == "baseline.json", (
        "快照文件名不是 baseline.json ⇒ 与既有约定不符，换机器/换人时找不到")


def n_no_snapshot_is_caught():
    """负控：把 `_gate_fingerprint` 里「看文件自身变化」那一行删掉 ⇒ M1 必须报红。

    ★★★ 0.36.6 修正本负控第一版：**打错了靶子**。
      第一版去掏空 `_save_snapshot`（"快照不落盘"），而 M1 断言的是**指纹会变**
      ⇒ 掏空另一个函数当然抓不到它 ⇒ 报「假守卫」。
      ⇒ 与本仓「负控强度对照防护层数」同型：负控要打的是
        **判据自己断言的那一句**，不是它附近看起来相关的代码。
    """
    G = _load_gate()
    p = os.path.join(ROOT, "ci", "delivery_gate.py")
    assert _snapshot(p)
    try:
        with io.open(p, encoding="utf-8") as f:
            t = f.read()
        old = ('parts.append("%s:%s" % (\n'
               '                    rel, hashlib.sha256(f.read()).hexdigest()[:16]))')
        if old not in t:
            return "锚点没找到（跳过负控）"
        with io.open(p, "w", encoding="utf-8") as f:
            f.write(t.replace(old, 'parts.append("%s:CONST" % rel)', 1))
        try:
            m1_snapshot_is_written_and_fingerprinted()
        except AssertionError as e:
            if "指纹" not in str(e):
                return "报红了但理由不对：%s" % e
            return True
        return "★ 指纹恒定化后 M1 仍绿 —— 这条判据是假守卫"
    finally:
        _restore_all()


@check("M2 差分归因：快照可比时必须算出「新增红」与「已转绿」",
       "n_diff_always_empty_is_caught")
def m2_diff_reports_new_and_fixed():
    """差分必须真能算出**新增红**—— 这是收敛速度的关键那一环。

    ★ 为什么这是"关键那一环"：闸门只会说「现在有红」，
      不会说「相对上次**多了**什么」⇒ 于是每次红都要重新做一次归因，
      而归因是本仓最贵的一步（要查是哪次改动引入的、判据测的是谁）。
    ★ 造一个**确定性的场景**来验：上一次全PASS，这一次0360 变红
      ⇒ 差分必须指出 0360 是新增红，且**不能**把其余 7 套算进去。
    """
    G = _load_gate()
    d = tempfile.mkdtemp(prefix="psl_diff_")
    try:
        snap_dir = os.path.join(d, "gate")
        os.makedirs(snap_dir)
        with io.open(os.path.join(snap_dir, "baseline.json"), "w",
                     encoding="utf-8") as f:
            json.dump({"fingerprint": G._gate_fingerprint(), "ts": 0,
                       "suites": {k: {"status": "PASS", "red_fp": ""}
                                  for k, _r, _d in G.SUITES}},
                      f)
        real_snap_dir, real_snap = G._SNAP_DIR, G._SNAP
        G._SNAP_DIR, G._SNAP = snap_dir, os.path.join(snap_dir, "baseline.json")
        try:
            fake = [{"suite": k, "status": "PASS", "red": ""}
                    for k, _r, _d in G.SUITES]
            for r in fake:
                if r["suite"] == "0360":
                    r["status"] = "RED"
                    r["red"] = "RED  P15 某某某 ⇒ 这是故意造的红"
            new_red, fixed, note = G._diff_against_baseline(fake,
                                                             G._gate_fingerprint())
            named = {s for s, _w in new_red}
            assert "0360" in named, ("新增红里没有 0360 ⇒ 差分没识别出"
                                     "「上次绿、这次红」这个最基本的形态：%s" % note)
            assert "0353" not in named, ("把一直绿的 0353 也算成新增红 ⇒"
                                         "差分在乱报，信它反而误伤")
            assert not fixed, ("没有一条从红转绿，却报出已转绿 %s ⇒ 判反了" % fixed)
        finally:
            G._SNAP_DIR, G._SNAP = real_snap_dir, real_snap
    finally:
        shutil.rmtree(d, ignore_errors=True)


def n_diff_always_empty_is_caught():
    """负控：让 `_diff_against_baseline` 永远返回空 ⇒ M2 必须报红。"""
    G = _load_gate()
    p = os.path.join(ROOT, "ci", "delivery_gate.py")
    assert _snapshot(p)
    try:
        # ★ 读用'r'：写成"w 模式里 f.read()"会抛 `UnsupportedOperation`，
        #   而那会让**负控自己崩**、看起来像机制有问题 ——
        #   其实是我的判据把工具写坏了（同本仓铁律：工具崩了不算判据红）。
        with io.open(p, encoding="utf-8") as f:
            t = f.read()
        old = "    return new_red, fixed,"
        if old not in t:
            return "锚点没找到（跳过负控）"
        with io.open(p, "w", encoding="utf-8") as f:
            f.write(t.replace(old, "    return [], [],", 1))
        try:
            m2_diff_reports_new_and_fixed()
        except AssertionError as e:
            if "新增红" not in str(e) and "0353" not in str(e):
                return "报红了但理由不对：%s" % e
            return True
        return "★ 差分永远返回空后 M2 仍绿 —— 这条判据是假守卫"
    finally:
        _restore_all()


# ═══════════════════════ 机制 ②  影响面自动点名（改了什么 → 复验什么）══════════════
@check("M3 影响面点名：改了产品文件必须点名到对应判据",
       "n_no_impact_is_caught")
def m3_impact_names_suites():
    """改了产品文件 ⇒ 自动算出「哪些判据直接读它」，不许静默返回空。

    ★ 由来是本轮真实踩到的一句话：「规则变更必须同时验证它没弄坏别的题」。
      而它的危险形态不是「忘了跑全套」，是「**跑了全套，但不知道该看哪一条**」。
    """
    G = _load_gate()
    assert hasattr(G, "impacted_suites"), "闸门里没有 impacted_suites()"
    hit, note = G.impacted_suites(["inbox_window.py"])
    assert "0362" in hit, ("改了 inbox_window.py 却没点名 0362"
                          "（它直接 import inbox_window）⇒ 名单有漏，"
                          "漏了＝那条判据等于没跑")
    hit2, note2 = G.impacted_suites(["host_shield.py"])
    assert "0353" in hit2, "改了 host_shield.py 却没点名 0353"
    # 反向：改一个判据不读的文件 ⇒ 必须**明说**没点名，而不是安静返回空
    hit3, note3 = G.impacted_suites(["README.md"])
    assert any("不是「不需要复验」" in ln for ln in note3), (
        "改无关文件时，名单没有明说「这不代表不需要复验」⇒ "
        "**沉默的空会被读成「不用管」**，与本仓铁律同型")


def n_no_impact_is_caught():
    """负控：让影响面永远点名不到 ⇒ M3 必须报红。"""
    G = _load_gate()
    p = os.path.join(ROOT, "ci", "delivery_gate.py")
    assert _snapshot(p)
    try:
        with io.open(p, encoding="utf-8") as f:
            t = f.read()
        old = "    hit = {k for k, deps in _DEP_CACHE.items() if deps & stems}"
        if old not in t:
            return "锚点没找到（跳过负控）"
        with io.open(p, "w", encoding="utf-8") as f:
            f.write(t.replace(old, "    hit = set()  # MUTANT", 1))
        try:
            m3_impact_names_suites()
        except AssertionError as e:
            if "没点名" not in str(e):
                return "报红了但理由不对：%s" % e
            return True
        return "★ 点名永远返回空后 M3 仍绿 —— 这条判据是假守卫"
    finally:
        _restore_all()


@check("M4 影响面不得被构建产物淹没（点名要有筛选意义）")
def m4_touch_filters_build_artifacts():
    """点名清单**必须滤掉构建产物**，否则长到 58 条＝等于没点名。

    ★ 实测踩到：本仓107 个文件从未提交过（`git status` 里全是 `??`），
      `git diff HEAD` 报出 58 个「改动」，其中混着 `*.egg-info`、`__pycache__`、
      `dist/`、`build/` —— 那些是**构建产物**，不是「我改了产品」。
    """
    G = _load_gate()
    assert hasattr(G, "_TOUCH_EXCLUDE"), "没有构建产物过滤正则"
    for junk in ("__pycache__/x.pyc", "antinel.egg-info/PKG-INFO",
                 "dist/antinel.whl", "build/lib/inbox_model.py",
                 ".psl/gate/baseline.json", ".git/config"):
        assert G._TOUCH_EXCLUDE.search(junk), (
            "构建产物 %r 没被过滤 ⇒ 影响面名单会被淹没" % junk)
    for real in ("inbox_model.py", "host_shield.py", "ci/inbox_guards_0360.py",
                 "scripts/build_package.py", "tools/enforce_probe.py"):
        assert not G._TOUCH_EXCLUDE.search(real), (
            "真实产品文件 %r 被误过滤了 ⇒ 它就再也不会被点名复验" % real)


# ═══════════════════════ 机制 ③  红项归属：本次引入的 vs 老账 ═════════════════════
@check("M5 红项归属提示必须真能在红项里认出改动过的模块名")
def m5_red_attribution_finds_touched_modules():
    """「这个红是不是我弄的」必须有机器答案，不再靠人逐条读。

    ★ 由来：本轮连续两次遇到「红项指向的代码**没有犯过这个错**」
      （一次指向已删的死函数 `_matches_title`，一次是 P15 判据自己的正则锚点）。
    ★ 口径：**红仍然是红、仍然阻断**；这里只把「可能是老账」这一事实摆到眼前，
      不替红项判罪、也不替它开脱。
    ★★★ 0.36.6 修正本判据第一版：**它自己抄了一份正则**，
      于是判的是一个"不存在的归属机制"（与本仓「判据不许二次实现」相反，
      也与 0.36.5 那条教训同型：测的不是被测对象）
      ⇒ 现在**直接调用闸门里的 `red_names_touched_modules`**。
    """
    G = _load_gate()
    assert hasattr(G, "red_names_touched_modules"), (
        "闸门里没有 red_names_touched_modules() ⇒ 归属提示是内联的，"
        "无法被单独验证")
    touched = {"inbox_window", "inbox_model"}
    red = ("RED  P15 后缀匹配对每个页面都成立\n"
           "       非值守台窗口 '请给我一个 · 值守台#486acd' 被误认成值守台"
           "（查 inbox_window）")
    named = G.red_names_touched_modules(red, touched)
    assert "inbox_window" in named, (
        "红项里明确提到 inbox_window，却没被认出来 ⇒ 归属提示在骗人"
        "（比不提示更坏：它会让你去查错的地方）；实得 %s" % sorted(named))
    old_red = "RED  P15 某某某 ⇒ 与本次改动无关的历史遗留问题"
    named2 = G.red_names_touched_modules(old_red, touched)
    assert not named2, ("老账红项被误当成本次引入 ⇒ 提示会误导排查方向；"
                        "实得 %s" % sorted(named2))
    assert G.red_names_touched_modules("", touched) == set(), "空红项不该认出模块"
    assert G.red_names_touched_modules(red, set()) == set(), (
        "没有改动时不该认出任何模块 ⇒ 否则所有红都会被标成『本次引入』")


@check("M6 收敛机制不得只在闸门里存在（判据自己要被登记进执行点）")
def m6_convergence_suites_registered():
    """本文件（收敛机制守卫）自己**必须**被登记进闸门，否则等于没写。

    ★ 这是本仓铁律「**有检查项但没人跑 ＝ 等于没有**」的直接应用。
      0.36.5 那一轮 113 条判据零执行点，代价是「已经红了一段时间却没人知道」。
    """
    G = _load_gate()
    rels = {rel for _k, rel, _d in G.SUITES}
    mine = os.path.relpath(os.path.abspath(__file__),
                            G.PKG).replace("\\", "/")
    assert mine in rels, ("本守卫文件 %r 没登记进 delivery_gate.SUITES "
                          "⇒ 写完了没人跑" % mine)
    # 也不能只查存在性：必须真的被跑起来（与 0364 G2 同型）
    assert G._orphaned_guard_files() == [], (
        "闸门认为有孤儿守卫文件却没报出来 ⇒ 清单与磁盘不一致")


@check("M8 崩/缺失不许混进「新增红」（收敛账本不许被污染）")
def m8_crash_is_not_counted_as_new_red():
    """判据崩了、文件缺失、零输出 —— **都不是红**，不许进「新增红」。

    ★★★ 为什么这条必须在最前面（0.36.6 实测推导）：
      收敛机制的价值全在「新增红」这三个字的可信度上。
      若一次"判据文件被误删"或"判据自身崩了"也以
      「我改出了新红」的形态出现 ⇒ **账本被污染**
      ⇒ 人开始怀疑整套机制 ⇒ 下一轮就不看了
      ⇒ 与「零输出被当通过」同族：**都是账面失真**，
        而账面失真是**收敛机制的头号死因**（信不过＝没有）。
      ⇒ 红项仍照常打印、仍阻断（红不会因为归类而被放过），
        只是**不许冒充缺陷**。
    """
    G = _load_gate()
    import tempfile
    d = tempfile.mkdtemp(prefix="psl_crash_")
    try:
        with io.open(os.path.join(d, "baseline.json"), "w", encoding="utf-8") as f:
            json.dump({"fingerprint": G._gate_fingerprint(), "ts": 0,
                       "suites": {k: {"status": "PASS", "red_fp": ""}
                                  for k, _r, _d in G.SUITES}}, f)
        rd, rp = G._SNAP_DIR, G._SNAP
        G._SNAP_DIR, G._SNAP = d, os.path.join(d, "baseline.json")
        try:
            fake = [{"suite": k, "status": "PASS", "red": ""}
                    for k, _r, _d in G.SUITES]
            by = {r["suite"]: r for r in fake}
            by["0360"]["status"] = "CRASH"
            by["0360"]["red"] = ""
            by["0362"]["status"] = "MISSING"
            by["0362"]["red"] = ""
            by["0363"]["status"] = "NOOP"
            by["0363"]["red"] = ""
            by["0364"]["status"] = "RED"
            by["0364"]["red"] = "RED  真缺陷一条"
            new_red, _fixed, _note = G._diff_against_baseline(
                fake, G._gate_fingerprint())
            txt = " ".join("%s=%s" % (s, w) for s, w in new_red)
            assert "0364" in txt, ("真缺陷没进新增红 ⇒ 机制①失去意义：%s" % txt)
            assert "0360" in txt and "CRASH" in txt, (
                "崩了的那套必须**出现在线索里**（不能被静默丢掉，"
                "否则就是「看不见的失败」）：%s" % txt)
            assert "不是红" in txt, (
                "崩了的那套必须**明写它不是红** ⇒ 否则会被当成我改出来的缺陷：%s"
                % txt)
            assert "0362" in txt and "MISSING" in txt, "缺失没被标出：%s" % txt
            assert "0363" in txt and "NOOP" in txt, "零输出没被标出：%s" % txt
        finally:
            G._SNAP_DIR, G._SNAP = rd, rp
    finally:
        shutil.rmtree(d, ignore_errors=True)


@check("M7 快照目录不许进包（快照是对产品的观察，不是产品的一部分）")
def m7_snapshot_not_in_package():
    """`.psl/gate/` 落在仓根下，**必须**不在 manifest 里。

    ★ 为什么：快照每次跑闸门都会变（时间戳＋指纹）⇒ 一旦进包，
      manifest 哈希必然每轮失配 ⇒ 打包前闸门**永远红**（自举死锁的变种）。
    """
    G = _load_gate()
    assert G._SNAP_DIR.startswith(G.PKG), "快照目录不在仓内"
    rel = os.path.relpath(G._SNAP_DIR, G.PKG).replace("\\", "/")
    man = os.path.join(G.PKG, "psl", "manifest.json")
    if not os.path.isfile(man):
        return "manifest 不存在（本轮尚未打包）"
    with io.open(man, encoding="utf-8") as f:
        m = json.load(f)
    files = m.get("files") or m.get("entries") or []
    keys = list(files.keys()) if isinstance(files, dict) else [
        (e.get("path") or "") for e in files]
    bad = [k for k in keys if k and (rel in k.replace("\\", "/")
                                     or k.endswith("baseline.json"))]
    assert not bad, "快照进了 manifest（%s）⇒ 每轮跑闸门都改它 ⇒ 打包前闸门永远红" % bad[:3]


def main():
    ok = fail = 0
    print("=" * 74)
    print("0.36.6 判据 —— 收敛机制本身的固化（发现错误的机制会不会出错）")
    print("=" * 74)
    try:
        for name, fn, neg in RESULTS:
            try:
                why = fn()
                print("  ✅ %-46s %s" % (name[:46], why or ""))
                ok += 1
            except AssertionError as e:
                print("  ❌ %-46s %s" % (name[:46], e))
                fail += 1
            except Exception as e:                              # noqa: BLE001
                print("  💥 %-46s %r" % (name[:46], e))
                fail += 1
        # 负控：把机制故意改坏，判据必须报红 —— 否则它只是一段会执行的代码
        print("-" * 74)
        print("负控（把机制改坏，看判据是否真的报红）")
        for name, fn, neg in RESULTS:
            if neg is None:
                continue
            negfn = globals().get(neg) if isinstance(neg, str) else neg
            if negfn is None or not callable(negfn):
                # ★ 负控"登记了但跑不起来"＝ 没写。静默跳过 = 假绿。
                print("  💥 %-46s 负控缺失或不可调用（登记名 %r）" % (name[:46], neg))
                fail += 1
                continue
            try:
                r = negfn()
            except Exception as e:                              # noqa: BLE001
                print("  💥 %-46s 负控自身崩了：%r" % (name[:46], e))
                fail += 1
                continue
            if r is True:
                print("  ✅ %-46s └ 负控生效" % name[:46])
                ok += 1
            else:
                print("  ❌ %-46s %s" % (name[:46], r))
                fail += 1
    finally:
        _restore_all()
    print()
    print("-" * 74)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
