#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""0.36.8 判据 —— **判据腐化检测**（JDG 族：守「发现错误的机制」自己）。

★ 这份文件与前面所有判据的区别（这就是它存在的理由）：

    0366 守的是**收敛机制管道**（基线差分／影响面点名／红项归属）。
    这份守的是**判据本身有没有腐烂** —— 也就是 2026-10-08 一天之内
    连续抓到的同族实例（前 6 例都由人眼抓住，第 7 例由本族第一次跑就指出）：

      ③ F-09  负控衰减：产品把守卫修好，负控的注入点失效 ⇒ 产品越修越对，
               判据越跑越错（0.35.3 起 task_installed 文件系统事实优先，
               注入的 OSError 永远到不了被测分支）
      ④ UX    重置死路径：测试重置 `proj/.psl/notify_state.json`，
               而 0.35.3 起产品读 `~/.antinel`（ANTINEL_HUB_DIR）⇒
               **重置指向一条不再被读的路径**，同日去重键从未被清
      ⑤ F-15  桩吞效应：先 `_notify=lambda: None` 打桩，再断言该函数
               的效应（notify_sent 置位）—— 桩恰好替掉了被测物本身
      ⑥ 冒泡复发：可见性判据只长在 host_shield._notify_throttled 通道，
               hook 的 notify_owner 是**另一条通道、另一套去重** ⇒ 窗口开着照样弹
      ⑦ notify 未受闸：安全键变更链 seven_step → notify → _notify →
               _notify_icon_and_tip **全链无闸**（0.36.8 修；本判据首发即命中）

    同族七次，前六次都没上升为机制。本文件把它变成机器检查。

★★★ 六条判据（都是**可机械执行**的不变式，不是纪律口号）：

    JDG-01  状态路径一致性
            **测试重置的状态路径，必须等于产品实际读取的状态路径。**
            机械判据：在同一沙箱环境里分别求值两侧——产品路径用
            notice_state_path() 自身（不重写），测试路径用该测试自己的
            构造表达式求值 ⇒ 逐字节相等才算数。

    JDG-02  通道一致性（I4）
            **同一条用户可感知判据，必须覆盖全部执行通道。**
            机械判据：AST 调用图（限定名 file:func，避免跨文件同名合并失真），
            从每个「入口」（无仓内调用者的函数）走到真身发射器
            （ShowBalloonTip 常量）的每一条路径，必须经过一次闸
            （console_is_visible / force=True）。

    JDG-03  清单归属分账（流程陈旧的机械化）
            **清单摘要与实物不符，必须能归属**：与 git HEAD 一致 ⇒
            合法 WIP 未刷新（流程陈旧）；两者都不一致 ⇒ 真漂移，必须红。

    JDG-04  契约自包含（0.36.9）
            **判据引用的每个本地 .py 都必须已入库。**

    JDG-05  构建器拥有的文件不许手工改（0.36.9）
            **仓内 .gitignore 必须与构建器 GITIGNORE_TEMPLATE 逐字节相同。**

    JDG-06  产件自洽（0.37.0）
            **dist/ 里最新的 wheel 必须：只含一个 dist-info 目录、目录版本
            == 当前包版本、RECORD 与包内条目逐条对得上。**
            来历（0.37.0 实测，靠眼看抓到，故上升为机制）：本机打包走
            keep_temp=True 的仓外驱动（宿主批量删除守卫的限制），
            staging 树跨版本复用 ⇒ 升版后旧版 `antinel-<old>.dist-info/`
            残留在 staging 里，新 wheel 一次带上两套 dist-info
            （0.37.0 实测 129 条目，其中 5 个是 0.36.9 的）。
            修法当时是「改名让开 + 重建」，但那是一次性的；
            本判据让这个形状从此在闸门层就暴露。

★ 三条纪律（与 0366 及全仓惯例一致）：
  · 每条判据都配**负控**：把对象改坏，判据必须报红——否则它只是会执行的代码。
  · 判据**不二次实现**口径：产品侧一律求值／import 产品自己的函数。
  · 收尾 `try/finally` 还原，还原后自己再验一次——「崩了」不许污染工作区。

★ 自审记录（本文件第一版自身的两个缺陷，都被负控/实跑当场抓出）：
  · `_call_product_func` 去掉 docstring 后没把函数定义包回去 ⇒ `return`
    无家可归（SyntaxError）。⇒ 保留 FunctionDef，只换 body。
  · `direct` 检测用常量**全等**比对 `"ShowBalloonTip"`，而真身是长
    PowerShell 串的一段 ⇒ 永不匹配，所有路径空转 `all([])` 成 True
    （假绿：把未受闸的 notify 通道放过了）。⇒ 改子串匹配。
    教训与 F-15「桩吞效应」同型：**检查条件写了，但它检不到那个东西**。
"""
from __future__ import annotations

import ast
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

HOOK = os.path.join(ROOT, "hooks", "pre_tool_use.py")
SHIELD = os.path.join(ROOT, "host_shield.py")
TESTS = os.path.join(ROOT, "scripts", "verification_tests.py")
JUDGMENT = os.path.join(ROOT, "psl", "judgment.json")

RESULTS = []          # [(name, fn, negctl)] —— 与 0366 记账范式一致
_BACKUP = []          # [(path, 原文)] —— 负控改坏的临时回滚栈


def check(name, negctl=None):
    """`negctl` 传函数名（字符串）：负控定义在判据之后，main() 里再解析。"""
    def deco(fn):
        RESULTS.append((name, fn, negctl))
        return fn
    return deco


def _restore_all():
    while _BACKUP:
        path, text = _BACKUP.pop()
        io.open(path, "w", encoding="utf-8", newline="").write(text)


def _patch(path, old, new):
    """临时替换文件内容（入回滚栈）。找不到锚点 ⇒ AssertionError（不静默）。"""
    src = io.open(path, encoding="utf-8").read()
    if old not in src:
        raise AssertionError("锚点未找到：%r 不在 %s" % (old[:60], os.path.basename(path)))
    _BACKUP.append((path, src))
    io.open(path, "w", encoding="utf-8", newline="").write(src.replace(old, new, 1))
    return True


def _func_segment(path, fname):
    """取产品函数的源码段。函数不存在 ⇒ AssertionError（没对象的检查 ＝ 假守卫）。"""
    src = io.open(path, encoding="utf-8").read()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.FunctionDef) and n.name == fname:
            seg = ast.get_source_segment(src, n)
            if seg:
                return seg
    raise AssertionError("产品函数 %s 不在 %s" % (fname, os.path.basename(path)))


def _call_product_func(path, fname, env=None):
    """在受控命名空间里执行产品函数（去 docstring），返回其真值。

    ★ 为什么不 import：hook 模块导入有副作用；而口径必须来自产品自身
      （判据不许二次实现）。只提供 os/json 与真实 environ。
    ★ 保留 FunctionDef 只换 body —— 第一版把 body 平铺成模块语句，
      `return` 顿时无家可归（SyntaxError），被首跑当场抓获。
    """
    seg = _func_segment(path, fname)
    fn_node = ast.parse(seg).body[0]
    fn_node.body = [s for s in fn_node.body
                    if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                            and isinstance(s.value.value, str))]
    mod = ast.Module(body=[fn_node], type_ignores=[])
    ns = {"os": os, "json": json}
    old = os.environ.get("ANTINEL_HUB_DIR")
    if env is not None:
        os.environ["ANTINEL_HUB_DIR"] = env
    try:
        exec(compile(mod, "<jdg-%s>" % fname, "exec"), ns)
        return ns[fname]()
    finally:
        if old is None:
            os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            os.environ["ANTINEL_HUB_DIR"] = old


# ═══════════════════ JDG-01 状态路径一致性 ═══════════════════

def _reset_sites():
    """测试文件里所有「重置 notify 状态」的赋值语句 ⇒ [(行号, 表达式源码)]。"""
    src = io.open(TESTS, encoding="utf-8").read()
    out = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(c, ast.Constant) and isinstance(c.value, str)
                   and c.value.endswith("notify_state.json")
                   for c in ast.walk(node.value)):
            continue
        out.append((node.lineno, ast.get_source_segment(src, node.value)))
    return out


def _eval_path_expr(expr, ns):
    """在镜像命名空间里求值路径构造表达式。未知名 ⇒ 独立哨兵目录（不猜）。

    ★ 自审：第一版用 `__missing__` 兜底未知名，但 eval 的 locals 是 dict
      **子类**时不会回落到 globals ⇒ 连 `os`/`Path` 都被吞成哨兵
      （`WindowsPath has no attribute environ`）。⇒ 先把已知全局名焊进 locals。
    """
    class _S(dict):
        def __missing__(self, key):
            p = Path(tempfile.gettempdir()) / "jdg01_unknown" / key
            self[key] = p
            return p
    known = {"os": os, "Path": Path, "json": json}
    known.update(ns)
    ns = _S(known)
    return str(eval(expr, {"__builtins__": __builtins__, "os": os, "Path": Path}, ns))


def jdg01_body():
    sandbox = str(Path(tempfile.mkdtemp(prefix="jdg01_")) / "hub")

    sites = _reset_sites()
    if not sites:
        raise AssertionError("测试套件里没有任何 notify 状态重置点（UX 用例不存在了？）")

    # 镜像套件自己的绑定：line 71 `os.environ["ANTINEL_HUB_DIR"] = str(WORK / "hub")`
    work = Path(tempfile.mkdtemp(prefix="jdg01_work_"))
    mirror = {"WORK": work, "proj": work / "proj"}
    old_env = os.environ.get("ANTINEL_HUB_DIR")
    os.environ["ANTINEL_HUB_DIR"] = sandbox          # 两侧同一环境
    try:
        product_path = _call_product_func(HOOK, "notice_state_path", env=sandbox)
        matched, mismatched, unknown = [], [], []
        for lineno, expr in sites:
            try:
                resolved = _eval_path_expr(expr, dict(mirror))
            except Exception as e:                      # noqa: BLE001
                unknown.append((lineno, expr, repr(e)))
                continue
            if os.path.normcase(os.path.normpath(resolved)) == \
               os.path.normcase(os.path.normpath(product_path)):
                matched.append((lineno, resolved))
            else:
                mismatched.append((lineno, expr, resolved))
    finally:
        if old_env is None:
            os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            os.environ["ANTINEL_HUB_DIR"] = old_env

    if not matched:
        detail = "；".join("L%d %s ⇒ %s" % (ln, e.split(" = ")[-1][:40], r)
                           for ln, e, r in mismatched) or "(无可判定重置点)"
        raise AssertionError("没有一处重置命中产品真实读取路径 %s；%s"
                             % (product_path, detail))
    for ln, _e, r in mismatched:                       # 有命中也有未命中：摆出来，不判红
        print("      ⚠ L%d 重置路径与产品不一致：%s" % (ln, r))
    for ln, _e, err in unknown:
        print("      ⚠ L%d 无法静态求值（不算数）：%s" % (ln, err))
    return "产品读 %s；%d 处重置命中" % (os.path.basename(product_path), len(matched))


@check("JDG-01 状态路径一致性：测试重置路径 == 产品读取路径", "n_state_path_regress")
def jdg01():
    return jdg01_body()


def n_state_path_regress():
    """负控：把产品侧路径改回 0.35.2 的老口径（按 cwd 存）⇒ 判据必须报红。"""
    _patch(HOOK,
           '    hub = os.environ.get("ANTINEL_HUB_DIR")\n'
           '    base = os.path.expanduser(hub) if hub else os.path.join(\n'
           '        os.path.expanduser("~"), ".antinel")\n'
           '    return os.path.join(base, "notify_state.json")',
           '    return os.path.join(os.getcwd(), ".psl", "notify_state.json")')
    try:
        jdg01_body()
        return False                    # 改坏了却仍绿 ⇒ 判据失效
    except AssertionError:
        return True
    finally:
        _restore_all()


# ═══════════════════ JDG-02 通道一致性（I4） ═══════════════════

_BALLOON_PRIMS = ("_notify", "_notify_throttled", "notify_owner", "_notify_icon_and_tip", "notify")
_GATE = "console_is_visible"


def _scan_files():
    """会碰气泡通道的产品文件（自选，不写死清单——新通道出现自动纳入）。"""
    files = []
    for base in (ROOT, os.path.join(ROOT, "hooks")):
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            if not name.endswith(".py") or name.startswith("_"):
                continue
            p = os.path.join(base, name)
            try:
                src = io.open(p, encoding="utf-8").read()
            except Exception:                            # noqa: BLE001
                continue
            if "ShowBalloonTip" in src or any(pr in src for pr in _BALLOON_PRIMS):
                files.append(p)
    return files


def _call_graph(paths):
    """限定名调用图：key = `文件名:函数名`（避免跨文件同名合并失真）。

    ★ 第一版用裸函数名做 key ⇒ antinel.py:main 与 pre_tool_use:main 被合并，
      一个文件的 gated 会掩盖另一个文件的未受闸。限定名分开记，
      callee 解析：同文件优先，全仓唯一匹配次之，多处定义不解析（保守）。
    """
    funcs = {}
    for p in paths:
        try:
            tree = ast.parse(io.open(p, encoding="utf-8").read())
        except SyntaxError:
            continue
        base = os.path.basename(p)
        for n in ast.walk(tree):
            if not isinstance(n, ast.FunctionDef):
                continue
            q = "%s:%s" % (base, n.name)
            callees, gated, forced, direct = set(), False, False, False
            # ★ 自审：docstring 也算常量 ⇒ `console_is_visible` 的说明文字里
            #   提到 `ShowBalloonTip` 就被误判成「真身发射者」。
            #   ⇒ 先收集本函数（含嵌套函数）的所有 docstring 节点，扫常量时跳过。
            docs = set()
            for f in ast.walk(n):
                if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                        and f.body and isinstance(f.body[0], ast.Expr) \
                        and isinstance(f.body[0].value, ast.Constant) \
                        and isinstance(f.body[0].value.value, str):
                    docs.add(id(f.body[0]))
            for c in ast.walk(n):
                if id(c) in docs:
                    continue
                if isinstance(c, ast.Constant) and isinstance(c.value, str) \
                        and "ShowBalloonTip" in c.value:
                    direct = True                          # 子串：真身是长 PS 串的一段
                if isinstance(c, ast.Call):
                    nm = c.func.attr if isinstance(c.func, ast.Attribute) else (
                        c.func.id if isinstance(c.func, ast.Name) else None)
                    if nm:
                        callees.add(nm)
                        if nm == _GATE:
                            gated = True
                    for kw in c.keywords:
                        if kw.arg == "force" and isinstance(kw.value, ast.Constant) \
                                and kw.value.value is True:
                            forced = True
            if q in funcs:                                 # 同名嵌套：合并（宁可多护）
                prev = funcs[q]
                prev["gated"] |= gated
                prev["forced"] |= forced
                prev["direct"] |= direct
                prev["callees"] |= callees
            else:
                funcs[q] = {"gated": gated, "forced": forced, "direct": direct,
                            "callees": callees, "file": base}
    for q, d in funcs.items():
        resolved = set()
        for c in d["callees"]:
            same = "%s:%s" % (d["file"], c)
            if same in funcs:
                resolved.add(same)
            else:
                cands = [x for x in funcs if x.endswith(":" + c)]
                if len(cands) == 1:
                    resolved.add(cands[0])
        d["resolved"] = resolved
    callers = {}
    for q, d in funcs.items():
        for c in d["resolved"]:
            callers.setdefault(c, set()).add(q)
    return funcs, callers


def _emitter_closure(funcs, prims_q):
    """传递闭包：能**走到**气泡发射的函数都算发射者。

    ★ 自审：第一版只看一层（`resolved & prims_q`）⇒ `_roots_add → seven_step
      → notify → …` 这条链里 seven_step 不是原语、_roots_add 离得更远，
      **整条 CLI 通道对判据隐形**——绿灯理由是错的，比红灯更危险。
      ⇒ 闭包：沿 resolved 传递，直到 direct 或撞见原语。
    """
    def reaches(q, seen):
        if q in seen:
            return False
        d = funcs.get(q)
        if d is None:
            return False
        if d["direct"] or (d["resolved"] & prims_q):
            return True
        seen = seen | {q}
        return any(reaches(c, seen) for c in d["resolved"])

    memo = {}

    def reaches_memo(q):
        if q not in memo:
            memo[q] = reaches(q, set())
        return memo[q]

    return {q for q in funcs if reaches_memo(q)}


def _entries(funcs, callers, emitters):
    """入口＝**源 SCC** 里的发射者（调用图上游没有外部流入的分量）。

    ★ 自审一：第一版「无仓内调用者」漏掉 `antinel.py:main`——它的唯一
      调用者是它自己（CLI 再入）⇒ 整棵 CLI 树对判据隐形。
    ★ 自审二：第二版「向上闭合」把含闸的中间层（_notify）也算成入口
      ⇒ 从链中段起跳，必然红（误报）。
    ⇒ 正解：源 SCC。互相递归（self-loop / A↔B）算同一分量；
      该分量若没有来自其他分量的调用者，它就是入口。
      （在源分量内部重复起跳无害：走的是同一条链，判据方向一致。）
    """
    fwd_cache = {}

    def fwd(x):
        if x not in fwd_cache:
            seen, stack = set(), [x]
            while stack:
                y = stack.pop()
                for c in funcs[y]["resolved"]:
                    if c in funcs and c not in seen:
                        seen.add(c)
                        stack.append(c)
            fwd_cache[x] = seen
        return fwd_cache[x]

    scc = {}
    for x in emitters:
        comp = {x} | {y for y in fwd(x) if x in fwd(y)}
        scc[x] = frozenset(comp)
    out = set()
    for x in emitters:
        s = scc[x]
        ext = any(callers.get(y, set()) - s for y in s)
        if not ext:
            out.add(x)
    return out


def _gate_ok(d, prims_q):
    """闸必须长在**本层直接触发发射**的函数上，否则是挂在无关代码上的洗白。

    ★ 自审：第一版只看「函数体内出现过 console_is_visible」——若某函数
      出于无关目的调了它（或将来有人这么写），下游未受闸的通道会被洗白。
      ⇒ 有效闸 = 调了闸 且（本层含真身常量 或 本层直接调用气泡原语）。
    """
    if not (d["gated"] or d["forced"]):
        return False
    return d["direct"] or bool(d["resolved"] & prims_q)


def _protected(funcs, emitters, prims_q, name, seen):
    """从入口 name 往下游走：到达真身发射器的每条路径都必须过闸。"""
    if name in seen:
        return True                      # 环：上游已判过
    d = funcs.get(name)
    if d is None:
        return True                      # 非本仓函数，由调用者负责
    seen = seen | {name}
    if _gate_ok(d, prims_q):
        return True
    if d["direct"]:
        return False                     # 真身发射且没闸 ⇒ 未受保护的通道
    # 只沿「能走到发射」的调用往下游；非发射分支走不到气泡，不参与判定
    subs = [c for c in d["resolved"] if c in emitters]
    if not subs:
        return True
    return all(_protected(funcs, emitters, prims_q, c, seen) for c in subs)


def jdg02_body():
    paths = _scan_files()
    if not paths:
        raise AssertionError("没扫到任何碰气泡通道的产品文件")
    funcs, callers = _call_graph(paths)
    prims_q = {q for q in funcs for p in _BALLOON_PRIMS if q.endswith(":" + p)}
    emitters = _emitter_closure(funcs, prims_q)
    if not emitters:
        raise AssertionError("调用图里没有任何气泡发射者")
    # 只看入口：通道是「入口 → 真身」的路径，
    # 中间的原语（如 _notify）由入口负责 ⇒ 不重复记账。
    entries = _entries(funcs, callers, emitters)
    bad = [q for q in sorted(entries) if not _protected(funcs, emitters, prims_q, q, set())]
    if bad:
        raise AssertionError("以下入口的气泡路径没有可见性闸（同族第⑦例形态）：%s"
                             % "、".join(bad))
    return "%d 个发射者 / %d 个入口，全部过闸" % (len(emitters), len(entries))


@check("JDG-02 通道一致性 I4：每条气泡路径都过可见性闸", "n_ungated_channel")
def jdg02():
    return jdg02_body()


def n_ungated_channel():
    """负控：把 notify 的闸摘掉（复原 0.36.8 之前的形态）⇒ 判据必须报红。"""
    _patch(SHIELD,
           '    try:\n'
           '        if console_is_visible() is True:\n'
           '            return\n'
           '    except Exception:\n'
           '        pass                                # 判不出 ⇒ 照弹\n'
           '    _notify(title, body)',
           '    _notify(title, body)')
    try:
        jdg02_body()
        return False
    except AssertionError:
        return True
    finally:
        _restore_all()


# ═══════════════ JDG-02B 通道行为：结构之外的第二个半边 ═══════════════

def jdg02b_body():
    """行为判据：两条真实通道，可见⇒不弹、不可见⇒弹（四象限）。

    ★ 为什么必须有这一半边（自审实录）：结构检查判定「调了
      console_is_visible 即算过闸」是**语法层**的。实测把闸写成
      `if False and _hs.console_is_visible() is True:`——调用还在、
      结构检查照样绿，而行为早已失效。⇒ 本仓纪律「判据只查行为」：
      调用存在不等于判据生效，必须在效应边界上量。
    ★ 副作用隔离：行为相位把 ANTINEL_HUB_DIR 指到临时目录，
      不碰开发者真实账本（notify_owner 抑制时会写 notify_shown_in_window）。
    """
    import host_shield as hs
    import importlib
    hs = importlib.reload(hs)          # ★ 自审：负控改的是磁盘，不复活模块对象
    hookdir = os.path.join(ROOT, "hooks")   #   测的就是旧字节（与「凭记忆还原」同型）
    if hookdir not in sys.path:
        sys.path.insert(0, hookdir)
    import pre_tool_use as p
    p = importlib.reload(p)
    import subprocess

    old_env = os.environ.get("ANTINEL_HUB_DIR")
    old_vis = hs.console_is_visible
    sandbox = tempfile.mkdtemp(prefix="jdg02b_")
    os.environ["ANTINEL_HUB_DIR"] = sandbox
    results = {}
    try:
        # 通道一：host_shield.notify（安全键变更链 seven_step → notify）
        real_notify = hs._notify
        hits = []
        hs._notify = lambda *a, **k: hits.append(1)
        try:
            hs.console_is_visible = lambda: True
            hs.notify("t", "b")
            results["notify@可见"] = not hits
            hits.clear()
            hs.console_is_visible = lambda: False
            hs.notify("t", "b")
            results["notify@不可见"] = bool(hits)
        finally:
            hs._notify = real_notify

        # 通道二：hook 的 notify_owner（拦截气泡）—— 效应边界＝Popen
        real_popen = subprocess.Popen
        pops = []
        subprocess.Popen = lambda *a, **k: pops.append(1)
        try:
            hs.console_is_visible = lambda: True
            p.notify_owner("t", "b")
            results["notify_owner@可见"] = not pops
            pops.clear()
            hs.console_is_visible = lambda: False
            p.notify_owner("t", "b")
            results["notify_owner@不可见"] = bool(pops)
        finally:
            subprocess.Popen = real_popen
    finally:
        hs.console_is_visible = old_vis
        if old_env is None:
            os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            os.environ["ANTINEL_HUB_DIR"] = old_env

    bad = [k for k, v in results.items() if not v]
    if bad:
        raise AssertionError("行为不符合「可见⇒不弹／不可见⇒弹」：%s" % "、".join(bad))
    return "四象限全对（可见抑制×2 / 不可见弹出×2）"


@check("JDG-02B 通道行为：真实通道弹/不弹四象限", "n_dead_gate_bypass")
def jdg02b():
    return jdg02b_body()


def n_dead_gate_bypass():
    """负控：把闸写成永假（`if False and console_is_visible()`）。

    ★ 这正是结构检查抓不到、行为检查必须抓住的形态：
      调用还在（结构绿），行为已死。第一版只有结构半边，本负控当场抓出漏报。
    """
    _patch(HOOK, '        if _hs.console_is_visible() is True:',
           '        if False and _hs.console_is_visible() is True:')
    try:
        jdg02b_body()
        return False
    except AssertionError:
        return True
    finally:
        _restore_all()


# ═══════════════════ JDG-03 清单归属分账 ═══════════════════

def _git_tracked(rel):
    """文件是否在 git 管理下（= 合法编辑链的凭证）。"""
    try:
        r = subprocess.run(["git", "ls-files", "--error-unmatch", rel], cwd=ROOT,
                           capture_output=True, timeout=60)
    except Exception:                                    # noqa: BLE001
        return None
    return r.returncode == 0


def classify_digests(judgment_path):
    """清单摘要逐项归属。返回 (相符, WIP陈旧, 真漂移)。

    ★ 归属规则（0.36.8 定）：
      相符                      ⇒ ok
      不符 + git 在管（tracked） ⇒ **WIP 陈旧**：digests 只是没跟上合法编辑
      （实测误报来源：harness 快照之后的编辑会同时「不符 digests」且
       「不符 HEAD」——第一版据此判真漂移，把合法 WIP 误报成产品问题）
      不符 + 不在 git / 文件缺失  ⇒ **真漂移**（不可归属，必须红）
    """
    import hashlib
    d = json.load(io.open(judgment_path, encoding="utf-8"))
    dig = d.get("digests") or {}
    ok, stale, drift = [], [], []
    for rel, val in sorted(dig.items()):
        want = val.split(":", 1)[1] if ":" in val else val
        fp = os.path.join(ROOT, rel)
        if not os.path.isfile(fp):
            drift.append((rel, "文件缺失"))
            continue
        actual = hashlib.sha256(io.open(fp, "rb").read()).hexdigest()
        if actual == want.lower():
            ok.append(rel)
            continue
        tracked = _git_tracked(rel)
        if tracked:
            stale.append(rel)          # git 在管 ⇒ 合法 WIP，只是清单没刷新
        else:
            drift.append((rel, "未入 git 却与清单不符 ⇒ 不可归属"))
    return ok, stale, drift


def jdg03_body(judgment_path=JUDGMENT):
    ok, stale, drift = classify_digests(judgment_path)
    if drift:
        raise AssertionError("真漂移 %d 项：%s" % (
            len(drift), "；".join("%s（%s）" % x for x in drift[:5])))
    return "%d 相符 / %d 项 WIP 陈旧（0 真漂移）" % (len(ok), len(stale))


@check("JDG-03 清单不符必须可归属（WIP 陈旧 vs 真漂移）", "n_bogus_digest_is_drift")
def jdg03():
    return jdg03_body()


def n_bogus_digest_is_drift():
    """负控：把一个摘要指向**不存在的文件**（不可归属）⇒ 判据必须报真漂移。

    ★ 自审：第一版负控造「HEAD 与实物都不符的假摘要」，但 tracked-dirty
      规则确立后那已归 WIP 陈旧 ⇒ 负控必须走**不可归属**分支才验得到红。
    """
    d = json.load(io.open(JUDGMENT, encoding="utf-8"))
    dig = d.get("digests") or {}
    if not dig:
        return False
    first = sorted(dig)[0]
    dig[first] = "sha256:" + "0" * 64
    d["digests"] = dig
    d["__negctl_missing__"] = True
    tmp = tempfile.mkdtemp(prefix="jdg03_")
    fake = os.path.join(tmp, "judgment.json")
    io.open(fake, "w", encoding="utf-8").write(json.dumps(d, ensure_ascii=False))
    # 指向一个必然不存在的路径，逼出「文件缺失」分支
    d2 = json.load(io.open(fake, encoding="utf-8"))
    d2["digests"]["zz_jdg03_missing_probe.py"] = "sha256:" + "1" * 64
    io.open(fake, "w", encoding="utf-8").write(json.dumps(d2, ensure_ascii=False))
    try:
        jdg03_body(judgment_path=fake)
        return False
    except AssertionError as e:
        return "漂移" in str(e)


# ═══════════════ JDG-04 契约自包含：判据引用的本地 .py 必须已入库 ═══════════════
#
# ★ 0.36.9 新增，而且是**本版实测抓到**的，不是设计构想：
#   0.36.8 把 10 套判据登记成统一契约，但 0360 套引用的 `_p_badge_probe.py`
#   从未入库；更早的 `ci/inbox_guards.py` 引用的 `_p_p11_negctl_mutation.py`
#   也从未入库。⇒ 本机全绿，**新克隆必红**（判据契约在新机器上不成立）。
#   0.36.8 的新克隆实验当场抓到：0360 报「缺 _p_badge_probe.py」。
#
#   ★ 为什么这是制度性漏洞而不是偶然：`.gitignore` 的 `_p_*` 把未入库探针
#     从 `git status` 里藏起来 ⇒ 缺口从「可见」变「隐藏」。0.36.8 为了收干净
#     工作区加的那条规则，反而让这类空洞不再出现在状态列表里 —— 修一处、
#     blind 一处，正是「判据腐化」的同族手法。
#
#   机械判据（不许靠人眼）：枚举 `ci/` 下每一份判据源码里出现的**仓库内
#   相对 .py 路径**（AST 抽字符串常量，不猜、不吃注释），逐个问 git「在库里
#   吗」。有一个不在就红，并把「谁引用了它」逐个点名。
#   ⇒「新增模块/判据时漏带依赖」从此进不了提交：闸门先红。
#
#   这正是「新增模块最大限度的避免引入新问题」的机制形态：**新东西不算被
#   接纳，直到它声明的每一份依赖都在版本控制里**。

def _string_constants(path):
    """AST 抽取源码里的字符串常量（比正则可靠：不被注释/文档字符串骗）。"""
    try:
        tree = ast.parse(io.open(path, encoding="utf-8").read())
    except SyntaxError:
        return []
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _local_py_refs():
    """{引用: {引用它的判据}} —— 只收**盘上存在**的仓库内相对 .py 路径。

    ★ 两个限定，都是为了让判据不假红（假红比漏红更坏：它训练人绕过闸门）：

      ① 只收**盘上存在**的：判据里也会出现 "setup.py"、"sitecustomize.py"
         这类**不属于本仓**的名字（示例、文档、第三方模块名）。
      ② 跳过 `build/` 镜像：`.gitignore` 第 5 行本就忽略 `build/`，其中 26 个
         .py 是 0.28 时代的历史 force-add、24 个新模块没跟上 ⇒ 这是「构建
         镜像该不该入库」的另一笔账（见交付说明的遗留项），不是判据契约洞。
         若把它算进契约，判据会为一个**设计上就该不存在于 git** 的目录天天红。
    """
    refs = {}
    ci_dir = os.path.join(ROOT, "ci")
    for name in sorted(os.listdir(ci_dir)):
        if not name.endswith(".py"):
            continue
        for s in _string_constants(os.path.join(ci_dir, name)):
            if not s.endswith(".py"):
                continue
            if s.startswith(("/", "\\")) or (len(s) > 1 and s[1] == ":"):
                continue                      # 绝对路径：安装态，不入库
            if s.startswith("build/") or s.startswith("build\\"):
                continue                      # 构建镜像：见 docstring ②
            if not os.path.isfile(os.path.join(ROOT, s)):
                continue                      # 不属于本仓的名字
            refs.setdefault(s, set()).add(name)
    return refs


def jdg04_body():
    refs = _local_py_refs()
    if not refs:
        raise AssertionError("一条引用都没抽到——AST 抽取坏了（量具自失效）")
    untracked, unknown = [], []
    for rel, users in sorted(refs.items()):
        t = _git_tracked(rel)
        if t is None:
            unknown.append(rel)
        elif t is False:
            untracked.append((rel, sorted(users)))
    if untracked or unknown:
        parts = ["未入库 %s（被 %s 引用）" % (r, "/".join(u)) for r, u in untracked]
        parts += ["入库状态取不到 %s" % r for r in unknown]
        raise AssertionError("；".join(parts))
    return "判据引用的 %d 个本地 .py 全部在库" % len(refs)


@check("JDG-04 契约自包含：判据引用的每个本地 .py 都已入库", "n_contract_hole_is_red")
def jdg04():
    return jdg04_body()


def n_contract_hole_is_red():
    """负控：把**一个**已入库引用伪装成未入库 ⇒ 判据必须报红并点名它。"""
    refs = _local_py_refs()
    tracked = [r for r in refs if _git_tracked(r)]
    if not tracked:
        return False
    victim = sorted(tracked)[0]
    real = globals()["_git_tracked"]

    def fake(rel):
        return False if rel == victim else real(rel)

    globals()["_git_tracked"] = fake
    try:
        jdg04_body()
        return False
    except AssertionError as e:
        return victim in str(e) and "未入库" in str(e)
    finally:
        globals()["_git_tracked"] = real


# ═══════════════ JDG-05 构建器拥有的文件不许手工改（.gitignore == 模板） ═══════════════
#
# ★ 0.36.9 新增，同样是**本版实测抓到**的，同一个坑第二次踩：
#   构建器每次都**整文件覆盖** `.gitignore` ⇒ 手工补进去的规则会在下一次构建后
#   **静默蒸发**。2026-09-29 踩过第一次（898791a 的三行被回退，修法写进注释）；
#   2026-10-08 又把 `*.trash*`／`_p_*`／`_t_*` 手工补进**仓里那份**而没改模板
#   ⇒ 一次构建后规则消失，`git status` 瞬间多出 92 个未跟踪探针（实测）。
#   ★★ 两次都是「注释记住了、手照旧」——**注释不是机制**。本判据就是那个机制。
#
#   机械判据：把构建器的 `GITIGNORE_TEMPLATE` 提成模块级常量，逐字节比对仓内
#   `.gitignore`；不一致就红，并点名「只有模板有／只有仓里有」各几行。
#   ⇒「构建器拥有的文件被手工改」从此在闸门层就暴露，而不是等构建后静默回退。

def jdg05_body():
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    try:
        import build_package as bp
    except Exception as e:                                # noqa: BLE001
        raise AssertionError("导不进构建器（%r）—— 无法比对模板" % (e,))
    tpl = getattr(bp, "GITIGNORE_TEMPLATE", None)
    if not isinstance(tpl, str) or not tpl.strip():
        raise AssertionError("构建器没有 GITIGNORE_TEMPLATE 常量 —— 模板没被提出来，"
                             "本判据无从比对（量具自失效）")
    disk_p = os.path.join(ROOT, ".gitignore")
    if not os.path.isfile(disk_p):
        raise AssertionError(".gitignore 不在仓根")
    disk = io.open(disk_p, encoding="utf-8", newline="").read()
    if disk != tpl:
        t, d = tpl.splitlines(), disk.splitlines()
        only_tpl = [x for x in t if x not in d]
        only_disk = [x for x in d if x not in t]
        raise AssertionError(
            "仓内 .gitignore 与构建器模板不一致（模板 %d 行／仓内 %d 行）—— "
            "手工改的规则会被下次构建静默回退。只有模板有: %s；只有仓里有: %s"
            % (len(t), len(d), only_tpl[:4] or "无", only_disk[:4] or "无"))
    return "仓内 .gitignore 与模板逐字节相同（%d 行）" % len(tpl.splitlines())


@check("JDG-05 构建器拥有的文件不许手工改（.gitignore == 模板）", "n_gitignore_drift_is_red")
def jdg05():
    return jdg05_body()


def n_gitignore_drift_is_red():
    """负控：往模板里塞一行仓内没有的规则 ⇒ 判据必须报红并点名方向。"""
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import build_package as bp
    real = bp.GITIGNORE_TEMPLATE
    canary = "# jdg05-canary"
    try:
        bp.GITIGNORE_TEMPLATE = real + canary + "\n"
        jdg05_body()
        return False
    except AssertionError as e:
        return "不一致" in str(e)
    finally:
        bp.GITIGNORE_TEMPLATE = real


# ═══════════════════ JDG-06 产件自洽：wheel 单 dist-info ＋ RECORD 对得上 ═══════════════════
#
# ★ 0.37.0 新增。来历是**本轮自己踩到的**（不是设计构想）：
#   本机打包走仓外驱动（keep_temp=True，绕开宿主批量删除守卫）。该属性让
#   setuptools 收尾不删 staging 树 —— 于是**跨版本复用时**，上一版的
#   `antinel-0.36.9.dist-info/` 还留在 staging 里，而新版 dist-info 目录名
#   带版本号、名字不同 ⇒ copy2 覆盖不到它 ⇒ 新 wheel 一次带上两套 dist-info
#   （0.37.0 首建实测 129 条目，5 个是 0.36.9 的；0.36.9 的 wheel 干净，
#   只因那次构建前 build/ 被改名让开过 —— 也就是说这个坑**每次升版都在，
#   只是之前每次都被顺手避开**）。
#   ⇒ 与 JDG-04/05 同型：「注释记住了、手照旧」＝没有机制。本条就是那个机制。
#
#   机械判据（三条，缺一不可）：
#     ① dist/ 里**最新的** wheel 只含一个 .dist-info 目录；
#     ② 该目录的版本 == 当前包版本（antinel.py 的 VERSION）；
#     ③ RECORD 行数与包内条目数相等，且 RECORD 指向的每个条目都在包内。
#   dist/ 无 wheel（新克隆/未打包）⇒ 返回说明文字，不阻断 ——
#     但会**明写**「无可检对象」，不与「检过了且通过」混在一种措辞里。

def _dist_wheels():
    """dist/ 下未改名让开的 wheel（.away-* 是历史产件，不检）。"""
    d = os.path.join(ROOT, "dist")
    out = []
    try:
        for n in sorted(os.listdir(d)):
            if n.startswith("antinel-") and n.endswith(".whl") and ".away-" not in n:
                out.append(os.path.join(d, n))
    except OSError:
        pass
    return out


def _pkg_version():
    try:
        src = io.open(os.path.join(ROOT, "antinel.py"), encoding="utf-8").read()
        m = re.search(r'^VERSION\s*=\s*"([^"]+)"', src, re.M)
        return m.group(1) if m else None
    except OSError:
        return None


def _wheel_defect(path, want_version):
    """返回 None（通过）或红项文案。`want_version` 为 None 时跳过版本比对。"""
    import zipfile
    try:
        z = zipfile.ZipFile(path)
    except Exception as e:                                    # noqa: BLE001
        return "打不开：%r" % (e,)
    names = z.namelist()
    di = sorted({n.split("/")[0] for n in names if ".dist-info" in n.split("/")[0]})
    if len(di) != 1:
        return ("wheel 里有 %d 个 .dist-info 目录：%s —— keep_temp staging "
                "跨版本复用的残留形态（旧版 dist-info 没被清掉）"
                % (len(di), "、".join(di)))
    if want_version and ("-" + want_version + ".dist-info") not in ("-" + di[0]):
        return "dist-info 目录 %s 与当前包版本 %s 不符" % (di[0], want_version)
    rec_name = di[0] + "/RECORD"
    if rec_name not in names:
        return "%s 不在包内" % rec_name
    try:
        rec = z.read(rec_name).decode("utf-8", "replace")
    except Exception as e:                                    # noqa: BLE001
        return "RECORD 读不出：%r" % (e,)
    lines = [l for l in rec.splitlines() if l.strip()]
    listed = [l.split(",")[0] for l in lines]
    missing = [n for n in listed if n not in names]
    if missing:
        return "RECORD 指向 %d 个不在包内的条目：%s" % (
            len(missing), "、".join(missing[:3]))
    if len(listed) != len(names):
        return "RECORD 只登记 %d 条，包内实际 %d 条（有条目没进清单）" % (
            len(listed), len(names))
    return None


def jdg06_body(wheel=None):
    """检 dist/ 里最新的 wheel；`wheel` 参数只给负控用（合成包）。"""
    if wheel is not None:
        why = _wheel_defect(wheel, None)
        if why:
            raise AssertionError(why)
        return "合成 wheel 通过"
    ws = _dist_wheels()
    if not ws:
        return "dist/ 里没有待检 wheel（未打包或新克隆）—— **无可检对象**，本条不阻断"
    # 最新＝版本号最大（.away-* 已排除）；旧版产件被改名让开前也按同一判据检
    def _key(p):
        m = re.search(r"antinel-(\d+)\.(\d+)\.(\d+)-py3", os.path.basename(p))
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)
    newest = max(ws, key=_key)
    want = _pkg_version()
    why = _wheel_defect(newest, want)
    if why:
        raise AssertionError("%s：%s" % (os.path.basename(newest), why))
    others = [os.path.basename(p) for p in ws if p != newest]
    return ("最新 wheel %s：单 dist-info（%s）且 RECORD 逐条对得上%s"
            % (os.path.basename(newest), want or "?",
               ("；dist/ 内另有旧产件：%s" % "、".join(others)) if others else ""))


@check("JDG-06 产件自洽：wheel 单 dist-info ＋ 版本对 ＋ RECORD 对得上",
       "n_wheel_pollution_is_red")
def jdg06():
    return jdg06_body()


def _mk_synthetic_wheel(double_distinfo=True, record_missing=False):
    """负控专用：在临时目录造一个最小 wheel。"""
    import zipfile
    tmp = tempfile.mkdtemp(prefix="jdg06_")
    p = os.path.join(tmp, "antinel-9.9.9-py3-none-any.whl")
    with zipfile.ZipFile(p, "w") as z:
        if double_distinfo:
            for di in ("antinel-9.9.8.dist-info", "antinel-9.9.9.dist-info"):
                z.writestr(di + "/METADATA", "Metadata-Version: 2.1\n")
                z.writestr(di + "/WHEEL", "Wheel-Version: 1.0\n")
            z.writestr("antinel-9.9.9.dist-info/RECORD", "")
            z.writestr("antinel.py", "# stub\n")
        else:
            z.writestr("antinel-9.9.9.dist-info/METADATA", "Metadata-Version: 2.1\n")
            z.writestr("antinel-9.9.9.dist-info/WHEEL", "Wheel-Version: 1.0\n")
            if record_missing:
                # RECORD 指向一个不在包内的条目
                z.writestr("antinel-9.9.9.dist-info/RECORD",
                           "antinel.py,,\nhost_shield.py,,\n")
            else:
                z.writestr("antinel-9.9.9.dist-info/RECORD",
                           "antinel-9.9.9.dist-info/METADATA,,\n"
                           "antinel-9.9.9.dist-info/WHEEL,,\n"
                           "antinel-9.9.9.dist-info/RECORD,,\n"
                           "antinel.py,,\n")
            z.writestr("antinel.py", "# stub\n")
    return tmp, p


def n_wheel_pollution_is_red():
    """负控（两个形状，一条负控）：合成 wheel 带病 ⇒ 判据必须红。

    形状一：两套 dist-info（0.37.0 实测踩到的 polling 形态）；
    形状二：单 dist-info 但 RECORD 指向不在包内的条目（构建被截断的形态）。
    ★ 为什么两条并成一条负控：RESULTS 的记账范式是一条判据一个负控名；
      硬拆成两条判据会让 jdg06_body() 白跑一遍。并题后**回报具体失塌形状**，
      不许只回 False —— 否则「红的是哪一半」靠猜。
    """
    tmp1, p1 = _mk_synthetic_wheel(double_distinfo=True)
    try:
        try:
            jdg06_body(wheel=p1)
            return "双 dist-info 形态没有红 —— 判据对产件污染是瞎的"
        except AssertionError:
            pass
        tmp2, p2 = _mk_synthetic_wheel(double_distinfo=False,
                                       record_missing=True)
        try:
            try:
                jdg06_body(wheel=p2)
                return "RECORD 失洽形态没有红 —— 判据对截断构建是瞎的"
            except AssertionError:
                pass
        finally:
            try:
                os.replace(tmp2, tmp2 + ".away-negctl")     # 零删除
            except OSError:
                pass
        return True
    finally:
        try:
            os.replace(tmp1, tmp1 + ".away-negctl")         # 零删除
        except OSError:
            pass


# ═══════════════════ main（与 0366 记账范式一致） ═══════════════════

def main():
    ok = fail = 0
    print("=" * 74)
    print("0.36.8 判据 —— 判据腐化检测（JDG 族：发现错误的机制自己会不会腐烂）")
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
            except Exception as e:                          # noqa: BLE001
                print("  💥 %-46s %r" % (name[:46], e))
                fail += 1
        print("-" * 74)
        print("负控（把对象改坏，看判据是否真的报红）")
        for name, fn, neg in RESULTS:
            if neg is None:
                continue
            negfn = globals().get(neg) if isinstance(neg, str) else neg
            if negfn is None or not callable(negfn):
                print("  💥 %-46s 负控缺失或不可调用（登记名 %r）" % (name[:46], neg))
                fail += 1
                continue
            try:
                r = negfn()
            except Exception as e:                          # noqa: BLE001
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
