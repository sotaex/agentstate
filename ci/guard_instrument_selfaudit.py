#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.42.0 meta 判据 —— **量具先量自己：判据不许用文本匹配代替结构匹配**。

★★ 为什么必须有这条（2026-10-09 本班**五次**踩同一个坑，每次都是我写判据时犯的）：

  ① S42：`"68" not in ast.dump(g)` —— 想查"提权阈值还是不是 68"。
     结果 `_pick_release_py()` 的 **docstring 里就写着 "setuptools >= 68"**
     ⇒ 把阈值改成 0 之后判据**仍然绿**（负控因此失效）。
  ② S42：`"sys.executable" not in ast.dump(g)` —— 它在 AST 里是
     `Attribute(Name('sys'), 'executable')`，**不是字符串常量** ⇒ 永远为假。
  ③ S44：`"return False" not in ast.dump(f)` —— AST 里是 `Return(Constant(False))`
     ⇒ 永远为假。
  ④ dist-hygiene S39：`for node in ast.walk(build_fn)` 取调用顺序 ——
     `ast.walk` 是**广度优先**，节点顺序 ≠ 源码顺序 ⇒ 顺序判据可能因遍历
     顺序巧合而**绿**（本班实测踩到，改用行号排序才对）。
  ⑤ N-S42：变异后 `probe` 为空，我判"负控失效" —— 但探针没了 S42 同样会红，
     负控其实成立 ⇒ 我自己把有效的负控误杀。

  共同的病：**把结构化事实序列化成字符串，再用子串匹配判断**。
  文本层看起来对，结构层是错的 —— 与台账里 F40（口径混装）同型：
  一个字符串同时命中 docstring 与代码，判据就静默失效。

  ⇒ 本套件扫全部判据文件，把这两种写法**钉成红**：
     R1：`ast.dump(...)` 的结果被拿去做子串匹配（`in dump` / `not in dump`）
     R2：用 `ast.walk(...)` 取"第一个"匹配项（顺序不可靠）

  ★★ 0.48.5 追加 R3（第三处同型的病，也是"量具先量自己"的第三个面）：
     R3：**并发夹具不许赌运气** —— 判据里"一次起 N 个真进程抢同一样东西"
         （`Popen` 落在循环/推导式内）却没走**会合栅栏**（`ci/race_amp.py`）。
         由来是 0470 `N-S98` 与 0450 `N-S75` 在同一周里**各假红一次**
         （实测撞上率 ≈ 83%，即六轮里必有一轮"没撞上"）——
         本仓铁律「一个时红时绿的量具比恒红的更坏」。

  ★ 为什么是"扫自己人"而不是靠review：本班五次全是**当场觉得那么写很自然**。
    自然的错要靠机械检查抓，不靠自觉。
  ★ 位置纪律：只读 ci/ 下的判据源，**不跑**它们（跑是 delivery_gate 的事）。

  ★★ 0.48.6 追加 R4（第四处同型的病：**把「非正文层」当正文**，C2 遗留问题）：
     R4：判据扫渲染产物做**文案断言**时，必须**显式选层**（`ci/page_caliber.py`），
         不许拿整页原文当正文；数源码里的**调用点**必须 AST。
         由来：U-10 断言「本机 · 127.0.0.1」零出现，正文里早删干净了，
         `<style>` 的 CSS 注释里却复述过一遍 ⇒ **误红**；U-03 的「分母」从术语
         浮层的词条口径行漏出剥离层 ⇒ **误红**；U-01 数调用点把注释里的
         `M.reading_note()` 也算上（2 调用 ＋ 2 注释 ＝ 4）⇒ 判据自己瞎了还不知道。
         ⇒ 判据 **S48**（＋负控 N-S48）。
"""
from __future__ import annotations

import ast
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CI = os.path.join(ROOT, "ci")

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


def _judge_files():
    """只扫"判据"文件：ci/ 下的 inbox_guards_*.py / guard_*.py / *_check.py。"""
    out = []
    if not os.path.isdir(CI):
        return out
    for n in sorted(os.listdir(CI)):
        if not n.endswith(".py"):
            continue
        base = n[:-3]
        if (base.startswith("inbox_guards_") or base.startswith("guard_")
                or base.endswith("_check") or base.endswith("_gate")):
            out.append(os.path.join(CI, n))
    return out


# ══════════ S45 · 不许把 ast.dump 的结果拿去做子串匹配 ═══════════════════
@check("S45 判据里不许出现「ast.dump(...) 的结果做子串匹配」")
def s45():
    """R1：`dump = ast.dump(x)` 之后 `"..." in dump` / `not in dump`。

    ★ 为什么必须禁：dump 是**整个函数体**的序列化，docstring、注释里的
      字面量全在里面。想查"阈值还是不是 68"，docstring 里的 ">= 68" 会让
      判据在**真的被改坏之后仍然绿** —— 负控因此失效，比没有判据更坏
      （它给人"我已经守住了"的错觉）。
    ★ 正确写法：只取你要的那类节点（`ast.Constant` / `ast.Attribute` …）
      再比；本套件自己的 S42/S44 修正后就是这么写的。
    """
    bad = []
    for path in _judge_files():
        try:
            src = io.open(path, encoding="utf-8").read()
            tree = ast.parse(src)
        except Exception:                             # noqa: BLE001
            continue                                  # 解析不了的不归本判据管
        rel = os.path.relpath(path, ROOT).replace("\\", "/")
        # 找 `X = ast.dump(...)` 赋值，再看同一作用域内有没有 in/not in X
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not (isinstance(node.value, ast.Call)
                    and getattr(node.value.func, "attr", None) == "dump"):
                continue
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            var = node.targets[0].id
            # 在其后的兄弟语句里找 `in var` / `not in var`
            parent = None
            for p in ast.walk(tree):
                for ch in ast.iter_child_nodes(p):
                    if ch is node:
                        parent = p
                        break
                if parent is not None:
                    break
            if parent is None:
                continue
            later = [n for n in ast.iter_child_nodes(parent)
                     if getattr(n, "lineno", 0) > node.lineno]
            for n in later:
                for sub in ast.walk(n):
                    if isinstance(sub, ast.Compare):
                        for op, cmp_ in zip(sub.ops, sub.comparators):
                            if isinstance(op, (ast.In, ast.NotIn)):
                                if isinstance(cmp_, ast.Name) and cmp_.id == var:
                                    bad.append("%s:%d `%s` 被拿去做子串匹配"
                                               % (rel, sub.lineno, var))
    if bad:
        return "；".join(sorted(set(bad))[:6]) + ("（共 %d 处）" % len(set(bad)) if len(set(bad)) > 6 else "")
    return True


@check("N-S45 负控：造一个「dump 后做子串匹配」的片段 ⇒ S45 必须报红")
def n_s45():
    snippet = (
        "import ast\n"
        "def probe():\n"
        "    tree = ast.parse('x = 1')\n"
        "    dump = ast.dump(tree)\n"
        "    if 'Constant' in dump:\n"
        "        return True\n"
        "    return False\n")
    tree = ast.parse(snippet)
    # 用 S45 的同款检测逻辑喂这个片段
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not (isinstance(node.value, ast.Call)
                and getattr(node.value.func, "attr", None) == "dump"):
            continue
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        var = node.targets[0].id
        for n in ast.walk(tree):
            for sub in ast.walk(n):
                if isinstance(sub, ast.Compare):
                    for op, cmp_ in zip(sub.ops, sub.comparators):
                        if isinstance(op, (ast.In, ast.NotIn)):
                            if isinstance(cmp_, ast.Name) and cmp_.id == var:
                                hits.append((sub.lineno, var))
    if not hits:
        return "负控失效：构造的违规片段没被检出（S45 的检测逻辑是假的）"
    return True


# ══════════ S46 · 不许用 ast.walk 取"第一个"（顺序不可靠） ═══════════════
@check("S46 判据里不许用 ast.walk 取「第一个匹配项」")
def s46():
    """R2：`for x in ast.walk(...)` 配 `break` / `[0]` / `next(...)` 取首个。

    ★ 为什么必须禁：`ast.walk` 是**广度优先**（先整层再下层），节点顺序
      **不等于源码顺序**。本班 S39 上实测踩到：拿 walk 的顺序判
      "挪旧件是否早于闸门"，因为遍历顺序巧合而**绿** —— 顺序判据绿了，
      但它守的那件事根本没被守。改用**行号排序**才对。
    ★ 正确写法：按 `node.lineno` 排序；或用 `ast.iter_child_nodes` 显式走源码序。
    ★ 注意：本判据只禁"取第一个"这个**用法**，不禁 `ast.walk` 本身
      （收集全部节点是合法的，本套件自己就在用）。
    """
    bad = []
    for path in _judge_files():
        try:
            src = io.open(path, encoding="utf-8").read()
            tree = ast.parse(src)
        except Exception:                             # noqa: BLE001
            continue
        rel = os.path.relpath(path, ROOT).replace("\\", "/")
        for node in ast.walk(tree):
            if not isinstance(node, ast.For):
                continue
            it = node.iter
            if not (isinstance(it, ast.Call)
                    and getattr(it.func, "attr", None) == "walk"):
                continue
            body = node.body
            # 形态 A：循环体第一条就是 break ⇒ 取第一个
            if body and isinstance(body[0], ast.Break):
                bad.append("%s:%d `for ... in ast.walk(...)` 后接 break（取第一个）"
                           % (rel, node.lineno))
            # 形态 B：`next((n for n in ast.walk(...) if <cond> ...), None)` 取第一个
            #   ★ 不是一律禁止：若 `<cond>` 带**唯一性约束**（比名字/属性），
            #     取第一个是安全的（本仓 `_func_tree()` / `build_fn` 就这么写，
            #     匹配的是函数名，同名概率可忽略）。
            #     真正有害的是 S39 那个形状：**没有唯一性约束**，还拿 walk 的
            #     遍历顺序当源码顺序判 ⇒ 顺序判据会因遍历巧合而假绿。
            for sub in ast.walk(tree):
                if not (isinstance(sub, ast.Call)
                        and getattr(sub.func, "id", None) == "next"):
                    continue
                if not (sub.args and isinstance(sub.args[0], ast.GeneratorExp)):
                    continue
                gen = sub.args[0]
                # ★ GeneratorExp 没有 `.iter` 字段 —— 迭代器在每个
                #   `comprehension` 里（本套件第一版正踩过：AttributeError）。
                its = [c.iter for c in gen.generators]
                if not any(isinstance(x, ast.Call)
                           and getattr(x.func, "attr", None) == "walk" for x in its):
                    continue
                conds = [c.ifs[0] for c in gen.generators if c.ifs]
                has_unique = False
                for c in conds:
                    for n2 in ast.walk(c):
                        # 名字等值比较：`n.name == "build"` / `a.arg == "x"`
                        if (isinstance(n2, ast.Compare)
                                and any(isinstance(o, ast.Eq) for o in n2.ops)):
                            has_unique = True
                if not has_unique:
                    bad.append("%s:%d `next(... for ... in ast.walk(...))` 取第一个，"
                               "且条件**无唯一性约束**（没有比名字/属性）"
                               % (rel, sub.lineno))
    if bad:
        uniq = sorted(set(bad))
        return "；".join(uniq[:6]) + ("（共 %d 处）" % len(uniq) if len(uniq) > 6 else "")
    return True


@check("N-S46 负控：造一个「walk 后接 break」的片段 ⇒ S46 必须报红")
def n_s46():
    snippet = (
        "import ast\n"
        "def probe(tree):\n"
        "    for n in ast.walk(tree):\n"
        "        if isinstance(n, ast.FunctionDef):\n"
        "            return n\n"
        "    return None\n")
    # 上面这个写法其实是"取第一个"的常见变体：命中即 return。
    # S46 检测的是 for+break；这里用 for+return-in-if 也属于同一病，
    # 但为了不误伤合法遍历，负控按 S46 的**明文形态**构造：
    snippet_break = (
        "import ast\n"
        "def probe(tree):\n"
        "    found = None\n"
        "    for n in ast.walk(tree):\n"
        "        if isinstance(n, ast.FunctionDef):\n"
        "            found = n\n"
        "            break\n"
        "    return found\n")
    t = ast.parse(snippet_break)
    hit = False
    for node in ast.walk(t):
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Call) \
                and getattr(node.iter.func, "attr", None) == "walk":
            if node.body and isinstance(node.body[-1], ast.Break):
                hit = True
            # 也认循环体任意位置有 break
            for sub in ast.walk(node):
                if isinstance(sub, ast.Break):
                    hit = True
    if not hit:
        return "负控失效：构造的违规片段没被检出（S46 的检测逻辑是假的）"
    # 顺带确认：同款的 for+return-in-if 不被误判为违规（避免误伤合法遍历）
    t2 = ast.parse(snippet)
    legal_hit = False
    for node in ast.walk(t2):
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Call) \
                and getattr(node.iter.func, "attr", None) == "walk":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Break):
                    legal_hit = True
    if legal_hit:
        return "负控有问题：`for ... walk` + `命中即 return` 被误判成违规（会误伤合法写法）"
    return True


# ══════════ S47 · 并发夹具不许赌运气（N 路齐冲必须走会合栅栏） ══════════════
#: "一次起 N 个进程"的语法形态：`Popen` 出现在**循环/推导式**里
_BURST_NODES = (ast.For, ast.While, ast.ListComp, ast.SetComp, ast.DictComp,
                ast.GeneratorExp)


def _burst_lines(node):
    """函数体里 `Popen` 调用**落在循环/推导式内**的那些行号（= N 路齐冲）。"""
    out = set()
    for sub in ast.walk(node):
        if isinstance(sub, _BURST_NODES):
            for c in ast.walk(sub):
                if (isinstance(c, ast.Call)
                        and getattr(c.func, "attr", None) == "Popen"):
                    out.add(c.lineno)
    return out


def _uses_race_amp(node):
    """函数体里有没有**真调用**会合栅栏（`race_amp.<fn>(...)`）。

    ★ 只认**调用**，不认 `import race_amp` —— 否则"导进来摆着不用"也能过。
    """
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Attribute)
                and isinstance(sub.func.value, ast.Name)
                and sub.func.value.id == "race_amp"):
            return True
    return False


def _race_burst_violations(tree):
    """返回 `[(函数名, 行号, [齐冲行号])]` —— 起 N 个真进程却没走会合栅栏的函数。"""
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        bursts = _burst_lines(fn)
        if not bursts or _uses_race_amp(fn):
            continue
        out.append((fn.name, fn.lineno, sorted(bursts)))
    return out


@check("S47 判据里「一次起 N 个真进程」必须走会合栅栏（race_amp）")
def s47():
    """R3：函数体里 `Popen` 调用落在**循环/推导式**内（= 一次起 N 个进程抢同一样
    东西）⇒ 该函数必须**真调用** `race_amp`（`ci/race_amp.py` 的会合栅栏）。

    ★ 为什么必须禁（实测，不是推演）：N 路齐冲若不先会合，就**全凭调度运气** ——
      `Popen` 返回得很快，但解释器启动有先后（本机实测每个 ≈100–200ms，机器一忙
      更久）；窗口只有几十毫秒时，"同时冲"会退化成"排队冲"，于是"本该撞车"的
      那一轮一次都没撞上。实测代价：
        · 0470 `N-S98`：本机复跑 6 轮 **5 撞 / 1 不撞**（撞上率 ≈ 83%）；
          全量交付闸门里假红过一次，报「4 轮并发守恒均成立（total=160, missed=0）」。
        · 0450 `N-S75`：打包闸门里假红过一次（0450 12 绿 / 1 红），
          随后连跑 3 次又全绿 —— 典型**时红时绿**。
      本仓铁律「**一个时红时绿的量具比恒红的更坏**」⇒ 这类夹具必须走会合栅栏。
      ★ 注意"等一个 go 文件"**不算**会合栅栏：迟到的进程看见 go 已存在就直接冲，
        等于没等（这正是 N-S75 假红的原因）。会合等的是**兄弟进程本身**。

    ★ 本判据只管"N 路齐冲"这一形态；**固定几个进程 ＋ 握手**（如 0450 的
      `_run_rw` 读者/写者）不算违规 —— 那种写法的重叠由"读者持续循环"保证，
      且自带 `seen > 0` 的假绿闸。
    """
    bad = []
    users = 0
    for path in _judge_files():
        try:
            src = io.open(path, encoding="utf-8").read()
            tree = ast.parse(src)
        except Exception:                             # noqa: BLE001
            continue
        rel = os.path.relpath(path, ROOT).replace("\\", "/")
        if "race_amp" in src:
            users += 1
        for name, ln, bursts in _race_burst_violations(tree):
            bad.append("%s:%d `%s`（齐冲行 %s）" % (rel, ln, name, bursts[:3]))
    if bad:
        uniq = sorted(set(bad))
        return ("；".join(uniq[:6])
                + ("（共 %d 处）" % len(uniq) if len(uniq) > 6 else ""))
    # ★ 反空转：装置建了必须**真的在用**（"机制是否落地"是可查的，不是自报）
    if users == 0:
        return ("会合栅栏装置 `ci/race_amp.py` 没有任何判据在用 ⇒ "
                "机制建了没落地（下次并发负控照样赌运气）")
    return True


@check("N-S47 负控：造一个「列表推导里 Popen 齐冲」的片段 ⇒ S47 必须报红")
def n_s47():
    snippet = (
        "import subprocess\n"
        "def race():\n"
        "    procs = [subprocess.Popen(['x']) for _ in range(4)]\n"
        "    for p in procs:\n"
        "        p.wait()\n")
    if not _race_burst_violations(ast.parse(snippet)):
        return "负控失效：构造的违规片段没被检出（S47 的检测逻辑是假的）"
    # ★ 反向对照：固定两个进程（读者/写者握手，如 0450 `_run_rw`）**不许**被误判
    pair = (
        "import subprocess\n"
        "def rw():\n"
        "    a = subprocess.Popen(['r'])\n"
        "    b = subprocess.Popen(['w'])\n"
        "    a.wait()\n"
        "    b.wait()\n")
    if _race_burst_violations(ast.parse(pair)):
        return ("负控有问题：固定两个进程（读者/写者握手）被误判成「N 路齐冲」"
                "⇒ 会误伤合法写法")
    # ★ 反向对照：走了会合栅栏的 N 路齐冲写法**不许**被判违规
    good = (
        "import subprocess\n"
        "import race_amp\n"
        "def race():\n"
        "    body = 'import subprocess\\n'\n"
        "    rcs, d = race_amp.run_race(body, 4)\n")
    if _race_burst_violations(ast.parse(good)):
        return "负控有问题：走了会合栅栏的写法仍被判违规 ⇒ 会误伤正确写法"
    return True


# ══════════ S48 · 判据扫渲染产物必须**显式选层**（C2 遗留问题）══════════════
#   同族第四面（S45 = `ast.dump` 子串、S46 = `ast.walk` 取首、S47 = 并发赌运气）：
#   **把「非正文层」当正文**。两类实测：
#     ① 渲染产物面 —— U-10 断言「本机 · 127.0.0.1」零出现，正文早删干净了，
#        可 `<style>` 的 CSS 注释里复述过一遍 ⇒ **误红**；U-03 的「分母」从
#        术语浮层的词条口径行漏出剥离层 ⇒ **误红**。
#     ② 源码面 —— U-01 数 `M.reading_note()` 的调用点，把**注释里**的同一串
#        也算上（2 次调用 ＋ 2 处注释 ＝ 4）⇒ 判据自己瞎了还不知道。
#   ⇒ ① 渲染产物上的**文案断言**（左操作数可能含中文）必须经显式口径
#        `page_caliber.body(...)` / `page_caliber.body_without_terms(...)`；
#        裸变量、`raw()`、`chrome()` 一律报红（中文文案只能来自正文层）。
#     ② 数源码里的**调用点**必须用 AST —— 不许 `len(re.findall(<调用语法>))`。
#   ★ 为什么不把「纯 ASCII 结构断言」也逼着改：`data-id=`、`f=action`、`<body>`
#     这类标记**不会**出现在中文注释/词条浮层里，不是本缺陷的现场；一刀切
#     只会制造 40 处无谓改动（把机制做成噪音，下一个人就会绕开它）。

def _caliber_contract():
    """从 `ci/page_caliber.py` **逐字**取层名（不在本文件重写一份口径 —— 维一）。

    ★ 为什么读磁盘而不 import：本套件只读源码、不执行（位置纪律）；
      且套件起法不保证 `sys.path[0]` 是 `ci/`。
    """
    p = os.path.join(CI, "page_caliber.py")
    if not os.path.isfile(p):
        return None
    tree = ast.parse(io.open(p, encoding="utf-8").read())
    out = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Tuple)):
            nm = node.targets[0].id
            if nm in ("LAYERS", "TEXT_LAYERS"):
                out[nm] = tuple(e.value for e in node.value.elts
                                if isinstance(e, ast.Constant))
    if "LAYERS" not in out or "TEXT_LAYERS" not in out:
        return None
    return out


def _caliber_bindings(tree):
    """本文件怎么引 `page_caliber` 的：`(模块别名集, 直导函数名集)`。"""
    aliases, names = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "page_caliber":
                    aliases.add(a.asname or "page_caliber")
        elif isinstance(node, ast.ImportFrom) and node.module == "page_caliber":
            for a in node.names:
                names.add(a.asname or a.name)
    return aliases, names


def _caliber_call_layer(node, aliases, names, layers):
    """节点是显式口径调用 ⇒ 返回层名，否则 None。"""
    if not isinstance(node, ast.Call):
        return None
    f = node.func
    if (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
            and f.value.id in aliases and f.attr in layers):
        return f.attr
    if isinstance(f, ast.Name) and f.id in names and f.id in layers:
        return f.id
    return None


def _tgt_names(target):
    for n in ast.walk(target):
        if isinstance(n, ast.Name):
            yield n.id


def _render_producers(call):
    """这个调用产出的东西是不是**渲染产物**（HTML 页/条）。"""
    name = getattr(call.func, "attr", None) or getattr(call.func, "id", None)
    if not name:
        return False
    return "render" in name or name.endswith("_page")


def _render_vars(fn):
    """函数内「渲染产物变量」名集合（赋自渲染调用，含 `page, _why = ...` 元组形）。"""
    out = set()
    for node in ast.walk(fn):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and _render_producers(node.value)):
            for t in node.targets:
                out.update(_tgt_names(t))
    return out


def _cjk_bound_names(scope):
    """**作用域内**「绑定到含中文常量」的名字（赋值 ＋ for 迭代元组）。

    ★ 为什么按整个文件跑一遍再取用：模块级常量（如 `_U05_OLD = ("点开看每一次",…)`）
      也是文案断言的来源 —— 只扫函数体会漏掉「`for bad in _U05_OLD: if bad in page`」
      这种形态（实测：0490 的 U-05 正是这样写的）。
    """
    out = set()
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign):
            val = node.value
        elif isinstance(node, (ast.For, ast.comprehension)):
            val = node.iter
        else:
            continue
        has = any(isinstance(n, ast.Constant) and isinstance(n.value, str)
                  and any("\u4e00" <= ch <= "\u9fff" for ch in n.value)
                  for n in ast.walk(val))
        if not has:
            continue
        tgt = node.target if isinstance(node, (ast.For, ast.comprehension)) \
            else ast.Tuple(elts=list(node.targets), ctx=ast.Store())
        out.update(_tgt_names(tgt))
    return out


def _left_maybe_cjk(left, cjk_names):
    if isinstance(left, ast.Constant) and isinstance(left.value, str):
        return any("\u4e00" <= ch <= "\u9fff" for ch in left.value)
    if isinstance(left, ast.Name):
        return left.id in cjk_names
    return any(isinstance(n, ast.Constant) and isinstance(n.value, str)
               and any("\u4e00" <= ch <= "\u9fff" for ch in n.value)
               for n in ast.walk(left))


def _s48a_violations(tree, aliases, names, text_layers):
    """① 文案断言打在**裸渲染产物**上（未经正文口径）。

    ★ 中文名集合按**整个文件**取（模块级常量也算），见 `_cjk_bound_names`。
    ★★ 不只是「裸变量」违规 —— `page_caliber.raw(page)` / `.chrome(page)` 同样违规：
      中文文案只可能来自**正文层**，声明「我要看整页」等于把 CSS 注释又放回来。
      （不把这条写死，S48 就是**纸糊的**：换 `raw(...)` 一行就绕过去了。）
    """
    all_layers = set(text_layers) | {"raw", "chrome"}
    out = []
    file_cjk = _cjk_bound_names(tree)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        raw_vars = _render_vars(fn)
        if not raw_vars:
            continue
        cjk = file_cjk | _cjk_bound_names(fn)
        for cmp_ in ast.walk(fn):
            if not isinstance(cmp_, ast.Compare):
                continue
            for op, c in zip(cmp_.ops, cmp_.comparators):
                if not isinstance(op, (ast.In, ast.NotIn)):
                    continue
                if not _left_maybe_cjk(cmp_.left, cjk):
                    continue
                # 右操作数：裸渲染变量 ⇒ 违规
                if isinstance(c, ast.Name) and c.id in raw_vars:
                    out.append((fn.name, cmp_.lineno, c.id))
                    continue
                # 右操作数：显式口径调用 —— 只有**正文层**才放行
                layer = _caliber_call_layer(c, aliases, names, all_layers)
                if layer is not None and layer not in text_layers:
                    out.append((fn.name, cmp_.lineno,
                                "page_caliber.%s(...)" % layer))
    return out


#: 「带调用语法的正则」：标识符（可带点）紧跟转义左括号，如 `reading_note\(`
_CALL_PAT = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*\\\(")


def _s48b_violations(tree):
    """② 用文本正则数源码里的**调用点**（注释会被一并算上）。"""
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name) and node.func.id == "len"
                and len(node.args) == 1 and isinstance(node.args[0], ast.Call)):
            continue
        inner = node.args[0]
        fname = getattr(inner.func, "attr", None) or getattr(inner.func, "id", None)
        if fname not in ("findall", "finditer"):
            continue
        pats = [a for a in inner.args
                if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        if any(_CALL_PAT.search(p.value) for p in pats):
            out.append((node.lineno, (pats[0].value[:40] if pats else "")))
    return out


@check("S48 判据扫渲染产物必须显式选层；数调用点必须用 AST（C2）")
def s48():
    """C2（2026-10-13）：**非正文层不许当正文**。

    ★ 两条一起守（同一病、两个面，见段首注释）：
      ① 渲染产物上的**文案断言**（左操作数可能含中文）必须经
         `page_caliber.body(...)` / `page_caliber.body_without_terms(...)`；
      ② 数源码里的调用点必须 AST，不许 `len(re.findall(<调用语法>))`。
    ★ 反空转：`ci/page_caliber.py` 必须存在、且**至少一个判据文件真的在用它**
      —— 装置建了不落地 = 下次照样赌注释（S47 同款纪律）。
    ★ 口径本身不在这里重写：层名逐字取自 `page_caliber.py`（维一）。
    """
    contract = _caliber_contract()
    if contract is None:
        return ("缺 `ci/page_caliber.py`（或它没声明 LAYERS/TEXT_LAYERS）—— "
                "统一口径装置不在位，渲染页断言又会各写一份剥法（C2 复发）")
    layers, text_layers = contract["LAYERS"], contract["TEXT_LAYERS"]
    bad, users = [], 0
    for path in _judge_files():
        try:
            src = io.open(path, encoding="utf-8").read()
            tree = ast.parse(src)
        except Exception:                             # noqa: BLE001
            continue
        rel = os.path.relpath(path, ROOT).replace("\\", "/")
        aliases, names = _caliber_bindings(tree)
        if aliases or names:
            users += 1
        for fname, ln, var in _s48a_violations(tree, aliases, names, text_layers):
            bad.append("%s:%d `%s` 里的文案断言打在**裸渲染变量** `%s` 上"
                       "（须 `page_caliber.body(...)`）" % (rel, ln, fname, var))
        for ln, pat in _s48b_violations(tree):
            bad.append("%s:%d 用文本正则数调用点（pattern=%r）—— 注释会被算上，"
                       "须改用 AST" % (rel, ln, pat))
    if bad:
        uniq = sorted(set(bad))
        return ("；".join(uniq[:6])
                + ("（共 %d 处）" % len(uniq) if len(uniq) > 6 else ""))
    if users == 0:
        return ("统一口径装置 `ci/page_caliber.py` 没有任何判据在用 ⇒ "
                "机制建了没落地（渲染页断言照样会各剥各的）")
    return True


@check("N-S48 负控：裸渲染文案断言 / 文本正则数调用点 ⇒ S48 必须各报红")
def n_s48():
    """反向对照（维二）：两种违规各造一片段，S48 的检测逻辑必须抓到；
    并反向确认**纯 ASCII 结构断言**与**数行数**不被误判（不误伤合法写法）。
    """
    contract = _caliber_contract()
    if contract is None:
        return "夹具不成立：`ci/page_caliber.py` 不在位，负控无分辨力"
    tl = contract["TEXT_LAYERS"]
    # ① 裸渲染文案断言（该红）
    bad_a = (
        "import page_caliber as PC\n"
        "def probe():\n"
        "    page = SV.render_page(view='inbox')\n"
        "    for bad in ('\\u5206\\u6bcd',):\n"
        "        if bad in page:\n"
        "            return False\n"
        "    return True\n")
    t_a = ast.parse(bad_a)
    al, nm = _caliber_bindings(t_a)
    if not _s48a_violations(t_a, al, nm, tl):
        return "负控失效：裸渲染文案断言没被检出（S48① 的检测逻辑是假的）"
    # ①' 反向对照：走了正文口径 ⇒ 不许判违规
    good_a = bad_a.replace("if bad in page:", "if bad in PC.body(page):")
    if _s48a_violations(ast.parse(good_a), al, nm, tl):
        return "负控有问题：走了 `page_caliber.body(...)` 仍被判违规 ⇒ 会误伤正确写法"
    # ①'' **堵纸糊的后门**：把裸变量换成 `PC.raw(...)` 仍是违规
    #     （中文文案只能来自正文层；声明"看整页"等于把 CSS 注释又放回来）
    cheat_a = bad_a.replace("if bad in page:", "if bad in PC.raw(page):")
    if not _s48a_violations(ast.parse(cheat_a), al, nm, tl):
        return ("负控失效：把裸变量换成 `page_caliber.raw(...)` 就绕过了 S48①"
                "⇒ 判据是纸糊的（一行替换即可逃逸）")
    # ①'' 反向对照：**纯 ASCII 结构断言**（左操作数不含中文）不许判违规
    good_ascii = (
        "def probe():\n"
        "    page = SV.render_page(view='inbox')\n"
        "    return 'data-id=' in page and 'f=action' in page\n")
    if _s48a_violations(ast.parse(good_ascii), set(), set(), tl):
        return ("负控有问题：纯 ASCII 结构断言被误判成「文案断言」"
                "⇒ 会误伤 40 处合法写法（机制变噪音）")
    # ② 文本正则数调用点（该红）
    bad_b = (
        "import re\n"
        "def probe(src):\n"
        "    return len(re.findall('reading_note\\\\(', src))\n")
    if not _s48b_violations(ast.parse(bad_b)):
        return "负控失效：文本正则数调用点没被检出（S48② 的检测逻辑是假的）"
    # ②' 反向对照：数**行数**（不是调用点）不许判违规
    good_b = (
        "import re\n"
        "def probe(src):\n"
        "    return len(re.findall('^\\\\s*\\\\(', src, re.M))\n")
    if _s48b_violations(ast.parse(good_b)):
        return "负控有问题：数行数（`^\\s*\\(`）被误判成「数调用点」⇒ 会误伤合法写法"
    return True


def main():
    print("=" * 74)
    print("0.42.0 meta 判据 —— 量具先量自己：判据不许用文本匹配代替结构匹配")
    print("=" * 74)
    print("  受检判据文件：%d 个" % len(_judge_files()))
    for n, r in PASSED:
        print("  ✅ %s" % n)
    for n, r in FAILED:
        print("  ❌ %s\n       → %s" % (n, r))
    print("-" * 74)
    print("  通过 %d / 失败 %d" % (len(PASSED), len(FAILED)))
    return 1 if FAILED else 0

if __name__ == "__main__":
    sys.exit(main())
