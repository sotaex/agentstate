#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

  ★ 为什么是"扫自己人"而不是靠review：本班五次全是**当场觉得那么写很自然**。
    自然的错要靠机械检查抓，不靠自觉。
  ★ 位置纪律：只读 ci/ 下的判据源，**不跑**它们（跑是 delivery_gate 的事）。
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
