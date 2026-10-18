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

  ★★ 0.51.0 追加 R5（第五个面：**判据定义了却没登记**，死判据＝没判据）：
     R5：`def c_xxx` / `def n_xxx` 必须出现在**登记表**里（顶层 `CHECKS* = [(str, fn, …)]`、
         `RESULTS.append(...)`、`@check` 装饰器自动登记、或 `@check("…", "n_xxx")`
         的字符串形式）。只定义不登记 ⇒ **从未执行**，它守的那条语义整批改掉也不翻红。
         由来：2026-10-17 做账本明细时实测 —— `c_ledger_page_populates_from_chain_snapshot`
         只定义没登记，账本落盘语义整批重写它都不吭声；同批还揪出
         `c_ledger_levels_match_meaning` 与它的负控同样是死的。
     ★ 判"登记"的口径很容易错，本判据自己踩了两次（写进负控里当标本）：
         ① 拿「名字在全文被引用过」当登记 ⇒ 主判据被自己那条死负控调用
            （`return not c_xxx()`）就算"活的" —— **假阴性**；
         ② 漏了 `@check("…", "n_xxx")` 这一种字符串登记形态 ⇒ 0366 三条被误报 —— **假阳性**。
         ⇒ 必须是「名字出现在登记表字面量/装饰器参数里」。
         ⇒ 判据 **S54**（＋负控 N-S54）。

  ★★ 0.51.2 追加 R6（第六个面：**文案与结构脱钩**，事后判据守不住全站）：
     R6：页面渲染函数（`_view_*`）里，**指向性数量词**（下列/以下/这 N 个·数·项…）
        不许是字符串**字面量**，必须带格式化占位符（即**派生**自结构）；
        同一渲染函数内不许并存两份计数来源（唯一实现）。
        由来：2026-10-17 账本页三问 —— 「下列四个数」硬编码、四张卡手写 4 组
        `%s`，两者**无引用关系** ⇒ 改卡片数忘改文案是**必然**；头部取旧快照、
        明细取链现算 ⇒ 同页「11 天 vs 8 天」打架。
     ★ 为什么不能只靠事后判据：0490 的 T-04d 只能守**账本页**这一个点，
        日报页同样 4 张卡 + 口径文案却没有对应判据。**要从源头取消这种不一致
        的可能，只能卡「数量词是不是派生的」这个结构**。
     ★ 试过做「全站通用正则判据」，**此路不通**（实测连翻三次车）：
        ① 把 `<style>` 里 CSS 注释与术语悬停当正文 ⇒ 满屏假阳性；
        ② 单位表漏了「数」⇒ 正好漏掉本批那个形态「下列四个**数**」；
        ③ 剥术语层的正则贪心（`.*?</span>` 跨区）⇒ 把整段正文吃掉。
        另有**本质性假阳性**：页面有「以下 N 项」这类合法数量词，
        判断它指向哪个结构需要 DOM 位置关系 —— 正则做不到。
        ⇒ 故只做**AST 结构判据**（窄而准），不做文本正则。
         ⇒ 判据 **S55**（＋负控 N-S55）。

  ★★ 0.53.0 追加 R7（第七个面：**设计要求没人承接**，2026-10-18）：
     R7：设计文件里每个一级章号（`## N.`）必须在 `docs/设计条款-判据映射.json`
         里有登记；`guarded` 的 `guarded_by` 必须指向**真实存在**的判据 id；
         `quote` 必须**逐字落在该章正文里**；`uncovered` 必须写 why／next。
         由来：创始人 2026-10-18 两问 —— 账本出现「防护缺口／缺口」、
         「要求指明哪个 AI 编程工具但看不到」。查下去是同一个病：
         **§6 要求「工具名」、§4.4-1 枚举里却没有「点名」这一项**，两份要求
         分散在不同章节；实现只跟了 §4.4，判据 U22 也只跟了 §4.4 ⇒
         一个专答「是哪个工具」的块，没有任何一条尺子检查工具名。
         人读漏一节，机器不提醒 —— 这就是「下一次没人读到的那一章」。
     ★ 为什么不是「再写一条 assert」：那只能抓住已经知道的那一次。
         本尺子守的是**覆盖关系**本身：新增条款不登记 ⇒ 红；登记了却指向
         不存在的判据 ⇒ 红；`quote` 拼错或搬到别的章 ⇒ 红。
     ★ 允许 `record`／`uncovered` 两类，但都不许沉默：前者必须写 why，
         后者必须写 why ＋ next，且 `record` 条数受 `record_cap` 约束 ——
         防「把每一章都标成记录」这条逃逸路线。
         ⇒ 判据 **S57**（＋负控 N-S57）。
"""
from __future__ import annotations

import ast
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CI = os.path.join(ROOT, "ci")

PASSED = []
FAILED = []


def _note(msg):
    """说明行（不是判据）：跑的时候看得见，方便人复核本条到底量了什么。"""
    print("  · %s" % msg)


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


# ══════════ S47-selfaudit · 并发夹具不许赌运气（N 路齐冲必须走会合栅栏） ══════════════
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


@check("S47-selfaudit 判据里「一次起 N 个真进程」必须走会合栅栏（race_amp）")
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


@check("N-S47-selfaudit 负控：造一个「列表推导里 Popen 齐冲」的片段 ⇒ S47-selfaudit 必须报红")
def n_s47():
    snippet = (
        "import subprocess\n"
        "def race():\n"
        "    procs = [subprocess.Popen(['x']) for _ in range(4)]\n"
        "    for p in procs:\n"
        "        p.wait()\n")
    if not _race_burst_violations(ast.parse(snippet)):
        return "负控失效：构造的违规片段没被检出（S47-selfaudit 的检测逻辑是假的）"
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
#   同族第四面（S45 = `ast.dump` 子串、S46 = `ast.walk` 取首、S47-selfaudit = 并发赌运气）：
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
      —— 装置建了不落地 = 下次照样赌注释（S47-selfaudit 同款纪律）。
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


# ══════════ S54 · 死判据：定义了必须进登记表 ═══════════════════


def _registry_names(tree):
    """「登记表」里的名字集合。登记形态共四种，漏任何一种都会误报：

      ① 顶层 `CHECKS* = [("名字", c_xxx, n_xxx), ...]`（元素 tuple 且首元素是字符串）
      ② `RESULTS.append((...))`
      ③ `@check("名字")` 装饰器 ⇒ 自动登记（不看名字，见 `_is_autoreg`）
      ④ `@check("名字", "n_xxx")` —— 负控以**字符串**传名（那时函数还没定义，
         0366 就是这么写的；它的 `main()` 会 `globals().get(neg)` 解析并执行）

    ★ 为什么不能拿「名字在全文被引用过」当登记（本判据自己踩的坑）：
      主判据被自己那条**死负控**调用（`return not c_xxx()`）也算"被引用"
      ⇒ 两条一起死，旧口径却只报负控一条（**假阴性**）。
    """
    names = set()

    def _collect(node):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name):
                names.add(sub.id)
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                names.add(sub.value)
                for tok in re.split(r"[\s\"'（）()，,]+", sub.value):
                    if tok:
                        names.add(tok)

    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, (ast.List, ast.Tuple)):
            elts = node.value.elts
            if elts and isinstance(elts[0], ast.Tuple) and elts[0].elts:
                first = elts[0].elts[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    _collect(node.value)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in ("append", "extend"):
                _collect(node)
            elif isinstance(f, ast.Name) and f.id == "check":      # ④ 字符串传名
                for a in node.args:
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        _collect(a)
    return names


def _is_autoreg(node):
    for d in node.decorator_list:
        nm = None
        if isinstance(d, ast.Name):
            nm = d.id
        elif isinstance(d, ast.Call) and isinstance(d.func, ast.Name):
            nm = d.func.id
        if nm == "check":
            return True
    return False


def _dead_check_names(tree):
    """[(lineno, name)] —— 定义了、却没进任何登记表的判据族函数。"""
    reg = _registry_names(tree)
    dead = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        nm = node.name
        if not (nm.startswith("c_") or nm.startswith("n_")):
            continue
        if _is_autoreg(node):
            continue
        if nm not in reg:
            dead.append((node.lineno, nm))
    return dead


@check("S54 判据定义了必须进登记表（死判据＝没判据）")
def s54():
    """R5：只定义不登记的判据**从未执行** —— 它守的那条语义整批改掉也不翻红。

    实测由来（2026-10-17 账本明细批）：`c_ledger_page_populates_from_chain_snapshot`
    只定义没登记 ⇒ 账本落盘语义整批重写，它一声不吭；同批还揪出
    `c_ledger_levels_match_meaning` 与它的负控同样是死的（主判据被死负控调用，
    按"被引用过"判断的旧口径扫不出来）。
    """
    bad = []
    scanned = 0
    for path in _judge_files():
        try:
            tree = ast.parse(io.open(path, encoding="utf-8").read())
        except (SyntaxError, UnicodeDecodeError) as e:
            bad.append("%s 解析失败：%r" % (os.path.basename(path), e))
            continue
        scanned += 1
        for lineno, nm in _dead_check_names(tree):
            bad.append("%s:%d `%s` 只定义没登记 ⇒ 从未执行"
                       % (os.path.basename(path), lineno, nm))
    if bad:
        uniq = sorted(set(bad))
        return ("；".join(uniq[:6])
                + ("（共 %d 处）" % len(uniq) if len(uniq) > 6 else ""))
    if scanned == 0:
        return "一个判据文件都没扫到 ⇒ 本判据判不出（判不出不许算通过）"
    return True


@check("N-S54 负控：真死判据必须报红；四种合法登记形态不许误报")
def n_s54():
    """反向对照（维二）：S54 最容易在**两个方向**上失手，各造标本钉住。

      方向一（漏报）：主判据被自己那条死负控调用 ⇒ 不许当活的（本仓真踩过）。
      方向二（误报）：四种合法登记形态 ⇒ 一律不许报（本仓真踩过 0366 那次）。
    """
    # ① 纯死判据：def 了，既没 @check 也没进表 ⇒ 必须被抓
    if not _dead_check_names(ast.parse(
            "def c_thing_is_true():\n    return True\n"
            "def n_thing_is_true():\n    return not c_thing_is_true()\n")):
        return "负控失效：纯死判据没被检出（S54 的检测逻辑是假的）"
    # ①' 更隐蔽的那种：主判据被自己那条**死负控**调用 ⇒ 两条都得报
    got = {nm for _, nm in _dead_check_names(ast.parse(
        "def c_thing():\n    return True\n"
        "def n_thing():\n    return not c_thing()\n"))}
    if got != {"c_thing", "n_thing"}:
        return ("负控失效：主判据被死负控调用就被当成活的（实得 %r）⇒ 假阴性还在"
                % sorted(got))
    # ② 四种合法登记形态 ⇒ 一律不许报（踩过：0366 的字符串形态被误报过一次）
    good = [
        ("CHECKS 表",
         "CHECKS = [\n    (\"名\", c_thing, n_thing),\n]\n"
         "def c_thing():\n    return True\n"
         "def n_thing():\n    return True\n"),
        ("@check 自动登记",
         "@check(\"名\")\ndef c_thing():\n    return True\n"),
        ("@check 字符串负控",
         "@check(\"名\", \"n_thing\")\ndef c_thing():\n    return True\n"
         "def n_thing():\n    return True\n"),
        ("RESULTS.append",
         "RESULTS.append((\"名\", c_thing, n_thing))\n"
         "def c_thing():\n    return True\n"
         "def n_thing():\n    return True\n"),
    ]
    for label, src in good:
        got = {nm for _, nm in _dead_check_names(ast.parse(src))}
        if got:
            return ("负控有问题：合法的「%s」形态被误报成死判据 %r ⇒ 会误伤正确写法"
                    % (label, sorted(got)))
    return True


# ══════════ S55 · 页面文案与结构一致：数量词必须**派生** ════════════════
#
# ★★ 为什么这是机制层（创始人 2026-10-17「这个能上升到机制层就好了」）：
#   账本页三问之一的真正成因不是「忘改文案」，而是**结构**——
#   「下列四个数」是字符串**字面量**、四张卡是**手写 4 组 `%s`**，
#   两者没有任何引用关系 ⇒ 改了卡片数而文案不跟，是**必然**而非疏忽。
#   事后判据（0490 T-04d）只能守账本页这一个点；要**全站**防住，
#   必须卡「数量词是不是从结构派生出来的」这个结构本身。
#
# 两条断言（扫所有定义了 `_view_*` 的顶层模块）：
#   ① 渲染函数里不许有**字面量形式的指向性数量词**
#      （下列/以下/这 N 个·数·项·条·张·类）—— 必须带格式化占位符。
#   ② 同一渲染函数内不许并存**两份**计数来源（唯一实现）——
#      三问之三（头部「11 天」vs 月行「8 天」）就是两份来源并存。
#
# 实测边界（写进负控，本仓真踩过）：
#   · 只认**字符串常量节点**（`ast.Constant`）⇒ 注释/docstring 里的同名字样
#     自动排除（本仓注释里就写着「下列四个数」在讲这段历史）；
#   · **误报标本**：`inbox_server.py:726`「以下 %d 项」是**派生**写法，
#     不许报（数量词带 `%d`）；范围限定在 `_view_*` 内，
#     叙述性文字（如「装着 37 条规则」）本就不在里面。

_PAGE_FN_PREFIX = "_view_"
_COUNT_WORD_RE = re.compile(
    r"(下列|以下|以上|这|那)\s*[0-9一二三四五六七八九十]{1,3}\s*"
    r"(个|数|项|条|张|类|种|块|栏)")
_COUNT_SRCS = ("day_counts", "load_days", "summary")


def _page_files():
    """顶层模块里**定义了 `_view_*` 渲染函数**的文件（页面文案的产地）。"""
    out = []
    if not os.path.isdir(ROOT):
        return out
    for n in sorted(os.listdir(ROOT)):
        if not n.endswith(".py"):
            continue
        p = os.path.join(ROOT, n)
        try:
            tree = ast.parse(io.open(p, encoding="utf-8").read())
        except Exception:                              # noqa: BLE001
            continue
        if any(isinstance(x, ast.FunctionDef) and x.name.startswith(_PAGE_FN_PREFIX)
               for x in ast.walk(tree)):
            out.append((p, tree))
    return out


def _renderer_defs(tree):
    return {n.name: n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name.startswith(_PAGE_FN_PREFIX)}


def _literal_count_words(fn):
    """函数内**字面量形式**的指向性数量词 ⇒ [(行号, 片段)]。"""
    out = []
    for sub in ast.walk(fn):
        if not isinstance(sub, ast.Constant) or not isinstance(sub.value, str):
            continue
        m = _COUNT_WORD_RE.search(sub.value)
        if m and "%" not in sub.value and "{" not in sub.value:
            out.append((sub.lineno, m.group(0)))
    return out


def _called_names(fn):
    names = set()
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Attribute):
                names.add(f.attr)
            elif isinstance(f, ast.Name):
                names.add(f.id)
    return names


@check("S55 页面渲染函数：数量词必须派生；同页计数来源须唯一")
def s55():
    """R6：数量词与结构脱钩是**必然出错**的结构，靠事后检查守不住全站。

    实测由来（2026-10-17 账本页三问）：「下列四个数」硬编码 + 四张卡手写
    ⇒ 卡片增删文案不跟；头部取旧快照、明细取链现算 ⇒ 同页两个口径。
    """
    files = _page_files()
    if not files:
        return "一个页面渲染文件都没扫到 ⇒ 本判据判不出（判不出不许算通过）"
    bad = []
    for path, tree in files:
        rel = os.path.relpath(path, ROOT).replace("\\", "/")
        for name, fn in sorted(_renderer_defs(tree).items()):
            for lineno, frag in _literal_count_words(fn):
                bad.append("%s %s:%d 「%s」是字面量 ⇒ 数量词没派生"
                           "（改结构时文案不会跟）" % (rel, name, lineno, frag))
            hits = _called_names(fn) & set(_COUNT_SRCS)
            if len(hits) >= 2:
                bad.append("%s %s 同时用了 %s ⇒ 同页可能两个计数口径"
                           % (rel, name, "/".join(sorted(hits))))
    if bad:
        return "；".join(sorted(set(bad))[:6])
    return True


@check("N-S55 负控：字面量数量词要报红；派生写法/注释字样/双来源都要能分辨")
def n_s55():
    """反向对照：两个方向各造标本（本仓 2026-10-17 真踩过前两个坑）。

      方向一（漏报）：字面量「下列四个数」⇒ 必须抓。
      方向二（误报）：派生写法（带 `%s`）、注释里的同名字样 ⇒ 不许抓。
      方向三（漏报）：同函数并存两份计数来源 ⇒ 必须抓。
    """
    # ① 字面量 ⇒ 必须报
    fn = _renderer_defs(ast.parse(
        "def _view_x():\n    return '<p>下列四个数只数今天</p>'\n"))["_view_x"]
    if not _literal_count_words(fn):
        return "负控失效：字面量「下列四个数」没被检出（S55 的检测逻辑是假的）"
    # ② 派生写法 ⇒ 不许报（本仓 inbox_server.py:726「以下 %d 项」是这个形态）
    fn = _renderer_defs(ast.parse(
        "def _view_x(n):\n    return '<p>下列%s个数只数今天</p>' % n\n"))["_view_x"]
    if _literal_count_words(fn):
        return "负控有问题：派生写法（带 %%s）被误报 ⇒ 会误伤正确写法"
    # ②' 注释里的同名汉字 ⇒ 不许报（只认字符串常量这条必须真生效）
    fn = _renderer_defs(ast.parse(
        "def _view_x():\n    # 历史上写过「下列四个数」，现已改为派生\n    return ''\n"
    ))["_view_x"]
    if _literal_count_words(fn):
        return "负控有问题：注释里的字样被误报 ⇒ 「只认字符串常量」没生效"
    # ③ 双来源 ⇒ 必须报
    fn = _renderer_defs(ast.parse(
        "def _view_x():\n    a = M.day_counts(x)\n    b = L.load_days(y)\n    return a\n"
    ))["_view_x"]
    if len(_called_names(fn) & set(_COUNT_SRCS)) < 2:
        return "负控失效：同函数并存两份计数来源没被检出"
    return True


# ══════════ S57 · 设计要求→判据映射：覆盖自审 ═════════════════════════

#: 映射表（设计要求 → 判据）。**它是账，不是尺子**：尺子是下面的 S57。
_MAP_REL = "docs/设计条款-判据映射.json"

#: 设计文件族前缀。族内版本号取最大值 —— 升版而映射表没跟，S57 就红。
_DESIGN_FAMILY = "Antinel·监理五页信息架构与工具归因方案 v"


def _squash(s):
    """去掉全部空白 —— 跨行引文与折行表格都能逐字比对（markdown 会折行）。"""
    return "".join(str(s or "").split())


def _design_chapters(text):
    """`[{"num": "4", "body": <本章归一文本，含标题行>}]` —— 章号从文件**派生**。

    ★ 为什么派生而不在映射表里列一份章号清单：清单会跟丢。设计文件新增一章，
      清单不会自己长；派生之后「新增一章没登记」当场红 —— 这正是本判据要守的。
    """
    out, cur, buf = [], None, []
    for line in text.splitlines():
        if line.startswith("## "):
            head = line[3:].strip()
            digits = ""
            for ch in head:
                if ch.isdigit():
                    digits += ch
                else:
                    break
            if digits:
                if cur is not None:
                    out.append({"num": cur, "body": _squash("\n".join(buf))})
                cur, buf = digits, [line]
                continue
        if cur is not None:
            buf.append(line)
    if cur is not None:
        out.append({"num": cur, "body": _squash("\n".join(buf))})
    return out


#: 判据 id 允许的字符（`U22`／`T-04e`／`W-SPK13`／`G1-granary`／`N-U22c` 都是真 id）
_ID_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-")


def _looks_like_id(tok):
    # 长度下限取 2：体检族真有 `H3`／`H7`／`H8`／`H9` 这种两字符 id（首版写 3，
    # 结果把四条真判据判成「不存在」—— 尺子自己先瞎了一次，记在这里）。
    if not (2 <= len(tok) <= 14):
        return False
    if tok[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        return False
    if not any(c.isdigit() for c in tok):
        return False
    return all(c in _ID_CHARS for c in tok)


def _judge_titles():
    """`{判据 id: [来源文件]}` —— 从判据源码 AST 里取**登记形态**的标题首词。

    ★ 为什么不复用 `defect_types._declared_ids()`：那支的 id 正则是给**登记簿**
      用的（归一化口径），实测把 `T-04e` 归一成 `T-04`、把 `W-SPK13` 整条丢掉
      （本轮实测清单：T-04e／W-SPK13／UID15-a／HSCAN15-a／H4b／N-U22c 全 MISS）。
      拿它验覆盖会逼人写**错的** id，或把真判据判成不存在 —— 两向都是假话。
      这里要的只是「这个 id 真的有一条判据」，故取标题首词原样。
    """
    out = {}
    for path in _judge_files():
        try:
            tree = ast.parse(io.open(path, encoding="utf-8").read())
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        rel = os.path.relpath(path, ROOT).replace("\\", "/")
        for node in ast.walk(tree):
            texts = []
            if isinstance(node, ast.FunctionDef):
                for d in node.decorator_list:
                    if (isinstance(d, ast.Call) and d.args
                            and isinstance(d.args[0], ast.Constant)
                            and isinstance(d.args[0].value, str)):
                        texts.append(d.args[0].value)
            elif isinstance(node, ast.Tuple) and len(node.elts) >= 2:
                first = node.elts[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    texts.append(first.value)
            for text in texts:
                parts = text.strip().split()
                if not parts:
                    continue
                tok = parts[0]
                if _looks_like_id(tok):
                    out.setdefault(tok, [])
                    if rel not in out[tok]:
                        out[tok].append(rel)
    return out


def _doc_version(name):
    """文件名里的 `vN.M` → `(N, M)`；取不到就是 `(0, 0)`。"""
    tail = name[len(_DESIGN_FAMILY):] if name.startswith(_DESIGN_FAMILY) else ""
    digits, minor, stage = "", "", 0
    for ch in tail:
        if ch.isdigit() and stage == 0:
            digits += ch
        elif ch == "." and stage == 0:
            stage = 1
        elif ch.isdigit() and stage == 1:
            minor += ch
        elif stage == 1:
            break
    if not digits:
        return (0, 0)
    return (int(digits), int(minor or 0))


def _map_problems(doc_text, table, known_ids, doc_names):
    """尺子：把「设计文件 × 映射表 × 真判据清单」三样对上。纯函数，不读盘。

    ★ 纯函数是**为负控**：负控可以喂任意表/任意文件头，不写任何产品文件
      （零写脏纪律）。所有分支都可被负控直接撞到。
    """
    chapters = _design_chapters(doc_text)
    if not chapters:
        return "设计文件里一个「## N.」章都没解析出来 ⇒ 判不出（判不出不许算通过）"
    bodies = {c["num"]: c["body"] for c in chapters}
    entries = table.get("entries") or []
    if not entries:
        return "映射表 entries 为空 —— 空表也能全绿的话，这条尺子就是摆设"
    problems, seen = [], set()
    for e in entries:
        clause = str(e.get("clause") or "")
        if not clause.startswith("§"):
            problems.append("clause %r 不是 § 开头" % clause)
            continue
        top = clause[1:].split(".")[0]
        if top not in bodies:
            problems.append("%s 在设计文件里不存在（防幻觉条款号）" % clause)
            continue
        if clause in seen:
            problems.append("%s 重复登记" % clause)
        seen.add(clause)
        kind = e.get("kind")
        if kind not in ("guarded", "uncovered", "record"):
            problems.append("%s kind=%r 不认识" % (clause, kind))
            continue
        if kind == "record":
            if not str(e.get("why") or "").strip():
                problems.append("%s 标了 record 却没写 why（不许无理由退场）" % clause)
            continue
        quote = _squash(e.get("quote"))
        if not quote:
            problems.append("%s 缺 quote —— 引不出原文就等于没读那一条" % clause)
        elif quote not in bodies[top]:
            problems.append("%s 的 quote「%s」不逐字落在本章正文里"
                            % (clause, str(e.get("quote"))[:28]))
        if kind == "uncovered":
            if not str(e.get("why") or "").strip():
                problems.append("%s uncovered 没写 why" % clause)
            if not str(e.get("next") or "").strip():
                problems.append("%s uncovered 没写 next（谁来关这条）" % clause)
            continue
        guards = e.get("guarded_by") or []
        if not guards:
            problems.append("%s 是 guarded 但 guarded_by 为空" % clause)
        for gid in guards:
            if gid not in known_ids:
                problems.append("%s 指向不存在的判据 %r" % (clause, gid))
    missing = [c["num"] for c in chapters if ("§" + c["num"]) not in seen]
    if missing:
        problems.append("设计文件有、映射表没有的章：%s"
                        % "、".join("§" + n for n in missing))
    recs = sum(1 for e in entries if e.get("kind") == "record")
    cap = int(table.get("record_cap") or 0)
    if recs > cap:
        problems.append("record 条数 %d 超过 record_cap %d（不许把疑问章一律标记录）"
                        % (recs, cap))
    want = os.path.basename(str(table.get("design_doc") or ""))
    best = ""
    for name in doc_names:
        if name.startswith(_DESIGN_FAMILY) and _doc_version(name) > _doc_version(best):
            best = name
    if not best:
        problems.append("docs/ 下找不到设计文件族（前缀 %r）" % _DESIGN_FAMILY)
    elif want != best:
        problems.append("设计文件已到 %r，映射表还指着 %r —— 升版必须逐条复核"
                        % (best, want))
    if not problems:
        return True
    extra = "" if len(problems) <= 8 else "（共 %d 处）" % len(problems)
    return "；".join(problems[:8]) + extra


@check("S57 设计要求→判据映射：每章都要有登记，且登记指向真判据")
def s57():
    """R7：**守的是覆盖关系本身**，不是某一条文案。

    由来（2026-10-18）：创始人问「账本怎么出现『防护缺口』」「要求指明哪个
    AI 编程工具，我怎么没看到」。两处的共同根因不是写错字，是**设计要求没人
    承接**：§6 要求工具名、§4.4-1 的枚举里却没有「点名」；实现与判据都只
    跟了 §4.4 ⇒ 一个专答「是哪个工具」的块，没有一条尺子检查工具名。

    ⇒ 本判据把「设计文件里有哪些章」与「每章由谁守」对上。它上线当刻就抓到
      **7 条登记为 uncovered 的章**（5 条一条判据都没有：§7 句子指纹／§11 用量／
      §15 粮草负控／§18 五列标准／§28 网站接入；2 条部分落地：§22 五道闸只落了
      闸五、§24 四条规矩无机器）—— 与 T-04e 首跑抓到 5 处旧词同型：**负数项自证有效**。
    """
    mp = os.path.join(ROOT, _MAP_REL)
    if not os.path.isfile(mp):
        return "映射表不存在：%s —— 没有它，设计要求与判据之间就没有账" % _MAP_REL
    try:
        table = json.loads(io.open(mp, encoding="utf-8").read())
    except ValueError as e:
        return "映射表不是合法 JSON：%r" % (e,)
    rel_doc = str(table.get("design_doc") or "")
    doc_path = os.path.join(ROOT, rel_doc.replace("/", os.sep))
    if not os.path.isfile(doc_path):
        return "映射表指的设计文件不存在：%r" % rel_doc
    doc_text = io.open(doc_path, encoding="utf-8").read()
    known = _judge_titles()
    if not known:
        return "一条判据 id 都没提取到 ⇒ 本判据判不出（判不出不许算通过）"
    docs_dir = os.path.join(ROOT, "docs")
    names = sorted(os.listdir(docs_dir)) if os.path.isdir(docs_dir) else []
    r = _map_problems(doc_text, table, known, names)
    if r is not True:
        return r
    kinds = {"guarded": 0, "uncovered": 0, "record": 0}
    for e in table.get("entries") or []:
        kinds[e.get("kind")] = kinds.get(e.get("kind"), 0) + 1
    _note("章 %d｜guarded %d｜uncovered %d｜record %d（cap %s）｜真判据 id %d 个"
          % (len(_design_chapters(doc_text)), kinds["guarded"],
             kinds["uncovered"], kinds["record"], table.get("record_cap"),
             len(known)))
    return True


@check("N-S57 负控：缺章／假判据／跨章 quote／record 超帽／版本掉队 ⇒ 必须各自红")
def n_s57():
    """反向对照：六个方向各造标本（全部内存态，零写盘）。

    ★ 为什么负控要这么多方向：这条尺子守的是「账」——账最容易被**看起来
      像账**的东西骗过（空表、全 record、指向不存在的判据、指旧版本）。
      每一个方向对应一条真实的逃逸路线。
    """
    doc = ("## 0. 甲\n本工具必须点名是哪家。\n"
           "## 1. 乙\n页面上只读不写。\n")
    ids = {"U22": ["ci/x.py"], "T-04": ["ci/y.py"]}
    names = [_DESIGN_FAMILY + "v1.12（2026-10-17）.md",
             _DESIGN_FAMILY + "v1.13（2026-10-19）.md"]
    ok_table = {
        "design_doc": "docs/" + names[1],
        "record_cap": 0,
        "entries": [
            {"clause": "§0", "kind": "guarded", "quote": "必须点名是哪家",
             "guarded_by": ["U22"]},
            {"clause": "§1", "kind": "guarded", "quote": "只读不写",
             "guarded_by": ["T-04"]},
        ],
    }
    # ① 合法表 ⇒ 不许误伤（否则下面所有红都没有意义）
    base = _map_problems(doc, ok_table, ids, names)
    if base is not True:
        return "负控方向异常：合法表被判红（%s）—— 尺子会误伤真账" % str(base)[:80]
    # ② 缺一章 ⇒ 必须红，且点名缺的章号
    miss = {"design_doc": ok_table["design_doc"], "record_cap": 0,
            "entries": ok_table["entries"][:1]}
    got = str(_map_problems(doc, miss, ids, names))
    if "§1" not in got:
        return "负控失效：少登记一章没被抓到（实得 %r）" % got[:80]
    # ③ 指向不存在的判据 ⇒ 必须红
    fake = json.loads(json.dumps(ok_table))
    fake["entries"][0]["guarded_by"] = ["U99"]
    got = str(_map_problems(doc, fake, ids, names))
    if "不存在的判据" not in got:
        return "负控失效：假判据 id 没被抓到（实得 %r）" % got[:80]
    # ④ 把别章的句子当 quote（章节区间腿）⇒ 必须红
    cross = json.loads(json.dumps(ok_table))
    cross["entries"][1]["quote"] = "必须点名是哪家"
    got = str(_map_problems(doc, cross, ids, names))
    if "不逐字落在本章" not in got:
        return "负控失效：跨章 quote 没被抓到（实得 %r）" % got[:80]
    # ⑤ 全标 record 逃逸 ⇒ 必须红（record_cap 是唯一的闸）
    esc = {"design_doc": ok_table["design_doc"], "record_cap": 0,
           "entries": [{"clause": "§0", "kind": "record", "why": "不想查"},
                       {"clause": "§1", "kind": "record", "why": "不想查"}]}
    got = str(_map_problems(doc, esc, ids, names))
    if "record 条数" not in got:
        return "负控失效：把章节标成 record 就能逃（实得 %r）" % got[:80]
    # ⑥ 设计升版而表没跟 ⇒ 必须红
    old = {"design_doc": "docs/" + names[0], "record_cap": 0,
           "entries": ok_table["entries"]}
    got = str(_map_problems(doc, old, ids, names))
    if "设计文件已到" not in got:
        return "负控失效：设计升版而映射表掉队没被抓到（实得 %r）" % got[:80]
    # ⑦ 真账上跑一遍（不只测标本）—— 正向自证
    mp = os.path.join(ROOT, _MAP_REL)
    real_doc = ""
    if os.path.isfile(mp):
        table = json.loads(io.open(mp, encoding="utf-8").read())
        p = os.path.join(ROOT, str(table.get("design_doc") or "").replace("/", os.sep))
        if os.path.isfile(p):
            real_doc = io.open(p, encoding="utf-8").read()
        docs_dir = os.path.join(ROOT, "docs")
        r = _map_problems(real_doc, table, _judge_titles(),
                          sorted(os.listdir(docs_dir)) if os.path.isdir(docs_dir) else [])
        if r is not True:
            return "真账被判红（%s）—— 标本全过而真账不过，说明尺子只认标本" % str(r)[:80]
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
