# SPDX-License-Identifier: Apache-2.0

"""★★ 交付前自检器 —— 把本轮的错误教训变成**每次必跑**的机器检查。

★ 为什么要有这个文件（这是本轮最重要的产出之一）：
  我把 0.36.0→0.36.4 的错误数了一遍：21 条，其中**只有 14 条有判据能自动抓住**。
  剩下 6 条当时只是"记下来了"，而「记下来」不等于「不会再犯」——
  下一轮我极可能重犯其中任何一条，因为没有任何机制拦我。
  ⇒ 收口办法不是再写一条纪律，而是**把纪律变成退出码非零的检查**：
    每次交付前跑它，任何一条复发当场报红。

★ 本文件检查的 6 条，全部来自 0.36.4 的实测错误（不是假想）：
  G2-selfcheck  `inspect.cleandoc` 破坏缩进 ⇒ `ast.parse` 失败 ⇒ 判据自身崩溃
  G5  判据逐字匹配文案 ⇒ 措辞一改就假红（本轮踩过："1 个没落位"）
  G6  判据用例没跟上被测函数的签名 ⇒ 抛异常（本轮踩过两处）
  M1-selfcheck  结论没有贴"实测"证据标签（本项目老纪律，跨项目通用）
  M2-selfcheck  版本号用字符串比较 ⇒ `0.99 < 0.1`（本轮踩过，方向反了）
  M4-selfcheck  未登记状态直接进集合运算 ⇒ 不可哈希值抛 `TypeError`
  ＋ P6  本轮第六条：治标不治因（本轮关窗治标 ⇒ 改独立 profile 断根）
"""
from __future__ import annotations

import ast
import io
import os
import re
import sys
import textwrap
from inspect import getsource

#: ★ `__file__` 在 `ci/` 下，所以仓根要**上溯一级**。
#:   踩过一次：把 `HERE` 当仓根用 ⇒ `ci/ci/` 不存在 ⇒ 7 条全报
#:   FileNotFoundError。⇒ **这正是本文件要防的 G6 同型**：
#:   验证工具自己出错，却因为「有输出」而被当成「检查发现了很多问题」。
#:   所以下面 `main()` 里把「非 AssertionError 的异常」单独标成 💥，
#:   与真正的红项区分开——工具崩了不算判据红。
_HERE = os.path.dirname(os.path.abspath(__file__))
HERE = os.path.dirname(_HERE)          # 仓根
CI = _HERE                           # 判据目录
RESULTS = []


def check(name):
    def deco(fn):
        RESULTS.append((name, fn))
        return fn
    return deco


def _strip_comments_and_docstrings(src):
    """剥掉注释与 docstring，只留可执行代码（按行号删除整行）。

    ★ 为什么必须有（本轮 M2-selfcheck 判据第一版踩过）：
      在源码**文本**里正则扫描会命中 docstring 里那些**举例说明**的字符串——
      而那些说明恰恰是在警告「别这么写」。判据于是把说明当成了实现。
      ⇒ 与本轮 G1（`find` 命中注释）同源：**文本 ≠ 语法**。
    """
    try:
        tree = ast.parse(textwrap.dedent(src))
    except SyntaxError:
        return src
    drop = set()
    for node in ast.walk(tree):
        # 多行字符串（docstring 与跨行常量）
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            a = node.lineno
            b = getattr(node, "end_lineno", a) or a
            for n in range(a, b + 1):
                drop.add(n)
    lines = src.split("\n")
    return "\n".join(ln for i, ln in enumerate(lines, 1) if i not in drop)


def _guard_files():
    return sorted(f for f in os.listdir(CI) if f.startswith("inbox_guards_"))


# ══════════════════════════════════════════════ 组 1：判据自身可靠（防 G2-selfcheck/G5/G6）
@check("G2-selfcheck 判据里没有 inspect.cleandoc（会破坏缩进使 AST 解析失败）")
def g2_no_cleandoc():
    bad = []
    for f in _guard_files():
        p = os.path.join(CI, f)
        s = io.open(p, encoding="utf-8").read()
        if "cleandoc" in s:
            bad.append(f)
    assert not bad, (
        "判据里用了 inspect.cleandoc：%s。"
        "cleandoc 会吃掉函数体首行缩进 ⇒ ast.parse 直接失败（实测踩过）。"
        "要用 textwrap.dedent。" % bad)
    return "%d 个判据文件均未用 cleandoc" % len(_guard_files())


@check("G5 判据不逐字匹配提示文案（措辞会变，语义不会）")
def g5_no_literal_copy():
    """逐字匹配的问题：文案为了说清事情会变，判据不该跟着改。

    ★ 判据里**允许**出现文案片段，但必须是"集合成员"式的判断
      （例如检查三类按钮都在），而不是"字符串 X 必须逐字出现"。
    ⇒ 这里抓的是最危险的一种：把某句完整中文文案当断言。
    """
    risks = []
    # ★★ 这条判据的第一版**过宽**，自己踩了一次 G5，已收窄（记录在案）：
    #   原判据抓「长中文串 + `in`」，结果把三类**正当**用法全误判为红：
    #     ① 页面内容断言（`"账本尚无可核对记录" not in page`）——
    #        验「某句话**不该**出现在页面上」，文案本身就是被测对象，
    #        这里逐字匹配是**唯一正确**的查法（它要抓的正是文案漂移）。
    #     ② 负控（`assert "某标记" not in marks`）——断言某串**不在**集合里，
    #        同样必须逐字。
    #     ③ `assert` 报错信息里引用的原文。
    #   ⇒ 教训：**「逐字匹配」本身不是病，「把措辞当语义」才是病。**
    #     区分标准是断言**意图**：验「这段文案不许变」→ 逐字正确；
    #     拿「这段文案在不在」代替「这件事有没有发生」→ 才是病。
    #   ⇒ 判据难以完美自动区分，故本条**保守降级为 warn**：
    #     报出来让人复核，但不阻断。一个天天假红的检查等于没有检查。
    _long_cn = re.compile(r'["\']([^"\'\n]*[\u4e00-\u9fa5]{8,}[^"\'\n]*)["\']')
    for f in _guard_files():
        p = os.path.join(CI, f)
        for i, line in enumerate(io.open(p, encoding="utf-8").read().split("\n"), 1):
            stripped = line.strip()
            if not stripped.startswith("assert"):
                continue                       # 只看断言语句
            if not _long_cn.search(stripped):
                continue
            # 集合成员判断 / 「页面不得含」两类正当用法，放行
            if re.search(r'\bnot\s+in\b', stripped):
                continue
            if re.search(r'\bin\s+[A-Za-z_]\w*\s*$', stripped):
                continue
            risks.append("%s:%d  %s" % (f, i, stripped[:66]))
    if not risks:
        return "无「拿文案当语义」的断言"
    print("  ⚠️  G5 有 %d 处疑似「拿文案当语义」的断言（**不阻断**，供人工复核）："
          % len(risks))
    for r in risks[:6]:
        print("       " + r)
    return "无阻断项；%d 处待人工复核" % len(risks)


@check("G6 判据里的被调函数签名与真实一致（防止用例没跟上）")
def g6_signature_sync():
    """本轮踩过：判据调`find_console_windows(lister=...)`，
    而真实函数加了 `run_id` 参数 ⇒ 负控的替身缺参 ⇒ 抛异常。

    这里做**通用**检查：判据里出现的 `模块.函数(` 调用，
    其关键字参数必须在真实函数签名里存在。
    """
    sys.path.insert(0, HERE)
    import inspect as _insp
    checked = miss = 0
    problems = []
    for f in _guard_files():
        p = os.path.join(CI, f)
        src = io.open(p, encoding="utf-8").read()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not isinstance(fn, ast.Attribute) or not isinstance(fn.value, ast.Name):
                continue
            mod_name, func_name = fn.value.id, fn.attr
            if mod_name not in ("WIN", "W", "R", "SV", "S", "M", "HS"):
                continue
            mod_map = {"WIN": "inbox_window", "W": "inbox_window",
                       "R": "remediation", "SV": "inbox_server",
                       "S": "inbox_store", "M": "inbox_model",
                       "HS": "host_shield"}
            try:
                mod = __import__(mod_map[mod_name])
            except Exception:                                # noqa: BLE001
                continue
            tgt = getattr(mod, func_name, None)
            if tgt is None or not callable(tgt):
                continue
            try:
                params = _insp.signature(tgt).parameters
            except (ValueError, TypeError):
                continue
            checked += 1
            for kw in node.keywords:
                if kw.arg is None:
                    continue                # **kwargs 展开，跳过
                if kw.arg not in params:
                    miss += 1
                    problems.append("%s: %s.%s(%s=...) 真实签名无此参数"
                                    % (f, mod_name, func_name, kw.arg))
    assert not miss, (
        "判据调用了不存在的关键字参数（%d 处）：\n    %s\n"
        "  ⇒ 判据自己会抛 TypeError/KeyError。"
        "  本轮踩过两处（find_console_windows / place_all 加参数后用例没跟上）。"
        % (miss, "\n    ".join(problems[:8])))
    return "已核对 %d 处跨模块调用的关键字参数，全部对得上" % checked


# ══════════════════════════════════════════════ 组 2：我自己最容易犯的（防 M1-selfcheck/M2-selfcheck/M4-selfcheck）
@check("M2-selfcheck 版本比较用逐段整数，不用字符串（字符串会让 0.99 < 0.1）")
def m2_version_compare():
    sys.path.insert(0, HERE)
    import host_shield as HS
    # ★★ 这条判据的第一版**过宽**，自己踩了一次，已修：
    #   它在整个源码**文本**里正则找 `"0.99" >` / `str(`，结果命中的是
    #   `_ver_lt` 的 **docstring** —— 那段话正是在**解释**「字符串比较是错的」，
    #   于是判据把"警告错误的说明"当成了"错误的实现"（产品代码是对的）。
    #   ⇒ 教训：**扫描代码必须先剥掉注释与 docstring**。
    #     与本轮 G1（`find` 命中注释）同源，都是"文本 ≠ 语法"。
    src = _strip_comments_and_docstrings(getsource(HS._ver_lt))
    bad = re.findall(r'(?:<|>)\s*\w+\[\d*:\s*\d*\]|str\s*\(|f?["\']\d+\.\d+["\']\s*(?:<|>)', src)
    assert not bad, (
        "_ver_lt 里出现了字符串式版本比较：%s。"
        "★ 实测本轮踩过：`'0.99' < '0.1'` 为 True（逐字符比 '9'>'1'）。"
        "必须逐段转 int 再比。" % bad)
    # 顺带做一次真实对拍
    assert HS._ver_lt("0.99.0", "0.1.0") is False or HS._ver_lt("0.99.0", "0.1.0") is None, (
        "版本比较方向反了：0.99 不应小于 0.1")
    assert HS._ver_lt("0.36.4", "0.36.3") is False
    assert HS._ver_lt("0.36.3", "0.36.4") is True
    return "逐段整数比较，对拍 3 组全对"


@check("M4-selfcheck light() 对非字符串状态不抛 TypeError（先 isinstance 再查集合）")
def m4_unknown_state_type():
    sys.path.insert(0, HERE)
    import inbox_model as M
    import host_shield as HS
    for bad in (None, "", "banana", 123, ["dev"], object()):
        try:
            light, why = M.light(bad, [])
        except TypeError as e:
            raise AssertionError(
                "light(%r) 抛了 TypeError：%s。"
                "★ 实测本轮踩过：不可哈希值进集合会炸。"
                "必须先 isinstance(..., str) 再查集合。" % (bad, e))
        except Exception as e:                            # noqa: BLE001
            raise AssertionError("light(%r) 抛了 %r（应一律兜底为未知态）"
                                 % (bad, type(e).__name__))
        else:
            # ★ 0.37.1 改名：LIGHT_OK ⇒ STATE_L0（六态口径换代）。
            #   集合外一律 L1 盲区，绝不是 L0 绿。
            assert light != M.STATE_L0, (
                "light(%r) 打成了绿灯 —— 未登记状态必须报未知，"
                "绝不报绿（本项目老纪律：查不出来 ≠ 查出来是好的）" % (bad,))
    # 合法姿态必须仍报绿/对应色
    assert M.light(HS.POSTURE_GUARDING, [])[0] == M.STATE_L0
    return "6 个非法状态全部兜底为未知，无一报绿"


@check("M1-selfcheck 每个判据函数都说明它验证什么（禁止无说明的裸 assert）")
def m1_every_check_explains():
    """本项目铁律：说「我实测过」之前先真的跑一遍。
    ⇒ 反向检查：每个判据都必须有 docstring 或 return 说明，
      否则它自己也不知道在验什么，就无法被审计。"""
    no_doc = []
    for f in _guard_files():
        p = os.path.join(CI, f)
        tree = ast.parse(io.open(p, encoding="utf-8").read())
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not node.name.startswith(("c_", "a", "b", "d", "e")):
                continue
            if not node.name.startswith("c_") and len(node.name) <= 2:
                continue
            has_doc = ast.get_docstring(node) is not None
            has_ret = any(isinstance(n, ast.Return) and n.value is not None
                          for n in ast.walk(node))
            if not has_doc and not has_ret:
                no_doc.append("%s:%s" % (f, node.name))
    assert not no_doc, (
        "这些判据函数既无 docstring 也无返回值说明（它们自己不知道在验什么，"
        "后人无法审计）：%s" % no_doc[:8])
    return "所有判据都有可读的说明"


# ══════════════════════════════════════════════ 组 3：治标 vs 断根（防 P6 复发）
@check("P6 开窗走独立 profile（治标=关窗/落位，断根=独立进程）")
def p6_root_cause_fix():
    """本轮第六条教训：0.36.0–0.36.3 的补丁链全打在「落位失败怎么办」上，
    而根因是窗口由用户浏览器进程复用 ⇒ 命令行几何参数被忽略。

    ⇒ 机械化判据：开窗命令**必须**带 `--user-data-dir`。
      没有它 = 又在打补丁；有了它 = 出生即正确。
    """
    sys.path.insert(0, HERE)
    import inbox_server as SV
    cmd = SV._app_window_cmd("http://127.0.0.1:1/")
    assert cmd, "构造不出开窗命令（本机没浏览器？判据应跳过而非误报）"
    joined = " ".join(cmd)
    assert "--user-data-dir" in joined, (
        "开窗命令没有 --user-data-dir ⇒ 又退回「开完再搬」的老路。"
        "★ 实测：走用户浏览器进程时 --window-size/--window-position 被完全忽略，"
        "这正是 0.36.2 窗口出现在旧位置旧尺寸的根因。")
    assert "--app=" in joined, "应用窗口模式丢失（会开成带标签页的普通窗口）"
    assert cmd[-1].startswith("--app="), "--app 必须在最后（否则 URL 被当成别的参数）"
    return "开窗命令带独立 profile + 应用模式，参数顺序正确"


@check("P7 打包在途标志必须自动设且用完还原（隐形免检后门）")
def p7_inflight_flag_hygiene():
    """★★ 0.36.5 新增。守的是本轮自己刚引入的那个机制。

    ★★ 为什么必须守（本轮差点自己造出后门）：
      为解 D-23 死锁，我给打包加了 `ANTINEL_BUILD_IN_FLIGHT=1`，
      让 D-23 在"打包在途"时**不判 dist 缺件**。若这个标志：
        · **不自动设** ⇒ 每次打包都要人记得手设 ⇒ 迟早忘 ⇒ 又变回死锁
          ⇒ 后一次「修正」很可能就是「干脆把 D-23 那条删掉」；
        · **用完不还原** ⇒ 它会泄到闸门之外的进程（最要命的是提交钩子），
          于是**真正的 dist 缺件 / 混旧包也不再报红** —— 一个隐形免检后门。
      ⇒ 判据（读**结构**，不读字符串常量）：
         ① 构建器在调闸门**前**设了它；
         ② 在 `finally` 里**还原**（还原是这条的要点，不是锦上添花）。

    ★ 只查结构不查字面量：把标志**改名**不该让这条红（那属于"换名"不是"去掉"）；
      但把 `finally` 整段删掉、还原逻辑消失 ⇒ 必须红。
    """
    sys.path.insert(0, os.path.join(HERE, "scripts"))
    src = io.open(os.path.join(HERE, "scripts", "build_package.py"),
                  encoding="utf-8").read()
    tree = ast.parse(src)

    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_delivery_gate":
            fn = node
            break
    assert fn is not None, (
        "构建器里找不到 _delivery_gate() ⇒ 打包前闸门被删掉了"
        "（0.36.5 接的第二个强制执行点已失效）")

    # 在途标志的设置点
    sets = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if (isinstance(t, ast.Subscript)
                        and isinstance(t.value, ast.Attribute)
                        and t.value.attr == "environ"):
                    for sub in ast.walk(n):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            sets.append((n.lineno, sub.value))
    names = [v for _l, v in sets]
    assert any("IN_FLIGHT" in v for v in names), (
        "_delivery_gate 里没有设 ANTINEL_BUILD_IN_FLIGHT ⇒ 打包时 D-23 会因"
        "「dist 缺本版件」永远判红 ⇒ 打包死锁复发。实测踩过。")
    assert any("IN_FLIGHT" not in v for _l, v in sets), (
        "★ 只设不还原 ⇒ 该标志会泄到提交钩子等进程 ⇒ 真正的 dist 缺件/混旧包"
        "从此不再报红（隐形免检后门）。必须在 finally 里还原。")

    # 还原必须发生在 finally 里（不是"看起来有还原"）
    # ★★ 0.36.5 **负控实测打出来的漏洞**（第一版只判 `n.finalbody` 非空）：
    #   把 finally 的**内容**换成 `pass`，`finalbody` 照样非空 ⇒ 判据照样绿。
    #   而真实后果是标志永不还原 ⇒ 隐形免检后门。
    #   ⇒ 现在要求 finally 段里**真的有还原动作**（`os.environ` 的写/删）。
    #   这与本文件 G5 记的教训同源：**"有结构"不等于"有行为"**。
    # ★★ 0.36.5 扩充：0.36.5 又加了第二个标志 `ANTINEL_BOOTSTRAP`（自举豁免）。
    #   两个标志**都要被守住** —— 否则"只守住一个"会让人误以为另一个也安全。
    restores = []
    pops = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Try) and n.finalbody:
            for stmt in n.finalbody:
                for sub in ast.walk(stmt):
                    if (isinstance(sub, ast.Call)
                            and isinstance(sub.func, ast.Attribute)
                            and sub.func.attr in ("pop", "update", "__setitem__")):
                        restores.append(sub.lineno)
                    if isinstance(sub, ast.Subscript):
                        restores.append(sub.lineno)
    assert restores, (
        "★ _delivery_gate 的 finally 里**没有还原动作**（只有 pass 之类）⇒ "
        "环境标志永不还原，会泄到提交钩子等后续进程 ⇒ "
        "真正的 dist 缺件 / 混旧包 / 版本分叉不再报红（隐形免检后门）。\n"
        "  ★ 这条漏洞是**负控实测打出来的**：第一版只判 `try` 有 finalbody，"
        "  把内容换成 `pass` 照样绿 ⇒ 「有结构」不等于「有行为」。")
    # 两个标志都必须**各自**被还原（漏一个就等于留一个后门）
    flags = ("ANTINEL_BUILD_IN_FLIGHT", "ANTINEL_BOOTSTRAP")
    not_restored = [f for f in flags if ('os.environ.pop("%s"' % f) not in src]
    assert not not_restored, (
        "标志在 finally 里没有各自还原：%r ⇒ 漏掉的那个会泄到后续进程"
        "（提交钩子会带着它跑闸门 ⇒ 真缺陷被免检）" % (not_restored,))
    return ("在途标志：自动设 ✔ · finally 真有还原动作 ✔（行 %d）；"
            "两个标志均各自还原 ✔" % restores[0])


@check("P8 每条判据都必须测真源（不许只查源码字样）")
def p8_guards_test_the_real_thing():
    """★★ 0.36.5 新增 —— 本轮**四次**踩到同一个坑，必须机械化守住。

    ★ 事故链（一条比一条隐蔽，全是"看起来有检查"）：
      ① **P04** 只查 `"endswith" in 源码` ⇒ 我把宽泛模式改成 `fullmatch`
         （更严格、修好了真缺陷）⇒ P04 反而报红。
      ② **F1** 只查 `"find_console_windows" in 源码` ⇒ 把
         `return bool(...)` 改成 `return False`（行为全坏）⇒ F1 照样绿。
      ③ **F3** 写了 `for bad in (...)` 却**从不注入**那个变量
         ⇒ 等于用同一个真实姿态断言了三次，还报得言之凿凿。
      ④ **G2-selfcheck** 只查 `"_delivery_gate(" in 源码` ⇒ 把调用挪进 `if False:`
         （永不执行）⇒ G2-selfcheck 照样绿。
      ⇒ 它们的共同形态：**判据验的是"源码里有没有某个字样"，
        而不是"运行起来是不是对的"**。
      ★ 后果最严重的一类是 ②④：它们是**假绿** —— 判据坏了而账面是绿的。
      ★ 与本文件 G5「有结构 ≠ 有行为」、P7「有 finalbody ≠ 有还原动作」
        是同一条纪律的第 5–8 次复发。

    ⇒ 判据：**任何守卫文件里，对源码做字样匹配的位置必须被登记**，
      且每处都必须**同时**有对应的行为验证用例。
      —— 说清实现：查「`in seg` / `in src` / `.search(` 这种**只看文本**」
      的调用出现在哪个文件的哪个判据里，然后对每个这样的判据，
      要求它在同一文件里存在**调用被测函数**的用例。
    """
    import ast as _ast
    guard_dir = os.path.join(HERE, "ci")
    offenders = []            # [(文件, 判据名, 形态)]
    behavioral = 0            # 真正跑被测对象的判据数
    for fn in sorted(os.listdir(guard_dir)):
        if not (fn.startswith("inbox_guards_") or fn.startswith("_p_")):
            continue
        if not fn.endswith(".py") or fn == "inbox_guards.py":
            continue
        path = os.path.join(guard_dir, fn)
        text = io.open(path, encoding="utf-8").read()
        # 一个判据函数 = 一个 def；看它里面有没有"只看文本"的匹配，
        # 以及有没有**真正调用**被测对象的迹象。
        for m in re.finditer(r"^def ((?:c_|n_|p\d|f\d|g\d|d\d|b\d|r\d|"
                             r"t\d|w\d|m\d|a\d)\w*)\(.*?\):", text, re.M):
            name = m.group(1)
            seg = text[m.end():]
            nxt = re.search(r"^(?:def |@check|#\s*═)", seg, re.M)
            seg = seg[:nxt.start()] if nxt else seg
            text_only = bool(re.search(r'in (?:seg|src|fn|full|code)\b'
                                       r'|\.search\(', seg))
            calls = bool(re.search(r"(?:WIN|HS|W|HOST|SV|HOSTSHIELD|"
                                   r"host_shield|inbox_window|inbox_model)"
                                   r"\.\w+\(", seg))
            if calls:
                behavioral += 1
            if text_only and not calls:
                offenders.append((fn, name))
    assert behavioral, "守卫文件里一条调用被测对象的判据都没有（量具坏了）"
    # 只**报告**，不判红 —— 存量里还有若干纯结构检查，
    # 一次性判红会把整批判据变成"待修"而不是"已发现"。
    # ★ 为什么这里降级为 warn：P8 的目的是**让新增的判据别再犯**，
    #   而不是否掉过去所有用结构检查的判据（那会造成大面积假红，
    #   而大面积假红的结果是所有人都不看这一条 —— 与本条目的相反）。
    if offenders:
        print("   [warn] 只查源码字样、没有行为验证的判据 %d 处（存量，未判红）："
              % len(offenders))
        for f, n in offenders[:8]:
            print("          %s :: %s" % (f, n))
        if len(offenders) > 8:
            print("          …… 另 %d 处" % (len(offenders) - 8))
    return "调用被测对象的判据 %d 条；纯结构检查 %d 处已列名（不判红）" % (
        behavioral, len(offenders))


# ══════════════════════════════════ 组 4：通道一致性（2026-11-01 实测驱动）
#
# ★ 事故（不是推演）：`ci/inbox_guards_0514.py` 单跑曾 **263 绿 / 23 红**，
#   根因不在规则，而在**钩子是怎么被起起来的**：
#     套件用 `-E` 起钩子，而 `-E` 只忽略 `PYTHON*` 环境变量，**仍然加载 user site**。
#     本机 user site 里有一份 0.28.0 旧 `host_shield.py`（缺 `resolve_rules_file`），
#     于是钩子首次调用抛 AttributeError ⇒ `HOOK_ERROR (allow)` ⇒ 正控全漏拦、
#     负控假绿、SELF-TAMPERED 不报 —— **三张面孔，一个根因**。
#   生产由 `scripts/install.py:365` 写成 `"<pythonw.exe>" -I -S "<abs>/hook.py"`：
#   `-I` 隐含 `-E -s -P`、`-S` 不加载 site ⇒ 那个旧模块永远进不来。
#   ⇒ **量具通道 ≠ 生产通道**。这个差异在无干扰时完全不显形，只在有干扰时静默失真，
#     所以它必须由判据守，不能靠人记。
#
# ★ 修好之后的实测（同一夹具，同一事件）：
#   263 绿/23 红 → **289 绿/0 红**；再把 0514 三处钩子调用从 `-E` 收紧到 `-I -S`，
#   仍 **289 绿/0 红** ⇒ 收紧不改变任何结论，只把量具挪到生产位。
#
# ★ 为什么允许登记豁免，而不是一律判红：
#   有些偏离是**故意的**，而且去掉就变成空转。最典型的是 HSI-01：
#   它要造「user site 里有同名旧模块」的遮蔽场景，而 `-I -S` 恰恰屏蔽 user site
#   ⇒ 带上就造不出遮蔽，判据自己失效。这类必须留，但要显形、要有对照腿。
#   ⇒ 登记表带 `kind`：`adversarial`（故意偏离，须有生产腿对照）
#     / `pending`（已知债，必有到期版本，到期不修则本条红）。

_CHANNEL_EXEMPT = {
    ("ci/inbox_guards_0514.py", "_hsid_fire"): {
        "kind": "adversarial",
        "until": None,
        "why": "HSI-01 要造「user site 里有同名旧模块」的遮蔽，-I/-S 会把它屏蔽掉 ⇒ "
               "带上就造不出遮蔽、判据空转。同文件 _sec05_fire/_c_fire/_fire 三处走 "
               "-I -S 的生产模拟腿，两条腿互为对照（敌对通道测加固，生产通道测真实行为）。",
    },
    ("ci/drift_a5_whitelist.py", "hook"): {
        "kind": "pending", "until": "0.64.0",
        "why": "历史诊断件，裸 PY 起钩子；2026-11-01 审计发现，未验是否影响其结论。",
    },
    ("ci/single_case_probe.py", "run_one"): {
        "kind": "pending", "until": "0.64.0",
        "why": "单例排查工具，裸 PY 起钩子；同上。",
    },
    ("ci/drift_audit.py", "hook"): {
        "kind": "pending", "until": "0.64.0",
        "why": "漂移审计的取数腿，裸 PY 起钩子；审计结论可能因此偏离生产通道。",
    },
    ("ci/regression_gate.py", "j_baseline_tag_reminder_in_place"): {
        "kind": "pending", "until": "0.64.0",
        "why": "该判据内裸 PY 起钩子，与同文件 call_hook（已 -I -S）不一致 —— 同一文件两把尺子。",
    },
    ("scripts/build_package.py", "build"): {
        "kind": "pending", "until": "0.64.0",
        "why": "构建期调子进程；经间接追一层被判进表。待核是否真起钩子（若只是跑 "
               "setup.py 则本条应从表内剔除，而不是给它加 -I -S）。",
    },
    ("scripts/verification_tests.py", "run"): {
        "kind": "pending", "until": "0.64.0",
        "why": "★★ 面最大的一处：270 条断言、190 处 hook() 全部经此函数起钩子，"
               "而它是裸 PY（既无 -I 也无 -E）。改它要重录判定（跑两遍），"
               "故单列一个窗口做，不在审计轮夹带。",
    },
    ("scripts/verification_tests.py", "main"): {
        "kind": "pending", "until": "0.64.0",
        "why": "同 run()：main 里 5 处直接起 post_tool_use/session_start_banner，裸 PY。",
    },
}

#: 非空集下界（口径见 ci/channel_scan.py）。取当前实测值的约八成，
#: 低了不许 —— 扫描面一旦缩水（比如把 ci/ 漏出 SCAN_DIRS），就不许再报绿。
_CHANNEL_MIN_GROUPS = 10
_CHANNEL_MIN_POINTS = 40


def _channel_scan():
    sys.path.insert(0, CI)
    import channel_scan as CS
    return CS


def _current_version():
    """读当前版本，供「登记到期」判。读不到 ⇒ None（上层按 fail-closed 判红）。"""
    try:
        sys.path.insert(0, HERE)
        import antinel as A
        return str(A.VERSION)
    except Exception:                                        # noqa: BLE001
        return None


@check("CH-1 起钩子的子进程须与生产同旗标（-I -S），偏离必须登记")
def ch1_hook_channel_matches_production():
    """守「量具通道 = 生产通道」这一件事。

    ★ 三个必答（缺一条就会变成假绿）：
      ① **非空集**：强制组数与点数不得低于下界 —— 否则扫描面缩水也照样绿。
      ② **真入口在同一张表**：`scripts/install.py` 里写命令行的那个函数必须被扫到
         并判为合规（记忆里的第十四族：对照实验必须把真入口放进同一张表）。
      ③ **登记不腐烂**：登记了但已经合规的条目 ⇒ 红（修好了要删登记）；
         `pending` 到期不修 ⇒ 红。
    """
    CS = _channel_scan()
    sys.path.insert(0, os.path.join(HERE, "scripts"))
    import install as I
    import host_shield as HS

    recs, errors, stats = CS.scan(HERE)
    assert not errors, (
        "通道扫描有文件解析失败：%s ⇒ 那些文件里的调用点全在表外，本条会假绿。"
        % [e["file"] for e in errors])

    groups = CS.group(recs)
    enforced = {k: v for k, v in groups.items()
                if all(r["cls"] in ("direct", "indirect", "shell") for r in v)}
    assert len(enforced) >= _CHANNEL_MIN_GROUPS and stats["enforced"] >= _CHANNEL_MIN_POINTS, (
        "★ 非空集下界未达：强制组 %d（< %d）／点数 %d（< %d）。"
        "扫描面缩水时本条必须红，不许因为「没扫到东西」而变绿。"
        % (len(enforced), _CHANNEL_MIN_GROUPS, stats["enforced"], _CHANNEL_MIN_POINTS))

    # ② 真入口在同一张表（且必须是**行为**，不是查源码字样）
    #    生产基准不是一个 spawn，而是 install.py 造出来的命令行模板 ——
    #    直接调用它，拿真值来比，避免「判据自己另写一套基准」（第一顽症）。
    shell_cmd = I.hook_command("pre_tool_use.py")
    process_entry = I.zcode_hook_entry("pre_tool_use.py")
    assert "-I" in shell_cmd and "-S" in shell_cmd, (
        "★ 生产基准变了：install.hook_command 不再输出 -I -S ⇒ 本判据的基准失效，"
        "必须先改基准再谈别处合规。实测输出：%r" % shell_cmd)
    args = process_entry.get("args") or []
    assert "-I" in args and "-S" in args, (
        "★ 生产基准变了：install.zcode_hook_entry 的 args 不含 -I -S。实测：%r" % args)

    # ③ 逐组判定
    bad, stale, expired = [], [], []
    for (f, fn), rows in sorted(enforced.items()):
        ok = all(CS.is_production(r) for r in rows)
        key = (f, fn)
        if not ok:
            if key not in _CHANNEL_EXEMPT:
                flags = sorted(set(tuple(r["flags"]) for r in rows))
                lines = ", ".join(str(r["line"]) for r in rows[:6])
                bad.append("%s:%s（%d 点在 %s）flags=%s"
                           % (f, fn, len(rows), lines, [list(x) for x in flags]))
        else:
            if key in _CHANNEL_EXEMPT:
                stale.append("%s:%s 已合规但登记还在" % (f, fn))

    cur = _current_version()
    for key, meta in _CHANNEL_EXEMPT.items():
        if meta["kind"] == "pending":
            until = meta.get("until")
            if not until:
                expired.append("%s:%s 登记为 pending 却没有到期版本 ⇒ 永久绿灯"
                               % key)
            elif cur is None:
                expired.append("%s:%s 到期检查读不到当前版本 ⇒ fail-closed 判红"
                               % key)
            else:
                if not HS._ver_lt(cur, until):
                    expired.append("%s:%s 到期未修（当前 %s ≥ 登记 %s）"
                                   % (key[0], key[1], cur, until))

    problems = []
    if bad:
        problems.append(
            "起钩子未与生产同旗标（%d 组），且未登记：\n      %s\n"
            "  ⇒ 生产是 `pythonw -I -S`（install.py:365），`-E` 仍加载 user site ⇒ "
            "旧同名模块可劫持整道防线并静默 fail-open（实测过 263/23）。"
            % (len(bad), "\n      ".join(bad)))
    if stale:
        problems.append("登记未清（修好了就要删登记，否则登记表本身腐烂）：%s" % stale)
    if expired:
        problems.append("登记到期：%s" % expired)
    assert not problems, "\n  ".join(problems)

    adv = [k for k, m in _CHANNEL_EXEMPT.items() if m["kind"] == "adversarial"]
    return ("强制 %d 组 / %d 点全部与生产同旗标；登记 %d 条（其中敌对通道 %d 条：%s）"
            % (len(enforced), stats["enforced"], len(_CHANNEL_EXEMPT), len(adv),
               ", ".join("%s:%s" % k for k in adv) or "无"))


@check("CH-2 负控：把 -I -S 拿掉后 CH-1 的判据必须咬住")
def ch2_channel_negctl():
    """★ 没有这条，CH-1 可能是恒绿：它数的是「有没有偏离」，
    而如果扫描器坏了（比如永远读不到 flags），偏离数恒为 0，CH-1 照样绿。

    ⇒ 变异体：把 `ci/inbox_guards_0514.py` 里所有 `"-I", "-S", `
    从源码里删掉（**先断言字节真的变了**），落成临时文件后用**同一个**扫描器重扫，
    断言那几处从合规翻成不合规。
    """
    CS = _channel_scan()
    src_p = os.path.join(CI, "inbox_guards_0514.py")
    is_p = os.path.join(CI, "single_case_probe.py")
    victim = src_p if os.path.isfile(src_p) else is_p
    raw = io.open(victim, encoding="utf-8").read()
    mut = raw.replace('"-I", "-S", ', "")
    assert mut != raw, (
        "★ 变异没有改到任何字节 ⇒ 负控是空转的（假绿第八族）。"
        "要么源码里已经没有 `\"-I\", \"-S\", ` 了，要么替换串写错了。")
    assert len(mut) < len(raw), "变异后反而变长，替换方向错了"

    # 变异体必须落在系统 TEMP（D 盘整盘禁 unlink；仓内落点还会污染扫描面）
    import tempfile
    fd, tmp = tempfile.mkstemp(suffix=".py", prefix="ch_negctl_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(mut)
        rows, err = CS.scan_file(tmp, HERE)
        assert err is None, "变异体解析失败：%s ⇒ 负控没测到东西" % err
        # 原文件里合规的组，在变异后必须出现不合规的
        orig_rows, _ = CS.scan_file(victim, HERE)
        orig_bad = [r for r in orig_rows
                    if r["cls"] in ("direct", "indirect") and not CS.is_production(r)]
        mut_bad = [r for r in rows
                   if r["cls"] in ("direct", "indirect") and not CS.is_production(r)]
        assert len(mut_bad) > len(orig_bad), (
            "★ 去掉 -I -S 之后不合规点数没有增加（原 %d → 变异 %d）⇒ "
            "扫描器对旗标失明，CH-1 的绿是假的。" % (len(orig_bad), len(mut_bad)))
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return ("变异体（%s 去掉 -I -S）不合规点 %d → %d，判据咬住"
            % (os.path.basename(victim), len(orig_bad), len(mut_bad)))


# ══════════════════════════════════════════════ 运行
def main():
    print("=" * 74)
    print("交付前自检器 —— 把历轮的错误教训变成机器检查")
    print("=" * 74)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            print("  ✅ %-48s %s" % (name[:48], why or ""))
            ok += 1
        except AssertionError as e:
            print("  ❌ %-48s %s" % (name[:48], e))
            fail += 1
        except Exception as e:                                # noqa: BLE001
            print("  💥 %-48s %r" % (name[:48], e))
            fail += 1
    print()
    print("-" * 74)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())