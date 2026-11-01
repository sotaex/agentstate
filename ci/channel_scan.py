# SPDX-License-Identifier: Apache-2.0

"""把「仓内所有起 Python 子进程的调用点」摊成一张表 —— **唯一实现**。

★ 为什么要这个模块（2026-11-01 通道一致性审计，实测驱动）：
  0514 单跑曾 **263 绿 / 23 红**，根因不是规则，是钩子用 `-E` 起（`-E` **仍加载
  user site**），而本机 user site 里有一份 0.28.0 旧 `host_shield.py`，缺
  `resolve_rules_file` ⇒ 首次调用抛 AttributeError ⇒ `HOOK_ERROR (allow)` ⇒
  正控全漏拦、负控假绿、SELF-TAMPERED 不报，三张面孔同一根因。
  生产由 `scripts/install.py:365` 写成 `"<pythonw.exe>" -I -S "<abs>/hook.py"` ——
  `-I` 隐含 `-E -s -P`、`-S` 不加载 site，旧模块永远进不来。
  ⇒ **量具通道 ≠ 生产通道**，且这个差异在无干扰时完全不显形，只在有干扰时静默失真。

★ 为什么必须是「一份实现」：
  本项目的第一顽症就是「同一事实多处实现」。扫描口径一旦有第二份，
  两份就会分叉，而分叉后**两边都还是绿的**。所以 `_p_delivery_selfcheck.py`
  的 CH 判据与任何诊断脚本都只调这里。

★ 三个口径决策（都是为了让判据**咬得住**而不是好看）：
  ① 扫描面 = `ci/ scripts/ tools/ hooks/` ＋ 根目录**不以 `_` 开头的**模块。
     根级 `_` 前缀是历史一次性诊断件（按族排除，不是按名字逐个排除）。
  ② 「起钩子」不只认字面量：`os.path.join(ROOT, "hooks", "pre_tool_use.py")`
     这种嵌套要能穿透（否则 direct 类恒为空 ⇒ 判据恒绿，即假绿第一族）。
  ③ 间接调用（`run("pre_tool_use.py", ...)` → 函数体内 spawn）必须追一层：
     只认「实参里出现钩子脚本名」的本文件函数，再迭代传递一次
     （`hook()` → `run()` 这种）。不追这一层，`verification_tests.py` 的
     `run()`（190 处 hook 调用的唯一通道）就会漏在表外 —— 那才是最大的一处偏离。
"""
from __future__ import annotations

import ast
import io
import os

HOOK_SCRIPTS = ("pre_tool_use.py", "post_tool_use.py",
                "session_dna.py", "session_start_banner.py")
SPAWN_FUNCS = ("run", "call", "check_call", "check_output", "Popen")
FLAG_TOKENS = ("-I", "-S", "-E", "-s", "-P", "-X", "-B", "-u")
SCAN_DIRS = ("ci", "scripts", "tools", "hooks")


def repo_root(start=None):
    here = start or os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(here)


def iter_files(root):
    """扫描面（口径 ①）。"""
    out = []
    for d in SCAN_DIRS:
        full = os.path.join(root, d)
        if not os.path.isdir(full):
            continue
        for name in sorted(os.listdir(full)):
            if name.endswith(".py"):
                out.append(os.path.join(full, name))
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if name.endswith(".py") and os.path.isfile(p) and not name.startswith("_"):
            out.append(p)
    return out


def _all_lits(node):
    """递归取表达式里**所有**字符串常量（口径 ②：穿 os.path.join / f-string）。"""
    return [n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _is_interp(node, consts):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "python" in node.value.lower()
    if isinstance(node, ast.Attribute) and node.attr == "executable":
        return True
    if isinstance(node, ast.Name) and consts.get(node.id) == "python":
        return True
    return False


def _collect_consts(tree):
    consts = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        t = node.targets[0]
        if not isinstance(t, ast.Name):
            continue
        v = node.value
        if isinstance(v, ast.Attribute) and v.attr == "executable":
            consts[t.id] = "python"
        elif isinstance(v, ast.Constant) and isinstance(v.value, str) \
                and "python" in v.value.lower():
            consts[t.id] = "python"
    return consts


def _spawn_name(call):
    f = call.func
    if isinstance(f, ast.Attribute) and f.attr in SPAWN_FUNCS:
        return f.attr
    if isinstance(f, ast.Name) and f.id in SPAWN_FUNCS:
        return f.id
    return None


def _func_spans(tree):
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            spans.append((node.lineno,
                          max(getattr(node, "end_lineno", node.lineno) or node.lineno,
                              node.lineno),
                          node.name))
    return spans


def _owner(spans, line):
    best = None
    for a, b, n in spans:
        if a <= line <= b and (best is None or a > best[0]):
            best = (a, n)
    return best[1] if best else "<module>"


def _hook_owner_funcs(tree, spans):
    """口径 ③：哪些本文件函数「经实参拿到过钩子脚本名」。迭代到不动点。

    起点：`run("pre_tool_use.py", ...)` —— 被调函数 id 进集合。
    传递：`hook()` 里调 `run()`，而 run 已在集合里 ⇒ hook 也进。
    """
    defs = {n for _a, _b, n in spans}
    owners = set()
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not isinstance(f, ast.Name) or f.id not in defs:
            continue
        lits = []
        for a in list(node.args) + [k.value for k in node.keywords]:
            lits += _all_lits(a)
        calls.append((f.id, any(h in s for h in HOOK_SCRIPTS for s in lits)))
    changed = True
    while changed:
        changed = False
        for callee, mentions in calls:
            if mentions and callee not in owners:
                owners.add(callee)
                changed = True
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if isinstance(f, ast.Name) and f.id in owners:
                holder = _owner(spans, node.lineno)
                if holder not in owners and holder != "<module>":
                    owners.add(holder)
                    changed = True
    return owners


def _rel(path, root):
    """相对路径；**跨盘时退回绝对路径**。

    ★ 踩过：负控把变异体落在系统 TEMP（C:），而仓在 D: ⇒ `os.path.relpath`
      直接抛 `ValueError: path is on mount 'C:', start on mount 'D:'`。
      这不是负控写错，是扫描器只支持「同盘」。而「探针必须建在系统 TEMP」
      是本机硬纪律（D 盘整盘禁 unlink）⇒ 扫描器必须容得下跨盘落点。
    """
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except ValueError:
        return os.path.abspath(path).replace("\\", "/")


def scan_file(path, root):
    try:
        src = io.open(path, encoding="utf-8", errors="replace").read()
        tree = ast.parse(src, filename=path)
    except SyntaxError as e:
        return [], {"file": _rel(path, root),
                    "error": "SyntaxError: %s" % e}
    consts = _collect_consts(tree)
    spans = _func_spans(tree)
    hook_funcs = _hook_owner_funcs(tree, spans)
    rel = _rel(path, root)
    file_mentions = any(h in s for h in HOOK_SCRIPTS for s in _all_lits(tree))
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        kind = _spawn_name(node)
        if kind is None:
            continue
        argv = node.args[0] if node.args else None
        if argv is None:
            for kw in node.keywords:
                if kw.arg in ("args", "cmd", "command"):
                    argv = kw.value
        if argv is None:
            continue
        lits = _all_lits(argv)
        hits = [s for s in lits if any(h in s for h in HOOK_SCRIPTS)]
        host = _owner(spans, node.lineno)
        if isinstance(argv, (ast.List, ast.Tuple)):
            elts = list(argv.elts)
            if not elts or not _is_interp(elts[0], consts):
                continue
            flags = [s for s in lits if s in FLAG_TOKENS]
            if hits:
                cls = "direct"
            elif host in hook_funcs:
                cls = "indirect"
            elif file_mentions:
                cls = "aux"
            else:
                continue
            out.append({"file": rel, "line": node.lineno, "func": host,
                        "spawn": kind, "flags": flags, "cls": cls,
                        "target": hits[0] if hits else "<expr>"})
        elif hits:
            out.append({"file": rel, "line": node.lineno, "func": host,
                        "spawn": kind, "flags": [], "cls": "shell",
                        "target": hits[0]})
    return out, None


def scan(root=None):
    """返回 (records, errors, stats)。records 每条含 file/line/func/flags/cls/target。"""
    root = root or repo_root()
    files = iter_files(root)
    recs, errors = [], []
    hook_files = []
    for p in files:
        rows, err = scan_file(p, root)
        recs += rows
        if err:
            errors.append(err)
        text_hits = [r for r in rows]
        if text_hits:
            hook_files.append(text_hits[0]["file"])
    enforced = [r for r in recs if r["cls"] in ("direct", "indirect", "shell")]
    return recs, errors, {"files": len(files), "points": len(recs),
                          "enforced": len(enforced),
                          "hook_files": len(set(hook_files))}


def is_production(rec):
    """与 `scripts/install.py:365` 的 `-I -S` 同一口径。"""
    return "-I" in rec["flags"] and "-S" in rec["flags"]


def group(recs, cls=None):
    """按 (文件, 函数) 分组；同组旗标应一致，不一致本身就是缺陷。"""
    out = {}
    for r in recs:
        if cls and r["cls"] != cls:
            continue
        out.setdefault((r["file"], r["func"]), []).append(r)
    return out
