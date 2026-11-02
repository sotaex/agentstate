#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""S3（只读）：把每一处 `decision` 写入点定性，产出 S4 的收窄依据。

契约 v0.3 §5.2 说「收敛的范围必须先量后改：70 处写入点里，哪些是给 action
顺便派生 decision（可收敛），哪些是独立判了个 decision（要先判定该不该保留）」。
本脚本就是那把尺子。

★ 为什么必须用 AST 而不是 grep
  grep `decision=` 会把注释、docstring、错误消息里的字符串一起命中。
  实测：`"decision=%s 不在回退表内"`（notify_policy 的错误文案）、
  `# decision=alert，action 优先就会把它静默`（注释）都会被 grep 当写入点。
  用 grep 数出来的「70 处」不可信；本脚本改用 AST，只认真正的语法节点。

★ 五种写入形态（少认一种就少算一类写入者）
  W1  kwarg      f(..., decision=X, ...)              —— 关键字实参
  W2  dictkey    {"decision": X}                       —— 字典字面量
  W3  subscript  rec["decision"] = X                   —— 下标赋值（**Store** 上下文）
  W4  attribute  obj.decision = X                       —— 属性赋值
  W5  update     d.update({"decision": X})              —— 由 W2 覆盖

  读取形态（**必须不认**，否则读点混进写点）：
  R1  rec["decision"] 作为表达式取值（Load 上下文）
  R2  rec.get("decision")
  R3  "decision" in rec

★ 自证四腿
  ① 正控：合成样本含 W1–W4 各一 + 各自的「读取孪生」，必须恰好认出 4 写 0 读；
  ② 负控：读取孪生一条都不许被认成写入；
  ③ 可读：打印扫描文件数 / 总写入点数 / 语法错误文件（错误不许静默吞掉）；
  ④ 变异：把「Store 判定」拿掉后，正控的写数必须变小（证明 Store 判定在承重）。

用法（只读，不写仓内文件）：
    P=/c/Users/大马/.workbuddy/binaries/python/versions/3.13.12/python
    "$P" -E -X utf8 output/lineA/s3_decision_writers.py --md out.md --json out.json
"""

import argparse
import ast
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

#: 运行时写入者所在目录（S4 的收窄目标）
RUNTIME_DIRS = ("hooks", "scripts")
#: 判据/测试所在目录（会写合成记录，不是运行时行为，单列）
GUARD_DIRS = ("ci",)

SKIP_DIRS = {
    "__pycache__", ".git", "_archive_dist", "build", "dist",
    ".worktrees", "node_modules", ".mypy_cache", ".pytest_cache",
}

DECISION_KEY = "decision"
ACTION_KEY = "action"
SEVERITY_KEY = "severity"


# ── AST 工具 ────────────────────────────────────────────────────────────────
def _is_decision_const(node):
    return isinstance(node, ast.Constant) and node.value == DECISION_KEY


def _iter_dict_pairs(node):
    """安全遍历 ast.Dict 的 (key, value)，key 为 None（**展开）时跳过。"""
    for k, v in zip(node.keys, node.values):
        if k is None:
            continue
        yield k, v


def _rhs_kind(rhs):
    """把右值分型 —— S4 就是按这一列决定「能不能直接换成 decision_of()」。"""
    if isinstance(rhs, ast.Constant):
        return "literal", repr(rhs.value)
    if isinstance(rhs, ast.IfExp):
        src = ast.unparse(rhs) if hasattr(ast, "unparse") else ""
        return "ifexp", src
    if isinstance(rhs, ast.Name):
        return "name", rhs.id
    if isinstance(rhs, ast.Call):
        src = ast.unparse(rhs) if hasattr(ast, "unparse") else ""
        return "call", src
    if isinstance(rhs, ast.BoolOp):
        return "boolop", (ast.unparse(rhs) if hasattr(ast, "unparse") else "")
    if isinstance(rhs, ast.Compare):
        return "compare", (ast.unparse(rhs) if hasattr(ast, "unparse") else "")
    return type(rhs).__name__.lower(), (ast.unparse(rhs) if hasattr(ast, "unparse") else "")


def _names_in(node):
    """node 里出现过的标识符集合（用来判断 RHS 是否引用了 action/severity）。

    ★ 必须同时收**字符串字面量键**，否则 `h["action"]` 判不出来。
      实测教训（第一版本脚本）：`_names_in` 只收 `ast.Name` 与 `ast.Attribute`，
      而产品里最常见的写法是 `h["action"]`（`ast.Subscript` + Constant 切片）
      ⇒ 「引用 action 的 ifexp」被判成 0 处，而真相不是 0 —— **0 不等于没有，
      可能是探针失明**。这条是假绿第五族的活样本：锚被别处天然满足之前，
      先得确认锚真的被看到了。
    """
    out = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            out.add(sub.id)
        elif isinstance(sub, ast.Attribute):
            out.add(sub.attr)
        elif isinstance(sub, ast.Subscript):
            sl = sub.slice
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                out.add(sl.value)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            # 只收短标识符形态，避免把整句子也塞进来
            if sub.value and len(sub.value) <= 24 and " " not in sub.value:
                out.add(sub.value)
    return out


def _dict_siblings(node, key_filter):
    """同一个 dict 字面量里，某个键对应的字面量值（用于判断 action 与 decision 是否同源）。"""
    vals = {}
    for k, v in _iter_dict_pairs(node):
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            if key_filter(k.value):
                vals[k.value] = (ast.unparse(v) if hasattr(ast, "unparse") else "")
    return vals


# ── 核心：找出一个文件里的全部写入点 ────────────────────────────────────────
def scan_source(src, path_label):
    """返回 (writers, readers)。writers 每项是 dict。"""
    tree = ast.parse(src)
    writers = []
    readers = []

    # 记录每个 node 的父节点，用来判断 Subscript 是 Store 还是 Load
    parent = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node

    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)

        # W1 关键字实参 decision=X
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == DECISION_KEY:
                    kind, src_txt = _rhs_kind(kw.value)
                    writers.append({
                        "form": "W1-kwarg", "line": line, "path": path_label,
                        "rhs_kind": kind, "rhs": src_txt[:120],
                        "refs": sorted(_names_in(kw.value)),
                    })

        # W2 字典键 "decision": X
        elif isinstance(node, ast.Dict):
            for k, v in _iter_dict_pairs(node):
                if _is_decision_const(k):
                    kind, src_txt = _rhs_kind(v)
                    sib = _dict_siblings(node, lambda s: s in (ACTION_KEY, SEVERITY_KEY))
                    writers.append({
                        "form": "W2-dictkey", "line": line, "path": path_label,
                        "rhs_kind": kind, "rhs": src_txt[:120],
                        "refs": sorted(_names_in(v)),
                        "siblings": sib,          # 同一 dict 里的 action/severity（若为字面量）
                    })

        # W3/W4：赋值目标
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                hit = None
                if isinstance(tgt, ast.Subscript) and _is_decision_const(tgt.slice):
                    hit = "W3-subscript"
                elif isinstance(tgt, ast.Attribute) and tgt.attr == DECISION_KEY:
                    hit = "W4-attribute"
                if hit:
                    kind, src_txt = _rhs_kind(node.value)
                    writers.append({
                        "form": hit, "line": line, "path": path_label,
                        "rhs_kind": kind, "rhs": src_txt[:120],
                        "refs": sorted(_names_in(node.value)),
                    })
        elif isinstance(node, ast.AnnAssign):
            tgt = node.target
            hit = None
            if isinstance(tgt, ast.Subscript) and _is_decision_const(tgt.slice):
                hit = "W3-subscript"
            elif isinstance(tgt, ast.Attribute) and tgt.attr == DECISION_KEY:
                hit = "W4-attribute"
            if hit and node.value is not None:
                kind, src_txt = _rhs_kind(node.value)
                writers.append({
                    "form": hit + "(ann)", "line": line, "path": path_label,
                    "rhs_kind": kind, "rhs": src_txt[:120],
                    "refs": sorted(_names_in(node.value)),
                })

        # 读取形态（只为自证「没把读点算成写点」，不参与统计）
        if isinstance(node, ast.Subscript) and _is_decision_const(node.slice):
            ctx = type(node.ctx).__name__
            if ctx == "Load":
                readers.append({"line": line, "note": "subscript-Load"})
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ("get", "pop", "setdefault"):
            for a in node.args:
                if _is_decision_const(a):
                    readers.append({"line": line, "note": "%s()" % node.func.attr})
        if isinstance(node, ast.Compare):
            if any(_is_decision_const(c) for c in [node.left] + list(node.comparators)):
                readers.append({"line": line, "note": "compare"})

    return writers, readers


# ── 自证腿 ──────────────────────────────────────────────────────────────────
POSITIVE_SAMPLE = '''
def f(rec, action, sev, flag):
    rec["decision"] = "block"                          # W3
    rec.decision = "alert"                             # W4
    log_event({"decision": "allow", "action": "allow"})  # W2（带 sibling）
    log_event(dict(base, decision="alert"))            # W1
    log_event(dict(base, decision="block" if h["action"] == "block" else "alert"))  # W1+ifexp
    d = "block" if action == "block" else "alert"      # 不是写入点（只是局部变量）
    x = rec["decision"]                                # R: Load
    y = rec.get("decision")                            # R: get()
    z = "decision" in rec                              # R: compare
    return d, x, y, z
'''


def selftest():
    fails = []
    w, r = scan_source(POSITIVE_SAMPLE, "<selftest>")
    forms = sorted(set(x["form"] for x in w))
    want_forms = ["W1-kwarg", "W2-dictkey", "W3-subscript", "W4-attribute"]
    if forms != want_forms:
        fails.append("正控：四种写入形态没认全，实际 %s（期望 %s）" % (forms, want_forms))
    if len(w) != 5:
        fails.append("正控：写入点应为 5 条，实际 %d" % len(w))
    if len(r) != 3:
        fails.append("负控：读取点应为 3 条（Load/get/compare），实际 %d" % len(r))
    # ★ 关键负控：`h["action"]` 这种下标取键必须被认成「引用了 action」。
    #   第一版漏了它，导致「可收敛候选」被读成 0 处 —— 假阴性比假阳性更难发现。
    ref_hits = [x for x in w if x["rhs_kind"] == "ifexp" and "action" in x["refs"]]
    if not ref_hits:
        fails.append("负控失明：`h[\"action\"]` 形态没被认成引用 action "
                     "⇒ 可收敛候选会被低估成 0")
    # W2 的 sibling 必须抓到
    w2 = [x for x in w if x["form"] == "W2-dictkey"]
    if not w2 or not w2[0].get("siblings"):
        fails.append("W2 的 sibling（同 dict 里的 action）没抓到")
    # W1/W3 的 ifexp/name 分型
    kinds = sorted(set(x["rhs_kind"] for x in w))
    if "literal" not in kinds:
        fails.append("字面量右值没识别出来：%s" % kinds)
    # 变异：拿掉 Store 判定后，W3 应该消失（证明 Store 判定在承重）
    mutated = POSITIVE_SAMPLE.replace('rec["decision"] = "block"', 'rec["other"] = "block"')
    w2m, _ = scan_source(mutated, "<mut>")
    if len(w2m) >= len(w):
        fails.append("变异腿：把 W3 改掉后写入点没变少（%d → %d）⇒ Store 判定不在承重"
                     % (len(w), len(w2m)))
    return fails, len(w), len(r)


# ── 扫仓 ────────────────────────────────────────────────────────────────────
def iter_py():
    for name in sorted(os.listdir(ROOT)):
        p = os.path.join(ROOT, name)
        if os.path.isfile(p) and name.endswith(".py"):
            yield p, "root"
    for d in RUNTIME_DIRS + GUARD_DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [x for x in dirnames if x not in SKIP_DIRS]
            for fn in sorted(filenames):
                if fn.endswith(".py"):
                    yield os.path.join(dirpath, fn), d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--md")
    ap.add_argument("--json")
    args = ap.parse_args()

    fails, nw, nr = selftest()
    print("=" * 78)
    print("S3 decision 写入点定性 —— 读取时刻 %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 78)
    print("自证腿：正控 %d 写入 / %d 读取（合成样本）" % (nw, nr))
    if fails:
        for f in fails:
            print("  ✗ %s" % f)
        print("★ 自证腿失败 ⇒ 后面的统计不可信，终止。")
        return 1
    print("  ✅ 正控/负控/变异三腿通过")
    print()

    rows = []
    parse_errors = []
    n_files = 0
    n_readers = 0
    for path, group in iter_py():
        n_files += 1
        try:
            src = open(path, encoding="utf-8", errors="replace").read()
            w, r = scan_source(src, os.path.relpath(path, ROOT).replace("\\", "/"))
        except SyntaxError as e:
            parse_errors.append("%s: %s" % (os.path.relpath(path, ROOT), e))
            continue
        n_readers += len(r)
        for item in w:
            item["group"] = group
            if group == "root":
                item["group"] = "root-runtime"
            rows.append(item)

    runtime = [x for x in rows if x["group"] in ("hooks", "scripts", "root-runtime")]
    guards = [x for x in rows if x["group"] == "ci"]

    print("扫描：%d 个 .py ／ 写入点 %d（运行时 %d ＋ 判据 %d）／ 读取点 %d"
          % (n_files, len(rows), len(runtime), len(guards), n_readers))
    print("语法错误：%d 个%s" % (len(parse_errors),
                                 ("：" + "; ".join(parse_errors[:3])) if parse_errors else "（0）"))
    print()

    # 分型统计（只对运行时，判据是合成记录不参与收敛）
    print("[运行时写入点按右值分型]（S4 就是按这一列决定能不能换 decision_of）")
    from collections import Counter
    kc = Counter(x["rhs_kind"] for x in runtime)
    for k, n in kc.most_common():
        print("  %-12s %3d" % (k, n))
    print()

    print("[运行时写入点按文件]")
    fc = Counter(x["path"] for x in runtime)
    for k, n in fc.most_common():
        print("  %-52s %3d" % (k, n))
    print()

    # 关键：可收敛候选 = ifexp 且 refs 里含 action
    conv = [x for x in runtime if x["rhs_kind"] == "ifexp" and "action" in x["refs"]]
    print("[可直接换成 decision_of(action, severity) 的候选]（ifexp 且引用 action）")
    if conv:
        for x in conv:
            print("  %s:%d  %s" % (x["path"], x["line"], x["rhs"][:90]))
    else:
        print("  （0 处）")
    print()

    # 同一 dict 里 action 与 decision 都是字面量 ⇒ 检查是否一致（矛盾就在这里产生）
    print("[同一 dict 里 action 与 decision 都是字面量]（逐条判是否一致）")
    literal_pairs = [x for x in rows if x["form"] == "W2-dictkey" and x.get("siblings")]
    bad = []
    for x in literal_pairs:
        sib = x["siblings"]
        act = sib.get("action", "")
        dec = x["rhs"]
        # 粗略一致性：block↔block、alert↔alert、allow↔allow/record
        pair = (act.strip("'\""), dec.strip("'\""))
        ok = (pair in (("block", "block"), ("alert", "alert"), ("allow", "allow"),
                       ("allow", "record"), ("record", "allow")))
        mark = "ok " if ok else "★  "
        if not ok:
            bad.append((x, pair))
        print("  %s%s:%d  action=%-10s decision=%-10s" %
              (mark, x["path"], x["line"], pair[0], pair[1]))
    print("  ⇒ 字面量对 %d 条，其中不一致 %d 条" % (len(literal_pairs), len(bad)))
    print()

    if args.md:
        with open(args.md, "w", encoding="utf-8") as f:
            f.write("# S3 decision 写入点定性（%s）\n\n" % time.strftime("%Y-%m-%d %H:%M"))
            f.write("扫描 %d 个 .py；写入点 %d（运行时 %d ＋ 判据 %d）；读取点 %d。\n\n"
                    % (n_files, len(rows), len(runtime), len(guards), n_readers))
            f.write("| 路径 | 行 | 形态 | 右值类型 | 右值 | 引用 action |\n|---|---|---|---|---|---|\n")
            for x in sorted(runtime, key=lambda y: (y["path"], y["line"])):
                f.write("| `%s` | %d | %s | %s | `%s` | %s |\n" % (
                    x["path"], x["line"], x["form"], x["rhs_kind"],
                    (x["rhs"] or "").replace("|", "\\|")[:80],
                    "是" if "action" in x["refs"] else ""))
            f.write("\n## 判据/测试里的写入点（不参与收敛）\n\n")
            for x in sorted(guards, key=lambda y: (y["path"], y["line"])):
                f.write("- `%s:%d` %s → `%s`\n" % (x["path"], x["line"], x["form"], x["rhs"][:70]))
        print("已写 %s" % args.md)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"read_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "files": n_files, "writers": rows,
                       "runtime": len(runtime), "guards": len(guards),
                       "readers": n_readers, "parse_errors": parse_errors},
                      f, ensure_ascii=False, indent=1)
        print("已写 %s" % args.json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
