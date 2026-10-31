# SPDX-License-Identifier: CC-BY-SA-4.0
# -*- coding: utf-8 -*-
"""0.64 开工前置探针：补齐契约草案 §5 的 F1–F4 与 F6（F5 另由账本探针给）。

只读。不改任何文件。落点 output/（不在随包面、不在清单）。

为什么要 AST 而不是 grep：
  F2「几处**写** decision」与 F3「几处**读** decision 做判断」是**两种不同的东西**，
  用 `grep '"decision"'` 会把两者混在一起 —— 那正是本项目头号顽症
  「同一事实多处实现」被数成「一处」的典型做法。

自证腿（没有这三条，「0 处」就只是失明）：
  L1 真读到了文件：打印扫描的 .py 数、总行数
  L2 正控：在内存里造一段含写/读/不相关三种用法的样本源码，必须被分到正确类别
  L3 负控：一个只把 decision 当普通字符串出现在注释里的样本，必须**不**被判为写或读
"""
import ast
import io
import os
import sys
import tokenize

ROOTS = ["hooks", "ci", "scripts"]
SKIP_DIRS = {"__pycache__", ".git", "_archive_dist"}


def iter_py(roots):
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if fn.endswith(".py"):
                    yield os.path.join(dirpath, fn)


class DecisionVisitor(ast.NodeVisitor):
    """把一个文件里所有与 decision 有关的节点分成 write / read / other。"""

    def __init__(self, path, src):
        self.path = path
        self.src = src
        self.writes = []   # (lineno, 描述)
        self.reads = []    # (lineno, 描述)
        self.others = []   # (lineno, 描述)

    def _is_decision_key(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value == "decision"
        return False

    def visit_Assign(self, node):
        for t in node.targets:
            # rec["decision"] = ...
            if isinstance(t, ast.Subscript) and self._is_decision_key(t.slice):
                self.writes.append((node.lineno, "subscript-assign"))
            # d["decision"] 形式已覆盖；attr 形式 obj.decision 也算写
            if isinstance(t, ast.Attribute) and t.attr == "decision":
                self.writes.append((node.lineno, "attr-assign"))
        self.generic_visit(node)

    def visit_Dict(self, node):
        # {"decision": "alert", ...} —— 记账字典字面量，是最主要的写入点
        for k, v in zip(node.keys, node.values):
            if self._is_decision_key(k):
                lit = None
                if isinstance(v, ast.Constant):
                    lit = repr(v.value)
                self.writes.append((node.lineno, "dict-literal value=%s" % lit))
        self.generic_visit(node)

    def visit_Subscript(self, node):
        # d = rec["decision"] —— Load 上下文才是「读」。
        # 正控样本第一版就漏了这一支（只拿 get() 当读），
        # 说明「读点」的形态至少三种：get()/pop()、下标取值、比较里的下标。
        if self._is_decision_key(node.slice) and isinstance(node.ctx, ast.Load):
            self.reads.append((node.lineno, "subscript-load"))
        self.generic_visit(node)

    def visit_Call(self, node):
        # .get("decision") / .pop("decision") / .setdefault("decision", x)
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in {"get", "pop", "setdefault"}:
            if node.args and self._is_decision_key(node.args[0]):
                if f.attr == "setdefault":
                    self.writes.append((node.lineno, "setdefault"))
                else:
                    self.reads.append((node.lineno, "%s() 取值" % f.attr))
        self.generic_visit(node)

    def visit_Compare(self, node):
        for side in [node.left] + list(node.comparators):
            if isinstance(side, ast.Subscript) and self._is_decision_key(side.slice):
                self.reads.append((node.lineno, "compare-subscript"))
            if isinstance(side, ast.Constant) and isinstance(side.value, str):
                # "alert" 这类字面量参与比较 —— 记录但不当作 decision 读取，
                # 由调用方按上下文判断（这里只统计出现次数，不臆断语义）
                if side.value in {"alert", "block", "allow", "warn"}:
                    self.others.append((node.lineno, "compare-literal %r" % side.value))
        self.generic_visit(node)


def scan_source(path, src):
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return None, "SyntaxError: %s" % e
    v = DecisionVisitor(path, src)
    v.visit(tree)
    return v, None


# ---------------- 自证腿 ----------------

POSITIVE_SAMPLE = '''
def f(rec):
    out = {"decision": "alert", "type": "x"}      # W1 dict 字面量
    rec["decision"] = "block"                      # W2 下标赋值
    rec.setdefault("decision", "allow")            # W3 setdefault
    if rec.get("decision") == "block": pass         # R1 get()
    d = rec["decision"]                             # R2 下标取值
    return out
'''

NEGATIVE_SAMPLE = '''
# 这里的 decision 只是普通英文单词，不是字段
def g():
    msg = "the decision was made"   # 普通字符串, 既非写也非读
    return msg
'''


def self_check():
    ok = True
    v, err = scan_source("<pos>", POSITIVE_SAMPLE)
    if err or not v:
        print("[L2 正控] 解析失败:", err)
        return False
    if len(v.writes) < 3:
        print("[L2 正控] 写入点应 >=3，实得", len(v.writes), v.writes)
        ok = False
    if len(v.reads) < 2:
        print("[L2 正控] 读取点应 >=2，实得", len(v.reads), v.reads)
        ok = False
    if ok:
        print("[L2 正控] 通过：写 %d 读 %d（写/读被正确分开）" % (len(v.writes), len(v.reads)))

    v2, err2 = scan_source("<neg>", NEGATIVE_SAMPLE)
    if err2 or not v2:
        print("[L3 负控] 解析失败:", err2)
        return False
    if v2.writes or v2.reads:
        print("[L3 负控] 失败：把普通单词误判成字段 —— 写", v2.writes, "读", v2.reads)
        ok = False
    else:
        print("[L3 负控] 通过：普通字符串未被误判为字段")
    return ok


def main():
    print("=" * 66)
    print("0.64 开工前置：契约草案 §5 的 F1–F4 / F6（只读）")
    print("=" * 66)
    print()
    print("[L2/L3 自证腿]")
    if not self_check():
        print("⇒ 探针自身不可信，后续读数作废")
        return 2
    print()

    files = sorted(iter_py(ROOTS))
    total_lines = 0
    per_file = []
    all_writes, all_reads, all_others = [], [], []
    for p in files:
        try:
            src = io.open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        total_lines += src.count("\n") + 1
        v, err = scan_source(p, src)
        if err:
            print("  跳过 %s（%s）" % (p, err))
            continue
        if v.writes or v.reads or v.others:
            per_file.append((p, v))
            all_writes += [(p, l, d) for l, d in v.writes]
            all_reads += [(p, l, d) for l, d in v.reads]
            all_others += [(p, l, d) for l, d in v.others]

    print("[L1 真读到了吗]")
    print("  扫描目录: %s" % ", ".join(ROOTS))
    print("  .py 文件: %d 个，合计 %d 行" % (len(files), total_lines))
    print("  命中 decision 的文件: %d 个" % len(per_file))
    print()

    # ---- F1: decision 的取值集合 ----
    print("[F1] decision 出现过的取值（字面量）")
    vals = {}
    for p, l, d in all_others:
        vals.setdefault(d.split()[-1], []).append("%s:%d" % (p, l))
    for k, loc in sorted(vals.items()):
        print("  %-10s %3d 处  例: %s" % (k, len(loc), loc[0]))
    print("  ⇒ 代码里参与比较的取值共 %d 个" % len(vals))
    print()

    # ---- F2: 写入点 ----
    print("[F2] 写入 decision 的点（F2 是「同一事实多处实现」的高发区）")
    for p, l, d in all_writes:
        print("  %-40s :%-5d %s" % (p, l, d))
    print("  ⇒ 写点合计 %d 处，分布在 %d 个文件" % (len(all_writes), len({w[0] for w in all_writes})))
    print()

    # ---- F3: 读取判断点 ----
    print("[F3] 读取 decision 做判断的点（漏一处，回退就没有唯一性）")
    for p, l, d in all_reads:
        print("  %-40s :%-5d %s" % (p, l, d))
    print("  ⇒ 读点合计 %d 处，分布在 %d 个文件" % (len(all_reads), len({w[0] for w in all_reads})))
    print()

    # ---- F4: emit_block / notice_gate 是否同一出口 ----
    print("[F4] emit_block / notice_gate 的定义与调用")
    for p in files:
        try:
            src = io.open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for name in ("emit_block", "notice_gate"):
            for i, line in enumerate(src.splitlines(), 1):
                if ("def %s" % name) in line or ("%s(" % name) in line:
                    kind = "DEF " if ("def %s" % name) in line else "CALL"
                    print("  %-8s %-38s :%-5d %s" % (kind, p, i, line.strip()[:70]))
    print()

    # ---- F6: 值守台/报告读的是哪个面 ----
    print("[F6] 报告与值守台的取数面（若不经 _notify_of，就是「读数源≠写入源」）")
    for p in files:
        try:
            src = io.open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for i, line in enumerate(src.splitlines(), 1):
            if any(k in line for k in ("ledger_rows", "day_counts", "render_view")):
                print("  %-40s :%-5d %s" % (p, i, line.strip()[:70]))
    print()
    print("=" * 66)
    print("读数时刻由本次运行给出；数字随代码变化，引用请重跑。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
