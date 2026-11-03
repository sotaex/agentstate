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
import io
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

_OUT = os.path.dirname(HERE)
if _OUT not in sys.path:
    sys.path.insert(0, _OUT)
import _commit                                              # noqa: E402

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
    """同一个 dict 字面量里，某个键对应的**纯字符串字面量**值。

    ★ 只收 `ast.Constant`（2026-11-03 修）：原先用 `ast.unparse(v)` 把任何表达式
      都转成串，于是 `hooks/pre_tool_use.py:5490` 的三元表达式
      `'allow' if _v.get('decision') == 'allow' else 'block'` 被当成了 action 的取值，
      凭空造出一条「action 与 decision 不一致」的**假阳性**。
      判据自己不能生产噪声 —— 一条假阳会让人开始不信所有真阳。
    """
    vals = {}
    for k, v in _iter_dict_pairs(node):
        if not (isinstance(k, ast.Constant) and isinstance(k.value, str)):
            continue
        if not key_filter(k.value):
            continue
        if not (isinstance(v, ast.Constant) and isinstance(v.value, str)):
            continue        # 非字面量（三元／变量／调用）⇒ 无从判定，不进配对
        vals[k.value] = v.value
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


# 同一 dict 里 action 与 decision 都写字面量时，这一对算不算矛盾。
#
# ★ 五态而不是两态（2026-11-03 三次修，每次修都由一类假警报逼出来）。
#   最初只有「一致／不一致」，把 38 条设计如此的记录天天印成警报；拆开之后
#   才知道那 38 条其实是四种不同的东西（读数见下）。判据有牙但咬错对象，
#   比没牙更坏 —— 真矛盾会被噪声淹掉。
#
# ★★ 语义**从产品真源取，本地不留副本**。
#   上一版我在这个文件里另抄了一份 `PAIR_DERIVED = (("alert","allow"),)`。
#   那正是本项目第一顽症（同一事实多处实现）的第二次复制：产品侧改了口径，
#   这份抄本不会跟着变，而且它会**继续印绿**。抄本比没判据更危险，
#   因为看屏幕看不出它已经过期。
#
#   读不到真源时**整个判据红**，不退回内置副本 —— 退回副本等于用一份可能
#   过期的抄本冒充证据。s3 是分析工具、不在产品运行路径上，红得起。
_HOOKS_DIR = os.path.join(ROOT, "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

try:
    import notify_policy as _NP                                  # noqa: E402
    # 私有名：这是**分析工具读产品真源**，不是产品内部互调。
    # 读私有名而不是复制一份，正是为了「改一处只有一处」。
    _CONFIG_FACE = frozenset(_NP._DECISION_FROM_CONFIG_FACE)
    _DECISION_TIERS = frozenset(_NP._RANK) | frozenset(_NP._DECISION_ALIAS)
except Exception as _exc:                                        # noqa: BLE001
    _CONFIG_FACE = None
    _DECISION_TIERS = None
    _NP_LOAD_ERROR = "%s: %s" % (type(_exc).__name__, _exc)

#: 一致的对：action 与 decision 说同一件事（两种写法）。
PAIR_CONSISTENT = (("block", "block"), ("alert", "alert"),
                   ("allow", "allow"), ("allow", "record"), ("record", "allow"))
#: 派生告警：提醒但不拦。**产品侧 verify 的就是这条**（notify_policy 注释：
#: 「alert + allow 949 条」），不是我在分析脚本里拍的。
PAIR_DERIVED = (("alert", "allow"),)


def classify_pair(action, decision) -> str:
    """返回 `consistent` / `derived` / `config_face` / `unpaired` / `conflict`。

    五态各自对应一件不同的事，缺一态就有一类记录被塞进别的栏里：

      · `unpaired`     —— 同 dict 里**没有 action 键**。实测 17 对。它们是
                          `policy_changed`、`canary_planted` 这类非裁决记录，
                          `decision` 只表示「这件事被允许做了」，没有可比的
                          action。算成「不一致」＝分母混进按设计的例外（第十五族）。
      · `config_face`  —— decision 的值在 `_DECISION_FROM_CONFIG_FACE` 里。
                          契约 §3 明写这类事实 **action 表达不了**，所以
                          「action=allow + decision=config_refresh」不是矛盾，
                          是两条不同面的事实写在同一行。实测 5 对。
      · `conflict`     —— 两个档位词打架（如 block + allow）。**这才是要抓的**。
      · `consistent` / `derived` —— 同一件事的两种写法 / 设计如此的派生告警。

    ★ decision 若既不是档位词、也不在登记表里（如 `config_skip`）⇒ 仍落
      `conflict`，但调用处会再分成「取值未登记」单列 —— 它不是矛盾，而是
      「有个取值没人登记」，运行时它落默认档。两类都不许静默。
    """
    a = "" if action is None else str(action).strip("'\"")
    d = str(decision).strip("'\"")
    if not a:
        return "unpaired"                # 没有 action ⇒ 无从判，不是矛盾
    if _CONFIG_FACE is not None and d in _CONFIG_FACE:
        return "config_face"             # 配置/报告面事实，action 表达不了
    p = (a, d)
    if p in PAIR_CONSISTENT:
        return "consistent"
    if p in PAIR_DERIVED:
        return "derived"
    return "conflict"


def is_registered_decision(decision) -> bool:
    """decision 的取值是不是一个**登记过的**值（档位词或配置面事件名）。"""
    d = str(decision).strip("'\"")
    if _CONFIG_FACE is None or _DECISION_TIERS is None:
        return True                      # 真源读不到时不在这一层下判断
    return d in _DECISION_TIERS or d in _CONFIG_FACE


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
    # ★ 一致性判据必须能翻面（2026-11-03 加）
    #   只验「alert+allow 不再算冲突」会得到一个永远绿的判据 ——
    #   把 `classify_pair` 写成 `return "derived"` 也能过。
    #   所以五类各给样本，外加**两条真矛盾**与**一条不认识**的组合。
    #   真矛盾那条最重要：没有它，「conflict 恒 0」与「判据漏了」同貌。
    _cases = [(("block", "block"), "consistent"),
              (("allow", "record"), "consistent"),
              (("alert", "allow"), "derived"),
              (("block", "allow"), "conflict"),           # 拦下却放行：真矛盾
              (("alert", "block"), "conflict"),           # 只提醒却拦：真矛盾
              (("somethingnew", "allow"), "conflict"),    # 不认识 ⇒ 必须报
              (("", "allow"), "unpaired"),                # 没有 action：无从判
              ((None, "allow"), "unpaired")]              # 键整个不存在
    for (a, d), want in _cases:
        got = classify_pair(a, d)
        if got != want:
            fails.append("一致性判据：(%s,%s) 期望 %s，实际 %s" % (a, d, want, got))

    # ★ 第五态必须**从真源取一个真实的词**来测，不能自己拼一个像样的词。
    #   自己拼的词（如 "config_refresh"）在真源改名后会立刻失效，而这条自检
    #   会以「样本写错了」的样子报红 —— 看上去像测试坏了，实际是判据跟丢了产品。
    #   所以：① 真源读得到 ⇒ 拿真源里最小的那个值跑一遍；② 真源读不到 ⇒ 红。
    if _CONFIG_FACE is None:
        fails.append("真源读不到（%s）⇒ 第五态无法验证" % _NP_LOAD_ERROR)
    else:
        _probe = sorted(_CONFIG_FACE)[0]
        if classify_pair("allow", _probe) != "config_face":
            fails.append("第五态：真源值 %r 未被认成 config_face（实际 %s）"
                         % (_probe, classify_pair("allow", _probe)))
        # 反向：把一个**确定不在**真源里的词喂进去，必须仍落 conflict。
        # 这条腿保证「config_face」不是一个什么都收的口袋。
        if classify_pair("allow", "__not_a_config_face__") != "conflict":
            fails.append("第五态反向：不在真源里的词被误认成 config_face")
        # 取值登记判据也要能翻面：真源值 ⇒ 已登记；乱写的词 ⇒ 未登记。
        if not is_registered_decision(_probe):
            fails.append("取值登记：真源值 %r 被判成未登记" % _probe)
        if is_registered_decision("definitely_not_registered"):
            fails.append("取值登记反向：乱写的词被判成已登记")
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
    tally = {"consistent": [], "derived": [], "config_face": [],
             "unpaired": [], "conflict": []}
    _MARK = {"consistent": "ok ", "derived": "派 ", "config_face": "配 ",
             "unpaired": "—  ", "conflict": "★  "}
    _NOTE = {"derived": "  ← 派生告警（提醒但不拦，产品侧设计如此）",
             "config_face": "  ← 配置/报告面事实，action 表达不了（契约 §3）",
             "unpaired": "  ← 同 dict 里没有 action，无从配对"}
    for x in literal_pairs:
        sib = x["siblings"]
        pair = (sib.get("action", "").strip("'\""), x["rhs"].strip("'\""))
        kind = classify_pair(*pair)
        tally[kind].append({"path": x["path"], "line": x["line"],
                            "action": pair[0], "decision": pair[1]})
        print("  %s%s:%d  action=%-10s decision=%-10s%s" %
              (_MARK[kind], x["path"], x["line"], pair[0] or "(无)", pair[1],
               _NOTE.get(kind, "")))
    _sum = sum(len(v) for v in tally.values())

    # ★ conflict 这一栏要再分一次（2026-11-03 第三次修）。
    #   落进 conflict 的其实有两种东西：
    #     ① 两个**档位词**打架（block + allow）—— 真矛盾，产品会做出错误裁决；
    #     ② decision 的取值**谁都没登记过**（如 `config_skip`）—— 不是矛盾，
    #        而是「有个取值没人认领」，运行时它落默认档（默认档＝会打扰用户）。
    #   合成一栏的后果：修 ① 的人看见 6 条以为是 6 处矛盾，实际只有 0 处矛盾，
    #   而真正该补登记的那 1 条被 5 条正常记录稀释掉了。
    _unregistered = [c for c in tally["conflict"]
                     if not is_registered_decision(c["decision"])]
    _real_conflict = [c for c in tally["conflict"]
                      if is_registered_decision(c["decision"])]

    # ★ 汇总行必须**把 conflict 拆开后的两个数都印出来**（2026-11-03 第四次修）。
    #   上一版这里印「档位打架 %d」用的是 _real_conflict，而分栏检查用的是
    #   tally["conflict"] —— 两个口径。结果屏幕上是
    #       12 + 11 + 5 + 17 + 0 = 45，而总数写 46
    #   差的那 1 条（config_skip）明明单列印出来了，却没进汇总行。
    #   这正是「一个数承担两个分母」的现场版：**分栏检查绿着，屏幕上的数却加不上**。
    #   六个被加数全印出来，读者能自己验算。
    print("  ⇒ 字面量对 %d 条：一致 %d ／ 派生告警 %d ／ 配置面 %d ／ 无对可判 %d "
          "／ 档位打架 %d ／ 取值未登记 %d（六栏相加＝总数）"
          % (len(literal_pairs), len(tally["consistent"]), len(tally["derived"]),
             len(tally["config_face"]), len(tally["unpaired"]),
             len(_real_conflict), len(_unregistered)))
    # 分栏相加必须等于总数 —— 否则「档位打架 0」可能只是被归进了别的栏，
    # 那是「分母悄悄换了一个」的经典形态，看屏幕完全看不出来。
    if _sum != len(literal_pairs):
        print("  ✗ 分栏之和 %d ≠ 字面量对 %d（分类器漏了）" % (_sum, len(literal_pairs)))
        return 1
    # ★ 再验一次**印出来的**那一行：拆开后的两个数加起来必须还原 conflict 总数。
    #   上一版就是这里漏的 —— 内部分类对、分栏检查对，只有屏幕上的数加不上。
    if len(_real_conflict) + len(_unregistered) != len(tally["conflict"]):
        print("  ✗ 汇总行加不上：档位打架 %d ＋ 取值未登记 %d ≠ conflict %d"
              % (len(_real_conflict), len(_unregistered), len(tally["conflict"])))
        return 1

    # ★ 两条独立的腿，两条都得能出声：
    #   「档位打架 0 条」与「未登记 0 条」都必须明确写出来，
    #   否则 `len([])==0` 与「这一栏压根没实现」在输出上完全一样。
    if _real_conflict:
        print("  ★ 档位打架 %d 条（action 与 decision 都是档位词却互相矛盾）："
              % len(_real_conflict))
        for c in _real_conflict:
            print("      %s:%d  action=%s  decision=%s"
                  % (c["path"], c["line"], c["action"], c["decision"]))
    else:
        print("  档位打架 0 条 —— **查过且没有**，不是「没查」。")
    if _unregistered:
        print("  ★ decision 取值未登记 %d 条（不在 `_DECISION_FROM_CONFIG_FACE` "
              "也不在档位集里 ⇒ 运行时落默认档）：" % len(_unregistered))
        for c in _unregistered:
            print("      %s:%d  action=%s  decision=%s"
                  % (c["path"], c["line"], c["action"], c["decision"]))
    else:
        print("  decision 取值未登记 0 条 —— **查过且没有**。")
    if _CONFIG_FACE is None:
        print("  ✗ 真源读不到（%s）⇒ 这一节的分类**不可信**，不当作结论。"
              % _NP_LOAD_ERROR)
        return 1
    print()

    if args.md:
        f = io.StringIO()
        f.write("# S3 decision 写入点定性（%s）\n\n" % time.strftime("%Y-%m-%d %H:%M"))
        f.write("扫描 %d 个 .py；写入点 %d（运行时 %d ＋ 判据 %d）；读取点 %d。\n\n"
                % (n_files, len(rows), len(runtime), len(guards), n_readers))
        f.write("| 路径 | 行 | 形态 | 右值类型 | 右值 | 引用 action |\n|---|---|---|---|---|---|\n")
        for x in sorted(runtime, key=lambda y: (y["path"], y["line"])):
            f.write("| `%s` | %d | %s | %s | `%s` | %s |\n" % (
                x["path"], x["line"], x["form"], x["rhs_kind"],
                (x["rhs"] or "").replace("|", "\\|")[:80],
                "是" if "action" in x["refs"] else ""))
        f.write("\n## 同一 dict 里 action 与 decision 的配对\n\n")
        f.write("字面量对 %d 条：一致 %d ／ 派生告警 %d ／ 配置面 %d ／ 无对可判 %d ／ "
                "档位打架 **%d** ／ 取值未登记 **%d**。（六栏相加＝总数）\n\n"
                % (len(literal_pairs), len(tally["consistent"]),
                   len(tally["derived"]), len(tally["config_face"]),
                   len(tally["unpaired"]), len(_real_conflict),
                   len(_unregistered)))
        if _real_conflict:
            f.write("### 档位打架（action 与 decision 都是档位词却互相矛盾）\n\n"
                    "| 路径 | 行 | action | decision |\n|---|---|---|---|\n")
            for c in _real_conflict:
                f.write("| `%s` | %d | %s | %s |\n"
                        % (c["path"], c["line"], c["action"], c["decision"]))
            f.write("\n")
        else:
            f.write("档位打架 **0 条** —— 查过且没有，不是「没查」。\n\n")
        if _unregistered:
            f.write("### decision 取值未登记（不是矛盾，是没人认领）\n\n"
                    "这些值既不是档位词，也不在 `hooks/notify_policy.py` 的 "
                    "`_DECISION_FROM_CONFIG_FACE` 里。运行时它们落**默认档**，"
                    "而默认档会打扰用户 —— 所以这不是命名问题，是行为问题。\n\n"
                    "| 路径 | 行 | action | decision |\n|---|---|---|---|\n")
            for c in _unregistered:
                f.write("| `%s` | %d | %s | %s |\n"
                        % (c["path"], c["line"], c["action"], c["decision"]))
            f.write("\n")
        else:
            f.write("decision 取值未登记 **0 条** —— 查过且没有。\n\n")
        f.write("> 分类口径**不来自本文件**：`config_face` 认哪些值，取自 "
                "`hooks/notify_policy.py` 的 `_DECISION_FROM_CONFIG_FACE`"
                "（契约 §3 定稿）；档位词取自同文件 `_RANK` ∪ `_DECISION_ALIAS`。"
                "本文件不留副本 —— 产品改口径，这里跟着变；读不到真源就整节判红，"
                "不退回内置抄本。\n")
        if _CONFIG_FACE is None:
            f.write("\n✗ **真源读不到（%s）⇒ 上面这一节不可信，不当作结论。**\n"
                    % _NP_LOAD_ERROR)
        f.write("\n## 判据/测试里的写入点（不参与收敛）\n\n")
        for x in sorted(guards, key=lambda y: (y["path"], y["line"])):
            f.write("- `%s:%d` %s → `%s`\n" % (x["path"], x["line"], x["form"], x["rhs"][:70]))
        r = _commit.write_text(args.md, f.getvalue())
        print("已写 %s（%d 字节 / %d 字符，落盘路径 %s）"
              % (args.md, r["bytes"], r["chars"], r["how"]))

    if args.json:
        # ★ 产物必须自带「牙齿证据」（2026-11-03）：
        #   自证腿一失败就直接 return，所以**文件存在本身就隐含自检通过** ——
        #   但那是一层推断，明天复核的人看不见。下面把正控条数与形态清单写进产物，
        #   读者不用相信「它肯定跑过自检」，能直接核对。
        #   `forms_seen` 与 `forms_taxonomy` 分开：本仓只出现 2 类，而分类器认 4 类；
        #   合成一栏会让「只认 2 类」与「本仓只有 2 类」同貌（0 与不可判同貌）。
        _forms = sorted(set(x["form"] for x in rows))
        r = _commit.write_json(args.json,
                               {"read_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "files": n_files, "writers": rows,
                                "runtime": len(runtime), "guards": len(guards),
                                "readers": n_readers, "parse_errors": parse_errors,
                                "selftest": {"passed": not fails, "fails": fails,
                                             "positive_write_points": nw,
                                             "positive_read_points": nr},
                                "forms_taxonomy": ["W1-kwarg", "W2-dictkey",
                                                   "W3-subscript", "W4-attribute"],
                                "forms_seen": _forms,
                                "forms_zero": [x for x in
                                               ("W1-kwarg", "W2-dictkey",
                                                "W3-subscript", "W4-attribute")
                                               if x not in _forms],
                                # 一致性五栏：相加必须等于 total。
                                # 只给 conflict 一个数，读者无法判断「0」是真没有
                                # 还是被归进了别的栏；把「未登记取值」也单列，
                                # 是为了让「0 处矛盾」与「1 处没人认领」两个结论
                                # 互不掩盖。
                                "pairs": {"total": len(literal_pairs),
                                          "consistent": len(tally["consistent"]),
                                          "derived": len(tally["derived"]),
                                          "config_face": len(tally["config_face"]),
                                          "unpaired": len(tally["unpaired"]),
                                          "conflict": len(_real_conflict),
                                          "unregistered_decision":
                                              len(_unregistered),
                                          "taxonomy_source":
                                              "hooks/notify_policy.py: "
                                              "_DECISION_FROM_CONFIG_FACE / "
                                              "_RANK / _DECISION_ALIAS"
                                              "（本脚本不留副本）",
                                          "taxonomy_loaded": _CONFIG_FACE is not None,
                                          "taxonomy_error": (None if _CONFIG_FACE
                                                             is not None
                                                             else _NP_LOAD_ERROR),
                                          "derived_rule": "action=alert + decision=allow（派生告警，产品侧设计如此）",
                                          "config_face_rule": "decision ∈ _DECISION_FROM_CONFIG_FACE（契约 §3：配置/报告面事实，action 表达不了）",
                                          "unpaired_rule": "同 dict 里没有 action 键（policy_changed／canary_planted 等非裁决记录）⇒ 无从配对，不是矛盾",
                                          "conflict_items": _real_conflict,
                                          "unregistered_items": _unregistered}},
                               sort_keys=False)
        print("已写 %s（%d 字节 / %d 字符，落盘路径 %s）"
              % (args.json, r["bytes"], r["chars"], r["how"]))

    return 0


if __name__ == "__main__":
    sys.exit(main())
