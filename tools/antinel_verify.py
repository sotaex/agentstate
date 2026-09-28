#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""antinel verify (A-8, v1.40 §8.7) - status derivation for a judgment record.

Compares the CURRENT bytes of every file covered by a judgment's `digests`
against the recorded digests, and derives the record status:

    current     every covered file hashes to its recorded value
    superseded  at least one covered file differs (auto-derived, V7 rule 1)
    unreadable  a covered file is missing (also a supersession, named apart)

The record itself is never modified: `status` here is DERIVED, not written
(V7 rule 3: the original credential is append-only). Any third party can run
this against a clone of the repo - no trust in us required.

Usage:
  python tools/antinel_verify.py                    # verify <pkg>/psl/judgment.json digests
  python tools/antinel_verify.py path/to/judgment.json
  python tools/antinel_verify.py --manifest         # verify ALL files in psl/manifest.json (0.17.0, P-B1)
  python tools/antinel_verify.py --invariants       # 0.29.0: 结构性不变量（不是哈希，是"规矩还在不在"）
  python tools/antinel_verify.py --json

Exit codes: 0 = current, 1 = superseded/unreadable, 2 = cannot verify.
Python 3.10+, stdlib only, no network.
"""
import argparse
import ast
import hashlib
import json
import re
import sys
from pathlib import Path

def _resolve_pkg():
    """定位包根。两种布局都要支持：

      · 随包布局：`<pkg>/tools/antinel_verify.py`  ⇒ 包根 = 上两级
      · 源仓布局：`<repo>/antinel_verify.py`        ⇒ 包根 = 上一级（r1v3 的 tools/ 不是包根）

    ★ 判据用「包根下有没有 rules/default.json」，不用目录名猜 —— 否则在源仓里跑
      会指向 `D:/psl/poc/`（不是包），报一堆"找不到文件"的假失败。
    """
    here = Path(__file__).resolve().parent
    for cand in (here.parent, here):
        if (cand / "rules" / "default.json").is_file():
            return cand
    return here.parent


PKG = _resolve_pkg()
DEFAULT = PKG / "psl" / "judgment.json"

# =============================================================== 0.29.0 不变量 ====
# ★ 为什么要有这个模式（本项目的铁律）：
#     「无检查项的禁令 ＝ 没有禁令」。
#   0.28.4 之前，好几条纪律只写在**注释和文档**里，没有任何东西会在它被破坏时变红：
#     · 兜底规则表可以悄悄比主规则表窄（G-1 实测就是如此，网络外传检测静默退化）；
#     · 扫描排除表可以悄悄吃掉"崩溃上报/会话历史"（G-9 实测就是如此，失明无报错）；
#     · 版本号可以悄悄漂移（`server.json` 落后 4 个版本、`AUDIT_SCHEMA.md` 抬头落后 2 版）；
#     · 代码可以往审计链里写一个**契约里没有登记**的事件类型（实测 7 个）。
#   注释拦不住这些。**能拦住的只有会红的检查项。** 本模式就是那批检查项。
#
# ★ 这里**不做任何哈希校验**（那是 --manifest 的活）。这里校验的是"结构还在不在"：
#   规矩被悄悄删掉时，哈希是**通过**的（文件被改了、哈希也跟着重算了）。
#   两种校验互补：--manifest 防"文件被改"，--invariants 防"规矩被删"。

# 与 pre_tool_use.py 的匹配种类标签、install.py 的钩子配置类型区分开：
# 这两个字符串**不是审计事件类型**，是规则/配置字段的值。显式维护排除表 ——
# 「无排除表的检查器 ＝ 会误报的检查器」。
_NON_EVENT_TYPE_KEYS = ("file_content", "process")

# INV-3：版本承载件。HARD = 必须与主版本一致；INFO = 只报告不判定。
# ★ 正则必须**精确指向"声明的版本"**。实测教训：`references/THREAT_MODEL.md` 里
#   正文提到 `v0.28.3`，用"第一个 vX.Y.Z"会把它当成声明版本 ⇒ 假命中、假报警。
_VERSION_HARD = (
    ("antinel.py",                  r'^VERSION\s*=\s*"([^"]+)"'),
    ("antinel_mcp.py",              r'"version"\s*:\s*"([^"]+)"'),
    ("rules/default.json",          r'"version"\s*:\s*"([^"]+)"'),
    ("pyproject.toml",              r'^version\s*=\s*"([^"]+)"'),
    ("server.json",                 r'"version"\s*:\s*"([^"]+)"'),
    ("psl/manifest.json",           r'"version"\s*:\s*"([^"]+)"'),
    ("docs/AUDIT_SCHEMA.md",        r'随\s*v(\d+\.\d+\.\d+)'),
    ("build_package.py",            r'^VERSION\s*=\s*"([^"]+)"'),
)
_VERSION_INFO = (("scripts/run_harness.py", r'(\d+\.\d+\.\d+)'),)


def _assign_node(tree, name):
    """在模块顶层找 `NAME = <expr>` 这个赋值节点（找不到返回 None）。"""
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return node.value
    return None


def _project_tuple(expr, consts):
    """受限求值 `tuple(<elt> for <vars> in NAME)` —— **只认这一个形状**。

    ★ 为什么需要它：`antinel.py` 里 `_RESIDUE_GUARD_PAIRS` 写成
      `tuple((k, k) for k, _lbl in _RESIDUE_SUBDIRS)`，刻意让配对表**由观察项
      名单推导**（单一真源，不手抄第二份）。这是**正确的语义**，但它的
      AST 是 `ast.Call`，`ast.literal_eval` 会直接抛错 ⇒ 旧版 `_ast_literal`
      返回 None ⇒ INV-2 误报成「无法解析」。

    ★ 为什么不是「干脆执行它」：本校验器的**设计前提是不执行被测代码**
      （见 `_ast_literal` docstring）。所以这里只做**形状受限**的静态求值：
        1) 外层必须是 `tuple(GENEXPR)`；
        2) GENEXPR 必须恰好是「一个 for、零个 if」的简单推导；
        3) 被迭代的 NAME 必须在同一文件里已能解析为**字面量序列**（consts）；
        4) `<elt>` 只允许由**循环变量 + 字面量**构造的 tuple/list/常量，
           **不允许**任何 Call / Attribute / Subscript / 比较等 —— 一旦出现
           就返回 None（宁可判「无法解析」，也不去"执行"未知代码）。

    ★ 代价（已知、且故意）：这只覆盖**这一种**推导形状。将来若有人把配对表
      改写成 `dict(...)`、`set(...)`、带 `if` 的推导、或调用函数，本函数会
      重新返回 None、INV-2 会变红。**那是正确行为** —— 红的意思是「量具读不懂
      这个新形状了」，它会逼着人来这里扩展白名单，而不是静默地"以为查过了"。
    """
    if not isinstance(expr, ast.Call):
        return None
    if not (isinstance(expr.func, ast.Name) and expr.func.id == "tuple"):
        return None
    if len(expr.args) != 1 or expr.keywords:
        return None
    gen = expr.args[0]
    if not isinstance(gen, ast.GeneratorExp):
        return None
    if len(gen.generators) != 1:
        return None
    g = gen.generators[0]
    if g.ifs or g.is_async:
        return None
    src = consts.get(g.iter.id) if isinstance(g.iter, ast.Name) else None
    if not isinstance(src, (list, tuple)):
        return None
    # 循环变量名（仅支持纯 Name 或一层 Tuple 解包）
    if isinstance(g.target, ast.Name):
        var_names = [g.target.id]
    elif isinstance(g.target, ast.Tuple):
        if not all(isinstance(e, ast.Name) for e in g.target.elts):
            return None
        var_names = [e.id for e in g.target.elts]
    else:
        return None

    def _safe_eval(node, env):
        """只允许：常量、循环变量、由二者搭出的 tuple/list。其余一律失败。"""
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            raise ValueError("名字不在环境里：%s" % node.id)
        if isinstance(node, ast.Tuple):
            return tuple(_safe_eval(e, env) for e in node.elts)
        if isinstance(node, ast.List):
            return [_safe_eval(e, env) for e in node.elts]
        raise ValueError("不支持的表达式：%s" % type(node).__name__)

    out = []
    for row in src:
        vals = list(row) if isinstance(row, (list, tuple)) else [row]
        if len(vals) < len(var_names):
            return None
        try:
            out.append(_safe_eval(gen.elt, dict(zip(var_names, vals))))
        except Exception:
            # ★ 关键：形状不认识时**返回 None**（＝"无法解析"），
            #   绝不把异常抛给调用方。校验器崩掉和校验器判红是两回事 ——
            #   崩掉会连 INV-2 之外的东西一起带走，而且看起来像"工具坏了"
            #   而不是"这里有东西要人看"。（这条是负控 4 实测出来的。）
            return None
    return tuple(out)


def _ast_literal(path, name):
    """从 .py 里取出一个**字面量赋值**（`NAME = [...]`），不执行该文件。

    ★ 为什么不用 import：钩子文件 import 时会跑模块级代码。校验器应该是
      **纯只读**的，不应该为了读一个常量而执行被测代码。

    ★ 0.33.1 夜间修订：除纯字面量外，另接受**形状受限的推导式**
      （`tuple((k, k) for k, _lbl in OTHER)`），见 `_project_tuple`。
      动机：`_RESIDUE_GUARD_PAIRS` 刻意由 `_RESIDUE_SUBDIRS` 推导以避免
      手抄第二份真源，是**正确的语义**，此前却把 INV-2 打红（量具读不懂，
      不是产品出错）。
    """
    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None
    node = _assign_node(tree, name)
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except Exception:
        pass
    # 退一步：收集同文件里**所有**可解析的顶层字面量，供推导式引用。
    consts = {}
    for n in getattr(tree, "body", []):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    try:
                        consts[t.id] = ast.literal_eval(n.value)
                    except Exception:
                        pass
    return _project_tuple(node, consts)


def _find(*rels):
    for rel in rels:
        p = PKG / rel
        if p.is_file():
            return p
    return None


def inv1_fallback_sync(ok_list, bad_list):
    """INV-1（G-1）：内置兜底规则表**不得比主规则表窄**。

    ★ 这条不变量是 0.28.4 一个真缺陷的直接产物：`_FALLBACK` 的 NET-01 是
      `["Bash"]`，而 `rules/default.json` 的 NET-01 是
      `["Bash","WebFetch","WebSearch","MCP"]`。规则文件一读不到，网络外传检测就
      **静默退化**成只认 Bash —— WebFetch/WebSearch/MCP 三条通道当场失守，零报错。
    """
    ptu = _find("hooks/pre_tool_use.py", "pre_tool_use.py")
    rules_p = _find("rules/default.json")
    if not ptu or not rules_p:
        bad_list.append("INV-1 跳过：找不到 pre_tool_use.py 或 rules/default.json")
        return
    fb = _ast_literal(ptu, "_FALLBACK")
    if not isinstance(fb, list):
        bad_list.append("INV-1 失败：无法从 %s 解析 _FALLBACK" % ptu)
        return
    try:
        rl = {r["id"]: r for r in json.loads(rules_p.read_text(encoding="utf-8")).get("rules", [])}
    except Exception as e:
        bad_list.append("INV-1 失败：rules/default.json 解析异常 %s" % e)
        return
    problems = []
    for r in fb:
        rid = r.get("id")
        full = rl.get(rid)
        if full is None:
            problems.append("%s：兜底表有、主规则表没有（凭空多出的规则）" % rid)
            continue
        # (a) apply_to_tools 必须完全相等 —— 窄一格就是静默失守
        a, b = set(r.get("apply_to_tools") or []), set(full.get("apply_to_tools") or [])
        if a != b:
            problems.append("%s：apply_to_tools 不一致 兜底=%s 主表=%s"
                            % (rid, sorted(a) or "(空=全部)", sorted(b) or "(空=全部)"))
        # (b) severity 必须相等
        if (r.get("severity") or "").lower() != (full.get("severity") or "").lower():
            problems.append("%s：severity 不一致 %s vs %s"
                            % (rid, r.get("severity"), full.get("severity")))
        # (c) 模式必须是主表的子集（兜底可以更窄，但不得凭空多出模式）
        for key in ("command_patterns", "file_patterns", "content_patterns"):
            fa, ra = set(r.get(key) or []), set(full.get(key) or [])
            extra = fa - ra
            if extra:
                problems.append("%s：兜底表 %s 有主表没有的模式 %s"
                                % (rid, key, sorted(extra)[:2]))
        # (d) ★ 2026-09-26 新增：中文说明必须**非空且与主表相等**。
        #     为什么：兜底集启用的时刻（规则文件被判篡改／读不到）**正是最需要人看懂的时刻**，
        #     而它原本只有英文 `description`，没有 `description_zh`/`remediation_zh` ⇒
        #     钩子拼出的理由里这两个字段取 `""`，用户看到的是
        #         `[NET-01] 提醒: `     ← 冒号后面是空的
        #     实测：`_strict_test/repro_a4.py`（篡改 rules_hash 后跑 PreToolUse）。
        #     「报出来≠出事了」不适用于这里 —— 这里是**该报的没报出来**，而且是降级态。
        for key in ("description_zh", "remediation_zh"):
            if not (r.get(key) or "").strip():
                problems.append("%s：兜底表 %s 为空（降级模式下理由会是空白）" % (rid, key))
            elif (r.get(key) or "") != (full.get(key) or ""):
                problems.append("%s：%s 与主表不一致" % (rid, key))
    if problems:
        bad_list.append("INV-1 失败：兜底表与主规则表不同步（%d 处）" % len(problems))
        for x in problems[:12]:
            bad_list.append("        · " + x)
    else:
        ok_list.append("INV-1 兜底表与主规则表同步：%d 条兜底规则逐条对齐（apply_to_tools 全等、"
                       "模式为主表子集）" % len(fb))
    # 覆盖率是**信息**，不是失败：兜底表本来就允许是子集
    missing = sorted(set(rl) - {r.get("id") for r in fb})
    ok_list.append("INV-1 信息：主表 %d 条，兜底 %d 条，兜底未覆盖 %d 条（%s…）"
                   % (len(rl), len(fb), len(missing), ", ".join(missing[:6])))


def inv2_residue_has_check(ok_list, bad_list):
    """INV-2（G-9）：**每一处"跳过"都必须有一条观察项盯着**。

    ★ 这是「无检查项的禁令 ＝ 没有禁令」的直接落地。0.28.4 的
      `_SCAN_SKIP_DIRS` 把崩溃上报/会话历史/日志/诊断整类跳过，而**没有任何
      地方报告它们的存在** —— 于是"没查"被伪装成"没发现"。现在每一条跳过
      都必须在 `_RESIDUE_SUBDIRS` 里有对应观察项，否则本项变红。
    """
    ap = _find("antinel.py")
    if not ap:
        bad_list.append("INV-2 跳过：找不到 antinel.py")
        return
    skip = _ast_literal(ap, "_SCAN_SKIP_DIRS")
    residue = _ast_literal(ap, "_RESIDUE_SUBDIRS")
    pairs = _ast_literal(ap, "_RESIDUE_GUARD_PAIRS")
    if not isinstance(skip, (set, list)) or not isinstance(residue, (list, tuple)) \
            or not isinstance(pairs, (list, tuple)):
        bad_list.append("INV-2 失败：无法解析 _SCAN_SKIP_DIRS / _RESIDUE_SUBDIRS / "
                        "_RESIDUE_GUARD_PAIRS")
        return
    skip = set(skip)
    residue_names = {str(r[0]) for r in residue if r}
    problems = []
    for pair in pairs:
        kw, obs = str(pair[0]), str(pair[1])
        if kw not in skip:
            problems.append("「%s」已不在 _SCAN_SKIP_DIRS 里，配对表过期（应同步更新）" % kw)
        if obs not in residue_names:
            problems.append("「%s」仍在跳过，但观察项「%s」不存在 ⇒ 又变成失明" % (kw, obs))
    if problems:
        bad_list.append("INV-2 失败：跳过项与观察项不配对（%d 处）" % len(problems))
        for x in problems[:12]:
            bad_list.append("        · " + x)
    else:
        ok_list.append("INV-2 跳过项与观察项配对：%d 对全部成立（观察项 %d 条）"
                       % (len(pairs), len(residue)))


def inv3_version_consistency(ok_list, bad_list):
    """INV-3：版本号不得漂移。

    ★ 动机：此前**没有任何守卫**扫版本号（实测 0 命中）。`server.json`（**配置者读的
      MCP 清单**）落后 4 个版本、`AUDIT_SCHEMA.md` 抬头落后 2 版，都是靠人眼发现的。
      「发布前必手扫版本号」如果只写在备忘里，就等于没有。
    ★ 只在文件存在时校验；**缺哪些文件会明说**，不假装查过。
    """
    found, missing, seen = {}, [], {}
    for rel, rx in _VERSION_HARD:
        # 源仓布局里 AUDIT_SCHEMA.md 在根、随包布局里在 docs/ —— 只在 `docs/` 前缀上回退，
        # 不做通用回退（否则会把同名但不同用途的文件当成版本承载件）。
        cands = [PKG / rel]
        if rel.startswith("docs/"):
            cands.append(PKG / rel.split("/", 1)[1])
        p = next((c for c in cands if c.is_file()), None)
        if p is None:
            missing.append(rel)
            continue
        try:
            s = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            missing.append(rel + "(读不到)")
            continue
        m = re.search(rx, s, re.M)
        if not m:
            missing.append(rel + "(未匹配到版本声明)")
            continue
        found[rel] = m.group(1)
        seen.setdefault(m.group(1), []).append(rel)
    if not found:
        bad_list.append("INV-3 失败：一个版本承载件都没找到（包结构不对？）")
        return
    if len(seen) > 1:
        bad_list.append("INV-3 失败：版本号不一致 —— %s"
                        % " ｜ ".join("%s ← %s" % (v, ", ".join(fs))
                                      for v, fs in sorted(seen.items())))
    else:
        v = list(seen)[0]
        ok_list.append("INV-3 版本一致：%s（%d 个承载件：%s）"
                       % (v, len(found), ", ".join(sorted(found))))
    if missing:
        ok_list.append("INV-3 信息：未校验 %d 个（不存在或不含版本声明）：%s"
                       % (len(missing), ", ".join(missing)))
    for rel, rx in _VERSION_INFO:
        p = PKG / rel
        if p.is_file():
            m = re.search(rx, p.read_text(encoding="utf-8", errors="replace"))
            if m:
                ok_list.append("INV-3 信息：%s 首个版本样字符串 = %s（**只报告**，"
                               "该文件正文可能提到别的版本）" % (rel, m.group(1)))


def inv4_rules_self_consistent(ok_list, bad_list):
    """INV-4：规则表自洽（id 唯一 / severity 合法 / apply_to_tools 非空 / 无 ReDoS 形态 /
    description 非空）。"""
    p = _find("rules/default.json")
    if not p:
        bad_list.append("INV-4 跳过：找不到 rules/default.json")
        return
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        bad_list.append("INV-4 失败：rules/default.json 解析异常 %s" % e)
        return
    rules = d.get("rules") or []
    ids = [r.get("id") for r in rules]
    problems = []
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        problems.append("id 重复：%s" % dup)
    ok_sev = {"critical", "warning", "info"}
    # 与 pre_tool_use.py 同一套 ReDoS 静态筛（嵌套量词/量词下的择一）
    nest = re.compile(r"\((?:[^()\\]|\\.)*(?:[+*]|\{\d+,\})\s*\)(?:[+*]|\{\d+,\})")
    altq = re.compile(r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)(?:[+*]|\{\d+,\})")
    for r in rules:
        rid = r.get("id") or "(无 id)"
        if (r.get("severity") or "").lower() not in ok_sev:
            problems.append("%s：severity 非法 %r" % (rid, r.get("severity")))
        if not (r.get("apply_to_tools") or []):
            problems.append("%s：apply_to_tools 为空（= 适用于全部工具，通常不是本意）" % rid)
        if not (r.get("description") or "").strip():
            problems.append("%s：缺 description" % rid)
        for key in ("command_patterns", "file_patterns", "content_patterns", "exclude_patterns"):
            for pat in (r.get(key) or []):
                if not isinstance(pat, str):
                    problems.append("%s：%s 里有非字符串" % (rid, key))
                elif nest.search(pat) or altq.search(pat):
                    problems.append("%s：%s 有 ReDoS 形态 —— %s" % (rid, key, pat[:50]))
    if problems:
        bad_list.append("INV-4 失败：规则表不自洽（%d 处）" % len(problems))
        for x in problems[:12]:
            bad_list.append("        · " + x)
    else:
        ok_list.append("INV-4 规则表自洽：%d 条规则，id 唯一、severity 合法、"
                       "apply_to_tools 非空、无 ReDoS 形态" % len(rules))


def inv5_rule_count_not_stale(ok_list, bad_list):
    """INV-5：**凡会变的数不许写死**。

    ★ 项目里有前车之鉴：规则数从 24 变 25 时，站上 15 处硬编码的"24 条规则"
      全变成假数字，**且没有任何报错**。规则表自己的 description 里那个条数
      是最容易腐坏的一处，所以单独盯。
    """
    p = _find("rules/default.json")
    if not p:
        bad_list.append("INV-5 跳过：找不到 rules/default.json")
        return
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        bad_list.append("INV-5 失败：解析异常 %s" % e)
        return
    n = len(d.get("rules") or [])
    desc = d.get("description") or ""
    m = re.search(r"(\d+)\s*rules", desc)
    if not m:
        bad_list.append("INV-5 失败：description 里没有「N rules」，无法校验（应写明条数）")
        return
    if int(m.group(1)) != n:
        bad_list.append("INV-5 失败：description 写着 %s 条，实际 %d 条（假数字）"
                        % (m.group(1), n))
    else:
        ok_list.append("INV-5 规则条数与 description 一致：%d" % n)


def inv6_audit_types_registered(ok_list, bad_list):
    """INV-6：**写进审计链的事件类型，必须登记在随包 AUDIT_SCHEMA.md**。

    ★ 这是契约纪律「没登记 ≠ 不存在」的落地。链上写着一个类型、随包契约里没有它，
      第三方复核就无从知道那个字段是什么意思。
      ★ 实测（0.29.0 首次跑）：22 个类型里 **7 个未登记** —— 契约早已不成立，
        而没有任何东西会红。现在会了。
    ★ 排除表显式维护（`file_content` 是规则类型标签、`process` 是钩子配置类型，
      都不是审计事件），避免误报。
    """
    schema = _find("docs/AUDIT_SCHEMA.md", "AUDIT_SCHEMA.md")
    if not schema:
        bad_list.append("INV-6 跳过：找不到 AUDIT_SCHEMA.md")
        return
    try:
        text = schema.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        bad_list.append("INV-6 失败：AUDIT_SCHEMA.md 读不到 %s" % e)
        return
    srcs = ["hooks/pre_tool_use.py", "pre_tool_use.py", "hooks/post_tool_use.py",
            "post_tool_use.py", "session_dna.py", "host_shield.py", "audit_chain.py",
            "antinel.py", "hub.py"]
    rx = re.compile(r'"type"\s*:\s*"([a-z][a-z0-9_]*)"')
    allt = {}
    for rel in srcs:
        p = PKG / rel
        if not p.is_file():
            continue
        try:
            s = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for t in set(rx.findall(s)):
            allt.setdefault(t, set()).add(rel)
    if not allt:
        bad_list.append("INV-6 失败：一个事件类型都没扫到（文件布局不对？）")
        return
    unreg = {t: v for t, v in allt.items()
             if t not in _NON_EVENT_TYPE_KEYS and ("`%s`" % t) not in text}
    if unreg:
        bad_list.append("INV-6 失败：%d 个事件类型写进了审计链但未登记在 AUDIT_SCHEMA.md"
                        % len(unreg))
        for t, v in sorted(unreg.items()):
            bad_list.append("        · %-34s %s" % (t, ",".join(sorted(v))))
    else:
        ok_list.append("INV-6 审计事件类型全部已登记：扫到 %d 个，"
                       "AUDIT_SCHEMA.md 全部有（已排除 %d 个非事件键）"
                       % (len(allt), len(_NON_EVENT_TYPE_KEYS)))


def run_invariants(as_json=False):
    ok_list, bad_list = [], []
    for fn in (inv1_fallback_sync, inv2_residue_has_check, inv3_version_consistency,
               inv4_rules_self_consistent, inv5_rule_count_not_stale,
               inv6_audit_types_registered):
        try:
            fn(ok_list, bad_list)
        except Exception as e:
            bad_list.append("%s 异常：%s: %s" % (fn.__name__, type(e).__name__, e))
    out = {"mode": "invariants", "package_root": str(PKG),
           "status": "ok" if not bad_list else "violated",
           "passed": len(ok_list), "failed": len(bad_list),
           "ok": ok_list, "violations": bad_list,
           "note": "本模式不做哈希校验（那是 --manifest）。这里校验的是"
                   "「规矩还在不在」—— 规矩被删掉时哈希反而是通过的。"}
    if as_json:
        print(json.dumps(out, ensure_ascii=False, indent=1))
    else:
        print("== Antinel 结构性不变量（%s）" % PKG)
        for x in ok_list:
            print("  [OK]   %s" % x)
        for x in bad_list:
            print("  [FAIL] %s" % x)
        print()
        print("[%s] 通过 %d ／ 违反 %d"
              % ("OK" if not bad_list else "VIOLATED", len(ok_list), len(bad_list)))
    return 0 if not bad_list else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="Derive the status of an Antinel judgment record")
    ap.add_argument("judgment", nargs="?", default=str(DEFAULT),
                    help="path to judgment.json (default: <pkg>/psl/judgment.json)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--manifest", action="store_true",
                    help="verify every file listed in psl/manifest.json instead of the "
                         "judgment digests (closes the 16-file verification gap, audit N6)")
    ap.add_argument("--invariants", action="store_true",
                    help="0.29.0: check structural invariants (fallback-table sync, "
                         "skip/observation pairing, version consistency, rule-set "
                         "self-consistency, audit-type registration) -- catches rules "
                         "being quietly DELETED, which hash verification cannot")
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if a.invariants:
        return run_invariants(as_json=a.json)

    jpath = Path(a.judgment)
    try:
        rec = json.loads(jpath.read_text(encoding="utf-8"))
    except Exception as e:
        print(json.dumps({"status": "error", "reason": "judgment unreadable: %s" % e}))
        return 2

    if a.manifest:
        mpath = PKG / "psl" / "manifest.json"
        try:
            man = json.loads(mpath.read_text(encoding="utf-8"))
        except Exception as e:
            print(json.dumps({"status": "error", "reason": "manifest unreadable: %s" % e}))
            return 2
        digests = man.get("files") or {}
        base = mpath.resolve().parent.parent
        scope = "manifest (%d files)" % len(digests)
    else:
        digests = rec.get("digests") or {}
        base = jpath.resolve().parent.parent          # digests are package-relative
        scope = "judgment digests (%d files)" % len(digests)
    if not digests:
        print(json.dumps({"status": "error", "reason": "no digests to verify (%s)" % scope}))
        return 2
    changed, missing, checked = [], [], 0
    for rel, want in sorted(digests.items()):
        f = base / rel
        checked += 1
        if not f.is_file():
            missing.append(rel)
            continue
        got = "sha256:" + hashlib.sha256(f.read_bytes()).hexdigest()
        if got != want:
            changed.append({"file": rel, "recorded": want[:23], "live": got[:23]})
    if changed:
        status, reason = "superseded", "%d of %d covered files differ (%s)" % (
            len(changed), checked, scope)
    elif missing:
        status, reason = "superseded", "%d of %d covered files are missing (%s)" % (
            len(missing), checked, scope)
    else:
        status, reason = "current", "all %d covered files hash to their recorded digests (%s)" % (
            checked, scope)
    out = {"status": status, "reason": reason, "checked": checked,
           "mode": "manifest" if a.manifest else "judgment",
           "changed": changed, "missing": missing,
           "record_verdict": rec.get("verdict"),
           "rule": "any failed verification supersedes the record (append-only; "
                   "this tool never edits the credential)"}
    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=1))
    else:
        mark = {"current": "OK", "superseded": "SUPERSEDED"}.get(status, status.upper())
        print("[%s] %s" % (mark, reason))
        for c in changed:
            print("  changed: %s\n    recorded %s...\n    live     %s..." % (c["file"], c["recorded"], c["live"]))
        for m in missing:
            print("  missing: %s" % m)
    return 0 if status == "current" else 1


if __name__ == "__main__":
    sys.exit(main())
