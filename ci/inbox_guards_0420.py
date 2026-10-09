#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""0.42.0 判据 —— `hook_slow` 从「记了却没人看」变成「报告里看得见」（P5-1）。

★★ 这一份判据的由来（《全类型报告审计》收尾时剩下的最后一项）：

    `hook_slow` 是 `AUDIT_SCHEMA.md` §4 **登记在案**的事件类型，写入侧
    （`hooks/pre_tool_use.py:3313`）写得忠诚信：超过 `SLOW_BUDGET_MS`（默认
    8000ms）就记一条，`elapsed_ms` / `tool` / `session` 全带。它存在的理由
    白纸黑字写在 §4：「宿主给钩子的超时是 10s(zcode)/15s(claude)，
    **超时=allow** ⇒ 慢到超时等于这张牌没打出去且无人知晓」。

    实测（真实工作区链 `D:/2026/PSL/.psl/audit/`，非本仓）：
        · **89 条**，跨 6 天（2026-09-28 .. 2026-10-09）
        · 最大 `elapsed_ms` = **2,476,295 ms ≈ 41 分钟**
        · 按工具：Bash 34 / WebSearch 24 / WebFetch 23 / Read 5 / Edit 2 …

    ⇒ 而**消费侧是零**：`scripts/report.py` 里唯一可能看见它的那一行是
      `elif ev.get("action") == "alert": stats["alerted"] += 1` —— **不分 type**。
      89 条真实信号被一个匿名通用计数吸收，读报告的人无法区分
      "有个钩子跑了 41 分钟" 与 "弹了一次气泡"。

    修法（沿用本仓 0.18.0 HP-47 处理 `hook_error` 的同一范式：
    "曾经只出现在原始 JSONL 里" ⇒ 纳入 `config_health` 并单独一行渲染）：
        · `config_health` 增 `hook_slow` 计数与 `hook_slow_max_ms` 最差值；
        · 文本报告单独一行（与 `sec_path_whitelisted` 同规格：必须让人看见）；
        · HTML 报告同一行；
        · JSON 出口自动跟随（`config_health` 通项导出）。

  ★ 为什么必须单独一行、不许并进 `alerts`：并进去就是这 89 条的老路 ——
    数字没错，但**读的人看不出它是什么**。`sec_path_whitelisted`（0.29.0 D-1）
    的注释已经把理由写死了："the one number a reviewer must not miss"。

  ★ 编写纪律（沿用 `inbox_guards_0400.py` 头部）：
    · 每条判据配负控，且负控**真的会红**（内存里变异源码后重载，不是"算一遍就丢"）；
    · 判据**只查行为/结构**，不查文案 —— 凡按源码字面查的，一律走 **AST**；
    · **不写任何产品文件**：合成事件全在内存里，`build_report` 的 `scan`/`manifest`
      参数传空值即可（`rules_descriptions(root=None)` 有兜底）。
"""
from __future__ import annotations

import ast
import io
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (ROOT, os.path.join(ROOT, "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

RESULTS = []


def check(name):
    """★ 判据**必须真会红** —— 返回说明串一律转成抛异常（同 0400 的收紧）。"""
    def deco(fn):
        def wrapper():
            r = fn()
            if r is True or r is None:
                return True
            raise AssertionError(r if isinstance(r, str) else repr(r))
        RESULTS.append((name, wrapper))
        return fn
    return deco


def _src(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _load_report(src=None):
    """把（可能被变异过的）`scripts/report.py` 源码加载成一个新模块对象。

    ★ 为什么可以这样做：`report.py` 只 import 标准库（argparse/csv/glob/gzip/
      hashlib/html/io/json/os/shutil/sys/tempfile/datetime/time/re/pathlib），
      没有仓内相对导入 ⇒ 在干净命名空间里 exec 不会缺依赖。
    ★ 变异只发生在内存里的这份字符串上，**磁盘文件一个字节都不动**。
    """
    if src is None:
        import report as _r                                   # noqa: F401
        return _r
    mod = types.ModuleType("report_mutated")
    mod.__file__ = os.path.join(ROOT, "scripts", "report.py")
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)    # noqa: S102
    return mod


def _synthetic_events():
    """三条 hook_slow ＋ 一条普通 post_tool_use（证明不是把总数蒙对）。"""
    base = {"type": "post_tool_use", "tool": "Bash", "session": "s1", "action": "allow"}
    slow = [
        {"type": "hook_slow", "tool": "Bash", "session": "s1", "decision": "allow",
         "severity": "warning", "action": "alert", "elapsed_ms": 9000},
        # 真实链上的最差值（≈41 分钟）——用真值，不用编造的整数
        {"type": "hook_slow", "tool": "WebSearch", "session": "s1", "decision": "allow",
         "severity": "warning", "action": "alert", "elapsed_ms": 2476295},
        {"type": "hook_slow", "tool": "Read", "session": "s2", "decision": "allow",
         "severity": "warning", "action": "alert", "elapsed_ms": 12000},
    ]
    return [base] + slow


def _report_of(mod):
    return mod.build_report(_synthetic_events(), scan=None, manifest={}, host_label="guard")


# ══════════ S35 · 计数必须真的进 config_health（含最差值）══════════════
@check("S35 ★ hook_slow 必须进 config_health：计数 3 ＋ 最差 2476295ms")
def s35():
    rep = _report_of(_load_report())
    ch = rep.get("config_health") or {}
    if ch.get("hook_slow") != 3:
        return "config_health.hook_slow = %r（应为 3）—— 89 条老路会原样复发" % ch.get("hook_slow")
    if ch.get("hook_slow_max_ms") != 2476295:
        return "config_health.hook_slow_max_ms = %r（应为 2476295）—— 只有计数没有最差，" \
               "读者仍分不清『8.1 秒一次』与『41 分钟一次』" % ch.get("hook_slow_max_ms")
    return True


@check("N-S35 负控：把 cfg 里的 hook_slow 键改个名 ⇒ S35 必须报红")
def n_s35():
    src = _src("scripts/report.py")
    mut = src.replace('"hook_slow": 0, "hook_slow_max_ms": 0',
                      '"hook_slow_renamed": 0, "hook_slow_max_ms": 0')
    if mut == src:
        return "负控无效：cfg 字面量里找不到 `\"hook_slow\": 0, \"hook_slow_max_ms\": 0`"
    rep = _report_of(_load_report(mut))
    ch = rep.get("config_health") or {}
    if ch.get("hook_slow") == 3:
        return "负控失效：键被改名后计数仍是 3（说明判据没在读这个键）"
    return True


# ══════════ S36 · 两个渲染面都必须单独一行（记了还要看得见）══════════════
@check("S36 ★ 文本与 HTML 都必须单独渲染 hook_slow（含最差值）")
def s36():
    mod = _load_report()
    rep = _report_of(mod)
    txt = mod.render_text(rep, "guard-synthetic")
    html = mod.render_html(rep, "guard-synthetic")
    if "hook slow (>= budget" not in txt:
        return "文本报告里没有 hook_slow 单独行 —— 又变成『只在原始 JSONL 里』"
    if "2476295" not in txt:
        return "文本报告没有最差值 —— 读者分不清量级"
    if "hook slow (>= budget" not in html:
        return "HTML 报告里没有 hook_slow 行（`--format html` 是默认交付面之一）"
    if "%(hookslow)s" in html:
        return "HTML 模板占位符没被替换 —— `%(hookslow)s` 原样漏到了输出里"
    return True


@check("N-S36 负控：摘掉文本渲染那一行 ⇒ S36 必须报红")
def n_s36():
    src = _src("scripts/report.py")
    lines = src.split("\n")
    anchor = 'L.append("  hook slow (>= budget; host timeout = ALLOW): %d | worst %d ms%s" % ('
    start = next((i for i, l in enumerate(lines) if anchor in l), None)
    if start is None:
        return "负控无效：找不到文本渲染行可供变异"
    # 语句跨 3 行：从 anchor 行起，到以 `if _hs_n else ""))` 收尾的行为止，
    # 整条摘成 `pass`（保留首行缩进，语法仍合法）。
    end = next((i for i in range(start, min(start + 6, len(lines)))
                if 'if _hs_n else ""))' in lines[i]), None)
    if end is None:
        return "负控无效：找不到渲染语句的收尾行"
    indent = lines[start][:len(lines[start]) - len(lines[start].lstrip())]
    mut = "\n".join(lines[:start] + [indent + "pass"] + lines[end + 1:])
    try:
        mod = _load_report(mut)
    except SyntaxError as e:
        return "负控无效：变异后的源码语法错误（%s）—— 修好变异本身" % e
    rep = _report_of(mod)
    txt = mod.render_text(rep, "guard-synthetic")
    if "hook slow (>= budget" in txt:
        return "负控失效：渲染行被摘掉后文本里仍然有这一行"
    return True


# ══════════ S37 · 计数必须走 cfg 通项通路，且渲染只许读 config_health ══════
@check("S37 ★ 结构：cfg 字面量含两键 ＋ `cfg[typ] += 1` 通路仍在 ＋ 导出是通项")
def s37():
    tree = ast.parse(_src("scripts/report.py"))
    br = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "build_report":
            br = node
            break
    if br is None:
        return "找不到 build_report()"
    keys, aug_ok, export_ok = set(), False, False
    for node in ast.walk(br):
        # (a) cfg = {...} 字面量里的键
        if isinstance(node, ast.Dict):
            for k in node.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str) \
                        and k.value.startswith("hook_slow"):
                    keys.add(k.value)
        # (b) 通项计数通路：cfg[typ] += 1
        if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add) \
                and isinstance(node.target, ast.Subscript) \
                and isinstance(node.target.value, ast.Name) \
                and node.target.value.id == "cfg":
            aug_ok = True
        # (c) 导出必须是通项（不许挑挑拣拣，否则新加的键会静默不进 JSON）
        if isinstance(node, ast.DictComp):
            export_ok = True
    if keys != {"hook_slow", "hook_slow_max_ms"}:
        return "cfg 字面量里的 hook_slow 族键 = %r（应为两个都在）" % sorted(keys)
    if not aug_ok:
        return "`cfg[typ] += 1` 通项计数通路不见了 —— 新事件类型会被静默漏掉"
    if not export_ok:
        return "config_health 的导出不再是通项推导 —— 手工挑键会让新键静默消失"
    return True


@check("N-S37 负控：把导出改成手工挑键 ⇒ S37 必须报红")
def n_s37():
    src = _src("scripts/report.py")
    old = '"config_health": {k: v for k, v in cfg.items()},'
    if old not in src:
        return "负控无效：找不到 config_health 通项导出行"
    mut = src.replace(old, '"config_health": {"hook_error": cfg.get("hook_error", 0)},')
    mod = _load_report(mut)
    rep = _report_of(mod)
    ch = rep.get("config_health") or {}
    if ch.get("hook_slow") == 3:
        return "负控失效：导出被改成手工挑键后计数仍是 3"
    return True


def main():
    print("=" * 78)
    print("0.42.0 判据 —— hook_slow 从「记了却没人看」到「报告里看得见」（P5-1）")
    print("（全部内存变异，不写任何产品文件）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                why = ""
            print("  ✅ %-58s %s" % (name, why or ""))
            ok += 1
        except AssertionError as e:
            print("  ❌ %-58s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-58s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
