#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""事件类型口径的**唯一权威量具**（0.33.1）。

★ 为什么需要它：同一个数被三处手写，于是三个数对不上 ——
    交接件写 24 ／ 文档逐行数 37 ／ `antinel_verify` 自扫 27。
  手写就会漂。判据：**事实由代码产生，描述由 schema 承载** ——
  所以以「代码里真的写了哪些 type」为权威，以「schema 是否登记」为检查项。

输出三组数：
  1) 代码中实际出现的记录 type（权威）
  2) AUDIT_SCHEMA.md §4 登记的类型
  3) 两个差集：
     - 代码有、schema 没登记  ⇒ **未登记**（INV 类问题，退出码 1）
     - schema 有、代码没写    ⇒ 陈旧登记或由别处产生（信息，不判失败）

用法：
    python tools/verify_event_types.py            # 人类可读
    python tools/verify_event_types.py --json     # 机器可读
    python tools/verify_event_types.py --count    # 只打印权威总数（给文案用）
"""
import ast
import io
import json
import re
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
SCHEMA = PKG / "docs" / "AUDIT_SCHEMA.md"

#: 审计记录的辨识判据：dict 字面量同时含 "type" 与下面任一字段。
#: 只认这个形状，避免把 MCP 的 {"type": "text"}、JSON-Schema 的 {"type": "object"}
#: 当成事件类型（0.33.1 实测：宽正则会把 command/text/object/integer 一起抓进来）。
AUDIT_SHAPE_KEYS = {"ts", "tool", "session", "chain"}

SCAN_DIRS = ("hooks", "scripts", "tools", ".")
SKIP_PREFIX = ("antinel-0.29", "build", "dist", "antinel.egg-info", "__pycache__", ".")


def _iter_sources():
    seen = set()
    for d in SCAN_DIRS:
        base = PKG if d == "." else PKG / d
        if not base.is_dir():
            continue
        for p in sorted(base.glob("*.py")):
            rel = p.relative_to(PKG).as_posix()
            if rel.startswith(SKIP_PREFIX) or rel in seen:
                continue
            seen.add(rel)
            yield rel, p


def code_types():
    """返回 (常量类型集合, 家族前缀集合)。

    ★ 只认**两种有据的写法**，不做裸子串匹配（后者正是上次误抓的来源，
      会把 MCP 的 {"type":"text"} 与字段名 `hash`/`files` 一起抓进来）：
        A) dict 字面量：`rec = {"type": "x", "ts": ...}`
        B) 位置参数：`record(audit_dir, "x", ...)`（host_shield.py 的写法，第 2 个位置参数）
    0.33.1 实测：只做 (A) 会漏掉 host_shield_* 全家族 10 个 ⇒ 断言"未登记 0"会变成**假绿**。
    """
    constants, families = set(), set()
    for rel, path in _iter_sources():
        try:
            tree = ast.parse(io.open(path, encoding="utf-8", errors="replace").read())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                keys = {}
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        keys[k.value] = v
                if "type" not in keys or not (AUDIT_SHAPE_KEYS & set(keys)):
                    continue
                v = keys["type"]
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    constants.add(v.value)
                elif isinstance(v, ast.JoinedStr):
                    head = ""
                    for part in v.values:
                        if isinstance(part, ast.Constant) and isinstance(part.value, str):
                            head += part.value
                        else:
                            break
                    if head:
                        families.add(head.rstrip("_"))
            elif isinstance(node, ast.Call):
                fn = node.func
                name = fn.id if isinstance(fn, ast.Name) else (
                    fn.attr if isinstance(fn, ast.Attribute) else "")
                if name != "record" or len(node.args) < 2:
                    continue
                a1 = node.args[1]
                if isinstance(a1, ast.Constant) and isinstance(a1.value, str):
                    constants.add(a1.value)
    return constants, families


def schema_types():
    """解析 AUDIT_SCHEMA.md §4（记录类型枚举）里表格首列的反引号标识符。"""
    if not SCHEMA.is_file():
        return set()
    text = io.open(SCHEMA, encoding="utf-8", errors="replace").read()
    m = re.search(r"^##\s*4\..*?$(.*?)^##\s*5\.", text, re.S | re.M)
    section = m.group(1) if m else text
    out = set()
    for line in section.splitlines():
        mm = re.match(r"^\|\s*`([a-z][a-z0-9_]{1,40})`\s*\|", line)
        if mm:
            out.add(mm.group(1))
    return out


def main():
    constants, families = code_types()
    registered = schema_types()

    expanded = set(constants)
    for fam in families:
        expanded |= {t for t in registered if t.startswith(fam + "_")}

    unregistered = sorted(t for t in constants if t not in registered
                          and not any(t.startswith(f + "_") for f in families))
    stale = sorted(registered - expanded)

    if "--json" in sys.argv:
        print(json.dumps({
            "code_total": len(expanded),
            "code_constants": sorted(constants),
            "code_families": sorted(families),
            "schema_total": len(registered),
            "unregistered": unregistered,
            "stale_in_schema": stale,
        }, ensure_ascii=False, indent=2))
        return 1 if unregistered else 0

    if "--count" in sys.argv:
        print(len(expanded))
        return 1 if unregistered else 0

    print("事件类型口径（权威＝代码）")
    print("  代码中实际的 type 常量 : %d" % len(constants))
    print("  代码中的 f-string 家族 : %d  %s" % (len(families), sorted(families)))
    print("  ⇒ 展平后总数         : %d" % len(expanded))
    print("  AUDIT_SCHEMA.md §4 登记: %d" % len(registered))
    print()
    if unregistered:
        print("  ✗ 代码有、schema 未登记（%d）:" % len(unregistered))
        for t in unregistered:
            print("      · %s" % t)
    else:
        print("  ✓ 代码里出现的 type 全部已在 schema 登记")
    if stale:
        print()
        print("  · schema 有、代码里没直接写（%d，信息非失败；可能是家族展开或由外部产生）:"
              % len(stale))
        print("      " + ", ".join(stale[:24]) + (" …" if len(stale) > 24 else ""))
    return 1 if unregistered else 0


if __name__ == "__main__":
    sys.exit(main())
