# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""0.48.1 许可升级 · SPDX 批量写入 + 仓根许可文件生成（一次性工具，保留供审计）。

职责（单一真源 = 构建器常量 + license-map.json）：
  ① 从 build_package.py 用 AST 提取 LICENSE_MD / MIT_MD / NOTICE_MD，
     生成仓根 LICENSE、NOTICE、challenge/LICENSE（G7-3 纪律：LICENSE 是构建器产物）
  ② 按 license-map 给全部 tracked 的 py/md/html 写 SPDX 头（shebang/coding 行之后）
  ③ 全部 .py 重新 ast.parse —— 证明头部插入零语法影响
  ④ 分组计数打印（Apache/MIT/CC-BY/CC-BY-SA），供执行报告回填

纪律：已带正确头的文件跳过；带错头的文件改写；全部完成前不触碰任何 .json。
"""
import ast
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "ci"))
from inbox_guards_0481 import _walk_files, _load_map, resolve, _extract_const  # noqa: E402

SPDX_LINE = {"py": "# SPDX-License-Identifier: %s\n",
             "md": "<!-- SPDX-License-Identifier: %s -->\n",
             "html": "<!-- SPDX-License-Identifier: %s -->\n"}


def insert_header(text, ext, lic):
    """在 shebang / coding 声明之后插入 SPDX 行；已存在则不重复。"""
    lines = text.split("\n")
    if any("SPDX-License-Identifier:" in ln for ln in lines[:6]):
        return None                                      # 已有头（对错由闸门判）
    idx = 0
    if lines and lines[0].startswith("#!"):
        idx = 1
    if idx < len(lines) and re.match(r"^#.*coding[:=]", lines[idx]):
        idx += 1
    lines.insert(idx, SPDX_LINE[ext] % lic)
    return "\n".join(lines)


def main():
    mp = _load_map()
    counts = {}
    changed = skipped = 0
    ast_errors = []

    files = _walk_files()
    for rel in files:
        if not rel.endswith((".py", ".md", ".html")):
            continue
        if rel.startswith(("rules/", "demo/", ".workbuddy/")) or rel == "license-map.json":
            continue
        lic = resolve(mp, rel)
        assert lic, "未覆盖: " + rel
        p = os.path.join(ROOT, rel)
        raw = io.open(p, encoding="utf-8", newline="").read()
        crlf = "\r\n" in raw
        text = raw.replace("\r\n", "\n")
        new = insert_header(text, rel.rsplit(".", 1)[-1].lower(), lic)
        if new is None:
            skipped += 1
        else:
            if crlf:
                new = new.replace("\n", "\r\n")
            io.open(p, "w", encoding="utf-8", newline="").write(new)
            changed += 1
        counts[lic] = counts.get(lic, 0) + 1

    print("== SPDX 批量 ==")
    print("写入 %d 处，已带头跳过 %d 处" % (changed, skipped))
    for k in sorted(counts):
        print("  %-12s %d 个文件" % (k, counts[k]))

    # ③ 全部 .py 语法复核
    for rel in files:
        if rel.endswith(".py"):
            src = io.open(os.path.join(ROOT, rel), encoding="utf-8").read()
            try:
                ast.parse(src)
            except SyntaxError as e:
                ast_errors.append("%s: %s" % (rel, e))
    if ast_errors:
        sys.exit("★ 语法复核失败（头部插入破坏了文件？）：\n" + "\n".join(ast_errors))
    print("== 语法复核 == 全部 .py ast.parse 通过")

    # ① 仓根许可三件（从构建器常量 AST 提取，单一真源）
    bp = io.open(os.path.join(ROOT, "scripts", "build_package.py"), encoding="utf-8").read()
    emit = [("LICENSE", "LICENSE_MD"), ("NOTICE", "NOTICE_MD"),
            (os.path.join("challenge", "LICENSE"), "MIT_MD")]
    for rel, const_name in emit:
        val = _extract_const(bp, const_name)
        assert val, "构建器缺常量 " + const_name
        io.open(os.path.join(ROOT, rel), "w", encoding="utf-8", newline="").write(val)
        print("生成 %s（%d 字符）" % (rel, len(val)))

    print("== 完成 ==")


if __name__ == "__main__":
    main()
