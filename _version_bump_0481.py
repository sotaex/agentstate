# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""0.48.1 定版：把 version_check 列出的 7 处 0.48.0 残留统一到 0.48.1。

每处断言命中数；任何一处不符即中止不写。rules/default.json 的 version 是
历版发布例行字段（rules_hash 随每次发布刷新、install 升级时重签），与许可无关。
"""
import io
import sys

ROOT = r"d:/psl/poc/antinel-security"
JOBS = [
    ("pyproject.toml",              'version = "0.48.0"',                       1),
    ("server.json",                 '"version": "0.48.0"',                      1),
    ("antinel_mcp.py",              '"serverInfo": {"name": "antinel", "version": "0.48.0"}', 1),
    ("hooks/pre_tool_use.py",       '_ANTINEL_VERSION = "0.48.0"',              1),
    ("rules/default.json",          '"version": "0.48.0"',                      1),
    ("docs/AUDIT_SCHEMA.md",        '审计记录模式 v1.18（随 v0.48.0）',          1),  # 只改标题；v1.18 历史行是登记记录，不动
    ("SKILL.md",                    'antinel-version: "0.48.0"',                1),
]

for rel, old, n in JOBS:
    p = ROOT + "/" + rel
    s = io.open(p, encoding="utf-8", newline="").read()
    c = s.count(old)
    if c != n:
        sys.exit("中止：%s 命中 %d 期望 %d —— 不写任何文件" % (rel, c, n))

for rel, old, n in JOBS:
    p = ROOT + "/" + rel
    s = io.open(p, encoding="utf-8", newline="").read()
    s = s.replace(old, old.replace("0.48.0", "0.48.1"), 1)
    io.open(p, "w", encoding="utf-8", newline="").write(s)
    print("已写 %-26s -> 0.48.1" % rel)
print("== 定版完成（7 处）==")
