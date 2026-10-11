# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""0.48.1 许可升级 · 构建器拼接件（一次性工具，执行后保留供审计）。

职责：把《Antinel许可策略v1.1》的四层许可落进 build_package.py 单一真源：
  ① LICENSE_MD  ：MIT → Apache-2.0 官方全文（含附录；源 = apache.org 原件，非记忆转写）
  ② 新增 MIT_MD ：原 MIT 文本逐字保留（challenge/ 目录 LICENSE 与 MIT 文件头同源）
  ③ 新增 NOTICE_MD：首行 MIT 豁免（策略 §五.5），A6 以指针形式进入，不进 LICENSE
  ④ pyproject classifier：MIT → Apache + MIT 双列
  ⑤ SKILL 模板 / PLUGIN_JSON / npm package.json 三处 license 字段
  ⑥ README 模板许可段 → 四层表
  ⑦ challenge package-data 增加 "LICENSE"（wheel/sdist 单一真源派生）
  ⑧ (pkg/"NOTICE") 写出
  ⑨ 版本 0.48.0 → 0.48.1（builder 侧；antinel.py 与 SKILL.md 另行拼接）

纪律：每处替换断言命中数；不符即中止**不写盘**；全过后单次写入。
"""
import io
import re
import sys

ROOT = r"d:/psl/poc/antinel-security"
BP = ROOT + "/scripts/build_package.py"

CANON = io.open(r"C:\Temp\PGINST~1\apache2_canonical.txt", encoding="utf-8", newline="").read()
assert "Apache License" in CANON[:200] and "Version 2.0, January 2004" in CANON[:200], "官方全文头部不符"
assert "limitations under the License." in CANON, "官方全文尾部不符"
assert CANON.count('"""') == 0, "官方全文含三引号，不能直接内嵌"

OLD_MIT_BLOCK_START = 'LICENSE_MD = """MIT License'
OLD_MIT_BLOCK_END = 'SOFTWARE.\n"""'

src = io.open(BP, encoding="utf-8", newline="").read()

# ---- ① 抽出旧 MIT 文本 → 定位整个 LICENSE_MD 字面量 ----
m = re.search(r'LICENSE_MD = """MIT License.*?SOFTWARE\.\n"""', src, re.S)
assert m, "找不到 LICENSE_MD 字面量"
old_block = m.group(0)
old_mit_text = old_block[len('LICENSE_MD = """'):-len('"""')]
assert old_mit_text.rstrip().endswith("SOFTWARE."), "旧 MIT 文本尾部不符"
assert "收入与中立性" not in old_mit_text, "旧 MIT 模板竟含 A6 尾（G7-3 应已删）"

NEW_MIT_MD = old_mit_text

NOTICE_MD = """Antinel NOTICE（本文件只对以 Apache-2.0 发布的部分生效）

MIT 豁免（置于首行，策略 v1.1 §五.5）：凡文件头 SPDX 标识为 MIT 的组件
（antinel_mcp.py、transcript_reader.py、tools/probe_host.py、strings.py、
challenge/ 目录）不适用本 NOTICE，仅受其随附的 MIT 许可与文件头 SPDX 标识约束。

Copyright 2026 Zhilv Technology (Antinel / PSL)

A6 收入边界声明（对项目自身的政策约束，不构成对本许可所授予权利的限制）
见 docs/A6收入边界声明.md（CC-BY-4.0）。
"""

README_TIER = """本包采用分层许可。逐文件真源见 `license-map.json`；机器可读标识见各文件头
`SPDX-License-Identifier`。

| 层 | 覆盖 | 许可 |
|---|---|---|
| 产品代码（默认） | 除下述外的全部源码与 CI 件 | Apache-2.0（见 LICENSE；义务与归属提示见 NOTICE） |
| 引流小件 | `antinel_mcp.py`、`transcript_reader.py`、`tools/probe_host.py`、`strings.py`、`challenge/` | MIT（见 challenge/LICENSE 与各文件头） |
| 声明与规则集 | `docs/A6收入边界声明.md`、`rules/*.json` | CC-BY-4.0 |
| 规范与文档 | README、docs/ 下规范与说明 | CC-BY-SA-4.0 |

收入与中立性边界见 docs/A6收入边界声明.md（CC-BY-4.0）：不收通过费、不出售排名、关联方无豁免。"""

subs = [
    # ① LICENSE_MD 整块替换 + 新增 MIT_MD / NOTICE_MD
    (old_block,
     '# ★★ 2026-10-11（0.48.1，策略 v1.1 落地）：主许可 MIT → Apache-2.0。\n'
     '#   官方全文自 apache.org 原件嵌入（md5 3b83ef96387f14655fc854ddc3c6bd57，含附录），\n'
     '#   不做任何附加——G7-3 的教训（附加段把相似度压到阈值之下）由\n'
     '#   ci/inbox_guards_0481.py L2 常驻把守。A6 只经 NOTICE 指针进入。\n'
     '#   四层归属的唯一数据真源 = license-map.json。\n'
     'LICENSE_MD = """' + CANON + '"""\n\n'
     '# MIT 层文本：策略 v1.1 §三 的引流小件（challenge/ 目录 LICENSE 与文件头同源）。\n'
     '# glossary.py 已按核验报告 v1.0 §1.4 乙案移出 MIT（顶层硬依赖 inbox_model）。\n'
     'MIT_MD = """' + NEW_MIT_MD + '"""\n\n'
     '# NOTICE：Apache-2.0 §4(d) 的归属通知载体。首行 = MIT 豁免（策略 §五.5）。\n'
     'NOTICE_MD = """' + NOTICE_MD + '"""',
     1),
    # ④ classifier 双列
    ('  "License :: OSI Approved :: MIT License",\n',
     '  "License :: OSI Approved :: Apache Software License",\n'
     '  "License :: OSI Approved :: MIT License",\n',
     1),
    # ⑤ SKILL 模板
    ('license: MIT\n', 'license: Apache-2.0\n', 1),
    # ⑤ PLUGIN_JSON（用上下文消歧，npm 处另有同形串）
    ('"author": {"name": "Zhilv Technology (Antinel / PSL)"},\n    "license": "MIT",',
     '"author": {"name": "Zhilv Technology (Antinel / PSL)"},\n    "license": "Apache-2.0",', 1),
    # ⑤ npm package.json
    ('"license": "MIT", "description": PLUGIN_JSON["description"]}',
     '"license": "(Apache-2.0 AND MIT)", "description": PLUGIN_JSON["description"]}', 1),
    # ⑥ README 许可段
    ('MIT（见 LICENSE 文件）。收入与中立性边界见 docs/A6收入边界声明.md。',
     README_TIER, 1),
    # ⑦ challenge 数据模式
    ('challenge = ["*.md", "*.html", "chain/*.jsonl", "chain/*.json"]',
     'challenge = ["*.md", "*.html", "chain/*.jsonl", "chain/*.json", "LICENSE"]', 1),
    # ⑧ NOTICE 写出
    ('(pkg / "LICENSE").write_text(LICENSE_MD, encoding="utf-8", newline="\\n")',
     '(pkg / "LICENSE").write_text(LICENSE_MD, encoding="utf-8", newline="\\n")\n'
     '    (pkg / "NOTICE").write_text(NOTICE_MD, encoding="utf-8", newline="\\n")', 1),
    # ⑨ builder 版本
    ('VERSION = "0.48.0"', 'VERSION = "0.48.1"', 1),
]

out = src
for i, (a, b, n) in enumerate(subs, 1):
    c = out.count(a)
    if c != n:
        sys.exit("中止：第 %d 处命中 %d（期望 %d）——不写盘。片段头：%r" % (i, c, n, a[:60]))
    out = out.replace(a, b, 1)

io.open(BP, "w", encoding="utf-8", newline="").write(out)
print("build_package.py 已写入（%d 处替换）" % len(subs))

# ---- antinel.py 版本 ----
AP = ROOT + "/antinel.py"
s2 = io.open(AP, encoding="utf-8", newline="").read()
assert s2.count('VERSION = "0.48.0"') == 1, "antinel.py 版本常量定位失败"
s2 = s2.replace('VERSION = "0.48.0"', 'VERSION = "0.48.1"', 1)
io.open(AP, "w", encoding="utf-8", newline="").write(s2)
print("antinel.py 已写入（版本 0.48.1）")

# ---- 仓根 SKILL.md license 行 ----
SK = ROOT + "/SKILL.md"
s3 = io.open(SK, encoding="utf-8", newline="").read()
assert s3.count("license: MIT") == 1, "SKILL.md license 行定位失败"
s3 = s3.replace("license: MIT", "license: Apache-2.0", 1)
io.open(SK, "w", encoding="utf-8", newline="").write(s3)
print("SKILL.md 已写入（license: Apache-2.0）")

# ---- 自证 ----
chk = io.open(BP, encoding="utf-8", newline="").read()
import ast
ast.parse(chk)  # 语法必须完好
assert 'LICENSE_MD = """                                 Apache License' in chk
assert chk.count('MIT_MD = """') == 1 and chk.count('NOTICE_MD = """') == 1
assert chk.count('License :: OSI Approved :: Apache Software License') == 1
assert chk.count('"license": "MIT"') == 0, "仍残留 MIT license 字段"
assert chk.count('license: MIT') == 0
assert chk.count('收入与中立性边界见 docs/A6收入边界声明.md。\n"""') == 0
assert 'VERSION = "0.48.1"' in chk
print("自证通过：语法完好、无 MIT 残留字段、三常量就位")
