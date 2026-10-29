"""按构建器的**同一个写出点**重建 references/RULES.md。

为什么要这个脚本：RULES.md 是 `build_package.py` 的产物（整文件生成）。0.62.0 把它改成
「从数据生成」之后，一次临时重建**绕过了写出点**（自己拼 `rules_md()` 的返回值），
漏掉写出点那句 SPDX 头 ⇒ 0481 的 L1 当场红。本脚本的唯一目的就是：
**把拼接的两端合回一处** —— 头 + 正文，与 `build_package.py:3050` 逐字相同。

用法：cd <repo>; python output/_p_regen_rules_md.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.build_package import rules_md  # noqa: E402

SPDX = "<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->\n"
OUT = ROOT / "references" / "RULES.md"

body = rules_md(ROOT / "rules" / "default.json")
text = SPDX + body
OUT.write_text(text, encoding="utf-8", newline="\n")

# 自校验：头在第 1 行；正文首行是标题；两份都不许丢
first, second = text.split("\n")[:2]
assert first == SPDX.rstrip("\n"), "SPDX 头没在第 1 行"
assert second.startswith("# Antinel detection rules"), "标题没在第 2 行"
assert "SPDX-License-Identifier" not in body, "正文里也带了 SPDX（会重复）"
print("wrote", OUT)
print("chars:", len(text), "lines:", text.count("\n"))
print("line1:", first)
print("line2:", second[:70])
