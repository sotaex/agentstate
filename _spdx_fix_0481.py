# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""0.48.1 许可升级 · 组装冲头事件的树内修复（一次性工具，保留供审计）。

背景（0481 L1 实测红 7 处的根因）：builder 六个再生点（SKILL/AGENT_SKILL/RULES/
THREAT_MODEL/HOST_PROBE/A6/probe_host）从**无头模板或仓外源件**再生成文件，
把 _license_apply_0481 写进实例的 SPDX 头冲掉——「修了实例、没修源头」的镜像。

修复分两层（本脚本只做第二层）：
  ① 源头层：builder 六个写盘点已改为输出带头的文件（见 build_package.py 0.48.1 注释）；
  ② 实例层：本脚本把仓内 7 个现存文件打成与 builder 下一轮输出**逐字节同构**的形态，
     使「闸门（组装前跑）→ 组装（再生）」形成不动点，闸门从此稳定全绿。

形态规则（与 builder 一一对应）：
  SKILL.md                 front matter 内第 2 行插 YAML 注释（文件最前会破坏 --- 开头约束）
  docs/A6收入边界声明.md    第 1 行 prepend HTML 注释（CC-BY-4.0），CRLF 归一为 LF（builder 以 \\n 落盘）
  references/*.md (3件)     第 1 行 prepend HTML 注释（CC-BY-SA-4.0）
  tools/HOST_PROBE.md       第 1 行 prepend HTML 注释（CC-BY-SA-4.0）
  tools/probe_host.py       shebang/coding 之后插 # 注释（MIT），CRLF 归一为 LF

纪律：已带头的文件跳过；形态不符即断言失败中止，不做部分写入。
"""
import ast
import io
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
MD = "<!-- SPDX-License-Identifier: %s -->\n"
CHANGES = []


def read(rel):
    return io.open(os.path.join(ROOT, rel), encoding="utf-8", newline="").read()


def write(rel, text):
    io.open(os.path.join(ROOT, rel), "w", encoding="utf-8", newline="").write(text)
    CHANGES.append(rel)


def has_spdx(text):
    return any("SPDX-License-Identifier:" in ln for ln in text.replace("\r\n", "\n").split("\n")[:6])


def prepend(rel, lic):
    raw = read(rel)
    if has_spdx(raw):
        print("跳过（已带头）: " + rel)
        return
    crlf = "\r\n" in raw
    text = MD % lic + raw.replace("\r\n", "\n")
    if crlf:
        pass  # builder 一律以 \n 落盘：此处保持归一后的 LF
    write(rel, text)


def fix_skill():
    rel = "SKILL.md"
    raw = read(rel)
    if has_spdx(raw):
        print("跳过（已带头）: " + rel)
        return
    lines = raw.replace("\r\n", "\n").split("\n")
    assert lines and lines[0].strip() == "---", "SKILL.md 首行不是 front matter 开界，形态变了，中止"
    lines.insert(1, "# SPDX-License-Identifier: CC-BY-SA-4.0")
    write(rel, "\n".join(lines))


def fix_probe_host():
    rel = os.path.join("tools", "probe_host.py")
    raw = read(rel)
    if has_spdx(raw):
        print("跳过（已带头）: " + rel)
        return
    lines = raw.replace("\r\n", "\n").split("\n")
    idx = 1 if lines and lines[0].startswith("#!") else 0
    if idx < len(lines) and lines[idx].startswith("#") and "coding" in lines[idx]:
        idx += 1
    lines.insert(idx, "# SPDX-License-Identifier: MIT")
    write(rel, "\n".join(lines))


def main():
    fix_skill()
    prepend("docs/A6收入边界声明.md", "CC-BY-4.0")
    for rel in ("references/AGENT_SKILL.md", "references/RULES.md",
                "references/THREAT_MODEL.md", "tools/HOST_PROBE.md"):
        prepend(rel, "CC-BY-SA-4.0")
    fix_probe_host()

    print("== 树内修复 ==")
    print("写入 %d 处" % len(CHANGES))
    for rel in CHANGES:
        print("  " + rel)

    # 语法复核：动过的 .py 必须仍可解析
    errs = []
    for rel in CHANGES:
        if rel.endswith(".py"):
            try:
                ast.parse(io.open(os.path.join(ROOT, rel), encoding="utf-8").read())
            except SyntaxError as e:
                errs.append("%s: %s" % (rel, e))
    assert not errs, "语法复核失败：\n" + "\n".join(errs)
    print("== 语法复核 == 动过的 .py 全部 ast.parse 通过")
    if len(CHANGES) != 7:
        sys.exit("★ 预期 7 处、实写 %d 处 —— 与根因清单不符，人工核对后再说" % len(CHANGES))
    print("== 完成（7/7）==")


if __name__ == "__main__":
    main()
