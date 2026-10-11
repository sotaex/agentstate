#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.48.1 判据 —— **许可分层的防复发六条**（策略 v1.1 ＋ 核验报告 v1.0 落地）。

★★ 由来（两次已付学费的复发通道，不是设计偏好）：

    ① G7-3（2026-09-24）：LICENSE 模板末尾的附加段把与标准文本的相似度压到
       licensee 阈值之下 ⇒ GitHub 至今把本仓识别为「Other/NOASSERTION」。
       当时修了构建器模板，**没修已发布实例**，且注释里自记的 0.9749 本身就低于 0.98。
    ② MIT 五件清单里混进了不自足的 glossary.py（核验报告 v1.0 §1.2 实测
       ImportError）⇒ 分层在「被单独抄走」的那一刻才失效，平时全绿。

    ⇒ 本文件把四层许可从「文档里的表」变成「每次交付前必跑、会报红、有负控」的机制。

★ 六条判据（＋ 六条负控）：
    L1 SPDX 头与 license-map 一致（＋ N-L1：无头/错标必须红）
    L2 根 LICENSE == 构建器常量，且无 A6 尾（＋ N-L2：A6 尾必须红）
    L3 challenge/LICENSE == MIT_MD（＋ N-L3：改动必须红）
    L4 NOTICE == NOTICE_MD 且首行 MIT 豁免（＋ N-L4：豁免行缺失必须红）
    L5 MIT 件自足性：AST import 扫描，跨层依赖即红（＋ N-L5：喂 host_shield 必须红）
    L6 归属表覆盖完备 ＋ 元数据四字段（＋ N-L6：孤儿覆盖必须红）

★ 编写纪律（沿用 0440–0470）：
    · 断言打在**结构/行为**上（AST 提取常量、逐字节比对），不查行号、不查文案；
    · **不写任何产品文件**：变异只发生在内存字符串上；
    · 真源单向：构建器常量 → 仓内文件；闸门只比对，不生成。
"""
from __future__ import annotations

import ast
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

RESULTS = []

_WALK_EXCLUDE = {".git", ".workbuddy", "__pycache__", "build", "dist", "node_modules",
                 ".github", ".psl", ".vscode", ".idea",
                 # ★ 0.48.2：模拟/验证的证据区（内含第三方 venv 与临时文件）不属于
                 #   本仓归属范围 —— 不排除会让 L1 扫到 700+ 个第三方文件而假红
                 #   （实测：`_uxtest/pypi_sim_0481/venv/...`）。与 .gitignore 同口径。
                 "_uxtest", "_uxtest2"}
_WALK_EXCLUDE_PREFIX = ("antinel-0.", "_backup.away-", "antinel_mcp.away")
SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9\-.]+)")

#: 这些目录里的 py/md/html **不要求** SPDX 头（理由登记在 license-map.spdx_exempt_reason）
EXEMPT_PREFIX = ("rules/", "demo/", ".workbuddy/")


# --------------------------------------------------------------- 工具 ----
def _walk_files():
    """仓内全部 py/md/html/json（排除构建产物与归档目录）。返回相对 posix 路径。"""
    out = []
    for base, dirs, files in os.walk(ROOT):
        rel_base = os.path.relpath(base, ROOT).replace("\\", "/")
        dirs[:] = [d for d in dirs if d not in _WALK_EXCLUDE
                   and not any((rel_base + "/" + d).startswith(p) or d.startswith(p)
                               for p in _WALK_EXCLUDE_PREFIX)]
        for f in files:
            rel = (rel_base + "/" + f) if rel_base != "." else f
            if rel.startswith(_WALK_EXCLUDE_PREFIX):
                continue
            if f.rsplit(".", 1)[-1].lower() in ("py", "md", "html", "json"):
                out.append(rel)
    return sorted(out)


def _load_map():
    return json.load(io.open(os.path.join(ROOT, "license-map.json"), encoding="utf-8"))


def resolve(mp, rel):
    """路径 → 许可。覆盖优先（整路径 > 目录前缀），否则按扩展名默认。"""
    ov = mp.get("overrides", {})
    if rel in ov:
        return ov[rel]
    parts = rel.split("/")
    for i in range(len(parts) - 1, 0, -1):
        pref = "/".join(parts[:i]) + "/"
        if pref in ov:
            return ov[pref]
    ext = rel.rsplit(".", 1)[-1].lower()
    return mp.get("defaults", {}).get(ext)


def _extract_const(src, name):
    """从构建器源码 AST 提取模块级字符串常量（单一真源，闸门不自抄一份）。"""
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name and isinstance(node.value, ast.Constant):
                    return node.value.value
    return None


def _norm(text):
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _spdx_issue(rel, text, mp):
    """单文件 SPDX 判定（纯函数，N-L1 也用它）。返回问题串或 None。"""
    want = resolve(mp, rel)
    if want is None:
        return "license-map 未覆盖（defaults 无该扩展名且无覆盖项）"
    head = "\n".join(_norm(text).split("\n")[:6])
    m = SPDX_RE.search(head)
    if m is None:
        return "缺 SPDX 头（前 6 行无 SPDX-License-Identifier）"
    if m.group(1) != want:
        return "SPDX 标识 %s != 本表归属 %s" % (m.group(1), want)
    return None


def _file_issue(actual, expected, forbidden=None):
    """文件 == 构建器常量 判定（纯函数，N-L2/N-L3 也用它）。"""
    if forbidden and forbidden in _norm(actual):
        return "含被禁附加段（%r）——G7-3 复发形态" % forbidden
    if _norm(actual) != _norm(expected):
        return "与构建器常量不一致（单一真源被绕开或内容漂移）"
    return None


def _project_module_names(files):
    mods = set()
    for rel in files:
        if rel.endswith(".py"):
            mods.add(rel[:-3].rsplit("/", 1)[-1])
        if "/" not in rel:
            mods.add(rel.rsplit(".", 1)[0])
        else:
            mods.add(rel.split("/", 1)[0])
    return mods


def _mit_import_issue(rel, src, project_mods, mit_mods):
    """MIT 件自足性判定（纯函数，N-L5 也用它）：跨层 import 即红。"""
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return "语法错误 %r" % (e,)
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module.split(".")[0]]
        for mod in names:
            if mod in sys.stdlib_module_names:
                continue
            if mod in mit_mods:
                continue
            if mod in project_mods:
                return "MIT 件 %s import 了非 MIT 项目模块 %r —— 分层在单文件被抄走时断裂" % (rel, mod)
            return "MIT 件 %s 依赖未知非标准库模块 %r" % (rel, mod)
    return None


def _notice_first_line_ok(notice_text):
    """NOTICE 首行豁免判定（纯函数，N-L4 也用它）。"""
    return "MIT 豁免" in _norm(notice_text).split("\n")[0]


# --------------------------------------------------------------- 判据 ----
def check(name):
    def deco(fn):
        RESULTS.append((name, fn))
        return fn
    return deco


@check("L1 全仓 SPDX 头与 license-map 一致")
def l1():
    mp = _load_map()
    bad = []
    for rel in _walk_files():
        if not rel.endswith((".py", ".md", ".html")):
            continue
        if rel.startswith(EXEMPT_PREFIX) or rel == "license-map.json":
            continue
        text = io.open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace").read()
        why = _spdx_issue(rel, text, mp)
        if why:
            bad.append("%s: %s" % (rel, why))
    if bad:
        return "共 %d 处：%s" % (len(bad), "；".join(bad[:5]))
    return True


@check("N-L1 负控：无头与错标都必须红")
def n_l1():
    mp = _load_map()
    if _spdx_issue("probe/x.py", "print(1)\n", mp) is None:
        return "判据失效：缺头的文件没被红"
    if _spdx_issue("strings.py", "# SPDX-License-Identifier: Apache-2.0\n", mp) is None:
        return "判据失效：错标（MIT 件标成 Apache）没被红"
    return True


@check("L2 根 LICENSE == 构建器 LICENSE_MD，且无 A6 附加段")
def l2():
    bp = io.open(os.path.join(ROOT, "scripts", "build_package.py"), encoding="utf-8").read()
    const = _extract_const(bp, "LICENSE_MD")
    if const is None:
        return "构建器里没有 LICENSE_MD 常量"
    if "收入与中立性" in const:
        return "构建器常量自身含 A6 附加段（G7-3 复发）"
    if "Version 2.0, January 2004" not in const:
        return "构建器常量不是 Apache-2.0 文本"
    actual = io.open(os.path.join(ROOT, "LICENSE"), encoding="utf-8", newline="").read()
    why = _file_issue(actual, const, forbidden="收入与中立性")
    if why:
        return why
    return True


@check("N-L2 负控：给常量挂上 A6 尾必须红")
def n_l2():
    bp = io.open(os.path.join(ROOT, "scripts", "build_package.py"), encoding="utf-8").read()
    const = _extract_const(bp, "LICENSE_MD")
    tail = const + "\n---\n收入与中立性边界（A6）：不收通过费。\n"
    if _file_issue(tail, const, forbidden="收入与中立性") is None:
        return "判据失效：A6 尾没被红"
    return True


@check("L3 challenge/LICENSE == 构建器 MIT_MD")
def l3():
    bp = io.open(os.path.join(ROOT, "scripts", "build_package.py"), encoding="utf-8").read()
    const = _extract_const(bp, "MIT_MD")
    if const is None:
        return "构建器里没有 MIT_MD 常量"
    p = os.path.join(ROOT, "challenge", "LICENSE")
    if not os.path.isfile(p):
        return "challenge/LICENSE 不存在"
    actual = io.open(p, encoding="utf-8", newline="").read()
    why = _file_issue(actual, const)
    if why:
        return why
    return True


@check("N-L3 负控：MIT 目录件被改动必须红")
def n_l3():
    bp = io.open(os.path.join(ROOT, "scripts", "build_package.py"), encoding="utf-8").read()
    const = _extract_const(bp, "MIT_MD")
    if _file_issue(const + "\n额外一行\n", const) is None:
        return "判据失效：改动的 MIT 文本没被红"
    return True


@check("L4 NOTICE == 构建器 NOTICE_MD 且首行含 MIT 豁免")
def l4():
    bp = io.open(os.path.join(ROOT, "scripts", "build_package.py"), encoding="utf-8").read()
    const = _extract_const(bp, "NOTICE_MD")
    if const is None:
        return "构建器里没有 NOTICE_MD 常量"
    p = os.path.join(ROOT, "NOTICE")
    if not os.path.isfile(p):
        return "NOTICE 不存在"
    actual = io.open(p, encoding="utf-8", newline="").read()
    why = _file_issue(actual, const)
    if why:
        return why
    if not _notice_first_line_ok(const):
        return "NOTICE 首行缺 MIT 豁免声明（策略 §五.5：否则分层白做）"
    return True


@check("N-L4 负控：NOTICE 缺豁免首行必须红")
def n_l4():
    bp = io.open(os.path.join(ROOT, "scripts", "build_package.py"), encoding="utf-8").read()
    const = _extract_const(bp, "NOTICE_MD")
    if not _notice_first_line_ok(const):
        return "夹具无效：现行常量本身就没有豁免首行"
    stripped = "\n".join(_norm(const).split("\n")[1:])
    if _notice_first_line_ok(stripped):
        return "夹具无效：豁免行没被真正摘掉"
    if _notice_first_line_ok(stripped) == _notice_first_line_ok(const):
        return "判据失效：豁免首行的有无不改变判定"
    return True


@check("L5 MIT 件自足性：AST import 扫描，跨层依赖即红")
def l5():
    mp = _load_map()
    files = _walk_files()
    pyfiles = [r for r in files if r.endswith(".py")]
    project_mods = _project_module_names(pyfiles)
    mit_mods = set()
    for rel in pyfiles:
        if resolve(mp, rel) == "MIT":
            mit_mods.add(rel[:-3].rsplit("/", 1)[-1])
    bad = []
    for rel in pyfiles:
        if resolve(mp, rel) != "MIT":
            continue
        src = io.open(os.path.join(ROOT, rel), encoding="utf-8").read()
        why = _mit_import_issue(rel, src, project_mods, mit_mods)
        if why:
            bad.append(why)
    if bad:
        return "；".join(bad)
    return True


@check("N-L5 负控：MIT 件喂进 host_shield import 必须红")
def n_l5():
    mp = _load_map()
    files = _walk_files()
    project_mods = _project_module_names([r for r in files if r.endswith(".py")])
    mit_mods = {r[:-3].rsplit("/", 1)[-1] for r in files
                if r.endswith(".py") and resolve(mp, r) == "MIT"}
    why = _mit_import_issue("strings.py", "import host_shield\n", project_mods, mit_mods)
    if why is None:
        return "判据失效：跨层 import 没被红"
    return True


@check("L6 归属表覆盖完备 ＋ 元数据四字段已换层")
def l6():
    mp = _load_map()
    files = _walk_files()
    # 覆盖完备：defaults 必须盖住见到的全部扩展名；overrides 路径必须真实存在
    exts = {rel.rsplit(".", 1)[-1].lower() for rel in files}
    missing = exts - set(mp.get("defaults", {}))
    if missing:
        return "defaults 缺扩展名：%s" % sorted(missing)
    orphans = [k for k in mp.get("overrides", {}) if not os.path.exists(os.path.join(ROOT, k))]
    if orphans:
        return "overrides 指向不存在的路径（拼写错误？）：%s" % orphans
    # 元数据四字段（构建器单源 + 仓根 SKILL）
    bp = io.open(os.path.join(ROOT, "scripts", "build_package.py"), encoding="utf-8").read()
    if "License :: OSI Approved :: Apache Software License" not in bp:
        return "pyproject 模板缺 Apache classifier"
    if '"license": "MIT"' in bp or "license: MIT" in bp:
        return "构建器仍残留 MIT license 字段"
    skill = io.open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8").read()
    if "license: Apache-2.0" not in skill:
        return "仓根 SKILL.md license 字段未换层"
    return True


@check("N-L6 负控：孤儿覆盖必须红")
def n_l6():
    mp = _load_map()
    files = _walk_files()
    exts = {rel.rsplit(".", 1)[-1].lower() for rel in files}
    broken = dict(mp.get("overrides", {}))
    broken["no/such/path.py"] = "MIT"
    orphans = [k for k in broken if not os.path.exists(os.path.join(ROOT, k))]
    if orphans != ["no/such/path.py"]:
        return "夹具无效"
    if not orphans:
        return "判据失效：孤儿覆盖没被红"
    return True


# --------------------------------------------------------------- 运行 ----
def main():
    print("=" * 78)
    print("inbox_guards_0481 —— 许可分层六条（每条带负控）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                print("  ✅ %-64s" % name)
                ok += 1
            else:
                # ★ 判读纪律（与 delivery_gate 的 return True 注入语义一致）：
                #   判据只有 return True 才是绿；字符串/False/None 一律红，
                #   否则「判不出」会被当成「带备注的通过」。
                print("  ❌ %-64s %s" % (name, why or "返回值不是 True"))
                fail += 1
        except AssertionError as e:
            print("  ❌ %-64s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-64s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
