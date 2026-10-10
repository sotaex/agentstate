#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""0.44.0 判据 —— **第一处根治：命令结构化**（误拦的根因修复）。

★★ 这一份判据的由来（2026-10-10 实测，非推演；方案 v2.0 §2.2 有完整对照实验）：

    一条命令被 DST-01 拦了：`cd /d/2026/PSL && F="…v1.0….md"; echo …; grep -nP … "$F" | …`
    —— 里面**没有一个删除动作**，但也确实写着 shell 变量赋值。

    把它喂给产品自己的 `readonly_command_context` 做对照实验，结论钉死：
      · 纯 grep（`grep -n x file.md`）**本来会**被降为提醒（True）；
      · 只多了一句 `F="x.md"` ⇒ **False**。
    ⇒ **不是 grep 的问题，是赋值的问题。**

    根因是两处叠加：
      ① `_first_token` 的前缀剥离正则 `^[A-Za-z_][A-Za-z0-9_]*=\\S*\\s+` 要求前缀后
         **必须有空白**。当整段**只是一个赋值、后面没有别的命令**时（`F="x.md"`），
         尾部没有空白 ⇒ 匹配失败 ⇒ 首词被取成 `f="x.md"` ⇒ 不在只读动词表 ⇒ 整条否决。
         且 `\\S*` 遇值里带空格（`F="my file.txt"`）就断在空格处 ⇒ 同样误拦。
      ② `readonly_command_context` 逐段判定、**一段不合格整条否决**；纯赋值段本无执行
         意图，却参与了否决。

    ★ 修法不是"给名单加一条例外"，而是**换掉判据的来源**：从「这段文本像不像只读」
      换成「这一段的结构是什么」。

  ★ 四件套（本文件逐条落地）：
    · 正判据 S70：赋值 + 只读命令，不再因结构丢资格（5 正例全 True）。
    · 反向对照 N-S70 / N-S70b：摘掉"中性段"处理 / 去掉"引号感知" ⇒ 正例必须重新变红
      （**真的会红**：内存变异源码后重载，不是"算一遍就丢"）。
    · 连带对照 S71：7 类真删除 + 1 条硬纪律（赋值成 dist 再删）**必须仍然拦**。
    · 可观测 S72：结构锚（引号感知 ＋ 行尾尾部）在位，且旧写法已不在。

  ★ 编写纪律（沿用 0430/0431）：
    · 每条判据配负控，且负控**真的会红**；
    · 判据**只查行为/结构**，不查文案；
    · **不写任何产品文件**：变异只发生在内存字符串上，磁盘一个字节都不动。
"""
from __future__ import annotations

import ast
import io
import os
import re
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

RESULTS = []


def check(name):
    """★ 判据**必须真会红** —— 返回说明串一律转成抛异常。"""
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


def _func_src(src, name):
    """抠出某个**顶层函数**的源码（AST 行号，不靠正则 —— 正则一遇缩进就漂）。

    ★ 为什么不用"整文件子串匹配"找旧正则：改动 1 的说明**注释里**就引用了旧写法，
      整文件匹配会把注释当成"残留"⇒ 假红。只看函数体，注释不进函数体。
    """
    for n in ast.parse(src).body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(src, n)
    return None


def _load(src, tag):
    """把（可能被变异过的）钩子源码在**内存**里加载成模块，返回该模块。

    ★ 只读：磁盘一个字节都不动（exec 到新建的 ModuleType）。
    """
    mod = types.ModuleType(tag)
    mod.__file__ = os.path.join(ROOT, "hooks", "pre_tool_use.py")
    sys.modules[tag] = mod
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)      # noqa: S102
    return mod


_HOOK = "hooks/pre_tool_use.py"

# ── 向量（出处：方案 v2.0 §2.2/§2.3/§2.4；P1 是该日被拦命令的原文）──────────
POS = [
    ("P1 当天被拦的那条",
     'cd /d/2026/PSL && F="Antinel\u00b7\u4e24\u5904\u6839\u6cbb\u6700\u4f18\u65b9\u6848 v1.0'
     '\uff082026-10-10\uff09.md"; echo "=== \u7ae0\u8282\u7ed3\u6784 ==="; '
     'grep -nP \'^[\\#]{1,3} \' "$F"; echo; echo "=== \u7ec8\u68c0 ==="; '
     'grep -nP \'[\\x{4e00}-\\x{9fff}]\\s*[A-Za-z]{2,}\\s*[\\x{4e00}-\\x{9fff}]\' "$F" '
     '| grep -vP \'(?:ci|psl|DST|rm|del|rmdir|unlink|shutil)\' | head -5; echo "(end)"'),
    ("P2 赋值 + grep",       'cd /tmp && F="x.md"; grep -nP \'a\' "$F"'),
    ("P3 赋带空格的值 + cat", 'F="my file.txt"; cat "$F"'),
    ("P4 多变量 + 管道",      'A=a; B=b; grep x f | head -3'),
    ("P5 基线纯 grep",        'grep -n x file.md'),
]

NEG = [
    ("N1 赋值 + 真删除",      'F="x"; rm -rf /tmp/zzz'),
    ("N2 命令替换里有删除",     'F=$(rm -rf /tmp)'),
    ("N3 管道送进 xargs",      'grep x f | xargs rm -f'),
    ("N4 前缀赋值 + 真删除",    'PATH=/tmp:$PATH rm -rf /tmp/zzz'),
    ("N5 && 后接删除",        'F="a" && rm -rf /tmp/zzz'),
    ("N6 find -delete",       'find . -name "*.pyc" -delete'),
    ("N7 反引号执行",          'X=`rm -rf /tmp/zzz`'),
    ("N8 硬纪律：赋值成 dist 再删", 'F="dist"; rm -rf "$F"'),
]

# ── 变异（内存变异；用于反向对照）──────────────────────────────────────
_MUT_NEUTRAL_OFF = (
    'if _ASSIGN_HEAD_RE.match((seg or "").strip()) and _first_token(seg) == "":',
    'if False:  # NEGCTL 中性段处理被摘掉',
)


# ══════════════ 正判据 S70 · 赋值 + 只读命令不再因结构丢资格 ══════════════
@check("S70 ★ 赋值 + 只读命令：不再因结构丢资格（5 正例全 True）")
def s70():
    m = _load(_src(_HOOK), "ptu_s70")
    bad = [tag for tag, cmd in POS if m.readonly_command_context(cmd) is not True]
    if bad:
        return "这些正例仍被误拦（应为 True）：%s" % "、".join(bad)
    return True


# ══════════════ 反向对照 N-S70 · 摘掉"中性段"处理 ⇒ 正例必红 ══════════════
@check("N-S70 负控：摘掉'纯赋值段视为中性'处理 ⇒ 至少两条正例必须重新变红")
def n_s70():
    src = _src(_HOOK)
    if _MUT_NEUTRAL_OFF[0] not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 这是负控自身失效，不算通过"
    mut = _load(src.replace(_MUT_NEUTRAL_OFF[0], _MUT_NEUTRAL_OFF[1]), "ptu_ns70")
    red = [tag for tag, cmd in POS if mut.readonly_command_context(cmd) is not True]
    if len(red) < 2:
        return ("摘掉中性段处理后只有 %d 条正例变红（应 ≥2）—— 该处理没被真正依赖，"
                "判据可能空转" % len(red))
    return True


# ══════════════ 反向对照 N-S70b · 去掉"引号感知" ⇒ P3 必红 ══════════════
@check("N-S70b 分辨力样本：去掉'引号感知' ⇒ 值带空格的正例(P3)必须变红")
def n_s70b():
    # ★ 这一条用**内存里换掉已编译的正则**来变异（而不是做源码字符串替换）：
    #   源码里那条正则写作 `r'…=(?:"[^"]*"|\'[^\']*\'|\S*)…'`（含转义反斜杠），
    #   字符串替换的锚点既脆又易错；换模块属性同样作用于真代码路径
    #   （`_first_token` 调用时读的正是这个模块全局），且**不写盘**。
    mut = _load(_src(_HOOK), "ptu_ns70b")
    mut._ASSIGN_PREFIX_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=\S*(?:\s+|$)')
    p3 = [cmd for tag, cmd in POS if tag.startswith("P3")][0]
    if mut.readonly_command_context(p3) is not False:
        return "去掉引号感知后 P3（值带空格）仍为 True —— 引号感知没被真正依赖（假守卫）"
    return True


# ══════════════ 连带对照 S71 · 真删除必须仍然拦 ══════════════
@check("S71 ★ 连带对照：8 类真删除/危险写法必须仍然拦（不许放松）")
def s71():
    m = _load(_src(_HOOK), "ptu_s71")
    leaked = [tag for tag, cmd in NEG if m.readonly_command_context(cmd) is not False]
    if leaked:
        return "这些危险写法被放行了（应为 False）：%s" % "、".join(leaked)
    return True


# ══════════════ 可观测 S72 · 结构锚在位、旧写法已不在 ══════════════
@check("S72 ★ 结构锚：引号感知 ＋ 行尾尾部在位；旧写法（要求尾空白）已不在")
def s72():
    m = _load(_src(_HOOK), "ptu_s72")
    pat = getattr(getattr(m, "_ASSIGN_PREFIX_RE", None), "pattern", None)
    if not pat:
        return "找不到 _ASSIGN_PREFIX_RE —— 改动 1 的结构锚不见了"
    if '"' not in pat or "'" not in pat:
        return "前缀正则不再引号感知（缺双/单引号分支）"
    if r"(?:\s+|$)" not in pat:
        return "前缀正则尾部不再是「空白或到行尾」"
    if pat.endswith(r"=\S*\s+"):
        return "前缀正则似乎退回了旧写法（要求尾空白）"
    # 旧写法必须已从 _first_token 的函数体里消失（只查函数体，不查注释 —— 见 _func_src）
    fsrc = _func_src(_src(_HOOK), "_first_token") or ""
    if r"=\S*\s+" in fsrc:
        return "_first_token 函数体里仍残留旧正则（要求尾空白）—— 改动 1 未落地干净"
    return True


def main():
    print("=" * 78)
    print("0.44.0 判据 —— 命令结构化：赋值 + 只读不再误拦；真删除仍拦")
    print("（全部内存变异，不写任何产品文件）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                why = ""
            print("  ✅ %-56s %s" % (name, why or ""))
            ok += 1
        except AssertionError as e:
            print("  ❌ %-56s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-56s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
