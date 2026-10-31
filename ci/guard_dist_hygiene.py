#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""dist 卫生判据 —— 「旧版发布件让开」从手工动作变成构建器自己的机制。

★★ 这一份判据的由来（2026-10-09 实测复发，**第三次同族**）：

    「把 dist 里的旧版发布件挪走」这件事，此前**完全是手工的**：
        · 0.40.0 出包后，我 `mv` 把 0.39.2 的两件挪进 `_archive_dist/*.old`；
        · 0.41.0 出包后，我 `mv` 把 0.40.0 的两件挪进 `_archive_dist/*.old`；
        · 0.42.0 这一轮，**我忘了** —— dist 里躺着 0.41.0 的两件。
      ⇒ 闸门 D-23（"dist 里混着非本版发布件"）与 JDG-06（"dist-info 与当前包
        版本不符"）同时判红 ⇒ **一整轮 4 分钟闸门白跑，一个包都没出来**。

    ★ 根因不是粗心，是**这个动作没有任何机制保证它发生** —— 与本项目反复验证过
      的结论同型："靠人记得就等于没有"（0.38.0 灯、0.40.0 四行失守都是这么修的）。
      正确解法：让**构建器自己**在跑闸门之前把旧版件挪走，并逐条打印。

    机制（`scripts/build_package.py::_archive_stale_dist`，三条安全约束）：
        ① **只挪更旧的**（`artifact_ver < VERSION`）—— 相等的留在原处；
        ② **遇到更新的 ⇒ 硬失败**（SystemExit，一个字节都不动）——
           防"把一版更新的包静默降级"；
        ③ **零删除、全留痕** —— 一律 `mv` 进 `_archive_dist/stale_<时间戳>/`，
           每个被挪走的文件名都打印。

    检测侧本来就有（D-23 / JDG-06 在闸门里判"混旧包"）—— 它们**确实抓住了**这次，
    只是抓得太晚（要等一整轮闸门）。本套件守的是**预防侧**：挪没挪、什么时候挪。

  ★ 编写纪律（沿用 `inbox_guards_0420.py` 头部）：
    · 每条判据配负控，且负控**真的会红**（内存变异源码后重载）；
    · 判据**只查行为/结构**，不查文案 —— 按源码字面查的一律走 AST；
    · **不写任何产品文件**：合成 dist 全在 `_TMP.tmpdir()` 里。
"""
from __future__ import annotations

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import tmpreg as _TMP   # 0.55.0 (F3): temp dir registry
import ast
import io
import os
import sys
import tempfile
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (ROOT, os.path.join(ROOT, "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

RESULTS = []


def check(name):
    """★ 判据**必须真会红** —— 返回说明串一律转成抛异常（同 0400/0420 的收紧）。"""
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


def _load_builder(src=None):
    """把（可能被变异过的）`scripts/build_package.py` 加载成新模块对象。

    ★ `build_package.py` 顶层只 import 标准库 ⇒ 干净命名空间里 exec 不会缺依赖。
    ★ 变异只发生在内存字符串上，**磁盘文件一个字节都不动**。
    ★ 用 `__name__ != "__main__"` 的模块名，避免它去解析命令行参数。
    """
    if src is None:
        import build_package as _b                                # noqa: F401
        return _b
    mod = types.ModuleType("build_package_mutated")
    mod.__file__ = os.path.join(ROOT, "scripts", "build_package.py")
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)        # noqa: S102
    return mod


def _mk_dist(tmp, names):
    """在 tmp 下造一个合成 dist/，返回 (dist_dir, archive_root)。"""
    dist = os.path.join(tmp, "dist")
    arch = os.path.join(tmp, "_archive_dist")
    os.makedirs(dist, exist_ok=True)
    for n in names:
        with open(os.path.join(dist, n), "w", encoding="utf-8") as f:
            f.write("x")
    return dist, arch


def _call_order(build_fn):
    """build() 里 `_archive_stale_dist` / `_delivery_gate` 两次调用的**源码顺序**。

    ★ 必须按**行号**排，不能按 `ast.walk` 的产出序：`ast.walk` 是**广度优先**，
      嵌套节点的产出顺序与源码顺序无关（本文件第一版就踩了 —— 变异后把调用
      挪到后面，walk 序仍把它排在前面 ⇒ 负控假绿）。行号是唯一可靠的源码序。
    """
    seen = []
    for node in ast.walk(build_fn):
        if isinstance(node, ast.Call):
            nm = getattr(node.func, "id", None)
            if nm in ("_archive_stale_dist", "_delivery_gate"):
                seen.append((node.lineno, nm))
    seen.sort()
    return [nm for _ln, nm in seen]


# ══════════ S38 · 行为：旧版挪走、本版留着、更新版硬失败、垃圾不碰 ══════════
@check("S38 ★ 旧版发布件自动挪走（零删除）｜本版不动｜垃圾不动")
def s38():
    # ★ 0.63.1：`ignore_cleanup_errors=True` —— 夹具的**收尾**不许掩盖判定结果。
    #   2026-10-31 本机实测：宿主 trash 服务拒一切目录清理（原生 rmdir 报
    #   WinError 5，关掉垫片同样），`TemporaryDirectory.__exit__` 于是抛
    #   PermissionError ⇒ 这条判据报「💥 崩」，读起来像产品有缺陷，其实与产品无关。
    #   断言一条没动；「临时目录该不该收掉」由 0353 的 P37 单独守，不在这里兼职。
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        dist, arch = _mk_dist(tmp, [
            "antinel-0.41.0-py3-none-any.whl",          # 旧 ⇒ 必须挪
            "antinel-0.41.0.tar.gz",                     # 旧 ⇒ 必须挪
            "antinel-0.42.0-py3-none-any.whl",          # 本版 ⇒ 必须留
            "antinel-0.41.0-py3-none-any.whl.REJECTED-double-distinfo",   # 让开态 ⇒ 留
            "antinel-0.40.0.tar.gz.old",                 # 让开态 ⇒ 留
            "notes.txt",                                 # 非发布件 ⇒ 留
        ])
        moved = _load_builder()._archive_stale_dist(dist, "0.42.0", arch)
        left = set(os.listdir(dist))
        if sorted(moved) != ["antinel-0.41.0-py3-none-any.whl", "antinel-0.41.0.tar.gz"]:
            return "挪走清单 = %r（应正好是 0.41.0 的两件）" % (moved,)
        if "antinel-0.42.0-py3-none-any.whl" not in left:
            return "本版产物被挪走了 —— 重复构建同一版本时不该动自己的产物"
        for junk in ("antinel-0.41.0-py3-none-any.whl.REJECTED-double-distinfo",
                     "antinel-0.40.0.tar.gz.old", "notes.txt"):
            if junk not in left:
                return "非发布件/让开态件被挪走了：%s" % junk
        # 零删除：归档区里必须真能找回来
        archived = []
        for root, _dirs, files in os.walk(arch):
            archived += files
        if sorted(archived) != ["antinel-0.41.0-py3-none-any.whl", "antinel-0.41.0.tar.gz"]:
            return "归档区内容 = %r（零删除 ⇒ 两件都该在这儿）" % (archived,)
        # ② 遇到**更新**的版本 ⇒ 硬失败，且一个字节都不动
        with open(os.path.join(dist, "antinel-0.43.0-py3-none-any.whl"), "w",
                  encoding="utf-8") as f:
            f.write("x")
        try:
            _load_builder()._archive_stale_dist(dist, "0.42.0", arch)
        except SystemExit:
            pass
        else:
            return "dist 里有比源码还新的 0.43.0，函数却放行了 —— 静默降级风险"
        if "antinel-0.43.0-py3-none-any.whl" not in set(os.listdir(dist)):
            return "硬失败前文件被挪走了 —— 失败代价必须是『什么都没动』"
        return True


@check("N-S38 负控：把「挪走＋记账」整块摘成空操作 ⇒ S38 必须报红")
def n_s38():
    src = _src("scripts/build_package.py")
    old = ("        _shutil.move(str(p), str(arch / name))\n"
           "        moved.append(name)")
    if old not in src:
        return "负控无效：找不到 `_shutil.move(...)` ＋ `moved.append(...)` 块可供变异"
    mut = src.replace(old, "        pass  # mutated: no move, no bookkeeping")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        dist, arch = _mk_dist(tmp, ["antinel-0.41.0-py3-none-any.whl",
                                    "antinel-0.41.0.tar.gz",
                                    "antinel-0.42.0-py3-none-any.whl"])
        moved = _load_builder(mut)._archive_stale_dist(dist, "0.42.0", arch)
        if moved:
            return "负控失效：move/append 被摘掉，仍然报告挪走了 %r" % (moved,)
        left = set(os.listdir(dist))
        if "antinel-0.41.0-py3-none-any.whl" not in left:
            return "负控有问题：文件被挪了却没记账 —— 变异本身不干净"
        return True


# ══════════ S39 · 结构：挪旧件必须发生在跑闸门**之前** ══════════
@check("S39 ★ 调用顺序：_archive_stale_dist 必须在 _delivery_gate 之前")
def s39():
    tree = ast.parse(_src("scripts/build_package.py"))
    build_fn = next((n for n in ast.walk(tree)
                     if isinstance(n, ast.FunctionDef) and n.name == "build"), None)
    if build_fn is None:
        return "找不到 build()"
    order = _call_order(build_fn)
    if "_archive_stale_dist" not in order:
        return "build() 里没有调用 _archive_stale_dist —— 手工挪旧件的复发无人再挡"
    if "_delivery_gate" not in order:
        return "build() 里没有调用 _delivery_gate"
    if order.index("_archive_stale_dist") > order.index("_delivery_gate"):
        return "顺序反了：先跑闸门后挪旧件 ⇒ D-23/JDG-06 仍会先红一轮（4 分钟白跑）"
    return True


@check("N-S39 负控：把挪旧件的调用挪到闸门之后 ⇒ S39 必须报红")
def n_s39():
    src = _src("scripts/build_package.py")
    call = ("    _archive_stale_dist(Path(out_root) / NAME / \"dist\", VERSION,\n"
            "                        Path(out_root) / NAME / \"_archive_dist\")\n")
    # 插到 `_verify_layout()` 之前（它在 if/else 整块**之后**，语法上安全，
    # 且语义上确实是"闸门跑完之后"——正是要否定的顺序）。
    anchor = "    _verify_layout()\n"
    if call not in src or anchor not in src:
        return "负控无效：找不到可供变异的调用块或插入点"
    mut = src.replace(call, "")                       # 先摘掉
    mut = mut.replace(anchor, call + anchor)          # 再插到 _verify_layout 之前
    if mut == src:
        return "负控无效：变异没产生任何变化"
    try:
        tree = ast.parse(mut)
    except SyntaxError as e:
        return "负控无效：变异后源码语法错误（%s）—— 修好变异本身" % e
    build_fn = next((n for n in ast.walk(tree)
                     if isinstance(n, ast.FunctionDef) and n.name == "build"), None)
    order = _call_order(build_fn)
    if order.index("_archive_stale_dist") < order.index("_delivery_gate"):
        return "负控失效：调用被挪到闸门之后，顺序判据仍然绿"
    return True


def main():
    print("=" * 78)
    print("dist 卫生判据 —— 旧版发布件让开：从手工动作到构建器自己的机制")
    print("（全部内存/临时目录变异，不写任何产品文件）")
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
