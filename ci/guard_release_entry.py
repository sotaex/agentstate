#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.42.0 判据 —— **发布入口不许退化成"建了没人用"**（S40–S42 ＋ S48-release/S49/S50-release，各带负控）。

★★ 这条判据为什么必须存在（2026-10-09 本班三次复发）：

  本班我新建了 `scripts/verify_release.py`（发布验收：dist 布局 / wheel 自洽 /
  twine / 真装一次），写完就丢在那里 —— **零调用方**。一个没有调用方的脚本
  等于不存在。这与本班另外两条复发是同一条病：

    ① 忘记把旧版发布件挪开（手工做，无机制）  ⇒ `_archive_stale_dist()` 自动兜住
    ② 坏 wheel 流到下一轮闸门才被抓            ⇒ `verify_release.py` 兜住
    ③ `verify_release.py` 自己没人调用          ⇒ `scripts/release.py` 入口兜住

  ⇒ 本套件守的是**第③条的兜底本身**：入口必须真的把三步串起来、
    版本号必须从源码读（不给"填错版本"留人手）、出包解释器必须验 setuptools>=68。

  ★ S50-release（2026-10-15，0.50.4 出包实测新增）：**救回必须按版本口径拣件**。
    见下方该判据 docstring —— 裸 `endswith('.tar.gz')` 会把 `.tmp` 残留的
    旧版件捞回 dist，与 `_archive_stale_dist` 的版本口径打架（T-09 同族）。

  ★ 全部判据走 AST / 内存变异，**不跑真实构建、不出真包、不写产品文件**。
  ★ 与 S38/S39（dist 卫生）分工：那两条守"挪旧件"这一步；本套守"整条发布链"。
"""
from __future__ import annotations

import ast
import io
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

PASSED = []
FAILED = []
SKIPPED = []          # 2026-10-16（S53）：补上本仓判据协议的 SKIP 通道
                      # （「返回 True/None=绿、SKIP 前缀=跳过、问题串=红」——
                      # 本套件此前没实现 SKIP；S53 的「无暂存＝非交接时刻」
                      # 需要诚实的跳过语义，不许假绿也不许假红）


def check(name):
    def deco(fn):
        try:
            r = fn()
        except Exception as e:                       # noqa: BLE001
            r = "判据自身异常：%r" % (e,)
        if isinstance(r, str) and r.startswith("SKIP"):
            SKIPPED.append((name, r))
        else:
            (PASSED if r is True else FAILED).append((name, r))
        return fn
    return deco


def _src(rel):
    return io.open(os.path.join(ROOT, rel), encoding="utf-8").read()


def _tree(src):
    return ast.parse(src)


def _func(tree, name):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef,)) and n.name == name:
            return n
    return None


def _calls(node):
    """取一个函数体里**按源码顺序**的全部直接调用名（按行号排序，不用 ast.walk）。

    ★ 为什么不能 `ast.walk`：它是广度优先，节点顺序 ≠ 源码顺序。
      本班在 S39 上正踩过这个 —— 顺序判据因为遍历顺序巧合而绿。
    """
    out = []
    for n in ast.iter_child_nodes(node):
        if isinstance(n, ast.Call):
            nm = getattr(n.func, "id", None)
            if nm:
                out.append((n.lineno, nm))
    # 递归进嵌套块（if/try/for/with），仍按行号汇总
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            nm = getattr(n.func, "id", None)
            if nm:
                out.append((n.lineno, nm))
    return sorted(set(out))


def _load_module(src, name):
    """把一段源码当模块加载（用于负控的内存变异）。"""
    import types
    mod = types.ModuleType(name)
    mod.__file__ = os.path.join(ROOT, name + ".py")
    code = compile(src, mod.__file__, "exec")
    sys.modules[name] = mod
    exec(code, mod.__dict__)                          # noqa: S102
    return mod


# ══════════ S40 · 发布入口必须真的串起三步 ══════════════════════════════
@check("S40 发布入口串联三步：build_package(--verify) → 出包 → verify_release")
def s40():
    rel = "scripts/release.py"
    if not os.path.isfile(os.path.join(ROOT, rel)):
        return "找不到 %s —— 入口不存在" % rel
    tree = _tree(_src(rel))
    # 三个必需调用：build_package.py / python -m build / verify_release.py
    text = _src(rel)
    for token, why in (("build_package.py", "装配＋闸门＋两次 harness"),
                       ('"-m", "build"', "出 wheel/sdist"),
                       ("verify_release.py", "发布验收")):
        if token not in text:
            return "入口里没有调用 %s（%s）—— 这一步会变成没人做的手工活" % (token, why)
    # 且顺序必须是 build_package 在前、verify_release 在后（不许验一个没出的包）
    i_bp = text.index("build_package.py")
    i_vr = text.index("verify_release.py")
    if i_bp > i_vr:
        return "顺序反了：verify_release 出现在 build_package 之前"
    return True


@check("N-S40 负控：把 verify_release 那一步摘掉 ⇒ S40 必须报红")
def n_s40():
    src = _src("scripts/release.py")
    anchor = '"verify_release.py"'
    if anchor not in src:
        return "负控无效：入口里找不到 verify_release 引用"
    mut = src.replace(anchor, '"verify_release_REMOVED.py"')
    if anchor not in _src("scripts/release.py"):
        return "负控无效：变异没有落在真实文件上"
    # 直接判字符串（S40 的同款逻辑，只是喂变异后的源码）
    if '"verify_release.py"' in mut:
        return "负控失效：摘掉那一步后入口仍引用 verify_release"
    return True


# ══════════ S41 · 版本号只从源码读，不许从命令行传 ══════════════════════
@check("S41 版本号从 antinel.py::VERSION 读，发布入口不接受 --version")
def s41():
    tree = _tree(_src("scripts/release.py"))
    f = _func(tree, "main")
    if f is None:
        return "找不到 main()"
    opts = []
    for n in ast.walk(f):
        if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "add_argument":
            if n.args and isinstance(n.args[0], ast.Constant):
                opts.append(n.args[0].value)
    if "--version" in opts:
        return "入口接了 --version —— 给了人手工填错版本的机会（0.41.0 那轮版本号散在 10 处）"
    g = _func(tree, "source_version")
    if g is None:
        return "找不到 source_version() —— 版本号必须从源码读，不是猜的"
    if "VERSION" not in ast.dump(g):
        return "source_version() 不再读 antinel.py 的 VERSION"
    return True


@check("N-S41 负控：给入口加一个 --version 选项 ⇒ S41 必须报红")
def n_s41():
    src = _src("scripts/release.py")
    # 变异：在 argparse 里插一个 --version
    anchor = 'ap.add_argument("--skip-install"'
    if anchor not in src:
        return "负控无效：找不到 add_argument 锚点"
    mut = src.replace(anchor,
                      'ap.add_argument("--version", default=None)\n    ' + anchor, 1)
    tree = _tree(mut)
    f = _func(tree, "main")
    opts = [n.args[0].value for n in ast.walk(f)
            if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "add_argument"
            and n.args and isinstance(n.args[0], ast.Constant)]
    if "--version" not in opts:
        return "负控失效：变异后仍无 --version（说明变异没生效）"
    return True


# ══════════ S42 · 出包解释器必须验 setuptools>=68 ═══════════════════════
@check("S42 出包解释器必须探测 setuptools>=68，不许默认 sys.executable")
def s42():
    tree = _tree(_src("scripts/release.py"))
    g = _func(tree, "_pick_release_py")
    if g is None:
        return "找不到 _pick_release_py() —— 出包解释器必须是探测出来的，不是猜的"
    # ★ 只查**探针常量**，不查整个 dump：docstring 里就写着 "setuptools >= 68"，
    #   用整段 dump 判会把"阈值被改成 0"判成绿（本套件第一版正踩过这个 ——
    #   一个字符串同时命中 docstring 与代码，判据就失效了）。
    probe = [n.value for n in ast.walk(g)
             if isinstance(n, ast.Constant) and isinstance(n.value, str)
             and n.value.startswith("import setuptools")]
    if not probe:
        return "_pick_release_py() 里没有 setuptools 探测代码"
    if "68" not in probe[0]:
        return "_pick_release_py() 不再校验 setuptools>=68（本机 C:\\Python311 是 65.5.0，" \
               "不校验就会拿到一个必然被 build 拒的解释器）"
    # sys.executable 在 AST 里是 **Attribute**（Name('sys').executable），
    # 不是字符串常量 ⇒ 判 dump 里有没有这个字面量永远为假。
    has_se = any(isinstance(n, ast.Attribute) and n.attr == "executable"
                 and isinstance(n.value, ast.Name) and n.value.id == "sys"
                 for n in ast.walk(g))
    if not has_se:
        return "_pick_release_py() 不再把 sys.executable 纳入候选（它应是**最后**候选，不是第一）"
    return True


@check("N-S42 负控：把 setuptools 探测摘掉 ⇒ S42 必须报红")
def n_s42():
    src = _src("scripts/release.py")
    probe_anchor = "import setuptools,sys;v=tuple(int(x) for x in "
    if probe_anchor not in src:
        return "负控无效：找不到 setuptools 探测代码可供变异"
    mut = src.replace(probe_anchor, "import sys;sys.exit(0);_UNUSED=(", 1)
    try:
        tree = _tree(mut)
    except SyntaxError as e:
        # 变异造成了语法错 —— 换一种不破坏语法的变异：把阈值 68 改成 0
        mut = src.replace("v>=(68,)", "v>=(0,)", 1)
        tree = _tree(mut)
    g = _func(tree, "_pick_release_py")
    if g is None:
        return "负控无效：变异后找不到函数"
    # 只比探针常量，不比整段 dump（docstring 里也有 "68"）
    probe = [n.value for n in ast.walk(g)
             if isinstance(n, ast.Constant) and isinstance(n.value, str)
             and n.value.startswith("import setuptools")]
    if not probe:
        # 探测代码整个被摘掉 ⇒ S42 会以「没有 setuptools 探测代码」报红
        # ⇒ 负控**成立**。（第一版在这里误判成"负控失效"：只看"68"在不在，
        #    没意识到"探针没了"同样让 S42 红。）
        return True
    if "68" in probe[0]:
        return "负控失效：阈值被改成 0 后仍能检出 68"
    return True


# ══════════ S48-release · verify_release 的 sdist 陈旧判据必须是结构的 ══════════════
#
# ★ 为什么补这条（0.42.1，一次实测逼出来的）：
#   0.42.0 出包后第一次真跑 `verify_release.py`，它在 [B] 步报
#   「sdist 里混着非本版目录成员：['antinel-0.42.0']」并中止 ——
#   而 tar 里 159 个成员**全部**在本版目录下（tarfile 逐名取证，零旧版成员）。
#   ★ 是**量具自己错了**：子串三段式把 tar 的顶层目录项本身（无尾斜杠）
#     误判成"非本版成员"（假红；更坏的是它中止在后，[C] twine / [D] 真装
#     都没跑到）。已改成结构判据（顶层路径分量恰为 antinel-<version>）。
#   ⇒ 本条把"两个方向"钉死：干净 sdist 不许误杀；真混旧版必须抓得到。
_CLEAN_MEMBERS = [
    "antinel-0.42.0",                       # ← 顶层目录项本身（无尾斜杠）：第一版就死在这
    "antinel-0.42.0/LICENSE",
    "antinel-0.42.0/PKG-INFO",
    "antinel-0.42.0/antinel.py",
    "antinel-0.42.0/antinel.egg-info/SOURCES.txt",
]
_STALE_MEMBERS = _CLEAN_MEMBERS + ["antinel-0.41.0", "antinel-0.41.0/old_module.py"]
_VER = "0.42.0"


def _judge_stale_fn(fn):
    """S48-release 的判据本体（行为判据：喂成员表，不看源码形状）。

    ★ 期望值**写死**在本文件里（_CLEAN_MEMBERS / _STALE_MEMBERS / _VER），
      不取自被测对象 —— 0380 S10 的教训：期望跟着被测对象变 ⇒ 判据永远绿。
    """
    try:
        clean = fn(list(_CLEAN_MEMBERS), _VER)
        stale = fn(list(_STALE_MEMBERS), _VER)
    except Exception as e:                           # noqa: BLE001
        return "判据自身异常：%r" % (e,)
    if clean:
        return ("干净 sdist 被误判出陈旧成员：%r —— 子串判据把本版顶层目录项"
                "（无尾斜杠）误杀，正是 0.42.1 修掉的假红" % (clean[:3],))
    if not stale:
        return "真混了旧版成员却判不出来 —— 判据失去检出能力（比假红更危险）"
    return True


@check("S48-release sdist 陈旧判据必须结构化：干净不误杀、混旧版必抓到")
def s48():
    rel = "scripts/verify_release.py"
    if not os.path.isfile(os.path.join(ROOT, rel)):
        return "找不到 %s" % rel
    mod = _load_module(_src(rel), "verify_release_under_test")
    fn = getattr(mod, "_sdist_stale_members", None)
    if fn is None:
        return "verify_release.py 里没有 _sdist_stale_members() —— 判据必须可单测"
    return _judge_stale_fn(fn)


@check("N-S48-release 负控：把判据换回第一版的子串写法 ⇒ 干净 sdist 必被误杀（S48-release 必须因此红）")
def n_s48():
    src = _src("scripts/verify_release.py")
    anchor = '        if top != want:\n'
    if anchor not in src:
        return "负控无效：找不到结构化判据锚点（产品已改写法？负控要同步）"
    # 变异＝**逐字复刻第一版的子串三段式**（0.42.1 修掉的那个假红）；
    # 只换条件行，其余原样 ⇒ 语法安全、语义忠实。
    buggy = ('        if ("antinel-0." in m and "/%s/" % version not in m\n'
             '                and not m.startswith("antinel-%s/" % version)):\n')
    mut = src.replace(anchor, buggy, 1)
    if mut == src:
        return "负控无效：变异没有落在真实源码上"
    try:
        code = compile(mut, "<n_s48_mutant>", "exec")
    except SyntaxError as e:
        return "负控无效：变异造成了语法错（%s）" % e
    import types
    mod = types.ModuleType("verify_release_mutant")
    mod.__file__ = os.path.join(ROOT, "verify_release_mutant.py")
    sys.modules["verify_release_mutant"] = mod
    exec(code, mod.__dict__)                         # noqa: S102
    fn = getattr(mod, "_sdist_stale_members", None)
    if fn is None:
        return "负控无效：变异后找不到函数"
    r = _judge_stale_fn(fn)
    if r is True:
        return ("负控失效：换回第一版子串写法后，干净 sdist 仍不被误杀 —— "
                "说明 S48-release 分辨不出这次复发（判据白装）")
    return True


# ══════════ S49 · 安装态探针必须真能跑通（行为判据：真跑，不是看字符串） ══════
#
# ★ 为什么补这条（0.42.1，第二次实测逼出来的）：
#   [B] 的子串假红修好后，verify_release 第一次走到 [D] 就挂在安装态探针上 ——
#   `antinel.main(['--version'])` 打完成本走 **SystemExit(0)**，第一版探针没接，
#   进程在 `process_elevation()` 之前就退了 ⇒ "E2E-OK" 永远打不出来 ⇒ 假红。
#   ★ 与 S48-release 同族、但更狠：**脚本化 D 步一次都没跑完过**（0.42.0 出包后被 [B]
#     中止；文档里 0.41.0 那次"通过"是手工探针）—— **零覆盖的路径必然是坏的**。
# ⇒ 本条把探针当**可执行对象**真跑（对源码树，不装包）：接住 SystemExit、
#   核对版本、提权探测可调，三件事缺一即红；负控两个变异都必须让它红。
def _source_version():
    """从 antinel.py 读 VERSION（AST；不拿整段 dump 判子串——docstring 里也有版本号）。"""
    tree = _tree(_src("antinel.py"))
    vals = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and n.value and isinstance(n.value, ast.Constant) \
                and isinstance(n.value.value, str):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id == "VERSION":
                    vals.add(n.value.value)
    if len(vals) != 1:
        return None
    return vals.pop()


def _run_probe(probe_src):
    return subprocess.run([sys.executable, "-c", probe_src],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=180)


@check("S49 安装态探针真跑通：接住 SystemExit ＋ 核对版本 ＋ 提权探测")
def s49():
    mod = _load_module(_src("scripts/verify_release.py"), "verify_release_ut2")
    tpl = getattr(mod, "_E2E_PROBE", None)
    if not tpl:
        return ("verify_release.py 里没有 _E2E_PROBE 常量 —— 探针必须可单测"
                "（第一版内联在 check_install 里，从来没有被执行过）")
    ver = _source_version()
    if not ver:
        return "读不到 antinel.py::VERSION（或有多份）"
    try:
        r = _run_probe(tpl.format(target=ROOT, version=ver))
    except Exception as e:                           # noqa: BLE001
        return "探针执行异常：%r" % (e,)
    if r.returncode != 0 or "E2E-OK" not in (r.stdout or ""):
        return ("探针在源码树上跑不通：rc=%s out=%r err=%r"
                % (r.returncode, (r.stdout or "")[-200:], (r.stderr or "")[-200:]))
    if ("E2E-OK %s " % ver) not in (r.stdout or ""):
        return "探针没打印期望的 E2E-OK %s …：%r" % (ver, (r.stdout or "")[-200:])
    return True


@check("N-S49 负控：摘掉 try/except ／ 喂错版本 ⇒ 探针必须失败（证 S49 不空转）")
def n_s49():
    mod = _load_module(_src("scripts/verify_release.py"), "verify_release_mut2")
    tpl = getattr(mod, "_E2E_PROBE", None)
    if not tpl:
        return "负控无效：没有 _E2E_PROBE"
    ver = _source_version()
    if not ver:
        return "负控无效：读不到版本"
    # 变异①：整块摘掉 try/except —— 逐字复刻第一版（main 退成 SystemExit ⇒ 探针死）
    anchor = ("try:\n    antinel.main(['--version'])\n"
              "except SystemExit as e:\n    assert e.code in (0, None), e.code\n")
    if anchor not in tpl:
        return "负控无效：找不到 try/except 锚点"
    mut1 = tpl.replace(anchor, "antinel.main(['--version'])\n", 1)
    r1 = _run_probe(mut1.format(target=ROOT, version=ver))
    ok1 = (r1.returncode == 0 and "E2E-OK" in (r1.stdout or ""))
    # 变异②：喂一个错版本号 —— 版本核对必须是承重的
    r2 = _run_probe(tpl.format(target=ROOT, version="0.0.0-deliberately-wrong"))
    ok2 = (r2.returncode == 0 and "E2E-OK" in (r2.stdout or ""))
    if ok1:
        return ("负控失效①：摘掉 try/except 后探针仍跑通 —— S49 的 SystemExit 半边空转"
                "（正是 0.42.1 修掉的假红）")
    if ok2:
        return "负控失效②：喂错版本探针仍跑通 —— 版本核对是空转的"
    return True


@check("S50-release sdist 救回必须按版本口径拣件：不许裸 endswith('.tar.gz') 捞回旧版")
def s50():
    """★★ 2026-10-15（0.50.4 出包实测）真缺陷的守卫。

    病：`build_artifacts` 的 sdist 救回循环扫 dist 下**所有** `.tmp-*/`，
      把**任何** `.tar.gz` 捞回，**不校验版本** ⇒ 上一轮残留的
      `.tmp-*/antinel-<旧版>.tar.gz` 被捞回来 ⇒ dist 混入旧版件 ⇒
      步骤 3 `verify_release` 判 `[A] dist 布局` 红，白跑一轮 22 分钟。

    本判据（结构，AST）：`build_artifacts` 里
      ① **不许**出现 `X.endswith(".tar.gz")`（裸后缀 = 没有版本口径）；
      ② **必须**出现 `"antinel-%s.tar.gz" % version`（期望名由版本构造）。
    两条缺一即红 —— 只看 ① 会因为"改了写法但没真按版本"漏判。
    """
    tree = _tree(_src("scripts/release.py"))
    fn = _func(tree, "build_artifacts")
    if fn is None:
        return "读不到 build_artifacts（发布入口结构变了，本判据会瞎——不许静默通过）"
    # ① 裸后缀筛选（病态形状）
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "endswith":
            vals = [a.value for a in n.args if isinstance(a, ast.Constant)]
            if ".tar.gz" in vals:
                return ("build_artifacts 里仍有裸 `endswith('.tar.gz')` 拣件"
                        "（第 %d 行）—— 没版本口径，会把 .tmp 残留的旧版件捞回 dist"
                        "（0.50.4 实测形状：dist 混入 antinel-0.50.3.tar.gz ⇒ 布局判红）"
                        % (n.lineno,))
    # ② 期望名必须由 version 构造
    want_ok = False
    for n in ast.walk(fn):
        if (isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod)
                and isinstance(n.left, ast.Constant)
                and isinstance(n.left.value, str)
                and "tar.gz" in n.left.value
                and isinstance(n.right, ast.Name) and n.right.id == "version"):
            want_ok = True
    if not want_ok:
        return ("build_artifacts 里找不到由 version 构造的期望文件名"
                "（应为 `'antinel-%s.tar.gz' % version`）—— 救回没有版本口径")
    return True


@check("N-S50-release 负控：把拣件条件换回裸 endswith('.tar.gz') ⇒ S50-release 必须报红")
def n_s50():
    src = _src("scripts/release.py")
    anchor = '                if f != _want:                       # ★ 只认本版件（版本口径）\n'
    if anchor not in src:
        return "负控无效：找不到版本口径锚点（产品又改形状了，先同步本判据）"
    mut = src.replace(anchor, '                if f.endswith(".tar.gz"):\n', 1)
    if mut == src:
        return "负控无效：变异没产生任何变化"
    try:
        tree = _tree(mut)
    except SyntaxError as e:                          # noqa: BLE001
        return "负控无效：变异造成语法错误 %r" % (e,)
    fn = _func(tree, "build_artifacts")
    if fn is None:
        return "负控无效：变异后读不到 build_artifacts"
    # 用 S50 的同款检测逻辑喂变异源码
    hit_bare = False
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "endswith":
            vals = [a.value for a in n.args if isinstance(a, ast.Constant)]
            if ".tar.gz" in vals:
                hit_bare = True
    if not hit_bare:
        return "负控失效：换回裸 endswith 后 S50 的检测逻辑没抓到（判据是装饰）"
    return True


# ══════════ S53 · 交接自检（2026-10-16，机制层方案 v1.0 §4）══════════════════
#   病灶：交接单接手时——暂存区带空白缺陷（--check rc=2）、manifest 未对齐、
#   新文件裸奔未归批 ⇒ 接手人先考古一小时。三件全是**可机械判**的状态，
#   却全靠人自觉。本判据把它们钉成「有暂存（＝交接时刻的机械代理）就必查」。
#
#   ★ 口径：`git diff --cached --quiet` rc≠0 ＝ 有暂存 ＝ 交接时刻 ⇒ 三件套全查；
#     无暂存 ⇒ 诚实 SKIP（「非交接时刻测不出」——协议允许，不假绿）。
#   ★ 判定逻辑抽纯函数（_staged_ws_clean / _naked_new_files），N-S53 喂变异输入，
#     **零写脏真实暂存区**。
#   ★ ②（manifest 对齐）无既有判据设站（已排查 self_check 在 ci/ 下零消费），
#     P5 允许；它放最后（最贵的一个）。
_NAKED_DOMAINS = ("ci/", "hooks/", "psl/", "scripts/", "rules/", "docs/")


def _staged_ws_clean(check_out):
    """① git diff --cached --check 的输出为空 ＝ 暂存区空白干净。"""
    return not (check_out or "").strip()


def _naked_new_files(status_out):
    """③ 未跟踪文件裸奔在产品/判据域 ⇒ 返回清单（豁免项不列）。

    敏感域：ci/ hooks/ psl/ scripts/ rules/ docs/ ＋ 根目录非 `_p_`/`_tools_`
    前缀的 .py（后两者是本仓探针/工具惯例）。output/ .workbuddy/ out/ dist/
    logs/ 是产物与工作区，不在敏感域。
    """
    naked = []
    for ln in (status_out or "").splitlines():
        ln = ln.rstrip("\r")
        if not ln.startswith("??"):
            continue
        p = ln[2:].strip().strip('"').replace("\\", "/")
        if not p:
            continue
        if any(p.startswith(d) for d in _NAKED_DOMAINS):
            naked.append(p)
        elif "/" not in p and p.endswith(".py") \
                and not p.startswith(("_p_", "_tools_")):
            naked.append(p)
    return naked


@check("S53 交接自检（有暂存才查）：暂存空白干净 ＋ 无裸奔新文件 ＋ manifest 对齐")
def s53():
    q = subprocess.run(["git", "-C", ROOT, "diff", "--cached", "--quiet"],
                       capture_output=True, timeout=30)
    if q.returncode == 0:
        return ("SKIP：无暂存内容——非交接时刻，三件套测不出（诚实跳过；"
                "交接时暂存区非空即自动转为全查）")
    # ① 暂存空白干净
    chk = subprocess.run(["git", "-C", ROOT, "diff", "--cached", "--check"],
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=30)
    if not _staged_ws_clean(chk.stdout):
        return "暂存区带空白缺陷（交接债，`git diff --cached --check` 非空）：\n%s" \
               % chk.stdout.strip()[:300]
    # ③ 无裸奔新文件
    st = subprocess.run(["git", "-C", ROOT, "status", "--porcelain"],
                        capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=30)
    naked = _naked_new_files(st.stdout)
    if naked:
        return ("新文件裸奔未归批（交接债）：%s —— 显式 git add 归批，"
                "或 .gitignore 登记豁免" % naked[:6])
    # ② manifest 与源码对齐（只读调用；产品真源不复制逻辑）
    try:
        if ROOT not in sys.path:
            sys.path.insert(0, ROOT)
        import host_shield                                   # noqa: E402
        ok, probs = host_shield.self_check()
    except Exception as e:                                   # noqa: BLE001
        return "self_check 调用失败（不可判非通过）：%r" % (e,)
    if not ok:
        return "manifest 与源码不对齐（交接债，先重签再交接）：%s" % (list(probs)[:3],)
    return True


@check("N-S53 负控：空白缺陷必须被抓、裸奔必须被抓、豁免必须放过（零写脏真实暂存区）")
def n_s53():
    if _staged_ws_clean("inbox_model.py:12: trailing whitespace.\n+xxx \n"):
        return "负控失效：带尾随空格的 check 输出没被抓 ⇒ ①没牙"
    if not _staged_ws_clean(""):
        return "负控失效：干净输出被误抓 ⇒ ①过宽"
    naked = _naked_new_files('?? ci/new_suite.py\n?? _p_probe.py\n'
                             '?? docs/new.md\n?? output/x.png\n'
                             '?? loose.py\n?? _tools_x/helper.py\n')
    for need in ("ci/new_suite.py", "docs/new.md", "loose.py"):
        if need not in naked:
            return "负控失效：裸奔文件 %s 没抓到 ⇒ ③没牙（ got=%r）" % (need, naked)
    for exempt in ("_p_probe.py", "output/x.png", "_tools_x/helper.py"):
        if exempt in naked:
            return "负控失效：豁免项 %s 被误抓 ⇒ ③过宽（got=%r）" % (exempt, naked)
    return True


def main():
    print("=" * 74)
    print("0.42.0 判据 —— 发布入口不许退化成「建了没人用」"
          "（S40–S42 ＋ S48-release/S49/S50-release ＋ S53 交接自检）")
    print("=" * 74)
    for n, r in PASSED:
        print("  ✅ %s" % n)
    for n, r in SKIPPED:
        print("  ⏭️ %s\n       → %s" % (n, r))
    for n, r in FAILED:
        print("  ❌ %s\n       → %s" % (n, r))
    print("-" * 74)
    print("  通过 %d / 失败 %d / 跳过 %d" % (len(PASSED), len(FAILED), len(SKIPPED)))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
