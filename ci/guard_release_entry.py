#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.42.0 判据 —— **发布入口不许退化成"建了没人用"**（S40–S42 ＋ S48-release/S49/S50-release ＋ S53，各带负控）。

  ★ S54-release（2026-10-22 新增）：**研发树复位步必须在入口里，且必须在验收之后**。
    S40 只查三个 token，`_finalize_dev_tree` 那两行零判据覆盖 —— 删掉它 S40 照样绿，
    而漏一次复位就把「研发树自检不符」渲染成假失守摆到用户眼前（0.53.1 漏两次、
    19:22 绕行出包又复发一次）。S70/N-S70 守**效果**（落差必须在），本条守**存在**。

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
def _s40_core(src):
    """S40 的纯判断（正/负控共用，**不二次实现**）：三 token 在＋顺序对。

    ★★ 2026-10-22 修正：顺序锚点改走 **AST 常量**。
      旧写法用 `text.index(...)` 比 `build_package.py` 与 `verify_release.py`
      的首现位置 —— 而这两个串都在 `release.py` 的**模块 docstring** 里就先出现过
      （第 11 行／第 16 行）⇒ 11 < 16 恒成立 ⇒ **顺序检查恒绿**。
      实证（`output/_p_s40_anchor.py`）：把 verify_release 那段调用真挪到
      build_package 之前，旧逻辑仍判过。只认 `main` 函数体内的字符串常量。
    """
    text = src
    for token, why in (("build_package.py", "装配＋闸门＋两次 harness"),
                       ('"-m", "build"', "出 wheel/sdist"),
                       ("verify_release.py", "发布验收")):
        if token not in text:
            return "入口里没有调用 %s（%s）—— 这一步会变成没人做的手工活" % (token, why)
    tree = _tree(text)
    main = _func(tree, "main")
    if main is None:
        return "找不到 main 函数（顺序判不出）"
    bp = [n.lineno for n in ast.walk(main)
          if isinstance(n, ast.Constant) and n.value == "build_package.py"]
    vr = [n.lineno for n in ast.walk(main)
          if isinstance(n, ast.Constant) and n.value == "verify_release.py"]
    if not bp or not vr:
        return ("main 里找不到 build_package.py / verify_release.py 的调用常量"
                "（锚点没了，判不出不许算通过）")
    if max(bp) > min(vr):
        return ("顺序反了：build_package（第 %s 行）在 verify_release（第 %d 行）之后"
                " —— 不许验一个没出的包" % (bp, min(vr)))
    return None


@check("S40 发布入口串联三步：build_package(--verify) → 出包 → verify_release")
def s40():
    rel = "scripts/release.py"
    if not os.path.isfile(os.path.join(ROOT, rel)):
        return "找不到 %s —— 入口不存在" % rel
    r = _s40_core(_src(rel))
    return r if r is not None else True


@check("N-S40 负控：把 verify_release 那一步摘掉／把顺序调换 ⇒ S40 必须各自红")
def n_s40():
    """两个方向都要真红：① 摘 token；② **只调顺序**（2026-10-22 补的方向）。

    ★ 为什么补方向②：旧负控只验「摘掉」，而旧 S40 的顺序检查本身恒绿
      （锚点钉在 docstring 上）⇒ 那个方向从来没被证过。现在 S40 用 AST 常量，
      负控必须喂一个**真把顺序调换**的变异体，否则新锚点同样没被证。
    """
    src = _src("scripts/release.py")
    anchor = '"verify_release.py"'
    if anchor not in src:
        return "负控无效：入口里找不到 verify_release 引用"
    # 方向①：摘掉**全部**引用（旧版只摘第一处 —— 那处在 docstring 里， main 的
    # 调用还在 ⇒ 新核心仍绿，负控会自曝失效，故必须全摘）。
    mut = src.replace(anchor, '"verify_release_REMOVED.py"')
    r1 = _s40_core(mut)
    if r1 is None:
        return "负控失效：摘掉 verify_release 后 S40 仍绿"
    # 方向②：把 verify_release 那段调用整块挪到 build_package 调用之前。
    a = '    cmd = [py, os.path.join(ROOT, "scripts", "verify_release.py"),'
    if a not in src:
        return "负控无效：找不到 verify_release 的 cmd 赋值锚点"
    i = src.index(a)
    j = src.index('    rc = _run(cmd, cwd=ROOT)', i)
    j = src.index("\n", j) + 1
    block = src[i:j]
    rest = src[:i] + src[j:]
    k = rest.index('    rc = _run([sys.executable, os.path.join(ROOT, "scripts",'
                   ' "build_package.py"),')
    # ★ 必须回到**行首**：这个 `_run([...])` 调用跨两行，插到第一行末尾会插在
    #   语句中间 ⇒ 变异体语法坏（负控连抓两次：先 substring not found，再 SyntaxError）。
    k = rest.rfind("\n", 0, k) + 1
    mut2 = rest[:k] + block + rest[k:]
    if mut2 == src:
        return "负控无效：顺序变异没有落在真实文件上"
    r2 = _s40_core(mut2)
    if r2 is None:
        return "负控失效：把 verify_release 调到 build_package 之前，S40 仍绿"
    if "顺序" not in str(r2):
        return "负控咬错地方：顺序变异该因「顺序」红，实得 %r" % str(r2)[:60]
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
    # ★★ 0.53.0：加 `-c core.whitespace=cr-at-eol` —— **不是放宽判据，是修口径**。
    #   本仓 `.gitattributes` 是构建器拥有的 `* -text`（永不做 EOL 转换），
    #   所以 CRLF 文件的 `\r` 是**内容**不是"行尾多余空白"。不加这个开关时，
    #   任何 CRLF 文件（实测 `ci/delivery_gate.py`）只要有一行被改过，
    #   那条新增行就会被逐行报成 trailing whitespace ⇒ **真缺陷被淹没在假红里**。
    #   `cr-at-eol` 只把 `\r` 归入行终止符：`foo \r\n` 仍会报（真空格照样抓）；
    #   `foo\r\n` 不再报。判据强度一点没降。
    chk = subprocess.run(["git", "-C", ROOT, "-c", "core.whitespace=cr-at-eol",
                          "diff", "--cached", "--check"],
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


# ══════════ S54-release · 研发树复位步必须在入口里（2026-10-22）══════════
def _s54_core(src):
    """S54-release 的纯判断（正/负控共用）：复位步**在**，且**在验收之后**。

    ★ 为什么需要它：S40 只查三个 token，**复位步零判据覆盖** —— 今天把
      `release.py` 里 `_finalize_dev_tree` 那两行删掉，S40 照样绿。而漏一次复位
      就把「研发树自检不符」渲染成**假失守**摆到用户眼前（0.53.1 漏过两次，
      19:22 又因绕行出包复发一次）。S70/N-S70 守的是**效果**（落差必须在），
      本条守**存在**（这一步还在不在入口里）——两件事，两条尺子。

    ★ 锚点纪律（与 S40 2026-10-22 修正同病）：顺序必须比 **main 内的 AST 常量**，
      不许比 `src.find` —— `verify_release.py` 在模块 docstring 第 16 行就出现过，
      比注释位置会让顺序检查恒绿（干跑时变异体当场溜过，见 output/_p_s54_dryrun.py）。
    """
    tree = _tree(src)
    defs = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    if "_finalize_dev_tree" not in defs:
        return "同文件里没有 _finalize_dev_tree 的定义（调用会指向不存在的东西）"
    main = _func(tree, "main")
    if main is None:
        return "找不到 main 函数"
    calls = _calls(main)                      # [(lineno, name)]，按源码顺序
    fin = [ln for ln, nm in calls if nm == "_finalize_dev_tree"]
    if not fin:
        return ("main 里没有调用 _finalize_dev_tree(...) —— 研发树复位这一步会变成"
                "没人做的手工活（漏一次就把假失守摆到用户眼前）")
    vr = [n.lineno for n in ast.walk(main)
          if isinstance(n, ast.Constant) and n.value == "verify_release.py"]
    if not vr:
        return "main 里没有 verify_release.py 的调用常量（锚点没了，判不出）"
    if not [ln for ln in fin if ln > max(vr)]:
        return ("_finalize_dev_tree（第 %s 行）在 verify_release（第 %d 行）之前"
                " —— 顺序反了：没验收完就复位" % (fin, max(vr)))
    return None


@check("S54-release 发布最后一步必须复位研发树（_finalize_dev_tree，且在 verify_release 之后）")
def s54_release():
    r = _s54_core(_src("scripts/release.py"))
    return r if r is not None else True


@check("N-S54-release 负控：摘掉复位调用／把它提到验收之前 ⇒ S54-release 必须各自红")
def n_s54_release():
    """两个方向都喂**内存变异**（零写盘），且必须因各自的红因红。

    ★ 变异体只改**调用点**不改定义（干跑第一版用全局 replace 把定义也改了，
      红因跑偏成「没有定义」，测的不是想测的那件事）。
    """
    src = _src("scripts/release.py")
    anchor = "    if _finalize_dev_tree(version) != 0:\n        return 1\n"
    if anchor not in src:
        return "负控无效：入口里找不到复位调用那两行"
    # 方向①：摘掉调用
    r1 = _s54_core(src.replace(anchor, "", 1))
    if r1 is None:
        return "负控失效：摘掉复位调用后 S54-release 仍绿"
    if "没有调用" not in str(r1):
        return "负控咬错地方：摘除变异该因「没有调用」红，实得 %r" % str(r1)[:60]
    # 方向②：把调用提到 verify_release 之前
    mark = '    _step("3/3"'
    if mark not in src:
        return "负控无效：找不到 _step(\"3/3\") 锚点"
    mut2 = src.replace(anchor, "", 1).replace(mark, anchor + "\n" + mark, 1)
    if mut2 == src:
        return "负控无效：提前变异没有落在真实文件上"
    r2 = _s54_core(mut2)
    if r2 is None:
        return "负控失效：把复位提到验收之前，S54-release 仍绿"
    if "顺序" not in str(r2):
        return "负控咬错地方：提前变异该因「顺序」红，实得 %r" % str(r2)[:60]
    return True


def main():
    print("=" * 74)
    print("0.42.0 判据 —— 发布入口不许退化成「建了没人用」"
          "（S40–S42 ＋ S48-release/S49/S50-release ＋ S53 交接自检"
          " ＋ S54-release 复位步，各带负控）")
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
