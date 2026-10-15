#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0516 判据 —— P1-2 打包缺件（bubble/logo/sounds）四件套。

★ 卡片原状：`inbox_bubble.py`、`inbox_logo.py` 未登记进 pyproject／
  build_package.py 包根模块清单；`assets/sounds/alert.wav` 需同步
  package-data glob。

★ 本轮实测（2026-10-14）—— 缺口比卡片大一件，根因比卡片深一层：

  ① [E] 实测差集 5 件，且**正是全部未跟踪新件**：`inbox_bubble.py`、
     `inbox_logo.py`、`assets/sounds/alert.wav`、`tools/logo.ps1`、
     `tools/mk_sound.py`（`git status` 实证五件均 `??`）。旧清单
     0.48.4/124 项＝**跟踪件全集**，五个新件从未进过任何清单。
     修法＝四处登记全部到位：pyproject `py-modules`（+inbox_bubble/
     inbox_logo）、pyproject `package-data assets`（+`sounds/*.wav`）、
     `build()` 的 root_mod 复制清单（+两个 .py）、`_LAYOUT`／
     `_TOOL_FALLBACK`（+logo.ps1）。

  ② 清单口径根因（上轮工作区变体踩的坑，比①更致命）： sanctioned 流程是
     `build_package.py --out D:/psl/poc`（release.py 默认值）⇒ final＝
     **仓根本身**，清单由 `_wheel_payload(final, final/MANIFEST.in)`
     生成，天然覆盖 wheel 载荷。上轮用了**新建的** out 目录 ⇒ 装配时
     final 不存在 ⇒ 构建器写不进 final/MANIFEST.in ⇒ 清单生成读到
     OSError ⇒ 退化成「暂存包内容」fallback（那条带 !! 警告的分支）⇒
     实测 128 项**双向错配**：混入 14 个只进 sdist 的件（README/LICENSE/
     docs/references/.github/ci…）、漏掉 15 个真进 wheel 的件
     （tools/host_matrix.py、scripts/run_harness.py…）。**同步那份
     128 项清单，[E] 会比不修更红**（15 未覆盖 vs 5 未覆盖）。
     正解＝final 先成为仓根工作树的完整副本再装配（本机 stage 在工作区
     外被 DST-02 拦，故落工作区内 out/）。重装后实测：129 项，与 wheel
     载荷 131 项减 2 项按设计排除**严格集合相等**（双向空差集）。

  ③ 连带修（不修则装态哈希失配）：仓根 `psl/SKILL.md` 与根 `SKILL.md`
     分家——根件手改后未再构建，装配的 merge 本就把根件盖进 psl/，
     但清单哈希算于 merge **之前**的旧件 ⇒ 插件自检当场
     `drifted ['psl/SKILL.md']`，且 wheel（从仓根出）会带上与清单
     不一致的旧 SKILL.md。按 merge 的既定语义预同步两件再重装。

★ 四件套映射（本文件）：
    正＝PKG16-a   真实 wheel+sdist 含焦点五件 ＋ 四处登记在位 ＋ 产品
                  自己的 [E] 集合对账放行（import，不复制逻辑）。
    反＝N-PKG16-a 安全夹具：py-modules 移除 inbox_bubble 一条声明，
                  真构建出 wheel ⇒ **同一把尺子**判红，且红的只是那一条
                  （其余四件在，归因纯）。
        N-PKG16-b 安全夹具：真 wheel 的副本里把清单 mk_sound.py 条目
                  删一条 ⇒ 产品 [E] 判据判红并点名。
    连带＝PKG16-b 全部 py-modules 都在 wheel 内（不只焦点五件）；
                  运行时资源加载路径（`inbox_bubble.sound_path()`、
                  `inbox_logo.script_path()`）在 wheel 内可解析；
                  判据 ID 无跨套件重名且本套件五条都在映射里。
    观测＝PKG16-c 发布验收原始日志留存且 [A][B][C][E][D] 标头全过；
                  产物路径/大小/哈希与清单版本/条目数入册。

编写纪律（沿用 0514/0515）：负控先实测见红；断言打行为/结构；正判据
导入产品真源；不写任何产品文件（夹具全在临时目录）；测不出 ⇒ SKIP，
绝不报 PASS。
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
CI = os.path.join(ROOT, "ci")
if CI not in sys.path:
    sys.path.insert(0, CI)

import defect_types as DT                                       # noqa: E402

RESULTS = []

#: 焦点五件：卡片三件 ＋ 本轮 [E] 实测补出的两件 tools 脚本（均未跟踪新件）。
_FOCUS = ("inbox_bubble.py", "inbox_logo.py", "assets/sounds/alert.wav",
          "tools/logo.ps1", "tools/mk_sound.py")

#: 发布验收日志的留存路径（观测判据的锚）。
_VERIFY_LOG = os.path.join(ROOT, "output", "p12_verify_release.log")

_BP_CACHE = {}


class Skip(Exception):
    """夹具凑不齐 ⇒ 这一条不判，也**不许判绿**。"""


def check(name):
    """判据必须真会红 —— 返回说明串一律转抛异常；SKIP 前缀转 Skip。"""
    def deco(fn):
        def wrapper():
            r = fn()
            if r is True or r is None:
                return True
            if isinstance(r, str) and r.startswith("SKIP"):
                raise Skip(r)
            raise AssertionError(r if isinstance(r, str) else repr(r))
        RESULTS.append((name, wrapper))
        return fn
    return deco


def _note(*a):
    """可观测：判定细节进 stdout（闸门运行输出即留证）。"""
    print("      · %s" % " ".join(str(x) for x in a))


# ---------------------------------------------------------------- 工具 --

def _version():
    """版本号只认源码里那一个（与 release.py 同源，不从命令行传）。"""
    src = io.open(os.path.join(ROOT, "antinel.py"), encoding="utf-8").read()
    m = re.search(r'^VERSION\s*=\s*"(\d+\.\d+\.\d+)"', src, re.M)
    if not m:
        raise Skip("读不到 antinel.py 的 VERSION —— 拒绝猜版本号")
    return m.group(1)


def _load_product(mod_name, rel):
    """按文件路径 import 产品真源（scripts/ 无 __init__，不用包路径）。"""
    import importlib.util
    p = os.path.join(ROOT, rel)
    if mod_name not in _BP_CACHE:
        spec = importlib.util.spec_from_file_location(mod_name, p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _BP_CACHE[mod_name] = m
    return _BP_CACHE[mod_name]


def _wheel_payload(whl):
    """wheel 载荷成员集合（排除目录项与 dist-info）。"""
    with zipfile.ZipFile(whl) as z:
        return set(n for n in z.namelist()
                   if not n.endswith("/") and ".dist-info" not in n.split("/")[0])


def _wheel_path(dist, version):
    whl = os.path.join(dist, "antinel-%s-py3-none-any.whl" % version)
    if not os.path.isfile(whl):
        raise Skip("没有 %s —— 未构建或已归档（先出包再判）" % whl)
    return whl


def _sdist_payload(tgz):
    """sdist 成员集合（剥掉顶层 `antinel-<ver>/` 前缀，与 wheel 口径对齐）。"""
    with tarfile.open(tgz) as t:
        return set(n.split("/", 1)[1] for n in t.getnames()
                   if "/" in n and n.split("/", 1)[1] and not n.endswith("/"))


def _sdist_path(dist, version):
    tgz = os.path.join(dist, "antinel-%s.tar.gz" % version)
    if not os.path.isfile(tgz):
        raise Skip("没有 %s —— 未构建或已归档（先出包再判）" % tgz)
    return tgz


def _sha16(p):
    h = hashlib.sha256()
    with io.open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def _declarations():
    """四处登记（py-modules / package-data / _LAYOUT / root_mod） direct-read。

    读的全是**真源**：仓根 pyproject.toml（wheel 的真正构建输入）、
    build_package.py 的模块级 `_LAYOUT`、build() 内 root_mod 元组（AST）。
    """
    with io.open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
        pp = tomllib.load(f)
    ts = pp.get("tool", {}).get("setuptools", {}) or {}
    mods = set(ts.get("py-modules") or [])
    pdata = ts.get("package-data") or {}
    bp = _load_product("bp_pkg16", os.path.join("scripts", "build_package.py"))
    layout_paths = set(str(v).replace("\\", "/") for v in bp._LAYOUT.values())
    return mods, pdata, layout_paths, _root_mod_set()


def _root_mod_set():
    """AST 取 build() 里 root_mod 复制清单（同前缀函数/文本 split 会落错）。"""
    src = io.open(os.path.join(ROOT, "scripts", "build_package.py"),
                  encoding="utf-8").read()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == "build":
            for sub in ast.walk(node):
                if isinstance(sub, ast.For) and isinstance(sub.iter, ast.Tuple):
                    vals = [e.value for e in sub.iter.elts
                            if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                    if "antinel.py" in vals:      # 认准 root_mod 那个元组
                        return set(vals)
    return None


def _presence_judge(wheel_names, sdist_names=None, decls=None):
    """正/负控**同一把尺子**，只换输入。返回问题串或 None。"""
    probs = []
    for rel in _FOCUS:
        if rel not in wheel_names:
            probs.append("wheel 缺 %s" % rel)
        if sdist_names is not None and rel not in sdist_names:
            probs.append("sdist 缺 %s" % rel)
    if decls is not None:
        mods, pdata, layout_paths, rootmod = decls
        for m in ("inbox_bubble", "inbox_logo"):
            if m not in mods:
                probs.append("pyproject py-modules 未登记 %s" % m)
        if "sounds/*.wav" not in (pdata.get("assets") or []):
            probs.append("pyproject package-data assets 未含 sounds/*.wav")
        if "tools/logo.ps1" not in layout_paths:
            probs.append("build_package._LAYOUT 未登记 tools/logo.ps1")
        if rootmod is not None:
            for m in ("inbox_bubble.py", "inbox_logo.py"):
                if m not in rootmod:
                    probs.append("build() root_mod 复制清单未含 %s" % m)
    return "；".join(probs) if probs else None


def _release_py():
    """找一个 setuptools>=68 的解释器（夹具构建用）；找不到返回 None。"""
    cands = []
    if os.environ.get("ANTINEL_RELEASE_PY"):
        cands.append(os.environ["ANTINEL_RELEASE_PY"])
    cands.append(os.path.join(os.path.expanduser("~"), ".workbuddy", "binaries",
                              "python", "envs", "default", "Scripts", "python.exe"))
    cands.append(sys.executable)
    for py in cands:
        if not py or not os.path.isfile(py):
            continue
        try:
            r = subprocess.run(
                [py, "-c", "import setuptools,sys;v=tuple(int(x) for x in "
                 "setuptools.__version__.split('.')[:2]);sys.exit(0 if v>=(68,) else 3)"],
                capture_output=True, timeout=120)
        except Exception:                                       # noqa: BLE001
            continue
        if r.returncode == 0:
            return py
    return None


def _build_fixture_tree(root, version):
    """安全夹具：py-modules **移除 inbox_bubble 一条声明**，其余照抄仓根。

    只动这一条 ⇒ 若尺子判红，红的必须只是它（其余四件仍在，归因纯）。
    资源件走与真构建同族的机制：assets/sounds 走 package-data glob、
    tools/*.ps1 走 package-data glob（真构建里它走 MANIFEST.in 的
    `recursive-include tools *.md *.ps1`，同效不同路，尺子不问路）。
    """
    with io.open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
        pp = tomllib.load(f)
    mods = [m for m in pp["tool"]["setuptools"]["py-modules"] if m != "inbox_bubble"]
    os.makedirs(os.path.join(root, "tools"), exist_ok=True)
    os.makedirs(os.path.join(root, "assets", "sounds"), exist_ok=True)
    for m in mods:
        shutil.copy2(os.path.join(ROOT, m + ".py"), os.path.join(root, m + ".py"))
    for rel in ("tools/logo.ps1", "tools/mk_sound.py", "assets/sounds/alert.wav"):
        shutil.copy2(os.path.join(ROOT, rel), os.path.join(root, rel))
    lines = [
        "[build-system]",
        'requires = ["setuptools>=68"]',
        'build-backend = "setuptools.build_meta"',
        "",
        "[project]",
        'name = "antinel"',
        'version = "%s"' % version,
        "",
        "[tool.setuptools]",
        "py-modules = [%s]" % ", ".join('"%s"' % m for m in mods),
        'packages = ["tools", "assets"]',
        "",
        "[tool.setuptools.package-data]",
        'assets = ["sounds/*.wav"]',
        'tools = ["*.ps1"]',
        "",
    ]
    with io.open(os.path.join(root, "pyproject.toml"), "w",
                 encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    return mods


# ═══════════════════════════════ 正判据 ═══════════════════════════════════

@check("PKG16-a ★ 真实产物含焦点五件（wheel＋sdist）＋ 四处登记在位 ＋ [E] 集合对账")
def c_pkg16a():
    version = _version()
    dist = os.path.join(ROOT, "dist")
    whl = _wheel_path(dist, version)
    tgz = _sdist_path(dist, version)
    wn = _wheel_payload(whl)
    sn = _sdist_payload(tgz)
    why = _presence_judge(wn, sn, _declarations())
    if why:
        return why
    # [E]：调**产品自己的判据**（import，不复制逻辑）—— 集合对账防「修好五件、
    # 碰坏一件」：双向空差集才算数。
    vr = _load_product("vr_pkg16", os.path.join("scripts", "verify_release.py"))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = vr.check_manifest_vs_wheel(dist, version)
    if not ok:
        tail = buf.getvalue().strip().splitlines()
        return "产品判据 [E] 判红：%s" % (tail[-1] if tail else "（无输出）")
    _note("wheel 载荷 %d 成员 / sdist %d 成员 / [E] 集合相等 ✅" % (len(wn), len(sn)))
    return True


# ═══════════════════════════════ 反向对照 ═════════════════════════════════

@check("N-PKG16-a 负控：py-modules 移除 inbox_bubble 一条声明 ⇒ 同一把尺子必须判红")
def n_pkg16a():
    py = _release_py()
    if not py:
        raise Skip("找不到 setuptools>=68 的解释器 —— 夹具构建跑不起来（不判绿）")
    version = _version()
    work = tempfile.mkdtemp(prefix="g0516_fix_")
    tree = os.path.join(work, "tree")
    fdist = os.path.join(work, "dist")
    os.makedirs(fdist, exist_ok=True)
    _build_fixture_tree(tree, version)
    try:
        rc = subprocess.run([py, "-m", "build", "--no-isolation", "--wheel",
                             "--outdir", fdist], cwd=tree,
                            capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        raise Skip("夹具构建超时 —— 环境问题，不是判据红")
    fwhl = os.path.join(fdist, "antinel-%s-py3-none-any.whl" % version)
    if rc.returncode != 0 or not os.path.isfile(fwhl):
        raise Skip("夹具构建失败（环境问题）：%s" %
                   (rc.stdout[-200:] if rc.stdout else rc.returncode))
    names = _wheel_payload(fwhl)
    why = _presence_judge(names)          # 同一把尺子，只换输入
    if why is None:
        return "负控失效：声明移除后尺子仍全绿 ⇒ 它根本没在查这件事"
    if "inbox_bubble.py" not in why:
        return "红了但红的不是 inbox_bubble.py（归因不纯）：%s" % why
    others_missing = [r for r in _FOCUS if r != "inbox_bubble.py" and r not in names]
    if others_missing:
        return ("夹具不成立：其余焦点件也缺 %r —— 红不能归因于移除的那一条"
                % others_missing)
    _note("夹具 wheel（py-modules 少 inbox_bubble）⇒ 尺子红：%s；其余四件均在" % why)
    return True


@check("N-PKG16-b 负控：清单少一条 mk_sound.py ⇒ 产品 [E] 判据必须判红并点名")
def n_pkg16b():
    version = _version()
    whl = _wheel_path(os.path.join(ROOT, "dist"), version)
    work = tempfile.mkdtemp(prefix="g0516_neg_")
    fdist = os.path.join(work, "dist")
    os.makedirs(fdist, exist_ok=True)
    fwhl = os.path.join(fdist, "antinel-%s-py3-none-any.whl" % version)
    # 逐成员重写：只把 psl/manifest.json 里的 tools/mk_sound.py 条目删掉，
    # 其余字节原样 —— 变异点唯一，红必须由它引起。
    with zipfile.ZipFile(whl) as zin, \
            zipfile.ZipFile(fwhl, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "psl/manifest.json":
                man = json.loads(data.decode("utf-8"))
                man["files"].pop("tools/mk_sound.py", None)
                data = json.dumps(man, ensure_ascii=False, indent=1).encode("utf-8")
            zout.writestr(item, data)
    vr = _load_product("vr_pkg16", os.path.join("scripts", "verify_release.py"))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = vr.check_manifest_vs_wheel(fdist, version)
    if ok:
        return "负控失效：清单少一条 tools/mk_sound.py，[E] 却放行"
    if "mk_sound.py" not in buf.getvalue():
        return "红了但没点名 mk_sound.py —— 判据没真的在查它"
    _note("变异 wheel 清单少 tools/mk_sound.py ⇒ [E] 红（产品判据自发，点名在）")
    return True


# ═══════════════════════════════ 连带对照 ═════════════════════════════════

@check("PKG16-b 连带：全部 py-modules 在 wheel；运行时资源路径可解析；判据 ID 无重名")
def c_pkg16b():
    version = _version()
    whl = _wheel_path(os.path.join(ROOT, "dist"), version)
    wn = _wheel_payload(whl)
    mods = _declarations()[0]
    missing = sorted(m for m in mods if (m + ".py") not in wn)
    if missing:
        return "py-modules 声明了但 wheel 里没有：%r" % missing
    # 运行时资源加载路径：产品真源 import，算出来的路径必须在 wheel 内
    # （inbox_bubble 响提示音、inbox_logo 起哨标，都指这个文件）。
    import inbox_bubble
    import inbox_logo
    sp = inbox_bubble.sound_path()
    rel = os.path.relpath(
        sp, os.path.dirname(os.path.abspath(inbox_bubble.__file__))
    ).replace("\\", "/")
    if rel not in wn:
        return "inbox_bubble.sound_path() 指向 %s，wheel 里没有" % rel
    lp = inbox_logo.script_path()
    rel2 = os.path.relpath(
        lp, os.path.dirname(os.path.abspath(inbox_logo.__file__))
    ).replace("\\", "/")
    if rel2 not in wn:
        return "inbox_logo.script_path() 指向 %s，wheel 里没有" % rel2
    # P0-2 口径延续：本套件五条 ID 必须真在映射里，且跨套件无重名。
    dups = DT.duplicate_gate_ids()
    if dups:
        return "判据 ID 跨套件重名：%r" % (dups[:3],)
    amap = DT.gate_id_map()
    for gid in ("PKG16-a", "N-PKG16-a", "N-PKG16-b", "PKG16-b", "PKG16-c"):
        if gid not in amap:
            return "本套件判据 %s 未进 gate_id_map（登记簿与实际不同锚）" % gid
    _note("py-modules %d 个全在 wheel；sound_path→%s；script_path→%s；"
          "ID 映射五条在位、无重名" % (len(mods), rel, rel2))
    return True


# ═══════════════════════════════ 可观测 ═══════════════════════════════════

@check("PKG16-c 观测：发布验收日志五标头留存全过；产物大小/哈希/清单版本入册")
def c_pkg16c():
    version = _version()
    if not os.path.isfile(_VERIFY_LOG):
        raise Skip("没有 %s —— 本轮未跑发布验收（不判绿）" % _VERIFY_LOG)
    txt = io.open(_VERIFY_LOG, encoding="utf-8").read()
    for marker in ("[A]", "[B]", "[C]", "[E]", "[D]", "全部通过"):
        if marker not in txt:
            return "验收日志缺 %s —— 要么没跑全，要么日志被截断" % marker
    if "❌" in txt or "未通过" in txt:
        return "验收日志里有红项 —— 留存的是失败记录"
    dist = os.path.join(ROOT, "dist")
    whl = _wheel_path(dist, version)
    tgz = _sdist_path(dist, version)
    for p in (whl, tgz):
        _note("%s  %d bytes  sha256:%s…"
              % (os.path.basename(p), os.path.getsize(p), _sha16(p)))
    man = json.load(io.open(os.path.join(ROOT, "psl", "manifest.json"),
                            encoding="utf-8"))
    if man.get("version") != version:
        return "清单版本 %s 与源码 VERSION %s 不一致" % (man.get("version"), version)
    _note("psl/manifest.json %s / %d entries / built_at=%s"
          % (man.get("version"), len(man.get("files") or {}), man.get("built_at")))
    return True


def main():
    print("=" * 78)
    print("0516 判据 —— P1-2 打包缺件四件套（真实产物/登记/集合对账/负控/连带/观测）")
    print("（夹具全在临时目录，不写任何产品文件）")
    print("=" * 78)
    ok = fail = skip = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True or why is None:
                why = ""
            print("  ✅ %-58s %s" % (name, why or ""))
            ok += 1
        except Skip as s:
            print("  ⏭️  %-58s %s" % (name, s))
            skip += 1
        except AssertionError as e:
            print("  ❌ %-58s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-58s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红 / %d 跳过" % (ok, fail, skip))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
