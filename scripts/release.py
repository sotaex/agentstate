#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""发布入口 —— 把 0.42.0 之前**四条手工命令**固化为一条（0.42.0 新增）。

★★ 为什么必须有这个入口（2026-10-09 本班三次复发逼出来的）：

  **复发①：忘记把旧版发布件挪开。** 0.41.0 出包时我**手工**把 0.40.0 两件挪进
  `_archive_dist/`。到 0.42.0 构建时我又忘了 ⇒ 闸门三条红（JDG-06 / version /
  regression），根因同一个：dist 里躺着上一版。⇒ 已由 `build_package.py` 的
  `_archive_stale_dist()` **自动**兜住（判据 S38/S39 守着"挪了"且"早于闸门"）。

  **复发②：打完包不验，坏包流到下一轮闸门才被抓。** M11 那个双 dist-info 的
  wheel，`twine check` **两件都放行**，是下一轮 JDG-06 抓住的。⇒ 已由
  `scripts/verify_release.py` 兜住（单一 dist-info / RECORD 自洽 / twine / 真装一次）。

  **复发③：`verify_release.py` 建好了却没人调用。** 它是本班新建的，**零调用方**
  —— 一个没有调用方的脚本等于不存在，正是"修了又复发"的标准形状。

  ⇒ 本入口把三件事串成**一条命令**，且任一步失败即整体失败（不许半途交付）：

     步骤 1  build_package.py --verify      闸门 17 套 → 装配 → 两次 harness
     步骤 2  python -m build                出 wheel ＋ sdist（分两次，带 sdist 救回）
     步骤 3  verify_release.py              布局 / wheel 自洽 / twine / 端到端安装

  ★ 位置纪律：本脚本只**调**别人，不自己实现任何检查逻辑（判据 S40 守着这一点）。
  ★ 版本号从 `antinel.py::VERSION` 读 —— **不**从命令行传（少一个可填错的人工会步）。
  ★ 全程零删除：救回用 `mv`，旧件由步骤 1 内部自动归档。
"""
from __future__ import annotations

import argparse
import hashlib
import os

# 0.60.0：起子进程一律带 CREATE_NO_WINDOW —— 父进程可能是**无控制台**的
# pythonw（钩子）／DETACHED（哨兵）／GUI 宿主 ⇒ 不带就会给子进程新建控制台
# ＝ 用户看到黑窗一闪。本文件若不走 host_shield，就地定义同一常量。
_CNW = 0x08000000 if os.name == "nt" else 0
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _step(n, title):
    print("=" * 74)
    print("步骤 %s —— %s" % (n, title))
    print("=" * 74)


def _run(cmd, **kw):
    print("+ %s" % " ".join(cmd))
    return subprocess.call(cmd, creationflags=_CNW, **kw)


def source_version():
    """版本号只认源码里的那一个（判据 S41 守着：不许从命令行传）。"""
    src = open(os.path.join(ROOT, "antinel.py"), encoding="utf-8").read()
    m = re.search(r'^VERSION\s*=\s*"(\d+\.\d+\.\d+)"', src, re.M)
    if not m:
        raise SystemExit("!! 读不到 antinel.py 的 VERSION —— 拒绝继续（不猜版本号）")
    return m.group(1)


def _pick_release_py(explicit):
    """找一个能出包的解释器：需要 setuptools >= 68。

    ★ 为什么不能就用当前解释器：本机 `C:\\Python311` 的 setuptools 是 65.5.0，
      `python -m build --no-isolation` 会**直接拒**（实测于 0.41.0 那轮）。
    ★ 不硬编码路径：先看 `--py`，再看 `ANTINEL_RELEASE_PY`，再按托管环境惯例找。
    """
    cands = []
    if explicit:
        cands.append(explicit)
    if os.environ.get("ANTINEL_RELEASE_PY"):
        cands.append(os.environ["ANTINEL_RELEASE_PY"])
    if os.environ.get("ANTINEL_PY"):
        cands.append(os.environ["ANTINEL_PY"])
    home = os.path.expanduser("~")
    cands.append(os.path.join(home, ".workbuddy", "binaries", "python", "envs",
                              "default", "Scripts", "python.exe"))
    cands.append(sys.executable)
    for py in cands:
        if not py or not os.path.isfile(py):
            continue
        probe = subprocess.run(
            [py, "-c", "import setuptools,sys;v=tuple(int(x) for x in "
                       "setuptools.__version__.split('.')[:2]);sys.exit(0 if v>=(68,) else 3)"],
            capture_output=True, creationflags=_CNW)
        if probe.returncode == 0:
            return py
    return None


def _sweep_stale_distinfo(tree, version):
    """把暂存树里**非本版**的 `*.dist-info` / `*.egg-info` **移出树外**（零删除）。

    ★ 为什么"移出"而不是"改名"：树内改名后 `wheel pack` 会把它一起打进 wheel
      （0.47.0 实测，JDG-06 判红）。判据按"目录名含 `.dist-info`"认，改名骗不过它。
    ★ 为什么零删除：本仓全程零删除纪律；旧件搬到 `build/_away-<ts>/` 让开即可，
      它是**构建产物目录**（不在 git 索引里，D-24 已判），搬走不损失任何东西。

    返回被搬走的名字列表（空表＝树本来就是干净的）。
    """
    import shutil
    import time as _t

    if not os.path.isdir(tree):
        return []
    keep = "antinel-%s.dist-info" % version
    away_root = os.path.join(os.path.dirname(os.path.dirname(tree)),
                             "_away-" + _t.strftime("%Y%m%d-%H%M%S"))
    moved = []
    for name in sorted(os.listdir(tree)):
        if not (name.endswith(".dist-info") or name.endswith(".egg-info")
                or ".dist-info." in name or ".egg-info." in name):
            continue
        if name == keep:
            continue
        src = os.path.join(tree, name)
        if not os.path.isdir(src):
            continue
        os.makedirs(away_root, exist_ok=True)
        shutil.move(src, os.path.join(away_root, name))
        moved.append(name)
    if moved:
        print("   [扫残留] 暂存树里的非本版 dist-info/egg-info 已移出树外：%s"
              % "、".join(moved))
        print("            （移到 %s；零删除）" % away_root)
    return moved


def _artifact_present(dist, version, kind):
    """dist 里是否已有**本版**产物（且非空）。`kind` = `"wheel"` / `"sdist"`。

    ★★ 0.60.0 为什么需要这个判定（实测形态，与下面两条救回都不同）：
      `python -m build --outdir dist` 是**先**把产物写进 dist、**后**做收尾清理。
      本宿主禁删 ⇒ 收尾清理必失败 ⇒ 后端 rc=1，**但产物已经在 dist 里了**。
      老的救回逻辑只去 `dist/.tmp-*/` 里捞，捞不到就报"无可救回产物" ——
      于是**把已经成功的构建报成失败**（0.60.0 实测：`antinel-0.60.0.tar.gz`
      3.6MB 已躺在 dist 里，程序却说失败）。
      ⇒ 「先看东西在不在，再决定要不要救」。
    """
    name = ("antinel-%s-py3-none-any.whl" % version if kind == "wheel"
            else "antinel-%s.tar.gz" % version)
    p = os.path.join(dist, name)
    try:
        return os.path.isfile(p) and os.path.getsize(p) > 0
    except OSError:
        return False


def _sha256_file(path):
    """裸字节 sha256（**不做换行归一**）。

    ★ 这里的比对对象是「暂存树里的文件」对「源码树里的同一文件」—— 两者都是
      构建器**二进制复制**的产物，不存在 CRLF 归一问题。故**故意**不用
      `host_shield.file_digest`（那个带版本串归一，用于 manifest 口径）：
      混用两套口径正是本仓第一顽症。此处要的就是「一模一样」。
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


#: 暂存树里**需要**与源码比对的后缀（其余如 `*.dist-info/*` 是构建生成的，跳过）
_STAGED_COMPARE_EXTS = (".py", ".json", ".md", ".txt", ".toml", ".yaml", ".yml")
#: 暂存树里**跳过**的目录特征（构建元数据，不是源码的影子）
_STAGED_SKIP_DIRS = (".dist-info", ".egg-info", "__pycache__")


def _staged_tree_matches_source(tree):
    """暂存树与源码**逐字节**一致吗？返回 `(ok, problems)`。

    ★★ 为什么救回②必须先过这一关（2026-10-28 实测发现的复发路径，本轮新增）：

      `build/lib/` 与 `build/bdist.*/wheel/` 是 setuptools 的**增量**产物 ——
      `build_py` 只按 **mtime** 决定要不要把源码复制过去。0.60.0 把
      `_retire_old_startup_cmd()` 从源码里删了，但暂存树里的旧副本**还在**
      （本轮 `grep` 到 `build/lib/antinel.py:1955` 与
      `build/bdist.win-amd64/wheel/antinel.py:1955` 各一份）。

      如果某次出包时源文件 mtime 不比暂存树里的新（`git checkout` 恢复文件、
      从备份拷回、时钟回拨都会这样），setuptools **不复制** ⇒ 暂存树里仍是
      **退役代码** ⇒ 救回② `wheel pack` 把它**原样打进发布件**。

      这是"活体修好了、发布件没修"最隐蔽的形态：源码 grep 全绿，
      只有解包发布件才看得见。发布件核对判据（D-6 族）**能**抓到，
      但不该让它来兜构建的底 —— 那是两道不同的门。

      ⇒ 救回② 只在「暂存树 == 源码」时才允许；不一致就让路给救回③
        （从**本轮现打的** sdist 重建，必然等于当前源码）。

    ★ 判据用 **sha256** 不用 mtime：mtime 只能说明"复制过"，
      不能说明"复制的是现在这份"。
    """
    if not os.path.isdir(tree):
        return False, ["暂存树不存在：%s" % tree]
    bad, n = [], 0
    for dirpath, dirnames, filenames in os.walk(tree):
        dirnames[:] = [d for d in dirnames
                       if not any(k in d for k in _STAGED_SKIP_DIRS)]
        for fn in filenames:
            if not fn.lower().endswith(_STAGED_COMPARE_EXTS):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, tree)
            src = os.path.join(ROOT, rel)
            n += 1
            if not os.path.isfile(src):
                # 暂存树里有、源码里没有 ⇒ 退役文件残留（只对代码判不合格，
                # 文档类可能由构建生成，记进清单但不算硬伤）
                if fn.lower().endswith(".py"):
                    bad.append("%s（源码里已无此文件 —— 退役残留）" % rel)
                continue
            try:
                if _sha256_file(p) != _sha256_file(src):
                    bad.append("%s（内容与源码不同）" % rel)
            except OSError as e:
                bad.append("%s（读不了：%s）" % (rel, e))
    if n == 0:
        return False, ["暂存树里一个可比对文件都没有：%s" % tree]
    return (not bad), bad


def _wheel_from_sdist(py, dist, version):
    """第三条路：在**系统 %TEMP%** 里从**本版 sdist** 重建 wheel。返回 True/False。

    ★★ 为什么必须有这条路（0.60.0 出包当场撞到，前两条救回同时失效）：
      `python -m build --wheel` 在**仓根**跑有两条**互相独立**的死因 ——
        ① 仓根 `build/` 是无 `__init__.py` 的 namespace 包 ⇒ `-m build` 先
           import 到它 ⇒ `No module named build.__main__`（连后端都没进）；
        ② 本宿主禁删 ⇒ bdist 阶段删不掉中间件 ⇒ `WinError 5`。
      ①+② 一起，让「`wheel pack` 暂存树」这条救回**也**失效 ——
      因为暂存树本身就是半成品（`Multiple .dist-info` / 缺 RECORD）。
      ⇒ 唯一出路：**离开仓根**、到**唯一可删区**（系统 %TEMP%）去建。
      0.57.0 起一直是**手工**跑 `output/_wheel_from_sdist.py` 补这一刀 ——
      那正是本文件注释里骂过的"机制建了一半"：一条命令走不完，就得靠人记得。
      现在把它焊进发布链路（判据 S40 只禁"自己实现检查逻辑"，构建兜底不在此列）。
    """
    sdist = os.path.join(dist, "antinel-%s.tar.gz" % version)
    if not os.path.isfile(sdist):
        print("   [从 sdist 建 wheel] 本版 sdist 不在（%s），这条路走不了"
              % os.path.basename(sdist))
        return False
    import tarfile
    import tempfile
    base = tempfile.mkdtemp(prefix="w0600_")
    print("   [从 sdist 建 wheel] 临时根 = %s" % base)
    try:
        with tarfile.open(sdist, "r:gz") as tf:
            tf.extractall(base)
        roots = [d for d in os.listdir(base)
                 if d.startswith("antinel-") and os.path.isdir(os.path.join(base, d))]
        if len(roots) != 1:
            print("   [从 sdist 建 wheel] 解包后顶层目录不是恰好 1 个：%r" % roots)
            return False
        src = os.path.join(base, roots[0])
        out = os.path.join(base, "wheelhouse")
        env = dict(os.environ)
        env["PYTHONPATH"] = ""
        env["TMPDIR"] = env["TEMP"] = env["TMP"] = base
        # ★ cwd **必须**离开仓根（死因①）；三个 TMP 变量一起指到 base（死因②）。
        rc = subprocess.call([py, "-m", "build", "--wheel", "--no-isolation",
                              "--outdir", out, src],
                             env=env, cwd=base, creationflags=_CNW)
        print("   [从 sdist 建 wheel] 后端 rc=%d" % rc)
        want = "antinel-%s-py3-none-any.whl" % version
        got = os.path.join(out, want)
        if not (os.path.isfile(got) and os.path.getsize(got) > 0):
            print("   [从 sdist 建 wheel] 没有产出 %s" % want)
            return False
        dst = os.path.join(dist, want)
        if os.path.exists(dst):
            dst += ".rebuilt"
        shutil.move(got, dst)
        print("   [从 sdist 建 wheel] 已搬到 %s（%d 字节）"
              % (dst, os.path.getsize(dst)))
        return True
    except (OSError, tarfile.TarError) as e:
        print("   [从 sdist 建 wheel] 失败：%s: %s" % (type(e).__name__, e))
        return False


def build_artifacts(py, dist, version):
    """步骤 2：wheel 与 sdist **分别**出，并带回救。

    ★★ 为什么必须带回救（2026-10-09 两种形态都实测过）：

      宿主"安全删除"守卫在 `python -m build` 的**收尾清理**处拦下它
      （删的文件数 > 阈值 50）⇒ 后端报错、产物没能搬进 dist/。
      但**产物本身已经生成**，只是卡在搬运转运：

      ① sdist 形态：tar 已在 `dist/.tmp-*/antinel-<ver>.tar.gz`，被拦的只是收尾
         ⇒ `mv` 救回即可。
      ② wheel 形态：整棵解包树已在 `build/bdist.win-amd64/wheel/`
         （含 `<ver>.dist-info/`、全部模块），被拦的是删这棵树
         ⇒ 用官方工具 `python -m wheel pack <那棵树> -d dist` 重打包。

    ★ 为什么两条都要写：0.42.0 之前我只写了 ①（sdist），
      结果 wheel 那次**没被救** ⇒ 白跑一轮 30 分钟构建。
      **"机制建了一半"和没建是一样的** —— 它会让人以为已经兑住了。
    """
    os.makedirs(dist, exist_ok=True)
    rescued = []

    # ---- ★★ 0.47.0：出包**之前**先扫掉暂存树里的"上一版 dist-info" ----
    #   为什么必须扫（**第三次复发**，前两次都只治了产物本身）：
    #     M11 双 dist-info → 0.42.0 加了"救回" → 0.47.0 出包时又撞：
    #     `build/bdist.win-amd64/wheel/` 里躺着 **0.46.0 的 dist-info**（上一版遗留），
    #     本版 install 后新增 0.47.0 的 ⇒ 一棵树两个 dist-info ⇒
    #       · setuptools 后端报 `Multiple .dist-info directories found`；
    #       · 下面那道 **wheel 救回**（`wheel pack` 整棵树）**同样**被它卡死
    #         ⇒ 救回形同没建（0.42.0 那句"机制建了一半和没建一样"，本轮亲自应验）。
    #   ★★ 关键细节（本轮踩到才知）：必须**移出暂存树**，不能在**树内改名**。
    #     我第一次就是树内改名成 `*.away-<ts>`，结果 `wheel pack` 把改名后的目录
    #     **一起打进 wheel**，JDG-06 照样判红（"wheel 里有 2 个 .dist-info 目录"）。
    #     ⇒ 判据是按"目录名含 .dist-info"认的，改名骗不过它 —— 这正说明判据有效。
    sweep = _sweep_stale_distinfo(os.path.join(ROOT, "build", "bdist.win-amd64",
                                               "wheel"), version)

    # ---- ★★ 0.60.0：**先 sdist、后 wheel** ----
    #   为什么要调这个顺序（原来 wheel 在前）：wheel 的第三条救回是"从本版 sdist
    #   重建" ⇒ 它**需要 sdist 先存在**。顺序反了，那条路永远没有输入，
    #   在"暂存树也救不回"的宿主上必然断链（0.60.0 实测就是这么断的）。
    #   ★ 这不是"顺手改顺序"，是**依赖关系决定的**：兜底路径依赖的输入必须先产出。

    # ---- sdist ----
    rc_s = _run([py, "-m", "build", "--no-isolation", "--sdist", "--outdir", dist], cwd=ROOT)
    if rc_s != 0:
        got = _artifact_present(dist, version, "sdist")
        if got:
            # ★★ 0.60.0：产物已直接落在 dist（build 是"先写产物、后收尾清理"，
            #   本宿主禁删 ⇒ 收尾必失败 ⇒ rc=1 但东西是好的）。
            print("   [救回 sdist] 后端 rc=%d，但 dist 里已有本版件 —— "
                  "被拦的只是收尾清理，产物本身是好的" % rc_s)
        else:
            # ★★★ 2026-10-15（0.50.4 出包实测）：**救回必须校验版本** —— 只捞本版件。
            #   病（真缺陷，本轮当场撞到）：原循环扫 dist 下**所有** `.tmp-*/`，
            #   把**任何** `.tar.gz` 捞回 dist，**不校验版本号** ⇒ 上一轮残留的
            #   `.tmp-_8b7mue4/antinel-0.50.3.tar.gz`（宿主删除守卫拦了收尾清理，
            #   一直躺在 dist 里）被这轮**捞了回来** ⇒ dist 混入旧版件 ⇒
            #   步骤 3 `verify_release` 判 `[A] dist 布局` 红（"混入旧版件或本版件缺失"）
            #   ⇒ 白跑一轮 22 分钟构建。
            #   ★ 这是本仓 T-09（同一事实两处副本）的又一变体：`_archive_stale_dist`
            #     （build_package 侧）**按版本**归档旧件，而本救回循环**没有版本口径**
            #     ⇒ 一个挪走、一个捞回，两把尺子打架。修法＝让救回也用**版本口径**。
            #   ★ 为什么不是"也捞旧件、让后续判据去红"：那会把"混旧包"这个
            #     D-23/JDG-06 专门要防的最危险一项，变成每次构建的必然产物
            #     （tmp 残留不清 ⇒ 每轮都把旧版捞回来），机制自相矛盾。
            _want = "antinel-%s.tar.gz" % version
            for name in sorted(os.listdir(dist)):
                tmpdir = os.path.join(dist, name)
                if not (name.startswith(".tmp-") and os.path.isdir(tmpdir)):
                    continue
                for f in sorted(os.listdir(tmpdir)):
                    if f != _want:                       # ★ 只认本版件（版本口径）
                        continue
                    dst = os.path.join(dist, f)
                    if not os.path.exists(dst):
                        shutil.move(os.path.join(tmpdir, f), dst)
                        got = True
                        print("   [救回 sdist] %s ← %s/%s（宿主守卫拦了收尾删除，"
                              "tar 本身是好的）" % (f, name, f))
        if not got:
            print("!! sdist 构建失败且无可救回产物（rc=%d）" % rc_s)
            return rc_s
        rescued.append("sdist")
        print("   [提示] sdist 后端报了 rc=%d，但已救回 —— 以 dist/ 实际内容为准" % rc_s)

    # ---- wheel（三条救回，按代价从低到高）----
    rc_w = _run([py, "-m", "build", "--no-isolation", "--wheel", "--outdir", dist], cwd=ROOT)
    if rc_w != 0:
        ok = _artifact_present(dist, version, "wheel")
        if ok:
            print("   [救回 wheel] 后端 rc=%d，但 dist 里已有本版件 —— "
                  "被拦的只是收尾清理" % rc_w)
        if not ok:
            # 救回②：暂存树 `wheel pack`（只在"暂存树是完整的"宿主上有效）
            tree = os.path.join(ROOT, "build", "bdist.win-amd64", "wheel")
            if os.path.isdir(tree):
                # ★★ 0.60.0：**先过内容门**，再决定要不要 pack 这棵树。
                #   暂存树是 setuptools 的增量产物，可能是**上一版**留下的
                #   （含已退役的代码）。pack 一棵旧树 = 把退役代码发出去，
                #   而且症状是"活体全绿、发布件带病"，极难发现。
                #   不一致就让路给救回③（从本轮现打的 sdist 重建）。
                same, why = _staged_tree_matches_source(tree)
                if not same:
                    print("   [救回 wheel] 暂存树与源码**不一致**（%d 处）⇒ "
                          "拒绝 pack 这棵树，改走 sdist 重建" % len(why))
                    for w in why[:6]:
                        print("      · %s" % w)
                    if len(why) > 6:
                        print("      · ……另 %d 处" % (len(why) - 6))
                else:
                    print("   [救回 wheel] 后端 rc=%d，暂存树在：%s（与源码逐字节一致）"
                          " —— 用官方 wheel pack 重打包" % (rc_w, tree))
                    if _run([py, "-m", "wheel", "pack", tree, "-d", dist], cwd=ROOT) == 0:
                        ok = _artifact_present(dist, version, "wheel")
        if not ok:
            # 救回③：离开仓根、到系统 %TEMP% 从本版 sdist 重建（本宿主的唯一出路）
            print("   [救回 wheel] 暂存树这条路走不通 —— 改在系统临时目录从 sdist 重建")
            ok = _wheel_from_sdist(py, dist, version)
        if not ok:
            print("!! wheel 构建失败（rc=%d）且三条救回全不可用" % rc_w)
            return rc_w
        rescued.append("wheel")
        print("   [提示] wheel 后端报了 rc=%d，但已救回 —— 以 dist/ 实际内容为准" % rc_w)

    if rescued:
        print("   本次救回：%s" % "、".join(rescued))
    return 0


def main():
    ap = argparse.ArgumentParser(description="Antinel 发布入口（装配验证 → 出包 → 发布验收）")
    ap.add_argument("--out", default=r"D:\psl\poc", help="产物仓根（build_package --out）")
    ap.add_argument("--py", default=None, help="出包用哪个解释器（默认自动探测 setuptools>=68）")
    ap.add_argument("--skip-install", action="store_true",
                    help="跳过 verify_release 的 D 步（**这是盲区，不是通过**）")
    args = ap.parse_args()

    version = source_version()
    dist = os.path.join(ROOT, "dist")
    print("发布入口：version=%s  out=%s" % (version, args.out))

    _step("1/3", "装配 ＋ 闸门 17 套 ＋ 两次 harness（旧版发布件自动归档）")
    rc = _run([sys.executable, os.path.join(ROOT, "scripts", "build_package.py"),
               "--out", args.out, "--verify"], cwd=ROOT)
    if rc != 0:
        print("\n!! 步骤 1 失败（rc=%d）—— 不进入出包。修好再跑，别带着红灯发布。" % rc)
        return rc

    _step("2/3", "出 wheel ＋ sdist")
    py = _pick_release_py(args.py)
    if not py:
        print("!! 找不到 setuptools>=68 的解释器。本机 C:\\Python311 是 65.5.0 会被拒；"
              "用 --py 指定，或设 ANTINEL_RELEASE_PY。")
        return 2
    print("   出包解释器：%s" % py)
    rc = build_artifacts(py, dist, version)
    if rc != 0:
        return rc

    _step("3/3", "发布验收（布局 / wheel 自洽 / twine / 端到端安装）")
    # ★ 用 step 2 已选定的工具链解释器 `py`，不用 sys.executable：
    #   验收里的 twine / pip 都属于**打包工具链**，只在出包环境里齐备；
    #   用当前解释器（本机 managed 3.13.12 **有 pip、没 twine**）会把 [C] 卡成
    #   `No module named twine`，[A]/[B] 全过也白搭（0.43.1 本轮实测）。
    #   解释器只选一次、两步共用 —— 别让 step 3 再退回一个没工具链的解释器。
    #   （verify_release 自身也带 twine 探测兜底，独立运行同样稳。）
    cmd = [py, os.path.join(ROOT, "scripts", "verify_release.py"),
           "--dist", dist, "--version", version]
    if args.skip_install:
        cmd.append("--skip-install")
    rc = _run(cmd, cwd=ROOT)
    if rc != 0:
        print("\n!! 步骤 3 失败（rc=%d）—— 产物不可发布。" % rc)
        return rc

    # ★★ 0.53.1：发布的**最后一步**是复位研发树。构建器按设计把 manifest
    #   恢复成纯 wheel 口径，而本仓就是研发树 ⇒ 不复位就留下**假失守**
    #   （窗口显示「失守：防护文件被改动」）。见 `_finalize_dev_tree`。
    if _finalize_dev_tree(version) != 0:
        return 1

    print("\n" + "=" * 74)
    print("发布就绪：antinel-%s-py3-none-any.whl ＋ antinel-%s.tar.gz" % (version, version))
    print("=" * 74)
    return 0


#: 研发树 manifest 的**惯例登记版本**（刻意低于代码版本）。
#: ★ 为什么必须有落差：`host_shield.is_dev_build()` 靠「登记版 < 代码版」判定
#:   研发树；落差为 0 时它恒为 False ⇒ 任何自检漂移都会被渲染成
#:   **失守 ＋「这份守门的代码我认不出是不是出厂那份」**（0431 S70 守着）。
_DEV_MANIFEST_VERSION = "0.50.5"


def _finalize_dev_tree(version):
    """发布的**最后一步**：把研发树复位到「自检通过 ＋ 版本有落差」。

    ★★ 为什么必须自动做（0.53.1 实测，创始人 2026-10-19 截图）：
      `build_package.py` 按其设计在跑完后把 `psl/manifest.json` 恢复成
      **纯 wheel 口径**（剥掉 `ci/freeze_zones.json`）并把 version 刷平到本版。
      而本仓就是**研发树**（final == 仓根）⇒ 出包一结束，研发树立刻进入两种坏态：
        ① `self_check()` 红 ⇒ 监理启动自检不过 ⇒ 窗口显示
           「失守：防护文件被改动」—— 这是**假失守**，而且是用户**直接看得见**的；
        ② version 与代码版本落差为 0 ⇒ 0421/0431 S70 与 0516 PKG16-c 结构性红。
      以前靠人记着再跑两条命令（`--adopt-dev` ＋ version 回落），
      **漏一次就把假失守摆到用户眼前**（0.53.1 这一轮漏了两次）。
      ⇒ 把这两步挪进发布的最后一步：走正规入口就不可能留下假失守。

    ★ 位置纪律（S40）：本函数**不自己实现检查逻辑** —— 补登调
      `_tools_034/_resign_manifest.py --adopt-dev`（与手工同一把尺子），
      收口用产品自己的 `host_shield.self_check()`。
      version 回落只改 manifest 的一个字段（没有工具做"只回落登记版本"这件事，
      且必须保留原文件的缩进格式）。
    ★ 失败方向：修不成就**大声说**并返回非零 —— 绝不允许"包发出去了、
      研发树在报假失守"这种状态悄悄留在机器上。
    """
    print("\n" + "-" * 74)
    print("复位研发树（自检通过 ＋ 版本有落差）")
    print("-" * 74)
    tool = os.path.join(ROOT, "_tools_034", "_resign_manifest.py")
    if not os.path.isfile(tool):
        print("  ⚠️  找不到 %s —— 研发树**未复位**。请手工：\n"
              "     1) python _tools_034/_resign_manifest.py --adopt-dev\n"
              "     2) 把 psl/manifest.json 的 version 回落为 %s"
              % (tool, _DEV_MANIFEST_VERSION))
        return 1
    rc = _run([sys.executable, tool, "--adopt-dev"], cwd=ROOT)
    if rc != 0:
        print("!! 补登研发树专属件失败（rc=%d）" % rc)
        return rc

    mp = os.path.join(ROOT, "psl", "manifest.json")
    with open(mp, encoding="utf-8") as f:
        txt = f.read()
    m = re.search(r'"version"\s*:\s*"([^"]*)"', txt)
    if not m:
        print("!! psl/manifest.json 里找不到 version 字段 —— 无法回落，拒绝静默放过")
        return 1
    cur = m.group(1)
    if cur != _DEV_MANIFEST_VERSION:
        old = '"version": "%s"' % cur
        if old not in txt:
            print("!! 定位不到 `%s`（格式变了？）—— 手工回落为 %s"
                  % (old, _DEV_MANIFEST_VERSION))
            return 1
        with open(mp, "w", encoding="utf-8", newline="") as f:
            f.write(txt.replace(old, '"version": "%s"' % _DEV_MANIFEST_VERSION, 1))
        print("  manifest version：%s → %s（研发态落差就位）"
              % (cur, _DEV_MANIFEST_VERSION))
    else:
        print("  manifest version：已是 %s，无需回落" % cur)

    # ---- 用产品自己的自检收口（不另写一套判定）----
    probe = ("import sys, host_shield\n"
             "ok, probs = host_shield.self_check()\n"
             "print('self_check ok=%r' % (ok,))\n"
             "for p in probs[:5]:\n"
             "    print('  -', p)\n"
             "sys.exit(0 if ok else 1)\n")
    rc = _run([sys.executable, "-c", probe], cwd=ROOT)
    if rc != 0:
        print("!! 研发树自检仍不通过（rc=%d）—— 包已出，但监理会显示失守，必须修好" % rc)
        return rc
    print("  ✅ 研发树已复位：自检通过 ＋ 登记版 %s < 代码版 %s"
          % (_DEV_MANIFEST_VERSION, version))
    return 0


if __name__ == "__main__":
    sys.exit(main())
