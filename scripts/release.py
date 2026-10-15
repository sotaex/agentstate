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
import os
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
    return subprocess.call(cmd, **kw)


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
            capture_output=True)
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

    # ---- wheel ----
    rc_w = _run([py, "-m", "build", "--no-isolation", "--wheel", "--outdir", dist], cwd=ROOT)
    if rc_w != 0:
        tree = os.path.join(ROOT, "build", "bdist.win-amd64", "wheel")
        if os.path.isdir(tree):
            print("   [救回 wheel] 后端 rc=%d，但暂存树在：%s —— 用官方 wheel pack 重打包"
                  % (rc_w, tree))
            if _run([py, "-m", "wheel", "pack", tree, "-d", dist], cwd=ROOT) == 0:
                rescued.append("wheel")
        if "wheel" not in rescued:
            print("!! wheel 构建失败（rc=%d）且无可救回产物" % rc_w)
            return rc_w
        print("   [提示] wheel 后端报了 rc=%d，但已救回 —— 以 dist/ 实际内容为准" % rc_w)

    # ---- sdist ----
    rc_s = _run([py, "-m", "build", "--no-isolation", "--sdist", "--outdir", dist], cwd=ROOT)
    if rc_s != 0:
        got = False
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
                    print("   [救回 sdist] %s ← %s/%s（宿主守卫拦了收尾删除，tar 本身是好的）"
                          % (f, name, f))
        if got:
            rescued.append("sdist")
            print("   [提示] sdist 后端报了 rc=%d，但已救回 —— 以 dist/ 实际内容为准" % rc_s)
        else:
            print("!! sdist 构建失败且无可救回产物（rc=%d）" % rc_s)
            return rc_s

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

    print("\n" + "=" * 74)
    print("发布就绪：antinel-%s-py3-none-any.whl ＋ antinel-%s.tar.gz" % (version, version))
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
