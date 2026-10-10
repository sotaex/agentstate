#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布验收 —— `python -m build` **之后**的那道机械检查（0.42.0 新增）。

★★ 为什么必须有这个脚本（2026-10-09 两件事逼出来的）：

  ① **M11：双 dist-info 的坏 wheel**。0.41.0 出包时复用了陈旧的 `build/` 暂存树，
     wheel 里**同时**装着 `antinel-0.40.0.dist-info` 与 `antinel-0.41.0.dist-info`。
     `twine check` **两件都放行**（它只看元数据可读性，不看有几个 dist-info）——
     真正抓住它的是下一轮闸门的 `JDG-06`。⇒ 缺的是"打完包立刻验"这一步。
  ② **e2e 安装验证是手工的**。0.41.0 那轮我手工 `pip install --target` 再 import
     才敢说"装得上"。这一步没有任何脚本保证 ⇒ 下次大概率被省略。

  ⇒ 本脚本把三件事固化为一条命令（**全部机械判定，不靠人眼看**）：
     A. dist/ 里**正好**两件、且都是本版（旧版件不许混入）；
     B. wheel **单一** dist-info 且名字对、RECORD 行数 == 成员数、RECORD 里
        每条路径都真实存在（防"RECORD 与内容不符"）；
     C. `twine check` 两件全过；
     D. **真装一次**：`pip install --no-deps --no-index --target <临时目录>`，
        然后从**安装态** import `antinel` / `host_shield`，跑 `--version`，
        并确认 `host_shield.process_elevation()` 可调用（0.41.0 起它是一等公民）。

  ★ 位置纪律：它只**读** dist/ 与一个临时目录，**不写产品文件、不写仓**。
    临时目录用 `tempfile.mkdtemp()`，退出时不删（留证据），路径打印出来。

  用法：
      python scripts/verify_release.py --dist dist --version 0.42.0
      python scripts/verify_release.py --dist dist --version 0.42.0 --skip-install
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _fail(msg):
    print("  ❌ %s" % msg)
    return False


def _py_with(module):
    """找一个能 `import <module>` 的解释器（找不到就退回 sys.executable）。

    ★★ 为什么要探测，而不是直接用 sys.executable（2026-10-10 修，本班踩到的）：

      [C] `twine check` 原先写死 `sys.executable -m twine`。但 twine 属于
      **打包工具链**，只装在出包环境里（本机 `~/.workbuddy/binaries/python/
      envs/default`，setuptools 84 + twine 7.0.0）；而本脚本被
      `scripts/release.py` 用**当前解释器**拉起 —— 实测 managed 3.13.12
      **有 pip、没 twine** ⇒ [C] 直接 `No module named twine` 报红、
      [A]/[B] 全过也白搭（0.43.1 这轮发布验收卡死在这里）。

      `release.py` 的 step 2 早就为同一类原因探测过"带 setuptools>=68 的解释器"
      （`_pick_release_py`）—— **同一种假设（工具链在 sys.executable 里）漏在了 step 3**，
      正是"改了一处漏一处"。这里把假设**去掉**：谁有 twine 就用谁，别再假设。

    候选顺序与 `release.py::_pick_release_py` 对齐（env 优先 → 托管环境惯例 →
    sys.executable 兜底）；一个都没有时退回 sys.executable，让 [C] 照常报红
    （报错信息不变，不吞掉失败）。
    """
    cands = []
    for var in ("ANTINEL_RELEASE_PY", "ANTINEL_PY"):
        if os.environ.get(var):
            cands.append(os.environ[var])
    cands.append(os.path.join(os.path.expanduser("~"), ".workbuddy", "binaries",
                              "python", "envs", "default", "Scripts", "python.exe"))
    cands.append(sys.executable)
    for py in cands:
        if not py or not os.path.isfile(py):
            continue
        probe = subprocess.run([py, "-c", "import %s" % module],
                               capture_output=True)
        if probe.returncode == 0:
            return py
    return sys.executable


def check_dist_layout(dist, version):
    """A：dist 里正好两件本版发布件。"""
    print("[A] dist 布局（正好两件、都是本版）")
    if not os.path.isdir(dist):
        return _fail("dist 目录不存在：%s" % dist)
    names = sorted(n for n in os.listdir(dist) if os.path.isfile(os.path.join(dist, n)))
    want = ["antinel-%s-py3-none-any.whl" % version, "antinel-%s.tar.gz" % version]
    if names != want:
        return _fail("dist 内容 = %r（应正好是 %r）—— 混入旧版件或本版件缺失" % (names, want))
    print("  ✅ %s" % " ＋ ".join(names))
    return True


def _sdist_stale_members(names, version):
    """sdist 成员里**不属于本版目录**的顶层项（结构判据，返回带例子的清单）。

    ★★ 为什么不能用子串（0.42.1 修，第一版的错）：

      第一版写成子串三段式：
          ("antinel-0." in m and "/%s/" % version not in m
           and not m.startswith("antinel-%s/" % version))
      —— tar 的**顶层目录项本身**（`antinel-0.42.0`，**无尾斜杠**）三条全中：
      含 "antinel-0." ✓、不含 "/0.42.0/" ✓、不以 "antinel-0.42.0/" 开头 ✓
      ⇒ 一个 159 成员全干净的 sdist 被误判"混着非本版目录成员"（**假红**，
      本次实测复现：verify_release 在 [B] 步中止，[C]/[D] 都没跑到）。

      结构判据（顶层路径分量必须**恰为** `antinel-<version>`）对目录项与文件项
      一视同仁；旧版成员（`antinel-0.41.0/...`）照样抓得到 —— 检出能力不降。
    """
    want = "antinel-%s" % version
    bad = {}
    for m in names:
        top = m.split("/")[0]
        if top != want:
            bad.setdefault(top, m)
    return ["%s（例：%s）" % (k, v) for k, v in sorted(bad.items())]


def check_wheel(dist, version):
    """B：单一 dist-info ＋ RECORD 自洽。"""
    print("[B] wheel 自洽（单一 dist-info ／ RECORD 对得上）")
    whl = os.path.join(dist, "antinel-%s-py3-none-any.whl" % version)
    z = zipfile.ZipFile(whl)
    members = z.namelist()
    di = sorted(set(n.split("/")[0] for n in members if ".dist-info/" in n))
    if di != ["antinel-%s.dist-info" % version]:
        return _fail("dist-info 目录 = %r（应只有 antinel-%s.dist-info）—— "
                     "陈旧 build/ 暂存树会在这里露出第二个" % (di, version))
    rec = [n for n in members if n.endswith(".dist-info/RECORD")]
    if len(rec) != 1:
        return _fail("RECORD 文件数 = %d（应 1）" % len(rec))
    lines = [l for l in z.read(rec[0]).decode("utf-8").splitlines() if l.strip()]
    listed = [l.split(",")[0] for l in lines]
    if len(listed) != len(members):
        return _fail("RECORD 行数 %d != 成员数 %d" % (len(listed), len(members)))
    missing = [p for p in listed if p and p not in members]
    if missing:
        return _fail("RECORD 里这些路径不在 wheel 内：%r" % missing[:5])
    # sdist 侧也看一眼：不许带旧版号的成员（结构判据，见 _sdist_stale_members 的 docstring）
    with tarfile.open(os.path.join(dist, "antinel-%s.tar.gz" % version)) as t:
        smembers = t.getnames()
    stale = _sdist_stale_members(smembers, version)
    if stale:
        return _fail("sdist 里混着非本版目录成员：%r" % stale[:5])
    print("  ✅ 单一 dist-info=%s ｜ RECORD %d 行 == 成员 %d ｜ sdist 成员 %d 全在本版目录下"
          % (di[0], len(listed), len(members), len(smembers)))
    return True


def check_twine(dist, version):
    """C：twine check 两件。"""
    print("[C] twine check")
    py = _py_with("twine")
    if py != sys.executable:
        print("   twine 解释器：%s（当前解释器无 twine，已自动探测）" % py)
    files = [os.path.join(dist, "antinel-%s-py3-none-any.whl" % version),
             os.path.join(dist, "antinel-%s.tar.gz" % version)]
    r = subprocess.run([py, "-m", "twine", "check"] + files,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0 or "PASSED" not in out:
        return _fail("twine check 未全过（rc=%d）：%s" % (r.returncode, out.strip()[:300]))
    n_pass = out.count("PASSED")
    if n_pass < 2:
        return _fail("twine 只报了 %d 个 PASSED（应 2）" % n_pass)
    print("  ✅ 两件均 PASSED")
    return True


# ★★ D 步的安装态探针（0.42.1 重写，第一版有两个坑）：
#
#   坑①（假红）：`antinel.main(['--version'])` 打出版本后走 **SystemExit(0)**
#     （标准 CLI 行为）—— 第一版没接，进程在 `process_elevation()` 之前就退了，
#     "E2E-OK" 永远打不出来 ⇒ 安装完全成功也被判失败。
#     （文档里 0.41.0 那次"通过"是**手工探针**；脚本化 D 步其实一次都没跑完过 ——
#       先被 [B] 的子串假红中止，[B] 修好才轮到它露馅。**零覆盖的路径必然是坏的**。）
#   坑②（漏检）：第一版不核对**打印出来的版本号**——装错版本的 wheel 也能亮绿灯。
#
# ⇒ 探针抽成模块级常量（可被 ci/guard_release_entry.py 的 S49 单测），
#   自含三件事：接住 SystemExit(0)／核对 VERSION／验提权探测是一等公民。
_E2E_PROBE = (
    "import sys\n"
    "sys.path.insert(0, {target!r})\n"
    "import antinel, host_shield\n"
    "try:\n"
    "    antinel.main(['--version'])\n"
    "except SystemExit as e:\n"
    "    assert e.code in (0, None), e.code\n"
    "assert antinel.VERSION == {version!r}, antinel.VERSION\n"
    "el = host_shield.process_elevation()\n"
    "assert isinstance(el, tuple) and len(el) == 2, el\n"
    "print('E2E-OK', antinel.VERSION, el[0])\n"
)


def check_install(dist, version):
    """D：真装一次，并从安装态导入。"""
    print("[D] 端到端安装（pip install --target → 安装态 import）")
    target = tempfile.mkdtemp(prefix="antinel_verify_release_")
    whl = os.path.join(dist, "antinel-%s-py3-none-any.whl" % version)
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps",
                        "--no-index", "--target", target, whl],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        return _fail("pip install 失败：%s" % ((r.stderr or "")[-300:]))
    probe = _E2E_PROBE.format(target=target, version=version)
    r2 = subprocess.run([sys.executable, "-c", probe],
                        capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r2.returncode != 0 or "E2E-OK" not in (r2.stdout or ""):
        return _fail("安装态导入/运行失败：%s%s" % ((r2.stdout or "")[-200:], (r2.stderr or "")[-300:]))
    line = [l for l in (r2.stdout or "").splitlines() if l.startswith("E2E-OK")]
    print("  ✅ %s（安装目录：%s）" % (line[0] if line else "E2E-OK", target))
    return True


def main():
    ap = argparse.ArgumentParser(description="发布验收：dist 布局 / wheel 自洽 / twine / 真装一次")
    ap.add_argument("--dist", default=os.path.join(ROOT, "dist"))
    ap.add_argument("--version", required=True)
    ap.add_argument("--skip-install", action="store_true",
                    help="跳过 D 步（离线或无 pip 环境时用；跳过必须在日志里可见）")
    args = ap.parse_args()
    print("=" * 74)
    print("发布验收 —— dist=%s  version=%s" % (args.dist, args.version))
    print("=" * 74)
    steps = [("A", check_dist_layout), ("B", check_wheel), ("C", check_twine)]
    if not args.skip_install:
        steps.append(("D", check_install))
    else:
        print("[D] 已按 --skip-install 跳过（**这是盲区，不是通过**）")
    ok = True
    for _tag, fn in steps:
        if not fn(args.dist, args.version):
            ok = False
            break
    print("-" * 74)
    print("  发布验收：%s" % ("全部通过" if ok else "未通过（已中止）"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
