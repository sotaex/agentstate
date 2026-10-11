#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.48.2 判据 —— **三条 P0 的防复发**（用户旅程模拟逼出来的呈现/可达性修复）。

★★ 由来（ci/j2_pypi_e2e.py 实测，2026-10-11，证据落 _uxtest2/）：

    ① 顶层 `-h/--help` 无出口：antinel.py 顶层 `argparse(add_help=False)` 却忘了补
       help 出口 ⇒ 用户第一直觉命令 `antinel -h` / `--help` 报 `unrecognized arguments`。
    ② 随包脚本命令安装后不可达：README/SKILL/NOTICE 里写成 `python scripts/x.py` 形，
       而这些脚本随包落在 `site-packages`（不在 CWD）⇒ 逐条实测 `reachable:false`。
    ③ A6 收入边界声明对 wheel 用户不可达：docs/ 不进 wheel，指针却未说清。

    ⇒ 本文件把这三条从「一次性修好」变成「每次交付前必跑、会报红、有负控」的机制。
       铁律：**页面上不许教跑不通的命令**（撞了就是坏体验，不管产品内部多正确）。

★ 判据（＋ 负控）：每条一个**正判据** ＋ 一个**反向负控**；关键的再加**连带对照**
  与**可观测**（沿用 0440–0481 的「四件套」纪律）。
"""
from __future__ import annotations

import io
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANTINEL = os.path.join(ROOT, "antinel.py")
BP = os.path.join(ROOT, "scripts", "build_package.py")
README = os.path.join(ROOT, "README.md")
SKILL = os.path.join(ROOT, "SKILL.md")
NOTICE = os.path.join(ROOT, "NOTICE")

RESULTS = []

#: 「相对项目根」的旧命令形态：`python scripts/x.py` / `python tools/y` （装完后不可达）
_BARE_RE = re.compile(r"python\s+(?:scripts|tools)[./][A-Za-z_][\w.]*")
#: 新形态：`python -m scripts.x` / `python -m tools.y`
_MFORM_RE = re.compile(r"python\s+-m\s+((?:scripts|tools)\.[A-Za-z_][\w.]*)")
#: 顶层 -h/--help 出口的注册（跨行）
_HELP_ARG_RE = re.compile(r'add_argument\(\s*"-h"\s*,\s*"--help"')


def _read(p):
    return io.open(p, encoding="utf-8", errors="replace").read()


def check(name):
    def deco(fn):
        RESULTS.append((name, fn))
        return fn
    return deco


# ============================================================ P0-1 顶层帮助出口
def _top_help_ok(src):
    """antinel.py 顶层必须：add_help=False ＋ 注册 -h/--help ＋ 接入分派。"""
    if "add_help=False" not in src:
        return "顶层未声明 add_help=False（本判据前提已变，请复核）"
    if not _HELP_ARG_RE.search(src):
        return "顶层缺 -h/--help 出口 ⇒ 用户第一直觉命令会报错"
    if "show_help" not in src:
        return "未把 -h/--help 接入分派（缺 show_help 路由）"
    return True


@check("S1 顶层 -h/--help 出口存在且接入分派（结构）")
def s1():
    return _top_help_ok(_read(ANTINEL))


@check("N-S1 负控：删掉 -h/--help 注册后必须红")
def n_s1():
    src = _read(ANTINEL)
    broken = _HELP_ARG_RE.sub('add_argument("--nope"', src)
    if broken == src:
        return "夹具无效：正则没匹配到 -h/--help 注册"
    if _top_help_ok(broken) is True:
        return "判据失效：摘掉 -h/--help 出口后仍判绿"
    return True


def _run_antinel(*args):
    """跑真入口，返回 (rc, 合并输出)。"""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    r = subprocess.run([sys.executable, ANTINEL] + list(args), cwd=ROOT,
                       capture_output=True, timeout=90, env=env)
    out = (r.stdout or b"").decode("utf-8", "replace")
    err = (r.stderr or b"").decode("utf-8", "replace")
    return r.returncode, (out + err)


@check("S1b 行为：-h / --help / help 三路皆 rc=0 且 -h 与 help 逐字一致")
def s1b():
    rc_h, o_h = _run_antinel("-h")
    rc_hl, o_hl = _run_antinel("--help")
    rc_help, o_help = _run_antinel("help")
    if not (rc_h == rc_hl == rc_help == 0):
        return "退出码不为 0：-h=%d --help=%d help=%d" % (rc_h, rc_hl, rc_help)
    if o_h != o_help:
        return "-h 输出与 help 不一致（用户看到两条不同的帮助）"
    return True


@check("S1c 行为：-V 正常且版本号与 antinel.py VERSION 一致")
def s1c():
    m = re.search(r'VERSION\s*=\s*"([0-9.]+)"', _read(ANTINEL))
    ver = m.group(1) if m else None
    rc, out = _run_antinel("-V")
    if rc != 0:
        return "antinel -V rc=%d" % rc
    if not ver or ver not in out:
        return "antinel -V 未报出版本 %s（得到 %r）" % (ver, out.strip()[:60])
    return True


@check("S1o 可观测：帮助正文含可跑的命令清单（非空壳）")
def s1o():
    _rc, out = _run_antinel("help")
    if len(out) < 200:
        return "帮助正文过短（%d 字符），疑似空壳" % len(out)
    if "antinel" not in out:
        return "帮助正文未出现 `antinel` 命令字样"
    return True


# ============================================================ P0-2 命令形态
def _bare_in(text):
    return _BARE_RE.findall(text)


@check("S2 构建器模板里 0 处旧命令形态（python scripts/x.py），且有 -m 形态")
def s2():
    src = _read(BP)
    bare = _bare_in(src)
    if bare:
        return "模板仍含 %d 处旧形态（装完不可达）：%s" % (len(bare), bare[:5])
    if not _MFORM_RE.search(src):
        return "模板未出现任何 `python -m` 形态（修法没落地）"
    return True


@check("N-S2 负控：含 `python scripts.install` 的串必须被判红")
def n_s2():
    probe = "运行 python scripts.install --check 看看"
    if not _bare_in(probe):
        return "判据失效：旧形态没被检出"
    return True


@check("S2b 连带：模板引用的全部 -m 目标模块真实存在")
def s2b():
    src = _read(BP)
    mods = sorted(set(_MFORM_RE.findall(src)))
    if not mods:
        return "模板没有 -m 目标可校验"
    missing = [m for m in mods if not os.path.exists(os.path.join(ROOT, m.replace(".", "/") + ".py"))]
    if missing:
        return "指向了不存在的模块：%s" % missing
    return True


@check("S2o 可观测：模板含「为什么写 python -m」说明段")
def s2o():
    if "为什么写 `python -m`" not in _read(BP):
        return "模板缺「为什么写 python -m」说明（用户会困惑）"
    return True


# ============================================================ P0-3 A6 指针
def _a6_pointer_ok(text):
    """A6 指针必须：点到文件 ＋ 明说随 sdist / 不随 wheel。"""
    if "A6收入边界声明.md" not in text:
        return "未出现 A6 声明文件指针"
    if ("不随 wheel" not in text) and ("随 sdist" not in text):
        return "指针未说明随 sdist / 不随 wheel（wheel 用户会找不到）"
    return True


@check("S3 模板 NOTICE/README 的 A6 指针明说「随 sdist / 不随 wheel」")
def s3():
    src = _read(BP)
    # NOTICE_MD 与 README_MD 两处都要有诚实指针
    if src.count("不随 wheel") < 2:
        return "模板里「不随 wheel」出现 %d 次（NOTICE 与 README 各应 ≥1）" % src.count("不随 wheel")
    return _a6_pointer_ok(src)


@check("N-S3 负控：去掉「不随 wheel / 随 sdist」限定必须红")
def n_s3():
    probe = "收入边界声明见 docs/A6收入边界声明.md：不收通过费。"
    if _a6_pointer_ok(probe) is True:
        return "判据失效：裸指针（未限定 sdist/wheel）仍判绿"
    return True


@check("S3b 连带：docs/A6收入边界声明.md 在源码仓真实存在（指针目标为真）")
def s3b():
    if not os.path.exists(os.path.join(ROOT, "docs", "A6收入边界声明.md")):
        return "源码仓缺 docs/A6收入边界声明.md（指针指向不存在的文件）"
    return True


# ============================================================ 产物一致（JDG-05）
@check("S4 随包 README.md（REPO-OWNED）无旧命令形态")
def s4():
    # ★ 只判 README.md：它是 **REPO-OWNED**（构建器不写，见 build_package.py:2558），
    #   闸门时刻一定是最新态。SKILL.md / NOTICE 是**构建产物**，且 SKILL.md 的自证卡
    #   依赖 harness 之后的记录 —— 闸门跑在装配**之前**，此刻它们必然陈旧，
    #   故不在本判据里断言（由 build 的装配步重生成；shipped NOTICE 由模拟轨核）。
    if not os.path.exists(README):
        return "缺 README.md"
    hits = _bare_in(_read(README))
    if hits:
        return "README.md 仍含旧形态（装完不可达）：%s" % hits[:4]
    return True


@check("N-S4 负控：喂一条旧形态必须被 S4 的检测器判红")
def n_s4():
    if not _bare_in("python scripts/run_harness.py"):
        return "判据失效：旧形态没被检出"
    return True


# --------------------------------------------------------------- 运行 ----
def main():
    print("=" * 78)
    print("inbox_guards_0482 —— 三条 P0 防复发（每条带负控）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                print("  ✅ %-60s" % name)
                ok += 1
            else:
                print("  ❌ %-60s %s" % (name, why or "返回值不是 True"))
                fail += 1
        except AssertionError as e:
            print("  ❌ %-60s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-60s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
