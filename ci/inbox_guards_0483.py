#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.48.3 判据 —— 「随包清单主体 = wheel 载荷」与命名空间件分发的防复发。

★★ 由来（`ci/j2_pypi_e2e.py` **装后**模拟实测，2026-10-11，证据落 `_uxtest2/`）：

   README 第 16/17/18 行那三条「别信我们，自己验」，在**纯净 wheel 安装**下全部不成立：

     · `python -m tools.antinel_verify`            → `[SUPERSEDED] 1 of 21 covered files are missing`
                                                     （缺 `antinel-namespaces.json`）
     · `python -m tools.antinel_verify --manifest` → `[SUPERSEDED] 15 of 124 covered files are missing`
     · `python -m tools.verify_namespaces`         → `namespaces list unreadable: No such file or directory`

   一个**没被动过**的安装，开口就告诉用户"本包已被篡改/已失效"（README 第 24 行自己定义
   「1＝superseded」）—— 在立信誉的地方喊狼来了。撞的还是本仓已有的铁律：
   **「页面上不许教跑不通的命令」**（0.35.2 就为这条把 `challenge/` 强塞进 wheel）。

   单一根因：**签名清单不随任何分发包**（wheel/sdist 都没有它），却同时是
     ① 随包 judgment 的 21 条 digest 之一、② 随包 manifest 的成员、
     ③ 随包工具 `tools/verify_namespaces.py` 的必需输入（工具发了，它要验的数据没发）。
   外加一层口径病：随包 manifest 的**主体取自暂存包 `pkg`**，而 wheel 是 setuptools 从
   **仓根**按 pyproject 声明构建的 ⇒ 两份主体**双向**错配（多覆盖 15 个 sdist-only 件、
   少覆盖 13 个真随包件；两侧数目恰好都是 124，**只看数量看不出来**）。

   ⇒ 本文件把这些从「一次性修好」变成「每次交付前必跑、会报红、有负控」的机制。

★ 判据（＋ 负控）：每条一个**正判据** ＋ 一个**反向负控**；关键的再加**连带对照**
  与**可观测**（沿用 0440–0482 的「四件套」纪律）。
"""
from __future__ import annotations

import importlib.util
import io
import os
import re
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BP = os.path.join(ROOT, "scripts", "build_package.py")
ANTINEL = os.path.join(ROOT, "antinel.py")
MANIFEST_IN = os.path.join(ROOT, "MANIFEST.in")
VERIFY_RELEASE = os.path.join(ROOT, "scripts", "verify_release.py")

#: 「自己验」三条命令**必须**能读到的随包文件（README 第 16/17/18 行的数据依赖）
TRUST_DEPS = ("psl/manifest.json", "psl/judgment.json", "psl/antinel-namespaces.json")

RESULTS = []


def _read(p):
    return io.open(p, encoding="utf-8", errors="replace").read()


def check(name):
    def deco(fn):
        RESULTS.append((name, fn))
        return fn
    return deco


def _load_bp():
    """动态加载构建器（要借它的 `_wheel_payload` / `_glob_match` / `_declared_*`）。

    ★ 用同一份真源，不在这里重写一份判据 —— 重写就会分家，那正是本缺陷的成因。
    """
    spec = importlib.util.spec_from_file_location("bp_0483", BP)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _src_version():
    m = re.search(r'^VERSION\s*=\s*"([0-9.]+)"', _read(ANTINEL), re.M)
    return m.group(1) if m else None


def _wheel_payload_now():
    bp = _load_bp()
    rules = [ln.strip() for ln in _read(MANIFEST_IN).splitlines() if ln.strip()]
    return bp, set(bp._wheel_payload(Path(ROOT), rules))


# ============================================================ N1 命名空间件落点
def _ns_location_ok(root_has, psl_has):
    if root_has:
        return "仓根仍有 antinel-namespaces.json —— 该位置**不随 wheel/sdist 分发**" \
               "（正是三条「自己验」命令全崩的根因）"
    if not psl_has:
        return "psl/antinel-namespaces.json 不存在 —— 「工具与数据同源」的前提被破坏"
    return True


@check("S1-483 命名空间清单落点：仓根无、psl/ 有")
def s1():
    return _ns_location_ok(
        os.path.exists(os.path.join(ROOT, "antinel-namespaces.json")),
        os.path.exists(os.path.join(ROOT, "psl", "antinel-namespaces.json")))


@check("N-S1-483 负控：放回仓根（psl/ 也在）必须判红")
def n_s1():
    if _ns_location_ok(True, True) is True:
        return "判据失效：仓根有件时仍判绿"
    return True


@check("S1b-483 连带：psl 的 package-data 覆盖 *.json ⇒ 清单真的随 wheel")
def s1b():
    bp = _load_bp()
    _pkgs, pd = bp._declared_from_pyproject()
    if not any(bp._glob_match("antinel-namespaces.json", pat) for pat in pd.get("psl", ())):
        return "pyproject 的 psl package-data 未覆盖 *.json ⇒ 清单不会随 wheel"
    return True


@check("S1c-483 连带：三处读取路径都指向新落点")
def s1c():
    need = 'PKG / "psl" / "antinel-namespaces.json"'
    bad = [p for p in ("scripts/run_harness.py", "tools/verify_namespaces.py",
                       "scripts/verification_tests.py")
           if need not in _read(os.path.join(ROOT, p))]
    if bad:
        return "这些文件仍指向旧落点（装后会 No such file）：%s" % bad
    if 'COVERED = ["psl/antinel-namespaces.json",' not in _read(
            os.path.join(ROOT, "scripts", "run_harness.py")):
        return "run_harness 的 COVERED 首项未改 ⇒ 随包 judgment 仍会覆盖不存在的路径"
    return True


# ============================================================ N2 清单 ⊆ 随包集
def _subset_violation(listed, payload):
    """返回「清单里有、随包集里没有」的项 —— 纯净安装下它们必然报 missing。"""
    return sorted(set(listed) - set(payload))


@check("S2-483 随包清单主体 ⊆ 随包集（无「覆盖了不随包文件」）")
def s2():
    man_p = os.path.join(ROOT, "psl", "manifest.json")
    if not os.path.exists(man_p):
        return "缺 psl/manifest.json"
    import json
    man = json.loads(_read(man_p))
    ver = str(man.get("version"))
    src = _src_version()
    if ver != src:
        # ★ 自举豁免（与构建器同一条判据）：清单由本次打包重生成，此刻必然落后。
        #   跳过必须在日志里**看得见** —— "跳过"不许与"通过"长得一样。
        print("     ↷ 自举豁免：manifest 版本 %s ≠ 源码 %s（本次打包会重生成），本判据跳过"
              % (ver, src))
        return True
    _bp, payload = _wheel_payload_now()
    extra = _subset_violation(man.get("files") or {}, payload)
    if extra:
        return "清单覆盖了 %d 个**不随包**的文件（纯净安装会报 superseded）：%s" % (len(extra), extra[:5])
    return True


@check("N-S2-483 负控：往清单里塞一个 sdist-only 路径必须被判红")
def n_s2():
    _bp, payload = _wheel_payload_now()
    if not _subset_violation(["docs/AUDIT_SCHEMA.md", "README.md"], payload):
        return "判据失效：sdist-only 路径没被检出"
    return True


# ============================================================ N3 自验命令的数据依赖
def _deps_not_shipped(root, deps=TRUST_DEPS):
    """返回「自己验」命令需要、但**没有打包规则覆盖**（或仓里根本不存在）的依赖。

    ★ 判据是「**会被打包规则收走**」，不是「在 manifest 覆盖面里」：
      `psl/manifest.json` 与 `psl/judgment.json` 按设计**不在**清单覆盖面内
      （清单不能覆盖它自己），但它们确实随 wheel 发（`psl` 的 package-data
      `*.json`）。用「清单覆盖面」判会把这两条**误报**成缺件。
    """
    bp = _load_bp()
    _pkgs, pd = bp._declared_from_pyproject()
    out = []
    for dep in deps:
        top, name = dep.split("/", 1)
        if not os.path.exists(os.path.join(root, dep)):
            out.append(dep + "（仓里不存在）")
            continue
        if not any(bp._glob_match(name, pat) for pat in pd.get(top, ())):
            out.append(dep + "（无打包规则覆盖 ⇒ 不随 wheel）")
    return out


@check("S3-483 「自己验」三条命令的数据依赖都被打包规则覆盖（本条无自举豁免）")
def s3():
    bad = _deps_not_shipped(ROOT)
    if bad:
        return "随包集缺「自己验」命令的数据依赖：%s ⇒ 纯净安装下必报 superseded/unreadable" % bad
    return True


@check("N-S3-483 负控：把依赖换成一个 sdist-only 路径必须判红")
def n_s3():
    if not _deps_not_shipped(ROOT, deps=("docs/AUDIT_SCHEMA.md",)):
        return "判据失效：sdist-only 路径没被检出"
    return True


# ============================================================ N4 对账判据有人调用
def _release_registered(src):
    if "def check_manifest_vs_wheel" not in src:
        return "verify_release.py 缺 check_manifest_vs_wheel（对账判据不存在）"
    if '("E", check_manifest_vs_wheel)' not in src:
        return "对账判据未注册进 steps ⇒ **建好了没人调用**（本仓复发③ 的标准形状）"
    return True


@check("S4-483 发布验收的「清单 vs 实测 wheel」对账判据存在且已注册")
def s4():
    return _release_registered(_read(VERIFY_RELEASE))


@check("N-S4-483 负控：抽掉注册行必须判红")
def n_s4():
    src = re.sub(r'\("E",\s*check_manifest_vs_wheel\)\s*,?', "", _read(VERIFY_RELEASE))
    if _release_registered(src) is True:
        return "判据失效：注册行被抽掉后仍判绿"
    return True


# ============================================================ N5 P-B1 探针的目标
VERIF = os.path.join(ROOT, "scripts", "verification_tests.py")
JUDGMENT = os.path.join(ROOT, "psl", "judgment.json")


def _p_b1_target_ok(src, manifest_files, covered):
    """P-B1 的篡改目标必须是「**在清单里、且不在 digest 集里**」的真随包件。

    ★★ 为什么必须有这条（0.48.3 实测，代价是一次 50 分钟的失败出包）：
       P-B1 的原目标 `README.md` 是仓根/sdist-only 件 —— 清单主体纠正为 wheel
       载荷后它**不再是清单成员**，于是断言**恒定假红**（`--manifest` 当然检不出
       一个不在清单里的文件）。这条把「探针打哪儿」从「靠记得」变成「交付前必跑、
       会报红、有负控」。判据**不重算**清单与 digest 集，只读产品自己写的那两份
       （随包清单 / 判定账本），避免"第二套口径"分家。
    """
    m = re.search(r'gap\s*=\s*PKG\s*/\s*"([^"]+)"(?:\s*/\s*"([^"]+)")?', src)
    if not m:
        return "verification_tests.py 里找不到 P-B1 的篡改目标锚点（gap = PKG / ...）"
    rel = "/".join(x for x in (m.group(1), m.group(2)) if x)
    if rel not in manifest_files:
        return ("P-B1 篡改目标 %s **不在清单里** ⇒ 它不是随包件，`--manifest` 必然检不出，"
                "断言恒定假红（0.48.3 之前的旧病形状）" % rel)
    if rel in covered:
        return ("P-B1 篡改目标 %s **在 digest 集里** ⇒ 裸 --json 就会检出，"
                "演示不出 --manifest 的增量（P-B1 的原意落空）" % rel)
    return True


def _load_sets():
    import json as _j
    man = _j.loads(_read(os.path.join(ROOT, "psl", "manifest.json"))).get("files") or {}
    try:
        cov = _j.loads(_read(JUDGMENT)).get("digests") or {}
    except Exception:                                            # noqa: BLE001
        cov = {}                     # 账本不可读 ⇒ 不当成"目标合法"，但也不假红
    return set(man), set(cov)


@check("S5 P-B1 探针目标 =「在清单、不在 digest 集」的真随包件")
def s5():
    man, cov = _load_sets()
    return _p_b1_target_ok(_read(VERIF), man, cov)


@check("N-S5 负控：目标换成 sdist-only 件 或 换成 digest 集内的件，都必须判红")
def n_s5():
    src = _read(VERIF)
    man, cov = _load_sets()
    _ANCHOR = 'gap = PKG / "hooks" / "_host_detect.py"'
    if _ANCHOR not in src:
        return "负控失效：P-B1 锚点已漂移（负控本身打在空处）"
    a = src.replace(_ANCHOR, 'gap = PKG / "docs" / "AUDIT_SCHEMA.md"')       # 不随包
    if _p_b1_target_ok(a, man, cov) is True:
        return "判据失效：sdist-only 目标仍判绿"
    b = src.replace(_ANCHOR, 'gap = PKG / "psl" / "antinel-namespaces.json"')  # 在 digest 集
    if _p_b1_target_ok(b, man, cov) is True:
        return "判据失效：digest 集内的目标仍判绿"
    return True


# --------------------------------------------------------------- 运行 ----
def main():
    print("=" * 78)
    print("inbox_guards_0483 —— 随包清单口径 ＋ 命名空间件分发 防复发（每条带负控）")
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
