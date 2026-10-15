# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""升版工具 —— 把**九处手工承载件**的版本号一次改到位（`psl/manifest.json` 不动）。

★★★ 为什么必须有这个工具（创始人 2026-10-14「这是开发态，如果缺乏机制，也请修到位」）：
  0.43.1 把根因修在 `ci/version_check.py`（manifest 是构建产物，只许落后、不许超前）
  —— 于是**研发态判据的成立条件变成了**「代码版本 ＞ 登记版本」，也就是
  「**开工时把 VERSION 升上去**」。可这条纪律**只写在注释里**，没有任何东西
  保证它被执行，于是本轮实测：`antinel.py VERSION = 0.48.4` 而
  `psl/manifest.json version = 0.48.4` ⇒ **落差 = 0** ⇒
  `is_dev_build()` 恒 False ⇒ 开发树上任何一次自检漂移都被渲染成
  **失守 ＋「这份守门的代码我认不出是不是出厂那份」**（旧病复发）。

  ⇒ 机制的一半是**守门的判据**（`ci/inbox_guards_0431.py` 的 S70：研发树上
     落差必须存在，否则判红）；另一半就是**本工具**：判据红了要有**一条命令
     的出路**（本仓铁律「红而无出路 ⇒ 红灯没人看」＝ T-04）。

★★ 单一真源（本仓纪律：判据/工具不许二次实现）
  承载件清单**只有一份** —— `ci/version_check.py` 的 `SPOTS`。
  本工具**import 它**，不另抄一份正则；否则两处迟早分叉，而分叉的后果是
  「升版工具改了 9 处、检查器只看 7 处」这种最坏的形状。

用法：
    python ci/bump_version.py              # 预览：只打印将要改的地方
    python ci/bump_version.py --apply      # 写入
    python ci/bump_version.py 0.50.3 --apply   # 指定目标版本

★ 不碰 `psl/manifest.json`：它的 `version` 是**构建产物**（打包时写入），
  「落后于代码」正是研发态判据赖以成立的那个落差。升它 = 亲手把落差刷平。
"""
from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import version_check as VC                                       # noqa: E402


def _code_version():
    """当前代码版本真源：`antinel.py` 的 `VERSION`（与 `version_check` 同法抽取）。"""
    p = os.path.join(ROOT, "antinel.py")
    with open(p, encoding="utf-8", errors="replace") as f:
        m = re.search(r'^VERSION\s*=\s*"([^"]+)"', f.read(), re.M)
    return m.group(1) if m else None


def _next_patch(v):
    """`0.50.2` → `0.50.3`（兜底：给不出就返回 None，让调用方要求显式指定）。"""
    try:
        a, b, c = (int(x) for x in str(v).split("."))
    except Exception:                                            # noqa: BLE001
        return None
    return "%d.%d.%d" % (a, b, c + 1)


def _spot_path(label):
    """`"docs/AUDIT_SCHEMA.md  标题"` → 真实文件路径（含源仓布局回退）。"""
    rel = label.split()[0]
    p = os.path.join(ROOT, rel.replace("/", os.sep))
    if not os.path.isfile(p) and rel.startswith("docs/"):
        p = os.path.join(ROOT, rel.split("/", 1)[1].replace("/", os.sep))
    return p, rel


def plan(target):
    """返回 `[(label, path, old, new_or_None, note)]`（不写盘）。"""
    rows = []
    for label, pat, grp in VC.SPOTS:
        path, rel = _spot_path(label)
        if not os.path.isfile(path):
            rows.append((label, path, None, None, "文件不存在"))
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            txt = f.read()
        m = re.search(pat, txt, re.M)
        if not m:
            rows.append((label, path, None, None, "未抽到（正则不匹配）"))
            continue
        old = m.group(grp)
        rows.append((label, path, old, target, ""))
    return rows


def apply(rows):
    """按 plan 写回。返回 (改了 N 处, 已是目标值的处数, 失败说明 list)。"""
    changed = already = 0
    fails = []
    for label, path, old, new, note in rows:
        if note:
            fails.append("%s：%s" % (label, note))
            continue
        if old == new:
            already += 1
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            txt = f.read()
        for lab2, pat, grp in VC.SPOTS:
            if lab2 != label:
                continue
            # ★ 只换**命中那一次**里的版本子串，不动同一文件里别的版本字面量
            #   （例：`hooks/pre_tool_use.py` 里还有历史注释）。
            out, n = re.subn(pat, lambda mm: mm.group(0).replace(
                mm.group(grp), new), txt, count=1, flags=re.M)
            if n != 1:
                fails.append("%s：正则命中 %d 次（应为 1）" % (label, n))
                break
            # ★ 逐字保留原换行风格：读进来什么样，写回去什么样。
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(out)
            changed += 1
            break
    return changed, already, fails


def main():
    ap = argparse.ArgumentParser(description="把九处版本承载件改到目标版本（不动 manifest）")
    ap.add_argument("version", nargs="?",
                    help="目标版本；不给则取 代码版本 +1 patch")
    ap.add_argument("--apply", action="store_true", help="写入（不给则只预览）")
    a = ap.parse_args()

    cur = _code_version()
    target = a.version or _next_patch(cur)
    if not target:
        print("★ 给不出目标版本（当前 %r）—— 请显式指定，例：python ci/bump_version.py 0.50.3" % cur)
        return 2

    print("=" * 78)
    print("升版工具 —— %d 处手工承载件 → %s（psl/manifest.json **不动**，落差正是研发态的依据）"
          % (len(VC.SPOTS), target))
    print("包路径：%s" % ROOT)
    print("=" * 78)
    rows = plan(target)
    for label, _p, old, new, note in rows:
        tag = ("%s → %s" % (old, new)) if old and old != new else (
            "%s（已是目标值）" % old if old else "★未抽到")
        print("  %-46s %s %s" % (label, tag, note))

    if not a.apply:
        print("\n（预览，未写盘。加 --apply 写入）")
        return 0

    changed, already, fails = apply(rows)
    print("\n已写入 %d 处；已是目标值 %d 处。" % (changed, already))
    if fails:
        print("★ 失败：")
        for f in fails:
            print("   - %s" % f)
        return 1
    print("下一步：跑 `python ci/version_check.py` 确认九处一致；")
    print("        `psl/manifest.json` 仍停在旧版本 ⇒ `is_dev_build()` 判研发态。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
