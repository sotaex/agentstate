# -*- coding: utf-8 -*-
"""版本号一致性守卫 —— 十处版本承载件必须逐字相同。

★★★ 为什么需要它（MEMORY 里点名的「无守卫」）
  「**发布前必手扫版本号**（pyproject / VERSION / server.json / antinel_mcp /
    AUDIT_SCHEMA 标题）—— **无守卫**。」
  手扫 = 靠人记得 = 迟早漏。实测落后程度：
      _ANTINEL_VERSION      = 0.32.2  （落后 2 版，且**进审计链**）
      build_package.VERSION = 0.29.0  （落后 4 版）
  两者都不是"注释里的历史标注"，是**活的声明**。

★★ 两个真源必须一致（这条本身也要能红）
  产品侧真源 = `tools/antinel_verify.py` 的 `_VERSION_HARD`（INV-3 不变量，8 处）
  本文件清单是它的**超集**（多 `hooks/pre_tool_use.py`、`scripts/build_package.py`、
   `SKILL.md`）。**清单分叉过一次**：初版只列 7 处，漏了 `rules/default.json`
  与 `docs/AUDIT_SCHEMA.md`；是 `antinel_verify.py --invariants` 的 INV-3 抓出来的。
  ⇒ 现在加判据 4：**本清单必须是 INV-3 清单的超集**，否则本检查器自己就是假守卫。

★ 判据设计（四条，都要能红）
  1. 逐处抽取值，**全部相同**才通过；列出每处的实际值供定位
  2. 抽不到值 ⇒ **FAIL**（不是 SKIP）—— 「查不出来 ≠ 查出来是好的」
  3. 与 `--expect` 一致（发布前用）
  4. 本清单 ⊇ `antinel_verify.py::_VERSION_HARD`（防两个检查器分叉）

用法：
    python ci/version_check.py
    python ci/version_check.py --expect 0.33.2   # 指定期望值（发布前用）
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

PKG = Path(os.environ.get("ANTINEL_PKG") or Path(__file__).resolve().parent.parent)

# (显示名, 相对路径, 正则, 分组号)
# ★ 只在**唯一且必填**的声明处抽取 —— 不要抽注释里的历史标注
# ★★ 本清单必须 ⊇ tools/antinel_verify.py 的 _VERSION_HARD（判据 4 强制）
SPOTS = [
    ("pyproject.toml",
     r'^version\s*=\s*"([^"]+)"', 1),
    ("server.json",
     r'"version"\s*:\s*"([^"]+)"', 1),
    ("antinel.py  VERSION",
     r'^VERSION\s*=\s*"([^"]+)"', 1),
    ("antinel_mcp.py",
     r'"serverInfo":\s*\{"name":\s*"antinel",\s*"version":\s*"([^"]+)"', 1),
    ("hooks/pre_tool_use.py  _ANTINEL_VERSION",
     r'^_ANTINEL_VERSION\s*=\s*"([^"]+)"', 1),
    ("scripts/build_package.py  VERSION",
     r'^VERSION\s*=\s*"([^"]+)"', 1),
    ("psl/manifest.json  version",
     r'"version"\s*:\s*"([^"]+)"', 1),
    ("rules/default.json  version",
     r'"version"\s*:\s*"([^"]+)"', 1),
    ("docs/AUDIT_SCHEMA.md  标题",
     r'随\s*v(\d+\.\d+\.\d+)', 1),
    ("SKILL.md  antinel-version",
     r'^\s*antinel-version:\s*"([^"]+)"', 1),
]

# INV-3 的 HARD 清单（产品侧真源）——用于判据 4 的"超集"检查。
# 只登记**相对路径**，不复制正则（正则的维护点是 antinel_verify.py）。
INV3_HARD_PATHS = {
    "antinel.py", "antinel_mcp.py", "rules/default.json", "pyproject.toml",
    "server.json", "psl/manifest.json", "docs/AUDIT_SCHEMA.md",
    "build_package.py",
}


def _inv3_superset_fails():
    """判据 4：本清单必须是 INV-3 清单的超集。
    比对用**文件名**（不比对全路径）—— INV-3 写 `build_package.py`（源仓布局
    平铺在根），本仓在 `scripts/`。这层错位正是它初版漏检的原因，必须显式容纳：
    ⇒ 只要**任一** SPOT 的 basename 等于 INV-3 项即算覆盖。"""
    ours = set()
    for label, _pat, _grp in SPOTS:
        rel = label.split()[0]
        ours.add(rel)
        ours.add(rel.rsplit("/", 1)[-1])
    return sorted(p for p in INV3_HARD_PATHS if p not in ours)


def extract():
    out = []
    for label, pat, grp in SPOTS:
        rel = label.split()[0]
        p = PKG / rel
        if not p.is_file() and rel.startswith("docs/"):
            p = PKG / rel.split("/", 1)[1]      # 源仓布局回退（与 INV-3 同法）
        if not p.is_file():
            out.append((label, None, "文件不存在"))
            continue
        try:
            t = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            out.append((label, None, "读取失败 %s" % type(e).__name__))
            continue
        m = re.search(pat, t, re.M)
        if not m:
            out.append((label, None, "未抽到（正则不匹配 ⇒ 声明可能被删/改格式）"))
            continue
        out.append((label, m.group(grp), ""))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect", help="期望版本（不给则用 psl/manifest.json 的 version）")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    rows = extract()
    print("=" * 78)
    print("版本号一致性守卫 —— %d 处承载件必须逐字相同" % len(SPOTS))
    print("包路径：%s" % PKG)
    print("=" * 78)

    # 先打印全部实际值（含未抽到的，如实显示）
    for label, val, err in rows:
        tag = val if val else "★未抽到"
        print("  %-46s %-10s %s" % (label, tag, err))
    print("-" * 78)

    vals = [v for _, v, _ in rows if v]
    missing = [(l, e) for l, v, e in rows if not v]

    fails = []
    # 判据 1：全部抽到
    if missing:
        for l, e in missing:
            fails.append("抽不到值：%s（%s）" % (l, e))
    # 判据 2：全部相同
    uniq = sorted(set(vals))
    if len(uniq) > 1:
        for v in uniq:
            who = [l for l, vv, _ in rows if vv == v]
            fails.append("版本 %s 出现在：%s" % (v, "; ".join(who)))
    # 判据 3：与期望一致
    expect = a.expect or (uniq[0] if len(uniq) == 1 else None)
    if a.expect and vals and any(v != a.expect for v in vals):
        fails.append("与 --expect=%s 不符（实际 %s）" % (a.expect, uniq))
    # 判据 4：本清单 ⊇ INV-3 清单（防两个检查器分叉 —— 初版就是这样漏了两处）
    gap = _inv3_superset_fails()
    if gap:
        fails.append("本清单漏了 INV-3 承载件：%s（两个检查器已分叉）" % ", ".join(gap))

    print()
    if not fails:
        print("★ PASS：%d 处版本号全部为 %s" % (len(rows), uniq[0]))
        # 额外提醒（不算 FAIL，但要看见）
        mf = PKG / "psl" / "manifest.json"
        if mf.is_file():
            d = json.loads(mf.read_text(encoding="utf-8"))
            bf = d.get("built_from")
            if bf and "r1v3" in str(bf):
                print("  ▲ 注意：psl/manifest.json 的 built_from 仍指向源仓 %s" % bf)
                print("     （build_package.py 已归位产物仓，重签时会自动改对）")
        if a.json:
            print(json.dumps({"ok": True, "version": uniq[0]}, ensure_ascii=False))
        return 0

    print("★ FAIL：版本号不一致 —— 发布前必须统一")
    for f in fails:
        print("   - %s" % f)
    if a.json:
        print(json.dumps({"ok": False, "fails": fails}, ensure_ascii=False))
    return 1


if __name__ == "__main__":
    sys.exit(main())
