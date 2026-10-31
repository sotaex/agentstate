#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""把 psl/manifest.json 从「研发树态」退回「纯随包态」（出包前用）。

为什么需要它：
  `_tools_034/_resign_manifest.py --adopt-dev` 会把研发树专属件
  （`host_shield._DEV_GUARDED_CHAIN_FILES`，实测为 `ci/freeze_zones.json`）
  补进清单 —— 那是研发树自检（D-36 / self_check）的配套出路。但构建器
  **原样复制**仓根这份清单进 wheel，而 `ci/` 从不进 wheel ⇒ 纯净安装下
  `--manifest` 报 superseded，发布验收 [E] 红。

口径纪律：
  哈希**不重新实现**，逐字照抄 `_resign_manifest.py::sha256()`
  （版本承载件走 `host_shield.norm_version_bytes` 归一化，其余裸 sha256）；
  写盘格式同样逐字照抄（`indent=1` / `ensure_ascii=False` / `newline=""` / 末尾换行）。

用法：
  python output/_p_pure_manifest_0632.py            # 预览
  python output/_p_pure_manifest_0632.py --write    # 写回
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAN = os.path.join(ROOT, "psl", "manifest.json")
sys.path.insert(0, ROOT)

import host_shield as _hs  # noqa: E402

DEV_LIST = tuple(getattr(_hs, "_DEV_GUARDED_CHAIN_FILES", ()) or ())


def sha256(rel: str) -> str:
    p = os.path.join(ROOT, rel.replace("/", os.sep))
    if rel in getattr(_hs, "VERSION_BEARING_CHAIN_FILES", ()):
        data = open(p, "rb").read()
        return "sha256:" + hashlib.sha256(_hs.norm_version_bytes(data)).hexdigest()
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def main() -> int:
    write = "--write" in sys.argv
    d = json.load(open(MAN, encoding="utf-8"))
    files = d.get("files")
    if not isinstance(files, dict) or not files:
        sys.exit("★ manifest 里没有 files 字典 —— refusing to touch it")

    before = len(files)
    print("研发树专属名单：%s" % (list(DEV_LIST) or "（空）"))

    dropped = [k for k in list(files) if k in DEV_LIST]
    for k in dropped:
        files.pop(k)

    changed, missing = [], []
    for rel, old in list(files.items()):
        p = os.path.join(ROOT, rel.replace("/", os.sep))
        if not os.path.isfile(p):
            missing.append(rel)
            continue
        new = sha256(rel)
        if new != old:
            changed.append(rel)
            files[rel] = new

    print("条目：%d → %d ｜ 摘出 %s ｜ 重算 %d 条 ｜ 缺文件 %d 条"
          % (before, len(files), dropped or "无", len(changed), len(missing)))
    for r in changed:
        print("  RESIGN %s" % r)
    if missing:
        for r in missing:
            print("  MISSING %s" % r)
        return 1

    if not write:
        print("\n预览（未写）。加 --write 落盘。")
        return 0

    d["files"] = files
    with open(MAN, "w", encoding="utf-8", newline="") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
        f.write("\n")

    back = json.load(open(MAN, encoding="utf-8"))
    n = len(back.get("files", {}))
    leftover = [k for k in back.get("files", {}) if k in DEV_LIST]
    print("已写回：%d 条 ｜ 回读 %d 条 ｜ 研发树件残留 %s" % (len(files), n, leftover or "无"))
    if n != len(files) or leftover:
        print("★ 回读不符 —— 不许继续出包")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
