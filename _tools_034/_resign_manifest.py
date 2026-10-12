# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""重签 psl/manifest.json 里已列出的文件哈希（不改清单本身）。

为什么需要它：D-1 守卫（`host_shield.self_check`）把 `host_shield.py` 的哈希
钉在 manifest 上 —— 这是**故意**的（防运行期被改）。但它意味着：**任何一次
正当的源码修改都会让自检变红**，而哨兵拉不起来（`spawn-failed`）。

正确的处置顺序是：改源码 → 重签 manifest → 再验证。
**不是**放掉守卫（放掉＝防投毒能力归零）。

边界（刻意保守）：
  · **只重算清单里已有的条目**——不新增文件、不删除条目。
    增删清单是构建器的职责（`scripts/build_package.py`），本工具不越权。
  · 文件不存在 ⇒ **报错并跳过**，不静默写 null（静默＝把"缺件"说成"已签"）。
  · 不碰 `name/version/built_at` 等元数据。

`--roll`（2026-10-12 新增，D-25 判据的配套出路）：
  死条目不再只能"报错并跳过"——那会让它**永远留在清单里**，而没有任何东西
  追平它（D-25 判据每次 commit 都会因此红，却给不出修法 ⇒ 红而无出路）。
  `--roll` 做**结构化对齐**，三个条件全是事实（集合运算），不是字面匹配豁免：
    ① 同目录；② 同扩展名；③ 该目录下该扩展名的文件**恰好一个**，
       且它自己还不在清单里。
  三条同时满足 ⇒ 把死条目改指向那个文件并重签；任一不满足 ⇒ **报错退出**，
  不猜、不静默（猜错＝把清单指向另一个错文件，比不修更坏）。

跑法：python _resign_manifest.py [--dry] [--roll]
"""
import argparse
import hashlib
import json
import os
import sys

# ★ 归档到 _tools_034/ 后仍要指向**包根**而不是本文件所在目录。
#   （本工具重签的是包根的 psl/manifest.json；跟着 __file__ 走会去找
#     _tools_034/psl/manifest.json —— 实测踩过一次 FileNotFoundError。）
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "psl", "manifest.json")

sys.path.insert(0, ROOT)     # 让 `import host_shield` 在源码树/归档布局下都成立

# ★★ 2026-10-12：口径必须与构建器 `scripts/build_package.py::_manifest_hash_of`
#   **逐字一致**。原先本工具用**裸 sha256**，而构建器对
#   `host_shield.VERSION_BEARING_CHAIN_FILES`（实测只 `hooks/pre_tool_use.py` 一件）
#   是**先把版本行的引号内值归一化掉再算**（版本行不进完整性哈希，否则每次
#   升版都会让自检变红）。两个口径不一致的后果是**双向的**：
#     · 假红：本工具把 hooks/pre_tool_use.py 判成"需重签"（它其实没变）；
#     · 破坏：照这个错值写回 manifest，`--manifest` 校验立刻从绿变红
#       （本轮实测踩过：`[SUPERSEDED] 1 of 124 ... changed: hooks/pre_tool_use.py`）。
#   判据不许二次实现 ⇒ 直接 import host_shield 拿归一化函数。
try:
    import host_shield as _hs_hash
except Exception as _e:                                       # noqa: BLE001
    sys.exit("★ import host_shield 失败（%s: %s）—— 取不到归一化口径，refusing to run"
             % (type(_e).__name__, _e))

ap = argparse.ArgumentParser()
ap.add_argument("--dry", action="store_true")
ap.add_argument("--roll", action="store_true",
                help="死条目结构化对齐：同目录+同扩展名+唯一 ⇒ 改指向它并重签")
args = ap.parse_args()


def sha256(rel):
    """与构建器 `_manifest_hash_of` 同一口径（归一化件走归一化，其余裸算）。"""
    p = os.path.join(ROOT, rel)
    if rel in getattr(_hs_hash, "VERSION_BEARING_CHAIN_FILES", ()):
        data = open(p, "rb").read()
        return "sha256:" + hashlib.sha256(_hs_hash.norm_version_bytes(data)).hexdigest()
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _roll_target(rel, listed):
    """死条目的**结构化**替代件：同目录 + 同扩展名 + 该目录下该扩展名恰好一个，
    且那个文件自己还不在清单里。三个条件全是事实（集合运算），不是字面匹配豁免。
    找不到唯一解 ⇒ None（调用方必须报错，不许猜）。"""
    d = os.path.dirname(rel)
    ext = os.path.splitext(rel)[1]
    dirp = os.path.join(ROOT, d) if d else ROOT
    if not os.path.isdir(dirp):
        return None
    cand = sorted(f for f in os.listdir(dirp)
                  if os.path.splitext(f)[1] == ext
                  and os.path.isfile(os.path.join(dirp, f))
                  and (d + "/" + f if d else f) not in listed)
    return (d + "/" + cand[0] if d else cand[0]) if len(cand) == 1 else None


d = json.load(open(MANIFEST, encoding="utf-8"))
files = d.get("files")
if not isinstance(files, dict) or not files:
    sys.exit("★ manifest 里没有 files 字典 ——  refusing to touch it")

# ★★ 量具先自检（维七：防量具假红假绿）—— 2026-10-12 由一次真实破坏逼出来。
#   本轮我跑本工具（旧口径）把 hooks/pre_tool_use.py "重签"成裸哈希，
#   而 `--manifest` 用归一化口径 ⇒ 校验立刻从绿变红。**量具自己错了，
#   而它没有任何一道自检会发现**（自检只注入产品缺陷，不验量具口径）。
#   ⇒ 现在：写回之前，先对每个"口径特殊件"验一次 —— 本工具算出的值必须与
#     manifest 已记录值一致（干净状态下理应相等）。不一致 ⇒ 本工具口径就错了
#     ⇒ **拒绝写回**（修工具，不许修清单）。
_selfcheck_bad = []
for _rel in getattr(_hs_hash, "VERSION_BEARING_CHAIN_FILES", ()):
    if _rel in files and os.path.isfile(os.path.join(ROOT, _rel)):
        if sha256(_rel) != files[_rel]:
            _selfcheck_bad.append(_rel)
if _selfcheck_bad:
    sys.exit("★ 量具自检失败：口径特殊件 %s 算出的值与清单不符 —— 本工具口径与构建器"
             "不一致，**拒绝写回**（修工具，别修清单）" % _selfcheck_bad)

changed, missing, same = [], [], 0
for rel in list(files):
    if not os.path.isfile(os.path.join(ROOT, rel)):
        missing.append(rel)
        continue
    live = sha256(rel)
    if files[rel] == live:
        same += 1
    else:
        changed.append(rel)
        files[rel] = live

# ---- --roll：把死条目结构化对齐到唯一同类件（D-25 判据的配套出路）----
rolled, stuck = [], []
if missing and args.roll:
    survivors = {}
    for rel in missing:
        tgt = _roll_target(rel, files)
        if tgt is None:
            stuck.append(rel)          # 猜不出唯一解 ⇒ 不许猜，报错退出
            continue
        # 重建 dict：把死条目的位置让给对齐件，保持原有 key 顺序
        survivors[tgt] = sha256(tgt)
        rolled.append((rel, tgt))
    if survivors:
        merged = {}
        for k, v in files.items():
            if k in dict(rolled):
                continue                # 死条目本身丢掉
            if k in survivors:
                merged[k] = survivors.pop(k)
                continue
            merged[k] = v
        for k, v in survivors.items():  # 目录里没有同目录活件时追加在尾部
            merged[k] = v
        files = merged

print("manifest 条目 %d ｜ 未变 %d ｜ 需重签 %d ｜ 文件不存在 %d"
      % (len(files), same, len(changed), len(missing)))
for r in changed:
    print("  RESIGN  %s" % r)
for r in missing:
    print("  MISSING %s  （不写入 —— 清单与磁盘不一致，需构建器处理）" % r)
for old, new in rolled:
    print("  ROLL    %s\n       -> %s" % (old, new))

if stuck:
    print("\n★ 有 %d 个死条目无法结构化对齐（同目录同扩展名不唯一或目录不在）⇒ 拒绝猜："
          "\n  请人工确认后手工处理，或跑 `python scripts/build_package.py` 重生清单。" % len(stuck))
    for r in stuck:
        print("     STUCK %s" % r)
    sys.exit(1)

if missing and not args.roll:
    print("\n★ 有 %d 个条目在磁盘上不存在。已重签其余条目，但**这份 manifest 与磁盘不一致**，"
          "\n  请跑 `python scripts/build_package.py` 生成完整发布包。"
          "\n  （若死因是活数据滚动——如 challenge/chain/ 每日替换——可用 `--roll` 结构化对齐）"
          % len(missing))

if args.dry:
    print("\n预览（未写）。")
    sys.exit(0)

if changed or rolled:
    d["files"] = files
    with open(MANIFEST, "w", encoding="utf-8", newline="") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("\n已写回：重签 %d 条、结构化对齐 %d 条。" % (len(changed), len(rolled)))
else:
    print("\n无需重签。")
