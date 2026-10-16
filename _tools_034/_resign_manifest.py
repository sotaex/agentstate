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
    **唯一例外**：`--adopt-dev`——把 `host_shield._DEV_GUARDED_CHAIN_FILES`
    里**缺登记**的条目补进清单。为什么必须破这个例：那些是研发树专属件
    （`ci/freeze_zones.json`），`ci/` 不进 wheel（MANIFEST.in 无 ci/ 规则）
    ⇒ 构建器永远不会收它们 ⇒ 不补就永远红一条「没登记」，且构建器
    给不出修法（它重生清单也不会有）。补登名单**从 host_shield import**
    （不另抄一份），逐条按在场才校验（不在场跳过，同 self_check 口径），
    哈希口径与主循环同函数（非版本承载件 ⇒ 裸 sha256，与 `file_digest`
    一致）。
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

跑法：python _resign_manifest.py [--dry] [--roll] [--adopt-dev]
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
ap.add_argument("--adopt-dev", action="store_true",
                help="研发树专属名单补登记：把 host_shield._DEV_GUARDED_CHAIN_FILES"
                     " 里缺登记且在场的条目补进清单（哈希口径同主循环）")
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

# ---- --adopt-dev：研发树专属名单缺登记补入（0.51.1，self_check 的配套出路）----
#   ★ 为什么这里能破「不增删清单」的边界：这些件构建器永远不会收
#     （ci/ 不进 wheel）⇒ 不补就永远红，构建器给不出修法。名单从
#     host_shield import（单一真源），在场才校验（同 self_check 口径），
#     哈希走本文件的 sha256()（非版本承载件 ⇒ 裸 sha256，与 file_digest 一致）。
adopted = []
if args.adopt_dev:
    _dev_list = tuple(getattr(_hs_hash, "_DEV_GUARDED_CHAIN_FILES", ()) or ())
    if not _dev_list:
        print("（--adopt-dev：host_shield 没有 _DEV_GUARDED_CHAIN_FILES，无从补登）")
    for rel in _dev_list:
        p = os.path.join(ROOT, rel.replace("/", os.sep))
        if not os.path.isfile(p):
            print("  ADOPT-SKIP %s（文件不在场——在场才校验，同 self_check 口径）" % rel)
            continue
        if rel in files:
            continue                    # 已登记 ⇒ 走下面的重算主循环
        files[rel] = sha256(rel)
        adopted.append(rel)
        print("  ADOPT  %s（研发树专属名单缺登记，已按主循环同口径补入）" % rel)

# ★★ 量具先自检（维七：防量具假红假绿）—— 2026-10-12 由一次真实破坏逼出来。
#   本轮我跑本工具（旧口径）把 hooks/pre_tool_use.py "重签"成裸哈希，
#   而 `--manifest` 用归一化口径 ⇒ 校验立刻从绿变红。**量具自己错了，
#   而它没有任何一道自检会发现**（自检只注入产品缺陷，不验量具口径）。
#   ⇒ 2026-10-12 引入：写回之前，先对每个"口径特殊件"验一次。
#
# ★★ 2026-10-16 修订（GOV-01 落地时实测撞上）：原自检把「文件真实变更」
#   与「口径漂移」混为一谈——特殊件发生**非版本行**的实质演进（本次给钩子加
#   GOV-01 函数）时，归一化哈希必然变化 ⇒ 自检恒拒 ⇒ 钩子的实质演进被
#   **永久阻塞**。这是自检自身的设计缺陷（它想验的是"口径一致"，却验成了
#   "文件没变"）。改良：
#     · 与构建器 `_manifest_hash_of` **逐字互证**（两个独立实现，import 真源
#       不复制逻辑）——互证不一致 ⇒ 口径漂移 ⇒ 拒绝写回（X-003 硬保护保留）；
#     · 互证一致但与 manifest 旧值不等 ⇒ 只能是文件真变了 ⇒ 正是重签的本职
#       ⇒ 放行（打印声明，留下痕）。
try:
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import build_package as _bp_cross                     # noqa: E402
    _bp_hash_of = getattr(_bp_cross, "_manifest_hash_of", None)
except Exception:                                         # noqa: BLE001
    _bp_hash_of = None                                    # 构建器不在 ⇒ 退回旧口径（从严）

_selfcheck_bad = []
_selfcheck_changed = []
for _rel in getattr(_hs_hash, "VERSION_BEARING_CHAIN_FILES", ()):
    if _rel in files and os.path.isfile(os.path.join(ROOT, _rel)):
        _got = sha256(_rel)
        if _bp_hash_of is not None:
            _bp = _bp_hash_of(_rel, os.path.join(ROOT, _rel))
            if _bp != _got:
                sys.exit("★ 量具自检失败：本工具口径(%s)与构建器口径(%s)在 %s 上不一致"
                         " —— 口径漂移，**拒绝写回**（修工具，别修清单）"
                         % (_got[:19], _bp[:19], _rel))
        if _got != files[_rel]:
            if _bp_hash_of is not None:
                _selfcheck_changed.append(_rel)   # 口径已互证 ⇒ 是文件真变了，放行
            else:
                _selfcheck_bad.append(_rel)       # 无互证 ⇒ 无法区分，从严拒写
if _selfcheck_bad:
    sys.exit("★ 量具自检失败：口径特殊件 %s 算出的值与清单不符，且构建器口径不可用"
             " —— 无法区分口径漂移与文件变更，**拒绝写回**（修工具，别修清单）" % _selfcheck_bad)
if _selfcheck_changed:
    print("（量具自检：口径特殊件 %s 已与构建器 `_manifest_hash_of` 逐字互证一致；"
          "与清单旧值不同判为**文件真实变更**，照重签——非版本行演进是合法变更，"
          "这正是本工具的本职）" % (_selfcheck_changed,))

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

print("manifest 条目 %d ｜ 未变 %d ｜ 需重签 %d ｜ 文件不存在 %d ｜ 补登记 %d"
      % (len(files), same, len(changed), len(missing), len(adopted)))
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

if changed or rolled or adopted:
    d["files"] = files
    # ★★ 2026-10-13：`indent` 必须与**构建器**（`scripts/build_package.py`
    #   的两处 `json.dumps(manifest, ensure_ascii=False, indent=1)`）**逐字一致**。
    #   原先这里写 `indent=2` ⇒ 每次重签都把**整份文件**重排一遍
    #   （实测：改 9 条哈希 ⇒ diff 148 增 148 删），而两个写者格式不同
    #   本身就是 T-09「同一事实两套口径」。改回 `indent=1` 后 diff 只落在
    #   真正变的哈希行上。
    with open(MANIFEST, "w", encoding="utf-8", newline="") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("\n已写回：重签 %d 条、结构化对齐 %d 条、补登记 %d 条。"
          % (len(changed), len(rolled), len(adopted)))
else:
    print("\n无需重签。")
