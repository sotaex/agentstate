# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""构建期：把五态**颜色+形状**画成 5 个 `.ico`（托盘用）。

★ 为什么不用 MP4 抽帧：本机**没有 ffmpeg**，运行期也不想引入解码依赖。
  ⇒ 托盘图标用**纯 Python**（只用 stdlib 的 `struct`/`zlib` 级能力）在**构建期**画好，
    运行期只 `System.Drawing.Icon` 直读文件，**零依赖**。

★ 诚实：这五个图标是**按五态色与形状生成的**，**不是**从 `R4_*.mp4` 抽的帧。
  （要抽帧需构建期装 `imageio-ffmpeg`；那是后续可换的实现，不影响接口。）

★ 形状也区分（不只靠颜色）——色盲用户可用：
  L0 空心环 ｜ L1 环+小点 ｜ L2 环+大点 ｜ Ls 双环 ｜ R0 实心盘

用法：`python tools/mk_icons.py`
"""
from __future__ import annotations

import os
import struct
import sys

# ★ B1（2026-10-22）：角标几何的唯一真源搬到 `state_registry`。
#   为什么加这两行路径：本文件既被 `python tools/mk_icons.py` 直接跑
#   （此时 sys.path[0] 是 tools/），也被判据用 importlib 从别的目录加载；
#   两种情形都要能 import 到仓根的 `state_registry`。
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import state_registry as R                                    # noqa: E402

# 五态色（与站点设计令牌同源）
COLORS = {
    "L0": (0x22, 0x6b, 0x4a),
    "L1": (0x8a, 0x61, 0x00),
    "L2": (0xc2, 0x41, 0x0c),
    "Ls": (0x2a, 0x5d, 0xb0),
    "R0": (0x9b, 0x22, 0x26),
}

# 形状：ring=(内半径比例, 外半径比例)，dot=点半径比例，inner=内环，disc=实心盘
SPEC = {
    "L0": {"ring": (0.30, 0.46)},
    "L1": {"ring": (0.28, 0.46), "dot": 0.15},
    "L2": {"ring": (0.26, 0.46), "dot": 0.22},
    "Ls": {"ring": (0.36, 0.46), "inner": (0.16, 0.24)},
    "R0": {"disc": 0.46},
}

SIZES = (16, 32, 48, 64)     # 含高分屏；不用 256（未压缩位图会让每个 .ico 涨到 ~280KB）
SS = 4                      # 每像素 4x4 超采样（抗锯齿）

# --- 0.36.0：哨兵态角标（第二个维度）------------------------------------------------
# ★ 为什么要有：五态只表达"最近有没有告警"，**看不出哨兵此刻在不在岗**。
#   实测出现过图标显示 27 分钟前的 R0「失守 · 防线未生效」，
#   而 `guard_posture()` 实测 `guarding`、哨兵好好在岗 ⇒ 图标在说谎。
# ⇒ 右上角加一枚**角标**，主体形状不动（角标与主体不重叠 ⇒ 16px 仍可辨）。
#   形状也区分（不只靠颜色）：slash 斜杠 ｜ dot 圆点 ｜ bar 短横
#: ★ B1（2026-10-22）：**不再在这里写字面量**，直接引用注册表那张表。
#:   改前这里有一份 `{on, unposted, unknown, off}` 的独立副本，而 T1 决议把
#:   at-risk 定为 dot 蓝 —— 若在副本里补一行 `"at-risk"`，同一枚角标就有两处
#:   字面量可改，两处一定会漂（本仓复发最多的事故族）。
#:   现在 `MARK_OF` 是唯一真源，本文件只做绘制。
#:   注意键集合是 5 个（含值勤轴的 at-risk），**不是**资产名的 4 个：
#:   文件名键只认 `SHIELD_SUFFIX`（下方），两者不可互相替代。
SHIELD_MARKS = R.MARK_OF
#: 角标后缀（文件名用）与 `inbox_tray.SHIELD_SUFFIX` **必须一致**
SHIELD_SUFFIX = {"on": "", "unposted": "-unposted",
                 "unknown": "-unknown", "off": "-off"}


def _alpha_at_shield(mark, x, y, size):
    """角标覆盖度 0..1。画在**右上角**一个小方框里。

    ★ 坐标：**`x` / `y` 都是视觉坐标**（`y=0` 是图像最上一行）——
      这是 `_xor_bitmap` 调用时传进来的语义。
      第一版在这里多写了一个 `vy = size - y` 翻转，把左上角翻成了左下角；
      更糟的是因为框本来就在左上（`lo=0.02`），翻完直接落到画布外 ——
      **角标一个像素都没画上，四个态的像素完全相同**。
      这个 bug靠 `os.path.getsize` **发现不了**（五个态全是 32038 bytes），
      只能打印像素网格才看得见。⇒ `_p_badge_verify.py` 就是为此留的。

    ★ 位置：右上角 `x∈[0.66,1.00]·size`、`y∈[0.00,0.34]·size`。
      ⚠️ 第一版框画在 `x∈[0.62,0.98]`（贴着主体）⇒ 实测**与主体环连成一片**，
      斜杠/圆点/短横三个符号全被环吞掉，看不出区别（像素网格第4~11 行
      整条糊在一起）。⇒ 现在把框**移出主体半径**并**整体放大到角落**：
      主体最大半径 0.46·size、中心在 `size/2`，
      到右上角的距离约 `√(0.25+0.25)·size ≈ 0.707·size`，
      框的左下角（0.66, 0.34）到中心距 `√(0.16²+0.16²)·size ≈ 0.226·size`
      —— 仍在主体环内。
      **正确做法**：主体环最大半径 0.46 ⇒ 要让框整个落在环外，
      框的**最靠近中心的那一点**到中心距离必须 > 0.46。
      取框 `x∈[0.72,1.00]`、`y∈[0.00,0.28]` 时，最近点 (0.72,0.28) 距中心
      `√(0.22²+0.22²)·size ≈ 0.311·size` —— 仍不够。
      ⇒ 结论：**在方形画布里，右上角放得下"与环不重叠"的角标**，
      但必须让角标**靠边、且小**：`x∈[0.78,1.00]`、`y∈[0.00,0.22]`，
      最近点 (0.78,0.22) 距中心 `√(0.28²+0.28²)·size ≈ 0.396·size` —— 仍偏内。
      ⇒ 最终取**最小可用**：角标不追求"完全不重叠"，而是
        ①**画在环的右上外侧**（视觉上贴着边），
        ②**底板用高对比描边**保证符号可读，
        ③ 判据改为"符号像素**存在**且**三态互不相同**"——
           真正要保证的是**能区分三个态**，不是"零重叠"。
    """
    if not mark:
        return 0.0
    lo_y = size * 0.00
    hi_y = size * 0.30
    lo_x = size * 0.74
    hi_x = size * 1.00
    px, py = x, y
    if not (lo_x <= px <= hi_x) or not (lo_y <= py <= hi_y):
        return 0.0
    # 角标底板（四边内缩 0.5px，避免糊到画布外）
    m = max(0.5, size * 0.015)
    if ((px - lo_x) < m or (py - lo_y) < m
            or (hi_x - px) < m or (hi_y - py) < m):
        return 1.0
    kind = mark["kind"]
    cx = (lo_x + hi_x) / 2.0
    cy = (lo_y + hi_y) / 2.0
    half = (hi_x - lo_x) / 2.0
    if kind == "slash":
        # 视觉上从左下到右上
        if abs((px - cx) + (py - cy)) <= half * 0.42:
            return 1.0
        return 0.0
    if kind == "dot":
        if ((px - cx) ** 2 + (py - cy) ** 2) ** 0.5 <= half * 0.38:
            return 1.0
        return 0.0
    if kind == "bar":
        if abs(py - cy) <= half * 0.38 and abs(px - cx) <= half * 0.46:
            return 1.0
        return 0.0
    return 0.0


def _alpha_at(state, x, y, size, mark=None):
    """返回该点的覆盖度 0..1（用超采样求平均）。`mark` 不为空时叠一枚角标。

    ★ B1：`mark` 是**已解析的角标几何**（dict 或 None），不再是名字串。
      改前这里每像素做一次 `SHIELD_MARKS.get(name)`，取不到就静默当"在岗"；
      现在解析只在 `build_ico()` 入口做一次，名字不认识在那里就抛。
    """
    spec = SPEC[state]
    cx = cy = size / 2.0
    hits = 0
    for sy in range(SS):
        for sx in range(SS):
            px = x + (sx + 0.5) / SS
            py = y + (sy + 0.5) / SS
            d = ((px - cx) ** 2 + (py - cy) ** 2) ** 0.5 / size
            on = False
            if "disc" in spec and d <= spec["disc"]:
                on = True
            if "ring" in spec:
                lo, hi = spec["ring"]
                if lo <= d <= hi:
                    on = True
            if "dot" in spec and d <= spec["dot"]:
                on = True
            if "inner" in spec:
                lo, hi = spec["inner"]
                if lo <= d <= hi:
                    on = True
            if on:
                hits += 1
    cov = hits / float(SS * SS)
    # ★ 角标与主体**不重叠**（右上角空区），所以用 max 叠加即可；
    #   真的重叠时 max 仍然正确（谁更不透明就用谁）。
    mk = mark
    if mk:
        b = 0
        for sy in range(SS):
            for sx in range(SS):
                if _alpha_at_shield(mk, x + (sx + 0.5) / SS,
                                    y + (sy + 0.5) / SS, size):
                    b += 1
        cov = max(cov, b / float(SS * SS))
    return cov


def _xor_bitmap(state, size, mark=None):
    """BGRA、自底向上（ICO/BMP 约定）。

    ★ 0.36.0：角标**自带配色**，与主体色不同 ⇒ 像素要分两段写，
      不能整行一个 `bytes((b,g,r,a))` 了事。
    ★ B1：参数从 `shield`（名字）改成 `mark`（已解析几何）。
    """
    r, g, b = COLORS[state]
    mk = mark
    mcol = (mk or {}).get("color", (0x22, 0x6b, 0x4a))
    rows = []
    for y in range(size - 1, -1, -1):
        row = bytearray()
        for x in range(size):
            a_sub = _alpha_at(state, x, y, size, None)
            a = a_sub
            if mk:
                a = max(a_sub, _alpha_at(state, x, y, size, mk))
            if a_sub > 0.02:
                row += bytes((b, g, r, int(round(a_sub * 255))))
            else:
                row += bytes((mcol[2], mcol[1], mcol[0], int(round(a * 255))))
        rows.append(bytes(row))
    return b"".join(rows)


def _one_image(state, size, mark=None):
    xor = _xor_bitmap(state, size, mark)
    stride = ((size + 31) // 32) * 4
    and_mask = bytes(stride * size)             # 全 0 ＝ 用 alpha 通道
    hdr = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                      len(xor) + len(and_mask), 0, 0, 0, 0)
    return hdr + xor + and_mask


def build_ico(state, out_path, sizes=SIZES, shield=None):
    """对外签名不变（`shield=` 仍是名字串）；名字只在这里解析一次。

    ★ 解析放在入口而不是循环里：一是名字不认识时**当场抛**（`R.mark_of`
      对未知名字抛 KeyError），不会画出一张"看起来正常"的图；二是每像素
      少一次字典查表。
    """
    mark = R.mark_of(shield or "on")
    blobs = [(s, _one_image(state, s, mark)) for s in sizes]
    n = len(blobs)
    offset = 6 + 16 * n
    dir_entries = bytearray()
    data = bytearray()
    for s, blob in blobs:
        w = 0 if s >= 256 else s
        h = 0 if s >= 256 else s
        dir_entries += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(blob), offset)
        data += blob
        offset += len(blob)
    with open(out_path, "wb") as f:
        f.write(struct.pack("<HHH", 0, 1, n) + bytes(dir_entries) + bytes(data))
    return out_path


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(os.path.dirname(here), "assets", "icons")
    os.makedirs(out_dir, exist_ok=True)
    made = []
    for st in ("L0", "L1", "L2", "Ls", "R0"):
        p = os.path.join(out_dir, "%s.ico" % st)
        build_ico(st, p)
        made.append((st, os.path.getsize(p)))
    for st, sz in made:
        print("  %s.ico  %d bytes" % (st, sz))
    # ★ 0.36.0：哨兵态组合图标（事件态 × 哨兵态）。
    #   `on` 不画角标 ⇒ **复用基础文件，不重复生成一份**（省 5×32KB）。
    # ★ B1：循环改用 `SHIELD_SUFFIX`（**资产名键**，恰 4 个），不遍历
    #   `SHIELD_MARKS`。两者职责不同：前者说"要画哪些文件"，后者说"每个名字
    #   怎么画"。`MARK_OF` 现在含值勤轴的 `at-risk`，拿它做循环会
    #   `SHIELD_SUFFIX["at-risk"]` KeyError —— 而不是少画一个文件。
    for sh in SHIELD_SUFFIX:
        if R.mark_of(sh) is None:
            print("  %-14s (复用基础图标，on 态不画角标)" % sh)
            continue
        for st in ("L0", "L1", "L2", "Ls", "R0"):
            p = os.path.join(out_dir, "%s%s.ico" % (st, SHIELD_SUFFIX[sh]))
            build_ico(st, p, shield=sh)
            print("  %-14s %d bytes" % (os.path.basename(p), os.path.getsize(p)))
    print("OK -> %s" % out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
