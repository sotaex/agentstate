# -*- coding: utf-8 -*-
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


def _alpha_at(state, x, y, size):
    """返回该点的覆盖度 0..1（用超采样求平均）。"""
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
    return hits / float(SS * SS)


def _xor_bitmap(state, size):
    """BGRA、自底向上（ICO/BMP 约定）。"""
    r, g, b = COLORS[state]
    rows = []
    for y in range(size - 1, -1, -1):
        row = bytearray()
        for x in range(size):
            a = int(round(_alpha_at(state, x, y, size) * 255))
            row += bytes((b, g, r, a))
        rows.append(bytes(row))
    return b"".join(rows)


def _one_image(state, size):
    xor = _xor_bitmap(state, size)
    stride = ((size + 31) // 32) * 4
    and_mask = bytes(stride * size)             # 全 0 ＝ 用 alpha 通道
    hdr = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                      len(xor) + len(and_mask), 0, 0, 0, 0)
    return hdr + xor + and_mask


def build_ico(state, out_path, sizes=SIZES):
    blobs = [(s, _one_image(state, s)) for s in sizes]
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
    print("OK -> %s" % out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
