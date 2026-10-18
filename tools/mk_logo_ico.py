# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""构建期：把 `assets/logo/logo.svg`（R4 定稿官方标志）栅格成 `assets/logo/antinel.ico`。

★ 用途（0.52.0）：桌面入口／登录自启／Toast AUMID 三处快捷方式共用的**品牌图标**。
  `.lnk` 的 `IconLocation` 要的是 `.ico`（不是 `.svg`）⇒ 构建期栅格化，运行期零依赖
  （与 `tools/mk_icons.py` 同 Convention：图 ico 是构建期产物，运行时不生成）。

★ 手法完全镜像 `tools/mk_icons.py`（纯 stdlib 画 `.ico`）：
  4x 超采样抗锯齿、32bpp BGRA 自底向上、AND 掩码全零。
★ 几何从 SVG **解析**而来（不硬编码）——`logo.svg` 保持单一真源，标志修订后重跑即可。
★ 已与 Edge 无头渲染的 SVG ground truth 逐结构比对一致（环四段、缺口位、指针角度）。

★★ 机制层自检（2026-10-17 小黄球第二次弄丢后重写；旧版只量"我以为 SVG 里有
   什么"，不量"SVG 里真有什么"——0.48.5 幻觉裁定删球后全链毫无察觉）：
  ⓪ **元素清单 fail-loud**：解析前清点 SVG 全部元素，白名单（svg/rect/g/path/
     circle）外的一律 FATAL —— 不许静默跳过（静默跳过＝元素丢失无人知晓）；
  ① **哨点在场断言**：没有 `<circle>` 直接 FATAL（FZ-001：创始人 2026-10-17
     裁定小黄球必须在场；0.48.5「去哨点」是幻觉裁定已作废）；
  ② **逐元素像素问责**：每个解析出的绘制层在 64px 下必须画出 ≥1 像素 ——
     "解析到了但什么都没画"与"没解析到"同样算丢（防单段弧被吞）；
  ③ **可辨断言**：哨点色不得与环色/底色相同（0.48.5 页面球"跟光束同色"
     那类事故在资产层的镜像）；16px 下哨点像素 ≥2（小尺寸仍可辨）；
  ④ 弧心 sanity bound（端点 0.1 精度 ⇒ 逐弧反推会散，只防整体跑偏）；
  ⑤ 16px 环/针/底像素下限（防"什么都没画"）；
  ⑥ 开口/环体方向探针（防角度算错、缺口开错位置）；
  ⑦ ASCII 网格 + PNG 落盘（仅研发树），人眼可复检。

用法：`python tools/mk_logo_ico.py`
"""
from __future__ import annotations

import math
import os
import re
import struct
import sys
import zlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVG_PATH = os.path.join(REPO, "assets", "logo", "logo.svg")
OUT_ICO = os.path.join(REPO, "assets", "logo", "antinel.ico")
OUT_DIR = os.path.join(REPO, ".psl")          # 仅研发树有；安装态没有就跳过落盘

SIZES = (16, 32, 48, 64)
SS = 4                      # 每像素 4x4 超采样（与 mk_icons 相同）
VIEW = 64.0                 # SVG viewBox 边长

#: 元素白名单 —— ⓪ 的元素清单 fail-loud 用它。**加元素类型必须先加这里**，
#: 且必须在 build_layers/render 里落地（清单过不了 ⇒ FATAL，不许静默）。
ALLOWED_TAGS = {"svg", "rect", "g", "path", "circle"}

#: 层种类 → ASCII 字符（O＝哨点/小黄球）
CH_OF_KIND = {"bg": "B", "arc": "R", "seg": "P", "dot": "O"}


# ---------- SVG 解析（只认本标志用到的元素形状，其余 fail-loud） ----------

def _attrs(tag):
    return dict(re.findall(r'([\w-]+)\s*=\s*"([^"]*)"', tag))


def _check_inventory(src):
    """⓪ 元素清单 fail-loud：SVG 里出现白名单外的元素 ⇒ FATAL。

    ★ 为什么必须有（机制层，2026-10-17）：旧版解析器只认 rect/path，0.48.5
      幻觉裁定把 `<circle>`（小黄球）删掉后**毫无察觉** —— 自检只量环/针/底，
      因为量具是按"我记得 SVG 里有什么"写的，不是按"SVG 里真有什么"写的。
      ⇒ 解析前先清点全部元素：白名单外的一律炸，不许静默跳过。
    """
    for m in re.finditer(r"<(\w+)(\s[^>]*)?>", src):
        tag = m.group(1)
        if tag not in ALLOWED_TAGS:
            raise SystemExit(
                "FATAL: logo.svg 出现白名单外元素 <%s> —— 栅格化器只支持 %s；"
                "要改图形走创始人签发，要先给本工具加支持（ALLOWED_TAGS）"
                % (tag, sorted(ALLOWED_TAGS)))


def parse_svg(path):
    src = open(path, encoding="utf-8").read()
    _check_inventory(src)                    # ⓪ 先清点，再解析
    doc = {"rect": None, "arcs": [], "segs": [], "dots": []}
    m = re.search(r"<rect\b[^>]*/>", src)
    if not m:
        raise SystemExit("FATAL: 没有 <rect>（背景）")
    a = _attrs(m.group(0))
    doc["rect"] = {"w": float(a["width"]), "h": float(a["height"]),
                   "rx": float(a.get("rx", "0")), "fill": a["fill"]}
    # <g> 的 stroke 属性对其子 path 生效
    gstroke = {}
    for gm in re.finditer(r"<g\b([^>]*)>", src):
        gstroke = _attrs("<g " + gm.group(1) + ">")
    for pm in re.finditer(r"<path\b[^>]*/>", src):
        a = _attrs(pm.group(0))
        stroke = a.get("stroke") or gstroke.get("stroke")
        sw = float(a.get("stroke-width") or gstroke.get("stroke-width", "1"))
        cap = a.get("stroke-linecap") or gstroke.get("stroke-linecap", "butt")
        d = a["d"]
        toks = re.findall(r"[A-ZaZ]|-?\d*\.?\d+(?:[eE]-?\d+)?", d)
        i = 0
        cur = None
        while i < len(toks):
            cmd = toks[i]
            if cmd == "M":
                cur = (float(toks[i + 1]), float(toks[i + 2])); i += 3
            elif cmd == "L":
                p2 = (float(toks[i + 1]), float(toks[i + 2])); i += 3
                doc["segs"].append({"p1": cur, "p2": p2, "w": sw,
                                    "color": stroke, "cap": cap})
                cur = p2
            elif cmd == "A":
                r = float(toks[i + 1])
                if abs(float(toks[i + 2]) - r) > 1e-9 or float(toks[i + 3]) != 0:
                    raise SystemExit("FATAL: 只支持圆形弧（rx=ry, rot=0）")
                laf, sf = int(toks[i + 4]), int(toks[i + 5])
                p2 = (float(toks[i + 1 + 5]), float(toks[i + 2 + 5]))
                i += 8
                doc["arcs"].append({"p1": cur, "p2": p2, "r": r, "w": sw,
                                    "color": stroke, "cap": cap,
                                    "large": laf, "sweep": sf})
                cur = p2
            else:
                raise SystemExit("FATAL: 不认识的路径命令 %r" % cmd)
    if not doc["arcs"]:
        raise SystemExit("FATAL: 没有弧（探针环）")
    for cm in re.finditer(r"<circle\b[^>]*/>", src):
        a = _attrs(cm.group(0))
        doc["dots"].append({"c": (float(a["cx"]), float(a["cy"])),
                            "r": float(a["r"]), "color": a["fill"]})
    # ① 哨点在场断言（FZ-001；0.48.5「去哨点」是幻觉裁定，2026-10-17 作废）
    if not doc["dots"]:
        raise SystemExit(
            "FATAL: logo.svg 没有 <circle>（小黄球/哨点）—— 创始人 2026-10-17"
            " 裁定：小黄球必须在场（FZ-001 冻结契约）；0.48.5『去哨点』是 AI"
            " 幻觉裁定，已作废。要真去掉它，先走 FZ-001 退休流程（创始人签字）")
    return doc


def arc_center(p1, p2, r, sweep):
    """端点 → 圆心（rot=0, rx=ry=r）。sweep=1 时圆心在中垂线负侧（本标志四段实测如此）。"""
    x1, y1 = p1; x2, y2 = p2
    mx, my = (x1 + x2) / 2.0, (y1 + y2) / 2.0
    dx, dy = x2 - x1, y2 - y1
    d = math.hypot(dx, dy)
    if d > 2 * r + 1e-9:
        raise SystemExit("FATAL: 弧半径小于半弦长")
    h = math.sqrt(max(r * r - (d / 2.0) ** 2, 0.0))
    ux, uy = dy / d, -dx / d
    s = -1.0 if sweep == 1 else 1.0
    return mx + s * h * ux, my + s * h * uy


def _hex(c):
    return tuple(int(c[i:i + 2], 16) for i in (1, 3, 5))


# ---------- 覆盖判定（全部在 64 空间） ----------

def in_round_rect(p, half, rad):
    qx = abs(p[0] - VIEW / 2) - (half - rad)
    qy = abs(p[1] - VIEW / 2) - (half - rad)
    return math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) <= rad


def in_arc(p, cx, cy, r, w, a1, delta):
    dx, dy = p[0] - cx, p[1] - cy
    if abs(math.hypot(dx, dy) - r) > w / 2.0:
        return False
    t = (math.atan2(dy, dx) - a1) % (2 * math.pi)
    return t <= delta + 1e-9 if delta >= 0 else t >= 2 * math.pi + delta - 1e-9


def in_dot(p, cx, cy, r):
    return math.hypot(p[0] - cx, p[1] - cy) <= r


def seg_dist(p, a, b):
    ax, ay = a; bx, by = b; px, py = p
    vx, vy = bx - ax, by - ay
    l2 = vx * vx + vy * vy
    t = 0.0 if l2 == 0 else max(0.0, min(1.0, ((px - ax) * vx + (py - ay) * vy) / l2))
    return math.hypot(px - (ax + t * vx), py - (ay + t * vy))


# ---------- 渲染 ----------

def build_layers(doc):
    """SVG → 绘制层（顺序即层级：后者在上）。返回 (layers, centers, kinds)。

    层种类：bg＝背景圆角矩形；arc＝探针环一段；seg＝指针；dot＝哨点（小黄球）。
    """
    layers = []
    rc = doc["rect"]
    layers.append(("bg", _hex(rc["fill"]), None))
    centers = []
    for a in doc["arcs"]:
        cx, cy = arc_center(a["p1"], a["p2"], a["r"], a["sweep"])
        centers.append((cx, cy))
        a1 = math.atan2(a["p1"][1] - cy, a["p1"][0] - cx)
        a2 = math.atan2(a["p2"][1] - cy, a["p2"][0] - cx)
        delta = (a2 - a1) % (2 * math.pi) if a["sweep"] == 1 else -((a1 - a2) % (2 * math.pi))
        layers.append(("arc", _hex(a["color"]), (cx, cy, a["r"], a["w"], a1, delta)))
    for s in doc["segs"]:
        layers.append(("seg", _hex(s["color"]), (s["p1"], s["p2"], s["w"])))
    for d in doc["dots"]:                   # 哨点最后＝最上层（SVG 子元素顺序）
        layers.append(("dot", _hex(d["color"]), (d["c"][0], d["c"][1], d["r"])))
    return layers, centers


def render(layers, size, half, rad):
    """返回 rows[j][i] = ((r,g,b,a), 赢家层下标, 主导字符)。

    主导字符按**子采样多数**定（O=哨点 P=指针 R=环 B=底 空格=透明）；
    赢家层下标取首个命中子采样的最上层（供逐元素问责用，比主导更敏感）。
    """
    step = VIEW / (size * SS)
    rows = []
    for j in range(size):
        row = []
        for i in range(size):
            sr = sg = sb = sa = 0.0
            n_dot = n_ptr = n_ring = n_bg = 0
            win = None
            for sy in range(SS):
                for sx in range(SS):
                    x = (i * SS + sx + 0.5) * step
                    y = (j * SS + sy + 0.5) * step
                    top = None
                    for li in range(len(layers) - 1, -1, -1):   # 后写的在上层
                        kind, col, g = layers[li]
                        if kind == "bg":
                            if in_round_rect((x, y), half, rad):
                                top = li; break
                        elif kind == "arc":
                            cx, cy, r, w, a1, delta = g
                            if in_arc((x, y), cx, cy, r, w, a1, delta):
                                top = li; break
                        elif kind == "dot":
                            cx, cy, r = g
                            if in_dot((x, y), cx, cy, r):
                                top = li; break
                        else:
                            p1, p2, w = g
                            if seg_dist((x, y), p1, p2) <= w / 2.0:
                                top = li; break
                    if top is None:
                        continue
                    if win is None:
                        win = top
                    kind = layers[top][0]
                    if kind == "bg":
                        n_bg += 1
                    elif kind == "arc":
                        n_ring += 1
                    elif kind == "dot":
                        n_dot += 1
                    else:
                        n_ptr += 1
                    col = layers[top][1]
                    sr += col[0]; sg += col[1]; sb += col[2]; sa += 255.0
            n = SS * SS
            if n_dot >= n_ptr and n_dot >= n_ring and n_dot >= n_bg and n_dot > 0:
                ch = "O"
            elif n_ptr >= n_ring and n_ptr >= n_bg and n_ptr > 0:
                ch = "P"
            elif n_ring >= n_bg and n_ring > 0:
                ch = "R"
            elif n_bg > 0:
                ch = "B"
            else:
                ch = " "
            row.append(((sr / n, sg / n, sb / n, sa / n), win, ch))
        rows.append(row)
    return rows


def ascii_dump(rows):
    return "\n".join("".join(ch for (_c, _li, ch) in row) for row in rows)


# ---------- ICO / PNG 写出 ----------

def one_image(rows, size):
    xor = bytearray()
    for j in range(size - 1, -1, -1):        # ICO/BMP 自底向上
        for i in range(size):
            r, g, b, a = rows[j][i][0]
            xor += bytes((int(round(b)), int(round(g)), int(round(r)), int(round(a))))
    stride = ((size + 31) // 32) * 4
    and_mask = bytes(stride * size)
    hdr = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                      len(xor) + len(and_mask), 0, 0, 0, 0)
    return hdr + bytes(xor) + and_mask


def build_ico(out, sizes, rows_by_size):
    blobs = [(s, one_image(rows_by_size[s], s)) for s in sizes]
    n = len(blobs)
    offset = 6 + 16 * n
    dir_entries = bytearray()
    data = bytearray()
    for s, blob in blobs:
        w = 0 if s >= 256 else s
        dir_entries += struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32, len(blob), offset)
        data += blob
        offset += len(blob)
    with open(out, "wb") as f:
        f.write(struct.pack("<HHH", 0, 1, n) + bytes(dir_entries) + bytes(data))


def _chunk(tag, data):
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


def write_png(path, rows):
    h = len(rows); w = len(rows[0])
    raw = b"".join(b"\x00" + b"".join(
        bytes((int(round(p[0][0])), int(round(p[0][1])),
               int(round(p[0][2])), int(round(p[0][3]))))
        for p in row) for row in rows)
    blob = (b"\x89PNG\r\n\x1a\n"
            + _chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(raw, 9))
            + _chunk(b"IEND", b""))
    open(path, "wb").write(blob)


def coverage_at(rows, size, x64, y64):
    """64 空间点 → 该像素的主导元素字符（最近邻，供方向探针用）。"""
    i = min(size - 1, max(0, int(x64 * size / VIEW)))
    j = min(size - 1, max(0, int(y64 * size / VIEW)))
    return rows[j][i][2]


def main():
    doc = parse_svg(SVG_PATH)
    layers, centers = build_layers(doc)
    # ④ 弧心 sanity bound（非精确共心）：logo.svg 路径端点是 0.1 精度圆过的，
    #   离 r=23.5 真圆最多差约 1.3px ⇒ 逐弧反推的圆心会散开（Edge 渲染器同样
    #   如此反推）——所以这里只防"整体跑偏"：均值须在 viewBox 中心 2px 内、
    #   单弧离均值不超 2px。角度一律用**逐弧圆心**算（忠实 SVG 规格）。
    cx0, cy0 = centers[0]
    mx = sum(c[0] for c in centers) / len(centers)
    my = sum(c[1] for c in centers) / len(centers)
    if math.hypot(mx - VIEW / 2, my - VIEW / 2) > 2.0:
        raise SystemExit("FATAL: 弧心整体偏离 viewBox 中心 %s" % (centers,))
    for cx, cy in centers:
        if math.hypot(cx - mx, cy - my) > 2.0:
            raise SystemExit("FATAL: 单弧圆心离群 %s" % (centers,))
    # ③ 可辨断言：哨点色不得与环色/底色相同（0.48.5 页面球"跟光束同色"那类
    #   事故在资产层的镜像 —— 颜色相同＝肉眼不可辨＝等于没有）
    dot_cols = {col for (kind, col, _g) in layers if kind == "dot"}
    other_cols = {col for (kind, col, _g) in layers if kind != "dot"}
    for dc in dot_cols:
        if dc in other_cols:
            raise SystemExit(
                "FATAL: 哨点色 %s 与其它元素同色 —— 肉眼不可辨（FZ-001 可辨契约）"
                % ("#%02x%02x%02x" % dc,))
    half = doc["rect"]["w"] / 2.0
    rad = doc["rect"]["rx"]
    rows_by_size = {}
    for s in SIZES:
        rows_by_size[s] = render(layers, s, half, rad)
    rows_big = render(layers, 192, half, rad)      # 大图只作人眼复检（不进 ICO）

    build_ico(OUT_ICO, SIZES, rows_by_size)
    print("ICO -> %s (%d bytes)" % (OUT_ICO, os.path.getsize(OUT_ICO)))
    for s in SIZES:
        print("  size %-3d ok" % s)

    # ② 逐元素像素问责：**每个**绘制层在 64px 下必须画出 ≥1 像素
    #   （"解析到了但什么都没画"与"没解析到"同样算丢 —— 防单段弧/哨点被吞）
    used = set()
    for row in rows_by_size[64]:
        for (_c, li, _ch) in row:
            if li is not None:
                used.add(li)
    missing = [i for i in range(len(layers)) if i not in used]
    if missing:
        raise SystemExit(
            "FATAL: 有绘制层一个像素都没画出（层下标 %s，种类 %s）—— 元素被吞"
            % (missing, [layers[i][0] for i in missing]))

    # ⑤ 16px 下环/针/哨点/底必须真的画上了（mk_icons 教训：大小发现不了空画）
    r16 = rows_by_size[16]
    cnt = {"R": 0, "P": 0, "B": 0, "O": 0}
    for row in r16:
        for px in row:
            cnt[px[2]] = cnt.get(px[2], 0) + 1
    print("16px: ring=%d pointer=%d dot=%d bg=%d / 256"
          % (cnt["R"], cnt["P"], cnt["O"], cnt["B"]))
    if cnt["R"] < 8 or cnt["P"] < 1 or cnt["B"] < 40:
        raise SystemExit("FATAL: 16px 渲染内容不足（环/针/底 有空）")
    # ③ 续：16px 下哨点 ≥2 像素（r=5/64 空间 ≈ 1.25px，含抗锯齿混合）
    if cnt["O"] < 2:
        raise SystemExit("FATAL: 16px 哨点像素不足：%d（小黄球不可辨？）" % cnt["O"])
    r64 = rows_by_size[64]
    n_ptr64 = sum(1 for row in r64 for px in row if px[2] == "P")
    if n_ptr64 < 20:
        raise SystemExit("FATAL: 64px 指针像素不足：%d" % n_ptr64)

    # ⑥ 方向探针——缺口中心（约 257°）不应有环；环体（45°）应几乎满环
    gap_pt = (32 + 23.5 * math.cos(math.radians(257)),
              32 + 23.5 * math.sin(math.radians(257)))
    ring_pt = (32 + 23.5 * math.cos(math.radians(45)),
               32 + 23.5 * math.sin(math.radians(45)))
    ch_gap = coverage_at(rows_big, 192, gap_pt[0], gap_pt[1])
    ch_ring = coverage_at(rows_big, 192, ring_pt[0], ring_pt[1])
    print("probe gap(257deg) -> %r ; ring(45deg) -> %r" % (ch_gap, ch_ring))
    if ch_gap not in (" ", "B"):
        raise SystemExit("FATAL: 开口位置画上了环（角度算错？）")
    if ch_ring != "R":
        raise SystemExit("FATAL: 环体位置没有环（角度算错？）")

    # ⑦ 复检产物（仅研发树有 .psl/；安装态跳过，不影响构建产物本身）
    if os.path.isdir(OUT_DIR):
        write_png(os.path.join(OUT_DIR, "_icon_check_192.png"), rows_big)
        for s in SIZES:
            write_png(os.path.join(OUT_DIR, "_icon_check_%d.png" % s), rows_by_size[s])
        print("PNG -> .psl/_icon_check_{16,32,48,64,192}.png")
    print("\n=== 64px ASCII（P=指针 R=环 O=哨点 B=底 空格=透明）===")
    print(ascii_dump(rows_by_size[64]))
    print("=== 16px ASCII ===")
    print(ascii_dump(rows_by_size[16]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
