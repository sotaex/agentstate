# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""哨兵态角标判据（生成侧，像素级）。

★ 判据为什么是「三态像素**互不相同**」而不是「角标不与主体重叠」：
  实测下来，在32px 方形画布里，右上角**必然**与中心环有部分重叠
  （环最大半径 0.46·size，而角落最近点距中心约 0.4·size）——
  "零重叠"是个做不到的目标，写进判据就是一条**恒红的假要求**。
  真正要保证的是**用户能区分三个态**，所以判据落在：
    ① 角标像素**存在**（on 态右上角必须为空）
    ② 非 on 三态在右上角的像素集合**两两不同**
    ③ 主体中心环**未被角标扰动**（左半边与 on 态逐字节一致）

★ 为什么必须打到像素级：`os.path.getsize` 发现不了这个问题 ——
  五个态全是 **32038 bytes**，一模一样。第一版角标**一个像素都没画上**
  （函数里多写了一次 y 翻转，框直接落到画布外），字节数依然相同。

用法：python _p_badge_probe.py
"""
import itertools
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tools"))

import mk_icons as M          # noqa: E402
import state_registry as R    # noqa: E402


def _mark(name):
    """名字 → 角标几何。

    ★ B1（2026-10-22）起 `_alpha_at()` 要**已解析的几何**，不要名字串：
      解析只在入口做一次。这里也**不许**写 `SHIELD_MARKS.get(name)` ——
      取不到会返回 None，而 None 的语义是「不画角标」，于是本探针会拿
      「on 那块空白」去和其他态比，比出来"全都不一样"⇒ 假绿。
      走 `R.mark_of()`：不认识的名字当场抛，探针直接报错而不是悄悄通过。
    """
    return R.mark_of(name)

SIZE = 32
STATES = ("on", "unposted", "unknown", "off")

# ★ 判据区域＝**角标独占区**，不是"右上象限"。
#   实测踩到的坑：第一版判据取"右上象限"，而主体环半径 0.46·size
#   **必然侵入右上象限**（环本身就在那里）⇒ on 态右上角有 95 个像素，
#   判据恒红。这是一条**测错对象**的判据，不是产品缺陷。
#   ⇒ 正确做法：只取「到中心距离 > 主体最大半径」的那部分像素。
#   主体最大半径 = SPEC 里最大的那个值（L0=0.46，R0 实心盘 0.46）。
BODY_R = 0.47# 留 0.01 余量


def _in_corner(x, y):
    """这个像素在角标区吗（距中心 > BODY_R 且在右上）？"""
    cx = cy = SIZE / 2.0
    d = (((x - cx) ** 2 + (y - cy) ** 2) ** 0.5) / SIZE
    return d > BODY_R and x >= SIZE // 2 and y < SIZE // 2


CORNER = [(x, y) for y in range(SIZE) for x in range(SIZE) if _in_corner(x, y)]


def corner_pixels(state, event="L0"):
    return frozenset(
        (x, y) for (x, y) in CORNER
        if M._alpha_at(event, x, y, SIZE, _mark(state)) > 0.5)


def body_pixels(state, event="L0"):
    """主体区＝到中心距离 ≤ BODY_R 的全部像素。"""
    cx = cy = SIZE / 2.0
    return frozenset(
        (x, y) for y in range(SIZE) for x in range(SIZE)
        if ((((x - cx) ** 2 + (y - cy) ** 2) ** 0.5) / SIZE) <= BODY_R
        and M._alpha_at(event, x, y, SIZE, _mark(state)) > 0.5)


def left_pixels(state, event="L0"):
    return frozenset(
        (x, y) for y in range(SIZE) for x in range(SIZE // 2)
        if M._alpha_at(event, x, y, SIZE, _mark(state)) > 0.5)


def ascii_art(state, event="L0", rows=14):
    out = ["=== %s ===" % state]
    for y in range(rows):
        line = ""
        for x in range(SIZE):
            a = M._alpha_at(event, x, y, SIZE, _mark(state))
            line += "#" if a > 0.5 else ("+" if a > 0.05 else ".")
        out.append("%2d %s" % (y, line))
    return "\n".join(out)


def main():
    verbose = "--ascii" in sys.argv
    if verbose:
        for st in STATES:
            print(ascii_art(st))
        print()

    corners = {st: corner_pixels(st) for st in STATES}
    lefts = {st: left_pixels(st) for st in STATES}
    reds = []

    # ① on 态右上角必须为空；其余三态必须有像素
    if corners["on"]:
        reds.append("on 态右上角不该有像素，实测 %d 个" % len(corners["on"]))
    for st in ("unposted", "unknown", "off"):
        if not corners[st]:
            reds.append("%s 态右上角一个像素都没有（角标没画上）" % st)

    print("### 右上角像素数（on 必须为 0） ###")
    for st in STATES:
        print("%-10s %4d" % (st, len(corners[st])))

    print()
    print("### 三态两两像素集合必须不同 ###")
    for a, b in itertools.combinations(("unposted", "unknown", "off"), 2):
        same = corners[a] == corners[b]
        inter = len(corners[a] & corners[b])
        print("%-10s vs %-10s identical=%-5s shared=%d" % (a, b, same, inter))
        if same:
            reds.append("%s 与 %s 像素完全相同 ⇒ 用户区分不出来" % (a, b))

    print()
    print("### 主体中心不得被角标扰动（左半应与 on 态逐点一致） ###")
    for st in ("unposted", "unknown", "off"):
        same = lefts[st] == lefts["on"]
        print("%-10s left-identical=%s" % (st, same))
        if not same:
            reds.append("%s 扰动了主体左半（多=%d 少=%d）"
                        % (st, len(lefts[st] - lefts["on"]),
                           len(lefts["on"] - lefts[st])))

    print()
    if reds:
        for r in reds:
            print("RED %s" % r)
        return 1
    print("GREEN 角标存在、三态可区分、主体未被扰动")
    return 0


if __name__ == "__main__":
    sys.exit(main())