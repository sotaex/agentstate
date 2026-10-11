# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""★ 负控：小泡泡根治措施（F1–F4）——逐条改坏，判据必须报红。

★★★ 为什么必须有（0.36.5，本轮核心）：
  「右下角又冒小泡泡」这个遗留，上一轮我给的结论是「服务没启动」——
  那是**现象**，不是根因。实测证明它是间歇的 ⇒「重启就好了」必然复发。
  本轮做了机制性根治（降噪闸看窗口可见性 ＋ 图标随姿态 ＋ 留痕），
  **但机制性改动如果没有负控，下一轮就会被"优化"掉而无人察觉**。

  ⇒ 本文件把四条措施逐条**注入缺陷**，断言 `ci/inbox_guards_0364.py`
    必须报红。**先红后绿** —— 不会红的判据是装饰。

★ 纪律（沿用本仓，且本轮又踩了一次）：
  · **无条件还原**（`finally`）—— 变异异常会残留产品代码；
  · **还原后逐字节复核** ——「以为还原了」不算还原；
  · **不在真实环境上试**（F2 教训）—— 判据/负控污染被测对象会让结果时绿时红。
"""
from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "ci", "inbox_guards_0364.py")
PY = sys.executable

# (名称, 目标文件, 原串, 变异串, 期望报红的判据前缀)
CASES = [
    # ── F1：把「窗口已可见就不弹」摘掉 ⇒ F1 必须红
    ("F1 降噪闸不再看窗口可见性",
     "host_shield.py",
     "        if console_is_visible():",
     "        if False:  # MUTANT: 不再看窗口可见性",
     "F1"),
    # ── F1b：把可见性判断改成恒 False（等价于"永远不弹"）⇒ F1 必须红
    ("F1b console_is_visible 恒 False（永远当成不可见）",
     "host_shield.py",
     "        return bool(WIN.find_console_windows())",
     "        return False  # MUTANT: 恒假",
     "F1"),
    # ── F2：把「判不出 ⇒ 照弹」改成「判不出 ⇒ 当已通知」⇒ F2 必须红
    ("F2 判不出可见性时静默免检",
     "host_shield.py",
     "        if console_is_visible():",
     "        if console_is_visible() is not False:  # MUTANT: None 也当已通知",
     "F2"),
    # ── F3：把图标写回一律 Warning ⇒ F3 必须红
    ("F3 图标退回一律黄色警告",
     "host_shield.py",
     '    bad = ("down", "interrupted", "warn")',
     '    bad = ("down", "interrupted", "warn", "guarding", "dev", None)',
     "F3"),
    # ── F3b：把「判不出」也判成 Warning ⇒ F3 必须红
    #   ★ 这条是 F3 **第二版**新增断言的负控（0.36.5）：
    #     「guard_posture 抛异常 / 无 state 键 ⇒ 偏中性」是新加的判断，
    #     没有负控的断言不是断言，是许愿。
    ("F3b 判不出姿态时也给警告（误报方向反了）",
     "host_shield.py",
     '    if s in bad:\n        return "Warning", "Warning"',
     '    if s in bad or s is None:\n        return "Warning", "Warning"',
     "F3"),
    # ── F3c：把「无 state 键」也判成坏 ⇒ F3 必须红
    ("F3c 无 state 键被当作故障",
     "host_shield.py",
     '    bad = ("down", "interrupted", "warn")\n'
     '    if s in bad:',
     '    bad = ("down", "interrupted", "warn")\n'
     '    if s in bad or (not s):',
     "F3"),
    # ── F4：气泡图标写死 Warning（只改托盘那处）⇒ F4 必须红
    ("F4 气泡图标写死 Warning（只改托盘那处）",
     "host_shield.py",
     '"$n.ShowBalloonTip(%d,\'%s\',\'%s\',\'%s\');"',
     '"$n.ShowBalloonTip(%d,\'%s\',\'%s\',\'Warning\');"',
     "F4"),
    # ── G2：把打包前闸门调用摘掉 ⇒ G2 必须红
    ("G2 打包前闸门被摘掉（纪律有、执行点无）",
     "scripts/build_package.py",
     "    if os.environ.get(\"ANTINEL_SKIP_GATE\") != \"1\":\n"
     "        _delivery_gate(out_root, full=not os.environ.get(\"ANTINEL_GATE_QUICK\"))",
     "    if False:  # MUTANT: 打包前闸门被摘掉\n"
     "        _delivery_gate(out_root, full=not os.environ.get(\"ANTINEL_GATE_QUICK\"))",
     "G2"),
]


def run_guard():
    # ★ `text=True` + `encoding` 必须成对给：漏了 `encoding` 时 Python 3.13
    #   直接返回 **bytes**，再调 .decode() 就是"str 与 bytes 相加"这种
    #   一看就懂的错 —— 但它让负控**整个崩在第一行**，看起来像"负控没跑"。
    #   ⇒ 判据/负控自身出错必须自己喊出来，不能长得像"通过了"。
    r = subprocess.run([PY, GUARD], capture_output=True, cwd=HERE, timeout=900,
                       text=True, encoding="utf-8", errors="replace")
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main():
    print("=" * 74)
    print("小泡泡根治负控：逐条改坏 F1–F4/G2，判据必须报红（先红后绿）")
    print("=" * 74)

    rc0, out0 = run_guard()
    # ★ 基线允许 D2 红（manifest 哈希随代码改动失配，属已知中间态），
    #   但**必须**能看到它，且不能有 F1–F4/G2 的红。
    base_bad = [ln.strip() for ln in out0.splitlines() if "❌" in ln]
    off = [ln for ln in base_bad if any(k in ln for k in
                                       ("F1", "F2", "F3", "F4", "G1", "G2"))]
    print("  基线：%s" % ("全绿" if not base_bad
                        else "%d 条红（%s）"
                        % (len(base_bad), "；".join(x[:40] for x in base_bad))))
    if off:
        print("  ⚠️ 基线里 F/G 组就已经红 —— 先修产品，负控不能建立在红基线上：")
        for x in off:
            print("     " + x)
        return 1

    ok = bad = 0
    for name, rel, old, new, expect in CASES:
        p = os.path.join(HERE, rel)
        bak = p + ".bubble_negctl.bak"
        src = io.open(p, encoding="utf-8").read()
        if old not in src:
            print("  [💥] %-46s 锚点未命中（%s）—— 负控失配，**不算通过**"
                  % (name[:46], rel))
            bad += 1
            continue
        shutil.copy2(p, bak)
        try:
            io.open(p, "w", encoding="utf-8", newline="\n").write(
                src.replace(old, new, 1))
            rc, out = run_guard()
            hit = expect in out and ("❌" in out or "💥" in out)
            if hit:
                print("  [RED(好)] %-46s -> 报红[%s]" % (name[:46], expect))
                ok += 1
            else:
                print("  [★GREEN(坏)] %-42s 期望 %s 报红，实际 rc=%d"
                      % (name[:42], expect, rc))
                for ln in out.splitlines():
                    if "❌" in ln or "💥" in ln:
                        print("         " + ln.strip()[:84])
                bad += 1
        finally:
            # 无条件还原
            shutil.move(bak, p)
            back = io.open(p, encoding="utf-8").read()
            if back != src:
                print("  ★ 还原失败：%s 与变异前不一致，需人工核对" % rel)
                bad += 1

    print()
    print("-" * 74)
    print("  %d 条按预期报红 / %d 条异常" % (ok, bad))
    if bad == 0:
        print("★ 负控通过：F1–F4/G2 都是真守卫，不是装饰")
    else:
        print("★ 负控有失败项：有判据是假守卫，或锚点需更新")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
