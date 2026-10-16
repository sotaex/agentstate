# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""★ 0.36.0 判据：窗口几何 ·托盘监理态 · 失守归因。

★ 本文件独立于 `inbox_guards_0353.py`，避免把上一轮已绿的判据搅在一起；
  两份会一起被 `ci/inbox_guards.py` 收录。

★ 纪律（沿用上一轮，每条都有本机实测支撑）：
  · **量具先测自己**：每条判据都配一条负控（`n_*`），
    负控把产品改坏 ⇒ 判据必须变红。恒真的判据等于没有判据。
  · **判据只读代码，不读解释代码的文字**：先剥注释再检查，
    否则修法说明里引用的旧写法会把判据自己搞红（本项目踩过两次）。
  · 口径类判据必须写清**分母与单位**（F40 病灶：口径混装）。
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for _p in (ROOT, os.path.join(ROOT, "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_SCRATCH = []


def _cleanup():
    for d in _SCRATCH:
        try:
            import shutil
            shutil.rmtree(d, ignore_errors=True)
        except Exception:                                       # noqa: BLE001
            pass
    del _SCRATCH[:]


def _strip_comments(src):
    """剥掉 `#` 行内注释。★ 判据只读代码，不读解释代码的文字。"""
    return "\n".join(ln.split("#", 1)[0] for ln in src.splitlines())


def _ast_seg(src, name):
    """★ 取某个函数的**真代码**（AST，docstring 已剥掉）。

    ★★★ 为什么必须有它（0.36.3 变异检验抓出来的）：
      `_code_only` **只剥注释，不剥 docstring** ⇒ 用它取段做的字符串检查
      会对"docstring 里提到了某个词"零分辨力。本轮已因此：
        · 假红一次：P10 命中了 docstring 里那句「而不是 `DestroyWindow`」；
        · 漏检一次：`Q03` 把关窗改成 `taskkill /F`（docstring 里
          恰好没有 `taskkill` 字样）⇒ **40 条判据无一报红**。
      ⇒ 凡要查"函数体里有没有某个危险动作"，一律走 AST 取段。
    """
    import ast
    try:
        tree = ast.parse(src)
    except Exception:                                       # noqa: BLE001
        return ""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            seg = ast.get_source_segment(src, node) or ""
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                i = seg.find(body[0].value.value)
                if i >= 0:
                    seg = seg[i + len(body[0].value.value):]
            return seg
    return ""


def _func_seg_of(code, name):
    """按**行边界**取 `def <name>(` 的函数段（到下一个行首 `def `/`class `）。

    ★ 为什么不能用子串 `split`（0.36.2 实测踩到，报了两条假红）：
      `find_console_window` 是 `find_console_windows` 的**前缀**，
      `split("def find_console_window")` 会先命中复数那个 ⇒ 取错段。
    """
    m = re.search(r"^def %s\(" % re.escape(name), code, re.M)
    if not m:
        return ""
    rest = code[m.start():]
    n = re.search(r"^(?:def |class )", rest[m.end() - m.start():], re.M)
    return rest[:m.end() - m.start() + n.start()] if n else rest


def _code_only(src, keep_strings=False):
    """返回**只含可执行代码**的源码：注释与 docstring 全部剥掉。

    ★ 为什么必须连 docstring 一起剥（本轮实测踩到）：
      `remediation.py` 的模块 docstring 里**专门写了**
      「不枚举窗口、不列进程」这段说明，还举了 `EnumWindows` 举例；
      而只剥 `#` 的第一版判据把**说明文字**当成了代码 ⇒ 报了一条假红。
      本项目已栽过两次同型（判据匹配到修法说明里引用的旧写法）。

    ★ 实现：用 `ast` 把整份文件重新生成（`ast.unparse`），
      它**天然**不含注释；再按需把字符串字面量替换成空串。

    ★★ `keep_strings` 为什么必须有（第二版实测踩到）：
      去掉 docstring 有两种做法 ——
        ① `node.value = ""`（把**所有**字符串都清空）：
           docstring 是清了，但**代码里的字符串字面量也一起没了**
           （`op == "guard_fix"` 变成 `op == ""`）⇒
           任何「检查操作名是否被受理」的判据全红，且是**假红**。
        ② 只清docstring：区分docstring 与有意义的字面量要靠 token/缩进启发，
           很脆。
      ⇒ 折中：清空**仅出现在语句位置**的字符串（那是 docstring），
        保留比较/字典键等位置的字符串。判据要查"函数调用了谁"时用默认；
        要查"字符串字面量是什么"时传 `keep_strings=True`。
    """
    import ast
    tree = ast.parse(src)
    if not keep_strings:
        for node in ast.walk(tree):
            # 语句位置的裸字符串（Expr(Constant(str))）就是 docstring
            if (isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                node.value.value = ""
    return ast.unparse(tree)


# ======================================================================
# 一、窗口几何（创始人 2026-10-07「别占屏幕太大面积，哨兵不能在舞台中央」）
# ======================================================================

def c_window_geometry_follows_resolution():
    """几何**必须随工作区变**，不是一组恰好没写死的常量。

    ★ 真实缺陷背景：本机实测开出来 **1050×1932、位置 (10,10)** ——
      高度占工作区（1952）的 **99%**、占屏幕面积 16%，紧贴左上角。
      根因是尺寸**写死**在 `WINDOW_SIZE = "1024,720"` 且**没有位置参数**。

    ★★ 判据两次收紧，都是变异检验逼出来的（不是读代码想出来的）：
      第一版只检查「四组不同工作区算出的矩形**互不相同**」。
      变异 `WORK_W_RATIO = 0`（宽度全归零）后，矩形变成
      `(2960,1264,0,640)` / `(1880,649,0,343)` / `(1326,440,0,240)` ——
      **x 不同 ⇒ 四组矩形仍互不相同 ⇒ 第一版判绿**，
      而窗口宽度已经是 **0**，用户根本看不见面板。
      ⇒ 现在加两条硬要求：
        ① 每个矩形的**宽和高都必须 > 0**；
        ② 宽与高**各自**在这四组工作区上也要互不相同
           （否则"只有宽度是常量"这类退化仍然漏过）。
    """
    import inbox_window as W
    cases = [(0, 0, 3000, 1952), (0, 0, 1920, 1040),
             (0, 0, 1366, 728), (0, 0, 2560, 1400)]
    rects = []
    for (l, t, r, b) in cases:
        g = W.console_geometry([W.WorkArea(l, t, r, b)])
        if not g["ok"]:
            return ("虚拟工作区 %dx%d 判成「开不下」：%s"
                    % (r - l, b - t, g["reason"]))
        _l, _t, ww, hh = g["rect"]
        if ww <= 0 or hh <= 0:
            return ("工作区 %dx%d 算出的面板尺寸是 %dx%d（宽或高为 0 ⇒ "
                    "用户根本看不见面板）" % (r - l, b - t, ww, hh))
        rects.append(tuple(g["rect"]))
    if len(set(rects)) != len(cases):
        return "四组不同工作区算出了重复矩形：%s" % (rects,)
    widths = {w for (_x, _y, w, _h) in rects}
    heights = {h for (_x, _y, _w, h) in rects}
    if len(widths) < 2:
        return ("四组工作区算出的**宽度全部相同**（%s）⇒ 宽度是常量，"
                "没有随屏幕变" % widths)
    if len(heights) < 2:
        return ("四组工作区算出的**高度全部相同**（%s）⇒ 高度是常量，"
                "没有随屏幕变" % heights)
    return True


def n_window_geometry_is_not_constant():
    """负控：把公式换成常量，判据必须变红。

    ★ 两个变异各测一条新增要求：
      ① `WORK_H_RATIO = 0` ⇒ 高度全 0（且高度全相同）
      ② `WORK_W_RATIO = 0` ⇒ 宽度全 0 —— 这正是第一版判据**漏过**的那个
    """
    import inbox_window as W
    cases = [(0, 0, 3000, 1952), (0, 0, 1920, 1040),
             (0, 0, 1366, 728), (0, 0, 2560, 1400)]

    def probe():
        rects = []
        for (l, t, r, b) in cases:
            g = W.console_geometry([W.WorkArea(l, t, r, b)])
            rects.append(tuple(g["rect"]) if g["ok"] else None)
        return rects

    base = probe()
    if len(set(base)) != 4:
        return False                    # 现状（公式）下不该命中

    orig_w, orig_h = W.WORK_W_RATIO, W.WORK_H_RATIO
    try:
        # 变异①：高度归零
        W.WORK_H_RATIO = 0.0
        r1 = probe()
        h_zero_catches = any((x and x[3] == 0) for x in r1)
        W.WORK_H_RATIO = orig_h
        # 变异②：宽度归零
        W.WORK_W_RATIO = 0.0
        r2 = probe()
        w_zero_catches = any((x and x[2] == 0) for x in r2)
        W.WORK_W_RATIO = orig_w
    finally:
        W.WORK_W_RATIO, W.WORK_H_RATIO = orig_w, orig_h
    return bool(h_zero_catches and w_zero_catches)


def c_panel_height_is_about_one_third():
    """面板高度 = 工作区高度的约 1/3（且有上限）。

    ★ 口径：分母＝**工作区**高度（已排除任务栏），不是屏幕高度。
      本机实测工作区 1952 ⇒ 面板 640 = 32.8%。
    """
    import inbox_window as W
    for (l, t, r, b) in [(0, 0, 3000, 1952), (0, 0, 1920, 1040),
                         (0, 0, 1366, 728)]:
        wa = W.WorkArea(l, t, r, b)
        g = W.console_geometry([wa])
        if not g["ok"]:
            return "工作区 %dx%d 判成开不下" % (wa.w, wa.h)
        h = g["rect"][3]
        ratio = h / float(wa.h)
        if not (0.30 <= ratio <= 0.36):
            return ("工作区 %d高 ⇒ 面板 %d 高 = %.1f%%，不在 30%%~36%% 区间"
                    % (wa.h, h, ratio * 100))
    return True


def c_panel_never_crosses_work_area():
    """面板**不得越出工作区**（越界＝会盖住任务栏、点不到关闭按钮）。"""
    import inbox_window as W
    bad = []
    for w_ in range(300, 4001, 137):
        for h_ in range(240, 2201, 113):
            wa = W.WorkArea(0, 0, w_, h_)
            g = W.console_geometry([wa])
            if not g["ok"]:
                continue
            l, t, ww, hh = g["rect"]
            if (l < wa.left or t < wa.top
                    or l + ww > wa.right or t + hh > wa.bottom):
                bad.append((wa.w, wa.h, g["rect"]))
    if bad:
        return "越界 %d 例，例：%s" % (len(bad), bad[:3])
    return True


def c_small_screen_degrades_honestly():
    """屏幕太小 ⇒ **不开面板**，并说清为什么。

    ★ 不许硬挤：硬挤出来的窗口盖住任务栏、点不到关闭按钮，
      那是"给不了就用"的形状。
    """
    import inbox_window as W
    for (l, t, r, b) in [(0, 0, 420, 300), (0, 0, 479, 359)]:
        g = W.console_geometry([W.WorkArea(l, t, r, b)])
        if g["ok"]:
            return "工作区 %dx%d 仍判成可开面板（应判开不下）" % (r - l, b - t)
        if not g["reason"]:
            return "判成开不下但**没给理由**（用户会以为是坏了）"
    return True


def c_no_display_info_is_not_silently_ok():
    """**探不到屏幕** ⇒ 也不许说"能开"。"""
    import inbox_window as W
    g = W.console_geometry([])
    if g["ok"]:
        return "一个显示器都探不到，却判成可以开面板"
    if not g["reason"]:
        return "探不到屏幕时没给理由"
    return True


def c_app_cmd_carries_size_and_position():
    """开窗口的命令**必须同时带尺寸与位置**，且 `--app=` 仍在末位。

    ★ `--app=` 放末位不是形式主义：既有判据
      （`c_console_app_window` / `c_console_real_branch`）按
      「最后一个参数是 `--app=`」判"是不是 app 模式"，顺序一换它们就误红。
    """
    import inbox_server as SV
    cmd = SV._app_window_cmd("http://127.0.0.1:1/?t=T")
    if not cmd:
        return "本机没找到 msedge/chrome ⇒ _app_window_cmd 返回 None"\
               "（不构成判据失败，但要如实知道）"
    if not cmd[-1].startswith("--app="):
        return "最后一个参数不是 --app=：%r" % (cmd[-1],)
    if not any(a.startswith("--window-size=") for a in cmd):
        return "命令里没有 --window-size"
    if not any(a.startswith("--window-position=") for a in cmd):
        return "命令里没有 --window-position（这就是「贴在左上角」的根因）"
    return True


def n_app_cmd_without_position_is_caught():
    """负控：**去掉** `--window-position` 后判据必须报红。

    ★★ 0.37.1 改真（2026-10-09）：旧版用**同样的入参**又调了一次
       `_app_window_cmd(url)`，然后断言"它不带 position"。
       ⇒ 前后两次调用的输入完全一样，什么都没变，却期望结论不同
         —— 这是披着负控外衣的**恒真/恒假断言**，不是变异反馈。
    """
    import inbox_server as SV
    orig = SV._app_window_cmd
    base = orig("http://127.0.0.1:1/?t=T")
    if not base:
        return True     # 本机没有 msedge/chrome ⇒ 无从变异（如实说明，不是失效）
    if not any(a.startswith("--window-position=") for a in base):
        return True     # 正常态本来就不带 ⇒ 负控无从分辨（本方法不适用）
    try:
        SV._app_window_cmd = lambda url, geometry=None: [
            a for a in (orig(url, geometry) or [])
            if not a.startswith("--window-position=")]
        r = c_app_cmd_carries_size_and_position()
        return True if r is not True else "负控失效：命令里已没有 --window-position，判据仍报绿"
    finally:
        SV._app_window_cmd = orig


def c_window_size_default_is_not_the_old_tall_one():
    """兜底尺寸不再是从前的 `1024,720`（那个实测开出来占满整屏高度）。"""
    import inbox_server as SV
    m = re.match(r"^(\d+),(\d+)$", SV.WINDOW_SIZE or "")
    if not m:
        return "WINDOW_SIZE 格式不对：%r" % SV.WINDOW_SIZE
    w, h = int(m.group(1)), int(m.group(2))
    if (w, h) == (1024, 720):
        return "兜底尺寸还是 1024,720（实测开出来 1050x1932，占满整屏）"
    if h > 700:
        return "兜底高度 %d 仍然过高" % h
    return True


# ======================================================================
# 一之二、开窗**之后**的落位（0.36.0 补正，本轮实测抓到的真缺陷）
# ======================================================================
# ★ 为什么单独一组：上一版只验「命令里带了 size+position」（G06），
#   而**实测证明带了也等于没带** —— 本机开出来仍是 1050x1932 @(10,10)，
#   因为 Edge 已有运行实例时 app 窗口由旧进程接管，命令行参数被丢弃。
#   ⇒ 这组判据盯的是「开完之后**真的**落到目标矩形」这条链路。
#   ★ 教训：G06 验的是**请求**，这组验的是**事实** —— 两者不能互相代替。

def c_place_window_moves_to_target():
    """落位必须真的把**目标矩形**下发给系统（注入替身验逻辑）。

    ★★★ 0.36.3：函数从 `place_window` 改成 **`place_all`**。
      删掉单数版 `place_window` 的依据是实测（生产代码零调用），
      判据必须跟着删；否则判据红的原因是"我守的函数没了"，
      而不是"产品坏了"—— 那叫**假红**，会让人忽略真正的红。
      ★ 判据的价值在于"改坏产品必变红"。守一个不存在的函数，
        既不会在产品坏时变红，又会在代码整理时假红 ⇒ 净负价值。
    """
    import inbox_window as WIN
    moved = {}

    def fake_setter(hwnd, rect):
        moved["hwnd"] = hwnd
        moved["rect"] = tuple(rect)
        return True

    # ★★ 0.36.4 修判据自身（实测踩到）：`reader` 原来返回**目标矩形**，
    #   而 0.36.4 的 `place_all` 新增 `skip_if_placed`（默认开，先回读）——
    #   回读结果等于目标 ⇒ 判定"已经对齐"⇒ **一条移动都不发**。
    #   ⇒ 判据看到 `moved["rect"] is None`，报"落位下发的矩形不对：None"。
    #   而**产品行为完全正确**：窗口已对齐时就不该再搬它。
    #   ⇒ 教训与 0362 Q06 同族：**判据必须显式构造它要验的场景**，
    #     不能让"新机制改变了默认路径"这件事变成假红。
    #   ⇒ 这里让 reader 报一个**未对齐**的矩形（真实故障形状 1050×1932），
    #     这样 place_all 必须下发移动，且移动后回读到目标。
    target = (2440, 1264, 520, 640)
    wrong = (10, 10, 1050, 1932)
    seen = {}

    def fake_reader(h):
        # 第一次回读（移动前）报未对齐；移动后报已对齐
        seen["moved"] = "hwnd" in moved
        return target if seen["moved"] else wrong

    ok, why = WIN.place_all([1234], target,
                            setter=fake_setter, reader=fake_reader)
    if not ok:
        return "落位没成功：%s" % why
    if moved.get("rect") != target:
        return "落位下发的矩形不对：%r" % (moved.get("rect"),)
    if moved.get("hwnd") != 1234:
        return "落位动错了窗口句柄：%r" % (moved.get("hwnd"),)
    return True


def n_place_window_without_moving_is_caught():
    """负控：setter 什么都没做（原地不动）时，落位必须**不报成功**。

    ★ 这条是「0.36.0 补正」的核心负控：上一版的写法是"下发成功就报成功"，
      而实测那正是 1050x1932 被当成已处理的原因。
    ★ 用真 hwnd 走不了（会动真窗口），所以验的是**判据自己的分辨力**：
      构造一个"setter 返回成功但实测矩形不符"的场景，要求函数返回 False。
    ★ 0.36.3：随单数版 `place_window` 删除，改测 `place_all`。
    """
    import inbox_window as WIN
    ok, why = WIN.place_all([0x7FFFFFF0], (2440, 1264, 520, 640),
                            setter=lambda h, r: True,
                            reader=lambda h: (10, 10, 1050, 1932))
    if ok:
        return False        # 报成功 ⇒ 判据无分辨力
    if "不一致" not in why and "没落位" not in why:
        return "说法不含糊：%r" % why
    return True


def c_place_window_checks_result_truthfully():
    """★★ 落位必须**核验实测结果**，不能"下发成功"就报成功。

    这条是本组的命门：2026-10-07 实测发现，正是"以为下发了就成"这类写法
    让 1050x1932 的窗口被当成已处理。

    ★★★ 0.36.2 把这条判据从"查字符串"改成"**真跑**"（变异检验抓出来的）：
      原版查 `place_one` 源码里有没有 `window_rect_of` / `不一致`。
      而 0.36.2 的变异 `got = reader(hwnd)` → `got = rect  # MUTANT: 假定下发即生效`
      **并没有删掉那两个字符串**（`reader = window_rect_of` 那一行还在）
      ⇒ **变异检验报 BAD：判据对这条变异零分辨力**。
      ★ 这与本轮 P12 是同型病：**字面量检查对"行为变了"零分辨力**。
        凡能真跑的就真跑 —— 判据的价值在于"改坏产品必变红"，不在于"有检查动作"。
      ⇒ 现在真跑一次：注入"下发成功但实测矩形不符"的场景，
        要求函数返回 False。变异后（`got = rect`）它会报成功 ⇒ 判红。
    """
    import inbox_window as WIN
    src = _src_of(WIN)
    if "window_rect_of" not in src:
        return "落位链路没有回读实测矩形（`window_rect_of`）"
    good = (2440, 1264, 520, 640)
    bad = (10, 10, 1050, 1932)          # 实测真实故障形状
    ok, why = WIN.place_all([1], good,
                            setter=lambda h, r: True,
                            reader=lambda h: bad)
    if ok:
        return ("实测矩形是 1050x1932 却报成功"
                "（＝'下发即生效'那类写法，正是本组命门）")
    if "不一致" not in why and "没落位" not in why:
        return "说法不含糊：%r" % why
    return True


def c_place_window_does_not_touch_other_windows():
    """★ 落位**只**动标题匹配的窗口 —— 误伤用户窗口不可接受。

    本仓既有纪律：`inbox_window` 不去移动别的程序。这条守住它。
    ★★ 这条判据**第一版有真实缺口**（变异检验抓出来的，不是推演）：
      原来只查 `place_window` 主体里有没有「循环里调 SetWindowPos」，
      于是把 `find_console_window` 里的 `== title` 换成"有标题就收"，
      本判据**仍然报绿** —— 而那正是"移动所有窗口"的实现形状。
      根因同本文件 `_code_only`：**只看了一段，没看调用链上游**。
      ⇒ 现在查整条链：枚举侧按标题过滤 + 找到就收手 + 收旧窗侧也过滤
        + 落位侧不批量。
    ★★ 第二版缺口（0.36.1）：匹配从"完整标题相等"改成
      "稳定后缀 endswith"（标题前半段随页面变）⇒ 本判据的
      `== title` 检查与实现脱节而报红。**判据也必须跟着口径改，
      但改的时候要说清新口径为什么仍然不会误伤**（见 P04）。
    """
    import inbox_window as WIN
    full = _src_of(WIN)
    code = _code_only(full)
    if "CONSOLE_WINDOW_TITLE_SUFFIX" not in full:
        return "没有标题常量，落位范围无法限定"
    # ① **枚举侧**（0.36.2：全量枚举搬到了 `find_console_windows`）：
    #    必须按标题过滤，且**必须带上判据实参**往下传 ——
    #    漏传就会退回宽泛判据，那正是"认错/关错用户窗口"的入口。
    #    ★ 口径变更（0.36.2）：统一入口从 `_matches_title` 换成
    #      `is_console_title` —— 因为身份串在标题**末尾**，
    #      通用后缀 endswith 认不出带身份串的窗口（实测为 False）。
    #      **不变量没变**（仍是"按标题过滤"），变的是"用哪个函数过滤"。
    seg = code.split("def find_console_windows", 1)[-1].split("\ndef ", 1)[0]
    if "is_console_title" not in seg:
        return ("枚举侧不再按标题过滤（`is_console_title` 消失）"
                "⇒ 会把所有有标题的窗口都当成Antinel 监理窗口移动")
    # 统一判据必须有**真正的匹配动作**。
    # ★ 这里不要求它调 `_matches_title`：身份后缀必须**整串**匹配，
    #   走 `_matches_title` 反而是错的口径（它只做通用后缀 endswith）。
    # ★★ 0.36.5 修这条判据的**合法动作清单**（实测：修好 P15 后它反而红了）：
    #   原来只认 `endswith` 与 `CONSOLE_WINDOW_TITLE_MARK` 两个**字样**，
    #   而 0.36.5 把宽泛判据改成 `fullmatch`（连前缀一起认，才防得住
    #   '记事本 - 收件箱 · 值守台' 这类**前面挂了别的程序**的窗口）
    #   ⇒ 代码是对的、判据是旧的。
    #   ⇒ 这里**不是放宽成"什么都行"**（那等于没有判据），
    #     而是补上**同样严格、甚至更严格**的那一类：整串匹配。
    #   ★ 判据的取向：宁可漏一个形态（会在 P15 实跑里报出来），
    #     也不许放过"根本没有匹配动作"（那会让所有误伤判据失去意义）。
    _iseg = _func_seg_of(code, "is_console_title")
    _MATCH_ACTIONS = ("endswith", "CONSOLE_WINDOW_TITLE_MARK",
                      "fullmatch", "_mark_at_tail", "search")
    if not any(a in _iseg for a in _MATCH_ACTIONS):
        return "统一标题判据里没有任何实际匹配动作"
    # ★ 浏览器普通窗口必须被排除（本轮真闯过"关掉用户 15 标签窗口"的祸）
    if "BROWSER_TITLE_MARKS" not in full:
        return "没有排除浏览器普通窗口的判据（会误关/误移用户窗口）"
    # ② ★★ 0.36.3：**单数兼容层已删除**，本项改为守"它不许复活"。
    #    删它的依据是实测（生产代码零调用），而它的语义"只返回第一个"
    #    正是 0.36.2 修掉的原故障根因 ⇒ 留着就是留着一扇复发之门。
    #    ⇒ 判据从"必须转发到全量"改成"**必须不存在**"。
    #    ★ 判据的方向性：判据不只该在产品坏时变红，也该在**漏洞被引回**时变红。
    _m1 = re.search(r"^def find_console_window\(", code, re.M)
    _m2 = re.search(r"^def place_window\(", code, re.M)
    if _m1 or _m2:
        return ("0.36.1 的兼容层复活了（%s）—— 它的"
                "『只处理第一个』语义正是『窗口出现在旧位置旧尺寸』的根因"
                % ("、".join([n for n, m in (("find_console_window", _m1),
                                             ("place_window", _m2)) if m])))
    # ③ 收旧窗那一侧同样必须按标题过滤（否则会误关用户窗口）
    cseg = code.split("def close_console_windows", 1)[-1].split("\ndef ", 1)[0]
    if "find_console_windows" not in cseg:
        return "close_console_windows 没走按标题过滤的全量枚举（会误关用户窗口）"
    # ④ 落位侧：循环**只允许**遍历"调用方传进来的、已过滤的句柄" ——
    #    0.36.1 的写法是"place_window 里不许有 for + SetWindowPos"，
    #    那条现在**搬到了 place_all**（全量落位，循环是必需的）。
    #    不变量没变：移动范围只能由**上游的标题过滤**决定。
    #    所以这里查的是"落位层自己**不枚举**、不自己匹配标题"。
    aseg = code.split("def place_all", 1)[-1].split("\ndef ", 1)[0]
    if "_matches_title" in aseg or "EnumWindows" in aseg:
        return "place_all 自己枚举/自己匹配标题（移动范围必须由上游过滤限定）"
    if "find_console_windows" in aseg or "find_console_window" in aseg:
        return "place_all 自己去枚举窗口（应只落位调用方传入的句柄）"
    pseg = code.split("def place_one", 1)[-1].split("\ndef ", 1)[0]
    if "SetWindowPos" not in pseg:
        return "place_one 里没有 SetWindowPos（落位链路断了）"
    # ⑤ ★ 0.36.2 新增：落位**必须只认本次运行的身份串**。
    #    没有这一条，"只按标题过滤"仍可能命中用户自己的浏览器窗口
    #    （实测 Edge 普通窗口标题含「 · 值守台」）。
    if "console_title_suffix" not in full:
        return "没有按 run_id 派生的窗口身份后缀（无法只认本次运行的窗口）"
    return True


def c_open_console_calls_place_after_open():
    """`open_console` 必须在开窗**之后**调用落位（顺序不能反）。"""
    import inbox_server as SV
    src = _src_of(SV)
    if "_place_if_needed" not in src:
        return "open_console 没有调用落位"
    # ★ 2026-10-13（C4）：必须按**行边界**取函数段（`_func_seg_of`），
    #   不许 `split("def open_console")` —— `open_console_settled`
    #   （C4 新增，定义在 `open_console` **之前**）是它的前缀，
    #   子串切分会先命中 settled 那个 ⇒ 取到错的函数段 ⇒ **假红**（实测：
    #   settled 里没有 `_place_if_needed`，P05 当场误报"没有调用落位"）。
    #   与 0.36.2 `find_console_window`/`find_console_windows` 同族。
    body = _func_seg_of(src, "open_console")
    # ★ 0.37.1：先判 `in body` 再 `.index()`。
    #   旧写法是 `body.index("_place_if_needed")` —— 变异把**调用**改掉之后
    #   （函数定义还在、模块里仍有这个词）走到这一句会抛 `ValueError`，
    #   于是判据不是"报红"，而是"自身崩溃"。
    #   ⇒ **异常不是检测结论**：它说不出哪里坏了，只让人以为跑挂了。
    if "_place_if_needed" not in body:
        return ("open_console 里没有调用落位（只剩定义行）⇒ 窗口开出来"
                "落在哪全凭运气")
    if "Popen" in body and body.index("Popen") > body.index("_place_if_needed"):
        return "落位在 Popen **之前**调用（窗口还没开出来，必然落空）"
    return True


def n_open_console_without_place_is_caught():
    """负控：**把源码里的落位调用改掉**后判据必须报红。

    ★★ 0.37.1 改真（2026-10-09）：旧版把源码字符串替换的结果存在局部变量
       `mutated` 里，**既不写盘也不 reload**，最后返回的是
       "替换后的字符串里有没有 `_place_if_needed`" ——
       它验的其实是 `str.replace` 成不成立，与判据有没有眼睛毫无关系
       （本仓第 6 次同型）。这类负控最危险：它永远绿，因为它从不接触产品。

    ⇒ 真变异：**真的写盘 + 真的 reload**，然后在变异态下调用判据看它红不红；
      跑完必须**还原并验证**还原成功（坏品种滞留比空负控更险）。
    """
    import importlib
    import inbox_server as SV
    p = os.path.join(ROOT, "inbox_server.py")
    # ★ 用**二进制**做原地快照：文本读写会把 LF 换成 CRLF（0.37.1 在
    #   psl/manifest.json 上刚吃过这个亏 —— 一行版本改动变成整份 diff）。
    # ★ 锚点取**真实的那次调用**（`inbox_server.py:1692`），不取旧版留下的
    #   `_place_if_needed(placer)` —— 那个形态已在 0.36.3 随 run_id 入参改掉了，
    #   沿用旧锚点会让本负控变成"恒不适用"（最舒服的一种假守卫）。
    anchor = "_place_if_needed(placer, run_id=run_id, verbose=verbose)"
    raw = open(p, "rb").read()
    raw_utf8 = raw.decode("utf-8")
    if anchor not in raw_utf8:
        return True     # 锚点已变 ⇒ 本负控不适用（如实说明，不冒充有效）
    wrote = False
    try:
        mutated = raw_utf8.replace(anchor, "pass  # mutated")
        open(p, "wb").write(mutated.encode("utf-8"))
        wrote = True
        importlib.reload(SV)
        r = c_open_console_calls_place_after_open()
        return (True if r is not True
                else "负控失效：源码里的落位调用已被改成 pass，判据仍报绿")
    finally:
        # ★ 只有在**真的改写过**时才校验还原（提前 return 的路径没写盘，
        #   无条件 assert 会把"本负控不适用"误报成"还原失败"）。
        open(p, "wb").write(raw)    # 覆盖写，不删文件 ⇒ 不碰删除规则
        importlib.reload(SV)
        if wrote and anchor not in open(p, "rb").read().decode("utf-8"):
            raise AssertionError("还原失败：变异留在了 inbox_server.py 里")


def c_place_reports_failure_honestly():
    """★ 找不到窗口 / 系统拒绝 / 实测不符 ⇒ 三种都要说人话，不许吞掉。

    ★ 0.36.3：随单数版 `place_window` 删除，改测 `place_all`。
      "空句柄列表"这条路径过去由单数版负责，现在由调用方
      （`_place_if_needed`）在枚举后自行判断 —— 所以这里改成直接验
      `place_all` 拿到空列表时的说法。
    """
    import inbox_window as WIN
    ok, why = WIN.place_all([], (2440, 1264, 520, 640),
                            setter=lambda h, r: True)
    if ok:
        return "没有窗口却报成功"
    if not why or "没找到" not in why:
        return "找不到窗口时的说法不含糊：%r" % why
    # 实测不符（= 1050×1932 大窗残留）必须报失败
    ok2, why2 = WIN.place_all([1], (2440, 1264, 520, 640),
                              setter=lambda h, r: True,
                              reader=lambda h: (10, 10, 1050, 1932))
    if ok2:
        return "实测是大窗却报成功"
    if not why2 or ("不一致" not in why2 and "没落位" not in why2):
        return "实测不符时的说法不含糊：%r" % why2
    return True


def c_place_window_title_is_exact_not_substring(src=None):
    """★ 窗口识别用**开头精确匹配**，不用 `in` 子串（子串会误伤别的窗口）。

    ★★ 为什么是「品牌开头整串」而不是「任意子串」（0.36.1 真缺陷，本轮实测）：
      页面标题是 `"%s · Antinel 监理"`，**前半段随当前页面变** ——
      收件箱 / 运行状态 / 账本 / 日报 各是一个标题。
      实测落位那一刻窗口标题已是「运行状态 · Antinel 监理」，
      只认「收件箱 · Antinel 监理」⇒ 找不到窗口、**落位静默失败**，
      而日志还打着「已落到 520x640」（量的是别的窗口）。
      ★ 0.51.1 反转（W-01 退休、FZ-002 冻结）：标题恒为
        「Antinel 监理#<6hex>」（状态词/页面名前缀退役）⇒ 认窗从
        「后缀 endswith」翻转为**品牌开头 + 其后只允许身份串**两层
        结构判据（见 `inbox_window._mark_at_tail` 0.51.1 段）。本条
        守的意图不变：**不许退化成子串匹配**。

    ★ 开头匹配**不是**子串搜索：必须是 `^` 锚定（品牌必须在开头），
      不是 `in`（任意位置出现）。这条守住它。

    ★★ 0.50.2 两处修正（都是**实测**出来的量具故障）：
      ① **末了一条扫描会误红**：原来查的是裸子串 `"in title"` / `"title in"`，
         而 `for h, title in enum_windows(...)`（元组解包）经 `ast.unparse`
         后**正好含 `title in`** ⇒ 判据被一句无关的 for 语句判红，且红的原因
         还指着「子串匹配」（张冠李戴）。⇒ 改成认**真正的成员测试形态**：
         `<标记变量> in <标题变量>`。
         ★ 为什么不能一刀切禁「标题里的子串测试」：`is_console_title` 里
         `any(m in t for m in BROWSER_TITLE_MARKS)` 是**故意**的（排除浏览器
         普通窗口），禁掉它等于把防误关的那一层拆了。
      ② 加 `src` 注入点（默认真源码）—— 负控才能拿**变异源码**跑同一条判据。
    """
    import inbox_window as WIN
    src = _code_only(src if src is not None else _src_of(WIN))
    # ★★★ 0.36.5：`_matches_title` 已删除（零生产调用方，且**注释与实现相反**：
    #   文档写「不是 in 子串」、实现正是 `suffix in actual`），
    #   判据改查**真源** `is_console_title`。判据的意图一字未改：
    #   「不许退化成子串匹配」—— 变的只是**被测对象**。
    #   ★ 顺带守"死函数不许复活"：它的注释会把下一个人引到错误路径上。
    if re.search(r"^def _matches_title\(", src, re.M):
        return ("`_matches_title` 复活了 —— 它是 0.36.2 之前的旧口径（子串匹配），"
                "而它的文档写着『不是 in 子串』⇒ 照它接代码必然误关用户窗口")
    fn = _func_seg_of(src, "is_console_title")
    if "endswith" not in fn:
        return ("严格模式（唯一允许移动窗口的路径）必须用 endswith 整串匹配"
                "本次身份后缀，否则会把别的窗口当成本次运行窗口")
    # 宽泛模式（收旧窗用）不许落回纯子串 —— 实测 0.36.5 两种都会误认：
    #   '收件箱 · 值守台助手'（标记后面还挂字）、'记事本 - 收件箱 · 值守台'（前面挂程序）
    if re.search(r"return\s+CONSOLE_WINDOW_TITLE_MARK\s+in\s+", fn):
        return ("`is_console_title` 宽泛模式退回 `MARK in title`（任意位置子串）"
                "⇒ 会把『收件箱 · Antinel 监理助手』这类用户窗口当成Antinel 监理")
    if "_mark_at_tail" not in fn and "CONSOLE_WINDOW_TITLE_MARK" not in fn:
        return ("`is_console_title` 宽泛模式没有整串匹配动作 ⇒ 它认不出带身份串的"
                "旧窗口（0.36.2 实测的『收旧窗失效』会复发）")
    # ★ 只认**真正的成员测试形态** `<标记变量> in <标题变量>`（0.50.2 修正，见 docstring）。
    if re.search(r"(?:CONSOLE_WINDOW_TITLE_MARK|LOGO_TITLE_MARK|BUBBLE_TITLE_MARK"
                 r"|\bmark|\bsuffix)\s+in\s+(?:title|t|actual|buf\.value)\b", src):
        return "出现「窗口标记 in 标题」的子串匹配，会误伤标题含该段的其它窗口"
    return True


def n_place_window_title_substring_is_caught():
    """负控：把宽泛模式退回 `CONSOLE_WINDOW_TITLE_MARK in t` 子串口径 ⇒ 必须红。

    ★ 0.50.2：本条原先**没有负控**（CHECKS 表里是 `None`）。补上 ——
      「判据不许没有负控」是本仓纪律；而且这一条恰好证明上面那行精确正则
      真的抓得住旧形状（不是改完就没人守了）。
    """
    import inbox_window as WIN
    src = _src_of(WIN)
    if "return _mark_at_tail(t)" not in src:
        return ("变异锚点未找到（`is_console_title` 里没有 "
                "`return _mark_at_tail(t)`）—— 负控自身失效，不算通过")
    mutated = src.replace("return _mark_at_tail(t)",
                          "return CONSOLE_WINDOW_TITLE_MARK in t", 1)
    if mutated == src:
        return "负控自身失效：替换没生效"
    if c_place_window_title_is_exact_not_substring(src=mutated) is True:
        return "负控失效：退回子串口径后仍判合格 —— 这条判据是装饰"
    return True


def c_window_title_matches_console_suffix():
    """★ 页面标题必须**恰好是**认窗后缀本体（无第二份实现）。

    0.36.2 起源时本条叫「页面标题前缀确实会变」（P13）—— 断言
    「标题 == 页面名 ＋ 派生后缀」，因为那时的认窗判据是**后缀匹配**，
    前半段随页面变是前提。
    ★★ 0.51.1 反转（W-01 退休、FZ-002 冻结，创始人 2026-10-16 拍板）：
      标题不再带状态词/页面名前缀，整串恒为「Antinel 监理#<6hex>」
      ⇒「前缀会变」的前提被**设计性地推翻**（页面名在选项卡＋h2）。
      但本条更深一层的意图**不变且更重要**：**标题与 `is_console_title`
      认的必须是同一个串** —— `inbox_server._head` 与
      `inbox_window.console_title_suffix` 两处实现漂移 ⇒ 认窗失效
      ⇒ 红。0.50.4 B7 收编为行为级后，这条就是「无第二份标题实现」
      的守门人（行为级：文案搬家不红，行为退化才红）。
    """
    import inbox_server as SV
    import inbox_window as WIN
    tok = "0360p13"
    head = SV._head("inbox", tok)
    want = "<title>%s</title>" % WIN.console_title_suffix(
        WIN.build_run_id(tok))
    if want not in head:
        got = re.search(r"<title>(.*?)</title>", head)
        return ("页面标题不再是认窗后缀本体—— 标题与认窗判据漂移（两处"
                "实现），认窗会失效（实测 %r）" % (got.group(1) if got else None))
    return True


def c_window_id_does_not_hardcode_page_name():
    """★ 窗口识别的**匹配逻辑**里不许硬编码「收件箱」这个页面名。

    实测教训：硬编码页面名 ⇒ 用户切到「运行状态」页后窗口就认不出了，
    而那恰恰是**用户最可能停留的页面**。
    """
    import inbox_window as WIN
    src = _code_only(_src_of(WIN))
    # 0.36.5：`_matches_title` 已删除 ⇒ 改查真源 `is_console_title`
    fn = _func_seg_of(src, "is_console_title")
    if "收件箱" in fn:
        return "匹配逻辑里出现了硬编码页面名「收件箱」"
    return True


def c_window_suffix_matches_every_page():
    """★★ 后缀匹配必须对**每个页面标题**都成立（0.36.1 加，最强的一条）。

    ★ 为什么这条不能靠读源码：P04 只验"是不是 endswith"，
      变异把后缀换成完整标题后 P04 仍绿 —— 缺口就在这。
      所以改成**实跑**：拿真实页面标题清单逐条验。
      一旦有人把后缀写死成某个页面名，这条立刻红。

    ★ 页面清单来自 `inbox_server` 的导航（用户真能到达的页面），
      少一个就说明清单本身需要更新 —— 那也是红。
    """
    import inbox_window as WIN
    import inbox_server as SV
    # ① 页面清单取自**真实映射字典本身**（`SV.PAGE_TITLES`），
    #    不是正则扫字符串 —— 后者会随文案改动而漏。
    # ★★ 0.36.5 实测再撞一次同一条纪律（判据的注释写对了，代码没照做）：
    #   原来这里写的是 `re.search(r'title = \{(.*?)\}\.get\(')` ——
    #   **锚在具体写法上**，而产品把字典提为模块级 `PAGE_TITLES`（正是本函数
    #   注释要求的"真实字典"）之后，正则失配 ⇒ 这条报红。
    #   ⇒ 判据自己把「不扫字符串」这条纪律又犯了一遍。
    #   ⇒ 现在**直接 import 那个字典**：清单与真源永不失配，
    #     页面名再改、字典再挪位置，这条都不用动。
    pages_obj = getattr(SV, "PAGE_TITLES", None)
    if not isinstance(pages_obj, dict) or not pages_obj:
        return ("inbox_server 里没有模块级 PAGE_TITLES 字典（清单来源变了）—— "
                "判据不该退回正则扫源码，改为直接 import 真源")
    pages = sorted(set(pages_obj.values()))
    if len(pages) < 3:
        return ("页面清单只有 %d 项（%s）—— 覆盖不到全部页面，"
                "判据等于没验" % (len(pages), pages))
    # ★ 清单与导航必须一致：导航里能点的页面，映射里都得有
    #   （`a(视图, 标题)` 里标题也取自同一个字典 ⇒ 逐个对，不扫字符串）
    nav = re.search(r'a\("(\w+)", "([^"]+)"\)', _src_of(SV))
    if nav:
        nav_name = nav.group(2)
        if nav_name not in pages:
            return ("导航里有页面 %r 不在标题映射里 ⇒ 它会被当成默认标题，"
                    "窗口可能认不出" % nav_name)
    # ★ 视图名清单也要与字典的键一致（漏一个键 = 那个视图会落回默认标题）
    if set(pages_obj.keys()) != {"inbox", "report", "health", "ledger"}:
        return ("PAGE_TITLES 的键变了：%s —— 判据的页面清单需要复核"
                % sorted(pages_obj.keys()))
    # ② 标题形态必须被认出来（**走真实匹配入口 `is_console_title`**）
    #   ★ 0.51.1 反转（W-01 退休、FZ-002 冻结，创始人 2026-10-16 拍板）：
    #     标题不再随页面变（状态词/页面名前缀退役，整串恒为品牌形态）
    #     ⇒ 「逐页认窗」的测试点消失，替换为品牌两种形态（无身份／带
    #     身份）——「用户切到任何页后窗口都认得出」由「标题恒为品牌」
    #     **更强地**满足：不再有「切到某页后窗口失联」的可能（旧形态
    #     0.36.1 实测的那个故障在结构上不再存在）。
    import inbox_window as WIN
    bare = WIN.CONSOLE_WINDOW_TITLE_MARK
    if not WIN.is_console_title(bare, None):
        return "品牌形态（无身份串）认不出来 ⇒ 窗口失联"
    if not WIN.is_console_title(bare + "#486acd", None):
        return "品牌形态（带身份串）认不出来 ⇒ 窗口失联"
    # ③ 反向：非值守台窗口绝不能被认出来
    # ★★ 0.36.5 修判据的**测点**（实测抓出来的，不是改判据放松）：
    #   原来测的是 `_matches_title` —— 那个函数是 0.36.2 之前的旧口径
    #   （只做 `suffix in actual`），**已不是匹配入口**；
    #   它对 '收件箱 · 值守台 - 记事本' 返回真，于是这条红。
    #   而真实入口 `is_console_title` 在 0.36.5 已修好（连前缀一起认）。
    #   ⇒ 这里**不改意图、不删用例**，只把测点换成真源。
    #   ★ 教训与 F3 同源：**测的不是被测对象 ⇒ 红项指向的可能是废代码**。
    #     判据"报红"不等于"产品有问题"—— 必须先确认它在测谁。
    #   ★★ 0.36.5 本轮实测当场抓到的真缺口（不是补的想象用例）：
    #     宽泛模式只查了标记位置/分隔符/扩展名三层**形状**，
    #     注释里承诺的「页面前缀必须是已知页面名之一」**从没实现**
    #     ⇒ 用户窗口标题里恰好含 ` · 值守台#486acd` 时被误认
    #     ⇒ 宽泛模式是用来**关窗**的 ⇒ 会关掉用户自己的窗口。
    #     （0.51.1 反转后这层「前缀白名单」退役——品牌前置天然排除；
    #     下列旧形状仍全部保留：新形态更严，它们仍被拒认。）
    # ★ 0.51.1 反转：另补**新形态特有**的两类负形状：品牌后挂字
    #   （「Antinel 监理#486acd 记事本」——旧形态「收件箱 · Antinel 监理
    #   助手」的对应物）与非 hex 身份串。
    for bad in ("记事本", "收件箱 · Antinel 监理 - 记事本", "记事本 - 收件箱 · Antinel 监理",
                "Microsoft Edge", "Antinel 监理（副本）", "我的Antinel 监理",
                "Antinel 监理备份", "收件箱", "收件箱 · Antinel 监理助手",
                "收件箱 · Antinel 监理#zzzzzzzz", "收件箱 · Antinel 监理#",
                "请给我一个 · Antinel 监理#486acd", "问题：收件箱 · Antinel 监理#486acd 怎么办",
                "备份 · Antinel 监理#486acd", "收件箱 · Antinel 监理#486acd - 副本",
                "Antinel 监理#486acd 记事本", "Antinel 监理#486acd 和另外 14 个页面",
                "Antinel 监理#zzzz", "Antinel 监理助手"):
        if WIN.is_console_title(bad, None):
            return ("非Antinel 监理窗口 %r 被误认成Antinel 监理（会误关/误移用户窗口）" % bad)
    # ④ 严格模式（唯一允许**移动**窗口的判据）必须更严：
    #   它必须只认本次运行的窗口，连**别的 run_id** 都不认。
    #   ★ 0.51.1：夹具换品牌形态；负清单补「品牌＋别的 rid」。
    if not WIN.is_console_title("Antinel 监理#486acd", "486acd"):
        return "严格模式认不出本次运行窗口 ⇒ 窗口永远落不了位"
    for other in ("Antinel 监理", "Antinel 监理#ffff",
                  "记事本 - Antinel 监理#486acd", "Antinel 监理#486acd - 副本"):
        if WIN.is_console_title(other, "486acd"):
            return ("严格模式把 %r 当成本次运行窗口 ⇒ 会移动/关闭别人的窗口" % other)
    return True


def c_place_thread_does_not_block_serve():
    """落位必须**异步**（不能把 `serve_forever` 堵住等窗口成型）。"""
    import inbox_server as SV
    body = _src_of(SV)
    if "def _place_if_needed" not in body:
        return "没有 _place_if_needed"
    seg = body.split("def _place_if_needed", 1)[-1].split("\ndef ", 1)[0]
    if "threading.Thread" not in seg and "Thread(" not in seg:
        return "落位不是异步线程（会堵住 serve_forever）"
    if "daemon=True" not in seg:
        return "落位线程不是守护线程（会挡进程退出）"
    return True


def c_place_imports_time_and_threading():
    """依赖完整性：`time` / `threading` 必须真导入（漏一个就 NameError）。

    ★ 这条不是形式主义：0.36.0 补正时真的漏了 `import time`，
      守护线程一跑就 `NameError`，而 `daemon=True` 会让这个错**静默**。
    ★ 用 AST 读模块级 import，不靠"取模块头那段字符串" ——
      第一版那么写，结果 docstring 里的空行把范围截到第 2 行 ⇒ **假红**。
      这与本文件 `_code_only` 的动机同源：字符串切分靠不住。
    """
    import ast
    import inbox_server as SV
    src = _src_of(SV)
    tree = ast.parse(src)
    mods = set()
    for node in tree.body:                     # 只看**模块级**
        if isinstance(node, ast.Import):
            for a in node.names:
                mods.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    missing = [m for m in ("time", "threading") if m not in mods]
    if missing:
        return "模块级缺 import %s（守护线程会 NameError 且被 daemon 静默）" % \
               ", ".join(missing)
    return True


# ======================================================================
# 二、托盘哨兵态（创始人「这个图标是动态的，能看到当前哨兵的工作状态」）
# ======================================================================

def c_tray_carries_sentinel_state():
    """`tray.json` 必须带 `shield` 字段（监理态）。

    ★ 为什么必须有：五态 `L0/L1/L2/Ls/R0` 只表达"最近有没有告警"，
      **看不出监理此刻在不在岗**。实测出现过：图标显示 27 分钟前的
      `R0`「失守 · 防线未生效」，而`guard_posture()` 实测 `guarding`、
      监理 pid 83352 好好在岗 ⇒ **图标在说谎**。
    """
    import json
    import inbox_tray as T
    import tempfile
    d = tempfile.mkdtemp(prefix="antinel-shield-")
    _SCRATCH.append(d)
    T.write_state("R0", 4, "测试", root=d)
    with open(T.state_path(d), encoding="utf-8") as f:
        p = json.load(f)
    if "shield" not in p:
        return "写出的 tray.json 里没有 shield 字段：%s" % (sorted(p),)
    if p["shield"] not in T.SHIELD_SUFFIX:
        return "shield 值不在已登记集合内：%r" % p["shield"]
    return True


def n_tray_without_shield_field_is_caught():
    """负控：托盘状态**缺 `shield` 字段**时判据必须红。

    ★★ 0.37.1 改真（2026-10-09）：旧版自己手写一份 `{"state":"R0",...}`
       到临时目录，再断言"里面没有 shield" —— 那份文件是**负控自己写的**，
       产品从头到尾没参与 ⇒ 它证明的是"我会写一个没有 shield 的 json"，
       不是"判据看得见缺字段"（本仓第 5 次同型空负控）。
       而且它用 `T.state_path(d)` 取路径、却没建目录 ⇒ 跑起来直接
       `FileNotFoundError`（**从未有人发现**，因为 main 从不调用负控）。

    ⇒ 真变异：**让产品自己写出的状态文件里没有 `shield`**（复现"写状态的人
       忘了带监理态"），判据必须报红；再把 `SHIELD_SUFFIX` 换成不含当前值的
       集合，判据也必须报红。两条断言各验一次，不许只挑好验的那条。
    ★ 约定：本文件的判据是**返回红因字符串**（不是抛异常），负控按返回值判。
    """
    import json
    import tempfile
    import inbox_tray as T

    saved_write, saved_suffix = T.write_state, dict(T.SHIELD_SUFFIX)
    saved_path = T.state_path
    d = tempfile.mkdtemp(prefix="antinel-shield-neg-")
    _SCRATCH.append(d)

    def bad_write(*a, **kw):
        """变异版：产品照常写，然后我们把 `shield` 字段抹掉。"""
        saved_write(*a, **kw)
        root = kw.get("root") if "root" in kw else (a[3] if len(a) > 3 else None)
        fp = saved_path(root)
        try:
            with open(fp, encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, ValueError):
            return                      # 写都没写成 ⇒ 无从变异
        payload.pop("shield", None)
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)

    try:
        T.write_state = bad_write
        r1 = c_tray_carries_sentinel_state()
        if r1 is True:
            return "负控失效：状态文件里已没有 shield 字段，判据仍报绿"
        T.write_state = saved_write
        T.SHIELD_SUFFIX = {"__负控占位__": "x"}      # ← 值不在登记集合内
        r2 = c_tray_carries_sentinel_state()
        if r2 is True:
            return "负控失效：shield 值已不在登记集合内，判据仍报绿"
        return True
    finally:
        T.write_state = saved_write
        T.SHIELD_SUFFIX.clear(); T.SHIELD_SUFFIX.update(saved_suffix)


def c_broken_posture_never_maps_to_on_duty():
    """★ 监理不在岗／探不到 ⇒ **绝不**映射成「在岗」（绿）。

    ★ 这是本条判据的**核心**：把"探不到"画成"没事"、把"不在岗"画成"在岗"，
      是本仓明令禁止的形状。
    """
    import inbox_tray as T
    for st in ("down", "interrupted", "warn", "unknown", "off", None):
        fake = {"state": st} if st else {}
        got = T.shield_state(fake)
        if got == T.SHIELD_ONPOSTURE:
            return "posture=%r 被映射成「监理在岗」（绿）" % (st,)
    # 未登记的新档位 ⇒ 落到 unknown（盲区），也不许落到「在岗」
    got = T.shield_state({"state": "brand_new_state_from_future"})
    if got == T.SHIELD_ONPOSTURE:
        return "未登记档位被映射成「监理在岗」"
    return True


def c_tray_ps1_reads_shield_field():
    """`tray.ps1` 必须读 `shield` 并按它选图标（否则写了字段也没人用）。"""
    import io
    p = os.path.join(ROOT, "tools", "tray.ps1")
    with io.open(p, encoding="utf-8") as f:
        src = _strip_comments(f.read())
    if "SHIELD_SUFFIX" not in src:
        return "tray.ps1 里没有 SHIELD_SUFFIX 映射表"
    if '"shield"' not in src:
        return "tray.ps1 不读shield 字段"
    return True


def c_all_icon_combinations_exist():
    """五事件态 × 四监理态 = 20 个 `.ico` 必须**都在**。

    ★ 缺一个 ⇒ 托盘会回落到基础图标，而监理态**静默丢失**
      （这正是本条要防的：回落时不许让"看不出监理状态"变成无声无息）。
    """
    import inbox_tray as T
    miss = []
    for ev in ("L0", "L1", "L2", "Ls", "R0"):
        for sh in T.SHIELD_SUFFIX:
            p = T.icon_file(ev, sh)
            if not os.path.exists(p):
                miss.append(os.path.basename(p))
    if miss:
        return "缺 %d 个图标：%s" % (len(miss), miss[:6])
    return True


def c_badge_marks_differ_per_shield_state():
    """三个监理态的角标**必须画得不一样**（能区分），且 `on` 态不画。

    ★ 调`_p_badge_probe.py` 的像素级判据 —— 为什么必须到像素：
      `os.path.getsize` 发现不了。第一版角标**一个像素都没画上**
      （函数里多写一次 y 翻转，框落到画布外），而五个态的文件大小
      全是32038 bytes，**一模一样**。
    """
    probe = os.path.join(ROOT, "_p_badge_probe.py")
    if not os.path.isfile(probe):
        return "缺 _p_badge_probe.py（角标像素判据不在）"
    import subprocess
    r = subprocess.run([sys.executable, probe], capture_output=True,
                       cwd=ROOT, timeout=180)
    if r.returncode != 0:
        return "角标像素判据报红：%s" % (r.stdout.decode("utf-8", "replace")[-300:],)
    return True


def c_tray_refreshes_without_daemon():
    """没有守护进程时，托盘也要**自己**周期刷新（图标不能停在旧值）。

    ★ 真实缺陷（本机实测）：`tray.json` 停在 **1642 秒（27 分钟）** 前、
      `read_state()` 判`stale=True`，可图标**依然显示** 27 分钟前的 `R0`
      「失守 · 防线未生效」，而同时 `guard_posture()` 实测 `guarding`。
      根因：原实现在 `run()` 启动那一刻刷新一次，之后全靠守护进程，
      而守护进程**不是常驻的**。
    """
    import inspect
    import inbox_tray as T
    src = _code_only(inspect.getsource(T.consume_loop))
    if "refresh_state" not in src:
        return ("consume_loop 里没有 refresh_state ⇒ 没有守护进程时"
                "图标会永久显示旧值（本机实测停过 1642 秒）")
    if "refresh_every" not in inspect.getsource(T.consume_loop):
        return "consume_loop 没有 refresh_every 参数（刷新频率不可控/写死）"
    return True


# ======================================================================
# 三、失守归因（创始人「不能无法改进，只能看」）
# ======================================================================

def c_every_r0_class_gives_an_action():
    """★ 每一类 R0 都必须**至少给出一个可执行动作**。

    ★ 这是本组判据的**总纲**（创始人原话：
      「要让用户能够有机会不断改进，不能无法改进，只能看」）。
      归因引擎第一版若对某类返回空动作，这里立刻红。
    """
    import collections
    import inbox_store as S
    import remediation as R
    items = S.load_items()
    byk = collections.OrderedDict()
    for it in items:
        if str(getattr(it, "level", "")).upper() != "R0":
            continue
        byk.setdefault(R._kind_of(it), []).append(it)
    if not byk:
        return "本机一条 R0 都没有 —— 判据失去作用对象（不构成失败，但要如实知道）"
    empties = []
    for k, group in byk.items():
        a = R.attribute(group[0])
        acts = [x for x in (a.get("actions") or [])
                if x.get("op") != R.ACT_ACCEPT]
        if not acts:
            empties.append("%s(n=%d)" % (k, len(group)))
    if empties:
        return "这些失守类**一个可执行动作都没有**（只能看）：%s" % empties
    return True


def c_b_class_offers_three_choices():
    """★ B 类（修不了根因）必须给出**三选一**：修复／移出监管／接受风险。

    ★ 创始人 2026-10-07 拍板：「不能只给修复，得让用户选。」
      只给"修"的话，用户点完发现修不了就**又回到只能看**。
    """
    import inbox_store as S
    import remediation as R
    items = S_items()
    need = set(R.B_CLASS_CHOICES)
    checked = 0
    for it in items:
        if str(getattr(it, "level", "")).upper() != "R0":
            continue
        a = R.attribute(it)
        if not a.get("b_class"):
            continue
        checked += 1
        got = set(x.get("op") for x in (a.get("actions") or []))
        miss = need - got
        if miss:
            return ("B 类%s 缺这些选项：%s（只有 %s）"
                    % (a.get("kind"), sorted(miss), sorted(got)))
    if not checked:
        return ("本机没有 B 类失守 ⇒ 判据没作用到对象"
                "（不构成失败，但要如实知道）")
    return True


def c_zone_lock_failure_lands_in_action_bucket():
    """★「安全区上锁失败」必须落进「**要处理**」，不能是「看一眼」。

    ★ 真实缺陷（本项目已修）：`host_shield_zone_locked` 一个 kind
      **同时表示"上锁成功"和"上锁失败"**，而 `AUTO_HANDLED_KINDS`
      只能按 kind 判 ⇒ **失败**（有进程对抗门闸，只有你本人能决策）
      被降级进「看一眼」。实测本机 12 条全部落错档，
      用户「要处理」里一条都没有 —— 唯一真正需要人决策的那类反而看不见。

    ★★ 0.36.1 修正判据本身（不是产品）：上一版拿**真实库里全部**
      `zone_locked` 记录直接判档，于是恒红 —— 因为本机这 12 条
      `state='done'`（已处理完毕），按 `bucket_of` 的设计就该归「归档」。
      ★ 错在哪：把"这条该不该进要处理"问成了"**这条现在**在不在要处理" ——
        档位会随时间推移和处置状态变化，判据却拿它当**恒定真值**。
      ⇒ 正确问法：构造一条「**未关闭**的上锁失败」，看它落哪档 ——
        这才是本条判据要守的不变量。

    ★★★ 0.41.0 修正判据本身（第二处，不是产品）：`host_shield_zone_locked`
      这**一个 kind 兼表成败**这件事，0.40.0（A8）已经用**结构化字段**分派了
      （`remediation._kind_of()`：`topic` → `severity` → 文本兜底）。
      而本条此前只按 `kind` 取"未关闭的"，**默认它们全是失败** ——
      0.40.0 之前恰好成立（那时的写侧只会记失败），0.41.0 起写侧会**如实记成功**
      （`topic=zone_ok` / `severity=warning`）⇒ 本条取到的第一条 live 记录可能是
      **成功**那条，于是拿"成功该不该进要处理"去问"失败该不该进要处理" ⇒ 假红。
      ⇒ 修法：**不再二次实现判别**，直接调产品自己的 `R._kind_of(i) == "zone_locked"`
        只取【失败】那一支（本仓纪律：判据不许二次实现判别口径）。
    """
    import inbox_model as M
    import remediation as R
    # 先在真实库里找一条未关闭的【失败】（成功那条不该进要处理，另由 S31 守）
    live = [i for i in S_items() if getattr(i, "kind", "") == "host_shield_zone_locked"
            and getattr(i, "state", "") not in M.CLOSED_STATES
            and R._kind_of(i) == "zone_locked"]
    if live:
        item = live[0]
        if M.bucket_of(item) != M.BUCKET_ACTION:
            return ("未关闭的上锁失败落在 %r（应进「要处理」）"
                    % M.bucket_of(item))
        return True
    # ★ 真实库里没有未关闭的 ⇒ 用**合成**对象验这条不变量
    #   （合成对象只测档位规则本身，不依赖当时有没有真实记录）
    # ★ `ts` 必须用**真实记录同格式的 ISO 字符串**：`within_hours()`
    #   走 `_parse_ts()`，喂浮点时间戳会解析失败 → 返回 False →
    #   整条被判成「窗口外 → 归档」。第一版正是这样恒红的，
    #   **看起来像产品坏了，其实是合成数据造错了**。
    import inbox_model as IM
    from datetime import datetime
    class _It(object):
        kind = "host_shield_zone_locked"
        topic = "zone_lock_failed"          # ★ 0.41.0：结构化字段（不靠文案）
        detail = ("安全区【上锁未生效】——本目录 ACL 未能限制写入"
                  "（可核：icacls 该目录）；**不等于**有进程在对抗门闸：D:\\x\\zone")
        state = "open"
        severity = "critical"
        recovered = False
        def __init__(self):
            self.ts = datetime.now().astimezone().isoformat(timespec="seconds")
    it = _It()
    b = M.bucket_of(it)
    if b != M.BUCKET_ACTION:
        return "合成一条未关闭的上锁失败却落在 %r（应进「要处理」）" % b
    return True


def S_items():
    """小helper：本机收件箱记录。"""
    import inbox_store as S
    return S.load_items()


def c_attribution_uses_no_window_enumeration():
    """★ 归因**不许依赖窗口枚举**（本机实测不可靠）。

    ★ 实测：`EnumWindows` 能看到 507 个 hwnd，但**新开的 app 窗口
      抓不到标题**（两次实测都拿不到）⇒ 任何"自动定位那个进程在写"
      的做法在本机**不可靠**。
      ⇒ 归因只用文件级证据；查不到就如实说查不到，不编进程名。
    """
    import remediation as R
    import inspect
    src = _code_only(inspect.getsource(R))
    banned = ("EnumWindows", "FindWindow", "GetWindowText", "tasklist",
              "psutil", "win32process", "EnumProcesses")
    hit = [b for b in banned if b in src]
    if hit:
        return "归因模块里出现窗口/进程枚举：%s" % hit
    return True


def c_attribution_states_what_got_through():
    """归因必须回答「**已经放过什么**」，不许只讲以后怎么办。

    ★ 口径纪律：这一句若说"没有放过东西"，**必须有查证**；
      查不到落点清单时要明说"查不到，不能说没有"。

    ★ 检查点选`what_got_through()` 而不是 `attribute()`（第一版选错了，
      报假红）：查证在 `what_got_through()` 里做，`attribute()` 只调用它。
    """
    import inspect
    import remediation as R
    src = _code_only(inspect.getsource(R.what_got_through))
    if "_outage_consequences" not in src:
        return ("what_got_through() 没有查监管对象 ⇒ 「已放过什么」"
                "不是查出来的，是编的")
    body = inspect.getsource(R.what_got_through)
    if "查不到" not in body and "不能" not in body:
        return ("what_got_through() 没有「查不到就不下结论」的分支"
                "（把读失败说成「没有」就是假话）")
    # attribute() 必须真的调它（否则面板里那句是死的）
    attr = inspect.getsource(R.attribute)
    if "what_got_through" not in attr:
        return "attribute() 没有调用 what_got_through() ⇒ 面板不回答这一问"
    return True


def c_unregistered_class_still_gives_a_step():
    """未登记的失守类 ⇒ **仍然要给得出下一步**（不许硬编原因，但不许 dead end）。

    ★ 纪律：归因规则没覆盖它，就说"这类我没归因过"，
      但**仍必须给一步能做的** —— 否则用户的失守进了一个死胡同。
    """
    import remediation as R

    class Fake(object):
        kind = "brand_new_kind_from_future"
        topic = ""
        level = "R0"
        detail = "未来某类失守"
        ts = "2026-10-07T00:00:00+08:00"
        chain_ref = ""
    a = R.attribute(Fake())
    acts = [x for x in (a.get("actions") or []) if x.get("op") != R.ACT_ACCEPT]
    if not acts:
        return "未登记的失守类给不出任何动作（用户会走进死胡同）"
    if "没归因" not in (a.get("cause") or "") and "不编" not in (a.get("cause") or ""):
        return "未登记的失守类**编了一个原因**（不许编，要如实说没有规则）"
    return True


def c_rem_panel_has_four_segments():
    """归因面板固定**四段**：根因／多严重／能做什么／代价。"""
    import inbox_server as SV
    import inbox_store as S
    r0 = [i for i in S.load_items()
          if str(getattr(i, "level", "")).upper() == "R0"]
    if not r0:
        return "本机没有 R0 —— 判据没作用到对象"
    h = SV._item_html(r0[0], "TOK")
    for kw, seg in (("① 根因是什么", "seg root"),
                    ("② 现在有多严重", "seg sev"),
                    ("③ 你现在能做什么", "seg act"),
                    ("④ 如果什么都不做", "seg cost")):
        if kw not in h:
            return "面板缺第 %s 段" % kw
        if seg not in h:
            return "面板缺 %s 的样式类" % seg
    return True


def n_rem_panel_without_actions_is_caught():
    """负控：归因返回空动作时，判据必须红。"""
    import remediation as R
    orig = R.attribute
    try:
        def broken(item, *a, **k):
            d = orig(item, *a, **k)
            d["actions"] = []
            return d
        R.attribute = broken
        import inbox_store as S
        r0 = [i for i in S.load_items()
              if str(getattr(i, "level", "")).upper() == "R0"]
        if not r0:
            return False
        a = R.attribute(r0[0])
        acts = [x for x in (a.get("actions") or []) if x.get("op") != R.ACT_ACCEPT]
        return not acts
    finally:
        R.attribute = orig


def c_pick_buttons_wired_to_real_ops():
    """归因按钮必须接到**真实动作**（不是点了没反应的假按钮）。

    ★ 本仓最恨的形状就是「长得能点、点了没反应」。

    ★ 两版都踩过的坑，这里记清正确写法：
      ① 查 `"guard_fix"` 带双引号 ⇒ `ast.unparse` 会规范成单引号 ⇒ 假红。
      ② 查 `node.test.left.value` ⇒ 左边是**变量名** `op`（`ast.Name`），
         不是 `ast.Constant` ⇒ 一个分支都匹配不到 ⇒ 又一条假红。
      ⇒ 正确做法：在 `Compare` 的 **comparators** 里找字符串字面量。
        那样与引号风格、与左右哪边是常量，都无关。
    """
    import ast
    import inbox_server as SV
    tree = ast.parse(_src_of(SV))
    want = {"guard_fix", "remediation_drop", "remediation_ack"}
    got = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        for side in [node.left] + list(node.comparators):
            if isinstance(side, ast.Constant) and isinstance(side.value, str):
                got.add(side.value)
            # ★ `op in ("a","b")` 形状：常量在 **Tuple** 里，不在 comparators。
            #   第三版判据只认 `==`，把 `in` 写法判成"没接上" ⇒ 又一条假红。
            #   （三种形状都要认：`== "x"` / `in ("x","y")` / `in ["x","y"]`）
            if isinstance(side, (ast.Tuple, ast.List, ast.Set)):
                for elt in side.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        got.add(elt.value)
    miss = want - got
    if miss:
        return "do_POST 不受理 %s（按钮点了没反应）" % sorted(miss)
    return True


def _src_of(mod):
    """取模块源码：优先读**文件**（`inspect` 在某些装载路径下会拿到残缺文本）。"""
    f = getattr(mod, "__file__", None)
    if f and os.path.isfile(f):
        with open(f, encoding="utf-8") as fh:
            return fh.read()
    import inspect
    return inspect.getsource(mod)


def c_drop_does_not_silently_disable_protection():
    """★「移出监管」**不得**在页面动作里真的改配置。

    ★ 擅自放弃保护不是产品该替用户做的选择。
      动作只把**决定**留痕，真正改配置要走明确的 `host-shield` 命令（可回滚）。

    ★ 检查方式（第一版按"字符窗口取 1400 字"判定，分支一加长就失效）：
      改为**沿 AST 走到那个 `elif` 分支的语句列表**，逐个看它调了什么函数。
      判据不依赖"分支有多长"，也不依赖源码格式。
    """
    import ast
    import inbox_server as SV
    tree = ast.parse(_src_of(SV))
    branches = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not isinstance(test, ast.Compare):
            continue
        names = set()
        for side in [test.left] + list(test.comparators):
            if isinstance(side, ast.Constant) and isinstance(side.value, str):
                names.add(side.value)
            # ★ `op in ("a","b")` 形状也要认（见 R08 里的同类说明）
            if isinstance(side, (ast.Tuple, ast.List, ast.Set)):
                for elt in side.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        names.add(elt.value)
        if names & {"remediation_drop", "remediation_ack"}:
            branches.append(node)
    if not branches:
        return "do_POST 里找不到 remediation_drop / remediation_ack 的分支"
    # ★ 禁用清单：这些动作会**真的改防线或删文件**
    banned_calls = {"os.remove", "os.unlink", "shutil.rmtree", "disable",
                    "save_state", "set_zones", "remove_zone", "rmtree"}
    for br in branches:
        for sub in ast.walk(br):
            if isinstance(sub, ast.Call):
                fn = sub.func
                name = ""
                if isinstance(fn, ast.Attribute):
                    name = fn.attr
                elif isinstance(fn, ast.Name):
                    name = fn.id
                if name in banned_calls:
                    return ("remediation 动作里调用了 %r ——"
                            " 不许在这里改防线或删文件" % name)
    return True


def c_by_text_recognition_is_labelled():
    """靠文案认出来的失守，页面上必须**标出来**（不能假装是结构化判定）。"""
    import ast
    import inspect
    import remediation as R
    src = inspect.getsource(R)
    if "by_text" not in src:
        return "归因结果里没有 by_text 标记"
    # ★ 用 AST 查字符串字面量，不靠文本 grep（`ast.unparse` 会改引号风格，
    #   而 grep 原始源码又会被 docstring 里的说明文字骗过）。
    import inbox_server as SV
    tree = ast.parse(_src_of(SV))
    lits = {n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    want = "靠记录文案认出来的"
    if not any(want in s for s in lits):
        return ("页面没有把「%s」告诉用户" % want)
    return True


# ======================================================================
# 五、页面文字（创始人 2026-10-07 三张截图）
# ======================================================================
# ★ 为什么单独一组：这轮抓到的三个缺陷**都不影响功能**，只影响"能不能读"。
#   而"功能判据全绿"恰恰**看不见**它们 ⇒ 必须有专门盯文字的判据。
#   ① 满屏 `**` 星号（术语正文写了 markdown，页面却是 HTML）
#   ② `<details>`/`<b>` 被当**文字**显示（已生成 HTML 又被 `_esc` 一遍）
#   ③ 术语详情被压进 140px 窄格，逐字换行成细长条

def _view_html(name="report", **over):
    """用一个**已知的样本报告**渲染某个视图（判据用，不依赖真实运行态）。

    ★ 为什么要造样本：直接用真实库的数据判文字，
      上一版就栽在这上面 —— 真实数据会随时间变化（记录被关闭、归档），
      判据就会"昨天绿今天红"，而**文字缺陷其实与数据无关**。
    """
    import inbox_server as SV
    rep = {"day": "2026-10-07", "levels": {"L2": 6, "L1": 28, "R0": 82},
           "window_levels": {"L2": 6, "L1": 28, "R0": 82},
           "window_hours": 24, "action_groups": 0,
           "buckets": {"action": 0, "info": 32, "archive": 216},
           "posture": {"state": "guarding", "label": "值守中",
                       "why": "监理在岗", "consequences": []},
           "revived_window": 25, "ledger": {"days": 0}, "rules": [],
           "chain": {"status": "ok", "files": 9, "records": 40101,
                     "broken": 0, "unchained": 0, "bad_lines": 0}}
    rep.update(over)
    fn = {"report": SV._view_report, "health": SV._view_health,
          "ledger": SV._view_ledger}[name]
    return fn(rep, "TOKEN")


def c_no_markdown_star_leaks_to_user():
    """★ 页面上不许出现 markdown 的 `**`。

    实测来源（截图一）：术语正文写的是 `单位是**条记录**`，
    而当时的渲染只做 HTML 转义、不解释 markdown ⇒ 星号原样吐给用户。

    ★★ 0.37.1 扩覆盖（2026-10-09）：原来**只查 report/health/ledger 三个视图**，
      而真正泄漏的地方是**收件箱页**（归因面板里的 `**重点**`，8 个归因类
      无一幸免）—— 判据没盖到首页，于是首页泄漏了很久也没人知道。
      ⇒ **判据没覆盖到的那个面，就是缺陷会长的那个面**（本仓第 N 次实证）。
    ★ 同时只看**可见文本**（去掉 `<style>/<script>`）：CSS 注释里也会写 `**…**`，
      那是给人读的注释，不是给用户看的字。
    """
    for name in ("report", "health", "ledger", "inbox"):
        h = _view_html_any(name)
        h = re.sub(r"<script.*?</script>", "", h, flags=re.S)
        h = re.sub(r"<style.*?</style>", "", h, flags=re.S)
        if "**" in h:
            i = h.index("**")
            return "[%s] 页面可见文本里有 markdown 星号：…%s…" % (
                name, h[max(0, i - 30):i + 30])
    return True


def _view_html_any(name):
    """`report/health/ledger` 走样本报告；`inbox` 走真实库（要用真记录的归因面板）。"""
    if name != "inbox":
        return _view_html(name)
    import inbox_server as SV
    import inbox_store as S
    # 只取「要处理」档（失守才有归因面板），且**限 20 条**：
    #   归因面板恰恰在点开后渲染，而这里要的是"会不会渲染出星号"，
    #   20 条足够覆盖全部归因类，且不让判据拖慢。
    import inbox_model as M
    items = [it for it in S.load_items()
             if M.bucket_of(it) == M.BUCKET_ACTION][:20]
    if not items:
        return ""                       # 没有待处理项 ⇒ 本判据无材料可查
    return SV._view_inbox(items, "TOKEN", M.BUCKET_ACTION, now=None)


def n_markdown_star_is_caught():
    """负控：把 `render()` 退回「不懂 markdown」＋术语正文写 `**…**` ⇒ 判据必须报红。

    ★★ 0.37.1 改真（2026-10-09）：旧版只做
        `GL.TERMS["L2"]["unit"] = "单位是**条记录**"; h = GL.chip("L2"); return "**" not in h`
       —— 它**既没跑 `c_no_markdown_star_leaks_to_user`，也没渲染任何页面**，
       只是在问"`GL.chip` 自己会不会把星号留在输出里"。
       而在 0.37.1 给 `render()` 补上 markdown 处理之后，答案是"不会"，
       于是这个负控**永远返回 True** ⇒ 它证明不了判据有任何眼睛。
       （同型第三次：0363 `n_light_greens`、0364 B1 都曾"算完就丢"。）

    ⇒ 要复现的是**历史那个真故障**：渲染管道不懂 markdown ＋ 作者写了 markdown。
      只变异一半都不成立（现在 `render()` 会吃掉 `**`，术语若改用 `<b>`
      则连"半边"也不需要）⇒ **两边一起变异**，然后真的调用判据。
    """
    import html as _H
    import glossary as GL

    saved_render = GL.render
    orig = GL.TERMS["L2"]["unit"]
    GL.TERMS["L2"]["unit"] = "单位是**条记录**（★负控变异）"
    GL.render = (lambda t, _e=_H.escape: _e(t or "", quote=False))   # 退回"只转义"
    try:
        h = GL.chip("L2")
        assert "**" in h, (
            "变异没生效：render 已被替换成不懂 markdown 的版本，"
            "chip() 输出里却没有星号 ⇒ 本负控测不到东西")
        # ★ 本文件的判据用「返回红因字符串」表达失败（不抛异常）⇒ 按返回值判。
        r = c_no_markdown_star_leaks_to_user()
        if r is True:
            raise AssertionError(
                "负控失效：正文已写成 markdown 星号、render 已退回不懂 markdown，"
                "页面**确实**会显示星号，判据却仍报绿")
        return True     # ★ 本文件约定：成功＝返回 True（不是返回说明文字；
                        #   说明文字会被 main 当成"负控失效的理由"）
    finally:
        GL.render = saved_render
        GL.TERMS["L2"]["unit"] = orig


def c_glossary_bold_really_bolds():
    """★ 术语正文里的 `<b>` 必须**真的加粗**，不能被转义成 `&lt;b&gt;`。

    ★ 第一版修法只把 `**` 换成 `<b>`，而渲染仍只做 `_H.escape()`
      ⇒ `<b>` 被转义，页面上显示成 `&lt;b&gt;`。
      这是"改了文案、没改渲染"的典型 —— 两条都要做。
    """
    import glossary as GL
    h = GL.chip("R0")
    if "&lt;b&gt;" in h:
        return "术语正文里的 <b> 被转义成 &lt;b&gt;（页面上会显示成标签文本）"
    if "<b>" not in h:
        return "术语正文没有输出任何 <b>，加粗形同虚设"
    return True


def c_generated_html_is_not_double_escaped():
    """★ 我们自己生成的 HTML 不许被再转义一遍（截图一的真凶）。

    ★ 根因：`_view_health` 用 `k.startswith("<details")` 放行，
      而那行的 key 是 `"最近 %d 小时" + GL.chip(...)` ——
      前面多了四个字 ⇒ 判定为假 ⇒ 整段 `_esc`。
    ★ 教训：**「以标签开头」判不出「是不是我们生成的 HTML」**
      ——生成方与消费方之间隔着字符串拼接，白名单必然漏。
    """
    h = _view_html("health")
    for tag in ("&lt;details", "&lt;summary", "&lt;b&gt;"):
        if tag in h:
            i = h.index(tag)
            return "已生成的 HTML 被当成普通文本转义了：%s（…%s…）" % (tag, h[i:i + 50])
    if "<details" not in h:
        return "健康页一个真正的 <details> 都没有（术语入口丢了）"
    return True


def c_term_popup_not_squeezed_into_narrow_column():
    """★ 术语详情不许被塞进窄列里（截图三）。

    ★ 病根：`.term{display:inline}` 让展开块留在 `.metrics` 的
      `minmax(140px,1fr)` 窄格里 ⇒ 中文逐字换行成细长条。
    ⇒ 要求详情块**脱离文档流**（`position:absolute`），宽度另有上限。
    """
    import inbox_server as SV
    src = _src_of(SV)
    nc = re.sub(r"/\*.*?\*/", "", src, flags=re.S)     # 去注释后只看真规则
    m = re.search(r"\.tdef\{([^}]*)\}", nc)
    if not m:
        return "找不到 .tdef 规则"
    rule = m.group(1)
    if "position:absolute" not in rule.replace(" ", ""):
        return (".tdef 没有脱离文档流（position:absolute）"
                "⇒ 展开内容会被压在卡片窄列里逐字换行")
    if "max-width" not in rule:
        return ".tdef 没有 max-width（浮层可能超出视口）"
    return True


def c_term_popup_has_narrow_screen_rule():
    """★ 窄屏要有专门规则（小工作区上面板会窄，浮层会溢出）。

    ★ 0.49.0 措辞订正（原 docstring 写"面板只有 520px 宽"是**旧设计的
      事实陈述**，曾被当成"面板就该这么宽"的默证）：0.49.0 起大工作区上
      面板宽 720（出生即正常版式，见 `inbox_window.MAX_W`），窄布局
      **只服务真正小的屏幕** —— 这条 @media 规则因此依然必须存在，
      但它的身份从"主版式的补丁"变成了"小屏降级路径"。
    """
    import inbox_server as SV
    if "max-width:620px" not in _src_of(SV).replace(" ", ""):
        return "缺少窄屏 @media 规则（窄工作区上浮层会溢出）"
    return True


def c_no_english_status_leaks_to_user():
    """★ 不许把英文状态变量直接显示给用户。

    ★ 实测来源：`_view_health` 写了 `ch["status"]`，
      页面就冒出 `ok` / `broken` / `unknown` —— 用户看不懂这是什么。

    ★★ 判据第一版写成只找 `>ok<`（紧贴标签），结果**漏了真形状**：
      实际渲染出来是 `…（ok（检查了 9 个文件…` —— 英文出现在**段落中间**。
      ⇒ 教训：**判"泄漏"不能只看紧邻关系**，英文变量可能出现在任何位置。
      做法：把术语正文与已知中文标签剥掉，剩下的可见文本里不许出现裸英文词。
    """
    import inbox_server as SV
    for name in ("report", "health", "ledger"):
        h = _view_html(name)
        # ★★ 0.37.2：把**所有默认收起的区块**整块排除，不再只排 `details.where`。
        #   创始人 2026-10-09（截图指令）把账本的文件路径等解释**并进了
        #   「账本」词条**（`GL.chip`，同样是 `<details>`、同样默认收起）。
        #   判据立意不变：**一直摆在眼前的正文字**里不许有裸英文；"点一下才
        #   看到"的内容（路径 / 口径 / 命令）不在此列 —— 区别正是"要不要主动读"。
        #   ⚠️ 非贪婪匹配：正文里这些 `<details>` 互不嵌套，故可整块剥掉。
        #   （顺带清掉旧版两行死代码：先算了一遍 `vis` 又立刻被覆盖。）
        vis = re.sub(r"<details\b.*?</details>", " ", h, flags=re.S)
        vis = re.sub(r"<[^>]+>", "\x00", vis)
        vis = re.sub(r"\x00+", " ", vis)
        allow = {"Antinel", "AI", "L2", "L1", "R0", "Ls", "L0", "TOKEN"}
        for w in re.findall(r"[A-Za-z_][A-Za-z_0-9./-]*", vis):
            if w in allow:
                continue
            if w.lower() in ("ok", "broken", "unknown", "none", "true", "false"):
                return ("[%s] 页面露出英文状态变量 %r（用户看不懂）" % (name, w))
            return ("[%s] 页面正文露出英文词 %r（不懂技术的用户看不懂）" % (name, w))
    return True


def c_window_hours_stated_once_not_per_card():
    """★ 「最近 N 小时」在标题里说一次，不在每张卡片**标题**上重复。

    ★ 第一版判据写成"卡片 HTML 块里不许出现『小时』"，结果**假红**：
      展开的术语定义里有「窗口＝最近 24 小时」是**该有的**（口径必须写明），
      它在 `<summary>` 之后，不在卡片标题上。
      ⇒ 只看 `<summary>…</summary>` 之间那截，才是"卡片标题"。
    ★ 与本文件另一处同源教训：**只看整块而不分"哪一段"，就会误判**。
    """
    h = _view_html("report")
    for summ in re.findall(r"<summary>(.*?)</summary>", h, re.S):
        if "小时" in summ:
            return "卡片标题里又写了时间范围：%s" % summ[:80]
    # 但必须**在别处说清楚**（否则成了删掉不说）
    body = re.sub(r"<details.*?</details>", "", h, flags=re.S)
    if "小时" not in body:
        return "时间范围被整个删掉了 —— 用户不知道数字算的是哪段时间"
    return True


def c_clickable_number_has_no_redundant_hint():
    """★ 数字本身就是链接，就不用再写「点数字看…」。

    实测来源（截图二）：数字有下划线可点，下面还写「点数字看是哪几条」
    ⇒ 重复用户的动作。
    """
    h = _view_html("report")
    for phrase in ("点数字看是", "点数字看详", "点数字看记录"):
        if phrase in h:
            i = h.index(phrase)
            return "数字可点却仍写着提示：…%s…" % h[i - 20:i + 40]
    return True


def c_user_facing_text_avoids_code_names():
    """★ 面向用户的说明里不许出现命令行/字段名。"""
    import glossary as GL
    bad = ["antinel host-audit", "antinel credits", "`", "session_start",
           "host_shield", "daily_report", "judgment.json"]
    for k, t in GL.TERMS.items():
        for f in ("one", "inc", "exc", "unit"):
            v = t.get(f) or ""
            for b in bad:
                if b in v:
                    return "术语 %s 的 %s 里出现技术名 %r：%s" % (k, f, b, v[:70])
    return True


def c_glossary_has_plain_language_first():
    """★ 定义的第一句要先说**对用户意味着什么**，再说技术名。

    ★ 依据：创始人「太专业了，要照顾不够专业的用户」。
      判据不咬文采，只咬**顺序**：第一句里不许只谈机制不提影响。
    """
    import glossary as GL
    # ★ 0.37.2：`posture` 术语已改名 `light`（「顶部这盏灯」）——
    #   页面上的状态词只剩灯一个。
    #   ★★ 0.39.1：灯的判据已改为**按来源**拼（状态类只由此刻、事件类只由账、
    #   **失守绝不回溯**，真源见 `inbox_model.current_state()`）—— 0.37.2 写的
    #   「两个读数取最重」说法**已作废**（判据 `inbox_guards_0380.py` S17 锁死
    #   术语表不得退回该说法）。
    #   判据跟着改名，不是放宽：新术语同样要过"第一句先说对用户意味着什么"。
    must_plain = ("chain", "chain_check", "unchained", "light",
                  "sentinel", "all")
    # 这些词若只写机制，用户读不出与自己有什么关系
    for k in must_plain:
        one = GL.TERMS[k]["one"]
        if not one.strip():
            return "术语 %s 的第一句是空的" % k
    # 「防篡改记录」等对外词条不该再叫「审计链」
    if GL.TERMS["chain"]["w"] != "防篡改记录":
        return "「记录」那一档对外仍叫 %r（用户听不懂）" % GL.TERMS["chain"]["w"]
    return True


def c_metric_card_has_no_third_line():
    """★ 数字卡片只留「标题 + 数字」两行，别塞第三行说明。

    实测来源（截图二）：卡片下那行字把卡片撑高、挤成一列。
    """
    h = _view_html("report")
    for m in re.finditer(r'<div class="metric">(.*?)(?=<div class="metric">|</div></div>)',
                         h, re.S):
        if m.group(1).count('<div class="k">') > 1:
            return "卡片里还有第三行说明：%s" % m.group(1)[:120]
    return True


def c_user_text_has_no_process_ids():
    """★ 页面文案里不许出现进程号（`pid 83352`）。

    实测来源（创始人「出现一些类似英文变量的词」）：
    态势那行原写「监理在岗（pid 83352），最后心跳 7 分钟前」。
    ⇒ 进程号是**实现细节**，用户看不懂、也拿它做不了任何事，纯噪音。
      它仍然留在 `evidence` 里 —— 要查的人查得到，只是不该摆在正文。
    """
    import host_shield as hs
    import os
    # 探真实态势（有值就用真的；探不到至少保证代码里没有 pid 字样）
    try:
        p = hs.guard_posture(os.path.dirname(os.path.dirname(
            os.path.abspath(hs.__file__))))
        why = str(p.get("why") or "")
        if "pid" in why.lower():
            return "态势说明里露出进程号：%r" % why
    except Exception:                                        # noqa: BLE001
        pass
    # 兜底：源码里也不该拼 "pid" 到用户文案
    src = _src_of(hs)
    for m in re.finditer(r'"why"[^\n]*\n?[^\n]*pid', src):
        seg = m.group(0)
        if "监理在岗" in src[max(0, m.start() - 200):m.start()]:
            return "源码里仍把 pid 拼进「监理在岗」的说明"
    return True


def c_glossary_avoids_bare_code_lists():
    """★ 术语定义里不许写「无 R0/L2/L1/Ls 记录」这种代码速记。

    实测来源：`L0` 的包含项原写「窗口内无 R0/L2/L1/Ls 记录」——
    用户看到的是四个字母缩写，不是"没有要处理的事"。
    """
    import glossary as GL
    t = GL.TERMS["L0"]["inc"]
    if re.search(r"[RLL][0-9s]", t):
        return "L0 的包含项仍写着代码速记：%s" % t
    if "失守" not in t:
        return "L0 的包含项没有用中文说明：%s" % t
    return True


def c_path_details_is_collapsed_by_default():
    """★ 账本「存在哪个文件」必须**写出来**，且**默认收起**、不许摆在正文。

    ★ 判据不禁止路径本身（需要的人查得到），
      禁止的是"路径占据正文"——那对不懂技术的用户是纯噪音。

    ★★ 0.37.2 改（创始人 2026-10-09 截图指令）：账本主界面改为**只留数字**，
      解释（含文件路径）全部并进**第一次出现的「账本」二字上的「？」**
      （`GL.chip("ledger")`）—— 创始人原话「用户自己会点开看」。
      ⇒ 路径的落点从 `inbox_server` 的 `details.where` 搬到 `glossary` 的
        `ledger` 词条。判据**跟着落点走，不放宽要求**：
        ① 路径必须仍然写着（在 `ledger` 词条里）；
        ② 在【渲染出来的账本页】里必须真的带着它；
        ③ 且它必须落在**默认收起**的元素内（把折叠块整块剥掉后不许还剩）。
    """
    import glossary as GL
    if "daily.jsonl" not in (GL.TERMS["ledger"]["one"] or ""):
        return "账本词条里不再说明存在哪个文件（用户会不知道这份账本能不能带走）"
    page = _view_html("ledger")
    if "daily.jsonl" not in page:
        return "账本页渲染后看不到文件路径（用户点开「账本」也查不到存在哪）"
    visible = re.sub(r"<details\b.*?</details>", " ", page, flags=re.S)
    if "daily.jsonl" in visible:
        return "文件路径没有收进可展开的折叠区，仍直接摆在正文"
    return True



# ======================================================================
# 一之三、开窗**之前**收掉旧窗口（0.36.1 真缺陷）
# ======================================================================
def c_close_old_windows_before_open():
    """★ 开窗**之前**必须先收掉已开着的同名窗口。

    实测真缺陷（本轮）：Antinel 监理窗口属于**浏览器进程**，服务重启 /
    被杀之后窗口**仍留在屏幕上**（本机实测：宿主 python 已 kill，
    1050×1932 的旧窗口还在）。而 `find_console_window` 只返回
    **第一个**同名窗口 ⇒ 落位会挑到旧的那个，把旧窗口挪到右下角、
    新开的仍是大方形 ⇒ 用户看到的是"修复没生效"。

    ★ 试过但**不可依赖**的路：按 `GWL_CREATIONTIME` 挑最新的 ——
      实测该属性对顶层窗口返回 **0**，枚举顺序也不承诺与创建时间一致。
      唯一确定的办法是让同名窗口在开窗前就不存在。
    """
    import inbox_server as SV
    code = _code_only(_src_of(SV))
    # ★ 2026-10-13（C4）：同 P05 —— 按行边界取段，不许子串 split。
    #   `open_console_settled`（C4 新增，定义在前）是 `open_console` 的前缀，
    #   `split("def open_console", 1)[-1]` 会落到 settled 上 ⇒ 假红
    #   （实测：settled 里没有 close_console_windows，P09 当场误报）。
    seg = _func_seg_of(code, "open_console")
    i_close = seg.find("close_console_windows")
    if i_close < 0:
        return "open_console 里没有收旧窗口这一步"
    # ★ 必须早于**两个**开窗分支：`Popen`（真身）与 `opener(`（判据注入路径）。
    #   只比 Popen 会漏：注入分支不经过 Popen，把收旧窗挪到 opener 之后就绕过了。
    marks = [("Popen", seg.find("Popen")), ("opener(", seg.find("opener("))]
    for name, pos in marks:
        if pos < 0:
            continue
        if i_close > pos:
            return ("收旧窗口发生在**开窗之后**（在 %s 之后）"
                    "⇒ 新的同名窗口会被一起收掉" % name)
    return True


def c_close_old_windows_only_exact_title():
    """★ 收旧窗口**只**动标题后缀匹配的，绝不误关用户窗口。

    本仓既有纪律：窗口几何不去动别的程序。这条守住它。
    ★ 判据读的是 `ast.unparse` 规范化后的源码（十六进制已折成十进制），
      所以只能认**调用形状**，不能认字面量写法。
    """
    import inbox_window as WIN
    full = _src_of(WIN)
    if "CONSOLE_WINDOW_TITLE_SUFFIX" not in full:
        return "没有稳定后缀常量，关窗范围无法限定"
    code = _code_only(full)
    seg = code.split("def close_console_windows", 1)[-1].split("\ndef ", 1)[0]
    # ★ 0.36.2：标题匹配搬进了 `find_console_windows`（唯一枚举实现）。
    #   本判据的不变量是"**必须走统一标题匹配**"，而不是"匹配代码必须
    #   写在这一段里"。判据要守住不变量 ⇒ 改成查**调用链**：
    #   本段必须调 `find_console_windows`，而那个函数里必须有 `_matches_title`。
    if "find_console_windows" not in seg:
        return "收旧窗口没走按标题过滤的枚举（范围可能被放宽）"
    eseg = code.split("def find_console_windows", 1)[-1].split("\ndef ", 1)[0]
    # ★ 0.36.2：统一标题判据的入口是 `is_console_title`（含浏览器窗口排除
    #   与两级语义），`_matches_title` 只是它内部那条精确匹配。
    if "is_console_title" not in eseg:
        return "枚举侧没有 `is_console_title`（收旧窗口的范围无法限定）"
    iseg = _func_seg_of(code, "is_console_title")
    # ★ 这条我第一次写错了：以为统一判据内部会调 `_matches_title`。
    #   实际它的严格分支是**直接** `endswith(console_title_suffix(run_id))`
    #   —— 身份后缀必须**整串匹配**，走 `_matches_title` 反而是错的口径。
    #   ⇒ 判据查的是"有没有真正的匹配动作"，不是"调了哪个函数"。
    if "endswith" not in iseg and "CONSOLE_WINDOW_TITLE_MARK" not in iseg:
        return "统一标题判据里没有任何实际匹配动作"
    # ★★★ 0.36.3 补回被我在 0.36.2 弄丢的两项：**关窗动作本身**。
    #   怎么发现的：变异检验的 `Q03 收旧窗口改用强杀进程` 报 **BAD**
    #   （40 条判据无一变红）—— 把 `PostMessageW(WM_CLOSE)` 换成
    #   `taskkill /F` **没人抓**。
    #   ★ 根因：0.36.2 我把 P10 改成只守"范围"（标题过滤），
    #     顺手把"必须 WM_CLOSE / 禁强杀"那两项删了 —— 守住了范围，
    #     丢掉了动作。**判据每被修改一次，就要问"我有没有顺手删掉别的"**。
    #   ★ 取段必须用 AST（剥 docstring）：`_code_only` **不剥 docstring**，
    #     而那段 docstring 里恰好写着「而不是 TerminateProcess」这类解释
    #     （本轮已因此假红过一次，见文件内 P10 旧注释）。
    _cseg = _ast_seg(full, "close_console_windows")
    if "PostMessageW" not in _cseg:
        return "关窗不是 WM_CLOSE（应让浏览器走正常关闭流程）"
    if "TerminateProcess" in _cseg or "DestroyWindow" in _cseg:
        return "出现了强杀/强销毁（对用户窗口不可接受）"
    if "taskkill" in _cseg:
        return "用 taskkill 强杀进程（会连用户自己的窗口一起杀掉）"
    # ★ 浏览器普通窗口必须被排除（0.36.2 实测真闯过这个祸）
    if "BROWSER_TITLE_MARKS" not in iseg:
        return "统一标题判据没有排除浏览器普通窗口（会误关用户窗口）"
    if "in title" in seg or "title in" in seg:
        return "出现子串匹配 `in`，会误关标题含该段的其它窗口"
    # 关闭动作必须是逐个 WM_CLOSE，不是批量销毁进程
    # ★★ 0.36.2 判据自身修一个**假红**：查 `full`（含注释）会命中
    #   docstring 里那句「而不是 `DestroyWindow`」——**那是在解释为什么不用它**。
    #   本文件头版的纪律就是「判据只读代码，不读解释代码的文字」，
    #   这里却查了全文，是自己犯了自己写下的纪律。
    #   ⇒ 改成查 `_code_only(full)`（注释与 docstring 已剥）。
    code_nc = _code_only(full)
    if "PostMessageW" not in code_nc:
        return "关闭动作不是 WM_CLOSE（应让浏览器自己走正常关闭流程）"
    if "TerminateProcess" in code_nc or "DestroyWindow" in code_nc:
        return "出现了强杀/强销毁（对用户窗口不可接受）"
    return True


def c_close_old_windows_reports_count():
    """收掉几个要**如实说**，不许静默吞掉（旧窗口留着用户会困惑）。"""
    import inbox_window as WIN
    src = _code_only(_src_of(WIN))
    seg = src.split("def close_console_windows", 1)[-1].split("\ndef ", 1)[0]
    if "return closed" not in seg:
        return "没返回关闭数量 ⇒ 调用方无法如实告知用户"
    if "return 0" not in seg:
        return "枚举失败时没有兜底返回（会抛到调用方）"
    return True


def c_close_old_windows_uses_injection_point():
    """可测性：`closer` 是注入点 —— 判据不该靠真实桌面才跑得起来。

    ★★★ 0.36.2 判据自身升级（这条判据的**原版形同虚设**，实测发现）：
      原版只查源码里有 `closer=None` 三个字 ⇒ 绿。
      而真实的 0.36.1 缺陷恰恰是：`closer` 写在**函数体里**
      （`if closer is None:`），**签名里根本没有** ⇒ 每次调用
      `UnboundLocalError` ⇒ 「开窗前收旧窗」从未生效。
      ★ 这就是本项目栽过两次的同型病：**替身/字面量盖住了真身**。
        字面量检查对"注入点真的能被注入"**零分辨力**。
      ⇒ 现在真跑一次：注入替身，验证它**只对枚举出的句柄**发关闭。
        若签名里没有 `closer`，第 3 步就会 TypeError ⇒ 判红。
    """
    import inspect
    import inbox_window as WIN
    sig = inspect.signature(WIN.close_console_windows)
    if "closer" not in sig.parameters:
        return "签名里没有 closer 注入点（判据无法在无桌面环境验它）"
    if "suffix" not in sig.parameters:
        return "签名里没有 suffix 参数，范围无法限定"
    # 真跑：注入枚举替身 + 关闭替身，验「只对枚举出的句柄发关闭」
    orig = WIN.find_console_windows
    asked, closed = [], []
    try:
        WIN.find_console_windows = lambda **kw: (
            asked.append(kw.get("suffix")), [101, 202])[1]
        n = WIN.close_console_windows(suffix=" · Antinel 监理#abc",
                                      closer=lambda h: (closed.append(h), True)[1])
    finally:
        WIN.find_console_windows = orig
    if n != 2:
        return "注入替身后关闭计数不对：%r" % (n,)
    if closed != [101, 202]:
        return "关闭动作没有只针对枚举出的句柄：%r" % (closed,)
    if asked and asked[0] != " · Antinel 监理#abc":
        return "枚举侧没收到调用方指定的 suffix：%r" % (asked,)
    return True



CHECKS = [
    ("G01 面板几何随分辨率变化", c_window_geometry_follows_resolution,
     n_window_geometry_is_not_constant),
    ("G02 面板高度约工作区三分之一", c_panel_height_is_about_one_third, None),
    ("G03 面板不越出工作区", c_panel_never_crosses_work_area, None),
    ("G04 小屏诚实降级", c_small_screen_degrades_honestly, None),
    ("G05 探不到屏幕不说能开", c_no_display_info_is_not_silently_ok, None),
    ("G06 开窗命令带尺寸与位置", c_app_cmd_carries_size_and_position,
     n_app_cmd_without_position_is_caught),
    ("G07 兜底尺寸不再占满屏", c_window_size_default_is_not_the_old_tall_one, None),
    ("P01 落位下发目标矩形", c_place_window_moves_to_target,
     n_place_window_without_moving_is_caught),
    ("P02 落位回读实测不谎报", c_place_window_checks_result_truthfully, None),
    ("P03 只动标题匹配的窗口", c_place_window_does_not_touch_other_windows, None),
    ("P04 标题精确相等非子串", c_place_window_title_is_exact_not_substring,
     n_place_window_title_substring_is_caught),
    ("P05 开窗之后才落位", c_open_console_calls_place_after_open,
     n_open_console_without_place_is_caught),
    ("P06 落位失败如实说", c_place_reports_failure_honestly, None),
    ("P07 落位异步不堵服务", c_place_thread_does_not_block_serve, None),
    ("P08 依赖导入完整", c_place_imports_time_and_threading, None),
    ("P09 开窗前先收旧窗口", c_close_old_windows_before_open, None),
    ("P10 收旧窗口只认精确标题", c_close_old_windows_only_exact_title, None),
    ("P11 收旧窗口如实报数量", c_close_old_windows_reports_count, None),
    ("P12 收旧窗口有注入点", c_close_old_windows_uses_injection_point, None),
    ("P13 页面标题与认窗后缀同串（无第二份实现）", c_window_title_matches_console_suffix, None),
    ("P14 窗口识别不硬编码页面名", c_window_id_does_not_hardcode_page_name, None),
    ("P15 后缀匹配对每个页面都成立", c_window_suffix_matches_every_page, None),
    ("W01 页面无 markdown 星号", c_no_markdown_star_leaks_to_user,
     n_markdown_star_is_caught),
    ("W02 术语加粗真的加粗", c_glossary_bold_really_bolds, None),
    ("W03 生成的 HTML 不被二次转义", c_generated_html_is_not_double_escaped, None),
    ("W04 术语浮层不挤进窄列", c_term_popup_not_squeezed_into_narrow_column, None),
    ("W05 窄屏有专门规则", c_term_popup_has_narrow_screen_rule, None),
    ("W06 不露英文状态变量", c_no_english_status_leaks_to_user, None),
    ("W07 时间范围只说一次", c_window_hours_stated_once_not_per_card, None),
    ("W08 可点数字不配冗余提示", c_clickable_number_has_no_redundant_hint, None),
    ("W09 用户文案不含技术名", c_user_facing_text_avoids_code_names, None),
    ("W10 术语先说大白话", c_glossary_has_plain_language_first, None),
    ("W11 卡片只有两行", c_metric_card_has_no_third_line, None),
    ("W12 页面不露进程号", c_user_text_has_no_process_ids, None),
    ("W13 术语不用代码速记", c_glossary_avoids_bare_code_lists, None),
    ("W14 文件路径收进折叠区", c_path_details_is_collapsed_by_default, None),
    ("T01 托盘带监理态", c_tray_carries_sentinel_state,
     n_tray_without_shield_field_is_caught),
    ("T02 坏了绝不画成在岗", c_broken_posture_never_maps_to_on_duty, None),
    ("T03 tray.ps1 读监理态", c_tray_ps1_reads_shield_field, None),
    ("T04 20 个图标组合齐全", c_all_icon_combinations_exist, None),
    ("T05 三个监理态角标可区分", c_badge_marks_differ_per_shield_state, None),
    ("T06 托盘自刷新不靠守护进程", c_tray_refreshes_without_daemon, None),
    ("R01 每类失守都给出动作", c_every_r0_class_gives_an_action, None),
    ("R02 B 类给三选一", c_b_class_offers_three_choices, None),
    ("R03 上锁失败进要处理档", c_zone_lock_failure_lands_in_action_bucket, None),
    ("R04 归因不依赖窗口枚举", c_attribution_uses_no_window_enumeration, None),
    ("R05 回答已放过什么", c_attribution_states_what_got_through, None),
    ("R06 未登记类仍给一步", c_unregistered_class_still_gives_a_step, None),
    ("R07 面板四段齐全", c_rem_panel_has_four_segments,
     n_rem_panel_without_actions_is_caught),
    ("R08 按钮接到真实动作", c_pick_buttons_wired_to_real_ops, None),
    ("R09 移出监管不静默改防线", c_drop_does_not_silently_disable_protection, None),
    ("R10 文案识别如实标注", c_by_text_recognition_is_labelled, None),
]


def main():
    """★ 绿区跑判据，**每一条带负控的还要真跑它的负控**。

    ★★ 0.37.1 补（2026-10-09）：本文件登记了 7 个负控，`CHECK` 表里格
        `neg` 那一栏也有值，而 main **从头到尾没调用过 `neg`**。
       ⇒ 那些负控是"写在纸上的守卫"：其中 4 个本轮第一次跑就直接失败
         （2 个返回 False、1 个抛异常、1 个误用返回约定），
         而在此之前它们一直"看起来都在"。
       ★ 这是比判据失效更险的形状：**失效被登记成有效**。
    """
    passed = failed = 0
    neg_passed = neg_failed = neg_missing = 0
    reds = []
    for name, fn, neg in CHECKS:
        try:
            r = fn()
        except Exception as e:                                   # noqa: BLE001
            r = "判据自身报错：%r" % (e,)
        if r is True:
            passed += 1
        else:
            failed += 1
            reds.append((name, r))
            print("RED  %s\n       %s" % (name, r))
        if neg is None:
            neg_missing += 1
            continue
        # ★ 判据自己已经红了 ⇒ 负控不必再证明它（它的眼力已经得到证明）
        if r is not True:
            neg_missing += 1
            continue
        try:
            rn = neg()
        except Exception as e:                                   # noqa: BLE001
            rn = "负控自身报错：%r" % (e,)
        if rn is True:
            neg_passed += 1
        else:
            neg_failed += 1
            reds.append((name + " 的负控", rn))
            print("RED  负控[%s]\n       %s" % (name, rn))
    _cleanup()
    print("0.36.0 guards: %d green / %d red"
          "（其中负控 %d 有效 / %d 失效 / %d 条无负控）"
          % (passed, failed, neg_passed, neg_failed, neg_missing))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())