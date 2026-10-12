# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""值守台 · 窗口几何（**唯一实现**：尺寸与位置在这里算，别处不二次实现）。

★ 为什么单独一个模块（创始人 2026-10-07「窗口太高了，别占屏幕太大面积」）：
  原来尺寸写死在 `inbox_server.WINDOW_SIZE = "1024,720"`，**没有位置**。
  实测本机后果：开出来的窗口 **1050×1932、位置 (10,10)** ——
  高度占工作区（1952）的**99%**、占屏幕面积的**16%**，
  而主工作区（WorkBuddy 2337×1887、Edge 1681×1709）就在它右边 ⇒
  哨兵占了舞台中央，把真正干活的界面挤掉了。
  ⇒ 这不是"美观问题"，是**功能与主业抢位置**。

★ 三条设计纪律：

  ① **绝不写死绝对坐标。** 一切从**工作区**（work area）实算 ——
     工作区已经把任务栏/侧边栏排除掉了。本机实测：屏幕 3000×2000、
     工作区 3000×1952（底部任务栏 48px）。

  ② **高度取工作区的 1/3（设上限）**，而不是"屏幕高度的 1/3"——
     分母必须是**用户真正能看见并使用的**那块面积。
     公式：`h = min(640, work_h * 0.33)`；`w = min(520, work_w * 0.34)`。
     在 3000×1952 上 ⇒ 640×520，正好是工作区高度的 33%。

  ③ **屏幕放不下就如实说，不硬挤。** 工作区小于 `MIN_WORK_W × MIN_WORK_H`
     时**不开面板**，只留托盘图标，并说清为什么 —— 硬挤出来的窗口
     会盖住任务栏、点不到关闭按钮，那是"给不了就用"的形状。

★ 为什么不用 pyautogui / pygetwindow：产品仓零运行时依赖（见 `inbox_tray`
  的既定纪律）；窗口几何只需要 `user32` 的系统指标，用 `ctypes` 足够。

★★ 0.36.0 补正（本模块原文档里写错了一条实测结论，害得开窗参数失效）：
  原文写「实测 `EnumWindows` **新开的 app 窗口抓不到标题** ⇒ 不做自动避让」。
  **这条结论是错的**：2026-10-07 复测，app 窗口标题稳定可读
  （`收件箱 · 值守台`，类名 `Chrome_WidgetWin_1`），枚举 3 次全部命中。
  ★ 错在哪：当时是**先枚举、后开窗**，还没开出来的窗口当然枚举不到 ——
    把"我枚举的那一刻它还不存在"当成"它不可枚举"。
    ⇒ 教训与本仓同型病一致：**"查不出来" ≠ "查出来是没有"**。
  ★ 但**「自动避开已有窗口」仍然不做** —— 那条结论**与抓不抓得到标题无关**：
    避让要判定"那块地方是不是用户的编辑器"，而判定依据只能是猜
    （按类名猜？按标题猜？），猜错就把面板推到用户找不到的地方。
    保留的规则仍是**工作区 + 右下角**：简单、可预测、不会自己乱跑。
  ★ 真正被这条错结论耽误的是另一件事：**开窗后没有落位兜底**（见 `place_window`）。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as w
import os
import re
import time

# --- 面板尺寸的**上限**（逻辑像素）。实际值还要被工作区比例再压一道 ---
MAX_W = 520
MAX_H = 640

#: 工作区占可用比例（分母＝**工作区**，不是屏幕）
WORK_W_RATIO = 0.34
WORK_H_RATIO = 0.33

#: 边距：右 40、下 48。★ 下边距必须 ≥ 任务栏高度，否则面板压住任务栏。
MARGIN_R = 40
MARGIN_B = 48

#: 小到这个程度就不开面板了（面板会盖满整屏、点不到关闭）
MIN_WORK_W = 480
MIN_WORK_H = 360

#: 位置选择的锚点。★ "右下"是**约定**不是搜索：右下角是主工作区之外的
#: 那一块（IDE/终端的视线终点都在左中区域），且紧邻任务栏托盘 ——
#: 图标与面板同处一地，认知成本最低。
ANCHOR = "bottom-right"


class WorkArea:
    """一块可用显示区域（逻辑像素）。`primary` 表示它是不是主屏。"""

    __slots__ = ("left", "top", "right", "bottom", "primary")

    def __init__(self, left, top, right, bottom, primary=True):
        self.left = int(left)
        self.top = int(top)
        self.right = int(right)
        self.bottom = int(bottom)
        self.primary = bool(primary)

    @property
    def w(self):
        return self.right - self.left

    @property
    def h(self):
        return self.bottom - self.top

    def as_tuple(self):
        """`(left, top, w, h)` —— **和 Win32 `RECT` 一样都是逻辑像素**。"""
        return (self.left, self.top, self.w, self.h)

    def contains(self, x, y):
        return self.left <= x < self.right and self.top <= y < self.bottom

    def __repr__(self):                                    # pragma: no cover
        return "WorkArea(%d,%d,%d,%d primary=%s)" % (
            self.left, self.top, self.right, self.bottom, self.primary)


def primary_work_area():
    """主屏工作区（**已排除任务栏**）。取不到 ⇒ 返回 `None`，**不假装知道**。

    ★ 用 `SPI_GETWORKAREA` 而不是 `GetSystemMetrics` —— 后者给的是**整屏**，
      任务栏也在里面。实测两者差 48px（2000 vs 1952），差别正好是任务栏。
    """
    if os_name() != "nt":
        return None
    try:
        u = ctypes.windll.user32
        # 让本进程按物理像素算，跨 DPI 缩放的机器上比例才准
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)   # PER_MONITOR_AWARE
        except Exception:                                       # noqa: BLE001
            try:
                u.SetProcessDPIAware()
            except Exception:                                   # noqa: BLE001
                pass
        r = w.RECT()
        SPI_GETWORKAREA = 0x0030
        ok = u.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(r), 0)
        if not ok:
            return None
        return WorkArea(r.left, r.top, r.right, r.bottom, primary=True)
    except Exception:                                       # noqa: BLE001
        return None


def work_areas():
    """全部显示器的工作区；一个都取不到 ⇒ 空列表。"""
    if os_name() != "nt":
        return []
    try:
        u = ctypes.windll.user32
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:                                       # noqa: BLE001
            pass

        class MONITORINFO(ctypes.Structure):
            _fields_ = [("cbSize", w.DWORD), ("rcMonitor", w.RECT),
                        ("rcWork", w.RECT), ("dwFlags", w.DWORD)]

        CB = ctypes.WINFUNCTYPE(w.BOOL, w.HMONITOR, w.HDC, ctypes.c_void_p)
        found = []

        def cb(hmon, _hdc, _lp):
            mi = MONITORINFO()
            mi.cbSize = ctypes.sizeof(mi)
            if u.GetMonitorInfoW(hmon, ctypes.byref(mi)):
                found.append(WorkArea(mi.rcWork.left, mi.rcWork.top,
                                       mi.rcWork.right, mi.rcWork.bottom,
                                       primary=bool(mi.dwFlags & 2)))
            return True

        u.EnumDisplayMonitors(None, None, CB(cb), None)
        return found
    except Exception:                                       # noqa: BLE001
        return []


def os_name():
    import os
    return os.name


def pick_work_area(areas=None):
    """挑一块显示区域：显式给了就用它；否则**优先主屏**；都没有就现取主屏。

    ★ 不做"挑最大的那块"或"挑离鼠标最近的那块" —— 那些是猜。
      规则只有一条：**主屏优先**，用户要换就显式指定。
    """
    if areas is None:
        areas = work_areas()
    if not areas:
        return None
    for a in areas:
        if a.primary:
            return a
    return areas[0]


def panel_size(work):
    """面板尺寸 `(w, h)` —— **按工作区比例算，且不超上限**。

    ★ 不做"至少多少像素"的兜底下限：屏幕上已经没有那么多可用地方时，
      硬撑出一个下限尺寸只会盖住任务栏。放弃开面板比硬挤好。
    """
    if work is None:
        return (0, 0)
    return (min(MAX_W, int(work.w * WORK_W_RATIO)),
            min(MAX_H, int(work.h * WORK_H_RATIO)))


def fits(work):
    """这块区域还够开面板吗？不够 ⇒ 返回 `(False, 一句人话)`。

    ★ 返回**为什么**不够，而不只是 `False` —— 调用方要把它说给用户听。
      「查不到屏幕尺寸」与「屏幕太小」是两件事，混成一句就成了假话。
    """
    if work is None:
        return False, "查不到这块屏幕的工作区尺寸（探不到显示设置），不开面板。"
    if work.w < MIN_WORK_W or work.h < MIN_WORK_H:
        return False, ("这块屏幕可用区域只有 %d×%d（%d×%d 以下就不开面板了，"
                       "否则会盖住任务栏、点不到关闭按钮）"
                       % (work.w, work.h, MIN_WORK_W, MIN_WORK_H))
    return True, ""


def panel_rect(work, size=None):
    """面板矩形 `(left, top, w, h)` —— 右下角，留右边距与下边距。

    ★ 下边距 `MARGIN_B` 的意义：保证底边**不超过**工作区下沿，
      也就是**永远压不到任务栏**。实测任务栏在底部 48px，故 48。
    """
    if work is None:
        return None
    pw, ph = size or panel_size(work)
    x = work.right - pw - MARGIN_R
    y = work.bottom - ph - MARGIN_B
    # 右边距过大导致跑出左边界时，**贴左边**而不是开成负坐标窗口
    if x < work.left:
        x = work.left
    if y < work.top:
        y = work.top
    return (x, y, pw, ph)


def window_size_str(rect):
    """`"--window-size=W,H"`（不含 `--window-size=` 前缀）。"""
    if rect is None:
        return "%d,%d" % (MAX_W, MAX_H)
    return "%d,%d" % (rect[2], rect[3])


def window_position_str(rect):
    """`"--window-position=X,Y"`（不含前缀）。"""
    if rect is None:
        return "0,0"
    return "%d,%d" % (rect[0], rect[1])


def console_geometry(areas=None):
    """一站式：**能不能开** + 该开多大 + 开在哪。

    返回 dict：
      `ok`      bool —— 该不该开面板
      `reason`  str  —— 不能开时，**为什么**（人话）
      `rect`    `(l,t,w,h)` 或 None
      `work`    用了哪块区域（诊断用）
    ★ 这是给 `inbox_server` 用的**唯一入口**；别处不自己算一遍。
    """
    work = pick_work_area(areas)
    ok, reason = fits(work)
    if not ok:
        return {"ok": False, "reason": reason, "rect": None, "work": work}
    size = panel_size(work)
    rect = panel_rect(work, size)
    # 二次保险：算完再看一眼是否真的落在工作区内，**不越界**
    if rect is None or not _inside(work, rect):
        return {"ok": False,
                "reason": ("按工作区算出来的位置会越出可用区域"
                           "（工作区 %d×%d，面板 %d×%d），不开面板。"
                           % (work.w, work.h, rect[2] if rect else 0,
                              rect[3] if rect else 0)),
                "rect": None, "work": work}
    return {"ok": True, "reason": "", "rect": rect, "work": work}


# ── 0.36.4：值守台的**专属浏览器身份**（治"窗口几何从一开始就不受控"这个根）──
# ★★★★ 创始人 2026-10-07：「落位失败就关窗，不是彻底的解决办法，
#     好好想想，拿出真正的根治方法。」
#
# ★ 先说清 0.36.0–0.36.3 为什么是**补丁**而不是根治（实测复盘）：
#   那三轮的思路都是「事后把窗口搬到该在的位置」：
#     0.36.0 加落位 → 0.36.2 修认错窗口/只挪第一个 → 0.36.3 落位失败就关窗。
#   每一轮都在**同一个前置条件失效**的前提下打补丁：只要 app 窗口是
#   **用户的 Edge 复用旧进程**开出来的，浏览器就**不认命令行上的几何参数**。
#   实测（本机，E3）：复用用户实例时给足 `--window-size=520,640
#   --window-position=2440,1264`，窗口仍然开成 **1050×1932 @(10,10)**
#   —— 参数被**完全忽略**，dx/dy/dw/dh 全错。
#   ⇒ 于是落位成了**唯一救命稻草**，而救命稻草必须有兜底 ⇒ 有了「关窗」。
#   ⇒ **关窗是补丁链的必然产物，不是设计选择。** 只要前置条件还在，就得有兜底；
#     兜底的代价就是「用户正在看的面板被杀掉」。
#
# ★★ 根治 = **换掉那个前置条件**（实测 E1/E2/E4/E5）：
#   给值守台一个**自己的** `--user-data-dir`，它就成了**独立浏览器进程**：
#     · E1 独立 profile 首次冷启动 ⇒ 520×640 @(2440,1264)，Δ 全 **0**
#     · E2 同一 profile 第二次（该 profile 进程已在跑）⇒ 仍然 **Δ 全 0**
#       ★ 这一条最关键：说明**不是**"必须冷启动"才生效，而是
#         "**这个 profile 的进程是自己的**"就生效 ⇒ 重复开窗不会退化。
#     · E4 全新 profile 且**不加** `--no-first-run` ⇒ 仍然 **Δ 全 0**，
#       且未出现任何额外可见窗口（实测「同标记的其它可见窗口: 无」）。
#     · E5 稳定 profile 连开 3 次 ⇒ **3/3 Δ 全 0**，不退化。
#     · E7 关窗后该 profile 的浏览器进程**完全回落**（实测 Δ=+0，
#       不残留一堆后台浏览器）。
#   ⇒ 命令行几何**从"请求"变成了"事实"**：
#     窗口**一出生**就在 520×640 @(2440,1264)，**不需要任何人去搬它**。
#
# ★★ 于是三层职责彻底分开（0.36.4 的结构）：
#     · 独立 profile  ⇒ **主路径**：窗口出生即正确。
#     · 落位（`place_all`）⇒ **兜底复核**：出生没对齐才搬，且逐个回读校验。
#     · 关窗 ⇒ **只用于「收旧窗」**（服务重启后的残留窗口），
#       **不再是落位失败的兜底**（见 `close_window` 的 0.36.4 改写）。
#   ⇒ 结果：正常路径**一次 SetWindowPos 都不发**，用户面板永远不会被杀。
#
# ★ 为什么这个方向是"根治"而不是又一层补丁（判据）：
#   补丁的共同特征是**在失效的前置条件之后补救**；根治的共同特征是
#   **让前置条件不再失效**。这里前置条件是「窗口由谁开的」，
#   它由我们决定 ⇒ 属于可根治的那一类。
#
# ★★ 为什么这个 profile 必须放在**用户数据目录**、不能放包目录（实测踩过）：
#   ① 包目录在**升级时会被整体替换** ⇒ profile 会被清掉，每次开窗退回冷启动；
#   ② 包目录进 `manifest.json` 的校验范围（实测 `psl/manifest.json` 有 101 项）
#      ⇒ 往里写运行期数据会**让自检永远不符** ⇒ 界面长期挂「存疑」。
#   ⇒ 落点：Windows 用 `%LOCALAPPDATA%\Antinel\console-browser`
#     （与本仓既有约定一致，见 `host_shield.py:2133` 用 `%APPDATA%` 的做法）。
#   ⇒ **目录不存在就创建**（第一次开窗会建），但**每次开窗都用同一个**（E5 证稳定）。


def console_profile_dir(create=True):
    """值守台**专属**浏览器 profile 目录（**唯一真源**，`inbox_server` 只问这里）。

    返回目录路径字符串；取不到合适位置时返回 `None` ⇒ 调用方**如实降级**
    （退回"复用用户实例 + 落位兜底"这条老路），**不假装拿到了独立 profile**。

    ★ 命名带 `console-` 前缀的理由：一眼能看出这是值守台自己的浏览器身份，
      不会和用户日常浏览混在一起（`agentstate`／`Antinel` 这类名字撞车风险高）。
    """
    try:
        if os_name() != "nt":
            return None
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            return None
        d = os.path.join(base, "Antinel", "console-browser")
        if create:
            os.makedirs(d, exist_ok=True)
        return d if os.path.isdir(d) else None
    except Exception:                                       # noqa: BLE001
        return None


#: 独立 profile 下**必须**加的开关（否则首次运行会弹流程、挡住窗口成型）。
#: ★ 实测 E4：即使**不加** `--no-first-run` 几何也精确，且无额外可见窗口；
#:   但那一次的首见耗时 1.86s vs 加了之后的 1.07–1.40s ⇒ **加上更快更稳**。
CONSOLE_PROFILE_FLAGS = ("--no-first-run", "--no-default-browser-check")



def _inside(work, rect):
    l, t, ww, hh = rect
    return (l >= work.left and t >= work.top
            and l + ww <= work.right and t + hh <= work.bottom)


# ── 0.36.0：开窗**之后**的落位兜底 ────────────────────────────────────────
# ★ 为什么必须有这一步（实测，2026-10-07）：
#   只靠 `--window-size` / `--window-position` **不够**。本机实测：
#   服务起来、窗口确实新开了一个，但它落在 **1050×1932 @(10,10)** ——
#   与 0.35.3 的旧窗口一模一样，也就是**新参数被完全忽略**。
#   根因：Edge/Chrome 已有运行实例时，app 窗口由**旧进程**接管，
#   此时命令行上的 size/position **不生效**（实测 Q2：换独立
#   `--user-data-dir` 冷启动，参数立刻精确生效 ⇒ 证实是"复用旧进程"所致）。
#   ⇒ 结论：**命令行参数是"请求"，`SetWindowPos` 才是"事实"**。
#     既然我们要的是事实，就在开窗后把它落到位。
#
# ★ 边界（必须守住，否则就是"为了效果不择手段"）：
#   ① **只动标题精确匹配的 app 窗口**，绝不枚举后批量移动 ——
#      误伤用户窗口是不可接受的（本仓库明写：窗口几何"不去移动别的程序"）。
#      判据：`title == CONSOLE_WINDOW_TITLE`。
#   ② **不匹配就什么都不做**，返回 `False` + 人话，**不猜、不近似成功**。
#   ③ 找不到窗口**不是错误**（用户可能已手动关掉）——但**如实说没落位**，
#      因为"没落位"与"已落位"对用户是两件事。
#
#: 值守台 app 窗口标题里**不会变**的那一段。
#:
#: ★★ 为什么不能只认完整标题（真缺陷，本轮实测抓到）：
#:   页面标题是 `"%s · 值守台"`，前半段**随当前页面变** ——
#:   收件箱 / 运行状态 / 账本 / 日报 各是一个标题。
#:   实测落位时窗口标题已是「运行状态 · 值守台」，
#:   只认「收件箱 · 值守台」⇒ **找不到窗口、落位静默失败**，
#:   而日志还打着"已落到 520x640"（量的是别的窗口）。
#:   ⇒ 认**稳定后缀**，前半段是什么都行；仍然是精确匹配整串，
#:     不是子串搜索（子串会误伤标题里恰含这两个字的其它窗口）。
CONSOLE_WINDOW_TITLE_SUFFIX = " · 值守台"
#: 完整标题（仅用于文档/展示；**代码请用 `is_console_title`**）。
CONSOLE_WINDOW_TITLE = "收件箱" + CONSOLE_WINDOW_TITLE_SUFFIX

# ── 0.36.2：窗口**身份标识**（治"认错窗口"这个根） ────────────────────────
# ★★★ 为什么必须有身份标识（0.36.2 修的是真缺陷，不是锦上添花）：
#   0.36.1 的落位靠"标题以「 · 值守台」结尾"来找窗口。实测本机这条判据
#   **不足以唯一确定窗口**，于是同时出现两个真实故障：
#     ① 认错对象：普通 Edge 窗口的标题是
#        「收件箱 · 值守台 和另外 14 个页面 - 个人 - Microsoft Edge」
#        —— 它**含有**「 · 值守台」，而整串**不以**它结尾，所以 endswith 救了它；
#        但只要 Edge 某次把标题写成「… · 值守台」（例如页面恰好是最后一个标签、
#        或窗口管理器只截取到页名），这个判据就会**命中用户的普通浏览器窗口**，
#        而 `SetWindowPos` 会**把用户的浏览器搬到右下角 520×640**。
#        ⇒ 落位判据的"错方向"是**破坏用户环境**，不是"面板没到位"。
#     ② 分不清新旧：同一时刻可能有多个"· 值守台"窗口（旧的残留 + 新开的），
#        靠标题无法区分谁是本次该落的那个。
#   ⇒ 机制上杜绝的办法：**给本次运行的窗口一个只有它自己有的身份串**，
#     落位时只认带这个身份串的窗口。认错在结构上不再可能。
#
# ★ 身份串放在标题**末尾**、后缀之内：`收件箱 · 值守台#<run_id>`。
#   - 放末尾 ⇒ 仍然满足 `console_title_suffix` 的 endswith 结构（老判据仍成立）。
#   - 放后缀之内 ⇒ 不引入第二个分隔符，`is_console_title` 逻辑不用改。
#   - 由服务端在渲染时注入 ⇒ **只有本进程开出来的窗口**才带它。
# ★ 为什么不用窗口句柄/进程 id 当身份：句柄每次都变；进程 id 在
#   "Edge 复用旧实例"时**根本不是我们起的那个**（实测子进程秒退）。
#   标题是唯一能跨进程、跨时刻稳定识别"这个窗口属于本次运行"的东西。
def build_run_id(token=None):
    """本次运行的窗口身份串（短、稳定、可复现）。

    ★ 优先用**本次服务的口令 token 派生**（而不是随机数）：同一个服务进程
      反复开窗 ⇒ 同一个身份串 ⇒ 「同一个窗口被反复重开」能被认出来，
      而**上一次服务运行**的窗口带着不同的串 ⇒ 天然被排除。
    ★ 派生而非直接用 token：token 是**访问凭据**，不该出现在窗口标题里
      （标题会进任务栏预览、屏幕录制、 Alt-Tab 提示）。取其哈希前 6 位，
      既能区分不同运行，又不泄露凭据。
    """
    import hashlib
    seed = token if token else "%d" % (os.getpid(),)
    return hashlib.sha256(str(seed).encode("utf-8")).hexdigest()[:6]


def console_title_suffix(run_id=None):
    """本次运行窗口应当匹配的后缀。`run_id` 为空 ⇒ 退回通用后缀。"""
    if not run_id:
        return CONSOLE_WINDOW_TITLE_SUFFIX
    return "%s#%s" % (CONSOLE_WINDOW_TITLE_SUFFIX, run_id)


#: 值守台窗口标题里，**身份串之前**那段稳定文本（含分隔符）。
#:
#: ★★ 0.36.2 补正（实测抓到的设计缺陷，不是推演）：
#:   身份串放在后缀**末尾**（`… · 值守台#abc123`）带来一个连带问题：
#:   **通用后缀 ` · 值守台` 不再是它的后缀** ⇒ 任何用通用后缀去认
#:   "任意值守台窗口"的代码，**认不出带身份串的窗口**。
#:   实测：`CONSOLE_WINDOW_TITLE_SUFFIX.endswith(" · 值守台#abc123")` 为假；
#:   而 `close_console_windows` 默认就按通用后缀匹配 ⇒
#:   **上一轮带身份串的窗口关不掉**，"收旧窗"对 newest 形态失效。
#:   ⇒ 必须有**两级**判据，不能只有一级：
#:     · `CONSOLE_WINDOW_TITLE_MARK`（` · 值守台`）
#:       —— 判"**这是不是一个值守台窗口**"（标题中段，**前缀**匹配），
#:         用于**收旧窗**：本次的、上次的、无标识的，都算值守台窗口。
#:     · `console_title_suffix(run_id)`（` · 值守台#<id>`）
#:       —— 判"**这是不是本次运行的窗口**"（**后缀**匹配），
#:         用于**落位**：只有本次的才允许被移动。
#:   两级不可互换，这是本模块"不误伤用户窗口"的全部依据。
CONSOLE_WINDOW_TITLE_MARK = CONSOLE_WINDOW_TITLE_SUFFIX


#: **浏览器普通窗口**标题里的品牌后缀片段（实测 2026-10-07）。
#:
#: ★★★ 0.36.2 实测抓到的**我自己引入的缺陷**（这一版差点闯大祸）：
#:   为了让"收旧窗"能认出带身份串的窗口，我把宽泛判据写成
#:   「标题**中段**含 ` · 值守台`」—— 结果它**命中了用户自己的浏览器窗口**：
#:     实测用户窗口标题：「收件箱 · 值守台 和另外 14 个页面 - 个人 - Microsoft Edge」
#:   我实测跑了一次 `close_console_windows()`，**那个有 15 个标签的
#:   用户窗口被关掉了**（枚举复查：两个 Edge 窗口只剩一个）。
#:   ⇒ **"关用户窗口"是不可接受的**（本仓明文纪律），必须补一道排除。
#:   ★ 关键实测数据（判据设计的依据，不是猜的）：
#:       app 窗口  「收件箱 · 值守台#f356b0」        —— **不含** `Microsoft`
#:       用户窗口  「收件箱 · 值守台 和另外 14 个页面 - 个人 - Microsoft Edge」
#:                —— **含** `Microsoft`
#:     两者的窗口类名**相同**（都是 `Chrome_WidgetWin_1`）⇒ **类名区分不了**，
#:     只能靠标题里的浏览器品牌后缀。
#:   ⇒ 判据：命中「值守台」之后，再确认**标题里没有浏览器品牌后缀**。
#:     两道都过 ⇒ 才是我们自己的 app 窗口。
#:
#: ★ 为什么用"品牌后缀"而不是"和另外 N 个页面"：后者只在**多标签**时出现，
#:   单标签的普通窗口标题是「收件箱 · 值守台 - 个人 - Microsoft Edge」，
#:   同样含 `Microsoft`。用品牌片段覆盖面更全。
BROWSER_TITLE_MARKS = ("Microsoft", "Chromium", "Google Chrome")


def is_console_title(actual, run_id=None):
    """这个窗口标题**是不是值守台 app 窗口**？

    ★ `run_id` 为空 ⇒ 只问"是不是值守台 app 窗口"（**中段标记**匹配）：
      覆盖「收件箱 · 值守台」「收件箱 · 值守台#abc123」两种形态。
    ★ `run_id` 给了 ⇒ 只问"是不是**本次运行**的"（**整串后缀**匹配）：
      这是**移动窗口前的唯一合法判据**（只有它能排除用户窗口）。
    ★★ 无论哪种模式，都先排除**浏览器普通窗口**（见 `BROWSER_TITLE_MARKS`）
      —— 否则宽泛判据会关掉用户自己的浏览器窗口（实测已闯过这个祸）。

    ★★★ 0.36.5 修一个**真缺陷**（0360 P15 实测抓出来的，不是假红）：
      宽泛模式原来用 `MARK in t`（**任意位置子串**），实测后果：

        '收件箱 · 值守台助手'          → True   ← 误伤
        '收件箱 · 值守台 - 记事本'     → True   ← 误伤
        '记事本 - 收件箱 · 值守台'     → True   ← 误伤

      而**宽泛模式正是"收旧窗"用的**（`run_id` 给了只认本次运行，
      旧窗口带的是**上一次**的 run_id ⇒ 只能靠宽泛模式认出来）
      ⇒ 子串匹配 ⇒ **会误关用户自己的窗口**。
      这正是 0.36.2 那条注释担心的「用户窗口恰好含这两个字」，
      只是当时只在严格模式上做了防护，**漏了宽泛模式这一侧**
      —— 与 0.36.2 记录的「新增一个正确的函数 ≠ 修正调用它的默认路径」同型：
      **这一次是「严格模式收紧了 ≠ 宽泛模式也跟着收紧」**。

      正确判据：标记必须出现在标题**末尾**，其后**只允许身份串**
      （`#hex`）。这样：
        '收件箱 · 值守台'            → True（通用，OK）
        '收件箱 · 值守台#486acd'     → True（带身份，OK）
        '收件箱 · 值守台助手'        → False（标记后面还有别的字）
        '收件箱 · 值守台 - 记事本'   → False（同上）
      ⇒ **两条形态都覆盖，误伤全部排除**，不需要第二份标记常量。
    """
    if not actual:
        return False
    t = actual.strip()
    if any(m in t for m in BROWSER_TITLE_MARKS):
        return False                    # ★ 浏览器普通窗口，不许当成值守台
    if not run_id:
        return _mark_at_tail(t)
    # ★★ 0.36.5：**严格模式也要挡"标记前面挂着别的程序"**（实测补上）。
    #   严格模式是**唯一允许移动窗口**的路径（`place_all` 只用它），
    #   一次误认就会把用户的记事本搬到屏幕角落并改尺寸 ——
    #   而那正是本轮最初那个投诉（「窗口出现在旧位置而且变成了旧尺寸」）。
    #   ⇒ 原来只有 `endswith`，实测 `'记事本 - 收件箱 · 值守台#486acd'` 为真。
    #   ⇒ 现在严格模式 = 后缀命中 **且** 前缀是干净的页面名。
    if not t.endswith(console_title_suffix(run_id)):
        return False
    return _mark_at_tail(t)


def _mark_at_tail(title):
    """整串是否形如「**页面名** · 值守台」或「**页面名** · 值守台#<hex 身份>」。

    ★ 0.48.5（交接件 §5.5 W-01）：前缀也可以是**状态词**（失守/拦截/注意/
      缺粮/值守中/研发中/未启用/中断 —— 标题自该版起恒用状态词，见
      `inbox_server.render_page`）。整串形态不变，只是白名单放宽一维。

    ★★ 0.36.5 修正一次**收窄过头**（实测自己抓出来的）：
      第一版我用 `fullmatch` 认「**固定前缀** + 标记」，前缀从
      `CONSOLE_WINDOW_TITLE`（＝"收件箱 · 值守台"）推导 ⇒ 等于**只认"收件箱"这一页**。
      实测后果（0362 Q08b/Q12b 报红）：
        '运行状态 · 值守台#f356b0'  认不出来
        '日报 · 值守台'             认不出来
      ⇒ 页面名是**随导航变的**（收件箱／日报／运行状态／账本…），
        判据 P15 明确要求「每个页面标题都必须被认出来」。
      ⇒ 正确形态：**标记在末尾**，其后**只允许身份串**；
        前面是页面名（可任意），但**整串不得再夹别的分隔结构**。

    ★ 为什么"标记在末尾"已经够用（第一版担心的两类）：
      · '收件箱 · 值守台助手'    → 标记后面还有中文 ⇒ 不在末尾 ⇒ 排除 ✔
      · '记事本 - 收件箱 · 值守台' → 标记**在末尾**，这条仍会命中 ✘
      ⇒ 唯一还需要挡的是"标记前面挂了别的程序"。
        而这类标题（'记事本 - 收件箱 · 值守台'）在**真实应用里不会出现**：
        值守台是 `--app=` 窗口，标题由页面名决定；Edge/记事本的标题
        永远以自己的名字结尾。
      ⇒ 那就用**真实判据**来挡它，不靠"猜用户会怎么起标题"：
        前缀必须是**已知页面名或状态词之一**（真源在 `inbox_server` 的映射
        与 `host_shield.POSTURE_LABEL_ALLOWED` 里），且不得含 Windows 窗口
        标题里表示"另一个窗口"的分隔符（` - `、` – `、` — `）。
      ★ 这条思路的来源：**判据不该假设标题长什么样，只该认可它产生的那个程序**
        —— 与「窗口枚举复用唯一实现」「判据不许二次实现」同源。
    """
    if not title:
        return False
    # ① 标记必须在末尾（其后只允许 `#hex` 身份串）
    m = _TAIL_RE.search(title)
    if not m:
        return False
    page = title[:m.start()]
    # ② 前面必须是**认得的前缀**（页面名或状态词），不得含"另一个窗口"的标题分隔符
    if not page or any(sep in page for sep in _WINDOW_TITLE_SEPS):
        return False
    # ③ 前缀必须**不含路径/可执行扩展名**等程序特征（记事本.exe 之类）
    if re.search(r"[\w.-]+\.(?:exe|py|bat|cmd|ps1)$", page, re.I):
        return False
    # ④ ★★ 0.36.5 真缺口（本轮实测当场抓到，不是推演）：
    #   「前缀」这三个字，上面 ②③ 只查了**形状**（有没有分隔符/扩展名），
    #   **根本没查它是不是我们自己认得的那几种之一** ⇒ 用户窗口标题里
    #   恰好含 ` · 值守台#a8276c` 时会被误认（实测 `请给我一个 · 值守台#a8276c`
    #   宽泛模式返回 True）⇒ 宽泛模式是用来**关窗**的 ⇒ 会关掉用户自己的窗口。
    #   ⇒ 补上白名单这一层，注释里承诺的判据才真正落地。
    #   清单**不写死在这里**，import 两个唯一真源：
    #     · `inbox_server.PAGE_TITLES`（四个页面名）
    #     · `host_shield.POSTURE_LABEL_ALLOWED`（8 个状态词，S04 真源）
    try:
        import inbox_server as _SV
        import host_shield as _HS
        # ★★ 0.48.5（交接件 §5.5 W-01）：白名单＝**页面名 ∪ 状态词**。
        #   标题自 0.48.5 起恒用状态词（render_page 传 `M.light_explain()`
        #   的 label）⇒ 前缀不再只是页面名；页面名仍保留：旧窗口/别的入口
        #   可能还带它，且 0360 P15 逐页「认得出」继续有效。
        #   ⚠️ 必须保持「一个 names 集合」而不是 `page in names or
        #      page in state_names` —— 回归闸门 G-05 负控的注入锚点**逐字**
        #      锁着下面 `if page not in names:` + `return False` 两行；
        #      改了写法 ＝ G-05 负控失配，那层「不许误关用户窗口」的保护
        #      会悄悄失效（交接件 §5.5 连带栏原话）。
        names = set(_SV.PAGE_TITLES.values()) | set(_HS.POSTURE_LABEL_ALLOWED)
    except Exception:                                          # noqa: BLE001
        # ★ 拿不到真源 ⇒ 判不出 ⇒ 走**严**的一边：不认。
        #   与 `console_is_visible()` 的取向相反是有意的——
        #   那边漏报会藏起真失守，这边误认会去动用户的窗口。
        return False
    if page not in names:
        return False
    return True


#: 标题**末尾**形态：标记（＋可选身份串）。
_TAIL_RE = re.compile(re.escape(CONSOLE_WINDOW_TITLE_MARK) + r"(?:#[0-9a-fA-F]{4,})?$")

#: 窗口标题里表示"这是另一个窗口"的分隔符（Edge 会把标签页标题串进去）。
_WINDOW_TITLE_SEPS = (" - ", " \u2013 ", " \u2014 ", " | ", " \u00b7 ")


def is_window_on_screen(hwnd):
    """★ 0.36.6：这个窗口此刻**用户真的看得见吗**（可见 **且** 没被最小化）。

    ★★★ 为什么必须区分「可见」与「在屏幕上」（实测抓到，不是推演）：
      跑完闸门后查窗口，发现 `IsWindowVisible=True` 而 `IsIconic=True`、
      rect = `(-32000,-32000,160,28)` —— **窗口是最小化状态**。
      ⇒ 只查 `IsWindowVisible` 时，降噪闸认为「用户正开着值守台窗口」
        ⇒ **不弹泡泡**；而实际上用户什么都看不到，那条急事就这么被吞了。
      ⇒ 这正是本仓铁律「**查不出来 ≠ 查出来是好的**」的最坏形态：
        查出了一个**假的肯定**（"可见"），而它推出来的结论是**漏报真失守**。
      ⇒ 与「零输出被判通过」同族：**账面失真 ⇒ 真失守被藏起来**。

    ★ 取不到窗口 / 非 Windows ⇒ 返回 **None（未知）**，与 `console_is_visible` 同口径。
    """
    try:
        import ctypes
        if os.name != "nt":
            return None
        u = ctypes.windll.user32
        h = int(hwnd)
        if not u.IsWindow(h):
            return None
        if not u.IsWindowVisible(h):
            return False
        if u.IsIconic(h):                 # ★ 最小化 = 用户看不到
            return False
        return True
    except Exception:                                          # noqa: BLE001
        return None


def find_console_windows(suffix=CONSOLE_WINDOW_TITLE_SUFFIX, visible_only=True,
                         lister=None, run_id=None):
    """枚举**全部**匹配的值守台窗口；返回句柄列表（可能为空）。

    ★★ 0.36.2 为什么必须有"全量"版本（真缺陷）：
      旧版 `find_console_window` 命中第一个就 `return False` 收手。
      同一个标题可能同时存在**多个**窗口（旧的残留 + 新开的；或用户
      手动开过），而"第一个"由**枚举顺序**决定 —— 那是不可控的。
      后果实测出现过：落位落到了**旧窗口**上（挪走了它），
      而**新窗口**留在旧位置旧尺寸 ⇒ 用户看到"修复没生效"。
      ⇒ 现在返回**全部**匹配句柄，由调用方决定怎么处置（关掉旧的、
        落位全部、或如实报告有几个），**不替调用方猜哪个是哪个**。

    ★★ 两级匹配（0.36.2，见 `CONSOLE_WINDOW_TITLE_MARK` 的说明）：
      · 给 `run_id` ⇒ 只认**本次运行**的窗口（整串后缀匹配）。
        **只有这个模式可以用于移动窗口。**
      · 不给 `run_id` ⇒ 认**任何**值守台窗口（中段标记匹配），
        覆盖带身份串的旧窗口。**只用于关窗**，不用于移动。

    ★★★ 0.36.2 实测再抓一个真缺陷（这个坑踩了两次才算看清）：
      第一版把"不给 run_id"的分支写成 `_matches_title(标题, 通用后缀)`
      —— 而通用后缀 ` · 值守台` **不是** ` · 值守台#486acd` 的后缀
      （实测 `endswith` 为 False，标题尾部码点是 `…台#486acd`）
      ⇒ 宽泛枚举**认不出任何带身份串的窗口**
      ⇒ 实测 `find_console_windows()` 稳定返回 `[]`，
        而同一时刻裸枚举能找到 3 个 ⇒ **"收旧窗"又失效了**。
      ★ 为什么踩两次：第一次我加 `is_console_title()` 时以为"默认宽泛"已经
        改掉了，其实只**新增**了函数、没**改掉**原来的默认分支。
        ⇒ 教训：**新增一个正确的函数 ≠ 修正调用它的默认路径**。
        判据必须覆盖"默认参数下的真实行为"，而不是"某个函数存在"。
      ⇒ 现在默认分支直接用 `is_console_title(title, run_id)`：
        `run_id` 为空 ⇒ 中段标记匹配（宽泛）；给了 ⇒ 整串后缀（严格）。
        **一条路径，两个语义**，不再有"默认是哪种"的分叉。

    ★ 可测性：`lister` 是注入点，判据不必真起浏览器。
    """
    if lister is not None:
        return [h for h in lister(suffix=suffix, visible_only=visible_only) if h]
    if os_name() != "nt":
        return []
    try:
        u = ctypes.windll.user32
        CB = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
        found = []

        def cb(hwnd, _l):
            if visible_only and not u.IsWindowVisible(hwnd):
                return True
            n = u.GetWindowTextLengthW(hwnd)
            if n == 0:
                return True
            buf = ctypes.create_unicode_buffer(n + 1)
            u.GetWindowTextW(hwnd, buf, n + 1)
            # ★ 一条路径两个语义：run_id 为空 ⇒ 宽泛（收旧窗），
            #   给了 ⇒ 严格（只认本次，可移动）。
            if is_console_title(buf.value, run_id):
                found.append(hwnd)
            return True                     # ★ 不收手：全量收集

        u.EnumWindows(CB(cb), 0)
        return found
    except Exception:                                       # noqa: BLE001
        return []


# ★★ 0.36.3 删除（创始人「大窗相关垃圾代码一律不要」）：
#   `find_console_window`（**单数**）已删。删它的依据是实测，不是审美：
#     ① 生产代码**零调用**（`grep` 排除 `ci/`、`_p_*` 后无命中）；
#     ② 唯一残留调用在 `place_window`（单数）体内，而那函数同样零调用；
#     ③ 它的语义"只返回第一个"正是 0.36.2 修掉的那个**原故障根因** ——
#        留着它，就留着一条"落位只挪第一个窗口"的口子，将来谁调用谁复发。
#   ⇒ 判据同步改测真正被调用的 `find_console_windows`（全量）＋ `place_all`。
#   ★ 注意：`ci/inbox_guards_0360.py` 的 P03 曾专门守"单数版必须转发到全量"，
#     该判据已随之删除（它守的是一个不再存在的函数）。
#
# def find_console_window(title=None, visible_only=True, finder=None, run_id=None):
#     ...（0.36.2 全文见 git 历史；不要再复活它 —— 要全量就调 find_console_windows）


def window_rect_of(hwnd):
    """窗口矩形 `(l, t, w, h)`；取不到 ⇒ `None`。"""
    if os_name() != "nt" or not hwnd:
        return None
    try:
        r = w.RECT()
        if not ctypes.windll.user32.GetWindowRect(w.HWND(hwnd), ctypes.byref(r)):
            return None
        return (r.left, r.top, r.right - r.left, r.bottom - r.top)
    except Exception:                                       # noqa: BLE001
        return None


def close_console_windows(suffix=CONSOLE_WINDOW_TITLE_SUFFIX, visible_only=True,
                          closer=None, run_id=None):
    """关掉**已经开着**的值守台窗口；返回关掉几个。

    ★★★ 0.36.2 修的真实根因（这一行让上一步**从未生效过**）：
      旧版函数体第一行是 `if closer is None:`，但 `closer` **不是参数**、
      本模块也从未定义过它 ⇒ Python 判定它是局部变量 ⇒ 每次调用
      **必然抛 `UnboundLocalError`**，而调用方（`inbox_server.open_console`）
      用 `except Exception` 兜住了，只往 stderr 打一行
      「收旧窗口失败」⇒ **从 0.36.1 起，"开窗前收旧窗"这一步一次都没成功过**。
      实测复现：`close_console_windows()` → `UnboundLocalError: cannot
      access local variable 'closer'`。
      ★ 这就是"窗口出现在旧位置旧尺寸"的**直接根因**：旧窗口没被收掉，
        落位又只认"第一个"同名窗口 ⇒ 挪走的是旧的，新窗口原地不动。
      ⇒ 现在 `closer` 是**真参数**（可注入 ⇒ 判据不必碰真实桌面），
        默认实现仍然 `PostMessageW(WM_CLOSE)`。
      ★ 教训（同本仓已犯过两次的病）：**注入点必须出现在签名里**。
        写在函数体里、靠闭包或全局兜着，静态检查与运行时都会静默失效。

    ★★ 为什么必须有这一步（实测，2026-10-07 第二轮）：
      值守台窗口属于**浏览器进程**，不属于我们的服务进程 ⇒
      服务被杀、崩溃或重启后，窗口**仍留在屏幕上**。
      本机实测：宿主 python 已被 kill，1050×1932 的旧窗口还在。

    ★ 为什么"关掉旧的"比"挑新的"可靠：
      试过 `GetWindowLongPtrW(GWL_CREATIONTIME)` 取创建时间来挑最新的，
      **实测返回 0**（该属性对顶层窗口不保证可用）⇒ 这条路不可依赖。
      枚举顺序也不承诺与创建时间一致。
      唯一**确定**的办法是让"同名窗口"在开窗前就不存在。

    ★ 边界（同上，必须守住）：**只关标题后缀匹配的窗口**，
      绝不枚举后批量关闭 —— 误关用户窗口不可接受。
      逐个发 `WM_CLOSE`（而不是 `DestroyWindow`）：让浏览器自己走
      正常的关闭流程，不强杀进程。

    ★ 0.36.2：默认走**宽泛模式**（`run_id=None` ⇒ 按 `CONSOLE_WINDOW_TITLE_MARK`
      中段匹配）—— 这一步是必须的，不是偷懒：
      身份串在标题**末尾**，所以通用后缀 ` · 值守台` **不是**
      ` · 值守台#abc123` 的后缀（实测 endswith 为假）。
      若这里还用"整串后缀 + 通用后缀"，则**上一轮带身份串的窗口关不掉**
      ⇒ "收旧窗"对最新形态失效 ⇒ 根因①换个形状复发。
      ⇒ 关窗用宽泛（是值守台窗口就关），**落位用严格**（只动本次的）。
    """
    if closer is None:
        if os_name() != "nt":
            return 0
        def closer(h):                                       # noqa: E731
            return bool(ctypes.windll.user32.PostMessageW(
                w.HWND(h), 0x0010, 0, 0))                   # WM_CLOSE
    try:
        victims = find_console_windows(suffix=suffix, run_id=run_id,
                                       visible_only=visible_only)
    except Exception:                                       # noqa: BLE001
        return 0
    closed = 0
    for h in victims:
        try:
            if closer(h):
                closed += 1
        except Exception:                                   # noqa: BLE001
            continue
    return closed


def wait_console_windows_gone(suffix=CONSOLE_WINDOW_TITLE_SUFFIX, tries=12,
                              interval=0.25, lister=None, run_id=None):
    """等匹配 `suffix` 的窗口**全部消失**；返回 `(是否已清空, 剩余几个)`。

    ★★ 0.36.2 为什么必须等（`WM_CLOSE` 是异步的）：
      `PostMessageW(WM_CLOSE)` 只是**投信**，浏览器何时真正销毁窗口
      不受我们控制。实测：投完立刻开新窗，旧的还在 ⇒ 那一刻屏幕上
      **有两个**「· 值守台」窗口 ⇒ 后续任何"取第一个"的操作都可能抓到
      正在退场的旧窗口。
      ⇒ 机制上杜绝：**不确认清空就不开新窗**。等不到就如实返回剩余数，
        由调用方决定是继续还是放弃（不假装清干净了）。
    """
    remaining = None
    for _ in range(max(1, tries)):
        remaining = len(find_console_windows(suffix=suffix, lister=lister, run_id=run_id))
        if remaining == 0:
            return True, 0
        time.sleep(interval)
    remaining = len(find_console_windows(suffix=suffix, lister=lister, run_id=run_id))
    return (remaining == 0), remaining


def place_one(hwnd, rect, setter=None, reader=None):
    """把**一个**窗口落到 `rect`；返回 `(是否成功, 人话原因)`。

    ★ 拆成"一个"是 0.36.2 的结构性改动：`place_all` 要对**每个**匹配窗口
      独立落位、独立回读校验。合成一个函数就会出现"循环里成功一次就
      报整体成功"，而实测故障恰恰是**部分落位**（旧的挪了、新的没挪）。
    """
    if hwnd is None:
        return False, "窗口句柄为空，没落位。"
    if setter is None:
        def setter(h, r):
            # SWP_NOZORDER(0x0004) | SWP_NOACTIVATE(0x0010)
            #   —— 只挪位置和大小，不抢焦点、不改 z 序：
            #   面板不该在用户打字时把焦点抢走。
            return bool(ctypes.windll.user32.SetWindowPos(
                w.HWND(h), None, r[0], r[1], r[2], r[3], 0x0004 | 0x0010))
    try:
        ok = setter(hwnd, rect)
    except Exception as e:                                  # noqa: BLE001
        return False, "移动窗口时出错（%s），没落位。" % (type(e).__name__,)
    if not ok:
        return False, "系统拒绝了移动请求，没落位。"
    if reader is None:
        reader = window_rect_of
    got = reader(hwnd)
    if got is not None and tuple(got) != tuple(rect):
        # ★ 不谎报：移动返回成功但实测不符，如实说实测值。
        return False, ("移动已下达但实测仍是 %dx%d @( %d,%d )，与目标不一致。"
                       % (got[2], got[3], got[0], got[1]))
    return True, "已落到 %dx%d @(%d,%d)。" % (rect[2], rect[3], rect[0], rect[1])


# ★★ 0.36.3 删除（与单数版 `find_console_window` 同批）：
#   `place_window`（**单数**）已删。它体内还留着一处 0.36.2 的**残留 bug**：
#     `finder = lambda **kw: [find_console_window(title=title)]`
#   ——既调用了刚被删的函数，又把"单个"语义包成列表喂给全量函数，
#   读起来像"支持自定义 finder"，实则只是历史残留。
#   生产代码零调用；调用方 `_place_if_needed` 用的是 `place_all`。
#   ⇒ 要落位就直接 `find_console_windows(...)` + `place_all(hwnds, rect)`。
#
# def place_window(rect, title=None, finder=None, setter=None):
#     ...（0.36.2 全文见 git 历史）


def close_window(hwnds, closer=None, why=""):
    """关掉给定的值守台窗口；返回 `(关掉几个, 人话原因)`。

    ★★★★ 0.36.4 **职责收窄**（创始人「落位失败就关窗不是彻底的解决办法」）：
      0.36.3 给本函数定的角色是「**落位失败时的兜底**」——
      重试耗尽就把窗口杀掉，理由是「留着它就会一直占着大窗」。
      ★ 现在回看，那是个**错误的角色**，代价有两处：
        ① **杀错了对象**：落位失败只说明"这一次没搬成"，
          而这个窗口本身**完全正常**（它就是值守台面板，主人正要看的那个）。
          为"位置不对"杀掉"内容"，是**手段颠倒了目的**。
        ② **它掩盖真问题**：面板被杀掉之后，"为什么没搬成"这条线索
          连同窗口一起没了 ⇒ 用户只看到"面板不见了"，
          而**根因（窗口几何从一开始就不受控）被这个兜底永久掩盖**。
      ⇒ **0.36.4 删掉这条兜底**：落位失败不再调本函数。
        改由 `place_all` 的失败路径如实上报（见 `_place_if_needed`），
        面板**留在它该在的地方、由用户决定关不关**。

    ★★ 现在本函数**只有一个正当用途**：**收旧窗** ——
      服务被杀/崩溃/重启后留在屏幕上的残留窗口（实测真实发生过：
      宿主 python 已 kill，1050×1932 的旧窗口还在）。
      那里的窗口**确实是垃圾**（没有服务在喂它），关它是对的。

    ★ 边界（不变，必须守住）：
      只关**调用方传进来的**句柄 —— 本函数**不枚举、不猜测**。
      范围由 `find_console_windows` 的标题过滤限定；
      落位侧传的是**本次运行的身份串**（`run_id`）
      ⇒ 结构上不可能命中用户窗口。
      逐个发 `WM_CLOSE`（不强杀进程），让浏览器走正常关闭流程。

    ★ `why` 是**调用方给的收窗理由**（人话），会原样带进返回值。
      新增它是因为「为什么关」是收旧窗时必须让人知道的事；
      而 0.36.3 那版把理由写死成「没能落位」，那在收旧窗场景下是**假话**。
    """
    if closer is None:
        if os_name() != "nt":
            return 0, "非 Windows 平台，没法关窗。"
        def closer(h):                                       # noqa: E731
            return bool(ctypes.windll.user32.PostMessageW(
                w.HWND(h), 0x0010, 0, 0))                   # WM_CLOSE
    hs = [h for h in (hwnds or []) if h]
    if not hs:
        return 0, "没有可关的窗口（多半已被用户手动关掉了）。"
    n = 0
    for h in hs:
        try:
            if closer(h):
                n += 1
        except Exception:                                   # noqa: BLE001
            continue
    if n <= 0:
        return 0, "没有关掉任何值守台窗口（多半已被用户手动关掉了）。"
    return n, ("关掉了 %d 个值守台窗口%s"
               % (n, ("（%s）" % why) if why else "。"))


def place_all(hwnds, rect, setter=None, reader=None, skip_if_placed=True):
    """把**全部**给定窗口逐个落位；返回 `(是否全部成功, 汇总人话)`。

    ★★ 0.36.2 为什么必须"全量 + 逐个校验"（这是当时修的核心机制）：
      实测故障：屏幕上同时有旧窗口和新窗口（同标题），
      旧版只认第一个 ⇒ 挪走旧的、新的留在原地 ⇒ **用户看到修复没生效**，
      而日志打的是"已落到 520x640"（量的是**别的**窗口）。
      ⇒ 现在：**每一个**匹配窗口都要落到目标矩形，且**每一个**都要回读校验；
        只要有一个不符就**整体报失败**并说清是几个里的几个。
        局部成功不算成功 —— 那正是原故障的形状。

    ★★ 0.36.4 新增 `skip_if_placed`（**默认开**，且**先回读再决定**）：
      独立 profile 方案下窗口**出生即正确**（实测 Δ 全 0），
      所以正常路径**一条 SetWindowPos 都不该发** —— 发了就是
      "对着已经正确的窗口再搬一次"，纯属多余动作，且**多一次误伤机会**。
      ⇒ 现在先 `reader(hwnd)` 读实测矩形；**已经等于目标就直接算成功**，
        一个字节都不动窗口。
      ★ 为什么必须"**先回读**"而不是"相信它一定对"：
        本仓铁律「查不出来 ≠ 查出来是好的」的同型 ——
        **"应该已经对"不是证据，回读才是**。若 `reader` 读不出来
        （窗口刚销毁/无权限），则**照常走落位**，不假装已对。
      ★ `skip_if_placed=False` 时无条件落位（保留给需要强制复位的场景与判据）。

    ★ 边界不变：调用方**只把标题后缀匹配的窗口**传进来
      （`find_console_windows` 已过滤）。本函数不枚举、不猜测，
      因此不存在"批量移动用户窗口"的可能 —— 移动范围由调用方的
      过滤结果限定，本函数只是**如实执行并如实校验**。
    """
    if rect is None:
        return False, "没有目标矩形（屏幕放不下），没落位。"
    hwnds = [h for h in (hwnds or []) if h]
    if not hwnds:
        return False, "没找到值守台窗口（可能已被手动关闭），没落位。"
    rd = reader or window_rect_of
    oks, whys, already = [], [], 0
    for h in hwnds:
        # ── 0.36.4：先回读。已对齐 ⇒ 不动它（实测正常路径走这里）。──
        if skip_if_placed:
            try:
                got = rd(h)
            except Exception:                               # noqa: BLE001
                got = None
            if got is not None and tuple(got) == tuple(rect):
                already += 1
                oks.append(True)
                whys.append("已经就在 %dx%d @(%d,%d)，没动它。"
                            % (rect[2], rect[3], rect[0], rect[1]))
                continue
        ok, why = place_one(h, rect, setter=setter, reader=rd)
        oks.append(ok)
        whys.append(why)
    if all(oks):
        if already == len(hwnds):
            return True, ("%d 个值守台窗口**出生即正确**，都在 %dx%d @(%d,%d)，"
                          "一个都没搬。" % (len(hwnds), rect[2], rect[3],
                                            rect[0], rect[1]))
        if already:
            return True, ("%d 个值守台窗口已全部对齐 %dx%d @(%d,%d)"
                          "（其中 %d 个出生即正确、%d 个搬过来的）。"
                          % (len(hwnds), rect[2], rect[3], rect[0], rect[1],
                             already, len(hwnds) - already))
        return True, "已把 %d 个值守台窗口都落到 %dx%d @(%d,%d)。" % (
            len(hwnds), rect[2], rect[3], rect[0], rect[1])
    bad = [w for o, w in zip(oks, whys) if not o]
    # ★ 0.36.4：**失败不再关窗**（见 `close_window` 的职责收窄说明）。
    #   如实说清"没搬成"，并明说面板**仍在屏幕上**、由用户处置。
    return False, ("%d 个匹配窗口里 %d 个没落到目标位置：%s"
                   "（面板仍留在屏幕上，没有被关掉——它就是值守台，"
                   "由你决定关不关）" % (len(hwnds), len(bad), bad[0]))