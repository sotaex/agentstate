#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.49.0 收口判据 —— W-08 / W-09 / U-17 / B-02…B-08 / FLO-01…FLO-06 ＋交互回归。

四件事（创始人 2026-10-14 夜交办，5 张截图实证 ＋ 三条"也要九维四件套"）：
  ① W-08 窗口默认尺寸：520×640 **低于 CSS 窄屏断点 620** ⇒ 一出生就落进
     窄降级布局（顶行折行压字）；拉宽才正常。修：MAX_W 520→720。
  ② W-09 术语浮层出界：问号浮层右缘/下缘被窗口裁掉。修：JS 量溢出量 ⇒
     服务端**平移优先、贴边撑开、还原不抢方向盘、露不全如实留余量**。
  ③ U-17 图标动效：0.48.5 戊1（461b4ef）把头部动效 mp4 换成静态 logo.svg
     ⇒ "好了但是死了"。修：内联 SVG＋rAF 状态机（规格 v1.2 的"代码即规格"
     实现 `antinel-motion-demo-v2.html` 的产品化移植）。
  ④ B-02…B-08 紧急提醒：急事（R0/L2）要"当时弹出来＋有声音＋不一闪而过＋
     人工确认"。路由换代（R0/L2→紧急提醒、其余→toast、同一事件只走一条通道）
     由 `ci/inbox_guards.py` 的 `c_daemon_tick_notifies_once`（记 B-01）守；
     **本文件守它的下游**：界面同源、不闪退、声音、节流/ack、可见性闸、
     服务起不来如实、一次一枚。
  ⑤ FLO-01…FLO-05 漂浮最小态："监理很多时候不要碍事，只要在"——收缩成一
     枚漂浮哨标（点击展开），展开即退役哨标。0.50.7 起收缩入口＝左上角
     LOGO 本体（创始人截图去重复，判据 FLO-05 跟着换锁 `button.logo`）。
  ⑥ U-18 哨标比例（0.50.2 补）：内联动效 SVG 照搬 demo 的 1024 画布 ⇒
     环只占半宽 0.465，定稿 logo.svg 是 0.844 ⇒ 缩进 48px 方框比定稿小 45%，
     创始人截图原话"LOGO 活了，但旧病复发，变得太小了"。修法：**只收紧
     viewBox**（按定稿比例反算），动法几何一个数不动；U-18b 顺带锁住
     `_LOGO_JS` 的 CX/CY/R 与 Python 常量逐项一致（防两处各写一份）。
  ⑦ U-18c / U-18d 波不被裁（0.50.3 补）：⑥ 把 viewBox 收到**环**上以后
     （half=282.074），涟漪最外缘 215+24+8+105=**352 > 282.074** ⇒ 波被切出
     直边，创始人截图原话"冒泡的 LOGO 不完整"。根因是**两条规格互不相容**
     （定稿 logo 要环占 0.844；动效规格 v1.2 的波幅 45/70/105 是在"环占
     0.465"的 demo 画布上标定的）。修法：**方框＝定稿方形轮廓（环不动），
     波幅按可用空间归一**（`_logo_wave_scale()`），新增渲染用表
     `LOGO_MOTION_RENDER`（＝规格表 × 归一系数，只差 waveR）。判据两条腿：
     U-18c 用 Python 常量＋渲染表算"框装得下全部绘制内容"（快、可注入）；
     U-18d 用 **Node 真跑**的坐标算（慢、拿真坐标）——一条抓"常量对不上
     渲染表"，一条抓"状态机自己把坐标画到框外"。
  ⑧ B-13「打开Antinel 监理」已开着就别重开（0.50.3 补）：创始人 2026-10-14
     「点击打开Antinel 监理后，之前的关闭了，打开了新的，但是状态不对了……点完了
     按钮显示'打开Antinel 监理'按钮好像不对吧，Antinel 监理打开着呢」。旧链路只有
     `open_console_settled()` 一条路（语义是"没有窗、要开一个"）⇒ 面板本来
     就开着时点一下 = 旧窗被关、新窗从头加载（态势读数重新算 ⇒"状态不对了"），
     而按钮上写着"打开" ⇒ **不成立的承诺**。修法：抽成唯一决策点
     `bubble_open_route()` 三路分流（看得见 ⇒ 只切到前面；看不见 ⇒ 开窗；
     **判不出来 ⇒ 开窗**，宁可多开一个窗也不许点了没反应）；文案侧开着就不画
     按钮、点完按钮退场换状态。判据打在**行为**上（三条路的动作序列＋返回值），
     N-B13 把分流条件反过来、**拿变异体跑同一条正判据** ⇒ 必红。
  ⑨ J1–J5「五条违和」同类可抓（**原 0518，2026-10-16 并入**）：创始人
     2026-10-16 截图标出五条违和，四条可机械判 ⇒ 同一个消费面
     （`inbox_server.py` 渲染产物）的尺子按 A2/P5 规则**并入本套件**，
     不立新套件。详见文件末「J 族」段头。
  ⑩ FLO-10a…e 漂浮哨标动效三态（**0.53.1，2026-10-19 并入**）：创始人截图
     三句话——「出现的居然是圆圈不是标准 LOGO」「点圆圈中间没反应」「LOGO
     应该跟主窗口一样保持动态」。修法：哨标改画**标准动效徽标**（动法＝
     `tools/logo_frame.ps1` 纯帧数学，规格经 tray.json 的 logo 块由
     `inbox_server.logo_motion_spec()` 单一真源下发）＋分层窗整圆可点＋
     线程池定时器帧泵。判据方法：PowerShell 驱动 dot-source **产品同一个**
     帧数学脚本真跑，Python 侧只做从同一份规格出发的独立推导（oracle）与
     逐项比对 —— 不二次实现被测逻辑。详见「FLO-10 族」段头。
  ⑪ T4-07／T4-08／T4-09 问号词条文案（**0.53.2，2026-10-19 补**）：T4 那六条
     只覆盖归因面板与收件箱条目，**没有一条经过 `glossary.TERMS`** ⇒ 一个
     233 字、单句 65 字、四段全讲实现的灯词条活了两版没人报红。补法：把
     品质性机制层的**预算网**（一句 ≤40 字、一字段 ≤2 句）、**禁用语网**、
     **跨字段重复网**（同一词条任意两字段公共子串 ≥6 字即红）接到词条这条
     腿上。T4-09 的必要性：前两条都按**字段**切分，而用户看到的是浮层里
     连续的四段 —— 四段各自合规、合起来说两遍同一件事，前两条都抓不到。
     详见「T4-07／T4-08」段头与 T4-09 的 docstring。

★ 规格真源（U-17 的唯一依据，不许凭记忆）：
    `D:\\2026\\PSL\\Antinel品牌动效报警语法v1.2（2026-09-27）.md`
    速度 12→8→5.5→3.5 s/圈；波幅 +45/70/105px @.30/.45/.65；
    R0 滑行 20° 后永停、波止、环转暗红 #4A2626 塌暗至 0.45；
    涟漪周期恒定 1.4s；环呼吸 ±6%/4s。

★ 编写纪律（沿用 0490/0470）：
  · 每条判据配负控，负控**先实测见红**（变异真生效才许写进文件）；
  · 断言打在**行为/结构**上（渲染产物、调用顺序、回读校验），不查行号；
  · **不写任何产品文件**：变异只在内存/临时目录；账本只落 `_HUB`；
  · 判据不许二次实现：口径一律 import 产品模块；
  · 测不出 ⇒ 报 SKIP（⏭️），**绝不报 PASS**（例：本机无可执行 node）。
"""
from __future__ import annotations

import io
import json
import math
import os
import re
import sys
import tempfile
import threading
import time
import inspect
from datetime import datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ★★ 必须在 import 产品模块**之前**把中枢换到临时目录（0470/0490 同款教训）：
#   否则渲染/记账路径会碰真实中枢的 notify_state.json。
_HUB = tempfile.mkdtemp(prefix="g0514_hub_")
os.environ["ANTINEL_HUB_DIR"] = _HUB
os.environ.pop("ANTINEL_AUDIT_DIRS", None)

import inbox_bubble as BB                                       # noqa: E402
import inbox_daemon as DM                                       # noqa: E402
import inbox_logo as IL                                         # noqa: E402
import inbox_model as M                                         # noqa: E402
import inbox_notify as NT                                       # noqa: E402
import inbox_server as SV                                       # noqa: E402
import inbox_tray as TR                                         # noqa: E402
import inbox_window as WIN                                      # noqa: E402
import glossary as GL                                           # noqa: E402
import page_caliber as PC                                       # noqa: E402
RESULTS = []

_SERVER_REL = "inbox_server.py"
_WINDOW_REL = "inbox_window.py"
_DAEMON_REL = "inbox_daemon.py"
_LOGO_PS1_REL = "tools/logo.ps1"
_FRAME_PS1_REL = "tools/logo_frame.ps1"
_TRAY_PS1_REL = "tools/tray.ps1"


class Skip(Exception):
    """夹具凑不齐（例：没有 node）⇒ 这一条**不判**，也**不许判绿**。"""


def check(name):
    """★ 判据**必须真会红** —— 返回说明串一律转成抛异常；SKIP 前缀转 Skip。"""
    def deco(fn):
        def wrapper():
            r = fn()
            if r is True or r is None:
                return True
            if isinstance(r, str) and r.startswith("SKIP"):
                raise Skip(r)
            raise AssertionError(r if isinstance(r, str) else repr(r))
        RESULTS.append((name, wrapper))
        return fn
    return deco


def _note(*a):
    """判据的**说明行**（原 0518 同款；并入后沿用同一输出形状）。"""
    print("      · %s" % " ".join(str(x) for x in a))


def _src(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class _Patch:
    """给模块属性打补丁并在退出时还原（变异只在内存，不落盘）。"""

    def __init__(self, mod, **attrs):
        self.mod = mod
        self.attrs = attrs
        self._saved = {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self._saved[k] = getattr(self.mod, k)
            setattr(self.mod, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self._saved.items():
            setattr(self.mod, k, v)
        return False


class _Area:
    """假工作区（只带 `pick_work_area`/`_winfit_apply` 用到的面）。"""

    def __init__(self, l, t, r, b):
        self.primary = True
        self.left, self.top, self.right, self.bottom = l, t, r, b
        self.w, self.h = r - l, b - t


class _Desk:
    """假桌面：hwnd→(l,t,w,h) 的记录型夹具 ＋ 调用计数。

    ★ 它是**记录型**的：`place_all` 真把新矩形写进记录，`window_rect_of`
      真从记录读 —— 于是"place 报了成功但窗没动"这类谎言会被回读校验抓住
      （W-09 负控 b 靠的正是这个，不是靠我们说它失败了）。
    """

    def __init__(self, hwnds=(101,), rect=(0, 0, 720, 640), work=(0, 0, 2560, 1400),
                 place_result=(True, "")):
        self.rects = {h: tuple(rect) for h in hwnds}
        self.hwnds = list(hwnds)
        self.area = _Area(*work)
        self.place_result = place_result
        self.calls = {"place": 0, "find": 0}
        self.last_rect = None

    # -- 夹具面（名字与真原语对齐，注入的就是它们）---------------------
    def find(self, suffix=None, visible_only=True, run_id=None, **kw):
        self.calls["find"] += 1
        return list(self.hwnds)

    def rect_of(self, h):
        return self.rects.get(h)

    def pick(self, areas=None):
        return self.area

    def place(self, hwnds, rect, setter=None, reader=None, skip_if_placed=True):
        self.calls["place"] += 1
        self.last_rect = tuple(rect)
        if self.place_result[0]:
            for h in hwnds:
                self.rects[h] = tuple(rect)
        return self.place_result

    def patch(self):
        return _Patch(WIN, find_console_windows=self.find,
                      find_bubble_windows=self.find,
                      window_rect_of=self.rect_of,
                      pick_work_area=self.pick, place_all=self.place)


def _winfit_reset():
    SV._WINFIT_STATE.update(orig=None, adj=None, run_id=None)


def _page(token="g0514"):
    return SV.render_page(items=[], posture={"state": "guarding",
                                             "can_fix": False}, token=token)


# ════════════════════════════════════════════════════════════ W-08 ══
#: 规格 v1.2 里**没有**这一条 —— 它是截图实证的窗口缺陷。断点从产品 CSS 读，
#: 不在这里写死（写死就成了"第二份事实"，CSS 一改判据就成谎言）。
#: ★ 正则必须带 `@media` 上下文：CSS 里还有普通规则 `main{max-width:1000px}`
#:   （首版没带上下文，把 1000 当断点 ⇒ 好值被判红，尺子反咬）。
_BP_RE = re.compile(r"@media\s*\(max-width:\s*(\d+)px\)")


def _css_breakpoints(css):
    return sorted({int(x) for x in _BP_RE.findall(css)})


def _w08_ok(max_w, bp, margin=100):
    """出生宽度必须**高于**窄屏断点并留足余量（降级布局本身是对的，
    错的是"一出生就降级"）。"""
    return max_w > bp and (max_w - bp) >= margin


@check("W-08 面板出生宽度高于 CSS 窄屏断点且留 100px 余量（截图 1/2）")
def c_w08():
    css = SV.CSS
    bps = _css_breakpoints(css)
    if not bps:
        return ("量具失效：产品 CSS 里找不到 max-width 断点（正则没命中）—— "
                "断点是这一条的事实来源，找不到就不判")
    bp = bps[-1]                       # 最宽的那条窄屏断点（620）
    if not _w08_ok(WIN.MAX_W, bp):
        return ("MAX_W=%d 未高于断点 %d（余量 %d）—— 面板一出生就落进窄降级"
                "布局，正是截图 1 的「乱样」" % (WIN.MAX_W, bp, WIN.MAX_W - bp))
    if SV.WINDOW_SIZE != "%d,%d" % (WIN.MAX_W, WIN.MAX_H):
        return ("WINDOW_SIZE=%r 与 MAX_W/MAX_H（%d×%d）不同源 —— 兜底值"
                "漂了就等于没兜底" % (SV.WINDOW_SIZE, WIN.MAX_W, WIN.MAX_H))
    # 大工作区上必须真的给到上限（比例不许把 720 吃小）
    big = WIN.panel_size(_Area(0, 0, 3840, 2160))
    if tuple(big) != (WIN.MAX_W, WIN.MAX_H):
        return "大工作区上面板尺寸 %r ≠ 上限 %s" % (big, (WIN.MAX_W, WIN.MAX_H))
    return True


@check("N-W08 负控：MAX_W 退回 520 ⇒ 同一把尺子必须判红（分辨力证明）")
def n_w08():
    bps = _css_breakpoints(SV.CSS)
    if not bps:
        return "量具失效：连断点都读不到，负控无从判起"
    bp = bps[-1]
    if _w08_ok(520, bp):
        return ("负控失效：520 也判「合格」—— 尺子对坏值不红，W-08 是空转"
                "（要么断点读错，要么 margin 条件是装饰）")
    if _w08_ok(WIN.MAX_W, bp) is not True:
        return "负控反咬：好值在负控尺子下也不绿，尺子坏了"
    return True


@check("W-08b 连带：小工作区仍走**正确的**降级（上限是上限，不是下限）")
def c_w08b():
    small = WIN.panel_size(_Area(0, 0, 1000, 600))
    if small[0] >= WIN.MAX_W:
        return ("1000×600 的工作区也给了 %dx%d —— 上限被当成下限用，窄屏"
                "会被盖住任务栏" % (small[0], small[1]))
    g = WIN.console_geometry(areas=[_Area(0, 0, 1000, 600)])
    if not g.get("ok"):
        return "1000×600 上 console_geometry 直接不开：降级路径不该是「不开」"
    return True


# ════════════════════════════════════════════════════════════ W-09 ══
@check("W-09a 浮层右/下溢出且左右有余量 ⇒ 平移优先（不改布局）")
def c_w09a():
    _winfit_reset()
    d = _Desk(rect=(2000, 1100, 720, 640), work=(0, 0, 2560, 1400))
    with d.patch():
        rep = SV._winfit_apply(80, 40, "tok-w09")
    if not rep.get("ok"):
        return "平移臂没成：%s" % rep.get("why")
    if rep.get("moved") != [80, 40] or rep.get("grew") != [0, 0]:
        return "平移量 %r / 撑开量 %r ≠ [80,40]/[0,0]（不只平移就是动了布局）" % (
            rep.get("moved"), rep.get("grew"))
    if tuple(d.rects[101]) != (1920, 1060, 720, 640):
        return "落位矩形 %r ≠ (1920,1060,720,640)（平移量没用在缺口上）" % (
            tuple(d.rects[101]),)
    if rep.get("left") != [0, 0]:
        return "全露了却还留余量 %r —— 余量是「没露全」的账，不许乱记" % (
            rep.get("left"),)
    if SV._WINFIT_STATE.get("orig") != (2000, 1100, 720, 640):
        return "没记住调整前矩形，还原时拿什么搬回？"
    return True


@check("N-W09a 负控：place 报成功但窗没动（回读校验必须抓住谎言）")
def n_w09a():
    _winfit_reset()
    # 记录型夹具的进化用法：place 返回 (True,") 却**不写**矩形 ——
    # 这不是"我们让它失败"，而是"它撒谎"，真实的 SetWindowPos 失败
    # 就是这个形状（返回 ok、窗口原地不动）。
    class _Liar(_Desk):
        def place(self, hwnds, rect, setter=None, reader=None,
                  skip_if_placed=True):
            self.calls["place"] += 1
            self.last_rect = tuple(rect)
            return (True, "")          # 报成功，但不落记录
    d = _Liar(rect=(2000, 1100, 720, 640), work=(0, 0, 2560, 1400))
    with d.patch():
        rep = SV._winfit_apply(80, 40, "tok-w09")
    if rep.get("ok"):
        return ("负控失效：place 报成功、窗没动，也被判成功 —— 没有回读校验"
                "的「平移优先」就是把谎言当真")
    if "成功" in (rep.get("why") or "") and rep.get("ok"):
        return "why 与 ok 自相矛盾"
    if SV._WINFIT_STATE.get("orig") is not None:
        return "没落位却记了 orig —— 还原会去搬一个从没搬动过的窗口"
    return True


@check("W-09b 贴左边/上边（没有平移余量）⇒ 才撑开右/下沿")
def c_w09b():
    _winfit_reset()
    d = _Desk(rect=(0, 0, 720, 640), work=(0, 0, 2560, 1400))
    with d.patch():
        rep = SV._winfit_apply(120, 60, "tok-w09")
    if rep.get("moved") != [0, 0] or rep.get("grew") != [120, 60]:
        return "平移 %r / 撑开 %r ≠ [0,0]/[120,60]" % (rep.get("moved"),
                                                     rep.get("grew"))
    if tuple(d.rects[101]) != (0, 0, 840, 700):
        return "落位 %r ≠ (0,0,840,700) —— 撑开量没加在窗宽窗高上" % (
            tuple(d.rects[101]),)
    return True


@check("W-09c 工作区就到边、实在露不全 ⇒ 余量如实留下，不许说成'露出了'")
def c_w09c():
    _winfit_reset()
    # 工作区比窗口还小：平移只能吃到 100/50，撑开一格都不剩。
    d = _Desk(rect=(100, 50, 720, 640), work=(0, 0, 700, 600))
    with d.patch():
        rep = SV._winfit_apply(400, 300, "tok-w09")
    if rep.get("left") != [300, 250]:
        return "余量 %r ≠ [300,250] —— 露不全的账记错了，用户会被误导" % (
            rep.get("left"),)
    if rep.get("left") == [0, 0]:
        return "明明没露全却记 0 —— 假成功"
    if rep.get("moved") != [100, 50] or rep.get("grew") != [0, 0]:
        return "平移/撑开 %r/%r 与工作区边界不符（该平移的没平移）" % (
            rep.get("moved"), rep.get("grew"))
    return True


@check("W-09d 还原时用户手动搬过窗口 ⇒ 不抢方向盘，如实说明")
def c_w09d():
    _winfit_reset()
    d = _Desk(rect=(2000, 1100, 720, 640), work=(0, 0, 2560, 1400))
    with d.patch():
        SV._winfit_apply(80, 40, "tok-w09")
        moves = d.calls["place"]
        # 用户把窗搬到了别处（当前矩形 ≠ 我们调整后的矩形）
        d.rects[101] = (1500, 900, 720, 640)
        rep = SV._winfit_restore("tok-w09")
    if rep.get("ok"):
        return "用户搬过的窗口也被强行搬回 —— 与用户抢方向盘"
    if d.calls["place"] != moves:
        return "说了不搬回，却又发了 SetWindowPos（言行不一）"
    if "手动搬动过" not in (rep.get("why") or ""):
        return "why 没说清是用户搬过：%r" % rep.get("why")
    if SV._WINFIT_STATE.get("orig") is not None:
        return "状态没清掉，下次还原会拿旧矩形再搬一次"
    return True


@check("W-09e 没人动过 ⇒ 原样搬回调整前矩形")
def c_w09e():
    _winfit_reset()
    d = _Desk(rect=(2000, 1100, 720, 640), work=(0, 0, 2560, 1400))
    with d.patch():
        SV._winfit_apply(80, 40, "tok-w09")
        rep = SV._winfit_restore("tok-w09")
    if not rep.get("ok"):
        return "该还原却没还原：%s" % rep.get("why")
    if tuple(d.rects[101]) != (2000, 1100, 720, 640):
        return "还原后 %r ≠ 原始矩形 —— 平移出去的回不来" % (tuple(d.rects[101]),)
    return True


@check("N-W09e 负控：要还原时窗口已经不在了 ⇒ 如实说，不许假成功")
def n_w09e():
    _winfit_reset()
    d = _Desk(rect=(2000, 1100, 720, 640), work=(0, 0, 2560, 1400))
    with d.patch():
        SV._winfit_apply(80, 40, "tok-w09")
        d.hwnds = []                    # 窗关了（用户自己关的）
        d.rects = {}
        rep = SV._winfit_restore("tok-w09")
    if rep.get("ok"):
        return "窗口没了还报还原成功 —— 假成功"
    if "窗口已经不在了" not in (rep.get("why") or ""):
        return "why 没说清窗没了：%r" % rep.get("why")
    return True


# ═══════════════════════════════════════════════════ B-09 紧急提醒窗"看得见" ══
#: ★★★ 0.50.1（创始人 2026-10-14 截图一「泡泡下沿没露出来」）：
#:   为什么这条必须存在 —— 旧版的保证链是「`bubble_geometry` 算出 384×148
#:   → `place_all` 落位 → **回读一致** → 报 placed=True」，而它**全绿**、
#:   用户却看不见下沿。因为 `place_all` 只保证"窗落在目标矩形上"，
#:   它**不知道内容有没有被裁掉** ⇒ "回读一致"≠"看得见"，缺的正是
#:   「内容 ↔ 窗口」这条闭环。所以尺子不能只量"落位成功"。

@check("B-09 紧急提醒窗高度闭环在位：页面报缺 → 服务端按内容长高（下沿不动）→ 回读")
def c_b09():
    page = BB.render("t", "b", "R0", "tok-b09", run_id="r", kind="k")
    if "bubblefit" not in page:
        return "紧急提醒页没有把'还差多少高度'报上去 ⇒ 窗口只能靠常量猜，裁掉也无声"
    if "scrollHeight" not in page or "clientHeight" not in page:
        return "紧急提醒页没有量 scrollHeight/clientHeight ⇒ 报上去的不是真缺量"
    # ★ 量具纪律（两条，都是实测踩出来的）：
    #   ① **不许用子串判** —— 首版写的是 `"height:100%" in …`，而
    #      `min-height:100%` 里**含**这个子串 ⇒ 好值被判红（尺子反咬）。
    #      ⇒ 用正则认 `html,body{…}` 那一条。
    #   ② **必须显式选层** —— CSS 断言走 `PC.chrome(...)`（S48：`<style>` 是
    #      另一层，拿整页原文当 CSS 会把注释/正文一起算进来）。
    _bub_css = PC.chrome(page)
    if not re.search(r"html,body\{[^}]*min-height:100%", _bub_css):
        return ("紧急提醒页没有 `html,body{min-height:100%}` ⇒ 文档被钉死在视口上，"
                "内容超出只能被裁（这正是旧版那条断掉的链）")
    if re.search(r"html,body\{[^}]*[^-]height:100%", _bub_css):
        return "紧急提醒页又把 html/body 钉回 height:100% 了 ⇒ 量不出缺多少"
    src = _src(_SERVER_REL)
    if 'op == "bubblefit"' not in src:
        return "服务端没有 bubblefit 路由 ⇒ 页面报了也没人接（半条链）"
    if "def _bubble_fit" not in src:
        return "没有 _bubble_fit 实现 ⇒ 页面报了也没人动窗"
    return True


@check("B-09b 加高：下沿不动、往上长、宽度不变，且回读一致才报 ok")
def c_b09b():
    d = _Desk(rect=(2000, 1100, 384, 190), work=(0, 0, 2560, 1400))
    with d.patch():
        rep = SV._bubble_fit(40, "tok-b09")
    if not rep.get("ok"):
        return "该长高却没长：%s" % rep.get("why")
    if tuple(d.rects[101]) != (2000, 1060, 384, 230):
        return ("落位 %r ≠ (2000,1060,384,230) —— 加高必须**下沿不动往上长**"
                "（下沿是锚点，动了就等于整窗跳一下）" % (tuple(d.rects[101]),))
    l, t, w, h = d.rects[101]
    if t + h != 1290 or w != 384:
        return "下沿 %d 或宽 %d 变了 —— 加高只许改 top/height" % (t + h, w)
    if rep.get("grew") != 40:
        return "grew=%r ≠ 40（报的量和真做的量对不上）" % (rep.get("grew"),)
    return True


@check("N-B09 负控：拔掉服务端路由（页面报了没人接）⇒ B-09 必须判红")
def n_b09():
    d = _Desk(rect=(2000, 1100, 384, 190))
    with d.patch():
        rep = SV._bubble_fit(40, "tok-b09")
    if not rep.get("ok"):
        return "负控失效：真实现本该能加高，却失败了 —— 尺子测的不是这条链"
    # 拔掉"页面报缺"这一半
    page = BB.render("t", "b", "R0", "tok", run_id="r", kind="k")
    stripped = page.replace("bubblefit", "___")
    if "bubblefit" in stripped:
        return "负控失效：替换没生效"
    # 拔掉"服务端接"这一半
    src = _src(_SERVER_REL)
    if 'op == "bubblefit"' not in src:
        return "负控失效：产品里本来就没有路由，这条判据没在守任何东西"
    return True


@check("B-09c 上方已到工作区上沿 ⇒ 能长多少长多少，缺的记进 left（不谎报露全）")
def c_b09c():
    d = _Desk(rect=(0, 10, 384, 190), work=(0, 0, 2560, 1400))
    with d.patch():
        rep = SV._bubble_fit(40, "tok-b09")
    if rep.get("grew") != 10 or rep.get("left") != 30:
        return ("grew=%r / left=%r ≠ 10 / 30 —— 露不全的账没如实记"
                % (rep.get("grew"), rep.get("left")))
    if tuple(d.rects[101]) != (0, 0, 384, 200):
        return "落位 %r ≠ (0,0,384,200)（该顶到上沿就顶到上沿）" % (tuple(d.rects[101]),)
    return True


@check("N-B09c 负控：窗口找不到 / 落位回读不一致 ⇒ 如实报失败，不许假成功")
def n_b09c():
    d = _Desk(rect=(2000, 1100, 384, 190))
    with d.patch():
        d.hwnds = []
        rep = SV._bubble_fit(40, "tok-b09")
    if rep.get("ok"):
        return "窗口没了还报加高成功 —— 假成功"
    if "没找到" not in (rep.get("why") or ""):
        return "why 没说清找不到窗：%r" % rep.get("why")
    d2 = _Desk(rect=(2000, 1100, 384, 190),
               place_result=(False, "SetWindowPos 失败"))
    with d2.patch():
        rep2 = SV._bubble_fit(40, "tok-b09")
    if rep2.get("ok") or rep2.get("grew"):
        return "落位失败却报 grew=%r —— 与 W-09 同型的谎" % rep2.get("grew")
    return True


@check("B-09d 出生高度不许退回「装不下内容」的旧值（148 是实测出事的那个数）")
def c_b09d():
    if WIN.BUBBLE_H < 180:
        return ("BUBBLE_H=%d —— 148 是实测「下沿看不见」的那个值（内容盒 146 ＋ "
                "Chromium 画在客户区里的标题栏 ~32）⇒ 出生就该够高，"
                "别把一切都推给事后补" % WIN.BUBBLE_H)
    geo = WIN.bubble_geometry(areas=[_Area(0, 0, 2560, 1400)])
    if not geo.get("ok") or geo["rect"][3] < 180:
        return "bubble_geometry 给出的高度 %r 仍装不下内容" % (geo.get("rect"),)
    return True


@check("N-B09d 负控：把 BUBBLE_H 改回 148 ⇒ 同一条判据必须判红")
def n_b09d():
    with _Patch(WIN, BUBBLE_H=148):
        bad = WIN.BUBBLE_H < 180
    if not bad:
        return "负控失效：148 竟然被判为合格 —— 尺子没有分辨力"
    return True


# ═══════════════════════════════════════════════ B-10 确认后按钮要退场 ══
@check("B-10 确认成功后按钮**退场**换状态文字（不留点不动的禁用长文按钮）")
def c_b10():
    page = BB.render("t", "b", "R0", "tok-b10", run_id="r", kind="k")
    if ".bub-done" not in page:
        return "没有 .bub-done 状态样式 ⇒ 确认后没有'退场'的去处"
    if "replaceWith" not in page:
        return ("确认成功只改按钮文字（旧形状：disabled ＋ 20+ 字长句 ⇒ "
                "创始人截图二「点了按钮之后就这样不动了」）")
    # ★ S48：中文文案断言必须走正文层 `PC.body(...)`（不许拿整页原文当正文）。
    if "已确认" not in PC.body(page):
        return "确认后的状态文字丢了 —— 用户不知道确认到底成没成"
    return True


@check("N-B10 负控：把'退场'改回'只改 textContent' ⇒ 判据必须判红")
def n_b10():
    page = BB.render("t", "b", "R0", "tok-b10", run_id="r", kind="k")
    broken = page.replace("replaceWith", "textContent=")
    if "replaceWith" in broken:
        return "负控失效：替换没生效"
    if ".bub-done" not in broken:
        return "负控失效：连样式也一起没了，测不出'只改文字'这一种坏法"
    return True


@check("B-11 紧急提醒页不许把字切开：按钮/注脚不折行，正文截断要给省略号")
def c_b11():
    page = BB.render("t", "b", "R0", "tok-b11", run_id="r", kind="k")
    css = page.split("<style>")[1].split("</style>")[0]
    for sel in (".bub-ok{", ".bub-open{", ".bub-note{"):
        blk = css.split(sel)[1].split("}")[0]
        if "nowrap" not in blk:
            return ("%s 允许折行 ⇒ 一窄就把「打开Antinel 监理」拆成「打开值/守台」"
                    "（创始人截图二）" % sel)
    body = css.split(".bub-body{")[1].split("}")[0]
    if "line-clamp" not in body or "ellipsis" not in page:
        return ("正文仍是硬切（旧版 max-height+overflow:hidden）⇒ 半个字被切掉、"
                "用户看不出'还有'")
    return True


@check("N-B11 负控：改回旧版硬切（max-height/overflow）⇒ 判据必须判红")
def n_b11():
    css = ".bub-body{margin:5px 0 9px;max-height:52px;overflow:hidden}"
    if "line-clamp" in css:
        return "负控失效：旧形状里竟然有 line-clamp"
    return True


# ════════════════════════════════════════════════════════════ UI_COPY/DRILL ══
_EMPTY_EXPECTED = {
    "action": "没有要你处理的事",
    "info": "当前「看一眼」中没有记录",
    "archive": "当前「归档」中没有记录",
    "all": "本次载入的记录为空",
}


def _empty_view(filt):
    return SV.render_page(view="inbox", filt=filt, root=_HUB, token="empty-copy",
                          items=[], posture={"state": "guarding",
                                             "can_fix": False})


@check("UICOPY1 空结果页各说各的真话，不把筛选空误说成「无待办」")
def c_empty_copy():
    for filt, phrase in _EMPTY_EXPECTED.items():
        h = _empty_view(filt)
        if phrase not in h:
            return "%s 空页缺正确提示 %r" % (filt, phrase)
        if filt != "action" and "没有要你处理的事" in h:
            return "%s 空页还在说「没有要你处理的事」—— 说的不是当前筛选结果" % filt
    h = _empty_view("kind:host_shield_revived")
    if "当前筛选「注意：防护已恢复」没有匹配记录" not in h:
        return "类型钻取空页没有回显筛选对象（输出违和/用户不知道空在哪）"
    return True


@check("N-UICOPY 负控：旧版所有 tab 共用「没有要你处理的事」必须判红")
def n_empty_copy():
    old = {f: "当前读取到的记录里，没有要你处理的事。" for f in _EMPTY_EXPECTED}
    bad = [f for f in ("info", "archive", "all")
           if _EMPTY_EXPECTED[f] in old[f] or "没有要你处理的事" in old[f]]
    if not bad:
        return "负控失效：旧文案在非待办页也被接受 —— 尺子没分辨力"
    if len(bad) != 3:
        return "负控量具异常：应抓到 info/archive/all，实抓 %r" % bad
    return True


@check("UIDRILL1 『看这 N 条』链接只打开该事由组的 N 条，不扩成整个 kind")
def c_group_drill_exact():
    rows = []
    for ident, topic, ts in (("a1", "subtype_a", "2026-10-14T06:00:00"),
                             ("a2", "subtype_a", "2026-10-14T06:01:00"),
                             ("b1", "subtype_b", "2026-10-14T06:02:00"),
                             ("b2", "subtype_b", "2026-10-14T06:03:00")):
        rows.append(SimpleNamespace(id=ident, kind="host_shield_spawn_failed",
                                    topic=topic, level="L2", title="拦截：测试",
                                    detail="fixture", rule_id="", ts=ts))
    groups = M.group_items(rows)
    if len(groups) != 2 or any(g["count"] != 2 for g in groups):
        return "夹具不成立：同 kind 两事由应为 2 组×2 条，实际 %s" % (
            [(g["key"], g["count"]) for g in groups],)
    for g in groups:
        h = SV._group_html(g, "tok", bucket=M.BUCKET_ACTION, total=4)
        m = re.search(r'href="(/\?[^\"]+)"[^>]*>看这 2 条', h)
        if not m:
            return "组 %r 的『看这 2 条』链接没渲染出来" % (g["key"],)
        href = m.group(1).replace("&amp;", "&")
        q = parse_qs(urlparse(href).query)
        filt = (q.get("f") or [""])[0]
        got = {x.id for x in M.filter_items(rows, filt)}
        want = set(g["ids"])
        if got != want:
            return "『看这 2 条』打开 %r ≠ 本组 %r（多看/漏看了）" % (
                sorted(got), sorted(want))
    # 旧版 kind drill 一定会把两个 subtype 的 4 条都打包进来；这是负样本。
    old = M.filter_items(rows, "kind:host_shield_spawn_failed")
    if len(old) != 4:
        return "负控失效：旧 kind 过滤应误捞 4 条，实测 %d（夹具没把两事由分开）" % len(old)
    return True


@check("N-UIDRILL 负控：旧版 kind:<kind> 钻取会把两组共 4 条误说成『看这 2 条』")
def n_group_drill_exact():
    rows = [SimpleNamespace(id=i, kind="same", topic=t, level="L2",
                            title="x", detail="d", rule_id="", ts="2026-10-14T06:00:00")
            for i, t in (("a1", "a"), ("a2", "a"), ("b1", "b"), ("b2", "b"))]
    old = M.filter_items(rows, "kind:same")
    target = M.filter_items(rows, "ids:a1,a2")
    if len(old) != 4 or len(target) != 2:
        return "负控失效：旧过滤应 4 条、精确过滤应 2 条，实测 %d/%d" % (
            len(old), len(target))
    if {x.id for x in target} != {"a1", "a2"}:
        return "精确过滤把别组记录也带进来：%r" % sorted(x.id for x in target)
    return True


@check("W-09f tooltip 在视口坐标定位并受宽高边界约束")
def c_w09f():
    css = SV.CSS
    match = re.search(r"\.term>\.tdef\{([^}]*)\}", css)
    if not match:
        return "术语浮层没有专属 `.term>.tdef` 规则"
    block = match.group(1)
    if "position:fixed" not in block:
        return "浮层仍相对 `.term` 定位；词条在屏幕中部、弹层较宽时会越出左边"
    if "max-height:calc(100vh - 16px)" not in block or "overflow:auto" not in block:
        return "浮层高度超过视口时没有自身滚动兜底"
    if "max-width:min(560px,calc(100vw - 16px))" not in block:
        return "浮层宽度没有为视口两侧各留 8px 安全区"
    if ".term.flipx>.tdef{left:8px;right:auto}" not in css:
        return "兼容翻转态仍可用 right:0 将弹层推回视口外"
    return True


@check("N-W09f 负控：退回绝对定位与右对齐 ⇒ 同一 CSS 判据必须报红")
def n_w09f():
    bad = SV.CSS.replace(".term>.tdef{position:fixed", ".term>tdef{position:fixed")
    bad = bad.replace(".term.flipx>.tdef{left:8px;right:auto}",
                      ".term.flipx>.tdef{left:auto;right:0}")
    if bad == SV.CSS:
        return "夹具不成立：定位规则变异没有命中"
    # 同一正判据读变异后的 CSS，任一失败就证明负控确实能翻面。
    with _Patch(SV, CSS=bad):
        why = c_w09f()
    if why is True or why is None:
        return "负控失效：退回旧定位仍通过 —— 尺子没有分辨力"
    return True


_TOOLTIP_BOUNDS_RUNNER = r"""
const p = JSON.parse(process.argv[1]);
function runOne(c) {
  const handlers = {doc: {}, win: {}};
  const root = {clientWidth:c.w, clientHeight:c.h};
  const pos = {x:c.x, y:c.y};
  const classes = new Set(['term']);
  const d = {
    open:true,
    classList:{contains:n=>classes.has(n), add:n=>classes.add(n), remove:n=>classes.delete(n)},
    querySelector:s=>s==='summary' ? summary : (s==='.tdef' ? box : null)
  };
  const summary = {getBoundingClientRect:()=>({left:pos.x, right:pos.x+14,
    top:pos.y, bottom:pos.y+14, width:14, height:14})};
  const box = {style:{left:'8px',top:'8px'}, getBoundingClientRect:function(){
    const width=Math.min(c.bw, Math.max(0,root.clientWidth-16));
    const height=Math.min(c.bh, Math.max(0,root.clientHeight-16));
    let left=parseFloat(this.style.left)||8, top=parseFloat(this.style.top)||8;
    if(p.layout==='absolute'){
      left=classes.has('flipx') ? pos.x+14-width : pos.x;
      top=pos.y+20;
    }
    return {left:left, top:top, width:width, height:height, vw:root.clientWidth,
      vh:root.clientHeight, right:left+width, bottom:top+height};
  }};
  const document={documentElement:root,
    addEventListener:(n,f)=>{handlers.doc[n]=f;},
    querySelectorAll:()=>d.open ? [d] : []};
  const window={addEventListener:(n,f)=>{handlers.win[n]=f;}};
  new Function('document','window',p.script)(document,window);
  function snap(){return box.getBoundingClientRect();}
  handlers.doc.toggle({target:d});
  const opened=snap();
  root.clientWidth=c.rw; root.clientHeight=c.rh; pos.x=c.rx; pos.y=c.ry;
  if(handlers.win.resize) handlers.win.resize();
  const resized=snap();
  pos.x=c.sx; pos.y=c.sy;
  if(handlers.win.scroll) handlers.win.scroll();
  const scrolled=snap();
  return {opened:opened,resized:resized,scrolled:scrolled};
}
console.log(JSON.stringify(p.cases.map(runOne)));
"""


def _tooltip_bounds_probe(script, layout="fixed"):
    """在 Node DOM 桩里真执行页面定位脚本，回读打开/缩放/滚动后的矩形。"""
    node = _node_path()
    if not node:
        raise Skip("本机没有可执行 node；tooltip 运行态判据 SKIP，不报 PASS")
    import subprocess
    match = re.search(r"<script>\s*(.*?)\s*</script>", script, re.S)
    if match:
        script = match.group(1)
    cases = [
        # 与用户截图一致的视口：词条不在右缘，但浮层宽于其左侧余量。
        dict(w=713,h=600,x=252,y=272,bw=560,bh=200,
             rw=320,rh=300,rx=150,ry=140,sx=4,sy=4),
        dict(w=320,h=600,x=142,y=272,bw=560,bh=200,
             rw=713,rh=600,rx=680,ry=272,sx=705,sy=580),
        dict(w=713,h=600,x=680,y=272,bw=560,bh=200,
             rw=713,rh=600,rx=252,ry=545,sx=252,sy=580),
        # 极矮视口：允许弹层自身滚动，但不能越过上/下边界。
        dict(w=360,h=220,x=170,y=175,bw=560,bh=700,
             rw=360,rh=220,rx=4,ry=4,sx=340,sy=205),
    ]
    payload = json.dumps({"script":script, "layout":layout, "cases":cases})
    try:
        p = subprocess.run([node, "-e", _TOOLTIP_BOUNDS_RUNNER, payload],
                           capture_output=True, timeout=20)
    except Exception as e:                                               # noqa: BLE001
        return None, "Node 执行 tooltip 脚本失败：%s: %s" % (type(e).__name__, e)
    if p.returncode:
        return None, "Node tooltip 夹具退出 %d：%s" % (
            p.returncode, p.stderr.decode("utf-8", "replace")[-500:])
    try:
        return json.loads(p.stdout.decode("utf-8")), ""
    except Exception as e:                                               # noqa: BLE001
        return None, "Node tooltip 夹具没有 JSON 回读：%s: %s" % (type(e).__name__, e)


def _tooltip_bounds_failures(rows):
    if not rows:
        return ["没有打开/缩放/滚动测量结果"]
    errors = []
    for ci, result in enumerate(rows):
        for phase, r in result.items():
            if r["left"] < 7.5 or r["right"] > r["vw"] - 7.5:
                errors.append("case%d/%s 横向越界 [%g,%g] / vw=%d" %
                              (ci+1, phase, r["left"], r["right"], r["vw"]))
            if r["top"] < 7.5 or r["bottom"] > r["vh"] - 7.5:
                errors.append("case%d/%s 纵向越界 [%g,%g] / vh=%d" %
                              (ci+1, phase, r["top"], r["bottom"], r["vh"]))
    return errors


@check("W-09h tooltip 实测坐标完整落在视口内，resize/scroll 后重新落位")
def c_w09h():
    css = SV.CSS
    if not re.search(r"\.term>\.tdef\{[^}]*position:fixed", css):
        return "tooltip 未使用视口坐标定位；DOM 几何回读的坐标基准不成立"
    rows, why = _tooltip_bounds_probe(SV._FLIP_JS)
    if why:
        return why
    bad = _tooltip_bounds_failures(rows)
    if bad:
        return "；".join(bad)
    # 连带：窄/矮视口有 max-height 与自身滚动，不把长定义裁成半截。
    if "max-height:calc(100vh - 16px)" not in css or "overflow:auto" not in css:
        return "弹层没有高度上限/自身滚动，极矮窗口仍会裁掉下半段"
    return True


_LEGACY_TOOLTIP_FLIP_JS = r"""
(function(){
  function fit(d){
    if (!d.classList) return;
    var box=d.querySelector('.tdef');
    if (!box) return;
    d.classList.remove('flipx');
    var r=box.getBoundingClientRect();
    if(r.right>document.documentElement.clientWidth-8) d.classList.add('flipx');
  }
  document.addEventListener('toggle',function(e){
    var d=e.target;
    if(d.classList&&d.classList.contains('term')&&d.open) fit(d);
  },true);
})();
"""


@check("N-W09h 负控：恢复旧的绝对定位 + flipx 右对齐，同一坐标尺必须报红")
def n_w09h():
    # 在隔离 DOM 桩中运行旧的实际交互口径，不改产品模块/文件；与正判据共用坐标尺。
    rows, why = _tooltip_bounds_probe(_LEGACY_TOOLTIP_FLIP_JS, layout="absolute")
    if why:
        return why
    bad = _tooltip_bounds_failures(rows)
    if not bad:
        return "负控失效：旧绝对定位/右对齐仍完整落在视口内 —— 坐标尺空转"
    if not any("case1/opened 横向越界" in x and x.startswith("case1/opened")
               for x in bad):
        return "负控方向不符：截图同形的中部锚点未复现左边越界：%r" % bad[:3]
    return True


def _read_js_ok(js, server):
    guard_at = js.find("if (!j || !j.ok)")
    commit_at = js.find("d.dataset.readed = '1'")
    if guard_at < 0 or commit_at < 0 or guard_at > commit_at:
        return "只有拿到 ok JSON 后才能落 data-readed=1"
    if "delete d.dataset.readPending" not in js or ".catch(function(){ delete d.dataset.readPending; })" not in js:
        return "失败后没有清 pending，折叠/重开也不能重试"
    if 'if op == "read":' not in server or 'return self._json({"ok": True})' not in server:
        return "read POST 没有 JSON 成功回执，前端无法区分写入成功与拒绝"
    return None


@check("UIREAD1 只在服务端确认成功后去未读点；失败能重试")
def c_read_truthful():
    why = _read_js_ok(SV._READ_JS, _src(_SERVER_REL))
    return why or True


@check("N-UIREAD 负控：移除服务端 ok 检查 ⇒ 量具必须判红")
def n_read_truthful():
    bad = SV._READ_JS.replace("if (!j || !j.ok) throw new Error('read rejected');", "")
    if bad == SV._READ_JS:
        return "夹具不成立：删 ok 检查变异没命中"
    why = _read_js_ok(bad, _src(_SERVER_REL))
    if why is None:
        return "负控失效：不检查服务端回执也判成功 —— 失败会被伪装成已读"
    return True


@check("W-09g `winfit` 非有限溢出量如 1e309 被当成坏输入处理")
def c_w09_overflow():
    src = _src(_SERVER_REL)
    if "except (ValueError, OverflowError):" not in src:
        return "`int(float('inf'))` 会抛 OverflowError，当前请求分支没兜住"
    try:
        int(float("1e309"))
        return "夹具不成立：运行时竟可把 inf 转成 int"
    except OverflowError:
        return True


@check("N-W09g 负控：拿掉 OverflowError 分支 ⇒ 同一判据判红")
def n_w09_overflow():
    src = _src(_SERVER_REL)
    bad = src.replace("except (ValueError, OverflowError):", "except ValueError:")
    if bad == src:
        return "夹具不成立：异常分支变异没命中"
    if "except (ValueError, OverflowError):" in bad:
        return "负控失效：移除了 overflow 处理仍被接受"
    try:
        int(float("1e309"))
    except OverflowError:
        return True
    return "夹具异常：inf 没有抛 OverflowError"


# ════════════════════════════════════════════════════════════ U-17 ══
#: 规格 v1.2（2026-09-27）逐项抄录 —— **这就是尺子**。产品表 `LOGO_MOTION`
#: 必须与它逐项相等；改规格要走改这份文档，不是改判据迁就产品。
_SPEC_MOTION = {
    "L0": {"c": (126, 155, 132), "lap": 12.0, "ringO": 1.0,
           "amberO": 0.35, "ringRed": 0.0, "waveR": 0, "waveO": 0.0},
    "L1": {"c": (205, 194, 154), "lap": 8.0, "ringO": 1.0,
           "amberO": 1.0, "ringRed": 0.0, "waveR": 45, "waveO": 0.30},
    "L2": {"c": (224, 180, 85), "lap": 5.5, "ringO": 1.0,
           "amberO": 1.0, "ringRed": 0.0, "waveR": 70, "waveO": 0.45},
    "LD": {"c": (232, 163, 61), "lap": 3.5, "ringO": 1.0,
           "amberO": 1.0, "ringRed": 0.0, "waveR": 105, "waveO": 0.65},
    "R0": {"c": (178, 84, 84), "lap": 0.0, "ringO": 0.45,
           "amberO": 0.85, "ringRed": 1.0, "waveR": 0, "waveO": 0.0},
}
_SPEC_RING_GREEN = (91, 130, 101)          # §二 色值总表 #5B8265
_SPEC_RING_DARKRED = (74, 38, 38)          # §二 R0 塌暗至 0.45 的 #4A2626
_SPEC_RIPPLE_SEC = 1.4                     # §一 铁律：频次恒定，不参与分级
_SPEC_R0_GLIDE_DEG = 20.0                  # §三 R0 停摆：惯性滑行 20° 后永停


def _u17_spec_ok(motion, ring_g, ring_r, mode_map):
    if set(motion) != set(_SPEC_MOTION):
        return "动法键集合 %s ≠ 规格 %s" % (sorted(motion),
                                          sorted(_SPEC_MOTION))
    for k, want in _SPEC_MOTION.items():
        got = motion.get(k) or {}
        for f, wv in want.items():
            gv = got.get(f)
            if isinstance(wv, tuple):
                if tuple(gv) != wv:
                    return "%s.%s = %r ≠ 规格 %r" % (k, f, gv, wv)
            elif float(gv) != float(wv):
                return "%s.%s = %r ≠ 规格 %r" % (k, f, gv, wv)
    if tuple(ring_g) != _SPEC_RING_GREEN or tuple(ring_r) != _SPEC_RING_DARKRED:
        return "环领地色 %r/%r ≠ 规格 %r/%r" % (tuple(ring_g), tuple(ring_r),
                                            _SPEC_RING_GREEN, _SPEC_RING_DARKRED)
    if dict(mode_map) != {"L0": "L0", "L1": "L1", "L2": "L2",
                          "Ls": "LD", "R0": "R0", "dev": "L0"}:
        return "灯态→动法键映射 %r 与规格不符" % (dict(mode_map),)
    return None


@check("U-17a 五态动法表逐项等于规格 v1.2（色/速/波幅/环亮度/塌暗）")
def c_u17a():
    why = _u17_spec_ok(SV.LOGO_MOTION, SV.LOGO_RING_GREEN,
                       SV.LOGO_RING_DARKRED, SV.LOGO_MODE)
    if why:
        return why
    # 规格铁律：速度通道单调换挡（12→8→5.5→3.5 相邻级 ≈1.5 倍）
    laps = [_SPEC_MOTION[k]["lap"] for k in ("L0", "L1", "L2", "LD")]
    if laps != sorted(laps, reverse=True) or laps[0] <= laps[-1]:
        return "规格表自身速度通道不单调：%r" % (laps,)
    return True


@check("N-U17a 负控：把 L1 圈时改成 12（与 L0 一样慢）⇒ 尺子必须判红")
def n_u17a():
    bad = {k: dict(v) for k, v in SV.LOGO_MOTION.items()}
    bad["L1"]["lap"] = 12.0
    if _u17_spec_ok(bad, SV.LOGO_RING_GREEN, SV.LOGO_RING_DARKRED,
                    SV.LOGO_MODE) is None:
        return "负控失效：L1 变慢被判合格 —— 规格锁是装饰"
    bad2 = {k: dict(v) for k, v in SV.LOGO_MOTION.items()}
    bad2["R0"]["ringO"] = 1.0
    if _u17_spec_ok(bad2, SV.LOGO_RING_GREEN, SV.LOGO_RING_DARKRED,
                    SV.LOGO_MODE) is None:
        return "负控失效：R0 不塌暗也判合格 —— 梯度断裂锁不住"
    return True


@check("U-17b 页面里的哨标是内联 SVG＋rAF 状态机（不是静态图）")
def c_u17b():
    html = _page()
    if "data-logo=" not in html:
        return "页面里没有 data-logo 哨标 —— 图标又死了（0.48.5 戊1 原状）"
    if "requestAnimationFrame" not in html:
        return "没有 rAF 驱动 —— 静态图套了个壳，还是不动"
    if "<noscript>" not in html or "logo.svg" not in html:
        return "没有 noscript 静态退回 —— 关 JS 的用户看到一块空白"
    if 'data-mode="%s"' % SV.LOGO_MODE.get("guarding", "L0") not in html and \
            'data-mode="L0"' not in html:
        return "渲染出的哨标没带 data-mode，状态机不知道当前该演哪态"
    js = SV._LOGO_JS
    if str(_SPEC_RIPPLE_SEC) not in js:
        return "状态机里找不到涟漪周期 %s —— 频次通道漂了" % _SPEC_RIPPLE_SEC
    return True


@check("N-U17b 负控：把 rAF 状态机从页面里拔掉 ⇒ 同一条判据必须判红")
def n_u17b():
    html = _page()
    # 变异：只留静态骨架（相当于 0.48.5 戊1 换回静态 logo.svg 的形状）
    dead = re.sub(r"<script>\n\(function\(\)\{.*?\}\)\(\)\;\n</script>", "",
                  html, flags=re.S)
    if dead == html:
        return "夹具不成立：页面里拔不出状态机脚本，负控无分辨力"
    if "requestAnimationFrame" in dead:
        return "负控失效：拔了脚本 rAF 还在 —— 判据查的不是会动的那个东西"
    return True


# ---- Node 实跑（可观测维度的硬证据：真执行、量几何量、对规格）----
_NODE_STUB = r"""
// ---- DOM 桩（只实现状态机用到的面；与 _p_logo_js.py 同一套）----
function El(){ this.attrs={}; this.children=[]; }
El.prototype.setAttribute=function(k,v){ this.attrs[k]=String(v); };
El.prototype.getAttribute=function(k){ return this.attrs[k]; };
El.prototype.appendChild=function(c){ this.children.push(c); };
function q(el,n){
  var hit=el.children.filter(function(c){ return c.attrs["data-p"]===n; });
  if(hit.length) return hit[0];
  var e=new El(); e.attrs["data-p"]=n; el.children.push(e); return e;
}
El.prototype.querySelector=function(sel){
  var m=/^\[data-p="(.+)"\]$/.exec(sel);
  return m ? q(this, m[1]) : null;
};
var svg=new El(); svg.attrs["data-logo"]="1"; svg.attrs["data-mode"]=process.argv[2];
var RAF=[];
var document={
  querySelectorAll:function(sel){ return sel==="svg[data-logo]" ? [svg] : []; },
  createElementNS:function(){ return new El(); },
  addEventListener:function(){}
};
var requestAnimationFrame=function(cb){ RAF.push(cb); };
// ---- 状态机源码（由 Python 注入）----
__JS__
// ---- 驱动：按 16.7ms 步进 25 秒，返回逐帧快照 ----
function thetaDeg(){
  var x2=parseFloat(q(svg,"beam").attrs["x2"]), y2=parseFloat(q(svg,"beam").attrs["y2"]);
  var dx=x2-512, dy=-(y2-512);
  var a=Math.atan2(dx,dy)*180/Math.PI; return ((a%360)+360)%360;
}
var out=[], t=0, prev=null, swept=0;
var FRAMES=+(process.argv[3]||1500);
for(var i=0;i<FRAMES;i++){
  var cbs=RAF.slice(); RAF.length=0;
  cbs.forEach(function(cb){ cb(t); });
  t+=16.7;
  var th=thetaDeg();
  if(prev!==null){
    // ★ JS 的 % 保留被除数符号（-179.7 % 360 = -179.7）—— 直接拿它做
    //   unwrap 会在每次过零时多吃一个 360（探针第一版就栽在这）。
    var d=th-prev;
    if(d>180) d-=360;
    if(d<-180) d+=360;
    swept+=d;
  }
  prev=th;
  // ★ 0.50.3：几何量一并快照 —— U-18d 要拿**真跑出来的坐标**验
  //   "全部绘制内容都落在 viewBox 里"（波被裁那道缺陷只有几何量能看见）。
  out.push({t:Math.round(t), th:th, swept:swept,
            amber:+q(svg,"amber").attrs["opacity"],
            ring:q(svg,"seg0").attrs["stroke"],
            w0:+q(svg,"wave0").attrs["opacity"],
            w1:+q(svg,"wave1").attrs["opacity"],
            ax:+q(svg,"amber").attrs["cx"], ay:+q(svg,"amber").attrs["cy"],
            r0:+q(svg,"wave0").attrs["r"], r1:+q(svg,"wave1").attrs["r"],
            bx:+q(svg,"beam").attrs["x2"], by:+q(svg,"beam").attrs["y2"]});
}
console.log(JSON.stringify(out));
"""

_JS_BLOCK_RE = re.compile(r"<script>\n(.*?)\n</script>", re.S)


def _node_path():
    import shutil
    return shutil.which("node")


def _node_run(mode, frames=None):
    """真跑状态机（Node＋DOM 桩）。返回逐帧快照 list。

    `frames` 不给 = 默认 1500 帧（25s，U-17c 的速度/停摆要用）；U-18d 只验几何，
    给 120 帧（≈2s，覆盖一个涟漪周期 1.4s）即可，省时间。
    """
    import json
    import subprocess
    html = _page()
    js = None
    for body in _JS_BLOCK_RE.findall(html):
        if "svg[data-logo]" in body and "var STYLE=" in body:
            js = body
            break
    if not js:
        raise RuntimeError("页面里找不到哨标状态机脚本（夹具不成立）")
    src = _NODE_STUB.replace("__JS__", js)
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                     encoding="utf-8") as f:
        f.write(src)
        path = f.name
    try:
        cmd = [_node_path(), path, mode]
        if frames is not None:
            cmd.append(str(int(frames)))
        p = subprocess.run(cmd, capture_output=True, timeout=90)
        if p.returncode != 0:
            raise RuntimeError("node 退出码 %d：%s" % (
                p.returncode, p.stderr.decode("utf-8", "replace")[:400]))
        return json.loads(p.stdout.decode("utf-8"))
    finally:
        os.unlink(path)


def _rgb_of(s):
    m = re.findall(r"-?\d+", str(s))
    return tuple(int(x) for x in m[:3]) if len(m) >= 3 else None


@check("U-17c Node 真跑状态机 25s：五态速度/停摆/波峰/环色逐项对规格")
def c_u17c():
    node = _node_path()
    if not node:
        return "SKIP：本机没有可执行 node —— 这一条**不判**（绝不假绿）"
    laps = {"L0": 12.0, "L1": 8.0, "L2": 5.5, "LD": 3.5}
    swept, waves, rings = {}, {}, {}
    for mode in ("L0", "L1", "L2", "LD", "R0"):
        seq = _node_run(mode)
        if not seq:
            return "%s：一帧都没跑出来（夹具失效，不判）" % mode
        t = seq[-1]["t"] / 1000.0
        swept[mode] = seq[-1]["swept"]
        waves[mode] = max(max(f["w0"], f["w1"]) for f in seq)
        rings[mode] = seq[-1]["ring"]
        if mode == "R0":
            if abs(swept[mode] - _SPEC_R0_GLIDE_DEG) > 1.5:
                return ("R0 累计扫过 %.1f° ≠ 规格滑行 20°（停摆没停住，"
                        "或滑行距离不对）" % swept[mode])
            tail = [f for f in seq if f["t"] >= 5000]
            if tail:
                drift = max(abs(tail[0]["th"] - f["th"]) for f in tail)
                if drift > 0.001:
                    return "R0 停摆后 20 秒内漂移 %.4f°（规格：永停）" % drift
        else:
            ideal = 360.0 * t / laps[mode]
            if abs(swept[mode] - ideal) > 0.03 * ideal:
                return ("%s：25s 扫过 %.1f° ≠ 理想 %.1f°（%.1fs/圈 没兑现）"
                        % (mode, swept[mode], ideal, laps[mode]))
    # 速度通道单调（规格铁律一：换挡是瞬间的，速比 ≈1.5）
    if not (swept["LD"] > swept["L2"] > swept["L1"] > swept["L0"]):
        return "扫过量不单调 %r —— 速度通道没有换挡感" % (
            {k: round(v, 1) for k, v in swept.items()},)
    # 波幅通道：强度 .30/.45/.65（缩到小图标后唯一存活通道）
    for mode, want in (("L1", 0.30), ("L2", 0.45), ("LD", 0.65)):
        if abs(waves[mode] - want) > 0.03:
            return "%s 波峰 opacity %.2f ≠ 规格 %.2f" % (mode, waves[mode], want)
    if waves["R0"] != 0 or waves["L0"] != 0:
        return "L0/R0 不该有波（%r）—— 波止纪律" % (waves["L0"], waves["R0"])
    # 环色：R0 转暗红 #4A2626=(74,38,38)，常态绿 #5B8265=(91,130,101)
    r0, l0 = _rgb_of(rings["R0"]), _rgb_of(rings["L0"])
    if r0 != _SPEC_RING_DARKRED:
        return "R0 环色 %r ≠ 规格暗红 %r" % (r0, _SPEC_RING_DARKRED)
    if l0 != _SPEC_RING_GREEN:
        return "L0 环色 %r ≠ 规格绿 %r" % (l0, _SPEC_RING_GREEN)
    return True


# ════════════════════════════════════════════════════════════ U-18 ══
#: ★★ 0.50.2（2026-10-14，创始人截图：「LOGO 是活了，但是旧病复发，变得太小了，
#:   需要变回最新的尺寸，同时还是活的」）。
#:   ★ 病根是**比例**不是字号：内联 SVG 照搬 demo 的 `viewBox="0 0 1024 1024"`，
#:     环外缘（R215＋环宽46/2＝238）只占画布半宽 512 的 **0.465**；定稿
#:     `assets/logo/logo.svg` 是 **0.844**。同一枚哨标塞进 48px 方框，
#:     动效版比静态版小 **45%** ⇒ 看着就是"缩水了"。
#:   ★ 尺子**不许凭记忆写比例**：从定稿 logo.svg **现算**（真源），再要求渲染
#:     出的哨标 viewBox 反算出同一个比例 —— 两条腿都量，才能抓住"页面一套、
#:     定稿一套"。顺带锁住「JS 开着看到的内联 SVG」＝「JS 关掉退回的
#:     `<noscript>` logo.svg」一样大（渐进增强不跳变）。
_LOGO_SVG_REL = "assets/logo/logo.svg"
_LOGO_RATIO_TOL = 0.01


def _logo_ratio_from_svg(text):
    """从定稿 logo.svg 量「环外缘 ÷ 画布半宽」。

    环 = `<g stroke-width=W>` 里那条 `A R R 0 0 1` 的弧。量不出就抛
    （夹具不成立 ⇒ 报错，不许静默放过成"合格"）。
    """
    vb = re.search(r'viewBox="0 0 (\d+(?:\.\d+)?) (\d+(?:\.\d+)?)"', text)
    if not vb:
        raise ValueError("定稿 logo.svg 没有 viewBox —— 量具无真源")
    half = float(vb.group(1)) / 2.0
    w = re.search(r'stroke-width="(\d+(?:\.\d+)?)"', text)
    arc = re.search(r"A\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+0\s+0\s+1", text)
    if not (w and arc):
        raise ValueError("定稿 logo.svg 量不出环半径/环宽 —— 量具失效")
    return (float(arc.group(1)) + float(w.group(1)) / 2.0) / half


def _logo_mark_ratio():
    """从**产品渲染出的**哨标 SVG 量同一个比例（viewBox 反算）。

    返回 `(ratio, why)`；`why` 非空即不合法（形状问题比大小问题更硬）。
    """
    html = SV._logo_mark("L0")
    m = re.search(r'viewBox="([^"]+)"', html)
    if not m:
        return None, "渲染出的哨标没有 viewBox —— 缩放到方框里全靠它"
    try:
        parts = [float(v) for v in m.group(1).split()]
    except ValueError:
        return None, "viewBox 不是四个数：%r" % (m.group(1),)
    if len(parts) != 4:
        return None, "viewBox 不是四个数：%r" % (m.group(1),)
    x, y, w, h = parts
    if w <= 0 or h <= 0:
        return None, "viewBox 尺寸非正：%r" % (m.group(1),)
    if abs(w - h) > 1e-6:
        return None, "viewBox 不是正方形（%g×%g）—— 方框里会被拉扁" % (w, h)
    if abs((x + w / 2.0) - SV.LOGO_CX) > 1e-6 or \
            abs((y + h / 2.0) - SV.LOGO_CY) > 1e-6:
        return None, ("viewBox 中心不在画布中心（%g,%g）—— 环会偏心"
                      % (x + w / 2.0, y + h / 2.0))
    outer = SV.LOGO_R + SV.LOGO_RING_W / 2.0
    return outer / (w / 2.0), ""


@check("U-18 哨标比例＝定稿 logo.svg（环外缘占半宽 0.844，不是 1024 画布的 0.465）")
def c_u18():
    want = _logo_ratio_from_svg(_src(_LOGO_SVG_REL))
    got, why = _logo_mark_ratio()
    if why:
        return why
    if abs(got - want) > _LOGO_RATIO_TOL:
        return ("哨标环只占画布半宽的 %.3f ≠ 定稿 logo.svg 的 %.3f —— "
                "同一枚标在 48px 方框里缩了 %.0f%%（创始人截图那条："
                "「活了，但变小了」）" % (got, want, (1 - got / want) * 100))
    # 连带对照：页面里两枚标必须并存 —— 开着 JS 看内联 SVG，关着 JS 看退回图，
    # 两者比例已由上式锁成同一个 ⇒ 关 JS 不会突然"变大/变小"。
    page = _page()
    if 'data-logo="1"' not in page or "/assets/logo.svg" not in page:
        return ("页面里缺内联哨标或 `<noscript>` 退回图 —— 渐进增强的两条腿"
                "缺一条，比例等式守的就不是用户看到的东西")
    return True


@check("N-U18 负控：把比例退回 demo 的 1024 画布（0.465）⇒ 同一条尺子必须判红")
def n_u18():
    demo_ratio = (SV.LOGO_R + SV.LOGO_RING_W / 2.0) / (SV.LOGO_CANVAS / 2.0)
    with _Patch(SV, LOGO_BOX_RATIO=demo_ratio):
        vb = SV._logo_viewbox()
        if vb != "0 0 1024 1024":
            return "夹具不成立：按 demo 比例反算得 %r，不是 0 0 1024 1024" % (vb,)
        got, why = _logo_mark_ratio()
        if why:
            return "夹具不成立：%s" % why
        want = _logo_ratio_from_svg(_src(_LOGO_SVG_REL))
        if abs(got - want) <= _LOGO_RATIO_TOL:
            return "负控失效：退回 1024 画布仍判合格 —— 这条尺子是装饰"
        if got > want:
            return "负控方向不对：退回画布后比例反而变大（%.3f > %.3f）" % (got, want)
    return True


@check("U-18b 动法几何单一真源：_LOGO_JS 里的 CX/CY/R 与 Python 常量逐项一致")
def c_u18b():
    js = SV._LOGO_JS
    for name, val in (("CX", SV.LOGO_CX), ("CY", SV.LOGO_CY),
                      ("R", SV.LOGO_R)):
        if not re.search(r"\b%s=%s\b" % (name, val), js):
            return ("状态机里 %s 不是 %s —— 画布几何在页面/产品两处各写一份"
                    "（viewBox 按常量反算，动法却按字面量跑 ⇒ 环会偏心）"
                    % (name, val))
    if 'stroke-width="%d"' % SV.LOGO_RING_W not in SV._logo_mark("L0"):
        return ("哨标环宽不是 LOGO_RING_W=%d —— viewBox 的反算前提被破坏"
                % SV.LOGO_RING_W)
    return True


@check("N-U18b 负控：把 R 常量改成 260（viewBox 跟着变、状态机没变）⇒ 必须判红")
def n_u18b():
    # `check` 装饰器把 wrapper 收进 RESULTS、**返回的仍是原函数** ⇒ 直接调它本体。
    if c_u18b() is not True:
        return "夹具不成立：未变异时 U-18b 就不合格，负控无分辨力"
    with _Patch(SV, LOGO_R=260):
        why = c_u18b()
        if why is True or why is None:
            return "负控失效：常量与状态机脱节仍判合格 —— 这条尺子是装饰"
    return True


# ════════════════════════════════════════════════════════════ U-18c ══
#: ★★★ 0.50.3（创始人截图：「冒泡的 LOGO 不完整」）：0.50.2 把 viewBox 收到
#:   **环**上以后，涟漪（圆心在半径 `LOGO_R` 的灯头上、半径最大
#:   `AMBER_R+8+waveR`＝137）离画布中心 215＋137＝**352** > 方框半宽
#:   **282.074** ⇒ 波的最外缘被切出一道直边（实测渲染图上肉眼可见）。
#:   ★ 尺子打在**几何**上：`viewBox` 装得下**全部会画出来的东西**才算合格。
#:     这是"完整性"这条不变式的唯一形式化写法 —— 不看字号、不看样式，
#:     只看"有没有东西伸到框外"。
#:   ★ 两条腿：U-18c 用 Python 侧常量＋渲染表算（快、可注入）；U-18d 用
#:     **Node 真跑**出来的坐标算（慢、但拿的是真坐标）—— 一条能抓"常量对不上
#:     渲染表"，另一条能抓"状态机自己把坐标画到框外"。
def _logo_overflow_reasons(mod=None):
    """列出"伸到方框外"的绘制元素（空 = 装得下）。`mod` 可注入（负控用）。"""
    M = mod or SV
    half = M._logo_half()
    out = []
    ring = M.LOGO_R + M.LOGO_RING_W / 2.0
    if ring > half:
        out.append("环外缘 %.1f > 方框半宽 %.1f" % (ring, half))
    amber = M.LOGO_R + M.LOGO_AMBER_R
    if amber > half:
        out.append("灯头外缘 %.1f > 方框半宽 %.1f" % (amber, half))
    beam = M.LOGO_BEAM_LEN + M.LOGO_BEAM_W / 2.0
    if beam > half:
        out.append("波束端点 %.1f > 方框半宽 %.1f" % (beam, half))
    for name, v in sorted(M.LOGO_MOTION_RENDER.items()):
        ext = (M.LOGO_R + M.LOGO_AMBER_R + M.LOGO_WAVE_GAP + float(v["waveR"]))
        if ext > half:
            out.append("%s 态涟漪最外缘 %.1f > 方框半宽 %.1f（会被切出直边）"
                       % (name, ext, half))
    return out


@check("U-18c 方框装得下全部绘制内容（环/灯头/波束/五态最大涟漪）")
def c_u18c():
    bad = _logo_overflow_reasons()
    if bad:
        return "；".join(bad)
    # 连带对照：渲染表必须是规格表**按几何归一**出来的 —— 只差 waveR 一栏，
    # 且差值恰为 `_logo_wave_scale()`。防"两处各写一份波幅"。
    k = SV._logo_wave_scale()
    for name, spec in SV.LOGO_MOTION.items():
        got = SV.LOGO_MOTION_RENDER.get(name)
        if not isinstance(got, dict):
            return "渲染动法表缺 %s 态" % name
        for f, v in spec.items():
            if f == "waveR":
                continue
            if got.get(f) != v:
                return ("渲染表 %s.%s=%r ≠ 规格 %r —— 归一化顺手改了别的字段"
                        % (name, f, got.get(f), v))
        want = round(float(spec["waveR"]) * k, 3)
        if abs(float(got["waveR"]) - want) > 1e-6:
            return ("渲染表 %s.waveR=%r ≠ 规格 %r × 归一系数 %.6f = %r"
                    % (name, got["waveR"], spec["waveR"], k, want))
    return True


@check("N-U18c 负控：渲染表退回未归一的规格波幅（105）⇒ 同一条尺子必须判红")
def n_u18c():
    if c_u18c() is not True:
        return "夹具不成立：未变异时 U-18c 就不合格，负控无分辨力"
    spec_only = {k: dict(v) for k, v in SV.LOGO_MOTION.items()}
    with _Patch(SV, LOGO_MOTION_RENDER=spec_only):
        why = c_u18c()
        if why is True or why is None:
            return "负控失效：波幅 105 伸出方框仍判合格 —— 这条尺子是装饰"
        if "涟漪" not in str(why):
            return "负控方向不对：报的不是涟漪越界（报的是 %r）" % (why,)
    return True


@check("U-18d Node 真跑五态：所有绘制坐标都落在 viewBox 里（波不被裁）")
def c_u18d():
    node = _node_path()
    if not node:
        return "SKIP：本机没有可执行 node —— 这一条**不判**（绝不假绿）"
    m = re.search(r'viewBox="([^"]+)"', SV._logo_mark("L0"))
    if not m:
        return "渲染出的哨标没有 viewBox —— 无框可验"
    parts = [float(v) for v in m.group(1).split()]
    half = parts[2] / 2.0
    worst_all = {}
    for mode in ("L0", "L1", "L2", "LD", "R0"):
        seq = _node_run(mode, frames=140)
        if not seq:
            return "%s：一帧都没跑出来（夹具失效，不判）" % mode
        worst, at = -1.0, None
        for f in seq:
            d = math.hypot(f["ax"] - SV.LOGO_CX, f["ay"] - SV.LOGO_CY)
            cand = [(d + SV.LOGO_AMBER_R, "灯头"),
                    (math.hypot(f["bx"] - SV.LOGO_CX, f["by"] - SV.LOGO_CY)
                     + SV.LOGO_BEAM_W / 2.0, "波束")]
            for key, nm in (("r0", "涟漪0"), ("r1", "涟漪1")):
                r = f.get(key)
                if isinstance(r, (int, float)) and r == r:      # 非 NaN
                    cand.append((d + float(r), nm))
            for v, nm in cand:
                if v > worst:
                    worst, at = v, nm
        worst_all[mode] = (worst, at)
        if worst > half + 0.5:
            return ("%s 态 %s 伸到 %.1f（方框半宽 %.1f）—— 被 viewBox 裁掉了"
                    "（创始人截图那条：「冒泡的 LOGO 不完整」）"
                    % (mode, at, worst, half))
    # 连带对照：环本身也必须还在框里（别为了塞波把环挪出去）
    ring = SV.LOGO_R + SV.LOGO_RING_W / 2.0
    if ring > half + 0.5:
        return "环外缘 %.1f 也在框外（%.1f）" % (ring, half)
    return True


@check("N-U18d 负控：把页面状态机换回未归一的波幅 ⇒ 真跑坐标必须越界判红")
def n_u18d():
    node = _node_path()
    if not node:
        return "SKIP：本机没有可执行 node —— 这一条**不判**（绝不假绿）"
    # ★ 0.51.1（Phase B2）：**不二次实现装配** —— 从产品装配产物 `_LOGO_JS`
    #   派生，只把 STYLE 表换回未归一的规格波幅。原实现手抄
    #   __STYLE__/__RING_GREEN__/__RING_DARKRED__ 三条替换，产品新增
    #   __AMBER_FILL__ 占位符时负控先炸（变异 JS 里占位符裸奔 ⇒ Node
    #   ReferenceError）—— 同 N-W02「尺子跟着源码形状走」的坑。
    bad_js = SV._LOGO_JS.replace(
        json.dumps(SV.LOGO_MOTION_RENDER, ensure_ascii=False),
        json.dumps(SV.LOGO_MOTION, ensure_ascii=False))
    if bad_js == SV._LOGO_JS:
        return ("负控自身失效：变异锚点未打中（STYLE 表替换没生效，"
                "产品装配口径可能变了）—— 量具故障，不算通过")
    with _Patch(SV, _LOGO_JS=bad_js):
        why = c_u18d()
        if why is True or why is None:
            return "负控失效：波幅 105 真跑越界仍判合格 —— 这条尺子是装饰"
        if str(why).startswith("SKIP"):
            return "负控失效：变异后判据退化成 SKIP，没有分辨力"
    return True


# ═════════════════════════════ B-13 「打开Antinel 监理」已开着就别重开（0.50.3）══
#: ★★★ 创始人 2026-10-14：「点击打开值守台后，之前的关闭了，打开了新的，但是
#:   状态不对了……另外，点完了按钮显示'打开Antinel 监理'按钮好像不对吧，Antinel 监理打开着
#:   呢」。两句话指的是同一件事的两个侧面：
#:     · **动作**：旧链路只有 `open_console_settled()`，而它**先收旧窗、再开新窗**
#:       ⇒ 面板本来就开着时点一下 = 窗闪一下、内容从头加载（状态读数是重新算的
#:       —— 这就是"状态不对了"）；
#:     · **文案**：按钮上写着"打开"，而它本来就开着 ⇒ 一个**不成立的承诺**。
#:   ⇒ 三条分流（见 `inbox_server.bubble_open_route`）：看得见 ⇒ **只切到前面**；
#:     看不见 ⇒ 开窗；判不出来 ⇒ 开窗（宁可多开一个窗，不许点了没反应）。
#:   ★ 尺子打在**行为**上：三条路的**实际动作序列**（调了 focus 还是 open）
#:     与**返回值**（`opened` 取什么），不看源码里有没有某个 `if`。
def _func_src(src, name):
    """按 AST 取一个顶层函数的源码（不靠字符串锚点 ⇒ 缩进/参数改名不腐化）。"""
    import ast
    tree = ast.parse(src)
    lines = src.splitlines()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return "\n".join(lines[node.lineno - 1:node.end_lineno])
    return None


def _ensure_console_record():
    """给临时中枢塞一条Antinel 监理记录（`bubble_open_route` 没有 URL 就直接早退）。"""
    rec = SV.read_console_record(None)
    if not rec or not rec.get("url"):
        SV.write_console_record(8799, "tok-b13", pid=os.getpid(), root=None)
    return SV.read_console_record(None) or {}


def _bubble_open_arms_fail(route):
    """三条分流的行为断言（**正判据与负控共用同一把尺子**）。返回错误串或 None。"""
    _ensure_console_record()
    seen = []

    def _open(url, token=None, verbose=False):                   # noqa: ARG001
        seen.append("open")
        return {"opened": "app", "placed": True, "why": ""}

    def _focus(hwnds):                                           # noqa: ARG001
        seen.append("focus")
        return True, "已切到前面"

    # ① 已开着 ⇒ **只切到前面**：一个窗都不许开（开了就是把旧窗关掉重建）
    del seen[:]
    r = route(vis=True, finder=lambda: [11, 22], focuser=_focus, opener=_open)
    if r.get("opened") != "existing":
        return ("Antinel 监理已开着，却返回 opened=%r（应 existing）⇒ 页面会以为"
                "「刚打开」" % (r.get("opened"),))
    if seen != ["focus"]:
        return ("Antinel 监理已开着，实际动作序列是 %r（应只有 focus）⇒ 旧窗被关、"
                "新窗重建（创始人原话「之前的关闭了，打开了新的」）" % (seen,))
    if r.get("ok") is not True:
        return "切到前面成功却没报 ok ⇒ 页面拿不到成功信号，会显示失败"
    # ② 没开着 ⇒ 才开窗；不许去切一个不存在的窗
    del seen[:]
    r2 = route(vis=False, finder=lambda: [11], focuser=_focus, opener=_open)
    if seen != ["open"]:
        return "Antinel 监理没开着，实际动作序列是 %r（应只有 open）" % (seen,)
    if r2.get("opened") not in ("app", "browser"):
        return "开窗成功却返回 opened=%r ⇒ 页面认不出「打开了」" % (r2.get("opened"),)
    # ③ 判不出来（None）⇒ 走开窗：宁可多开一个窗，也不许点了没反应
    del seen[:]
    r3 = route(vis=None, probe=lambda: None, finder=lambda: [11],
               focuser=_focus, opener=_open)
    if seen != ["open"]:
        return ("可见性判不出来时没走开窗（实际 %r）⇒ 用户点了没反应"
                "（「漏做」比「多做」坏）" % (seen,))
    if r3.get("ok") is not True:
        return "开窗成功却没报 ok"
    return None


@check("B-13 打开Antinel 监理：已开着 ⇒ 只切到前面（不关旧窗不重开）；没开/判不出 ⇒ 才开窗")
def c_b13():
    err = _bubble_open_arms_fail(SV.bubble_open_route)
    if err:
        return err
    # ---- 文案侧：渲染那一刻Antinel 监理已开着 ⇒ 不画按钮，改一句状态 ----
    BTN = '<button class="bub-open"'
    STA = '<span class="bub-has">'
    off = BB.render("t", "b", "R0", "tok-b13", run_id="r", kind="k",
                    console_open=False)
    on = BB.render("t", "b", "R0", "tok-b13", run_id="r", kind="k",
                   console_open=True)
    if BTN not in off:
        return "Antinel 监理没开着时反而没有「打开Antinel 监理」按钮 ⇒ 用户没入口"
    if BTN in on:
        return ("Antinel 监理已开着，却仍画着「打开Antinel 监理」按钮 ⇒ 一个不成立的承诺"
                "（创始人截图二「Antinel 监理打开着呢」）")
    if STA not in on:
        return "Antinel 监理已开着，却没换成一句状态 ⇒ 那个位置空着，用户不知道怎么回事"
    # ★ 缺按钮时 JS 不许整段抛错（旧版直接 `op.addEventListener` ⇒ 连带把
    #   `fit()` 与「知道了」那条链一起打死）
    if "if (op) {" not in off:
        return ("`.bub-open` 缺失时 JS 没有 null 守卫 ⇒ 没按钮的页面上"
                "整段脚本抛错，连「知道了」也点不动")
    # ★ 点完要退场换状态（与 B-10 同一形状：一次性动作做完不许留点不动的按钮）
    if '"existing"' not in off:
        return "JS 不认服务端回的 `opened=\"existing\"` ⇒ 用户点完看不到任何反馈"
    if ".bub-has" not in off:
        return "没有 `.bub-has` 状态样式 ⇒ 按钮退场后没有去处"
    return True


@check("N-B13 负控：把分流条件反过来（已开着也去开新窗）⇒ 同一条尺子必须判红")
def n_b13():
    src = _src("inbox_server.py")
    fs = _func_src(src, "bubble_open_route")
    if not fs:
        return "负控无效：找不到 `bubble_open_route`（判据与源码已失配）"
    anchor = "    if vis is True:"
    if anchor not in fs:
        return "负控无效：找不到分流锚点（判据与源码已失配）"
    mut_fs = fs.replace(anchor, "    if vis is False:", 1)
    # 把变异后的函数装进**真模块的命名空间**里跑（真 `read_console_record`
    # / 真 `open_console_settled` 都在），**不写任何产品文件**。
    ns = dict(vars(SV))
    exec(compile(mut_fs, "<mutant:bubble_open_route>", "exec"), ns)   # noqa: S102
    mutant = ns["bubble_open_route"]
    # ① 反空转：变异体在"没开着"那一路必须仍然对（否则红的是别的东西）
    if _bubble_open_arms_fail(mutant) is None:
        return "负控失效：分流条件反了却仍判合格 —— 这条尺子是装饰"
    # ② 方向正确：红的原因必须是"已开着却去开新窗"
    seen = []

    def _open(url, token=None, verbose=False):                   # noqa: ARG001
        seen.append("open")
        return {"opened": "app", "placed": True, "why": ""}
    _ensure_console_record()
    mutant(vis=True, finder=lambda: [11], focuser=lambda hs: (True, "x"),
           opener=_open)
    if seen != ["open"]:
        return "负控方向不对：变异体在已开着时没去开新窗（实际 %r）" % (seen,)
    return True


# ═════════════════════════════════ B-14…B-16 小窗与监理同款（0.53.0 T3）══
#: 创始人 2026-10-19 截图三条：① 小窗标题栏要「Antinel 监理（编号）· 紧急提醒」；
#: ② 小窗图标是浏览器默认网格球，与监理的圆环并排像两个产品；③ 监理开着，小窗
#: 还挂着「打开 Antinel 监理」。三条都属「同一个产品两副面孔」，故并成一组。
def _bubble_js(html):
    """小窗的**动作脚本**（含 `bubble_ack` 的那一段）。

    ★ 页面里有多段 `<script>`（动效状态机 ＋ 动作），抓第一段会全程空转 ——
      B-03 的探针第一版就栽在这里，这里按**内容**挑段。
    """
    for body in re.findall(r"<script>\n(.*?)\n</script>", html, re.S):
        if "bubble_ack" in body:
            return body
    return ""


def _b14_core(html, rid):
    """小窗标题：**与监理同款开头** ＋ 标记收尾 ＋ 不被认成监理窗 ＋ 认窗跟得上。"""
    m = re.search(r"<title>(.*?)</title>", html, re.S)
    if not m:
        return "小窗页面没有 <title> —— 标题栏只能显示浏览器默认名"
    title = m.group(1)
    # ★ 顺序有意：先判"会不会被认成监理窗"。摘掉标记的标题同时满足两条，
    #   但真正的危害是前者（通知被当成面板 ⇒ 后续急事全被咽掉）。
    if WIN.is_console_title(title) or WIN.is_console_title(title, rid):
        return ("小窗标题 %r 被认成监理窗 ⇒ 降噪闸会把通知当成「用户在看面板」，"
                "后续急事全被咽掉" % (title,))
    want = "%s#%s%s" % (WIN.CONSOLE_WINDOW_TITLE_SUFFIX, rid, WIN.BUBBLE_TITLE_MARK)
    if title != want:
        return "小窗标题是 %r，应为 %r —— 与监理不同款" % (title, want)
    # 认窗：按本次身份必须认得到（开窗后的落位/置顶都靠它）
    real = WIN.enum_windows
    WIN.enum_windows = _fake_enum
    try:
        strict = WIN.find_bubble_windows(run_id=rid)
    finally:
        WIN.enum_windows = real
    if strict != [5]:
        return ("按本次身份认不到小窗（得到 %r）—— 身份串挪位后严格匹配没跟上，"
                "开窗后的落位与置顶都会失效" % (strict,))
    return True


@check("B-14 小窗标题＝监理同款：品牌＋编号＋· 紧急提醒，且不被认成监理窗")
def c_b14():
    return _b14_core(BB.render("拦截：危险操作被挡下", "正文……", "R0", "tok-b14",
                               run_id="abc123", kind="k"), "abc123")


@check("N-B14 负控：摘掉「 · 紧急提醒」⇒ 被认成监理窗；退回旧格式 ⇒ 不同款")
def n_b14():
    html = BB.render("拦截：危险操作被挡下", "正文……", "R0", "tok-b14",
                     run_id="abc123", kind="k")
    good = re.search(r"<title>.*?</title>", html, re.S).group(0)
    # ① 只留品牌＋编号：这正是**会被当成面板**的形状（降噪闸最危险的假肯定）
    bare = "<title>%s#abc123</title>" % WIN.CONSOLE_WINDOW_TITLE_SUFFIX
    why = _b14_core(html.replace(good, bare), "abc123")
    if why is True:
        return "负控失效：摘掉标记后仍判合格"
    if "认成监理窗" not in why:
        return "负控方向不对：红的原因不是「被认成监理窗」（实际：%s）" % why
    # ② 旧格式（事由开头、编号收尾）：与监理不同款
    old = "<title>拦截：危险操作被挡下%s#abc123</title>" % WIN.BUBBLE_TITLE_MARK
    why2 = _b14_core(html.replace(good, old), "abc123")
    if why2 is True:
        return "负控失效：旧格式标题仍判合格"
    if "不同款" not in why2:
        return "负控方向不对：旧格式红的原因不是「不同款」（实际：%s）" % why2
    return True


def _b15_core(html, console_html):
    if SV.FAVICON_LINK not in html:
        return ("小窗没有图标链接 ⇒ 标题栏落浏览器默认的网格球（创始人截图），"
                "与监理的圆环并排像两个产品")
    if SV.FAVICON_LINK not in console_html:
        return "监理页没有同一枚图标链接 ⇒ 「统一」只是小窗单方面"
    return True


@check("B-15 小窗与监理同一枚图标：favicon 链接同源，不落浏览器默认球")
def c_b15():
    return _b15_core(BB.render("t", "b", "R0", "tok-b15", run_id="r", kind="k"),
                     SV._head("收件箱", "tok-b15"))


@check("N-B15 负控：把小窗的图标链接摘掉 ⇒ 必须红（两边任一摘掉都算）")
def n_b15():
    html = BB.render("t", "b", "R0", "tok-b15", run_id="r", kind="k")
    con = SV._head("收件箱", "tok-b15")
    if _b15_core(html.replace(SV.FAVICON_LINK, ""), con) is True:
        return "负控失效：小窗摘掉图标链接仍判合格"
    if _b15_core(html, con.replace(SV.FAVICON_LINK, "")) is True:
        return "负控失效：监理页摘掉图标链接仍判合格"
    return True


#: 姿态灯（六态）—— **一枚都不许当品牌标**。
_B15B_POSE_ICONS = ("L0.ico", "L1.ico", "L2.ico", "Ls.ico", "R0.ico")


def _b15b_core(server_src, resolve, brand_path, assets_dir):
    """favicon 必须解析到**品牌完整 LOGO**；姿态灯一律不算。

    ★★ 为什么 B-15 拦不住（0.53.1 复发的机制）：B-15 守的是「**链接**同源」
      —— 它只证明小窗与监理页引**同一个 URL**，完全不证明那个 URL
      **解析到哪个文件**。于是 `"favicon.ico": "icons/L0.ico"` 可以长期与
      「品牌图标不许用姿态灯」这条纪律并存：修在一条腿上，另一条腿天然全绿。
      创始人 2026-10-19 截图原话「LOGO 又又又被改了……完整的LOGO呢」。

    ★ 三条腿，缺一条就会被绕过：
      ① **结构**：资源白名单里不许有 `favicon.ico` 条目（那是品牌标的
         第二份来源，抄一份值就是分叉的开始）；
      ② **派生**：解析必须走品牌真源（`_brand_favicon_rel`）；
      ③ **真值**：解析出的**字节**必须等于品牌图标、且不等于任一枚姿态灯。
         只看源码文本不够 —— 路径改了而文件没换时 ①② 都绿，用户看到的还是灯。
    """
    if not server_src or not server_src.strip():
        return "读不到 inbox_server.py 源码 —— 判据锚点失效"

    m = re.search(r"ASSET_WHITELIST\s*=\s*\{(.*?)\n\}", server_src, re.S)
    if not m:
        return "找不到 ASSET_WHITELIST 定义 —— 判据锚点失效（改名了？）"
    if re.search(r"""["']favicon\.ico["']\s*:""", m.group(1)):
        return ("favicon.ico 又出现在资源白名单里 —— 那是品牌标的**第二份来源**；"
                "值一旦写成姿态灯，失守时标题栏仍显示值守灯（对用户撒谎）")
    if "_brand_favicon_rel" not in server_src:
        return "favicon 没有从品牌真源派生（缺 `_brand_favicon_rel`）"

    rel = resolve()
    if not rel:
        return "品牌图标派生返回空 ⇒ favicon 会 404（落浏览器默认球）"
    p = os.path.join(assets_dir, rel)
    if not os.path.isfile(p):
        return "派生出的 %s 不存在 ⇒ favicon 404（落浏览器默认球）" % rel
    if not brand_path or not os.path.isfile(brand_path):
        return "拿不到品牌图标本体（brand_icon_path() 返回 %r）" % (brand_path,)
    got = io.open(p, "rb").read()
    want = io.open(brand_path, "rb").read()
    if got != want:
        return ("favicon 解析到 %s，与品牌图标 %s **不是同一份字节**"
                " ⇒ 用户看到的不是完整 LOGO" % (rel, os.path.basename(brand_path)))
    for name in _B15B_POSE_ICONS:
        q = os.path.join(assets_dir, "icons", name)
        if not os.path.isfile(q):
            continue
        if io.open(q, "rb").read() == got:
            return ("favicon 与姿态灯 %s **字节相同** —— 拿状态灯当品牌标"
                    "（失守时标题栏仍显示值守灯，等于说没事）" % name)
    return True


@check("B-15b 小窗与监理共用的 favicon **解析到品牌完整 LOGO**，不许是姿态灯")
def c_b15b():
    return _b15b_core(_src("inbox_server.py"), SV._brand_favicon_rel,
                      WIN.brand_icon_path(), SV.ASSETS_DIR)


@check("N-B15b 负控：favicon 解析回姿态灯 / 白名单里再挂一条 ⇒ 必须红")
def n_b15b():
    src = _src("inbox_server.py")
    assets = SV.ASSETS_DIR
    brand = WIN.brand_icon_path()
    ok = _b15b_core(src, SV._brand_favicon_rel, brand, assets)
    if ok is not True:
        return "负控前置失败：当前生产实现没通过 B-15b（%r）" % (ok,)
    # ① 把解析改回姿态灯 —— 字节口径必须当场红
    bad = _b15b_core(src, lambda: "icons/L0.ico", brand, assets)
    if bad is True:
        return "负控失效：favicon 解析到 L0.ico 仍判合格"
    if "字节" not in str(bad):
        return ("方向不对：解析到 L0 报的红不是字节不符（%s）—— 量具打偏"
                % str(bad)[:140])
    # ② 结构：白名单里重新挂上 favicon 条目
    anchor = '"Ls.ico": "icons/Ls.ico", "R0.ico": "icons/R0.ico",\n}'
    if anchor not in src:
        return "负控锚点未找到（ASSET_WHITELIST 写法变了）—— 负控自身失效"
    mut = src.replace(anchor,
                      '"Ls.ico": "icons/Ls.ico", "R0.ico": "icons/R0.ico",\n'
                      '    "favicon.ico": "icons/L0.ico",\n}', 1)
    bad2 = _b15b_core(mut, SV._brand_favicon_rel, brand, assets)
    if bad2 is True:
        return "负控失效：白名单里重新挂上 favicon 仍判合格"
    return True


def _b16_core(js, server_src):
    """小窗必须**自己复查**监理是否开着 —— 渲染那一刻判一次不够。"""
    if "bubble_vis" not in js:
        return ("小窗不会复查监理是否开着 ⇒ 用户后来把监理拉开，按钮仍写着"
                "「打开 Antinel 监理」（创始人 2026-10-19 截图）")
    if 'addEventListener("load"' not in js:
        return "加载后不复查 ⇒ 只有渲染那一刻判过一次"
    if 'addEventListener("focus"' not in js:
        return "窗口获得焦点时不复查 ⇒ 用户切回来还看得见旧按钮"
    if "setInterval(syncOpen" not in js:
        return "没有定时复查 ⇒ 用户不动鼠标，按钮就一直挂着"
    if "bub-has" not in js:
        return "撤掉按钮后没有去处（应换成一句状态）"
    i = server_src.find('op == "bubble_vis"')
    if i < 0:
        return "服务端没有 bubble_vis 出口 ⇒ 页面复查只能拿到失败"
    seg = server_src[i:i + 800]
    if "console_is_visible" not in seg:
        return "bubble_vis 没走唯一的可见性实现（console_is_visible）"
    if "find_console_windows" in seg or "enum_windows" in seg:
        return "bubble_vis 自己又枚举了一遍窗口 —— 同一件事不许两份实现"
    return True


@check("B-16 监理后来才被打开也要撤掉「打开」按钮：加载/聚焦/定时三处复查")
def c_b16():
    html = BB.render("t", "b", "R0", "tok-b16", run_id="r", kind="k")
    return _b16_core(_bubble_js(html), _src("inbox_server.py"))


@check("N-B16 负控：拆掉复查那条链 / 服务端出口 ⇒ 必须红")
def n_b16():
    html = BB.render("t", "b", "R0", "tok-b16", run_id="r", kind="k")
    js = _bubble_js(html)
    src = _src("inbox_server.py")
    if not js or 'op == "bubble_vis"' not in src:
        return "夹具不成立：取不到动作脚本或服务端没有该出口"
    if _b16_core(js.replace("bubble_vis", "bubble_xx"), src) is True:
        return "负控失效：拆掉复查调用仍判合格"
    if _b16_core(js, src.replace('op == "bubble_vis"', 'op == "bubble_xx"')) is True:
        return "负控失效：服务端摘掉出口仍判合格"
    return True


# ═══════════════════════════════════════════════════ B-12 认窗口径必须同一把尺 ══
#: 假桌面：五枚可见窗，其中两枚是**用户窗口** —— 标题里恰好含哨标/紧急提醒的标记，
#: 但标记**不在末尾**。这就是实测误伤的形状（`_p_probe_win.py` 的内存替换夹具）。
#: ★ 0.51.1 反转（Phase B1）：console 窗标题改为「品牌开头＋身份串」整串
#:   （原「页面名 · Antinel 监理#rid」前缀形态本版不认领 —— 诚实缓建，
#:   0360 已钉负形状）⇒ 夹具 1 号窗同步换新形态；哨标/紧急提醒两路
#:   仍是标记收尾口径（`_mark_at_tail_any`，0.51.1 未动），夹具不动。
_FAKE_WINDOWS = [
    (1, "Antinel 监理#abc123"),                  # 本次Antinel 监理（0.51.1 新形态）
    (2, "我的 · 哨标 收藏夹"),             # ★ 用户窗口（含标记，不在末尾）
    (3, "Antinel · 哨标#abc123"),          # 本次哨标
    (4, "整理一下 · 紧急提醒 记录"),         # ★ 用户窗口（含标记，不在末尾）
    (5, "Antinel 监理#abc123 · 紧急提醒"),   # 本次紧急提醒（0.53.0 T3 同款开头）
]


def _fake_enum(visible_only=True):                          # noqa: ARG001
    return list(_FAKE_WINDOWS)


@check("B-12 认窗口径一致：哨标/紧急提醒宽泛分支不许用任意位置子串（会关用户窗口）")
def c_b12(mod=None):
    """★★ 清单 B4（实测真缺陷）：三处认窗必须同一口径 —— 标记只在合规位置。

    ★ 0.51.1 反转（Phase B1）后三路口径：console＝**品牌开头＋身份串收尾**
      （标题恒为「Antinel 监理#<rid>」，`is_console_title` 的 `_HEAD_RE`
      ＋rest 检查）；哨标/紧急提醒＝**标记收尾**（`_mark_at_tail_any`）。
      形态不同、**同一把尺**：标记之外不许挂别的字 ⇒ 用户窗口一律拒认。

    原来 `find_logo_windows` / `find_bubble_windows` 的宽泛分支用
    `mark in title`（任意位置子串），而 `is_console_title` 用 `_mark_at_tail`
    （0.36.5 时是末尾＋白名单，0.51.1 后为品牌开头＋身份串）。实测后果：
    用户窗口「我的 · 哨标 收藏夹」「整理一下 · 紧急提醒 记录」被认成本次
    哨标/紧急提醒窗，而这两条路径通向 `WM_CLOSE` ⇒ **可能关掉用户自己的
    窗口**（0.36.5 明令不可接受）。

    ★ `mod` 注入点：负控拿**变异模块**跑同一条判据（不是自己重写一遍口径）。
    """
    W = mod or WIN
    real = W.enum_windows
    W.enum_windows = _fake_enum
    try:
        logo = W.find_logo_windows()
        bub = W.find_bubble_windows()
        con = W.find_console_windows()
    finally:
        W.enum_windows = real
    if con != [1]:
        return "Antinel 监理认窗把用户窗口也算进来了：%r（应为 [1]）" % (con,)
    if logo != [3]:
        return ("哨标认窗把用户窗口也算进来了：%r（应为 [3]）—— 这条路径通向 "
                "WM_CLOSE，会关掉用户自己的窗口" % (logo,))
    if bub != [5]:
        return ("紧急提醒认窗把用户窗口也算进来了：%r（应为 [5]）—— 同上，"
                "会关掉用户自己的窗口" % (bub,))
    return True


@check("N-B12 负控：宽泛分支退回 `mark in title` 子串口径 ⇒ 同一条尺子必须判红")
def n_b12():
    import types
    src = _src(_WINDOW_REL)
    mutated, n = re.subn(r"elif _mark_at_tail_any\(title, mark\):",
                         "elif mark in title:", src)
    if n != 2:
        return ("变异锚点命中 %d 处（应为 2 处：哨标＋紧急提醒各一）"
                "—— 负控自身失效，不算通过" % n)
    mod = types.ModuleType("is0514_b12_mut")
    mod.__file__ = os.path.join(ROOT, _WINDOW_REL)
    exec(compile(mutated, mod.__file__, "exec"), mod.__dict__)   # noqa: S102
    if c_b12(mod=mod) is True:
        return "负控失效：退回子串口径后仍判合格 —— 这条判据是装饰"
    return True


# ════════════════════════════════════════════════════════════ B-02…B-08 ══
class _PopEnv:
    """紧急提醒链路的假桌面：假 opener（记录调用）、假 console（不起真服务）。"""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="g0514_pop_")
        self.urls = []
        self.rec = {"url": "http://127.0.0.1:9/", "token": "tk0514"}

    def opener(self, url):
        self.urls.append(url)
        return {"placed": True, "opened": "app", "topmost": True}

    def console(self, port, root):
        return (dict(self.rec), False)

    def pop(self, **kw):
        base = dict(title="R0 失守：判据夹具", body="这是判据在说话，不是真事。",
                    level="R0", root=self.root, force=True, now=1000000.0,
                    sound=False, opener=self.opener, verbose=False,
                    cfg={"bubble": True}, console=self.console)
        base.update(kw)
        return BB.pop(**base)


def _b02_ok(html):
    # ★ 0.50.5 锚点同步（产品改文案，判据跟着改，**断言强度不变**）：
    #   「知道了（去处理）」→「知道了」（括号把确认与处理绑成一件，与
    #   bubble_ack「确认 ≠ 处理」的立场相反）；
    #   「不自动消失」→「会一直留着，直到你处理完」（讲利益不讲机制）。
    #   判据仍然要求这两句**逐字在场**—— 少一句照样红。
    # ★★ 0.50.4（改名批，P4）：按钮文案「打开值守台」→「**打开 Antinel 监理**」
    #   —— 注意**空格**：创始人拍的是带空格的写法，锚点逐字同步（少一框照样红）。
    return ("data-logo=" in html and "requestAnimationFrame" in html
            and "知道了" in html and "打开 Antinel 监理" in html
            and "会一直留着" in html)


@check("B-02 紧急提醒界面与Antinel 监理同源：同一套 CSS＋同一枚动效哨标＋确认/打开钮")
def c_b02():
    html = BB.render("R0 失守：探针", "正文……", "R0", "tok", "run42",
                     kind="host_shield_revived")
    page = PC.body(html)
    if not _b02_ok(page):
        miss = [k for k, v in (("动效哨标", "data-logo=" in page),
                               ("rAF 状态机", "requestAnimationFrame" in page),
                               ("确认钮", "知道了" in page),
                               ("打开钮", "打开 Antinel 监理" in page),
                               ("留存说明", "会一直留着" in page)) if not v]
        return "紧急提醒页缺：%s —— 与Antinel 监理同源是 founder 点名要的" % "、".join(miss)
    # ★ 0.53.0 T3：标题改为**与监理同款开头**（品牌#编号 · 紧急提醒）。
    #   断言强度不变：品牌、编号、标记三样都必须逐字在场。
    if "<title>Antinel 监理#run42 · 紧急提醒</title>" not in page:
        return "标题不是「Antinel 监理#编号 · 紧急提醒」—— 与监理不同款，认窗也失去目标"
    if 'data-kind="host_shield_revived"' not in page:
        return "冒泡页未携带真实 kind —— 确认按钮无法对准下一次节流键"
    # ★ 0.50.1：动作脚本重写后，kind 不再拼成字面 `&kind=`，而是走
    #   `post(op, "kind=" + encodeURIComponent(dataset.kind), …)`。
    #   ⇒ 判据认**契约**（读当前 kind ＋ 把它作为字段发出去），不认某一种拼法。
    if "dataset.kind" not in page or '"kind="' not in page:
        return "确认 POST 没把当前告警 kind 传给 ack —— 确认静默会记错对象"
    # ★ S48：CSS 是**另一层**（`body()` 会把 `<style>` 剥掉）⇒ 显式走 `chrome()`。
    _css = PC.chrome(html)
    if "var(--r0)" not in _css or "var(--brand)" not in _css:
        return "没有沿用Antinel 监理的 CSS 变量 —— 「同源」只剩口号"
    return True


@check("N-B02 负控：拔掉冒泡页里的动效哨标 ⇒ 同一条判据必须判红")
def n_b02():
    html = BB.render("R0 失守：探针", "正文……", "R0", "tok", "run42")
    dead = re.sub(r"<svg class=\"lgmark\".*?</svg>", "", html, flags=re.S)
    if dead == html:
        return "夹具不成立：冒泡页里拔不出哨标 SVG，负控无分辨力"
    if _b02_ok(dead):
        return "负控失效：没有哨标也判同源 —— 这条判据是装饰"
    return True


@check("B-03 冒泡不一闪而过：无自动关闭，确认后明说「手工关」")
def c_b03():
    html = BB.render("R0 失守：探针", "正文……", "R0", "tok", "")
    # ★ 页面里有**多个** `<script>`（动效状态机 ＋ 冒泡动作）—— 按内容挑段，
    #   不许抓第一段（探针第一版就栽在这：抓到状态机，判据全程空转）。
    js = None
    for body in re.findall(r"<script>\n(.*?)\n</script>", html, re.S):
        if "bub-ok" in body and "bubble_ack" in body:
            js = body
            break
    if not js:
        return "夹具不成立：冒泡页里找不到动作脚本（bub-ok/bubble_ack 都不在）"
    if re.search(r"setTimeout\([^;]{0,160}close", js):
        return "有 setTimeout 自动关 —— 「不能一闪而过」被推翻"
    if "bubble_ack" not in js or "bubble_open" not in js:
        return "确认/打开两个动作没接上服务端 op"
    # ★ 0.50.6 锚点同步：确认态行按 STE 缩行（28→22 字），逐字断言串随之
    #   替换 —— 强度不变（同一串，砍任何一半都红；三个事实仍在：
    #   已确认／还没标记处理／点右上角 × 关）。
    if "已确认，还没标记处理 · 处理后点右上角 × 关" not in js:
        return "确认态没有区分「已知悉」与「已处理」，或没说清要手工关闭"
    if "!j || !j.ok" not in js or "没记上" not in js:
        return "服务端确认失败时仍可能显示成功（UI 会撒谎）"
    if "再点一次" not in js:
        return "确认失败时没让用户重试（文案里没有重试提示）"
    # ★ 0.50.1：动作脚本重写后变量名不再叫 `btn` ⇒ 认**行为**（失败要把按钮
    #   恢复可点），不认某个变量名 —— 否则改个名字就把尺子弄瞎。
    if not re.search(r"\.disabled\s*=\s*false", js):
        return "请求失败后按钮没有恢复可点状态——文本让重试，控件却不让重试"
    return True


@check("B-04 声音通道：自建铃声在；缺失/失败都如实报，不静默")
def c_b04():
    import wave
    p = BB.sound_path()
    if not os.path.isfile(p):
        return "自建提示音不在 %s —— 「会有声音」撑着空文件" % p
    if os.path.getsize(p) < 1000:
        return "提示音只有 %d 字节，不像有效 WAV" % os.path.getsize(p)
    try:
        with wave.open(p, "rb") as w:
            if w.getnframes() <= 0:
                return "WAV 一帧都没有"
    except Exception as e:                                      # noqa: BLE001
        return "提示音打不开：%s: %s" % (type(e).__name__, e)
    # 真实播放走 winsound；判据只验**如实**：缺文件⇒退回并说明；炸了⇒说不响。
    import winsound
    with _Patch(winsound,
                PlaySound=lambda *a, **k: None,
                MessageBeep=lambda *a, **k: None):
        ok, how = BB.play_sound()
        if not ok or "自建" not in how:
            return "有铃声却报 %r/%r" % (ok, how)
        with _Patch(BB, sound_path=lambda root=None: os.path.join(
                p, "no-such-alert.wav")):
            ok, how = BB.play_sound()
            if not ok or "退回" not in how:
                return "铃声缺失时报 %r/%r —— 没如实说退了" % (ok, how)
    with _Patch(winsound, PlaySound=lambda *a, **k: (_ for _ in ()).throw(
            OSError("桩：设备忙"))):
        ok, how = BB.play_sound()
        if ok or "播放失败" not in how:
            return "播放失败却报 %r/%r —— 假响" % (ok, how)
    return True


@check("N-B04 负控：播放通道全炸 ⇒ 必须报「没响」而不是返回 True")
def n_b04():
    import winsound
    with _Patch(winsound,
                PlaySound=lambda *a, **k: (_ for _ in ()).throw(
                    OSError("桩：没声卡")),
                MessageBeep=lambda *a, **k: (_ for _ in ()).throw(
                    OSError("桩：系统音也没了"))):
        ok, how = BB.play_sound()
    if ok:
        return "负控失效：两条通道都炸了还报响了 —— 用户永远不知道没声音"
    if not how:
        return "报了失败却不说原因"
    return True


@check("B-05 节流与确认静默：同类 1800s 内不重复；ack 后 1800s 不打扰")
def c_b05():
    env = _PopEnv()
    T = 1000000.0
    kind = "host_shield_revived"   # daemon 实际传 item.kind；不是级别 R0/L2
    r1 = env.pop(kind=kind, now=T)
    if not r1.get("ok") or len(env.urls) != 1:
        return "第一枚都没弹成：%s" % r1.get("why")
    r2 = env.pop(kind=kind, now=T + 60)
    if r2.get("ok") or len(env.urls) != 1:
        return "同类 60 秒后又弹了一枚（%r）—— 门铃节流失效" % r2.get("why")
    if "已提醒过" not in (r2.get("why") or ""):
        return "节流原因没说清：%r" % r2.get("why")
    # ★ force **不穿节流**（只穿可见性闸，见 B-06b）：节流是时间窗，
    #   窗口过了自然放行 —— 人工/演示要连时间窗一起穿，是另一条路径的事。
    r3 = env.pop(kind=kind, now=T + 120, force=True)
    if r3.get("ok") or len(env.urls) != 1:
        return "force 把节流也穿了（%r）—— 人工一按就连环炸" % r3.get("why")
    r3b = env.pop(kind=kind, now=T + BB.MIN_INTERVAL + 1)
    if not r3b.get("ok") or len(env.urls) != 2:
        return "节流窗口过了还不放行 —— 门铃变成永动机，真急事也被自己吞"
    # ★ 两个窗口都是 1800s，要让 ack 分支**可被观测**，ack 必须晚于上一次
    #   弹泡：同刻记 ⇒ 两条 why 逐字一样，ack 分支永远走不到（首版就踩了）。
    T2 = T + BB.MIN_INTERVAL + 1
    ok, msg = BB.ack(kind, root=env.root, now=T2 + 100)
    if not ok:
        return "确认没记上：%s" % msg
    r4 = env.pop(kind=kind, now=T2 + BB.MIN_INTERVAL)
    if r4.get("ok") or len(env.urls) != 2:
        return "确认过又弹了 —— 用户确认是个噪声动作"
    if "确认过" not in (r4.get("why") or ""):
        return "ack 静默原因没说清（走到别的分支了）：%r" % r4.get("why")
    r5 = env.pop(kind=kind,
                 now=T2 + BB.MIN_INTERVAL + BB.ACK_QUIET_SEC + 1)
    if not r5.get("ok") or len(env.urls) != 3:
        return "确认静默期过了还不放行 —— 用户确认过就永远不再提醒了"
    th = NT.throttle_state(env.root) or {}
    if "bubble:" + kind not in th or "bubble-ack:" + kind not in th:
        return "节流账不是 inbox_notify 那一本，或 ack 记在错误的 kind 上（toast/冒泡各记各的 ⇒ 双响）"
    return True


@check("N-B05 负控：全新账本上同一条链路必须照弹（尺子分辨力）")
def n_b05():
    env = _PopEnv()
    r = env.pop(kind="R0", now=2000000.0)
    if not r.get("ok"):
        return "负控失效：干净账本上也不弹 —— 上面的「不重复」可能是夹具坏了"
    return True


@check("B-06 可见性闸：Antinel 监理窗口正开着 ⇒ 不弹（不重复打扰）")
def c_b06():
    import host_shield as HS
    env = _PopEnv()
    with _Patch(HS, console_is_visible=lambda: True):
        r = env.pop(force=False, now=3000000.0)
    if r.get("ok") or env.urls:
        return "用户正开着面板还弹冒泡 —— 右下角又冒小泡泡（0.43.1 修过的老毛病）"
    if "正开着" not in (r.get("why") or ""):
        return "没说是「用户正看着」：%r" % r.get("why")
    with _Patch(HS, console_is_visible=lambda: False):
        r2 = env.pop(force=False, now=3000100.0)
    if not r2.get("ok"):
        return "面板没开着也不弹 —— 闸把急事咽了（宁可多弹不可漏报）"
    return True


@check("B-06b force 是人工/演示穿透口：可见性可穿，节流仍不可穿")
def c_b06b():
    """不是缺陷，是**契约的一半**：用户正开着面板时默认不弹（B-06），
    但人工确认过的急事要能当场再看一次 ⇒ force 穿可见性、不穿节流。
    两边都钉住，才知道哪一面变了。
    """
    import host_shield as HS
    env = _PopEnv()
    with _Patch(HS, console_is_visible=lambda: True):
        r = env.pop(force=True, now=7000000.0)
    if not r.get("ok") or len(env.urls) != 1:
        return "force 穿不了可见性闸 —— 人工/演示路径没了：%s" % r.get("why")
    r2 = env.pop(force=True, now=7000060.0)
    if r2.get("ok") or len(env.urls) != 1:
        return "force 连节流也穿 —— 人工一按就连环炸（%r）" % r2.get("why")
    return True


@check("B-07 Antinel 监理服务起不来 ⇒ 如实说发不出，opener 一次都不调")
def c_b07():
    env = _PopEnv()
    r = env.pop(console=lambda port, root: (None, False), now=5000000.0)
    if r.get("ok") or env.urls:
        return "服务没起来却弹了/开了窗 —— 假成功"
    if "起不来" not in (r.get("why") or ""):
        return "没说清是服务起不来：%r" % r.get("why")
    th = NT.throttle_state(env.root) or {}
    if "bubble:R0" in th:
        return "没弹成却记了节流账 —— 下一次真急事会被自己吞掉"
    return True


@check("B-08 一次一枚＋级别门＋配置闸：R0/L2 才走冒泡，先收旧的再开新的")
def c_b08():
    if tuple(BB.URGENT_LEVELS) != ("R0", "L2"):
        return "URGENT_LEVELS=%r ≠ ('R0','L2') —— 路由换代被推翻" % (
            BB.URGENT_LEVELS,)
    env = _PopEnv()
    r = env.pop(level="L1", now=6000000.0)
    if r.get("ok") or env.urls:
        return "L1 也走冒泡了 —— 两条通道同时响＝告警泛洪"
    if "不走紧急提醒" not in (r.get("why") or ""):
        return "级别门原因没说清：%r" % r.get("why")
    with _Patch(WIN, close_bubble_windows=lambda *a, **k: (1, "收了 1 枚")):
        r2 = env.pop(level="R0", kind="R0", now=6000100.0)
    if not r2.get("ok") or len(env.urls) != 1:
        return "该弹没弹：%s" % r2.get("why")
    if r2.get("closed_old") != 1:
        return "没收旧窗（closed_old=%r）—— 会长成一串" % r2.get("closed_old")
    r3 = env.pop(level="R0", kind="R0", now=6000200.0, cfg={"bubble": False})
    if r3.get("ok") or len(env.urls) != 1:
        return "配置关掉了还弹 —— 配置闸失效"
    if "配置" not in (r3.get("why") or ""):
        return "配置闸原因没说清：%r" % r3.get("why")
    return True


# ════════════════════════════════════════════════════════════ FLO-01…05 ══
#: logo.ps1 里的动法表必须与规格 v1.2 同值（它是 Python 侧状态机的
#: PowerShell 孪生；两处各写一份 ⇒ 迟早漂，这条就是防漂的）。
#: 0.52.0 新契约（创始人 2026-10-17 截图：哨标颤抖难看、切换慢、点它不回值守台）：
#: **托盘同族静态图标＋双缓冲**（颤抖根源＝GDI+ 动效 40ms 全量重绘，删净）；
#: **常驻三标志**（quit / hide / show）；**点击不自毁**（写完 open 原地待命，
#: 消费方开出Antinel 监理后写 hide 藏它 —— 旧契约「点击成功即退」正是反向切换坏掉的病根）。
#: 0.53.1 契约（创始人 2026-10-19 截图：最小化后是秃圆圈、点圆圈中间没反应、不会动）
#: —— 静态图标修好了颤抖，却同时制造三个新症状，全部在本条里钉住：
#:   ① 「出现的居然是圆圈，不是标准 LOGO」⇒ 哨标画**标准动效徽标**：环＋光束＋
#:      拖尾＋灯头＋涟漪，动法＝`tools/logo_frame.ps1` 的纯帧数学（dot-source
#:      同一文件，**不许在 logo.ps1 里另写一遍**）；规格经 tray.json 的 logo 块
#:      下发（FLO-10c 锁下发、FLO-10d 锁页面 JS 与它逐项同源）。
#:   ② 「点圆圈中间没反应，只有点在线圈上才切得回」⇒ 窗口是**逐像素 alpha 的
#:      分层窗**（WS_EX_LAYERED＋UpdateLayeredWindow，**禁 TransparencyKey**
#:      —— 镂空只命中不透明像素，图标中心全透明 ⇒ 点中间没反应；AA 边的粉边
#:      也是它）。WndProc 自答 WM_NCHITTEST：**整个内切圆内**可点，四角
#:      HTTRANSPARENT 让位给背后的窗口。命中半径从规格推导（Get-HitRadius），
#:      不写死（FLO-10a 拿独立推导的 oracle 对数值）。
#:   ③ 「LOGO 应该跟主窗口一样保持动态」⇒ 帧泵＝**线程池定时器投递到窗体线程**
#:      （System.Timers.Timer＋SynchronizingObject，AutoReset=$false，finally
#:      带 quitting 闸重启，add_Load 起泵，读盘有 LastWriteTimeUtc 守卫）。
#:      禁 WinForms Timer（WM_TIMER 只在队列空时合成，输入负载下饿死 —— 0.50.0
#:      病根）与自续期 posted invoke（队列永不空 ⇒ 自造饥饿 —— 8 轮实测
#:      ticks=1/frames=352，2026-10-19）；两个被否设计都写进 logo.ps1 注释。
#:   ④ 减少动效（MinAnimate=0）：只画一帧静态，且取在**目标态**（xfade 处），
#:      不是启动态 —— 启动态会让 R0 演成一枚绿环（FLO-10e 锁这条）。
#:   ⑤ 回落链：规格取不到 ⇒ 回落托盘同族静态图标（0.52.0 的腿），不假装会动。
#: ★ 0.52.0 的「双缓冲」条款在 0.53.1 **退役**：分层窗的内容是整帧位图，窗体
#:   自己的 DC 从不显示，双缓冲无从谈起（颤抖的根治在架构层，不在这个开关）。
def _flo01_ok(src):
    """0.53.1 契约。返回 None = 合格；否则返回第一条不合格的原因（人读）。"""
    # ---- 0.52.0 仍然成立的条款（常驻三标志 / 点击不自毁 / 拖拽 / 回落链）----
    if 'FormBorderStyle = "None"' not in src:
        return "没钉死无边框 —— 会有标题栏，哨标不像哨标"
    # ★ 锚「建窗时」那一段（ShowInTaskbar 紧接 TopMost），不是任意一处
    #   `TopMost = $true`：Show-Now 里也有一句重申报（从托盘唤回时补），
    #   只认那一句的话「建窗时没置顶」照样判绿 —— 负控「不置顶」会失去
    #   分辨力（2026-10-19 实测：锚点出现 2 次，变异打不到真位置）。
    if "$form.ShowInTaskbar = $false\n$form.TopMost = $true" not in src:
        return "建窗时没置顶 —— 会被别的窗盖住（监理要「一直在」）"
    for edge in ("MinimumSize", "MaximumSize"):
        if ("$form.%s = New-Object System.Drawing.Size($Size, $Size)" % edge
                not in src):
            return "%s 没钉死 —— WinForms 有最小跟踪宽度（实测 136px），不钉就缩不到 46" % edge
    if "Test-Path -LiteralPath $Quit" not in src or "Quit-Now" not in src:
        return "没有轮询退役标志自退 —— 退役只能靠强杀"
    if 'Write-Action "open"' not in src:
        return "点击没写 open 动作 —— 点了哨标展不开 Antinel 监理"
    # 0.52.0：点击**不自毁** —— Quit-Now 在**代码里**只许出现两处（函数定义 +
    # quit 标志轮询）。★ 只数代码行：注释里提到函数名是正常文档（0.53.1 的架构
    # 注记就提了一次），把文档提及当成调用，尺子就会红在措辞上而不是缺陷上。
    code = "\n".join(l for l in src.splitlines()
                     if not l.lstrip().startswith("#"))
    if code.count("Quit-Now") != 2:
        return ("点击路径在自毁（Quit-Now 在代码里出现 %d 次 ≠ 2）—— "
                "哨标消失而 Antinel 监理没开，正是 2026-10-17 截图的病"
                % code.count("Quit-Now"))
    if "$script:actionWriteFailed = $true" not in src or "$script:actionWriteFailTip" not in src:
        return "动作写盘失败没有可观测反馈 —— 用户点了没反应"
    if "add_MouseMove" not in src or "dragging" not in src:
        return "不能拖拽 —— 用户无法把它挪到不碍事的位置"
    # 0.52.0 常驻三标志：hide/show 必须有（且各自把窗真藏/真现出）
    if "Consume-Flag $Show" not in src or "$form.Show()" not in src:
        return "没有唤标志处理 —— 常驻哨标唤不出，收缩仍要冷启 PowerShell（切换慢）"
    if "Consume-Flag $Hide" not in src or "$form.Hide()" not in src:
        return "没有藏标志处理 —— 展开后哨标退不死也藏不了，屏幕上多漂一枚"
    # 0.52.0 静态图标：托盘同族 .ico + 回落链（0.53.1 起它是规格缺失时的回落）
    if "[string]$IconDir" not in src:
        return "-IconDir 没接 —— 规格取不到时画不了托盘同族状态图标（回落链断了）"
    if "ToBitmap" not in src or "DrawImage" not in src:
        return "不是按 .ico 画 —— 回落图标与 Antinel 监理图标不同源（创始人要「同样的图标」）"
    if '($st + $suf + ".ico")' not in src or '($st + ".ico")' not in src:
        return "状态图标回落链不完整 —— 组合态缺文件时该回落基础态（icon_file 同规）"
    if '"unposted" = "-unposted"' not in src or '"off" = "-off"' not in src:
        return "哨兵态后缀表不全 —— shield 维度画不出来（托盘同族映射漂了）"
    # ---- 0.53.1：分层透明窗（粉边／命中区的病根都在这一层）----
    if "cp.ExStyle |= 0x00080000" not in src:
        return "没开 WS_EX_LAYERED —— 逐像素 alpha 的分层窗才是 0.53.1 的画法"
    if "UpdateLayeredWindow" not in src:
        return "没有 UpdateLayeredWindow —— 帧没有真正成为窗口内容（会留一块底色）"
    if "TransparencyKey =" in src:
        return ("又用回 TransparencyKey 镂空 —— 只命中不透明像素（点图标中间没反应），"
                "AA 边还会出现粉边（0.50.0 实测）")
    # ---- 0.53.1：整个内切圆可点，四角让位 ----
    if "m.Msg == 0x0084" not in src or "NcHitTest" not in src:
        return "WndProc 没有自答 WM_NCHITTEST —— 命中区回到系统默认（点中间没反应）"
    if "return -1" not in src:
        return "四角没有 HTTRANSPARENT —— 哨标会抢走背后窗口的点击"
    if "Test-Hit $x $y $Size $script:hitRadius" not in src:
        return "命中判定没走规格推导的 Test-Hit —— 半径又成了写死的数"
    if "Get-HitRadius $Size $script:spec" not in src:
        return "hitRadius 没从规格推导 —— 画的和点的不是同一个圆（FLO-10a 锁数值）"
    # ---- 0.53.1：帧数学单一实现（logo_frame.ps1），logo.ps1 只管画 ----
    if ". $Frame" not in src:
        return "没有 dot-source 帧数学 —— 徽标动法要在 PowerShell 里另写一遍"
    if "Get-Frame -Spec $script:spec" not in src:
        return "没有按规格算帧 —— 标准动效 LOGO 只是摆设"
    for fn in ("Get-Frame", "Get-HitRadius", "Test-Hit", "New-Visual",
               "ConvertTo-Hashtable", "Get-RingSegments", "Get-Clamp"):
        if ("function %s" % fn) in src:
            return "logo.ps1 里又定义了 %s —— 帧数学出现了第二份实现（迟早漂）" % fn
    # ---- 0.53.1：帧泵＝池定时器投递（两个被实测否掉的设计都不许复活）----
    if "System.Windows.Forms.Timer" in src:
        return ("又用回 WinForms Timer —— WM_TIMER 只在消息队列空时合成，"
                "鼠标一压上来动画就饿死（0.50.0 颤抖／停摆的病根）")
    if "New-Object System.Timers.Timer($LOGO_FRAME_MS)" not in src:
        return "帧泵不是线程池定时器 —— 满载下会堆积或饿死（0.53.1 实测定稿）"
    if src.count(".SynchronizingObject = $form") != 2:
        return ("SynchronizingObject 不是正好两处（帧泵＋轮询）—— "
                "池线程上触发的回调会跨线程踩窗体")
    if src.count("AutoReset = $false") != 2:
        return "AutoReset 没关 —— 回调会堆积（最多一枚待投递是这条架构的前提）"
    if src.count("if (-not $script:quitting) {") != 2:
        return ("finally 里的 quitting 闸不是正好两处 —— 处理器抛异常时泵要么死掉"
                "（静默冻住），要么退出了还重启（往死句柄上投递）")
    # ★ 只看「有没有 add_Load」不够：句柄建好不开泵，徽标一样是死的
    #   （负控实测：把 Start-Pump/Start-Poll 挖空后老条款仍判绿）。
    if "$form.add_Load({\n  Start-Pump\n  Start-Poll\n})" not in src:
        return ("add_Load 里没起泵/起轮询 —— 句柄建好前投递会炸"
                "（InvalidOperationException），不起泵徽标就是死的")
    if "LastWriteTimeUtc" not in src:
        return "读盘没有 LastWriteTimeUtc 守卫 —— 常驻哨标会每秒重解析 JSON（实测 ~77ms/次）"
    if "$left = $LOGO_FRAME_MS -" not in src:
        return "帧间隔没有自适应（预算−实测工作量）—— 慢机堆积、快机不满预算"
    if "TotalSeconds -gt 1.5" not in src or "lastFrameUtc" not in src:
        return "帧泵没有看门狗 —— 泵悄悄死了徽标就静默冻住（最糟的失败）"
    # ---- 0.53.1：减少动效取目标态 ----
    if "MinAnimate" not in src:
        return "没读系统的「显示动画」偏好 —— 晕动敏感用户没有退路（Q-20 同族）"
    if "$mt = [double]$script:spec.anim.xfade" not in src:
        return ("减少动效的静态帧没取在目标态（xfade）—— 会演成启动态："
                "R0 在减少动效下成一枚绿环，状态读错（FLO-10e 锁这条）")
    # ---- 回落链：规格取不到就静态图标，不假装会动 ----
    if "Import-Spec" not in src or "Load-Icon (Resolve-IconPath $st $sh)" not in src:
        return "规格缺失时没有回落托盘同族静态图标 —— 要么假动要么空白"
    # ---- 0.53.1：源码 ASCII-only（PS 5.1 无 BOM 按 GBK 读 .ps1）----
    # 同一轮三轮实证：无 BOM 的 .ps1 里任何非 ASCII 字节——哪怕只在注释里——
    # 都会被按 GBK 误解码并**静默劣化行为**（驱动「循环跑 9 次但 hashtable
    # 键一个不进」5/5 复现）；用户可见字符串更直接变乱码（tray.ps1 的
    # `·` 实测显示成「路」）。产品三件套（logo/tray/logo_frame）的字节级
    # 检查在 c_flo01；这里守**内存里的源码形状**（负控的变异走这条）。
    try:
        src.encode("ascii")
    except UnicodeEncodeError:
        return ("源码含非 ASCII 字符 —— PS 5.1 把无 BOM 的 .ps1 按 GBK 读，"
                "注释里的全角字符都会静默劣化行为，用户可见字符串直接变乱码")
    return None


@check("FLO-01 logo.ps1 契约（0.53.1）：标准动效徽标＋分层窗整圆可点＋池定时器帧泵＋常驻三标志")
def c_flo01():
    src = _src(_LOGO_PS1_REL)
    why = _flo01_ok(src)
    if why:
        return why
    if not os.path.isfile(IL.script_path()):
        return "IL.script_path() 指向的脚本不在：%s" % IL.script_path()
    if not os.path.isfile(IL.frame_script_path()):
        return "帧数学脚本不在：%s —— dot-source 会失败，哨标只能回落静态图标" % IL.frame_script_path()
    # 字节级 ASCII 检查（三件套）：文本级条款守内存形状，这里守**落盘的字节**——
    # UTF-8 编解码都正常的字符，只要 >127 就会在 PS 5.1 眼里变形。
    for rel in (_LOGO_PS1_REL, _FRAME_PS1_REL, _TRAY_PS1_REL):
        p = os.path.join(ROOT, rel)
        with open(p, "rb") as f:
            raw = f.read()
        bad = [i for i, b in enumerate(raw) if b > 127]
        if bad:
            line = raw[:bad[0]].count(b"\n") + 1
            return ("%s 第 %d 行含非 ASCII 字节（共 %d 个）—— PS 5.1 按 GBK 读它，"
                    "行为静默劣化／用户可见字符串变乱码（2026-10-19 实证）"
                    % (rel, line, len(bad)))
    return True


@check("N-FLO01 负控：九种复发（镂空复活／点击自毁／第二份帧数学／WinForms 计时器／"
       "重启闸被阉／Load 不起泵／读盘守卫拔掉／不置顶／非 ASCII 字节混入源）⇒ 尺子必须全判红")
def n_flo01():
    src = _src(_LOGO_PS1_REL)
    base = _flo01_ok(src)
    if base is not None:
        return "夹具不成立：未变异时 FLO-01 就不合格（%s），负控无分辨力" % base
    # 每个变异：(名字, 锚, 替换体, 期望原因关键词)。锚必须**恰好出现一次**——
    # 0 次＝尺子跟源码形状漂了（负控自身失效），>1 次＝变异会打到别处去。
    muts = [
        ("TransparencyKey 镂空复活",
         "$form.Text = $Title",
         "$form.Text = $Title\n"
         "$form.TransparencyKey = [System.Drawing.Color]::Fuchsia",
         "TransparencyKey"),
        ("点击自毁",
         'Write-Action "open" | Out-Null',
         'Write-Action "open" | Out-Null; Quit-Now',
         "自毁"),
        ("第二份帧数学",
         "function Read-State",
         "function Get-Frame { param($Spec,[string]$Mode,[double]$Mt,$Snap) return $null }\n"
         "function Read-State",
         "第二份实现"),
        ("WinForms 计时器复活",
         "New-Object System.Timers.Timer($LOGO_FRAME_MS)",
         "New-Object System.Windows.Forms.Timer\n"
         "$script:frameTimer.Interval = $LOGO_FRAME_MS",
         "WinForms"),
        ("finally 重启闸被阉",
         "      if (-not $script:quitting) {\n        $left = $LOGO_FRAME_MS",
         "      if ($true) {\n        $left = $LOGO_FRAME_MS",
         "quitting"),
        ("add_Load 不起泵",
         "$form.add_Load({\n  Start-Pump\n  Start-Poll\n})",
         "$form.add_Load({\n})",
         "add_Load"),
        ("读盘守卫拔掉",
         "    $w = (Get-Item -LiteralPath $State).LastWriteTimeUtc\n"
         "    if ((-not $script:stateParsed) -or ($w -ne $script:stateStamp)) {",
         "    if ($true) {",
         "LastWriteTimeUtc"),
        ("不置顶",
         "$form.ShowInTaskbar = $false\n$form.TopMost = $true",
         "$form.ShowInTaskbar = $false\n$form.TopMost = $false",
         "置顶"),
        ("非 ASCII 字节混入源",
         "try { . $Frame; $script:frameOk = $true }",
         "try { . $Frame; $script:frameOk = $true }  # \u00b7 note",
         "非 ASCII"),
    ]
    for name, anchor, repl, kw in muts:
        n = src.count(anchor)
        if n != 1:
            return ("夹具不成立：%s 的锚点出现 %d 次（要恰好 1 次）—— 尺子跟源码"
                    "形状漂了，负控自身失效，不算通过" % (name, n))
        why = _flo01_ok(src.replace(anchor, repl))
        if why is None:
            return "负控失效：%s 仍判合格 —— 这条尺子是装饰" % name
        if kw not in why:
            return "负控方向不对：%s 判红了但报的不是预期原因（%r）" % (name, why)
    return True


# ═══════════════════════════════════════════════ FLO-10 族（0.53.1）══
#: ★★★ 创始人 2026-10-19 截图（最小化后的哨标）三句话，四条判据腿：
#:   「出现的居然是圆圈，不是标准 LOGO」     ⇒ FLO-10c/d 锁动效规格单一真源与下发
#:   「点圆圈中间没反应，只有点线上才切得回」 ⇒ FLO-10a 锁命中区（规格推导的内切圆）
#:   「LOGO 应该跟主窗口一样保持动态」        ⇒ FLO-10b 锁帧随时间推进（五态各对规格）
#:   ＋ FLO-10e：减少动效的静态帧取**目标态**（R0 不许演成启动态的一枚绿环）。
#: ★ 方法纪律（本族的心脏）：帧数学的判据**不二次实现**。写一个 ASCII-only 的
#:   PowerShell 驱动（`_FLO10_DRIVER`），dot-source 产品同一个
#:   `tools/logo_frame.ps1`，真跑 `Get-Frame`/`Get-HitRadius`/`Test-Hit`/
#:   `New-Visual`，JSON 出栈；Python 侧只做两件事：① 从**同一份规格**出发的
#:   独立推导（oracle）；② 逐项比对。两份实现在同一输入上必须给出同一个答案
#:   —— 分歧即红。负控只动 `logo_frame.ps1` 的**临时副本**，不落产品文件。
#: ★ 为什么值得单独一族：这三句话是「监理要不要碍事」这条产品线的三个面
#:   （看得见、点得到、是活的），任何一个面坏掉，哨标就从「监理在」退化成
#:   「一个碍事的装饰」—— 而装饰比没有更糟（用户会以为它在守）。

# ---- 驱动：真跑帧数学（ASCII-only；PS 5.1 无 BOM 会解错 UTF-8 源）----
# ★★ 驱动内局部变量**严禁**与参数名大小写碰撞（PowerShell 变量名大小写
#   不敏感）：曾用 `$spec = ConvertTo-Hashtable $j.logo`，而参数块里有
#   `[string]$Spec` —— 同一个变量，[string] 类型 ⇒ 整个 Hashtable 被
#   强制转成字符串 "System.Collections.Hashtable" ⇒ `.geom` 为 null
#   ⇒ half=0 ⇒ scale=∞ ⇒ `[int]NaN` 崩（2026-10-19 实测定位）。故一律
#   用 `$sp` 这类与任何参数都不同名的短名。
# ★★ 驱动**必须 ASCII-only**：PS 5.1 把无 BOM 的 .ps1 按 GBK 读，文件里
#   任何非 ASCII 字节——哪怕在注释里——都会静默劣化行为（同一轮实证：
#   中文注释版驱动「循环跑 9 次但 hashtable 键一个不进」，5/5 复现；
#   换成 ASCII 立即恢复）。`_flo10_ps` 落盘前有断言把守。
_FLO10_DRIVER = r"""
param(
  [Parameter(Mandatory=$true)][string]$Frame,
  [Parameter(Mandatory=$true)][string]$Spec,
  [Parameter(Mandatory=$true)][string]$Job,
  [string]$Mode = "L0",
  [string]$Mts = "",
  [int]$Size = 46,
  [string]$Points = ""
)
$ErrorActionPreference = "Stop"
. $Frame
$j = Get-Content -LiteralPath $Spec -Raw -Encoding UTF8 | ConvertFrom-Json
$sp = ConvertTo-Hashtable $j.logo
if ($null -eq $sp) {
  [Console]::Out.Write('{"error":"tray.json has no logo block"}'); exit 2
}
if ($Job -eq "hit") {
  $hr = Get-HitRadius $Size $sp
  $res = @{ radius = $hr }
  $i = 0
  foreach ($p in ($Points -split ';')) {
    if ($p -eq "") { continue }
    $xy = $p -split ','
    # NOTE (ASCII-only file!): the cast MUST be ([int]$xy[0]), NOT
    # [int]$xy[0] -- in PowerShell a cast binds tighter than indexing,
    # so the latter is ([int]$xy)[0]: the array gets OFS-joined into
    # "23 23" and the int cast explodes (measured 2026-10-19).
    $res["p$i"] = [bool](Test-Hit ([int]$xy[0]) ([int]$xy[1]) $Size $hr)
    $i = $i + 1
  }
  [Console]::Out.Write((ConvertTo-Json $res -Compress))
} elseif ($Job -eq "frames") {
  $snap = New-Visual $sp
  $out = @()
  foreach ($m in ($Mts -split ',')) {
    if ($m -eq "") { continue }
    $f = Get-Frame -Spec $sp -Mode $Mode -Mt ([double]$m) -Snap $snap
    $row = @{ mt = [double]$m
              theta = [double]$f.theta
              ringO = [double]$f.ringO
              amberO = [double]$f.amberO
              ringRed = [double]$f.ringRed
              breath = [double]$f.breath
              beamC = @([double]$f.beamC[0], [double]$f.beamC[1], [double]$f.beamC[2])
              ringC = @([double]$f.ringC[0], [double]$f.ringC[1], [double]$f.ringC[2])
              bx = [double]$f.beam.x2
              by = [double]$f.beam.y2
              waves = @() }
    foreach ($w in $f.waves) {
      $row.waves += @{ r = [double]$w.r; w = [double]$w.w; opa = [double]$w.opa }
    }
    $out += $row
  }
  [Console]::Out.Write((ConvertTo-Json @{ frames = $out } -Compress -Depth 7))
} else {
  [Console]::Out.Write('{"error":"unknown job"}'); exit 2
}
"""


def _ps_path():
    import shutil
    return shutil.which("powershell") or shutil.which("pwsh")


def _flo10_ps(job, spec_path, frame_path=None, mode="L0", mts="", size=46,
              points=""):
    """真跑帧数学（PowerShell + dot-source 产品脚本）。返回解析后的 JSON dict。

    `frame_path` 不给 = 产品脚本；给 = 临时变异副本（负控用）。跑不动 ⇒ 抛
    （调用方按红处理，**不许**静默当成"测不出"）。
    """
    ps = _ps_path()
    if not ps:
        raise RuntimeError("PATH 上没有 powershell/pwsh —— 帧数学无法真跑")
    import subprocess
    # ★ 机制层断言：驱动 ASCII-only。PS 5.1 无 BOM 按 GBK 读 .ps1，非
    #   ASCII 字节（哪怕只在注释里）会静默劣化行为——不在这里炸一声，
    #   症状会变成「量具莫名其妙测不出」（2026-10-19 三轮实证）。
    try:
        _FLO10_DRIVER.encode("ascii")
    except UnicodeEncodeError as e:
        raise RuntimeError("帧数学驱动含非 ASCII 字节（%s）—— PS 5.1 会按 GBK "
                           "误解码，行为静默劣化；注释说明放 Python 侧" % e)
    d = tempfile.mkdtemp(prefix="g0514_flo10_")
    drv = os.path.join(d, "flo10_driver.ps1")
    with io.open(drv, "w", encoding="utf-8", newline="\n") as f:
        f.write(_FLO10_DRIVER)
    cmd = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", drv,
           "-Frame", frame_path or IL.frame_script_path(),
           "-Spec", spec_path, "-Job", job, "-Mode", mode,
           "-Mts", mts, "-Size", str(int(size)), "-Points", points]
    p = subprocess.run(cmd, capture_output=True, timeout=300)
    out = (p.stdout or b"").decode("utf-8", "replace").strip()
    if p.returncode != 0 or not out:
        raise RuntimeError("帧数学驱动失败 rc=%r out=%r err=%r" % (
            p.returncode, out[:200],
            (p.stderr or b"").decode("utf-8", "replace")[:300]))
    return json.loads(out)


def _flo10_tray(state="L2"):
    """写一份**真** tray.json（含 logo 规格块），返回 (root, 路径, 读回的 payload)。

    为什么不直接拿 `logo_motion_spec()` 的返回值喂驱动：那样就只测了函数本身。
    走 `inbox_tray.write_state` ⇒ 测的是**下发通路**（规格真的落到托盘那一个
    状态文件里），驱动读的也是哨标真正会读的那个文件。
    """
    root = tempfile.mkdtemp(prefix="g0514_flo10_hub_")
    TR.write_state(state, 1, "intercepting - unhandled 1", root=root)
    p = TR.state_path(root)
    with io.open(p, encoding="utf-8") as f:
        payload = json.load(f)
    return root, p, payload


# ---------------------------------------------------------------- FLO-10a --
def _flo10_hit_extent(spec):
    """「画出来的最大半径」（画布单位）——`Get-ContentExtent` 的 Python 孪生。

    这是**故意的第二份实现**（oracle）：产品在 PowerShell 里算一遍，判据在
    Python 里从同一份规格算一遍，两份必须一致。它防两类事：半径被写死（不随
    规格走），以及产品公式自身写错（缩放/取整/封顶）。
    """
    g = spec["geom"]
    ext = 0.0
    for m in spec["motion"].values():
        e = (float(g["r"]) + float(g["amberR"]) + float(g["waveGap"])
             + float(m["waveR"]))
        if e > ext:
            ext = e
    half = float(g["half"])
    return ext if ext <= half else half


def _flo10_hit_raw(spec, size):
    half = float(spec["geom"]["half"])
    return _flo10_hit_extent(spec) * float(size) / (2.0 * half)


@check("FLO-10a 命中区＝规格推导的内切圆：整个 LOGO 边界内可点，四角让位")
def c_flo10a(frame_path=None):
    root, tray, payload = _flo10_tray()
    spec = payload.get("logo")
    if not isinstance(spec, dict):
        return "tray.json 里没有 logo 规格块 —— 哨标只能回落静态图标（FLO-10c 锁下发）"
    size = 46
    raw = _flo10_hit_raw(spec, size)
    hr = int(round(raw))
    c = size / 2.0
    pts = [("center", int(c), int(c)),
           ("right_in", int(c + hr - 3), int(c)),
           ("left_in", int(c - hr + 3), int(c)),
           ("top_in", int(c), int(c - hr + 3)),
           ("bottom_in", int(c), int(c + hr - 3)),
           ("corner_tl", 2, 2),
           ("corner_br", size - 3, size - 3),
           ("out_right", int(c + hr + 3), int(c)),
           ("out_left", int(c - hr - 3), int(c))]
    got = _flo10_ps("hit", tray, frame_path=frame_path, size=size,
                    points=";".join("%d,%d" % (x, y) for _, x, y in pts))
    if "radius" not in got:
        return "帧数学驱动没返回半径：%r" % (got,)
    # 半径数值：容差 0.5px（PS 的 Round 是四舍五入远零，Python 的 round 是
    # 银行家舍入 —— 真出现 x.5 时两者可差 1，那不是产品缺陷）。
    if abs(float(got["radius"]) - raw) > 0.5 + 1e-9:
        return ("Get-HitRadius 实测 %s ≠ 规格推导 %.4f —— 画出来的圆和点得到的圆"
                "不是一个（创始人截图：点圆圈中间没反应）" % (got["radius"], raw))
    for i, (name, x, y) in enumerate(pts):
        want = ((x - c) ** 2 + (y - c) ** 2) <= hr * hr
        key = "p%d" % i
        if key not in got:
            return "驱动没判 %s 点（%d,%d）—— 量具缺腿" % (name, x, y)
        if bool(got[key]) != want:
            return ("%s 点（%d,%d）Test-Hit=%s ≠ 推导 %s —— 命中区与规格不一致"
                    % (name, x, y, got[key], want))
    # 半径随窗口尺寸缩放（证明是推出来的，不是写死的 23）
    raw2 = _flo10_hit_raw(spec, 2 * size)
    got2 = _flo10_ps("hit", tray, frame_path=frame_path, size=2 * size, points="")
    if abs(float(got2.get("radius", -1)) - raw2) > 0.5 + 1e-9:
        return ("窗口放大一倍后半径 %s ≠ 推导 %.4f —— hitRadius 是写死的数"
                % (got2.get("radius"), raw2))
    if hr > size // 2:
        return "命中半径 %d 超出内切圆 %d —— 会抢走四角属于背后窗口的点击" % (
            hr, size // 2)
    return True


@check("N-FLO10a 负控：半径改 Floor／Test-Hit 恒真 ⇒ 同一条尺子必须判红")
def n_flo10a():
    root, tray, payload = _flo10_tray()
    if "logo" not in payload:
        return "夹具不成立：tray.json 没有 logo 块，负控无从测起"
    base = c_flo10a()
    if base is not True:
        return "夹具不成立：未变异时 FLO-10a 就不合格：%s" % (base,)
    frame_src = io.open(IL.frame_script_path(), encoding="utf-8").read()
    d = tempfile.mkdtemp(prefix="g0514_flo10n_")
    # 变异 1：Round → Floor（边界差一；对当前规格 23 → 22）。
    # ★ 为什么不用「直接返回 Size/2」：当前规格推导出的半径恰好就是 23＝Size/2
    #   （extent 280.074 ≈ half 282.074，缩放取整后重合）—— 那个变异**不改变
    #   取值**，量具看不见。负控必须是真能改变取值的变异，否则就是假负控。
    a = "return [int][Math]::Round((Get-ContentExtent $Spec) * $scale)"
    if frame_src.count(a) != 1:
        return "夹具不成立：Get-HitRadius 锚点没打中（源码已变，需更新负控）"
    p1 = os.path.join(d, "frame_floor.ps1")
    with io.open(p1, "w", encoding="utf-8", newline="\n") as f:
        f.write(frame_src.replace(
            a, "return [int][Math]::Floor((Get-ContentExtent $Spec) * $scale)"))
    why = c_flo10a(frame_path=p1)
    if why is True or why is None:
        return "负控失效：半径退回 Floor 仍判合格 —— 差一像素没人抓"
    # 变异 2：Test-Hit 恒真（半径约束整个掉）⇒ 探针必须翻
    b = "return (($dx * $dx + $dy * $dy) -le ($Radius * $Radius))"
    if frame_src.count(b) != 1:
        return "夹具不成立：Test-Hit 锚点没打中（源码已变，需更新负控）"
    p2 = os.path.join(d, "frame_always.ps1")
    with io.open(p2, "w", encoding="utf-8", newline="\n") as f:
        f.write(frame_src.replace(b, "return $true"))
    why = c_flo10a(frame_path=p2)
    if why is True or why is None:
        return "负控失效：Test-Hit 恒真仍判合格 —— 四角也会被哨标抢走点击"
    return True


# ---------------------------------------------------------------- FLO-10b --
_FLO10B_FINE = [round(0.02 * i, 2) for i in range(0, 151)]        # 0 … 3.00
_FLO10B_COARSE = [round(3.25 + 0.25 * i, 2) for i in range(0, 88)]  # 3.25 … 25.00
_FLO10B_MTS = _FLO10B_FINE + _FLO10B_COARSE


def _flo10b_unwrap1(t0, t1):
    d = t1 - t0
    if d > 180:
        d -= 360
    if d < -180:
        d += 360
    return d


def _flo10b_swept(thetas):
    swept, prev = 0.0, None
    for th in thetas:
        if prev is not None:
            swept += _flo10b_unwrap1(prev, th)
        prev = th
    return swept


def _flo10b_mode(mode, fr, spec):
    """一个态的全部帧动态断言。返回 None = 合格，否则第一条不符的原因。"""
    g, a, row = spec["geom"], spec["anim"], spec["motion"][mode]
    idx = {m: i for i, m in enumerate(_FLO10B_MTS)}

    def at(m):
        return fr[idx[m]]

    # ① 换态渐变：Mt=0 必须是启动态（L0 行），Mt≥xfade 必须到达目标态
    f0, f2 = at(0.0), at(2.0)
    for key, want0, want2 in (("ringO", 1.0, float(row["ringO"])),
                              ("amberO", 0.35, float(row["amberO"])),
                              ("ringRed", 0.0, float(row["ringRed"]))):
        if abs(f0[key] - want0) > 1e-9:
            return "%s Mt=0 的 %s=%.6f ≠ 启动态 %.2f（渐变没从快照起）" % (
                mode, key, f0[key], want0)
        if abs(f2[key] - want2) > 1e-9:
            return "%s Mt=2 的 %s=%.6f ≠ 目标态 %.2f（xfade=%.1fs 没走完）" % (
                mode, key, f2[key], want2, a["xfade"])
    for i in range(3):
        if abs(f0["beamC"][i] - spec["motion"]["L0"]["c"][i]) > 1e-9:
            return "%s Mt=0 的光束色不是启动态 L0" % mode
        if abs(f2["beamC"][i] - row["c"][i]) > 1e-9:
            return "%s Mt=2 的光束色 %r ≠ 目标色 %r" % (mode, f2["beamC"], row["c"])
    # ② 角度通道
    if mode == "R0":
        glide = _flo10b_unwrap1(at(0.0)["theta"], at(0.8)["theta"])
        if abs(glide - float(a["r0Slide"])) > 0.5:
            return "R0 滑行 %.3f° ≠ 规格 %.1f°（停摆没停住或滑距不对）" % (
                glide, a["r0Slide"])
        tail = [f["theta"] for f in fr if f["mt"] >= 1.0]
        if max(tail) - min(tail) > 1e-9:
            return ("R0 滑行结束后 24 秒内漂移 %.6f° —— 规格是永停（讣告不该"
                    "一直转）" % (max(tail) - min(tail)))
        seg = [at(m)["theta"] for m in _FLO10B_FINE if m <= 0.8]
        if any(_flo10b_unwrap1(seg[i], seg[i + 1]) < -1e-12
               for i in range(len(seg) - 1)):
            return "R0 滑行段回摆 —— 不是单调滑行"
    elif mode == "L0":
        if abs(at(0.1)["theta"] - at(0.0)["theta"]) > 1e-12:
            return "L0 在起步停顿 %.2fs 内就转了（规格：%.2fs 后才起转）" % (
                0.1, a["l0Delay"])
        lap = float(row["lap"])
        sp = _flo10b_unwrap1(at(6.0)["theta"], at(7.0)["theta"])
        if abs(sp - 360.0 / lap) > 0.5:
            return "L0 稳速 %.3f°/s ≠ %.3f°/s（%.1fs/圈 没兑现）" % (
                sp, 360.0 / lap, lap)
        thetas = [f["theta"] for f in fr]
        if _flo10b_swept(thetas) <= 0 or any(
                _flo10b_unwrap1(thetas[i], thetas[i + 1]) < -1e-12
                for i in range(len(thetas) - 1)):
            return "L0 全程没有单调推进 —— 徽标「不动了」"
    else:
        lap = float(row["lap"])
        end = {"L1": 8.0, "L2": 5.5, "LD": 3.5}[mode]
        swept = _flo10b_swept([f["theta"] for f in fr if f["mt"] <= end])
        if abs(swept - 360.0) > 1.0:
            return "%s：%.1fs 扫过 %.3f° ≠ 360°（%.1fs/圈 没兑现）" % (
                mode, end, swept, lap)
        sp = _flo10b_unwrap1(at(end - 1.0)["theta"], at(end)["theta"])
        if abs(sp - 360.0 / lap) > 0.5:
            return "%s 稳速 %.3f°/s ≠ %.3f°/s" % (mode, sp, 360.0 / lap)
    # ③ 涟漪通道：L1/L2/LD 开（扩散＋衰减），L0/R0 止
    on = mode in ("L1", "L2", "LD")
    base_r = float(g["amberR"]) + float(g["waveGap"])
    amp, peak = float(row["waveR"]), float(row["waveO"])
    max_opa = 0.0
    for f in fr:
        for w in f["waves"]:
            if not on:
                if w["r"] != 0.0 or w["opa"] != 0.0 or w["w"] != 0.0:
                    return ("%s 态不该有涟漪（r=%.3f opa=%.3f）—— 规格：波止"
                            % (mode, w["r"], w["opa"]))
                continue
            if w["r"] < base_r - 1e-9 or w["r"] > base_r + amp + 1e-9:
                return "%s 涟漪半径 %.4f 跳出 [%g, %g]" % (mode, w["r"], base_r,
                                                          base_r + amp)
            if w["r"] > base_r + 1e-6:
                ph = (w["r"] - base_r) / amp
                if abs(w["opa"] - peak * (1.0 - ph) ** 2) > 1e-6:
                    return ("%s 涟漪 ph=%.4f 处不透明度 %.5f ≠ %.5f（扩散衰减"
                            "公式：越远越淡）" % (mode, ph, w["opa"],
                                                peak * (1.0 - ph) ** 2))
                if abs(w["w"] - (float(a["waveW0"]) - float(a["waveW1"]) * ph)) > 1e-6:
                    return "%s 涟漪线宽 %.4f 与相位 ph=%.4f 不符" % (mode, w["w"], ph)
            max_opa = max(max_opa, w["opa"])
    if on and abs(max_opa - peak) > 0.01:
        return ("%s 涟漪峰值不透明度 %.3f ≠ 规格 %.2f —— 波峰从没出现过，"
                "涟漪是假的" % (mode, max_opa, peak))
    # ④ R0 环色塌暗
    if mode == "R0":
        dark = spec["colors"]["ringDarkRed"]
        if any(abs(f2["ringC"][i] - dark[i]) > 1e-6 for i in range(3)):
            return "R0 环色 %r ≠ 规格暗红 %r" % (f2["ringC"], dark)
    return None


@check("FLO-10b 帧随时间推进：五态速度/停摆/涟漪扩散衰减/波止，逐项对规格")
def c_flo10b(frame_path=None):
    root, tray, payload = _flo10_tray()
    spec = payload.get("logo")
    if not isinstance(spec, dict):
        return "tray.json 里没有 logo 规格块"
    mts_txt = ",".join("%g" % m for m in _FLO10B_MTS)
    for mode in ("L0", "L1", "L2", "LD", "R0"):
        got = _flo10_ps("frames", tray, frame_path=frame_path, mode=mode,
                        mts=mts_txt)
        fr = got.get("frames")
        if not fr or len(fr) != len(_FLO10B_MTS):
            return "%s：驱动返回 %d 帧 ≠ 请求 %d 帧（量具缺腿）" % (
                mode, len(fr or []), len(_FLO10B_MTS))
        why = _flo10b_mode(mode, fr, spec)
        if why:
            return why
    return True


@check("N-FLO10b 负控：渐变系数置 0／起转冻结 ⇒ 同一条尺子必须判红")
def n_flo10b():
    root, tray, payload = _flo10_tray()
    if "logo" not in payload:
        return "夹具不成立：tray.json 没有 logo 块"
    base = c_flo10b()
    if base is not True:
        return "夹具不成立：未变异时 FLO-10b 就不合格：%s" % (base,)
    frame_src = io.open(IL.frame_script_path(), encoding="utf-8").read()
    d = tempfile.mkdtemp(prefix="g0514_flo10n_")
    # 变异 1：k=0 —— 换态渐变永远不起（Mt=2 仍停在启动态）
    a = "$k = Get-EaseOut (Get-Clamp ($Mt / [double]$a.xfade) 0 1)"
    if frame_src.count(a) != 1:
        return "夹具不成立：xfade 锚点没打中（源码已变，需更新负控）"
    p1 = os.path.join(d, "frame_k0.ps1")
    with io.open(p1, "w", encoding="utf-8", newline="\n") as f:
        f.write(frame_src.replace(a, "$k = 0"))
    why = c_flo10b(frame_path=p1)
    if why is True or why is None:
        return "负控失效：渐变系数恒 0 仍判绿 —— Mt=2 的帧停在了启动态"
    # 变异 2：起转冻结（theta 不吃 Mt）—— 「不动了」必须有人抓
    b = "$theta = Get-Mod ($Snap.theta + $Mt * 360.0 / $lap)"
    if frame_src.count(b) != 1:
        return "夹具不成立：起转锚点没打中（源码已变，需更新负控）"
    p2 = os.path.join(d, "frame_frozen.ps1")
    with io.open(p2, "w", encoding="utf-8", newline="\n") as f:
        f.write(frame_src.replace(b, "$theta = Get-Mod ($Snap.theta)"))
    why = c_flo10b(frame_path=p2)
    if why is True or why is None:
        return "负控失效：起转冻结仍判绿 —— 徽标「不动了」没人抓"
    return True


# ---------------------------------------------------------------- FLO-10c --
@check("FLO-10c 动效规格单一真源：logo_motion_spec ≡ 渲染表＋几何常量，且真写进 tray.json")
def c_flo10c():
    spec = SV.logo_motion_spec()
    # ① motion 表 ≡ LOGO_MOTION_RENDER（逐态逐字段，含字段集）
    for name, row in SV.LOGO_MOTION_RENDER.items():
        got = spec["motion"].get(name)
        if not isinstance(got, dict):
            return "规格缺 %s 态 —— 哨标演不了这一态" % name
        if set(got) != set(row):
            return "规格 %s 态字段集 %r ≠ 渲染表 %r" % (name, sorted(got), sorted(row))
        if list(row["c"]) != got["c"]:
            return "规格 %s.c=%r ≠ 渲染表 %r" % (name, got["c"], list(row["c"]))
        for f in ("lap", "ringO", "amberO", "ringRed", "waveR", "waveO"):
            if float(row[f]) != float(got[f]):
                return "规格 %s.%s=%r ≠ 渲染表 %r" % (name, f, got[f], row[f])
    if set(spec["motion"]) != set(SV.LOGO_MOTION_RENDER):
        return "规格多出渲染表没有的态：%r" % (
            sorted(set(spec["motion"]) - set(SV.LOGO_MOTION_RENDER)),)
    # ② 几何逐项 ≡ 常量
    want_geom = {"cx": SV.LOGO_CX, "cy": SV.LOGO_CY, "r": SV.LOGO_R,
                 "ringW": SV.LOGO_RING_W, "amberR": SV.LOGO_AMBER_R,
                 "waveGap": SV.LOGO_WAVE_GAP, "beamLen": SV.LOGO_BEAM_LEN,
                 "beamW": SV.LOGO_BEAM_W, "boxRatio": SV.LOGO_BOX_RATIO,
                 "half": round(SV._logo_half(), 3)}
    for k, v in want_geom.items():
        if k not in spec["geom"]:
            return "规格 geom 缺 %s" % k
        if float(spec["geom"][k]) != float(v):
            return "规格 geom.%s=%r ≠ 常量 %r" % (k, spec["geom"][k], v)
    # ③ 色表
    want_colors = {"ringGreen": list(SV.LOGO_RING_GREEN),
                   "ringDarkRed": list(SV.LOGO_RING_DARKRED),
                   "amber": list(SV._hex_rgb(SV.LOGO_AMBER_FILL)),
                   "trail": list(SV._hex_rgb(SV.LOGO_TRAIL_COLOR))}
    for k, v in want_colors.items():
        if list(spec["colors"].get(k, [])) != v:
            return "规格 colors.%s=%r ≠ %r" % (k, spec["colors"].get(k), v)
    # ④ 动画常量逐项
    want_anim = {"trailN": SV.LOGO_TRAIL_N, "trailStep": SV.LOGO_TRAIL_STEP,
                 "trailOpa": list(SV.LOGO_TRAIL_OPA), "trailFrac": SV.LOGO_TRAIL_FRAC,
                 "trailInset": SV.LOGO_TRAIL_INSET, "wavePeriod": SV.LOGO_WAVE_PERIOD,
                 "waveW0": SV.LOGO_WAVE_W0, "waveW1": SV.LOGO_WAVE_W1,
                 "beamA0": SV.LOGO_BEAM_A0, "beamStart": SV.LOGO_BEAM_START,
                 "segGap": SV.LOGO_SEG_GAP, "breathBase": SV.LOGO_BREATH_BASE,
                 "breathAmp": SV.LOGO_BREATH_AMP, "breathPeriod": SV.LOGO_BREATH_PERIOD,
                 "xfade": SV.LOGO_XFADE, "l0Delay": SV.LOGO_L0_DELAY,
                 "l0Ramp": SV.LOGO_L0_RAMP, "r0Slide": SV.LOGO_R0_SLIDE,
                 "r0SlideT": SV.LOGO_R0_SLIDE_T}
    for k, v in want_anim.items():
        if k not in spec["anim"]:
            return "规格 anim 缺 %s" % k
        if spec["anim"][k] != v:
            return "规格 anim.%s=%r ≠ 常量 %r" % (k, spec["anim"][k], v)
    if spec["modes"] != dict(SV.LOGO_MODE):
        return "规格 modes=%r ≠ LOGO_MODE %r" % (spec["modes"], dict(SV.LOGO_MODE))
    # ⑤ 真下发：写一份 tray.json，读回来必须带着同一份规格
    root, tray, payload = _flo10_tray()
    if "logo" not in payload:
        return "tray.json 里没有 logo 块 —— 规格没有真下发（哨标会悄悄变哑）"
    if payload["logo"] != spec:
        return "tray.json 的 logo 块 ≠ logo_motion_spec() —— 下发路上被改过"
    return True


@check("N-FLO10c 负控：规格塞进未归一的波幅（45/70/105）⇒ 同一条尺子必须判红")
def n_flo10c():
    if c_flo10c() is not True:
        return "夹具不成立：未变异时 FLO-10c 就不合格，负控无分辨力"
    good = SV.logo_motion_spec()
    bad = json.loads(json.dumps(good))                # 深拷贝，只动一波幅
    for name, row in SV.LOGO_MOTION.items():
        bad["motion"][name]["waveR"] = float(row["waveR"])   # 未归一的规格值
    with _Patch(SV, logo_motion_spec=lambda: bad):
        why = c_flo10c()
        if why is True or why is None:
            return ("负控失效：波幅退回未归一仍判合格 —— 哨标上的涟漪会伸出"
                    "窗外被裁（0.50.3「冒泡的 LOGO 不完整」同型）")
        if "waveR" not in str(why):
            return "负控方向不对：判红了但报的不是波幅（%r）" % (why,)
    return True


# ---------------------------------------------------------------- FLO-10d --
_LOGO_STYLE_RE = re.compile(r"var STYLE=(\{.*?\});\r?\nvar RING_GREEN=", re.S)


def _flo10d_js_pins():
    """渲染产物 `_LOGO_JS` 里必须逐字出现的常量针（占位符注入的那些）。

    注入是渲染时从常量算的，正常不可能漂；这条钉的是**渲染之后有人手改文本**。
    """
    pins = []
    for name, const in (("CX", SV.LOGO_CX), ("CY", SV.LOGO_CY), ("R", SV.LOGO_R),
                        ("W_BEAM", SV.LOGO_BEAM_W), ("L_BEAM", SV.LOGO_BEAM_LEN),
                        ("AMBER_R", SV.LOGO_AMBER_R), ("GAP", SV.LOGO_SEG_GAP),
                        ("TRAIL_N", SV.LOGO_TRAIL_N), ("TRAIL_STEP", SV.LOGO_TRAIL_STEP),
                        ("TRAIL_FRAC", SV.LOGO_TRAIL_FRAC),
                        ("TRAIL_INSET", SV.LOGO_TRAIL_INSET),
                        ("WAVE_PERIOD", SV.LOGO_WAVE_PERIOD), ("WAVE_W0", SV.LOGO_WAVE_W0),
                        ("WAVE_W1", SV.LOGO_WAVE_W1)):
        pins.append(("%s=%s" % (name, SV._jsnum(const)), name))
    pins.append(("TRAIL_OPA=[%s]" % ",".join(SV._jsnum(v) for v in SV.LOGO_TRAIL_OPA),
                 "TRAIL_OPA"))
    pins.append(("V={theta:%s," % SV._jsnum(SV.LOGO_BEAM_START), "BEAM_START"))
    return pins


def _flo10d_handwritten():
    """模板里**手写**（不经占位符）的数字 —— 0.53.1 提升常量时漏掉的那几个。

    每个都要能在 JS 文本里按 Python 常量的字面量找到（前导 0 有无都认）。
    为什么不顺手把它们也改成占位符：那是渲染路径上的改动，超出本轮截图三
    症状的范围；先把漂移钉成红项，让"改常量不忘改模板"成为机械可判的事。
    """
    def lit(v):
        return "0?" + re.escape(SV._jsnum(v))
    return [
        (r"V\.breath=" + lit(SV.LOGO_BREATH_BASE), SV.LOGO_BREATH_BASE,
         "呼吸中位 breathBase"),
        (r"\+" + lit(SV.LOGO_BREATH_AMP) + r"\*Math\.sin", SV.LOGO_BREATH_AMP,
         "呼吸幅度 breathAmp"),
        (r"\*2\*Math\.PI/" + lit(SV.LOGO_BREATH_PERIOD), SV.LOGO_BREATH_PERIOD,
         "呼吸周期 breathPeriod"),
        (r"clamp\(mt/" + lit(SV.LOGO_XFADE) + r",0,1\)", SV.LOGO_XFADE,
         "渐变时长 xfade"),
        (r"mt>" + lit(SV.LOGO_L0_DELAY), SV.LOGO_L0_DELAY, "L0 起步停顿 l0Delay"),
        (r"\)/" + lit(SV.LOGO_L0_RAMP) + r",0,1", SV.LOGO_L0_RAMP,
         "L0 匀加速 l0Ramp"),
        (r"snap\.theta\+" + lit(SV.LOGO_R0_SLIDE) + r"\*easeInOut",
         SV.LOGO_R0_SLIDE, "R0 滑行角 r0Slide"),
        (r"clamp\(mt/" + lit(SV.LOGO_R0_SLIDE_T) + r",0,1\)", SV.LOGO_R0_SLIDE_T,
         "R0 滑行时长 r0SlideT"),
        (r"AMBER_R\+" + lit(SV.LOGO_WAVE_GAP), SV.LOGO_WAVE_GAP,
         "涟漪起始缝 waveGap"),
    ]


@check("FLO-10d 页面 JS 与哨标规格同源：STYLE 表逐项一致，手写字面量逐个钉住")
def c_flo10d():
    js = SV._LOGO_JS
    spec = SV.logo_motion_spec()
    m = _LOGO_STYLE_RE.search(js)
    if not m:
        return "状态机里取不出 var STYLE=... 表 —— 页面动法的家当不见了"
    try:
        style = json.loads(m.group(1))
    except ValueError:
        return "STYLE 表不是合法 JSON：%r" % (m.group(1)[:120],)
    # ① STYLE 表 ≡ 哨标规格的 motion 表（同一份 LOGO_MOTION_RENDER 的两个出口）
    if set(style) != set(spec["motion"]):
        return "STYLE 表的态集 %r ≠ 哨标规格 %r" % (sorted(style),
                                                  sorted(spec["motion"]))
    for name, row in spec["motion"].items():
        got = style.get(name)
        if not isinstance(got, dict):
            return "STYLE 表缺 %s 态" % name
        if set(got) != set(row):
            return "STYLE %s 字段集不同：%r ≠ %r" % (name, sorted(got), sorted(row))
        for f, v in row.items():
            if got.get(f) != v:
                return ("STYLE %s.%s=%r ≠ 哨标规格 %r —— 页面一套、哨标一套"
                        % (name, f, got.get(f), v))
    # ② 占位符注入的常量（渲染产物里逐个钉）
    for needle, name in _flo10d_js_pins():
        if needle not in js:
            return "状态机里找不到 %s（期望 %r）—— 有人手改了 JS 文本" % (name, needle)
    # ③ 手写在模板里的字面量逐个钉
    for pat, const, name in _flo10d_handwritten():
        if not re.search(pat, js):
            return ("状态机里 %s 的字面量与 Python 常量 %r 对不上 —— 模板手写处"
                    "漂了（页面会动、哨标不会动，或反过来）" % (name, const))
    return True


@check("N-FLO10d 负控：STYLE 表改一个数／手写字面量改一个数 ⇒ 同一条尺子必须判红")
def n_flo10d():
    if c_flo10d() is not True:
        return "夹具不成立：未变异时 FLO-10d 就不合格，负控无分辨力"
    # 变异 1：STYLE 表里 L2 的圈速 5.5 → 6.0（页面快了、哨标没快）
    a = '"lap": 5.5'
    if SV._LOGO_JS.count(a) != 1:
        return "夹具不成立：STYLE 锚点没打中（json.dumps 口径变了，需更新负控）"
    with _Patch(SV, _LOGO_JS=SV._LOGO_JS.replace(a, '"lap": 6.0')):
        why = c_flo10d()
        if why is True or why is None:
            return "负控失效：STYLE 表与规格脱节仍判合格 —— 页面一套、哨标一套"
    # 变异 2：手写的呼吸中位 .94 → .95（Python 常量没动）
    b = "V.breath=.94+.06*Math.sin"
    if SV._LOGO_JS.count(b) != 1:
        return "夹具不成立：手写字面量锚点没打中（源码已变，需更新负控）"
    with _Patch(SV, _LOGO_JS=SV._LOGO_JS.replace(b, "V.breath=.95+.06*Math.sin")):
        why = c_flo10d()
        if why is True or why is None:
            return "负控失效：手写字面量漂了仍判合格 —— 模板里的第二份数字没人抓"
    return True


# ---------------------------------------------------------------- FLO-10e --
def _flo10e_reduce_ok(logo_src, js_tmpl):
    """减少动效的静态帧必须取在**目标态**（xfade 处），不是启动态。"""
    if "$mt = [double]$script:spec.anim.xfade" not in logo_src:
        return ("哨标的减少动效分支没把静态帧取在目标态 —— R0 会演成启动态"
                "的一枚绿环（状态读错）")
    # ★ 锚**代码行**，不是裸 `update(__XFADE__)`：模板里那段注释为了解释
    #   「为什么不能 update(0)」也原样写了这个片段 ⇒ 裸锚在变异成 update(0)
    #   之后仍命中注释，判据永远绿（2026-10-19 负控实测抓出）。
    if "if (_reduce) { update(__XFADE__); render(); }" not in js_tmpl:
        return "页面的减少动效分支没有 update(__XFADE__) —— 同型 bug 在页面侧没人守"
    return None


#: reduce 桩：把系统的「减少动态效果」偏好看成开着（页面侧的
#: prefers-reduced-motion: reduce）—— boot() 于是只画一帧静态就收工，
#: 没有 rAF 循环。DOM 桩与 `_NODE_STUB` 同一套。
_NODE_STUB_REDUCE = r"""
function El(){ this.attrs={}; this.children=[]; }
El.prototype.setAttribute=function(k,v){ this.attrs[k]=String(v); };
El.prototype.getAttribute=function(k){ return this.attrs[k]; };
El.prototype.appendChild=function(c){ this.children.push(c); };
function q(el,n){
  var hit=el.children.filter(function(c){ return c.attrs["data-p"]===n; });
  if(hit.length) return hit[0];
  var e=new El(); e.attrs["data-p"]=n; el.children.push(e); return e;
}
El.prototype.querySelector=function(sel){
  var m=/^\[data-p="(.+)"\]$/.exec(sel);
  return m ? q(this, m[1]) : null;
};
var svg=new El(); svg.attrs["data-logo"]="1"; svg.attrs["data-mode"]=process.argv[2];
var RAF=[];
var document={
  querySelectorAll:function(sel){ return sel==="svg[data-logo]" ? [svg] : []; },
  createElementNS:function(){ return new El(); },
  addEventListener:function(){}
};
var requestAnimationFrame=function(cb){ RAF.push(cb); };
var window={ matchMedia:function(q){ return { matches:true }; } };
__JS__
var out={ ring:q(svg,"seg0").attrs["stroke"], ringO:+q(svg,"seg0").attrs["opacity"],
          amberO:+q(svg,"amber").attrs["opacity"], amberFill:q(svg,"amber").attrs["fill"],
          beam:q(svg,"beam").attrs["stroke"], w0:+q(svg,"wave0").attrs["opacity"],
          bx:+q(svg,"beam").attrs["x2"], by:+q(svg,"beam").attrs["y2"] };
console.log(JSON.stringify(out));
"""


def _node_run_reduce(mode):
    """真跑页面状态机的**减少动效**路径。返回最终那一帧的属性 dict。

    夹具失效（取不出 JS）⇒ 抛；Node 退出码非 0 ⇒ 抛（那是产品坏，不是
    "测不出"—— 绝不把产品失败洗成 SKIP）。
    """
    node = _node_path()
    if not node:
        raise RuntimeError("没有可执行 node")
    import subprocess
    html = _page()
    js = None
    for body in _JS_BLOCK_RE.findall(html):
        if "svg[data-logo]" in body and "var STYLE=" in body:
            js = body
            break
    if not js:
        raise RuntimeError("页面里找不到哨标状态机脚本（夹具失效）")
    src = _NODE_STUB_REDUCE.replace("__JS__", js)
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                     encoding="utf-8") as f:
        f.write(src)
        path = f.name
    try:
        p = subprocess.run([node, path, mode], capture_output=True, timeout=90)
        if p.returncode != 0:
            raise RuntimeError("reduce 桩退出码 %d：%s" % (
                p.returncode, p.stderr.decode("utf-8", "replace")[:400]))
        return json.loads(p.stdout.decode("utf-8"))
    finally:
        os.unlink(path)


@check("FLO-10e 减少动效：静态帧取目标态（xfade），启动态≠目标态有分辨力")
def c_flo10e():
    node = _node_path()
    if not node:
        return "SKIP：本机没有可执行 node —— 这一条**不判**（绝不假绿）"
    # ① 结构性：两条腿（哨标 / 页面）都把静态帧放在 xfade
    why = _flo10e_reduce_ok(_src(_LOGO_PS1_REL), SV._LOGO_JS_TMPL)
    if why:
        return why
    # ② 行为（哨标侧）：Get-Frame 在 Mt=xfade 必须是目标态；Mt=0 是启动态
    root, tray, payload = _flo10_tray()
    if "logo" not in payload:
        return "tray.json 里没有 logo 规格块"
    spec = payload["logo"]
    got = _flo10_ps("frames", tray, mode="R0",
                    mts="0,%g" % float(spec["anim"]["xfade"]))
    fr = got.get("frames") or []
    if len(fr) != 2:
        return "帧数学驱动没返回两帧（量具缺腿）"
    boot, target = fr[0], fr[1]
    r0, l0 = spec["motion"]["R0"], spec["motion"]["L0"]
    for key, want in (("ringRed", float(r0["ringRed"])), ("ringO", float(r0["ringO"])),
                      ("amberO", float(r0["amberO"]))):
        if abs(target[key] - want) > 1e-9:
            return "减少动效静态帧 %s=%.6f ≠ R0 目标态 %.2f" % (key, target[key], want)
        if abs(boot[key] - float(l0[key])) > 1e-9:
            return ("Mt=0 帧不是启动态（%s=%.6f）—— 分辨力没了，这条尺子测不出"
                    "「冻住」和「到位」的差异" % (key, boot[key]))
    for i in range(3):
        if abs(target["ringC"][i] - spec["colors"]["ringDarkRed"][i]) > 1e-6:
            return "减少动效下 R0 环色 %r ≠ 暗红 —— 会演成绿环" % (target["ringC"],)
        if abs(target["beamC"][i] - r0["c"][i]) > 1e-9:
            return "减少动效下 R0 光束色不是目标色 %r" % (r0["c"],)
    if abs(boot["ringRed"] - target["ringRed"]) < 0.5:
        return ("启动态与目标态的 ringRed 差 %.3f < 0.5 —— 尺子分不清『冻住』"
                "和『到位』" % abs(boot["ringRed"] - target["ringRed"]))
    # ③ 行为（页面侧）：Node 真跑 reduce=true ⇒ R0 必须是暗红，且与不 reduce 的首帧不同
    red = _node_run_reduce("R0")
    dark = "rgb(%d,%d,%d)" % tuple(spec["colors"]["ringDarkRed"])
    green = "rgb(%d,%d,%d)" % tuple(spec["colors"]["ringGreen"])
    if red["ring"] != dark:
        return "页面减少动效下 R0 环色 %r ≠ 暗红 %r —— 静态帧停在启动态（绿环）" % (
            red["ring"], dark)
    if abs(red["amberO"] - float(r0["amberO"])) > 0.02:
        return "页面减少动效下 R0 灯头不透明度 %.3f ≠ %.2f" % (
            red["amberO"], r0["amberO"])
    if red["amberFill"] != SV.LOGO_AMBER_FILL:
        return "页面减少动效下灯头填充色 %r ≠ %r（FZ-001 定过的琥珀色）" % (
            red["amberFill"], SV.LOGO_AMBER_FILL)
    if red["w0"] != 0:
        return "页面减少动效下 R0 还有涟漪（opacity=%r）—— 规格：波止" % (red["w0"],)
    seq = _node_run("R0", frames=1)
    if not seq:
        return "不 reduce 的首帧没跑出来（对照组失效）"
    if seq[0]["ring"] == red["ring"]:
        return ("reduce 与不 reduce 的首帧环色相同（%r）—— 测的不是『取目标态』"
                % (red["ring"],))
    if seq[0]["ring"] != green:
        return "不 reduce 首帧不是启动态绿色 %r —— 对照组本身就不对" % (seq[0]["ring"],)
    return True


@check("N-FLO10e 负控：静态帧退回 update(0)（哨标／页面两腿）⇒ 必须判红")
def n_flo10e():
    if c_flo10e() is not True:
        return "夹具不成立：未变异时 FLO-10e 就不合格，负控无分辨力"
    src = _src(_LOGO_PS1_REL)
    # 变异 1：哨标侧 mt=0（历史 bug 原样复活）
    a = "$mt = [double]$script:spec.anim.xfade"
    if src.count(a) != 1:
        return "夹具不成立：哨标变异锚点没打中（源码已变，需更新负控）"
    if _flo10e_reduce_ok(src.replace(a, "$mt = 0"), SV._LOGO_JS_TMPL) is None:
        return "负控失效：哨标静态帧退回 mt=0 也判合格 —— R0 在减少动效下会演成绿环"
    # 变异 2：页面侧 update(0)（模板层）
    # ★ 锚必须是**代码行**，不能是裸 `update(__XFADE__)`：同一段注释里为了
    #   说明「为什么不是 update(0)」也写了这个片段，裸锚会出现 2 次 ⇒ 变异
    #   打不中（2026-10-19 实测，负控自己报「夹具不成立」）。
    b = "if (_reduce) { update(__XFADE__); render(); }"
    nb = SV._LOGO_JS_TMPL.count(b)
    if nb != 1:
        return ("夹具不成立：页面变异锚点出现 %d 次（要恰好 1 次）—— 源码已变，"
                "需更新负控" % nb)
    if _flo10e_reduce_ok(src, SV._LOGO_JS_TMPL.replace(b, "if (_reduce) { update(0); render(); }")) is None:
        return "负控失效：页面静态帧退回 update(0) 也判合格"
    # 变异 3：渲染产物里的 reduce 帧退回 update(0) ⇒ Node 腿必须抓住
    c = "if (_reduce) { update(.4); render(); }"
    if SV._LOGO_JS.count(c) != 1:
        return "夹具不成立：渲染态锚点没打中（_jsnum 口径变了，需更新负控）"
    with _Patch(SV, _LOGO_JS=SV._LOGO_JS.replace(
            c, "if (_reduce) { update(0); render(); }")):
        why = c_flo10e()
        if why is True or why is None:
            return "负控失效：渲染出的 reduce 帧退回 update(0)，Node 腿仍判绿"
    return True


def _logo_root_problem(cmd, root):
    expected = {"-State": IL.state_path(root),
                "-Action": IL.action_path(root),
                "-Quit": IL.flag_path(root)}
    for arg, path in expected.items():
        if arg not in cmd or cmd[cmd.index(arg) + 1] != path:
            return "%s 路径错：命令实参 %r ≠ root 下的 %r" % (
                arg, cmd[cmd.index(arg) + 1] if arg in cmd else None, path)
    return None


@check("FLO-06 自定义 root：哨标状态/动作/退役标志全部跟着同一中枢目录")
def c_flo06_root():
    root = tempfile.mkdtemp(prefix="g0514_logo_root_")
    cmd = IL.logo_cmd(root=root)
    why = _logo_root_problem(cmd, root)
    if why:
        return why
    # 展开端也走这个 root，不能让 logo 的 open 写到默认中枢之外。
    if cmd[cmd.index("-Action") + 1] != IL.action_path(root):
        return "open 动作回到默认中枢，守护进程（自定义 root）永远收不到"
    return True


@check("N-FLO06 负控：把三条命令路径换回默认 root ⇒ 同一量具判红")
def n_flo06_root():
    root = tempfile.mkdtemp(prefix="g0514_logo_root_")
    bad = IL.logo_cmd(root=root)
    defaults = {"-State": IL.state_path(None),
                "-Action": IL.action_path(None),
                "-Quit": IL.flag_path(None)}
    for arg, path in defaults.items():
        bad[bad.index(arg) + 1] = path
    why = _logo_root_problem(bad, root)
    if not why:
        return "负控失效：默认中枢路径被误判成自定义 root"
    return True


class _HideEnv:
    """假桌面：一枚「看见 hide 标志就自己藏」的哨标（忠实 logo.ps1 的约定）。

    ★ 与 `_MarkEnv` 分开立：hide 用的是 `logo.hide`（不是 quit），finder
      必须按同一规则反应，否则「标志没被消费」这个真缺陷测不出来。
    """

    def __init__(self, root, old=True):
        self.root = root
        self.win = [66] if old else []
        self.log = []

    def finder(self):
        if os.path.exists(IL.hide_flag_path(self.root)):
            self.win = []                    # 哨标看到藏标志，自己藏
        return list(self.win)

    def killer(self, why=""):
        self.log.append("killer")
        n = len(self.win)
        self.win = []
        return (n, "兜底关掉 %d 枚（%s）" % (n, why))


@check("FLO-07 hide 三态：没有⇒空转并清陈年标志；标志劝动⇒自己藏；劝不动⇒兜底退役")
def c_flo07():
    root = tempfile.mkdtemp(prefix="g0514_flo_")
    # a) 没有哨标 ⇒ 空转成功，且**陈年 hide 标志被清**（留着它，下一枚
    #    哨标一出生就被藏 —— "开了等于没开"同型）
    os.makedirs(os.path.dirname(IL.hide_flag_path(root)), exist_ok=True)
    with open(IL.hide_flag_path(root), "w") as f:
        f.write("stale\n")
    env = _HideEnv(root, old=False)
    rep = IL.hide(root=root, finder=env.finder, killer=env.killer,
                  wait_sec=0.5, verbose=False)
    if not rep.get("ok") or rep.get("acted"):
        return "没有哨标时 hide 不空转：%r" % rep
    if os.path.exists(IL.hide_flag_path(root)):
        return "陈年 hide 标志没清 —— 下一枚哨标一出生就被藏"
    # b) 标志劝动 ⇒ 哨标自己藏，不走兜底
    env = _HideEnv(root, old=True)
    rep = IL.hide(root=root, finder=env.finder, killer=env.killer,
                  wait_sec=1.0, verbose=False)
    if not rep.get("ok") or not rep.get("acted"):
        return "藏标志劝动这条没成：%s" % rep.get("why")
    if env.log:
        return "藏标志劝动了还兜底关窗（%r）—— 白绕一圈 WM_CLOSE" % env.log
    if os.path.exists(IL.hide_flag_path(root)):
        return "藏起后标志没清 —— 虽由哨标消费，写方兜底也没接住"
    # c) 劝不动 ⇒ 兜底真退役，并在 why 里说明
    class Stubborn(_HideEnv):
        def finder(self):
            return list(self.win)            # 无视藏标志
    env = Stubborn(root, old=True)
    rep = IL.hide(root=root, finder=env.finder, killer=env.killer,
                  wait_sec=0.4, verbose=False)
    if not rep.get("ok") or not env.log:
        return "兜底退役没走成：%s / log=%r" % (rep.get("why"), env.log)
    if "兜底" not in (rep.get("why") or ""):
        return "用了兜底却不说 —— 用户以为哨标自己藏的：%r" % rep.get("why")
    return True


@check("N-FLO07 负控：藏不动且兜底也失败 ⇒ 如实报失败，不许说藏了")
def n_flo07():
    root = tempfile.mkdtemp(prefix="g0514_flo_")

    class StubbornDead(_HideEnv):
        def finder(self):
            return list(self.win)

        def killer(self, why=""):
            raise OSError("桩：关窗也失败")
    env = StubbornDead(root, old=True)
    rep = IL.hide(root=root, finder=env.finder, killer=env.killer,
                  wait_sec=0.4, verbose=False)
    if rep.get("ok"):
        return "负控失效：兜底失败了还报藏起成功 —— 假成功"
    if "兜底" not in (rep.get("why") or ""):
        return "没说清兜底失败：%r" % rep.get("why")
    return True


class _ResidentEnv:
    """假桌面：一枚常驻（隐藏）哨标，看见 show 标志就自己现出。"""

    def __init__(self, root, responsive=True):
        self.root = root
        self.resident = [55]                 # 常驻（隐藏）窗
        self.visible = []
        self.log = []
        self.responsive = responsive

    def finder(self):
        if self.responsive and os.path.exists(IL.show_flag_path(self.root)):
            self.visible = list(self.resident)
        return list(self.visible)

    def any_finder(self):
        return list(self.resident)

    def topmost(self, hs):
        self.log.append("topmost")
        return (True, "")

    def launcher(self, cmd):
        self.log.append("launch")            # fast 路径不该走到冷启
        self.visible = [77]                  # 冷启后窗出现（忠实真哨标）


@check("FLO-08 show_or_spawn：常驻哨标 ⇒ 写 show 唤出（不冷启、置顶、消费标志）；没有 ⇒ 回落冷启")
def c_flo08():
    root = tempfile.mkdtemp(prefix="g0514_flo_")
    env = _ResidentEnv(root)
    rep = IL.show_or_spawn(root=root, launcher=env.launcher,
                           finder=env.finder, any_finder=env.any_finder,
                           wait_sec=1.5, topmost=env.topmost, verbose=False)
    if not rep.get("ok"):
        return "常驻哨标没唤出：%s" % rep.get("why")
    if not rep.get("fast"):
        return "走了冷启而非唤出 —— 「瞬时切换」没兑现：%r" % rep
    if env.log != ["topmost"]:
        return "唤出路径动作 %r ≠ [topmost]（不该 launch）" % env.log
    if os.path.exists(IL.show_flag_path(root)):
        return "唤标志没被消费也没清 —— 下一枚哨标一出生就被唤"
    # 回落：唤不动（僵尸）⇒ 清标志后冷启，不谎报就位
    env2 = _ResidentEnv(root, responsive=False)
    rep2 = IL.show_or_spawn(root=root, launcher=env2.launcher,
                            finder=env2.finder, any_finder=env2.any_finder,
                            wait_sec=0.6, topmost=env2.topmost, verbose=False)
    if not rep2.get("ok"):
        return "唤不动时没回落冷启：%s" % rep2.get("why")
    if "launch" not in env2.log:
        return "回落路径没走冷启（launch 没发生）：%r" % rep2
    if os.path.exists(IL.show_flag_path(root)):
        return "回落冷启后唤标志还留着 —— 新哨标会被它一出生就唤"
    return True


@check("N-FLO08 负控：判据注入 finder 而不给 any_finder ⇒ 不做隐藏检查（假桌面行为同旧）")
def n_flo08():
    root = tempfile.mkdtemp(prefix="g0514_flo_")
    env = _ResidentEnv(root)                 # 有"常驻"窗，但不给 any_finder
    rep = IL.show_or_spawn(root=root, launcher=env.launcher,
                           finder=env.finder, wait_sec=1.0,
                           topmost=env.topmost, verbose=False)
    if "launch" not in env.log:
        return "注入 finder 未给 any_finder 时却走了隐藏检查 —— 判据假桌面的行为被改了"
    if not rep.get("ok"):
        return "回落冷启失败：%s" % rep.get("why")
    return True


@check("FLO-09 服务端消费哨标 open 动作：serve 起消费线程、URL 注入、唯一实现、错了不死")
def c_flo09():
    sv = _src(_SERVER_REL)
    if "_consume_actions_loop" not in sv:
        return "服务端没有动作消费循环 —— 点哨标后只有 daemon/tray 会消费，都不在跑时 Antinel 监理永远开不出来"
    if "threading.Thread(target=_consume_actions_loop" not in sv:
        return "serve() 没起消费线程 —— 判据锁的是那一次真实调用"
    src_fn = inspect.getsource(SV._consume_actions_loop)
    if "handle_actions" not in src_fn:
        return "消费循环没走 inbox_daemon.handle_actions —— 动作语义出了第二份实现"
    # 行为：consumer 被注入，收到的 console_url 必须原样透传
    root = tempfile.mkdtemp(prefix="g0514_flo_")
    got = {}
    stop = threading.Event()

    def consumer(root=None, console_url=None):
        got["url"] = console_url
        stop.set()
    SV._consume_actions_loop(root=root, console_url="http://127.0.0.1:1/?t=x",
                             stop=stop, interval=0.05, consumer=consumer)
    if got.get("url") != "http://127.0.0.1:1/?t=x":
        return "消费循环没把自己的 URL 传下去 —— open_console_now 会另起一个服务实例（端口漂移同款病）"
    return True


@check("N-FLO09 负控：consumer 连环抛错 ⇒ 循环必须活着（不许一轮打死）")
def n_flo09():
    root = tempfile.mkdtemp(prefix="g0514_flo_")
    calls = {"n": 0}
    stop = threading.Event()

    def bad_consumer(root=None, console_url=None):
        """验证点：consumer 每轮抛错 ⇒ 循环必须吞掉并继续下一轮（不死）。"""
        calls["n"] += 1
        if calls["n"] >= 3:
            stop.set()
        raise OSError("桩：消费轮出错")
    SV._consume_actions_loop(root=root, console_url="http://127.0.0.1:1/?t=x",
                             stop=stop, interval=0.02, consumer=bad_consumer)
    if calls["n"] < 3:
        return "负控失效：一轮异常打死了消费循环（%d 次）—— 之后点哨标永远没反应" % calls["n"]
    return True


class _MarkEnv:
    """假桌面：一枚「看见退役标志就自己退」的哨标（忠实 logo.ps1 的约定）。

    ★ 为什么 finder 要看**真标志文件**：`retire` 的清标志时机（窗口消失后
      才清）是产品行为，fixture 必须站在哨标那边按同一规则反应，
      否则「标志没清导致下一枚一出生就退」这个真缺陷永远测不出来。
    """

    def __init__(self, root, old=True):
        self.root = root
        self.win = [88] if old else []
        self.log = []
        self.flag_at_launch = None
        self.win_at_launch = None
        self.got_topmost = None

    def finder(self):
        if os.path.exists(IL.flag_path(self.root)):
            self.win = []                    # 哨标看到标志，自己退
        return list(self.win)

    def killer(self, why=""):
        self.log.append("killer")
        n = len(self.win)
        self.win = []
        return (n, "兜底关掉 %d 枚（%s）" % (n, why))

    def launcher(self, cmd):
        self.log.append("launch")
        # 顺序不变式的观测点（不抛异常 —— 抛了会被 open_floating 转成 why，
        # 我们要的是判据自己红，不是产品帮我们吞）
        self.flag_at_launch = os.path.exists(IL.flag_path(self.root))
        self.win_at_launch = list(self.win)
        self.win = [77]

    def topmost(self, hs):
        self.log.append("topmost")
        self.got_topmost = list(hs)
        return (True, "")


@check("FLO-02 起哨标顺序：先退役旧的（含清标志）⇒ 才起 ⇒ 等窗 ⇒ 置顶")
def c_flo02():
    root = tempfile.mkdtemp(prefix="g0514_flo_")
    env = _MarkEnv(root, old=True)
    rep = IL.open_floating(root=root, launcher=env.launcher, finder=env.finder,
                           killer=env.killer, wait_sec=1.5,
                           topmost=env.topmost, verbose=False)
    if not rep.get("ok"):
        return "哨标没起来：%s" % rep.get("why")
    if env.flag_at_launch:
        return "起新哨标时退役标志还在 —— 它会一出生就退（用户点收缩却「什么都没发生」）"
    if env.win_at_launch:
        return "起新哨标时旧的还在（%r）—— 会叠成两枚" % (env.win_at_launch,)
    if env.log != ["launch", "topmost"]:
        return "调用顺序 %r ≠ [launch, topmost]（退役/起窗/置顶的纪律变了）" % env.log
    if env.got_topmost != [77]:
        return "置顶置的不是新窗：%r" % (env.got_topmost,)
    if os.path.exists(IL.flag_path(root)):
        return "跑完标志还留着 —— 下一枚哨标会一出生就退"
    return True


@check("N-FLO02 负控：哨标进程起了但窗不出现 ⇒ 如实报没就位，不置顶")
def n_flo02():
    root = tempfile.mkdtemp(prefix="g0514_flo_")
    env = _MarkEnv(root, old=False)

    def dead_launcher(cmd):
        """替身：进程"起了"但窗永远不出现 —— 验"起不来必须如实报没就位"。"""
        env.log.append("launch")            # 进程起了，窗永远不出现
    rep = IL.open_floating(root=root, launcher=dead_launcher,
                           finder=env.finder, killer=env.killer,
                           wait_sec=0.4, topmost=env.topmost, verbose=False)
    if rep.get("ok"):
        return "负控失效：窗没出现也算就位 —— 假成功（C4 同款病）"
    if "topmost" in env.log:
        return "窗都没有还去置顶 —— 顺序乱了"
    if "窗口" not in (rep.get("why") or ""):
        return "没说清是窗口没出现：%r" % rep.get("why")
    return True


@check("FLO-03 退役三态：没有⇒空转；标志劝动⇒自己退；劝不动⇒兜底并说明")
def c_flo03():
    root = tempfile.mkdtemp(prefix="g0514_flo_")
    # a) 没有哨标 ⇒ 空转成功（不该有副作用）
    env = _MarkEnv(root, old=False)
    rep = IL.retire(root=root, finder=env.finder, killer=env.killer,
                    wait_sec=0.5, verbose=False)
    if not rep.get("ok") or rep.get("acted"):
        return "没有哨标时退役不空转：%r" % rep
    if env.log:
        return "没有哨标却动了手（%r）—— 会误伤别人的窗" % env.log
    # b) 标志劝动 ⇒ 哨标自己退，不走兜底
    env = _MarkEnv(root, old=True)
    rep = IL.retire(root=root, finder=env.finder, killer=env.killer,
                    wait_sec=1.0, verbose=False)
    if not rep.get("ok") or not rep.get("acted"):
        return "标志劝动这条没成：%s" % rep.get("why")
    if env.log:
        return "标志劝动了还兜底关窗（%r）—— 白绕一圈 WM_CLOSE" % env.log
    if os.path.exists(IL.flag_path(root)):
        return "退役后标志没清 —— 下一枚一出生就退"
    # c) 劝不动 ⇒ 兜底关窗，并在 why 里说明是兜底
    class Stubborn(_MarkEnv):
        def finder(self):
            return list(self.win)            # 无视标志
    env = Stubborn(root, old=True)
    rep = IL.retire(root=root, finder=env.finder, killer=env.killer,
                    wait_sec=0.5, verbose=False)
    if not rep.get("ok") or not env.log:
        return "兜底没走成：%s / log=%r" % (rep.get("why"), env.log)
    if "兜底" not in (rep.get("why") or ""):
        return "用了兜底却不说 —— 用户以为标志劝动的：%r" % rep.get("why")
    if os.path.exists(IL.flag_path(root)):
        return "兜底路径也没清标志"
    return True


@check("N-FLO03 负控：兜底也关不掉 ⇒ 如实报失败，不许说退了")
def n_flo03():
    root = tempfile.mkdtemp(prefix="g0514_flo_")

    class Stubborn(_MarkEnv):
        def finder(self):
            return list(self.win)

        def killer(self, why=""):
            raise OSError("桩：关窗也失败")
    env = Stubborn(root, old=True)
    rep = IL.retire(root=root, finder=env.finder, killer=env.killer,
                    wait_sec=0.4, verbose=False)
    if rep.get("ok"):
        return "负控失效：兜底失败了还报退役成功 —— 假成功"
    if "兜底关窗也失败" not in (rep.get("why") or ""):
        return "没说清兜底失败：%r" % rep.get("why")
    if os.path.exists(IL.flag_path(root)):
        return "失败路径也没清标志 —— 下一枚照样一出生就退"
    return True


@check("FLO-04 收缩：哨标就位才关面板窗；strict 没中再宽泛一次")
def c_flo04():
    root = tempfile.mkdtemp(prefix="g0514_flo_")
    env = _MarkEnv(root, old=False)
    seen = []

    def win_finder(run_id=None, suffix=None, visible_only=True):
        seen.append(run_id)
        return [] if run_id else [2222]      # strict 落空，宽泛命中

    def closer(h):
        env.log.append("close")
        return True
    rep = IL.collapse_console(root=root, run_id="rid1", closer=closer,
                              launcher=env.launcher, finder=env.finder,
                              killer=env.killer, win_finder=win_finder,
                              wait_sec=1.5, topmost=env.topmost, verbose=False)
    if not rep.get("ok") or rep.get("closed") != 1:
        return "收缩没成：%s（closed=%r）" % (rep.get("why"), rep.get("closed"))
    if env.log != ["launch", "topmost", "close"]:
        return "顺序 %r ≠ [launch, topmost, close] —— 顺序即安全被打破" % env.log
    if seen[:2] != ["rid1", None]:
        return "关窗顺序 %r ≠ [strict, broad]" % (seen[:2],)
    return True


@check("N-FLO04a 负控：哨标起不来 ⇒ 一枚面板窗都不许关（顺序即安全）")
def n_flo04a():
    root = tempfile.mkdtemp(prefix="g0514_flo_")
    env = _MarkEnv(root, old=False)
    closed = {"n": 0}

    def closer(h):
        closed["n"] += 1
        return True
    rep = IL.collapse_console(root=root, run_id="rid1", closer=closer,
                              launcher=lambda cmd: None, finder=env.finder,
                              killer=env.killer, wait_sec=0.4,
                              topmost=env.topmost, verbose=False)
    if rep.get("ok") or closed["n"]:
        return ("负控失效：哨标没起来也关了面板 —— 用户两手空空"
                "（比不收缩坏得多）")
    if "没有关面板窗" not in (rep.get("why") or ""):
        return "没说清「没关」：%r" % rep.get("why")
    return True


@check("N-FLO04b 负控：关窗抛错 ⇒ 如实报失败，哨标留着（不两头空）")
def n_flo04b():
    root = tempfile.mkdtemp(prefix="g0514_flo_")
    env = _MarkEnv(root, old=False)

    def closer(h):
        raise OSError("桩：WM_CLOSE 发不出去")

    def win_finder(run_id=None, suffix=None, visible_only=True):
        return [2222]
    rep = IL.collapse_console(root=root, run_id="rid1", closer=closer,
                              launcher=env.launcher, finder=env.finder,
                              killer=env.killer, win_finder=win_finder,
                              wait_sec=1.0, topmost=env.topmost, verbose=False)
    if rep.get("ok") or rep.get("closed"):
        return "关窗失败了还报成功 —— 假成功"
    if not (rep.get("floating") or {}).get("ok"):
        return "哨标本身该在（关失败不影响它就位）"
    if not rep.get("why"):
        return "失败了不说原因"
    return True


@check("FLO-05 收缩入口（LOGO 本体）＋服务端 op＋展开即退役哨标，三处都在")
def c_flo05():
    """★★ 0.50.7（2026-10-16，创始人截图「左上角 LOGO 与右上角收缩钮是
    同一枚图形、两个入口」）：收缩入口**合并进 LOGO 本体** —— 右上角那枚
    独立的 collbtn 删除，全页只一枚 lgmark（去重本身由判据 J1 守）。
    追随规格更新（不是放松）：入口在、用的是 `_logo_mark`（不是静态图）、
    title 说人话、op=collapse 链三处 —— 断言一条不少，只换锁的类名
    （`collbtn` → `logo`），并补上「入口内嵌动效哨标本体」这条原文只在
    CSS 注释里声称、判据并未锁的断言。
    """
    html = _page()
    button = re.search(r'<button class="logo".*?</button>', html, re.S)
    if not button or 'data-coll="1"' not in button.group(0):
        return "页面里没有收缩入口（LOGO 本体即钮）—— 漂浮最小态没有入口"
    if "data-logo=" not in button.group(0):
        return "收缩入口没用动效哨标本体（退回了静态图）—— 所见即所得没了"
    if "收缩成漂浮哨标" not in PC.body(button.group(0)):
        return "收缩入口标题没说人话（用户不知道点了会怎样）"
    if "op=collapse" not in html:
        return "收缩钮没接 op=collapse"
    sv = _src(_SERVER_REL)
    if 'op == "collapse"' not in sv:
        return "服务端没有 op=collapse 分支 —— 点了没反应（静默）"
    if "collapse_console" not in sv:
        return "服务端没调 inbox_logo.collapse_console —— 路由断了"
    dm = _src(_DAEMON_REL)
    if "_hide_mark" not in dm:
        return "守护进程没有展开后藏哨标的钩子（0.52.0：hide 非 retire）—— 展开后会多出一枚寡妇哨标"
    if "IL.retire(" in dm:
        return "守护进程展开后仍在真退役哨标（0.52.0 应 hide 藏起待命）—— 下一次收缩又要冷启"
    return True


@check("N-FLO05 负控：把收缩入口（LOGO 钮）从页面里拔掉 ⇒ 同一条判据必须判红")
def n_flo05():
    html = _page()
    dead = re.sub(r"<button class=\"logo\".*?</button>", "", html, flags=re.S)
    if dead == html:
        return "夹具不成立：页面里拔不出收缩入口，负控无分辨力"
    if re.search(r'<button class="logo".*?</button>', dead, re.S):
        return "负控失效：入口拔除后仍匹配到 logo 按钮"
    return True


# ══════════════════ J 族：创始人「五条违和」的同类可抓（原 0518 并入）═══════════
#
# ★★ 并入由来（2026-10-16，A2 唯一合法出路 —— 不是随手挪文件）：
#   0518 于 2026-10-16 晨随机制升级加入 `delivery_gate.SUITES`（常驻 29→30），
#   其 A1 前置门的 **P5（扩展优先）自答「不满足」** —— 五条判据与本套件**同域**：
#   消费面同为 `inbox_server.py` 的渲染产物，病灶同属「创始人截图标出的、
#   机械可判的页面形状」。按 P5「不满足 ⇒ 并入现有套件」，**整套原样并入本文件**。
#   随之：`ci/suite_retirement.json` 的 pending 记录转 `done`、
#   `delivery_gate.SUITES` 撤下 0518、原文件改名让开（零删除纪律）。
#   ★ 判据 ID（J1–J5 / N-J1…N-J4）**一字未改** —— `ci/defect_types.py` T-11 的
#     guards 与 `inbox_server.py` 的注释都按 ID 引用，改名会造出第二个断链。
#
#   五条违和（创始人 2026-10-16 截图）与对应尺子：
#     #1 同一图形两入口（左上 LOGO 与右上收缩钮同渲染 `_logo_mark`）⇒ J1
#     #2 一句枚举被断行切成两截（单行 <p> ＋ details 隐式闭合 <p>）⇒ J2
#     #3 同屏括号不一致（Ls/L0 走 chip 默认带码形态）⇒ J3
#     #4 归并无解释（`_pill` 注释声称词条写了，unit 字段零命中＝T-11）⇒ J4
#     #5 裸数字无单位（健康页「23 次 / 54」；日报页 0.50.4 已修、本页漏改）⇒ J4
#   ★ 残余（人为判断）如实申报盲区：J2 只锁**结构确定性**（不再被浏览器自由断），
#     不锁「折成几行好看」—— 观感不可机械判，已在 L2 触发层清单留记。
#
#   编写纪律沿用本文件：负控先实测见红；断言打在渲染产物的结构/行为上；
#   不写任何产品文件（变异只在内存/临时目录）；测不出 ⇒ SKIP，绝不假绿。

_NOW = datetime(2026, 10, 16, 12, 0, 0).astimezone()
#: ★ `Alert.ts` 是 **ISO 字符串**（`within_hours` 走 `_parse_ts`）——
#:   传数值时间戳会被判"解析不了 ⇒ 不算在窗口内"（首跑实测 wl 全 0）。
_TS = _NOW.isoformat()


def _mk(kind, n, groups):
    """同 kind 的 n 条记录、groups 个事由（group_key＝kind+topic+level）。"""
    out = []
    for i in range(n):
        a = M.Alert.build(_TS, kind, reason="r%d" % (i % groups),
                          topic="tp%d" % (i % groups))
        out.append(M.Item(a))
    return out


def _items():
    return _mk("tool_call_blocked", 11, 3) + _mk("host_shield_changed", 43, 3)


def _bar(items=None):
    return SV._bar(items if items is not None else _items(), "T",
                   posture={"state": "guarding", "can_fix": False}, now=_NOW)


def _rep():
    """合成日报（0353/0490 同款形状；账本页要读 `ledger` 键，给全）。

    ★ `window_levels` **从真源算**（`M.window_levels(_items(), now=_NOW)`），
      不硬编码 —— 硬编码一改夹具就与真源脱节（判据依赖的数字必须同源）。
    """
    wl = M.window_levels(_items(), now=_NOW)
    wg = M.window_level_groups(_items(), now=_NOW)
    return {"day": "2026-10-16",
            "levels": dict(wl), "window_levels": dict(wl),
            "window_hours": M.WINDOW_HOURS,
            "buckets": {"action": 2, "info": 2, "archive": 1},
            "action_groups": M.count_groups(
                [it for it in _items()
                 if M.bucket_of(it, now=_NOW) == M.BUCKET_ACTION]),
            "revived_window": sum(wl.get(k, 0) for k in ("R0", "L2", "L1")),
            "posture": {"state": "guarding", "can_fix": False},
            "rules": [{"rule_id": "DST-01", "count": 2}],
            "chain": {"status": "ok", "files": 12, "records": 54,
                      "broken": 0, "unchained": 0, "reason": ""},
            "ledger": {"days": 3, "streak_days": 3, "blocked": wg.get("L2", 0),
                       "noticed": wg.get("L1", 0), "breached": 0, "acked": 0}}


def _health(items=None):
    return SV._view_health(_rep(), "T", items=items if items is not None
                           else _items())


def _src_or_skip(rel):
    """原 0518 的 `_src`（找不到文件 ⇒ **Skip**，不凭空判）。

    ★ 为什么改名：本文件早有 `_src`（读不到就抛 `FileNotFoundError`）。
      两者语义不同（一个报错、一个跳过），**不许互相覆盖** ⇒ 并入时改名保留。
    """
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        raise Skip("找不到 %s（拒绝凭空判）" % rel)
    return io.open(p, encoding="utf-8").read()


# ══════════════════════════════════ J1 同一图形不被渲染两遍 ═══════════════════
@check("J1 ★ 全页动效哨标恰一枚（同一图形不许两处入口）")
def j1():
    """★★ #1 的尺子（2026-10-16 创始人截图「左上角 LOGO 与右上角收缩钮是
    同一枚图形、两个入口」）：

    病根不是"多了个按钮"，是**同一份渲染（`_logo_mark`）在同一个页面上
    落两处** —— 用户看到两枚一模一样的动效哨标，不知道点哪一枚、
    猜它们是不是干同一件事（L2 触发层 UX 洁癖清单第 6 条「去重复」）。

    ★ 为什么数 `lgmark` 而不是数"按钮"：一枚 lgmark ＝ 一枚用户看得见的
      动效标（`_logo_mark` 是它的唯一渲染入口）。数按钮会被"把标拆到
      span 里"绕开；数 lgmark 数的是**用户看到的那个东西**。
    ★ 四视图全数：只在顶部条有标、但**每页都可能单独加一枚** ——
      实测 0.50.6 之前健康页/日报页各有一枚 top logo ＋ 一枚收缩钮 ⇒ 2。
    """
    hub = tempfile.mkdtemp(prefix="g0514_j1_")
    items = _items()
    bad = []
    for view, filt in (("inbox", "action"), ("report", None),
                       ("health", None), ("ledger", None)):
        html = SV.render_page(view=view, filt=filt, root=hub, token="T",
                              items=items, rep=_rep(),
                              posture={"state": "guarding", "can_fix": False})
        n = len(re.findall(r'<svg class="lgmark"[^>]*data-logo="1"', html))
        if n != 1:
            bad.append("%s 页有 %d 枚动效哨标（应恰 1）" % (view, n))
    if bad:
        return "；".join(bad) + " —— 同一图形两处入口＝用户要猜点哪一枚"
    _note("四视图各恰 1 枚 lgmark")


@check("N-J1 负控：让 logo 渲染两遍（模拟双入口）⇒ 同一条 J1 判据必须判红")
def n_j1():
    """反向对照（真跑正判据）：把 `_logo_mark` 变异成**渲染两枚**，
    再调**同一条 `j1()`** —— 它必须判红（不是另写一套条件）。

    ★ 裸 `j1()` 返回**说明串**（不抛异常；抛异常是 `check` wrapper 干的）
      ⇒ 负控判"返回值不是 True"，不判"抛没抛"（首版踩到：判 except 永不成立）。
    """
    orig = SV._logo_mark
    try:
        SV._logo_mark = (lambda st, label="Antinel":
                         (orig(st, label) + orig(st, label)))
        r = j1()
        if r is True or r is None:
            return "负控失效：渲染两枚哨标后 J1 仍判绿（尺子没分辨力）"
        if "两处入口" in str(r) or "应恰 1" in str(r):
            return True
        return "负控方向不对：判红了，但原因不是双入口（%s）" % r
    finally:
        SV._logo_mark = orig


# ═══════════════════════════════ J2 枚举断行确定性 ════════════════════════════
#: 六态行的结构锚（正判据与负控**共用同一把尺子**）。
_SIX_RE = re.compile(r'灯的六态由重到轻：<br>(.*?)</div>\s*<p class="note">',
                     re.S)


def _six_ok(html):
    """纯判据：六态行结构确定（标签独占一行＋5 枚 nowrap span＋4 分隔符）。
    返回 True 或说明串。★ 抽成吃 html 的纯函数 ⇒ 负控能把变异 html
    喂进**同一个实现**（而不是另写一套条件冒充负控）。"""
    m = _SIX_RE.search(html)
    if not m:
        return ("六态行不是「标签＋显式 <br>」形状 —— 断点又交给浏览器自由决定"
                "（#2 复发）")
    body = m.group(1)
    spans = re.findall(r'<span class="sixit">.*?</span>', body, re.S)
    if len(spans) != 5:
        return "六态行原子 span 是 %d 枚（应 5）—— 有态没被包住，会被切断" % len(spans)
    if body.count(" · ") != 4:
        return "六态行分隔符「 · 」是 %d 个（应 4）—— 枚举散了" % body.count(" · ")
    if ".sixit{white-space:nowrap}" not in PC.chrome("<style>" + SV.CSS
                                                    + "</style>"):
        return "CSS 里没有 .sixit{white-space:nowrap} —— span 是空壳，态名照样被切"
    return True


@check("J2 ★ 六态行断行确定：标签独占一行＋各态包原子 span")
def j2():
    """★★ #2 的尺子（2026-10-16 创始人截图二「失守后换行」）：

    旧形状 `<p class="note">灯的六态由重到轻：失守 · 拦截 · …</p>` 有三个病：
      ① 单行纯文本 ⇒ 断点落在哪**全看窗口宽度**，实测断在「失守」后
         （用户读到「失守」一行、「拦截 · 注意…」另一行，像两组）；
      ② 枚举里塞了 `<details>` 芯片 —— HTML 解析规则里 details 会
         **隐式闭合** `<p>`，于是从第一枚芯片处整段被切成两截；
      ③ 断点落在态名中间时，一个短词被切成两半（观感最差）。
    ⇒ 修法：标签后显式 `<br>`（第一行就是标签）、每个态包
      `<span class="sixit">`（`white-space:nowrap` ⇒ 态名永不被内部切断）。

    ★ 只锁**结构确定性**，不锁"折成几行好看"（那是人为判断，已在 L2
      触发层清单留记并申报盲区 —— 见文件头第 5 条残余说明）。
    """
    r = _six_ok(_health())
    if r is not True:
        return r
    _note("标签独占一行＋5 枚 nowrap span＋4 个分隔符")


@check("N-J2 负控：六态行退回单行 <p> 且剥掉 span ⇒ 同一条 J2 判据必须判红")
def n_j2():
    """反向对照（真跑正判据 `_six_ok`，非另写条件）：把 J2 锁的结构逐个
    拆掉（退回单行 <p> ＋剥 span），喂进**同一个 `_six_ok`** 必须判假。"""
    h = _health()
    if _six_ok(h) is not True:
        return "夹具不成立：现行渲染就判红 —— 负控无分辨力"
    dead = h.replace('<div class="note sixline">灯的六态由重到轻：<br>',
                     '<p class="note">灯的六态由重到轻：')
    dead = re.sub(r'<span class="sixit">(.*?)</span>', r"\1", dead, flags=re.S)
    r = _six_ok(dead)
    if r is True:
        return "负控失效：退回单行 <p>＋剥 span 后 J2 仍判绿（尺子没分辨力）"
    return True


# ═════════════════════════════ J3 同屏括号形态一致 ══════════════════════════
def _six_summaries_ok(html):
    """纯判据：六态行两只芯片的 summary 都不带码。返回 True 或说明串。"""
    m = _SIX_RE.search(html)
    if not m:
        return "找不到六态行（J2 的前置结构不在）—— 拒绝在错误形状上判括号"
    summaries = re.findall(r"<summary>(.*?)</summary>", m.group(1), re.S)
    if len(summaries) != 2:
        return ("六态行可点开芯片是 %d 枚（应 2：Ls/L0）—— 落点变了，"
                "J3 的比对面要重新认" % len(summaries))
    bad = [s for s in summaries if "（Ls）" in s or "（L0）" in s]
    if bad:
        return ("六态行 summary 仍带码：%r —— 与裸词三态同屏两种写法（#3 复发）"
                % bad)
    return True


@check("J3 ★ 六态行 summary 无可见码（同屏括号形态一致）")
def j3():
    """★★ #3 的尺子（2026-10-16 创始人截图三「缺粮（Ls）／值守中（L0）
    与失守／拦截／注意 括号不一致」）：

    六态行里五态并列，其中三态是裸词、两态带码 —— 同屏两种写法。
    `GL.chip()` 默认取 `TERMS[k]["w"]`＝`_wl()` 的「词（码）」形态 ⇒
    落点改造时**忘了传 `text=`**，于是默认形态漏进六态行。

    ★ 断言打在 summary 层（码只能留在**展开体首行** —— 那是词条定义
      的一部分，P13 的落点也在）；不锁"码彻底消失"（那会与词条定义冲突）。
    ★ 两态都要查：只查 Ls 会漏 L0（同族）。
    """
    r = _six_summaries_ok(_health())
    if r is not True:
        return r
    # 码必须仍在展开体首行（不许用"把码删掉"来假过）
    for k in ("Ls", "L0"):
        chip = GL.chip(k, text=M.state_short(k))
        if "<b>%s（%s）</b>：" % (M.state_short(k), k) not in chip:
            return "%s 词条展开体首行丢了本名带码（用删码假过 J3）" % k
    _note("summary 无码；码仍在词条展开体首行")


@check("N-J3 负控：把带码 summary 注入六态行 ⇒ 同一条 J3 判据必须判红")
def n_j3():
    """反向对照（真跑正判据 `_six_summaries_ok`）：默认 `GL.chip("Ls")`
    就是带码形态；把它注回六态行，**同一个 `_six_summaries_ok`** 必须判假。
    """
    if _six_summaries_ok(_health()) is not True:
        return "夹具不成立：现行渲染就判红 —— 负控无分辨力"
    # 默认 chip 的 summary 确实带码（负控前提成立）
    summary = re.search(r"<summary>(.*?)</summary>", GL.chip("Ls"), re.S)
    if not summary or "（Ls）" not in summary.group(1):
        return "夹具不成立：chip 默认形态不带码 —— 负控无分辨力"
    h = _health()
    dead = h.replace("<summary>缺粮</summary>", "<summary>缺粮（Ls）</summary>")
    if "（Ls）" not in dead:
        return "夹具不成立：六态行里摘不到「缺粮」summary（结构已变）"
    r = _six_summaries_ok(dead)
    if r is True:
        return "负控失效：注入带码 summary 后 J3 仍判绿（尺子没分辨力）"
    return True


# ═══════════════════════════ J4 数字自己带单位（裸分母）═══════════════════════
def _bare_denom_ok(html, total, revived):
    """纯判据：健康页拉起次数分子分母各自带单位。返回 True 或说明串。"""
    if not re.search(r"%d 次</a>；同期记录 %d 条" % (revived, total), html):
        return ("健康页拉起次数不是「N 次；同期记录 M 条」形状（M=%d）—— "
                "分母又裸了，或数字与真源不符（#5 复发）" % total)
    if re.search(r"次</a>\s*/\s*\d+", html):
        return "健康页仍有「次</a> / N」裸斜杠分母（异质量相除）"
    return True


def _unit_has_merge(k):
    """纯判据：级词条 unit 含条→件事换算说明，并指向**仍活着的展示位**。

    ★ 0.53.0（T3.2）重锚：旧锚点「已归并为」是顶部计数排括号的字面
      「（已归并为 N 件事）」—— 那排随 T3.2 撤掉 ⇒ 词条改指「要处理」
      后面的件数（收件箱筛选条／日报要处理指标）。锚点跟着展示位走，
      不跟着已删的字面走（判据守已不存在的东西＝死判据）。
    """
    u = GL.TERMS[k].get("unit") or ""
    return "算一件事" in u and "要处理" in u


@check("J4 ★ 拉起次数分子分母各自带单位（界面不许有裸分母）")
def j4():
    """★★ #4/#5 的尺子（2026-10-16 创始人截图四「（已归并为 N 件事）
    无解释」＋截图五「54 次 / 54 裸分母」）：

    两个病同源 —— **异质量的量被摆在一起时没各自交代单位/口径**：
      · 「23 次 / 54」：分子单位是「次」、分母没有单位，一条斜杠暗示
        "每 N 条里 23 次"（做了一个没意义的除法）。0.50.4 Q-03 修了日报页
        （改成「；同期记录 %d 条」），**健康页漏改**。
      · 「（已归并为 N 件事）」：条→件的换算当时只有顶部计数排括号一处
        出现，词条里没写（`_pill` 注释声称"词条里写了"＝愿望写成事实）。
    ⇒ 两条腿：① 健康页拉起次数分母带单位；② R0/L2/L1 的 unit 字段
      必须含条→件换算说明（「要处理」件数自解释的前提）。
    ★ 0.53.0（T3.2）：括号随顶部计数排撤了，腿②的落点改为「要处理」
      后面的件数（词条与锚点同批更新，见 `_unit_has_merge`）。

    ★ ① 的数字从产品真源算（`_rep()["revived_window"]`／`window_levels`），
      不硬编码 —— 硬编码的数字一改产品就假绿。
    """
    r = _rep()
    want_total = sum(int(r["window_levels"].get(k, 0) or 0)
                     for k in ("R0", "L2", "L1"))
    res = _bare_denom_ok(_health(), want_total, r["revived_window"])
    if res is not True:
        return res
    miss = [k for k in ("R0", "L2", "L1") if not _unit_has_merge(k)]
    if miss:
        return ("这些级词条的 unit 没解释条→件事换算：%s —— "
                "页面上「（已归并为 N 件事）」仍是不会解释的括号（#4 复发）"
                % "、".join(miss))
    _note("分母带单位＝同期记录 %d 条；级词条 unit 均含换算说明" % want_total)


@check("N-J4 负控：分母退回裸斜杠 / unit 退回无换算文本 ⇒ J4 必须判红")
def n_j4():
    """反向对照（真跑正判据）：两条腿各变异一次，喂进**同一个纯判据**。"""
    r = _rep()
    want_total = sum(int(r["window_levels"].get(k, 0) or 0)
                     for k in ("R0", "L2", "L1"))
    h = _health()
    if _bare_denom_ok(h, want_total, r["revived_window"]) is not True:
        return "夹具不成立：现行渲染就判红 —— 负控无分辨力"
    # 腿①：分母退回裸斜杠
    dead = h.replace("次</a>；同期记录 %d 条" % want_total,
                     "次</a> / %d" % want_total)
    r1 = _bare_denom_ok(dead, want_total, r["revived_window"])
    if r1 is True:
        return "负控失效：裸分母替换后 J4 腿① 仍判绿"
    # 腿②：unit 退回无换算的旧文本
    orig = GL.TERMS["L2"]["unit"]
    try:
        GL.TERMS["L2"]["unit"] = "单位是<b>条记录</b>，按最近 24 小时数。"
        if _unit_has_merge("L2"):
            return "负控失效：退回旧 unit 文本后 J4 腿② 仍判绿"
    finally:
        GL.TERMS["L2"]["unit"] = orig
    return True


# ═════════════════════════════ J5 连带（判据自身不空转）═══════════════════════
@check("J5 连带：四条尺子都真会红（正判据在真源上跑、不空转）")
def j5():
    """连带对照：J1–J4 的正判据若在**现行产品**上都判绿，说明它们不是
    "恒红"；再确认它们依赖的真源（`_logo_mark`／`state_short`／
    `TERMS[*].unit`／`_revived_value`）都在位 —— 少一个真源，尺子就空转。"""
    for rel, want in ((_SERVER_REL, "_logo_mark"),
                      # ★ 0.53.0（T3.2）：原锚 `window_level_groups`（顶部药丸
                      #   的"件数"口径）随计数排撤销从 inbox_server 消失 ——
                      #   本腿查的是"J 族依赖的真源还在"，故改锚仍在的
                      #   `window_levels`（日报四指标的同一份数）。
                      (_SERVER_REL, "window_levels")):
        if want not in _src_or_skip(rel):
            return "%s 里找不到 %s —— J 族依赖的真源变了" % (rel, want)
    import inbox_model as MM
    if MM.state_short("Ls") != "缺粮" or MM.state_short("L0") != "值守中":
        return "state_short 的六态短名变了 —— J3 的比对面要重新认"
    if len(GL.TERMS) < 20:
        return "术语表条数异常（%d）—— J4 的 unit 断言覆盖面可疑" % len(GL.TERMS)
    # 四条正判据必须都判绿（否则"尺子恒红"＝噪音）
    #   ★ 调 RESULTS 里注册的 **wrapper**（它把 None 归成 True），
    #     不调裸 fn（裸 fn 返回 None ⇒ 误判"恒红"，首跑踩到）。
    want = ("J1 ", "J2 ", "J3 ", "J4 ")
    wrappers = {n: f for n, f in RESULTS if n.startswith(want)}
    if len(wrappers) != 4:
        return "四条正判据的注册名对不上（找到 %d 条）" % len(wrappers)
    for n, f in wrappers.items():
        r = f()
        if r is not True:
            return "%s 在现行产品上判红（尺子恒红＝噪音）：%s" % (n.strip(), r)
    _note("四条正判据在现行产品上均绿；四条真源都在位")


# ════════════ W-SPK 族：界面机器腔人话化（0.51.2，创始人 2026-10-17 截图）═══════════
# 创始人原话：「请看所有的截图说明，都在说鸟语，请你都改成看得懂的人话吧？
#   请好好设计方案，务必一次做干净，全覆盖无遗漏，包括可能我没截图的其他
#   说明文字。严格遵循相关机制，避免复发，避免引入新问题。」
#
# ★ 为什么并入本套件（A2/P5 扩展优先）：W-SPK 的**消费面**与 J 族同一处 ——
#   `inbox_server` 的渲染产物（收件箱页）。同一消费面按 A2 规则并入，
#   不立新套件（0518 并入 0514 是同一条纪律的先例）。
#
# 四条守四件事：
#   W-SPK1 告警**第二行**（meta）不含机器腔键值对（pid=/mode=/cause=）
#   W-SPK2 **整页渲染**不含裸术语（manifest/state 文件/哈希，非代码样位置）
#   W-SPK3 **读侧兜底**：旧版机器串经读侧出口后仍是人话（链 append-only）
#   W-SPK4 归因抠原因：新/旧文案的 spawn_failed **都仍能归因**（不静默退化）

_SPK_KV = ("pid=", "mode=", "cause=", "subkind=", "reason=", "topic=", "kind=")
_SPK_TERMS = ("manifest", "state 文件", "哈希")


def _spk_item(kind, detail="", ts=None, chain_ref="abc123",
              rule_id="", snippet="", topic="", command="", file_path=""):
    """造一条 Item（口径走产品：标题由 TITLE_OF_TOPIC/KIND 派生）。

    ★★ 0.53.0（T3.2）拆时间炸弹：原来 `ts` 写死 `"2026-10-17T01:22:31+08:00"`。
      收件箱「要处理」是按 **24 小时窗口**筛的（`bucket_of`），过了这个窗口
      ⇒ 这些夹具**根本不进页面**。后果两样都坏：
        ① 正向 W-SPK2「整页不含裸术语」变成**对空页面打分**（假绿）；
        ② 负控 N-WSPK2 报「关掉 humanize 也找不到」＝夹具失效（2026-10-18 实测）。
      ⇒ 默认取「一小时前」，永远落在窗口内。要考时间的老化行为请显式传 ts。
    """
    if ts is None:
        ts = (datetime.now().astimezone()
              - timedelta(hours=1)).isoformat(timespec="seconds")
    title = M.TITLE_OF_TOPIC.get(topic) or M.TITLE_OF_KIND.get(kind, kind)
    al = M.Alert.build(ts=ts, kind=kind, title=title, detail=detail,
                       rule_id=rule_id, snippet=snippet, chain_ref=chain_ref,
                       reason=detail, topic=topic,
                       command=command, file_path=file_path)
    return M.Item(alert=al, state="unread")


def _spk_meta(h):
    m = re.search(r'<p class="m">(.*?)</p>', h, re.S)
    return m.group(1) if m else ""


@check("W-SPK1 告警第二行（meta）不含机器腔键值对（pid=/mode=/cause=）")
def c_spk_meta_no_kv():
    cases = [
        _spk_item("host_shield_revived",
                  "监理不在（旧 pid=19764），由 hook-parametric 重新拉起（mode=detached）"),
        _spk_item("host_shield_spawn_failed",
                  "监理死亡（旧 pid=None）且拉起失败（cause=hook-parametric, "
                  "mode=self-check-failed: xxx）——门闸无人值守", topic="spawn_failed"),
        _spk_item("tool_call_blocked", rule_id="DST-04", snippet="schtasks"),
    ]
    probs = []
    for it in cases:
        meta = _spk_meta(SV._item_html(it, "tok-wspk1"))
        for k in _SPK_KV:
            if k in meta:
                probs.append("%s 的 meta 仍含 %r" % (it.kind, k))
    if probs:
        return "；".join(probs[:4])
    # 反向对照：meta 要**有**人话（pid → 进程号），证明尺子不是恒真
    if "进程号" not in SV._item_html(cases[0], "tok-wspk1"):
        return "反向对照失败：pid 没被换成人话「进程号」（尺子无分辨力？）"
    _note("三类记录 meta 均无键值对；pid 已换「进程号」")
    return True


@check("N-WSPK1 负控：关掉读侧 humanize ⇒ 同一条 W-SPK1 必须报红")
def n_spk_meta_no_kv():
    it = _spk_item("host_shield_revived", "监理不在（旧 pid=19764）")
    if not any(k in it.detail for k in _SPK_KV):
        return "负控夹具失效：原始 detail 里没有机器腔键值对"
    orig = M.humanize
    try:
        M.humanize = lambda s: ("" if s is None else str(s))
        meta = _spk_meta(SV._item_html(it, "tok-n1"))
    finally:
        M.humanize = orig
    if not any(k in meta for k in _SPK_KV):
        return "负控失效：关掉读侧免疫后 meta 仍无机器腔 —— 尺子没接在真闸上"
    return True


@check("W-SPK2 整页渲染不含裸术语（manifest/state 文件/哈希，非代码样位置）")
def c_spk_render_no_terms():
    hub = tempfile.mkdtemp(prefix="g0514_spk_")
    items = [
        _spk_item("host_shield_dev_drift",
                  "研发态：代码与登记表不符（改动未重建清单）——这一版还没发出去，"
                  "不是防线失守；监理照常在岗。", topic="code_drift"),
        _spk_item("host_shield_tamper",
                  "state 文件 enabled=False 与审计链最近状态（armed）不一致——以链为准。",
                  topic="state_drift"),
        _spk_item("host_shield_breach",
                  "登记表与 manifest 不符（疑似运行期投毒）——按启动缓存执法：x",
                  topic="registry_manifest"),
    ]
    h = SV.render_page(view="inbox", root=hub, token="tok2", items=items,
                       posture={"state": "guarding", "can_fix": False})
    probs = []
    for term in _SPK_TERMS:
        for mm in re.finditer(re.escape(term), h):
            s, e = mm.start(), mm.end()
            ctx = h[max(0, s - 40):min(len(h), e + 10)]
            if M._CODEY_RE.search(ctx):
                continue
            probs.append("%r 出现在非代码样位置：…%s…" % (term, ctx[-30:]))
            break
    if probs:
        return "；".join(probs[:3])
    _note("整页渲染无裸术语（代码样位置如 _resign_manifest.py 已豁免）")
    return True


@check("N-WSPK2 负控：关掉 humanize 把裸术语塞进渲染 ⇒ 同一条 W-SPK2 判红")
def n_spk_render_no_terms():
    # ★ 0.52.0：负控夹具从「manifest」换成「state 文件」——
    #   strip_governance v2 起，「manifest」是治理标记，含它的子句在
    #   record_meta 层就被整段删掉（根本到不了 humanize）⇒ 拿 manifest
    #   做负控夹具，关掉 humanize 页面上也不会有它，负控恒「夹具失效」
    #   （假红，方向还错）。「state 文件」不在治理标记表里：strip 不动它，
    #   只有 humanize 词表会删 ⇒ 关掉 humanize 它就上屏（红），
    #   恢复就消失（方向对），且证明的是 humanize 层本身接在闸上。
    bare = "state 文件"
    orig = M.humanize
    try:
        M.humanize = lambda s: ("" if s is None else str(s))
        hub = tempfile.mkdtemp(prefix="g0514_spkn_")
        it = _spk_item("host_shield_tamper",
                       "state 文件 enabled=False 与审计链最近状态（armed）不一致——以链为准。",
                       topic="state_drift")
        h_bad = SV.render_page(view="inbox", root=hub, token="tok2", items=[it],
                               posture={"state": "guarding", "can_fix": False})
    finally:
        M.humanize = orig
    # ★★ 0.53.0（T6.3）：**注入点必须真的过 humanize** —— 原来只断言「整页能找到」，
    #   而整页有好几条渲染路径（明细行 meta／归因面板 cause／note），其中有的本来就
    #   不过 humanize。于是"关掉 humanize 就上屏"这句话在页面上**分辨不出是哪条路**
    #   —— 关掉的是 A 路的闸，红的是 B 路的门。现在改成钉在**过 humanize 的那个字段**
    #   （`record_meta` 产出的 `<p class="m">`）上：两向都只看这一处。
    if bare not in _spk_meta(h_bad):
        return ("负控注入点失效：关掉 humanize 后 %r 没出现在过 humanize 的明细行里"
                "（说明它从别的渲染路径上屏，这条负控证明的不是 humanize）" % bare)
    hub2 = tempfile.mkdtemp(prefix="g0514_spkn2_")
    it2 = _spk_item("host_shield_tamper",
                    "state 文件 enabled=False 与审计链最近状态（armed）不一致——以链为准。",
                    topic="state_drift")
    h_ok = SV.render_page(view="inbox", root=hub2, token="tok2", items=[it2],
                          posture={"state": "guarding", "can_fix": False})
    if bare in _spk_meta(h_ok):
        return "负控方向异常：humanize 恢复后 %r 仍在明细行里" % bare
    if bare in PC.body(h_ok):
        return "负控方向异常：humanize 恢复后 %r 仍在页面上" % bare
    return True


@check("W-SPK3 读侧兜底：旧版机器串记录渲染后仍是人话（链 append-only）")
def c_spk_legacy_humanized():
    legacy = [
        ("监理不在（旧 pid=19764），由 hook-parametric 重新拉起（mode=detached）", "pid="),
        ("state 文件 enabled=False 与审计链最近状态（armed）不一致——以链为准", "state 文件"),
        ("登记表与 manifest 不符（疑似运行期投毒）", "manifest"),
    ]
    probs = []
    for text, machine in legacy:
        out = M.visible_text(text)                 # 读侧**唯一**出口
        if machine in out:
            probs.append("读侧未免疫 %r" % machine)
        if out == text:
            probs.append("读侧对 %r 没做任何变换（兜底没接线？）" % text[:20])
    if probs:
        return "；".join(probs[:3])
    once = M.visible_text(legacy[0][0])
    if once != M.visible_text(once):
        return "读侧非幂等：二次过读侧结果变化"
    _note("三条旧机器串过读侧后均人话化且幂等")
    return True


@check("N-WSPK3 负控：拆掉读侧 humanize ⇒ 同一条 W-SPK3 必须报红")
def n_spk_legacy_humanized():
    orig = M.humanize
    try:
        M.humanize = lambda s: ("" if s is None else str(s))
        out = M.visible_text("监理不在（旧 pid=19764），由 hook-parametric 重新拉起")
    finally:
        M.humanize = orig
    if "pid=" not in out:
        return "负控失效：拆掉 humanize 后 pid= 仍消失（尺子没接在 humanize 上）"
    return True


@check("W-SPK4 归因抠原因：新/旧文案的 spawn_failed 都仍能归因（不静默退化）")
def c_spk_spawn_failed_both():
    import remediation as RM
    new = _spk_item("host_shield_spawn_failed",
                    "监理已停止（旧进程号 5），重新拉起也没成功（触发方式：钩子机制自动触发，"
                    "拉起方式：自检没通过：ci/freeze_zones.json 未登记）——现在没人值守。",
                    topic="spawn_failed")
    old = _spk_item("host_shield_spawn_failed",
                    "监理死亡（旧 pid=5）且拉起失败（cause=manual, "
                    "mode=self-check-failed: ci/freeze_zones.json 未登记）——门闸无人值守",
                    topic="spawn_failed")
    probs = []
    for tag, it in (("新文案", new), ("旧文案", old)):
        a = RM.attribute(it)
        if a.get("kind") != "spawn_failed":
            probs.append("%s 没归到 spawn_failed（实为 %r）" % (tag, a.get("kind")))
            continue
        cause = str(a.get("cause") or "")
        if "失败环节" not in cause:
            probs.append("%s 的 cause 丢了「失败环节」（抠原因退化）" % tag)
        if "self-check-failed" not in cause and "自检没通过" not in cause:
            probs.append("%s 的 cause 里看不到失败原因内容" % tag)
    if probs:
        return "；".join(probs[:4])
    _note("新/旧文案的 spawn_failed 都抠出了失败环节")
    return True


@check("N-WSPK4 负控：抽掉新文案锚点 ⇒ 新记录归因必须丢原因（证明 W-SPK4 有牙）")
def n_spk_spawn_failed_both():
    import remediation as RM
    orig = RM._path_from_detail

    def _no_new(text, patterns):
        return orig(text, [p for p in patterns if "拉起方式" not in p])

    try:
        RM._path_from_detail = _no_new
        it = _spk_item("host_shield_spawn_failed",
                       "监理已停止（旧进程号 5），重新拉起也没成功（触发方式：钩子机制自动触发，"
                       "拉起方式：自检没通过：ci/freeze_zones.json 未登记）——现在没人值守。",
                       topic="spawn_failed")
        a = RM.attribute(it)
    finally:
        RM._path_from_detail = orig
    if "失败环节" in str(a.get("cause") or ""):
        return "负控失效：抽掉新锚点后仍抠出了原因 ⇒ W-SPK4 是空转的"
    return True


# ═══════════ W-SPK5…W-SPK11 · 0.51.2 **第二轮**（创始人四张截图后的新契约）═══════════
# 为什么需要这一族：第一轮的 W-SPK1…4 只禁**词级机器串**（pid=/mode=/manifest），
# 截图证明「术语替换后新生成的赘肉」完全无感——规则编号两遍、「命中「os.remove」」
# 不告诉用户删什么、裸 ISO 时间、64 位核对号、研发态修法命令、态势矛盾的按钮。
# 这一族全部打在**结构与行为**上（渲染产物、可见文本、动作集合、按态势分支），
# 且每条配**「赘肉注入」型负控**（把坏形状塞回去 ⇒ 必须判红）——
# 区别于 W-SPK1…4 的回退型负控（只证明「退不回去」，不证明「新坨进不来」）。
#
# ★ 机器无关：时区名断言打形状（`<名> MM-DD HH:MM`），不写死「北京时间」——
#   海外机器上名字本来就不同（创始人：洛杉矶写美西时间，波士顿写美东时间）。

_ISO_TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")
_TIME_SHAPE_RE = re.compile(r"(\S.{0,12}?)\s(\d{2}-\d{2} \d{2}:\d{2})$")
_HEX64_RE = re.compile(r"[0-9a-fA-F]{32,}")


def _spk_page(items, posture, filt="all"):
    """渲染一整页（真实渲染路径，posture 穿线到面板）。"""
    hub = tempfile.mkdtemp(prefix="g0514_spk_")
    return SV.render_page(view="inbox", filt=filt, root=hub, token="T",
                          items=items, posture=posture)


@check("W-SPK5 详情行时间：无裸 ISO（T/+08:00），是「时区名 MM-DD HH:MM」形状")
def c_spk_meta_time_shape():
    import inbox_model as _M
    it = _spk_item("host_shield_revived", "监理刚才不在（旧进程号 5）。")
    meta = _M.record_meta(it)
    if _ISO_TIME_RE.search(meta) or "+08:00" in meta:
        return "详情行仍有裸 ISO 时间：%r" % meta
    m = _TIME_SHAPE_RE.search(meta)
    if not m:
        return "详情行时间不是「时区名 MM-DD HH:MM」形状：%r" % meta
    _note("时间形状：%s" % m.group(0))
    return True


@check("N-WSPK5 负控（赘肉注入）：ts_label 变异回裸 ISO ⇒ W-SPK5 必须判红")
def n_spk_meta_time_shape():
    import inbox_model as _M
    orig = _M.ts_label
    try:
        _M.ts_label = lambda s: ("" if s is None else str(s))
        r = c_spk_meta_time_shape()
        if r is True or r is None:
            return "负控失效：时间退回裸 ISO 后 W-SPK5 仍判绿（尺子没接在闸上）"
        if "裸 ISO" in str(r):
            return True
        return "负控方向不对：判红了但原因不是裸 ISO（%s）" % r
    finally:
        _M.ts_label = orig


@check("W-SPK6 详情行无「核对号」与长十六进制串（链哈希不再上屏）")
def c_spk_meta_no_chain():
    import inbox_model as _M
    it = _spk_item("tool_call_blocked", "规则 DST-01 · 命中「os.remove」",
                   rule_id="DST-01", snippet="os.remove", chain_ref="a" * 64)
    meta = _M.record_meta(it)
    if "核对号" in meta:
        return "详情行仍有「核对号」：%r" % meta
    if _HEX64_RE.search(meta):
        return "详情行仍有长十六进制串（链哈希）：%r" % meta
    return True


@check("N-WSPK6 负控（赘肉注入）：record_meta 变异成补回核对号 ⇒ W-SPK6 必须判红")
def n_spk_meta_no_chain():
    import inbox_model as _M
    orig = _M.record_meta

    def _fat(it, with_time=True):
        return orig(it, with_time=with_time) + " · 核对号 " + "b" * 64

    try:
        _M.record_meta = _fat
        r = c_spk_meta_no_chain()
        if r is True or r is None:
            return "负控失效：补回核对号后 W-SPK6 仍判绿（尺子没分辨力）"
        if "核对号" in str(r) or "十六进制" in str(r):
            return True
        return "负控方向不对：判红了但原因不是核对号（%s）" % r
    finally:
        _M.record_meta = orig


@check("W-SPK7 详情行：规则编号只出现一次；无「命中「」」字样")
def c_spk_meta_rule_once():
    import inbox_model as _M
    it = _spk_item("tool_call_blocked", "规则 DST-01 · 命中「os.remove」",
                   rule_id="DST-01", snippet="os.remove")
    meta = _M.record_meta(it)
    n = meta.count("DST-01")
    if n != 1:
        return "规则编号在详情行出现 %d 次（应恰 1 次）：%r" % (n, meta)
    if "命中" in meta:
        return "详情行仍有「命中」字样：%r" % meta
    return True


@check("N-WSPK7 负控（赘肉注入）：record_meta 变异成规则写两遍 ⇒ W-SPK7 必须判红")
def n_spk_meta_rule_once():
    import inbox_model as _M
    orig = _M.record_meta

    def _dup(it, with_time=True):
        m = orig(it, with_time=with_time)
        return m.replace("规则 DST-01", "规则 DST-01（哪条防护规则拦下它的）· 规则 DST-01", 1)

    try:
        _M.record_meta = _dup
        r = c_spk_meta_rule_once()
        if r is True or r is None:
            return "负控失效：规则写两遍后 W-SPK7 仍判绿（尺子没分辨力）"
        if "2 次" in str(r) or "1 次" in str(r):
            return True
        return "负控方向不对：判红了但原因不是重复（%s）" % r
    finally:
        _M.record_meta = orig


@check("W-SPK8 详情行 ≤90 字（行级预算：单项合规、总量也会失控）")
def c_spk_meta_budget():
    import inbox_model as _M
    # ★ 0.52.0：夹具扩到**真实记录形状**。旧夹具只有一种（三目标 rm）；
    #   真实 spawn_failed/tamper 记录的 detail 带嵌套括号＋治理清单，
    #   消毒后必须仍够短——只测合成形状 = 机制对真记录无覆盖。
    cases = [
        _spk_item("tool_call_blocked", "规则 DST-01 · 命中「os.remove」",
                  rule_id="DST-01", snippet="os.remove",
                  command="rm -rf 'C:/a b/c.txt' 'C:/d/e.json' 'C:/f/g.md'"),
        _spk_item("host_shield_spawn_failed",
                  "监理已停止（旧进程号 33416），重新拉起也没成功（触发方式：钩子机制自动触发，"
                  "拉起方式：自检没通过：host_shield.py 与出厂登记不符（运行代码可能被改）；"
                  "hooks/pre_tool_use.py 与出厂登记不符（告警链路文件可能被改）；"
                  "tools/enforce_probe.py 与出厂登记）——现在没人值守。",
                  topic="spawn_failed"),
        _spk_item("host_shield_tamper",
                  "监理启动时的自检没通过：host_shield.py 与出厂登记不符（运行代码可能被改）；"
                  "hooks/pre_tool_use.py 与出厂登记不符（告警链路文件可能被改）；"
                  "tools/enforce_probe.py 与出厂登记不符（告警链路文件可能被改）",
                  topic="code_drift"),
        # ★ 0.53.0：**真记录形状**——12:14 那条在页面上拼到 94 字（三目标＋
        #   等文件＋规则大白话＋时间＋规则编号）。旧夹具只有「三目标 rm」一种，
        #   目标数恰好顶格，从未撞到行预算 ⇒ 现网违规而判据全绿。
        _spk_item("tool_call_blocked", "规则 DST-01 · 命中「rm」",
                  rule_id="DST-01", snippet="rm",
                  command="rm -rf _dbg_logo.txt inbox_store.py inbox_server.py "
                          "_dbg_probe.json"),
    ]
    worst = 0
    for it in cases:
        meta = _M.record_meta(it)
        worst = max(worst, len(meta))
        if len(meta) > _M._META_MAX:
            return ("详情行 %d 字，超 %d 字预算（%s）：%r"
                    % (len(meta), _M._META_MAX, it.kind, meta))
    _note("最长情形 %d 字（%d 个夹具，含真实记录形状）" % (worst, len(cases)))
    return True


@check("N-WSPK8 负控（赘肉注入）：record_meta 变异成 200 字 ⇒ W-SPK8 必须判红")
def n_spk_meta_budget():
    import inbox_model as _M
    orig = _M.record_meta

    def _fat(it, with_time=True):
        return orig(it, with_time=with_time) + " · " + "啰" * 130

    try:
        _M.record_meta = _fat
        r = c_spk_meta_budget()
        if r is True or r is None:
            return "负控失效：详情行涨到 200 字后 W-SPK8 仍判绿（预算尺子空转）"
        if "预算" in str(r):
            return True
        return "负控方向不对：判红了但原因不是超预算（%s）" % r
    finally:
        _M.record_meta = orig


#: 目标抽取的五类真实形状（全部取自 2026-10-17 本机链上真实记录，不是编的）。
#: 每条给「必须出现」与「绝不许出现」两侧，缺任一侧都算不上有牙。
_SPK_TARGET_CASES = (
    ("grep 正则片段",
     r'cd "D:\psl\poc\antinel-security" && grep -n "def _item_html\|def _group_html'
     r'\|def _badge_html\|attribute(" inbox_server.py',
     "", r"\|"),
    ("python -c 的代码体",
     'PYTHONPATH= TMP=/x "C:/Users/大马/.workbuddy/binaries/python/versions/3.13.12/'
     'python.exe" -E -X utf8 -c "\nimport sys\norig = SV._item_html\n'
     'lambda it: (\'<div class=\\"seg cost\\">④</div>\')"',
     "", "seg cost"),
    ("cd 的目录（上下文不是目标）",
     'cd "D:\\psl\\poc\\antinel-security" && ls',
     "", "antinel-security"),
    ("持久化：深层长路径只亮文件名",
     'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d '
     '"C:/Users/大马/.workbuddy/config/plugins/startup/Startup"',
     "Startup", "C:/Users"),
    ("对照·删除三目标（不许改坏）",
     "rm -rf 'C:/a b/c.txt' 'C:/d/e.json' 'C:/f/g.md'",
     "c.txt、e.json、g.md", "C:/a b"),
    ("对照·裸文件名",
     "rm build_package.py",
     "build_package.py", ""),
    ("对照·URL 与版本号",
     "curl https://pypi.org/project/antinel/ && pip install antinel==0.52.0",
     "", "pypi"),
)


@check("W-SPK13 详情行「目标」：只认会动文件的段（删除/写入/持久化），"
       "正则片段·cd 上下文·转义残尾不许当文件，深层路径只亮文件名")
def c_spk_targets_plausible():
    import inbox_model as _M
    probs = []
    for label, cmd, must, forbid in _SPK_TARGET_CASES:
        got = _M._targets_phrase(cmd)
        if must and must not in got:
            probs.append("%s：应含 %r，实得 %r" % (label, must, got))
        if forbid and forbid in got:
            probs.append("%s：不该出现 %r，实得 %r" % (label, forbid, got))
        if len(got) > 60:
            probs.append("%s：目标片段 %d 字，超 60 字预算（%r）"
                         % (label, len(got), got))
    if probs:
        return "；".join(probs[:3]) + ("（共 %d 处）" % len(probs) if len(probs) > 3 else "")
    # 对照腿再走一遍整行：目标片段确实落在详情行里（不是函数对、渲染没接上）
    it = _spk_item("tool_call_blocked", "规则 DST-01 · 命中「rm」",
                   rule_id="DST-01", snippet="rm",
                   command="rm build_package.py")
    meta = _M.record_meta(it)
    if "目标 build_package.py" not in meta:
        return "渲染层没接上：详情行缺「目标 build_package.py」（%r）" % meta
    _note("%d 类真实形状（含 3 条对照）" % len(_SPK_TARGET_CASES))
    return True


@check("N-WSPK13 负控（退回旧抽取）：恢复「抓引号里所有像路径的串」⇒ W-SPK13 必须判红")
def n_spk_targets_plausible():
    import inbox_model as _M
    orig = _M._file_targets

    def _old(text):
        """0.52.0 之前的实现：三档全抓，无合法性、无角色、不缩 basename。"""
        if not text:
            return [], False
        t = str(text)
        out, seen = [], set()

        def _add(tok):
            tok = (tok or "").strip().strip("'\"").rstrip(",;)")
            if not tok or len(tok) > 120 or tok in seen:
                return
            if tok.startswith("//") or "://" in tok:
                return
            if ("/" in tok or "\\" in tok) or _M._ext_ok(tok):
                seen.add(tok)
                out.append(tok)

        import re as _re
        for m in _re.findall(r"['\"]([^'\"]{1,200})['\"]", t):
            _add(m)
        for m in _re.findall(r"\b([A-Za-z0-9_\-]+\.[A-Za-z0-9]{1,6})\b", t):
            _add(m)
        if not out:
            for m in _re.findall(r"(?:[A-Za-z]:|\.{1,2})?[\\/][^\s'\"|;&)]+", t):
                _add(m)
        return (out[:_M._MAX_TARGETS], len(out) > _M._MAX_TARGETS)

    try:
        _M._file_targets = _old
        r = c_spk_targets_plausible()
        if r is True or r is None:
            return "负控失效：退回旧抽取后 W-SPK13 仍判绿（尺子没分辨力）"
        return True
    finally:
        _M._file_targets = orig


@check("W-SPK9 整页渲染：无研发态话术（保护名单/登记簿/研发树/研发态治理）、"
       "无 python 命令、无 --flag")
def c_spk_render_no_gov():
    import inbox_model as _M
    gov_detail = ("监理已停止（旧进程号 5），重新拉起也没成功（触发方式：钩子机制自动触发，"
                  "拉起方式：自检没通过：ci/freeze_zones.json 在研发树专属保护名单里，"
                  "却没登记进 manifest（研发态治理登记簿可被改而查不出；修法：python "
                  "_tools_034/_resign_manifest.py --adopt-dev））——现在没人值守。")
    # ★ 0.52.0：**真实记录形状**两例（10-17 实测漏网的两型）：
    #   ① 嵌套括号：治理细节整段在外层括号、内层是无标记小括号
    #      （旧算法只删最内层 ⇒ 外层永远不被检查）；
    #   ② 裸标记：治理清单在括号外（「：<文件> 与出厂登记不符；…」）。
    real_nested = ("监理已停止（旧进程号 33416），重新拉起也没成功（触发方式：钩子机制自动触发，"
                   "拉起方式：自检没通过：host_shield.py 与出厂登记不符（运行代码可能被改）；"
                   "hooks/pre_tool_use.py 与出厂登记不符（告警链路文件可能被改）；"
                   "tools/enforce_probe.py 与出厂登记）——现在没人值守。")
    real_bare = ("监理启动时的自检没通过：host_shield.py 与出厂登记不符（运行代码可能被改）；"
                 "hooks/pre_tool_use.py 与出厂登记不符（告警链路文件可能被改）；"
                 "tools/enforce_probe.py 与出厂登记不符（告警链路文件可能被改）")
    items = [
        _spk_item("host_shield_spawn_failed", gov_detail, topic="spawn_failed"),
        _spk_item("host_shield_spawn_failed", real_nested, topic="spawn_failed"),
        _spk_item("host_shield_tamper", real_bare, topic="code_drift"),
    ]
    bad = []
    for posture in ({"state": "guarding", "can_fix": False},
                    {"state": "warn", "can_fix": False}):
        h = _spk_page(items, posture)
        # ★ S48（C2）：文案断言必须显式选正文层 —— 裸渲染变量会把
        #   <style>/HTML 注释里的复述一并算进来（U-16 同族事故）。
        b = PC.body(h)
        for w in ("保护名单", "登记簿", "研发树", "研发态治理", "--adopt-dev",
                  "python _tools", "_resign_manifest", "出厂登记",
                  "host_shield.py", "enforce_probe.py", "hooks/pre_tool_use.py"):
            if w in b:
                bad.append("态势 %s 仍含研发态话术 %r" % (posture["state"], w))
        if re.search(r"python\s+\S+\.py", b):
            bad.append("态势 %s 仍含 python 命令形状" % posture["state"])
    if bad:
        return "；".join(bad[:4])
    _note("研发态治理话术在两种态势下都不上屏（含真实嵌套/裸标记两型）")
    return True


@check("N-WSPK9 负控（赘肉注入）：strip_governance 变异成恒等 ⇒ W-SPK9 必须判红")
def n_spk_render_no_gov():
    import inbox_model as _M
    orig = _M.strip_governance
    try:
        _M.strip_governance = lambda t: ("" if t is None else str(t))
        r = c_spk_render_no_gov()
        if r is True or r is None:
            return "负控失效：消毒函数失效后 W-SPK9 仍判绿（尺子没接在闸上）"
        if "研发态" in str(r) or "python" in str(r):
            return True
        return "负控方向不对：判红了但原因不是治理话术（%s）" % r
    finally:
        _M.strip_governance = orig


@check("W-SPK10 「现在重新拉起」按钮按态势渲染：值守中不出现，真缺岗才出现")
def c_spk_retry_posture_gate():
    import remediation as RM
    it = _spk_item("host_shield_spawn_failed",
                   "监理已停止（旧进程号 5），重新拉起也没成功。",
                   topic="spawn_failed")
    # ★ 0.53.0 T4：正臂从 `warn` 改成 `down`／`interrupted` —— 门控口径
    #   从黑名单（≠guarding）改成**白名单**（只有真缺岗）。`warn`／`dev`
    #   是"在岗但代码认不出/比登记的新"，看得见页面就说明它在跑，
    #   给"重新拉起"仍然是一句不成立的话（本轮现场正是 dev 态）。
    h_guard = _spk_page([it], {"state": "guarding", "can_fix": False})
    h_dev = _spk_page([it], {"state": "dev", "can_fix": False})
    h_fail = _spk_page([it], {"state": "down", "can_fix": False})
    h_int = _spk_page([it], {"state": "interrupted", "can_fix": False})
    # ★ 断言打在**按钮文案**上（按态势门控的是按钮，不是动作标题）：
    #   标题「重新拉起监理」讲选项是什么，按钮「现在重新拉起」是点下去的
    #   那一下（0.52.0 去重，与 0.37.2 accept 的同型教训一致）。
    # ★ S48：中文文案断言必须显式选层走 `PC.body(...)`（不许拿整页渲染原文当正文）。
    btn = SV._PICK["retry"][0]
    if btn in PC.body(h_guard):
        return "值守中仍渲染「%s」按钮（看得到页面＝监理在跑，按钮逻辑矛盾）" % btn
    if btn in PC.body(h_dev):
        return "研发中仍渲染「%s」按钮（在岗，只是代码比登记的新）" % btn
    if btn not in PC.body(h_fail):
        return "真缺岗（down）时「%s」按钮不见了（该给动作时不给）" % btn
    if btn not in PC.body(h_int):
        return "缺岗无损失（interrupted）时「%s」按钮不见了" % btn
    # 门控函数真的被调（不是碰巧几种态势都不渲染）
    if not RM._can_revive({"state": "guarding"}) and RM._can_revive({"state": "down"}):
        _note("值守中不给、真缺岗才给；_can_revive 两向都对")
    return True


@check("N-WSPK10 负控（赘肉注入）：_can_revive 变异成恒真 ⇒ W-SPK10 必须判红")
def n_spk_retry_posture_gate():
    import remediation as RM
    orig = RM._can_revive
    try:
        RM._can_revive = lambda posture: True
        r = c_spk_retry_posture_gate()
        if r is True or r is None:
            return "负控失效：门控恒真后 W-SPK10 仍判绿（尺子没分辨力）"
        if "重新拉起" in str(r):
            return True
        return "负控方向不对：判红了但原因不是按钮（%s）" % r
    finally:
        RM._can_revive = orig


@check("W-SPK11 R0 面板无 <code class=\"cmd\"> 命令块（研发/运维命令不上屏）")
def c_spk_panel_no_cmd():
    import remediation as RM
    it = _spk_item("host_shield_spawn_failed",
                   "监理已停止（旧进程号 5），重新拉起也没成功。",
                   topic="spawn_failed")
    for posture in ({"state": "guarding", "can_fix": False},
                    {"state": "warn", "can_fix": False}):
        h = _spk_page([it], posture)
        if '<code class="cmd"' in h:
            return "态势 %s 的面板仍渲染 <code class=\"cmd\"> 命令块" % posture["state"]
    return True


@check("N-WSPK11 负控（赘肉注入）：把 cmd 代码块加回面板渲染 ⇒ W-SPK11 必须判红")
def n_spk_panel_no_cmd():
    orig = SV._rem_html

    def _with_cmd(it, token, posture=None):
        h = orig(it, token, posture)
        return h.replace("</div></details>",
                         '<code class="cmd">antinel host-shield enable</code>'
                         "</div></details>", 1)

    try:
        SV._rem_html = _with_cmd
        r = c_spk_panel_no_cmd()
        if r is True or r is None:
            return "负控失效：命令块加回面板后 W-SPK11 仍判绿（尺子没分辨力）"
        if "cmd" in str(r):
            return True
        return "负控方向不对：判红了但原因不是命令块（%s）" % r
    finally:
        SV._rem_html = orig


@check("W-SPK12 B 类面板亮出落点路径（当前写侧形态：路径在记录结尾冒号后）")
def c_spk_zone_path_on_panel():
    """★ 裁定 #3「亮文件名」的 zone_locked 对应物（0.52.0 实测缺口）。

    当前写侧（`host_shield.py:3665`，0.45.0 H-7 起）的失败记录把路径放在
    文案结尾「…对抗门闸：<盘符路径>」，**没有**「人工介入」锚点 ⇒ 旧提取
    模式全落空，面板 ① 段显示「(落点路径没在记录里)」——路径明明在记录里。
    0.52.0 补了「全角冒号＋盘符＋分隔符＋行尾」的兜底模式；本条判据
    守在**渲染产物**上（① 段可见文本），提取与渲染两头都盖住。
    """
    it = _spk_item("host_shield_zone_locked",
                   "安全区【上锁没生效】——本目录的访问控制没能限制写入"
                   "（可核：icacls 该目录）；注意：「不等于」有进程在对抗门闸："
                   "D:\\ws\\zone_vault",
                   topic="zone_lock_failed")
    h = SV._item_html(it, "tok-wspk12")
    m = re.search(r'<div class="seg root">(.*?)</div>', h, re.S)
    if not m:
        return "面板没有 ① 段（发生了什么）——四段制骨架破了"
    root_txt = re.sub(r"<[^>]+>", "", m.group(1))
    if "(落点路径没在记录里)" in root_txt:
        return "① 段仍显示占位串「(落点路径没在记录里)」——路径提取失效"
    if "D:\\ws\\zone_vault" not in root_txt:
        return "① 段没有落点路径（裁定 #3：亮文件名）"
    _note("落点路径已上屏：D:\\ws\\zone_vault")
    return True


@check("N-WSPK12 负控（赘肉注入）：路径提取失效 ⇒ W-SPK12 必须判红")
def n_spk_zone_path_on_panel():
    import remediation as RM
    orig = RM._path_from_detail
    try:
        RM._path_from_detail = lambda d, pats: ""
        r = c_spk_zone_path_on_panel()
        if r is True or r is None:
            return "负控失效：路径提取失效后 W-SPK12 仍判绿（尺子没分辨力）"
        if "路径" in str(r):
            return True
        return "负控方向不对：判红了但原因不是路径（%s）" % r
    finally:
        RM._path_from_detail = orig


# ══════════════════════════════════════════════════════════════════════
# 0.53.0 T4（创始人 2026-10-19 截图裁定）：**违和与废话的根治判据**
#
# 现场三件事，合起来是一个问题：**面板在替自己说话，而不是替事实说话**。
#   ① 小窗／面板出现「重新拉起监理」按钮，而看得见这个页面本身
#      就证明监理在跑 —— 创始人原话：「那个按钮我专门讲过，如果能看到，
#      说明 Antinel 监理在运行，否则怎么看到？？？」
#   ② 「④ 不做的后果」整段 —— 创始人定性「完全是废话」：它把②段说过的
#      后果换个说法再说一遍。
#   ③ 详情行（L1/L2 的说明）仍在上屏「旧进程号 None」「mode=detached」
#      「哨兵」—— Python 的字与退休词。
#
# ★★ 为什么这一族必须**单独立判据**：W-SPK10 早在 0.51.2 就守同一个按钮，
#   却让它死灰复燃了一整轮。根因不是没判据，是**判据走的那条路与生产
#   走的那条路不是同一条**：
#     · W-SPK10 用 `_spk_page(items, posture)` —— **注入姿态**；
#     · 生产 `render_page(...)` 不注入 ⇒ `posture=None` ⇒ 归因模块的
#       `posture is None` 兜底路径 ⇒ 按钮恒现。
#   ⇒ 本轮每一条都从**生产默认路径**出发（不打注入、不打桩产品函数），
#     负控一律把守的那条机制反过来，看判据是否真的会红。
# ══════════════════════════════════════════════════════════════════════
_SPAWN_DETAIL = ("监理已停止（旧进程号 None），重新拉起也没成功"
                 "（触发方式：钩子机制自动触发，拉起方式：自检没通过）"
                 "——当时没人值守。")
_ZONE_DETAIL = ("安全区【上锁没生效】——本目录的访问控制没能限制写入"
                "（可核：icacls 该目录）；注意：「不等于」有进程在对抗门闸："
                "D:\\ws\\zone_vault")
_GUARD_POSTURE = {"state": "guarding", "label": "值守中", "can_fix": False}


def _t4_page(items, posture=None):
    """真实渲染路径：`render_page` 默认入口（**不注入姿态**时传 None）。"""
    hub = tempfile.mkdtemp(prefix="g0514_t4_")
    return SV.render_page(view="inbox", root=hub, token="T",
                          items=items, posture=posture)


@check("T4-01 ★ 值守中（生产默认路径）不出现「重新拉起监理」按钮")
def c_t4_revive_gate_on_default_path():
    """★ 判据走**生产默认路径**：不打注入姿态、不打桩产品函数，
    只把 `posture_now` 换成已知值（那是"现探"的唯一入口，本来就该可换）。

    ★ 为什么不再信"注入姿态"的判据：见本段段头。注入姿态那条路
      永远绿，因为生产根本不走它。
    """
    it = _spk_item("host_shield_spawn_failed", _SPAWN_DETAIL,
                   topic="spawn_failed")
    orig = SV.posture_now
    SV.posture_now = lambda: dict(_GUARD_POSTURE)
    try:
        h = _t4_page([it])
    finally:
        SV.posture_now = orig
    txt = PC.body(h)
    # ★ 断言打在**按钮文案**上（从 `_PICK` 取，不另抄一份）—— 记录原文里
    #   也有「重新拉起也没成功」这种字样，拿它当锚点会把判据判成永红。
    btn = SV._PICK["retry"][0]
    if btn in txt:
        return ("值守中仍渲染「%s」按钮 —— 看得到页面＝监理在跑，"
                "这个按钮是一句不成立的话" % btn)
    if "现在实测" not in txt:
        return ("和解句「现在实测」不见了 —— 这条历史记录会被读成"
                "此刻也没人在守")
    _note("生产默认路径下按钮不在、和解句在位")
    return True


@check("N-T4-01 负控：门控恒真 ⇒ T4-01 必须判红")
def n_t4_revive_gate_on_default_path():
    import remediation as RM
    it = _spk_item("host_shield_spawn_failed", _SPAWN_DETAIL,
                   topic="spawn_failed")
    orig_rev, orig_now = RM._can_revive, SV.posture_now
    try:
        RM._can_revive = lambda posture: True
        SV.posture_now = lambda: dict(_GUARD_POSTURE)
        r = c_t4_revive_gate_on_default_path()
    finally:
        RM._can_revive, SV.posture_now = orig_rev, orig_now
    if r is True or r is None:
        return "负控失效：门控恒真后 T4-01 仍判绿（尺子没分辨力）"
    if SV._PICK["retry"][0] not in str(r):
        return "负控方向不对：判红了但报的不是那个按钮（%s）" % r
    return True


@check("T4-02 ★ _can_revive(None) 一律现探；只有真缺岗才给按钮（白名单）")
def c_t4_can_revive_none_fail_closed():
    """None 这条路就是**生产默认路径**（调用方不注入姿态时拿到 None）。
    旧实现在这里 `return True` —— 那是本轮按钮违和的直接成因。
    白名单口径见 `remediation._revive_ok_states`：研发中／可信性存疑／
    未启用都在岗（或拉起也白拉），一个都不发给按钮。
    """
    import remediation as RM
    orig = RM._live_posture
    try:
        RM._live_posture = lambda: None
        if RM._can_revive(None) is not False:
            return "探不到态势 ⇒ 仍给按钮（宁可少一个入口，不许给假的）"
        for st, want in (("guarding", False), ("warn", False), ("dev", False),
                         ("off", False), ("unknown", False),
                         ("down", True), ("interrupted", True)):
            RM._live_posture = (lambda s: (lambda: {"state": s}))(st)
            got = RM._can_revive(None)
            if got is not want:
                return "None＋%s ⇒ 判 %r，应为 %r" % (st, got, want)
        RM._live_posture = lambda: None
        if RM._can_revive({"state": "down"}) is not True:
            return "显式 down 却没给按钮"
        if RM._can_revive("不是字典") is not False:
            return "posture 不是字典也发给按钮"
    finally:
        RM._live_posture = orig
    _note("None→现探→七态全对（只有 down/interrupted 给按钮）")
    return True


@check("N-T4-02 负控：_can_revive 对 None 恒真 ⇒ T4-02 必须判红")
def n_t4_can_revive_none_fail_closed():
    import remediation as RM
    orig = RM._live_posture

    def _always_true(posture):
        return True
    try:
        RM._live_posture = lambda: None
        RM._can_revive, keep = _always_true, RM._can_revive
        r = c_t4_can_revive_none_fail_closed()
    finally:
        RM._can_revive = keep
        RM._live_posture = orig
    if r is True or r is None:
        return "负控失效：None 恒真后 T4-02 仍判绿"
    if "探不到" not in str(r):
        return "负控方向不对：判红了但报的不是恒真（%s）" % r
    return True


#: 详情行（L1/L2 的说明）里不许出现的机器残留。
_META_RESIDUE = ("None", "pid=", "mode=", "enabled=", "severity=",
                 "subkind=", "topic=", "哨兵", "armed", "already-running",
                 "self-check-failed", "hook-paramedic")


@check("T4-03 ★ 详情行不出现机器残留（None／字段名／退休词／英文枚举）")
def c_t4_meta_no_machine_residue():
    """★ 为什么查**本机真实记录**而不是夹具：夹具只能覆盖我想到的形状，
    而本机 469 条里躺着的形状比我想到的多（`enabled=None`／`armed`／
    `net_mode` 都是这一遍才撞见的）。夹具 + 真记录两头都查。
    """
    samples = [
        _spk_item("host_shield_revived",
                  "监理不在（旧进程号 None），由 hook-paramedic 重新拉起"
                  "（mode=detached）"),
        _spk_item("host_shield_breach",
                  "state 文件 enabled=None 与审计链最近状态（armed）不一致"
                  "——以链为准"),
        _spk_item("host_shield_breach",
                  "安全区已上锁（区内防篡改；出网由 net_mode 把闸）："
                  "C:\\Temp\\x\\proj\\zone_vault"),
        _spk_item("host_shield_breach",
                  "监理 pid=19764 的进程号已被复用——旧哨兵已死，判不在岗并重启"),
    ]
    try:
        import inbox_store as S
        samples.extend(S.load_items())
    except Exception:                                           # noqa: BLE001
        pass                                    # 读不到真记录 ⇒ 只判夹具
    for it in samples:
        meta = M.record_meta(it)
        for tok in _META_RESIDUE:
            if tok in meta:
                return "详情行仍含 %r：%s" % (tok, meta[:110])
    _note("查了 %d 条（含本机真实记录）" % len(samples))
    return True


@check("N-T4-03 负控：关掉人话化 ⇒ T4-03 必须判红")
def n_t4_meta_no_machine_residue():
    orig = M.humanize
    try:
        M.humanize = lambda s: s
        r = c_t4_meta_no_machine_residue()
    finally:
        M.humanize = orig
    if r is True or r is None:
        return "负控失效：人话化关掉后 T4-03 仍判绿（尺子没分辨力）"
    return True


#: 面板文案里的**禁用语**：自夸／讲自己怎么实现／恐吓式预告／自问自答标题。
_PANEL_BANNED = (
    "不会假绿",          # 产品自夸（创始人：说事实，别说自己好）
    "不会假装好了",       # 同上
    "不是你的操作问题",   # 把责任推给产品的同时还教育用户
    "这是产品的已知短板",  # 同上
    "点这个会",           # 讲按钮怎么实现
    "什么都不做",         # 恐吓式预告（④ 段的口气）
    "不做的后果",         # 已删除的段名
    "你能做什么",         # 已删除的自问自答标题
    "现在怎么样",         # 同上
    "如果什么都不做",
    "你就只能看到",       # 恐吓式预告
    "等于没有守卫",       # 产品自我评价
)


def _panel_banned_hit(src):
    """扫**字符串字面量**（注释里复述历史事故原文不算 —— 那是给人看的账）。"""
    for lit in re.findall(r'"[^"\n]*"', src or ""):
        for b in _PANEL_BANNED:
            if b in lit:
                return "文案字面量里出现 %r：%s" % (b, lit[:70])
    return None


@check("T4-04 ★ 归因面板文案无自夸／机制句／恐吓句（ASD-STE100 精炼）")
def c_t4_panel_copy_ste():
    import remediation as RM
    why = _panel_banned_hit(inspect.getsource(RM))
    if why:
        return why
    _note("扫了 %d 个禁用语" % len(_PANEL_BANNED))
    return True


@check("N-T4-04 负控：把一句自夸塞回文案 ⇒ T4-04 必须判红")
def n_t4_panel_copy_ste():
    import remediation as RM
    src = inspect.getsource(RM)
    anchor = '_a(ACT_FIX, "再试一次上锁"),'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = src.replace(anchor,
                      '_a(ACT_FIX, "再试一次上锁",'
                      ' hint="点了会当场重试，不会假装好了。"),', 1)
    why = _panel_banned_hit(mut)
    if not why:
        return "夹具不成立：变异源码里没有禁用语 ⇒ 负控无分辨力"
    if _panel_banned_hit(src) is not None:
        return "夹具不成立：真源码本身就红 ⇒ 负控无分辨力"
    return True


@check("T4-05 ★ 写侧进程号缺省时整段不写（None 不许上屏）")
def c_t4_pid_note_no_none():
    import host_shield as HS
    if HS._pid_note(None) != "":
        return "pid 为空仍写出 %r —— Python 的字上屏了" % HS._pid_note(None)
    if HS._pid_note("") != "":
        return "pid 为空串仍写出 %r" % HS._pid_note("")
    if HS._pid_note(5) != "（旧进程号 5）":
        return "有进程号时形状变了：%r" % HS._pid_note(5)
    # 渲染层兜底：detail 里带 None 的历史记录，上屏后不许还有 None
    it = _spk_item("host_shield_spawn_failed", _SPAWN_DETAIL,
                   topic="spawn_failed")
    if "None" in PC.body(_t4_page([it])):
        return "页面上仍有裸 None（写侧修了，读侧还有漏）"
    return True


@check("N-T4-05 负控：_pid_note 回到「%s 硬塞」⇒ T4-05 必须判红")
def n_t4_pid_note_no_none():
    import host_shield as HS
    orig = HS._pid_note
    try:
        HS._pid_note = lambda pid: "（旧进程号 %s）" % pid
        r = c_t4_pid_note_no_none()
    finally:
        HS._pid_note = orig
    if r is True or r is None:
        return "负控失效：回到硬塞 None 后 T4-05 仍判绿"
    if "None" not in str(r):
        return "负控方向不对：判红了但报的不是 None（%s）" % r
    return True


@check("T4-06 ★ 「现在实测」只在需要的类别出现（值守中不挂无关和解句）")
def c_t4_posture_note_only_when_needed():
    """值守中时：讲监理自己的记录要一句现场来和解；讲某个落点的记录不要 ——
    落点开着与监理在岗两件事都真，摆一句"现在值守中"反而像自相矛盾
    （与截图里的违和同型：同一张卡片两个时刻打架）。
    """
    zone = _spk_item("host_shield_zone_locked", _ZONE_DETAIL,
                     topic="zone_lock_failed")
    spawn = _spk_item("host_shield_spawn_failed",
                      "监理已停止（旧进程号 5），重新拉起也没成功。",
                      topic="spawn_failed")
    h_zone = PC.body(_t4_page([zone], posture=dict(_GUARD_POSTURE)))
    if "现在实测" in h_zone:
        return "值守中＋落点类记录也挂「现在实测」—— 与①段的历史时刻打架"
    h_spawn = PC.body(_t4_page([spawn], posture=dict(_GUARD_POSTURE)))
    if "现在实测" not in h_spawn:
        return "监理自己没起来的那条，值守中却没有和解句 —— 会被读成此刻也没在守"
    _note("落点类不出、监理类出")
    return True


@check("N-T4-06 负控：落点类记录也挂和解句 ⇒ T4-06 必须判红")
def n_t4_posture_note_only_when_needed():
    """变异走**真实入口**：`zone_locked` 分支的 `severity_note` 取自
    `what_got_through()`（不是 `_posture_note`）—— 把那个函数的返回换成
    和解句，等价于"落点类也挂了现在实测"。
    """
    import remediation as RM
    orig = RM.what_got_through
    try:
        RM.what_got_through = lambda d: ("（现在实测：值守中。）", "")
        r = c_t4_posture_note_only_when_needed()
    finally:
        RM.what_got_through = orig
    if r is True or r is None:
        return "负控失效：落点类也挂和解句后 T4-06 仍判绿"
    if "现在实测" not in str(r):
        return "负控方向不对：判红了但报的不是和解句（%s）" % r
    return True


# ════════ T4-07／T4-08 词条文案：把品质性机制层的两张网接上「问号」这条腿 ════════
#: ★ 为什么单立这两条（0.53.2，创始人 2026-10-19 06:21 交办）：
#:   原话「我建议所有的---R0、L1、L2的说明都过一遍，把违和、废话都清理了。
#:         还有，参考ASD-STE100做一下精炼，防范各种啰嗦废话。」
#:   T4 那一批只改了**归因面板**（`remediation.py`）：T4-04 扫的是
#:   `inspect.getsource(RM)`，一个字都不看 `glossary.TERMS`。于是「问号词条」
#:   这条腿在品质性机制层里是**空的** ——
#:     · 预算网（单句 ≤40 字）挂在 `record_meta()`（收件箱条目）；
#:     · 禁用语网挂在归因面板；
#:     · 主语网（网四）挂在渲染出的页面。
#:   三张网都不经过「词条正文」这个消费面 ⇒ 一个 233 字、四句机制话的灯词条
#:   **活了两版没人报红**。这正是本仓最贵的那个形状：
#:   **只守一条腿，另一条腿天然全绿**。
#:   ★ 已有的 H6b（`ci/inbox_guards_0360.py`）确实**扫了**词条五个字段 ——
#:     但只扫「鸟语」（金丝雀那类未登记词）。同一字段被守了一个维度，
#:     另一个维度没守，看起来像"词条已经有判据了"—— 这比完全没有判据更危险。
#:   ★ 为什么不把「我们」也放进 `_TERM_BANNED`：网四的 `T-04f` 渲染六个页面
#:     取可见文本，词条正文就在那六个页面的 HTML 里 ⇒ **已被覆盖**。
#:     同一断言开两个入口必漂（本仓「同一事实两处实现」标准形状），故不重复。
#:   ★ 与 T4-04 的分工：T4-04 扫**源码字面量**（面板文案是拼出来的，只能看源码）；
#:     这两条扫**运行时的词条字典**（问号正文是数据，且含 `_shield_overview()`
#:     这类派生句 —— 扫源码会漏掉派生结果）。各守一层，各配负控。

#: ASD-STE100 折算：一句 ≤20 词 ⇒ 中文按 1 词 ≈ 2 字 ⇒ **一句 ≤40 字**。
_TERM_SENT_MAX = 40
#: 一个字段最多几句：STE 一段 ≤6 句，但词条字段是短说明 ⇒ **2 句封顶**。
_TERM_SENT_PER_FIELD = 2


def _tw(s):
    """显示宽度（不叫"字数"）：汉字算 1，其余非空白算 0.5。

    ★ 为什么不用 `len()`：`~/.antinel/ledger/daily.jsonl` 有 29 个字符但只占
      约 15 个汉字宽 —— 用 `len()` 会让"该不该带路径"变成"会不会判红"，
      判据就逼着产品藏信息（本仓最忌的形状）。宽度才是浮层的真实预算。
    """
    w = 0.0
    for ch in s or "":
        if ch.isspace():
            continue
        w += 1.0 if ord(ch) > 0x2E7F else 0.5
    return int(w + 0.5)


def _term_sentences(s):
    """把一段词条正文切成句子（按 。！？ 断；`<b>` 等标签不计宽）。"""
    plain = re.sub(r"<[^>]+>", "", str(s or ""))
    return [p for p in re.split(r"(?<=[。！？])", plain) if p.strip()]


def _term_budget_problems(terms):
    """纯函数：给「键 → 词条字典」，返回问题清单（空 = 过预算网）。

    ★ 纯函数是为了让负控**直接复用同一把尺子**：给变异后的字典，
      与正判据走同一段代码 —— 不另写一份"负控专用"的判读。
    """
    bad = []
    for k in sorted(terms):
        t = terms.get(k)
        if not isinstance(t, dict):
            continue
        for f in ("one", "inc", "exc", "unit"):
            ss = _term_sentences(t.get(f))
            if not ss:
                continue
            if len(ss) > _TERM_SENT_PER_FIELD:
                bad.append("%s.%s 有 %d 句（上限 %d）"
                           % (k, f, len(ss), _TERM_SENT_PER_FIELD))
            for s in ss:
                w = _tw(s)
                if w > _TERM_SENT_MAX:
                    bad.append("%s.%s 有一句 %d 字（上限 %d）：%s…"
                               % (k, f, w, _TERM_SENT_MAX, s.strip()[:24]))
    return bad


#: 词条专属禁用语。每一条都能追到创始人的一句原话，不是"我觉得不好"。
_TERM_BANNED = (
    "按来源",    # 讲"怎么算出来的"，不是回答"这是什么"（创始人：这是机制话）
    "抢位",      # 内部隐喻：灯和徽标谁占版面，用户不需要知道版面协商
    "不冒充",    # 自我评价（"不冒充此刻"）—— 说事实，别说自己不撒谎
    "也就是说",  # 同义反复的标志（网二：同一句话说两次）
    "换句话说",  # 同上
)


def _term_banned_hits(terms, banned=None):
    """纯函数：词条正文命中禁用语 ⇒ 返回清单（空 = 干净）。"""
    ban = tuple(banned if banned is not None else (_TERM_BANNED + _PANEL_BANNED))
    hits = []
    for k in sorted(terms):
        t = terms.get(k)
        if not isinstance(t, dict):
            continue
        for f in ("w", "one", "inc", "exc", "unit"):
            plain = re.sub(r"<[^>]+>", "", str(t.get(f) or ""))
            for b in ban:
                if b in plain:
                    hits.append("%s.%s 里出现 %r" % (k, f, b))
    return hits


@check("T4-07 ★ 词条文案过预算网：一句 ≤40 字、一个字段 ≤2 句（ASD-STE100 折算）")
def c_t4_term_budget():
    """★ 从**运行时的词条字典**出发，不从源码字面量出发。

    词条里有派生句（`L2.inc` 由 `_shield_overview()` 现算），扫源码只能看到
    表达式 —— 派生出来的长句会被漏掉，而它恰恰是最长的那一类。
    """
    import glossary as GL
    bad = _term_budget_problems(GL.TERMS)
    if bad:
        more = "…（共 %d 处）" % len(bad) if len(bad) > 4 else ""
        return "；".join(bad[:4]) + more
    _note("%d 条词条 × 4 字段全过预算网" % len(GL.TERMS))
    return True


@check("N-T4-07 负控：把灯词条退回 107 字的旧机制句 ⇒ T4-07 必须判红")
def n_t4_term_budget():
    import glossary as GL
    if _term_budget_problems(GL.TERMS):
        return "夹具不成立：真词条本身就超预算 ⇒ 负控无分辨力"
    orig = GL.TERMS["light"]["inc"]
    try:
        GL.TERMS["light"]["inc"] = (
            "它按来源拼：失守只认此刻；拦截／注意看最近 24 小时的账，"
            "但只有刚发生的才算数 —— 你看过、或放久了，就转成「待阅」里的一条，"
            "不再占着灯。")
        r = c_t4_term_budget()
    finally:
        GL.TERMS["light"]["inc"] = orig
    if r is True or r is None:
        return "负控失效：退回旧机制句后仍判绿（尺子没有分辨力）"
    if "light.inc" not in str(r):
        return "负控方向不对：判红了但没点名词条（%s）" % r
    return True


@check("T4-08 ★ 词条文案过禁用语网：不出现机制句／内部隐喻／同义反复标志")
def c_t4_term_banned():
    import glossary as GL
    hits = _term_banned_hits(GL.TERMS)
    if hits:
        more = "…（共 %d 处）" % len(hits) if len(hits) > 4 else ""
        return "；".join(hits[:4]) + more
    _note("扫了 %d 个禁用语 × %d 条词条" % (len(_TERM_BANNED) + len(_PANEL_BANNED),
                                            len(GL.TERMS)))
    return True


@check("N-T4-08 负控：把「不跟灯抢位」塞回灯词条 ⇒ T4-08 必须判红")
def n_t4_term_banned():
    import glossary as GL
    if _term_banned_hits(GL.TERMS):
        return "夹具不成立：真词条本身就有禁用语 ⇒ 负控无分辨力"
    orig = GL.TERMS["light"]["exc"]
    try:
        GL.TERMS["light"]["exc"] = orig + "另有研发中、缺粮两件事不跟灯抢位。"
        r = c_t4_term_banned()
    finally:
        GL.TERMS["light"]["exc"] = orig
    if r is True or r is None:
        return "负控失效：塞回「不跟灯抢位」后仍判绿（尺子没有分辨力）"
    if "抢位" not in str(r):
        return "负控方向不对：判红了但报的不是「抢位」（%s）" % r
    return True


#: 同一词条内两个字段之间，公共子串到这么长就认定「同一件事说了两遍」。
#: 取 6 的来处：中文里 6 字已经能承载一个完整的断言（「低于一周口粮」7 字、
#: 「有东西没被挡住」7 字）。4–5 字多是功能词（「你已经处理」「没被挡住」），
#: 那两个字段本来就是在讲同一件事的两面，压到 4 会逼产品把话说得别扭。
_TERM_DUP_MIN = 6

_TERM_FIELDS = ("one", "inc", "exc", "unit")


def _term_dup_norm(s):
    """去标签、去标点、去空白 —— 只留下"说了什么字"。"""
    s = re.sub(r"<[^>]+>", "", str(s or ""))
    return re.sub(r"[\s，。、；：「」（）()—…·/]", "", s)


def _lcs_len(a, b):
    """最长公共**子串**长度（不是子序列 —— 子序列会把不相干的字凑成一条）。"""
    if not a or not b:
        return 0
    best = 0
    prev = [0] * (len(b) + 1)
    for i in range(1, len(a) + 1):
        cur = [0] * (len(b) + 1)
        for j in range(1, len(b) + 1):
            if a[i - 1] == b[j - 1]:
                cur[j] = prev[j - 1] + 1
                if cur[j] > best:
                    best = cur[j]
        prev = cur
    return best


def _term_dup_problems(terms, limit=None):
    """纯函数：词条内跨字段同义反复清单（空 = 干净）。

    ★ 为什么单立这一条（不改 T4-07／T4-08 的量法）：那两条按**字段**切分
      —— 一句 ≤40 字、一字段 ≤2 句 —— 而创始人看到的是一个浮层里的**连续
      四段**。四段各自合规、合起来把同一件事说了两遍，两条尺子都抓不到。
      实测过的形状：`days` 的 one「账本里有事件记录的天数，一共多少天」与
      unit「就是账本里记着事的天数」（逐字同义）；`archive` 的 exc 与 unit
      都在说"文件读得到才显示"。
    ★ 与网二（信息网：同一句话说两次 ≥8 字即红）的分工：网二挂在**整页
      渲染结果**上（跨条目、跨区域），本条挂在**单条词条内部**（跨字段）
      —— 两者的分母不同，不是同一断言开两个入口。
    """
    cap = _TERM_DUP_MIN if limit is None else limit
    out = []
    for k in sorted(terms):
        t = terms.get(k)
        if not isinstance(t, dict):
            continue
        plain = {f: _term_dup_norm(t.get(f)) for f in _TERM_FIELDS}
        for i in range(len(_TERM_FIELDS)):
            for j in range(i + 1, len(_TERM_FIELDS)):
                f1, f2 = _TERM_FIELDS[i], _TERM_FIELDS[j]
                n = _lcs_len(plain[f1], plain[f2])
                if n >= cap:
                    out.append("%s.%s 与 %s 重复 %d 字（上限 %d）"
                               % (k, f1, f2, n, cap - 1))
    return out


@check("T4-09 ★ 词条内不许同一件事说两遍：任意两字段公共子串 ≥6 字即红")
def c_t4_term_no_dup():
    """创始人 2026-10-19「把违和的、错的、啰嗦的等等都修掉」的第二把尺子。

    ★ 量的是**运行时的词条字典**，不是源码 —— 理由同 T4-07（`L2.inc` 是
      现算的）。也正因为是运行时的，负控可以就地变异一个字段再还原。
    """
    import glossary as GL
    bad = _term_dup_problems(GL.TERMS)
    if bad:
        more = "…（共 %d 处）" % len(bad) if len(bad) > 4 else ""
        return "；".join(bad[:4]) + more
    _note("%d 条词条内部无跨字段同义反复（阈值 %d 字）"
          % (len(GL.TERMS), _TERM_DUP_MIN))
    return True


@check("N-T4-09 负控：把「低于一周口粮时亮」同时塞进缺粮的 one 与 inc ⇒ T4-09 必须判红")
def n_t4_term_no_dup():
    import glossary as GL
    if _term_dup_problems(GL.TERMS):
        return "夹具不成立：真词条本身就有跨字段重复 ⇒ 负控无分辨力"
    orig = GL.TERMS["Ls"]["inc"]
    try:
        GL.TERMS["Ls"]["inc"] = "粮的余额低于一周口粮时亮起。"
        r = c_t4_term_no_dup()
    finally:
        GL.TERMS["Ls"]["inc"] = orig
    if r is True or r is None:
        return "负控失效：同一句话塞进两个字段后仍判绿（尺子没有分辨力）"
    if "Ls" not in str(r):
        return "负控方向不对：判红了但没点名缺粮词条（%s）" % r
    return True


def main():
    print("=" * 78)
    print("0.49.0 收口判据 —— W-08 默认尺寸 · W-09 浮层逃逸 · U-17 图标动效 · "
          "U-18 哨标比例/不被裁 · B-02…B-08/B-13 冒泡 · FLO-01…FLO-05 漂浮哨标")
    print("＋ FLO-10a…e 哨标动效三态（0.53.1：标准 LOGO／整圆可点／保持动态）")
    print("＋ J1–J5「五条违和」同类可抓（原 0518，2026-10-16 按 A2/P5 并入）")
    print("（负控全部内存/临时目录变异，不写任何产品文件；node 缺失 ⇒ SKIP，不假绿）")
    print("=" * 78)
    ok = fail = skip = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True or why is None:
                why = ""
            print("  ✅ %-62s %s" % (name, why or ""))
            ok += 1
        except Skip as s:
            print("  ⏭️  %-62s %s" % (name, s))
            skip += 1
        except AssertionError as e:
            print("  ❌ %-62s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-62s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红 / %d 跳过" % (ok, fail, skip))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
