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
  ④ B-02…B-08 冒泡：急事（R0/L2）要"当时弹出来＋有声音＋不一闪而过＋
     人工确认"。路由换代（R0/L2→冒泡、其余→toast、同一事件只走一条通道）
     由 `ci/inbox_guards.py` 的 `c_daemon_tick_notifies_once`（记 B-01）守；
     **本文件守它的下游**：界面同源、不闪退、声音、节流/ack、可见性闸、
     服务起不来如实、一次一枚。
  ⑤ FLO-01…FLO-05 漂浮最小态："哨兵很多时候不要碍事，只要在"——收缩成
     一枚漂浮哨标（点击展开），面板右上角一个钮，展开即退役哨标。
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
  ⑧ B-13「打开值守台」已开着就别重开（0.50.3 补）：创始人 2026-10-14
     「点击打开值守台后，之前的关闭了，打开了新的，但是状态不对了……点完了
     按钮显示'打开值守台'按钮好像不对吧，值守台打开着呢」。旧链路只有
     `open_console_settled()` 一条路（语义是"没有窗、要开一个"）⇒ 面板本来
     就开着时点一下 = 旧窗被关、新窗从头加载（态势读数重新算 ⇒"状态不对了"），
     而按钮上写着"打开" ⇒ **不成立的承诺**。修法：抽成唯一决策点
     `bubble_open_route()` 三路分流（看得见 ⇒ 只切到前面；看不见 ⇒ 开窗；
     **判不出来 ⇒ 开窗**，宁可多开一个窗也不许点了没反应）；文案侧开着就不画
     按钮、点完按钮退场换状态。判据打在**行为**上（三条路的动作序列＋返回值），
     N-B13 把分流条件反过来、**拿变异体跑同一条正判据** ⇒ 必红。

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
import time
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
import inbox_window as WIN                                      # noqa: E402
import page_caliber as PC                                       # noqa: E402
RESULTS = []

_SERVER_REL = "inbox_server.py"
_WINDOW_REL = "inbox_window.py"
_DAEMON_REL = "inbox_daemon.py"
_LOGO_PS1_REL = "tools/logo.ps1"


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


# ═══════════════════════════════════════════════════ B-09 冒泡窗"看得见" ══
#: ★★★ 0.50.1（创始人 2026-10-14 截图一「泡泡下沿没露出来」）：
#:   为什么这条必须存在 —— 旧版的保证链是「`bubble_geometry` 算出 384×148
#:   → `place_all` 落位 → **回读一致** → 报 placed=True」，而它**全绿**、
#:   用户却看不见下沿。因为 `place_all` 只保证"窗落在目标矩形上"，
#:   它**不知道内容有没有被裁掉** ⇒ "回读一致"≠"看得见"，缺的正是
#:   「内容 ↔ 窗口」这条闭环。所以尺子不能只量"落位成功"。

@check("B-09 冒泡窗高度闭环在位：页面报缺 → 服务端按内容长高（下沿不动）→ 回读")
def c_b09():
    page = BB.render("t", "b", "R0", "tok-b09", run_id="r", kind="k")
    if "bubblefit" not in page:
        return "冒泡页没有把'还差多少高度'报上去 ⇒ 窗口只能靠常量猜，裁掉也无声"
    if "scrollHeight" not in page or "clientHeight" not in page:
        return "冒泡页没有量 scrollHeight/clientHeight ⇒ 报上去的不是真缺量"
    # ★ 量具纪律（两条，都是实测踩出来的）：
    #   ① **不许用子串判** —— 首版写的是 `"height:100%" in …`，而
    #      `min-height:100%` 里**含**这个子串 ⇒ 好值被判红（尺子反咬）。
    #      ⇒ 用正则认 `html,body{…}` 那一条。
    #   ② **必须显式选层** —— CSS 断言走 `PC.chrome(...)`（S48：`<style>` 是
    #      另一层，拿整页原文当 CSS 会把注释/正文一起算进来）。
    _bub_css = PC.chrome(page)
    if not re.search(r"html,body\{[^}]*min-height:100%", _bub_css):
        return ("冒泡页没有 `html,body{min-height:100%}` ⇒ 文档被钉死在视口上，"
                "内容超出只能被裁（这正是旧版那条断掉的链）")
    if re.search(r"html,body\{[^}]*[^-]height:100%", _bub_css):
        return "冒泡页又把 html/body 钉回 height:100% 了 ⇒ 量不出缺多少"
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


@check("B-11 冒泡页不许把字切开：按钮/注脚不折行，正文截断要给省略号")
def c_b11():
    page = BB.render("t", "b", "R0", "tok-b11", run_id="r", kind="k")
    css = page.split("<style>")[1].split("</style>")[0]
    for sel in (".bub-ok{", ".bub-open{", ".bub-note{"):
        blk = css.split(sel)[1].split("}")[0]
        if "nowrap" not in blk:
            return ("%s 允许折行 ⇒ 一窄就把「打开值守台」拆成「打开值/守台」"
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
    bad_js = (SV._LOGO_JS_TMPL
              .replace("__STYLE__", json.dumps(SV.LOGO_MOTION,
                                               ensure_ascii=False))
              .replace("__RING_GREEN__", json.dumps(list(SV.LOGO_RING_GREEN)))
              .replace("__RING_DARKRED__", json.dumps(list(SV.LOGO_RING_DARKRED))))
    with _Patch(SV, _LOGO_JS=bad_js):
        why = c_u18d()
        if why is True or why is None:
            return "负控失效：波幅 105 真跑越界仍判合格 —— 这条尺子是装饰"
        if str(why).startswith("SKIP"):
            return "负控失效：变异后判据退化成 SKIP，没有分辨力"
    return True


# ═════════════════════════════ B-13 「打开值守台」已开着就别重开（0.50.3）══
#: ★★★ 创始人 2026-10-14：「点击打开值守台后，之前的关闭了，打开了新的，但是
#:   状态不对了……另外，点完了按钮显示'打开值守台'按钮好像不对吧，值守台打开着
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
    """给临时中枢塞一条值守台记录（`bubble_open_route` 没有 URL 就直接早退）。"""
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
        return ("值守台已开着，却返回 opened=%r（应 existing）⇒ 页面会以为"
                "「刚打开」" % (r.get("opened"),))
    if seen != ["focus"]:
        return ("值守台已开着，实际动作序列是 %r（应只有 focus）⇒ 旧窗被关、"
                "新窗重建（创始人原话「之前的关闭了，打开了新的」）" % (seen,))
    if r.get("ok") is not True:
        return "切到前面成功却没报 ok ⇒ 页面拿不到成功信号，会显示失败"
    # ② 没开着 ⇒ 才开窗；不许去切一个不存在的窗
    del seen[:]
    r2 = route(vis=False, finder=lambda: [11], focuser=_focus, opener=_open)
    if seen != ["open"]:
        return "值守台没开着，实际动作序列是 %r（应只有 open）" % (seen,)
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


@check("B-13 打开值守台：已开着 ⇒ 只切到前面（不关旧窗不重开）；没开/判不出 ⇒ 才开窗")
def c_b13():
    err = _bubble_open_arms_fail(SV.bubble_open_route)
    if err:
        return err
    # ---- 文案侧：渲染那一刻值守台已开着 ⇒ 不画按钮，改一句状态 ----
    BTN = '<button class="bub-open"'
    STA = '<span class="bub-has">'
    off = BB.render("t", "b", "R0", "tok-b13", run_id="r", kind="k",
                    console_open=False)
    on = BB.render("t", "b", "R0", "tok-b13", run_id="r", kind="k",
                   console_open=True)
    if BTN not in off:
        return "值守台没开着时反而没有「打开值守台」按钮 ⇒ 用户没入口"
    if BTN in on:
        return ("值守台已开着，却仍画着「打开值守台」按钮 ⇒ 一个不成立的承诺"
                "（创始人截图二「值守台打开着呢」）")
    if STA not in on:
        return "值守台已开着，却没换成一句状态 ⇒ 那个位置空着，用户不知道怎么回事"
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


# ═══════════════════════════════════════════════════ B-12 认窗口径必须同一把尺 ══
#: 假桌面：五枚可见窗，其中两枚是**用户窗口** —— 标题里恰好含哨标/冒泡的标记，
#: 但标记**不在末尾**。这就是实测误伤的形状（`_p_probe_win.py` 的内存替换夹具）。
_FAKE_WINDOWS = [
    (1, "收件箱 · 值守台#abc123"),        # 本次值守台
    (2, "我的 · 哨标 收藏夹"),             # ★ 用户窗口（含标记，不在末尾）
    (3, "Antinel · 哨标#abc123"),          # 本次哨标
    (4, "整理一下 · 冒泡 记录"),           # ★ 用户窗口（含标记，不在末尾）
    (5, "需要你处理 · 冒泡#abc123"),       # 本次冒泡
]


def _fake_enum(visible_only=True):                          # noqa: ARG001
    return list(_FAKE_WINDOWS)


@check("B-12 认窗口径一致：哨标/冒泡宽泛分支不许用任意位置子串（会关用户窗口）")
def c_b12(mod=None):
    """★★ 清单 B4（实测真缺陷）：三处认窗必须同一口径 —— 标记**在末尾**。

    原来 `find_logo_windows` / `find_bubble_windows` 的宽泛分支用
    `mark in title`（任意位置子串），而 `is_console_title` 用 `_mark_at_tail`
    （末尾＋白名单）。实测后果：用户窗口「我的 · 哨标 收藏夹」
    「整理一下 · 冒泡 记录」被认成本次哨标/冒泡窗，而这两条路径通向
    `WM_CLOSE` ⇒ **可能关掉用户自己的窗口**（0.36.5 明令不可接受）。

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
        return "值守台认窗把用户窗口也算进来了：%r（应为 [1]）" % (con,)
    if logo != [3]:
        return ("哨标认窗把用户窗口也算进来了：%r（应为 [3]）—— 这条路径通向 "
                "WM_CLOSE，会关掉用户自己的窗口" % (logo,))
    if bub != [5]:
        return ("冒泡认窗把用户窗口也算进来了：%r（应为 [5]）—— 同上，"
                "会关掉用户自己的窗口" % (bub,))
    return True


@check("N-B12 负控：宽泛分支退回 `mark in title` 子串口径 ⇒ 同一条尺子必须判红")
def n_b12():
    import types
    src = _src(_WINDOW_REL)
    mutated, n = re.subn(r"elif _mark_at_tail_any\(title, mark\):",
                         "elif mark in title:", src)
    if n != 2:
        return ("变异锚点命中 %d 处（应为 2 处：哨标＋冒泡各一）"
                "—— 负控自身失效，不算通过" % n)
    mod = types.ModuleType("is0514_b12_mut")
    mod.__file__ = os.path.join(ROOT, _WINDOW_REL)
    exec(compile(mutated, mod.__file__, "exec"), mod.__dict__)   # noqa: S102
    if c_b12(mod=mod) is True:
        return "负控失效：退回子串口径后仍判合格 —— 这条判据是装饰"
    return True


# ════════════════════════════════════════════════════════════ B-02…B-08 ══
class _PopEnv:
    """冒泡链路的假桌面：假 opener（记录调用）、假 console（不起真服务）。"""

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
    return ("data-logo=" in html and "requestAnimationFrame" in html
            and "知道了" in html and "打开值守台" in html
            and "会一直留着" in html)


@check("B-02 冒泡界面与值守台同源：同一套 CSS＋同一枚动效哨标＋确认/打开钮")
def c_b02():
    html = BB.render("R0 失守：探针", "正文……", "R0", "tok", "run42",
                     kind="host_shield_revived")
    page = PC.body(html)
    if not _b02_ok(page):
        miss = [k for k, v in (("动效哨标", "data-logo=" in page),
                               ("rAF 状态机", "requestAnimationFrame" in page),
                               ("确认钮", "知道了" in page),
                               ("打开钮", "打开值守台" in page),
                               ("留存说明", "会一直留着" in page)) if not v]
        return "冒泡页缺：%s —— 与值守台同源是 founder 点名要的" % "、".join(miss)
    if " · 冒泡#run42" not in page:
        return "标题没带 #run_id —— 认窗（关旧冒泡）会失去目标"
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
        return "没有沿用值守台的 CSS 变量 —— 「同源」只剩口号"
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
    if "尚未标记处理" not in js or "处理后请点右上角 × 关闭" not in js:
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
    if "已冒过泡" not in (r2.get("why") or ""):
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


@check("B-06 可见性闸：值守台窗口正开着 ⇒ 不弹（不重复打扰）")
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


@check("B-07 值守台服务起不来 ⇒ 如实说发不出，opener 一次都不调")
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
    if "不走冒泡" not in (r.get("why") or ""):
        return "级别门原因没说清：%r" % r.get("why")
    with _Patch(WIN, close_bubble_windows=lambda *a, **k: (1, "收了 1 枚")):
        r2 = env.pop(level="R0", kind="R0", now=6000100.0)
    if not r2.get("ok") or len(env.urls) != 1:
        return "该弹没弹：%s" % r2.get("why")
    if r2.get("closed_old") != 1:
        return "没收旧冒泡（closed_old=%r）—— 会长成一串" % r2.get("closed_old")
    r3 = env.pop(level="R0", kind="R0", now=6000200.0, cfg={"bubble": False})
    if r3.get("ok") or len(env.urls) != 1:
        return "配置关掉了还弹 —— 配置闸失效"
    if "配置" not in (r3.get("why") or ""):
        return "配置闸原因没说清：%r" % r3.get("why")
    return True


# ════════════════════════════════════════════════════════════ FLO-01…05 ══
#: logo.ps1 里的动法表必须与规格 v1.2 同值（它是 Python 侧状态机的
#: PowerShell 孪生；两处各写一份 ⇒ 迟早漂，这条就是防漂的）。
_FLO_SPEC_ROWS = {
    "L0": ((126, 155, 132), 12.0, 1.0, 0),
    "L1": ((205, 194, 154), 8.0, 1.0, 45),
    "L2": ((224, 180, 85), 5.5, 1.0, 70),
    "LD": ((232, 163, 61), 3.5, 1.0, 105),
    "R0": ((178, 84, 84), 0.0, 0.45, 0),
}
_ROW_RE = re.compile(r'"(\w+)"\s*=\s*@\{\s*c\s*=\s*@\((\d+),\s*(\d+),\s*(\d+)\);'
                     r'\s*lap\s*=\s*([\d.]+);\s*ringO\s*=\s*([\d.]+);'
                     r'\s*waveR\s*=\s*(\d+);')


def _flo01_ok(src):
    if 'FormBorderStyle = "None"' not in src:
        return "没钉死无边框 —— 会有标题栏，哨标不像哨标"
    if "TopMost = $true" not in src:
        return "没置顶 —— 会被别的窗盖住（哨兵要「一直在」）"
    for edge in ("MinimumSize", "MaximumSize"):
        if ("$form.%s = New-Object System.Drawing.Size($Size, $Size)" % edge
                not in src):
            return "%s 没钉死 —— WinForms 有最小跟踪宽度（实测 136px），不钉就缩不到 46" % edge
    if "Test-Path -LiteralPath $Quit" not in src or "Quit-Now" not in src:
        return "没有轮询退役标志自退 —— 退役只能靠强杀"
    if 'Write-Action "open"' not in src:
        return "点击没写 open 动作 —— 点了哨标展不开值守台"
    if 'if (Write-Action "open") { Quit-Now }' not in src:
        return "open 动作写失败也会自退 —— 窗口消失但托盘没收到，用户无从重试"
    if "$script:actionWriteFailed = $true" not in src or "$script:actionWriteFailTip" not in src:
        return "动作写盘失败没有可观测反馈 —— 用户点了没反应"
    if "add_MouseMove" not in src or "dragging" not in src:
        return "不能拖拽 —— 用户无法把它挪到不碍事的位置"
    if "1.4" not in src:
        return "找不到涟漪周期 1.4s —— 频次通道漂了"
    if "coast" not in src:
        return "没有惯性滑行量 —— R0「滑行 20° 后永停」演不出来"
    rows = {}
    for m in _ROW_RE.finditer(src):
        rows[m.group(1)] = ((int(m.group(2)), int(m.group(3)), int(m.group(4))),
                            float(m.group(5)), float(m.group(6)),
                            int(m.group(7)))
    if set(rows) != set(_FLO_SPEC_ROWS):
        return "动法键集合 %s ≠ 规格 %s" % (sorted(rows), sorted(_FLO_SPEC_ROWS))
    for k, want in _FLO_SPEC_ROWS.items():
        got = rows[k]
        if (got[0] != want[0] or abs(got[1] - want[1]) > 1e-9
                or abs(got[2] - want[2]) > 1e-9 or got[3] != want[3]):
            return "%s 行 %r ≠ 规格 %r" % (k, got, want)
    if "waveR / 105.0" not in src:
        return "波幅缩放没以规格满档 105 为基准"
    return None


@check("FLO-01 logo.ps1 契约：动法表同规格、无边框、置顶、可拖、标志自退")
def c_flo01():
    src = _src(_LOGO_PS1_REL)
    why = _flo01_ok(src)
    if why:
        return why
    if not os.path.isfile(IL.script_path()):
        return "IL.script_path() 指向的脚本不在：%s" % IL.script_path()
    return True


@check("N-FLO01 负控：把 R0 圈时改成 3.5（不停摆）⇒ 尺子必须判红")
def n_flo01():
    src = _src(_LOGO_PS1_REL)
    bad = src.replace('"R0" = @{ c = @(178,84,84);   lap = 0.0;',
                      '"R0" = @{ c = @(178,84,84);   lap = 3.5;')
    if bad == src:
        return "夹具不成立：变异没生效（要改的那行没匹配上）"
    if _flo01_ok(bad) is None:
        return "负控失效：R0 不停摆也判合格 —— 规格锁是装饰"
    bad2 = src.replace('$form.TopMost = $true', '$form.TopMost = $false')
    if bad2 == src:
        return "夹具不成立：置顶变异没生效"
    if _flo01_ok(bad2) is None:
        return "负控失效：不置顶也判合格"
    bad3 = src.replace('if (Write-Action "open") { Quit-Now }',
                       'Write-Action "open"\n    Quit-Now')
    if bad3 == src:
        return "夹具不成立：点击失败仍退出的变异没命中"
    if _flo01_ok(bad3) is None:
        return "负控失效：点击动作可能写失败还无条件退出也被判合格"
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


@check("FLO-05 面板收缩钮＋服务端 op＋展开即退役哨标，三处都在")
def c_flo05():
    html = _page()
    button = re.search(r'<button class="collbtn".*?</button>', html, re.S)
    if not button or 'data-coll="1"' not in button.group(0):
        return "页面里没有收缩钮 —— 漂浮最小态没有入口"
    if "收缩成漂浮哨标" not in PC.body(button.group(0)):
        return "收缩钮标题没说人话（用户不知道点了会怎样）"
        return "收缩钮标题没说人话（用户不知道点了会怎样）"
    if "op=collapse" not in html:
        return "收缩钮没接 op=collapse"
    sv = _src(_SERVER_REL)
    if 'op == "collapse"' not in sv:
        return "服务端没有 op=collapse 分支 —— 点了没反应（静默）"
    if "collapse_console" not in sv:
        return "服务端没调 inbox_logo.collapse_console —— 路由断了"
    dm = _src(_DAEMON_REL)
    if "_retire_mark" not in dm:
        return "守护进程没有展开退役钩子 —— 点哨标展开后会多出一枚寡妇哨标"
    return True


@check("N-FLO05 负控：把收缩钮从页面里拔掉 ⇒ 同一条判据必须判红")
def n_flo05():
    html = _page()
    dead = re.sub(r"<button class=\"collbtn\".*?</button>", "", html, flags=re.S)
    if dead == html:
        return "夹具不成立：页面里拔不出收缩钮，负控无分辨力"
    if re.search(r'<button class="collbtn".*?</button>', dead, re.S):
        return "负控失效：按钮拔除后仍匹配到 collbtn"
    return True


def main():
    print("=" * 78)
    print("0.49.0 收口判据 —— W-08 默认尺寸 · W-09 浮层逃逸 · U-17 图标动效 · "
          "U-18 哨标比例/不被裁 · B-02…B-08/B-13 冒泡 · FLO-01…FLO-05 漂浮哨标")
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
