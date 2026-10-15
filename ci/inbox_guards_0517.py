# SPDX-License-Identifier: Apache-2.0
"""0517 判据 —— Antinel 监理窗口「活得比调用方久」（daemon 委托开窗路径）。

背景（2026-10-14 创始人实测「起得来、活不久」）：
  `antinel inbox window` 如实报「已就位」，窗口随后消失。四路同机实证：
    · CLI Popen(CREATE_NO_WINDOW)      ⇒ 跨调用边界死
    · CLI Popen(DETACHED|NEW_GROUP)    ⇒ 跨调用边界死
    · CLI 经 cmd /c start              ⇒ 跨调用边界死
    · daemon（长命 supervise 进程）Popen ⇒ 跨边界**存活**
  ⇒ 病根不是"起法不对"，是"**谁来起**"：窗口必须由活得比它久的进程起。
  修法：`cmd_window` 先走 `open_console_via_daemon`（推托盘 open 动作，
  daemon 2s tick 消费后开窗），失败**如实降级**直起，不假装成功。

四件套（全部内存注入，不起真浏览器、不动真窗口）：
  W17-a   正：cmd_window 委托优先；daemon 路径失败 ⇒ 降级直起且不返回非零
  N-W17-a 负：同一把尺子 —— 跳过委托的变体必须判红（委托不是可选装饰）
  W17-b   正：via_daemon 协议 —— 推动作/通用后缀等窗/落位/回读取证；
           placed 只能由回读说了算
  N-W17-b 负：daemon 不开窗 ⇒ 必须 opened="none" + why 非空（失败不谎报）
  W17-c   连带：_DETACHED_FLAGS 在，两处起浏览器的 Popen 都用它；
           spawn_console（服务路径）的 DETACHED 不受影响
  W17-d   观测：运行态 direct read —— 服务/窗口实态如实留痕（无窗≠故障）
"""
import ast
import contextlib
import importlib.util
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

RESULTS = []


class Skip(Exception):
    """夹具凑不齐 ⇒ 这一条不判，也**不许判绿**。"""


def check(name):
    """判据必须真会红 —— 返回说明串一律转抛异常；SKIP 前缀转 Skip。"""
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
    """可观测：判定细节进 stdout（闸门运行输出即留证）。"""
    print("      · %s" % " ".join(str(x) for x in a))


def _load(name):
    """拿**产品真实 import 的那个模块对象**（进 sys.modules 的那个）。

    ★ 为什么不能用 spec_from_file_location 自命名加载：产品函数体内
      `import inbox_server as SV` 命中 sys.modules 里的真模块；判据若
      加载一份同名不同实例，patch 打在判据的副本上，产品跑的仍是真模块
      —— mock 形同虚设（实测踩过：判据因此真起了浏览器、真收了窗）。
    """
    return importlib.import_module(name)


SV = _load("inbox_server")
CLI = _load("inbox_cli")
WIN = _load("inbox_window")

_URL = "http://127.0.0.1:8790/?t=OX5MreAJH2aYj98rn3SyXSFonmX1MXDv"
_RECT = (2240, 1264, 720, 640)


class _NS(object):
    """argparse Namespace 的最小替身（cmd_window 只读 root）。"""

    def __init__(self, root=None):
        self.root = root


def _patch(mod, name, value):
    old = getattr(mod, name)
    setattr(mod, name, value)
    return old


@contextlib.contextmanager
def _patched(pairs):
    """pairs: [(module, attr, value)] —— 退出即还原（判据不许污染产品态）。"""
    olds = [_patch(m, n, v) for (m, n, v) in pairs]
    try:
        yield
    finally:
        for (m, n, _v), old in zip(pairs, olds):
            setattr(m, n, old)


# ═══════════════════════ W17-a：cmd_window 委托优先 + 诚实降级 ═══════════════════

@check("W17-a ★ cmd_window：daemon 委托优先；daemon 失败 ⇒ 降级直起且不卡用户")
def w17a():
    calls = {"ensure": 0, "via": 0, "settled": 0}

    def _ensure(root=None):
        calls["ensure"] += 1
        return {"url": _URL}, False

    def _via(url, root=None):
        calls["via"] += 1
        return {"opened": "app", "placed": True, "want": list(_RECT),
                "got": list(_RECT), "why": "daemon 开的窗已就位", "via": "daemon"}

    def _settled(url, root=None):
        calls["settled"] += 1
        return {"opened": "app", "placed": True, "want": list(_RECT),
                "got": list(_RECT), "why": "直起就位"}

    buf = io.StringIO()
    with _patched([(SV, "ensure_console", _ensure),
                   (SV, "open_console_via_daemon", _via),
                   (SV, "open_console_settled", _settled)]):
        with contextlib.redirect_stdout(buf):
            rc = CLI.cmd_window(_NS())
    if rc != 0:
        return "委托成功路径返回了非零（%r）—— 不卡用户的契约破了" % rc
    if calls["via"] != 1:
        return "daemon 委托没被调用（%r）—— 窗口又会挂在 CLI 进程树下" % calls
    if calls["settled"] != 0:
        return "委托成功时又走了直起（%r）—— 那是被沙箱杀的那条路" % calls
    if "已就位" not in buf.getvalue():
        return "成功路径没出声（可观测性退回）"

    # 臂②：daemon 路径失败 ⇒ 必须降级直起、仍返回 0（用户仍拿到窗口）
    calls.update({"via": 0, "settled": 0})

    def _via_none(url, root=None):
        calls["via"] += 1
        return {"opened": "none", "placed": False, "want": list(_RECT),
                "got": [], "why": "daemon 没开出窗口", "via": "daemon"}

    buf2 = io.StringIO()
    with _patched([(SV, "ensure_console", _ensure),
                   (SV, "open_console_via_daemon", _via_none),
                   (SV, "open_console_settled", _settled)]):
        with contextlib.redirect_stdout(buf2):
            rc2 = CLI.cmd_window(_NS())
    if rc2 != 0:
        return "降级路径返回了非零（%r）—— daemon 不在时用户被卡住" % rc2
    if calls["via"] != 1 or calls["settled"] != 1:
        return "降级路径没走 委托→直起（%r）" % calls
    _note("臂① 委托优先（settled 0 次）；臂② daemon 失败 ⇒ 降级直起、rc=0")
    return True


@check("N-W17-a 负控：跳过委托的变体（直起优先）必须判红 —— 同一把尺子")
def n_w17a():
    # 合成「修复前形状」的 cmd_window：直起优先、无委托。同一把尺子
    # （mock 三件套 + 输出断言）只换被测函数 ⇒ 必须红。
    def _bad_window(a):
        import inbox_server as SV
        rec, started = SV.ensure_console(root=getattr(a, "root", None))
        if not rec or not rec.get("url"):
            return 1
        rep = SV.open_console_settled(rec["url"])
        return 0

    calls = {"via": 0, "settled": 0}

    def _ensure(root=None):
        return {"url": _URL}, False

    def _via(url, root=None):
        calls["via"] += 1
        return {"opened": "app", "placed": True, "want": list(_RECT),
                "got": list(_RECT), "why": "x", "via": "daemon"}

    def _settled(url, root=None):
        calls["settled"] += 1
        return {"opened": "app", "placed": True, "want": list(_RECT),
                "got": list(_RECT), "why": "x"}

    buf = io.StringIO()
    with _patched([(SV, "ensure_console", _ensure),
                   (SV, "open_console_via_daemon", _via),
                   (SV, "open_console_settled", _settled)]):
        with contextlib.redirect_stdout(buf):
            rc = _bad_window(_NS())
    # 同一把尺子的判红条件：rc=0 但 settled 被调、via 没被调
    if not (rc == 0 and calls["settled"] == 1 and calls["via"] == 0):
        return ("负控失效：变异体没表现出「直起优先」形状（%r, rc=%r）"
                % (calls, rc))
    _note("变异体 settled=1/via=0、rc=0 —— 正是「窗口秒死」的病态形状")
    return True


# ═════════════════ W17-b：open_console_via_daemon 协议（同一把尺子） ══════════════

def _via_daemon_with(pushed, found, placed_ok=True, got_rect=None,
                     geo=None):
    """同一把尺子：mock 产品原语后跑真 `open_console_via_daemon`。

    pushed: 记录 push_action 调用；found: 每次枚举返回的句柄列表；
    placed_ok: place_all 返回的 ok；got_rect: 回读矩形（默认与目标一致）。
    """
    state = {"pushed": pushed, "found": found, "place_calls": 0}

    def _push(action, root=None):
        state["pushed"].append(action)
        return True

    def _find(run_id=None, **kw):
        # 协议要求：**不传 run_id**（通用后缀）—— daemon 开的窗 run_id 不同
        if run_id is not None:
            raise AssertionError("等窗必须用通用后缀（run_id 漂移实证）")
        return list(state["found"])

    def _geo(areas=None):
        return geo or {"ok": True, "rect": list(_RECT), "work": None}

    def _place(hwnds, rect, **kw):
        state["place_calls"] += 1
        return (placed_ok, "mock place")

    def _rect_of(h):
        return got_rect if got_rect is not None else list(_RECT)

    with _patched([(WIN, "console_geometry", _geo),
                   (WIN, "find_console_windows", _find),
                   (WIN, "place_all", _place),
                   (WIN, "window_rect_of", _rect_of)]):
        import inbox_tray as TR
        with _patched([(TR, "push_action", _push)]):
            rep = SV.open_console_via_daemon(_URL, wait_sec=1.5)
    return rep, state


@check("W17-b ★ via_daemon 协议：推动作＋通用后缀等窗＋落位＋回读取证")
def w17b():
    pushed, found = [], [4242]
    rep, st = _via_daemon_with(pushed, found)
    if rep.get("opened") != "app":
        return "窗口出现了却没报 opened=app：%r" % rep
    if pushed != ["open"]:
        return "没推托盘 open 动作（%r）—— daemon 无从开窗" % pushed
    if st["place_calls"] != 1:
        return "没落位（%r）—— 只开不搬，右下角问题复发" % st
    if rep.get("placed") is not True:
        return "回读一致却没判 placed：%r" % rep
    if tuple(rep.get("want") or ()) != _RECT:
        return "want 不是目标几何：%r" % rep.get("want")
    _note("pushed=%r place_calls=%d placed=%r" % (pushed, st["place_calls"],
                                                  rep.get("placed")))
    return True


@check("W17-b2 ★ placed 只能由**回读**说了算：place_all 说 ok、回读不一致 ⇒ 必须 False")
def w17b2():
    pushed, found = [], [4242]
    # place_all 返回 ok=True，但 window_rect_of 给出**另一个**矩形 ⇒ 谎报必须被抓
    rep, _st = _via_daemon_with(pushed, found, placed_ok=True,
                                got_rect=(40, 40, 720, 640))
    if rep.get("placed") is not False:
        return "place_all 说 ok 就判 placed —— 回读取证被跳过了（%r）" % rep
    if rep.get("got") != [[40, 40, 720, 640]]:
        return "got 没如实回写实测矩形：%r" % rep.get("got")
    _note("place_all ok=True 但回读 (40,40,720,640)≠目标 ⇒ placed=False")
    return True


@check("N-W17-b 负控：daemon 不开窗 ⇒ 必须 opened=none 且 why 非空（不谎报）")
def n_w17b():
    pushed, found = [], []
    rep, _st = _via_daemon_with(pushed, found)
    if rep.get("opened") != "none":
        return "窗口根本没出现却报 opened=%r —— 这正是今天的病型" % rep.get("opened")
    if not rep.get("why"):
        return "失败没有原因（静默降级 ＝ T-10）"
    if rep.get("placed") is not False:
        return "失败却判 placed：%r" % rep
    if pushed != ["open"]:
        return "失败路径没留推动作痕迹（%r）—— 复盘缺据" % pushed
    _note("daemon 不开窗 ⇒ opened=none, why=%r" % rep.get("why"))
    return True


# ═════════════════ W17-c：连带 —— 起浏览器的 Popen 必须带分离标志 ════════════════

@check("W17-c 连带：_DETACHED_FLAGS 在；两处起浏览器 Popen 都用它；spawn 不受影响")
def w17c():
    src = io.open(os.path.join(ROOT, "inbox_server.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    if not hasattr(SV, "_DETACHED_FLAGS"):
        return "_DETACHED_FLAGS 常量不见了 —— 起窗口又挂回调用方进程树"
    flags = SV._DETACHED_FLAGS
    if os.name == "nt" and not (flags & 0x00000008):
        return "_DETACHED_FLAGS 缺 DETACHED_PROCESS(0x8)：%#x" % flags
    if os.name == "nt" and not (flags & 0x00000200):
        return "_DETACHED_FLAGS 缺 CREATE_NEW_PROCESS_GROUP(0x200)：%#x" % flags
    # 所有起浏览器的 Popen（cmd 含 msedge/chrome 的）必须用 _DETACHED_FLAGS
    browser_popens = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Attribute)
                and node.func.attr == "Popen"):
            continue
        args = [a for a in node.args if isinstance(a, ast.Name)]
        if args and args[0].id == "cmd":
            for kw in node.keywords:
                if kw.arg == "creationflags":
                    val = kw.value
                    if (isinstance(val, ast.Name)
                            and val.id == "_DETACHED_FLAGS"):
                        browser_popens += 1
                    else:
                        return ("起浏览器的 Popen 用了别的 creationflags：%s"
                                % ast.dump(val)[:80])
    if browser_popens < 2:
        return ("起浏览器的 Popen 只找到 %d 处带 _DETACHED_FLAGS"
                "（console app 窗 + 冒泡窗应各一处）" % browser_popens)
    # 服务路径（spawn_console）的 DETACHED 仍在
    if "0x00000008 | _CREATE_NO_WINDOW" not in src:
        return "spawn_console 的 DETACHED 写法被改动 —— 服务路径回归风险"
    _note("browser Popen w/ _DETACHED_FLAGS: %d 处；spawn_console DETACHED 在位"
          % browser_popens)
    return True


# ═════════════════ W17-d：观测 —— 运行态 direct read（无窗≠故障） ═════════════════

@check("W17-d 观测：运行态 direct read —— 服务/窗口实态如实留痕（无窗≠故障）")
def w17d():
    """★ 语义修正（首版写错，2026-10-14）：「关窗不停服务」是**设计语义**
    ⇒ 服务在跑但无窗口 **不是**故障（用户有权关窗）。本条只做**观测**：
    窗口在 ⇒ 报矩形；不在 ⇒ SKIP 并说明；真正判红的只有一种情况——
    有桌面却连服务都没在听（保服务链路断了）。
    窗口「跨边界存活」的实证在探针留痕（四路对照 + 修复后复测），
    不塞进判据里让它在无窗环境误红。
    """
    import subprocess
    out = subprocess.run(["netstat", "-ano"], capture_output=True).stdout
    txt = out.decode("utf-8", "replace")
    listening = [ln for ln in txt.splitlines()
                 if "8790" in ln and "LISTENING" in ln]
    desktops = [1 for (_h, t) in WIN.enum_windows(visible_only=True) if t]
    hwnds = WIN.find_console_windows()
    if listening:
        _note("服务 8790 LISTENING ✓；窗口=%s" % (hwnds or "无（用户可能已关窗）"))
        if hwnds:
            for h in hwnds:
                r = WIN.window_rect_of(h)
                if r[2] < 200 or r[3] < 200:
                    return "窗口矩形异常（%r）—— 几何回读失败" % (r,)
                _note("  hwnd=%s rect=%s" % (h, r))
        elif desktops:
            raise Skip("SKIP: 服务在、窗口不在（关窗不停服务是设计语义，非故障）")
        else:
            raise Skip("SKIP: 无桌面枚举环境（CI）")
    else:
        if desktops:
            return "Antinel 监理服务（8790）没在听，但本会话有桌面 —— 保服务链路断了"
        raise Skip("SKIP: 无Antinel 监理服务且无桌面（CI 环境）")
    return True


def main():
    print("=" * 78)
    print("0517 判据 —— Antinel 监理窗口寿命：daemon 委托开窗（起得来，更要活得久）")
    print("（全部内存注入；负控同一把尺子只换输入；不碰真窗口/真浏览器）")
    print("=" * 78)
    ok = fail = skip = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True or why is None:
                why = ""
            print("  ✅ %-58s %s" % (name, why or ""))
            ok += 1
        except Skip as s:
            print("  ⏭️  %-58s %s" % (name, s))
            skip += 1
        except AssertionError as e:
            print("  ❌ %-58s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-58s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红 / %d 跳过" % (ok, fail, skip))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
