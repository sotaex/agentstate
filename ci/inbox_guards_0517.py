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

★★ 2026-10-18（创始人「点图标看不到、我真怕你」）—— 上面那条修法**只修了一半**：
  它解决了"窗口由谁开"，没解决"**daemon 根本不在**"。实测：daemon 不在时
  `open_console_via_daemon` 必然返回 none ⇒ 降级直起 ⇒ 窗口挂在短命 CLI 名下
  ⇒ 打印「已就位」而窗口几秒后消失（本机枚举：日志有「已就位」，窗口命中 0 个）。
  而**当时的 W17-a 臂② 恰恰把这条路断言为合格**（"降级直起且不返回非零"）。
  ⇒ 判据把已知会坏的路批成了合格，这是比缺判据更坏的形状。
  另有一处同族：`ensure_console` 用 `rec2 or rec` 兜底，没起来时拿**旧记录**
  冒充「已重拉」（本机连打 7 次「已重拉」，8790 一次都没听）。

四件套（全部内存注入，不起真浏览器、不动真窗口）：
  W17-a   正：cmd_window **先确保 daemon 在**再开窗；daemon 起不来 ⇒ 必须
           **出声说"活不过本命令"**在降级（静默降级判红）
  N-W17-a 负：同一把尺子 —— 跳过委托的变体必须判红（委托不是可选装饰）
  W17-b   正：via_daemon 协议 —— 推动作/通用后缀等窗/落位/回读取证；
           placed 只能由回读说了算
  N-W17-b 负：daemon 不开窗 ⇒ 必须 opened="none" + why 非空（失败不谎报）
  W17-c   连带：_DETACHED_FLAGS 在，两处起浏览器的 Popen 都用它；
           spawn_console（服务路径）的 DETACHED 不受影响
  W17-d   观测：运行态 direct read —— 服务/窗口实态如实留痕（无窗≠故障）
  W17-e   正：ensure_console 的**成功只由回读决定** —— spawn 走过但端口没起
           ⇒ 必须返回 None，不许拿旧记录冒充
  N-W17-e 负：把 `rec2 or rec` 兜底塞回一个同尺的变体 ⇒ 必须判红
  W17-f   正：ensure_daemon 的**成功只由回读决定** —— 没登记到 pid ⇒ alive=False
  N-W17-f 负：合成"spawn 即成功"的变体 ⇒ 必须判红
"""
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import tmpreg as _TMP   # 0.55.0 (F3): temp dir registry
import ast
import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import time

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


def _svc_port():
    """服务端口：**只读运行时真源** `~/.antinel/console/url.json`。

    ★★ 2026-10-19 实测（0.53.2）：W17-d 原先在 netstat 里写死 "8790"。而
      8790 被占用时产品会取一个空闲端口重新拉起（本机实测漂到 35089）——
      于是 daemon 明明在跑、服务明明在听，判据却报
      「守护进程在跑，服务（8790）却没在听 —— supervise 链路断了」。
      这是**量具自己在编事实**：本仓纪律早就写着「活体回读的 URL/端口
      只读 `~/.antinel/console/url.json`，仓内 console/url.json 是旧缓存」，
      判据却没照做。读不到真源才回落 8790（默认端口，保持旧行为）。
    """
    import io as _io
    import json as _json
    import os as _os
    p = _os.path.expanduser("~/.antinel/console/url.json")
    try:
        with _io.open(p, encoding="utf-8") as f:
            port = int((_json.load(f) or {}).get("port") or 0)
        if port > 0:
            return port
    except Exception:                                          # noqa: BLE001
        pass
    return 8790


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

@check("W17-a ★ cmd_window：**先确保 daemon 在**再开窗；daemon 起不来必须出声（不许静默降级）")
def w17a():
    calls = {"ensure": 0, "daemon": 0, "via": 0, "settled": 0}

    def _ensure(root=None):
        calls["ensure"] += 1
        return {"url": _URL}, False

    def _daemon_ok(root=None):
        calls["daemon"] += 1
        return True, 4242, False, "已在跑"

    def _daemon_bad(root=None):
        calls["daemon"] += 1
        return False, None, True, "拉不起来：6.0 秒内没登记到守护进程"

    def _via(url, root=None):
        calls["via"] += 1
        return {"opened": "app", "placed": True, "want": list(_RECT),
                "got": list(_RECT), "why": "daemon 开的窗已就位", "via": "daemon"}

    def _settled(url, root=None):
        calls["settled"] += 1
        return {"opened": "app", "placed": True, "want": list(_RECT),
                "got": list(_RECT), "why": "直起就位"}

    buf = io.StringIO()
    with _patched([(SV, "ensure_daemon", _daemon_ok),
                   (SV, "ensure_console", _ensure),
                   (SV, "open_console_via_daemon", _via),
                   (SV, "open_console_settled", _settled)]):
        with contextlib.redirect_stdout(buf):
            rc = CLI.cmd_window(_NS())
    if rc != 0:
        return "委托成功路径返回了非零（%r）—— 不卡用户的契约破了" % rc
    if calls["daemon"] != 1:
        return ("开窗前**没检查守护进程**（ensure_daemon 调用 %d 次）—— "
                "daemon 不在时窗口只能由 CLI 直起，命令一退就死" % calls["daemon"])
    if calls["via"] != 1:
        return "daemon 委托没被调用（%r）—— 窗口又会挂在 CLI 进程树下" % calls
    if calls["settled"] != 0:
        return "委托成功时又走了直起（%r）—— 那是被沙箱杀的那条路" % calls
    if "已就位" not in buf.getvalue():
        return "成功路径没出声（可观测性退回）"

    # 臂②：daemon 在、但开窗失败 ⇒ 必须降级直起、仍返回 0（用户仍拿到窗口）
    calls.update({"via": 0, "settled": 0, "daemon": 0})

    def _via_none(url, root=None):
        calls["via"] += 1
        return {"opened": "none", "placed": False, "want": list(_RECT),
                "got": [], "why": "daemon 没开出窗口", "via": "daemon"}

    buf2 = io.StringIO()
    with _patched([(SV, "ensure_daemon", _daemon_ok),
                   (SV, "ensure_console", _ensure),
                   (SV, "open_console_via_daemon", _via_none),
                   (SV, "open_console_settled", _settled)]):
        with contextlib.redirect_stdout(buf2):
            rc2 = CLI.cmd_window(_NS())
    if rc2 != 0:
        return "降级路径返回了非零（%r）—— daemon 不在时用户被卡住" % rc2
    if calls["via"] != 1 or calls["settled"] != 1:
        return "降级路径没走 委托→直起（%r）" % calls

    # 臂③ ★ 0.53.0 新增：**daemon 起不来** ⇒ 可以降级（不卡人），但必须
    #   **出声**说清"这个窗口活不过本命令"。静默降级 = 让用户以为常驻了。
    calls.update({"via": 0, "settled": 0, "daemon": 0})
    err3 = io.StringIO()
    with _patched([(SV, "ensure_daemon", _daemon_bad),
                   (SV, "ensure_console", _ensure),
                   (SV, "open_console_via_daemon", _via_none),
                   (SV, "open_console_settled", _settled)]):
        with contextlib.redirect_stderr(err3), contextlib.redirect_stdout(io.StringIO()):
            rc3 = CLI.cmd_window(_NS())
    if calls["daemon"] != 1:
        return "臂③：ensure_daemon 没被调用（%r）" % calls
    if rc3 != 0:
        return "臂③：daemon 起不来就把用户卡死（rc=%r）—— 必须降级且不卡人" % rc3
    if calls["settled"] != 1:
        return "臂③：daemon 起不来时也没直起（%r）—— 用户什么窗口都拿不到" % calls
    _e3 = err3.getvalue()
    if "活不过本命令" not in _e3:
        return ("臂③：daemon 起不来却**没告诉用户窗口会死**（stderr=%r）—— "
                "「已就位」和「窗口秒死」又能同时成立了" % _e3[:120])
    _note("臂① 先确保 daemon（1 次）再委托；臂② 委托失败降级直起 rc=0；"
          "臂③ daemon 起不来 ⇒ 明确告警「活不过本命令」")
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
    with _patched([(SV, "ensure_daemon", lambda root=None: (True, 1, False, "在")),
                   (SV, "ensure_console", _ensure),
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

# ══════════ W17-e/f：**成功只由回读决定**（报成功不许由「走了哪个分支」决定） ══════════
#
# 这一组守的不是某一行代码，是**一族病**：
#   `ensure_console` 旧实现 `rec2 or rec` ⇒ spawn 走过就还记录 ⇒ 调用方打印
#   「已重拉」而端口没开；`ensure_daemon` 若写成"spawn 回来就算成功"同型。
# 本机实测（2026-10-18）：`console.log` 连打 7 次「已重拉」，`netstat` 里
# 8790 一次都没出现过；日志写「已就位」，枚举窗口命中 0 个。两句话都在撒谎，
# 而当时所有判据都是绿的 —— 因为判据问的是"重拉了没有"，不是"起来了没有"。

def _stale_record_hub(prefix):
    """造一个「记录在、服务不在」的中枢：登记 pid 是个死号，端口不绑。"""
    hub = _TMP.tmpdir(prefix=prefix)
    SV.write_console_record(8799, "TOK-STALE", pid=999999, root=hub)
    return hub


def _ensure_readback_core(impl):
    """尺子：喂一个**什么都不做**的 spawner，要求「没起来」被如实返回。"""
    hub = _stale_record_hub("g0517_w17e_")
    try:
        rec, started = impl(root=hub, spawner=lambda *a: None, wait_sec=1.0)
    except Exception as e:                                  # noqa: BLE001
        return "调用崩了：%s: %s" % (type(e).__name__, e)
    if rec is not None:
        return ("服务没起来，却还回了记录（url=%r）—— 调用方会打印「已重拉」，"
                "而端口根本没开" % ((rec or {}).get("url"),))
    if started is not True:
        return "没走重拉分支（started=%r）—— 场景没构造对" % (started,)
    return True


@check("W17-e ★ ensure_console：spawn 走过但端口没起 ⇒ 必须返回 None（不许拿旧记录冒充）")
def w17e():
    r = _ensure_readback_core(SV.ensure_console)
    if r is not True:
        return r
    _note("假 spawner（什么都不做）⇒ rec=None：不拿旧记录充「已重拉」")
    return True


@check("N-W17-e 负控：把 `rec2 or rec` 兜底塞进同尺变体 ⇒ W17-e 必须红")
def n_w17e():
    def _old_ensure(root=None, spawner=None, wait_sec=1.0, port=8790):
        """**旧形状**（0.48.5→0.53.0 的实现）。不是缓存，是负控标本。"""
        alive, rec, _why = SV.console_status(root)
        if alive:
            return rec, False
        want_port = int((rec or {}).get("port") or port)
        want_tok = (rec or {}).get("token") or "TOK"
        (spawner or SV.spawn_console)(want_port, want_tok, root)
        time.sleep(min(float(wait_sec), 1.0))
        _a, rec2, _w = SV.console_status(root)
        return (rec2 or rec), True                  # ← 病灶：以旧充新

    r = _ensure_readback_core(_old_ensure)
    if r is True:
        return "负控失效：旧形状（rec2 or rec）在同一把尺子上被判绿 —— 尺子是摆设"
    _note("旧形状同尺判红：%s" % str(r)[:80])
    return True


def _daemon_readback_core(impl):
    """尺子：喂一个什么都不做的 spawner，要求「没登记到 pid」被如实返回。"""
    hub = _TMP.tmpdir(prefix="g0517_w17f_")
    try:
        alive, pid, started, why = impl(root=hub, spawner=lambda *a: None,
                                        wait_sec=0.6)
    except Exception as e:                                  # noqa: BLE001
        return "调用崩了：%s: %s" % (type(e).__name__, e)
    if alive:
        return "守护进程没登记到 pid，却报 alive=True（pid=%r）" % (pid,)
    if not why:
        return "没给原因（why 为空）—— 调用方无法出声"
    if started is not True:
        return "没走重拉分支（started=%r）—— 场景没构造对" % (started,)
    return True


@check("W17-f ★ ensure_daemon：spawn 走过但没登记到 pid ⇒ 必须 alive=False")
def w17f():
    r = _daemon_readback_core(SV.ensure_daemon)
    if r is not True:
        return r
    _note("假 spawner ⇒ alive=False，原因如实返回（调用方据此出声）")
    return True


@check("N-W17-f 负控：合成「spawn 即成功」的变体 ⇒ W17-f 必须红")
def n_w17f():
    def _spawn_is_success(root=None, spawner=None, wait_sec=0.6):
        (spawner or SV.spawn_daemon)(root)
        return True, 1234, True, "已重拉"            # ← 病灶：分支即成功

    r = _daemon_readback_core(_spawn_is_success)
    if r is True:
        return "负控失效：「spawn 即成功」的变体被判绿 —— 尺子是摆设"
    _note("旧形状同尺判红：%s" % str(r)[:80])
    return True


#: 窗口几何的最小合理尺寸（像素）。小于它 ⇒ 这不是一枚**在屏上**的监理窗。
#: ★ 提到模块级：正判据与负控读**同一个数**（本仓铁律 8，不许各写一份）。
_W17D_MIN_SIDE = 200


def _rect_problem(rect, on_screen):
    """纯函数（正判据与负控共用同一把尺子）：几何回读有问题 ⇒ 返回人读串。

    `on_screen` 取 `inbox_window.is_window_on_screen()` 的语义：
      · False ⇒ **最小化或不在屏上**：Windows 这时给的是图标占位矩形
        `(-32000,-32000,160,28)`，拿它判「几何坏了」就是把用户的正常动作
        判成缺陷 ⇒ **不判**（返回 None）。
      · None  ⇒ 判不出（取不到窗口）：不当成通过，按「取不到矩形」处理。
      · True  ⇒ 真在屏上：宽高都必须 ≥ `_W17D_MIN_SIDE`。
    """
    if on_screen is False:
        return None
    if not rect or len(rect) < 4:
        return "取不到窗口矩形（%r）—— 几何回读失败" % (rect,)
    if rect[2] < _W17D_MIN_SIDE or rect[3] < _W17D_MIN_SIDE:
        return ("窗口矩形异常（%r）—— 几何回读失败（在屏窗宽高应 ≥ %d）"
                % (tuple(rect), _W17D_MIN_SIDE))
    return None


@check("W17-d 观测：运行态 direct read —— 服务/窗口实态如实留痕（无窗≠故障）")
def w17d():
    """★ 语义修正（首版写错，2026-10-14）：「关窗不停服务」是**设计语义**
    ⇒ 服务在跑但无窗口 **不是**故障（用户有权关窗）。本条只做**观测**：
    窗口在 ⇒ 报矩形；不在 ⇒ SKIP 并说明；真正判红的只有一种情况——
    有桌面却连服务都没在听（保服务链路断了）。
    窗口「跨边界存活」的实证在探针留痕（四路对照 + 修复后复测），
    不塞进判据里让它在无窗环境误红。

    ★★ 2026-10-19（0.53.1 出包实测）：**最小化不许判红**。
      窗口最小化时 Windows 给的是图标占位矩形 `(-32000,-32000,160,28)`，
      旧实现只问「宽或高 < 200」⇒ 判「几何回读失败」⇒ **把用户的正常动作
      判成了缺陷**。而这恰恰是本产品的**前置动作**：先最小化/收缩，才看得见
      漂浮哨标 —— 用户天天都会做。⇒ 先问 `is_window_on_screen()`
      （产品真源：可见 **且** 没被最小化），最小化就**不判几何**、只留痕；
      只要还有一枚真在屏上的窗，几何照判。
    """
    import subprocess
    out = subprocess.run(["netstat", "-ano"], capture_output=True).stdout
    txt = out.decode("utf-8", "replace")
    port = _svc_port()
    listening = [ln for ln in txt.splitlines()
                 if (":%d" % port) in ln and "LISTENING" in ln]
    desktops = [1 for (_h, t) in WIN.enum_windows(visible_only=True) if t]
    hwnds = WIN.find_console_windows()
    if listening:
        _note("服务 %d LISTENING ✓；窗口=%s" % (port, hwnds or "无（用户可能已关窗）"))
        if hwnds:
            on_screen = []
            for h in hwnds:
                why = _rect_problem(WIN.window_rect_of(h),
                                    WIN.is_window_on_screen(h))
                if why:
                    return why
                if WIN.is_window_on_screen(h) is False:
                    _note("  hwnd=%s 最小化/不在屏上（图标占位矩形）⇒ 几何不判" % h)
                else:
                    on_screen.append(h)
                    _note("  hwnd=%s rect=%s" % (h, WIN.window_rect_of(h)))
            if not on_screen:
                raise Skip("SKIP: 窗口都在最小化态（用户主动收起，几何无从回读；"
                           "收缩后应出现漂浮哨标）")
        elif desktops:
            raise Skip("SKIP: 服务在、窗口不在（关窗不停服务是设计语义，非故障）")
        else:
            raise Skip("SKIP: 无桌面枚举环境（CI）")
    else:
        # ★★ 0.53.0：**区分「用户没启动」与「链路断了」**。
        #   旧实现「有桌面却没服务 ⇒ 判红」把**环境态**混进了代码门禁：
        #   用户没开监理时，任何提交都会被拦 —— 与 byte-budget 那条纪律
        #   （环境态的项不许进 pass/fail 分母）是同一件事。
        #   准确判据：**daemon 在跑、服务却没起** ⇒ supervise 链路真断了（红）；
        #   daemon 也不在 ⇒ 用户压根没启动，SKIP 并说明。
        import inbox_daemon as DM
        d_alive, _dpid = DM.daemon_alive()
        if d_alive:
            return ("守护进程在跑，服务（%d）却没在听 —— supervise 链路断了"
                    % port)
        raise Skip("SKIP: 服务没在听且守护进程未在跑（用户没启动监理，非链路故障）")
    return True


@check("N-W17-d 负控：最小化占位矩形不许判红；真在屏的小窗仍必须判红")
def n_w17d():
    """同一把尺子（`_rect_problem`）换输入，证明三件事：

    ① **最小化** `(-32000,-32000,160,28)` ＋ `on_screen=False` ⇒ 不判红
       （这是用户的正常动作，也是哨标的前置动作）；
    ② 同一枚矩形若 `on_screen=True`（谎报在屏）⇒ **仍判红** —— 豁免只跟
       真源 `is_window_on_screen()` 走，不跟矩形长相走，没法靠形状骗过去；
    ③ 真在屏的小窗（如 160×28 的畸形窗）⇒ 判红，断言强度没被这条豁免吃掉。
    """
    iconic = (-32000, -32000, 160, 28)
    if _rect_problem(iconic, False) is not None:
        return "负控失效：最小化占位矩形被判红了 —— 用户收起窗口就会被拦"
    if _rect_problem(iconic, True) is None:
        return ("负控失效：同一枚矩形在**谎报在屏**时也放过了 —— 豁免跟着矩形"
                "形状走而不是跟着真源走，可以靠形状骗过去")
    if _rect_problem((100, 100, 160, 28), True) is None:
        return "负控失效：真在屏的小窗（160×28）被放过 —— 断言强度被豁免吃掉了"
    if _rect_problem((100, 100, 1200, 800), True) is not None:
        return "负控失效：正常窗口（1200×800）被判红 —— 尺子过宽，会压正常态"
    return True


# ---------------------------------------------------------------------------
# 0.57.3 —— **改了代码就换血**（2026-10-27 创始人「体检修好了吗，还是老样子」）
# ---------------------------------------------------------------------------
# ★ 这一族为什么必须常驻守：那天代码 06:19 落盘、服务是**前一晚 21:32** 起的，
#   页面永远是旧的，而**页面不会说自己旧**。出包闸门 34 套全绿也救不了 ——
#   闸门验的是**文件**，不是**活体**；用户唯一的读数就是屏幕。
# ★ 每条都配负控，因为这个族最危险的两种退法都很"安静"：
#   ① 戳里混进会自己变的量（模块件数）⇒ 每 20–30 秒自我重启。**这不是假想**：
#      2026-10-27 07:08 我自己的第一版就这么写，本机实测连换 3 次后触发限流才停手。
#   ② 修法文案退回「重启一次即可：antinel inbox window」—— 那条命令是**幂等**的，
#      服务活着就只说「已在跑」，**永远不换血**。用户照着做，看到的老样子不变。
#      （与 0.53.2 同族：那次给的是**不存在的命令**，这次是**存在但无效的命令**。）


class _FakeHTTPD(object):
    """只看"有没有被叫去关" —— 判据不对真 httpd 下手。"""

    def __init__(self):
        self.down = 0

    def shutdown(self):
        self.down += 1


#: 夹具模块名计数 —— 每次造夹具用一个**从没用过**的名字。
#   ★★ 为什么必须唯一：`importlib.import_module("ar_mod")` 命中 `sys.modules`
#      就直接返回**上一个 tmpdir 里的那个**，新目录的 sys.modules 腿因此恒为空
#      ⇒ 判据要么报"空集"、要么在空集上打转（看起来像夹具没生效，其实是缓存在骗人）。
_AR_SEQ = {"n": 0}


def _ar_tree():
    """造一个"假包根"：一个**已 import** 的模块 ＋ hooks/ ＋ rules/。

    ★ 模块必须真的进 `sys.modules`：`_code_files` 的面就是 sys.modules，
      拿 `spec_from_file_location` 造一个不进 sys.modules 的实例，那条腿恒为空集
      ⇒ 判据会在"什么都没测到"的情况下判绿（假绿第三族）。
    返回 `(目录, 模块文件, 模块名)`。
    """
    _AR_SEQ["n"] += 1
    mod = "ar_mod_%d" % _AR_SEQ["n"]
    d = _TMP.tmpdir("antinel-ar-")
    foo = os.path.join(d, mod + ".py")
    with open(foo, "w", encoding="utf-8", newline="\n") as f:
        f.write("X = 1\n")
    if d not in sys.path:
        sys.path.insert(0, d)
    importlib.import_module(mod)
    os.makedirs(os.path.join(d, "hooks"), exist_ok=True)
    os.makedirs(os.path.join(d, "rules"), exist_ok=True)
    return d, foo, mod


def _ar_daemon(d):
    """把 daemon.pid 写成**本进程 pid**：`daemon_alive` 见 pid==自己 ⇒ 真。

    ★ 不用假 patch：`_supervisor_present` 走的是真 `inbox_daemon.daemon_alive`，
      判据必须喂它真输入，否则测的是判据自己的模型（假绿第九族）。
    """
    cdir = os.path.join(d, "console")
    os.makedirs(cdir, exist_ok=True)
    with open(os.path.join(cdir, "daemon.pid"), "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))


def _ar_sleep(foo, base):
    """第一次"睡"就把模块弄新 —— 模拟"人刚改了代码"。"""
    box = {"n": 0}

    def _s(_sec):
        box["n"] += 1
        if box["n"] == 1:
            os.utime(foo, (base + 1000, base + 1000))
    return _s


def _r57a_body():
    """R-57a 的**判据体**（抽成命名函数：负控要能换掉同一实现）。

    ★ 这里**不许**对戳做数值运算（`s1 > 0` 之类）：负控喂进来的变异体返回的是
      二元组，一比较就 TypeError ⇒ 判据"红"了，但红的原因是**崩了**，不是
      "抓住件数混进比较口径"。那种红是**假的分辨力**（红的理由不对＝量具打偏）。
      所以只用两种与类型无关的判据：**非空**（真读到文件了）＋ **两次相等**。
    """
    d, foo, mod = _ar_tree()
    t0 = os.path.getmtime(foo)
    files1 = SV._code_files(d)
    s1 = SV._code_stamp(d)
    if not files1:
        return "空集：一个文件都没读进来 —— 这条判据什么也没测到"
    bar_mod = mod + "_bar"
    bar = os.path.join(d, bar_mod + ".py")
    with open(bar, "w", encoding="utf-8", newline="\n") as f:
        f.write("Y = 2\n")
    os.utime(bar, (t0, t0))            # 故意更旧：件数变、最新 mtime 不变
    n1 = len(SV._code_files(d))
    importlib.import_module(bar_mod)
    n2 = len(SV._code_files(d))
    s2 = SV._code_stamp(d)
    _note("files %d -> %d，stamp %s -> %s" % (n1, n2, s1, s2))
    if n2 != n1 + 1:
        return "夹具没生效：件数没变（%d -> %d）—— 判据在测空气" % (n1, n2)
    if s2 != s1:
        return ("懒加载多一件就把戳弄脏了（%s → %s）—— 服务会因此每 20 秒自我"
                "重启，连换几次后触发限流停手" % (s1, s2))
    return True


@check("R-57a 戳只认 mtime：懒加载多一件不许弄脏戳")
def r57a():
    return _r57a_body()


@check("N-57a 负控：戳里混回件数 ⇒ R-57a 必红")
def n57a():
    import inspect as _insp
    import textwrap as _tw
    real = SV._code_stamp
    src = _tw.dedent(_insp.getsource(real))
    anchor = "    return round(newest, 6)"
    if anchor not in src:
        return ("SKIP 变异锚点不在了（源码改过）—— 先更新本判据锚点：`%s`"
                % anchor.strip())
    mut = src.replace(
        anchor,
        "    return (round(newest, 6), len(_code_files(root)))")
    ns = {}
    exec(compile(mut, "<mutant:_code_stamp>", "exec"), SV.__dict__, ns)
    SV._code_stamp = ns["_code_stamp"]
    try:
        r = _r57a_body()
    finally:
        SV._code_stamp = real
    if r is True:
        return ("负控失效：把件数混回戳以后 R-57a 仍然绿 —— 防循环那条腿是假的"
                "（这正是 07:08 真实发生过的那次自我重启）")
    _note("变异体被判红：%s" % str(r)[:70])
    return True


@check("R-57b 没人拉我起来 ⇒ 绝不自退（宁可看旧页面）")
def r57b():
    d, foo, mod = _ar_tree()
    h = _FakeHTTPD()
    base = SV._code_stamp(d)
    out = SV._auto_reload_loop(h, base, root=d, interval=0,
                               sleep=_ar_sleep(foo, base))
    if h.down:
        return ("没有守护进程时它仍然退出了 —— 前台跑 antinel inbox serve 的"
                "用户会得到一张空页面，比看到旧页面糟得多")
    if out != "no-supervisor":
        return "结局不对：%r（应为 no-supervisor）" % (out,)
    return True


@check("R-57c 有守护进程 ⇒ 优雅退恰一次（端口口令由它沿用）")
def r57c():
    d, foo, mod = _ar_tree()
    _ar_daemon(d)
    ok, why = SV._supervisor_present(d)
    if not ok:
        return "夹具没生效：写了 daemon.pid 仍判没人管（%s）" % (why,)
    h = _FakeHTTPD()
    base = SV._code_stamp(d)
    out = SV._auto_reload_loop(h, base, root=d, interval=0,
                               sleep=_ar_sleep(foo, base))
    if out != "reload":
        return "结局不对：%r（应为 reload）" % (out,)
    if h.down != 1:
        return "shutdown 被调了 %d 次（应恰 1 次）" % h.down
    return True


@check("R-57d 换太勤 ⇒ 停手（不把机器拖进循环）")
def r57d():
    d, foo, mod = _ar_tree()
    _ar_daemon(d)
    for _i in range(SV.RELOAD_MAX_IN_WINDOW):
        SV._reload_record(d, SV._code_stamp(d), kind="reload")
    ok, why = SV._reload_budget(d)
    if ok:
        return "限流没生效：已记 %d 次仍说能换" % SV.RELOAD_MAX_IN_WINDOW
    _note("限流理由：%s" % why)
    h = _FakeHTTPD()
    base = SV._code_stamp(d)
    out = SV._auto_reload_loop(h, base, root=d, interval=0,
                               sleep=_ar_sleep(foo, base))
    if out != "throttled" or h.down:
        return "限流后仍在动：out=%r down=%d" % (out, h.down)
    return True


@check("R-57e 代码没变 ⇒ 不退（对照腿：不是「必然退」）")
def r57e():
    import threading as _th
    d, foo, mod = _ar_tree()
    _ar_daemon(d)
    h = _FakeHTTPD()
    stop = _th.Event()
    base = SV._code_stamp(d)
    out = SV._auto_reload_loop(h, base, root=d, interval=0,
                               sleep=lambda _s: stop.set(), stop=stop)
    if out != "stopped" or h.down:
        return "代码没变却退了：out=%r down=%d" % (out, h.down)
    return True


def _r57f_body():
    """R-57f 的判据体。返回 True 或问题串。"""
    hint = SV._restart_hint({"port": 2559,
                             "url": "http://127.0.0.1:2559/?t=x",
                             "pid": 4242})
    txt = hint[1]
    bad = []
    if "结束" not in txt:
        bad.append("没说要先结束旧进程")
    if "4242" not in txt:
        bad.append("没给出要结束的那个 pid")
    if "重启一次即可" in txt:
        bad.append("退回了「重启一次即可：antinel inbox window」—— 那条命令是幂等的")
    if "已在跑" not in txt:
        bad.append("没警告「不先结束，第②步只会说已在跑」")
    if bad:
        return "；".join(bad)
    return True


@check("R-57f 换血清单必须写「先结束、再开」两步")
def r57f():
    return _r57f_body()


@check("N-57f 负控：文案退回旧版 ⇒ R-57f 必红")
def n57f():
    real = SV._restart_hint

    def _old(rec, pid=None):
        if isinstance(rec, dict) and ("port" in rec or "url" in rec):
            return ("监理服务", "重启一次即可：antinel inbox window")
        return real(rec, pid)

    SV._restart_hint = _old
    try:
        r = _r57f_body()
    finally:
        SV._restart_hint = real
    if r is True:
        return ("负控失效：退回旧文案后 R-57f 仍然绿 —— 文案腿是假的"
                "（旧文案照做不会换血，用户会认定整个自检是坏的）")
    _note("变异体被判红：%s" % str(r)[:70])
    return True


# ══════════════════════════════════════════════════════════════════════════
# R-58 族：**存活判定的三条根因**（0.59.0，2026-10-27 创始人「上古的冒泡又复发了」）
#
# 症状：右下角每 30–45 分钟冒一次泡，连续五天。链上读数：
#   · `notice_log.jsonl` 里 `host_shield_tamper` / `host_shield_revived` 成对出现；
#   · `sidecar/` 里躺着 903 条心跳、697 条 `host_shield_revived`；
#   · `lock_events.jsonl` 单日 `acq_timeout` 4622 次。
#
# 根因三条（都不是"没打心跳"，是**读的人看错了地方 / 读坏了当成了事实**）：
#   ① 心跳只进审计链；链锁抢不到就落 `sidecar/`，而读心跳只扫顶层
#      ⇒ 活哨兵被判"37 分钟没心跳" ⇒ 杀掉重拉 ⇒ `revived`(critical) ⇒ 冒泡。
#   ② 主循环用 `load_state()` 读状态，它在读失败时**编一个"已撤防"**
#      ⇒ 那一拍被记成 `host_shield_tamper`（文案里的「实际值（None）」就是铁证：
#      None 不是任何人的写入值，是"这份 state 里根本没有 enabled"）。
#   ③ "该不该弹"有唯一真源 `bubble_decision`，但只守气泡通道；toast 通道
#      从来没人问过它 ⇒ 同一条 `revived` 在气泡通道被压掉、在 toast 通道照响。
#
# 三条判据各配一条负控：把修法换回旧口径，这条判据**必须**变红。
# ══════════════════════════════════════════════════════════════════════════


def _r58_audit(tag):
    """一个空审计目录（链里一条记录都没有）。"""
    return _TMP.tmpdir("antinel-r58%s-" % tag)


def _r58_hs_mut(old, new):
    """把 host_shield.py 读进来、换掉一处，返回**变异后的模块对象**。

    ★ 用真源码改，不用"照着写一份"：后者测的是判据作者的想象，不是产品行为
      （假绿第九族）。锚点必须唯一，对不上就返回 None 由判据判红。
    """
    p = os.path.join(ROOT, "host_shield.py")
    with io.open(p, encoding="utf-8") as f:
        src = f.read()
    if src.count(old) != 1:
        return None
    ns = {"__name__": "hs_r58_mut"}
    exec(compile(src.replace(old, new), p, "exec"), ns)
    return ns


@check("R-58a 心跳信标：链里一条记录都没有，也要说得出「它还活着」")
def r58a():
    HS = _load("host_shield")
    d = _r58_audit("a")
    if [f for f in os.listdir(d) if f.endswith(".jsonl")]:
        return "夹具不成立：这个目录里居然有链文件 —— 那这条判据可能在读链"
    if not HS.write_heartbeat_beacon(d, 4242):
        return "信标写不进去 ⇒ 链锁被抢时「还活着」这句话就说不出口了"
    age, ts = HS._heartbeat_age_in(d)
    if age is None:
        return "信标已经写了，却读不到心跳（age=None）—— 修法等于没装"
    if age > 60:
        return "刚写的信标却报 %.0f 秒前，时钟口径不对" % age
    _note("链 0 条 ＋ 只有信标 ⇒ age=%.1fs ts=%s" % (age, ts))
    return True


@check("N-58a 负控：读心跳若忽略信标 ⇒ R-58a 必红（不是信标恰好没用）")
def n58a():
    old = ("    _b_ts = read_heartbeat_beacon(d)\n"
           "    if _b_ts and (best_ts is None or _ts_newer(_b_ts, best_ts)):\n"
           "        best_ts = _b_ts\n")
    ns = _r58_hs_mut(old, "")          # ← 拆掉信标那一支（＝修之前的读法）
    if ns is None:
        return "变异锚点没找到（唯一性不成立）—— 判据失明，不许判绿"
    d = _r58_audit("na")
    ns["write_heartbeat_beacon"](d, 4242)
    age, _ = ns["_heartbeat_age_in"](d)
    if age is not None:
        return ("拆掉信标后仍读得到心跳（age=%r）⇒ 说明 R-58a 的绿与信标无关，"
                "这条判据没有分辨力" % (age,))
    _note("拆掉信标那一支后 age=None（正是五天里误杀活哨兵的那个读数）")
    return True


@check("R-58b 读不到≠被撤防：坏读一律不许拿去和链比")
def r58b():
    HS = _load("host_shield")
    bad = [None, {}, {"enabled": None}, {"enabled": "true"}, {"workspaces": {}},
           []]
    for st in bad:
        if HS._state_gate(st) is not False:
            return "坏读被判成「可以比」：%r —— 它会被记成篡改" % (st,)
    for st in ({"enabled": True}, {"enabled": False}):
        if HS._state_gate(st) is not True:
            return "正常状态被判成不可比：%r（真撤防也要比）" % (st,)
    _note("坏读 6 种全 False；正常 2 种 True（含真撤防）")
    return True


@check("N-58b 负控：拆掉这道闸 ⇒ 同一份坏读立刻变成「发散」")
def n58b():
    old = ('return isinstance(state, dict) and isinstance(state.get("enabled"), bool)')
    ns = _r58_hs_mut(old, "return True   # ← 旧口径变异体")
    if ns is None:
        return "变异锚点没找到（唯一性不成立）—— 判据失明"
    forged = {"enabled": None}
    diverged = (ns["_state_gate"](forged) is True) and (bool(forged.get("enabled")) is not True)
    if not diverged:
        return "拆掉闸之后没有出现「发散」—— 负控没咬住，R-58b 的绿是空的"
    HS = _load("host_shield")
    if HS._state_gate(forged) and bool(forged.get("enabled")) is not True:
        return "新口径下同一份坏读仍进入发散分支"
    _note("旧口径：坏读→发散→假 tamper；新口径：不进分支")
    return True


@check("R-58c 一把尺子：自愈事件不走 toast，真篡改照样走")
def r58c():
    M = _load("inbox_model")
    D = _load("inbox_daemon")

    def item(kind, recovered=False, severity="critical"):
        return M.Item(alert=M.Alert(id="r58" + kind[-3:], ts="2026-10-27T10:00:00+08:00",
                                    level="L1", kind=kind, recovered=recovered,
                                    severity=severity))
    cases = [
        (item("host_shield_revived"), False, "自愈（已自动重启）"),
        (item("host_shield_tamper", recovered=True), False, "已自愈"),
        (item("host_shield_tamper", recovered=False), True, "真篡改必须敲门"),
        (item("host_shield_zone_locked", severity="warning"), False, "常规执法"),
        (item("host_shield_heartbeat", severity="none"), True, "非告警类不归它管"),
    ]
    for it, want, why in cases:
        got, w = D._should_knock(it)
        if bool(got) is not bool(want):
            return "%s：期望敲门=%s，实际=%s（%s）" % (why, want, got, w)
    _note("5 条路由全对（2 条不敲门、3 条敲门，含真篡改的对照腿）")
    return True


@check("N-58c 负控：把尺子拆掉（永远敲门）⇒ 同一张路由表必红")
def n58c():
    # ★ 负控必须**咬同一张表**：用真源码变异出一个"永远敲门"的 `_should_knock`，
    #   再把 R-58c 那 5 条路由原样喂给它，至少有一条必须对不上。
    #   （只断言"变异体返回 True"是自证 —— 那种负控不会红，等于没有。）
    p = os.path.join(ROOT, "inbox_daemon.py")
    with io.open(p, encoding="utf-8") as f:
        src = f.read()
    anchor = "    return HS.bubble_decision(it.kind, rec)"
    if src.count(anchor) != 1:
        return "变异锚点没找到（出现 %d 次）—— 判据失明" % src.count(anchor)
    ns = {"__name__": "dm_r58_mut"}
    exec(compile(src.replace(anchor, '    return True, ""   # ← 旧口径：永远敲门'),
                 p, "exec"), ns)
    M = _load("inbox_model")
    D = _load("inbox_daemon")

    def item(kind, recovered=False, severity="critical"):
        return M.Item(alert=M.Alert(id="n58" + kind[-3:], ts="2026-10-27T10:00:00+08:00",
                                    level="L1", kind=kind, recovered=recovered,
                                    severity=severity))
    cases = [
        (item("host_shield_revived"), False),
        (item("host_shield_tamper", recovered=True), False),
        (item("host_shield_tamper", recovered=False), True),
        (item("host_shield_zone_locked", severity="warning"), False),
    ]
    miss = []
    for it, want in cases:
        got, _w = ns["_should_knock"](it)
        if bool(got) is not bool(want):
            miss.append("%s→%s" % (it.kind, got))
    if not miss:
        return ("变异体（永远敲门）居然和修好的一样通过 ⇒ 这 4 条没有分辨力，"
                "R-58c 的绿是空的")
    for it, want in cases:                     # 修好的那份必须一条不差
        got, _w = D._should_knock(it)
        if bool(got) is not bool(want):
            return "修好的版本在 %s 上就不对（got=%s）" % (it.kind, got)
    _note("变异体在 %d/%d 条上与期望相反（%s）—— 负控咬住了"
          % (len(miss), len(cases), "、".join(miss)))
    return True


@check("R-58d 新类型必须登记进 AUDIT_SCHEMA（防 F-10 复发）")
def r58d():
    tp = "host_shield_state_unreadable"
    p = os.path.join(ROOT, "docs", "AUDIT_SCHEMA.md")
    with io.open(p, encoding="utf-8") as f:
        doc = f.read()
    if ("`%s`" % tp) not in doc:
        return "代码里写出的新类型 %s 没进 AUDIT_SCHEMA §4" % tp
    with io.open(os.path.join(ROOT, "host_shield.py"), encoding="utf-8") as f:
        src = f.read()
    if tp not in src:
        return "AUDIT_SCHEMA 登记了 %s，但代码里根本没有这个类型" % tp
    _note("代码与模式表两侧都有 %s" % tp)
    return True



# ══════════════════════════════════════════════════════════════════════════
# ★★ 0.60.0 并入（原 ci/inbox_guards_0600.py）—— DEV-01 A2「常驻上限 29 已满，
#    P5 正解是并站」，所以不立新站，直接并进本套件。
#
#    两件事都属于「**装的时候是新的、以后一直是旧的**」：
#      ① 规则副本不跟着包走 —— `pip install -U` 只换包不跑 install，钩子读的
#         `<root>/.psl/rules/default.json` 永久停在首次安装那一版（本仓实测
#         包内 0.59.0 / 副本 0.58.0 ⇒ 一个版本区间的规则修正一条都没生效）。
#      ② 钩子解释器写死在安装那一刻 —— `python.exe` 是控制台子系统程序 ⇒ 宿主
#         每跑一次钩子就分配一个控制台，Win11 默认终端是 Windows Terminal ⇒
#         **每一次工具调用都在屏幕上弹一个终端窗口**（WinEvent 实测：钩子在则
#         每次必有一对 CASCADIA_HOSTING_WINDOW_CLASS；清空两处 settings 的 hooks
#         后同样操作一个窗口都不弹）。修法：`pythonw.exe`（实测决策完全等价）。
#
#    为什么并进 0517 而不是别处：本套件已经在守「窗口这件事」（起得来、活得久），
#    而 ② 正是「窗口不该出现」的另一面；① 与本套件同属 daemon tick / 安装态。
# ══════════════════════════════════════════════════════════════════════════
import hashlib as _hashlib
import json
import shutil as _shutil
import subprocess as _subprocess

_SCRIPTS_DIR = os.path.join(ROOT, "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.append(_SCRIPTS_DIR)
HS = _load("host_shield")
INST = _load("install")

PKG_RULES = HS.package_rules_path()
PKG_VER = json.load(open(PKG_RULES, encoding="utf-8"))["version"]
NO_WIN = 0x08000000
HOOK_PRE = os.path.join(ROOT, "hooks", "pre_tool_use.py")


def _isolated(fn):
    """每条判据跑在自己的枢纽目录里 —— 不许把审计记录写进真实家目录。

    ★ 同时**打开**规则自愈（清掉 `ANTINEL_NO_AUTO_RULES`）：闸门统一给所有套件
      设了这个关闭阀（判据测「给定规则下的判定」，不该被自愈改掉夹具），
      而本族的 RF-60* 恰恰是**唯一要测自愈本身**的地方 —— 不在这里打开，
      它们就会在闸门里量到"关闭阀生效"，测不到真东西。
    """
    def w():
        old = os.environ.get("ANTINEL_HUB_DIR")
        old_off = os.environ.pop("ANTINEL_NO_AUTO_RULES", None)
        os.environ["ANTINEL_HUB_DIR"] = _TMP.tmpdir(prefix="g0600_hub_")
        try:
            return fn()
        finally:
            if old is None:
                os.environ.pop("ANTINEL_HUB_DIR", None)
            else:
                os.environ["ANTINEL_HUB_DIR"] = old
            if old_off is not None:
                os.environ["ANTINEL_NO_AUTO_RULES"] = old_off
    w.__name__ = getattr(fn, "__name__", "w")
    return w


def _must_fail(fn):
    """「必红」口径 —— 与 `check()` 的 wrapper 同一把尺子。

    ★ 踩过的坑：负控直接调**原函数**时，原函数返回的是**错误说明串**而不是抛异常
      （异常是 `check` 的 wrapper 转的）⇒ `try/except AssertionError` 抓不到
      ⇒ 变异体被判成"绿"，负控自己假红。
    """
    try:
        r = fn()
    except AssertionError:
        return True
    except Exception:                                       # noqa: BLE001
        return True
    if r is True or r is None:
        return False
    return True


def _mkproj(tag, ver, tamper=False):
    """造一个「已安装」的项目：`.psl/manifest.json` + 规则副本（版本可控）。"""
    d = _TMP.tmpdir(prefix="g0600_%s_" % tag)
    psl = os.path.join(d, ".psl")
    os.makedirs(os.path.join(psl, "rules"), exist_ok=True)
    os.makedirs(os.path.join(psl, "audit"), exist_ok=True)
    dst = os.path.join(psl, "rules", "default.json")
    data = json.load(open(PKG_RULES, encoding="utf-8"))
    data["version"] = ver
    raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    open(dst, "wb").write(raw)
    h = "sha256:" + _hashlib.sha256(raw).hexdigest()
    man = {"created_by": "guards0517-rf60", "rules_file": ".psl/rules/default.json",
           "rules_hash": ("sha256:" + "0" * 64) if tamper else h,
           "skill_version": ver}
    json.dump(man, open(os.path.join(psl, "manifest.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    return d, dst, os.path.join(psl, "manifest.json")


def _chain_types(root):
    out = []
    ad = os.path.join(root, ".psl", "audit")
    if not os.path.isdir(ad):
        return out
    for fn in sorted(os.listdir(ad)):
        if fn.endswith(".jsonl"):
            for line in open(os.path.join(ad, fn), encoding="utf-8"):
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line).get("type"))
                    except Exception:                       # noqa: BLE001
                        out.append("<bad>")
    return out


@check("RF-60a 规则副本落后 ⇒ 刷到包内这一版（内容全等 + manifest 同步 + 留痕）")
@_isolated
def rf60a():
    d, dst, manp = _mkproj("a", "0.0.1")
    before = open(dst, "rb").read()
    rep = HS.ensure_rules_current(d)
    after = open(dst, "rb").read()
    if rep.get("action") != "refreshed":
        return "action=%r（应为 refreshed）" % rep.get("action")
    if after != open(PKG_RULES, "rb").read():
        return "副本内容与包内不全等"
    if before == after:
        return "内容根本没变（夹具没起作用）"
    man = json.load(open(manp, encoding="utf-8"))
    if man.get("rules_hash") != "sha256:" + _hashlib.sha256(after).hexdigest():
        return "manifest.rules_hash 没跟着更新（下一跳会判 SELF-TAMPERED）"
    if man.get("skill_version") != PKG_VER:
        return "manifest.skill_version=%r（应为 %r）" % (man.get("skill_version"), PKG_VER)
    if "rules_snapshot_refreshed" not in _chain_types(d):
        return "审计链上没有刷新记录（改了防护依据却不留痕）"
    _note("0.0.1 -> %s；链上 %s" % (PKG_VER, _chain_types(d)))
    return True


@check("RF-60b 规则自愈幂等：已是包内这一版 ⇒ current 且 mtime 不变")
@_isolated
def rf60b():
    d, dst, _m = _mkproj("b", "0.0.1")
    HS.ensure_rules_current(d)
    mt = os.stat(dst).st_mtime_ns
    rep = HS.ensure_rules_current(d)
    mt2 = os.stat(dst).st_mtime_ns
    if rep.get("action") != "current":
        return "action=%r" % rep.get("action")
    if mt != mt2:
        return "mtime 变了（幂等不成立，白写盘）"
    return True


@check("RF-60c 规则副本比包还新 ⇒ ahead，不倒退")
@_isolated
def rf60c():
    d, dst, _m = _mkproj("c", "99.0.0")
    before = open(dst, "rb").read()
    rep = HS.ensure_rules_current(d)
    if rep.get("action") != "ahead":
        return "action=%r" % rep.get("action")
    if open(dst, "rb").read() != before:
        return "把更新的副本覆盖了（倒退）"
    return True


@check("RF-60d 规则副本被改过 ⇒ modified 且**不覆盖**，另留 skipped 痕")
@_isolated
def rf60d():
    d, dst, _m = _mkproj("d", "0.0.1", tamper=True)
    tampered = open(dst, "rb").read()
    rep = HS.ensure_rules_current(d)
    if rep.get("action") != "modified":
        return "action=%r（应为 modified：哈希对不上登记值）" % rep.get("action")
    if open(dst, "rb").read() != tampered:
        return "覆盖了被改过的副本 —— 把篡改证据一起抹掉了"
    if "rules_auto_refresh_skipped" not in _chain_types(d):
        return "没有 skipped 留痕"
    return True


@check("RF-60e 未安装的目录 ⇒ no_project，且不凭空造 .psl")
@_isolated
def rf60e():
    d = _TMP.tmpdir(prefix="g0600_none_")
    rep = HS.ensure_rules_current(d)
    if rep.get("action") != "no_project":
        return "action=%r" % rep.get("action")
    if os.path.exists(os.path.join(d, ".psl")):
        return "凭空建了 .psl"
    return True


@check("RF-60f 包内规则读不到 ⇒ error（不假装成功）")
@_isolated
def rf60f():
    d, _dst, _m = _mkproj("f", "0.0.1")
    rep = HS.ensure_rules_current(d, package_rules=os.path.join(d, "nope.json"))
    if rep.get("action") != "error":
        return "action=%r" % rep.get("action")
    return True


@check("RF-60g 关闭阀管自动那一路：force=False ⇒ disabled 一字不写；force=True 照刷")
@_isolated
def rf60g():
    d, dst, _m = _mkproj("g", "0.0.1")
    before = open(dst, "rb").read()
    os.environ["ANTINEL_NO_AUTO_RULES"] = "1"
    try:
        rep = HS.ensure_rules_current(d)
    finally:
        os.environ.pop("ANTINEL_NO_AUTO_RULES", None)
    if rep.get("action") != "disabled":
        return "自动那一路 action=%r（应为 disabled）" % rep.get("action")
    if open(dst, "rb").read() != before:
        return "关闭阀下仍然写了盘"

    # ★ 第二腿（0.60.0）：`force=True` 是**人敲的**（`--refresh-rules`），阀门不该挡。
    #   少这一腿就会出现「用户显式要求刷新，却被告知'被环境变量关掉了'」——
    #   而那个变量是闸门为了保住夹具设的，跟用户的意图毫无关系。
    os.environ["ANTINEL_NO_AUTO_RULES"] = "1"
    try:
        rep2 = HS.ensure_rules_current(d, force=True)
    finally:
        os.environ.pop("ANTINEL_NO_AUTO_RULES", None)
    if rep2.get("action") != "refreshed":
        return "force=True 时 action=%r（显式命令被阀门挡住了）" % rep2.get("action")
    if open(dst, "rb").read() == before:
        return "force=True 报 refreshed，但副本没变"
    return True


@check("RF-60h 三个入口同一实现：钩子 / daemon / CLI 都不许自己再写一份拷贝")
def rf60h():
    缺 = []
    for rel in ("hooks/pre_tool_use.py", "inbox_daemon.py", "scripts/install.py"):
        s = open(os.path.join(ROOT, rel), encoding="utf-8").read()
        if "ensure_rules_current" not in s:
            缺.append("%s 没有调用自愈" % rel)
    # ★ 只查**刷新路径**那只函数：install 主流程首次安装时的 copy2 是「建立副本」，
    #   不是「刷新副本」，那是合理的唯一一份（首次安装时还没有 manifest，
    #   自愈函数按设计就不该在这条路上跑）。按全文判会误伤它。
    inst = open(os.path.join(ROOT, "scripts", "install.py"), encoding="utf-8").read()
    i = inst.find("def refresh_rules(")
    j = inst.find("def fix_hooks(")
    body = inst[i:j] if (i >= 0 and j > i) else ""
    if not body:
        缺.append("找不到 refresh_rules 的函数体（判不了）")
    elif "shutil.copy2" in body:
        缺.append("refresh_rules 还留着自己那份拷贝（第二实现）")
    if 缺:
        return "；".join(缺)
    _note("钩子 / daemon / CLI 三处都指向 ensure_rules_current")
    return True


@check("N-RF-60a 负控：只换文件不换 rules_hash 的变异体必须判红")
@_isolated
def n_rf60a():
    def 坏(root=None, package_rules=None, force=False):
        p, _man = HS.resolve_rules_file([root])
        HS._write_bytes_atomic(p, open(PKG_RULES, "rb").read())   # 只换文件
        return {"action": "refreshed", "path": p}                 # hash 没登记

    orig = HS.ensure_rules_current
    try:
        HS.ensure_rules_current = 坏
        if _must_fail(rf60a):
            return True
        return "变异体（只换文件不登记 hash）被判绿 —— 判据量不到最坏的那种刷新"
    finally:
        HS.ensure_rules_current = orig


# ══════════════════════════════════════════════════════════════════════════
# RF-61（0.61.0）安装登记版本：**一个事实一个数**
#
#   本轮实测（不是读代码推的）：`.psl/manifest.json` 的 `skill_version`
#   有**三个写入点、两种含义** ——
#     · `install.py` 写死常量 `0.33.1`（注释称「钩子协议版本」）
#     · `host_shield.ensure_rules_current` 规则自愈时写**包版本**
#     · `run_harness` 给自检夹具写包版本
#   而 `--check` 又拿安装值去比 `0.33.1` ⇒ 本机长期报
#   「installed 0.60.2 != package 0.33.1 (re-run install.py to refresh)」。
#   **它提示的修法会把 0.33.1 写回去，下一跳再被自愈刷回包版本** ——
#   这个提示永远修不好它自己提示的那件事。
#   修法：删掉那个常量，三处共用 `_package_version()`；对外键名
#   `hook_protocol_version` → `installed_version`（全仓按"协议版本"分支的
#   代码是 0 处，那个名字在骗人）。
# ══════════════════════════════════════════════════════════════════════════

def _mkproj_rf61(ver):
    """已安装项目夹具：规则副本与包内**逐字节全等**。

    ★ 为什么必须逐字节：`--check` 里除了版本还查 rules_hash 与脚本哈希。
      夹具若换个序列化方式，哈希那几项就会先红 ⇒ 版本这条被挡住、断言不过去
      （同一形状的坑在 RF-60a 上踩过）。这里让哈希天然一致，漂移只可能来自版本。
    """
    d = _TMP.tmpdir(prefix="g0600_rf61_")
    psl = os.path.join(d, ".psl")
    os.makedirs(os.path.join(psl, "rules"), exist_ok=True)
    dst = os.path.join(psl, "rules", "default.json")
    _shutil.copyfile(PKG_RULES, dst)
    raw = open(dst, "rb").read()
    man = {"skill_version": ver, "rules_file": ".psl/rules/default.json",
           "rules_hash": "sha256:" + _hashlib.sha256(raw).hexdigest()}
    with io.open(os.path.join(psl, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(man, f)
    return d


def _check_out(fn, proj):
    """跑一次 `--check`，把它的**输出**也读回来 —— 判「报了哪一类漂移」必须
    看得到那个字符串，只看 rc=3 会把「rules_hash 不符」当成「版本不符」。"""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(proj)
    return rc, buf.getvalue()


@check("RF-61a 安装登记版本一个来源：装着登记的就是包版本，--check 不再自相矛盾")
def rf61a():
    src = io.open(INST.__file__, encoding="utf-8").read()
    # ① 第二个版本源（常量形态）不许回来。只看赋值形态：注释/文档里点名它不算。
    for ln in src.splitlines():
        if ln.strip().startswith("SKILL_VERSION") and "=" in ln:
            return "install.py 里又出现 SKILL_VERSION 常量（第二个版本源）：%r" % ln.strip()[:60]
    if '"skill_version": _pv,' not in src:
        return "manifest 的 skill_version 不是取自 `_pv = _package_version()`"
    pv = INST._package_version()
    if not pv or pv == "unknown":
        return "_package_version() 读不到（%r）—— 判据自己先瞎了" % pv
    # ② 登记=包版本 ⇒ 必须 rc=0（旧实现在这里必红，见 N-RF-61a）
    good = _mkproj_rf61(pv)
    rc, out = _check_out(INST.check_installed, good)
    if rc != 0:
        return "登记的正是包版本 %s，--check 却说漂移（rc=%d）：%s" % (
            pv, rc, out.strip().replace("\n", " ")[-180:])
    # ③ 落后的登记必须被抓到 —— 不然「一致」是空话（空集与确实没有同貌）
    old = _mkproj_rf61("0.0.1")
    rc2, out2 = _check_out(INST.check_installed, old)
    if rc2 != 3 or "version:" not in out2:
        return "登记 0.0.1 时 --check 没报版本漂移（rc=%d）：%r" % (rc2, out2.strip()[:140])
    # ④ 对外键名：installed_version 在、hook_protocol_version 不在、两数相等
    r = _subprocess.run([sys.executable, os.path.join(ROOT, "antinel.py"),
                         "agent", "--json"], cwd=good, capture_output=True,
                        text=True, encoding="utf-8", errors="replace", timeout=180)
    try:
        d = json.loads(r.stdout)
    except Exception:                                       # noqa: BLE001
        return "agent --json 读不出（rc=%s）：%r" % (
            r.returncode, (r.stdout or r.stderr or "")[:160])
    if "hook_protocol_version" in d:
        return "agent --json 还在报 hook_protocol_version（那个值不是协议版本）"
    if d.get("installed_version") != d.get("package_version"):
        return ("installed_version=%r 与 package_version=%r 不等 —— 两个数又分叉了"
                % (d.get("installed_version"), d.get("package_version")))
    _note("包版本 %s；登记 0.0.1 被抓到；agent --json 报 installed_version" % pv)
    return True


@check("N-RF-61a 负控：把写死的 0.33.1 塞回比较处，上面那条必须红")
def n_rf61a():
    """★ 变异体**真跑**（exec 进装脚本本体，`__file__` 指回真路径），
      不是塞一句假源码去查字串 —— 缺陷在比较逻辑里，改字串测不到。

    ★★ 同一批夹具同时喂给变异体与原版（第十四族）：变异体必须红、
      原版必须绿。原版也红 ⇒ 先疑夹具，不给自己发奖。
    """
    src = io.open(INST.__file__, encoding="utf-8").read()
    anchor = "    _pkg = _package_version()"
    if src.count(anchor) != 1:
        return "锚点 `%s` 出现 %d 次（应为 1）—— 负控失效，先修负控" % (anchor.strip(), src.count(anchor))
    mut = src.replace(anchor, '    _pkg = "0.33.1"')
    if mut == src:
        return "变异没生效"
    g = {"__name__": "install_rf61_mut", "__file__": INST.__file__}
    exec(compile(mut, INST.__file__, "exec"), g)             # noqa: S102
    pv = INST._package_version()
    good = _mkproj_rf61(pv)
    rc, out = _check_out(g["check_installed"], good)
    if rc != 3 or "version:" not in out:
        return "变异体在「登记=包版本」的项目上没报版本漂移（rc=%d）：%r" % (rc, out.strip()[:140])
    rc0, _o0 = _check_out(INST.check_installed, good)
    if rc0 != 0:
        return "同一夹具上修好的版本也不是绿的（rc=%d）—— 先疑夹具" % rc0
    _note("同一夹具：变异体 rc=3（报 version 漂移）／原版 rc=0")
    return True


@check("HK-60a 钩子解释器口径：pythonw 优先，两处入口都写进去")
def hk60a():
    exe = INST.hook_python()
    if not os.path.basename(exe).lower().startswith("pythonw"):
        return "hook_python()=%r（应为 pythonw.exe，否则每次工具调用都弹控制台窗口）" % exe
    if not os.path.isfile(exe):
        return "pythonw 路径不存在：%r" % exe
    cmd = INST.hook_command("pre_tool_use.py")
    if "pythonw" not in cmd.lower():
        return "hook_command() 没把 pythonw 写进命令行：%r" % cmd[:90]
    z = INST.zcode_hook_entry("pre_tool_use.py")
    if "pythonw" not in str(z.get("command", "")).lower():
        return "zcode 形态没跟着换：%r" % z.get("command")
    _note("exe=%s" % exe)
    return True


def _run_hook(exe, payload):
    r = _subprocess.run([exe, "-I", "-S", HOOK_PRE], input=json.dumps(payload),
                        capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=180, cwd=ROOT,
                        creationflags=NO_WIN,
                        env=dict(os.environ, ANTINEL_HOST_MIRROR="0"))
    out = (r.stdout or "").strip()
    try:
        dec = json.loads(out).get("decision", "") if out else ""
    except Exception:                                       # noqa: BLE001
        dec = "<non-json>"
    return r.returncode, dec


@check("HK-60b 行为腿：用产品会给的解释器真起钩子，block 样本必须 rc=2 + block")
@_isolated
def hk60b():
    exe = INST.hook_python()
    if "pythonw" not in os.path.basename(exe).lower():
        return "解释器不是 pythonw：%r" % exe
    bad = "Remove-" + "Item -Recurse -Force C:\\data"
    rc, dec = _run_hook(exe, {"session_id": "g0517rf", "tool_name": "Bash",
                              "tool_input": {"command": bad}})
    if rc != 2 or dec != "block":
        return "pythonw 下决策变了：rc=%s decision=%r（最危险的失败方向）" % (rc, dec)
    rc2, dec2 = _run_hook(exe, {"session_id": "g0517rf", "tool_name": "Bash",
                                "tool_input": {"command": "echo hello"}})
    if rc2 != 0 or dec2 not in ("", "allow"):
        return "pythonw 下 allow 样本异常：rc=%s decision=%r" % (rc2, dec2)
    _note("block rc=2/decision=block；allow rc=0")
    return True


@check("N-HK-60b 负控：换回 python.exe 时这条判据必须红（不然它量不到窗口）")
def n_hk60b():
    orig = INST.hook_python
    try:
        INST.hook_python = lambda: sys.executable
        if _must_fail(hk60b):
            return True
        return "python.exe 也判绿 —— 判据只量了「决策对不对」，量不到「有没有窗口」"
    finally:
        INST.hook_python = orig


@check("HK-60c 迁移入口：临时 USERPROFILE 下的旧 settings 被换掉，外来钩子保留")
def hk60c():
    home = _TMP.tmpdir(prefix="g0600_home_")
    proj = _TMP.tmpdir(prefix="g0600_proj_")
    os.makedirs(os.path.join(proj, ".psl"), exist_ok=True)
    json.dump({"rules_file": ".psl/rules/default.json"},
              open(os.path.join(proj, ".psl", "manifest.json"), "w", encoding="utf-8"))
    d = os.path.join(home, ".workbuddy")
    os.makedirs(d, exist_ok=True)
    sp = os.path.join(d, "settings.json")
    old_cmd = '"%s" -I -S "%s"' % (sys.executable, HOOK_PRE)
    foreign = {"matcher": ".*", "hooks": [
        {"type": "command", "command": "echo foreign-hook", "timeout": 5}]}
    json.dump({"hooks": {"PreToolUse": [
        {"matcher": ".*", "hooks": [{"type": "command", "command": old_cmd,
                                     "timeout": 10}]},
        foreign]}}, open(sp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    old_pe = os.environ.get("USERPROFILE")
    os.environ["USERPROFILE"] = home
    try:
        rc = INST.fix_hooks(proj)
    finally:
        if old_pe is None:
            os.environ.pop("USERPROFILE", None)
        else:
            os.environ["USERPROFILE"] = old_pe
    if rc != 0:
        return "fix_hooks 返回 %r" % rc
    entries = json.load(open(sp, encoding="utf-8"))["hooks"]["PreToolUse"]
    flat = json.dumps(entries, ensure_ascii=False)
    if "pythonw" not in flat.lower():
        return "临时用户级 settings 里的钩子没换成 pythonw：%s" % flat[:160]
    if "foreign-hook" not in flat:
        return "把外来钩子弄丢了（只许动我们自己的条目）"
    if sum(1 for e in entries if "pre_tool_use.py" in json.dumps(e)) != 1:
        return "我们的条目不是恰好 1 个"
    _note("临时 USERPROFILE 下已换成 pythonw，外来钩子保留")
    return True


@check("HK-60d 扫描面：用户级 settings 也要被找到（不是只看项目级）")
def hk60d():
    home = _TMP.tmpdir(prefix="g0600_home2_")
    proj = _TMP.tmpdir(prefix="g0600_proj2_")
    d = os.path.join(home, ".workbuddy")
    os.makedirs(d, exist_ok=True)
    sp = os.path.join(d, "settings.json")
    json.dump({"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
        {"type": "command", "command": 'pythonw.exe -I -S "%s"' % HOOK_PRE,
         "timeout": 10}]}]}}, open(sp, "w", encoding="utf-8"), ensure_ascii=False)
    old_pe = os.environ.get("USERPROFILE")
    os.environ["USERPROFILE"] = home
    try:
        found = INST._our_hook_settings(proj)
    finally:
        if old_pe is None:
            os.environ.pop("USERPROFILE", None)
        else:
            os.environ["USERPROFILE"] = old_pe
    paths = [str(p) for p, _s in found]
    if not any(os.path.join(home, ".workbuddy") in p for p in paths):
        return "没扫到用户级 settings（只改项目级 = 本机实测过的假阴性）found=%r" % paths
    _note("扫到 %d 处，含用户级" % len(paths))
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
