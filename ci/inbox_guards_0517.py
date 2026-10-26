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
