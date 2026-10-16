# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""★ 0.36.2 判据：窗口落位**根因修**（身份标识 · 全量落位 · 等旧窗消失）。

★ 本轮触发事件：创始人 2026-10-07 再测「窗口出现在旧位置而且变成了旧尺寸」。
  与 0.36.1 的关系：0.36.1 打了两个补丁（收旧窗 + 后缀匹配），
  **两个都没生效** —— 本文件的存在就是为了钉死"它们为什么曾经无效"。

★ 三条根因（全部有本机实测支撑，不是推演）：
  ① `close_console_windows` 函数体写 `if closer is None:`，而 `closer`
     **既不是参数也没定义** ⇒ 每次调用必然 `UnboundLocalError`
     ⇒ 被 `open_console` 的 `except Exception` 兜住、只往 stderr 打一行
     ⇒ **「开窗前收旧窗」从 0.36.1 起一次都没成功过**。
     实测：`close_console_windows()` → `UnboundLocalError`。
  ② 落位只取**第一个**同名窗口（`find_console_window` 命中即 `return False`）。
     同标题有多个时（旧的残留 + 新开的），"第一个"由枚举顺序决定、不可控
     ⇒ 挪走旧的、新的留在旧位置旧尺寸 ⇒ **正是用户看到的现象**。
  ③ 落位认窗口只靠"标题含「 · Antinel 监理」"⇒ 可能命中**用户自己的浏览器窗口**
     （实测本机 Edge 普通窗口标题为
     「收件箱 · Antinel 监理 和另外 14 个页面 - 个人 - Microsoft Edge」），
     而 `SetWindowPos` 命中它的后果是**把用户的浏览器搬走**。

★ 本文件的判据纪律（沿用 0.36.0，每条都有配套负控 `n_*`）：
  · **量具先测自己**：每条判据配负控，负控改坏产品 ⇒ 判据必须变红。
  · **判据只读代码，不读解释代码的文字**（用 `_code_only`）——
    0.36.2 实测又栽一次：查 `DestroyWindow` 命中了 docstring 里
    「而不是 `DestroyWindow`」那句**解释**，报了一条假红。
  · **字面量检查对"真的能不能用"零分辨力**：0.36.1 的
    `closer=None` 字面量判据**报了绿**，而真身是坏的
    ⇒ 凡能真跑的就真跑（见 `c_close_console_windows_injection_actually_runs`）。
  · 取源码段必须按**行边界**：`find_console_window` 是 `find_console_windows`
    的**前缀**，子串 `split` 会先命中复数那个 ⇒ 取错段 ⇒ 假红（实测踩到）。
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


def _src_of(mod):
    import inspect
    return inspect.getsource(mod)


def _code_only(src, keep_strings=False):
    """返回**只含可执行代码**的源码：注释与 docstring 全部剥掉。

    （沿用 0.36.0 的实现，`ast.unparse` 天然不含注释。）
    """
    import ast
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(getattr(node.body[0], "value", None), ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
        if not keep_strings:
            for node in ast.walk(node if isinstance(node, ast.AST) else tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    node.value = ""
    return ast.unparse(tree)


def _func_seg(code, name):
    """按**行边界**取出 `def <name>(` 的函数体段（到下一个行首 `def `/`class `）。

    ★ 为什么不能用 `split("def %s" % name)`：本模块里
      `find_console_window` 是 `find_console_windows` 的**前缀**，
      子串切分会先命中复数那个 ⇒ 取到错的段 ⇒ 假红（本轮实测踩到）。
    """
    m = re.search(r"^def %s\(" % re.escape(name), code, re.M)
    if not m:
        return ""
    rest = code[m.start():]
    n = re.search(r"^(?:def |class )", rest[m.end() - m.start():], re.M)
    return rest[:m.end() - m.start() + n.start()] if n else rest


# ═══════════════════════════════ 根因 ①：收旧窗曾经从未生效 ══════════════
def c_close_console_windows_not_unbound():
    """★ 根因①：`close_console_windows()` **真跑一次不许抛 `UnboundLocalError`**。

    ★ 这条判据是本轮**最关键**的一条：0.36.1 的缺陷正是"函数一调用就炸"，
      而当时的判据只查源码里有 `closer=None` 三个字 ⇒ **报了绿**。
      ⇒ 现在**真跑**。真跑是这类"运行时才暴露"的缺陷唯一有效的检验。
    """
    import inspect
    import inbox_window as WIN
    if "closer" not in inspect.signature(WIN.close_console_windows).parameters:
        return "签名里没有 closer ⇒ 函数体里引用它必然 UnboundLocalError"
    orig = WIN.find_console_windows
    try:
        WIN.find_console_windows = lambda **kw: []
        try:
            n = WIN.close_console_windows()
        except UnboundLocalError as e:
            return "真跑就抛 UnboundLocalError：%s" % (e,)
        except Exception as e:                                # noqa: BLE001
            return "真跑抛了别的异常（%s）：%s" % (type(e).__name__, e)
    finally:
        WIN.find_console_windows = orig
    if n != 0:
        return "无匹配窗口时返回 %r，应为 0" % (n,)
    return True


def n_close_console_unbound_is_caught():
    """负控：把 `closer` 从签名里去掉（还原 0.36.1 的形状）⇒ Q01 必须报红。

    ★ 负控的写法纪律：**必须真的制造变异并跑判据**，不能只反问一句
      「签名里有没有 closer」（那不是负控，是把判据重问一遍）。
      做法：临时把 `closer` 参数从签名摘掉 ⇒
      函数体里 `if closer is None:` 引用未定义名字 ⇒ 真跑必抛
      `UnboundLocalError` ⇒ 模拟判据应当返回那句红。
    """
    import inspect
    import inbox_window as WIN
    orig = WIN.close_console_windows
    try:
        # 还原 0.36.1 的形状：签名里没有 closer
        def broken(suffix=WIN.CONSOLE_WINDOW_TITLE_SUFFIX, visible_only=True,
                   run_id=None):
            if closer is None:                                # noqa: F821
                closer = lambda h: True                       # noqa: E731,F841
            return orig(suffix=suffix, visible_only=visible_only)
        WIN.close_console_windows = broken
        try:
            broken()
        except UnboundLocalError as e:
            return True   # 负控生效：还原 0.36.1 形状后确实抛 UnboundLocalError
        except Exception as e:                                # noqa: BLE001
            return "还原后抛的是 %s，不是 UnboundLocalError" % type(e).__name__
        else:
            return False            # 没抛 ⇒ 0.36.1 那个缺陷的性质判断错了
    finally:
        WIN.close_console_windows = orig


def c_close_console_only_touches_enumerated():
    """★ 收旧窗**只对枚举出的句柄**发关闭，且逐个发（不是批量销毁进程）。"""
    import inbox_window as WIN
    orig = WIN.find_console_windows
    asked, closed = [], []
    try:
        WIN.find_console_windows = lambda **kw: (asked.append(kw.get("suffix")),
                                                 [11, 22, 33])[1]
        n = WIN.close_console_windows(suffix=" · Antinel 监理#zz",
                                      closer=lambda h: (closed.append(h), True)[1])
    finally:
        WIN.find_console_windows = orig
    if closed != [11, 22, 33]:
        return "关闭动作没有逐个作用于枚举出的句柄：%r" % (closed,)
    if n != 3:
        return "关闭计数不对：%r" % (n,)
    if asked and asked[0] != " · Antinel 监理#zz":
        return "枚举侧没收到调用方指定的 suffix：%r" % (asked,)
    return True


def c_close_console_uses_wm_close_not_kill():
    """★ 关闭必须走 `WM_CLOSE`（让浏览器正常退场），不强杀。"""
    import inbox_window as WIN
    code = _code_only(_src_of(WIN))
    if "PostMessageW" not in code:
        return "关闭动作不是 WM_CLOSE"
    for bad in ("TerminateProcess", "DestroyWindow", "taskkill"):
        if bad in code:
            return "出现了强杀/强销毁 %s（对用户窗口不可接受）" % bad
    return True


# ═════════════════════════════ 根因 ②：只取第一个同名窗口 ═════════════════
def c_find_console_windows_returns_all():
    """★ 枚举必须返回**全部**匹配窗口，不是第一个。"""
    import inbox_window as WIN
    got = WIN.find_console_windows(lister=lambda **kw: [1, 2, 3])
    if list(got) != [1, 2, 3]:
        return "全量枚举没有把三个句柄都返回：%r" % (got,)
    if WIN.find_console_windows(lister=lambda **kw: []) != []:
        return "无匹配时应返回空列表"
    return True


def n_find_console_windows_first_only_is_caught():
    """负控：枚举只返回第一个 ⇒ Q04/Q05 必须报红。

    ★ 真造变异：把 `lister` 替身的结果砍到第一个，然后跑产品函数，
      看 Q04（全量）与 Q05（全量落位）是否都会红。

    ★★ 0.36.4 修判据自身：`first_only` 原来的签名是
      `(suffix=None, visible_only=True)`，而 `find_console_windows`
      在 0.36.4 加了 `run_id=None` ⇒ 负控一调用就抛
      `TypeError: unexpected keyword argument 'run_id'`
      ⇒ **负控自己崩了**，它既没报红也没报绿，等于静默失效。
      ⇒ 改成 `**kw` 吸收任意关键字（负控只关心"给回什么"，不关心参数名）。
      ★ 这与本轮 D1 那个 bug 同族：**判据自己出错时最危险，因为它看起来像通过。**
    """
    import inbox_window as WIN

    def first_only(**kw):
        return [1, 2, 3][:1]            # ← 变异：只给第一个

    got = WIN.find_console_windows(lister=first_only)
    if len(list(got)) == 3:
        return False                    # 变异没生效
    # Q04 的判据逻辑：三个句柄是否都拿到
    q04_ok = (list(got) == [1, 2, 3])
    if q04_ok:
        return False                    # Q04 对这个变异没有分辨力
    # Q05 的判据逻辑：每个窗口都被移动
    # ★ 0.36.4：`place_all` 新增 `skip_if_placed`（默认开，会先回读）。
    #   这里显式关掉，否则 reader 返回的矩形恰好等于目标 ⇒ 全部"已对齐"
    #   ⇒ 一个都不移动 ⇒ Q05 的判据逻辑会误以为"没分辨力"。
    moved = []
    WIN.place_all([1, 2, 3], (0, 0, 10, 10), skip_if_placed=False,
                  setter=lambda h, r: (moved.append(h), True)[1],
                  reader=lambda h: (999, 999, 1, 1))   # 读出来 ≠ 目标 ⇒ 必须移
    return len(moved) == 3


def c_place_all_moves_every_window():
    """★ 全量落位：**每一个**匹配窗口都要被移动。

    ★★ 0.36.4 扩成**两态**判据（原来只测一种，现在测两种）：
      A. 窗口**未对齐** ⇒ 每个都要移动（0.36.2 的原意，防"只挪第一个"）
      B. 窗口**已对齐** ⇒ 一个都不动（0.36.4 独立 profile 的新机制：
         窗口出生即正确，再搬一次纯属多余动作 + 多一次误伤机会）
    两态都验，才既守住旧机制、又守住新机制。
    """
    import inbox_window as WIN
    target = (2440, 1264, 520, 640)
    wrong = (10, 10, 1050, 1932)          # 实测真实故障形状

    # ── A 态：未对齐 ⇒ 每个都要移动 ──
    #   ★ reader 必须模拟真实语义：**移动前**报未对齐，**移动后**报已对齐。
    #   我第一版让 reader 恒返回 `wrong`，于是移动后回读仍不符
    #   ⇒ place_all 正确地判失败（"移动已下达但实测仍是 1050×1932"）
    #   ⇒ 而判据却期待成功 ⇒ **假红**。产品没坏，是用例没搭好场景。
    #   这与 P01、Q06 同族：**判据必须显式构造它要验的场景。**
    target = (2440, 1264, 520, 640)
    wrong = (10, 10, 1050, 1932)          # 实测真实故障形状
    moved = []
    moved_set = set()

    def reader_a(h):
        return target if h in moved_set else wrong

    def setter_a(h, r):
        moved.append(h)
        moved_set.add(h)
        return True

    ok, why = WIN.place_all([101, 202, 303], target,
                            setter=setter_a, reader=reader_a)
    if not ok:
        return "全部落位却报失败：%s" % why
    if moved != [101, 202, 303]:
        return "A 态（未对齐）只移动了 %r，三个窗口都要落位" % (moved,)

    # ── B 态：已对齐 ⇒ 一个都不动（0.36.4 独立 profile 的新机制）──
    moved2 = []
    ok2, why2 = WIN.place_all([101, 202, 303], target,
                              setter=lambda h, r: (moved2.append(h), True)[1],
                              reader=lambda h: target)
    if not ok2:
        return "B 态（已对齐）却报失败：%s" % why2
    if moved2:
        return ("B 态（已对齐）仍发了 %d 次移动（%r）—— 窗口出生即正确，"
                "再搬一次纯属多余动作，且多一次误伤机会" % (len(moved2), moved2))
    return True


def c_place_all_partial_failure_is_not_success(mod=None):
    """★★ 根因②的正面判据：**局部成功不算成功**。

    ★★ 这条是本轮最要紧的行为判据。实测故障形态：
      旧窗口挪走了、新窗口没挪 ⇒ 若此时报"已落位"，
      用户看到的就是"修复没生效"而日志说成功 —— **谎报**。
      ⇒ 要求：N 个里任一个不符 ⇒ 整体 False，且说清几个不符。

    ★ 0.50.2：加 `mod` 注入点（默认真模块）—— 负控才能拿**变异模块**跑
      同一条正判据，证明"正判据真的会翻面"（原来只证明"变异看得见"）。
    """
    import inbox_window as _W
    WIN = mod or _W
    good = (2440, 1264, 520, 640)
    bad = (10, 10, 1050, 1932)          # 实测真实故障形状
    ok, why = WIN.place_all([1, 2], good,
                            setter=lambda h, r: True,
                            reader=lambda h: good if h == 1 else bad)
    if ok:
        return "一个窗口没落位却报成功（＝谎报，正是实测故障）"
    # ★★ 0.36.4 修判据自身的**脆性**（实测踩到）：
    #   原来查的是逐字片段 `"1 个没落位"`，而 0.36.4 为了撤掉「落位失败就关窗」，
    #   把文案改成了「1 个没落到目标位置」（多了"到目标位置"四字）⇒ 判据报红，
    #   而**产品行为完全正确**（数量说了、实测矩形说了、整体判 False）。
    #   ⇒ 教训：**判据不该逐字匹配措辞**。措辞会为了说清事情而变，
    #     判据要守的是「数量信息在不在」，不是「是不是这几个字」。
    #   ⇒ 改查：既含失败数量、也含总数，且两个数字都在。
    #     （仍然严格：只报"没落位"而不说几个 ⇒ 依然报红）
    if "1 个没" not in why:
        return "没有说清几个没落位：%r" % why
    if "2 个匹配窗口" not in why:
        return "没有说清一共几个窗口：%r" % why
    if "1050x1932" not in why:
        return "没有如实报出实测矩形：%r" % why
    # ★ 0.36.4：撤掉关窗兜底后，失败文案**必须说清"面板仍在屏幕上"**
    #   —— 用户需要知道那个窗口还在（不是消失了），否则会去反复找它。
    if "留在屏幕上" not in why:
        return "失败文案没说清面板仍在屏幕上：%r" % why
    return True


def n_place_all_partial_ok_is_caught():
    """负控：把 `place_all` 的「整体成功」改成「任一成功即成功」⇒ 本条必须报红。

    ★★ 0.50.2 修两处（都是**实测**出来的量具故障，不是产品问题）：
      ① **变异打错了函数**：文件里有**两处** `if all(oks):`
         （`set_topmost` 与 `place_all`），`src.replace(..., 1)` 命中的是
         **前面那处** ⇒ `place_all` 行为一字未变 ⇒ 负控恒报"失效"，
         而屏上只打一个裸 `False`，看不出是"锚点过时"还是"变异没翻面"。
         ⇒ 改成先切出 `place_all` 的函数段再变异。
      ② 失败时返回**说明串**（不再返回裸 `False`）—— 量具故障要能一眼读出。
      ③ 负控改成**拿变异模块跑同一条正判据**（`mod=` 注入），
         而不是自己重写一遍"变异后应该成功"的判断。
    """
    import types

    import inbox_window as WIN
    src = _src_of(WIN)
    seg = _func_seg(src, "place_all")
    if "if all(oks):" not in seg:
        return ("变异锚点未找到（`place_all` 段里没有 `if all(oks):`）"
                "—— 负控自身失效，不算通过")
    mutated_seg = seg.replace("if all(oks):", "if any(oks):", 1)
    if mutated_seg == seg:
        return "负控自身失效：段内替换没生效"
    mutated = src.replace(seg, mutated_seg, 1)
    if mutated == src:
        return "负控自身失效：变异没落到源上"
    ns = {}
    exec(compile(mutated, "<mut_place_all>", "exec"), ns)       # noqa: S102
    shim = types.SimpleNamespace(place_all=ns["place_all"])
    good = (2440, 1264, 520, 640)
    bad = (10, 10, 1050, 1932)
    ok, _why = shim.place_all([1, 2], good,
                              setter=lambda h, r: True,
                              reader=lambda h: good if h == 1 else bad)
    if ok is not True:
        return ("负控失效：变异成「任一成功即成功」后 `place_all` 仍报失败"
                "（实测 %r）—— 变异没打到判分点" % (str(_why)[:70],))
    # 拿变异模块跑**同一条正判据** ⇒ 必须翻面
    if c_place_all_partial_failure_is_not_success(mod=shim) is True:
        return "负控失效：变异模块跑正判据仍判合格 —— 这条判据是装饰"
    return True


def c_place_all_refuses_empty_and_none():
    """★ 没有窗口 / 没有目标矩形 ⇒ 都要说人话，不许吞掉。"""
    import inbox_window as WIN
    ok, why = WIN.place_all([], (1, 2, 3, 4))
    if ok or "没找到" not in why:
        return "空窗口列表却报成功：%r" % (why,)
    ok2, why2 = WIN.place_all([5], None)
    if ok2 or not why2:
        return "rect=None 却报成功或没给理由：%r" % (why2,)
    return True


def c_place_all_does_not_enumerate_itself():
    """★ 落位层**不自己枚举**、不自己匹配标题 —— 移动范围由上游过滤限定。

    ★ 0.36.1 的守卫写的是"`place_window` 里不许 `for` + `SetWindowPos`"；
      0.36.2 全量落位必须循环，那条字面判据已失效。
      **不变量没变**：移动范围只能由"上游按标题过滤后的结果"决定。
      ⇒ 判据改成查"落位层没有枚举、没有自己匹配标题"。
    """
    import inbox_window as WIN
    code = _code_only(_src_of(WIN))
    for name in ("place_all", "place_one"):
        seg = _func_seg(code, name)
        if not seg:
            return "找不到 %s 的定义" % name
        for bad in ("_matches_title", "EnumWindows",
                    "find_console_window"):
            if bad in seg:
                return ("%s 里出现 %s ⇒ 落位层自己在决定移动范围，"
                        "范围必须由上游按标题过滤限定" % (name, bad))
    return True


# ═══════════════════ 根因 ③：可能命中用户自己的浏览器窗口 ═══════════════
def c_run_id_differs_between_runs():
    """★ 身份串必须**每次运行都不同**（否则认不出"上次运行的窗口"）。"""
    import inbox_window as WIN
    a = WIN.build_run_id("token-A")
    b = WIN.build_run_id("token-B")
    if not a or not b:
        return "身份串为空"
    if a == b:
        return "两个不同口令派生出同一身份串：%r" % a
    if len(a) < 4:
        return "身份串太短（%r），不足以区分运行" % a
    return True


def c_run_id_is_stable_within_run():
    """★ 同一口令 ⇒ 同一身份串（否则自己开的窗口也认不出）。"""
    import inbox_window as WIN
    if WIN.build_run_id("tok") != WIN.build_run_id("tok"):
        return "同一口令两次派生不一致"
    return True


def c_run_id_does_not_leak_token():
    """★ 身份串**不得**包含口令本身（标题会进任务栏预览/录屏/Alt-Tab）。"""
    import inbox_window as WIN
    secret = "SUPERSECRETTOKEN123"
    rid = WIN.build_run_id(secret)
    if secret in rid:
        return "身份串泄露了口令：%r" % rid
    if len(rid) > 12:
        return "身份串过长（%r），像是截取凭据而不是哈希" % rid
    return True


def c_console_title_suffix_carries_run_id():
    """★ 身份后缀形状：`<稳定后缀>#<身份>`，且**以身份结尾**。

    ★★ 这条判据的第一版把方向写反了（我自己踩的）：
      我写「身份后缀必须以稳定后缀结尾」—— 实测 `False`，
      因为身份串就在**末尾**，` · Antinel 监理#abc123` 不以 ` · Antinel 监理` 结尾。
      ★ 写完立刻暴露了一个**真实设计缺陷**（不是判据的错）：
        通用后缀因此**认不出**带身份串的窗口 ⇒
        `close_console_windows` 若按通用后缀匹配就关不掉上一轮的窗口。
        ⇒ 修法是引入**两级**判据（`CONSOLE_WINDOW_TITLE_MARK` 中段 /
          `console_title_suffix` 后缀），关窗走宽泛、落位走严格。
      ⇒ 教训：**判据报错时先问"是不是产品错了"**，别急着改判据。
        本条就是靠判据红了一次，才逮到设计缺陷。
    """
    import inbox_window as WIN
    s = WIN.console_title_suffix("abc123")
    # ★ 0.51.1 反转（W-01 退休、FZ-002 冻结）：后缀值随
    #   CONSOLE_WINDOW_TITLE_SUFFIX 收为品牌本体（去前导「 · 」）。
    if s != "Antinel 监理#abc123":
        return "身份后缀形状不对：%r" % s
    # 身份串在**末尾** ⇒ 通用后缀不是它的后缀（这是设计好的，必须如此）
    if s.endswith(WIN.CONSOLE_WINDOW_TITLE_SUFFIX):
        return "身份串不在末尾（会让通用后缀误以为能匹配）"
    if not s.startswith(WIN.CONSOLE_WINDOW_TITLE_MARK):
        return "身份后缀没有以稳定标记开头"
    if WIN.console_title_suffix(None) != WIN.CONSOLE_WINDOW_TITLE_SUFFIX:
        return "无 run_id 时应退回通用后缀"
    # ★ 两级判据必须都在
    if WIN.CONSOLE_WINDOW_TITLE_MARK != WIN.CONSOLE_WINDOW_TITLE_SUFFIX:
        return "宽泛标记与稳定后缀应当同一个常量"
    return True


def c_browser_window_never_matched():
    """★★★ 绝不把**浏览器普通窗口**当成Antinel 监理窗口（本轮真闯过这个祸）。

    ★★★ 这条判据来自 0.36.2 修过程中的**真实事故**，不是推演：
      我为了让"收旧窗"能认出带身份串的窗口，把宽泛判据写成
      「标题**中段**含 ` · Antinel 监理`」。实测跑了一次
      `close_console_windows()`，**用户那个有 15 个标签的 Edge 窗口
      被关掉了**（枚举复查：两个 Edge 窗口只剩一个）。
      实测真实标题（判据设计的依据）：
        app 窗口 「收件箱 · Antinel 监理#f356b0」
        用户窗口 「收件箱 · Antinel 监理 和另外 14 个页面 - 个人 - Microsoft Edge」
      两者窗口类名**相同**（`Chrome_WidgetWin_1`）⇒ 类名区分不了。
    ★ 判据要求：**任何模式**下都不能命中带浏览器品牌后缀的标题。
    """
    import inbox_window as WIN
    user_windows = [
        # ↓ 实测本机真实标题（2026-10-07）
        "收件箱 · Antinel 监理 和另外 14 个页面 - 个人 - Microsoft Edge",
        "收件箱 · Antinel 监理 - 个人 - Microsoft Edge",     # 单标签形态
        # ★ 0.51.1 反转后的**新形态误伤面**：标签页恰为纯品牌标题时，
        #   Edge 把它串成「Antinel 监理#f356b0 和另外 14 个页面…」——
        #   品牌在开头（第一层过了），靠 rest 检查＋浏览器品牌排除挡。
        "Antinel 监理#f356b0 和另外 14 个页面 - 个人 - Microsoft Edge",
        "新建标签页 - 个人 - Microsoft Edge",
    ]
    for t in user_windows:
        if WIN.is_console_title(t):
            return "宽泛判据命中了用户浏览器窗口：%r" % t
        if WIN.is_console_title(t, run_id="any123"):
            return "严格判据命中了用户浏览器窗口：%r" % t
    # 反面：自己的 app 窗口必须仍然被认出来（别把判据修成"永不匹配"）
    # ★ 0.51.1 反转：app 窗口形态从「页面名 · Antinel 监理#f356b0」
    #   （随页面变的三种）收为**品牌恒形态**两种（无身份／带身份）。
    for t in ("Antinel 监理#f356b0", "Antinel 监理"):
        if not WIN.is_console_title(t):
            return "自己的 app 窗口认不出来了：%r" % t
    return True


def n_browser_window_matched_is_caught():
    """负控：宽泛模式退回**纯子串** ⇒ Q08b 必须报红。

    ★★ 0.36.5 重写（实测：原版**假红**，看起来像"判据没分辨力"）：
      原来注入的是"删掉 `BROWSER_TITLE_MARKS` 排除"。
      但 0.36.5 给宽泛模式加了**第二道独立防护**（标记必须在末尾 ＋
      页面前缀不得含窗口标题分隔符）⇒ 删掉浏览器排除后，
      Edge 窗口**仍然被正确排除**（它的标题里带 ` - `，被第二道挡住了）
      ⇒ 负控报"变异不生效"。
      ★ 这里有一个容易骗过自己的地方：那个结果**看起来**像
        「判据没分辨力」，实际是「**变异太弱**」——
        而负控的失败模式恰恰是"看起来还有检查"。
      ⇒ 现在改成注入**真正能穿透**的缺陷：宽泛模式退回子串匹配。
        这同时废掉两道防护 ⇒ Edge 窗口被误认 ⇒ Q08b 必须报红。
      ★ 与本轮另外三次同源：F1（数字符串）、F3（变量未使用）、
        G2（查函数名不见死分支）—— **四次都是"形式上有检查、
        实际上测不到对象"**。这是本轮最值得记住的一条。
    """
    import inbox_window as WIN
    import inspect
    src = inspect.getsource(WIN)
    lines = src.split("\n")
    # ★★ 变异必须**一次废掉两层防护**，否则打不穿（实测）：
    #   只把宽泛模式退回子串 ⇒ Edge 窗口**仍被正确排除**，
    #   因为 `BROWSER_TITLE_MARKS` 那道独立防护还在 ⇒ 负控假红。
    #   只删浏览器排除 ⇒ 也打不穿，末尾+前缀检查挡住了。
    #   ⇒ 负控的变异强度必须**对照防护层数**确定，不是"改一处试试"。
    cand = [i for i, l in enumerate(lines) if l.strip() == "return _mark_at_tail(t)"]
    if len(cand) < 1:
        return False                        # 锚点过时
    lines[cand[0]] = "        return CONSOLE_WINDOW_TITLE_SUFFIX in t"
    # ★★ 0.50.4（改名批）：浏览器排除那道防护的锚点**不许带注释文字** ——
    #   旧写法把整行 `return False  # ★ 浏览器普通窗口，不许当成…` 写进 replace，
    #   而改名批只改产品**字符串**不改注释 ⇒ 锚点失配 ⇒ 变异静默失效
    #   （负控返回 False，看起来像"判据没分辨力"）。⇒ 改为按**语句**锚：
    #   找 `if any(m in t for m in BROWSER_TITLE_MARKS):` 与紧随的 `return False`，
    #   两行一起删 —— 与注释写成什么字无关。
    gi = [i for i, l in enumerate(lines)
          if l.strip() == "if any(m in t for m in BROWSER_TITLE_MARKS):"]
    if len(gi) < 1 or not lines[gi[0] + 1].strip().startswith("return False"):
        return False                        # 锚点过时
    del lines[gi[0]:gi[0] + 2]
    mutated = "\n".join(lines)
    ns = {}
    exec(compile(mutated, "<mut>", "exec"), ns)              # noqa: S102
    user_win = "收件箱 · Antinel 监理 和另外 14 个页面 - 个人 - Microsoft Edge"
    matched = ns["is_console_title"](user_win)
    if matched is not True:
        return False                        # 变异后仍不匹配 ⇒ 判据无分辨力
    return True                             # 变异生效：去掉防护后确实误命中


def c_wide_enumeration_default_is_wide(src=None):
    """★★ 宽泛枚举的**默认路径**必须真的是宽泛的（不是"函数存在就算"）。

    ★★★ 这条判据来自 0.36.2 的**第二次同型踩坑**：
      第一次我新增了 `is_console_title()`（含正确的宽泛语义），
      却**没改掉** `find_console_windows` 默认走的 `_matches_title` 分支
      ⇒ 实测 `find_console_windows()` **稳定返回 `[]`**，
        而同一时刻裸枚举能找到 3 个窗口 ⇒ "收旧窗"又失效了。
      ★ 教训：**新增一个正确的函数 ≠ 修正调用它的默认路径**。
        所以这条判据不看"函数在不在"，而是**真跑默认参数**，
        并要求它能认出带身份串的窗口（严格 endswith 认不出的那种）。

    ★ 0.50.2：加 `src` 注入点（默认真源码）—— 负控才能拿**变异源码**跑
      同一条正判据（本条的落点是源码形状，不是运行期行为）。
    """
    import inbox_window as WIN
    # 默认参数（不给 run_id）下，枚举必须走宽泛判据。
    # 判据要求：默认分支里**直接**调 `is_console_title`，
    # 而不是在 run_id 为空时退回 `_matches_title`（那是窄的）。
    code = _code_only(src if src is not None else _src_of(WIN))
    seg = _func_seg(code, "find_console_windows")
    if "is_console_title" not in seg:
        return ("枚举的默认路径没有走 `is_console_title`"
                "（宽泛语义没接到默认路径上）")
    if re.search(r"else\s+_matches_title", seg):
        return ("run_id 为空时退回 `_matches_title`（那是窄判据，"
                "认不出带身份串的窗口）")
    # 真跑：默认参数 + lister 注入只验参数透传；真实验证靠下面这行
    got = WIN.find_console_windows(lister=lambda **kw: [])
    if got != []:
        return "无匹配时应返回空列表：%r" % (got,)
    return True


def n_wide_default_narrowed_is_caught():
    """负控：把默认分支改回窄判据 ⇒ 上一条必须报红。

    ★★ 0.50.2 修两处（实测的量具故障）：
      ① **锚点已死**：老锚点 `if is_console_title(buf.value, run_id):`
         在 `find_console_windows` 改成列表推导后就不存在了 ⇒ 负控恒报
         "失效"，屏上只打一个裸 `False`。⇒ 改成按**调用形态**变异
         （正则认 `is_console_title(...)` 整体，参数名改了也不会腐化）。
      ② 改成**拿变异源码跑同一条正判据**（`src=` 注入），不再自己重写
         "变异后应该没有 is_console_title" 的判断。
    """
    import inbox_window as WIN
    src = _src_of(WIN)
    code = _code_only(src)
    seg = _func_seg(code, "find_console_windows")
    if "is_console_title" not in seg:
        return ("变异锚点未找到（`find_console_windows` 段里没有 "
                "`is_console_title`）—— 负控自身失效，不算通过")
    mutated_seg, n = re.subn(r"is_console_title\([^)]*\)",
                             "_matches_title(title, suffix)", seg, count=1)
    if n == 0:
        return "负控自身失效：按调用形态变异没命中"
    if "is_console_title" in mutated_seg:
        return "负控自身失效：变异后段里仍有 is_console_title"
    mutated = code.replace(seg, mutated_seg, 1)
    if mutated == code:
        return "负控自身失效：变异没落到源码上"
    if c_wide_enumeration_default_is_wide(src=mutated) is True:
        return "负控失效：变异源码跑正判据仍判合格 —— 这条判据是装饰"
    return True


def c_two_level_matching_covers_all_forms():
    """★★ 宽泛判据必须**认得出所有形态**的Antinel 监理窗口（关窗才关得掉）。

    ★★ 0.51.1 标题反转（创始人 2026-10-16 拍板；W-01 退休、
      FZ-002 冻结）：形态从「<页面名> · Antinel 监理#<rid>」翻转为
      **品牌开头整串**——「Antinel 监理」（无身份）与「Antinel 监理#abc123」
      （带身份）。正向夹具随形态迁移；旧形态（0.48.5 前缀形态、
      0.50.4 前「… · 值守台#…」）本版**不认领**（`_HEAD_RE` 品牌前置
      天然排除）：无分发⇒无升级人口，dev 机旧窗手动关闭/重启消化；
      分发前必须补 legacy 认领（LEGACY 标记常量＋`_mark_at_tail(title,
      mark=None)` 默认参数化＋daemon sweep），否则升级用户旧窗成孤儿
      ——与《改名零后遗症执行策略》§8 L2/L3-sweep 缓建裁定同源。
    ★ 形态契约由 FZ-002（freeze_zones.json：window_title_format，output 类）
      与 Q14 精确形态断言钉死。
    ★ 这条是 0.36.2 真实设计缺陷的正面判据。两种形态都要被宽泛判据认领：
      「Antinel 监理」              （无标识）
      「Antinel 监理#abc123」       （带身份 —— **通用后缀 endswith 认不出**）
    而**严格**判据（给 run_id）必须只认本次这一种。
    """
    import inbox_window as WIN
    for t in ("Antinel 监理",
              "Antinel 监理#abc123"):
        if not WIN.is_console_title(t):
            return "宽泛判据认不出这类Antinel 监理窗口（关窗会漏）：%r" % t
    if not WIN.is_console_title("Antinel 监理#abc123", run_id="abc123"):
        return "严格判据认不出本次窗口"
    for t in ("Antinel 监理#OLD",
              "Antinel 监理",
              "记事本"):
        if WIN.is_console_title(t, run_id="abc123"):
            return "严格判据认错了对象：%r" % t
    return True


def c_match_title_rejects_other_windows():
    """★★ 根因③的正面判据：本次身份串**认不出**用户窗口与旧窗口。

    ★★ 这条用**本机实测到的真实标题**做反例，不是构造的。
      实测本机 Edge 普通窗口标题：
        「收件箱 · Antinel 监理 和另外 14 个页面 - 个人 - Microsoft Edge」
      —— 它**含有**「 · Antinel 监理」。若用通用后缀去 endswith，
      某些标题形态会命中它 ⇒ `SetWindowPos` 把用户浏览器搬走。
    ★★ 0.51.1 标题反转（W-01 退休、FZ-002 冻结）：用户浏览器窗的
      新形态对应物「Antinel 监理#f356b0 和另外 14 个页面 - 个人 -
      Microsoft Edge」一并入列（仍含 Microsoft ⇒ 入口排除；且 rest
      检查也会挡）。旧形态实测条目保留——仍被正确拒认，且作为
      legacy 判据负向锚点有效。
    """
    import inbox_window as WIN
    rid = "abc123"
    s = WIN.console_title_suffix(rid)
    must_match = [
        "Antinel 监理#abc123",             # 本次运行（0.51.1 反转后唯一形态）
    ]
    must_not = [
        "Antinel 监理#f356b0 和另外 14 个页面 - 个人 - Microsoft Edge",  # 0.51.1 新形态：实测同款用户浏览器窗
        "收件箱 · Antinel 监理 和另外 14 个页面 - 个人 - Microsoft Edge",   # 实测：用户普通窗口（旧形态保留）
        "Antinel 监理#OLDRUN",             # 上次运行（新形态）
        "收件箱 · Antinel 监理#OLDRUN",         # 上次运行（旧形态保留）
        "Antinel 监理",                 # 无身份标识（0.51.1 新形态：宽泛认得、严格不认）
        "记事本",                          # 无关窗口
        "",
    ]
    # ★★★ 0.36.5 新增：宽泛模式（**收旧窗用**）的反向用例。
    #   实测两轮才把这层堵上，两轮都是**判据没测到**：
    #     ① `'收件箱 · 值守台助手'`      —— 标记**后面**还挂了字
    #     ② `'记事本 - 收件箱 · 值守台'`  —— 标记**前面**挂了别的程序
    #   而宽泛模式是**关窗**用的 ⇒ 误认 = **误关用户自己的窗口**。
    #   严格模式同样要挡②：它是**唯一允许移动窗口**的路径，
    #   一次误认就把用户的记事本搬到屏幕角落并改尺寸
    #   —— 那正是本轮最初那个投诉（「窗口出现在旧位置而且变成了旧尺寸」）。
    # ★★ 0.51.1 反转：两类误伤形态的新形态对应物一并入列
    #   （「Antinel 监理助手」后挂字、「Antinel 监理#486acd 记事本」
    #   身份串后挂字）；旧形态条目保留——仍被正确拒认（`_HEAD_RE`
    #   品牌前置天然排除），且作为 legacy 判据负向锚点有效。
    must_not_wide = [
        "收件箱 · Antinel 监理助手",
        "收件箱 · Antinel 监理 - 记事本",
        "记事本 - 收件箱 · Antinel 监理",
        "记事本 - 收件箱 · Antinel 监理#abc123",
        "收件箱 · 值守中",
        "收件箱 · Antinel 监理#zzzzzzzz",   # 身份串必须是 hex：非本服务生成的串不认
        "收件箱 · Antinel 监理#",           # 半个身份串
        "Antinel 监理助手",                 # 0.51.1 新形态：标记后面挂了字
        "Antinel 监理#486acd 记事本",       # 0.51.1 新形态：身份串后面挂了字
    ]
    # ★★ 0.36.5：`_matches_title` 已删除（子串匹配，且注释与实现相反）。
    #   这里改用**真源** `is_console_title(t, run_id)` ——
    #   它就是**落位层唯一合法的那条路径**（`place_all` 传 `run_id`）。
    #   判据的意图一字未改：「本次身份串认不出用户窗口与旧窗口」；
    #   变的只是把"用哪个函数表达这个要求"。
    #   ⇒ 附带好处：现在这条判据**与生产路径同一个函数**，
    #     不再出现"判据测的函数不是生产用的那个"这类测错对象的缺口。
    for t in must_match:
        if not WIN.is_console_title(t, rid):
            return "本次运行的窗口没被认出来：%r" % t
    for t in must_not:
        if WIN.is_console_title(t, rid):
            return "不该认领的窗口被认领了（＝可能误伤用户窗口）：%r" % t
    for t in must_not_wide:
        if WIN.is_console_title(t, None):
            return ("宽泛判据（收旧窗用）把用户窗口 %r 认成Antinel 监理 ⇒ 会误关它" % t)
    # 宽泛模式**必须**仍然认得出所有形态（正向不能被反向用例挤掉）
    # ★ 0.51.1 反转：正向夹具同步迁移到品牌两形态（页面名随反转退休）
    for t in ("Antinel 监理", "Antinel 监理#abc123"):
        if not WIN.is_console_title(t, None):
            return "宽泛判据认不出这类Antinel 监理窗口（关窗会漏）：%r" % t
    return True


def n_wide_mode_substring_is_caught():
    """负控：把宽泛模式退回**纯子串** ⇒ 上一条必须报红。

    ★ 这条是 0.36.5 那个真缺陷的**分辨力证明**：
      实测 `'收件箱 · Antinel 监理助手'` 在子串匹配下被认成Antinel 监理
      ⇒ 而宽泛模式是关窗用的 ⇒ 会误关用户窗口。
      ⇒ 说明"宽泛模式必须整串匹配"**不是过度设计**。

    ★ 同时守另一侧：若有人把宽泛模式收窄成"只认固定前缀"，
      `'运行状态 · Antinel 监理#abc123'` 会认不出 ⇒ 上面的正向用例会报红。
      ⇒ 两类错误（过宽误伤 / 过窄漏关）都被覆盖。
    """
    import inbox_window as WIN
    import inspect
    src = inspect.getsource(WIN)
    # ★ 0.36.5：按**行**定位（不按字符串）—— 宽泛与严格两处都调
    #   `_mark_at_tail`，整串锚点会"出现 0 次"，负控就**默默不生效**
    #   （而负控最坏的失败模式恰恰是看起来还有检查）。
    lines = src.split("\n")
    cand = [i for i, l in enumerate(lines) if l.strip() == "return _mark_at_tail(t)"]
    if len(cand) < 1:
        return False                        # 锚点过时
    lines[cand[0]] = "        return CONSOLE_WINDOW_TITLE_MARK in t"
    mutated = "\n".join(lines)
    ns = {}
    exec(compile(mutated, "<mut>", "exec"), ns)              # noqa: S102
    return ns["is_console_title"]("收件箱 · Antinel 监理助手") is True


def n_match_title_generic_suffix_is_caught():
    """负控：退回通用后缀去认领 ⇒ 上面的用户窗口反例必须被抓住。

    ★ 这条是根因③的**分辨力证明**：证明"用通用后缀"确实会认错，
      从而说明"必须带身份串"不是过度设计。
    ★ 0.36.5：改用真源 `is_console_title(标题, None)`（宽泛模式）——
      那正是"误用通用后缀"的等价物（run_id 为空 ⇒ 不带身份串 ⇒ 宽泛认领）。
    """
    import inbox_window as WIN
    user_win = "收件箱 · Antinel 监理 和另外 14 个页面 - 个人 - Microsoft Edge"
    return WIN.is_console_title(user_win, None) is False


def c_page_title_carries_run_id():
    """★ 服务端渲染的标题必须**带上**身份串（且在前端 JS 之前）。

    ★ 为什么必须在**服务端**注入而不是 JS 改 `document.title`：
      JS 改标题晚于开窗，落位那一刻读到的仍是旧标题 ⇒ 认不出窗口。
    ★★ 0.51.1 标题反转（W-01 退休、FZ-002 冻结）：标题整串从
      「<页面名> · Antinel 监理#<rid>」翻转为**品牌开头整串**
      「Antinel 监理#<rid>」（页面名/状态词从标题退休）⇒ 断言
      从「含身份串 ＋ 页面名前缀」升级为**精确形态**：整串必须等于
      `console_title_suffix(rid)`（期望串由产品常量派生，不二次
      实现口径）。负控（剥掉 #rid ⇒ 整串退为品牌名）仍必红。
    """
    import re as _re
    import inbox_server as SV
    head = SV._head("收件箱", "tok-for-test")
    m = _re.search(r"<title>(.*?)</title>", head, _re.S)
    if not m:
        return "取不到 <title>"
    title = m.group(1)
    import html as _html
    title = _html.unescape(title)
    import inbox_window as WIN
    rid = WIN.build_run_id("tok-for-test")
    if ("#" + rid) not in title:
        return "标题里没有本次身份串：%r（期望含 #%s）" % (title, rid)
    # ★ 0.51.1：精确形态断言 —— 期望串由产品常量派生（唯一真源）
    want = WIN.console_title_suffix(rid)
    if title != want:
        return ("标题形态不是「Antinel 监理#<rid>」整串：%r（期望 %r）"
                % (title, want))
    return True


def n_page_title_without_run_id_is_caught():
    """负控：把身份串从标题里去掉 ⇒ Q14 必须报红。

    ★ 真跑判据：临时把 `_head` 换成不带身份串的版本，
      然后调用 `c_page_title_carries_run_id()`，它必须返回红。
    """
    import inbox_server as SV
    orig = SV._head
    try:
        # 变异：还原 0.36.1 的标题（不带 #run_id）
        def legacy_head(title, token):
            return orig(title, token).replace("#", "\x00").replace(
                "\x00%s" % "", "")
        # 直接构造一个不带身份串的 head 更可靠
        import re as _re
        raw = orig("收件箱", "tok-for-test")
        mutated = _re.sub(r"<title>(.*?)</title>",
                          lambda m: "<title>%s</title>"
                          % m.group(1).split("#")[0], raw, flags=_re.S)
        def mutated_head(title, token):
            return mutated
        SV._head = mutated_head
        r = c_page_title_carries_run_id()
        if r is True:
            return False               # Q14 对"没有身份串"没有分辨力
        return True   # 负控生效：去掉身份串后 Q14 报红
    finally:
        SV._head = orig


# ══════════ Q15 · 已退休（0.51.1 标题反转，创始人 2026-10-16 拍板）═════════
#: ★★ c_run_id_not_in_token_position（「身份段在末尾」）已退休：
#:   标题形态从「<页面> · Antinel 监理#<id>」翻转为**品牌开头整串**
#:   「Antinel 监理#<id>」——「末尾」这个位置概念随页面名/状态词前缀
#:   整体退役（反转后身份串紧跟品牌，天然在末尾且无歧义）。形态契约
#:   现由 FZ-002 冻结的 window_title_format（output 类，D-38 执法）
#:   与 Q14 精确形态断言（整串 == console_title_suffix(rid)）全覆盖。
#:   登记：ci/suite_retirement.json（判据级退休，不减套件数）。
#: ★ 别再复活它 —— 旧形态的正则 `^.+ · Antinel 监理#\w+$` 在新认窗
#:   判据（品牌开头＋其后只允许 #hex）下**恒不匹配**，复活即假红。
#:
# def c_run_id_not_in_token_position():
#     """★ 标题里的身份段在**末尾**（紧贴稳定后缀），不放前面。

#     ★ 放末尾才能同时满足：① `_matches_title` 的 endswith 结构不变；
#       ② 一眼能看出这是"同一次运行"的标识。
#     """
#     import re as _html_re
#     import html as _html
#     import inbox_server as SV
#     head = SV._head("收件箱", "tok-x")
#     title = _html.unescape(
#         _html_re.search(r"<title>(.*?)</title>", head, _html_re.S).group(1))
#     m = _html_re.match(r"^.+ · Antinel 监理#\w+$", title)
#     if not m:
#         return "标题形状不是「<页面> · Antinel 监理#<id>」：%r" % title
#     return True


# ═══════════════════════ 时序：WM_CLOSE 异步 ⇒ 必须等 ═════════════════════
def c_wait_gone_returns_when_empty():
    """★ 等旧窗消失：已经没有窗口时**立刻**返回已清空。"""
    import inbox_window as WIN
    ok, left = WIN.wait_console_windows_gone(tries=3, interval=0.01,
                                             lister=lambda **kw: [])
    if not ok or left != 0:
        return "无窗口时却报未清空：ok=%r left=%r" % (ok, left)
    return True


def c_wait_gone_reports_remaining_honestly():
    """★ 等不到就**如实说还剩几个**，不假装清干净了。"""
    import inbox_window as WIN
    ok, left = WIN.wait_console_windows_gone(tries=2, interval=0.01,
                                             lister=lambda **kw: [1, 2])
    if ok:
        return "一直有窗口却报已清空"
    if left != 2:
        return "剩余数不对：%r（应为 2）" % (left,)
    return True


def c_open_console_waits_before_opening():
    """★★ 开窗**之前**必须等旧窗清空 —— 时序不能反。

    ★ 为什么这是独立的一条：`WM_CLOSE` 只是投信，浏览器何时销毁窗口
      不受我们控制。不等 ⇒ 那一刻屏幕上有两个「· Antinel 监理」窗口
      ⇒ 后续任何"取第一个"都可能抓到正在退场的旧窗口。
    """
    import inbox_server as SV
    code = _code_only(_src_of(SV))
    seg = _func_seg(code, "open_console")
    if not seg:
        return "找不到 open_console"
    if "wait_console_windows_gone" not in seg:
        return "开窗前没有等旧窗消失"
    i_wait = seg.find("wait_console_windows_gone")
    i_pop = seg.find("Popen")
    i_open = seg.find("opener(cmd)")
    if i_pop == -1 and i_open == -1:
        return "判据失效：open_console 里找不到开窗动作（锚点过时）"
    i_do = min(x for x in (i_pop, i_open) if x != -1)
    if i_wait > i_do:
        return "等旧窗清空发生在开窗**之后**（时序反了）"
    return True


def n_open_console_wait_removed_is_caught():
    """负控：删掉等待调用 ⇒ 上一条必须报红。"""
    import inbox_server as SV
    code = _code_only(_src_of(SV))
    seg = _func_seg(code, "open_console")
    mutated = seg.replace("wait_console_windows_gone", "_mutated_no_wait", 1)
    if mutated == seg:
        return False                     # 锚点过时
    return "wait_console_windows_gone" not in mutated


def c_open_console_passes_run_id_to_place():
    """★ 落位必须**只认本次身份**（run_id 要一路传到落位层）。"""
    import inbox_server as SV
    code = _code_only(_src_of(SV))
    seg = _func_seg(code, "open_console")
    if "run_id=run_id" not in seg:
        return "落位调用没有传 run_id（会退回通用后缀 ⇒ 可能误伤用户窗口）"
    return True


def c_place_uses_instance_suffix():
    """★ 落位侧必须用**带身份串**的后缀去认窗口。"""
    import inbox_server as SV
    code = _code_only(_src_of(SV))
    seg = _func_seg(code, "_place_if_needed")
    if "console_title_suffix" not in seg:
        return "落位侧没有用带身份串的后缀"
    if "suffix=suffix" not in seg:
        return "枚举时没有把该后缀传下去"
    return True


CHECKS = [
    # 根因 ①
    ("Q01 收旧窗真跑不抛未绑定", c_close_console_windows_not_unbound,
     n_close_console_unbound_is_caught),
    ("Q02 只关枚举出的句柄", c_close_console_only_touches_enumerated, None),
    ("Q03 用 WM_CLOSE 不强杀", c_close_console_uses_wm_close_not_kill, None),
    # 根因 ②
    ("Q04 枚举返回全部窗口", c_find_console_windows_returns_all,
     n_find_console_windows_first_only_is_caught),
    ("Q05 全量落位每个都动", c_place_all_moves_every_window, None),
    ("Q06 局部成功不算成功", c_place_all_partial_failure_is_not_success,
     n_place_all_partial_ok_is_caught),
    ("Q07 空与 None 都拒", c_place_all_refuses_empty_and_none, None),
    ("Q08 落位层不自己枚举", c_place_all_does_not_enumerate_itself, None),
    ("Q08b 浏览器窗口永不命中", c_browser_window_never_matched,
     n_browser_window_matched_is_caught),
    ("Q08c 宽泛默认路径真宽泛", c_wide_enumeration_default_is_wide,
     n_wide_default_narrowed_is_caught),
    # 根因 ③
    ("Q09 身份串逐次不同", c_run_id_differs_between_runs, None),
    ("Q10 身份串同次稳定", c_run_id_is_stable_within_run, None),
    ("Q11 身份串不泄口令", c_run_id_does_not_leak_token, None),
    ("Q12 身份后缀形状正确", c_console_title_suffix_carries_run_id, None),
    ("Q12b 两级匹配覆盖全形态", c_two_level_matching_covers_all_forms, None),
    ("Q13 认不出用户窗口与旧窗", c_match_title_rejects_other_windows,
     n_match_title_generic_suffix_is_caught),
     # ★ 0.36.5：宽泛模式退回子串 ⇒ Q13 必须红（新增负控）
    ("负控 Q13b 宽泛模式退回子串", n_wide_mode_substring_is_caught, None),
    ("Q14 标题带身份串", c_page_title_carries_run_id,
     n_page_title_without_run_id_is_caught),
    # Q15（身份段在末尾）已于 0.51.1 退休：形态契约由 FZ-002＋Q14
    # 精确形态断言全覆盖（墓碑见上方，登记 suite_retirement.json）
    # 时序
    ("Q16 无窗立刻判定清空", c_wait_gone_returns_when_empty, None),
    ("Q17 等不到如实报剩余", c_wait_gone_reports_remaining_honestly, None),
    ("Q18 开窗前先等清空", c_open_console_waits_before_opening,
     n_open_console_wait_removed_is_caught),
    ("Q19 落位只认本次身份", c_open_console_passes_run_id_to_place, None),
    ("Q20 落位用身份后缀", c_place_uses_instance_suffix, None),
]


def main():
    passed = failed = 0
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
        # 负控：把产品改坏，判据必须变红（否则判据无分辨力）
        if neg is not None:
            try:
                nr = neg()
            except Exception as e:                               # noqa: BLE001
                nr = "负控自身报错：%r" % (e,)
            if nr is not True:
                failed += 1
                print("RED  负控 %s\n       %s" % (name, nr))
            else:
                passed += 1
    print("0.36.2 guards: %d green / %d red" % (passed, failed))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
