#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.43.1 判据 —— **右下冒泡根治（十维）**：通知不许撒谎、不许重复、不许各自为政；
外加**状态判据**三维（研发态必须可达 S67；其根因 S69「构建产物不许冒充手工承载件」
不许被改回去；**S70 研发态的"可达性"本身要被守** —— 0.50.3 补，见下）。

★★ 这一份判据的由来（2026-10-10 实测「右下冒泡」复发，非推演）：

    当天 11:11:47 一条 `host_shield_tamper`（`field=enabled`、`subkind=state_drift`、
    **`recovered=true`**）被弹了泡 —— 而它描述的事**已经自愈**（监理按链权威回写恢复），
    Antinel 监理早就按 `recovered` 把它降到 L1（`inbox_model.level_of_record`）；
    同一时刻 `guard_posture()` 是 **guarding（值守中）**。
    ⇒ **通知在说「失守」，事实是「值守中」。通知与事实相反。**

    这不是"偶发"，是三条**互不相干**的发射路径各自演化的必然：
      · `host_shield._notify`（监理事件）—— 图标随姿态（0.36.5 修过）；
      · `hooks/pre_tool_use.notify_owner`（拦截事件）—— 自己 spawn 一份 PowerShell，
        图标**写死 `SystemIcons.Warning`**（0.36.5 的图标修复只改到了另一份）；
      · `inbox_notify.toast`（Antinel 监理，WinRT，落操作中心）。
    ⇒ 「修好一处、漏掉另一处」的标准形状；且**判定名单**（`_ALERT_KINDS`）
      是"按类型一刀切"，**不看 `recovered`**。

  ★ 编写纪律（沿用 `inbox_guards_0430.py`）：
    · 每条判据配负控，且负控**真的会红**（内存变异源码后重载，不是"算一遍就丢"）；
    · 判据**只查行为/结构**，不查文案 —— 凡按源码字面查的，一律走 **AST**；
    · **不写任何产品文件**：变异只发生在内存字符串上，磁盘一个字节都不动。
"""
from __future__ import annotations

import ast
import io
import os
import re
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

RESULTS = []


class Skip(Exception):
    """夹具凑不齐（例：本机没有 git / 不在工作树里）⇒ **不判**，也**不许判绿**。"""


def check(name):
    """★ 判据**必须真会红** —— 返回说明串一律转成抛异常；`SKIP` 前缀转 Skip。"""
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


def _func_src(src, name):
    """抠出某个**顶层函数**的源码（AST 行号，不靠正则 —— 正则一遇缩进就漂）。"""
    tree = ast.parse(src)
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(src, n)
    return None


def _load_decision(src=None):
    """把（可能被变异过的）`bubble_decision` 单独加载成可调用对象。

    ★ 为什么只抠这一个函数：它只依赖 `_ALERT_KINDS` 一个常量
      ⇒ 可以在**干净命名空间**里 exec，不必把整个 host_shield 拖进来
      （拖进来会连带跑模块级副作用，量具反而更脆）。
    """
    if src is None:
        src = _src("host_shield.py")
    fs = _func_src(src, "bubble_decision")
    if not fs:
        raise AssertionError("host_shield.py 里找不到 bubble_decision（唯一真源不见了）")
    ns = {}
    # `_ALERT_KINDS` 从真源码里抠（避免这里再写一份名单 —— 那就是第二套口径）
    m = re.search(r"^_ALERT_KINDS = (\{.*?\})\s*$", src, re.M | re.S)
    if not m:
        raise AssertionError("找不到 _ALERT_KINDS 定义")
    ns["_ALERT_KINDS"] = eval(m.group(1))                       # noqa: S307
    exec(compile(fs, "<bubble_decision>", "exec"), ns)          # noqa: S102
    return ns["bubble_decision"]


# ══════════════════ 维度一／九 · 触发源：自愈事件不许再冒泡 ══════════════════
@check("S60 ★ 自愈（recovered=true）⇒ 不冒泡；真失守（recovered≠true）⇒ 仍冒泡")
def s60():
    dec = _load_decision()
    if dec("host_shield_tamper", {"recovered": True, "severity": "critical"})[0] is not False:
        return "自愈事件仍被判为要冒泡 —— 通知会与事实相反（本次复发的真身）"
    if dec("host_shield_tamper", {"recovered": False, "severity": "critical"})[0] is not True:
        return "把真失守也压掉了 —— 一刀切，方向错（宁可多弹不可漏报）"
    if dec("host_shield_tamper", {"severity": "critical"})[0] is not True:
        return "recovered 缺省（未知）被当成已自愈 —— 方向必须收紧（未知按有后果）"
    return True


@check("N-S60 负控：抽掉 recovered 判断 ⇒ S60 必须报红")
def n_s60():
    src = _src("host_shield.py")
    old = '    if rec.get("recovered") is True:\n        return False, "已自愈（recovered=true，无后果；Antinel 监理仍收）"\n'
    if old not in src:
        return "负控无效：找不到 recovered 判断锚点（判据与源码已失配）"
    mut = src.replace(old, "", 1)
    if mut == src:
        return "负控无效：变异没生效"
    dec = _load_decision(mut)
    if dec("host_shield_tamper", {"recovered": True, "severity": "critical"})[0] is not True:
        return "负控失效：抽掉 recovered 判断后判据仍绿 —— S60 分辨不出这次复发"
    return True


# ══════════════════ 维度二／三 · 通道唯一 ＋ 图标不撒谎 ══════════════════
def _native_ui_sources(root=None, tokens=None):
    """真正**发射原生外观**的产品文件（AST：非 docstring 的字符串常量含任一 token）。

    ★ 走 AST 而不用子串搜索：docstring 里提到这些名字是**讲历史**，
      子串搜索会把"讲历史"读成"还有一个发射者" —— 量具的错不能记成产品的错。
    ★ 扫描面＝仓根全部 .py ＋ hooks/ 全部 .py：像素可以从任何随包模块产生，
      只看一个目录等于给第二条通道留门（本仓复发过七次，全是"改一处漏一处"）。
    """
    # ★ 口径只看**外观**，不看"响"：`System.Media.SystemSounds` 走的是
    #   `System.Windows.Forms` 这个程序集名，但它不画任何像素（只是发声），
    #   把它算成"又一个外观实现"会让判据过宽 ⇒ 假红，进而被人加豁免。
    tokens = tokens or ("ShowBalloonTip(", "ToastNotificationManager",
                        "BurntToast",
                        "System.Windows.Forms.NotifyIcon",
                        "System.Windows.Forms.Form",
                        "New-Object System.Windows.Forms")
    base_root = root or ROOT
    hits = []
    for base in (base_root, os.path.join(base_root, "hooks")):
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            if not name.endswith(".py") or name.startswith("_"):
                continue
            p = os.path.join(base, name)
            try:
                tree = ast.parse(io.open(p, encoding="utf-8").read())
            except Exception:                                    # noqa: BLE001
                continue
            docs = set()
            for n in ast.walk(tree):
                if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef)) \
                        and n.body and isinstance(n.body[0], ast.Expr) \
                        and isinstance(n.body[0].value, ast.Constant) \
                        and isinstance(n.body[0].value.value, str):
                    # ★ 两个 id 都要登记：`Expr` 本身，**以及它的 `Constant` 子节点**
                    #   —— ast.walk 走到的是后者；只登记前者等于没排除。
                    docs.add(id(n.body[0]))
                    docs.add(id(n.body[0].value))
            for n in ast.walk(tree):
                if id(n) in docs:
                    continue
                if isinstance(n, ast.Constant) and isinstance(n.value, str) \
                        and any(t in n.value for t in tokens):
                    hits.append(os.path.relpath(p, base_root).replace("\\", "/"))
                    break
    return sorted(set(hits))


@check("S61 ★ 零原生发射口：全仓不许再自己拼系统托盘气泡／系统通知；像素只许由品牌化浮窗产生")
def s61():
    hits = _native_ui_sources()
    if hits:
        return ("仍有原生外观发射实现 %r —— 这正是「上古泡泡」的真身：它不需要 Edge、"
                "不需要端口、不需要窗口就位，比品牌化提醒容易赢；"
                "留着它等于给下一次复发留入口（0.59.0 已连根去除，本条守的是"
                "「别加回来」）" % (hits,))
    bb = os.path.join(ROOT, "inbox_bubble.py")
    if not os.path.exists(bb):
        return "唯一像素出口不见了：inbox_bubble.py 不存在"
    if "def pop(" not in io.open(bb, encoding="utf-8").read():
        return "inbox_bubble.py 里没有 pop() —— 品牌化浮窗的唯一发射点没了"
    # ★ 可读性正控：0 处命中必须能证明"真的扫过面"，否则"没有违规"与"没扫"同貌
    if not os.path.exists(os.path.join(ROOT, "inbox_daemon.py")):
        return "扫描面异常：inbox_daemon.py 不在 ⇒ 这次的 0 处不可信"
    return True


@check("N-S61 负控：塞一个自己拼系统通知的文件 ⇒ 扫描必须抓到（不是恒绿）")
def n_s61():
    import shutil
    import tmpreg as _TMP
    d = _TMP.tmpdir("n61_")
    try:
        os.makedirs(os.path.join(d, "hooks"), exist_ok=True)
        io.open(os.path.join(d, "evil.py"), "w", encoding="utf-8").write(
            u'ps = "Add-Type -AssemblyName System.Windows.Forms;"\n'
            u'"$n.ShowBalloonTip(8000, 1, 2, 3)"\n')
        got = _native_ui_sources(root=d)
        if got != ["evil.py"]:
            return "负控失效：塞进去的自拼系统通知没被抓到（got=%r）" % (got,)
        # 第三条腿：**只写在 docstring 里**不算发射（防过宽 ⇒ 把讲历史判成产品缺陷）
        io.open(os.path.join(d, "hist.py"), "w", encoding="utf-8").write(
            u'"""讲历史：当年用过 ShowBalloonTip(15000) 和 System.Windows.Forms。"""\n'
            u'X = 1\n')
        got2 = _native_ui_sources(root=d)
        if got2 != ["evil.py"]:
            return "过宽：docstring 里讲历史也被判成发射者（got=%r）" % (got2,)
        return True
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _brand_ok(root=None):
    """品牌化浮窗是否成立：官方 LOGO ＋ 与主窗口同源的样式。返回 `(ok, why)`。"""
    root = root or ROOT
    bb = os.path.join(root, "inbox_bubble.py")
    if not os.path.exists(bb):
        return False, "inbox_bubble.py 不存在"
    src = io.open(bb, encoding="utf-8").read()
    missing = [m for m in ("_logo_mark", "FAVICON_LINK") if m not in src]
    if missing:
        return False, ("品牌化浮窗缺 %r —— 创始人 2026-10-27 明确：新提醒要跟主窗口"
                       "差不多、都带 Antinel 官方 LOGO" % (missing,))
    if "inbox_server" not in src:
        return False, "浮窗没有复用主窗口的样式与渲染（inbox_server）—— 那就是第二套外观"
    return True, ""


@check("S62 ★ 唯一像素出口必须是品牌化的：浮窗带官方 LOGO，且与主窗口同一套 CSS")
def s62():
    ok, why = _brand_ok()
    return True if ok else why


@check("N-S62 负控：把官方 LOGO 从浮窗里抹掉 ⇒ S62 必须报红")
def n_s62():
    import shutil
    import tmpreg as _TMP
    bb = os.path.join(ROOT, "inbox_bubble.py")
    src = io.open(bb, encoding="utf-8").read()
    if "_logo_mark" not in src:
        return "负控夹具不成立：源码里根本没有 _logo_mark"
    mut = src.replace("_logo_mark", "no_logo_here")
    if "_logo_mark" in mut:
        return "负控变异没生效"
    d = _TMP.tmpdir("n62_")
    try:
        io.open(os.path.join(d, "inbox_bubble.py"), "w", encoding="utf-8").write(mut)
        ok, _why = _brand_ok(root=d)
        if ok:
            return "负控失效：抹掉官方 LOGO 后仍判合格 —— S62 抓不到"
        return True
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ══════════════════ 维度四／五／六 · 去重口径与运行态 ══════════════════
@check("S63 ★ 可观测：气泡保护能自报（sent/shown/suppressed ＋ Antinel 监理在岗）")
def s63():
    import host_shield as HS
    for fn in ("bubble_self_report", "note_bubble_suppressed", "console_channel_status"):
        if not callable(getattr(HS, fn, None)):
            return "缺 %s —— 保护不能回答「我今天生效了吗」（交接件四件套第④件）" % fn
    rep = HS.bubble_self_report()
    for k in ("sent", "shown", "suppressed", "console"):
        if k not in rep:
            return "bubble_self_report 缺 %r" % k
    # 压制要真的记进通知账（不是只在内存里数一下）
    src = _src("host_shield.py")
    nt = _func_src(src, "_notify_throttled") or ""
    if "note_bubble_suppressed(" not in nt:
        return "_notify_throttled 压泡时没记账 —— 「生效了吗」答不出来"
    rec = _func_src(src, "record") or ""
    if "note_bubble_suppressed(" not in rec:
        return "record() 压泡时没记账 —— 自愈事件被压了多少次无从查证"
    return True


# ══════════════════ 维度七 · 数据口径：展示层字段不许留在安全状态 ══════════════════
@check("S64 ★ 展示层字段不得留在安全状态：写回时清掉已迁移的 notify_shown_in_window")
def s64():
    src = _src("host_shield.py")
    if "_LEGACY_STATE_KEYS" not in src or "notify_shown_in_window" not in src:
        return "没有清理机制 —— 旧展示层字段会一直躺在安全状态里（两套口径并存）"
    ss = _func_src(src, "save_state") or ""
    if "_LEGACY_STATE_KEYS" not in ss:
        return "save_state（唯一写入口）没有清旧字段 —— 清理点不在唯一入口上，必然漏"
    return True


# ══════════════════ 维度八 · 唯一真源：record 不许再内联"名单 + 静默" ══════════════════
@check("S65 ★ 该不该弹只有一个实现：record() 走 bubble_decision，且不再内联 _silent")
def s65():
    src = _src("host_shield.py")
    rec = _func_src(src, "record") or ""
    if "bubble_decision(" not in rec:
        return "record() 没走唯一真源 bubble_decision —— 判定又散回各处"
    if "_silent" in rec:
        return "record() 仍内联 _silent（第二套判定口径）—— 名单式判定会再次漂移"
    return True


# ══════════════════ 维度九 · 根因可查：拒写必须出声 ══════════════════
@check("S66 ★ 拒写必须出声：按字段更新被拒写时进链留痕（不许静默）")
def s66():
    src = _src("host_shield.py")
    usf = _func_src(src, "update_state_fields") or ""
    if "_state_write_refused(" not in usf:
        return "拒写分支静默 return False —— 一个保护会悄悄打掉另一个保护（纪律 10.12）"
    if "_note_state_write" not in src:
        return "没有状态写入时间序列 —— 交接件 §7.2 要求把「拒写/覆盖」两个候选分开，无从做起"
    return True


# ══════════════════ 维度十 · 状态判据：研发态必须可达（不许恒判失守）══════════════════
#
# ★★★ 由来（2026-10-10 创始人当场点名，实测复现，非推演）：
#   Antinel 监理显示 **失守（warn）**，而事实是"版本已升、还没重打包"的**正常迭代**。
#   根因＝**同一根因的两处叠加**（这就是"机制缺口"）：
#     ① 触发器「登记版本 ＜ 代码版本」被 `ci/version_check.py`
#        （10 处承载件逐字一致，`psl/manifest.json` 是其一）**结构性作废**
#        —— 升版必须把 manifest 的 version 也刷成同号 ⇒ 落差永远为 0；
#     ② `DEV_NEVER_EXEMPT_MARKS` 又把"链路文件哈希漂移"塞进永不豁免
#        —— 而链路文件每版都在改 ⇒ 第二道闸也判"不豁免"。
#   ⇒ 两条叠加 = 「研发中」这一档**长期不可达**，合法迭代必挂 R0 假失守。
#   ★ 同根已修过一处：`scripts/build_package.py::_self_bootstrap`（0.36.8）
#     早把触发器改成"哈希漂移也算自举"，**运行侧漏了**。

def _load_dev_exempt(src=None):
    """单独加载 `_dev_exempt_problems` ＋ 它的标记表（**从真源码抠**，不另写一份）。"""
    if src is None:
        src = _src("host_shield.py")
    fs = _func_src(src, "_dev_exempt_problems")
    if not fs:
        raise AssertionError("host_shield.py 里找不到 _dev_exempt_problems")
    m = re.search(r"^DEV_NEVER_EXEMPT_MARKS = \((.*?)\n\)", src, re.M | re.S)
    if not m:
        raise AssertionError("找不到 DEV_NEVER_EXEMPT_MARKS 定义")
    marks = eval("(" + m.group(1) + "\n)")                       # noqa: S307
    ns = {"DEV_NEVER_EXEMPT_MARKS": marks}
    exec(compile(fs, "<_dev_exempt_problems>", "exec"), ns)      # noqa: S102
    return ns["_dev_exempt_problems"], marks


def _load_is_dev_build(src=None, inst="1.0.0", code="1.0.0", problems=()):
    """把 `is_dev_build` 单独加载，依赖用**桩**喂进去，做**行为**断言。

    ★ 为什么用桩：真跑要读本机 manifest/版本，量具会跟着环境漂；
      本判据要钉的是**判据本身的逻辑**（"版本相等时到底看没看清单"）。
    """
    if src is None:
        src = _src("host_shield.py")
    fs = _func_src(src, "is_dev_build")
    if not fs:
        raise AssertionError("host_shield.py 里找不到 is_dev_build")
    _dep, _marks = _load_dev_exempt(src)

    def _ver_lt(a, b):
        try:
            return (tuple(int(x) for x in str(a).split("."))
                    < tuple(int(x) for x in str(b).split(".")))
        except Exception:                                        # noqa: BLE001
            return None
    ns = {"_installed_version": lambda: inst, "_code_version": lambda: code,
          "self_check": lambda: (False, list(problems)),
          "_dev_exempt_problems": _dep, "_ver_lt": _ver_lt}
    exec(compile(fs, "<is_dev_build>", "exec"), ns)              # noqa: S102
    return ns["is_dev_build"]


@check("S67 ★ 研发态触发器只认版本落差（不许拿'哈希漂移'替代 —— B1 撤回的红线）")
def s67():
    _P = ["host_shield.py 与 manifest 不符（运行代码可能被改）"]
    # ① 版本相等 + 清单漂移 ⇒ **不许**判研发态（已发版后改码＝按篡改报）
    #    ★ 这是 B1 撤回（0.40.0）与 0363 R06 / 0364 C3 共同钉住的同一件事：
    #      "已发版 + 码被改 ⇒ 不是 dev"，否则「我在写代码」成了篡改的免责理由。
    f = _load_is_dev_build(inst="1.0.0", code="1.0.0", problems=_P)
    ok, why = f()
    if ok is not False:
        return ("版本相等 + 清单漂移被判成研发态 ⇒ 「我在写代码」成了已发版包"
                "被篡改的免责理由（%s）" % why)
    # ② 版本落差存在 ⇒ **必须**判研发态（这才是合法迭代，研发态必须可达）
    f2 = _load_is_dev_build(inst="0.9.0", code="1.0.0", problems=_P)
    ok2, why2 = f2()
    if ok2 is not True:
        return "版本落差存在却判不出研发态 ⇒ 合法迭代挂 R0 假失守（%s）" % why2
    # ③ 登记版本**不低于**代码版本 ⇒ 仍不许研发态（方向往严的一边偏）
    f3 = _load_is_dev_build(inst="1.0.0", code="0.9.0", problems=_P)
    ok3, why3 = f3()
    if ok3 is not False:
        return "登记版本不低于代码版本却判研发态 ⇒ 方向没往严的一边偏（%s）" % why3
    return True


@check("N-S67 负控：给触发器塞一条'哈希漂移也算'捷径 ⇒ S67 必须报红")
def n_s67():
    src = _src("host_shield.py")
    fs = _func_src(src, "is_dev_build")
    old = "        newer = _ver_lt(inst, code)"
    if old not in fs:
        return "负控无效：找不到触发器锚点（判据与源码已失配）"
    new = ("        newer = _ver_lt(inst, code) or bool(\n"
           "            [p for p in self_check()[1] if '与 manifest 不符' in p])")
    mut = src.replace(fs, fs.replace(old, new, 1), 1)
    if mut == src:
        return "负控无效：变异没生效"
    f = _load_is_dev_build(src=mut, inst="1.0.0", code="1.0.0",
                           problems=["host_shield.py 与 manifest 不符（运行代码可能被改）"])
    if f()[0] is False:
        return "负控失效：塞进哈希漂移捷径后仍不判研发态 —— S67 是假绿"
    return True


@check("S68 ★ 登记表漂移仍永不豁免（数据面投毒不许被研发态吞掉）")
def s68():
    fn, marks = _load_dev_exempt()
    if not any("登记表" in m for m in marks):
        return "DEV_NEVER_EXEMPT_MARKS 里没有登记表标记 —— 保护面被删空"
    _fine, never = fn(["rules/hosts/autoclaw.json 与 manifest 不符（登记表可能被毒化）"])
    if not never:
        return "登记表漂移被归成可豁免 ⇒ 投毒面能被'我在写代码'吞掉（0.36.4 的洞重开）"
    return True


@check("N-S68 负控：删掉登记表标记 ⇒ S68 必须报红")
def n_s68():
    src = _src("host_shield.py")
    old = '    "与 manifest 不符（登记表可能被毒化）",'
    if old not in src:
        return "负控无效：找不到登记表标记锚点（判据与源码已失配）"
    mut = src.replace(old, "", 1)
    if mut == src:
        return "负控无效：变异没生效"
    fn, _marks = _load_dev_exempt(mut)
    _fine, never = fn(["rules/hosts/x.json 与 manifest 不符（登记表可能被毒化）"])
    if never:
        return "负控失效：删掉标记后仍判永不豁免 —— S68 抓不到保护面被删"
    return True


# ══════════════ 维度十一 · 根因：构建产物不许冒充手工承载件（0.43.1 根因修复）══════════════
#: 为什么单独一维（创始人 2026-10-10「目前状态是失守，这是不对的……是不是机制上有欠缺」）：
#:   研发态（S67）**可达**的前提是"版本落差存在"。而落差之所以长期为 0，根因**不在**
#:   `is_dev_build()`，在 `ci/version_check.py` —— 它把**构建产物** `psl/manifest.json`
#:   当成"10 处必须逐字一致的手工承载件"之一 ⇒ 每次升版被迫把 manifest 的 version
#:   也刷平 ⇒ 落差永远为 0。⇒ 修根＝把它从"逐字一致"集**摘出**，另立判据管它
#:   （「≤ 代码版本、不许超前」）。本维钉住"摘出"这件事**不被悄悄改回去**。
def _vc_manifest_carrier_fails(vc, av):
    """S69 的核心：构建产物不许再被当成手工承载件。返回错误串，或 None（通过）。"""
    m = re.search(r"^SPOTS = \[(.*?)^\]", vc, re.M | re.S)
    if not m:
        return "找不到 version_check.py 的 SPOTS 段（量具结构变了）"
    if "psl/manifest.json" in m.group(1):
        return ("psl/manifest.json 又回到'逐字一致'清单里 ⇒ 升版被迫刷平它 ⇒ "
                "is_dev_build 的版本落差永远为 0（研发态结构性失效复发）")
    if "_manifest_lag_fails" not in vc:
        return "version_check.py 没有 _manifest_lag_fails ⇒ 摘出后没有判据管它（单方面放松）"
    if "_manifest_lag_fails()" not in vc:
        return "_manifest_lag_fails 定义了却没接进 main()（有判据没人跑＝没判据）"
    mh = re.search(r"^_VERSION_HARD = \((.*?)^\)", av, re.M | re.S)
    if not mh:
        return "找不到 antinel_verify.py 的 _VERSION_HARD 段（量具结构变了）"
    if "psl/manifest.json" in mh.group(1):
        return "INV-3 的 HARD 侧仍收 psl/manifest.json ⇒ 与 version_check 分叉"
    return None


@check("S69 ★ 构建产物不再冒充手工承载件：manifest 不在'逐字一致'集，且另有判据管它")
def s69():
    err = _vc_manifest_carrier_fails(_src("ci/version_check.py"),
                                     _src("tools/antinel_verify.py"))
    return True if err is None else err


@check("N-S69 负控：把 manifest 塞回 SPOTS ⇒ S69 必须报红")
def n_s69():
    vc = _src("ci/version_check.py")
    av = _src("tools/antinel_verify.py")
    ins = ('    ("psl/manifest.json  version",\n'
           '     r\'"version"\\s*:\\s*"([^"]+)"\', 1),\n')
    mut = vc.replace("SPOTS = [\n", "SPOTS = [\n" + ins, 1)
    if mut == vc:
        return "负控无效：变异没生效"
    err = _vc_manifest_carrier_fails(mut, av)
    if err is None:
        return "负控失效：把 manifest 塞回 SPOTS 后 S69 仍不报红 —— S69 是假绿"
    return True


# ════════ 维度十二 · 研发态的**可达性**本身要被守（0.50.3 补，创始人 2026-10-14）════════
#: 为什么单开一维（**同一句话创始人说过两遍**，中间隔了四天 —— 这就是"旧病复发"）：
#:   2026-10-10：「目前状态是失守，这是不对的……是不是机制上有欠缺，给补上」
#:     ⇒ 0.43.1 判出**根因**在 `ci/version_check.py`（把构建产物 manifest 当手工承载件
#:       ⇒ 每次升版被迫把 manifest 的 version 刷平 ⇒ 落差恒为 0 ⇒ 研发态结构性失效），
#:       修法＝把它从"逐字一致"里**摘出**（S69 钉住"摘出不被改回去"）。
#:   2026-10-14：「这段词是旧病复发，显然缺乏目前的九维机制吧？……这是开发态，
#:                如果缺乏机制，也请修到位」—— 实测本机：
#:       `antinel.py VERSION = 0.48.4`，`psl/manifest.json version = 0.48.4` ⇒ **落差 = 0**
#:       ⇒ `is_dev_build()` 恒 False ⇒ 开发树上任何一次自检漂移都被渲染成
#:         **失守 ＋「这份守门的代码我认不出是不是出厂那份」**（两臂实测见下）。
#:
#:   ★★ 0.43.1 修对了**根因**，但只修了「**机制**」这一半，漏了「**可达性**」这一半：
#:      S67 验的是"**给定落差存在**，函数行为对不对"；S69 验的是"落差**能不能**存在"。
#:      两者都在**注入的版本号**上跑 —— **没有任何一条判据看这棵树自己**。
#:      ⇒ 于是"落差在这棵树上实际为 0"这件事，**没有任何东西会红**，
#:        只能靠创始人肉眼看见"失守"再回来报（本轮实测正是如此）。
#:      ⇒ 本维补的就是它：**研发树上，落差必须真实存在**（否则红，并给一条命令的出路）。
#:
#:   ★★★ 两臂实测（本机，`ci/inbox_guards_0431.py` 写之前先跑过一遍）：
#:     漂移 = `host_shield.py 与 manifest 不符（运行代码可能被改）`，自检强制为不符：
#:       A 落差存在（登记 0.48.4 ＜ 代码 0.50.3）⇒ posture=**dev**，灯=**研发中**（蓝）
#:       B 落差为 0（登记 0.50.3 ＝ 代码 0.50.3）⇒ posture=**warn**，灯=**失守**（红）
#:     B 的 `why` 与创始人截图**逐字相同**：
#:       「哨兵在岗，但这份守门的代码我认不出是不是出厂那份——可能被改动过，
#:         也可能是这次没装好。」
#:     ⇒ 这就是"失守"那条红字的**唯一来源**，也证明修法（把落差恢复）**对症**。
#:
#:   ★ 为什么"研发树"要**用 git 判**（而产品侧不许用 —— S27 的红线）：
#:     `is_dev_build()` 是**产品运行时代码**，它一旦用环境信号（`.git`／mtime），
#:     本机"跑哨兵的就是源码检出"⇒ 那条信号**恒真** ⇒ 已发版包被篡改也会被读成
#:     "研发中"（0.40.0 B1 撤回的正是这条）。**判据不是产品**：它在开发仓里跑，
#:     `git` 是"这棵树相对最近一次发布有没有差异"的**可靠读数**，不会恒真。
#:     ⇒ 产品侧继续只认版本落差（S67 守着），本判据负责**逼出**那个落差。
def _git_out(args):
    """跑一条 git 命令，返回 `(returncode, stdout.strip())`；跑不起来返回 `(None, "")`。"""
    import shutil
    import subprocess
    exe = shutil.which("git")
    if not exe:
        return None, ""
    try:
        p = subprocess.run([exe] + list(args), cwd=ROOT, capture_output=True,
                           timeout=30)
    except Exception:                                           # noqa: BLE001
        return None, ""
    return p.returncode, p.stdout.decode("utf-8", "replace").strip()


def _dev_tree_facts():
    """这棵树是不是"研发树"。返回 `(is_dev, 说明)`；判不了 ⇒ `(None, 原因)`（→ SKIP）。

    ★ 口径（**刻意用"相对最近一次发布"而不是"有没有脏文件"**）：
      提交完工作树也会变干净，可代码**照样**比登记的新 —— 只看脏文件会漏掉
      "已经 commit、还没发版"这个最常见的中段。⇒ 两个读数取**或**：
        · `git status --porcelain` 非空（有未提交/未跟踪改动）
        · `git diff --name-only <最近 tag> HEAD` 非空（已提交、但比上次发布新）
    """
    rc, inside = _git_out(["rev-parse", "--is-inside-work-tree"])
    if rc is None or inside != "true":
        return None, "本机没有 git，或这里不是一个 git 工作树（判不了 ⇒ 不判）"
    rc, dirty = _git_out(["status", "--porcelain"])
    if rc != 0:
        return None, "`git status` 跑不通（判不了 ⇒ 不判）"
    rc, tag = _git_out(["describe", "--tags", "--abbrev=0"])
    ahead = ""
    if rc == 0 and tag:
        rc2, ahead = _git_out(["diff", "--name-only", tag, "HEAD"])
        if rc2 != 0:
            return None, "`git diff %s HEAD` 跑不通（判不了 ⇒ 不判）" % tag
    else:
        # 一个 tag 都没有 ⇒ 从没发布过 ⇒ 整棵树都是"还没发出去"的
        tag = "(无 tag)"
    is_dev = bool(dirty) or bool(ahead)
    return is_dev, ("工作树相对 %s %s（未提交 %d 行、已提交未发布 %d 个文件）"
                    % (tag, "有差异 ⇒ 这是研发树" if is_dev else "无差异 ⇒ 不是研发树",
                       len(dirty.splitlines()), len(ahead.splitlines())))


def _dev_gap_fails(is_dev, inst, code):
    """S70 的核心（**纯函数，可注入**）：研发树上落差必须存在。返回错误串或 None。"""
    if not is_dev:
        return None                      # 不是研发树 ⇒ 不要求落差（已发版本来就相等）
    if not inst or not code:
        return ("这是研发树，却读不到版本对照（登记 %r／代码 %r）⇒ 研发态判据"
                "无法成立，任何自检漂移都会被读成失守" % (inst, code))
    try:
        sys.path.insert(0, ROOT)
        import host_shield as _HS
        newer = _HS._ver_lt(inst, code)
    except Exception as e:                                      # noqa: BLE001
        return "版本号比不了（%s vs %s，%s）⇒ 往严偏，判红" % (inst, code, type(e).__name__)
    if newer is None:
        return "版本号比不了（%s vs %s）⇒ 往严偏，判红" % (inst, code)
    if not newer:
        return ("**研发态判据在这棵树上结构性失效**：工作树是研发树，而版本落差为 0"
                "（登记 %s ≮ 代码 %s）⇒ `is_dev_build()` 恒 False ⇒ 任何自检漂移"
                "都会被渲染成**失守 ＋「这份守门的代码我认不出是不是出厂那份」**"
                "（创始人 2026-10-14 截图那条）。出路（一条命令）："
                "`python ci/bump_version.py %s --apply` —— 只升九处承载件，"
                "`psl/manifest.json` 保持落后，落差即恢复。"
                % (inst, code, code))
    return None


@check("S70 ★ 研发树上版本落差必须存在（否则研发态判据结构性失效 ⇒ 自检漂移被读成失守）")
def s70():
    is_dev, why = _dev_tree_facts()
    if is_dev is None:
        return "SKIP：%s" % why
    import host_shield as HS
    err = _dev_gap_fails(is_dev, HS._installed_version(), HS._code_version())
    if err:
        return err
    # 连带对照：落差真的被**用上**了 —— `is_dev_build()` 必须判得出研发态。
    #   （只查"落差存在"不够：函数里任何一处早退都会让落差白存在。）
    ok, dev_why = HS.is_dev_build()
    if is_dev and ok is not True:
        return ("落差存在，`is_dev_build()` 却仍判 False（%s）⇒ 研发态**不可达**，"
                "落差白存在（自检一漂移就掉回失守）" % dev_why)
    return True


@check("N-S70 负控：研发树 + 落差为 0 ⇒ 同一条尺子必须判红")
def n_s70():
    # ① 反空转：正例（研发树 + 落差）必须**不红**，否则负控没有分辨力
    if _dev_gap_fails(True, "0.48.4", "0.50.3") is not None:
        return "夹具不成立：研发树 + 有落差被判红，负控无分辨力"
    # ② 非研发树（已发版）⇒ 落差为 0 也**不该**红（方向不许往另一头偏）
    if _dev_gap_fails(False, "0.50.3", "0.50.3") is not None:
        return "非研发树 + 无落差被判红 ⇒ 尺子误伤已发版形态"
    # ③ 变异：研发树 + 落差 0 ⇒ 必红，且必须报出"研发态判据结构性失效"
    why = _dev_gap_fails(True, "0.50.3", "0.50.3")
    if why is None:
        return "负控失效：研发树 + 落差 0 仍判合格 —— 这条尺子是装饰"
    if "结构性失效" not in str(why):
        return "负控方向不对：报的不是'研发态判据结构性失效'（报的是 %r）" % (why,)
    # ④ 变异：落差**反向**（登记 ＞ 代码）同样必红
    if _dev_gap_fails(True, "0.50.3", "0.48.4") is None:
        return "负控失效：登记版本超前代码版本仍判合格 —— 方向没往严的一边偏"
    return True


def main():
    print("=" * 78)
    print("0.43.1 判据 —— 右下冒泡根治（十维）：不撒谎 / 不重复 / 单一通道 / 可观测 / 研发态可达")
    print("（＋0.50.3 S70：研发态在这棵树上的**可达性**必须被守 —— 落差为 0 即红，并给出路）")
    print("（全部内存变异，不写任何产品文件）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                why = ""
            print("  ✅ %-58s %s" % (name, why or ""))
            ok += 1
        except AssertionError as e:
            print("  ❌ %-58s %s" % (name, e))
            fail += 1
        except Skip as s:
            print("  ⏭️  %-58s %s" % (name, s))
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-58s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
