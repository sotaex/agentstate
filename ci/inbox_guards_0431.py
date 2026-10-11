#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.43.1 判据 —— **右下冒泡根治（十维）**：通知不许撒谎、不许重复、不许各自为政；
外加**状态判据**两维（研发态必须可达 S67；且其根因 S69「构建产物不许冒充手工承载件」
不许被改回去）。

★★ 这一份判据的由来（2026-10-10 实测「右下冒泡」复发，非推演）：

    当天 11:11:47 一条 `host_shield_tamper`（`field=enabled`、`subkind=state_drift`、
    **`recovered=true`**）被弹了泡 —— 而它描述的事**已经自愈**（哨兵按链权威回写恢复），
    值守台早就按 `recovered` 把它降到 L1（`inbox_model.level_of_record`）；
    同一时刻 `guard_posture()` 是 **guarding（值守中）**。
    ⇒ **通知在说「失守」，事实是「值守中」。通知与事实相反。**

    这不是"偶发"，是三条**互不相干**的发射路径各自演化的必然：
      · `host_shield._notify`（哨兵事件）—— 图标随姿态（0.36.5 修过）；
      · `hooks/pre_tool_use.notify_owner`（拦截事件）—— 自己 spawn 一份 PowerShell，
        图标**写死 `SystemIcons.Warning`**（0.36.5 的图标修复只改到了另一份）；
      · `inbox_notify.toast`（值守台，WinRT，落操作中心）。
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


def check(name):
    """★ 判据**必须真会红** —— 返回说明串一律转成抛异常。"""
    def deco(fn):
        def wrapper():
            r = fn()
            if r is True or r is None:
                return True
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
    old = '    if rec.get("recovered") is True:\n        return False, "已自愈（recovered=true，无后果；值守台仍收）"\n'
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
def _balloon_real_sources():
    """真正**发射**气泡的产品文件（AST：非 docstring 的字符串常量含 `ShowBalloonTip(`）。

    ★ 必须走 AST：`inbox_notify.py` 的 docstring 里**提到**了 `ShowBalloonTip(15000)`
      （讲历史），子串搜索会把它误判成"第二个发射者"—— 量具的错不能记成产品的错。
    """
    hits = []
    for base in (ROOT, os.path.join(ROOT, "hooks")):
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
                    #   —— ast.walk 走到的是后者；只登记前者等于没排除
                    #   （第一版就栽在这：`inbox_notify` 的模块 docstring 被当成发射者）。
                    docs.add(id(n.body[0]))
                    docs.add(id(n.body[0].value))
            for n in ast.walk(tree):
                if id(n) in docs:
                    continue
                if isinstance(n, ast.Constant) and isinstance(n.value, str) \
                        and "ShowBalloonTip(" in n.value:
                    hits.append(os.path.relpath(p, ROOT).replace("\\", "/"))
                    break
    return sorted(set(hits))


@check("S61 ★ 气泡发射口唯一：全仓只有 host_shield.py 真发射；hooks/ 必须委托")
def s61():
    hits = _balloon_real_sources()
    if hits != ["host_shield.py"]:
        return ("气泡真身发射者 = %r（应只有 ['host_shield.py']）—— "
                "第二条通道会各自一套去重与图标（本次复发的结构根因）" % (hits,))
    return True


def _balloon_literal_violations(src):
    """含 `ShowBalloonTip(` 的行里，图标参数**写死为字面量**的（空列表＝合格）。

    ★ 只查**那一行**的第 4 个参数 —— 不跨行数占位符（0364 第一版按整条命令数，
      跨行必然数错，那是量具自己的错）。
    """
    bad = []
    for i, ln in enumerate(src.split("\n"), 1):
        if "ShowBalloonTip(" not in ln:
            continue
        m = re.search(r"ShowBalloonTip\([^)]*\)", ln)
        if not m:
            continue
        args = m.group(0)[len("ShowBalloonTip("):-1]
        parts = [p.strip() for p in args.split(",")]
        if len(parts) >= 4 and parts[3].strip("'\"") in ("Warning", "Error", "Info"):
            bad.append("第 %d 行气泡图标写死 %s" % (i, parts[3]))
    return bad


@check("S62 ★ 图标不撒谎：任何发射实现的 ShowBalloonTip 图标参数都不得是字面量")
def s62():
    allbad = []
    for rel in _balloon_real_sources():
        v = _balloon_literal_violations(_src(rel))
        allbad += ["%s: %s" % (rel, x) for x in v]
    if allbad:
        return ("气泡图标写死字面量（通知会与姿态无关地报警）—— " + "；".join(allbad))
    return True


@check("N-S62 分辨力样本：把钩子的图标写回字面量 'Warning' ⇒ S62 的判据必须报红")
def n_s62():
    # 分辨力样本：**同一份文本里，图标是字面量**。它钉住"改了一处漏一处"这个方向。
    sample = ('    ps = ("$n=New-Object System.Windows.Forms.NotifyIcon;"\n'
              '          "$n.ShowBalloonTip(15000,\'%s\',\'%s\',\'Warning\');")\n')
    v = _balloon_literal_violations(sample)
    if not v:
        return "分辨力样本失效：把图标写死成 'Warning' 竟然判不出 —— S62 抓不到这次复发"
    # 反向：合格样本必须**零**违规（否则 S62 会把干净的判成脏 —— 假红）
    ok_sample = '          "$n.ShowBalloonTip(%d,\'%s\',\'%s\',\'%s\');"'
    if _balloon_literal_violations(ok_sample):
        return "合格样本（图标为占位符 %s）被误判为违规 —— S62 有过宽豁免"
    return True


# ══════════════════ 维度四／五／六 · 去重口径与运行态 ══════════════════
@check("S63 ★ 可观测：气泡保护能自报（sent/shown/suppressed ＋ 值守台在岗）")
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
#   值守台显示 **失守（warn）**，而事实是"版本已升、还没重打包"的**正常迭代**。
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


def main():
    print("=" * 78)
    print("0.43.1 判据 —— 右下冒泡根治（十维）：不撒谎 / 不重复 / 单一通道 / 可观测 / 研发态可达")
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
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-58s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
