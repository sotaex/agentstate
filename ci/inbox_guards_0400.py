#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.40.0 判据 —— 「四行失守」的根因修复（A 组 5 条 ＋ B 组 1 条）＋ **B1 撤回的防复发**。

★★ 这一份判据的由来（创始人 2026-10-09）：

    「为了吸取之前各种修了又复发的问题，这次修，要把所有相关机制都建立和用上，
      这个最重要，确保解决的是根因，修得彻底，绝不会再复发。」

  ⇒ 修好一处不难，难的是**没人能再改回去**。本文件把 A/B 两组改动从"代码里的事实"
    变成"会报红、有负控的机制"：

    S20-400 A2「读不到」≠「读到了一份撤防的」：`load_state_strict()` 读失败返 `None`；
    S21 A2'「存在但读不到 ⇒ 拒写」：`update_state_fields()` 是**唯一读-改-写入口**，
        坏文件上必须**拒写且字节不变**（源②的正面修复）；
    S22 A4「授权不进别人的账本」：设了 `ANTINEL_HUB_DIR` ⇒ `_shield_chain_dir()`
        **必须跟随沙箱**（源①：93 条 zone_locked 全是测试授权写进真链）；
    S23 A1「钩子不碰安全状态文件」：`hooks/pre_tool_use.py` 里 `save_state` 调用
        **必须为 0**（源②的写手就是它 —— 窗口可见时 `load→改→整份写回`）；
    S24 A5「归并键按病因」：`self-check`/`registry` → 同一组；`enabled`/`state` → 另一组
        （改前：同因拆两行、三因挤一行）；
    S25 B2「研发态自检不符 ⇒ L1，不占 R0」：且它**不进** `_ALERT_KINDS`（不弹气泡）、
        **进** `AUTO_HANDLED_KINDS`（不进"要处理"）；
    S26 A3「自愈必须带结构化标记」：凡 `field ∈ {enabled, state}` 的 tamper 记录点
        **必须**传 `recovered=True`（改前：全链 30 天只有 3 条打对，33 条漏打）；
    S27 ★★ **B1 撤回的防复发**：`is_dev_build()` 的判据**只许用版本落差**，
        **禁止**引入任何环境性信号（`.git` / mtime / 清单 built_at）——
        B1 曾在版本相等时用「源码检出 ＋ 工作树比清单新」判研发态，实测推翻：
        本机没有 pip 安装，跑监理的就是源码检出 ⇒ 那条信号**恒真** ⇒
        "已出厂"作废 ⇒ **真篡改被读成"研发中"（R0→L1）**；
    S28 ★★ **全类型报告方向一致**：`LEVEL_OF_KIND` 里每一个 kind，其用户可见标题
        的**方向**必须与级别一致（说"没守住"⇒必须是 R0；R0 必须说"没守住"），
        且**每个 kind 都必须有标题**（不许"未登记就按 kind 名显示"）——
        这条把 2026-10-09 的《全类型报告审计》从"跑一次的探针"变成"常驻机制"。
    S29 A6「旧 subkind 名对齐现行 topic」：`self_check`（旧名）与 `code_drift`（新名）
        是**同一件事**，必须并到同一 topic 同一组；且**归因层与归并层同向**
        （A6 的正当性全部来自"归因层本来就把它们当一回事"）。
    S30 A7「同一 kind 的记录点 subkind 口径一致」：`host_shield_spawn_failed`
        有两个记录点，实测一个写了 `subkind`、一个没写 ⇒ 同一件事会被归成两行。
        这是**写 side** 的同因拆两行，只查投影查不到，必须回到**源码调用点**。
    S31 A8「`zone_locked` 成败按记录分档」：这个 kind **兼表上锁成功与失败** ⇒
        级别/标题/要不要人管/有没有后果，四项**都要按记录判**。
        实测旧实现里 `remediation._kind_of` 无条件返回同一类 ⇒ 注释声称的
        「成功=自动处理／失败=要你决策」**一直是空转的**（一条成功被渲染成 R0 失守）。
    S32 ★ **提权判据「唯一口径」**：ACL 类判据在**提权进程**里会失真 ——
        `acl_deny` 授出的 `Administrators:(OI)(CI)(F)` 对本进程生效 ⇒ 写探针恒成功 ⇒
        `is_denied()` 恒 False ⇒ 把"已上锁"读成"上锁失败"，并写下一句**不成立的指控**
        「有进程在对抗门闸」（0.40.0 本机实测复现）。判据必须先问"我是不是提权"。
        ★ 0.41.0：这个判断有**三份实现**（`host_shield.process_elevation` 随包、
        `scripts/verification_tests.py::_process_elevation` 随包 —— 测试侧**刻意**
        保持独立、不 import 被测产品、`ci/drift_audit.py::_acl_audit_usable` 不随包
        ⇒ 不能 import，只能镜像）；S32 保证三份**同规则**（whoami / `S-1-16-` /
        `0x3000`），**只改一边就报红**。
    S33 ★★ **`is_denied()` 必须提权感知（根因修复的防复发）**：写探针在提权令牌下
        **无效**（`Administrators:(OI)(CI)(F)` 先生效）⇒ 判据改读 **ACL**。
        `is_denied()` 的函数体**必须同时**出现 `process_elevation` 与
        `acl_read_deny` —— 否则"提权下把已上锁读成上锁失败"会**原样复发**。
    S34 ★★ **文案不许冤枉人**：`scan_once()` 里 `host_shield_zone_locked` 那条记录的
        `reason` **不得断言**「有进程在对抗门闸」——实测真因是提权令牌让写探针失真，
        与"有人对抗"是两回事。这条把 0.41.0 的文案修复从"改对了一次"变成"改不回去"。

  ★ 编写纪律（沿用本仓惯例，见 `inbox_guards_0372.py` / `inbox_guards_0380.py` 头部）：
    · 每条判据配负控，且负控**真的会红**（不是"算一遍就丢"）；
    · 判据**只查行为/结构**，不查文案 —— 凡按源码字面查的，一律走 **AST**
      （本文件写 S27 时就差点踩：`is_dev_build` 的**注释**里写着 `.git`，
       用子串查会**假红** —— 去查"解释这件事的那段文字"是本仓反复出现的坑）；
    · **不写任何产品文件**：需要落盘的用例一律写 `_TMPREG.tmpdir()` 建的临时目录。
"""
from __future__ import annotations

import ast
import io
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (ROOT, os.path.join(ROOT, "ci")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# 0.55.0 (F3): temp dir registry
import tmpreg as _TMPREG                                              # noqa: E402

RESULTS = []


def check(name):
    """★ 判据**必须真会红** —— 装饰器把「返回说明串」收紧成**抛异常**。

    ★★★ 为什么需要这一层（本轮实测抓到的、**判据自身**的缺陷）：
      本仓既有套件（0364 / 0380）的 `main()` 是这么计的 ——
        `why = fn(); print("✅ … %s" % (why or "")); ok += 1`
      也就是说：判据**返回一个说明串**（本意是"我失败了，原因是…"）时
      **照样打 ✅、照样计入绿**。实测本文件第一版就踩了：
        · `S27` 报了"第 1325 行出现环境性字面量…"（docstring 误判）却被打 ✅；
        · `N-S24` 报"负控失效：兼容层去掉后两组仍然不同"也被打 ✅。
      ⇒ 两条**真缺陷**被自己的量具藏了起来 —— 这正是 0380 头部那句
        「它报了'负控失效'却被计为绿 ⇒ 判据本身失效」的同型复发。
      ⇒ 收紧：判据只许 `return True` 才算过；返回任何非 True ⇒ 在这里
        **主动 `raise AssertionError`** ⇒ 显示 ❌、计入红、退出码非零。
      这样 `main()` 的 `ok/fail` 与磁盘上的真实结论**重新对齐**。
    """
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


def _func_tree(src, name):
    """取某个顶层函数的 AST 节点；找不到 ⇒ None。"""
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _func_seg(src, name):
    """按**行边界**取 `def <name>(` 的函数段源码；找不到 ⇒ None。

    ★ 为什么需要它（0.42.0 S47）：S47 要分别检查 `_item_html()` 与
      `_group_html()` **各自**的渲染出口。两条路径各有一份 meta，
      0.42.0 第一版只改了前者 ⇒ W01 仍红（归并行是漏掉的那条）。
      ⇒ 判据必须**逐函数**看，不能全文搜一个字符串就完事
        （全文搜会因为"另一条路径也有"而假绿）。
    ★ 与 `guard_dist_hygiene` 的教训一致：用 `ast.walk` 遍历取节点时，
      **节点顺序 ≠ 源码顺序**；这里改用 `lineno`/`end_lineno` 精确切片。
    """
    node = _func_tree(src, name)
    if node is None:
        return None
    lines = src.split("\n")
    return "\n".join(lines[node.lineno - 1:node.end_lineno])


def _call_name(call):
    """`ast.Call` → 被调名（`x.f()` 取 `f`；`f()` 取 `f`）。"""
    f = call.func
    return getattr(f, "attr", None) or getattr(f, "id", None)


def _kwarg(call, key):
    for kw in call.keywords:
        if kw.arg == key:
            return kw.value
    return None


# ═════════════════════════════ S20-400 · A2「读不到」≠「已撤防」════════════════════
def _load_state_strict_problems(mod, sp):
    """在**指定的状态文件路径**上核 `load_state_strict` 的诚实性。

    ★ 期望值**写死在这里**（不从 `load_state` 的返回值反推）—— 本仓纪律：
      期望绝不取自被测对象，否则负控变异它时两边一起错 ⇒ 判据永远绿。
    """
    probs = []
    p = sp()
    if mod.load_state_strict() is not None:
        probs.append("状态文件不存在时 `load_state_strict()` 不是 None"
                     " ⇒ 又把「读不到」当成了事实")
    with io.open(p, "w", encoding="utf-8") as f:
        f.write("{ 这不是 JSON")
    if mod.load_state_strict() is not None:
        probs.append("状态文件损坏时 `load_state_strict()` 不是 None"
                     " ⇒ 「读不到」被伪装成「读到了一份撤防的」")
    return probs


@check("S20-400 A2「读不到」≠「已撤防」：读失败返 None ＋ 无背书撤防不落盘")
def s20():
    import host_shield as H
    tmp = _TMPREG.tmpdir(prefix="g0400_s20_")
    o_sp = H.state_path
    H.state_path = lambda: os.path.join(tmp, "host_shield.json")
    try:
        probs = _load_state_strict_problems(H, H.state_path)
        if probs:
            return "；".join(probs)
        # ② 真·已布防 ⇒ **无背书**的撤防必须被拦（这是源②的止血闸）
        H.save_state({"enabled": True, "workspaces": {}}, allow_disarm=True)
        H.save_state({"enabled": False, "workspaces": {}})
        got = json.loads(io.open(H.state_path(), encoding="utf-8").read())
        if not got.get("enabled"):
            return ("没传 allow_disarm 的撤防**写进去了**（enabled 变 False）"
                    " ⇒ 静默撤防仍然可行")
        # ③ 反向对照：**显式** allow_disarm ⇒ 必须允许（否则合法撤防被误拦）
        H.save_state({"enabled": False}, allow_disarm=True)
        got2 = json.loads(io.open(H.state_path(), encoding="utf-8").read())
        if got2.get("enabled"):
            return "显式 allow_disarm=True 仍撤不掉 ⇒ 合法撤防被误拦（方向反了）"
        return True
    finally:
        H.state_path = o_sp


@check("N-S20-400 负控：让 load_state_strict 退回「读不到返默认撤防」⇒ S20-400 必须报红")
def n_s20():
    import host_shield as H
    o = H.load_state_strict
    try:
        H.load_state_strict = lambda: {"enabled": False, "workspaces": {}}
        tmp = _TMPREG.tmpdir(prefix="g0400_n20_")
        probs = _load_state_strict_problems(
            H, lambda: os.path.join(tmp, "host_shield.json"))
        if not probs:
            return "负控失效：退回旧口径后 S20-400 仍然绿"
        return True
    finally:
        H.load_state_strict = o


# ═════════════════════════════ S21 · A2' 存在但读不到 ⇒ 拒写 ════════════════════
@check("S21 update_state_fields：坏状态文件 ⇒ 拒写且字节不变；好文件 ⇒ 真写")
def s21():
    import host_shield as H
    tmp = _TMPREG.tmpdir(prefix="g0400_s21_")
    o_sp = H.state_path
    H.state_path = lambda: os.path.join(tmp, "host_shield.json")
    try:
        with io.open(H.state_path(), "w", encoding="utf-8") as f:
            f.write("{ 半截的写入")
        with io.open(H.state_path(), "rb") as f:
            before = f.read()
        r = H.update_state_fields(sentinel_pid=12345)
        if r is not False:
            return ("坏状态文件上 `update_state_fields` 返回 %r（应为 False）"
                    " ⇒ 拒写闸失效（源②会复发）" % (r,))
        with io.open(H.state_path(), "rb") as f:
            after = f.read()
        if after != before:
            return "拒写失败：字节变了（应逐字节不变）"
        # 反向对照：文件不存在（全新机器）⇒ 必须能写，且不编造安全字段
        os.remove(H.state_path())
        if H.update_state_fields(sentinel_pid=7) is not True:
            return "文件不存在时拒写了 ⇒ 新机器上永远建不出状态"
        got = json.loads(io.open(H.state_path(), encoding="utf-8").read())
        if got.get("sentinel_pid") != 7:
            return "新文件里没写进目标字段（%r）" % (got,)
        if "enabled" in got:
            return ("新文件里被**编造**了 `enabled`（%r）—— 状态文件缺失时"
                    "不许凭空写安全字段" % (got,))
        return True
    finally:
        H.state_path = o_sp


@check("N-S21 负控：把拒写分支去掉（回到整份默认写回）⇒ S21 必须报红")
def n_s21():
    import host_shield as H
    tmp = _TMPREG.tmpdir(prefix="g0400_n21_")
    o_sp = H.state_path
    H.state_path = lambda: os.path.join(tmp, "host_shield.json")
    try:
        with io.open(H.state_path(), "w", encoding="utf-8") as f:
            f.write("{ 坏")
        # 变异：**骗过「存在但读不到 ⇒ 拒写」那道门** —— 谎报"文件不存在"，
        #   让代码走"新建"分支（复现源②的形状）。
        # ★ 0.45.0：不再连 `load_state_strict` 一起 mock —— 甲层给
        #   `update_state_fields` 加了**乐观锁**（写后要读回核对版本号），
        #   把读函数恒返回 None 会让"写后核对"永远失败 ⇒ 无论拒写分支在不在
        #   都返回 False ⇒ 负控分辨不出"拒写分支"的作用（负控自身失效）。
        #   只谎报存在性即可：真读函数会把坏文件读成 None，写入后能读回 ⇒ 核对通过。
        prev_exists = os.path.exists

        def _fake_exists(p):
            return False            # 骗过「存在但读不到 ⇒ 拒写」那道门
        os.path.exists = _fake_exists
        try:
            r = H.update_state_fields(sentinel_pid=1)
        finally:
            os.path.exists = prev_exists
        if r is False:
            return "负控失效：骗过存在性检查后仍拒写"
        return True
    finally:
        H.state_path = o_sp


# ═════════════════════════════ S22 · A4 授权跟随中枢 ════════════════════════════
def _chain_dir_problems(chain_dir, hub_rollup, pkg_chain, sandbox):
    """期望值**由调用方写死**传入（不从被测函数反推）。"""
    probs = []
    o = os.environ.get("ANTINEL_HUB_DIR")
    try:
        if sandbox is None:
            os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            os.environ["ANTINEL_HUB_DIR"] = sandbox
        got = os.path.normcase(os.path.abspath(chain_dir()))
        if sandbox is not None:
            want = os.path.normcase(os.path.abspath(hub_rollup()))
            if got != want:
                probs.append("设了 ANTINEL_HUB_DIR=%s 时仍指向 %s（应 %s）"
                             " ⇒ 测试/沙箱的授权会写进**真项目链**（源①）"
                             % (sandbox, got, want))
        else:
            want = os.path.normcase(os.path.abspath(pkg_chain()))
            if got != want:
                probs.append("未设沙箱时应指向包链 %s，实际 %s" % (want, got))
    finally:
        if o is None:
            os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            os.environ["ANTINEL_HUB_DIR"] = o
    return probs


@check("S22 A4 授权不进别人的账本：设了中枢 ⇒ _shield_chain_dir 跟随沙箱")
def s22():
    import antinel
    import host_shield as H
    tmp = _TMPREG.tmpdir(prefix="g0400_s22_")
    probs = _chain_dir_problems(
        antinel._shield_chain_dir, H._hub_rollup_dir,
        lambda: H._shield_audit_dir(H._pkg_root()), tmp)
    if probs:
        return "；".join(probs)
    # 反向对照：不设沙箱 ⇒ 必须是**包链**（证明上面那条不是"恒等于 hub_rollup"）
    probs2 = _chain_dir_problems(
        antinel._shield_chain_dir, H._hub_rollup_dir,
        lambda: H._shield_audit_dir(H._pkg_root()), None)
    if probs2:
        return "；".join(probs2)
    return True


@check("N-S22 负控：把「跟随中枢」那行去掉 ⇒ S22 必须报红")
def n_s22():
    import host_shield as H
    tmp = _TMPREG.tmpdir(prefix="g0400_n22_")
    # 变异：一个**永远返回包链**的替身（＝把跟随中枢那行删掉的行为）
    fake = lambda: H._shield_audit_dir(H._pkg_root())                       # noqa: E731
    probs = _chain_dir_problems(fake, H._hub_rollup_dir,
                                lambda: H._shield_audit_dir(H._pkg_root()), tmp)
    if not probs:
        return "负控失效：不跟随中枢的实现仍被判绿"
    return True


# ═════════════════════════════ S23 · A1 钩子不碰安全状态文件 ════════════════════
_STATE_FNS = ("save_state", "update_state_fields", "load_state_strict")


def _hook_state_write_calls(src):
    """AST 找出 `hooks/pre_tool_use.py` 里对**安全状态文件**的写/读改写调用。

    ★ 为什么用 AST 而不是 `"save_state" in src`：本仓已多次踩 ——
      **去查"解释代码的那段文字"**（docstring/注释里提到函数名）会假红/假绿。
    """
    hits = []
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in _STATE_FNS:
            hits.append((node.lineno, _call_name(node)))
    return hits


@check("S23 A1 钩子不碰安全状态文件（save_state/load_state 调用为 0）")
def s23():
    src = _src("hooks/pre_tool_use.py")
    hits = _hook_state_write_calls(src)
    if hits:
        return ("`hooks/pre_tool_use.py` 仍在写安全状态文件：%r"
                " ⇒ 源②的写手回来了（钩子 load→改→整份写回会抹掉 enabled/zones）"
                % (hits[:4],))
    # 正向：气泡节流必须走**展示账**（否则降噪记账无处可去）
    #   ★★ 0.43.1：**记账点搬家了** —— 钩子不再自己记账，而是把发射**委托**给
    #     唯一发射口 `host_shield.notify_owner`（→ `_notify_throttled`，记账在那里）。
    #     判据必须跟着搬到**真身**上；留在钩子上就是"量具指错了对象"
    #     （同 JDG-02B 负控搬家那一体：改了一处、判据没跟着搬）。
    if not any(_call_name(n) == "notify_owner"
               for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call)):
        return "钩子没有委托 `notify_owner(` ⇒ 它又在自己发射气泡（第二套通道回来了）"
    if "mark_notify_shown" not in _src("host_shield.py"):
        return ("唯一发射口（host_shield）里没有 `mark_notify_shown(`"
                " ⇒ 降噪记账被删了（节流会失效）")
    # 行为级：`mark_notify_shown` 绝不能经由 `save_state` 落盘
    import host_shield as H
    tmp = _TMPREG.tmpdir(prefix="g0400_s23_")
    o_hub, o_save = H._hub_dir, H.save_state
    H._hub_dir = lambda: tmp
    H.save_state = lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("mark_notify_shown 走 save_state 落盘 ⇒ 还在碰安全状态"))
    try:
        H.mark_notify_shown("s23_probe")
    finally:
        H._hub_dir, H.save_state = o_hub, o_save
    data = json.loads(io.open(os.path.join(tmp, "notify_state.json"),
                              encoding="utf-8").read())
    if not any("s23_probe" in k for k in data):
        return "mark_notify_shown 没写进通知账（%r）" % (list(data)[:4],)
    return True


@check("N-S23 负控：把 save_state 加回钩子 ⇒ S23 必须报红")
def n_s23():
    src = _src("hooks/pre_tool_use.py")
    mutated = src + "\n\n\ndef _g0400_probe():\n    _hs.save_state({})\n"
    if not _hook_state_write_calls(mutated):
        return "负控失效：加回 save_state 后仍未被抓到"
    # ★ 0.43.1 第二半：把"委托"抽掉（钩子又自己发射气泡）⇒ 判据必须报红
    _no_deleg = src.replace("notify_owner(", "_x_notify_owner(")
    if _no_deleg == src:
        return "负控无效：找不到 notify_owner 委托锚点（判据与源码已失配）"
    if any(_call_name(n) == "notify_owner"
           for n in ast.walk(ast.parse(_no_deleg)) if isinstance(n, ast.Call)):
        return "负控失效：抽掉委托后仍被判成有委托 —— S23 第二半是假绿"
    return True


# ═════════════════════════════ S24 · A5 归并键按病因 ════════════════════════════
def _group(topic_field, subkind, ts="2026-10-09T10:00:00+08:00"):
    import inbox_store as S
    kinds = S.alert_kinds()
    rec = {"ts": ts, "type": "host_shield_tamper", "field": topic_field,
           "subkind": subkind, "reason": "probe", "severity": "critical",
           "decision": "deny"}
    a = S.project_record(rec, kinds)
    return a


def _merge_problems():
    """同因必须同组、异因必须异组。**两个方向都查**（只查一个方向会被"全都不同组"骗过）。"""
    import inbox_model as M
    probs = []
    a = _group("self-check", "")        # 历史：只有 field
    b = _group("registry", "")          # 历史：只有 field
    c = _group("enabled", "")           # 历史：只有 field
    if M.group_key(a) != M.group_key(b):
        probs.append("`self-check` 与 `registry` 没归到同一组（同因被拆两行）")
    if M.group_key(a) == M.group_key(c):
        probs.append("`self-check` 与 `enabled` 被归到同一组（异因被压一行）")
    # 新口径（A5 生产侧）与历史口径必须落到**同一组**，否则同一件事会裂成两行
    if M.group_key(a) != M.group_key(_group("self-check", "code_drift")):
        probs.append("新老口径的 `code_drift` 没落到同一组")
    if M.group_key(c) != M.group_key(_group("enabled", "state_drift")):
        probs.append("新老口径的 `state_drift` 没落到同一组")
    # 标题方向：两条都得是**失守**（tamper 是 R0）
    for x in (a, c):
        if "没守住" not in x.title:
            probs.append("tamper 的标题没有说「失守」：%r" % (x.title,))
    return probs


@check("S24 A5 归并键按病因：self-check/registry 一组、enabled/state 另一组")
def s24():
    probs = _merge_problems()
    return "；".join(probs) if probs else True


@check("N-S24 负控：把 field→topic 的兼容层去掉 ⇒ 异因被压回同一组，S24 必须报红")
def n_s24():
    """★ 变异**产品**（兼容层），断言**判据 S24 本体**变红 —— 不是另写一遍判断。

    ★★★ 这里修过一个**方向搞反**的负控（本轮实测抓到的第二处自身缺陷）：
      第一版写的是「去掉兼容层后两组 `group_key` **不同** ⇒ 负控有效」——
      恰好写反了：兼容层一去掉，两条的 topic 都变空 ⇒ 它们**变成同一组**，
      `!=` 为假 ⇒ 负控报"失效"。**负控失效的方向写反，会让人以为判据没分辨力**。
      现在直接断言 `_merge_problems()`（S24 的真身）在变异后**非空**，
      方向不可能再搞反，也顺带覆盖了"新老口径对齐"那两条。
    """
    import inbox_store as S
    o = S._TOPIC_OF_FIELD
    try:
        S._TOPIC_OF_FIELD = {}          # 变异：兼容层失效 ⇒ 历史记录 topic 全空
        probs = _merge_problems()
        if probs:
            return True                 # 变异后果出现（S24 真会红）⇒ 负控有效
        return "负控失效：兼容层去掉后 S24 仍然全绿（判据对这道病因没有分辨力）"
    finally:
        S._TOPIC_OF_FIELD = o


# ═════════════════════════════ S25 · B2 研发态降 L1（不占 R0）═══════════════════
#: ★ 期望值**写死**在这里，不从产品表反推（0380 的第一条教训）。
_EXPECT_DEV_DRIFT = {
    "level": "L1",
    "in_alert_kinds": False,        # 不弹气泡（研发噪声不该敲门）
    "auto_handled": True,           # 不进「要处理」
}


def _dev_drift_problems(level_tbl, alert_kinds, auto_tbl):
    probs = []
    k = "host_shield_dev_drift"
    if k not in level_tbl:
        return ["`host_shield_dev_drift` 未登记级别 ⇒ 研发态自检不符无处可去"]
    if level_tbl[k] != _EXPECT_DEV_DRIFT["level"]:
        probs.append("级别是 %r（应 %r）—— 研发期「代码≠登记」不是失守"
                     % (level_tbl[k], _EXPECT_DEV_DRIFT["level"]))
    if (k in alert_kinds) is not _EXPECT_DEV_DRIFT["in_alert_kinds"]:
        probs.append("它在 `_ALERT_KINDS` 里 ⇒ 每次改码都会弹气泡（创始人最恨的形状）")
    if (k in auto_tbl) is not _EXPECT_DEV_DRIFT["auto_handled"]:
        probs.append("它不在 `AUTO_HANDLED_KINDS` 里 ⇒ 研发噪声会占满「要处理」")
    return probs


@check("S25 B2 研发态自检不符 ⇒ L1（不弹泡、不进「要处理」）")
def s25():
    import host_shield as H
    import inbox_model as M
    probs = _dev_drift_problems(M.LEVEL_OF_KIND, H._ALERT_KINDS,
                                M.AUTO_HANDLED_KINDS)
    if probs:
        return "；".join(probs)
    # 接线：`run_sentinel` 必须**先问研发态**再决定记哪种事件，两个分支缺一不可
    seg = ast.get_source_segment(
        _src("host_shield.py"), _func_tree(_src("host_shield.py"), "run_sentinel"))
    if seg is None:
        return "取不到 run_sentinel 的真代码（AST 解析失败）"
    if "host_shield_dev_drift" not in seg:
        return "`run_sentinel` 里没有记 `host_shield_dev_drift` ⇒ B2 没接线"
    if "host_shield_tamper" not in seg:
        return "`run_sentinel` 里没有 `host_shield_tamper` 分支 ⇒ 已出厂的真篡改无处可去"
    if "is_dev_build()" not in seg:
        return "`run_sentinel` 没有先问 `is_dev_build()` ⇒ 两种事件无法区分"
    return True


@check("N-S25 负控：把 dev_drift 的级别改回 R0 ⇒ S25 必须报红")
def n_s25():
    import host_shield as H
    import inbox_model as M
    tbl = dict(M.LEVEL_OF_KIND)
    tbl["host_shield_dev_drift"] = "R0"        # 变异：退回"研发态占 R0"
    if not _dev_drift_problems(tbl, H._ALERT_KINDS, M.AUTO_HANDLED_KINDS):
        return "负控失效：把 dev_drift 改回 R0 仍被判绿"
    return True


# ═════════════════════════════ S26 · A3 自愈必须带结构化标记 ════════════════════
#: 这两个 `field` 的记录点**在结构上必然是自愈的**（记录后紧接着回写状态）——
#: 所以它们**必须**带 `recovered=True`，否则一条"已经好了"的事会冒充 R0 失守。
_SELF_HEALED_FIELDS = ("enabled", "state")


def _recovered_problems(src):
    """AST 核：凡 `record(...)` 且 `field ∈ _SELF_HEALED_FIELDS` 的调用点，
    必须同时传 `recovered=True`；**非**自愈的 `field` 则不许传（防乱打标记）。"""
    probs = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Call) or _call_name(node) != "record":
            continue
        fv = _kwarg(node, "field")
        if not (isinstance(fv, ast.Constant) and isinstance(fv.value, str)):
            continue
        rv = _kwarg(node, "recovered")
        is_true = isinstance(rv, ast.Constant) and rv.value is True
        if fv.value in _SELF_HEALED_FIELDS:
            if not is_true:
                probs.append("第 %d 行：`field=%r` 是自愈事件却没传 `recovered=True`"
                             % (node.lineno, fv.value))
        else:
            if is_true:
                probs.append("第 %d 行：`field=%r` **不是**自愈事件却打了"
                             " `recovered=True`（会给真失守降档）"
                             % (node.lineno, fv.value))
    return probs


@check("S26 A3 自愈事件必须带 recovered=True（三个记录点全查）")
def s26():
    probs = _recovered_problems(_src("host_shield.py"))
    if probs:
        return "；".join(probs[:4])
    # 至少要有 3 处自愈标记点（enabled×2 ＋ state×1）
    n = 0
    for node in ast.walk(ast.parse(_src("host_shield.py"))):
        if (isinstance(node, ast.Call) and _call_name(node) == "record"
                and isinstance(_kwarg(node, "recovered"), ast.Constant)
                and _kwarg(node, "recovered").value is True):
            n += 1
    if n < 3:
        return "带 `recovered=True` 的记录点只有 %d 处（应 ≥3）" % n
    return True


@check("N-S26 负控：抽掉一个 recovered=True ⇒ S26 必须报红")
def n_s26():
    src = _src("host_shield.py")
    mutated = src.replace('subkind="state_drift", recovered=True',
                          'subkind="state_drift"', 1)
    if mutated == src:
        return "负控失效：源码里找不到可抽掉的 `recovered=True` 锚点（判据需更新）"
    if not _recovered_problems(mutated):
        return "负控失效：抽掉一个 recovered=True 后仍被判绿"
    return True


# ═════════════════════════════ S27 · ★★ B1 撤回的防复发 ═════════════════════════
#: 研发态判据**禁用**的环境性信号（它们在"跑哨兵的那份代码就是源码检出"
#: 这类部署上**恒真**，而且都能被伪造 ⇒ 等于把这一支放开）。
_FORBIDDEN_DEV_SIGNALS = {
    "isdir": "查目录（`.git` 那类「源码检出」信号）",
    "getmtime": "查文件时间（「工作树比清单新」）",
    "listdir": "枚举目录",
}
_FORBIDDEN_DEV_STRINGS = (".git", "built_at")
#: B1 引入过的函数名：**出现即红**（它们已被实测推翻并删除）
_B1_REMOVED = ("_is_source_checkout", "_protected_files", "_newest_protected_mtime",
               "_manifest_built_at", "_ts_txt")


def _dev_signal_problems(src):
    """AST 核 `is_dev_build()`：只许用版本落差，不许引入环境性信号。

    ★★★ 为什么**必须**用 AST、不能用子串：
      本文件写第一版时差点踩 —— `is_dev_build` 的**注释/留档**里就写着 `.git`、
      `built_at`（B1 撤回留档），用 `in src` 查会**假红**。
      "去查解释这件事的那段文字"是本仓反复出现的坑（0360 P10 / 0363 `_func_seg`）。
      AST 只认**真代码**（属性访问、字符串常量、被调名），注释根本不参与。
    """
    probs = []
    fn = _func_tree(src, "is_dev_build")
    if fn is None:
        return ["找不到 `is_dev_build()`"]
    # ★★★ docstring **豁免**（本轮实测踩到并修）：
    #   `is_dev_build` 的函数说明（`fn.body[0]` 那个字符串常量）里**正当地**
    #   写着 `.git` / `built_at`（那就是"B1 撤回留档"本身）。它虽是 `ast.Constant`，
    #   却**不是代码** ⇒ 必须跳过，否则判据对**自己的留档**报红。
    #   ⚠️ 只豁免**函数 docstring 这一个节点**，不是"凡是字符串都放行" ——
    #     真代码里的字符串常量（例如 `if kind == ".git"`）仍会被抓到。
    _doc = None
    if (fn.body and isinstance(fn.body[0], ast.Expr)
            and isinstance(fn.body[0].value, ast.Constant)
            and isinstance(fn.body[0].value.value, str)):
        _doc = fn.body[0].value
    # ① 禁用的环境性调用 / 常量 / 函数名
    for node in ast.walk(fn):
        if node is _doc:                       # ← docstring 不是代码，跳过
            continue
        if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_DEV_SIGNALS:
            probs.append("第 %d 行用了 `.%s`（%s）—— 环境性信号，"
                         "在本部署上恒真且可伪造" % (node.lineno, node.attr,
                                                _FORBIDDEN_DEV_SIGNALS[node.attr]))
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and any(s in node.value for s in _FORBIDDEN_DEV_STRINGS):
            probs.append("第 %d 行出现环境性字面量 %r" % (node.lineno, node.value))
        if isinstance(node, ast.Name) and node.id in _B1_REMOVED:
            probs.append("第 %d 行调用了 B1 已撤回的函数 `%s`" % (node.lineno, node.id))
    # ② 正向：必须**仍然**用版本落差（去掉它 ⇒ 研发态永远出不来）
    if not any(isinstance(n, ast.Name) and n.id == "_ver_lt" for n in ast.walk(fn)):
        probs.append("`is_dev_build()` 不再做版本比较（`_ver_lt` 不见了）"
                     " ⇒ 研发态的唯一来源被拆掉了")
    # ③ 那五个函数**不许**在模块里复活
    live = {n.name for n in ast.walk(ast.parse(src))
            if isinstance(n, ast.FunctionDef)}
    for gone in _B1_REMOVED:
        if gone in live:
            probs.append("`%s` 又出现在模块里 ⇒ B1 复活了"
                         "（它的前提「生产 ≠ 源码检出」本机实测不成立）" % gone)
    return probs


@check("S27 ★ 研发态只认版本落差：禁用 .git/mtime/built_at 等环境性信号")
def s27():
    probs = _dev_signal_problems(_src("host_shield.py"))
    return "；".join(probs[:4]) if probs else True


@check("N-S27 负控：把「源码检出」信号加回去 ⇒ S27 必须报红")
def n_s27():
    src = _src("host_shield.py")
    # ★ 0.43.1：锚点从 `if inst == code:` 改为版本比较那一行 ——
    #   0.43.1 的根因修复把"版本相等"的整支收进 `_ver_lt` 的统一分支里
    #   （不再有独立的 `if inst == code:`），判据锚点必须跟着搬家
    #   （本仓纪律：**判据要跟着实现搬家**，否则负控静默失效成假绿）。
    mutated = src.replace("        newer = _ver_lt(inst, code)\n",
                          "        newer = _ver_lt(inst, code)\n"
                          "        if os.path.isdir(os.path.join(_pkg_root(), '.git')):\n"
                          "            return True, 'x'\n", 1)
    if mutated == src:
        return "负控失效：找不到版本比较锚点（判据需更新）"
    probs = _dev_signal_problems(mutated)
    if not probs:
        return "负控失效：加回 `.git` 信号后仍被判绿"
    return True


# ═════════════════════════════ S28 · ★★ 全类型报告方向一致 ══════════════════════
def _title_dir_problems(level_tbl, title_tbl):
    """每个 kind：标题的**方向**必须与级别一致，且必须有标题。

    ★ 为什么这条是"从机制上确保报告真实"的核心：
      用户照标签做判断 —— 一条 L1「注意」挂上「失守」字样，或一条 R0 挂着
      「已拦截」，都会让人**得出相反结论**（本仓 0.35.3 已有先例：
      `host_shield_breach` 曾被写成"已拦截：越界动作被挡下"，方向正好反了）。
    """
    probs = []
    for k, lv in sorted(level_tbl.items()):
        t = title_tbl.get(k)
        if not t:
            probs.append("`%s` 没有用户可见标题 ⇒ 界面会回落显示内部 kind 名" % k)
            continue
        says_breach = "没守住" in t
        is_r0 = (lv == "R0")
        if says_breach != is_r0:
            probs.append("`%s`（%s）标题 %r 方向不一致 —— 说失守必须是 R0，"
                         "R0 必须说失守" % (k, lv, t))
    return probs


@check("S28 ★ 全类型报告方向一致：每一个 kind 的标题方向 = 级别；且都有标题")
def s28():
    import inbox_model as M
    probs = _title_dir_problems(M.LEVEL_OF_KIND, M.TITLE_OF_KIND)
    if probs:
        return "；".join(probs[:4])
    # 反向对照：给一个 L1 挂上「失守」标题 ⇒ 必须被抓（证明这条**有分辨力**）
    tbl = dict(M.TITLE_OF_KIND)
    tbl["host_shield_changed"] = "没守住：防护设置被改动"
    if not _title_dir_problems(M.LEVEL_OF_KIND, tbl):
        return "反向对照失败：L1 挂「失守」标题却没被抓到 ⇒ 判据没有分辨力"
    return True


@check("N-S28 负控：抽掉一个 kind 的标题 ⇒ S28 必须报红")
def n_s28():
    import inbox_model as M
    tbl = dict(M.TITLE_OF_KIND)
    tbl.pop("host_shield_breach", None)
    if not _title_dir_problems(M.LEVEL_OF_KIND, tbl):
        return "负控失效：抽掉标题后仍被判绿"
    return True


# ═════════════════════ S29 · A6 旧 subkind 名对齐现行 topic（跨层一致）═══════════
def _tamper_topic(store, kinds, subkind):
    return store.project_record(
        {"ts": "2026-10-09T10:00:00+08:00", "type": "host_shield_tamper",
         "field": "self-check", "subkind": subkind,
         "reason": "监理启动自检不符：host_shield.py 与 manifest 不符"}, kinds)


def _topic_alias_problems(store, model, remed):
    """① 旧 subkind `self_check` 与现行 `code_drift` 必须落到**同一 topic/同一组**；
       ② 归因层（`remediation._kind_of`）与归并层必须**同向**（否则两层口径漂移）。

    ★ 为什么②也要查：A6 的正当性**全部**来自"归因层本来就把它们当一回事"。
      若哪天有人把归因层改成区分这两者，A6 就失去了依据 ⇒ 必须一起红，
      逼人重新想清楚，而不是让两层各说各话（本仓 F40「一个数两个口径」的同型）。"""
    import inbox_model as M
    a = _tamper_topic(store, kinds=_k(), subkind="self_check")
    b = _tamper_topic(store, kinds=_k(), subkind="code_drift")
    probs = []
    if a.topic != b.topic:
        probs.append("旧 `self_check` 与现行 `code_drift` 的 topic 不同（%r vs %r）"
                     " ⇒ 同因拆两行" % (a.topic, b.topic))
    if M.group_key(a) != M.group_key(b):
        probs.append("旧 `self_check` 与现行 `code_drift` 没归到同一组")
    if remed._kind_of(a) != remed._kind_of(b):
        probs.append("归因层把 `self_check` 与 `code_drift` 当成两回事"
                     " ⇒ 与归并层口径相反（A6 的依据没了）")
    return probs


def _k():
    import inbox_store as S
    return S.alert_kinds()


@check("S29 A6 旧 subkind 名对齐现行 topic：self_check 并进 code_drift，两层同向")
def s29():
    import inbox_model as M
    import inbox_store as S
    import remediation
    probs = _topic_alias_problems(S, M, remediation)
    return "；".join(probs) if probs else True


@check("N-S29 负控：抽掉 `_TOPIC_ALIAS` ⇒ 旧 subkind 会被拆回两行，S29 必须报红")
def n_s29():
    import inbox_model as M
    import inbox_store as S
    import remediation
    o = S._TOPIC_ALIAS
    try:
        S._TOPIC_ALIAS = {}             # 变异：兼容层失效 ⇒ 旧名不再对齐
        if _topic_alias_problems(S, M, remediation):
            return True
        return "负控失效：抽掉 `_TOPIC_ALIAS` 后 S29 仍然绿"
    finally:
        S._TOPIC_ALIAS = o


# ═════════════════ S30 · A7 同一 kind 的 record 点 subkind 口径一致 ══════════════
def _subkind_consistency_problems(src, kind):
    """**同一 kind** 的每个 `record(...)` 调用点，`subkind` 必须**要么都写、要么都不写**。

    ★ 为什么这条是"防复发"而不是洁癖：
      `host_shield_spawn_failed` 实测有**两个**记录点，一个写了 `subkind`、
      一个没写 ⇒ 归并键 `(kind, topic, level)` 会把**同一件事**
      （监理没能启动）拆成两行（topic='' 与 topic='spawn_failed'）。
      这与 A5/A6 是**同一类**缺陷（同因拆两行），只是发生在**写 side**。
      只查读 side（投影）查不到它 —— 必须回到**源码的调用点**。"""
    probs = []
    sites = []
    for node in ast.walk(ast.parse(src)):
        if not (isinstance(node, ast.Call) and _call_name(node) == "record"):
            continue
        if not (len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == kind):
            continue
        sites.append((node.lineno, _kwarg(node, "subkind") is not None))
    if not sites:
        return ["找不到 `record(..., %r, ...)` 的调用点（判据需更新）" % kind]
    has = [ln for ln, ok in sites if ok]
    missing = [ln for ln, ok in sites if not ok]
    if has and missing:
        probs.append("`%s` 的记录点口径不一致：第 %s 行写了 `subkind`，"
                     "第 %s 行没写 ⇒ 同一件事会被归成两行"
                     % (kind, has, missing))
    return probs


@check("S30 A7 同一 kind 的记录点 subkind 口径一致（spawn_failed 两个点都要写）")
def s30():
    probs = _subkind_consistency_problems(_src("host_shield.py"),
                                          "host_shield_spawn_failed")
    return "；".join(probs) if probs else True


@check("N-S30 负控：抽掉 spawn_failed 一个记录点的 subkind ⇒ S30 必须报红")
def n_s30():
    src = _src("host_shield.py")
    mutated = src.replace('               subkind="spawn_failed",\n', "", 1)
    if mutated == src:
        return "负控失效：找不到 `subkind=\"spawn_failed\"` 锚点（判据需更新）"
    if not _subkind_consistency_problems(mutated, "host_shield_spawn_failed"):
        return "负控失效：抽掉一个 subkind 后 S30 仍判绿"
    return True


# ═════════════════ S31 · A8 zone_locked 成败按记录分档（描述＝实现）═══════════════
def _zone_grade_problems(store, model):
    """`zone_locked` 兼表成败 ⇒ 级别/标题/要不要人管/有没有后果，全部**按记录**判。

    ★ 为什么必须**逐条**查这四项（而不是只看 level）：
      0.36.0 的注释写「上锁成功＝自动处理／失败＝要你决策」，但实测那个机制
      **一直是空转的**（`remediation._kind_of` 无条件返回 `zone_locked`）
      ⇒ 一条"上锁成功"被渲染成 R0 失守 + 进「要处理」+ 记成"有后果"。
      只查 level 会漏掉后三项，所以四项一起断言。"""
    kinds = _k()

    def mk(sev, reason):
        return store.project_record(
            {"ts": "2026-10-09T10:00:00+08:00", "type": "host_shield_zone_locked",
             "decision": "deny", "severity": sev, "reason": reason}, kinds)

    ok = mk("warning", "安全区已上锁（区内防篡改；出网由 net_mode 把闸）：D:\\x\\zone")
    bad = mk("critical", "安全区【上锁失败】——有进程在对抗门闸，须人工介入：D:\\x\\zone")
    probs = []
    if ok.level == "R0" or "没守住" in ok.title:
        probs.append("上锁成功被标成失守（level=%s title=%r）" % (ok.level, ok.title))
    if model.needs_owner(ok):
        probs.append("上锁成功进了「要处理」")
    if model.has_consequence(ok):
        probs.append("上锁成功被记成「有后果」")
    if bad.level != "R0" or "没守住" not in bad.title:
        probs.append("上锁失败没被标成失守（level=%s）" % bad.level)
    if not model.needs_owner(bad):
        probs.append("上锁失败没进「要处理」⇒ 唯一要人决策的那类反而看不见")
    if not model.has_consequence(bad):
        probs.append("上锁失败被记成「无后果」")
    return probs


@check("S31 A8 zone_locked 成败按记录分档：成功⇒非失守/不管/无后果；失败⇒失守/要管")
def s31():
    import inbox_model as M
    import inbox_store as S
    probs = _zone_grade_problems(S, M)
    return "；".join(probs) if probs else True


@check("N-S31 负控：让 `_kind_of` 对 zone_locked 恒返一类 ⇒ 成功会被当成失守")
def n_s31():
    import inbox_model as M
    import inbox_store as S
    import remediation
    o = remediation._kind_of

    def flat(item):                      # 变异：退回"按 kind 一刀切"
        if str(getattr(item, "kind", "")) == "host_shield_zone_locked":
            return "zone_locked"
        return o(item)

    remediation._kind_of = flat
    try:
        if _zone_grade_problems(S, M):
            return True
        return "负控失效：`_kind_of` 不分成败后 S31 仍然绿"
    finally:
        remediation._kind_of = o


# ══════════ S32 · 提权判据「唯一口径」（三份实现必须同规则）══════════════
def _elevation_rule_problems(pairs):
    """`pairs` = [(label, src, funcname), ...] —— 每份提权判据必须**同规则**：
    都跑 `whoami`、都认 `S-1-16-`、阈值都是 `0x3000`。

    ★ 为什么是**结构**判据、不是行为判据（限制必须写清）：
      `scripts/verification_tests.py` 随包分发，`ci/drift_audit.py` **不随包**
      ⇒ 前者**不能** import 后者，只能镜像；测试侧还**刻意不** import 被测产品
      （拿被测对象来判测试自己的环境 = 自我指涉）⇒ 只能各自实现。
      而行为上三者在同一台机上**必然同答**（跑的是同一次 `whoami`）⇒
      行为比对**证明不了任何事**。真正会漂的只有**规则本身**（只改一边的阈值或标记）。
    ★ 所以这条挡的是"单侧改动"，**挡不住"三边一起改错"** —— 不夸大成"已验证同源"。
    """
    probs = []
    for label, src, fn in pairs:
        node = _func_tree(src, fn)
        if node is None:
            probs.append("%s 里找不到 %s()" % (label, fn))
            continue
        consts = [n.value for n in ast.walk(node) if isinstance(n, ast.Constant)]
        strs = [c for c in consts if isinstance(c, str)]
        nums = [c for c in consts if isinstance(c, int) and not isinstance(c, bool)]
        if not any("S-1-16-" in s for s in strs):
            probs.append("%s 的 %s() 不再认 `S-1-16-`（完整性级别标记）" % (label, fn))
        if not any("whoami" in s for s in strs):
            probs.append("%s 的 %s() 不再跑 `whoami`" % (label, fn))
        if 0x3000 not in nums:
            probs.append("%s 的 %s() 的提权阈值不再是 0x3000（现为 %s）"
                         % (label, fn, [hex(n) for n in nums]))
    return probs


def _elevation_pairs(overrides=None):
    o = overrides or {}
    return [("host_shield.py",
             o.get("host_shield.py", _src("host_shield.py")), "process_elevation"),
            ("scripts/verification_tests.py",
             o.get("scripts/verification_tests.py",
                   _src("scripts/verification_tests.py")), "_process_elevation"),
            ("ci/drift_audit.py",
             o.get("ci/drift_audit.py", _src("ci/drift_audit.py")), "_acl_audit_usable")]


@check("S32 ★ 提权判据唯一口径：三份实现同规则（whoami / S-1-16- / 0x3000）")
def s32():
    probs = _elevation_rule_problems(_elevation_pairs())
    return "；".join(probs) if probs else True


@check("N-S32 负控：把脚本那侧的阈值改成 0x1000 ⇒ S32 必须报红")
def n_s32():
    va = _src("scripts/verification_tests.py")
    mut = va.replace("lvl >= 0x3000", "lvl >= 0x1000")
    if mut == va:
        return "负控无效：脚本里找不到 `lvl >= 0x3000` 可供变异"
    if _elevation_rule_problems(_elevation_pairs({"scripts/verification_tests.py": mut})):
        return True
    return "负控失效：单侧阈值被改，S32 仍然绿"


@check("N-S32b 负控：把产品侧 host_shield 的阈值改成 0x1000 ⇒ S32 必须报红")
def n_s32b():
    hb = _src("host_shield.py")
    mut = hb.replace("lvl >= 0x3000", "lvl >= 0x1000")
    if mut == hb:
        return "负控无效：host_shield 里找不到 `lvl >= 0x3000` 可供变异"
    if _elevation_rule_problems(_elevation_pairs({"host_shield.py": mut})):
        return True
    return "负控失效：产品侧阈值被改，S32 仍然绿"


# ══════════ S33 · `is_denied()` 必须提权感知（根因修复的防复发）══════════════
def _names_in(node):
    """函数体里出现过的所有名字（调用名／属性／标识符）。"""
    seen = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            nm = _call_name(n)
            if nm:
                seen.add(nm)
        if isinstance(n, ast.Attribute):
            seen.add(n.attr)
        if isinstance(n, ast.Name):
            seen.add(n.id)
    return seen


def _is_denied_elevation_problems(hs_src):
    """`is_denied()` 的实现必须**同时**引用 `process_elevation` 与 `acl_read_deny`。

    ★ 为什么查这两处、而不是查行为：行为判据在**非提权**环境里必然绿
      （那条分支根本不进），跑不出差别；而"提权下把已上锁读成上锁失败"这个根因
      一旦被回退，只有**恰好运行在提权终端**才看得出来 —— 也就是说，
      它会在最不该被发现的地方悄悄复发。⇒ 只能查**结构**：
      提权分支在、且它用的是 ACL 读取（而不是又一次写探针）。

    ★★ 2026-10-22：`is_denied()` 改成**委托**给三态实现 `deny_state()`（N4）。
      判据的意图是"提权感知分支不许被回退"，而它现在落在**真正做判断的那个函数**里。
      ⇒ 若 `is_denied` 只是委托，检查点跟着走；不跟随就等于要求"必须写在老位置上"
        —— 那是拿实现位置冒充判据，也正是这轮 S33 差点变成假红的原因。
    """
    node = _func_tree(hs_src, "is_denied")
    if node is None:
        return ["host_shield.py 里找不到 is_denied()"]
    if "deny_state" in _names_in(node):
        node = _func_tree(hs_src, "deny_state")
        if node is None:
            return ["is_denied() 已委托给 deny_state()，但后者不存在 ⇒ 提权感知无处安放"]
    seen = _names_in(node)
    probs = []
    for need in ("process_elevation", "acl_read_deny"):
        if need not in seen:
            probs.append("`is_denied()` 的实现不再引用 `%s` ⇒ 提权感知被回退"
                         "（提权令牌下会把'已上锁'读成'上锁失败'，并再写出那句冤枉文案）"
                         % need)
    return probs


@check("S33 ★ is_denied() 提权感知：函数体必须同时用 process_elevation + acl_read_deny")
def s33():
    probs = _is_denied_elevation_problems(_src("host_shield.py"))
    return "；".join(probs) if probs else True


@check("N-S33 负控：把提权分支从 is_denied() 摘掉 ⇒ S33 必须报红")
def n_s33():
    hs = _src("host_shield.py")
    # ★★ 2026-10-22：**不写死"提权分支原文"**。那段代码在这一轮从 `is_denied()`
    #   搬进了 `deny_state()`，写死字面量的负控会当场失效并报"找不到原文"
    #   —— 与本仓复发三次的那个形状（负控夹具写死旧文案）一模一样。
    #   ⇒ 按**结构**摘腿：把实现里读 ACL 的那一句换成常量。
    #   这样无论代码搬到哪个函数，只要它还在、这条负控就有分辨力。
    old_call = "r = acl_read_deny(path)"
    if old_call not in hs:
        return "负控无效：host_shield.py 里找不到 `%s`" % old_call
    mut = hs.replace(old_call, "r = False", 1)
    if _is_denied_elevation_problems(mut):
        return True
    return "负控失效：ACL 读取被摘掉，S33 仍然绿"


# ══════════ S34 · 文案不许冤枉人（zone_locked 不得断言"有人对抗"）══════════════
_ACCUSE = "有进程在对抗门闸"


def _zone_locked_reason_strings(hs_src):
    """取 `host_shield_zone_locked` 那条 `record(...)` 的 `reason=` 里的全部字符串常量。"""
    out = []
    for node in ast.walk(ast.parse(hs_src)):
        if not isinstance(node, ast.Call) or _call_name(node) != "record":
            continue
        args = node.args
        if not (len(args) >= 2 and isinstance(args[1], ast.Constant)
                and args[1].value == "host_shield_zone_locked"):
            continue
        for kw in node.keywords:
            if kw.arg == "reason":
                for n in ast.walk(kw.value):
                    if isinstance(n, ast.Constant) and isinstance(n.value, str):
                        out.append(n.value)
    return out


def _zone_locked_text_problems(hs_src):
    strs = _zone_locked_reason_strings(hs_src)
    if not strs:
        return ["找不到 `host_shield_zone_locked` 的 record(...) 及其 reason= 文案"]
    probs = []
    for s in strs:
        if _ACCUSE in s and "不等于" not in s:
            probs.append("zone_locked 的 reason **断言**了「%s」—— 实测真因是提权令牌让写探针"
                         "失真，与「有人对抗」是两回事：%r" % (_ACCUSE, s[:60]))
    return probs


@check("S34 ★ 文案不许冤枉人：zone_locked 的 reason 不得断言「有进程在对抗门闸」")
def s34():
    probs = _zone_locked_text_problems(_src("host_shield.py"))
    return "；".join(probs) if probs else True


@check("N-S34 负控：抽掉 zone_locked 文案里的「不等于」⇒ S34 必须报红")
def n_s34():
    hs = _src("host_shield.py")
    # ★ 0.42.0：文案从 `**不等于**<指控>` 改成 `注意：「不等于」<指控>`
    #   （markdown 星号被 0360 W01 抓到 —— 见 host_shield.py 2752 附近的说明）。
    #   负控锚点跟着改成**语义锚点**「不等于」而不是某个具体标点形式：
    #   钉标点形式 ⇒ 文案一改版负控就失效（本套件这次正踩到）。
    mut = hs.replace("注意：「不等于」" + _ACCUSE, _ACCUSE)
    if mut == hs:
        # 兜底：万一文案又换了一种写法，退回去找没有「不等于」的版本
        mut = hs.replace("不等于" + _ACCUSE, _ACCUSE)
    if mut == hs:
        return ("负控无效：host_shield.py 里找不到「不等于」+%s 可供变异 "
                "（文案换过写法？请同步更新本锚点）" % _ACCUSE)
    if _zone_locked_text_problems(mut):
        return True
    return "负控失效：冤枉断言被放回，S34 仍然绿"


@check("S47 ★ 读侧免疫：item 与归并两条渲染路径都必须过 _vis()（剥 markdown 星号）")
def s47():
    """★ 0.42.0：**读侧免疫** —— item 与归并两条渲染路径都必须过 `_vis()`。

    ★ 为什么必须禁"只改写侧"（0.41.0 → 0.42.0 实测的回归）：
      0.41.0 我把 `zone_locked` 失败文案写成 `**不等于**…`（markdown 加粗），
      而 item 渲染只做 HTML 转义、不解释 markdown ⇒ 那对 `**` 原样吐给用户。
      我把**写侧**改回纯文本，但 `0360 W01` 仍然红 —— 因为审计链是
      append-only，**链上已经躺着那条带星号的记录**。

      ⇒ 只改写侧治的是"本机这一条"；换个用户、换条旧记录，星号照样露。
        正解是**读侧免疫**：`_vis()` 在渲染前剥掉 `**`，不管记录是哪一版写的。

    ★ 必须**两条路径都查**：`_item_html()` 与 `_group_html()` 各有一份 meta，
      0.42.0 第一版只改了前者 ⇒ W01 仍红（归并行是漏掉的那条）。
      ⇒ 判据没覆盖到的那个面，就是缺陷会长的那个面（本仓第 N 次实证）。
    """
    src = _src("inbox_server.py")
    if "_MD_STARS" not in src:
        return "inbox_server.py 里没有 _MD_STARS —— 读侧没有星号清洗"
    probs = []
    for fn, anchor in (("_item_html", "_vis(meta)"),
                       ("_group_html", "_vis(meta)")):
        seg = _func_seg(src, fn)
        if seg is None:
            probs.append("找不到 %s()" % fn)
            continue
        if anchor not in seg:
            probs.append("%s() 的 meta 没有过 %s" % (fn, anchor))
    if probs:
        return "；".join(probs)
    return True


@check("N-S47 负控：把归并路径的 _vis(meta) 退回 _esc(meta) ⇒ S47 必须报红")
def n_s47():
    """负控：把归并那条路径的 `_vis(meta)` 退回 `_esc(meta)` ⇒ S47 必须报红。"""
    src = _src("inbox_server.py")
    node = _func_tree(src, "_group_html")
    if node is None:
        return "负控无效：找不到 _group_html()"
    # ★ 只改**归并函数自己的行区间**内的 `_vis(meta)`，不碰 `_item_html`。
    #   （第一版用全文 `str.replace` 再切片还原 —— `"\n".join` 丢了尾换行，
    #     切片偏移 1 字符，变异落错位置 ⇒ 负控失效。逐行改没有偏移问题。）
    lines = src.split("\n")
    hit = False
    for k in range(node.lineno - 1, node.end_lineno):
        if "_vis(meta)" in lines[k]:
            lines[k] = lines[k].replace("_vis(meta)", "_esc(meta)")
            hit = True
    if not hit:
        return "负控无效：_group_html() 行区间内找不到 _vis(meta)"
    mut = "\n".join(lines)
    seg = _func_seg(mut, "_group_html")
    if seg is None:
        return "负控无效：变异后取不到 _group_html() 段"
    if "_vis(meta)" in seg:
        return "负控失效：归并路径被退回 _esc(meta)，S47 仍然绿"
    # 还要确认另一条路径**没被误改**（否则证明不了是归并这条在起作用）
    if "_vis(meta)" not in (_func_seg(mut, "_item_html") or ""):
        return "负控有问题：_item_html 那条也被改了，证明不了是归并路径在起作用"
    return True


def main():
    print("=" * 78)
    print("0.40.0–0.41.0 判据 —— 四行失守的根因修复（A1–A5 ＋ B2）＋ **B1 撤回的防复发**"
          "＋ 全类型报告审计（A6–A8）＋ **S33/S34 提权盲区的根因修复**"
          "（全部内存/临时目录变异，不写产品文件）")
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
