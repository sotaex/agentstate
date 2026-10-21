#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.47.0 判据 —— **告警预算 ＋ 篡改分通道 ＋ 界面必带分母**（方案 v3.0 §5 三步）。

★★ 由来（方案 v3.0 §5，数据实测，不是设计偏好）：

    提醒与拦截之比 **16,797 : 2,403**（约七比一）；单条规则在提醒中独占
    **73.5%（12,350 / 16,797）**；篡改类记录里疑似真投毒只占 **7.5%（12 / 160）**。

    ⇒ 疲劳是**结构性**的，治理对象是**配额与分级**，不是规则增减。
      方案原话（§7.5）：「不做会怎么复发：疲劳持续，于是有人会想到『把那条规则
      放宽』——**那正是旧病复发的入口**：一放宽，误拦与漏判一起回来。」

★ 本文件逐条落地**三步**：
    步一 提醒预算 → S90/S91/S92/S96（＋ N-S90/N-S91/N-S92/N-S96）
    步二 篡改分通道 → S93/S94（＋ N-S93/N-S94）
    步三 界面必带窗口与分母 → S95（＋ N-S95）
    连带对照（既有保护仍绿）→ S97

★ 编写纪律（沿用 0440/0450/0460）：
    · 每条判据配负控，且负控**真的会红**（先验夹具成立，再验变异后翻面）；
    · 断言打在**行为/结构**上，不查文案、不查行号；
    · **不写任何产品文件**：变异只发生在内存字符串上；账本与链都落临时目录
      （`ANTINEL_HUB_DIR` 由本文件在 import 产品模块**之前**设好）。
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import time
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ★ 渲染产物断言的**统一口径**（C2，`ci/page_caliber.py`）：`body(...)` 剥
#   `<style>`/HTML 注释；`note_text(...)` 归一口径行里的**实时载入时刻**
#   （0.50.4 起 `M.reading_note()` 含 `载入于 HH:MM` —— 逐字比对会跨分钟伪红，
#    与上面 `_iso_now` 记的「量具时间炸弹」同族，见 S95 处注释）。
import page_caliber as PC                                        # noqa: E402

# ★★ 必须在 import 产品模块**之前**把中枢换到临时目录 —— 否则本判据会写脏
#    真实中枢的 `notify_state.json`（那正是 0.40.0 分出来的展示层账本）。
_HUB = tempfile.mkdtemp(prefix="g0470_hub_")
os.environ["ANTINEL_HUB_DIR"] = _HUB

RESULTS = []

#: 预算的配额与窗口（取自产品真身，不在这里另写一份 —— 漂移即红，见 S90）
_HOOK_REL = "hooks/pre_tool_use.py"
_HS_REL = "host_shield.py"
_MODEL_REL = "inbox_model.py"

def _iso_now():
    """当前时刻的 ISO 串（+08:00），供构造 Item 的 ts 用。

    ★★ 0.48.4：这里原先写死 `_NOW = "2026-10-10T23:30:00+08:00"`，注释说
    「落在 24 小时窗口内，判据因此可重复」——**它只在写完的当天成立**。
    产品侧 `_window_open(items, hours=24)` 只收窗口内的记录，于是这个固定
    时点会**随真实时间推进而滑出窗口**：2026-10-11 23:30 之后，本套判据里
    所有 Item 一律被当成"超过 24 小时"，`chans` 恒为空集 ⇒
    S93/N-S93/N-S93b/S95/S99/N-S99 **六条同时转红**（实测 2026-10-11 23:43）。

    这是**量具的时间炸弹，不是产品缺陷**：产品行为自始至终正确，是判据的
    夹具过期了。按本仓铁律「一个时红时绿的量具比恒红的更坏」，修法是让夹具
    每次运行都取"当下"，而不是再钉一个新的固定日期（那只会把炸弹往后拨）。
    """
    import datetime as _dt
    return (_dt.datetime.now(_dt.timezone(_dt.timedelta(hours=8)))
            .replace(microsecond=0).isoformat())


#: 构造 Item 用的时点 —— **每次运行取当下**（理由见 `_iso_now` 的注释）
_NOW = _iso_now()


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


def _load(src, tag):
    """把（可能被变异过的）源码在**内存**里加载成模块（只读：磁盘一字节不动）。"""
    mod = types.ModuleType(tag)
    mod.__file__ = os.path.join(ROOT, rel_of(tag))
    sys.modules[tag] = mod
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)          # noqa: S102
    return mod


def rel_of(tag):
    return _HOOK_REL if tag.startswith("ptu") else (
        _HS_REL if tag.startswith("hs") else _MODEL_REL)


def _model():
    """`inbox_model` 的真身（本文件所有模型级判据都走它，不另起副本）。"""
    import inbox_model as M
    return M


def _hs():
    return _load(_src(_HS_REL), "hs0470_live")


def _fresh_hub(tag):
    """每个判据一份**独立**账本 —— 否则判据之间会互相污染计数。"""
    d = tempfile.mkdtemp(prefix="g0470_ledger_%s_" % tag)
    m = _load(_src(_HS_REL), "hs0470_%s" % tag)
    m.notify_ledger_path = lambda _d=d: os.path.join(_d, "notify_state.json")
    return m, d


def _fresh_hook(tag, cwd=None):
    """独立的钩子实例（账本 + 链都落临时目录）。"""
    d = tempfile.mkdtemp(prefix="g0470_hook_%s_" % tag)
    c = cwd or tempfile.mkdtemp(prefix="g0470_cwd_%s_" % tag)
    os.environ["ANTINEL_HUB_DIR"] = d
    m = _load(_src(_HOOK_REL), "ptu0470_%s" % tag)
    m._hs_module = lambda _d=d: _hs_with_ledger(_d, tag)
    return m, c, d


def _hs_with_ledger(hubdir, tag):
    m = _load(_src(_HS_REL), "hs0470_in_%s" % tag)
    m.notify_ledger_path = lambda _d=hubdir: os.path.join(_d, "notify_state.json")
    return m


def _chain_records(cwd):
    """读临时 cwd 下当天链文件里的全部记录。"""
    d = os.path.join(cwd, ".psl", "audit")
    if not os.path.isdir(d):
        return []
    out = []
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".jsonl"):
            continue
        with io.open(os.path.join(d, fn), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:                                    # noqa: BLE001
                    pass
    return out


# ══════════════ S90 · 提醒预算：配额内出声、超预算合并、原始条数不丢 ══════════════
@check("S90 ★ 提醒预算：配额内逐条出声；超预算后合并；**原始条数一条不丢**")
def s90():
    m, _d = _fresh_hub("s90")
    q = int(m.NOTICE_BUDGET_MAX)
    n = q + 7
    seen = [m.notice_budget_gate("R-X", "s-%d" % i) for i in range(n)]
    spoke = [r for r in seen if r and r["speak"]]
    if len(spoke) != q:
        return "出声 %d 次（应恰为配额 %d）⇒ 预算没在承重" % (len(spoke), q)
    over = [r for r in seen if r and r["reason"] == "over_budget"]
    if len(over) != n - q:
        return "超预算合并 %d 条（应 %d）" % (len(over), n - q)
    # ★★ 关键：**原始条数**必须等于请求总次数（"合并"不许变成"丢弃"）
    if seen[-1]["total"] != n:
        return ("原始条数 total=%d ≠ 请求次数 %d ⇒ 条数在合并过程中丢了"
                % (seen[-1]["total"], n))
    if sum(1 for r in seen if r and r["first_over"]) != 1:
        return "首次跨过配额的标记应恰好出现一次（否则汇总会刷屏）"
    return True


@check("N-S90 负控：摘掉预算（超预算仍逐条出声）⇒ 配额失效 ⇒ 必须红")
def n_s90():
    src = _src(_HS_REL)
    anchor = "        elif int(b.get(\"used\") or 0) < q:"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, "        elif True:"), "hs0470_ns90")
    d = tempfile.mkdtemp(prefix="g0470_ns90_")
    mut.notify_ledger_path = lambda: os.path.join(d, "notify_state.json")
    q = int(mut.NOTICE_BUDGET_MAX)
    # 夹具前提：真实现下这条**确实**被预算挡住 —— 否则负控无分辨力。
    live, dl = _fresh_hub("ns90_live")
    if len([r for r in (live.notice_budget_gate("R-X", "s-%d" % i) for i in range(q + 3))
            if r and r["speak"]]) != q:
        return "夹具不成立：真实现下出声次数≠配额 ⇒ 负控无分辨力"
    spoke = [r for r in (mut.notice_budget_gate("R-X", "s-%d" % i) for i in range(q + 3))
             if r and r["speak"]]
    if len(spoke) == q:
        return "负控失效：摘掉配额判断后出声次数仍是 %d ⇒ 该判断没被依赖" % q
    return True


# ══════════════ S91 · 合并与补记**必须留痕（写链）** ══════════════
@check("S91 ★ 合并与补记必须写链：merged 与 window_closed 各一条，且带原始条数")
def s91():
    m, cwd, _hub = _fresh_hook("s91")
    old = os.getcwd()
    os.chdir(cwd)
    try:
        q = int(_hs().NOTICE_BUDGET_MAX)
        for i in range(q + 4):
            m.notice_gate("R-Y", "s-%d" % i)
        recs = [r for r in _chain_records(cwd)
                if str(r.get("type", "")).startswith("notice_budget")]
        kinds = {r.get("type") for r in recs}
        if "notice_budget_merged" not in kinds:
            return "超预算合并**没写链**（只有 stderr 不算数）⇒ 与静默丢弃无区别"
        # window_closed 要等窗口滚过去才写 ⇒ 把时间推到窗口外再调一次
        import time as _t
        _hs2 = m._hs_module()
        r2 = _hs2.notice_budget_gate("R-Y", "later", now=_t.time() + 10 ** 6)
        if not r2 or not r2.get("closed"):
            return "把时间推到窗口外后仍未收盘 ⇒ 滚动窗口没在承重"
    finally:
        os.chdir(old)
    return True


@check("N-S91 负控：把写链摘掉（只留 stderr）⇒ 链上查不到留痕 ⇒ 必须红")
def n_s91():
    src = _src(_HOOK_REL)
    anchor = "    _notice_budget_trace(res)"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, "    pass"), "ptu0470_ns91")
    d = tempfile.mkdtemp(prefix="g0470_ns91_")
    cwd = tempfile.mkdtemp(prefix="g0470_ns91c_")
    os.environ["ANTINEL_HUB_DIR"] = d
    mut._hs_module = lambda: _hs_with_ledger(d, "ns91")
    old = os.getcwd()
    os.chdir(cwd)
    try:
        q = int(_hs().NOTICE_BUDGET_MAX)
        for i in range(q + 4):
            mut.notice_gate("R-Y", "s-%d" % i)
        recs = [r for r in _chain_records(cwd)
                if str(r.get("type", "")).startswith("notice_budget")]
    finally:
        os.chdir(old)
    if recs:
        return "负控失效：摘掉 `_notice_budget_trace` 后链上仍有留痕 ⇒ 别处也在写"
    # ★ 连回正判据 S91：真实现下同一个动作**必须**有留痕 —— 否则这条负控无分辨力
    return True


# ══════════════ S92 · 绝不静默丢弃（三项加和守恒）══════════════
@check("S92 ★ 绝不静默丢弃：补记里 used + dup + merged == total（原始条数守恒）")
def s92():
    m, _d = _fresh_hub("s92")
    q = int(m.NOTICE_BUDGET_MAX)
    # ★ 顺序有讲究：重复片段必须在**配额耗尽之前**调。
    #   配额耗尽后，从未出声过的片段走的是 over_budget（合并），不是 dedup ——
    #   那是正确语义（"今天已说过"才叫重复），夹具若排反了就会误判成口径混装。
    # ① 同一片段重复：第 1 次出声，其余走 dedup
    for i in range(4):
        m.notice_budget_gate("R-Z", "same-snippet")
    # ② 不同片段：补足配额后，其余走 over_budget
    for i in range(q + 5):
        m.notice_budget_gate("R-Z", "s-%d" % i)
    import time as _t
    closed = m.notice_budget_gate("R-Z", "later", now=_t.time() + 10 ** 6)["closed"]
    if not closed:
        return "窗口外调用未收盘 ⇒ 无法核对守恒"
    t = int(closed["total"])
    if int(closed["used"]) + int(closed["dup"]) + int(closed["merged"]) != t:
        return ("三项加和 %d+%d+%d ≠ total %d ⇒ 有请求没被记账（静默丢弃）"
                % (closed["used"], closed["dup"], closed["merged"], t))
    if int(closed["dup"]) < 3:
        return "同片段重复没被单独记账（dup=%s）⇒ 口径混装" % closed["dup"]
    return True


@check("N-S92 负控：超预算时**不记账直接返回**（静默丢弃）⇒ 守恒被打破 ⇒ 必须红")
def n_s92():
    src = _src(_HS_REL)
    anchor = "        b[\"total\"] = int(b.get(\"total\") or 0) + 1"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    # 变异：超预算分支在累加之前就 return（= 这条请求根本没进账）
    mut_src = src.replace(
        "        else:\n            b[\"merged\"] = int(b.get(\"merged\") or 0) + 1",
        "        else:\n            out[\"reason\"] = \"over_budget\"\n"
        "            d[bkey] = b\n            return d\n"
        "            b[\"merged\"] = int(b.get(\"merged\") or 0) + 1")
    if mut_src == src:
        return "变异锚点 2 未找到（源码已变）—— 负控自身失效，不算通过"
    mut = _load(mut_src, "hs0470_ns92")
    d = tempfile.mkdtemp(prefix="g0470_ns92_")
    mut.notify_ledger_path = lambda: os.path.join(d, "notify_state.json")
    q = int(mut.NOTICE_BUDGET_MAX)
    for i in range(q + 5):
        mut.notice_budget_gate("R-Z", "s-%d" % i)
    import time as _t
    closed = mut.notice_budget_gate("R-Z", "later", now=_t.time() + 10 ** 6)["closed"]
    if not closed:
        return "变异后拿不到收盘数据 ⇒ 负控无法核对（不算通过）"
    t = int(closed["total"])
    if int(closed["used"]) + int(closed["dup"]) + int(closed["merged"]) == t:
        return ("负控失效：静默丢弃变异下三项加和仍等于 total ⇒ "
                "原始条数没被真正记账（预算形同虚设）")
    return True


# ══════════════ S93 · 篡改分通道：两条不共用一盏灯 ══════════════
#: ★★★ 2026-10-21 **重签（口径反转）** —— 创始人「它一直是拦截，现在还是。
#:   这是个问题吧」那一轮的连带。
#:
#:   旧契约：「dev_drift ⇒ 普通 L1 事件灯；tamper ⇒ 不抬灯」—— 靠**灯的差别**
#:   证明两条通道分开了。`INFO_LAMP_LIFT = False`（规格 v1.1 §B 上策：拦截是
#:   事件、不是此刻）之后，**info 桶一律不抬灯** ⇒ dev_drift 也不再点灯
#:   ⇒ 旧断言的两条腿一起落空（实测：两条都是 L0，判据报"共用一盏灯"）。
#:
#:   ★ 重签后**不变的是那条纪律**（不许把「有人动了我的文件」读成「我在改
#:     代码」），变的是它由**什么**守住 —— 现在分的是**去处与说法**，不是灯：
#:       ① 通道分类：`tamper ⇒ "poison"`、`dev_drift ⇒ "dev"`，**两值不许相等**；
#:       ② 自研迭代 ⇒ **进「看一眼」桶**（收件箱里按条看得到、日报有计数），
#:          灯是 L0，且**绝不**进「要处理」（否则变成"请你去处理我在改代码"）；
#:       ③ 疑似投毒 ⇒ 灯一律 L0（已自愈/未自愈都不许读成"此刻的注意"）；
#:       ④ 未自愈投毒 ⇒ **仍须进「要处理」**（只有你能定）—— 分通道不许把
#:          真待办也一起关掉。
#:
#:   ★ 「灯不许永远不亮」这条腿**不在这里**：它由 S100（action 桶持续抬灯）
#:     与 S99④ 承担。本判据只守"两条通道别混"，一件判据只改一个口径。
@check("S93 ★ 篡改分通道：自研迭代进「看一眼」不抬灯；投毒一律不抬灯（分去处，不共用一盏灯）")
def s93():
    import inbox_model as M
    import inbox_store as S
    import host_shield as HS
    kinds = set(HS._ALERT_KINDS)          # ★ 用产品真身（dev_drift 故意不在里面）

    def item(kind, recovered=False, topic=""):
        a = S.project_record({"ts": _NOW, "type": kind, "reason": "p",
                              "recovered": recovered, "subkind": topic,
                              "severity": "critical"}, kinds)
        return M.Item(alert=a, state="unread")

    dev = item("host_shield_dev_drift", topic="code_drift")
    poison_healed = item("host_shield_tamper", recovered=True)
    poison_fresh = item("host_shield_tamper", recovered=False)

    # ① 通道分类（分通道的前提：两个值不许相等）
    cp = M.tamper_channel_of("host_shield_tamper")
    cd = M.tamper_channel_of("host_shield_dev_drift")
    if cp is None or cd is None:
        return "篡改类 kind 没进 TAMPER_CHANNEL_KINDS（%r / %r）⇒ 分通道失效" % (cp, cd)
    if cp == cd:
        return ("投毒与自研迭代被归成同一个通道（都是 %r）⇒ 分通道名存实亡" % cp)

    # ② 自研迭代：进「看一眼」（看得到），不抬灯，且绝不进「要处理」
    b_dev = M.bucket_of(dev)
    if b_dev != M.BUCKET_INFO:
        return ("自研迭代落在 %r 桶（应是 info「看一眼」）—— 进 action 等于"
                "「请你去处理我在改代码」，进 archive 等于看不见" % b_dev)
    l_dev = M.current_state("guarding", None, [dev])
    if l_dev != M.STATE_L0:
        return ("自研迭代抬了 %s 灯 ⇒ 它是「我在改代码」（info、无后果），"
                "不是此刻的注意；身份由研发中徽标说" % l_dev)

    # ③ 疑似投毒：两条都不许抬灯
    l_heal = M.current_state("guarding", None, [poison_healed])
    if l_heal != M.STATE_L0:
        return ("已自愈投毒抬了 %s 灯（level 已降 L1、落 info 桶）⇒ "
                "把「有人动了我的文件」读成了此刻的注意" % l_heal)
    l_fresh = M.current_state("guarding", None, [poison_fresh])
    if l_fresh in (M.STATE_L1, M.STATE_L2):
        return "疑似投毒（未自愈）抬了 %s 灯 ⇒ 投毒被读成「注意/拦截」" % l_fresh

    # ④ 未自愈投毒仍须进「要处理」（分通道不许把真待办也关掉）
    b_fresh = M.bucket_of(poison_fresh)
    if b_fresh != M.BUCKET_ACTION:
        return ("未自愈投毒落在 %r 桶（应是 action「要处理」）⇒ 分通道把"
                "「有人动了我的文件」也一起藏了" % b_fresh)
    return True


def _mk_item(mod, kind, recovered=False, topic=""):
    import inbox_store as S0
    import host_shield as HS0
    a = S0.project_record({"ts": _NOW, "type": kind, "reason": "p",
                           "recovered": recovered, "subkind": topic,
                           "severity": "critical"}, set(HS0._ALERT_KINDS))
    return mod.Item(alert=a, state="unread")


@check("N-S93 负控：回退档下摘掉 poison 门 ⇒ 已自愈投毒抬灯 ⇒ S93 必须红")
def n_s93():
    # ★★ 2026-10-21 重签：现行档（`INFO_LAMP_LIFT = False`）里 info 桶一律
    #   不抬灯 ⇒ 已自愈投毒本就不亮，**poison 那道门在这一档是冗余保险**
    #   （实测：摘掉它三格灯一模一样）。但它是**回退档的必需品** ——
    #   `INFO_LAMP_LIFT = True` 是产品写明的回退开关，那时 info 桶会抬灯，
    #   只有这道门还挡着投毒。
    #   ⇒ 负控**在两档都要握得住**：先在回退档下证明门承重，再确认现行档
    #     下行为仍被 S93③ 守住。只测现行档 = 负控 vacuous（本轮反复吃的病）。
    src = _src(_MODEL_REL)
    anchor = '        if tamper_channel_of(it.kind) == "poison":\n            continue\n'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, ""), "im0470_ns93")
    import inbox_model as M0

    # 两臂对照：回退档下，**有门**必须不抬灯、**无门**必须抬灯
    M0.INFO_LAMP_LIFT = True
    try:
        real_rb = M0.current_state(
            "guarding", None, [_mk_item(M0, "host_shield_tamper", recovered=True)])
    finally:
        M0.INFO_LAMP_LIFT = False
    if real_rb != M0.STATE_L0:
        return ("夹具不成立：回退档下真实现就没挡住已自愈投毒（得到 %s）⇒ "
                "这道门不是唯一防线，负控方向要重定" % real_rb)
    mut.INFO_LAMP_LIFT = True
    got = mut.current_state(
        "guarding", None, [_mk_item(mut, "host_shield_tamper", recovered=True)])
    if got == M0.STATE_L0:
        return "负控失效：回退档下摘掉 poison 门后投毒仍不抬灯（%s）⇒ 该门没被依赖" % got
    return True


@check("N-S93b 负控：把自研迭代摘出「自动处理」名单 ⇒ 它变成待办并抬灯 ⇒ S93 必须红")
def n_s93b():
    # ★★ 2026-10-21 重签：旧方向（"把 dev 也并进 poison 排除集 ⇒ 它丢掉自己的
    #   灯"）随 info 桶不抬灯一起失效了（现在它本来就不亮）。
    #   新方向打在**当下真实存在**的承重处：`dev_drift` 在
    #   `AUTO_HANDLED_KINDS` 里 ⇒ 落 info 桶 ⇒ 不抬灯。把它摘出去，
    #   它就变成「只有你能解决」的待办 ⇒ 抬 L1 灯 + 进「要处理」
    #   ⇒ 正是 S93② 点名的病（"请你去处理我在改代码"）。
    import inbox_model as M0
    old = M0.AUTO_HANDLED_KINDS
    M0.AUTO_HANDLED_KINDS = frozenset(old - {"host_shield_dev_drift"})
    try:
        r = s93()
    finally:
        M0.AUTO_HANDLED_KINDS = old
    if r is True:
        return "负控失效：把自研迭代抬成待办后 S93 仍然绿"
    return True


# ══════════════ S94 · 「失守」标题只归 tamper ══════════════
@check("S94 ★ 标题方向：自研迭代不得挂「失守」（借 code_drift 也不行）")
def s94():
    import inbox_model as M
    t_dev = M.title_of_record("host_shield_dev_drift", "L1", "code_drift")
    if "失守" in t_dev:
        return ("自研迭代挂上了「失守」标题：%r —— 方向反了（把「我在改代码」"
                "说成「防线失守」）" % t_dev)
    # ★ 反向：tamper 那侧**不许**被这道门误伤
    t_tam = M.title_of_record("host_shield_tamper", "R0", "code_drift")
    if "失守" not in t_tam:
        return "疑似投毒反而丢了「失守」标题：%r ⇒ 门开反了" % t_tam
    # 连带：其它事由标题不受影响
    if "自启" not in M.title_of_record("host_shield_breach", "R0", "autostart_missing"):
        return "归因标题被这道门误伤（autostart_missing）"
    if "已上锁" not in M.title_of_record("host_shield_zone_locked", "L1", "zone_ok"):
        return "zone_ok 标题被这道门误伤"
    return True


@check("N-S94 负控：摘掉事由标题归属门 ⇒ 自研迭代重新挂上「失守」⇒ 必须红")
def n_s94():
    src = _src(_MODEL_REL)
    anchor = "    return True if owners is None else kind in owners"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, "    return True"), "im0470_ns94")
    t = mut.title_of_record("host_shield_dev_drift", "L1", "code_drift")
    if "失守" not in t:
        return "负控失效：摘掉归属门后仍不含「失守」⇒ 该门没在承重"
    return True


# ══════════════ S95 · 界面告警数必带窗口与分母 ══════════════
@check("S95 ★ 界面告警数必带窗口与分母（`_bar` / 收件箱 / 托盘 / 日报）")
def s95():
    import inbox_model as M
    import inbox_server as SV
    import inbox_store as S
    import inbox_tray as T
    import host_shield as HS
    kinds = set(HS._ALERT_KINDS)

    def item(kind, state="unread", i=0):
        a = S.project_record({"ts": _NOW, "type": kind, "reason": "r%d" % i,
                              "recovered": False, "subkind": "",
                              "severity": "critical"}, kinds)
        return M.Item(alert=a, state=state)

    items = [item("host_shield_tamper", i=i) for i in range(4)]
    total = len(items)

    # ① 顶部条后缀（非收件箱页）
    bar = SV._bar(items, "T", posture={"state": "guarding", "label": "值守中",
                                       "why": "在岗"}, view="report")
    want = M.count_text(M.count_groups(
        [it for it in items if M.bucket_of(it) == M.BUCKET_ACTION]), total)
    if want not in bar:
        return "顶部条后缀缺「窗口＋分母」形式的件数（应有 %r）" % want
    # ★ 旧的无分母形式**不许**再出现（回潮即红）
    if "件，点开查看）" in bar and want not in bar:
        return "顶部条仍是裸分子"

    # ② 收件箱筛选条上方的口径行
    #   ★★ 0.48.5（交接件 v1.1 §5.3/§5.4）：口径行改走 `M.reading_note()`
    #      （旧 `window_note` 承诺「分母均为 N 条」—— 对四个 tab 至少三个是假的，
    #      且「最近 24 小时」不随页面停留滚动）。分母纪律并未放松：它下沉到
    #      每 tab 可见单位、hover 口径与「？」词条，本套件 ①③ 仍守 count_text。
    #   ★★ 2026-10-16 修（**判据自身时变**，非产品漂移）：0.50.4（Q-22）给
    #      `M.reading_note()` 加了**实时**载入时刻（`载入于 HH:MM`）。原先是
    #      渲染之后**再调一次**该函数逐字比对 —— 两次独立读数跨分钟即伪红
    #      （满载单页渲染实测可达秒级）。⇒ 两侧先归一刻时刻（`PC.note_text`）
    #      再比静态文案；顺带按 C2 走 `PC.body(...)`（正文层，剥 style/注释）。
    #      断言强度未降：静态文案仍须逐字来自唯一实现（0490 N-U01c 反证）。
    page = SV.render_page(view="inbox", root=tempfile.mkdtemp(prefix="g0470_s95_"),
                          token="T", items=items)
    if PC.note_text(M.reading_note()) not in PC.note_text(PC.body(page)):
        return "收件箱页缺口径行（应有 %r）" % M.reading_note()

    # ③ 托盘：`total`（分母）必须落盘，tip 必须带窗口与分母
    root = tempfile.mkdtemp(prefix="g0470_s95t_")
    st = T.sync_from_items(items, root=root)
    if st.get("total") != total:
        return "托盘状态缺分母字段（total=%r，应为 %d）" % (st.get("total"), total)
    if "最近 %d 小时" % M.WINDOW_HOURS not in st["tip"]:
        return "托盘提示缺窗口：%r" % st["tip"]
    if "/ %d" % total not in st["tip"]:
        return "托盘提示缺分母：%r" % st["tip"]
    return True


@check("N-S95 负控：把 `count_text` 退回裸分子 ⇒ 界面重新出现无分母的告警数 ⇒ 必须红")
def n_s95():
    src = _src(_MODEL_REL)
    anchor = ('    return "%d %s / %d（最近 %d 小时）" % '
              '(int(n or 0), unit, int(total), int(hours))')
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, '    return "%d %s" % (int(n or 0), unit)'),
                "im0470_ns95")
    got = mut.count_text(3, 128)
    if "/ 128" in got or "最近 24 小时" in got:
        return "负控失效：退回裸分子后仍带分母/窗口（%r）" % got
    # ★ 连回正判据 S95：真实现下同一个调用**必须**带分母与窗口
    import inbox_model as M0
    live = M0.count_text(3, 128)
    if "/ 128" not in live or "最近 24 小时" not in live:
        return "夹具不成立：真实现下 count_text 就不带分母 ⇒ 负控无分辨力"
    return True


# ══════════════ S96 · 可观测：预算能答「我今天生效了吗」══════════════
@check("S96 ★ 保护自报：预算能答「生效了几次 ＋ 最近一次什么时候」（维五）")
def s96():
    m, _d = _fresh_hub("s96")
    q = int(m.NOTICE_BUDGET_MAX)
    for i in range(q + 4):
        m.notice_budget_gate("R-W", "s-%d" % i)
    rep = m.notice_budget_self_report()
    row = (rep.get("rules") or {}).get("R-W")
    if not row:
        return "自报里查不到 R-W ⇒ 这个保护答不出「我今天生效了吗」（不许上线）"
    if int(row.get("fired") or 0) < 1:
        return "生效次数 fired=%r ⇒ 合并发生过却没记 ⇒ 自报不实" % row.get("fired")
    if not float(row.get("last") or 0.0):
        return "最近一次生效时刻 last=%r ⇒ 自报不完整" % row.get("last")
    if int(row.get("total") or 0) != q + 4:
        return "自报的原始条数 %r ≠ %d ⇒ 自报与账本不同源" % (row.get("total"), q + 4)
    return True


@check("N-S96 负控：摘掉自报里的生效计数 ⇒ fired 恒为 0 ⇒ 必须红")
def n_s96():
    src = _src(_HS_REL)
    anchor = "                b[\"fired\"] = int(b.get(\"fired\") or 0) + 1"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, "                pass"), "hs0470_ns96")
    d = tempfile.mkdtemp(prefix="g0470_ns96_")
    mut.notify_ledger_path = lambda: os.path.join(d, "notify_state.json")
    q = int(mut.NOTICE_BUDGET_MAX)
    for i in range(q + 4):
        mut.notice_budget_gate("R-W", "s-%d" % i)
    row = (mut.notice_budget_self_report().get("rules") or {}).get("R-W") or {}
    if int(row.get("fired") or 0) >= 1:
        return "负控失效：摘掉计数后 fired 仍 ≥1 ⇒ 自报另有来源"
    return True


# ══════════════ S97 · 连带对照：既有保护仍绿 ══════════════
@check("S97 ★ 连带对照：预算只动呈现不动判定；既有「同片段一天一次」去重仍生效")
def s97():
    """★ 交接件 §5.5 维四：改前先问「这次会让哪条既有保证变松」。

    本步 5 的两条既有保证，一条都不能松：
      ① **判定不变**：`collect_hits` 的 block 结论不因提醒预算而变化 ——
         预算只决定"出不出声"，**不许**决定"拦不拦"；
      ② **既有去重仍在**：同一 rule ＋ 同一片段，第二次起应判 `dedup`
         （0.35.3 的"一天只敲一次门"，不是被预算顶替掉）。
    """
    # ① 判定不变（用真规则表跑真判定路径）
    m, cwd, _hub = _fresh_hook("s97")
    old = os.getcwd()
    os.chdir(cwd)
    try:
        with io.open(os.path.join(ROOT, "rules", "default.json"),
                     encoding="utf-8") as f:
            rules = json.load(f)["rules"]
        blocks_before = [x.get("rule_id") for x in m.collect_hits(
            rules, "Bash", {"command": "rm -rf hooks", "file_path": "",
                            "content": "", "url": ""}, ROOT, [], m.EMPTY_POLICY,
            workspace_roots=())
            if x.get("action") == "block"]
        # 把这条规则的提醒预算**彻底用光**（远超配额）之后再判一次
        for i in range(int(_hs().NOTICE_BUDGET_MAX) + 12):
            m.notice_gate("DST-01", "rm -rf hooks")
        blocks_after = [x.get("rule_id") for x in m.collect_hits(
            rules, "Bash", {"command": "rm -rf hooks", "file_path": "",
                            "content": "", "url": ""}, ROOT, [], m.EMPTY_POLICY,
            workspace_roots=())
            if x.get("action") == "block"]
    finally:
        os.chdir(old)
    if "DST-01" not in blocks_before:
        return "夹具不成立：`rm -rf hooks` 本就不拦 ⇒ 判据无分辨力"
    if blocks_after != blocks_before:
        return ("预算用光后判定结论变了（%s → %s）⇒ 预算越界动到了判定"
                % (blocks_before, blocks_after))

    # ② 既有去重仍在
    mm, _dd = _fresh_hub("s97b")
    r1 = mm.notice_budget_gate("R-DUP", "same")
    r2 = mm.notice_budget_gate("R-DUP", "same")
    if not r1 or r1["reason"] != "fresh":
        return "既有去重失效：首次调用 reason=%r（应 fresh）" % (r1 and r1["reason"])
    if not r2 or r2["reason"] != "dedup":
        return ("既有「同片段一天一次」去重被预算顶替：第二次 reason=%r（应 dedup）"
                % (r2 and r2["reason"]))
    return True


# ══════════════ S98 · 并发下绝不静默丢弃（★ 压测撞出来的真洞）══════════════
#: ★ 为什么必须有这一条（0.47.0 并发压测实测，不是推演）：
#:   8 个真进程 × 25 次同一规则 ⇒ 收盘 `total` 只有 **192–195**（应 200），
#:   每次丢 5–8 条，且**没有任何痕迹**。
#:   根因在 `host_shield.ledger_rmw`：`audit_chain.acquire_lock()` 在重试预算
#:   耗尽时返回 **None**（契约明写"预算耗尽返回 None"），而旧实现**没判断** ⇒
#:   拿不到锁也照样读-改-写 ⇒ 多个写者无锁整份覆盖 ⇒ 别人的记账被静默吃掉。
#:   这正是 0.45.0 要根治的那个形状 ——「静默丢失」，只是换了个发生地。
#: ★ 修法方向：拿不到锁 ⇒ **一个字都不写**，返回 False ⇒ 调用方按"没抑制过"
#:   处理（宁可多提示一次）。方向是**更吵**，不是**更静**。
#: 并发 worker 的**公共身体**（正控与负控共用）——
#: ★ 栅栏**不在这里写**：由 `ci/race_amp.run_race()` 注入头部执行会合。
#:   `mod` = 子进程要 import 的产品模块名（负控把变异源码落盘成 `hs_mut.py` 后用 `hs_mut`）。
_CONC_TAIL = '''
import %(mod)s as HS
HS.notify_ledger_path = lambda: os.path.join(os.getcwd(), "notify_state.json")
missed = 0
for i in range(%(iters)d):
    if HS.notice_budget_gate("R-CONC", "%%s-%%d" %% (os.environ.get("RZ_WHO"), i)) is None:
        missed += 1
with open(os.path.join(os.getcwd(), "m-%%s.json" %% os.environ.get("RZ_WHO")),
          "w", encoding="utf-8") as f:
    json.dump({"missed": missed}, f)
'''

#: ★ 前置条件强制化（只强制**前置条件**，不强制结论）：
#:   N-S98 的变异**只在"锁取不到"时才现形**，而"锁取不到"是争用的结果
#:   ⇒ 旧版把"变异是否现形"交给了调度运气（实测撞上率 ≈ 83%，全量闸门里假红过）。
#:   这里把前置条件**直接摆好**：`acquire_lock` 恒返回 None（= 重试预算永远耗尽）。
_NOLOCK_PATCH = '''
import audit_chain
audit_chain.acquire_lock = lambda p, *a, **k: None
audit_chain.release_lock = lambda lk=None: None
'''

#: 并发规模。★ 0.48.5：有了会合栅栏 ⇒ 每轮都**真的同时冲**，
#: 不再需要"靠多轮碰运气"，也不需要一个跑 20–70 秒的大负载。
_NS98_PROCS = 8
_NS98_ITERS = 20          # 正控（s98）用：沿用 0.47.0 的 8×20 = 160
_NS98_MUT_ITERS = 6       # 负控（n_s98）用：另有 20ms 窗口放大，6 次足够丢干净


def _conc_body(mod, iters, force_nolock=False):
    head = ("import json\nimport os\nimport sys\n"
            "sys.path.insert(0, %r)\n" % ROOT)
    if force_nolock:
        head += _NOLOCK_PATCH
    return head + _CONC_TAIL % {"mod": mod, "iters": iters}


def _sum_missed(workdir):
    """把各 worker 落盘的 `m-*.json` 里的"明说没进账"次数加总。"""
    n = 0
    try:
        names = os.listdir(workdir)
    except OSError:
        return 0
    for fn in names:
        if fn.startswith("m-") and fn.endswith(".json"):
            try:
                with io.open(os.path.join(workdir, fn), encoding="utf-8") as f:
                    n += int(json.load(f).get("missed") or 0)
            except Exception:                                    # noqa: BLE001
                pass
    return n


def _ledger_total(workdir):
    """直接读账本里 `budget|R-CONC` 的**原始条数**（没写过 ⇒ 0）。

    ★ 为什么不用 s98 那套"收盘数据"：负控的**对照臂**（修复在场）按定义
      **一条都不写**，账本里压根没有这条记录，收盘数据自然拿不到 ——
      而那正是对照臂该有的样子（"拿不到锁 ⇒ 一个字都不写"）。
    """
    try:
        with io.open(os.path.join(workdir, "notify_state.json"),
                     encoding="utf-8") as f:
            d = json.load(f)
    except Exception:                                            # noqa: BLE001
        return 0
    b = (d or {}).get("budget|R-CONC")
    return int((b or {}).get("total") or 0)


@check("S98 ★ 并发守恒：真进程并发下 进账 + 明说没进账 == 请求总数（绝不静默丢弃）")
def s98():
    """★★ 0.48.5：起进程改走 `ci/race_amp.py` 的**会合栅栏**（N 个进程全部到齐才一起冲）。

    旧版用 `Popen` 一把起 8 个再各跑各的 —— 进程启动错峰（每个 ≈100–200ms）
    会把"同时冲"变成"排队冲"，争用强度随机器负载漂移。会合栅栏把这一步变确定。
    **判定口径一个字没改**（守恒式与配额式都不变）。
    """
    import race_amp
    d = tempfile.mkdtemp(prefix="g0470_conc_")
    body = _conc_body("host_shield", _NS98_ITERS)
    rcs, d = race_amp.run_race(body, _NS98_PROCS, workdir=d, timeout=300)
    if race_amp.join_failed(rcs):
        raise AssertionError("会合失败（有 worker 超时未到齐）⇒ **夹具失效**，"
                             "本轮不算通过也不判红：rcs=%r" % (rcs,))
    if not race_amp.joined_ok(rcs):
        raise AssertionError("并发 worker 非正常退出：rcs=%r ⇒ 夹具失效" % (rcs,))
    total_req = _NS98_PROCS * _NS98_ITERS
    missed = _sum_missed(d)
    m = _hs()
    m.notify_ledger_path = lambda _l=os.path.join(d, "notify_state.json"): _l
    r = m.notice_budget_gate("R-CONC", "closer",
                             now=time.time() + float(m.NOTICE_BUDGET_WINDOW) + 10)
    closed = (r or {}).get("closed")
    if not closed:
        raise AssertionError("并发后没拿到收盘数据 ⇒ 无法核对守恒")
    t = int(closed["total"])
    if t + missed != total_req:
        raise AssertionError(
            "total(%d) + 记账失败(%d) = %d ≠ %d ⇒ 有 %d 次请求既没进账也没被告知"
            "（静默丢弃）" % (t, missed, t + missed, total_req, total_req - t - missed))
    if int(closed["used"]) > int(m.NOTICE_BUDGET_MAX):
        raise AssertionError("并发下出声 %s 次 > 配额 %s ⇒ 并发把配额冲破了"
                             % (closed["used"], m.NOTICE_BUDGET_MAX))


@check("N-S98 负控：恢复「拿不到锁也照样写」⇒ 并发重新静默丢计数 ⇒ 必须红")
def n_s98():
    """★★ 0.48.5 重做：**两臂对照 ＋ 会合栅栏 ＋ 前置条件强制化**（装置见 `ci/race_amp.py`）。

    ★ 旧版为什么必须换（实测，不是推演）：
      旧版把"撞不撞得上"交给运气 —— 8 进程 × 20 次无锁读改写，**只**在
      `acquire_lock` 重试预算真的耗尽时才现形，而预算是争用的结果。
      本机复跑 6 轮 **5 撞 / 1 不撞**；全量交付闸门里就报过
        「4 轮并发守恒均成立（末轮 total=160, missed=0）」。
      本仓铁律「一个时红时绿的量具比恒红的更坏」⇒ 不许再赌。

    ★ 现在的做法（三件事，缺一不可）：
      ① **会合栅栏**：8 个进程全部到齐才一起冲（消掉启动错峰）；
      ② **前置条件强制化**：把 `audit_chain.acquire_lock` 打成恒返回 `None`
         —— 缺陷**只在锁取不到时才现形**，那就把"锁取不到"直接摆好；
         另把读写窗口人为拉宽 20ms（**只放大窗口，不改判定语义**）；
      ③ **两臂对照**：同一套夹具跑两遍，**只差"修复在不在"** ——
         · 对照臂（修复在场）⇒ 必须 `total==0 且 missed==N`（一个字都不写，
           且每一次都**明说**没记上账）；守恒成立；
         · 变异臂（摘掉修复）⇒ 必须**破坏守恒**。
         对照臂是②的**许可证**：没有它，放大窗口就成了自证其罪
         （"破坏也许是夹具自己造成的"）。
    """
    src = _src(_HS_REL)
    fix = "            if not lock:\n                return False"
    amp = "        d = ledger_read()"
    if fix not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    if src.count(amp) != 1:
        return ("窗口放大锚点 `d = ledger_read()` 出现 %d 次（应恰 1 次）"
                "—— 负控自身失效，不算通过" % src.count(amp))
    amp_src = src.replace(amp, amp + "\n        time.sleep(0.02)")
    mut_src = amp_src.replace(fix, "            pass")
    n_req = _NS98_PROCS * _NS98_MUT_ITERS

    # ── 对照臂：**修复在场**（同一套夹具：会合 ＋ 强制无锁 ＋ 20ms 窗口）──
    ctl = _race_arm(amp_src, "hs0470_ns98_ctl", "hs_ctl")
    if ctl is None:
        return "负控自身失效：对照臂没跑起来（夹具故障），不算通过"
    t_c, m_c = ctl
    if t_c != 0 or m_c != n_req:
        return ("对照臂（**修复在场**）就不守恒：total=%d（应 0）、missed=%d（应 %d）"
                " ⇒ 破坏是夹具自己造成的，本负控不成立"
                % (t_c, m_c, n_req))

    # ── 变异臂：**摘掉修复**（其余一切与对照臂逐字相同）──
    mut = _race_arm(mut_src, "hs0470_ns98_mut", "hs_mut")
    if mut is None:
        return "负控自身失效：变异臂没跑起来（夹具故障），不算通过"
    t_m, m_m = mut
    if t_m + m_m != n_req:
        return True                        # 撞出守恒破坏 ⇒ 负控有效
    return ("负控失效：摘掉修复后仍守恒（total=%d, missed=%d, 应合 %d）"
            " ⇒ 夹具没测出这个修复" % (t_m, m_m, n_req))


def _race_arm(src, tag, modname):
    """跑一臂（会合栅栏 ＋ 强制无锁 ＋ 20ms 窗口），返回 `(total, missed)`。

    跑不起来（会合超时 / worker 非正常退出）⇒ `None` —— 调用方必须报
    「夹具失效」，**绝不**把"没跑起来"读成"没撞上"或"通过了"。
    """
    import race_amp
    d = tempfile.mkdtemp(prefix="g0470_ns98_%s_" % tag)
    # ★ 变异源码落盘成模块文件，让子进程 import 它 ——
    #   内存里的变异模块传不进子进程（落临时目录，不碰产品文件）。
    with io.open(os.path.join(d, modname + ".py"), "w", encoding="utf-8") as f:
        f.write(src)
    body = _conc_body(modname, _NS98_MUT_ITERS, force_nolock=True)
    rcs, d = race_amp.run_race(body, _NS98_PROCS, workdir=d, timeout=300)
    if race_amp.join_failed(rcs) or not race_amp.joined_ok(rcs):
        return None
    return (_ledger_total(d), _sum_missed(d))


# ══════════════ S99 · 疑似投毒 ⇒ 不许被读成「研发中」 ══════════════
#: ★★ 0.51.0 重签（规格 v1.2 §7.2）：v1.1 版断言的是「投毒在场 ⇒ 不抬 **dev 灯**」。
#:   v1.2 里 **dev 已不是灯**（身份移徽标、判据是 PyPI 版本比对，与事件无关），
#:   所以旧断言的落点没了。**不变的是那条纪律**：不许把「有人动了我的文件」
#:   解释成「我在改代码」—— 现在它由两件事共同守住：
#:     ① 通道分类：`tamper ⇒ "poison"`、`dev_drift ⇒ "dev"`，**两值不许相等**；
#:     ② poison 通道**一律不抬灯**（已自愈的 tamper 降档 L1 后也不抬）。
#: ★★★ 2026-10-21 再签（创始人「它一直是拦截，现在还是」）：`INFO_LAMP_LIFT=False`
#:   之后 ④ 那条「只有自研迭代 ⇒ 必须还有 L1」不成立了 —— 现在它**也不抬灯**。
#:   ⇒ ④ 改守「**不点灯 ≠ 看不见**」：灯 L0，但仍在 info 桶（收件箱/日报看得到）。
#:     这条比旧 ④ 更要紧：旧版只防"门开反了"，新版还要防"干脆全不抬灯之后
#:     顺手把自研迭代也藏了"（信息丢失比灯多亮一次严重得多）。
def _s99_core(M):
    """S99 的纯判断（正/负控共用；`M` 可注入变异体）。返回 True 或说明串。"""
    cp = M.tamper_channel_of("host_shield_tamper")
    cd = M.tamper_channel_of("host_shield_dev_drift")
    if cp is None or cd is None:
        return "篡改类 kind 没进 TAMPER_CHANNEL_KINDS（%r / %r）⇒ 分通道失效" % (cp, cd)
    if cp == cd:
        return "投毒与自研迭代被归成同一个通道（都是 %r）⇒ 分通道名存实亡" % cp

    # ② ★ 承重那一半：**只有已自愈投毒**在场（降档 L1、落 info 桶、未读、fresh）
    #    ⇒ 仍须不抬灯。
    lv0 = M.current_state("guarding", None,
                          [_mk_item(M, "host_shield_tamper", recovered=True)])
    if lv0 != M.STATE_L0:
        return ("只有已自愈投毒在场时灯是 %s（应 L0）⇒ 投毒被读成了普通事件"
                % lv0)

    # ③ 自研迭代 ＋ 未自愈投毒 ⇒ 绝不染成 R0「失守」，也绝不抬 dev
    lv = M.current_state("guarding", None,
                         [_mk_item(M, "host_shield_dev_drift", topic="code_drift"),
                          _mk_item(M, "host_shield_tamper", recovered=False)])
    if lv == M.STATE_DEV:
        return "投毒（未自愈）在场仍抬 dev ⇒ 把投毒读成了自己改代码"
    if lv == M.STATE_R0:
        return ("投毒（未自愈）在场把灯染成 R0「失守」（得到 %s）—— R0 绝不由账给"
                % lv)

    # ④ ★ 反向：只有自研迭代时 —— 灯 L0，但**必须还在「看一眼」桶里**
    dev = _mk_item(M, "host_shield_dev_drift", topic="code_drift")
    lv3 = M.current_state("guarding", None, [dev])
    if lv3 != M.STATE_L0:
        return ("只有自研迭代时灯是 %s（应 L0）—— 它是 info、不是此刻的注意；"
                "身份由研发中徽标说" % lv3)
    if M.bucket_of(dev) != M.BUCKET_INFO:
        return ("自研迭代被挪出了「看一眼」桶（得到 %r）⇒ 不点灯变成了看不见，"
                "信息丢了" % (M.bucket_of(dev),))
    return True


@check("S99 ★ 疑似投毒不许被读成「研发中」：通道两值不等 ＋ 投毒不抬灯 ＋ 自研迭代看得到")
def s99():
    import inbox_model as M
    return _s99_core(M)


@check("N-S99 负控：把投毒并进自研通道 ⇒ 回退档下已自愈投毒抬灯 ⇒ S99 必须红")
def n_s99():
    # ★ 0.51.0 重签：旧锚点（`if "poison" in chans: return lv`）随 0.51.0 消失。
    #   新变异＝**把两条通道归成一类**（投毒写成 "dev"）—— 正是 S99 标题点名的病：
    #   「把有人动了我的文件，读成我在改代码」。
    # ★★ 2026-10-21 补：现行档（info 桶不抬灯）里归成一类也看不出差别
    #   （已自愈投毒本就不亮）⇒ 负控必须**在回退档下**跑，否则 vacuous。
    src = _src(_MODEL_REL)
    anchor = '    "host_shield_tamper": "poison",       # 疑似投毒（防护文件被动过）'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(
        anchor, '    "host_shield_tamper": "dev",          # ← MUTANT：并进自研通道'),
        "im0470_ns99")
    if mut.tamper_channel_of("host_shield_tamper") == \
       mut.tamper_channel_of("host_shield_dev_drift"):
        mut.INFO_LAMP_LIFT = True                 # ← 回退档：info 桶会抬灯
        r = _s99_core(mut)
        if r is True:
            return ("负控失效：两条通道归成一类、且回退档下 info 抬灯，"
                    "S99 仍然绿")
        return True
    return "负控失效：变异没生效（两值仍不等）⇒ 该分类没被 S99① 依赖"


def main():
    print("=" * 78)
    print("0.47.0 判据 —— 告警预算 / 篡改分通道 / 界面必带分母（方案 v3.0 §5）")
    print("（变异只在内存，账本与链只落临时目录，不写任何产品文件）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                why = ""
            print("  ✅ %-64s %s" % (name, why or ""))
            ok += 1
        except AssertionError as e:
            print("  ❌ %-64s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-64s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
