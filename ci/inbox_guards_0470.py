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

# ★★ 必须在 import 产品模块**之前**把中枢换到临时目录 —— 否则本判据会写脏
#    真实中枢的 `notify_state.json`（那正是 0.40.0 分出来的展示层账本）。
_HUB = tempfile.mkdtemp(prefix="g0470_hub_")
os.environ["ANTINEL_HUB_DIR"] = _HUB

RESULTS = []

#: 预算的配额与窗口（取自产品真身，不在这里另写一份 —— 漂移即红，见 S90）
_HOOK_REL = "hooks/pre_tool_use.py"
_HS_REL = "host_shield.py"
_MODEL_REL = "inbox_model.py"

#: 构造 Item 用的固定时点（落在 24 小时窗口内，判据因此可重复）
_NOW = "2026-10-10T23:30:00+08:00"


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
@check("S93 ★ 篡改分通道：自研迭代 ⇒ dev 灯；疑似投毒 ⇒ 不是 dev 灯（不共用一盏）")
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

    l_dev = M.current_state("guarding", None, [dev])
    l_heal = M.current_state("guarding", None, [poison_healed])
    l_fresh = M.current_state("guarding", None, [poison_fresh])
    if l_dev == l_heal:
        return ("自研迭代与疑似投毒共用一盏灯（都是 %s）⇒ 正是方案 §5 步二点名的病"
                % l_dev)
    if l_dev == l_fresh:
        return "自研迭代与未自愈投毒共用一盏灯（都是 %s）" % l_dev
    if l_dev != M.STATE_DEV:
        return "自研迭代没有走它自己的 dev 灯（得到 %s）" % l_dev
    if l_heal == M.STATE_DEV:
        return "疑似投毒（已自愈）被判成研发中 ⇒ 把投毒读成了自己改代码"
    return True


def _mk_item(mod, kind, recovered=False, topic=""):
    import inbox_store as S0
    import host_shield as HS0
    a = S0.project_record({"ts": _NOW, "type": kind, "reason": "p",
                           "recovered": recovered, "subkind": topic,
                           "severity": "critical"}, set(HS0._ALERT_KINDS))
    return mod.Item(alert=a, state="unread")


@check("N-S93 负控：把 dev_drift 放回共用的 L1 桶 ⇒ 两条重新共用一盏灯 ⇒ 必须红")
def n_s93():
    # ★ 为什么变异这一处：真正让两条"共用一盏灯"的，是 **dev_drift 被算进
    #   L1 抬灯桶**（0.46.0 的原状）。只摘掉 `_tamper_channel_light` 里的
    #   dev 分支，dev_drift 会掉回 L0 —— 两条**仍然不同灯**，负控就没有分辨力
    #   （首跑已实测：L0 vs L1）。⇒ 变异必须打在"共用的那个桶"上。
    src = _src(_MODEL_REL)
    anchor = '              and tamper_channel_of(it.kind) != "dev"]'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, "]"), "im0470_ns93")
    import inbox_model as M0

    # 夹具前提：真实现下两条**不同灯** —— 否则负控无分辨力
    if M0.current_state("guarding", None,
                        [_mk_item(M0, "host_shield_dev_drift",
                                  topic="code_drift")]) == \
       M0.current_state("guarding", None,
                        [_mk_item(M0, "host_shield_tamper", recovered=True)]):
        return "夹具不成立：真实现下两条本就同灯 ⇒ 负控无分辨力"
    a = mut.current_state("guarding", None,
                          [_mk_item(mut, "host_shield_dev_drift",
                                    topic="code_drift")])
    b = mut.current_state("guarding", None,
                          [_mk_item(mut, "host_shield_tamper", recovered=True)])
    if a != b:
        return "负控失效：放回共用桶后两条仍不同灯（%s vs %s）⇒ 该排除没被依赖" % (a, b)
    return True


@check("N-S93b 负控：摘掉 dev 灯分支 ⇒ 自研迭代丢掉自己的灯 ⇒ 必须红")
def n_s93b():
    src = _src(_MODEL_REL)
    anchor = '    if "dev" in chans and lv in (STATE_L0, STATE_DEV):\n        return STATE_DEV'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, "    if False:\n        return STATE_DEV"),
                "im0470_ns93b")
    import inbox_model as M0
    real = M0.current_state("guarding", None,
                            [_mk_item(M0, "host_shield_dev_drift",
                                      topic="code_drift")])
    if real != M0.STATE_DEV:
        return "夹具不成立：真实现下自研迭代就没走 dev 灯（%s）" % real
    got = mut.current_state("guarding", None,
                            [_mk_item(mut, "host_shield_dev_drift",
                                      topic="code_drift")])
    if got == M0.STATE_DEV:
        return "负控失效：摘掉 dev 分支后仍亮 dev 灯 ⇒ 该分支没在承重"
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
    page = SV.render_page(view="inbox", root=tempfile.mkdtemp(prefix="g0470_s95_"),
                          token="T", items=items)
    if M.window_note(total) not in page:
        return "收件箱页缺「窗口＋分母」口径行（应有 %r）" % M.window_note(total)

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
_CONC_WORKER = '''
import os, sys, json
sys.path.insert(0, %r)
import host_shield as HS
HS.notify_ledger_path = lambda: %r
n = int(sys.argv[1]); tag = sys.argv[2]; out = sys.argv[3]
missed = 0
for i in range(n):
    if HS.notice_budget_gate("R-CONC", "%%s-%%d" %% (tag, i)) is None:
        missed += 1
with open(out, "w", encoding="utf-8") as f:
    json.dump({"missed": missed}, f)
'''


@check("S98 ★ 并发守恒：真进程并发下 进账 + 明说没进账 == 请求总数（绝不静默丢弃）")
def s98():
    import subprocess
    d = tempfile.mkdtemp(prefix="g0470_conc_")
    led = os.path.join(d, "notify_state.json")
    worker = os.path.join(d, "_w.py")
    with io.open(worker, "w", encoding="utf-8") as f:
        f.write(_CONC_WORKER % (ROOT, led))
    total_req = 8 * 20
    outs = [os.path.join(d, "m%d.json" % i) for i in range(8)]
    procs = [subprocess.Popen([sys.executable, worker, "20", "p%d" % i, outs[i]],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
             for i in range(8)]
    for p in procs:
        p.communicate(timeout=240)
    missed = 0
    for o in outs:
        if os.path.isfile(o):
            missed += int(json.loads(io.open(o, encoding="utf-8").read())["missed"])
    m = _hs()
    m.notify_ledger_path = lambda _l=led: _l
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
    src = _src(_HS_REL)
    anchor = ("            if not lock:\n                return False")
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, "            pass"), "hs0470_ns98")
    import subprocess
    d = tempfile.mkdtemp(prefix="g0470_conc_mut_")
    led = os.path.join(d, "notify_state.json")
    # ★ 把**变异后的源码**落盘成 `hs_mut.py`，让子进程 import 它 ——
    #   内存里的变异模块传不进子进程，只能落盘（落临时目录，不碰产品文件）。
    with io.open(os.path.join(d, "hs_mut.py"), "w", encoding="utf-8") as f:
        f.write(src.replace(anchor, "            pass"))
    w2 = os.path.join(d, "_w2.py")
    with io.open(w2, "w", encoding="utf-8") as f:
        f.write(_CONC_WORKER.replace("import host_shield as HS",
                                     "import hs_mut as HS")
                % (ROOT, led))
    outs = [os.path.join(d, "n%d.json" % i) for i in range(8)]
    procs = [subprocess.Popen([sys.executable, w2, "20", "p%d" % i, outs[i]],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd=d)
             for i in range(8)]
    for p in procs:
        p.communicate(timeout=240)
    missed = 0
    for o in outs:
        if os.path.isfile(o):
            missed += int(json.loads(io.open(o, encoding="utf-8").read())["missed"])
    m2 = _load(src.replace(anchor, "            pass"), "hs0470_ns98_read")
    m2.notify_ledger_path = lambda _l=led: _l
    r = m2.notice_budget_gate("R-CONC", "closer",
                              now=time.time() + float(m2.NOTICE_BUDGET_WINDOW) + 10)
    closed = (r or {}).get("closed") or {}
    t = int(closed.get("total") or 0)
    if t + missed == 160:
        return ("负控失效：恢复「无锁照写」后守恒仍成立（total=%d, missed=%d）⇒ "
                "变异没起作用或并发这次没撞上（重跑一次；若恒绿则该分支没被依赖）"
                % (t, missed))
    return True


# ══════════════ S99 · 疑似投毒在场 ⇒ 不许抬 dev 灯 ══════════════
@check("S99 ★ 疑似投毒在场 ⇒ 不抬 dev 灯（不许把「有人动了我的文件」解释成「我在改代码」）")
def s99():
    import inbox_model as M
    import inbox_store as S
    import host_shield as HS
    kinds = set(HS._ALERT_KINDS)

    def it(kind, recovered=False, topic=""):
        a = S.project_record({"ts": _NOW, "type": kind, "reason": "p",
                              "recovered": recovered, "subkind": topic,
                              "severity": "critical"}, kinds)
        return M.Item(alert=a, state="unread")

    # ① 自研迭代 ＋ 疑似投毒（未自愈）⇒ 不是 dev
    lv = M.current_state("guarding", None,
                         [it("host_shield_dev_drift", topic="code_drift"),
                          it("host_shield_tamper", recovered=False)])
    if lv == M.STATE_DEV:
        return "投毒（未自愈）在场仍抬 dev 灯 ⇒ 把投毒读成了自己改代码"
    # ② 自研迭代 ＋ 疑似投毒（已自愈）⇒ 也不是 dev
    lv2 = M.current_state("guarding", None,
                          [it("host_shield_dev_drift", topic="code_drift"),
                           it("host_shield_tamper", recovered=True)])
    if lv2 == M.STATE_DEV:
        return "投毒（已自愈）在场仍抬 dev 灯（得到 %s）" % lv2
    # ③ ★ 反向：只有自研迭代时**必须**还是 dev（不许这道门把正常分支也关掉）
    lv3 = M.current_state("guarding", None,
                          [it("host_shield_dev_drift", topic="code_drift")])
    if lv3 != M.STATE_DEV:
        return "只有自研迭代时反而丢了 dev 灯（得到 %s）⇒ 门开反了" % lv3
    return True


@check("N-S99 负控：摘掉 poison 在场这道门 ⇒ 投毒在场仍抬 dev ⇒ 必须红")
def n_s99():
    src = _src(_MODEL_REL)
    anchor = '    if "poison" in chans:\n        return lv'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, "    pass"), "im0470_ns99")
    import inbox_store as S0
    import host_shield as HS0
    kinds = set(HS0._ALERT_KINDS)

    def it(kind, recovered=False, topic=""):
        a = S0.project_record({"ts": _NOW, "type": kind, "reason": "p",
                               "recovered": recovered, "subkind": topic,
                               "severity": "critical"}, kinds)
        return mut.Item(alert=a, state="unread")

    lv = mut.current_state("guarding", None,
                           [it("host_shield_dev_drift", topic="code_drift"),
                            it("host_shield_tamper", recovered=False)])
    if lv != mut.STATE_DEV:
        return "负控失效：摘掉这道门后仍不抬 dev（得到 %s）⇒ 该门没在承重" % lv
    return True


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
