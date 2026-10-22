#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""facts —— 不可变事实快照（F1 冻结）。

## 职责一句话

把「机器现在到底什么情况」采成一份**扁平、无逻辑、可序列化**的字典，供
`situation.py` 的纯函数投影使用。**本模块不判断、不选词、不算灯**。

## 为什么字段表比代码长

F1 冻结的是**接口**，而接口的主要风险不是「函数签名变了」，是「字段悄悄少了
一个」——少一个字段，投影层就会自己补一个默认值，那就是猜。
⇒ 字段表写成「名字／组／类型／来源／缺失语义」五件齐全的数据，缺一不进表。

## 三份冻结件的字段数不一致 —— 本条已登记为 #54

| 出处 | 字段数 | 说明 |
|---|---|---|
| 地基件 §3.1（D-02） | 23 | 字段总表，含诊断/徽标/证据字段 |
| 冻结件 §F1 第 96 行 | 23 ＋ 4 新 ＝ 27 | 新增 `partial_read`/`at_risk`/`chain_recon`/`notice_state` |
| 冻结件 §5.2 的 `BASE`（夹具基线） | 24 | 与上面两方**双向都有缺** |
| **本模块采用** | **30（并集）** | 见下 |

`BASE` 比 `D-02 ∪ 新增4` **多 3 个**：`granary_balance_hours`（冻结件 G4 特冻，
单位小时，源自 `granary.HOURS_PER_DAY=24`）、`counts`（N9 同屏互斥用）、
`egress_free_bytes`（N6-c 磁盘 at-risk 用）。
`BASE` 比 `D-02 ∪ 新增4` **少 6 个**：`heartbeat_ts`/`self_check_problems`/`dev_exempt`/
`published_version`/`code_version`/`heartbeat_slices`（全是诊断、徽标、证据字段，
投影不读，但 D-02 要求产出）。

**裁定取并集 30**，理由：少字段 ⇒ 投影要用时没有 ⇒ 又变成猜（比多字段危险得多）；
而多出来的 3 个每一个都有硬出处（见上）。⇒ 验收口径相应改为
**`BASE` ⊆ `FIELDS`**（不是相等）：夹具给的每个键都必须能喂进 facts，
facts 可以另有夹具不喂的诊断字段（值为 `None`，走 F1 的缺失语义）。

## 类型写法（F1 三态）

`type` 一律写成「基类型」＋可选 `?`（`?` ＝ 允许 `None` 表示「查不到」）。
基类型封闭为 `str/bool/int/float/list/dict` 六种；**禁**用 `0` 或 `False` 冒充缺失
（F1 原文：「禁『0 表示没有』，没有就是 `None`」）。
时长一律秒（`float`，保留 1 位）；绝对时刻一律 ISO8601 本地时区（`str`，禁 epoch）。

## 本模块在 A1 阶段的边界

`collect()` 目前是**骨架**：它不读任何外部来源，所有值由调用方注入。
真读取在 A2 接上，但**入口形状不变**（A2 只换「值从哪来」，不换签名）——
这样 A1 的验收探针在 A2 之后仍然有效，不需要重写。
"""

__all__ = [
    "FIELDS", "GROUPS", "BASE_TYPES", "PROJECTION_KEYS", "EXPECTED_MISSING",
    "collect", "empty_trace", "check_types", "selfcheck",
]

#: 基类型封闭集（F1）。`?` 后缀表示允许 None，不是第七种类型。
BASE_TYPES = ("str", "bool", "int", "float", "list", "dict")

#: 组名 —— 与 D-02 §3.2「registry 的键名直接采用本表的组名」对齐。
#: `notice` 与 `ledger` 是本模块新增的两组（D-02 没有，但 4 个新字段与 counts
#: 无处安放，硬塞进已有组会让「组」失去意义）。
GROUPS = ("scope", "mode", "duty", "trust", "harm", "badge",
          "presence", "notice", "ledger")

#: 字段表 —— 30 项，五件齐全（名字＝键／group／type／source／missing）。
#: `missing` 是「值为 None 时投影该怎么理解」，**不是**「怎么补一个默认值」。
FIELDS = {
    # ---------------------------------------------------------------- scope
    "scope_device": {
        "group": "scope", "type": "str", "source": "machine_id",
        "missing": "单机视图降级（本机固定值，正常不该为 None）",
    },
    "scope_host": {
        "group": "scope", "type": "str?", "source": "宿主归因（现有 host 字段复用）",
        "missing": "不按宿主切分",
    },
    # ----------------------------------------------------------------- mode
    "armed": {
        "group": "mode", "type": "bool?", "source": "host_shield.armed_state()（链权威）",
        "missing": "**不是** unarmed；归 bounded ＋ duty=off（探针 exception 路径）",
    },
    "is_dev": {
        "group": "mode", "type": "bool?", "source": "host_shield.is_dev_build()（登记版＜代码版）",
        "missing": "不挂演练徽标（降级不假阳，同 granary 容错哲学）",
    },
    # ----------------------------------------------------------------- duty
    "sentinel_alive": {
        "group": "duty", "type": "bool?", "source": "sentinel_alive(st)",
        "missing": "duty=off",
    },
    "heartbeat_age": {
        "group": "duty", "type": "float?", "source": "host_shield.sentinel_heartbeat_age()",
        "missing": "看 uptime 兜底；两者都 None ⇒ off",
    },
    "heartbeat_ts": {
        "group": "duty", "type": "str?", "source": "同上（ISO8601 本地时区）",
        "missing": "仅诊断，不参与判定",
    },
    "heartbeat_source": {
        "group": "duty", "type": "str?", "source": "_sentinel_heartbeat_chain()（registered/legacy_pkg/legacy_hub）",
        "missing": "「为什么读不到」说不清 ⇒ 归 bounded",
    },
    "sentinel_uptime": {
        "group": "duty", "type": "float?", "source": "_sentinel_uptime(st)",
        "missing": "无兜底",
    },
    "clock_skewed": {
        "group": "duty", "type": "bool", "source": "BL-02：age<0 ∨ uptime<0（host_shield.py:3621-3624）",
        "missing": "不存在 None —— 算不出 skew 本身也是 skew",
    },
    "granary_level": {
        "group": "duty", "type": "str?", "source": "granary 读数",
        "missing": "不算 at-risk（不假阳）",
    },
    "granary_balance_hours": {
        "group": "duty", "type": "int?", "source": "granary 读数（单位**小时**，HOURS_PER_DAY=24）",
        "missing": "不派生天数；**不许当秒用**（冻结件 G4 异质单位特冻）",
    },
    "credits_low_open": {
        "group": "duty", "type": "bool", "source": "未关闭的 credits_low 记录",
        "missing": "False 为真值（无记录＝没有这件事）",
    },
    "egress_free_bytes": {
        "group": "duty", "type": "int?", "source": "egress.capacity()",
        "missing": "不判磁盘 at-risk；**拿不到不许当满**（N6-c 负控）",
    },
    "at_risk": {
        "group": "duty", "type": "list", "source": "N6 注册表的预告源（granary_low/heartbeat_will_stall/disk_write_full）",
        "missing": "空表 ⇒ 没有预告源（不是「不知道」）",
    },
    # ---------------------------------------------------------------- trust
    "self_check_ok": {
        "group": "trust", "type": "bool?", "source": "host_shield.self_check()",
        "missing": "bounded",
    },
    "self_check_problems": {
        "group": "trust", "type": "list", "source": "同上",
        "missing": "空表为真值（没有问题是事实，不是未知）",
    },
    "dev_exempt": {
        "group": "trust", "type": "list", "source": "_dev_exempt_problems() 的 _fine 类",
        "missing": "空表为真值",
    },
    "chain_integrity_ok": {
        "group": "trust", "type": "bool?", "source": "链完整性校验（入口见 §10.1：audit_chain.chain_link_ok）",
        "missing": "bounded",
    },
    "chain_write_lost": {
        "group": "trust", "type": "int", "source": "audit_chain.write_health() 的 lost（BL-03）",
        "missing": "0 为真值",
    },
    "probe_error": {
        "group": "trust", "type": "str?", "source": "guard_posture 的 except 分支",
        "missing": "None 为真值；非 None ⇒ bounded",
    },
    "partial_read": {
        "group": "trust", "type": "dict?", "source": "N7：{seen, total, why}",
        "missing": "None ⇒ 没有发生截断（**不是**「截断了但不知道多少」）",
    },
    "chain_recon": {
        "group": "trust", "type": "str", "source": "N10：ok / lost_suspect / unknown_window",
        "missing": "封闭三值，不许 None（对账状态本身就是结论）",
    },
    # ----------------------------------------------------------------- harm
    "gaps": {
        "group": "harm", "type": "list", "source": "账本记录派生（v2 读路径补齐，不落盘）",
        "missing": "空表＋能统计 ⇒ none",
    },
    "outage_consequences": {
        "group": "harm", "type": "list?", "source": "_outage_consequences()（现算）",
        "missing": "算不出（与 trust=unbounded 同现）",
    },
    # ---------------------------------------------------------------- badge
    "published_version": {
        "group": "badge", "type": "str?", "source": "workspace_facts.json 登记位（只能实查改写）",
        "missing": "不挂研发徽标",
    },
    "code_version": {
        "group": "badge", "type": "str", "source": "antinel.VERSION",
        "missing": "—（模块常量，不会缺）",
    },
    # ------------------------------------------------------------- presence
    "heartbeat_slices": {
        "group": "presence", "type": "list", "source": "心跳链（D-07）",
        "missing": "空 ⇒ 「没有证据」，**不编造**",
    },
    # --------------------------------------------------------------- notice
    "notice_state": {
        "group": "notice", "type": "str?", "source": "N12 通知三态",
        "missing": "None ⇒ 没有待送达的通知（不是「不知道有没有」）",
    },
    # --------------------------------------------------------------- ledger
    "counts": {
        "group": "ledger", "type": "dict", "source": "账本计数 {action, info}",
        "missing": "0 为真值",
    },
}

#: **已登记「尚未接上」的字段** —— A2 的诚实清单。
#: 每项必须带「为什么现在接不上」＋「哪一步接」；理由为空 ⇒ 判据红（不是豁免）。
#: 双向对账（同 S58）：登记了但实际已接上 ⇒ 也红（表过期＝接了没销账）。
EXPECTED_MISSING = {
    "is_dev": "F1 白名单未列 `is_dev_build()`（实测存在、只读，但不在九类里）"
              "⇒ #55 待扩白名单；**不扩则 mode 轴永远分不出 drill 与 armed**",
    "scope_device": "D-02 写来源 `machine_id`，实测 host_shield **没有这个符号**"
                    "⇒ #55 待指定真实来源",
    "scope_host": "宿主归因字段（现有 host 复用），来源未指定 ⇒ #55",
    "credits_low_open": "来自账本 `credits_low` 记录；白名单列了消费函数却没列"
                        "账本读取入口（`load_items_all`）⇒ #55",
    "gaps": "同上：需要账本 items 才能派生缺口族；白名单不闭合 ⇒ #55",
    "counts": "同上：`day_counts(items)` 需要 items ⇒ #55",
    "outage_consequences": "D-02 写 `_outage_consequences()`，但它是 host_shield 私有"
                           "函数、不在白名单；`guard_posture()` 的 `consequences`"
                           "只在非异常分支给 ⇒ 待 A3 决定取哪个",
    "partial_read": "N7 未实现（`partial_read` 的产出在扫描器改造后）",
    "at_risk": "N6 注册表未实现（预告源三成分）",
    "chain_recon": "N10 对账未实现（依赖 `chain_link_ok`，§10.1 待补）",
    "notice_state": "N12 通知三态未实现",
    "heartbeat_slices": "presence（D-07）未实现，属 A5",
    "published_version": "来自 `workspace_facts.json` 登记位（非白名单函数）"
                        "⇒ 待 A6 徽标接线时接",
    "code_version": "来自 `antinel.VERSION` 模块常量（非白名单函数）"
                 "⇒ 待 A6 徽标接线时接",
    "dev_exempt": "D-02 写 `_dev_exempt_problems()`，私有函数不在白名单 ⇒ #55",
    "chain_integrity_ok": "`chain_link_ok` 不存在（§10.1 已冻结落点、待实现）"
                          "⇒ 按 §7.2 走 trace.missing 记名",
}

#: 投影必需键 —— 即 `ci/_situation_cases.BASE` 的 24 个键。
#: 这 24 个必须全部在 `FIELDS` 里（否则夹具喂不进来）；
#: `FIELDS` 另有 6 个诊断/徽标/证据字段，夹具不喂，值为 None。
PROJECTION_KEYS = (
    "scope_device", "scope_host", "armed", "is_dev",
    "sentinel_alive", "heartbeat_age", "heartbeat_source", "sentinel_uptime",
    "clock_skewed", "granary_level", "granary_balance_hours", "credits_low_open",
    "self_check_ok", "chain_integrity_ok", "chain_write_lost", "probe_error",
    "gaps", "outage_consequences", "partial_read", "at_risk", "chain_recon",
    "notice_state", "counts", "egress_free_bytes",
)


# ───────────────────────────── 二、采集入口 ─────────────────────────────
def empty_trace():
    """空的 trace —— F1 冻结的两键结构：`missing`（缺字段名）与 `sources`（来源）。"""
    return {"missing": [], "sources": {}}


def _live_values():
    """真实采集：**每个来源只调一次**，返回 `(values, sources, errors)`。

    ★★ 为什么是「一次采集」而不是「每字段一个 reader」：
      `guard_posture()` 会跑心跳链读取 ＋ `self_check()`（含 manifest 哈希），
      一次几百毫秒。30 个字段各调一次＝几十秒，而且**同一时刻的两次探测可能
      给出不同的值**（心跳在走）—— 那会让 facts 自相矛盾。
      ⇒ 先采一个上下文，再从它派生。

    ★ 白名单（F1）只允许调这些；本函数**不调任何私有函数**。
      白名单给不出的字段就留空（进 `trace.missing`），由后续步接 —— 不许自己探。

    实测（2026-10-22，impl 树）：
      · `guard_posture()` → evidence 含 10 键（armed/sentinel_alive/heartbeat_age/
        heartbeat_ts/heartbeat_source/sentinel_uptime/sentinel_pid/self_check_ok/
        self_check_problems/heartbeat_dir）—— 一个入口覆盖 8 个 facts 字段
      · `granary.state()` → {state, balance, threshold, days_left, why}
      · `egress.capacity()` → {free, total, low_free, dir_full, readable, …}
      · `audit_chain.write_health()` → {lost, last_error, last_ts}
    """
    vals, srcs, errs = {}, {}, {}

    #: 每个来源「负责」哪些字段 —— 失败时按这张表把 error 精确落到字段上。
    #: ★ 不用「source 字符串前缀匹配」猜归属：那会把 `is_dev`（来源是
    #:   `is_dev_build()`）错标成 guard_posture 的错，误导读日志的人。
    owned = {
        "guard_posture": ("armed", "sentinel_alive", "heartbeat_age",
                          "heartbeat_ts", "heartbeat_source", "sentinel_uptime",
                          "self_check_ok", "self_check_problems",
                          "probe_error", "clock_skewed"),
        "granary": ("granary_level", "granary_balance_hours"),
        "egress": ("egress_free_bytes",),
        "audit_chain": ("chain_write_lost",),
    }

    # ① 聚合入口：guard_posture() —— 8 个字段 + probe_error + clock_skewed 派生
    try:
        import host_shield as HS
        gp = HS.guard_posture()
        ev = gp.get("evidence") or {}
        for k in ("armed", "sentinel_alive", "heartbeat_age", "heartbeat_ts",
                  "heartbeat_source", "sentinel_uptime",
                  "self_check_ok", "self_check_problems"):
            if k in ev:
                vals[k] = ev[k]
                srcs[k] = "host_shield.guard_posture().evidence"
        # probe_error：只有 exception 分支的 evidence 才带 `error` 键
        #   （规则⑥「读不到心跳链」也给 unknown，但**没有** error —— 那不是探针故障）
        # ★ 正常时显式写 None：D-02 说「None 为真值」——「没有探针错误」是一个
        #   **结论**，不是「没接上」。若让它留空进 missing，就会永远挂着一条假缺口。
        if "error" in ev:
            vals["probe_error"] = ev["error"]
            srcs["probe_error"] = "host_shield.guard_posture().evidence.error"
        else:
            vals["probe_error"] = None
            srcs["probe_error"] = ("host_shield.guard_posture()（无 exception ⇒ "
                                   "None 为真值）")
        # clock_skewed 派生（BL-02：age<0 ∨ uptime<0）。纯计算，不算「自己探」——
        #   用的是白名单刚给的两个读数。
        age, up = ev.get("heartbeat_age"), ev.get("sentinel_uptime")
        vals["clock_skewed"] = bool(
            (isinstance(age, (int, float)) and age < 0)
            or (isinstance(up, (int, float)) and up < 0))
        srcs["clock_skewed"] = "derived: heartbeat_age<0 ∨ sentinel_uptime<0 (BL-02)"
    except Exception as e:                                   # noqa: BLE001
        errs["guard_posture"] = repr(e)
        for _k in owned["guard_posture"]:
            srcs[_k] = "error[guard_posture]: %r" % (e,)

    # ② granary.state() —— granary_level / granary_balance_hours
    try:
        import granary as G
        g = G.state()
        if isinstance(g, dict):
            if "state" in g:
                vals["granary_level"] = g.get("state")
                srcs["granary_level"] = "granary.state().state"
            if "balance" in g:
                # balance 的单位**就是小时**（granary.HOURS_PER_DAY=24）
                vals["granary_balance_hours"] = g.get("balance")
                srcs["granary_balance_hours"] = "granary.state().balance（单位小时）"
    except Exception as e:                                   # noqa: BLE001
        errs["granary"] = repr(e)
        for _k in owned["granary"]:
            srcs[_k] = "error[granary]: %r" % (e,)

    # ③ egress.capacity() —— egress_free_bytes
    try:
        import egress as E
        cap = E.capacity()
        if isinstance(cap, dict) and "free" in cap:
            vals["egress_free_bytes"] = cap.get("free")
            srcs["egress_free_bytes"] = "egress.capacity().free"
    except Exception as e:                                   # noqa: BLE001
        errs["egress"] = repr(e)
        for _k in owned["egress"]:
            srcs[_k] = "error[egress]: %r" % (e,)

    # ④ audit_chain.write_health() —— chain_write_lost
    try:
        import audit_chain as A
        wh = A.write_health()
        if isinstance(wh, dict) and "lost" in wh:
            vals["chain_write_lost"] = wh.get("lost")
            srcs["chain_write_lost"] = "audit_chain.write_health().lost"
    except Exception as e:                                   # noqa: BLE001
        errs["audit_chain"] = repr(e)
        for _k in owned["audit_chain"]:
            srcs[_k] = "error[audit_chain]: %r" % (e,)

    return vals, srcs, errs


def collect(_offline=False, **injected):
    """采集一份 facts 快照。返回 `(facts, trace)`。

    · `facts` —— 30 个键**全在**（缺的值为 `None`，**不是不出现**）
    · `trace` —— 只有 `missing` 与 `sources` 两键（F1 冻结，不许加第三键）

    三种取值优先级（高→低）：**注入** ＞ **真实采集** ＞ `None`。

    `_offline=True` ⇒ 完全不读外部（A1 骨架模式／单元测试用）：
    每个来源只调一次的成本在这里是零，探针可以在无环境依赖下反复跑。

    ★ 为什么缺字段也要出现在 facts 里（值为 None）而不是干脆不放这个键：
      「键不存在」与「键在且为 None」差别很大 —— 前者会让投影层的
      `facts.get(k, 默认)` 悄悄生效，那正是 F1 禁止的「静默默认」。

    ★ 读取失败怎么表达：F1 只给了 `missing`/`sources` 两键，所以**不加 errors 键**，
      而是把失败写进 `sources[字段] = "error: <repr>"`，同时该字段进 `missing`。
      这样「读不到」与「没接」在 sources 里可区分，而 trace 结构不变。
    """
    vals, srcs, errs = ({}, {}, {}) if _offline else _live_values()

    facts = {}
    missing = []
    sources = {}
    for name, spec in FIELDS.items():
        if name in injected:
            facts[name] = injected[name]
            sources[name] = "injected"
        elif name in vals:
            facts[name] = vals[name]
            sources[name] = srcs.get(name, "live")
        else:
            facts[name] = None
            missing.append(name)
            # `_live_values()` 已经把「读失败」精确落到 srcs；没落的才是「没接」
            sources[name] = srcs.get(name) or spec["source"]
    return facts, {"missing": missing, "sources": sources}


# ───────────────────────────── 三、结构自检 ─────────────────────────────
def _type_ok(base, val):
    """基类型匹配。★ `bool` 是 `int` 的子类，必须先排掉，否则 `True` 会被当成计数 1。"""
    if base == "bool":
        return isinstance(val, bool)
    if isinstance(val, bool):
        return False
    if base == "int":
        return isinstance(val, int)
    if base == "float":
        return isinstance(val, (int, float))
    return isinstance(val, {"str": str, "list": list, "dict": dict}[base])


def check_types(facts, strict=False):
    """逐字段验类型与可空性。返回问题列表，空＝全绿。

    `strict` 管的是**「None 算不算错」**：
      · `strict=False`（A1 骨架阶段用）：None 一律放行 —— 骨架不读外部，
        诊断字段本来就该是 None，那不是缺陷；
      · `strict=True`（真实采集后用）：声明不可 None 的字段若仍是 None ⇒ 红。
        「空表为真值」的字段（`self_check_problems`/`dev_exempt`/`heartbeat_slices`/
        `counts`）在真实采集里必须给 `[]`/`{}`，**不许给 None** —— 因为 None 的语义是
        「查不到」，而「查过了，没有」是另一件事。
    """
    bad = []
    for name, val in facts.items():
        spec = FIELDS.get(name)
        if spec is None:
            bad.append("未知字段 %r（FIELDS 里没有，投影层会读到一个它不认识的东西）"
                       % name)
            continue
        t = spec["type"]
        nullable = t.endswith("?")
        base = t.rstrip("?")
        if base not in BASE_TYPES:
            bad.append("%s 声明类型 %r 的基类型不在封闭集 %r"
                       % (name, t, BASE_TYPES))
            continue
        if val is None:
            if strict and not nullable:
                bad.append("%s 声明不可 None（%r），实际是 None —— 该字段必须总能算出"
                           % (name, t))
            continue
        if not _type_ok(base, val):
            bad.append("%s 应为 %s，实际 %r" % (name, base, type(val).__name__))
    return bad


def selfcheck():
    """字段表**结构**自检（不接外部数据）。返回问题列表，空＝全绿。

    验六条：① 每字段五件齐全；② `group` 在封闭集；③ `type` 基类型合法；
    ④ `source`/`missing` 非空；⑤ `PROJECTION_KEYS` 无重复且 ⊆ `FIELDS`；
    ⑥ 每个组至少有一个字段（没有空组）。
    """
    bad = []
    need = {"group", "type", "source", "missing"}

    for name, spec in FIELDS.items():
        miss = need - set(spec)
        extra = set(spec) - need
        if miss:
            bad.append("① %s 缺 %r" % (name, sorted(miss)))
        if extra:
            bad.append("① %s 多 %r（四件之外不许加）" % (name, sorted(extra)))
        if spec.get("group") not in GROUPS:
            bad.append("② %s group=%r 不在封闭集" % (name, spec.get("group")))
        t = spec.get("type") or ""
        if t.rstrip("?") not in BASE_TYPES:
            bad.append("③ %s type=%r 基类型非法" % (name, t))
        for k in ("source", "missing"):
            if not str(spec.get(k) or "").strip():
                bad.append("④ %s 的 %s 为空" % (name, k))

    if len(set(PROJECTION_KEYS)) != len(PROJECTION_KEYS):
        dup = sorted({k for k in PROJECTION_KEYS if PROJECTION_KEYS.count(k) > 1})
        bad.append("⑤ PROJECTION_KEYS 有重复：%r" % dup)
    outside = [k for k in PROJECTION_KEYS if k not in FIELDS]
    if outside:
        bad.append("⑤ PROJECTION_KEYS 里的 %r 不在 FIELDS（夹具会喂不进来）"
                   % outside)

    used = {spec["group"] for spec in FIELDS.values() if "group" in spec}
    for g in GROUPS:
        if g not in used:
            bad.append("⑥ 组 %r 没有任何字段（空组会让组名失去意义）" % g)
    return bad
