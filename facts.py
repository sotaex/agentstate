#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""facts —— 不可变事实快照（F1 冻结）。

## 职责一句话

把「机器现在到底什么情况」采成一份**扁平、无逻辑、可序列化**的字典，供
`situation.py` 的纯函数投影使用。**本模块不选词、不算灯、不拼句子** ——
那三件事全在 `situation.py`。

## 本模块只做两件事（A1/A2 与 A3 的分界）

1. `collect()` —— 采事实（A1 骨架／A2 白名单接线）；
2. `axes()` —— 把事实**映射**成四轴（A3，冻结件 §5.2 的 14 行表）。

★ `axes()` 是**映射**不是**判定**：它只回答「哪一格」，不回答「什么灯、什么词」。
  灯与成因是 `situation.py` 的事（A4）——本模块一旦开始算灯，F2 的「投影不读文件
  不看时钟」就会被从底下破掉：灯会跟着 facts 的采集时机漂移。

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
    "AXIS_VALUES", "GAP_LEVEL", "AT_RISK_SOURCES",
    "collect", "axes", "at_risk_sources", "check_axes",
    "empty_trace", "check_types", "selfcheck",
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


# ──────────────────────── 四、四轴映射（A3：facts → 四轴） ────────────────────────
#: 四轴取值 —— 封闭集，与 `ci/_state_matrix_ref.py` 的 MODES/DUTIES/TRUSTS/HARMS 逐字一致。
#: ★ 键顺序即求值顺序：harm 依赖 trust（裁定 R2），必须最后算。
AXIS_VALUES = {
    "mode": ("unarmed", "drill", "armed"),
    "duty": ("on", "at-risk", "off"),
    "trust": ("sound", "bounded", "unbounded"),
    "harm": ("none", "some", "unknown"),
}

#: 缺口族 ⇔ 事件级别 `R0`（**派生，不写死族名** —— 见 `_kind_levels()` 的 #56 说明）。
GAP_LEVEL = "R0"

#: 预告源（at-risk）的三个键 —— 与 `state_registry.STATES["draining"]["badge"]` 同集。
#: ★ #57a（A4 撞出）：`at_risk` 在 F1 里是**字段**，但它此前没有任何生产者 ——
#:   `BASE["at_risk"]` 恒为 `[]`，于是 §5.2 的 at-risk 来路「`at_risk[]` 非空」永远为假，
#:   而 `egress_free_bytes` 那条磁盘来路**只**经由 `at_risk[]` 进入判定
#:   ⇒ N6-c（磁盘将满）会静默假绿。裁定：`at_risk` 由本模块**派生**（纯函数，
#:   输入是 F1 已有字段与产品阈值），`collect()` 填进快照、`axes()` 直接读。
AT_RISK_SOURCES = ("granary_low", "heartbeat_will_stall", "disk_write_full")

#: 懒加载缓存：产品常量（阈值／级别表）。同一进程内恒定，故 `axes()` 仍是纯函数。
_CONST_CACHE = {}


def _const(name):
    """取产品常量（懒加载＋缓存）。取不到返回 `None`，由调用方**显式降级**。

    ★ 为什么不在模块顶层 import：`facts.py` 会被 `situation.py`、`inbox_server.py`
      间接 import，顶层拉进 `host_shield`（含 subprocess/hashlib 与一堆 Windows 常量）
      会让「只想用字段表」的调用方也付这份代价。A2 的 `_live_values()` 同样懒加载。
    ★ 为什么不用「3 × HEARTBEAT_SECONDS」自己算：那是**二次实现产品口径**（铁律 6）。
      `_STALE_AFTER` 改一次定义，这里就要跟着改一次 —— 直接 import 才只有一个真源。
    """
    if name not in _CONST_CACHE:
        _CONST_CACHE[name] = None
        if name == "stale":
            try:
                from host_shield import _STALE_AFTER
                _CONST_CACHE[name] = float(_STALE_AFTER)
            except Exception:                                # noqa: BLE001
                _CONST_CACHE[name] = None
        elif name == "min_free":
            #: 磁盘「快写满了」的阈值 —— 取 `egress.MIN_FREE_BYTES`（产品既有口径）。
            #: ★ #57b：§5.3 N6-c 的理由写「19.6MB＝7 天写入量（84MB/月实测折算）」，
            #:   但 84MB/月是**实测观测值**、产品里没有对应常量 ⇒ 按 19.6MB 实现
            #:   等于把一次观测写死成阈值。改用产品既有的 64MB：夹具两点（15MB 亮、
            #:   200MB 不亮）都满足；要严格 19.6MB 需先新增派生常量（P2）。
            try:
                from egress import MIN_FREE_BYTES
                _CONST_CACHE[name] = float(MIN_FREE_BYTES)
            except Exception:                                # noqa: BLE001
                _CONST_CACHE[name] = None
    return _CONST_CACHE[name]


def _kind_levels():
    """事件级别表 —— 取自 `inbox_model.LEVEL_OF_KIND`（该表自述「唯一真源」）。

    ★★ #56（A3 撞出，已登记）：冻结件 §5.2 的「缺口族」列了 7 个名字
      （`host_shield_tamper`/`code_drift`/`state_drift`/`zone_lock_failed`/
      `autostart_missing`/`spawn_failed`/`host_shield_breach`），实测**混装**了
      4 个 kind 与 3 个 subkind，且两个名字与真实 kind 名不同：

        | 冻结件写法 | 真实落点 | 实测出处 |
        |---|---|---|
        | `spawn_failed` | subkind ⊂ `host_shield_spawn_failed` | `host_shield.py:3413` |
        | `autostart_missing` | subkind ⊂ `host_shield_breach` | `host_shield.py:4141` |
        | `zone_lock_failed` | subkind ⊂ `host_shield_zone_locked` | `host_shield.py:4184` |
        | `code_drift` / `state_drift` | subkind ⊂ `host_shield_tamper` | `host_shield.py:4498/4514` |

      ⇒ 按字面实现，`kind` 永远匹配不上，`harm` **永远是 none** —— 那正是 F1 假绿的
      根因原样保留。裁定：**在 kind 层取族界**（`LEVEL_OF_KIND[kind] == "R0"`），
      7 个族名因此全部被覆盖，且不写死任何一个名字。

    返回 `None` ⇒ 级别表读不到 ⇒ 族界不可判，`harm` 归 `unknown`（fail-closed）。
    """
    if "levels" not in _CONST_CACHE:
        try:
            from inbox_model import LEVEL_OF_KIND
            _CONST_CACHE["levels"] = dict(LEVEL_OF_KIND)
        except Exception:                                    # noqa: BLE001
            _CONST_CACHE["levels"] = None
    return _CONST_CACHE["levels"]


def _num(v):
    """数字或 `None`。★ `bool` 是 `int` 的子类，必须先排掉（否则 `True` 被当成 1 秒）。"""
    if isinstance(v, bool):
        return None
    return float(v) if isinstance(v, (int, float)) else None


def _fresh(age, uptime, stale):
    """心跳是否新鲜（D-03 §4.2 原式 ＋ BL-02 的负数防护）。

    `_elapsed_ok(v)` ≡ `v is not None ∧ v >= 0` —— 负数只可能来自时钟回拨，
    回拨时的「时长」不是时长（BL-02 实测：旧写法 `v <= _STALE_AFTER` 对负数恒真）。

    返回 `True`/`False`/`None`：`None` ＝ **不可判**（阈值读不到），由调用方归 `off`。
    宁可不判「在岗」，也不许拿猜来的阈值判绿。
    """
    if stale is None:
        return None
    a, u = _num(age), _num(uptime)
    if a is not None:
        return a >= 0 and a <= stale
    if u is not None:
        return u >= 0 and u <= stale
    return False                       # 两个读数都没有 ⇒ 证明不了在岗（D-02：两者都 None ⇒ off）


def _self_check_unbounded(facts):
    """自检失败 ∧ 问题不在 dev 豁免里 ⇒ 无界无知。

    ★ 三处不许默认：
      · `self_check_ok is not False` ⇒ 不算失败（`None` 是「查不到」，由别的来路承担，
        不在这里冒充失败）；
      · `self_check_problems is None`（失败但清单没读到）⇒ **算非豁免**（fail-closed）；
      · `dev_exempt is None` ⇒ 没有豁免可援引（同上）。
      反过来若把 None 当「全部豁免」，`sound` 就会被一个读不到的清单骗出来。
    """
    if facts.get("self_check_ok") is not False:
        return False
    probs = facts.get("self_check_problems")
    if probs is None:
        return True
    exempt = facts.get("dev_exempt")
    exempt = set(exempt) if isinstance(exempt, (list, tuple, set)) else set()
    return any(p not in exempt for p in probs)


def _bounded(facts):
    """有界无知的六条来路（D-03 §4.3 ＋ N7）。任一成立即 `bounded`。"""
    if facts.get("probe_error") is not None:                  # ① 探针抛错
        return True
    if facts.get("heartbeat_age") is None and facts.get("heartbeat_source") is None:
        return True                                           # ② 心跳链读不到（分支⑥）
    if facts.get("clock_skewed") is True:                     # ③ 时钟回拨（BL-02）
        return True
    if facts.get("armed") is None:                            # ④ armed 读不到（D-03 明令）
        return True
    if facts.get("granary_level") is None:                    # ⑤ 非核心探针失败（D-14）
        return True
    if facts.get("partial_read") is not None:                 # ⑥ 受监管落点截断（N7／#56）
        return True
    return False


def at_risk_sources(facts):
    """预告源（at-risk 三成分）—— **纯函数**，输入是 F1 已有字段与产品阈值。

    返回按 `AT_RISK_SOURCES` 顺序排列的键列表（可能为空）。三条各自的成立条件：

      · `granary_low`         ← `granary_level == "low"`（阈值已由 `granary.state()` 应用）
      · `heartbeat_will_stall` ← 心跳过了陈旧阈值的一半，但**还没陈旧**
        （`> 0.5×_STALE_AFTER ∧ ≤ _STALE_AFTER`；已陈旧是 duty=off，不是预告）
      · `disk_write_full`     ← `egress_free_bytes` 有值且低于 `egress.MIN_FREE_BYTES`

    ★ 「拿不到」一律不算预告（`None` ⇒ 不亮）：宁可少报一个黄，不许把「不知道」
      说成「快满了」（N6-c 负控②：`capacity()=None` 亮 ⇒ 红）。
    ★ 这是**派生**不是**采集**：不改 `facts`、不读文件、不看时钟。
    """
    stale = _const("stale")
    out = []
    if facts.get("granary_level") == "low":
        out.append("granary_low")
    age = _num(facts.get("heartbeat_age"))
    if stale is not None and age is not None and 0 <= age <= stale and age > 0.5 * stale:
        out.append("heartbeat_will_stall")
    free, floor = _num(facts.get("egress_free_bytes")), _const("min_free")
    if free is not None and floor is not None and free < floor:
        out.append("disk_write_full")
    return out


def axes(facts):
    """facts → 四轴（冻结件 §5.2 的 14 行映射表）。**只产四轴，不产灯**。

    返回 `{"mode","duty","trust","harm"}` 四键，值域见 `AXIS_VALUES`。

    ★ 纯函数：只读 `facts` 这一个 dict，不读文件、不看时钟、不调产品函数。
      （两个阈值/级别表是模块常量，进程内恒定 ⇒ 同输入必同输出。）
    ★ 禁静默默认：一律 `facts.get(k)`（缺键 ⇒ `None` ⇒ F1 的「查不到」），
      **绝不**写 `facts.get(k, 默认)` —— 那正是 F1 明令禁止的静默默认。
    ★ 顺序：mode → duty → trust → harm。harm 依赖 trust（裁定 R2），故必须最后算。

    四轴各自的成立条件逐条见 §5.2；这里只标注**三处容易写错**的地方：
      ① `armed is None` **不许**落 `unarmed`（那是「读不到」不是「没开」）；
      ② `at-risk` 只在 `duty=on` 之内细分（off 就是 off，没有「off 且快没粮」）；
      ③ `harm` 只收**缺口族**（`R0`），预告族（`credits_low`）只进 at-risk/徽标。
    """
    stale = _const("stale")

    # ① mode —— armed 是链权威；is_dev 只用来区分 drill 与 armed
    armed, is_dev = facts.get("armed"), facts.get("is_dev")
    if armed is False:
        mode = "unarmed"
    elif armed is True and is_dev is True:
        mode = "drill"
    else:
        # armed is True ∧ is_dev 为 False/None，或 armed is None（读不到）。
        #   ★ 读不到 armed 不许落 unarmed —— 降级由下面两处显式承担：
        #     ② `armed is None ⇒ duty=off`，③ `_bounded()` 的 `armed is None ⇒ bounded`。
        mode = "armed"

    # ② duty
    alive = facts.get("sentinel_alive")
    fresh = _fresh(facts.get("heartbeat_age"), facts.get("sentinel_uptime"), stale)
    duty = "on" if (alive is True and fresh is True) else "off"
    if armed is None:
        # §5.2 明列的一行：`armed is None` ⇒ duty=off。读不到「装没装」时，
        #   值勤也证明不了（探针 exception 路径）—— 不许拿半份读数判在岗。
        duty = "off"
    elif duty == "on" and (
            facts.get("credits_low_open") is True     # 未关的额度预警
            or bool(facts.get("at_risk"))             # 采集侧预置（可空，见 #57a）
            or bool(at_risk_sources(facts))):         # 派生三成分：粮／心跳／磁盘
        duty = "at-risk"

    # ③ trust
    lost = _num(facts.get("chain_write_lost"))
    if (_self_check_unbounded(facts)
            or facts.get("chain_integrity_ok") is False
            or (lost is not None and lost > 0)           # BL-03／N4
            or facts.get("chain_recon") == "lost_suspect"):   # N10
        trust = "unbounded"
    elif _bounded(facts):
        trust = "bounded"
    else:
        trust = "sound"

    # ④ harm —— 必须在 trust 之后（R2：unbounded ⇒ unknown）
    if trust == "unbounded":
        # 证明不了自己在守 ⇒ 后果也不可信（裁定 R2 把探针里的隐含规则升为明文）
        harm = "unknown"
    else:
        gaps, levels = facts.get("gaps"), _kind_levels()
        if gaps is None or levels is None:
            # 防御分支（`gaps` 声明不可 None，正常走不到）：统计不出 ⇒ 报不出后果。
            #   ★ 不许当 none —— 那会把「看不见」说成「没事」。
            harm = "unknown"
        else:
            harmful = [g for g in gaps
                       if isinstance(g, dict)
                       and g.get("gap_state") in ("open", "acked")   # acked 不算修
                       and levels.get(g.get("kind")) == GAP_LEVEL]   # 只收缺口族
            harm = "some" if harmful else "none"

    return {"mode": mode, "duty": duty, "trust": trust, "harm": harm}


def check_axes(a):
    """四轴结构自检。返回问题列表，空＝全绿。

    验两条：① 恰好四键（不多不少 —— 多一个键就是「顺手把灯也算进来了」）；
    ② 每轴的值在封闭集内。

    ★ 不把「`sound|bounded ∧ unknown` 矛盾输入」算错：那是 R2 允许代码兜住的形状
      （归 `blind`），`gaps` 读不到时正会走到这里。把它判红会让防御分支反过来咬人。
    """
    bad = []
    if set(a) != set(AXIS_VALUES):
        bad.append("① 四轴键集不对：多 %r / 少 %r"
                   % (sorted(set(a) - set(AXIS_VALUES)),
                      sorted(set(AXIS_VALUES) - set(a))))
        return bad
    for k, allowed in AXIS_VALUES.items():
        if a[k] not in allowed:
            bad.append("② %s=%r 不在封闭集 %r" % (k, a[k], allowed))
    return bad
