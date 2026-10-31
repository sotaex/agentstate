#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.64 去噪 -- `notify` 三档的唯一实现（契约 v0.3 §5.1／§3）。

三层三个问题，三套词，别再混用：

    action    做了什么      allow / record / alert / block   （写入者给的事实）
    decision  判成什么      ← decision_of() 派生，不独立写
    notify    要不要打扰    ← notify_of() 派生，**不落盘**

★ 为什么 notify 不落盘（P2 已拍，契约 §5.1）
  账本有 70 处 decision 写入点。把 notify 落盘＝70 处各自决定自己的 notify，
  等于把「同一事实多处实现」从 1 个字段复制成 2 个字段 × 70 处。
  不落盘则：写点改动 0、账本改动 0、N4 自动成立（规则根本设不了 notify）、
  历史自动兼容（回退表就是函数体）。
  代价一处：规则无法显式声明「这条要打扰我」—— 留 `notify_hint` 作渐进路线，本版不做。

★ 默认值为什么偏「吵」（契约 §2 末行）
  漏报不可逆，多报只是烦。遇到没见过的 decision 值、或两字段全无的记录，
  一律 toast，绝不 none。**这条是安全腿，不是风格偏好。**

★ 纯函数
  无 IO、无副作用、不读环境、不写账本、不缓存。同样的 record 永远得同样的结果，
  这样它才能被单测穷举，也才能在值守台与服务端两侧共用同一套判定。

0.64.0 新增。
"""

# ── 三档 ────────────────────────────────────────────────────────────────────
GATE = "gate"      # 停下等人处理（已拦下 / 必须让人知道）
TOAST = "toast"    # 提醒但不停（该吵，但可略过）
NONE = "none"      # 不进通知面

NOTIFY_LEVELS = (GATE, TOAST, NONE)

#: 未知取值／字段全无 ⇒ **偏吵**（漏报不可逆，多报只是烦）
NOTIFY_DEFAULT = TOAST


# ── action（写入者给的事实，4 个取值）────────────────────────────────────────
ACTION_ALLOW = "allow"
ACTION_RECORD = "record"
ACTION_ALERT = "alert"
ACTION_BLOCK = "block"

#: `record` 是「执行事实」（post_tool_use），不是裁决 —— 它的裁决已由
#: 同一批调用的 pre_tool_use 记录表达过。映射成 allow ⇒ notify=none。
_ACTION_FIXED = {
    ACTION_BLOCK: "block",
    ACTION_ALERT: "alert",
    ACTION_RECORD: "allow",
}

#: `allow` + 这两档 severity ⇒ 必须升级成 alert。
#: 实测依据（2026-10-31 账本 164,266 条）：`critical`+`allow` 333 条 ——
#: 「判成 critical 却静默放行」，正是 0.64 要去掉的噪音反面（该吵的没吵）。
#: `warning` 同理：warning 被 allow 吞掉就是漏报。
_SEVERITY_ESCALATE = frozenset(("critical", "warning"))


# ── decision（11 个取值，其中 4 个来自配置面，不由 action 派生）─────────────
#: 这些 decision 表达的是「配置/报告面」的事实，`action` 表达不了。
#: 若让 action 覆盖它们，`config_refresh`（13+2 条）会被误升级成 toast，
#: 而契约 §3 明确它应为 none（正常的配置刷新不该打扰）。
_DECISION_FROM_CONFIG_FACE = frozenset((
    "config_refresh",
    "config_fallback",
    "config_rejected",
    "finding",
))

#: 同义归一：`deny` 与 `block` 在账本里并存（`command_deletion_permission`
#: 176 条 deny + 175 条 deny&block）。0.64 起统一成 `block`（契约 §5.3 S5）。
_DECISION_ALIAS = {"deny": "block"}

#: 「取严」用的严重度序。**当 action 派生值与已有的 decision 打架时，取更重的那个。**
#:
#: ★ 为什么是「取严」而不是「action 优先」（2026-10-31 全量交叉表给的答案）：
#:   action×decision 一共只出现 14 种组合，其中真正冲突的两种方向是
#:       `alert` + `allow`   949 条   （action 更重）
#:       `block` + `deny`    176 条   （同义两词）
#:   实测**不存在** `allow` + `alert` 这个反方向 —— 所以今天 action 优先不会漏报。
#:   但「今天不漏」不等于「明天不漏」：任何写入者只要写成 action=allow 而
#:   decision=alert，action 优先就会把它静默，而**漏报不可逆**。
#:   取严对两个方向都安全，且今天的行为与 action 优先完全一致（因为反方向是空的）。
_RANK = {"block": 3, "alert": 2, "warn": 2, "allow": 1}

#: 契约 §3 回退表（定稿）。**这张表就是函数体的数据部分** ——
#: 改它等于改运行时行为 ⇒ minor bump（见 CONTRIBUTING 的版本纪律）。
_NOTIFY_OF_DECISION = {
    "block": GATE,            # 已拦下，必须让人知道
    "deny": GATE,             # 与 block 同义（历史记录里仍会出现，故保留键）
    "alert": TOAST,           # 提醒但没拦
    "warn": TOAST,            # 0.64 引入的目标值，尚未有写入者
    "config_fallback": TOAST,  # 配置失效要让人知道
    "config_rejected": TOAST,  # 同上
    "finding": TOAST,         # 报告类结论
    "config_refresh": NONE,   # 正常配置刷新，不该打扰
    "allow": NONE,            # 放行不打扰
}

#: 结构上**不是事件**的 type ⇒ 不进通知面。
#: 这不是「静音」，是「不适用」—— 三类都不表达「发生了什么需要人看的事」。
#: 判据全部来自 2026-10-31 全量 type 画像（34 类 / 164,266 条）：
#:   usage_delta             40,878 条：token 与费用计量，无 decision/action/severity
#:   session_dna                 33 条：会话汇总
#:   pre_tool_use_summary     1,163 条：按**调用**聚合，与逐条 pre_tool_use 覆盖同一批
#:                                     调用（133 条 alert + 330 条 block）。若它也进
#:                                     通知面，一次命中会提醒两次（逐条一次＋汇总一次）
#:   notice_budget_window_closed  759 条：通知预算的**账务流水**，reason 是
#:                                     「本窗口 5 条提醒，出声 0 条」。让它 toast 会出现
#:                                     「说出声 0 条、自己却出声」的自相矛盾
#:   notice_budget_merged         151 条：同上（合并记账）
#: 其余 29 类一律走回退表 —— 未列入不等于放行，未知 type 默认 TOAST。
NON_EVENT_TYPES = frozenset((
    "usage_delta",
    "session_dna",
    "pre_tool_use_summary",
    "notice_budget_window_closed",
    "notice_budget_merged",
))


def _clean(value):
    """非字符串／空白 ⇒ None。不猜、不 zhuan 换类型。"""
    if not isinstance(value, str):
        return None
    s = value.strip()
    return s or None


def _derive_from_action(action, severity):
    """只从 action（＋severity）派生 decision；派生不出来 ⇒ None。"""
    act = _clean(action)
    if act is None:
        return None
    fixed = _ACTION_FIXED.get(act)
    if fixed is not None:
        return fixed
    if act == ACTION_ALLOW:
        # 放行但严重度不低 ⇒ 升级成 alert（333 条 critical+allow 的修法）
        if _clean(severity) in _SEVERITY_ESCALATE:
            return "alert"
        return "allow"
    return None                      # 没见过的 action ⇒ 不猜


def decision_of(action, severity=None, current=None):
    """`decision` 的唯一派生实现 —— 今天这段逻辑散在 70 处写入点里。

    参数
    ----
    action    : 写入者给的 action（allow/record/alert/block）。可缺省。
    severity  : 这条命中的严重度（none/info/warning/critical）。可缺省。
    current   : 账本里**已有**的 decision。三种情况下被采用：
                ① 它属于配置/报告面（`_DECISION_FROM_CONFIG_FACE`）——action 表达不了；
                ② 没有 action 可派生（历史记录、宿主侧写入者）；
                ③ 它比 action 派生出来的**更重**（取严，见 `_RANK`）。
                其余情况由 action 重新派生 —— 这正是「收敛」的含义。

    返回
    ----
    收敛后的 decision 字符串；三样都拿不到 ⇒ None（**不猜**）。
    """
    cur = _clean(current)
    if cur is not None:
        cur = _DECISION_ALIAS.get(cur, cur)

    # ① 配置/报告面的事实优先于 action（action 表达不了它们）
    if cur in _DECISION_FROM_CONFIG_FACE:
        return cur

    derived = _derive_from_action(action, severity)

    # ② 没有 action（历史记录 / 宿主侧写入者）⇒ 沿用已有 decision
    if derived is None:
        return cur
    # ③ 没有已有 decision ⇒ 用派生值
    if cur is None:
        return derived

    # ④ 两边都有 ⇒ 取严（漏报不可逆，多报只是烦）
    if _RANK.get(cur, 0) > _RANK.get(derived, 0):
        return cur
    return derived


def notify_of(record, default=None):
    """`notify` 的唯一实现。返回 `"gate"` / `"toast"` / `"none"`。

    `record` 是账本里的一条 dict（或任何带 `type`/`action`/`decision`/`severity`
    的映射）。不是 dict、字段全无、取值没见过的，一律返回 `default`
    （默认 `NOTIFY_DEFAULT`＝`"toast"`）—— **偏吵**，见模块头。
    """
    fallback = NOTIFY_DEFAULT if default is None else default

    if not isinstance(record, dict):
        return fallback

    t = _clean(record.get("type"))
    if t is not None and t in NON_EVENT_TYPES:
        return NONE

    d = decision_of(record.get("action"), record.get("severity"), record.get("decision"))
    if d is None:
        return fallback
    return _NOTIFY_OF_DECISION.get(d, fallback)


def explain(record):
    """给对账／排查用：返回 `(notify, decision, why)`。

    `why` 是**给人看的一句话**，说明这条为什么落到这一档。它不参与判定，
    只是让「逐桶对账」能解释每一档的来源（S2 验收要求「变化可解释」）。
    """
    fallback = NOTIFY_DEFAULT
    if not isinstance(record, dict):
        return (fallback, None, "记录不是 mapping ⇒ 按默认值偏吵")

    t = _clean(record.get("type"))
    if t is not None and t in NON_EVENT_TYPES:
        return (NONE, None, "type=%s 结构上不是事件（不适用，非静音）" % t)

    d = decision_of(record.get("action"), record.get("severity"), record.get("decision"))
    if d is None:
        return (fallback, None, "action/decision/severity 全无 ⇒ 默认偏吵")
    n = _NOTIFY_OF_DECISION.get(d, fallback)
    if d not in _NOTIFY_OF_DECISION:
        return (n, d, "decision=%s 不在回退表内 ⇒ 默认偏吵" % d)
    return (n, d, "decision=%s 按回退表" % d)


def decision_values():
    """回退表覆盖的 decision 取值（给单测窮举用，避免测试自己抄一份）。"""
    return tuple(sorted(_NOTIFY_OF_DECISION))


def non_event_types():
    """非事件 type 集合（给单测与文档生成用）。"""
    return tuple(sorted(NON_EVENT_TYPES))
