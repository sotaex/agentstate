# -*- coding: utf-8 -*-
"""值守台 · 数据模型与状态聚合（唯一真源）。

★ 本模块只做**纯逻辑**：不读盘、不联网、不 import 产品其它模块。
  页面 / 托盘 / 通知 / 日报 / 导出，全部 import 本模块取口径 ——
  **判据不许二次实现**（本仓铁律）。

四态（创始人 2026-10-05 拍板）::

    未读 unread ──点开──▶ 已读 read ──┐
                                      ├─▶ 已处理 done     （我处置了）
                                      └─▶ 已忽略 ignored  （我看了，判断无需动作）

★★ 一条最容易漏的硬规则（"未处理"的口径）::

    "未处理" = 未读 + 已读      ← ★ 已读**不**减少未处理数
    只有 done / ignored 才减少。

    为什么：否则"全部已读"这个批量按钮，就变成了**把没处理的事藏起来**的手段 ——
    一个假守卫。安全产品里，"我看过了"绝不等于"没事了"。
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

# ------------------------------------------------------------------ 四态 ----
STATES = ("unread", "read", "done", "ignored")

# ★ "未处理" = 未读 + 已读（见模块 docstring 的硬规则）
OPEN_STATES = ("unread", "read")
# 已关闭
CLOSED_STATES = ("done", "ignored")

# 合法迁移表。同一态重复置位是幂等的（不算错）。
# read/done/ignored 都能"重开"回 read —— 手滑了要能撤销。
_TRANSITIONS = {
    "unread": {"read", "done", "ignored"},
    "read": {"done", "ignored", "unread"},
    "done": {"read"},
    "ignored": {"read"},
}


class InboxError(Exception):
    """值守台数据层的统一异常基类。"""


class UnknownKind(InboxError):
    """出现了 LEVEL_OF_KIND 未登记的 kind —— 必须报错，不许静默降级。"""


class BadState(InboxError):
    """非法状态名 / 非法迁移。"""


class NoteRequired(InboxError):
    """该级别的事件在"忽略"时必须写备注。"""


# ------------------------------------------------------------- 级别映射 ----
# 优先级：R0 > L2 > L1 > Ls > L0（对齐 LOGO 五态）
PRIORITY = {"R0": 5, "L2": 4, "L1": 3, "Ls": 2, "L0": 1}

# ★ 唯一真源。真源依据：host_shield.py 的 _ALERT_KINDS（6 个）＋ credits 的额度事件。
#   出现未登记的 kind ⇒ level_of() 抛错（不许悄悄按默认值走）。
LEVEL_OF_KIND = {
    # R0 失守：防线本身失效
    "host_shield_tamper": "R0",           # 链/文件被动过
    "host_shield_spawn_failed": "R0",     # 看门狗起不来
    "host_shield_zone_locked": "R0",      # 补锁失败类
    # L2 拦截：已阻断
    "host_shield_breach": "L2",           # 命中并阻断
    # L1 注意：状态变化 / 放行
    "host_shield_revived": "L1",
    "host_shield_changed": "L1",
    # Ls 预算：额度/积分
    "credits_low": "Ls",
    # ★ 归一化类型：项目链里的"规则拦截"（`pre_tool_use` + decision=block）
    #   链上的 type 不叫这个名字，是投影时归一化出来的（见 inbox_store.project_record）。
    #   它不在 host_shield._ALERT_KINDS 里，但同样是"拦截"级事实。
    "tool_call_blocked": "L2",
}

# 人类可读标题（大白话，不许写成内部术语）。
# ★ 消费点：收件箱列表、托盘提示、通知标题 —— 不是"登记了没人查"的字段。
TITLE_OF_KIND = {
    "host_shield_tamper": "失守：防护文件被改动",
    "host_shield_spawn_failed": "失守：看门狗没能启动",
    "host_shield_zone_locked": "失守：安全区加锁失败",
    "host_shield_breach": "已拦截：越界动作被挡下",
    "host_shield_revived": "注意：防护已恢复",
    "host_shield_changed": "注意：防护设置被改动",
    "credits_low": "额度提示：积分余额偏低",
    "tool_call_blocked": "已拦截：危险操作被挡下",
}

# 忽略时必须写备注的级别（最高级："防线失效"不能一句话就抹掉）。
NOTE_REQUIRED_TO_IGNORE = ("R0",)


def level_of(kind):
    """kind -> level（"R0"/"L2"/"L1"/"Ls"）。

    未登记 ⇒ 抛 UnknownKind。**不许返回默认值** —— 静默降级会让新事件消失得
    无声无息（本项目最反对的形状：把"没查"渲染成"没问题"）。
    """
    try:
        return LEVEL_OF_KIND[kind]
    except KeyError:
        raise UnknownKind(
            "未登记的告警类型 %r —— 请先在 inbox_model.LEVEL_OF_KIND 里登记它；"
            "否则该事件会被静默降级。" % (kind,)
        ) from None


def alert_id(ts, kind, reason):
    """稳定 ID：sha1(ts|kind|reason)[:8]。

    同一事件重放得到同一 ID ⇒ 追加是**幂等**的（重放不会造出重复条目）。
    """
    raw = "%s|%s|%s" % (ts, kind, reason)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]


def can_transition(src, dst):
    """src -> dst 是否合法。未知状态名一律抛 BadState。"""
    for s in (src, dst):
        if s not in STATES:
            raise BadState("未知状态 %r（合法：%s）" % (s, ", ".join(STATES)))
    if src == dst:
        return True                                   # 幂等
    return dst in _TRANSITIONS.get(src, set())


def check_ignore_note(level, note):
    """忽略某级别时是否必须写备注。不满足 ⇒ 抛 NoteRequired。"""
    if level in NOTE_REQUIRED_TO_IGNORE and not (note or "").strip():
        raise NoteRequired(
            "忽略 %s 级事件必须写一句备注（说明为什么判断无需动作）。" % level
        )


# --------------------------------------------------------------- 数据结构 ----
@dataclass
class Alert:
    """一条告警**事实**（追加写、不可变）。字段来源见详细设计 §2.1。"""

    id: str
    ts: str
    level: str
    kind: str
    title: str = ""
    detail: str = ""
    rule_id: str = ""
    snippet: str = ""
    severity: str = ""
    chain_ref: str = ""

    def to_dict(self):
        return asdict(self)

    @classmethod
    def build(cls, ts, kind, title="", detail="", rule_id="", snippet="",
              severity="", chain_ref="", reason=None):
        """由原始事件造一条 Alert。level 一律经 level_of() 得到（唯一真源）。"""
        lvl = level_of(kind)
        return cls(
            id=alert_id(ts, kind, reason if reason is not None else (rule_id or detail)),
            ts=ts, level=lvl, kind=kind, title=title, detail=detail,
            rule_id=rule_id, snippet=snippet, severity=severity, chain_ref=chain_ref,
        )


@dataclass
class Item:
    """Alert ＋ 一份**可变**状态（收件箱状态独立于链，见详细设计 §2.7）。"""

    alert: Alert
    state: str = "unread"
    read_at: str = ""
    closed_at: str = ""
    note: str = ""
    actor: str = "owner"

    # --- 便捷透传（页面/托盘只认这几个） ---
    @property
    def id(self):
        return self.alert.id

    @property
    def level(self):
        return self.alert.level

    @property
    def kind(self):
        return self.alert.kind

    @property
    def ts(self):
        return self.alert.ts

    # 显示字段也要透传 —— 收件箱列表/详情/托盘提示都要用（消费点见 UI 层）
    @property
    def title(self):
        return self.alert.title

    @property
    def detail(self):
        return self.alert.detail

    @property
    def rule_id(self):
        return self.alert.rule_id

    @property
    def snippet(self):
        return self.alert.snippet

    @property
    def severity(self):
        return self.alert.severity

    @property
    def chain_ref(self):
        return self.alert.chain_ref

    @property
    def is_open(self):
        return self.state in OPEN_STATES

    def to_dict(self):
        d = self.alert.to_dict()
        d.update(state=self.state, read_at=self.read_at, closed_at=self.closed_at,
                 note=self.note, actor=self.actor)
        return d


# --------------------------------------------------------------- 聚合算法 ----
def console_state(items):
    """取所有**未处理**（未读+已读）项里的最高级别；无 ⇒ L0。

    ★ 这是"LOGO 五态"的**唯一算法**：页面、托盘、通知、favicon 全调它。
    """
    live = [it.level for it in items if it.state in OPEN_STATES]
    if not live:
        return "L0"
    return max(live, key=lambda l: PRIORITY[l])


def unhandled_count(items):
    """未处理数 = 未读 + 已读。★ 与 console_state() 同一口径。"""
    return sum(1 for it in items if it.state in OPEN_STATES)


def counts_by_state(items):
    """每个状态各有几条（页面筛选条用）。"""
    d = {s: 0 for s in STATES}
    for it in items:
        d[it.state] = d.get(it.state, 0) + 1
    return d


def counts_by_level(items, only_open=True):
    """每个级别各有几条（日报排行用）。"""
    d = {}
    for it in items:
        if only_open and it.state not in OPEN_STATES:
            continue
        d[it.level] = d.get(it.level, 0) + 1
    return d
