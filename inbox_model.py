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

    为什么：0.35.3 起"已读"是**点开就自动发生**的（`inbox_server._READ_JS`），
    不再有"标为已读"按钮。若"已读"能减少未处理数，那么**点开看一眼**就等于
    把事藏起来了 —— 一个假守卫。安全产品里，"我看过了"绝不等于"没事了"。
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime

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
    # R0 失守：防线本身失效（事件没有被防护措施挡住）
    "host_shield_tamper": "R0",           # 链/文件被动过
    "host_shield_spawn_failed": "R0",     # 看门狗起不来
    "host_shield_zone_locked": "R0",      # 补锁失败类
    "host_shield_breach": "R0",           # 门闸有缺口：不是「已拦截」，而是有东西没被挡住
    # L2 拦截：实际被阻止的危险操作
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
    # ★ 0.35.3 修（创始人 2026-10-06「要处理 37 条」复盘时发现）：
    #   旧标题是「**已拦截**：越界动作被挡下」—— 但 `host_shield_breach` 描述的
    #   根本不是"拦住了"，而是"**有东西没被挡住**"（自启缺失 / 落点没人巡检 /
    #   钩子被拔）。把"缺口"说成"已拦截"，是**方向反了**的标签 ——
    #   创始人最恨的形状（用户照着标签做判断，会得出相反结论）。
    "host_shield_breach": "失守：门闸有缺口（有东西没被挡住）",
    "host_shield_revived": "注意：防护已恢复",
    "host_shield_changed": "注意：防护设置被改动",
    "credits_low": "额度提示：积分余额偏低",
    "tool_call_blocked": "已拦截：危险操作被挡下",
}

#: ★ 0.35.3：按**事由**（链记录 `subkind`）给更准的标题；没有则回落到 `TITLE_OF_KIND`。
#:   为什么要它：同一个 kind 下的事由差别很大 ——
#:   「开机不会自动防护」和「有落点没人巡检」都是 `host_shield_breach`，
#:   但用户该做的事完全不同（前者装自启，后者做裁决）。
TITLE_OF_TOPIC = {
    "autostart_missing": "失守：开机不会自动防护（要你装一次自启）",
    "spawn_failed": "失守：看门狗没能启动",
    "self_check": "失守：防护文件被改动（要你核对/重装）",
}

# 忽略时必须写备注的级别（最高级："防线失效"不能一句话就抹掉）。
NOTE_REQUIRED_TO_IGNORE = ("R0",)

# ------------------------------------------------- 有没有后果（结构化）----
# ★★ 0.35.3（创始人 2026-10-06 拍板"不会再带来后果的，归档即可"）：
#   "有没有后果"必须是**结构化判定**，不许读 `reason` 文案（文案会改，
#   按文案判档的判据会**静默失效** —— 本仓第 4 次同一形状）。
#   · 链记录带 `recovered=True` ⇒ 防线自己扛住了、没留后果（见 AUDIT_SCHEMA v1.10）
#   · 下面这几种 kind 本身就是"纯状态变更/正常态留痕"，不构成后果
#   · **其余一律按"有后果"处理** —— 字段缺失＝"不知道"，方向收紧，
#     绝不把"不知道"读成"没事"。
NO_CONSEQUENCE_KINDS = frozenset({
    "host_shield_changed",      # 防护设置被改动（改了设置，没放跑什么）
    "host_shield_revived",      # 防护已恢复（自愈记录）
})

# 三档（页面/日报共用，唯一实现）
BUCKET_ACTION = "action"        # 要你处理的（有后果 + 未处理）
BUCKET_INFO = "info"            # 看一眼的（24 小时内、无后果）
BUCKET_ARCHIVE = "archive"      # 归档（更早的无后果记录 / 已有处置动作）

#: 顶部窗口默认 24 小时（创始人 2026-10-06 拍板："窗口太长了，默认不要这么长"）
WINDOW_HOURS = 24

# ---------------------------------------------------- 要不要你动手 ----
# ★★★ 0.35.3（创始人 2026-10-06「**尽可能少让人处理**，核心原则就是用户体验，
#   尽可能让用户少操心、少动作，同时效果还好」）：
#
#   「要处理」= **只有你本人动手才能解决**的事。Antinel 自己已经处理掉的
#   （拦下、自愈、只是状态变更）一律**不进**「要处理」—— 你知情即可。
#
#   ★ 为什么用**黑名单**（"Antinel 自己处理掉的"）而不是白名单：
#     白名单意味着"没登记的新类型 = 不用你管" ⇒ 新缺陷会被**静默降级**成
#     "看一眼"。黑名单则相反：**没登记 = 要你处理**（fail-loud，方向收紧）。
#     这与本仓「不知道 ≠ 没事」是同一条纪律。
#
#   ★ 结构化判定（kind），**不读 `reason` 文案** —— 文案会改，按文案判档的
#     判据会静默失效（本仓第 4 次同一形状）。
AUTO_HANDLED_KINDS = frozenset({
    "tool_call_blocked",        # 已拦截：危险操作被挡下 —— Antinel 已经干完了
    "host_shield_revived",      # 防护已恢复（自愈记录）
    "host_shield_changed",      # 防护设置被改动（改了设置，没放跑什么）
    "host_shield_zone_locked",  # ★ 见下方注释：成功=自动处理／失败=要你决策
    "host_shield_lock_held",    # 门闸持锁中（周期性状态留痕）
})

# ★★★ 0.36.0 真缺陷修复（创始人 2026-10-07「不能无法改进，只能看」）：
#   `host_shield_zone_locked` 这一个 kind **同时表示"上锁成功"和"上锁失败"**，
#   而黑名单只能按 kind 判 ⇒ 于是**上锁失败**（有进程在对抗门闸，
#   **Antinel 赢不了、必须你决策**）被降级进了「看一眼」。
#   实测本机：12 条 `zone_locked` 失守全部落在「看一眼」档，
#   用户的「要处理」里一条都没有 —— 唯一真正需要人决策的那类反而看不见。
#
#   ⇒ 拆成**按记录判**：同一个 kind，成功与失败走不同档。
#     上锁失败 ⇒ 进「要处理」（`remediation.py` 里它是唯一的 B 类，
#       会给出"三选一"：修复／移出监管／接受风险）。
#   ★ 判据仍**不用文案**：`remediation._kind_of()` 先按 `(kind, topic)`，
#     再用 detail 的**固定前缀**兜底（历史记录没有 topic，实测 12 条）。
#     这里复用那一份判定，不另立第二套。
AUTO_HANDLED_TOPICS = frozenset({
    # zone_locked 的 topic 登记见 host_shield 写入侧；空 topic 的历史记录
    # 由 `needs_owner` 交给 `_zone_lock_failed()` 按 detail 固定前缀判。
})


def _zone_lock_failed(item):
    """这条 `zone_locked` 是**上锁失败**吗（=只有你本人能解决）。

    ★ 复用 `remediation._kind_of()`（**唯一实现**）——
      这里**不**重新写一遍"怎么算失败"，否则又是一套会漂移的口径。
    """
    try:
        import remediation as RM
        return RM._kind_of(item) == "zone_locked"
    except Exception:                                           # noqa: BLE001
        # ★ 判不了 ⇒按「要你处理」算（fail-loud）。
        #   把判不出来的降级成"不用你管"，正是本仓最恨的形状。
        return True


def needs_owner(item):
    """这件事**是不是只有你本人动手才能解决**（★ 唯一实现）。

    · False ⇒ Antinel 已经处理掉了 ⇒ 进「看一眼」，不占你的待办。
    · True  ⇒ 进「要处理」（例：门闸缺岗、自检不符、拉不起来、待裁决落点）。

    ★ 默认（没登记过的 kind）＝ True：**宁可多报，不许静默降级**。

    ★ 0.36.0：`host_shield_zone_locked` 从「按 kind 一刀切」改为**按记录判** ——
      上锁成功＝Antinel 干完了（不看一眼）；
      **上锁失败＝只有你本人能解决**（进「要处理」）。
      理由与实测见 `AUTO_HANDLED_KINDS` 上方那段注释。
    """
    if item.kind == "host_shield_zone_locked":
        #★ 不在黑名单里时走默认 True；在黑名单里则按记录判成败。
        return _zone_lock_failed(item)
    return item.kind not in AUTO_HANDLED_KINDS


def group_key(item):
    """同一件「事由」的归并键（★ 唯一实现）。

    ★★ 为什么要归并（创始人 2026-10-06「要处理 37 条，很多不该列进来」）：
      同一条事实反复发生会占满待办 —— 实测本机 24 小时窗口内
      「登录自启缺失」14 条、「拉起失败」13 条、「自检不符」4 条，
      **其实是 3 件事**。用户看到的是 31 条，于是 31 条一起被忽略。
      ⇒ 归并后显示「3 件事（各自发生了 N 次）」。
    ★ 键是**结构化**的（kind + 子类 + 级别），**不读文案**。
      子类 `topic` 由写入方在链记录里带 `subkind` 给出（见 AUDIT_SCHEMA）。
    """
    return (item.kind, getattr(item, "topic", "") or "", item.level)


def has_consequence(item):
    """这条记录**有没有带来后果**（见上面 NO_CONSEQUENCE_KINDS 的说明）。"""
    if getattr(item, "recovered", False):
        return False
    return item.kind not in NO_CONSEQUENCE_KINDS


def _parse_ts(ts):
    """ISO ts → datetime；解析不了 ⇒ None（**不猜**）。"""
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(str(ts))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo is not None else d.astimezone()


def within_hours(ts, hours=WINDOW_HOURS, now=None):
    """这条记录在不在窗口内。ts 解析不了 ⇒ False（**不把"不知道"读成"在窗口内"**，
    否则一条坏时间戳会把旧记录永久顶在首屏）。"""
    d = _parse_ts(ts)
    if d is None:
        return False
    now = now or datetime.now().astimezone()
    age = (now - d).total_seconds()
    return 0 <= age <= hours * 3600


def bucket_of(item, now=None, hours=WINDOW_HOURS):
    """一条记录进哪一档（★ 唯一实现，页面与日报都调它）。

    ★★ 0.35.3 新口径（创始人 2026-10-06「**尽可能少让人处理**」）：
      · `action` 要处理 —— 窗口内、有后果、**而且只有你本人动手才能解决**
        （`needs_owner`）。这才是真正的待办。
      · `info`   看一眼 —— 窗口内、但 **Antinel 自己已经处理掉了**
        （拦下 / 自愈 / 只是状态变更）⇒ 你**知情即可，不用动手**。
      · `archive` 归档  —— 其余（窗口外的、或已有处置动作的）。
    ★ 为什么 action 也要带窗口：本机实测不带窗口时有 100 条"要处理"，
      其中绝大多数是 7 天前已经过期的拦截 —— 那就又回到"次要信息霸屏"。
      ★ 窗口外的有后果记录**不丢**，进"归档"，随时可翻。
    ★ 页面按 `group_key()` **按事由归并**显示（14 条同因记录 = 1 件事）。
    """
    if not within_hours(item.ts, hours, now):
        return BUCKET_ARCHIVE
    if item.state in CLOSED_STATES:
        return BUCKET_ARCHIVE
    if not has_consequence(item):
        return BUCKET_INFO
    if not needs_owner(item):
        return BUCKET_INFO
    return BUCKET_ACTION


def counts_by_bucket(items, now=None, hours=WINDOW_HOURS):
    """三档各几条。"""
    d = {BUCKET_ACTION: 0, BUCKET_INFO: 0, BUCKET_ARCHIVE: 0}
    for it in items:
        d[bucket_of(it, now=now, hours=hours)] += 1
    return d


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
    #: ★ 0.35.3：链记录的结构化字段 `recovered`（见 docs/AUDIT_SCHEMA.md v1.10）。
    #:   True ＝ 这件事已经自动愈合、没留后果。**不许靠解析 reason 文案得到它。**
    recovered: bool = False
    #: ★ 0.35.3：**同一件「事由」的稳定标识**（来自链记录 `subkind`，见 AUDIT_SCHEMA）。
    #:   用途：把"同一条事实反复发生"归并成一件事（创始人 2026-10-06「37 条太多」）。
    #:   例：登录自启缺失 → `autostart_missing`；自检不符 → `self_check`。
    #:   缺省 `""` ＝ 该类型没细分（同 kind 同级别归为一件事）。
    topic: str = ""

    def to_dict(self):
        return asdict(self)

    @classmethod
    def build(cls, ts, kind, title="", detail="", rule_id="", snippet="",
              severity="", chain_ref="", reason=None, recovered=False, topic=""):
        """由原始事件造一条 Alert。level 一律经 level_of() 得到（唯一真源）。"""
        lvl = level_of(kind)
        return cls(
            id=alert_id(ts, kind, reason if reason is not None else (rule_id or detail)),
            ts=ts, level=lvl, kind=kind, title=title, detail=detail,
            rule_id=rule_id, snippet=snippet, severity=severity, chain_ref=chain_ref,
            recovered=bool(recovered), topic=str(topic or ""),
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
    def recovered(self):
        return self.alert.recovered

    @property
    def topic(self):
        return self.alert.topic

    @property
    def is_open(self):
        return self.state in OPEN_STATES

    def to_dict(self):
        d = self.alert.to_dict()
        d.update(state=self.state, read_at=self.read_at, closed_at=self.closed_at,
                 note=self.note, actor=self.actor)
        return d


# --------------------------------------------------------------- 聚合算法 ----
def console_state(items, hours=WINDOW_HOURS, now=None):
    """取窗口内**确实需要用户本人动手**的事项最高级别；无 ⇒ L0。

    ★★ 0.35.3：灯必须与「要处理」定义同口径，不能因为 Antinel 已拦下的命令
      或自己恢复的状态就报「值守中·有事」。统一委托 `bucket_of()`；它包含
      时间窗口、有后果、当前未处理、且只有用户本人能解决这四项判定。
      ★ "当前是否失守"不由本函数决定 —— 那由 `host_shield.guard_posture()` 现探。
    """
    live = [it.level for it in items
            if bucket_of(it, now=now, hours=hours) == BUCKET_ACTION]
    if not live:
        return "L0"
    return max(live, key=lambda l: PRIORITY[l])


def unhandled_count(items, hours=None, now=None):
    """未处理数 = 未读 + 已读。

    `hours=None` ⇒ 全部历史（旧口径，托盘/favicon 用）；
    传了 `hours` ⇒ 只数窗口内、且**有后果**的（与 `console_state()` 同一口径）。
    """
    if hours is None:
        return sum(1 for it in items if it.state in OPEN_STATES)
    return sum(1 for it in items
               if it.state in OPEN_STATES and has_consequence(it)
               and within_hours(it.ts, hours, now))


def counts_by_state(items):
    """每个状态各有几条（页面筛选条用）。"""
    d = {s: 0 for s in STATES}
    for it in items:
        d[it.state] = d.get(it.state, 0) + 1
    return d




def window_levels(items, hours=WINDOW_HOURS, now=None):
    """窗口内每个级别各几条（顶部条那排数字 / 日报的"最近 24 小时"共用）。

    ★ 唯一实现：顶部条与日报**必须**是同一个数（否则页面上两个数字会打架）。
    """
    d = {"R0": 0, "L2": 0, "L1": 0, "Ls": 0}
    for it in items:
        if it.level in d and within_hours(it.ts, hours, now):
            d[it.level] += 1
    return d



def counts_by_level(items, only_open=True):
    """每个级别各有几条（日报排行用）。"""
    d = {}
    for it in items:
        if only_open and it.state not in OPEN_STATES:
            continue
        d[it.level] = d.get(it.level, 0) + 1
    return d


# ------------------------------------------------------------- 筛选（唯一实现）----
# ★ 页面上的筛选条与日报里每个数字的**钻取链接**共用这一套取值。
#   取值文法：
#     action / info / archive / all      —— 三档 + 全部
#     lv:R0 / lv:L2 / lv:L1 / lv:Ls      —— 按级别
#     kind:<kind>                        —— 按类型
#     rule:<rule_id>                     —— 按规则
FILTER_LABEL = {
    BUCKET_ACTION: "要处理", BUCKET_INFO: "看一眼", BUCKET_ARCHIVE: "归档",
    "all": "已载入记录",
}


def filter_label(filt, hours=WINDOW_HOURS):
    """筛选条的**人话**标签（页面与钻取页共用）。"""
    if filt in FILTER_LABEL:
        return FILTER_LABEL[filt]
    if filt.startswith("lv:"):
        lv = filt[3:]
        return {"R0": "失守", "L2": "拦截", "L1": "注意", "Ls": "额度"}.get(lv, lv)
    if filt.startswith("kind:"):
        return TITLE_OF_KIND.get(filt[5:], filt[5:])
    if filt.startswith("rule:"):
        return "规则 " + filt[5:]
    if filt.startswith("win:"):
        try:
            _p, h, inner = filt.split(":", 2)
            return "最近 %s 小时 · %s" % (h, filter_label(inner, hours=hours))
        except ValueError:
            return filt
    if filt.startswith("day:"):
        try:
            _p, d, inner = filt.split(":", 2)
            return "%s · %s" % (d, filter_label(inner, hours=hours))
        except ValueError:
            return filt
    return filt


def filter_items(items, filt, now=None, hours=WINDOW_HOURS):
    """按筛选条取值过滤（★ 唯一实现 —— 页面与日报钻取都调它，不许各写一遍）。"""
    if not filt or filt == "all":
        return list(items)
    if filt in (BUCKET_ACTION, BUCKET_INFO, BUCKET_ARCHIVE):
        return [it for it in items if bucket_of(it, now=now, hours=hours) == filt]
    if filt.startswith("win:"):
        try:
            _p, raw_hours, inner = filt.split(":", 2)
            window = int(raw_hours)
        except (ValueError, TypeError):
            return []
        return filter_items([it for it in items if within_hours(it.ts, window, now)],
                            inner, now=now, hours=window)
    if filt.startswith("day:"):
        try:
            _p, want_day, inner = filt.split(":", 2)
            datetime.strptime(want_day, "%Y-%m-%d")
        except (ValueError, TypeError):
            return []
        return filter_items([it for it in items if str(it.ts)[:10] == want_day],
                            inner, now=now, hours=hours)
    if filt.startswith("lv:"):
        return [it for it in items if it.level == filt[3:]]
    if filt.startswith("kind:"):
        return [it for it in items if it.kind == filt[5:]]
    if filt.startswith("rule:"):
        return [it for it in items if it.rule_id == filt[5:]]
    return [it for it in items if bucket_of(it, now=now, hours=hours) == filt]




def group_by_kind(items):
    """按类型分组（"看一眼/归档"用它 —— 次要信息不许一张一条霸屏）。

    返回 `[{kind, title, level, count, first_ts, last_ts, ids}]`，按
    (级别优先级 desc, 最近时间 desc) 排。

    ★ 为什么必须分组：本机实测 24 小时内 39 条"看一眼"里，31 条是同一种
      `host_shield_revived`（哨兵被反复拉起）。一张一条会把首屏占满，
      而它们其实是**同一件事** —— 分组后一行说清，点开才看单条。
    """
    g = {}
    for it in items:
        d = g.get(it.kind)
        if d is None:
            g[it.kind] = {"kind": it.kind, "title": it.title, "level": it.level,
                          "count": 1, "first_ts": it.ts, "last_ts": it.ts,
                          "ids": [it.id]}
        else:
            d["count"] += 1
            if it.ts > d["last_ts"]:
                d["last_ts"] = it.ts
            if it.ts < d["first_ts"]:
                d["first_ts"] = it.ts
            d["ids"].append(it.id)
    rows = list(g.values())
    # ★ 两级排序：先按时间倒序，再**稳定**按级别倒序 ⇒ 主键＝级别、次键＝时间。
    rows.sort(key=lambda r: r["last_ts"], reverse=True)
    rows.sort(key=lambda r: PRIORITY.get(r["level"], 0), reverse=True)
    return rows



def group_items(items):
    """按「事由」归并（★ 唯一实现）。返回 `[{key, kind, topic, title, level, count,
    first_ts, last_ts, ids}]`，按 (级别优先级 desc, 最近时间 desc) 排。

    ★ 与 `group_by_kind` 的区别：那个只按 kind（"看一眼"够用）；
      这个把 **kind + 子类 + 级别** 一起当键 —— 「要处理」是待办，
      同一 kind 下不同事由（例：自启缺失 vs 钩子被拔）**必须分开**，
      否则点进去看到的清单跟标题对不上。
    """
    g = {}
    for it in items:
        k = group_key(it)
        d = g.get(k)
        if d is None:
            g[k] = {"key": k, "kind": it.kind, "topic": it.topic, "title": it.title,
                    "level": it.level, "detail": it.detail, "rule_id": it.rule_id,
                    "count": 1, "first_ts": it.ts, "last_ts": it.ts, "ids": [it.id],
                    # ★ 0.36.0：留一条**真实 Item**，供页面渲染归因面板
                    #（`remediation.attribute()` 要读 kind/topic/detail，不是纯字段）。
                    # 只在**首次出现**时记，且后续不更新 —— 因为归并键就是按事由分的，
                    # 组内根因相同，取哪一条都一样；要"最近那条"请看 `detail`（已按ts 更新）。
                    "first_item": it}
        else:
            d["count"] += 1
            if it.ts > d["last_ts"]:
                d["last_ts"] = it.ts
                d["detail"] = it.detail          # 用最近一条的说明
            if it.ts < d["first_ts"]:
                d["first_ts"] = it.ts
            d["ids"].append(it.id)
    rows = list(g.values())
    rows.sort(key=lambda r: r["last_ts"], reverse=True)
    rows.sort(key=lambda r: PRIORITY.get(r["level"], 0), reverse=True)
    return rows


def count_groups(items):
    """按事由归并后的**件事数** —— 页面/托盘上显示的待办数就是这个。"""
    return len({group_key(it) for it in items})


def known_filter(filt):
    """筛选条取值是不是合法的（页面收到非法值 ⇒ 退回默认，不静默当成"全部"）。"""
    if filt in ("action", "info", "archive", "all"):
        return True
    for p in ("lv:", "kind:", "rule:"):
        if filt.startswith(p) and len(filt) > len(p):
            return True
    if filt.startswith("win:") or filt.startswith("day:"):
        try:
            prefix, scope, inner = filt.split(":", 2)
            if prefix == "win":
                if int(scope) <= 0:
                    return False
            elif prefix == "day":
                datetime.strptime(scope, "%Y-%m-%d")
            else:
                return False
            return known_filter(inner)
        except (ValueError, TypeError):
            return False
    return False


# --------------------------------------------------------------- 顶部灯（唯一实现）----
# ★★ 创始人 2026-10-06 拍板：「是否失守，应该是**当前的状态**；
#   如果当前确实是失守状态，应该有地方可以马上解决问题」。
#   ⇒ 灯色由**现探**的态势决定（`host_shield.guard_posture()`），
#     历史账只用来把"值守中"细分成"值守中 / 值守中但有未处理的事"。
LIGHT_DOWN = "down"             # 红：当前确实失守（缺岗 **且**有可指认的后果）
LIGHT_INTERRUPTED = "interrupted"  # 黄：缺岗，但此刻没有监管对象 ⇒ 无损失（★ 0.35.3）
LIGHT_WARN = "warn"             # 黄：在守，但守门的那份代码认不出（可信性存疑，★ 0.35.3）
LIGHT_DEV = "dev"               # 蓝：研发迭代中，这一版还没发出去（★ 0.36.3，非故障）
LIGHT_ATTENTION = "attention"   # 橙：值守中，但 24 小时内有未处理的有后果项
LIGHT_OK = "ok"                 # 绿：值守中，24 小时内干净
LIGHT_OFF = "off"               # 灰：未启用（默认态，不是故障）
LIGHT_UNKNOWN = "unknown"       # 黄：查不到（盲区，≠ 没问题）

#: ★★ 合法**姿态**的封闭集合（0.36.3）—— 真源在 `host_shield.POSTURE_ALL`，
#:   这里**转发**而不是手抄一份。
#:
#: ★★ 为什么必须转发而不是各写一份（**这一版我先抄错了，实测当场抓出来**）：
#:   我第一版把 `LIGHT_OK`（"值守中"这个**灯**）写进了这个集合 ⇒ 集合里
#:   **没有 `guarding`**（那是**姿态**）⇒ `light("guarding")` 被兜底拦成黄灯
#:   「查不到」，正常状态被误判。实测才发现。
#:   ⇒ 抄第二份的代价不是"多写一行"，而是**两份清单必然漂移**：
#:     一边加了状态、另一边没加 ⇒ 正常态被判成盲区（或更糟：异常态被判成绿）。
#:   ⇒ 现在：**姿态集合只有一处定义**（`host_shield.POSTURE_ALL`），
#:     本模块只 import。这样新增姿态时**只有一处要改**，漂移无从发生。
try:
    from host_shield import POSTURE_ALL as _POSTURE_ALL
except Exception:                                        # noqa: BLE001
    # 取不到就退回本地最小集 —— **宁可漏判成盲区，也绝不把未知当正常**。
    _POSTURE_ALL = frozenset(("down", "interrupted", "warn", "dev",
                              "unknown", "off", "guarding"))

LIGHT_LABEL = {LIGHT_DOWN: "失守", LIGHT_INTERRUPTED: "中断·无损失",
               LIGHT_WARN: "存疑", LIGHT_DEV: "研发中",
               LIGHT_ATTENTION: "值守中·需你处理",
               LIGHT_OK: "值守中", LIGHT_OFF: "未启用", LIGHT_UNKNOWN: "查不到"}

#: 灯 → LOGO 资源名（assets/logo/*.mp4 与 icons/*.ico）
#: ★ 研发态用 L1（黄）而不是新增资源：**不为一种状态多做一套动图**，
#:   且研发态与"存疑"在"这不是红灯"这件事上同族 ⇒ 复用同一资源不引入歧义。
LIGHT_LOGO = {LIGHT_DOWN: "R0", LIGHT_INTERRUPTED: "Ls", LIGHT_WARN: "Ls",
              LIGHT_DEV: "L1",
              LIGHT_ATTENTION: "L2", LIGHT_OK: "L0",
              LIGHT_OFF: "L0", LIGHT_UNKNOWN: "Ls"}
#: 灯 → 强调色 CSS 变量
LIGHT_VAR = {LIGHT_DOWN: "--r0", LIGHT_INTERRUPTED: "--l1", LIGHT_WARN: "--l1",
             LIGHT_DEV: "--l1",
             LIGHT_ATTENTION: "--l2", LIGHT_OK: "--l0",
             LIGHT_OFF: "--muted", LIGHT_UNKNOWN: "--l1"}


def light(posture_state, items, now=None, hours=WINDOW_HOURS):
    """顶部灯的**唯一算法**。返回 `(light, why)`。

    ★ 优先级：当前态势 > 24 小时历史。
      · 当前失守 ⇒ 红（**不管历史多干净** —— 防线此刻真的不在岗，且有损失）
      · 当前中断 ⇒ 黄（缺岗但无监管对象 ⇒ 可证明没损失；**不冒称"失守"**）
      · 当前存疑 ⇒ 黄（在守，但守门的代码认不出 ⇒ 不敢打绿）
      · 当前查不到 ⇒ 黄（盲区）
      · 当前未启用 ⇒ 灰（默认态。**不是故障**，把"没开"渲染成"坏了"是噪音）
      · 当前值守中 ⇒ 看 24 小时内有没有未处理的有后果项：有 ⇒ 橙，无 ⇒ 绿

    ★★ 0.35.3 为什么拆出「中断」和「存疑」（创始人 2026-10-06）：
      「如果现在的『真失守』跟假失守没啥区别，不会带来明显不利后果，
        那就跟假失守没啥区别。」⇒ 红灯必须**说得出损失**。说不出损失的缺岗、
      以及"认不出守门代码"（在守，只是身份存疑），都只配黄灯。
    """
    if posture_state == "down":
        return LIGHT_DOWN, "防线此刻确实不在岗，而且有东西没人管"
    if posture_state == "interrupted":
        return LIGHT_INTERRUPTED, "门闸缺岗，但此刻没有监管对象——可证明没损失"
    if posture_state == "warn":
        return LIGHT_WARN, "哨兵在岗，但守门的这份代码我认不出是不是出厂那份"
    # ★★★ 0.36.4 修（创始人 2026-10-07 第一条要求，本机实测证实）：
    #   「研发中只是状态之一，如哨兵发现状况了，该出现的状态，还是要出现。」
    #
    #   **改之前**这里是一行 `if posture_state == "dev": return LIGHT_DEV, ...`
    #   —— 它在函数最前面**直接 return**，把 24 小时后果账**整段跳过**。
    #   实测（`_p_dev_mask_probe.py`）：
    #     `light("guarding", 三件 R0 急事)` → `attention`（橙，该报警）
    #     `light("dev",      同样三件 R0)` → `dev`      （蓝，**静默**）
    #   ⇒ 哨兵报了 R0，界面只显示"正在研发迭代"。
    #   ⇒ 这是**最坏的形状**：研发态不是"多一个状态"，是**一个能吞掉红灯的状态**。
    #     研发期恰恰是告警最需要被看见的时候（正在改的东西最容易改坏），
    #     而这个状态恰好在那段时间把告警静音了。
    #
    #   **改之后**：dev **不预占灯色**，和 `guarding` 一样往下走后果账 ——
    #   有需要用户亲自处理的事就显示橙（并说明研发态这一层），
    #   没事才显示蓝。**优先级让位给真实状况，身份标注不吞掉后果。**
    #   与 `warn` 的差别：warn 是"认不出"（不确定该不该信）⇒ 黄；
    #   dev 是"确知是迭代产物"（确定只是没发版）⇒ 不加不确定性。
    if posture_state == "dev":
        _action = [it for it in items
                   if bucket_of(it, now=now, hours=hours) == BUCKET_ACTION]
        if not _action:
            return LIGHT_DEV, ("正在研发迭代：这一版还没发出去，代码与登记不一致是"
                               "改出来的（这不改变哨兵仍在正常放哨）")
        _n = count_groups(_action)
        _lv = max((it.level for it in _action), key=lambda x: PRIORITY[x])
        return LIGHT_ATTENTION, (
            "哨兵在岗，%d 小时内有 %d 件事需要你亲自处理（最高 %s）；"
            "同时这一版还在研发迭代中，代码与登记不一致是改出来的。"
            % (hours, _n, _lv))
    if posture_state == "unknown":
        return LIGHT_UNKNOWN, "探不到防线状态——这是盲区，不等于没问题"
    if posture_state == "off":
        return LIGHT_OFF, "护盾默认关闭。开启后才会拦、才会记账。"
    if posture_state == "guarding":
        # ★★★ 0.36.3 新增这一支 —— 它**以前根本不存在**。
        #   `guard_posture()` 在一切正常时返回的**就是 `guarding`**（实测，
        #   `inbox_server.py:404` 直接把 `p["state"]` 喂给 `light()`），
        #   而改造前 `light()` 的 `if` 链里**没有 `guarding` 分支** ⇒
        #   它一路穿到函数末尾，靠"落到 else 段"**意外**拿到 LIGHT_OK。
        #   ⇒ 也就是说：**"值守中"这个最正常的结果，一直是靠一个 bug 支撑的**。
        #     平时看不出来，因为兜底恰好给了它绿灯。
        #   ⇒ 0.36.3 加了"集合外一律黄灯"之后，这个 bug 立刻暴露成
        #     **正常状态被判成"查不到"**（实测复现）。
        #   ⇒ 现在显式写出来：值守中 ⇒ 往下看 24 小时账（下面几行）。
        pass                                 # 正常路径，继续往下算历史账
    # ★★★ 0.36.3（创始人「状态都是计划内的」，实测抓到）：
    #   下面这段是**兜底**，改造前**根本不存在** —— 未知姿态会穿过上面
    #   全部 `if` 落到函数末尾，被当成"值守中"⇒ **打绿**。
    #   实测：`light("banana")` / `light(None)` / `light("")` 全都 → `ok`。
    #   ⇒ 新增状态忘了改这里，界面就**安静地显示一切正常**。
    #   ⇒ 现在：集合外一律黄灯「查不到」，并**说清收到的是什么** ——
    #     「查不到」和「没问题」必须长得不一样（0.28.3 起的老纪律）。
    #
    #   ★★ 判据写成 `isinstance(..., str)` **再**查集合，而不是直接 `not in`：
    #     `not in frozenset` 会对 `list`/`dict` 抛 `TypeError: unhashable type`
    #     （实测踩到）。而抛异常的坏处比返回黄灯更重：**整个灯算不出来**，
    #     页面直接崩给你看 —— 那正是"查不出来"最该避免的表现形式。
    #     ⇒ 不可哈希的输入也走同一条兜底，不许把异常泄给调用方。
    if not isinstance(posture_state, str) or posture_state not in _POSTURE_ALL:
        return LIGHT_UNKNOWN, ("收到一个不认识的防线状态（%r）——这是盲区，"
                               "不等于没问题" % (posture_state,))
    action_items = [it for it in items
                    if bucket_of(it, now=now, hours=hours) == BUCKET_ACTION]
    if not action_items:
        return LIGHT_OK, "哨兵在岗，%d 小时内没有需要你亲自处理的事" % hours
    n = count_groups(action_items)
    lv = max((it.level for it in action_items), key=lambda x: PRIORITY[x])
    return LIGHT_ATTENTION, ("哨兵在岗，%d 小时内有 %d 件事需要你亲自处理（最高 %s）"
                             % (hours, n, lv))
