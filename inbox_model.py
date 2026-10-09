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
# ★★★ 这把尺量的是「**领地离终结有多近**」，不是「事件有多严重」。
#   依据就是品牌动效语法 v1.2 自己的两处原文：
#     · §一.3「绿→浅黄→明黄→橙都是『领地有事、越来越急』；红色是另一回事——哨兵没了」
#     · §三 扫描周期 12 → 8 → 5.5 → 3.5 → **停摆**：这条单调刻度本身就是
#       「离停下还有多远」——越近越快，到站即停。
#   ⇒ 据此排序：L0 值守中 < L1 注意 < L2 拦截 < **Ls 缺粮** < R0 失守。
#   ⚠️ 0.37.3 修正：旧值 `{R0:5, L2:4, L1:3, Ls:2, L0:1}` 把 Ls 压在 L1 之下 ——
#      那是按「安全事件等级」量，与品牌**方向相反**，也与橙色动效
#      「3.5s/圈 · 波撑到最大 · 即使缩成小图标波浪也在喊」自相矛盾：
#      同一份设计用了两把尺。**橙=领地即将停摆，比一次已被拦下的入侵更接近终结。**
#   ⚠️ 新信号上梯先问「它离终结有多近」，**不要**问「它多严重」。
PRIORITY = {"R0": 5, "Ls": 4, "L2": 3, "L1": 2, "L0": 1}

# ★ 唯一真源。真源依据：host_shield.py 的 _ALERT_KINDS（6 个）＋ credits 的额度事件。
#   出现未登记的 kind ⇒ level_of() 抛错（不许悄悄按默认值走）。
LEVEL_OF_KIND = {
    # R0 失守：防线本身失效（事件没有被防护措施挡住）
    "host_shield_tamper": "R0",           # 链/文件被动过
    "host_shield_spawn_failed": "R0",     # 看门狗起不来
    "host_shield_zone_locked": "R0",      # 补锁失败类
    "host_shield_breach": "R0",           # 门闸有缺口：不是「已拦截」，而是有东西没被挡住
    # ★★ 0.40.0：研发态的自检不符 —— **它不是失守**。
    #   研发期"代码与登记表不符"是**范畴事实**（这一版还没发出去），把它当 R0
    #   正是创始人点名的"没有失守却显示失守"。⇒ 归 **L1「注意」**：知情即可。
    #   它**不在** `host_shield._ALERT_KINDS` 里 ⇒ 不弹气泡（研发噪声不该敲门）；
    #   投影由 `inbox_store.project_record` 专门一支负责。
    "host_shield_dev_drift": "L1",
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
    # ★ 0.37.1：标题里的「看门狗」改成「哨兵」—— 词表、托盘图标、归因文案
    #   都叫它「哨兵」，只有这两个标题还在说「看门狗」。
    #   后果不是"不好听"：同一条失守的**标题**写「看门狗没能启动」、
    #   紧挨着的**原因**却写「哨兵启动自检不符」⇒ 用户读到两个名字指同一个东西，
    #   只好停下判断它俩是不是一回事（创始人说的"违和感"）。
    "host_shield_spawn_failed": "失守：哨兵没能启动",
    "host_shield_zone_locked": "失守：安全区加锁失败",
    # ★ 0.35.3 修（创始人 2026-10-06「要处理 37 条」复盘时发现）：
    #   旧标题是「**已拦截**：越界动作被挡下」—— 但 `host_shield_breach` 描述的
    #   根本不是"拦住了"，而是"**有东西没被挡住**"（自启缺失 / 落点没人巡检 /
    #   钩子被拔）。把"缺口"说成"已拦截"，是**方向反了**的标签 ——
    #   创始人最恨的形状（用户照着标签做判断，会得出相反结论）。
    "host_shield_breach": "失守：防护有缺口（有东西没被挡住）",
    "host_shield_revived": "注意：防护已恢复",
    "host_shield_changed": "注意：防护设置被改动",
    "host_shield_dev_drift": "注意：研发迭代中（代码与登记表不符）",
    "credits_low": "缺粮：积分余额偏低",
    "tool_call_blocked": "拦截：危险操作被挡下",
}

#: ★ 0.35.3：按**事由**（链记录 `subkind`）给更准的标题；没有则回落到 `TITLE_OF_KIND`。
#:   为什么要它：同一个 kind 下的事由差别很大 ——
#:   「开机不会自动防护」和「有落点没人巡检」都是 `host_shield_breach`，
#:   但用户该做的事完全不同（前者装自启，后者做裁决）。
TITLE_OF_TOPIC = {
    "autostart_missing": "失守：开机不会自动防护（要你装一次自启）",
    "spawn_failed": "失守：哨兵没能启动",
    # ★★ 0.40.0（A5）：按**病因**分，不再按"哪个字段"分 ——
    #   `self_check` / `registry` 都是「代码/登记表与 manifest 不符」⇒ **一件事**（code_drift）；
    #   `enabled` / `state` 都是「安全状态字段在运行期漂移、哨兵已回写恢复」⇒ **另一件事**（state_drift）。
    #   改前：前者被拆成两行、后者三因挤一行（归并键 `(kind, topic, level)`，后三者 topic 为空）。
    #   ★ 旧 `self_check` 词条**保留**：链 append-only，历史记录（实测 47 条）仍是那个 subkind。
    "code_drift": "失守：防护文件被改动（代码与登记表不符）",
    "state_drift": "失守：防护文件被改动（状态被改，已自动恢复）",
    "self_check": "失守：防护文件被改动（要你核对/重装）",
    # ★★ 0.40.0（A8）：`zone_locked` 兼表成败 —— **成功**那条不能借用 kind 标题
    #   （kind 标题写着"失守：安全区加锁失败"），否则一条成功被读成失守。
    "zone_ok": "注意：安全区已上锁（区内防篡改）",
    "zone_lock_failed": "失守：安全区加锁失败",
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
    "tool_call_blocked",        # 拦截：危险操作被挡下 —— Antinel 已经干完了
    "host_shield_revived",      # 防护已恢复（自愈记录）
    "host_shield_changed",      # 防护设置被改动（改了设置，没放跑什么）
    "host_shield_zone_locked",  # ★ 见下方注释：成功=自动处理／失败=要你决策
    "host_shield_lock_held",    # 门闸持锁中（周期性状态留痕）
    # ★★ 0.40.0：研发迭代中的"代码与登记表不符"—— 哨兵照常在岗、发版即消失
    #   （收敛靠事实追平，不靠时间）⇒ **你知情即可，不进"要处理"**。
    #   它与"出厂包被改"（`host_shield_tamper`，仍是 R0）是**两种事件**，不是同一件的两档。
    "host_shield_dev_drift",
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
    # ★★ 0.40.0：`zone_locked` 兼表成败 ⇒ 后果也要**按记录**判（与 `needs_owner` 同源）。
    #   上锁成功＝Antinel 干完了（没有后果）；上锁失败＝有后果。
    if item.kind == "host_shield_zone_locked":
        return _zone_lock_failed(item)
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


def window_level_groups(items, hours=WINDOW_HOURS, now=None):
    """窗口内每个级别各几**件事**（按事由归并后）—— 顶部条那排数字用。

    ★ 唯一实现（0.37.1 新增）：顶部条原来**手抄**了一遍分组逻辑
      （`_win` + `_grp`），与 `window_levels` 声明「唯一实现」自相矛盾 ——
      两边一旦漂移，顶部条与日报的 24h 数字就会打架，而**没有任何判据
      看得见**（因为判据也只验证了其中一个口径）。现在成对提供：
      记录数走 `window_levels`，件事数走这里，同一个 `within_hours` 口径。
    """
    keys = {"R0": set(), "L2": set(), "L1": set(), "Ls": set()}
    for it in items:
        if it.level in keys and within_hours(it.ts, hours, now):
            keys[it.level].add(group_key(it))
    return {k: len(v) for k, v in keys.items()}



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
        return state_short(lv)
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
# ★★★ 2026-10-08 换代（创始人拍板）：灯态从「8 个派生灯态」收回
#   **LOGO 五态 + 开发态** 六态封闭集合。
#
#   ★ 历史（为什么换）：0.36.0–0.36.4 期间，灯态由「姿态 × 24h 历史」两轴
#     派生出了 8 个灯（失守/中断/存疑/研发中/值守中·需你处理/值守中/未启用/
#     查不到）—— 这是 AI 自己长出来的派生层，不是产品词汇。创始人定性：
#     「那 8 态是之前的 AI 主观臆想的，要去掉」。
#   ★ 产品词汇在品牌侧早有定义（`Antinel品牌动效报警语法v1.2` §三
#     五态定义总表；`assets/logo/*.mp4`、`assets/icons/*.ico` 全部按它备料）：
#       L0 值守  allow 放行          光束绿
#       L1 注意  alert 提示          警戒浅黄
#       L2 拦截  block 拦截          警戒明黄
#       Ls 预算  credits 阈值告警    警戒橙
#       R0 失守  fail-open/断链/逃逸 讣告红（停摆）
#     ＋ 开发态（0.36.3 落地）：研发迭代专用。**复用 L1 动图资源**，不新增资产。
#
#   ★ 「存疑」态取消（创始人 2026-10-07 原话：「值守台出现计划外状态『存疑』，
#     不允许」）：出厂代码与登记不符（且不是研发态）⇒ **fail-closed 按 R0 失守**，
#     文案说清是「守门代码认不出」—— 不 waffle、也不谎报损失。
STATE_R0 = "R0"          # 红·讣告：防线没生效（缺岗有损失／fail-open／断链／出厂码不符）
STATE_L2 = "L2"          # 明黄：有操作被拦下（未处理）
STATE_L1 = "L1"          # 浅黄：知情即可的提示（含缺岗无损失、探不到＝盲区）
STATE_Ls = "Ls"          # 橙：额度/预算阈值告警
STATE_L0 = "L0"          # 绿：值守中（一切正常）；灰变体＝未启用（默认全关，不是故障）
STATE_DEV = "dev"        # 蓝：研发迭代中（在守，代码比登记的新）

#: ★★ 合法**灯态**的封闭集合（六态）。集合外一律 L1 盲区，**绝不打绿**。
#: ★ 命名警告：**不能叫 `STATES`** —— 那个名字自本模块建立起就是
#:   「条目状态」（unread/read/done/ignored，`inbox_store` 的状态机在用）。
#:   0.37.1 我第一版就把六态集合命名成 `STATES`，**把它覆盖了** ⇒
#:   实测 `can_transition("unread","done")` 抛「未知状态 unread」
#:   ⇒ 页面上所有「知道了/忽略」按钮静默失效（0353 P12 当场抓到）。
#:   ⇒ 教训与 JDG-05 同型：**新增模块级常量必须先查占用**。
LIGHT_STATES = (STATE_R0, STATE_L2, STATE_L1, STATE_Ls, STATE_L0, STATE_DEV)

STATE_LABEL = {STATE_R0: "失守", STATE_L2: "拦截", STATE_L1: "注意",
               STATE_Ls: "缺粮", STATE_L0: "值守中", STATE_DEV: "研发中"}

#: ★★★ 六态短名的**唯一真源**就是上面这张 `STATE_LABEL`。
#:   取名一律走 `state_short()`；术语表 / CLI / 日报 / 筛选条 / 托盘 / 事件标题前缀
#:   **全部派生**。任何模块**不得**再写第二份 `{"R0": "…", …}` —— 判据
#:   `inbox_guards_0372.py` S08 会全仓扫描第二份声明并报红。
#:   ★ 为什么是"扫第二份"而不是"多写几条断言"：漂移的**入口**是"又抄了一份"，
#:     把入口堵死，比在每个出口巡逻更省事、也更难绕过。
def state_short(key):
    """态的对外短名（**唯一入口**）。未知键原样返回，不抛错。"""
    return STATE_LABEL.get(key, key)


#: 光梯次序的**人话**写法（术语表/文案用），由 `PRIORITY` **算出来**，不手写 ——
#: 手写必然与 `PRIORITY` 漂移（0.37.3 前术语表写的次序正好与代码相反，就是这么来的）。
PRIORITY_ORDER_TEXT = " > ".join(
    state_short(k) for k, _ in sorted(PRIORITY.items(), key=lambda kv: -kv[1]))

#: 灯态 → LOGO 资源名（assets/logo/*.mp4 与 icons/*.ico）
#: ★ 开发态复用 L1 动图（0.36.3 决定：不为一种状态多做一套动图）；
#:   未启用复用 L0 动图、由调用方把颜色压灰（`STATE_VAR`）。
STATE_LOGO = {STATE_R0: "R0", STATE_L2: "L2", STATE_L1: "L1",
              STATE_Ls: "Ls", STATE_L0: "L0", STATE_DEV: "L1"}

#: 灯态 → 强调色 CSS 变量（与 `inbox_server.LEVEL_VAR` 同一套色；
#:   dev 用品牌蓝而不是 L1 浅黄 —— 否则「研发中」和「注意」长得一样）。
STATE_VAR = {STATE_R0: "--r0", STATE_L2: "--l2", STATE_L1: "--l1",
             STATE_Ls: "--ls", STATE_L0: "--l0", STATE_DEV: "--brand"}


#: ★★ 合法**姿态**的封闭集合 —— 真源在 `host_shield.POSTURE_ALL`，
#:   这里**转发**而不是手抄一份（两份清单必然漂移：一边加了状态另一边没加
#:   ⇒ 正常态被判成盲区，或更糟：异常态被判成绿）。
try:
    from host_shield import POSTURE_ALL as _POSTURE_ALL
except Exception:                                        # noqa: BLE001
    # 取不到就退回本地最小集 —— **宁可漏判成盲区，也绝不把未知当正常**。
    _POSTURE_ALL = frozenset(("down", "interrupted", "warn", "dev",
                              "unknown", "off", "guarding"))


def state_label(state, posture_state=None):
    """灯态的人话标签。★ L0 有一个**灰变体**：未启用时显示「未启用」。

    为什么不是第七个态：未启用与值守中同属 L0（放行/正常），差别只在
    「有没有在守」—— 用标签区分足矣，再造一个灯态就是 8 态复辟。
    """
    if state == STATE_L0 and posture_state == "off":
        return "未启用"
    return STATE_LABEL.get(state, STATE_LABEL[STATE_L1])


# ------------------------------------------------------- 粮（口粮）----
#: 只有这几种姿态下"缺粮"才说得通 —— 哨兵**在岗**才有消耗。
#: `off`（没启用）/`interrupted`（缺岗）/`unknown`（探不到）时根本没在吃粮，
#: 报"缺粮"是编；`down`/`warn` 已在 ① 返回 R0，走不到这里。
_GRANARY_ON_DUTY = ("guarding", "dev")


def granary_now(root=None):
    """粮的**实时读数**（真源在 `granary`）。本函数只做容错转发，读不到返回 None。

    ★ 为什么要有它：页面不该直接依赖 `granary` —— 少一个模块挂掉就整页挂掉。
      这里做成"取不到就当没有粮账"，页面照常渲染（降级，不假绿也不崩）。
    """
    try:
        import granary as G
        return G.state(root)
    except Exception:                                  # noqa: BLE001
        return None


def _granary_level(granary, posture_state):
    """粮的当前缺口 ⇒ `"Ls"`，否则 `None`。"""
    if not granary or posture_state not in _GRANARY_ON_DUTY:
        return None
    return "Ls" if granary.get("state") == "low" else None


def _granary_why(granary):
    return (granary or {}).get("why") or "粮快见底了"


def light(posture_state, items, now=None, hours=WINDOW_HOURS, granary=None):
    """「此刻 ＋ 24h 账」的**合并读**。返回 `(state, why)`（六态之一）。

    ★★★ 0.39.0 身份更正（**重要：别再拿它当"灯"**）：
      创始人 2026-10-09 裁定「一定要让值守台反应当前的准确状态，没有失守
      却显示失守，就是错误的」⇒ **灯改用 `current_state()`**（只看此刻）。
      本函数**保留原语义**（此刻 × 账，取最高级）—— 它答的是"合起来最该提
      哪一档"，**不是**"现在怎么样"。**页面渲染不得直接调它**：目录里
      `ci/inbox_guards_0380.py` 的 S12 会扫源码钉死这一点。

    ★ 0.38.0：新增 `granary`（可选）—— 粮的读数（`granary.state()` 的返回值）。
      **不传 ⇒ 与 0.37.x 逐字同行为**（既有判据与调用点因此不受影响）。
      传了且余额低于阈值、且哨兵在岗 ⇒ 与 24h 事件**同台比级**（`PRIORITY`
      已把 Ls 排在 L2 之上：「离终结更近」）。

    ★★ 判读顺序（**当前态势 > 24h 未处理事件／缺粮 > 当前缺口 > 身份态**）：

      ① 防线没生效或不可信（缺岗且有可指认后果 `down`；出厂码与登记不符
         `warn` 且非研发态）⇒ **R0 失守**（红）。warn 走 fail-closed：
         「认不出守门的是不是原来那道门」时，按它在裸奔算 ——  waffle
         一个「存疑」黄灯正是被创始人禁掉的形状。
      ② 24h 内有未处理事件 ⇒ **取最高级**（R0/L2/L1/Ls）—— LOGO 五态
         的原生读法（「黄一点＝重一点」的梯度就是事件级差）。
      ③ 没有未处理事件时的当前缺口：缺岗但无损失 `interrupted`、探针抛错
         `unknown` ⇒ **L1 注意**（黄：盲区/缺口，不等于没问题，也≠失守）。
      ④ 未启用 `off` ⇒ **L0 值守**（灰变体：默认全关是产品第一原则，
         把「没开」渲染成「坏了」是噪音）。
      ⑤ 研发态 `dev` ⇒ **dev 研发中**（蓝）。★ dev **不预占灯色**：有未处理
         事件时按事件级显示（走 ②），研发身份写进 why —— 这正是 0.36.4
         「研发中只是状态之一，哨兵发现状况了该出现的状态还是要出现」。
      ⑥ 集合外（不认识的姿态/None/不可哈希）⇒ **L1 注意**（盲区）——
         绝不打绿：状态机出错时界面替你安静地说「一切正常」是本仓
         明令禁止的最坏形状（0.36.3 实测 `light("banana")` 曾 → 绿）。
    """
    # ① 防线没生效/不可信 ⇒ R0（当前态势优先于一切历史）
    direct = _posture_direct(posture_state)
    if direct is not None:
        return direct
    # ⑥ 集合外一律盲区（放在 ①② 之后：真实测到的坏态势优先于输入异常）
    if not isinstance(posture_state, str) or posture_state not in _POSTURE_ALL:
        return STATE_L1, ("收到一个不认识的防线状态（%r）——这是盲区，"
                          "不等于没问题" % (posture_state,))
    # ② 24h 未处理事件 ＋ 粮的当前缺口 ⇒ 取最高级
    #   ★★ 这一步必须在 ③④⑤（含 dev）**之前**：否则研发态会提前返回，
    #      把真实告警吞掉 —— 0.36.4 纪律「研发中不掩盖真实状况」。
    #   ★ 0.38.0：粮的缺口与事件**同台比级**（`PRIORITY` 说了算），不另立一套次序。
    open_items = _window_open(items, hours, now)
    lv_ev = (max((it.level for it in open_items), key=lambda x: PRIORITY[x])
             if open_items else None)
    gl = _granary_level(granary, posture_state)
    if lv_ev is not None or gl is not None:
        if gl is not None and (lv_ev is None or PRIORITY[gl] > PRIORITY[lv_ev]):
            lv, why = gl, _granary_why(granary)
        else:
            lv = lv_ev
            why = "%d 小时内有未处理事项（最高 %s）" % (hours, lv_ev)
        dev_note = ("；同时这一版还在研发迭代中，代码与登记不一致是改出来的"
                    if posture_state == "dev" else "")
        # ★ why 里**不放件数**（0.37.1 去重）：件数是"要处理多少件事"，
        #   它由页面其他表面各按各的口径各显示一次（收件箱页＝筛选条，
        #   其他页＝顶部条后缀）—— 状态说明只说"有没有、最高哪级"。
        return lv, why + dev_note
    # ③④⑤ ＋ guarding：此刻态势自身给出的档位（历史账已在 ② 判完）
    return base_state(posture_state)


def _window_open(items, hours=WINDOW_HOURS, now=None):
    """窗口内**未处理**（未读＋已读）的记录（★ 灯的唯一取数口径）。

    ★ 0.37.2 抽出来：`light()` 与 `light_explain()` 必须数**同一批记录** ——
      否则会出现"灯按 9 件报红、页面原因行却说 4 件"的同一屏数字打架。
    """
    return [it for it in items
            if it.state in OPEN_STATES and within_hours(it.ts, hours, now)]


def _posture_direct(posture_state):
    """★ 只看**此刻**就能定档的两种态势：`down` / `warn` ⇒ R0。

    ★ 0.37.2 抽出来（fix）：`base_state()` 原先**没有** down/warn 两个分支
      （它们在 `light()` 里），于是 `posture_light()` 遇到 `down` 会落到
      函数末尾的兜底 ⇒ 返回 L1「收到一个没登记的防线状态（'down'）」。
      **实测形状**：日报/运行状态的「现在的防线状态」在真正失守时显示
      「注意」—— 把最严重的态势读成了最轻的那档。
      ⇒ 抽成一份，`light()` 与 `base_state()` 共用，不会再漏。
    """
    if posture_state == "down":
        return STATE_R0, "防线此刻确实不在岗，而且有东西没人管"
    if posture_state == "warn":
        # 出厂码不符且非研发（dev 已在 host_shield 侧分流）⇒ fail-closed。
        return STATE_R0, ("哨兵进程在岗，但守门的这份代码跟出厂登记的那份对不上"
                          "（可能被改动过，也可能这次没装好）——认不出它守的是不是"
                          "原来那道门，先按失守算")
    return None


def base_state(posture_state):
    """★ 只看**此刻这一次的态势**（不含任何历史事件账）。返回 `(state, why)`。

    ★★ 为什么要有第二个入口（2026-10-09，创始人第 1 问「后台数据跟前沿的
      对接是否正确」引出的真 bug）：
      日报/运行状态页有一行叫「现在的防线状态」，释义写的是
      「不计数；是**当场查一次**的结果」，而它显示的值取自 `light()` ——
      那是「此刻态势 × 24h 历史账」的**混合判读**。
      ⇒ 页面上出现了"自称 A、实际 B"的一行：明明写着「当场查一次」，
        原因却写「24 小时内有未处理事项（最高 R0）」。
      ⇒ 拆开：`light()` 答"整体该报什么"，`base_state()` 答"此刻查到了什么"。
        两者共用同一套 MAP，不写第二份映射，不会漂移。

    ★ 0.37.2 fix：`down` / `warn` 原先**不在这里**（只在 `light()` 里），
      于是 `posture_light()` 拿到 `down` 会落到末尾兜底 ⇒ 报 L1「没登记的
      防线状态」—— **真正失守被读成最轻的一档**。现在走 `_posture_direct()`
      共用一份（详见那里的注释）。

    ★ `guarding` 仍走**显式分支**：不许靠"穿透 if 链落到函数末尾"拿正常结果
      —— 0.36.3 实测教训：穿透＝把正确性交给运气（兜底一改，绿就变黄）。
    """
    direct = _posture_direct(posture_state)
    if direct is not None:
        return direct
    if posture_state == "interrupted":
        # ★ 0.37.2：`哨兵` 是页面上**唯一**的守护角色（创始人 2026-10-09：
        #   「不要制造并列的护盾加哨兵两个概念，哨兵一个概念足矣，
        #     护盾是哨兵手里的一个工具」）。缺岗说的是**没人盯着** ⇒
        #   主语只能是哨兵。记录原文里另有「门闸」一词（历史写法，记录不改写）；
        #   界面文案一律用「哨兵」，防护状态类用中性名词「防护」，
        #   护盾只在 `sentinel` 词条里作为**工具**出现一次。
        return STATE_L1, ("哨兵缺岗，但此刻没有监管对象——可证明没损失；"
                          "仍建议尽快拉起来")
    if posture_state == "unknown":
        return STATE_L1, "探不到哨兵状态——这是盲区，不等于没问题"
    if posture_state == "off":
        return STATE_L0, "哨兵默认没在值守。开启后才会拦、才会记账。"
    if posture_state == "dev":
        return STATE_DEV, ("正在研发迭代：这一版还没发出去，代码与登记不一致是"
                           "改出来的（哨兵仍在正常放哨；它发现状况时该报的一样会报）")
    if posture_state == "guarding":
        return STATE_L0, "哨兵在岗，此刻没查出缺口"
    # 理论上不可达（上面已穷尽 POSTURE_ALL，`light()` 里集合外已被拦成 L1）。
    # 保留是**故意的**：万一 POSTURE_ALL 扩容而这里忘了加分支，它打**黄**
    # （盲区）而不是绿 —— 新增状态忘记接线时必须**看得见**。
    return STATE_L1, ("收到一个没登记的防线状态（%r）——这是盲区，"
                      "不等于没问题" % (posture_state,))


def current_state(posture_state, granary=None, items=None, now=None,
                  hours=WINDOW_HOURS):
    """★★ 「灯态」的**唯一真源**（2026-10-09 创始人裁定 ＋ 逐态复审，0.39.0）。

    ★★★ 六态的**来源分工**（这是本函数存在的全部理由，判据 `ci/inbox_guards_0380.py` 钉死）：

      | 态 | 性质 | 唯一来源 | 为什么 |
      |----|------|----------|--------|
      | R0 失守 | **状态**（有时态） | **只由此刻** | 「现在失守」才叫失守；「昨天失守过、已恢复」≠ 现在失守 |
      | L2 拦截 | **事件**（天然过去时） | **只由账** | 不存在"此刻正在拦截"——拦下就是拦下了 |
      | L1 注意 | 兼有 | 此刻（缺岗无损失／探不到）＋账 | 盲区与提示都是"别慌，但要知道" |
      | Ls 缺粮 | **状态**（余额） | **只由此刻** | 余额是当下事实 |
      | L0 值守中 | 状态 | 只由此刻 | — |
      | dev 研发中 | 状态 | 只由此刻 | — |

      ⇒ **铁律：R0 绝不由账给。** 其余事件级（L2/L1）绝不由"姿态"编。

    ★★★ 为什么必须有它（真问题，本机实测，不是设计偏好）：
      旧实现里页面那盏灯取 `light()` —— 那是**两个维度的合并读**（此刻 × 24h 账）。
      本机实测：哨兵在岗、心跳 4 分钟前、自检通过，而 24 小时里躺着未处理的
      **失守记录** ⇒ 灯显示**失守（红）**，创始人点进去才发现**此刻好好的**。
      创始人裁定：「**一定要让值守台反应当前的准确状态，没有失守却显示失守，
      就是错误的**，请修正，并且要从机制上修正，防范再犯。」

    ★★ 更正：第一版把它写成"**纯**此刻"（完全不看账）—— **那是错的**，
      它让 `L2 拦截` **永远亮不起来**（六态里少一个可达态）。实测见
      `_p_state_reach` 探针：`guarding ＋ 一条 tool_call_blocked` ⇒ 灯 L0（旧版
      纯此刻）而 `light()` 给 L2。⇒ 修法不是"再把账整个放回来"，而是
      **按范畴分开**：状态用此刻、事件用账、**失守永不回溯**。

    ★ 与 `light()` 的分工（**不许混用**）：
      · `current_state()` ⇒ **灯**用它（本函数）；
      · `light()`         ⇒ 答"此刻＋账合起来最该提哪一档"（含历史 R0）⇒
                             只用于诊断/账，**页面渲染不得直接调它**。
    """
    lv, _ = base_state(posture_state)
    # ---- 事件级：只取 L2/L1；**历史 R0 一律不抬灯** ----
    if items:
        ev = [it.level for it in _window_open(items, hours, now)
              if it.level in (STATE_L2, STATE_L1)]
        if ev:
            top = max(ev, key=lambda x: PRIORITY.get(x, 0))
            if PRIORITY.get(top, 0) > PRIORITY.get(lv, 0):
                lv = top
    # ---- 粮：此刻的余额缺口 ----
    gl = _granary_level(granary, posture_state)
    if gl is not None and PRIORITY.get(gl, 0) > PRIORITY.get(lv, 0):
        lv = gl
    return lv


def posture_light(posture, hours=WINDOW_HOURS):
    """给「现在的防线状态」用的**实时读数** —— 答"此刻查到了什么"。

    返回 `(state, label, why)`。`why` 取守门模块**当场**给出的原因原文
    （`guard_posture()["why"]`），不是事件账推出来的；这就让页面上
    「当场查一次」这行字名副其实。
    """
    p = posture or {}
    st, fallback = base_state(p.get("state"))
    why = (p.get("why") or "").strip() or fallback
    return st, state_label(st, p.get("state")), why


def light_explain(posture, items, now=None, hours=WINDOW_HOURS, granary=None):
    """★★ 顶部灯的**完整说明**（0.37.2 新增，★ 唯一实现）。

    ★ 0.38.0：新增 `granary`（可选）—— 粮的读数。**不传 ⇒ 与 0.37.x 逐字同行为**。
      传了且余额低、哨兵在岗 ⇒ 这盏灯可能是「缺粮（Ls）」给的，
      原因句因此改说粮，而不是"此刻是好的"（否则灯说缺粮、句子说没事，自相矛盾）。

    ★★★ 0.39.0 决议（**取向已反转**，2026-10-09 创始人二次裁定）：
      0.37.2 的折中是"状态词仍取合并读（可能显示失守），另用事实句解释另一维"。
      创始人实测后**否掉了它**：「**一定要让值守台反应当前的准确状态，没有失守
      却显示失守，就是错误的**，请修正，并且要从机制上修正，防范再犯。」
      ⇒ 现在 `state` / `label` 取 **`current_state()`**（只看此刻），
        历史账改由 `ledger_bad` / `reason` 表达。
      ⇒ "两个状态词会困惑"的顾虑**仍然成立**，所以并**没有**引入第二个状态词：
        账这一维用**非状态的事实句**说（"另外，24 小时里还有没处理的事"），
        件数照旧只归筛选条 / 钻取后缀（数字只出现一次）。

    ★★ 为什么要有它（创始人 2026-10-09 实测点名的真问题）：
      `light()` 把**两个不同的维度**合成了一个数 ——
        · 维度一「此刻」：哨兵在不在岗、心跳多旧、自检过不过；
        · 维度二「24 小时账」：这段历史里有没有**还没处理**的记录。
      本机实测：此刻哨兵在岗、心跳 0 分钟前、自检通过；而 24 小时里躺着
      未处理的失守记录 ⇒ 灯显示「失守」（红）。用户看到红，点进去才发现
      **此刻好好的** —— 一个词回答了两个问题，等于两个都没答清。

    ★★ 为什么不拆成两个状态读数（文档 §2.3 方案乙）：
      同屏出现两个状态词（「失守」＋「值守中」）时，用户不知道该信哪个 ——
      而这个形状**不用假设**：日报页已经是顶部条「失守」＋页面内「值守中」，
      实测正是困惑的来源。⇒ 状态词仍然只有一个，**另一个维度改用
      非状态的事实句表达**（"此刻是好的（哨兵在岗…）"），并明说灯的色
      是哪一维给的。

    返回 dict：
      `state`      六态之一
      `label`      人话状态词
      `now_text`   「此刻」这一维的事实句（取守门模块**当场**给出的原话）
      `now_bad`    此刻这一维本身是不是就该报警
      `ledger_bad` 24 小时账这一维是不是有未处理项
      `reason`     拼好的一句话原因（页面直接用，不再自己拼）
    """
    p = posture or {}
    # ★★★ 0.39.0（创始人裁定「没有失守却显示失守，就是错误的」）：
    #   灯＝`current_state()`，**不再**取 `light()` 的「此刻 × 24h 账」合并读。
    #   ★ 注意它**不是**"纯此刻"：**状态类**（R0/Ls/L0/dev）只由此刻给，
    #     **事件类**（L2/L1）只由账给 —— 尤其**历史 R0 一律不抬灯**
    #     （来源分工表见 `current_state()` 的 docstring）。
    #     第一版写成"纯此刻"会把 `L2 拦截` 变成**不可达态**（实测抓到的回归）。
    #   完整账（含历史 R0）由下面的 `ledger_bad` / `reason` 与页面上的
    #   「要处理 N」承担 —— 账照样摆出来，只是不再冒充"此刻"。
    st = current_state(p.get("state"), granary, items, now, hours)
    label = state_label(st, p.get("state"))

    # ---- 维度一：此刻（走 base_state 的**同一份**映射 + 当场原话）----
    bst, fallback = base_state(p.get("state"))
    now_text = (p.get("why") or "").strip() or fallback
    # L0（含未启用）与 dev 都算"此刻这一维是干净的"；其余（R0/L1/Ls/盲区）都要说
    # ★ 0.38.0：粮低也算"此刻不干净"（余额是**当下的事实**，不是历史账）。
    gran_bad = _granary_level(granary, p.get("state")) is not None
    now_bad = bst not in (STATE_L0, STATE_DEV) or gran_bad

    # ---- 维度二：24 小时账（与灯同一批记录，绝不各数各的）----
    ledger_bad = bool(_window_open(items, hours, now))

    # ---- 拼一句话：始终先说此刻，再说账 ----
    # ★ 不放件数：`light()` 的 why 里放件数是 0.37.1 就删掉的重复源，
    #   件数归筛选条/顶部钻取/药丸各管一处；这一句只答"为什么是这个色"。
    # ★ 0.37.2 fix：守门模块给的 `why` **自带句号**（如"…这次没装好。"）——
    #   直接往后接"；另外…"会拼出「。；」这种双层句读（本机实测见账本页
    #   顶部条）。⇒ 只在**把 `now_text` 嵌进更长的句子**时去掉它的尾部句读；
    #   单独成句的那条分支照旧保留原文（它是一个完整句子）。
    _nt = now_text.rstrip("。；;.")
    if gran_bad:
        # 此刻这一维不干净的原因就是粮 —— 照实说粮，不许再说"此刻是好的"。
        _gt = _granary_why(granary).rstrip("。；;.")
        reason = ("此刻：%s；另外，24 小时里还有没处理的事。" % _gt if ledger_bad
                  else "此刻：%s" % _gt)
    elif now_bad and ledger_bad:
        reason = "此刻：%s；另外，24 小时里还有没处理的事。" % _nt
    elif now_bad:
        reason = "此刻：%s" % now_text
    elif ledger_bad:
        # ★★ 0.39.0：灯现在**就是**"此刻"（`current_state`）⇒ 旧文案
        #   「灯这样报，是因为 24 小时里有没处理的事」**已不成立** ——
        #   此刻好 ⇒ 灯是绿的，根本没有"被账报红"这回事。改成"另外…"，
        #   如实把它说成**另一件事**，而不是灯色的来源。
        reason = "此刻是好的（%s）；另外，24 小时里还有没处理的事。" % _nt
    else:
        reason = "%s；24 小时里也没有等你处理的事。" % _nt
    return {"state": st, "label": label, "now_text": now_text,
            "now_bad": now_bad, "ledger_bad": ledger_bad, "reason": reason}
