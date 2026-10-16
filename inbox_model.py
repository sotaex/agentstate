# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

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
import re
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
    "host_shield_spawn_failed": "失守：监理没能启动",
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
    "spawn_failed": "失守：监理没能启动",
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


#: ★★ 0.43.0（A3 收口）：**自愈事件不得再顶 R0**。
#:   链记录带 `recovered=True` ＝「防线自己扛住了、没留后果」（AUDIT_SCHEMA v1.10）。
#:   而 `LEVEL_OF_KIND` 是**按类型一刀切**，答不了"这一条**实际**有没有后果"
#:   ⇒ 实测 24h 内 17 条自愈记录仍被定成 R0，页面于是长出自相矛盾的标题
#:   「**失守**：防护文件被改动（状态被改，**已自动恢复**）」
#:   （取证见 `_p_r0_audit3.py`：recovered=true 却 severity=critical）。
#:   ★ 为什么不直接改 `LEVEL_OF_KIND`：那张表回答的是「这类事件**通常**多严重」，
#:     降级必须发生在**记录级**，否则一条真失守会被一起降掉（本仓最恨的"一刀切"）。
DEMOTE_RECOVERED_FROM = ("R0",)
DEMOTE_RECOVERED_TO = "L1"

#: 降档后的标题（★ 方向必须同向：降到 L1 就**不许**再挂「失守」二字）。
TITLE_WHEN_DEMOTED = {
    "host_shield_tamper": "注意：防护设置被改、已自动恢复",
}


def level_of_record(kind, *, recovered=False, zone_failed=None):
    """★★ 记录级定档（**唯一实现**：收件箱／页面／日报／托盘全部走这里）。

    ★ 为什么必须有它：`level_of(kind)` 只能答「这类事件**通常**多严重」，
      答不了「**这一条**有没有后果」。两类记录必须**按记录**判：
        · `recovered=True`（自愈，0.43.0）⇒ 降档；
        · `host_shield_zone_locked` 兼表成败（A8，0.40.0）⇒ 成功不是失守。
      ⇒ 两者都收进本函数，**不许**在投影层各写一段 `if`（那是两套会漂移的口径，
        本仓「同一事实两处实现」第 N 次复发的标准形状）。
    """
    lvl = level_of(kind)          # 未登记 ⇒ UnknownKind（响亮失败，不许静默降级）
    if kind == "host_shield_zone_locked":
        # A8：上锁**成功**不是失守（实测 2 条被报成失守）。
        return lvl if zone_failed else DEMOTE_RECOVERED_TO
    if recovered and lvl in DEMOTE_RECOVERED_FROM:
        return DEMOTE_RECOVERED_TO
    return lvl


#: ★ 0.47.0：`TITLE_OF_TOPIC` 里**写着「失守」**的那些条目，只准挂给列出的 kind。
#:   ★ 判据不读文案猜方向 —— 用**显式归属表**（`host_shield_zone_locked` 的
#:     `zone_lock_failed` 也是同一类：它是"失守"，且只属于 zone_locked）。
#:   ★ 未登记的事由标题（不带"失守"的那些，如 `zone_ok`）对所有 kind 开放。
_TOPIC_TITLE_OWNERS = {
    "code_drift": ("host_shield_tamper",),
    "state_drift": ("host_shield_tamper",),
    "self_check": ("host_shield_tamper",),
    "zone_lock_failed": ("host_shield_zone_locked",),
    "autostart_missing": ("host_shield_breach",),
    "spawn_failed": ("host_shield_breach", "host_shield_spawn_failed"),
}


def _topic_title_allowed(kind, topic):
    """这个事由标题能不能挂给这个 kind（0.47.0，见 `_TOPIC_TITLE_OWNERS`）。"""
    owners = _TOPIC_TITLE_OWNERS.get(topic)
    return True if owners is None else kind in owners


def title_of_record(kind, level, topic=""):
    """标题与级别**同向**（★ 唯一实现）。`level` 由 `level_of_record` 给出。

    ★ 为什么标题也要走这里：`TITLE_OF_TOPIC["state_drift"]` 写着「失守：…」。
      自愈记录降档到 L1 之后若还借它，就会产出「L1 · 失守」这种自我矛盾的
      标签 —— 与 `host_shield_breach` 旧标题「**已拦截**：越界动作被挡下」
      同型（把"没被挡住"说成"拦住了"），是本仓反复出现的**方向反了**型缺陷。
    """
    base = TITLE_OF_KIND.get(kind, kind)
    tt = TITLE_OF_TOPIC.get(topic)
    # ★★ 0.47.0（方案 v3.0 §5 步二）：**「失守」类事由标题只许挂给 tamper**。
    #   实测（`_p_0470_probe1.py`）：`title_of_record("host_shield_dev_drift", "L1",
    #   "code_drift")` 会借到 `TITLE_OF_TOPIC["code_drift"]` ＝
    #   「**失守**：防护文件被改动（代码与登记表不符）」—— 而 `dev_drift` 是
    #   **自研迭代**，与"失守"方向相反（本仓"方向反了"型缺陷第 N 次）。
    #   真运行时它走 `inbox_store.project_record` 的专门分支（只用 `TITLE_OF_KIND`）
    #   ⇒ 今天不发病；但只要 `kinds` 一放宽、或任何新投影路径调到这里，就立刻错挂。
    #   ⇒ 在**唯一实现**这里加门，而不是让每个调用点各自记得（后者必然漂移）。
    if tt and _topic_title_allowed(kind, topic):
        base = tt
    if level == level_of(kind):
        return base                                  # 没改档 ⇒ 原标题
    if kind == "host_shield_zone_locked":
        # A8：成功 ⇒ 换成"已上锁"标题（借 R0 那条会把成功读成失守）。
        return TITLE_OF_TOPIC.get("zone_ok") or "注意：安全区已上锁（区内防篡改）"
    # ★ 兜底（不许静默留着「失守」二字）：没登记专用文案 ⇒ 把方向改过来。
    return TITLE_WHEN_DEMOTED.get(kind) or (
        "注意：" + base[len("失守："):] if base.startswith("失守：") else base)


#: ★★ 0.43.0：**用户可见文本**的去 markdown 化（**唯一实现**）。
#:   为什么必须有：审计链 append-only ⇒ 机器上躺着各旧版本写下的记录，
#:   其中混着 markdown 加粗（实测 `zone_locked` 文案里的 `**不等于**`）。
#:   0.42.0 只在**网页**两条渲染路径做了免疫（`inbox_server._vis`），
#:   **命令行**那条路漏了 ⇒ `inbox_cli.py list` 照样吐裸星号（2026-10-10 实测）。
#:   ⇒ 收进这里，网页与命令行共用一份（不许各写一份 —— 那是第二套口径）。
_MD_STARS = re.compile(r"\*+")


def visible_text(s):
    """**用户可见文本**的出口：去掉 markdown 星号（★ 唯一实现，纯文本版）。

    ★ 只改写侧文案不够（旧记录改不了）⇒ 读侧免疫，与 0.41.0 修 `is_denied()`
      同一条思路（换 oracle，而不是把某一次的结果改对）。
    ★ 口径：`**X**` → `X`（删掉加粗标记，语义不变）。
    """
    return _MD_STARS.sub("", "" if s is None else str(s))


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
    if filt.startswith("ids:"):
        n = len([x for x in filt[4:].split(",") if x])
        return "指定的 %d 条记录" % n
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
    if filt.startswith("ids:"):
        wanted = {x for x in filt[4:].split(",") if x}
        return [it for it in items if it.id in wanted]
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


# ────────────────────────────────────────────────────────────────────────
# ★★ 0.47.0（方案 v3.0 §5 步三）：**界面不许出现无分母的告警数**。
#   方案原文：「凡显示告警，必同时给出**窗口与分母**」。
#
# ★ 为什么（数据口径，不是排版偏好）：「要处理 37 条」里的 37 是**分子**，
#   它的分母（这次一共读了多少条）没说 ⇒ 读者无从判断 37 是多还是少，
#   只能靠恐慌。这与方案 §5「真信号被稀释成二十分之一」**同源**：
#   **没了分母，比例信息整个丢失** —— 于是"稀释"这件事在界面上永远看不见，
#   而它恰恰是第三处病的名字。
#
# ★ 唯一实现：页面上每一处告警数都走 `count_text()`，不许各写一段 `%d 件`
#   （各写一段＝第二套口径，本仓「同一事实两处实现」的标准形状）。
def count_text(n, total, hours=WINDOW_HOURS, unit="件"):
    """告警数的**唯一显示格式**：分子 / 分母 ＋ 窗口（★ 唯一实现）。

    ★ `total`（分母）**不许为 None** —— 那就成了"无分母的告警数"，
      判据 `ci/inbox_guards_0470.py` 的 S 会把它抓出来。取不到分母时不显示该数，
      不要显示一个光秃秃的分子。
    """
    if total is None:
        return "%d %s / 分母未知" % (int(n or 0), unit)
    return "%d %s / %d（最近 %d 小时）" % (int(n or 0), unit, int(total), int(hours))


def reading_note():
    """一排数字的**读数口径说明**（★ 唯一实现，取代旧 `window_note`）。

    ★★ 为什么换掉（交接件 v1.1 §5.3 甲2 / §5.4 甲4，2026-10-12 实测）：
       旧句「最近 %d 小时 · 以上数字的分母均为本次载入的 %d 条记录」
       **两句都维持不住**：
       ① 页面不自动刷新 ⇒「最近 24 小时」的窗口边界**不随时间滚动** ——
          它把一次载入的快照说成了活的（甲2；托盘侧有 StaleTip 陈旧机制，
          Web 页零对应物，甲3 同批定性：本版不建陈旧守卫，将来做刷新时同批建）；
       ②「分母均为 N 条」对四个 tab 至少三个是假的 —— 要处理按**件事**归并、
          归档**无时间上限**，`glossary` 词条自述四个 tab 分母是四个不同的东西
          （甲4）；且日报页另有第二份内联说明不走唯一实现（维一）。
       ⇒ 改成一句**不承诺维持不住的口径**的说明：只说是本次载入时的读数、
         窗口自载入起算。分母与单位下沉到每个 tab 的**可见单位**与「？」词条的
         口径行（那才是定义处）。**先删谎，再谈增强**（§5.3 反漂移）。
    """
    # ★ 0.50.4（Q-22）：补上**载入时刻**。页面诚实声明"不随页面停留刷新"，
    #   可用户看不出手上这一屏是 1 分钟前还是 3 小时前的 —— 只说"不刷新"
    #   而不给时刻，等于让用户自己猜快照的新旧。
    #   ★ 不加参数（调用点保持 `M.reading_note()` 形态）：判据
    #     `ci/inbox_guards_0490.py` 用 AST 查调用形态，`ci/inbox_guards_0470.py`
    #     直接比对 `M.reading_note()` 与页面文本 —— 加参数会让两边都错位。
    _at = datetime.now().astimezone().strftime("%H:%M")
    return ("以上数字均为本次载入时的读数（载入于 %s）；窗口自载入起算，"
            "不随页面停留刷新。" % _at)


def known_filter(filt):
    """筛选条取值是不是合法的（页面收到非法值 ⇒ 退回默认，不静默当成"全部"）。"""
    if filt in ("action", "info", "archive", "all"):
        return True
    for p in ("lv:", "kind:", "rule:"):
        if filt.startswith(p) and len(filt) > len(p):
            return True
    if filt.startswith("ids:"):
        ids = filt[4:].split(",")
        return bool(ids and all(x.strip() for x in ids))
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


# ---------------------------------------------------- 保持期（时长）----
#: ★★ 0.51.0（规格 v1.2 §3）：**info 桶事件的保持期**（分钟）。
#:   创始人 2026-10-16 第二问「拦截是瞬时的事情，是否约定一个时长，在拦截
#:   刚发生之后的一定时间段内显示」⇒ 定 H＝30 分钟（参数化，改值不改结构）。
#:   · info 桶（Antinel 自己处理掉的）只在 `未读 ∧ now - ts ≤ H` 内抬主灯；
#:     **已读＝已知情，提前结束**（0.35.3「你知情即可」的机制化）；
#:   · action 桶（只有你能解决）**不适用保持期** —— 待办不是新闻，
#:     24h 窗口内未关闭即持续抬灯（窗口是 0.35.3 既定，不改）。
#:   ★ H 与"紧急提醒"气泡分工：气泡管「刚发生」、灯管「还新鲜」、计数管
#:     「还没看」；参数化 ⇒ 改值只是改这个常量，判据锁的是**结构**不是数值。
LAMP_HOLD_MINUTES = 30

# -------------------------------------------------------- 徽标（并存维）----
#: ★★ 0.51.0（规格 v1.2 §2.2）：**研发中**与**缺粮**不再抢主灯，改为
#:   「徽标」——**不互斥、可多枚、常驻**。主灯（`current_state`）只答
#:   「此刻什么情况」（R0/L2/L1/L0，互斥）；徽标答「还有哪些并存态」。
#:   ⇒ 创始人 2026-10-16 第一问（"缺粮跟其他几态可能同时存在"）与第四问
#:     （"研发中跟其他态始终同时"）由**通道分工**回答：不选一个遮一个。
#: 键 → 人话名（**唯一真源**；判据 0372 S08 只认 inbox_model 里的态名声明）。
BADGE_DEV = "dev"              # 研发中（本机代码版本 > 已发布版本）
BADGE_GRANARY = "granary"      # 缺粮（粮低 ∧ 在岗 ∨ 未关闭的 credits_low）
BADGE_LABEL = {BADGE_DEV: "研发中", BADGE_GRANARY: "缺粮"}
#: ★★ 0.51.0：徽标的**短提示**（hover 用），与 `BADGE_LABEL` 同处 —— 判据
#:   0490 U-11 锁「收件箱页全部 title 属性 ≤ 20 字」，而 `badges()` 返回的
#:   `why` 是**完整原因句**（含具体版本号，如「研发中——本机这一版（0.51.0）
#:   比已发布的（0.35.1）新，还没发出去」= 38 字）⇒ 那句**不许进 title**，
#:   它走顶栏可见的原因句（`light_explain()["reason"]` 的「另外：…」段）。
#:   这里是 hover 的一句话：**说这个词是什么意思**，不搬工程说明。
BADGE_TIP = {
    BADGE_DEV: "本机这一版比已发布的更新",
    BADGE_GRANARY: "粮快见底了",
}
#: ★★ 0.51.0（四态问号小窗方案 v1.1 拍板点三，2026-10-16）：徽标 → 态词条键
#:   （顶栏徽标旁的问号芯片按它查 `glossary.TERMS`）。缺粮徽标的语义就是
#:   Ls 态（词条键 `Ls`）；研发中即 `dev`。新徽标必须同批登记三张表
#:   （BADGE_LABEL／BADGE_TIP／本表）—— 缺本表键 ⇒ 页面不出问号（.get 判空）。
BADGE_STATE = {BADGE_DEV: "dev", BADGE_GRANARY: "Ls"}


def _ver_tuple(s):
    """`"0.50.6"` → `(0, 50, 6)`；非字符串／坏格式 ⇒ `None`（**不猜**）。"""
    if not isinstance(s, str):
        return None
    m = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)", s)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def is_ahead_of_published(local, published):
    """本机版本是否**高于**已发布版本（研发中徽标的**唯一判据**）。

    ★ 取不到任何一侧 ⇒ `False`（**降级不假阳**）—— 与 `granary_now` 同一条
      容错哲学：读不到就当"没有这回事"，绝不编一个"研发中"出来。
    ★ 用**数值元组**比较，不用字符串比较：字符串比较下 `"0.9.0" > "0.10.0"`
      为真（逐字符先比 `"9" > "1"`）—— 版本 0.9.0 会被误判成比 0.10.0 新。
    """
    a, b = _ver_tuple(local), _ver_tuple(published)
    if a is None or b is None:
        return False
    return a > b


def version_pair(root=None):
    """`(本机代码版本, 已发布版本)` —— 容错读，取不到给 `None`。

    ★ 真源：本机＝`antinel.py::VERSION`；已发布＝`psl/workspace_facts.json`
      的 `release.pypi.published_version`（**该位只由 PyPI 实查改写**，是本仓
      既有纪律；`release.version` 作本机版本的兜底）。
    ★ 读不到（已装成包、无 dev 事实件）⇒ `(None, None)` ⇒ 徽标不显示
      （降级，不假绿也不假阳）。
    ★ 与 `granary_now` 同一条边界：模型层只做**容错转发**，读不到不抛错。
    """
    local = pub = None
    try:
        import antinel as _A
        local = getattr(_A, "VERSION", None)
    except Exception:                                      # noqa: BLE001
        pass
    try:
        import io
        import json
        import os
        p = os.path.join(root or os.path.dirname(os.path.abspath(__file__)),
                         "psl", "workspace_facts.json")
        with io.open(p, encoding="utf-8") as f:
            d = json.load(f)
        rel = d.get("release") or {}
        pub = (rel.get("pypi") or {}).get("published_version")
        if local is None:
            local = rel.get("version")
    except Exception:                                      # noqa: BLE001
        pass
    return local, pub


def badges(posture_state, granary=None, items=None, now=None,
           hours=WINDOW_HOURS, versions=None):
    """**徽标**（并存维）：返回 `[(键, 人话名, 原因), …]`，可同时多枚、常驻。

    ★ 徽标**不互斥、不抢主灯**：主灯说"此刻什么情况"，徽标说"还有哪些并存态"
      （规格 v1.2 §2.2）。「研发中的机器此刻失守」＝研发徽标 ＋ R0 主灯，
      两个事实都显示，谁也不掩盖谁。

    · **研发中**＝本机代码版本 > 已发布版本（`is_ahead_of_published`）。
      ★ 姿态 `dev`（自检与登记表不符）**不**并点这枚徽标 —— 那是**另一套信号**
        （`host_shield.is_dev_build`，比 manifest，服务安全路径与自检解释），
        与"发布身份"（比 PyPI）分开：两套信号说两个问题，不许互相冒充。
    · **缺粮**＝粮低 ∧ 哨兵在岗（`_granary_level`）**或**存在未关闭的
      `credits_low` 记录（已活的那一个源）。
    """
    out = []
    # ① 研发中
    if versions is None:
        versions = version_pair()
    if isinstance(versions, (tuple, list)) and len(versions) == 2:
        loc, pub = versions
    else:
        loc, pub = None, None
    if is_ahead_of_published(loc, pub):
        out.append((BADGE_DEV, BADGE_LABEL[BADGE_DEV],
                    "%s——本机这一版（%s）比已发布的（%s）新，还没发出去"
                    % (BADGE_LABEL[BADGE_DEV], loc, pub)))
    # ② 缺粮
    gl = _granary_level(granary, posture_state)
    cred = [it for it in (items or [])
            if it.kind == "credits_low" and it.state in OPEN_STATES
            and within_hours(it.ts, hours, now)]
    if gl is not None:
        out.append((BADGE_GRANARY, BADGE_LABEL[BADGE_GRANARY],
                    "%s——%s" % (BADGE_LABEL[BADGE_GRANARY], _granary_why(granary))))
    elif cred:
        # ★ 原因句从 `TITLE_OF_KIND` **派生**（不另写一份），去掉"缺粮："前缀。
        _t = TITLE_OF_KIND.get("credits_low", "")
        _why = _t.split("：", 1)[1] if "：" in _t else "粮快见底了"
        out.append((BADGE_GRANARY, BADGE_LABEL[BADGE_GRANARY],
                    "%s——%s" % (BADGE_LABEL[BADGE_GRANARY], _why)))
    return out


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
        return STATE_R0, ("监理进程在岗，但守门的这份代码跟出厂登记的那份对不上"
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
        #   ★★ 0.50.4 命名变更注记（创始人 2026-10-15 签发《值守台退休与窗口
        #      命名裁定》）：显示词「哨兵」→「**监理**」，「界面文案一律用哨兵」
        #      一句随之更新为「一律用监理」；上面 0.37.2 的注释是**当时的决策
        #      记录**，按「记录原文不改写」纪律保留原样。下面各状态原因文案
        #      已同批换词（哨兵→监理）。
        return STATE_L1, ("监理缺岗，但此刻没有监管对象——可证明没损失；"
                          "仍建议尽快拉起来")
    if posture_state == "unknown":
        return STATE_L1, "探不到监理状态——这是盲区，不等于没问题"
    if posture_state == "off":
        return STATE_L0, "监理默认没在值守。开启后才会拦、才会记账。"
    if posture_state == "dev":
        return STATE_DEV, ("正在研发迭代：这一版还没发出去，代码与登记不一致是"
                           "改出来的（监理仍在正常值守；它发现状况时该报的一样会报）")
    if posture_state == "guarding":
        return STATE_L0, "监理在岗，此刻没查出缺口"
    # 理论上不可达（上面已穷尽 POSTURE_ALL，`light()` 里集合外已被拦成 L1）。
    # 保留是**故意的**：万一 POSTURE_ALL 扩容而这里忘了加分支，它打**黄**
    # （盲区）而不是绿 —— 新增状态忘记接线时必须**看得见**。
    return STATE_L1, ("收到一个没登记的防线状态（%r）——这是盲区，"
                      "不等于没问题" % (posture_state,))


def current_state(posture_state, granary=None, items=None, now=None,
                  hours=WINDOW_HOURS):
    """★★ 「灯态」的**唯一真源**（2026-10-09 创始人裁定 ＋ 逐态复审，0.39.0）。

    ★★★ 主灯的**来源分工**（这是本函数存在的全部理由，判据 `ci/inbox_guards_0380.py` 钉死）：

      | 态 | 性质 | 唯一来源 | 为什么 |
      |----|------|----------|--------|
      | R0 失守 | **状态**（有时态） | **只由此刻** | 「现在失守」才叫失守；「昨天失守过、已恢复」≠ 现在失守 |
      | L2 拦截 | **事件**（天然过去时） | **只由账** | 不存在"此刻正在拦截"——拦下就是拦下了 |
      | L1 注意 | 兼有 | 此刻（缺岗无损失／探不到）＋账 | 盲区与提示都是"别慌，但要知道" |
      | L0 值守中 | 状态 | 只由此刻 | — |

      ⇒ **铁律：R0 绝不由账给。** 事件级（L2/L1）绝不由"姿态"编。
      ⇒ ★★ 0.51.0：`Ls 缺粮` 与 `dev 研发中` **不再是主灯态** ——
        它们是**并存徽标**（`badges()`）：主灯互斥、徽标可多枚常驻。
        六态**词表不动**（0372 S09 键不可撤），变的是**组成方式**与判据锚点。

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

    ★★ 0.51.0 改口径（规格 v1.2 §2）：改"单值优先级梯"为**三通道**——
      本函数只给**主灯**（互斥，R0/L2/L1/L0），只答"**此刻什么情况**"。
      研发中／缺粮**移出主灯**，改为 `badges()` 的**并存徽标**：
        · `dev` 姿态 ⇒ 主灯 **L0**（哨兵在岗是事实；研发**身份**由徽标说）；
        · 粮低 ⇒ **不再抬灯**（缺粮徽标 ＋ 要处理计数出面）。
      抬灯按**桶**分流（详见 `_event_lamp_level`）：action 桶持续抬灯；
      info 桶只在**未读 ∧ 刚发生**（保持期 `LAMP_HOLD_MINUTES`）内抬灯。
    """
    lv, _ = base_state(posture_state)
    # ---- ★ 0.51.0：dev 姿态的主灯是 L0（"监理在岗、此刻没查出缺口"）----
    #   研发**身份**移徽标（`badges()`）；主灯不再为"研发中"单独留一档。
    #   依据规格 v1.2 §2.1 —— dev 姿态下哨兵在岗放哨是**事实**；"我在研发"
    #   是**身份**；两者各说各的（0.36.4「研发中不掩盖真实状况」的彻底化：
    #   不是把研发身份说成在岗，是**两个通道各说各的**）。
    if lv == STATE_DEV:
        lv = STATE_L0
    # ---- 事件抬灯：只取 L2/L1；**历史 R0 一律不抬灯** ----
    ev = _event_lamp_level(items, hours, now)
    if ev is not None and PRIORITY.get(ev, 0) > PRIORITY.get(lv, 0):
        lv = ev
    # ---- 粮**不再**抬主灯：缺粮是并存徽标（`badges()`），不是"此刻的灯"----
    #   ★ `granary` 形参保留只为兼容既有调用点与判据的按位传参，
    #     本函数**不再读它**（规格 v1.2 §2.1：Ls 从灯态变徽标态）。
    return lv


# ────────────────────────────────────────────────────────────────────────
#: ★★ 0.47.0（方案 v3.0 §5 步二）：**篡改类的两条通道**（唯一真源）。
#:   方案原文：「篡改类分通道（自研迭代导致 ／ 疑似投毒导致）走不同类型与
#:   不同级别，**界面上不共用一盏灯**」。
#:
#:   数据（方案 §5）：篡改类里疑似真投毒只占 **7.5%（12 / 160）**，其余百分之
#:   九十二点五都是自家迭代与布防位不一致 ⇒ 「篡改」这一个词把两件事记成了
#:   同一种东西，真信号被稀释成二十分之一。
#:
#: ★ 0.40.0 已把**类型与级别**分好（`host_shield_dev_drift`=L1 自研迭代 ／
#:   `host_shield_tamper`=R0 疑似投毒）。**0.47.0 补的是界面这一半**：
#:   实测（`_p_0470_probe1.py`，0.46.0）——
#:     · 自研迭代 `dev_drift`      ⇒ 灯 **L1 注意**
#:     · 疑似投毒 `tamper` 已自愈  ⇒ 灯 **L1 注意**   ★ 与上面**同一盏灯**
#:     · 普通状态变更 `changed`    ⇒ 灯 **L1 注意**   ★ 也是同一盏
#:   ⇒ 三条完全不同的事挤在一盏浅黄灯下，用户分不出「我自己在改代码」和
#:     「有人动了我的防护文件」。这正是方案点名的病。
#:
#: ★ 修法：给「自研迭代」这条通道一盏**它自己的灯** —— 六态里的 `dev`（研发中，蓝）。
#:   · 不新增第七个态（`dev` 本来就在六态封闭集里，0.36.3 落地）；
#:   · **不许压过真实告警**：只在灯此刻是 L0 / dev 时才抬 dev，
#:     已有 L1/L2/R0/Ls 时**不动**（0.36.4 纪律「研发中不掩盖真实状况」的反向也成立）。
#:   · `tamper` 那一侧**一个字都不改**（R0 仍不由账给 —— 0.39.0 创始人裁定，
#:     「昨天失守过、已恢复 ≠ 现在失守」，必须保留）。
#:
#: ★★ 0.51.0 更新（规格 v1.2 §2.1／§7.2）：**dev 不再是一盏灯**，改为
#:   **并存徽标**（`badges()`，判据＝版本比对）。上面 0.47.0 的"给它一盏自己的灯"
#:   在 0.51.0 由通道分工**升级**为：
#:     · 「自研迭代」`host_shield_dev_drift` ⇒ 回归**普通 L1 事件**
#:       （info 桶，保持期内、未读 ⇒ 抬 L1；0.40.0 的本意）；
#:     · 「疑似投毒」`host_shield_tamper` ⇒ **不抬灯**（R0 家族；未自愈进
#:       「要处理」，已自愈归计数）；
#:   ⇒ **两条仍然不共用一盏灯**（一条能抬、一条不抬），只是"研发中"这枚标记
#:     从灯搬到了常驻徽标上 —— 与"我在研发"是**身份**、不是"此刻的灯"相符。
TAMPER_CHANNEL_KINDS = {
    "host_shield_tamper": "poison",       # 疑似投毒（防护文件被动过）
    "host_shield_dev_drift": "dev",       # 自研迭代（代码与登记表不符）
}


def tamper_channel_of(kind):
    """这条记录属于篡改类的哪一条通道（★ 唯一实现）。不在篡改类 ⇒ `None`。"""
    return TAMPER_CHANNEL_KINDS.get(kind)


def _event_lamp_level(items, hours=WINDOW_HOURS, now=None):
    """窗口内**值得抬主灯**的事件里最高的级别（L2/L1）；没有 ⇒ `None`。

    ★★ 0.51.0（规格 v1.2 §2.1／§3）：抬灯按**桶**分流 ——
      · **action 桶**（只有你本人能解决）⇒ 抬灯，24h 窗口内持续到处理/关闭
        （它是**待办**，不是新闻 ⇒ **不适用保持期**）；
      · **info 桶**（Antinel 自己处理掉的）⇒ 只在 **未读 ∧ 刚发生**
        （`now - ts ≤ LAMP_HOLD_MINUTES`）时抬灯；**已读＝已知情，提前结束**
        （0.35.3「你知情即可」的机制化），超期只进「待阅 N」；
      · **R0 级一律不抬灯**（0.39.0 铁律；R0 由"要处理"计数与原因句出面）；
      · **疑似投毒（tamper）通道不抬灯** —— 它是 R0 家族、天然过去时；
        把它读成"此刻的注意"会与"自研迭代"混成一盏灯（0.47.0 分通道的延续：
        两条通道**不共用一盏灯** ⇒ 自研迭代走普通 L1 事件，投毒不抬灯）。

    ★ 为什么单独抽出来：`current_state()` 是主灯的唯一真源，但"抬灯按桶分流 ∧
      保持期"是一条**独立可验**的规矩，抽出来才能给它配单独的负控与探针。
    """
    if not items:
        return None
    best = None
    hold = LAMP_HOLD_MINUTES / 60.0
    for it in _window_open(items, hours, now):
        lv = it.level
        if lv not in (STATE_L2, STATE_L1):
            continue
        if tamper_channel_of(it.kind) == "poison":
            continue
        b = bucket_of(it, now=now, hours=hours)
        if b == BUCKET_ACTION:
            lift = True
        elif b == BUCKET_INFO:
            lift = (it.state == "unread" and within_hours(it.ts, hold, now))
        else:                                    # archive：不抬灯
            lift = False
        if lift and (best is None or PRIORITY.get(lv, 0) > PRIORITY.get(best, 0)):
            best = lv
    return best


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


def light_explain(posture, items, now=None, hours=WINDOW_HOURS, granary=None,
                  versions=None):
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
      `state`      **主灯**态（R0/L2/L1/L0；互斥）
      `label`      人话状态词
      `now_text`   「此刻」这一维的事实句（取守门模块**当场**给出的原话）
      `now_bad`    此刻这一维本身是不是就该报警
      `ledger_bad` 24 小时账这一维是不是有未处理项
      `reason`     拼好的原因句（**三元组**：主灯原因 ＋ 徽标原因 ＋ 待办提示）
      `badges`     ★ 0.51.0：**并存徽标** `[(键, 人话名, 原因)]`（研发中／缺粮）
      `action_count` / `info_count`  ★ 0.51.0：要处理件事数／待阅条数
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
    # ★★ 0.51.0：粮不再算"此刻不干净" —— 缺粮改为**并存徽标**（`badges()`），
    #   它不与主灯争"此刻"，也不该把主灯的原因句改写成粮的原因句。
    now_bad = bst not in (STATE_L0, STATE_DEV)

    # ---- 维度二：24 小时账（与灯同一批记录，绝不各数各的）----
    ledger_bad = bool(_window_open(items, hours, now))

    # ---- 维度三：**并存徽标**（研发中／缺粮）----
    #   ★ 与前两维**不争位**：主灯答"此刻什么情况"，徽标答"还有哪些并存态"。
    bs = badges(p.get("state"), granary, items, now, hours, versions)

    # ---- 计数（待办/待阅；与页面「要处理 N」同一把尺子）----
    n_act = count_groups([it for it in (items or [])
                          if bucket_of(it, now=now, hours=hours) == BUCKET_ACTION])
    n_info = len([it for it in (items or [])
                  if bucket_of(it, now=now, hours=hours) == BUCKET_INFO])

    # ---- 拼原因句：**主灯原因 ＋ 徽标原因 ＋ 待办提示**（三元组）----
    # ★ 不放件数式重复：件数归筛选条/顶部钻取（0.37.1 去重纪律）；这一句只答
    #   "为什么它是这个色、还有哪些并存态、有没有等你办的事"。
    _nt = now_text.rstrip("。；;.")
    parts = []
    if now_bad:
        parts.append("此刻：%s" % _nt)
    elif n_act > 0:
        # ★★ 立规（规格 v1.2 §2.3）：**action>0 时禁止说"此刻是好的"** ——
        #   只有你能解决的事还躺在待办里，灯却是绿的；说"是好的"会把
        #   待办读成没事（v1.1 探针 B5 记的正是这个缺陷）。
        parts.append("此刻没查出缺口（%s）" % _nt)
    else:
        parts.append("此刻是好的（%s）" % _nt)
    _bt = "；".join(r for _k, _n, r in bs)
    if _bt:
        parts.append("另外：%s" % _bt.rstrip("。；;."))
    if n_act > 0:
        parts.append("还有 %d 件事没处理" % n_act)
    elif n_info > 0:
        # ★ 窗口内未处理但都不需你动手（info 桶）⇒ 说"没处理"而**不说"事"**，
        #   并把"看过即知、不用动手"讲清（0.35.3「你知情即可」）。
        # ★★ 0.51.0（品质审查，2026-10-16）：括号里补**谁处理掉了** —— info 桶
        #   定义原话是「Antinel 自己已经处理掉了（拦下/自愈/状态变更）」，旧句
        #   只说"没处理"与桶定义自相矛盾（同一批记录两个说法）；括号自述口径
        #   后两个说法各归其位：没处理的是你，处理掉的是监理。
        #   「没处理」「看过即知」两个词被 0380 S11/S17 钉住，不许动。
        parts.append("还有 %d 条没处理（监理已自动处理，看过即知，不用动手）" % n_info)
    else:
        parts.append("24 小时里也没有等你处理的事")
    reason = "；".join(parts) + "。"
    return {"state": st, "label": label, "now_text": now_text,
            "now_bad": now_bad, "ledger_bad": ledger_bad, "reason": reason,
            "badges": bs, "action_count": n_act, "info_count": n_info}
