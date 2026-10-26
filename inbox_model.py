# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Antinel 监理 · 数据模型与状态聚合（唯一真源）。

★ 本模块只做**纯逻辑**：不写盘、不联网、不 import 产品其它模块。
  页面 / 托盘 / 通知 / 日报 / 导出，全部 import 本模块取口径 ——
  **判据不许二次实现**（本仓铁律）。

★ 两处**只读**例外（0.51.2 第二轮「人话化」加入，均有失败回落）：
  ① `rules/default.json`（随包发布的规则大白话表）—— 读一次、模块级缓存；
  ② 本机时区注册表（`TimeZoneKeyName`）—— 失败回落偏移名，再回落「当地时间」。
  两处都只影响**显示文案**，不影响任何判定口径 ⇒ 不破坏「纯逻辑」的本意
  （可测、无副作用）。判据断言一律打在**形状**上（有时区名、MM-DD HH:MM、
  无裸 ISO），不写死「北京时间」—— 海外机器上名字本来就不同。

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
from datetime import datetime, timedelta

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

# ---------------------------------------------------------------- 缺口态 ----
# ★★ 2026-10-22（40 格 · 人·判）：`state` 原来**兼职两件事** ——
#   ① 你知不知道（unread/read）；② 这件事还在不在（done/ignored）。
#   兼职的后果不是"显示难看"，是**一个没修的真实缺口会从待办里彻底消失**：
#   点一下"忽略"⇒ `bucket_of → ARCHIVE` ⇒ 它既不在待办、也不在任何计数里。
#   而"我决定先不管"和"这件事已经好了"是两句完全不同的话。
#
#   ⇒ 拆出 `gap_state`（缺口态），与 `state`（知情态）各管一件事：
#     · open   缺口没修，也没人说要不管 ⇒ 按原口径进待办/看一眼
#     · acked  缺口没修，**你声明过先不管** ⇒ 退出待办，但进"已知未修"台账，
#              并且**复核期一到会回来说一次**（不许变成永久黑洞）
#     · closed 已处置 ⇒ 归档
#     · ""     未声明（旧数据）⇒ 按四态派生：done→closed，ignored→acked，其余→open
#
#   ★ 为什么 `ignored` 派生为 `acked` 而不是 `closed`：历史"忽略"动作的语义
#     本来就是"我知道、我暂时不管"，从来没有说过"它好了"。把它读成 closed，
#     等于替用户宣布一个他没做过的结论。
#   ★ 为什么 acked 还要有复核期：没有复核期，忽略就是永久黑洞 ——
#     与"缺口不许消失"是同一句话的两面。14 天 = 一个迭代周期，
#     短到能记住，长到不打扰。
GAP_OPEN = "open"
GAP_ACKED = "acked"
GAP_CLOSED = "closed"
GAP_STATES = (GAP_OPEN, GAP_ACKED, GAP_CLOSED)
ACK_REVIEW_DAYS = 14



class InboxError(Exception):
    """Antinel 监理数据层的统一异常基类。"""


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
    # ★★ 0.53.0（T1.3）：首检提醒 —— 装好 ≥24h 仍没体检过 ⇒ 收件箱 1 条。
    #   **归 L1 不归 L2**：L2 在产品机制里＝`inbox_bubble.URGENT_LEVELS`＝
    #   置顶不自动消失的紧急提醒窗（0514 判据钉死），"还没体检"是温和提醒，
    #   弹紧急窗与设计 §29 意图冲突；L1「注意：知情即可」语义准确且走 toast。
    #   ★ 施工单字面写 L2，这条决策已记入施工单 v1.5 待创始人复核；
    #     若裁定改回 L2，改本行一处，TITLE/判据全部同源跟随。
    "exam_reminder": "L1",
}

# 人类可读标题（大白话，不许写成内部术语）。
# ★ 消费点：收件箱列表、托盘提示、通知标题 —— 不是"登记了没人查"的字段。
TITLE_OF_KIND = {
    "host_shield_tamper": "没守住：防护文件被改动",
    # ★ 0.37.1：标题里的「看门狗」改成「哨兵」—— 词表、托盘图标、归因文案
    #   都叫它「哨兵」，只有这两个标题还在说「看门狗」。
    #   后果不是"不好听"：同一条失守的**标题**写「看门狗没能启动」、
    #   紧挨着的**原因**却写「哨兵启动自检不符」⇒ 用户读到两个名字指同一个东西，
    #   只好停下判断它俩是不是一回事（创始人说的"违和感"）。
    "host_shield_spawn_failed": "没守住：监理没能启动",
    "host_shield_zone_locked": "没守住：安全区加锁失败",
    # ★ 0.35.3 修（创始人 2026-10-06「要处理 37 条」复盘时发现）：
    #   旧标题是「**已拦截**：越界动作被挡下」—— 但 `host_shield_breach` 描述的
    #   根本不是"拦住了"，而是"**有东西没被挡住**"（自启缺失 / 落点没人巡检 /
    #   钩子被拔）。把"缺口"说成"已拦截"，是**方向反了**的标签 ——
    #   创始人最恨的形状（用户照着标签做判断，会得出相反结论）。
    # ★ 0.53.1（创始人 2026-10-18）：去掉「防护有缺口」里的「缺口」—— 它不是态名，
    #   而账本曾把同一个 R0 叫「防护缺口／缺口」。标题已用「失守：」打头，后半句
    #   只需说清"是什么事"，不该再引入一个会被读成第四种态的词。
    "host_shield_breach": "没守住：有东西没被挡住",
    "host_shield_revived": "提醒：防护已恢复",
    "host_shield_changed": "提醒：防护设置被改动",
    "host_shield_dev_drift": "提醒：研发迭代中（代码与登记的那份不符）",
    "credits_low": "缺粮：积分余额偏低",
    "tool_call_blocked": "挡下：危险操作没有执行",
    # ★ 0.53.0（T1.3）：首检提醒标题。S1/S3 两种事由的**具体文案**走
    #   host_shield.record 的 reason（subkind=never/overdue 区分），
    #   这里只给默认标题（TITLE_OF_TOPIC 未登记 subkind 时的回落）。
    "exam_reminder": "提醒：还没做过体检",
}

#: ★ 0.35.3：按**事由**（链记录 `subkind`）给更准的标题；没有则回落到 `TITLE_OF_KIND`。
#:   为什么要它：同一个 kind 下的事由差别很大 ——
#:   「开机不会自动防护」和「有落点没人巡检」都是 `host_shield_breach`，
#:   但用户该做的事完全不同（前者装自启，后者做裁决）。
TITLE_OF_TOPIC = {
    "autostart_missing": "没守住：开机不会自动防护（要你装一次自启）",
    "spawn_failed": "没守住：监理没能启动",
    # ★★ 0.40.0（A5）：按**病因**分，不再按"哪个字段"分 ——
    #   `self_check` / `registry` 都是「代码/登记表与 manifest 不符」⇒ **一件事**（code_drift）；
    #   `enabled` / `state` 都是「安全状态字段在运行期漂移、哨兵已回写恢复」⇒ **另一件事**（state_drift）。
    #   改前：前者被拆成两行、后者三因挤一行（归并键 `(kind, topic, level)`，后三者 topic 为空）。
    #   ★ 旧 `self_check` 词条**保留**：链 append-only，历史记录（实测 47 条）仍是那个 subkind。
    "code_drift": "没守住：防护文件被改动（代码与登记的那份不符）",
    "state_drift": "没守住：防护文件被改动（状态被改，已自动恢复）",
    "self_check": "没守住：防护文件被改动（要你核对/重装）",
    # ★★ 0.40.0（A8）：`zone_locked` 兼表成败 —— **成功**那条不能借用 kind 标题
    #   （kind 标题写着"没守住：安全区加锁失败"），否则一条成功被读成失守。
    "zone_ok": "提醒：安全区已上锁（区内防篡改）",
    "zone_lock_failed": "没守住：安全区加锁失败",
}

#: 首检提醒判定常量（设计 v1.11 §29.1；判定本体见 `exam_state`）。
EXAM_GRACE_HOURS = 24         #: 装好不满一天不催 —— 装完给时间，不追杀
EXAM_STALE_DAYS = 30          #: 体检过但超过 30 天 ⇒ 再提醒一次


def exam_state(hub_dir=None, now=None):
    """首检提醒判定：**设计 v1.11 §29.1 四态状态机的唯一实现**（放本模块，不放页面）。

    返回 `(state, info)`：

    · `S0` 三链全无且装好 < 24h —— **不出**（装完给时间）
    · `S1` 三链全无且装好 ≥ 24h —— **出 1 条**（去重靠链，见 `host_shield.exam_reminder_check`）
    · `S2` 三链任一命中且 ≤ 30 天 —— **不出**
    · `S3` 三链任一命中但 > 30 天 —— **出 1 条**（同 S1 去重）

    三链（设计 §28.5，按优先级；都是**本机留下过的痕迹**）：
      ① `<hub>/health/audit-*.json` —— 体检存档（控制台/CLI/网站桥一都落这里）
      ② `<hub>/findings.json`（`host-scan --arm`）／`<hub>/survey.json`（`--survey`）
      ③ 用户粘进来的回执（桥二）—— **无文件形态，本函数不判**：它的场景是
         「在网站上自查过」，本机无痕迹；本机跑过必有 ①②。缺 ③ 的方向是
         **可能多催一次**（另一端「催了但人家查过」由 ①② 挡住）——
         误催有「忽略」出口，漏催没有，方向取保守是对的。

    「装好时间」锚＝hub 注册表里**最早**的 `registered_at`（安装即入册，
      `scripts/install.py` 第 6 步经 `hub.register` 写入）—— 安装事实，
      不是「安装时间早于某时刻」式推断（§28.5 禁的是那个）。
      取不到 ⇒ 判 `S0`：无法判定安装时长就不催（催用户是动作，方向取保守）。

    `now` 可注入（判据/测试用；缺省＝此刻）。
    """
    import os
    from datetime import datetime
    if now is None:
        now = datetime.now().astimezone()
    hub = hub_dir
    if hub is None:
        try:
            import host_shield as _hs
            hub = _hs._hub_dir()
        except Exception:                                   # noqa: BLE001
            hub = ""
    info = {"installed_at": "", "last_exam_at": "", "days_installed": None,
            "days_since_exam": None}
    if not hub:
        return "S0", info

    # ── 三链：任一命中 ⇒ 体检过；取链①最新一份的时间作「上次体检」 ──
    try:
        import host_shield as _hs
        reports = _hs.health_reports()
    except Exception:                                       # noqa: BLE001
        reports = []
    examined = bool(reports)
    if examined:
        # ★ 文件名格式 `audit-%Y%m%d-%H%M%S-%03d.json`（定宽后缀，见
        #   `host_shield.save_health_report`）⇒ 剥前缀/后缀会留下 `-000`，
        #   必须用正则只取时间两段（第一版直接切片 ⇒ strptime 失败 ⇒
        #   S3「超 30 天」永远判不出来，被探针当场抓到）。
        _m = re.match(r"audit-(\d{8}-\d{6})", os.path.basename(reports[-1]))
        if _m:
            info["last_exam_at"] = _m.group(1)
    if not examined:
        for rel in ("findings.json", "survey.json"):
            if os.path.isfile(os.path.join(hub, rel)):
                examined = True
                break

    # ── 装好时间：注册表里最早的 registered_at ──
    try:
        import hub as _hub
        reg = _hub.load_registry()
        stamps = [str(p.get("registered_at") or "") for p in (reg.get("projects") or [])]
        stamps = [s for s in stamps if s]
        if stamps:
            first = min(stamps)
            info["installed_at"] = first
            try:
                t0 = datetime.fromisoformat(first)
                if t0.tzinfo is None:
                    t0 = t0.astimezone()
                info["days_installed"] = (now - t0).total_seconds() / 3600.0
            except ValueError:
                pass
    except Exception:                                       # noqa: BLE001
        pass

    if info["days_installed"] is None:
        return "S0", info            # 判不出装了多久 ⇒ 不催（保守方向）

    if examined:
        # 体检过：算「距上次体检」——链①有时间；链②（findings/survey）没有
        # 可靠时间字段，只在 S2 边界内用（不催），不算天数。
        if info["last_exam_at"]:
            try:
                t1 = datetime.strptime(info["last_exam_at"], "%Y%m%d-%H%M%S")
                t1 = t1.replace(tzinfo=now.tzinfo)
                info["days_since_exam"] = (now - t1).total_seconds() / 86400.0
            except ValueError:
                pass
        if info["days_since_exam"] is not None and info["days_since_exam"] > EXAM_STALE_DAYS:
            return "S3", info
        return "S2", info

    if info["days_installed"] >= EXAM_GRACE_HOURS:
        return "S1", info
    return "S0", info


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

    ★★ 2026-10-22（40 格 · 人·判）：分档由**缺口态**决定，不再由四态一刀切。
      `ignored` 以前等同于"归档"，于是"我看了但没修"和"已经修好"在账面上
      长得一模一样 —— 一个真实缺口就这样从待办消失（且任何计数都数不到）。
      现在：`acked` 退出待办但进 `unrepaired_count()` 台账，复核期一到回待办。
    """
    gs = gap_state_of(item)
    if gs == GAP_CLOSED:
        return BUCKET_ARCHIVE
    if gs == GAP_ACKED:
        # 你声明过"先不管" ⇒ 退出待办；但缺口没修，复核期一到回来说一次。
        # ★ 复核期只对"本来就在待办里"的记录有意义：窗口外/无后果/不用本人动手的，
        #   到期也不需要打扰（否则会把一堆历史归档重新翻上来）。
        if ack_expired(item, now) and within_hours(item.ts, hours, now) \
                and has_consequence(item) and needs_owner(item):
            return BUCKET_ACTION
        return BUCKET_ARCHIVE
    if not within_hours(item.ts, hours, now):
        return BUCKET_ARCHIVE
    if not has_consequence(item):
        return BUCKET_INFO
    if not needs_owner(item):
        return BUCKET_INFO
    return BUCKET_ACTION


def gap_state_of(item):
    """一条记录的**缺口态**（★ 唯一实现：分档、台账、页面都调它）。

    · `open`   没修、也没人说要不管
    · `acked`  没修，你说过先不管（有复核期）
    · `closed` 已处置
    · 字段为空（旧数据）⇒ 从四态派生，见上方 `GAP_*` 那段注释。
    """
    g = getattr(item, "gap_state", "") or ""
    if g in GAP_STATES:
        return g
    st = getattr(item, "state", "") or ""
    if st == "done":
        return GAP_CLOSED
    if st == "ignored":
        return GAP_ACKED
    return GAP_OPEN


def ack_expired(item, now=None, days=ACK_REVIEW_DAYS):
    """"先不管"是否已过复核期。**不知道什么时候忽略的 ⇒ 不催**（宁可少打扰）。"""
    d = _parse_ts(getattr(item, "closed_at", "") or "")
    if d is None:
        return False
    now = now or datetime.now().astimezone()
    return (now - d).total_seconds() >= days * 86400


def unrepaired_count(items, now=None, hours=None):
    """「已知未修」台账：你说过先不管、但它其实还坏着的条数。

    返回 `{"n":…, "due":…, "oldest_ack_days":…|None,
           "oldest_record_days":…|None, "kinds":[(kind, n)…]}`。

    ★★ 为什么要有它（40 格 · 人·判）：忽略之后记录从待办消失，是对的
      （尊重你的决定）；但**从账面上也消失，是错的** —— 那就等于
      "我点了一下，缺口就好了"。这条台账是那句话的反面证据。
    ★ `due` ＝ 已过复核期、本该重新进待办的条数。它必须能和 `n` 分开看：
      `n=5, due=0` 是"都还在你设定的宽限里"，`n=5, due=5` 是"你不管了但它还在"。
    ★ 口径与 `bucket_of` 同源（都调 `gap_state_of` / `ack_expired`），
      **不许在本函数里另写一套"算不算未修"的规则**。

    ★★ 0.55.0（复核 F7）：`oldest_record_days` 是**给判据用的第二基准**，
      **生产侧没有任何消费点**（页面只用 `oldest_ack_days`，见 `inbox_server._unrepaired_line`）。
      留着它的唯一理由：让 `P31b` 能证明"两个基准确实不同"，从而守住
      "页面不许把记录年龄当成搁置年龄"。**不要因为"没人读"删掉它** —— 删了那条判据就失明。
    """
    now = now or datetime.now().astimezone()
    acked = [it for it in items if gap_state_of(it) == GAP_ACKED]
    if hours is not None:
        acked = [it for it in acked if within_hours(it.ts, hours, now)]
    due = sum(1 for it in acked if ack_expired(it, now))
    # ★★ 两个基准必须**各自具名**（A7）：`ts` 是"记录发生的时间"，
    #   `closed_at` 是"你说先不管的时间"。一句话里并排给两个不同基准的"天前"，
    #   读者会以为二者可比（`n=5, 最早 30 天前, 其中 4 条已过 14 天复核期`——
    #   30 天是记录的年龄，14 天是搁置的年龄，两个数根本不在同一条轴上）。
    #   页面只用 `oldest_ack_days`：它与 `due` 同基准，才能和"复核期"一起读。
    rec_ages, ack_ages = [], []
    for it in acked:
        d = _parse_ts(it.ts)
        if d is not None:
            rec_ages.append(max(0.0, (now - d).total_seconds()) / 86400.0)
        a = _parse_ts(getattr(it, "closed_at", "") or "")
        if a is not None:
            ack_ages.append(max(0.0, (now - a).total_seconds()) / 86400.0)
    by = {}
    for it in acked:
        by[it.kind] = by.get(it.kind, 0) + 1
    return {"n": len(acked), "due": due,
            "oldest_ack_days": int(max(ack_ages)) if ack_ages else None,
            "oldest_record_days": int(max(rec_ages)) if rec_ages else None,
            "kinds": sorted(by.items(), key=lambda kv: -kv[1])}



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
    "host_shield_tamper": "提醒：防护设置被改、已自动恢复",
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
        return TITLE_OF_TOPIC.get("zone_ok") or "提醒：安全区已上锁（区内防篡改）"
    # ★ 兜底（不许静默留着「失守」二字）：没登记专用文案 ⇒ 把方向改过来。
    return TITLE_WHEN_DEMOTED.get(kind) or (
        "提醒：" + base[len("没守住："):] if base.startswith("没守住：") else base)


#: ★★ 0.43.0：**用户可见文本**的去 markdown 化（**唯一实现**）。
#:   为什么必须有：审计链 append-only ⇒ 机器上躺着各旧版本写下的记录，
#:   其中混着 markdown 加粗（实测 `zone_locked` 文案里的 `**不等于**`）。
#:   0.42.0 只在**网页**两条渲染路径做了免疫（`inbox_server._vis`），
#:   **命令行**那条路漏了 ⇒ `inbox_cli.py list` 照样吐裸星号（2026-10-10 实测）。
#:   ⇒ 收进这里，网页与命令行共用一份（不许各写一份 —— 那是第二套口径）。
_MD_STARS = re.compile(r"\*+")


def visible_text(s):
    """**用户可见文本**的出口：去掉 markdown 星号 ＋ 机器腔人话化
    （★ 唯一实现，纯文本版）。

    ★ 只改写侧文案不够（旧记录改不了）⇒ 读侧免疫，与 0.41.0 修 `is_denied()`
      同一条思路（换 oracle，而不是把某一次的结果改对）。
    ★ 口径：`**X**` → `X`（删掉加粗标记，语义不变）。
    ★★ 0.51.2（创始人 2026-10-17「都在说鸟语」）：在去星号之后，
      **再过一遍 `humanize()`** —— 这是读侧对**机器腔**的免疫：
      审计链 append-only，用户机上躺着各旧版本写下的 `pid=` / `mode=` /
      `manifest` 等机器串，光改写侧治不了它们的旧记录。
      ⇒ 收进这里，网页（`inbox_server._vis`）与命令行（`inbox_cli`）共用一份。
    """
    return humanize(_MD_STARS.sub("", "" if s is None else str(s)))


# --------------------------------------------------------------------------
# ★★ 0.51.2：机器腔 → 人话（**唯一真源**）
#
# 创始人 2026-10-17 三张截图原话：「都在说鸟语，都改成看得懂的人话」。
#
# 口径（为什么是**两张表**而不是一张）：
#   ① `_TERM_MAP` —— **裸术语**（词级替换，整串里换词，顺序无关、可叠加）；
#      例：`manifest` → 「登记的那份」、`哈希` → 「指纹」。
#   ② `_KV_MAP`   —— **键值对**（正则替换，把 `pid=123` 这种序列化碎片
#      连字段名一起换成人话）。
#   ⇒ 分开的原因：术语是"换词"，键值对是"换结构"，两者的匹配方式不同。
#     合一张表会写成"正则里塞词"，难读也难验。
#
# ★ 三条纪律（写在这里是因为**这里是唯一真源**，判据也读这张表）：
#   1. **顺序敏感**：长模式在前（否则 `state 文件` 会被 `state` 先吃掉半截）。
#   2. **不许编**：认不出的键值对**原样保留**（fail-loud），绝不猜一个中文。
#   3. **术语表词条不动**：`glossary.TERMS` 是"解释层"（点开才看），
#      本表是"主行层"（扫一眼就要懂）—— 两层各司其职，不互相改写。
# --------------------------------------------------------------------------

#: 裸术语 → 人话（长模式在前）。
_TERM_MAP = [
    ("state 文件", "防护设置文件"),
    ("manifest", "登记的那份"),
    ("登记表", "登记清单"),
    ("哈希", "指纹"),
    ("链记录", "安全记录"),
    ("链上", "安全记录里"),
    ("基线", "布防时记下的样子"),
    ("子类型", "事由"),
    # ★ 0.53.0 T4：**退休词收尾**。0.53.0 起这个角色在页面上只叫「监理」，
    #   但历史记录里写的是「哨兵」—— 同一件事两个名字，读者会以为是两套东西。
    #   词级替换放这里，旧记录与新记录就此同词。
    ("哨兵", "监理"),
]

#: ★★ **不许被替换的"代码样"片段**（2026-10-17 实测踩到）：
#:   `_tools_034/_resign_manifest.py` 里的 `manifest` 被词级替换成
#:   `_resign_出厂登记.py` —— 把**文件名**改坏了。这正是创始人要防的
#:   「避免引入新问题」。⇒ 替换前先把这些片段**抠出来占位**，替换完再放回。
#:   判定口径（任一命中即算代码样）：含路径分隔符 `/` 或 `\`、含扩展名
#:   `.py/.json/.jsonl/.md/.exe/.cmd`、被反引号包裹、或含 `__`。
_CODEY_RE = re.compile(
    r"`[^`]*`"                                  # 反引号包裹
    r"|[A-Za-z0-9_.\-]*[\\/][A-Za-z0-9_.\-\\/]*"  # 含路径分隔符
    r"|[A-Za-z0-9_\-]+\.(?:py|json|jsonl|md|exe|cmd|bat|ps1|txt|log|cfg|ini)\b"  # 带扩展名
    r"|[A-Za-z0-9_]*__[A-Za-z0-9_]*"            # 双下划线标识符
)


def _protect_codey(t):
    """把"代码样"片段抠成占位符，返回 (占位后的串, 还原表)。"""
    stash = []

    def _stash(m):
        stash.append(m.group(0))
        return "\x00%d\x00" % (len(stash) - 1)

    return _CODEY_RE.sub(_stash, t), stash


def _restore_codey(t, stash):
    for i, s in enumerate(stash):
        t = t.replace("\x00%d\x00" % i, s)
    return t

#: 键值对 → 人话（字段名换成中文词，值原样保留）。
#: ★ 值是**机器枚举**（detached / hook-parametric / self-check-failed …）
#:   也一并换；认不出的值原样留（见 `_MODE_TEXT` / `_CAUSE_TEXT`）。
_KV_RE = re.compile(
    r"(?<![A-Za-z_])"
    r"(pid|mode|cause|subkind|reason|kind|topic|enabled|severity)="
    r"([^\s，。；）)、,]+)")
_KV_MAP = {
    "pid": "进程号",
    "mode": "拉起方式：",
    "cause": "触发",
    "subkind": "事由",
    "reason": "原因",
    "kind": "类型",
    "topic": "事由",
    "enabled": "开关",
    "severity": "严重度",
}

#: 机器枚举值 → 人话。认不出的原样保留（fail-loud，不编）。
_MODE_TEXT = {
    "detached+breakaway": "后台独立拉起并脱离子进程组",
    "detached": "后台独立拉起",
    "self-check-failed": "自检没通过",
    "already-running": "已经在运行",
    "script-missing": "找不到启动脚本",
    "spawn-failed": "拉起命令执行失败",
    "unsupported-platform": "此系统不支持",
}
_CAUSE_TEXT = {
    "hook-paramedic": "钩子机制自动触发",
    "hook-parametric": "钩子机制自动触发",
    "console": "控制台",
    "manual": "手动操作",
    "guard": "巡检",
    "self-check": "自检",
}

#: ★★ **裸枚举**兜底（0.51.2）：有些**旧记录**把枚举值**直接嵌在句子里**
#:   （不是 `key=value` 形态），例如「由 hook-paramedic 重新拉起」「mode=
#:   self-check-failed: …」被别的正则抠出来后剩下裸枚举。
#:   ⇒ 这些词在任何位置出现都换成人话（词级，长词在前）。
#:   ★ 键一律带"业务特征"，不用短词（避免误伤英文正文）。
_BARE_ENUM_TEXT = [
    ("detached+breakaway", "后台独立拉起并脱离子进程组"),
    ("self-check-failed", "自检没通过"),
    ("hook-paramedic", "钩子机制自动触发"),
    ("hook-parametric", "钩子机制自动触发"),
    ("already-running", "已经在运行"),
    ("script-missing", "找不到启动脚本"),
    ("unsupported-platform", "此系统不支持"),
]

#: **短语级**固定搭配（键值对换完之后再过一遍，修接缝）。
#: ★ 为什么需要：`旧 pid=` → `旧 进程号` 的接缝空格人读起来硌眼，
#:   这是"词级替换"必然留下的碎屑 ⇒ 用短语表抹平，而不是让渲染层去猜。
_PHRASE_MAP = [
    ("旧 进程号", "旧进程号"),
    ("新 进程号", "新进程号"),
    # ★ 0.53.0 T4：历史记录的残句。这些串都出自旧版写侧文案，
    #   记录已经写进审计链、改不回来，只能在**读给人看**这一步收口。
    ("监理死亡", "监理进程已停止"),
    ("门闸无人值守", "当时没人值守"),
    ("现在没人值守", "当时没人值守"),
    ("旧监理已死", "旧进程已死"),
    ("在岗名片记的启动时刻", "登记时记下的启动时刻"),
    ("开关未知", "开关值读不出来"),
    ("（armed）", "（已布防）"),
    ("出网由 net_mode 把闸", "出网也受限制"),
]


def _kv_human(m):
    """一个 `字段=值` → 人话。

    ★ 值的**枚举翻译只对"整值相等"生效**（`val` 完全等于 `detached` 才翻）；
      `self-check-failed: …` 这类"值里还带冒号说明"的，只翻前缀、保留尾巴。
    ★ 值里可能是 `None`（旧记录）⇒ 说成「未知」，不说 `None` 这个 Python 字。
    """
    key, val = m.group(1), m.group(2)
    label = _KV_MAP.get(key, key)
    v = val
    if key == "mode":
        v = _enum_text(val, _MODE_TEXT)
    elif key == "cause":
        v = _enum_text(val, _CAUSE_TEXT)
    if v == "None":
        v = "未知"
    return "%s %s" % (label, v)


def _enum_text(val, table):
    """枚举值 → 人话：整值命中就换；带尾巴（`x: y`）就换前缀、留尾巴。"""
    if val in table:
        return table[val]
    if ":" in val:
        head, _, tail = val.partition(":")
        if head in table:
            return "%s：%s" % (table[head], tail.strip())
    return val


def humanize(s):
    """机器腔 → 人话（★ 唯一实现）。输入输出都是普通字符串。

    ★ 幂等：已人话化的串再过一遍不变（判据 W-SPK3 钉这条）。
    ★ 顺序：**先键值对、后术语** —— 键值对替换会引入中文（如「进程号」），
      中文不会再被术语表误伤；反过来（先术语）会把 `state 文件` 里的
      `state` 当成键值对键名去匹配（虽然 `state=` 才匹配，但先做更稳）。
    ★★ **代码样片段受保护**（0.51.2 实测踩到）：文件名 `_resign_manifest.py`
      里的 `manifest` 不能被换成中文（会把文件名改坏）。⇒ 替换前把
      `_CODEY_RE` 命中的片段抠成占位符，替换完再放回（见 `_protect_codey`）。
    ★ 收尾**合并多余空格**：词级替换会在「旧 pid=123」→「旧 进程号 123」
      这样的接缝处留出多余空格，人读起来硌眼 ⇒ 统一压成单空格并
      修掉标点前后的空格。
    """
    if s is None:
        return ""
    t = str(s)
    if not t:
        return t
    # 1) 抠出代码样片段（文件名/路径/标识符/反引号内容）
    t, stash = _protect_codey(t)
    # 2) 键值对 → 人话
    t = _KV_RE.sub(_kv_human, t)
    # 2b) ★ 0.53.0 T4：**先把接缝压掉，再做短语表** —— 旧版把压空格放在
    #     最后，于是「开关 未知」这种 KV 接缝要到下一遍才被短语表认出来
    #     （实测 26 条不幂等：第一遍出「开关未知」，第二遍才换成
    #     「开关值读不出来」）。幂等是这个函数的钉子属性（W-SPK3），
    #     接缝必须在**同一遍内**清掉。
    t = re.sub(r"(?<=[\u4e00-\u9fff]) +(?=[\u4e00-\u9fff])", "", t)
    # 3) 裸术语 → 人话
    for a, b in _TERM_MAP:
        if a in t:
            t = t.replace(a, b)
    # 3b) 裸枚举 → 人话（旧记录里枚举直接嵌在句子里）
    for a, b in _BARE_ENUM_TEXT:
        if a in t:
            t = t.replace(a, b)
    for a, b in _PHRASE_MAP:
        if a in t:
            t = t.replace(a, b)
    # 3c) ★ 0.53.0 T4：**残句收尾**（历史记录专用，见 `_PHRASE_MAP` 注释）
    #    · 「进程号 24928 的进程号」—— `pid=` 被翻成「进程号」后与后半句的
    #      「的进程号」叠在一起，同一行同一个词出现两次。
    #    · 裸 `None`（已经写成「旧进程号 None」这种中文夹 Python 字的形状）——
    #      没有值的字段就把**整段括号**摘掉；摘不掉的（如「实际值（None）」）
    #      说成「未知」，绝不让 Python 的字上屏。
    t = re.sub(r"(进程号 \d+)\s*的进程号\s*", r"\1 ", t)
    t = re.sub(r"[（(]旧进程号 (?:None|未知)[）)]", "", t)
    t = re.sub(r"(?<![A-Za-z_])None(?![A-Za-z_])", "未知", t)
    # 4) 接缝整理：重复空格 → 单空格；中文标点/右括号前后不留空格；
    #    **两个中文字之间的空格**全去掉（词级替换留下的接缝）。
    t = re.sub(r"[ \t]{2,}", " ", t)
    t = re.sub(r"\s+([，。；：、）】》])", r"\1", t)
    t = re.sub(r"([（【《])\s+", r"\1", t)
    t = re.sub(r"([，。；：、])\s+", r"\1", t)
    t = re.sub(r"(?<=[\u4e00-\u9fff]) +(?=[\u4e00-\u9fff])", "", t)
    # ★★ 0.53.0 T4 教训：**这里曾加过一条「数字与汉字之间不留空格」**，
    #   结果把「WorkBuddy 2 条」压成「2条」—— 数字与量词之间的空格是
    #   排版约定，不是接缝。⇒ 通用规则只做汉字—汉字；数字—汉字的接缝
    #   由具体的去重正则自己处理（它把尾随空格补回来）。
    # 5) 放回代码样片段
    return _restore_codey(t, stash)


def alert_id(ts, kind, reason):
    """稳定 ID：sha1(ts|kind|reason)[:8]。

    同一事件重放得到同一 ID ⇒ 追加是**幂等**的（重放不会造出重复条目）。
    """
    raw = "%s|%s|%s" % (ts, kind, reason)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]


# ══════════════════════════════════════════════════════════════════════
# 0.51.2 第二轮「人话化」（创始人 2026-10-17 四张截图裁定）：
# 时区命名 ＋ 详情行（第二行）重做
# ══════════════════════════════════════════════════════════════════════
# 创始人原话：
#   「时间的时区是北京时间，是吧？？？？你直接写北京时间不行吗？？？？？？」
#   「因为用户可能在海外，比如洛杉矶的就写美西时间，波士顿的就写美东时间，
#    等等，这块需要专门设计。一切围绕用户体验。」
#   「规则编号保留一次。一句大白话解释清楚，能结合具体情形场景是最好的体验。」
#   「亮文件名。如果文件很多，亮三个加上『等文件』。」
#   「什么狗屁核对号，去掉！！！！！！」

#: Windows 时区键名 → 人话（唯一真源：注册表 `TimeZoneKeyName`）。
#: ★ 为什么按**键名**而不是按偏移：偏移撞车（+8 有北京/新加坡/珀斯；-5 有
#:   美东/哥伦比亚/秘鲁）⇒ 把用户的时区叫成别的城市的名，比不给名字更糟。
#:   键名是系统自己认的辖区，不撞车。
#: ★ 夏令时不区分：美西夏令时仍叫「美西时间」（通行说法），不按季节改名。
_TZ_KEY_ZH = {
    "China Standard Time": "北京时间",
    "Pacific Standard Time": "美西时间",
    "Eastern Standard Time": "美东时间",
    "Central Standard Time": "美中时间",
    "Mountain Standard Time": "美山区时间",
    "US Mountain Standard Time": "美山区时间",
    "GMT Standard Time": "格林尼治时间",
    "Tokyo Standard Time": "东京时间",
    "Korea Standard Time": "首尔时间",
    "Singapore Standard Time": "新加坡时间",
    "India Standard Time": "印度时间",
    "W. Europe Standard Time": "中欧时间",
    "Romance Standard Time": "中欧时间",
    "Central Europe Standard Time": "中欧时间",
    "AUS Eastern Standard Time": "澳洲东部时间",
    "E. Australia Standard Time": "澳洲东部时间",
    "New Zealand Standard Time": "新西兰时间",
    "SE Asia Standard Time": "中南半岛时间",
    "Canada Central Standard Time": "加拿大中部时间",
}

#: 偏移回落表（拿不到注册表键名时用；只收不撞车的常用偏移）。
#: ±7 既是美西夏令时也是山区标准时 ⇒ 都归「美西时间」可能误标山区用户 ——
#: 回落路径本就是降级，宁可少猜：只收 8/9/0 与美东两档（最常见的海外华人分布）。
_TZ_OFFSET_ZH = {
    8: "北京时间", 9: "东京时间", 0: "格林尼治时间",
    -8: "美西时间", -7: "美西时间", -5: "美东时间", -4: "美东时间",
}


def tz_name():
    """本机时区的人话名（北京时间/美西时间/美东时间/…）。**唯一实现**。

    取值链：注册表 `TimeZoneKeyName` → 键名映射表 → 偏移映射表 →
    「UTC±N」→「当地时间」。任一步失败都不抛，只降级。
    """
    try:
        import winreg
        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation") as k:
            key = str(winreg.QueryValueEx(k, "TimeZoneKeyName")[0])
        name = _TZ_KEY_ZH.get(key)
        if name:
            return name
    except Exception:                                   # noqa: BLE001
        pass
    try:
        off = datetime.now().astimezone().utcoffset()
        if off is not None:
            h = int(round(off.total_seconds() / 3600))
            name = _TZ_OFFSET_ZH.get(h)
            if name:
                return name
            return "UTC%+d" % h
    except Exception:                                   # noqa: BLE001
        pass
    return "当地时间"


def ts_label(s):
    """ISO 时间戳 → 人话时间：`北京时间 10-17 09:23`（**唯一实现**）。

    ★ 口径：`fromisoformat` 解析后 `astimezone()` 落到**本机**时区 ——
      记录里带任意偏移（旧机器/跨时区机器写的）都按本机时区读，不按
      记录里的偏移原样显示（那样等于让用户心算时差）。
    ★ 解析失败回落字符串切片（旧 `_ts_hm` 口径：不编造、不截半）。
    ★ 返回形状恒为「<时区名> MM-DD HH:MM」——判据断言打在这个形状上，
      不写死具体城市名（海外机器名字本来就不同）。
    """
    t = "" if s is None else str(s)
    try:
        dt = datetime.fromisoformat(t).astimezone()
        return "%s %s" % (tz_name(), dt.strftime("%m-%d %H:%M"))
    except Exception:                                   # noqa: BLE001
        body = t[5:16].replace("T", " ") if len(t) >= 16 else t
        return "%s %s" % (tz_name(), body) if body else tz_name()


#: 规则编号 → 一句大白话（`description_zh` 首句，唯一真源：随包发布的
#: `rules/default.json`）。**为什么读表而不是在页面另写一份**：规则表是
#: 产品的口径，页面写第二份就会漂移（本仓「同一事实两处实现」的标准形状）。
_RULE_DESC = None


def _rule_desc(rule_id):
    """规则编号 → 大白话首句（读不到表/没这条 ⇒ `""`，调用方回落）。"""
    global _RULE_DESC
    if _RULE_DESC is None:
        table = {}
        try:
            import json
            import os
            p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "rules", "default.json")
            with open(p, encoding="utf-8") as fh:
                for r in (json.load(fh).get("rules") or []):
                    rid = str(r.get("id") or "")
                    desc = str(r.get("description_zh") or "").strip()
                    #: 首句：分号/全角括号切开取第一段（长描述的补充情形留给
                    #: 规则表本身，详情行不放说明书）。
                    head = re.split(r"[；（(]", desc)[0].strip()
                    if rid and head:
                        table[rid] = head
        except Exception:                               # noqa: BLE001
            table = {}
        _RULE_DESC = table
    return _RULE_DESC.get(str(rule_id or ""), "")


#: 命令文本里抠「目标文件名」的扩展名白名单（裸文件名必须有已知扩展名才算
#: 目标 —— 否则 `v1.2`、`127.0.0.1`、`os.remove` 都会被当成文件）。
_FILE_EXTS = frozenset((
    "py", "json", "jsonl", "md", "txt", "log", "cfg", "ini", "csv", "xml",
    "yaml", "yml", "ps1", "bat", "cmd", "sh", "db", "sqlite", "sqlite3",
    "env", "toml", "lock", "pem", "key", "crt", "zip", "tar", "gz", "png",
    "jpg", "jpeg", "html", "htm", "js", "ts", "whl",
))

#: 最多亮几个目标（创始人：亮三个，多了加「等文件」）。
_MAX_TARGETS = 3

#: 详情行（第二行）的**行级字数上限**——判据 W-SPK8 与本函数共用这一个数
#: （两处各写一个 90 就是又一处「同页两个口径」）。
#: 0.52.0 实测：合成夹具全部 ≤63 字，而真实记录里三目标＋规则大白话拼到 94 字
#: ⇒ 上限必须**反过来约束目标个数**，不能只在判据里事后数。
_META_MAX = 90


def _ext_ok(tok):
    base = tok.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in base:
        return False
    return base.rsplit(".", 1)[-1].lower() in _FILE_EXTS


#: 不产目标的段动词：这些是**读**或**上下文**，段里的路径不是「会被动的文件」。
#: 0.52.0 实测（创始人截图三行）：`grep` 的正则片段、`cd` 的目录、`python -c`
#: 的代码体全被当成目标 ⇒ 详情行出现「目标 def _item_html\|def _group_html\|…」。
#: 宁可少说一个目标，也不许说错一个目标（说错＝把正则当文件，读者无从判断真假）。
_NO_TARGET_VERBS = frozenset((
    "cd", "pushd", "popd", "set", "export", "setx",
    "grep", "rg", "ag", "find", "fd", "ls", "dir", "tree", "stat", "wc",
    "cat", "type", "more", "less", "head", "tail", "sed", "awk", "sort",
    "echo", "printf", "which", "where", "tasklist", "netstat", "curl", "wget",
    "git", "npm", "pip", "pip3", "node", "python", "pythonw", "py",
    "powershell", "pwsh", "bash", "sh", "cmd",
))

#: 目标串里绝不许出现的字符（正则/通配/变量/赋值/重定向/引号/注释）。
#: 真实文件名极少含这些；含了几乎一定是命令片段而非文件（`command=`、`a\|b`）。
_TARGET_BAD_CHARS = "|*?$<>{}=`\"'#"


def _plausible(tok):
    """这个串**像不像**一个文件/目录（合法性，不看角色）。"""
    if not tok or len(tok) > 120:
        return False
    if tok.startswith("//") or "://" in tok:              # URL 不是文件
        return False
    if any(ch in tok for ch in _TARGET_BAD_CHARS):
        return False
    if tok.endswith("\\") or tok.endswith("/"):           # 悬空分隔符
        return False
    if re.search(r'\\[\s"\'\\]', tok):                    # 转义残尾（`seg cost\`）
        return False
    if "(" in tok or ")" in tok:
        # 半角括号只在成对且不贴结尾时算文件名（`attribute(` 是正则残片；
        # `report (1).py` 这类真实文件名仍放行）。
        if tok.count("(") != tok.count(")") or tok.rstrip().endswith(")"):
            return False
    return ("/" in tok or "\\" in tok) or _ext_ok(tok)


def _short_name(tok):
    """只亮文件名（创始人裁定）：`C:/a/b/Startup` → `Startup`。"""
    base = tok.replace("\\", "/").rsplit("/", 1)[-1]
    return base or tok


def _cmd_segments(text):
    """按**引号外**的 `&&`/`||`/`;`/`|`/换行 切段（引号内的分隔符不算）。"""
    segs, buf, quote = [], [], ""
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            elif ch == "\\" and i + 1 < n:
                buf.append(text[i + 1])
                i += 1
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in ";|\n":
            segs.append("".join(buf))
            buf = []
            i += 1
            continue
        if ch == "&" and i + 1 < n and text[i + 1] == "&":
            segs.append("".join(buf))
            buf = []
            i += 2
            continue
        buf.append(ch)
        i += 1
    segs.append("".join(buf))
    return [s for s in segs if s.strip()]


def _seg_verb(seg):
    """段的动词：首个 token（跳过 `VAR=value` 前缀），去路径、去 .exe、小写。"""
    for raw in seg.strip().split():
        tok = raw.strip("'\"")
        if not tok:
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok):    # 环境变量前缀
            continue
        tok = tok.replace("\\", "/").rsplit("/", 1)[-1]
        if tok.lower().endswith(".exe"):
            tok = tok[:-4]
        return tok.strip("'\"").lower()
    return ""


def _file_targets(text):
    """从命令/路径文本里抠目标文件名：去重、保序、≤3。

    两把尺子，缺一不可：

    ★ **角色**（`_cmd_segments`/`_seg_verb`）：只从「会动文件的段」取参数。
      读类与上下文类动词（`grep`/`cd`/`python -c` …）整段跳过 —— 它们的
      参数是被读的东西或工作目录，不是「会被动的文件」。
    ★ **合法性**（`_plausible`）：正则片段、shell 赋值、转义残尾一律拒收。

    内部仍按三档取候选（① 引号包裹 → ② 带已知扩展名的裸词 → ③ 带路径
    分隔符的裸路径），但**每档都过合法性**；档③ 仍只在①②都没收获时才跑
    （`cd d:/x && rm y` 里 `d:/x` 是上下文，补进来只会掺噪声）。
    显示层只留文件名（`_short_name`）。
    """
    if not text:
        return [], False
    t = str(text)
    out, seen = [], set()

    def _add(tok):
        tok = (tok or "").strip().strip("'\"").rstrip(",;)")
        if not _plausible(tok):
            return
        tok = _short_name(tok)
        if not tok or tok in seen:
            return
        seen.add(tok)
        out.append(tok)

    live = [s for s in _cmd_segments(t) if _seg_verb(s) not in _NO_TARGET_VERBS]
    if not live:                                          # 全是读/上下文 ⇒ 无目标
        return [], False
    joined = "\n".join(live)

    for m in re.findall(r"['\"]([^'\"]{1,200})['\"]", joined):   # ① 引号包裹
        _add(m)
    for m in re.findall(r"\b([A-Za-z0-9_\-]+\.[A-Za-z0-9]{1,6})\b", joined):
        _add(m)                                                   # ② 裸词带扩展名
    if not out:
        for m in re.findall(r"(?:[A-Za-z]:|\.{1,2})?[\\/][^\s'\"|;&)]+", joined):
            _add(m)                                               # ③ 裸路径（兜底）
    return (out[:_MAX_TARGETS], len(out) > _MAX_TARGETS)


def _targets_phrase(text, budget=0):
    """目标文件名 → 人话片段（`a、b、c 等文件`；≤3 个不带「等文件」）。

    `budget>0` ⇒ 片段最长 budget 字：**从尾往前减目标**，减到还剩几个就写几个，
    收尾一律加「等文件」（因为确实还有没写出来的）。这样行预算由**结构**保证，
    而不是靠事后数——合成夹具合规、真记录 94 字的事不该再发生。
    """
    out, more = _file_targets(text)
    if not out:
        return ""

    def _join(names, tail):
        return "、".join(names) + (" 等文件" if tail else "")

    names = list(out)
    phrase = _join(names, more)
    if budget <= 0 or len(phrase) <= budget:
        return phrase
    while len(names) > 1:
        names.pop()
        cand = _join(names, True)
        if len(cand) <= budget:
            return cand
    return _join(names, True) if len(_join(names, True)) <= budget else ""


#: 研发态治理话术标记（0.51.2 第二轮，创始人截图三裁定）：含这些词的
#: 括号段整段不进用户可见文案。
#: 创始人原话：「那些文件名不列出来会死吗？？？？？？为什么要写修法，
#:   这个是我修，用户不会修，我也不会让用户修，你为什么要写？？？？？？」
_GOV_MARKERS = ("研发树", "保护名单", "登记簿", "manifest", "出厂登记",
                "修法", "python", "--", "freeze_zones", "_resign")

#: 治理子句的分句符（全角句读——治理细节多半挂在分句尾巴上）。
#: ★ 0.52.0 补「—」（破折号）：真实 dev_drift 记录里用户相关的事实挂在
#:   治理子句尾巴的「——」后面（「…与出厂登记不符（…）——这一版还没发出去」），
#:   不拆就整条被连带删掉（实测丢「这一版还没发出去」）。破折号紧跟
#:   句读时不可能合法 ⇒ 删段留下的悬空破折号由残迹清理收掉。
_GOV_CLAUSE_SEPS = "，、：；。—"


def _top_paren_spans(t):
    """所有**顶层**平衡括号段的 (start, end)（不含嵌套在别的括号段里的）。

    ★ 为什么需要它（0.52.0 实测缺口）：旧 `strip_governance` 只匹配
      **最内层**括号（正则 `（[^（）]*）`），而真实记录里治理细节整段在
      **外层**括号、内层反而是无标记小括号（如「（运行代码可能被改）」）
      ⇒ 外层永远不被检查、整段漏网（实测 spawn_failed 详情行 165 字、
      含「出厂登记」原样上屏）。
      从最外层开始删：外层含标记 ⇒ 整段删（内层跟着走，本来就是治理细节）。
    """
    spans = []
    depth = 0
    start = -1
    for i, ch in enumerate(t):
        if ch == "（":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "）" and depth > 0:
            depth -= 1
            if depth == 0 and start >= 0:
                spans.append((start, i + 1))
                start = -1
    return spans


def _drop_marker_clauses(t):
    """删掉**含治理标记的子句**（按分句符切；标记出现在括号外时靠这级兜住）。

    例：「监理启动时的自检没通过：host_shield.py 与出厂登记不符（…）；…」
      ⇒ 只留「监理启动时的自检没通过」——文件名与出厂登记是研发态内部事，
        用户面板只需要「自检没通过」这个事实（详见 ① 段归因）。
    幂等；无标记 ⇒ 原样返回。
    """
    if not any(w in t for w in _GOV_MARKERS):
        return t
    kept = []
    buf = ""
    for ch in t:
        buf += ch
        if ch in _GOV_CLAUSE_SEPS:
            if not any(w in buf for w in _GOV_MARKERS):
                kept.append(buf)
            buf = ""
    if buf and not any(w in buf for w in _GOV_MARKERS):
        kept.append(buf)
    return "".join(kept)


def gov_free(text):
    """文本是否**不含**研发态治理标记（True ⇒ 可以进用户可见文案）。

    与 `strip_governance` 共用同一份标记表（`_GOV_MARKERS`）——
    短标签过滤（`remediation` 抠「失败环节」）也走本函数，不另写一份。
    """
    t = str(text or "")
    return not any(w in t for w in _GOV_MARKERS)


def strip_governance(text):
    """研发态治理细节 → 不进用户可见文案（**唯一实现**）。

    做法（两级，反复到干净）：
      ① **括号段**（`_top_paren_spans`）：从**最外层**删含治理标记的
         平衡括号段 —— 治理细节整段挂在大括号里（触发方式/拉起方式/
         自检明细），内层无标记小括号不挡路；
      ② **裸标记子句**（`_drop_marker_clauses`）：标记出现在括号外时
         （如「host_shield.py 与出厂登记不符；…」），按分句删掉含标记
         的子句 —— 只留事实（「监理启动时的自检没通过」）。
    ★ 不变式：输出**不再含**任何治理标记（`gov_free(out) is True`）；
      输入本来就干净 ⇒ 原样返回（幂等）。
    ★ 为什么在渲染层做而不是改链：审计链 append-only，旧记录改不了；
      读侧免疫才是「修得彻底、不复发」（与 `humanize` 同一条思路）。
    ★ 消费方：详情行 `record_meta` 与归因面板 `remediation._base`
      —— 两处都调本函数，不各写一份。
    """
    t = str(text or "")
    if not t or not any(w in t for w in _GOV_MARKERS):
        return t
    changed = True
    while changed:
        changed = False
        for (s, e) in _top_paren_spans(t):
            if any(w in t[s:e] for w in _GOV_MARKERS):
                t = t[:s] + t[e:]
                changed = True
                break
        if changed:
            continue
        t2 = _drop_marker_clauses(t)
        if t2 != t:
            t = t2
            changed = True
    # 删段留下的标点残迹：重复句读、悬空分号/冒号
    t = re.sub(r"[，。；、]\s*[，。；、]+", "。", t)   # 删除留下的标点连击
    t = re.sub(r"[：；，、]+\s*。", "。", t)          # 悬空句读 + 句号
    t = re.sub(r"[：；，、]+\s*$", "", t.strip())     # 结尾悬空句读
    # 悬空破折号：治理子句被删后，它尾部的「—」会把下一节的「—」顶成句首
    #   （「研发迭代中：——这一版还没发出去」）⇒ 句读后的破折号连击全部剥掉
    #   （中文行文里「：——」「，——」不可能合法；句中的「没生效——现在」
    #    型破折号不在句读后，不受影响）。
    t = re.sub(r"([：；，、])—+", r"\1", t)
    return t.strip()


def record_meta(it, with_time=True):
    """告警**详情行**（第二行）—— 0.51.2 第二轮「人话化」重做。**唯一实现**。

    结构（三个片段，` · ` 连接）::

        拦截类：  <规则大白话>（，目标 <文件>） · 规则 <编号> · <时区> <MM-DD HH:MM>
        其它类：  <detail（已人话化）> · <时区> <MM-DD HH:MM>（＋ 备注）

    ★ 规则编号**只出现一次** —— 旧版两遍的根因：`inbox_store` 拼的 detail 已含
      「规则 X · 命中「Y」」，渲染层又把 `rule_id`/`snippet` 拼了一遍
      （实测第二行 135 字符）。现在渲染层**不看 detail 里的规则部分**，
      一律从规则表取大白话 ＋ 从命令抠目标文件。
    ★ 去掉的：核对号＋64 位链哈希（创始人「什么狗屁核对号，去掉」）、
      「命中「X」」片段（改成讲目标文件）、裸 ISO 时间（`T`/`+08:00`）。
    ★ 时间由 `ts_label` 统一（北京时间/美西时间/…），渲染出口照旧 `_vis`
      （HTML 转义 ⇒ 命令文本不会注入页面）。
    ★ `with_time=False` 给**归并行**用：它另有「最近/最早」时间段
      （行内时间保持 MM-DD HH:MM 短式 `_ts_hm`，全站唯一短式）。
    """
    parts = []
    rid = str(getattr(it, "rule_id", "") or "")
    ts_txt = ts_label(getattr(it, "ts", "")) if with_time else ""
    note = str(getattr(it, "note", "") or "").strip()
    if rid:
        head = _rule_desc(rid) or "危险操作被挡下"
        #: 其余片段的固定开销先扣掉，剩下的才是「目标」能用的预算。
        #: 目标个数由预算**派生**（不是固定 3 个）——真记录拼到 94 字就是
        #: 「个数写死、预算事后数」的必然结果。
        tail_len = len(" · 规则 %s" % rid)
        if ts_txt:
            tail_len += len(" · ") + len(ts_txt)
        if note and ts_txt:
            tail_len += len(" · 备注：") + len(note)
        budget = _META_MAX - len(head) - len("，目标 ") - tail_len
        targets = _targets_phrase(getattr(it, "command", "") or
                                  getattr(it, "file_path", ""), budget=budget)
        if targets:
            head += "，目标 %s" % targets
        parts.append(head)
        parts.append("规则 %s" % rid)
    else:
        # ★★ 0.53.0 T4：详情行**也要过人话化**（旧版只做 `strip_governance`）。
        #   实测现场（469 条本机记录）：L1/L2 详情行仍在显示
        #   「旧进程号 None」「mode=detached」「哨兵」「实际值（None）」——
        #   这些是 Python 的字与研发态词，不是给人看的字。
        #   为什么以前没有：`humanize` 当时只被归因面板调用，而**页面渲染
        #   这一路**走的是另一支（strip_governance）—— 两条路，各修一半，
        #   正是"改 A 悄悄漏 B"的标准形状。现在收口成一个出口。
        d = humanize(strip_governance(
            str(getattr(it, "detail", "") or "").strip()))
        if d:
            parts.append(d)
    if ts_txt:
        parts.append(ts_txt)
    if note and ts_txt:
        parts.append("备注：%s" % note)
    return " · ".join(p for p in parts if p)


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
            "忽略 %s 级记录必须写一句备注（说明为什么判断无需动作）。" % level
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
    #: ★ 0.51.2（第二轮「人话化」）：拦截记录的**原始命令与目标路径**
    #:   （来自审计记录 `input.command` / `input.file_path`，写侧已 mask_secrets）。
    #:   用途：详情行亮「要删/动的是哪个文件」（创始人：直接讲要删什么文件）。
    #:   渲染出口一律走 `_vis`（HTML 转义）⇒ 命令文本不会注入页面。
    command: str = ""
    file_path: str = ""
    #: ★ 0.35.3：链记录的结构化字段 `recovered`（见 docs/AUDIT_SCHEMA.md v1.10）。
    #:   True ＝ 这件事已经自动愈合、没留后果。**不许靠解析 reason 文案得到它。**
    recovered: bool = False
    #: ★ 0.35.3：**同一件「事由」的稳定标识**（来自链记录 `subkind`，见 AUDIT_SCHEMA）。
    #:   用途：把"同一条事实反复发生"归并成一件事（创始人 2026-10-06「37 条太多」）。
    #:   例：登录自启缺失 → `autostart_missing`；自检不符 → `self_check`。
    #:   缺省 `""` ＝ 该类型没细分（同 kind 同级别归为一件事）。
    topic: str = ""
    #: ★★ 0.53.0（T2.1）：**归因宿主**（哪个 AI 工具做的这件事）＋ 归因置信度。
    #:   来源＝链记录 `host` 与 `host_confidence`（写侧 `hooks/post_tool_use.py`
    #:   0.33.1 起填，detector 是唯一来源 `hooks/_host_detect.py`）。
    #:   **缺失留 `""`，不填 `generic`**：generic 是 detect 失败时的 fallback
    #:   标签，把它显示成"generic 工具"＝把「不知道」显示成「知道」。
    #:   0.33.1 前的旧记录没有这两个字段 ⇒ 按未知分代，不显示成任何工具。
    host: str = ""
    host_confidence: str = ""

    def to_dict(self):
        return asdict(self)

    @classmethod
    def build(cls, ts, kind, title="", detail="", rule_id="", snippet="",
              severity="", chain_ref="", reason=None, recovered=False, topic="",
              command="", file_path="", host="", host_confidence=""):
        """由原始事件造一条 Alert。level 一律经 level_of() 得到（唯一真源）。"""
        lvl = level_of(kind)
        return cls(
            id=alert_id(ts, kind, reason if reason is not None else (rule_id or detail)),
            ts=ts, level=lvl, kind=kind, title=title, detail=detail,
            rule_id=rule_id, snippet=snippet, severity=severity, chain_ref=chain_ref,
            recovered=bool(recovered), topic=str(topic or ""),
            command=str(command or ""), file_path=str(file_path or ""),
            host=str(host or ""), host_confidence=str(host_confidence or ""),
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
    #: 缺口态（open/acked/closed/""）—— 与 `state`（知情态）**各管一件事**。
    #: 空串＝旧数据，由 `gap_state_of()` 从 `state` 派生（见 GAP_* 那段）。
    gap_state: str = ""

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

    #: 0.51.2：拦截记录的原始命令/目标路径（详情行亮文件名用）。
    @property
    def command(self):
        return self.alert.command

    @property
    def file_path(self):
        return self.alert.file_path

    @property
    def recovered(self):
        return self.alert.recovered

    @property
    def topic(self):
        return self.alert.topic

    #: ★ 0.53.0（T2.2）：host 归因（「哪个工具环境里发生的」）—— 与 topic 同型透传。
    #:   缺失/兜底标签都不填 ⇒ `""`（页面按未知分代，不显示成任何工具）。
    @property
    def host(self):
        return self.alert.host

    @property
    def host_confidence(self):
        return self.alert.host_confidence

    @property
    def is_open(self):
        return self.state in OPEN_STATES

    def to_dict(self):
        d = self.alert.to_dict()
        d.update(state=self.state, read_at=self.read_at, closed_at=self.closed_at,
                 note=self.note, actor=self.actor,
                 gap_state=gap_state_of(self))
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


# --------------------------------------------------- 工具归因（显示，唯一实现）----
# ★★ 0.53.0（T3.3，设计 §14.3 第 3／6 条）：
#   ① 行内**工具徽标**只在"本机观测到 ≥2 个工具"时显示 —— 单工具上徽标＝
#      每行重复几百次（v0 的教训），信息量 0、噪声满屏；
#   ② **归并行尾部**给一行工具分布，**不新增小节** —— 另开一节＝同一页
#      两套计数，正是「重复即红」要消灭的形状。
#
# ★ 为什么这两个函数在模型层、而"工具→人话名"的映射在 `host_shield`：
#   本模块的契约是**纯逻辑**（不读盘）；`rules/hosts/*.json` 的读取权归
#   登记表的宿主模块。故标签映射走 `label_of` **注入**（默认原样返回
#   封闭标签 —— 缺名字时照实显示标签，绝不编一个）。
def host_distribution(items, label_of=None):
    """→ `[(显示名, 条数)]` 全量，按条数降序（同数按标签字典序，稳定）。

    ★ **host 缺失的旧记录不计入**（0.33.1 前的链记录占 16.4%）：设计
      §14.2 定的口径是「按『未知（旧记录）』分代，**不显示成任何工具**」。
      在分布里列一个「未知 N 条」等于把"不知道"变成一个新的工具名 ——
      与 P18（generic 不冒充工具名）同一条纪律。
    """
    cnt = {}
    for it in items or ():
        h = str(getattr(it, "host", "") or "").strip()
        if not h or h == "generic":
            continue
        cnt[h] = cnt.get(h, 0) + 1
    if not cnt:
        return []
    rows = sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0]))
    f = label_of or (lambda h: h)
    return [(str(f(h) or h), n) for h, n in rows]


def host_count(items):
    """观测到几个**有归因**的工具（行内徽标的开关：≥2 才显示）。"""
    return len(host_distribution(items))


#: 工具归因的置信度 → 人话（页面上不许出现 high/medium/none）
HOST_CONF_ZH = {"high": "有直接证据", "medium": "间接线索",
                "low": "线索很弱", "none": "说不清"}


def host_attribution_stats(items, days=7, now=None):
    """近 N 天的**工具归因**统计（运行状态页「工具识别」块的唯一数据源）。

    返回 `{total, attributed, unclear, by_conf, unclear_ratio}`：
      · `total`      ＝ 窗口内记录条数（分母）；
      · `attributed` ＝ 有归因的条数（`host` 非空且不是 `generic` 兜底）；
      · `unclear`    ＝ `total - attributed`（**说不清**：旧记录或检测失败）；
      · `by_conf`    ＝ 有归因记录按置信度分组（`{high: n, medium: n}`）；
      · `unclear_ratio` ＝ `unclear / total`（`total == 0` ⇒ `0.0`）。

    ★ 为什么「说不清」要单独算：设计 §14.6 要求占比 >5% 提醒 —— 而
      **分母必须是窗口内全部记录**，不是"有归因的那些"（后者天然 0%，
      这个指标就永远绿，等于没做）。F40 同型：分母选错＝指标失效。
    ★ `generic` 一并算进"说不清"：它是 detect 失败的兜底标签，不是工具名
      （与 P18／`_host_of` 同一条纪律）。
    """
    win = [it for it in (items or ()) if within_hours(it.ts, days * 24, now=now)]
    total = len(win)
    by_conf = {}
    attributed = 0
    for it in win:
        h = str(getattr(it, "host", "") or "").strip()
        if not h or h == "generic":
            continue
        attributed += 1
        c = str(getattr(it, "host_confidence", "") or "").strip() or "none"
        by_conf[c] = by_conf.get(c, 0) + 1
    unclear = total - attributed
    return {"total": total, "attributed": attributed, "unclear": unclear,
            "by_conf": by_conf,
            "unclear_ratio": (float(unclear) / total) if total else 0.0}


def host_phrase(items, limit=3, label_of=None):
    """归并行尾部的一句工具分布（唯一实现）：「工具：WorkBuddy 3 条 · Qoder 1 条」。

    ★ 超过 3 种只列前 3 ＋ 「等 N 种」：详情行有 90 字预算（`_META_MAX`），
      列 8 个工具会把归并行撑成两行；截断只影响**标签**，不影响计数口径
      （页面上没有第二个"工具总数"可被拿来对不上）。
    """
    rows = host_distribution(items, label_of=label_of)
    if not rows:
        return ""
    head = " · ".join("%s %d 条" % (nm, n) for nm, n in rows[:limit])
    if len(rows) > limit:
        head += " · 等 %d 种" % len(rows)
    return "工具：" + head


# ------------------------------------------------------------- 筛选（唯一实现）----
# ★ 页面上的筛选条与日报里每个数字的**钻取链接**共用这一套取值。
#   取值文法：
#     action / info / archive / all      —— 三档 + 全部
#     lv:R0 / lv:L2 / lv:L1 / lv:Ls      —— 按级别
#     kind:<kind>                        —— 按类型
#     rule:<rule_id>                     —— 按规则
#     closed:<日期>                      —— 按关闭日（0.51.0，账本「已处理」深链）
#     host:<工具名>                      —— 按工具归因（0.53.0 T3.1，工具分布深链）
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
    if filt.startswith("closed:"):
        return "%s · 已处理/已忽略" % filt[7:]
    # ★ 0.53.0（T3.1）：host 归因筛选的人话标签。「工具」前缀点明这一筛
    #   的是"哪个工具环境"；工具名本身是检测器写的封闭标签（T6.1 会给
    #   宿主人话名，到位后这里优先用人话名）。
    if filt.startswith("host:"):
        return "工具 %s" % (filt[5:] or "？")
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
    # ★ 0.51.0（账本明细深链）：`closed:<日期>` ＝ **closed_at 落在该天**的
    #   已关闭件。为什么不用 `day:<d>:archive`：归档桶混着「已老去滑窗」的
    #   无后果记录，标签对不上数；账本「已处理」格要的是**精确的关闭日**
    #   口径（与账本 acked 同源）。坏日期一律空集，不静默当成"全部"。
    if filt.startswith("closed:"):
        try:
            datetime.strptime(filt[7:], "%Y-%m-%d")
        except (ValueError, TypeError):
            return []
        return [it for it in items
                if it.state in CLOSED_STATES
                and str(it.closed_at or "")[:10] == filt[7:]]
    # ★★ 0.53.0（T3.1，设计 §14.3 第 5 条）：`host:<工具名>` 第 7 个前缀
    #   —— 按链上的 host 归因筛（「这件事是哪个工具环境里发生的」）。
    #   第一消费点：归并行尾部的工具分布（T3.3）—— 每个工具名链到这里。
    #   ★ **两条不变量**（比"能筛"更重要，判据 P19 钉住）：
    #     ① 不存在的工具名 ⇒ **空集**。绝不像未知前缀那样有"静默当全部"
    #        的退路 —— 末尾 fallthrough 是桶比较（对非桶值恒空），那是
    #        偶然不是设计；这里显式写空集才是"不漏"。
    #     ② host 缺失（0.33.1 前旧记录）⇒ `""`，不被任何工具名筛中
    #        （未知分代，不冒充任何工具 —— 与 `_host_of` 同向）。
    #   ★ 精确匹配不做大小写/模糊：工具名是检测器写的封闭标签
    #     （`rules/hosts/*.json` 的 host 字段），模糊匹配会把"近似"
    #     显示成"就是它"。
    if filt.startswith("host:"):
        want = filt[5:].strip()
        if not want:
            return []
        return [it for it in items if it.host == want]
    return [it for it in items if bucket_of(it, now=now, hours=hours) == filt]


# ────────────────────────────────────────────────────────────────────────
# ★★ 0.51.0（账本页四问，创始人 2026-10-16 拍板）：按天四格账的**唯一实现**。
#   为什么放 model 不放页面/daemon：「拦截/注意/缺口按 ts 落日数、已处理按
#   closed_at 落日数」是**数据口径**，账本写入（`record_day` 的补记＋更正）
#   与账本页明细（按天表/按月聚合）都要用 —— 两处各写一遍＝第二套口径
#   （本仓标准禁形）。账准修复后，daily.jsonl 快照与本函数现算一致。
LEDGER_KEYS = ("blocked", "noticed", "breached", "acked")


def day_counts(items, days=None):
    """按天四格账（拦截/注意/防护缺口/已处理）—— 账本侧唯一数据源。

    全量扫一遍 `items`（O(N)）；`days` 给定时只统计落在这些天的格子
    （供 `record_day` 的 14 天窗口用），缺省统计出现过的**全部**天
    （供账本页按月聚合）。事件按 **ts 落日**计数、已处理按 **closed_at
    落日**计数 —— 与 `record_day` 既有口径逐字一致（口径只此一份）。
    返回 `{date: {"date","blocked","noticed","breached","acked"}}`。
    """
    want = set(days) if days is not None else None
    out = {}

    def _slot(d):
        if want is not None and d not in want:
            return None
        e = out.get(d)
        if e is None:
            e = out[d] = {"date": d, "blocked": 0, "noticed": 0,
                          "breached": 0, "acked": 0}
        return e

    for it in items:
        e = _slot(str(it.ts)[:10])
        if e is not None:
            if it.level == "L2":
                e["blocked"] += 1
            elif it.level == "L1":
                e["noticed"] += 1
            elif it.level == "R0":
                e["breached"] += 1
        if it.state in CLOSED_STATES and it.closed_at:
            e2 = _slot(str(it.closed_at)[:10])
            if e2 is not None:
                e2["acked"] += 1
    return out


def ledger_rows(items, days=7, today=None):
    """按天账的**机器可读形态**（`antinel ledger --days N --json` 的唯一实现）。

    返回 `[{"date", "events", "acked", "pending"}, ...]`，**新→旧**，恰好 `days`
    个日历天（含今天）。

    三格口径（与账本页同源，全部来自 `day_counts` ＋ 同一次遍历）：
      · `events` ＝ 当天**产生**的记录数（按 `ts` 落日）；
      · `acked`  ＝ 当天**关闭**的记录数（按 `closed_at` 落日，可以是更早的事）；
      · `pending`＝ 当天产生的记录里**此刻仍未关闭**的条数。
        ★ 刻意**不用** `events - acked`：`acked` 落的是关闭日，关掉的是老事
          ⇒ 相减会出负数（异质口径做减法，F54 同型）。

    ★★ **无记录的天给 `null`，不给 `0`**（设计 §14.5 第 4 条）：这台机器那天
      可能没开机 —— 「没查」与「查过没事」在 JSON 里必须可区分，否则下游
      任何"日均"一算就把缺口洗成零。
    ★ 坏 `days`（≤0 / 非整数）⇒ 退回 7，**不静默给空表**：空表会被读成
      "这台机器没有记录"，那是另一个谎。
    """
    try:
        n = int(days)
    except (TypeError, ValueError):
        n = 7
    if n <= 0:
        n = 7
    base = today or datetime.now().astimezone().date()
    if isinstance(base, str):
        try:
            base = datetime.strptime(base[:10], "%Y-%m-%d").date()
        except ValueError:
            base = datetime.now().astimezone().date()
    dlist = [(base - timedelta(days=k)).isoformat() for k in range(n)]
    cnt = day_counts(items, days=dlist)
    pend = {d: 0 for d in dlist}
    for it in items:
        d = str(it.ts)[:10]
        if d in pend and it.state in OPEN_STATES:
            pend[d] += 1
    out = []
    for d in dlist:
        e = cnt.get(d)
        if not e or not any(int(e.get(k) or 0) for k in LEDGER_KEYS):
            out.append({"date": d, "events": None, "acked": None,
                        "pending": None})
            continue
        out.append({"date": d,
                    "events": sum(int(e.get(k) or 0)
                                  for k in ("blocked", "noticed", "breached")),
                    "acked": int(e.get("acked") or 0),
                    "pending": pend.get(d, 0)})
    return out


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
        # ★ 0.53.5（STE100 体检 S-13）：「分母未知」→「总数未知」——
        #   0490 U-03 要求正文零「分母」，兜底句也不能破例。
        return "%d %s / 总数未知" % (int(n or 0), unit)
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
    if filt.startswith("closed:"):
        try:
            datetime.strptime(filt[7:], "%Y-%m-%d")
            return True
        except (ValueError, TypeError):
            return False
    # ★ 0.53.0（T3.1）：`host:<工具名>` 也必须过页面级闸门 —— `render_page`
    #   对 `known_filter` 不认识的 filt 会**退回「要处理」**（防"静默当全部"
    #   的設計）。数据层加了前缀而这里漏加 ⇒ 钻取链接点下去看到的是**另一个
    #   视图**（模型层全绿、页面层改道 —— 活体闸当场抓到过这一版）。
    if filt.startswith("host:"):
        return bool(filt[5:].strip())
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

STATE_LABEL = {STATE_R0: "没守住", STATE_L2: "挡下", STATE_L1: "提醒",
               STATE_Ls: "缺粮", STATE_L0: "值守中", STATE_DEV: "研发中"}

#: ★★★ 六态短名的**唯一真源**就是上面这张 `STATE_LABEL`（**只描述此刻**）。
#:   取名一律走 `state_short()`；术语表 / CLI / 日报 / 筛选条 / 托盘 / 事件标题前缀
#:   **全部派生**。任何模块**不得**再写第二份 `{"R0": "…", …}` —— 判据
#:   `inbox_guards_0372.py` S08 会全仓扫描第二份声明并报红。
#:   ★ 为什么是"扫第二份"而不是"多写几条断言"：漂移的**入口**是"又抄了一份"，
#:     把入口堵死，比在每个出口巡逻更省事、也更难绕过。
#:   ★ 数**过去**的事不在这张表里 —— 走下面的 `EVENT_LABEL`／`event_short()`
#:     （2026-10-21 S-03：灯态词与事件词分开两个真源，见该处注释）。
def state_short(key):
    """态的对外短名（**唯一入口**）。未知键原样返回，不抛错。"""
    return STATE_LABEL.get(key, key)


#: ★★★ **过去发生的事**的短名 —— 第二真源（2026-10-21 STE100 体检 S-03 立，
#:   创始人拍板）。为什么必须有第二张表：`STATE_LABEL` 的六个词**只描述此刻**
#:   （「失守」＝现在没人替你挡着），可账本／日报／筛选条要用同样的键**数过去
#:   的事**。「昨日失守 3 次」是把一个"只认此刻"的词拿去数历史 —— 读者刚在灯上
#:   学会「失守＝现在」，翻一页又看见它当过去用，两个语义在同一套界面里打架
#:   （0.39.0 创始人裁定要消灭的混淆，曾以这个词回到文案里）。
#:   ⇒ 灯态走 `state_short()`，账／日报走 `event_short()`，**两个真源各管一个
#:     语义**；R0/L2/L1 三个键的值在两表里**不许重叠**（重叠＝一词二义，
#:     判据 `inbox_guards_0372.py` S08 新增腿会把 overlap 报红）。
#:   ★ Ls/L0/dev 三个键两表同值**是有意的**：它们不参与"此刻 vs 过去"的冲突
#:     （L0 是常态、dev 是开发态、Ls 是常驻徽标不是灯态），硬给它们造第二个
#:     名字只会多三个要记的词。
#:   ★ 「挡下」与状态行的动词**故意同一个词**：0.53.3 顶部条已定「挡下」，
#:     这里再造一个「挡住」就是 0.53.4 一词多义族（拦下/挡下）的复发。
#:   ★★★ 2026-10-26（创始人「出事这个词太重，显然感觉有问题」）：
#:     R0 的事件词由「出事」改为「**没守住**」。**这不是换口味，是修一个断言错误**：
#:     R0 的定义是「防线没起作用，或者根本没人守着」（见术语表 `TERMS["R0"]["one"]`），
#:     后果另有独立一条轴（none/some/unknown）；而「出事」在中文里**预判了已经
#:     造成损失** ⇒ 比这一档的定义重一档，也与后果轴打架（后果 unknown 时屏上
#:     已经说"出事了"）。本表新增词必须满足的关系是：
#:     **事件词＝灯态词的"数得出来的"同义口语版，不许换成另一个判断。**
#:     三对逐条核对：拦截→挡下（同一件事）✓｜注意→提醒（同一件事）✓｜
#:     失守→没守住（同一件事）✓ —— 只有「失守→出事」不满足，所以只改它一个。
#:     ★ 回退成「失守」不成立：`ci/inbox_guards_0372.py::_two_sources_ok` 第②腿
#:       明查「事件词不许掉进灯态词表」，回退必红 —— 那正是 2026-10-21 那次
#:       裁定（「昨天失守 3 次」违和）长出来的牙齿，不该为改一个词拆掉。
#:     ★ 三个事件词此前**一个都没进 `glossary.TERMS`** ⇒ 数卡标题写「出事」、
#:       点开首行却是「失守（R0）」，同一个数字两种叫法。已同步在三个词条的
#:       `one` 里写明"数过去的事时写什么"，并由 S08 新增一腿守着（见 0372）。
EVENT_LABEL = {STATE_R0: "没守住", STATE_L2: "挡下", STATE_L1: "提醒",
               STATE_Ls: "缺粮", STATE_L0: "值守中", STATE_DEV: "研发中"}


def event_short(key):
    """过去发生的事的短名（账／日报专用入口，**与灯态词分开**）。

    未知键原样返回，不抛错 —— 与 `state_short()` 同一条契约。
    """
    return EVENT_LABEL.get(key, key)


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
        # ★ 同 `host_shield` 缺岗分支：「不在岗」是判据锚（0372 N-S19），不许换词。
        return STATE_R0, "监理不在岗，现在没人替你挡着"
    if posture_state == "warn":
        # 出厂码不符且非研发（dev 已在 host_shield 侧分流）⇒ fail-closed。
        # ★ 0.53.5：旧句「防护开着…」先说"开着"再说"没人守"⇒ 一句话自相矛盾；
        #   且"认不出它守的是不是原来那道门"是**机制**，读者要的是**处境**。
        return STATE_R0, ("守门用的代码跟出厂记录对不上：可能被改过，"
                          "也可能这次没装好")
    return None


# ───────────────────────────────────── 0.53.5 状态说明句（唯一真源）─────────
#: ★★ 顶部条那句话的**全部字面**都在这里（判据与页面都从这里取，不许另写一份）。
#:   旧形状（`light_explain` 里现拼）的病，见 `base_state()` 头上的 0.53.5 注记。
#:
#:   立规（创始人 2026-10-21 拍板）：
#:     ① **两段制**：先说处境（结论），再说动作（要不要你动手）；不第三段；
#:     ② **标签说过的不再说第二遍**（标签「值守中」⇒ 正文不许再写"好/正常/在岗"）；
#:     ③ **主语只许监理**；无反引号、无裸英文、无技术名词（纪律 §23.2）；
#:     ④ 一句最多**一个括号**、**一个数字**；整句 ≤ `REASON_MAX_CHARS` 字；
#:     ⑤ **红/黄态不许有玩笑**，也不许拖一句无关的"24 小时没事"当安慰。
#:
#: ★ 时间口径一律由 `hours` 派生（写死 24 会与 `WINDOW_HOURS` 漂移）。
#: ★ `HUMOR` 只影响**无账那一句**：那是唯一每天出现、且真的没事的一档；
#:   关掉它回落到平实版（对外演示/企业客户场景用）。
HUMOR = True
REASON_MAX_CHARS = 48

#: ★★★ 2026-10-21（创始人「它一直是拦截，现在还是。这是个问题吧」）：
#:   **info 桶不再抬主灯** —— 规格 v1.1 §B（上策）落地。
#:
#:   为什么（实测数据，不是偏好）：本机 24 小时 13 次拦截**跨 10 个小时**，
#:   而保持期是 30 分钟且**每来一条新记录就重新计时** ⇒ 灯整天黄着
#:   （约 6.5 小时/24 小时）。一个"一直是拦截"的灯等于没有灯。
#:   而它说的其实是**监理在正常干活**（挡下的是 AI 自己的命令，14 条全是
#:   `rm`／`del`／`git checkout --`／临时目录）—— 用户既无从处理、也不需要处理。
#:
#:   语义依据（本仓自己的分工表）：L2 拦截是**事件**（天然过去时），
#:   不是"此刻"。0.39.0 已为 R0 立过同一条铁律（失守不回溯），
#:   info 桶的拦截是同一件事的另一种写法。
#:
#:   ★ 信息一个都没少（只换位置，不删）：收件箱按条列（带规则号与命中原文）
#:     ＋ 待阅 N ＋ 日报 24 小时按级计数 ＋ **顶部条主行的账句**
#:     （"最近 24 小时挡下 N 次，都替你处理完了。"）。
#:   ★ `True` ＝ 回退开关：恢复"未读 ∧ 30 分钟内抬灯"的旧行为（一行改回）。
INFO_LAMP_LIFT = False

#: 未启用：**不许**报平安（没开就是没开 —— 说"好"是假绿）。
_OFF_LINE = "还没开启，现在没有任何东西在替你看门"
#: 研发中（姿态 dev）：**身份**由徽标说，主行只说"照常在守"。
#: ★ 与 `host_shield.guard_posture()` 的 dev 分支**逐字同句**（两处都写是因为
#:   两个模块不能互相 import；改动必须同步，注释即为契约）。
DEV_LINE = "正在用还没发布的版本守着，能拦的照拦"
#: 无账（最常见、每天看几十次的那一句）。B 档＝有人味，A 档＝平实回落。
#: ★ 0.57.1：句里原写作"没出事" —— 与 0.53.5 的事件词同源，一并换掉。
#:   理由不是"这个词不好听"，而是它**预判了损失**（见 `EVENT_LABEL` 上方长注）；
#:   无账时恰恰是"什么后果都没有"，用"没事"才与事实同档。
_QUIET_HUMOR = "最近 %d 小时没事。监理守着呢，你忙你的"
_QUIET_PLAIN = "最近 %d 小时没有需要你处理的事"
#: 有账 · info 桶（监理自己处理掉了）：动词由**级别**派生，不写死 kind 表 ——
#:   全是 L2（被拦下）⇒ 说"挡下"；掺了 L1（自愈/状态变更）⇒ 说"变动"。
_INFO_BLOCKED = "最近 %d 小时挡下 %d 次，都替你处理完了"
_INFO_MIXED = "最近 %d 小时有 %d 条变动，都替你处理完了"
#: 有账 · action 桶（只有你能办）。
_ACTION_LINE = "有 %d 件事只有你能办"
#: 处境句已经占了主行时，账句用**短式**（"另有…"）—— 账不许被藏，但不许啰嗦。
_ACTION_SHORT = "另有 %d 件事只有你能办"
_INFO_SHORT = "另有 %d 次已处理"


def quiet_line(hours=WINDOW_HOURS):
    """无账那一句（**唯一实现**）。`HUMOR` 关掉 ⇒ 平实版。"""
    return (("%s" % _QUIET_HUMOR) if HUMOR else _QUIET_PLAIN) % hours


def info_line(n, hours=WINDOW_HOURS, levels=None):
    """info 桶那一句（**唯一实现**）。动词由**级别**派生，不由 kind 写死。

    ★ 为什么按级别而不是列一张 kind 表：`LEVEL_OF_KIND` 已经说了每条记录是
      哪一档（L2＝被拦下，L1＝知情即可），再抄一份 kind 表必然与它漂移
      （本仓"两份清单"的老病）。
    """
    if levels and levels <= {STATE_L2}:
        return _INFO_BLOCKED % (hours, n)
    return _INFO_MIXED % (hours, n)


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
    # ★★ 0.53.5（2026-10-21）**全量改句**：本函数这六句会直接进页面顶部条与
    #   运行状态页（见 `light_explain()` 的 `now_text`）。旧句的四个毛病
    #   （创始人 2026-10-21 截图点名）：
    #     ① **同义反复**：标签已经说「值守中」，正文又说"好的"，括号再说"在岗"；
    #     ② **审计腔自贬**："没查出问题"把"我查过、干净"说成了"我尽力了没查到"；
    #     ③ **技术残渣**：`%r`（异常 repr）、`**`（markdown 星号）上屏；
    #     ④ **未启用说"好"**：没开却报平安 —— 与本仓"绝不打假绿"正面冲突。
    #   ⇒ 新口径：**说处境，不说机制**；**主语只许监理**；一句最多一个括号。
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
        # ★ "没有监管对象"这五个字被 `ci/inbox_guards_0353.py` 的
        #   `c_outage_without_consequence_is_interrupted` 钉住（它守的是
        #   "为什么不算失守"这一**语义**）⇒ 改句不许把它改没，只许去掉
        #   括号里那四个术语（放行窗/安全区/受监管工作区/受监管落点）。
        return STATE_L1, ("监理暂停了一会儿，好在这段时间没有监管对象，"
                          "没有放过任何东西")
    if posture_state == "unknown":
        return STATE_L1, "看不到监理的状态：现在判断不了它还在不在守"
    if posture_state == "off":
        # ★ 未启用**绝不许**出现"好/正常/没事"（那是假绿）：没开就是没开。
        return STATE_L0, "还没开启，现在不会拦，也不会记账"
    if posture_state == "dev":
        return STATE_DEV, DEV_LINE
    if posture_state == "guarding":
        return STATE_L0, "监理在岗，没发现问题"
    # 理论上不可达（上面已穷尽 POSTURE_ALL，`light()` 里集合外已被拦成 L1）。
    # 保留是**故意的**：万一 POSTURE_ALL 扩容而这里忘了加分支，它打**黄**
    # （盲区）而不是绿 —— 新增状态忘记接线时必须**看得见**。
    # ★ 0.53.5：旧句把 `%r`（原始 repr）直接上屏 —— 那是给开发看的。
    #   用户面只说处境；原始值由调用方（日志／evidence）承载，不进页面。
    return STATE_L1, ("监理报了一个没登记的防线状态：认不出它是什么，"
                      # ★ 0.53.5（STE100 体检 S-12）：「档位」→「情况」
                      #   —— 读者没有"档"这个概念。
                      "先按最谨慎的情况显示")


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
      · **info 桶**（Antinel 自己处理掉的）⇒ 由 `INFO_LAMP_LIFT` 说了算：
        **现行＝一律不抬灯**（见该常量的注记：实测"一直是拦截"的那一轮）；
        回退档＝只在 **未读 ∧ 刚发生**（`LAMP_HOLD_MINUTES`）内抬灯；
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
            lift = (INFO_LAMP_LIFT and it.state == "unread"
                    and within_hours(it.ts, hold, now))
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
    # ★ info 桶的**列表**留下来（不只要个数）：0.53.5 的措辞要按**级别**派生动词
    #   （全是被拦下 ⇒ "挡下"；掺了自愈/变更 ⇒ "变动"），级别只能从记录本身取。
    _info_items = [it for it in (items or [])
                   if bucket_of(it, now=now, hours=hours) == BUCKET_INFO]
    n_info = len(_info_items)

    # ---- 拼原因句：**主灯原因 ＋ 待办提示**（二元组）----
    # ★ 不放件数式重复：件数归筛选条/顶部钻取（0.37.1 去重纪律）；这一句只答
    #   "为什么它是这个色、有没有等你办的事"。
    # ★★ FZ-004（2026-10-17 兑现）：**徽标原因不进主行**。
    #   原病（创始人 2026-10-16 截图 #4「啰嗦、浓重机器味」）：研发中徽标的
    #   完整原因句（「本机这一版（0.51.2）比已发布的（0.51.1）新，还没发出去」
    #   ＝ 30+ 字版本差工程说明）被拼进**每一态**的主行「另外：…」段 ——
    #   于是失守/注意/值守中 每一行都拖着同一条版本说明，主行被淹没。
    #   契约：主行只留状态词本身的原因；**版本差与计数挪 ? 点击展开**
    #   ⇒ 版本差仍完整保留在 `badges`（页面按 `BADGE_STATE` 挂问号芯片，
    #     点开即见），只是不占主行。**信息不丢，只换位置**（不是删）。
    _nt = now_text.rstrip("。；;.")
    # ★★ 0.53.5（2026-10-21 创始人拍板）：**整句重写**，结构从"两维拼接"改成
    #   "**处境 ＋ 动作**"两段制。旧形状的三个病（截图实测）：
    #     ① 「此刻是好的（监理在岗）」—— 标签说"值守中"、正文说"好的"、
    #        括号说"在岗"，同一件事说三遍；而真正的信息在分号后面；
    #     ② 「还有 25 条没处理（监理已自动处理…）」—— 主句"没处理"与括号
    #        "已自动处理"自我打架，还得靠 18 个字圆回来；
    #     ③ 危险态后面拖「24 小时里也没有等你处理的事」—— 最紧张时说句无关安慰。
    #   ⇒ 新结构：**有处境先说处境；有账说账（账不许被藏）；都没有才说"没事"**。
    #     ★ 关键：未启用/研发中不走"没事"分支（未启用说"没事"就是假绿）。
    parts = []
    _pst = p.get("state")
    if _pst == "off":
        parts.append(_OFF_LINE)
    elif bst == STATE_DEV and not (n_act > 0 or n_info > 0):
        # ★ dev 这一档**不取** `posture["why"]`：那条 why 是 30+ 字的工程说明
        #   （版本差），按 FZ-004 契约它不许进主行 —— 版本差归徽标与悬停提示。
        # ★★ 2026-10-21（创始人「拦截」核实轮 · 设计 §47.11.6 补条款，**待签发**）：
        #   **有账时，dev 姿态句不占主行。**
        #   理由（实测，不是偏好）：旧形状是「主行说身份、灯说事件」⇒
        #   同一屏两个说法 —— 灯明明写着「拦截」，正文却一句没提被拦了什么，
        #   只说"另有 19 次已处理" ⇒ 正是创始人点名的那副形状
        #   （吓人 + 说不清 + 无从下手）。
        #   ⇒ 规矩：**账有话可说时，账句上主行**（设计 §47.11.2 的表：
        #     info 桶 ⇒「最近 24 小时…都替你处理完了。」／action 桶 ⇒
        #     「有 N 件事只有你能办。」）；**身份退到徽标**（研发中徽标 ＋
        #     问号小窗 ＋ 运行状态页仍在 ⇒ 信息不丢，只是换位置）。
        #   ⇒ 与**验收活体回读**同形：设计 §47.11 的验收行本来就是
        #     「拦截｜研发中｜最近 24 小时有 25 条变动，都替你处理完了。」——
        #     那一轮姿态是 guarding；**dev 姿态这一格当时没被测到**
        #     （输入空间没覆盖，与 FZ-004 那次同型：判据天天绿，
        #      因为夹具从没喂过 dev ＋ 有账）。
        #   ★ 无账时 dev 句仍占主行（设计 §47.11.2 的「研发中」行）。
        parts.append(DEV_LINE)
    elif now_bad:
        parts.append(_nt)
    # ---- 第二段：账（有就说，绝不藏）----
    # ★ X（2026-10-23）：这一段单独留成 `_acct` 并随返回值交出，供 `render_view()`
    #   把「账句」接到新投影的主行后面。**账句只有这一个实现** —— 新投影不重算，
    #   否则就是「同一件事两处实现」（本仓第一顽症），且两边的窗口口径会漂。
    _acct = ""
    if n_act > 0:
        _acct = _ACTION_SHORT % n_act if parts else _ACTION_LINE % n_act
        parts.append(_acct)
    elif n_info > 0:
        if parts:
            _acct = _INFO_SHORT % n_info
        else:
            _acct = info_line(n_info, hours,
                              levels={it.level for it in _info_items})
        parts.append(_acct)
    elif not parts:
        parts.append(quiet_line(hours))
    reason = "；".join(parts) + "。"
    return {"state": st, "label": label, "now_text": now_text,
            "now_bad": now_bad, "ledger_bad": ledger_bad, "reason": reason,
            "badges": bs, "action_count": n_act, "info_count": n_info,
            "account_text": _acct}


#: ------------------------------------------------------------------ X 步翻译层
#:  新投影（`facts` 四轴 → `situation` 三函数）与**页面契约**之间的唯一桥梁。
#:  为什么放在本模块：本模块拥有旧词表（`STATE_LABEL`／`STATE_VAR`／`STATE_LOGO`）
#:  与页面原因句的唯一实现（`light_explain`）。放到 `state_registry` 就得把旧词表
#:  抄第二份 —— 0372 S08 挡的正是这个。


def state_var(st):
    """灯态 → CSS 变量。**认不出就当场炸**，绝不静默回落。

    ★ 为什么要有它：`STATE_VAR[st]` 裸下标在两条渲染链上各有一处
      （`inbox_server` 顶部条／`inbox_bubble` 浮窗）。裸下标遇到域外键会抛
      `KeyError` —— 那是**好**结果（响亮）；真正危险的是有人为了"稳妥"改成
      `.get(st, "--l0")`：**不认识的态会画成绿**，也就是「看不清」被画成
      「没事」。本函数让域外键炸在**一处**，并说清楚它不在哪张表里。
    """
    if st not in STATE_VAR:
        # ★ 报错串**不带 `%r`**：`%r` 是「不上屏的开发者消息」的标记，而这条
        #   诊断不需要 repr 也读得懂（键本身就是个短词）。带上它等于白占一条
        #   豁免额度 —— U-29 把豁免面按条数钉死，加两条就红（实测 29 > 27）。
        raise KeyError("灯态 %s 不在灯态表里（合法：%s）"
                       % (st, "/".join(sorted(STATE_VAR))))
    return STATE_VAR[st]


#: 后果在身的三种成因（红态）。账句规矩见 `render_view()` 里那段注释。
_HARM_CAUSES = ("absent", "breach", "blind")


def render_view(posture=None, items=None, now=None, hours=WINDOW_HOURS,
                granary=None, versions=None, facts_obj=None):
    """★★ X 步：**生产侧唯一取数点** —— 新投影说话，旧契约出场。

    返回 dict ＝ `light_explain()` 的全部键（几何与计数照旧）＋ 五个新键：

      `lamp`        四值小写英文（`grey/green/yellow/red`，F2 冻结枚举）
      `cause`       八成因键之一（F3 注册表键）
      `color_var`   灯色 CSS 变量（`state_registry.COLOR_VAR` 单点定义）
      `sentence`    冻结句 `{"main","action"}`（F2 冻结）
      `projection`  恒 `True` —— 渲染点据此断言"这一屏的话来自新投影"

    ★ 三个"为什么"：

    ① **`state` 仍返旧六键之一**（`R0/L2/L1/Ls/L0/dev`）。它只承担**几何**：
      图标形状、动效、CSS 变量、`assets/icons/*.ico` 的取图键。换成成因键会让
      托盘找不到文件、`_logo_mark()` 认不出、`0360 T04` 逐格红 —— 而这一层
      本步**不需要**动。词归 `label`，色归 `color_var`，形状归 `state`，三件事
      各有各的通道（I6：颜色与文字同权，正因为它们不是一回事）。

    ② **`label` 取注册表的词**，不取 `STATE_LABEL`。旧词表装不下新模型的区分：
      「监理不在岗」与「在岗但有缺口」在旧表里都叫「失守」，而这正是本次重做
      要分开的两件事。旧词表整族保留（283 处判据的锚），只是**不再由它出场**。

    ③ **账句沿用 `light_explain()` 算好的那一句**（`account_text`）。件数与窗口
      口径只有一处实现；新投影只换「处境段」，不重算账。

    ★ `facts_obj` 可注入：判据用它喂合成事实，**不许**让判据走 `collect()` ——
      那会让判据在真实机器上时绿时红，且与它自己的夹具无关（假绿第三形态）。
    """
    base = light_explain(posture, items, now=now, hours=hours,
                         granary=granary, versions=versions)
    if facts_obj is None:
        import facts as _F
        # ★ 把调用方**已经探过**的姿态与**已经读过的账**交下去：
        #   `render_page()` 探过一次姿态、读过一遍账本，采集层再来一遍就是
        #   「同一事实两遍算」（TP-A1 守的正是这条），且两遍之间账变了会让
        #   灯与列表各说各话。
        facts_obj = _F.collect(posture=posture, items=items)[0]
    import situation as _S
    import state_registry as _R

    c = _S.cause(facts_obj)
    key = _S.cause_key_of(c)
    lamp_v = _S.lamp(facts_obj)
    sent = _S.sentence(c, facts_obj)
    # ★ 成因键 → 出场旧键**只有一处实现**（`legacy_key_of`：认不出就炸）。
    #   上一版在这里又写了一道「键不在注册表里」的守卫，报错串带 `%r` ⇒ 白占一条
    #   开发者消息豁免（U-29 当场红）。同一个键要过两道守卫，本身就是给漂移留了
    #   第二个入口 —— 删掉这道，让唯一那份先炸。
    _st = _R.legacy_key_of(key)
    ent = _R.STATES_BY_KEY[key]

    main = (sent.get("main") or "").rstrip("。")
    acct = (base.get("account_text") or "").strip()
    # ★★ 账句什么时候能接在后果句后面（实测撞出来的规矩，不是偏好）：
    #   红态主行说「有 3 件没修」，后面接「最近 24 小时有 37 条变动，**都替你
    #   处理完了**」—— 两句在同一行里互相拆台：前一句说没修完，后一句说完事。
    #   这正是创始人 0.53.5 点名过的形状（「没处理」＋「已自动处理」自我打架）。
    #   ⇒ 后果在身的三种成因（absent／breach／blind）只接**动作类**账句
    #     （「有 N 件事只有你能办」）；info 类账句一律不接，那一维由页面计数承担。
    if key in _HARM_CAUSES and not (base.get("action_count") or 0) > 0:
        acct = ""
    # ★★ 第二处：`ok`／`paused` 的处境句本身**断言没有待办**
    #   （「今天没什么要拦的」「这会儿没有要管的东西」）。有 action 账时把它接在
    #   后面，会读出「没有要管的东西；有 1 件事只有你能办」——两句互相拆台，
    #   与上面那条是同一个病，只是方向反了。
    #   治法沿用 0.53.5 已拍板的那条（「有账时账句上主行、身份退到徽标/灯」）：
    #   这两种成因**主行只说账**，处境由状态词与灯色承担（信息不丢，只换位置）。
    if acct and key in ("ok", "paused"):
        main = ""
    # ★ 句末的句号由这里补：`account_text` 与 `sentence.main` 都**不带**收尾句号
    #   （句号的唯一实现留在这条拼装线上，否则会出现「办。。」）。
    reason = ("%s；%s。" % (main, acct) if (main and acct)
              else "%s。" % (main or acct))
    out = dict(base)
    out.update({
        "state": _st,
        # ★★ 出场的**词**仍取旧词表（`state_label`）——理由见
        #   `state_registry.CAUSE_LEGACY` 的注释：新词这一族还没有术语表条目，
        #   屏幕上出现一个点不开解释的词比用旧词更糟。切换词表属于「旧屏句子
        #   迁移」，单独一步做；本步只换「谁决定它是哪一档」。
        "label": state_label(_st, (posture or {}).get("state")),
        "reason": reason,
        "lamp": lamp_v,
        "cause": key,
        "cause_label": ent["label"],            # 注册表里的新词，随数据交出但不上屏
        "color_var": _R.COLOR_VAR[lamp_v],
        "sentence": sent,
        "projection": True,
    })
    return out
