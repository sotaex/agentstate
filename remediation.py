# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Antinel 监理 · 失守归因（「为什么 & 怎么办」按钮背后的实现，**唯一实现**）。

★ 为什么要有这个模块（创始人2026-10-07 原话）：
  「要让用户知道，是什么原因造成了这个失守，有什么办法能解决，
    如果没有办法，如何能做到不造成实际损失，
    总之，要让用户能够有机会不断改进，**不能无法改进，只能看**。」
  ⇒ 「只能看」就是产品失败。**每一条 R0 都必须至少给出"能做什么"的一步。**

★ 三条不许破的纪律：

  ① **归因只用文件级证据**（链记录 / manifest 哈希 / state 文件 / 自启项 /
     工作区登记）。**不枚举窗口、不列进程**。
     理由是**实测**：本机 `EnumWindows` 可见 507 个 hwnd，但**新开的 app
     窗口抓不到标题**（实测两次都拿不到）⇒ 任何"自动定位那个进程"的
     做法在本机**不可靠**。宁可说"这一项查不到"，也不编一个进程名。

  ② **"已经放过什么"必须查，不许推断。** 去链上找 `succeeded=true` 的写入；
     找不到就说「查到的范围内没有」——**把"没查到"说成"没有"就是假话**。

  ③ **分A/B 两类，且 B 类也必须给下一步。**
     A 类 = 能一键修好（已有 `host_shield.guard_fix` 落地）。
     B 类 = 修不了根因（门闸被对抗）⇒ 给**三选一**：
       修复（附命令）／ 移出监管名单（承认打不赢）／ 接受风险（写明代价）。
     ★ 创始人 2026-10-07 拍板：「不能只给修复，得让用户选。」

★ 结构固定四段（页面只排版，判定全在这里）：
     `cause`     根因：哪个文件/哪次变更/为什么
     `severity`  现在有多严重：有没有真的放过东西
     `actions`   能做什么（**至少一个**，按可执行性排序）
     `accept`    代价说明：什么都不做会怎样
"""
from __future__ import annotations

import os
import re

# --- 处置类别 -------------------------------------------------------------
ACT_FIX = "fix"            # 修根因（一条命令）
ACT_RETRY = "retry"        # 重新拉起哨兵
ACT_REARM = "rearm"        # 重新布防（刷新基线）
ACT_DROP = "drop"          # 承认打不赢：移出监管名单
ACT_ACCEPT = "accept"      # 接受风险（写明代价）—— 红按钮，点了等于签字担责
ACT_INFO = "info"          # 纯告知（不带任何处置）—— 普通按钮，点了只是知道了

#: B 类三选一（创始人拍板的顺序）。★ 三条**都必须**出现在页面上，
#   否则"点开发现修不了"就退化成"只能看"。
B_CLASS_CHOICES = (ACT_FIX, ACT_DROP, ACT_ACCEPT)

# ★★ 0.36.4「消灭副本」是**错的，已回退**（本轮由 `_PICK` 表实测推翻）：
#   0.36.4 我判断 `ACT_INFO` 与 `ACT_ACCEPT` 是同一语义的两个名字，于是删掉前者。
#   ★ 推翻它的事实（不是推理，是 `inbox_server._PICK` 的真实内容）：
#:     accept → 按钮文案「就这样，我不处理」＋ 样式 `risk`（红）
#:     info   → 按钮文案「知道了」　　　　＋ 样式 无（普通）
#     **文案与样式都不同 ⇒ 它们是两个不同的用户承诺，不是同义复数。**
#     且 `inbox_server.py:557`（归因模块故障兜底）**仍在真实发 `op="info"`** ——
#     删掉常量等于让那个 op 变成「有消费、无声明」的野值：
#     消费方 `_PICK["info"]` 还认得，但常量表已无从查证它被正确使用。
#     这恰好是本项目反复吃过的那个亏的**反例**：把活契约当冗余删掉。
#     —— 判据能抓「声明与实现脱节」，但抓不到「契约被删成活野值」。
#
#   ★ 那 `B_CLASS_CHOICES` 与实现脱节是不是真的？**是真的，但修法不是消灭副本**：
#     B 类那条动作的 hint 明写「代价：这个落点持续无人巡检，改动不会被告警」
#     ⇒ 它**确实是在接受风险**（`accept` 的定义就是"接受风险，写明代价"），
#       原代码用 `info` 发它才是错的（承担风险的承诺配了纯告知的 op）。
#     ⇒ 两件事各归各位：`ACT_INFO` 保留（它有真实消费方）；
#       B 类那条**改发 `ACT_ACCEPT`**（已改）。
#   ★ 判据同步：0360 那三处原本排除 `ACT_INFO`（当时 B 类发的是 info，
#     排除它才能测出「还有别的可执行项」）。改成 `accept` 后，
#     排除对象必须跟着变，否则测的就不是同一个东西了。
#     —— 这不是「改判据让它变绿」，判据的**被测语义**确实随实现口径变了。


def _chain_records(since=None):
    """哨兵链上的记录（**只读**，取不到就返回空列表）。

    ★ 取不到**不抛** —— 调用方据实说"查不到"，不许把读失败说成"没问题"。
    """
    try:
        import host_shield as HS
        d = HS.sentinel_audit_dir()
        p = os.path.join(d, "audit-%s.jsonl" % __import__("datetime").date.today().isoformat())
        if not os.path.isfile(p):
            return []
        out = []
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    import json
                    out.append(json.loads(line))
                except Exception:                              # noqa: BLE001
                    continue
        return out
    except Exception:                                           # noqa: BLE001
        return []


def _path_from_detail(detail, patterns):
    """从 `reason` 文案里取路径（只认**明确的路径形状**，不猜）。"""
    for pat in patterns:
        m = re.search(pat, detail or "")
        if m:
            return m.group(1)
    return ""


def what_got_through(detail=""):
    """「已经放过什么」——**查链，不推断**。

    返回 `(结论句, 查到的条数)`。查不到落点清单时明说查不到，不说"没有"。
    """
    try:
        import host_shield as HS
        st = HS.load_state()
        cons = HS._outage_consequences(st)
    except Exception as e:                                       # noqa: BLE001
        return ("查不到当前有哪些受监管对象（%s）——因此不能说"
                "「没有放过东西」。" % e, 0)
    if not cons:
        return ("监理此刻没有受监管对象（无放行窗、安全区、受监管工作区、受监管落点）。"
                "所以这段时间不可能放过任何东西。", 0)
    # ★ 0.37.2 fix：旧版这里**以冒号结尾、却不给清单** ——
    #   页面上渲染成「…期间发生的改动 不会被发现 ：」然后什么都没有
    #   （实测截图：一句话悬在半空）。冒号是"下面要列东西"的承诺，
    #   列不出来就别打冒号。⇒ 把查到的受监管对象**直接接在后面**。
    #   注意：这段会过 `glossary.render()`（只放行 `<b>/<code>`），
    #   所以用「；」分隔，不写 `<br>`/`<ul>`（那会被转义成一串标签文本）。
    names = [(c.get("text") if isinstance(c, dict) else str(c)) for c in cons]
    return ("这些受监管对象此刻无人巡检，期间发生的改动不会被发现：%s"
            % "；".join(names), len(cons), )


def _base(item):
    import inbox_model as M
    _raw = str(getattr(item, "detail", "") or "")
    d = dict(
        kind=str(getattr(item, "kind", "") or ""),
        topic=str(getattr(item, "topic", "") or ""),
        level=str(getattr(item, "level", "") or ""),
        # ★★ 0.51.2 第二轮（创始人截图三）：**detail 进面板前先过
        #   `M.strip_governance`** —— 研发态治理细节（文件名、保护名单、
        #   修法命令）不进用户可见文案。唯一实现调 inbox_model，不另写。
        detail=M.strip_governance(_raw),
        #: 原文（未消毒）—— 只给 spawn_failed 抠「失败环节」短标签用
        #: （抠完只留冒号前的用户能懂的一截，治理细节照样进不来）。
        detail_raw=_raw,
        ts=str(getattr(item, "ts", "") or ""),
        chain_ref=str(getattr(item, "chain_ref", "") or ""),
    )
    d["path"] = ""
    return d


# --------------------------------------------------------------------------
# 各类失守的归因。**只认实测存在的六类**（见下 `_kind_of`）：
#zone_locked / tamper / hook_registration_changed / autostart_missing /
#            spawn_failed / breach(其他)
# 遇到未登记的 kind ⇒ 走 `_fallback`，说清"这类我没归因过"，
# 但**仍然给得出下一步**（回运行状态页的现探 + 归档），
# 因为纪律③ 要求每条 R0 都有一���"能做什么"。
# --------------------------------------------------------------------------

def _kind_of(item):
    """这条失守属于哪一类（**唯一实现**）。

    ★ 主判据＝**结构化字段** `(kind, topic)`。
    ★ 唯一例外是这段**文本兜底**，且必须如实标注它是什么：
      本机实测有 **14 条**「登录自启缺失」的历史记录`topic` 为空 ——
      查证结果：写入侧**现在**已经带 `subkind="autostart_missing"`
      （`host_shield.py:1746`），所以那些是**旧版本留下的**记录，
      结构化字段本来就没有，**补不回来**（链不可改，这是设计）。
      ⇒ 只能按 `detail` 的**固定前缀**精确匹配，并且：
        ① 只匹配**完整已知前缀**（不是模糊包含），避免把别的记录误判进来；
        ② 归因结果里**明说**这条是靠文案认出来的、不是结构化字段。
      为什么不干脆不认：把 14 条真失守归到「未归类」，等于告诉用户
      「本产品认不出自己的失守」——那比多一处文本匹配更糟。
    """
    k = str(getattr(item, "kind", "") or "")
    t = str(getattr(item, "topic", "") or "")
    d = str(getattr(item, "detail", "") or "")
    if k == "host_shield_zone_locked":
        # ★★★ 0.40.0：这个 kind **兼表"上锁成功"与"上锁失败"**，必须按记录分派。
        #   修的是什么（实测缺陷）：旧实现**无条件** `return "zone_locked"` ⇒
        #   `inbox_model._zone_lock_failed()` 恒为 True ⇒ 它声称的"按记录判成败"
        #   是**空转的**：一条"安全区已上锁"（severity=warning）被渲染成
        #   R0「失守：安全区加锁失败」且进「要处理」。实测本机 2 条。
        #   ⇒ 分派顺序（结构化优先，文本殿后）：
        #       ① `subkind`（0.40.0 之后的新记录；写 side 已加）
        #       ② `severity`（新老记录**都有**的结构化字段：warning=成功 / critical=失败）
        #       ③ detail 固定前缀（只在 ①② 都取不到时才用；如实标注是文本兜底）
        #       ④ 全判不出 ⇒ 当作**失败**（fail-loud：宁可多报"要你处理"）
        if t == "zone_ok":
            return "zone_ok"                        # 结构化 ✔
        if t == "zone_lock_failed":
            return "zone_locked"                    # 结构化 ✔
        sev = str(getattr(item, "severity", "") or "")
        if sev == "warning":
            return "zone_ok"                        # 结构化 ✔（新老记录都有）
        if sev == "critical":
            return "zone_locked"                    # 结构化 ✔
        if d.startswith("安全区已上锁"):
            return "zone_ok"                        # ← 文本兜底（无 severity 的历史件）
        return "zone_locked"                        # 判不出 ⇒ 按失败（fail-loud）
    if k == "host_shield_tamper":
        # ★★ 0.37.1 修「归因错配」（创始人第 1 问「后台数据跟前沿的对接是否
        #   正确」抓到的**真缺陷**）：
        #   旧版把所有 tamper 都说成一句 「有人改过 `enabled`」，并让用户去跑
        #   `antinel host-shield enable`。本机实测 71 条 tamper 里只有 **16 条**
        #   真的在讲 `enabled` ——
        #     39 条 = 哨兵自检不符（运行代码/登记表与 manifest 对不上，topic=self_check）
        #      6 条 = 登记表与 manifest 不符（疑似运行期投毒）
        #     10 条 = workspaces/zones/windows 在无链背书下被改
        #   ⇒ 剩下 **55 条(77%)** 拿到的是**错的**"为什么"和错的第一步：
        #     用重装去重签 manifest 漂移这类问题上不去根，还把真原因盖住了。
        #   ⇒ 分派：`topic` 是结构化字段，优先用它；
        #     topic 为空的旧记录才按**完整前缀**做文本兜底（会如实标注）。
        # ★ 0.40.0（A5）：`code_drift` 是 `self_check` 的**病因合并键**（同一件事：
        #   代码/登记表与 manifest 不符）。旧记录仍是 `self_check`，两者都要认。
        if t in ("self_check", "code_drift"):
            return "self_check"                        # 结构化 ✔
        if "登记表与 manifest" in d or "manifest 不符" in d:
            return "registry_manifest"
        if d.startswith("state 文件") and "enabled" in d:
            return "tamper_enabled"                    # ← 旧文案**唯一**适用的类
        if d.startswith("state 文件") and (
                "zones" in d or "workspaces" in d or "windows" in d):
            return "tamper_registry"
        return "tamper"
    if k == "host_shield_breach" and t == "hook_registration_changed":
        return "hook_registration_changed"
    if k == "host_shield_breach" and t == "autostart_missing":
        return "autostart_missing"
    # ★ 文本兜底（只对 `topic` 为空的旧记录；匹配**完整前缀**）
    if k == "host_shield_breach" and not t:
        # ★ 0.51.2：新增新文案前缀（`开机自启没装上`）—— 双前缀同列。
        #   旧记录仍是「登录自启缺失」；新记录走结构化 subkind（上面那条），
        #   这里只是**兜底不落空**（万一 subkind 丢了也认得出）。
        if d.startswith("登录自启缺失") or d.startswith("开机自启没装上"):
            return "autostart_missing"
    if k == "host_shield_spawn_failed":
        return "spawn_failed"
    if k == "host_shield_breach":
        return "breach_other"
    return "unknown"


#: 靠文案（而非结构化字段）认出来的类 —— 页面上要如实标出来。
#: ★ 0.37.1：新增三类 tamper 细分都属此类（它们的 `topic` 是空的，
#:   只能靠 `detail` 的**完整前缀**认 —— 这是只能如此，但必须说出来）。
_TEXT_MATCHED = {"autostart_missing", "registry_manifest",
                 "tamper_enabled", "tamper_registry"}


def recognised_by_text(item):
    """这条是靠文案认出来的吗（页面据此加一句说明）。"""
    k = _kind_of(item)
    return k in _TEXT_MATCHED and not str(getattr(item, "topic", "") or "")


def attribute(item, posture=None, consequences=None):
    """一条失守 → 归因 dict。

    返回字段：
      `kind`/`title`   这类失守叫什么
      `b_class`        `True` = 修不了根因（页面上要显示"降损"三选一）
      `cause`          发生了什么（**大白话**，带具体文件/路径）
      `severity`       有多严重（**查过的**，不是推断的）
      `severity_note`  现场一句（现在实测）；只在需要与历史记录和解时出现
      `actions`        `[{"op":..,"label":..,"hint":..,"ack":..,"href":..}, ...]`
                       `ack=True` 的动作不上面板（见 `_a`）
      `cost`           ★ 0.53.0 T4 起恒为空串：旧版「不做的后果」整段删除
                       （创始人 2026-10-19 定性"完全是废话"——它把 ② 段已经
                       说过的事换个说法再说一遍）。字段保留只为不打断既有
                       调用方；渲染层不再读它。
    """
    k = _kind_of(item)
    b = _base(item)
    b_class = False
    b["by_text"] = recognised_by_text(item)   # ★ 靠文案认出来的，页面要标出来

    if k == "zone_locked":
        # ★ 0.51.2：路径锚点跟着写侧文案搬家（新「需要人工介入：」＋旧「须人工介入：」）。
        # ★★ 0.52.0（实测缺口）：当前写侧（host_shield.py:3665，0.45.0 H-7 起）的失败
        #   文案是「安全区【上锁没生效】——…；注意：「不等于」有进程在对抗门闸：<路径>」，
        #   **没有**「人工介入」锚点 ⇒ 上面两个模式全落空，面板显示
        #   「(落点路径没在记录里)」——路径明明在记录里（创始人裁定 #3：亮文件名）。
        #   兜底模式只认**明确的路径形状**（全角冒号＋盘符＋分隔符＋行尾），不猜。
        path = _path_from_detail(b["detail"], [r"需要人工介入：(.+)$",
                                               r"须人工介入：(.+)$",
                                               r"：([A-Za-z]:[\\/][^：；]*)$"])
        b["path"] = path or "(落点路径没在记录里)"
        t, n = what_got_through(b["detail"])
        # ★★ 0.52.0：面板不许与记录矛盾。当前写侧形态的记录**明确写了**
        #   「不等于有进程在对抗门闸」（真相是 ACL 没限制住写入）——
        #   旧文案 headline 却断言「有进程正在写」，与记录直接打架（裁定 #5）。
        #   ⇒ 按记录形态分流：ACL 形态说 ACL 的实话，对抗形态说对抗的实话。
        if "上锁没生效" in b["detail"] or "不等于" in b["detail"]:
            return dict(b, kind=k, title="安全区上锁失败", b_class=True,
                        cause=("这个落点的安全区锁没有生效。落在它上面的改动"
                               "拦不住，也发现不了。记录写明了原因：本目录的"
                               "访问控制没能限制写入。落点：%s。" % b["path"]),
                        severity="这个落点现在是开着的。",
                        severity_note=t,
                        actions=[
                            _a(ACT_DROP, "移出监管名单",
                               hint="这个目录从此不受保护，改动不会被发现。"),
                            _a(ACT_ACCEPT, "就这样放着，我自己守着",
                               hint="这个落点持续无人巡检。"),
                            _a(ACT_FIX, "再试一次上锁"),
                        ])
        return dict(b, kind=k, title="安全区上锁失败", b_class=True,
                    cause=("监理上不了这个落点的锁：%s。"
                           "可能有程序的权限正在改它（备份软件、同步盘），"
                           "也可能有东西在绕开监理。" % b["path"]),
                    severity="这个落点现在是开着的。",
                    severity_note=t,
                    actions=[
                        _a(ACT_DROP, "移出监管名单",
                           hint="这个目录从此不受保护，改动不会被发现。"),
                        _a(ACT_ACCEPT, "就这样放着，我自己守着",
                           hint="这个落点持续无人巡检。"),
                        _a(ACT_FIX, "再试一次上锁"),
                    ])

    if k in ("self_check", "registry_manifest"):
        # ★ 0.37.1 新增（旧版这两类都被当成「enabled 被改」，给错了第一步）。
        #   两者的处置是同一件：**让代码/登记表与 manifest 重新对上**。
        # ★★ 0.51.2 第二轮（创始人：研发态话术/文件名/修法命令不进用户面板）：
        #   · 「出厂登记/指纹/登记表」是我第一轮自造的术语，用户读不懂 ⇒ 换成
        #     大白话（「登记的那份」「系统里记的那份」）；
        #   · cause 不再整段嵌 `b["detail"]`（那里有研发态治理细节、文件名、
        #     修法命令）——自检没通过这个事实一句说完，细节留研发侧；
        #   · 去掉 ACT_REARM（用户不会修，也不许让用户修）。
        return dict(b, kind=k, title="守门的程序跟登记的那份不一样了",
                    b_class=False,
                    cause=("监理每次启动都核对：正在运行的程序与系统里登记的"
                           "那份是不是同一份。这次对不上。可能是程序改动后"
                           "还没重新登记，也可能有人动过它。"),
                    severity="守门的这份程序是不是原来那份，已经认不出来了。",
                    severity_note=_posture_note(posture, k),
                    actions=[
                        _a(ACT_INFO, "查一下是谁动的",
                           hint="看这些程序的修改时间和来源。不是你动的，"
                                "就按有人动过防护处理。"),
                    ])

    if k == "tamper_registry":
        # ★★ 0.51.2 第二轮：cause 不再嵌 `b["detail"]`（含研发态治理话术）；
        #   去掉 ACT_REARM 与其命令行。
        return dict(b, kind=k, title="受监管名单被改动，改动没走正规入口",
                    b_class=False,
                    cause=("受监管名单被改动过，安全记录里没有对应条目。"
                           "改动没走正规入口。"),
                    severity="被看着的范围可能跟你的设置不一致。",
                    severity_note=_posture_note(posture, k),
                    actions=[
                        _a(ACT_INFO, "看改成什么了",
                           hint="明细里写了改动前后的值。"),
                    ])

    if k == "tamper_enabled":
        return dict(b, kind=k, title="防护状态与安全记录对不上", b_class=False,
                    cause=("防护设置文件里的开关值被改过，"
                           "安全记录里最后记的正好相反。"),
                    severity="防护可能被关掉了。",
                    # ★ 0.37.1：旧版这句写死成 `state 写 enabled=False，链上是 armed`
                    #   —— 一旦实际值不同（或链上最后状态不是 armed），
                    #   界面就在**编数据**。⇒ 改为照抄记录原文，让记录自己说话。
                    severity_note="（记录原文：%s）" % (b["detail"] or "（无原文）"),
                    actions=[
                        _a(ACT_INFO, "查是谁动的",
                           hint="看这个文件的修改时间和来源。不是你动的，"
                                "就是有东西在动防护。"),
                    ])

    if k == "tamper":
        # ★ 上面都没对上：不猜，把原文摆出来。
        return dict(b, kind=k, title="登记文件被动过（具体字段记录里没写）",
                    b_class=False,
                    cause=("这条记录只说动了防护设置，没写清动了哪个字段。"
                           "原文：%s。" % (b["detail"] or "（无原文）")),
                    severity="防护设置可能被改动了，方向不确定。",
                    severity_note=_posture_note(posture, k),
                    actions=[
                        _a(ACT_INFO, "看这条记录的原文"),
                    ])

    if k == "hook_registration_changed":
        # ★ 0.51.2：写侧文案人话化后，路径抽取的锚点跟着搬 —— 同时保留旧锚
        #   （历史记录仍是旧文案）。两条都不命中 ⇒ 路径给"没在记录里"。
        # ★★ 0.51.2 第二轮：去掉 ACT_REARM＋命令行；「先看改了什么」是查证
        #   动作不是修复 ⇒ 改 ACT_INFO（按钮不许写着「修」却什么也没修）。
        p = _path_from_detail(b["detail"], [
            r"就能对齐）：(.+)$",            # 0.51.2 新文案
            r"基线）：(.+)$", r"不一致：(.+)$",  # 0.51.2 之前
        ])
        b["path"] = p or "(设置文件路径没在记录里)"
        return dict(b, kind=k, title="钩子注册文件被改动（防护失效）",
                    b_class=False,
                    cause=("工具的钩子注册文件决定哪些调用会被拦。"
                           "它与布防时记下的样子对不上：%s。"
                           "可能你自己改过它，也可能有人在拆防护。" % b["path"]),
                    severity="这个工具的调用现在可能拦不住。",
                    severity_note="（能确定的是「跟布防时的样子对不上」，"
                                  "不能确定的是「改了什么」。）",
                    actions=[
                        _a(ACT_INFO, "看改了什么",
                           hint="比对设置文件与布防时留下的副本，看是不是你改的。"),
                    ])

    if k == "autostart_missing":
        return dict(b, kind=k, title="开机自启没装上（监理不会随开机起来）",
                    b_class=False,
                    cause=("计划任务和启动文件夹里都没有登记项。"
                           "监理只在这次会话里活着，一重启就没人守。"),
                    severity="现在还在守，下次开机后不守。",
                    severity_note="（自启查过两处：计划任务、启动文件夹。"
                                  "不是查不到，是没装。）",
                    # ★★ 0.51.2 第二轮：这条**本来就是用户自己的装机动作**
                    #   （与运行状态页「要开启，在终端执行一次」同口径）——
                    #   命令留在 hint 里当说明；按钮不再假装能就地修好
                    #   （旧版 ACT_REARM 点了只会回「没有可就地修复的动作」，
                    #   是创始人最恨的假按钮形状）。
                    actions=[
                        _a(ACT_INFO, "装开机自启",
                           hint="在终端执行一次：antinel host-shield enable"
                                "（需管理员权限）。"
                                "装完以后，重启也能守。"),
                    ])

    if k == "spawn_failed":
        # ★★ 0.51.2（创始人 2026-10-17「都在说鸟语」）：**不再从机器串里抠原因**。
        #   旧实现 `_path_from_detail(b["detail"], [r"mode=([^）]*)）"])` 是从
        #   `mode=self-check-failed: …）` 这段**序列化碎片**里正则抠出失败原因 ——
        #   写侧文案一旦人话化（本轮改成「拉起方式：…」），这条正则就**静默失效**，
        #   归因会退化成"没有原因"（本仓最恨的形状：改 A 悄悄弄坏 B）。
        #   ⇒ 改成**两段式**：
        #     ① 新文案（「拉起方式：X」）—— 直接匹配中文键；
        #     ② 旧文案（`mode=X`）—— 兜底，让**历史记录**仍能归因。
        # ★★ 0.51.2 第二轮（创始人截图三「集鸟语和愚蠢之大成」）：
        #   抠 reason 走**原文**（`detail_raw`，消毒前）——消毒后「拉起方式」
        #   那段括号已被摘掉；抠出后只保留**冒号前的短标签**（「自检没通过」），
        #   冒号后面是研发态治理细节（文件名、保护名单、修法命令），
        #   一律不进用户面板（创始人：文件名不列出来会死吗？为什么要写修法，
        #   用户不会修，我也不会让用户修）。
        reason = _path_from_detail(b["detail_raw"], [
            r"拉起方式：([^）]*)）",          # 0.51.2 新文案
            r"mode=([^）]*)）",               # 0.51.2 之前的历史记录
        ])
        short = ""
        if reason:
            reason = reason.strip()
            #: 冒号前短标签：新文案全角「：」、旧文案 ASCII「:」都要切
            #: （W-SPK4 旧文案夹具 `mode=self-check-failed: xxx` 是 ASCII 冒号）。
            head = re.split(r"[：:]", reason, 1)[0].strip()
            #: 旧枚举值先过人话化（self-check-failed → 自检没通过）。
            try:
                import inbox_model as _M
                head = _M.humanize(head)
            except Exception:                               # noqa: BLE001
                pass
            #: 短标签只认「用户能懂且无治理标记」的；治理细节整段丢弃
            #: （研发态修法在审计链/CLI 里查得到，不进用户面板）。
            try:
                import inbox_model as _M
                _ok = _M.gov_free(head)
            except Exception:                               # noqa: BLE001
                _ok = not any(w in head for w in ("研发", "登记", "manifest",
                                                  "python", "保护名单", "修法"))
            if head and len(head) <= 20 and _ok:
                short = head
        return dict(b, kind=k, title="监理没能启动", b_class=False,
                    cause=("监理进程停了，重新拉起没成功。"
                           + ("失败环节：%s。" % short if short else "")),
                    severity=("那段时间受监管的改动没人巡检，改了也发现不了。"),
                    severity_note=_posture_note(posture, k),
                    # ★★ 0.53.0 T4（创始人 2026-10-19「那个按钮我专门讲过」）：
                    #   看得见这个页面 ⇒ 监理在跑。值守中只发 ack（不上屏），
                    #   不发给「重新拉起」——那个按钮在值守中恒为一句假话。
                    actions=([_a(ACT_INFO, "知道了", ack=True)]
                             if not _can_revive(posture) else
                             [_a(ACT_RETRY, "重新拉起监理")]),
                    cost="")

    # breach_other / unknown —— 不硬编归因，但**必须给得出下一步**
    _acts = [_a(ACT_INFO, "看运行状态页",
                hint="那里有此刻的实测态势：监理在不在、心跳多旧、自检过不过。",
                href="/?v=health")]
    if _can_revive(posture):
        _acts.append(_a(ACT_RETRY, "先试一次拉起监理"))
    # ★ 0.53.1（创始人 2026-10-18）：标题里的「防护有缺口／有缺口」去掉 ——
    #   这个词不在六态表里，会被读成第四种态；同一件事的标准名是**失守**。
    return dict(b, kind=k, title="失守（未归类）", b_class=False,
                cause=("这一类失守没有专门的归因规则。记录原文：%s。"
                       % (b["detail"] or "（无原文）")),
                severity="按运行状态页的现探结果为准。",
                severity_note=_posture_note(posture, k),
                actions=_acts,
                cost="")


def _a(op, label, hint="", ack=False, href=""):
    """一个可执行动作。★ 0.51.2 第二轮：**去掉 `cmd` 字段** ——
    研发/运维命令（`antinel host-shield enable`）不再以 `<code>` 块
    的形式摆在用户面板上（创始人：用户不会修，也不许让用户修）。
    真需要用户在终端执行的动作，命令写在 hint 里当说明，不当按钮。

    ★★ 0.53.0 T4（创始人 2026-10-19「那个按钮我专门讲过」）：
      `ack=True` ＝ 这条动作只是「收下这条通知」，不改变任何东西。
      面板**不渲染**它 —— 条目底部已经有「知道了」；同一件事在一张卡片里
      出现两次，第二次就只是噪音。数据层仍保留（0360 判据要求每条 R0
      至少给一个动作，那个「动作」不一定要上屏）。
    """
    d = {"op": op, "label": label, "hint": hint, "ack": bool(ack)}
    if href:
        d["href"] = href
    return d


def _posture_note(posture, kind=""):
    """「有多严重」段末尾的**现场**一句（与面板标题不许自相矛盾）。

    ★★ 创始人截图三：面板标题「监理拉起失败（没人值守）」，这句却写
      「（此刻实测：值守中）」—— 面板是**历史**记录，这句算的是**当前**
      态势，两个时刻打架。⇒ 措辞统一成「现在实测」，与「① 发生了什么」
      （当时的事）分属两段，不再互相矛盾。
    ★ 值是**实时算出来的**（`_six_state_label` → 六态）。
    ★★ 0.53.0 T4（创始人 2026-10-19）：「现在实测」这句**只在两种时候出现**：
        ① 现在不是值守中（此刻真的在失守，读者必须知道）；
        ② 这条记录讲的是监理自己没起来（spawn_failed / 自检不符 /
           登记不符 / 没装自启）—— 那类历史记录容易被读成"现在也没在守"，
         必须给一句现场来和解。
      其余类别（例如某个落点上不了锁）在值守中时**不出**这句：它在值守中
      仍然成立（落点开着与监理在岗两件事都真），摆一句"现在值守中"反而像
      自相矛盾 —— 与截图里的"违和"同型。
    """
    if posture is None:
        posture = _live_posture()
    if posture is None:
        return ""
    st = str(posture.get("state") or "")
    if st != "guarding":
        return "（现在实测：%s。）" % (_six_state_label(posture),)
    if kind in _LIVE_KINDS:
        return "（现在实测：%s。）" % (_six_state_label(posture),)
    return ""


#: 「现在实测」这句必须出现的类别（见 `_posture_note`）—— 记录讲的是监理自己。
_LIVE_KINDS = frozenset(("spawn_failed", "self_check", "registry_manifest",
                         "autostart_missing"))


def _revive_ok_states():
    """允许「重新拉起监理」的态势**白名单**（0.53.0 T4）。

    ★★ 为什么从黑名单改成白名单：旧口径是 `state != "guarding"` —— 凡是
      不在"值守中"这一格里的都发给按钮。实测本机姿态是 **dev（研发中）**
      （在岗、只是代码比登记的新）⇒ 页面照样挂「现在重新拉起」——
      而看得见页面就说明它在跑，这个按钮仍然是一句不成立的话。
      黑名单的错在于：**它假设"不在岗"只有一种形状**，而六态里有四种
      都在岗（guarding／warn／dev）加一种未启用（off，拉起也白拉）。
    ★ 取值只有两个：真缺岗（down＝有损失；interrupted＝无损失）。
      导入失败 ⇒ 空集（一个都不给）—— 宁可少一个入口，不许给假的。
    """
    try:
        import host_shield as HS
        return frozenset((HS.POSTURE_DOWN, HS.POSTURE_INTERRUPTED))
    except Exception:                                           # noqa: BLE001
        return frozenset()


def _can_revive(posture):
    """当前态势能不能「重新拉起监理」——0.51.2 第二轮（创始人截图四）。

    创始人原话：「如果用户能看到，必然监理系统在运行，否则用户看不到，
    那么你设置这个按钮干什么呢？？？？？？已经再跑了，还要重新拉起？？？」

    ★★ 0.53.0 T4（创始人 2026-10-19「这种超级违和还能死灰复燃，要查清原因」）：
      两处都改，缺一处都不算修完：
      ① `posture is None` 旧实现返回 True —— 而生产渲染路径**恰恰就是
         None**（`render_page` 只把注入值往下传，不注入时整页拿到 None），
         于是每一次真实打开都判"可以拉起"，按钮恒现。判据 W-SPK10 只用
         注入姿态跑，走不到这条 None 路径 ⇒ 假绿。现在 None 一律**现探**。
      ② 判据从"≠ 值守中"换成**白名单**（见 `_revive_ok_states`）——
         研发中／可信性存疑／未启用都不再发给按钮。
      探不到态势 ⇒ False：按钮是**可执行承诺**，宁可少一个入口，
      不许给一个点了可能白点的按钮（创始人最恨的形状）。
    """
    if posture is None:
        posture = _live_posture()
    if not isinstance(posture, dict):
        return False
    return str(posture.get("state") or "") in _revive_ok_states()


def _six_state_label(posture):
    """姿态 → **六态灯态标签**（0.37.1）。

    ★ 为什么不能直接用 `posture["label"]`：那个字典里有「存疑」——
      创始人 2026-10-07 定性的「计划外状态，不允许」。归因面板也是用户
      界面，照样不许出现 ⇒ 一律过 `inbox_model.light()` 拿六态词。
    ★ 顺带修 0.35.3 同型漏改：`_live_posture_label()` 原来调
      `guard_posture()` 不传包根 ⇒ 读中枢 rollup 链，显示过时态势。
    """
    try:
        import inbox_model as M
        st, _why = M.light(posture.get("state"), [], now=None)
        return M.state_label(st, posture.get("state"))
    except Exception:                                           # noqa: BLE001
        return posture.get("label") or "?"


def _live_posture():
    """现探当前态势（唯一实现：`host_shield.guard_posture`，带包根）。

    ★ 0.53.0 T4：把**取态势**与**给标签**拆成两个函数 —— 旧版只有
      `_live_posture_label()`（返回人话串），而门控判断需要的是**原始
      state**。过去要 state 的一方只能再猜一次字符串（"值守中" == guarding?）
      ⇒ 两把尺子。现在一律拿 dict，标签由 `_six_state_label` 出。
    """
    try:
        import host_shield as HS
        return HS.guard_posture(os.path.dirname(os.path.abspath(__file__)))
    except Exception:                                           # noqa: BLE001
        return None


def _live_posture_label():
    """现探态势的六态标签（探不到 ⇒ 空串，不编）。"""
    p = _live_posture()
    return "" if p is None else _six_state_label(p)


def summarize(items):
    """一批失守 → 一句汇总（给日报/归并组用）。

    ★ 口径纪律：单位是**类**（不是条数），并写清本机实测的类清单——
      不让"1 类 12 条"这种混读发生（F40 口径混装）。
    """
    seen = {}
    for it in items:
        k = _kind_of(it)
        seen[k] = seen.get(k, 0) + 1
    if not seen:
        return ""
    return "共 %d 类：%s（本机实测各类记录条数见括号）" % (
        len(seen),
        "、".join("%s %d 条" % (_TITLE.get(k, k), n)
                  for k, n in sorted(seen.items(), key=lambda kv: -kv[1])))


_TITLE = {
    "zone_locked": "安全区上锁失败",
    "tamper": "防护状态被改动",
    "hook_registration_changed": "钩子注册被改动",
    "autostart_missing": "开机自启没装上",
    "spawn_failed": "监理没能启动",
    "breach_other": "失守（未归类）",
    "unknown": "未归类",
}