# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""值守台 · 失守归因（「为什么 & 怎么办」按钮背后的实现，**唯一实现**）。

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
        return ("查不到当前有哪些受监管对象（%s）——因此**不能**说"
                "「没有放过东西」。" % e, 0)
    if not cons:
        return ("监理此刻没有受监管对象（无放行窗/安全区/受监管工作区/受监管落点），"
                "所以这段时间**不可能**放过任何东西。", 0)
    # ★ 0.37.2 fix：旧版这里**以冒号结尾、却不给清单** ——
    #   页面上渲染成「…期间发生的改动 不会被发现 ：」然后什么都没有
    #   （实测截图：一句话悬在半空）。冒号是"下面要列东西"的承诺，
    #   列不出来就别打冒号。⇒ 把查到的受监管对象**直接接在后面**。
    #   注意：这段会过 `glossary.render()`（只放行 `<b>/<code>`），
    #   所以用「；」分隔，不写 `<br>`/`<ul>`（那会被转义成一串标签文本）。
    names = [(c.get("text") if isinstance(c, dict) else str(c)) for c in cons]
    return ("这些受监管对象此刻**无人巡检**，期间发生的改动**不会被发现**：%s"
            % "；".join(names), len(cons), )


def _base(item):
    d = dict(
        kind=str(getattr(item, "kind", "") or ""),
        topic=str(getattr(item, "topic", "") or ""),
        level=str(getattr(item, "level", "") or ""),
        detail=str(getattr(item, "detail", "") or ""),
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
        if d.startswith("登录自启缺失"):
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
      `cause`          根因（**大白话**，带具体文件/路径）
      `severity`       现在有多严重（**查过的**，不是推断的）
      `severity_note`  查证范围/盲区说明
      `actions`        `[{"op":..,"label":..,"cmd":..,"hint":..}, ...]`
      `cost`           什么都不做的代价
    """
    k = _kind_of(item)
    b = _base(item)
    b_class = False
    b["by_text"] = recognised_by_text(item)   # ★ 靠文案认出来的，页面要标出来

    if k == "zone_locked":
        path = _path_from_detail(b["detail"], [r"须人工介入：(.+)$"])
        b["path"] = path or "(落点路径没在记录里)"
        t, n = what_got_through(b["detail"])
        return dict(b, kind=k, title="安全区上锁失败（有进程在写）", b_class=True,
                    cause=("有进程正在写这个落点，Antinel 上不了锁："
                           "%s。"
                           "上不了锁——要么是有权限的进程正在改它（可能是你自己"
                           "装的工具、备份软件、同步盘），要么是有东西在故意绕开。"
                           % b["path"]),
                    severity=("**这个落点此刻是开着的**：落在它上面的改动拦不住、"
                              "也发现不了。"),
                    severity_note=t,
                    actions=[
                        # ★ 0.37.2：选项标题去掉「（承认打不赢）」——
                        #   按钮上写的就是「承认打不赢，移出监管」，
                        #   标题再写一遍 ⇒ 同一行里同一个意思出现两次。
                        _a(ACT_DROP, "移出监管名单",
                           hint=("把它从安全区拿掉，监理不再为一个它守不住的落点"
                                 "反复报警。代价：那个目录从此**不受保护**，"
                                 "你得自己保证它不被改。")),
                        _a(ACT_ACCEPT, "就这样放着，我自己盯着",
                           hint="不改任何设置。代价：这个落点持续无人巡检，"
                                "改动不会被告警。"),
                        # ★ 0.37.2：选项标题原来是「先查是谁在对抗」，而它下面
                        #   挂的按钮是「试一下，看能不能修好」（ACT_FIX 的通用
                        #   文案）⇒ 标题说"查"、按钮说"修"，点下去做的事和
                        #   标题对不上。改成与按钮同一件事：再试一次上锁；
                        #   "查是谁在对抗"那部分如实写进说明（它本机查不到）。
                        _a(ACT_FIX, "再试一次上锁",
                           hint="Antinel 当场重试一次；还是失败会把原因报给你，"
                                "不会假装好了。想查**是谁在占用**那个目录 —— "
                                "这一项**本机查不到**（窗口枚举不可靠），"
                                "给不出命令，需要你自己确认那个目录是什么程序在写。"),
                    ],
                    cost=("一直报警，但监理确实守不住这个落点。"
                          "反复红而无改善 ⇒ 红灯就没人看了，"
                          "等于没有守卫。"))

    if k in ("self_check", "registry_manifest"):
        # ★ 0.37.1 新增（旧版这两类都被当成「enabled 被改」，给错了第一步）。
        #   两者的处置是同一件：**让代码/登记表与 manifest 重新对上**。
        return dict(b, kind=k, title="守门的这份代码跟出厂登记对不上",
                    b_class=False,
                    cause=("每次启动都会拿**正在运行的文件**与 manifest 里登记的"
                           "哈希对一遍；这次对不上：%s。"
                           "两种可能 —— ①你（或你的构建流程）刚改过这些文件、"
                           "还没重新签发登记；②有人动过这些文件。"
                           % (b["detail"] or "（记录里没写具体文件）")),
                    severity=("认不出此刻守门的是不是原来那道门 ⇒ "
                              "**按失守算**（宁可报错也不装作没事）。"),
                    severity_note=_posture_note(posture),
                    actions=[
                        _a(ACT_REARM, "是我改的：重新签发登记",
                           cmd="antinel host-shield enable",
                           hint="走正规入口重装一次，manifest 会被重签，"
                                "这份代码就重新有了户口。"),
                        _a(ACT_INFO, "不是我改的：先核对这两个文件",
                           hint="看它们的修改时间与来源；若不是你自己动的，"
                                "按「文件被动过」处理。"),
                    ],
                    cost=("不重签就一直对不上 ⇒ 每次监理启动都会重报同一条，"
                          "这条红到最后就没人看了。"))

    if k == "tamper_registry":
        return dict(b, kind=k, title="受监管名单在没有链记录的情况下被改",
                    b_class=False,
                    cause=("state 文件里的名单被改动，而这次改动"
                           "**没有对应的链记录**（说明它不是走正规入口改的）：%s。"
                           % (b["detail"] or "（记录里没写具体字段）")),
                    severity=("名单被动过的那段时间，实际被看着的范围"
                              "**可能跟你的设置不一致**。"),
                    severity_note=_posture_note(posture),
                    actions=[
                        _a(ACT_REARM, "按现在的设置重新布防",
                           cmd="antinel host-shield enable",
                           hint="把你认可的名单重新登记一次，链上就有了背书。"),
                        _a(ACT_INFO, "先看改成什么了",
                           hint="明细里写了改动前后的值；确认那是不是你要的。"),
                    ],
                    cost="没有背书的改动会一直被当成可疑；开着又不处理 ⇒ "
                         "分不清真告警和历史噪音。")

    if k == "tamper_enabled":
        return dict(b, kind=k, title="防护状态文件与审计链不一致", b_class=False,
                    cause=("有人改过 `host_shield.json` 里的 `enabled`，"
                           "而链上最后一次记录与之相反。"
                           "两条记录对不上 ⇒ 要么改文件的人没走正规入口，"
                           "要么有人想绕开监理的拦截。"),
                    severity="**防护可能被关掉了**，而这次改动没走 `host-shield`（链上没有）。",
                    # ★ 0.37.1：旧版这句写死成 `state 写 enabled=False，链上是 armed`
                    #   —— 一旦实际值不同（或链上最后状态不是 armed），
                    #   界面就在**编数据**。⇒ 改为照抄记录原文，让记录自己说话。
                    severity_note="（这条记录原文：%s）" % (b["detail"] or "（无原文）"),
                    actions=[
                        _a(ACT_REARM, "重新布防（以链为准，把状态改回来）",
                           cmd="antinel host-shield enable",
                           hint="用正规入口重跑一次，链与state 就一致了。"),
                        _a(ACT_FIX, "确认是不是我改的",
                           hint="如果你没改过，那就是有东西在动它——"
                                "先查这个文件的修改时间与来源。"),
                    ],
                    cost="状态与链不一致期间，监理按哪一份执法是**不确定**的；"
                         "不一致一直挂着，自检就一直不通过。")

    if k == "tamper":
        # ★ 上面都没对上：不猜，把原文摆出来。
        return dict(b, kind=k, title="登记文件被动过（具体字段记录里没写）",
                    b_class=False,
                    cause=("这条记录只说动了 `state`，没写清动了哪个字段。"
                           "**不替它猜一个** —— 原文在下面，请你自己核对：%s。"
                           % (b["detail"] or "（无原文）")),
                    severity="防护设置可能被改动了（方向不确定）。",
                    severity_note=_posture_note(posture),
                    actions=[
                        _a(ACT_REARM, "按现在的设置重新布防",
                           cmd="antinel host-shield enable",
                           hint="把你认可的设置重新登记一次，链上就有了背书。"),
                        _a(ACT_INFO, "看这条记录的原文",
                           hint="原文在「为什么」第一段。"),
                    ],
                    cost="没有背书的改动会一直挂着 ⇒ 自检一直不过。")

    if k == "hook_registration_changed":
        p = _path_from_detail(b["detail"], [r"基线）：(.+)$", r"不一致：(.+)$"])
        b["path"] = p or "(设置文件路径没在记录里)"
        return dict(b, kind=k, title="钩子注册文件被改动（防护有缺口）",
                    b_class=False,
                    cause=("工具的钩子注册文件（决定「哪些调用会被拦」）"
                           "与布防时记录的基线不一致：%s。"
                           "要么是你合法编辑了它（没刷新基线），"
                           "要么是有东西在拆防护。" % b["path"]),
                    severity="**这个工具的调用现在可能拦不住**——"
                             "取决于改动的内容。",
                    severity_note="（能确定的是「基线对不上」，不能确定的是「改了什么」。）",
                    actions=[
                        _a(ACT_REARM, "刷新基线（按现在的文件重新布防）",
                           cmd="antinel host-shield enable",
                           hint="如果你确认那个改动是你合法做的，"
                                "跑这条把基线对齐，缺口就补上了。"),
                        _a(ACT_FIX, "先看改了什么",
                           hint="比对设置文件与布防时的基线副本，"
                                "看是不是你改的。"),
                    ],
                    cost="基线一直不对 ⇒ 每次巡视都报同一条，"
                         "要么一直红，要么被忽略；两种都等于没有守卫。")

    if k == "autostart_missing":
        return dict(b, kind=k, title="登录自启缺失（监理不会随开机起来）",
                    b_class=False,
                    cause=("计划任务与启动文件夹里**都没有**登记项"
                           "（自启三态判定为「不在」）。"
                           "所以监理只在这次会话里活着——"
                           "**一重启就没人在守**。"),
                    severity="**现在这一刻还在守，但下次登录后不会守。**",
                    severity_note="（自启三态：True=在／False=不在／None=查不到；"
                                  "这里是 False=确实不在。）",
                    actions=[
                        _a(ACT_REARM, "装上登录自启（一次就够）",
                           cmd="antinel host-shield enable",
                           hint="需要管理员权限。装完之后重启也能自动守。"),
                    ],
                    cost="**最坏的一类**：此刻看起来一切正常，"
                         "但关机重启后防线就没了，且**没有人会告诉你**。")

    if k == "spawn_failed":
        reason = _path_from_detail(b["detail"], [r"mode=([^）]*)）"])
        return dict(b, kind=k, title="监理拉起失败（没人值守）", b_class=False,
                    cause=("监理进程死后没能被重新拉起。"
                           + ("失败原因：%s。" % reason if reason else "")
                           + "常见于**运行中的代码与登记的 manifest 不符**——"
                           "也就是跑着的守门代码可能不是登记过的那份。"),
                    severity="**监理不在的这段时间，没人在巡检受监管落点**"
                             "（外传发现不了）。",
                    severity_note=_posture_note(posture),
                    actions=[
                        _a(ACT_RETRY, "重新拉起监理",
                           hint="点这个会当场重试并复测；"
                                "如果还是失败，会告诉你失败原因，不会假绿。"),
                        _a(ACT_REARM, "先让代码与登记一致",
                           cmd="antinel host-shield enable",
                           hint="自检不符时重跑安装/布防，"
                                "让 manifest 与实际文件对上。"),
                    ],
                    cost="监理不在 ⇒ 这段时间发生的改动不会有告警。")

    # breach_other / unknown —— 不硬编归因，但**必须给得出下一步**
    return dict(b, kind=k, title="防护有缺口（未归类）", b_class=False,
                cause=("这一类失守我没有专门的归因规则（记录原文：%s）。"
                       "**不编一个听起来合理的原因**——"
                       "归因规则没有覆盖它，就如实说没有。" % (b["detail"] or "（无原文）")),
                severity="按运行状态页的现探结果为准。",
                severity_note=_posture_note(posture),
                actions=[
                    _a(ACT_FIX, "回运行状态页看现探",
                       hint="那里有此刻的实测态势（监理在不在、心跳多旧、自检过不过）。"),
                    _a(ACT_RETRY, "先试一次拉起监理",
                       hint="多数「没人守」都能这样恢复。"),
                ],
                cost="归因规则没覆盖 ⇒ 你只能看到「有缺口」，"
                     "拿不到「为什么」。这是本产品的已知短板，不是你的操作问题。")


def _a(op, label, cmd="", hint=""):
    return {"op": op, "label": label, "cmd": cmd, "hint": hint}


def _posture_note(posture):
    """★ 0.37.2：**不再把内部函数名印到用户屏幕上**。

    旧版渲染成「（本机实测：此刻 `guard_posture()` = 值守中）」——
    带反引号的 Python 标识符是**给开发者看的**，摆在「② 现在有多严重」
    下面就是工程腔，而且是创始人点名的"违和感"。
    ★ 值是**实时算出来的**（`_six_state_label` → 六态），这点没错，
      要改的只是说法：把函数名换成"此刻实测"。
    """
    if posture is None:
        return "（此刻实测：%s）" % (_live_posture_label(),)
    return "（此刻实测：%s）" % (_six_state_label(posture),)


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


def _live_posture_label():
    try:
        import host_shield as HS
        return _six_state_label(
            HS.guard_posture(os.path.dirname(os.path.abspath(__file__))))
    except Exception:                                           # noqa: BLE001
        return "探不到"


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
    "autostart_missing": "登录自启缺失",
    "spawn_failed": "监理拉起失败",
    "breach_other": "防护有缺口（未归类）",
    "unknown": "未归类",
}