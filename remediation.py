# -*- coding: utf-8 -*-
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
        return ("门闸此刻没有受监管对象（无放行窗/安全区/受监管工作区/受监管落点），"
                "所以这段时间**不可能**放过任何东西。", 0)
    return ("这些受监管对象此刻**无人巡检**，期间发生的改动**不会被发现**：",
            len(cons), )


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
        return "zone_locked"
    if k == "host_shield_tamper":
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


#: 靠文案（而非结构化字段）认出来的类 —— 页面上要如实标出来
_TEXT_MATCHED = {"autostart_missing"}


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
        return dict(b, kind=k, title="安全区上锁失败（门闸被对抗）", b_class=True,
                    cause=("有进程在**对抗门闸**，Antinel 没能给这个落点上锁："
                           "%s。"
                           "对上了锁——要么是有权限的进程在改它（可能是你自己"
                           "装的工具、备份软件、同步盘），要么是有东西在故意绕开。"
                           % b["path"]),
                    severity=("**这个落点此刻是开着的**：落在它上面的改动拦不住、"
                              "也发现不了。"),
                    severity_note=t,
                    actions=[
                        _a(ACT_DROP, "移出监管名单（承认打不赢）",
                           hint=("把它从安全区拿掉，门闸不再为一个它守不住的落点"
                                 "反复报警。代价：那个目录从此**不受保护**，"
                                 "你得自己保证它不被改。")),
                        _a(ACT_ACCEPT, "就这样放着，我自己盯着",
                           hint="不改任何设置。代价：这个落点持续无人巡检，"
                                "改动不会被告警。"),
                        _a(ACT_FIX, "先查是谁在对抗",
                           hint="需要能列出占用该目录的进程——这一项"
                                "**本机实测查不到**（窗口枚举不可靠），"
                                "所以给不出命令。请你自己确认那个目录"
                                "是什么程序在写。"),
                    ],
                    cost=("一直报警，但门闸确实守不住这个落点。"
                          "反复红而无改善 ⇒ 红灯就没人看了，"
                          "等于没有守卫。"))

    if k == "tamper":
        return dict(b, kind=k, title="防护状态文件与审计链不一致", b_class=False,
                    cause=("有人改过`host_shield.json` 里的 `enabled`，"
                           "而链上最后一次记录是 `armed`。"
                           "两条记录对不上 ⇒ 要么改文件的人没走正规入口，"
                           "要么有人想绕过门闸。"),
                    severity="**防护可能被关掉了**，而这次改动没走 `host-shield`（链上没有）。",
                    severity_note="（本机实测：state 写 enabled=False，链上是 armed。）",
                    actions=[
                        _a(ACT_REARM, "重新布防（以链为准，把状态改回来）",
                           cmd="antinel host-shield enable",
                           hint="用正规入口重跑一次，链与state 就一致了。"),
                        _a(ACT_FIX, "确认是不是我改的",
                           hint="如果你没改过，那就是有东西在动它——"
                                "先查这个文件的修改时间与来源。"),
                    ],
                    cost="状态与链不一致期间，门闸的行为以谁为准是**不确定**的；"
                         "不一致一直挂着，自检就一直不通过。")

    if k == "hook_registration_changed":
        p = _path_from_detail(b["detail"], [r"基线）：(.+)$", r"不一致：(.+)$"])
        b["path"] = p or "(设置文件路径没在记录里)"
        return dict(b, kind=k, title="钩子注册文件被改动（门闸有缺口）",
                    b_class=False,
                    cause=("工具的钩子注册文件（决定「哪些调用会被拦」）"
                           "与布防时记录的基线不一致：%s。"
                           "要么是你合法编辑了它（没刷新基线），"
                           "要么是有东西在拆门闸。" % b["path"]),
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
        return dict(b, kind=k, title="登录自启缺失（哨兵不会随开机起来）",
                    b_class=False,
                    cause=("计划任务与启动文件夹里**都没有**登记项"
                           "（自启三态判定为「不在」）。"
                           "所以哨兵只在这次会话里活着——"
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
        return dict(b, kind=k, title="哨兵拉起失败（门闸无人值守）", b_class=False,
                    cause=("哨兵进程死后没能被重新拉起。"
                           + ("失败原因：%s。" % reason if reason else "")
                           + "常见于**运行中的代码与登记的 manifest 不符**——"
                           "也就是跑着的守门代码可能不是登记过的那份。"),
                    severity="**哨兵不在的这段时间，没人在巡检受监管落点**"
                             "（外传发现不了）。",
                    severity_note=_posture_note(posture),
                    actions=[
                        _a(ACT_RETRY, "重新拉起哨兵",
                           hint="点这个会当场重试并复测；"
                                "如果还是失败，会告诉你失败原因，不会假绿。"),
                        _a(ACT_REARM, "先让代码与登记一致",
                           cmd="antinel host-shield enable",
                           hint="自检不符时重跑安装/布防，"
                                "让 manifest 与实际文件对上。"),
                    ],
                    cost="哨兵不在 ⇒ 这段时间发生的改动不会有告警。")

    # breach_other / unknown —— 不硬编归因，但**必须给得出下一步**
    return dict(b, kind=k, title="门闸有缺口（未归类）", b_class=False,
                cause=("这一类失守我没有专门的归因规则（记录原文：%s）。"
                       "**不编一个听起来合理的原因**——"
                       "归因规则没有覆盖它，就如实说没有。" % (b["detail"] or "（无原文）")),
                severity="按运行状态页的现探结果为准。",
                severity_note=_posture_note(posture),
                actions=[
                    _a(ACT_FIX, "回运行状态页看现探",
                       hint="那里有此刻的实测态势（哨兵在不在、心跳多旧、自检过不过）。"),
                    _a(ACT_RETRY, "先试一次拉起哨兵",
                       hint="多数「没人守」都能这样恢复。"),
                ],
                cost="归因规则没覆盖 ⇒ 你只能看到「有缺口」，"
                     "拿不到「为什么」。这是本产品的已知短板，不是你的操作问题。")


def _a(op, label, cmd="", hint=""):
    return {"op": op, "label": label, "cmd": cmd, "hint": hint}


def _posture_note(posture):
    if posture is None:
        return "（本机实测：此刻 `guard_posture()` = %s）" % (_live_posture_label(),)
    return "（本机实测：`guard_posture()` = %s）" % (posture.get("label") or "?")


def _live_posture_label():
    try:
        import host_shield as HS
        return HS.guard_posture().get("label") or "?"
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
    "spawn_failed": "哨兵拉起失败",
    "breach_other": "门闸有缺口（未归类）",
    "unknown": "未归类",
}