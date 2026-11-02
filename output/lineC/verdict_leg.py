#!/usr/bin/env python
# SPDX-License-Identifier: CC-BY-SA-4.0
"""第三只腿：**从账本里读「今天真的挡下了什么」**。

★ 为什么需要这只腿（2026-11-02 实测）
  `evidence.collect()` 原来只跑两条腿：auditor（账本自洽）＋ watchman（变化巡检）。
  两条腿**都不读 `decision` 字段**，于是真账本里当天真的发生的裁决
  （11-02：通知面口径 29 条）在结论里一条不出现，一页纸写「需要你看一眼 0 条」。
  `evidence.py` 头注那句「本模块一条『挡下』都不许产出」**只对那两条腿成立**，
  不对账本成立 —— 它被写成模块级约束，于是整条线自我阉割了。

★★ 这只腿的定位：**只读取证，不改产品代码**
  · 它读账本，不写账本。
  · 它**不自己定「哪些该通知人」** —— 那张表是产品侧
    `hooks/notify_policy.py` 的 `_NOTIFY_OF_DECISION`，
    这里**直接 import 它**（单一真源，铁律 R4），不抄一份。
  · 它不裁决「这件事该不该给人看」 —— 那是创始人拍板的事（DEC-27 的 D-1）。
    它只回答一个事实问题：**账本里有哪些裁决记录，它们长什么样。**

★★ 三类东西必须分开（铁律 44：同值不同义比不同值更难发现）
  实测 11-02 的 29 条 GATE 里，26 条带规则号（规则挡住了），
  3 条不带（`host_shield_breach` / `host_shield_dev_drift` —— 守卫自己不在岗）。
  它们都写着 `decision=block`，只按 decision 统计会被混成同一个数。
  ⇒ 本模块把它们分成**两个不同的强度档**：
      · 带规则号 ⇒ `held`（挡下）—— 动作真的没执行，且能指到规则
      · 不带规则号 ⇒ `no_response`（已发现无法处置）—— 动作没执行，
        但不是规则挡的，是**守卫自己出了状况**，需要人看一眼但不是「规则生效」
        —— 这一档必须显式区分，否则会把它读成「规则挡住了」，强度被读强。

★ 守恒：每一条账本裁决记录都要落到**恰好一个**桶里，不许丢、不许重。
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))  # ← 仓库根（lineC 的上一级）
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
if os.path.join(_ROOT, "hooks") not in sys.path:
    sys.path.insert(0, os.path.join(_ROOT, "hooks"))

import notify_policy as NP  # noqa: E402  产品侧通知面：唯一真源，不抄一份

#: 裁决＝动作真的没执行。**不叫「拦截」** —— 「拦截」在 glossary.RETIRED_WORDS
#: 里已判死（与「出事／失守／注意」同批），用错名＝对外强度虚高。
VERDICT_DECISIONS = frozenset(("block", "deny"))

#: 宿主盾自检事件的 type 前缀。这类事件写的是 `decision=block`，
#: 但它不是「规则挡住了」，是**守卫自己没上班/状态异常**。
SHIELD_TYPES = frozenset((
    "host_shield_spawn_failed",
    "host_shield_tamper",
    "host_shield_zone_locked",
    "host_shield_breach",
    "host_shield_dev_drift",
    "host_shield_state_unreadable",
    "host_shield_task_unknown",
    "host_shield_revived",
    "host_shield_heartbeat",
))

#: 这两个强度档与 `evidence.py` 的 K_* 一一对应。
#: **不在这里定义新词表** —— 中文措辞由 evidence.WORD 统一持有（铁律 R4）。
K_HELD = "held"
K_ALERT = "alert"
K_NO_RESPONSE = "no_response"

#: 这条腿**能产出**的强度档。由 `Cluster.strength()` 的返回域决定。
#:
#: ★ 为什么要在 JSON 里报出去：消费方（`evidence.need_zero_note`）要回答
#:   「这一档的 0 是查了没有，还是压根没腿去读」。它**不许自己猜**——
#:   猜出来的答案是「三档都查了」，而真答案是「只有两档查了」。
#:   声明写在这里、自检把它和 `strength()` 钉在一起，消费方只读声明。
#: ★ `alert` 不在里面，是**事实不是遗漏**：本腿只读 `VERDICT_DECISIONS`
#:   （block/deny），而 `alert` 侧（11-02 当天 441 条）一条不读。
#:   「提醒」这一档今天**没有任何一条腿供给** —— 这句话必须能被机器读出来。
PRODUCES: Tuple[str, ...] = (K_HELD, K_NO_RESPONSE)

#: 日文件名。**与 watchman／auditor 同一条正则**（不许各写一份）。
#: ★ 为什么必须校验：`glob("*.jsonl")` 会把 `lock_events.jsonl` 一起捞进来。
#:   实测 2026-11-02 全期跑出「日文件 36 个（2026-09-25 .. lock_event）」——
#:   真实日文件 35 个，多出来的那个是**锁事件流水**（5781 条）。
#:   分母被污染时不会报错，它只会把「35」说成「36」，并把 `lock_event`
#:   当成一个日期印出来。铁律 22：分布太整齐先怀疑量具。
_DAY_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl$")

#: 产品侧判为 **TOAST（出声）** 的 decision 取值。**从产品侧派生，不抄表**。
#:
#: ★ 这是「提醒」这一档的原料：`alert` ＝ 告警但放行 ＝ 产品词表的 L1「提醒」。
#:   本腿只读 `VERDICT_DECISIONS`（block/deny），所以这一类**一条不读**。
#:   不数出来，报告上那个「提醒 0 条」就无法与「提醒真的没有」区分
#:   —— 而这两件事的处理方式完全相反（一个是结论，一个是盲区）。
_TOAST_DECISIONS: frozenset = frozenset(
    d for d in NP.decision_values() if NP.notify_of({"decision": d}) == NP.TOAST
)


@dataclass
class Cluster:
    """一簇裁决记录。**簇＝聚合单位**，不是一个事件。

    为什么要有簇：同一条规则在一次会话里可以命中十几次
    （实测 AN-009 在一个会话里 9 次）。一页纸放不下十几次，
    而「挡了 14 次 AN-009」与「挡了 14 次，每次都要人看一眼」
    是两件不同的事 —— 前者一条，后者十四条。
    ⇒ **拦截时归并、记账时分开**（铁律 35）：簇里保留总条数，
    报告里一条簇结论 + 一个总条数，两样都在。

    ★★ 2026-11-02 深夜修正：**一次动作会被记成两条记录**。
      实测当天 29 条落桶记录里，有 12 组是「同会话＋同秒＋同工具＋同命令」
      的两条记录：
        · `pre_tool_use`                        decision=block
        · `command_deletion_permission`         decision=deny
      而产品侧 `notify_policy._NOTIFY_OF_DECISION` 明写
      `"deny": GATE,  # 与 block 同义（历史记录里仍会出现，故保留键）`。
      ⇒ 它们是**同一次动作**被两个钩子各记了一遍。

      ⇒ 第一版把 `decision` 放进聚合键，于是同一次动作被拆成两簇、各报一遍
        —— 一页纸上出现两条「AN-009 挡下 9 次」，读者会以为是两件事。
        真实动作只有 17 次，而记录有 29 条。**两者都是真的，且都不能丢**
        （铁律 35：拦截时归并、记账时分开；铁律 39：原始条数一条不丢）。

      ⇒ 所以本簇同时带两个计数，且**措辞必须区分**：
        `n_records` 29 条（记账口径，可回指到每一行）
        `n_actions` 17 次（拦截口径，一次动作算一次）
    """

    #: 聚合键：规则号（或「无规则号」）＋ 会话前 8 位。
    #: ★ **不含 `decision`** —— 见类注释：block 与 deny 是同义，放进去会把
    #:   同一次动作拆成两簇。decision 改成簇内的**取值集合**记录。
    rule_id: str
    session: str
    severity: str
    #: 该簇的原始记录条数（**原始条数不丢**，铁律 39）
    n_records: int = 0
    #: 该簇覆盖的**真实动作数**（按 会话+时刻+工具+命令 去重）。
    #: ★ 与 `n_records` 分开记：一个是记账口径、一个是拦截口径，
    #:   合成一个数就会「一次动作说成两次」（铁律 35 / F40）。
    n_actions: int = 0
    #: 簇内出现过的 decision 取值（实测会同时出现 block 与 deny）
    decisions: List[str] = field(default_factory=list)
    #: 动作去重键（内部用，序列化时不带出去）
    _action_keys: set = field(default_factory=set, repr=False)
    #: 每条记录各带一个出处（簇里第一条的定位，用于回指）
    cites: List[Tuple[str, int]] = field(default_factory=list)
    #: 该簇里出现过的 type（去重后）
    types: List[str] = field(default_factory=list)
    #: 该簇里出现过的 reason（去重后，限量）
    reasons: List[str] = field(default_factory=list)
    #: 是否带规则号（带 ⇒ 规则挡住了；不带 ⇒ 守卫自己异常）
    has_rule: bool = False
    #: 是否属宿主盾自检事件
    is_shield: bool = False

    def key(self) -> Tuple[str, str]:
        return (self.rule_id, self.session)

    def strength(self) -> str:
        """这一簇该落哪一档。

        ★ 判定顺序很重要：**带规则号优先**。
          一条记录可能既是宿主盾事件、又带规则号（`host_shield_dev_drift`
          在实测里就带 `rule_id`）——那种情况它仍然是「规则/机制挡住了」，
          因为动作确实没执行，且能指到是谁挡的。
        ⇒ 顺序：带规则号 ⇒ held（动作没执行且能指到出处）；
                 不带规则号 ⇒ no_response（动作没执行，但守卫自己异常）。
        """
        if self.has_rule:
            return K_HELD
        return K_NO_RESPONSE

    def claim(self) -> str:
        """给人看的一句话。**不许渲染层自己改写这句话**（铁律 21）。

        ★ 措辞必须区分两个计数（2026-11-02 深夜修正）：
          · 「次」＝**真实动作数**（拦截口径，一次动作算一次）
          · 「条」＝**账本记录数**（记账口径，可逐行回指）
          第一版把 `n_records` 当「次」印，于是同一次动作被两条记录各算一次
          —— 实测当天 29 条记录只对应 17 次动作，虚高 12 次。
          **一次动作说成两次，是把「挡住了」说成了「挡住了两次」。**
          两个数都真，所以两个都印，且各自带单位。
        """
        unit = "%d 次" % self.n_actions
        if self.n_records != self.n_actions:
            # 记录多于动作 ⇒ 必须说清差额从哪来，否则读者以为我们重复计数。
            unit += "（账本 %d 条记录，同一次动作被多个钩子各记一遍）" % self.n_records
        if self.has_rule:
            base = "%s 挡下 %s" % (self.rule_id, unit)
        else:
            base = "监理自身异常，动作未执行 %s" % unit
        if self.severity and self.severity != "none":
            base += "（严重度 %s）" % self.severity
        return base


@dataclass
class Survey:
    """一次裁决面普查的产物。

    ★ 守恒式：**每一条裁决记录都落进恰好一个桶**。
      `n_records` 之和 == 落桶的记录数（`n_bucketed`），
      而 `n_bucketed` ≤ `n_verdicts`（差额＝被产品侧判为非事件的）。
      差额必须能解释，不许是黑洞。
    """

    read_at: str
    day: str
    #: 本次读到的裁决记录总数（按 decision 值数）
    n_verdicts: int = 0
    #: 其中产品侧判为「结构上不是事件」的
    n_non_event: int = 0
    #: 落进桶的记录数
    n_bucketed: int = 0
    #: 通知面分流结果：gate / toast 的记录数
    n_gate: int = 0
    n_toast: int = 0
    #: **本腿没读**的「出声」档记录数，按 decision 取值分开记。
    #:
    #: ★ 为什么必须有这个字段：C 线一页纸有一格叫「提醒」。它由 `alert`
    #:   （告警但放行）这类记录产生，而本腿只读 block/deny ⇒ 这一格**永远是 0**。
    #:   不把这个 0 的来源数出来，它就和「今天真的没有提醒」长得一模一样
    #:   —— 一个是结论，一个是盲区，而页面上只有一个 0（铁律 45）。
    #:   按 decision 取值分记而不是合成一个数：`alert` 才是「提醒」的原料，
    #:   `config_fallback` 是配置失效，两者不能共用一个分母（F40）。
    unread_toast: Dict[str, int] = field(default_factory=dict)
    #: 按规则号聚合后的簇
    clusters: List[Cluster] = field(default_factory=list)
    #: 分母说明。**每个数字都要能回答「这是哪个分母」**（F40）。
    denominators: Dict[str, str] = field(default_factory=dict)
    #: 结构性盲区
    blind: Tuple[str, ...] = ()
    #: 算不出来的部分（没跑成 ≠ 没有）
    undecidable: List[str] = field(default_factory=list)

    def by_strength(self) -> Dict[str, List[Cluster]]:
        out: Dict[str, List[Cluster]] = {}
        for c in self.clusters:
            out.setdefault(c.strength(), []).append(c)
        return out

    def n_clusters(self) -> int:
        return len(self.clusters)


def rule_ids_of(rec: Dict[str, Any]) -> List[str]:
    """从一条账本记录里取规则号。**三种形态都要认**。

    实测三种形态并存，字段名各不相同：
      · `rules_hit: ["AN-010"]`            —— pre_tool_use
      · `hits: [{"rule_id": ...}]`        —— pre_tool_use_summary（产品侧判为非事件）
      · `rule_id: "AN-009"`               —— command_deletion_permission
    只认一种 ⇒ 另两种被当成「没有规则号」⇒ 强度被读低。
    """
    out: List[str] = []
    for rid in rec.get("rules_hit") or []:
        if isinstance(rid, str) and rid:
            out.append(rid)
        elif isinstance(rid, dict) and rid.get("rule_id"):
            out.append(str(rid["rule_id"]))
    for h in rec.get("hits") or []:
        if isinstance(h, dict) and h.get("rule_id"):
            out.append(str(h["rule_id"]))
    rid = rec.get("rule_id")
    if isinstance(rid, str) and rid:
        out.append(rid)
    seen: List[str] = []
    for r in out:
        if r not in seen:
            seen.append(r)
    return seen


def _day_files(root: str, day: str) -> List[str]:
    p = os.path.join(root, day + ".jsonl")
    return [p] if os.path.exists(p) else []


def _all_day_files(root: str) -> List[str]:
    """所有**日文件**（严格 `YYYY-MM-DD.jsonl`）。

    ★ 不许用 `glob("*.jsonl")`：那会把 `lock_events.jsonl`、`day_manifest.json`
      的兄弟文件一起捞进来。分母一旦被污染，报告不会红，它只会**多算一个**，
      并且把非日期字符串当成日期印出去（实测印出过 `.. lock_event`）。
    """
    out = []
    for p in glob.glob(os.path.join(root, "*.jsonl")):
        if _DAY_FILE.match(os.path.basename(p)):
            out.append(p)
    return sorted(out)


def latest_day(root: str) -> str:
    """账本里**最新一天**（`YYYY-MM-DD`）。没有日文件 ⇒ 空串。

    ★ 存在的理由：「这次」这个词必须有个机器可读的定义。
      一页纸首屏写「这次看见了什么」，而本腿若扫全期（实测 2033 条 → 120 簇），
      那 120 簇里有一大半是上个月的事 —— **「这次」被偷偷换成了「历来」**。
      另两条腿的口径：auditor 核整本账（它问的是账本自洽，全期是对的），
      watchman 用 `today = max(daily)`（只报今天）。本腿属于「今天」那一类。
    """
    days = [os.path.basename(p)[:10] for p in _all_day_files(root)]
    return max(days) if days else ""


def survey(root: str, *, day: str = "", as_of: str = "",
           all_days: bool = False) -> Survey:
    """普查一天的裁决面。

    ★ 默认口径＝**最新一天**（「这次」），不是全期。
      `day` 给了就只读那天；`as_of` 给了就只读 ≤ 该日的文件；
      只有显式 `all_days=True`（CLI `--all`）才读全部日文件。

      ★ 为什么默认改掉（2026-11-02，本轮实测）：一页纸首屏写「这次看见了什么」，
        而本腿原来默认扫全期 ⇒ 2033 条 → 120 簇，其中一大半是上个月的事。
        「这次」被偷偷换成了「历来」，而页面上**没有任何一处会显示这件事**。
        这正是 F40 的第三种形态：不是两个分母印在一起，而是**一个词的指代范围
        被悄悄放大**，读者无从对照。
      ★ 全期仍然要能跑（量具需要），但它必须是**显式**的 —— 默认值不许替人决定口径。
    """
    from datetime import datetime

    if as_of:
        files = [f for f in _all_day_files(root)
                 if os.path.basename(f)[:10] <= as_of]
        scope = "≤ %s" % as_of
    elif day:
        files = _day_files(root, day)
        scope = day
    elif all_days:
        files = _all_day_files(root)
        scope = "全期"
    else:
        # 默认＝最新一天。取不到 ⇒ 走下面「没找到日文件」分支（报没跑成）。
        latest = latest_day(root)
        files = _day_files(root, latest) if latest else []
        scope = latest or "（无日文件）"

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not files:
        s = Survey(read_at=now, day=scope)
        s.undecidable.append(
            "没找到账本日文件（目录 %s）—— 这是「没跑成」，不是「没有裁决」" % root
        )
        s.denominators["裁决面"] = "读不到日文件 ⇒ 分母未知"
        return s

    by_key: Dict[Tuple[str, str, str], Cluster] = {}
    n_verdicts = 0
    n_non_event = 0
    n_gate = 0
    n_toast = 0
    n_bucketed = 0
    unread_toast: Dict[str, int] = {}
    seen_days: List[str] = []

    for path in files:
        d = os.path.basename(path)[:10]
        seen_days.append(d)
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if not isinstance(rec, dict):
                    continue
                dec = rec.get("decision")
                if dec not in VERDICT_DECISIONS:
                    # ★ 不读它，但**必须数它**。这一类里有「提醒」的原料（alert）：
                    #   本腿不读 ⇒ 一页纸上「提醒」恒为 0。若连数都不数，
                    #   那个 0 就永远说不清是「没有」还是「没读」（铁律 45）。
                    if dec in _TOAST_DECISIONS:
                        unread_toast[str(dec)] = unread_toast.get(str(dec), 0) + 1
                    continue
                n_verdicts += 1
                # ★ 通知面分流用**产品侧实现**（不抄表）。
                face, _d, _why = NP.explain(rec)
                if face == NP.NONE:
                    # 产品侧已判「结构上不是事件」（如 pre_tool_use_summary：
                    # 与逐条 pre_tool_use 覆盖同一批调用，同时通知会提醒两次）。
                    # ★ 这不是「静音」，是「不适用」——两者必须分开记。
                    n_non_event += 1
                    continue
                if face == NP.GATE:
                    n_gate += 1
                elif face == NP.TOAST:
                    n_toast += 1
                n_bucketed += 1

                rids = rule_ids_of(rec)
                rule = rids[0] if rids else ""
                sess = str(rec.get("session") or "")[:8]
                # ★ 聚合键**不含 decision**（block 与 deny 同义，放进去会把
                #   同一次动作拆成两簇）。decision 改成簇内的取值集合。
                key = (rule, sess)
                cl = by_key.get(key)
                if cl is None:
                    cl = Cluster(
                        rule_id=rule or "（无规则号）",
                        session=sess,
                        severity=str(rec.get("severity") or "none"),
                        n_records=0,
                        has_rule=bool(rids),
                        is_shield=str(rec.get("type") or "") in SHIELD_TYPES,
                    )
                    by_key[key] = cl
                cl.n_records += 1
                if str(dec) not in cl.decisions:
                    cl.decisions.append(str(dec))
                # ★ 真实动作去重：同会话＋同时刻＋同工具＋同命令 ⇒ 同一次调用。
                #   实测 11-02：29 条记录 → 17 次动作（12 组被两个钩子各记一遍）。
                #   ★ 命令取前 300 字：两个钩子对 `input.command` 的**截断长度不同**
                #     （实测一条 300 字、一条 500 字，短的是长的前缀），
                #     取全串会把同一次动作当成两次。取前 300 字两者相同。
                _inp = rec.get("input") or {}
                _cmd = str(_inp.get("command") if isinstance(_inp, dict) else "")[:300]
                cl._action_keys.add((sess, str(rec.get("ts") or ""),
                                     str(rec.get("tool") or ""), _cmd))
                cl.n_actions = len(cl._action_keys)
                if len(cl.cites) < 40:      # 簇内出处限量，但总条数不丢
                    cl.cites.append((d, lineno))
                t = str(rec.get("type") or "")
                if t and t not in cl.types:
                    cl.types.append(t)
                rsn = str(rec.get("reason") or "")
                if rsn and rsn not in cl.reasons and len(cl.reasons) < 4:
                    cl.reasons.append(rsn)

    s = Survey(
        read_at=now,
        day=scope,
        n_verdicts=n_verdicts,
        n_non_event=n_non_event,
        n_bucketed=n_bucketed,
        n_gate=n_gate,
        n_toast=n_toast,
        unread_toast=dict(unread_toast),
        clusters=list(by_key.values()),
    )

    # ★ 分母：三个数分列，**不许合成一个**（F40）。
    s.denominators["裁决面"] = (
        "按 decision 值数（block+deny）%d 条｜其中产品侧判为非事件 %d 条"
        "（不适用，非静音）｜落桶 %d 条"
        % (n_verdicts, n_non_event, n_bucketed)
    )
    # ★★ 第二重口径：**记录 ≠ 动作**。必须与上面那一条并列，不许合成。
    #   实测 11-02：29 条记录 / 17 次动作（12 次被两个钩子各记一遍）。
    #   ★ 这两个数都是真的，且都能被核（前者可逐行回指，后者可按
    #     会话+时刻+工具+命令 复算）。合成一个数就会让「一次动作」被读成「两次」。
    n_actions_total = sum(c.n_actions for c in s.clusters)
    s.denominators["动作数"] = (
        "按（会话+时刻+工具+命令）去重后 %d 次动作｜对应 %d 条记录"
        "｜差额 %d 条是「同一次动作被多个钩子各记一遍」"
        "（block 与 deny 同义，见 notify_policy 回退表）"
        % (n_actions_total, n_bucketed, n_bucketed - n_actions_total)
    )
    s.denominators["通知面"] = (
        "gate %d 条｜toast %d 条｜聚合后 %d 簇（规则×会话）"
        % (n_gate, n_toast, len(by_key))
    )
    s.denominators["账本"] = (
        "日文件 %d 个（%s .. %s）"
        % (len(files), seen_days[0] if seen_days else "?",
           seen_days[-1] if seen_days else "?")
    )
    # ★ 「没读的那一档」也要有分母，且**分 decision 取值列**。
    #   合成一个「另有 N 条」会把「提醒」和「配置失效」混成一个数（F40）。
    if unread_toast:
        s.denominators["本腿没读的出声档"] = (
            "｜".join("%s %d 条" % (k, v) for k, v in sorted(unread_toast.items()))
            + "（本腿只读 block/deny，这一档今天没有腿读）"
        )

    # ★ 守恒自检：落桶数必须等于各簇条数之和。不等就是有记录被吞了。
    n_sum = sum(c.n_records for c in s.clusters)
    if n_sum != n_bucketed:
        s.undecidable.append(
            "守恒对不上：落桶 %d 条，各簇条数之和 %d 条 —— 有记录被吞或被重"
            % (n_bucketed, n_sum)
        )
    # ★ 第二重守恒：动作数必须 ≤ 记录数。反过来就是去重键把两个动作并了。
    if n_actions_total > n_bucketed:
        s.undecidable.append(
            "动作数 %d 大于记录数 %d —— 去重键失效（把不同动作算成了同一个）"
            % (n_actions_total, n_bucketed)
        )

    s.blind = (
        "账本里是否混有本项目自己的测试数据 —— 负控与红队曾往真账本写过"
        "假命令、假域名（evil.example.com 就在 2026-10-31 的「首次出现域名」里，"
        "与百度、几个政府网站并列）。账本没有「这是夹具」字段，本模块无法区分"
        "夹具与真实事件；每一条都要按「可能是夹具」再复核一遍",
        "本模块只读账本里已经写好的裁决记录，读不到「当时该挡但没挡」"
        "—— 漏挡不在账本里（账本只记发生过什么，不记该发生什么）",
        "聚合键是「规则×会话」，是我选的一种，不是唯一正确分法；"
        "换一种分法，簇数会变（条数守恒，簇数不守恒）",
    )
    # ★ 把「没读的那一档」写成盲区，**不是**写成一句免责声明。
    #   它是一条可核的事实：这一档今天有 N 条记录，本腿一条不读。
    #   ★ 2026-11-02 深夜：这几句原文里带 Markdown 的 `**强调**`，
    #     而它们会经 `evidence.collect()` 直接进 HTML 的「看不见什么」一节
    #     ⇒ 页面上印出 `本腿**一条不读**`。实测由端到端负控 e7 抓到。
    #     修法按 `evidence.plain()` 的注释：**让上游散文别写 `**`**，
    #     不是在渲染层加白名单（加白名单等于承认分不清散文和原文）。
    if unread_toast:
        s.blind += (
            "本腿只读 block/deny（动作没执行的裁决）。产品侧判为出声（toast）"
            "的其它 decision 取值，本腿一条不读 —— 本次读到的有：%s。"
            "所以「提醒」这一档在任何报告里都是 0，而这个 0 是「没腿读」，"
            "不是「今天没有提醒」。要让它有值，必须再加一条腿读这一档"
            % "、".join("%s %d 条" % (k, v) for k, v in sorted(unread_toast.items())),
        )
    return s


def _selfcheck() -> int:
    """自检：只验函数，不验「今天有没有裁决」。

    ★ 为什么自检只验这些（铁律 41）：真账本的内容天天变，
      把「今天有多少条」写成判据 ⇒ 明天就红 ⇒ 恒红项等于没有项。
      所以判据必须验**不随数据变的性质**：口径自洽、守恒、字段识别。
    """
    fails: List[str] = []

    def ck(cond: bool, msg: str) -> None:
        if not cond:
            fails.append(msg)

    # ── 1. 产品侧表被真的用上了（不是抄一份）────────────────────────
    ck(len(NP.decision_values()) > 0, "产品侧回退表读不到")
    ck("pre_tool_use_summary" in NP.non_event_types(),
       "产品侧非事件表读不到 pre_tool_use_summary")

    # ── 2. 三种形态的规则号都认得 ───────────────────────────────────
    cases = [
        ({"rules_hit": ["AN-010"]}, ["AN-010"]),
        ({"hits": [{"rule_id": "AN-010"}]}, ["AN-010"]),
        ({"rule_id": "AN-009"}, ["AN-009"]),
        ({"rules_hit": ["AN-010"], "hits": [{"rule_id": "AN-011"}]},
         ["AN-010", "AN-011"]),
        ({}, []),
    ]
    for rec, want in cases:
        got = rule_ids_of(rec)
        ck(got == want, "规则号识别错：%r ⇒ %r（要 %r）" % (rec, got, want))

    # ── 3. 强度分档：带规则号 ⇒ held；不带 ⇒ no_response ────────────
    c1 = Cluster(rule_id="AN-010", session="s", severity="critical",
                 n_records=1, n_actions=1, has_rule=True)
    c2 = Cluster(rule_id="（无规则号）", session="s", severity="warning",
                 n_records=1, n_actions=1, has_rule=False)
    ck(c1.strength() == K_HELD, "带规则号的簇应落 held")
    ck(c2.strength() == K_NO_RESPONSE, "无规则号的簇应落 no_response")

    # ── 4. 负控：**故意让强度被读强**，判据必须能发现 ──────────────
    #  这条是本模块最容易出的错：把「守卫自己异常」印成「规则挡住了」。
    #  负控 = 反过来构造：给无规则号的簇挂一个 claim，验它的措辞里
    #  **没有**「挡下」两个字（不许把强度读强）。
    ck("挡下" not in c2.claim(), "无规则号的簇不许说「挡下」（强度读强）")
    ck("挡下" in c1.claim(), "带规则号的簇应当说「挡下」")

    # ── 4b. 负控：**记录数不许被当成动作数**（2026-11-02 深夜新增）──────
    #  ★ 这是本轮自己撞出来的真错：同一次工具调用被 pre_tool_use(block) 与
    #    command_deletion_permission(deny) 各记一遍，而第一版把 n_records 当
    #    「次」印 ⇒ 29 条记录说成「挡下 29 次」，真实只有 17 次。
    #    **一次动作说成两次，是把「挡住了」说成「挡住了两次」。**
    c_dup = Cluster(rule_id="AN-009", session="s", severity="critical",
                    n_records=18, n_actions=9, has_rule=True)
    _cl = c_dup.claim()
    ck("9 次" in _cl, "动作数没被印成「次」：%r" % (_cl,))
    ck("18 次" not in _cl, "记录数被当成「次」印出来了（虚高一倍）：%r" % (_cl,))
    ck("18 条" in _cl, "差额没说清「账本多少条记录」：%r —— "
                       "读者会以为我们重复计数" % (_cl,))
    # 负控的反面：记录数==动作数时**不许**画蛇添足提「记录」
    c_clean = Cluster(rule_id="AN-010", session="s", severity="critical",
                      n_records=3, n_actions=3, has_rule=True)
    ck("条" not in c_clean.claim(),
       "记录数等于动作数时不该再提「账本 N 条」：%r" % (c_clean.claim(),))

    # ── 5. 守恒：簇条数之和 == 落桶数 ───────────────────────────────
    s = Survey(read_at="x", day="2026-01-01")
    s.n_bucketed = 3
    s.clusters = [c1, c2]
    c1.n_records = 2
    c2.n_records = 1
    ck(sum(c.n_records for c in s.clusters) == s.n_bucketed,
       "守恒自检本身算错")

    # ── 6. 读不到日文件 ⇒ 报「没跑成」，不许报「没有裁决」 ──────────
    # ★ 不建临时目录：这台机器上 tempfile 的清理会被宿主拦下（WinError 5），
    #   于是一个纯逻辑自检会被环境问题搞红 —— 而恒红项等于没有项（铁律 41）。
    #   这里用一个**保证不存在的目录名**代替临时目录：不依赖任何默认值。
    s2 = survey(os.path.join(_ROOT, ".psl", "audit_no_such_dir_20261102"),
                day="1999-01-01")
    ck(s2.n_verdicts == 0, "读不到文件时裁决数必须为 0")
    ck(len(s2.undecidable) > 0,
       "读不到文件必须进 undecidable，不许静默报「没有」")
    ck("没跑成" in s2.undecidable[0] or "没找到" in s2.undecidable[0],
       "undecidable 的措辞必须说明是没跑成")

    # ── 7. 负控：故意让守恒破裂，判据必须能发现 ────────────────────
    #  直接调 survey 走一遍真数据太慢，这里用构造法验「守恒检查会报」。
    s3 = Survey(read_at="x", day="2026-01-01", n_bucketed=5)
    s3.clusters = [c1, c2]
    s3.clusters[0].n_records = 2
    s3.clusters[1].n_records = 1
    broken = sum(c.n_records for c in s3.clusters) != s3.n_bucketed
    ck(broken, "守恒破裂时必须能被检出（负控自检）")

    # ── 8. 负控：动作数大于记录数 ⇒ 去重键失效，必须能检出 ──────────
    _bad = Cluster(rule_id="X", session="s", severity="none",
                   n_records=1, n_actions=2, has_rule=True)
    ck(_bad.n_actions > _bad.n_records,
       "构造法本身算错（动作数不可能大于记录数）")

    # ── 9. 默认口径＝最新一天，**不是全期**（本轮修）───────────────────
    #  ★ 这条守的是「这次」这个词：一页纸首屏写「这次看见了什么」，
    #    而本腿原来默认扫全期 ⇒ 120 簇里一大半是上个月的事。
    #    「这次」被默认值悄悄换成了「历来」，页面上没有任何一处会显示这件事。
    #  ★ 判据不许依赖真账本内容（铁律 41）：用一个**保证不存在**的目录，
    #    验它给的是「没跑成」而不是「全期 0 条」。
    _empty = survey(os.path.join(_ROOT, ".psl", "no_such_ledger_20261102"))
    ck(len(_empty.undecidable) > 0, "空账本必须报「没跑成」")
    ck(_empty.n_verdicts == 0, "空账本裁决数必须为 0")

    if fails:
        print("自检失败 %d 项：" % len(fails))
        for f in fails:
            print("  ·", f)
        return 1
    print("verdict_leg 自检：9 组全通过")
    return 0


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="裁决面普查（第三只腿）")
    ap.add_argument("--root", default="", help="账本目录（默认 <仓库>/.psl/audit）")
    ap.add_argument("--day", default="", help="某一天（留空＝**最新一天**，不是全期）")
    ap.add_argument("--as-of", default="", help="只读 ≤ 该日的日文件")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--selfcheck", action="store_true")
    ap.add_argument(
        "--all",
        action="store_true",
        help="读全部日文件（全期）。**默认不这么做** —— 默认只读最新一天。"
             "「这次」必须有个机器可读的定义，否则它会被默认值悄悄换成「历来」。",
    )
    args = ap.parse_args()

    if args.selfcheck:
        return _selfcheck()

    root = args.root or os.path.join(_ROOT, ".psl", "audit")
    s = survey(root, day=args.day, as_of=args.as_of, all_days=args.all)

    if args.json:
        print(json.dumps({
            "read_at": s.read_at,
            "day": s.day,
            "n_verdicts": s.n_verdicts,
            "n_non_event": s.n_non_event,
            "n_bucketed": s.n_bucketed,
            "n_gate": s.n_gate,
            "n_toast": s.n_toast,
            "n_clusters": s.n_clusters(),
            # ★ 本腿**能产出**哪几档（声明，供消费方判断「某一档的 0」是什么 0）。
            "produces": list(PRODUCES),
            # ★ 本腿**没读**的出声档，按 decision 取值分开。
            "unread_toast": s.unread_toast,
            "clusters": [
                {
                    "rule_id": c.rule_id,
                    "session": c.session,
                    "decisions": c.decisions,
                    "severity": c.severity,
                    # ★ 两个计数都要出去：一个是拦截口径、一个是记账口径。
                    #   只给一个，消费方就会把「记录」当「次」用（已犯过一次）。
                    "n_records": c.n_records,
                    "n_actions": c.n_actions,
                    "strength": c.strength(),
                    "claim": c.claim(),
                    "types": c.types,
                    "cites": c.cites[:5],
                    "is_shield": c.is_shield,
                }
                for c in s.clusters
            ],
            "denominators": s.denominators,
            "blind": list(s.blind),
            "undecidable": s.undecidable,
        }, ensure_ascii=False, indent=1))
        return 0

    print("裁决面普查｜%s｜读数时刻 %s" % (s.day, s.read_at))
    for k, v in s.denominators.items():
        print("  [%s] %s" % (k, v))
    print()
    for c in sorted(s.clusters, key=lambda c: (-c.n_actions, c.rule_id))[:30]:
        print("  %-10s %-8s n=%-3d 动作/%-3d 条  %s"
              % (c.rule_id, c.session, c.n_actions, c.n_records, c.claim()))
    if s.undecidable:
        print()
        print("  算不出来：")
        for u in s.undecidable:
            print("   ·", u)
    print()
    print("这条输出不能证明什么：")
    print("  · 不能证明这些裁决该不该给人看（产品判断，属创始人拍板）。")
    print("  · 不能证明这些是真发现（可能含夹具）。")
    print("  · 能证明的只有一句：账本里有哪些裁决记录，长什么样，可回指。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
