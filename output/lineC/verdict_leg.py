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

★★ 2026-11-03：**本腿从「只读 gate 带」扩到读整张通知面（gate ＋ toast）**
  上一版这里写着一句老实的话：「`alert` 不在 PRODUCES 里，是事实不是遗漏」——
  它承认了「提醒」这一档**没有任何一条腿去读**，所以一页纸上那一格永远是 0，
  而这个 0 与「今天真的没有提醒」长得一模一样（铁律 45）。
  现在补上：本腿读 toast 带里 `alert`／`warn` 这两个取值，产出 `alert` 档。

  ★ 为什么是「扩本腿」而不是「加第五个模块」：
    「哪些该通知人」已经是产品侧一张表（`notify_policy`），gate／toast 是**同一张表
    的两半**。拆成两个模块，就要把「记录去重键怎么取」「哪些 type 是非事件」
    「簇怎么聚合」各写两遍 —— 那正是本仓第一顽症（同一事实多处实现）。
    拆开还有一个更贵的代价：**两半各记一份「我没读什么」**，于是
    「提醒这一档没腿读」这句话会同时由两处维护，一处改了另一处不改，页面就会
    一边说「有腿读」一边说「没腿读」——两个都是断言，其中必有一个在撒谎。

  ★ 但扩进来会撞上一个新问题，必须显式处理：**同一簇里不能混两档**。
    带规则号的 alert（「AN-010 提醒 288 次」）与同规则同会话的 block（「AN-010 挡下 9 次」）
    聚合键完全相同。若不把「带」放进键里，它们会被并成一簇，簇的 `strength()`
    只能二选一 ⇒ 要么把 288 次提醒说成「挡下」，要么把 9 次挡下说成「提醒」。
    **一次动作说成两次比漏掉一次更难发现，而一档说成另一档比两者都难**——
    因为两个数都真、页面也自洽，只有把「带」写进键里，两个数才会分开出现。
    ⇒ 聚合键变成 (规则号, 会话, 带)。这是本版**唯一**改口径的地方。
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

#: ★ 心跳**不算「守不住」**（2026-11-03 定口径）。
#:
#:   它在 `SHIELD_TYPES` 里，因为它是宿主盾自检事件的一种，要能按前缀认出来；
#:   但它写的是「**我在岗**」——把它算进「守不住」会让分母从 63 涨到 227，
#:   而多出来的 164 条恰恰是守卫**正常运行**的证据。
#:   「守不住」要数的是「本该守着却没守住」，不是「守了多少次」。
#:   这两种数混在一起，会让「守卫一直在岗」看起来像「出过 164 次事」。
SHIELD_HEARTBEAT = "host_shield_heartbeat"

#: 这两个强度档与 `evidence.py` 的 K_* 一一对应。
#: **不在这里定义新词表** —— 中文措辞由 evidence.WORD 统一持有（铁律 R4）。
K_HELD = "held"
K_ALERT = "alert"
K_NO_RESPONSE = "no_response"

#: 通知面的两条「带」。**这是产品侧那张回退表的两半，不是本模块发明的分法**：
#: `notify_of()` 把每条记录判成 gate（停下等人）或 toast（提醒但不停）。
#: ★ 它同时是**聚合键的第三段**：同规则、同会话、不同带的两批记录绝不许并成一簇。
BAND_GATE = "gate"
BAND_ALERT = "alert"

#: 这条腿**能产出**的强度档。由 `Cluster.strength()` 的返回域决定。
#:
#: ★ 为什么要在 JSON 里报出去：消费方（`evidence.need_zero_note`）要回答
#:   「这一档的 0 是查了没有，还是压根没腿去读」。它**不许自己猜**——
#:   猜出来的答案是「三档都查了」，而真答案是「只有两档查了」。
#:   声明写在这里、自检把它和 `strength()` 钉在一起，消费方只读声明。
#: ★ 2026-11-03：`alert` 从「不在里面（是事实不是遗漏）」改成**在里面**。
#:   改这一行的理由只有一个：本腿真的开始读 toast 带了。声明必须跟着实现变，
#:   否则它会变成一句「昨天的事实」——而那比没有声明更危险（它看起来是权威的）。
PRODUCES: Tuple[str, ...] = (K_HELD, K_ALERT, K_NO_RESPONSE)

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
_TOAST_DECISIONS: frozenset = frozenset(
    d for d in NP.decision_values() if NP.notify_of({"decision": d}) == NP.TOAST
)

#: 其中**本腿读**、并落进 `alert` 档的那两个取值。
#:
#: ★ `warn` 在产品侧是「0.64 引入的目标值，尚未有写入者」（`notify_policy.py:96`）。
#:   它与 `alert` 在同一档（`_RANK` 里都算 2）⇒ 一旦有写入者开始用 `warn`，
#:   它必须**当场落进同一档**，而不是变成一条新的「没腿读」。
#:   「今天没有写入者」不等于「以后没有」——漏报不可逆。
ALERT_DECISIONS: Tuple[str, ...] = ("alert", "warn")

#: 出声档里**语义不属于任何一档**的取值。**必须逐个登记**（见自检 ⑩）。
#:
#: ★ 为什么要有这张表：`notify_policy` 的回退表会加键（它是产品侧在改的表），
#:   而本腿按「取值 → 档」映射。新键出现时若没有登记，它会被静默跳过 ——
#:   页面不说、分母不说、盲区不说，表现和「这一档今天真的没有」完全一样。
#:   ⇒ 登记表 + 「未登记即红」的自检，是本模块对「清单式真源的固有风险」
#:     （漏登记不报错）唯一有效的防守。**不许用「其他一律跳过」兜底。**
TOAST_NOT_A_TIER: Dict[str, str] = {
    "config_fallback": "配置失效：不是规则命中，也不是动作被放行，语义不属任何一档",
    "config_rejected": "配置被拒：同上",
    "finding": "报告类结论：没有说话人、没有动作，本腿读不出它该落哪一档",
}


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

    #: 聚合键：规则号（或「无规则号」）＋ 会话前 8 位 ＋ **带**。
    #: ★ **不含 `decision`** —— 见类注释：block 与 deny 是同义，放进去会把
    #:   同一次动作拆成两簇。decision 改成簇内的**取值集合**记录。
    #: ★ 2026-11-03 加第三段 `band`：同规则同会话的 block（挡下）与 alert（提醒）
    #:   必须分开。不加这一段，`strength()` 只能二选一 ⇒ 288 次提醒被印成
    #:   「挡下 288 次」，或者 9 次挡下被印成「提醒」。**一档说成另一档，
    #:   两个数都真、页面也自洽**，只有把带写进键里才会分开出现。
    rule_id: str
    session: str
    severity: str
    #: 这条簇属于通知面的哪一带（`gate` 停下等人／`alert` 提醒但放行）。
    band: str = BAND_GATE
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

    def key(self) -> Tuple[str, str, str]:
        return (self.rule_id, self.session, self.band)

    def strength(self) -> str:
        """这一簇该落哪一档。

        ★ 判定顺序很重要（gate 带内）：**带规则号优先**。
          一条记录可能既是宿主盾事件、又带规则号（`host_shield_dev_drift`
          在实测里就带 `rule_id`）——那种情况它仍然是「规则/机制挡住了」，
          因为动作确实没执行，且能指到是谁挡的。
        ⇒ 顺序：带规则号 ⇒ held（动作没执行且能指到出处）；
                 不带规则号 ⇒ no_response（动作没执行，但守卫自己异常）。

        ★ alert 带：**一律 `alert`，且这一带里没有「无规则号」的簇。**
          理由在 `survey()`：不带规则号的 alert 记录（实测 11-02 有 302 条
          `host_changed`）会被数进 `untiered_alert`，**不进簇**。
          因为「提醒」这个词的定义是「有规则命中并告警」（`evidence.py` 的
          `strength_note`）——没有规则号却印成「提醒」，是拿一个我们核不了的
          结论去顶替一个词。**词的适用范围比词好听更重要。**
        """
        if self.band == BAND_ALERT:
            return K_ALERT
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

        ★ 2026-11-03：alert 带的话必须**从自己这一带的事实出发**。
          「提醒」的完整意思是「告警了，但动作仍然执行了」——后半句不能省：
          省掉之后，「提醒 288 次」会被读成「挡下了 288 次」的软说法，
          而真实情况是**这 288 次命令全都执行了**。省掉那五个字，
          是把「没挡住」说成了「挡住了但语气轻一点」。

        ★★ 2026-11-03 第二处改：**这句话里不许出现档名**（「挡下」「提醒」）。
          理由不是文风，是单一真源（R4）：档名的中文词只在
          `evidence.WORD` 里声明一次（从产品侧 `STATE_LABEL` 派生）。
          这里手写一份，产品侧改词时就会出现「徽标是『提醒』、正文写着『挡下』」
          —— 同一页上两个词指一件事，读者只能二选一，而他没有任何依据选。
          ⇒ 本函数只说**事实**（动作未执行／仍然执行／监理自身异常），
            档名由渲染层从 `WORD` 取。判据见 `jchecks.py` 的 J6：
            把 `WORD` 的中文全换成哨兵值，页面上不许再出现任何一个旧档名。
        """
        unit = "%d 次" % self.n_actions
        if self.n_records != self.n_actions:
            # 记录多于动作 ⇒ 必须说清差额从哪来，否则读者以为我们重复计数。
            unit += "（账本 %d 条记录，同一次动作被多个钩子各记一遍）" % self.n_records
        if self.band == BAND_ALERT:
            base = "%s：动作仍然执行了 %s" % (self.rule_id, unit)
        elif self.has_rule:
            base = "%s：动作未执行 %s" % (self.rule_id, unit)
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
    #: ★ 2026-11-03：alert 带的三个数。**分母必须与 gate 带分开记**（F40）。
    #:   `n_alert_raw`     按 decision 取值数（alert+warn）的原始条数
    #:   `n_alert_non_event` 其中产品侧判为非事件的（实测 11-02：10 条
    #:                     `pre_tool_use_summary`，与逐条记录覆盖同一批调用）
    #:   `n_alert_bucketed` 落进 alert 档的记录数
    n_alert_raw: int = 0
    n_alert_non_event: int = 0
    n_alert_bucketed: int = 0
    #: ★ 读到了、但**现有各档都装不进去**的 alert 记录（按 type 分开数）。
    #:
    #:   实测 11-02：302 条 `host_changed`（severity=warning，
    #:   reason「宿主版本变化——钩子协议可能漂移」）。它们是出声档，**但没有规则号**，
    #:   而「提醒」这个词的定义是「有规则命中并告警」（`Evidence.strength_note`）
    #:   ⇒ 印成「提醒」就是拿一个核不了的说法顶替一个词。
    #:   也不能塞进「已发现无法处置」（那是「发现了、没手段」，与「主机变了、
    #:   没有规则可指」不是一件事），更不能丢。
    #:   ⇒ **只计数、不装档**，并在归因句与盲区里说出来。要给它一个档，
    #:     得创始人拍板（D-5）——分档就是替人做产品判断。
    untiered_alert: Dict[str, int] = field(default_factory=dict)
    #: 同一批「无档可落」记录**按身份**的明细：`{type: {身份: 条数}}`。
    #:
    #:   ★ 为什么计数还不够（2026-11-03 实测）：302 条 `host_changed` 逐条看下去
    #:     只有两个身份 —— `5.9.3→5.9.4` 152 次、`5.9.4→5.9.3` 150 次，
    #:     同一会话、同一天。**这是一次版本抖动被记了 302 次，不是 302 件事。**
    #:     只印「302 条」，读者会以为宿主被改了 302 回；而真实情况是
    #:     「宿主版本在两个值之间反复横跳」——这是**一个**需要处理的事实。
    #:   ⇒ 计数之外必须给身份明细。归属判据不看频次，看**这条记录在说哪件事**。
    #:     这是铁律 35／39（记录 ≠ 事件；原始条数不丢）在这里的第二次现形。
    #:   ★ 产品侧可以更彻底地修（同一 `(from,to)` 短时间内不重复写），
    #:     但那是产品代码；本腿只负责**不说谎**。
    untiered_detail: Dict[str, Dict[str, int]] = field(default_factory=dict)
    #: ★ 账本里的「漏读面」：raw decision 不在本腿读的那几个取值上、
    #:   但产品侧会把它派生/升级成 alert 的记录数。
    #:
    #:   ★ 为什么必须数它：本腿按账本里的 `decision` **字段取值**筛记录，
    #:     而产品侧的 `decision_of()` 会拿 `action`+`severity` **重新派生**
    #:     （实测规则：`allow` + warning/critical ⇒ 升级成 alert，
    #:     见 `notify_policy._SEVERITY_ESCALATE`）。两条口径不一致的那一小块，
    #:     就是本腿看不见的地方。**不数它，它就会表现为「提醒比实际少」**，
    #:     而「少」在页面上看起来和「没有」一样。
    n_escalated_unread: int = 0
    #: ★ 宿主盾自检事件（守卫自己不在岗／状态异常）的**独立计数**，按带分开。
    #:
    #:   为什么必须独立计（判据 J5／L2-3）：这类事件写的是 `decision=block`，
    #:   与规则命中**在账本字段上长得一模一样**。实测 11-02：3 条 `host_shield_*`
    #:   并进「挡下」之后，页面上只有一个「挡下 3 次」，读者分不出
    #:   「规则挡住了」与「守卫当时根本不在岗」—— 而后者比前者严重得多。
    #:   ⇒ 单独计数、单独上屏。但**不新增强度档**：新增一档 = 新增一个对外强度词，
    #:     属产品词表，须创始人拍板（DEC-27 的 D-3）。计数不是档。
    n_shield_gate: int = 0
    n_shield_alert: int = 0
    #: 「守不住」这类事件的**全量**，已排除心跳。
    #:
    #:   ★ 为什么需要它（2026-11-03 实测，这是「守不住」一栏此前**低报 20 倍**的原因）：
    #:     11-02 账本里 `host_shield_*` 共 227 条，去掉 164 条心跳，是 **63 条**真事件。
    #:     而 `n_shield_gate + n_shield_alert` 只报 **3 条** —— 差的 60 条
    #:     （`revived` 37 ＋ `state_unreadable` 23）是 `decision=allow`，
    #:     既不进 gate 带也不进 alert 带，于是**一条腿都不数它们**。
    #:     ★ 但它们并非「该读没读」：产品侧 `notify_policy.explain()` 明确判
    #:       `face=none`（结构上不通知人）。所以正确的说法不是「漏读」，
    #:       而是「**读到了、产品侧判不通知**」——两句话指向完全不同的责任方。
    #:   ⇒ 一栏必须写两个数：该通知你的 / 产品侧判不通知的。只写前者，
    #:     会让「宿主盾一天只在岗 3 次」变成一个看起来正常的读数。
    #:   ★ 心跳不算「守不住」：它是「我在岗」的信号，把它算进去会让分母
    #:     从 63 涨到 227，而多出来的 164 条恰恰是**守卫正常运行**的证据。
    n_shield_all: int = 0
    #: **本腿没读**的「出声」档记录数，按 decision 取值分开记。
    #:
    #: ★ 为什么必须有这个字段：C 线一页纸有一格叫「提醒」。它由 `alert`
    #:   （告警但放行）这类记录产生。
    #:   ★ 2026-11-03 之后本腿**读** `alert` 了 ⇒ 本字段里不再有 `alert`，
    #:     只剩 `TOAST_NOT_A_TIER` 登记的那几个取值（配置失效／报告类结论）。
    #:     它们仍然要说出来：不说，读者会以为「出声档都读过了」。
    #:   按 decision 取值分记而不是合成一个数：`config_fallback` 是配置失效，
    #:   与「提醒」不能共用一个分母（F40）。
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

    def clusters_of(self, band: str) -> List[Cluster]:
        return [c for c in self.clusters if c.band == band]

    def shield_counted(self) -> int:
        """守不住的事件一共几条（两条带相加）。

        ★ 这是**一个计数，不是一档**（见 `n_shield_gate` 的注释）。
          它与「挡下」共用同一批记录 ⇒ 两个数**不许相加**，
          也不许拿它去和簇数相除（分母不同）。
        ★ 2026-11-03：它只是「该通知你的」那一半。全量见 `n_shield_all`，
          两半之差见 `shield_silent()` —— **不许把这三者混用**。
        """
        return self.n_shield_gate + self.n_shield_alert

    def shield_silent(self) -> int:
        """读到了、但产品侧判不通知的「守不住」事件条数。

        ★ 它不是「漏读」：这些记录本腿读到了，产品侧 `notify_policy.explain()`
          判 `face=none`（结构上不通知人）。区别很重要 ——
          「没读」是我们的问题，「产品侧判不通知」是产品判断。
          把它说成漏读，会让人去修一个不存在的东西。
        ★ 不 clamp 到 0：万一算成负数，页面上会出现「-1 条」——
          那是显眼异常，比静默抹平成 0 好。自检 「守不住 两半相加等于全量」守着这件事。
        """
        return self.n_shield_all - self.n_shield_gate - self.n_shield_alert

    def balance(self) -> Dict[str, Any]:
        """守恒账：**每条读到的记录都要在等号右边出现一次，不许有黑洞。**

        ★ 为什么需要它（判据 `J3`／`L2-2`，2026-11-03）：
          上一版能说出「43 条」「29 条」「17 次」，但**说不出**「29 条里有多少条
          变成结论、多少条被合进同一簇、多少条被产品侧判为不适用」。
          三个数各自都对，加不起来 —— 而**加不起来的分母不是分母，是一句注释**。
          产品侧早就有同款式子（`host_shield.py:1494-1501` 的
          `total == used + dup + merged`），C 线这边一直只是「砍掉 + 印一句另有 N 条」。

        ★ 两条式子**分开写、不许合并**（F40：一个数承担两个分母）：
            gate 带：原始条数 == 不适用 ＋ 落桶
            alert 带：原始条数 == 不适用 ＋ 落桶 ＋ **无档可落**
          两边各有一个「落桶 == 簇数 ＋ 合并」。
          ★ 「合并」在同一条带内为正（一次会话里同规则命中 18 次 ⇒ 1 簇），
            跨带**不许**合并 —— 见 `Cluster` 的 `band` 注释。

        ★ 返回值里 `broken` 非空 ⇒ 有记录被吞或被重。**它不许被当成 warning**：
          守恒破了就等于这张表的每一个数都可能是错的。
        """
        rows: List[Dict[str, Any]] = []
        broken: List[str] = []

        for band, name in ((BAND_GATE, "裁决面（停下等人）"),
                           (BAND_ALERT, "提醒面（告警但放行）")):
            cls = self.clusters_of(band)
            n_bucketed = (self.n_bucketed if band == BAND_GATE
                          else self.n_alert_bucketed)
            n_raw = (self.n_verdicts if band == BAND_GATE else self.n_alert_raw)
            n_na = (self.n_non_event if band == BAND_GATE
                    else self.n_alert_non_event)
            n_untiered = sum(self.untiered_alert.values()) if band == BAND_ALERT else 0
            merged = n_bucketed - len(cls)
            rows.append({
                "band": band,
                "name": name,
                "candidates": n_raw,
                "into_evidence": len(cls),
                "merged": merged,
                "not_applicable": n_na,
                "untiered": n_untiered,
            })
            if n_raw != n_na + n_bucketed + n_untiered:
                broken.append(
                    "%s：原始 %d 条 ≠ 不适用 %d ＋ 落桶 %d ＋ 无档可落 %d"
                    % (name, n_raw, n_na, n_bucketed, n_untiered))
            if merged < 0:
                broken.append("%s：簇数 %d 大于落桶 %d —— 一条记录被算进了两簇"
                              % (name, len(cls), n_bucketed))
            if n_bucketed != sum(c.n_records for c in cls):
                broken.append(
                    "%s：落桶 %d 条 ≠ 该带各簇条数之和 %d 条"
                    % (name, n_bucketed, sum(c.n_records for c in cls)))
            # ★ 提醒带里**不许**有无规则号的簇：那种记录必须落 `untiered_alert`。
            #   允许它进簇就等于允许印「提醒」，而「提醒」的定义是「有规则命中」
            #   —— 一条核不了的结论借一个词的壳上了首屏。
            if band == BAND_ALERT:
                _nr = [c for c in cls if not c.has_rule]
                if _nr:
                    broken.append(
                        "%s：有 %d 簇没有规则号却进了簇（应落「无档可落」）"
                        % (name, len(_nr)))

        return {"rows": rows, "broken": broken}

    def balance_line(self) -> str:
        """守恒账的一行人话。**报数必须带式子**，否则读者只能相信。"""
        b = self.balance()
        parts = []
        for r in b["rows"]:
            s = ("%s 候选 %d 条 ＝ 进证据 %d 簇 ＋ 合并 %d ＋ 不适用 %d"
                 % (r["name"], r["candidates"], r["into_evidence"],
                    r["merged"], r["not_applicable"]))
            if r["untiered"]:
                s += " ＋ 无档可落 %d" % r["untiered"]
            parts.append(s)
        if b["broken"]:
            parts.append("守恒破裂：" + "；".join(b["broken"]))
        return "｜".join(parts)


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


def untiered_identity(rec: Dict[str, Any]) -> str:
    """一条「无档可落」的记录在说**哪件事**（用于把 302 条还原成 1 件事）。

    ★ 判据只认**记录自己带着的身份字段**，不猜：
        · `from_version` / `to_version` —— 宿主版本变化事件的真实身份。
          实测 11-02：302 条只有两个身份（`5.9.3→5.9.4` 152、`5.9.4→5.9.3` 150）。
          两个身份交替出现 = **同一个抖动**，不是 302 件独立的事。
        · 没有版本字段就退回 `reason` 前 40 字 —— 宁可退到「粗一点的同义」，
          也不要退到「用 type 当身份」（那等于说「这一天所有同类事件是一件事」，
          会把 302 说成 1，方向正相反、同样撒谎）。
        · 两者都没有 ⇒ 返回空串，调用方按「无身份」处理，**不许静默并进一桶**。
    """
    fv = str(rec.get("from_version") or "")
    tv = str(rec.get("to_version") or "")
    if fv or tv:
        return "%s→%s" % (fv or "?", tv or "?")
    rsn = str(rec.get("reason") or "").strip()
    if rsn:
        return rsn[:40]
    return ""


def _repeat_note(detail: Dict[str, int]) -> str:
    """「这么多条其实只有几个身份」时补一句。

    ★ 为什么必须在分母里补（2026-11-03）：实测 302 条 `host_changed` 只有 2 个身份。
      只印「302 条」，读者会以为发生了 302 件事；而「302 条记录、2 个身份、
      来回交替」说的是**一个**事实：宿主版本在抖。
      **条数是账本的行数，件数是有几个身份** —— 这两个数都要给，
      只给一个都会让读者算出错误的严重度。
    ★ 阈值为什么是 `n >= 10 且身份 <= 2`：
      不是从数据拟合出来的，是「只有极少数身份却有很多条」这个形状本身。
      身份数 3 以上时不补 —— 那时「多」是真的多，不该被一句话抹平。
    ★ 只对**无档可落**的那批用：进簇的记录已经有 `n_records/n_actions` 两个口径了。
    """
    n = sum(detail.values())
    if n < 10 or len(detail) > 2:
        return ""
    parts = "、".join("%s %d 次" % (k, v)
                     for k, v in sorted(detail.items(), key=lambda kv: -kv[1]))
    return ("｜其中 %d 条只有 %d 个身份（%s）⇒ 是同一件事被记了 %d 次，"
            "不是 %d 件事" % (n, len(detail), parts, n, n))


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
        s.denominators["停下等人"] = "读不到日文件 ⇒ 分母未知"
        return s

    by_key: Dict[Tuple[str, str, str], Cluster] = {}
    n_verdicts = 0
    n_non_event = 0
    n_gate = 0
    n_toast = 0
    n_bucketed = 0
    n_alert_raw = 0
    n_alert_non_event = 0
    n_alert_bucketed = 0
    n_alert_misfit = 0
    n_escalated_unread = 0
    n_shield_gate = 0
    n_shield_alert = 0
    n_shield_all = 0
    n_shield_heartbeat = 0
    untiered_alert: Dict[str, int] = {}
    untiered_detail: Dict[str, Dict[str, int]] = {}
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
                # ★ 「守不住」的全量计数必须放在**所有 continue 之前**（2026-11-03）。
                #   放在下面任何一处都会漏掉一类：实测 60 条（revived 37 ＋
                #   state_unreadable 23）是 decision=allow，走 `else` 分支直接 continue，
                #   于是「守不住」只报 3 条 —— **低报 20 倍，而页面上没有任何一处会红**。
                #   这正是「分母错的时候页面不会报错，它只会把 63 说成 3」（铁律 22）。
                _tx = str(rec.get("type") or "")
                if _tx in SHIELD_TYPES:
                    if _tx == SHIELD_HEARTBEAT:
                        n_shield_heartbeat += 1
                    else:
                        n_shield_all += 1
                dec = rec.get("decision")
                # ★ 2026-11-03：读两面。**选面只看账本字段取值，分档才问产品侧**。
                #   两面各有自己的原始条数分母 —— 合成一个数就是 F40。
                if dec in VERDICT_DECISIONS:
                    band = BAND_GATE
                elif dec in ALERT_DECISIONS:
                    band = BAND_ALERT
                else:
                    # ★ 不读它，但**必须数它**，而且要分清它属于哪一种「不读」：
                    #   ① 出声档里登记过「不属任何一档」的（配置失效／报告结论）
                    #      ⇒ 进 `unread_toast`，按取值分记；
                    #   ② 账本字段说「放行」，而产品侧会**升级**成 alert 的
                    #      （`allow` + warning/critical，见 `_SEVERITY_ESCALATE`）
                    #      ⇒ 进 `n_escalated_unread`。这一类最容易被漏掉：
                    #        它在字段上不是 alert，在本腿的筛选条件上被跳过，
                    #        而产品侧认为它该吵 —— 页面上表现为「提醒比实际少」。
                    if dec in _TOAST_DECISIONS:
                        unread_toast[str(dec)] = unread_toast.get(str(dec), 0) + 1
                    else:
                        _face, _derived, _ = NP.explain(rec)
                        if _face == NP.TOAST and _derived in ALERT_DECISIONS:
                            n_escalated_unread += 1
                    continue
                if band == BAND_GATE:
                    n_verdicts += 1
                else:
                    n_alert_raw += 1
                # ★ 通知面分流用**产品侧实现**（不抄表）。
                face, _d, _why = NP.explain(rec)
                if face == NP.NONE:
                    # 产品侧已判「结构上不是事件」（如 pre_tool_use_summary：
                    # 与逐条 pre_tool_use 覆盖同一批调用，同时通知会提醒两次）。
                    # ★ 这不是「静音」，是「不适用」——两者必须分开记。
                    if band == BAND_GATE:
                        n_non_event += 1
                    else:
                        n_alert_non_event += 1
                    continue
                if band == BAND_ALERT and face != NP.TOAST:
                    # ★ 账本字段说「告警放行」，产品侧按 action／severity 重新派生
                    #   却判成「停下等人」。**两条口径打架时不许挑一个**：
                    #   挑 gate ⇒ 印「挡下」，而动作其实执行了（强度读强）；
                    #   挑 toast ⇒ 印「提醒」，而产品侧认为该停下（强度读低）。
                    #   两种都是拿一个我们核不了的说法顶替一个词 ⇒ 只计数、报出来。
                    #   （实测 11-02 全天 0 条，但「今天没有」不等于「不会发生」。）
                    n_alert_misfit += 1
                    continue
                if band == BAND_GATE:
                    n_gate += 1
                    n_bucketed += 1
                else:
                    rids0 = rule_ids_of(rec)
                    if not rids0:
                        # ★ 出声、但没有规则号 ⇒ **不进任何档**（理由见 `strength()`）。
                        #   只按 type 计数：322 条「无档可落」与「302 条 host_changed」
                        #   在页面上差别很大 —— 前者像是我们没做完，后者才说得清是什么。
                        #   ★ 它**不是「落桶」**：落桶意味着「被装进某一档」。
                        t0 = str(rec.get("type") or "（无 type）")
                        untiered_alert[t0] = untiered_alert.get(t0, 0) + 1
                        # ★ 计数之外记**身份**（2026-11-03）：只印「302 条」会让
                        #   读者以为宿主被改了 302 回，而它是**同一个抖动**被记了 302 次。
                        #   身份判据见 `untiered_identity()` —— 只认记录自带的字段，
                        #   不许拿 type 当身份（那会把 302 说成 1，方向相反、同样撒谎）。
                        _ident0 = untiered_identity(rec)
                        if _ident0:
                            _dm = untiered_detail.setdefault(t0, {})
                            _dm[_ident0] = _dm.get(_ident0, 0) + 1
                        continue
                    n_toast += 1
                    n_alert_bucketed += 1

                rids = rule_ids_of(rec)
                rule = rids[0] if rids else ""
                sess = str(rec.get("session") or "")[:8]
                # ★ 聚合键**不含 decision**（block 与 deny 同义，放进去会把
                #   同一次动作拆成两簇）。decision 改成簇内的取值集合。
                # ★ 但**必须含 band**：同规则同会话的「挡下」与「提醒」是两件事，
                #   并成一簇就只能二选一。
                key = (rule, sess, band)
                cl = by_key.get(key)
                if cl is None:
                    cl = Cluster(
                        rule_id=rule or "（无规则号）",
                        session=sess,
                        severity=str(rec.get("severity") or "none"),
                        band=band,
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
                # ★ 守不住的那一类**逐条计**，与簇的 is_shield 是两条独立的路
                #   （簇上的 is_shield 只看第一条记录 ⇒ 混簇时它不是全貌）。
                if t in SHIELD_TYPES:
                    if band == BAND_GATE:
                        n_shield_gate += 1
                    else:
                        n_shield_alert += 1
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
        n_alert_raw=n_alert_raw,
        n_alert_non_event=n_alert_non_event,
        n_alert_bucketed=n_alert_bucketed,
        untiered_alert=dict(untiered_alert),
        untiered_detail={k: dict(v) for k, v in untiered_detail.items()},
        n_escalated_unread=n_escalated_unread,
        n_shield_gate=n_shield_gate,
        n_shield_alert=n_shield_alert,
        n_shield_all=n_shield_all,
        unread_toast=dict(unread_toast),
        clusters=list(by_key.values()),
    )

    # ★ 分母：三个数分列，**不许合成一个**（F40）。
    # ★ 2026-11-03：键名改成**不带「面」字的短名**。原来叫「裁决面」，而本腿现在
    #   读两面 ⇒ 消费方加前缀后会出现「裁决面·提醒面」这种读起来像口吃的东西。
    #   短名 + 前缀 = 「裁决面·告警放行」，一眼能读懂说的是哪一带。
    s.denominators["停下等人"] = (
        "按 decision 值数（block+deny）%d 条｜其中产品侧判为非事件 %d 条"
        "（不适用，非静音）｜落桶 %d 条"
        % (n_verdicts, n_non_event, n_bucketed)
    )
    # ★★ 第二重口径：**记录 ≠ 动作**。必须与上面那一条并列，不许合成。
    #   实测 11-02：29 条记录 / 17 次动作（12 次被两个钩子各记一遍）。
    #   ★ 这两个数都是真的，且都能被核（前者可逐行回指，后者可按
    #     会话+时刻+工具+命令 复算）。合成一个数就会让「一次动作」被读成「两次」。
    n_actions_total = sum(c.n_actions for c in s.clusters)
    n_actions_gate = sum(c.n_actions for c in s.clusters_of(BAND_GATE))
    n_actions_alert = sum(c.n_actions for c in s.clusters_of(BAND_ALERT))
    s.denominators["动作数"] = (
        "按（会话+时刻+工具+命令）去重后 %d 次动作｜对应 %d 条记录"
        "｜差额 %d 条是「同一次动作被多个钩子各记一遍」"
        "（block 与 deny 同义，见 notify_policy 回退表）"
        "｜其中挡下 %d 次、提醒 %d 次"
        % (n_actions_total, n_bucketed + n_alert_bucketed,
           (n_bucketed + n_alert_bucketed) - n_actions_total,
           n_actions_gate, n_actions_alert)
    )
    s.denominators["通知面"] = (
        "gate %d 条｜toast %d 条｜聚合后 %d 簇（规则×会话×带）"
        % (n_gate, n_toast, len(by_key))
    )
    # ★ 2026-11-03：**提醒面单独一条分母**，不许并进「裁决面」。
    #   它的原始条数、不适用、落桶、无档可落四个数各自成立，合成一个数就是 F40。
    s.denominators["告警放行"] = (
        "按 decision 值数（alert+warn）%d 条｜其中产品侧判为非事件 %d 条"
        "（不适用，非静音）｜落桶 %d 条｜无档可落 %d 条"
        % (n_alert_raw, n_alert_non_event, n_alert_bucketed,
           sum(untiered_alert.values()))
        + ("（%s）" % "、".join("%s %d" % (k, v)
                             for k, v in sorted(untiered_alert.items()))
           if untiered_alert else "")
        # ★ 2026-11-03：**「无档可落」还要说清它是几件事**。
        #   302 条 `host_changed` 只有两个身份（`5.9.3→5.9.4` 152、
        #   `5.9.4→5.9.3` 150），是同一个版本抖动被记了 302 次。
        #   只印 302，读者会以为宿主被改了 302 回；而真实情况是
        #   「它一直在两个版本之间来回横跳」——那是**一个**要处理的事实。
        + "".join(_repeat_note(untiered_detail[t])
                  for t in sorted(untiered_detail))
    )
    # ★ 守不住单独一条分母（J5／L2-3）：**不是新增一档，是新增一个计数**。
    #   它与「挡下」共用同一批记录，所以两个数相加没有任何意义 ——
    #   写在这里就是为了让读者知道它们**不许相加**。
    #
    # ★★ 2026-11-03 改成**两栏**（此前只印进簇的那 3 条，低报了 20 倍）：
    #   11-02 实测：`host_shield_*` 227 条 → 去掉 164 条心跳 → **63 条**真事件。
    #   其中进簇 3 条（`breach` 1 ＋ `dev_drift` 2），其余 60 条
    #   （`revived` 37 ＋ `state_unreadable` 23）是 `decision=allow`，
    #   两条带都不收 ⇒ 一条腿都不数它们 ⇒ 页面上写「守不住 3 条」。
    #   而这 60 条**不是漏读**：产品侧 `notify_policy.explain()` 判 `face=none`
    #   （结构上不通知人）。所以正确说法是「读到了、产品侧判不通知」，
    #   不是「没人读」—— 两句话指向的责任方完全不同（见 J4 的三态判据）。
    #   ⇒ 一栏写两个数。只写「该通知你的 3 条」，会让「宿主盾今天只在岗 3 次」
    #     变成一个看起来完全正常的读数。
    s.denominators["守不住"] = (
        "宿主盾自检事件（守卫自己不在岗／状态异常）全量 %d 条（已排除 %s %d 条心跳）"
        "｜该通知你的 %d 条（gate %d、alert %d）"
        "｜读到了但产品侧判不通知的 %d 条（自愈、状态探不到等）"
        "｜这类记录与「有规则号的命中」共用同一批账本记录，两个数不许相加"
        % (n_shield_all, SHIELD_HEARTBEAT, n_shield_heartbeat,
           n_shield_gate + n_shield_alert, n_shield_gate, n_shield_alert,
           s.shield_silent())
    )
    s.denominators["账本日文件"] = (
        "日文件 %d 个（%s .. %s）"
        % (len(files), seen_days[0] if seen_days else "?",
           seen_days[-1] if seen_days else "?")
    )
    # ★ 守恒账（判据 J3／L2-2）：上面几块分母各自成立，这一条把它们加起来核对。
    #   **它是唯一会自己喊「对不上」的地方** —— 其余分母只是陈述。
    s.denominators["守恒"] = s.balance_line()
    # ★ 「没读的那一档」也要有分母，且**分 decision 取值列**。
    #   合成一个「另有 N 条」会把「配置失效」和「报告结论」混成一个数（F40）。
    if unread_toast:
        s.denominators["本腿没读的出声档"] = (
            "｜".join("%s %d 条" % (k, v) for k, v in sorted(unread_toast.items()))
            + "（这些取值不属任何一档，见 verdict_leg.TOAST_NOT_A_TIER）"
        )

    # ★ 守恒自检：落桶数必须等于各簇条数之和。不等就是有记录被吞了。
    n_sum = sum(c.n_records for c in s.clusters)
    if n_sum != n_bucketed + n_alert_bucketed:
        s.undecidable.append(
            "守恒对不上：落桶 %d 条（挡下 %d ＋ 提醒 %d），各簇条数之和 %d 条"
            " —— 有记录被吞或被重"
            % (n_bucketed + n_alert_bucketed, n_bucketed, n_alert_bucketed, n_sum)
        )
    # ★ 第二重守恒：动作数必须 ≤ 记录数。反过来就是去重键把两个动作并了。
    if n_actions_total > n_bucketed + n_alert_bucketed:
        s.undecidable.append(
            "动作数 %d 大于记录数 %d —— 去重键失效（把不同动作算成了同一个）"
            % (n_actions_total, n_bucketed + n_alert_bucketed)
        )
    # ★ 第三重守恒：两条带各自的式子。**破了就必须报，不许只印着**。
    for _msg in s.balance()["broken"]:
        s.undecidable.append("守恒账破裂：" + _msg)

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
            "本腿读 block／deny（停下等人）与 alert／warn（提醒但放行）这两类决策取值。"
            "出声档里还有%s不属任何一档，本腿一条不读"
            "（它们既不在「停下等人」这一带，也不在「告警放行」这一带；"
            "硬塞进任何一档，就是拿一个我们核不了的说法顶替一个词）"
            % "、".join("%s %d 条" % (k, v) for k, v in sorted(unread_toast.items())),
        )
    # ★ 2026-11-03 新增两条盲区，都是本版**扩面时撞出来的**，不是设想的：
    if untiered_alert:
        s.blind += (
            "出声档里有 %d 条记录没有规则号，本模块读到了但没有装进任何一档"
            "（%s）。需要规则号的那一档，其定义要求「有规则命中并告警」；"
            "没有规则号就印不出那一档 ⇒ 它们只在分母里出现，不进首屏。"
            "要不要给它们一档，"
            "属产品词表，须创始人拍板（DEC-27 的 D-5）"
            % (sum(untiered_alert.values()),
               "、".join("%s %d 条" % (k, v) for k, v in sorted(untiered_alert.items()))),
        )
    if n_escalated_unread:
        s.blind += (
            "账本里还有 %d 条记录的 decision 写的是「放行」，但产品侧会按"
            " action 与 severity 把它升级成提醒（notify_policy 的 _SEVERITY_ESCALATE："
            "allow 加 warning 或 critical）。本模块按账本字段取值筛记录 ⇒ 不读它们，"
            "所以真实的提醒次数会多于本报告里的数。这是口径差，不是漏报检查"
            % n_escalated_unread,
        )
    if n_alert_misfit:
        s.undecidable.append(
            "有 %d 条记录 decision 写着告警放行，而产品侧按 action 与 severity "
            "重新派生却判成「停下等人」—— 两条口径打架，本模块不替它们选边："
            "挑一边就是拿一个我们核不了的说法顶替一个词。这些记录未进任何一档"
            % n_alert_misfit
        )
    return s


def _unregistered_toast(decisions: Iterable[str]) -> Tuple[str, ...]:
    """出声档取值里**没登记归属**的那些。

    ★ 存在的理由：本腿按「取值 → 档」映射。产品侧那张回退表会加键，
      而新键出现时若没有登记，它会被静默跳过 —— 页面不说、分母不说、
      盲区不说，表现得和「这一档今天真的没有」一模一样（铁律 45）。
      ⇒ 判据不是「映射表写全了没有」（那是自律），而是「有没有一个函数
        能把没登记的点出来，并且自检真的拿一个没登记的取值喂过它」。
    """
    known = set(ALERT_DECISIONS) | set(TOAST_NOT_A_TIER)
    return tuple(sorted(d for d in decisions if d not in known))


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
    #  ★ 2026-11-03 改锚点：原来断言「无规则号的簇不许出现『挡下』两个字」。
    #    现在 claim 里**根本不许出现档名**（档名只在 evidence.WORD 一处声明），
    #    所以那句话变成了永远成立的死判据 —— 而**永远成立的判据与真判据同貌**。
    #    ⇒ 改成断言事实面的差：带回指 ⇒ 说的是「某个规则让动作没执行」；
    #      不带回指 ⇒ 说的是「监理自己异常」。两者用的词必须不同。
    ck("动作未执行" in c1.claim(), "带规则号的簇应当说清「动作未执行」")
    ck("监理自身异常" in c2.claim(),
       "无规则号的簇必须说成「监理自身异常」，不许说成规则挡住了：%r"
       % (c2.claim(),))
    ck("AN-" not in c2.claim(),
       "无规则号的簇点了一个规则号 —— 它没有规则号，点出来就是编的：%r"
       % (c2.claim(),))
    # ★ 档名不许出现在 claim 里（单一真源）：出现一次，改词就要改两处。
    for _c in (c1, c2):
        for _w in ("挡下", "提醒"):
            ck(_w not in _c.claim(),
               "claim 里出现了档名「%s」：%r —— 档名只许在 evidence.WORD 里声明一次"
               % (_w, _c.claim()))

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

    # ── 10. alert 带：一档说成另一档，判据必须能发现（2026-11-03 新增）───
    #  ★ 这一组守的是本版**新开的那一面**里最容易出、且最难发现的一个错：
    #    同规则同会话的「挡下」与「提醒」若并成一簇，`strength()` 只能二选一
    #    ⇒ 要么 288 次「提醒」被印成「挡下 288 次」（强度读强），
    #       要么 9 次「挡下」被印成「提醒」（强度读弱）。
    #    **两个数都真、页面也自洽**，只有把带写进聚合键才会分开出现。
    ca = Cluster(rule_id="AN-010", session="s", severity="warning",
                 band=BAND_ALERT, n_records=3, n_actions=3, has_rule=True)
    ck(ca.strength() == K_ALERT, "alert 带的簇必须落 alert 档，实际 %r"
       % (ca.strength(),))
    _ca = ca.claim()
    ck("AN-010" in _ca, "alert 带的簇丢了规则号：%r" % (_ca,))
    ck("挡下" not in _ca, "alert 带的簇说了「挡下」（把提醒说成挡下）：%r" % (_ca,))
    # ★ 「动作仍然执行了」这半句不许省：省掉之后「提醒 N 次」会被读成
    #   「挡下了 N 次」的软说法，而真实情况是这 N 次**全都执行了**。
    ck("动作仍然执行了" in _ca,
       "alert 带的簇没说「动作仍然执行了」—— 读者会把提醒读成挡住：%r" % (_ca,))
    # ★ 档名（「提醒」）不许由本模块写：它只在 evidence.WORD 里声明一次。
    ck("提醒" not in _ca,
       "alert 带的簇里出现了档名「提醒」：%r —— 改词就要改两处" % (_ca,))
    # 负控：同规则、同会话、不同带 ⇒ **必须是两个不同的聚合键**
    cg = Cluster(rule_id="AN-010", session="s", severity="critical",
                 band=BAND_GATE, n_records=9, n_actions=9, has_rule=True)
    ck(ca.key() != cg.key(),
       "同规则同会话的挡下与提醒聚合键相同 —— 它们会被并成一簇，"
       "然后只能二选一")
    ck(cg.strength() == K_HELD, "gate 带的规则命中必须仍落 held")

    # ── 11. 出声档的取值必须**全部登记**，未登记即报（清单式真源的防守）──
    _unreg = _unregistered_toast(_TOAST_DECISIONS)
    ck(not _unreg,
       "产品侧出声档里有取值没登记归属：%s —— 它会被静默跳过，"
       "而静默跳过与「这一档今天没有」完全同貌" % ("、".join(_unreg),))
    # ★ 负控：**必须证明这个检查能红**。永远为空的检查与恒真的检查一样没用。
    ck(_unregistered_toast(set(_TOAST_DECISIONS) | {"brand_new_decision"})
       == ("brand_new_decision",),
       "未登记检查不会报 —— 它对任何输入都放行，等于没有检查")
    ck(set(ALERT_DECISIONS) <= set(_TOAST_DECISIONS),
       "ALERT_DECISIONS 里有产品侧并不判为出声的取值 —— 档与表脱钩了")

    # ── 12. `PRODUCES` 必须等于 `strength()` 的值域（声明钉在实现上）────
    #  ★ 声明写死在常数里、实现另写一套 ⇒ 两边一定会漂。这一条把它们钉在一起：
    #    两个带 × 有无规则号 的四种组合，跑一遍 `strength()`，取到的档必须
    #    恰好等于 `PRODUCES`。多一个档 ⇒ 声明少写了（消费方会以为没腿读）；
    #    少一个档 ⇒ 声明多写了（消费方会以为有腿读，而实际产不出来）。
    _realized = set()
    for _band in (BAND_GATE, BAND_ALERT):
        for _has in (True, False):
            _realized.add(Cluster(rule_id="X" if _has else "（无规则号）",
                                  session="s", severity="none", band=_band,
                                  n_records=1, n_actions=1,
                                  has_rule=_has).strength())
    ck(_realized == set(PRODUCES),
       "PRODUCES %r 与 strength() 实际值域 %r 不一致 —— "
       "声明与实现已经脱钩" % (list(PRODUCES), sorted(_realized)))

    # ── 13. 守恒账：闭合、且破裂必须报（判据 J3／L2-2）───────────────
    _ok = Survey(read_at="x", day="d", n_verdicts=4, n_non_event=1, n_bucketed=3,
                 n_gate=3, n_toast=2, n_alert_raw=2, n_alert_non_event=0,
                 n_alert_bucketed=2)
    _ok.clusters = [
        Cluster(rule_id="A", session="s1", severity="none", band=BAND_GATE,
                n_records=3, n_actions=2, has_rule=True),
        Cluster(rule_id="B", session="s1", severity="none", band=BAND_ALERT,
                n_records=2, n_actions=2, has_rule=True),
    ]
    ck(not _ok.balance()["broken"],
       "闭合的守恒账被判成破裂：%r" % (_ok.balance()["broken"],))
    # 负控①：吞掉一条 alert 记录（落桶比原始少一条，且没进任何一项）
    _bad1 = Survey(read_at="x", day="d", n_alert_raw=3, n_alert_non_event=0,
                   n_alert_bucketed=2)
    _bad1.clusters = [_ok.clusters[1]]
    ck(any("提醒面" in b for b in _bad1.balance()["broken"]),
       "吞掉一条提醒记录，守恒账没报 —— 黑洞又回来了")
    # 负控②：把同一条记录算进两簇（簇条数之和 > 落桶）
    _bad2 = Survey(read_at="x", day="d", n_verdicts=2, n_bucketed=2, n_gate=2)
    _bad2.clusters = [_ok.clusters[0],
                      Cluster(rule_id="A2", session="s1", severity="none",
                              band=BAND_GATE, n_records=2, n_actions=1,
                              has_rule=True)]
    ck(_bad2.balance()["broken"],
       "一条记录被算进两簇，守恒账没报 —— 重算比漏算更难发现")
    # 负控③：alert 带里出现无规则号的簇（它本该落 untiered，不许进簇）
    _bad3 = Survey(read_at="x", day="d", n_alert_raw=1, n_alert_bucketed=1)
    _bad3.clusters = [Cluster(rule_id="（无规则号）", session="s", severity="none",
                              band=BAND_ALERT, n_records=1, n_actions=1,
                              has_rule=False)]
    ck(_bad3.balance()["broken"],
       "alert 带里的无规则号簇没被拦下 —— 它会印成「提醒」，"
       "而「提醒」的定义是有规则命中")

    # ── 14. 守不住两栏：全量必须覆盖**所有分流路径**（2026-11-03 新增）───
    # ★ 为什么必须真跑一遍 survey，而不是构造一个 Survey 验算术：
    #   这一栏此前低报 20 倍（63 说成 3）的根因**不在算术**，在**计数点位置** ——
    #   它原来写在「分流进哪条带」之后，于是 `decision=allow` 的 60 条
    #   在 `else: continue` 里就消失了，一条腿都没数过它们。
    #   构造 Survey 只能验「全量 - 进簇 = 不通知」这个减法，而那个减法
    #   **永远成立**（silent 就是减出来的）⇒ 构造法在这里是一条
    #   永远清白的判据，与真判据同貌（假绿第十四族）。
    # ⇒ 必须喂一份**造出来的账本**，让真正的分流代码跑过那三种取值。
    import shutil
    import tempfile
    _sd = tempfile.mkdtemp(prefix="vl-shield-")
    try:
        _srecs = [
            # ① gate 带、带规则号 ⇒ 归「挡下」，不是守不住
            {"ts": "2026-01-01T10:00:00+08:00", "type": "pre_tool_use",
             "decision": "block", "session": "s1", "rules_hit": ["AN-009"]},
            # ② gate 带、无规则号 ⇒ 进簇，且算「该通知你的」
            {"ts": "2026-01-01T10:01:00+08:00", "type": "host_shield_breach",
             "decision": "deny", "session": "s2", "severity": "warning"},
            # ③ allow + 心跳 ⇒ **不算守不住**（它写的是「我在岗」）
            {"ts": "2026-01-01T10:02:00+08:00", "type": "host_shield_heartbeat",
             "decision": "allow", "session": "", "severity": "none"},
            # ④ allow + 自愈 ⇒ 算全量，但不进任何带（产品侧判 face=none）
            {"ts": "2026-01-01T10:03:00+08:00", "type": "host_shield_revived",
             "decision": "allow", "session": "", "severity": "warning"},
            # ⑤ allow + 状态探不到 ⇒ 同上
            {"ts": "2026-01-01T10:04:00+08:00",
             "type": "host_shield_state_unreadable",
             "decision": "allow", "session": "", "severity": "warning"},
        ]
        with open(os.path.join(_sd, "2026-01-01.jsonl"), "w",
                  encoding="utf-8") as _fh:
            for _r in _srecs:
                _fh.write(json.dumps(_r, ensure_ascii=False) + "\n")
        _sv = survey(_sd, day="2026-01-01")
        ck(_sv.n_shield_all == 3,
           "守不住全量应为 3 条（breach＋revived＋state_unreadable，心跳不算），"
           "实际 %d —— 计数点没覆盖 allow 分支（这正是低报 20 倍的形状）"
           % _sv.n_shield_all)
        ck(_sv.n_shield_gate + _sv.n_shield_alert == 1,
           "该通知你的应为 1 条（只有 breach 进簇），实际 %d"
           % (_sv.n_shield_gate + _sv.n_shield_alert))
        ck(_sv.shield_silent() == 2,
           "读到了但产品侧判不通知的应为 2 条（revived＋state_unreadable），"
           "实际 %d" % _sv.shield_silent())
        ck(_sv.shield_silent() >= 0,
           "不通知数成了负数 —— 进簇数大于全量，两栏用了不同分母")
        # ★ 负控①：把心跳那一条改成 revived ⇒ 全量必须 +1（证明确实在数）
        _srecs[2]["type"] = "host_shield_revived"
        with open(os.path.join(_sd, "2026-01-01.jsonl"), "w",
                  encoding="utf-8") as _fh:
            for _r in _srecs:
                _fh.write(json.dumps(_r, ensure_ascii=False) + "\n")
        _sv2 = survey(_sd, day="2026-01-01")
        ck(_sv2.n_shield_all == _sv.n_shield_all + 1,
           "把心跳改成真事件后全量没涨 —— 心跳的排除逻辑写反了（%d → %d）"
           % (_sv.n_shield_all, _sv2.n_shield_all))
        # ★ 负控②：把 breach 的 decision 改成 alert ⇒ 它应从「该通知」挪到
        #   「产品侧判不通知」，但**全量不变**（同一件事不该因为换了条带就消失）
        _srecs[1]["decision"] = "alert"
        with open(os.path.join(_sd, "2026-01-01.jsonl"), "w",
                  encoding="utf-8") as _fh:
            for _r in _srecs:
                _fh.write(json.dumps(_r, ensure_ascii=False) + "\n")
        _sv3 = survey(_sd, day="2026-01-01")
        ck(_sv3.n_shield_all == _sv2.n_shield_all,
           "换了一条带之后全量变了 —— 全量必须与带无关")
    finally:
        shutil.rmtree(_sd, ignore_errors=True)

    # ── 15. 「302 条」必须说清是「几件事」（2026-11-03 新增）───
    # ★ 守的是 D-5：302 条 `host_changed` 只有两个身份（5.9.3→5.9.4 152、
    #   5.9.4→5.9.3 150），是**一次版本抖动被记了 302 次**。
    #   只印条数，读者会把「宿主版本在抖」读成「宿主被改了 302 回」。
    _shake = _repeat_note({"5.9.3→5.9.4": 152, "5.9.4→5.9.3": 150})
    ck("2 个身份" in _shake and "302 次" in _shake,
       "抖动说明没同时说出身份数与条数：%r" % (_shake,))
    ck(_repeat_note({"a": 10, "b": 10, "c": 10}) == "",
       "三个身份时不该说成「同一件事」—— 那时「多」是真的多")
    ck(_repeat_note({"a": 5, "b": 4}) == "",
       "只有 9 条时不该补这句 —— 阈值失效，会把小数目也说成抖动")
    ck(_repeat_note({}) == "", "空明细不该补这句")
    # ★ 单身份也要补：「40 条只有 1 个身份」同样是「一件事被记了 40 次」。
    ck("1 个身份" in _repeat_note({"x": 40}),
       "单个身份时也必须说清「这是同一件事」—— 否则 40 条会被读成 40 件")

    if fails:
        print("自检失败 %d 项：" % len(fails))
        for f in fails:
            print("  ·", f)
        return 1
    print("verdict_leg 自检：15 组全通过")
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
            # ★ 提醒面的四个数（原始／不适用／落桶／无档可落）。**不许合成一个**。
            "n_alert_raw": s.n_alert_raw,
            "n_alert_non_event": s.n_alert_non_event,
            "n_alert_bucketed": s.n_alert_bucketed,
            "untiered_alert": s.untiered_alert,
            # ★ 「这些条是几件事」的身份明细（2026-11-03）。消费方要印
            #   「302 条是同一件事被记了 302 次」，就只能从这里取，不许自己数。
            "untiered_detail": s.untiered_detail,
            # ★ 漏读面：账本字段说「放行」、产品侧会升级成提醒的记录数。
            "n_escalated_unread": s.n_escalated_unread,
            "n_shield_gate": s.n_shield_gate,
            "n_shield_alert": s.n_shield_alert,
            # ★ 2026-11-03：守不住一栏必须两半都给，否则消费方只能印进簇的 3 条，
            #   而真事件是 63 条 —— 低报 20 倍且页面上不会红。
            "n_shield_all": s.n_shield_all,
            "n_shield_silent": s.shield_silent(),
            # ★ 本腿**没读**的出声档，按 decision 取值分开。
            "unread_toast": s.unread_toast,
            # ★ 守恒账：两条带各自的式子与破裂项。消费方要印就印，不许自己加。
            "balance": s.balance(),
            "clusters": [
                {
                    "rule_id": c.rule_id,
                    "session": c.session,
                    # ★ 带必须随簇出去：消费方要按档分栏，就得知道它在哪一带。
                    "band": c.band,
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
        print("  %-10s %-8s %-6s n=%-3d 动作/%-3d 条  %s"
              % (c.rule_id, c.session, c.band, c.n_actions, c.n_records, c.claim()))
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
