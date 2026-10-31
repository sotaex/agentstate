# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""C-3 取证 Agent：把「什么变了」变成「可以出示的证据」。

出处：方案书 §5.1「监理的交付物是报告，不是没出事」；§5.7「每一句已发现／
已拦截／已记录都要能回指一条审计记录，回指不到 ⇒ 不许写」。

──────────────────────────────────────────────────────────────────────────
准入三问（作业单 §0.5，答不出不许写代码）
──────────────────────────────────────────────────────────────────────────
1. 需求：**A（主动去看）**。不是 B（看得懂）、不是 C（说人话）——本模块
   只把已有读数重新装订，不生成新句子，不调模型。
2. 决策器档：**档 0**（纯计算，零裁量）。没有任何阈值是这里定的：阈值全在
   auditor / watchman 里，本模块只搬运与校验。
3. 裁量位置：**观测侧**。本模块不判断「这条危险吗」——那是 rules/default.json
   的判定侧；越过去账本 L0 就塌了。

──────────────────────────────────────────────────────────────────────────
强度档为什么不是方案书 §5.3 那三个词
──────────────────────────────────────────────────────────────────────────
方案书 §5.3 写「已拦截／已发现无法处置／已记录未判定，三句不能互换」。
**其中「已拦截」是产品已经判死的错名**：

  `inbox_model.py:165` 原文：「旧标题是『**已拦截**：越界动作被挡下』—— 但
  `host_shield_breach` 描述的……」⇒ 现词表（`inbox_model.py:156-179`）是
  **没守住／挡下／提醒**，全仓只此一处声明。

同一件事在收件箱叫「挡下」、在报告里叫「已拦截」，就是本项目刚量出来的
「同义两词」病（`deny`+`block` 177 条命名未收敛，见 watchman 的 verdict 八档）。
所以本模块**用产品词表**；方案书 §5.3 的纠偏记在 W5。

内部键与渲染词分开：内部键稳定（`held`/`alert`/`log_only`/`no_response`/
`checked`），渲染词可改。**同义必须收敛到一处**，否则下次改词要改三遍。

  held        → 挡下           有规则号，且账本显示动作确实没执行
  alert       → 提醒           有规则号，告警但放行
  log_only    → 已记录未判定    记了，没判（63.4% 的规则在这一档，这是定位不是缺陷）
  no_response → 已发现无法处置   发现了，但没有任何可执行的处置手段
  checked     → 已核对          账本自检结果，**不是**拦截结论

★ 硬约束（代码里 assert，不是文案自律）：`挡下` 只能由**带 rule_id 的规则
  命中**产生。C 线今天读的是账本、不是规则 ⇒ **本模块一条 `挡下` 都不许产出**。
  这正是记忆里那条铁律的落地：指不出「哪个文件哪一行」的机制断言，降级成下一步。

──────────────────────────────────────────────────────────────────────────
为什么走子进程而不是 import
──────────────────────────────────────────────────────────────────────────
auditor / watchman 已通过 30 臂负控。改它们（哪怕只是抽出 collect 函数）都要
全量重跑，风险与本模块的收益不成比例。更重要的是：**子进程天然给出「不可判」
与「零」的分界**——它们崩了，`undecidable` 里会记一条，而不是安静地返回空列表。

  零       ＝ 查了，确实没有
  不可判   ＝ 没查成，不知道有没有
  ★ 两者长得一样（都是「没有线索」），但一个是结论、一个是盲区。
    这就是 A 线 report.py 说的「零与不可判同貌」，也是本项目最忌的一种错。

只读：本模块不写账本、不写规则库、不碰任何随包目录。
"""

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))

# --------------------------------------------------------------------------- 强度档

#: 内部键。**代码里只许用这些**；中文词只在 WORD 里出现一次。
K_HELD = "held"
K_ALERT = "alert"
K_LOG_ONLY = "log_only"
K_NO_RESPONSE = "no_response"
K_CHECKED = "checked"

#: 渲染词。与 `inbox_model.py:156-179` 的产品词表对齐 ——
#: 「同义必须收敛到一处」，否则改一次词要改三遍，而且第三遍一定会漏。
WORD = {
    K_HELD: "挡下",
    K_ALERT: "提醒",
    K_LOG_ONLY: "已记录未判定",
    K_NO_RESPONSE: "已发现无法处置",
    K_CHECKED: "已核对",
}

#: 只允许由规则命中产生的那一档。C 线无规则命中数据 ⇒ 恒不产出。
HELD_ONLY_FROM_RULES = (K_HELD,)


# --------------------------------------------------------------------------- 模型


@dataclass(frozen=True)
class Cite:
    """一处可定位的位置。`(day, lineno)` 是回指的最小单位。

    `what` 是「这一行是什么」，用于**人眼复核**：光有行号，读者仍要自己打开
    文件才知道对不对；带上 type 与一两句摘要，他扫一眼就能判断「找错地方了」。

    ★ 为什么不能只有行号：账本在长。**当天文件**的行号在本次读取之后仍会变，
      所以 Cite 必须配合 Evidence.read_at 一起读——「2026-10-31 的第 812 行」
      只在 read_at 那一刻成立。封盘日的行号才是稳定的。
    """

    day: str
    lineno: int
    what: str = ""

    def key(self) -> Tuple[str, int]:
        return (self.day, self.lineno)

    @property
    def day_level(self) -> bool:
        """这条证据的定位粒度是不是只到「天」。

        auditor 用 `(文件名, 0)` 表示「整天的问题」——例如 size 与清单不符、
        缺锚。那种问题**没有某一行可指**：清单条目本身缺失，指哪一行都是编的。

        ★ 「没有行号」不等于「行号错了」。硬要它给行号，它只能给 0；而把 0
          当越界报红，就是把「定位粒度不同」说成「回指造假」——同一个错误的
          两个方向（铁律 45）。所以粒度必须显式带出来，让渲染层说清楚。
        """
        return self.lineno == 0


@dataclass(frozen=True)
class Evidence:
    """一条可以对外出示的证据。

    不许为空的三样：claim（说了什么）、cites（凭什么这么说）、source（哪来的）。
    缺任何一样，这条就不是证据，是意见。
    """

    eid: str
    claim: str
    strength: str
    cites: Tuple[Cite, ...]
    source: str
    read_at: str
    rule_id: str = ""
    blind: str = ""
    items: Tuple[str, ...] = ()
    #: 上游判定的原始状态（auditor 的 PASS／WARN／FAIL／SKIP）。
    #:
    #: ★ 为什么必须有这个字段：强度词表里 PASS 与 WARN 是**同一个词**（「已核对」），
    #:   但它们对读者的意思相反 —— 一个是「核过了，一致」，一个是「核过了，
    #:   有性质偏离，只是不算篡改」。真账本上 A3（历史缺锚）与 A4（495 处倒序）
    #:   都是 WARN，第一版把两条都印成绿色「已核对」——读者一眼扫过去，
    #:   而那正是最该停一下的两条。**把偏离印成通过，是把一个已知事实抹掉。**
    status: str = ""

    def __post_init__(self) -> None:
        if not self.claim.strip():
            raise ValueError(f"证据没有结论（{self.eid}）")
        if not self.cites:
            raise ValueError(f"证据没有出处，不许存在（{self.eid}／{self.claim[:30]}）")
        if not self.source.strip():
            raise ValueError(f"证据没说来源（{self.eid}）")
        if self.strength in HELD_ONLY_FROM_RULES and not self.rule_id:
            raise ValueError(
                f"「{K_HELD}」只能由规则命中产生，但这条没有 rule_id"
                f"（{self.eid}／{self.claim[:30]}）"
            )
        if self.strength not in WORD:
            raise ValueError(
                f"强度档不在词表内：{self.strength!r}（{self.eid}）"
                f" —— 合法值 {sorted(WORD)}"
            )

    def word(self) -> str:
        """给人看的词。**渲染层只许调这里**，不许自己写中文。"""
        return WORD[self.strength]

    def strength_note(self) -> str:
        """强度档的**必带限定语**。单独写在一处，避免渲染层各自发挥。"""
        return {
            K_HELD: "已由规则拦下（有规则号，可查规则库）",
            K_ALERT: "有规则命中并告警，但动作仍然执行了",
            K_NO_RESPONSE: "已发现，但没有可执行的处置手段",
            K_LOG_ONLY: "已记录，未作判定（不知道是否危险，只知道它变了）",
            K_CHECKED: "已核对（这是账本自洽性检查，不是拦截结论）",
        }[self.strength]


@dataclass
class Bundle:
    """一次取证的全部产物。三级渲染共用这一份，只换输出。"""

    read_at: str
    root: str
    evidence: List[Evidence] = field(default_factory=list)
    #: 算不出来的部分。**必须与「没有」分开**：这是盲区，不是结论。
    undecidable: List[str] = field(default_factory=list)
    #: 「不适用」（工具明确判了 SKIP）。**与 undecidable 分开**：
    #:   没跑成   ＝ 不知道有没有（工具坏了／起不来／超时）
    #:   不适用   ＝ 问了，但这把尺子量不到这件事（例如没给 --declare）
    #: 合成一句「没有跑成」，就把一条**已知的适用边界**说成了**未知的故障**——
    #: 方向正好相反：把确定性说成了不确定性。真账本上 A5 就是这样被误述的。
    not_applicable: List[str] = field(default_factory=list)
    #: 分母：每个数字怎么算出来的。报数不带分母等于报了个没法核的数。
    denominators: Dict[str, str] = field(default_factory=dict)
    #: 结构性盲区：这批证据整体看不见什么。
    blind: Tuple[str, ...] = ()

    def by_strength(self) -> Dict[str, List[Evidence]]:
        out: Dict[str, List[Evidence]] = {}
        for e in self.evidence:
            out.setdefault(e.strength, []).append(e)
        return out

    def count(self) -> int:
        return len(self.evidence)


# --------------------------------------------------------------------------- 取数


def _run_json(script: str, root: str, extra: Optional[List[str]] = None) -> Tuple[Any, str]:
    """跑同目录下的原型，返回 (json, 错误说明)。**崩了不抛，返回 None + 原因。**

    为什么不抛：取证要尽量给出「能给的都给了」，一条腿崩不该让整份报告消失。
    但**必须**把崩记进 `undecidable` —— 否则「这条腿没跑」会伪装成「这条腿没发现问题」。
    """
    cmd = [sys.executable, "-E", "-X", "utf8", os.path.join(HERE, script),
           "--root", root, "--json"]
    if extra:
        cmd += extra
    env = dict(os.environ)
    env.setdefault("TMPDIR", os.environ.get("TEMP", "/tmp"))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=900, env=env, cwd=REPO)
    except subprocess.TimeoutExpired:
        return None, f"{script} 超时（900s）—— 账本可能过大，或机器正被其他任务占满"
    except Exception as exc:                      # noqa: BLE001
        return None, f"{script} 起不来：{type(exc).__name__}: {exc}"
    if p.returncode != 0:
        tail = (p.stderr or "").strip().splitlines()[-3:]
        return None, f"{script} 退出码 {p.returncode}：{' / '.join(tail) or '（无 stderr）'}"
    try:
        return json.loads(p.stdout), ""
    except Exception as exc:                      # noqa: BLE001
        return None, f"{script} 输出不是合法 JSON：{type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------- 转换


def _fmt_evidence(ev: Any) -> Tuple[Cite, ...]:
    """把 auditor/watchman 的 `((day, lineno), ...)` 变成 Cite。

    两种来源的 evidence 都是 `(文件名或日, 行号)` 二元组；auditor 传的是
    **文件名**（`2026-10-31.jsonl`），watchman 传的是**日**（`2026-10-31`）。
    归一在这里做一次，下游只见 day —— 否则渲染层要处理两种形态。
    """
    out: List[Cite] = []
    for pair in ev or ():
        try:
            name, lineno = pair
        except (TypeError, ValueError):
            continue
        day = str(name)
        if day.endswith(".jsonl"):
            day = day[:-6]
        try:
            ln = int(lineno)
        except (TypeError, ValueError):
            ln = 0
        out.append(Cite(day=day, lineno=ln))
    return tuple(out)


def plain(text: str) -> str:
    """去掉**我们自己写的散文**里的 `**强调**` 星号。

    来源：auditor／watchman 的 `detail`／`subject`／盲区文案是我们**自己写的散文**，
    写的时候用了 Markdown 的 `**强调**`，进 HTML 和纯文本就变成两个多余字符
    （实测报告里印出「这是**无界**盲区」）。

    ★ **已知代价，写在这里而不是藏着**：`subject` 里可能嵌着账本原文
      （命令、路径）。如果某条命令本身就是 `ls **/*.py` 这种 glob，
      这两个星号会被一起去掉。概率极低，但代价是真的。
      真出现时的正确修法是**让上游散文别写 `**`**，不是在这里加白名单 ——
      加白名单就等于承认「我们分不清散文和原文」，那才是更贵的问题。
    ★ watchman.py 里也有一个同名函数，处理的是纯文本报告，同一个作者错误的两处出口。
    """
    return text.replace("**", "")


def _stable_id(prefix: str, claim: str, cites: Tuple[Cite, ...]) -> str:
    """证据 id 由**内容**决定，不由数组下标决定。

    ★ 为什么不能用 `f"AUD-{i+1:02d}"`（第一版就是这么写的，是个真 bug）：
      下标 id 会随「本次有几条证据」漂移。昨天 `AUD-03` 是「A3 日清单」，
      今天若 A1／A2 都 PASS（不进证据），`AUD-03` 就变成别的东西。
      读者拿两份报告对照，会以为「同一件事变了」——**其实是编号换了对象**。
      同一个字符串在两个时刻指两个东西，正是本仓最忌的「同值不同义」
      （铁律 44），而且它比「不同值」更难发现：两份报告各自都自洽。

    ★ 取 claim + 首个出处做指纹，不取全部出处：
      出处的**数量**会变（同一天多记了一条，第 5 处就出现了），取全部会让
      id 跟着抖。claim ＋ 首个位置已经足够区分「是不是同一件事」。

    ★ 8 位十六进制 ＝ 32 bit。单份报告里证据数是十位量级，碰撞概率可忽略；
      而且碰撞的后果只是「两条证据同 id」，比「同一 id 指两件事」轻。
    """
    head = cites[0] if cites else None
    basis = claim + "|" + (f"{head.day}:{head.lineno}" if head else "")
    return "%s-%s" % (prefix, hashlib.sha256(basis.encode("utf-8")).hexdigest()[:8])


def from_audit(res: Dict[str, Any], read_at: str
               ) -> Tuple[List[Evidence], List[str], List[str]]:
    """auditor 的四个维度 → 证据。**只把不 PASS 的变成证据。**

    PASS 的维度不产生证据：它的结论是「这一维没有问题」，属于分母，不是结论。
    但 PASS 的**计数**要进 denominators —— 「核了 N 条」是这份报告的底气。

    ★ 返回**三样**：`(证据, 没跑成, 不适用)`。第一版把后两样并成一个 notes 列表，
      于是渲染层只能给它们写一句共同解释 ——「这些项目没有跑成」。而 SKIP 的
      真实含义是「问了，这把尺子量不到这件事」，不是「没跑成」。一句话把
      一条已知的适用边界说成了未知的故障，方向正好相反。
    """
    evs: List[Evidence] = []
    notes: List[str] = []
    na: List[str] = []
    findings = res.get("findings") or []
    if not findings:
        notes.append("auditor 返回了 0 个维度 —— 这不该发生（至少应有 A1–A4）")
        return evs, notes, na

    for i, f in enumerate(findings):
        status = f.get("status")
        dim = f.get("dim") or f"维度{i + 1}"
        detail = plain(f.get("detail") or "")
        if status == "PASS":
            continue
        if status == "SKIP":
            # 「不适用」不是「失败」，也不是「通过」（铁律 45）。它**不能**与
            # 「没跑成」并进同一张清单 —— 进 na，不进 notes。
            na.append(f"{dim} 不适用：{detail}")
            continue
        cites = _fmt_evidence(f.get("evidence"))
        if not cites:
            # FAIL 却没断点：这是 auditor 自己的约束（FAIL 必须带 evidence），
            # 走到这里说明契约被破坏了。报出来，不许静默。
            notes.append(f"{dim} 判为 {status} 却没有断点位置 —— 契约被破坏，本维度不计入证据")
            continue
        claim = f"{dim}：{detail}"
        evs.append(
            Evidence(
                # ★ 指纹基用 `dim`，不用 `claim`。claim 里嵌着**实时数字**
                #   （「495 处 ts 比前一条早（共验 167827 条）」），账本每长一条它就变，
                #   于是同一条结论每次跑都换一个 id —— 负控 nc17 现场抓到
                #   （AUD-2c0abc2c vs AUD-3ee74610）。
                #   「同一个字符串在两个时刻指两个东西」与「同一个东西在两个时刻
                #   有两个字符串」一样坏：后者让「用这个号指名」永远指不中，
                #   而且它不像前者那样会在对照两份报告时露馅 —— 两份各自都自洽。
                #   `dim` 是这条结论的**身份**（A3 日清单），数字是它的**读数**；
                #   身份稳定、读数每天变，这才是对的。
                #   ★ 为什么改成稳定 id 不会串更正：`corrections.resolve` 先按
                #     `target_report == rid` 筛（corrections.py:349），eid 只需在
                #     一份报告内唯一 —— 每个 dim 在一份报告里只出现一次。
                eid=_stable_id("AUD", dim, ()),
                claim=claim,
                strength=K_CHECKED,
                cites=cites,
                source="auditor",
                read_at=read_at,
                blind="本维度只核账本自身是否自洽，不判断记录内容是否危险",
                status=status,
            )
        )
    return evs, notes, na


#: watchman 线索类型 → (强度档, 一句「这类线索看不到什么」)
_CLUE_META: Dict[str, Tuple[str, str]] = {
    "anchor": (K_CHECKED, "只看锚与文件是否对得上；整链重写并同步改锚，这里仍报自洽"),
    "verdict": (K_LOG_ONLY, "只看裁决字段的取值关系是否合法，不看这个裁决对不对"),
    "baseline": (K_LOG_ONLY, "只比条数相对过去的变化，不看变多的是好事还是坏事"),
    "absent": (K_LOG_ONLY, "只看「该出现的类型没出现」，不区分是你停手还是钩子坏了"),
    "repeat": (K_LOG_ONLY, "只看同一件事是否反复出现，不看它是否重要"),
    "first_seen": (K_LOG_ONLY, "只看「第一次见」，不判断这个新东西是好是坏"),
    "rule_pair": (K_LOG_ONLY, "只看两个规则在同一会话里相邻出现，不做因果推断"),
    "gap": (K_LOG_ONLY, "只看日内时间断层，无法区分「停手」与「钩子断了」"),
}


def from_watch(res: Dict[str, Any], read_at: str) -> Tuple[List[Evidence], List[str]]:
    """watchman 的线索 → 证据。每一条线索都是一条证据（它已自带 evidence）。"""
    evs: List[Evidence] = []
    notes: List[str] = []

    # ★★ 九维一（入口唯一）／R4（同一件事一处实现）：
    #    kind 清单不许两处各写一份。watchman 的 `coverage` 每个检测器一项，
    #    它是 kind 集合的**机器可读真源**。第一版 `_CLUE_META` 是手抄的一份 ⇒
    #    加第 9 个 kind 时不会自动跟上，新线索会静默落进「未知类型」分支、
    #    盲区声明缺失。这正是品质方案第 3 条「机制层不守自己」的原样复现，
    #    所以这项检查必须常驻，不能靠人记得同步。
    cov = res.get("coverage")
    if isinstance(cov, dict) and cov:
        unregistered = sorted(set(cov) - set(_CLUE_META))
        stale = sorted(set(_CLUE_META) - set(cov))
        if unregistered:
            notes.append(
                "watchman 有 %d 个检测器没在本模块登记盲区声明：%s"
                " —— 这些类型的线索会缺「它看不见什么」"
                % (len(unregistered), "、".join(unregistered))
            )
        if stale:
            notes.append(
                "本模块登记了 %d 个 watchman 已没有的检测器：%s —— 该清理"
                % (len(stale), "、".join(stale))
            )

    clues = res.get("clues") or []
    for i, c in enumerate(clues):
        kind = c.get("kind") or "unknown"
        cites = _fmt_evidence(c.get("evidence"))
        if not cites:
            notes.append(f"线索 {kind} 没有出处 —— 不装成证据（契约：Clue.evidence 不许为空）")
            continue
        strength, blind = _CLUE_META.get(kind, (K_LOG_ONLY, "未知线索类型，本工具未声明它看不见什么"))
        if kind not in _CLUE_META:
            notes.append(f"线索类型 {kind!r} 未在本模块登记 —— 已按「已记录未判定」装，但盲区声明是缺的")
        subject = plain(c.get("subject") or kind)
        note = c.get("note") or ""
        evs.append(
            Evidence(
                # 同上：subject 里也嵌着会变的数字（「已经重复 3 次以上」、
                # 「首次出现域名：A、B、C」——新域名出现就变）。用 kind ＋ 首个
                # 出处做指纹：同一种线索靠**第一次出现的位置**区分，位置不会漂。
                eid=_stable_id("WCH", kind, cites),
                claim=subject,
                strength=strength,
                cites=cites,
                source=f"watchman/{kind}",
                read_at=read_at,
                blind=blind,
                items=tuple(c.get("items") or ()),
            )
        )
        if note:
            # note 是线索自带的限定语（如「有 hash ⇒ 锚本该挂上」），
            # 丢它就是丢限定条件 ⇒ 结论会被读强。挂在 blind 后面而不是替换。
            evs[-1] = Evidence(
                eid=evs[-1].eid, claim=evs[-1].claim, strength=evs[-1].strength,
                cites=evs[-1].cites, source=evs[-1].source, read_at=evs[-1].read_at,
                blind=(blind + "；" + note) if blind else note, items=evs[-1].items,
            )
    return evs, notes


# --------------------------------------------------------------------------- 校验


#: 定位结果三态。**不许合成两态**（铁律 45：没有的东西不能报成失败）。
LOC_OK = "ok"
LOC_BAD = "bad"
LOC_UNDECIDABLE = "undecidable"


class DayCache:
    """日文件行缓存。一次取证每个日文件只读一次。

    ★ 为什么不缓存整个账本：16 万条全读进内存约 300MB，而一份报告通常只引用
      几十行。缓存**被引用到的日文件**即可 —— 命中的是少数，没命中的不读。
    """

    def __init__(self, root: str) -> None:
        self.root = root
        self._d: Dict[str, Optional[List[str]]] = {}

    def lines(self, day: str) -> Optional[List[str]]:
        if day not in self._d:
            path = os.path.join(self.root, f"{day}.jsonl")
            if not os.path.isfile(path):
                self._d[day] = None
            else:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    self._d[day] = fh.readlines()
        return self._d[day]


def locate(day: str, lineno: int, cache: DayCache) -> Tuple[str, str]:
    """把 `(day, lineno)` 落到账本上。返回 `(三态, 人话说明)`。**不抛。**

    ★ 这是「回指能不能核」的**唯一实现**：`verify_cites`（针对 Bundle）与
      `citecheck`（针对渲染产物）都调它。两处各写一套必然漂，而且漂了还都
      绿着 —— 那是最难发现的一种坏（同一件事两套尺子，其中一套坏了不报警）。

    ★ 三态与四档：
      · `lineno == 0` 且文件非空 ⇒ OK（天粒度，这条本来就没有行号可指）
      · `lineno == 0` 但文件为空 ⇒ BAD（连天都没得定位）
      · 日文件不存在           ⇒ UNDECIDABLE（可能是滚动删了，不是造假）
      · 行号越界               ⇒ BAD（文件在，没那么长 ⇒ 回指是编的）
      · 行号落在空行           ⇒ BAD（定位到空行等于没定位）
    """
    lines = cache.lines(day)
    if lines is None:
        return LOC_UNDECIDABLE, f"日文件 {day}.jsonl 不存在 ⇒ 不可判（非失败）"
    if lineno == 0:
        if not lines:
            return LOC_BAD, f"天粒度回指 {day}，但该日文件是空的 ⇒ 连天都没得定位"
        return LOC_OK, f"{day}（整天，共 {len(lines)} 行）"
    if lineno < 0 or lineno > len(lines):
        return LOC_BAD, f"回指 {day}:{lineno} 越界（该文件只有 {len(lines)} 行）"
    if not lines[lineno - 1].strip():
        return LOC_BAD, f"回指 {day}:{lineno} 落在空行上 ⇒ 等于没定位"
    return LOC_OK, f"{day}:{lineno}"


def verify_cites(bundle: Bundle, root: str) -> Tuple[List[str], List[str]]:
    """逐条核回指：`(day, lineno)` 真能在原文件里定位到那一行吗？

    返回 (坏掉的, 说明)。**这不是「报告写得好不好」的检查，是「这句话有没有
    资格出现」的检查**（§5.7：回指不到 ⇒ 不许写）。

    ★ 四档判定，不许合成两档：
      · 天粒度（lineno==0）且文件非空 ⇒ 通过（这条证据本来就只定位到天）
      · 天粒度但文件是空的     ⇒ 坏（连天都没得定位）
      · 日文件不存在           ⇒ 不可判（那一天不在账本里，可能是滚动删了）
      · 行号越界               ⇒ 坏（文件在，但没那么长 ⇒ 回指是编的）
      · 行号存在但空行         ⇒ 坏（定位到一个空行，等于没定位）

    ★ 为什么「天粒度」要单列：第一版把 lineno==0 当越界报红，于是 auditor 的
      A3（缺锚是整天的问题，本来就没有行号可指）被自己的校验器判成造假。
      **「没有行号」不等于「行号错了」**——同一件事的两个方向，都会让报告撒谎。
    """
    bad: List[str] = []
    notes: List[str] = []
    cache = DayCache(root)

    for e in bundle.evidence:
        for c in e.cites:
            status, msg = locate(c.day, c.lineno, cache)
            if status == LOC_BAD:
                bad.append(f"{e.eid}: {msg}")
            elif status == LOC_UNDECIDABLE:
                notes.append(f"{e.eid}: {msg}")
    return bad, notes


# --------------------------------------------------------------------------- 主入口


def blind_of(payload: Dict[str, Any]) -> Tuple[str, ...]:
    """把一份工具 JSON 里的 `blind_spots` 变成一行行文字。**只有这一处实现。**

    ★ 第一版是两段各写一份：auditor 那段认 dict、watchman 那段认二元组与 str，
      两边**各自缺一种形态**。于是 watchman 的 JSON 根本没有这个键时，
      它的 8 条盲区**静默消失**，而报告那一节仍然有内容（另一个工具的 5 条），
      读起来毫无异样 —— 少了几行盲区不会报错，它只会把「我不知道」变成「我知道」。

    ★ 认不出来的形态**报出来**，不许 `continue`。盲区解析失败与「没有盲区」
      长得一样，而这两件事的含义正好相反（铁律 45）。
    """
    out: List[str] = []
    for b in payload.get("blind_spots") or ():
        if isinstance(b, dict):
            title = str(b.get("title") or "").strip()
            detail = str(b.get("detail") or "").strip()
            if title:
                out.append(plain("%s —— %s" % (title, detail)) if detail
                           else plain(title))
            else:
                out.append("（一条盲区没有标题，形态是 %r —— 它没有说出口）" % (b,))
        elif isinstance(b, (list, tuple)) and len(b) >= 2:
            out.append(plain("%s —— %s" % (b[0], b[1])))
        elif isinstance(b, str) and b.strip():
            out.append(plain(b))
        else:
            out.append("（一条盲区的形态无法解析：%r —— 这条盲区没有说出口）" % (b,))
    return tuple(out)


def need_zero_note() -> str:
    """「需要你看一眼 0 条」这句话的**唯一解释**。渲染层只许调这里。

    ★ 为什么必须是机制而不是渲染层的文案：0 至少有三种来源（真的没有危险／
      这一层的判据还没接上／工具根本没跑），而页面上只有一个「0」。
      交给渲染层自由发挥，三份报告会说三种话，而且都会说成最好听的那种。

    ★ 今天 C 线只有一种来源：读账本、不读规则库。所以这里写死一种解释。
      将来接了规则库，这个函数要按**实际来源**返回不同的话 —— 那时它会需要参数，
      而那时也正是它最容易被人改成一句「一切正常」的时候。

    ★ 文案里不许出现 `**`：它会被 `_e()` 原样印进 HTML（同一个字符串有两个消费者，
      就得挑两边都成立的字面）。
    """
    return ("「需要你看一眼」为 0，是因为本报告只读账本、不读规则库："
            "「挡下」「提醒」这两档只能由规则命中产生，所以今天结构上产不出来。"
            "这个 0 不是「查了没有危险」，是「这一层的判据还没接上」。")


def collect(root: str, *, watch_args: Optional[List[str]] = None) -> Bundle:
    """跑两条腿，装成一份 Bundle。**任何一条腿崩，都进 undecidable 而不是消失。**"""
    read_at = ""  # 由 auditor / watchman 各自记；这里取二者之一作为整份报告的读数时刻
    bundle = Bundle(read_at="", root=root)

    # ★ 结构性前提，**不是某次发现**：账本里混着本项目自己造的测试数据。
    #   负控与红队往真账本里写过假命令、假域名 —— 实测 2026-10-31 那条
    #   「首次出现域名」证据里，`evil.example.com` 和百度、几个政府网站并列，
    #   读起来像「我们发现了一个恶意域名」，而它其实是我自己造的夹具。
    #   账本没有「这是夹具」这个字段 ⇒ 本工具**无法区分**。不说这一句，
    #   读者会把一条夹具读成一条发现，而两者在页面上长得一模一样。
    #   ★ 无条件加，不按路径判断：换成别人的账本时这句话同样成立（只是答案变成
    #     「大概没有」），而「按路径猜」会让这条盲区在别人的账本上静默消失。
    bundle.blind += (
        "账本里是否混有本项目自己的测试数据 —— 负控与红队曾往真账本写过假命令、"
        "假域名（evil.example.com 就在 2026-10-31 的「首次出现域名」里，与百度、"
        "几个政府网站并列）。账本没有「这是夹具」字段，本报告无法区分夹具与真实"
        "事件；线索里出现的每一项都要按「可能是夹具」再复核一遍",
    )

    audit, err_a = _run_json("auditor.py", root)
    watch, err_w = _run_json("watchman.py", root, watch_args)

    if err_a:
        bundle.undecidable.append(f"账本自检（auditor）没跑成：{err_a}")
    if err_w:
        bundle.undecidable.append(f"变化巡检（watchman）没跑成：{err_w}")

    if audit:
        read_at = audit.get("read_at") or read_at
        evs, notes, na = from_audit(audit, read_at)
        bundle.evidence += evs
        bundle.undecidable += notes
        bundle.not_applicable += na
        # ★ 字段在**顶层**，不在 `meta` 里。第一版读 meta.get("files")，于是页脚
        #   长期显示「日文件 ? 个｜记录 ? 条」——报数不带分母，等于没报。
        #   不可解析条数 auditor 只写进 detail 文字、没有独立字段，所以这里不编一个。
        bundle.denominators["账本"] = (
            f"日文件 {audit.get('files', '?')} 个｜记录 {audit.get('records', '?')} 条"
        )
        # auditor 的盲区随 JSON 一起回来，并进「这份报告看不见什么」。
        # **盲区不并进来，读者就会以为没说的地方是没问题的地方。**
        bundle.blind += blind_of(audit)
    if watch:
        read_at = read_at or watch.get("read_at") or (watch.get("meta") or {}).get("read_at", "")
        evs, notes = from_watch(watch, read_at)
        bundle.evidence += evs
        bundle.undecidable += notes
        meta = watch.get("meta") or {}
        bundle.denominators["巡检窗口"] = (
            f"基线 {meta.get('window', '?')} 天｜今天 {meta.get('today', '?')}"
            f"｜今日记录 {meta.get('today_records', '?')} 条"
        )
        bundle.blind += blind_of(watch)

    bundle.read_at = read_at or "（未取到读数时刻）"
    if not bundle.read_at.startswith("20"):
        # 读数时刻取不到 ⇒ 所有回指都失去锚点（当天文件行号会漂）。这是硬缺口。
        bundle.undecidable.append(
            "没取到读数时刻 —— 当天文件的回指无法复核（行号在读取之后仍会变）"
        )

    if not bundle.evidence and not bundle.undecidable:
        # 两条腿都跑成、且都没报东西。这是**真的干净**，还是**两条腿都哑了**？
        # 只有「跑成了」才能这么说；此处两条腿都成功，故可报干净。
        bundle.denominators["结论"] = "两条腿都跑成且都无异常 —— 这是「查了，没有」，不是「没查」"
    return bundle


def _selfcheck() -> int:
    """量具自检（铁律 10 第 7 条）：四条硬约束先在本机验一遍，再去看真账本。"""
    fails: List[str] = []

    # ① 无出处的证据不许存在
    try:
        Evidence(eid="X", claim="测试", strength=K_LOG_ONLY, cites=(), source="t", read_at="t")
        fails.append("空 cites 被放过了 —— §5.7 的回指约束没生效")
    except ValueError:
        pass

    # ② 「已拦截」必须有 rule_id
    try:
        Evidence(eid="X", claim="测试", strength=K_HELD,
                 cites=(Cite("2026-01-01", 1),), source="t", read_at="t")
        fails.append("无 rule_id 的「挡下」被放过了 —— 会把核对结论说成拦截")
    except ValueError:
        pass

    # ③ 带 rule_id 的「已拦截」必须能构造（否则约束过紧，正常路径也被堵）
    try:
        Evidence(eid="X", claim="测试", strength=K_HELD, rule_id="SEC-01",
                 cites=(Cite("2026-01-01", 1),), source="t", read_at="t")
    except ValueError as exc:
        fails.append(f"合法「挡下」被误拒：{exc}")

    # ④ 四档之外不许通过
    try:
        Evidence(eid="X", claim="测试", strength="已处理",
                 cites=(Cite("2026-01-01", 1),), source="t", read_at="t")
        fails.append("四档之外的强度档被放过了")
    except ValueError:
        pass

    # ⑤ 散文里的 `**` 不许外泄到产物；**账本原文里没有星号的普通内容也不许被改**
    if plain("这是**无界**盲区") != "这是无界盲区":
        fails.append("散文里的 `**` 没有去掉 —— 报告里会印出「这是**无界**盲区」")
    if plain("ls -la /tmp && echo ok") != "ls -la /tmp && echo ok":
        fails.append("不含星号的普通命令被改动了 —— 清洗过头比不清洗更危险")
    if plain("") != "":
        fails.append("空串处理出问题")

    # ⑥ 盲区解析：**三种形态都必须被收进来**。
    #    第一版是两段各写一份：auditor 那段认 dict、watchman 那段认二元组与 str，
    #    各自缺一种形态。watchman 的 JSON 用 dict ⇒ 它的 8 条盲区被静默丢弃，
    #    而报告那一节仍然有 auditor 的 5 条，读起来毫无异样。
    got = blind_of({"blind_spots": [{"title": "T1", "detail": "D1"}]})
    if got != ("T1 —— D1",):
        fails.append("dict 形态的盲区没有被收进来：%r —— watchman 的盲区会静默消失"
                     % (got,))
    got2 = blind_of({"blind_spots": [("T2", "D2"), "裸字符串"]})
    if got2 != ("T2 —— D2", "裸字符串"):
        fails.append("二元组／字符串形态的盲区没有被收进来：%r" % (got2,))
    if not blind_of({"blind_spots": [{"detail": "没有标题"}]})[0].startswith("（"):
        fails.append("没有标题的盲区被静默丢弃了 —— 它应该被报出来，不是被丢掉")

    # ⑦ SKIP 必须进 not_applicable，**不许**进 undecidable。
    #    合成一处就等于把「这把尺子量不到这件事」说成「工具坏了」——
    #    真账本上 A5 就是这样被误述成「没有跑成」的。
    _evs, _notes, _na = from_audit(
        {"findings": [{"dim": "A5 总量", "status": "SKIP",
                       "detail": "未给 --declare"}]}, "t")
    if _notes:
        fails.append("SKIP 进了「没跑成」：%r —— 把已知的适用边界说成了未知的故障"
                     % (_notes,))
    if not _na or "A5" not in _na[0]:
        fails.append("SKIP 没有进「不适用」：%r" % (_na,))

    # ⑧ 0 条的解释里不许有 `**`（它会被原样印进 HTML）
    if "**" in need_zero_note():
        fails.append("need_zero_note 里有 `**` —— 会原样印进 HTML")

    for f in fails:
        print(f"[自检失败] {f}", file=sys.stderr)
    if fails:
        return 1
    print("[自检] 八条硬约束全部生效（空出处／无号挡下／合法挡下／词表外／散文星号不外泄／"
          "盲区三形态／SKIP 进不适用／0 的解释无星号）")
    return 0


def _cite_s(c: Cite) -> str:
    """人读的回指写法。天粒度必须写「整天」——否则 `2026-10-05:0` 会被读成
    「第 0 行」，而第 0 行不存在，读者会以为回指是坏的（其实是我们表达得不对）。"""
    return f"{c.day}（整天）" if c.day_level else f"{c.day}:{c.lineno}"


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="C-3 取证 Agent 原型（只读，档 0）")
    ap.add_argument("--root", default=".psl/audit")
    ap.add_argument("--selfcheck", action="store_true", help="只跑量具自检")
    ap.add_argument("--verify", action="store_true", help="核回指能否定位")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if args.selfcheck:
        return _selfcheck()
    if not os.path.isdir(args.root):
        print(f"[停] 目录不存在：{args.root}", file=sys.stderr)
        return 2

    b = collect(args.root)
    bad, notes = verify_cites(b, args.root)

    if args.json:
        print(json.dumps({
            "read_at": b.read_at,
            "n_evidence": b.count(),
            "by_strength": {k: len(v) for k, v in b.by_strength().items()},
            "undecidable": b.undecidable,
            "denominators": b.denominators,
            "blind": list(b.blind),
            "cites_bad": bad,
            "cites_notes": notes,
            "evidence": [
                {"eid": e.eid, "claim": e.claim, "strength": e.strength,
                 "strength_word": e.word(),
                 "source": e.source, "blind": e.blind,
                 "cites": [
                     {"day": c.day, "lineno": c.lineno,
                      "granularity": "day" if c.day_level else "line"}
                     for c in e.cites
                 ]}
                for e in b.evidence
            ],
        }, ensure_ascii=False, indent=1))
    else:
        print(f"读数时刻：{b.read_at}")
        print(f"证据 {b.count()} 条")
        for e in b.evidence:
            print(f"  [{e.word()}] {e.eid} {e.claim}")
            shown = [_cite_s(c) for c in e.cites[:4]]
            print(f"        出处：{', '.join(shown)}"
                  + (f" 等 {len(e.cites)} 处" if len(e.cites) > 4 else ""))
        if b.undecidable:
            print("不可判：")
            for u in b.undecidable:
                print(f"  · {u}")
        if bad:
            print("回指坏了：")
            for x in bad:
                print(f"  ✗ {x}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
