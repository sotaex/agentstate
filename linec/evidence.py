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
REPO = os.path.dirname(HERE)

# --------------------------------------------------------------------------- 强度档

#: 内部键。**代码里只许用这些**；中文词只在 WORD 里出现一次。
K_HELD = "held"
K_ALERT = "alert"
K_LOG_ONLY = "log_only"
K_NO_RESPONSE = "no_response"
K_CHECKED = "checked"


def _load_product_state_label() -> Dict[str, str]:
    """从产品侧读六态词表。**读不到就显式降级，不许静默用旧词表。**

    ★ 为什么不许静默降级：静默降级意味着「产品改了词，C 线还在用旧词」，
      而读者看到的是一个**看起来正常**的旧词 —— 这正是 S08 那个漏洞的翻版
      （按键名扫 ⇒ 换键名就绕过）。降级必须**说出来**，且要能被负控抓到。

    ★ 为什么用 AST 解析而不是 import：`inbox_model.py` 是个大模块，
      import 它会把整个产品模型拖进分析工具的依赖里。
      这里只取那一张表，**不 exec 产品代码**。

    ★ 为什么不能直接 `ast.literal_eval`：`STATE_LABEL` 的键是常量名
      （`STATE_R0` 等），不是字面量 ⇒ literal_eval 会失败。
      修法：**先扫出模块顶层的字符串常量赋值**（六态常量都是简单字符串），
      再用它当环境去解析 `STATE_LABEL`。
      这仍然**只读字面量、不执行任何产品逻辑**。
    """
    import ast

    path = os.path.join(REPO, "inbox_model.py")
    try:
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
    except Exception as exc:            # noqa: BLE001
        WORD_DEGRADED.append(
            "读不到产品侧词表（%s：%s）—— 中文措辞降级为模块内置值，"
            "**这不代表产品侧的词是这样**" % (path, exc)
        )
        return {}

    # ① 顶层常量环境：只收「简单字符串字面量」的赋值。
    consts: Dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        tgt = node.targets[0]
        if not isinstance(tgt, ast.Name):
            continue
        try:
            val = ast.literal_eval(node.value)
        except Exception:                # noqa: BLE001
            continue
        if isinstance(val, str):
            consts[tgt.id] = val

    # ② 用这个环境解析 `STATE_LABEL`。
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "STATE_LABEL"
                   for t in node.targets):
            continue
        try:
            val = ast.literal_eval(node.value)   # 键是常量名 ⇒ 这步会失败
        except Exception:                        # noqa: BLE001
            val = None
        if val is None:
            val = _eval_with_consts(node.value, consts)
        if isinstance(val, dict):
            return {str(k): str(v) for k, v in val.items()}
        WORD_DEGRADED.append("产品侧 STATE_LABEL 解析不出字典 —— 判为读不到")
        return {}
    WORD_DEGRADED.append(
        "产品侧 STATE_LABEL 找不到（%s）—— 中文措辞降级为模块内置值" % path
    )
    return {}


def _eval_with_consts(node: "ast.AST", consts: Dict[str, str]) -> Any:
    """在一个只含字符串常量的环境里求值一个**纯字面量表达式**。

    只支持：字符串字面量、字典、列表、元组、集合，以及这些结构里的常量名。
    **不执行任何函数调用、不做属性访问、不下标运算。**
    遇到不认识的一律返回 None（⇒ 判为读不到）。
    """
    import ast as _ast

    if isinstance(node, _ast.Constant):
        return node.value
    if isinstance(node, _ast.Name):
        return consts.get(node.id)
    if isinstance(node, _ast.Dict):
        out = {}
        for k, v in zip(node.keys, node.values):
            if k is None:
                continue
            kv = _eval_with_consts(k, consts)
            vv = _eval_with_consts(v, consts)
            if kv is None or vv is None:
                return None
            out[kv] = vv
        return out
    if isinstance(node, (_ast.List, _ast.Tuple)):
        out = []
        for e in node.elts:
            ev = _eval_with_consts(e, consts)
            if ev is None:
                return None
            out.append(ev)
        return out
    return None


#: 降级记录。**非空 ⇒ 报告必须说出来**（不许悄悄用旧词）。
WORD_DEGRADED: List[str] = []

#: 渲染词。**从产品侧派生，不手抄**（2026-11-02 落实，替代方案判据 L3-2）。
#:
#: ★ 为什么改成派生（这是「第二份声明」的修法）：
#:   旧版这里是一份**手抄**的产品词表，注释还把出处写错了
#:   （写 `inbox_model.py:156-179`，那里其实是 `TITLE_OF_KIND`，
#:   真正的六态表在 `:2218-2219` 的 `STATE_LABEL`）。
#:   手抄的代价是**改一次要改两遍，第二遍一定会漏**；
#:   更糟的是 S08「第二份中文态名表」判据按**键名**扫六态键
#:   （`ci/inbox_guards_0372.py:918-919`），C 线用的是 `held/alert/...`
#:   ⇒ **换一批键名就能绕过那个判据**。
#:   改成派生后：不再有第二批中文词表可扫 ⇒ 那个漏洞**自动消失**，
#:   而且产品侧改词，C 线这边跟着变。
#:
#: ★ 派生规则：**只映射语义真重合的那两档**。
#:   `held` ＝ 产品 L2「挡下」；`alert` ＝ 产品 L1「提醒」。
#:   其余三档（`log_only`／`no_response`／`checked`）**产品侧没有对应态**
#:   （实测：`inbox_model.py` 与 `glossary.py` 里都没有「已记录未判定」
#:   「已发现无法处置」「已核对」这三个词）⇒ 它们是**本模块自有**，
#:   必须显式登记，且**不许被说成产品态**。
#:   ★ 踩过的坑（铁律 44：同值不同义）：第一版把 `no_response` 映射到产品
#:     `Ls`，而 `Ls` 是「**缺粮**」（额度告警，见 `inbox_model.py:2205`），
#:     与「已发现无法处置」语义完全不同 ⇒ 派生出来的是**错词**。
#:     键名相似不等于语义相同。修法：**只映射经得起语义核对的那两档**。
PRODUCT_STATE_LABEL: Dict[str, str] = _load_product_state_label()

#: 本模块自有、不在产品六态里的档位。**显式登记**，不许藏在别处。
LOCAL_ONLY_WORDS: Dict[str, str] = {
    K_LOG_ONLY: "已记录未判定",
    K_NO_RESPONSE: "已发现无法处置",
    K_CHECKED: "已核对",
}

#: 内部键 → 产品六态键。**只列语义真重合的**。
#: `no_response` 不在表内：产品没有「已发现无法处置」这个态。
#: `Ls`＝缺粮（额度告警）≠「已发现无法处置」⇒ 不许硬塞。
WORD_PRODUCT_STATE_KEY: Dict[str, str] = {
    K_HELD: "L2",     # 挡下
    K_ALERT: "L1",    # 提醒
}

WORD: Dict[str, str] = {
    k: PRODUCT_STATE_LABEL.get(sk, LOCAL_ONLY_WORDS.get(k, k))
    for k, sk in WORD_PRODUCT_STATE_KEY.items()
}
WORD.update(LOCAL_ONLY_WORDS)

#: 哪些渲染词是产品态、哪些是本模块自有。**报告要能说清**，
#: 否则读者会把「已记录未判定」当成产品的一个态（它不是）。
WORD_IS_PRODUCT_STATE: Dict[str, bool] = {
    k: (k in WORD_PRODUCT_STATE_KEY) for k in WORD
}

#: 只允许由规则命中产生的那一档。C 线无规则命中数据 ⇒ 恒不产出。
HELD_ONLY_FROM_RULES = (K_HELD,)

#: 「需要你看一眼」＝这三档之和。**唯一声明处**（onepager 不许自己再列一遍）。
#:
#: ★ 为什么要单列：一页纸上那格数字把三档压成了一个数，而**三档的来源不同**。
#:   `held`／`no_response` 由裁决面这条腿供给；`alert` 今天**没有任何腿读**。
#:   压成一个数之后，「0」就同时可能是「查了没有」「没跑成」「没腿读」三种意思，
#:   而页面上只有一个 0（铁律 45：零与不可判同貌）。
#:   把口径声明在这里，归因函数与渲染层读的是同一份。
NEED_TIERS: Tuple[str, ...] = (K_HELD, K_ALERT, K_NO_RESPONSE)


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
        """强度档的**必带限定语**。单独写在一处，避免渲染层各自发挥。

        ★ 2026-11-03：这里**不许复述档名**。原文 `K_CHECKED` 那句是
          「已核对（这是账本自洽性检查，不是拦截结论）」，而「已核对」正是
          `WORD[K_CHECKED]` —— 于是同一页上这个档的词有两个来源：
          徽标从 `WORD` 取（能跟着产品侧变），限定语写死（不跟着变）。
          实测由 `jchecks.py` 的 J6 抓到（把 `WORD` 换成哨兵值后，
          页面上还剩一个「已核对」）。
          ⇒ 限定语只说**限定**，不重复档名。
        """
        return {
            K_HELD: "已由规则拦下（有规则号，可查规则库）",
            K_ALERT: "有规则命中并告警，但动作仍然执行了",
            K_NO_RESPONSE: "已发现，但没有可执行的处置手段",
            K_LOG_ONLY: "已记录，未作判定（不知道是否危险，只知道它变了）",
            K_CHECKED: "这是账本自洽性检查的结论，不是拦截结论",
        }[self.strength]


@dataclass
class LegReport:
    """一条腿的实况。**「0 条」的归因只能从这里读，不许渲染层自己编。**

    ★ 为什么需要它：一页纸有一格叫「需要你看一眼」。它把三档压成一个数
      （`NEED_TIERS`），而三档的来源不同 —— 有的腿读、有的腿不读、有的腿崩了。
      不给每条腿留一份实况，那格「0」就同时可能是三种意思，
      而页面上只有一个 0（铁律 45）。

    ★ `produces` 是**这条腿自己声明的**，不是这里猜的。
      第一版想让本模块推断「这条腿能产出哪几档」，推断出来的答案是
      「三档都查了」——而真答案是「只有两档有腿」。
    """

    name: str
    #: 跑成了没有。`False` ⇒ 它没读，不是「读了没有」。
    ran: bool
    #: 这条腿能产出哪些强度档（空 ⇒ 它不产结论，只产分母/账）。
    produces: Tuple[str, ...]
    #: 查了哪个分母。**报数不带分母等于没报**。
    denominator: str = ""
    #: 没跑成的原因，或这条腿的其它限定语。
    note: str = ""


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
    #: 每条腿的实况。**「0 条」的归因只从这里读。**
    legs: List["LegReport"] = field(default_factory=list)
    #: 本腿**没读**的「出声」档记录，按 decision 取值分开（来自第三只腿）。
    #: 空 ⇒ 没有没读的；非空 ⇒ 这一档的 0 是「没腿读」，不是「没有」。
    #: ★ 2026-11-03 之后：`alert` 已被本腿读走 ⇒ 这里只剩下
    #:   `TOAST_NOT_A_TIER` 登记的那几个取值。**字段不许改名**（消费面已固定），
    #:   但它的含义要跟着变：「这一档没腿读」变成「这些取值不属任何一档」。
    unread_toast: Dict[str, int] = field(default_factory=dict)
    #: ★ 读到了、但**现有各档都装不进去**的记录（按 type 分开数，来自第三只腿）。
    #:
    #:   实测 11-02：302 条 `host_changed`（「宿主版本变化——钩子协议可能漂移」），
    #:   出声、但没有规则号 ⇒ 印成「提醒」就是拿一个核不了的说法顶替一个词
    #:   （「提醒」的定义是「有规则命中并告警」）。
    #:   ⇒ 它既不是「结论」也不是「盲区」，是**第四种东西**：读到了、没档可落。
    #:     三者必须分开说，否则「读了没装」会被读者当成「没有」（铁律 45）。
    untiered_alert: Dict[str, int] = field(default_factory=dict)
    #: ★ 守恒账（判据 J3／L2-2），来自第三只腿：`{"rows": [...], "broken": [...]}`。
    #:   渲染层只许原样印出来，**不许自己算** —— 自己算就是第二套尺子。
    balance: Dict[str, Any] = field(default_factory=dict)

    def leg(self, name: str) -> Optional["LegReport"]:
        for lg in self.legs:
            if lg.name == name:
                return lg
        return None

    def tiers_with_no_leg(self) -> Tuple[str, ...]:
        """哪些「需要你看一眼」的档**没有任何一条腿**去读。

        ★ 这是 0 的第三种来源。前两种是「查了没有」「没跑成」，
          第三种是「压根没腿」—— 它最容易被写成「今天没有」。
        """
        covered = set()
        for lg in self.legs:
            covered.update(lg.produces)
        return tuple(t for t in NEED_TIERS if t not in covered)

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


def need_zero_note(bundle: Optional["Bundle"] = None) -> str:
    """「需要你看一眼 0 条」这句话的**唯一解释**。渲染层只许调这里。

    ★ 为什么必须是机制而不是渲染层的文案：0 至少有**四种**来源，而页面上只有
      一个「0」。交给渲染层自由发挥，三份报告会说三种话，而且都会说成最好听的那种。

        ① 查了，没有      —— 有腿读了，读到的就是 0 条（这是结论）
        ② 没跑成          —— 腿崩了，不知道有没有（这是盲区）
        ③ 没腿读          —— 这一档今天压根没有腿去读（这是结构性缺口）
        ④ 读了但没装进来  —— 腿读到了、但契约挡下了（这是要修的 bug）

    ★ 2026-11-02 改版：**这条函数原来是写死一句话的**。
      原文：「本报告只读账本、不读规则库：『挡下』『提醒』这两档只能由规则命中
      产生，所以今天结构上产不出来。」
      这句话在当时是对的 —— 那时只有两条腿，都不读 `decision` 字段。
      但第三只腿接上之后，**「挡下」已经产得出来了**，这句话就变成了一句
      **过期 24 小时的自我安慰**：它还在说「产不出来」，而实际已经产出了。

      ⇒ 现在按**实际来源**逐档说话（这正是旧注释预告的那次改写：
        「将来接了规则库，这个函数要按实际来源返回不同的话 —— 那时它会需要参数，
        而那时也正是它最容易被人改成一句『一切正常』的时候」）。
        **参数来了，且没有变成「一切正常」。**

    ★ 文案里不许出现 `**`：它会被 `_e()` 原样印进 HTML（同一个字符串有两个消费者，
      就得挑两边都成立的字面）。
    """
    if bundle is None:
        # ★ 不给 bundle 就说不出真话 ⇒ 明说「说不出」，**不许**退回那句旧文案。
        #   旧文案是「过期即撒谎」的典型：它读起来像结论，实际是两天前的现状。
        return ("「需要你看一眼」为 0，但本报告没有把各条腿的实况传进来，"
                "所以无法判断这个 0 是「查了没有」「没跑成」还是「这一档没腿读」。"
                "按规矩，说不出归因的 0 不许被当成「没事」。")

    no_leg = bundle.tiers_with_no_leg()
    by = bundle.by_strength()
    parts: List[str] = []

    # ① 有腿覆盖、且**确实读到 0 条**的档：说清「查了，没有」，并带上分母。
    #   ★ 必须逐档判「是不是真的 0」：本函数在别处被调用时，bundle 里可能有
    #     非零的档（例如实跑时「挡下」有 9 条）。无脑说「读到 0 条」会在那种
    #     情况下**直接撒谎**——而撒谎的方向恰好是「把有说成没有」。
    zero_covered = [t for t in NEED_TIERS
                    if t not in no_leg and not by.get(t)]
    if zero_covered:
        names = "、".join(WORD[t] for t in zero_covered)
        dens = []
        for lg in bundle.legs:
            if lg.ran and set(lg.produces) & set(zero_covered) and lg.denominator:
                dens.append(lg.denominator)
        text = "%s：腿读了，读到 0 条 —— 这是「查了，没有」，不是「没查」" % names
        if dens:
            text += "。读的分母：%s" % "；".join(dens)
        parts.append(text)

    # ② 没腿覆盖的档：明说「没腿读」，并给出**这一档今天实际有多少条**。
    for t in no_leg:
        text = "「%s」这一档今天没有任何一条腿去读" % WORD[t]
        if t == K_ALERT and bundle.unread_toast:
            detail = "、".join("%s %d 条" % (k, v)
                              for k, v in sorted(bundle.unread_toast.items()))
            text += ("—— 账本里这样的记录有 %s，一条没进本报告。"
                     "所以这个 0 是「这一层还没接上」，不是「今天没有提醒」"
                     % detail)
        else:
            text += "—— 这个 0 是「这一层还没接上」，不是「没有」"
        parts.append(text)

    # ③ 跑没跑成：单独说，**不许**混进上面两句。
    dead = [lg for lg in bundle.legs if not lg.ran]
    if dead:
        parts.append(
            "%s没跑成（%s）—— 它们负责的档今天既不是「没有」也不是「有」，是「不知道」"
            % ("、".join(lg.name for lg in dead),
               "；".join(lg.note or "原因见「不可判」" for lg in dead)))

    # ④ 2026-11-03 新增：**读到了、但装不进任何一档**的那一批。
    #   ★ 它不属于原来那四种 0 —— 四种里最接近的是「读了没装进来（要修的 bug）」，
    #     而这一批不是 bug：是产品词表里就没有它们的位置。
    #     不单独说，读者会把它当成「没有」；说成「没腿读」，又冤枉了那条腿
    #     （它明明读了）。所以必须有第五句话。
    if bundle.untiered_alert:
        parts.append(
            "另有 %d 条记录读到了但没有装进任何一档（%s）—— 它们出声、却没有规则号，"
            "而「提醒」的定义是有规则命中并告警。这批既不是「没有」，也不是「没读」，"
            "是「读到了、没档可落」"
            % (sum(bundle.untiered_alert.values()),
               "、".join("%s %d 条" % (k, v)
                         for k, v in sorted(bundle.untiered_alert.items()))))

    # ⑤ 出声档里**不属任何一档**的取值（配置失效／报告类结论）仍然是没读。
    #   ★ 只有当「提醒」这一档已经有腿读时才走这一支；没有腿读时，上面第 ② 句
    #     已经把它们说全了 —— 两句都说会变成「同一件事说两遍」，
    #     而重复会让「一条」看起来像「两条」（见 §9.9b 的排版版）。
    if bundle.unread_toast and K_ALERT not in no_leg:
        parts.append(
            "出声档里还有 %s 不属任何一档，本报告不读它们"
            % "、".join("%s %d 条" % (k, v)
                       for k, v in sorted(bundle.unread_toast.items())))

    if not parts:
        # 三条腿全跑成、都产出了结论、且三档都有腿 —— 此时 0 是干净的 0。
        # ★ 仍然要带分母，否则它读起来和「没查」一样。
        parts.append("三档都有腿读过，且都读到 0 条 —— 这是「查了，没有」")

    return "；".join(parts) + "。"


def from_verdict(survey_json: Dict[str, Any], read_at: str
                 ) -> Tuple[List[Evidence], List[str], Dict[str, str]]:
    """第三只腿的产物（裁决面普查）→ 证据。

    ★ 为什么要簇而不是一条一条：同一条规则在一次会话里能命中十几次
      （实测 11-02：AN-009 在一个会话里 9 次）。一页纸放不下十几次，
      而「挡了 9 次 AN-009」与「9 次都要人看一眼」是两件事
      ⇒ **簇里保留总条数，报告里一条结论 + 一个总条数，两样都在**
      （铁律 35：拦截时归并、记账时分开）。

    ★ 强度分档由 `verdict_leg` 判好（带规则号 ⇒ held；不带 ⇒ no_response）。
      这里**不重判** —— 两处各判一次必然漂（铁律 R4）。
    """
    evs: List[Evidence] = []
    notes: List[str] = []
    dens: Dict[str, str] = {}

    for c in survey_json.get("clusters") or []:
        cites = _fmt_evidence(
            [(d, ln) for d, ln in (c.get("cites") or [])[:5]]
        )
        if not cites:
            notes.append(
                "裁决簇 %s 没有出处 —— 不装成证据（契约：证据不许无出处）"
                % (c.get("rule_id") or "?")
            )
            continue
        strength = c.get("strength") or K_LOG_ONLY
        claim = c.get("claim") or ""
        rule_id = c.get("rule_id") or ""
        session = c.get("session") or ""
        band = c.get("band") or ""
        # ★ 无规则号的簇不许被说成「规则挡住了」⇒ 它落 no_response 档，
        #   而 no_response 的措辞由 WORD 统一持有，渲染层不许改写。
        blind = (
            "只看账本里写好的裁决记录；簇的聚合键是「规则×会话×带」，"
            "换一种分法簇数会变（条数守恒、簇数不守恒）"
        )
        if not rule_id or rule_id == "（无规则号）":
            blind += "；这一簇没有规则号 —— 它不是「规则挡住了」，是监理自身状态异常"
        evs.append(
            Evidence(
                # ★ 身份＝**簇的聚合键**（规则|会话），不是 claim，也不带裁决取值。
                #   claim 里嵌着 `n_records`（「挡下 9 次」），账本每长一条它就变
                #   ⇒ 同一条结论每天换一个 id ⇒ 用这个号指名永远指不中。
                #   ★ 也不许把 `decision` 放进来（2026-11-02 深夜修）：聚合键本身
                #     已经不含 decision（block 与 deny 同义，放进去会把同一次动作
                #     拆成两簇），而这里若仍读 `c["decision"]`，那个键**已经不存在**
                #     ⇒ 恒取空串，看起来「稳定」，实际是**一个恒空字段在冒充身份**。
                #     这种错不会报错，它只会让身份在有人把键加回来时静默改变。
                #   ★ 2026-11-03 再补一段 `band`：同规则同会话的「挡下」与「提醒」
                #     是两个不同的簇（`verdict_leg` 已把带写进聚合键），但它们的
                #     规则号与会话号**完全一样** ⇒ 只用前两段做身份，两条证据会拿到
                #     同一个 eid。实测 11-02 的 AN-010／g0517rf 就同时有挡下与提醒。
                #     **两条不同的结论共用一个号**，比「同一个东西两个号」更坏：
                #     更正链按 eid 指名，指一条会同时改两条。
                eid=_stable_id("VDT", "%s|%s|%s" % (rule_id or "norule", session, band), ()),
                claim=claim,
                strength=strength,
                cites=cites,
                source="verdict_leg/%s" % (c.get("rule_id") or "（无规则号）"),
                read_at=read_at,
                rule_id="" if rule_id in ("", "（无规则号）") else rule_id,
                blind=blind,
                items=tuple(c.get("types") or ()),
            )
        )

    for k, v in (survey_json.get("denominators") or {}).items():
        dens["裁决面·%s" % k] = str(v)
    notes += list(survey_json.get("undecidable") or [])
    return evs, notes, dens


def verdict_leg_report(survey_json: Dict[str, Any], ran: bool,
                       note: str = "") -> "LegReport":
    """第三只腿的实况 → `LegReport`。**`produces` 读它自己声明的，不在这里猜。**

    ★ 为什么必须读它的声明而不是推断：第一版想「这条腿当然能产 held 和
      no_response」，而它实际只读 block/deny ⇒ **「提醒」这一档它压根不读**。
      推断出来的答案是「三档都有腿」，真答案是「只有两档有腿」。
      差别不在数字，在于**页面上那个 0 会被读成「今天没有提醒」**。
    """
    produces = tuple(survey_json.get("produces") or ())
    # ★ 只取**两条带的主分母**进归因句。把全部分母塞进一句会变成一堵墙，
    #   而读者在那一句里要回答的只有一个问题：「这条腿读了什么、读了多少」。
    #   其余分母照旧进页脚（`bundle.denominators`），一条不少。
    # ★ 2026-11-03：从「只取一条」改成「两条带各取一条」。只报停下等人的话，
    #   读者会以为这条腿只读了那一半 —— 而「提醒面 34 条」正是这次新接上的那一半。
    _dens = survey_json.get("denominators") or {}
    dens = "｜".join(
        "%s：%s" % (k, _dens[k]) for k in ("停下等人", "告警放行") if _dens.get(k)
    )
    return LegReport(
        name="裁决面",
        ran=ran,
        produces=produces,
        denominator=dens,
        note=note,
    )


def collect(root: str, *, watch_args: Optional[List[str]] = None) -> Bundle:
    """跑三条腿，装成一份 Bundle。**任何一条腿崩，都进 undecidable 而不是消失。**"""
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

    # ★ 第三只腿（2026-11-02 落实，替代方案判据 L1-1）：
    #   前两条腿都不读 `decision` 字段 ⇒ 账本里当天真的发生的裁决一条都进不了结论。
    #   实测 11-02：真账本按产品侧通知面口径有 29 条真裁决，
    #   而一页纸写「需要你看一眼 0 条」—— 根因在取材层，不在渲染层。
    #   这条腿**只读账本**，不写账本、不改产品代码。
    verdict, err_v = _run_json("verdict_leg.py", root)

    if err_v:
        bundle.undecidable.append(f"裁决面普查（verdict_leg）没跑成：{err_v}")

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
    # ★ 每条腿都要留一份实况 —— 「0 条」的归因靠它，不靠渲染层猜。
    #   `produces` 是**腿自己声明的**：auditor 只产 checked（账本自洽），
    #   watchman 产 checked＋log_only。这两条腿**都不产** held/alert/no_response。
    bundle.legs.append(LegReport(
        name="账本自洽",
        ran=bool(audit),
        produces=(K_CHECKED,) if audit else (),
        denominator=bundle.denominators.get("账本", ""),
        note="" if audit else (err_a or ""),
    ))
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
    bundle.legs.append(LegReport(
        name="变化巡检",
        ran=bool(watch),
        produces=(K_CHECKED, K_LOG_ONLY) if watch else (),
        denominator=bundle.denominators.get("巡检窗口", ""),
        note="" if watch else (err_w or ""),
    ))
    if verdict:
        read_at = read_at or verdict.get("read_at") or ""
        evs, notes, dens = from_verdict(verdict, read_at)
        bundle.evidence += evs
        # ★ 2026-11-02 深夜修：`plain()` 必须在这一层就做掉。
        #   前两条腿的盲区都走 `blind_of()`，那里做了 `plain()`；第三只腿的
        #   盲区是**现成的字符串列表**，直接 `+=` 就把它跳过了 ——
        #   于是 `verdict_leg` 里那些「本腿**一条不读**」的星号原样进了 HTML。
        #   实测由 `端到端负控 e7` 抓到（折叠样本里出现 `**`）。
        #   ★ 这是 R4（同一件事一处实现）的典型失守：两条路径做同一件事，
        #     其中一条忘了做，而**忘了的那条不会报错**，它只会少洗一次。
        bundle.undecidable += [plain(x) for x in notes]
        # ★ 分母**必须带口径**（F40）：这三个数分列，不许合成一个。
        bundle.denominators.update(dens)
        bundle.blind += tuple(plain(x) for x in (verdict.get("blind") or ()))
        # ★ 「没读的那一档」跟着腿一起回来 —— 它是「提醒」这一档 0 的来源。
        bundle.unread_toast.update(verdict.get("unread_toast") or {})
        # ★ 2026-11-03：读到了但装不进任何一档的那一批（无规则号的出声记录），
        #   以及守恒账。**两者都必须原样带出来**：前者是「读了没装」与「没有」
        #   的分界，后者是「每个数加得起来」的唯一凭据。
        bundle.untiered_alert.update(verdict.get("untiered_alert") or {})
        bundle.balance = verdict.get("balance") or {}
    # ★ 第三只腿的 `produces` **读它自己的声明**，不在这里推断。
    #   崩了也要有一条实况：`ran=False` 与「读了没有」长得一样，含义相反。
    bundle.legs.append(
        verdict_leg_report(verdict, bool(verdict), err_v) if verdict
        else LegReport(name="裁决面", ran=False, produces=(),
                       denominator="", note=err_v or "没跑成")
    )

    bundle.read_at = read_at or "（未取到读数时刻）"
    if not bundle.read_at.startswith("20"):
        # 读数时刻取不到 ⇒ 所有回指都失去锚点（当天文件行号会漂）。这是硬缺口。
        bundle.undecidable.append(
            "没取到读数时刻 —— 当天文件的回指无法复核（行号在读取之后仍会变）"
        )

    if not bundle.evidence and not bundle.undecidable:
        # ★ 三条腿都跑成、且都没报东西。这是**真的干净**，还是**腿都哑了**？
        #   只有「跑成了」才能这么说。
        # ★ 这句话原文写「两条腿都跑成」—— 第三只腿接上后它就是错的：
        #   它会让读者以为「全查过了」，而实际「提醒」那一档今天没有腿读。
        #   判据 L1-2 说的就是这个：「要修的不是这句话，是它的适用范围」。
        n_ran = sum(1 for lg in bundle.legs if lg.ran)
        no_leg = bundle.tiers_with_no_leg()
        tail = ""
        if no_leg:
            tail = ("。但「%s」这一档今天没有腿读 —— 这个干净只覆盖有腿的档"
                    % "」「".join(WORD[t] for t in no_leg))
        bundle.denominators["结论"] = (
            "%d 条腿跑成且都无异常 —— 这是「查了，没有」，不是「没查」%s"
            % (n_ran, tail)
        )
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

    # ⑧ 0 条的解释里不许有 `**`（它会被原样印进 HTML），
    #    且**必须按实际来源说话**（2026-11-02 新增，本轮改版的判据）。
    #    ★ 这条负控守的是「归因过期」：旧版这里写死一句「挡下/提醒结构上产不出来」，
    #      第三只腿接上后那句话就变成了假话。**写死的归因一定会过期** ——
    #      所以要验的不是「有没有这句话」，而是「换一种腿状态，话会不会跟着变」。
    _b = Bundle(read_at="t", root="")
    _b.legs = [
        LegReport(name="账本自洽", ran=True, produces=(K_CHECKED,), denominator="日文件 1 个"),
        LegReport(name="变化巡检", ran=True, produces=(K_CHECKED, K_LOG_ONLY)),
        LegReport(name="裁决面", ran=True, produces=(K_HELD, K_NO_RESPONSE),
                  denominator="按 decision 值数 43 条"),
    ]
    _b.unread_toast = {"alert": 441}
    _note_ok = need_zero_note(_b)
    if "**" in _note_ok:
        fails.append("need_zero_note 里有 `**` —— 会原样印进 HTML")
    if "查了，没有" not in _note_ok:
        fails.append("有腿覆盖的档没有说「查了，没有」：%r" % (_note_ok,))
    if "没有任何一条腿去读" not in _note_ok:
        fails.append("「提醒」这一档没腿读，归因里却没说出来：%r" % (_note_ok,))
    if "441" not in _note_ok:
        fails.append("没腿读的档没给出「今天实际有多少条」：%r —— "
                     "0 会被读成「今天没有提醒」" % (_note_ok,))

    # 负控：把裁决腿改判成「没跑成」，归因**必须**跟着变（不许还说「查了，没有」）
    _b2 = Bundle(read_at="t", root="")
    _b2.legs = [
        LegReport(name="账本自洽", ran=True, produces=(K_CHECKED,)),
        LegReport(name="裁决面", ran=False, produces=(), note="超时"),
    ]
    _note_dead = need_zero_note(_b2)
    if "查了，没有" in _note_dead and "没跑成" not in _note_dead:
        fails.append("裁决腿没跑成，归因却仍说「查了，没有」：%r" % (_note_dead,))
    if "没跑成" not in _note_dead:
        fails.append("腿没跑成，归因里没说出来：%r" % (_note_dead,))

    # 负控：不给 bundle ⇒ 必须说「说不出」，**不许**退回那句旧文案
    if "查了，没有" in need_zero_note(None):
        fails.append("不给腿实况时，归因却给出了肯定结论 —— "
                     "说不出归因的 0 不许被当成「没事」")

    # ---- 2026-11-03 新增：提醒面接上之后的两条归因 ----
    # ⑨ 「提醒」这一档**有了腿读**，归因必须**跟着变**：
    #    旧版这里必然是「没有任何一条腿去读」，而现在那句话是假的。
    #    ★ 这条守的正是「写死的归因会过期」：同一个 0，换了腿的覆盖情况，
    #      话必须跟着换 —— 否则它就从「盲区说明」退化成「自我安慰」。
    _b3 = Bundle(read_at="t", root="")
    _b3.legs = [
        LegReport(name="账本自洽", ran=True, produces=(K_CHECKED,), denominator="日文件 1 个"),
        LegReport(name="裁决面", ran=True,
                  produces=(K_HELD, K_ALERT, K_NO_RESPONSE),
                  denominator="提醒面 665 条｜落桶 353 条"),
    ]
    _n3 = need_zero_note(_b3)
    if "没有任何一条腿去读" in _n3:
        fails.append("「提醒」这一档已经有腿读了，归因却还写着没腿读：%r —— "
                     "过期 24 小时的自我安慰" % (_n3,))
    if "查了，没有" not in _n3:
        fails.append("三档都有腿读且都读到 0 条，归因里没有「查了，没有」：%r" % (_n3,))
    if "665" not in _n3:
        fails.append("有腿覆盖的档没带分母：%r —— 报数不带分母等于没报" % (_n3,))

    # ⑩ 「读到了、没档可落」必须与「没有」区分开（第五种 0 的雏形）
    _b4 = Bundle(read_at="t", root="")
    _b4.legs = [LegReport(name="裁决面", ran=True,
                          produces=(K_HELD, K_ALERT, K_NO_RESPONSE),
                          denominator="提醒面 665 条")]
    _b4.untiered_alert = {"host_changed": 302}
    _n4 = need_zero_note(_b4)
    if "302" not in _n4:
        fails.append("没档可落的那一批没给出条数：%r —— 读者会当成「没有」" % (_n4,))
    if "读到了、没档可落" not in _n4:
        fails.append("没档可落的那一批被说成了别的东西：%r —— "
                     "说成「没有」冤了读者，说成「没读」冤了那条腿" % (_n4,))

    # ⑪ 出声档里不属任何一档的取值（配置失效等）仍然是「没读」，必须说出来
    _b5 = Bundle(read_at="t", root="")
    _b5.legs = [LegReport(name="裁决面", ran=True,
                          produces=(K_HELD, K_ALERT, K_NO_RESPONSE),
                          denominator="提醒面 665 条")]
    _b5.unread_toast = {"config_fallback": 7}
    _n5 = need_zero_note(_b5)
    if "config_fallback" not in _n5:
        fails.append("出声档里没读的取值没被说出来：%r —— "
                     "读者会以为出声档都读过了" % (_n5,))

    for f in fails:
        print(f"[自检失败] {f}", file=sys.stderr)
    if fails:
        return 1
    print("[自检] 十二条硬约束全部生效（空出处／无号挡下／合法挡下／词表外／散文星号不外泄／"
          "盲区三形态／SKIP 进不适用／0 的解释无星号且按实际来源／0 的归因有负控／"
          "提醒面接上后归因跟着变／没档可落的档必须说出来／出声档没读的取值必须说出来）")
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
