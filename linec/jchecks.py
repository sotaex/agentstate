# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""J1–J6：**六条判据，每条自带正控与负控**。

──────────────────────────────────────────────────────────────────────────
它治的病：判据写在文档里等于没有判据
──────────────────────────────────────────────────────────────────────────
`output/Antinel·报告形态：七问的天花板与替代方案（2026-11-02）.md` 里有六条判据
（J1 来源可回指／J2 分母不混装／J3 守恒账／J4 三态不分装／J5 守不住不被混装／
J6 措辞单一真源）。到 2026-11-02 为止，**六条一条都没进 `selfproof.CHECKS`**。

文档里的判据有两个结局，都不好：
  · 被人忘了 —— 而「忘了」不会报错；
  · 被人记住了，但记成了**结论**（「我们做到了 J3」），而不是**可执行的东西**。
    后者更危险：它听起来像一次验收。

──────────────────────────────────────────────────────────────────────────
每条判据的解剖：三条腿，缺一条就变成装饰
──────────────────────────────────────────────────────────────────────────
  ① 正判据   —— 合规的样本必须通过。
  ② 反向对照 —— **故意破坏**，判据必须报红。
  ③ 可翻面   —— 把「该红的样本」当正控喂进去，或者反过来，结论必须跟着翻。

★ 为什么 ③ 必须单独写（第十四族的代价）：
  **永远命中或永远清白的判据，与真判据同貌。** 一条只见过合规样本的检查，
  和一个 `return True` 在行为上完全一样。所以要证明它能红——
  而且要用**产品自己的形状**去喂它，不是用我编的形状。

★ 为什么每条判据单列一个闸门项（而不是合成一项）：
  红的时候要能**指名**是哪一条破了。合成一项的话，报出来的是
  「J1–J6 失败」，而人接着要做的第一件事就是去猜是哪一条——猜的成本
  比多跑五个进程高得多。`selfproof.CHECKS` 里六条各占一项（17 → 23）。

──────────────────────────────────────────────────────────────────────────
它不做什么
──────────────────────────────────────────────────────────────────────────
· 不判「报告说得好不好」，只判六条**结构性**的东西（能不能回指、加不加得起来、
  三态分不分得开、档名有没有第二份）。
· 不读真账本做判据（铁律 41：真账本天天变，把「今天多少条」写成判据 ⇒ 明天就红）。
  只在使用**受控夹具**时读账本，且夹具由本文件自己造。
· 不发判据号。`J1`–`J6` 是文档内部代号，按那份文档的说法，进 CI 从 `S105` 起——
  那一步要创始人拍板，本文件只把它们变成**可执行的东西**，不改号段。
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from typing import Callable, Dict, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
LINE_C = HERE
OUTPUT = os.path.dirname(LINE_C)
if LINE_C not in sys.path:
    sys.path.insert(0, LINE_C)

import citecheck as CC  # noqa: E402
import evidence as E  # noqa: E402
import onepager as OP  # noqa: E402
import verdict_leg as V  # noqa: E402

#: 一条臂的结果：(名字, 是否通过, 说明)。**说明必须带上量到的数**，
#: 否则红了以后第一件事还是去猜。
Arm = Tuple[str, bool, str]


def _ev(strength: str, claim: str, *, rule_id: str = "", day: str = "2026-01-01",
        lineno: int = 1, source: str = "jchecks", status: str = "",
        blind: str = "") -> "E.Evidence":
    return E.Evidence(eid=E._stable_id("J", claim, (E.Cite(day, lineno),)),
                      claim=claim, strength=strength,
                      cites=(E.Cite(day, lineno),), source=source,
                      read_at="2026-01-01 00:00:00", rule_id=rule_id,
                      status=status, blind=blind)


def _strip_style(html: str) -> str:
    """去掉 `<style>`：CSS 注释不是给读者看的字。

    ★ 这个豁免要说清理由，不许默默做：`onepager` 的 CSS 注释里写了档名的
      中文（解释色值用）。它随文件归档、但不随页面显示。J6 管的是
      「读者能看到的每个词」。**排除它 ≠ 放它过关**：`**` 那条判据
      （onepager 自检）连 CSS 一起查，因为它关心的是「产物里有没有脏字节」。
      两条判据的口径不同，因为问的问题不同。
    """
    return re.sub(r"<style>.*?</style>", "", html, flags=re.S)


def _mk_ledger(days: Sequence[Tuple[str, Sequence[Dict]]]) -> str:
    """造一份只给 `verdict_leg.survey()` 读的账本（不建链、不建清单）。

    ★ 只为 J5 用：它要验的是「宿主盾事件有没有被单独计数」，
      而这件事需要**真的走一遍 survey 的循环**，不能拿构造的 Survey 假装。
      `survey()` 只读 decision/type/rule/ts/session/tool/input/reason/severity，
      不碰链 ⇒ 夹具可以很薄。
    ★ 目录建在系统 TEMP：本机 D 盘的 unlink 不可用，建在仓库里会留下搬不走的残骸。
    """
    root = os.path.join(tempfile.mkdtemp(prefix="antinel-j-"), "audit")
    os.makedirs(root)
    for day, recs in days:
        with open(os.path.join(root, day + ".jsonl"), "w",
                  encoding="utf-8", newline="\n") as fh:
            for r in recs:
                fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    return root


# --------------------------------------------------------------------------- J1


def j1(html_of: Callable) -> List[Arm]:
    """J1 来源可回指率：每条结论都能落到 `日:行`，且该有规则号的必须有。

    判据原话：「每条结论有 `日:行 + 规则号 + 动作`」，负控是
    「造一条无规则号的，必须掉到『已记录未判定』」。

    ★ 这里把它落成两条**行为**断言（不是文案断言）：
      · 产物里每条 `.ev` 都带 `data-eid` 与 `data-cites`（缺一个就核不了）；
      · 带规则号的档（挡下／提醒）必须带 `data-rule`，无规则号的档**不许**带
        —— 后者防的是「给它安一个规则号让页面看起来更权威」。
    """
    arms: List[Arm] = []

    b = E.Bundle(read_at="2026-01-01 00:00:00", root="")
    b.evidence = [
        _ev(E.K_HELD, "AN-001：动作未执行 2 次", rule_id="AN-001"),
        _ev(E.K_ALERT, "AN-002：动作仍然执行了 3 次", rule_id="AN-002", lineno=2),
        _ev(E.K_NO_RESPONSE, "监理自身异常，动作未执行 1 次", lineno=3),
        _ev(E.K_LOG_ONLY, "某条线索变了", lineno=4),
    ]
    html = html_of(b)
    n_ev = html.count('class="ev ')
    arms.append(("J1 契约齐全", n_ev == 4, "产物里 .ev 条目 %d 条（应 4）" % n_ev))
    for attr, want in (("data-eid=", 4), ("data-cites=", 4), ("data-rule=", 2)):
        got = html.count(attr)
        arms.append(("J1 %s 计数" % attr, got == want,
                     "%s 出现 %d 次（应 %d）" % (attr, got, want)))

    # ① 正判据：整份产物交给 citecheck 自己判（**不另写一套**，R4）
    bad, notes, stats = CC.check(html, os.path.join(OUTPUT, "__no_such_ledger__"),
                                 expect_n=4)
    arms.append(("J1 citecheck 正控", not bad, "坏 %d 项／不可判 %d 项：%s"
                 % (len(bad), len(notes), "；".join(bad[:2]) or "无")))

    # ② 反向对照：把一条的 data-cites 抹掉 ⇒ 必须报「没有出处」
    broken = html.replace('data-cites="2026-01-01:3"', 'data-cites=""')
    if broken == html:
        arms.append(("J1 反向对照可构造", False,
                     "夹具没改动产物 —— 这条负控什么也没验到"))
    else:
        bad2, _n2, _s2 = CC.check(broken, os.path.join(OUTPUT, "__no_such_ledger__"),
                                  expect_n=4)
        arms.append(("J1 反向对照", bool(bad2),
                     "抹掉一处出处后 citecheck：%s" % ("；".join(bad2[:2]) or "没报")))

    # ③ 可翻面：无规则号的「挡下」必须造不出来（契约层面，不是文案层面）
    try:
        _ev(E.K_HELD, "伪造的一条挡下")
        arms.append(("J1 无号挡下被拒", False,
                     "无规则号的挡下被放过了 —— 会把核对结论说成拦截"))
    except ValueError as exc:
        arms.append(("J1 无号挡下被拒", True, "被契约拒绝：%s" % str(exc)[:60]))
    return arms


# --------------------------------------------------------------------------- J2

#: 「同一句里两个分母必须自己说清差额」的识别器。
#:
#: ★ 为什么是这两个词：`verdict_leg` 的簇同时带「次」（动作数）与「条」（记录数），
#:   而这两个数**天然不等**（同一次动作被多个钩子各记一遍）。F40 的作案现场
#:   就是「两个数印在一起、谁也不说差额」。所以判据只盯这一种句式。
_UNIT_ACTION = re.compile(r"(\d+)\s*次")
_UNIT_RECORD = re.compile(r"(\d+)\s*条")
_EXPLAINED = ("同一次动作", "差额", "各记一遍")


def j2() -> List[Arm]:
    """J2 分母不混装：一个数只承担一个分母；两个一起出现时必须说清差额。"""
    arms: List[Arm] = []

    def unexplained(text: str) -> bool:
        a = _UNIT_ACTION.search(text)
        r = _UNIT_RECORD.search(text)
        if not (a and r):
            return False                    # 只有一个单位 ⇒ 没有混装
        if a.group(1) == r.group(1):
            return False                    # 两个数相等 ⇒ 没有差额可解释
        return not any(m in text for m in _EXPLAINED)

    # ① 正判据：真簇产出的句子都不许被这个识别器抓到
    c_dup = V.Cluster(rule_id="AN-009", session="s", severity="critical",
                      n_records=18, n_actions=9, has_rule=True)
    c_eq = V.Cluster(rule_id="AN-010", session="s", severity="critical",
                     n_records=3, n_actions=3, has_rule=True)
    c_al = V.Cluster(rule_id="AN-010", session="s", severity="warning",
                     band=V.BAND_ALERT, n_records=28, n_actions=26, has_rule=True)
    for name, c in (("挡下·记录多于动作", c_dup), ("挡下·记录等于动作", c_eq),
                    ("提醒·记录多于动作", c_al)):
        arms.append(("J2 正控·%s" % name, not unexplained(c.claim()),
                     "判为混装：%r" % (c.claim(),)))

    # ② 反向对照：**故意把差额抹掉**，识别器必须报
    naked = "AN-009 挡下 9 次 18 条"
    arms.append(("J2 反向对照·抹掉差额", unexplained(naked),
                 "抹掉差额后识别器%s" % ("报红" if unexplained(naked) else "没报")))
    # ③ 可翻面：把差额加回去，同一条必须转绿
    fixed = "AN-009 挡下 9 次（账本 18 条记录，同一次动作被多个钩子各记一遍）"
    arms.append(("J2 可翻面·补回差额", not unexplained(fixed),
                 "补回差额后识别器%s" % ("仍报红" if unexplained(fixed) else "转绿")))

    # ④ 分母必须印在页脚：**每个数字都要能回答「这是哪个分母」**
    b = E.Bundle(read_at="t", root="")
    b.denominators["甲口径"] = "9 次动作｜18 条记录"
    b.denominators["乙口径"] = "只数落桶的"
    html = _strip_style(OP.render(b))
    for k, v in b.denominators.items():
        arms.append(("J2 分母上屏·%s" % k, k in html and v in html,
                     "页脚里%s" % ("都有" if (k in html and v in html) else "缺了")))
    return arms


# --------------------------------------------------------------------------- J3


def j3() -> List[Arm]:
    """J3 守恒账：`候选 == 展示 + 折叠 + 合并 + 不适用`，且破裂必须报红。"""
    arms: List[Arm] = []

    # ① 正判据：闭合的账
    s = V.Survey(read_at="t", day="d", n_verdicts=4, n_non_event=1, n_bucketed=3,
                 n_gate=3, n_toast=2, n_alert_raw=2, n_alert_bucketed=2)
    s.clusters = [
        V.Cluster(rule_id="A", session="s", severity="none", band=V.BAND_GATE,
                  n_records=3, n_actions=2, has_rule=True),
        V.Cluster(rule_id="B", session="s", severity="none", band=V.BAND_ALERT,
                  n_records=2, n_actions=2, has_rule=True),
    ]
    broken = s.balance()["broken"]
    arms.append(("J3 记账层闭合", not broken, "破裂项 %d 个：%s"
                 % (len(broken), "；".join(broken[:2]) or "无")))

    # ② 反向对照：吞掉一条 ⇒ 必须报
    s2 = V.Survey(read_at="t", day="d", n_alert_raw=3, n_alert_bucketed=2)
    s2.clusters = [s.clusters[1]]
    arms.append(("J3 反向对照·吞一条", bool(s2.balance()["broken"]),
                 "吞掉一条后破裂项 %d 个" % len(s2.balance()["broken"])))

    # ③ 渲染层：四项加和必须等于候选，且破裂时必须自己喊
    ok_bal = OP.Balance(candidates=10, shown=3, folded=5, merged=2,
                        not_applicable=0)
    arms.append(("J3 渲染层四项加和", ok_bal.closed(),
                 "3+5+2+0 = %d，候选 %d" % (ok_bal.total(), ok_bal.candidates)))
    bad_bal = OP.Balance(candidates=10, shown=3, folded=5, merged=1,
                         not_applicable=0)
    arms.append(("J3 反向对照·少一项", not bad_bal.closed() and "对不上" in bad_bal.line(),
                 "破裂时的那一行：%r" % (bad_bal.line(),)))

    # ④ 上屏：守恒式必须**印在页面上**，不是只算在内存里
    b = E.Bundle(read_at="t", root="")
    b.balance = {"rows": [{"band": "gate", "name": "裁决面（停下等人）",
                           "candidates": 49, "into_evidence": 6, "merged": 27,
                           "not_applicable": 16, "untiered": 0}], "broken": []}
    html = _strip_style(OP.render(b))
    arms.append(("J3 守恒式上屏",
                 "候选 49 ＝ 进证据 6 ＋ 合并 27 ＋ 不适用 16" in html,
                 "页面里%s" % ("有" if "候选 49" in html else "没有")))
    return arms


# --------------------------------------------------------------------------- J4


def j4() -> List[Arm]:
    """J4 三态不分装：「查了没有」≠「没查」≠「不适用」，三者在页面上必须不同貌。"""
    arms: List[Arm] = []

    # a) 三档都有腿、都读到 0 条
    a = E.Bundle(read_at="t", root="")
    a.legs = [E.LegReport(name="裁决面", ran=True,
                          produces=(E.K_HELD, E.K_ALERT, E.K_NO_RESPONSE),
                          denominator="停下等人 0 条")]
    ha = _strip_style(OP.render(a))

    # b) 腿没跑成
    bb = E.Bundle(read_at="t", root="")
    bb.legs = [E.LegReport(name="裁决面", ran=False, produces=(), note="超时")]
    bb.undecidable.append("裁决面普查（verdict_leg）没跑成：超时")
    hb = _strip_style(OP.render(bb))

    # c) 不适用（跑了，但这把尺子量不到）
    c = E.Bundle(read_at="t", root="")
    c.not_applicable.append("A5 总量 不适用：未给 --declare")
    hc = _strip_style(OP.render(c))

    arms.append(("J4 查了没有", "查了，没有" in ha, "a 份：%s"
                 % ("有" if "查了，没有" in ha else "没有")))
    arms.append(("J4 没跑成", "没跑成" in hb, "b 份：%s"
                 % ("有" if "没跑成" in hb else "没有")))
    arms.append(("J4 不适用", "不适用（1 项）" in hc, "c 份：%s"
                 % ("有" if "不适用" in hc else "没有")))

    # ② 反向对照：三份不许长得一样（互不冒充）
    #   ★ 逐对判，不是「三份哈希不同」——哈希不同只能证明字节不同，
    #     而这里要证明的是**该出现的那句话没有出现在不该出现的份里**。
    arms.append(("J4 b 不许说查了没有", "查了，没有" not in hb,
                 "没跑成的那份%s说「查了，没有」"
                 % ("还是" if "查了，没有" in hb else "没有")))
    arms.append(("J4 c 不许说没跑成", "没有跑成" not in hc,
                 "不适用那份%s说「没有跑成」"
                 % ("还是" if "没有跑成" in hc else "没有")))

    # ③ 可翻面：把 b 的腿改成「跑成了」⇒ 页面不许再说没跑成
    bb.legs = [E.LegReport(name="裁决面", ran=True,
                           produces=(E.K_HELD, E.K_ALERT, E.K_NO_RESPONSE),
                           denominator="停下等人 0 条")]
    bb.undecidable.clear()
    hb2 = _strip_style(OP.render(bb))
    arms.append(("J4 可翻面·腿改活", "没跑成" not in hb2 and "查了，没有" in hb2,
                 "腿改活后：没跑成%s／查了没有%s"
                 % ("在" if "没跑成" in hb2 else "不在",
                    "在" if "查了，没有" in hb2 else "不在")))
    return arms


# --------------------------------------------------------------------------- J5


def j5() -> List[Arm]:
    """J5 守不住不被混装：宿主盾自检事件必须**单独计数**，不许并进规则命中。

    判据原话来自 `L2-3`：不可回指的裁决要拆成「守住了」（规则命中，有规则号）
    与「守不住」（守卫自己没上班）。这两件事分别计数、分别呈现。
    """
    arms: List[Arm] = []

    def rec(typ, dec, rule=None, ts="2026-01-01T00:00:00+08:00", day="2026-01-01"):
        r = {"ts": ts, "type": typ, "decision": dec, "severity": "critical",
             "session": "s1", "tool": "Bash", "input": {"command": "rm x"}}
        if rule:
            r["rule_id"] = rule
        return r

    days = [("2026-01-01", [
        rec("pre_tool_use", "block", "AN-009"),
        rec("host_shield_breach", "block"),              # 守不住（无规则号）
        rec("host_shield_dev_drift", "block", "AN-024"),  # 守卫事件，但带规则号
        rec("host_changed", "alert"),                     # 出声、无规则号
        rec("pre_tool_use", "alert", "AN-010"),           # 提醒（有规则号）
    ])]
    root = _mk_ledger(days)
    s = V.survey(root, day="2026-01-01")

    # ① 正判据：两条守不住的事件被单独计到
    arms.append(("J5 守不住单独计数", s.shield_counted() == 2,
                 "守不住计 %d 条（夹具里 2 条宿主盾事件）" % s.shield_counted()))
    # ★ 交叉核对：**逐条计数**与**簇上的 is_shield 标记**是两条独立的路，
    #   它们必须给出同一个数。写这条路的人与写那条路的人不是同一个时刻的自己
    #   —— 这正是「同一件事两处实现会不会漂」的最小可测形态。
    #   边界（写出来不藏着）：簇上的 is_shield 只看该簇**第一条**记录，
    #   混簇时它不是全貌 ⇒ 本臂只在夹具「一种类型一簇」时成立，够用且诚实。
    arms.append(("J5 计数与簇标记一致",
                 sum(1 for c in s.clusters if c.is_shield) == s.shield_counted(),
                 "簇上标了 %d 个／逐条计到 %d 条"
                 % (sum(1 for c in s.clusters if c.is_shield), s.shield_counted())))
    # 分母里必须有这一行，否则页面上只有一个「挡下 2 次」，读者分不出谁在挡
    line = s.denominators.get("守不住", "")
    arms.append(("J5 分母里有守不住", "宿主盾" in line and "2" in line,
                 "分母：%r" % (line,)))
    # 无档可落的那条必须只计数、不装档（J5 与 J3 联动的那个口子）
    arms.append(("J5 无号出声不装档",
                 s.untiered_alert.get("host_changed") == 1
                 and not any(c.band == V.BAND_ALERT and not c.has_rule
                             for c in s.clusters),
                 "无档可落 %r；alert 带里的无规则号簇 %d 个"
                 % (s.untiered_alert,
                    sum(1 for c in s.clusters
                        if c.band == V.BAND_ALERT and not c.has_rule))))

    # ② 反向对照：**把类型改掉**（不再叫 host_shield_*）⇒ 计数必须归零。
    #   ★ 这一条是判据的翻面测试：如果计数写死在代码里（或恒等于某个常数），
    #     改数据它不会变 ⇒ 这里必须红。
    days2 = [("2026-01-01", [
        rec("pre_tool_use", "block", "AN-009"),
        rec("something_else", "block"),
        rec("something_else", "block", "AN-024"),
        rec("host_changed", "alert"),
        rec("pre_tool_use", "alert", "AN-010"),
    ])]
    s2 = V.survey(_mk_ledger(days2), day="2026-01-01")
    arms.append(("J5 反向对照·改类型", s2.shield_counted() == 0,
                 "把宿主盾类型改掉后仍计到 %d 条" % s2.shield_counted()))
    arms.append(("J5 反向对照·其余不变",
                 len(s2.clusters) == len(s.clusters),
                 "改类型前 %d 簇／后 %d 簇 —— 只该变守不住那个数"
                 % (len(s.clusters), len(s2.clusters))))
    return arms


# --------------------------------------------------------------------------- J6


def j6() -> List[Arm]:
    """J6 措辞单一真源：改 `WORD` 的中文，页面上**一个旧词都不许剩**。

    ★ 这条是把上一轮发现的 S08 判据漏洞变成自证漏洞的判据：
      S08 按**键名**扫六态键，换一批键名就绕过。而这里不看键名，
      看**中文值在产物里出没出现** —— 换键名绕不过去，因为词就是那个词。
    """
    arms: List[Arm] = []

    sentinel = {k: "哨兵词%d" % i for i, k in enumerate(sorted(E.WORD))}
    originals = dict(E.WORD)
    b = E.Bundle(read_at="t", root="")
    b.evidence = [
        _ev(E.K_HELD, "AN-001：动作未执行 2 次", rule_id="AN-001"),
        _ev(E.K_ALERT, "AN-002：动作仍然执行了 3 次", rule_id="AN-002", lineno=2),
        _ev(E.K_NO_RESPONSE, "监理自身异常，动作未执行 1 次", lineno=3),
        _ev(E.K_LOG_ONLY, "某条线索变了", lineno=4),
        _ev(E.K_CHECKED, "A3 日清单：一致", lineno=5),
    ]
    # 把「会引述档名的散文」也放进来，让扫描面覆盖盲区与归因句
    b.unread_toast = {"config_fallback": 7}
    b.untiered_alert = {"host_changed": 302}
    b.legs = [E.LegReport(name="裁决面", ran=True,
                          produces=(E.K_HELD, E.K_ALERT, E.K_NO_RESPONSE),
                          denominator="停下等人 1 条")]

    try:
        E.WORD.update(sentinel)
        html = _strip_style(OP.render(b))
        # 逐条抽出 (档位, 徽标文字)：**徽标是读者实际看到的那个词**。
        pairs: List[Tuple[str, str]] = []
        for blk in html.split('<div class="ev')[1:]:
            m = re.search(r'data-strength="([a-z_]+)"', blk)
            bm = re.search(r'<span class="badge"[^>]*>([^<]+)</span>', blk)
            if m and bm:
                pairs.append((m.group(1), bm.group(1)))
    finally:
        E.WORD.clear()
        E.WORD.update(originals)

    left = {w: html.count(w) for w in originals.values() if w in html}
    arms.append(("J6 改词后无旧词", not left,
                 "改词后页面上还剩旧档名：%s" % (left or "无")))
    missing = [v for v in sentinel.values() if v not in html]
    arms.append(("J6 新词必须上屏", not missing,
                 "改词后页面上找不到 %d 个新词：%s"
                 % (len(missing), "、".join(missing[:2]) or "无")))

    # ② 反向对照：**故意留一处写死的旧词**，判据必须红
    #   ★ 用产品自己的形状喂它（一条 claim 里带档名），不是编一个字符串。
    _old = E.WORD[E.K_HELD]
    try:
        E.WORD[E.K_HELD] = "哨兵X"
        hard = _ev(E.K_HELD, "AN-001 挡下 2 次", rule_id="AN-001")
        b2 = E.Bundle(read_at="t", root="")
        b2.evidence = [hard]
        h2 = _strip_style(OP.render(b2))
        arms.append(("J6 反向对照·写死旧词", _old in h2,
                     "claim 里写死了「%s」，扫描%s抓到" % (_old, "" if _old in h2 else "没")))
    finally:
        E.WORD[E.K_HELD] = _old

    # ③ 可翻面：把那一处改成不含档名的说法 ⇒ **结论句**里必须找不到档名。
    #   ★ 范围只到「结论句」，不到整页：整页里还有一处在**合法的**引述档名 ——
    #     `排序规则：按结论强度（挡下 → 提醒 → …）`。那句是我们自己生成的、
    #     确实从 `WORD` 取（所以改词它会跟着变），但它**必然**含档名。
    #     ⇒ 判据必须分清「写死的档名」与「从真源取的档名」：
    #       前者的特征是**换词后不变**，后者换了就变。
    #       整页扫描（上面那条）用哨兵值验后者，这条用结论句验前者。
    b3 = E.Bundle(read_at="t", root="")
    b3.evidence = [_ev(E.K_HELD, "AN-001：动作未执行 2 次", rule_id="AN-001")]
    h3 = _strip_style(OP.render(b3))
    claims = re.findall(r'<div class="claim">([^<]*)</div>', h3)
    leaked = [w for w in originals.values() if any(w in c for c in claims)]
    arms.append(("J6 可翻面·结论句无档名", not leaked,
                 "结论句 %d 条，里面%s档名：%s"
                 % (len(claims), "有" if leaked else "没有", leaked or "无")))

    # ④ 徽标必须**逐条等于** `WORD` 里的词（不是「有个词就行」）——
    #   这一条防的是「五个档共用一句话」或「徽标缓存了旧值」。
    wrong = [(st, txt) for st, txt in pairs
             if sentinel.get(st) != txt]
    arms.append(("J6 徽标词逐条等于 WORD",
                 len(pairs) == 5 and not wrong,
                 "抽出 %d 个徽标，与哨兵不符 %d 个：%s"
                 % (len(pairs), len(wrong), wrong[:2] or "无")))
    return arms


def _runner(name: str) -> Callable[[], List[Arm]]:
    if name == "J1":
        return lambda: j1(OP.render)
    return {"J2": j2, "J3": j3, "J4": j4, "J5": j5, "J6": j6}[name]


NAMES = ("J1", "J2", "J3", "J4", "J5", "J6")


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="J1–J6 判据（每条自带正控与负控）")
    ap.add_argument("--j", default="", help="只跑一条：J1..J6")
    ap.add_argument("--all", action="store_true", help="六条全跑")
    ap.add_argument("--list", action="store_true", help="列出判据")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if args.list:
        for n in NAMES:
            print(n)
        return 0

    names = (args.j,) if args.j else NAMES
    if args.j and args.j not in NAMES:
        print("[停] 没有这条判据：%s（有 %s）" % (args.j, "、".join(NAMES)))
        return 2

    total = passed = 0
    fails: List[str] = []
    for n in names:
        print("=" * 70)
        print("%s" % n)
        print("-" * 70)
        try:
            arms = _runner(n)()
        except Exception as exc:                   # noqa: BLE001
            print("  [NG] %s 自己崩了：%s: %s" % (n, type(exc).__name__, exc))
            fails.append("%s 崩了：%s" % (n, exc))
            total += 1
            continue
        for arm_name, ok, detail in arms:
            total += 1
            passed += 1 if ok else 0
            print("  [%s] %-26s %s" % ("OK" if ok else "NG", arm_name, detail))
            if not ok:
                fails.append("%s／%s：%s" % (n, arm_name, detail))

    print()
    print("合计 %d 臂：通过 %d ／ 失败 %d" % (total, passed, len(fails)))
    if fails:
        print("失败项（这一条判据现在不成立，不许当成「已做到」）：")
        for f in fails[:20]:
            print("  · %s" % f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
