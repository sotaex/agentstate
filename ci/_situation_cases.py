#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""对拍夹具 57 行 —— 状态机新模型的唯一期望值来源。

★★ 本模块**只有数据，没有逻辑**：无断言、不 import 任何产品模块。
   理由（冻结件 §5.1 纪律 5）：夹具一旦含逻辑，它自己就成了「副本尺子」——
   产品与夹具同时改，两边一起错，判据照样绿。纯数据模块没有这个洞。

## 这 57 行是什么

31 行基线（地基件 §5.2 的 D-01 表）＋ 26 行新行（冻结件 §5.3 的 N5–N12）。
31 行是**四轴**输入（模式／值勤／可信／后果），26 行是**facts overrides** 输入
（相对 `BASE`）。两者输入形态不同，故每行带 `feed` 字段显式分派：

    feed="axes"      31 行基线：判据用 axes 构造 facts（反向映射在判据侧，不在这里）
    feed="facts"     N5–N10：判据用 BASE ⊕ overrides 得 facts
    feed="registry"  N11：直接查 0a 态注册表行的 `tense` 字段，不经 facts
    feed="notice"    N12：通知链场景，喂 `inbox_notify` 侧夹具，不经 facts

## 本模块对冻结件做的两处补全（已登记，勿当猜测）

- **#50**：`BASE` 缺 `egress_free_bytes`，而 §5.3 的 N6-c 在 overrides 里引用了它
  ⇒ 本模块补 `None` 入基线（「读不到」的合法表示，与 F1 三态一致）。
- **#51**：§5.3 的 `overrides` 列在 N11 行写的是描述性文字（「unarmed 成因行」）
  而非 dict ⇒ 规格的输入形态不统一。本模块用 `feed` 字段显式分派，N11/N12/31 行的
  `overrides` 一律 `None`（N12 例外：它的 overrides 是通知场景参数，是 dict）。
- **#52**：§5.3 的 N9-b 把 `period_line` 写进 overrides，但「期间行」是渲染层概念、
  facts 里没有该字段 ⇒ 本模块把它移入 `expect["period_line_text"]`。留在 overrides
  会让「overrides 键 ⊆ BASE」这条判据红，而那不是缺陷、是形态错位。

## 纪律（冻结件 §5.1 七条，逐条落在本文件）

1. 期望值**从设计意图派生**，不从现行实现抄；「现行今天给什么」不进本模块。
2. 夹具自带负控 —— 每行 `neg` 非空，写清「改什么 ⇒ 必须红」。
3. 判据化时断言改为 import 产品真源，本表退役进 `ci/`（本文件即退役落点）。
4. 「现行今天」列未活体实测，**不许转抄**（故本模块不含该列）。
5. **落点单源**：57 行只在这里，**不许抄进任何判据文件**（R4）。
6. 行格式五字段 `id`／`unit`／`overrides`／`expect`／`neg`，**缺一不进表**；
   `overrides` 只写与 `BASE` 不同的字段；**基线若变，全表重算**。
7. 换值自证：改期望值或负控值，同批跑「改一行 ⇒ 红 ⇒ 还原 ⇒ 绿」，提交信息记锚点。

## 与 #48 裁定的关系（重要）

`drill` **不是成因**，是模式层身份（冻结件 §11.4 四条结构证据）。故：

- 31 行里 `mode="drill"` 的 15 行，其 `expect["cause"]` 仍是八成因之一
  （blind/absent/breach/paused/draining/ok），`expect["mode"]` 单独记 `"drill"`；
- N11 的八行**全部是成因**（含 `partial`），原规格的「drill 成因行」已按裁定移除；
- drill 的身份断言（`tense == "never"`）不在 57 行内，见文件末尾
  `MODE_IDENTITY_CASES` —— 它断言的对象不是成因，放进 57 行会让
  「一行＝一个成因」这个不变量失真。

## 出处（每行可回源）

- 31 行：`docs/Antinel·状态机详细设计清单与地基件 v1.0（2026-10-22）.md` §5.2 表
- 26 行：`docs/Antinel·编码前无猜测审核与接口冻结 v1.0（2026-10-22）.md` §5.3 表
- 八成因键：`state_registry.STATES`（0a 真源，本模块**不 import**，只按值引用）
- 基线 facts：冻结件 §5.2「基线 facts」代码块（逐字，仅补 #50 一个字段）
"""

__all__ = [
    "BASE",
    "CASES",
    "MODE_IDENTITY_CASES",
    "FIELDS",
    "FEEDS",
    "ROW_COUNT",
]

#: 行格式五字段（纪律 6）。顺序即表格列序，判据按此顺序报错。
#: ★ 本模块在其上**增加第六个必需键 `feed`**（补全 #51：规格的输入形态不统一，
#:   31 行走四轴、N5–N10 走 facts、N11 走态注册表、N12 走通知链，不给显式标记
#:   就只能靠 unit 前缀猜）。判据验「六键齐全」，不是五键。
FIELDS = ("id", "feed", "unit", "overrides", "expect", "neg")

#: 输入形态四值（本模块对冻结件的补全 #51）。每行必须有 `feed`，缺一不进表。
FEEDS = ("axes", "facts", "registry", "notice")

#: 表行数（不心算：判据用 `len(CASES)` 复核，此常量只作交叉验证的第二把尺子）。
ROW_COUNT = 57

#: 基线 facts —— 全绿底。26 行共用，行内 `overrides` 只写与本表不同的字段。
#: ★ 逐字取自冻结件 §5.2，**唯一补全**是 `egress_free_bytes`（#50）。
#: ★ 单位一律照 F1：秒（`heartbeat_age`/`sentinel_uptime`）／ISO（无本表字段）／
#:   计数（`chain_write_lost`/`counts`）／小时（`granary_balance_hours`，
#:   源自 `granary.HOURS_PER_DAY=24`）／None（未知）。
BASE = {
    "scope_device": "DEV-0",
    "scope_host": None,
    "armed": True,
    "is_dev": False,                       # mode（D-02 既有字段）
    "sentinel_alive": True,
    "heartbeat_age": 120.0,                # 秒；fresh
    "heartbeat_source": "registered",
    "sentinel_uptime": 7200.0,
    "clock_skewed": False,
    "granary_level": "ok",
    "granary_balance_hours": 240,          # 小时（HOURS_PER_DAY=24）
    "credits_low_open": False,
    "self_check_ok": True,
    "chain_integrity_ok": True,
    "chain_write_lost": 0,
    "probe_error": None,                   # trust
    "gaps": [],                            # harm
    "outage_consequences": [],
    "partial_read": None,
    "at_risk": [],
    "chain_recon": "ok",
    "notice_state": None,
    "counts": {"action": 0, "info": 0},
    "egress_free_bytes": None,             # #50：本模块补入，N6-c 首个使用
}

#: 57 行。id 命名：31 行用 `D01-01`..`D01-31`（地基件表序），26 行用规格行号原值。
CASES = [
    # ---------------------------------------------------------------- 31 行基线
    # 四轴顺序：模式／值勤／可信／后果。灯值四值小写英文（F2 冻结）。
    # `mode` 与 `cause` 分开记：drill 是模式身份，不是成因（#48）。
    {
        "id": "D01-01",
        "feed": "axes",
        "unit": "F3",
        "overrides": None,
        "expect": {"mode": "unarmed", "lamp": "grey", "cause": "unarmed",
                   "action": "arm"},
        "neg": "把 unarmed 打回 L0 绿（现行行为）⇒ 必须红；F3 就是这一行",
    },
    {
        "id": "D01-02",
        "feed": "axes",
        "unit": "N1",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "red", "cause": "blind",
                   "action": "verify-reinstall"},
        "neg": "把 blind 说成 absent（现行给「失守」）⇒ 必须红：词错位",
    },
    {
        "id": "D01-03",
        "feed": "axes",
        "unit": "N1",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "red", "cause": "blind",
                   "action": "verify-reinstall"},
        "neg": "duty=at-risk 不该改变 blind 的灯与词 ⇒ 改任一项必红",
    },
    {
        "id": "D01-04",
        "feed": "axes",
        "unit": "N1",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "red", "cause": "blind",
                   "action": "verify-reinstall"},
        "neg": "duty=off 时把 blind 降成 paused ⇒ 必须红（看不清优先于不在岗）",
    },
    {
        "id": "D01-05",
        "feed": "axes",
        "unit": "N1",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "red", "cause": "blind",
                   "action": "verify-reinstall"},
        "neg": "drill 掩盖 blind 判成 L0 绿「研发中」（现行行为）⇒ 必须红；N1 灯错",
    },
    {
        "id": "D01-06",
        "feed": "axes",
        "unit": "N1",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "red", "cause": "blind",
                   "action": "verify-reinstall"},
        "neg": "同上，at-risk 变体：drill 不是豁免牌 ⇒ 判绿必红",
    },
    {
        "id": "D01-07",
        "feed": "axes",
        "unit": "N1",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "red", "cause": "blind",
                   "action": "verify-reinstall"},
        "neg": "drill/off：现行因 down 不看 dev 而给「失守」⇒ 词错位，判 absent 必红",
    },
    {
        "id": "D01-08",
        "feed": "axes",
        "unit": "absent",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "red", "cause": "absent",
                   "action": "revive+assess"},
        "neg": "把 absent 判成 breach ⇒ 必须红（不在岗 ∧ 有损失 ≠ 在岗但有缺口）",
    },
    {
        "id": "D01-09",
        "feed": "axes",
        "unit": "absent",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "red", "cause": "absent",
                   "action": "revive+assess"},
        "neg": "trust=bounded 不该把 absent 降级 ⇒ 改灯或改词必红",
    },
    {
        "id": "D01-10",
        "feed": "axes",
        "unit": "absent",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "red", "cause": "absent",
                   "action": "revive+assess"},
        "neg": "drill 下 absent 判绿 ⇒ 必须红（演练不是免责）",
    },
    {
        "id": "D01-11",
        "feed": "axes",
        "unit": "absent",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "red", "cause": "absent",
                   "action": "revive+assess"},
        "neg": "同上 bounded 变体：判 paused 必红",
    },
    {
        "id": "D01-12",
        "feed": "axes",
        "unit": "F1",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "red", "cause": "breach",
                   "action": "fix-listed"},
        "neg": "把「有 open 缺口」判成 L0 绿「没发现问题」（现行行为）⇒ 必须红；F1",
    },
    {
        "id": "D01-13",
        "feed": "axes",
        "unit": "F1",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "red", "cause": "breach",
                   "action": "fix-listed"},
        "neg": "trust=bounded 不豁免 breach ⇒ 判黄必红",
    },
    {
        "id": "D01-14",
        "feed": "axes",
        "unit": "F1",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "red", "cause": "breach",
                   "action": "fix-listed"},
        "neg": "duty=at-risk 不降 breach ⇒ 判 draining 必红（有缺口优先于缺粮）",
    },
    {
        "id": "D01-15",
        "feed": "axes",
        "unit": "F1",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "red", "cause": "breach",
                   "action": "fix-listed"},
        "neg": "同上 bounded 变体：判 partial 必红",
    },
    {
        "id": "D01-16",
        "feed": "axes",
        "unit": "F1",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "red", "cause": "breach",
                   "action": "fix-listed"},
        "neg": "drill 分支 `consequences=[]` 导致判绿（现行行为）⇒ 必须红；F1",
    },
    {
        "id": "D01-17",
        "feed": "axes",
        "unit": "F1",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "red", "cause": "breach",
                   "action": "fix-listed"},
        "neg": "同上 bounded 变体：drill 判绿必红",
    },
    {
        "id": "D01-18",
        "feed": "axes",
        "unit": "F1",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "red", "cause": "breach",
                   "action": "fix-listed"},
        "neg": "drill/at-risk：判 draining 必红（缺口优先于缺粮）",
    },
    {
        "id": "D01-19",
        "feed": "axes",
        "unit": "F1",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "red", "cause": "breach",
                   "action": "fix-listed"},
        "neg": "同上 bounded 变体：判 partial 必红",
    },
    {
        "id": "D01-20",
        "feed": "axes",
        "unit": "paused",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "yellow", "cause": "paused",
                   "action": "revive"},
        "neg": "灯对词错：现行给 L1「注意」⇒ 判成 partial 或 absent 必红",
    },
    {
        "id": "D01-21",
        "feed": "axes",
        "unit": "paused",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "yellow", "cause": "paused",
                   "action": "revive"},
        "neg": "trust=bounded 不改变 paused 的词 ⇒ 判 blind 必红",
    },
    {
        "id": "D01-22",
        "feed": "axes",
        "unit": "paused",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "yellow", "cause": "paused",
                   "action": "revive"},
        "neg": "drill 下 paused 判绿（「研发中」）⇒ 必须红",
    },
    {
        "id": "D01-23",
        "feed": "axes",
        "unit": "paused",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "yellow", "cause": "paused",
                   "action": "revive"},
        "neg": "同上 bounded 变体：判 absent 必红（没有损失证据不许指控失守）",
    },
    {
        "id": "D01-24",
        "feed": "axes",
        "unit": "draining",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "yellow", "cause": "draining",
                   "action": "topup"},
        "neg": "缺粮只挂徽标、主灯仍绿（现行行为）⇒ 必须红；这是灯错不是徽标错",
    },
    {
        "id": "D01-25",
        "feed": "axes",
        "unit": "draining",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "yellow", "cause": "draining",
                   "action": "topup"},
        "neg": "同上 bounded 变体：判 partial 必红（缺粮不是「没查到」）",
    },
    {
        "id": "D01-26",
        "feed": "axes",
        "unit": "draining",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "yellow", "cause": "draining",
                   "action": "topup"},
        "neg": "drill 下缺粮判绿＋徽标 ⇒ 必须红",
    },
    {
        "id": "D01-27",
        "feed": "axes",
        "unit": "draining",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "yellow", "cause": "draining",
                   "action": "topup"},
        "neg": "同上 bounded 变体：判 paused 必红（在岗缺粮 ≠ 不在岗）",
    },
    {
        "id": "D01-28",
        "feed": "axes",
        "unit": "partial",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "yellow", "cause": "partial",
                   "action": "check-item"},
        "neg": "灯对词错：现行给 L1「注意」(unknown) ⇒ 判成 blind 必红（看不清是红）",
    },
    {
        "id": "D01-29",
        "feed": "axes",
        "unit": "partial",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "yellow", "cause": "partial",
                   "action": "check-item"},
        "neg": "drill 下 partial 判绿 ⇒ 必须红（没查到不许当查过了）",
    },
    {
        "id": "D01-30",
        "feed": "axes",
        "unit": "ok",
        "overrides": None,
        "expect": {"mode": "armed", "lamp": "green", "cause": "ok",
                   "action": "none"},
        "neg": "把 ok 判成 partial 或 draining ⇒ 必须红（假黄会训练用户忽略黄灯）",
    },
    {
        "id": "D01-31",
        "feed": "axes",
        "unit": "ok",
        "overrides": None,
        "expect": {"mode": "drill", "lamp": "green", "cause": "ok",
                   "action": "none"},
        "neg": "drill/ok 的徽标是演练标，不许当缺粮徽标 ⇒ 徽标键判错必红",
    },
    # ------------------------------------------- 26 行新行：N5–N10（facts 形态）
    {
        "id": "N5-a",
        "feed": "facts",
        "unit": "N5",
        "overrides": {"armed": False},
        "expect": {"mode": "unarmed", "lamp": "grey", "cause": "unarmed",
                   "sentence_key": "unarmed.main"},
        "neg": "结构判据守来源：`facts.py` 直读 `load_state()[\"enabled\"]` 的调用点"
               "计数必须为 0（AST 数，不用 find）；直读 ⇒ green 假绿",
    },
    {
        "id": "N5-b",
        "feed": "facts",
        "unit": "N5",
        "overrides": {"armed": True},
        "expect": {"mode": "armed", "lamp": "green", "cause": "ok"},
        "neg": "链无 changed 记录时 `armed_state()` 返回 None ⇒ 落 unbounded/blind "
               "假红；把 None 当 False 判 unarmed 同样红",
    },
    {
        "id": "N6-a",
        "feed": "facts",
        "unit": "N6",
        "overrides": {"granary_level": "low", "granary_balance_hours": 100},
        "expect": {"lamp": "yellow", "cause": "draining",
                   "at_risk_has": ["granary_low"], "badge_has": ["缺粮"],
                   "sentence_key": "draining.granary"},
        "neg": "① balance=200 仍亮 ⇒ 红；② 阈值写死「7 天」切断 `LOW_THRESHOLD` "
               "派生 ⇒ 红（100÷24=4.2 天，4.2<7 才亮）",
    },
    {
        "id": "N6-b",
        "feed": "facts",
        "unit": "N6",
        "overrides": {"heartbeat_age": 1000.0},
        "expect": {"lamp": "yellow", "cause": "draining",
                   "at_risk_has": ["heartbeat_will_stall"],
                   "sentence_key": "draining.heartbeat"},
        "neg": "① age=600 就亮 ⇒ 红（阈值是 0.5×`_STALE_AFTER`=900）；"
               "② 阈值写死 900 切断派生 ⇒ 红",
    },
    {
        "id": "N6-c",
        "feed": "facts",
        "unit": "N6",
        "overrides": {"egress_free_bytes": 15728640},
        "expect": {"lamp": "yellow", "cause": "draining",
                   "at_risk_has": ["disk_write_full"],
                   "badge_has": ["磁盘"]},
        "neg": "① free=200MB 就亮 ⇒ 红（阈值 19.6MB＝7 天写入量）；"
               "② `capacity()` 返回 None 也亮 ⇒ 红（拿不到就说拿不到，None 当满＝猜）",
    },
    {
        "id": "N7-a",
        "feed": "facts",
        "unit": "N7",
        "overrides": {"partial_read": {"seen": 320, "total": 812,
                                       "why": "预算内未完成"}},
        "expect": {"lamp": "yellow", "cause": "partial",
                   "sentence_key": "partial.main",
                   "detail_has": "还有 492 处没看"},
        "neg": "截断分支静默跳过（truncated 而 trust 仍判 sound）⇒ 红",
    },
    {
        "id": "N7-b",
        "feed": "facts",
        "unit": "N7",
        "overrides": {"partial_read": {"seen": 40, "total": 55,
                                       "why": "宿主探测预算"}},
        "expect": {"lamp": "green", "cause": "ok", "registered_only": True},
        "neg": "非核心面截断也判 bounded ⇒ 红（BL-08 分层；「一律降级」会把黄灯"
               "变噪音，那是另一种失真）",
    },
    {
        "id": "N8-a",
        "feed": "facts",
        "unit": "N8",
        "overrides": {},
        "expect": {"lamp": "green", "cause": "ok", "badge_has": [],
                   "sentence_key": "ok.main"},
        "neg": "标准档挂「缺粮」徽标 ⇒ 红（D-10：条件为假必须消失，不许常驻）",
    },
    {
        "id": "N8-b",
        "feed": "facts",
        "unit": "N8",
        "overrides": {"granary_level": "low", "granary_balance_hours": 10},
        "expect": {"lamp": "yellow", "cause": "draining",
                   "badge_has": ["缺粮"],
                   "sentence_key": "draining.guard_mode",
                   "spend_today": 12},
        "neg": "spend 记 24 ⇒ 红（守备档半价；写死 24 每天多扣一倍粮，观察期数据"
               "整体失真）",
    },
    {
        "id": "N8-c",
        "feed": "facts",
        "unit": "N8",
        "overrides": {"granary_level": "low", "granary_balance_hours": -5,
                      "sentinel_alive": False},
        "expect": {"lamp": "yellow", "cause": "paused",
                   "sentence_key": "paused.granary_stop",
                   "forbid_text": "没有要管的东西"},
        "neg": "① 停摆用通用 paused 句（含「没有要管的东西」）⇒ 红（没付电费不是"
               "无事发生）；② 来路判据（余额<0）失效 ⇒ 红",
    },
    {
        "id": "N9-a",
        "feed": "facts",
        "unit": "N9",
        "overrides": {"gaps": [{"kind": "host_shield_breach",
                                "gap_state": "open"}],
                      "counts": {"action": 2, "info": 5}},
        "expect": {"lamp": "red", "cause": "breach",
                   "sentence_key": "breach.main",
                   "forbid_text": "都替你处理完了"},
        "neg": "把 info 桶句拼进主行 ⇒ 红（同屏互斥：主行只说「只有你能解决的」）",
    },
    {
        "id": "N9-b",
        "feed": "facts",
        "unit": "N9",
        # ★ #52：规格把 `period_line` 写进 overrides，但它是**渲染层期间行文本**，
        #   不是 facts 字段（facts 里没有「期间行」这个概念）⇒ 本模块移入 expect。
        #   若留在 overrides，`BASE ⊕ overrides` 会多出一个投影永远不读的键，
        #   而判据验「overrides 键 ⊆ BASE」会红 —— 规格自身的形态错位。
        "overrides": {"gaps": [{"kind": "host_shield_breach",
                                "gap_state": "open"}],
                      "counts": {"action": 2, "info": 5}},
        "expect": {"lamp": "red", "cause": "breach",
                   "period_line_text": "最近 24 小时挡下 5 次，都替你处理完成了。",
                   "period_line_allowed": True},
        "neg": "判据把期间行的 info 句也判互斥 ⇒ **判据自身假红**（这是负控的负控："
               "豁免①必须真的豁免）",
    },
    {
        "id": "N10-a",
        "feed": "facts",
        "unit": "N10",
        "overrides": {"chain_recon": "lost_suspect", "chain_write_lost": 3},
        "expect": {"lamp": "red", "cause": "blind", "recon_reports_diff": True},
        "neg": "差 ≤1 也判 lost ⇒ 红（N10：差 >1 才报，单拍抖动不算丢）",
    },
    {
        "id": "N10-b",
        "feed": "facts",
        "unit": "N10",
        "overrides": {"chain_recon": "lost_suspect"},
        "expect": {"lamp": "red", "cause": "blind", "recon_denominator": 138},
        "neg": "分母写死 144 ⇒ 在 DST 23 小时日夹具下必须红（23×600=138）",
    },
    {
        "id": "N10-c",
        "feed": "facts",
        "unit": "N10",
        "overrides": {"chain_recon": "unknown_window"},
        "expect": {"lamp": "green", "cause": "ok", "recon_registered_only": True},
        "neg": "保留窗外日期判 lost_suspect ⇒ 假红（窗外不可验，只登记不判定）",
    },
    # --------------------------------- N11（8 行，全成因；registry 形态）＋N12
    # ★★ N11 已按 #48 裁定更正：原规格的 N11-b 是「drill 成因行」，但 drill 不是
    #    成因而是模式层身份 ⇒ 该行改为 `partial`（原八行缺它、多一个非成因）。
    #    更正后八行与 `state_registry.STATES` 的八个 key 一一对应，顺序按规格原序。
    #    drill 的身份断言见文件末尾 `MODE_IDENTITY_CASES`（不在 57 行内）。
    {
        "id": "N11-a",
        "feed": "registry",
        "unit": "N11",
        "overrides": None,
        "expect": {"cause_key": "unarmed", "tense": "never"},
        "neg": "tense 删空或挪格 ⇒ 红（八行共一条负控：一行空即整表红）",
    },
    {
        "id": "N11-b",
        "feed": "registry",
        "unit": "N11",
        "overrides": None,
        "expect": {"cause_key": "partial", "tense": "now"},
        "neg": "partial 登记成 past 或留空 ⇒ 红（「有一项没查到」是此刻状态）",
    },
    {
        "id": "N11-c",
        "feed": "registry",
        "unit": "N11",
        "overrides": None,
        "expect": {"cause_key": "ok", "tense": "now"},
        "neg": "ok 登记成 past ⇒ 红（值守中是此刻，不是「曾经」）",
    },
    {
        "id": "N11-d",
        "feed": "registry",
        "unit": "N11",
        "overrides": None,
        "expect": {"cause_key": "paused", "tense": "past"},
        "neg": "paused 登记成 now ⇒ 红（刚停过；现在没在发生）",
    },
    {
        "id": "N11-e",
        "feed": "registry",
        "unit": "N11",
        "overrides": None,
        "expect": {"cause_key": "draining", "tense": "future"},
        "neg": "draining 登记成 now ⇒ 红（快没粮了是将来，不是已经没粮）",
    },
    {
        "id": "N11-f",
        "feed": "registry",
        "unit": "N11",
        "overrides": None,
        "expect": {"cause_key": "breach", "tense": "now"},
        "neg": "breach 登记成 past ⇒ 红（那正是 F1：用时间窗判过去；缺口此刻还在，"
               "事件是过去但成因取状态时态）",
    },
    {
        "id": "N11-g",
        "feed": "registry",
        "unit": "N11",
        "overrides": None,
        "expect": {"cause_key": "absent", "tense": "now"},
        "neg": "absent 登记成 past ⇒ 红（不在岗是此刻状态）",
    },
    {
        "id": "N11-h",
        "feed": "registry",
        "unit": "N11",
        "overrides": None,
        "expect": {"cause_key": "blind", "tense": "unknowable"},
        "neg": "留空或塞进「正在」⇒ 红（I5 折叠：看不清必须显式登记为不可知）",
    },
    {
        "id": "N12-a",
        "feed": "notice",
        "unit": "N12",
        "overrides": {"notice_state": "sent", "notice_age_min": 45,
                      "downgrade_ok": True},
        "expect": {"chain_kind": None, "tray_badge": True, "banner": True},
        "neg": "降级成功也记 `delivery_unknown` ⇒ 红（成功不是未知）",
    },
    {
        "id": "N12-b",
        "feed": "notice",
        "unit": "N12",
        "overrides": {"notice_state": "sent", "notice_age_min": 45,
                      "downgrade_ok": False},
        "expect": {"chain_kind": "delivery_unknown",
                   "chain_fields": ["ts", "kind", "downgrade", "minutes_overdue"]},
        "neg": "① 删链记录 ⇒ 红；② schema 未同批登记 ⇒ harness F-10 红"
               "（0.40.0／0.51.2 两次同型事故）",
    },
    {
        "id": "N12-c",
        "feed": "notice",
        "unit": "N12",
        "overrides": {"notice_state": "sent", "headless": True},
        "expect": {"chain_kind": None, "via": "file"},
        "neg": "无头场景判 unknown ⇒ 红（没有通道不是通道坏了）",
    },
]

#: drill 的模式层身份断言 —— **不在 57 行内**（#48 裁定：drill 不是成因）。
#: 放进 `CASES` 会让「一行＝一个成因」的不变量失真，故单列。
#: 判据用法：`state_registry.MODE_IDENTITY["drill"]` 必须满足本表两条。
MODE_IDENTITY_CASES = [
    {
        "id": "MODE-drill",
        "key": "drill",
        "expect": {"tense": "never", "is_cause": False},
        "neg": "把 drill 写进 `STATES`（当成因）⇒ 红；`legacy_of` 里 dev 仍须指向它"
               "（drill 是旧键 dev 的语义承载者，不是成因）",
    },
]

# 57 行 = 31（D01-01..D01-31）＋ 26（N5-a..N12-c）。此注释是给人看的，
# 真值由 `len(CASES)` 判据复核 —— 两个数不一致即红（不心算，纪律 7）。
