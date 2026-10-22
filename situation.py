#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""situation —— 态势投影（F2 冻结）：灯 / 成因 / 句子 / 徽标 / 期间行。

## 职责一句话

把 `facts`（F1 冻结）投影成**用户看得见的那一句话与那一盏灯**。
本模块**只做投影**：不采集、不读文件、不看时钟。

## 三条铁律（F2 原文，逐条可查）

1. **纯函数**：同输入两次投影必须 `diff=0`（Q8）。时间由调用方传（`scope["window"]`），
   读数由 `facts.py` 采 —— 本模块一旦 `time.time()` 或 `open()`，这条立刻失效。
2. **求值顺序不许重排**：灯是 灰 → 红(harm) → 红(trust=unbounded) → 黄(duty) → 绿。
   换一下顺序，`未装配` 就会被「有后果」抢先判红（F3 假绿的反面：假红）。
3. **句子从 §4 逐字取**：全部句子集中在 `SENTENCES`，**不许临场写**。
   宽度由 `output/_p_sentence_width.py` 按 T4-07 复算；改句要连宽度一起改。

## 本模块与 facts.py 的分界

    facts.collect()   → 事实（30 字段）
    facts.axes()      → 四轴（A3）
    situation.lamp()  → 灯（A4）        ← 本模块从这里开始
    situation.cause() → 成因（八选一 ＋ 并存成因）
    situation.sentence() → 显示句 ＋ 动作句

## 已登记的未冻结之处（#57，详见冻结件 §11.8）

    (c) §4.2 的主行规则表**漏了 `paused`** —— 不在岗且无账时会落到 `ok` 句
        （「今天没什么要拦的」），N8-c 的 `forbid_text` 正是抓这个。
    (e) 数字位不可得时的渲染形态（`breach` 的 D 位、`absent` 的 N 位）未冻结。
    (f) 期间行的「混合」形态需要比 `counts{action,info}` 更细的分桶，P2。
"""

import facts as _facts

__all__ = [
    "SENTENCES", "ACTION_SENTENCE", "DEFAULT_SCOPE",
    "lamp", "cause", "sentence", "sentence_key", "badges", "detail",
    "period_line", "spend_today", "recon_report",
    "presence", "period_presence",
]

#: 默认 scope（F2 冻结形状）。`window` 的第二位是窗口起点（ISO8601 或 None）。
DEFAULT_SCOPE = {"device": None, "host": None, "window": ("now", None)}

#: 动作句（§4.1 最后一列，逐字）。挂在**成因**上，不挂在灯上。
ACTION_SENTENCE = {
    "unarmed": "去开启",
    "drill": "不用动",
    "ok": "不用动",
    "paused": "重新拉起",
    "draining": "补充口粮",
    "breach": "按清单逐项修",
    "absent": "先拉起，再看清单",
    "blind": "核对或重装",
    "partial": "去查没查到的那几项",
}

#: 同一成因下**按来路改动作**的两处（#57h）。理由：`draining` 的动作句是「补充口粮」，
#: 但心跳将断与磁盘将满**补粮都不解决问题**——照搬会把用户引到错误的动作上，
#: 而「动作错」比「灯错」更难发现（用户照做了、没用，下次就不信了）。
#: 心跳：§4.3 的 tooltip 原文「再断会自动重拉，不用你动手。」
#: 磁盘：§4.3 只给了徽标句、没给动作 ⇒ 取「清理账本」（与 `BADGE_ACTION["disk"]` 同义）。
ACTION_BY_KEY = {
    "draining.heartbeat": "不用动",
    "draining.disk": "清理账本",
}

#: 句子表 —— **唯一真源**，逐字取自冻结件 §4.1／§4.3。
#: `{N}`/`{M}`/`{D}` 是数字位，填充值一律来自 `facts` 字段（句子不许现算）。
SENTENCES = {
    # ---------------------------------------------------- §4.1 八成因显示句
    "unarmed.main": "还没开启，现在没有任何东西在替你看门。",
    "drill.main": "正在用还没发布的版本守着，能拦的照拦。",
    "ok.main": "今天没什么要拦的。它在盯着。",
    "paused.main": "监理暂停了一会儿，这会儿没有要管的东西。",
    "paused.granary_stop": "口粮用完了，这段时间没在守。",
    "draining.main": "粮还够 {N} 天，用完监理会停。",
    "draining.granary": "粮还够 {N} 天，用完监理会停。",
    "draining.heartbeat": "监理 {N} 分钟没动静了（平时 10 分钟一次）。",
    "draining.disk": "账本快写不下了，写不下就不能记账。",
    "draining.guard_mode": "粮还够 {N} 天，用完监理会停。",
    "breach.main": "有 {N} 处没修，最早一处是 {D} 天前。",
    "absent.main": "监理不在岗。这段时间有 {N} 件没被挡。",
    "blind.main": "我证明不了自己在守。按最坏算，先核对一次。",
    "partial.main": "有 {N} 项没查到，先按有问题算。",
    # ---------------------------------------------------- §4.3 其余新句
    "partial.detail": ("这次只看了 {N} 处，还有 {M} 处没看——"
                       "没看的部分当空白读，不要当成「没问题」。"),
    "draining.guard_mode.disclosure": "现在只看基础目录，钩子停了。",
    "badge.granary": "粮还够 {N} 天，用完监理会停。",
    "badge.heartbeat": "监理 {N} 分钟没动静了（平时 10 分钟一次）。",
    "badge.heartbeat.tooltip": "再断会自动重拉，不用你动手。",
    "badge.disk": "账本快写不下了，写不下就不能记账。",
    "account.action": "有 {N} 件事只有你能办。",
    "account.info": "最近 24 小时挡下 {N} 次，都替你处理完成了。",
    # ★ #58d：**待创始人核签的新句**（§4.3 没有覆盖「不可对账段」）。
    #   睡眠证据拿不到 ⇒ 显式降级为「算不清」，而不是替机器断言「它睡了」或「它没守」。
    "period.unknown_window": "有 {N} 分钟没留下记录，那段时间算不清。",
    #: D-05 §6.2 的期间行原文。本期**不可达**（拿不到睡眠证据），补取数落地后启用。
    "period.asleep": "它不在（机器睡着了）。",
}

#: 徽标的短词（D-10 登记表）。★ 与长句分开：短词上角标，长句进 tooltip／主行。
BADGE_WORD = {"dev": "研发中", "granary": "缺粮", "disk": "磁盘"}

#: 徽标动作（D-10 规则：每枚必须带动作，否则就是装饰）。
BADGE_ACTION = {"dev": "none", "granary": "topup", "disk": "clean-ledger"}

#: 成因的优先级（F2：`others` 按动作优先级排）。
CAUSE_PRIORITY = ("absent", "breach", "blind", "paused", "draining", "ok")


def _scope(scope):
    """scope 缺省值。**只补形状，不补语义**（`device`/`host` 为 None 就是「不切」）。"""
    if scope is None:
        return dict(DEFAULT_SCOPE)
    out = dict(DEFAULT_SCOPE)
    out.update(scope)
    return out


def _num(v):
    """数字或 None（bool 先排掉，同 `facts._num`）。"""
    if isinstance(v, bool):
        return None
    return float(v) if isinstance(v, (int, float)) else None


def _hours_per_day():
    """一天多少小时 —— 取自 `granary.HOURS_PER_DAY`（异质单位特冻 G4：不许当 24 写死）。"""
    try:
        from granary import HOURS_PER_DAY
        return float(HOURS_PER_DAY)
    except Exception:                                        # noqa: BLE001
        return None


def _spend_tiers():
    try:
        from granary import SPEND_TIERS, DAILY_SPEND_DEFAULT
        return SPEND_TIERS, DAILY_SPEND_DEFAULT
    except Exception:                                        # noqa: BLE001
        return (), None


def _heartbeat_seconds():
    try:
        from host_shield import HEARTBEAT_SECONDS
        return float(HEARTBEAT_SECONDS)
    except Exception:                                        # noqa: BLE001
        return None


# ───────────────────────────── 一、灯与成因 ─────────────────────────────
def lamp(facts, scope=None):
    """灯 —— 四值小写英文（F2 唯一枚举）。**五条规则的先后就是优先级。**

      1. 未装配        ⇒ 灰（灯不供电：没装配就没有担保可给）
      2. 有后果／未知  ⇒ 红（后果说不清时按最坏算 —— fail-closed 只在这里）
      3. 无界无知      ⇒ 红（核心判定受影响）
      4. 值勤受损或有界无知 ⇒ 黄（**无损失**时才允许黄）
      5. 其余          ⇒ 绿
    """
    a = _facts.axes(facts)
    if a["mode"] == "unarmed":
        return "grey"
    if a["harm"] in ("some", "unknown"):
        return "red"
    if a["trust"] == "unbounded":
        return "red"
    if a["trust"] == "bounded" or a["duty"] in ("at-risk", "off"):
        return "yellow"
    return "green"


def _candidates(facts):
    """此刻**同时成立**的成因（可能有多个）—— `cause()` 的原料。"""
    a = _facts.axes(facts)
    mode, duty, trust, harm = a["mode"], a["duty"], a["trust"], a["harm"]
    out = []
    if mode == "unarmed":
        return ["unarmed"]
    if harm == "some":
        out.append("absent" if duty == "off" else "breach")
    if trust == "unbounded" or harm == "unknown":
        out.append("blind")
    if trust == "bounded":
        out.append("partial")
    if duty == "off":
        out.append("paused")
    elif duty == "at-risk":
        out.append("draining")
    if not out:
        out.append("ok")
    return out


def cause(facts, scope=None):
    """成因 —— 主成因 ＋ 并存成因（F2 形状：`{"key", "others"}`）。

    主成因的选法与灯一致：**先定灯，再在灯内按动作紧急度选**。
    `others` 按动作优先级排（`absent > breach > blind > paused/draining > ok`）。
    """
    cands = _candidates(facts)
    lamp_v = lamp(facts, scope)
    if lamp_v == "grey":
        main = "unarmed"
    elif lamp_v == "red":
        # 顺序即优先级：没人守且有损失 > 有人守但有缺口 > 其余（不可信）
        if "absent" in cands:
            main = "absent"
        elif "breach" in cands:
            main = "breach"
        else:
            main = "blind"
    elif lamp_v == "yellow":
        # 顺序即优先级：没人在守 > 即将失去 > 只是某一项没查到
        for k in ("paused", "draining", "partial"):
            if k in cands:
                main = k
                break
        else:
            main = "partial"
    else:
        main = "ok"
    others = [c for c in CAUSE_PRIORITY if c in cands and c != main]
    return {"key": main, "others": others}


# ───────────────────────────── 二、句子 ─────────────────────────────
def _fmt_days(hours):
    """小时 → 「N 天」（1 位小数）。★ 除的是 `HOURS_PER_DAY`，不是 24（G4 特冻）。"""
    h, per = _num(hours), _hours_per_day()
    if h is None or not per:
        return None
    return "%.1f" % (h / per)


def _fmt_minutes(seconds):
    s = _num(seconds)
    return None if s is None else "%.1f" % (s / 60.0)


def _is_stop_by_granary(facts):
    """停摆来路（§5.2 第三条连带冻结）：`granary_level != "off" ∧ balance < 0`。

    ★ `level == "off"` 是「粮库没启用」，不是「粮用完了」——两者都会让余额为 0，
      但只有后者能说「口粮用完了」。分不开就会出现「没付电费被说成无事发生」。
    """
    b = _num(facts.get("granary_balance_hours"))
    return facts.get("granary_level") != "off" and b is not None and b < 0


def _is_guard_mode(facts):
    """守备档：`0 ≤ 余额 < 一天`（`granary.SPEND_TIERS[0]` 的条件，数字不写死）。"""
    b, per = _num(facts.get("granary_balance_hours")), _hours_per_day()
    return b is not None and per is not None and 0 <= b < per


def _harmful_gaps(facts):
    """算作 harm 的缺口记录（族界＋状态两条腿，与 `facts.axes` 同一口径）。"""
    gaps, levels = facts.get("gaps"), _facts._kind_levels()
    if not isinstance(gaps, list) or levels is None:
        return []
    return [g for g in gaps
            if isinstance(g, dict)
            and g.get("gap_state") in ("open", "acked")
            and levels.get(g.get("kind")) == _facts.GAP_LEVEL]


def _at_risk(facts):
    """预告源的并集（派生 ＋ 采集侧预置）。顺序按 `AT_RISK_SOURCES`。"""
    got = set(_facts.at_risk_sources(facts))
    got |= set(facts.get("at_risk") or [])
    return [k for k in _facts.AT_RISK_SOURCES if k in got]


def _counts(facts):
    c = facts.get("counts")
    if not isinstance(c, dict):
        return 0, 0
    return int(_num(c.get("action")) or 0), int(_num(c.get("info")) or 0)


def sentence_key(cause_key, facts, scope=None):
    """这一格该用哪一句（句子表的键）。**渲染层与判据都只认这个键。**

    ★ §4.2 的主行构成规则（顺序即优先级）：
        未启用 → 此刻有缺口 → **不在岗（#57c 补）** → 有 action 账 → 有 info 账
        → 无账 ∧ drill → 其余
      `paused` 那一行是 #57c 补的：原表漏了它，于是「不在岗且无账」会落到 `ok` 句
      （「今天没什么要拦的」）—— N8-c 的 `forbid_text` 抓的正是这个。
    """
    if cause_key == "unarmed":
        return "unarmed.main"
    if cause_key in ("breach", "absent", "blind", "partial"):
        return "%s.main" % cause_key
    if cause_key == "paused":
        return "paused.granary_stop" if _is_stop_by_granary(facts) else "paused.main"
    if cause_key == "draining":
        srcs = _at_risk(facts)
        if "granary_low" in srcs:
            return "draining.guard_mode" if _is_guard_mode(facts) else "draining.granary"
        if "heartbeat_will_stall" in srcs:
            return "draining.heartbeat"
        if "disk_write_full" in srcs:
            return "draining.disk"
        return "draining.main"
    # cause_key == "ok"
    action_n, info_n = _counts(facts)
    if action_n > 0:
        return "account.action"
    if info_n > 0:
        return "account.info"
    if facts.get("is_dev") is True:
        return "drill.main"
    return "ok.main"


def _fill(key, facts, scope=None):
    """把数字位填进模板。**填不出的位 ⇒ 该分句整段省略**（不写 `None`、不猜数字）。"""
    tpl = SENTENCES[key]
    if key in ("draining.main", "draining.granary", "draining.guard_mode",
               "badge.granary"):
        n = _fmt_days(facts.get("granary_balance_hours"))
        return tpl.replace("{N}", n) if n is not None else None
    if key in ("draining.heartbeat", "badge.heartbeat"):
        n = _fmt_minutes(facts.get("heartbeat_age"))
        return tpl.replace("{N}", n) if n is not None else None
    if key == "breach.main":
        n = len(_harmful_gaps(facts))
        d = _days_since_earliest(facts, scope)
        if d is None:
            # ★ #57e：D 位不可得 ⇒ **只留前半句**（逐字取自同一句，不另造句）。
            #   绝不能把 `{D}` 原样漏到屏上 —— 那比说错话更糟：用户会以为这是暗号。
            return tpl.split("，")[0].replace("{N}", str(n)) + "。"
        return tpl.replace("{N}", str(n)).replace("{D}", d)
    if key == "absent.main":
        cons = facts.get("outage_consequences")
        n = len(cons) if isinstance(cons, list) else None
        return tpl.replace("{N}", str(n)) if n is not None else None
    if key == "partial.main":
        return tpl.replace("{N}", "1")
    if key == "partial.detail":
        pr = facts.get("partial_read")
        if not isinstance(pr, dict):
            return None
        seen, total = _num(pr.get("seen")), _num(pr.get("total"))
        if seen is None or total is None:
            return None
        return tpl.replace("{N}", "%d" % seen).replace("{M}", "%d" % (total - seen))
    if key in ("account.action", "account.info"):
        action_n, info_n = _counts(facts)
        return tpl.replace("{N}", str(action_n if key == "account.action" else info_n))
    return tpl


def _days_since_earliest(facts, scope=None):
    """最早一条缺口的「几天前」。**没有 `opened_at`／没有参照时刻就返回 None**（不猜 0）。

    ★ 参照时刻**由调用方给**（`scope["window"][1]`）—— 投影层不许自己看时钟（F2 铁律）。
      拿不到参照时刻 ⇒ 返回 None，句子降级为省略该分句（#57e），而不是拿「今天」硬算。
    """
    stamps = [g.get("opened_at") for g in _harmful_gaps(facts)
              if isinstance(g.get("opened_at"), str)]
    anchor = (_scope(scope).get("window") or (None, None))[1]
    if not stamps or not isinstance(anchor, str):
        return None
    try:
        from datetime import datetime
        earliest = min(datetime.fromisoformat(s) for s in stamps)
        now = datetime.fromisoformat(anchor)
        return str(max(0, (now - earliest).days))
    except Exception:                                        # noqa: BLE001
        return None


def sentence(cause_key, facts, scope=None):
    """显示句 ＋ 动作句（F2 冻结的两键）。句子**逐字取**自 `SENTENCES`。"""
    key = sentence_key(cause_key, facts, scope)
    main = _fill(key, facts, scope)
    if main is None:
        # 数字位填不出 ⇒ 退回该成因的主句（仍不写 None、不编数字）
        main = (_fill("%s.main" % cause_key, facts, scope)
                if cause_key != "ok" else SENTENCES["ok.main"])
    return {"main": main or "",
            "action": ACTION_BY_KEY.get(key) or ACTION_SENTENCE.get(cause_key, "")}


def detail(facts, scope=None):
    """体检页的明细句（E3b 截断原文）。没有截断 ⇒ 空串。"""
    return _fill("partial.detail", facts, scope) or ""


# ───────────────────────────── 三、徽标与期间行 ─────────────────────────────
def badges(facts, scope=None):
    """徽标（F2 形状：`{"key","text","action"}`）。**每枚必须带动作**，否则是装饰。

    `text` 是**短词**（上角标），长句在 `SENTENCES["badge.*"]` 里给 tooltip／主行用
    —— 两者分开是 D-10 与 §4.3 的合成：短词管「一眼看出」，长句管「说清后果」。
    """
    out = []
    if facts.get("is_dev") is True:
        out.append({"key": "dev", "text": BADGE_WORD["dev"],
                    "action": BADGE_ACTION["dev"]})
    if facts.get("granary_level") == "low" or facts.get("credits_low_open") is True:
        out.append({"key": "granary", "text": BADGE_WORD["granary"],
                    "action": BADGE_ACTION["granary"]})
    if "disk_write_full" in _at_risk(facts):
        out.append({"key": "disk", "text": BADGE_WORD["disk"],
                    "action": BADGE_ACTION["disk"]})
    return out


def period_line(facts, scope=None):
    """期间行（收件箱里那句「最近 24 小时…」）。

    ★ N9-b 的豁免①：info 桶的句子**只许**出现在这里，不许拼进主行。
      「挡下 N 次都处理完了」与「有 N 处没修」同屏出现，等于一边说没事一边说有事。
    ★ 只承载 **info** 桶：`action` 桶的去处是**主行**（§4.2 第 3 条），
      两处都放会让「主行 ⊄ 期间行」这条互斥检查失去意义（自己跟自己撞）。
    """
    _action_n, info_n = _counts(facts)
    if info_n > 0:
        return {"kind": "info",
                "text": SENTENCES["account.info"].replace("{N}", str(info_n))}
    return {"kind": "none", "text": ""}


# ───────────────────────── 四、在场证明（A5：presence） ─────────────────────────
def _iso(dt):
    return dt.isoformat(timespec="seconds")


def _parse_stamps(raw):
    """`heartbeat_slices` → `(排好序的 datetime 列表, 解析失败的个数)`。

    ★ #58c：F1 只写「list[Slice]」，**没定义 Slice 形状**。裁定＝**时间戳列表**
      （每条心跳一个 ISO 时刻）：切片是**相对窗口**的概念，属投影；事实层只该有
      时间点。这样不必为 `Slice` 再造一层子 schema，也不会把「窗口多长」这个
      投影参数写进事实。
    ★ 解析不了的元素**跳过并计数**（不静默丢），调用方据此决定要不要降级。
    """
    from datetime import datetime
    out, dropped = [], 0
    for x in (raw or []):
        try:
            out.append(datetime.fromisoformat(str(x)))
        except (TypeError, ValueError):
            dropped += 1
    out.sort()
    return out, dropped


def _hole(start, k0, k1, hb):
    """空档三元组（F2 形状）：起／止／分钟数。分钟数 = 缺片数 × 片长。"""
    from datetime import timedelta
    return (_iso(start + timedelta(seconds=k0 * hb)),
            _iso(start + timedelta(seconds=(k1 + 1) * hb)),
            int((k1 - k0 + 1) * hb // 60))


def presence(facts, days=1):
    """在场证明（F2 ＋ D-07）。**纯函数**：只读 `facts["heartbeat_slices"]`，不看时钟。

    返回五键：

      `slices`        本窗口应有的片数（`days × 86400 ÷ HEARTBEAT_SECONDS`；1 天＝144）
      `with_evidence` 有证据的片数（**写 `141/144`，不写百分比** —— F40）
      `holes`         全部空档 `[(起, 止, 分钟)]`，按时间升序
      `asleep`        有**睡眠证据**的空档 —— **本期恒为空**（见下）
      `unknown`       已判缺席（≥ `_STALE_AFTER`）却**没有睡眠证据**的空档

    ★★ 睡眠证据（D-05 §6.1）当前**拿不到**：`_sentinel_uptime()` 只用墙钟，
      「uptime 增量 < 墙钟增量」这条判据算不出来 ⇒ **机器睡了 8 小时与监理死了 8 小时
      在现有数据上完全一样**。故（创始人 2026-10-22 16:2x 拍板「显式降级」）：

        · `asleep` 恒 `[]` —— 不替机器断言「它睡了」；
        · 长空档进 `unknown` —— 判缺席，但**原因算不清**；
        · **不判 `absent`** —— 没证据就指控「失守」是假指控。D-05 §6.2 的
          「空档 ∧ 无睡眠证据 ⇒ 照判」说的是「**查过了**没有睡眠」，不是「**查不了**」；
          这两件事在 F1 三态里是 `False` 与 `None` 的区别。

      补取数的施工单已写成待签发件（设计件 §11.9）。

    ★ 空档阈值取 `_STALE_AFTER`（=3 片×600s=1800s，D-07 规则 2 原文「≥3 片 ⇒ 判缺席」），
      **不写死 3 或 1800**。
    """
    hb = _heartbeat_seconds()
    if not hb:
        return {"slices": 0, "with_evidence": 0, "holes": [],
                "asleep": [], "unknown": []}
    n = int(days * 86400 // hb)
    stamps, _dropped = _parse_stamps(facts.get("heartbeat_slices"))

    if not stamps:
        # 一条证据都没有 ⇒ 整段是一个空档。★ 起止给 None：**没有锚点就没有时间轴**，
        #   编一个「今天 0 点」出来就是拿墙钟假装知道。
        whole = (None, None, int(n * hb // 60))
        return {"slices": n, "with_evidence": 0, "holes": [whole],
                "asleep": [], "unknown": [whole]}

    from datetime import timedelta
    # 窗口＝(end − n×hb, end]，`end` 取「最后一条证据所在片的下一个边界」。
    #   ★ 不能直接把 `end` 设成 `stamps[-1]`：那样最后一个点恰好落在右边界上，
    #     最左一片会凭空空出来（一条 1 片假空档），是「自己造出来的缺席」。
    end = stamps[-1] + timedelta(seconds=hb)
    start = end - timedelta(seconds=n * hb)
    used = set()
    for ts in stamps:
        k = int((ts - start).total_seconds() // hb)
        if 0 <= k <= n:
            used.add(min(k, n - 1))

    holes, run = [], None
    for k in range(n):
        if k in used:
            if run is not None:
                holes.append(_hole(start, run, k - 1, hb))
                run = None
        elif run is None:
            run = k
    if run is not None:
        holes.append(_hole(start, run, n - 1, hb))

    floor = _facts._const("stale")
    unknown = [h for h in holes if floor is not None and h[2] * 60 >= floor]
    return {"slices": n, "with_evidence": len(used), "holes": holes,
            "asleep": [], "unknown": unknown}


def period_presence(pres):
    """把空档投影成**期间行的一句话**（D-05 §6.2 的呈现面）。

    · 有睡眠证据 ⇒ 「它不在（机器睡着了）」—— 本期不可达（无证据源），
      但句子先摆在这里：补取数落地时只改 `presence`，呈现层一行不用动。
    · 只有 `unknown` ⇒ `period.unknown_window`（#58d：**待核签的新句**）
    · 都没有 ⇒ 空串（**不留白也不编「一切正常」**）
    """
    if pres.get("asleep"):
        return SENTENCES["period.asleep"].replace(
            "{N}", str(sum(x[2] for x in pres["asleep"])))
    if pres.get("unknown"):
        return SENTENCES["period.unknown_window"].replace(
            "{N}", str(sum(x[2] for x in pres["unknown"])))
    return ""


def spend_today(facts):
    """当日消耗（小时）。守备档半价 —— **由档位派生，不许写死 24**。

    守备档 ⇔ `0 ≤ 余额 < 一天`（`granary.SPEND_TIERS[0]` 的条件）。
    N8-b 负控：写死 24 ⇒ 守备档每天多扣一倍粮，观察期数据整体失真。
    """
    tiers, default = _spend_tiers()
    if _is_guard_mode(facts) and tiers:
        return tiers[0][1]
    return default


def recon_report(facts, hours=24):
    """对账报告（N10）。**分母由小时数与心跳间隔派生，不写死 144。**

    · `reports_diff`   —— 差 > 1 才报（单拍抖动不算丢）
    · `denominator`    —— `hours × (3600 ÷ HEARTBEAT_SECONDS)`；DST 23 小时日 ⇒ 138
    · `registered_only` —— `unknown_window`：窗外不可验，**只登记不判定**
    """
    hb = _heartbeat_seconds()
    denom = int(hours * (3600 // hb)) if hb else None
    state = facts.get("chain_recon")
    lost = _num(facts.get("chain_write_lost")) or 0.0
    return {
        "reports_diff": bool(state == "lost_suspect" and lost > 1),
        "denominator": denom,
        "registered_only": state == "unknown_window",
    }
