# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""粮 · 哨兵的口粮（**纯本地，零外传**）。

★★ 三个"账本"必须分清 —— 混了会污染两边口径（本仓已在 `ledger.py` 头部警告过一次）::

    antinel credits …… 追踪**宿主 AI 工具烧了多少积分**（只读，画像驱动）
    ledger ………………… 值守台本机**可核对事件的按日摘要**（拦截/注意/缺口/处理状态）
    granary（本模块）… 本机哨兵的**口粮**：余额、发放、消耗、流水

  本模块只管第三件。它**不**记录宿主工具烧了多少，也**不**统计拦了几件事。

★ 粮是什么：**哨兵的口粮 ＝ 续航**。它回答「**我的领地还能不能继续站着**」，
  不是「我花了多少钱」。口径全文见《Antinel·粮（积分）方案 v1.2（2026-10-09）》。

★ 单位（0.38.0 定案）：**1 粮 ＝ 哨兵在岗 1 小时**（标准档 24 粮/天）。
  · **为什么不用"分钟"**（创始人曾提议「1 分钟 1 个点」）：单位只改**记法**，
    不改任何比值 —— 「今日消耗 ÷ 余额」恒等于「1 ÷ 续航天数」，**与单位无关**。
    把 24 改成 1440，只是把同一个比值写成更大的数字，却让余额涨到 6 位数、
    让全表数字变噪音。⇒ 调单位**不能**让人更"看得见消耗"。
  · "看得见"由**另外两件事**承担：① 秒级**在岗计时**（正向累积，见页面）；
    ② 余额一律显示成「**还够 N 天**」而不是一个裸大数。
  · 顺带：24/天与产品既有的「最近 24 小时」窗口**同构**，用户不必再学一个刻度。

★ 铁律（**现阶段**）：`不可转让 · 不可兑换 · 不承诺收益 · 现阶段不出售`
  · **不可转让**：本模块**没有**任何"把粮转给别人/别的机器"的入口。
  · **不可兑换**：本模块**没有**任何"粮换钱／换物／换链上资产"的入口。
  · **现阶段不出售**：现在不提供购买；开放注册后开放充值渠道 —— 见下面 `RECHARGE`
    （**只声明、未实现**）。★ 撞两条铁律的只有「粮→钱（兑换）」与「粮→粮（转让）」；
    「钱→粮」是单向充值，不产生货币性。
  · **不承诺收益**：余额是**本机计量**，不对任何未来的兑换/分红作承诺。
  · 判据：`ci/guard_granary.py` 三条，各配负控。**任一条被削弱即须回撤邀请返粮**。

★ 充值（创始人 2026-10-09 拍板）：**现在不卖粮；开放注册后开放充值渠道**。
  ⇒ 本模块只放一个**声明占位** `RECHARGE`，**不**实现任何支付路径。
    将来开放时，充值通道是**唯一**的付费入口，且**不**改变上面"不可转让、不可兑换"两条。

★ 落盘：`<hub>/granary/ledger.jsonl`，一行一笔、**追加写**（不改旧行）。
  余额＝Σ发放 − Σ消耗，**由流水算出** —— 不存"当前余额"这种会被改坏的单值
  （单值一旦被写坏，页面会理直气壮地显示一个假数）。

★ 机器键：记账带上本机显示码（`machine_id.machine_code`）**只作标注**，
  **只读**（`machine.json` 不存在就留空）—— 读一次余额不该顺带写盘。
"""
from __future__ import annotations

import json
import os
from datetime import date, datetime

#: 环境变量：账本根目录（与 `ledger.py` 同一个）。判据靠它把流水写到临时目录。
_HUB_ENV = "ANTINEL_HUB_DIR"

#: 流水条目分类。**只有两种**，金额恒为正，正负由分类决定 ——
#: 不写带符号的数（同一笔"减"被写两次就成"加"，是本仓已见过的形状）。
KIND_GRANT = "grant"
KIND_SPEND = "spend"

#: ★ 单位：1 粮 ＝ 哨兵在岗 **1 小时**。改它＝改整个刻度，**只允许在这里改一处**
#:   （全表数字都由下面的常量派生，不散写字面量）。
HOURS_PER_DAY = 24

#: 标准档消耗（粮/天）＝ 24（＝一天 24 小时在岗）。见《方案》§四.1：
#: 守备档 0.5 → **12/天**；勤务档 ×台数。
DAILY_SPEND_DEFAULT = HOURS_PER_DAY

#: 低于这个余额 ⇒ **Ls 缺粮**亮灯。取"7 天标准档口粮"＝ 168：
#: 还够站一周 ⇒ 还来得及补，不至于今天断明天灭（口径见《方案》§四.3）。
LOW_THRESHOLD = 7 * HOURS_PER_DAY

#: 入驻口粮（一次性）＝ **180 天**口粮。
#:   ★ 2026-10-09 创始人二次拍板「**粮草要多给，多多给**」⇒ 由 90 天提到 180 天。
#:     早期先用"给足"换覆盖率的理由：粮无变现出口，多给只增覆盖、不增成本。
SEED_GRANT = 180 * HOURS_PER_DAY

#: ★ 充值通道（Phase 2，**尚未实现**）。这里只是**声明占位**：
#:   `ci/guard_granary.py` 的 G1 据此区分"我们声明的未来通道"与
#:   "某个版本里悄悄长出来的售卖路径" —— 前者放行，后者报红。
RECHARGE = {
    "enabled": False,
    "opens_with": "账号注册（Phase 2）",
    "note": "开放注册后提供充值渠道；充值不改变「不可转让、不可兑换」两条铁律。",
}

#: 获得规则表（**数据**，不是散在代码里的字面量）。
#: 每一行＝`(机会, 发粮, 频次)`，**一律写成"几天口粮"×`HOURS_PER_DAY`**。
#: ★ 与《方案》v1.2 §A.4 逐条对应。
#: ★ 2026-10-09 二次拍板「**粮草要多给，多多给**」⇒ 全表上调（见各行括号里的天数）。
RULES_GRANT = {
    "入门": [
        ("入驻口粮", SEED_GRANT, "一次性，＝180 天口粮"),
        ("首扫礼", 10 * HOURS_PER_DAY, "一次性，＝10 天"),
        ("首拦礼", 10 * HOURS_PER_DAY, "一次性"),
        ("首报告礼", 10 * HOURS_PER_DAY, "一次性"),
        ("接钩子礼", 10 * HOURS_PER_DAY, "一次性"),
    ],
    "在岗": [
        ("每日在岗", HOURS_PER_DAY, "自动，零点击，＝1 天"),
        ("连续在岗 7 天", 14 * HOURS_PER_DAY, "每满 7 天"),
        ("每月保底", 60 * HOURS_PER_DAY, "每月 1 号自动，永久有效"),
    ],
    "贡献": [
        ("有效缺陷报告", 20 * HOURS_PER_DAY, "每个，＝20 天"),
        ("公开案例", 60 * HOURS_PER_DAY, "每篇"),
        ("教程／长文", 120 * HOURS_PER_DAY, "每篇"),
        ("规则／判据入库", 120 * HOURS_PER_DAY, "每次，另有长期分成"),
        ("翻译／本地化", 60 * HOURS_PER_DAY, "每份"),
    ],
    "传播": [
        # ★★ 创始人 2026-10-09 三次表态：①「注册即发、双方各得、上不封顶」
        #   ②「不要日/月上限，早期不要限制用户」③「**拉人还是很重要的**，
        #   WorkBuddy 也是这样的，粮草要多给，多多给」（并附 WorkBuddy 邀请卡截图：
        #   「好友加入，积分上涨 —— 邀请一位好友可获得 100 积分」）。
        #   ⇒ 本条是**覆盖率的主动力**，无上限。
        #   代价与风险（与 §B 充值叠加）见《方案》v1.3 §D 敞口 3/4。
        # ★★ 创始人第四次表态（2026-10-09 10:44）：「初期阶段拉好友给 100 是不是太少了……
        #   人家 WorkBuddy 是大厂，少给可以，我们不行，我认为得 1000，至少 10 倍」。
        #   ⇒ 邀请额度由 100 天 → **1000 天**（＝10× WorkBuddy 的「100」）；仍无上限。
        ("邀请好友", 1000 * HOURS_PER_DAY, "注册即发，双方各得，无上限，＝1000 天"),
    ],
}

#: 消耗档位（**数据**）。与《方案》§四.1 对应。★ 数字由 `HOURS_PER_DAY` 派生。
SPEND_TIERS = (
    ("守备档", HOURS_PER_DAY // 2, "1 台机、基础目录"),
    ("标准档", DAILY_SPEND_DEFAULT, "1 台机、全目录 ＋ 钩子（默认）"),
    ("勤务档", "%d/天 × 台数" % HOURS_PER_DAY, "多台机"),
)


def hub_dir():
    """账本根目录。与 `ledger.py` **同一个**（先问它，问不到再自己读环境变量）。"""
    try:
        import ledger
        return ledger.hub_dir()
    except Exception:                                  # noqa: BLE001
        return os.path.expanduser(os.environ.get(_HUB_ENV) or "~/.antinel")


def granary_dir(root=None):
    return os.path.join(root or hub_dir(), "granary")


def ledger_path(root=None):
    return os.path.join(granary_dir(root), "ledger.jsonl")


# ------------------------------------------------------------ 机器键 ----
def machine_code(root=None):
    """本机显示码（如 `YN579-2XZ28-1P6YA`）。**只读**：没有 `machine.json` 就返回空串。

    ★ 为什么只读：`machine_id.ensure()` 会在缺文件时**生成并落盘**。
      读一次粮余额不该顺带写盘（判据只读地查余额时尤其不能有副作用）。
    """
    try:
        import machine_id as MID
        p = MID.machine_path(root)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return (json.load(f) or {}).get("code") or ""
    except Exception:                                  # noqa: BLE001
        pass
    return ""


# ------------------------------------------------------------ 流水 IO ----
def _append(entry, root=None):
    """追加一笔。优先用产品自带的加锁追加（与审计链同一把锁）。"""
    p = ledger_path(root)
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n"
    try:
        import audit_chain
        audit_chain.append_locked(p, line)
        return entry
    except ImportError:
        pass
    with open(p, "a", encoding="utf-8", newline="\n") as f:
        f.write(line)
        f.flush()
    return entry


def load(root=None):
    """读全部流水（坏行跳过，不抛；读不到就空表）。"""
    out = []
    try:
        with open(ledger_path(root), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:                      # noqa: BLE001
                    continue
                if isinstance(e, dict) and e.get("kind") in (KIND_GRANT, KIND_SPEND):
                    out.append(e)
    except FileNotFoundError:
        return []
    return out


def balance(root=None):
    """余额＝Σ发放 − Σ消耗。**由流水算出**（没有"当前余额"单值可被改坏）。"""
    g = s = 0
    for e in load(root):
        try:
            amt = int(e.get("amount") or 0)
        except (TypeError, ValueError):
            continue
        if e.get("kind") == KIND_GRANT:
            g += amt
        else:
            s += amt
    return g - s


def has_ledger(root=None):
    return os.path.exists(ledger_path(root))


# ------------------------------------------------------------ 写流水 ----
def _now_iso(now=None):
    if now is None:
        return datetime.now().astimezone().isoformat(timespec="seconds")
    if isinstance(now, datetime):
        return now.astimezone().isoformat(timespec="seconds")
    return str(now)


def _entry(kind, reason, amount, root=None, now=None, extra=None):
    amt = int(amount)
    if amt <= 0:
        raise ValueError("粮的金额必须为正整数（正负由分类决定）：%r" % (amount,))
    e = {"ts": _now_iso(now), "date": date.today().isoformat(),
         "kind": kind, "reason": str(reason), "amount": amt,
         "machine": machine_code(root)}
    if extra:
        e.update(extra)
    return _append(e, root=root)


def grant(reason, amount, root=None, now=None, extra=None):
    """发放口粮（**唯一的加粮入口**）。"""
    return _entry(KIND_GRANT, reason, amount, root=root, now=now, extra=extra)


def spend(reason, amount, root=None, now=None, extra=None):
    """消耗口粮（**唯一的减粮入口**）。哨兵站岗按天走这里。"""
    return _entry(KIND_SPEND, reason, amount, root=root, now=now, extra=extra)


def seed_once(root=None, now=None):
    """入驻口粮：**只发一次**（幂等）。已发过则返回 None，不重复发。"""
    for e in load(root):
        if e.get("kind") == KIND_GRANT and e.get("reason") == "入驻口粮":
            return None
    return grant("入驻口粮", SEED_GRANT, root=root, now=now)


# ------------------------------------------------------------ 读状态 ----
def tier(bal=None, root=None):
    """按余额给档位（粮尽降档续守用）。余额低于一天口粮 ⇒ 守备档。"""
    b = balance(root) if bal is None else bal
    if b < DAILY_SPEND_DEFAULT:
        return "守备档"
    return "标准档"


def days_left(bal=None, root=None):
    """还够站几天（按标准档）。**不承诺**——它只是余额 ÷ 每日消耗。"""
    b = balance(root) if bal is None else bal
    return round(b / DAILY_SPEND_DEFAULT, 1)


def state(root=None):
    """给顶部灯用的读数。返回::

        {"state": "low"|"ok"|"off", "balance": int, "threshold": int,
         "days_left": float|None, "why": str}

    ★ `off` ＝**还没记过粮账**（没有流水文件）⇒ 不报警（像"未启用"：默认没开不是故障）。
      这与"字段缺失＝不知道，方向收紧"不冲突：粮账**本来就没有**时，
      说"缺粮"才是编 —— 那时**根本没在消耗**。
    """
    if not has_ledger(root):
        return {"state": "off", "balance": 0, "threshold": LOW_THRESHOLD,
                "days_left": None, "why": "还没记过粮账（哨兵开始站岗后才有消耗）"}
    b = balance(root)
    if b < LOW_THRESHOLD:
        return {"state": "low", "balance": b, "threshold": LOW_THRESHOLD,
                "days_left": days_left(b),
                "why": "粮只够 %s 天（余额 %d）—— 领地的续航快见底了"
                       % (days_left(b), b)}
    return {"state": "ok", "balance": b, "threshold": LOW_THRESHOLD,
            "days_left": days_left(b), "why": "粮还够 %s 天（余额 %d）" % (days_left(b), b)}


def is_low(root=None):
    return state(root)["state"] == "low"


# ------------------------------------------------------------ 展示用 ----
def rules():
    """规则表（供 `antinel 粮 rules` 与页面渲染；返回副本，防调用方改到真源）。"""
    return {"grant": {k: list(v) for k, v in RULES_GRANT.items()},
            "spend": [list(t) for t in SPEND_TIERS],
            "low_threshold": LOW_THRESHOLD,
            "daily_spend": DAILY_SPEND_DEFAULT,
            "recharge": dict(RECHARGE)}


def summary(root=None):
    st = state(root)
    st["tier"] = tier(root=root) if st["state"] != "off" else "—"
    st["has_ledger"] = has_ledger(root)
    st["entries"] = len(load(root))
    return st


def recent(n=20, root=None):
    """最近 n 笔（新的在前）。"""
    return list(reversed(load(root)))[:n]


def _main(argv):
    """`python granary.py [balance|rules|recent|seed]` —— 便于手工核对。"""
    cmd = (argv[1] if len(argv) > 1 else "balance").lower()
    if cmd == "rules":
        print(json.dumps(rules(), ensure_ascii=False, indent=1))
    elif cmd == "recent":
        for e in recent(int(argv[2]) if len(argv) > 2 else 20):
            print("%s  %-10s %+4d  %s" % (e["ts"], e["reason"],
                                          e["amount"] if e["kind"] == KIND_GRANT else -e["amount"],
                                          e.get("machine") or ""))
    elif cmd == "seed":
        e = seed_once()
        print("已发入驻口粮" if e else "入驻口粮此前已发过（不重复发）")
        print("余额：", balance())
    else:
        print(json.dumps(summary(), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    import sys
    _main(sys.argv)
