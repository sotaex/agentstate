#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.37.0 判据 —— **问题数单调收敛闸门（PCM：Problem-count Convergence Monitor）**。

★★★ 这份文件存在的理由（创始人 2026-10-08 原话，一字不改地记在这里）：

    「在新增模块，以及修改老问题时，要最大限度避免引入新问题，
      系统的问题总量要求不断收敛，能以最快的速度清零，
      **这个要求需要从机制上解决**。」

  「从机制上解决」＝ 不许靠人记得、不许靠人勤快。本仓已有一整条收敛管道
  （0366 基线差分／影响面点名／JDG 判据腐化检测／by_kind 失败四分类账），
  但它们回答的都是「**这次多了什么、红是真是假**」；
  没有一个回答「**问题总量有没有在变小、变小是真的变小还是账面变小**」。
  ⇒ 本文件补上这一条，并且只做这一条。

★★★ 四条判据（全部可机械执行，输入只有两份：判定账本 ＋ 收敛账本）

    PCM-01  输入契约（fail-closed）
            judgment.json 必须带 discrimination.by_kind.counts.product 与
            per_failure 明细。缺一项 ⇒ 红 —— 「量具没说话」与「量具说没问题」
            在账面上不许长得一样。

    PCM-02  P1 单调不增：本版 product 数 ≤ 上一版
            product 类＝「产品缺陷」（fail-closed 默认类）。它只许降、不许升。
            升了必须有一张**人写的豁免单**（版本／类别／数量／理由四要素齐，
            见 .psl/gate/pcm_waiver.json），否则红。
            ⇒ 为什么单挑 product 类：instrument/environment/process-stale
              都可能随环境与登记表波动，把它们一起捆进「只许降」会天天假红
              （假红比漏红更坏：它训练人绕过闸门）。

    PCM-03  P2 一进一出：本版新增失败条数 ≤ 本版关闭失败条数
            失败身份＝断言名（harness 结构化结果里的 name，稳定标识）。
            新增 > 关闭 ⇒ 需要豁免单，否则红。
            ⇒ 它盯的是「修一个坏两个」：P1 只看 product 类，
              P2 看**全口径**失败集合的进出平衡。

    PCM-04  P3 停滞即红：连续 3 个版本 product 数一次都没降，且当前 > 0 ⇒ 红
            「不降」含「持平」——持平不是收敛，是账不走了。
            ★ 不可豁免：停滞正是本闸门存在的理由，给它开豁免门＝没有闸门。
            ★ product 已清零（=0）时永远通过 —— 清零是目标态，不是停滞。

    PCM-05  P4 分类迁移不冒充收敛
            product 数下降，必须由「失败真的消失了」解释，不许由
            「失败还在、只是被改分类」解释。
            机械判据：上一版 product 类失败集合里，「不在本版失败集合」的条数
            （真修）必须 ≥ product 下降数；否则红，并点名那些
            「仍在失败、但被搬去别的类」的断言。
            ⇒ 它防的是**账面收敛**：改分类表（_BY_KIND_OVERRIDES）就能让
              product 数归零，而断言一条都没修好。这是本闸门最容易被
              「合法地」绕开的一条，所以它必须存在。

★★★ 三条纪律（与 JDG 族、0366 一脉相承）
  · 每条判据都配负控：把输入换坏，判据必须报红 —— 负控全在**内存态**跑，
    不碰产品文件、不碰真实账本（比 JDG 的文件补丁负控更安全一档）。
  · 判据不许二次实现：product 数、失败身份全部读 harness 写的
    judgment.json 自身，本文件一个数都不重算。
  · 「无上一版可比」必须与「通过了」在输出里**可区分**（SKIP-BASELINE
    与 PASS 分列）—— 否则「第一次跑」会被读成「已经收敛」。

★★★ 两份账（都不进包、不进 manifest，写在 .psl/gate/ 下）
  · pcm_ledger.json   收敛账本：每次闸门跑过就追加一行（版本／判定／
                       product 数／失败名→类），先 rename-aside 成
                       .prev.json 再写新（零删除，与 baseline.json 同范式）。
                       它是**观察记录，不是奖惩记录**：闸门判红也照记实况。
  · pcm_waiver.json   豁免单：**只能由人写**。闸门自己永远不写它 ——
                       否则「违规者给自己开路」只需要改一行判据代码。

★ 已知局限（明写，不假装覆盖）：
  ① 失败身份用断言名。断言被改名时，旧名记「关闭」、新名记「新增」，
     P2 一进一出恰好抵平（不误红），但「改名即收敛」的伪装 P2 看不出来 ——
     拦住它的是 by_kind 的 basis 留痕与人工审阅，不是本闸门。
  ② 账本从 0.37.0 起才有 per_failure 明细 ⇒ 本闸门的P3/P4 对更早的版本
     无从比起。不伪造历史（那比没有历史更坏），基线就从当前版本开始。
  ③ product 数的口径完全信任 _BY_KIND_OVERRIDES 登记表；登记表本身腐烂
     由 by_kind.stale_entries 留痕，不在本闸门职责内。
"""
from __future__ import annotations

import io
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

JUDGMENT = os.path.join(ROOT, "psl", "judgment.json")
LEDGER = os.path.join(ROOT, ".psl", "gate", "pcm_ledger.json")
LEDGER_PREV = os.path.join(ROOT, ".psl", "gate", "pcm_ledger.prev.json")
WAIVER = os.path.join(ROOT, ".psl", "gate", "pcm_waiver.json")

#: P3 的窗口：连续多少个版本不降才算停滞（含当前版本）。
STAGNATION_VERSIONS = 3

#: 豁免单的两种合法类别。别的类别名一律不认（防「换个名字就不是违规」）。
WAIVER_KINDS = ("product-increase", "one-in-one-out")

RESULTS = []          # [(判据名, 检查函数, 负控名)] —— 与 JDG 族记账范式一致


def check(name, negctl=None):
    def deco(fn):
        RESULTS.append((name, fn, negctl))
        return fn
    return deco


# ═══════════════════ 输入侧：只读，不重算任何一个数 ═══════════════════

def load_current():
    """从 judgment.json 取当前态。契约不齐 ⇒ None（由 PCM-01 判红）。

    ★ 为什么返回 None 而不是抛异常：契约缺失是**判据要报的红**，
      不是判据自己的故障。两者在输出里必须分开（与 delivery_gate 的
      CRASH/RED 分列同源）。
    """
    try:
        d = json.load(io.open(JUDGMENT, encoding="utf-8"))
    except Exception:                                          # noqa: BLE001
        return {"version": None, "product_count": None, "failures": None,
                "why": "judgment.json 读不到或不是合法 JSON"}
    disc = d.get("discrimination") or {}
    bk = disc.get("by_kind") or {}
    counts = bk.get("counts") or {}
    per = bk.get("per_failure")
    if "product" not in counts:
        return {"version": d.get("skill_version"), "product_count": None,
                "failures": None,
                "why": "by_kind.counts.product 缺失（harness 未生成四分类账）"}
    failures = None
    if isinstance(per, list):
        failures = {}
        for f in per:
            n = f.get("name")
            if n:
                failures[n] = f.get("kind") or "product"
    if failures is None:
        return {"version": d.get("skill_version"),
                "product_count": counts.get("product"),
                "failures": None,
                "why": "by_kind.per_failure 缺失（拿不到失败身份与分类）"}
    return {"version": d.get("skill_version") or "unknown",
            "product_count": int(counts.get("product") or 0),
            "failures": failures, "why": ""}


def load_rows():
    """收敛账本（缺失 ⇒ 空表，即首次运行）。"""
    try:
        d = json.load(io.open(LEDGER, encoding="utf-8"))
    except Exception:                                          # noqa: BLE001
        return []
    rows = d.get("rows")
    return rows if isinstance(rows, list) else []


def load_waivers():
    """人写的豁免单（缺失 ⇒ 空）。"""
    try:
        d = json.load(io.open(WAIVER, encoding="utf-8"))
    except Exception:                                          # noqa: BLE001
        return []
    ws = d.get("waivers")
    return ws if isinstance(ws, list) else []


def write_row(cur):
    """把当前态追加进收敛账本。先 rename-aside 成 .prev（零删除）。

    ★ 为什么判红也照记：账本是**观察记录**。若只记绿灯，那么「红过一次」
      这件事本身会从历史上消失，P3/P4 的窗口就被人为剪干净了。
    """
    row = {"version": cur["version"], "product_count": cur["product_count"],
           "failures": cur["failures"], "recorded_at": time.time(),
           "source": "psl/judgment.json"}
    rows = load_rows()
    rows.append(row)
    try:
        os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
        if os.path.isfile(LEDGER):
            os.replace(LEDGER, LEDGER_PREV)      # 改名让开，不是删除
        with io.open(LEDGER, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"rows": rows}, f, ensure_ascii=False, indent=1)
        return True, len(rows)
    except Exception as e:                                  # noqa: BLE001
        return False, repr(e)


# ═══════════════════ 纯判断层：evaluate() 全部吃内存数据，可负控 ═══════════════════

def _versions_and_prev(rows, cur_version):
    """按出现顺序去重：返回 (有序版本表, 每版最后一行, 上一版行或 None)。

    「上一版」＝ 当前版本在序表中的**前一个不同版本**；当前版本若是新的，
    就是序表末行。当前版本自己历史上出现过几次都不参与比较
    （同版本内重跑 harness 不构成一次版本推进）。
    """
    order, last = [], {}
    for r in rows:
        v = (r or {}).get("version")
        if v is None:
            continue
        if v not in last:
            order.append(v)
        last[v] = r
    if cur_version in order:
        i = order.index(cur_version)
        return order, last, (last[order[i - 1]] if i > 0 else None)
    return order, last, (last[order[-1]] if order else None)


def _find_waiver(waivers, version, kind, count):
    """找一张能覆盖本次违规的豁免单。四要素缺一 ⇒ 不算豁免。"""
    for w in waivers:
        if not isinstance(w, dict):
            continue
        if w.get("version") != version or w.get("kind") != kind:
            continue
        if not str(w.get("reason") or "").strip():
            continue                      # 没写理由的豁免单不是豁免单
        try:
            if int(w.get("count") or 0) >= count:
                return w
        except (TypeError, ValueError):
            continue
    return None


def evaluate(cur, rows, waivers):
    """四条判据的纯函数版。返回 [(id, status, detail)]，status ∈
    PASS / RED / SKIP-BASELINE / WAIVED。

    ★ 为什么拆成纯函数：负控要能**换掉输入**看判据是否变红。
      若判断逻辑内联在 main() 的文件读写里，负控就只能去改真实账本 ——
      那会让「测闸门」本身变成一次「污染闸门」。
    """
    out = []

    # ── PCM-01 输入契约 ──
    if cur is None or cur.get("product_count") is None or cur.get("failures") is None:
        out.append(("PCM-01 输入契约", "RED",
                    (cur or {}).get("why") or "当前态不可用"))
    else:
        out.append(("PCM-01 输入契约", "PASS",
                    "judgment v%s：product=%d，失败 %d 条"
                    % (cur["version"], cur["product_count"], len(cur["failures"]))))

    if cur is None or cur.get("product_count") is None or cur.get("failures") is None:
        # 契约不齐时后面几条没有判断依据 —— 全部记 RED（依据不建立在没拿到的信息上）
        for cid in ("PCM-02 P1 单调不增", "PCM-03 P2 一进一出",
                    "PCM-04 P3 停滞即红", "PCM-05 P4 分类不冒充收敛"):
            out.append((cid, "RED", "输入契约不齐，本条无判断依据"))
        return out

    version = cur["version"]
    cur_p = cur["product_count"]
    cur_f = cur["failures"]
    order, last, prev = _versions_and_prev(rows, version)

    # ── PCM-02 P1 单调不增 ──
    if prev is None:
        out.append(("PCM-02 P1 单调不增", "SKIP-BASELINE",
                    "无上一版可比（首跑/版本推进过头）—— 这是建立基线，不是通过"))
    else:
        prev_p = int(prev.get("product_count") or 0)
        if prev.get("failures") is None:
            out.append(("PCM-02 P1 单调不增", "RED",
                        "账本上一版行缺 failures 明细（账本契约被破坏）"))
        else:
            delta = cur_p - prev_p
            if delta <= 0:
                out.append(("PCM-02 P1 单调不增", "PASS",
                            "product %d ≤ 上一版 %s 的 %d"
                            % (cur_p, prev.get("version"), prev_p)))
            else:
                w = _find_waiver(waivers, version, "product-increase", delta)
                if w:
                    out.append(("PCM-02 P1 单调不增", "WAIVED",
                                "product %d → %d（+%d）已豁免：%s"
                                % (prev_p, cur_p, delta,
                                   str(w.get("reason"))[:120])))
                else:
                    out.append(("PCM-02 P1 单调不增", "RED",
                                "product %d → %d（**+%d**）且无有效豁免单"
                                "（.psl/gate/pcm_waiver.json 需 version/kind="
                                "product-increase/count≥%d/reason）"
                                % (prev_p, cur_p, delta, delta)))

    # ── PCM-03 P2 一进一出 ──
    if prev is None:
        out.append(("PCM-03 P2 一进一出", "SKIP-BASELINE",
                    "无上一版可比 —— 无法计算失败集合的进出"))
    elif prev.get("failures") is None:
        out.append(("PCM-03 P2 一进一出", "RED",
                    "账本上一版行缺 failures 明细（无法比对失败集合）"))
    else:
        prev_f = prev["failures"]
        new = sorted(set(cur_f) - set(prev_f))
        closed = sorted(set(prev_f) - set(cur_f))
        imbalance = len(new) - len(closed)
        if imbalance <= 0:
            out.append(("PCM-03 P2 一进一出", "PASS",
                        "新增 %d / 关闭 %d（关闭的有：%s）"
                        % (len(new), len(closed),
                           "、".join(n[:40] for n in closed) or "无")))
        else:
            w = _find_waiver(waivers, version, "one-in-one-out", imbalance)
            detail = ("新增 %d（%s）＞ 关闭 %d —— 多出来的 %d 条没有同版关闭"
                      % (len(new), "、".join(n[:40] for n in new),
                         len(closed), imbalance))
            if w:
                out.append(("PCM-03 P2 一进一出", "WAIVED",
                            detail + "；已豁免：%s" % str(w.get("reason"))[:120]))
            else:
                out.append(("PCM-03 P2 一进一出", "RED",
                            detail + "，且无有效豁免单（kind=one-in-one-out）"))

    # ── PCM-04 P3 停滞即红 ──
    # ★★ SS（2026-10-22）：「窗口末位」必须是**当前观测**，不能是「出现序的末项」。
    #   版本回落后账本里会留着比当前更新的版本行（本仓实测：树是 0.53.2，账本里
    #   夹着一行 `0.53.5 | product 1`）。此时 `seq[-1]` 不是当前版本 ⇒
    #   `prods[-1]` 读到的是**别人的** product 数 ⇒ 一个已经清零的当前态
    #   被判成「停滞」。这与本判据的文档契约（「product 已清零时永远通过」）相反。
    #   ⇒ 把当前版本移到末位；窗口内它的历史行由下方循环的 `v == version`
    #     分支用 `cur_p` 覆盖（同版本内重跑不构成一次版本推进，这点不变）。
    seq = [v for v in order if v != version]
    seq.append(version)
    window = seq[-STAGNATION_VERSIONS:]
    if len(window) < STAGNATION_VERSIONS:
        out.append(("PCM-04 P3 停滞即红", "SKIP-BASELINE",
                    "独立版本数 %d < %d，窗口未满 —— 判定不了停滞"
                    % (len(window), STAGNATION_VERSIONS)))
    else:
        prods = []
        for v in window:
            if v == version:
                prods.append(cur_p)
            else:
                prods.append(int((last.get(v) or {}).get("product_count") or 0))
        drops = sum(1 for a, b in zip(prods, prods[1:]) if b < a)
        if cur_p == 0:
            # 判「当前」只看 cur_p，不看 prods[-1] —— 后者要对，前提是窗口末位
            # 恰好是当前版本，而版本回落后不再成立（见上方 SS 注释）。
            out.append(("PCM-04 P3 停滞即红", "PASS",
                        "product 已清零（窗口 %s）—— 清零是目标态"
                        % "→".join(str(x) for x in prods)))
        elif drops == 0:
            out.append(("PCM-04 P3 停滞即红", "RED",
                        "连续 %d 个版本一次都没降（%s，当前 %d）—— "
                        "持平不是收敛；本条**不可豁免**"
                        % (len(window), "→".join(str(x) for x in prods), cur_p)))
        else:
            out.append(("PCM-04 P3 停滞即红", "PASS",
                        "窗口 %s 内有 %d 次下降"
                        % ("→".join(str(x) for x in prods), drops)))

    # ── PCM-05 P4 分类迁移不冒充收敛 ──
    if prev is None:
        out.append(("PCM-05 P4 分类不冒充收敛", "SKIP-BASELINE",
                    "无上一版可比 —— 无法审计下降的成因"))
    elif prev.get("failures") is None:
        out.append(("PCM-05 P4 分类不冒充收敛", "RED",
                    "账本上一版行缺 failures 明细（无法审计分类迁移）"))
    else:
        prev_f = prev["failures"]
        prev_products = sorted(n for n, k in prev_f.items() if k == "product")
        decrease = int(prev.get("product_count") or 0) - cur_p
        if decrease <= 0:
            out.append(("PCM-05 P4 分类不冒充收敛", "PASS",
                        "product 未下降（%d → %d）—— 无可审计的「收敛」"
                        % (prev.get("product_count"), cur_p)))
        else:
            fixed = [n for n in prev_products if n not in cur_f]
            migrated = [n for n in prev_products if n in cur_f]
            if len(fixed) >= decrease:
                out.append(("PCM-05 P4 分类不冒充收敛", "PASS",
                            "product 降 %d，其中 %d 条失败真的消失了%s"
                            % (decrease, len(fixed),
                               ("；仍在失败但换了类的有：%s"
                                % "、".join(n[:40] for n in migrated))
                               if migrated else "")))
            else:
                out.append(("PCM-05 P4 分类不冒充收敛", "RED",
                            "product 降 %d，但只有 %d 条失败真的消失；"
                            "其余 %d 条**仍在失败、只是被改分类**（%s）—— "
                            "这是账面收敛，不是收敛"
                            % (decrease, len(fixed), len(migrated),
                               "、".join(n[:40] for n in migrated) or "?")))
    return out


# ═══════════════════ 判据（真实相位：只读 + 记账，不改任何产品文件）═══════════════

def run_real():
    cur = load_current()
    rows = load_rows()
    waivers = load_waivers()
    out = evaluate(cur, rows, waivers)
    return out, cur


# ═══════════════════ 负控（全部内存态：换输入，不换文件）═══════════════

def _mk(version, product, failures):
    return {"version": version, "product_count": product, "failures": failures}


def n_baseline_is_not_green():
    """负控：首跑（无上一版）时，**四条收敛判据**（P1–P4）都不许报 PASS。

    ★ 防的是装饰化：若把「无据可比」记成通过，那么**不跑 harness 的版本**
      在账面上与「已收敛」完全一样 —— 这正是本仓铁律
      「有检查项但没人跑＝等于没有」的收敛账本版。

    ★ 自审（首跑当场抓到本负控自己的缺陷）：第一版断言「全部判据无 PASS」，
      但 PCM-01（输入契约）在契约齐全时**本来就该 PASS** ——
      把它算进去，这条负控永远红，而它是量具不是判据。
      ⇒ 只查 P1–P4 四条收敛判据：全 SKIP-BASELINE、零 PASS、零 RED。
    """
    cur = _mk("9.9.9", 1, {"a": "product"})
    out = evaluate(cur, [], [])
    conv = [s for cid, s, _d in out if cid != "PCM-01 输入契约"]
    return ("SKIP-BASELINE" in conv) and ("PASS" not in conv) and ("RED" not in conv)


def n_p1_regress_is_red():
    """负控：上一版 product=0，本版变 1（无豁免）⇒ P1 必须红。"""
    cur = _mk("9.9.9", 1, {"a": "product"})
    rows = [_mk("9.9.8", 0, {})]
    out = dict((cid, (s, d)) for cid, s, d in evaluate(cur, rows, []))
    s, _d = out["PCM-02 P1 单调不增"]
    return s == "RED"


def n_p1_waiver_is_accepted():
    """负控：同一违规，但有合格豁免单 ⇒ P1 必须 WAIVED 而不是 RED。

    ★ 没有这条负控，豁免路径就是**从未被执行的代码** ——
      而没执行过的代码在红起来的那天才能发现是坏的（那时最急）。
    """
    cur = _mk("9.9.9", 2, {"a": "product", "b": "product"})
    rows = [_mk("9.9.8", 0, {})]
    w = [{"version": "9.9.9", "kind": "product-increase", "count": 2,
          "reason": "负控自撰理由", "by": "negctl", "at": "n/a"}]
    out = dict((cid, (s, d)) for cid, s, d in evaluate(cur, rows, w))
    s, _d = out["PCM-02 P1 单调不增"]
    return s == "WAIVED"


def n_p2_regress_is_red():
    """负控：新增 1 条失败、同版关闭 0 条 ⇒ P2 必须红。"""
    cur = _mk("9.9.9", 2, {"a": "product", "b": "product", "c": "product"})
    rows = [_mk("9.9.8", 2, {"a": "product", "b": "product"})]
    out = dict((cid, (s, d)) for cid, s, d in evaluate(cur, rows, []))
    s, _d = out["PCM-03 P2 一进一出"]
    return s == "RED"


def n_p2_waiver_is_accepted():
    """负控：一进一出失衡但有合格豁免单 ⇒ WAIVED。"""
    cur = _mk("9.9.9", 2, {"a": "product", "b": "product", "c": "product"})
    rows = [_mk("9.9.8", 2, {"a": "product", "b": "product"})]
    w = [{"version": "9.9.9", "kind": "one-in-one-out", "count": 1,
          "reason": "负控自撰理由", "by": "negctl", "at": "n/a"}]
    out = dict((cid, (s, d)) for cid, s, d in evaluate(cur, rows, w))
    s, _d = out["PCM-03 P2 一进一出"]
    return s == "WAIVED"


def n_p3_stagnation_is_red():
    """负控：连续三个版本 product 持平 5 ⇒ P3 必须红（且不可豁免）。"""
    cur = _mk("9.9.9", 5, {("f%d" % i): "product" for i in range(5)})
    rows = [_mk("9.9.7", 5, {("f%d" % i): "product" for i in range(5)}),
            _mk("9.9.8", 5, {("f%d" % i): "product" for i in range(5)})]
    w = [{"version": "9.9.9", "kind": "product-increase", "count": 99,
          "reason": "负控：想让 P3 被豁免", "by": "negctl", "at": "n/a"}]
    out = dict((cid, (s, d)) for cid, s, d in evaluate(cur, rows, w))
    s, _d = out["PCM-04 P3 停滞即红"]
    return s == "RED"          # 带了别的类别豁免单也照红：P3 不可豁免


def n_p3_zero_is_pass():
    """负控（反向）：窗口内归过零 ⇒ P3 必须放行（清零是目标态）。"""
    cur = _mk("9.9.9", 0, {})
    rows = [_mk("9.9.7", 5, {("f%d" % i): "product" for i in range(5)}),
            _mk("9.9.8", 5, {("f%d" % i): "product" for i in range(5)})]
    out = dict((cid, (s, d)) for cid, s, d in evaluate(cur, rows, []))
    s, _d = out["PCM-04 P3 停滞即红"]
    return s == "PASS"


def n_p3_rollback_zero_is_pass():
    """负控：**版本回落后**当前已清零 ⇒ 必须 PASS（不是停滞）。

    形状照抄本仓实测：账本里留着比当前更新的版本行（树 0.53.2，账本一行 0.53.5
    product=1）。旧实现拿 `prods[-1]` 当「当前」，读到的是那行的 1 ⇒
    把已清零的当前态判成停滞。这条负控在旧实现上**是红的**。
    """
    cur = _mk("9.9.9", 0, {})
    rows = [_mk("9.9.8", 0, {}),
            _mk("9.9.9", 0, {}),
            _mk("9.9.10", 1, {"a": "product"})]      # 回落前留下的"未来版本"行
    out = dict((cid, (s, d)) for cid, s, d in evaluate(cur, rows, []))
    s, _d = out["PCM-04 P3 停滞即红"]
    return s == "PASS"


def n_p3_rollback_stagnant_is_red():
    """负控：同样的回落形状，但当前仍有 5 条且窗口一次没降 ⇒ 必须 RED。

    ★ 与上一条成对：只加"回落即放行"会把 P3 变成一条对回落形状永远绿的判据。
    """
    f = {("f%d" % i): "product" for i in range(5)}
    cur = _mk("9.9.9", 5, dict(f))
    rows = [_mk("9.9.8", 5, dict(f)),
            _mk("9.9.9", 5, dict(f)),
            _mk("9.9.10", 5, dict(f))]
    out = dict((cid, (s, d)) for cid, s, d in evaluate(cur, rows, []))
    s, _d = out["PCM-04 P3 停滞即红"]
    return s == "RED"


def n_p4_reclass_is_red():
    """负控：两条 product 失败仍在，只是被改分类 ⇒ product 归零也必须红。"""
    cur = _mk("9.9.9", 0, {"a": "instrument", "b": "environment"})
    rows = [_mk("9.9.8", 2, {"a": "product", "b": "product"})]
    out = dict((cid, (s, d)) for cid, s, d in evaluate(cur, rows, []))
    s, _d = out["PCM-05 P4 分类不冒充收敛"]
    return s == "RED"


def n_p4_real_fix_is_pass():
    """负控（反向）：失败真的消失了 ⇒ P5 放行。"""
    cur = _mk("9.9.9", 0, {})
    rows = [_mk("9.9.8", 1, {"a": "product"})]
    out = dict((cid, (s, d)) for cid, s, d in evaluate(cur, rows, []))
    s, _d = out["PCM-05 P4 分类不冒充收敛"]
    return s == "PASS"


def n_contract_missing_is_red():
    """负控：judgment 缺 by_kind（量具没说话）⇒ PCM-01 必须红。"""
    out = evaluate({"version": "9.9.9", "product_count": None,
                    "failures": None, "why": "负控：契约不齐"}, [], [])
    s = out[0][1]
    return s == "RED"


# ═══════════════════ main ═══════════════════

def main():
    print("=" * 78)
    print("PCM 问题数单调收敛闸门 —— product 只许降；失败一进一出；停滞即红")
    print("账本：%s" % os.path.relpath(LEDGER, ROOT))
    print("=" * 78)

    negctls = [(n.__name__, n) for n in (
        n_baseline_is_not_green, n_p1_regress_is_red, n_p1_waiver_is_accepted,
        n_p2_regress_is_red, n_p2_waiver_is_accepted, n_p3_stagnation_is_red,
        n_p3_zero_is_pass, n_p3_rollback_zero_is_pass,
        n_p3_rollback_stagnant_is_red,
        n_p4_reclass_is_red, n_p4_real_fix_is_pass,
        n_contract_missing_is_red)]
    run_neg = "--negctl" in sys.argv

    # ── 真实相位 ──
    out, cur = run_real()
    n_red = 0
    for cid, st, detail in out:
        icon = {"PASS": "✅", "RED": "❌", "WAIVED": "⬆",
                "SKIP-BASELINE": "ⓘ"}[st]
        print("  %s %-46s %s" % (icon, cid, detail))
        if st == "RED":
            n_red += 1

    # ── 记账相位：无论红绿都记实况（观察记录，不是奖惩记录）──
    if cur is not None and cur.get("product_count") is not None:
        ok, info = write_row(cur)
        if ok:
            print("  ⓘ 收敛账本已追加一行（现共 %d 行；.prev 保留上一态）" % info)
        else:
            print("  ⚠ 收敛账本写入失败：%s（判断照常生效，只是历史断了）" % info)

    if run_neg:
        print("-" * 78)
        print("负控（换输入看判据是否真的红 —— 全部内存态，不碰真实账本）")
        nf = 0
        for name, fn in negctls:
            try:
                r = fn()
            except Exception as e:                              # noqa: BLE001
                print("  💥 %-46s 负控自身崩了：%r" % (name[:46], e))
                nf += 1
                continue
            if r is True:
                print("  ✅ %-46s └ 负控生效" % name[:46])
            else:
                print("  ❌ %-46s 判据在该注入下没有红 —— 它是装饰" % name[:46])
                nf += 1
        print("-" * 78)
        print("  %d 绿 / %d 红（含负控）" % (len(out) - n_red + (len(negctls) - nf),
                                        n_red + nf))
        return 0 if (n_red == 0 and nf == 0) else 1

    print("-" * 78)
    print("  四条判据：红 %d（SKIP-BASELINE/WAIVED 不阻断，但单独列出）" % n_red)
    if n_red:
        print("★ 闸门未通过：问题总量没有单调收敛（或豁免单不合格）。")
        print("  · product 上升/一进一出失衡 ⇒ 要么修，要么写"
              " .psl/gate/pcm_waiver.json（人写，带理由）。")
        print("  · 停滞/改分类冒充收敛 ⇒ **不可豁免**，只能真修。")
        print("  · 单独复跑负控：python ci/pcm_gate_0370.py --negctl")
    else:
        print("★ 闸门通过：问题总量维持单调收敛（或处于基线期/已豁免/已清零）。")
    return 0 if n_red == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
