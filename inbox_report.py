# -*- coding: utf-8 -*-
"""值守台 · 日报（**从链与账本算**）。

★ 判据不许二次实现：日报的每个数字都必须来自 `inbox_store` / `ledger` / `inbox_model`
  的同一批函数；**页面只负责排版，不许自己再加一遍**（J5 守的就是这条）。

★ 诚实纪律（最容易犯的两条）：
  1. **链读不到 ≠ 链是好的**：校验不了必须报 `unknown`，**绝不报 `ok`**。
  2. **没有记录 ≠ 没有发生**：数字为 0 时要能区分"查过了、确实没有"与"没查成"。
"""
from __future__ import annotations

import json
from datetime import date, datetime

import inbox_model as M
import inbox_store as S
import ledger as L


def _day_of_ts(ts):
    """取一条记录的**本地日期**（生产者写链时用 `.astimezone()`，故前缀即本地日期）。

    取不到 ⇒ 返回 None（**不静默当今天** —— 那会把未知日期混进今日统计）。
    """
    s = str(ts or "")
    if len(s) >= 10 and s[4] == "-" and s[7] == "-":
        return s[:10]
    return None


def chain_health(chain_files):
    """逐文件校验链式链接。**用产品自己的 `audit_chain.chain_with`，不二次实现哈希。**

    返回 `{"status": "ok"|"broken"|"unknown", ...}`。

    ★★ 一条**实测得来**的规则（首版踩过，必须记住）：
      **`hash` 为空的记录是"未链接记录"（如 `session_start`），不是断链。**
      把它们算成断链会**误报**（实测 18 个文件 40101 条里误报 128 条），
      而**会误报的检查器用两次就没人信**。⇒ 单独计数为 `unchained`，**不影响 status**。

    ★ 拿不到校验器 / 没有文件 / **一条可校验的都没有** ⇒ **unknown**（不是 ok）。
    """
    if not chain_files:
        return {"status": "unknown", "files": 0, "records": 0, "broken": 0,
                "unchained": 0, "bad_lines": 0, "first_bad": "",
                "reason": "没有可校验的链文件 —— 这是「没查成」，不是「没问题」。"}
    try:
        import audit_chain as ac
    except Exception as e:                      # noqa: BLE001
        return {"status": "unknown", "files": len(chain_files), "records": 0,
                "broken": 0, "unchained": 0, "bad_lines": 0, "first_bad": "",
                "reason": "拿不到校验器：%s" % (e,)}

    files = records = broken = badjson = unchained = 0
    first_bad = ""
    for p in chain_files:
        files += 1
        prev = ""
        try:
            f = open(p, encoding="utf-8", errors="replace")
        except OSError:
            badjson += 1
            continue
        with f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:               # noqa: BLE001
                    badjson += 1
                    continue
                if not isinstance(rec, dict):
                    badjson += 1
                    continue
                h = rec.get("hash")
                if not h:
                    unchained += 1              # ★ 未链接记录，不是断链
                    continue
                records += 1
                rc = ac.chain_with(rec, prev)   # ← 产品原语
                if rc["hash"] != h or rc["prev"] != rec.get("prev"):
                    broken += 1
                    if not first_bad:
                        first_bad = "%s@%s" % (p, rec.get("ts"))
                prev = h

    if records == 0:
        status = "unknown"                      # 一条可校验的都没有 ⇒ 没查成
    else:
        status = "broken" if (broken or badjson) else "ok"
    return {"status": status, "files": files, "records": records,
            "broken": broken, "unchained": unchained, "bad_lines": badjson,
            "first_bad": first_bad, "reason": ""}


def daily_report(day=None, root=None, chain_files=None, items=None,
                 chain=None, led=None):
    """生成某一天的日报。`day` 缺省＝本地今天。

    `items` / `chain` / `led` 可注入（测试用；生产走真实来源）。
    """
    day = day or date.today().isoformat()
    files = S.discover_chain_files(root=root) if chain_files is None else chain_files
    items = S.load_items(chain_files=files, root=root) if items is None else items

    today = [it for it in items if _day_of_ts(it.ts) == day]
    levels = {"R0": 0, "L2": 0, "L1": 0, "Ls": 0}
    for it in today:
        if it.level in levels:
            levels[it.level] += 1

    rules = {}
    for it in today:
        if it.rule_id:
            rules[it.rule_id] = rules.get(it.rule_id, 0) + 1
    rule_rows = sorted(({"rule_id": k, "count": v} for k, v in rules.items()),
                       key=lambda r: (-r["count"], r["rule_id"]))

    carried = [it for it in items if it.state in M.OPEN_STATES
               and (_day_of_ts(it.ts) or "") < day]

    hourly = {}
    for it in today:
        h = str(it.ts)[11:13]
        if not h.isdigit():
            continue
        cur = hourly.get(h)
        if cur is None or M.PRIORITY.get(it.level, 0) > M.PRIORITY.get(cur, 0):
            hourly[h] = it.level
    hourly_rows = [{"hour": h + ":00", "level": hourly[h]} for h in sorted(hourly)]

    return {
        "day": day,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "levels": levels,
        "blocked": levels["L2"],
        "noticed": levels["L1"],
        "breached": levels["R0"],
        "budget": levels["Ls"],
        "total_today": len(today),
        "states": M.counts_by_state(items),
        "unhandled_total": M.unhandled_count(items),
        "console_state": M.console_state(items),
        "carried_over": [{"id": it.id, "level": it.level, "title": it.title,
                          "ts": it.ts, "state": it.state} for it in carried[:50]],
        "carried_over_count": len(carried),
        "rules": rule_rows,
        "hourly": hourly_rows,
        "chain": chain_health(files) if chain is None else chain,
        "ledger": L.summary(root=root, today=day) if led is None else led,
    }


def render_text(rep):
    """纯文本日报（终端/邮件正文用）。"""
    L_ = rep["levels"]
    lines = [
        "值守台日报 · %s" % rep["day"],
        "=" * 34,
        "拦截 %d ｜ 注意 %d ｜ 失守 %d ｜ 额度 %d" % (L_["L2"], L_["L1"], L_["R0"], L_["Ls"]),
        "未处理合计 %d（未读 %d / 已读 %d）" % (
            rep["unhandled_total"], rep["states"]["unread"], rep["states"]["read"]),
        "已处理 %d ｜ 已忽略 %d" % (rep["states"]["done"], rep["states"]["ignored"]),
        "",
        "链完整性：%s（%d 文件 / %d 条 / 断 %d）%s" % (
            rep["chain"]["status"], rep["chain"]["files"], rep["chain"]["records"],
            rep["chain"]["broken"], rep["chain"]["reason"] or ""),
        "值守时长：%s 小时" % round((rep["ledger"].get("watch_seconds") or 0) / 3600.0, 1),
    ]
    if rep["rules"]:
        lines.append("")
        lines.append("规则命中排行：")
        for r in rep["rules"][:8]:
            lines.append("  %-10s %d" % (r["rule_id"], r["count"]))
    if rep["carried_over_count"]:
        lines.append("")
        lines.append("遗留未处理（%d 条，含更早）：" % rep["carried_over_count"])
        for c in rep["carried_over"][:8]:
            lines.append("  [%s] %s · %s" % (c["level"], c["title"], c["ts"]))
    return "\n".join(lines)


def render_markdown(rep):
    L_ = rep["levels"]
    out = ["# 值守台日报 · %s" % rep["day"], "",
           "| 级别 | 今日 |", "|---|---|",
           "| R0 失守 | %d |" % L_["R0"], "| L2 拦截 | %d |" % L_["L2"],
           "| L1 注意 | %d |" % L_["L1"], "| Ls 额度 | %d |" % L_["Ls"], "",
           "- 未处理合计 **%d**（未读 %d / 已读 %d）" % (
               rep["unhandled_total"], rep["states"]["unread"], rep["states"]["read"]),
           "- 已处理 %d ｜ 已忽略 %d" % (rep["states"]["done"], rep["states"]["ignored"]),
           "- 链完整性：**%s**（%d 文件 / %d 条 / 断 %d）" % (
               rep["chain"]["status"], rep["chain"]["files"],
               rep["chain"]["records"], rep["chain"]["broken"]), ""]
    if rep["rules"]:
        out += ["## 规则命中排行", "", "| 规则 | 次数 |", "|---|---|"]
        out += ["| %s | %d |" % (r["rule_id"], r["count"]) for r in rep["rules"][:10]]
        out.append("")
    if rep["carried_over_count"]:
        out += ["## 遗留未处理（%d 条）" % rep["carried_over_count"], "",
                "| 级别 | 标题 | 时间 |", "|---|---|---|"]
        out += ["| %s | %s | %s |" % (c["level"], c["title"], c["ts"])
                for c in rep["carried_over"][:20]]
        out.append("")
    return "\n".join(out)
