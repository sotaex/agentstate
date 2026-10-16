# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""值守台 · 日报（**从链与账本算**）。

★ 判据不许二次实现：日报的每个数字都必须来自 `inbox_store` / `ledger` / `inbox_model`
  的同一批函数；**页面只负责排版，不许自己再加一遍**（J5 守的就是这条）。

★ 诚实纪律（最容易犯的两条）：
  1. **链读不到 ≠ 链是好的**：校验不了必须报 `unknown`，**绝不报 `ok`**。
  2. **没有记录 ≠ 没有发生**：数字为 0 时要能区分"查过了、确实没有"与"没查成"。
"""
from __future__ import annotations

import json
import os
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


#: 文件指纹 -> 该文件链校验计数。
#  ★★ 为什么可以缓存（**严格正确**，不是"副本改新"）：
#    `chain_health` 对每个文件都是**独立**的 —— `prev` 在**每个文件开头重置**，
#    `chain_with()` 只看这一条记录与它的前驱 ⇒ 结果只依赖**该文件自己的内容**。
#    ⇒ 同一 (path, mtime_ns, size) 必然得到同一组计数。
#    链是 append-only ⇒ 追加即 mtime_ns/size 变 ⇒ 该文件缓存自动失效。
#  ★ 不缓存跨文件聚合结果 —— 那是"整个链"的函数，聚合本身很便宜（几十次加法）。
#  ★ 实测：本机 20 文件 / 43149 行，逐条复算 ≈ 5–10s；缓存后一次刷新只重算当天那个。
_CHAIN_CACHE = {}
_CHAIN_CACHE_MAX = 64


def chain_status_label(status):
    """内部状态码 → 用户可读状态；JSON 数据仍保留稳定机器值。"""
    return {"ok": "完整", "broken": "发现问题", "unknown": "未能核验"}.get(
        str(status), "未能核验")


def _chain_check_file(path, ac):
    """校验**一个**链文件，返回计数 dict（按文件指纹缓存）。"""
    try:
        stt = os.stat(path)
        fp = (os.path.normpath(path), stt.st_mtime_ns, stt.st_size)
    except OSError:
        return {"records": 0, "broken": 0, "bad": 1, "unchained": 0, "first_bad": ""}
    hit = _CHAIN_CACHE.get(fp)
    if hit is not None:
        return hit
    records = broken = badjson = unchained = 0
    first_bad = ""
    try:
        f = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return {"records": 0, "broken": 0, "bad": 1, "unchained": 0, "first_bad": ""}
    with f:
        prev = ""
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:                   # noqa: BLE001
                badjson += 1
                continue
            if not isinstance(rec, dict):
                badjson += 1
                continue
            h = rec.get("hash")
            if not h:
                unchained += 1                  # ★ 未链接记录，不是断链
                continue
            records += 1
            rc = ac.chain_with(rec, prev)       # ← 产品原语
            if rc["hash"] != h or rc["prev"] != rec.get("prev"):
                broken += 1
                if not first_bad:
                    first_bad = "%s@%s" % (path, rec.get("ts"))
            prev = h
    out = {"records": records, "broken": broken, "bad": badjson,
           "unchained": unchained, "first_bad": first_bad}
    if len(_CHAIN_CACHE) >= _CHAIN_CACHE_MAX:
        _CHAIN_CACHE.pop(next(iter(_CHAIN_CACHE)), None)
    _CHAIN_CACHE[fp] = out
    return out


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
        r = _chain_check_file(p, ac)
        files += 1
        records += r["records"]
        broken += r["broken"]
        badjson += r["bad"]
        unchained += r["unchained"]
        if not first_bad and r["first_bad"]:
            first_bad = r["first_bad"]

    if records == 0:
        status = "unknown"                      # 一条可校验的都没有 ⇒ 没查成
    else:
        status = "broken" if (broken or badjson) else "ok"
    return {"status": status, "files": files, "records": records,
            "broken": broken, "unchained": unchained, "bad_lines": badjson,
            "first_bad": first_bad, "reason": ""}


_HERE = os.path.dirname(os.path.abspath(__file__))
_RULE_ZH = None          #: `id → description_zh` 缓存（读一次；读不到 ⇒ 空表）
_RULE_TABLE = None       #: 完整规则列表缓存（0.51.0；读不到 ⇒ 空表）
_RULE_LB = None          #: `id → label_zh` 上屏短名缓存（0.51.0；读不到 ⇒ 空表）


def rule_table():
    """`rules/default.json` 的**完整规则列表**（唯一读取实现）。

    ★ 0.51.0（四态问号小窗方案 v1.1 动作二，2026-10-16）：拦截态问号小窗要
      下钻到**规则层**——总数、类别分组、每条中文说明全部从规则表派生，
      `rule_zh_map()` 改由本函数派生（同一份文件只读一次，两条消费面共享
      一份缓存；不出现第二份路径定位逻辑）。
    ★ 返回 list[dict]（每条＝规则表原字段；至少含 id，通常含 category /
      severity / description_zh）。
    ★ 兜底纪律（与 `rule_zh_map` 同源）：读不到 / 解析失败 ⇒ 空表。
      词条层（glossary）拿到空表**自己抛 UnknownTerm** —— 词条定义不许空，
      比静默编一段"暂不可用"诚实；日报排行行则退回规则号，两处受众不同。
    """
    global _RULE_TABLE
    if _RULE_TABLE is not None:
        return _RULE_TABLE
    rows = []
    # 两种布局都能找到（与 `hooks/pre_tool_use.py::_locate` 同思路：
    # 扁平仓 `rules/` 在旁边，技能包 `rules/` 在上一层）。
    for base in (_HERE, os.path.dirname(_HERE)):
        p = os.path.join(base, "rules", "default.json")
        if not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
            rr = d.get("rules") if isinstance(d, dict) else d
            rows = [r for r in (rr or []) if isinstance(r, dict) and r.get("id")]
        except Exception:                                   # noqa: BLE001
            rows = []                      # 读坏 ⇒ 当没有（词条层抛错兜住）
        break
    _RULE_TABLE = rows
    return rows


def rule_zh_map():
    """`rules/default.json` 的规则**人话名**（`id → description_zh`，唯一实现）。

    ★★ 为什么新增它（0.50.4 / Q-04，2026-10-15 品质扫描）：日报页「规则命中
       排行」原先直接把**内部规则号**（`DST-10`）摆给用户 —— 那是工程串，不是
       人话；而 `rules/default.json` 里**每一条都写了 `description_zh`**
       （例：DST-10 ＝「从命令行写入 NTFS 备用数据流…」），只差读出来。
    ★ 兜底纪律（先删谎，不补谎）：读不到 / 解析失败 / 该 id 没有中文描述
       ⇒ 返回空串，页面**退回显示规则号**，绝不拿 `name`（英文）充数、更不编造。
    ★ 只读一次并缓存：日报每渲染一次就扫 37 条规则不划算，且规则文件在
       会话内不变。
    ★ 0.51.0：本函数**改由 `rule_table()` 派生** —— 文件读取只有一份实现，
       缓存也只有一份（`_RULE_TABLE`），本函数只剩"id→中文"这一层投影。
    """
    global _RULE_ZH
    if _RULE_ZH is not None:
        return _RULE_ZH
    _RULE_ZH = {r["id"]: r["description_zh"]
                for r in rule_table() if r.get("description_zh")}
    return _RULE_ZH


def rule_label_map():
    """`rules/default.json` 的规则**上屏短名**（`id → label_zh`，唯一实现）。

    ★★ 为什么新增（0.51.0，2026-10-16 日报页品质审查，创始人拍板点 4）：
       Q-04 把 description_zh 搬上排行主显示位是**受众错配** —— 那是写给
       审计方看的全文（实测 23/37 条带英文词或超 30 字），上屏就挤成三四行。
       短名是**新造的上屏字段**：≤14 字、无英文（SSH/MCP 除外）、无规则号
       自引用，由 INV-4 强制存在。全文 description_zh 不删（审计受众不动），
       退到 hover title；编号淡显上屏（与问号全表 .rid 同一视觉语言）。
    ★ 兜底纪律同族：读不到该字段 ⇒ 空串，页面按 label → zh → 规则号 退链，
       绝不编造。
    """
    global _RULE_LB
    if _RULE_LB is not None:
        return _RULE_LB
    _RULE_LB = {r["id"]: r["label_zh"]
                for r in rule_table() if r.get("label_zh")}
    return _RULE_LB


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
    # ★ 0.50.4（Q-04）：带上规则**人话名**（`description_zh`）；取不到为空串，
    #   页面据此退回规则号 —— 报告侧只提供数据，显示取舍由页面唯一实现决定。
    # ★★ 0.51.0（品质审查拍板点 4）：再带上**上屏短名**（`label_zh`）——
    #   description_zh 是审计受众的全文（实测最长 60 字），上屏挤成三四行；
    #   短名 ≤14 字由 INV-4 强制。页面显示取舍：label → zh → 规则号。
    _zh = rule_zh_map()
    _lb = rule_label_map()
    rule_rows = sorted(({"rule_id": k, "count": v, "zh": _zh.get(k, ""),
                         "label": _lb.get(k, "")}
                        for k, v in rules.items()),
                       key=lambda r: (-r["count"], r["rule_id"]))

    # ---- 窗口（默认 24 小时）内的数字：顶部条与"每个数字可点钻取"共用 ----
    hours = M.WINDOW_HOURS
    win = [it for it in items if M.within_hours(it.ts, hours=hours)]
    win_levels = M.window_levels(items, hours=hours)

    # ★ 每个数字都带**钻取键**（页面据此生成链接，判定不写在页面里）
    drill = [
        {"key": "L2", "label": M.state_short("L2"), "count": win_levels["L2"], "filt": "lv:L2"},
        {"key": "L1", "label": M.state_short("L1"), "count": win_levels["L1"], "filt": "lv:L1"},
        {"key": "R0", "label": M.state_short("R0"), "count": win_levels["R0"], "filt": "lv:R0"},
    ]
    if win_levels["Ls"]:
        drill.append({"key": "Ls", "label": M.state_short("Ls"), "count": win_levels["Ls"],
                      "filt": "lv:Ls"})

    try:
        import host_shield as _hs
        posture = _hs.guard_posture(os.path.dirname(os.path.abspath(__file__)))
    except Exception as e:                      # noqa: BLE001
        posture = {"state": "unknown", "label": "查不到", "why": "读不到监理状态：%r" % (e,),
                   "evidence": {}, "can_fix": False, "fix": None, "fix_hint": ""}

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
        "console_state": M.console_state(items),
        # ---- 0.35.3 新增：窗口口径（创始人拍板"24 小时"）----
        "window_hours": hours,
        "window_levels": win_levels,
        "window_total": len(win),
        "buckets": M.counts_by_bucket(items),
        # ★ 0.35.3：「要处理」显示**件事数**（按事由归并），不是记录条数 ——
        #   创始人 2026-10-06「37 条太多，很多不该列进来」。
        "action_groups": M.count_groups(
            [it for it in items if M.bucket_of(it) == M.BUCKET_ACTION]),
        "drill": drill,
        "posture": posture,
        # ★ 哨兵被反复拉起的次数（本机实测 24h 内 6 次）——
        #   它**不是后果**（已恢复），所以不进"要处理"；但"门闸一直在死"必须看得见，
        #   否则就是"报告了不等于没事"的反面：**没事不等于没事**。
        "revived_window": sum(1 for it in win if it.kind == "host_shield_revived"),
        "rules": rule_rows,
        "chain": chain_health(files) if chain is None else chain,
        "ledger": L.summary(root=root, today=day) if led is None else led,
    }


def render_text(rep):
    """纯文本日报（终端/邮件正文用）。"""
    L_ = rep["levels"]
    lines = [
        "Antinel 监理日报 · %s" % rep["day"],
        "=" * 34,
        "%s %d ｜ %s %d ｜ %s %d ｜ %s %d" % (
            M.state_short("L2"), L_["L2"], M.state_short("L1"), L_["L1"],
            M.state_short("R0"), L_["R0"], M.state_short("Ls"), L_["Ls"]),
        "最近 %d 小时：拦截 %d ｜ 注意 %d ｜ 失守 %d（监理被拉起 %d 次）" % (
            rep.get("window_hours", 24), rep.get("window_levels", {}).get("L2", 0),
            rep.get("window_levels", {}).get("L1", 0), rep.get("window_levels", {}).get("R0", 0),
            rep.get("revived_window", 0)),
        "要处理 %d 件事（共 %d 条）｜ 看一眼 %d ｜ 归档 %d" % (
            rep.get("action_groups", rep.get("buckets", {}).get("action", 0)),
            rep.get("buckets", {}).get("action", 0),
            rep.get("buckets", {}).get("info", 0),
            rep.get("buckets", {}).get("archive", 0)),
        "已处理 %d ｜ 已忽略 %d" % (rep["states"]["done"], rep["states"]["ignored"]),
        "",
        "链校验：%s（检查 %d 个文件、%d 条链记录；断链 %d、坏行 %d、未链接 %d 条）%s" % (
            chain_status_label(rep["chain"]["status"]), rep["chain"]["files"],
            rep["chain"]["records"], rep["chain"]["broken"],
            rep["chain"].get("bad_lines", 0), rep["chain"].get("unchained", 0),
            rep["chain"]["reason"] or ""),
    ]
    if rep["rules"]:
        lines.append("")
        lines.append("规则命中排行：")
        for r in rep["rules"][:8]:
            lines.append("  %-10s %d" % (r["rule_id"], r["count"]))
    return "\n".join(lines)


def render_markdown(rep):
    L_ = rep["levels"]
    out = ["# Antinel 监理日报 · %s" % rep["day"], "",
           "| 级别 | 今日 |", "|---|---|",
           "| R0 %s | %d |" % (M.state_short("R0"), L_["R0"]),
           "| L2 %s | %d |" % (M.state_short("L2"), L_["L2"]),
           "| L1 %s | %d |" % (M.state_short("L1"), L_["L1"]),
           "| Ls %s | %d |" % (M.state_short("Ls"), L_["Ls"]), "",
           "- 最近 **%d** 小时：拦截 %d ｜ 注意 %d ｜ 失守 %d（监理被拉起 %d 次）" % (
               rep.get("window_hours", 24), rep.get("window_levels", {}).get("L2", 0),
               rep.get("window_levels", {}).get("L1", 0),
               rep.get("window_levels", {}).get("R0", 0), rep.get("revived_window", 0)),
           "- 要处理 **%d 件事**（%d 条记录）｜ 看一眼 %d 条 ｜ 归档 %d 条" % (
               rep.get("action_groups", 0),
               rep.get("buckets", {}).get("action", 0),
               rep.get("buckets", {}).get("info", 0),
               rep.get("buckets", {}).get("archive", 0)),
           "- 已处理 %d ｜ 已忽略 %d" % (rep["states"]["done"], rep["states"]["ignored"]),
           "- 链校验：**%s**（检查 %d 个文件、%d 条链记录；断链 %d、坏行 %d、未链接 %d 条）" % (
               chain_status_label(rep["chain"]["status"]), rep["chain"]["files"],
               rep["chain"]["records"], rep["chain"]["broken"],
               rep["chain"].get("bad_lines", 0), rep["chain"].get("unchained", 0)), ""]
    if rep["rules"]:
        out += ["## 规则命中排行", "", "| 规则 | 次数 |", "|---|---|"]
        out += ["| %s | %d |" % (r["rule_id"], r["count"]) for r in rep["rules"][:10]]
        out.append("")
    return "\n".join(out)
