# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""观察 sidecar（T3）—— 灯态采样的**唯一**读写与汇总实现。

★ 规格真源：《Antinel·编码前无猜测审核与接口冻结 v1.0》§F8（行形状全冻）
  ＋《Antinel·四项在飞事项施工方案 v1.0》§3.2（`<hub>/console/observe_red.jsonl`）。

## 这一层只做三件事

    record()      把一拍的观察写成一行（**唯一的写入实现**）
    iter_rows()   把原始行读出来（**唯一的读取实现**，坏行不静默）
    rollup()      从原始行复算 M1/M2/M3 的原始量（**唯一的汇总实现**）

「唯一」不是形容词：写入与读取都在这个文件里，别处只许调它。理由是本仓复发
最多的事故族——一个事实两个写法。判据 `_p_sidecar_twice.py` 的 N⑤ 守这一条。

## 三条不许破的边界

① **本模块不生产灯与成因。** `lamp` / `cause` / `badge` 由投影层给出
   （§F2 的 `lamp()` / `cause()` / `badges()`），本模块只登记。
   采集点接线（`inbox_daemon.tick` 调一次 `record()`）**不在本步**：
   §F8 只冻了行的形状，台账 B3 的产出也只列 `sidecar.py`，而
   `inbox_daemon.py` 不在 B 线文件清单里（台账 §1.1 的五个文件）。
   接线要等 `situation.py` 出来（A 线），再走 X 步同一批。

② **`rollup()` 是纯函数**：只吃行，不吃时钟、不吃环境变量、不吃 cwd。
   H-e（同一份原始行两次汇总同一结果）靠的就是这一条，它也是 §F2
   「投影不读时钟、时间由调用方传」的同一条纪律。
   ⇒ 要「某一周」这类窗口，由调用方拿 `rollup()` 的输出自己筛，别让汇总看表。

③ **行形状五字段，一个不多。** `{ts, lamp, cause, badge, info_unread_overdue}`。
   加字段要回改 §F8（那是公开契约），不许在这里顺手加。

## 两个显式限制（写在这里，免得下一个人以为它做到了）

- **没有去重键**：一行＝一次采样。同一拍写两次就算两行。写入方负责不重写
  （理由：加 id 就是加第六个字段，违反边界③；而重试去重是写入方的语义，
  不是采样日志能替它决定的）。
- **回合切分按 `lamp` 变化，不按空档**：进程停摆 8 小时后再红，仍算同一回合。
  这是**故意的**——切分阈值是个口径，本模块不拍。它把 `gap_max_min` 与
  `rows` 一起报出来，让消费方按自己的口径修正。**M1「红次数」因此是上界**，
  不是精确值；这个偏差是显式的、可修正的，而不是藏在汇总里。

## 读取侧只校验形状，不校验枚举

写侧 `record()` 严格校验（`lamp` ∈ `state_registry.LAMPS`、`cause` ∈ 八成因），
读侧 `iter_rows()` 只校验「类型对不对、ts 解不解得开」。
理由：sidecar 是历史证据，而成因表会演进。把枚举校验放进读侧，会让
「注册表加/删一个键」把**历史数据整体变成坏行**——那是把判据绑在会动的锚上。
读侧见到不认得的 `lamp` 时，`rollup()` 单独计 `lamp_unknown`，不并进任何一格。
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import statistics

import inbox_config as CFG
import state_registry as R

#: 文件名（§3.2 定死）。
SIDECAR_NAME = "observe_red.jsonl"

#: 行形状——§F8 全冻。改这里必须同批改 `docs/AUDIT_SCHEMA.md` 之外的公开契约件。
FIELDS = ("ts", "lamp", "cause", "badge", "info_unread_overdue")

#: 汇总里出现的「灯的未知取值」格名（不与四灯混）。
LAMP_UNKNOWN = "lamp_unknown"


# --------------------------------------------------------------- 路径 ----
def sidecar_path(root=None):
    """`<hub>/console/observe_red.jsonl`。

    ★ 目录的唯一定义在 `inbox_config.console_dir()`（它认 `ANTINEL_HUB_DIR`
      沙箱），本函数**不自己拼** `~/.antinel/console`。自己拼的后果实测过：
      设了沙箱的判据会静默读到真机的文件，判据随机器而飘。
    """
    return os.path.join(CFG.console_dir(root), SIDECAR_NAME)


# --------------------------------------------------------------- 写入 ----
def _iso(now=None):
    """此刻的 ISO 8601（**带本机时区偏移**，秒精度）。

    ★ 必须带偏移：不带偏移的 `ts` 在换时区/跨夏令时的机器上无法归属到某一天，
      而 M1（周）与 M2（日）的分桶全靠这个归属。与 `host_shield` 的
      `state_writes.jsonl` 同型（那个文件也是 `datetime.now().astimezone()`）。
    ★ 秒精度：tick 间隔以秒计，毫秒没有信息量；且秒精度让两次汇总更容易比对。
    """
    t = now if now is not None else _dt.datetime.now().astimezone()
    if isinstance(t, (int, float)):
        t = _dt.datetime.fromtimestamp(t).astimezone()
    if not isinstance(t, _dt.datetime):
        raise TypeError("now 只接受 datetime 或秒级时间戳，收到 %r" % (type(t).__name__,))
    if t.tzinfo is None:
        t = t.astimezone()
    return t.isoformat(timespec="seconds")


def _check_lamp(lamp):
    if lamp not in R.LAMPS:
        raise ValueError("lamp 只许 %s 之一，收到 %r" % ("/".join(R.LAMPS), lamp))
    return lamp


def _cause_keys():
    return tuple(e["key"] for e in R.STATES)


def _check_cause(cause):
    keys = _cause_keys()
    if cause not in keys:
        raise ValueError("cause 只许八成因键 %s 之一，收到 %r" % ("/".join(keys), cause))
    return cause


def _check_badge(badge):
    if isinstance(badge, (str, bytes)):
        raise ValueError("badge 是数组，不是字符串（收到 %r）——单个也要包成 [x]" % (badge,))
    keys = _cause_keys()
    out = []
    for k in badge:
        if k not in keys:
            raise ValueError("badge 里有不认得的成因键 %r（合法：%s）"
                             % (k, "/".join(keys)))
        out.append(k)
    return out


def _check_count(v, name):
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("%s 必须是整数，收到 %r" % (name, v))
    if v < 0:
        raise ValueError("%s 不许为负（收到 %d）" % (name, v))
    return v


def record(lamp, cause, badge=(), info_unread_overdue=0, now=None, root=None):
    """写一行观察。返回写入的那个 dict。

    ★ **校验在前、落盘在后**：`lamp` / `cause` / `badge` 不合格 ⇒ 抛 `ValueError`，
      一个字节都不写。写进去一行坏数据，下游三个指标会一起把它当真。
    ★ 落盘用**二进制追加**：文本模式的 `open(..., "a")` 会把 `\n` 按平台换行符
      改写，本仓在 0490 上踩过整文件假 diff。二进制写什么就是什么。
    ★ 写失败**不吞**：`OSError` 原样抛。磁盘满、目录只读、句柄用尽——
      「这一拍没记上」必须让调用方知道（否则账上少一行，没人会发现）。
    """
    row = {
        "ts": _iso(now),
        "lamp": _check_lamp(lamp),
        "cause": _check_cause(cause),
        "badge": _check_badge(badge),
        "info_unread_overdue": _check_count(info_unread_overdue, "info_unread_overdue"),
    }
    p = sidecar_path(root)
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    line = json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
    _append_line(p, line)
    return row


def _append_line(path, line):
    """把一行追加到文件。**二进制**：不换行尾、不加 BOM。

    ★ 抽成函数不是为了好看：文本模式的 `open(..., "a")` 在 Windows 上会把
      `"\\n"` 写成 `"\\r\\n"`，本仓在 0490 上踩过整文件假 diff。
      抽出来，负控才能**换掉同一份实现**去证明这条守得住（`_p_sidecar_twice.py` N⑧）。
    """
    with open(path, "ab") as f:
        f.write(line.encode("utf-8"))


# --------------------------------------------------------------- 读取 ----
def _parse_ts(s):
    """ISO 串 → 带时区的 datetime。解不开返回 None（由调用方记坏行）。"""
    if not isinstance(s, str) or not s.strip():
        return None
    try:
        t = _dt.datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo is not None else t.astimezone()


def _shape_problem(row):
    """只看形状（类型/可解析），不看枚举。合格返回 None，否则返回原因串。"""
    if not isinstance(row, dict):
        return "不是 JSON 对象，是 %s" % type(row).__name__
    missing = [k for k in FIELDS if k not in row]
    if missing:
        return "缺字段 %s" % "、".join(missing)
    if _parse_ts(row.get("ts")) is None:
        return "ts 解不开：%r" % (row.get("ts"),)
    if not isinstance(row.get("lamp"), str):
        return "lamp 不是字符串：%r" % (row.get("lamp"),)
    if not isinstance(row.get("cause"), str):
        return "cause 不是字符串：%r" % (row.get("cause"),)
    if not isinstance(row.get("badge"), list):
        return "badge 不是数组：%r" % (row.get("badge"),)
    if any(not isinstance(x, str) for x in row["badge"]):
        return "badge 里有非字符串：%r" % (row.get("badge"),)
    v = row.get("info_unread_overdue")
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        return "info_unread_overdue 不是非负整数：%r" % (v,)
    return None


def iter_rows(path=None, root=None):
    """读全部原始行。返回 `(rows, bad)`。

        rows = [(lineno, row_dict)]   —— **保持文件顺序**（追加顺序即采样顺序）
        bad  = [{"line": int, "why": str, "raw": str}]  —— 前 80 字原样留着

    ★ 坏行**不跳过、不修补、不补默认值**：进 `bad` 并带行号。
      静默丢弃会让「文件里 300 行读不懂」表现成「这个月没有红」——
      空值与零混同，正是 0.55.0 修 F2 的那条。
    ★ 文件不存在 ⇒ 返回 `([], [])`，不是错误。「还没采过」和「采过但读不出」
      必须分得开：后者由 `OSError` 抛出，前者是空。
    """
    p = path or sidecar_path(root)
    try:
        with open(p, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return [], []
    text = raw.decode("utf-8", "replace")        # 半个汉字也不丢行号
    rows, bad = [], []
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue                              # 空行不是数据，也不是坏行
        try:
            got = json.loads(line)
        except ValueError as e:
            bad.append({"line": i, "why": "JSON 解不开：%s" % e, "raw": line[:80]})
            continue
        why = _shape_problem(got)
        if why:
            bad.append({"line": i, "why": why, "raw": line[:80]})
            continue
        rows.append((i, got))
    return rows, bad


# --------------------------------------------------------------- 汇总 ----
def _day_of(t):
    """行自身偏移下的本地日 `YYYY-MM-DD`。**不换算到本机时区**。"""
    return t.date().isoformat()


def _week_of(t):
    """行自身偏移下的 ISO 周 `YYYY-Www`（周一为一周之始）。"""
    y, w, _ = t.date().isocalendar()
    return "%04d-W%02d" % (y, w)


def _ordered_days(days):
    """日槽的输出顺序：**按日名排序**，与文件追加顺序无关。

    ★ 抽成函数：分组表与顺序无关，排序让它与「这份文件是按什么顺序攒起来的」
      解耦。同一批行换个追加顺序，`days` 仍逐字相同（`_p_sidecar_twice.py` C⑫
      与 N⑩ 守这一条）。
    """
    return [days[k] for k in sorted(days)]


def _take_cause(causes_seen):
    """回合的「主成因」＝**回合结束时**那一行的成因（M3 口径，施工方案 §3.1）。

    ★ 抽成函数：口径是可替换的实现（`_p_sidecar_twice.py` N④ 把它换成
      `causes_seen[0]` 去证明 C⑦ 有分辨力）。内联在循环里就没法被替换，
      也就没法证明这条承重。
    """
    return causes_seen[-1]


def _minutes(a, b):
    """b - a 的分钟数；结果为负返回 None（**算不出 ≠ 很小**）。"""
    d = (b - a).total_seconds() / 60.0
    return None if d < 0 else round(d, 3)


def _median(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return round(float(statistics.median(xs)), 3)


def rollup(rows, bad=None):
    """从 `(lineno, row)` 序列复算 M1/M2/M3 的原始量。**纯函数**。

    参数只吃行；`bad` 只为把「读侧坏了多少行」带进结论（默认 0）。

    返回（键的含义见施工方案 §3.1）：
        source      {rows, bad, nonmonotonic}
        lamps       {lamp: n}          —— 未知取值单独计 `lamp_unknown`
        days        [{day, rows, lamps, red_episodes}]  —— **按 day 排序**
        episodes    [{start, end, day, week, end_week, rows, cause,
                      causes_seen, span_min, gap_max_min, time_reversed}]
        by_cause    {cause: n}         —— 按**回合结束时**的主成因计次（M3）
        weeks       [{week, episodes, causes, span_min_median, span_min_max}]
        durations_min {n, median, max} —— M2（用 span_min，即首末跨度）

    ★ `episodes` **保持文件顺序**：回合是「连续采样」的产物，重排就改了语义。
      `days` / `weeks` 按名字排序：它们的分组与顺序无关，排序让输出与文件顺序
      解耦（同一份行换个追加顺序，分组表仍然逐字相同）。
    ★ `nonmonotonic` 数的是「`ts` 比前一行小」的次数。它是**数据质量指标**，
      不改变任何分桶——发现它不代表修正它，报出来让人看。
    """
    bad = list(bad or [])
    lamps = {}
    days = {}
    nonmono = 0
    prev_ts = None

    episodes = []
    cur = None

    for lineno, r in rows:
        t = _parse_ts(r["ts"])
        lamp = r["lamp"] if isinstance(r["lamp"], str) else LAMP_UNKNOWN
        key = lamp if lamp in R.LAMPS else LAMP_UNKNOWN

        lamps[key] = lamps.get(key, 0) + 1
        if prev_ts is not None and t < prev_ts:
            nonmono += 1
        prev_ts = t

        day = _day_of(t)
        dslot = days.setdefault(day, {"day": day, "rows": 0, "lamps": {}, "red_episodes": 0})
        dslot["rows"] += 1
        dslot["lamps"][key] = dslot["lamps"].get(key, 0) + 1

        if key != "red":
            if cur is not None:
                episodes.append(cur)
                cur = None
            continue

        if cur is None:
            cur = {"start": r["ts"], "end": r["ts"], "_t0": t, "_t1": t,
                   "rows": 1, "causes_seen": [r["cause"]], "_gaps": []}
            # 一个回合只在这个日槽里 +1（下面接着加行不重复计数）
            dslot["red_episodes"] += 1
        else:
            g = _minutes(cur["_t1"], t)
            if g is None:
                cur["time_reversed"] = True
            else:
                cur["_gaps"].append(g)
            cur["end"] = r["ts"]
            cur["_t1"] = t
            cur["rows"] += 1
            if r["cause"] not in cur["causes_seen"]:
                cur["causes_seen"].append(r["cause"])

    if cur is not None:
        episodes.append(cur)

    # 回合收尾：把内部字段折成对外形状
    out_eps = []
    for e in episodes:
        span = _minutes(e["_t0"], e["_t1"])
        out = {
            "start": e["start"], "end": e["end"],
            "day": _day_of(e["_t0"]), "week": _week_of(e["_t0"]),
            "end_week": _week_of(e["_t1"]),
            "rows": e["rows"],
            "cause": _take_cause(e["causes_seen"]),   # ← M3：回合结束时的主成因
            "causes_seen": list(e["causes_seen"]),
            "span_min": span,                       # 首末跨度（上界），负 ⇒ None
            "gap_max_min": (max(e["_gaps"]) if e["_gaps"] else None),
            "time_reversed": bool(e.get("time_reversed")),
        }
        out_eps.append(out)

    by_cause = {}
    weeks = {}
    for e in out_eps:
        by_cause[e["cause"]] = by_cause.get(e["cause"], 0) + 1
        w = weeks.setdefault(e["week"], {"week": e["week"], "episodes": 0,
                                         "causes": {}, "_spans": []})
        w["episodes"] += 1
        w["causes"][e["cause"]] = w["causes"].get(e["cause"], 0) + 1
        if e["span_min"] is not None:
            w["_spans"].append(e["span_min"])

    out_weeks = []
    for k in sorted(weeks):
        w = weeks[k]
        out_weeks.append({
            "week": w["week"], "episodes": w["episodes"], "causes": dict(sorted(w["causes"].items())),
            "span_min_median": _median(w["_spans"]),
            "span_min_max": (round(max(w["_spans"]), 3) if w["_spans"] else None),
        })

    spans = [s for s in (e["span_min"] for e in out_eps) if s is not None]
    return {
        "source": {"rows": len(rows), "bad": len(bad), "nonmonotonic": nonmono},
        "lamps": dict(sorted(lamps.items())),
        "days": _ordered_days(days),
        "episodes": out_eps,
        "by_cause": dict(sorted(by_cause.items())),
        "weeks": out_weeks,
        "durations_min": {
            "n": len(spans),
            "median": _median(spans),
            "max": (round(max(spans), 3) if spans else None),
        },
        "bad": bad,
    }


def rollup_file(path=None, root=None):
    """`iter_rows` ＋ `rollup` 的便捷组合。坏行一并带进结果。"""
    rows, bad = iter_rows(path=path, root=root)
    return rollup(rows, bad=bad)
