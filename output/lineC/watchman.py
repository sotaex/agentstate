#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""巡检 Agent · 档 1 原型（只读，零模型）。

问的是「和过去比，什么变了」，不是「这条危不危险」。
危险是判断，归 rules/default.json；变化是事实，归这里。

三条纪律：
  1. 每条线索必须有 evidence（(day, lineno)），不许空 —— 没回指的线索是「模型说的」；
  2. 每条线索只有一个 kind —— 混装会让「有几条线索」失去意义；
  3. 输出里不出现「危险」「可疑」「违规」—— 只说「变了」「首次出现」「从未同时出现过」。

用法：
    python output/lineC/watchman.py
    python output/lineC/watchman.py --root .psl/audit --window 14 --recent 3
"""

from __future__ import annotations

import argparse
import collections
import glob
import os
import re
import statistics
import sys
from dataclasses import dataclass, field
from datetime import datetime

# ts 归一唯一实现：本文件不许再写一遍解析（入口唯一性，见 tsnorm 模块头）。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tsnorm  # noqa: E402
from typing import Any, Dict, Iterator, List, Tuple

_URL_HOST = re.compile(r"https?://([^/\s:'\"]+)")
_DAY_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl$")


@dataclass(frozen=True)
class Clue:
    """一条线索。evidence 不许为空。

    items 是「这条线索涉及的全部名字」。subject 会截断成一句话（注意力预算），
    但截断掉的那些**必须**能从这里取回 —— 否则「等 9 个」就是个死路：
    用户知道有 9 个，却看不到第 7 个是什么。负控撞出来的。
    """

    kind: str
    day: str
    subject: str
    evidence: Tuple[Tuple[str, int], ...]
    note: str = ""
    items: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError(f"线索缺 evidence（{self.kind} / {self.subject}）")


# --------------------------------------------------------------------------- 读取层


def day_files(root: str) -> List[str]:
    """只取 YYYY-MM-DD.jsonl。lock_events.jsonl 字段完全不同，混进来会污染分母。"""
    out: List[Tuple[str, str]] = []
    for p in glob.glob(os.path.join(root, "*.jsonl")):
        m = _DAY_FILE.match(os.path.basename(p))
        if m:
            out.append((m.group(1), p))
    return [p for _, p in sorted(out)]


def iter_records(root: str) -> Iterator[Tuple[str, int, Dict[str, Any]]]:
    """(day, lineno, rec)。lineno 从 1 起，与文件行号一致，供回指使用。"""
    for path in day_files(root):
        day = _DAY_FILE.match(os.path.basename(path)).group(1)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = _loads(line)
                except Exception:
                    yield day, i, {"__unparsed__": True}
                    continue
                if isinstance(rec, dict):
                    yield day, i, rec
                else:
                    yield day, i, {"__unparsed__": True}


def _loads(line: str) -> Any:
    import json

    return json.loads(line)


RULES_PATH = os.path.join("rules", "default.json")
_ALIAS: Dict[str, str] | None = None
_CUR_IDS: set = set()


def load_rule_ids(path: str = RULES_PATH) -> Tuple[Dict[str, str], set]:
    """从规则库生成 `legacy_id -> id` 映射。**映射表不许手写**（手写必漂）。

    0.63.0 把规则号从 `PREFIX-NN` 改成 `AN-NNN`，历史账本留的是旧号。
    实测：37 条规则**全部**带 `legacy_id`，所以映射能全自动生成。
    """
    import json

    if not os.path.isfile(path):
        return {}, set()
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    rules = data.get("rules", [])
    cur = {r["id"] for r in rules if isinstance(r, dict) and r.get("id")}
    alias = {
        r["legacy_id"]: r["id"]
        for r in rules
        if isinstance(r, dict) and r.get("legacy_id") and r.get("id")
    }
    return alias, cur


def _ensure_alias() -> None:
    global _ALIAS, _CUR_IDS
    if _ALIAS is None:
        _ALIAS, _CUR_IDS = load_rule_ids()


def _rules_raw(rec: Dict[str, Any]) -> List[str]:
    """账本里写的原样 id —— 只在口径统计里用，业务逻辑一律走 `_rules_of`。"""
    raw = rec.get("rules_hit") or []
    out: List[str] = []
    if isinstance(raw, list):
        for it in raw:
            if isinstance(it, str):
                out.append(it)
            elif isinstance(it, dict):
                rid = it.get("id") or it.get("rule_id") or it.get("legacy_id")
                if isinstance(rid, str):
                    out.append(rid)
    return out


def _rules_of(rec: Dict[str, Any]) -> List[str]:
    """**唯一的规则 id 读取点**：旧号在这里归一成当前号。

    归一必须发生在读取层，不能发生在每个统计函数里 —— 否则迟早有一处忘掉，
    而忘掉的那一处会把同一条规则数成两条，且它不会报错，只会给出一个错的分母。

    映射不到的 id **原样保留**，不许丢：`OUT-01`／`GOV-01` 这类不是规则号，
    丢掉它们等于把「非规则号混进 rules_hit」这件事从账本里抹掉。
    """
    _ensure_alias()
    assert _ALIAS is not None
    return [_ALIAS.get(x, x) for x in _rules_raw(rec)]


def _cmd_head(rec: Dict[str, Any]) -> str | None:
    inp = rec.get("input")
    if not isinstance(inp, dict):
        return None
    cmd = inp.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        return None
    tok = cmd.strip().split()[0].strip("\"'").rstrip(";,")
    if not tok or tok.startswith("-") or tok.startswith("$"):
        return None
    # 变量赋值不是命令。实测首版把 `out=/tmp/x;`、`D=$(python`、`$ts` 全当成了命令，
    # 报出来的「首次出现」一半是赋值语句 —— 噪声比线索多。
    if "=" in tok:
        return None
    return tok


def _url_hosts(rec: Dict[str, Any]) -> List[str]:
    inp = rec.get("input")
    if not isinstance(inp, dict):
        return []
    blob = " ".join(str(v) for v in inp.values() if isinstance(v, str))
    out: List[str] = []
    for h in _URL_HOST.findall(blob):
        h = h.lower()
        # 域名必须带点；`https://$h` 这类变量占位不是域名（实测会混进 9 个里 1 个）
        if "." not in h or h.startswith("$"):
            continue
        out.append(h)
    return out


def _path_prefix(rec: Dict[str, Any]) -> str | None:
    inp = rec.get("input")
    if not isinstance(inp, dict):
        return None
    fp = inp.get("file_path")
    if not isinstance(fp, str) or not fp.strip():
        return None
    parts = re.split(r"[\\/]+", fp.strip())
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return None
    return "/".join(parts[:2])


# --------------------------------------------------------------------------- 检测器


def _tod(rec: Dict[str, Any]) -> str | None:
    """取 ts 的钟点部分（HH:MM:SS）。薄委托到 tsnorm，**不在这里再实现一遍**。"""
    return tsnorm.tod(rec)


def detect_absent(
    per_type: Dict[str, collections.Counter],
    today: str,
    cutoff: str | None,
    today_lines: int,
    days_back: int = 7,
    min_days: int = 5,
    min_each: int = 3,
) -> List[Clue]:
    """D-0：**昨天还在，今天一条都没有**。

    这条比「基线偏离」锋利，因为它问的不是「今天比平常少」，
    而是「这个东西昨天还在，今天一条都没有」——**失败大多是静默的**：

        post_tool_use 钩子挂了   -> pre_tool_use 照常，post_tool_use 整天为 0
        某条规则被静默关掉       -> 该规则命中数从每天 N 降到 0
        钩子超时没记账           -> 条数正常，但某个 type 整个消失

    只报「过去 days_back 天里 >= min_days 天出现过、且中位数 >= min_each」的键，
    否则每个只出现过一两次的冷门 type 每天都会「消失」一次 —— 那是噪声，不是线索。

    ★ 必须用**同期口径**：一个只在下午出现的 type，早上九点看必然是 0。
    不截 cutoff，这条检测器每天早上都会集体误报。
    """
    days = sorted(per_type)
    if today not in per_type:
        return []
    idx = days.index(today)
    prior = days[max(0, idx - days_back) : idx]
    if len(prior) < min_days:
        return []

    scope = f"截至 {cutoff[:5]}" if cutoff else "全天"
    keys: set = set()
    for d in prior:
        keys |= set(per_type[d])
    clues: List[Clue] = []
    for k in sorted(x for x in keys if isinstance(x, str)):
        vals = [per_type[d].get(k, 0) for d in prior]
        present = sum(1 for v in vals if v > 0)
        if present < min_days:
            continue
        med = statistics.median(vals)
        if med < min_each:
            continue
        if per_type[today].get(k, 0) != 0:
            continue
        clues.append(
            Clue(
                kind="absent",
                day=today,
                subject=(
                    f"{today} {scope} 没有一条 {k}（前 {len(prior)} 天有 {present} 天出现，"
                    f"中位数 {med:g} 条）"
                ),
                # 「没有记录」的回指只能是「我读到了这里」——读到文件末尾，零条。
                # 假装能指到某一行是造假；指向末行是诚实的边界。
                evidence=((today, today_lines),),
                note=f"窗口 {len(prior)} 天｜出现 >= {min_days} 天｜中位数 >= {min_each}｜口径={scope}",
            )
        )
    return clues


def detect_baseline(
    daily: Dict[str, int],
    window: int = 14,
    k: float = 3.0,
    min_median: int = 10,
    recent: int = 1,
    cutoff: str | None = None,
) -> List[Clue]:
    """D-1：某天的动作量，相对过去 N 天常态偏了多少。

    用中位数与 MAD，不用均值 —— 这台机器有闸门日（几千条）与休息日（0 条），
    均值会被离群日拖走，算出来的「常态」不是常态。

    只报最后 `recent` 天的偏离：主动报告说的是「**今天**值得看」，
    把 10 天前的偏离翻出来，等于把历史当新闻。

    ★ `daily` 必须是**同期口径**（每一天都截到 `cutoff` 这个钟点），
    不是全天口径。这条不是洁癖，是实跑撞出来的：

        早上九点送达报告时，全天口径会报「今天 640 条，前 8 天中位数 1940，
        偏离 0.3 倍」——**纯误报**：不是今天少了，是今天还没过完。

    ⇒ **送达时机决定基线口径，这两件事是一件事。** 报告越早送，越必须同期比；
    午夜送达才可以用全天口径。cutoff 为 None 时退回全天口径，并在 note 里写明。
    """
    days = sorted(daily)
    tail = set(days[-recent:]) if recent > 0 else set(days)
    # 口径必须写进每一句话：同一个「1940」在同期口径和全天口径下是两个数，
    # 读的人不知道是哪个，就会自己脑补一个（F40 的温床）。
    scope = f"截至 {cutoff[:5]}" if cutoff else "全天"
    clues: List[Clue] = []
    for idx, d in enumerate(days):
        if d not in tail:
            continue
        prior = [daily[x] for x in days[max(0, idx - window) : idx]]
        if len(prior) < max(5, window // 2):
            continue
        med = statistics.median(prior)
        if med < min_median:
            continue
        mad = statistics.median([abs(x - med) for x in prior])
        scale = mad * 1.4826 if mad > 0 else 0.0
        cur = daily[d]
        if scale > 0:
            z = abs(cur - med) / scale
            if z <= k:
                continue
            ratio = (cur / med) if med else float("inf")
            clues.append(
                Clue(
                    kind="baseline",
                    day=d,
                    subject=(
                        f"{d} pre_tool_use {cur} 条（{scope}），"
                        f"前 {len(prior)} 天同期中位数 {med:g}，偏离 {z:.1f}×MAD（{ratio:.1f} 倍）"
                    ),
                    evidence=((d, 1),),
                    note=f"MAD={mad:g}｜口径={scope}",
                )
            )
        else:
            # 前 N 天完全一样（MAD=0）⇒ 任何变化都值得看一眼，但要说清是这种情况
            if cur != med and abs(cur - med) >= min_median:
                clues.append(
                    Clue(
                        kind="baseline",
                        day=d,
                        subject=f"{d} pre_tool_use {cur} 条（{scope}），前 {len(prior)} 天同期全部为 {med:g}",
                        evidence=((d, 1),),
                        note=f"MAD=0（前期完全平稳），按绝对差判｜口径={scope}",
                    )
                )
    return clues


@dataclass
class ItemStats:
    """「出现过什么」的**唯一**统计结果。

    first_seen / repeat 两个检测器都从这里取数 —— 一处实现，两套问句。
    各写一遍就会出现「同一个新命令在一处算首次、在另一处算重复」。
    """

    first_day: Dict[str, str]
    first_ev: Dict[str, Tuple[str, int]]
    per_day: Dict[str, collections.Counter]
    counts: Dict[str, int]


def _item_stats(recs: List[Tuple[str, int, Dict[str, Any]]]) -> ItemStats:
    first_day: Dict[str, str] = {}
    first_ev: Dict[str, Tuple[str, int]] = {}
    per_day: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    counts = {"cmd": 0, "host": 0, "path": 0}

    for day, lineno, rec in recs:
        if rec.get("__unparsed__"):
            continue
        items: List[Tuple[str, str]] = []
        h = _cmd_head(rec)
        if h:
            items.append(("cmd", h))
        for host in _url_hosts(rec):
            items.append(("host", host))
        p = _path_prefix(rec)
        if p:
            items.append(("path", p))

        for kind, val in items:
            key = f"{kind}:{val}"
            per_day[key][day] += 1
            if key not in first_day:
                first_day[key] = day
                first_ev[key] = (day, lineno)
                counts[kind] += 1
    return ItemStats(first_day=first_day, first_ev=first_ev, per_day=per_day, counts=counts)


def detect_repeat(
    stats: ItemStats,
    today: str,
    min_count: int = 3,
) -> Tuple[List[Clue], set]:
    """D-2b：**第一次见，但今天已经重复 ≥3 次**。

    为什么这条要单独报（2026-10-31 深挖出来的）：

        「首次出现」单独看，噪声比线索多 —— 一次可能是手滑、是笔误、是临时脚本。
        **第二次才算数**：一个今天才第一次出现、今天已经用了 3 次以上的东西，
        不是手滑，是「形成了新习惯」。后者才是值得人看一眼的变化。

    返回 (clues, 已占用的 key)。被本检测器报过的 key 必须从 first_seen 里剔除，
    否则同一件事占两条注意力预算 —— 而上限只有 5 条。
    """
    label = {"cmd": "命令", "host": "域名", "path": "目录"}
    by_kind: Dict[str, List[Tuple[str, int]]] = collections.defaultdict(list)
    used: set = set()
    for key, fd in stats.first_day.items():
        if fd != today:
            continue
        n = stats.per_day[key][today]
        if n < min_count:
            continue
        kind, val = key.split(":", 1)
        by_kind[kind].append((val, n))
        used.add(key)

    clues: List[Clue] = []
    for kind, pairs in sorted(by_kind.items()):
        pairs.sort(key=lambda x: -x[1])
        names = "、".join(f"{v}({n} 次)" for v, n in pairs[:6])
        more = f" 等 {len(pairs)} 个" if len(pairs) > 6 else ""
        ev = tuple(stats.first_ev[f"{kind}:{v}"] for v, _ in pairs[:5])
        clues.append(
            Clue(
                kind="repeat",
                day=today,
                subject=f"{today} 今天才第一次出现的{label[kind]}，已经重复 {min_count} 次以上：{names}{more}",
                evidence=ev,
                note=f"门槛：当天首次出现且当天 >= {min_count} 次",
                items=tuple(v for v, _ in pairs),
            )
        )
    return clues, used


def detect_first_seen(
    stats: ItemStats,
    recent: int = 3,
    exclude: set | None = None,
) -> Tuple[List[Clue], Dict[str, int]]:
    """D-2：什么东西在全部历史里第一次出现。

    只报最后 recent 天 —— 33 天窗口下，头几天必然大量「首次出现」，
    报出来是噪声，不是线索。窗口必须写进 note。

    `exclude` 是 repeat 已经报过的 key：**同一件事不占两份注意力预算**。
    """
    exclude = exclude or set()
    days = sorted({d for k, d in stats.first_day.items() if k not in exclude})
    tail = set(days[-recent:]) if recent > 0 else set(days)
    label = {"cmd": "命令", "host": "域名", "path": "目录"}

    per_day: Dict[str, List[Tuple[str, str, Tuple[str, int]]]] = collections.defaultdict(list)
    for key, fd in stats.first_day.items():
        if fd not in tail or key in exclude:
            continue
        kind, val = key.split(":", 1)
        per_day[fd].append((kind, val, stats.first_ev[key]))

    clues: List[Clue] = []
    for d in sorted(per_day):
        # 同一天同一种类合并成一条线索；**必须写出具体是什么**，
        # 只报「8 个」等于没说 —— 用户要的是名字，不是计数。
        by_kind: Dict[str, List[Tuple[str, Tuple[str, int]]]] = collections.defaultdict(list)
        for kind, val, ev in per_day[d]:
            by_kind[kind].append((val, ev))
        for kind, pairs in sorted(by_kind.items()):
            names = [v for v, _ in pairs]
            shown_n = 8
            shown = "、".join(names[:shown_n])
            more = (
                f" 等 {len(names)} 个（其余 {len(names) - shown_n} 个见明细）"
                if len(names) > shown_n
                else ""
            )
            clues.append(
                Clue(
                    kind="first_seen",
                    day=d,
                    subject=f"{d} 首次出现{label[kind]}：{shown}{more}",
                    evidence=tuple(ev for _, ev in pairs[:5]),
                    note=f"窗口=全期，只报最后 {recent} 天",
                    items=tuple(names),
                )
            )
    return clues, stats.counts


def rule_pair_index(
    recs: List[Tuple[str, int, Dict[str, Any]]], gap_min: float = 5.0
) -> Tuple[Dict[Tuple[str, str], collections.Counter], Dict[Tuple[str, str], Tuple[str, int]], collections.Counter, int]:
    """配对索引：`{(A,B): Counter(day -> 次数)}`。

    抽成公开函数是为了**负控和检测器共用同一套配对逻辑** ——
    负控自己再实现一遍配对，就会在检测器改窗口、改门槛时静默失配，
    于是「负控通过」变成一个没有意义的绿灯。
    """
    solo: collections.Counter = collections.Counter()
    per_sess: Dict[str, List[Tuple[Any, str, int, str]]] = collections.defaultdict(list)

    for day, lineno, rec in recs:
        if rec.get("__unparsed__"):
            continue
        rs = _rules_of(rec)
        if not rs:
            continue
        solo.update(rs)
        sid = rec.get("session")
        dt = tsnorm.parse_ts(rec.get("ts"))
        if not isinstance(sid, str) or dt is None:
            continue
        for r in rs:
            per_sess[sid].append((dt, day, lineno, r))

    pair_days: Dict[Tuple[str, str], collections.Counter] = collections.defaultdict(
        collections.Counter
    )
    pair_ev: Dict[Tuple[str, str], Tuple[str, int]] = {}
    for _sid, seq in per_sess.items():
        seq.sort(key=lambda x: x[0])
        for i, (t0, _d0, _l0, a) in enumerate(seq):
            for j in range(i + 1, len(seq)):
                t1, d1, l1, bb = seq[j]
                if (t1 - t0).total_seconds() / 60.0 > gap_min:
                    break
                if a == bb:
                    continue
                key = (a, bb)
                pair_days[key][d1] += 1
                pair_ev.setdefault(key, (d1, l1))
    return pair_days, pair_ev, solo, len(per_sess)


def detect_rule_pairs(
    recs: List[Tuple[str, int, Dict[str, Any]]],
    recent: int = 1,
    gap_min: float = 5.0,
    min_each: int = 3,
    max_today: int = 3,
) -> Tuple[List[Clue], Dict[str, Any]]:
    """D-3：同一会话里，规则 A 命中之后 `gap_min` 分钟内又命中 B（A≠B）。

    **为什么换形态**（2026-10-31 实测）：旧形态是「两条规则在同一条记录里同时命中」，
    而这份账本里 `rules_hit` 的长度分布是 `{1: 1396}`、最大 1 ——
    **永远不可能触发**。旧报告把它写成「不可判定」，那是自我安慰：
    「不可判定」暗示换个条件还能判，「死了」才是事实。所以旧实现整段删除，
    不留两套（一套必然漂）。

    新形态是可判定的：同一 `session` 内按时间排序，相邻两条规则命中间隔 <= gap_min。

    `min_each` 门槛不能省：两条各只出现过一次，先后出现一次是必然的，不是线索。
    """
    pair_days, pair_ev, solo, n_sess = rule_pair_index(recs, gap_min)
    days = sorted({d for per in pair_days.values() for d in per})
    if not days:
        days = sorted({d for _, d, _, _ in recs})
    tail = set(days[-recent:]) if recent > 0 else set(days)

    clues: List[Clue] = []
    new_pairs = 0
    for (a, bb), per in sorted(
        pair_days.items(), key=lambda kv: -sum(kv[1].values())
    ):
        if solo[a] < min_each or solo[bb] < min_each:
            continue
        # 「罕见」的判据是**这个组合以前没出现过**，不是「两条规则各自很罕见」。
        # 实测教训：只按 min_each 过滤，10-30 一天报 30 条 —— 因为 AN-014 单独命中
        # 406 次，它跟谁在 5 分钟内凑一起都不稀奇。**门槛选错，检测器就变成噪声源。**
        prior = sum(v for dd, v in per.items() if dd not in tail)
        if prior:
            continue
        new_pairs += 1
        d, ln = pair_ev[(a, bb)]
        n = per[d]
        # 上界同样重要：一天出现 21 次的组合不是「罕见」，是**新常态**。
        # 新常态归 baseline 管，不归这里。没有上界，本检测器就变成噪声源
        # （实测：只设下界时 10-30 一天报 30 条，其中最高的一条 21 次）。
        if n > max_today:
            continue
        clues.append(
            Clue(
                kind="rule_pair",
                day=d,
                subject=(
                    f"{d} 首次出现组合：同一会话内 `{a}` 之后 {gap_min:g} 分钟内又命中 `{bb}`"
                    f"（当天 {n} 次）"
                ),
                evidence=((d, ln),),
                note=f"此前从未同时出现过｜各自单独命中 {solo[a]}/{solo[bb]} 次",
                items=(a, bb),
            )
        )
    stats = {
        "rules": len(solo),
        "pairs": len(pair_days),
        "new_pairs": new_pairs,
        "eligible_pairs": sum(
            1 for (x, y) in pair_days if solo[x] >= min_each and solo[y] >= min_each
        ),
        "min_each": min_each,
        "max_today": max_today,
        "gap_min": gap_min,
        "sessions": n_sess,
        "status": "ok" if n_sess else "undecidable",
    }
    return clues, stats


def detect_gap(
    recs: List[Tuple[str, int, Dict[str, Any]]],
    threshold_min: float = 30.0,
    recent: int = 3,
) -> List[Clue]:
    """Q3：哪段时间是空的 —— 同一天内两条记录间隔超过阈值。

    与 B-1「缺日」分工：B-1 是**跨天**（哪天整个日文件不存在），
    这里是**日内**（那天中间断了两小时）。不同粒度，不重叠。
    """
    per_day: Dict[str, List[Tuple[datetime, int]]] = collections.defaultdict(list)
    for day, lineno, rec in recs:
        if rec.get("__unparsed__"):
            continue
        ts = rec.get("ts")
        if not isinstance(ts, str):
            continue
        try:
            dt = datetime.fromisoformat(ts)
        except Exception:
            continue
        # 账本里 ts 有的带 +08:00、有的不带，混在一起 sorted() 会抛
        # TypeError: can't compare offset-naive and offset-aware。
        # 全部按本地墙钟处理（这台机器上都是 +08:00），去掉时区再比。
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        per_day[day].append((dt, lineno))

    days = sorted(per_day)
    tail = set(days[-recent:]) if recent > 0 else set(days)
    clues: List[Clue] = []
    for d in sorted(tail):
        seq = sorted(per_day[d])
        for (t0, ln0), (t1, ln1) in zip(seq, seq[1:]):
            gap_min = (t1 - t0).total_seconds() / 60.0
            if gap_min < threshold_min:
                continue
            h = int(gap_min // 60)
            m = int(gap_min % 60)
            span = f"{h} 小时 {m} 分" if h else f"{m} 分"
            clues.append(
                Clue(
                    kind="gap",
                    day=d,
                    subject=f"{d} {t0.strftime('%H:%M')}–{t1.strftime('%H:%M')} 之间有 {span}没有记录",
                    evidence=((d, ln0), (d, ln1)),
                    note=f"阈值 {threshold_min:g} 分钟",
                )
            )
    return clues


def rule_id_census(root: str) -> Dict[str, Any]:
    """口径统计：账本里的 id 与规则库对不对得上。

    这里必须同时看**原样**与**归一后**两套数，因为两套数回答两个不同的问题：
      · 原样 id 数 → 账本里到底写了多少种字符串（0.63.0 之前/之后混着写）；
      · 归一后 id 数 → 实际涉及多少条规则（**这才是分母**）。

    `non_rule` 是**非规则号**（映射不到、也不在当前规则库里）——
    `OUT-01`／`GOV-01` 就属这类。按铁律 46，处置/治理编号**永不发号**，
    所以它们出现在 `rules_hit` 里是**记账缺陷**，不是「已废弃规则」。
    本函数只负责把它们**报出来**，不替产品定性。
    """
    _ensure_alias()
    raw_ids: collections.Counter = collections.Counter()
    for _, _, rec in iter_records(root):
        if rec.get("__unparsed__"):
            continue
        raw_ids.update(_rules_raw(rec))

    norm_ids = {(_ALIAS or {}).get(k, k) for k in raw_ids}
    non_rule = sorted(k for k in raw_ids if _CUR_IDS and k not in _CUR_IDS and k not in (_ALIAS or {}))
    legacy_mapped = sorted(k for k in raw_ids if k in (_ALIAS or {}))
    touched = norm_ids & _CUR_IDS
    return {
        "n_ids_raw": len(raw_ids),
        "n_ids_norm": len(norm_ids),
        "n_rules_touched": len(touched),
        "n_never_hit": len(_CUR_IDS - norm_ids),
        "n_current": len(_CUR_IDS),
        "n_legacy_mapped": len(legacy_mapped),
        "non_rule": non_rule,
        "has_rules_file": bool(_CUR_IDS),
    }


# --------------------------------------------------------------------------- 渲染


# 排序即产品判断，不是格式。
#   absent 第一：它多半意味着**产品自己坏了**（钩子挂了、规则被静默关掉），不是用户干了什么；
#   gap    最低：日内断层大多只是「你去吃饭了」，它无法区分「停手」与「钩子断了」，
#          而这件事已经由 absent 用更准的方式问了 —— 同样的现象，更好的问句排在前面。
PRIORITY = {
    "absent": 0,
    "baseline": 1,
    "repeat": 2,
    "first_seen": 3,
    "rule_pair": 4,
    "gap": 5,
}


# --------------------------------------------------------------------------- 盲区自述

# 每个检测器都必须在 `main` 里申报自己的「覆盖状态」。
# 为什么是**机制**而不是一段手写文案：手写的盲区说明会和检测器一起漂 ——
# 加了新检测器、忘了改文案，报告就会继续说「我只查了这五件事」。
# 所以：键必须齐，缺一个就抛（见 `_coverage_selfcheck`），
# 且状态只能从下面这四种里取，不许自由发挥。
COVERAGE_KEYS = ("absent", "baseline", "repeat", "first_seen", "gap", "rule_pair")

RAN, EMPTY, UNDECIDABLE, SKIPPED = "ran", "empty", "undecidable", "skipped"
COV_MARK = {
    RAN: "查了",
    EMPTY: "查了，没有",
    UNDECIDABLE: "查了，判不了",
    SKIPPED: "没查",
}

# 结构性盲区：与具体检测器无关，是这份数据/这个工具**原理上**看不到的东西。
# 它们必须每次都出现，否则「没报」会被读成「没问题」。
BLIND_SPOTS = (
    ("账本以外的一切", "没被钩子拦到的动作不进账本；本工具只看得见账本"),
    ("记录内容对不对", "本工具只报「什么变了」，不判断是否危险、是否合规"),
    ("是否被整链重写", "整链重写后重算全部 hash 与清单，本工具仍报内部自洽（需 L2 外部锚）"),
)


def _coverage_selfcheck(cov: Dict[str, Dict[str, str]]) -> None:
    """反向对照：漏报一个检测器的覆盖状态，必须当场炸，而不是悄悄少一行。

    这是「保护自报活跃」——盲区自述本身也要被守，否则它自己就是下一个会漂的东西。
    """
    missing = [k for k in COVERAGE_KEYS if k not in cov]
    if missing:
        raise ValueError(f"检测器未申报覆盖状态：{missing}（盲区自述会因此说谎）")
    bad = [k for k, v in cov.items() if v.get("status") not in COV_MARK]
    if bad:
        raise ValueError(f"覆盖状态取值非法：{bad}")


def render_coverage(coverage: Dict[str, Dict[str, str]] | None) -> List[str]:
    """把「本次查了什么、没查什么、判不了什么」印出来。

    顺序是刻意的：**先说没查的，再说查了的**。反过来的话，读者读到「都查了」
    就不会往下看，而盲区恰恰是后面那几行。
    """
    if not coverage:
        return ["—— 盲区 —— 本报告未申报覆盖状态（这是缺陷，不是省略）", ""]
    _coverage_selfcheck(coverage)
    lines = ["—— 盲区 ——"]
    for name, why in BLIND_SPOTS:
        lines.append(f"  原理上看不到：{name} —— {why}")
    for k in COVERAGE_KEYS:
        v = coverage[k]
        mark = COV_MARK[v["status"]]
        note = v.get("note") or ""
        lines.append(f"  {k}：{mark}{('（' + note + '）') if note else ''}")
    lines.append("")
    return lines


def render(
    clues: List[Clue],
    meta: Dict[str, Any],
    recent: int,
    cap: int = 5,
    coverage: Dict[str, Dict[str, str]] | None = None,
) -> str:
    """主动报告。六条契约见《主动性设计》§5。

    5.2 一句话在前：第一行先给结论，用户读完第一行就知道要不要往下看。
    5.3 全局上限：超过 cap 只出前 cap 条，其余折叠成一句。
    5.4 沉默说话：没有线索时**也必须说一句话** —— 沉默会被读成「它坏了」。
    """
    cen = meta.get("rule_census") or {}
    legacy_note = ""
    if cen.get("n_legacy_mapped"):
        # 归一是**读取层**做的（`_rules_of`），所以这里不再是「请你自己换算」的免责声明，
        # 而是「已经换算过、原样写了多少种」的事实陈述。
        legacy_note = (
            f"（口径：账本原样写了 {cen['n_ids_raw']} 种 id，"
            f"其中 {cen['n_legacy_mapped']} 个是 0.63.0 之前的旧号，已在读取层归一 ⇒ "
            f"实际涉及 {cen['n_rules_touched']} 条规则；规则库 {cen['n_current']} 条，"
            f"{cen['n_never_hit']} 条从未命中）"
        )
    if cen.get("non_rule"):
        legacy_note += (
            f"（另有 {len(cen['non_rule'])} 个非规则号出现在 rules_hit 里："
            f"{'、'.join(cen['non_rule'])} —— 已记录，未判定，不并入规则分母）"
        )

    ordered = sorted(clues, key=lambda c: PRIORITY.get(c.kind, 9))
    shown, hidden = ordered[:cap], ordered[cap:]

    lines: List[str] = []
    # —— 5.2 一句话在前 ——
    # 「今天记了 N 条」里的 N 必须是**今天的**条数，不是全期总量。
    # 首版写成 meta['records']（全期），一句话里两个分母 —— 正是 F40 那一类。
    today_n = meta.get("today_records", 0)
    if not ordered:
        lines.append(f"今天记了 {today_n:,} 条，没有需要你看的。{legacy_note}")
    else:
        lines.append(
            f"今天记了 {today_n:,} 条，有 {len(ordered)} 件值得看。{legacy_note}"
        )
    lines.append("")

    for i, c in enumerate(shown, 1):
        lines.append(f"{i}. {c.subject}")
        ev = " · ".join(f"{d}.jsonl:{ln}" for d, ln in c.evidence[:2])
        lines.append(f"   {ev}")
        if c.note:
            lines.append(f"   {c.note}")
        lines.append("")

    if hidden:
        lines.append(f"另有 {len(hidden)} 条，打开查看全部。")
        lines.append("")

    # —— 5.3 分母永远在，但放在最后 ——
    rp = meta["pair_stats"]
    rp_state = (
        "不可判定（账本里没有带 session 的规则命中）"
        if rp.get("status") == "undecidable"
        else (
            f"{rp.get('pairs', 0)} 个配对／{rp.get('new_pairs', 0)} 个本次首次出现"
        )
    )
    lines.append(
        "—— 分母 ——"
        f" 日文件 {meta['files']}｜记录 {meta['records']:,}｜不可解析 {meta['unparsed']}｜"
        f"基线窗口 {meta['window']} 天｜首次出现窗口 {recent} 天｜规则配对 {rp_state}"
    )
    lines.append("")
    lines.extend(render_coverage(coverage))
    lines.append("本报告只陈述「什么变了」，不判断是否危险。")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="巡检 Agent 档 1 原型（只读）")
    ap.add_argument("--root", default=".psl/audit")
    ap.add_argument("--window", type=int, default=14)
    ap.add_argument("--recent", type=int, default=1, help="只报最后几天（主动报告默认只看今天）")
    ap.add_argument("--min-each", type=int, default=3)
    ap.add_argument("--gap-min", type=float, default=30.0, help="日内断层阈值（分钟）")
    ap.add_argument("--cap", type=int, default=5, help="主动报告上限（注意力预算）")
    ap.add_argument("--repeat-min", type=int, default=3, help="「第二次才算数」的重复门槛")
    ap.add_argument("--pair-gap", type=float, default=5.0, help="规则配对的会话内时间窗（分钟）")
    ap.add_argument("--pair-max", type=int, default=3, help="组合当天出现次数上界（超过算新常态）")
    ap.add_argument("--json", action="store_true", help="输出 JSON（供负控断言用）")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")  # 中文 Windows 控制台
    except Exception:
        pass

    if not os.path.isdir(args.root):
        print(f"[停] 目录不存在：{args.root}", file=sys.stderr)
        return 2

    recs = list(iter_records(args.root))
    if not recs:
        print(f"[停] {args.root} 里没有任何日文件记录", file=sys.stderr)
        return 2

    unparsed = sum(1 for _, _, r in recs if r.get("__unparsed__"))
    daily: Dict[str, int] = collections.defaultdict(int)
    for day, _, rec in recs:
        if rec.get("type") == "pre_tool_use":
            daily[day] += 1

    today = max(daily) if daily else "—"

    # 同期口径：cutoff = 今天最后一条记录的钟点。前 N 天都截到同一钟点再比，
    # 否则早上九点送达时「今天还没过完」会被读成「今天少了很多」。
    cutoff: str | None = None
    if daily:
        tods = [
            t
            for d, _, rec in recs
            if d == today and rec.get("type") == "pre_tool_use"
            for t in [_tod(rec)]
            if t
        ]
        cutoff = max(tods) if tods else None
    daily_cut: Dict[str, int] = collections.defaultdict(int)
    per_type: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for day, _, rec in recs:
        if rec.get("__unparsed__"):
            continue
        t = _tod(rec)
        if cutoff is not None and t is not None and t > cutoff:
            continue
        per_type[day][rec.get("type")] += 1
        if rec.get("type") == "pre_tool_use":
            daily_cut[day] += 1

    clues: List[Clue] = []
    coverage: Dict[str, Dict[str, str]] = {}
    scope = f"截至 {cutoff[:5]}" if cutoff else "全天"

    today_lines = sum(1 for d, _, _ in recs if d == today)
    got = detect_absent(per_type, today, cutoff, today_lines)
    clues += got
    coverage["absent"] = {
        "status": RAN if got else EMPTY,
        "note": f"前 7 天里 >=5 天出现且中位数 >=3 的 type；口径 {scope}",
    }

    got = detect_baseline(daily_cut, window=args.window, recent=args.recent, cutoff=cutoff)
    clues += got
    coverage["baseline"] = {
        "status": RAN if got else EMPTY,
        "note": f"前 {args.window} 天同期中位数＋MAD（3 倍）；口径 {scope}",
    }

    stats = _item_stats(recs)
    got, used = detect_repeat(stats, today, min_count=args.repeat_min)
    clues += got
    coverage["repeat"] = {
        "status": RAN if got else EMPTY,
        "note": f"当天首次出现且当天 >= {args.repeat_min} 次",
    }

    got, fs_counts = detect_first_seen(stats, recent=args.recent, exclude=used)
    clues += got
    coverage["first_seen"] = {
        "status": RAN if got else EMPTY,
        "note": f"全期窗口／只报最后 {args.recent} 天；已剔除 repeat 报过的 {len(used)} 项",
    }

    got = detect_gap(recs, threshold_min=args.gap_min, recent=args.recent)
    clues += got
    coverage["gap"] = {"status": RAN if got else EMPTY, "note": f"阈值 {args.gap_min:g} 分钟"}

    rp_clues, pair_stats = detect_rule_pairs(
        recs,
        recent=args.recent,
        gap_min=args.pair_gap,
        min_each=args.min_each,
        max_today=args.pair_max,
    )
    clues += rp_clues
    coverage["rule_pair"] = {
        "status": (
            UNDECIDABLE
            if pair_stats.get("status") == "undecidable"
            else (RAN if rp_clues else EMPTY)
        ),
        "note": f"同 session 内 {args.pair_gap:g} 分钟窗口；各自需 >= {args.min_each} 次单独命中",
    }
    _coverage_selfcheck(coverage)

    today_records = sum(1 for d, _, r in recs if d == today and not r.get("__unparsed__"))
    meta = {
        "today": today,
        "today_records": today_records,
        "files": len(day_files(args.root)),
        "records": len(recs),
        "unparsed": unparsed,
        "window": args.window,
        "baseline_cutoff": cutoff,
        "pair_stats": pair_stats,
        "rule_census": rule_id_census(args.root),
    }
    if args.json:
        import json as _json

        print(
            _json.dumps(
                {
                    "meta": meta,
                    "coverage": coverage,
                    "clues": [
                        {
                            "kind": c.kind,
                            "day": c.day,
                            "subject": c.subject,
                            "evidence": c.evidence,
                            "note": c.note,
                            "items": list(c.items),
                        }
                        for c in sorted(clues, key=lambda x: PRIORITY.get(x.kind, 9))
                    ],
                },
                ensure_ascii=False,
                indent=1,
            )
        )
        return 0

    print(render(clues, meta, args.recent, cap=args.cap, coverage=coverage))

    print(
        f"[分母] 记录 {len(recs)}｜不可解析 {unparsed}｜"
        f"pre_tool_use 覆盖 {len(daily)} 天｜"
        f"首次出现抽样 {fs_counts}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
