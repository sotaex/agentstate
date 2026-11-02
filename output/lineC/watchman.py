#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""巡检 Agent · 档 1 原型（**对账本只读**，零模型）。

问的是「和过去比，什么变了」，不是「这条危不危险」。
危险是判断，归 rules/default.json；变化是事实，归这里。

★ 「只读」要说准（2026-11-02）：本文件**不写 `.psl/audit` 一个字节**，
  但它自己有一本账（`clue_ledger.py`，默认 `_watchman_ledger.json`）。
  那本账记的是「我说过什么」，不是「世界发生了什么」。
  **两本账不能合并**：观察者的记忆一旦写进被观察的目录，它就同时是证据
  和对证据的加工 —— 自指的第三种形态。所以默认路径在 `lineC/` 下，不在 `.psl/`。
  说成「完全只读」是超额声明；准确的说法是「对账本只读；另有一本自己的账」。
  `--no-ledger` 可关掉那本账（关掉后主动性退回一次性，同一条线索会天天出现）。

三条纪律：
  1. 每条线索必须有 evidence（(day, lineno)），不许空 —— 没回指的线索是「模型说的」；
  2. 每条线索只有一个 kind —— 混装会让「有几条线索」失去意义；
  3. 输出里不出现「危险」「可疑」「违规」—— 只说「变了」「首次出现」「从未同时出现过」。

用法：
    python output/lineC/watchman.py
    python output/lineC/watchman.py --root .psl/audit --window 14 --recent 3
    python output/lineC/watchman.py --no-ledger          # 退回一次性
    python output/lineC/clue_ledger.py --dump            # 看账本现状
    python output/lineC/clue_ledger.py --ack <KEY>       # 「知道了，别再说」
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
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
    #: 这条线索的**稳定身份**，由产生它的检测器声明（见 clue_ledger.clue_key）。
    #: 空则退回到「按 kind 猜」。★ 为什么必须由检测器声明：只有它知道
    #: 「什么算同一件事」。消费方（账本）只能看到 kind/day/subject，而
    #: subject 里带当天计数（「9 个」→「10 个」）、day 有时恒为 today
    #: （anchor/absent/verdict 都是），两者都不足以当身份 —— 拿它们猜，
    #: 结果就是「每天都是新线索」，账本退化成计数器。
    key: str = ""
    #: 这条线索的**规模**：当天次数／缺失天数／偏离倍数／涉及条目数。
    #: 由检测器声明，账本用它算内容指纹（`clue_ledger.clue_fingerprint`）。
    #:
    #: ★ 为什么必须有它，而不是从 subject 里抠数字：
    #:   ① subject 是给人看的一句话，随时会为了可读性重写（本文件 2026-11-02
    #:      就把 `AN-010` 改成了 `写到项目目录之外（AN-010）`）；抠数字等于
    #:      把「文案」当「数据」，改文案就换指纹。
    #:   ② 「同一件事变了没有」必须能回答「1 次 → 40 次算不算变」。
    #:      只有 items 时，1 次和 40 次的 items 完全一样 ⇒ 指纹不变 ⇒
    #:      用户按过 `--ack` 之后就**永远听不到**这件事变严重了。
    #:      那不是「别再说了」，是把眼睛闭上。
    #:   ③ 所以规模必须由**知道它的那一层**显式交出来，不靠下游猜。
    magnitude: int = 0

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


#: ★ 规则库路径用**文件自身位置**定位，不用 cwd（2026-11-03 修）。
#:
#:   原写法是相对路径 `rules/default.json` ⇒ 从 `output/lineC/` 里跑时**读不到**，
#:   于是 `_CUR_IDS` 与 `_CUR_CAT` 双双为空 ⇒ 两处过滤**同时静默失效**：
#:     · `non_rule` 不生效 ⇒ `OUT-01` 这类非规则号混进配对（N-04 的老毛病复发）
#:     · 意图簇不生效   ⇒ `AN-001→AN-010` 这类噪声配对全部回来（N-05 复发）
#:   实测（2026-11-03 04:5x）：从 `output/lineC` 跑，11-01 报 4 条且带 `OUT-01`；
#:   从仓库根跑，报 3 条、`OUT-01` 被滤掉。**同一份代码、同一份账本，两个结果。**
#:
#:   ★ 它不报错、不警告，只是**多报** —— 而「多报」在报告里看起来像「检测器很灵敏」。
#:     这是「配置缺失时的降级」最容易被读成正常的一种形状（铁律 22 的邻域）。
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
RULES_PATH = os.path.join(_REPO, "rules", "default.json")
_ALIAS: Dict[str, str] | None = None
_CUR_IDS: set = set()
_CUR_CAT: Dict[str, str] = {}


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


def load_rule_categories(path: str = RULES_PATH) -> Dict[str, str]:
    """`id -> category`。**从规则库读，不手抄一份。**

    实测 37 条规则全都带 `category`，取值 8 类：
    `secrets`(10) / `destructive`(11) / `network`(4) / `injection`(4) /
    `supply_chain`(5) / `context`(1) / `metadata`(1) / `canary`(1)。
    """
    import json

    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    out: Dict[str, str] = {}
    for r in data.get("rules", []):
        if isinstance(r, dict) and r.get("id") and r.get("category"):
            out[str(r["id"])] = str(r["category"])
    return out


#: 规则的 `category` → **意图簇**。链只在同一簇内成立（2026-11-03，修 N-05）。
#:
#: ★ 这张表解决的是 N-05：`rule_pair` 原来只问「两条规则 5 分钟内先后响过」，
#:   于是 `AN-001（读密钥配置）→ AN-010（写到项目目录之外）` 被报成一条链。
#:   而它只是「先读了配置、后来又写了文件」——**两个不相干的动作**，
#:   先后发生是必然的（两条规则各命中十几次以上，5 分钟内凑一起毫不稀奇）。
#:
#: ★ 为什么不用 `category_order` 当判据（先试过了，不行）：
#:   它也排不出真假 —— `AN-002→AN-014`（真）与 `AN-001→AN-010`（噪声）
#:   在 `category_order` 里**都是「前进」**（secrets 在 destructive 之前）。
#:   序号先后说的是「显示顺序」，不是「这两步有没有因果关系」。
#:
#: ★ 判据不变量：**同一个意图下的两小步才算一条链。**
#:     · probe（找信息）：读凭证／枚举环境变量／读元数据 —— 都是「在找」
#:     · act（已出手）：破坏／外网／注入／供应链／蜜饵外发 —— 都是「动手了」
#:   跨簇之间没有「因为所以」：找到钥匙，不等于要砸门。
#:
#: ★★ 样本量必须坦白：它由 **4 个配对（6 个实例）** 检验，3 真 1 假。
#:    **这个量不足以证明它**，只够说「它把这 4 条分对了」。
#:    要证伪它，需要的是下一批**新配对**：若出现「同簇却明显不相干」，
#:    或「跨簇却真是链」，那是**分簇错**，不是数据噪声。
#:    ⇒ 所以它写成**可改的表**而不是阈值：改表能说清改了什么，
#:      改阈值改不出任何可陈述的东西（v4 §四 已用算术证明阈值无解）。
#:
#: ★ `canary` 归 act：它命中意味着「内容真的出去了」，是**已经发生的后果**，
#:   与「在找信息」不是同一件事。归 probe 会让「读文件 → 蜜饵出现」被当成
#:   一条侦察链，而那时外发已经完成了。
_CHAIN_CLUSTER: Dict[str, str] = {
    "secrets": "probe",
    "context": "probe",
    "metadata": "probe",
    "destructive": "act",
    "network": "act",
    "injection": "act",
    "supply_chain": "act",
    "canary": "act",
}


def chain_cluster(rid: str) -> str:
    """这条规则属于哪个意图簇；**查不到返回空串**（＝不参与链判定）。"""
    _ensure_alias()
    return _CHAIN_CLUSTER.get(_CUR_CAT.get(rid, ""), "")


def _ensure_alias() -> None:
    global _ALIAS, _CUR_IDS, _CUR_CAT
    if _ALIAS is None:
        _ALIAS, _CUR_IDS = load_rule_ids()
        _CUR_CAT = load_rule_categories()


_LABELS: Dict[str, str] | None = None


def load_rule_labels(path: str = RULES_PATH) -> Dict[str, str]:
    """`id -> 中文名`。**唯一真源是 `rules/default.json`，不许手抄一份。**

    为什么需要它：报告里只写 `AN-010`，用户看不出这是什么规则。
    「可读性」是记录质量五问之一（铁律 37），而这一条恰恰是主动报告的
    **全部价值所在** —— 说了但没人看得懂，等于没说，而且还占了注意力预算。

    ★ 只用于**显示**，不用于身份。身份（`Clue.key`）必须用号，因为号稳定、
      中文名会随文案改；用名字当键，改一次文案就等于「换了一件新事」。
    """
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    out: Dict[str, str] = {}
    for r in data.get("rules", []):
        if isinstance(r, dict) and r.get("id"):
            lab = r.get("label_zh") or r.get("name") or ""
            if lab:
                out[r["id"]] = str(lab)
    return out


def rule_label(rid: str) -> str:
    """`AN-010` → `写到项目目录之外（AN-010）`。查不到就**只给号，不编**。"""
    global _LABELS
    if _LABELS is None:
        _LABELS = load_rule_labels()
    lab = _LABELS.get(rid)
    return f"{lab}（{rid}）" if lab else rid


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
    # ★ 2026-11-01 修 N-02：原来取 parts[:2]，把 D:\Application\WB\CN\resources
    #   压成 D:/Application —— 盘符＋顶层目录，零区分度；同一产品下不同子目录
    #   还会撞成同一个名字。取前 3 段后，D:/Application/WB 与 D:/Application/Qoder
    #   能分开（判据见 noise_baseline.json 第 2 条）。
    return "/".join(parts[:3])


BENIGN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benign.json")


def load_benign(path: str = BENIGN_PATH) -> Dict[str, Any]:
    """读常见物词表。

    ★ 读不到时**不静默降级**：返回带 `_missing` 的**空词表**，调用方必须把它
      写进报告。否则「词表丢了」会表现成「今天一条噪声都没有」——那是最好的
      假象，也是最坏的假象。
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        if not isinstance(d, dict):
            raise ValueError("benign.json 顶层不是对象")
        return d
    except Exception as exc:  # noqa: BLE001
        return {
            "_missing": f"{type(exc).__name__}: {exc}",
            "cmd": [], "host_suffix": [], "host_reserved": [], "path_prefix": [],
        }


def is_benign(kind: str, val: str, benign: Dict[str, Any]) -> bool:
    """这条「首次出现」是不是常见物。

    ★ 只用来决定**报不报**，绝不决定**记不记** —— 账本里它照旧存在，
      `items` 里照旧出现。忽略的是注意力，不是事实（铁律 34）。
    """
    if kind == "cmd":
        return val in set(benign.get("cmd") or [])
    if kind == "path":
        # ★ 目录类默认不报首现（benign.json 的 skip_path_first_seen）。
        #   实测：路径粒度从 2 段改到 3 段之后，D:/Application 消失了，
        #   但 C:/Users/x 冒出来 —— 说明根因不是「粒度」，是「目录首现没信息量」。
        #   用户新建一个项目目录不该被告警；「写到 C:/Windows 危险吗」归规则库。
        if benign.get("skip_path_first_seen"):
            return True
        for p in benign.get("path_prefix") or []:
            if val == p or val.startswith(p + "/"):
                return True
        return False
    if kind == "host":
        h = val.lower().strip(".")
        for r in benign.get("host_reserved") or []:
            r = r.lower()
            if h == r or h.endswith("." + r):
                return True
        for s in benign.get("host_suffix") or []:
            s = s.lower()
            # 按标签边界匹配：x.microsoft.com 命中，notmicrosoft.com **不**命中。
            # 裸子串匹配会让伪装域名（notmicrosoft.com）被当成常见物放过。
            if h == s or h.endswith("." + s):
                return True
        return False
    return False


def _benign_note(benign: Dict[str, Any] | None, skipped: Dict[str, int]) -> str:
    """把词表状态写进覆盖注记。

    ★ 三种状态必须长得不一样：未启用／读取失败／生效中。
      「词表丢了」会表现成「今天一条噪声都没有」—— 那是最坏的假象，
      因为报告看起来比平时还干净。
    """
    if benign is None:
        return "｜常见物词表：未启用（--no-benign）"
    if benign.get("_missing"):
        return f"｜常见物词表：**读取失败**（{benign['_missing']}）⇒ 噪声未被过滤"
    n = sum(skipped.values()) if skipped else 0
    if not n:
        return "｜常见物词表：已启用，本次无命中"
    detail = "、".join(f"{k} {v}" for k, v in sorted(skipped.items()))
    return f"｜常见物词表：忽略 {n} 个（{detail}）"


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
                # 身份＝「哪个 type 不见了」，与哪天无关：同一个 type 连着三天
                # 不出现是同一个状态，不是三个事实。
                key=f"absent|{k}",
                # 规模＝这个 type 平时一天有多少条。它决定「不见了」有多反常：
                # 平时 200 条的 type 消失，与平时 3 条的 type 消失，不是一回事。
                magnitude=int(med),
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
                    # 身份＝哪一天偏了。这里的 day 就是身份：昨天偏和今天偏
                    # 是两个事实，不能合并成「一直在偏」。
                    key=f"baseline|{d}",
                    # 规模＝当天实际条数（偏离的方向由 subject 说，指纹只认量级）。
                    magnitude=int(cur),
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
                        key=f"baseline|{d}",
                        magnitude=int(cur),
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
    benign: Dict[str, Any] | None = None,
) -> Tuple[List[Clue], set, Dict[str, int]]:
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
    skipped: Dict[str, int] = collections.defaultdict(int)
    used: set = set()
    for key, fd in stats.first_day.items():
        if fd != today:
            continue
        n = stats.per_day[key][today]
        if n < min_count:
            continue
        kind, val = key.split(":", 1)
        if benign is not None and is_benign(kind, val, benign):
            skipped[kind] += 1
            # ★ 被词表忽略的 key 也必须占位：否则 first_seen 会把它再报一次，
            #   等于「压了又冒出来」，而用户看到的是同一条噪声换了个标题。
            used.add(key)
            continue
        by_kind[kind].append((val, n))
        used.add(key)

    clues: List[Clue] = []
    for kind, pairs in sorted(by_kind.items()):
        pairs.sort(key=lambda x: -x[1])
        names = "、".join(f"{v}({n} 次)" for v, n in pairs[:6])
        more = f" 等 {len(pairs)} 个" if len(pairs) > 6 else ""
        ev = tuple(stats.first_ev[f"{kind}:{v}"] for v, _ in pairs[:5])
        note = f"门槛：当天首次出现且当天 >= {min_count} 次"
        if skipped.get(kind):
            note += f"｜按常见物词表忽略 {skipped[kind]} 个（账本仍记，--no-benign 可看）"
        clues.append(
            Clue(
                kind="repeat",
                day=today,
                subject=f"{today} 今天才第一次出现的{label[kind]}，已经重复 {min_count} 次以上：{names}{more}",
                evidence=ev,
                note=note,
                items=tuple(v for v, _ in pairs),
                # 身份＝「这一类里有哪些名字」。与 day 无关：同一个命令
                # 换一天重复出现仍是同一件事，不该每天重新说一遍。
                key="repeat|%s|" % kind + "|".join(sorted(v for v, _ in pairs)),
                # 规模＝这批里出现最多的那个名字重复了几次。
                # 3 次和 300 次是两件事，而 items 完全一样。
                magnitude=max((n for _, n in pairs), default=0),
            )
        )
    return clues, used, dict(skipped)


def detect_first_seen(
    stats: ItemStats,
    recent: int = 3,
    exclude: set | None = None,
    benign: Dict[str, Any] | None = None,
) -> Tuple[List[Clue], Dict[str, int], Dict[str, int]]:
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
    skipped: Dict[str, int] = collections.defaultdict(int)
    for key, fd in stats.first_day.items():
        if fd not in tail or key in exclude:
            continue
        kind, val = key.split(":", 1)
        if benign is not None and is_benign(kind, val, benign):
            skipped[kind] += 1
            continue
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
                    note=(
                        f"窗口=全期，只报最后 {recent} 天"
                        + (
                            f"｜按常见物词表忽略 {skipped[kind]} 个{label[kind]}（账本仍记）"
                            if skipped.get(kind)
                            else ""
                        )
                    ),
                    items=tuple(names),
                    # 身份＝「首次出现了哪些名字」。day 属于**事件发生的日子**，
                    # 但它不是身份：同一个名字的「首次出现」只发生一次。
                    key="first_seen|%s|" % kind + "|".join(sorted(names)),
                    # 规模＝这一类首次出现了几个名字。1 个和 20 个不一样。
                    magnitude=len(names),
                )
            )
    return clues, stats.counts, dict(skipped)


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
    # ★ 2026-11-01 修 N-04：非规则号（OUT-01／GOV-01 这类命名空间号）不该进规则配对。
    #   实测第 8 条就是 `AN-005` → `OUT-01`，报出来用户无法理解「OUT-01 是什么规则」。
    #   ★ 规则库读不到时（_CUR_IDS 为空）**不过滤** —— 宁可多报，不许因为配置缺失
    #     把整类线索静默关掉。
    _ensure_alias()
    non_rule: set = set()
    if _CUR_IDS:
        non_rule = {r for r in solo if r not in _CUR_IDS}
    days = sorted({d for per in pair_days.values() for d in per})
    if not days:
        # ★ 这条回退分支是**没有任何配对**时才会走的：新装机、空账本、
        #   规则字段被抹掉、或者一天里根本没触发过规则。
        #   它原来写的是 `for _, d, _, _ in recs` —— 而 recs 的元素是
        #   `(day, lineno, rec)` **三元组**。于是只要走到这里就
        #   `ValueError: not enough values to unpack (expected 4, got 3)`，
        #   整个巡检 rc=1、**一条输出都没有**。
        #
        #   为什么一直没被发现：干净账本永远有配对（实测 11 组），
        #   这条分支**一次都没被执行过**。红队 R5（把 ts 全抹成空串）
        #   第一次把它踩出来 —— 而「新装的机器上第一次跑」会踩到同一个地方，
        #   只是没人把它和红队联系起来。
        days = sorted({d for d, _ln, _r in recs})
    tail = set(days[-recent:]) if recent > 0 else set(days)

    clues: List[Clue] = []
    new_pairs = 0
    for (a, bb), per in sorted(
        pair_days.items(), key=lambda kv: -sum(kv[1].values())
    ):
        if a in non_rule or bb in non_rule:
            continue
        # ★★ N-05（2026-11-03）：**跨意图簇的两步不算一条链。**
        #   这一条守的是「这两步算不算一条链」，不是「凑得近不近」。
        #   实测 4 个配对的判定（v4 金标准）：
        #     AN-002(secrets)→AN-014(context)   同簇 probe  ⇒ 真   ✓
        #     AN-014(context)→AN-005(secrets)   同簇 probe  ⇒ 真   ✓
        #     AN-001(secrets)→AN-002(secrets)   同簇 probe  ⇒ 弱   ✓
        #     AN-001(secrets)→AN-010(destructive) 跨簇     ⇒ 噪声 ✗（本轮滤掉的就是它）
        # ★ 查不到簇时**不过滤**，与上面 `non_rule` 同一原则：
        #   规则库缺项属于配置问题，宁可多报，不许因为配置缺失静默关掉一类线索。
        _ca, _cb = chain_cluster(a), chain_cluster(bb)
        if _ca and _cb and _ca != _cb:
            continue
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
                    f"{d} 首次出现组合：同一会话内 {rule_label(a)} 之后 "
                    f"{gap_min:g} 分钟内又命中 {rule_label(bb)}（当天 {n} 次）"
                ),
                evidence=((d, ln),),
                note=f"此前从未同时出现过｜各自单独命中 {solo[a]}/{solo[bb]} 次",
                items=(a, bb),
                # 身份＝「哪两条规则凑在一起」。**不带 day**：同一对规则换一天
                # 再凑一次还是同一件事，否则「首次出现」这个说法自相矛盾。
                # ★ 排序的理由是**归并同一个现象**，不是「遍历次序不定」：
                #   `rule_pair_index` 里 seq 已按时间排好，`(a, bb)` 天然是
                #   时间序，方向是确定的。但实测 124 个配对里有 **37 组是双向的**
                #   （A→B 与 B→A 都出现过），不排序就会把同一组共现报成两条
                #   「首次出现组合」，注意力预算直接对折。
                # ⇒ 记账按**无序组合**计数（铁律 35 的「拦截时归并」），
                #   报告文案里的方向仍按该条证据的真实时间序写。
                #   代价：方向反转不会触发账本重开（magnitude 跨桶时仍会重开）。
                key="rule_pair|" + "|".join(sorted((a, bb))),
                # 规模＝这对组合当天出现了几次。上界 `max_today` 挡的是「新常态」，
                # 但在上界之内，1 次和 3 次仍然是不同的事实。
                magnitude=n,
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


def _gap_series(
    recs: List[Tuple[str, int, Dict[str, Any]]]
) -> Tuple[Dict[str, List[Tuple[datetime, int]]], int]:
    """把记录按天摊成 `(时间, 行号)`，并回报**有多少条真的带可解析 ts**。

    ★ 第二个返回值不是装饰：`detect_gap` 用「没有线索」判断「查了，没有」，
      而「一条 ts 都不可解析」和「ts 都在、只是间隔不够」在返回值上**长得一样**。
      没有这个分母，检测器就会把「没查成」报成「查了没有」。
      所以摊平逻辑与分母统计放在同一处（R4），不许各写一份。
    """
    per_day: Dict[str, List[Tuple[datetime, int]]] = collections.defaultdict(list)
    with_ts = 0
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
        with_ts += 1
    return per_day, with_ts


def gap_census(recs: List[Tuple[str, int, Dict[str, Any]]]) -> Dict[str, int]:
    """gap 检测的分母：`with_ts` 为 0 ⇒ 这一项只能报「判不了」，不能报「没有」。"""
    per_day, with_ts = _gap_series(recs)
    return {"with_ts": with_ts, "total": len(recs), "days": len(per_day)}


def detect_gap(
    recs: List[Tuple[str, int, Dict[str, Any]]],
    threshold_min: float = 30.0,
    recent: int = 3,
    routine_days: int = 7,
    routine_min: int = 4,
) -> Tuple[List[Clue], int]:
    """Q3：哪段时间是空的 —— 同一天内两条记录间隔超过阈值。

    与 B-1「缺日」分工：B-1 是**跨天**（哪天整个日文件不存在），
    这里是**日内**（那天中间断了两小时）。不同粒度，不重叠。

    ★ 2026-11-01 修 N-06：原来每天固定时段断（早饭、晚饭）都报一次，
      实测一天报 3 条全是作息。现在先看**前 routine_days 天同一钟点**
      （起点差 ≤30 分）是不是也常断：≥ routine_min 天也断 ⇒ 判为作息，不报。

    ★ 这条抑制本身养出一个盲区：**攻击者每天同一时段删记录，就会被学成「作息」**。
      它和 absent 的「基线来自账本本身」是同一个病。已写进 BLIND_SPOTS 第 9 条。
    """
    per_day, _with_ts = _gap_series(recs)

    days = sorted(per_day)

    # 先算**全部天**的断层（不只 recent），作息判定要用历史
    gaps_by_day: Dict[str, List[Tuple[datetime, datetime, int, int]]] = {}
    for d in days:
        seq = sorted(per_day[d])
        lst: List[Tuple[datetime, datetime, int, int]] = []
        for (t0, ln0), (t1, ln1) in zip(seq, seq[1:]):
            gm = (t1 - t0).total_seconds() / 60.0
            if gm >= threshold_min:
                lst.append((t0, t1, ln0, ln1))
        gaps_by_day[d] = lst

    tail = set(days[-recent:]) if recent > 0 else set(days)
    clues: List[Clue] = []
    n_routine = 0
    for d in sorted(tail):
        idx = days.index(d)
        prior = days[max(0, idx - routine_days): idx]
        for (t0, t1, ln0, ln1) in gaps_by_day[d]:
            same_slot = 0
            for pd in prior:
                for (p0, _p1, _pl0, _pl1) in gaps_by_day.get(pd, []):
                    if abs((p0 - t0).total_seconds()) <= 1800:
                        same_slot += 1
                        break
            if same_slot >= routine_min:
                n_routine += 1
                continue
            gap_min = (t1 - t0).total_seconds() / 60.0
            h = int(gap_min // 60)
            m = int(gap_min % 60)
            span = f"{h} 小时 {m} 分" if h else f"{m} 分"
            clues.append(
                Clue(
                    kind="gap",
                    day=d,
                    subject=f"{d} {t0.strftime('%H:%M')}–{t1.strftime('%H:%M')} 之间有 {span}没有记录",
                    evidence=((d, ln0), (d, ln1)),
                    note=f"阈值 {threshold_min:g} 分钟"
                         + (f"｜前 {len(prior)} 天同段只断 {same_slot} 天，不是作息" if prior else ""),
                    # 身份＝哪天的哪个起点。同一天可以有好几个断层，只按 day 分会
                    # 把它们压成一条（账本自检第 5 臂就是这么撞出来的）。
                    key=f"gap|{d}|{t0.strftime('%H:%M')}",
                    # 规模＝断了多少分钟。90 分钟和 8 小时不是一回事。
                    # （gap 默认已关闭，但保留 magnitude 以免 --with-gap 时
                    #   指纹退化成「只看起点时间」，那等于每天都是新的。）
                    magnitude=int(gap_min),
                )
            )
    return clues, n_routine


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


# --------------------------------------------------------------------------- 裁决口径

# `decision` 与 `action` 是**两套字段并存**，不是一套（协同说明坑 1）。
# 实测 2026-10-31 22:54：164,304 条里 action 出现 105,749 次、decision 77,388 次。
# 差额主要是 post_tool_use —— 它**没有 decision**，裁决记在 action=record 里。
# ⇒ 只按 decision 分桶会把执行侧整类漏掉（28.0% 的记录）。
DECISION_DOMAIN = (
    "allow", "deny", "alert", "block", "config_refresh", "config_fallback", None,
)
ACTION_DOMAIN = ("allow", "record", "alert", "block", None)

# decision 字段里混着**非裁决值**：配置刷新/回退借用了同一个字段。
# 它们不是裁决，但也不能算表外 —— 必须显式登记，否则每天都报红，
# 而每天都红的规则等于没有规则（铁律 26）。
NON_VERDICT_DECISION = {
    "config_refresh": "配置刷新",
    "config_fallback": "配置回退",
}

# 组合的合法性由**关系**判，不逐条列。
# 逐条列的话，表会随 type 增长无限膨胀，「表外」就退化成「我还没抄到」——
# 那正是铁律 28 说的「兜底让没分类看起来像分类完了」。
REL_AGREE = "一致"          # decision == action
REL_EXEC = "执行侧"         # 无 decision，裁决记在 action（post_tool_use 那类）
REL_NONE = "无裁决"         # 两个都没有（计量／摘要记录）
REL_ALLOW_ALERT = "放行但告警"  # allow × alert —— **不是矛盾**
REL_SYNONYM = "同义两词"     # deny × block —— 命名未收敛
REL_DEC_ONLY = "只有裁决"    # 有 decision 无 action（哨兵／汇总那类）
REL_NON_VERDICT = "非裁决值"  # decision 里装了 config_*
REL_OUT = "表外"            # 兜底：新组合，必须人看

REL_ORDER = (
    REL_AGREE, REL_EXEC, REL_NONE, REL_DEC_ONLY,
    REL_ALLOW_ALERT, REL_SYNONYM, REL_NON_VERDICT, REL_OUT,
)


def classify_verdict(decision: Any, action: Any) -> str:
    """把 (decision, action) 判进八档之一。纯函数，负控直接打它。"""
    if decision in NON_VERDICT_DECISION:
        return REL_NON_VERDICT
    if decision is None:
        # 没有 decision 但有 action ⇒ 裁决记在 action（执行侧）。
        # 这一档**必须存在**：把它并进「无裁决」就等于把 45,988 条执行记录
        # 说成「没有裁决」，而它们恰恰是有裁决的，只是记在另一个字段里。
        return REL_NONE if action is None else REL_EXEC
    if action is None:
        return REL_DEC_ONLY
    if decision == action:
        return REL_AGREE
    if decision == "allow" and action == "alert":
        return REL_ALLOW_ALERT
    if decision == "deny" and action == "block":
        return REL_SYNONYM
    return REL_OUT


def verdict_census(recs: List[Tuple[str, int, Dict[str, Any]]]) -> Dict[str, Any]:
    """裁决口径统计。**同时**验值域与关系，两件事分开报。

    只验关系的话，一个新取值（`decision="quarantine"`）会落进「表外」——
    报出来了，但报成「组合不认识」，而真正的问题是「值域变了」。
    两件事混报，读的人就分不清是产品加了新裁决，还是写错了字段。
    """
    rel: collections.Counter = collections.Counter()
    out: collections.Counter = collections.Counter()
    bad_val: collections.Counter = collections.Counter()
    n_dec = n_act = n = 0
    for _, _, r in recs:
        if r.get("__unparsed__"):
            continue
        n += 1
        d, a = r.get("decision"), r.get("action")
        if d is not None:
            n_dec += 1
        if a is not None:
            n_act += 1
        if d not in DECISION_DOMAIN:
            bad_val[f"decision={d!r}"] += 1
        if a not in ACTION_DOMAIN:
            bad_val[f"action={a!r}"] += 1
        k = classify_verdict(d, a)
        rel[k] += 1
        if k == REL_OUT:
            out[(str(r.get("type")), str(d), str(a))] += 1
    return {
        "records": n,
        "n_decision": n_dec,
        "n_action": n_act,
        "rel": {k: rel.get(k, 0) for k in REL_ORDER},
        "out": out,
        "bad_value": bad_val,
    }


def detect_verdict(vc: Dict[str, Any], today: str, today_lines: int) -> List[Clue]:
    """表外组合与值域外的取值，各报一条。

    这条**只在非空时报**：它恒为空是正常的（实测 40 种组合全部落进八档）。
    恒绿的判据不许进人的清单（铁律 41），所以空的时候只出现在「盲区」那一行。
    """
    clues: List[Clue] = []
    out, bad_val = vc["out"], vc["bad_value"]
    if out:
        items = tuple(f"{t}｜decision={d}｜action={a}" for (t, d, a) in sorted(out))
        clues.append(
            Clue(
                kind="verdict",
                day=today,
                subject=(
                    f"裁决口径出现 {len(out)} 种**表外组合**（共 {sum(out.values())} 条）"
                ),
                # 表外组合散布在多个 type 上，回指不了单一位置；
                # 指向「今天读到末尾」是诚实的边界，假装指到某一行是造假。
                evidence=((today, today_lines),),
                note="表外＝(decision, action) 的关系不在这八档里，需人确认是新增裁决还是写错字段",
                items=items,
                key="verdict|out|" + "|".join(sorted(f"{t}/{d}/{a}" for (t, d, a) in out)),
                # 规模＝这些表外组合一共多少条记录。
                magnitude=sum(out.values()),
            )
        )
    if bad_val:
        items = tuple(f"{k}×{v}" for k, v in sorted(bad_val.items()))
        clues.append(
            Clue(
                kind="verdict",
                day=today,
                subject=(
                    f"裁决字段出现 {len(bad_val)} 个**值域外取值**（共 {sum(bad_val.values())} 条）"
                ),
                evidence=((today, today_lines),),
                note="值域变了 ⇒ 要么产品加了新裁决，要么字段被写坏；两者都要人看",
                items=items,
                key="verdict|badval|" + "|".join(sorted(bad_val)),
                # 规模＝值域外的取值一共出现多少条。
                magnitude=sum(bad_val.values()),
            )
        )
    return clues


# --------------------------------------------------------------------------- 日锚

# 日锚 = `day_manifest.json` 里逐日的 {size, last_hash, updated_at}。
# 它比「日文件存在」强，因为它记的是**写入那一刻的指纹**：
#   size 不符 -> 锚写完之后文件又被写过（追加／截断）
#   hash 不符 -> 末条记录被换掉了
#  有锚无文件 -> 文件被删了而锚还在 —— 这是**删除证据**，不是缺失。
#
# ★ 但它只是 L0，不是 L2（铁律 42）：锚与账本由**同一个进程**写。
#   整链重写会连锚一起重算，那时本工具仍报内部自洽。
#   能抓的只有「改完没重算」，所以措辞里不许出现「防篡改」。
ANCHOR_NO_HASH = "(无hash字段)"   # 记录连 hash 都没有，锚无处可挂（旧 schema）
ANCHOR_MISSING = "(有hash但无锚)"  # 有 hash 却没有清单条目 —— 事实，**不是**判定


def anchor_census(
    root: str, recs: List[Tuple[str, int, Dict[str, Any]]], as_of: str | None = None
) -> Dict[str, Any]:
    """逐日核对日锚。**只读**，零写入。

    末条 hash 从已经读进内存的 `recs` 里取（取该日最后一条带 hash 的记录），
    不再读一遍盘 —— 33 个日文件最大 13MB，重读是白花。

    `as_of` 只在**重放**时给：把日锚清单也截到那天，否则「重放 11-01」
    会把 11-02 的锚读成「账本文件不见了」—— 一个纯属量具的假线索。
    这类假线索在打分器里会被算成「金标准外」的误报，直接压掉精确率，
    而真实原因只是「重放没截干净」（铁律 22：先怀疑量具）。
    """
    man_path = os.path.join(root, "day_manifest.json")
    man: Dict[str, Any] = {}
    if os.path.exists(man_path):
        try:
            with open(man_path, "r", encoding="utf-8") as f:
                got = json.load(f)
            if isinstance(got, dict):
                man = got
        except Exception:
            man = {}
    if as_of:
        man = {
            k: v for k, v in man.items()
            if isinstance(k, str) and k[:10] <= as_of
        }

    # 该日最后一条带 hash 的记录
    last_hash: Dict[str, str] = {}
    lines_of: Dict[str, int] = collections.Counter()
    for day, _ln, r in recs:
        lines_of[day] += 1
        if r.get("__unparsed__"):
            continue
        h = r.get("hash")
        if isinstance(h, str) and h:
            last_hash[day] = h

    size_bad: List[Tuple[str, Any, int]] = []
    hash_bad: List[Tuple[str, str, str]] = []
    missing: List[Tuple[str, int, str]] = []
    anchored = 0
    # 当天文件还在写：**追加是正常的**，只有变短才是截断。
    # 不区分的话，报告每次都会把今天报成「被动过」—— 而每天都红的规则等于没有规则。
    # （产品侧 `verify_tail()` 对**所有**日子都只抓 `size < anchored`，见 tools/verify_chain.py:155；
    #  这里对已封盘的日子更严：要求**严格相等**，因为封盘后不该再长。）
    live = max(lines_of) if lines_of else ""
    for day in sorted(lines_of):
        name = f"{day}.jsonl"
        path = os.path.join(root, name)
        try:
            sz = os.path.getsize(path)
        except OSError:
            continue
        e = man.get(name)
        if not isinstance(e, dict):
            # 缺锚分两档：记录里有没有 hash，决定这是「无处可挂」还是「有 hash 却无锚」
            missing.append(
                (day, lines_of[day], ANCHOR_NO_HASH if day not in last_hash else ANCHOR_MISSING)
            )
            continue
        anchored += 1
        asz = e.get("size")
        if day == live:
            if isinstance(asz, int) and sz < asz:
                size_bad.append((day, asz, sz))
        elif asz != sz:
            size_bad.append((day, asz, sz))
        # 当天末条随时在变，比 hash 只会得到噪声 —— 只对已封盘的日子比。
        if day == live:
            continue
        ah, lh = e.get("last_hash"), last_hash.get(day)
        if isinstance(ah, str) and isinstance(lh, str) and ah != lh:
            hash_bad.append((day, ah[:12], lh[:12]))

    orphan = sorted(set(man) - {f"{d}.jsonl" for d in lines_of})
    return {
        "n_days": len(lines_of),
        "n_anchored": anchored,
        "n_manifest": len(man),
        "size_bad": size_bad,
        "hash_bad": hash_bad,
        "missing": missing,
        "orphan": orphan,
        "has_manifest": bool(man),
    }


def detect_anchor(
    ac: Dict[str, Any], today: str, today_lines: int, recent_days: set | None = None
) -> List[Clue]:
    """锚不符／锚孤儿／**新**缺锚，各报一条。缺锚两档分开说，不合报。

    ★ 缺锚只报**最近 N 天**的：旧缺锚（如 2026-10-05）是**状态**，不是事件 ——
    历史不会变，天天报就是恒红，而恒红的规则会稀释注意力（铁律 26／41）。
    旧缺锚仍进覆盖状态那一行（`anchor：… 缺锚 2 天 …`），只是不占每日清单的位置。
    """
    clues: List[Clue] = []
    ev = ((today, today_lines),)

    if ac["size_bad"] or ac["hash_bad"]:
        n = len(ac["size_bad"]) + len(ac["hash_bad"])
        parts = [f"{d} size {a}→{b}" for d, a, b in ac["size_bad"]]
        parts += [f"{d} 末条 hash {a}→{b}" for d, a, b in ac["hash_bad"]]
        clues.append(
            Clue(
                kind="anchor",
                day=today,
                subject=f"{n} 天的账本与日锚对不上（锚写完之后文件被改过）",
                evidence=ev,
                note=(
                    "只抓「改完没重算」，不是防篡改（锚与账本同一个进程写）；"
                    "但它是目前唯一能指出「哪一天被动过」的证据"
                ),
                items=tuple(parts),
                # 身份＝「哪几天对不上」。items 里带 size 的数值（每天在变），
                # 拿它当键会让同一条线索天天变成新的；这里只取日期集合。
                key="anchor|sizehash|" + "|".join(
                    sorted({d for d, _a, _b in ac["size_bad"]}
                           | {d for d, _a, _b in ac["hash_bad"]})
                ),
                # 规模＝几天对不上。
                magnitude=n,
            )
        )

    if ac["orphan"]:
        clues.append(
            Clue(
                kind="anchor",
                day=today,
                subject=f"日锚里有 {len(ac['orphan'])} 天的账本文件不见了",
                evidence=ev,
                note="锚在、文件没了 ⇒ 删除证据（不是「那天没有记录」）",
                items=tuple(ac["orphan"]),
                key="anchor|orphan|" + "|".join(sorted(ac["orphan"])),
                # 规模＝几个锚找不到对应文件。
                magnitude=len(ac["orphan"]),
            )
        )

    # 缺锚两档：只有「有 hash 却没挂」才算线索；「无 hash 字段」是数据形态不支持，
    # 报出来就是拿不可判定的东西当失败（铁律 45）。
    # 再加一道「只看最近 N 天」：旧缺锚是状态不是事件，天天报就变成恒红。
    real_miss = [
        (d, n)
        for d, n, kind in ac["missing"]
        if kind == ANCHOR_MISSING and (recent_days is None or d in recent_days)
    ]
    if real_miss:
        clues.append(
            Clue(
                kind="anchor",
                day=today,
                subject=f"{len(real_miss)} 天有 hash 却没有日锚",
                evidence=ev,
                note=(
                    "**事实，不是判定**：有 hash 只说明这条记录能挂锚，"
                    "没挂上是「漏了」还是「当时还没有调锚这个动作」，要看当日代码 —— "
                    "本工具读不到代码历史，所以只记事实（B 线 b9 已定性 2026-10-05 属后者）"
                ),
                items=tuple(f"{d}（{n} 行）" for d, n in real_miss),
                # 身份只取日期。items 里的「n 行」每天在长，带上它等于每天都是新线索。
                key="anchor|missing|" + "|".join(sorted(d for d, _n in real_miss)),
                # 规模＝缺了几天的锚。
                magnitude=len(real_miss),
            )
        )
    return clues


# --------------------------------------------------------------------------- 渲染


# 排序即产品判断，不是格式。
#   anchor 第一：账本与日锚对不上 ⇒ **下游一切读数都不可信**，先别看别的；
#   absent 第二：它多半意味着**产品自己坏了**（钩子挂了、规则被静默关掉），不是用户干了什么；
#   verdict 第三：口径变了（新增裁决／写错字段），要人确认，但通常不是事故；
#   gap    最低：日内断层大多只是「你去吃饭了」，它无法区分「停手」与「钩子断了」，
#          而这件事已经由 absent 用更准的方式问了 —— 同样的现象，更好的问句排在前面。
PRIORITY = {
    "anchor": 0,
    "absent": 1,
    "verdict": 2,
    "baseline": 3,
    "repeat": 4,
    "first_seen": 5,
    "rule_pair": 6,
    "gap": 7,
}


# --------------------------------------------------------------------------- 盲区自述

# 每个检测器都必须在 `main` 里申报自己的「覆盖状态」。
# 为什么是**机制**而不是一段手写文案：手写的盲区说明会和检测器一起漂 ——
# 加了新检测器、忘了改文案，报告就会继续说「我只查了这五件事」。
# 所以：键必须齐，缺一个就抛（见 `_coverage_selfcheck`），
# 且状态只能从下面这四种里取，不许自由发挥。
COVERAGE_KEYS = (
    "anchor", "absent", "verdict", "baseline", "repeat", "first_seen", "gap", "rule_pair",
)

RAN, EMPTY, FILTERED, UNDECIDABLE, SKIPPED = (
    "ran", "empty", "filtered", "undecidable", "skipped",
)
COV_MARK = {
    RAN: "查了",
    EMPTY: "查了，没有",
    # ★ 第五态（2026-11-02 补）：查了、有、但全部按常见物词表忽略了。
    #   与 EMPTY 的区别是「零」与「被压掉」的区别 —— 而这两者长得一模一样：
    #   报告上都只是「这个检测器没出线索」。压噪声的代价是**看不见压掉了什么**，
    #   所以被压掉的那部分必须有自己的名字，否则降噪就变成了静默删除。
    #   （同一条毛病在账本上叫「账本记成说过了而用户没看到」，两面一体。）
    FILTERED: "查了，有但按常见物忽略",
    UNDECIDABLE: "查了，判不了",
    SKIPPED: "没查",
}

# 结构性盲区：与具体检测器无关，是这份数据/这个工具**原理上**看不到的东西。
# 它们必须每次都出现，否则「没报」会被读成「没问题」。
BLIND_SPOTS = (
    ("账本以外的一切", "没被钩子拦到的动作不进账本；本工具只看得见账本"),
    ("记录内容对不对", "本工具只报「什么变了」，不判断是否危险、是否合规"),
    (
        "是否被整链重写",
        "日锚与账本由同一个进程写，整链重写会连锚一起重算 ⇒ 仍报内部自洽"
        "（要系统外的锚才算 L2；目前没有）",
    ),
    (
        "账本是否被整体替换",
        "换掉整天文件并同步改 day_manifest 的 size 与 hash，本工具看不出来",
    ),
    (
        "absent 的基线来自账本本身",
        "「某个钩子应该出现」这条判断，用的是**前 7 天的账本**算出来的中位数。"
        "删得比窗口更长，基线就跟着挪 —— 那个钩子「曾经存在」这件事从数据里"
        "消失，于是没有任何东西能发现它消失。这是**无界**盲区：删 3 天没事，"
        "删 8 天就干净了。redteam_c2.py R6 复现（对照 R7：不重算锚时 anchor 立刻报）。",
    ),
    (
        "锚只钉 size 与末条 hash",
        "anchor 比的是「文件字节数」和「最后一条记录的 hash」。改中间记录、"
        "长度不变、hash 字段没动 ⇒ anchor 零线索。redteam_c2.py R8 复现"
        "（平移 5 万行 ts，anchor 一声不响）。这一条 C-1 的 A1 能抓，"
        "所以是「C-2 单独看不见，整体不瞎」—— 两句话不许互换。",
    ),
    (
        "连链带锚一起重算就没有检测点",
        "redteam_c2.py R9 实测：删掉某 type 全期记录 ＋ 按文件重算链 ＋ 重算日锚 "
        "⇒ C-1 的 A1/A2/A3 全 PASS、C-2 的 anchor/absent 全静。"
        "这是实测不是推断。补法只有一条：账本之外的第二份记录（L2 外部锚），"
        "今天没有。任何说「防篡改」的话在这里被证伪。",
    ),
    (
        "删掉一整天在 A1/A2 上天生无痕",
        "链是按文件的（auditor.check_content 每个文件 prev_full 重起），"
        "所以整天文件消失时剩下的文件链一点都没断。只有 A3 的日清单管得着 —— "
        "那是 A3 存在的唯一理由，也是它的单点。",
    ),
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


def plain(text: str) -> str:
    """去掉 `**强调**` 的星号。

    ★ 这些字符串同时在三个地方被读：终端纯文本、JSON、以及被别的脚本摘走。
      写 `**` 只对 Markdown 有效，进纯文本就是两个多余字符 ——
      实测报告里印出过「这是**无界**盲区」，读起来像排版事故。
      同一个字符串被多个消费者读，就得挑**每个消费者都成立**的字面。
    """
    return text.replace("**", "")


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
        # ★ 「没有需要你看的」是一句**事实断言**，只有在真的没有时才成立。
        #   账本压掉的那几条不是「没有」，是「说过了／静默了」—— 说成「没有」
        #   就是零与不可判同貌的又一处出口：读者从此无法区分
        #   「今天真没事」和「今天有事但被压掉了」。
        lc = meta.get("ledger_counts") or {}
        n_said = int(lc.get("said_today", 0) or 0)
        n_mute = int(lc.get("muted", 0) or 0) + int(lc.get("acked", 0) or 0)
        if n_said or n_mute:
            bits = []
            if n_said:
                bits.append(f"{n_said} 条今天已经说过")
            if n_mute:
                bits.append(f"{n_mute} 条在静默或已按你的确认闭嘴")
            lines.append(
                f"今天记了 {today_n:,} 条，**没有新的**要看（{'、'.join(bits)}；"
                f"明细见下方「账本」一行）。{legacy_note}"
            )
        else:
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
        f" 读数 {meta.get('read_at', '—')}｜"
        f"日文件 {meta['files']}｜记录 {meta['records']:,}｜不可解析 {meta['unparsed']}｜"
        f"基线窗口 {meta['window']} 天｜首次出现窗口 {recent} 天｜规则配对 {rp_state}"
    )
    # ★ 重放必须自报。用 `--as-of` 跑出来的报告与「今天」的报告长得一模一样，
    #   唯一区别就是这一行。不印出来，读者会把历史结论当今日结论 ——
    #   这正是 F40 那一类（数都对，分母不是那个分母）。
    if meta.get("as_of"):
        lines.append(
            f"—— 重放 —— 账本截到 {meta['as_of']}（**这不是今天的读数**："
            f"「今天」= {meta['today']}，是截断后的最后一天，不是挂钟今天）"
        )
    # —— 账本口径 ——
    # ★ 这一行不是装饰：被静默／被顺延的条数如果不出现在报告里，
    #   读者就无法区分「没事」和「被压掉了」。恒红线索天天占位与恒绿判据
    #   进清单是同一个毛病，而两者的修法都必须是**把压掉的量说出来**，
    #   不是把压掉的动作藏起来（铁律 41 的正向应用）。
    if meta.get("ledger_note"):
        lines.append(f"—— 账本 —— {meta['ledger_note']}")
    lines.append("")

    # —— 裁决口径 ——
    # 这一行不是装饰：协同说明坑 1 的代价，就是有人拿「52.9% 的记录没有 decision」
    # 当结论报出去。真实原因是**两套字段并存** —— 执行侧把裁决记在 action 里。
    # 所以这里每次都把两个字段的条数并排印出来，让读者不必自己推。
    vd = meta.get("verdict") or {}
    if vd.get("rel"):
        ac_ = meta.get("anchor") or {}
        rel_txt = "／".join(f"{k} {v:,}" for k, v in vd["rel"].items() if v)
        lines.append(f"—— 裁决口径 —— {rel_txt}")
        lines.append(
            f"   decision 有值 {vd.get('n_decision', 0):,}｜action 有值 "
            f"{vd.get('n_action', 0):,}｜表外 {vd.get('n_out', 0)}｜"
            f"值域外 {vd.get('n_bad_value', 0)}"
        )
        lines.append(
            "   两套字段并存：post_tool_use 没有 decision，裁决记在 action=record 里 ⇒"
            " 只按 decision 分桶会把执行侧整类漏掉。「放行但告警」不是矛盾，是"
            "「放行但又告警」；「同义两词」是 deny 与 block 命名未收敛。"
        )
        n_no_dec = meta.get("records", 0) - vd.get("n_decision", 0)
        n_all = meta.get("records", 0)
        lines.append(
            f"   没有 decision 的 {n_no_dec:,} 条 = 执行侧 {vd['rel'].get(REL_EXEC, 0):,}"
            f"（裁决在 action 里）+ 无裁决 {vd['rel'].get(REL_NONE, 0):,}"
            f"（usage_delta／session_dna 本来就没有裁决）⇒ 这是**适用面不同**，不是字段缺失；"
            f"报成「{n_no_dec / n_all * 100:.1f}% 的记录没有 decision」是错的。"
        )
        if ac_.get("n_days"):
            lines.append(
                f"   日锚 {ac_.get('n_anchored', 0)}/{ac_.get('n_days', 0)} 天"
                f"（size 与末条 hash 都对得上）；锚只抓「改完没重算」，不是防篡改。"
            )
        lines.append("")
    lines.extend(render_coverage(coverage))
    lines.append("本报告只陈述「什么变了」，不判断是否危险。")
    return "\n".join(lines)


#: 哪些线索值得**主动弹到屏幕上**。目前只有一种。
#:
#: ★ 为什么只有 `rule_pair`（2026-11-03，D-4 落地时的取舍）：
#:   · `held`（挡下）**不推**：产品侧在**拦截的那一刻**已经弹过了
#:     （`host_shield.bubble_decision` 那套五条闸）。C 线事后再弹一次，
#:     用户收到的是同一件事的第二种说法 —— 那是重复打扰，不是主动性。
#:     主动性的定义是「指向未被注意的事」，不是「把已知的事再说一遍」。
#:   · `baseline`／`repeat`／`absent` 不推：它们说的是「量和昨天不一样」，
#:     读者要看到对比才明白，一句话说不清 —— 一页纸里有它们的位置。
#:   · `rule_pair` 推，因为它是**产品侧实时通道永远看不见的那一类**：
#:     单次拦截是实时的事实，而「这两条规则今天连着响了、以前从没连过」
#:     只有在时间维度上才成立。**这是 C 线的独占价值**，
#:     也应该是它唯一有资格打扰用户的理由。
NOTIFY_KINDS = ("rule_pair",)

#: 推送用的级别。**必须是产品侧 `URGENT_LEVELS` 里的值，不许自造。**
#: `L2` ＝「有操作被拦下（未处理）」—— 一条新组合确实意味着有操作被拦下，
#: 而且是连着两次。用 `R0`（防线没生效）会把强度说高：
#: **拦截是成功的，防线没有失效。** 对外强度不许超过内部定性（F55）。
NOTIFY_LEVEL = "L2"

#: 节流键。**必须与产品侧的键分开。**
#: 产品侧按它自己的 `kind` 节流（`bubble:<kind>`）；共用键会让两边互相抑制：
#: 要么产品侧刚弹过、C 线永远弹不出来；要么反过来，C 线弹过之后
#: 产品侧的真告警被静音。两种都是**静默故障**，且都表现为「本来就没那么多事」。
NOTIFY_KIND = "c_line_pair"


def push_clue(clue: "Clue", *, root: str | None = None,
              pop: Any = None) -> Dict[str, Any]:
    """把一条线索推到**产品侧弹窗通道**。不新造通道，也不新造级别。

    返回 dict，`ok` 只在窗口真就位时为 True —— 与 `inbox_bubble.pop` 同一契约。

    ★ `pop` 可注入：判据要能在**不起真窗口**的前提下验完整条链。
      不注入的话，自检会去碰真桌面，而桌面上可能真开着提醒窗 ⇒
      判据被现实污染（假红或假绿，看起来一模一样）。
    ★ 一切失败都**如实返回、不抛**：巡检的主体是出一页纸，
      弹不出来不等于巡检失败 —— 但它必须说出来，否则就是
      「系统自己知道有事，却什么都没说」。
    """
    rep: Dict[str, Any] = {"ok": False, "sent": False, "why": "", "raw": None}
    if clue.kind not in NOTIFY_KINDS:
        rep["why"] = "这一类不主动弹（只有 %s 值得打扰）" % "/".join(NOTIFY_KINDS)
        return rep
    if pop is None:
        try:
            if _REPO not in sys.path:
                sys.path.insert(0, _REPO)
            import inbox_bubble as BB  # noqa: PLC0415  产品侧通道，延迟导入
            pop = BB.pop
        except Exception as exc:                       # noqa: BLE001
            rep["why"] = "弹窗通道不可用（%s: %s）" % (type(exc).__name__, exc)
            return rep
    try:
        r = pop(title="发现一条新的动作组合",
                body=str(clue.subject)[:120],
                level=NOTIFY_LEVEL, kind=NOTIFY_KIND, root=root)
    except Exception as exc:                           # noqa: BLE001
        rep["why"] = "弹窗调用异常（%s: %s）" % (type(exc).__name__, exc)
        return rep
    rep["sent"] = True
    if isinstance(r, dict):
        rep["raw"] = r
        rep["ok"] = bool(r.get("ok"))
        rep["why"] = str(r.get("why") or "")
    else:
        rep["why"] = "弹窗返回了非 dict：%r" % (r,)
    return rep


def _selfcheck() -> int:
    """watchman 自检：只测两件事 —— **配置读得到**、**链的判据能翻面**。

    ★ 为什么需要它（2026-11-03）：`RULES_PATH` 曾经是**相对 cwd** 的。
      从 `output/lineC/` 里跑就读不到 `rules/default.json` ⇒ `_CUR_IDS` 与
      `_CUR_CAT` 双双为空 ⇒ 两处过滤**同时静默失效**：
        · 非规则号（`OUT-01`）混进配对 —— N-04 的老毛病复发；
        · 跨簇噪声（`AN-001→AN-010`）全部回来 —— N-05 复发。
      实测同一份账本：仓库根跑报 3 条；`output/lineC` 跑报 4 条且带 `OUT-01`。
    ★ 它不报错、不警告，只是**多报** —— 而「多报」在报告里看起来像「检测器很灵敏」。
      所以这条自检必须能翻面：**规则库读不到时它要变红**，不能永远清白。
    """
    fails: List[str] = []

    def ck(ok: bool, msg: str) -> None:
        if not ok:
            fails.append(msg)

    # ① 配置必须读得到（路径基准必须与 cwd 无关）
    ck(os.path.isfile(RULES_PATH),
       "规则库读不到：%s —— 两处过滤会静默失效（只多报、不报错）" % RULES_PATH)
    _ensure_alias()
    ck(bool(_CUR_IDS), "规则号集合为空 —— 非规则号不会被过滤（N-04 会复发）")
    ck(bool(_CUR_CAT), "category 集合为空 —— 意图簇过滤静默失效（N-05 会复发）")

    # ② 分簇必须与规则库一致。**期望的簇从规则库的 category 现取**，
    #   不在这里写死中文名（写死了产品侧改分类也不会红）。
    for _rid in ("AN-001", "AN-002", "AN-005", "AN-010", "AN-014"):
        ck(bool(chain_cluster(_rid)), "%s 没有簇 —— 它不会参与链判定" % _rid)
    ck(chain_cluster("AN-001") == chain_cluster("AN-002"),
       "AN-001 与 AN-002 同属 secrets，簇却不一致")
    ck(chain_cluster("AN-001") != chain_cluster("AN-010"),
       "AN-001(secrets) 与 AN-010(destructive) 簇相同 —— 分簇表配错了")

    # ③ 可翻面：同簇的配对要留下，跨簇的要滤掉。
    #    每对只凑 3 次 —— 正好卡在 `max_today`（默认 3）上，多一次会被上界滤掉，
    #    那时「没报」就不能证明是簇过滤起作用了（假绿）。
    _mins = [0, 1, 20, 21, 40, 41]

    def _mk(rid_a: str, rid_b: str, sess: str) -> List[Tuple[str, int, Dict[str, Any]]]:
        out: List[Tuple[str, int, Dict[str, Any]]] = []
        for k, m in enumerate(_mins):
            rid = rid_a if k % 2 == 0 else rid_b
            out.append(("2026-01-01", k + 1,
                        {"ts": "2026-01-01T10:%02d:00+08:00" % m,
                         "session": sess, "rules_hit": [rid],
                         "decision": "block"}))
        return out

    def _pairs(recs: List[Tuple[str, int, Dict[str, Any]]]) -> set:
        cl, _st = detect_rule_pairs(recs, recent=1)
        return {"→".join(c.items) for c in cl}

    _got_same = _pairs(_mk("AN-001", "AN-002", "sc-same"))
    _got_cross = _pairs(_mk("AN-005", "AN-010", "sc-cross"))
    ck("AN-001→AN-002" in _got_same,
       "同簇配对 AN-001→AN-002 被滤掉了 —— 过滤条件写反了：%r" % (_got_same,))
    ck("AN-005→AN-010" not in _got_cross,
       "跨簇配对 AN-005→AN-010 没被滤掉 —— 噪声会照旧报出来：%r" % (_got_cross,))
    # ★ 负控：把簇表清空 ⇒ 跨簇配对**必须回来**。
    #   不回来就说明「没报」是别的原因（比如门槛把它挡了），这条判据是死的。
    _saved = dict(_CHAIN_CLUSTER)
    try:
        _CHAIN_CLUSTER.clear()
        _got_off = _pairs(_mk("AN-005", "AN-010", "sc-cross"))
    finally:
        _CHAIN_CLUSTER.update(_saved)
    ck("AN-005→AN-010" in _got_off,
       "清空簇表后跨簇配对仍不报 —— 说明它本来就被别处挡掉了，"
       "上面那条「滤掉了」证明不了任何事：%r" % (_got_off,))

    # ④ 主动推送：只弹该弹的，失败必须如实说（2026-11-03，D-4）
    _calls: List[Dict[str, Any]] = []

    def _fake_pop(**kw: Any) -> Dict[str, Any]:
        _calls.append(kw)
        return {"ok": True, "why": ""}

    _pair = Clue(kind="rule_pair", day="2026-01-01", subject="x",
                 evidence=(("2026-01-01", 1),), note="",
                 items=("AN-001", "AN-002"))
    _held = Clue(kind="verdict", day="2026-01-01", subject="y",
                 evidence=(("2026-01-01", 2),), note="", items=("AN-009",))
    _r1 = push_clue(_pair, pop=_fake_pop)
    ck(_r1["ok"], "rule_pair 该弹却没弹：%r" % (_r1,))
    ck(bool(_calls) and _calls[0].get("level") == NOTIFY_LEVEL,
       "弹窗级别不是产品侧的 %s（自造级别＝对外强度虚高）：%r"
       % (NOTIFY_LEVEL, _calls))
    ck(bool(_calls) and _calls[0].get("kind") == NOTIFY_KIND,
       "节流键与产品侧撞了 —— 两边会互相静音：%r" % (_calls,))
    _before = len(_calls)
    _r2 = push_clue(_held, pop=_fake_pop)
    ck(not _r2["ok"] and not _r2["sent"],
       "「挡下」这类不该主动弹（产品侧在拦截那一刻已经弹过了）：%r" % (_r2,))
    ck(len(_calls) == _before,
       "不该弹的那一类仍然调用了 pop —— 重复打扰就是这么来的")
    # 负控①：通道报失败 ⇒ 必须如实转述，不许说成成功
    _r3 = push_clue(_pair, pop=lambda **kw: {"ok": False, "why": "通道忙"})
    ck(not _r3["ok"] and "通道忙" in _r3["why"],
       "弹窗失败时没如实转述：%r" % (_r3,))
    # 负控②：通道抛异常 ⇒ 不许把巡检带崩，但必须说出来
    def _boom(**kw: Any) -> Dict[str, Any]:
        raise RuntimeError("炸了")

    _r4 = push_clue(_pair, pop=_boom)
    ck(not _r4["ok"] and "炸了" in _r4["why"],
       "弹窗抛异常时没接住（会让整次巡检崩掉）：%r" % (_r4,))

    if fails:
        print("自检失败 %d 项：" % len(fails))
        for f in fails:
            print("  ·", f)
        return 1
    # ★ 不写条数：条数会随臂的增减而漂，而文案没人会同步改
    #   （「注释里的数字会过期」——本文件已经因为这句话吃过一次亏）。
    print("watchman 自检：全部通过（规则库可读／分簇与规则库一致／"
          "同簇配对留下／跨簇配对滤掉／负控能翻面／"
          "只有 rule_pair 推送／级别与节流键不自造／失败如实转述）")
    return 0


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="巡检 Agent 档 1 原型（只读）")
    ap.add_argument("--root", default=".psl/audit")
    ap.add_argument("--selfcheck", action="store_true", help="自检（不读账本）")
    ap.add_argument(
        "--notify",
        action="store_true",
        help="把「新出现的动作组合」弹到屏幕上。**默认关闭**。"
        "只有 rule_pair 会弹（产品侧已经在拦截那一刻弹过「挡下」，"
        "本模块再弹一次就是重复打扰）。走产品侧 inbox_bubble.pop，"
        "级别用产品侧的 L2，不自造。",
    )
    ap.add_argument("--window", type=int, default=14)
    ap.add_argument("--recent", type=int, default=1, help="只报最后几天（主动报告默认只看今天）")
    ap.add_argument(
        "--as-of",
        default=None,
        metavar="YYYY-MM-DD",
        help="把账本截到这一天（含）为止再算，用于**重放历史某天**。"
        "★ 存在的唯一理由是让金标准可复核：noise_baseline.json 是某一天实跑的"
        "快照，若只能跑「今天」，那么金标准每天都在过期，打分器报的「召回 0%%」"
        "既可能是代码退化、也可能只是换了采样日 —— 两者在报告上长得一模一样。"
        "加上这个开关，「拿今天的代码跑昨天的数据」才成为可能，"
        "金标准的可比性才不依赖运气。",
    )
    ap.add_argument("--min-each", type=int, default=3)
    ap.add_argument(
        "--with-gap",
        action="store_true",
        help="启用日内断层检测。**默认关闭**（2026-11-02 决策）。"
        "理由：实测 gap 报的是作息不是异常 —— 阈值 30 分钟时一天报 5 条，"
        "内容全是 00:50–06:10 之间的整点空隙，也就是这个人在睡觉；"
        "阈值 90 分钟时一条不报，不是「调对了」，是刚好把睡眠挡住。"
        "而「某个钩子挂了」这件事由 absent 用更准的量具抓（日级出现频次，"
        "不是小时级间隙）。**gap 报作息，absent 报故障。**"
        "留着 gap 只是让报告多一个会说谎的量具，所以关掉而不是调参。",
    )
    ap.add_argument(
        "--gap-min",
        type=float,
        default=90.0,
        help="日内断层阈值（分钟）。只在 --with-gap 时生效。"
        "★ 2026-11-01 从 30 提到 90；2026-11-02 起该检测器默认关闭。"
        "**这个数是拍的，不是算的**——原计划的『按前 7 天同段作息抑制』已被证伪："
        "这个人没有稳定作息（见结果文档 §4）。",
    )
    ap.add_argument("--cap", type=int, default=5, help="主动报告上限（注意力预算）")
    ap.add_argument("--repeat-min", type=int, default=3, help="「第二次才算数」的重复门槛")
    ap.add_argument("--pair-gap", type=float, default=5.0, help="规则配对的会话内时间窗（分钟）")
    ap.add_argument("--pair-max", type=int, default=3, help="组合当天出现次数上界（超过算新常态）")
    ap.add_argument("--json", action="store_true", help="输出 JSON（供负控断言用）")
    ap.add_argument(
        "--no-benign",
        action="store_true",
        help="关掉常见物词表（负控 NC4：被忽略的必须全部回来）",
    )
    ap.add_argument(
        "--no-ledger",
        action="store_true",
        help="关掉线索账本（退回一次性：同一条线索会天天出现）",
    )
    ap.add_argument(
        "--ledger",
        default=None,
        help="账本路径（默认 lineC/_watchman_ledger.json，**不写进 .psl/audit**）",
    )
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")  # 中文 Windows 控制台
    except Exception:
        pass

    # ★ 自检必须**在检查账本目录之前**：它不读账本，
    #   而「配置读得到吗」这件事与账本在不在没关系。
    #   放在目录检查之后，会让没有账本的机器上报「目录不存在」而不是「配置坏了」——
    #   归因错了，修的人就会去建目录。
    if args.selfcheck:
        return _selfcheck()

    # ★ `--json` 是取证通道，**必须无副作用**（取证时反复跑，不能改变推送节奏）。
    #   所以两者同时给时直接拒绝，而不是「悄悄忽略一个」——
    #   悄悄忽略会让脚本以为弹过了，而屏幕上什么都没有。
    if args.notify and args.json:
        print("[停] --notify 与 --json 不能同时用：--json 必须无副作用",
              file=sys.stderr)
        return 2

    if not os.path.isdir(args.root):
        print(f"[停] 目录不存在：{args.root}", file=sys.stderr)
        return 2

    # ★ 本工具把**整本账读进内存**（173k 条实测约数百 MB）。这是已知的规模上限，
    #   不是 bug，但**必须说成「读不完」而不是裸 traceback**：
    #   2026-11-01 深夜实测撞过一次 `MemoryError` —— 当时总闸门正在跑
    #   `_p_c2_negctl.py`（它复制 16 个日文件），我又并发跑了几个 watchman。
    #   裸 traceback 会让人以为「代码坏了」，而真实原因是「内存不够，等一下再跑」。
    #   两种原因的处理方式完全不同，所以要在出口处把它们分开。
    try:
        recs = list(iter_records(args.root))
    except MemoryError:
        print(
            f"[停] 读不完：{args.root} 的记录装不进内存（本工具全量载入，无流式）。\n"
            "      这不是账本坏了，是本次可用内存不够 —— 常见原因：同时还在跑别的"
            "重活（总闸门的负控会复制整份账本做夹具）。\n"
            "      处置：等别的任务跑完再试；或用 --window 缩小窗口（不减少读入量，"
            "只减少后续计算）。",
            file=sys.stderr,
        )
        return 3
    if not recs:
        print(f"[停] {args.root} 里没有任何日文件记录", file=sys.stderr)
        return 2

    # ★ --as-of：把账本截到某天为止。**截在载入之后、一切计算之前**，
    #   这样「今天」(`max(daily)`)、同期 cutoff、基线窗口、最近 N 天
    #   全部自动跟着走 —— 一处过滤，不必在八个检测器里各改一遍
    #   （铁律：同一件事只许有一处定义，八处各写一份必然漂）。
    #   注意它截的是「哪一天的记录参与计算」，不是「报哪一天」；
    #   报哪一天仍由 --recent 决定。两个旋钮不许合并。
    if args.as_of:
        if len(args.as_of) != 10 or args.as_of[4] != "-" or args.as_of[7] != "-":
            print(f"[停] --as-of 要 YYYY-MM-DD：{args.as_of!r}", file=sys.stderr)
            return 2
        before = len(recs)
        earliest = min(r[0] for r in recs)
        recs = [r for r in recs if r[0] <= args.as_of]
        if not recs:
            print(
                f"[停] --as-of {args.as_of} 之后一条记录都不剩"
                f"（账本最早一天是 {earliest}，共 {before} 条）。"
                "这不是「那天没问题」，是「那天没数据」—— 两者必须分开说。",
                file=sys.stderr,
            )
            return 2
    # 报数规矩（协同说明 §七）：任何条数必须带读取时刻 —— 账本 30 天滚动，
    # 明天必不同。这里记的是**读完那一刻**，不是报告生成那一刻，两者差几秒也是差。
    read_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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

    # 锚先算：它决定「下游读数可不可信」。锚坏了而先报别的，等于在坏尺子上量东西。
    ac = anchor_census(args.root, recs, as_of=args.as_of)
    all_days = sorted(per_type)
    recent_days = set(all_days[-args.recent:]) if args.recent > 0 else set(all_days)
    got = detect_anchor(ac, today, today_lines, recent_days)
    clues += got
    n_miss_nohash = sum(1 for _d, _n, k in ac["missing"] if k == ANCHOR_NO_HASH)
    n_miss_real = sum(1 for _d, _n, k in ac["missing"] if k == ANCHOR_MISSING)
    n_miss_old = sum(
        1 for d, _n, k in ac["missing"] if k == ANCHOR_MISSING and d not in recent_days
    )
    coverage["anchor"] = {
        "status": RAN if got else EMPTY,
        "note": (
            f"{ac['n_anchored']}/{ac['n_days']} 天有锚；缺锚 {len(ac['missing'])} 天"
            f"（无 hash 字段 {n_miss_nohash}／有 hash 无锚 {n_miss_real}"
            + (f"，其中 {n_miss_old} 天不在最近 {args.recent} 天 ⇒ 只计数不上报" if n_miss_old else "")
            + f"）；size 不符 {len(ac['size_bad'])}、末条 hash 不符 {len(ac['hash_bad'])}、"
            f"锚孤儿 {len(ac['orphan'])}"
        ),
    }

    got = detect_absent(per_type, today, cutoff, today_lines)
    clues += got
    coverage["absent"] = {
        "status": RAN if got else EMPTY,
        "note": f"前 7 天里 >=5 天出现且中位数 >=3 的 type；口径 {scope}",
    }

    vc = verdict_census(recs)
    got = detect_verdict(vc, today, today_lines)
    clues += got
    n_rel = {k: v for k, v in vc["rel"].items() if v}
    coverage["verdict"] = {
        "status": RAN if got else EMPTY,
        "note": (
            f"{vc['records']:,} 条按 (type, decision, action) 分档，"
            f"{len(n_rel)} 档有数、表外 {vc['rel'][REL_OUT]}；"
            f"decision 有值 {vc['n_decision']:,}／action 有值 {vc['n_action']:,}"
            f"（差额是执行侧：裁决记在 action 里）"
        ),
    }

    got = detect_baseline(daily_cut, window=args.window, recent=args.recent, cutoff=cutoff)
    clues += got
    coverage["baseline"] = {
        "status": RAN if got else EMPTY,
        "note": f"前 {args.window} 天同期中位数＋MAD（3 倍）；口径 {scope}",
    }

    stats = _item_stats(recs)
    benign = None if args.no_benign else load_benign()
    got, used, rep_skip = detect_repeat(
        stats, today, min_count=args.repeat_min, benign=benign
    )
    clues += got
    _bn_note = _benign_note(benign, rep_skip)
    _n_rep_skip = sum(rep_skip.values()) if rep_skip else 0
    coverage["repeat"] = {
        # 有线索 ⇒ RAN；没线索但压过 ⇒ FILTERED（不是「没有」）；都没 ⇒ EMPTY
        "status": RAN if got else (FILTERED if _n_rep_skip else EMPTY),
        "note": f"当天首次出现且当天 >= {args.repeat_min} 次" + _bn_note,
    }

    got, fs_counts, fs_skip = detect_first_seen(
        stats, recent=args.recent, exclude=used, benign=benign
    )
    clues += got
    _n_fs_skip = sum(fs_skip.values()) if fs_skip else 0
    coverage["first_seen"] = {
        "status": RAN if got else (FILTERED if _n_fs_skip else EMPTY),
        "note": (
            f"全期窗口／只报最后 {args.recent} 天；已剔除 repeat 报过的 {len(used)} 项"
            + _benign_note(benign, fs_skip)
        ),
    }

    # ★ 2026-11-02 决策：gap 默认关闭。覆盖状态必须说「没查」而不是「查了没有」，
    #   并且要说清「为什么没查」—— 「按决策关闭」与「还没实现」在报告上都长得像
    #   「这一项没有输出」，但前者是结论，后者是欠账。混为一谈就是铁律 31 的反面。
    gc = gap_census(recs)
    if args.with_gap:
        got, n_routine = detect_gap(
            recs, threshold_min=args.gap_min, recent=args.recent
        )
        clues += got
        # ★ 覆盖状态不能只看「有没有线索」。一条 ts 都不可解析时，
        #   报「查了，没有」是把**没查成**说成了**查了没有** —— 零与不可判同貌。
        #   红队 R5 现场：把 ts 全抹成空串，修完崩溃之后 gap 报的正是「查了，没有」。
        coverage["gap"] = {
            "status": (
                UNDECIDABLE if gc["with_ts"] == 0 else (RAN if got else EMPTY)
            ),
            "note": (
                f"阈值 {args.gap_min:g} 分钟；带可解析 ts 的记录 {gc['with_ts']:,} 条"
                f"／共 {gc['total']:,} 条"
            ),
        }
    else:
        coverage["gap"] = {
            "status": SKIPPED,
            "note": (
                "按 2026-11-02 决策关闭（--with-gap 可开）。"
                "实测它报的是作息不是异常：阈值 30 分钟时一天报 5 条，"
                "全是 00:50–06:10 的整点空隙；阈值 90 分钟时一条不报，"
                "不是调对了而是刚好把睡眠挡住。「钩子挂了」由 absent 抓"
                f"（日级频次，不是小时级间隙）。分母仍算清：带可解析 ts 的记录 "
                f"{gc['with_ts']:,} 条／共 {gc['total']:,} 条"
            ),
        }

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

    # ------------------------------------------------------------------ 线索账本
    # ★ 账本**只作用于主动推送（文本出口）**，不作用于 `--json`。
    #   这不是偷懒，是分工：
    #     · 文本出口＝它自己开口找你 ⇒ 主动性 ⇒ 必须压节奏（同一条别天天说）；
    #     · `--json` 是取证／内部读数，是**你问它**才出的 ⇒ 响应性 ⇒ 必须完整。
    #   在响应式出口上做静默，等于「你问它，它还替你筛」——那是另一种欺骗。
    #   但 JSON 里会带 `ledger` 块说明「如果推送，会压掉几条」，让这个差别看得见。
    #
    # ★ 记账顺序是硬不变量：annotate → plan → render → commit(shown)。
    #   在 render 之前 commit，就是「记成说过了而用户没看到」= 永久静默。
    ledger = None
    annotated = None
    ledger_path = None
    ledger_error = None
    ledger_notice = None
    # ★ 身份（clue_key）与账本的开关**是两件事**：`--no-ledger` 关掉的是「记忆」，
    #   不是「这条线索叫什么」。所以模块总是导入，JSON 出口永远能给出稳定的 key ——
    #   否则「同一件事」这件事本身就成了可选项。
    import clue_ledger as CL  # noqa: N813

    # 机制层守自己：新加检测器忘了写 `key` 时，不许静默退回「按 kind 猜」。
    # 这条检查来自真事：本文件第一版按 `kind|day` 猜身份，同一天的 8 个 gap
    # 全算成同一个键（账本自检第 8 臂）。猜出来的身份看不出来是猜的。
    _no_key = sorted({c.kind for c in clues if not c.key})
    if _no_key:
        print("[警告] %d 类线索没声明身份 key：%s ⇒ 已退回按 kind/day 推导，"
              "可能把不同的事合并成一条" % (len(_no_key), "、".join(_no_key)),
              file=sys.stderr)

    if not args.no_ledger:
        ledger_path = args.ledger or CL.DEFAULT_PATH
        ledger = CL.load(ledger_path)
        # ★ error 与 notice 必须分开：error 是「这次读不了」⇒ 不用账本；
        #   notice 是「一次性历史事件」⇒ 照常用，只是要说一句。
        #   第一版把两者合并，结果 key_version 提示让账本永久不可用、
        #   永远不保存、提示天天重复 —— 一次性的历史事件被写成了恒红状态。
        ledger_error = ledger.get("ledger_error")
        ledger_notice = ledger.get("ledger_notice")
        if ledger_error is None:
            try:
                annotated = CL.annotate(clues, ledger, today)
            except CL.KeyCollision as exc:
                # 撞键是**检测器的 bug**，不是数据的问题。不许把报告带下去：
                # 崩溃的表现是「没有那条记录」，比报错更难发现（铁律 45）。
                # 但也不许静默降级 —— 降级本身要出现在报告里。
                annotated = None
                ledger_error = "撞键：%s" % str(exc).splitlines()[0]

    today_records = sum(1 for d, _, r in recs if d == today and not r.get("__unparsed__"))
    meta = {
        "today": today,
        "today_records": today_records,
        "read_at": read_at,
        # ★ 重放标记：`as_of` 非空时，这份报告算的是「截至那天的账本」，
        #   不是「今天的账本」。分母必须跟着变 —— 否则「日文件 35」配
        #   「记录 173,647」会让人以为丢了 4 千条（F40：一句话两个分母）。
        "as_of": args.as_of,
        "files": (
            len({d for d, _, _ in recs}) if args.as_of else len(day_files(args.root))
        ),
        "records": len(recs),
        "unparsed": unparsed,
        "window": args.window,
        "baseline_cutoff": cutoff,
        "pair_stats": pair_stats,
        "rule_census": rule_id_census(args.root),
        "anchor": ac,
        "verdict": {
            "rel": vc["rel"],
            "n_decision": vc["n_decision"],
            "n_action": vc["n_action"],
            "n_out": vc["rel"][REL_OUT],
            "n_bad_value": sum(vc["bad_value"].values()),
        },
    }
    if args.json:
        import json as _json

        # JSON 出口：**不抑制、不记账**，但把「若推送会怎样」算出来一并给出。
        # 纯读 —— `--json` 不该有副作用（取证时反复跑，不能改变推送节奏）。
        st_map: Dict[int, str] = {}
        led_block: Dict[str, Any] = {"path": ledger_path, "error": ledger_error,
                                      "notice": ledger_notice}
        if annotated is not None:
            st_map = {id(c): st for c, _k, st, _e in annotated}
            try:
                _s, _d, _sup = CL.plan(annotated, args.cap, PRIORITY)
                led_block.update(
                    {
                        "n_would_say": len(_s),
                        "n_would_defer": len(_d),
                        "n_suppressed": len(_sup),
                        "note": CL.render_note(annotated, _s, _d, ledger_error, ledger_notice),
                    }
                )
            except Exception as exc:                            # noqa: BLE001
                led_block["error"] = "plan 失败：%s: %s" % (type(exc).__name__, exc)
        elif ledger_error:
            led_block["note"] = "账本不可用：%s" % ledger_error
        if args.no_ledger:
            led_block["note"] = "账本已关闭（--no-ledger）：本读数与推送完全一致"

        print(
            _json.dumps(
                {
                    "meta": meta,
                    "coverage": coverage,
                    # ★★ 盲区必须随 JSON 出去。第一版**没有这个键**，于是
                    #    `evidence.collect` 里那段 `for b in watch.get("blind_spots")`
                    #    从来没有执行过一次 —— 本文件写下的 8 条盲区一条都没进过报告，
                    #    而报告那一节照样有内容（auditor 的 5 条），读起来毫无异样。
                    #    这正是本项目刚学到的：**「从没被执行过的分支」与「写对了的
                    #    分支」在代码里长得一模一样**，区别只在有没有人从外面数一遍。
                    #    自检抓不到它，因为自检跑的是 render()，不是 JSON 出口。
                    "blind_spots": [{"title": t, "detail": d} for t, d in BLIND_SPOTS],
                    "ledger": led_block,
                    "clues": [
                        {
                            "kind": c.kind,
                            "day": c.day,
                            "subject": c.subject,
                            "evidence": c.evidence,
                            "note": c.note,
                            "items": list(c.items),
                            # 身份与推送状态一起出去：读者才能自己核对
                            # 「这条为什么没出现在推送里」。
                            "key": CL.clue_key(c),
                            "ledger_state": st_map.get(id(c)),
                            # ★ v3 遗留项（2026-11-03 补）：**取证时要的是
                            #   「这条变了没有」，不是「它叫什么」**。
                            #   `key` 只回答「是不是同一件事」；指纹回答
                            #   「同一件事的内容变了没有」—— 两者不可互换，
                            #   缺了后者，取证时只能靠肉眼比对两个 subject。
                            #   `magnitude` 一并给：指纹就是 items＋量级算出来的，
                            #   只给指纹、不给被哈希进去的那个量级，等于给结论不给依据。
                            "fingerprint": CL.clue_fingerprint(c),
                            "magnitude": int(getattr(c, "magnitude", 0) or 0),
                        }
                        for c in sorted(clues, key=lambda x: PRIORITY.get(x.kind, 9))
                    ],
                },
                ensure_ascii=False,
                indent=1,
            )
        )
        return 0

    # ---------------------------------------------------------------- 主动推送
    if annotated is not None:
        shown, deferred, suppressed = CL.plan(annotated, args.cap, PRIORITY)
        meta["ledger_note"] = CL.render_note(annotated, shown, deferred,
                                             ledger_error, ledger_notice)
        _n = CL.counts(annotated)
        meta["ledger_counts"] = {
            "new": _n[CL.NEW],
            "ongoing": _n[CL.ONGOING],
            "said_today": _n[CL.SAID_TODAY],
            "muted": _n[CL.MUTED],
            "acked": _n[CL.ACKED],
        }
        # cap 传 len(shown)：让 render 不做二次截断。二次截断＝「账本记了、
        # 报告没印」，正是那条永久静默的失败模式。
        print(plain(render(shown, meta, args.recent,
                           cap=max(1, len(shown)), coverage=coverage)))
        # ★ 只有确实印出来的那几条才记账（不变量 1）。
        CL.commit(ledger, annotated, shown, deferred, today)
        try:
            CL.save(ledger_path, ledger)
        except Exception as exc:                                # noqa: BLE001
            print("[警告] 账本写不进去（%s: %s）⇒ 下次会重复说同一批线索"
                  % (type(exc).__name__, exc), file=sys.stderr)
        # ★ D-4 最小通路（2026-11-03）：**主动推送**，`--notify` 才开。
        #   候选只从 `shown` 里挑 —— 它已经过账本节流（说 3 次 → 静默 7 天），
        #   所以不会「同一件事反复弹」。一天最多一枚（只取第一条）。
        if args.notify:
            _cand = [c for c in shown if c.kind in NOTIFY_KINDS]
            if not _cand:
                print("[推送] 没有值得弹的（只有 %s 会弹）"
                      % "/".join(NOTIFY_KINDS))
            else:
                _r = push_clue(_cand[0])
                if _r["ok"]:
                    print("[推送] 已弹出：%s" % str(_cand[0].subject)[:60])
                else:
                    # ★ 弹不出来必须印出来。静默失败会让「屏幕上没有东西」
                    #   与「本来就没东西」长得一模一样。
                    print("[推送] 没弹出：%s" % (_r["why"] or "未知原因"))
    else:
        if ledger_error:
            meta["ledger_note"] = (
                "★ 账本不可用：%s ⇒ 本次按「没说过」处理，可能重复" % ledger_error
            )
        print(plain(render(clues, meta, args.recent, cap=args.cap, coverage=coverage)))

    print(
        f"[分母] 记录 {len(recs)}｜不可解析 {unparsed}｜"
        f"pre_tool_use 覆盖 {len(daily)} 天｜"
        f"首次出现抽样 {fs_counts}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
