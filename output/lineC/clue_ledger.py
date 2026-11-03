# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""线索账本 · 让主动性从「一次性」变成「有记忆」（档 1 原型）

═══════════════════════════════════════════════════════════════════════════
它解决什么问题
═══════════════════════════════════════════════════════════════════════════
没有账本时，watchman 每次运行都从零重算。同一条线索（比如某个 type 消失了）
会连续 20 天出现在报告里。从第 3 天起它就不再是信息，而是背景噪音 ——
而报告仍然是绿的。

这与「恒绿判据不许进人的清单」（铁律 41）是同一条毛病的另一面：
**恒红线索同样稀释注意力**。人不会因为看得多而更警觉，只会更麻木。

═══════════════════════════════════════════════════════════════════════════
但账本有一个比「没有账本」更危险的失败模式
═══════════════════════════════════════════════════════════════════════════
    账本记成「说过了」，而用户其实没看到。
于是那条线索永远不会再说 —— **一次记账错误 = 永久静默**，且不留痕迹。

所以本文件有两条硬不变量：

  【不变量 1】只有确实出现在最终输出里的线索，才允许 `n_told += 1`。
    记账发生在 render 之后，用的是渲染实际吐出来的那几条，不是「算出来的」那几条。
    ⇒ `commit()` 的入参是 `shown`（已渲染），不是 `clues`（已算出）。

  【不变量 2】被 cap 截断、没进输出的线索，必须 `n_deferred += 1` 并在下次排序提前。
    否则它们会被排在后面的新线索永远挤掉 —— 饿死。
    ⇒ 排序键里 `-n_deferred` 排在新旧状态之后、优先级之前。

  【不变量 3】`n_told <= CAP_HARD` 每次都断言。这是硬的，不因为「今天发现了 20 条」放宽。

═══════════════════════════════════════════════════════════════════════════
静默的判据：只谈节奏，不谈「有没有变坏」
═══════════════════════════════════════════════════════════════════════════
「同一条连说 3 次就静默」看起来太钝 —— 如果它变严重了呢？

诚实的回答是：**账本判断不了「有没有变严重」，那是判据的事。**
账本只负责节奏（十维里的 D9）。所以这里不做「升级检测」，只做占空比：

    说满 3 次 → 静默 7 天 → 期满后回来说 1 次 → 再静默 7 天 …

静默期满时它一定会回来一次，那时候用户自己就能看出「变没变」。
**把「要不要判断」推给能判断的那一层，是本文件唯一的设计选择。**

═══════════════════════════════════════════════════════════════════════════
账本写在哪：不能写进被观察的目录
═══════════════════════════════════════════════════════════════════════════
默认落在 `output/lineC/_watchman_ledger.json`，**不在 `.psl/audit` 里**。

理由不是洁癖：`.psl/audit` 是被观察对象。观察者的记忆一旦写进去，
它就同时是「证据」和「对证据的加工」—— 自指的第三种形态（铁律 32）。
明天 anchor 一算，这份记忆自己就成了被审计的记录之一。

★ 因此 watchman 的「只读」要精确成：**对账本只读；自己另有一本账。**
  说成「完全只读」是超额声明（铁律 21）。

═══════════════════════════════════════════════════════════════════════════
两种身份：日级事实 vs 持续状态
═══════════════════════════════════════════════════════════════════════════
`clue_key()` 里，day 是否属于身份，按 kind 分两类：

  日级事实（anchor／baseline／gap）：day **是**身份。
    「今天缺锚」和「昨天缺锚」是两个不同的事实，不能合并。

  持续状态（absent／verdict／repeat／first_seen／rule_pair）：day **不是**身份。
    「这个 type 消失了」是同一个状态，换一天还是它。

这与既有口径一致：**旧缺锚是状态只进分母，新缺锚是事件才进每日线索。**

用法：
    from clue_ledger import annotate, plan, commit, load, save
    python output/lineC/clue_ledger.py --selfcheck
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence, Tuple

_OUT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _OUT not in sys.path:
    sys.path.insert(0, _OUT)
import _commit                                              # noqa: E402

VERSION = 1

#: 身份规则的版本。**改 `clue_key` 或任何检测器的 `key=` 就要 +1。**
#: 为什么单独立一个版本号：身份规则变了以后，旧账本里的键**再也对不上**，
#: 于是所有线索都会变成「新的」—— 报告上看起来像「今天突然多了一堆事」，
#: 而真实原因是我们改了算身份的代码。
#: 这种「自己的改动伪装成世界的变化」是量具自指的一种（铁律 27），
#: 所以宁可让它在账本里显形：版本不符 ⇒ 旧账归档、明确说一句、重新开始。
KEY_VERSION = 1

#: 一次最多说几条。**硬的**：`--cap` 是注意力预算（可调），这个是上限（不可越过）。
CAP_HARD = 5

#: 同一条连说满几次转静默。
#:
#: ★★ 2026-11-02 起**不再决定主行为**（保留常量只为不破坏外部引用）。
#:   为什么废掉：这两个数是「一个数管八种线索」，而八种东西方向相反 ——
#:   「某个钩子挂了」说一遍就闭嘴是错的；「某个组合首次出现」说三遍也是错的。
#:   现在静默由 kind 的语义决定（见 FAULT_KINDS / EVENT_KINDS），
#:   由**内容指纹**决定「变了没有」（见 clue_fingerprint）。
#:   这同时是铁律 35 的正向应用：计数单位要分开，不要用一个数压平。
SILENT_AFTER = 3

#: 静默多少天后回来说一次。同上，已不决定主行为。
COOL_DAYS = 7

#: 多少天没再出现的条目从账本淡出（不是删除，是移到 `retired`）。
RETAIN_DAYS = 60

#: 每个条目最多留多少个出现日（防止账本无限长）。
MAX_DAYS_PER_ENTRY = 40

# ---- 状态 ----
NEW = "new"                # 从没见过 ⇒ 该说
REOPENED = "reopened"      # 说过了／确认过了，但**内容变了** ⇒ 该说
ONGOING = "ongoing"        # 见过、今天还没说、没到静默 ⇒ 该说
SAID_TODAY = "said_today"  # 今天已经说过了 ⇒ 不再说（同日重跑的幂等靠它）
MUTED = "muted"            # 事件类说过了且内容没变 ⇒ 不说
ACKED = "acked"            # 用户确认过且内容没变 ⇒ 不说

SPEAKABLE = frozenset({NEW, REOPENED, ONGOING})

#: **故障类**：说的是「有个东西坏了」。坏了就天天说，直到好了。
#: 静默在这里是错的 —— 你不修它，它就该一直在。
#: 恒红会稀释注意力（铁律 41），但「故障没修」不是恒红，是**事实没变**。
#: 恒红的定义是「判据本身永远成立」；而这一类的成立条件是真的坏了。
FAULT_KINDS = frozenset({"absent", "anchor", "verdict", "baseline"})

#: **事件类**：说的是「有件事发生了」。说过一次就够，除非内容变了。
#: 同一件事重复说三遍不增加信息 —— 它只增加噪音，而噪音正是主动性的头号敌人。
EVENT_KINDS = frozenset({"rule_pair", "first_seen", "repeat", "gap"})

#: 未知 kind 按**故障类**处理（宁可多说，不可漏说）。
#: 依据：主动性的价值是「不让你错过」；漏一条的代价大于多说一条。
#: 但这是有代价的选择，所以报告里会把它标出来（见 render_note）。
def is_fault(kind: str) -> bool:
    return kind not in EVENT_KINDS


#: 日级事实：day 属于身份（**仅兜底用**，正常情况下由 `Clue.key` 声明）
DAY_KINDS = frozenset({"anchor", "baseline", "gap"})
#: 持续状态：day 不属于身份（**仅兜底用**）
STATUS_KINDS = frozenset({"absent", "verdict", "repeat", "first_seen", "rule_pair"})

DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "_watchman_ledger.json"
)


# --------------------------------------------------------------------------- 身份


def clue_key(clue: Any) -> str:
    """线索的稳定身份。

    ★ 首选 `clue.key` —— **身份由产生线索的检测器声明，不由账本猜**。
      只有检测器知道「什么算同一件事」。账本手里只有 kind/day/subject/items，
      而这三样都不够：
        · `subject` 带当天计数（「9 个」→「10 个」），每天不同；
        · `day` 对 anchor／absent／verdict 恒为 today（它们讲的是**别的**天）；
        · `items` 里可能带 size／行号，每天在长。
      拿它们猜的后果是「每天都是新线索」—— 账本退化成计数器，而且看不出来。

    ★ 兜底规则（`key` 为空时）：按 kind 分两类，day 是否属于身份。
        · 日级事实（baseline 等）：day **是**身份 —— 「今天缺锚」与「昨天缺锚」
          是两个事实。
        · 持续状态（repeat／first_seen／rule_pair）：day **不是**身份 ——
          「这个命令第一次出现」换一天还是它。
      兜底存在只为了「新加检测器忘了写 key」时不崩，不是为了让它成为常态。
    """
    declared = str(getattr(clue, "key", "") or "")
    if declared:
        return declared
    kind = clue.kind
    items = tuple(getattr(clue, "items", ()) or ())
    if kind in STATUS_KINDS:
        body = "|".join(sorted(items))
        if not body:
            # 退化：没有 items 时只能拿 subject 顶。标 `?` 让它在账本里显形。
            return "%s|?%s" % (kind, clue.subject)
        return "%s|%s" % (kind, body)
    # 日级事实（含未知 kind：保守地按日级处理，宁可重复说也不误合并）
    return "%s|%s" % (kind, clue.day)


# --------------------------------------------------------------------------- 指纹


def _mag_bucket(n: int) -> str:
    """把规模压成**量级桶**，不是精确值。

    ★ 为什么必须分桶：不分桶的话「当天 4 次 → 5 次」也算「变了」，
      于是同一条线索天天重开，指纹退化成「每天都是新的」——
      和没有指纹一样，只是多了一层看起来在工作。

    ★ 为什么必须分桶而不是忽略：`1 次 → 40 次` 是真变化。
      不分桶、又不忽略，就得挑一个阈值（比如「变化 > 50% 才算」），
      而那个阈值是拍的 —— 本文件已经因为「拍出来的数」吃过两次亏
      （`SILENT_AFTER` / `COOL_DAYS`），不再拍第三个。
      量级桶的边界是**数量级**，不是调参：1 / 2-3 / 4-10 / 11-30 / 31-100 / 100+。
    """
    n = abs(int(n or 0))
    for hi, lab in ((1, "1"), (3, "2-3"), (10, "4-10"),
                    (30, "11-30"), (100, "31-100")):
        if n <= hi:
            return lab
    return "100+"


def clue_fingerprint(clue: Any) -> str:
    """这条线索的**内容指纹**：`items` 的集合 + 规模的量级。

    ★ 它回答的问题与 `clue_key` **不同**，两者不可互换：
        · `clue_key` 回答「这是不是同一件事」—— 变了就不该是同一件事的，不算进去；
        · 指纹回答「同一件事**变了没有**」—— 只有 key 相同才有意义。

    ★ 不含 `subject`：本文件 2026-11-02 刚把 `AN-010` 改成
      `写到项目目录之外（AN-010）`（可读性修复）。如果指纹含 subject，
      那次纯文案改动会让**所有已确认的线索同时重开** —— 用户看到的是
      「它突然把旧事全翻出来了」，而真实原因是我们改了措辞。
      这正是铁律 27（量具自指）的形状：自己的改动伪装成世界的变化。

    ★ 不含 `day`：event 类的 day 不是身份（见 clue_key 的说明）。
      同一条「首次出现」换一天再出现，items 和规模才是要比较的东西。
    """
    items = tuple(sorted(str(x) for x in (getattr(clue, "items", ()) or ())))
    mag = int(getattr(clue, "magnitude", 0) or 0)
    body = "%s\x1f%s" % ("|".join(items), _mag_bucket(mag))
    return hashlib.sha1(body.encode("utf-8")).hexdigest()[:12]


def _blank(kind: str, subject: str) -> Dict[str, Any]:
    return {
        "kind": kind,
        "subject": subject,
        "first_day": None,
        "last_day": None,
        "days": [],
        "n_seen": 0,
        "n_told": 0,          # 本轮已说几次（静默后归零重计）
        "n_told_total": 0,    # 一共说过几次（只增，供审计）
        "last_told_day": None,
        "n_deferred": 0,      # 算出来但被 cap 截断的次数（防饿死）
        "muted_until": None,
        "acked_day": None,
        #: 上一次见到的内容指纹。「变了没有」全靠它。
        "fingerprint": None,
        #: 用户按下 `--ack` 那一刻的内容指纹。
        #: ★ 它把 `--ack` 的语义从「永久失明」改成「这件事我知道了，变了再叫我」——
        #:   这才是人按那个按钮时真正想说的。旧语义下，一条「组合首次出现」被确认后，
        #:   即使它从 1 次涨到每天 40 次，也永远不会再开口。那不是「别再说了」，
        #:   是把眼睛闭上。
        "acked_fingerprint": None,
    }


# --------------------------------------------------------------------------- 读写


def load(path: str = DEFAULT_PATH) -> Dict[str, Any]:
    """读账本。**任何异常都不许抛** —— 账本坏了不能让巡检停摆。

    但也不许把「坏了」说成「空账本」：`ledger_error` 会带出去，
    由调用方决定怎么披露。零与不可判同貌，这是本项目的核心纪律之一。
    """
    blank = {
        "version": VERSION,
        "key_version": KEY_VERSION,
        "updated_at": None,
        "entries": {},
        "retired": {},
        "ledger_error": None,
        "ledger_notice": None,
    }
    if not os.path.exists(path):
        return blank
    try:
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        if not isinstance(d, dict) or not isinstance(d.get("entries"), dict):
            raise ValueError("结构不符（缺 entries 字典）")
        if int(d.get("version", 0)) > VERSION:
            raise ValueError("账本版本 %s 比本程序（%s）新" % (d.get("version"), VERSION))
        d.setdefault("version", VERSION)
        d.setdefault("updated_at", None)
        d["ledger_error"] = None
        d["ledger_notice"] = None
        d.setdefault("retired", {})
        # 身份规则变了 ⇒ 旧键全对不上。**归档而不是删除**，并且要说出来：
        # 不说的话，用户看到的是「今天突然多了 20 件事」。
        #
        # ★ 这是 `notice` 不是 `error`。第一版写成了 error，于是账本被判「不可用」
        #   ⇒ 不记账 ⇒ 不保存 ⇒ `key_version` 永远停在 0 ⇒ 提示**每次都重复**。
        #   一次性的历史事件被写成了恒红状态 —— 正是本文件要防的那种病。
        kv = int(d.get("key_version", 0) or 0)
        if kv != KEY_VERSION:
            ret = d.setdefault("retired", {})
            for k, v in list(d.get("entries", {}).items()):
                ret["kv%d|%s" % (kv, k)] = v
            d["entries"] = {}
            d["key_version"] = KEY_VERSION
            d["ledger_notice"] = (
                "身份规则版本 %d→%d，旧账 %d 条已归档；本次全部按「新的」处理"
                "（一次性的，不是世界变了）" % (kv, KEY_VERSION, len(ret))
            )
        return d
    except Exception as exc:                                    # noqa: BLE001
        out = dict(blank)
        out["ledger_error"] = "%s: %s" % (type(exc).__name__, exc)
        return out


def save(path: str, ledger: Dict[str, Any]) -> None:
    """落盘并回读。半写的账本比没有账本更坏：它会被 `load` 读成「账本坏了」
    ⇒ 所有线索变 NEW ⇒ 洪泛。

    ★ 为什么不再自己写 `.tmp` + `os.replace`：本机 `os.replace` 到已存在目标
      会**偶发** WinError 5（2026-11-03 实测），而账本默认就落在 D 盘仓库目录。
      重试与退路收在 `output/_commit.py`；这里仍然 raise，不吞异常。
    """
    ledger["version"] = VERSION
    ledger["key_version"] = KEY_VERSION
    ledger["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # 两个都是**运行时**状态，不落盘：error 说明这次读失败（下次该重试），
    # notice 是这一次性事件（写进新 key_version 后就不该再出现）。
    ledger.pop("ledger_error", None)
    ledger.pop("ledger_notice", None)
    _commit.write_json(path, ledger)


# --------------------------------------------------------------------------- 判定


def _plus_days(day: str, n: int) -> str:
    return (date.fromisoformat(day) + timedelta(days=n)).isoformat()


class KeyCollision(Exception):
    """两条不同的线索算出同一个身份。

    这不是「用户的问题」，是**检测器的 bug**：它把两件不同的事声明成了同一件。
    后果是账本会把其中一条记成另一条 —— 说过的被当成没说，或者反过来
    「一次记账错误 = 永久静默」。
    ★ 所以宁可当场抛，也不许合并。但调用方（watchman）必须接住它并降级成
      「本次不用账本」，不许让它把整份报告带下去 —— 崩溃的表现是「没有那条记录」，
      比报错更难发现（铁律 45）。
    """


def annotate(
    clues: Sequence[Any],
    ledger: Dict[str, Any],
    today: str,
) -> List[Tuple[Any, str, str, Optional[Dict[str, Any]]]]:
    """给每条线索标状态。返回 (clue, key, state, entry)。

    纯读，不改账本 —— 这样 `--dry-run` 和真正的运行走同一条判定路径，
    不会出现「预览和实跑不一样」。
    """
    entries = ledger.get("entries") or {}
    out: List[Tuple[Any, str, str, Optional[Dict[str, Any]]]] = []
    owner: Dict[str, Any] = {}
    for c in clues:
        k = clue_key(c)
        if k in owner and owner[k] is not c:
            raise KeyCollision(
                "两条线索撞键：%r\n  A: %s / %s\n  B: %s / %s"
                % (k, owner[k].kind, owner[k].subject, c.kind, c.subject)
            )
        owner[k] = c
        fp = clue_fingerprint(c)
        e = entries.get(k)
        if e is None:
            out.append((c, k, NEW, None))
            continue

        # ── 1. 用户确认过：内容变了才重开 ─────────────────────────────────
        # ★ 旧语义是 `acked_day` 一置就**永久静默，不看内容**。
        #   那等于「你按过一次按钮，从此这件事再严重也听不到」——
        #   按钮上写的是「知道了」，实际效果是「别再让我知道」。
        #   现在比指纹：变了 ⇒ REOPENED（说，并标明「你确认过的那件事变了」）。
        # ★ 缺 `acked_fingerprint`（升级前按的）⇒ 按 ACKED 处理，不突然重开。
        #   但这不是静默吞掉：`render_note` 会把这类条数点出来，说明
        #   「它们的变化在补指纹之前无法被发现」。
        if e.get("acked_day"):
            acked_fp = e.get("acked_fingerprint")
            out.append((c, k, REOPENED if (acked_fp and acked_fp != fp) else ACKED, e))
            continue

        # ── 2. 同日重跑：今天说过了就不再重复（两类都适用）──────────────
        if e.get("last_told_day") == today:
            out.append((c, k, SAID_TODAY, e))
            continue

        # ── 3. 故障类：天天说，不静默 ────────────────────────────────────
        # 「有个东西坏了」这件事，你不修它就该一直在。让它闭嘴等于替你
        # 决定「你已经知道了」—— 而账本没有「人真的读过了」的信号，
        # 这个假设没有依据（见结果文档 §7.3）。
        if is_fault(c.kind):
            out.append((c, k, ONGOING, e))
            continue

        # ── 4. 事件类：说过一次就够，除非内容变了 ────────────────────────
        prev_fp = e.get("fingerprint")
        told = int(e.get("n_told_total", 0) or 0)
        if told >= 1 and prev_fp:
            out.append((c, k, MUTED if prev_fp == fp else REOPENED, e))
            continue
        # 没说过，或老账本没有指纹（**不知道变没变**）⇒ 说一次。
        # 「不知道」不许当成「没变」—— 那正是零与不可判同貌。
        out.append((c, k, ONGOING, e))
    return out


#: 排序档：REOPENED 最前（它推翻的是人已经做过的判断），NEW 次之，ONGOING 最后。
_RANK = {REOPENED: 0, NEW: 1, ONGOING: 2}


def plan(
    annotated: Sequence[Tuple[Any, str, str, Optional[Dict[str, Any]]]],
    cap: int,
    priority: Dict[str, int],
    enforce_hard: bool = True,
) -> Tuple[List[Any], List[Any], List[Any]]:
    """决定说哪些。返回 (shown, deferred, suppressed)。

    排序（字典序）：
      1. **REOPENED 优先于 NEW 优先于 ONGOING** —— 「你确认过的那件事变了」
         比「一件新事」更值钱：它推翻的是一个人**已经做过的判断**。
         主动性唯一正当的领域就是「系统知道、而用户不知道自己需要知道」，
         而「你以为已经处理完的那件事，现在不一样了」正落在那一格里。
      2. `-n_deferred` —— 被截断过几次，就提前几位（防饿死，不变量 2）。
      3. 检测器优先级 —— 沿用 watchman 的 PRIORITY。
      4. subject —— 只为让同一天的输出稳定可复现。

    ★ 排序里**没有**「说了几次」。静默由 kind 语义 + 内容指纹决定，
      不靠排序压。把「少说」做成排序的副作用，是那种「看起来在工作」的假机制。
    """
    limit = min(cap, CAP_HARD) if enforce_hard else cap
    speakable = [t for t in annotated if t[2] in SPEAKABLE]

    def key(t: Tuple[Any, str, str, Optional[Dict[str, Any]]]) -> Tuple[int, int, int, str]:
        c, _k, st, e = t
        e = e or {}
        return (
            _RANK.get(st, 3),
            -int(e.get("n_deferred", 0) or 0),
            priority.get(c.kind, 9),
            c.subject,
        )

    speakable.sort(key=key)
    shown = speakable[:limit]
    deferred = speakable[limit:]
    suppressed = [t for t in annotated if t[2] not in SPEAKABLE]
    if enforce_hard and len(shown) > CAP_HARD:                  # 不可达，但断言留着
        raise AssertionError("越过 CAP_HARD=%d" % CAP_HARD)
    return [t[0] for t in shown], [t[0] for t in deferred], [t[0] for t in suppressed]


def commit(
    ledger: Dict[str, Any],
    annotated: Sequence[Tuple[Any, str, str, Optional[Dict[str, Any]]]],
    shown: Sequence[Any],
    deferred: Sequence[Any],
    today: str,
) -> Dict[str, int]:
    """记账。**`shown` 必须是渲染实际输出的那几条。**

    调用顺序铁律：annotate → plan → render → commit(shown)。
    在 render 之前 commit，就是「记成说过了而用户没看到」——
    那是本文件最危险的失败模式（不变量 1）。
    """
    entries = ledger.setdefault("entries", {})
    stats = {"seen": 0, "told": 0, "deferred": 0, "new_entries": 0}

    for c, k, _st, _e in annotated:
        ent = entries.get(k)
        if ent is None:
            ent = _blank(c.kind, c.subject)
            entries[k] = ent
            stats["new_entries"] += 1
        ent["subject"] = c.subject              # 措辞跟着最近一次走
        # ★ 指纹对**所有**见到的线索更新，不只对说出去的。
        #   理由：它记的是「最近一次见到的内容」。只更新 shown 的话，
        #   被 cap 截断的那些会停在旧指纹 ⇒ 下次一比对就「变了」⇒ 假重开。
        ent["fingerprint"] = clue_fingerprint(c)
        ent["last_day"] = max(ent.get("last_day") or "", c.day)
        if not ent.get("first_day"):
            ent["first_day"] = c.day
        days = ent.setdefault("days", [])
        if c.day not in days:
            days.append(c.day)
            days.sort()
            if len(days) > MAX_DAYS_PER_ENTRY:
                del days[: len(days) - MAX_DAYS_PER_ENTRY]
            ent["n_seen"] = int(ent.get("n_seen", 0)) + 1
            stats["seen"] += 1

    shown_keys = {clue_key(c) for c in shown}
    deferred_keys = {clue_key(c) for c in deferred}
    if shown_keys & deferred_keys:
        raise AssertionError("同一条线索同时出现在 shown 和 deferred 里")

    for k in shown_keys:
        ent = entries[k]
        ent["n_told"] = int(ent.get("n_told", 0)) + 1
        ent["n_told_total"] = int(ent.get("n_told_total", 0)) + 1
        ent["last_told_day"] = today
        ent["n_deferred"] = 0
        stats["told"] += 1
        # ★ 这里原来写「说满 SILENT_AFTER 次就写 muted_until」。
        #   2026-11-02 起**不写了**：静默由 kind 语义 + 内容指纹决定
        #   （事件类说一次就够；故障类永远不静默）。
        #   `muted_until` 字段保留但已不参与判定 —— 留着是为了让老账本
        #   读进来不报结构错，而不是因为它还有用。写它反而会让下一个读代码的人
        #   以为静默还归它管。
    for k in deferred_keys:
        ent = entries[k]
        ent["n_deferred"] = int(ent.get("n_deferred", 0)) + 1
        stats["deferred"] += 1

    _retire(ledger, today)
    return stats


def _retire(ledger: Dict[str, Any], today: str) -> None:
    """把长期没再出现的条目挪到 `retired`。**不是删除** —— 删了就丢了「说过几次」。"""
    entries = ledger.setdefault("entries", {})
    retired = ledger.setdefault("retired", {})
    horizon = _plus_days(today, -RETAIN_DAYS)
    for k in list(entries):
        last = entries[k].get("last_day") or ""
        if last and last < horizon:
            retired[k] = entries.pop(k)


# --------------------------------------------------------------------------- 披露


def counts(
    annotated: Sequence[Tuple[Any, str, str, Optional[Dict[str, Any]]]],
) -> Dict[str, int]:
    """各状态条数。**唯一实现** —— 报告首句和账本行都从这里取，
    两处各算一遍必然漂，而漂了以后两个数都「看起来正常」。"""
    n = {s: 0 for s in (NEW, REOPENED, ONGOING, SAID_TODAY, MUTED, ACKED)}
    for _c, _k, st, _e in annotated:
        n[st] = n.get(st, 0) + 1
    return n


def render_note(
    annotated: Sequence[Tuple[Any, str, str, Optional[Dict[str, Any]]]],
    shown: Sequence[Any],
    deferred: Sequence[Any],
    ledger_error: Optional[str] = None,
    ledger_notice: Optional[str] = None,
) -> str:
    """一行账本口径。**必须有** —— 被静默的条数不许看不见。

    这是铁律 41 的正向应用：如果「今天没说的话」不出现在报告里，
    读者就无法区分「没事」和「被压掉了」。
    """
    n = counts(annotated)
    parts = [
        "账本：新 %d｜变了 %d｜还在 %d｜今日已说 %d｜静默 %d｜已确认 %d"
        % (n[NEW], n[REOPENED], n[ONGOING], n[SAID_TODAY], n[MUTED], n[ACKED]),
        "本次说 %d 条（硬上限 %d）" % (len(shown), CAP_HARD),
    ]
    if deferred:
        parts.append("顺延 %d 条（下次优先）" % len(deferred))
    # ★ 升级前按过 `--ack` 的条目没有指纹 ⇒ 它变了也发现不了。
    #   这必须说出来：不说的话，「已确认 N 条」读起来像「N 条都在看着」，
    #   而其中一部分其实是**看不见了**。零与不可判同貌。
    _nofp = sum(
        1 for _c, _k, st, e in annotated
        if st == ACKED and e and not e.get("acked_fingerprint")
    )
    if _nofp:
        parts.append("其中 %d 条已确认但没有指纹（升级前按的）⇒ 它们的变化发现不了，"
                     "重新 --ack 一次即可补上" % _nofp)
    if ledger_notice:
        parts.append("注意：%s" % ledger_notice)
    if ledger_error:
        parts.append("★ 账本读取失败：%s ⇒ 本次按「没说过」处理，可能重复" % ledger_error)
    return "｜".join(parts)


# --------------------------------------------------------------------------- 自检


class _C:  # 自检用的假 Clue（不 import watchman，避免循环）
    def __init__(self, kind: str, day: str, subject: str,
                 items: Sequence[str] = (), key: str = "", magnitude: int = 0):
        self.kind, self.day, self.subject = kind, day, subject
        self.items = tuple(items)
        self.key = key
        self.magnitude = magnitude
        self.evidence = ((day + ".jsonl", 1),)


def _selfcheck() -> int:
    """十二臂。每臂都对应一个「错了会静默」的方向，不是「函数能跑」。"""
    ok = 0
    bad: List[str] = []

    def arm(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        if cond:
            ok += 1
            print("  [OK] %s %s" % (name, detail))
        else:
            bad.append(name)
            print("  [XX] %s %s" % (name, detail))

    PRI = {"anchor": 0, "absent": 1, "verdict": 2, "baseline": 3, "repeat": 4,
           "first_seen": 5, "rule_pair": 6, "gap": 7}
    D1, D2, D3 = "2026-01-01", "2026-01-02", "2026-01-03"

    # —— 1 空账本：全 NEW ——
    led = load(os.path.join(tempfile.gettempdir(), "_nope_%d.json" % os.getpid()))
    a = annotate([_C("absent", D1, "某 type 消失", ("hook.x",))], led, D1)
    arm("1 空账本全 NEW", a[0][2] == NEW and led.get("ledger_error") is None)

    # —— 2 说一次 → 同日重跑必须 SAID_TODAY（幂等）——
    c1 = _C("absent", D1, "某 type 消失", ("hook.x",))
    a = annotate([c1], led, D1)
    shown, deferred, _sup = plan(a, 5, PRI)
    commit(led, a, shown, deferred, D1)
    a2 = annotate([c1], led, D1)
    arm("2 同日重跑不重复说", a2[0][2] == SAID_TODAY)

    # 让故障类真的说满三次 —— 第 4 臂要断言「说三次之后仍然该说」，
    # 少了这三轮，它验的就只是「第一次该说」。
    for d in (D2, D3):
        a = annotate([c1], led, d)
        s, df, _ = plan(a, 5, PRI)
        commit(led, a, s, df, d)

    # —— 3 事件类：说一次就静默（不再靠「说满 3 次」这个拍的数）——
    # ★ 2026-11-02 改。旧臂是「说满 SILENT_AFTER 次转静默」，用的是 absent
    #   （故障类）。新语义下故障类**永不静默**，所以旧臂必然红 —— 而它红得对：
    #   「钩子挂了」说三遍就闭嘴，等于替你决定「你已经知道了」。
    lev = {"version": VERSION, "updated_at": None, "entries": {}, "ledger_error": None}
    ce = _C("rule_pair", D1, "组合首次出现", ("AN-002", "AN-014"),
            key="rule_pair|AN-002|AN-014", magnitude=1)
    a = annotate([ce], lev, D1)
    s, df, _ = plan(a, 5, PRI)
    commit(lev, a, s, df, D1)
    a3 = annotate([ce], lev, D2)
    arm("3 事件类说一次就静默", a3[0][2] == MUTED,
        "说 %d 次后状态=%s"
        % (lev["entries"][clue_key(ce)]["n_told_total"], a3[0][2]))

    # —— 4 故障类：说了三次仍然该说（天天说，直到好了）——
    a4 = annotate([c1], led, "2026-01-04")
    arm("4 故障类不静默", a4[0][2] == ONGOING,
        "absent 说了 %d 次，第四次状态=%s"
        % (led["entries"][clue_key(c1)]["n_told_total"], a4[0][2]))

    # —— 5 cap 截断 → n_deferred 让下次提前（不饿死）——
    led2 = {"version": VERSION, "updated_at": None, "entries": {}, "ledger_error": None}
    many = [_C("gap", D1, "断层 %02d" % i, key="gap|%s|%02d:00" % (D1, i))
            for i in range(8)]
    a = annotate(many, led2, D1)
    s, df, _ = plan(a, 2, PRI)
    commit(led2, a, s, df, D1)
    dkeys = [clue_key(c) for c in df]
    bumped = all(led2["entries"][k]["n_deferred"] == 1 for k in dkeys)
    a_next = annotate(many, led2, D2)
    s_next, _df2, _ = plan(a_next, 2, PRI)
    # 顺延过的必须排在本轮新出现的 gap 前面 —— 但这里全是同一批，所以看首个是否被顺延过
    first_is_deferred = clue_key(s_next[0]) in dkeys
    arm("5 被截断的下次提前", bumped and first_is_deferred,
        "顺延 %d 条，下次首个是否顺延过=%s" % (len(df), first_is_deferred))

    # —— 6 账本损坏：不崩、报错、全 NEW ——
    bad_path = os.path.join(tempfile.gettempdir(), "_bad_%d.json" % os.getpid())
    with open(bad_path, "w", encoding="utf-8") as fh:
        fh.write("{ 这不是 JSON")
    led3 = load(bad_path)
    a = annotate([c1], led3, D1)
    arm("6 账本损坏不崩且自报", a[0][2] == NEW and bool(led3.get("ledger_error")))
    try:
        os.unlink(bad_path)
    except OSError:
        pass

    # —— 7 CAP_HARD 硬上限：cap=100 也不许越过 ——
    led4 = {"version": VERSION, "updated_at": None, "entries": {}, "ledger_error": None}
    lots = [_C("gap", D1, "断层 %02d" % i, key="gap|%s|%02d:00" % (D1, i))
            for i in range(20)]
    a = annotate(lots, led4, D1)
    s, df, _ = plan(a, 100, PRI)
    s_free, _df_free, _ = plan(a, 100, PRI, enforce_hard=False)
    arm("7 硬上限不可越过", len(s) == CAP_HARD and len(s_free) == 20,
        "enforce_hard 时 %d 条／关掉时 %d 条" % (len(s), len(s_free)))

    # —— 8 撞键必须当场抛（不是合并）——
    # 这一臂来自真事：本文件第一版按 `kind|day` 算身份，同一天的 8 个 gap
    # 全算成同一个键，于是「同一条线索同时出现在 shown 和 deferred 里」。
    # 如果不抛，账本会把 7 条记成 1 条 —— 用户永远看不到那 7 条。
    dup = [_C("gap", D1, "断层 甲"), _C("gap", D1, "断层 乙")]
    try:
        annotate(dup, {"entries": {}}, D1)
        arm("8 撞键必须报", False, "没抛")
    except KeyCollision as exc:
        arm("8 撞键必须报", True, str(exc).splitlines()[0][:40])

    # —— 9 规模跨量级桶 ⇒ 重开 ——
    # 这是 `--ack` 从「永久失明」改成「变了再叫我」的关键一步。
    # 账本里记的是 1 次（桶「1」），现在 40 次（桶「31-100」）⇒ 跨桶。
    ce_big = _C("rule_pair", D2, "组合首次出现", ("AN-002", "AN-014"),
                key="rule_pair|AN-002|AN-014", magnitude=40)
    a9 = annotate([ce_big], lev, D2)
    arm("9 规模跨量级 ⇒ 重开", a9[0][2] == REOPENED, "1 次 → 40 次，状态=%s" % a9[0][2])

    # 把 40 次这一次记进账本（第 10、11、12 臂要用更新后的指纹）
    s, df, _ = plan(annotate([ce_big], lev, D2), 5, PRI)
    commit(lev, annotate([ce_big], lev, D2), s, df, D2)

    # —— 10 同桶 ⇒ 不算变（40 → 45 都是「31-100」）——
    # ★ 这条臂守的是「不要用精确值当指纹」：用精确值的话，
    #   同一条线索 4 次→5 次就重开，用户看到的是「它天天把旧事翻出来」。
    ce_more = _C("rule_pair", D3, "组合首次出现", ("AN-002", "AN-014"),
                 key="rule_pair|AN-002|AN-014", magnitude=45)
    a10 = annotate([ce_more], lev, D3)
    arm("10 同桶不算变", a10[0][2] == MUTED, "40 次 → 45 次同桶，状态=%s" % a10[0][2])

    # —— 11 已确认但内容变了 ⇒ 重开（ack 不是永久失明）——
    ent = lev["entries"]["rule_pair|AN-002|AN-014"]
    ent["acked_day"] = D3
    ent["acked_fingerprint"] = clue_fingerprint(ce_more)   # 确认的是「45 次」那一次
    ce_small = _C("rule_pair", D3, "组合首次出现", ("AN-002", "AN-014"),
                  key="rule_pair|AN-002|AN-014", magnitude=2)
    a11 = annotate([ce_small], lev, "2026-01-04")          # 现在掉到 2 次
    arm("11 已确认但内容变了 ⇒ 重开", a11[0][2] == REOPENED,
        "确认时 45 次，现在 2 次，状态=%s" % a11[0][2])

    # —— 12 已确认且内容没变 ⇒ 不重开（否则 ack 等于没按）——
    a12 = annotate([ce_more], lev, "2026-01-05")
    arm("12 已确认且没变 ⇒ 静默", a12[0][2] == ACKED, "状态=%s" % a12[0][2])

    print("\n  结论：%d/12 通过%s" % (ok, "" if not bad else "，失败：" + "、".join(bad)))
    return 0 if not bad else 1


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="线索账本（档 1 原型）")
    ap.add_argument("--ledger", default=DEFAULT_PATH)
    ap.add_argument("--selfcheck", action="store_true")
    ap.add_argument("--dump", action="store_true", help="打印账本现状")
    ap.add_argument(
        "--ack",
        metavar="KEY",
        help="我说这条我看过了（**不是系统检测到你看了**）—— 从此永久静默，"
             "直到它的内容变化。系统无法验证你是不是真的看过，"
             "所以它只记录「你说过」，不记录「你看过」。",
    )
    ap.add_argument("--ack-all", action="store_true", help="全部标记为已确认")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if args.selfcheck:
        return _selfcheck()

    led = load(args.ledger)
    if led.get("ledger_error"):
        print("[警告] 账本读取失败：%s" % led["ledger_error"], file=sys.stderr)

    if args.ack or args.ack_all:
        today = date.today().isoformat()
        ents = led.get("entries") or {}

        def _ack(k: str) -> None:
            """确认 = 记住**此刻**的内容。变了就重开。

            ★ `acked_fingerprint` 取的是账本里已有的 `fingerprint`
              （上一次运行时写下的），不是现算 —— 因为这里没有线索对象可算。
              如果它是 None（这条从没被 commit 过），就诚实留 None：
              报告会把「已确认但没有指纹」的条数点出来，而不是假装它在看着。
            """
            ents[k]["acked_day"] = today
            ents[k]["acked_fingerprint"] = ents[k].get("fingerprint")

        if args.ack_all:
            for k in ents:
                _ack(k)
            print("已确认 %d 条（都记了当时的内容；变了会重新开口）" % len(ents))
        else:
            if args.ack not in ents:
                print("[停] 账本里没有这个键：%s" % args.ack, file=sys.stderr)
                return 2
            _ack(args.ack)
            print("已确认：%s（变了会重新开口）" % args.ack)
        save(args.ledger, led)
        return 0

    if args.dump:
        ents = led.get("entries") or {}
        print("账本 %s｜条目 %d｜更新 %s" % (args.ledger, len(ents), led.get("updated_at")))
        # ★ 指纹列（v3 遗留项，2026-11-03 补）：人工核对时最常问的两件事是
        #   「这条我确认过了吗」和「它变了没有」—— 而后者只有指纹能答。
        #   分开印 `fp`（当前内容指纹）与 `ack`（确认时记下的那个）：
        #   两者**不等**就是「确认之后内容变了」，也就是它会重新开口。
        #   只印一个数，读者没法自己判断这件事，只能信我们说的。
        print("  %-8s %-8s %-40s 见 说 顺延 静默至"
              % ("指纹", "确认时", "身份"))
        for k, e in sorted(ents.items(), key=lambda kv: -(kv[1].get("n_seen") or 0)):
            _fp = str(e.get("fingerprint") or "—")[:8]
            _afp = str(e.get("acked_fingerprint") or "—")[:8]
            # 两个都在、且不相等 ⇒ 确认之后内容变过。用一个记号点出来。
            _mark = "≠" if (e.get("fingerprint") and e.get("acked_fingerprint")
                            and e.get("fingerprint") != e.get("acked_fingerprint")) else " "
            print("  %-8s %s%-8s %-40s %2d %2d %2d %s"
                  % (_fp, _mark, _afp, k[:40], e.get("n_seen", 0),
                     e.get("n_told_total", 0), e.get("n_deferred", 0),
                     e.get("muted_until") or "—"))
        return 0

    print("用法：--selfcheck｜--dump｜--ack KEY｜--ack-all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
