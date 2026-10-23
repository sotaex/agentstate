# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Antinel 监理 · 收件箱存储（读链 ＋ 一份可变状态）。

★★ 架构关键（详细设计 §2.7）::

    审计链（append-only、不可变）  ──只读──▶  收件箱（视图）
    状态文件（可变、独立）          ──叠加──▶  未读/已读/已处理/已忽略

★ 本模块**不新造事实**：告警事实一律**读链**（真源）后**投影**，不复制一份。
  它只**拥有**那份可变状态（`state.json`）。
  ⇒ 用户清空收件箱，链还在；状态文件坏了，事实不丢（只丢"已读状态"）。
  这是"同一事实两处副本"的解药：**消灭副本，而不是把副本改新**。

★ 家目录沿用产品既有约定：`ANTINEL_HUB_DIR` 或 `~/.antinel`
  （与 `tools/judge_service.py` 同源）。**不另造 `~/.psl`** —— 那是**项目级**目录。
"""
from __future__ import annotations

import glob
import json
import os
import time
from datetime import datetime, timedelta

import inbox_model as M

# ------------------------------------------------------------ 路径 ----
_HUB_ENV = "ANTINEL_HUB_DIR"
_AUDIT_DIRS_ENV = "ANTINEL_AUDIT_DIRS"


def hub_dir():
    """host 级家目录。与 `tools/judge_service.py:37` 同一口径。"""
    return os.path.expanduser(os.environ.get(_HUB_ENV) or "~/.antinel")


def inbox_dir(root=None):
    return os.path.join(root or hub_dir(), "inbox")


def state_path(root=None):
    return os.path.join(inbox_dir(root), "state.json")


def rollup_dir(root=None):
    return os.path.join(root or hub_dir(), "rollup")


def _now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


# ------------------------------------------------------ 告警类型清单 ----
def alert_kinds():
    """告警类型清单 ＝ `host_shield._ALERT_KINDS`（**唯一真源，不许二次实现**）。

    ★ 读不到 ⇒ **抛错**，绝不返回空集。
      返回空集 = 把"读不到清单"渲染成"没有告警" —— 本项目最反对的形状。
    """
    try:
        import host_shield
        ks = set(host_shield._ALERT_KINDS)
    except Exception as e:                      # noqa: BLE001
        raise M.InboxError(
            "读不到告警类型清单（host_shield._ALERT_KINDS）：%s" % (e,)
        ) from None
    if not ks:
        raise M.InboxError("告警类型清单为空 —— 拒绝按「没有告警」处理。")
    return ks


# ---------------------------------------------------------- 投影 ----
#: 链记录 `field` → 归并用的 `topic`（**0.40.0 向后兼容**，见 `project_record`）。
#: ★ 与生产侧 A5 的映射**逐字一致**（不许出现第二套口径）：
#:   `self-check` / `registry` ⇒ `code_drift`（代码/登记表与清单不符 —— 同一件事）
#:   `enabled` / `state`       ⇒ `state_drift`（安全状态字段漂移 —— 另一件事）
_TOPIC_OF_FIELD = {
    "self-check": "code_drift",
    "registry": "code_drift",
    "enabled": "state_drift",
    "state": "state_drift",
}

#: ★★ 0.40.0 第二层兼容：**旧 `subkind` 名 → 现行 `topic`**（已核实的同义改名）。
#:
#: 为什么需要它（本仓实测，2026-10-09 全类型报告审计）：
#:   生产侧在 A5 里把自检不符的 `subkind` 从 `self_check` 改成了 `code_drift`
#:   —— 但**链是 append-only**，改写不了历史记录 ⇒ 归并键 `(kind, topic, level)`
#:   把**同一件事**拆成两行：`host_shield_tamper/self_check`（47 条，10-07..10-09）
#:   与 `host_shield_tamper/code_drift`（17 条，10-09）。用户看到两条
#:   「失守：防护文件被改动」，其实是**一件**（都是「哨兵启动自检不符」）。
#:
#: ★★ 为什么敢合（证据链，不是感觉）：
#:   `remediation._kind_of()` **本来就把这两个值归成同一类**
#:   （`if t in ("self_check", "code_drift"): return "self_check"`）。
#:   ⇒ 也就是说，**产品内部两层口径本来就不一致**：归因层说"一件事"，
#:     归并层说"两件事"。本表让归并层**对齐**归因层 —— 而不是新造第三套口径。
#:   ★ 只映射**已核实的旧名**（键是穷举的），不做前缀/模糊匹配。
_TOPIC_ALIAS = {
    "self_check": "code_drift",     # A5 之前的名字；归因层已视为同类
}


def _host_of(rec):
    """链记录 → `(host, host_confidence)`（T2.2 唯一读取处，四个投影分支共用）。

    ★ **缺失／兜底标签都不填**：没有 `host` 字段（0.33.1 前的旧记录）⇒ `("", "")`；
      `host == "generic"` 且 `host_confidence == "none"`（detect 失败的 fallback
      路径，`hooks/post_tool_use.py:556`）⇒ 同样 `("", "")` —— generic 不是工具名，
      是「不知道」的标签，显示成"generic 工具"就是把不知道显示成知道。
    ★ 读 `host_confidence` 平铺字段（写侧已从 `host_evidence.confidence` 平出，
      `post_tool_use.py:580`）；旧记录两字段都没有 ⇒ 空串（页面按未知分代）。
    """
    h = str(rec.get("host") or "").strip()
    c = str(rec.get("host_confidence") or "").strip()
    if not h or h == "generic" or c == "none":
        return "", c if c and c != "none" else ""
    return h, c


def project_record(rec, kinds):
    """把一条链记录投影成 Alert；不是告警 ⇒ 返回 None。

    ★ **不猜**：两种形状都来自实测（见长程方案 §附"证据与来源"）。
      ① host 级链：`type in _ALERT_KINDS` → level 由 `level_of()` 定（未登记 ⇒ 响亮报错）
      ② 项目级链：`type == "pre_tool_use"` 且 `decision == "block"` → 归一化为 L2
    """
    if not isinstance(rec, dict):
        return None
    t = rec.get("type")
    ts = str(rec.get("ts") or "")

    if t in kinds:
        lvl = M.level_of(t)                     # 未登记 ⇒ UnknownKind（响亮失败）
        _topic = str(rec.get("subkind") or "")
        # ★★ 0.40.0 向后兼容：`subkind` 缺失时按**结构化字段 `field`** 补出 topic。
        #   为什么需要它：0.40.0（A5）之前的生产者只写 `field`、不写 `subkind`
        #   ⇒ 历史记录 topic 为空 ⇒ 归并键把**不同病因压成一行**
        #   （实测 58 条：`enabled`/`state` 与 `self-check`/`registry` 混在一条里，
        #    用户看到"防护文件被改动 ×58"，其实是两件事）。
        #   ★ 读的是**记录里的结构化字段**（`field`），不是 `reason` 文案 ——
        #     文案会改，按文案判档会静默失效（本仓第 4 次同名纪律）。
        #   ★ 映射与 A5 的生产侧**逐字一致**（`self-check`/`registry` → code_drift；
        #     `enabled`/`state` → state_drift），不另立第二套口径。
        #   ★ 只在 `subkind` 为空时补 ⇒ **新记录一律自带 subkind，这条永不覆盖新口径**。
        #   ★★ 它**只补分组/标题，不推断结局**：`field=enabled` 只说明"改的是哪个
        #     字段"，**不**说明"已经恢复了" ⇒ 这里**不许**据此补 `recovered`
        #     （字段缺失＝"不知道"，方向收紧 —— 见 `inbox_model.NO_CONSEQUENCE_KINDS`）。
        #   ⚠️ **必须收窄到 `host_shield_tamper`**：`field` 不是 tamper 独有的
        #      （实测 `host_shield_changed` 同样带 `field="enabled"`）——
        #      不加这道门，一条 L1「注意：防护设置被改动」会被套上 tamper 的
        #      标题「**失守**：防护文件被改动」⇒ **方向相反**的标签
        #      （本探针当场抓到 65 条，见 `_p_report_audit.py` Q3）。
        if not _topic and t == "host_shield_tamper":
            _topic = _TOPIC_OF_FIELD.get(str(rec.get("field") or ""), "")
        # ★★ 0.40.0 第二层兼容：旧 `subkind` 名对齐现行 `topic`（见上方 `_TOPIC_ALIAS`）。
        #   与上面那层**方向相反**：上一层补"本来就没写 topic"的，
        #   这一层改"写了旧名字"的 —— 两层都是**只在投影期归一**，链不动。
        _topic = _TOPIC_ALIAS.get(_topic, _topic)
        _recovered = bool(rec.get("recovered"))
        # ★ 0.53.0（T2.2）：host 归因（「这件事是哪个工具环境里发生的」）——
        #   读链记录的**结构化字段**，缺失／兜底标签都不填（见 `_host_of`）。
        _host, _conf = _host_of(rec)
        _a = M.Alert(
            id=M.alert_id(ts, t, str(rec.get("reason") or "")),
            ts=ts, level=lvl, kind=t,
            # ★ 0.35.3：先按**事由**取更准的标题，没有则回落 kind 标题。
            title=(M.TITLE_OF_TOPIC.get(_topic) or M.TITLE_OF_KIND.get(t, t)),
            detail=str(rec.get("reason") or ""),
            severity=str(rec.get("severity") or ""),
            chain_ref=str(rec.get("hash") or ""),
            # ★ 0.35.3：链记录的**结构化**字段（AUDIT_SCHEMA v1.10）。
            #   页面据此判"有没有后果"，**不解析 reason 文案**。
            recovered=_recovered,
            # ★ 0.35.3：`subkind` → `topic`，用于把"同一件事反复发生"归并。
            #   例：登录自启缺失 → subkind=autostart_missing（14 条 = 1 件事）。
            topic=_topic,
            host=_host, host_confidence=_conf,
        )
        # ★★ 0.43.0：**所有"按记录改档"只在这里、只走这两个函数** ——
        #   · A8（0.40.0）：`host_shield_zone_locked` 兼表成败 ⇒ 成功不是失守
        #     （实测本机 2 条被报成失守）；
        #   · A3（0.43.0）：`recovered=True` 的自愈记录 ⇒ 不顶 R0
        #     （实测 24h 内 17 条顶着 R0，见 `_p_r0_audit3.py`）。
        #   ★ 为什么收进 `M.level_of_record`：此前 A8 是**在投影层手写一段 `if`**
        #     —— 那就是第二套口径（本仓「同一事实两处实现」的标准形状）；
        #     现在 zone 的成败判据仍复用 `M._zone_lock_failed`（它又复用
        #     `remediation._kind_of`），但**改档动作**只有一处。
        _a.level = M.level_of_record(
            t, recovered=_recovered,
            zone_failed=(M._zone_lock_failed(_a)
                         if t == "host_shield_zone_locked" else None))
        _a.title = M.title_of_record(t, _a.level, _topic)
        return _a

    # ★★ 0.40.0：研发态自检不符 —— **故意不进 `_ALERT_KINDS`**（⇒ 不弹气泡：
    #   研发期每次改码都弹一次泡，正是创始人说的"泡泡又冒了"）；
    #   但要**进收件箱**（知情即可）：级别由 `LEVEL_OF_KIND` 给 L1「注意」。
    if t == "host_shield_dev_drift":
        _host, _conf = _host_of(rec)
        return M.Alert(
            id=M.alert_id(ts, t, str(rec.get("reason") or "")),
            ts=ts, level=M.level_of_record(t), kind=t,
            # ★ 标题只取 `TITLE_OF_KIND`：`TITLE_OF_TOPIC["code_drift"]` 那条是给
            #   **R0 的 tamper** 用的（写着"失守"），这里不能借（免得 L1 挂"失守"标题）。
            title=M.TITLE_OF_KIND.get(t, t),
            detail=str(rec.get("reason") or ""),
            severity=str(rec.get("severity") or ""),
            chain_ref=str(rec.get("hash") or ""),
            recovered=False,
            topic=str(rec.get("subkind") or ""),
            host=_host, host_confidence=_conf,
        )

    # ★★ 0.53.0（T1.3）：首检提醒 —— 与 `host_shield_dev_drift` **同型**：
    #   故意不进 `_ALERT_KINDS`（⇒ 不弹气泡：温和提醒不该敲门），但要
    #   **进收件箱**（level 由 `LEVEL_OF_KIND` 给 L1「注意」）。生成侧与
    #   去重见 `host_shield.exam_reminder_check`；判定唯一实现是
    #   `inbox_model.exam_state`。
    if t == "exam_reminder":
        _topic = str(rec.get("subkind") or "")
        _host, _conf = _host_of(rec)
        return M.Alert(
            id=M.alert_id(ts, t, str(rec.get("reason") or "")),
            ts=ts, level=M.level_of_record(t), kind=t,
            # ★ 标题只取 `TITLE_OF_KIND`（S1/S3 的具体事由在 detail/reason 里，
            #   不借 `TITLE_OF_TOPIC` —— 那个表是 R0 tamper 的病因标题）。
            title=M.TITLE_OF_KIND.get(t, t),
            detail=str(rec.get("reason") or ""),
            severity=str(rec.get("severity") or ""),
            chain_ref=str(rec.get("hash") or ""),
            recovered=False,
            topic=_topic,
            host=_host, host_confidence=_conf,
        )

    if t == "pre_tool_use" and rec.get("decision") == "block":
        hits = rec.get("rules_hit") or []
        rule = str(hits[0]) if hits else ""
        snip = str(rec.get("match_snippet") or "")
        detail = "规则 %s · 命中「%s」" % (rule or "?", snip) if (rule or snip) else ""
        # ★ 0.51.2 第二轮：原始命令/目标路径一并进 Alert —— 详情行要亮
        #   「要删的是哪个文件」（创始人：直接讲要删什么文件）。写侧已
        #   mask_secrets；渲染出口 `_vis` 会 HTML 转义，不会注入页面。
        _inp = rec.get("input") or {}
        # ★ 0.53.0（T2.2）：拦截事件的 host 归因 —— 「哪个工具环境里想干危险事」。
        #   这是 host 字段**最该亮**的一类：项目链拦截不带 host，用户看到
        #   「拦截：危险操作被挡下」却不知道是哪个客户端触发的。
        _host, _conf = _host_of(rec)
        return M.Alert(
            id=M.alert_id(ts, "tool_call_blocked", rule + snip),
            ts=ts, level=M.level_of("tool_call_blocked"), kind="tool_call_blocked",
            title=M.TITLE_OF_KIND["tool_call_blocked"],
            detail=detail, rule_id=rule, snippet=snip,
            severity=str(rec.get("severity") or ""),
            chain_ref=str(rec.get("hash") or ""),
            command=str(_inp.get("command") or ""),
            file_path=str(_inp.get("file_path") or ""),
            # ★ 同一规则反复拦 ⇒ 归并成一件事（"规则 DST-01 拦了 6 次"）。
            topic=rule,
            host=_host, host_confidence=_conf,
        )
    return None


# ------------------------------------------------------- 链文件发现 ----
def _day_of(path):
    """从 `YYYY-MM-DD.jsonl` 取日期；取不到 ⇒ None（不参与窗口过滤）。"""
    base = os.path.basename(path)
    try:
        return datetime.strptime(base[:10], "%Y-%m-%d").date()
    except Exception:                           # noqa: BLE001
        return None


def _registry_roots(root=None):
    """`registry.json` 里登记过的项目根（每个项目的链在 `<root>/.psl/audit/`）。"""
    p = os.path.join(root or hub_dir(), "registry.json")
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return [str(x.get("root")) for x in (data.get("projects") or []) if x.get("root")]
    except Exception:                           # noqa: BLE001
        return []


#: 取数窗口。**两个口径，不许混用**（混用就是"报告取数参数而不是报告数据"）：
#:   `WINDOW_RECENT_DAYS` —— 收件箱／日报："最近"，看得见就够；
#:   `WINDOW_ALL`         —— 账本：**历史全量，不设窗口**。
#: ★★ 为什么账本不能沿用 7 天（创始人 2026-10-20「有记录永远是 8 天，从来不会
#:   增长」）：账本的「有记录多少天」若被取数窗口封顶，它就**恒等于窗口长度**
#:   （7 天窗口 ⇒ 含今天恰好 8 天），读者看到的是**取数参数**，不是数据。
#:   实测本机：窗口 7 天 ⇒ 8 天；放开 ⇒ **39 天**（2026-09-10 → 2026-10-20）。
WINDOW_RECENT_DAYS = 7
WINDOW_ALL = None


def discover_chain_files(days=WINDOW_RECENT_DAYS, root=None, include_projects=True):
    """发现要读的链文件。★ 每个来源都有消费点（不留"登记了没人查"的字段）。

    - host 级：`<hub>/rollup/*.jsonl`
    - 追加源：`ANTINEL_AUDIT_DIRS`（逗号分隔的目录）
    - 项目级：`registry.json` 里每个项目根的 `<root>/.psl/audit/*.jsonl`

    ★ `days=None`（＝ `WINDOW_ALL`）⇒ **不设 cutoff**，返回全部链文件。
      旧版任何取法都带窗口，账本因此永远读不到 7 天之前的记录。
    """
    cutoff = None if days is None else \
        datetime.now().date() - timedelta(days=max(0, int(days)))
    files = []

    def _take(pat):
        for p in glob.glob(pat):
            d = _day_of(p)
            if d is None or cutoff is None or d >= cutoff:
                files.append(os.path.normpath(p))

    _take(os.path.join(rollup_dir(root), "*.jsonl"))

    for d in (os.environ.get(_AUDIT_DIRS_ENV) or "").split(","):
        d = d.strip()
        if d:
            _take(os.path.join(d, "*.jsonl"))

    if include_projects:
        for r in _registry_roots(root):
            if os.path.isdir(r):
                _take(os.path.join(r, ".psl", "audit", "*.jsonl"))

    return sorted(set(files))


def read_records(chain_files):
    """逐行读链。坏行**跳过但不假装没发生**（计入 bad_lines 由调用方处置）。"""
    recs, bad = [], 0
    for p in chain_files:
        try:
            with open(p, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        recs.append(json.loads(line))
                    except Exception:           # noqa: BLE001
                        bad += 1
        except OSError:
            bad += 1
    return recs, bad


# ------------------------------------------------------------ 状态 ----
def load_state(root=None):
    """读可变状态。

    ★ 状态文件**损坏时不许把整个收件箱带崩**（详细设计 §8.2：链仍在，收件箱可重建，
      只丢"已读状态"）。做法＝**把坏文件改名让开**（留证据、不删除），返回空 dict。
      ⇒ 事实不丢、界面还能用、坏文件留在盘上等人看。
    """
    try:
        with open(state_path(root), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception:                           # noqa: BLE001
        p = state_path(root)
        try:
            os.rename(p, p + ".corrupt-%d" % int(time.time()))
        except OSError:
            pass
        return {}


def state_corruption(root=None):
    """列出被改名让开的坏状态文件（**有它 ＝ 曾经坏过**，界面应显式提示）。"""
    d = inbox_dir(root)
    try:
        return sorted(f for f in os.listdir(d) if f.startswith("state.json.corrupt-"))
    except OSError:
        return []


def save_state(st, root=None):
    """全量覆盖写状态（0600）。★ 状态是**派生看法**，丢了可重建，所以可覆盖。"""
    p = state_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(st, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, p)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def _reopens(dst, intent):
    """这次置位算不算「重开」。

    ★★ 0.55.0（复核 F1）：抽成函数不是为了好看 —— 负控要换掉**同一份实现**
      （`_reopens = lambda dst, intent: True` 就复现了旧行为），
      规则写两处的话，负控只能复制代码去测副本。
    """
    return dst not in M.CLOSED_STATES and intent == "reopen"


def _apply(st, item_id, dst, note="", actor="owner", t=None, level=None,
           intent="read"):
    """把一次置位**应用到内存里的状态表**（**不落盘**）。返回该条目。

    ★★ 唯一实现：`set_state()`（单条）、`set_state_many()`（批量）、
      `close_recovered()`（复核结案）都走这里。写第二遍就一定会漂，
      而漂的方向必然是**批量漏了一格** —— 比如忘了写 `gap_state`，
      于是 496 条"已结案"在账上仍算缺口（灯照样红，且查不出为什么）。
    """
    cur = (st.get(item_id) or {}).get("state", "unread")
    if not M.can_transition(cur, dst):
        raise M.BadState("不允许从 %s 迁到 %s" % (cur, dst))

    if dst == "ignored":
        M.check_ignore_note(level, note)

    t = t or _now()
    ent = st.get(item_id) or {}
    ent["state"] = dst
    ent["actor"] = actor
    if dst == "read" and not ent.get("read_at"):
        ent["read_at"] = t
    if dst in M.CLOSED_STATES:
        # ★ `closed_at` 从 2026-10-22 起有两个含义，按 `gap_state` 读：
        #   done ⇒ "处置时刻"；ignored ⇒ "你说先不管的时刻"（`ack_expired` 用它算复核期）。
        ent["closed_at"] = t
        ent["note"] = note or ""
    elif _reopens(dst, intent):
        # ★ 0.55.0：只有**重开**才清 `closed_at`。知情（read）必须把"什么时候搁下的"
        #   留着 —— 那是复核期的唯一基准，看一眼就清掉等于把计时归零。
        ent.pop("closed_at", None)
    # ---------------------------------------------------------------- 缺口态
    # ★★ 40 格 · 人·判：`ignored` **不等于**修好了。
    #   以前这里只写 state，于是"我决定先不管"与"已经好了"在账面上无法区分，
    #   分档只能一刀切归档 ⇒ 未修的缺口从待办和计数里一起消失。
    #   ⇒ 现在把两件事分开写：state 答"你知不知道"，gap_state 答"缺口还在不在"。
    if dst == "done":
        ent["gap_state"] = M.GAP_CLOSED
    elif dst == "ignored":
        ent["gap_state"] = M.GAP_ACKED
    elif _reopens(dst, intent):
        ent["gap_state"] = M.GAP_OPEN
    # ★ 0.55.0（F1）：其余情况是 `read`/`unread` 且这次只是"知情"
    #   ⇒ 缺口态**一个字节都不动**。旧实现在这里无条件写 `GAP_OPEN`，
    #   于是"点开看一眼"就足以撤销 ack（实测：`ignored → read` 得
    #   `('read','open',False)`，`closed_at` 被清、复核计时归零）。
    st[item_id] = ent
    return ent


def set_state(item_id, dst, note="", actor="owner", now=None, level=None, root=None,
              intent="read"):
    """置状态。**校验迁移**；忽略 R0 必须写备注。返回置位后的状态条目。

    `level` 不传 ⇒ 自动从链里查这条告警的级别（CLI 用；测试可直接传）。

    ★★ 0.55.0（复核 F1）`intent`：**`read` 这个目标态不再自动等于"重开"**。
      旧实现只要 `dst="read"` 就把 `gap_state` 打回 `open`、把 `closed_at` 删掉
      ⇒ **任何**写 `read` 的调用点都会把已忽略/已处置的缺口重新打开。
      门禁当时装在 HTTP 层（`/action` 的 `_auto_read_allowed`），
      于是 `remediation_ack`（`inbox_server.py:4127`）这个侧门直接绕过去了。
      ⇒ 权威放在这一层：`intent="read"`（知情，默认）**不动**缺口态与 `closed_at`；
        `intent="reopen"`（重开）才把缺口打回 `open`。
      ★ 默认值取安全侧：不传参的旧调用点行为变成"只记已读"，而"只看一眼就把缺口
        重新打开"正是 A1 实测过的伤害。
    """
    if intent not in ("read", "reopen"):
        raise M.BadState("未知意图 %s（合法：read, reopen）" % (intent,))
    if level is None:
        found = [it for it in load_items(root=root) if it.id == item_id]
        if not found:
            raise M.InboxError("找不到告警 %s" % item_id)
        level = found[0].level

    st = load_state(root)
    ent = _apply(st, item_id, dst, note=note, actor=actor, t=now or _now(),
                 level=level, intent=intent)
    save_state(st, root)
    return ent


def set_state_many(item_ids, dst, note="", actor="owner", now=None, levels=None,
                   root=None, intent="read"):
    """同一目标态批量置位：**一次读、一次写**。返回 `(done, skipped)`。

    ★ 为什么要它（实测，不是估）：本机状态表 766 条 / 121 KB，
      `save_state()` 单次 **141 ms**（Windows 上 `os.replace`＋`chmod` 占大头）
      ⇒ 496 条逐条走 `set_state()` 光写盘就要 **70 秒**，且中途每一条都要
      重写整份状态（任一次失败都留一个半成品账）。
    ★ 迁移规则**不复制**：逐条走 `_apply()`（唯一实现），只是把读写各收成一次。
    ★ 单条失败**不拖垮整批**（已是终态、目标非法都只跳过），与 `done_all` 同语义。
    """
    if intent not in ("read", "reopen"):
        raise M.BadState("未知意图 %s（合法：read, reopen）" % (intent,))
    levels = levels or {}
    st = load_state(root)
    t = now or _now()
    done, skipped = [], []
    for iid in item_ids:
        try:
            _apply(st, iid, dst, note=note, actor=actor, t=t,
                   level=levels.get(iid), intent=intent)
        except (M.BadState, M.InboxError) as e:
            skipped.append((iid, str(e)))
            continue
        done.append(iid)
    if done:
        save_state(st, root)
    return done, skipped


def _gap_level():
    """缺口族的事件级别（本机现为 `R0`）。**真源在 `facts.GAP_LEVEL`**，这里只懒读。

    ★ 为什么不在此处再写一个 `"R0"`：族别是**产品口径**，写在两处必然漂
      （一处说 R0、一处说 R1 时，灯与结案会各算各的）。也不在模块顶层 import ——
      `facts` 会懒加载本模块，顶层互相 import 会成环。
    """
    import facts as _F
    return _F.GAP_LEVEL


def unrepaired_gap_items(items=None, root=None):
    """**没结案的缺口记录**（`open` 或 `acked`、记录级 `R0`）。返回 Item 列表。

    ★ 与 `facts.harmful_gaps()` **故意不同**，且只差一处：这里**不看**事由级复档
      （`LEVEL_OF_KIND`）与复核期（`active`），只认**记录级** `R0` 与"结没结案"。
      理由：复核期管的是"还算不算此刻的后果"，**不管**"这笔账结没结"——
      老账哪怕沉寂半年，结案也是对的；而件数/灯由 `harmful_gaps()` 那边管。
    """
    items = load_items(root=root) if items is None else items
    lv = _gap_level()
    return [it for it in items
            if it.level == lv
            and M.gap_state_of(it) in (M.GAP_OPEN, M.GAP_ACKED)]


def _recovery_kinds():
    """**有恢复判据**的事由集合（真源：`facts.RECOVERY_OF`）。懒读，理由同上。

    ★ 为什么要在这里再挡一道：证据句是调用方传进来的 dict，一个手写的
      `{"host_shield_zone_locked": "..."}` 就能把一件**根本没有恢复判据**的事
      结掉。判据放在证据生成处（`facts.recovery_evidence`）只挡住了生产路径，
      挡不住第二个调用点 —— 而"第二个调用点"正是本仓反复出事的形状。
    """
    import facts as _F
    return set(_F.RECOVERY_OF)


def close_recovered(evidence, items=None, root=None, now=None, actor="reconcile",
                    note_fmt="复核结案：%s"):
    """把「已有恢复证据」的事由，此前**没结案的记录**一次性结案。返回统计。

    ★★ 这是 B（恢复即结案）的**唯一实现**。为什么要有它（本机实测）：
      反复发生的同一件事，每次自愈只把**当次那一条**降档（`recovered=True`
      ⇒ R0→L1），**不回补**历史 ⇒ 「同一件事复发 124 次、每次都自愈」在账上
      留成 124 条欠账；页面读出来是「有 3 件没修」，而机器此刻半点毛病没有。

    ★ 三条不许松：
      ① `evidence` 为空（`{}`／全是空串）⇒ **一条都不关**（fail-closed）。
         否则它就是一把"清账器"——把真缺口一起抹平，而抹平之后页面全绿，
         再没有任何东西能发现它被抹平过。
      ② 只关**证据覆盖到的那个事由**（`kind` 精确匹配），绝不因为 A 事恢复了
         就连带关 B 事（本机三件事的恢复条件各不相同）。
      ③ 关掉的每一条都写**结案说明**（`note`）与时刻（`closed_at`）——
         账要能回答"谁在什么时候凭什么关的"。
    """
    if not isinstance(evidence, dict):
        raise M.InboxError("恢复证据必须是 dict：事由 → 证据句")
    kinds_ok = _recovery_kinds()
    ev = {k: v.strip() for k, v in evidence.items()
          if isinstance(v, str) and v.strip() and k in kinds_ok}
    out = {"closed": [], "skipped": [], "by_kind": {}, "no_evidence": True}
    if not ev:
        return out
    out["no_evidence"] = False
    items = load_items(root=root) if items is None else items
    st = load_state(root)
    # ★★ 目标选取**以状态文件为准**，不以外面的 Item 对象为准：
    #   `Item` 只是投影（`load_items` 用它，判据也会拿它注入夹具）；而"关不关"
    #   是写账动作，必须看账上此刻的真值。否则同一条会被关第二次 ——
    #   第二次会把 `closed_at` 与"当初为什么关"的说明一起盖掉。
    targets = []
    for it in items:
        if it.kind not in ev or it.level != _gap_level():
            continue
        e = st.get(it.id) or {}
        gap = e.get("gap_state") or M.gap_state_of(it)
        if gap in (M.GAP_OPEN, M.GAP_ACKED):
            targets.append((it, gap))
    if not targets:
        return out
    t = now or _now()
    for it, gap in targets:
        note = note_fmt % ev[it.kind]
        try:
            if gap == M.GAP_ACKED:
                # ★ 「先不管」不能一步跳到「已处置」—— 迁移表没有这条边，
                #   而绕过去（直接 `_apply(...,"done")` 或改表）就是侧门。
                #   合法走法：先标「知道了」（`intent="read"` 不动缺口态），再结案。
                #   两步都走唯一实现，同一次落盘，账上看不到中间态。
                _apply(st, it.id, "read", actor=actor, t=t, level=it.level,
                       intent="read")
            _apply(st, it.id, "done", note=note, actor=actor, t=t, level=it.level)
        except (M.BadState, M.InboxError) as e:
            out["skipped"].append((it.id, str(e)))
            continue
        out["closed"].append(it.id)
        out["by_kind"][it.kind] = out["by_kind"].get(it.kind, 0) + 1
    if out["closed"]:
        save_state(st, root)
    return out


# ★★ 0.35.3：`mark_all_read()`（批量「全部已读」）**已整体下线**。
#   创始人 2026-10-06 拍板：「1 取消吧」。页面按钮、服务端动作、托盘菜单、
#   守护进程分支、CLI 子命令**一并取消** —— 只留一处「点开即已读」
#   （见 inbox_server._READ_JS）。**半取消＝没取消**：留着托盘菜单里的
#   「Mark all read」，用户点了却和页面说法不一致，比不取消更糟。


# ------------------------------------------------------------ 组装 ----
#: 文件指纹 -> 该文件投影出的 Alert 列表。
#  ★★ 为什么这样缓存是**严格正确**的（不是"同一事实两处副本"）：
#    `project_record(rec, kinds)` 只依赖**这一条记录本身**与 kinds，
#    **不依赖其它文件、不依赖状态文件**（状态是后面才叠加的）。
#    ⇒ 同一个 (path, mtime_ns, size, kinds) 必然产出同一个列表。
#    审计链是 **append-only** ⇒ 任一文件被追加，mtime_ns/size 必变 ⇒ 该文件自动失效。
#    ⇒ **不存在"静默落后"**：改了内容就必然重算。
#  ★ 只缓存**投影出的 Alert**（本机 43149 行 → 212 条），
#    **不缓存原始记录**（36.8 MB JSON 全缓存会吃掉几百 MB 内存）。
#  ★★ 为什么必须要有它（0.35.2 实测，创始人 2026-10-06「点开像卡死」）：
#    本机 20 个链文件 / 43149 行 / 36.8 MB；每次开页面都**全量**重投影 ≈ 3.6s，
#    日报再逐条复算整条链 ≈ 5–10s ⇒ 四个视图实测 **5–18 秒**。
#    有了它，一次刷新只重算**当天那个正在追加的文件**，其余 19 个直接命中。
_PROJ_CACHE = {}
#: ★★ 0.53.2：64 → **512**。为什么（实测，不是估）：
#:   64 是 0.35.2 按"本机 20 个链文件"定的。账本改**全量取数**后一次扫描
#:   **107 个文件**（本机 2026-09-10 → 10-20）⇒ 上限小于文件数时，每读一个新
#:   文件就挤掉一个旧的，**缓存 100% 未命中**（实测：连续两次全量各 6.6s / 5.5s）。
#:   提到 512 后实测：首次 6.6s，**之后 0.02s**。
#:   ⇒ **上限必须大于一次全量扫描的文件数**，否则"全量窗口"虽然在参数上放开了，
#:     实际上每次开账本页都要重投影 21 万行 —— 窗口放开了一半，账本仍然慢得
#:     让人不敢点。判据 L-02 钉住这条（用真文件数比对，不写死）。
#:   512 约合 17 个月的逐日链文件（1 文件/天），留了余量；仍是无界增长的护栏。
_PROJ_CACHE_MAX = 512


def _project_file(path, kinds_key, kinds):
    """读**一个**链文件 → 投影成 Alert 列表（按文件指纹缓存）。

    ★ 缓存键含 `mtime_ns` 与 `size`：文件被追加 ⇒ 键变 ⇒ 必然重算。
    ★ 读不到文件（`OSError`）⇒ **不缓存**，直接返回空列表（下次仍会重试）。
    """
    try:
        stt = os.stat(path)
        fp = (os.path.normpath(path), stt.st_mtime_ns, stt.st_size, kinds_key)
    except OSError:
        return []
    hit = _PROJ_CACHE.get(fp)
    if hit is not None:
        return hit
    recs, _bad = read_records([path])
    out = [a for a in (project_record(r, kinds) for r in recs) if a is not None]
    if len(_PROJ_CACHE) >= _PROJ_CACHE_MAX:
        _PROJ_CACHE.pop(next(iter(_PROJ_CACHE)), None)   # 丢最早的那个
    _PROJ_CACHE[fp] = out
    return out


def load_items(chain_files=None, root=None, kinds=None):
    """投影链 → 叠加状态 → Item 列表（按时间倒序）。

    ★ 0.35.2：改为**逐文件**走 `_project_file()`（带文件指纹缓存）。
      语义与旧版**完全一致**（同一顺序遍历、同一个 id 先去重者胜），
      只是**没变的文件不再重算**。
    """
    kinds = kinds if kinds is not None else alert_kinds()
    files = discover_chain_files(root=root) if chain_files is None else chain_files
    kinds_key = tuple(sorted(kinds))

    st = load_state(root)
    seen, out = set(), []
    for path in files:
        for a in _project_file(path, kinds_key, kinds):
            if a.id in seen:
                continue
            seen.add(a.id)
            e = st.get(a.id) or {}
            state = e.get("state") or "unread"
            if state not in M.STATES:
                state = "unread"                    # 状态文件被改坏 ⇒ 退回未读（宁可多提醒）
            out.append(M.Item(alert=a, state=state,
                              read_at=e.get("read_at") or "",
                              closed_at=e.get("closed_at") or "",
                              note=e.get("note") or "",
                              actor=e.get("actor") or "owner",
                              gap_state=(e.get("gap_state")
                                         if e.get("gap_state") in M.GAP_STATES else "")))
    out.sort(key=lambda it: (it.ts, it.id), reverse=True)
    return out


def load_items_all(root=None, kinds=None):
    """账本专用：**全量**取数（`discover_chain_files(days=WINDOW_ALL)`）。

    ★ 为什么单开一个入口而不是让调用方各自传 `days=None`：账本的"有记录多少天"
      一旦被窗口封顶，就**恒等于窗口长度**（创始人 2026-10-20 指出的"永远是 8 天"）。
      这类事故的形状是**默认值吃掉了口径** —— 每多一个调用点就多一次机会写回
      默认窗口。留一个**名字里带 all** 的入口，判据（L-01）才好锚住"账本不许用
      带窗口的取数"，而不是去猜每个调用点传了什么。
    ★ 口径本身没变：仍走同一个 `load_items`，只是 chain_files 不带窗口。
    """
    return load_items(chain_files=discover_chain_files(days=WINDOW_ALL, root=root),
                      root=root, kinds=kinds)


# ------------------------------------------------------------ 导出 ----
def export_items(fmt="json", root=None, chain_files=None, scope=None):
    """导出收件箱（含状态）。★ 导出的是**看法+状态**；事实请用 `antinel verify` 核链。

    ★★ 0.35.3：`scope`（口径说明）**只在 JSON 里做进结构内部**，成为
      `_export_scope` 字段；**不传 `scope` 时输出仍是原来的顶层数组**，
      旧调用方不受影响。

      为什么 JSON 不走"第一行前缀"：加了前缀的 `--format json`
      **根本不是合法 JSON**（实测 `json.loads` 直接 JSONDecodeError）——
      那比"没说口径"更糟。口径该在结构里，不该挡在结构前面。
    """
    items = load_items(root=root, chain_files=chain_files)
    rows = [it.to_dict() for it in items]
    if fmt == "json":
        if scope:
            return json.dumps({"_export_scope": scope, "count": len(rows),
                               "items": rows}, ensure_ascii=False, indent=1)
        return json.dumps(rows, ensure_ascii=False, indent=1)
    if fmt == "csv":
        cols = ["id", "ts", "level", "kind", "state", "title", "detail",
                "rule_id", "snippet", "chain_ref", "note", "actor"]
        lines = [",".join(cols)]
        for r in rows:
            lines.append(",".join('"%s"' % str(r.get(c, "")).replace('"', '""')
                                  for c in cols))
        return "\n".join(lines) + "\n"
    if fmt == "md":
        lines = ["| 级别 | 状态 | 时间 | 标题 | 规则 | 链引用 |",
                 "|---|---|---|---|---|---|"]
        for r in rows:
            lines.append("| %s | %s | %s | %s | %s | %s |"
                         % (r["level"], r["state"], r["ts"], r["title"],
                            r["rule_id"] or "-", (r["chain_ref"] or "-")[:10]))
        return "\n".join(lines) + "\n"
    raise M.InboxError("未知导出格式 %r（json/csv/md）" % (fmt,))
