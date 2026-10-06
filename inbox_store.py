# -*- coding: utf-8 -*-
"""值守台 · 收件箱存储（读链 ＋ 一份可变状态）。

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
        return M.Alert(
            id=M.alert_id(ts, t, str(rec.get("reason") or "")),
            ts=ts, level=lvl, kind=t,
            title=M.TITLE_OF_KIND.get(t, t),
            detail=str(rec.get("reason") or ""),
            severity=str(rec.get("severity") or ""),
            chain_ref=str(rec.get("hash") or ""),
        )

    if t == "pre_tool_use" and rec.get("decision") == "block":
        hits = rec.get("rules_hit") or []
        rule = str(hits[0]) if hits else ""
        snip = str(rec.get("match_snippet") or "")
        detail = "规则 %s · 命中「%s」" % (rule or "?", snip) if (rule or snip) else ""
        return M.Alert(
            id=M.alert_id(ts, "tool_call_blocked", rule + snip),
            ts=ts, level=M.level_of("tool_call_blocked"), kind="tool_call_blocked",
            title=M.TITLE_OF_KIND["tool_call_blocked"],
            detail=detail, rule_id=rule, snippet=snip,
            severity=str(rec.get("severity") or ""),
            chain_ref=str(rec.get("hash") or ""),
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


def discover_chain_files(days=7, root=None, include_projects=True):
    """发现要读的链文件。★ 每个来源都有消费点（不留"登记了没人查"的字段）。

    - host 级：`<hub>/rollup/*.jsonl`
    - 追加源：`ANTINEL_AUDIT_DIRS`（逗号分隔的目录）
    - 项目级：`registry.json` 里每个项目根的 `<root>/.psl/audit/*.jsonl`
    """
    cutoff = datetime.now().date() - timedelta(days=max(0, int(days)))
    files = []

    def _take(pat):
        for p in glob.glob(pat):
            d = _day_of(p)
            if d is None or d >= cutoff:
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


def set_state(item_id, dst, note="", actor="owner", now=None, level=None, root=None):
    """置状态。**校验迁移**；忽略 R0 必须写备注。返回置位后的状态条目。

    `level` 不传 ⇒ 自动从链里查这条告警的级别（CLI 用；测试可直接传）。
    """
    if level is None:
        found = [it for it in load_items(root=root) if it.id == item_id]
        if not found:
            raise M.InboxError("找不到告警 %s" % item_id)
        level = found[0].level

    st = load_state(root)
    cur = (st.get(item_id) or {}).get("state", "unread")
    if not M.can_transition(cur, dst):
        raise M.BadState("不允许从 %s 迁到 %s" % (cur, dst))

    if dst == "ignored":
        M.check_ignore_note(level, note)

    t = now or _now()
    ent = st.get(item_id) or {}
    ent["state"] = dst
    ent["actor"] = actor
    if dst == "read" and not ent.get("read_at"):
        ent["read_at"] = t
    if dst in M.CLOSED_STATES:
        ent["closed_at"] = t
        ent["note"] = note or ""
    else:
        ent.pop("closed_at", None)
    st[item_id] = ent
    save_state(st, root)
    return ent


def mark_all_read(now=None, root=None):
    """★ "全部已读"：把**未读**都置为已读。

    ★★ 它**不减少未处理数** —— 未读+已读都算未处理。这是刻意的：
      否则这个按钮就成了"把没处理的事藏起来"的手段（假守卫）。
    """
    st = load_state(root)
    t = now or _now()
    n = 0
    for it in load_items(root=root):
        if it.state == "unread":
            ent = st.get(it.id) or {}
            ent["state"] = "read"
            ent["actor"] = ent.get("actor") or "owner"
            ent["read_at"] = ent.get("read_at") or t
            st[it.id] = ent
            n += 1
    if n:
        save_state(st, root)
    return n


# ------------------------------------------------------------ 组装 ----
def load_items(chain_files=None, root=None, kinds=None):
    """投影链 → 叠加状态 → Item 列表（按时间倒序）。"""
    kinds = kinds if kinds is not None else alert_kinds()
    files = discover_chain_files(root=root) if chain_files is None else chain_files
    recs, _bad = read_records(files)

    st = load_state(root)
    seen, out = set(), []
    for r in recs:
        a = project_record(r, kinds)
        if a is None or a.id in seen:
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
                          actor=e.get("actor") or "owner"))
    out.sort(key=lambda it: (it.ts, it.id), reverse=True)
    return out


# ------------------------------------------------------------ 导出 ----
def export_items(fmt="json", root=None, chain_files=None):
    """导出收件箱（含状态）。★ 导出的是**看法+状态**；事实请用 `antinel verify` 核链。"""
    items = load_items(root=root, chain_files=chain_files)
    rows = [it.to_dict() for it in items]
    if fmt == "json":
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
