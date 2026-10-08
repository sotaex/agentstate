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
        _topic = str(rec.get("subkind") or "")
        return M.Alert(
            id=M.alert_id(ts, t, str(rec.get("reason") or "")),
            ts=ts, level=lvl, kind=t,
            # ★ 0.35.3：先按**事由**取更准的标题，没有则回落 kind 标题。
            title=(M.TITLE_OF_TOPIC.get(_topic) or M.TITLE_OF_KIND.get(t, t)),
            detail=str(rec.get("reason") or ""),
            severity=str(rec.get("severity") or ""),
            chain_ref=str(rec.get("hash") or ""),
            # ★ 0.35.3：链记录的**结构化**字段（AUDIT_SCHEMA v1.10）。
            #   页面据此判"有没有后果"，**不解析 reason 文案**。
            recovered=bool(rec.get("recovered")),
            # ★ 0.35.3：`subkind` → `topic`，用于把"同一件事反复发生"归并。
            #   例：登录自启缺失 → subkind=autostart_missing（14 条 = 1 件事）。
            topic=_topic,
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
            # ★ 同一规则反复拦 ⇒ 归并成一件事（"规则 DST-01 拦了 6 次"）。
            topic=rule,
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
_PROJ_CACHE_MAX = 64          # 只留最近 64 个指纹，防无界增长


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
                              actor=e.get("actor") or "owner"))
    out.sort(key=lambda it: (it.ts, it.id), reverse=True)
    return out


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
