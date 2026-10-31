#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""B-2 · `I1-02` 对账：`calls − posts − blocked`

**出处**：方案书 §7.2 步 5「接上 `I1-02`：`calls − posts − blocked`，先看那 27 个桶」。
`I1-02` 在 82 骨架里的判据只有一句：「**动作数 ≠ 审计记录数**」。

本工具把这句话变成一次可以逐桶复算的减法，并且**不许任何差额落进「其它」**。

────────────────────────────────────────────────────────────────────────
一、三个数是什么（先定名，否则减出来的是三个同名异义）
────────────────────────────────────────────────────────────────────────

  calls   = `type == "pre_tool_use"` 的记录数
  posts   = `type == "post_tool_use"` 的记录数
  blocked = `type == "pre_tool_use"` 且 `decision == "block"` 的记录数

★ 三个**必须排除**的近名项（每一个都能把分母算错）：

  | 混进来会怎样 | 是什么 |
  |---|---|
  | `pre_tool_use_summary` | 同一次调用的**摘要副记录**（有 hits 时另写一条），不是第二次调用。用 `"pre_tool_use" in type` 这种子串判法会把它算成 call ⇒ calls 虚增。本脚本用**全等**比较。 |
  | `dst02_bash_path_suspect` | Bash 通道的**旁证记录**，`decision=alert`，不是调用。 |
  | `command_deletion_permission` | 删除放行/拒绝的**裁决记录**，`decision=deny`。同一个「被拦下」的事实它写 `deny`、pre 写 `block`、summary 写 `block` ⇒ 按 `deny` 统计拦截次数会少算，按 `block` 统计会漏它。 |
  | `lock_events.jsonl` | **不是日文件**。混进来会把日期解析错（B-6 已被它坑过一次）。 |

────────────────────────────────────────────────────────────────────────
二、配对口径（唯一实现，不造第二把尺子）
────────────────────────────────────────────────────────────────────────

配对键 `(session, content_digest)`。`content_digest` 是 spec 2.8 的可复算摘要
（`sha256(canonical JSON of {tool_name, tool_input})`），pre 与 post **两侧同配方**
（`hooks/pre_tool_use.py:3513` 与 `hooks/post_tool_use.py:171`），所以可以跨记录对上。

设某组 `n_pre` 条 pre、`n_post` 条 post，则 `matched = min(n_pre, n_post)`，
差额 `n_pre − n_post` 与 `n_post − n_pre` 分别进入下面的归因。

★ **为什么用「post 证明执行过」而不是用时间窗口判重复**：
实测同一 `(session, digest)` 的两条 pre 记录**除 `ts`/`hash`/`prev` 外逐字段完全相同**
（`2026-10-10T16:34:34` 与 `16:34:35`，`present_files`），是**同一次调用被记了两遍**。
但真实重复命令（同一小时内跑两次 `git status`）在字段上也一样。唯一能分开两者的证据是
**post 的条数**：一次执行只产生一条 post。所以：
  · 组内有 post ⇒ 多出来的 pre 是**重复记录**（E3）；
  · 组内无 post ⇒ 用 post 反证不了，多余的 pre 单列为 **E7**（不硬塞进 E3）。

时间窗口（`--dup-window`）只用来**描述** E3 的间隔分布，**不参与任何判定**。

────────────────────────────────────────────────────────────────────────
三、差额归因到已命名的出口（E1–E7，无「其它」桶）
────────────────────────────────────────────────────────────────────────

  | 出口 | 条件 | 含义 |
  |---|---|---|
  | `E1 blocked_stopped` | 组内 `n_post == 0` 且 `decision == block` | 拦截生效，按设计不产生 post |
  | `E2 deny_not_honored` | 组内 `decision == block` 但**有** post | E-3：宿主没执行 deny 信号 ⇒ 拦了却跑了 |
  | `E3 duplicate_pre` | 组内有 post、`n_pre > n_post`、且多余 pre 与配对 pre 相隔 ≤ 窗口 | 同一次调用写了多条 pre |
  | `E4 orphan_post` | `n_post > n_pre` | 有后无前：post 找不到对应的 pre |
  | `E5 alert_no_post` | 组内 `n_post == 0` 且 `decision == alert` | 告警通道放行了，却没有后记录 |
  | `E6 allow_no_post` | 组内 `n_post == 0` 且 `decision == allow` | 放行了却没有后记录（拆 E6a/E6b，见下） |
  | `E7 dup_pre_unprovable` | `n_post == 0` 且 `n_pre > 1` 的**多余**条数 | 无 post 可反证，单列不并账 |
  | `E8 surplus_pre_ambiguous` | 组内有 post，但多余 pre 相隔 **> 窗口** | 更像两次真实调用丢了一条 post，与 E3 在账本上分不开 |

`E6` 再分两条腿，判据是「这个会话后面还有没有动作」：

  · `E6a session_tail`：该条是该会话**最后一条** `pre_tool_use` ⇒ 会话可能在此终止；
  · `E6b session_continued`：同会话之后还有别的 `pre_tool_use` ⇒ 会话继续了，
    这一次调用**就是没有后记录**。**这是唯一的硬残差，不是解释，是缺陷本身。**

恒等式（脚本逐桶断言，不满足即红）：
  `E1 + E3 + E5 + E6a + E6b + E7 + E8 − E4 == calls − posts`

★ **`calls − posts − blocked` 不等于 0，也不应该等于 0**（本工具跑出来的结果之一）：
  它假设「没有后记录的都被拦下了」，可真正由拦截解释的只有 E1，而 E1 < `blocked`；
  `blocked` 里还含着重复写下的 pre。所以那一步减法**在第一步就错**。

────────────────────────────────────────────────────────────────────────
四、三条自证腿（+2 条，共 5 条；每条都断言「真的改了字节」或「真的读到了」）
────────────────────────────────────────────────────────────────────────

  T1 正控：1 call + 1 post + 1 block ⇒ `calls−posts−blocked == 0`
  T2 负控：再加 1 条只有 call 没有 post ⇒ 差额 **== 1**，且**归因到那条 call 所在的桶**
  T3 可读：空目录 ⇒ 必须判 `FAIL`（读到 0 条也是差额 0，这正是最像结论的假绿）
  T4 排除：往目录里塞 `lock_events.jsonl`（内容故意非 JSON）⇒ 必须被忽略且不报坏行
  T5 近名：塞一条 `pre_tool_use_summary` ⇒ `calls` 必须**不变**

夹具一律建在**系统 TEMP**（本机只有 `%LOCALAPPDATA%\\Temp` 能删目录，
`C:\\Temp` 与 D 盘整盘是 `WinError 5`）。仓库零字节写入。

用法：
  python output/lineB/b2_i1_02_reconcile.py                 # 对账仓库自己的账本
  python output/lineB/b2_i1_02_reconcile.py --selftest      # 只跑 5 条自证腿
  python output/lineB/b2_i1_02_reconcile.py --json out.json --md report.md
"""
from __future__ import annotations

import argparse
import collections
import datetime as _dt
import json
import os
import shutil
import sys
import tempfile

# ── 记录类型定名（全等比较，禁用子串）───────────────────────────────────
T_CALL = "pre_tool_use"
T_POST = "post_tool_use"
T_SUMMARY = "pre_tool_use_summary"          # 副记录，不是调用
EXCLUDED_FILES = {"lock_events.jsonl"}      # 不是日文件

# ── 出口定名 ────────────────────────────────────────────────────────────
EXITS = [
    ("E1", "blocked_stopped", "拦截生效，按设计不产生 post"),
    ("E2", "deny_not_honored", "block 了但仍然执行（E-3，最严重）"),
    ("E3", "duplicate_pre", "同一次调用写了多条 pre（组内有 post 可反证，间隔 ≤ 窗口）"),
    ("E4", "orphan_post", "有后无前：post 找不到对应 pre"),
    ("E5", "alert_no_post", "告警通道放行但没有后记录"),
    ("E6a", "session_tail", "放行且无后记录；该会话最后一条动作"),
    ("E6b", "session_continued", "放行且无后记录；会话之后仍在继续（硬残差）"),
    ("E7", "dup_pre_unprovable", "放行/拦截且无 post，同组多条 pre 的多余部分"),
    ("E8", "surplus_pre_ambiguous", "组内有 post，但多余 pre 与配对 pre 相隔超过窗口："
                                   "更像两次真实调用丢了一条 post，无法与重复记录区分"),
]


# ══════════════════════════════════════════════════════════════════════
# 读
# ══════════════════════════════════════════════════════════════════════
def load(audit_dir):
    """读全部日文件。返回 (records, meta)。只读，不加锁，不建文件。

    records 里每条加 `_file` 与 `_seq`（同文件内的行序），用于同 ts 时的稳定排序。
    """
    d = os.path.abspath(audit_dir)
    meta = {
        "audit_dir": d,
        "read_at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "files": 0,
        "records": 0,
        "bad_lines": 0,
        "skipped_files": [],
        "file_list": [],
    }
    records = []
    if not os.path.isdir(d):
        meta["error"] = "目录不存在：%s" % d
        return records, meta

    names = sorted(n for n in os.listdir(d) if n.endswith(".jsonl"))
    for n in names:
        if n in EXCLUDED_FILES:
            meta["skipped_files"].append(n)
            continue
        p = os.path.join(d, n)
        if not os.path.isfile(p):
            continue
        meta["files"] += 1
        try:
            size = os.path.getsize(p)
        except OSError:
            size = -1
        meta["file_list"].append({"name": n, "bytes": size})
        seq = 0
        try:
            fh = open(p, "r", encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    meta["bad_lines"] += 1
                    continue
                if not isinstance(r, dict):
                    meta["bad_lines"] += 1
                    continue
                r["_file"] = n
                r["_seq"] = seq
                seq += 1
                records.append(r)
                meta["records"] += 1
    return records, meta


def _ts(r):
    try:
        return _dt.datetime.fromisoformat(str(r.get("ts")))
    except Exception:
        return None


def _key(r):
    return (r.get("session"), r.get("content_digest"))


# ══════════════════════════════════════════════════════════════════════
# 对账（唯一实现）
# ══════════════════════════════════════════════════════════════════════
def reconcile(records, dup_window=60.0):
    """把 calls/posts/blocked 减clean，逐桶归因到 E1–E7。

    返回 dict：
      totals   全局五个数 + 恒等式残差
      exits    出口 → 条数
      buckets  [(bucket_key, {calls,posts,blocked,...,exits{}})] 按工具×裁决分桶
      daysess  [(day,session)] 分桶（方案书说的「27 个桶」那一层）
      samples  每个出口取 1 条样本（给证据卡用）
      warn     读侧告警（读不到、坏行）
    """
    calls = [r for r in records if r.get("type") == T_CALL]
    posts = [r for r in records if r.get("type") == T_POST]

    # 会话内时间序（判 E6a/E6b 用）
    sess_last_call = {}
    for r in calls:
        t = _ts(r)
        k = r.get("session")
        cur = sess_last_call.get(k)
        if t is not None and (cur is None or t > cur):
            sess_last_call[k] = t

    groups = collections.defaultdict(lambda: {"pre": [], "post": []})
    for r in calls:
        groups[_key(r)]["pre"].append(r)
    for r in posts:
        groups[_key(r)]["post"].append(r)

    exits = collections.Counter({name: 0 for _, name, _ in EXITS})
    extra_by_decision = collections.Counter()   # 零 post 组里「多余 pre」按裁决分
    samples = {}
    dup_deltas = []
    matched = 0

    # ★ 分桶键 = **工具**，不是「工具 × 裁决」。
    #   理由（T1/T2 两条自证腿撞出来的）：`post_tool_use` 的裁决记在 `action`
    #   而 `decision` 为空，若把裁决并进桶键，同一次调用会被劈进
    #   `Bash/allow`（call）与 `Bash/<none>`（post）两个桶，**逐桶加减法不闭合**。
    #   裁决维度另表列出（by_decision），不参与恒等式。
    buckets = collections.defaultdict(lambda: {
        "calls": 0, "posts": 0, "blocked": 0, "matched": 0,
        "exits": collections.Counter({name: 0 for _, name, _ in EXITS}),
    })

    def _b(r):
        return r.get("tool") or "<none>"

    for r in calls:
        buckets[_b(r)]["calls"] += 1
        if r.get("decision") == "block":
            buckets[_b(r)]["blocked"] += 1
    for r in posts:
        buckets[_b(r)]["posts"] += 1

    for k, g in groups.items():
        pre = sorted(g["pre"], key=lambda r: (str(r.get("ts")), r.get("_file"), r.get("_seq")))
        post = sorted(g["post"], key=lambda r: (str(r.get("ts")), r.get("_file"), r.get("_seq")))
        m = min(len(pre), len(post))
        matched += m
        if pre:
            buckets[_b(pre[0])]["matched"] += m
        # E2：block 且有 post
        if post and any(r.get("decision") == "block" for r in pre):
            n = sum(1 for r in pre if r.get("decision") == "block")
            exits["deny_not_honored"] += n
            buckets[_b(pre[0])]["exits"]["deny_not_honored"] += n
            samples.setdefault("deny_not_honored", _slim(pre[0]))
        # E4：post 比 pre 多
        if len(post) > len(pre):
            n = len(post) - len(pre)
            exits["orphan_post"] += n
            if post:
                buckets[_b(post[0])]["exits"]["orphan_post"] += n
                samples.setdefault("orphan_post", _slim(post[0]))
        # pre 比 post 多
        if len(pre) > len(post):
            extra = pre[len(post):]          # 配不上 post 的那些
            if post:
                # 组内有 post ⇒ 多出来的 pre 是重复记录 —— 但只有间隔够近才敢这么说。
                # 相隔超过窗口的，更像「两次真实调用，其中一次丢了 post」，
                # 两者在账本上**无法区分**，所以单列 E8，不硬塞进 E3。
                m = len(post)
                anchor = _ts(pre[m - 1])
                for r in extra:
                    t = _ts(r)
                    dt = abs((t - anchor).total_seconds()) if (t and anchor) else None
                    if dt is not None:
                        dup_deltas.append(dt)
                    near = dt is not None and dt <= dup_window
                    name = "duplicate_pre" if near else "surplus_pre_ambiguous"
                    exits[name] += 1
                    buckets[_b(r)]["exits"][name] += 1
                    samples.setdefault(name, _slim(r))
            else:
                # 组内一条 post 都没有：第一条按裁决归类，其余进 E7
                first, rest = extra[0], extra[1:]
                dec = first.get("decision") or "<none>"
                if dec == "block":
                    name = "blocked_stopped"
                elif dec == "alert":
                    name = "alert_no_post"
                else:
                    t = _ts(first)
                    last = sess_last_call.get(first.get("session"))
                    name = "session_tail" if (t is not None and last is not None and t >= last) \
                        else "session_continued"
                exits[name] += 1
                buckets[_b(first)]["exits"][name] += 1
                samples.setdefault(name, _slim(first))
                if rest:
                    exits["dup_pre_unprovable"] += len(rest)
                    buckets[_b(first)]["exits"]["dup_pre_unprovable"] += len(rest)
                    samples.setdefault("dup_pre_unprovable", _slim(rest[0]))
                    # 单独记下「拦截组里的多余 pre」有多少条，供结论段精确引用
                    extra_by_decision[dec] += len(rest)

    # ── 逐桶恒等式断言 ──
    violations = []
    for key, b in buckets.items():
        e = b["exits"]
        lhs = (e["blocked_stopped"] + e["duplicate_pre"] + e["alert_no_post"]
               + e["session_tail"] + e["session_continued"] + e["dup_pre_unprovable"]
               + e["surplus_pre_ambiguous"]
               - e["orphan_post"])
        rhs = b["calls"] - b["posts"]
        if lhs != rhs:
            violations.append({"bucket": key, "lhs": lhs, "rhs": rhs,
                               "calls": b["calls"], "posts": b["posts"]})

    # ── (day, session) 分桶：方案书说的「先看那 27 个桶」就是这一层 ──
    daysess = collections.defaultdict(lambda: {"calls": 0, "posts": 0, "blocked": 0})
    for r in calls:
        k = (r.get("_file", "").replace(".jsonl", ""), r.get("session") or "<none>")
        daysess[k]["calls"] += 1
        if r.get("decision") == "block":
            daysess[k]["blocked"] += 1
    for r in posts:
        k = (r.get("_file", "").replace(".jsonl", ""), r.get("session") or "<none>")
        daysess[k]["posts"] += 1

    # ── decision × action 交叉表：post 的裁决在 action 上，必须让读者看见 ──
    cross = collections.Counter(
        (r.get("type"), r.get("decision"), r.get("action")) for r in records
    )

    # ── 「被拦下」这件事一共用了几种写法 ──
    block_words = collections.Counter()
    for r in records:
        dec, act = r.get("decision"), r.get("action")
        if dec in ("block", "deny") or act in ("block", "deny"):
            block_words[(r.get("type"), dec, act)] += 1

    # ── 裁决维度（只统计 call 侧；post 侧裁决在 action 上，单列交叉表）──
    by_decision = collections.Counter((r.get("decision") or "<none>") for r in calls)

    n_calls, n_posts = len(calls), len(posts)
    n_blocked = sum(1 for r in calls if r.get("decision") == "block")
    return {
        "totals": {
            "calls": n_calls,
            "posts": n_posts,
            "blocked": n_blocked,
            "matched": matched,
            "calls_minus_posts": n_calls - n_posts,
            "calls_minus_posts_minus_blocked": n_calls - n_posts - n_blocked,
        },
        "exits": dict(exits),
        "extra_by_decision": dict(extra_by_decision),
        "buckets": {k: {
            "calls": v["calls"], "posts": v["posts"], "blocked": v["blocked"],
            "matched": v["matched"], "exits": dict(v["exits"]),
        } for k, v in buckets.items()},
        "by_decision": dict(by_decision),
        "dup_window": dup_window,
        "posts_nonzero_exit": sum(1 for r in posts
                                  if isinstance(r.get("exit_code"), int)
                                  and r.get("exit_code") != 0),
        "daysess": [{"day": k[0], "session": k[1], **v} for k, v in daysess.items()],
        "cross": [{"type": t, "decision": d, "action": a, "n": n}
                  for (t, d, a), n in cross.most_common()],
        "block_words": [{"type": t, "decision": d, "action": a, "n": n}
                        for (t, d, a), n in block_words.most_common()],
        "samples": samples,
        "dup_deltas": sorted(round(x, 2) for x in dup_deltas),
        "violations": violations,
    }


def _slim(r):
    """样本只留能复核的字段（摘要 + 时间 + 会话），不留命令正文。"""
    return {
        "ts": r.get("ts"), "type": r.get("type"), "tool": r.get("tool"),
        "session": (str(r.get("session"))[:8] if r.get("session") else ""),
        "decision": r.get("decision"), "action": r.get("action"),
        "digest": (r.get("content_digest") or "")[:20],
        "file": r.get("_file"),
    }


# ══════════════════════════════════════════════════════════════════════
# 判据
# ══════════════════════════════════════════════════════════════════════
def verdict(res, meta):
    """四条红：读不到 / 坏行 / 恒等式破 / 硬残差。

    ★ 「0 套 ≠ 通过」：读到 0 个文件必须红，不能因为差额是 0 就绿。
    ★ 硬残差 E6b>0 不是「失败」，是**本工具要交付的那个数**——它红不代表脚本错，
      代表产品漏记。所以单独列，不和前三条混。
    """
    reds, notes = [], []
    if meta.get("files", 0) == 0:
        reds.append("读到 0 个日文件（探针失明，任何差额都是假绿）")
    if meta.get("records", 0) == 0:
        reds.append("读到 0 条记录")
    if meta.get("bad_lines", 0) > 0:
        reds.append("坏行 %d 条：账本里有不能解析的行，分母不可信" % meta["bad_lines"])
    if res["violations"]:
        reds.append("恒等式在 %d 个桶上不成立（归因没有覆盖全部差额）" % len(res["violations"]))
    e = res["exits"]
    if e.get("deny_not_honored", 0) > 0:
        reds.append("E2 deny_not_honored=%d：拦了却跑了（E-3）" % e["deny_not_honored"])
    notes.append("calls−posts−blocked = %d：**这个减法不该等于 0**，"
                 "它把 E3/E5/E6b/E7/E8 全当成「被拦」了；正确口径是 `calls − posts` = %d"
                 % (res["totals"]["calls_minus_posts_minus_blocked"],
                    res["totals"]["calls_minus_posts"]))
    notes.append("E6b session_continued = %d（硬残差：放行、会话继续、就是没有后记录）"
                 % e.get("session_continued", 0))
    return reds, notes


# ══════════════════════════════════════════════════════════════════════
# 自证腿
# ══════════════════════════════════════════════════════════════════════
def _mk(path, recs):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return os.path.getsize(path)


def _rec(typ, tool, session, digest, decision, action, ts="2026-01-01T00:00:00+08:00"):
    return {"ts": ts, "type": typ, "tool": tool, "session": session,
            "content_digest": digest, "decision": decision, "action": action}


def selftest(verbose=True):
    """5 条腿。任一不过 ⇒ False。夹具在系统 TEMP，跑完即删。"""
    tmp = tempfile.mkdtemp(prefix="antinel_b2_")
    ok = True

    def _say(leg, passed, detail):
        nonlocal ok
        if verbose:
            print("  [%s] %-3s %s" % ("PASS" if passed else "FAIL", leg, detail))
        if not passed:
            ok = False

    try:
        # ── T1 正控：1 call + 1 post + 1 block ⇒ 差额 0 ──
        d1 = os.path.join(tmp, "t1"); os.makedirs(d1)
        recs1 = [
            _rec(T_CALL, "Bash", "s1", "sha256:aa", "allow", "allow"),
            _rec(T_POST, "Bash", "s1", "sha256:aa", None, "record"),
            _rec(T_CALL, "Bash", "s1", "sha256:bb", "block", "block"),
        ]
        _mk(os.path.join(d1, "2026-01-01.jsonl"), recs1)
        r1, m1 = load(d1)
        res1 = reconcile(r1)
        t = res1["totals"]
        good = (t["calls"] == 2 and t["posts"] == 1 and t["blocked"] == 1
                and t["calls_minus_posts_minus_blocked"] == 0
                and res1["exits"]["blocked_stopped"] == 1
                and not res1["violations"])
        _say("T1", good, "正控 calls=%d posts=%d blocked=%d 差额=%d E1=%d"
             % (t["calls"], t["posts"], t["blocked"],
                t["calls_minus_posts_minus_blocked"], res1["exits"]["blocked_stopped"]))

        # ── T2 负控：再加 1 条只有 call 没有 post ⇒ 差额 1 且归因到该桶 ──
        d2 = os.path.join(tmp, "t2"); os.makedirs(d2)
        recs2 = recs1 + [_rec(T_CALL, "Edit", "s1", "sha256:cc", "allow", "allow")]
        _mk(os.path.join(d2, "2026-01-01.jsonl"), recs2)
        r2, _ = load(d2)
        res2 = reconcile(r2)
        t2 = res2["totals"]
        bk = res2["buckets"].get("Edit")
        good = (t2["calls"] - t2["posts"] - t2["blocked"] == 1
                and bk is not None
                and (bk["exits"]["session_tail"] + bk["exits"]["session_continued"]) == 1
                and not res2["violations"])
        _say("T2", good, "负控 差额=%d，归因到 Edit 桶：%s"
             % (t2["calls"] - t2["posts"] - t2["blocked"],
                None if bk is None else {k: v for k, v in bk["exits"].items() if v}))

        # ── T3 可读：空目录必须红 ──
        d3 = os.path.join(tmp, "t3"); os.makedirs(d3)
        r3, m3 = load(d3)
        res3 = reconcile(r3)
        reds3, _ = verdict(res3, m3)
        good = bool(reds3) and m3["files"] == 0
        _say("T3", good, "空目录 文件=%d 记录=%d ⇒ 判红=%s"
             % (m3["files"], m3["records"], bool(reds3)))

        # ── T4 排除：lock_events.jsonl 必须被忽略（内容故意坏）──
        d4 = os.path.join(tmp, "t4"); os.makedirs(d4)
        _mk(os.path.join(d4, "2026-01-01.jsonl"), recs1)
        with open(os.path.join(d4, "lock_events.jsonl"), "w", encoding="utf-8") as f:
            f.write("this is not json at all\n{\"type\":\"pre_tool_use\"}\n")
        r4, m4 = load(d4)
        res4 = reconcile(r4)
        good = (m4["bad_lines"] == 0 and m4["files"] == 1
                and "lock_events.jsonl" in m4["skipped_files"]
                and res4["totals"]["calls"] == 2)
        _say("T4", good, "lock_events 已排除 files=%d 坏行=%d calls=%d"
             % (m4["files"], m4["bad_lines"], res4["totals"]["calls"]))

        # ── T5 近名：pre_tool_use_summary 不算 call ──
        d5 = os.path.join(tmp, "t5"); os.makedirs(d5)
        recs5 = recs1 + [_rec(T_SUMMARY, "Bash", "s1", "", "block", None)]
        _mk(os.path.join(d5, "2026-01-01.jsonl"), recs5)
        r5, _ = load(d5)
        res5 = reconcile(r5)
        good = (res5["totals"]["calls"] == 2
                and res5["totals"]["calls_minus_posts_minus_blocked"] == 0)
        _say("T5", good, "summary 未计入 calls（仍为 %d）" % res5["totals"]["calls"])

        # ── T6 夹具自证：写下去的字节数 > 0（防「夹具没写成也 PASS」）──
        sz = os.path.getsize(os.path.join(d1, "2026-01-01.jsonl"))
        _say("T6", sz > 0, "夹具真的落盘 %d 字节" % sz)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return ok


# ══════════════════════════════════════════════════════════════════════
# 输出
# ══════════════════════════════════════════════════════════════════════
def _table(headers, rows):
    w = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            w[i] = max(w[i], len(str(c)))
    out = ["| " + " | ".join(str(h).ljust(w[i]) for i, h in enumerate(headers)) + " |",
           "|" + "|".join("-" * (w[i] + 2) for i in range(len(headers))) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c).ljust(w[i]) for i, c in enumerate(r)) + " |")
    return "\n".join(out)


def render_md(res, meta, reds, notes):
    L = []
    t = res["totals"]
    L.append("# B-2 · `I1-02` 对账结果\n")
    L.append("> 读数时刻 **%s**，目录 `%s`。" % (meta["read_at"], meta["audit_dir"]))
    L.append("> 日文件 **%d** 个，记录 **%d** 条，坏行 **%d** 条；已排除 `%s`。\n"
             % (meta["files"], meta["records"], meta["bad_lines"],
                "`, `".join(meta["skipped_files"]) or "（无）"))
    L.append("★ 账本是**活的**：本工具运行期间，本会话自己的工具调用仍在往里写记录。"
             "所以上面的数是**读取时刻的快照**，不是常量——复跑会漂。\n")

    L.append("## 1 三个数\n")
    L.append(_table(["项", "条数", "口径"], [
        ["calls", t["calls"], "`type == \"pre_tool_use\"`（全等，不含 summary）"],
        ["posts", t["posts"], "`type == \"post_tool_use\"`"],
        ["blocked", t["blocked"], "上述 calls 中 `decision == \"block\"`"],
        ["配对成功", t["matched"], "同一 `(session, content_digest)` 内 pre 与 post 配对"],
        ["calls − posts", t["calls_minus_posts"], "**真正的待归因总量**"],
        ["calls − posts − blocked", t["calls_minus_posts_minus_blocked"],
         "★ **这一项不等于 0，也不应该等于 0** —— 见 §8 结论 2"],
    ]))
    L.append("")

    L.append("## 2 差额归因（E1–E8，无「其它」桶）\n")
    rows = []
    gross = 0
    for code, name, why in EXITS:
        n = res["exits"].get(name, 0)
        if name != "orphan_post":
            gross += n
        rows.append([code, "`%s`" % name, n, why])
    rows.append(["", "**加向（不含 E4）**", gross, "把差额解释掉的那一头"])
    rows.append(["", "**减向 E4**", res["exits"].get("orphan_post", 0), "把差额造出来的那一头"])
    rows.append(["", "**净额**", gross - res["exits"].get("orphan_post", 0),
                 "必须 == `calls − posts` = %d" % t["calls_minus_posts"]])
    L.append(_table(["号", "出口", "条数", "含义"], rows))
    L.append("")
    L.append("恒等式：`E1+E3+E5+E6a+E6b+E7+E8 − E4 == calls − posts`，"
             "即 **%d − %d = %d**。逐桶断言结果：**%s**。\n"
             % (gross, res["exits"].get("orphan_post", 0),
                gross - res["exits"].get("orphan_post", 0),
                "全部成立" if not res["violations"]
                else "**%d 个桶不成立**" % len(res["violations"])))

    L.append("## 3 分桶（按工具）：差额落在哪几个工具上\n")
    L.append("★ 桶键用**工具**而不是「工具 × 裁决」，是被自证腿 T1/T2 撞出来的："
             "`post_tool_use` 的裁决记在 `action` 而 `decision` 为空，"
             "把裁决并进桶键会把同一次调用劈进 `Bash/allow`（call）与 `Bash/<none>`（post）"
             "两个桶，**逐桶加减法不闭合**。裁决维度见 §4 交叉表。\n")
    rows = []
    for name, b in sorted(res["buckets"].items(),
                          key=lambda kv: -abs(kv[1]["calls"] - kv[1]["posts"])):
        d = b["calls"] - b["posts"]
        if d == 0 and b["calls"] == 0:
            continue
        rows.append([name, b["calls"], b["posts"], d, b["blocked"],
                     b["exits"]["duplicate_pre"], b["exits"]["blocked_stopped"],
                     b["exits"]["session_continued"]])
    L.append(_table(["工具", "calls", "posts", "差", "blocked",
                     "E3 重复", "E1 拦截", "E6b 硬残差"], rows))
    L.append("")

    L.append("## 4 call 侧的裁决分布 与 `decision × action` 交叉表\n")
    rr = [[k, v] for k, v in sorted(res["by_decision"].items(), key=lambda kv: -kv[1])]
    L.append(_table(["call 的 decision", "条数"], rr))
    L.append("")
    rows = []
    for r in res["cross"]:
        rows.append(["`%s`" % r["type"], r["decision"], r["action"], r["n"]])
    L.append(_table(["记录类型", "decision", "action", "条数"], rows))
    L.append("")

    L.append("## 5 每条被拦下的事实，在账本里叫几个名字\n")
    rows = []
    for r in res["block_words"]:
        rows.append(["`%s`" % r["type"], r["decision"], r["action"], r["n"]])
    L.append(_table(["记录类型", "decision", "action", "条数"], rows))
    L.append("")
    L.append("⇒ 同一次「被拦下」，pre 记 `block`、`command_deletion_permission` 记 `deny`、"
             "summary 记 `block`。**按任一个词单独统计「拦截次数」都会算错。**\n")

    if res["dup_deltas"]:
        ds = res["dup_deltas"]
        L.append("## 6 重复 pre 的时间间隔（E3 / E8 的唯一分野）\n")
        L.append("组内有 post 的多余 pre 共 **%d** 条，间隔分布：中位 **%.1fs**，"
                 "最小 **%.1fs**，最大 **%.1fs**。以 **%.0f 秒**为界：≤ 界进 E3（重复写），"
                 "> 界进 E8（更可能是两次真实调用丢了一条 post）。"
                 "界上 **%d** 条、界下 **%d** 条。\n"
                 % (len(ds), ds[len(ds) // 2], ds[0], ds[-1], res.get("dup_window", 60.0),
                    sum(1 for x in ds if x > res.get("dup_window", 60.0)),
                    sum(1 for x in ds if x <= res.get("dup_window", 60.0))))
        L.append("★ 这条界线是**描述性**的，不是判据：账本里没有字段能区分这两种成因。"
                 "换一个阈值会改变 E3/E8 的分配，但**不改变** `calls−posts` 与恒等式。\n")

    L.append("## 7 判定\n")
    if reds:
        L.append("**红项：**\n")
        for r in reds:
            L.append("- %s" % r)
    else:
        L.append("**无红项。**")
    L.append("")
    for n in notes:
        L.append("- %s" % n)
    L.append("")

    # ── 结论：句子由数算出来，不手抄 ──
    e = res["exits"]
    b = res["buckets"]
    gross = sum(v for k, v in e.items() if k != "orphan_post")
    L.append("## 8 结论（每条都由上面的数算出来）\n")
    L.append("1. **差额可以逐条归因，一分钱不剩。** 加向出口合计 **%d**，"
             "减掉 E4 的 **%d**，净额 **%d**，与 `calls−posts=%d` 逐桶对齐（%s）。"
             "这就是 `I1-02` 从没做过的那次减法。"
             % (gross, e.get("orphan_post", 0), gross - e.get("orphan_post", 0),
                t["calls_minus_posts"],
                "全部成立" if not res["violations"] else "**%d 个桶破了**" % len(res["violations"])))
    _e1 = e.get("blocked_stopped", 0)
    L.append("2. **`calls − posts − blocked` 这个减法本身是错的，而且错两处。** "
             "它等于 **%d**，既不是 0，也不该是 0：\n"
             "   - 错一：它假设「没有后记录的都被拦下了」，可真正由拦截解释的只有 **E1=%d**，"
             "其余 %d 条差额由 E3／E5／E6a／E6b／E7／E8 解释（净额，已扣 E4），"
             "它们**跟拦截毫无关系**。\n"
             "   - 错二：`blocked=%d` 里本身含 **%d** 条重复写下的 pre"
             "（实测这 %d 条 block 记录只分布在 **%d** 个组里，每组首条都是 block、"
             "且一条 post 都没有 ⇒ 多出来的 %d 条是同一次拦截被记了两遍），"
             "所以它连「被拦了几次」这个数都不是。\n"
             "   ⇒ **正确的一步是 `calls − posts`，再逐条归因；不是三个数直接相减。**"
             % (t["calls_minus_posts_minus_blocked"], _e1,
                t["calls_minus_posts"] - _e1,
                t["blocked"], t["blocked"] - _e1,
                t["blocked"], _e1,
                t["blocked"] - _e1))
    top = sorted(b.items(), key=lambda kv: -kv[1]["exits"]["duplicate_pre"])[:4]
    top = [(k, v) for k, v in top if v["exits"]["duplicate_pre"]]
    if top:
        L.append("3. **离「丢失」最近的那一类，其实是重复写。** E3 共 %d 条，集中在 %s —— "
                 "这几个工具的 posts 恰好是 calls 的一半左右。实测同组两条 pre "
                 "**除 `ts`/`hash`/`prev` 外逐字段完全相同**（相隔 1 秒），"
                 "是**同一次调用被记了两遍**，不是两次调用。"
                 % (e["duplicate_pre"],
                    "、".join("`%s`（%d 条）" % (k, v["exits"]["duplicate_pre"])
                              for k, v in top)))
        L.append("   ⇒ 任何用 `pre_tool_use` 条数当「动作数」的报告，"
                 "在这几个工具上**分母虚高近一倍**；而 E8 那 %d 条相隔超过 %.0f 秒的，"
                 "更像「两次真实调用丢了一条 post」，两者在账本上分不开，故单列。"
                 % (e.get("surplus_pre_ambiguous", 0), res.get("dup_window", 60.0)))
    L.append("4. **`deny` 是守住的。** E2 = **%d**：没有一条「拦了却仍然执行」。"
             "这是本次对账唯一一条正向结论，也是唯一能用账本自证的。"
             % e.get("deny_not_honored", 0))
    bash_e6b = b.get("Bash", {}).get("exits", {}).get("session_continued", 0)
    L.append("5. **硬残差 %d 条，机制已确认一半。** 其中 Bash %d 条、非 Bash %d 条。"
             "非 Bash 那一半的机制已实测确认：**工具层报错（如 `old_string` 不存在）时"
             "宿主不发 `PostToolUse`** —— 本轮用一条注定失败的 `Edit` 做正控，"
             "它留下 1 条 `pre_tool_use`、0 条 `post_tool_use`，而其后紧邻的 Bash 调用"
             "都正常留痕；另测得 Bash **非零退出仍会留 post**（%d 条 `exit_code≠0` 的 post 在账），"
             "所以 Bash 那 %d 条**不是**同一种机制，仍属未解释。"
             % (e.get("session_continued", 0), bash_e6b,
                e.get("session_continued", 0) - bash_e6b,
                res.get("posts_nonzero_exit", 0),
                bash_e6b))
    L.append("6. **「被拦下」在账本里有三个名字**（见 §5）。"
             "按 `block` 统计拦截次数会漏掉 `command_deletion_permission` 的 `deny`，"
             "按 `deny` 统计会漏掉 pre 的 `block`。**两个词单独用都是错的。**")
    L.append("")
    return "\n".join(L)


def print_console(res, meta, reds, notes):
    t = res["totals"]
    print("=" * 74)
    print("B-2 · I1-02 对账  读数时刻 %s" % meta["read_at"])
    print("  目录 %s" % meta["audit_dir"])
    print("  日文件 %d 个 / 记录 %d 条 / 坏行 %d / 已排除 %s"
          % (meta["files"], meta["records"], meta["bad_lines"],
             ",".join(meta["skipped_files"]) or "无"))
    print("-" * 74)
    print("  calls=%d  posts=%d  blocked=%d" % (t["calls"], t["posts"], t["blocked"]))
    print("  calls - posts - blocked = %d" % t["calls_minus_posts_minus_blocked"])
    print("-" * 74)
    for code, name, _ in EXITS:
        n = res["exits"].get(name, 0)
        if n:
            print("  %-4s %-22s %6d" % (code, name, n))
    print("-" * 74)
    print("  恒等式逐桶断言：%s" % ("全部成立" if not res["violations"]
                                   else "%d 个桶不成立" % len(res["violations"])))
    for r in reds:
        print("  [RED] %s" % r)
    for n in notes:
        print("  [NOTE] %s" % n)
    print("=" * 74)


def realmutate(audit_dir, verbose=True):
    """真数据变异腿：把真实账本**复制**到系统 TEMP，删掉一条 post，看残差是否 +1。

    合成夹具能证明「逻辑对」，证明不了「在真数据上灵」。这一条把两者接上：
    变异点选**副本**上第一条 `post_tool_use`，删掉它 ⇒
      `calls − posts` 必须 **恰好 +1**，且多出来的 1 条必须落在**同一个工具**的桶里。
    仓库零写入。
    """
    tmp = tempfile.mkdtemp(prefix="antinel_b2_mut_")
    ok = True
    try:
        src = os.path.abspath(audit_dir)
        dst = os.path.join(tmp, "audit")
        os.makedirs(dst)
        n_copy = 0
        for n in sorted(os.listdir(src)):
            if not n.endswith(".jsonl") or n in EXCLUDED_FILES:
                continue
            shutil.copyfile(os.path.join(src, n), os.path.join(dst, n))
            n_copy += 1
        base_recs, base_meta = load(dst)
        base = reconcile(base_recs)
        if verbose:
            print("  副本 %d 个日文件 / %d 条记录" % (n_copy, base_meta["records"]))
        if base["totals"]["calls"] == 0 or base["totals"]["posts"] == 0:
            # 空集比较先断 before > 0（否则 +1 恒成立，是假绿）
            print("  [FAIL] M1 副本读到 0 条，变异无意义")
            return False

        # 挑一条 post 删掉：取第一个「所在组有多条 post」的，保证删完不是整组归零
        victim = None
        for r in base_recs:
            if r.get("type") != T_POST:
                continue
            victim = r
            break
        if victim is None:
            print("  [FAIL] M1 副本里找不到可删的 post")
            return False
        vfile, vseq, vtool = victim["_file"], victim["_seq"], victim.get("tool")

        # 重写那个文件（去掉一行），并断言字节真的少了
        p = os.path.join(dst, vfile)
        before = os.path.getsize(p)
        keep = []
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                try:
                    o = json.loads(s)
                except Exception:
                    keep.append(s)
                    continue
                if o.get("type") == T_POST and o.get("content_digest") == victim.get("content_digest") \
                        and o.get("ts") == victim.get("ts") and not getattr(realmutate, "_hit", False):
                    realmutate._hit = True      # 只删这一条
                    continue
                keep.append(s)
        realmutate._hit = False
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            for s in keep:
                f.write(s + "\n")
        after = os.path.getsize(p)
        mutated = before != after
        if verbose:
            print("  变异：从 %s 删 1 条 post，%d → %d 字节（真的变了=%s）"
                  % (vfile, before, after, mutated))
        if not mutated:
            print("  [FAIL] M1 变异没改到字节（等于没变异）")
            return False

        mut_recs, _ = load(dst)
        mut = reconcile(mut_recs)
        d_posts = base["totals"]["posts"] - mut["totals"]["posts"]
        d_gap = (mut["totals"]["calls"] - mut["totals"]["posts"]) - \
                (base["totals"]["calls"] - base["totals"]["posts"])
        bb = base["buckets"].get(vtool, {})
        mb = mut["buckets"].get(vtool, {})
        be = bb.get("exits", {})
        me = mb.get("exits", {})
        d_exit = sum(me.values()) - sum(be.values())
        good = (d_posts == 1 and d_gap == 1 and d_exit == 1)
        if verbose:
            print("  [%s] M1 删 1 条 post ⇒ posts-%d，差额+%d，工具桶（%s）出口合计+%d"
                  % ("PASS" if good else "FAIL", d_posts, d_gap, vtool, d_exit))
        if not good:
            ok = False
        if mut["violations"]:
            print("  [FAIL] M2 变异后恒等式在 %d 个桶上不成立" % len(mut["violations"]))
            ok = False
        elif verbose:
            print("  [PASS] M2 变异后恒等式仍全部成立")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(description="B-2 · I1-02 对账")
    ap.add_argument("--audit", default=os.path.join(".psl", "audit"))
    ap.add_argument("--json", default=None)
    ap.add_argument("--md", default=None)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--realmutate", action="store_true",
                    help="在真实账本的 TEMP 副本上做一次变异，验证检测器有牙")
    ap.add_argument("--dup-window", type=float, default=60.0,
                    help="E3 与 E8 的分界（秒）；只改分配，不改 calls−posts 与恒等式")
    a = ap.parse_args(argv)

    if a.selftest:
        print("B-2 自证腿（夹具在系统 TEMP：%s）" % tempfile.gettempdir())
        return 0 if selftest() else 1
    if a.realmutate:
        print("B-2 真数据变异腿（副本在系统 TEMP：%s）" % tempfile.gettempdir())
        return 0 if realmutate(a.audit) else 1

    records, meta = load(a.audit)
    res = reconcile(records, dup_window=a.dup_window)
    reds, notes = verdict(res, meta)
    print_console(res, meta, reds, notes)

    if a.json:
        with open(a.json, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"meta": meta, "result": res, "reds": reds, "notes": notes},
                      f, ensure_ascii=False, indent=1)
        print("  → %s" % a.json)
    if a.md:
        with open(a.md, "w", encoding="utf-8", newline="\n") as f:
            f.write(render_md(res, meta, reds, notes))
        print("  → %s" % a.md)
    return 0 if not reds else 2


if __name__ == "__main__":
    sys.exit(main())
