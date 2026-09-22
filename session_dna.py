#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel Security Suite v0.27.0 - session DNA (三问三答 v1.0, A5).

One chained record per session that summarizes the session's audit trail:
action counts, blocks by rule, touched files, pre/post duration pairs, and
nonzero exit codes. Consumers:

  report.py --session <id> [--write-dna]   on demand, full audit dir
  hooks/session_start_banner.py             bounded roll-up of the previous
                                            session (newest 2 day files, 64 MB
                                            combined, fail-open)

The DNA is FACTS ONLY -- every field is an aggregation of records already in
the hash chain; nothing is inferred, nothing is scored. The record itself is
appended through the same lock/prev/hash/day-manifest recipe as every other
audit record, so verify_chain covers it like any other link.

stdlib only, no network. Python 3.10+.
"""
import hashlib
import json
import os
import time
from datetime import datetime
from statistics import median

MAX_ROLLUP_BYTES = 64 * 1024 * 1024      # SessionStart roll-up latency guard
DNA_TOP_FILES = 5
_EXCLUDE_SESSIONS = ("banner", "-", "")


def _iter_day_files(audit_dir, max_files=None):
    """Plain *.jsonl day files, oldest first. Archived .gz days are out of
    scope (the DNA covers the live window; coverage.days states it)."""
    try:
        files = [os.path.join(audit_dir, f) for f in os.listdir(audit_dir)
                 if f.endswith(".jsonl") and not f.endswith(".lock")]
    except OSError:
        return []
    files.sort()
    return files[-max_files:] if max_files else files


def _rows(files, max_bytes, stop):
    """Yield (day, record) pairs across the day files (paths, oldest first).
    Sets stop[0]=True and returns when the byte budget is exceeded; unparsable
    lines are skipped (the DNA aggregates what is readable)."""
    seen = 0
    for fp in files:
        day = os.path.basename(fp)
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    seen += len(line)
                    if seen > max_bytes:
                        stop[0] = True
                        return
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield day, json.loads(line)
                    except Exception:
                        continue
        except OSError:
            continue


def _parse_ts(ts):
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _cost_estimate(usage_by_model, pricing):
    """0.23.0 (A3/A4): DERIVED cost -- never a fact, never stored per action.
    Computed only when the caller supplies a pricing table; models without a
    rate are REPORTED, never guessed. `unit` == "per_1m_tokens" (default) or
    "per_token"; currency comes from the table (USD, credits, ...)."""
    if not isinstance(pricing, dict) or not usage_by_model:
        return None
    rates = pricing.get("rates") or {}
    div = 1_000_000.0 if (pricing.get("unit") or "per_1m_tokens") == "per_1m_tokens" else 1.0
    total, by_model, unpriced = 0.0, {}, []
    for m, u in usage_by_model.items():
        r = rates.get(m)
        if not isinstance(r, dict):
            unpriced.append(m)
            continue
        c = ((u.get("input") or 0) * (r.get("input") or 0)
             + (u.get("output") or 0) * (r.get("output") or 0)
             + (u.get("cache_read") or 0) * (r.get("cache_read") or 0)
             + (u.get("cache_creation") or 0) * (r.get("cache_creation") or 0)) / div
        by_model[m] = round(c, 6)
        total += c
    return {"currency": pricing.get("currency") or "USD",
            "total": round(total, 6),
            "by_model": by_model,
            "pricing_version": pricing.get("version"),
            "unpriced_models": sorted(unpriced)}


def compute(audit_dir, session, max_bytes=None, max_files=None,
            generated_by="report.py", pricing=None):
    """Aggregate one session's records into a DNA dict (no chain fields yet).
    Returns None when the session left no readable records."""
    if not session:
        return None
    files = _iter_day_files(audit_dir, max_files)
    if not files:
        return None
    stop = [False]
    max_bytes = float("inf") if max_bytes is None else max_bytes

    days, n_records = [], 0
    first_ts = last_ts = None
    by_tool, by_rule = {}, {}
    actions = warnings = blocks = 0
    nonzero = exits_observed = 0
    file_counts = {}
    pres, posts = [], []
    usage_by_model = {}                      # 0.23.0 (A1/A2): token facts aggregate
    usage_entries = 0

    for _day, rec in _rows(files, max_bytes, stop):
        if rec.get("session") != session:
            continue
        n_records += 1
        day = _day
        if day not in days:
            days.append(day)
        ts = rec.get("ts") or ""
        if ts:
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts
        rtype = rec.get("type")
        if rtype == "pre_tool_use":
            actions += 1
            t = rec.get("tool") or "?"
            by_tool[t] = by_tool.get(t, 0) + 1
            dec = rec.get("decision")
            if dec == "block":
                blocks += 1
                for rid in (rec.get("rules_hit") or []):
                    by_rule[rid] = by_rule.get(rid, 0) + 1
            elif dec == "alert":
                warnings += 1
            fp_ = (rec.get("input") or {}).get("file_path") or ""
            if fp_:
                file_counts[fp_] = file_counts.get(fp_, 0) + 1
            pres.append(rec)
        elif rtype == "post_tool_use":
            fp_ = (rec.get("input") or {}).get("file_path") or ""
            if fp_:
                file_counts[fp_] = file_counts.get(fp_, 0) + 1
            ec = rec.get("exit_code")
            if ec is not None:
                exits_observed += 1
                if ec > 0:
                    nonzero += 1
            posts.append(rec)
        elif rtype == "usage_delta":
            usage_entries += 1
            for e in (rec.get("entries") or []):
                m = e.get("model") or "unknown"
                u = usage_by_model.setdefault(
                    m, {"entries": 0, "input": 0, "output": 0,
                        "cache_read": 0, "cache_creation": 0, "total": 0})
                u["entries"] += 1
                for canon, field in (("input", "input_tokens"),
                                     ("output", "output_tokens"),
                                     ("cache_read", "cache_read_input_tokens"),
                                     ("cache_creation", "cache_creation_input_tokens"),
                                     ("total", "total_tokens")):
                    v = e.get(field)
                    if isinstance(v, int):
                        u[canon] += v

    if n_records == 0:
        return None

    # Duration pairs: earliest unpaired pre with the same content_digest that
    # did not fire after the post (same-call join; retries pair in order).
    pres.sort(key=lambda r: r.get("ts") or "")
    used = [False] * len(pres)
    durs_ms = []
    for post in sorted(posts, key=lambda r: r.get("ts") or ""):
        dg = post.get("content_digest")
        if not dg:
            continue
        pt = _parse_ts(post.get("ts") or "")
        for i, pre in enumerate(pres):
            if used[i] or pre.get("content_digest") != dg:
                continue
            bt = _parse_ts(pre.get("ts") or "")
            if bt and pt and 0 <= (pt - bt).total_seconds() < 3600:
                durs_ms.append((pt - bt).total_seconds() * 1000.0)
                used[i] = True
            break
    durs_ms.sort()
    dur = {"pairs": len(durs_ms),
           "median_ms": round(median(durs_ms), 1) if durs_ms else None,
           "p95_ms": round(durs_ms[min(len(durs_ms) - 1, max(0, int(len(durs_ms) * 0.95) - 1))], 1)
           if durs_ms else None}

    top = sorted(file_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:DNA_TOP_FILES]
    dna = {
        "type": "session_dna",
        "session": session,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "generated_by": generated_by,
        "coverage": {"days": days, "records": n_records, "truncated": bool(stop[0])},
        "span": {"first": first_ts, "last": last_ts},
        "actions": {"total": actions, "by_tool": by_tool},
        "blocks": {"total": blocks, "by_rule": by_rule},
        "warnings": {"total": warnings},
        "files": {"touched_unique": len(file_counts),
                  "top": [{"path": p, "count": c} for p, c in top]},
        "durations": dur,
        "exits": {"observed": exits_observed, "nonzero": nonzero},
    }
    # 0.23.0 (A1-A4): token facts always; cost only as a DERIVED estimate when
    # the caller passed a pricing table. Facts and derivation are kept apart.
    dna["usage"] = {"entries": usage_entries, "by_model": usage_by_model}
    cost = _cost_estimate(usage_by_model, pricing)
    if cost is not None:
        dna["usage"]["cost_estimate"] = cost
    return dna


def find_undone_session(audit_dir, exclude=(), max_files=2):
    """Most recent session in the newest `max_files` day files that (a) is not
    excluded, not a banner/heartbeat pseudo-session, and (b) has no session_dna
    record yet. Returns the session id or None."""
    files = _iter_day_files(audit_dir, max_files)
    last_seen, done = {}, set()
    for _day, rec in _rows(files, float("inf"), [False]):
        sid = rec.get("session")
        if not sid:
            continue
        if rec.get("type") == "session_dna":
            done.add(sid)
            continue
        if sid not in _EXCLUDE_SESSIONS:
            last_seen[sid] = rec.get("ts") or ""
    best = None
    for sid, ts in last_seen.items():
        if sid in done or sid in exclude:
            continue
        if best is None or ts >= best[1]:
            best = (sid, ts)
    return best[0] if best else None


def find_latest_session(audit_dir, exclude=(), max_files=3):
    """Most recent real session id in the newest day files (skips heartbeat
    pseudo-sessions and the CLI's own). For `report --session latest`."""
    files = _iter_day_files(audit_dir, max_files)
    last = None
    for _day, rec in _rows(files, float("inf"), [False]):
        sid = rec.get("session")
        if not sid or sid in _EXCLUDE_SESSIONS or sid in exclude:
            continue
        if rec.get("type") in ("pre_tool_use", "post_tool_use", "usage_delta"):
            last = sid
    return last



def _ac():
    """C-1: audit_chain.py 是锁与链追加的唯一实现（包根）；钩子可能从
    <pkg>/hooks/ 运行，ImportError 时把包根补进 sys.path。"""
    global _AUDIT_CHAIN
    if _AUDIT_CHAIN is None:
        try:
            import audit_chain as _m
        except ImportError:
            parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if parent not in sys.path:
                sys.path.insert(0, parent)
            import audit_chain as _m
        _AUDIT_CHAIN = _m
    return _AUDIT_CHAIN


_AUDIT_CHAIN = None


def append_chained(audit_dir, record):
    """C-1 (v0.28)：经 audit_chain 唯一实现追加。锁预算耗尽按条款 C-3 落
    sidecar——历史 docstring 的「不落盘」从未实现过（2026-09-21 对照发现，
    统一为 sidecar），返回 False 仍表示「未进主链」，调用方告警语义不变。
    返回 True = 已按锁定协议进主链。"""
    try:
        os.makedirs(audit_dir, exist_ok=True)
    except OSError:
        return False
    fn = os.path.join(audit_dir, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
    try:
        _rec, chained = _ac().append_chained(fn, record, on_timeout="sidecar")
        if chained:
            _ac().touch_day_manifest(fn)
        return chained
    except Exception:
        return False
