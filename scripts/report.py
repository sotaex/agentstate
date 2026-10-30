#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""AgentState v0.29.0 - report generator (F-04 behaviour report, F-05 score).

Sources:
  .psl/audit/*.jsonl      hook events written by pre_tool_use.py / post_tool_use.py
  .psl/scan_last.json     latest static scan (optional, merged into the report)
  .psl/manifest.json      rules hash -> SELF-TAMPERED check (spec 2.8)

Formats: text (default, spec 2.6 layout) | json | html (spec C-03: single
file, inline CSS, no JavaScript, colours #dc3545 / #ffc107 / #28a745 / #6c757d)
| csv (US-05, one finding per row) | sarif (US-05, SARIF 2.1.0 for code-scanning UIs).

Period (F-04): --days N keeps the last N calendar days (1 = daily, 7 = weekly);
--since YYYY-MM-DD keeps records on/after that date. Default: all retained logs.

Score (spec 2.6 / C-04): 100 - 20 per CRITICAL - 5 per WARNING, clamped to
0..100. Findings are de-duplicated on (rule_id, target) so a retried action
is counted once. The report always prints the score basis (US-02 v1.1 wording:
"含评分依据与扣分明细").

--archive (spec B-05): gzip audit files older than the retention period into
.psl/audit/archive/YYYY-MM/; retention defaults to 30 days and is read from
.psl/policy.json (global_settings.log_retention_days, spec C-05) or
--retention-days; if the audit directory exceeds 100 MB the oldest files are
compressed regardless of age. Nothing is ever deleted.

SELF-TAMPERED (spec 2.8): the rules file AND the five scripts are hashed at
install time (manifest rules_hash / scripts_hash); any drift is reported.

Exit codes (spec A-10): 0 = report written, 1 = no log data, 2 = error.
Python 3.10+, stdlib only, no network.
"""
import argparse
import csv
import glob
import gzip
import hashlib
import html
import io
import json
import os
import shutil
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent


def _tool_version():
    """产品版本号。唯一真源是发行元数据，源码态退回 pyproject。

    0.55.2：这里原来钉着 "0.33.1" 一个字面量，于是 `antinel -V` 说 0.55.1、
    report --format json 的 tool_version 却说 0.33.1 —— 同一个产品在同一台机器上
    报两个版本。按「同一事实多处实现」处理：改成取发行元数据，不再手写。
    """
    try:
        from importlib.metadata import version
        return version("antinel")
    except Exception:
        pass
    try:
        for line in (PKG_DIR.parent / "pyproject.toml").read_text(
                encoding="utf-8").splitlines():
            if line.startswith("version ="):
                return line.split("=", 1)[1].strip().strip("\"'")
    except Exception:
        pass
    return "unknown"


TOOL_VERSION = _tool_version()
RETENTION_DAYS_DEFAULT = 30
SCRIPT_FILES = ("pre_tool_use.py", "post_tool_use.py", "scan.py", "install.py", "report.py")


def _os_locale():
    """OS locale 名（形如 zh_CN）。自包含：不依赖调用方的模块级 import。

    为什么不直接用 locale.getlocale() 或环境变量（本机实测 2026-10-11）：
      getdefaultlocale()      -> ('zh_CN', 'cp936')                  正确
      getlocale(LC_CTYPE)     -> ('Chinese (Simplified)_China','936') 切不出 zh
      LC_ALL / LANG           -> C.UTF-8 / en_US.UTF-8               会把中文机判成英文
    ⇒ 3.15 之前继续用 getdefaultlocale（压掉警告即可），3.15 之后走 ctypes 查 UI 语言。"""
    import locale as _loc, sys as _sys, os as _os
    _gdl = getattr(_loc, "getdefaultlocale", None)
    if _gdl is not None:
        try:
            import warnings as _w
            with _w.catch_warnings():
                _w.simplefilter("ignore", DeprecationWarning)
                return _gdl()[0] or ""
        except Exception:
            pass
    if _sys.platform == "win32":
        try:
            import ctypes as _ct
            _m = {2052: "zh_CN", 1028: "zh_TW", 1041: "ja_JP", 1042: "ko_KR"}
            return _m.get(_ct.windll.kernel32.GetUserDefaultUILanguage() & 0xFFFF, "en_US")
        except Exception:
            pass
    for _k in ("LC_ALL", "LC_CTYPE", "LANG"):
        _v = _os.environ.get(_k)
        if _v and _v not in ("C", "C.UTF-8", "POSIX"):
            return _v
    return ""


def _locate(*rel):
    """Flat PoC layout or skill package layout (report.py in scripts/, hooks in ../hooks, rules in ../rules)."""
    for base in (PKG_DIR, PKG_DIR.parent):
        for sub in ("", "hooks", "scripts"):
            p = (base / sub).joinpath(*rel) if sub else base.joinpath(*rel)
            if p.exists():
                return p
    return PKG_DIR.joinpath(*rel)
MAX_AUDIT_BYTES = 100 * 1024 * 1024
SEVERITY_WEIGHT = {"critical": 20, "warning": 5, "info": 0}
BAR = "\u2501" * 34
COLORS = {"critical": "#dc3545", "warning": "#ffc107", "ok": "#28a745", "neutral": "#6c757d"}
# ★ 0.55.3（2026-10-23）：原句是「安装 psl-watch 技能后运行 python -m scripts.scan」——
#   `psl-watch` 在产品里**不存在**（全仓 grep 零命中），也就是说这条指引的前置条件
#   是个死物；而正文尾行已经给过同一条命令。品牌同时从 AgentState 收回 Antinel。
FOOTER = ("本报告由 Antinel 监理生成。复扫方式：python -m scripts.scan --root .")


# --------------------------------------------------------------- loading ----
def load_events(log_path, since=None):
    """since: 'YYYY-MM-DD' or None. Day files are selected by name first, then
    each record is filtered on its ts prefix (records carry local ISO timestamps)."""
    files = []
    p = Path(log_path)
    if p.is_file():
        files = [str(p)]
    elif p.is_dir():
        files = sorted(glob.glob(str(p / "*.jsonl")))
    if since:
        files = [f for f in files if not _is_day_file(f) or Path(f).stem >= since]
    events = []
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue
                    if since and (ev.get("ts") or "")[:10] < since:
                        continue
                    events.append(ev)
        except OSError:
            continue
    return events, files


def _is_day_file(path):
    try:
        datetime.strptime(Path(path).stem, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def load_policy(root):
    """Spec C-05: .psl/policy.json; unknown fields ignored, missing file = defaults."""
    pol = load_json(Path(root) / ".psl" / "policy.json") or {}
    gs = pol.get("global_settings") or {}
    try:
        days = int(gs.get("log_retention_days", RETENTION_DAYS_DEFAULT))
    except (TypeError, ValueError):
        days = RETENTION_DAYS_DEFAULT
    return {"log_retention_days": max(0, days), "auto_archive": bool(gs.get("auto_archive", False))}


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def rules_descriptions(root=None):
    data = load_json(_locate("rules", "default.json")) or {}
    out = {r.get("id"): r for r in data.get("rules", [])}
    if root:
        custom = load_json(Path(root) / ".psl" / "rules" / "custom.json") or {}
        for r in custom.get("rules", []):
            if r.get("id") and r.get("id") not in out:
                out[r["id"]] = r
    return out


def _sha256(path):
    try:
        return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except Exception:
        return None


def self_tamper_check(manifest):
    """Spec 2.8: compare manifest hashes (rules + scripts) with the live package."""
    if not manifest:
        return None
    drift = []
    if manifest.get("rules_hash"):
        live = _sha256(_locate("rules", "default.json"))
        if live != manifest["rules_hash"]:
            drift.append("rules/default.json")
    for name, recorded in (manifest.get("scripts_hash") or {}).items():
        live = _sha256(_locate(name))
        if live != recorded:
            drift.append(name)
    if drift:
        return "SELF-TAMPERED: %s differ from manifest hashes recorded at install (%s)" % (
            ", ".join(drift), manifest.get("installed_at", "?"))
    return None


# -------------------------------------------------------------- analysis ----
def build_report(events, scan, manifest, host_label="", root=None):
    rules = rules_descriptions(root)
    findings = {}
    stats = {"events": len(events), "pre": 0, "post": 0, "blocked": 0, "alerted": 0,
             "post_alerts": 0, "by_tool": {}, "canaries": set(), "sessions": set()}
    # 0.16.0 (P0-7 / WS-3): degraded-config events must be visible in the report,
    # not only in the raw audit log. Three families, counted separately because
    # they mean different things (T1): rules fell back (integrity mismatch or
    # unreadable file) and workspace_roots entries were rejected.
    cfg = {"rules_integrity_fallback": 0, "rules_unreadable_fallback": 0,
           "workspace_config_rejected": 0,
           # 0.19.2: AN-010 released its own host-level config file. Counted here
           # because it is a boundary change, not an ordinary allow: the report
           # must show that the trust boundary was edited, and by what.
           "dst02_host_config_self_maintenance": 0,
           # 0.29.0 (D-1): the last silent release in the codebase is now counted.
           # A whitelist-released secrets read used to leave NO record at all, so
           # the report could not distinguish "released" from "nothing matched".
           # Counting it here is the whole point of D-1: the number must be visible.
           "sec_path_whitelisted": 0,
           # 0.18.0 (HP-47): hook health events become visible too -- a hook
           # that crashed mid-call used to appear ONLY in the raw JSONL.
           "hook_error": 0, "session_start": 0, "hook_alive": 0,
           # 0.42.0 (P5-1): hook_slow was the LAST silent release of this
           # family -- AUDIT_SCHEMA §4 registers it and states its reason for
           # existing ("慢到超时＝这张牌没打出去且无人知晓"), the hook writes it
           # faithfully (89 records, worst 2,476,295 ms ~ 41 min, on the real
           # workspace chain), yet NOTHING consumed it: the only line that
           # could see it (`elif action == "alert"`) is type-blind, so all 89
           # were absorbed by one anonymous counter and no reader could tell
           # "a hook ran 41 minutes" from "an alert fired". Counting it here
           # is the whole point: a timeout is treated as ALLOW by the host,
           # so the verdict may never have reached the host at all.
           "hook_slow": 0, "hook_slow_max_ms": 0}
    for ev in events:
        typ = ev.get("type", "")
        if typ in cfg:
            cfg[typ] += 1
        # 0.42.0 (P5-1): the count alone understates it -- 89 records with a
        # worst case of 41 minutes is a different fact from 89 records that
        # each took 8.1 s. Keep the worst so the line can show both.
        if typ == "hook_slow":
            try:
                cfg["hook_slow_max_ms"] = max(cfg["hook_slow_max_ms"],
                                              int(ev.get("elapsed_ms") or 0))
            except (TypeError, ValueError):
                pass
        tool = ev.get("tool") or "unknown"
        if typ == "pre_tool_use":
            stats["pre"] += 1
        elif typ == "post_tool_use":
            stats["post"] += 1
            stats["by_tool"][tool] = stats["by_tool"].get(tool, 0) + 1
            if ev.get("action") == "alert":
                stats["post_alerts"] += 1
            for c in ev.get("canaries_observed") or []:
                stats["canaries"].add(c)
        if ev.get("session"):
            stats["sessions"].add(ev["session"])
        if ev.get("decision") == "block":
            stats["blocked"] += 1
        elif ev.get("action") == "alert":
            stats["alerted"] += 1
        for rid in ev.get("rules_hit") or []:
            inp = ev.get("input") or {}
            target = inp.get("file_path") or inp.get("command") or ""
            key = (rid, target[:200])
            if key in findings:
                findings[key]["count"] += 1
                continue
            rule = rules.get(rid, {})
            findings[key] = {
                "rule_id": rid,
                "severity": (ev.get("severity") or rule.get("severity") or "warning").lower(),
                "source": "hook",
                "time": ev.get("ts", ""),
                "tool": tool,
                "target": target[:200],
                "description": rule.get("description") or (
                    "tool output contains secret-like content" if rid == "OUT-01" else rid),
                "remediation": rule.get("remediation", ""),
                "decision": ev.get("decision") or ev.get("action") or "",
                "count": 1,
            }
    if scan:
        for f in scan.get("findings", []):
            key = (f.get("rule_id"), "scan:" + f.get("file", ""))
            if key in findings:
                continue
            findings[key] = {
                "rule_id": f.get("rule_id"), "severity": f.get("severity", "warning"),
                "source": "scan", "time": scan.get("generated_at", ""), "tool": "scan",
                "target": f.get("file", "") + (":%d" % f["line"] if f.get("line") else ""),
                "description": f.get("description", ""), "remediation": f.get("remediation", ""),
                "decision": "finding", "count": 1,
            }
    flist = list(findings.values())
    score = 100
    summary = {"critical": 0, "warning": 0, "info": 0}
    for f in flist:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
        score -= SEVERITY_WEIGHT.get(f["severity"], 0)
    score = max(0, min(100, score))
    # ★ 0.55.3（2026-10-23，企业首日复核）：同一个 score 字段有两种分母。
    #   没有 Agent 调用、只有 .psl/scan_last.json 时，这个分只覆盖「文件里有没有
    #   已知模式」，不覆盖运行期行为 —— 此时说 secure 与「环境安全」都是假话
    #   （实测：全新项目 events=0，`python -m scripts.report --format json`
    #   打出 score=100 / grade="secure"）。三态，机器可读：
    #     observed  = 有会话/调用事件，分数覆盖运行期
    #     scan_only = 只有静态扫描，运行期未被观测
    #     none      = 两者皆无（主流程会把 score 置 None、grade 置 no_data）
    basis = "observed" if events else ("scan_only" if scan else "none")
    grade = ("secure" if score >= 90 else "needs attention" if score >= 70
             else "at risk" if score >= 50 else "unsafe")
    if basis == "scan_only":
        # secure 是「观测到没有问题」的断言；没有观测就没有这个资格。
        grade = "scan_only"
    # 0.30.0 (E-3): enforcement status -- is the deny signal still honored?
    # Facts only, straight from the chain: synthetic probe results
    # (enforcement_probe), real-traffic gaps (enforcement_gap = a call the
    # guardrail blocked was executed anyway), and the days the hook proved
    # alive (hook_alive). The morning report must be able to say "the gate is
    # dead" instead of silently shipping a ledger-only product.
    probes = [e for e in events if e.get("type") == "enforcement_probe"]
    gaps = [e for e in events if e.get("type") == "enforcement_gap"]
    enforcement = {
        "probe_last": ({k: probes[-1].get(k) for k in
                        ("ts", "ok", "host", "exit_code", "stdout_channel", "deny_mode")}
                       if probes else None),
        "probe_ok": sum(1 for e in probes if e.get("ok") is True),
        "probe_fail": sum(1 for e in probes if e.get("ok") is False),
        "gaps": len(gaps),
        "last_gap": ({k: gaps[-1].get(k) for k in ("ts", "content_digest", "rule_ids")}
                     if gaps else None),
        "alive_days": len({(e.get("ts") or "")[:10] for e in events
                           if e.get("type") == "hook_alive"}),
    }
    return {
        "schema": "antinel-report-v1",
        "tool_version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "host": host_label or (manifest or {}).get("host", "") or "unknown",
        "sessions": sorted(stats["sessions"]),
        "stats": {k: (sorted(v) if isinstance(v, set) else v) for k, v in stats.items()},
        "findings": sorted(flist, key=lambda f: ({"critical": 0, "warning": 1}.get(f["severity"], 2),
                                                 f["time"])),
        "summary": summary,
        "score": score,
        "grade": grade,
        "basis": basis,
        "score_basis": {"base": 100, "critical_weight": 20, "warning_weight": 5,
                        "critical": summary.get("critical", 0), "warning": summary.get("warning", 0),
                        "raw": 100 - 20 * summary.get("critical", 0) - 5 * summary.get("warning", 0),
                        "dedupe_key": "(rule_id, target)"},
        "self_tamper": self_tamper_check(manifest),
        "config_health": {k: v for k, v in cfg.items()},
        "enforcement": enforcement,
        # 0.33.1 (P4-1)：宿主标签可信度。0.33.1 之前的记录没有 host_confidence
        # 字段 ⇒ 归因无证据（实测：本项目 WorkBuddy 流量被标成 qoder）。链不可变，
        # 所以不改链，改读法：把这个比例印在报告里，让 host 字段不再被当事实引用。
        "host_trust": {
            "records": len([e for e in events if e.get("type") in ("pre_tool_use", "post_tool_use")]),
            "unverified": sum(1 for e in events if e.get("type") in ("pre_tool_use", "post_tool_use")
                              and e.get("host_confidence") is None),
            "low": sum(1 for e in events if e.get("type") in ("pre_tool_use", "post_tool_use")
                       and e.get("host_confidence") == "low"),
            "high": sum(1 for e in events if e.get("type") in ("pre_tool_use", "post_tool_use")
                        and e.get("host_confidence") == "high"),
            "note": "unverified = written before 0.33.1 (no attribution evidence recorded); "
                    "their host field must NOT be cited as fact",
        },
        "scan_included": bool(scan),
    }


# --------------------------------------------------------------- renders ----
def _lang():
    """Detect UI language."""
    v = os.environ.get("ANTINEL_LANG", "")
    if v in ("zh", "en"):
        return v
    try:
        import locale
        loc = _os_locale().lower()
        return "zh" if loc.startswith("zh") else "en"
    except Exception:
        return "en"


def render_text(rep, log_label):
    L = [BAR, " Antinel Security Audit Report",
         " %s | %s | sessions: %d" % (rep["generated_at"][:16].replace("T", " "),
                                      rep["host"], len(rep["sessions"])),
         BAR, ""]
    if rep.get("self_tamper"):
        L += [" \u26A0 " + rep["self_tamper"], ""]
    n = 0
    for sev, icon, title in (("critical", "\U0001F534", "CRITICAL"),
                             ("warning", "\U0001F7E1", "WARNING")):
        group = [f for f in rep["findings"] if f["severity"] == sev]
        if not group:
            continue
        L.append(" %s %s (%d)" % (icon, title, len(group)))
        for f in group:
            n += 1
            L.append("  %d. [%s] %s" % (n, f["rule_id"], f["description"]))
            when = f["time"][11:19] if len(f["time"]) >= 19 else f["time"]
            tgt = f["target"] or "-"
            L.append("     Time: %s | %s: %s%s" % (
                when, "Path" if f["tool"] in ("Read", "Write", "Edit", "scan") else "Command",
                tgt, (" | x%d" % f["count"]) if f["count"] > 1 else ""))
            L.append("     Decision: %s | Source: %s" % (f["decision"], f["source"]))
            if f.get("remediation"):
                L.append("     \u2192 %s" % f["remediation"])
        L.append("")
    st = rep["stats"]
    normal = max(0, st["post"] - st.get("post_alerts", 0))
    L.append(" \U0001F7E2 Normal (%d operations)" % normal)
    if st["by_tool"]:
        L.append("  " + " | ".join("%s: %d" % (k, v) for k, v in sorted(st["by_tool"].items())))
    L.append("  blocked: %d | alerts: %d | pre-checks: %d" % (st["blocked"], st["alerted"], st["pre"]))
    if st["canaries"]:
        L.append("  canaries observed: %s" % ", ".join(st["canaries"]))
    # 0.16.0: degraded-config visibility (WS-3 / P0-7). A workspace_roots entry
    # that was rejected, or a rules fallback, changes what the numbers above mean
    # -- so it is printed here, not just buried in the JSONL.
    ch = rep.get("config_health") or {}
    L.append("  config entries rejected: %d | rules fallback (integrity/unreadable): %d/%d" % (
        ch.get("workspace_config_rejected", 0), ch.get("rules_integrity_fallback", 0),
        ch.get("rules_unreadable_fallback", 0)))
    # 0.19.2: the trust boundary is editable from inside the project by design,
    # so the count of boundary edits is part of reading the numbers above.
    L.append("  trust-boundary edits (AN-010 released on Antinel's own config): %d" % (
        ch.get("dst02_host_config_self_maintenance", 0)))
    # 0.18.0 (HP-47): hook health -- a crash count > 0 means at least one call
    # was allowed by the HOST (fail-open) with no verdict recorded at all.
    L.append("  hook health: crash=%d | session_start=%d | hook_alive=%d" % (
        ch.get("hook_error", 0), ch.get("session_start", 0), ch.get("hook_alive", 0)))
    # 0.42.0 (P5-1): hook_slow -- a hook that ran past SLOW_BUDGET_MS. The host
    # kills hooks at 10-15 s and a timeout is treated as ALLOW, so each of
    # these is a call whose verdict may never have been delivered. Printed on
    # its own line for the same reason as sec_path_whitelisted above: it is a
    # number a reviewer must not miss, and folding it into `alerts` (which is
    # what happened for 89 records) hides exactly that.
    _hs_n = ch.get("hook_slow", 0)
    L.append("  hook slow (>= budget; host timeout = ALLOW): %d | worst %d ms%s" % (
        _hs_n, ch.get("hook_slow_max_ms", 0),
        "   <-- these verdicts may never have reached the host" if _hs_n else ""))
    # 0.33.1 (P4-1)：宿主标签可信度（读侧标注，不改链）
    ht = rep.get("host_trust") or {}
    if ht.get("records"):
        L.append("  host attribution: %d/%d records UNVERIFIED (pre-0.33.1, no evidence), "
                 "%d low (dir marker only), %d high (env evidence)"
                 % (ht.get("unverified", 0), ht.get("records", 0),
                    ht.get("low", 0), ht.get("high", 0)))
        if ht.get("unverified"):
            L.append("    \u2192 the host field of those records must not be cited as fact")
    # 0.33.1 (P4-4)：边界必须写在产物里，不能只在威胁模型里。
    L.append("  BOUNDARY: rules match tool-call text only; a delete/egress written into a "
             ".py/.sh and then executed is NOT intercepted. This is a guardrail, not an "
             "isolation layer -- use a container or sandbox for that.")
    # 0.30.0 (E-3): enforcement status -- the gate must be able to say "I am
    # dead" out loud. gaps>0 means a blocked call executed anyway (deny not
    # honored by the host); probe_fail>0 means the signaling channels failed
    # their own synthetic test. Either one turns the "闸门" into a ledger-only
    # product -- that must never be silent.
    en = rep.get("enforcement") or {}
    pl = en.get("probe_last")
    if pl:
        L.append("  enforcement probe: %s | last %s | ok %d / fail %d (this window)" % (
            "OK" if en.get("probe_fail", 0) == 0 else "FAIL",
            (pl.get("ts") or "")[:16].replace("T", " "),
            en.get("probe_ok", 0), en.get("probe_fail", 0)))
    else:
        L.append("  enforcement probe: no probe in this window (first probe runs within 24h of install; manual: python -m tools.enforce_probe)")
    if en.get("gaps"):
        lg = en.get("last_gap") or {}
        L.append("  ⚠ ENFORCEMENT GAP: %d blocked call(s) executed anyway (deny not honored) | last %s rules=%s"
                 % (en.get("gaps", 0), (lg.get("ts") or "")[:16].replace("T", " "),
                    ",".join(lg.get("rule_ids") or [])))
    L.append("  gate alive days (hook_alive): %d" % en.get("alive_days", 0))
    # 0.29.0 (D-1): a whitelist-released secrets read. Printed on its own line and
    # NOT folded into the findings above, because it is the one number a reviewer
    # must not miss: above, `rules_hit` counts what was caught; this counts what
    # was caught and then let through. Same event, opposite meaning.
    _sw = ch.get("sec_path_whitelisted", 0)
    L.append("  whitelist-released secrets reads (caught, then let through): %d%s" % (
        _sw, "   <-- review these: they are NOT in the findings above" if _sw else ""))
    sb = rep.get("score_basis", {})
    if rep.get("empty"):
        # ★ 0.55.1（2026-10-23）：空窗口最危险的不是「没话说」，是**给了分数**。
        #   实测：新装项目第一次 report 打出「Security Score: 100/100 (secure) ＋
        #   环境安全」——分母为零，100 分与「安全」都是假话。企业会截图这句话，
        #   要么信错，要么发现没数据后不再信任何结论。空态一律不出分。
        L += ["", BAR,
              " Security Score: ——（这一窗口没有任何被记录的调用，不出分）",
              " 为什么不出分：分数是「问题占多少」；分母为零时，100 分和「环境安全」是同一种假话。"]
    else:
        L += ["", BAR, " Security Score: %d/100 (%s)" % (rep["score"], rep["grade"]),
              " Score basis: 100 - 20 x %d critical - 5 x %d warning = %d (clamped to %d); dedupe on (rule, target)" % (
                  sb.get("critical", 0), sb.get("warning", 0), sb.get("raw", rep["score"]), rep["score"])]
        if rep.get("basis") == "scan_only":
            # ★ 0.55.3：分数在，但分母只有一半。不说这句，读者会把 100 分读成
            #   「跑了一周没有风险行为」——那正是这一版要止住的误读。
            L.append(" 依据：这一窗口没有 Agent 调用记录。这个分只来自静态扫描"
                     "（.psl/scan_last.json），说的是「文件里没扫出已知的坏模式」，"
                     "不是「运行期没有风险行为」。")
    nfind = len(rep["findings"])
    lang = _lang()
    if rep.get("empty"):
        L.append(" 结论：这一窗口没有可统计的记录 —— 既不能说安全，也不能说不安全。"
                 "装好钩子之后，下一次 Agent 调用就会被记进来。")
    elif lang == "zh":
        if rep.get("basis") == "scan_only":
            # ★ 0.55.3：这行原来是「观察期内未发现风险行为，环境安全」—— 同一句假话的
            #   第二处实现（第一处是 score 行）。只改分数不改这句，等于没改。
            L.append(" 结论：静态扫描未发现问题；运行期行为尚未被观测，"
                     "所以这里不下「环境安全」的结论。"
                     "装好钩子之后，下一次 Agent 调用就会被记进来。")
        elif nfind:
            L.append(" 结论：发现 %d 项问题（CRITICAL %d / WARNING %d），建议优先处理 CRITICAL 项；完整轨迹见审计日志。" % (
                nfind, rep["summary"].get("critical", 0), rep["summary"].get("warning", 0)))
        else:
            L.append(" 结论：观察期内未发现风险行为，环境安全。")
    else:
        if rep.get("basis") == "scan_only":
            L.append(" Conclusion: static scan found nothing; runtime behaviour was NOT observed, "
                     "so this is not a statement that the environment is safe.")
        elif nfind:
            L.append(" Conclusion: %d finding(s) found (CRITICAL %d / WARNING %d). Address CRITICAL items first." % (
                nfind, rep["summary"].get("critical", 0), rep["summary"].get("warning", 0)))
        else:
            L.append(" Conclusion: no risky behaviour observed, environment is safe.")
    # ★ 0.48.4：`python scan.py` 在**安装态**下跑不通（scan.py 在 site-packages 里，
    #   不在项目根）——正面撞「页面上不许教跑不通的命令」。改为安装态可用的写法。
    L += [" Full log: %s" % log_label,
          " Re-scan: python -m scripts.scan --root .", BAR]
    return "\n".join(L)


def render_csv(rep):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["severity", "rule_id", "source", "time", "tool", "target", "decision", "count",
                "description", "remediation"])
    for f in rep["findings"]:
        w.writerow([f["severity"], f["rule_id"], f["source"], f["time"], f["tool"], f["target"],
                    f["decision"], f["count"], f["description"], f.get("remediation", "")])
    return buf.getvalue()


def render_sarif(rep):
    """SARIF 2.1.0 (US-05). critical -> error, warning -> warning, info -> note."""
    level = {"critical": "error", "warning": "warning", "info": "note"}
    rules = {}
    results = []
    for f in rep["findings"]:
        rid = f["rule_id"]
        rules.setdefault(rid, {"id": rid,
                               "shortDescription": {"text": f["description"] or rid},
                               "help": {"text": f.get("remediation", "") or ""},
                               "defaultConfiguration": {"level": level.get(f["severity"], "note")}})
        target = f["target"] or ""
        loc = {"physicalLocation": {"artifactLocation": {"uri": target.split(":")[0] if f["source"] == "scan" else target}}}
        if f["source"] == "scan" and ":" in target and target.rsplit(":", 1)[-1].isdigit():
            loc["physicalLocation"]["region"] = {"startLine": int(target.rsplit(":", 1)[-1])}
        results.append({
            "ruleId": rid,
            "level": level.get(f["severity"], "note"),
            "message": {"text": "%s (%s, %s, x%d)" % (f["description"] or rid, f["source"], f["decision"], f["count"])},
            "locations": [loc] if target else [],
            "properties": {"source": f["source"], "tool": f["tool"], "time": f["time"], "decision": f["decision"]},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Antinel", "version": TOOL_VERSION,
                                # ★ 0.55.3：原值 github.com/antinel/security-suite 实测
                                #   HTTP 404 —— 灌进 GitHub Code Scanning 后工具链接是死链。
                                "informationUri": "https://antinel.com/",
                                "rules": list(rules.values())}},
            "results": results,
            "properties": {"score": rep["score"], "grade": rep["grade"], "host": rep["host"],
                           "generated_at": rep["generated_at"], "self_tamper": rep.get("self_tamper")},
        }],
    }, ensure_ascii=False, indent=1)


def render_html(rep, log_label):
    e = html.escape
    rows = []
    for f in rep["findings"]:
        color = COLORS.get(f["severity"], COLORS["neutral"])
        rows.append(
            "<tr><td style='color:%s;font-weight:bold'>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td>%s</td><td>%s</td></tr>" % (
                color, e(f["severity"].upper()), e(f["rule_id"]), e(f["description"]),
                e(f["target"] or "-"), e(f["decision"]), e(f.get("remediation", ""))))
    st = rep["stats"]
    bars = []
    top = max([1] + list(st["by_tool"].values()))
    for tool, cnt in sorted(st["by_tool"].items()):
        width = int(300 * cnt / top)
        bars.append("<div class='bar'><span class='lbl'>%s</span>"
                    "<span class='fill' style='width:%dpx'></span> %d</div>" % (e(tool), width, cnt))
    # ★ 0.55.1：空窗口 rep["score"] 是 None（不出分）。HTML 仍然要能打开，
    #   不能因为「没有分数」就 500 —— 空态页面比崩溃页诚实得多。
    if rep.get("score") is None:
        score_color = COLORS["neutral"]
        score_txt = "&mdash;"
    elif rep.get("basis") == "scan_only":
        # ★ 0.55.3：分数只来自静态扫描 ⇒ 不上绿色。「绿 + 100/100」是这一版之前
        #   企业截图里最容易误读的一张图。中性色 + grade=scan_only 说清证据等级。
        score_color = COLORS["neutral"]
        score_txt = "%d/100" % rep["score"]
    else:
        score_color = COLORS["ok"] if rep["score"] >= 90 else (
            COLORS["warning"] if rep["score"] >= 70 else COLORS["critical"])
        score_txt = "%d/100" % rep["score"]
    tamper = ("<p class='tamper'>%s</p>" % e(rep["self_tamper"])) if rep.get("self_tamper") else ""
    # 0.42.0 (P5-1): hook_slow gets the same treatment as the text report --
    # its own line, because a host timeout is an ALLOW and these verdicts may
    # never have been delivered.
    _ch = rep.get("config_health") or {}
    _hs_n = _ch.get("hook_slow", 0)
    hookslow = ("<p>hook slow (>= budget; host timeout = ALLOW): %d | worst %d ms"
                "%s</p>" % (_hs_n, _ch.get("hook_slow_max_ms", 0),
                            " &mdash; these verdicts may never have reached the host"
                            if _hs_n else ""))
    return """<!doctype html><html><head><meta charset="utf-8">
<title>Antinel Security Audit Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#212529}
h1{margin:0 0 4px 0} .meta{color:%(neutral)s;margin-bottom:20px}
.score{font-size:40px;font-weight:bold;color:%(score_color)s}
table{border-collapse:collapse;width:100%%;margin:16px 0}
th,td{border:1px solid #dee2e6;padding:6px 8px;text-align:left;font-size:14px;vertical-align:top}
th{background:#f8f9fa}
.bar{margin:4px 0;font-size:14px} .lbl{display:inline-block;width:90px}
.fill{display:inline-block;height:12px;background:%(ok)s;vertical-align:middle}
.tamper{color:%(critical)s;font-weight:bold}
.footer{color:%(neutral)s;font-size:12px;margin-top:32px;border-top:1px solid #dee2e6;padding-top:8px}
</style></head><body>
<h1>Antinel Security Audit Report</h1>
<div class="meta">%(when)s | host: %(host)s | sessions: %(sessions)d | log: %(log)s</div>
<div class="score">%(score_txt)s</div><div>%(grade)s</div>
%(tamper)s
<h2>Findings (critical: %(crit)d, warning: %(warn)d)</h2>
<table><tr><th>Severity</th><th>Rule</th><th>Description</th><th>Target</th><th>Decision</th><th>Remediation</th></tr>
%(rows)s</table>
<h2>Operations</h2>
<p>post-tool records: %(post)d | pre-checks: %(pre)d | blocked: %(blocked)d | alerts: %(alerted)d</p>
%(hookslow)s
%(bars)s
<div class="footer">%(footer)s</div>
</body></html>""" % {
        "neutral": COLORS["neutral"], "ok": COLORS["ok"], "critical": COLORS["critical"],
        "score_color": score_color, "when": e(rep["generated_at"][:16].replace("T", " ")),
        "host": e(rep["host"]), "sessions": len(rep["sessions"]), "log": e(log_label),
        "score_txt": score_txt, "grade": e(rep["grade"]), "tamper": tamper,
        "crit": rep["summary"].get("critical", 0), "warn": rep["summary"].get("warning", 0),
        "rows": "\n".join(rows) or "<tr><td colspan='6'>No findings</td></tr>",
        "post": st["post"], "pre": st["pre"], "blocked": st["blocked"], "alerted": st["alerted"],
        "hookslow": hookslow,
        "bars": "\n".join(bars), "footer": e(FOOTER),
    }


# --------------------------------------------------------------- archive ----
def archive_logs(audit_dir, retention_days=RETENTION_DAYS_DEFAULT):
    audit_dir = Path(audit_dir)
    if not audit_dir.is_dir():
        return []
    archived = []
    cutoff = datetime.now() - timedelta(days=retention_days)
    files = sorted(audit_dir.glob("*.jsonl"))

    def compress(fp):
        month = fp.stem[:7] if len(fp.stem) >= 7 else "misc"
        dst_dir = audit_dir / "archive" / month
        dst_dir.mkdir(parents=True, exist_ok=True)
        dst = dst_dir / (fp.name + ".gz")
        with open(fp, "rb") as fin, gzip.open(dst, "wb") as fout:
            shutil.copyfileobj(fin, fout)
        fp.unlink()
        archived.append(str(dst))

    today = datetime.now().strftime("%Y-%m-%d")
    for fp in files:
        try:
            day = datetime.strptime(fp.stem, "%Y-%m-%d")
        except ValueError:
            continue
        if day < cutoff and fp.stem != today:
            compress(fp)
    remaining = sorted(audit_dir.glob("*.jsonl"))
    total = sum(f.stat().st_size for f in remaining)
    while total > MAX_AUDIT_BYTES and len(remaining) > 1:
        oldest = remaining.pop(0)
        total -= oldest.stat().st_size
        compress(oldest)
    return archived


# ------------------------------------------------------------------ main ----
def _root_module(name):
    """包根模块的导入兜底（`host_shield` / `session_dna` …）。

    本文件在 `scripts/`，源仓布局与随包布局下包根都是上一级目录。
    ★ 归口：**只留这一份** sys.path 兜底，`_import_session_dna` 复用它 ——
      「同一件事两份实现」是本仓第一顽症，别在这里再添一处。
    """
    try:
        parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if parent not in sys.path:
            sys.path.insert(0, parent)
        return __import__(name)
    except Exception:                                          # noqa: BLE001
        return None


def _import_session_dna():
    """session_dna lives at the package root; report.py may run from the source
    tree (same dir) or an installed layout (<pkg>/scripts)."""
    return _root_module("session_dna")


def _emit_rules_drift(root):
    """★ 0.57.0（第 32 条）：规则快照落差，**在任何数字之前**说出来。

    为什么位置这么靠前：下面 `--session latest` 的空态分支会直接 return，
    而「刚升级完、项目里规则还是旧的」恰恰最常发生在刚装好、还没有会话的时候。
    提示若挂在汇总块上，就永远打不出来。文案由 `host_shield.rules_drift_lines`
    唯一提供（别在这里另写一份）。
    """
    hs = _root_module("host_shield")
    if hs is None:
        return
    try:
        lines = hs.rules_drift_lines(str(root))
    except Exception:                                          # noqa: BLE001
        return
    if not lines:
        return
    for ln in lines:
        print(ln)
    print("")


def _session_dna_main(args, root, log_path):
    """--session handler: compute (and optionally chain-write) one session's
    DNA. Independent of the normal report path so a session query never needs
    manifest/scan artifacts."""
    sd = _import_session_dna()
    if sd is None:
        sys.stderr.write("session_dna module not found next to report.py\n")
        return 2
    audit_dir = log_path if log_path.is_dir() else log_path.parent
    session_q = args.session
    if session_q == "latest":
        sd0 = sd
        latest = sd0.find_latest_session(audit_dir)
        if not latest:
            # ★ 0.55.1（2026-10-23，企业首日实测）：这是 `antinel report` 的
            #   **默认路径**（不传 --days 就走会话；而人敲的就是 `antinel report`）。
            #   旧版在这里 return 1 ⇒ 新装企业第一天拿到失败退出码，被读成「查询失败」。
            #   与 --days 路径同口径：空态不是错，照实说，退出码 0。
            # ★ 同一处还要分格式：`python -m scripts.report --format json` 是
            #   README 教的导出命令，空态若在 stdout 印中文，`--format json` 的调用方
            #   会拿到「rc=0 但不是 JSON」—— 这比原来的 rc=1 更坏（失败被伪装成成功）。
            _why = "这个项目还没有可统计的会话（心跳与 CLI 不算）"
            if args.format == "json":
                sys.stdout.write(json.dumps(
                    {"empty": True, "session": None, "reason": _why,
                     "note": "这不是「一切正常」的结论：这一窗口里没有东西可算。"},
                    ensure_ascii=False) + "\n")
            else:
                # html / csv / sarif 在空态下**不编造**空文档结构（编出来的表头
                # 会让下游以为「这一版有这个格式的空表示例」）；一律回退成这句话，
                # 退出码仍为 0。README 已写明非 json 格式的空态长这样。
                sys.stdout.write(
                    _why + "。\n"
                    "这表示这一窗口里没有东西可算，不是「一切正常」的结论。\n"
                    "装好钩子之后，下一次 Agent 调用就会被记进来。\n")
            return 0
        session_q = latest
    # 0.23.0 (A3/A4): pricing lookup -- project rules first, then the package's
    # own rules/. Missing table => facts-only DNA (no cost_estimate block).
    pricing = None
    for cand in (root / ".psl" / "rules" / "pricing.json",
                 Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / "rules" / "pricing.json",
                 Path(__file__).resolve().parent / "rules" / "pricing.json"):
        try:
            p = json.load(open(cand, encoding="utf-8"))
            if isinstance(p, dict) and isinstance(p.get("rates"), dict):
                pricing = p
                break
        except Exception:
            continue
    dna = sd.compute(audit_dir, session_q,
                     max_bytes=None, max_files=None, generated_by="report.py",
                     pricing=pricing)
    if dna is None:
        sys.stderr.write("no audit records for session %s under %s\n" % (session_q, audit_dir))
        return 1
    wrote = False
    if args.write_dna:
        wrote = sd.append_chained(audit_dir, dna)
        if not wrote:
            sys.stderr.write("AUDIT_WRITE_FAILED: session_dna could not be chained; "
                             "not written unchained\n")
            return 1
    if args.format == "json":
        payload = dict(dna)
        if args.write_dna:
            payload["dna_written"] = bool(wrote)
        body = json.dumps(payload, ensure_ascii=False, indent=1)
    else:
        _u = dna.get("usage") or {}
        _tok = sum((v.get("total") or 0) for v in (_u.get("by_model") or {}).values())
        lines = [
            "【摘要】本会话 %s 次操作、拦截 %s 次、提醒 %s 次、触碰 %s 个文件%s——证据链在账，明细如下。"
            % (dna["actions"]["total"], dna["blocks"]["total"], dna["warnings"]["total"],
               dna["files"]["touched_unique"],
               ("、token 进出 %s" % format(_tok, ",")) if _tok else ""),
            "Session DNA: %s" % dna["session"],
            "  generated_by: %s   at: %s" % (dna["generated_by"], dna["generated_at"]),
            "  coverage: %s record(s) across %s day file(s)%s"
            % (dna["coverage"]["records"], len(dna["coverage"]["days"]),
               "  [TRUNCATED at byte budget]" if dna["coverage"]["truncated"] else ""),
            "  span: %s .. %s" % (dna["span"]["first"], dna["span"]["last"]),
            "  actions: %s   by_tool: %s" % (dna["actions"]["total"], dna["actions"]["by_tool"]),
            "  blocks: %s   by_rule: %s" % (dna["blocks"]["total"], dna["blocks"]["by_rule"]),
            "  warnings: %s" % dna["warnings"]["total"],
            "  files touched (unique): %s   top: %s"
            % (dna["files"]["touched_unique"],
               ", ".join("%s x%s" % (f["path"], f["count"]) for f in dna["files"]["top"]) or "-"),
            "  durations: %s pair(s), median %s ms, p95 %s ms"
            % (dna["durations"]["pairs"], dna["durations"]["median_ms"], dna["durations"]["p95_ms"]),
            "  exits: %s observed, %s nonzero" % (dna["exits"]["observed"], dna["exits"]["nonzero"]),
        ]
        u = dna.get("usage") or {}
        if u.get("entries"):
            lines.append("  usage: %s harvest entry(ies)" % u["entries"])
            for m, v in sorted((u.get("by_model") or {}).items()):
                lines.append("    %s: %s turn(s), in=%s out=%s cache_read=%s total=%s"
                             % (m, v.get("entries"), v.get("input"), v.get("output"),
                                v.get("cache_read"), v.get("total")))
            ce = u.get("cost_estimate")
            if ce:
                lines.append("  cost ESTIMATE (%s, pricing %s): %s %s"
                             % (ce.get("currency"), ce.get("pricing_version"),
                                ce.get("total"), "  unpriced: %s" % ",".join(ce.get("unpriced_models") or [])
                                if ce.get("unpriced_models") else ""))
                for m, c in sorted((ce.get("by_model") or {}).items()):
                    lines.append("    %s: %s" % (m, c))
            else:
                lines.append("  cost: no usable pricing table (rates empty) -- tokens are facts, "
                             "fill rules/pricing.json to derive cost")
        if args.write_dna:
            lines.append("  dna_written: %s (chained)" % ("true" if wrote else "false"))
        body = "\n".join(lines)
    if args.out:
        Path(args.out).write_text(body, encoding="utf-8")
        print("session DNA written: %s" % args.out)
    else:
        print(body)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Antinel behaviour report")
    ap.add_argument("--root", default=os.getcwd(), help="project root (default: cwd)")
    ap.add_argument("--log", help="audit dir or .jsonl file (default: <root>/.psl/audit)")
    ap.add_argument("--format", default="text", choices=["text", "json", "html", "csv", "sarif"])
    ap.add_argument("--out", help="write report to this file instead of stdout")
    ap.add_argument("--days", type=int, help="only the last N calendar days (1 = daily, 7 = weekly)")
    ap.add_argument("--since", help="only records on/after YYYY-MM-DD")
    ap.add_argument("--no-scan", action="store_true", help="do not merge .psl/scan_last.json")
    ap.add_argument("--archive", action="store_true", help="apply retention policy (B-05)")
    ap.add_argument("--retention-days", type=int, help="override .psl/policy.json log_retention_days")
    # 0.22.0 (A5, 三问三答 v1.0): per-session DNA. Facts only -- every field is
    # an aggregation of records already in the audit chain.
    ap.add_argument("--session", help="session DNA: aggregate one session's audit records")
    ap.add_argument("--write-dna", action="store_true",
                    help="with --session: append the DNA to the audit chain (chained)")
    # ★ 0.34.0 (E5)：按人分层。
    #   动机（实测）：本报告 19 行正文里有 8 行是给**安全工程师**看的
    #   （config health / hook health / host attribution / enforcement probe /
    #    gate alive days / rules fallback / trust-boundary edits /
    #    whitelist-released secrets reads）—— 这些是真价值，**一行都不删**。
    #   ★ 但**决策层要的三个数字一个都没有**（有没有外发／比上期／该做什么）。
    #   ⇒ `--audience exec` 走 `antinel brief`（同一份账本，同一套判据），
    #     默认 `engineer` = 本文件原有行为，**一字不变**（向后兼容）。
    ap.add_argument("--audience", default="engineer",
                    choices=["engineer", "exec"],
                    help="engineer=完整技术报告（默认）；exec=决策层一页纸（转 antinel brief）")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    root = Path(args.root).resolve()
    log_path = Path(args.log) if args.log else root / ".psl" / "audit"

    # ★ 0.57.0（第 32 条）：先报规则快照落差，再谈任何数字。
    _emit_rules_drift(root)

    # ★ 0.34.0 (E5)：`--audience exec` 派发到 `antinel brief`。
    #   ★ 派发而不是复制实现：`brief` 在 antinel.py 里，本文件不 import 它
    #     （它 import 本文件，复过来会成环）⇒ 用同目录的 antinel.py 跑一次子进程。
    #   ⇒ 判据只有**一处**（`antinel._agg_audit`），两层视图口径天然一致。
    if args.audience == "exec":
        import subprocess as _sp, sys as _sys
        # ★ antinel.py 在**包根**，不在 scripts/（本文件在 scripts/）——
        #   随包布局与源仓布局都是 `../antinel.py`。
        _here = Path(__file__).resolve().parent
        _argv = [_sys.executable, str(_here.parent / "antinel.py"), "brief"]
        if args.days:
            _argv += ["--days", str(args.days)]
        return _sp.call(_argv)

    if args.session:
        return _session_dna_main(args, root, log_path)

    since = None
    if args.since:
        try:
            since = datetime.strptime(args.since, "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            sys.stderr.write("bad --since, expected YYYY-MM-DD\n")
            return 2
    if args.days is not None:
        if args.days < 1:
            sys.stderr.write("--days must be >= 1\n")
            return 2
        since = (datetime.now() - timedelta(days=args.days - 1)).strftime("%Y-%m-%d")
    try:
        policy = load_policy(root)
        retention = args.retention_days if args.retention_days is not None else policy["log_retention_days"]
        if args.archive or policy.get("auto_archive"):
            for a in archive_logs(log_path if log_path.is_dir() else log_path.parent, retention):
                print("archived: " + a)
        events, files = load_events(log_path, since)
        scan = None if (args.no_scan or since) else load_json(root / ".psl" / "scan_last.json")
        manifest = load_json(root / ".psl" / "manifest.json")
        # 0.55.1：空态不是错。旧版在这里 return 1，于是「刚装好、当天还没有
        #   任何调用」的人跑第一条查询，拿到的是退出码 1 —— 把「还没有东西可看」
        #   报成了「查询失败」。现在仍走同一条产出路径（零值报告，结构与有数据时
        #   一致），退出码 0，并在报告里标 empty，让机器读者能区分「零」与「坏」。
        empty = not events and not scan
        if empty:
            sys.stderr.write("no audit events under %s%s — empty window, "
                             "reporting zeros\n" % (
                                 log_path, (" since " + since) if since else ""))
        rep = build_report(events, scan, manifest, root=root)
        rep["period"] = {"since": since, "days": args.days}
        if empty:
            rep["empty"] = True
            # ★ 0.55.1：空窗口不出分。见 text 渲染处的长注释（分母为零时 100 分是假话）。
            rep["score"] = None
            rep["grade"] = "no_data"
        label = str(log_path) if len(files) != 1 else files[0]
        if args.format == "json":
            out = json.dumps(rep, ensure_ascii=False, indent=1)
        elif args.format == "html":
            out = render_html(rep, label)
        elif args.format == "csv":
            out = render_csv(rep)
        elif args.format == "sarif":
            out = render_sarif(rep)
        else:
            out = render_text(rep, label)
        if args.out:
            Path(args.out).write_text(out, encoding="utf-8")
            print("report written: %s" % args.out)
        else:
            print(out)
        return 0
    except Exception as e:
        sys.stderr.write("report error: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
