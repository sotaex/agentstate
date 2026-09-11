#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel Security Suite v1.1 - report generator (F-04 behaviour report, F-05 score).

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
TOOL_VERSION = "0.17.0"
RETENTION_DAYS_DEFAULT = 30
SCRIPT_FILES = ("pre_tool_use.py", "post_tool_use.py", "scan.py", "install.py", "report.py")


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
FOOTER = ("本报告由 Antinel Security Suite 生成。验证方式：安装 psl-watch 技能后运行 "
          "python scripts/scan.py。")


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
           "workspace_config_rejected": 0}
    for ev in events:
        typ = ev.get("type", "")
        if typ in cfg:
            cfg[typ] += 1
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
    grade = ("secure" if score >= 90 else "needs attention" if score >= 70
             else "at risk" if score >= 50 else "unsafe")
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
        "score_basis": {"base": 100, "critical_weight": 20, "warning_weight": 5,
                        "critical": summary.get("critical", 0), "warning": summary.get("warning", 0),
                        "raw": 100 - 20 * summary.get("critical", 0) - 5 * summary.get("warning", 0),
                        "dedupe_key": "(rule_id, target)"},
        "self_tamper": self_tamper_check(manifest),
        "config_health": {k: v for k, v in cfg.items()},
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
        loc = (locale.getdefaultlocale()[0] or "").lower()
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
    sb = rep.get("score_basis", {})
    L += ["", BAR, " Security Score: %d/100 (%s)" % (rep["score"], rep["grade"]),
          " Score basis: 100 - 20 x %d critical - 5 x %d warning = %d (clamped to %d); dedupe on (rule, target)" % (
              sb.get("critical", 0), sb.get("warning", 0), sb.get("raw", rep["score"]), rep["score"])]
    nfind = len(rep["findings"])
    lang = _lang()
    if lang == "zh":
        if nfind:
            L.append(" 结论：发现 %d 项问题（CRITICAL %d / WARNING %d），建议优先处理 CRITICAL 项；完整轨迹见审计日志。" % (
                nfind, rep["summary"].get("critical", 0), rep["summary"].get("warning", 0)))
        else:
            L.append(" 结论：观察期内未发现风险行为，环境安全。")
    else:
        if nfind:
            L.append(" Conclusion: %d finding(s) found (CRITICAL %d / WARNING %d). Address CRITICAL items first." % (
                nfind, rep["summary"].get("critical", 0), rep["summary"].get("warning", 0)))
        else:
            L.append(" Conclusion: no risky behaviour observed, environment is safe.")
    L += [" Full log: %s" % log_label, " Re-scan: python scan.py", BAR]
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
            "tool": {"driver": {"name": "Antinel Security Suite", "version": TOOL_VERSION,
                                "informationUri": "https://github.com/antinel/security-suite",
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
    score_color = COLORS["ok"] if rep["score"] >= 90 else (
        COLORS["warning"] if rep["score"] >= 70 else COLORS["critical"])
    tamper = ("<p class='tamper'>%s</p>" % e(rep["self_tamper"])) if rep.get("self_tamper") else ""
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
<div class="score">%(score)d/100</div><div>%(grade)s</div>
%(tamper)s
<h2>Findings (critical: %(crit)d, warning: %(warn)d)</h2>
<table><tr><th>Severity</th><th>Rule</th><th>Description</th><th>Target</th><th>Decision</th><th>Remediation</th></tr>
%(rows)s</table>
<h2>Operations</h2>
<p>post-tool records: %(post)d | pre-checks: %(pre)d | blocked: %(blocked)d | alerts: %(alerted)d</p>
%(bars)s
<div class="footer">%(footer)s</div>
</body></html>""" % {
        "neutral": COLORS["neutral"], "ok": COLORS["ok"], "critical": COLORS["critical"],
        "score_color": score_color, "when": e(rep["generated_at"][:16].replace("T", " ")),
        "host": e(rep["host"]), "sessions": len(rep["sessions"]), "log": e(log_label),
        "score": rep["score"], "grade": e(rep["grade"]), "tamper": tamper,
        "crit": rep["summary"].get("critical", 0), "warn": rep["summary"].get("warning", 0),
        "rows": "\n".join(rows) or "<tr><td colspan='6'>No findings</td></tr>",
        "post": st["post"], "pre": st["pre"], "blocked": st["blocked"], "alerted": st["alerted"],
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
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    root = Path(args.root).resolve()
    log_path = Path(args.log) if args.log else root / ".psl" / "audit"
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
        if not events and not scan:
            sys.stderr.write("no audit events found under %s%s\n" % (
                log_path, (" since " + since) if since else ""))
            return 1
        rep = build_report(events, scan, manifest, root=root)
        rep["period"] = {"since": since, "days": args.days}
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
