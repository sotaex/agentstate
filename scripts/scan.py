#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel Security Suite v0.17.0 - static scan engine (F-01 environment scan).

Single-pass, multi-rule: one os.walk() over the tree, every file is checked
against every applicable STATIC rule (spec part 3). Static rules: SEC-01..05
(sensitive-file exposure, by path), SEC-06 (secret literals in content --
reclassified static in 0.16.0: content_patterns run against text files during
the scan, so the health-check can find a live key, matching what RULES.md has
always claimed) and CTX-02..05 (skill content / metadata). Dynamic rules
(NET-*, DST-*, CTX-01) need runtime evidence and live in the hooks only.

root_dir priority (spec A-06): --root > git rev-parse --show-toplevel > cwd.
Traversal policy (spec A-07): depth <= 15, files > 2 MB read only the first
64 KB, binary files (NUL byte in first 1 KB) skipped, symlinks followed but
recorded when they point outside the root.

Exit codes (spec A-10): 0 = scan complete, 1 = partial (read errors),
2 = fatal (root unusable / rules unloadable).
Python 3.10+, stdlib only, no network.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent


def _locate(*rel):
    """Flat PoC layout (rules/ next to scan.py) or skill package (scan.py in scripts/, rules in ../rules)."""
    for base in (PKG_DIR, PKG_DIR.parent):
        p = base.joinpath(*rel)
        if p.exists():
            return p
    return PKG_DIR.joinpath(*rel)


DEFAULT_RULES = _locate("rules", "default.json")

EXCLUDED_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", ".tox",
                 "dist", "build", "vendor", "third_party"}
EXCLUDED_REL_PATHS = {".psl/audit"}
TEXT_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".py", ".js",
                 ".ts", ".sh", ".bash", ".zsh"}
MAX_DEPTH = 15
MAX_FILE_BYTES = 2 * 1024 * 1024
HEAD_BYTES = 64 * 1024
QUICK_MAX_FILES = 5000
QUICK_MAX_CHARSCAN = 256 * 1024

STATIC_CATEGORIES = {"secrets", "injection", "metadata"}
SEVERITY_WEIGHT = {"critical": 20, "warning": 5, "info": 0}
DEFAULT_RANGES = [(917504, 917631), (8203, 8207), (8288, 8292), (65279, 65279)]


# ---------------------------------------------------------------- rules ----
def load_rules(path, project_root):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = list(data.get("rules", []))
    by_id = {r.get("id"): r for r in rules}
    custom = Path(project_root) / ".psl" / "rules" / "custom.json"
    if custom.is_file():                                   # B-03 merge
        try:
            cdata = json.loads(custom.read_text(encoding="utf-8"))
            for r in cdata.get("rules", []):
                rid = r.get("id")
                if rid in by_id:
                    for key in ("severity", "action", "enabled"):
                        if key in r:
                            by_id[rid][key] = r[key]
                elif rid:
                    rules.append(r)
        except Exception:
            pass
    # C7: drop over-long custom patterns (ReDoS / memory guard)
    for r in rules:
        for key in ("command_patterns", "file_patterns", "content_patterns", "exclude_patterns"):
            pats = r.get(key)
            if isinstance(pats, list):
                keep = [x for x in pats if isinstance(x, str) and len(x) <= 500]
                if len(keep) != len(pats):
                    r[key] = keep
    return rules


class CompiledRule:
    """Pre-compiled static rule (one instance per rule, compiled once)."""

    def __init__(self, rule):
        self.raw = rule
        self.id = rule.get("id", "?")
        self.category = rule.get("category", "")
        self.severity = (rule.get("severity") or "warning").lower()
        self.type = rule.get("type", "")
        self.target = rule.get("target")
        self.detection = rule.get("detection")
        self.description = rule.get("description", "")
        self.remediation = rule.get("remediation", "")
        flags = re.IGNORECASE
        # Patterns live at rule top level (v1.2 flat layout); legacy match.* nesting still accepted.
        legacy = rule.get("match") or {}
        self.file_patterns = _compile_all(rule.get("file_patterns") or legacy.get("file_patterns"), flags)
        self.content_patterns = _compile_all(rule.get("content_patterns") or legacy.get("content_patterns"), flags)
        self.exclude_patterns = _compile_all(rule.get("exclude_patterns"), flags)
        self.ranges = [(int(r["start"]), int(r["end"])) for r in rule.get("ranges", [])] \
            if rule.get("ranges") else DEFAULT_RANGES

    def is_static(self):
        if self.raw.get("enabled") is False:
            return False
        if self.type in ("file_content", "metadata_check"):
            return True
        if self.category == "secrets" and bool(self.file_patterns):
            return True
        # 0.16.0 (gap-report D-05): a tool_call rule that matches ONLY on
        # content_patterns (SEC-06) is static too -- the scanner owns file
        # contents just as much as the hook does. Previously it fell through to
        # False, so the static report ran 9 rules while RULES.md claimed 10.
        return bool(self.content_patterns) and not self.file_patterns
        # and not command_patterns: command-only rules (NET-*/DST-*) never carry
        # command_patterns into this branch because content_patterns is empty.

    def excluded(self, *texts):
        for rx in self.exclude_patterns:
            for t in texts:
                if t and rx.search(t):
                    return True
        return False


def _compile_all(patterns, flags):
    out = []
    for p in patterns or []:
        try:
            out.append(re.compile(p, flags))
        except re.error:
            continue
    return out


# ------------------------------------------------------------- helpers ----
def resolve_root(explicit):
    if explicit:
        return Path(explicit).resolve()
    try:
        out = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip()).resolve()
    except Exception:
        pass
    return Path.cwd().resolve()


def is_text_candidate(name):
    if name == "SKILL.md" or name.startswith(".env"):
        return True
    suffix = os.path.splitext(name)[1].lower()
    if suffix in TEXT_SUFFIXES:
        return True
    return suffix == ""              # no extension but readable (A-07)


def read_text_capped(path):
    """Returns (text, truncated, sha256_hex). Binary files return (None, False, "")."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        raw = f.read(HEAD_BYTES if size > MAX_FILE_BYTES else MAX_FILE_BYTES)
    if b"\x00" in raw[:1024]:
        return None, False, ""
    import hashlib
    return raw.decode("utf-8", errors="replace"), size > MAX_FILE_BYTES, \
        hashlib.sha256(raw).hexdigest()


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def frontmatter_name(text):
    m = re.search(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    if not m:
        return None
    nm = re.search(r"^name:\s*['\"]?([^'\"\n]+)['\"]?\s*$", m.group(1), re.MULTILINE)
    return nm.group(1).strip() if nm else None


def scan_invisible(text, ranges):
    """CTX-03: returns list of (line, codepoint_label). ZWJ U+200D and a BOM at
    offset 0 are whitelisted (spec B-02)."""
    hits = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp == 0x200D or (cp == 0xFEFF and i == 0):
            continue
        for lo, hi in ranges:
            if lo <= cp <= hi:
                hits.append((line_of(text, i), "U+%04X" % cp))
                break
    return hits


def load_path_whitelist(project_root):
    """F-06 (spec C-05) whitelist.paths: prefixes exempt from SECRETS exposure findings only."""
    try:
        pol = json.loads((Path(project_root) / ".psl" / "policy.json").read_text(encoding="utf-8"))
        paths = (pol.get("whitelist") or {}).get("paths") or []
        return [p.replace("\\", "/").lstrip("./").lower() for p in paths if isinstance(p, str) and p.strip()]
    except Exception:
        return []


# ---------------------------------------------------------------- engine ----
def scan_directory(root, rules, quick=False, path_whitelist=None):
    """One os.walk(); each file checked against all applicable static rules.
    Returns (findings, stats). Dedup key: (file, rule_id, line)."""
    path_whitelist = path_whitelist or []
    compiled = [CompiledRule(r) for r in rules]
    static = [c for c in compiled if c.is_static()]
    findings = {}
    stats = {"files_seen": 0, "files_scanned": 0, "files_skipped": 0,
             "read_errors": 0, "symlinks_outside": 0, "truncated": 0}
    digests = []                                           # P0-6: subject digest inputs
    root = Path(root)
    root_str = str(root)

    def add(rule, rel, line, match, extra=None):
        key = (rel, rule.id, line)
        if key in findings:
            return
        findings[key] = {
            "rule_id": rule.id, "severity": rule.severity, "category": rule.category,
            "file": rel, "line": line, "target": "%s:%d" % (rel, line),
            "match": (match or "")[:120],
            "description": rule.description, "remediation": rule.remediation,
            "kind": extra or rule.type,
        }

    for dirpath, dirnames, filenames in os.walk(root_str, followlinks=True):
        rel_dir = os.path.relpath(dirpath, root_str).replace("\\", "/")
        depth = 0 if rel_dir == "." else rel_dir.count("/") + 1
        if depth >= MAX_DEPTH:
            dirnames[:] = []
        dirnames[:] = sorted(d for d in dirnames
                             if d not in EXCLUDED_DIRS
                             and (rel_dir + "/" + d).lstrip("./") not in EXCLUDED_REL_PATHS)
        dir_name = os.path.basename(dirpath)
        for fn in sorted(filenames):
            stats["files_seen"] += 1
            if quick and stats["files_seen"] > QUICK_MAX_FILES:
                break
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root_str).replace("\\", "/")
            if os.path.islink(full):
                try:
                    tgt = os.path.realpath(full)
                    if not tgt.lower().startswith(root_str.lower()):
                        stats["symlinks_outside"] += 1
                except Exception:
                    pass

            # Gate 2: sensitive-file exposure (SEC-xx file_patterns on the path)
            rel_l = rel.lower()
            for rule in static:
                if rule.category != "secrets":
                    continue
                if any(rel_l.startswith(p) for p in path_whitelist):
                    continue                              # F-06 whitelist.paths
                if rule.excluded(rel, fn):
                    continue
                for rx in rule.file_patterns:
                    m = rx.search(rel) or rx.search(fn)
                    if m:
                        add(rule, rel, 0, m.group(0), "exposure")
                        break

            if not is_text_candidate(fn):
                stats["files_skipped"] += 1
                continue
            try:
                text, truncated, fdigest = read_text_capped(full)
            except (IOError, OSError):
                stats["read_errors"] += 1
                continue
            if text is None:
                stats["files_skipped"] += 1
                continue
            stats["files_scanned"] += 1
            if fdigest:
                digests.append("%s  %s" % (rel, fdigest))
            if truncated:
                stats["truncated"] += 1

            for rule in static:
                if rule.category == "secrets" and not (rule.content_patterns and not rule.file_patterns):
                    # SEC-01..05 are path-matched above; only a pure-content
                    # secrets rule (SEC-06) takes the content path below.
                    continue
                if rule.category == "secrets" and any(rel_l.startswith(p) for p in path_whitelist):
                    continue                              # F-06 whitelist.paths covers SEC-06 findings too
                if rule.type == "file_content":
                    if rule.target == "SKILL.md" and fn != "SKILL.md":
                        continue
                    if rule.excluded(rel, fn):
                        continue
                    if rule.detection == "character_code_scan":
                        if quick and len(text) > QUICK_MAX_CHARSCAN:
                            continue
                        for line, label in scan_invisible(text, rule.ranges):
                            add(rule, rel, line, label, "invisible_char")
                    else:
                        for rx in rule.content_patterns:
                            for m in rx.finditer(text):
                                snippet = m.group(0)
                                if len(snippet) > 60:
                                    snippet = snippet[:40] + "...(" + str(len(m.group(0))) + " chars)"
                                add(rule, rel, line_of(text, m.start()), snippet)
                elif rule.type == "metadata_check" and fn == "SKILL.md":
                    name = frontmatter_name(text)
                    if name is not None and name.lower() != dir_name.lower():
                        add(rule, rel, 1, name + " != " + dir_name, "metadata")
                elif rule.content_patterns and not rule.file_patterns:
                    # 0.16.0: static content rules typed tool_call (SEC-06). The
                    # hook still guards Write/Edit live; this is the offline pass.
                    if rule.excluded(rel, fn):
                        continue
                    for rx in rule.content_patterns:
                        for m in rx.finditer(text):
                            snippet = m.group(0)
                            if len(snippet) > 60:
                                snippet = snippet[:40] + "...(" + str(len(m.group(0))) + " chars)"
                            add(rule, rel, line_of(text, m.start()), snippet)
    import hashlib
    subject_digest = None
    if digests:
        subject_digest = "sha256:" + hashlib.sha256(
            "\n".join(sorted(digests)).encode("utf-8")).hexdigest()
    return list(findings.values()), stats, [c.id for c in static], subject_digest


def calculate_score(findings):
    """Spec 2.6: base 100, critical -20, warning -5, clamp 0..100."""
    score = 100
    breakdown = {"critical": 0, "warning": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        breakdown[sev] = breakdown.get(sev, 0) + 1
        score -= SEVERITY_WEIGHT.get(sev, 0)
    score = max(0, min(100, score))
    if score >= 90:
        grade = "A (secure)"
    elif score >= 70:
        grade = "B (needs attention)"
    elif score >= 50:
        grade = "C (at risk)"
    else:
        grade = "D (unsafe)"
    return score, grade, breakdown


# ---------------------------------------------------------------- output ----
BAR = "\u2501" * 34




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

def render_text(result):
    lines = [BAR, " Antinel Security Scan Report",
             " %s | root: %s" % (result["generated_at"][:16].replace("T", " "), result["root"]),
             " files scanned: %d | skipped: %d | static rules: %d" % (
                 result["stats"]["files_scanned"], result["stats"]["files_skipped"],
                 len(result["rules_applied"])),
             BAR, ""]
    order = {"critical": 0, "warning": 1, "info": 2}
    fs = sorted(result["findings"], key=lambda f: (order.get(f["severity"], 9), f["file"], f["line"]))
    n = 0
    for sev, icon, title in (("critical", "\U0001F534", "CRITICAL"),
                             ("warning", "\U0001F7E1", "WARNING"),
                             ("info", "\U0001F535", "INFO")):
        group = [f for f in fs if f["severity"] == sev]
        if not group:
            continue
        lines.append(" %s %s (%d)" % (icon, title, len(group)))
        for f in group:
            n += 1
            loc = f["file"] + (":%d" % f["line"] if f["line"] else "")
            lines.append("  %d. [%s] %s" % (n, f["rule_id"], f["description"]))
            lines.append("     File: %s" % loc)
            if f.get("match"):
                lines.append("     Match: %s" % f["match"])
            if f.get("remediation"):
                lines.append("     \u2192 %s" % f["remediation"])
        lines.append("")
    if not fs:
        lines.append(" \U0001F7E2 No findings. Environment looks clean.")
        lines.append("")
    lines += [BAR, " Security Score: %d/100 %s" % (result["score"], result["grade"])]
    sb = result.get("score_basis", {})
    lines.append(" Score basis: 100 - 20 x %d critical - 5 x %d warning = %d (clamped to %d)" % (
        sb.get("critical", 0), sb.get("warning", 0), sb.get("raw", result["score"]), result["score"]))
    summ = result.get("summary", {})
    lang = _lang()
    nf = len(result["findings"])
    if lang == "zh":
        if nf:
            lines.append(" 结论：发现 %d 项问题（CRITICAL %d / WARNING %d / INFO %d），建议优先处理上方的 CRITICAL 项，每条附有处理建议。" % (
                nf, summ.get("critical", 0), summ.get("warning", 0), summ.get("info", 0)))
        else:
            lines.append(" 结论：未发现风险项，环境安全。")
    else:
        if nf:
            lines.append(" Conclusion: %d finding(s) (CRITICAL %d / WARNING %d / INFO %d). Address CRITICAL items first." % (
                nf, summ.get("critical", 0), summ.get("warning", 0), summ.get("info", 0)))
        else:
            lines.append(" Conclusion: no risks found, environment is safe.")
    if result.get("json_path"):
        lines.append(" JSON: %s" % result["json_path"])
    lines.append(BAR)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Antinel static security scan")
    ap.add_argument("--root", help="project root (default: git toplevel or cwd)")
    ap.add_argument("--rules", default=str(DEFAULT_RULES), help="rules JSON path")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--out", help="also write JSON result to this file")
    ap.add_argument("--quick", action="store_true", help="fast mode (file/size caps)")
    ap.add_argument("--min-severity", default="info", choices=["info", "warning", "critical"])
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    root = resolve_root(args.root)
    if not root.is_dir():
        sys.stderr.write("FATAL: root is not a directory: %s\n" % root)
        return 2
    try:
        rules = load_rules(args.rules, root)
    except Exception as e:
        sys.stderr.write("FATAL: cannot load rules: %s\n" % e)
        return 2

    findings, stats, applied, subject_digest = scan_directory(
        root, rules, quick=args.quick, path_whitelist=load_path_whitelist(root))
    order = {"info": 0, "warning": 1, "critical": 2}
    findings = [f for f in findings if order[f["severity"]] >= order[args.min_severity]]
    score, grade, breakdown = calculate_score(findings)
    result = {
        "schema": "antinel-scan-v1",
        "spec": "psl-vs-0.1",
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "root": str(root),
        "rules_applied": applied,
        "stats": stats,
        "subject": {"digest_alg": "sha256", "digest": subject_digest,
                    "files": stats["files_scanned"],
                    "note": "digest over (relpath, sha256) of every text file read; "
                            "re-running scan on an unchanged tree reproduces it byte-for-byte"},
        "discrimination": {"instrument": {"name": "antinel-scan-v1", "rules": len(applied)},
                           "score_basis": "static findings only; hook alerts are counted by report.py"},
        "findings": findings,
        "summary": breakdown,
        "score": score,
        "grade": grade,
        "score_basis": {"base": 100, "critical_weight": 20, "warning_weight": 5,
                        "critical": breakdown.get("critical", 0), "warning": breakdown.get("warning", 0),
                        "raw": 100 - 20 * breakdown.get("critical", 0) - 5 * breakdown.get("warning", 0),
                        "dedupe_key": "(rule_id, target)"},
    }
    json_path = None
    try:
        target = Path(args.out) if args.out else (root / ".psl" / "scan_last.json"
                                                  if (root / ".psl").is_dir() else None)
        if target:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
            json_path = str(target)
    except Exception:
        pass
    result["json_path"] = json_path

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
    else:
        print(render_text(result))
    return 1 if stats["read_errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
