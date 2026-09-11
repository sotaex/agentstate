#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel Security Suite v0.17.0 - PostToolUse hook (Claude Code / ZCode compatible).

Input (stdin, one JSON line): {session_id, transcript_path, tool_name,
tool_input, tool_response}. PostToolUse cannot block an action that already
ran (spec A-01); it only records and alerts.

Responsibilities (spec table 2-3):
  1. append the execution record to .psl/audit/YYYY-MM-DD.jsonl
  2. inspect tool_response for leaked secrets (keys, tokens, private keys)
  3. observe canary markers CANARY-<skill>-<8hex> (spec C-01, gate g3 evidence)
  4. keep per-day counters so report.py can print operation statistics

Exit codes (spec A-10): 0 = recorded; 1 = record failed (host unaffected).
Python 3.10+, stdlib only, no network.
"""
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

MAX_RESPONSE_CHARS = 200_000          # inspect at most this much output text

OUTPUT_SENSITIVE_PATTERNS = [
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("OpenAI-style secret key", r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("Slack token", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("Private key block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("Credential assignment",
     r"(?i)\b(api[_\-]?key|secret[_\-]?key|access[_\-]?token|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+=]{12,}"),
]

CANARY_RE = re.compile(r"\bCANARY-[A-Za-z0-9_\-]+-[0-9a-f]{8}\b")


def response_text(tool_response):
    """Flatten whatever the host sent as tool_response into text."""
    if tool_response is None:
        return ""
    if isinstance(tool_response, str):
        return tool_response[:MAX_RESPONSE_CHARS]
    try:
        return json.dumps(tool_response, ensure_ascii=False)[:MAX_RESPONSE_CHARS]
    except Exception:
        return str(tool_response)[:MAX_RESPONSE_CHARS]


def find_sensitive(text):
    hits = []
    for label, pat in OUTPUT_SENSITIVE_PATTERNS:
        try:
            m = re.search(pat, text)
        except re.error:
            continue
        if m:
            token = m.group(0)
            masked = token[:6] + "..." + token[-3:] if len(token) > 12 else "***"
            hits.append({"label": label, "sample": masked})
    return hits


MASK_PATTERNS = [
    r"\bsk-[A-Za-z0-9_\-]{8,}",
    r"\bgh[pousr]_[A-Za-z0-9]{8,}",
    r"\bAKIA[0-9A-Z]{8,}",
    r"\bxox[baprs]-[A-Za-z0-9\-]{8,}",
    r"\bAIza[0-9A-Za-z_\-]{8,}",
    r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?[A-Za-z0-9_\-.=/+]{8,}",
    r"(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_/+=\-]{8,}",
]


def mask_secrets(text):
    for pat in MASK_PATTERNS:
        try:
            text = re.sub(pat, lambda m: m.group(0)[:4] + "[已脱敏]", text)
        except re.error:
            continue
    return text


def content_digest(tool_name, tool_input):
    """Spec 2.8: sha256 over canonical JSON of {"tool_name","tool_input"} (same recipe as pre_tool_use)."""
    try:
        canon = json.dumps({"tool_name": tool_name, "tool_input": tool_input},
                           sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()
    except Exception:
        return ""


def audit_dir():
    return os.path.join(os.getcwd(), ".psl", "audit")


def _chain_fields(fn, rec):
    """L10 audit chain (same recipe as pre_tool_use)."""
    prev = ""
    try:
        with open(fn, "r", encoding="utf-8", errors="replace") as f:
            for l in f:
                l = l.strip()
                if not l:
                    continue
                try:
                    h = json.loads(l).get("hash")
                    if h:
                        prev = h
                except Exception:
                    pass
    except Exception:
        pass
    rec = dict(rec)
    rec["prev"] = prev[-16:]
    canon = json.dumps({k: v for k, v in rec.items() if k != "hash"},
                       sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    rec["hash"] = hashlib.sha256((prev + canon).encode("utf-8")).hexdigest()
    return rec


def append_jsonl(record):
    d = audit_dir()
    os.makedirs(d, exist_ok=True)
    fn = os.path.join(d, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
    record = _chain_fields(fn, record)
    line = json.dumps(record, ensure_ascii=False) + "\n"
    lock = fn + ".lock"
    for _ in range(50):                                  # A8: serialise concurrent appends
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            break
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(lock) > 5:
                    os.remove(lock)                      # stale lock: steal it
            except OSError:
                pass
            time.sleep(0.002)
    try:
        with open(fn, "a", encoding="utf-8") as f:
            f.write(line)
    finally:
        try:
            os.remove(lock)
        except OSError:
            pass


def bump_stats(tool_name, alerted):
    """Tiny per-day counter file; corruption is tolerated (rewritten).

    0.17.0 (P-B8 / audit C-3): the sensitive-output counter is renamed
    `alerts` -> `post_alerts`, because it counts ONLY PostToolUse
    sensitive-output alerts -- while PreToolUse degrades (ro_cmd) and
    warning-level hits also land `action: "alert"` in the log. One name used
    to carry two quantities (audit finding N19); now the name says which."""
    p = os.path.join(audit_dir(), "stats.json")
    try:
        with open(p, "r", encoding="utf-8") as f:
            stats = json.load(f)
    except Exception:
        stats = {}
    day = datetime.now().strftime("%Y-%m-%d")
    dstat = stats.setdefault(day, {"total": 0, "by_tool": {}, "post_alerts": 0})
    dstat["total"] = int(dstat.get("total", 0)) + 1
    by_tool = dstat.setdefault("by_tool", {})
    by_tool[tool_name or "unknown"] = int(by_tool.get(tool_name or "unknown", 0)) + 1
    if alerted:
        # legacy key migrated on first write; new name is the only live one
        dstat["post_alerts"] = int(dstat.pop("alerts", dstat.get("post_alerts", 0))) + 1
    if len(stats) > 90:                                  # A7: keep the newest 90 days
        for k in sorted(stats.keys())[:len(stats) - 90]:
            stats.pop(k, None)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)


def main():
    try:  # utf-8 out determinism (host decoders expect utf-8)
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")   # fix: text mode decoded UTF-8 as GBK (live-smoke finding)
    try:
        event = json.loads(raw)
    except Exception:
        try:
            sys.stderr.write("INVALID_INPUT\n")
        except Exception:
            pass
        sys.exit(0)

    tool_name = event.get("tool_name", "") or ""
    tool_input = event.get("tool_input", {}) or {}
    session_id = event.get("session_id", "") or ""
    text = response_text(event.get("tool_response"))

    sensitive = find_sensitive(text)
    canaries = sorted(set(CANARY_RE.findall(text)))

    record = {
        "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "type": "post_tool_use",
        "tool": tool_name,
        "input": {
            "command": mask_secrets((tool_input.get("command", "") or ""))[:500],
            "file_path": tool_input.get("file_path") or tool_input.get("path") or "",
        },
        "session": session_id,
        "host": "",
        "content_digest": content_digest(tool_name, tool_input),
        "response_digest": "sha256:" + hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
        "response_chars": len(text),
        "rules_hit": ["OUT-01"] if sensitive else [],
        "severity": "warning" if sensitive else "none",
        "action": "alert" if sensitive else "record",
        "sensitive_output": sensitive,
        "canaries_observed": canaries,
    }

    ok = True
    try:
        append_jsonl(record)
        bump_stats(tool_name, bool(sensitive))
    except Exception:
        ok = False                                   # A-08: never affect the host

    if sensitive:
        try:
            labels = ", ".join(h["label"] for h in sensitive)
            sys.stderr.write("[OUT-01] 提醒：工具输出包含疑似密钥（%s），已记录审计；请轮换相关凭证\n" % labels)
        except Exception:
            pass
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        try:
            sys.stderr.write("HOOK_ERROR (ignored)\n")
        except Exception:
            pass
        sys.exit(1)
