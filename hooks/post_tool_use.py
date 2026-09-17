#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel Security Suite v0.21.0 - PostToolUse hook (Claude Code / ZCode compatible).

Input (stdin, one JSON line): {session_id, transcript_path, tool_name,
tool_input, tool_response}. PostToolUse cannot block an action that already
ran (spec A-01); it only records and alerts.

Responsibilities (spec table 2-3):
  1. append the execution record to .psl/audit/YYYY-MM-DD.jsonl (chained)
  2. inspect tool_response for leaked secrets (keys, tokens, private keys)
  3. observe canary markers CANARY-<skill>-<8hex> (spec C-01, gate g3 evidence)

Exit codes (spec A-10): 0 = recorded; 1 = record failed (host unaffected).
Python 3.10+, stdlib only, no network.

0.20.0 changes:
  - stats.json / bump_stats() removed: it was a read-modify-write counter with
    no lock (50.3% data loss measured on 09-16), and report.py never read it.
    A counter nobody reads that also computes wrong numbers serves only to
    provide a second, conflicting source of truth.
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
    """0.20.0 (P0-1): chained write — lock-acquire → lock-read prev → chain →
    append → release. Same pattern as pre_tool_use._append_chained(). This
    replaces the old code that read prev OUTSIDE the lock (racing with
    PreToolUse writes to the same file → same-parent forks in the audit log,
    audit finding E-06)."""
    lock = fn + ".lock"
    got_lock = False
    for _ in range(200):                                 # ~1s window (matches pre side)
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            got_lock = True
            break
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(lock) > 5:
                    os.remove(lock)                      # stale lock: steal it
            except OSError:
                pass
            time.sleep(0.005)
    try:
        # read prev INSIDE the lock (this is the fix — the old code read before locking)
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
        if not got_lock:
            rec["chain"] = "unlocked"                    # downgrade marker
        rec["prev"] = prev[-16:]
        canon = json.dumps({k: v for k, v in rec.items() if k != "hash"},
                           sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        rec["hash"] = hashlib.sha256((prev + canon).encode("utf-8")).hexdigest()
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        with open(fn, "a", encoding="utf-8") as f:
            f.write(line)
        # 0.18.0 day anchor (same as pre_tool_use)
        _touch_day_manifest(fn)
    finally:
        try:
            os.remove(lock)
        except OSError:
            pass


def _touch_day_manifest(fn):
    """0.18.0 (R-20): day anchor — same as pre_tool_use._touch_day_manifest."""
    try:
        size = os.path.getsize(fn)
        with open(fn, "rb") as f:
            f.seek(max(0, size - 4096))
            tail = f.read().decode("utf-8", errors="replace").rstrip("\r\n")
        last_line = tail.rsplit("\n", 1)[-1] if "\n" in tail else tail
        last_hash = json.loads(last_line).get("hash", "") if last_line else ""
        mpath = os.path.join(os.path.dirname(fn), "day_manifest.json")
        day = os.path.basename(fn)
        try:
            man = json.load(open(mpath, encoding="utf-8"))
            if not isinstance(man, dict):
                man = {}
        except Exception:
            man = {}
        prev = man.get(day) or {}
        if size >= int(prev.get("size", 0)):
            man[day] = {"size": size, "last_hash": last_hash,
                        "updated_at": datetime.now().isoformat(timespec="seconds")}
            tmp = mpath + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(man, f, ensure_ascii=False, indent=1)
            os.replace(tmp, mpath)
    except Exception:
        pass


def append_jsonl(record):
    d = audit_dir()
    os.makedirs(d, exist_ok=True)
    fn = os.path.join(d, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
    _chain_fields(fn, record)


# 0.20.0: bump_stats() removed entirely — see module docstring.
# The old stats.json file, if it exists on disk, is left alone (let it age out
# naturally; report.py never read it anyway).


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
        # 0.20.0: bump_stats() removed — it was a read-modify-write counter
        # with no lock (50.3% data loss measured) and zero consumers.
    except Exception:
        ok = False

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
