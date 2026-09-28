#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel Security Suite v0.27.0 - PostToolUse hook (Claude Code / ZCode compatible).

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

0.22.0 changes (三问三答 v1.0, A5/B1/C1):
  - C1: file_state_after for structured writes (Write/Edit) -- sha256+size of
    the target AFTER the tool ran; joins to pre_tool_use's file_state_before
    via the shared content_digest. Hashes only, never content.
  - B1: exit_code extracted from tool_response when the host exposes one.
    Facts only: unknown stays null -- absent evidence is not invented.
    (Durations are derived by report.py from pre/post ts pairs.)

0.23.0 changes (三问三答 v1.0, A1/A2 -- the cost ledger):
  - transcript_reader.py (adapter layer, package root) harvests token FACTS
    (model / input / output / cache_read / total) from the host transcript
    incrementally (byte offset state in .psl/state/). Each harvest with new
    entries appends a chained `usage_delta` record. Cost is NEVER written
    here -- tokens are facts, cost is derived (report/session DNA only).
    The transcript path is stored as a sha256 tag in the ledger, never raw.
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

# ------------------------------------------------------ 0.22.0 (B1/C1) helpers --
# Canonical write-tool names: the host sends raw names (MultiEdit, NotebookEdit);
# pre_tool_use aliases them (TOOL_ALIASES) before its records carry "tool". The
# content_digest is computed over the RAW tool_input on both sides either way,
# so the pre/post join key is unaffected by aliasing.
_TOOL_CANON = {"MultiEdit": "Edit", "ApplyPatch": "Edit", "NotebookEdit": "Write"}
WRITE_TOOLS = ("Write", "Edit")
FILE_STATE_MAX_BYTES = 1_000_000         # same cap and recipe as pre_tool_use
_EXIT_CODE_KEYS = ("exit_code", "exitCode", "returncode", "returnCode", "code")


def file_state_snapshot(path):
    """C1 after-state. Same deterministic outcomes as pre_tool_use:
      {"hash": "sha256:...", "size": n} | {"hash": "absent"}
      | {"hash": "too_large", "size": n} | {"hash": "unreadable"}
    """
    try:
        if not path or not os.path.isfile(path):
            return {"hash": "absent"}
        size = os.path.getsize(path)
        if size > FILE_STATE_MAX_BYTES:
            return {"hash": "too_large", "size": size}
        with open(path, "rb") as f:
            return {"hash": "sha256:" + hashlib.sha256(f.read()).hexdigest(), "size": size}
    except Exception:
        return {"hash": "unreadable"}


def extract_exit_code(tool_response):
    """B1: best-effort numeric exit code from the tool response. Dict shapes are
    probed on known keys (top level, then result/output wrappers); string
    responses get one bounded regex. Returns None when the host exposes
    nothing -- the record keeps the null rather than guessing."""
    tr = tool_response
    if isinstance(tr, dict):
        for k in _EXIT_CODE_KEYS:
            v = tr.get(k)
            if isinstance(v, int) and not isinstance(v, bool):
                return v
        for wrap in ("result", "output"):
            inner = tr.get(wrap)
            if isinstance(inner, dict):
                for k in _EXIT_CODE_KEYS:
                    v = inner.get(k)
                    if isinstance(v, int) and not isinstance(v, bool):
                        return v
    elif isinstance(tr, str):
        m = re.search(r"(?:exit\s*code|exited with(?: code)?|returncode)\s*[:=]?\s*(\d{1,4})",
                      tr, re.I)
        if m:
            return int(m.group(1))
    return None


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


def _chain_fields(fn, rec):
    """0.20.0 (P0-1) → C-1 (v0.28)：实现收拢至 audit_chain（sidecar 策略）。"""
    _rec, got = _ac().append_chained(fn, rec, on_timeout="sidecar")
    if got:
        _ac().touch_day_manifest(fn)


def _touch_day_manifest(fn):
    """R-20 日锚（链外副本，检出尾部删除）。"""
    _ac().touch_day_manifest(fn)
def append_jsonl(record):
    d = audit_dir()
    os.makedirs(d, exist_ok=True)
    fn = os.path.join(d, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
    _chain_fields(fn, record)


# ------------------------------------------------- 0.23.0 (A1/A2) usage chain --
def _import_transcript_reader():
    """transcript_reader.py sits at the package root; this hook may run from
    the source tree (same dir) or an installed layout (<pkg>/hooks)."""
    try:
        parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if parent not in sys.path:
            sys.path.insert(0, parent)
        import transcript_reader
        return transcript_reader
    except Exception:
        try:
            import transcript_reader
            return transcript_reader
        except Exception:
            return None


def record_usage_delta(event, session_id):
    """Harvest new token facts from the transcript and append one chained
    `usage_delta` record. Every failure mode is silent (fail-open, A-08):
    a billing side-channel must never break or distort the security hook."""
    try:
        tp = event.get("transcript_path") or ""
        if not tp:
            return
        # 定稿方案 v1.1 控制感：消耗采集总开关（global_settings.usage_collect=false 关）
        try:
            _pp = os.path.join(os.getcwd(), ".psl", "policy.json")
            with open(_pp, encoding="utf-8") as _f:
                _gs = (json.load(_f).get("global_settings") or {})
            if _gs.get("usage_collect") is False:
                return
        except Exception:
            pass
        tr = _import_transcript_reader()
        if tr is None:
            return
        state_dir = os.path.join(os.getcwd(), ".psl", "state")
        entries, meta = tr.harvest_delta(tp, state_dir)
        if not entries:
            return
        rec = {
            "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "type": "usage_delta",
            "tool": "-",
            "session": session_id,
            "host": "",
            "source": {"path_tag": (meta or {}).get("path_tag"),
                       "scope": (meta or {}).get("scope"),
                       "reset": bool((meta or {}).get("reset")),
                       "bytes_read": (meta or {}).get("bytes_read", 0),
                       "deduped": (meta or {}).get("deduped", 0),
                       "usage_source": "transcript"},
            "entries": entries,
        }
        append_jsonl(rec)
        _accumulate_budget_state(session_id, entries)
    except Exception:
        pass


def _accumulate_budget_state(session_id, entries):
    """v0.27.0 (BUDGET-01 数据底座): 会话/项目日 两档 token 累计，供
    PreToolUse 预算执法读取。best-effort：预算执法基于已记录的事实，
    状态缺失时 PreToolUse fail-open（不执法也不谎报）。"""
    try:
        import re as _re
        state_dir = os.path.join(os.getcwd(), ".psl", "state")
        os.makedirs(state_dir, exist_ok=True)
        p = os.path.join(state_dir, "session_usage.json")
        try:
            st = json.load(open(p, encoding="utf-8"))
        except Exception:
            st = {}
        day = datetime.now().strftime("%Y-%m-%d")
        din = sum(e.get("input_tokens") or 0 for e in entries)
        dout = sum(e.get("output_tokens") or 0 for e in entries)
        s = st.setdefault("sessions", {}).setdefault(session_id or "?", {})
        s["in"] = s.get("in", 0) + din
        s["out"] = s.get("out", 0) + dout
        s["updated_at"] = datetime.now().isoformat(timespec="seconds")
        d = st.setdefault("daily", {}).setdefault(day, {})
        d["in"] = d.get("in", 0) + din
        d["out"] = d.get("out", 0) + dout
        d["updated_at"] = s["updated_at"]
        # 防膨胀：只留最近 20 个会话与 7 个日键
        ss = st["sessions"]
        if len(ss) > 20:
            for k in sorted(ss, key=lambda k: ss[k].get("updated_at", ""))[:-20]:
                ss.pop(k, None)
        dd = st["daily"]
        if len(dd) > 7:
            for k in sorted(dd)[:-7]:
                dd.pop(k, None)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f, ensure_ascii=False, indent=1)
        os.replace(tmp, p)
    except Exception:
        pass


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

    # 0.22.0 (B1/C1): exit code when the host exposes one; after-state for
    # structured writes. Joined to the pre record via the shared content_digest.
    record["exit_code"] = extract_exit_code(event.get("tool_response"))
    _canon = _TOOL_CANON.get(tool_name, tool_name)
    if _canon in WRITE_TOOLS:
        _fp = tool_input.get("file_path") or tool_input.get("path") or ""
        if _fp:
            record["file_state_after"] = file_state_snapshot(_fp)

    ok = True
    try:
        append_jsonl(record)
        # 0.20.0: bump_stats() removed — it was a read-modify-write counter
        # with no lock (50.3% data loss measured) and zero consumers.
    except Exception:
        ok = False

    # 0.23.0 (A1/A2): token facts from the transcript into the chain, after the
    # security record -- the security ledger must never wait on the billing one.
    record_usage_delta(event, session_id)

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
