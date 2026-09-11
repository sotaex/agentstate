#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SessionStart hook: one-line protection banner, once per session.

additionalContext is injected into the conversation, so the AGENT knows
protection is active (and can tell the user); the exit code is always 0.
Set global_settings.session_banner=false in .psl/policy.json to silence."""
import json
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def _rule_count():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     os.pardir, "rules", "default.json")
    try:
        with open(p, "r", encoding="utf-8") as f:
            return len(json.load(f).get("rules", []))
    except Exception:
        return "?"


def _banner_quiet():
    for base in (os.getcwd(), os.path.dirname(os.getcwd())):
        p = os.path.join(base, ".psl", "policy.json")
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    gs = (json.load(f).get("global_settings") or {})
                return gs.get("session_banner") is False
            except Exception:
                return False
    return False


def main():
    # 0.17.0 (P-A5): session heartbeat. A session that leaves NO trace anywhere
    # is indistinguishable from "the hook never ran" -- the exact blindness that
    # audit finding N5 measured. Best-effort: a failed heartbeat write never
    # breaks the banner (fail-open, A-08).
    try:
        d = os.path.join(os.getcwd(), ".psl", "audit")
        os.makedirs(d, exist_ok=True)
        from datetime import datetime
        fn = os.path.join(d, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
        with open(fn, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": datetime.now().astimezone().isoformat(timespec="seconds"),
                "type": "session_start", "tool": "-", "session": "banner",
                "decision": "allow", "severity": "none",
                "reason": "SessionStart heartbeat (hook ran; banner shown)"},
                ensure_ascii=False) + "\n")
    except Exception:
        pass
    if _banner_quiet():
        return 0
    n = _rule_count()
    msg = ("Antinel Security Suite 正在守护此项目：" + str(n) + " 条规则 · 4 道闸门 · "
           "危险操作将被拦截并留痕（审计 .psl/audit）。被拦截的操作重试无效；"
           "放行见 .psl/policy.json。")
    try:
        print(json.dumps({"additionalContext": msg}, ensure_ascii=False))
    except Exception:
        pass
    return 0


sys.exit(main())
