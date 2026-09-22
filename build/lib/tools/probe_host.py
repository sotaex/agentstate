#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Host-protocol probe (U-47 evidence collector).

Register this as the PreToolUse hook of an UNVERIFIED host (Qoder / TRAE), trigger ONE
tool call in that host, then send the captured JSON back for adapter profile completion.

  Qoder (candidate path, confirm in its docs/harness):  .qoder/settings.json
  TRAE (candidate path, confirm on device):             .trae/settings.json

Registration JSON (same shape as Claude Code):
  {"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
      {"type": "command", "command": "<python> <abs>/probe_host.py --tag qoder", "timeout": 10}]}}]}

The probe NEVER blocks (always exit 0) and captures: raw stdin bytes, argv, cwd,
env markers. Captures land in .psl/probe/<tag>-<n>.json next to the project.
"""
import json
import os
import sys
from datetime import datetime


def main():
    tag = "host"
    if "--tag" in sys.argv:
        tag = sys.argv[sys.argv.index("--tag") + 1]
    try:
        raw = sys.stdin.buffer.read()
    except Exception:
        raw = b""
    try:
        event = json.loads(raw.decode("utf-8", errors="replace"))
        keys = {"top": sorted(event.keys()),
                "tool_input_keys": sorted((event.get("tool_input") or {}).keys()),
                "tool_name": event.get("tool_name")}
    except Exception:
        event, keys = None, {"top": None, "parse_error": True}
    rec = {"captured_at": datetime.now().astimezone().isoformat(timespec="seconds"),
           "tag": tag, "argv": sys.argv[1:], "cwd": os.getcwd(),
           "env_markers": {k: os.environ[k] for k in os.environ
                           if any(s in k.upper() for s in ("QODER", "TRAE", "CLAUDE", "ZCODE"))},
           "keys": keys, "raw_len": len(raw), "raw": raw.decode("utf-8", errors="replace")[:4000]}
    try:
        d = os.path.join(os.getcwd(), ".psl", "probe")
        os.makedirs(d, exist_ok=True)
        n = 1
        while os.path.isfile(os.path.join(d, "%s-%d.json" % (tag, n))):
            n += 1
        out = os.path.join(d, "%s-%d.json" % (tag, n))
        with open(out, "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=1)
        sys.stderr.write("probe captured: %s\n" % out)
    except Exception:
        pass
    sys.exit(0)                                     # never block anything


if __name__ == "__main__":
    main()
