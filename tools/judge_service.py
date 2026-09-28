#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AgentState v0.33.0 - Resident Judge Service (D4 approved, B3).

Pre-loads pre_tool_use module (rules, compiled patterns, all logic) once.
Listens on 127.0.0.1:<ephemeral>. Each connection = one tool-call event.
Runs the SAME pre_tool_use.main() pipeline in-process (zero logic duplication)
by patching stdin/cwd. The hook becomes a ~20ms thin client instead of a
~146ms cold Python process.

Protocol: newline-delimited JSON over TCP 127.0.0.1.
  Request:  {"token": "...", "cwd": "<project_root>", "event_json": "<JSON string>"}
  Response: {"exit_code": 0|2, "stdout": "...", "stderr": "..."}

Security: 127.0.0.1 only + shared token. Same-privilege attacker class.
Fail-open: any error returns exit_code=0. The hook falls back to direct
execution if the service is unavailable.

Opt-in: policy global_settings.performance_mode = "resident" (default "hook").
"""
import io
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(PKG / "hooks"))

import pre_tool_use as ptu

_TOKEN = os.urandom(16).hex()
_HUB = Path(os.path.expanduser(os.environ.get("ANTINEL_HUB_DIR") or "~/.antinel"))


class _FakeStdin:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)
    def read(self, *a):
        return self.buffer.read(*a)


def _handle(conn):
    data = b""
    conn.settimeout(5)
    while b"\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return
        data += chunk
        if len(data) > (1 << 20):
            break
    try:
        req = json.loads(data.decode("utf-8", errors="replace"))
    except Exception:
        return
    if req.get("token") != _TOKEN:
        conn.sendall(json.dumps({"exit_code": 0, "stdout": "", "stderr": "AUTH"}).encode() + b"\n")
        return
    cwd = req.get("cwd", os.getcwd())
    event_json = req.get("event_json", "{}")
    old_cwd = os.getcwd()
    old_stdin = sys.stdin
    old_out = sys.stdout
    old_err = sys.stderr
    out_buf, err_buf = io.StringIO(), io.StringIO()
    exit_code = 0
    try:
        os.chdir(cwd)
        sys.stdin = _FakeStdin(event_json.encode("utf-8"))
        sys.stdout = out_buf
        sys.stderr = err_buf
        try:
            ptu.main()
        except SystemExit as e:
            exit_code = e.code if isinstance(e.code, int) else 0
        except Exception:
            exit_code = 1
            err_buf.write("HOOK_ERROR (judge caught)")
    finally:
        os.chdir(old_cwd)
        sys.stdin = old_stdin
        sys.stdout = old_out
        sys.stderr = old_err
    resp = json.dumps({"exit_code": exit_code,
                       "stdout": out_buf.getvalue(),
                       "stderr": err_buf.getvalue()}, ensure_ascii=False)
    try:
        conn.sendall(resp.encode("utf-8") + b"\n")
    except Exception:
        pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(5)
    _HUB.mkdir(parents=True, exist_ok=True)
    state = {"port": port, "token": _TOKEN, "pid": os.getpid(),
             "started": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
             "antinel_version": "0.33.0"}
    (_HUB / "judge.json").write_text(json.dumps(state, ensure_ascii=False, indent=1),
                                     encoding="utf-8", newline="\n")
    sys.stderr.write("judge: listening on 127.0.0.1:%d pid=%d\n" % (port, os.getpid()))
    while True:
        try:
            conn, addr = srv.accept()
            if addr[0] != "127.0.0.1":
                conn.close()
                continue
            _handle(conn)
            conn.close()
        except KeyboardInterrupt:
            break
        except Exception:
            pass
    srv.close()


if __name__ == "__main__":
    main()
