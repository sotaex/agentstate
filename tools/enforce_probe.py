#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""AgentState v0.30.0 - enforcement self-probe (E-3 closure, signaling half).

Why this exists (THREAT_MODEL E-3): the guardrail's deny signal rested on
exit 2 alone; a host that stopped honoring it would silently degrade every
block into an allow -- no error, no drop in hook invocations, and the audit
chain would keep recording antinel's DECISION, not the world's OUTCOME. This
probe closes the signaling half of that hole:

  1. runs hooks/pre_tool_use.py (the REAL hook) with a synthetic event that
     must be blocked (Read of a *.env path -- SEC-01, critical),
  2. asserts the deny on every channel the host contract expects: exit code 2,
     stdout deny contract (hookSpecificOutput.permissionDecision="deny") and/or
     legacy {"decision":"block"} -- per the armed deny_stdout policy mode and
     the detected host tag,
  3. chains ONE `enforcement_probe` record (truthful, pass or fail) into the
     project audit chain, mirrored to the host-level audit dir.

What this probe proves: the hook script still loads rules, decides, and
signals deny on every channel. What it CANNOT prove: that the HOST honors the
signal -- that half is covered by real-traffic detection (post_tool_use
`enforcement_gap`), because a probe cannot reach inside the host's decision
loop. Together the two halves close E-3.

Scheduling: post_tool_use spawns this script detached once per
global_settings.probe_interval_hours (default 24; 0 disables). Manual run:
    python -m tools.enforce_probe [--root <project>]
Exit: 0 = probe passed (or skipped for a benign reason); 1 = probe FAILED
(the gate is not signaling -- morning report and the owner are told).

Python 3.10+, stdlib only, no network. Fail-open: every internal error is
recorded as a failed/unknown probe, never raised into the host.
"""
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

_ANTINEL_VERSION = "0.30.0"


def _pkg_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ac():
    """audit_chain.py is the single chaining authority (C-1); same import
    fallback pattern as the hooks (may run from tools/ or an installed layout)."""
    global _AUDIT_CHAIN
    if _AUDIT_CHAIN is None:
        try:
            import audit_chain as _m
        except ImportError:
            parent = _pkg_root()
            if parent not in sys.path:
                sys.path.insert(0, parent)
            import audit_chain as _m
        _AUDIT_CHAIN = _m
    return _AUDIT_CHAIN


_AUDIT_CHAIN = None


def _host_audit_dir():
    if os.environ.get("ANTINEL_HOST_MIRROR") == "0":
        return None
    cd = os.environ.get("WORKBUDDY_CONFIG_DIR")
    base = os.path.expanduser(cd) if cd else os.path.join(os.path.expanduser("~"), ".workbuddy")
    return os.path.join(base, "antinel-audit")


def _chain_probe_record(root, rec):
    """Chain the probe record into the project audit (+ host-level mirror).
    Same recipe as every other record: audit_chain.append_chained + day anchor."""
    try:
        d = os.path.join(root, ".psl", "audit")
        os.makedirs(d, exist_ok=True)
        fn = os.path.join(d, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
        _ac().append_chained(fn, rec)
        _ac().touch_day_manifest(fn)
        mirror = _host_audit_dir()
        if mirror:
            os.makedirs(mirror, exist_ok=True)
            mfn = os.path.join(mirror, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
            _ac().append_locked(mfn, json.dumps(rec, ensure_ascii=False) + "\n")
            _ac().touch_day_manifest(mfn)
        return True
    except Exception:
        return False


def _notify_owner_failure(root, detail):
    """Probe failure is one of the few events worth waking the owner for:
    'the gate is not signaling' must not live only in a log file. Reuses the
    pre-hook notifier (single implementation); failures stay silent.

    ★★ 0.35.3 修（创始人 2026-10-07 实测「右下角冒泡又出现了」）：
      本函数原来**无条件弹一次**，完全不走 `notice_gate` 降噪。
      而哨兵每轮都会跑探针 ⇒ 一旦门临时不符（比如改了
      `host_shield.py` 而 manifest 还没刷新），就**每轮弹一次**，
      弹到人开始无视为止 —— 与 0.35.3 已经治过的那条
      「一条常用规则反复拦 ⇒ 气泡刷屏」是**同一个病**，
      只是换了个调用点。
      ⇒ 现在也过 `notice_gate`：**同一条探针失败一天只敲一次门**，
        其次只留痕（Antinel 监理台账里翻得到）。
        探针失败是 Antinel 自己没修好，**更不该拿气泡去轰炸用户**。
    """
    try:
        hooks_dir = os.path.join(_pkg_root(), "hooks")
        if hooks_dir not in sys.path:
            sys.path.insert(0, hooks_dir)
        import pre_tool_use as _pre
        gate = getattr(_pre, "notice_gate", None)
        if gate is not None:
            # key 固定用 probe + 失败原因片段 ⇒ 同因一天一次；
            # 换了原因就算新事，值得再敲一次。
            if gate("ENFORCEMENT-PROBE|FAIL",
                    ("%s|%s" % (os.path.basename(root), detail))[:60]):
                return                      # 今天已经敲过 ⇒ 静默
        _pre.notify_owner("Antinel 自检失败：拦截信号未生效",
                          "enforcement_probe FAIL @ %s | %s | 护栏可能已退化为纯记录模式，"
                          "请重跑 probe_host.py 并核对宿主钩子协议" % (os.path.basename(root), detail))
    except Exception:
        pass


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = sys.argv[1:]
    root = os.getcwd()
    if "--root" in args:
        root = os.path.abspath(args[args.index("--root") + 1])
    if not os.path.isdir(os.path.join(root, ".psl")):
        # Not an installed project -- probing makes no claim about a machine
        # where the guardrail was never installed. Skip honestly, exit 0.
        print("enforce-probe: no .psl under %s -- nothing to probe (skip)" % root)
        return 0

    pkg = _pkg_root()
    pre = os.path.join(pkg, "hooks", "pre_tool_use.py")
    if not os.path.isfile(pre):
        rec_ok, detail = False, "pre_tool_use.py not found at %s" % pre
    else:
        # Detect the host tag the same way the hook will (cwd markers first).
        try:
            hooks_dir = os.path.join(pkg, "hooks")
            if hooks_dir not in sys.path:
                sys.path.insert(0, hooks_dir)
            import pre_tool_use as _pre
            cwd0 = os.getcwd()
            os.chdir(root)
            try:
                host_tag = _pre.detect_host_tag()
            finally:
                os.chdir(cwd0)
        except Exception:
            host_tag = "generic"
        # Which stdout channels does the armed policy expect?
        try:
            pol = json.load(open(os.path.join(root, ".psl", "policy.json"), encoding="utf-8"))
        except Exception:
            pol = {}
        deny_mode = str((pol.get("global_settings") or {}).get("deny_stdout", "dual")).lower()
        if deny_mode not in ("dual", "legacy", "quiet"):
            deny_mode = "dual"

        # Synthetic event that MUST be blocked: SEC-01 (critical) fires on any
        # Read of a *.env path. The file does not exist and needs not exist --
        # the block happens at the tool-call layer, before any filesystem read.
        ev = {"session_id": "antinel-probe", "transcript_path": "",
              "tool_name": "Read", "tool_input": {"file_path": os.path.join(root, "__antinel_probe__.env")}}
        # ANTINEL_PROBE=1 puts the hook in side-effect-free mode; ANTINEL_CONFIG
        # isolates the trust boundary the same way the verification suite does.
        iso = os.path.join(root, ".psl", "antinel_isolated.json")
        try:
            with open(iso, "w", encoding="utf-8") as f:
                json.dump({"workspace_roots": []}, f, ensure_ascii=False)
        except Exception:
            pass
        env = dict(os.environ)
        env["ANTINEL_PROBE"] = "1"
        env["ANTINEL_CONFIG"] = iso
        env["ANTINEL_HOST_MIRROR"] = "0"
        t0 = time.time()
        try:
            p = subprocess.run([sys.executable, pre], cwd=root,
                               input=json.dumps(ev, ensure_ascii=False),
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=30, env=env,
                               creationflags=0x08000000 if os.name == "nt" else 0)
            rc, out, err = p.returncode, p.stdout or "", p.stderr or ""
        except Exception as e:
            rc, out, err = -1, "", "probe subprocess error: %r" % (e,)
        dur = int((time.time() - t0) * 1000)

        decided = "block"
        for ln in err.splitlines():
            if ln.startswith("ANTINEL_PROBE decision="):
                decided = ln.split("=", 1)[1].strip()
                break

        # 0.33.1：这份"走 stdout 双通道的宿主名单"此前是**第三份**硬编码副本
        # （另两份在 pre_tool_use._deny_payload 与旧 post 钩子里）。归因修好后
        # workbuddy 被正确识别，三个副本立刻给出三种结论：钩子发了契约，探针
        # 却要求 stdout 为空 ⇒ ok=false（实测）。改为向钩子的唯一来源取值。
        try:
            dual_hosts = _pre._dual_stdout_hosts()
        except Exception:
            dual_hosts = getattr(_pre, "DUAL_STDOUT_HOSTS", ("claude-code", "generic"))
        if host_tag in dual_hosts and deny_mode != "quiet":
            contract = False
            legacy = False
            try:
                j = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
                legacy = (j.get("decision") == "block")
                hso = (j.get("hookSpecificOutput") or {})
                contract = (hso.get("permissionDecision") == "deny"
                            and hso.get("hookEventName") == "PreToolUse")
            except Exception:
                pass
            want = {"dual": (contract and legacy), "legacy": legacy, "quiet": True}[deny_mode]
            channel = {"dual": "contract+legacy+exit2", "legacy": "legacy+exit2",
                       "quiet": "exit2"}[deny_mode]
            ok = (rc == 2 and decided == "block" and want)
            detail = ("rc=%d decided=%s contract=%s legacy=%s mode=%s" % (rc, decided, contract, legacy, deny_mode))
        else:
            # stdout-quiet hosts (ZCode strict schema): exit 2 + stderr + empty stdout
            ok = (rc == 2 and decided == "block" and out.strip() == "")
            channel = "exit2+stderr"
            detail = ("rc=%d decided=%s stdout_empty=%s mode=%s"
                      % (rc, decided, str(out.strip() == ""), deny_mode))

        rec = {"ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
               "type": "enforcement_probe", "tool": "-", "session": "antinel-probe",
               "host": host_tag, "probe": "pre_tool_use", "expected": "block",
               "got": ("block" if rc == 2 else ("allow(rc=%d)" % rc)), "exit_code": rc,
               "stdout_channel": channel, "deny_mode": deny_mode,
               "antinel_version": _ANTINEL_VERSION, "duration_ms": dur,
               "decision": "alert" if not ok else "allow",
               "severity": "critical" if not ok else "none",
               "ok": bool(ok), "reason": detail}
        written = _chain_probe_record(root, rec)
        if not written:
            rec_ok, detail = False, detail + " | PROBE RECORD WRITE FAILED (AUDIT_WRITE_FAILED class)"
        else:
            rec_ok = bool(ok)
        if not rec_ok:
            try:
                sys.stderr.write("[Antinel][E-3] ENFORCEMENT_PROBE FAIL: %s\n" % detail)
            except Exception:
                pass
            _notify_owner_failure(root, detail)
        else:
            try:
                sys.stderr.write("[Antinel][E-3] enforcement probe OK (%s, %d ms)\n" % (channel, dur))
            except Exception:
                pass
        print("enforce-probe: ok=%s %s" % (str(rec_ok).lower(), detail))
        return 0 if rec_ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:
        try:
            sys.stderr.write("enforce_probe error (ignored): %r\n" % (e,))
        except Exception:
            pass
        sys.exit(0)          # fail-open: the probe must never break the host
