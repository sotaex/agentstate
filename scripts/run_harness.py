#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-run the verification suite against THIS package and record psl/judgment.json (psl-vs-0.1).
Usage: python scripts/run_harness.py        (third parties: any failed re-run supersedes the shipped record)

0.16.0 (v1.40 §5.14 minimal publishable subset): the record now carries the five
hard-precondition fields -- status (V7), scope (V8), discrimination (V1),
platformSpec (V5), objectOwnership (V12) -- and appends one idempotent row to
the append-only ledger psl/verdict-ledger.jsonl (V6, row 1 = this self-verdict).
Third-party status check: python tools/antinel_verify.py (A-8) -- it DERIVES
current/superseded from the digests and never edits this record.
"""
import hashlib, json, os, platform, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
OUT = PKG / "psl" / "judgment.json"
LEDGER = PKG / "psl" / "verdict-ledger.jsonl"
COVERED = ["rules/default.json", "hooks/pre_tool_use.py", "hooks/post_tool_use.py",
           "scripts/scan.py", "scripts/install.py", "scripts/report.py",
           "scripts/verification_tests.py"]

def sha(p):
    return "sha256:" + hashlib.sha256(Path(p).read_bytes()).hexdigest()

def main():
    env = dict(os.environ); env["ANTINEL_PKG"] = str(PKG)
    t0 = time.time(); started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    proc = subprocess.run([sys.executable, str(PKG / "scripts" / "verification_tests.py")],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    total = passed = 0
    for line in proc.stdout.splitlines():
        if line.startswith("PASS ") or line.startswith("FAIL "):
            total += 1; passed += line.startswith("PASS ")
    verdict = "PASS" if proc.returncode == 0 and total and passed == total else "FAIL"
    digests = {rel: sha(PKG / rel) for rel in COVERED}
    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    rec = {
        "spec": "psl-vs-0.1",
        "card_id": "antinel-security-suite",
        "skill": "antinel-security",
        "skill_version": "0.16.0",
        "verdict": verdict,
        # V7: status is a status BIT, appended info; this file itself is never
        # edited after publication. A third party derives current/superseded
        # with tools/antinel_verify.py; checkedAt is when WE last derived it.
        "status": {"value": "current", "derivation": "auto", "reason": None,
                   "checkedAt": now,
                   "note": "re-derive any time: python tools/antinel_verify.py"},
        # V8: scope -- what this verdict covers and, just as loudly, what it does not.
        "scope": {"covered": COVERED,
                  "notCovered": ["runtime behaviour of the monitored host",
                                 "files outside the seven digests above",
                                 "the security posture of your machine or environment",
                                 "dynamic tool traffic (that is the hooks\' job, not this record\'s)"]},
        # V1: the gauge behind the number. assertions 108/108 without a named
        # instrument is exactly the drift shape this field exists to prevent.
        "discrimination": {"instrument": {"name": "scripts/verification_tests.py",
                                          "object": "this package (the " + str(len(COVERED)) + " digested files)",
                                          "runner": "scripts/run_harness.py",
                                          "op": "black-box subprocess assertions (stdin JSON in, exit code + stdout/stderr out)"},
                           "assertions": {"passed": passed, "total": total}},
        # V5: true == verified on THIS platform only. Honest until CI proves more.
        "platformSpec": True,
        # V12: the subject is our own package -> self (derivable from
        # antinel-namespaces.json; fail-closed unattributed when it cannot be resolved).
        "objectOwnership": "self",
        "assertions_total": total,
        "assertions_passed": passed,
        "criteria_independence": "Assertions exercise the hook protocol, rule matching, scanner, installer and reporter as black boxes through subprocesses (stdin JSON in, exit code and stdout/stderr out); they were authored from the design specification ANT-SEC-SPEC-001 v1.1, not from the implementation; third-party re-run supported.",
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "stdlib_only": True, "network": "none"},
        "digests": digests,
        "run": {"started_at": started, "duration_ms": int((time.time() - t0) * 1000),
                "executor": "scripts/run_harness.py", "exit_code": proc.returncode},
        "re_run": "python scripts/run_harness.py",
        "verify": "python tools/antinel_verify.py",
        "anchor": None,
        "note": "v0.1 judgment: single-machine execution by the packaging agent; verification is not a security audit of the user environment. Any failed third-party re-run supersedes this record.",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")
    # V6 ledger (minimal form): append-only, idempotent -- a re-run with the same
    # subject digest and verdict does not grow the file.
    subject = "sha256:" + hashlib.sha256(
        "\n".join(digests[k] for k in COVERED).encode()).hexdigest()
    row = {"recorded_at": now, "row_kind": "self-verdict", "card_id": rec["card_id"],
           "skill_version": rec["skill_version"], "verdict": verdict,
           "subject_digest": subject, "status": "current",
           "objectOwnership": "self",
           "instrument": rec["discrimination"]["instrument"]["name"],
           "assertions": "%d/%d" % (passed, total),
           "re_run": rec["re_run"], "verify": rec["verify"], "anchor": None}
    prev = None
    if LEDGER.is_file():
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try: prev = json.loads(line)
                except Exception: pass
    if not (prev and prev.get("subject_digest") == subject and prev.get("verdict") == verdict):
        with LEDGER.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print("verdict=%s assertions=%d/%d -> %s" % (verdict, passed, total, OUT))
    return 0 if verdict == "PASS" else 1

if __name__ == "__main__":
    sys.exit(main())
