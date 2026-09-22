#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-run the verification suite against THIS package and record psl/judgment.json (psl-vs-0.1).
Usage: python scripts/run_harness.py            third parties: any failed re-run supersedes the shipped record
       python scripts/run_harness.py --bootstrap   build-time run: NO ledger write, verdict marked bootstrap

0.17.0 (P-A1, audit N2/N3): the assertion count now comes from the suite's
STRUCTURED results file (last_results.json), not from grepping human-readable
stdout; the record's presence is a REQUIRED input in pkg layout (a run without
it FAILS instead of quietly scoring 1 lower); and the ledger idempotency key
includes the assertion count, so a changed denominator can never be swallowed
by the "no change" guard again.
"""
import hashlib, json, os, platform, re, subprocess, sys, tempfile, time
from datetime import datetime, timezone
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent      # run_harness lives in <pkg>/scripts/
OUT = PKG / "psl" / "judgment.json"
LEDGER = PKG / "psl" / "verdict-ledger.jsonl"
MANIFEST = PKG / "psl" / "manifest.json"
COVERED = ["antinel-namespaces.json",
           "rules/default.json", "rules/pricing.json",
           "rules/economics/workbuddy.json", "rules/economics/zcode.json",
           "rules/economics/claude-code.json", "rules/economics/qoder.json",
           "rules/economics/generic.json",
           "hooks/pre_tool_use.py", "hooks/post_tool_use.py",
           "scripts/scan.py", "scripts/install.py", "scripts/report.py",
           "scripts/verification_tests.py", "session_dna.py", "transcript_reader.py",
           "audit_chain.py",
           "antinel.py", "hub.py"]

def sha(p):
    return "sha256:" + hashlib.sha256(Path(p).read_bytes()).hexdigest()

def pinned_fingerprint():
    """The namespace-list key fingerprint pinned in README.md (single source)."""
    try:
        txt = (PKG / "README.md").read_text(encoding="utf-8")
        m = re.search(r"sha256:[0-9a-f]{16}", txt)
        return m.group(0) if m else None
    except Exception:
        return None

def repo_identity():
    """(host, owner) this build declares itself as: git remote first, then the
    namespace the builder wrote into psl/manifest.json, else None."""
    try:
        out = subprocess.run(["git", "remote", "get-url", "origin"], cwd=str(PKG),
                             capture_output=True, text=True, timeout=5)
        url = (out.stdout or "").strip()
        m = re.search(r"[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?$", url)
        if m:
            # group(1)=owner, group(2)=repo —— owner 才是命名空间主体（0.29 修复：
            # 取反了会让 subject 解析成 github.com/antinel 而非 github.com/sotaex）
            return "github.com", m.group(1).lower(), m.group(2).lower()
    except Exception:
        pass
    try:
        ns = (json.loads(MANIFEST.read_text(encoding="utf-8")) or {}).get("namespace") or {}
        if ns.get("host") and ns.get("owner"):
            return ns["host"], ns["owner"], ns["owner"]
    except Exception:
        pass
    return None

def derive_object_ownership():
    """V12 derivation. fail-closed: the default is `unattributed`; `self` is
    returned only on a positive match against a signed list whose key
    fingerprint equals the value pinned in README.md."""
    try:
        doc = json.loads((PKG / "antinel-namespaces.json").read_text(encoding="utf-8"))
    except Exception as e:
        return "unattributed", "namespaces list unreadable (%s)" % type(e).__name__
    sig = doc.get("signature") or {}
    if not (sig.get("value") and sig.get("public_key_fingerprint")):
        return "unattributed", "namespaces list carries no signature block"
    pinned = pinned_fingerprint()
    if not pinned or pinned != sig["public_key_fingerprint"]:
        return "unattributed", "list fingerprint %s does not match README-pinned %s" % (
            sig.get("public_key_fingerprint"), pinned)
    ident = repo_identity()
    if not ident:
        return "unattributed", "subject identity is not resolvable (no git remote, no manifest.namespace)"
    host, owner, _disp = ident
    for e in doc.get("namespaces") or []:
        if e.get("host") == host and str(e.get("owner", "")).lower() == owner:
            return "self", "subject %s/%s is in the signed namespace list" % (host, owner)
    return "third-party", "subject %s/%s is NOT in the signed namespace list" % (host, owner)

def should_append(prev_row, new_row):
    """0.18.0 (R-21/HP-14): the ledger-append decision, EXTRACTED so it can be
    exercised by tests without writing anything (scripts/run_harness.py
    --check-ledger). The idempotency key includes the assertion count, so a
    changed denominator always lands a new row."""
    return not (prev_row
                and prev_row.get("subject_digest") == new_row.get("subject_digest")
                and prev_row.get("verdict") == new_row.get("verdict")
                and prev_row.get("assertions") == new_row.get("assertions"))

def main():
    bootstrap = "--bootstrap" in sys.argv
    check_ledger = "--check-ledger" in sys.argv
    if check_ledger:
        # R-21 (HP-14): dry-run the ledger-append decision AGAINST THE CURRENT
        # TREE, using the existing judgment record's verdict/assertions -- no
        # suite run, no writes. Answers "would an official run right now land a
        # new ledger row?" in under a second, so tests can exercise idempotency.
        prev = None
        if LEDGER.is_file():
            for line in LEDGER.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try: prev = json.loads(line)
                    except Exception: pass
        try:
            old = json.loads(OUT.read_text(encoding="utf-8"))
            verdict = old.get("verdict", "FAIL")
            total = int(old.get("assertions_total", 0))
            passed = int(old.get("assertions_passed", 0))
        except Exception:
            print("would_append=unknown (no judgment record -- bootstrap first)")
            return 0
        digests = {rel: sha(PKG / rel) for rel in COVERED}
        ownership, _basis = derive_object_ownership()
        subject = "sha256:" + hashlib.sha256(
            "\n".join(digests[k] for k in COVERED).encode()).hexdigest()
        row = {"subject_digest": subject, "verdict": verdict,
               "assertions": "%d/%d" % (passed, total)}
        print("would_append=%s" % str(should_append(prev, row)).lower())
        return 0
    env = dict(os.environ); env["ANTINEL_PKG"] = str(PKG)
    # P-A1: the layout is DECLARED here. pkg = the record is required (absent
    # record FAILS the suite); bootstrap = build-time run before the record
    # exists -- the judgment block contributes 0 assertions and the ledger is
    # never written.
    env["ANTINEL_LAYOUT"] = "bootstrap" if bootstrap else "pkg"
    work = tempfile.mkdtemp(prefix="antinel_harness_")  # per-run: no stale results file
    env["ANTINEL_WORK"] = work
    t0 = time.time(); started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    proc = subprocess.run([sys.executable, str(PKG / "scripts" / "verification_tests.py")],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    res = Path(work) / "last_results.json"
    # CI 调试转储（ANTINEL_DEBUG_CI=1 时）：把套件输出与结构化结果留到仓内
    # psl/ci_debug/，让无日志权限的第三方也能定位失败。默认关。
    if os.environ.get("ANTINEL_DEBUG_CI") == "1":
        try:
            dbg = PKG / "psl" / "ci_debug"
            dbg.mkdir(parents=True, exist_ok=True)
            (dbg / "suite_stdout.txt").write_text(proc.stdout or "", encoding="utf-8")
            (dbg / "suite_stderr.txt").write_text(proc.stderr or "", encoding="utf-8")
            if res.is_file():
                shutil.copyfile(res, dbg / "last_results.json")
            (dbg / "run_info.txt").write_text(
                "python=%s platform=%s rc=%d\n" % (sys.version, platform.platform(),
                                                   proc.returncode), encoding="utf-8")
        except Exception:
            pass
    try:
        rows = json.loads(res.read_text(encoding="utf-8"))
        total = len(rows)
        passed = sum(1 for r in rows if r.get("pass"))
    except Exception as e:
        print("harness: cannot read structured results %s (%s) -- refusing to report a count" % (res, e))
        tail = (proc.stderr or "")[-1500:]
        out_tail = (proc.stdout or "")[-800:]
        if tail:
            print("--- suite stderr tail ---\n" + tail)
        if out_tail:
            print("--- suite stdout tail ---\n" + out_tail)
        return 2
    verdict = "PASS" if proc.returncode == 0 and total and passed == total else "FAIL"
    ownership, ownership_basis = derive_object_ownership()
    digests = {rel: sha(PKG / rel) for rel in COVERED}
    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    rec = {
        "spec": "psl-vs-0.1",
        "card_id": "antinel-security-suite",
        "skill": "antinel-security",
        "skill_version": "0.27.0",
        "verdict": ("PASS (bootstrap)" if bootstrap and verdict == "PASS" else verdict),
        # V7: status is a status BIT, appended info; this file itself is never
        # edited after publication. A third party derives current/superseded
        # with tools/antinel_verify.py; checkedAt is when WE last derived it.
        "status": {"value": "current", "derivation": "auto", "reason": None,
                   "checkedAt": now,
                   "note": "re-derive any time: python tools/antinel_verify.py (--manifest for all 24 shipped files)"},
        # V8: scope -- what this verdict covers and, just as loudly, what it does not.
        "scope": {"covered": COVERED,
                  "notCovered": ["runtime behaviour of the monitored host",
                                 "files outside the " + str(len(COVERED)) + " digests above",
                                 "the security posture of your machine or environment",
                                 "dynamic tool traffic (that is the hooks\' job, not this record\'s)",
                                 "the " + "\u4f53\u68c0" " behaviour corpus is not shipped with the package; "
                                 "that reading is not reproducible from this package alone"]},
        # V1: the gauge behind the number. assertions N/N without a named
        # instrument is exactly the drift shape this field exists to prevent.
        "discrimination": {"instrument": {"name": "scripts/verification_tests.py",
                                          "object": "this package (the " + str(len(COVERED)) + " digested files)",
                                          "runner": "scripts/run_harness.py",
                                          "op": "black-box subprocess assertions (stdin JSON in, exit code + stdout/stderr out)"},
                           "assertions": {"passed": passed, "total": total}},
        # V5: true == verified on THIS platform only. Honest until CI proves more.
        "platformSpec": True,
        # V12: DERIVED (0.17.0, P-A3), no longer a constant: fail-closed
        # unattributed unless the signed list + pinned fingerprint + subject
        # identity all check out. Basis kept beside the value.
        "objectOwnership": ownership,
        "objectOwnershipBasis": ownership_basis,
        "assertions_total": total,
        "assertions_passed": passed,
        "criteria_independence": "Assertions exercise the hook protocol, rule matching, scanner, installer and reporter as black boxes through subprocesses (stdin JSON in, exit code and stdout/stderr out); they were authored from the design specification ANT-SEC-SPEC-001 v1.1, not from the implementation; third-party re-run supported.",
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "stdlib_only": True, "network": "none"},
        "digests": digests,
        "run": {"started_at": started, "duration_ms": int((time.time() - t0) * 1000),
                "duration_note": "wall-clock of a subprocess fan-out suite; machine- and load-dependent, not comparable across environments",
                "executor": "scripts/run_harness.py", "exit_code": proc.returncode,
                "bootstrap": bootstrap},
        "re_run": "python scripts/run_harness.py",
        "verify": "python tools/antinel_verify.py",
        "anchor": None,
        "note": "v0.1 judgment: single-machine execution by the packaging agent; verification is not a security audit of the user environment. Any failed third-party re-run supersedes this record.",
    }
    # V6 ledger (minimal form): append-only, idempotent. P-A1: the idempotency
    # key includes the assertion count, so a changed denominator always lands a
    # new row instead of being swallowed. Bootstrap runs NEVER write the ledger.
    subject = "sha256:" + hashlib.sha256(
        "\n".join(digests[k] for k in COVERED).encode()).hexdigest()
    row = {"recorded_at": now, "row_kind": "self-verdict", "card_id": rec["card_id"],
           "skill_version": rec["skill_version"], "verdict": rec["verdict"],
           "subject_digest": subject, "status": "current",
           "objectOwnership": ownership,
           "instrument": rec["discrimination"]["instrument"]["name"],
           "assertions": "%d/%d" % (passed, total),
           "re_run": rec["re_run"], "verify": rec["verify"], "anchor": None}
    prev = None
    if LEDGER.is_file():
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try: prev = json.loads(line)
                except Exception: pass
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")
    if bootstrap:
        print("harness: bootstrap run -- ledger untouched")
    elif should_append(prev, row):
        with LEDGER.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print("verdict=%s assertions=%d/%d -> %s" % (rec["verdict"], passed, total, OUT))
    return 0 if verdict == "PASS" else 1

if __name__ == "__main__":
    sys.exit(main())
