#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel Security Suite v0.16.0 - self installer (F-07) and uninstaller (F-08).

Steps (spec part 4):
  1. detect host type            (A-04 algorithm + C-02 refinements)
  2. snapshot rules into .psl/   (rules/default.json -> .psl/rules/default.json)
  3. register hooks              (append to <host>/settings.json, never overwrite)
  4. initialise .psl/            (audit/, rules/, manifest.json per D-05)
  5. run the first scan          (scan.py --quick)
  6. write manifest.json         (existence + parsability = "installed" flag)

Upgrade path (0.16.0, gap-report P0-7): the installer now DETECTS a previous
install of a different version, says so, and refreshes the rules snapshot and
manifest hashes in the same run (init_psl always rewrites them). `--check` runs
the comparison alone: installed version + rules_hash + script hashes vs the
package, without touching anything (exit 3 = drift). Before 0.16.0, upgrading
the package left the installed manifest stale, so the A4 integrity check
silently degraded every hook call to the 11-rule fallback set (181 such events
measured on 09-11 alone).

Hook registration format (A-01 / A-05):
  {"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
       {"type": "command", "command": "<python> -I -S <abs>/pre_tool_use.py", "timeout": 10}]}],
             "PostToolUse": [...]}}
Commands use absolute paths (B-06: the host runs hooks from its own cwd).

Exit codes (spec A-10): 0 = installed / check ok, 1 = host detection failed under
--strict (no hook-capable host), 2 = installation error (permissions/disk),
3 = --check found drift (version or hash mismatch).
Set ANTINEL_NO_HOME_DETECT=1 to skip the home-directory markers (A-04 step 2),
useful for isolated tests on machines that already have a host installed.
Python 3.10+, stdlib only, no network.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
SKILL_VERSION = "0.16.0"
PSL_SPEC = "psl-vs-0.1"
SCRIPT_FILES = ("pre_tool_use.py", "post_tool_use.py", "scan.py", "install.py", "report.py")

# 0.16.0 (P1-7): agent-managed directories that legitimately live OUTSIDE any
# project root. When one of these exists at first install, the policy template
# is seeded with it so a legitimate write (e.g. updating your own skill) does
# not collide with DST-02 on day one. Seeded paths are visible and removable in
# .psl/policy.json; every DST-02 release through them is audit-logged
# (dst02_path_whitelisted), so the relaxation is traceable, never silent.
AGENT_MANAGED_DIRS = (".workbuddy/skills", ".claude/skills", ".zcode/skills",
                      ".qoder/skills", ".trae/skills")


def _locate(*rel):
    """Flat PoC layout (everything next to install.py) or skill package layout
    (install.py in scripts/, hooks in ../hooks, rules in ../rules)."""
    for base in (PKG_DIR, PKG_DIR.parent):
        for sub in ("", "hooks", "scripts"):
            p = (base / sub).joinpath(*rel) if sub else base.joinpath(*rel)
            if p.exists():
                return p
    return PKG_DIR.joinpath(*rel)


POLICY_TEMPLATE = {
    "$schema": "antinel-policy-v1",
    "version": "1.0",
    "global_settings": {"alert_threshold": "warning", "log_retention_days": 30,
                        "auto_archive": False, "desktop_notify": False},
    "whitelist": {"domains": [], "paths": [], "commands": []},
    "_semantics": {
        "whitelist.domains": "relaxes NETWORK rules only (NET-01/02 excludes, NET-03 whitelist)",
        "whitelist.paths": "path prefixes exempt from SECRETS rules; also releases DST-02 "
                           "(write-outside-root) for these prefixes -- every DST-02 release "
                           "is audit-logged as dst02_path_whitelisted (0.16.0)",
        "whitelist.commands": "command prefixes exempt from WARNING-level rules only; critical never relaxed",
        "alert_threshold": "warning (default) or critical: suppresses stderr notices below it; logging/blocking unchanged",
        "auto_archive": "true: report.py applies the retention policy on every run",
        "desktop_notify": "ignored in v1 (spec B-04)",
    },
}


def seeded_policy_paths():
    """P1-7: agent-managed directories that exist on this machine get pre-seeded
    into whitelist.paths at FIRST policy creation only (policy.json is never
    overwritten on re-install). Visible, removable, and every DST-02 release
    through them leaves an audit record."""
    out = []
    home = Path.home()
    for rel in AGENT_MANAGED_DIRS:
        p = home / rel
        try:
            if p.is_dir():
                out.append(str(p).replace("\\", "/").rstrip("/") + "/")
        except Exception:
            continue
    return out
HOST_DIRS = (("claude-code", ".claude"), ("zcode", ".zcode"), ("qoder", ".qoder"))
HOOK_EVENTS = ("PreToolUse", "PostToolUse", "SessionStart")
HOOK_SCRIPTS = {"PreToolUse": "pre_tool_use.py", "PostToolUse": "post_tool_use.py",
                "SessionStart": "session_start_banner.py"}
HOOK_TIMEOUT_SECONDS = 10


# ------------------------------------------------------------ detection ----
def _settings_has_hooks(path):
    try:
        return "hooks" in json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return False


def detect_host(root):
    """Returns (host, settings_path). Priority (A-04): project markers >
    home markers > environment variables > generic. Among several markers at
    the same level the most recently modified settings.json wins (C-02)."""
    root = Path(root)
    bases = [root] if os.environ.get("ANTINEL_NO_HOME_DETECT") else [root, Path.home()]
    for base in bases:
        found = []
        for host, d in HOST_DIRS:
            p = base / d / ("config.json" if d == ".zcode" else "settings.json")
            if p.is_file():
                found.append((p.stat().st_mtime, _settings_has_hooks(p), host, p))
            elif base == root and (base / d).is_dir():
                found.append((0.0, False, host, p))
        if found:
            found.sort(key=lambda t: (t[1], t[0]), reverse=True)     # hooks key, then mtime
            _, _, host, p = found[0]
            return host, (root / p.parent.name / ("config.json" if p.parent.name == ".zcode" else "settings.json")) if base != root else p
    if os.environ.get("CLAUDE_CODE"):
        return "claude-code", root / ".claude" / "settings.json"
    if os.environ.get("ZCODE_SESSION"):
        return "zcode", root / ".zcode" / "config.json"
    return "generic", root / ".psl" / "hooks.json"


# ---------------------------------------------------------- hook config ----
def hook_command(script_name):
    """Claude Code contract (A-01): a shell command line. -I -S cut interpreter
    start-up by roughly 15-20 ms per call (NFR-03). ZCode uses type "process"
    (see zcode_hook_entry) so no shell quoting is needed there."""
    return '"%s" -I -S "%s"' % (sys.executable, _locate(script_name))


def zcode_hook_entry(script_name):
    """Real ZCode contract (verified against the client's diagnosing-hooks guide,
    smoke test 2026-09-10): hooks live in .zcode/config.json under hooks.events,
    must set hooks.enabled=true, and type "process" runs an argv without a shell."""
    return {"type": "process", "command": sys.executable,
            "args": ["-I", "-S", str(_locate(script_name))], "timeoutMs": 10000}


def _is_ours(entry):
    for h in entry.get("hooks", []) or []:
        cmd = (h.get("command") or "") + " ".join(h.get("args") or [])
        cmd = cmd.lower()
        if "pre_tool_use.py" in cmd or "post_tool_use.py" in cmd or "session_start_banner.py" in cmd:
            return True
    return False


def register_hooks_claude(settings_path):
    """Claude Code / Qoder shape: {"hooks": {"<Event>": [{matcher, hooks:[...]}]}}.
    Existing foreign hooks are preserved; previous Antinel entries are replaced."""
    settings_path = Path(settings_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    if settings_path.is_file():
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8"))
        except Exception:
            backup = settings_path.with_suffix(".json.bak")
            shutil.copy2(settings_path, backup)
            data = {}
    if not isinstance(data, dict):
        data = {}
    hooks = data.setdefault("hooks", {})
    registered = []
    for event in HOOK_EVENTS:
        entries = [e for e in (hooks.get(event) or []) if not _is_ours(e)]
        entries.append({
            "matcher": ".*",
            "hooks": [{"type": "command",
                       "command": hook_command(HOOK_SCRIPTS[event]),
                       "timeout": HOOK_TIMEOUT_SECONDS}],
        })
        hooks[event] = entries
        registered.append(event)
    if settings_path.name == "hooks.json":               # generic fallback manifest
        data["_note"] = ("PSL generic hook manifest: no host hook support detected; "
                         "scan-only mode. Point your host at these commands manually.")
    settings_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return registered


def register_hooks_zcode(config_path):
    """Real ZCode shape: .zcode/config.json, hooks.enabled must be true, events under
    hooks.events (source: zcode-guide diagnosing-hooks; replaces the v1.1 assumption
    that ZCode mirrored .claude/settings.json). Foreign hooks and foreign config keys
    are preserved; the runner gate is enabled because ours are configuration hooks."""
    config_path = Path(config_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    if config_path.is_file():
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except Exception:
            backup = config_path.with_suffix(".json.bak")
            shutil.copy2(config_path, backup)
            data = {}
    if not isinstance(data, dict):
        data = {}
    hooks = data.get("hooks") or {}
    hooks["enabled"] = True
    events = hooks.setdefault("events", {})
    registered = []
    for event in HOOK_EVENTS:
        entries = [e for e in (events.get(event) or []) if not _is_ours(e)]
        entries.append({"matcher": ".*",
                        "hooks": [zcode_hook_entry(HOOK_SCRIPTS[event])]})
        events[event] = entries
        registered.append(event)
    data["hooks"] = hooks
    config_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return registered


def register_hooks(settings_path, host):
    if host == "zcode":
        return register_hooks_zcode(settings_path)
    return register_hooks_claude(settings_path)


def unregister_hooks(settings_path):
    settings_path = Path(settings_path)
    if not settings_path.is_file():
        return 0
    try:
        data = json.loads(settings_path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    hooks = data.get("hooks") or {}
    removed = 0
    # ZCode shape: {"enabled": true, "events": {...}}; Claude shape: {"<Event>": [...]}.  # noqa
    events = hooks.get("events") if isinstance(hooks.get("events"), dict) else hooks
    for event in list(events.keys()):
        entries = events[event]
        if not isinstance(entries, list):
            continue
        keep = [e for e in entries if not _is_ours(e)]
        removed += len(entries) - len(keep)
        if keep:
            events[event] = keep
        else:
            del events[event]
    if isinstance(hooks.get("events"), dict) and not hooks["events"]:
        del hooks["events"]
        if set(hooks.keys()) <= {"enabled"}:
            del data["hooks"]
    settings_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return removed


# --------------------------------------------------------------- .psl/ ----
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def init_psl(root, host, settings_path, registered, global_hooks=False):
    psl = Path(root) / ".psl"
    (psl / "audit").mkdir(parents=True, exist_ok=True)
    (psl / "rules").mkdir(parents=True, exist_ok=True)
    gi = psl / ".gitignore"                              # D7: behaviour logs must not enter VCS
    if not gi.is_file():
        gi.write_text("# Antinel: local audit logs, policy and state - do not commit\n*\n",
                      encoding="utf-8")
    src = _locate("rules", "default.json")
    dst = psl / "rules" / "default.json"
    shutil.copy2(src, dst)                                   # D-04: overwrite default only
    policy = psl / "policy.json"
    if not policy.is_file():                                 # C-05 template; never overwritten
        tpl = json.loads(json.dumps(POLICY_TEMPLATE))        # deep copy
        seeded = seeded_policy_paths()
        if seeded:
            tpl["whitelist"]["paths"] = seeded
            tpl["_semantics"]["_seeded_paths"] = (
                "auto-seeded at install with agent-managed directories that exist on "
                "this machine; delete any line to re-enable strict DST-02 for it")
        policy.write_text(json.dumps(tpl, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest = {
        "schema_version": "1.0",
        "installed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": host,
        "host_version": "unknown",
        "skill_version": SKILL_VERSION,
        "psl_spec": PSL_SPEC,
        "hooks_registered": registered,
        "rules_file": ".psl/rules/default.json",
        "rules_hash": sha256_file(src),
        "scripts_hash": {f: sha256_file(_locate(f)) for f in SCRIPT_FILES if _locate(f).is_file()},
        "policy_file": ".psl/policy.json",
        "audit_log_dir": ".psl/audit",
        "created_by": "install.py v" + SKILL_VERSION,
        "settings_file": str(settings_path),
        "scope": "user" if global_hooks else "project",
        "package_dir": str(PKG_DIR),
        "python": sys.executable,
    }
    (psl / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
    return manifest


def first_scan(root):
    cmd = [sys.executable, str(_locate("scan.py")), "--root", str(root), "--quick"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=120)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        return 2, "", str(e)


# ------------------------------------------------------------------ main ----
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


def install(root, host_override=None, redetect=False, skip_scan=False, strict=False, force=False,
            global_hooks=False):
    root = Path(root).resolve()
    manifest_path = root / ".psl" / "manifest.json"
    host = settings_path = None
    if manifest_path.is_file() and not redetect and not host_override:
        try:                                                  # C-02: reuse recorded host
            old = json.loads(manifest_path.read_text(encoding="utf-8"))
            host, settings_path = old.get("host"), Path(old.get("settings_file", ""))
            old_ver = old.get("skill_version")
            if old_ver and old_ver != SKILL_VERSION:
                print("[upgrade] installed version %s != package %s" % (old_ver, SKILL_VERSION))
                print("          refreshing rules snapshot + manifest hashes in this run "
                      "(the hook degrades to the embedded fallback set until you do)")
        except Exception:
            host = None
    if not host or not str(settings_path):
        host, settings_path = detect_host(root)
    if host_override:
        detected, _ = detect_host(root)
        if detected != "generic" and detected != host_override and not force:
            print("refused: --host %s but the project looks like %s (markers found). "
                  "--host is a test-only override; use auto-detection in production, "
                  "or pass --force if you really mean it." % (host_override, detected))
            return 1
        if detected != host_override:
            print("warning: forcing host=%s (auto-detected: %s); hooks will be registered "
                  "under the forced host's settings file" % (host_override, detected))
        host = host_override
        settings_path = (root / ".psl" / "hooks.json") if host == "generic" \
            else root / dict((h, d) for h, d in HOST_DIRS)[host] / ("config.json" if host == "zcode" else "settings.json")
    if host == "generic" and strict:
        print("host detection failed: no hook-capable host found (use --host to force)")
        return 1

    if global_hooks:
        home = Path.home()
        settings_path = {"claude-code": home / ".claude" / "settings.json",
                         "zcode": home / ".zcode" / "cli" / "config.json",
                         "qoder": home / ".qoder" / "settings.json",
                         "generic": home / ".psl" / "hooks.json"}[host]

    print("[1/6] host: %s%s" % (host, "  |  scope: USER-LEVEL (--global: every workspace)" if global_hooks else ""))
    _others = [h for h, d_ in HOST_DIRS if h != host and os.path.isdir(os.path.join(str(root), d_))]
    if _others:
        print("      also detected here: " + ", ".join(_others) +
              " -- only " + host + " gets the hooks; "
              "--host <name> --force to switch, --global for every host")
    print("[2/6] settings: %s" % settings_path)
    registered = register_hooks(settings_path, host)
    if host == "generic":
        print("[3/6] hooks: written to PSL manifest only (scan-only mode, no host hook support)")
        registered = []
    else:
        print("[3/6] hooks: %s registered (append mode)" % ", ".join(registered))
    manifest = init_psl(root, host, settings_path, registered, global_hooks=global_hooks)
    print("[4/6] .psl/ initialised: rules snapshot %s" % manifest["rules_hash"][:23])
    if skip_scan:
        print("[5/6] first scan skipped (--skip-scan)")
    else:
        rc, out, err = first_scan(root)
        print("[5/6] first scan exit=%d" % rc)
        if out:
            print(out)
        if err.strip():
            print(err.strip())
    print("[6/6] manifest: %s" % manifest_path)
    return 0


def check_installed(root):
    """0.16.0 (P0-7): compare the installed manifest against the package WITHOUT
    touching anything. Exit 0 = in sync, 3 = drift (version or hash mismatch),
    1 = nothing installed here. This is the read-only twin of re-running install."""
    root = Path(root).resolve()
    manifest_path = root / ".psl" / "manifest.json"
    if not manifest_path.is_file():
        print("not installed here: %s" % manifest_path)
        return 1
    try:
        old = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        print("manifest unreadable: %s" % e)
        return 3
    problems = []
    old_ver = old.get("skill_version")
    if old_ver != SKILL_VERSION:
        problems.append("version: installed %s != package %s (re-run install.py to refresh)"
                        % (old_ver, SKILL_VERSION))
    want_rules = sha256_file(_locate("rules", "default.json"))
    if old.get("rules_hash") != want_rules:
        problems.append("rules_hash: installed %s != package %s" %
                        (str(old.get("rules_hash"))[:28], want_rules[:28]))
    for f, h in (old.get("scripts_hash") or {}).items():
        p = _locate(f)
        if p.is_file() and sha256_file(p) != h:
            problems.append("script %s differs from the installed hash" % f)
    if problems:
        print("DRIFT detected (%d):" % len(problems))
        for p in problems:
            print("  - %s" % p)
        print("fix: python scripts/install.py --root %s" % root)
        return 3
    print("in sync: version %s, rules_hash matches, %d script hashes match"
          % (old_ver, len(old.get("scripts_hash") or {})))
    return 0


def uninstall(root, purge=False):
    root = Path(root).resolve()
    manifest_path = root / ".psl" / "manifest.json"
    settings_path = None
    if manifest_path.is_file():
        try:
            settings_path = Path(json.loads(manifest_path.read_text(encoding="utf-8"))
                                 .get("settings_file", ""))
        except Exception:
            settings_path = None
    if not settings_path or not str(settings_path):
        _, settings_path = detect_host(root)
    removed = unregister_hooks(settings_path)
    print("hooks removed: %d (%s)" % (removed, settings_path))
    if purge and (root / ".psl").is_dir():
        shutil.rmtree(root / ".psl")
        print(".psl/ removed (purge)")
    elif manifest_path.is_file():
        manifest_path.unlink()
        print("manifest removed; audit logs kept in .psl/audit (use --purge to delete)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Antinel Security Suite installer")
    ap.add_argument("--root", default=os.getcwd(), help="project root (default: cwd)")
    ap.add_argument("--host", choices=["claude-code", "zcode", "qoder", "generic"],
                    help="force host type (TEST ONLY; refused when it contradicts detected markers unless --force)")
    ap.add_argument("--force", action="store_true", help="allow --host to override a contradicting detection")
    ap.add_argument("--global", dest="global_hooks", action="store_true",
                    help="register at user level so EVERY workspace is protected; "
                         "project root, policy and audit logs are still derived per directory at runtime")
    ap.add_argument("--redetect", action="store_true", help="ignore recorded host")
    ap.add_argument("--skip-scan", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="compare installed manifest vs package (version + hashes); no changes")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 instead of degrading to scan-only mode")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--purge", action="store_true", help="with --uninstall: delete .psl/")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        if args.check:
            return check_installed(args.root)
        if args.uninstall:
            return uninstall(args.root, purge=args.purge)
        return install(args.root, host_override=args.host, redetect=args.redetect,
                       skip_scan=args.skip_scan, strict=args.strict, force=args.force,
                       global_hooks=args.global_hooks)
    except PermissionError as e:
        print("permission denied: %s. Run with sufficient rights or create the directory manually." % e)
        return 2
    except OSError as e:
        print("installation error: %s" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
