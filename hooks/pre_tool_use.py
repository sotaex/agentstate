#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel Security Suite v0.17.0 - PreToolUse hook (Claude Code / ZCode compatible).

v1.2 fixes over v1.1:
  G-01: rules loaded from PKG_DIR only (install.py snapshot in .psl/ is informational)
  G-03: FALLBACK_RULES expanded to cover all core patterns
  G-04: project_root inferred from .psl/ or .git/ presence (walk up from cwd)
  G-05+G-09: invisible Unicode scanned in command / path / content, not just file content
  G-06: all rule hits collected, highest severity decides, every hit logged
  G-11: custom rules path: cwd then parent (.psl/rules/custom.json)
  G-12: unified field access - command_patterns / file_patterns / content_patterns /
        exclude_patterns / check / whitelist_domains are read from the rule TOP LEVEL
        (flat layout of rules/default.json v1.2). A legacy "match" sub-object is still
        honoured as fallback so older rule files keep working.

Protocol (spec A-01 / D-01): one JSON event on stdin
    {"session_id", "transcript_path", "tool_name", "tool_input"}
Block: stdout {"decision":"block","reason":...} + stderr reason + exit 2 (dual channel).
Warning: stderr notice, exit 0. Any internal failure: exit 0 (fail open, A-08).

tool_input mapping: Bash -> command; Read -> file_path; Write -> file_path + content;
Edit -> file_path + old_string + new_string.
Spec refs: psl-vs-0.1, ANT-SEC-SPEC-001 v1.1 sections 2.4 - 2.5.
"""
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------- constants --
PKG_DIR = os.path.dirname(os.path.abspath(__file__))


def _locate(*rel):
    """Resolve a package resource for both layouts: flat PoC (rules/ next to the
    hook) and skill package (hook in hooks/, rules in ../rules, spec B-06)."""
    for base in (PKG_DIR, os.path.dirname(PKG_DIR)):
        p = os.path.join(base, *rel)
        if os.path.exists(p):
            return p
    return os.path.join(PKG_DIR, *rel)


RULES_PATH = _locate("rules", "default.json")
MAX_READ = 2 * 1024 * 1024
MAX_CMD = 256 * 1024                    # legacy name, kept for callers; no longer a cut
MAX_CONTENT = 1024 * 1024               # legacy name, kept for callers; no longer a cut
# P0-1: bounded-window matching (see _search). SCAN_LIMIT is the honest ceiling: past it
# the scan stops and says so (`scan_truncated`) rather than silently skipping the tail.
SCAN_CHUNK = 64 * 1024
SCAN_OVERLAP = 4 * 1024
SCAN_LIMIT = 4 * 1024 * 1024            # head+tail budget; 见下方实测（原 2MB）
PREFILTER_MIN = 64 * 1024               # below this the regex is already cheap; skip prefiltering
# Differential-testing switch: with ANTINEL_NO_PREFILTER=1 every pattern runs its regex
# on every text. The two modes must return identical verdicts on every input -- that
# equivalence is the only real proof the prefilter is conservative.
_PREFILTER_OFF = os.environ.get("ANTINEL_NO_PREFILTER") == "1"

_RX_CACHE = {}
_LIT_CACHE = {}
_LC_CACHE = [None, None]                # (text_object, lowered) -- strong ref keeps id stable


def _rx(pat):
    """Compiled pattern, cached. Returns None for a pattern that does not compile."""
    if pat in _RX_CACHE:
        return _RX_CACHE[pat] or None
    try:
        rx = re.compile(pat, re.IGNORECASE)
    except (re.error, TypeError, OverflowError):
        rx = None                       # a bad pattern disables that one rule, not the hook
    _RX_CACHE[pat] = rx
    return rx
INVISIBLE_RANGES = [(917504, 917631), (8203, 8207), (8288, 8292), (65279, 65279),
                    # E-F01 (2026-09-10): U+202D LRO / U+202E RLO —— 文件名伪装扩展名的
                    # 经典手法（resume<RLO>cod.exe 显示为 resumexe.exe）。此前不在检测
                    # 范围，实测 `Write` 到含 RLO 的路径直接放行。只收 override 两个
                    # 控制符，不收 U+202A..U+202C 嵌入符与 U+2066..2069 隔离符——后两者
                    # 在正常的希伯来/阿拉伯混排文本里出现，收进来会误伤。
                    (8237, 8238)]
SEV_RANK = {"critical": 0, "warning": 1, "info": 2}
CAT_ORDER = {"secrets": 0, "destructive": 1, "network": 2, "injection": 3, "context": 4, "metadata": 5}
TOOL_ALIASES = {"MultiEdit": "Edit", "ApplyPatch": "Edit", "NotebookEdit": "Write",
                "Task": "Agent"}          # A9: rules apply to the canonical tool name
TEXT_EXTS = (".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".py", ".js", ".ts", ".sh", ".bash", ".zsh")

# G-03: embedded fallback, used only when the rules file is unreadable (flat layout).
_FALLBACK = [
    {"id": "SEC-01", "category": "secrets", "severity": "critical", "apply_to_tools": ["Read", "Bash"],
     # 0.17.0 (P-B5): excludes kept literally identical to rules/default.json
     # (three separate strings, not a merged alternation) so the suite's
     # fallback-subset assertion can compare them mechanically.
     "file_patterns": [r"\.env$", r"\.env\."],
     "exclude_patterns": [r"\.env\.example", r"\.env\.template", r"\.env\.sample"],
     "description": "Agent attempted to read a .env file which may contain API keys and secrets"},
    {"id": "SEC-02", "category": "secrets", "severity": "critical", "apply_to_tools": ["Read", "Bash"],
     "file_patterns": [r"\.ssh[/\\]", "id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys"],
     "description": "Agent attempted to read SSH private key or authorized_keys file"},
    {"id": "SEC-03", "category": "secrets", "severity": "critical", "apply_to_tools": ["Read", "Bash"],
     "file_patterns": [r"\.aws[/\\]", r"\.kube[/\\]config", r"credentials\.json", r"\.netrc"],
     "description": "Agent attempted to read cloud provider credentials"},
    {"id": "DST-01", "category": "destructive", "severity": "critical", "apply_to_tools": ["Bash"],
     # A10: kept in sync with rules/default.json DST-01. Previously a fallback
     # (triggered by a corrupt/missing rules file) silently reverted Windows
     # coverage to the pre-A1 state -- Remove-Item and rd/s /q were not matched.
     # 0.16.0: the bare \brd\b became command-position + argument-context
     # (\brd(?:\s*[/][A-Za-z]|\s+[^=\s])) — the bare form matched Python code
     # like `rd = 3` and, via the letter-quote-join variant, raw-string prefixes
     # like r'D:\...' (both critical false positives on D:\ machines). Both
     # copies (rules file AND this fallback) must change together.
     "command_patterns": [r"\brm\b", r"\bdel\b", r"\brmdir\b", r"\bunlink\b",
                          r"\bshutil\.rmtree\b", r"\bos\.remove\b", r"remove-item",
                          r"(?:^|[;&|(]\s*|\s)rd(?:\s*[/][A-Za-z]|\s+[^=\s])"],
     "exclude_patterns": ["rm -rf node_modules", r"rm -rf \.git", r"rm -rf \.psl",
                          "remove-item node_modules", r"remove-item -recurse.*node_modules",
                          # 0.17.0 (P-B5): the fallback is the DEGRADED mode; it must
                          # not be noisier than the full rule set. These four excludes
                          # existed only in rules/default.json, so during a fallback
                          # `rm -rf dist` went from allowed to BLOCKED. Synced to the
                          # full 9; the suite now asserts fallback ⊆ rules per id.
                          r"rm -rf __pycache__",
                          r"\brm\s+-rf\s+(dist|build|target|venv|\.tox|\.mypy_cache|\.ruff_cache|\.pytest_cache|htmlcov|coverage|out|bin|obj)(\s|$|;)",
                          r"\brm\s+-rf\s+\S*\.(egg-info|pyc)(\s|$|;)",
                          r"\brm\s+-rf\s+\.nox\b"],
     "description": "Agent executed a file or directory deletion command"},
    {"id": "DST-02", "category": "destructive", "severity": "critical", "apply_to_tools": ["Write", "Edit"],
     "check": "path_outside_project_root",
     "description": "Agent attempted to write to a file outside the project root directory"},
    {"id": "DST-03", "category": "destructive", "severity": "critical", "apply_to_tools": ["Write", "Edit", "Bash"],
     "file_patterns": [r"\.bashrc", r"\.zshrc", r"\.profile", r"\.bash_profile"],
     "description": "Agent attempted to modify shell startup configuration (persistence mechanism)"},
    {"id": "DST-04", "category": "destructive", "severity": "critical", "apply_to_tools": ["Write", "Edit", "Bash"],
     "file_patterns": ["crontab", r"systemd[/\\]system", "LaunchAgents"],
     # A10: synced with rules/default.json DST-04 (schtasks / reg add were missing,
     # so a fallback undid A2). A16: Windows startup folder, regedit and the legacy
     # `at` scheduler are added to both copies -- the Linux .config/autostart form
     # was covered while these three were not.
     "command_patterns": [r"crontab\s+-[el]", r"systemctl\s+enable", r"launchctl\s+load",
                          r"\bschtasks\b", r"\breg\s+add\b",
                          r"(?i)\bregedit\b", r"(?i)start menu.*startup",
                          r"(?i)\bat\s+\d{1,2}:\d{2}\s+/\w+"],
     "description": "Agent attempted to establish persistence (cron job, systemd service, startup item)"},
    {"id": "NET-01", "category": "network", "severity": "warning", "apply_to_tools": ["Bash"],
     "command_patterns": [r"\b(curl|wget|fetch)\b.*https?://"],
     "exclude_patterns": ["localhost", r"127\.0\.0\.1", r"registry\.npmjs\.org", r"pypi\.org"],
     "description": "Agent made an external network request via shell command to a non-whitelisted domain"},
    {"id": "CTX-01", "category": "context", "severity": "warning", "apply_to_tools": ["Bash"],
     "command_patterns": [r"\benv\b(?!\s*=)", r"\bprintenv\b", r"os\.environ", r"process\.env"],
     "description": "Agent attempted to enumerate all environment variables (may expose API keys and secrets)"},
    {"id": "CTX-02", "category": "injection", "severity": "critical", "type": "file_content", "target": "SKILL.md",
     "apply_to_tools": ["Read", "Write", "Edit"],
     "content_patterns": [r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
                          r"忽略(以上|之前|先前|上面)(的)?(所有)?(指令|指示|规则)"],
     "description": "Potential prompt injection payload detected in skill instruction file"},
    {"id": "CTX-03", "category": "injection", "severity": "critical", "type": "file_content",
     "target": "all_text_files", "detection": "character_code_scan",
     "apply_to_tools": ["Read", "Write", "Edit", "Bash"],
     "description": "Invisible Unicode character detected (tag characters, zero-width, word joiner, BOM in middle of file)"},
]

_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", re.I)
KNOWN_TLDS = set("com org net io dev ai cn co uk de jp fr ru us edu gov mil int info biz app "
                 "xyz top site online tech cloud me tv cc ws to ly gg link club store shop "
                 "live news blog page space today world zone in br it nl es se no fi dk pl ch "
                 "at be cz ie pt gr hu ro tr il sa ae sg hk tw kr au nz ca mx ar cl za ng ke "
                 "eg id my th vn ph pk bd ir".split())
FILE_EXTS = set("py js ts md json yml yaml toml sh txt lock cfg ini log csv html css git zip "
                "tar gz exe bat ps1 env xml sql db pyc whl egg jar class go rs java c h cpp hpp "
                "rb php pl swift kt dart vue svelte jsx tsx mjs cjs map min svg png jpg jpeg gif "
                "ico pdf doc docx xls xlsx ppt pptx mp3 mp4 wav mov avi tmp bak old orig rej diff "
                "patch sample example template local test spec config conf d".split())


# ------------------------------------------------------ unified field access --
def _field(rule, key, default=None):
    """G-12: read a rule field from the TOP LEVEL; fall back to legacy rule["match"][key]."""
    if key in rule and rule[key] is not None:
        return rule[key]
    legacy = rule.get("match")
    if isinstance(legacy, dict) and legacy.get(key) is not None:
        return legacy[key]
    return default


def _patterns(rule, key):
    return _field(rule, key, []) or []


# --------------------------------------------------------------- rule loading --
# C9 (v1.2.2): ReDoS screen for *custom* rules.
# Windows has no signal.SIGALRM and no signal.setitimer (measured: hasattr is
# False for both), so a runtime timeout on regex matching is impossible on the
# primary target platform. Custom patterns are therefore screened statically for
# the shapes that make a regex blow up: a quantifier applied to a group that
# itself contains a quantifier, or an alternation under an outer quantifier.
# Measured against the 90 built-in patterns: 0 rejected. Against 9 known ReDoS
# samples: 9/9 caught. Against 20 benign alternation idioms: 1 conservative
# rejection ((?:foo|bar)+ -- overlapping alternatives under an outer quantifier
# are genuinely risky, so rejecting is the safe direction).
_NESTED_Q = re.compile(r"\((?:[^()\\]|\\.)*(?:[+*]|\{\d+,\})\s*\)(?:[+*]|\{\d+,\})")
_ALT_Q = re.compile(r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)(?:[+*]|\{\d+,\})")
_INNER_Q = re.compile(r"\((?:[^()\\]|\\.)*\?(?:[^()\\]|\\.)*\)(?:[+*]|\{\d+,\})")
_REDOS_KEYS = ("command_patterns", "file_patterns", "content_patterns", "exclude_patterns")


def redos_risky(pat):
    """C9: True if a pattern has a nested-quantifier / alternation-under-quantifier shape."""
    if not isinstance(pat, str):
        return False
    return bool(_NESTED_Q.search(pat) or _ALT_Q.search(pat) or _INNER_Q.search(pat))


def load_rules():
    try:
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            rules = list(json.load(f).get("rules", []))
        # A4: runtime integrity check against the manifest recorded at install.
        # A mismatch means the monitored party may have edited the rules -> do NOT
        # trust them; fall back to the embedded minimal set and say so loudly.
        for base in (os.getcwd(), os.path.dirname(os.getcwd())):
            mp = os.path.join(base, ".psl", "manifest.json")
            if os.path.isfile(mp):
                try:
                    with open(mp, encoding="utf-8") as f:
                        rh = (json.load(f) or {}).get("rules_hash")
                    if rh:
                        with open(RULES_PATH, "rb") as f:
                            live = "sha256:" + hashlib.sha256(f.read()).hexdigest()
                        if live != rh:
                            try:
                                sys.stderr.write("[Antinel] SELF-TAMPERED: rules/default.json differs from the "
                                                 "installed manifest hash; falling back to the embedded minimal "
                                                 "set. Re-run install.py if this update is intentional.\n")
                            except Exception:
                                pass
                            # A16 (2026-09-10): stderr 是唯一出口时，宿主一吞掉，
                            # 防护就从 18 条静默降到 11 条且事后查不到——对一个卖
                            # "证据链"的产品这是最不该出现的失败模式。补一条审计
                            # 记录并镜像到宿主级（ANTINEL_HOST_MIRROR=0 可关，
                            # 回归套件默认关，不污染 home）。
                            try:
                                log_event({"ts": datetime.now().isoformat(timespec="seconds"),
                                           "type": "rules_integrity_fallback", "tool": "-",
                                           "session": "-", "rule_id": "A4",
                                           "decision": "config_fallback", "severity": "critical",
                                           "action": "alert",
                                           "reason": "rules/default.json differs from manifest rules_hash; "
                                                     "fell back to the embedded minimal set",
                                           "expected": rh, "live": live,
                                           "rules_loaded": len(_FALLBACK)}, mirror=True)
                            except Exception:
                                pass
                            return [dict(r) for r in _FALLBACK]
                except Exception:
                    pass
                break
    except Exception as e:
        # 0.16.0 (P0-7): the two fallback paths used to be indistinguishable in
        # the audit log -- "rules tampered" (A4 mismatch above) and "rules
        # unreadable" (here) both degraded to 11 rules with at most one stderr
        # line, and this path did not even get that. They are now separate,
        # fielded events: rules_integrity_fallback vs rules_unreadable_fallback.
        rules = [dict(r) for r in _FALLBACK]
        try:
            sys.stderr.write("[Antinel] WARNING: rules file unreadable (%s); running with the "
                             "embedded minimal set (%d rules). Re-install to restore full coverage.\n"
                             % (type(e).__name__, len(rules)))
        except Exception:
            pass
        try:
            log_event({"ts": datetime.now().isoformat(timespec="seconds"),
                       "type": "rules_unreadable_fallback", "tool": "-",
                       "session": "-", "rule_id": "A4",
                       "decision": "config_fallback", "severity": "critical",
                       "action": "alert",
                       "reason": "rules file unreadable; fell back to the embedded minimal set",
                       "error": type(e).__name__,
                       "rules_loaded": len(rules)}, mirror=True)
        except Exception:
            pass
    by_id = {r["id"]: r for r in rules if r.get("id")}
    # B-03 / G-11: custom.json appended; same id overrides severity/action/enabled only
    for base in (os.getcwd(), os.path.dirname(os.getcwd())):
        p = os.path.join(base, ".psl", "rules", "custom.json")
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            for r in data.get("rules", []):
                rid = r.get("id")
                if rid and rid in by_id:
                    for k in ("severity", "action", "enabled", "deprecated"):
                        if k in r:
                            by_id[rid][k] = r[k]
                elif rid:
                    # C9: a custom rule whose patterns can wedge the hook is dropped
                    # before it ever reaches the matcher. Silent loading here is what
                    # made a 6-character rule enough to disable the whole suite.
                    bad = None
                    for _k in _REDOS_KEYS:
                        for _p in (r.get(_k) or []):
                            if redos_risky(_p):
                                bad = _p
                                break
                        if bad is not None:
                            break
                    if bad is not None:
                        try:
                            sys.stderr.write(
                                "[Antinel] CUSTOM RULE REJECTED %s: nested-quantifier pattern "
                                "(ReDoS risk); rule not loaded: %r\n" % (rid, bad[:80]))
                        except Exception:
                            pass
                        continue
                    rules.append(r)
                    by_id[rid] = r
        except Exception:
            pass
        break
    # C7: guard against pathological custom patterns (ReDoS / memory) - the hook
    # must never be wedged by a rule; over-long patterns are silently dropped.
    for r in rules:
        for key in ("command_patterns", "file_patterns", "content_patterns", "exclude_patterns"):
            pats = r.get(key)
            if isinstance(pats, list):
                keep = [x for x in pats if isinstance(x, str) and len(x) <= 500]
                if len(keep) != len(pats):
                    r[key] = keep
    rules.sort(key=lambda r: CAT_ORDER.get(r.get("category", ""), 9))
    return rules


# ------------------------------------------------- F-06 policy (spec C-05) --
EMPTY_POLICY = {"domains": [], "paths": [], "commands": [], "alert_threshold": "warning"}


def _norm_prefix(p):
    """A12: normalise a whitelist path prefix. Root-like inputs (".", "..", "/",
    "C:\\", "c:") normalise to strings that match *every* path, so a single such
    entry switched off all SEC-* critical rules at once (measured: read .env,
    .aws/credentials and .kube/config all went from block to allow). They are
    rejected here and dropped by the caller."""
    s = (p or "").replace("\\", "/").strip().lower()
    if s in ("", ".", "..", "/"):
        return ""
    s2 = s.lstrip("./")
    if not s2 or s2.endswith(":") or s2.endswith(":/"):
        return ""
    return s2


def _policy_integrity(raw):
    """A12 (policy): rules/default.json is hash-checked by install.py, but policy.json
    -- the file that decides what gets RELEASED -- was not. A whitelist edited out of
    band therefore looked exactly like a legitimate one. This records the hash on
    first sight and reports later changes, turning a silent edit into a visible one.

    It is NOT tamper protection: the state file sits in .psl/ next to the file it
    guards, so anything that can edit one can edit the other. That is the same honest
    level as A4/A11 (detect accidental change, not resist an equal-privilege attacker),
    and it is stated that way on purpose.
    Returns the new hash when the content changed, else None."""
    try:
        h = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()
        st_path = os.path.join(os.getcwd(), ".psl", "policy_state.json")
        prev = None
        if os.path.isfile(st_path):
            try:
                prev = json.load(open(st_path, encoding="utf-8")).get("policy_hash")
            except Exception:
                prev = None
        os.makedirs(os.path.dirname(st_path), exist_ok=True)
        with open(st_path, "w", encoding="utf-8") as f:
            json.dump({"policy_hash": h}, f)
        return None if prev is None or prev == h else h
    except Exception:
        return None


def load_policy():
    """.psl/policy.json (cwd, then parent). Consumed fields (v1.2 semantics):
      whitelist.domains   -> relax NETWORK rules only (NET-01/02 excludes, NET-03 whitelist)
      whitelist.paths     -> path prefixes that skip SECRETS rules (SEC-*), and since
                             0.16.0 also release DST-02 (each release is audit-logged)
      whitelist.commands  -> command prefixes that skip WARNING-level rules only
      global_settings.alert_threshold -> 'warning' (default) or 'critical': stderr notices
                             below the threshold are suppressed; logging and blocking unchanged
    Everything else (desktop_notify, auto_archive, ...) is ignored here."""
    for base in (os.getcwd(), os.path.dirname(os.getcwd())):
        p = os.path.join(base, ".psl", "policy.json")
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                raw = f.read()
            pol = json.loads(raw)
            changed = _policy_integrity(raw)
            if changed and not notice_gate("POLICY-INTEGRITY", changed):
                sys.stderr.write(
                    "[Antinel][配置变更] .psl/policy.json 内容已变化（sha256 %s…）\n"
                    "          白名单/阈值的放行范围随之改变。若非你本人修改，请检查：%s\n"
                    "          确认无误后可忽略；要重置基线请删除 .psl/policy_state.json\n"
                    % (changed[:12], p))
            wl = pol.get("whitelist") or {}
            gs = pol.get("global_settings") or {}
            thr = str(gs.get("alert_threshold", "warning")).lower()
            return {"domains": [d.lower().strip() for d in wl.get("domains") or [] if isinstance(d, str) and d.strip()],
                    "paths": [q for q in (_norm_prefix(x) for x in wl.get("paths") or []
                                         if isinstance(x, str) and x.strip()) if q],
                    "commands": [c for c in wl.get("commands") or [] if isinstance(c, str) and c],
                    "alert_threshold": thr if thr in ("warning", "critical") else "warning"}
        except Exception:
            return dict(EMPTY_POLICY)
    return dict(EMPTY_POLICY)


def apply_policy(rules, policy):
    """whitelist.domains: network rules only. Never touches critical non-network rules."""
    if not policy.get("domains"):
        return rules
    escaped = [re.escape(d) for d in policy["domains"]]
    for r in rules:
        if r.get("category") != "network":
            continue
        r["exclude_patterns"] = list(_patterns(r, "exclude_patterns")) + escaped
        if _field(r, "check") == "domain_whitelist":
            r["whitelist_domains"] = list(_field(r, "whitelist_domains", []) or []) + policy["domains"]
    return rules


def path_whitelisted(file_path, project_root, prefixes):
    if not file_path or not prefixes:
        return False
    cands = [file_path.replace("\\", "/").lower()]
    try:
        rel = os.path.relpath(os.path.abspath(file_path), project_root).replace("\\", "/").lower()
        if not rel.startswith("../"):
            cands.append(rel)
    except Exception:
        pass
    return any(c.startswith(p) for c in cands for p in prefixes)


def command_whitelisted(command, prefixes):
    return bool(command) and any(command.startswith(p) for p in prefixes)


# ------------------------------------------------------ read-only command ctx --
# A false positive we hit twice in one day: `grep 'Remove-Item' hooks/pre_tool_use.py`
# was blocked by DST-01 and `grep 'schtasks' ...` by DST-04. The hook matches the
# command *text*, so merely MENTIONING a dangerous word inside a read-only command
# is indistinguishable from executing it. Developers grep for these words constantly
# -- including the people who build this -- so a hook that cannot tell mention from
# execution gets uninstalled on the first day, and an uninstalled hook stops zero
# attacks. That is the trade being made here, deliberately.
#
# Downgrade rule, and nothing more: if every segment of the command begins with a
# read-only verb and the command contains no way to turn a mention into an execution,
# a *command_patterns* hit is downgraded from block to alert (still logged, still
# counted in report.py). Everything else is untouched:
#   * file/content/check/detection families still block. `grep -r sk- .env` is still
#     blocked by SEC-01's file_patterns, not by this rule.
#   * file_patterns on Bash still see the command text (bash_extra), so reading a
#     secret path is never downgraded.
# Deliberate exclusions -- these are exactly how a mention becomes an execution:
#   backtick $() <() `>` redirect, or any segment whose verb is not read-only
#   (sudo, xargs, eval, source, rm, ...). A chain qualifies only if ALL of it is
#   read-only: `cd src && grep x f` passes, `grep x | xargs rm -f` does not.
# Deliberate exclusions -- write-capable flags on otherwise read-only verbs:
#   find -delete/-exec/...
# Matching is quote-aware: `grep -E "foo|bar" src` has a `|` inside quotes and must
# still be treated as read-only, while `grep x | rm -rf /` must not be.
# Truncated commands (>= MAX_CMD) are never downgraded: the tail we cannot see may
# contain the chain.
# Deliberately absent even though they look read-only, because they can execute:
#   awk  -- system("...") and print | "cmd"
#   sed  -- GNU `s///e` runs the replacement as a shell command
#   fd   -- -x/--exec
# A read-only verb that can reach a shell is not a read-only verb.
_READONLY_CMDS = frozenset("""
grep egrep fgrep rgrep zgrep bzgrep rg ag ack sift
cat bat head tail less more most nl tac od strings
echo                            # `echo x > f` 有 danger 标记兜底，不会因加它而放行写入
ls dir tree wc diff comm cmp file stat du df
find locate which where
cut tr sort uniq join paste expand unexpand split
md5sum sha1sum sha256sum shasum
select-string get-content get-childitem get-item get-acl
cd pwd
""".split())
# find -i is not a thing; sed -i is a write. Scoped per verb to avoid the
# `grep -i` vs `sed -i` collision a single global "-i" check would create.
_WRITE_FLAGS_BY_CMD = {
    "find": ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls"),
    "sed": ("-i", "--in-place"),
}
# Only true fd plumbing (2>&1, &>file). A bare `>` is an output redirect and must
# survive the substitution: `grep -n rm f > out.txt` writes, so it is not read-only.
_FD_REDIRECT_RE = re.compile(r"\d*>&\d*|&>")                # 2>&1, &>file: not a chain


def _scan_command(cmd):
    """Split a command on shell operators that appear OUTSIDE quotes.

    Returns (segments, dangerous). `dangerous` means the command can do more than
    read whatever its verbs are: backticks, $() and <() run a sub-command, and a bare
    `>` writes. Quote awareness is what makes `grep -E "rm|del" f` read-only while
    `grep x | rm -rf` is not. fd plumbing (2>&1, &>file) is stripped first so it is
    not mistaken for a chain."""
    s = _FD_REDIRECT_RE.sub(" ", cmd)
    segs, cur, q, i, n = [], [], None, 0, len(s)
    danger = False
    while i < n:
        c = s[i]
        if q:
            if c == "\\" and q == '"' and i + 1 < n:
                cur.append(s[i + 1])
                i += 2
                continue
            if c == q:
                q = None
            cur.append(c)
            i += 1
            continue
        if c in "\"'":
            q = c
            cur.append(c)
        elif c == "\\" and i + 1 < n:
            cur.append(s[i + 1])
            i += 2
            continue
        elif c in ";\n\r|&":
            segs.append("".join(cur))
            cur = []
            if c == "&" and i + 1 < n and s[i + 1] == "&":
                i += 1
        elif c == "`":
            danger = True
        elif c == "$" and i + 1 < n and s[i + 1] == "(":
            danger = True
            i += 1
        elif c in "<>" and i + 1 < n and s[i + 1] == "(":
            danger = True
            i += 1
        elif c == ">":
            danger = True                                   # output redirect = a write
        else:
            cur.append(c)
        i += 1
    segs.append("".join(cur))
    return [x for x in segs if x.strip()], danger


def _first_token(cmd):
    s = cmd.strip()
    while True:                                             # strip FOO=bar prefixes
        m = re.match(r"^[A-Za-z_][A-Za-z0-9_]*=\S*\s+", s)
        if not m:
            break
        s = s[m.end():]
    if not s:
        return ""
    tok = s.split(None, 1)[0].strip("\"'")
    tok = tok.replace("\\", "/").split("/")[-1]             # C:\tools\grep.exe -> grep
    if tok.lower().endswith(".exe"):
        tok = tok[:-4]
    return tok.lower()


def readonly_command_context(command):
    """True when a dangerous word in this command is a mention, not an execution.

    Every segment must be a read-only verb: `cd src && grep -n x f` is no more
    dangerous than `grep -n x f`, and blocking the first form is exactly how a hook
    gets uninstalled. Conversely `grep x | xargs rm` fails here, because xargs is not
    a read-only verb -- so a chain is only accepted when ALL of it is read-only."""
    if not command or len(command) >= SCAN_LIMIT:
        return False
    segs, danger = _scan_command(command)
    if danger or not segs:
        return False
    for seg in segs:
        tok = _first_token(seg)
        if tok not in _READONLY_CMDS:
            return False
        for flag in _WRITE_FLAGS_BY_CMD.get(tok, ()):
            if re.search(r"(^|\s)" + re.escape(flag) + r"(\s|=|$)", seg, re.IGNORECASE):
                return False
    return True


def _normalize_path(p):
    """Windows 解析路径时会剥掉每个分段的尾部空格与点。

    于是 `Read .env `（尾部一个空格）在规则眼里是 `.env `、`\\.env$` 匹配不上，
    但操作系统真正打开的是 `.env`——实测一个空格就绕过了 SEC-01（2026-09-10）。
    匹配前按同一规则剥掉，让规则看到的就是系统将要打开的那个路径。

    POSIX 下尾随空格是合法文件名，不做剥离（os.name != "nt" 直接返回原值）。
    单个 "." / ".." 分段剥完会变空，保留原样，避免把相对路径弄没。
    """
    if not p or os.name != "nt":
        return p
    sep = "\\" if "\\" in p else "/"
    out = []
    for seg in p.split(sep):
        t = seg.rstrip(" .")
        out.append(t if t else seg)
    return sep.join(out)







# ------------------------------------------------------------------ i18n lite --
_LANG_SUPPORTED = {"zh", "en"}


def _lang():
    """Detect UI language: policy.json > ANTINEL_LANG env > system locale > 'en'."""
    v = os.environ.get("ANTINEL_LANG", "")
    if v in _LANG_SUPPORTED:
        return v
    try:
        import locale
        loc = (locale.getdefaultlocale()[0] or "").lower()
        if loc.startswith("zh"):
            return "zh"
    except Exception:
        pass
    for base in (os.getcwd(), os.path.dirname(os.getcwd())):
        p = os.path.join(base, ".psl", "policy.json")
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                pol = json.load(f)
            lang = (pol.get("language") or "").lower()
            if lang in _LANG_SUPPORTED:
                return lang
        except Exception:
            pass
    return "en"


def _pick(rule, field, lang):
    """Select rule text: top-level {field}_{lang} first, then English, then zh."""
    for l in (lang, "en", "zh"):
        v = rule.get(f"{field}_{l}")
        if v:
            return v
    return rule.get(field, "")

# -------------------------------------------------------------------- helpers --


def command_variants(cmd):
    """Problem list D02-D05: conservative normalisations of shell evasion.

    The ORIGINAL string always participates in matching; variants only ADD
    matches. Variants: de-backslash-word (r\\m -> rm), letter-quote-letter join
    ("r"m -> rm), $'\\x72' hex-decode, same-command variable expansion
    (A=r; B=m; $A$B -> rm). Joined with newlines so cross-variant splices
    cannot create phantom matches."""
    if not cmd or len(cmd) > MAX_CMD:
        # A5/P0-1 boundary: giant commands are fully matched against the ORIGINAL
        # text by the chunked scanner; variant passes only apply to commands within
        # the truncation budget, keeping the 10s hook budget intact (perf ladder
        # B-021..B-023).
        return [cmd]
    out = [cmd]
    out.append(re.sub(r"\\(?=[A-Za-z0-9$])", "", cmd))
    q = out[-1]
    for _ in range(3):
        q2 = re.sub(r"([A-Za-z0-9])['\"]([A-Za-z0-9])", r"\1\2", q)
        if q2 == q:
            break
        q = q2
    out.append(q)
    out.append(re.sub(r"\\[xX]([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), cmd))
    exp = cmd
    assigns = dict(re.findall(r"(?<![=$\w])([A-Za-z_]\w*)=([^;\s]+)", exp))
    if assigns:
        for k in sorted(assigns, key=len, reverse=True):
            exp = exp.replace("$" + k, assigns[k])
        if exp != cmd:
            out.append(exp)
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq

def _search(pat, text):
    """Match `pat` anywhere in `text`, over the WHOLE text.

    P0-1. This used to be `re.search(pat, text)` on a string that had already been
    truncated to MAX_CMD / MAX_CONTENT (256KB / 1MB). Truncating BEFORE matching means
    everything past the cut is never scanned, so a payload only has to be preceded by
    enough padding to become invisible -- no skill required, and it worked on every
    rule at once. Measured: `100KB pad + rm -rf /` blocked, `1MB pad + rm -rf /` allowed.

    Now the text is scanned in OVERLAPPING windows, so padding in front, behind, or in
    the middle no longer hides anything. The windows keep three properties:

      * bounded  -- each re.search sees at most SCAN_CHUNK, which caps the damage of a
                    catastrophic-backtracking pattern (the ReDoS defence survives);
      * total    -- every byte up to SCAN_LIMIT is inside at least one window;
      * overlap  -- a pattern straddling a window edge is still matched whole, as long
                    as it is shorter than SCAN_OVERLAP (our longest rule pattern is
                    under 200 chars, so 4KB is a wide margin).

    SCAN_LIMIT is a byte budget, deliberately not a time budget: a time-based cutoff
    would make the verdict depend on machine load, and a hook that is non-deterministic
    cannot be regression-tested. Past SCAN_LIMIT we scan the HEAD and the TAIL instead
    of the head only: padding in front no longer hides a trailing payload, and padding
    behind no longer hides a leading one.

    预算实测（2026-09-10，端到端含进程启动，8MB 输入）：SCAN_LIMIT=2MB 时 5.2s，
    抬到 4MB 时约 6.6s，预算 9s 尚余约 2.4s——多花约 1.4s 换来"两侧各 1MB 填充"
    这一整类绕过被堵上（B-023 由逃逸变拦截）。现在要绕过需两侧各 >= 2MB 填充，
    且越界时 caller 会记录 `scan_truncated`：没查到的部分要说出来，不能假装查过。
    """
    if not text:
        return None
    rx = _rx(pat)
    if rx is None:
        return None
    n = len(text)
    if n <= SCAN_CHUNK:
        return rx.search(text)
    # Literal prefilter: measured, 1MB of clean text costs ~30ms to scan for literals
    # and ~860ms to run all 28 command patterns over it. A pattern whose literals do not
    # occur in the text cannot match, so skip the regex entirely. Skipping is only ever
    # done when a literal is provably absent, which makes this conservative: a bad
    # literal costs performance, never detection.
    if n >= PREFILTER_MIN and not _PREFILTER_OFF and not _literals_present(pat, text):
        return None
    spans = ((0, n),) if n <= SCAN_LIMIT else ((0, SCAN_LIMIT // 2), (n - SCAN_LIMIT // 2, n))
    step = SCAN_CHUNK - SCAN_OVERLAP
    for lo, hi in spans:
        off = lo
        while off < hi:
            m = rx.search(text, off, min(off + SCAN_CHUNK, hi))
            if m:
                return m
            if off + SCAN_CHUNK >= hi:
                break
            off += step
    return None


_LIT_RE = re.compile(r"[A-Za-z0-9_]{2,}")
_ESCAPE_RE = re.compile(r"\\[A-Za-z0-9\\]")
_CLASS_RE = re.compile(r"\[(?:[^\]\\]|\\.)*\]")     # [A-Za-z0-9+/=], [^\x00-\x1f], ...


def _literals(pat):
    """Alpha-numeric fragments a pattern cannot match without.

    `\\bshutil\\.rmtree\\b` -> {'shutil', 'rmtree'}; `\\bat\\s+\\d{1,2}:` -> {'at'}.
    Short common fragments ('at', 'rd') make the prefilter permissive rather than
    wrong -- they cost speed, never detection.
    """
    if pat in _LIT_CACHE:
        return _LIT_CACHE[pat]
    # Two syntax forms must be stripped before tokenising, or the prefilter silently
    # invents literals that are not real and then skips a pattern that should have run:
    #   1. character classes -- `[A-Za-z0-9+/=]{200,}` tokenises to {'z0','za'}, so a
    #      base64 blob containing neither is never tested by the base64 rule at all;
    #   2. escape sequences -- `\brm\b` tokenises to {'brm'} (the \b is read as a
    #      letter), which made DST-01 miss on every command.
    # Both are *under*-approximations of what could match. Strip them and what is left
    # is a conservative literal set: a miss here costs speed, never detection.
    s = _CLASS_RE.sub(" ", pat)
    s = _ESCAPE_RE.sub(" ", s)
    toks = {t.lower() for t in _LIT_RE.findall(s) if not t.isdigit()}
    _LIT_CACHE[pat] = toks
    return toks


def _lower_cached(text):
    """lower() once per text object. Holds a strong reference, so the id we key on
    cannot be recycled while the entry is live."""
    c = _LC_CACHE
    if c[0] is text:
        return c[1]
    lc = text.lower()
    c[0] = text
    c[1] = lc
    return lc


def _literals_present(pat, text):
    toks = _literals(pat)
    if not toks:
        return True                     # no literal to test: run the regex
    lc = _lower_cached(text)
    for t in toks:
        if t in lc:
            return True
    return False


def scan_truncated(*texts):
    """True when some input was longer than SCAN_LIMIT and therefore only partly scanned."""
    return any(t and len(t) > SCAN_LIMIT for t in texts)


def _disabled(rule):
    # 0.17.0 (P-B7): `deprecated: true` retires a rule without deleting it --
    # it stays visible in rules/RULES.md and in the audit of its retirement,
    # but it never fires. Same fail-direction as `enabled: false`.
    return rule.get("enabled") is False or rule.get("deprecated") is True


def _applies(rule, tool):
    tools = rule.get("apply_to_tools") or []
    return (not tools) or (tool in tools)


def _excluded(rule, texts):
    for pat in _patterns(rule, "exclude_patterns"):
        for t in texts:
            if t and _search(pat, t):
                return True
    return False


def _command_segment_forced(rule, command):
    """P0（2026-09-10 实测）：命令类豁免必须**逐段**判定，不能按整条命令判定。

    原实现是 `_excluded(rule, [command, file_path, content, url])`——只要命令任意
    位置出现豁免词，整条命令连同链上的真破坏一起放行。实测：

        rm -rf dist && rm -rf /home/x     -> rc=0 放行
        rm -rf /home/x && rm -rf dist     -> rc=0 放行
        rm -rf dist; rm -rf /etc          -> rc=0 放行

    豁免词原本只有 .psl / .git / node_modules 三个，FP-101 又补进 12 个开发者天天敲
    的目录名（dist/build/venv/target/...），这条绕过的使用成本由此降为零。

    逐段判定：任一段命中 command_patterns、该段自身不在豁免内、且该段不是"只读提及"
    （复用 readonly_command_context，所以 `echo "rm -rf /" && rm -rf dist` 不误伤）
    -> 整条命令不得走豁免。

    已知边界：命令长度 >= SCAN_LIMIT 时无法安全分段，退回原行为（与其他 SCAN_LIMIT
    边界一致，登记在案）。
    """
    pats = _patterns(rule, "command_patterns")
    if not pats or not command or len(command) >= SCAN_LIMIT:
        return False
    try:
        segs, _danger = _scan_command(command)
    except Exception:
        return False
    excl = _patterns(rule, "exclude_patterns")
    for seg in segs:
        if not seg or not seg.strip():
            continue
        if not any(_search(p, seg) for p in pats):
            continue
        if excl and any(_search(p, seg) for p in excl):
            continue                       # 这一段本身就是豁免里的日常命令
        if readonly_command_context(seg):
            continue                       # 只是"提及"（echo/grep 参数里的危险词）
        return True                        # 有一段真命中且不该被豁免 -> 不许放行整条
    return False


def _first_hit(patterns, texts):
    """Returns (pattern, matched_snippet) for the first pattern that matches any text."""
    for pat in patterns:
        for t in texts:
            if not t:
                continue
            m = _search(pat, t)
            if m:
                return pat, m.group(0)
    return None


# ------------------------------------------------- workspace roots (host level) --
# Antinel assumed the trust boundary is one project root. Real work spans a set of
# workspaces (code in D:\psl\poc, strategy docs in D:\2026\PSL), so writing outside
# the project root was blocked even for the user's own second workspace -- and the
# only escape was uninstalling the hooks, which is worse than any false positive.
#
# workspace_roots widens the boundary, not the rule: DST-02 still blocks every
# write outside the declared set. Three constraints make it safe:
#   1. the file lives at host level (~/.workbuddy/antinel.json), NOT under .psl/ --
#      an agent that wants to widen it must write outside the project, which DST-02
#      itself blocks, so the config is protected by the rule it configures;
#   2. root-like, relative, ".." and wildcard entries are rejected at load time --
#      otherwise one entry ("C:\") re-creates the A12 failure mode where a single
#      prefix switched off all critical rules;
#   3. every allow that a workspace root causes is written to the audit log, so the
#      widening is visible after the fact instead of silent.
WORKSPACE_CONFIG_NAME = "antinel.json"


def _workspace_config_paths():
    """Host-level config, highest priority first. ANTINEL_CONFIG exists so the
    regression suite can point at a fixture without touching the real one."""
    out = []
    env = os.environ.get("ANTINEL_CONFIG")
    if env:
        out.append(os.path.expanduser(env))
    cd = os.environ.get("WORKBUDDY_CONFIG_DIR")
    if cd:
        out.append(os.path.join(os.path.expanduser(cd), WORKSPACE_CONFIG_NAME))
    home = os.path.expanduser("~")
    out.append(os.path.join(home, ".workbuddy", WORKSPACE_CONFIG_NAME))
    out.append(os.path.join(home, ".antinel.json"))
    return out


def _valid_workspace_root(p):
    """Return the normalised root, or "" if the entry must be rejected.

    Rejected: relative paths (nothing to anchor against), any ".." segment,
    wildcards, drive roots ("C:\\", "c:/"), bare UNC server roots, and anything
    whose normalised form is empty. Existing-directory is NOT required -- a
    workspace may legitimately not exist yet."""
    if not isinstance(p, str) or not p.strip():
        return ""
    s = p.strip().strip('"')
    if not os.path.isabs(s):
        return ""
    if any(c in s for c in "*?<>"):
        return ""
    # ".." is checked on the RAW input, before normpath: normpath collapses
    # "D:\a\..\b" to "D:\b", so a post-normalisation check never sees it and
    # would silently widen the root to a different directory than declared.
    if ".." in s.replace("\\", "/").split("/"):
        return ""
    n = os.path.normpath(s)
    if n.startswith("\\\\"):                      # UNC: need more than \\server
        parts = [x for x in n[2:].split("\\") if x]
        if len(parts) < 2:
            return ""
    else:
        _, tail = os.path.splitdrive(n)
        if tail in ("", "\\", "/"):               # drive root
            return ""
    return n.rstrip("\\/") or ""


def load_workspace_roots():
    """Read workspace_roots from the first host-level config file that exists.
    Returns (roots, source, rejected) -- rejected entries are reported so a typo
    fails loudly instead of silently disabling protection."""
    for path in _workspace_config_paths():
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            return [], path, []
        raw = cfg.get("workspace_roots") if isinstance(cfg, dict) else None
        if not isinstance(raw, list):
            return [], path, []
        roots, rejected = [], []
        for item in raw:
            v = _valid_workspace_root(item)
            if v:
                if v.lower() not in [r.lower() for r in roots]:
                    roots.append(v)
            else:
                rejected.append(item if isinstance(item, str) else repr(item))
        return roots, path, rejected
    return [], "", []


def _safe_realpath(p):
    """realpath 会解析符号链接，Windows 上遇到 UNC 路径会真的去连那台机器。

    实测（2026-09-10）：`Write` 到 `\\\\server\\share\\f.txt` 单次耗时 **5.99s**
    ——SMB 超时的量级。钩子总预算 10s，一条网络路径就能吃掉一大半；服务器不可达时
    更可能直接超时，而超时即放行（fail open）。UNC 路径跳过解析，退回
    normpath（不解析链接，但也不碰网络）；本地路径仍走 realpath，保留符号链接防护。
    """
    s = str(p or "")
    if os.name == "nt" and s.startswith("\\\\"):
        return os.path.normpath(s).rstrip(os.sep).lower()
    return os.path.realpath(s).rstrip(os.sep).lower()


def _matching_root(path, roots):
    """Which workspace root contains `path`, or None."""
    if not path or not roots:
        return None
    try:
        rp = _safe_realpath(path)
    except Exception:
        return None
    for r in roots:
        try:
            rr = _safe_realpath(r)
        except Exception:
            continue
        if rr and (rp == rr or rp.startswith(rr + os.sep)):
            return r
    return None


# ------------------------------------------------------ G-04: project root ----
def find_project_root():
    d = os.getcwd()
    for _ in range(6):
        if os.path.isdir(os.path.join(d, ".psl")) or os.path.isdir(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return os.getcwd()


def check_outside_root(path, root, extra_roots=()):
    """True when `path` is outside the project root AND outside every declared
    workspace root. extra_roots is what makes workspace_roots work: the boundary
    becomes a set of roots instead of one."""
    if not path:
        return False
    try:
        p = path if os.path.isabs(path) else os.path.join(root, path)
        rp = _safe_realpath(p)
        for r in [root] + list(extra_roots or ()):
            rr = _safe_realpath(r)
            if rr and (rp == rr or rp.startswith(rr + os.sep)):
                return False
        return True
    except Exception:
        return False


# 0.17.0 (P-A4): the Bash channel has no file_path, so DST-02's check never
# fires there -- a script that writes/deletes outside the root is invisible to
# the boundary check (measured 2026-09-11: six shapes, all through). We do NOT
# parse script contents (that would be a sandbox promise we cannot keep -- see
# THREAT_MODEL "Non-goals"), but EXPLICIT absolute paths in the command text are
# cheap to surface. Recorded as an alert, never a block: `echo x > /tmp/a` is
# everyday AI-coding traffic, and blocking it would destroy the signal/noise
# ratio. This closes the "afterwards unfindable" half of the finding, not the
# "not blocked" half -- that half is a documented boundary.
_BASH_ABS_PATH_RE = re.compile(
    r"(?:\b[A-Za-z]:[\\/][^\s\"'`|;&<>)\]]+|(?<![\w~/])\/(?:[A-Za-z0-9._-]+\/){1,}[A-Za-z0-9._-]+)")
# POSIX pseudo-devices: redirect targets like /dev/null are everyday noise, not
# boundary events (the first build of this regex flagged every `2>/dev/null`).
_BASH_PATH_SKIP_PREFIXES = ("/dev/", "/proc/", "/sys/")


def _bash_absolute_paths(command):
    """Explicit absolute paths (Windows drive / POSIX multi-segment) in command text.

    Capped at the first 8 distinct candidates, each at most 200 chars: every
    candidate costs a realpath in the boundary check, and a padded command can
    carry multi-hundred-KB "paths" (measured: one 2MB token cost +2.5 s on
    corpus B-023 -- real paths are short; padded ones are attack noise)."""
    if not command or len(command) >= SCAN_LIMIT:
        return []
    out = []
    for m in _BASH_ABS_PATH_RE.finditer(command):
        if len(out) >= 8:
            break
        p = m.group(0).rstrip(".,;:")
        if len(p) > 200:
            continue
        if any(p.replace("\\", "/").lower().startswith(q) for q in _BASH_PATH_SKIP_PREFIXES):
            continue
        if p not in out:
            out.append(p)
    return out


# --------------------------------------------- G-05/G-09: invisible Unicode ----
_INVIS_RE_CACHE = {}


def _invisible_re(ranges):
    """A13: compile the invisible-codepoint class once; matching then runs in C.
    Built with chr() rather than a \\uXXXX escape: the first range is
    U+E0000-U+E007F (TAG characters), a supplementary-plane range whose hex form
    is 5 digits, and "%04x" silently produced \\ue0000 -- which re parsed as
    U+E000 followed by a literal '0', turning the class into '0-\\ue007' and
    matching nearly every ASCII character. Every path with a drive letter was
    then reported as an invisible-character attack."""
    key = tuple(ranges)
    rx = _INVIS_RE_CACHE.get(key)
    if rx is None:
        parts = []
        for lo, hi in ranges:
            parts.append(re.escape(chr(lo)) if lo == hi
                         else re.escape(chr(lo)) + "-" + re.escape(chr(hi)))
        rx = re.compile("[" + "".join(parts) + "]")
        _INVIS_RE_CACHE[key] = rx
    return rx


def scan_invisible(text, ranges=None, whitelist=None):
    """CTX-03. Whitelist (B-02): ZWJ U+200D anywhere; BOM U+FEFF only at offset 0.
    A13: was a per-character Python loop -- 5MB of content cost 6.9s here alone,
    which is most of the 10s hook budget (and a timeout means the tool runs).
    Now a single C-level regex pass; content is also capped before we get here."""
    ranges = ranges or INVISIBLE_RANGES
    wl = set(whitelist or []) | {"\u200d"}
    for m in _invisible_re(ranges).finditer(text or ""):
        i = m.start()
        ch = m.group(0)
        if ch in wl or (ch == "\ufeff" and i == 0):
            continue
        return "U+%04X at offset %d" % (ord(ch), i)
    return None


# ------------------------------------------------------------ NET-03 domains --
def check_domains(cmd, whitelist):
    hosts = []
    text = cmd or ""
    for m in _DOMAIN_RE.finditer(text):
        host = m.group(1).lower().rstrip(".")
        tld = host.rsplit(".", 1)[-1]
        prefix = text[max(0, m.start() - 3):m.start()]
        in_url = prefix.endswith("://") or prefix.endswith("@") or host.startswith("www.")
        if not in_url and (tld in FILE_EXTS or tld not in KNOWN_TLDS):
            continue
        if any(host == w or host.endswith("." + w) for w in whitelist):
            continue
        if host not in hosts:
            hosts.append(host)
    return hosts


# ------------------------------------------------------------ CTX-05 metadata --
def frontmatter_name(text):
    m = re.search(r"^---\s*\n(.*?)\n---", text or "", re.DOTALL)
    if not m:
        return None
    nm = re.search(r"^name:\s*['\"]?([^'\"\n]+)['\"]?\s*$", m.group(1), re.MULTILINE)
    return nm.group(1).strip() if nm else None


# --------------------------------------------------------- event extraction ----
# Host adaptation layer (spec A-03 / U-41, second-batch addition).
# Claude Code and ZCode share the identical wire format (verified). Qoder and
# TRAE are declared profiles: field aliases are best-effort and fall back to
# the Claude Code layout; each is marked verified=False until its harness is
# confirmed (Qoder: open-source harness; TRAE: on-device probe pending).
HOST_ADAPTERS = {
    "claude-code": {"verified": True,
                    "command": ("Bash", "command"),
                    "file_path": (("Read", "Write", "Edit", "MultiEdit", "NotebookEdit"),
                                  "file_path", "path", "notebook_path"),
                    "content": {"Write": ("content", "new_source"), "Edit": ("old_string", "new_string"),
                                "NotebookEdit": ("new_source",)},
                    "url": (("WebFetch",), "url", "query"),
                    "pattern": (("Glob", "Grep"), "pattern")},
    "zcode":       {"verified": True},                      # identical to claude-code
    "qoder":       {"verified": False},                     # falls back to claude-code
    "trae":        {"verified": False,
                    "command": ("Bash", "command", "cmd"),  # alias candidate, unverified
                    "file_path": (("Read", "Write", "Edit"), "file_path", "path", "file")},
    "generic":     {"verified": True},
}


def detect_host_tag():
    """Cheap host tag for adapter selection; project markers beat env vars."""
    cwd = os.getcwd()
    for d, tag in ((".claude", "claude-code"), (".zcode", "zcode"), (".qoder", "qoder"), (".trae", "trae")):
        if os.path.isdir(os.path.join(cwd, d)):
            return tag
    if os.environ.get("CLAUDE_CODE"):
        return "claude-code"
    if os.environ.get("ZCODE_SESSION"):
        return "zcode"
    if os.environ.get("QODER"):
        return "qoder"
    if os.environ.get("TRAE"):
        return "trae"
    return "generic"


def extract(tool_name, ti, host_tag="generic"):
    """Extract (command, file_path, content, url) from tool_input for the host's layout."""
    ti = ti or {}
    raw_tool = tool_name
    tool_name = TOOL_ALIASES.get(tool_name, tool_name)      # A9 canonical tool name (rules apply)
    if raw_tool == "MultiEdit":
        pass                                                 # handled below via edits[] vector
    ad = HOST_ADAPTERS.get("claude-code" if host_tag == "zcode" else host_tag) or HOST_ADAPTERS["claude-code"]
    if not ad.get("verified") and "command" not in ad:
        ad = HOST_ADAPTERS["claude-code"]                   # unverified profile: CC fallback
    cc = HOST_ADAPTERS["claude-code"]

    def first(*keys):
        for k in keys:
            v = ti.get(k)
            if v:
                return v
        return ""

    ckeys = ad.get("command", cc["command"])[1:]
    cmd = first(*ckeys) if tool_name == "Bash" else ""       # P0-1: no pre-cut
    ftools, *fkeys = ad.get("file_path", cc["file_path"])
    fpath = _normalize_path(first(*fkeys)) if tool_name in ftools else ""
    content = ""
    ckeys_by_tool = ad.get("content", cc["content"])
    if raw_tool == "MultiEdit":                             # A9: edits[] vector
        edits = ti.get("edits") or []
        content = "\n".join(
            (e.get("old_string", "") or "") + "\n" + (e.get("new_string", "") or "")
            for e in edits if isinstance(e, dict))
    elif tool_name in ckeys_by_tool:
        content = "\n".join((ti.get(k, "") or "") for k in ckeys_by_tool[tool_name])
    # A13: content used to be uncapped -- a 20MB Write matched for 14.5s and a
    # 30MB one for 22.5s, both past the 10s hook timeout (timeout == allow).
    # P0-1: the cap moved from "cut then match" to the bounded-window scan in _search,
    # so this is now only a memory guard, not a visibility limit.
    if len(content) > SCAN_LIMIT:
        content = content[:SCAN_LIMIT]
    url = ""
    if tool_name in ("WebFetch", "WebSearch"):
        url = first("url", "query")
    elif tool_name in ("Glob", "Grep"):
        url = first("pattern")
    elif tool_name not in ("Bash", "Read", "Write", "Edit"):
        try:
            url = json.dumps(ti, ensure_ascii=False)
        except Exception:
            url = ""
    return cmd, fpath, content, url


def file_text_targets(tool_name, file_path, content):
    """[(target_spec, text)] whose content file_content rules inspect.
    Read: text is loaded from disk (capped, binary skipped). Write/Edit: event content."""
    if not file_path:
        return []
    base = os.path.basename(file_path)
    spec = "SKILL.md" if base == "SKILL.md" else (
        "all_text_files" if base.lower().endswith(TEXT_EXTS) or base.startswith(".env") else None)
    if spec is None:
        return []
    if tool_name == "Read":
        try:
            with open(file_path, "rb") as f:
                raw = f.read(MAX_READ)
            if b"\x00" in raw[:1024]:
                return []
            return [(spec, raw.decode("utf-8", errors="replace"))]
        except Exception:
            return []
    if tool_name in ("Write", "Edit") and content:
        return [(spec, content)]
    return []


# ---------------------------------------------------------------- logging ----
# A3: the audit log must not become a secret store. Same pattern family as the
# PostToolUse OUT-01 check; applied to every persisted command / snippet.
MASK_PATTERNS = [
    r"\bsk-[A-Za-z0-9_\-]{8,}",
    r"\bgh[pousr]_[A-Za-z0-9]{8,}",
    r"\bAKIA[0-9A-Z]{8,}",
    r"\bxox[baprs]-[A-Za-z0-9\-]{8,}",
    r"\bAIza[0-9A-Za-z_\-]{8,}",
    r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?[A-Za-z0-9_\-.=/+]{8,}",
    r"(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_/+=\-]{8,}",
    # A14: the PostToolUse OUT-01 check already flags private keys in tool *output*,
    # so warning about one while writing it verbatim into our own audit log was
    # self-contradictory. Same pattern family, applied to persisted input.
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
]


def mask_secrets(text):
    for pat in MASK_PATTERNS:
        try:
            text = re.sub(pat, lambda m: m.group(0)[:4] + "[已脱敏]", text)
        except re.error:
            continue
    return text


def content_digest(tool_name, tool_input):
    """Spec 2.8 recomputable digest: sha256 over the canonical JSON of
    {"tool_name", "tool_input"} (sort_keys, compact separators, UTF-8, no ASCII
    escaping). A third party holding the host transcript can recompute it."""
    try:
        canon = json.dumps({"tool_name": tool_name, "tool_input": tool_input},
                           sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()
    except Exception:
        return ""




def _chain_fields(fn, rec):
    """L10 audit chain: rec["hash"] = sha256(prev_hash + canonical_json(rec)),
    rec["prev"] = last 16 hex of the previous record's hash ("" for first).
    Anyone can recompute the chain offline; any edit/delete breaks it."""
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


def _append_locked(fn, line):
    """A8: cross-process append serialised with a lockfile; after ~100ms of
    contention we append anyway (a lost line beats a broken host)."""
    lock = fn + ".lock"
    for _ in range(50):
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            break
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(lock) > 5:
                    os.remove(lock)                  # stale lock: steal it
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


def log_event(rec, mirror=False):
    """Append one audit record. Returns True when the project-local write was
    VERIFIED (read back and re-parsed), False otherwise.

    0.17.0 (P-A5): a security product whose evidence log can silently fail must
    at least SAY so. The write is now read back and re-parsed; on any failure
    stderr gets AUDIT_WRITE_FAILED (visible, grep-able) instead of the old bare
    `except: pass`. Whether a lost audit line should also BLOCK the tool call
    is a policy choice: `global_settings.fail_closed_on_audit_loss` (default
    false -- a guardrail must not take the host down because its own log
    directory is read-only)."""
    ok = False
    try:
        d = os.path.join(os.getcwd(), ".psl", "audit")
        os.makedirs(d, exist_ok=True)
        fn = os.path.join(d, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
        rec = _chain_fields(fn, rec)
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        _append_locked(fn, line)
        with open(fn, "rb") as f:                        # write-then-read-back
            f.seek(max(0, os.path.getsize(fn) - len(line.encode("utf-8")) - 8))
            # newline-agnostic: _append_locked writes TEXT mode, so Windows
            # stores \r\n -- compare on normalized tails (first build of this
            # check compared \n against \r\n and flagged every write).
            tail = f.read().decode("utf-8", errors="replace").replace("\r\n", "\n").rstrip("\n")
        ok = bool(tail) and tail.rsplit("\n", 1)[-1] == line.rstrip("\n") \
            and isinstance(json.loads(tail.rsplit("\n", 1)[-1]), dict)
    except Exception:
        ok = False
    if not ok:
        try:
            sys.stderr.write("[Antinel] AUDIT_WRITE_FAILED: this event's audit record "
                             "could not be written/read back; the action proceeded "
                             "(fail-open). Set global_settings.fail_closed_on_audit_loss "
                             "= true in .psl/policy.json to make audit loss block.\n")
        except Exception:
            pass
    # A15: `.psl/audit/` is inside the project, so `rm -rf .psl` -- whitelisted by
    # DST-01 -- erases the record that says it happened. The mirror lives at host
    # level, outside every project; an agent cannot write there without tripping
    # DST-02. Not a duplicate for report.py: report reads .psl/audit only, so this
    # is forensics, not a second source of truth. ANTINEL_HOST_MIRROR=0 opts out
    # (regression suite must not write to the developer's home).
    if not mirror:
        return ok
    try:
        d = _host_audit_dir()
        if d:
            os.makedirs(d, exist_ok=True)
            fn = os.path.join(d, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
            _append_locked(fn, json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
    return ok


def _host_audit_dir():
    if os.environ.get("ANTINEL_HOST_MIRROR") == "0":
        return None
    cd = os.environ.get("WORKBUDDY_CONFIG_DIR")
    base = os.path.expanduser(cd) if cd else os.path.join(os.path.expanduser("~"), ".workbuddy")
    return os.path.join(base, "antinel-audit")


def notice_gate(rule_id, snippet):
    """UX: identical alert (rule + snippet) notifies once per day; repeats are
    silently logged. State lives in .psl/notify_state.json (today's keys only)."""
    today = datetime.now().strftime("%Y-%m-%d")
    key = rule_id + "|" + re.sub(r"\s+", " ", snippet)[:60]
    try:
        p = os.path.join(os.getcwd(), ".psl", "notify_state.json")
        st = {}
        if os.path.isfile(p):
            try:
                st = json.load(open(p, encoding="utf-8"))
            except Exception:
                st = {}
        st = {k: v for k, v in st.items() if v == today}
        sup = st.get(key) == today
        if not sup:
            st[key] = today
            try:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(st, f, ensure_ascii=False)
            except Exception:
                pass
        return sup
    except Exception:
        return False


def emit_block(rule_id, reason, json_stdout=True):
    """Dual channel for hosts that parse stdout JSON (Claude Code, A-01). For ZCode
    the stdout schema is strict (unknown keys invalidate the result), so we emit
    NOTHING on stdout and rely on the exit-2 + stderr channel only."""
    if json_stdout:
        try:
            print(json.dumps({"decision": "block", "reason": reason}, ensure_ascii=False))
        except Exception:
            pass
    try:
        sys.stderr.write(reason + "\n")
    except Exception:
        pass
    sys.exit(2)


# ------------------------------------------------- G-06: multi-hit collection --
def collect_hits(rules, tool_name, texts, project_root, file_targets, policy=None,
                 workspace_roots=(), ws_allow_log=None, excluded_log=None,
                 path_wl_log=None, bash_path_log=None):
    """Run every enabled, applicable rule against the event; return ALL hits.

    Match families (all fields read from the rule top level, G-12):
      command_patterns  -> command, url
      file_patterns     -> file_path, plus command for Bash (cat .env, cat ~/.ssh/id_rsa)
      content_patterns  -> tool_call rules: content, command, url
                           file_content rules (CTX-02/04): text of target files
      check             -> path_outside_project_root (DST-02) | domain_whitelist (NET-03)
      detection         -> character_code_scan (CTX-03): command, path, content, file text
      type metadata_check (CTX-05): SKILL.md frontmatter name vs directory name
    Policy (F-06, spec C-05): whitelist.paths skips SECRETS rules for matching paths
    and, since 0.16.0, also releases DST-02 for matching paths (a legitimate write
    to the platform's own agent directory must be reachable without editing the
    policy first) -- but a policy-released DST-02 is recorded via path_wl_log, so
    the allow is traceable in report.py, never silent.
    whitelist.commands skips WARNING-level rules for matching command prefixes;
    critical non-network rules are never relaxed by policy.
    """
    policy = policy or EMPTY_POLICY
    command = texts.get("command", "")
    file_path = texts.get("file_path", "")
    content = texts.get("content", "")
    url = texts.get("url", "")
    bash_extra = [command] if tool_name == "Bash" else []
    hits = []
    path_wl = path_whitelisted(file_path, project_root, policy.get("paths"))
    cmd_wl = command_whitelisted(command, policy.get("commands"))
    # Read-only context: see readonly_command_context. Only command_patterns hits are
    # affected; the file/content/check/detection families below keep their strength.
    ro_cmd = readonly_command_context(command)

    for rule in rules:
        if _disabled(rule) or not _applies(rule, tool_name):
            continue
        if path_wl and rule.get("category") == "secrets":
            continue
        if cmd_wl and (rule.get("severity") or "warning").lower() != "critical":
            continue
        if (_excluded(rule, [command, file_path, content, url])
                and not _command_segment_forced(rule, command)):
            # A15: the rule matched but an exclude_patterns entry let it through
            # (`rm -rf .psl`, `rm -rf node_modules`). This is the only place that
            # knows an allow was a decision and not an absence, so it is recorded
            # here and mirrored to host level by main().
            if excluded_log is not None and rule.get("severity") == "critical":
                excluded_log.append(rule.get("id", "?"))
            continue

        rtype = rule.get("type") or "tool_call"
        detection = rule.get("detection") or ("character_code_scan" if rtype == "invisible_unicode" else None)
        check = _field(rule, "check")
        hit = None          # (snippet, kind)

        # 1. command family
        r = _first_hit(_patterns(rule, "command_patterns"),
                       command_variants(command) + [url])
        if r:
            hit = (r[1], "command")
        # 2. file family
        if hit is None:
            r = _first_hit(_patterns(rule, "file_patterns"), [file_path] + bash_extra)
            if r:
                hit = (r[1], "path")
        # 3. content family
        if hit is None and detection is None:
            pats = _patterns(rule, "content_patterns")
            if rtype == "file_content":
                target = rule.get("target")
                for spec, text in file_targets:
                    if target not in (None, spec, "all_text_files"):
                        continue
                    r = _first_hit(pats, [text])
                    if r:
                        hit = (r[1], "file_content")
                        break
            else:
                r = _first_hit(pats, [content, url] + bash_extra)
                if r:
                    hit = (r[1], "content")
        # 4. special checks
        if hit is None and check == "path_outside_project_root":
            if check_outside_root(file_path, project_root, workspace_roots):
                if path_wl and file_path:
                    # 0.16.0 (P1-7): whitelist.paths releases DST-02 for the
                    # listed prefixes (e.g. the platform's own agent directory).
                    # Deliberate: recorded, never silent.
                    if path_wl_log is not None:
                        path_wl_log.append(file_path)
                else:
                    hit = (file_path, "path_outside_project_root")
            elif tool_name == "Bash" and bash_path_log is not None and command:
                # 0.17.0 (P-A4): surface explicit out-of-root absolute paths in
                # Bash commands as alerts. Never a block (see _bash_absolute_paths).
                for cand in _bash_absolute_paths(command):
                    if check_outside_root(cand, project_root, workspace_roots) and cand not in bash_path_log:
                        bash_path_log.append(cand)
            elif ws_allow_log is not None and file_path and workspace_roots:
                # Allowed only because a workspace root covers it -- and it would
                # have been blocked without them. Record it (constraint 3).
                r = _matching_root(file_path, workspace_roots)
                if r is not None and check_outside_root(file_path, project_root):
                    ws_allow_log.append(r)
        if hit is None and check == "domain_whitelist":
            bad = check_domains(command, _field(rule, "whitelist_domains", []) or [])
            if bad:
                hit = (", ".join(bad), "domain_whitelist")
        # 5. invisible Unicode (CTX-03): command / path / content / file text
        if hit is None and detection == "character_code_scan":
            ranges = [(int(x["start"]), int(x["end"])) for x in rule.get("ranges", [])] or None
            wl = rule.get("whitelist_chars") or []
            probe = [(command, "command"), (file_path, "path"), (content, "content")] + \
                    [(t, "file_content") for _, t in file_targets]
            for text, kind in probe:
                found = scan_invisible(text, ranges, wl)
                if found:
                    hit = (found, "invisible_" + kind)
                    break
        # 6. metadata (CTX-05): SKILL.md frontmatter name == directory name
        if hit is None and rtype == "metadata_check":
            for spec, text in file_targets:
                if spec != "SKILL.md":
                    continue
                name = frontmatter_name(text)
                dname = os.path.basename(os.path.dirname(os.path.abspath(file_path))) if file_path else ""
                if name is not None and dname and name.lower() != dname.lower():
                    hit = (name + " != " + dname, "metadata")
                    break

        if hit is None:
            continue
        sev = (rule.get("severity") or "warning").lower()
        action = (rule.get("action") or ("block" if sev == "critical" else "alert")).lower()
        entry = {"rule_id": rule.get("id", "?"),
                 "severity": sev,
                 "action": action,
                 "match_kind": hit[1],
                 "match_snippet": mask_secrets(str(hit[0]))[:120],
                 "description": rule.get("description", ""),
                 "description_zh": rule.get("description_zh", ""),
                 "remediation_zh": rule.get("remediation_zh", "")}
        if action == "block" and hit[1] == "command" and ro_cmd:
            # Mentioned, not executed. Downgraded instead of dropped: the hit is still
            # logged and still counted, so a pattern of "grep for dangerous things"
            # remains visible in report.py instead of vanishing.
            entry["action"] = "alert"
            entry["downgraded_from"] = "block"
            entry["downgrade_reason"] = "read-only command context"
        hits.append(entry)
    return hits


# ------------------------------------------------------------------- main -----
def main():
    try:  # utf-8 in/out determinism (host decoders expect utf-8)
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    try:
        event = json.loads(raw)
    except Exception:
        try:
            sys.stderr.write("INVALID_INPUT\n")
        except Exception:
            pass
        sys.exit(0)                                     # A-08: allow on parse failure

    raw_tool = event.get("tool_name", "") or ""
    tool_name = TOOL_ALIASES.get(raw_tool, raw_tool)        # A9
    tool_input = event.get("tool_input") or {}
    session_id = event.get("session_id", "") or ""
    project_root = find_project_root()
    workspace_roots, ws_source, ws_rejected = load_workspace_roots()
    host_tag = detect_host_tag()

    cmd, fpath, content, url = extract(raw_tool, tool_input, host_tag)
    texts = {"command": cmd, "file_path": fpath, "content": content, "url": url}
    file_targets = file_text_targets(tool_name, fpath, content)

    policy = load_policy()
    ws_allow_log = []
    excluded_log = []
    path_wl_log = []
    bash_path_log = []
    hits = collect_hits(apply_policy(load_rules(), policy), tool_name, texts, project_root,
                        file_targets, policy, workspace_roots=workspace_roots,
                        ws_allow_log=ws_allow_log, excluded_log=excluded_log,
                        path_wl_log=path_wl_log, bash_path_log=bash_path_log)
    hits.sort(key=lambda h: SEV_RANK.get(h["severity"], 9))       # stable: keeps category order
    blocking = [h for h in hits if h["action"] == "block"]
    decision = "block" if blocking else ("alert" if hits else "allow")

    ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    base = {"ts": ts, "type": "pre_tool_use", "tool": raw_tool, "session": session_id, "host": host_tag,
            "input": {"command": mask_secrets(cmd)[:500],
                      # A14: file_path used to be persisted verbatim, so a key like
                      # "C:\p\sk-Abc123....pem" landed in the audit log in the clear.
                      # Only the persisted copy is masked -- matching still sees the
                      # original path (texts above), so detection is unaffected.
                      "file_path": mask_secrets(fpath),
                      "content_len": len(content)},
            "content_digest": content_digest(tool_name, tool_input)}
    # Constraint 3: an allow caused by workspace_roots is recorded, never silent.
    for r in ws_allow_log:
        log_event({"ts": ts, "type": "workspace_root_allow", "tool": raw_tool, "session": session_id,
                   "host": host_tag, "rule_id": "DST-02", "decision": "allow",
                   "reason": "path inside a declared workspace root",
                   "matched_root": r, "config_source": ws_source,
                   "input": {"file_path": mask_secrets(fpath)}}, mirror=True)
    # A15: an allow caused by exclude_patterns (`rm -rf .psl`) is mirrored to host
    # level, because the project-local copy dies with the directory being deleted.
    for rid in excluded_log:
        log_event({"ts": ts, "type": "exclude_patterns_allow", "tool": raw_tool,
                   "session": session_id, "host": host_tag, "rule_id": rid,
                   "decision": "allow", "severity": "critical", "action": "allow",
                   "reason": "matched a critical rule but released by exclude_patterns",
                   "input": {"command": mask_secrets(cmd)[:300]}}, mirror=True)
    # 0.16.0 (P1-7): an allow caused by whitelist.paths on DST-02 is also recorded
    # -- a released block must leave a trace, exactly like exclude_patterns_allow.
    for wp in path_wl_log:
        log_event({"ts": ts, "type": "dst02_path_whitelisted", "tool": raw_tool,
                   "session": session_id, "host": host_tag, "rule_id": "DST-02",
                   "decision": "allow", "severity": "critical", "action": "allow",
                   "reason": "path outside the project root but inside policy whitelist.paths",
                   "input": {"file_path": mask_secrets(wp)}}, mirror=True)
    # 0.17.0 (P-A4): explicit out-of-root absolute paths seen on the Bash channel
    # -- alert-only evidence, never a block (guardrail boundary, not a sandbox).
    for cand in bash_path_log:
        log_event({"ts": ts, "type": "dst02_bash_path_suspect", "tool": raw_tool,
                   "session": session_id, "host": host_tag, "rule_id": "DST-02",
                   "decision": "alert", "severity": "warning", "action": "alert",
                   "reason": "command text references an explicit absolute path outside the "
                             "project root; scripts are not parsed (THREAT_MODEL Non-goals)",
                   "input": {"command": mask_secrets(cmd)[:300], "path": mask_secrets(cand)}},
                  mirror=True)
        if not notice_gate("DST-02-BASH", cand):
            try:
                sys.stderr.write("[DST-02] 提醒: 命令文本中出现项目根之外的显式绝对路径（已记录；脚本内容不解析，"
                                 "详见 THREAT_MODEL Non-goals）: %s\n" % mask_secrets(cand))
            except Exception:
                pass
    # 0.17.0 (P-A5): heartbeat -- the day's first record proves the hook ran at
    # all. N5 measured a tool call that left NO trace in any log; a per-day
    # alive-marker makes "the hook never ran today" distinguishable from "the
    # hook ran and this call was lost".
    try:
        _today_log = os.path.join(os.getcwd(), ".psl", "audit",
                                  datetime.now().strftime("%Y-%m-%d") + ".jsonl")
        if not os.path.isfile(_today_log):
            log_event({"ts": ts, "type": "hook_alive", "tool": raw_tool, "session": session_id,
                       "host": host_tag, "decision": "allow", "severity": "none",
                       "reason": "first hook invocation of the day"}, mirror=True)
    except Exception:
        pass
    # WS-2/WS-3: a malformed entry used to be visible once a day on stderr and
    # nowhere else -- `report.py` showed no sign of it, so a config that silently
    # stopped widening the boundary could not be diagnosed after the fact. It is now
    # an audit record (visible in report.py) and the stderr text says what the
    # consequence is, not just what was rejected.
    for bad in ws_rejected:
        log_event({"ts": ts, "type": "workspace_config_rejected", "tool": raw_tool,
                   "session": session_id, "host": host_tag, "rule_id": "DST-02",
                   "decision": "config_rejected", "severity": "warning", "action": "alert",
                   "config_source": ws_source, "input": {"entry": str(bad)[:200]},
                   "reason": "workspace_roots entry rejected: root/relative/'..'/wildcard"},
                  mirror=True)
        if not notice_gate("WORKSPACE-CONFIG", str(bad)):
            sys.stderr.write(
                "[Antinel][配置错误] workspace_roots 条目被拒绝，**该条目不生效**（不是告警，是没配上）：%r\n"
                "          拒绝类型：根路径 / 相对路径 / 含 '..' / 含通配符\n"
                "          后果：向该路径写入仍会被 DST-02 拦截\n"
                "          来源: %s\n"
                "          修法: 编辑该配置的 workspace_roots 字段，填入绝对路径（或删除该条目）\n"
                % (bad, ws_source))
    if hits:
        for h in hits:                                  # one record per hit (report.py reads rules_hit)
            log_event(dict(base, rules_hit=[h["rule_id"]], severity=h["severity"], action=h["action"],
                           decision="block" if h["action"] == "block" else "alert",
                           match_kind=h["match_kind"], match_snippet=h["match_snippet"],
                           **({"downgraded_from": h["downgraded_from"],
                               "downgrade_reason": h["downgrade_reason"]}
                              if h.get("downgraded_from") else {})),
                      mirror=(h["action"] == "block"))
        log_event({"ts": ts, "type": "pre_tool_use_summary", "tool": tool_name, "session": session_id,
                   "total_hits": len(hits), "decision": decision,
                   "hits": [{"rule_id": h["rule_id"], "severity": h["severity"],
                             "match_kind": h["match_kind"], "snippet": h["match_snippet"]} for h in hits]})
    else:
        log_event(dict(base, rules_hit=[], severity="none", action="allow", decision="allow"))

    if decision == "block":
        top = blocking[0]
        lang = _lang()
        desc = _pick(top, "description", lang)
        rem = _pick(top, "remediation", lang)
        if lang == "zh":
            reason = "Antinel 拦截 [%s] %s | 命中: %s | 放行/处理: %s | 重试无效（策略拦截）" % (
                top["rule_id"], desc, top["match_snippet"], rem)
        else:
            reason = "Antinel blocked [%s] %s | matched: %s | to allow: %s (retry is futile)" % (
                top["rule_id"], top.get("description") or "policy violation",
                top["match_snippet"], rem)
        emit_block(top["rule_id"], reason, json_stdout=host_tag in ("claude-code", "generic"))

    threshold = SEV_RANK.get(policy.get("alert_threshold", "warning"), 1)
    for h in hits:                                      # warning-level: notify, allow (B-04)
        if SEV_RANK.get(h["severity"], 9) > threshold:
            continue                                    # below alert_threshold: logged only
        if notice_gate(h["rule_id"], h.get("match_snippet", "")):
            continue                                    # UX: repeat alert, already notified today
        lang = _lang()
        msg = _pick(h, "description_" + lang, "description") if isinstance(h, dict) else str(h)
        tag = "提醒" if lang == "zh" else "Notice"
        try:
            sys.stderr.write("[%s] %s: %s\n" % (h["rule_id"], tag, msg))
        except Exception:
            pass
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        try:
            sys.stderr.write("HOOK_ERROR (allow)\n")
        except Exception:
            pass
        sys.exit(0)                                     # A-08: fail open