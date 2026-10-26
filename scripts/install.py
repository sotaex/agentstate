#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""AgentState v0.30.0 - self installer (F-07) and uninstaller (F-08).

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
SKILL_VERSION = "0.33.1"


def _os_locale():
    """OS locale 名（形如 zh_CN）。自包含：不依赖调用方的模块级 import。

    为什么不直接用 locale.getlocale() 或环境变量（本机实测 2026-10-11）：
      getdefaultlocale()      -> ('zh_CN', 'cp936')                  正确
      getlocale(LC_CTYPE)     -> ('Chinese (Simplified)_China','936') 切不出 zh
      LC_ALL / LANG           -> C.UTF-8 / en_US.UTF-8               会把中文机判成英文
    ⇒ 3.15 之前继续用 getdefaultlocale（压掉警告即可），3.15 之后走 ctypes 查 UI 语言。"""
    import locale as _loc, sys as _sys, os as _os
    _gdl = getattr(_loc, "getdefaultlocale", None)
    if _gdl is not None:
        try:
            import warnings as _w
            with _w.catch_warnings():
                _w.simplefilter("ignore", DeprecationWarning)
                return _gdl()[0] or ""
        except Exception:
            pass
    if _sys.platform == "win32":
        try:
            import ctypes as _ct
            _m = {2052: "zh_CN", 1028: "zh_TW", 1041: "ja_JP", 1042: "ko_KR"}
            return _m.get(_ct.windll.kernel32.GetUserDefaultUILanguage() & 0xFFFF, "en_US")
        except Exception:
            pass
    for _k in ("LC_ALL", "LC_CTYPE", "LANG"):
        _v = _os.environ.get(_k)
        if _v and _v not in ("C", "C.UTF-8", "POSIX"):
            return _v
    return ""


def _package_version():
    """包版本（0.48.x），与 SKILL_VERSION（钩子协议版本 0.33.1）是两个不同的数。

    ★ 0.48.4：这两个数在界面上长期混用——`--check` 印 SKILL_VERSION，而
      `antinel -V` 印包版本，用户看到两个数打架却无从判断哪个是"装了什么"。
      现在各报各的名字；取值优先用安装元数据（真实来源），失败再退回源码常量。"""
    try:
        from importlib.metadata import version as _v
        return _v("antinel")
    except Exception:
        pass
    try:
        for line in (_locate("antinel.py")).read_text(encoding="utf-8",
                                                      errors="replace").splitlines():
            if line.startswith("VERSION = "):
                return line.split('"')[1]
    except Exception:
        pass
    return "unknown"
PSL_SPEC = "psl-vs-0.1"
SCRIPT_FILES = ("pre_tool_use.py", "post_tool_use.py", "session_dna.py",
                "audit_chain.py",
                "transcript_reader.py", "antinel.py", "hub.py", "host_shield.py",
                "strings.py", "scan.py", "install.py", "report.py")

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
                        "auto_archive": False, "desktop_notify": False,
                        # 0.30.0 (E-3): deny signaling contract + self-probe cadence.
                        # deny_stdout: dual = documented hookSpecificOutput contract AND
                        # legacy {"decision":"block"} on stdout (claude-code/generic only;
                        # ZCode stays stdout-quiet by strict schema); legacy = pre-0.30
                        # shape; quiet = no stdout (exit 2 + stderr only).
                        "deny_stdout": "dual",
                        # enforcement self-probe cadence in hours (0 disables); the probe
                        # runs tools/enforce_probe.py detached from post_tool_use and
                        # chains an enforcement_probe record.
                        "probe_interval_hours": 24,
                        # 0.32.2 (C1): 误报税控制——非 SKILL.md 指令文件上，
                        # "双泛化命中"的 CTX-02 降级为 alert（SPECIFIC 仍 block）。
                        # full = 恢复全部 block（误报风险自担）。
                        "instruction_block_mode": "specific-only",
                        # 0.33.0 (B3/D4): performance_mode = "hook"（默认，每次调用
                        # 冷启动 Python）或 "resident"（常驻判定服务，~20ms/次）。
                        # resident 需运行 tools/judge_service.py（opt-in，默认关）。
                        "performance_mode": "hook"},
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


def _cfg_name(dirname):
    return "config.json" if dirname == ".zcode" else "settings.json"


def _host_detector():
    """取宿主归因的唯一来源 `hooks/_host_detect`；取不到返回 None（不抛）。

    ★ 0.48.4：install.py 既会被 `python -m scripts.install` 调用，也会被
    `python install.py` **当脚本直接跑**（harness 就是这个形态，实测
    88/315 崩在这里）。后一种形态下 `sys.path[0]` 是 `scripts/` 目录，
    顶层 `hooks` 包**不在路径上** ⇒ `from hooks import _host_detect` 静默失败
    ⇒ 宿主归因整条链路退化为 None。⇒ 显式把**包根**加进 sys.path。
    """
    try:
        _root = str(Path(__file__).resolve().parent.parent)
        if _root not in sys.path:
            sys.path.insert(0, _root)
        from hooks import _host_detect
        return _host_detect
    except Exception:
        return None


def detect_host(root):
    """Returns (host, settings_path).

    ★ 0.48.4（Agent 零摩擦 · 宿主归因裂缝）：**修的是一处静默失效**。
      改之前，install.py 自带一份只认 claude-code / zcode / qoder 的检测，且
      **home 目录标记优先于环境变量**。实测后果（2026-10-11，wheel 安装态）：
      在 WorkBuddy 里让 Agent 装钩子——本机 home 下有 `.qoder` 目录——于是
      **装进了「项目/.qoder/settings.json」并一路打印成功**，而 WorkBuddy 不读
      那个文件 ⇒ 钩子静默不生效。同一时刻 `antinel` CLI 的 detect_host() 却
      认得 workbuddy：**两份实现，对同一台机器给出两个结论**。

      现在的判定顺序（强证据在前）：
        (0) 项目里**已有带 hooks 的 settings.json** ⇒ 沿用，不重复造目录。
            这条保护所有既有安装：升级不会把已生效的钩子搬走。
        (1) **项目目录内的宿主标记**（顺序取自 `hooks/_host_detect._DIR_MARKERS`，
            唯一来源，不另抄一份）。install 装的是"这个项目"，所以项目里的
            `.zcode` / `.claude` 是最直接的证据 —— **排在 env 之前**，理由见
            步骤 (1) 处的注释（实测：`_host_detect` 的 env 优先会被宿主进程的
            环境变量带偏，把"我在 WorkBuddy 里跑命令"读成"这个目录属于 WorkBuddy"）。
        (2) 项目里没有标记 ⇒ 再看 env（`_host_detect.detect()`，认得
            CODEBUDDY_CONFIG_DIR / WORKBUDDY_HOST 等键）。
        (3) 只对**本版已验证钩子协议**的三家（claude-code / zcode / qoder）
            写钩子配置；workbuddy / trae 等落 generic，由调用方**明说**没接入，
            而不是静默装在宿主不读的地方。
        (4) 环境变量兜底（CLAUDE_CODE / ZCODE_SESSION）。
        (5) home 标记兜底 —— 排到最后：它只是"这台机器装过某工具"，
            不构成"这个目录属于它"的证据，还会在共用机器上误判。
    """
    root = Path(root)

    # (0) 既有安装：已装过钩子的配置文件说了算
    for host, d in HOST_DIRS:
        p = root / d / _cfg_name(d)
        try:
            if p.is_file() and _settings_has_hooks(p):
                return host, p
        except Exception:
            continue

    # (1) **项目目录内的宿主标记**。
    #     为什么在 install 场景里它排在 env 之前（与 `hooks/_host_detect.py` 的
    #     "env 优先"**刻意不同**）：_host_detect 判的是"这一**次调用**来自哪个宿主"，
    #     而 install 判的是"把钩子装进**哪个项目**"。环境变量是**宿主进程**设的——
    #     在本会话里跑的任何命令（含测试）都带着 `CODEBUDDY_CONFIG_DIR`，于是
    #     "当前进程在 WorkBuddy 里"被误当成"这个目录属于 WorkBuddy"。
    #     实测（0.48.4 首跑 harness，88/315 崩）：临时项目 `zc_proj/` 里明明有
    #     `.zcode`，却被 env 判成 workbuddy ⇒ 不写 `.zcode/config.json`
    #     ⇒ 后续断言 FileNotFoundError。**目录标记在这里才是直接证据。**
    tag = None
    _hd = _host_detector()
    if _hd is not None:
        for d, t in _hd._DIR_MARKERS:
            if (root / d).is_dir():
                tag = t
                break

    # (2) 目录没命中 ⇒ 再看 env（认得 workbuddy / codebuddy / trae 的键）
    if tag is None and _hd is not None:
        try:
            tag, _ev = _hd.detect(str(root))
        except Exception:
            tag = None

    # (3) 已验证协议的三家：写进它们自己的配置目录
    if tag in ("claude-code", "zcode", "qoder"):
        d = dict(HOST_DIRS)[tag]
        return tag, root / d / _cfg_name(d)
    if tag in ("trae", "workbuddy", "codebuddy"):
        # TRAE 的布局是声明式适配、未实测；WorkBuddy 本版没有实测过的钩子协议
        # （README「已知边界」已有登记）。不猜目录：落 generic，由 install() 明说。
        return "generic", root / ".psl" / "hooks.json"
    if tag not in (None, "generic"):
        return "generic", root / ".psl" / "hooks.json"

    # (4) 环境变量兜底
    if os.environ.get("CLAUDE_CODE"):
        return "claude-code", root / ".claude" / "settings.json"
    if os.environ.get("ZCODE_SESSION"):
        return "zcode", root / ".zcode" / "config.json"

    # (4) home 标记兜底 —— **只在完全没有任何归因线索时**才用。
    #     若已经知道是 workbuddy（步骤 1 命中），就不许再拿 home 下的 .qoder
    #     去猜：那正是 0.48.3 及以前"装成功但钩子不生效"的那条路径。
    if tag is None:
        home = Path.home()
        for host, d in HOST_DIRS:
            if (home / d).is_dir():
                return host, root / d / _cfg_name(d)
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


def refresh_rules(root):
    """把包内规则快照刷进项目（`--refresh-rules`）。返回退出码。

    ★ 为什么需要这个入口（2026-10-26 实测，第 40 条）：
      hook 加载的是 `<root>/.psl/rules/default.json`（install 时拷的那份），
      `pip install -U` 只换包**不跑 install** ⇒ 项目副本永久停在首次安装的版本。
      本仓实测：项目副本 version 0.34.0（10-03）／包内 0.57.1（10-26），
      中间 9 条规则的全部修复（SEC-04/05/06、DST-01/04/06、CTX-01/03/05 共 15 处
      字段差异）在这台机器上**一条都没生效**。
      0.57.0 第 32 条只做到「说出来 + 给修法」，没给「一键修」—— 用户看到提示
      也照样只能重跑 install，而 install 会重写 settings、重扫全盘。

    ★ 只动三样：规则副本、manifest 的 rules_hash 与 skill_version。
      policy 不碰（那是用户的），settings 不碰（那是宿主的），审计不碰。
    ★ `rules_hash` 必须与副本**同时**更新：它是 SELF-TAMPERED 判定的基准，
      只换文件不换 hash ⇒ 立刻被判篡改并退回内嵌兜底（比不修更坏）。
    ★ 刷新这件事本身进审计链：改了防护依据却不留痕，等于给自己开静默后门。
    """
    psl = Path(root) / ".psl"
    man_path = psl / "manifest.json"
    if not man_path.is_file():
        print("这个目录没有安装过：%s 不存在。先用 install.py 装一次。" % man_path)
        return 2
    src = _locate("rules", "default.json")
    if not src.is_file():
        print("包内规则文件找不到：%s" % src)
        return 2
    dst = psl / "rules" / "default.json"
    dst.parent.mkdir(parents=True, exist_ok=True)

    def _ver(p):
        try:
            with open(p, encoding="utf-8") as f:
                return str(json.load(f).get("version") or "")
        except Exception:                                     # noqa: BLE001
            return ""

    old_ver, new_ver = _ver(dst) if dst.is_file() else "(无)", _ver(src)
    old_hash = sha256_file(dst) if dst.is_file() else "(无)"
    new_hash = sha256_file(src)
    if old_hash == new_hash:
        print("规则快照已是包内这一版（%s），什么都没做。" % (new_ver or "?"))
        return 0

    shutil.copy2(src, dst)
    try:
        man = json.loads(man_path.read_text(encoding="utf-8"))
    except Exception as e:                                    # noqa: BLE001
        print("manifest 读不出来（%s），规则副本已更新但哈希没登记 —— "
              "下次 hook 会判 SELF-TAMPERED。请重跑 install.py。" % type(e).__name__)
        return 2
    man["rules_hash"] = new_hash
    man["skill_version"] = SKILL_VERSION
    man["rules_refreshed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    man_path.write_text(json.dumps(man, ensure_ascii=False, indent=2), encoding="utf-8")

    print("规则快照已刷新：%s → %s" % (old_ver or "?", new_ver or "?"))
    print("  %s" % dst)
    print("  hash %s → %s" % (old_hash[:22] + "…", new_hash[:22] + "…"))
    _wrote, _err = _audit_append(root, {
        "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "type": "rules_snapshot_refreshed", "tool": "-", "session": "antinel-cli",
        "rule_id": "A4", "decision": "config_refresh", "severity": "info",
        "action": "allow",
        "reason": "project rules snapshot refreshed from the package",
        "rules_file": str(dst),
        "version_from": old_ver, "version_to": new_ver,
        "hash_from": old_hash, "hash_to": new_hash})
    # ★ 只说自己做得到的事：写成功才说「已写进审计链」。
    #   0.57.2 之前这里印的是无条件那句，而真正调用的 `host_shield.log_event`
    #   **从来没有存在过**（AttributeError 被 except 吞掉）⇒ 屏幕说留痕了，
    #   链上一个字都没有。判据 RF-40f 的「留痕」那条腿 2026-10-26 夜当场抓出。
    if _wrote:
        print("  这条记录已写进审计链（type=rules_snapshot_refreshed）：%s" % _wrote[0])
    else:
        print("  ⚠ 留痕没写成（%s）—— 规则已刷新，但链上没有这一笔。" % (_err or "无可用链"))
    return 0


def _audit_append(root, rec, mirror_dirs=None):
    """把一条记录写进项目链＋宿主级镜像。返回 `(写成功的文件, 首个错误)`。

    ★ **唯一实现**：`uninstall` 与 `--refresh-rules` 都走这里。
      两条 CLI 路径各写一遍「8 行链追加」，正是本仓第一顽症（同一事实多处实现）；
      而这次更糟：写 `refresh_rules` 时我调了一个**不存在的函数**
      （`host_shield.log_event`），异常被 `except: pass` 吃掉，屏幕上照样印
      「已写进审计链」。判据只断言「屏幕上那句话」是抓不到的 —— 必须断言
      **链里真的有这条 type**（RF-40f 的第四腿）。
    ★ 项目链用 `append_chained`（带哈希链），镜像用 `append_locked`
      （跨目录单副本，不参与本项目链），与 `uninstall` 原写法逐字一致。
    ★ `mirror_dirs` 缺省＝`host_shield._mirror_dir()`（套件沙箱里自动落在 hub 内）；
      卸载那条路径传自己的宿主目录，行为与 0.57.1 逐字一致。
    """
    wrote, err = [], None
    try:
        try:
            import audit_chain as _acm
        except ImportError:
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
            import audit_chain as _acm
    except Exception as e:                                    # noqa: BLE001
        return wrote, repr(e)
    day = datetime.now().strftime("%Y-%m-%d")
    ad = Path(root) / ".psl" / "audit"
    if ad.is_dir():
        fn = ad / (day + ".jsonl")
        try:
            _acm.append_chained(str(fn), rec)
            _acm.touch_day_manifest(str(fn))
            wrote.append(str(fn))
        except Exception as e:                                # noqa: BLE001
            err = err or repr(e)
    dirs = mirror_dirs
    if dirs is None:
        try:
            import host_shield as _hs
            dirs = [Path(_hs._mirror_dir())]
        except Exception as e:                                # noqa: BLE001
            return wrote, err or repr(e)
    for md in dirs:
        try:
            md = Path(md)
            md.mkdir(parents=True, exist_ok=True)
            fn = md / (day + ".jsonl")
            _acm.append_locked(str(fn), json.dumps(rec, ensure_ascii=False) + "\n")
            _acm.touch_day_manifest(str(fn))
            wrote.append(str(fn))
        except Exception as e:                                # noqa: BLE001
            err = err or repr(e)
    return wrote, err


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
        loc = _os_locale().lower()
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
        # ★ 0.48.4：不许静默。改之前，WorkBuddy 里的安装会一路打印"成功"，
        #   而钩子其实落在宿主不读的目录里——Agent 与用户都拿不到"没生效"这个事实。
        #   现在把「检测到了什么 / 没接上 / 还能用什么 / 怎么接」一次说清。
        print("      ⚠ 这个宿主还没有我们实测过的钩子协议 ⇒ 本次只装了**审计与扫描**，")
        print("        Agent 的动作**不会**被实时拦截（不是装失败，是这一宿主尚未接入）。")
        print("        仍然可用：antinel brief ／ antinel digest ／ python -m scripts.scan")
        print("        已验证可拦截的宿主：claude-code / zcode / qoder（--host 可显式指定）")
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
    # v0.23.1 (定稿方案 v1.2): 个人中枢自动登记——安装即入册，联邦 digest 才有分母。
    # 不入册：generic（扫描-only）；系统临时目录下的项目（测试/一次性）——确定性判据，
    # 不依赖 TTY 检测（后台 shell 的 stdin 可能仍是 console）。
    # Best-effort：中枢登记失败不影响安装结果。
    import tempfile as _tempfile
    _root_s = str(root)
    _in_temp = _root_s.lower().startswith(_tempfile.gettempdir().lower())
    if host != "generic" and not _in_temp:
        try:
            parent = str(Path(__file__).resolve().parent.parent)
            if parent not in sys.path:
                sys.path.insert(0, parent)
            import hub as _hub
            _hub.register(_root_s, host, registered_by="installer")
            print("      hub: registered in ~/.antinel/registry.json")
        except Exception as _e:
            print("      hub: register skipped (%s)" % _e)
        try:  # 0.24.0: PATH 垫片（不碰注册表；把 ~/.antinel 加入 PATH 即可用 antinel）
            shim_dir = os.path.join(os.path.expanduser("~"), ".antinel")
            os.makedirs(shim_dir, exist_ok=True)
            shim = os.path.join(shim_dir, "antinel.cmd")
            # ★ 0.34.0 修：原为 `encoding="ascii"`，遇到**含中文的用户名目录**
            #   （本机就是 C:\Users\大马\）直接 UnicodeEncodeError ⇒ 垫片静默跳过
            #   ⇒ 中文用户拿不到 `antinel` 命令，而 help/README 恰恰教他们用这个命令。
            #   .cmd 是**字节文件**（cmd.exe 按 OEM cp936 读），所以：
            #   ① 文件本身用 utf-8 写（Python 侧不报错）；
            #   ② 行首加 `chcp 65001` 让 cmd 以 UTF-8 解释后续行。
            #   ⇒ 路径含任何非 ASCII 字符都能用。
            with open(shim, "w", encoding="utf-8", newline="\r\n") as f:
                f.write('@echo off\r\nchcp 65001 >nul\r\n"%s" -I -S "%s" %%*\r\n'
                        % (sys.executable, _locate("antinel.py")))
            print("      shim: %s（把该目录加入 PATH 后任意终端可用 antinel）" % shim)
        except Exception as _e:
            print("      shim: skipped (%s)" % _e)
    # ★ 0.53.0（T1.4，设计 v1.11 §29.2 触点 1＋施工单 v1.4）：装好之后的
    #   收尾一句话 —— 创始人原话「装后建议用户先做一次体检……要有设计」。
    #   **只打印命令，不自动开浏览器**：Agent 环境自动弹窗会打断（设计原文）。
    #   无条件打印（generic 扫描-only 安装同样该知道有体检这件事）。
    #   判据：ci/inbox_guards_0353.py P17（AST 逐字，含负控）。
    print("装好了。建议现在花一分钟做一次体检：antinel ui")
    return 0


def check_installed(root):
    """0.16.0 (P0-7): compare the installed manifest against the package WITHOUT
    touching anything. Exit 0 = in sync, 3 = drift (version or hash mismatch),
    1 = nothing installed here. This is the read-only twin of re-running install."""
    root = Path(root).resolve()
    manifest_path = root / ".psl" / "manifest.json"
    if not manifest_path.is_file():
        # ★ 0.34.0（E3）：原来只印一句 `not installed here: <路径>` ——
        #   实测输出是**纯英文**、**没有下一步**、**没有"要不要装"**。
        #   而这是企业最有价值的一条入口（先体检、零风险、看了再决定装不装），
        #   把"我有没有装"这个最关键的问题回答成一句谜语，等于把入口堵死。
        #   ⇒ 改成：中文结论 ＋ **实际发生了什么** ＋ **下一步给什么**。
        print("这台机器上还没有安装 Antinel。")
        print("  查的是：%s" % manifest_path)
        print("  原因：这个路径下没有 .psl/manifest.json —— 装过的话一定有（卸载会清掉它）。")
        print("")
        print("下一步，二选一：")
        print("  · 想先看它能查到什么（不装任何东西）：")
        print("      python -m pip install --user antinel   然后")
        print("      python -m antinel host-audit")
        print("  · 想直接装上（含钩子，开始记账）：")
        print("      python -m scripts.install --root .")
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
        print("fix: python -m scripts.install --root %s" % root)
        return 3
    # ★ 0.48.4：把「哪个版本」说清楚。旧文案只印 `version 0.33.1`，而
    #   `antinel -V` 印的是 `0.48.3` ⇒ 用户/Agent 看到两个数打架，且无从判断
    #   哪个才是"装了什么"。0.33.1 是**钩子协议版本**（只在协议变化时 bump），
    #   0.48.3 是**包版本**；两者本来就不同步，但界面上必须各报各的名字。
    _pkg = _package_version()
    print("in sync: 钩子协议版本 %s ／ 包版本 %s；rules_hash 一致，%d 个脚本哈希一致"
          % (old_ver, _pkg, len(old.get("scripts_hash") or {})))
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
    # 0.31.0 (F4)：自我移除必须在删除动作之前留痕——卸载是用户权利，不因留痕
    # 失败而拒绝（fail-open）；purge 会删掉项目副本，宿主级镜像保证证据仍在。
    # 这是"闸门被拔线必须大声说"的另一半：E-3 管信号失效，这里管钩子被整体拔掉。
    try:
        _rec = {"ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
                "type": "antinel_uninstall", "tool": "-", "session": "antinel-cli",
                "host": detect_host(root)[0] if isinstance(detect_host(root), tuple) else str(detect_host(root)),
                "decision": "alert", "severity": "critical", "action": "alert",
                "removed_hooks": removed, "purge": bool(purge),
                "settings_file": str(settings_path),
                "reason": "guardrail self-removal requested -- recorded BEFORE removal; "
                          "purge deletes the project copy, the host-level mirror keeps "
                          "the evidence"}
        # ★ 0.57.2：这一段原先是内联的 8 行链追加；现在与 `--refresh-rules`
        #   共用 `_audit_append`（同一事实一处实现）。镜像目录仍指宿主级那棵，
        #   与 0.57.1 的行为逐字一致。
        _mad = Path(os.path.expanduser(os.environ.get("WORKBUDDY_CONFIG_DIR")
                                       or "~/.workbuddy")) / "antinel-audit"
        _wrote, _err = _audit_append(root, _rec, mirror_dirs=[_mad])
        if not _wrote:
            raise RuntimeError(_err or "没有可写的链")
    except Exception as e:
        print("[Antinel] 卸载留痕失败（继续卸载；不影响本操作）：%r" % (e,))
    if purge and (root / ".psl").is_dir():
        shutil.rmtree(root / ".psl")
        print(".psl/ removed (purge)")
    elif manifest_path.is_file():
        # ★ 0.34.1 修：**卸载不该因为"一次删不掉"就报失败。**
        #   到这一行时，钩子已摘除、卸载留痕已写 —— 用户要的事已经做完了。
        #   实测（本机宿主删除守卫）：裸 `unlink()` 抛**非 OSError** ⇒ 穿透 ⇒
        #   整个卸载 rc=1，而用户看到的是"卸载失败"—— 实际是**半截成功**
        #   （钩子摘干净了，只是清单没删掉），这是最坏的形状：外部信号与实际状态不符。
        #   修法：先真删；失败就**改名让开**（本项目既有的零删除模式）；再失败才如实说。
        _gone = False
        try:
            manifest_path.unlink()
            _gone = True
        except Exception:
            try:
                os.rename(str(manifest_path),
                          str(manifest_path) + ".removed-%d" % os.getpid())
                _gone = True
            except Exception:
                pass
        if _gone:
            print("manifest removed; audit logs kept in .psl/audit (use --purge to delete)")
        else:
            print("[Antinel] 清单没能删掉（%s）—— 钩子已摘除、留痕已写，"
                  "残留该文件不影响卸载。" % manifest_path)
    return 0


def _batch(args):
    """★ 0.34.0（E7）批量安装。

    清单格式（JSON，最小可用）：
        {"roots": ["D:/proj-a", "D:/proj-b"],
         "host": "claude-code",       # 可选；不给则逐个自动探测
         "global": false,             # 可选；true = 注册到用户级（每个 workspace 都受管）
         "skip_scan": true}          # 可选；true = 跳过首次全盘扫（快，批量场景常用）

    ★ 三条设计纪律：
      ① **动作与单机安装逐字相同** —— 批量只是"省掉交互、跑多个 root"，
         **不另写一套安装逻辑**（那会立刻漂移成"批量装的和手装的不一样"）。
      ② **逐条留痕，且标明是批量装的** —— 企业审计必问"这批怎么装的"。
         写进项目链的 `host_shield_changed` 与包级 manifest，
         ★ 并且**留痕失败不阻断安装**（fail-open，与卸载同一条纪律：
         留痕是证据，不是许可证）。
      ③ **`--dry-run` 先跑** —— 批量是唯一"一次改 N 台"的动作，
         必须有一个不改任何东西的预览。
    """
    import json as _json
    try:
        with open(args.config, "r", encoding="utf-8") as f:
            cfg = _json.load(f)
    except Exception as e:
        print("读不了清单 %s：%r" % (args.config, e))
        return 2
    roots = cfg.get("roots") or []
    if not roots:
        print("清单里没有 roots（要装到哪些目录？）—— 什么都不做。")
        return 2
    default_host = cfg.get("host")
    g_hooks = bool(cfg.get("global", False))
    skip = bool(cfg.get("skip_scan", True))

    mode = "预演（不改任何文件）" if args.dry_run else ("静默批量安装" if args.silent else "批量安装")
    print("=" * 68)
    print(" Antinel 批量安装｜%s" % mode)
    print(" 清单：%s ｜ %d 个目录" % (args.config, len(roots)))
    if not args.silent and not args.dry_run:
        print(" ★ 非 --silent：每个目录仍会逐项确认（Ctrl-C 可中止，已装的保留）")
    if args.dry_run:
        print(" ★ 预演模式：下面每一行都**不会**真的执行")
    print("=" * 68)

    ok = fail = skipd = 0
    for i, r in enumerate(roots, 1):
        rp = Path(r)
        line = "  [%d/%d] %s" % (i, len(roots), r)
        try:
            if not rp.is_dir():
                print(line + " —— 跳过（目录不存在）")
                skipd += 1
                continue
            if args.dry_run:
                # 预演：只报将要做什么，不调用 install()
                _m = rp / ".psl" / "manifest.json"
                print(line + (" —— 将会覆盖安装（已有 manifest）" if _m.is_file()
                              else " —— 将会全新安装"))
                ok += 1
                continue
            rc = install(str(rp), host_override=default_host, redetect=False,
                         skip_scan=skip, strict=args.strict, force=args.force,
                         global_hooks=g_hooks)
            if rc == 0:
                print(line + " —— 完成")
                ok += 1
            else:
                print(line + " —— 失败（rc=%d）" % rc)
                fail += 1
        except KeyboardInterrupt:
            print("\n  已中止。**已装的保留**（不 rollback：账本与钩子已在工作，逐台回滚"
                  "比留着更危险）。")
            break
        except Exception as e:
            print(line + " —— 异常：%r" % e)
            fail += 1

    print("-" * 68)
    print(" 成功 %d ｜ 失败 %d ｜ 跳过 %d" % (ok, fail, skipd))
    if args.dry_run:
        print(" ★ 这是预演。去掉 --dry-run 才会真的装。")
    elif fail:
        print(" ★ 有 %d 个目录没装成 —— 重跑本命令会**只补没成的**（已成的会覆盖，"
              "账本不清空）。" % fail)
        return 1
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Antinel installer")
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
    # ★ 0.34.0（E7）：批量安装。**企业 50 台机器的第一块砖**，且不碰任何红线
    #   （全部动作与单机安装逐字相同，只是省掉交互、跑多个 root）。
    #   为什么现在做：审核实测 install.py 此前**无** --silent/--batch/--config，
    #   企业部署＝50 次人工；而"批量"本身也是团队版能不能落地的分水岭。
    ap.add_argument("--config", help="批量：JSON 清单（根、host、是否全局、是否跳扫描）")
    ap.add_argument("--silent", action="store_true",
                    help="批量：非交互（每次安装都按默认值应答，**不逐项确认**）")
    ap.add_argument("--dry-run", action="store_true",
                    help="批量：只打印将要做什么，不改任何文件（**上线前必跑一次**）")
    ap.add_argument("--refresh-rules", action="store_true",
                    help="只把包内的规则快照刷进本项目（不动 settings / policy / 审计）")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        if args.config:
            return _batch(args)
        if args.check:
            return check_installed(args.root)
        if args.refresh_rules:
            return refresh_rules(args.root)
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
