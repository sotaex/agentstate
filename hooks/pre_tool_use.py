#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""AgentState v0.32.2 - PreToolUse hook (Claude Code / ZCode compatible).

v0.30.0 changes (E-3 closure -- the deny-signal single point of failure):
  E3-a: deny is now signaled on THREE additive channels at once -- the
        documented contract JSON (hookSpecificOutput.permissionDecision="deny"),
        the legacy stdout JSON ({"decision":"block"}), and exit 2 + stderr.
        Previously the block rested on exit 2 alone; a host that stopped
        honoring it would silently degrade every block into an allow.
        Policy escape hatch: global_settings.deny_stdout = dual (default) /
        legacy / quiet.
  E3-b: ANTINEL_PROBE=1 -- tools/enforce_probe.py runs this hook against a
        synthetic must-block event and verifies the signal channels. In probe
        mode the hook is side-effect-free: no audit writes, no owner
        notification, and the policy whitelist is bypassed (the probe tests
        the ENGINE's deny path, not the user's release configuration).
  E3-c: hook_alive and pre_tool_use_summary records now carry
        antinel_version, host_version (when the host sends one) and the deny
        contract in force -- the ledger itself shows which deny contract
        was armed.

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
Block: stdout {"decision":"block","reason":...,"hookSpecificOutput":{...permissionDecision:"deny"}} + stderr reason + exit 2 (three additive channels; 0.30.0 E-3).
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
import time as _time_mod
from datetime import datetime, timezone

_T0 = _time_mod.perf_counter()          # 0.32.2 (B1): import 段起点（性能插桩）

# ---------------------------------------------------------------- constants --
PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_ANTINEL_VERSION = "0.53.1"   # 0.30.0 (E-3): recorded in hook_alive / summary / probe records
_T1 = _time_mod.perf_counter()          # 0.32.2 (B1): import 段终点（性能插桩）


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
# 0.33.1 (P3-4): 钩子"慢到超时"的留痕阈值。宿主超时 10s(zcode)/15s(claude)，
# 超时=allow（A-08）。取 8s 留 2s 余量，超线即写 hook_slow 事件。
SLOW_BUDGET_MS = 8000
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
TEXT_EXTS = (".md", ".mdc", ".txt", ".json", ".yaml", ".yml", ".toml", ".py", ".js", ".ts", ".sh", ".bash", ".zsh")
# 0.31.0 (F1): the instruction surface -- files an agent reads AS INSTRUCTIONS.
# CTX-02/04 target "instruction_files" = SKILL.md + this set. Keep in sync with
# scripts/scan.py (parity is asserted in verification_tests, E1-8).
INSTRUCTION_BASENAMES = ("AGENTS.md", "AGENTS.local.md", "CLAUDE.md",
                         "CLAUDE.local.md", ".cursorrules", "copilot-instructions.md")
INSTRUCTION_DIR_MARKERS = (".cursor/rules",)   # + basename endswith .mdc

# G-03: embedded fallback, used only when the rules file is unreadable (flat layout).
_FALLBACK = [
    {"id": "SEC-01",
     "description_zh": "读取 .env 文件可能泄露 API 密钥与机密配置", "remediation_zh": "把 .env 移出 Agent 可读范围；确需变量时手动复制具体几行；测试夹具路径可在 policy.json 白名单登记", "category": "secrets", "severity": "critical", "apply_to_tools": ["Read", "Bash"],
     # 0.17.0 (P-B5): excludes kept literally identical to rules/default.json
     # (three separate strings, not a merged alternation) so the suite's
     # fallback-subset assertion can compare them mechanically.
     "file_patterns": [r"\.env$", r"\.env\."],
     "exclude_patterns": [r"\.env\.example", r"\.env\.template", r"\.env\.sample"],
     "description": "Agent attempted to read a .env file which may contain API keys and secrets"},
    {"id": "SEC-02",
     "description_zh": "读取 SSH 私钥或 authorized_keys", "remediation_zh": "SSH 密钥不要放进 Agent 工作范围；改用 ssh-agent 转发", "category": "secrets", "severity": "critical", "apply_to_tools": ["Read", "Bash"],
     "file_patterns": [r"\.ssh[/\\]id_", r"\.ssh[/\\]authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys"],
     "description": "Agent attempted to read SSH private key or authorized_keys file"},
    {"id": "SEC-03",
     "description_zh": "读取云厂商凭证文件", "remediation_zh": "改用云厂商 CLI 的短期令牌；确需操作时请手动执行", "category": "secrets", "severity": "critical", "apply_to_tools": ["Read", "Bash"],
     "file_patterns": [r"\.aws[/\\]credentials", r"\.kube[/\\]config", r"credentials\.json", r"\.netrc", "application_default_credentials"],
     "description": "Agent attempted to read cloud provider credentials"},
    {"id": "DST-01",
     "description_zh": "执行文件或目录删除命令", "remediation_zh": "确认删除目标无误；构建产物类删除（如 node_modules）已在豁免清单", "category": "destructive", "severity": "critical", "apply_to_tools": ["Bash"],
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
    # ★ 0.29.0：本行由 `antinel_verify.py --invariants` 的 INV-1 抓出 ——
    #   兜底表此处原为 ["Write","Edit"]，而 rules/default.json 的 DST-02 是
    #   ["Write","Edit","Bash"] ⇒ **Bash 通道的"写项目外"在降级模式下静默失守**。
    #   与 NET-01 是**同一个缺陷类**：兜底表比主表窄，且没有任何东西会红。
    #   手工比对只发现了 NET-01；是守卫把这一条也抓了出来。
    {"id": "DST-02",
     "description_zh": "试图写入项目根目录之外；或用 tar 解包越权覆盖系统文件", "remediation_zh": "放行：antinel paths add <目录前缀>（进审计链）；确需更大范围用 antinel roots add <路径>；或把文件写进项目内", "category": "destructive", "severity": "critical",
     "apply_to_tools": ["Write", "Edit", "Bash"],
     "check": "path_outside_project_root",
     "description": "Agent attempted to write to a file outside the project root directory"},
    {"id": "DST-03",
     "description_zh": "修改 Shell 启动配置（.bashrc 等，属持久化机制）", "remediation_zh": "启动脚本每次开终端都会执行，不要让 Agent 追加内容；确需修改请手动审查后进行", "category": "destructive", "severity": "critical", "apply_to_tools": ["Write", "Edit", "Bash"],
     "file_patterns": [r"\.bashrc", r"\.zshrc", r"\.profile", r"\.bash_profile"],
     "description": "Agent attempted to modify shell startup configuration (persistence mechanism)"},
    {"id": "DST-04",
     "description_zh": "建立持久化机制（计划任务/系统服务/启动项/注册表 Run 键）", "remediation_zh": "持久化会在会话结束后反复执行，必须由你本人确认后手动操作", "category": "destructive", "severity": "critical", "apply_to_tools": ["Write", "Edit", "Bash"],
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
    # 0.29.0（G-1）：**兜底表与主规则表逐字段对齐**。
    # 缺陷原貌：rules/default.json 的 NET-01 早已是 ["Bash","WebFetch","WebSearch","MCP"]
    # （0.28.3 红队 EX-08/09/10 修的），但这份内置兜底表**只有 ["Bash"]**
    # ⇒ 一旦规则文件不可读/被判定篡改，网络外传检测就**静默退化**成"只认 Bash"，
    #    WebFetch/WebSearch/MCP 三条宿主自带外传通道当场失守，且**没有任何报错**。
    # 这正是本项目铁律「查不出来 ≠ 查出来是好的」的代码版：降级是静默的。
    # 现在两条纪律同时上：
    #   · 本表与 rules/default.json 的同 id 条目 **apply_to_tools 必须完全相等**；
    #   · command_patterns 必须是主表的**子集**（兜底可以更窄，但不得凭空多出模式）。
    # 两者由 `antinel_verify.py --invariants` 断言（无检查项的禁令 ＝ 没有禁令）。
    {"id": "NET-01",
     "description_zh": "通过 Shell 向白名单外域名发起网络请求", "remediation_zh": "核对目标域名；常用下载源放行：antinel domains add <域名>（进审计链）", "category": "network", "severity": "warning",
     "apply_to_tools": ["Bash", "WebFetch", "WebSearch", "MCP"],
     "command_patterns": [r"\b(curl|wget|fetch)\b.*https?://",
                          r"https?://(?!registry\.npmjs\.org|pypi\.org|github\.com)",
                          r"\b(scp|sftp|rsync|ssh|nc|ncat)\b\s+[^\n]{0,120}@",
                          r"\b(certutil|bitsadmin)\b[^\n]{0,120}(urlcache|transfer|/transfer|/urlcache)",
                          r"Invoke-(WebRequest|RestMethod)|Start-BitsTransfer",
                          r"\bgit\s+push\b[^\n]*?(?:https?://|ssh://|[\w.-]+@[\w.-]+:)",
                          r"\bgh\s+(release|repo)\s+create\b"],
     "exclude_patterns": ["localhost", r"127\.0\.0\.1", r"registry\.npmjs\.org", r"pypi\.org",
                          r"files\.pythonhosted\.org", r"github\.com", r"api\.github\.com",
                          r"objects\.githubusercontent\.com"],
     "description": "Agent made an external network request via shell command to a non-whitelisted domain"},
    {"id": "CTX-01",
     "description_zh": "枚举全部环境变量（可能暴露密钥）", "remediation_zh": "让 Agent 只打印它需要的具体变量名", "category": "context", "severity": "warning", "apply_to_tools": ["Bash"],
     "command_patterns": [r"\benv\b(?!\s*=)", r"\bprintenv\b", r"os\.environ", r"process\.env"],
     "description": "Agent attempted to enumerate all environment variables (may expose API keys and secrets)"},
    {"id": "CTX-02",
     "description_zh": "技能指令文件中发现提示注入载荷", "remediation_zh": "移除该技能并核查来源；不要运行其中的指令", "category": "injection", "severity": "critical", "type": "file_content", "target": "SKILL.md",
     "apply_to_tools": ["Read", "Write", "Edit"],
     "content_patterns": [r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
                          r"忽略(以上|之前|先前|上面)(的)?(所有)?(指令|指示|规则)"],
     "description": "Potential prompt injection payload detected in skill instruction file"},
    {"id": "CTX-03",
     "description_zh": "检出隐形 Unicode 字符（标签字符/零宽字符等）", "remediation_zh": "清除隐形字符；出现在指令文件中默认按恶意处理", "category": "injection", "severity": "critical", "type": "file_content",
     "target": "all_text_files", "detection": "character_code_scan",
     "apply_to_tools": ["Read", "Write", "Edit", "Bash"],
     "description": "Invisible Unicode character detected (tag characters, zero-width, word joiner, BOM in middle of file)"},
    # -------- 0.29.0：新增 6 条规则同步进兜底表（G-2/G-3/G-5/G-7/G-8/G-11）-------
    # 理由同 NET-01：兜底表是"规则文件没了之后你还有什么"。这 6 条防的都是
    # **一步就能做到的外传**（一条命令读剪贴板/截屏/打包 IM 库），恰恰是最不该
    # 在降级时丢掉的。apply_to_tools 与主表逐字段相等，patterns 为主表子集。
    {"id": "SEC-07",
     "description_zh": "读取系统剪贴板（可能含用户刚复制的口令/令牌/隐私文本）", "remediation_zh": "不要让 Agent 读剪贴板；需要某个值请用户自己粘贴", "category": "secrets", "severity": "critical",
     "apply_to_tools": ["Bash"],
     "command_patterns": [r"(?i)\bget-clipboard\b", r"(?i)\bpbpaste\b",
                          r"(?i)\bxclip\b[^\n]{0,40}\s-o\b", r"(?i)\bxsel\b[^\n]{0,40}\s-o\b",
                          r"(?i)\bwl-paste\b", r"(?i)\bpyperclip\b[^\n]{0,40}\.paste\b",
                          r"(?i)win32clipboard[^\n]{0,80}GetClipboardData",
                          r"(?i)clipboard_get\s*\(",
                          r"(?i)\[System\.Windows\.Forms\.Clipboard\]::(GetText|GetData|GetImage|ContainsText)",
                          r"(?i)\[Windows\.ApplicationData\]::Current\.GetClipboardContent"],
     "description": "Agent read the system clipboard, which may hold passwords, tokens or private text the user copied"},
    {"id": "SEC-08",
     "description_zh": "截屏/录屏（屏幕上有什么就会被带走什么）", "remediation_zh": "Agent 几乎不需要截屏；确需截屏请人工操作", "category": "secrets", "severity": "warning",
     "apply_to_tools": ["Bash"],
     "command_patterns": [r"(?i)\bscreencapture\b", r"(?i)\bgnome-screenshot\b", r"(?i)\bscrot\b",
                          r"(?i)\bimport\s+-window\b", r"(?i)\bxwd\b",
                          r"(?i)\bnircmd\b[^\n]{0,60}savescreenshot",
                          r"(?i)ffmpeg[^\n]{0,140}(-f\s+gdigrab|-f\s+avfoundation|-f\s+x11grab)",
                          r"(?i)CopyFromScreen", r"(?i)ImageGrab\.grab",
                          r"(?i)pyautogui\.screenshot",
                          r"(?i)\bGet-CimInstance\b[^\n]{0,80}Win32_VideoController"],
     "description": "Agent captured the screen (screenshot/record), which can carry whatever is displayed"},
    {"id": "SEC-09",
     "description_zh": "读取 IM/邮件客户端的本地库（等于全部往来记录）", "remediation_zh": "这是用户私人通信；应完全禁止 Agent 访问", "category": "secrets", "severity": "critical",
     "apply_to_tools": ["Read", "Bash"],
     "file_patterns": [r"(?i)WeChat Files", r"(?i)xwechat_files", r"(?i)Tencent[\\/]WeChat\b",
                       r"(?i)com\.tencent\.xinWeChat",
                       r"(?i)[\\/]Msg[\\/][^\\/]{0,40}\.db",
                       r"(?i)[\\/]DingTalk[\\/][^\\/]{0,40}\.db",
                       r"(?i)[\\/]nt_qq\b",
                       r"(?i)\.ost$", r"(?i)\.pst$", r"(?i)Lark[\\/][^\\/]{0,40}\.db",
                       r"(?i)\bDingTalk\b"],
     "command_patterns": [r"(?i)(WeChat Files|xwechat_files|Tencent[\\/]WeChat)[^\n]{0,200}\.db",
                          r"(?i)\b(nt_msg|media_msg|message_\d+|MediaMSG\d*|nt_qq)\w*\.db\b",
                          r"(?i)(copy|xcopy|robocopy|tar|zip|7z)[^\n]{0,200}\.(ost|pst)\b",
                          r"(?i)sqlite3?[^\n]{0,200}(nt_msg|media_msg|message_\d+|nt_qq)"],
     "description": "Agent read an instant-messaging or mail client's local store (full message history)"},
    {"id": "SEC-10",
     "description_zh": "读取输入法用户词库/上屏记录（等于用户打过什么字）", "remediation_zh": "输入历史属隐私；不要让 Agent 读取输入法词库", "category": "secrets", "severity": "warning",
     "apply_to_tools": ["Read", "Bash"],
     "file_patterns": [r"(?i)[\\/]SogouPY\b", r"(?i)[\\/]SogouInput\b", r"(?i)[\\/]WeChatInput\b",
                       r"(?i)[\\/]BaiduPinyin\b", r"(?i)[\\/]QQPinyin\b", r"(?i)[\\/]Rime\b",
                       r"(?i)\.scel$"],
     "command_patterns": [r"(?i)(copy|xcopy|robocopy|tar|zip|7z)[^\n]{0,200}(SogouPY|SogouInput|BaiduPinyin|QQPinyin|userdict)",
                          r"(?i)(SogouPY|SogouInput|BaiduPinyin|QQPinyin)[^\n]{0,200}\.(dat|bin|db)\b"],
     "description": "Agent read the input-method user dictionary, which records what the user has typed"},
    {"id": "DST-11",
     "description_zh": "写进云盘同步目录 —— 同步客户端会自动把它传上云", "remediation_zh": "确需放行：antinel paths add <目录前缀>（进审计链）；否则写进项目内", "category": "destructive", "severity": "critical",
     "check": "path_in_cloud_sync_dir",
     "apply_to_tools": ["Write", "Edit", "Bash"],
     "description": "Agent wrote into a cloud-drive sync folder: the sync client will upload the file automatically"},
    {"id": "NET-04",
     "description_zh": "建立隧道/隐蔽信道（反向隧道、代理、DNS/ICMP 载波）——绕过常规出网检查", "remediation_zh": "隧道会绕过常规出网检查；放行前先确认目标", "category": "network", "severity": "warning",
     "apply_to_tools": ["Bash", "WebFetch", "WebSearch", "MCP"],
     "command_patterns": [r"(?i)\b(ngrok|frpc|frps|v2ray|xray|sing-box|trojan|hysteria|clash|shadowsocks|ss-local)\b",
                          r"(?i)\b(icmpsh|ptunnel|iodine|dnscat2?|hans|chisel|socat|stunnel|obfs4)\b",
                          r"(?i)\bnc(at)?\b[^\n]{0,60}\s-[a-z]*e\b",
                          r"(?i)\bssh\b[^\n]{0,80}\s-[RLD]\s",
                          r"(?i)\bping\b[^\n]{0,60}\s-[lp]\s+(?:[0-9A-Fa-f]{16,}|\d{4,})",
                          r"(?i)\b(ngrok(-free)?\.(io|app)|trycloudflare\.com|serveo\.net|localtunnel\.me|"
                          r"localhost\.run|pinggy\.(io|link)|bore\.pub|lhr\.life|tunnel\.to)\b"],
     "description": "Agent opened a tunnel / covert channel (reverse tunnel, proxy, DNS-ICMP carrier) to move data out"},
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
    rules = None
    for _retry in range(3):
        try:
            with open(RULES_PATH, "r", encoding="utf-8") as f:
                rules = list(json.load(f).get("rules", []))
            break
        except (FileNotFoundError, json.JSONDecodeError, PermissionError):
            if _retry < 2:
                import time
                time.sleep(0.1)
    if rules is not None:
        return _load_rules_integrity(rules)
    # 0.29.0（A-1）：这里原本调用 _load_rules_fallback()，而该函数**从未定义** ⇒ 规则文件
    # 读不出来时不是走兜底，而是 NameError → fail-open 静默放行、链上一条记录都没有。
    # 修法不需要新写逻辑：_load_rules_integrity 一进来就会重读同一个文件（见下），读不到
    # 必然抛异常，于是自然落进它**已经写好**的 except 分支（stderr 警告 ＋
    # rules_unreadable_fallback ＋ 用内置兜底集）——一行接通即可，零新增逻辑。
    return _load_rules_integrity(None)

def _load_rules_integrity(rules):
    # ★★★ 0.33.2 (A2，2026-09-28)：**加载与完整性比对必须指向同一个文件**。
    #
    # 原实现：加载读 `RULES_PATH`（包内 `rules/default.json`），却拿
    #         `manifest["rules_hash"]` 比对 —— 而 install.py 记的 `rules_file` 是
    #         `<root>/.psl/rules/default.json`（**另一个文件**）。
    # 实测后果（套件 A4 的 FAIL 真因）：
    #   沙箱里只 install 了（有 `<root>/.psl/rules/…`）、没有包内 `rules/` ⇒ 加载读不到
    #   包内文件 ⇒ 与 manifest 的 hash 必然不符 ⇒ **无条件判 SELF-TAMPERED**。
    #   真实用户场景下两者内容恰好一致，所以这个错位**平时查不出来** ——
    #   判据指向 A、被测对象是 B，正是"能查 ≠ 查了"那条铁律的又一次现身。
    #
    # 修法：先找 manifest，按其 `rules_file` 解析出**该装的规则文件**；加载与哈希
    #       比对都用这一个路径。找不到 manifest 或 rules_file 时，退回 `RULES_PATH`
    #       （保持"未安装时也能跑"的既有行为）。
    _rules_path = RULES_PATH
    _manifest = None
    for base in (os.getcwd(), os.path.dirname(os.getcwd())):
        mp = os.path.join(base, ".psl", "manifest.json")
        if os.path.isfile(mp):
            try:
                with open(mp, encoding="utf-8") as f:
                    _manifest = json.load(f) or {}
            except Exception:
                _manifest = None
            if _manifest is not None:
                _rf = _manifest.get("rules_file")
                if _rf:
                    _cand = _rf if os.path.isabs(_rf) else os.path.join(base, _rf)
                    if os.path.isfile(_cand):
                        _rules_path = _cand        # ← 加载与比对同源
                break
    try:
        with open(_rules_path, "r", encoding="utf-8") as f:
            rules = list(json.load(f).get("rules", []))
        # A4: runtime integrity check against the manifest recorded at install.
        # A mismatch means the monitored party may have edited the rules -> do NOT
        # trust them; fall back to the embedded minimal set and say so loudly.
        if _manifest is not None:
            rh = _manifest.get("rules_hash")
            if rh:
                try:
                    with open(_rules_path, "rb") as f:
                        live = "sha256:" + hashlib.sha256(f.read()).hexdigest()
                except Exception:
                    live = None
                if live is not None and live != rh:
                    try:
                        sys.stderr.write("[Antinel] SELF-TAMPERED: %s differs from the "
                                         "installed manifest hash; falling back to the embedded minimal "
                                         "set. Re-run install.py if this update is intentional.\n"
                                         % os.path.basename(_rules_path))
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
                                   "reason": "rules file differs from manifest rules_hash; "
                                             "fell back to the embedded minimal set",
                                   "rules_file": _rules_path,
                                   "expected": rh, "live": live,
                                   "rules_loaded": len(_FALLBACK)}, mirror=True)
                    except Exception:
                        pass
                    return [dict(r) for r in _FALLBACK]
    except Exception as e:
        # 0.16.0 (P0-7): the two fallback paths used to be indistinguishable in
        # the audit log -- "rules tampered" (A4 mismatch above) and "rules
        # unreadable" (here) both degraded to the embedded minimal set with at most one stderr
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
EMPTY_POLICY = {"domains": [], "paths": [], "commands": [], "alert_threshold": "warning", "agent_paths": [],
                "fail_closed_on_audit_loss": False}

# 0.33.1: 本次调用的策略快照，供 _deny_payload 读 settings.deny_stdout_hosts。
_POLICY = {}


def _norm_prefix(p):
    """A12: normalise a whitelist path prefix. Root-like inputs (".", "..", "/",
    "C:\\", "c:") normalise to strings that match *every* path, so a single such
    entry switched off all SEC-* critical rules at once (measured: read .env,
    .aws/credentials and .kube/config all went from block to allow). They are
    rejected here and dropped by the caller.
    0.18.0 (R-19 second half, audit HP-48/H-10): entries containing a mid-path
    ".." or wildcards are rejected too -- same validation strength as
    workspace_roots (which already rejected these). Fail-closed: a rejected
    entry releases nothing."""
    s = (p or "").replace("\\", "/").strip().lower()
    if s in ("", ".", "..", "/"):
        return ""
    was_abs_posix = s.startswith("/")           # POSIX 绝对路径（0.28.0：
    s2 = s.lstrip("./")                         # 修复 Linux 白名单永不释放）
    if not s2 or s2.endswith(":") or s2.endswith(":/"):
        return ""
    if ".." in s2 or any(ch in s2 for ch in "*?["):
        return ""
    if was_abs_posix and not s2.startswith("/"):
        s2 = "/" + s2
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
            _agent_paths = [q for q in (_norm_prefix(x) for x in (
                pol.get("agent_paths") or wl.get("agent_paths") or [])
                if isinstance(x, str) and x.strip()) if q]
            return {"domains": [d.lower().strip() for d in wl.get("domains") or [] if isinstance(d, str) and d.strip()],
                    "paths": [q for q in (_norm_prefix(x) for x in wl.get("paths") or []
                                         if isinstance(x, str) and x.strip()) if q],
                    "agent_paths": _agent_paths,
                    "commands": [c for c in wl.get("commands") or [] if isinstance(c, str) and c],
                    "alert_threshold": thr if thr in ("warning", "critical") else "warning",
                    # 0.18.0 (R-18, audit H-05/H11): the key the v0.17 stderr text
                    # promised is now actually read. Default False (fail-open --
                    # a guardrail must not take the host down over its own log
                    # dir); when True, an audit write failure BLOCKS the call.
                    "fail_closed_on_audit_loss":
                        str((gs.get("fail_closed_on_audit_loss", False))).lower() == "true",
                    # 0.24.0 (BUDGET-01): 预算键随 global_settings 原样透传
                    "settings": gs}
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


_RL_PREFIX_CACHE = {}


def _real_prefixes(prefixes, project_root):
    """0.18.0 (R-19, audit HP-22): realpath the prefixes ONCE per (root, prefixes)
    and compare realpath(file) against them -- the SAME rule the boundary check
    uses. Before this, the release was lexical (startswith on the raw string)
    while the boundary was realpath: a junction/symlink named like a whitelisted
    prefix released a write whose REAL landing spot was outside the whitelist
    (and vice versa). Cached: policy prefixes are stable per process."""
    key = (str(project_root), tuple(prefixes))
    hit = _RL_PREFIX_CACHE.get(key)
    if hit is None:
        out = []
        for p in prefixes:
            cand = p if re.match(r"^[A-Za-z]:", p) or p.startswith("/") or p.startswith("\\") \
                else os.path.join(project_root, p.replace("/", os.sep))
            rp = _safe_realpath(cand)
            if rp:
                out.append(rp.replace("\\", "/").lower().rstrip("/") + "/")
        hit = tuple(out)
        _RL_PREFIX_CACHE[key] = hit
    return hit


def path_whitelisted(file_path, project_root, prefixes):
    """Lexical release check (primary) + realpath advisory (secondary).

    Primary: lexical startswith (normalize both sides, then prefix match).
    This is the check the tests were written against and the one that works
    reliably in temp directories.

    Secondary: realpath cross-check catches junctions/symlinks that LEXICALLY
    match a whitelisted prefix but resolve OUTSIDE it. This is advisory-only
    (logged, not blocking) because realpath resolution can differ between the
    hook process and the host process (temp dirs, subst drives, etc.).

    0.20.1: the 0.20.0 version used realpath-ONLY which broke 5 tests (the
    whitelist.paths release chain: F-06 + three DST-02 tests) because Windows
    symlink resolution in temp dirs didn't match between prefix and file.
    Reverted to lexical as the release criterion; realpath remains as a
    tool-level check in verify_chain.py."""
    if not file_path or not prefixes:
        return False

    # Primary: lexical (normalize both sides, then startswith)
    norm_prefixes = [_norm_prefix(x) for x in prefixes]
    cands = [file_path.replace("\\", "/").lower()]
    try:
        rel = os.path.relpath(os.path.abspath(file_path), project_root).replace("\\", "/").lower()
        if not rel.startswith("../"):
            cands.append(rel)
    except Exception:
        pass
    released = any(c.startswith(np) for c in cands for np in norm_prefixes if np)
    if released:
        # 0.22.0 (R-19, reopened when the load_policy NameError fix brought the
        # whitelist back to life): lexical release stays primary, but a junction
        # that LEXICALLY matches a whitelisted prefix while its REAL target sits
        # outside every whitelisted prefix is a bypass, not a release. realpath
        # here can only ever NARROW a lexical release, never widen it, so the
        # 0.20.0 failure mode (8.3 short-name temp dirs breaking a realpath
        # PRIMARY) cannot recur: we still return True on any lexical or
        # realpath-form prefix match, and veto only when the file exists under
        # a concrete realpath matching NEITHER form. The DST-02 boundary check
        # already resolves realpath for the same path, so no new sandbox
        # promise is being made. A veto simply falls through to the normal
        # DST-02 block, which is audited like any other block -- recorded,
        # never silent.
        rp = _safe_realpath(file_path)
        if rp and rp.replace("\\", "/").lower() != file_path.replace("\\", "/").lower():
            rp_n = rp.replace("\\", "/").lower().rstrip("/") + "/"
            for x in prefixes:
                np = _norm_prefix(x)
                if np and rp_n.startswith(np):
                    return True
                cand = x if re.match(r"^[A-Za-z]:", x) or x.startswith("/") or x.startswith("\\") \
                    else os.path.join(project_root, x.replace("/", os.sep))
                rp_prefix = _safe_realpath(cand)
                if rp_prefix:
                    rp_prefix_n = rp_prefix.replace("\\", "/").lower().rstrip("/") + "/"
                    if rp_prefix_n and rp_n.startswith(rp_prefix_n):
                        return True
            return False                      # veto: real target outside the whitelist
        return True

    # Secondary: realpath cross-check (advisory, not blocking)
    # A junction/symlink that LEXICALLY matches but REALPATH resolves outside
    # is a potential bypass — logged but not blocked (the hook cannot verify
    # junctions without resolving them, which is a sandbox promise).
    return False


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
# 0.33.2 (D-3): 解释器首词 —— 它们不是"只读动词"，但 `-c/-e` 里的字符串字面量是数据。
# 判据仍以「引号外残留代码」为准（见 _strip_interpreter_code_literals），
# 所以这里放宽的是**数据位置**，不是**执行位置**。
_INTERPRETERS = frozenset("python python3 python3.13 python3.12 python3.11 py node nodejs perl ruby php bash sh zsh pwsh powershell".split())
# ★ 判据不二次实现：删除类模式从 DST-01 的**同一真源**取。
#   `_rules` / `_FALLBACK_RULES` 的 DST-01 条目在模块加载后即可用；
#   取不到时退回空集 —— 空集只会让 `readonly_command_context` 更保守（返回 False），
#   方向安全，且 NOT_HARDCODED 检查项会盯住这个引用。
def _dst_command_patterns():
    """DST-01 的 command_patterns，取自规则表本身（唯一真源）。

    优先用磁盘规则表（load_rules 的结果），失败时退回内嵌兜底表 `_FALLBACK`。
    两条路都取不到时返回空集 —— 空集只让调用方更保守（见 readonly_command_context），
    方向安全。
    """
    out = []
    try:
        for r in load_rules():
            if r.get("id") == "DST-01":
                out.extend(_patterns(r, "command_patterns"))
                if out:
                    return out
    except Exception:
        pass
    try:
        for r in _FALLBACK:
            if r.get("id") == "DST-01":
                out.extend(_patterns(r, "command_patterns"))
                if out:
                    return out
    except Exception:
        pass
    return []


_DST_PATS_CACHE = []


def _dst_command_pats():
    """惰性求值 + 缓存：模块加载时规则可能还没就绪。"""
    if not _DST_PATS_CACHE:
        _DST_PATS_CACHE.extend(_dst_command_patterns())
    return _DST_PATS_CACHE
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


# ★★★ 0.44.0（结构化修复 · 改动 1）：前缀剥离正则的尾部由「必须有空白」扩展为
#   「空白**或到行尾**」，并做**引号感知**（值允许：双引号串 ｜ 单引号串 ｜ 无空白串）。
#
#   旧写法 `^[A-Za-z_][A-Za-z0-9_]*=\S*\s+` 有两个毛病（2026-10-10 实测，方案 v2.0 §2.2）：
#     ① 当整段**只是一个赋值、后面没有别的命令**时（如 `F="x.md"`），尾部没有空白
#        ⇒ 匹配失败 ⇒ 首词被取成 `f="x.md"` ⇒ 不在只读动词表 ⇒ **整条命令被否决**。
#        实测：一条「赋值 ＋ grep」的命令因此从「提醒」被误降为「拦截」（当天被拦的那条）。
#     ② `\S*` 遇值里带空格（`F="my file.txt"`）就断在空格处，把 `file.txt"` 当成命令词
#        ⇒ 同样误拦。所以必须**引号感知**。
#   新写法把「值」限定为三种形态之一，尾部对齐到「空白或行尾」。
#   ★ 方向安全：值写不进去时退回"不剥离"（首词仍非只读动词）⇒ 宁可多拦，不可漏放。
_ASSIGN_HEAD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_ASSIGN_PREFIX_RE = re.compile(
    r'^[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|\'[^\']*\'|\S*)(?:\s+|$)')


def _first_token(cmd):
    s = cmd.strip()
    while True:                                             # strip FOO=bar prefixes
        m = _ASSIGN_PREFIX_RE.match(s)
        if not m:
            break
        rest = s[m.end():].lstrip()
        if rest == s:                                        # 防零宽匹配死循环（理论不可达）
            break
        s = rest
    if not s:
        return ""
    tok = s.split(None, 1)[0].strip("\"'")
    tok = tok.replace("\\", "/").split("/")[-1]             # C:\tools\grep.exe -> grep
    if tok.lower().endswith(".exe"):
        tok = tok[:-4]
    return tok.lower()


# 0.33.2 (D-3): 解释器的 `-c`/`-e` 参数里，**引号内的字符串字面量是数据，不是代码**。
#
# 实测假阳性（2026-09-28，负控 F1-F4）：判据只看首词，而 `python` 不在
# _READONLY_CMDS 里 ⇒ 下面四条「删除字样只出现在字符串里」的命令全被 BLOCK：
#     python -c "print('rm -rf /')"
#     python -c "x='shutil.rmtree'; print(x)"
#     python -c "print(re.escape('rm'))"
#     python -c "print('os.remove')"
# 这是我们自家纪律说的「会误报的检查器用两次就没人信」——而它误报的正是
# 「我在写一条关于删除的文档/命令」这种**最该被允许**的场景。
#
# 修法是缩小"数据"的范围，不是放松"执行"的判定：把 `-c` 参数里**最外层引号内**
# 的字符串替换成占位符后再看剩余文本。字符串里的删除字样消失，而**留在引号外**
# 的仍然是代码，照旧会命中 —— 所以下面两条真删除仍然 BLOCK：
#     python -c "import shutil; shutil.rmtree('/tmp/x')"   -> shutil.rmtree( 在引号外
#     python -c "import os; os.system('rm -rf /tmp/x')"     -> os.system( 在引号外
# 已知边界：嵌套引号（如 print("a'b")）只剥最外层，剥不干净时退回原判定
# （即仍可能拦），方向安全——宁可多拦，不可漏放。
_INTERP_C_ARG_RE = re.compile(
    r"(?:^|\s)(?:-c|-e)\s+([\"'])(.*)\1\s*$", re.DOTALL
)


def _strip_interpreter_code_literals(seg):
    """把解释器 -c/-e 参数里的**字符串常量**换成空串，但**不**放过任何"把字符串当命令跑"的调用。

    ★ 关键区分（2026-09-28 负控 T7/T8 实测）：
        python -c "print('rm -rf /')"                    -> 数据，应放行
        python -c "import os; os.system('rm -rf /tmp')"  -> 执行，必须拦
        python -c "import subprocess; subprocess.run(['rm','-rf','/tmp'])" -> 执行，必须拦
    三者都是"引号里出现 rm"，**所以"在不在引号里"根本不是判据**。它们真正的区别是
    字符串**是否被送进执行通道**。

    做法：用 ast 解析 -c 的源码。若字符串常量只出现在非执行位置 -> 返回"已净化"的
    残留（供 readonly_command_context 判定为提及）；一旦发现字符串被喂给执行类调用
    （os.system / subprocess / eval / exec / os.popen / 任何 .run/.call 等），
    直接返回原段 —— 让原判定继续拦。
    """
    r = _interp_mention_residue(seg)
    return seg if r is None else r


def _interp_mention_residue(seg):
    """真源判据：这条解释器段还能不能判"提及"。

    返回：
      · 已净化的残留字符串 —— **可以判"提及"**（python 系列 + 解析成功 + 全纯消费调用）
      · None               —— **判不了**（非解释器 / 非 python 系列 / 无 -c 参数 /
                              解析失败 / 出现执行通道 / 出现未知调用）

    ★ 单一来源：`_strip_interpreter_code_literals`（返回段）与
      `readonly_command_context`（判提及）都调这里，避免两份判据分叉。
    """
    tok = _first_token(seg)
    if tok not in _INTERPRETERS:
        return None
    m = _INTERP_C_ARG_RE.search(seg)
    if not m:
        return None
    code = m.group(2)

    # 只有 Python 系列能用 ast 判；其它解释器（node/perl/bash/powershell）保守处理：
    # 返回 None ⇒ 调用方不判"提及"⇒ 维持原有拦截能力（方向安全）。
    if not tok.startswith(("python", "py")):
        return None

    try:
        import ast                       # 局部导入：只在解释器分支才付代价，
    except Exception:                    # 不影响钩子冷启动（每次工具调用都跑）
        return None

    try:
        tree = ast.parse(code)
    except Exception:
        return None                    # 解析不了 ⇒ 保守，不放过

    # 见到这些名字，直接认定"字符串可能被执行" ⇒ 不净化
    exec_names = {"system", "popen", "run", "call", "check_call", "check_output",
                  "Popen", "eval", "exec", "execfile", "spawn", "spawnSync",
                  "execSync", "execFile", "execFileSync", "compile", "loads"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = getattr(f, "attr", None) or getattr(f, "id", None)
            if name in exec_names:
                return None            # 有执行通道 ⇒ 不净化，继续拦

    # ★★ 2026-09-28 负控发现的交互风险（必须写下来，否则下一个人会踩）：
    #    `python -c "from shutil import rmtree; rmtree('/x')"` —— `rmtree` 作为**裸函数名**
    #    出现，而 DST-01 的模式是 `\bshutil\.rmtree\b`（要求带前缀）⇒ hit=False ⇒ 本条
    #    本来就漏（**既有漏洞，非 D-3 引入**，已用对照实验证实）。
    #    但 D-3 会把 ro 从 False 变 True ⇒ **一旦将来把 `\brmtree\b` 补进模式表，
    #    本条会因 ro=True 而被降级放行** —— 修复一个漏洞却打开另一个。
    #
    # 因此这里的纪律是**白名单而非黑名单**：只有当每一个调用都是"已知纯消费"时才敢
    # 认定是纯数据；出现任何**未知调用**一律返回 None（保守），让模式表继续说了算。
    # 白名单必须窄 —— 只放行"把参数字符串当**输出**用"的函数。
    _BENIGN_CALLS = {"print", "format", "join", "split", "strip", "lower", "upper",
                     "escape", "dumps", "loads", "len", "repr", "str", "list", "dict",
                     "set", "tuple", "sorted", "enumerate", "range", "get", "keys",
                     "values", "items", "endswith", "startswith", "replace", "encode",
                     "decode", "add", "append", "extend", "update"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = getattr(f, "attr", None) or getattr(f, "id", None)
            if name not in _BENIGN_CALLS:
                return None            # 未知调用 ⇒ 保守，不净化

    # 全部是已知纯消费调用 ⇒ 把字符串常量清空后再看残留
    try:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                node.value = ""
        return ast.unparse(tree)
    except Exception:
        return None


def readonly_command_context(command):
    """True when a dangerous word in this command is a mention, not an execution.

    Every segment must be a read-only verb: `cd src && grep -n x f` is no more
    dangerous than `grep -n x f`, and blocking the first form is exactly how a hook
    gets uninstalled. Conversely `grep x | xargs rm` fails here, because xargs is not
    a read-only verb -- so a chain is only accepted when ALL of it is read-only.

    0.33.2 (D-3): 解释器段先剥掉 `-c` 参数里的字符串字面量再看首词——`python` 本身
    不在 _READONLY_CMDS 里，导致 `python -c "print('rm -rf')"` 被误拦（见上）。"""
    if not command or len(command) >= SCAN_LIMIT:
        return False
    segs, danger = _scan_command(command)
    if danger or not segs:
        return False
    for seg in segs:
        # ★★★ 0.44.0（结构化修复 · 改动 2）：**纯赋值段**（剥完前缀后没有剩余命令）
        #   没有执行意图 ⇒ 视为中性，跳过该段，不参与否决。
        #
        #   为什么这才叫根治：不是给名单加一条例外，而是**换掉判据的来源** ——
        #   从「这段文本像不像只读」换成「这一段的结构是什么」。不这么做，每遇到一种
        #   新写法就要加一条例外，名单永续增长。
        #
        #   ★ 一处行为变化（方案 §3.3 已提前声明）：`VAR=x; rm -rf dist` 这类写法会从
        #     「拦」变成「走豁免放行」——这是**消除不一致**（规则本就写明该目标在豁免内，
        #     之前只是被那句赋值连带否掉了），且放行照常记 `exclude_patterns_allow`，留痕不失。
        #   ★ 硬纪律：赋值建起来的变量表**只许用于展示/提示/目标提取，不许用于匹配豁免
        #     名单**。所以 `F="dist"; rm -rf "$F"` 仍然拦（删除段的动词不是只读动词）。
        if _ASSIGN_HEAD_RE.match((seg or "").strip()) and _first_token(seg) == "":
            continue
        tok = _first_token(seg)
        if tok in _INTERPRETERS:
            # ★★★ 0.33.2 (D-3a，2026-09-28 实测修正)：解释器分支**先问"能不能判"，
            # 再问"是不是提及"**。只有 python 系列可以判"提及"。
            #
            # 原实现拿 `_dst_command_pats()`（**只含 DST-01 模式**）去回答"危险词还在不在"，
            # 而这个问题**需要覆盖全部规则的 command_patterns**。实测反例：
            #     powershell -c "Set-Content -Path .\data.txt -Stream evil -Value x"
            #   · 真正命中的是 **DST-10**（`Set-Content … -Stream`）
            #   · 但 DST-01 模式在残留里命中 0 ⇒ 被误判为"只读提及" ⇒ 上层把 DST-10 的
            #     block 降级成 alert（`and ro_cmd` 那一句）⇒ 套件 FAIL
            # ⇒ **窄判据被用来裁决宽问题**。这是"判据不许二次实现"的镜像错误。
            #
            # 修法：判据的适用面**收缩到我们有把握解析的那种解释器**。
            #   · python 系列：`_strip_interpreter_code_literals` 用 ast 真解析过，能区分
            #     "字符串常量"与"送进执行通道"，可以谨慎认可"提及"。
            #   · 其余（powershell/pwsh/node/bash/perl/ruby/php/sh/zsh）：
            #     我们**不解析**它们的语法，任何"提及"判断都是猜的 ⇒ 一律 return False
            #     （不放过），与 `_strip_interpreter_code_literals` 里"非 python 保守"
            #     的取向一致。**方向安全**：宁可多拦，不可少拦。
            #
            # 判据用 `_interp_mention_residue(seg)`：可判且已净化 ⇒ 返回 residue 字符串；
            # 不可判（非 python / 解析失败 / 走执行通道）⇒ 返回 None。
            residue = _interp_mention_residue(seg)
            if residue is None:
                return False               # 判不了 ⇒ 不放过
            if not any(_search(p, residue) for p in _dst_command_pats()):
                return True
            return False
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


_LANG_CACHE = [None]


def _lang():
    """Detect UI language. Precedence (0.20.0 修正为与 docstring 一致):
    ANTINEL_LANG env > system locale (cached, suppressed warning) > policy.json > 'en'.
    0.20.0: (a) locale.getdefaultlocale() 每次新进程都向 stderr 打
    DeprecationWarning——用 warnings 抑制＋缓存修复；(b) 结果缓存避免重读。"""
    if _LANG_CACHE[0]:
        return _LANG_CACHE[0]
    import warnings
    v = os.environ.get("ANTINEL_LANG", "")
    if v in _LANG_SUPPORTED:
        _LANG_CACHE[0] = v
        return v
    # system locale (Windows: reads user locale; Linux: reads LANG env)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            import locale
            loc = (locale.getdefaultlocale()[0] or "").lower()
            if loc.startswith("zh"):
                _LANG_CACHE[0] = "zh"
                return "zh"
        except Exception:
            pass
    # policy.json fallback
    for base in (os.getcwd(), os.path.dirname(os.getcwd())):
        p = os.path.join(base, ".psl", "policy.json")
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                lang = (json.load(f).get("language") or "").lower()
            if lang in _LANG_SUPPORTED:
                _LANG_CACHE[0] = lang
                return lang
        except Exception:
            pass
    _LANG_CACHE[0] = "en"
    return "en"


def _pick(rule, field, lang):
    """Select rule text: {field}_{lang} first, then the bare field (English), then {field}_zh.

    ★ 0.34.1 修：旧实现是 `for l in (lang, "en", "zh")` 再回退裸字段。
      rules/default.json 里**只有裸字段（英文）与 `_zh`**，没有 `_en` ——
      于是 lang="en" 时循环里 `_zh` 先命中，**英文用户拿到中文文案**。
      这正是「先查 `_zh` 再查英文」的顺序错，与 docstring 写明的
      「then English, then zh」相反。现在按 docstring 修正：
      先 `_{lang}`，再裸字段（英文），最后才是 `_zh`。
    """
    for l in (lang, "en"):
        v = rule.get(f"{field}_{l}")
        if v:
            return v
    return rule.get(field, "") or rule.get(f"{field}_zh", "")

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
    # 0.18.0 (HP-01/已登记逃逸 #1/#2/#4): cmd caret-escape and PowerShell
    # backtick-escape -- `d`el` and `d^el` hid the verb from every pattern.
    # Conservative: only strips an escape before an alphanumeric (a lone ^ or
    # one before punctuation is shell syntax, not an escaped verb).
    out.append(re.sub(r"\^(?=[A-Za-z0-9])", "", cmd))
    out.append(re.sub(r"`(?=[A-Za-z0-9])", "", cmd))
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
    """0.28.3（A7/A8）：MCP 工具名不可枚举（mcp__<server>__<tool>），以伪工具名
    "MCP" 在 apply_to_tools 里声明纳管——宿主自带 WebFetch/WebSearch 直接点名。"""
    tools = rule.get("apply_to_tools") or []
    if not tools:
        return True
    if tool in tools:
        return True
    if tool.startswith("mcp__") and "MCP" in tools:
        return True
    return False


# 0.19.0 (ADS round): RULE-LEVEL PLATFORM GATE.
# A rule may declare "platforms": ["nt"] (or ["posix"]); a rule without the key
# applies everywhere -- which is every rule written before 0.19.0, so this is
# additive and cannot silently narrow an existing rule.
# The rule STAYS in the loaded list on every host -- only the matcher skips it.
# That is deliberate: rule counts, references/RULES.md and the package manifest
# digest are then byte-identical on all three CI operating systems, and the only
# thing that differs is behaviour, which is exactly what the field is for.
# Motive: an NTFS alternate data stream (path:stream) is ordinary text on POSIX,
# where "file.txt:stream" is a LEGAL FILENAME. An ungated rule would turn the
# Linux/macOS CI cells into a false-positive machine (measured: this is the
# reason DST-09/DST-10 are nt-only rather than pattern-narrowed).
_HOST_PLATFORM = "nt" if os.name == "nt" else "posix"


def _platform_applies(rule):
    plats = rule.get("platforms")
    if not plats:
        return True
    if isinstance(plats, str):
        plats = [plats]
    return _HOST_PLATFORM in plats


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


# ══════════════════════════════════════════════════════════════════════════════
# ★★★ 0.46.0：**删除许可（VCT）** —— 「能不能删」的两票裁决（方案 v3.0 §3.4/§3.5）
# ══════════════════════════════════════════════════════════════════════════════
# 由来：删除类判定的现状是「**只有一份兜底名单**（exclude_patterns）做判据」⇒ 名单越长、
#   攻击面越大；且「清理构建目录」这类最日常的动作会持续误拦（名单里塞了 dist/build/...）。
#   改成**两票都同意才允许删除**：
#     第一票 —— 用户自己**声明**过这是产物吗？（版本工具忽略查询，**必须带忽略索引参数**）
#     第二票 —— 它真的**能再来一份**吗？（向上查找各生态的构建描述文件）
#   两票做**并且**运算；兜底名单**降级**为两票都取不到信号时的最后退路。
# ★ 三处强化（方案 §3.4）：① 用忽略规则的**反向语义**（工作树内且未被声明为产物即受保护），
#   不用「追踪清单」（追踪清单覆盖不到刚写完还没提交的新代码）；② **忽略声明优先于已追踪**
#   （本仓现成反例：`_archive_dist/` 在忽略规则里，索引里却有 23 个被追踪文件）；③ 与
#   「可再生」做**并且**运算，不是或者（配置文件常被写进忽略规则，但删了就真没了）。
# ★ 性能（方案 §3.6）：单次忽略查询约 404ms ⇒ **绝不进热路径**；只在「已判定为删除类
#   操作且已拿到字面目标」之后调用，带 **2 秒超时**，超时走出口丙且留痕。
# ★ 纪律 10.8：工作树外路径（git 返回 128）走**出口丙**，**不许**把 128 当成「未被忽略」。

VCT_TIMEOUT = 2.0                 # 单次版本查询超时（秒）
VCT_MAX_UP = 12                   # 第二票向上查找的最大层数

#: 第二票「可再生」的信号源：各生态的**构建描述文件**。只认文件事实，不认目录名。
#: 前缀 `*.` 表示按扩展名匹配（如 `*.csproj`）。
VCT_BUILD_DESCRIPTORS = (
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
    "package.json", "Cargo.toml", "go.mod", "pom.xml", "build.gradle",
    "build.gradle.kts", "CMakeLists.txt", "Makefile", "composer.json",
    "Gemfile", "meson.build", "*.csproj", "*.sln", "*.vcxproj",
)

#: 段内的「选项」token（`-rf` / `-Recurse` / `del` 的 `/s`）—— 不是目标。
_VCT_FLAG_RE = re.compile(r"^-[A-Za-z][A-Za-z0-9-]*$|^/[A-Za-z]$")
#: 含这些字符的 token 不是**字面**目标（变量/反引号/通配/替换）⇒ 出口乙。
_VCT_NONLITERAL_RE = re.compile(r"[`$*?\[\]{}<>()|&;!]")


def _vct_run_git(args, cwd, timeout=VCT_TIMEOUT):
    """跑一次 git；返回 `(rc, stdout, stderr)`。超时/异常 ⇒ rc=None（调用方走出口丙）。

    ★ 惰性 import subprocess：本模块被钩子在**每次工具调用**时导入，而 VCT 只在
      「删除类且拿到字面目标」时才走到 ⇒ 不为罕见的路径付常驻启动成本。
    """
    try:
        import subprocess
    except Exception:                                            # noqa: BLE001
        return None, "", ""
    try:
        # ★ 必须显式 `CREATE_NO_WINDOW`（0.35.3 创始人报障「窗口不停弹出又马上关掉」）：
        #   钩子由宿主拉起、未必带控制台 ⇒ 起 git 若不显式禁窗，会为子进程新建控制台
        #   ＝ 黑窗一闪。`-WindowStyle Hidden` 挡不住（窗口在建进程时就已创建）。
        #   判据 P12（ci/inbox_guards_0353.py）扫**全部**起子进程的调用，漏一个就红。
        p = subprocess.run(["git"] + list(args), cwd=cwd, timeout=timeout,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           creationflags=_CREATE_NO_WINDOW)
        return (p.returncode,
                p.stdout.decode("utf-8", "replace"),
                p.stderr.decode("utf-8", "replace"))
    except Exception:                                            # noqa: BLE001
        return None, "", ""


def _vct_worktree_root(project_root):
    """工作树根（`git rev-parse --show-toplevel`）；取不到 ⇒ None（走出口丙）。"""
    rc, out, _err = _vct_run_git(["rev-parse", "--show-toplevel"],
                                 project_root or os.getcwd())
    if rc == 0 and out.strip():
        return os.path.normpath(out.strip())
    return None


def _vct_seg_tokens(seg):
    """把一段命令切成 token（**尊重引号**，剥掉外层引号）。

    ★ 不用 `shlex`：Windows 路径里的反斜杠会被 shlex 当成转义符 ⇒ 把 `C:\\a\\b` 切坏。
    """
    out, cur, q = [], [], None
    for c in seg:
        if q:
            if c == q:
                q = None
            else:
                cur.append(c)
            continue
        if c in "\"'":
            q = c
        elif c.isspace():
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(c)
    if cur:
        out.append("".join(cur))
    return out


def _vct_literal_targets(command):
    """从**删除类段**里取字面目标路径。返回 `(targets, why, is_delete)`。

    · is_delete=False ⇒ 这条命令**压根不是删除类操作**（方案 §3.5 步骤三：到此结束，
      不进入删除许可，也**不留痕** —— 否则 `ls -la` 也会被记一笔）；
    · is_delete=True 且 targets 非空 ⇒ 拿到了字面目标（可进删除许可）；
    · is_delete=True 且 targets 为空 ⇒ why 说明原因（**出口乙**：取不到字面目标）。

    ★ 只取**字面**（不含 `$VAR` / 反引号 / 通配 / 命令替换）—— 变量展开值**只用于
      展示/提示**，**绝不**用于匹配豁免（硬纪律 10.5）。取不到就退回兜底名单，方向安全。
    ★★ 判定顺序：先过 `readonly_command_context` 再置 `is_delete` ——
      `echo "rm -rf dist"` 只是**提及**删除词，不是删除类操作（否则它会被记成
      「删除许可取不到目标」，把账本写成一条根本不该有的记录）。
    """
    try:
        segs, _danger = _scan_command(command)
    except Exception:                                            # noqa: BLE001
        return [], "分段失败", False
    pats = _dst_command_pats()
    if not pats:
        return [], "删除类模式不可用", False
    out = []
    is_delete = False
    for seg in segs:
        if not seg or not seg.strip():
            continue
        if not any(_search(p, seg) for p in pats):
            continue
        if readonly_command_context(seg):
            continue                       # 只是"提及"（echo/grep 参数里的删除词）
        is_delete = True                   # ← 到这里才算「这条命令是删除类操作」
        toks = _vct_seg_tokens(seg)
        for t in toks[1:]:                 # 跳过首词（动词）
            if not t or _VCT_FLAG_RE.match(t):
                continue
            if _VCT_NONLITERAL_RE.search(t):
                return [], "目标含变量/通配/替换（取不到字面目标）", True
            t = t.rstrip("/\\")                # `dist/` -> `dist`
            if t.startswith("./") or t.startswith(".\\"):
                t = t[2:]                      # `./build` -> `build`（Windows 习惯写法）
            elif (t.startswith(".") and len(t) > 1 and not t.startswith("..")
                  and (".\\" + t[1:]) in command):
                # ★★ `_scan_command` 把 `\X` 当**转义符**吞掉（`.\build` ⇒ `.build`），
                #   所以上面那条 `startswith(".\\")` 对 PowerShell/CMD 写法**永远不触发**
                #   —— 实测：`Remove-Item .\build` 被判成 `.build`（受保护）⇒ 误拦。
                #   这里用**原命令**里是否真写着 `.\<名字>` 来还原（确定性判据，不看猜测）。
                #   只看原命令文本，不依赖任何外部状态 ⇒ 不会把 `.psl` 这类真隐藏目录改坏。
                t = t[1:]
            out.append(t or ".")
    if not out:
        return [], "取不到字面目标", is_delete
    return out, "", is_delete


def _vct_vote1(abs_target, root):
    """第一票：**用户声明过这是产物吗**（版本工具忽略查询）。返回 `(state, detail)`。

    state ∈ {`ignored`, `protected`, `outside`, `unavailable`}：
      · `ignored`    —— 被忽略规则声明为产物（rc=0）；
      · `protected`  —— 未被声明为产物 ⇒ **受保护**（rc=1）；
      · `outside`    —— 路径在工作树外（rc=128）⇒ **出口丙**（纪律 10.8）；
      · `unavailable`—— 查询超时/异常/其它返回码 ⇒ **出口丙**。

    ★★ 必须带 `--no-index`：不带时，**已追踪**文件会被报成「未被忽略」（rc=1）——
      本仓现成反例：`_archive_dist/` 明明在忽略规则里，索引里却有 23 个被追踪文件。
      若用「追踪清单」当判据，「清理产物」这个最日常的动作会立刻变成新的误拦。
      **用户手写的产物声明，语义强于一次手滑入库的历史事实。**
    ★★ 返回 128 是「工作树外」，**不是**「未被忽略」——把 128 当 protected 继续判，
      会按错误的前提做安全取舍；判据 S83 常驻盯这一点。
    """
    rc, _out, err = _vct_run_git(
        ["check-ignore", "--no-index", "-q", "--", abs_target], root)
    if rc is None:
        return "unavailable", "版本查询超时/异常"
    if rc == 0:
        return "ignored", ""
    if rc == 1:
        return "protected", ""
    if rc == 128 or "outside repository" in (err or ""):
        return "outside", "路径在工作树外（rc=128）"
    return "unavailable", "版本查询返回码 %s" % rc


def _vct_vote2(abs_target):
    """第二票：**它真的能再来一份吗**（向上查找各生态的构建描述文件）。

    返回 `(ok, detail)`；ok=True 时 detail 是找到的构建描述文件路径。

    ★ 为什么必须与第一票做**并且**：配置文件常被写进忽略规则，但删了就真没了
      （方案 §3.4 强化③）。只有「声明为产物」＋「可再生」同时成立，才谈得上
      「删了能再来一份」。
    ★ 为什么**要求目标是个目录**：构建**输出**是目录（dist / build / node_modules /
      target / __pycache__ …），而**配置**是文件（`.env` / `.npmrc` / `.pypirc`）——
      后者常被写进忽略规则却删了就真没了。只认「目录 ＋ 上层有构建描述」，才不会
      把「删配置」当成「清产物」。**方向安全**：认不出 ⇒ 判**不可再生**（拦）。
    ★ 从目标的**上一层**开始向上找：`rm -rf dist` 的描述文件在 `dist` 的父目录
      （pyproject.toml / package.json …），而不是 `dist` 自己里面。
    """
    if not abs_target or not os.path.isdir(abs_target):
        return False, ""                                     # 非目录 ⇒ 不认「可再生」
    cur = os.path.dirname(abs_target)
    if not cur:
        return False, ""
    for _ in range(VCT_MAX_UP):
        try:
            names = os.listdir(cur)
        except Exception:                                        # noqa: BLE001
            names = []
        low = {n.lower(): n for n in names}
        for want in VCT_BUILD_DESCRIPTORS:
            if want.startswith("*."):
                if any(n.endswith(want[1:]) for n in low):
                    return True, os.path.join(cur, want)
            elif want.lower() in low:
                return True, os.path.join(cur, low[want.lower()])
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return False, ""


def _vct_abs(target, project_root):
    """把目标解析成绝对路径（相对路径按**项目根**解析）。"""
    if os.path.isabs(target):
        return os.path.normpath(target)
    return os.path.normpath(os.path.join(project_root or os.getcwd(), target))


def _is_delete_rule(rule):
    """这条规则是不是**文件删除**类 —— 只有它才走删除许可两票。

    ★ 判据取自**数据**、不硬编码 id：本仓的「删除类命令模式」只有一个真源
      （`_dst_command_patterns()`：DST-01 的 `command_patterns`）。谁的
      `command_patterns` 与它逐条相同，谁就是那条删除规则。
    ★★ 为什么**不能**用 `category == "destructive"` 一刀切（设计期抓到的真坑）：
      DST-02…DST-11 全是 destructive 类，但它们管的是「写项目外 / 云盘同步 /
      持久化 / 提权 / git 丢弃」，**与文件删除无关**。若一并门控，
      `rm -rf dist && echo x > ~/OneDrive/y` 会因为「删除产物」拿到删除许可，
      ⇒ **顺手把云盘写入规则也放行了** —— 一个许可开两扇门，正是本仓最忌的形状。
    """
    if not rule:
        return False
    dst = _dst_command_pats()
    pats = _patterns(rule, "command_patterns")
    if not dst or not pats:
        return False
    return set(pats) == set(dst)


def deletion_permission(command, project_root):
    """**删除许可（VCT）两票裁决 ＋ 五步顺序 ＋ 四退出口**（方案 §3.4/§3.5）。

    返回 dict：
      `{'allow': True/False/None, 'exit': '', 'vote1', 'vote2', 'why', 'targets', 'is_delete'}`

      · is_delete is False —— 这条命令**不是删除类操作**（步骤三：到此结束，不留痕）；
      · allow is True  —— 两票都同意 ⇒ **放行**；
      · allow is False —— 有明确结论且至少一票否决 ⇒ **拦**；
      · allow is None  —— **取不到信号** ⇒ 走出口（`'乙'`/`'丙'`），交由兜底名单/默认拦。

    四退出口（共同要求：**不许静默**，走到哪一个都要写明"为什么走到这里"）：
      甲：命令分不出段 —— 本函数不处理（调用方按现有保守口径走）；
      乙：取不到字面目标 —— exit='乙'；
      丙：版本信号不可用/超时/工作树外 —— exit='丙'；
      丁：兜底名单也无信号 —— 由调用方处理（exit='丁'）。
    """
    # ★★ 顺序即性能（方案 §3.6：单次忽略查询约 404ms，**绝不进热路径**）。
    #   先做**不需要 git** 的目标提取（步骤二/三：这一步就筛掉了「压根不是删除类」
    #   与「取不到字面目标」的命令）——只有真的拿到了字面删除目标，才去问版本工具。
    #   反过来先定位工作树根，会让**每一条** Bash 命令都付一次 git 启动成本。
    targets, why, is_delete = _vct_literal_targets(command)
    if not is_delete:
        return {"allow": None, "exit": "", "why": why or "不是删除类操作",
                "vote1": "", "vote2": "", "targets": [], "is_delete": False}
    if not targets:
        return {"allow": None, "exit": "乙", "why": why,
                "vote1": "", "vote2": "", "targets": [], "is_delete": True}
    root = _vct_worktree_root(project_root)
    if not root:
        return {"allow": None, "exit": "丙", "why": "工作树根不可用",
                "vote1": "", "vote2": "", "targets": targets, "is_delete": True}
    for t in targets:
        abs_t = _vct_abs(t, project_root)
        v1, d1 = _vct_vote1(abs_t, root)
        if v1 in ("unavailable", "outside"):
            return {"allow": None, "exit": "丙", "why": "%s：%s" % (t, d1),
                    "vote1": v1, "vote2": "", "targets": targets, "is_delete": True}
        if v1 == "protected":
            return {"allow": False, "exit": "", "vote1": v1, "vote2": "",
                    "why": "%s 未被声明为产物（受保护）" % t, "targets": targets,
                    "is_delete": True}
        v2, _d2 = _vct_vote2(abs_t)
        if not v2:
            return {"allow": False, "exit": "", "vote1": v1, "vote2": "not_regenerable",
                    "why": "%s 声明为产物但不可再生" % t, "targets": targets,
                    "is_delete": True}
    return {"allow": True, "exit": "", "vote1": "ignored", "vote2": "regenerable",
            "why": "两票都同意（声明为产物 ＋ 可再生）", "targets": targets,
            "is_delete": True}


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
#      so an agent that wants to widen it must reach outside the project, and that
#      reach is always recorded (0.19.2: recorded is all it ever was -- see
#      is_host_config_path() for the measurement that falsified the older claim
#      that DST-02 *blocks* this file; it only ever blocked one of the two
#      channels, while also blocking the user's own delegated maintenance);
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


def _host_config_files():
    """Realpaths of the host-level config files Antinel itself reads. NOT their
    parent directories -- only these exact files are released by DST-02.
    Relative entries are skipped so a malformed ANTINEL_CONFIG cannot point the
    release at whatever the hook's cwd happens to be."""
    out = []
    for p in _workspace_config_paths():
        if not p or not os.path.isabs(p):
            continue
        try:
            r = _safe_realpath(p)
        except Exception:
            continue
        if r and r not in out:
            out.append(r)
    return out


def is_host_config_path(path):
    """True when `path` IS one of the host-level config files Antinel reads.

    0.19.2. DST-02 used to block Write/Edit on this file, on the theory recorded
    above: "an agent that wants to widen it must write outside the project, which
    DST-02 itself blocks, so the config is protected by the rule it configures".
    Measured 2026-09-14, that theory did not hold:

      - the Bash channel never blocks an out-of-root path (dst02_bash_path_suspect
        is alert-only, by design), so the block was one-sided;
      - the Bash channel only scans *literal* absolute paths in the command text,
        so `python -c "...expanduser('~')..."` reached the same file with no
        DST-02 signal at all (audit: decision=allow, rules_hit=[]).

    Net effect: the block stopped the user's own delegated maintenance (the host
    config is not writable by the tool that is supposed to maintain it) while
    leaving the other channel open. Both channels now do the same thing --
    release, and record. The release is deliberately narrow (these exact files,
    not their parents, not the whole platform directory) and every release is
    written to the audit log, so widening the boundary stays visible after the
    fact. This is a downgrade from "prevent" to "record", deliberately: the same
    posture 0.17.0 already took for out-of-root paths on the Bash channel
    ("guardrail boundary, not a sandbox").
    """
    if not path:
        return False
    try:
        rp = _safe_realpath(path)
    except Exception:
        return False
    return any(rp == h for h in _host_config_files())


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
# POSIX pseudo-devices: redirect targets like /dev/null are everyday noise.
_BASH_PATH_SKIP_PREFIXES = ("/dev/", "/proc/", "/sys/")
# 0.21.0: infrastructure paths that appear in EVERY Bash call — the interpreter
# binary itself, Git Bash's PATH prefix, and the system directory. These are the
# runtime environment, not agent-initiated writes. Measured: 4 paths accounted
# for 874/891 suspect events (98%) — all infrastructure, zero agent intent.
_BASH_INFRA_RE = re.compile(
    r"(?:[\\/](?:usr|c[/\\]Windows)[\\/]|\.workbuddy[/\\]binaries[/\\])",
    re.IGNORECASE)


def _posix_to_win(p):
    """Git Bash POSIX drive path \u2192 Windows form. `/d/2026/PSL` \u2192 `D:\\2026\\PSL`."""
    m = re.match(r"^/([A-Za-z])/(.+)", p)
    if m:
        return m.group(1).upper() + ":\\" + m.group(2).replace("/", "\\")
    return None


def _bash_absolute_paths(command):
    """Explicit absolute paths (Windows drive / POSIX multi-segment) in command text.

    Three noise filters (0.21.0):
      1. skip infrastructure paths (interpreter, /usr/bin, system dirs)
      2. POSIX\u2192Windows conversion: /d/2026/PSL IS the project root, not "outside"
      3. cap at 8 unique \u00d7 200 chars (padded commands are attack noise)"""
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
        if _BASH_INFRA_RE.search(p):
            continue
        # POSIX\u2192Windows: convert before the outside-root check
        win = _posix_to_win(p)
        if win is not None:
            p = win
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
    "qoder":       {"verified": True},                       # 0.33.0 真机实证：enforce_probe rc=2
    "trae":        {"verified": False,
                    "command": ("Bash", "command", "cmd"),  # alias candidate, unverified
                    "file_path": (("Read", "Write", "Edit"), "file_path", "path", "file")},
    "generic":     {"verified": True},
}


_HOST_DETECT_CACHE = {"mod": None, "tried": False}


def _load_host_detect():
    """0.33.1 (A-1): 归因逻辑的唯一来源。

    为什么不能写 `import _host_detect`：钩子以 `python -I -S` 启动，而 -I 隐含
    -P（脚本目录不入 sys.path），裸 import 在真机上必然 ImportError。所以按绝对
    路径显式加载。加载失败时返回 None，由调用方走兜底并在证据里留痕——
    绝不让"模块没加载到"退化成静默的旧行为。
    """
    if _HOST_DETECT_CACHE["tried"]:
        return _HOST_DETECT_CACHE["mod"]
    _HOST_DETECT_CACHE["tried"] = True
    try:
        import importlib.util
        _p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_host_detect.py")
        _spec = importlib.util.spec_from_file_location("_host_detect", _p)
        _m = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_m)
        _HOST_DETECT_CACHE["mod"] = _m
    except Exception:
        _HOST_DETECT_CACHE["mod"] = None
    return _HOST_DETECT_CACHE["mod"]


def detect_host_tag_full():
    """返回 (tag, evidence)。

    evidence 落进记录的 host_evidence 字段：归因不再是"信不信由你"，而是可复核
    （source / key / markers_seen / confidence 全在）。
    """
    _m = _load_host_detect()
    if _m is not None:
        try:
            return _m.detect()
        except Exception:
            pass
    # 兜底：模块加载失败 → 退回 0.33.0 旧逻辑，但标 source=fallback。
    # 宁可要一条"我降级了"的可见记录，也不要一次静默的失败。
    for env_key, tag in (("CLAUDE_CODE", "claude-code"), ("ZCODE_SESSION", "zcode"),
                         ("QODER", "qoder"), ("QODER_CN", "qoder"),
                         ("TRAE", "trae"), ("TRAE_CN", "trae")):
        if os.environ.get(env_key):
            return tag, {"source": "fallback", "key": env_key, "confidence": "low",
                         "detector": "inline@0.33.0"}
    cwd = os.getcwd()
    for d, tag in ((".claude", "claude-code"), (".zcode", "zcode"),
                   (".qoder", "qoder"), (".qoder-cn", "qoder"),
                   (".trae", "trae"), (".trae-cn", "trae")):
        if os.path.isdir(os.path.join(cwd, d)):
            return tag, {"source": "fallback", "key": d, "confidence": "low",
                         "detector": "inline@0.33.0"}
    return "generic", {"source": "fallback", "key": None, "confidence": "none",
                       "detector": "inline@0.33.0"}


def detect_host_tag():
    """只要标签的薄封装 —— 保持 0.33.0 的签名（tools/enforce_probe.py 依赖它）。"""
    return detect_host_tag_full()[0]


def extract(tool_name, ti, host_tag="generic"):
    """Extract (command, file_path, content, url) from tool_input for the host's layout.
    0.18.0: every value is coerced to str -- a hostile/broken host can send a
    number or an array where the text belongs; a TypeError here used to fall out
    to the fail-open handler with ZERO audit record (corpus B-043/044 -- the
    first catches by the expect_audit criterion, fixed same round)."""
    def _s(v):
        if isinstance(v, str):
            return v
        if v is None:
            return ""
        if isinstance(v, (list, dict)):      # containers (MultiEdit edits[]) must survive
            return v
        return str(v)

    ti = ti or {}
    ti = {k: _s(v) for k, v in ti.items()}
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


def _is_instruction_file(file_path):
    """0.31.0 (F1): basename in the instruction set, or a .cursor/rules/*.mdc rule file."""
    base = os.path.basename(file_path)
    if base in INSTRUCTION_BASENAMES:
        return True
    norm = file_path.replace("\\", "/")
    return any(m + "/" in norm for m in INSTRUCTION_DIR_MARKERS) and base.endswith(".mdc")


def file_text_targets(tool_name, file_path, content):
    """[(target_spec, text)] whose content file_content rules inspect.
    Read: text is loaded from disk (capped, binary skipped). Write/Edit: event content.
    0.31.0 (F1): three-level spec -- SKILL.md > instruction_file > all_text_files.
    all_text_files rules still match instruction files (superset, unchanged)."""
    if not file_path:
        return []
    base = os.path.basename(file_path)
    if base == "SKILL.md":
        spec = "SKILL.md"
    elif _is_instruction_file(file_path):
        spec = "instruction_file"
    elif base.lower().endswith(TEXT_EXTS) or base.startswith(".env"):
        spec = "all_text_files"
    else:
        spec = None
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




def _last_hash(fn):
    """末条记录的 hash（"" = 文件不存在或为空）。只读，无锁。"""
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
    return prev


def _chain_with(rec, prev):
    """给定 prev，算出 rec["prev"]（尾 16 位）与 rec["hash"]。纯函数，不碰 IO。

    L10 audit chain: rec["hash"] = sha256(prev_hash + canonical_json(rec)),
    rec["prev"] = last 16 hex of the previous record's hash ("" for first).
    Anyone can recompute the chain offline; any edit/delete breaks it."""
    rec = dict(rec)
    rec["prev"] = prev[-16:]
    canon = json.dumps({k: v for k, v in rec.items() if k != "hash"},
                       sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    rec["hash"] = hashlib.sha256((prev + canon).encode("utf-8")).hexdigest()
    return rec



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
    """0.19.1 (TN-09) 历史只读路径（锁外读末条 hash），写入用 _append_chained()。
    C-1 (v0.28)：实现收拢至 audit_chain，本文件只留薄委托。"""
    ac = _ac()
    return ac.chain_with(rec, ac.last_hash(fn))


def _acquire_lock(fn):
    return _ac().acquire_lock(fn)


def _release_lock(lock):
    _ac().release_lock(lock)


def _append_chained(fn, rec):
    """TN-09 + C-2/C-3：锁内读 prev → 锁内追加；锁预算耗尽改投 sidecar
    （chain:"unlocked"）。完整配方与叙事见 audit_chain.append_chained。"""
    return _ac().append_chained(fn, rec, on_timeout="sidecar")[0]


def _append_locked(fn, line):
    """A8 宿主镜像：锁内平文追加已序列化文本，不重算链（逐字节副本）。"""
    _ac().append_locked(fn, line)


def _touch_day_manifest(fn):
    """R-20 日锚（链外副本，检出尾部删除）。"""
    _ac().touch_day_manifest(fn)


def _last_hash(fn):
    return _ac().last_hash(fn)


def _chain_with(rec, prev):
    return _ac().chain_with(rec, prev)
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
        # 0.19.1 (TN-09)：读 prev 与 append 必须在同一把锁内 —— 见 _append_chained。
        rec = _append_chained(fn, rec)
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        # 0.28.0 (C-4): verify by PRESENCE among the last lines, not by "still
        # the last line" -- a concurrent append right after ours used to read
        # as a false loss. Windows text mode stores \r\n; compare normalized.
        with open(fn, "rb") as f:
            f.seek(max(0, os.path.getsize(fn) - 262144))
            tail = f.read().decode("utf-8", errors="replace").replace("\r\n", "\n")
        mine = line.rstrip("\n")
        ok = False
        for recent in [l for l in tail.split("\n") if l.strip()][-8:]:
            if recent == mine:
                try:
                    ok = isinstance(json.loads(recent), dict)
                except Exception:
                    ok = False
                break
        if ok:
            _touch_day_manifest(fn)
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
            # 0.18.0 (R-20, audit HP-46): the mirror is the OUT-OF-PROJECT
            # forensic copy -- it gets the same day anchor as the project copy,
            # so a truncated mirror no longer verifies silently either.
            _touch_day_manifest(fn)
    except Exception:
        pass
    return ok


def _host_audit_dir():
    if os.environ.get("ANTINEL_HOST_MIRROR") == "0":
        return None
    cd = os.environ.get("WORKBUDDY_CONFIG_DIR")
    base = os.path.expanduser(cd) if cd else os.path.join(os.path.expanduser("~"), ".workbuddy")
    return os.path.join(base, "antinel-audit")


def notice_state_path():
    """气泡降噪状态文件的位置 —— **唯一口径**。

    ★★ 0.35.3 修（创始人 2026-10-07 实测「右下角冒泡又出现了」）：
      原来这里写的是 `os.getcwd()/.psl/notify_state.json`。
      **`cwd` 随宿主而变**：钩子由哪个工具、在哪个目录拉起，就落在哪个目录。
      实测本机同一时刻散落着**4 份** `notify_state.json`：
        `D:\\psl\\poc\\.psl\\`（09-18）、`…\\antinel-security\\.psl\\`（10-03）、
        `…\\_evade_work\\.psl\\`（09-10）、`…\\_p9_wheeltest\\repo\\.psl\\`（10-03）
      ⇒ 同一个告警在另一个 cwd 下**又会被当成没通知过**，于是重新弹。
      降噪被摊薄成 N 份，而用户只看到一条没完没了的气泡。
      ★ 这与本仓已修过的 `heartbeat_age(包根 vs 审计目录)` 是**同一类错**：
        **同一个状态按"当前目录"存，必然分裂**。
      ⇒ 改存**个人中枢**（`~/.antinel`）—— 一台机器一份，全局唯一。
        `ANTINEL_HUB_DIR` 可覆盖（测试隔离用）。
    """
    hub = os.environ.get("ANTINEL_HUB_DIR")
    base = os.path.expanduser(hub) if hub else os.path.join(
        os.path.expanduser("~"), ".antinel")
    return os.path.join(base, "notify_state.json")
    # ★ 0.40.0：**唯一真源**是 `host_shield.notify_ledger_path()`（同一份文件，
    #   同一口径）。这里保留本地算法是为了在 host_shield 不可导入时仍能工作；
    #   两者**必须算出同一个路径** —— 由 `ci/inbox_guards_0400.py` 的 S23 钉死。


def _hs_module():
    """取 `host_shield` 模块（带"把包根塞进 sys.path"的兜底）。拿不到 ⇒ None。

    ★ 归口：本文件里所有对 host_shield 的 import 都走这里（**消灭副本**）——
      过去 `notify_owner` 自己内联了一份同样的兜底 import。
    """
    try:
        import host_shield as _hs
        return _hs
    except Exception:                                            # noqa: BLE001
        pass
    try:
        parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if parent not in sys.path:
            sys.path.insert(0, parent)
        import host_shield as _hs
        return _hs
    except Exception:                                            # noqa: BLE001
        return None


def notice_gate(rule_id, snippet):
    """UX: identical alert (rule + snippet) notifies once per day; repeats are
    silently logged. State lives in the **个人中枢**（一台机器一份，见
    `notice_state_path`）—— 原来按 cwd 存，会分裂成多份，降噪等于失效。

    ★★ 0.40.0：写入改走 **host_shield.ledger_rmw**（通知账的**唯一写入口**，
    带文件锁）。两个理由：
      ① 本条与气泡节流（`shown|*` / `sent|*`）**共用同一份文件** —— 各自写一份
         读-改-写会互相覆盖（并发钩子）；
      ② 旧实现里的"每日清理"是 `{k: v for k, v in st.items() if v == today}`，
         它会**连气泡节流的数值型键一起删掉**（时间戳 ≠ 日期字符串）——
         现在只在 `ledger_rmw` 的 mutator 里清"值是日期"的旧键。

    ★★★ 0.47.0：**在此之上叠一层「单条规则滚动窗口提醒预算」**
    （方案 v3.0 §5 步一，根治第三处告警疲劳）。
      数据（方案 §5）：提醒与拦截 **16,797 : 2,403**（约七比一），单条规则独占
      提醒的 **73.5%（12,350 / 16,797）** ⇒ 疲劳是**结构性**的，治理对象是**配额**。
      ⇒ 去重（同一片段一天一次）**之上**再给**单条规则**一个滚动窗口配额：
         超预算的后续提醒**不逐条出声**，但**条数照记**（`total`），
         窗口结束时**补记一条汇总**；原始条数**绝不丢弃**。
      ★ 判定**一字未动**：预算只决定"出不出声"，不决定"拦不拦"。
      ★ 账本仍走 `ledger_rmw`（交接件 §5.2 维一：不许另写第二份锁）。
      ★ 记账失败 ⇒ 返回 False（按"没抑制过"处理）—— 保护失效时**更吵**，不更静。
    """
    _hs = _hs_module()
    if _hs is None:
        return False                        # 拿不到记账模块 ⇒ 按"没抑制过"（宁可多提示）
    try:
        res = _hs.notice_budget_gate(rule_id, snippet)
    except Exception:                                            # noqa: BLE001
        return False
    if not res:
        return False                        # 账本写不进去 ⇒ 同上，宁可多提示
    # ★ 合并与补记**必须留痕**（交接件 §2.1 ① 关键纪律）：不许只有 stderr。
    _notice_budget_trace(res)
    return not res["speak"]


def _notice_budget_trace(res):
    """预算的两个动作**写链 ＋ 出声**（★ 唯一实现；链与界面各一份，互为对照）。

    ★★ 为什么必须写链：只往 `stderr` 打一行的合并，**关掉终端就消失了** ——
      那与"静默丢弃"在证据层面没有区别（链是本项目唯一可验真的地方）。
    ★ 为什么不弹气泡：预算是"少打扰"的机制，**它自己不该再敲门** ——
      只走 stderr（宿主可见）与链（可回看），不进气泡通道。
    """
    rid = str(res.get("rule_id") or "?")
    try:
        if res.get("closed"):
            c = res["closed"]
            log_event({"ts": datetime.now().isoformat(timespec="seconds"),
                       "type": "notice_budget_window_closed", "tool": "-",
                       "session": "-", "host": "-", "decision": "allow",
                       "severity": "info", "action": "alert",
                       "rule_id": rid,
                       "total": int(c.get("total") or 0),
                       "used": int(c.get("used") or 0),
                       "dup": int(c.get("dup") or 0),
                       "merged": int(c.get("merged") or 0),
                       "window_seconds": int(c.get("window_seconds") or 0),
                       "reason": "窗口结束补记：规则 %s 本窗口共 %d 条提醒，出声 %d 条、"
                                 "重复 %d 条、合并 %d 条（原始条数不丢）"
                                 % (rid, int(c.get("total") or 0),
                                    int(c.get("used") or 0), int(c.get("dup") or 0),
                                    int(c.get("merged") or 0))},
                      mirror=False)
            try:
                sys.stderr.write(
                    "[Antinel·提醒合并] 规则 %s：最近 %d 秒内共 %d 条同类提醒，"
                    "出声 %d 条、合并 %d 条（原始条数已全部留痕，未丢弃）。\n"
                    % (rid, int(c.get("window_seconds") or 0), int(c.get("total") or 0),
                       int(c.get("used") or 0), int(c.get("merged") or 0)))
            except Exception:                                        # noqa: BLE001
                pass
        if res.get("first_over"):
            log_event({"ts": datetime.now().isoformat(timespec="seconds"),
                       "type": "notice_budget_merged", "tool": "-",
                       "session": "-", "host": "-", "decision": "allow",
                       "severity": "info", "action": "alert",
                       "rule_id": rid,
                       "total": int(res.get("total") or 0),
                       "used": int(res.get("used") or 0),
                       "merged": int(res.get("merged") or 0),
                       "quota": int(res.get("quota") or 0),
                       "window_seconds": int(res.get("window_seconds") or 0),
                       "reason": "规则 %s 本窗口提醒已达上限 %d 条，后续不再逐条出声，"
                                 "改为合并；窗口结束时给一次汇总（原始条数不丢）"
                                 % (rid, int(res.get("quota") or 0))},
                      mirror=False)
            try:
                sys.stderr.write(
                    "[Antinel·提醒合并] 规则 %s：本窗口已提醒 %d 条（上限 %d），"
                    "后续同类提醒合并，%d 秒后给一次汇总（原始条数照记）。\n"
                    % (rid, int(res.get("used") or 0), int(res.get("quota") or 0),
                       int(res.get("window_seconds") or 0)))
            except Exception:                                        # noqa: BLE001
                pass
    except Exception:                                                # noqa: BLE001
        pass




# 0.33.1：走"双通道 stdout"的宿主名单。
# 原实现是硬编码 `("claude-code", "generic")` —— 一张写死在代码里的名单，任何
# 新识别出来的宿主都会落进 else 分支，于是 **deny 的第三条通道（hookSpecificOutput）
# 被静默丢掉**。归因修好后 workbuddy 第一次被正确识别，立刻踩中：真机上拦截只剩
# exit 2 + stderr 两条通道。
# 判据：多给一个 key 最坏是被宿主忽略；少给一条通道则是拦截失效。二者不对称，
# 所以未知宿主默认给，只对**已证实严格校验 schema** 的宿主（zcode）保持静默。
DUAL_STDOUT_HOSTS = ("claude-code", "generic", "workbuddy", "codebuddy")
# workbuddy 进名单的依据（实测，非推理）：WorkBuddy 会读钩子的 stdout JSON ——
# session_start_banner.py 的 additionalContext 在真机上确实送达。


def _dual_stdout_hosts():
    """策略可覆盖（global_settings.deny_stdout_hosts），不覆盖时用默认名单。"""
    try:
        cfg = ((_POLICY or {}).get("settings") or {}).get("deny_stdout_hosts")
        if isinstance(cfg, list) and cfg:
            return tuple(str(x) for x in cfg)
    except Exception:
        pass
    return DUAL_STDOUT_HOSTS


def _deny_payload(reason, host_tag, deny_mode):
    """0.30.0 (E-3): build the stdout payload for a deny, per host and policy.
    Returns None when this host must stay stdout-quiet (ZCode: strict schema,
    unknown keys invalidate the result) or the policy forced quiet mode.
    deny_mode (policy global_settings.deny_stdout): dual (default) = documented
    contract + legacy keys together; legacy = legacy key only; quiet = no stdout."""
    if host_tag not in _dual_stdout_hosts():
        return None
    if deny_mode == "quiet":
        return None
    payload = {"decision": "block", "reason": reason}          # legacy shape (A-01)
    if deny_mode == "dual":
        payload["hookSpecificOutput"] = {                      # documented contract
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason}
    return payload


def _timing_emit(timing):
    """0.32.2 (B1): 分段耗时（仅在 ANTINEL_TIMING=1 时输出到 stderr）。
    分段：imports（模块导入）/ rules（规则+策略加载）/ match（命中判定）/
    audit（审计链写+读回+日锚）/ other（其余：stdin 读、解析、通知等）。"""
    if os.environ.get("ANTINEL_TIMING") != "1" or not timing:
        return
    try:
        sys.stderr.write("ANTINEL_TIMING total=%d imports=%d rules=%d match=%d audit=%d other=%d\n"
                         % (timing.get("total", 0), timing.get("imports", 0),
                            timing.get("rules", 0), timing.get("match", 0),
                            timing.get("audit", 0), timing.get("other", 0)))
    except Exception:
        pass


def emit_block(rule_id, reason, host_tag="generic", deny_mode="dual", timing=None):
    """0.30.0 (E-3): deny on THREE additive channels at once -- documented JSON
    contract (hookSpecificOutput.permissionDecision="deny"), legacy stdout JSON
    ({"decision":"block"}), and exit 2 + stderr. A host that reads any ONE of
    them still denies, so the silent-degradation risk (a host dropping exit-2
    support) is closed on the signaling side and detected on the enforcement
    side (post_tool_use enforcement_gap). ZCode keeps the stdout-quiet channel
    (strict schema) and stays on exit 2 + stderr until probed otherwise."""
    _timing_emit(timing)
    payload = _deny_payload(reason, host_tag, deny_mode)
    if payload:
        try:
            print(json.dumps(payload, ensure_ascii=False))
        except Exception:
            pass
    try:
        sys.stderr.write(reason + "\n")
    except Exception:
        pass
    sys.exit(2)


# ------------------------------------------------- G-06: multi-hit collection --
# ------------------------------------- 0.29.0 (G-8): cloud-sync directories ----
# 威胁：把文件写进云盘同步目录，**同步客户端会替你把文件传上云** —— 这一步
# 不经钩子、不经命令行、不需要任何网络命令，常规出网检测（NET-01/02）看不见。
#
# ★ 为什么必须有这条规则，而不是靠 DST-02：DST-02 拦的是"写项目外"。用户把
#   `whitelist.paths` 一开（放行某个前缀），DST-02 就被释放了，写进云盘目录也
#   照样放行、且只有一条笼统的 allow 记录。DST-11 把"写进云盘"这件事**单独命名**，
#   于是无论路径是否在白名单里，这个动作都有名字、有理由。
#
# ★ 为什么必须带"项目外"这个条件：把项目放在 OneDrive 是极常见的配置。
#   只看目录名会把**全部正常写入**都判成外传 —— 那正是铁律
#   「一个会误报的检查器，用两次就没人信了」。所以判据是
#   **在同步目录内 且 在项目根之外**。
_SYNC_DIR_MARKERS = (
    (r"[\\/]OneDrive([\\/]|$)", "OneDrive"),
    # ★ 必须 `\s+-\s+`（带空格）：实测 `OneDrive-ish` 被 `\s*-\s*` 误判成
    #   "OneDrive - 组织" 目录。真实目录名是 `OneDrive - Contoso`（两侧有空格）。
    (r"[\\/]OneDrive\s+-\s+[^\\/]+([\\/]|$)", "OneDrive(工作/学校)"),
    (r"[\\/]Dropbox([\\/]|$)", "Dropbox"),
    (r"[\\/]Dropbox\s*\([^)]*\)([\\/]|$)", "Dropbox"),
    (r"[\\/]Google\s*Drive([\\/]|$)", "Google Drive"),
    (r"[\\/]GoogleDrive([\\/]|$)", "Google Drive"),
    (r"[\\/]My\s*Drive([\\/]|$)", "Google Drive"),
    (r"[\\/]iCloud\s*Drive([\\/]|$)", "iCloud Drive"),
    (r"[\\/]iCloudDrive([\\/]|$)", "iCloud Drive"),
    (r"[\\/]BaiduNetdisk([\\/]|$)", "百度网盘"),
    (r"[\\/]BaiduYunGuanjia([\\/]|$)", "百度网盘"),
    (r"[\\/]百度网盘([\\/]|$)", "百度网盘"),
    (r"[\\/]Nutstore([\\/]|$)", "坚果云"),
    (r"[\\/]坚果云([\\/]|$)", "坚果云"),
    (r"[\\/]Weiyun([\\/]|$)", "腾讯微云"),
    (r"[\\/]微云([\\/]|$)", "腾讯微云"),
    (r"[\\/]AliyunDrive([\\/]|$)", "阿里云盘"),
    (r"[\\/]aDrive([\\/]|$)", "阿里云盘"),
    (r"[\\/]阿里云盘([\\/]|$)", "阿里云盘"),
    (r"[\\/]天翼云盘([\\/]|$)", "天翼云盘"),
    (r"[\\/]CloudDisk([\\/]|$)", "天翼云盘"),
    (r"[\\/]亿方云([\\/]|$)", "亿方云"),
    (r"[\\/]和彩云([\\/]|$)", "和彩云"),
    (r"[\\/]115网盘([\\/]|$)", "115网盘"),
    (r"[\\/]MEGAsync([\\/]|$)", "MEGA"),
    (r"[\\/]pCloudDrive([\\/]|$)", "pCloud"),
    (r"[\\/]Box\s*Sync([\\/]|$)", "Box"),
    (r"[\\/]Syncthing([\\/]|$)", "Syncthing"),
    (r"[\\/]Nextcloud([\\/]|$)", "Nextcloud"),
    (r"[\\/]ownCloud([\\/]|$)", "ownCloud"),
    (r"[\\/]Seafile([\\/]|$)", "Seafile"),
    (r"[\\/]Resilio\s*Sync([\\/]|$)", "Resilio Sync"),
)
_SYNC_DIR_RE = None


def cloud_sync_dir_of(path):
    """命中的云盘同步目录名（如 'OneDrive'）；未命中返回 None。

    只做**字符串匹配**，不碰文件系统 —— 目录可能还没建（同步客户端会自己建），
    也可能因为权限读不到；而"Agent 打算往那儿写"这件事在命令文本里就已经成立。
    """
    global _SYNC_DIR_RE
    if not path:
        return None
    if _SYNC_DIR_RE is None:
        _SYNC_DIR_RE = [(re.compile(p, re.I), lbl) for p, lbl in _SYNC_DIR_MARKERS]
    s = str(path)
    for rx, lbl in _SYNC_DIR_RE:
        if rx.search(s):
            return lbl
    return None


def _basic_hit(rule, command, file_path, content, url, bash_extra, file_targets,
               rtype, detection):
    """0.29.0 (E-1)：command / file / content 三通道命中判定 —— **本仓唯一实现**。

    ★ 为什么必须抽出来：放行留痕（sec_wl_log）与主命中判定问的是同一个问题
    ——"这条规则本来会不会命中"。E-1 之前两处各写一遍，留痕只查 file_patterns、
    主判定查三通道 ⇒ 不同源 ⇒ SEC-09/10（靠 command_patterns 命中）与
    SEC-01（靠 content_patterns 命中）被路径白名单放行却**零留痕**，静默后门没堵死。
    **重复实现必然漂移**，故抽成唯一实现，两边共用。
    """
    r = _first_hit(_patterns(rule, "command_patterns"),
                   command_variants(command) + [url])
    if r:
        return (r[1], "command")
    r = _first_hit(_patterns(rule, "file_patterns"), [file_path] + bash_extra)
    if r:
        return (r[1], "path")
    if detection is None:
        pats = _patterns(rule, "content_patterns")
        if rtype == "file_content":
            # 0.31.0 (F2): a file_content rule carrying file_patterns only
            # inspects files whose path matches them (MCP-02/03/04 target MCP
            # config files; without this guard every text file on disk would be
            # content-scanned for their patterns).
            _fp_pats = _patterns(rule, "file_patterns")
            if _fp_pats and not (file_path and _first_hit(_fp_pats, [file_path])):
                return None
            target = rule.get("target")
            # 0.31.0 (F1): target semantics -- "instruction_files" matches SKILL.md
            # plus the instruction set; "all_text_files" stays a superset of
            # everything (CTX-03 keeps covering instruction files).
            compound = bool(rule.get("compound_nonprimary"))
            sf = int(rule.get("specific_from") or 0)
            for spec, text in file_targets:
                spec_ok = (target is None or target == spec or target == "all_text_files"
                           or (target == "instruction_files"
                               and spec in ("SKILL.md", "instruction_file")))
                if not spec_ok:
                    continue
                # 0.31.0 (F1): compound criterion for NON-SKILL.md instruction
                # files -- a lone GENERIC pattern ("ignore previous instructions"
                # quoted in a doc) is the classic false positive; require 2
                # distinct generic hits OR 1 specific hit (exfiltration /
                # do-not-tell / print-system-prompt). SKILL.md keeps the old
                # single-hit behavior. Falling below the threshold is NOT a
                # release: nothing is written to released[].
                if compound and spec == "instruction_file":
                    hit_idx = [k for k, p in enumerate(pats)
                               if _first_hit([p], [text])]
                    spec_hits = [k for k in hit_idx if k >= sf]
                    gen_hits = [k for k in hit_idx if k < sf]
                    if spec_hits:
                        r = _first_hit([pats[spec_hits[0]]], [text])
                        if r:
                            return (r[1], "file_content",
                                    {"spec": spec, "spc": len(spec_hits), "gen": len(gen_hits)})
                    if len(gen_hits) >= 2:
                        r = _first_hit([pats[gen_hits[0]]], [text])
                        if r:
                            return (r[1], "file_content",
                                    {"spec": spec, "spc": 0, "gen": len(gen_hits)})
                    continue
                r = _first_hit(pats, [text])
                if r:
                    return (r[1], "file_content", {"spec": spec})
        else:
            r = _first_hit(pats, [content, url] + bash_extra)
            if r:
                return (r[1], "content")
    return None


def collect_hits(rules, tool_name, texts, project_root, file_targets, policy=None,
                 workspace_roots=(), ws_allow_log=None, excluded_log=None,
                 path_wl_log=None, bash_path_log=None, host_cfg_log=None,
                 sync_wl_log=None, sec_wl_log=None, vct_log=None):
    """Run every enabled, applicable rule against the event; return ALL hits.

    Match families (all fields read from the rule top level, G-12):
      command_patterns  -> command, url
      file_patterns     -> file_path, plus command for Bash (cat .env, cat ~/.ssh/id_rsa)
      content_patterns  -> tool_call rules: content, command, url
                           file_content rules (CTX-02/04): text of target files
      check             -> path_outside_project_root (DST-02) | domain_whitelist (NET-03)
                           | path_in_cloud_sync_dir (DST-11, 0.29.0 G-8)
      detection         -> character_code_scan (CTX-03): command, path, content, file text
      type metadata_check (CTX-05): SKILL.md frontmatter name vs directory name
    Policy (F-06, spec C-05): whitelist.paths skips SECRETS rules for matching paths
    and, since 0.16.0, also releases DST-02 for matching paths (a legitimate write
    to the platform's own agent directory must be reachable without editing the
    policy first) -- but a policy-released DST-02 is recorded via path_wl_log, so
    the allow is traceable in report.py, never silent. Since 0.19.2 DST-02 also
    releases Antinel's own host-level config files, for the same reason and under
    the same obligation: recorded via host_cfg_log. See is_host_config_path().
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
    # ★ 0.46.0：删除许可（VCT）**按命令缓存** —— 单次版本查询约 404ms，同一条命令
    #   可能被多条删除类规则各问一次；缓存后每条命令最多查一次（方案 §3.6 的性能约束）。
    _vct_cache = {}

    for rule in rules:
        if (_disabled(rule) or not _platform_applies(rule)
                or not _applies(rule, tool_name)):
            continue
        rtype = rule.get("type") or "tool_call"
        detection = rule.get("detection") or ("character_code_scan" if rtype == "invisible_unicode" else None)
        if path_wl and rule.get("category") == "secrets" and rule.get("file_patterns"):
            # 0.29.0 (D-2)：**路径白名单只开"靠路径判断"的那扇门**。
            # 旧写法是 `category == "secrets"` 一刀切 ⇒ 读剪贴板(SEC-07)、截屏(SEC-08)、
            # 内容里的密钥字面量(SEC-06) 这三条**与路径毫无关系**的规则，只因同一次调用
            # 顺带带了一个白名单内的 file_path 就被一并放行 —— 实测 `pbpaste` 因此静默通过。
            # 通行证不该是万能卡：它只能开它真正对应的那扇门。
            # 0.29.0 (D-1)：放行**必须留痕**。此处是全仓最后一个静默放行通道 ——
            # 同文件另五处释放路径（DST-02 / DST-11 / exclude_patterns / workspace_roots /
            # host_cfg）各有专门事件类型并镜像到宿主级，只有这一处什么都不写，
            # 于是账本把它记成了"压根没命中"（rules_hit=[], severity="none"）。
            # ★ 不是新增规矩：ci/drift_audit.py 的 A5 早就判"放行成功 且 留痕"，长期红。
            if sec_wl_log is not None:
                # ★ 只记"这次调用**本来真的会命中**"的那条，不记"所有被跳过的规则"。
                # 若图省事把整批 secrets 规则都记上，账本会说"放行了 7 条"，
                # 而实际只有 1 条命中 —— 那就是用一个假数字换另一个假数字，
                # 与本次要修的毛病（账本不诚实）是同一回事。
                # ★★ 0.29.0 (E-1)：判据必须与主判定**同源**（同一 `_basic_hit`）。
                # 旧写法只查 file_patterns ⇒ SEC-09/10（靠 command_patterns 命中）、
                # SEC-01（靠 content_patterns 命中）被放行却**零留痕** ⇒ 静默后门没堵死。
                # 这是「改了一半」第四次复发；根治办法是不重写判据，而是共用它。
                if _basic_hit(rule, command, file_path, content, url, bash_extra,
                              file_targets, rtype, detection):
                    sec_wl_log.append(rule.get("id", "?"))
            continue
        if cmd_wl and (rule.get("severity") or "warning").lower() != "critical":
            continue
        # ★★★ 0.46.0：**删除许可（VCT）** —— 删除类**先过两票裁决**（方案 §3.5 第四步），
        #   兜底名单**降级**为「两票都取不到信号」时的最后退路（§3.7）。
        #   ★ 为什么必须放在 `_excluded` **之前**：两票都同意时，**即使目标不在兜底名单里**
        #     也要放行 —— 这正是「名单长度不再是攻击面的增长点」的兑现（名单不再是主判据）。
        #   ★★★ 为什么这里**不**再加 `not _command_segment_forced(rule, command)`：
        #     `_command_segment_forced` 是给**整条文本匹配**的兜底名单补「逐段判别」用的；
        #     而删除许可两票**本身就是逐目标的**（`deletion_permission` 遍历命令里的
        #     全部字面目标，任一目标受保护即否决）。再套一层 `_command_segment_forced`
        #     会把它**在最需要时关掉**：实测 `rm -rf _archive_dist`（被忽略＋可再生、
        #     但不在兜底名单里）该条件为真 ⇒ 两票整段被跳过 ⇒ 仍旧误拦。
        _vct = None
        _rec = None
        if _is_delete_rule(rule) and command:
            if command not in _vct_cache:
                _vct_cache[command] = deletion_permission(command, project_root)
            _vct = _vct_cache[command]
            if not _vct.get("is_delete"):
                # 步骤三：**不是删除类操作** ⇒ 到此结束，不进入删除许可（也不留痕，
                # 否则 `ls -la` 之类的日常命令都会被记一笔"删除许可取不到目标"）。
                _vct = None
            else:
                _rec = {"rule_id": rule.get("id", "?"), "exit": _vct.get("exit", ""),
                        "vote1": _vct.get("vote1", ""), "vote2": _vct.get("vote2", ""),
                        "why": _vct.get("why", ""), "targets": list(_vct.get("targets") or [])}
                if _vct["allow"] is True:
                    if vct_log is not None:
                        vct_log.append(dict(_rec, subkind="vct_allow", decision="allow"))
                    continue                   # 两票都同意 ⇒ 放行（不再看兜底名单）
                if _vct["allow"] is False and vct_log is not None:
                    # ★★ 明确否决 ⇒ 拦。这一笔**无论兜底名单是否命中**都必须留痕 ——
                    #   实测漏过：早先只在「兜底名单命中」那一支里记，于是
                    #   `rm -rf old-config`（名单没命中、真拦了）在账本上一条记录都没有。
                    vct_log.append(dict(_rec, subkind="vct_deny", decision="deny"))
        _excl_now = (_excluded(rule, [command, file_path, content, url])
                     and not _command_segment_forced(rule, command))
        if _excl_now:
            # A15: the rule matched but an exclude_patterns entry let it through
            # (`rm -rf .psl`, `rm -rf node_modules`). This is the only place that
            # knows an allow was a decision and not an absence, so it is recorded
            # here and mirrored to host level by main().
            if _vct is not None and _vct["allow"] is False:
                # 两票有**明确结论**且否决 ⇒ 兜底名单**不得**翻面（§3.7）
                # 不 continue ⇒ 落到正常判定 ⇒ 拦（留痕已在上面的 vct_deny 记过）
                pass
            else:
                # 非删除类，或删除类**取不到信号**（出口乙/丙）⇒ 兜底名单（最后退路）放行
                if excluded_log is not None and rule.get("severity") == "critical":
                    excluded_log.append(rule.get("id", "?"))
                if _vct is not None and vct_log is not None:
                    vct_log.append(dict(_rec, subkind="fallback_allow", decision="allow"))
                continue
        elif _vct is not None and _vct["allow"] is None and vct_log is not None:
            # ★★ 出口乙/丙 且兜底名单**也没接住** ⇒ 按现有默认拦，且**必须留痕**。
            #   设计 §3.5：「四个退出口的共同要求：不许静默」。这一支正是最容易被漏掉的
            #   一处 —— 早先只写了「兜底名单放行」那一支，于是 `rm -rf /c/Windows/System32`
            #   （出口丙）在账本上**一条记录都没有**，事后无从知道它走了哪条路。
            vct_log.append(dict(_rec, subkind="exit_" + (_vct.get("exit") or "?"),
                                decision="deny"))

        check = _field(rule, "check")
        # 1–3. command / file / content 三通道 —— 与放行留痕共用 `_basic_hit`（0.29.0 E-1）。
        #     此前此处是三通道的完整实现、留痕处是只查 file_patterns 的半份实现，
        #     两者漂移 ⇒ 放行不留痕。现在唯一实现在 `_basic_hit`，两边不可能再分叉。
        hit = _basic_hit(rule, command, file_path, content, url, bash_extra,
                         file_targets, rtype, detection)
        # 4. special checks
        agent_ap = any(file_path and file_path.replace("\\", "/").lower().rstrip("/").startswith(
            ap.rstrip("/")) for ap in policy.get("agent_paths", []))
        if hit is None and check == "path_outside_project_root":
            if check_outside_root(file_path, project_root, workspace_roots):
                if agent_ap and file_path:
                    # 0.21.0: agent_paths release — separate from whitelist.paths,
                    # dedicated audit event type
                    if path_wl_log is not None:
                        path_wl_log.append(file_path)
                elif path_wl and file_path:
                    # 0.16.0 (P1-7): whitelist.paths releases DST-02 for the
                    # listed prefixes (e.g. the platform's own agent directory).
                    # Deliberate: recorded, never silent.
                    if path_wl_log is not None:
                        path_wl_log.append(file_path)
                elif is_host_config_path(file_path):
                    # 0.19.2: Antinel's own host-level config. The tool that
                    # maintains the config must be able to reach it (see
                    # is_host_config_path). Released, and recorded -- never silent.
                    if host_cfg_log is not None:
                        host_cfg_log.append(file_path)
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
            bad = check_domains((command + " " + url).strip(), _field(rule, "whitelist_domains", []) or [])
            if bad:
                hit = (", ".join(bad), "domain_whitelist")
        # 4b. 0.29.0 (G-8, DST-11): 写进云盘同步目录（且项目外）。
        #     三个条件同时成立才算：①路径命中已知同步目录名 ②在项目根之外
        #     ③未被 whitelist.paths 显式放行（放行也留痕，不静默）。
        #     Bash 通道没有 file_path，用 _bash_absolute_paths 从命令文本里取显式绝对路径
        #     —— 与 DST-02 的 Bash 分支同一套提取，避免"Bash 走空"。
        if hit is None and check == "path_in_cloud_sync_dir":
            _cands = [file_path] if file_path else []
            if tool_name == "Bash" and command:
                _cands += [c for c in _bash_absolute_paths(command) if c not in _cands]
            for _c in _cands:
                _sync = cloud_sync_dir_of(_c)
                if not _sync:
                    continue
                if not check_outside_root(_c, project_root, workspace_roots):
                    continue        # 项目内（含项目本身放在云盘里）→ 不管
                if path_whitelisted(_c, project_root, policy.get("paths")):
                    if sync_wl_log is not None:
                        sync_wl_log.append(_c)
                    continue        # 用户显式放行 → 记录，不拦
                hit = (_sync, "path_in_cloud_sync_dir")
                break
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
        # 0.32.2 (C1): instruction_block_mode=specific-only —— 非 SKILL.md 指令文件上
        # "双泛化命中"的 block 降级为 alert（误报税减半），SPECIFIC 命中仍 block。
        # 降级必须留痕（downgraded_from），与 readonly 降级同一呈现纪律。
        _meta = hit[2] if len(hit) > 2 else {}
        if (action == "block" and rule.get("compound_nonprimary")
                and _meta.get("spec") == "instruction_file" and _meta.get("spc", 0) == 0
                and str((policy.get("settings") or {}).get(
                    "instruction_block_mode", "specific-only")).lower() == "specific-only"):
            entry["action"] = "alert"
            entry["severity"] = "warning"
            entry["downgraded_from"] = "block"
            entry["downgrade_reason"] = ("instruction_block_mode=specific-only "
                                         "(generic-only hit on a non-SKILL.md instruction file)")
        hits.append(entry)
    return hits


# ------------------------------------------------------------------- main -----
# ------------------------------------------------------------- file state (C1) --
# 0.22.0 (三问三答 v1.0, C1): evidence of what a write target looked like BEFORE
# a structured write tool runs. post_tool_use.py snapshots AFTER; the two records
# join on the shared content_digest (same recipe both sides, spec 2.8). Hashes
# and sizes only -- never content, never diffs.
WRITE_TOOLS = ("Write", "Edit")          # canonical names, post TOOL_ALIASES
FILE_STATE_MAX_BYTES = 1_000_000         # over this: record size, not a hash


def file_state_snapshot(path):
    """Deterministic outcomes:
      {"hash": "sha256:...", "size": n}  hashed (<= FILE_STATE_MAX_BYTES)
      {"hash": "absent"}                 target does not exist (a create)
      {"hash": "too_large", "size": n}   over cap -- size recorded, bytes not hashed
      {"hash": "unreadable"}             exists but could not be read (lock/ACL)
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


# ------------------------------------------------------------ BUDGET-01 ----
def _budget_hit(tool_name, session_id, policy):
    """0.24.0 (三问三答第三步: 成本即策略). 预算执法基于 post 钩子维护的
    token 累计事实（.psl/state/session_usage.json）；状态缺失即不执法
    （fail-open，绝不谎报）。三档 50/80/100，各会话各档只提醒一次；
    budget_block=true 且 100% 档时升级为拦截，且只拦写通道
    （Write/Edit/Bash）——只读放行，让 Agent 保留看清现状并收尾的能力。"""
    gs = policy.get("settings") or {}
    sb = gs.get("budget_tokens_per_session")
    db = gs.get("budget_tokens_per_day")
    if not sb and not db:
        return None
    try:
        st = json.load(open(os.path.join(os.getcwd(), ".psl", "state",
                                         "session_usage.json"), encoding="utf-8"))
    except Exception:
        return None
    day = datetime.now().strftime("%Y-%m-%d")
    s = st.get("sessions", {}).get(session_id or "?") or {}
    d = st.get("daily", {}).get(day) or {}
    best = None
    for name, used, budget in (("session", s, sb), ("day", d, db)):
        if not budget:
            continue
        used_n = (used.get("in", 0) if isinstance(used, dict) else 0) + \
                 (used.get("out", 0) if isinstance(used, dict) else 0)
        p = used_n / float(budget) * 100.0
        tier = 100 if p >= 100 else 80 if p >= 80 else 50 if p >= 50 else 0
        if tier and (best is None or tier > best[0]):
            best = (tier, name, used_n, int(budget), p)
    if best is None:
        return None
    tier, name, used_n, budget, p = best
    block_mode = str(gs.get("budget_block", "false")).lower() == "true"
    write_channel = tool_name in WRITE_TOOLS or tool_name == "Bash"
    snippet = "%s tokens %d/%d (%.0f%%)" % (name, used_n, budget, p)
    base_hit = {"rule_id": "BUDGET-01", "match_kind": "budget",
                "match_snippet": snippet, "snippet": snippet}
    if block_mode and tier >= 100 and write_channel:
        return dict(base_hit, severity="critical", action="block",
                    description="Session/day token budget exceeded (%s)" % snippet,
                    description_zh="会话/日 token 预算已超限（%s）" % snippet,
                    remediation="Raise it: antinel settings set budget_tokens_per_%s <N>, or wait for reset"
                                % name,
                    remediation_zh="调整预算：antinel settings set budget_tokens_per_%s <N>；"
                                   "或等待周期重置" % name)
    if not notice_gate("BUDGET-01", "%s|%s|%d" % (session_id, name, tier)):
        lang = _lang()
        if lang == "zh":
            msg = ("[BUDGET-01] 提醒: %s token 预算已用 %.0f%%（%d/%d）"
                   "——调整：antinel settings set budget_tokens_per_%s <N>\n"
                   % (name, p, used_n, budget, name))
        else:
            msg = ("[BUDGET-01] notice: %s token budget at %.0f%% (%d/%d)"
                   " -- adjust: antinel settings set budget_tokens_per_%s <N>\n"
                   % (name, p, used_n, budget, name))
        try:
            sys.stderr.write(msg)
        except Exception:
            pass
        return dict(base_hit, severity="warning", action="alert",
                    description="token budget at %.0f%%" % p,
                    description_zh="token 预算已用 %.0f%%" % p)
    return None                                        # 同档已提醒过：静默放行


# -------------------------------------------------- 0.26.0 实时通知主人 ----
# 0.28.3（B4i）：外部命令绝对路径——Windows 程序搜索顺序里应用目录先于 System32，
# 裸 "powershell" 可被 PATH/应用目录投毒劫持。
_PS_EXE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                       "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
# ★★ 0.35.3（创始人报障：窗口不停弹出又马上关掉）：钩子由宿主拉起，未必带控制台
#   ⇒ 起 PowerShell 若不显式 `CREATE_NO_WINDOW`，会为子进程新建控制台 = 黑窗一闪。
#   `-WindowStyle Hidden` 挡不住（控制台宿主窗口在建进程时就已创建）。
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def _slop_hit(tool_name, command, policy):
    """0.32.0 (F6): typosquatting / slopsquatting detection for install commands.

    依据 _budget_hit 的同构模式：返回带规则字段的 hit dict（走既有 hits 流 →
    审计/报告零改造），不命中返回 None。判定三档：① 名字（PEP503 归一化后在
    常见包参考集内 → 不命中（热门包，allow 不留痕）；② 不在参考集但与某个热门名
    SequenceMatcher ratio ≥ 0.85 或仅大小写/连字符差异 → SLOP-01 alert；
    ③ 完全生僻名 → 不命中。诚实边界（THREAT_MODEL Non-goals）：参考集是随包
    静态快照（rules/typosquat_top.json，带版本与日期），**日期之后新发布的包
    不在判据内**；"全新包恶意与否"本地无从判定，本规则只防"撞名牌"。
    alert 不拦：安装是合法动作，看见了再由人决定（同 MCP-01 分寸）。"""
    if tool_name != "Bash" or not command:
        return None
    m = re.search(r"(?i)\b(pip3?|uv\s+pip|npm|pnpm|yarn|bun)\s+(?:install|add|i)\s+(.{1,300})$", command)
    if not m:
        return None
    tool_p, spec = (m.group(1), m.group(2))
    registry = "npm" if re.search(r"(?i)npm|pnpm|yarn|bun", tool_p) else "pypi"
    try:
        with open(_locate("rules", "typosquat_top.json"), encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None                                    # 参考集缺失/坏 → 不执法（fail-open）
    names_raw = data.get(registry) or []
    if not names_raw:
        return None
    import difflib

    def _norm(n):
        return re.sub(r"[-_.]+", "-", n).lower()

    def _lev(a, b, cap=3):
        """编辑距离（≤cap 即可判定，超过早停）。stdlib DP，名单规模内成本可忽略。"""
        if abs(len(a) - len(b)) > cap:
            return cap + 1
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            cur = [i]
            for j, cb in enumerate(b, 1):
                cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                               prev[j - 1] + (ca != cb)))
            if min(cur) > cap:
                return cap + 1
            prev = cur
        return prev[-1]

    known = {_norm(n): n for n in names_raw}
    spec = re.sub(r"(?i)\b(==|>=|<=|~=?|@)\s*[\w.\-]+", "", spec)   # 去版本说明
    suspects = []
    for tok in spec.split():
        tok = tok.strip("\"'`,;")
        if not tok or tok.startswith("-") or "/" in tok or tok.startswith("."):
            continue                               # 选项/本地路径不算包名
        name = tok.split("@")[0].split("==")[0].strip()
        if not name or "@" in tok and not name:
            continue
        nn = _norm(name)
        if nn in known:
            continue                               # 热门包本身：allow 不留痕
        best = None
        for kn in known:
            d = _lev(nn, kn, cap=2)
            r = difflib.SequenceMatcher(None, nn, kn).ratio()
            if best is None or (d, -r) < (best[0], -best[1]):
                best = (d, r, known[kn])
        if best and (best[0] <= 2 or best[1] >= 0.85):
            suspects.append("%s (≈ %s, 距离 %d)" % (name, best[2], best[0]))
    if not suspects:
        return None
    return {"rule_id": "SLOP-01", "severity": "warning", "action": "alert",
            "match_kind": "command", "match_snippet": ", ".join(suspects)[:120],
            "description": "Install command references a package name suspiciously close to a "
                           "popular package (typosquatting/slopsquatting class; reference set "
                           "%s, dated %s -- later packages are not judged)"
                           % (data.get("version"), data.get("updated")),
            "remediation": "Check the package name against the official docs; install only after confirming; remove anything already installed and rotate credentials.",
            "description_zh": "安装命令中的包名与热门包高度相近（撞名/slopsquatting 类；参考集 "
                              "%s，日期 %s——其后新包不在判据内）"
                              % (data.get("version"), data.get("updated")),
            "remediation_zh": "核对包名拼写与官方文档；确认后再安装；已安装的立即移除并轮换凭据"}


# -------------------------------------------------------------- GOV-01 ----
# 2026-10-16（机制层方案 v1.0 §3）：套件治理（A1/A2）前移到**写入时刻**。
# 病灶：0518 当天「先登记、闸门才发现缺 P1-P5 ＋ 常驻超限」——检查在提交时刻，
# 登记在写入时刻，违规状态已经存在了半天。本函数把检查搬 到登记动作发生的那一刻。
# ★ 自包含（不 import ci/ 模块）：钩子在安装态运行，ci/ 不保证在旁。
#   下面两个常量与 ci/delivery_gate.py 双向同步 —— 改那边必须同步这边
#   （delivery_gate 侧注释已声明此约束）。
_GOV_P1P5 = re.compile(r"^\s*P([1-5])\s*[:：]\s*\S", re.M)   # = delivery_gate._P1P5_LINE
_GOV_RESIDENT = re.compile(
    r"\(\s*\"[^\"]*\"\s*,\s*\"ci/(?:inbox_guards_|guard_)[^\"]*\.py\"")
_GOV_RES_PATH = re.compile(r"\"ci/(?:inbox_guards_|guard_)[^\"]*\.py\"")
_GOV_CAP = 29                                                # = delivery_gate.RESIDENT_SUITE_CAP


def _gov_p1p5_ok(text):
    """前 60 行里 P1..P5 五行齐全？（口径 = delivery_gate.suites_missing_p1p5）"""
    head = "\n".join(text.split("\n")[:60])
    return set(_GOV_P1P5.findall(head)) >= set("12345")


def _gov_retirement_pending(project_root):
    """退休簿里 pending 记录数；读不到 ⇒ 0（无额度）。"""
    try:
        with open(os.path.join(project_root, "ci", "suite_retirement.json"),
                  encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return 0
    recs = data.get("records") if isinstance(data, dict) else data
    if not isinstance(recs, list):
        return 0
    return sum(1 for r in recs
               if isinstance(r, dict) and str(r.get("status", "")).lower() == "pending")


def _gov_resident_count(project_root):
    """磁盘 delivery_gate.py 里登记的常驻套件数；读不到 ⇒ None（判不了不放行也不拦）。"""
    try:
        with open(os.path.join(project_root, "ci", "delivery_gate.py"),
                  encoding="utf-8") as f:
            return len(_GOV_RESIDENT.findall(f.read()))
    except Exception:
        return None


def _gov_hit_payload(action, snippet, zh, en, rem_zh, rem_en):
    return {"rule_id": "GOV-01", "severity": "critical" if action == "block" else "warning",
            "action": action, "match_kind": "file", "match_snippet": snippet[:120],
            "description": en, "remediation": rem_en,
            "description_zh": zh, "remediation_zh": rem_zh}


def _suite_gov_hit(tool_name, file_path, tool_input, project_root):
    """GOV-01：A1/A2 写入时刻拦截（照 _budget_hit/_slop_hit 同构模式返回 hit dict）。

    口径（方案 v1.0 §3）：
      · Write 新常驻套件（ci/inbox_guards_*.py / ci/guard_*.py）：
          content 前 60 行缺 P1-P5 ⇒ block（A1，0518 事故原样）；
          磁盘常驻数 +1 > cap 且退休簿无 pending ⇒ alert（草稿出声不拦）。
      · Write 覆盖**既有**常驻套件：全文前 60 行缺 P1-P5 同样 block（删块也拦）。
        Edit 既有套件收窄放行（old/new 拼不出完整头部；存量由闸门兜底）。
      · Write/Edit ci/delivery_gate.py：登记条目差值 Δ>0 时——
          新登记文件磁盘不存在 ⇒ block（登记悬空）；
          存在但缺 P1-P5 ⇒ block（A1）；
          常驻数 + Δ > cap 且无 pending ⇒ block（A2）。
    fail-open（A-08）：内部任何异常 ⇒ None 放行——本函数绝不能成为第二个
    「钩子故障拦死合法操作」的单点。
    """
    try:
        tool_name = TOOL_ALIASES.get(tool_name, tool_name)
        if tool_name not in ("Write", "Edit") or not file_path or not project_root:
            return None
        norm = str(file_path).replace("\\", "/").lower()
        m_suite = re.search(r"(?:^|/)ci/(inbox_guards_[^/]+|guard_[^/]+)\.py$", norm)
        m_gate = re.search(r"(?:^|/)ci/delivery_gate\.py$", norm)
        if not m_suite and not m_gate:
            return None

        if m_suite:
            content = tool_input.get("content") or ""
            if tool_name != "Write" or not content:
                return None                      # Edit 既有套件：收窄放行（见 docstring）
            existed = os.path.isfile(file_path)
            if not _gov_p1p5_ok(content):
                return _gov_hit_payload(
                    "block", "ci/%s.py" % m_suite.group(1),
                    "新常驻套件缺 P1-P5 作答块（A1 前置门）——0518 事故原样",
                    "New resident suite lacks its P1-P5 block (gate A1)",
                    "在文件头 60 行内补 P1:…P5: 五行自答（P5 不满足 ⇒ 并入现有套件，不立新站）",
                    "Add P1:..P5: answer lines within the first 60 lines")
            if not existed:
                n_now = _gov_resident_count(project_root)
                if n_now is not None and n_now + 1 > _GOV_CAP \
                        and _gov_retirement_pending(project_root) < 1:
                    return _gov_hit_payload(
                        "alert", "ci/%s.py（第 %d 个常驻套件，上限 %d）"
                                 % (m_suite.group(1), n_now + 1, _GOV_CAP),
                        "常驻套件将超上限且无退休 pending 额度（A2）——登记前先并站或补退休记录",
                        "Resident suite count would exceed the cap with no pending retirement",
                        "并入现有套件（P5）或在 ci/suite_retirement.json 登记 pending 额度",
                        "Merge into an existing suite or register a pending retirement")
            return None

        # ---- delivery_gate.py：登记动作 ----
        new_text = tool_input.get("content") if tool_name == "Write" \
            else (tool_input.get("new_string") or "")
        old_text = ""
        if tool_name == "Edit":
            old_text = tool_input.get("old_string") or ""
        else:
            try:
                with open(file_path, encoding="utf-8") as f:
                    old_text = f.read()
            except Exception:
                old_text = ""
        if not new_text:
            return None
        delta = (len(_GOV_RESIDENT.findall(new_text))
                 - len(_GOV_RESIDENT.findall(old_text)))
        if delta <= 0:
            return None
        old_paths = set(_GOV_RES_PATH.findall(old_text))
        new_paths = [p for p in _GOV_RES_PATH.findall(new_text) if p not in old_paths]
        for p in new_paths[:4]:                  # 报前 4 个，够定位
            target = os.path.join(project_root, p.strip('"'))
            if not os.path.isfile(target):
                return _gov_hit_payload(
                    "block", p,
                    "登记悬空：SUITES 里登记的套件文件不在磁盘上",
                    "Registered suite file does not exist on disk",
                    "先写套件文件（含 P1-P5 块）再登记；或撤下这条登记",
                    "Create the suite file first, then register it")
            with open(target, encoding="utf-8") as f:
                head = f.read()
            if not _gov_p1p5_ok(head):
                return _gov_hit_payload(
                    "block", p,
                    "登记的套件缺 P1-P5 作答块（A1 前置门）——0518 事故原样",
                    "Registered suite lacks its P1-P5 block (gate A1)",
                    "给该文件头 60 行补 P1:…P5: 五行自答，或暂缓登记",
                    "Add P1:..P5: lines to the suite header, or hold the registration")
        n_now = _gov_resident_count(project_root)
        if n_now is not None and n_now + delta > _GOV_CAP \
                and _gov_retirement_pending(project_root) < (n_now + delta - _GOV_CAP):
            return _gov_hit_payload(
                "block", "SUITES 常驻 %d + %d > 上限 %d，退休簿额度不足"
                         % (n_now, delta, _GOV_CAP),
                "常驻套件登记超上限且 pending 额度不足（A2 硬红）",
                "Resident suite cap exceeded with insufficient pending quota",
                "并入现有套件（P5 正解）或先在 ci/suite_retirement.json 登记 pending",
                "Merge into an existing suite or register pending quota first")
        return None
    except Exception:
        return None                              # A-08 fail-open：治理检查绝不开杀戒


def notify_owner(title, body, kind="block|owner"):
    """拦截时通知主人（气泡）—— **委托给唯一发射口** `host_shield.notify_owner`。

    ★★★ 0.43.1（2026-10-10 实测复发，非推演）：本函数此前**自己 spawn 一份
      PowerShell**，图标**写死** `SystemIcons.Warning`；而 0.36.5 的图标修复
      （通知图标随姿态取，不再一律黄色警告）**只改到了 `host_shield._notify` 那一份**
      —— 判据 `ci/inbox_guards_0364.py::F4` 也只 `inspect.getsource(HS._notify)`。
      ⇒ 后果：**拦截气泡永远是黄色警告三角**，与"正常拦截 / 真出事"无关。
        这正是 0.36.5 定为「冒泡泡」根因②的那条（"它在撒谎，且撒谎是默认行为"），
        在**钩子这条副本**上原封不动地活着 —— 「修好一处、漏掉另一处」的标准形状。

      ⇒ 现在本函数不再有第二份实现：只发一条命令，交给唯一发射口。
        图标 / 去重 / 「窗口可见即不弹」三件事**全部只有一处**。

    ★ 行为变化（诚实登记）：去重口径由"每 rule+snippet 每天一次"（`notice_gate`，
      仍在 main 里管 stderr）之外，**再加**一道"同 kind 30 分钟内不重复弹泡"
      （唯一发射口的 `_NOTIFY_MIN_INTERVAL`）。⇒ 气泡只会更少，不会更多。
    ★ 判据 `ci/inbox_guards_0431.py` 守着"钩子里不许再有 ShowBalloonTip"。
    """
    try:
        _hs = _hs_module()                  # ★ 统一走 _hs_module()（消灭内联副本）
        if _hs is None:
            return                          # 拿不到模块 ⇒ 不弹（钩子绝不因此崩）
        _hs.notify_owner(title, body, kind=kind)
    except Exception:
        pass                                # 通知失败静默：留痕已在链上，气泡只是门铃


def main():
    t_main = time.perf_counter()                 # 0.32.2 (B1): 主体段起点
    try:  # utf-8 in/out determinism (host decoders expect utf-8)
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    # 0.33.0 (B3/D4): 常驻判定薄客户端。performance_mode=resident 且 judge
    # 存活时，把整个决策管线委托给常驻服务（预载规则+预编译正则），
    # 本进程只做信号转发（stdout/stderr/exit code）。三层 fail-open：
    # ① judge.json 不存在/pid 死 → 直跑 ② 连接失败/超时 → 直跑
    # ③ 服务返回错误 → 放行（A-08）。
    perf_mode = None
    try:
        _pp = os.path.join(os.getcwd(), ".psl", "policy.json")
        _pol0 = json.load(open(_pp, encoding="utf-8"))
        perf_mode = str((_pol0.get("global_settings") or {}).get(
            "performance_mode", "hook")).lower()
    except Exception:
        pass
    if perf_mode == "resident":
        try:
            import socket as _sock
            from pathlib import Path as _P
            _hub = _P(os.path.expanduser(os.environ.get(
                "ANTINEL_HUB_DIR") or "~/.antinel"))
            _jj = _hub / "judge.json"
            _jd = json.loads(_jj.read_text(encoding="utf-8"))
            os.kill(_jd.get("pid", 0), 0)               # 哨兵存活探测
            _ts = _jd.get("started", "")
            _age = time.time() - time.mktime(time.strptime(_ts[:19], "%Y-%m-%dT%H:%M:%S"))
            if _age > 60:
                raise ValueError("judge stale")
            _s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            _s.settimeout(2.0)
            _s.connect(("127.0.0.1", _jd["port"]))
            _req = json.dumps({"token": _jd["token"], "cwd": os.getcwd(),
                               "event_json": raw}, ensure_ascii=False)
            _s.sendall(_req.encode("utf-8") + b"\n")
            _resp_data = b""
            while b"\n" not in _resp_data:
                _chunk = _s.recv(65536)
                if not _chunk:
                    break
                _resp_data += _chunk
            _s.close()
            _resp = json.loads(_resp_data.decode("utf-8", errors="replace"))
            sys.stdout.write(_resp.get("stdout", ""))
            sys.stderr.write(_resp.get("stderr", ""))
            sys.exit(_resp.get("exit_code", 0))
        except Exception:
            pass                                    # ③ fail-open：直跑
    try:
        event = json.loads(raw)
    except Exception:
        # 0.29.0（A-2）：A-08 决定"解析失败就放行"（没有事件就没法判规则），这一条不变。
        # 变的是**留痕**：原先只打一行 INVALID_INPUT，链上一条记录都没有 ⇒ 一段坏 JSON
        # 就能让整道哨兵静默失效，而账本看起来完全正常——对一个卖"证据链"的产品，这是
        # 最不该出现的失败模式（定位句：「能拦的拦下，拦不住的记账」）。
        # 这里照抄 __main__ 里"钩子自己崩了"的现成写法（stderr HOOK_ERROR ＋ hook_error）。
        # hook_error 已登记在随包 AUDIT_SCHEMA.md，故契约文件不用动。
        try:
            sys.stderr.write("INVALID_INPUT\n")
            sys.stderr.write("HOOK_ERROR (allow)\n")
        except Exception:
            pass
        try:
            log_event({"ts": datetime.now().isoformat(timespec="seconds"),
                       "type": "hook_error", "tool": "-", "session": "-", "host": "-",
                       "decision": "allow", "severity": "critical", "action": "alert",
                       "reason": "stdin was not parseable JSON, so no rule could be applied; "
                                 "action was allowed by the host (fail-open, A-08) and this "
                                 "record is the only trace"})
        except Exception:
            pass
        sys.exit(0)                                     # A-08: allow on parse failure

    raw_tool = event.get("tool_name", "") or ""
    tool_name = TOOL_ALIASES.get(raw_tool, raw_tool)        # A9
    tool_input = event.get("tool_input") or {}
    # extract() coerces values to str, but a bare-string container used to
    # crash it (HOOK_ERROR fail-open); normalize the container itself too.
    if isinstance(tool_input, str):
        tool_input = {"command": tool_input}
    elif not isinstance(tool_input, dict):
        tool_input = {"command": str(tool_input)}
    session_id = event.get("session_id", "") or ""
    project_root = find_project_root()
    workspace_roots, ws_source, ws_rejected = load_workspace_roots()
    host_tag, host_evidence = detect_host_tag_full()

    cmd, fpath, content, url = extract(raw_tool, tool_input, host_tag)
    texts = {"command": cmd, "file_path": fpath, "content": content, "url": url}
    file_targets = file_text_targets(tool_name, fpath, content)

    policy = load_policy()
    global _POLICY            # 0.33.1: deny_stdout_hosts 需要读策略
    _POLICY = policy or {}
    ws_allow_log = []
    excluded_log = []
    path_wl_log = []
    bash_path_log = []
    host_cfg_log = []
    sync_wl_log = []
    sec_wl_log = []
    vct_log = []                                 # 0.46.0: 删除许可（VCT）裁决留痕
    effective_rules = apply_policy(load_rules(), policy)
    t_rules_done = time.perf_counter()           # 0.32.2 (B1)
    hits = collect_hits(effective_rules, tool_name, texts, project_root,
                        file_targets, policy, workspace_roots=workspace_roots,
                        ws_allow_log=ws_allow_log, excluded_log=excluded_log,
                        path_wl_log=path_wl_log, bash_path_log=bash_path_log,
                        host_cfg_log=host_cfg_log, sync_wl_log=sync_wl_log,
                        sec_wl_log=sec_wl_log, vct_log=vct_log)
    hits.sort(key=lambda h: SEV_RANK.get(h["severity"], 9))       # stable: keeps category order
    # 0.24.0 (BUDGET-01): 预算档位命中与规则命中同构（rules_hit 记录、report 可见）
    _bh = _budget_hit(tool_name, session_id, policy)
    if _bh:
        hits.append(_bh)
        hits.sort(key=lambda h: SEV_RANK.get(h["severity"], 9))
    # 0.32.0 (F6): slopsquatting——安装命令里的"撞名牌"包名（同构特判，S1-1..3）
    _sh = _slop_hit(tool_name, cmd, policy)
    if _sh:
        hits.append(_sh)
        hits.sort(key=lambda h: SEV_RANK.get(h["severity"], 9))
    # 2026-10-16 (GOV-01): 套件治理前移到写入时刻——A1/A2 违规在「登记动作」发生的
    # 那一刻就拦下，而不是等闸门跑时才发现已经登记进去了（0518 事故原样）。
    _gov = _suite_gov_hit(tool_name, fpath, tool_input, project_root)
    if _gov:
        hits.append(_gov)
        hits.sort(key=lambda h: SEV_RANK.get(h["severity"], 9))
    t_match_done = time.perf_counter()           # 0.32.2 (B1)
    # 0.26.0 (对抗分析 v1.0): net_mode=block —— 网络外传从"提醒"升级为"拦截"。
    # 仅在策略显式 block 时升级 NET 命中；默认 warn 保持不变（分寸：不静默加严）。
    if str((policy.get("settings") or {}).get("net_mode", "warn")).lower() == "block":
        for h in hits:
            if h.get("action") == "alert" and str(h.get("rule_id") or "").startswith("NET"):
                h["severity"] = "critical"
                h["action"] = "block"
    blocking = [h for h in hits if h["action"] == "block"]
    decision = "block" if blocking else ("alert" if hits else "allow")
    # 0.30.0 (E-3): which stdout deny contract is armed. dual (default) =
    # documented hookSpecificOutput + legacy decision key together; legacy =
    # the pre-0.30 shape; quiet = no stdout (exit 2 + stderr only). Escape
    # hatch for a host that chokes on the contract key.
    deny_mode = str((policy.get("settings") or {}).get("deny_stdout", "dual")).lower()
    if deny_mode not in ("dual", "legacy", "quiet"):
        deny_mode = "dual"
    # -------------------------------------------------- 0.30.0 (E-3): probe mode --
    # tools/enforce_probe.py runs THIS hook with a synthetic event that must be
    # blocked, then verifies the signal channels end to end. In probe mode the
    # hook is side-effect-free: no audit writes (the wrapper chains ONE truthful
    # enforcement_probe record), no owner notification -- and the policy
    # whitelist is bypassed, because the probe tests the ENGINE's deny path,
    # not the user's release configuration (release paths are covered by the
    # verification suite). Failure of any step here is fail-open on purpose:
    # the probe must never become a second way to break the host.
    if os.environ.get("ANTINEL_PROBE") == "1":
        # 0.33.1 (P4-2)：探针使用必须留痕。
        # ANTINEL_PROBE=1 让这次调用跳过主链写入 —— 这是已登记的边界：能设这个
        # env 的人，同样能改 .psl/，与攻击者同权，**防不住**。防不住就让它可检测：
        # 探针每跑一次往 sidecar 写一条 probe_used。主链语义不变（探针依然不污染
        # 主链），但"谁在什么时候用过探针"从此有据可查。
        try:
            _sd = os.path.join(os.getcwd(), ".psl", "audit", "sidecar")
            os.makedirs(_sd, exist_ok=True)
            _sp = os.path.join(_sd, datetime.now().strftime("%Y-%m-%d") + ".probe.jsonl")
            with open(_sp, "a", encoding="utf-8") as _f:
                _f.write(json.dumps(
                    {"ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
                     "type": "probe_used", "tool": raw_tool, "session": session_id,
                     "host": host_tag, "decision": "allow", "severity": "info",
                     "reason": "ANTINEL_PROBE=1: this call skipped main-chain audit; "
                               "this sidecar record is the only trace"},
                    ensure_ascii=False) + "\n")
        except Exception:
            pass
        _probe_policy = {k: v for k, v in policy.items() if k != "whitelist"}
        hits = collect_hits(effective_rules, tool_name, texts, project_root,
                            file_targets, _probe_policy,
                            workspace_roots=workspace_roots)
        hits.sort(key=lambda h: SEV_RANK.get(h["severity"], 9))
        blocking = [h for h in hits if h["action"] == "block"]
        decision = "block" if blocking else ("alert" if hits else "allow")
        try:
            sys.stderr.write("ANTINEL_PROBE decision=%s\n" % decision)
        except Exception:
            pass
        if decision == "block":
            top = blocking[0]
            lang = _lang()
            desc = _pick(top, "description", lang)
            rem = _pick(top, "remediation", lang)
            if lang == "zh":
                reason = ("Antinel 拦截 [%s] %s | 命中: %s | 放行/处理: %s | 自检探针（E-3）"
                          % (top["rule_id"], desc, top["match_snippet"], rem))
            else:
                reason = ("Antinel blocked [%s] %s | matched: %s | enforcement self-probe (E-3)"
                          % (top["rule_id"], top.get("description") or "policy violation",
                             top["match_snippet"]))
            emit_block(top["rule_id"], reason, host_tag, deny_mode)
        sys.exit(0)

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
    # 0.33.1 (A-1 / P4-1)：归因证据与可信度落链。
    # 旧记录没有这两个字段 ⇒ 读侧（report/digest）据此把 09-10..09-27 判为
    # "宿主标签不可信"日期段。链本身一字不改——不可变的链不因读法变化而改。
    base["host_evidence"] = host_evidence
    base["host_confidence"] = (host_evidence or {}).get("confidence", "none")
    if host_tag == "generic":
        # 自动取证：什么都没命中时，把可见线索写成一条独立事件。
        # 这样 TRAE / Qoder 国际版这类"需要真机证据"的宿主，只要被任何人跑一次，
        # 证据就自动落到链上 —— 不必再埋探针、不必等创始人重启。
        try:
            log_event({"ts": ts, "type": "host_tag_uncertain", "tool": raw_tool,
                       "session": session_id, "host": host_tag, "decision": "allow",
                       "severity": "info", "action": "allow",
                       "reason": "no host env key or directory marker matched; "
                                 "host attribution for this record is UNVERIFIED",
                       "host_evidence": host_evidence}, mirror=False)
        except Exception:
            pass
    # 0.29.0 (D-1)：**放行 ≠ 没命中**。旧账本把"命中了但被白名单放行"写成
    # {rules_hit: [], severity: "none"}，与"压根没匹配任何规则"**逐字段相同** ⇒
    # 事后复盘无从区分（判据④同型：「被放行」被伪装成「没命中」）。
    # 这里把被放行的规则 id 显式写进主记录，账本本身从此诚实 —— 不必拿两个本子对账。
    if sec_wl_log:
        base["released"] = sorted(set(sec_wl_log))
    # 0.22.0 (C1): before-state of a structured write target. Recorded even when
    # the call ends up blocked -- "a write was attempted against this state" is
    # itself evidence. Joined to the after-state via the shared content_digest.
    if tool_name in WRITE_TOOLS and fpath:
        base["file_state_before"] = file_state_snapshot(fpath)
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
    # ★★★ 0.46.0：**删除许可（VCT）** 的每一次裁决都进链（方案 §3.5：四个退出口
    #   共同要求「不许静默」，走到哪一个都要写明"为什么走到这里"）。
    #   `subkind` 分派（四种，恰好覆盖四条路）：
    #     `vct_allow`      —— 两票都同意 ⇒ 放行；
    #     `vct_deny`       —— 有明确结论且否决 ⇒ 拦；
    #     `fallback_allow` —— 取不到信号（出口乙/丙）⇒ 兜底名单接住并放行；
    #     `exit_乙`/`exit_丙` —— 取不到信号且兜底名单**也没接住** ⇒ 按默认拦（**留痕**）。
    #   `exit` 字段同时记退出口（甲/乙/丙/丁），`why` 记「为什么走到这里」。
    #   ★ 类型独立于 `exclude_patterns_allow`：读者要能分开「兜底名单放行」与
    #     「两票裁决放行」—— 混在一处就分不清是哪条路生效（本项目最忌的形状）。
    for _v in vct_log:
        log_event({"ts": ts, "type": "command_deletion_permission", "tool": raw_tool,
                   "session": session_id, "host": host_tag,
                   "rule_id": _v.get("rule_id", "?"),
                   "decision": _v.get("decision", "allow"),
                   "severity": "critical",
                   "action": "allow" if _v.get("decision") == "allow" else "block",
                   "subkind": _v.get("subkind", ""),
                   "exit": _v.get("exit", ""),
                   "vote1": _v.get("vote1", ""), "vote2": _v.get("vote2", ""),
                   "targets": _v.get("targets", []),
                   "reason": _v.get("why", ""),
                   "input": {"command": mask_secrets(cmd)[:300]}}, mirror=True)
    # 0.16.0 (P1-7): an allow caused by whitelist.paths on DST-02 is also recorded
    # -- a released block must leave a trace, exactly like exclude_patterns_allow.
    for wp in path_wl_log:
        log_event({"ts": ts, "type": "dst02_path_whitelisted", "tool": raw_tool,
                   "session": session_id, "host": host_tag, "rule_id": "DST-02",
                   "decision": "allow", "severity": "critical", "action": "allow",
                   "reason": "path outside the project root but inside policy whitelist.paths",
                   "input": {"file_path": mask_secrets(wp)}}, mirror=True)
    # 0.19.2: DST-02 released its own host-level config file. Recorded for exactly
    # the same reason path_wl_log is -- widening the trust boundary must be
    # visible after the fact, and this is the one path whose widening is itself
    # the boundary change. severity=warning so it shows up in report.py's
    # config-health line rather than blending into the allow stream.
    for hc in host_cfg_log:
        log_event({"ts": ts, "type": "dst02_host_config_self_maintenance", "tool": raw_tool,
                   "session": session_id, "host": host_tag, "rule_id": "DST-02",
                   "decision": "allow", "severity": "warning", "action": "alert",
                   "reason": "DST-02 released on Antinel's own host-level config file "
                             "(the tool that maintains the config must be able to reach it); "
                             "this allows the trust boundary itself to be edited",
                   "input": {"file_path": mask_secrets(hc)}}, mirror=True)
    # 0.29.0 (G-8, DST-11): a write into a cloud-sync directory released by
    # whitelist.paths. Same obligation as every other release in this file:
    # widening the trust boundary must be visible after the fact. Separate event
    # type (not dst02_path_whitelisted) so a report can tell "released a write
    # into a sync folder" apart from "released a write outside the project".
    # ★ 契约纪律：本事件类型已登记在随包 AUDIT_SCHEMA.md（没登记 ≠ 不存在）。
    for sc in sync_wl_log:
        log_event({"ts": ts, "type": "dst11_syncdir_released", "tool": raw_tool,
                   "session": session_id, "host": host_tag, "rule_id": "DST-11",
                   "decision": "allow", "severity": "critical", "action": "allow",
                   "reason": "write into a cloud-sync directory was released by "
                             "policy whitelist.paths -- the sync client will still "
                             "upload it; recorded so the release is never silent",
                   "input": {"file_path": mask_secrets(sc)}}, mirror=True)
    # 0.29.0 (D-1)：**补上全仓最后一个静默放行通道**。
    # whitelist.paths 放行了 secrets 规则（读 .env / SSH 私钥 / 云凭证 / 微信库 …），
    # 此前什么都不写 ⇒ 账本上它和"没命中"一模一样。现在单独命名（不并入
    # dst02_path_whitelisted），因为"放行一次读敏感文件"与"放行一次写项目外"
    # 是两件不同的事。severity 取自被放行规则的实际等级，不禁写死为 critical。
    # ★ 契约纪律：本事件类型已登记在随包 AUDIT_SCHEMA.md（没登记 ≠ 不存在）。
    # ★ 0.29.0 (E-1)：severity **取自被放行规则的实际等级**（不再写死 warning）。
    # 写死会让"放行了一次 critical 规则"在账本上降级成 warning ⇒ 事后复盘低估。
    # 用生效规则集反查（id 唯一），取不到时才回落到 warning —— 宁可回落，也不静默。
    _sev_by_id = {r.get("id"): (r.get("severity") or "warning")
                  for r in effective_rules if r.get("id")}
    for rid in sorted(set(sec_wl_log)):
        log_event({"ts": ts, "type": "sec_path_whitelisted", "tool": raw_tool,
                   "session": session_id, "host": host_tag, "rule_id": rid,
                   "decision": "allow", "severity": _sev_by_id.get(rid, "warning"),
                   "action": "allow",
                   "reason": "matched a secrets rule but released by policy "
                             "whitelist.paths; recorded so the release is never "
                             "silent and never looks like 'nothing matched'",
                   "input": {"file_path": mask_secrets(fpath),
                             "command": mask_secrets(cmd)[:200]}}, mirror=True)
    # 0.17.0 (P-A4): explicit out-of-root absolute paths seen on the Bash channel
    # -- alert-only evidence, never a block (guardrail boundary, not a sandbox).
    # 0.20.1: dedup — same path, same day → one stderr + one audit event.
    # The audit record is still written for EVERY occurrence (evidence integrity);
    # only the stderr reminder is deduplicated via notice_gate.
    seen_suspects = set()
    for cand in bash_path_log:
        if cand in seen_suspects:
            continue
        seen_suspects.add(cand)
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
                       "antinel_version": _ANTINEL_VERSION,
                       "host_version": (event.get("version") or None),
                       "deny_mode": deny_mode,
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
    audit_fail_n = 0
    if hits:
        for h in hits:                                  # one record per hit (report.py reads rules_hit)
            if not log_event(dict(base, rules_hit=[h["rule_id"]], severity=h["severity"], action=h["action"],
                                  decision="block" if h["action"] == "block" else "alert",
                                  match_kind=h["match_kind"], match_snippet=h["match_snippet"],
                                  **({"downgraded_from": h["downgraded_from"],
                                      "downgrade_reason": h["downgrade_reason"]}
                                     if h.get("downgraded_from") else {})),
                             mirror=(h["action"] == "block")):
                audit_fail_n += 1
        if not log_event({"ts": ts, "type": "pre_tool_use_summary", "tool": tool_name, "session": session_id,
                          "antinel_version": _ANTINEL_VERSION,
                          "host_version": (event.get("version") or None),
                          "total_hits": len(hits), "decision": decision,
                          "hits": [{"rule_id": h["rule_id"], "severity": h["severity"],
                                    "match_kind": h["match_kind"], "snippet": h["match_snippet"]} for h in hits]}):
            audit_fail_n += 1
    else:
        if not log_event(dict(base, rules_hit=[], severity="none", action="allow", decision="allow")):
            audit_fail_n += 1
    # 0.33.1 (P3-4): 钩子超时是"静默放行"的入口，必须留痕。
    # 宿主给钩子的超时是 10s（zcode）/ 15s（claude）；一旦跑超，宿主按超时处理，
    # 而超时=allow（A-08）。也就是说：**慢到超时，等于这张牌没打出去，而且没人知道**。
    # 实测（本机，5MB 输入）端到端 median 19,473ms —— 已越过两条超时线。
    # 所以：超过 SLOW_BUDGET_MS 就写一条 hook_slow，把"我太慢了"变成可查事实，
    # 而不是让用户以为"没报警就是没命中"。
    try:
        _elapsed_ms = int((time.perf_counter() - _T0) * 1000)
        if _elapsed_ms >= SLOW_BUDGET_MS:
            log_event({"ts": ts, "type": "hook_slow", "tool": raw_tool, "session": session_id,
                       "host": host_tag, "decision": "allow", "severity": "warning",
                       "action": "alert",
                       "reason": "hook took %d ms (>= budget %d ms); hosts kill the hook at "
                                 "10-15s and a timeout is treated as ALLOW, so this verdict "
                                 "may never have reached the host"
                                 % (_elapsed_ms, SLOW_BUDGET_MS),
                       "elapsed_ms": _elapsed_ms,
                       "input_sizes": {"command": len(cmd or ""), "content": len(content or ""),
                                       "file_path": len(fpath or ""), "url": len(url or "")}},
                      mirror=False)
    except Exception:
        pass
    t_audit_done = time.perf_counter()           # 0.32.2 (B1)
    timing = {"total": int((time.perf_counter() - _T0) * 1000),
              "imports": int((_T1 - _T0) * 1000),
              "rules": int((t_rules_done - t_main) * 1000),
              "match": int((t_match_done - t_rules_done) * 1000),
              "audit": int((t_audit_done - t_match_done) * 1000),
              "other": max(0, int((t_audit_done - t_main) * 1000)
                           - int((t_rules_done - t_main) * 1000)
                           - int((t_match_done - t_rules_done) * 1000)
                           - int((t_audit_done - t_match_done) * 1000))}

    # 0.18.0 (R-18, audit HP-11): the switch the v0.17 stderr text promised is
    # now wired. Default stays fail-open (a guardrail must not take the host
    # down over its own log dir); with the policy ON, a lost audit record turns
    # into an explicit block -- the call still happened, but the host is told
    # WHY the result was withheld evidence.
    if decision != "block" and audit_fail_n and policy.get("fail_closed_on_audit_loss"):
        lang = _lang()
        if lang == "zh":
            reason = ("Antinel 拦截 [AUDIT-LOSS] 审计记录写入失败且 fail_closed_on_audit_loss=true | "
                      "失败记录数: %d | 放行/处理: 修复 .psl/audit 可写性后重试；"
                      "确认接受裸奔可在 .psl/policy.json 将该键改为 false" % audit_fail_n)
        else:
            reason = ("Antinel blocked [AUDIT-LOSS] audit write failed with fail_closed_on_audit_loss=true | "
                      "failed records: %d | to allow: fix .psl/audit writability and retry, "
                      "or set the policy key to false" % audit_fail_n)
        emit_block("AUDIT-LOSS", reason, host_tag, deny_mode, timing=timing)

    if decision == "block":
        top = blocking[0]
        lang = _lang()
        desc = _pick(top, "description", lang)
        rem = _pick(top, "remediation", lang)
        # 0.26.0: 实时通知主人——对手采取行动的第一时间，主人要能知道并手工介入
        # ★★ 0.35.3（创始人 2026-10-06「**不停地有弹窗**」＋「尽可能少让人处理」）：
        #   拦截**本来就是 Antinel 干完的活** —— 同一条规则 + 同一段命中，
        #   **一天只敲一次门**；其余只留痕（Antinel 监理台账里翻得到）。
        #   否则一条常用规则反复拦 ⇒ 气泡刷屏 ⇒ 人开始无视气泡
        #   （"会误报的检查器用两次就没人信"）。
        if str((policy.get("settings") or {}).get("notify_owner", "true")).lower() != "false":
            if not notice_gate("block|" + str(top.get("rule_id") or "?"),
                               str(top.get("match_snippet") or "")):
                what = desc or top.get("description") or "危险操作"
                detail = str(top.get("match_snippet", ""))[:80]
                notify_owner("Antinel 已拦下危险操作",
                             "%s%s。已留痕，详情见 antinel report --session latest"
                             % (what, ("｜" + detail) if detail else ""),
                             kind="block|" + str(top.get("rule_id") or "?"))
        if lang == "zh":
            reason = "Antinel 拦截 [%s] %s | 命中: %s | 放行/处理: %s | 重试无效（策略拦截）" % (
                top["rule_id"], desc, top["match_snippet"], rem)
        else:
            reason = "Antinel blocked [%s] %s | matched: %s | to allow: %s (retry is futile)" % (
                top["rule_id"], top.get("description") or "policy violation",
                top["match_snippet"], rem)
        emit_block(top["rule_id"], reason, host_tag, deny_mode, timing=timing)

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
    _timing_emit(timing)
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
        # 0.18.0: even an exploding hook must leave a trace -- a silent exit was
        # exactly the N5 blindness. Best-effort: if logging itself is broken,
        # there is nothing more we can do (fail-open, A-08).
        try:
            log_event({"ts": datetime.now().isoformat(timespec="seconds"),
                       "type": "hook_error", "tool": "-", "session": "-", "host": "-",
                       "decision": "allow", "severity": "critical", "action": "alert",
                       "reason": "hook crashed after accepting the event; action was "
                                 "allowed by the host (fail-open) and this record is "
                                 "the only trace"})
        except Exception:
            pass
        sys.exit(0)                                     # A-08: fail open