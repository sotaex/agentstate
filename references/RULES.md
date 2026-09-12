# Antinel detection rules (generated from rules/default.json v0.18.1 - do not edit by hand)

Category order = match priority: secrets > destructive > network > injection > context > metadata.
Severity to action: critical = block, warning = alert (logged, allowed). All hits are collected; highest severity decides.

## SEC-01  Sensitive file read (.env)
- category: secrets | severity: critical | static + dynamic | tools: Read, Bash
- purpose: Prevents an agent reading .env files (live-blocked in ZCode on 09-10; the founding interception)
- description: Agent attempted to read a .env file which may contain API keys and secrets
- 说明: 读取 .env 文件可能泄露 API 密钥与机密配置
- 处理建议: 把 .env 移出 Agent 可读范围；确需变量时手动复制具体几行；测试夹具路径可在 policy.json 白名单登记
- file_patterns:
    - `\.env$`
    - `\.env\.`
    - `[/\\]\.env$`
    - `^\.env$`
- content_patterns:
    - `\.env\b`
- exclude_patterns: `\.env\.example`, `\.env\.template`, `\.env\.sample`
- remediation: Remove .env from agent-readable scope or add to deny list. Use environment variable injection instead.

## SEC-02  SSH key file read
- category: secrets | severity: critical | static + dynamic | tools: Read, Bash
- purpose: Prevents SSH private key / authorized_keys reads (the credential that outlives every session)
- description: Agent attempted to read SSH private key or authorized_keys file
- 说明: 读取 SSH 私钥或 authorized_keys
- 处理建议: SSH 密钥不要放进 Agent 工作范围；改用 ssh-agent 转发
- file_patterns:
    - `\.ssh[/\\]`
    - `id_rsa`
    - `id_ed25519`
    - `id_ecdsa`
    - `authorized_keys`
- remediation: Keep SSH keys outside agent working scope; use ssh-agent forwarding instead of key files.

## SEC-03  Cloud credential file read
- category: secrets | severity: critical | static + dynamic | tools: Read, Bash
- purpose: Prevents cloud credential file reads (aws/kube/gcloud -- the keys that move cloud billings)
- description: Agent attempted to read cloud provider credentials
- 说明: 读取云厂商凭证文件
- 处理建议: 改用云厂商 CLI 的短期令牌；确需操作时请手动执行
- file_patterns:
    - `\.aws[/\\]`
    - `\.kube[/\\]config`
    - `credentials\.json`
    - `\.netrc`
    - `application_default_credentials`
- remediation: Use short-lived tokens via the provider CLI instead of exposing credential files to the agent.

## SEC-04  Wallet/keystore file read
- category: secrets | severity: critical | static + dynamic | tools: Read, Bash
- purpose: Prevents wallet/keystore access (irreversible financial loss class)
- description: Agent attempted to read cryptocurrency wallet or keystore file
- 说明: 读取加密货币钱包或密钥库文件
- 处理建议: 钱包目录永远不要交给编码 Agent；必要时移入加密保管
- file_patterns:
    - `wallet`
    - `keystore`
    - `metamask`
    - `\.ethereum`
- exclude_patterns: `test_wallet`, `mock_wallet`
- remediation: Never let a coding agent touch wallet directories; move keystores to an encrypted vault.

## SEC-05  Browser data read
- category: secrets | severity: critical | static + dynamic | tools: Read, Bash
- purpose: Prevents browser profile reads (live login sessions, not just passwords)
- description: Agent attempted to read browser stored data (cookies, passwords, sessions)
- 说明: 读取浏览器数据（Cookie、密码、会话）
- 处理建议: 浏览器配置目录包含登录态，应完全禁止 Agent 访问
- file_patterns:
    - `Cookies`
    - `Login\s+Data`
    - `Local\s+Storage`
    - `Web\s+Data`
- remediation: Browser profiles contain live sessions; deny all agent access to profile directories.

## NET-01  Shell network request
- category: network | severity: warning | dynamic (hook only) | tools: Bash
- purpose: Surfaces shell egress to non-whitelisted domains (first-generation C2 / exfil channel)
- description: Agent made an external network request via shell command to a non-whitelisted domain
- 说明: 通过 Shell 向白名单外域名发起网络请求
- 处理建议: 核对目标域名是否预期；常用下载源可在 policy.json 的 whitelist.domains 登记
- command_patterns:
    - `\b(curl|wget|fetch)\b.*https?://`
    - `https?://(?!registry\.npmjs\.org|pypi\.org|github\.com)`
- exclude_patterns: `localhost`, `127\.0\.0\.1`, `registry\.npmjs\.org`, `pypi\.org`
- remediation: Pin downloads to whitelisted registries (npmjs/pypi/github) or review the destination.

## NET-02  Python network request
- category: network | severity: warning | dynamic (hook only) | tools: Bash
- purpose: Surfaces inline-code network calls (the same egress hidden inside python -c)
- description: Agent code contains Python network request calls
- 说明: 内联代码包含 Python 网络请求调用
- 处理建议: 核对请求目标地址后再放行
- command_patterns:
    - `urllib\.request`
    - `requests\.(get|post|put|delete)`
    - `httpx\.`
    - `socket\.create_connection`
- remediation: Review the endpoints used by inline Python network code before allowing egress.

## NET-03  Non-whitelisted domain connection
- category: network | severity: warning | dynamic (hook only) | tools: Bash
- purpose: Surfaces non-whitelisted domains named in commands (DNS-level comparison is v2)
- description: Agent command references a domain outside the whitelist (v1 compares command-line domains; DNS-level comparison is a v2 kernel-layer capability)
- 说明: 命令引用了白名单外的域名
- 处理建议: 确认域名无害后，写入 policy.json 的 whitelist.domains 即不再提醒
- check: domain_whitelist
- whitelist_domains: registry.npmjs.org, pypi.org, files.pythonhosted.org, github.com, localhost
- exclude_patterns: `127\.0\.0\.1`
- remediation: Add the domain to the whitelist only after verifying it is the intended destination.

## DST-01  File deletion
- category: destructive | severity: critical | dynamic (hook only) | tools: Bash
- purpose: Blocks deletion commands (rm/del/rd/Remove-Item and library calls -- measured 11 live blocks)
- description: Agent executed a file or directory deletion command
- 说明: 执行文件或目录删除命令
- 处理建议: 确认删除目标无误；构建产物类删除（如 node_modules）已在豁免清单
- command_patterns:
    - `\brm\b`
    - `\bdel\b`
    - `\brmdir\b`
    - `\bunlink\b`
    - `\bshutil\.rmtree\b`
    - `\bos\.remove\b`
    - `remove-item`
    - `(?:^|[;&|(]\s*|\s)rd(?:\s*[/][A-Za-z]|\s+[^=\s])`
    - `\bdd\s+if=[^\n]{0,80}\bof=/dev/`
    - `\bmkfs\b`
    - `\btruncate\s+-s\b`
    - `\bshred\s+-[a-z]*u?\b`
    - `\bmv\b[^\n]{0,120}\s/dev/null\b`
    - `(^|[;|&]\s*):\s*>\s*[^\s]`
    - `\brmSync\s*\(`
    - `\brm_rf\b`
    - `\bFileUtils\.rm\b`
    - `\bunlink\s+glob\b`
    - `array_map\(\s*["']unlink["']`
    - `\bosascript\b[^\n]{0,200}\bdelete\b`
    - `\bfind\b[^\n]{0,200}\s-delete\b`
- exclude_patterns: `rm -rf node_modules`, `rm -rf \.git`, `rm -rf __pycache__`, `rm -rf \.psl`, `remove-item node_modules`, `remove-item -recurse.*node_modules`, `\brm\s+-rf\s+(dist|build|target|venv|\.tox|\.mypy_cache|\.ruff_cache|\.pytest_cache|htmlcov|coverage|out|bin|obj)(\s|$|;)`, `\brm\s+-rf\s+\S*\.(egg-info|pyc)(\s|$|;)`, `\brm\s+-rf\s+\.nox\b`
- remediation: Confirm the deletion target; prefer moving to trash over rm -rf outside build artifacts.

## DST-02  Write outside project root
- category: destructive | severity: critical | dynamic (hook only) | tools: Write, Edit, Bash
- purpose: Blocks writes outside the project root (the workspace is the trust boundary)
- description: Agent attempted to write to a file outside the project root directory
- 说明: 试图写入项目根目录之外；或用 tar 解包越权覆盖系统文件
- 处理建议: 让 Agent 把文件写进项目内；确需写外部路径时请手动执行
- command_patterns:
    - `\btar\b[^\n]{0,120}-C\s+/(?:\s|$)`
    - `\btar\b[^\n]{0,120}\s-C\s+/(?:etc|usr|bin|sbin|var|lib|boot|srv|opt|home|root)(?:\s|$)`
- check: path_outside_project_root
- remediation: Keep agent writes inside the project; grant explicit exceptions per path if needed.

## DST-03  Shell configuration modification
- category: destructive | severity: critical | dynamic (hook only) | tools: Write, Edit, Bash
- purpose: Blocks shell-startup edits (persistence that re-executes on every terminal)
- description: Agent attempted to modify shell startup configuration (persistence mechanism)
- 说明: 修改 Shell 启动配置（.bashrc 等，属持久化机制）
- 处理建议: 启动脚本每次开终端都会执行，不要让 Agent 追加内容；确需修改请手动审查后进行
- command_patterns:
    - `>>\s*~[/\\]\.(bashrc|zshrc|profile)`
    - `echo.*>>.*\.(bashrc|zshrc|profile)`
- file_patterns:
    - `\.bashrc`
    - `\.zshrc`
    - `\.profile`
    - `\.bash_profile`
- remediation: Shell startup files execute on every terminal; never let an agent append to them unreviewed.

## DST-04  Persistence mechanism
- category: destructive | severity: critical | dynamic (hook only) | tools: Write, Edit, Bash
- purpose: Blocks persistence installs (cron/systemd/registry Run/schtasks -- survives the session)
- description: Agent attempted to establish persistence (cron job, systemd service, startup item, scheduled task, registry Run key)
- 说明: 建立持久化机制（计划任务/系统服务/启动项/注册表 Run 键）
- 处理建议: 持久化会在会话结束后反复执行，必须由你本人确认后手动操作
- command_patterns:
    - `crontab\s+-[el]`
    - `systemctl\s+enable`
    - `launchctl\s+load`
    - `\bschtasks\b`
    - `\breg\s+add\b`
    - `(?i)\bregedit\b`
    - `(?i)start menu.*startup`
    - `(?i)\bat\s+\d{1,2}:\d{2}\s+/\w+`
    - `\bpowershell\b[^\n]{0,80}\-(enc|encodedcommand)\b`
- file_patterns:
    - `crontab`
    - `systemd[/\\]system`
    - `LaunchAgents`
    - `rc\.local`
    - `\.config[/\\]autostart`
    - `currentversion[/\\]run`
    - `(?i)start menu.*startup`
- remediation: Persistence entries survive the session and re-execute code; require explicit human approval.

## DST-05  Privilege escalation
- category: destructive | severity: warning | dynamic (hook only) | tools: Bash
- purpose: Alerts on privilege escalation (sudo/chmod 777 -- sysadmin territory)
- description: Agent attempted to escalate privileges
- 说明: 尝试提权操作
- 处理建议: 涉及提权的步骤建议你本人执行，不给 Agent 提权
- command_patterns:
    - `^\s*sudo\b`
    - `^\s*su\b`
    - `chmod\s+777`
    - `chown\s+root`
- exclude_patterns: `sudo apt-get install`, `sudo pip install`
- remediation: Run privileged steps yourself instead of letting the agent hold elevated shells.

## CTX-01  Environment variable enumeration
- category: context | severity: warning | dynamic (hook only) | tools: Bash
- purpose: Alerts on environment enumeration (the precursor to secret exfiltration)
- description: Agent attempted to enumerate all environment variables (may expose API keys and secrets)
- 说明: 枚举全部环境变量（可能暴露密钥）
- 处理建议: 让 Agent 只打印它需要的具体变量名
- command_patterns:
    - `\benv\b(?!\s*=)`
    - `\bprintenv\b`
    - `os\.environ`
    - `process\.env`
- remediation: Print only the specific variables needed instead of dumping the whole environment.

## CTX-02  Prompt injection pattern in SKILL.md
- category: injection | severity: critical | static + dynamic | tools: Read, Write, Edit
- purpose: Blocks prompt injection in skill instructions (the skill-poisoning payload core)
- description: Potential prompt injection payload detected in skill instruction file
- 说明: 技能指令文件中发现提示注入载荷
- 处理建议: 移除该技能并核查来源；不要运行其中的指令
- content_patterns:
    - `ignore\s+(all\s+)?(previous|prior|above)\s+instructions`
    - `disregard\s+(all\s+)?(previous|prior|above)`
    - `(you\s+are\s+now|act\s+as\s+(a\s+)?different)`
    - `忽略(以上|之前|先前|上面)(的)?(所有)?(指令|指示|规则)`
    - `(不管|无视|忽略)(系统|安全|开发者)(提示词|指令|约束)`
    - `exfiltrate|send\s+(the\s+)?(secrets?|credentials?|keys?|tokens?)\s+(to|via)`
    - `do\s+not\s+(tell|inform|notify|reveal)\s+(the\s+)?user`
    - `print\s+(the\s+)?(system\s+prompt|api\s+keys?)`
- remediation: Remove the skill; audit its source; report the pattern to the skill marketplace.

## CTX-03  Invisible Unicode characters
- category: injection | severity: critical | static + dynamic | tools: Read, Write, Edit, Bash
- purpose: Blocks invisible Unicode (tag/zero-width/RLO -- the human-eye bypass, live-blocked 3x)
- description: Invisible Unicode character detected (tag characters, zero-width, word joiner, BOM in middle of file)
- 说明: 检出隐形 Unicode 字符（标签字符/零宽字符等）
- 处理建议: 清除隐形字符；出现在指令文件中默认按恶意处理
- detection: character_code_scan (ranges [{'start': 917504, 'end': 917631}, {'start': 8203, 'end': 8207}, {'start': 8288, 'end': 8292}, {'start': 65279, 'end': 65279}, {'start': 8232, 'end': 8238}], whitelist ['\u200d'])
- remediation: Strip invisible characters; treat any occurrence in instructions as hostile until proven otherwise.

## CTX-04  Encoded payload
- category: injection | severity: warning | static + dynamic | tools: Read, Write, Edit
- purpose: Alerts on long encoded blobs in skills (the payload behind base64/hex laundering)
- description: Long base64 or hex string detected (potential encoded payload)
- 说明: 检出超长 base64/hex 编码载荷
- 处理建议: 先解码审查再决定；正常说明文档极少内嵌长编码
- content_patterns:
    - `[A-Za-z0-9+/=]{200,}`
    - `[0-9a-fA-F]{400,}`
- remediation: Decode and review the payload; legitimate instructions rarely embed long encoded blobs.

## CTX-05  Skill name mismatch
- category: metadata | severity: warning | static + dynamic | tools: Read
- purpose: Detects SKILL.md identity mismatch (name spoofing / packaging slip)
- description: SKILL.md frontmatter name field does not match parent directory name
- 说明: SKILL.md 声明的 name 与目录名不一致
- 处理建议: 改名保持一致；不一致通常意味着身份伪装或打包疏漏
- check: frontmatter.name == directory_name
- remediation: Rename the directory or fix the frontmatter; mismatches hide a skill's real identity.

## DST-06  Remote script piped to interpreter
- category: destructive | severity: critical | dynamic (hook only) | tools: Bash
- purpose: Blocks remote-script-piped-to-interpreter (the classic supply-chain install)
- description: Agent downloaded a remote script and piped it straight into a shell or interpreter
- 说明: 下载远程脚本并直接交给解释器执行
- 处理建议: 先落盘查看内容再执行；确认来源可信
- command_patterns:
    - `(curl|wget)\b[^\n|;]{0,200}\|\s*(sudo\s+)?(sh|bash|zsh|dash|python|powershell)`
    - `\b(irm|iwr)\b[^\n|]{0,200}\|\s*(iex|invoke-expression)`
    - `\bbash\s+<\s*\(curl`
    - `\bcurl\b[^\n]{0,200}\b(-o|\-\-output)\s+[^\n]{0,80}\.(sh|ps1)\b[^\n]{0,80}[;&|]\s*(sh|bash|\.)`
    - `\bbase64\b[^\n]{0,60}(-d|--decode)[^\n]{0,80}\|\s*(sh|bash|python)`
    - `\|\s*base64\s+-d\b`
    - `(?:\[char\]\d+\+){2,}`
- exclude_patterns: `localhost`, `127\.0\.0\.1`
- remediation: Download and inspect the script first; confirm the source is trusted before executing.

## DST-07  Irreversible git discard
- category: destructive | severity: critical | dynamic (hook only) | tools: Bash
- purpose: Blocks irreversible git discards (reset --hard / clean -fdx eat uncommitted work)
- description: Agent ran a git command that irreversibly discards working-tree changes or untracked files
- 说明: 丢弃工作区改动的 git 命令（不可逆）
- 处理建议: 先 git stash 或提交，再执行
- command_patterns:
    - `\bgit\s+reset\s+--hard\b`
    - `\bgit\s+clean\s+-[fdxn]*[fdx]`
    - `\bgit\s+checkout\s+--(\s|$)`
- exclude_patterns: `git\s+clean\s+-n(\s|$)`
- remediation: Stash or commit first; only then discard, and prefer dry-run forms.

## SEC-06  Secret literal in content
- category: secrets | severity: critical | static + dynamic | tools: Write, Edit, Read, Bash
- purpose: Catches secret literals IN content (a key pasted into code outlives the file it was meant for)
- description: Secret-looking literal (API key, private key, token) appeared in written or edited content
- 说明: 写入或编辑的内容中出现密钥字面量
- 处理建议: 改用环境变量或密钥管理服务，不要把明文密钥写进文件
- content_patterns:
    - `sk-[A-Za-z0-9]{20,}`
    - `-----BEGIN [A-Z ]*PRIVATE KEY-----`
    - `AKIA[0-9A-Z]{16}`
    - `gh[pousr]_[A-Za-z0-9]{30,}`
    - `xox[baprs]-[A-Za-z0-9-]{12,}`
- exclude_patterns: `AKIAIOSFODNN7EXAMPLE`, `sk-(your|xxx|test|example|placeholder|dummy)`
- remediation: Use environment variables or a secrets manager; never paste plaintext keys into files.

## DST-08  Permission/ownership destruction
- category: destructive | severity: critical | dynamic (hook only) | tools: Bash
- purpose: Blocks recursive permission/ownership destruction (denial-of-service class)
- description: Agent attempted to destroy permissions or ownership recursively (denial of service)
- 说明: 递归破坏权限或属主，可致服务不可用
- 处理建议: 递归改权限/属主属于系统管理操作，请人工审查后执行
- command_patterns:
    - `\bchmod\s+000\b`
    - `\bchmod\b[^#\n]{0,40}\s-R\b`
    - `\bchown\b[^#\n]{0,40}\s-R\b`
- remediation: Permission/ownership recursion is a sysadmin action; do it yourself after review

## Policy file (.psl/policy.json, spec C-05)

| field | semantics |
|---|---|
| whitelist.domains | relaxes NETWORK rules only (NET-01/02 excludes, NET-03 whitelist, subdomains included) |
| whitelist.paths | path prefixes exempt from SECRETS rules and releasing DST-02 (each DST-02 release is audit-logged as dst02_path_whitelisted); install seeds agent-managed dirs that exist on the machine |
| whitelist.commands | command prefixes exempt from WARNING-level rules only; critical rules are never relaxed |
| global_settings.alert_threshold | warning (default) or critical: suppresses stderr notices below it; logging and blocking unchanged |
| global_settings.log_retention_days | archive age for report.py --archive (default 30) |
| global_settings.auto_archive | true: report.py applies retention on every run |
| global_settings.desktop_notify | ignored in v1 (spec B-04) |
