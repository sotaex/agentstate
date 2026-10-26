<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Antinel detection rules (generated from rules/default.json v0.57.1 - do not edit by hand)

Category order = match priority: secrets > destructive > network > injection > context > metadata.
Severity to action: critical = block, warning = alert (logged, allowed). All hits are collected; highest severity decides.

## SEC-01  Sensitive file read (.env)
- category: secrets | severity: critical | static + dynamic | tools: Read, Bash
- purpose: Prevents an agent reading .env files (live-blocked in ZCode on 09-10; the founding interception)
- description: Agent attempted to read a .env file which may contain API keys and secrets
- 说明: 读取 .env 文件可能泄露 API 密钥与机密配置
- 处理建议: 把 .env 移出 Agent 可读范围。确需变量时，手动复制具体几行。测试目录可在设置里登记
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
    - `\.ssh[/\\]id_`
    - `\.ssh[/\\]authorized_keys`
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
    - `\.aws[/\\]credentials`
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
    - `(?:^|[\\/])wallets?(?![\w.-])`
    - `(?:^|[\\/])keystores?(?![\w.-])`
    - `(?:^|[\\/])\.ethereum(?![\w.-])`
    - `(?:^|[\\/])metamask(?![\w.-])`
    - `(?:^|[\\/])(?:electrum|exodus|bitmonero|monero)(?![\w.-])`
    - `(?:^|[\\/])wallet\.(?:dat|json|key|keys|dump|db|sqlite)(?![\w.-])`
    - `(?:^|[\\/])keystore\.(?:json|db|sqlite)(?![\w.-])`
    - `(?:^|[\\/])wallet[_-][\w-]*\.(?:dat|json|key|keys|dump|db|sqlite|txt|seed)(?![\w.-])`
    - `(?:^|[\\/])keystore[_-][\w-]*\.(?:dat|json|key|db|sqlite)(?![\w.-])`
- exclude_patterns: `test_wallet`, `mock_wallet`
- remediation: Never let a coding agent touch wallet directories; move keystores to an encrypted vault.

## SEC-05  Browser data read
- category: secrets | severity: critical | static + dynamic | tools: Read, Bash
- purpose: Prevents browser profile reads (live login sessions, not just passwords)
- description: Agent attempted to read browser stored data (cookies, passwords, sessions)
- 说明: 读取浏览器数据（Cookie、密码、会话）
- 处理建议: 浏览器配置目录包含登录态，应完全禁止 Agent 访问
- file_patterns:
    - `(?:^|[\\/])(?:Cookies(?:-journal)?|Login\s+Data|Web\s+Data)(?![\\/\w.-])`
    - `(?:^|[\\/])Local\s+Storage(?![\w.-])`
    - `(?:^|[\\/])cookies\.sqlite(?:-wal|-shm)?(?!\w)`
    - `(?:^|[\\/])Cookies\.binarycookies(?!\w)`
    - `(?:^|[\\/])Google[\\/]Chrome[\\/]User Data[\\/]`
    - `(?:^|[\\/])Microsoft[\\/]Edge[\\/]User Data[\\/]`
    - `(?:^|[\\/])BraveSoftware[\\/]Brave-Browser[\\/]User Data[\\/]`
    - `(?:^|[\\/])\.mozilla[\\/]firefox[\\/](?:Profiles|[^\\/]+\.default)`
    - `(?:^|[\\/])\.config[\\/](?:google-chrome|chromium|BraveSoftware|vivaldi)[\\/](?:Default|Profile)`
    - `(?:^|[\\/])Library[\\/]Application Support[\\/](?:Google[\\/]Chrome|Firefox)[\\/]`
- remediation: Browser profiles contain live sessions; deny all agent access to profile directories.

## NET-01  Shell network request
- category: network | severity: warning | dynamic (hook only) | tools: Bash, WebFetch, WebSearch, MCP
- purpose: Surfaces shell egress to non-whitelisted domains (first-generation C2 / exfil channel)
- description: Agent made an external network request via shell command to a non-whitelisted domain
- 说明: 通过 Shell 向白名单外域名发起网络请求
- 处理建议: 核对目标域名。常用下载源放行：antinel domains add <域名>（进审计链）
- command_patterns:
    - `\b(curl|wget|fetch)\b.*https?://`
    - `https?://(?!registry\.npmjs\.org|pypi\.org|github\.com)`
    - `\b(scp|sftp|rsync|ssh|nc|ncat)\b\s+[^\n]{0,120}@`
    - `\b(certutil|bitsadmin)\b[^\n]{0,120}(urlcache|transfer|/transfer|/urlcache)`
    - `Invoke-(WebRequest|RestMethod)|Start-BitsTransfer`
    - `\bgit\s+push\b[^\n]*?(?:https?://|ssh://|[\w.-]+@[\w.-]+:)`
    - `\bgh\s+(release|repo)\s+create\b`
- exclude_patterns: `localhost`, `127\.0\.0\.1`, `registry\.npmjs\.org`, `pypi\.org`, `files\.pythonhosted\.org`, `github\.com`, `api\.github\.com`, `objects\.githubusercontent\.com`
- remediation: Pin downloads to whitelisted registries (npmjs/pypi/github) or review the destination.

## NET-02  Python network request
- category: network | severity: warning | dynamic (hook only) | tools: Bash, WebFetch, WebSearch, MCP
- purpose: Surfaces inline-code network calls (the same egress hidden inside python -c)
- description: Agent code contains Python network request calls
- 说明: 内联代码包含 Python 网络请求调用
- 处理建议: 核对请求目标地址后再放行
- command_patterns:
    - `urllib\.request`
    - `requests\.(get|post|put|delete)`
    - `httpx\.`
    - `socket\.create_connection`
    - `\bsocket\.socket\s*\(`
    - `\bhttp\.client\b`
    - `\bsmtplib\.SMTP\b`
    - `\bftplib\.FTP\b`
    - `require\(['"]https?['"]\)`
- remediation: Review the endpoints used by inline Python network code before allowing egress.

## NET-03  Non-whitelisted domain connection
- category: network | severity: warning | dynamic (hook only) | tools: Bash, WebFetch, WebSearch, MCP
- purpose: Surfaces non-whitelisted domains named in commands (DNS-level comparison is v2)
- description: Agent command references a domain outside the whitelist (v1 compares command-line domains; DNS-level comparison is a v2 kernel-layer capability)
- 说明: 命令引用了白名单外的域名
- 处理建议: 确认域名无害后放行：antinel domains add <域名>（进审计链）
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
- exclude_patterns: `rm -rf node_modules`, `rm -rf \.git`, `rm -rf __pycache__`, `rm -rf \.psl`, `remove-item node_modules`, `remove-item -recurse.*node_modules`, `\brm\s+(?:-[a-zA-Z]+\s+)*(?:\./)?(?:dist|build|target|venv|\.venv|node_modules|__pycache__|\.tox|\.nox|\.mypy_cache|\.ruff_cache|\.pytest_cache|\.cache|\.next|\.nuxt|\.svelte\-kit|\.turbo|\.parcel\-cache|\.gradle|htmlcov|coverage|out|bin|obj|Debug|Release)(?:[/\\][^\s;&|]*)?(?:\s|$|;|&|\|)`, `\brm\s+-rf\s+\S*\.(egg-info|pyc)(\s|$|;)`, `\brm\s+-rf\s+\.nox\b`, `^\s*(?:#|::|rem\s)`, `\bdef\s+\w*(?:remove|unlink|delete)\w*\(`
- remediation: Confirm the deletion target; prefer moving to trash over rm -rf outside build artifacts.

## DST-02  Write outside project root
- category: destructive | severity: critical | dynamic (hook only) | tools: Write, Edit, Bash
- purpose: Blocks writes outside the project root (the workspace is the trust boundary)
- description: Agent attempted to write to a file outside the project root directory
- 说明: 试图写入项目根目录之外；或用 tar 解包越权覆盖系统文件
- 处理建议: 放行：antinel paths add <目录前缀>（进审计链）。确需更大范围用 antinel roots add <路径>。或把文件写进项目内
- command_patterns:
    - `\btar\b[^\n]{0,120}-C\s+/(?:\s|$)`
    - `\btar\b[^\n]{0,120}\s-C\s+/(?:etc|usr|bin|sbin|var|lib|boot|srv|opt|home|root)(?:\s|$)`
- check: path_outside_project_root
- remediation: Allow: run `antinel paths add <prefix>` (audited) or `antinel roots add <dir>`; or keep agent writes inside the project.

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
    - `(?i)system32[/\\]tasks\b`
    - `(?i)launchdaemons\b`
    - `(?i)etc[/\\]cron\b`
    - `(?i)spool[/\\]cron\b`
    - `(?i)\.reg\b`
    - `(?i)currentversion[/\\]winlogon`
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

## CTX-02  Prompt injection pattern in instruction file
- category: injection | severity: critical | static + dynamic | tools: Read, Write, Edit
- purpose: Blocks prompt injection in skill instructions (the skill-poisoning payload core)
- description: Potential prompt injection payload in an instruction file (SKILL.md/AGENTS.md/CLAUDE.md/.cursorrules; non-SKILL.md needs 2 generic or 1 specific hit)
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
- detection: character_code_scan（7 类码点，按出现面分档：path / command / instruction / content）
    - U+E0000–U+E007F tag: path=critical, command=critical, instruction=critical, content=critical
    - U+202A–U+202E bidi_override: path=critical, command=critical, instruction=critical, content=info
    - U+2066–U+2069 bidi_isolate: path=critical, command=critical, instruction=critical, content=info
    - U+FEFF–U+FEFF mid_bom: path=warning, command=warning, instruction=warning, content=info
    - U+200B–U+200B zero_width: path=warning, command=warning, instruction=critical, content=info
    - U+2060–U+2064 word_joiner: path=warning, command=warning, instruction=critical, content=info
    - U+00AD–U+00AD soft_hyphen: path=warning, command=warning, instruction=warning, content=info
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
    - `(?:\||^|;|&&)\s*base64\s+(?:-d|--decode)\b[^\n]{0,80}\|\s*(?:sudo\s+)?(?:[\w./\\-]*[\\/])?(?:sh|bash|zsh|dash|python[0-9.]*|powershell)\b`
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
    - `-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/]{60,}`
    - `AKIA[0-9A-Z]{16}`
    - `gh[pousr]_[A-Za-z0-9]{30,}`
    - `xox[baprs]-[A-Za-z0-9-]{12,}`
- placeholder_patterns（命中片段是已知占位值 ⇒ 不算发现）: `AKIAIOSFODNN7EXAMPLE`, `AKIAI44QH8DHBEXAMPLE`, `sk-(?:your|xxx+|test|example|placeholder|dummy|fake|redacted)`, `gh[pousr]_(?:x{8,}|0{8,}|your|example|placeholder)`, `xox[baprs]-(?:0{8,}|x{8,}|your|placeholder)`
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

## DST-09  Alternate data stream write (file path)
- category: destructive | severity: critical | dynamic (hook only) | tools: Write, Edit
- purpose: Blocks alternate-data-stream writes from a file tool (Windows-only: path:stream is a legal POSIX filename)
- description: Agent attempted to write an NTFS alternate data stream (path:stream) -- invisible to dir/ls and carried along by a plain file copy
- 说明: 写入 NTFS 备用数据流（path:stream）。dir/ls 看不到，随文件复制一起走，是评审盲区
- 处理建议: ADS 在常规列表中不可见，且复制文件时随行，等于绕开评审；请改写为普通文件以便审查
- file_patterns:
    - `\.[^\\/:\s]{1,32}:(?!Zone\.Identifier\b)`
- platforms: nt (rule is skipped on other hosts; it stays in the loaded set so rule counts are platform-invariant)
- remediation: Stored in the file's own stream table, an ADS does not show up in normal listings or in the copy that gets reviewed. Write the bytes as a normal file instead.

## DST-10  Alternate data stream write (command)
- category: destructive | severity: critical | dynamic (hook only) | tools: Bash
- purpose: Blocks alternate-data-stream writes from a shell (redirect / -Stream / copy / open -- the command half of DST-09)
- description: Agent attempted to write an NTFS alternate data stream from a shell (redirect / -Stream / copy / open) -- the command-line half of DST-09
- 说明: 从命令行写入 NTFS 备用数据流。重定向 / -Stream / copy / open 等命令通道都能做到。
- 处理建议: 与 DST-09 同一通道的命令行写法，产物同样逃过审查；请改用普通文件
- command_patterns:
    - `>\s*[^\s|;&\"'<>]*\.[^\\/:\s]{1,32}:(?!Zone\.Identifier\b)`
    - `\b(?:Set-Content|Add-Content|Clear-Content)\b[^\n]{0,160}?-Stream\b(?![\s\"']*Zone\.Identifier)`
    - `\b(?:copy|xcopy|robocopy)\b[^\n]{0,120}?\.[^\\/:\s]{1,32}:(?!Zone\.Identifier\b)`
    - `\bopen\s*\([^\n)]{0,200}\.[^\\/:\s\"']{1,32}:(?!Zone\.Identifier)[^\"'\n]{0,200}[\"']\s*,\s*[\"'][wa]`
- platforms: nt (rule is skipped on other hosts; it stays in the loaded set so rule counts are platform-invariant)
- remediation: Same channel as DST-09 reached from a shell; the file written this way survives review. Use a normal file.

## CTX-07  Inline base64-decode exec
- category: injection | severity: critical | static + dynamic | tools: Bash
- purpose: unknown (generator table missing an entry)
- description: Inline base64-decode-then-exec/eval in a shell command (classic obfuscated payload carrier)
- 说明: 命令行内联 base64 解码后 exec/eval 执行（经典混淆载荷载体）
- 处理建议: 先解码审查内容；不要让解码后的代码直接执行
- content_patterns:
    - `\bexec\s*\(\s*(?:__import__\(['\"]base64['\"]\)\.)?base64\.b64decode\(`
    - `\beval\s*\(\s*(?:__import__\(['\"]base64['\"]\)\.)?base64\.b64decode\(`
    - `(?:exec|eval)\s*\([^;\n]{0,120}b64decode\s*\(`
- remediation: Decode and inspect the payload first; never let inline decoded code run directly.

## SEC-07  Clipboard read
- category: secrets | severity: critical | static + dynamic | tools: Bash
- purpose: unknown (generator table missing an entry)
- description: Agent read the system clipboard, which may hold passwords, tokens or private text the user copied
- 说明: 读取系统剪贴板（可能含用户刚复制的口令/令牌/隐私文本）
- 处理建议: 不要让 Agent 读剪贴板；需要某个值请用户自己粘贴
- command_patterns:
    - `(?i)\bget-clipboard\b`
    - `(?i)\bpbpaste\b`
    - `(?i)\bxclip\b[^\n]{0,40}\s-o\b`
    - `(?i)\bxsel\b[^\n]{0,40}\s-o\b`
    - `(?i)\bwl-paste\b`
    - `(?i)\bpyperclip\b[^\n]{0,40}\.paste\b`
    - `(?i)win32clipboard[^\n]{0,80}GetClipboardData`
    - `(?i)clipboard_get\s*\(`
    - `(?i)\[System\.Windows\.Forms\.Clipboard\]::(GetText|GetData|GetImage|ContainsText)`
    - `(?i)\[Windows\.ApplicationData\]::Current\.GetClipboardContent`
- remediation: Do not read the clipboard from an agent command; ask the user to paste the value instead.

## SEC-08  Screen capture
- category: secrets | severity: warning | static + dynamic | tools: Bash
- purpose: unknown (generator table missing an entry)
- description: Agent captured the screen (screenshot/record), which can carry whatever is displayed
- 说明: 截屏/录屏（屏幕上有什么就会被带走什么）
- 处理建议: Agent 几乎不需要截屏；确需截屏请人工操作
- command_patterns:
    - `(?i)\bscreencapture\b`
    - `(?i)\bgnome-screenshot\b`
    - `(?i)\bscrot\b`
    - `(?i)\bimport\s+-window\b`
    - `(?i)\bxwd\b`
    - `(?i)\bnircmd\b[^\n]{0,60}savescreenshot`
    - `(?i)ffmpeg[^\n]{0,140}(-f\s+gdigrab|-f\s+avfoundation|-f\s+x11grab)`
    - `(?i)CopyFromScreen`
    - `(?i)ImageGrab\.grab`
    - `(?i)pyautogui\.screenshot`
    - `(?i)\bGet-CimInstance\b[^\n]{0,80}Win32_VideoController`
- remediation: Screen capture from an agent is almost never needed; if it is, do it manually.

## SEC-09  IM/mail local store read
- category: secrets | severity: critical | static + dynamic | tools: Read, Bash
- purpose: unknown (generator table missing an entry)
- description: Agent read an instant-messaging or mail client's local store (full message history)
- 说明: 读取 IM/邮件客户端的本地库（等于全部往来记录）
- 处理建议: 这是用户私人通信；应完全禁止 Agent 访问
- command_patterns:
    - `(?i)(WeChat Files|xwechat_files|Tencent[\\/]WeChat)[^\n]{0,200}\.db`
    - `(?i)\b(nt_msg|media_msg|message_\d+|MediaMSG\d*|nt_qq)\w*\.db\b`
    - `(?i)(copy|xcopy|robocopy|tar|zip|7z)[^\n]{0,200}\.(ost|pst)\b`
    - `(?i)sqlite3?[^\n]{0,200}(nt_msg|media_msg|message_\d+|nt_qq)`
- file_patterns:
    - `(?i)WeChat Files`
    - `(?i)xwechat_files`
    - `(?i)Tencent[\\/]WeChat\b`
    - `(?i)com\.tencent\.xinWeChat`
    - `(?i)[\\/]Msg[\\/][^\\/]{0,40}\.db`
    - `(?i)[\\/]DingTalk[\\/][^\\/]{0,40}\.db`
    - `(?i)[\\/]nt_qq\b`
    - `(?i)\.ost$`
    - `(?i)\.pst$`
    - `(?i)Lark[\\/][^\\/]{0,40}\.db`
    - `(?i)\bDingTalk\b`
- remediation: These stores are the user's private correspondence; deny agent access entirely.

## SEC-10  Input-method user dictionary read
- category: secrets | severity: warning | static + dynamic | tools: Read, Bash
- purpose: unknown (generator table missing an entry)
- description: Agent read the input-method user dictionary, which records what the user has typed
- 说明: 读取输入法用户词库/上屏记录（等于用户打过什么字）
- 处理建议: 输入历史属隐私；不要让 Agent 读取输入法词库
- command_patterns:
    - `(?i)(copy|xcopy|robocopy|tar|zip|7z)[^\n]{0,200}(SogouPY|SogouInput|BaiduPinyin|QQPinyin|userdict)`
    - `(?i)(SogouPY|SogouInput|BaiduPinyin|QQPinyin)[^\n]{0,200}\.(dat|bin|db)\b`
- file_patterns:
    - `(?i)[\\/]SogouPY\b`
    - `(?i)[\\/]SogouInput\b`
    - `(?i)[\\/]WeChatInput\b`
    - `(?i)[\\/]BaiduPinyin\b`
    - `(?i)[\\/]QQPinyin\b`
    - `(?i)[\\/]Rime\b`
    - `(?i)\.scel$`
- remediation: Typing history is private; do not let an agent read IME dictionaries.

## DST-11  Write into cloud-sync directory
- category: destructive | severity: critical | dynamic (hook only) | tools: Write, Edit, Bash
- purpose: unknown (generator table missing an entry)
- description: Agent wrote into a cloud-drive sync folder: the sync client will upload the file automatically
- 说明: 写进云盘同步目录 —— 同步客户端会自动把它传上云
- 处理建议: 确需放行：antinel paths add <目录前缀>（进审计链）。否则写进项目内
- check: path_in_cloud_sync_dir
- remediation: Allow deliberately with `antinel paths add <prefix>` (audited), or write inside the project.

## NET-04  Tunnel / covert channel
- category: network | severity: warning | dynamic (hook only) | tools: Bash, WebFetch, WebSearch, MCP
- purpose: unknown (generator table missing an entry)
- description: Agent opened a tunnel / covert channel (reverse tunnel, proxy, DNS-ICMP carrier) to move data out
- 说明: 建立隧道/隐蔽信道（反向隧道、代理、DNS/ICMP 载波）——绕过常规出网检查
- 处理建议: 隧道会绕过常规出网检查；放行前先确认目标
- command_patterns:
    - `(?i)\b(ngrok|frpc|frps|v2ray|xray|sing-box|trojan|hysteria|clash|shadowsocks|ss-local)\b`
    - `(?i)\b(icmpsh|ptunnel|iodine|dnscat2?|hans|chisel|socat|stunnel|obfs4)\b`
    - `(?i)\bnc(at)?\b[^\n]{0,60}\s-[a-z]*e\b`
    - `(?i)\bssh\b[^\n]{0,80}\s-[RLD]\s`
    - `(?i)\bping\b[^\n]{0,60}\s-[lp]\s+(?:[0-9A-Fa-f]{16,}|\d{4,})`
    - `(?i)\b(ngrok(-free)?\.(io|app)|trycloudflare\.com|serveo\.net|localtunnel\.me|localhost\.run|pinggy\.(io|link)|bore\.pub|lhr\.life|tunnel\.to)\b`
- remediation: Tunnels bypass ordinary egress checks; confirm the destination before allowing.

## MCP-01  Write to MCP config file
- category: supply_chain | severity: warning | dynamic (hook only) | tools: Write, Edit, Bash
- purpose: unknown (generator table missing an entry)
- description: MCP configuration file written/modified -- verify the new server's source, command and url (malicious MCP servers are an active 2025-2026 supply-chain channel)
- 说明: MCP 配置文件被写入或修改
- 处理建议: 核对新增 server 的来源。不认识的一律移除，并轮换相关凭据
- file_patterns:
    - `(^|[\\/])\.cursor[\\/]mcp\.json$`
    - `(^|[\\/])\.mcp\.json$`
    - `(^|[\\/])claude_desktop_config\.json$`
    - `(^|[\\/])\.vscode[\\/]mcp\.json$`
- content_patterns:
    - `(?is)(?:>>|>|\btee\b|\bcp\b|\bmv\b|\bmove\b|\bcopy\b|\bset-content\b|\bout-file\b|\badd-content\b)[^\n]{0,120}\.mcp\.json`
    - `(?is)(?:>>|>|\btee\b|\bcp\b|\bmv\b|\bmove\b|\bcopy\b|\bset-content\b|\bout-file\b|\badd-content\b)[^\n]{0,120}mcp\.json`
    - `(?is)(?:>>|>|\btee\b|\bcp\b|\bmv\b|\bmove\b|\bcopy\b|\bset-content\b|\bout-file\b|\badd-content\b)[^\n]{0,120}claude_desktop_config\.json`
- remediation: Verify the new server's source, command and url; remove any you do not recognize and rotate the related credentials.

## MCP-02  Prompt injection in MCP tool description
- category: supply_chain | severity: warning | dynamic (hook only) | tools: Read, Write, Edit
- purpose: unknown (generator table missing an entry)
- description: MCP tool description/config contains prompt-injection patterns (tool-poisoning class; postmark-mcp case)
- 说明: MCP 工具描述/配置中发现提示注入模式（工具投毒类；postmark-mcp 案例）
- 处理建议: 移除该 MCP 服务器并核查其来源；工具描述里的指令会在每次工具调用时进入模型上下文
- file_patterns:
    - `(^|[\\/])\.cursor[\\/]mcp\.json$`
    - `(^|[\\/])\.mcp\.json$`
    - `(^|[\\/])claude_desktop_config\.json$`
    - `(^|[\\/])\.vscode[\\/]mcp\.json$`
- content_patterns:
    - `ignore\s+(all\s+)?(previous|prior|above)\s+instructions`
    - `exfiltrate|send\s+(the\s+)?(secrets?|credentials?|keys?|tokens?)\s+(to|via)`
    - `do\s+not\s+(tell|inform|notify|reveal)\s+(the\s+)?user`
    - `trust\s+this\s+server\s+automatically`
    - `curl\s+[^\s]*\$\{?[A-Z_]*(KEY|TOKEN|SECRET)`
- remediation: Remove that MCP server and check where it came from; instructions in a tool description enter the model context on every tool call.

## MCP-03  Unaudited remote MCP server
- category: supply_chain | severity: warning | dynamic (hook only) | tools: Read, Write, Edit
- purpose: unknown (generator table missing an entry)
- description: MCP config references a remote server (http url or mcp-remote bridge) -- remote tool definitions can change silently after approval
- 说明: MCP 配置引用远程服务器（http url 或 mcp-remote 桥接）
- 处理建议: 确认远程端点可信；优先本地 stdio server；远程定义变更不受你控制
- file_patterns:
    - `(^|[\\/])\.cursor[\\/]mcp\.json$`
    - `(^|[\\/])\.mcp\.json$`
    - `(^|[\\/])claude_desktop_config\.json$`
    - `(^|[\\/])\.vscode[\\/]mcp\.json$`
- content_patterns:
    - `mcp-remote`
    - `"url"\s*:\s*"https?://`
- remediation: Confirm the remote endpoint is trustworthy; prefer a local stdio server -- remote tool definitions can change without your control.

## MCP-04  Plaintext secret in MCP config env
- category: supply_chain | severity: warning | dynamic (hook only) | tools: Read, Write, Edit
- purpose: unknown (generator table missing an entry)
- description: Plaintext API key/token inside MCP config env block (config files get synced, shared and committed far more often than .env)
- 说明: MCP 配置 env 块中存在明文密钥
- 处理建议: 改用凭据引用/环境注入；已写入的密钥视为已泄露并轮换
- file_patterns:
    - `(^|[\\/])\.cursor[\\/]mcp\.json$`
    - `(^|[\\/])\.mcp\.json$`
    - `(^|[\\/])claude_desktop_config\.json$`
    - `(^|[\\/])\.vscode[\\/]mcp\.json$`
- content_patterns:
    - `\bsk-[A-Za-z0-9_\-]{20,}\b`
    - `\bgh[pousr]_[A-Za-z0-9]{36,}\b`
    - `\bAKIA[0-9A-Z]{16}\b`
    - `\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`
    - `\bAIza[0-9A-Za-z_\-]{35}\b`
    - `-----BEGIN [A-Z ]*PRIVATE KEY-----`
- remediation: Use credential references or environment injection instead; treat any key already written as leaked and rotate it.

## SEC-11  Canary file read
- category: canary | severity: warning | dynamic (hook only) | tools: Read, Bash
- purpose: unknown (generator table missing an entry)
- description: Agent read a canary file -- if its marker (CANARY-*) appears in any external channel, that proves exfiltration of project content
- 说明: Agent 读取了诱饵文件
- 处理建议: 记录并观察：诱饵文件被读取本身不是泄露。标记出现在外部通道才是证据（日报的诱饵文件统计）
- file_patterns:
    - `(^|[\\/])\.canary[\\/]CANARY-`
- content_patterns:
    - `\.canary[\\/]CANARY-`
- remediation: Record and observe: reading a canary is not itself a leak -- the marker appearing in an external channel is the evidence (see the canaries count in `report`).

## SLOP-01  Typosquatted package name in install command
- category: supply_chain | severity: warning | dynamic (hook only) | tools: Bash
- purpose: unknown (generator table missing an entry)
- description: Install command references a package name suspiciously close to a popular package (typosquatting / slopsquatting class). Determined by the hook's built-in reference set (rules/typosquat_top.json, static, dated) -- new packages published after the set date are not judged.
- 说明: 安装命令中的包名与热门包高度相近（撞名/slopsquatting 类）
- 处理建议: 核对包名拼写与官方文档；确认后再安装；已安装的立即移除并轮换凭据
- command_patterns:
    - `(?i)\b(pip|pip3|npm)\s+install\b`
- remediation: Check the package name against the official docs; install only after confirming; remove anything already installed and rotate credentials.

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
