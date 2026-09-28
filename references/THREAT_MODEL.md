# Antinel Security Suite - Threat Model (v0.33.1)

## What we protect against
An AI coding agent running inside an IDE host (Claude Code, ZCode, ...) executes tools on the
developer's machine. Four gates, 37 rules:

| Gate | Threat | Rules | Evidence source |
|---|---|---|---|
| 1 Content safety | Poisoned skill instructions: prompt injection, invisible Unicode, encoded payloads | CTX-02..04, CTX-07 | static file content + Read/Write hook |
| 2 Sensitive surface | Agent reads secrets: .env, SSH keys, cloud credentials, wallets, browser data; secret literals in file content; input-method dictionaries; canary files planted to prove exfiltration | SEC-01..11 | file system + Read/Bash hook |
| 3 Metadata / egress policy | Skill identity spoofing; connections to non-whitelisted domains; tunnels and covert channels | CTX-05, NET-03..04 | metadata + command line |
| 4 Behaviour | Deletion, writes outside the project, alternate-data-stream writes (Windows), shell startup edits, persistence, privilege escalation, env enumeration, raw egress | CTX-01, DST-01..11, NET-01..02 | PreToolUse / PostToolUse events |

Rule-range notation is by family and must be re-derived from `rules/default.json`
whenever a rule is added: a stale range silently understates what is enforced.

Severity to action: critical = block (stdout decision JSON + stderr + exit 2), warning = alert (logged, stderr notice, allowed).
All hits of one event are collected; the highest severity decides.

## What we explicitly do not do (Phase 1)
- No hardening or remediation (we report; fixing is the user's call or Anxin Zhixin hardware products).
- No encrypted-traffic or network-layer analysis (tool-call layer only; DNS-level comparison is a v2 kernel capability).
- No SAST/DAST vulnerability scanning of the user's code.
- No certified test reports (audit logs and assessments only; CMA red line).
- No MCP server permission audit (Phase 1.5) and no dependency supply-chain audit (Phase 2).
- No token-level output interception (v2: hook soft interception / kernel hard interception).

## Our own attack surface
- Zero network at runtime; standard library only; no persistent process.
- Fail open: any internal error allows the action (a security tool must never break the host).
- Probe mode (ANTINEL_PROBE=1 hook env) skips audit writes for the probed call. Setting that env requires host-environment control -- the same equal-privilege attacker class as editing .psl/ (A12): documented, not defended. Legit probes chain an enforcement_probe record; an attacker-set probe still emits deny (exit 2), so it degrades EVIDENCE, not protection. 0.32.1 registers this boundary after adversarial self-review.
- Self-tamper: install records sha256 of rules and all five scripts; report.py prints SELF-TAMPERED on drift.
- Recomputable audit: every record carries content_digest = sha256(canonical JSON of tool_name + tool_input).
- Policy cannot weaken the baseline: whitelist.paths relaxes secrets rules only, whitelist.commands relaxes
  warning-level rules only, whitelist.domains relaxes network rules only; critical non-network rules are never relaxed.

## Known limits (documented, not hidden)
- Guardrail, NOT a sandbox: rules match TOOL-CALL TEXT only. A deletion or an
  out-of-root write placed inside a .py/.sh that the agent later executes is NOT
  intercepted (measured: the Bash channel has no file_path, so DST-02 never
  fires there). Since 0.17.0 such commands are SURFACED as
  dst02_bash_path_suspect alert records, never blocked.
- The deny signal was a SINGLE-CHANNEL dependency (0.29.0, E-3). `emit_block`
  printed a top-level `{"decision": "block", ...}` and stood on `exit 2` as the
  authoritative channel, while hosts document `hookSpecificOutput` (with
  permissionDecision) as the current PreToolUse contract. Should a host stop
  honouring exit 2, every block would degrade into an allow **silently** -- no
  error, no drop in hook invocations, and the audit chain would keep recording
  antinel's DECISION while the world saw the opposite outcome.
  **0.30.0 closure, two halves:**
  1. *Signaling half* (proven actively): deny is emitted on THREE additive
     channels -- documented contract JSON (`hookSpecificOutput.permissionDecision=
     "deny"`), legacy stdout JSON, and exit 2 + stderr (policy
     `global_settings.deny_stdout`: dual/legacy/quiet). A daily synthetic
     self-probe (`tools/enforce_probe.py`, scheduled detached from post_tool_use
     or run manually) feeds the REAL hook a must-block event and chains an
     `enforcement_probe` record asserting every channel -- so a signaling
     regression is found within a day, by the system, not by a user.
  2. *Enforcement half* (proven passively, on real traffic): post_tool_use joins
     on `content_digest`; if a pre record with `decision=block` is followed by
     the tool ACTUALLY RUNNING, that is chained as `enforcement_gap` -- the
     host did not honor the deny. This is the only honest proof of host
     behaviour, because a probe cannot reach inside the host's decision loop.
  **Residual (honest):** the probe proves the hook signals correctly; host
  honoring is proven only when a blocked call recurs (real traffic) -- a quiet
  host that never re-runs a blocked call delays that proof, not its detection
  of signaling failures. Qoder/TRAE remain declared-unverified profiles; on
  them the probe now at least states whether the hook side works.

## Non-goals
- Script-content scanning. Parsing every script the agent writes for dangerous
  operations would be a sandbox promise this layer cannot keep (and an
  avalanche of false positives -- test fixtures contain dangerous words by
  design). Isolation belongs to containers/VMs, not to a PreToolUse hook.
- Alternate-data-stream CONTENT. DST-09/DST-10 block the WRITE PATH on Windows
  (`echo x > f.txt:stream`, `Set-Content -Stream`, `copy`, `open(...,"w")`), but
  the PAYLOAD inside a stream cannot be read back through the tool-call layer, so
  contents already written into an ADS are invisible to review. The write is
  intercepted; the contents are not inspected. Measured scope: DST-09/DST-10 are
  Windows-gated (`path:stream` is a legal POSIX filename) and `Zone.Identifier`
  is exempt by design -- it is written by browsers and downloaders on every save.
- Stopping everything. Severity decides: critical blocks, warnings alert and
  proceed. A hook that blocks a developer's daily build command gets uninstalled
  on day one -- and an uninstalled hook stops nothing.
- Protecting the guardrail's OWN configuration. workspace_roots (the trust
  boundary) lives at host level and is read by the hook. Until 0.19.1 a write to
  it was blocked on the Write/Edit channel only; measured 2026-09-14 the Bash
  channel reached the same file via a script that builds the path internally,
  with NO DST-02 signal at all (audit: decision=allow, rules_hit=[]). So the
  block stopped the user's own delegated maintenance -- including creating
  skills -- without stopping anyone else. Since 0.19.2 both channels do the same
  thing: RELEASE the exact config file (not its parent directory) and RECORD it
  as dst02_host_config_self_maintenance. That is a downgrade from prevent to
  record, deliberately: a boundary that must not be editable needs a read-only
  mount or a container, which a hook running as the agent cannot provide.
- Host prompt passthrough (`ask`) is a RETIRED idea, not a pending feature
  (0.29.0, E-3). Host documentation confirms only `deny` and `allow` for
  permissionDecision; `ask` is not confirmed on any host. Nothing is lost: the
  host's own confirmation dialog still fires, because our allow is silence and
  silence means "no opinion, continue the normal permission flow". Do not
  implement `ask` without a measurement on a real host -- an unconfirmed value
  kept on a backlog is how an unmeasured claim becomes a shipped promise.
- Hook latency on Windows is about 65 ms per call (interpreter start dominates); Linux/macOS untested.
- Only actions that pass through the host's PreToolUse hook can be blocked.
- Qoder / TRAE field layouts are declared profiles, not verified.

## 0.33.1 additions — host attribution is evidence, not a guess

**归因的三档可信度（新记录带 `host_confidence` 字段）：**

| source | confidence | 含义 |
|---|---|---|
| `explicit`（`ANTINEL_HOST`） | high | 人显式指定，人说了算 |
| `env`（宿主进程实际设置的键） | high | 每次调用由宿主进程注入，最可靠 |
| `dir`（项目目录标记） | **low** | 只说明"这个工具曾在此项目跑过"，不代表本次调用来自它 |
| `none` | none | 什么都没命中 ⇒ 额外写一条 `host_tag_uncertain` 事件（自动取证） |

**为什么目录标记是低可信**：多人多工具共用一个项目目录是常态（PSL 根目录同时有
`.qoder` `.trae` `.workbuddy`）。它记录的是"来过"，不是"这次是它"。所以排序必须
显式定序，且要把 `markers_seen` 全量记进证据供事后复核。

**env 优先这条策略的前提**：我方键表必须覆盖**宿主实际会设的键**。WorkBuddy 设的是
`CODEBUDDY_*` + `CLAUDE_PROJECT_DIR`，不设 `CLAUDE_CODE`。0.33.0 的键表不覆盖它 ⇒
env 全落空 ⇒ 静默退回目录标记 ⇒ 本项目的 WorkBuddy 流量全被标成 `qoder`（实测）。
修法不是加一行判断，是把"键表必须覆盖宿主实际行为"这条前提写进设计，并让落空时
自动留证（不再静默）。

**旧记录的宿主标签不可信**：0.33.1 之前的记录没有 `host_confidence` 字段，其 `host`
值不得当作事实引用。链不可变 ⇒ 不改链，改读法：`digest` / `report` 会打印不可信
记录数与占比，并明确写"这两个 host 字段不能当事实引用"。

**deny 通道完整性（0.33.1 实测修复）**：`_deny_payload` 原先只对硬编码名单
`("claude-code","generic")` 输出 stdout 契约；任何新识别的宿主都会落进静默分支，
于是 `hookSpecificOutput.permissionDecision=deny` 这条通道被**静默丢掉**，只剩
exit 2 + stderr。归因修好后 workbuddy 首次被正确识别即踩中。判据：多给一个 key
最坏是被宿主忽略，少给一条通道则是拦截失效——二者不对称。名单已改为可配置
（`global_settings.deny_stdout_hosts`），默认含 workbuddy（依据：WorkBuddy 会读
钩子的 stdout JSON，SessionStart 横幅在真机上送达）。

**探针（ANTINEL_PROBE=1）**：仍然是边界——能设这个 env 的人同样能改 `.psl/`，
与攻击者同权，防不住。0.33.1 起改为可检测：探针每次运行往
`audit/sidecar/<日>.probe.jsonl` 写一条 `probe_used`。主链不被污染（探针语义不变），
但"谁在什么时候用过探针"从此有据可查。
