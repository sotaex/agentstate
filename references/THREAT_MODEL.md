# Antinel Security Suite - Threat Model (v0.27.0)

## What we protect against
An AI coding agent running inside an IDE host (Claude Code, ZCode, ...) executes tools on the
developer's machine. Four gates, 24 rules:

| Gate | Threat | Rules | Evidence source |
|---|---|---|---|
| 1 Content safety | Poisoned skill instructions: prompt injection, invisible Unicode, encoded payloads | CTX-02, CTX-03, CTX-04 | static file content + Read/Write hook |
| 2 Sensitive surface | Agent reads secrets: .env, SSH keys, cloud credentials, wallets, browser data | SEC-01..06 | file system + Read/Bash hook |
| 3 Metadata / egress policy | Skill identity spoofing; connections to non-whitelisted domains | CTX-05, NET-03 | metadata + command line |
| 4 Behaviour | Deletion, writes outside the project, alternate-data-stream writes (Windows), shell startup edits, persistence, privilege escalation, env enumeration, raw egress | DST-01..10, CTX-01, NET-01, NET-02 | PreToolUse / PostToolUse events |

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
- Hook latency on Windows is about 65 ms per call (interpreter start dominates); Linux/macOS untested.
- Only actions that pass through the host's PreToolUse hook can be blocked.
- Qoder / TRAE field layouts are declared profiles, not verified.
