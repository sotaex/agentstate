# Antinel Security Suite - Threat Model (v0.16.0)

## What we protect against
An AI coding agent running inside an IDE host (Claude Code, ZCode, ...) executes tools on the
developer's machine. Four gates, 22 rules:

| Gate | Threat | Rules | Evidence source |
|---|---|---|---|
| 1 Content safety | Poisoned skill instructions: prompt injection, invisible Unicode, encoded payloads | CTX-02, CTX-03, CTX-04 | static file content + Read/Write hook |
| 2 Sensitive surface | Agent reads secrets: .env, SSH keys, cloud credentials, wallets, browser data | SEC-01..05 | file system + Read/Bash hook |
| 3 Metadata / egress policy | Skill identity spoofing; connections to non-whitelisted domains | CTX-05, NET-03 | metadata + command line |
| 4 Behaviour | Deletion, writes outside the project, shell startup edits, persistence, privilege escalation, env enumeration, raw egress | DST-01..05, CTX-01, NET-01, NET-02 | PreToolUse / PostToolUse events |

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
- Hook latency on Windows is about 65 ms per call (interpreter start dominates); Linux/macOS untested.
- Only actions that pass through the host's PreToolUse hook can be blocked.
- Qoder / TRAE field layouts are declared profiles, not verified.
