---
name: antinel-security
description: >
  Scans your AI coding environment for security risks: exposed secrets,
  prompt injection and hidden characters in skills, network egress, and
  behavioral anomalies (37 rules, 4 gates). Use when the user asks about
  security, safety, environment audit, or mentions .env / API keys /
  permissions concerns. Triggers: security audit, is my agent safe, check secrets,
  skill poisoning, prompt injection, agent monitoring, 密钥泄露, Agent 行为监控.
  MCP server permission audit: planned for Phase 1.5.
  中文触发词：安全检查, 环境审计, 安全扫描, 是否安全.
license: MIT
compatibility: Requires Python 3.10+; standard library only; no network access; no third-party packages. Hooks verified on Claude Code and ZCode (identical protocol); workbuddy verified by real traffic (0.33.1, host_confidence=high); Qoder/TRAE profiles declared but unverified -- Qoder's flag rests on pre-0.33.1 records whose host label is itself unverified, so it is flagged for re-probe.
metadata:
  psl-verified: "false"
  psl-verified-spec: "psl-vs-0.1"
  psl-verified-at: "2026-09-28"
  psl-verified-evidence: "RE-RECORDED 2026-09-28 13:10 (0.33.1): all 21 covered files hash to their recorded digests in psl/judgment.json (antinel_verify derives 'current'); suite 309/313 assertions passed. NOT verified = verdict FAIL, 4 assertions fail: A4 (tampered rules hash -> fallback minimal set + SELF-TAMPERED; pre-existing, ordering-induced inside the suite); F-13/F-14/F-17 (host-shield sentinel: cannot spawn in a sandbox, schtasks.exe blocked by program blacklist -- re-run on a real host). REPRODUCIBILITY: the count no longer varies with machine load -- the A5 (30s) and C9 (15s) wall-clock gates plus a 6s SessionStart-banner hang-ceiling were removed on 2026-09-28 (a wall-clock ceiling measures the machine, not the hook). Host attribution: 0.33.1 records carry host_confidence; records written before 0.33.1 have NO attribution evidence and their host field must not be cited as fact."
  psl-verifier: "scripts/run_harness.py"
  antinel-product: "security-audit"
  antinel-tier: "free"
  antinel-version: "0.33.1"
  psl-token-interception: "false"
---

# AgentState (by Antinel) — AI Agent Audit Chain

> 展示名 **AgentState**｜厂牌 **by Antinel**｜本文件的 `name:`（技能标识符）与包名**不动**。
> 与 `server.json` 的 `title` 逐字一致。
> ⚠️ 已知不一致（属显式待办，不是遗漏）：**运行期消息仍写作「Antinel 拦截 …」**，
> 统一它需要改多个受覆盖文件、并牵动多条依赖该字串的断言 ⇒ 单独一次做（见交接件 §八）。

## 安全审计流程

当用户要求安全检查时，按以下步骤执行：

### 步骤1：安装Hooks（如果尚未安装）
检查当前项目目录下是否存在 .psl/manifest.json。
- 如果存在，跳到步骤3。
- 如果不存在，运行：python scripts/install.py

### 步骤2：确认安装
检查 .psl/manifest.json 是否已创建。
- 如果创建成功，继续步骤3。
- 如果创建失败，告知用户具体的错误信息。

### 步骤3：运行安全扫描
运行 python scripts/scan.py
- 退出码 0：扫描成功，读取输出的JSON报告。
- 退出码非0：读取stderr中的错误信息，告知用户。

### 步骤4：生成并展示报告
将扫描结果格式化为用户友好的报告。
按严重度排序：CRITICAL > WARNING > INFO。
每个发现包含：规则ID、文件路径、描述、修复建议。
行为报告（含扣分明细）：python scripts/report.py；按周：--days 7；导出：--format csv|sarif|html|json。

### 注意事项
- 你不需要理解每条安全规则的技术细节。
- 你只需要正确运行脚本并转述结果。
- 不要修改检测规则或审计日志。
- 如果扫描结果为空，告知用户"未发现异常"。
- 自定义白名单与阈值在 .psl/policy.json（安装时生成模板，语义见 references/RULES.md 末尾）。
