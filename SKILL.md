---
name: antinel-security
description: >
  Scans your AI coding environment for security risks: exposed secrets,
  prompt injection and hidden characters in skills, network egress, and
  behavioral anomalies (24 rules, 4 gates). Use when the user asks about
  security, safety, environment audit, or mentions .env / API keys /
  permissions concerns. Triggers: security audit, is my agent safe, check secrets,
  skill poisoning, prompt injection, agent monitoring, 密钥泄露, Agent 行为监控.
  MCP server permission audit: planned for Phase 1.5.
  中文触发词：安全检查, 环境审计, 安全扫描, 是否安全.
license: MIT
compatibility: Requires Python 3.10+; standard library only; no network access; no third-party packages. Hooks verified on Claude Code and ZCode (identical protocol); Qoder/TRAE profiles declared but unverified.
metadata:
  psl-verified: "true"
  psl-verified-spec: "psl-vs-0.1"
  psl-verified-at: "2026-09-21T18:50:56+08:00"
  psl-verified-evidence: "live PreToolUse block of a real .env read in ZCode (SEC-01) plus a full-assertion judgment run (count: psl/judgment.json assertions_total)"
  psl-verifier: "scripts/run_harness.py"
  antinel-product: "security-audit"
  antinel-tier: "free"
  antinel-version: "0.27.0"
  psl-token-interception: "false"
---

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
