---
# SPDX-License-Identifier: CC-BY-SA-4.0
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
license: Apache-2.0
compatibility: Requires Python 3.10+; standard library only; no network access; no third-party packages. Hooks verified on Claude Code and ZCode (identical protocol); Qoder/TRAE profiles declared but unverified.
metadata:
  psl-verified: "true"
  psl-verified-spec: "psl-vs-0.1"
  psl-verified-at: "2026-10-28T10:41:03+0800"
  psl-verified-evidence: "live PreToolUse block of a real .env read in ZCode (SEC-01) plus a full-assertion judgment run; digest check 21/21 digests match this build (assertions 325/325)"
  psl-verifier: "scripts/run_harness.py"
  antinel-product: "security-audit"
  antinel-tier: "free"
  antinel-version: "0.60.0"
  psl-token-interception: "false"
---

## 安装（只需要一次）

```
pip install antinel
```

包名是 **`antinel`**（不是 `antinel-security` —— 那是技能名）。零依赖、纯标准库、运行时不联网。

不确定装没装、或想看当前状态，跑一条就够：

```
antinel agent --json
```

> 如果报「命令找不到」（`--user` 安装时 `Scripts` 常不在 PATH），
> 把 `antinel` 换成 `python -m antinel` —— 后面所有命令都这么换即可。

它返回一个 JSON：`installed`（钩子装没装）、`host_detected`（识别出的宿主）、
`next_steps`（下一步敲什么）、`skill_md`（本文件的路径）、退出码契约。
**不要靠猜，先跑这一条。**

## 安全审计流程

### 步骤0：确认已安装

- 目标项目里没有 `.psl/manifest.json` ⇒ 说明还没装。
- 装：`antinel install`（等价 `python -m scripts.install`，两条都对）。
- 装完**必须重启宿主一次**——钩子在宿主启动时加载，不重启不生效。

### 步骤1：跑扫描

```
python -m scripts.scan --root .
```

- 退出码 0 = 扫描完成。**有发现也是 0**（发现数量看报告，不看退出码）。
- 想要机器可读：`python -m scripts.scan --json`。

⚠ 命令要写成**模块形态**（上面那样带 `-m`）。把模块当文件路径敲的那种写法，
装完之后跑不通——那些文件在 `site-packages` 里，不在你的项目根下。
（反例长什么样这里不写全，免得被当成"教过的命令"抄走。）

### 步骤2：读报告

```
python -m scripts.report --days 7
```

按严重度排序：CRITICAL > WARNING > INFO。每条发现含：规则 ID、文件路径、描述、修复建议。
导出：`--format csv|sarif|html|json`。

### 步骤3：讲给用户听

- 有发现：按严重度排序转述，**每条都带上修复建议**（报告里就有，不要自己编）。
- 没发现：直接说"未发现异常"，并附上扫描了多少文件（报告里有分母）。
- **不要**因为退出码非 0 就说失败——先读 stderr 里的原文。

## 常用命令（都能在装完之后直接跑）

| 你要什么 | 命令 |
|---|---|
| 当前状态、下一步 | `antinel agent --json` |
| 装 / 查 / 卸钩子 | `antinel install` ／ `--check` ／ `--uninstall` |
| 打印本手册 | `antinel skill`（`--path` 只给路径，省 token） |
| 决策层一页纸 | `antinel brief` |
| 近 N 天干了什么 | `antinel digest --days N` |
| 静态扫描（机器可读） | `python -m scripts.scan --json` |
| 证据链有没有被动过 | `antinel verify` |
| 行为报告 | `python -m scripts.report --days 7` |

## 注意事项

- 你不需要理解每条安全规则的技术细节。
- 你只需要正确运行脚本并转述结果。
- 不要修改检测规则或审计日志。
- 自定义白名单与阈值在 `.psl/policy.json`（安装时生成模板）。
- 运行时零网络、无第三方依赖、无驻留进程。
- 它只匹配工具调用文本与文件内容，**不解析脚本语义**——把删除或外发写进一个
  `.py`/`.sh` 再执行，闸门不会拦。这是护栏，不是隔离层。
- 已验证可拦截的宿主：Claude Code / ZCode / Qoder。其余宿主装完是**审计与扫描模式**，
  `antinel install` 会明说这一点——那不是装失败。
