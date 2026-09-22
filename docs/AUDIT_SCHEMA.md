# AUDIT_SCHEMA.md — Antinel 审计记录模式 v1.2（随 v0.28.0）

> 本文是 `.psl/audit/` 下每一条记录的**字段级契约**，供第三方独立复核。
> 原则：**记录里只有事实与指纹，没有内容、没有评分**。任何字段语义变更必须 bump 本文档版本并在变更说明中登记。
> v1.1（0.23.0）：新增 `usage_delta` 记录类型（token 事实）；`session_dna` 新增 `usage` 块（聚合与**派生**成本估算）。
> v1.2（0.28.0）：**降级记录迁移至 sidecar**——`chain:"unlocked"` 的记录不再写入主链，改写 `audit/sidecar/<日>.<pid>.jsonl`（单写者文件）；主链从此只含按锁定协议成链的记录。依据：《v0.28 条款·链并发语义 v2》C-2/C-3（葛广 2026-09-21 确认）；动机：Gauntlet 实证 unlocked 直写主链与持锁写相撞会产生与篡改同形的分叉。

## 1. 存放位置

| 位置 | 内容 |
|---|---|
| `<root>/.psl/audit/YYYY-MM-DD.jsonl` | 当日审计链（每行一条 JSON 记录，**仅含按锁定协议成链的记录**） |
| `<root>/.psl/audit/day_manifest.json` | 日锚：每日文件的字节大小 + 末行 hash（链外副本，用于检出尾部删除） |
| `<root>/.psl/audit/sidecar/YYYY-MM-DD.<pid>.jsonl` | **v1.2**：锁竞争超时的降级记录（自带 `chain:"unlocked"` 标记；单写者文件；经 `--fold-sidecars` 显式并链后改名留档） |
| `<root>/.psl/audit/YYYY-MM-DD.jsonl.gz` | 过期归档（`report.py --archive`，默认 30 天） |
| 宿主镜像目录（如 `~/.workbuddy/antinel-audit/`） | 关键 allow 事件的宿主级副本（项目目录被删时证据仍在） |

## 2. 链字段（每条链上记录必备）

| 字段 | 含义 |
|---|---|
| `prev` | 前一条记录 hash 的**末 16 位**（首条为 ""） |
| `hash` | `sha256(prev + canonical_json(record 去掉 hash 字段))`，canonical = `sort_keys=True, separators=(",", ":")` |
| `chain` | 仅在降级时出现：`"unlocked"` = 锁竞争超时写入（**v1.2 起该记录落 sidecar，不进主链**；并链时重算 prev/hash，原记录体不变） |

**例外（历史遗留）**：`session_start` 心跳记录目前为**无链直写**（见 §4）。无 `hash` 的记录不参与链校验，也不破坏链（verify_chain 跳过无 hash 行）。

**锁协议**（v1.2 起为锁文件内容契约 `{pid, ts, token}`，偷锁前存活探测、释放前 token 匹配）属实现语义，见《Antinel v0.28 条款·链并发语义 v2》；本模式只约束其在记录上的可见后果。

**复核入口**：`tools/verify_chain.py <audit_dir>`（逐条链校验 + 日锚对照，`--json` 机器可读，`--all` 含历史日）。任何第三方拿到审计目录即可复算全部 hash。

## 3. 公共字段

| 字段 | 出现于 | 含义 |
|---|---|---|
| `ts` | 全部 | 本地时间 ISO8601（秒精度） |
| `type` | 全部 | 记录类型（§4 枚举） |
| `tool` | 多数 | 工具名（pre 侧为宿主原名；规则匹配用 canonical 名：MultiEdit→Edit、NotebookEdit→Write、ApplyPatch→Edit、Task→Agent） |
| `session` | 多数 | 宿主会话 id；`"banner"`=心跳伪会话 |
| `host` | 多数 | 宿主标签（claude-code / zcode / workbuddy / generic …） |
| `input.command` | pre/post | 命令文本，**经 mask_secrets 脱敏、截断至 500 字符** |
| `input.file_path` | pre/post | 目标路径（脱敏后原文保留） |
| `input.content_len` | pre | 内容长度（只记长度，不记内容） |
| `content_digest` | pre/post | `sha256(canonical_json({tool_name, tool_input}))` — **pre↔post 配对键**（两侧同配方，spec 2.8） |

## 4. 记录类型枚举

### 决策类

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `pre_tool_use` | pre | `rules_hit[]`, `severity`, `action(block/alert/allow)`, `decision`, `file_state_before` | 每次调用一条；`file_state_before` 为 **0.22.0 (C1)** 新增：写工具（Write/Edit）目标文件的写前状态 `{hash, size}` / `{hash:"absent"}` / `{hash:"too_large",size}` / `{hash:"unreadable"}`（>1MB 只记尺寸；被拦截的尝试同样记录——"对什么状态发起过写入"本身就是证据） |
| `pre_tool_use_summary` | pre | `rules_hit`, `decision` | 决策摘要行（各决策记录之外的一条汇总） |
| `post_tool_use` | post | `response_digest`, `response_chars`, `rules_hit`(OUT-01), `sensitive_output[]`, `canaries_observed[]`, `exit_code`, `file_state_after` | `exit_code` 为 **0.22.0 (B1)**：宿主暴露的数字退出码，取不到为 `null`（**缺失不造假**）；`file_state_after` 为 **0.22.0 (C1)**：写后状态，与 `file_state_before` 经 `content_digest` 配对。**时长 = post.ts − pre.ts，由 report 层派生，钩子不记** |

### 会话与心跳

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `session_start` | banner | `reason` | SessionStart 心跳（**无链直写，历史遗留**） |
| `hook_alive` | pre | — | 当日首次调用的心跳 |
| `session_dna` | report / banner | 见 §5 | **0.22.0 (A5)**：会话汇总，链上记录 |

### 释放留痕类（"放行必须留痕"）

| type | 来源 | 说明 |
|---|---|---|
| `workspace_root_allow` | pre | 因 `workspace_roots` 而放行的本应拦截项（记 `matched_root`、`config_source`） |
| `exclude_patterns_allow` | pre | 因规则 `exclude_patterns` 放行的 critical 命中（宿主级镜像） |
| `dst02_path_whitelisted` | pre | 因 `whitelist.paths` 放行的 DST-02 |
| `dst02_host_config_self_maintenance` | pre | Antinel 自身宿主级配置的自我维护写入 |
| `dst02_bash_path_suspect` | pre | Bash 命令文本中出现根外绝对路径（**提醒不拦截**） |
| `workspace_config_rejected` | pre | 被拒绝的 workspace_roots 配置（含拒绝原因） |

### 资源账本类（0.23.0）

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `usage_delta` | post | `source{path_tag, scope, reset, bytes_read, deduped, usage_source}`, `entries[]` | **token 事实**。每次从 transcript 增量收割到新条目时追加一条（收割不到就不写，不写空记录）。`entries[]` 元素：`{ts, model, input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens, total_tokens, id}`——全部为宿主 transcript 中的原始数值（缺字段为 null，不补 0、不推算）。`path_tag` = transcript 路径的 sha256 前 16 位（**路径原文不进账本**，只存在本地 `.psl/state/usage_offsets.json`）；`scope` = incremental / tail_first_sight；`reset`=true 表示 transcript 文件变小后重读（重叠条目按指纹去重，`deduped` 计数）。**成本永不写入此记录**——token 是事实，成本是派生物 |

### 错误类

| type | 来源 | 说明 |
|---|---|---|
| `hook_error` | pre | 钩子内部异常（fail-open，宿主不受影响） |

## 5. `session_dna` 字段表（0.22.0）

| 字段 | 含义 |
|---|---|
| `session`, `generated_at`, `generated_by` | 会话 id；生成时间；`report.py` 或 `session_start_rollup` |
| `coverage` | `{days:[日文件名], records:N, truncated:bool}`（banner 补算只扫最近 2 日 / 64MB） |
| `span` | `{first, last}` 该会话首末记录 ts |
| `actions` | `{total, by_tool{}}` — pre_tool_use 计数 |
| `blocks` | `{total, by_rule{}}` — 拦截计数与规则分布 |
| `warnings` | `{total}` — alert 计数 |
| `files` | `{touched_unique, top:[{path,count}×5]}` — 去重触碰文件与 Top5 |
| `durations` | `{pairs, median_ms, p95_ms}` — **content_digest 配对**的 pre/post 时长（同调用、pre≤post、<1h；重试按序配对） |
| `exits` | `{observed, nonzero}` — 有退出码的 post 记录数 / 其中非零数（null 不计入 observed） |
| `usage` | **0.23.0**：`{entries, by_model{model:{entries,input,output,cache_read,cache_creation,total}}}` — usage_delta 的聚合（**事实**） |
| `usage.cost_estimate` | **0.23.0**：`{currency, total, by_model{}, pricing_version, unpriced_models[]}` — **派生物**，仅当调用方提供 pricing 表时出现；rates 缺失的模型进 `unpriced_models`，**永不代估**。`pricing_version` 回指 `rules/pricing.json` 的 version |

生成原则：**DNA 只聚合链上已有记录，不推断、不评分**；成本只按调用方提供的定价表派生并永远标 estimate；`report.py --session <id> [--write-dna]`，补算写入走与全部记录相同的链配方（verify_chain 全覆盖）。

## 6. 隐私与边界（本模式"不记什么"）

- 不记文件内容、不记 diff——只有 sha256 与字节数（C1 亦然）。
- 命令文本脱敏（密钥/token 掩码）后截断 500 字符。
- 不记网络出站字节（钩子看不见；DST-02 类同，见 THREAT_MODEL Non-goals）。
- 成本/token 消耗（三问三答 A 族）**尚未进入账本**——`transcript_path` 已随事件到达但 v0.22.0 未使用，属 v0.23.0 范围。
