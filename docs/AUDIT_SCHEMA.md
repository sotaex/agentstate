# AUDIT_SCHEMA.md — Antinel 审计记录模式 v1.10（随 v0.37.0）

> v1.10（0.35.3）：新增**公共可选字段 `recovered`**（布尔）——"这条记录描述的事
> **已经自己愈合、没有留下后果**"。首用点：`host_shield_tamper` 的
> workspaces/zones/windows 回写恢复类。★ 为什么要它：这类记录此前**只能靠读
> `reason` 文案里的"已回写恢复"四个字**来区分"真出事了"和"防线自己扛住了"，
> 而按文案判档正是本仓明令禁止的形状（文案会改，判据会静默失效）。
> 同时补登记 `policy_changed` 的 `field` 取值域（`zones` / `workspaces` /
> `windows` / `roots` / `paths` / `domains` / 预算项 …）—— 门闸的**链背书判定**
> 按它取字段，取值域属于契约的一部分。
>
> v1.9（0.33.1）：新增「归因与边界类」三条 —— `host_tag_uncertain`（归因自动取证）、
> `hook_slow`（慢到超时的留痕）、`probe_used`（探针使用留痕，落 sidecar）。

> 本文是 `.psl/audit/` 下每一条记录的**字段级契约**，供第三方独立复核。
> 原则：**记录里只有事实与指纹，没有内容、没有评分**。任何字段语义变更必须 bump 本文档版本并在变更说明中登记。
> v1.1（0.23.0）：新增 `usage_delta` 记录类型（token 事实）；`session_dna` 新增 `usage` 块（聚合与**派生**成本估算）。
> v1.2（0.28.0）：**降级记录迁移至 sidecar**——`chain:"unlocked"` 的记录不再写入主链，改写 `audit/sidecar/<日>.<pid>.jsonl`（单写者文件）；主链从此只含按锁定协议成链的记录。依据：《v0.28 条款·链并发语义 v2》C-2/C-3（葛广 2026-09-21 确认）；动机：Gauntlet 实证 unlocked 直写主链与持锁写相撞会产生与篡改同形的分叉。
> v1.3（0.28.0）：**补登记门闸事件族**（`host_shield_*` 共 6 类，见 §4 门闸类）。此前代码已写入**同一条链**而本文未登记 —— §4 自称"枚举"，缺登记即契约不成立。依据：《Antinel 门闸自检两处缺口取证（fail-open ＋ 未登记事件）（2026-09-24）》F2。
> v1.4（0.28.1）：门闸事件族新增 `host_shield_revived`（哨兵死亡后被 paramedic/CLI 重新拉起）与 `host_shield_spawn_failed`（拉起失败＝门闸无人值守的显式证据）；`host_shield_changed` 增补 `autostart`（schtasks / startup-folder / none）与 `spawn`（ok / failed）两个字段。依据：同日《哨兵死因取证》（重建丢 `__main__` 入口、schtasks rc 未查、会话 Job 连带杀、`-I` 下留痕全聋）。
> v1.5（0.28.3）：门闸事件族新增 `host_shield_tamper`（状态文件/登记表/自身代码与审计链或 manifest 不符——B4b/b2/c/d、B4e/f 类"无声开关"的显式证据）；`host_shield_changed` 增补 `armed` 布尔字段（enabled 翻转后的权威值，哨兵据此链权威执法）；`host_shield_breach` 的语义从三种扩为四种（新增④心跳陈旧且旧进程镜像异常，拒绝自动重启）。依据：同日《哨兵绕过办法全谱与根方案对照 v1.0》。
> v1.6（0.29.0）：**补登记 6 个早已写入同一条链、但本文从未登记的事件类型** —— `dst11_syncdir_released`（新增）、`rules_integrity_fallback`、`rules_unreadable_fallback`、`policy_changed`、`credits_snapshot`、`digest_rollup`。同时把抬头版本从 v1.3 修正到 v1.6（抬头落后两版：v1.4/v1.5 的变更说明已写在正文，标题却一直没改）。
> v1.6a（0.29.0，同日）：**门闸族再补登记 2 类** —— `host_shield_lock_held`、`host_shield_contested`（见 §4）。这两类是 v1.3 补登记门闸族时**漏掉的**：v1.3 的变更说明自称"共 6 类"，而代码里实际有 13 类，两处一直没有对齐。**发现方式＝同一道 INV-6**（严格测试的 257 条断言里，`F-10 门闸事件类型全部登记于 AUDIT_SCHEMA.md（11 类）` 报 `未登记: ['host_shield_contested', 'host_shield_lock_held']`）。
> v1.7（0.30.0）：**E-3 关闭的两半上链** —— 新增 `enforcement_gap`（post：宿主把"已拦截"的调用真的执行了＝deny 信号未被尊重的**真实流量证据**）与 `enforcement_probe`（tools/enforce_probe.py：合成必拦事件、验证全部下发通道的**主动自检**）。同时 `hook_alive` 与 `pre_tool_use_summary` 增补三个可选字段：`antinel_version`、`host_version`（宿主在事件里带 version 才有值，**缺失不造假**）、`deny_mode`（当前武装的 deny 契约：dual/legacy/quiet）。依据：THREAT_MODEL E-3——"拦截"必须拥有自己的证据，而不是只在钩子的决定里存在。
> v1.8（0.31.0）：**指令面/供应链/金丝雀/自移除** —— 新增 `canary_planted`（antinel canary plant：金丝雀布置/复用的事实记录，标记本身由 post 侧 canaries_observed 观察半边接管）与 `antinel_uninstall`（install.py --uninstall：**护栏自我移除在删除动作之前**的 critical 留痕，宿主级镜像强制；purge 会删项目副本、镜像保证据）。配套规则族：MCP-01..04（MCP 供应链，命中走既有 pre_tool_use 记录，不新增类型）、SEC-11（读金丝雀 → alert，故意不拦——拦下就看不到外传链路）。
> ★ **教训（第三次同一类）**："补登记"如果只按**手写清单**补，就会漏；只有**扫代码写出的 type**才对得上。v1.3 是手写清单补的，所以漏了 2 个；v1.6 的另外 6 个是 INV-6 扫出来的，所以齐了。**没对象的检查项＝假守卫；有对象的检查项才补得齐。**
> **依据（本条的来源就是一次自查）**：`antinel_verify.py --invariants` 的 INV-6 用正则扫出"代码写入的 type ∉ 本文登记"，一次跑出 7 个未登记项。**这正是本项目的契约纪律：「没登记 ≠ 不存在」**——链上写着一个类型，而随包契约里没有它，第三方复核时就无从知道那个字段是什么意思。**现在 INV-6 是一道会红的守卫**，不是一句口号。

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
| `recovered` | 可选（v1.10 起） | **布尔**。`true` ＝ 本条描述的事**已经自动愈合、没有留下后果**（例：`host_shield_tamper` 的 state 回写恢复类——防线把被改的配置回滚回去了，用户配置与执法状态均未受损）。★ **是结构化字段，不是文案**：消费者（值守台分档、日报）必须读它，**不许解析 `reason` 里的"已回写恢复"**。字段缺省 ⇒ 语义＝"未知"（按"有后果"处理，方向收紧） |

## 4. 记录类型枚举

### 决策类

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `pre_tool_use` | pre | `rules_hit[]`, `severity`, `action(block/alert/allow)`, `decision`, `file_state_before`, `released[]` | 每次调用一条；**`released[]` 为 0.29.0 (D-1) 新增**：本次调用中**命中了但被 `whitelist.paths` 放行**的规则 id 列表（无放行时该字段不存在）。★ 有它，`rules_hit=[]` 才有唯一解释（真的没命中），而不是被"放行"冒名顶替；`file_state_before` 为 **0.22.0 (C1)** 新增：写工具（Write/Edit）目标文件的写前状态 `{hash, size}` / `{hash:"absent"}` / `{hash:"too_large",size}` / `{hash:"unreadable"}`（>1MB 只记尺寸；被拦截的尝试同样记录——"对什么状态发起过写入"本身就是证据） |
| `pre_tool_use_summary` | pre | `rules_hit`, `decision`, `antinel_version`, `host_version` | 决策摘要行（各决策记录之外的一条汇总）。**0.30.0 (E-3)**：`antinel_version`＝钩子包版本；`host_version`＝宿主事件自带的 version 字段（缺失为 null，**缺失不造假**） |
| `post_tool_use` | post | `response_digest`, `response_chars`, `rules_hit`(OUT-01), `sensitive_output[]`, `canaries_observed[]`, `exit_code`, `file_state_after` | `exit_code` 为 **0.22.0 (B1)**：宿主暴露的数字退出码，取不到为 `null`（**缺失不造假**）；`file_state_after` 为 **0.22.0 (C1)**：写后状态，与 `file_state_before` 经 `content_digest` 配对。**时长 = post.ts − pre.ts，由 report 层派生，钩子不记** |
| `enforcement_gap` | post | `content_digest`, `rule_ids[]`, `blocked_at` | **0.30.0 (E-3)：执法缺口——真实流量证据**。本条存在即说明：pre 侧对同一 `content_digest` 写过 `decision=block`，而宿主**还是把这次调用执行了**（post 记录存在本身就是执行证据）⇒ deny 信号（exit 2 / stdout 契约）未被尊重。配对取**最近一条**同 digest 的 pre 记录且限 1 小时窗口（旧拦不缠新放）。`rule_ids` 为被拦时的规则；`blocked_at` 为原 pre.ts。这是"闸门已死"的显式证据，晨报必现 |
| `enforcement_probe` | tools/enforce_probe.py | `probe`, `expected`, `got`, `exit_code`, `stdout_channel`, `deny_mode`, `ok`, `antinel_version`, `duration_ms` | **0.30.0 (E-3)：主动自检——信号半边的关闭**。合成一个必拦事件（Read `__antinel_probe__.env` → SEC-01）跑**真钩子**，断言全部下发通道：exit 2、stdout 契约（`hookSpecificOutput.permissionDecision="deny"`）与/或 legacy 键（按宿主与 `deny_stdout` 模式；ZCode 严格 stdout 模式下断言 stdout 为空）。探针模式钩子**零副作用**（不写普通审计、不通知主人、绕过策略白名单——探针测的是引擎与通道，不是用户的放行配置）。`ok=false`＝信号半边失效，晨报必现并通知主人。★ **它证明不了宿主会尊重信号**——那一半由 `enforcement_gap` 的真实流量检测覆盖；两半合起来才是 E-3 的闭合 |

### 会话与心跳

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `session_start` | banner | `reason` | SessionStart 心跳（**无链直写，历史遗留**） |
| `hook_alive` | pre | `antinel_version`, `host_version`, `deny_mode` | 当日首次调用的心跳。**0.30.0 (E-3)**：三个可选字段（宿主 version 缺失为 null，**缺失不造假**）让账本自己记录"哪天、哪个版本、什么 deny 契约在岗" |
| `host_changed` | post | `from_version`, `to_version` | **0.32.2 (A1)**：宿主版本变化时上链（宿主在事件中带 version 才触发；两版本相同不重复）。W2 对冲：宿主升级是钩子协议漂移的头号来源，此记录让漂移在晨报可见 |
| `session_dna` | report / banner | 见 §5 | **0.22.0 (A5)**：会话汇总，链上记录 |

### 释放留痕类（"放行必须留痕"）

| type | 来源 | 说明 |
|---|---|---|
| `workspace_root_allow` | pre | 因 `workspace_roots` 而放行的本应拦截项（记 `matched_root`、`config_source`） |
| `exclude_patterns_allow` | pre | 因规则 `exclude_patterns` 放行的 critical 命中（宿主级镜像） |
| `dst02_path_whitelisted` | pre | 因 `whitelist.paths` 放行的 DST-02 |
| `dst02_host_config_self_maintenance` | pre | Antinel 自身宿主级配置的自我维护写入 |
| `dst02_bash_path_suspect` | pre | Bash 命令文本中出现根外绝对路径（**提醒不拦截**） |
| `dst11_syncdir_released` | pre | **0.29.0 (G-8)**：写进云盘同步目录、被 `whitelist.paths` 放行。单独命名（不并入 `dst02_path_whitelisted`），因为"放行了一次写进同步文件夹"与"放行了一次写项目外"是两件不同的事——同步客户端**仍然会把文件传上云**。记 `input.file_path` |
| `workspace_config_rejected` | pre | 被拒绝的 workspace_roots 配置（含拒绝原因） |
| `sec_path_whitelisted` | pre | **0.29.0 (D-1)**：命中了 secrets 规则（读 .env / SSH 私钥 / 云凭证 / 微信本地库 …）但被 `whitelist.paths` 放行。单独命名（不并入 `dst02_path_whitelisted`），因为"放行一次读敏感文件"与"放行一次写项目外"是两件不同的事。记 `rule_id`、`input.file_path`、`input.command`。★ **这是全仓最后一个静默放行通道**：在此之前该放行**不写任何记录**，于是账本上它与"压根没命中任何规则"逐字段相同（`rules_hit=[]`、`severity="none"`），事后复盘无从区分——**判据④「'没查'被伪装成'没发现'」的同型：此处是「被放行」被伪装成「没命中」** |

### 降级与配置变更类（v1.6 补登记）

> ★ 本组此前**代码已在写、本文未登记**（v1.6 补）。补登记的依据是"没登记 ≠ 不存在"：
> 链上有这个类型，随包契约里就必须有它的字段语义，否则第三方复核无从下手。

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `rules_integrity_fallback` | pre | `expected`, `live`, `rules_loaded` | `rules/default.json` 与 manifest 的 `rules_hash` 不符 ⇒ 判定为篡改，**退回内置兜底规则集**并大声记账（A4）。`expected`/`live` 是两侧哈希，供复核 |
| `rules_unreadable_fallback` | pre | `error`, `rules_loaded` | 规则文件**读不出来**（缺失/坏 JSON/无权限）⇒ 退回内置兜底集。与上一条**分开命名**：`tampered` 与 `unreadable` 是两种不同的失败，不能合并成一条 |
| `policy_changed` | antinel CLI | `change`, `field`, `old_sha256`, `new_sha256`, `invoked_by` | `.psl/policy.json` 被 CLI 改写（白名单/阈值/档位）。每一次都记，因为**放行范围因此改变**。**v1.10 补登记 `field` 取值域**：`zones` / `workspaces` / `windows` / `roots` / `paths` / `domains` / 预算与限额项 …。★ 门闸的**链背书判定**按 `field` 取字段（`host_shield._backing_field()`）——`field=zones` 的记录才替 `host_shield.json` 的 `zones` 变化背书。**改这个取值域＝改门闸的判据**，必须同步改 `_BACKING_TYPES` 的守卫 |
| `credits_snapshot` | antinel CLI | 余额快照 | 用户登记的积分余额事实（`antinel credits snapshot`）。**是事实记录，不是估算** |
| `digest_rollup` | antinel CLI | 汇总 | 日报/汇总层生成的滚存记录 |

### 资源账本类（0.23.0）

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `usage_delta` | post | `source{path_tag, scope, reset, bytes_read, deduped, usage_source}`, `entries[]` | **token 事实**。每次从 transcript 增量收割到新条目时追加一条（收割不到就不写，不写空记录）。`entries[]` 元素：`{ts, model, input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens, total_tokens, id}`——全部为宿主 transcript 中的原始数值（缺字段为 null，不补 0、不推算）。`path_tag` = transcript 路径的 sha256 前 16 位（**路径原文不进账本**，只存在本地 `.psl/state/usage_offsets.json`）；`scope` = incremental / tail_first_sight；`reset`=true 表示 transcript 文件变小后重读（重叠条目按指纹去重，`deduped` 计数）。**成本永不写入此记录**——token 是事实，成本是派生物 |

### 证据标记类（0.31.0，v1.8）

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `canary_planted` | antinel CLI | `marker`, `path`, `note` | **0.31.0 (F3)**：金丝雀布置/复用的事实记录（`antinel canary plant`；`note` ∈ planted/already）。蜜饵文件在 `<root>/.canary/CANARY-<slug>-<8hex>`；**观察半边不在本记录**——agent 读取金丝雀由 SEC-11 alert 留痕，标记出现在工具输出由 post 侧 `canaries_observed` 接管并进 report 统计 |
| `antinel_uninstall` | install CLI | `removed_hooks`, `purge`, `settings_file` | **0.31.0 (F4)：护栏自我移除的 critical 留痕**（`install.py --uninstall`）。在任何删除动作**之前**写入；purge 会删掉项目侧副本，**宿主级镜像强制**（证据不随 purge 消失）。卸载是用户权利——留痕失败不拒绝卸载（fail-open），stderr 可见 |

### 错误类

| type | 来源 | 说明 |
|---|---|---|
| `hook_error` | pre | 钩子内部异常（fail-open，宿主不受影响） |

### 归因与边界类（0.33.1，v1.9 补登记）

> 0.33.1 新增的三条都服务于同一条纪律：**归因与边界不能靠猜，也不能沉默**。
> 前两条让"宿主是谁"变成可复核的证据，第三条让"探针被用过"留下痕迹。

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `host_tag_uncertain` | pre | `host_evidence{source,key,markers_seen,cwd,confidence}`, `decision="allow"`, `severity="info"` | 宿主归因**什么都没命中**（env 键与目录标记全落空）时写入。★ 这是**自动取证**：TRAE / Qoder 国际版之类"需要真机证据"的宿主，只要被任何人跑一次，线索就自动落到链上 —— 不必再埋探针、不必等创始人重启 |
| `hook_slow` | pre | `elapsed_ms`, `input_sizes`, `severity="warning"` | 钩子耗时 ≥ `SLOW_BUDGET_MS`（默认 8000）时写入。★ 宿主给钩子的超时是 10s(zcode)/15s(claude)，**超时=allow** ⇒ 慢到超时等于这张牌没打出去且无人知晓。实测（本机，5MB 输入）median 19,473ms 已越过两条线 |
| `probe_used` | pre | `tool`, `session`, `host`, `reason` | `ANTINEL_PROBE=1` 时写入，**落 sidecar 而非主链**。`audit/sidecar/<日>.probe.jsonl`。★ 探针仍会跳过主链写入（语义不变），但"谁在什么时候用过探针"从此有据可查 —— 防不住，就让它可检测 |

### 门闸类（host-shield，v1.3 补登记；v1.4 增补）

> 由 `host_shield.py` 哨兵与 `antinel.py host-shield enable/disable` 写入**与上表同一条链**。
> ★ 门闸**默认关闭**（须 `antinel host-shield enable` 才布防）；未布防时链中不出现本族记录。
> 本族 `session` 固定为 `"host-shield"`、`tool` 固定为 `"-"`、`host` 固定为 `"generic"`（见 §3 公共字段）。

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `host_shield_zone_locked` | 哨兵 | `decision="deny"`, `reason`(含路径) | 安全区（zone）已上锁：区内防篡改；出网另由 `net_mode` 把闸 |
| `host_shield_breach` | 哨兵 | `decision="deny"` | **门闸异常**四种：① 自启缺失（计划任务与启动文件夹均无，`#6`）② 发现未拦的外传落盘点并补锁（补锁失败时 severity=critical）③ 发现符号链接（绕过载体）④ 心跳陈旧（疑似挂起/僵死）且旧进程镜像异常，拒绝自动重启 |
| `host_shield_task_unknown` | 哨兵 | `decision="alert"` | **v1.3 新增**：无法确认计划任务状态（`schtasks` 不可用／被策略拦截／超时）。★ 与 `breach` **分开记** —— **"查不出来"不是"查到了是坏的"**；此前该情形被 fail-open 吞成"已安装"，导致 `breach` 永不触发 |
| `host_shield_window_closed` | 哨兵 | `decision`, `reason` | 放行窗到期关闭 |
| `host_shield_heartbeat` | 哨兵 | `decision="allow"`, `watched`(登记路径数) | 哨兵心跳（门闸在岗），每 `HEARTBEAT_SECONDS` 一次；**断档由晨报/`host-shield status` 呈现**（v1.4 起） |
| `host_shield_changed` | `antinel.py` | `decision="allow"`, `severity="warning"`, `field`, `change`, `invoked_by`, `autostart`, `spawn`, `armed` | 门闸被 enable／disable；`change` 为 `"false → true"` 形式。**v1.4 增补**：`autostart` ∈ schtasks / startup-folder / none（自启注册的真实结局，不假成功）；`spawn` ∈ ok / failed（哨兵本次是否真的拉起来了）。**v1.5 增补**：`armed` 布尔＝翻转后的权威值——哨兵对 enabled 的执法以链上本字段为准（B4b 系"无声开关"的闭合） |
| `host_shield_revived` | 哨兵/paramedic | `decision="allow"`, `pid`, `cause`, `spawn_mode` | **v1.4 新增**：哨兵死亡后被重新拉起（钩子 paramedic 或 CLI）。复活记录本身就是"此前有断档"的证据 |
| `host_shield_spawn_failed` | 哨兵/paramedic | `decision="deny"`, `severity="critical"`, `cause` | **v1.4 新增**：哨兵死亡且拉起失败——门闸无人值守的显式记录（此前该状态只存在于沉默里） |
| `host_shield_tamper` | 哨兵 | `decision="deny"`, `severity="critical"`, `field`, `reason`, `recovered` | **v1.5 新增**：本地配置与权威依据不符——state 文件 `enabled` 与链不一致（B4b/b2/c/d）；workspaces/zones/windows 无链背书被改并已回写恢复；启动自检发现运行代码/登记表与 manifest 不符（B4e/f）。执法按链/按已知值继续，绝不因文件被改而静默停摆。**v1.10**：`field="state"` 的回写恢复类**必须带 `recovered=true`**（防线已自愈、无后果）；`reason` 增补"哪个字段从什么变成什么"（`host_shield._fp_diff_txt()`）——旧文案只说"workspaces/zones/windows 被修改"，**不说改了哪个**，事后无法定位真因（2026-10-06 就是靠翻全链邻居才认出真因） |
| `host_shield_lock_held` | 哨兵 | `decision="deny"`, `severity="none"`, `reason`(含路径) | **v1.6a 补登记**：门闸**持锁中**的周期性状态留痕（每 `LOCK_HELD_EVERY` 一次，`lock_held_at` 去重）。★ 与 `breach` **分开**：锁**在**是正常态，不该只在"出事"时才出现在账本上 —— 旧机制下 `if is_denied(...)` 为真就**整支跳过**，于是"锁挂了两个月、账本一字不提"（09-25/26 审计只剩心跳、零 breach） |
| `host_shield_contested` | 哨兵 | `decision="deny"`, `severity="critical"`, `reason`(含路径与补锁次数) | **v1.6a 补登记**：同一落点在 `CONTEST_WINDOW` 内被补锁 ≥ `CONTEST_TIMES` 次 —— 上锁**未稳定生效**或**有进程在对抗门闸**，须人工介入。★ 与 `breach` 的分工：`breach` 是"发现未拦的落点"（第 1 次，且明说"不等于有进程在对抗"），本类是"补锁反复不生效"（第 N 次） |

**本族不记什么**（与 §6 同源）：不读密文内容（红线 A3）；不记被拦文件的字节；`reason` 中的路径为脱敏后原文。

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
