<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# AUDIT_SCHEMA.md — Antinel 审计记录模式 v1.26（随 v0.62.1）

> v1.26（0.62.0）：**字段拆义，不新增记录类型** —— `notice_budget_window_closed`
> 新增 `bucket`，`rule_id` 语义收紧为「只放真规则号」。此前 `rule_id` 直接写
> `notice_gate()` 的第一个参数，而该参数既装真规则号（`SLOP-01`）又装**分桶 key**
> （`DST-02-BASH` —— 同一规则 `DST-02` 的 Bash 提醒通道）⇒ 账本里出现 390 条
> 「规则库里没有的规则号」，看起来像第 38 条规则，实际是分桶名占了字段名。
> **不改**已有字段名（`rule_id` 保留）、**不改**已有取值域（新取值只会更窄）、
> **不改** append-only 契约。**历史记录不追溯**：读旧记录按 `bucket` 取旧口径。
> ★ 起因：37 条 × 新编号对照时把 `DST-02-BASH` 误判成「第 38 条幽灵规则」，
> 读代码才发现是字段语义混装（铁律 44「同值不同义」）。
>
> v1.25（0.60.0）：**补登记 2 类** —— `rules_auto_refresh_skipped`、
> `autostart_no_window_fixed`（均见下文「降级与配置变更类」），并把
> `rules_snapshot_refreshed` 的**触发者**
> 从「只由 CLI 写」扩到「钩子加载前 / 守护进程每 tick / CLI」三处同一实现。
> ★ 起因（创始人 2026-10-27）：「既然系统更新，那肯定是全面更新，包括规则的更新。」
> 以及「任何类型的闪出黑窗都是不可接受的」。
>   实测：`pip install -U` 只换包、不跑 install ⇒ 项目内的规则副本永久停在首次
>   安装那一版（包内 0.59.0 / 副本 0.58.0，一个版本区间的规则修正一条都没生效），
>   而包与副本两侧都自认正常。现在副本落后就自动补齐。
> ★ 为什么单独立 `rules_auto_refresh_skipped`：自动刷新有一条硬红线 ——
>   **副本被手工改过（哈希 ≠ manifest 登记值）就不覆盖**。覆盖一份被改过的防护
>   依据，等于把篡改证据连同问题一起抹掉，比不修更坏。所以"该刷而没刷"必须是
>   一条**记录在案**的事件（`severity=critical`），而不是一次沉默的跳过。
> **不改**已有字段名、**不改**已有取值域、**不改** append-only 契约。

> v1.24（0.59.0）：**补登记 1 类** —— `host_shield_state_unreadable`
> （见下文「门闸事件族」）。
> ★ 它记的是**盲区**，不是篡改：安全状态文件这一刻读不出来（另一个进程正在
> 原子替换，或文件半写/损坏）。旧口径把这种"没读到"当成"读到了一份已撤防的"
> （`load_state()` 的历史口径），于是每一拍都判成 `host_shield_tamper` ——
> 盘上实测：一整天 `field=enabled` 的 tamper 记录里，文案反复写
> 「实际值（**None**）」，而 None 不是任何人的写入值，它是"这份 state 里
> 根本没有这个键"。**把盲区读成篡改，会让每一次读抖动都变成一次告警。**
> ★ 定档 **L0**（记进账、页面可见、不弹任何窗）：它会自己收敛，不该敲门；
> 但"不敲门"不等于"健康"——它在页面上仍是**盲区**，不是清白。
> **不改**已有字段名、**不改**已有取值域、**不改** append-only 契约。

> v1.23（0.57.2）：**补登记 1 类** —— `rules_snapshot_refreshed`
> （见下文「降级与配置变更类」）。由 `python scripts/install.py --refresh-rules`
> 写入：把项目里的规则副本刷成包内那一版，**同时**更新 manifest 的 `rules_hash`。
> ★ 必须登记的理由（不是形式）：这条记录改的是**门闸判定所依据的那份规则**——
> 改了防护依据却不留痕，等于给自己开一条静默后门；而不登记则第三方复核时
> 认不出这笔记录，与"压根没发生"逐字段相同。
> ★ 抓到它的判据：`scripts/verification_tests.py` 的 **F-10**（代码里的事件类型
> 50 类 vs 本文登记表，缺一个就红）。本次是**先写代码后补登记**，F-10 当场咬住。
> **不改**已有字段名、**不改**已有取值域、**不改** append-only 契约。

> v1.22（0.54.0）：**补登记 2 类** —— `delivery_unknown`（见下文「通知送达类」）
> 与 `gap_fixed`（见下文「缺口生命周期类」）。
> **不改**已有字段名、**不改**已有取值域、**不改** append-only 契约。
> ★ 两者是**同批**登记的，理由写在冻结件 §2-F7：分开登就会出现「一半在条约里、
> 一半只在代码里」的窗口期，而窗口期内的记录无法被第三方按 schema 复算。
> ★ `delivery_unknown` **有真生产者**（`inbox_notify.settle`，N12 送达兜底链）；
> `gap_fixed` **当前无生产者** —— U4 的「我修好了」按钮还没接线。本条登记的是
> 类型存在性与字段语义，**不是**「链上已有记录」（与 `credits_low` 的登记同型）。
> ★ 为什么必须补：0.40.0 与 0.51.2 两次同型事故（只写代码不写 schema ⇒
> `tools/verify_event_types.py` 当场判「未登记」，harness F-10 红）。
>
> ——— 以下为 v1.22 之前的登记说明（保留原文，零删除）———
> v1.20（0.53.0）：**补登记 1 类** —— `exam_reminder`（见下文「体检提醒类」）。
> 语义：该做体检了（装好 ≥24 小时没做过／上次体检过去很久），**L1** 级。
> **不改**已有字段名、**不改**已有取值域、**不改** append-only 契约。
> ★ 为什么必须补：0.53.0 的 T1.3 把它写进 `inbox_model.LEVEL_OF_KIND`／`TITLE_OF_KIND`
> 并有了**真生产者**（`host_shield.exam_reminder_check`），却没同步 schema ——
> 与 0.40.0、0.51.2 那次完全同型（只写代码不写 schema ⇒ `tools/verify_event_types.py`
> 当场判"未登记"，harness F-10 红：实测 `未登记: ['exam_reminder']`）。
>
> ——— 以下为 v1.19 的登记说明（保留原文，零删除）———
>
> v1.19（0.51.2）：**补登记 1 类** —— `credits_low`（见下文「降级与配置变更类」）。
> **不改**已有字段名、**不改**已有取值域、**不改** append-only 契约，只**新增一个记录类型**。
> 语义：缺粮事件（积分余额偏低），**Ls** 级；是徽标「缺粮」的**第二个来源**
> （存在未关闭的 `credits_low` 记录即亮徽标，`inbox_model.badges`）。
> ★ **当前无生产者** —— 没有任何产品代码路径写它（链上暂无此类型记录）；
> 本条登记的是**类型存在性与字段语义**，不是"链上已有记录"。
> ★ 与 `credits_snapshot` 是两件事：一个是**告警态**（余额偏低），一个是**事实快照**
> （用户主动登记的余额，`antinel credits snapshot`）。
> ★ 为什么必须补：0.51.0 把该类型写进 `inbox_model.LEVEL_OF_KIND`／`TITLE_OF_KIND`
> 时没同步 schema —— 与 0.40.0 那次同型（只写代码不写 schema ⇒ F-10 红）。
> 登记方式＝`tools/verify_event_types.py` 扫代码写出的 type。
>
> v1.18（0.47.0 登记、0.48.0 随版）：**提醒预算族新增 2 类** —— `notice_budget_merged`、
> `notice_budget_window_closed`（见下文「提醒预算类」）。**不改**已有字段名、
> **不改**已有取值域、**不改** append-only 契约，只**新增两个记录类型**。
> ★ 为什么必须新开一族：这两条是**限额类机制自己的留痕** —— 合并若只写
> `stderr`，在证据层面与「静默丢弃」**没有区别**（交接件 §2.1 ① 关键纪律）。
> 有了它们，"没被逐条说出来的那些条"才有唯一去处，守恒式
> `total == used + dup + merged` 才可被机械核对（`ci/inbox_guards_0470.py` 常驻）。
> 登记方式＝`tools/verify_event_types.py` 扫代码写出的 type。
>
> v1.17（0.46.0）：**释放留痕族新增 1 类** —— `command_deletion_permission`
> （见 §4 释放留痕类）。**不改**已有字段名、**不改**已有取值域、**不改** append-only
> 契约，只**新增一个记录类型**。语义：删除许可（VCT）两票裁决的**每一次**结论，
> 用 `subkind` 把四条路结构化（`vct_allow` / `vct_deny` / `fallback_allow` /
> `exit_乙`·`exit_丙`）。
> ★ 为什么必须新增而不是复用 `exclude_patterns_allow`（交接件 §7.4 + 方案 §3.5）：
> ① 两者是**不同判据**放的行（"用户声明＋可再生事实" vs "名字在兜底名单里"），
> 合并就分不清是哪条路生效；② 设计明写「四个退出口不许静默」——旧实现里
> 出口乙/丙 **一条记录都不写**，事后无从知道它走了哪条路（"静默是复发的温床"）。
> 登记方式＝`tools/verify_event_types.py` 扫代码写出的 type。
>
> v1.16（0.45.0）：**门闸族给 1 类记录加字段** —— `host_shield_state_write_refused`
> 增补 `subkind`（取值域 `refused` / `optimistic_lock_lost`），把"没保住"的**两种成因**
> 结构化（与 `host_shield_zone_locked` 的 zone_ok/zone_lock_failed 同一手法：写 side 分派）。
> **不新增**记录类型、**不改**已有字段名、**不改**已有取值域、**不改** append-only 契约。
> ★ 为什么必须加：0.45.0 给状态文件引入**乐观锁**（`_rev`）后，"写后版本号不符 ⇒ 被并发
> 覆盖"与"读不到 ⇒ 主动拒写"是**两个不同根因**；若共用一条记录、不区分，读者层无法分派
> （交接件 §4.3 甲层纪律：**写 side 把区分结构化**，别让读者去猜）。
> v1.15（0.44.0）：**模式无变化** —— 0.44.0 只改**命令判定语义**（赋值前缀不再
> 连坐整条命令），放行照旧记为**既有的**「豁免放行」记录类型，**不新增**记录类型、
> **不改**字段名与取值域。抬头随**代码版本**前移，模式号仍为 **v1.15**。
> v1.15（0.43.1）：**门闸族新增 1 类** —— `host_shield_state_write_refused`
> （见 §4 门闸类）。**不改**已有字段名、**不改**已有取值域、**不改** append-only
> 契约，只**新增一个记录类型**。
> 语义：`update_state_fields()` 这道"读不到就拒写"的保护**生效时**的留痕
> （`decision="deny"`, `severity="warning"`, `notify=False`）。它**不进**
> `host_shield._ALERT_KINDS`（是诊断，不是"要你动手"）⇒ **不弹气泡**。
> ★ 为什么必须单独记（交接件纪律 10.12 / §5.6「保护自报」）：这道保护静默生效时，
> 会让**依赖写成功的节流与记账一起失效**，症状就是"哨兵被反复拉起"（实测当天
> 19 次 `host_shield_revived`）。过去这里只有一句 `return False`，而三处调用点
> **全部忽略返回值** ⇒ 保护在起作用，却没有任何人能看见（"失效不可见"）。
> 登记方式＝`tools/verify_event_types.py` 扫代码写出的 type（本次首发即命中，
> 正是 v1.6 那条教训「只有扫代码写出的 type 才对得上」）。
>
> ★ 同版**收窄一处既有语义**（不改字段、不改取值域）：`host_shield_dev_drift` 与
> `host_shield_tamper` 的分界里，「**已出厂**」的定义从「登记版本 ≥ 代码版本」
> 收窄为「登记版本 ＞ 代码版本，**或**（登记版本 == 代码版本 **且**清单与工作树
> 逐字节相符）」。原因（实测）：`ci/version_check.py` 要求 10 处承载件逐字相同
> （`psl/manifest.json` 是其一）⇒ 升版**必然**把 manifest 的 version 刷成同号
> ⇒ 原口径下「研发态」**长期不可达**，合法迭代被自己的界面报成 R0「失守」。
> 判据 S67/N-S67/S68/N-S68（`ci/inbox_guards_0431.py`）常驻防复发。

> v1.13（0.42.0）：**`hook_slow` 补上消费侧**（P5-1）—— **不改**字段名、**不改**
> 取值域、**不改** append-only 契约，只补一条**读者契约**：
> `hook_slow`（§4 归因与边界类，v1.9 登记）的写入侧一直忠实（超过
> `SLOW_BUDGET_MS` 记一条，带 `elapsed_ms`/`tool`/`session`），但**消费侧为零**：
> `scripts/report.py` 里唯一可能看见它的 `elif action == "alert"` **不分 type**，
> 89 条真实信号（真实工作区链实测，最差 `elapsed_ms`=2,476,295 ≈ 41 分钟）
> 被一个匿名通用计数吸收 ⇒ 读报告的人分不清"有个钩子跑了 41 分钟"与"弹了一次气泡"。
> 本版起它进 `config_health`（`hook_slow` 计数 ＋ `hook_slow_max_ms` 最差值），
> 文本与 HTML 报告各单独一行。判据 S35–S37（含三条负控）常驻防复发。
> **纪律**：这与 0.29.0 D-1（`sec_path_whitelisted`）、0.18.0 HP-47（`hook_error`）
> 是同一条——**"记了"不等于"看得见"**；新登记事件类型必须同时回答"谁来读它"。

> v1.12（0.42.0）：**提权盲区根因修复** —— **不改**字段名、**不改**取值域、**不改**
> append-only 契约；只**更正两处语义描述**并加一条强制：
> · `host_shield_zone_locked` **兼表成败**：`subkind=zone_ok`（已上锁）/
>   `zone_lock_failed`（本次未能限制写入）。其「未生效」分支的 `reason`
>   **不得断言**「有进程在对抗门闸」—— 本机实测该断言的真因是**提权令牌**下
>   写探针失真（`acl_deny` 有意保留的 `Administrators:(OI)(CI)(F)` 对本进程生效），
>   与"有人对抗"是两回事。判据 S34/N-S34 常驻防复发。
> · `host_shield.is_denied()` **提权感知**：写探针说"能写"且本进程提权时，
>   改读 **ACL**（`acl_read_deny()`）判定"锁有没有上"——写探针在提权令牌下
>   **不是有效 oracle**。判据 S33/N-S33 常驻防复发。
> · 三份提权判据（`host_shield.process_elevation` / `verification_tests._process_elevation`
>   / `drift_audit._acl_audit_usable`）必须**同规则**（whoami / `S-1-16-` / `0x3000`），
>   判据 S32 常驻（**只改一边就报红**）。
>
> v1.11（0.40.0）：**"四行失守"的根因修复**带来的字段变更，全部是**加字段/加取值**，
> 不改已有字段语义（append-only 契约不变）：
> · 新增记录类型 **`host_shield_dev_drift`** ——「研发迭代中：代码与登记表不符」。
>   它与 `host_shield_tamper`（出厂包被改）是**两种事件**：前者研发期必然发生、
>   发版即消失，级别 L1（不弹泡、不进「要处理」）；后者 R0。**不能互相顶替。**
> · `host_shield_tamper` 的 `subkind` 取值域确立为 **`code_drift`**（代码/登记表与
>   manifest 不符）与 **`state_drift`**（安全状态字段运行期漂移、哨兵已回写恢复）；
>   旧值 `self_check` 是 `code_drift` 的**同义旧名**，读侧必须归一（链不可改）。
> · 自愈类记录（`field ∈ {enabled, state}` 且哨兵已回写恢复）**必须**带
>   `recovered=true`（v1.10 定义的语义，此处收窄成强制）。
> · `host_shield_zone_locked` 的 `subkind` 取值域确立为 **`zone_ok`**（上锁成功）
>   与 **`zone_lock_failed`**（上锁失败）；该类型**兼表成败**，读侧必须按记录分档
>   （成功≠失守），不得按类型一刀切。
> · `host_shield_spawn_failed` 的所有记录点**统一**带 `subkind="spawn_failed"`
>   （此前一个记录点写、一个不写 ⇒ 同一件事被归并成两行）。

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
| `recovered` | 可选（v1.10 起） | **布尔**。`true` ＝ 本条描述的事**已经自动愈合、没有留下后果**（例：`host_shield_tamper` 的 state 回写恢复类——防线把被改的配置回滚回去了，用户配置与执法状态均未受损）。★ **是结构化字段，不是文案**：消费者（Antinel 监理分档、日报）必须读它，**不许解析 `reason` 里的"已回写恢复"**。字段缺省 ⇒ 语义＝"未知"（按"有后果"处理，方向收紧）。**★ v1.14（0.43.0）收窄为强制：消费侧必须据此降档** —— `true` 的记录**不得再定成 R0**（`inbox_model.level_of_record` 是唯一实现），且标题**不得再写"失守"**（`title_of_record`）。原因（实测 24h 内 17 条）：定档此前按类型一刀切，档位说"失守"、分桶又说"不用你管"，同一条记录自相矛盾 |

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

### 通知送达类（0.54.0，v1.22 新增）

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `delivery_unknown` | daemon | `kind`, `downgrade`, `minutes_overdue`, `noticed` | **L1**。语义：一条通知**发出去了**，`NOTICE_WINDOW`（30 分钟）内没有见到用户动作，且降级（托盘角标／首屏横幅）也失败 ⇒ 这就是「最后一米断了」的**证据**。★ 三种情况**不许**写它：降级成功（成功不是未知）／无头场景 `channel="file"`（没有通道不是通道坏了）／用户已经见过（`notice_seen` 是最硬的证据）。★ 两种「判不了」也不许写成它：时差为负（时钟回拨／未来时间）／当日链读不到（无法去重）。两者报 `undecidable`，**不落链**。★ `downgrade` 取值域 `tray`／`banner`／`none`：`none` 指没有可用的降级通道；有通道但失败时记**最后尝试的那一道**（这样「没通道」与「有通道但坏了」分得开）。★ `minutes_overdue` 为整数分钟，从**发出行的 `ts`** 派生的时差，不用系统时钟另算。★ **不弹气泡**（N12 原文）：本条自己就是「报不达」的证据，再弹一次会递归。★ 同日同 `kind` **只记一条**（daemon 每 10 分钟一拍，不去重就是每天几十条脏账）；去重口径是当日链上是否已有同 `kind` 记录 —— 代价是同日同 `kind` 的第二次独立失败不会单独留痕，这条边界写在 B 线施工日志里 |

### 缺口生命周期类（0.54.0，v1.22 新增）

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `gap_fixed` | server / daemon | `ref`, `by` | **用户显式声明某个缺口已经修好**：`ref` 指向原缺口记录，`by` 为 `user`。读路径据此把原记录的 `gap_state` 派生为 `fixed`（双读兼容：原记录不改写）。★ 与 `waived`（「忽略」）是**两件事两个词**，不共用：`waived` 是「我不打算修」，退出 harm 但留在期间行；`fixed` 是「它好了」。把 `waived` 写成 `gap_fixed` ⇒ 撒谎（不可补救的 `host_shield_breach` 更不能靠它变绿）。★ **当前无生产者** —— U4 的「我修好了」按钮尚未接线，本条登记的是类型与字段语义 |

### 释放留痕类（"放行必须留痕"）

| type | 来源 | 说明 |
|---|---|---|
| `workspace_root_allow` | pre | 因 `workspace_roots` 而放行的本应拦截项（记 `matched_root`、`config_source`） |
| `exclude_patterns_allow` | pre | 因规则 `exclude_patterns` 放行的 critical 命中（宿主级镜像） |
| `command_deletion_permission` | pre | **0.46.0 (v1.17)**：删除许可（VCT）两票裁决的**每一次**结论（宿主级镜像）。关键字段：`subkind`（取值域见下）、`exit`（退出口 `甲`/`乙`/`丙`/`丁`，非退出口为空串）、`vote1`（第一票 `ignored`/`protected`/`outside`/`unavailable`）、`vote2`（第二票 `regenerable`/`not_regenerable`）、`targets[]`（命令里取到的**字面**目标）、`reason`（"为什么走到这里"）。★ `subkind` 取值域：`vct_allow`（两票都同意⇒放行）/ `vct_deny`（有明确结论且否决⇒拦）/ `fallback_allow`（取不到信号⇒兜底名单接住并放行）/ `exit_乙`·`exit_丙`（取不到信号且兜底名单**也没接住**⇒按默认拦）。★ 为什么必须独立命名（不并入 `exclude_patterns_allow`）：两者是**不同判据**放的行——混在一处，读者分不清这次是"两票裁决"生效还是"名单兜底"生效，而这正是本仓最忌的形状（"分不清是哪条路生效"）。★ 为什么四个退出口都要写：设计 §3.5 明写「不许静默——任何一条静默分支，将来都会被当成正常路径」 |
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
| `rules_snapshot_refreshed` | 钩子加载前 / 守护进程每 tick / antinel CLI（`install.py --refresh-rules`） | `rules_file`, `version_from`, `version_to`, `hash_from`, `hash_to`, `auto` | **v1.23（0.57.2）立目，v1.25（0.60.0）扩触发者**：项目里的规则副本被刷成包内那一版。★ 为什么单独立账：hook 读的是 `<项目>/.psl/rules/default.json`（install 时拷的那份），`pip install -U` **只换包不跑 install** ⇒ 副本会永久停在首次安装的版本（本机实测：副本 0.34.0／包内 0.57.1，中间 9 条规则的 15 处修复一条都没生效）。刷新副本＝**改门闸的判据依据**，所以必须留痕：`hash_from`/`hash_to` 就是这次判定换了哪把尺子。★ v1.25 起这条不再只由人手敲命令产生：`host_shield.ensure_rules_current()` 在**每次钩子加载前**与**守护进程每 tick** 都会判一次（幂等，正常路径只读两个 `version` 字段、不写盘），所以 `auto=true` 表示"包一换就自己补上的"，`auto=false`（缺省）表示"人明确要求的" |
| `rules_auto_refresh_skipped` | 钩子加载前 / 守护进程每 tick | `rules_file`, `version_from`, `version_to`, `hash_from`, `hash_to`, `expected`, `auto` | **v1.25（0.60.0）新增**：**该刷而没刷**。自动刷新的硬红线是「副本被手工改过就不覆盖」——实算哈希与 manifest 登记的 `rules_hash` 不符 ⇒ 视为有人动过这份防护依据 ⇒ 保留原样、交给 A4 判 SELF-TAMPERED，只留这条 `severity=critical` 的记录。★ 为什么不是"静默跳过"：自动覆盖一份被改过的规则，等于把篡改证据连同问题一起抹掉，比不修更坏；而沉默的跳过会让"没刷"与"本来就不用刷"逐字段相同 |
| `autostart_no_window_fixed` | 哨兵启动时 / `install.py --fix-hooks` | `action_taken`, `moved_count`, `task` | **v1.25（0.60.0）新增**：**把旧的自启方式换成了不弹窗的那一种**。本机老版本用 `schtasks /TR "…antinel-shield.cmd"` 注册登录自启，`.cmd` 只能由 `cmd.exe` 执行，而计划任务的服务进程**没有控制台** ⇒ Windows 每次登录必定新建一个控制台窗口（创始人 2026-10-27：「任何类型的闪出黑窗都不可接受」）。这条记录的是「老任务被改指 `.lnk`（pythonw）」与「启动文件夹里旧的 `.cmd`/`.away-*` 被搬进 `<hub>/archive/`」。★ 为什么必须留痕：这是**改开机行为**的动作，而且只做一次（按版本打标记），事后没人能凭现象反推它做过没有 |
| `policy_changed` | antinel CLI | `change`, `field`, `old_sha256`, `new_sha256`, `invoked_by` | `.psl/policy.json` 被 CLI 改写（白名单/阈值/档位）。每一次都记，因为**放行范围因此改变**。**v1.10 补登记 `field` 取值域**：`zones` / `workspaces` / `windows` / `roots` / `paths` / `domains` / 预算与限额项 …。★ 门闸的**链背书判定**按 `field` 取字段（`host_shield._backing_field()`）——`field=zones` 的记录才替 `host_shield.json` 的 `zones` 变化背书。**改这个取值域＝改门闸的判据**，必须同步改 `_BACKING_TYPES` 的守卫 |
| `credits_snapshot` | antinel CLI | 余额快照 | 用户登记的积分余额事实（`antinel credits snapshot`）。**是事实记录，不是估算** |
| `credits_low` | （暂无生产者） | `reason` | **v1.19（0.51.2）补登记**：缺粮事件——积分余额偏低。0.51.0 起在 `inbox_model.LEVEL_OF_KIND`（**Ls** 级）与 `TITLE_OF_KIND`（「缺粮：积分余额偏低」）登记，并是徽标「缺粮」的**第二个来源**（存在未关闭的 `credits_low` 记录即亮徽标）。★ **当前无生产者** —— 链上暂无此类型记录；本条登记的是**类型存在性与字段语义**。★ 与 `credits_snapshot` 是两件事：一个是**告警态**，一个是**事实快照** |
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

### 提醒预算类（0.47.0，v1.18 新增）

> 0.47.0 新增的两类都服务于同一条纪律：**合并不是丢弃，补记不能只靠记忆**。
> 方案 v3.0 §5 步一（根治第三处告警疲劳）：给**单条规则**设滚动窗口提醒配额。
> 超预算的后续提醒**不再逐条出声**，但**条数照记**；窗口结束时**补记**最终总数。
> ★ 这两条记录就是"没被逐条说出来的那些条"**唯一的去处** ——
>   没有它们，"合并"在证据层面与"静默丢弃"没有区别（交接件 §2.1 ① 关键纪律：
>   合并与补记动作必须留痕，不许只有 `stderr`）。

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `notice_budget_merged` | 钩子 `notice_gate` | `rule_id`, `total`, `used`, `merged`, `quota`, `window_seconds`, `decision="allow"`, `severity="info"` | 某条规则**在本窗口内首次跨过配额**时写一条（每窗口每规则**最多一条**，不是每条提醒一条 —— 否则降噪机制自己把账本灌满）。语义："接下来不再逐条出声，改为合并"。★ 只记"进入合并态"这一次，不记后续每一次 |
| `notice_budget_window_closed` | 钩子 `notice_gate` | `rule_id`, `bucket`, `total`, `used`, `dup`, `merged`, `window_seconds`, `decision="allow"`, `severity="info"` | 滚动窗口**结束时**的补记：`total` ＝ 本窗口该规则被请求提醒的**原始总条数**（＝ `used + dup + merged`）。★ 这是"原始条数不丢"的**可验真处** —— 三个分项之和必须等于 `total`，判据 `ci/inbox_guards_0470.py` 常驻核对。<br>★★ 0.62.0（v1.21）：**新增 `bucket` 字段，`rule_id` 语义收紧**。此前 `rule_id` 直接写 `notice_gate()` 的第一个参数，而该参数既装真规则号（`SLOP-01`）又装**分桶 key**（`DST-02-BASH` —— 同一规则 `DST-02` 的 Bash 提醒通道）⇒ 账本里出现 390 条"规则库里没有的规则号"，看起来像第 38 条规则。现在：`rule_id` **只放真规则号**（正则 `^[A-Z]{2,5}-\d{2}` 取前缀，取不到填 `-`），`bucket` 放原始分桶名（与旧 `rule_id` 取值逐字相同）。**历史记录不追溯**（append-only），读账本时按 `bucket` 取旧口径、按 `rule_id` 取新口径 |

### 体检提醒类（0.53.0，v1.20 新增）

> 0.53.0 起体检进控制台（第五个选项卡），「还没做过体检」不再只写在引导条上：
> 到点出一条收件箱记录。**提醒的独占家在收件箱**（设计 §29），体检页只写
> 「上次体检 X 天前」，不重复出声。

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `exam_reminder` | `host_shield.exam_reminder_check`（daemon tick 调用） | `reason`（人话整句）, `subkind` ∈ `never` / `overdue`, `severity="info"`, `decision` 缺省, `notify=False` | **v1.20（0.53.0）补登记**：该做体检了。`subkind="never"` ＝ 装好 ≥24 小时一次体检都没做过（`exam_state` 的 `S1`）；`subkind="overdue"` ＝ 上次体检已过去很久（`S3`）。★ **去重靠链不靠内存**：hub rollup 链上已有 `type=exam_reminder` 就再也不出（`exam_reminder_check` 里查链），所以这类型全历史**最多一条** —— 它是「提醒过了」的证据，不是台账。★ 级别定在 **L1（注意）** 而不是 L2：L2 会弹置顶紧急窗，而"还没体检"只是知情即可（`inbox_model.LEVEL_OF_KIND` 一处可翻回，判据同源跟随）。★ 与 `credits_low` 同类：都是**通知性质**、都不代表防线出事 |

### 哨标规格类（0.53.2，v1.21 新增）

> 0.53.2 起，漂浮哨标（tools/logo.ps1）与托盘之间的动效规格链有了**留痕**：
> 规格取不到（T2）／规格缺态键（T2）都不再静默回落。
> ★ 两条路的进链方式不同，各有各的原因：
>   · `logo_spec_missing` 由 Python 侧（`inbox_tray.write_state`）直接写本链；
>   · 徽标是 PowerShell，**写不了** Python 账本（hash 链与锁协议都在
>     Python 侧）⇒ 它往 `console_dir/logo_events.jsonl` 追加 JSON 行，
>     由 daemon tick（`inbox_daemon.Daemon.tick` ③b）**改名消费**后按同一
>     配方进链 —— 顺序是**先链后改名**（与 `poll_actions` 的先改名相反，
>     故意的）：动作丢了只是少点一下，**审计证据丢了不可再生**；进链失败
>     不消费，下 tick 重试（最坏重复记几条，好过静默丢失）。
> ★ 谁来读它：晨报／日报与 `antinel inbox status`；托盘状态文件
>   （tray.json 的 `logo_missing`/`logo_error`）是**同一事实的文件标记**，
>   两类读者各取所需，不互相依赖。

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `logo_spec_missing` | `inbox_tray.write_state`（daemon tick ③ 顺带） | `reason`（人话整句）, `error`（`Type: msg`）, `severity="warning"` | **v1.21（0.53.2 T2）**：写托盘状态时拿不到动效规格。tray.json 同拍写出 `logo_missing: true` ＋ `logo_error`（文件标记），哨标回落品牌 LOGO 静态图标。★ **每进程每个失败 episode 至多一条**（失败→恢复→再失败是两个 episode；失败进行中不重复）——守护进程 2 秒一拍，不节流会一天写出四万多条同因记录（0470 提醒预算同款纪律）。★ 与 0.53.1「不写这个键」的区别就在这张表里：旧口径下「旧版没这功能」与「新版坏了」在 tray.json 里**逐字节相同**，静默且不可分辨 |
| `logo_mode_missing` | 徽标 `tools/logo.ps1`（经 logo_events.jsonl 进链） | `state`（缺键的那个态）, `reason`, `severity="warning"` | **v1.21（0.53.2 T2）**：规格 `modes` 里没有当前态的键（例：来了个 `L9`）。回落 L0 帧照旧（画点什么总比不画好），但**不许静默**——静默回落会让「规格丢了键」与「规格好好的」在屏幕上长得一样。★ 进程内每 `(type\|reason)` 至多一条。★ 与 `logo_frame_unavailable` 同型：**Python 侧无直接生产者**（生产者是 PowerShell；`tools/verify_event_types.py` 只扫 Python 的 dict 字面量）——本条登记的是**类型存在性与字段语义**；Python 侧唯一的常量出现是 `inbox_tray.LOGO_EVENTS_KNOWN` 白名单（进链时按它校验 type） |
| `logo_event_unreadable` | `inbox_tray.drain_logo_events` | `raw`（原文截断 200 字符）, `severity="warning"` | **v1.21（0.53.2）**：徽标往 logo_events.jsonl 写过一行**读不懂**的东西（坏 JSON／未知 type／非对象）。★ 为什么单列而不丢弃：「徽标写过一行没人看得懂的东西」本身就是证据；静默丢弃是与本表同类要防的形状 |
| `logo_dpi_changed` | 徽标 `tools/logo.ps1`（WM_DPICHANGED ⇒ 经 logo_events.jsonl 进链） | `state`, `reason`（`dpi <旧> -> <新>`）, `severity="warning"` | **v1.21（0.53.2 T4）**：哨标所在显示器的缩放变了（拖到另一块屏／改系统缩放），徽标按**同一个派生**重算物理尺寸与可点半径并重画。★ 为什么算「注意」而不是「信息」：换屏重算如果悄悄没生效，症状是「大小不对／点不准」，而屏幕上没有任何东西会自己喊；本条是**换屏这件事发生过**的可溯源证据。★ 与 `logo_mode_missing` 同型：PowerShell 侧生产者，Python 侧只出现在 `LOGO_EVENTS_KNOWN` 白名单 |

### 门闸类（host-shield，v1.3 补登记；v1.4 增补）

> 由 `host_shield.py` 哨兵与 `antinel.py host-shield enable/disable` 写入**与上表同一条链**。
> ★ 门闸**默认关闭**（须 `antinel host-shield enable` 才布防）；未布防时链中不出现本族记录。
> 本族 `session` 固定为 `"host-shield"`、`tool` 固定为 `"-"`、`host` 固定为 `"generic"`（见 §3 公共字段）。

| type | 来源 | 关键字段 | 说明 |
|---|---|---|---|
| `host_shield_zone_locked` | 哨兵 | `decision="deny"`, `subkind`(`zone_ok`/`zone_lock_failed`), `severity`(`warning`/`critical`), `reason`(含路径) | 安全区（zone）ACL 上锁的**结果**（该类型**兼表成败**，读侧必须按 `subkind` 分档）：`zone_ok`=已上锁（区内防篡改；出网另由 `net_mode` 把闸）；`zone_lock_failed`=本次**未能限制写入**（★ **不等于**"有进程在对抗门闸"——提权令牌下写探针失真曾是它的成因，0.42.0 起 `is_denied()` 提权感知、改读 ACL） |
| `host_shield_breach` | 哨兵 | `decision="deny"` | **门闸异常**四种：① 自启缺失（计划任务与启动文件夹均无，`#6`）② 发现未拦的外传落盘点并补锁（补锁失败时 severity=critical）③ 发现符号链接（绕过载体）④ 心跳陈旧（疑似挂起/僵死）且旧进程镜像异常，拒绝自动重启 |
| `host_shield_task_unknown` | 哨兵 | `decision="alert"` | **v1.3 新增**：无法确认计划任务状态（`schtasks` 不可用／被策略拦截／超时）。★ 与 `breach` **分开记** —— **"查不出来"不是"查到了是坏的"**；此前该情形被 fail-open 吞成"已安装"，导致 `breach` 永不触发 |
| `host_shield_window_closed` | 哨兵 | `decision`, `reason` | 放行窗到期关闭 |
| `host_shield_heartbeat` | 哨兵 | `decision="allow"`, `watched`(登记路径数) | 哨兵心跳（门闸在岗），每 `HEARTBEAT_SECONDS` 一次；**断档由晨报/`host-shield status` 呈现**（v1.4 起） |
| `host_shield_changed` | `antinel.py` | `decision="allow"`, `severity="warning"`, `field`, `change`, `invoked_by`, `autostart`, `spawn`, `armed` | 门闸被 enable／disable；`change` 为 `"false → true"` 形式。**v1.4 增补**：`autostart` ∈ schtasks / startup-folder / none（自启注册的真实结局，不假成功）；`spawn` ∈ ok / failed（哨兵本次是否真的拉起来了）。**v1.5 增补**：`armed` 布尔＝翻转后的权威值——哨兵对 enabled 的执法以链上本字段为准（B4b 系"无声开关"的闭合） |
| `host_shield_revived` | 哨兵/paramedic | `decision="allow"`, `pid`, `cause`, `spawn_mode` | **v1.4 新增**：哨兵死亡后被重新拉起（钩子 paramedic 或 CLI）。复活记录本身就是"此前有断档"的证据 |
| `host_shield_spawn_failed` | 哨兵/paramedic | `decision="deny"`, `severity="critical"`, `cause` | **v1.4 新增**：哨兵死亡且拉起失败——门闸无人值守的显式记录（此前该状态只存在于沉默里） |
| `host_shield_tamper` | 哨兵 | `decision="deny"`, `severity="critical"`, `field`, `reason`, `recovered` | **v1.5 新增**：本地配置与权威依据不符——state 文件 `enabled` 与链不一致（B4b/b2/c/d）；workspaces/zones/windows 无链背书被改并已回写恢复；启动自检发现运行代码/登记表与 manifest 不符（B4e/f）。执法按链/按已知值继续，绝不因文件被改而静默停摆。**v1.10**：`field="state"` 的回写恢复类**必须带 `recovered=true`**（防线已自愈、无后果）；`reason` 增补"哪个字段从什么变成什么"（`host_shield._fp_diff_txt()`）——旧文案只说"workspaces/zones/windows 被修改"，**不说改了哪个**，事后无法定位真因（2026-10-06 就是靠翻全链邻居才认出真因） |
| `host_shield_dev_drift` | 哨兵 | `decision="deny"`, `severity="warning"`, `field="self-check"`, `subkind="code_drift"` | **v1.11 新增**：启动自检不符，但**判定为研发态**（登记表`psl/manifest.json`停在发版那一刻，而工作树比它新）⇒ 这是**范畴事实，不是防线失守**。★ 为什么必须与 `host_shield_tamper` **分开记**：类型错了，读者层再修也修不回来 —— 旧口径把这情形判成 R0「失守」，而**那个判断本身就是错的**（创始人 2026-10-09 点名的「没有失守却显示失守」）。Antinel 监理按 **L1（注意）** 呈现、**不进**「要处理」、**不弹气泡**（不在 `host_shield._ALERT_KINDS` 里）。★ 报红条件（负控，判据 S25）：一旦**已出厂** ⇒ 仍记 `host_shield_tamper` critical ⇒ R0。★ **v1.15（0.43.1）收窄"已出厂"的定义**：原口径是「登记版本 ≥ 代码版本」，但那把「登记版本 == 代码版本」也算进去了 —— 而 `ci/version_check.py` 要求 10 处承载件（含 `psl/manifest.json`）逐字相同，升版**必然**把 manifest 的 version 刷成同号 ⇒ 落差永远为 0 ⇒ 研发态**长期不可达**（实测：界面挂 R0「失守」而事实是正常迭代）。新口径：**已出厂 ⇔ 登记版本 ＞ 代码版本，或（登记版本 == 代码版本 且清单与工作树逐字节相符）**；登记版本 == 代码版本**但清单与工作树不符** ⇒ 这是"版本已升、尚未重打包"⇒ 仍判研发态。判据 S67/N-S67（`ci/inbox_guards_0431.py`）常驻防复发。★ 登记纪律：新增链类型必须**同时**进本文 §4 —— 只写抬头说明会被 `tools/verify_event_types.py` 判"未登记"（0.40.0 实际踩过：F-10 因此变红） |
| `host_shield_lock_held` | 哨兵 | `decision="deny"`, `severity="none"`, `reason`(含路径) | **v1.6a 补登记**：门闸**持锁中**的周期性状态留痕（每 `LOCK_HELD_EVERY` 一次，`lock_held_at` 去重）。★ 与 `breach` **分开**：锁**在**是正常态，不该只在"出事"时才出现在账本上 —— 旧机制下 `if is_denied(...)` 为真就**整支跳过**，于是"锁挂了两个月、账本一字不提"（09-25/26 审计只剩心跳、零 breach） |
| `host_shield_contested` | 哨兵 | `decision="deny"`, `severity="critical"`, `reason`(含路径与补锁次数) | **v1.6a 补登记**：同一落点在 `CONTEST_WINDOW` 内被补锁 ≥ `CONTEST_TIMES` 次 —— 上锁**未稳定生效**或**有进程在对抗门闸**，须人工介入。★ 与 `breach` 的分工：`breach` 是"发现未拦的落点"（第 1 次，且明说"不等于有进程在对抗"），本类是"补锁反复不生效"（第 N 次） |
| `host_shield_state_write_refused` | 哨兵/钩子 | `decision="deny"`, `severity="warning"`, `fields`(被拒写的字段名列表), `subkind`(`refused`/`optimistic_lock_lost`), `reason` | **v1.15 新增；v1.16 增补 `subkind`**：`update_state_fields()` 这道"没保住就出声"的留痕，**两种成因按 `subkind` 分派**：`refused`=状态文件**存在但读不到**（坏/半截）⇒ 主动拒写、返回 False；`optimistic_lock_lost`=写后读回版本号（`_rev`）不符 ⇒ 被并发覆盖、重试一次仍不符。★ 为什么必须出声：保护静默生效会让**节流与记账一起悄悄失效**（症状＝哨兵被反复拉起，实测当天 19 次 `host_shield_revived`），而过去三处调用点**全部忽略返回值** ⇒ 无人可见。★ **不弹气泡**（`notify=False`，不在 `host_shield._ALERT_KINDS` 内）：它是诊断，不是"需要你动手"。★ 登记纪律：新增链类型必须**同时**进本文 §4，由 `tools/verify_event_types.py` 扫代码写出的 type 校验（只写抬头说明会判"未登记"，0.40.0 踩过 F-10） |

| `host_shield_state_unreadable` | 哨兵 | `decision="allow"`, `severity="warning"`, `subkind="state_unreadable"`, `reason` | **v1.24（0.59.0）新增**：安全状态文件**这一刻读不出来**（重试仍失败：另一个进程正原子替换／文件半写／损坏）。★ 为什么必须与 `host_shield_tamper` **分开记**：两件事的**后果相反**——tamper 是"读到了，且和链权威不符"（有篡改嫌疑，要人看），本条是"根本没读到"（盲区，会自行收敛）。合在一起记，读者无法分辨"有人动了开关"与"这次没读到"；2026-10-27 实测正是后者被记成了前者：当日 `field=enabled` 的 tamper 文案反复写「实际值（**None**）」，而 None 不是任何人写进去的值。★ 定档 **L0**：不弹气泡、不发 toast（`should_touch` 默认门槛 L1），但仍进收件箱与页面（盲区不许被静默成清白）。★ 节流：同类 30 分钟至多一条（`_STATE_UNREADABLE_LAST`）。★ 代价必须写进账：启动时若读不到，**单实例检查没做成**（读不到已在跑的哨兵 pid），可能双哨兵并存——这句写在 `reason` 里，不隐藏 |

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
