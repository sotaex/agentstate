# B-2 · `I1-02` 对账结果

> 读数时刻 **2026-10-31T22:46:04+08:00**，目录 `D:\psl\poc\antinel-security\.psl\audit`。
> 日文件 **33** 个，记录 **164049** 条，坏行 **0** 条；已排除 `lock_events.jsonl`。

★ 账本是**活的**：本工具运行期间，本会话自己的工具调用仍在往里写记录。所以上面的数是**读取时刻的快照**，不是常量——复跑会漂。

## 1 三个数

| 项                       | 条数    | 口径                                             |
|-------------------------|-------|------------------------------------------------|
| calls                   | 47596 | `type == "pre_tool_use"`（全等，不含 summary）        |
| posts                   | 45928 | `type == "post_tool_use"`                      |
| blocked                 | 347   | 上述 calls 中 `decision == "block"`               |
| 配对成功                    | 45887 | 同一 `(session, content_digest)` 内 pre 与 post 配对 |
| calls − posts           | 1668  | **真正的待归因总量**                                   |
| calls − posts − blocked | 1321  | ★ **这一项不等于 0，也不应该等于 0** —— 见 §8 结论 2           |

## 2 差额归因（E1–E8，无「其它」桶）

| 号   | 出口                      | 条数   | 含义                                                          |
|-----|-------------------------|------|-------------------------------------------------------------|
| E1  | `blocked_stopped`       | 301  | 拦截生效，按设计不产生 post                                            |
| E2  | `deny_not_honored`      | 0    | block 了但仍然执行（E-3，最严重）                                       |
| E3  | `duplicate_pre`         | 616  | 同一次调用写了多条 pre（组内有 post 可反证，间隔 ≤ 窗口）                         |
| E4  | `orphan_post`           | 41   | 有后无前：post 找不到对应 pre                                         |
| E5  | `alert_no_post`         | 23   | 告警通道放行但没有后记录                                                |
| E6a | `session_tail`          | 3    | 放行且无后记录；该会话最后一条动作                                           |
| E6b | `session_continued`     | 574  | 放行且无后记录；会话之后仍在继续（硬残差）                                       |
| E7  | `dup_pre_unprovable`    | 164  | 放行/拦截且无 post，同组多条 pre 的多余部分                                 |
| E8  | `surplus_pre_ambiguous` | 28   | 组内有 post，但多余 pre 与配对 pre 相隔超过窗口：更像两次真实调用丢了一条 post，无法与重复记录区分 |
|     | **加向（不含 E4）**           | 1709 | 把差额解释掉的那一头                                                  |
|     | **减向 E4**               | 41   | 把差额造出来的那一头                                                  |
|     | **净额**                  | 1668 | 必须 == `calls − posts` = 1668                                |

恒等式：`E1+E3+E5+E6a+E6b+E7+E8 − E4 == calls − posts`，即 **1709 − 41 = 1668**。逐桶断言结果：**全部成立**。

## 3 分桶（按工具）：差额落在哪几个工具上

★ 桶键用**工具**而不是「工具 × 裁决」，是被自证腿 T1/T2 撞出来的：`post_tool_use` 的裁决记在 `action` 而 `decision` 为空，把裁决并进桶键会把同一次调用劈进 `Bash/allow`（call）与 `Bash/<none>`（post）两个桶，**逐桶加减法不闭合**。裁决维度见 §4 交叉表。

| 工具                  | calls | posts | 差   | blocked | E3 重复 | E1 拦截 | E6b 硬残差 |
|---------------------|-------|-------|-----|---------|-------|-------|---------|
| Bash                | 25996 | 25299 | 697 | 283     | 104   | 237   | 212     |
| present_files       | 730   | 363   | 367 | 0       | 363   | 0     | 2       |
| Edit                | 7797  | 7584  | 213 | 8       | 5     | 8     | 194     |
| Write               | 1900  | 1795  | 105 | 55      | 7     | 55    | 38      |
| WebFetch            | 138   | 71    | 67  | 0       | 57    | 0     | 0       |
| show_widget         | 115   | 58    | 57  | 0       | 57    | 0     | 0       |
| Grep                | 1712  | 1658  | 54  | 0       | 0     | 0     | 54      |
| widget_guidelines   | 50    | 25    | 25  | 0       | 15    | 0     | 0       |
| TaskOutput          | 1521  | 1497  | 24  | 0       | 3     | 0     | 20      |
| Read                | 5503  | 5482  | 21  | 1       | 3     | 1     | 11      |
| Glob                | 165   | 146   | 19  | 0       | 0     | 0     | 19      |
| PowerShell          | 772   | 759   | 13  | 0       | 0     | 0     | 14      |
| WebSearch           | 156   | 153   | 3   | 0       | 0     | 0     | 2       |
| MultiEdit           | 6     | 4     | 2   | 0       | 0     | 0     | 6       |
| TaskStop            | 48    | 49    | -1  | 0       | 0     | 0     | 0       |
| ToolSearch          | 18    | 17    | 1   | 0       | 1     | 0     | 0       |
| DeferExecuteTool    | 19    | 20    | -1  | 0       | 0     | 0     | 0       |
| automation_update   | 2     | 1     | 1   | 0       | 1     | 0     | 0       |
| <none>              | 1     | 0     | 1   | 0       | 0     | 0     | 1       |
| TaskCreate          | 369   | 369   | 0   | 0       | 0     | 0     | 0       |
| TaskUpdate          | 447   | 447   | 0   | 0       | 0     | 0     | 1       |
| AskUserQuestion     | 42    | 42    | 0   | 0       | 0     | 0     | 0       |
| TaskList            | 27    | 27    | 0   | 0       | 0     | 0     | 0       |
| Agent               | 10    | 10    | 0   | 0       | 0     | 0     | 0       |
| Skill               | 24    | 24    | 0   | 0       | 0     | 0     | 0       |
| search_plugins      | 2     | 2     | 0   | 0       | 0     | 0     | 0       |
| conversation_search | 3     | 3     | 0   | 0       | 0     | 0     | 0       |
| TaskGet             | 3     | 3     | 0   | 0       | 0     | 0     | 0       |
| ViewImage           | 20    | 20    | 0   | 0       | 0     | 0     | 0       |

## 4 call 侧的裁决分布 与 `decision × action` 交叉表

| call 的 decision | 条数    |
|-----------------|-------|
| allow           | 46209 |
| alert           | 1040  |
| block           | 347   |

| 记录类型                           | decision        | action | 条数    |
|--------------------------------|-----------------|--------|-------|
| `pre_tool_use`                 | allow           | allow  | 46209 |
| `post_tool_use`                | None            | record | 45917 |
| `usage_delta`                  | None            | None   | 40826 |
| `dst02_bash_path_suspect`      | alert           | alert  | 10580 |
| `host_changed`                 | alert           | None   | 7631  |
| `host_shield_heartbeat`        | allow           | None   | 6303  |
| `pre_tool_use`                 | alert           | alert  | 1040  |
| `pre_tool_use_summary`         | alert           | None   | 832   |
| `notice_budget_window_closed`  | allow           | alert  | 757   |
| `host_shield_revived`          | allow           | None   | 576   |
| `workspace_root_allow`         | allow           | None   | 454   |
| `pre_tool_use`                 | block           | block  | 347   |
| `pre_tool_use_summary`         | block           | None   | 329   |
| `exclude_patterns_allow`       | allow           | allow  | 318   |
| `session_start`                | allow           | None   | 311   |
| `host_shield_spawn_failed`     | deny            | None   | 301   |
| `host_shield_tamper`           | deny            | None   | 273   |
| `host_shield_zone_locked`      | deny            | None   | 208   |
| `command_deletion_permission`  | deny            | block  | 176   |
| `host_shield_breach`           | deny            | None   | 170   |
| `notice_budget_merged`         | allow           | alert  | 151   |
| `host_shield_state_unreadable` | allow           | None   | 77    |
| `host_shield_dev_drift`        | deny            | None   | 68    |
| `hook_slow`                    | allow           | alert  | 38    |
| `session_dna`                  | None            | None   | 33    |
| `host_shield_task_unknown`     | alert           | None   | 26    |
| `enforcement_probe`            | alert           | None   | 22    |
| `command_deletion_permission`  | allow           | allow  | 14    |
| `rules_snapshot_refreshed`     | config_refresh  | allow  | 13    |
| `host_shield_changed`          | allow           | None   | 12    |
| `post_tool_use`                | None            | alert  | 11    |
| `rules_integrity_fallback`     | config_fallback | alert  | 10    |
| `hook_alive`                   | allow           | None   | 7     |
| `policy_changed`               | allow           | None   | 3     |
| `autostart_no_window_fixed`    | config_refresh  | allow  | 2     |
| `dst02_path_whitelisted`       | allow           | allow  | 1     |
| `credits_snapshot`             | allow           | None   | 1     |
| `hook_error`                   | allow           | alert  | 1     |
| `canary_planted`               | allow           | None   | 1     |

## 5 每条被拦下的事实，在账本里叫几个名字

| 记录类型                          | decision | action | 条数  |
|-------------------------------|----------|--------|-----|
| `pre_tool_use`                | block    | block  | 347 |
| `pre_tool_use_summary`        | block    | None   | 329 |
| `host_shield_spawn_failed`    | deny     | None   | 301 |
| `host_shield_tamper`          | deny     | None   | 273 |
| `host_shield_zone_locked`     | deny     | None   | 208 |
| `command_deletion_permission` | deny     | block  | 176 |
| `host_shield_breach`          | deny     | None   | 170 |
| `host_shield_dev_drift`       | deny     | None   | 68  |

⇒ 同一次「被拦下」，pre 记 `block`、`command_deletion_permission` 记 `deny`、summary 记 `block`。**按任一个词单独统计「拦截次数」都会算错。**

## 6 重复 pre 的时间间隔（E3 / E8 的唯一分野）

组内有 post 的多余 pre 共 **644** 条，间隔分布：中位 **1.0s**，最小 **0.0s**，最大 **740230.0s**。以 **60 秒**为界：≤ 界进 E3（重复写），> 界进 E8（更可能是两次真实调用丢了一条 post）。界上 **28** 条、界下 **616** 条。

★ 这条界线是**描述性**的，不是判据：账本里没有字段能区分这两种成因。换一个阈值会改变 E3/E8 的分配，但**不改变** `calls−posts` 与恒等式。

## 7 判定

**无红项。**

- calls−posts−blocked = 1321：**这个减法不该等于 0**，它把 E3/E5/E6b/E7/E8 全当成「被拦」了；正确口径是 `calls − posts` = 1668
- E6b session_continued = 574（硬残差：放行、会话继续、就是没有后记录）

## 8 结论（每条都由上面的数算出来）

1. **差额可以逐条归因，一分钱不剩。** 加向出口合计 **1709**，减掉 E4 的 **41**，净额 **1668**，与 `calls−posts=1668` 逐桶对齐（全部成立）。这就是 `I1-02` 从没做过的那次减法。
2. **`calls − posts − blocked` 这个减法本身是错的，而且错两处。** 它等于 **1321**，既不是 0，也不该是 0：
   - 错一：它假设「没有后记录的都被拦下了」，可真正由拦截解释的只有 **E1=301**，其余 1367 条差额由 E3／E5／E6a／E6b／E7／E8 解释（净额，已扣 E4），它们**跟拦截毫无关系**。
   - 错二：`blocked=347` 里本身含 **46** 条重复写下的 pre（实测这 347 条 block 记录只分布在 **301** 个组里，每组首条都是 block、且一条 post 都没有 ⇒ 多出来的 46 条是同一次拦截被记了两遍），所以它连「被拦了几次」这个数都不是。
   ⇒ **正确的一步是 `calls − posts`，再逐条归因；不是三个数直接相减。**
3. **离「丢失」最近的那一类，其实是重复写。** E3 共 616 条，集中在 `present_files`（363 条）、`Bash`（104 条）、`WebFetch`（57 条）、`show_widget`（57 条） —— 这几个工具的 posts 恰好是 calls 的一半左右。实测同组两条 pre **除 `ts`/`hash`/`prev` 外逐字段完全相同**（相隔 1 秒），是**同一次调用被记了两遍**，不是两次调用。
   ⇒ 任何用 `pre_tool_use` 条数当「动作数」的报告，在这几个工具上**分母虚高近一倍**；而 E8 那 28 条相隔超过 60 秒的，更像「两次真实调用丢了一条 post」，两者在账本上分不开，故单列。
4. **`deny` 是守住的。** E2 = **0**：没有一条「拦了却仍然执行」。这是本次对账唯一一条正向结论，也是唯一能用账本自证的。
5. **硬残差 574 条，机制已确认一半。** 其中 Bash 212 条、非 Bash 362 条。非 Bash 那一半的机制已实测确认：**工具层报错（如 `old_string` 不存在）时宿主不发 `PostToolUse`** —— 本轮用一条注定失败的 `Edit` 做正控，它留下 1 条 `pre_tool_use`、0 条 `post_tool_use`，而其后紧邻的 Bash 调用都正常留痕；另测得 Bash **非零退出仍会留 post**（1051 条 `exit_code≠0` 的 post 在账），所以 Bash 那 212 条**不是**同一种机制，仍属未解释。
6. **「被拦下」在账本里有三个名字**（见 §5）。按 `block` 统计拦截次数会漏掉 `command_deletion_permission` 的 `deny`，按 `deny` 统计会漏掉 pre 的 `block`。**两个词单独用都是错的。**
