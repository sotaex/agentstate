# 0.64 去噪：`action` / `decision` / `notify` 三层正交（契约 v0.3 · 定稿）

> 2026-10-31 22:40。v0.2 的两件待拍板**已拍**（P1＝按 type 分层后再定音／P2＝不落盘），
> 拍板后做的分桶测量**推翻了 v0.2 的问题提法**，并挖出比 `decision` 更要紧的东西：
> **`action` 是第四个取值域，而 `decision` 是它的不完整派生量。**
> 本稿把实现路线定死，可以直接照着写代码。

---

## 1 一页结论

| 项 | v0.2 的假设 | 实测（2026-10-31 22:18，163,533 条） |
|---|---|---|
| 无 `decision` 的记录 | 86,379 条"字段缺失，需要回退兜底" | 86,508 条里 **99.96% 只有三个 type**，且**风险面 0 条** |
| `decision` 取值 | 11 个（代码面） | 11 个，但**其中 7 个只写不判** |
| 与之并存的字段 | 未提及 | **`action`（allow/record/alert/block），46,415+45,776+12,532+520 条** |
| 两字段关系 | 未提及 | `decision` 是 `action` 的**不完整派生**：`pre_tool_use.py:5434` 写着 `decision="block" if action=="block" else "alert"`，但另有多处写入点各自为政 ⇒ **944 条 `allow`+`alert`、175 条 `deny`+`block`** |

**所以 0.64 不是"加一个字段"，是给三个已经在混用同一批词的东西分层：**

```
action    做了什么     allow / record / alert / block       （写入者给，事实）
decision  判成什么     ← 收敛为 action 的纯函数：f(action, severity)   （派生，不独立写）
notify    要不要打扰   ← 收敛为 (decision, type) 的纯函数             （派生，不落盘）
```

`notify` 是本次新增；`decision` 从"各处自写"收敛为"一处派生"——**后者才是去噪的主体**。

---

## 2 为什么 v0.2 的 P1 提法错了（这条必须记住）

v0.2 §6 写「86,379 条无 `decision` 回退成什么」，暗示这是个**字段缺失**问题。分桶后：

| type | 条数 | 有无 decision | 性质 |
|---|---|---|---|
| `post_tool_use` | 45,777 | 无 decision，但有 `action=record` | **裁决记在别名里**，不是缺失 |
| `usage_delta` | 40,695 | 无 decision，无 action | 计量记录，**结构上不属于裁决面** |
| `session_dna` | 33 | 无 decision，无 action | 会话汇总，同上 |

三类合计 **86,505 / 86,508 ＝ 99.96%**；名字含告警词且无 decision 的记录 **0 条**。

⇒ **"52.9% 的记录没有 decision"这句话本身是错的**：它把"这类记录不属于这个字段的适用范围"
说成了"字段缺失"。**一个数承担了两个分母**（F40 的典型形状）。
真正"该有而没有"的条数是 **0** —— 不存在需要 `silent`／`toast` 兜底的那批数据。

**P1 定案（按拍板"先按 type 分层"）**：

| 情形 | notify | 理由 |
|---|---|---|
| `type` 在**非裁决白名单**（`usage_delta`／`session_dna`） | `none` | 结构上不是事件，不进通知面。**这不叫静音，叫不适用** |
| `action == "record"`（`post_tool_use`） | `none` | 执行事实，已被 `pre_tool_use` 的裁决覆盖 |
| 其余：有 decision 或 action | 走回退表 | 见 §3 |
| **其余 type 但两字段全无**（未来新 type 忘了写） | `toast`（**不是 none**） | **默认多报，不少报** —— 新 type 遗忘时宁可烦一次，不可静默 |

最后一行是本次的关键取舍：**默认值必须偏"吵"，因为漏报不可逆、多报只是烦。**

---

## 3 回退表（定稿，覆盖 decision 11 种 ＋ action 4 种）

按 `decision` 查（`action` 只作补充，因为 `decision` 收敛后是主键）：

| decision | 账本条数 | notify | 说明 |
|---|---|---|---|
| `block` | 520 + 175(`deny`) | `gate` | 已拦下，必须让人知道 |
| `alert` | 20,012 量级 | `toast` | 提醒但没拦 |
| `deny` | 1,195 | `gate` | **与 block 同义，合并**（`command_deletion_permission` 175 条是 `deny`+`block` 并存） |
| `allow` | 46,415 + | `none` | 放行不打扰 |
| `warn` | **0**（代码里只判不写） | `toast` | 0.64 引入目标值，**必须先给第一个写入者**，否则上线即空转 |
| `config_fallback` | 10 | `toast` | 配置失效要让人知道 |
| `config_rejected` | — | `toast` | 同上 |
| `config_refresh` | 15 | `none` | 正常的配置刷新，不该打扰 |
| `finding` | — | `toast` | 报告类结论 |
| `None`（且 type 不在白名单） | — | `toast` | 见 §2 末行 |

**`allow` + `alert` 并存那 944 条（`notice_budget_window_closed` 756／`notice_budget_merged` 150／`hook_slow` 38）**：
这不是矛盾，是**两个字段由不同写入点独立赋值**的产物。
按本表，`decision=allow` ⇒ `notify=none`，但这三类的 `action=alert` 说明它们**本该吵**。
⇒ **这正是 0.64 要修的真缺陷**，也是"`decision` 必须是 `action` 的纯函数"的直接理由：
收敛后 `action=alert` ⇒ `decision=alert` ⇒ `notify=toast`，944 条自动归位。

---

## 4 三个面（v0.1 完全没提，验收必须三面同时读）

| 面 | 位置 | 谁在读 | 22:18 读数 |
|---|---|---|---|
| A 日汇总 | `~/.antinel/ledger/daily.jsonl` | 旧报表 | 1,311 条，**`decision` 100% 为 None**（是 acked/blocked/breached，不是审计账） |
| B 审计真源 | `.psl/audit/YYYY-MM-DD.jsonl` | `audit_chain`／B 线工具 | 33 个日文件 / 163,533 条 |
| C 值守台 | `state_registry.load_items_all()` | `inbox_model.render_view()` | 第三套取数，**不走上面两个** |

**面 A 永远不要用来校准 `decision`** —— v0.1 §4 那条校准命令读的就是它，跑出来必是 0。

---

## 5 实现路线（定稿，可照写）

### 5.1 `notify` 不落盘（P2 已拍）

```python
# hooks/notify_policy.py（新文件，随包）
def notify_of(record) -> str:      # "gate" | "toast" | "none"
    """唯一实现。纯函数，无 IO，无副作用。"""
```

四条后果：写点改动 **0**（70 处一个不动）、账本改动 **0**（不碰"证据不可篡改"）、
N4 **自动成立**（规则设不了 `notify`，无法给自己静音）、历史**自动兼容**（回退表就是函数体）。

代价一处：规则无法显式声明"这条要打扰我"。留可选 `notify_hint` 作渐进路线，本版不做。

### 5.2 `decision` 收敛（本版主体，v0.2 未提）

```python
def decision_of(action, severity) -> str:
    """唯一实现。今天这段逻辑散在 pre_tool_use.py:5434 等 70 处。"""
```

**收敛的范围必须先量后改**：70 处写入点里，哪些是"给 `action` 顺便派生 `decision`"（可收敛），
哪些是"独立判了个 `decision`"（要先判定该不该保留）。
**这是 0.64 的第一个编码任务，也是唯一有回归风险的动作** —— 必须单独提交、单独跑全量。

### 5.3 分步（每步可独立验收）

| 步 | 做什么 | 验收 | 风险 |
|---|---|---|---|
| S1 | 写 `notify_of()` ＋ 单测（纯新增，不接线） | 11 种取值 × 3 类 type 全覆盖，正负控各一 | 零 |
| S2 | 值守台接 `notify_of()`（面 C 一个入口） | 屏上"提醒"条数变化可解释，逐桶对账 | 低 |
| S3 | 量 70 处写入点的 `decision` 性质并分类 | 分类表逐处有行号，无"其他"兜底 | 零（只读） |
| S4 | `decision_of()` 收敛 + 944 条 `allow`+`alert` 归位 | 归位前后条数差 = 944（可精确预期） | **中** |
| S5 | `deny`→`block` 合并、`warn` 给第一个写入者 | 账本新记录不再出现 `deny` | 低 |

S1 现在就能写，S3 是只读。**S4 之前不要动产品代码。**

---

## 6 开工前置（已清零）

| 前置 | 状态 |
|---|---|
| 六件事实 F1–F6 | ✅ 已量（`output/Antinel·0.64 开工前置实测 F1-F6`） |
| 扫描面扩到根目录全部产品模块 | ✅ 127 个 `.py` / 129,264 行 |
| 契约定稿 | ✅ 本稿 |
| A 线独立工作树 | ✅ `.worktrees/a064`（`feat/0.64-dev`） |
| P1／P2 拍板 | ✅ 2026-10-31 22:30 创始人 |
| 版本号 0.64.0.dev0 | ⬜ 待落九处（A 线第一步） |

---

## 7 边界

1. **不承诺数字**。本稿所有条数都是 2026-10-31 22:18 的读数，账本 30 天滚动，重算用
   `output/lineA/p1_undecided_buckets.py`（自带正控/负控/可读三腿）。
2. **不改历史**。任何"把老记录重写成新语义"的方案都不进本版。
3. **`code_freeze` 措辞过期**（写着"功能开发版本从 0.63.0.dev0 起"），随版本落定一并改。
