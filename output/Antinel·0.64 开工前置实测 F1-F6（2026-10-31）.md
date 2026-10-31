<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0.64 开工前置实测：F1–F6 六项全部补齐（2026-10-31 21:5x）

**一句话：《0.64 契约草案 v0.1》§5 列的六件"今晚确认不了、必须明早用 grep 补"的事实已全部量出，
其中三项读数**推翻**该草案的既有假设，契约需升 v0.2 才能开工。**

> 全部读数来自本机实跑，只读、未改任何产品文件。
> 重算命令：`python output/lineA/f064_frontwork_probe.py`（F1–F4/F6）、
> `python output/lineA/f064_ledger_probe.py`（F5 + 三个面）。
> **数字会随代码与账本变化，引用时必须标「读取时刻」并重跑，不要引用本卡的绝对值。**

---

## 1 六项事实（按契约草案 §5 的编号）

### F1 `decision` 一共有几个取值 —— **不是 3 个，是 9 个**

代码里（`hooks/`+`ci/`+`scripts/`，72 个 .py、90,078 行，19 个文件命中）：

| 取值 | 出现形态 | 样例 |
|---|---|---|
| `allow` | 字面量比较 + 写入 | `hooks/pre_tool_use.py:5321` |
| `block` | 字面量比较（31 处，最多） | `ci/drift_audit.py:303` |
| `alert` | 字面量比较 + 写入 | `hooks/pre_tool_use.py:5152` |
| `warn` | 字面量比较 | `ci/inbox_guards_0490.py:5697` |
| `deny` | **只在写入点出现** | `ci/inbox_guards_0400.py:429` |
| `config_fallback` | 只在写入点 | `hooks/pre_tool_use.py:1289` |
| `config_rejected` | 只在写入点 | `hooks/pre_tool_use.py:5416` |
| `finding` | 只在写入点 | `scripts/report.py:315` |
| `None` | 写入点直接给 None | `hooks/pre_tool_use.py:5316` |

**契约草案 §3 的回退表只覆盖 `alert`/`block`/`allow` 三种。**
剩下 6 种没有归属 ⇒ 按现表推导，`deny` 与 `block` 会落到表外（行为未定义）、
`config_*` 会落到表外、`None` 会落到表外。

### F2 有几处**写** `decision` —— **60+ 处，8 个文件**

`ci/inbox_guards_0353.py` 16 处、`hooks/pre_tool_use.py` 19 处、`scripts/verification_tests.py` 10 处、
`ci/inbox_guards_0420.py` 3 处、`ci/inbox_guards_0400.py` 2 处、`ci/inbox_guards.py` 2 处、
`hooks/post_tool_use.py` 2 处、`scripts/report.py` 3 处、`scripts/install.py` 1 处、
`hooks/session_start_banner.py` 1 处、`ci/inbox_guards_0372.py` 1 处。

**契约草案 §6 说 0.64「只碰写入点与读侧」，隐含"写入点不多"。实际写入点是 60+ 处。**
这是头号顽症「同一事实多处实现」的标准形状 —— 若 `notify` 逐个写在这 60 处，
0.64 会新增 60 处同类实现，问题从 1 个字段变成 2 个字段 × 60 处。

### F3 有几处**读** `decision` 做判断 —— **16 处，6 个文件**

`scripts/report.py` 7 处（含 4 处下标取值）、`scripts/verification_tests.py` 3 处、
`ci/drift_audit.py` 2 处、`hooks/pre_tool_use.py` 2 处、`hooks/post_tool_use.py` 1 处、
`ci/inbox_guards_0517.py` 1 处。

⇒ `_notify_of(rec)` 若要「读侧唯一」，这 16 处必须全部改道。**漏一处回退就没有唯一性。**

### F4 `emit_block` / `notice_gate` 是否同一出口 —— **不是，是两个出口**

| 出口 | 定义 | 调用点 | 通道性质 |
|---|---|---|---|
| `emit_block` | `hooks/pre_tool_use.py:3941` | 3 处（:5216 / :5499 / :5528） | block：exit(2)，无条件写 |
| `notice_gate` | `hooks/pre_tool_use.py:3765` | 6 处（:1481 / :4628 / :5401 / :5422 / :5513 等） | alert：单规则 1h 3 次抑制 |

**契约草案 §5 F4 问"是否都经同一个出口"，答案是不存在合流处。**
⇒ N2（`block` ⇒ `gate`）的强制点只能在 `emit_block`，
N4（规则不能自行把 `gate` 降 `silent`）的强制点只能在 `notice_gate`，
**两条不变式必须分别落在两个函数里**，写在一处等于只覆盖一条通道。

### F5 账本里 `decision` 的当前分布 —— **要看是哪个账本，这是本次最重要的发现**

| 面 | 位置 | 形态 | 读数（21:55） |
|---|---|---|---|
| **面 A** | `~/.antinel/ledger/daily.jsonl` | **单文件累积的日汇总** | 1,311 条，键只有 `acked/blocked/breached/date/noticed`，**`decision` 100% 为 None** |
| **面 B** | `.psl/audit/*.jsonl` | 日分片审计记录 | **163,287 条**，`decision` 有 7 种取值 |

面 B 的真实分布：

| decision | 条数 | 占比 |
|---|---|---|
| `None` | 86,379 | **52.9%** |
| `allow` | 55,004 | 33.7% |
| `alert` | 20,012 | 12.3% |
| `deny` | 1,195 | 0.7% |
| `block` | 672 | 0.4% |
| `config_refresh` | 15 | 0.0% |
| `config_fallback` | 10 | 0.0% |

**三处推翻契约草案：**

1. **§4 的取数面写错了。** 草案给的校准命令读 `~/.antinel/ledger/daily.jsonl`，
   而那个面里 `decision` 字段**根本不存在**（1311 条全是 None）。照那条命令核 18,815，
   只会得到 0 —— 然后被误读成"数据丢了"。真值在面 B。
2. **52.9% 的记录没有 `decision` 字段。** 契约草案完全没提这个多数派。
   回退表对 `None` 无定义 ⇒ 这 86,379 条在 0.64 之后到底算不算"需要人看"，
   是一个**必须拍板**的问题，不是实现细节。
3. **`warn` 在账本里 0 条。** 契约 §2 要把 `decision` 收窄成 `allow/block/warn`，
   但账本里从来没有 `warn`；反过来账本里有 `deny`、`config_refresh`，
   而 F1 的代码取值集合里**没有 `config_refresh`** ⇒ 该值由本次扫描面之外的写入点产生，
   说明**扫描面没覆盖全部写入者**（`hooks/`+`ci/`+`scripts/` 之外的模块也在写账本）。

### F6 值守台读的是哪个面 —— **第三个面，两个账本都不是**

`day_counts` / `ledger_rows` / `render_view` 三者的定义都在根 `inbox_model.py`
（:1914 / :1951 / :3074），消费链是：

- `antinel.py:1390` → `_M.ledger_rows(_ST.load_items_all(), days=days)`
- `inbox_daemon.py:88` → `M.day_counts(items, days=window)`
- `inbox_server.py:926` → `M.render_view(p, items, ...)`

**数据源是 `state_registry.load_items_all()` 的 items，不是面 A、也不是面 B。**
⇒ 契约 §3「回退必须只有一处实现，读侧所有消费点都走它」这句话，
要落地就必须同时回答：**`_notify_of(rec)` 的 `rec` 来自哪一面？**
三个面三条链，一处实现只能覆盖一条链 —— 剩下两条就是「账本改对了、页面还是老数字」。

---

## 2 探针自身两次失败（照实记录，因为它们都是本项目的常见病灶）

**失败一：漏了一种读取形态。** 第一版只把 `.get("decision")` 当读，
`d = rec["decision"]`（下标取值）没被算作读 ⇒ 正控样本断言失败。
补 `visit_Subscript` 的 Load 分支后通过。**产品代码里下标取值占 F3 的 4/16，漏了就少算四分之一。**

**失败二：拿一个面的尺子去量另一个面。** 第一版用「必须是 `YYYY-MM-DD.jsonl`」筛面 A，
结果 `daily.jsonl` 被判成非日文件，**整个面读成 0 条**。
两个账本形态本来就不同（面 B 日分片、面 A 单文件累积），共用一把尺子必然一边读空。
修正后各面用自己的约定。**这条与 F5 第 1 点是同一个病：尺子与被量对象不同源。**

两条都靠自证腿抓到 —— 若没有正控样本和"打印读到几个文件"，两次都会静默出错、
并且输出会以「0」的形式看起来非常正常。

---

## 3 对 0.64 契约草案的修订建议（三条，落地前必须做）

| # | 草案原话 | 实测 | 建议 |
|---|---|---|---|
| R1 | §4 校准命令读 `~/.antinel/ledger/daily.jsonl` | 该面无 `decision` | 改读 `.psl/audit/*.jsonl`，并注明"面 A 是日汇总，不是审计账" |
| R2 | §3 回退表覆盖 3 种取值 | 实际 9 种（代码）/ 7 种（账本） | 回退表补 `deny→gate`、`config_*→toast`、`None→`（待拍），并把 `None` 单列 |
| R3 | §5 F4 假设有"合流出口" | 两个出口，无合流 | N2 落 `emit_block`、N4 落 `notice_gate`，分别写判据 |

**另有一条不在草案里、但实测撞出来的：**
`config_refresh` 出现在账本里但不在 F1 的代码取值集合里 ⇒
**0.64 开工前必须先把「谁在写账本」的扫描面扩大**（至少覆盖根目录的 `inbox_*.py`、
`state_registry.py`、`ledger.py`），否则会漏掉一整类写入者。

---

## 4 本卡不回答什么

- 不回答 `None` 该回退成什么 —— 这是产品判断，需要创始人拍板（见 §3 R2）。
- 不回答三个面要不要合成一个 —— 那是 0.64 之后的事，本轮只记录三面并存。
- 不承诺条数趋势：账本 30 天滚动，明天重跑数字必然不同。
