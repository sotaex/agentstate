# Antinel · 并行调试分工 A1：facts 事实源（v1.0，2026-10-22）

> 给**另一位 AI**（下称「执行方」）的任务书。派单方＝主树维护者（下称「主线」）。
> 一句话：**只补 `facts.py` 的取数，不动任何别的产品文件**。主线的面是渲染接线（X），
> 与本任务的**文件交集为零**。

---

## 0 开工前的两个自检（先做，别跳）

```bash
cd /d/psl/poc/antinel-security
git log --oneline -3
git status --short facts.py
```

- 若 `git log` 里**看不到**标题含 `fix(投影入口)` 的提交 ⇒ 主线那批改动还没落，**只做只读
  核对与写探针**，不要改 `facts.py`；等能看到了再动手。
- 若 `git status --short facts.py` **不是空** ⇒ 有人正在改这个文件，**停下**并报告，不要覆盖。

运行时一律用这一串（用户 shell 的 `python` 是商店占位别名，会静默 rc=0）：

```bash
PYTHONPATH= TMP=D:/_antmp TEMP=D:/_antmp TMPDIR=D:/_antmp \
  "C:/Users/大马/.workbuddy/binaries/python/versions/3.13.12/python.exe" -E -X utf8 <脚本>
```

临时目录**不许**开在仓内（会带偏 `workspace_roots` ⇒ 判据假红）。

---

## 1 背景（你不需要重新推导，这些是实测）

`facts.py` 的 `collect()` 产出 30 个字段，是投影层（`situation.py`）的唯一输入。
**实测（2026-10-22 20:0x，主树）**：真实采集下 16 个字段是 `None`，进 `trace.missing`：

```
scope_device scope_host is_dev credits_low_open at_risk dev_exempt
chain_integrity_ok partial_read chain_recon gaps outage_consequences
published_version code_version heartbeat_slices notice_state counts
```

`gaps` 已由主线接上（账本派生，实测 887 条缺口族记录，采集耗时 0.04s）。
**剩下的不是「都该接」**：`EXPECTED_MISSING` 里逐条写了为什么没接，其中 6 条是
**待拍板的决策项**（要扩白名单／要指定来源），**不属于你的任务**。

### 与你的任务直接相关的一条实测

`facts.axes()` 的 `harm` 轴只读 `gaps`；`gaps` 接上后实测 `harm=some`、
`cause=breach`、主行「有 732 处没修。」——**灯恒红**。这是设计口径与历史数据的冲突，
主线正在申请裁定，**你不要改 `axes()`、不要改 `gaps` 的算法**。

---

## 2 你的任务（按优先级，逐条独立可验收）

只改 **`facts.py` 里的 `_live_values()`**（必要时加模块级私有小函数），
并在 `owned` 表里为每个新来源登记它负责的字段（失败时错误要精确落到字段上）。

| # | 字段 | 来源（已存在，不许新造） | 口径要求 |
|---|---|---|---|
| A1 | `at_risk` | **派生**，不新增 IO：`at_risk_sources(facts)` 已能从 `granary_balance_hours`／`heartbeat_age`／`egress_free_bytes` 算出三成分 | 返回 `list[str]`（可为 `[]`＝「没有预告源」，不是「不知道」）。必须在所有上游字段填完之后再算 |
| A2 | `code_version` | `antinel.VERSION`（模块常量） | `str`。取不到 ⇒ `None` ＋ `missing`，不许写 `""` 或 `"unknown"` |
| A3 | `published_version` | `psl/workspace_facts.json`（登记位；先 `grep` 确认键名，**不要猜**） | `str`。同一文件里没有该键 ⇒ `None`；文件读不到 ⇒ `sources` 记 `error[...]` |
| A4 | `notice_state` | `inbox_notify.outcome_of()`（B2 已实现，返回含 `state` 的 dict） | 只搬 `state` 一个值（`str`）。**注意词法**：`unknown`＝确知没送达，`undecidable`＝判不了，**不许合并成一个词** |
| A5 | `heartbeat_slices` | `heartbeat.py` 的切片目录（144 片/天） | `list`。**这是唯一可能超预算的一条**：先只读实测单次耗时，> 200ms 就写进报告并**暂缓**，不要为了接上而让它拖慢每一次 `collect()` |

### 明确**不属于**你的（六个决策项，别碰）

`scope_device`／`scope_host`／`is_dev`／`dev_exempt`／`credits_low_open`／
`outage_consequences` —— 缺的是「白名单该不该扩／真实来源是哪个符号」的裁定，
不是取数代码。你要接它们，必须先有裁定。

同理 `chain_integrity_ok`／`chain_recon`／`partial_read`／`counts` 分属 N10／N7／N9，
是主线那边的改造面（会动 `audit_chain.py` 与扫描器），**本轮不做**。

---

## 3 纪律（这些是本仓踩出来的，违反即返工）

1. **取不到 ≠ 取到空**：`None` 只表示「查不到」；`[]`／`0`／`False` 只表示「查过了，如此」。
   **禁写 `facts.get(k, 默认)`**，那正是静默默认。
2. **口径不许写第二遍**：族界、等级、状态词一律从现有模块取（`inbox_model.LEVEL_OF_KIND` 等），
   不许在 `facts.py` 里抄一份表。抄一份 ⇒ 两边漂移 ⇒ 判据测的是副本。
3. **不新增外部依赖、不重新实现已有函数**。你要的东西本仓都有，找不到就报告，不要造。
4. **写盘用二进制**（`io.open(p,"wb")`）；本仓 `facts.py` 行尾是 **LF**，写完
   `git ls-files --eol facts.py` 必须仍是 `w:lf`。文本模式写入会把行尾换掉，产生整文件假 diff。
5. **批量改源码禁按行号区间**：一律「精确片段 ＋ 断言出现次数恰好 1，对不上整批不写盘」。
6. **一次采集只调一次来源**：`collect()` 每次调用都可能被页面渲染走，单次预算
   目标 **< 100ms**（现状 0.04s）。超了就说明你在某个来源上做了重活。

---

## 4 你要交的东西

### 4.1 判据（自己写，`output/_p_facts_src.py`，git 忽略、不入库）

- **正控**：每个新接字段在真实采集下类型正确、值域正确、且**不再出现在 `missing` 里**。
- **负控（必须有，且必须实测判红）**：对每个来源做一次破坏（把来源函数换成抛异常／
  把登记文件改名／把返回值换成非法形状），**同一个检查函数**必须报红。
  「写了负控但没执行」是本仓最常见假绿（曾有 90 条负控挂了清单一次没跑）——
  驱动要**逐条执行、正负分开计数**。
- 输出末行固定格式：`结论: PASS（正控 N／负控 M，问题 K）`。

### 4.2 报告（回给主线，不要写进仓里）

一张表：字段 | 改前 | 改后实测值 | 采集耗时增量 | 负控编号 | 备注。
外加两条结论：① `collect()` 总耗时改前/改后；② 还剩哪些 `missing` 与为什么。

### 4.3 提交

```bash
git commit --no-verify --only -- facts.py -F <说明文件>
```

`--no-verify` 的理由写进提交正文（本仓钩子会红两条**改前就红**的项：
`built_from` 指主树、`dist/` 无当前版本产物）。**只 add `facts.py`**，
禁 `git add -A`、禁 `git add .`、禁 amend。

---

## 5 禁止清单（红线）

- 禁改 `situation.py`／`inbox_server.py`／`inbox_bubble.py`／`inbox_tray.py`／
  `state_registry.py`／`inbox_notify.py`／`audit_chain.py`／`psl/manifest.json` ——
  全是主线正在动或将要动的面。
- 禁跑 `ci/delivery_gate.py`（主线正在跑全量闸门，同一棵树上并发跑会互相拖成假红）。
  你只跑自己的 `output/_p_facts_src.py`。
- 禁重启 console／serve／守护进程，禁改 `~/.antinel/` 下任何东西。
- 禁装包、禁改 `pyproject.toml`（加模块会扩大 STE100 扫描面，连带别的套件红）。
- 禁 `rm`／`del`／`Remove-Item`／`schtasks`／写 `.env`（产品自己的 hook 会拦，别撞）。

---

## 6 一句话验收

`facts.collect()` 在真实主机上跑，五条新字段里**至少 A1–A3 三条**有真实值、
进不了 `missing`；A4 有值或如实报「读不到」；`output/_p_facts_src.py` 正负控
全绿且负控**真的执行过**；`git ls-files --eol facts.py` 仍是 `w:lf`；
`collect()` 单次耗时 < 100ms。
