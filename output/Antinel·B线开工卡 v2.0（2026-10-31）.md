# Antinel · B 线开工卡 v2.0

> 2026-10-31 22:30。**这份文件是 B 线的唯一开工依据**，自包含：不读别的文档也能干。
> 上一版《B 线独立开发作业单 v1.0》写于 20:20，其中 B-1／B-5／B-6／B-8 已完成，
> 落点结论也已被一条实测推翻（见 §1 铁律 1）。**本版取代 v1.0，v1.0 留作历史。**
>
> 三线并行中：**A 线（0.64 去噪）在 `.worktrees/a064`；C 线在 `output/lineC/`（国际版已在写）；
> B 线（本文件）在主工作区 `output/lineB/`。三条线共用一个仓。**

---

## 0 一句话说清 B 线是什么

B 线是**只读的审计线**：读账本、出证据、写测量工具。它不改产品代码，所以它**永远不阻塞发布**；
代价是它的产物在合入前**不算交付、不进任何分母**。

---

## 1 三条铁律（违反即作废，不是建议）

### 铁律 1 · 留在主工作区，**绝对不要进 worktree**

`.psl/` 在 `.gitignore` 里，worktree 不会把它带过去。**任何在 worktree 里跑、要读审计账本的探针，
都会读到 0 条**，而 `0` 长得像结论（"没有异常记录"），实际是探针失明。
实测：`.worktrees/a064/.psl` 不存在。A 线进 worktree 是因为它改产品代码；B 线**必须留在主树**。

### 铁律 2 · 只写 `output/lineB/`

`hooks`／`scripts`／`tools`／`rules`／`psl`／`assets`／`challenge` 这 7 个面**都会被打进 wheel**
（`pyproject.toml` 的 `packages` ＋ `package-data` 的 `hooks = ["*.py"]`）。
往这些面新建 `.py` ⇒ 清单里没有它 ⇒ A 线出包必红（`S2-483`／`D-36`）。
`output/` 在清单里 0 条、在 sdist 里 0 成员 ⇒ **只有这里安全**。
仓根的单文件模块也在 `py-modules` 里，同样不能新建。

### 铁律 3 · 四类东西一律不碰

| 不碰 | 原因 |
|---|---|
| 产品代码（`hooks/*.py`、`audit_chain.py`、`state_registry.py` 等） | 补丁额度 3/3 已满，任何产品改动只能排队进 0.64 |
| 版本号、`psl/manifest.json`、`psl/workspace_facts.json` | 这是 A 线的独占面，改一个字节就要重签清单 |
| 全量闸门 `ci/delivery_gate.py` | **不要直接调用它**。闸门是独占资源，且它的锁按「工作区根」算 ⇒ 各线各建一把锁、互不可见 ⇒ 并发。**唯一入口见 §4.5** |
| `.workbuddy/memory/` | 并行约定 v1.2 §4.1 记着的 git 够不到的死角，三线各写各的必冲突 |

**发现产品缺陷怎么办：写证据卡，不改代码。** B-6 已经撞到一个真实缺陷
（`audit_chain.py:593` `except: man = {}` 后覆盖整份日锚，历史锚无声消失），
处理方式就是记录 + 排队，不是顺手修。

---

## 2 已完成，**不要重做**

| # | 产物 | 结论（一句话） |
|---|---|---|
| B-1 | `chain_calendar.py` ＋ `test_chain_calendar.py` | 三条腿自检通过；复现 2026-09-30、10-01、10-02、10-04 四个空洞 |
| B-4 | `B4_closure_triad_draft.md`（146 行） | 闭环三件套字段表 ＋ 状态机**草案**，未定稿 |
| B-5 | `b5_ledger_read_coverage.py` | 34 类记录、**0 类读侧**；正控造 `ledger_read` 必命中、负控 `pre_tool_use` 必不误判 |
| B-6 | `b6_retention.py` | 33 日文件／126.5 MB／覆盖 36 天／4 空洞；**推翻方案书"零删除"断言**：AST 查得 3 处 `os.replace` |
| B-8 | `b8_day_anchor_page.py` ＋ `day_anchor_page.md` | **33 天只有 31 天有锚**，缺 09-25 与 10-05，其中 10-05 是活缺口 |
| 证据卡 | `B5B6_ledger_blindspots.md` | B-5／B-6／B-8 合并证据，含限定语 |

已提交并推送：`c5a1f43`（B-8 与证据卡）。B-5／B-6 在 `6b6f2c9` 里。

---

## 3 待做：四个任务，按优先级

### B-2 · `I1-02` 对账（**最高优先，完全没开工**）

**出处**：方案书 §7.2 步 5「接上 `I1-02`：`calls − posts − blocked`，先看那 27 个桶」。

**做什么**：新建 `output/lineB/b2_i1_02_reconcile.py`，按 `(type, decision)` 分桶做加减法对账。

**为什么它最优先**：这是唯一能把"账本上的三个数能不能互相对上"变成可证伪结论的活。
如果对不上，说明有出口没记账 —— 那比任何 UX 问题都严重。

**验收口径（先写死，做不到就是没做完）**：

1. **分母现取现报**，且带读取时刻（`2026-10-31 22:18` 读数：33 个日文件 / 163,533 条）。
2. 每桶 `calls`／`posts`／`blocked` 必须可加和，差额**逐桶归因到已命名的出口**。
   **不许"其他"兜底** —— 兜底桶就是缺陷藏身处。
3. 三条自证腿：
   - 正控：人造 3 条记录（1 call、1 post、1 block）⇒ 差额必须为 0；
   - 负控：人造 1 条只有 call 没有 post ⇒ 差额必须为 1 且归因到该桶；
   - 可读：必须打印「读到几个文件、几条记录」，防"读到 0 条也是差额 0"。
4. **必须排除 `lock_events.jsonl`**（它不是日文件，混进来会把日期解析错 —— B-6 已被它坑过一次）。

**已知的坑**：`post_tool_use` 的裁决记在 `action` 字段而**不是** `decision`（45,777 条 `action=record`）。
按 `decision` 分桶会把执行侧整类漏掉。**分桶键要用 `(type, decision, action)` 三元组**，
或者至少打印一张 `decision × action` 交叉表让读者看见这件事。

### B-3 · `verify_chain` 三腿攻击（**脚本已在，无结论，重跑**）

**出处**：方案书 §9.3 未核实清单第 7 条，原文标「**未跑**」。

**现状**：`b3_verify_chain_attack.py`（126 行）已写，上一轮跑成 `aborted`，**没有拿到结果**。

**三腿**：① 对照（不改）② 重写 ＋ 同步清单 ③ 重写 ＋ **不**同步清单。

**验收口径**：在系统 TEMP 建副本跑，仓库零写入。
**第三腿是关键**：若 `exit=0`（不报篡改），说明"日锚"没有牙齿 ⇒ `DEC-11` 必须重新论证。
**这是结论，不是失败** —— 不许因为"结果不好看"而改判据。

**跑之前的硬前置**（本机实测，踩过三次）：

```
TMP/TEMP/TMPDIR = C:\Users\大马\AppData\Local\Temp
```
本机只有 `%LOCALAPPDATA%\Temp` 能删目录；`C:\Temp` 与 D 盘整盘都 `WinError 5`。
不设这个，任何需要建临时树的脚本必红。

### B-9 · 两个缺锚日的根因（B-8 暴露的活缺口，新任务）

**做什么**：查清 2026-09-25 与 2026-10-05 为什么没有日锚。

已知：10-05 不是空洞日、442 条记录在，却没锚 ⇒ 那天**尾部截断与整文件重写今天检不出来**。
B-8 的推断是"锚只在写记录时更新"，但**没验证**。

**验收口径**：对这两天各给出一个可复现的判定 —— 是"当天没有写入"、"写入路径绕过了锚"、
还是"锚被覆盖掉了"。**必须能回答"下一次什么时候会再发生"**，否则只是描述现象。

**边界**：只读 `.psl/audit/day_manifest.json` 与日文件，**不改锚**。修是 0.64 的事。

### B-4 · 闭环三件套定稿（草案 → 定稿）

**现状**：146 行草案，字段表与状态机有了，但**没有走查**。

**要补的三条走查**（缺一条不算定稿）：① 正常闭环 ② 超时未回复 ③ 复查推翻原判。
每个字段必须能答"谁填／何时填／填错怎么更正"。

**为什么值得做**：方案书 §5.5 记着"闭环三件套与更正机制（**全空**，批 2 的硬阻塞）"。
这是批 2 能不能启动的前置，且**纯文档、零代码风险**。

---

## 4 开工第一条命令（照抄）

```bash
cd /d/psl/poc/antinel-security
export TMP="C:\Users\大马\AppData\Local\Temp" TEMP="C:\Users\大马\AppData\Local\Temp" TMPDIR="C:\Users\大马\AppData\Local\Temp"
# 先确认落点对不对（三个数都要对上）
ls -d .psl/audit                      # 必须存在，不存在说明你在 worktree 里
ls .psl/audit/*.jsonl | wc -l          # 22:18 读数 33 个日文件（含 1 个 lock_events）
git rev-parse --abbrev-ref HEAD        # 应为 main
```

Python 用 `/c/Users/大马/.workbuddy/binaries/python/versions/3.13.12/python -E -X utf8`。
**不要用裸 `python`**：默认解释器不带 `setuptools`；而 `python` 若解析到 Windows Store 占位符，
会静默返回 `rc=0` 且零输出。

---

## 4.5 全量闸门：**三条线只有一条入口**（这是"不一起卡死"的唯一硬机制）

**不要**直接 `python ci/delivery_gate.py`。原因不是纪律，是缺陷：

闸门自己**有锁**（`_acquire_lock()`：`O_CREAT|O_EXCL`、三态判活、"拿不准按占用"、
陈旧锁改名让开——实现是完整的），但锁路径是

```
_SNAP_DIR = ANTINEL_GATE_STATE_DIR or <工作区根>/.psl/gate
```

而 `.psl/` 在 `.gitignore` 里 ⇒ **worktree 里没有 `.psl`** ⇒ 主树锁在
`D:/psl/poc/antinel-security/.psl/gate/run.lock`，a064 树锁在
`.../.worktrees/a064/.psl/gate/run.lock`，**两把锁互不可见**，于是两个闸门可以同时跑。

后果不是慢，是**读数被污染**：2026-10-13 实测两个闸门并发，日志被交错写成一行
"0481 RED"，追了 20 分钟幽灵红，最后靠基线快照才证明那次其实是 30/30 全绿。

**修法：不另造一把锁，三条线指向同一个状态目录，用闸门自带的锁互斥。**

```bash
# 唯一入口（在主树或任意 worktree 里都行，脚本自己算路径）
bash /d/psl/poc/antinel-security/output/tools/gate_all.sh --status   # 先看谁在跑
bash /d/psl/poc/antinel-security/output/tools/gate_all.sh            # 全量 34 套
bash /d/psl/poc/antinel-security/output/tools/gate_all.sh --only 0431 # 单套（秒级）
```

脚本只做三件事：把 `ANTINEL_GATE_STATE_DIR` 固定到**主仓根**的 `.psl/gate`、
设好本机的 `TMP/TEMP/TMPDIR` 硬约束、原地跑闸门。

**已实测三条腿**（不是设计意图）：

| 腿 | 做法 | 结果 |
|---|---|---|
| 跨树互斥 | 主树造空锁，**从 a064 树**跑闸门 | `★ 闸门未启动：另有一次闸门正在跑…**不许并发**`，rc=3 |
| 不被误挡 | 清锁后从 a064 树跑 `--only 0431` | 18 绿 / 0 红，4.2s，rc=0 |
| 状态共享 | 上一条的结果落点 | 写进 **主树** `.psl/gate/last_run.json`，证明 state dir 真的共享 |

**空锁也要当占用**：写 pid 与创建文件之间有空窗，闸门把「空内容」按占用处理。
所以看到 `run.lock` 存在就先等，不要去删它 —— 陈旧锁闸门自己会改名让开。

**B 线本身不该跑全量闸门**（这是 A 线出包前的事）。这条写在这里，是为了万一你要跑，
别用错的调用方式把另外两条线带进坑。

---

## 5 提交纪律（逐条照做）

1. `git add output/lineB/<具体文件>`，**永远不用 `git add -A`／`-a`**。
2. 提交前 `git diff --stat` **认领每一个已跟踪改动** —— 出现不是你改的文件就停下。
3. 提交说明**写文件再 `-F`**，不要塞进 bash 双引号串或 heredoc（正文里的反引号会被真执行）。
4. **提交前先 `git status --porcelain | grep -v '^??'`**：如果看见 `hooks/`／`ci/`／`psl/` 的 M，
   那是 A 线正在动的文件，**不要提交它们，也不要撤销它们**。
5. 推送前量分叉 `git rev-list --left-right --count origin/main...HEAD`。
   **`ahead N` ≠ 能推**，还要看 behind。当前状态：**1 个提交待推，推送报 `CONNECT tunnel failed, response 502`**，
   这是网络故障（记忆中反复出现），不是本地问题 —— 重试即可，别改 git 配置。

---

## 6 与 A 线（0.64）的三个接口

| 接口 | B 线要给 A 线什么 | 什么时候给 |
|---|---|---|
| `audit_chain.py:593` 日锚覆盖缺陷 | 一段能复现的最小步骤（不要修） | B-9 做完时 |
| `decision` vs `action` 双字段 | B-2 的 `decision × action` 交叉表 | B-2 做完时 |
| 锚覆盖 31/33 天 | B-8 已有的对照页 | **已交付**（`day_anchor_page.md`） |

A 线正在做的事（供你判断相关性，**不要去改**）：把 `decision` 与 `notify` 正交化，
唯一实现在读侧推导（`_notify_of()`），账本零改动。

---

## 7 红线清单（贴在手边）

1. 不进 worktree 干读账本的活
2. 不在 7 个随包面新建 `.py`
3. 不改版本号、清单、`workspace_facts`
4. 不跑 `ci/delivery_gate.py`
5. 不写 `.workbuddy/memory/`
6. 不 `git add -A`
7. 不修产品代码（发现缺陷写卡）
8. 不用裸 `python`
9. 不排除 `lock_events.jsonl` 就读账本
10. 报数不带读取时刻

---

## 8 一句话交接

**B-2 先做**（它是唯一能把"账本自洽"变成可证伪结论的活，且完全没开工）；
B-3 重跑取结论（脚本已有，只差一次干净的运行）；
B-9 查两个缺锚日的根因（B-8 已暴露，尚未解释）；
B-4 补三条走查定稿（纯文档，零风险）。
四个都做完，B 线这一轮就完整了。
