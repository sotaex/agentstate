<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Antinel · 待修项修复设计 v1.0（2026-10-22）

> 上游：《本轮改动全面审核报告 v1.0》的 A1–A13、九维第 4/6 维、版本号。
> 本件先于编码写成。**编码只许照本件做；做的过程中发现本件错了，改本件再改代码**，
> 不许"代码先行、文档后补"——那正是 PCM-04 那类"判据实现与契约不一致"的成因。

---

## 0. 范围（做什么、不做什么）

**做**：A1–A13 全部 13 条；补 7 条判据与成对负控；九维第 4 维（既有保护连带对照）、
第 6 维（运行态确认）；版本号 `0.53.2 → 0.54.0`（九处承载件）。

**不做**（每一项都有理由，不是遗漏）：
- **不构建、不打 tag、不推 PyPI**：出包是创始人确认的动作。本批只升代码版本。
- **不动 `psl/workspace_facts.json`**：它是**环境事实**真源，不是意图声明。
  只有真要出包时才同步 `release.version`（D-23 的鸡生蛋顺序）。
  不动它的代价：D-23 继续红，理由从"缺 0.53.2"变成"缺 0.54.0"——状态没变坏。
- **不动 `.psl/gate/pcm_ledger.json`**：那是观察记录，抹一行等于给自己开路。
- **不改 `Item.state` 的四态集合**：A1 的修法是"谁能改它"，不是"改它能取什么值"。

---

## 1. 逐条设计

### A1 · 「点开即已读」把已处置/已忽略改回「未修」

**实测**（`output/_p_gap_ui.py`）：`ignored → read` 得 `('read','open',False)`；
`done → read` 同理。ack 撤销、`closed_at` 被 pop、复核计时清零。

**根因两层**：
1. 页面侧：`_item_html` 对**每一行**都发 `data-id`/`data-token`，`_READ_JS` 只看
   `data-readed`；而全仓没有一处输出 `data-readed` ⇒ 展开任意一行都会发 `op=read`。
2. 服务端：`S.set_state(iid, "read")` 无条件执行，**没人问这条现在是什么状态**。

**修法（甲案，两处，都不改「重开」语义）**：

| 位置 | 改动 |
|---|---|
| `inbox_server._item_html` | 非 `unread` 项在 `<details>` 上加 `data-readed="1"` ⇒ JS 早退，不发请求 |
| `inbox_server` 的 `/action` | 取 `_auto = (headers.get("X-Antinel-Read") or "") == "1"`；`op=="read" and _auto` 时**只处理当前 `state=="unread"` 的记录**，其余 `continue`（不写盘） |

为什么用**请求头**做判据、而不是用 `op` 词：用户的「重开」按钮是不带该头的 form POST，
两者 `op` 都是 `read`。用头区分"自动"与"人点"，才既堵住吞缺口、又保住重开。

**门禁放在哪一层**：`/action` 的分发处（唯一写入口），不放在 `S.set_state`。
放 `set_state` 会让"重开"也无路可走，而 `set_state` 是状态机的公共入口。

### A2 · heredoc 正文「管道给解释器」时仍被剥

**实测**（`output/_p_hook_bypass.py`）：`cat <<'EOF' | bash`、`| sh`、`tee … | bash`
三例正文被剥掉，而 bash 照样执行 ⇒ **漏放方向**。

**根因**：`exec_re.search(line[:m.start()])` 只看 `<<` 左边。正文的去向不只在左边，
还可以由 `|` 把 stdout 交给下游解释器。

**修法**：
1. 新增 `_strip_line_comment(line)`：引号感知地剪掉行内 `#` 之后的部分
   （`#` 前必须是行首或空白）。理由：`cat <<'EOF'  # 不是 bash 脚本` 这种注释里的
   解释器词会让判定变成"不剥"⇒ 正文进扫描面 ⇒ 误拦。剪注释是为了**让整行搜索可用**。
2. 判定从 `search(line[:m.start()])` 改成 `search(_strip_line_comment(line))`。

方向说明：整行搜索是"生产者 + 所有下游"的超集。超集只会让**更多**正文留在扫描面
（多拦），不会漏放。**多拦可接受，漏放不可接受**。

### A3 · 丢失计数被静默抹掉（真值 4 报 1）

**实测**（`output/_p_lost_merge.py`）：磁盘满期 3 条 → 恢复后再丢 1 条 →
`lost_pending()` 报 **1**，连 `first` 都退成最晚那条。

**根因**：`_note_lost` 用"盘上 n + 1"写盘，**内存里那几条从没并进去**；写成功就把内存清零。

**修法**：
```python
total = n + _LOST["n"]                     # ★ 盘上 + 内存，缺一即少记
first = cur.get("first") or _LOST["first"] # 起点取更早的那个（or 的顺序就是优先级）
if _write_json("lost.json", {"n": total, "first": first, "last": now}):
    _LOST["n"], _LOST["first"], _LOST["last"] = 0, None, None
```

### A4 · `KEEP_DAYS` 边界抖动（15 vs 16）

**实测**（`output/_p_keepdays.py`）：今天那份存在 ⇒ 留 14；不存在 ⇒ 留 15。

**根因**：`n_days = len(ds["days"])` 把"今天还没建"的那一格算漏了，而删除池
`days` 又排除了今天 ⇒ 两处口径不同。

**修法**：给"今天那一格"预留位置，让两条口径对齐到"**删完后该目录里事件文件数 ≤ KEEP_DAYS**"：
```python
have_today = any(x[0] == today for x in ds["days"])
n_days = len(ds["days"]) + (0 if have_today else 1)   # 今天那份待会会落盘
```
验算：有今天、20 天 ⇒ 删 6 剩 14；无今天、20 个过去日 ⇒ 删 7 剩 13 + 今天 = 14。

### A5 · `lock_pressure.checked` 契约自毁

**根因**：末尾 `if os.path.isdir(...): out["checked"] = True`。它只证明目录存在，
却把自己的契约（"文件读不到 ⇒ False"）作废——**存在但读失败时也被置 True**。

**修法**：
- 删掉末尾 `isdir` 断言。
- 新增 `unreadable: [basename…]`；`open` 抛 `OSError` 时记入。
- `checked = not unreadable`（**「文件不存在」不算失败**：从未记到竞争就是没竞争，
  这是空账本的合法形态；把它算成"没量到"会让每台新机器天天报"读不到"＝狼来了）。
- `inbox_server._lock_line`：`checked=False` ⇒ 显示「竞争读数读不到」一行；
  有竞争 ⇒ 竞争行；其余 ⇒ 空串。

**判据口径调整（与报告不同，理由在此）**：报告写的 P32b 是"事件文件不存在时
`checked` 必须 False"。那会把"空账本"误判成"没查成"，与 `checked` 的用途
（页面敢不敢说"没竞争"）冲突。改为：**存在但读不到 ⇒ False**。
夹具用"把 `lock_events.jsonl` 建成目录"造读失败——跨平台、不依赖权限。

### A6 · `capacity.readable` 算了没人读

**根因**：`dir_stats` 与 `capacity` 都给了 `readable`，`render` 一个字节都没看 ⇒
目录读不到时上屏「账本 0 个文件 0.0 MB」，把"没量到"渲染成"没有"。

**修法**：`render` 里 `if cap and not cap.get("readable")` ⇒ 账本半截改成
「账本目录读不到（不是 0）」，`dir_files`/`dir_bytes` 不上屏。

### A7 · 一句话里两个基准的「天前」

**根因**：`oldest_days` 用 `it.ts`（记录发生时间），`due` 用 `closed_at`（忽略时间）。
一句话里并排出现 ⇒ 读者会以为二者可比。

**修法**：`unrepaired_count` 返回两个**各自具名**的字段，页面只用与复核期同基准的那个：
- `oldest_ack_days`：基准 `closed_at`（= "最早多久没管"）
- `oldest_record_days`：基准 `ts`（= "最老的记录多久了"）
页面文案：「你说过先不管、其实还没修好的：N 条（最早 N 天前就搁下了）。」

### A8 · 「有 N 条没能写进账本」是上界

**根因**：清零那一步失败会重复补记（口径"宁可多记"），所以盘上累计的 `n` 之和是**上界**，
页面按精确值说。

**修法**：文案改「**至少有** N 条记录没能写进账本」。

### A9 · 「账本 N 个文件」把非事件文件也数进去

**根因**：`dir_files` 来自 `dir_stats` 的全目录计数，含 `lost.json`／`current.json`／
`disk_warn.json`／`.tmp`。

**修法**：`dir_stats` 增 `event_files`（`_day_of(name)` 非空的个数）；
`capacity` 透传；`render` 用 `event_files`，文案「账本 N 个日文件」。

### A10 · 句柄与临时名

- `_read_json`：`json.load(open(p))` → `with open(...)`。
- `load_events`：`for line in open(p)` → `with open(...)`。
- `_write_json`：`tmp = p + ".tmp"` → `"%s.%d.tmp" % (p, os.getpid())`
  （两进程同写 `lost.json` 会互踩，`os.replace` 可能搬走半个文件）。
- 残留 `.tmp` 不清理：`enforce_retention` 只删事件文件；残留会被
  `dir_stats.bytes` 计入预算（占空间是事实）。注释写明。

### A11 · `_disk_pressure_once` 绕过丢失补偿

**根因**：用 `_write_line` 直写账本 ⇒ 这条写失败既不重试、也不进 `lost` 计数。

**修法**：改走 `_append(rec)`（自带三段式：补旧账 → 写 → 腾空间重试 → 仍失败记 lost）。
`disk_warn.json` 仍在写成功后落，保持"一天一条"。

**环检查**：`_append` 失败时调 `enforce_retention(force=True)`，它不调 `housekeep`、
也不调 `_disk_pressure_once` ⇒ 无递归。

### A12 · `run()` 与 `tick()` 顺序不同

**修法**：`run()` 的 `housekeep()` 提到 `sample()` 之前，与 `tick()` 一致。
统一为「先维护、再采样、再记账」：A4 的"预留今天那一格"依赖"写发生在 housekeep 之后"。

### A13 · 每次 append 都读一次 `lost.json`

**修法**：内存快判 + 每 32 次写查一次盘：
```python
_ASK = {"tick": 0}
if _ROT_NOTE or _LOST["n"] or _ASK["tick"] <= 0:
    _flush_lost(p)
_ASK["tick"] = _PROBE_EVERY if _ASK["tick"] <= 0 else _ASK["tick"] - 1
```
为什么不能"只看内存"：上一个进程留下的 `lost.json` 只在查盘时才发现，永不查＝永不补。

---

## 2. 判据与负控（成对）

**负控一律按结构摘腿**：改一个变量赋值／一个判据表达式，**不复述旧代码字面量**。

| ID | 守什么 | 负控怎么摘 |
|---|---|---|
| P34 | 自动已读不改 `gap_state`；显式重开要改 | `_auto = (…) == "1"` → `_auto = False` ⇒ 前两条必红 |
| P30b | 管道给解释器不剥；纯数据仍剥 | `search(_strip_line_comment(line))` → `search(line[:m.start()])` ⇒ 三个管道形状必红 |
| P25b | 丢失计数盘上+内存合并 | `n + _LOST["n"]` → `n + 1` ⇒ 必红 |
| P24b | 今天那份缺失时保留天数仍成立 | 删掉 `+ (0 if have_today else 1)` ⇒ 缺今天的形状必红 |
| P32b | 存在但读不到 ⇒ `checked=False` | 加回末尾 `isdir ⇒ True` ⇒ 必红 |
| P26b | `readable=False` 不渲染成 0 | 删 `not readable` 分支 ⇒ 必红 |
| P31b | 两个基准分列、页面只用 ack 基准 | 把页面换回 `oldest_record_days` ⇒ 必红 |
| P30c | **既有保护连带对照**（九维第 4 维）：改扫描面不许削弱既有拦截；也不许把纯数据误拦 | 摘 `_NULL_SINK_RE.sub`／`strip_heredoc_bodies` 的任一腿 ⇒ 对应形状必红 |

"成对"的含义：每条正控必须至少有一个负控，且负控实测红（不是写了就完）。

---

## 3. 九维第 6 维：运行态确认（不是判据，是动作）

进程内全绿 ≠ 线上对。本批改的是**常驻服务**会走的路径（`/action` 的 read 门禁、
`render_page` 的两行、egress 的 `tick`）。收尾必须做：

1. 杀常驻进程（守护进程会按 `url.json` 自动重拉，端口与口令原样沿用）；
2. 从 `~/.antinel/console/url.json` 取 URL 与口令（**唯一真源**，仓内那份是旧缓存）；
3. 回读收件箱页、账本、运行状态；确认新文案/新行为在线上出现；
4. 把回读的时间戳与结论记进工作日志——**没回读＝没完成**。

---

## 4. 施工顺序（依赖优先）

1. `egress.py`：A3 → A4 → A6/A9 → A10 → A11 → A12 → A13（同一文件，一次改完再跑）
2. `hooks/pre_tool_use.py`：A2
3. `audit_chain.py`：A5；`inbox_server.py`：A5 的页面腿 + A1 的两处
4. `inbox_model.py`：A7
5. 版本号九处
6. 判据与负控（先写会让当前树变红的，再写已绿的）
7. 套件 → 全量闸门 → 活体回读

**每一步之前先让对应判据红**（先红后绿）。已经绿的判据不许"顺手改绿"。

---

## 5. 施工中的偏离（施工后补记，逐条说明为什么偏离）

设计不是预言。下面五处是照着做的时候发现"设计本身不够"，改的是设计 + 代码，两边同步。

| # | 偏离 | 为什么 |
|---|---|---|
| D1 | A13 的第一版（只看内存）**是错的**，加了 `_DISK_DIRTY` | 磁盘满时 `_note_lost` 会**落盘成功**（`lost.json` 只有几十字节，通常还写得进）然后清内存 ⇒ 内存 0、盘上 1。此时"内存非空才查盘"让下次写**永不查盘**，那一条丢失再也补不上。**P25 当场抓红**——既有判据拦住了我这次"优化"。 |
| D2 | P32b 的判据口径与上游报告不同 | 报告写"事件文件不存在时 `checked` 必须 False"。那会把"空账本"误判成"没查成"，与 `checked` 的用途冲突（页面敢不敢说"没竞争"）。改为"**存在但读不到 ⇒ False**"，夹具用"目录冒充事件文件"造真实读失败。 |
| D3 | P34 的页面断言从 `render_page` 改成 `_item_html` | 已处置项落归档档，`view="inbox"` 根本不渲染它 ⇒ 断言打在空处。 |
| D4 | P34 的断言顺序调整（渲染断言提到"点成已读"之前） | 顺序反了会让"未读项不许带 data-readed"读到已经是 `read` 的对象 ⇒ 假红。 |
| D5 | 三条判断抽成命名函数（`_auto_read_allowed`／`_merge_lost`／`_keep_target`／`_checked_from`） | 负控要能换掉**同一份实现**。规则内联时，负控只能复制整段代码来测副本，而副本红了不代表线上红。 |

另有两处文案/断言被既有判据打回，属于"改完才发现"：

- **0490 U-25**：新写的"这不等于没有竞争"命中 D8（STE100 禁双重否定）⇒ 改成肯定句"竞争次数暂时无从得知，当时可能发生过竞争"。
- **instrument-selfaudit S48**：新判据把中文断在裸渲染变量 `out` 上 ⇒ 改走 `PC.body()`。

---

## 6. 本件自身的边界

- 本件不预言"修完就没有缺陷"。它只保证**这 13 条有明确关闭证据**。
- A5 的判据口径与上游报告不同，理由已写明；如果这个口径错了，
  错在"空账本算不算没查成"这一处判断，不在实现。
- `_strip_line_comment` 是新增的引号感知解析。它的边界是**单行**：
  跨行引号（`"…\n…"`）不处理——那种形状下注释裁剪可能误判，
  但误判方向是"保留更多内容"（多拦），不是漏放。
