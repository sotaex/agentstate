<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Antinel·五个 TAB 切换卡顿 · 根因分析与方案（只读轮，未动产品）

**日期**：2026-10-20 ｜ **性质**：只读分析（**当日**产品一个字节未动；结论已于
2026-10-21 由创始人拍板并全部落地，见文末 §6 追记）
**方法**：活体 HTTP 实测（curl 计时，pid 67116 / port 5846）＋ 进程内解剖探针
（`ci/_p_tabprof.py` / `_p_tabprof2.py` / `_p_recordday.py` / `_p_chainprof.py`，
sys.path 指主树根，import 活体同源代码）＋ cProfile 热斑 ＋ 判据面 grep。

---

## 0. 结论（先行）

**能解决，且不需要推翻现有架构。** 卡顿由「结构性重复计算」与「当日生长文件必然缓存失效」
两层叠加，再被并行线机器负载放大 2.5–3 倍构成。按性价比排序，前两项即可把
report/health 从当前 20s+ 拉回 3–5s（load 下），且语义零变化、判据面干净。

## 1. 实测数据（全部可复现，非估计）

### 1.1 活体 HTTP 三视角 × 3 轮（并行线在途，机器满载）

| 视图 | R1 | R2 | R3 | 空闲时参照（早前） |
|---|---|---|---|---|
| inbox | 13.42s | 1.41s | 1.43s | 0.84s |
| report | 6.14s | 4.30s | **62.20s** | 1.41s |
| health | 22.11s | 20.18s | 19.01s | 0.79s |
| ledger | 10.42s | 12.69s | 4.56s | 9.88s |
| health_exam | 5.60s | 18.83s | 8.33s | 0.76s |

### 1.2 进程内热态分段（探针，同源代码）

| 阶段 | 冷 | 热（指纹缓存命中） |
|---|---|---|
| `load_items`（7 天，475 条） | 6.40s | 0.07s |
| `load_items_all`（全量，1941 条） | 15.95s | 0.11s |
| `guard_posture` 单次 | 1.23s | ~0.9–1.2s |
| `chain_health`（32 文件 / 66,529 条） | **12.05s** | 0.006s（全命中） |
| `M.day_counts`（1941×14 天） | — | 0.004s |
| `L.load_days` / `L.summary` | — | 0.008s / 0.009s |

### 1.3 链文件体积（`discover_chain_files` = 32 个 / 53.5MB）

大头是**各注册项目的 `.psl/audit/*.jsonl`**（本仓 8 天 ≈ 50MB，单日 4.9–9.5MB）；
hub rollup 极小（3.6–14.6KB/日）。egress 出口审计（79MB）**不进渲染主路径**（已确认无其他消费点）。

### 1.4  synthesised 模型（load 下 health ≈ 20s 的闭合解释）

`health = posture_now(0.93×3) + daily_report[ guard_posture#2(1.23×3)
+ chain_health 重散当日 5.4MB(2.2×3) ] + load_items 重投影当日文件(2×3) + 渲染/HTTP`
≈ 19–22s ✔ 与实测吻合。

## 2. 根因（分层声明，元纪律 M-C）

### 产品层

**R1 · 同一事实两遍算（真浪费，零收益）。**
`render_page` 每个视图先 `posture_now()` 跑一次全量 `guard_posture(_pkg_root())`；
`report/health/ledger` 三视图的 `daily_report()` **函数体内又跑一次**
`guard_posture(dirname(abspath(inbox_report.py)))`（inbox_report.py:323）——
两处入参经核实**是同一个目录、同一个函数**。每次 `guard_posture` ≈1.2s
（`_heartbeat_age_in` 读审计目录末 3 个文件 ≈15MB：`sentinel_heartbeat_age` 0.54s×2、
`self_check` 重散全部 manifest 0.44s×2）。三视图每页白付一倍。
且违反产品自己的 0.53.0 T4 原则——「一个事实一个变量，页面从头到尾同一份态势」。

**R2 · 当日生长文件必然缓存失效（三层缓存全部被它击穿）。**
`.psl/audit/2026-10-20.jsonl`（5.4MB / 6,963 条）在并行线跑闸门时持续追加，
于是每次渲染：①`chain_health` 指纹缓存（path, mtime_ns, size）失效 ⇒ 全文件重散 ~2.2s；
②`load_items*` 的 `_PROJ_CACHE`（512 条目）同理失效 ⇒ 全文件重投影 ~2s；
③`_heartbeat_age_in` 从文件头顺序读末 3 个 jsonl ≈15MB/次（每次 `guard_posture`）。
进程内缓存机制本身是健全的（0.53.2 已把上限从 64 提到 512，判据 L-02 钉住）——
问题只在**活跃文件恒热**。

**R3 · 账本页三笔重账。**
①`load_items_all` 全量 1941 条（冷 16s；且它是唯一走全量的视图）；
②`record_day` 14 天补记窗口在 **GET 路径里同步执行**——实测单次追加 6 个变更多天，
活体每笔 ≈0.4–1.0s（持锁+写）；
③ledger 还连带 `daily_report`（R1/R2 全付）。空闲时 ledger 9.88s vs health 0.79s
的 9 秒差 ≈ 全量取数 + record_day。

**R4 · 无客户端缓存，每次点 TAB ＝ 一次完整 GET + 整页服务端重渲染**（46KB HTML/次）。
这是「切换不畅」的体验层根因：服务器算什么，用户就等什么。

### 环境层（放大，非产品缺陷）

**R5 · 并行线在途，机器满载**：8 核被闸门（delivery_gate 30 套 ~20–25min）与 AV
实时扫描占满 ⇒ 一切 I/O ×2.5–3。空闲体感 0.76–1.41s ↔ 满载 20–62s。
**此项随并行线结束自然消退，但它证明：结构不修，负载一高就现形。**

### 量具层（测量环境 artifact，已排除，教训入档）

**R6 · 探针被宿主垫片灌胖**：`record_day` 在探针里 58.36s，其中 **57.99s 耗在
`release_lock` 的 `os.remove(锁文件)`**——WorkBuddy 宿主 `sitecustomize._safe_remove`
把删除改走回收站（SHFileOperationW 失败 0x2），每次 ≈9.6s × 6 次追加。
活体 `antinel.cmd` 用 `python -I -S` 启动：`-S` 不加载 site、`-I` 忽略 PYTHONPATH
⇒ **垫片不生效，活体不付这笔钱**。教训：测活体性能必须走 HTTP 或 `-I -S`，
否则量具给产品戴口罩（与时红时绿同族的测量污染）。

## 3. 方案选项与取舍（等拍板）

### A. `posture` 注入去重（**推荐**，零语义变化）

`daily_report(..., posture=None)` 增加可选注入；`render_page` 把已算好的 `p` 传进去。
- 收益：report/health/ledger 每页省 ~1.2s（load 下 ~3.6s）；heartbeat 15MB 双读变单读。
- 风险：≈0。默认值保持自算 ⇒ 现有判据（4 个套件引用 daily_report，无一面钉「必须自算」）
  行为不变；注入后页面顶部条与日报**同一份态势**，正是 T4 原则的延伸。
- 规则层：判据可加「render_page 渲染期间 guard_posture 只许被调一次」（AST 数调用点）。

### B. `guard_posture` 内部瘦身（**推荐**，两处）

- B1 `self_check` 按 manifest 指纹集缓存：manifest 文件 (path, mtime_ns, size) 全同 ⇒ 跳过重散
  （版本不变时 0.44s→~0s）。
- B2 `_heartbeat_age_in` 改**倒序读文件尾**（末 64KB 即含最新心跳），语义保持「取最大 ts」
  ⇒ 15MB/次 → KB 级。需小心：倒序首个匹配 ≠ 全局最大 ts（乱序追加时）——
  取「尾窗内最大 ts」并在注释中声明该边界，或对尾窗内全量取 max（64KB 窗口足够）。
- 风险：低。B2 是读取策略变化，判据需补「心跳年龄与顺序全读一致」两臂对照。

### C. `record_day` 移出 GET 同步路径（**推荐节流版**）

进程内节流：同一 server 进程 N 秒（30–60s）内只跑一次 `record_day`，daemon `tick()` 不变。
- 保留 0.51.0 的修复语义（daemon 没跑的日子账本仍会更新——首次打开必然触发一次）；
- 消灭「每次打开账本页都写 6 行」； ledger 每页省 3–6s（load 下更多）。
- 备选（更激进）：GET 只读 `L.summary`（0.009s），写入完全交还 daemon tick
  ⇒ 若 daemon 未运行则账本停更（0.51.0 事故复现条件），**不推荐**。

### D. 客户端 SPA 化 / TAB 局部刷新（**暂不做**）

五个 TAB 改 JS fetch 局部替换 `<main>`，可把「切换」降到一次数据请求。
- 收益最大，但风险最高：整页 token 逃逸（`_escape_js`）、窗口认领（`_mark_at_tail`
  认标题）、`_FLIP_JS`/`_READ_JS`/`_collapse_js` 全部耦合整页生命周期；
- 且有 0.53.4 设计线在途——与其在整页架构上动刀，先把 A/B/C 的结构性浪费拆掉，
  若仍不够再评估 D。

### E. 感知性能（治标，随时可做）

切 TAB 立刻高亮 + 顶部细进度条（等待有反馈）；鼠标悬停 100ms 预取。
不改一个计算，专治「等好久」的心理时长。可与 A/B/C 并行。

### F. 环境项（无需动作）

并行线结束后负载消退；R6 只是探针现象。**但若将来出包给用户在受监控环境运行
（如企业 DLP 钩 `os.remove`），record_day 的持锁追加会同样被灌胖——这不是本轮范围，
登记为盲区。**

## 4. 拍板点（请创始人定）

1. A+B（去重 + 瘦身）现在就做，还是合并窗口期与主树 0.53.4 设计线一起做？
2. C 选节流版（30–60s）还是更激进的纯 daemon 版？（推荐节流版）
3. E（进度条/预取）要不要同期做？
4. D 明确搁置还是排期？

## 5. 盲区与未决（如实申报）

- 20–62s 尖峰中有多少纯来自机器负载，未做受控对比（无法在并行线在途时复现空闲态）——
  A/B/C 的收益估算按「结构成本 × 负载系数」推得，标注为推算而非实测。
- B2 倒序读的心跳边界（乱序追加）未实测构造用例。
- 判据面 grep 确认「无 daily_report posture 自算依赖」，但**未跑全套**；
  动代码前需 0360/0372 等套件复跑确认。

## 6. 落地状态追记（2026-10-21；创始人拍板「A+B+C 一起做，E 顺带」，D 明确不做）

四案全部落地，**每个提交自带判据＋负控，负控全部实测真红**：

| 案 | 提交 | 判据（含负控） |
|---|---|---|
| A `daily_report(posture=None)` 注入 | `d7c1bfd` | TP-A1 / TP-A2 ＋ N-TPA1 / N-TPA2 |
| B1 `self_check` manifest 指纹缓存 | `90ef8c4` | TP-B1 ＋ N-TPB1 |
| B2 `_heartbeat_age_in` 倒序读尾窗 256KB＋双回退 | `90ef8c4` | TP-B2 ＋ N-TPB2 |
| C 账本页 GET 的 `record_day` 45s 节流 | `b5e2206` | TP-C ＋ N-TPC |
| E 切页即时反馈（点击即高亮＋细进度条＋悬停 100ms 预取） | `206a00b` | TP-E1 / TP-E2 ＋ N-TPE1 / N-TPE2 |

登记：A/E 进 `ci/inbox_guards_0514.py`（渲染面，177 绿）；B/C 进
`ci/inbox_guards_0353.py`（host_shield＋账本面，87 绿）。
验证：全量交付闸门 `ci/delivery_gate.py` **34/34 绿、EXIT=0、无 Traceback**；
四案各自另跑相邻套件（0363/0364/0360/0372/0490/0380）复绿。

§5 申报盲区的收官情况：
- 「未跑全套」⇒ 已跑全量（34/34）。
- B2 心跳边界（乱序追加）⇒ TP-B2 夹具按契约构造了**乱序头探针／空窗回退／残行**
  三臂两臂对照；残留边界在 `_HB_TAIL_BYTES` 常量注释里**显式申报**：窗外若存在
  更大 ts，读尾窗可能取到较旧值 ⇒ `_hb_full_scan` 全扫路径保留作回退，不许删。
- 机器负载尖峰（R5）⇒ 属环境项（F），随并行线结束消退；收益核算仍按结构成本口径。

实测效果（同机同法，与 §1.1 空闲参照对照；未重跑旧码、负载背景不同，
**非受控 A/B，仅作指示性对照**）：
`_heartbeat_age_in` 0.16–0.18s → **0.010s**；`self_check` 二遍 **0.0014s／0 次哈希**；
真 hub 整页（冷→热）inbox 1.95→**0.10**、report 5.06→**0.15**、health 0.24→**0.16**、
ledger 5.27→**0.35**、体检 0.28→**0.14** 秒；账本页连开 3 次 0.06s×3、
`record_day` 只跑 1 次。

遗留（**记录待批示，未动**）：`guard_posture` 自身缓存后仍有 ~0.07s 固定成本
（`sentinel_alive`/`load_state` 等，未做函数级剖析）；主树 D-36 重签流程破损
（并行线改码不重签）已 heal，流程规矩本身待立。

本轮探针位置：`output/_p_tab_*.py`（主树，gitignored）；夜线合并候选与冲突
处置包在 `.worktrees/night/output/`。

---

*本文件为只读轮交付物；**分析当日**产品代码零改动。探针 `ci/_p_*.py` 均在 night worktree
（gitignore），主树工作区未碰。*
