<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Antinel · 六态切换逻辑落地记录 v1.0（2026-10-16）

> **这份记录是什么**：《六态切换逻辑规格 v1.2》**实现轮的落地实况**——
> 11 项拍板怎么落、产品改了什么、判据重签了哪些、全量复跑什么结论、
> 唯一的红项属于哪一类、机制层（A1/A2）是否合规。
> **它是「做过什么」的证据，不是设计文档**——设计看规格 v1.2，图解看
> 《六态切换逻辑图解 v1.0》。
>
> 版本：本轮产品版本 **0.51.0**（上一版 HEAD 为 0.50.5）。

---

## 0. 一句话结论

三通道显示模型（主灯／徽标／计数）＋ info 类保持期（H=30 分钟）＋ 研发徽标
按 **PyPI 已发布版本比对** 全部落地；判据侧重签 6 处、新增 4 条正判据＋2 组
负控；**30 个常驻套件全量复跑 585 绿 / 1 红 / 3 跳过**，唯一的红项经 git
取证为**改动前就红**（见 §5）。

---

## 1. 11 项拍板 → 实现落点

| # | 事项（§8） | 落地落点 |
|---|---|---|
| 1 | 三通道显示模型 | `inbox_model.py::light_explain`（返回 state/label/badges/action_count/info_count）＋ `inbox_server.py::_bar` 渲染 |
| 2 | H = 30 分钟 | `inbox_model.LAMP_HOLD_MINUTES = 30`（唯一定义处） |
| 3 | info 已读提前结束保持期 | `_event_lamp_level()`：info 分支 `unread ∧ now-ts ≤ H` |
| 4 | 研发徽标＝版本比对；posture=dev 不并点徽标 | `inbox_model.badges()` / `version_pair()` / `is_ahead_of_published()` |
| 5 | Ls 徽标化（六态键**不撤**，改组成方式） | `glossary.TERMS["light"]` 改写；六态词表 keys 保持 |
| 6 | 窗口标题不带徽标 | 徽标只在**页面芯片**＋**托盘 tooltip** 出场 |
| 7 | W-03 重签 | `inbox_guards_0490.py::_w03_assert` 现 4 用例（账内 R0 / 保持期内 / 过保持期 / 已读） |
| 8 | S93/N-S93b 重签 | `inbox_guards_0470.py`：dev_drift 回归 L1 事件＋徽标 |
| 9 | 术语表「灯」词条改写 | 同 §5（`glossary.py`） |
| 10 | 发布流程回写 `published_version` | 纳入发布流程（接缝已留；**未推 PyPI**，回写待发布动作） |
| 11 | 口粮数据源接入 | **延期**（仅留接缝）；缺粮当前＝徽标（granary 不再抬主灯） |

---

## 2. 产品改动（文件级）

| 文件 | 改了什么 |
|---|---|
| `inbox_model.py` | `LAMP_HOLD_MINUTES=30`；徽标块（`BADGE_DEV`/`BADGE_GRANARY`/`BADGE_LABEL`/`BADGE_TIP`）；`_ver_tuple`/`is_ahead_of_published`/`version_pair`/`badges`；`current_state` 重写（dev ⇒ 主灯 L0）；`_event_lamp_level`（按桶抬灯，毒信道永不抬）；`light_explain` 扩出徽标与计数 |
| `inbox_server.py` | `.badges`/`.bdg` 样式；`_bar` 依 `ex["badges"]` 生成芯片；芯片 `title=` 用 **`M.BADGE_TIP` 短提示**（≤20 字，过 U-11 硬上限） |
| `inbox_tray.py` | `sync_from_items` 把徽标名**追加在标签之后**（保 `tip.startswith(label)`，W-03 不破） |
| `glossary.py` | 「灯」词条按三通道改写（定义里**不含承诺**） |
| 版本承载 9 件 | `pyproject.toml`/`server.json`/`antinel.py`/`antinel_mcp.py`/`hooks/pre_tool_use.py`/`scripts/build_package.py`/`rules/default.json`/`docs/AUDIT_SCHEMA.md`/`SKILL.md` → **0.51.0** |
| `psl/workspace_facts.json` | `release.version` → 0.51.0（另加 `_note_0510`） |

**未动**：`psl/manifest.json` 的 `version`（由打包步骤写，**只重签了文件哈希**）。

---

## 3. 判据重签（逐条）

| 套件 | 改动 |
|---|---|
| `0380` | `check()` 修为**包异常**（原先 29 条判据永远判不了红 —— Sev-0）；`_EXPECT["dev"]="L0"`；S10/S13 改判「granary 低 ⇒ L0+缺粮徽标」；S15 双通道可达；S17 术语锚点；**新增 S100–S103 ＋ N-S100…N-S103** |
| `0490` | `_w03_assert` 4 用例；**U-01 修时钟竞态**（见 §5.1）＋ N-U01b/N-U01c；U-11 改锚 `BADGE_TIP` |
| `0470` | S93 重写（dev_drift ⇒ 普通 L1 事件；毒永不抬）；N-S93 锚点改 `if tamper_channel_of(it.kind)=="poison": continue`；N-S93b 反向变异；S99 重写；N-S99 变异（tamper→"dev"） |
| `0518`（**已并入 0514**） | 先补 **P1–P5 块**（A1 前置门）——P5 **自答「不满足」**（理由见 §6）；同日按创始人指令**并入 0514**（J1–J5 一字未改，0514 74 → **83 绿**），撤下 SUITES、退休簿转 done |
| `0366` | M7 的裸 `return "manifest 不存在…"` 改为 `raise AssertionError`（`_p_harness_audit.py` 抓到的唯一真 WARN） |
| `page_caliber.py` | 新增纯函数 **`note_text()`**：归一口径行里的载入时刻（两侧同归一再比） |

---

## 4. 全量复跑证据

驱动：`_p_run_suites.py`（仓根，只读可复跑）。日志：
`output/q_suite_all_20261016_103325.log`。

**30 套件 → 585 绿 / 1 红 / 3 跳过**（跳过全在 0516，见 §5）。

★ **销账后复跑（0518 并入 0514，见 §6.3）**：**29 套件 → 585 绿 / 1 红**
（0514 由 74 → **83 绿**；0518 不再单列 ⇒ 套件数 30→29、绿数不变）。
日志 `output/q_suite_all_20261016_111518.log`。两轮**唯一的红都是
0516 PKG16-c**（改动前就红，见 §5.2）。数字一律**脚本计数**，不手算。

下表是**首轮**（30 套件）逐套件快照：

| 套件 | 结果 | 套件 | 结果 |
|---|---|---|---|
| 0353 | 62 绿 | 0460 | 18 绿 |
| 0360 | 52 绿 | 0470 | 20 绿 |
| 0362 | 32 绿 | 0481 | 12 绿 |
| 0363 | 13 绿 | 0482 | 14 绿 |
| 0364 | 25 绿 | 0483 | 12 绿 |
| 0366 | 11 绿 | 0490 | 45 绿 |
| 0372 | 22 绿 | 0514 | 74 绿（销账后 **83**） |
| 0380 | 29 绿 | 0515 | 8 绿 |
| 0400 | 33 绿 | **0516** | **2 绿 / 1 红 / 3 跳过** |
| 0420 | 6 绿 | 0517 | 7 绿 |
| 0430 | 6 绿 | 0518 | 9 绿（**已并入 0514**） |
| 0431 | 17 绿 | guard_dist_hygiene | 4 绿 |
| 0440 | 5 绿 | guard_granary | 8 绿 |
| 0450 | 13 绿 | guard_instrument_selfaudit | 通过 8/0 |
| — | — | guard_release_entry | 通过 12/0 |
| — | — | guard_selfcert_timing | 通过 6/0 |

另：`ci/version_check.py` **PASS 9/9 @ 0.51.0**；`ci/inbox_guards_0481.py`
**12 绿 / 0 红**（新文档与探针 SPDX 头齐备）。

---

## 5. 红项分类（本项目纪律：红项先分类再动手）

只有 **1 条红**：

### 5.1 已修（本轮引入，改完即绿）

- **0490 U-01 假红（判据自身时钟竞态，不是产品漂移）**：
  `M.reading_note()` 在 0.50.4（Q-22）加了实时「载入于 HH:MM」。U-01（与
  0470 S95）**先渲染页面、再调一次该函数**逐字比对 ⇒ 两次独立读数**跨分钟**
  即伪红；页面渲染在负载下要数秒，故每 tab 有百分之几的概率翻面。
  修法：抽纯函数 `PC.note_text()` 把两侧载入时刻**归一再比**，比对收敛到
  单一落点 `_note_matches()`。**变异-红-还原已实测**：把比对退回逐字 ⇒
  **N-U01b 转红**（负控承重）；把比对改成恒真 ⇒ **N-U01c 转红**（负控有分辨力）。
- **0490 U-11**：我一度把 38 字的徽标原因塞进芯片 `title=`，越 U-11 的
  「任意 title ≤20 字」硬上限 ⇒ 改用 `M.BADGE_TIP` 短提示，`why` 只留在
  可见原因句里。
- **0481 L1（我引入 4 条 + 历史 7 条）**：新探针 SPDX id 误写 MIT（表里是
  Apache-2.0）＋ 7 条旧探针缺头 ⇒ 11 条全补，现 **12 绿 / 0 红**。

### 5.2 唯一残留红：0516 PKG16-c —— **改动前就红**（git 取证）

判据说：「`psl/manifest.json` 版本 0.50.5 **超前** 验收日志 0.50.4 ⇒ 登记了
一个还没产出（或验不过）的版本」。取证：

- `git show HEAD:psl/manifest.json` ⇒ **已提交**版本就是 0.50.5
  （`built_at 2026-10-15T14:38:46Z`，129 项）；
- `output/p12_verify_release.log` **未进 git**（本机留存件，抬头 0.50.4）；
- `dist/` **为空**（0.50.5 与本版 0.51.0 的产物都不在盘上）。

⇒ 该红项在 HEAD（改动前）即成立，**与本轮改动无关**。它的正当解法在
**发布路径**（打包 → 验收 → 回写日志/清单到同一版本），而发布动作**须创始人
批准**（PyPI 仍停 0.35.1，target 未推）。故本轮**不动它**：既不放松判据，也不
伪造一次验收。**三名 SKIP 同理**（无 wheel ⇒ 「先出包再判」的诚实跳过）。

---

## 6. 机制层合规（今早升级带来的 A1/A2）

### 6.1 A1 前置门（新套件须有 P1–P5）

今早升级把 `ci/inbox_guards_0518.py` 登记进 `SUITES`（常驻 **29 → 30**），
但该文件**没有 P1–P5 块** ⇒ A1 判红。本轮补上五答：

- **P1**（频率×损失）满足；**P2**（二值可判定）满足；**P3**（咽喉点不可规避）满足；
- **P4**（自检闭环）满足；
- **P5**（**扩展优先**）**自答「不满足」** —— 其 5 条判据与 `0514` **同锚
  `inbox_server.py` 渲染产物**，属重复设站 ⇒ 正解是**并入 0514**，不是新增。

⇒ `ci/delivery_gate.py::suites_missing_p1p5()` 现绿。

### 6.2 A2 常驻上限 29（现 30）

`resident_suite_count()`＝30 ＞ `RESIDENT_SUITE_CAP`＝29 ⇒ 硬红。纪律要求：
超限须在 `ci/suite_retirement.json` 有 ≥ 超额数的 **pending** 记录（30 天宽限、
须带 `replacement`）。本轮登记：

```json
{ "suite": "0518", "date": "2026-10-16", "status": "pending",
  "reason": "A2 超限来源…P5 不满足…并入 0514", "replacement": "0514" }
```

⇒ 由 **pending 额度**合法放行，`cap_violation()` 转绿。

### 6.3 销账已执行（2026-10-16 上午，创始人指令「你先合并销账吧」）

| 动作 | 落点 |
|---|---|
| **J1–J5 ＋ N-J1…N-J4（9 条）原样并入 0514** | `ci/inbox_guards_0514.py` 末段「J 族」（判据 ID **一字未改**）；0514 由 **74 绿 → 83 绿 / 0 红 / 0 跳过** |
| 唯一改名 | 0518 的 `_src` → **`_src_or_skip`**（0514 早已有 `_src`，语义不同不许互相覆盖） |
| 撤下 SUITES | `ci/delivery_gate.py` 删 0518 登记行（`REQUIRED` 随之自动少一条） |
| 退休簿转正 | `ci/suite_retirement.json`：`status: pending → done`、填 `removed_from_suites_on` / `merged_on` / `merge_note` |
| 原文件让开 | `ci/inbox_guards_0518.py` → `ci/inbox_guards_0518.py.away-20261016-merged-into-0514`（**零删除纪律**：改名让开 —— 若只撤登记而不改名，留下的 `inbox_guards_*.py` 会撞 `_orphaned_guard_files` 判红） |
| 交叉引用同步 | `ci/defect_types.py` T-11 的 note、`inbox_server.py:154` 的注释（都按 **ID** 引用，无需改名） |

**实测核对**（`ci/delivery_gate.py` ＋ `ci/defect_types.py` 直调）：常驻
**29 / 29**、`cap_violation()` 不红、A1 无缺块、**孤儿守卫文件 0**、
`REQUIRED` 缺件 0、**跨套件重名 0**、`gate_id_map()` 里 J1–J5/N-J1 全归
**0514**、0518 已不在 SUITES。⇒ **A2 销账完成**。

---

## 7. 探针与变异实测（全部只读可复跑）

| 探针 | 证明了什么 |
|---|---|
| `_p_hold_lamp.py` | H 边界（29/30/31 分）；已读/完成提前结束；action 桶 20h 仍在；L1 三源各自结束；**枚举出可抬灯的信道**（纠正我先前认为 action-抬灯分支不可达的错判：`host_shield_zone_locked` 正是 action+L1） |
| `_p_dev_badge.py` | 版本四态（> / = / < / 取不到）；**`0.9.0` vs `0.10.0` 字符串陷阱**（须数值比）；facts 缺失降级不假阳；posture=dev **不**伪造徽标 |
| `_p_coexist.py` | dev 徽标 ＋ R0 主灯 ＋ action 计数**同时为真**（并存模型正面证据）；两枚徽标并存；徽标不抢主灯 |
| `_p_harness_audit.py` | 28 套件判据「死活」审计（正负控齐备）：0 DEAD / 2 WARN ⇒ 抓出 0366 M7 的裸 return |
| `_p_text_audit.py` | 全量可见文字扫（口径照抄 0360 W06/W09）：**W09 0 命中、W06 0 命中** |
| `_p_u01_repro.py` | 复现并定位 U-01 时钟竞态（连跑逐字比对，结论：当次渲染自洽 ⇒ 前次红属跨分钟） |

---

## 8. 本记录不能证明什么 / 遗留

1. **H=30 无实测依据**，判据化的是结构（保持期机制），不是数值；
2. 徽标渲染的 **UX 未测**（屏幕占驻、可读性、与既有芯片视觉关系）——待截图轮；
3. `published_version` 陈旧窗口会徽标假阳，**靠发布纪律对冲**（拍板 10），未实测；
4. **0516 PKG16-c 红项未修**（改动前就红；解法在创始人批准的发布路径，见 §5.2）；
5. **A2 已销账**：0518 → 0514 的合并**已于同日执行完毕**（常驻回 **29/29**，见 §6.3）；
6. PyPI 仍停 0.35.1，**本版 0.51.0 未推**（发布须创始人批准）。

---

## 9. 把系统独立拉起来（2026-10-16 11:12，在屏实证）

**为什么必须重启 daemon 而不是重启 8790**：用户眼前那枚窗由 **daemon 进程内的
`_BG` 服务**提供（端口**每次随机** —— 06:56 那次 `57226`、本次 `31370`），
8790 只是**受监督的独立 service**。改完产品后只重拉 8790 或只按 F5，屏幕照旧。

**动作序列（可复跑）**：

| 步 | 动作 | 实测 |
|---|---|---|
| 1 | 杀旧窗 PID ＋ 旧 daemon PID | 杀 daemon ⇒ service 同死（W-04 再次实证，8790 立刻无监听） |
| 2 | `run_in_background` 跑 `python -W ignore -c "import inbox_daemon; inbox_daemon.run_daemon()"`（cwd=仓根） | 新 daemon **26720**；supervise 按记录重拉 service **5756 @8790**，**token/URL 不变**（B1） |
| 3 | `inbox_cli.py window`（同步调用、launch-and-return） | 打印「[window] 已就位：720x640 @(2240,1264)」 |
| 4 | 默认落点被 WorkBuddy 主窗遮挡 ⇒ 用**产品自己的** `inbox_window.place_all` 挪到 (150,150) 并回读 | `True ｜ 已把 1 个值守台窗口都落到 870x790 @(150,150)` |

**在屏证据**（`_p_console_open.py` 绕代理探窗口真加载的那份 HTML ＋
`_p_console_shot.py` 截图）：窗口标题「**值守中 · Antinel 监理#b39a0a**」、
主灯 **值守中（L0）**、页头带 **研发中徽标芯片**（`bdg dev` 命中 1 次）、
原因句为**三元组**——「此刻是好的（监理在岗）；另外：研发中——本机这一版
（0.51.0）比已发布的（0.35.1）新，还没发出去；还有 46 条没处理（需要动手）」。

⇒ **v1.2 三通道模型在屏可见**：主灯说「此刻」，徽标说「并存」，计数说
「多少事没办」。这正是本轮要修的那个病（22 小时前的自动拦截把灯钉死）的
反面 —— 现在同一批数据下灯是 **值守中**，研发身份降级为**徽标**。
