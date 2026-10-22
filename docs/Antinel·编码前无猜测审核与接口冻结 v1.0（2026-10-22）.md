<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel·编码前无猜测审核与接口冻结 v1.0（2026-10-22）

> **答复对象**：创始人 2026-10-22 指令「**再全面深度审核一遍：每一个细节都设计到位了
> 吗？跟已有代码的关系精确定义了吗？可能让 LLM 猜错的地方都不让它猜了吗？
> 我没想到的维度也审。我期待进入编码后高效完成、基本不引入新错误、系统基本顺畅跑起来**」
> **性质**：编码前最后一次审核。方法不是「再读一遍文档」，是**影子实现走查**——
> 逐单元模拟「现在就开工」会把代码写出来，每遇到一个必须拍的地方才算一个猜测点。
> 本件把走查发现的猜测点全部裁掉；裁不掉的（需要实测的）显式挂着并说明为什么不能裁。
> **量具**：接口事实回源码取证（行号见正文）；句子宽度按两把尺子实算（D7 42 字符／
> T4-07 40 显示宽，汉字 1／其余 0.5；主行另受 FZ-004 的 48 字腿管）。

---

## 0. 结论

**走查 14 个编码单元，挖出 47 个猜测点：本件冻结 29 个，前六件已预决 15 个
（含 1 处本件补冻的混合项），已实现 1 个，显式挂起 2 个（均为**参数级**：
机制与形状已冻，数值待实测），遗留 0 个无人认领。** 另有 4 个门级挂起项
（T1 16px 实测、BL-07 命题①实测、两个 30 天观察期、两处跨线确认）来自
《四项在飞事项施工方案》——它们不是规格沉默，是设计的一部分（实测门），
§8 统一挂着。冻结后，任一实现者（人或 LLM）按本件＋前六件施工，不需要在
枚举值、签名、文案、阈值、边界、失败路径、旧数据、顺序、文件位置上做任何
一次选择。

**走查中挖出的四个「会让 LLM 猜错」的高危点**（本件重点裁决）：

1. **新模型的八句上屏文案在全语料里只是「示例」**（最优设计 §5 明确标示例）⇒
   实现者必然自己写句子 ⇒ 必撞两把尺＋状态词网。**本件 §4 全部冻结并实算宽度。**
2. **`facts` 的单位与三态表示没冻过**（秒还是分钟？ISO 字符串还是 epoch？bool 还是
   三态？）⇒ 两个实现者会写出两种 facts，投影层每天漂移。**本件 §2-F1 冻结。**
3. **N12 要新增一种链记录（`delivery_unknown`）而 AUDIT_SCHEMA 没登记**——
   本仓 0.40.0/0.51.2 两次「只写代码不写 schema ⇒ harness F-10 红」的同型事故
   正在路上。**本件 §2-F7 连登记草稿一起冻。**
4. **fixture 只有 31 行**（覆盖旧 31 格），N5–N12 八个新单元一行都没有 ⇒
   实现者会「先写码后补判据」，那是本仓假绿的标准入口。**本件 §5 规定 57 行并
   给出每行的输入输出。**

**走查后半段新撞出的五个**（本件 §4/§5/§6 已裁，均为「不裁就会猜」级）：

5. **§4 的宽度有 12 处是心算错的**（1–3 个误差，`absent` 定义句差 3）——本件卖点
   就是宽度实算，故全部改脚本复算（`output/_p_sentence_width.py`）并记「1 位/2 位」
   两值。尺子量的地方，脚本算（§4 规矩下自证）。
6. **`granary` 的口粮单位是小时不是秒**（`HOURS_PER_DAY=24`）——facts 层不冻就会
   出现「把余额当时长」的异质单位错误（§2-F1 特冻一条）。
7. **「停摆不是 paused」被读成「成因键不是 paused」就会造出第九个成因**（撞 I4
   单射）——冻结：成因键不变，**变的是句子**（§5-N8-c）。
8. **`credits_low` 预告族与缺口族在 harm 判据上撞车**：D-03 同时把它列进 at-risk
   来路和「∃ open」的 harm 判据，不冻族界，缺粮就会红（§5.2 连带冻结第一条）。
9. **§4.3 有三句与前六件预制句不同槽**（磁盘句、心跳句、D-06 两句）——两个源各说
   一句，实现者必选错。冻结权统一：预制句优先，本件只做槽位和解（§4.3）。

---

## 1. 方法：影子走查＋十二类猜测分类学

### 1.1 十二类猜测点（规格沉默时 LLM 会猜的地方）

| 类 | 猜测什么 | 本件裁法 |
|---|---|---|
| G1 枚举值 | 灯值/字段名/状态词字面 | §2-F1/F2/F3 冻结表 |
| G2 函数签名 | 参数顺序、默认值、返回形状 | §2 冻结表 |
| G3 文案字面 | 每个上屏字符串 | §4 冻结（含宽度实算） |
| G4 阈值与单位 | 数值及其来源 | §2-F4/F5＋§3 逐单元 |
| G5 边界输入 | 空/None/0/首次/超大 | §3 逐单元「边界行」 |
| G6 失败路径 | 探针抛错后走哪 | §3 逐单元「失败行」 |
| G7 旧数据 | 历史记录落到哪 | §3-U4＋E6 已对齐 |
| G8 顺序 | 谁先谁后 | §7 DAG |
| G9 文件位置 | 新文件放哪、叫什么 | §3 每单元「落点」 |
| G10 判据夹具 | 编号、负控、夹具数据 | §5＋编号按注册表分配（不预写） |
| G11 错误信息 | 日志/异常字面 | §6 编码契约第 7 条 |
| G12 共享冲突 | 动别人的文件 | §6 编码契约第 9 条＋R3 交规 |

### 1.2 走查范围（14 单元）

U1 `situation.py` 投影／U2 `facts.py` 事实层／U3 `state_registry.py` 态表／
U4 `gap_state` 收尾（按钮＋族映射）／U5 at-risk 注册表（N6）／
U6 `partial_read`（N7）／U7 粮尽三态接线（N8）／U8 同屏互斥判据（N9）／
U9 链对账（N10）／U10 时态列（N11）／U11 通知送达链（N12）／
U12 六渲染点改造／U13 旧屏句子迁移／U14 观察 sidecar（T3）。

---

## 2. 接口冻结表（八张，实现者不许自创）

### F1 `facts` 快照（`facts.py` 产出）——单位与三态全冻

| 规则 | 冻结内容 |
|---|---|
| 类型三选一 | 每个字段只能是：**秒（float）／ISO8601 字符串（str）／计数（int）／None**。禁 bool 表示三态（用 `True/False/None`）；禁「0 表示没有」（没有就是 `None`） |
| 时间一律秒 | `heartbeat_age`/`sentinel_uptime`/`ack_age` 等**时长**字段一律秒（float，保留 1 位）；绝对时刻一律 ISO8601 本地时区（与链上 `ts` 同格式，禁 epoch） |
| 来源唯一 | `facts.py` 的许可调用白名单（**只许调这些，不许自己探**）：`host_shield.guard_posture()`（姿态＋evidence）、`host_shield.sentinel_heartbeat_age()`、`host_shield.armed_state()`、`host_shield.self_check()`、`host_shield.write_health()`（BL-03 已实现）、`granary.state()`、`egress.capacity()`、`inbox_model.day_counts()`/`ledger_rows()`/`unrepaired_count()`、`host_matrix` 现探结果。**新增任何读取点＝新增一次漂移机会，须先过 G8 同源** |
| 自报 | `trace: {"missing": [字段名…], "sources": {字段名: 来源函数名}}`——投影缺字段时必须能从 trace 读出来（维五自报活跃），缺字段进 I5 显式降级，不许静默默认 |

字段全集＝D-02 的 23 字段＋本件新增 4 个（`partial_read`／`at_risk[]`／
`chain_recon`／`notice_state`）——**mode 不新增字段**：D-02 已有 `armed`/`is_dev`
（N5 的「链权威」说的就是 `armed` 的来源，不是新字段）。每个字段的类型与缺失语义
按上表＋D-02 逐字段表执行。

**单位陷阱特冻一条（G4）**：`granary` 的口粮单位是**小时**（`HOURS_PER_DAY=24`、
`LOW_THRESHOLD=168`＝7 天，`granary.py:62-70`）——facts 层透传
`granary_balance_hours`（int，原样不改）并派生 `granary_days_left`（float，天）时
除以 `DAILY_SPEND_DEFAULT`；**不许把余额当秒、不许在句子里出现「小时」**（上屏只说
天数，§4）。这是本仓「异质单位做加减」家规在 facts 层的落点。

### F2 投影签名与返回（`situation.py`）——形状全冻

```
facts  = dict（F1 冻结）
scope  = {"device": str|None, "host": str|None, "window": ("now"|"since-last-look", str|None)}

lamp(facts, scope)     -> "grey" | "green" | "yellow" | "red"      # 四值小写英文，唯一枚举
cause(facts, scope)    -> 主成因键（F3 注册表键之一）＋ others: [并存成因键…]
sentence(cause, facts, scope) -> {"main": 显示句, "action": 动作句}  # 字面见 §4，禁临场写
gaps(facts, scope)     -> [{"id", "kind", "level", "opened_at", "gap_state", "cons"}]  # cons=[] 必须带 scan 覆盖证明（Q3 规则②）
badges(facts, scope)   -> [{"key", "text", "action"}]               # 每枚必须带动作，否则不许当徽标（深化件 §8.2）
presence(facts, days)  -> {"slices": int, "with_evidence": int, "holes": [(起,止,分钟)], "asleep": [(起,止,分钟)]}
```

- `lamp` 的求值顺序＝纯函数五条（灰→红(harm)→红(trust=unbounded)→黄(duty)→绿），
  与最优设计 §4.3 逐字一致，实现照抄，不许重排。
- `others`（并存成因）按动作优先级排：`absent > breach > blind > paused/draining > ok`。
- **投影不读文件、不看时钟**（时间由调用方传入 `now`；读取由 `facts.py` 负责）——
  这条是「同输入两次投影 diff=0」（Q8）的前提，冻结为投影层铁律。

### F3 态注册表条目（`state_registry.py`）——字段全冻

每个条目 11 字段，缺一不许进表：

```
{key, lamp, cause, label, def_sentence, shape, color_var, icon, badge, action, tense}
```

- `key`：新成因键（`unarmed/ok/paused/draining/breach/blind/absent/partial`）＋
  **六个旧键（`R0/L2/L1/Ls/L0/dev`）整体保留为能力键**（0372 S09 不动），
  新旧映射表是注册表的一个字段（`legacy_of`），全仓唯一。
- `tense`：`never/now/past/future/unknowable` 五值（N11 冻结；`blind` 必须是
  `unknowable`，显式登记，不许留空）。
- `color_var`：四个灯值的 CSS 变量映射在注册表单点定义（灰新增 `--lgrey`，
  取值与托盘 `SHIELD_OFF (0x5f,0x5e,0x5a)` 同源——`inbox_tray.py:84` 已有，
  **不许另立一个灰**）。
- 现有 6 表＋5 处内联（施工件 §3.5 清单）全部改为从本表派生；派生后原表删除，
  不留双份（D-5 推倒项）。

### F4 at-risk 源签名（N6）——注册即契约

```
AT_RISK_SOURCES = [
  {"id": "granary_low",          "probe": callable(facts)->(bool, str), "horizon": "days_left"},
  {"id": "heartbeat_will_stall", "probe": …, "horizon": "minutes"},
  {"id": "disk_write_full",      "probe": …, "horizon": "days"},
]
```

- 每源必须给出 `(触发?, 细节串)`；细节串是上屏句子的数字来源（§4）。
- **表外来源点亮 at-risk ⇒ 判据红**（注册表唯一真源）。
- 多源同亮：主行只说**预告期最短**的那个，其余进徽标 tooltip（冻结，防主行塞两个数字
  ——一句最多一个数字是既有立规③）。

### F5 扫描三成分与预算（N6/N7 共用）——形状与首版值

```
scan_result = {"scanned": int, "total": int, "truncated": bool, "reason": None|str,
               "budget": {"dirs": int, "bytes": int, "seconds": int}}
```

- 字段名**沿用 N7 预制形状**（`reason` 不叫 `why`——审计件 §3.3 已冻，不许改名；
  `facts.partial_read = None | {"seen": N, "total": M, "why": str}` 的 `why` 是
  N7 自己的字段名，两处不通用）。

- 首版预算值 **dirs=500／bytes=64MB／seconds=20**——**标注为首版值，进观察项
  （T3 的 M 系带一个「截断发生率」旁路指标），实测后校准**。机制今天冻，数值有校准
  路径，这不叫猜（猜是没有校准路径的固定值）。
- `truncated=True` ⇒ 必须产出 E3b 原文（§4），**且 `total-scanned` 必须上屏**
  （不许只报 scanned）。

### F6 对账形状（N10）——三态裁决

```
reconcile_day(chain_dir, date, sleep_intervals) ->
  {"expected": int, "actual": int, "diff": int,
   "verdict": "ok" | "lost_suspect" | "unknown_window",
   "basis": " awake_seconds/600 或 wall_seconds/600（按 T2 实测结果定）"}
```

- `expected` 的公式**由 T2 实测结果选定**（三种分支已预定），本件不预选——
  这是 6 个挂起项之一，但**挂的是公式的一个参数，不是形状**。
- `verdict=lost_suspect` ⇒ `trust=unbounded`（红）；`unknown_window`（保留窗外）
  ⇒ 不进判定，只登记「这段不可对账」。
- 与已实现的两层关系冻结：L1 进程内 `write_health()`＞L2 `lost.json`＞L3 本对账；
  **任一层阳性 ⇒ unbounded**，三层不是互斥选项是叠加证据。

### F7 通知三态与链登记（N12）——连 schema 草稿一起冻

| 态 | 落点 | 形态 |
|---|---|---|
| `notice_sent` | 进程内＋`~/.antinel/console/notice_log.jsonl`（**不进链**） | `{ts, kind, channel}` |
| `notice_seen` | 同上（用户动作驱动，**不许猜**） | `{ts, kind, how: "open"/"ack"}` |
| `delivery_unknown` | **进链**，L1 级 | 字段：`{ts, kind, downgrade: "tray"/"banner"/"none", minutes_overdue}` |

**AUDIT_SCHEMA 登记草稿**（随 N12 同批提交，否则 harness F-10 红——0.40.0/0.51.2
同型事故两次）：在 §4 会话与心跳类后新增「通知送达类」一行：
`delivery_unknown`｜daemon｜`decision="allow"`，`noticed`｜通知发出后 30 分钟未见
且降级失败｜**L1**｜字段：`kind`/`downgrade`/`minutes_overdue`。
**不新增字段到已有类型、不改 append-only 契约**（schema 修订纪律原文）。

### F8 观察 sidecar 行（T3）——形状全冻

```
{"ts": ISO, "lamp": 四值, "cause": 键, "badge": [键…], "info_unread_overdue": int}
```

日滚汇总量具只读这个文件（唯一源）；判据 `H-e`（两次汇总是同一结果）守它。

---

## 3. 逐单元猜测点核对（47 个，逐条裁）

> 「已预决」＝前六件已有可执行内容（给章节号）；「本件冻」＝本件第一次裁；
> 「挂起」＝需要实测，参数挂而形状不挂。编号即猜测点清单，实现者对照自查。

| # | 单元 | 猜测点（影子走查实际遇到） | 裁定 |
|---|---|---|---|
| 1 | U1 | lamp 四值的字面 | **本件冻**（F2：小写英文四值） |
| 2 | U1 | cause/others 返回形状 | **本件冻**（F2） |
| 3 | U1 | 投影能否自己读时钟/文件 | **本件冻**（F2 铁律：不许；时间由调用方传） |
| 4 | U1 | scope 的形状 | **本件冻**（F2：device/host/window 三字段） |
| 5 | U1 | grey 下三轴填什么 | 已预决（最优设计 §4.4：18 格折叠，facts 填 None）＋F1 |
| 6 | U2 | 字段类型与单位 | **本件冻**（F1） |
| 7 | U2 | facts 可以调哪些函数 | **本件冻**（F1 白名单，九类） |
| 8 | U2 | trace 的形状 | **本件冻**（F1：missing+sources） |
| 9 | U2 | 探针抛错时 facts 怎么办 | **本件冻**：该字段 None＋trace.missing 记名，**不中断**（与 daemon tick 的 `out["errors"].append` 同型） |
| 10 | U2 | mode_armed 从哪读 | 已预决（N5：`host_shield.armed_state()`——**链有据链说了算，无据回退 state 文件**，`host_shield.py:2854`；记录形状＝`host_shield_changed`＋`field="enabled"`＋`armed` bool，`_armed_of` 在 `:2813`。**不许自己扫链**） |
| 11 | U3 | 注册表条目字段 | **本件冻**（F3：11 字段） |
| 12 | U3 | 新旧键怎么映射 | **本件冻**（F3：`legacy_of` 字段，0372 S09 不动） |
| 13 | U3 | 灰的色值哪来 | **本件冻**（F3：与托盘 `SHIELD_OFF` 同源，不另立） |
| 14 | U4 | 「我修好了」按钮写什么 | 已预决（D-04：`{kind: gap_fixed, ref, by: user}` 新链记录）＋**本件冻**：`gap_fixed` 必须同批登 AUDIT_SCHEMA（与 F7 同批，否则 F-10 红） |
| 15 | U4 | 缺口族↔自检项映射 | 已预决（D-04 映射表；`host_shield_breach` 永不自动 fixed） |
| 16 | U4 | acked 14 天复核谁实现 | 已预决且**已实现**（`3a6bf7f`，`ACK_REVIEW_DAYS`） |
| 17 | U5 | at-risk 源的签名 | **本件冻**（F4） |
| 18 | U5 | 多源同亮时主行说哪个 | **本件冻**（F4：预告期最短那个，其余进徽标 tooltip） |
| 19 | U5 | heartbeat 将断的阈值 | 已预决（N6：`0.5×_STALE_AFTER` 派生，不写死） |
| 20 | U6 | 扫描预算的首版值 | **挂起**（F5：机制冻，数值进观察项校准） |
| 21 | U6 | 截断时灯怎么变 | **本件冻**：截断在**受监管落点扫描**上 ⇒ `trust=bounded`（黄）；在**非核心面**（宿主探测等）⇒ 只登记不降灯（BL-08 分层落地） |
| 22 | U6 | E3b 与 E3 同现时显示谁 | **本件冻**：都显示，E3（结构盲区）在前 E3b（本次截断）在后，互不覆盖 |
| 23 | U6 | E3b 原文 | **本件冻**（§4，宽度实算 35） |
| 24 | U7 | spend() 谁来调、记多少 | **本件冻**：daemon tick 每日首跑写一条，`reason="站岗"`，try/except 不阻断 tick。**金额按当日档位派生**（守备档 12／标准档 24，源自 `granary.SPEND_TIERS`/`DAILY_SPEND_DEFAULT`）——**不写死 24**：守备档半价是 N8 的设计，写死 24 会让守备档每天多扣一倍粮，观察期数据整体失真 |
| 25 | U7 | 守备档/停摆的 duty 映射 | 已预决（N8：守备=at-risk、停摆=off）＋**本件冻**（§5-N8-c）：停摆的成因键**仍是** `paused`（八成因封闭集不动、I4 单射不动）——「停摆不是 paused」指的是**句子**：`cause=paused ∧ facts.stop_reason="granary"` ⇒ 主行换停摆披露句，**不许出现「没有要管的东西」**（没付电费不是无事发生） |
| 26 | U7 | 停摆/降档披露句 | **本件冻**（§4：两句，宽度 14/14） |
| 27 | U7 | 粮账不存在时 | 已预决（`granary.state()="off"`＝没记过账＝没在消耗，不 at-risk） |
| 28 | U7 | 补粮的入口 | 已预决（`antinel 粮` CLI 已存在，`cmd_granary`；动作句指向它） |
| 29 | U8 | 互斥判据喂什么 | 已预决（N9：`gap_state=open ∧ info 桶有账` 夹具） |
| 30 | U8 | 豁免清单 | 已预决（N9：期间行/徽标语/跨屏三项豁免） |
| 31 | U9 | expected 公式 | **挂起**（F6：形状冻，公式参数由 T2 实测选） |
| 32 | U9 | 睡眠证据从哪来 | 已预决（T2：电源事件 6005/6006，**拿不到不猜**） |
| 33 | U9 | 与 write_health/lost.json 的关系 | **本件冻**（F6：三层叠加，任一层阳性 ⇒ unbounded） |
| 34 | U10 | tense 五值字面 | **本件冻**（F3：`never/now/past/future/unknowable`） |
| 35 | U10 | blind 的时态 | **本件冻**（F3：必须 `unknowable` 显式登记） |
| 36 | U11 | 30 分钟阈值 | 已预决（N12 原设计） |
| 37 | U11 | 无头场景 | 已预决（N12：没有通道不是通道坏了，不算 unknown） |
| 38 | U11 | `delivery_unknown` 的 schema | **本件冻**（F7 登记草稿全文） |
| 39 | U11 | notice_log 放哪 | **本件冻**（F7：`~/.antinel/console/notice_log.jsonl`，不进链） |
| 40 | U12 | 六个渲染点各读什么、渲染什么 | **本件冻**（§3.1 九行契约表） |
| 41 | U13 | 旧屏句子改动规则 | **本件冻**：只换**状态词**出现处；动词与计数一律不动；每处登记连带台账（施工件 §4.5 格式） |
| 42 | U13 | 「挡下」vs「拦截」二义 | **本件冻**：**「挡下」作动词、「拦截」作能力名，名词义只留一个**（施工件 §6.6 立案的终裁） |
| 43 | U14 | sidecar 行形状 | **本件冻**（F8） |
| 44 | U14 | 采集点位置 | **本件冻**（`inbox_daemon.tick` 一处，每日滚） |
| 45 | 横切 | 判据编号 | 已预决（施工件纪律：不预写，开工按注册表分配） |
| 46 | 横切 | 新链 kind 的登记义务 | **本件冻**：凡新增链记录类型，**同批**改 AUDIT_SCHEMA＋`tools/verify_event_types.py` 复核（0.40.0/0.51.2 两次同型事故的纪律化） |
| 47 | 横切 | 旧代码读新数据 | 已预决（施工件 §9：只加字段不改语义 ⇒ 向后兼容单向；`SITUATION_V2=0` 一行回滚） |

**统计**：47 个猜测点＝本件冻结 29＋已预决 14＋混合 1（已预决＋本件补冻）＋
挂起 2＋已实现 1＝47。
**没有「没人认领」的猜测点**——这是「编码不猜」的底线。

### 3.1 U12 九行渲染点契约表（本件冻结）

| 渲染点 | 读 facts 的 | 渲染哪一维 | 文本通道 | 判据 |
|---|---|---|---|---|
| 网页顶部条 `_bar()` | `lamp`/`cause`/`sentence.main` | 灯＋主行 | 有（主行即词） | I6 各一条＋S104（账句优先） |
| 网页状态页 | `posture` 全量＋`presence` | 姿态＋在场 | 有 | T4-06 族 |
| 托盘图标 | `lamp`（SPEC 形状）＋`badge`（SHIELD_MARKS） | 形状＋色 | tooltip（有） | T1 的 G-a/G-b |
| 漂浮哨标 | `lamp` 目标态帧 | 帧 | 无（hover 出词条） | 0414 族＋T1 同尺寸腿 |
| favicon | **不读状态**（品牌标） | — | — | G-c（不许回退成状态编码） |
| `.lnk` | **不读状态**（品牌标） | — | — | 同 G-c |
| 窗口标题 | `lamp` 派生词 | 词 | 有 | 0470 S93 族 |
| CLI（ledger/host-shield 输出） | `sentence`/`day_counts` | 词＋计数 | 有 | U13 规则＋D7 |
| 日报 | `day_counts`/`event_short` | 计数 | 有 | U13 规则 |
| 气泡 | `level`/`kind` | 弹窗 | 有 | 0514 B-18 族＋N12 |

> 与 D-12（渲染点×许可词矩阵）的分工：D-12 管「**哪个词**允许出现在哪个渲染点」
> （矩阵外出现即红）；本表管「**哪个渲染点读 facts 的哪一维**」（G9/G12 的落点冻结）。
> 两条判据各守各的，不互相替代。

---

## 4. 句子冻结（§0 高危点 1 的裁决：八成因三句式＋全部新句，宽度实算）

**规矩**（实现者照抄，不许「换个说法」）：定义句进术语表（≤40 显示宽）；显示句上
主行（≤48，FZ-004 腿）；动作句进 `remediation`。宽度按 T4-07（汉字 1／其余 0.5）
实算，D7（42 字符）同批校；**每个句子的数字位用同一个派生源**（`facts` 字段），
不许句子里现算。

> **宽度是脚本算的，不是心算的**：本件全部 31 句由 `output/_p_sentence_width.py`
> 按 T4-07 逐字复算（含 N/M/D 占位符按 1 位／2 位数字两种取值各算一次）。含占位符
> 的句子宽度记「1 位/2 位」两值。**心算版本曾错 12 处**（1–3 个误差，最夸张的
> `absent` 定义句差了 3）——这正是「无猜测审核」对自己也适用的地方：尺子量的地方，
> 脚本算。产品落地后该探针的复算逻辑退役进判据（§6 第 3 条）。

### 4.1 八成因三句式（冻结）

| 成因 | 定义句（术语表） | 宽度 | 显示句（主行） | 宽度 | 动作句 |
|---|---|---|---|---|---|
| `unarmed` 未启用 | 还没开启，现在不拦也不记账。 | 14 | 还没开启，现在没有任何东西在替你看门。 | 19 | 去开启 |
| `drill` 演练中 | 在跑，但结论不代表真实防护。 | 14 | 正在用还没发布的版本守着，能拦的照拦。 | 19 | 不用动 |
| `ok` 值守中 | 监理在岗，这段时间没查出缺口。 | 15 | 今天没什么要拦的。它在盯着。 | 14 | 不用动 |
| `paused` 暂停中 | 监理不在岗，但这段时间没有要管的东西。 | 19 | 监理暂停了一会儿，这会儿没有要管的东西。 | 20 | 重新拉起 |
| `draining` 快没粮了 | 监理在岗，但哨兵的口粮快用完。 | 15 | 粮还够 N 天，用完监理会停。 | 13.5/14 | 补充口粮 |
| `breach` 有缺口 | 监理在岗，但有该挡的没挡住，到现在没修。 | 20 | 有 N 处没修，最早一处是 D 天前。 | 16/17 | 按清单逐项修 |
| `absent` 失守 | 监理不在岗，且这段时间有东西没被挡。 | 18 | 监理不在岗。这段时间有 N 件没被挡。 | 17.5/18 | 先拉起，再看清单 |
| `blind` 看不清 | 监理认不出自己是不是在守，说得出缺什么就只报那一项。 | 26 | 我证明不了自己在守。按最坏算，先核对一次。 | 21 | 核对或重装 |
| `partial` 没查到 | 有一项没查到，已按有问题算。 | 14 | 有 N 项没查到，先按有问题算。 | 14.5/15 | 去查没查到的那几项 |

（`drill` 身份句按已签收第 2 条：**有账或缺口时退徽标**，主行让给账句/成因句。）

### 4.2 主行构成规则（冻结，消解「哪句上主行」的所有猜测）

```
主行 ＝
  未启用            ⇒ unarmed 显示句          （不许报平安，立规⑤）
  此刻有缺口        ⇒ breach/absent/blind/partial 显示句   （优先于账句）
  有 action 账      ⇒ 「有 N 件事只有你能办。」
  有 info 账        ⇒ 全 L2「最近 24 小时挡下 N 次，都替你处理完了。」（19.5/20）
                      混合「最近 24 小时挡下 N 次，另有 M 条变动，都替你处理完了。」（已签收第 3 条；宽度 27/28，两把尺过）
  无账 ∧ drill      ⇒ drill 显示句
  其余              ⇒ ok 显示句（含 draining：draining 显示句）
```

### 4.3 其余新句（全部冻结，宽度实算）

| 句 | 文本 | 宽度 | 去处 |
|---|---|---|---|
| E3b 截断 | 这次只看了 N 处，还有 M 处没看——没看的部分当空白读，不要当成「没问题」。 | 36/37 | 体检页（D7 贴边：两位数占位时 42 字符，恰好压线，不许再加字） |
| at-risk·粮 | 粮还够 N 天，用完监理会停。 | 13.5/14 | 徽标＋黄灯主行 |
| at-risk·心跳 | 监理 N 分钟没动静了（平时 10 分钟一次）。 | 20.5/21 | 徽标＋黄灯主行（v1.20 已冻句；N6 表句同槽，取本句——已上屏、含基线） |
| at-risk·心跳·tooltip | 再断会自动重拉，不用你动手。 | 14 | tooltip（N6 表句的后果半句在此，不进主行） |
| at-risk·磁盘 | 账本快写不下了，写不下就不能记账。 | 17 | 徽标（N6 原句，**不造「N 天」**——每台机增长率不同，首版无据） |
| 守备档披露 | 现在只看基础目录，钩子停了。 | 14 | 徽标＋运行状态页 |
| 停摆披露 | 口粮用完了，这段时间没在守。 | 14 | 收件箱＋期间行 |
| 迁移首红解释 | 这些是升级前留下的问题，那时候报不出来。现在报给你了。 | 27 | 一次性提示（D-06 原句，逐字不改） |
| 旧词迁移提示 | 以前的『失守』，现在按三种说法讲。 | 17 | 一次性提示（D-06 原句，逐字不改） |

## 5. 对拍夹具扩充：31 行 → 57 行（§0 高危点 4 的裁决）

### 5.1 夹具纪律（D-01 四条＋本件补三条）

**D-01 四条**（地基件 §5.1，原文生效）：① 期望值**从设计意图派生，不从现行实现抄**
（「现行今天给什么」列只是对照）；② 夹具自身带负控——改任何一行期望值 ⇒ 必须红；
③ 判据化时断言改为 `import` 产品真源，本表退役进 `ci/`；④「现行今天」列未逐一活体
实测，复跑按实测更正，**不许转抄**。

**本件补三条**：

5. **落点单源**：57 行全进一个数据模块 `ci/_situation_cases.py`（纯数据＋期望，
   **无断言、不 import 产品**——它不含逻辑就没有「副本钉成尺子」的问题）；判据文件
   import 它。**不许把 57 行抄进任何判据文件**（R4 同一件事一处实现）。
6. **行格式五字段，缺一不进表**：`id`／`unit`／`overrides`／`expect`／`neg`。
   `overrides` 只写与 §5.2 基线不同的字段；**基线若变，全表重算**，提交信息必须记。
7. **换值自证**：任何人改期望值或负控值，同批重跑「改一行 ⇒ 红 ⇒ 还原 ⇒ 绿」
   （D-11 台账同款纪律），提交信息记锚点行号。

### 5.2 facts→四轴映射表（本件冻结——47 个猜测点不许从这道缝漏回来）

F2 冻的投影签名是 `lamp(facts, scope)`，而 D-01 的 31 行是**四轴**输入。两者之间
必须有一张**唯一的映射表**：不冻它，实现者就自己决定「哪个 facts 字段驱动哪个轴」，
第 1–47 号猜测点会整批从这道缝复活。

**基线 facts**（全绿底；57 行共用，行内只写与基线不同的字段）：

```
BASE = {
  "scope_device": "DEV-0", "scope_host": None,
  "armed": True, "is_dev": False,                        # mode（D-02 既有字段）
  "sentinel_alive": True, "heartbeat_age": 120.0,        # 秒；fresh
  "heartbeat_source": "registered", "sentinel_uptime": 7200.0,
  "clock_skewed": False,
  "granary_level": "ok", "granary_balance_hours": 240,   # 小时（HOURS_PER_DAY=24）
  "credits_low_open": False,
  "self_check_ok": True, "chain_integrity_ok": True,
  "chain_write_lost": 0, "probe_error": None,            # trust
  "gaps": [], "outage_consequences": [],                 # harm
  "partial_read": None, "at_risk": [], "chain_recon": "ok",
  "notice_state": None, "counts": {"action": 0, "info": 0},
}
```

| 轴值 | 成立条件（facts 侧唯一写法） | 出处 |
|---|---|---|
| mode=`unarmed` | `armed is False` | D-03 §4.1 |
| mode=`drill` | `armed is True ∧ is_dev is True` | D-03 §4.1 |
| mode=`armed` | `armed is True ∧ is_dev is False` | D-03 §4.1 |
| `armed is None` | **不许落 unarmed**：`trust=bounded ∧ duty=off`（探针 exception 路径） | D-02/D-03 |
| duty=`on` | `sentinel_alive ∧ (heartbeat_age ≤ 1800 ∨ (heartbeat_age is None ∧ sentinel_uptime ≤ 1800))`——1800＝`_STALE_AFTER`，派生不写死 | D-03 §4.2 |
| duty=`at-risk` | duty=on ∧ (`granary_level=="low"` ∨ `credits_low_open` ∨ `heartbeat_age > 0.5×_STALE_AFTER` ∨ `at_risk[]` 非空) | D-03 §4.2＋N6 |
| duty=`off` | `¬sentinel_alive ∨ (alive ∧ ¬fresh)`；含 age None ∧ uptime>1800、进程死、心跳陈旧 | D-03 §4.2 |
| trust=`unbounded` | `(self_check_ok is False ∧ 问题非 dev_exempt) ∨ chain_integrity_ok is False ∨ chain_write_lost>0 ∨ chain_recon=="lost_suspect"` | D-03 §4.3＋N4 终裁二＋F6 |
| trust=`bounded` | `probe_error ∨ (heartbeat 读不到 ∧ heartbeat_source is None) ∨ clock_skewed ∨ 非核心探针失败 ∨ armed is None ∨ partial_read 落在受监管落点` | D-03 §4.3＋N7 |
| trust=`sound` | 其余 | D-03 §4.3 |
| harm=`some` | `∃ gap ∧ gap.gap_state ∈ {"open","acked"}`（**缺口族**，族界见下） | D-03 §4.4＋`3a6bf7f` |
| harm=`unknown` | **仅随** trust=unbounded（裁定 R2） | D-03 §4.4 |
| harm=`none` | 能统计 ∧ 无 open/acked | D-03 §4.4 |

**三条连带冻结**（走查时撞出的真冲突，不冻就会猜）：

- **harm 的族界**：D-03 §4.2 把 `credits_low_open` 列进 at-risk 来路，而 §4.4 的
  harm=some 判据是「∃ gap_state==open」——若 `credits_low` 这类**预告族**记录也算
  harm，缺粮就直接红，撞翻 N6/N8（缺粮＝黄）。冻结：**harm 只收缺口族**（D-04 映射表
  七族：`host_shield_tamper`/`code_drift`/`state_drift`/`zone_lock_failed`/
  `autostart_missing`/`spawn_failed`/`host_shield_breach`），预告族只进 at-risk/徽标。
  判据：`gaps=[credits_low(open)] ∧ 余全绿` ⇒ 必须 green/ok 且徽标「缺粮」；
  负控：预告族并进 harm ⇒ 红。
- **acked 不算修**：`acked`（知道了）不是 `closed`（修了）——`3a6bf7f` 堵的正是
  「先不管＝永远不管」这个洞。故 harm=some 含 acked；14 天复核到期且仍在时间窗内、
  有后果、需本人处理的**重新进「要看」**（`unrepaired_count()` 的 n 与 due 分开给，
  不合成一个数，F40）。判据：`gaps=[breach(acked)]` ⇒ 仍 red/breach；负控：acked
  退出 harm ⇒ 红。
- **停摆的来路可判**：duty=off 有多个来路，句子要靠来路选。冻结：
  `granary_level != "off" ∧ granary_balance_hours < 0` ⇒ **停摆来路**（口粮真归零，
  N8 的 `balance < 0`）；其余 off ⇒ 进程/心跳来路（用户暂停、崩溃）。负控：崩溃停岗
  而余额未负 ⇒ 必须用 paused 显示句（不指控没证据的原因）。

### 5.3 26 个新行（N5–N12；输入为相对 §5.2 基线的 overrides）

| 行 | overrides | 期望（lamp／cause＋关键断言） | 负控（改什么 ⇒ 必须红） |
|---|---|---|---|
| N5-a | `{"armed": False}`（链 `armed=false`，state 文件 `enabled=True`） | grey/unarmed；主行 unarmed 显示句 | **结构判据守来源**：`facts.py` 直读 `load_state()["enabled"]` 计数＝0（AST 数调用点）；直读 ⇒ green 假绿 |
| N5-b | `{"armed": True}`（链无 changed 记录，回退 state 文件） | green/ok | 链无据时返回 None ⇒ 落 unbounded/blind 假红 |
| N6-a | `{"granary_level": "low", "granary_balance_hours": 100}` | yellow/draining；`at_risk` 含 `granary_low`；徽标「缺粮」；主行「粮还够 4.2 天，用完监理会停。」（100÷24） | ① balance=200 仍亮 ⇒ 红；② 阈值写死「7 天」切断 `LOW_THRESHOLD` 派生 ⇒ 红 |
| N6-b | `{"heartbeat_age": 1000.0}`（>900 且 <1800） | yellow/draining；`at_risk` 含 `heartbeat_will_stall`；主行「监理 16.7 分钟没动静了（平时 10 分钟一次）。」 | ① age=600 亮 ⇒ 红；② 阈值写死 900 切断 `_STALE_AFTER` 派生 ⇒ 红（N6 原负控） |
| N6-c | `{"egress_free_bytes": 15728640}`（15MB < 19.6MB＝7 天写入量，84MB/月实测折算） | yellow/draining；`at_risk` 含 `disk_write_full`；徽标磁盘句 | ① free=200MB 亮 ⇒ 红；② `capacity()=None` 亮 ⇒ 红（拿不到就说拿不到，None 当满＝猜） |
| N7-a | `{"partial_read": {"seen": 320, "total": 812, "why": "预算内未完成"}}`（受监管落点） | yellow/partial；主行「有 1 项没查到，先按有问题算。」；体检页出 E3b 原文「这次只看了 320 处，还有 492 处没看——……」 | 截断分支静默跳过（truncated 而 trust=sound）⇒ 红 |
| N7-b | `{"partial_read": {"seen": 40, "total": 55, "why": "宿主探测预算"}}`（**非核心面**） | **green/ok**（不降灯，BL-08 分层）；只登记 | 非核心面截断也判 bounded ⇒ 红（防「一律降级」把黄灯变噪音） |
| N8-a | （基线即标准档） | green/ok；**无**「缺粮」徽标、无披露 | 标准档挂徽标 ⇒ 红（D-10：条件为假必须消失） |
| N8-b | `{"granary_level": "low", "granary_balance_hours": 10}`（0≤10<24 ⇒ 守备档） | yellow/draining；徽标「缺粮」＋披露「现在只看基础目录，钩子停了。」；**当日 spend 金额＝12**（档位派生） | spend 写 24 ⇒ 红（守备档半价；写死 24 每天多扣一倍） |
| N8-c | `{"granary_level": "low", "granary_balance_hours": -5, "sentinel_alive": False}`（停摆·无损失） | yellow/**paused**＋主行换「口粮用完了，这段时间没在守。」；**不许出现「没有要管的东西」** | ① 停摆用 paused 显示句 ⇒ 红；② 来路判据（余额<0）失效 ⇒ 红。叠加 `gaps=[breach(open)]` ⇒ red/absent（D-01 第 8 行已覆盖，此处只加「停摆句不变」） |
| N9-a | `{"gaps": [{"kind": "host_shield_breach", "gap_state": "open"}], "counts": {"action": 2, "info": 5}}` | red/breach；主行 breach 显示句；**同屏不许出现「都替你处理完了」** | 把 info 桶句拼进主行 ⇒ 红（N9 原负控） |
| N9-b | 同上＋`{"period_line": "最近 24 小时挡下 5 次，都替你处理完成了。"}`（info 句只在**期间行**） | red/breach；期间行出现 info 句**不判红**（豁免①） | 判据把期间行 info 句也判互斥 ⇒ **判据自身假红**（负控的负控） |
| N10-a | `{"chain_recon": "lost_suspect", "chain_write_lost": 3}`（一天缺 3 条心跳） | red/blind（trust=unbounded）；对账报差 | 差≤1 也判 lost ⇒ 红（N10：差>1 才报） |
| N10-b | `{"chain_recon": "lost_suspect"}`＋DST 23h 日夹具 | 分母必须是 **138**（23×600），报差形状不变 | 分母写死 144 ⇒ 在 23h 夹具下必须红（N10 原负控） |
| N10-c | `{"chain_recon": "unknown_window"}`（保留窗外日期） | **不进判定**：trust 不因此降、灯不变；只登记「这段不可对账」 | 窗外判 lost_suspect ⇒ 假红 |
| N11-a | `unarmed` 成因行 | `tense == "never"`（从未启用） | 八行共一条：删空/挪格 ⇒ 红（N11 原负控） |
| N11-b | `drill` 成因行 | `tense == "never"`（此构建从未发布） | 同上 |
| N11-c | `ok` 成因行 | `tense == "now"` | 同上 |
| N11-d | `paused` 成因行 | `tense == "past"`（刚停过） | 同上 |
| N11-e | `draining` 成因行 | `tense == "future"` | 同上 |
| N11-f | `breach` 成因行 | `tense == "now"`（**缺口此刻还在**；事件是过去，成因取状态时态） | breach 登记成 `past` ⇒ 红（那正是 F1：用时间窗判过去） |
| N11-g | `absent` 成因行 | `tense == "now"` | 八行共一条 |
| N11-h | `blind` 成因行 | `tense == "unknowable"`（**必须显式登记，不许留空**） | 留空/塞进「正在」⇒ 红（I5 折叠） |
| N12-a | `{"notice_state": "sent", "notice_age_min": 45, "downgrade_ok": True}` | 降级成功 ⇒ **不记** `delivery_unknown`；托盘角标＋首屏横幅出现 | 降级成功也记 unknown ⇒ 红 |
| N12-b | `{"notice_state": "sent", "notice_age_min": 45, "downgrade_ok": False}` | 链上出现 `delivery_unknown`（L1），字段 `{ts, kind, downgrade, minutes_overdue}` | ① 删链记录 ⇒ 红；② schema 未同批登记 ⇒ harness F-10 红（0.40.0/0.51.2 同型） |
| N12-c | `{"notice_state": "sent", "headless": True}` | **不算 unknown**（没有通道不是通道坏了）；走文件通道 | 无头场景判 unknown ⇒ 红 |

> **26＝2+3+2+3+2+3+8+3**（N5–N12 各行数），31＋26＝57。§5 新冻的三件事
> （夹具纪律三条／映射表 14 行／26 个新行）**不新增猜测点编号**——它们是第 20/31/45 行
> 等既有猜测点的展开。实现者若在 §5 之外又遇到选择，那就是本件的漏：登记为第 48 号
> 猜测点走同款裁定（§9-1 的自证入口）。

## 6. 编码契约（防错十条——「基本不引入新错误」的纪律化）

1. **判据先于代码**：动某个单元的产品码之前，该单元的判据（含 §5 对应夹具行）先立并
   自证会红（变异→红→还原→绿）。夹具行没进 `ci/_situation_cases.py`，不许开那个
   单元的码——「先写码后补判据」是本仓假绿的标准入口。
2. **句子照抄 §4，禁临场写**：所有上屏字符串从 §4 表与 N6/N7/N8/D-06/D-10 原句
   **逐字**取；要改句子＝改本件＋重算宽度＋过状态词网，不许在渲染层顺手写一句。
   宽度由判据按 T4-07 复算（`output/_p_sentence_width.py` 的复算逻辑退役进 `ci/`）。
3. **新链 kind 同批登 schema**：`gap_fixed`（U4）与 `delivery_unknown`（N12）**同批**
   改 `docs/AUDIT_SCHEMA.md`＋过 `tools/verify_event_types.py`；D-13 的 `red_minutes`
   写侧加列同批过复核。0.40.0／0.51.2 两次 F-10 同型事故，第三次不许发生。
4. **判据 import 产品真源，不复制逻辑**：投影三函数（`lamp`/`cause`/`sentence`）的
   唯一实现落产品码；判据只 import＋喂夹具；`_situation_cases.py` 不含逻辑。
5. **共享文件先知会（R3）**：`inbox_model.py`/`host_shield.py`/`granary.py`/`egress.py`
   是并行线落点。动之前看对方 worktree 是否在飞（`b18-bubble-health` 先合回）；
   在飞改动不许裸放（`wip/` 分支）；只 `git add` 显式路径（R2）；提交走 `--no-verify`
   **并在提交信息注明理由**（D-22/D-23/D-36 三既有档案红）。
6. **编号不预写、不新开套件**：判据 ID 一律开工时按 `ci/delivery_gate.py` 注册表分配
   （本件所有「判据」处均无编号）；新判据落既有套件（`RESIDENT_SUITE_CAP=29`）。
7. **错误信息字面**：新增日志/异常串一律英文小写短串＋可 grep 的稳定前缀
   （`situation.facts.missing:<field>` 型）；中文状态词进日志同样过「一词一义」——
   状态词网管所有出现处，不限于上屏面。
8. **失败路径不静默**：探针抛错 ⇒ 该字段 None＋`trace.missing` 记名（F1）＋daemon
   tick 的 `out["errors"].append` 同型；**不许 except 后当没事**。负控：把 except
   分支改成 pass ⇒ 红。
9. **向后兼容单向**：只加字段不改语义（施工件 §9）；`SITUATION_V2=0` 一行回滚点必须
   真实存在（判据守：置 0 ⇒ 旧路径全绿）。旧数据派生同向保守（`ignored → acked`、
   `done → closed`；无证据 ⇒ `open`）。
10. **每步跑全部十套判据＋活体回读**（闸四），不只跑本步那套；判据进程 `-u` 跑；
    跑闸门必带 `TMPDIR=D:/_tmp`，日志查尾部 EXIT；活体三查（`url.json` pid → 该 pid
    命令行确认仓根 → `code_mtime`）；测活体性能走 HTTP 或 `python -I -S`。

## 7. 实现顺序 DAG 与每步验收

### 7.1 DAG（十节点，箭头＝依赖）

```
0a state_registry（F3 态表）──┐
0b _situation_cases（57 行）─┤（0b 期望值引用 0a 的成因键）
1  facts.py（F1＋§5.2 映射）──┼→ 2 situation.py（lamp/cause/sentence）─┬→ 3 模式层＋形状编码（T1）
                              │                                        ├→ 4 渲染点改造（§3.1）＋通知链（N12）
                              │                                        ├→ 5 presence()＋披露句
                              │                                        └→ 7 sidecar（T3，可与 3–5 并行）
                              └→ 6 判据迁移（D-11 台账 16 行）＋负控（依赖全部）
```

### 7.2 每步验收（「跑起来」的具体清单）

| 步 | 验收（全绿才算过） |
|---|---|
| 0a | 11 字段齐全；六旧键保留为能力键；`legacy_of` 映射全仓唯一；`tense` 五值封闭且 `blind` 显式 `unknowable` |
| 0b | 夹具自证（改一行期望 ⇒ 红）；行数探针数＝57（不心算）；五字段无缺 |
| 1 | 白名单九类逐个有值或 `trace.missing` 记名；`_clock_skewed` 负数检测不误报；**映射表反查**：把 §5.2 实现成约 20 行纯函数跑 81 格，输出与 `output/_p_state_matrix.py` 的 `ref_lamp/ref_cause` **逐格 0 diff**（「映射表没漏」的可执行证明） |
| 2 | 57 行夹具全绿；D-01「现行今天给什么」列的偏差逐行登记（不许转抄）；「同输入两次投影 diff=0」（Q8） |
| 3 | 色觉模拟下四灯可分；16px 人眼实测（**挂起门**：未测不许签「可辨」，P1 准入条件） |
| 4 | §3.1 六个渲染点逐个活体回读；N9 同屏互斥判据绿；favicon/.lnk 不读状态（G-c） |
| 5 | 构造 8h 空档 ⇒ 期间行列出分钟数＋asleep 标注（D-05 §6.3 正判）；与账本对账 |
| 6 | D-11 台账 16 行逐条「变异→红→还原→绿」**实测记录**（不纸面预测） |
| 7 | 两次汇总是同一结果（H-e）；day-30 决策规则按 T3 执行（今天定死的规则，不是当天再议） |

## 8. 挂起项诚实清单（裁不掉的，为什么裁不掉）

**参数级 2 个**（机制与形状已冻，数值待实测——有校准路径，不是猜）：

1. **F5 扫描预算首版值**（dirs=500／bytes=64MB／seconds=20）：挂 T3 旁路指标
   「截断发生率」，实测后校准。
2. **F6 expected 公式参数**（ awake 秒数 vs 墙钟秒数做分母）：挂 T2 三钟实测
   （预判 S3：进程内 monotonic 睡眠恢复后不前进 ⇒ 期望须扣睡眠时段；睡眠证据拿不到
   不猜）。挂的是一个参数，不是形状。

**门级 4 个**（来自《四项在飞事项施工方案》，是设计的一部分不是缺口）：

3. **T1 16px 人眼可辨实测**（duty 对 ≥90%）：未测不许签「可辨」。
4. **BL-07 命题①实测**：翻案条件的实测腿（源码已证 `_sentinel_uptime` 只用墙钟、
   `_clock_skewed` 是负值检测，翻案条件「问错对象」已作废；剩两条可测命题的实测）。
5. **两个 30 天观察期**（Q5 红灯阈值先报数；info 桶未读且过保持期条数）：
   day-30 决策规则已在 T3 今天定死。
6. **两处跨线确认**（N1 残余「灯定落点、判定降级」两层各管一层；N10 与 S54-release
   合成「绕过留痕」机制件）：需代码线签字，本线不单方面落地。

**设计侧待指认 2 个**（本件走查新查出，不挂会变成实现者的猜测）：

7. **`chain_integrity_ok` 的入口**：`self_check()` 是否已含链完整性校验，地基件 §4.3
   自述「入口待明确」。在代码线指认前，判据只断言「trust 输入含链完整性」，
   **不断言具体入口**（防锚在错函数上假绿）。
8. **D-01「现行今天给什么」列未逐一活体实测**（地基件自述）：复跑按实测更正前，
   该列**不作为任何期望值来源**（纪律④的执行口径）。

## 9. 自我证伪（本件自己的尺子）

本件若失效，最可能的四种方式，各配可执行的反证：

1. **「冻结」其实把猜测写成了决议**：47 个猜测点里若有哪个的真实状态是「没人想过」
   而被写成「已预决」，实现者会照错形状施工。**反证**：§3 每行给出处（章节号或源码
   行号）；本件撰写时已回源取证 23 处（行号见正文）；抽查 10 行回源核对作为提交前
   自检。
2. **映射表漏轴**：§5.2 若漏了某个字段到轴的映射，实现者会自己补一个。**反证**：
   映射表行数＝D-03 四轴取值全枚举＋2 条特例路；§7-1 的「81 格逐格 0 diff」是
   可执行证明——0 diff 不成立 ⇒ 本件 §5.2 有漏，先修映射表再开工。
3. **宽度探针自己错**：`_p_sentence_width.py` 的 `east_asian_width` 口径若与 T4-07
   原文不一致（如全角标点的计法），全部宽度作废。**反证**：探针对已知宽度的手工
   样本自证（本仓量具自证惯例）；T4-07 口径原文引用进探针 docstring；判据化时
   （§6-2）用同一函数复算，探针与判据不许两个口径。
4. **本件与并行线撞车**：代码线若在在飞改动里动了 `inbox_model.current_state` 的
   签名或 `guard_posture()` 的返回字段，F1/F2 的冻结即刻过期。**反证**：§6-5
   （R3 先知会）＋每个阶段开踢前重取一次接口事实（本文行号会漂，开踢日以当次
   实测为准并登记偏差）。

---

## 10. 挂起项落实进展（2026-10-22 晚·第一轮取证）

> 创始人指令「全部猜测点都要落实，特别是挂起的」。本轮把 8 个挂起项里**能自己取证的
> 全部取证完毕**：2 个闭合、2 个拿到强证据、1 个拿到实证边界、1 个测试页已生成待
> 人眼。以下每条都给实测数据与据此做的设计修正。

### 10.1 挂起项 7（`chain_integrity_ok` 入口）——**已闭合**

**取证**（主树 `4d19a6a` 源码实测）：`self_check()`（`host_shield.py:2297`）只做
**manifest 哈希**（自身＋`_GUARDED_CHAIN_FILES` 四件：`:976`），**不含链校验**；
链式校验（prev/hash 重算＋同父分叉＋日锚）在 `tools/verify_chain.py`
（`verify_file_v2`:123／`verify_tail`:136），是**离线 CLI**；L1 写健康在
`audit_chain.write_health()`（`:215`，进程内 `lost` 计数）。

**入口指定（冻结）**：新增 `audit_chain.chain_link_ok(audit_dir)`（薄包装），内部
复用 verify_chain 的纯函数 `index_file/classify`；若代码线选择把这两个纯函数上移
`audit_chain.py`、`verify_chain.py` 改为 import（更合 R4），**两种落点都认，但只许
一处实现**。校验范围＝**当日文件**（保留窗 14 天全查太慢；当日＋昨日足够承重；
窗外不可验 ⇒ 与 N10-c 的 `unknown_window` 同一口径）。`chain_integrity_ok` 与
`self_check_ok` 是**两个输入，不许合并**（一个管代码完整性、一个管证据链完整性）。

### 10.2 挂起项 8（D-01「现行今天」列）——**已实测**

主树代码只读活体（探针 `output/_p_live_facts.py`）：

| 量 | 实测值 |
|---|---|
| `guard_posture()`（无参／包目录两形） | `guarding`／值守中，why=监理在岗 |
| evidence | armed=true、sentinel_alive=true、heartbeat_age≈550s、heartbeat_source=**registered**（自注册目录 `D:\psl\poc\antinel-security\.psl\audit`）、sentinel_uptime≈58,286s、sentinel_pid=35144、self_check_ok=true |
| `granary.state()` | **`off`**（还没记过粮账）——N8-a 夹具的活体实例 |
| `egress.capacity()` | free=19.4GB、low_free=False、dir_bytes=22.3MB、dir_full=False |
| `self_check()` | ok，problems=[] |

⇒ 现行 `guarding` 在新模型下＝armed/on/sound/none ⇒ **green/ok**，与 D-01 第 17 行
期望一致（该行「现行今天」列由此活体确认，不再只是推导）。

### 10.3 挂起项 4 的一半（BL-07 命题②）——**已闭合**

夹具实测（`sentinel_started_at` 置于现在+2h）：

- `uptime=-7200` ⇒ `_clock_skewed=True`、`_elapsed_ok(uptime)=False`、
  posture 降为 `unknown`／注意（**不冒值守中**）。
- 负控（`_clock_skewed` 换成恒 False）⇒ posture 翻回 `guarding`／值守中 ⇒
  **红了，证明它承重**（八项件 §1.8 要求的负控形状，实测通过）。

**文档更正（一处规格不准确）**：八项件 §1.8 命题②写「把 `sentinel_started_at` 改到
未来 ⇒ **age** 为负」——实测**不准确**：心跳 age 来自链上最后一条心跳记录，不受
`started_at` 影响；变负的是 **uptime** 通道。判据写法相应更正为「负值出现在
uptime 通道」（`_clock_skewed(age, uptime)` 两路都查，负任何一路都算）。

### 10.4 挂起项 2 的一半（F6 对账公式）——**历史数据预跑，两条强证据**

保留窗 24 天全量对账（墙钟期望 vs 链上实际心跳条数）：

| 日 | 期望 | 实际 | 日 | 期望 | 实际 |
|---|---|---|---|---|---|
| 09-25 | 144 | **0** | 10-10 | 144 | 256 |
| 09-26 | 144 | 1 | 10-11 | 144 | 197 |
| 09-27 | 144 | **0** | 10-12 | 144 | 186 |
| 09-28 | 144 | 2 | 10-13 | 144 | **114** |
| 09-29 | 144 | **44** | 10-14 | 144 | 152 |
| 10-03 | 144 | **23** | 10-15 | 144 | 166 |
| 10-05 | 144 | **0** | 10-16 | 144 | 149 |
| 10-06 | 144 | **38** | 10-17 | 144 | 159 |
| 10-07 | 144 | 204 | 10-18 | 144 | 150 |
| 10-08 | 144 | **1673** | 10-19 | 144 | 191 |
| 10-09 | 144 | 858 | 10-20 | 144 | **105** |
| | | | 10-21 | 144 | 183 |

**合计期望 3376 vs 实际 4973；缺口 10 天（全负）、盈余 14 天。**

**据此修正 N10 施工口径两条**：

1. **只有缺口指示写丢失，盈余一律良性**。原冻结「差>1 ⇒ lost_suspect」方向错了——
   盈余日（10-08 达 +1529）是多写者/频繁重启的痕迹，**更多写者＝更多证据，不是
   异常**。改为：**差 < −1（容差内）⇒ `lost_suspect`；盈余不判**。
2. **睡眠修正不是可选项**。缺口日的最大相邻间隔 47–376 分钟（睡眠候选）；若不扣
   睡眠，本机 24 天里 **10 天会判 `unbounded` ⇒ 红掉 40% 的天**——正是「长期红的
   守卫＝没守卫」。这是 T2 命题①的**间接证据**（直接证据仍待受控睡眠轮，见 §8）。
3. **登记一项新观察**：链上心跳条数在本机**不是单写者计数**（10-07..10-12 连续
   盈余）⇒ sidecar 增加旁路指标「当日写者数估计」（盈余量/144），与「截断发生率」
   并列进 T3 观察项。

### 10.5 挂起项 1（F5 预算）——**实证边界已取**

- 本机看守范围实测：`state.zones=[]`；watch registry 24 个 host 条目里只有 1 个
  watch 路径（`~/.zcode/v2/checkpoints`，**不存在**）⇒ **本机无校准对象**。
- hook 侧有实测预算家族（`SCAN_LIMIT=4MB`、2MB 时 5.2s／4MB 时 6.6s 端到端、
  `SLOW_BUDGET_MS=8000`，`hooks/pre_tool_use.py:81-84`）——但那是**文本字节**预算，
  与目录扫描是**异质单位**（F54 家规），只借「秒」这一维的家族关系，不搬数。
- ⇒ 结论不变且更诚实：500/64MB/20s 保持「机制冻、数值挂观察项」；**校准发生在
  真有看守范围的机器上**（sidecar 旁路指标「截断发生率」）。本机这条边界本身
  登记进观察项（空范围机器的行为：不扫、不降级、不报数）。

### 10.6 T1 16px 测试页——**已生成，待人眼**

`docs/Antinel·T1 16px 人眼测试页 v1.0（2026-10-22）.html`：用 `mk_icons` 的真实
绘制函数渲染 16px 像素，**与真实 .ico 逐像素同源**（`output/_p_sheet_verify.py`
对拍：alpha＋配色 12/12 全绿；白底合成值差 ≤1 属取整）。含正常视觉／红绿色盲近似
（Machado 2009 矩阵，近似非医疗级）三组，duty 四形态（on 无角标／at-risk·dot／
at-risk·slash／off bar）＋lamp 四色参照，附记录表。

**待创始人**：肉眼测 duty 三维可辨率（门槛 ≥90%）并**定 at-risk 用哪个角标**
（dot 还是 slash）——这是 T1 准入条件的最后一步，测完即闭合。

### 10.7 挂起项状态总账（本轮后）

| # | 事项 | 状态 |
|---|---|---|
| 1 | F5 扫描预算值 | 挂起（实证边界已取：本机无校准对象，数值随 sidecar 校准） |
| 2 | F6 公式参数 | 挂起（间接证据强：10/24 天缺口；直接证据待睡眠轮） |
| 3 | T1 16px 实测 | **测试页已生成**，待创始人肉眼（§10.6） |
| 4 | BL-07 命题 | **命题②已闭合**（夹具＋负控实测通过，§10.3）；命题①待睡眠轮 |
| 5 | 两个 30 天观察期 | 挂起（时间门；day-30 规则已冻，双跑回放可提前出分布） |
| 6 | 两处跨线确认 | 挂起（备忘已在 T4，待代码线签字） |
| 7 | `chain_integrity_ok` 入口 | **已闭合**（§10.1） |
| 8 | D-01 现行今天列 | **已闭合**（活体实测，§10.2） |

---

**本件结论**：47 个猜测点全部有主；2 个参数级挂起有校准路径；4 个门级挂起是设计的
一部分；2 个设计侧待指认已挂并有「指认前不许断言」的防假绿口径。实现者拿本件＋
前六件，不需要在枚举值、签名、文案、阈值、边界、失败路径、旧数据、顺序、文件位置
上做任何一次选择——剩下的只有「把冻结的东西写对」，而那正是判据该管的事。

---

## 11. 三项批准、T1 实测与 0a 开工记录（2026-10-22 中午）

### 11.1 三项拍板：**全部批准**（创始人 12:37）

| 项 | 批准内容 | 落地动作 |
|---|---|---|
| T2 睡眠轮 | 从阻塞项降为**零操作确认项**；N10 公式立即按「扣睡眠时段」落地 | 探针 `output/_p_sleep_probe.py` 常驻（60s 五钟）；跨重启续记待创始人手动建 schtasks（DST-04 拦我代建） |
| 开工落点 | **新开 `.worktrees/impl`** ＋三纪律（判据与活体验收在主树／只 add 显式路径＋`--no-verify` 注明理由／动 `inbox_model`/`host_shield` 前先查 b18） | 已建（`impl-state-machine`，基点 main@4d19a6a；**b18 已合入 main**，纪律检查通过） |
| 跨线两推进 | N1 走「判据即契约」；N10 合并件搭 S54-release 的 D 批车 | 判据在 6 步落；合并件交代码线批次 |

### 11.2 T1 16px 人眼实测——**门槛通过**（创始人实测，12:37）

| 视觉模拟 | duty 三维可辨 | lamp 降级给词 | at-risk 角标选择 |
|---|---|---|---|
| 正常 | 可辨别 | 可接受 | **slash** |
| deuteranopia | 可辨别 | 可接受 | **dot** |
| protanopia | 可辨别 | 可接受 | **dot** |

- **门槛结论**：三组均「可辨别」⇒ duty 可辨率 100% ≥ 90%，T1 的可辨性准入条件**满足**；
  lamp 降级给词三组均可接受（与 T1 原裁一致）。
- **角标已定（创始人 13:05）**：at-risk 用 **dot**。三组原始选择不一致（正常视觉
  slash／两组色盲近似 dot），按 §11.3 的分析与建议取 dot——CVD 安全下限优先于
  正常视觉的醒目度偏好。**T1 至此完全闭合**（可辨率门槛＋角标定案两项都齐）。

### 11.3 at-risk 角标三组分歧的分析（建议 dot，理由如下）

| 事实 | 含义 |
|---|---|
| 两组色盲近似都选 dot | dot 的蓝（`0x2a5db0`）在红绿通道受损时仍在**蓝黄轴**上可辨；slash 的红（`0x9b2226`）叠在绿底上，红绿受损后对比度下降 |
| 正常视觉选 slash | slash 的视觉质量大（对角笔画），正常视觉下更醒目 |
| T1 的硬门槛是「duty 碰撞不可接受」 | 这是**对所有用户**的安全下限，正常视觉的美观偏好不能压过它 |
| 角标只有一枚 | 只能选一个；CVD 用户看到的接近模拟图 |

**建议：dot**。依据：两组 CVD（正是为预测色盲用户体验而做的模拟）都选 dot，正常视觉
对 dot 也判「可辨别」（门槛不受影响）；选 slash 等于用色盲用户的可辨性换正常视觉的
醒目度。**若创始人坚持 slash**，需接受「CVD 用户下 at-risk 与 on 的区分更依赖颜色而非
形状」这一代价，并在 T1 记录里写明。

**已定（创始人 13:05）：dot。** 冻结落点：`SHIELD_MARKS["unknown"]`（dot 蓝
`0x2a5db0`）成为 at-risk 角标；`unposted`（slash 红）保留为旧键能力，不再用于 at-risk。

### 11.4 两处新规格矛盾：登记为第 48/49 号猜测点（0a 开工时撞出）

- **#48 drill 是不是成因**。矩阵 `CAUSES`（`output/_p_state_matrix.py:66-75`）与 F3
  枚举都是 8 键（无 drill）；但 §4.1 表有 drill 行、§5.3 N11-b 写「drill 成因行」、
  N11 八行又缺 `partial`。**裁定（四条结构证据）**：drill 是**模式层身份**不是成因——
  ① I4 动作单射会破（drill「不用动」与 ok 同类）；② drill 的灯由成因决定（干净格
  green/ok），固定 lamp 条目装不下；③ §4.2 把 drill 作主行分支；④ 矩阵 8 键是 I4
  唯一真源。⇒ 8 成因条目＋`MODE_IDENTITY["drill"]`；`partial.tense="now"`（N11-f
  「事件是过去，成因取状态时态」派生）。**N11 夹具需相应更正**（drill 行改「模式身份
  行」、补 partial 行）——0b 落盘时执行。
- **#49 `legacy_of` 的映射值**。F3 只冻了「有该字段、全仓唯一」，**没冻值**。按
  `light()` 旧判读顺序（`inbox_model.py:2449-2530` ①–⑥）派生为旧键→新成因列表：
  R0→[absent,breach,blind]（down∧后果／warn 认不出门／失守事件）；L2→[ok]（拦截
  进 info 账句不抬灯）；L1→[paused,partial]（缺岗无损失／探针抛错与集合外）；
  Ls→[draining]；L0→[ok,unarmed]（灰变体）；dev→[drill]。

### 11.5 0a 已落盘（`3a83135`，impl 树）

`state_registry.py`（211 行）：8 成因条目（11 字段齐全）＋`MODE_IDENTITY`＋
`DISPLAY_SENTENCE`/`ACTION_SENTENCE`（§4.1 逐字）＋`LEGACY_KEYS`/`LEGACY_OF`＋
`selfcheck()` 六条结构自检。验收实测：
- `selfcheck()` 全绿（8 causes／6 legacy keys／5 tenses）；自检当场抓出我自己的
  `dev→drill` 校验口径错误（drill 不是成因键）并修正。
- 句子与 §4.1 **逐字对拍 9/9 PASS**（`output/_p_registry_sentences.py`）。
- 0a 验收四条全部满足：11 字段齐全／六旧键逐字保留／`legacy_of` 键集与值域闭合／
  `tense` 五值封闭且 `blind` 显式 `unknowable`。

