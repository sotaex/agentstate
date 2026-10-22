<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel·B 线施工日志 v1.2（2026-10-22）

> 本文件在 B 线自己的工位（`.worktrees/bstate`，分支 `b-presentation`）。
> 共享台账 `docs/Antinel·状态机施工台账与任务卡 v1.0` 的 §4 归两条线共同追加，
> 动它之前要看对面在不在改（协作约定 R3）。2026-10-22 15:2x／16:0x／17:2x 三次实测：
> 那份台账都在 design 分支上（`git status` 里它不在本树工作区）⇒ **本步仍不碰它**，
> 三行待粘在 §12。

**v1.1 → v1.2 摘要：新增 §10（B2 · 通知三态与送达兜底，完成）、§11（跨线纠错一条 +
D-20 的完整名单）、§12（台账三行）。** v1.1 已退役为
`Antinel·B线施工日志 v1.1（2026-10-22）.md.away-20261022-1724`，
v1.0 更早已退役为 `.away-20261022-1614`。本节以下的 §1–§9 是 v1.1 原文，逐字保留。

## §1 B1 · 形状编码（角标）—— 完成

| 项 | 内容 |
|---|---|
| 步 | B1（任务卡：`state_registry` 的 `icon` 字段落实 ＋ `mk_icons` 的形状表） |
| 工位 | `.worktrees/bstate`，分支 `b-presentation`，基点 `b258fe3`（含 A0／A1） |
| 前置 | 无（`state_registry` 与 T1 决议均已就绪） |
| 验收 | `output/_p_shape_parity.py`：**正判据 8 绿 / 0 红；负控 7 绿 / 0 红；量具自检 1 绿 / 0 红** |
| 回归 | 0360 **63/0**；0514 **214/0/0**；0372 **28/0**；0481 **12/0** |

## §2 方案选择：(b) 注册表立唯一真源，实测否决 (a)

任务卡给的是两读法（见上一轮盘点）。**实测下来 (a) 不只是"不够优雅"，它是走不通的**：

| # | 事实（可复现） | 后果 |
|---|---|---|
| 1 | `mk_icons.main()` 里是 `SHIELD_SUFFIX[sh]` | 给 `SHIELD_MARKS` 加 `at-risk` 键 ⇒ 循环到它时 **KeyError**，不是少画一个文件 |
| 2 | `SHIELD_SUFFIX` 的 4 个键是 `tray.ps1`／`logo.ps1`／20 个 `.ico` 的文件名后缀；`0514:4383` 把 PowerShell 那行**逐字**钉着 | 要让它不炸就得加进 `SHIELD_SUFFIX` ⇒ 同一批要改两个 PowerShell 文件 + 5 个判据断言 |
| 3 | `0360.c_all_icon_combinations_exist` 按 `SHIELD_SUFFIX` 键集逐格查产物 | 加键 ⇒ 缺 5 个 `.ico` 就红；补齐则是 **B4 的活**，不是 B1 |
| 4 | `on` / `off` 在**两根轴**上都存在 | 混进一张「名字→图案」表，同一个键立刻有两个含义（值勤 `off`＝不该在岗；监理态 `off`＝哨兵未启用） |

⇒ (b)：几何只在 `state_registry.DUTY_MARK` 写一次，`MARK_OF` 只声明「哪个名字借哪一枚」，
`mk_icons.SHIELD_MARKS` 就是 `R.MARK_OF` 本身（`is` 同一对象，探针 ⑧ 守）。

**两根轴分开表达，但共用一个键空间**：资产名键仍是那 4 个（`on/unposted/unknown/off`），
值勤轴新增 `at-risk`。`unknown` 借 `at-risk` 的 dot 是 **T1 的裁决**（角标只有一枚），
属有意耦合 —— 改 at-risk 的几何，5 个 `-unknown.ico` 会跟着变，**必须同批重生成（B4）**。

## §3 改了哪四处

| 文件 | 改动 |
|---|---|
| `state_registry.py` | 新增 `DUTY`／`DUTY_MARK`／`MARK_OF`／`MARK_KINDS`／`mark_of()`；`icon` 改为从 `SHAPE[lamp]` 派生（8 条不再各写一遍）；`selfcheck()` 增第 ⑦ 条 |
| `tools/mk_icons.py` | `SHIELD_MARKS = R.MARK_OF`（删掉本地副本）；角标解析从"每像素一次 `.get()`"提到 `build_ico()` 入口一次；`main()` 循环改用 `SHIELD_SUFFIX` |
| `_p_badge_probe.py` | 4 处调用改传**已解析几何**（原传名字串）；补 `_mark()` 并写明为什么不能用 `.get()` |
| `state_registry.py` 头 | SPDX `CC-BY-SA-4.0` → `Apache-2.0`（**改动前就红**，A0 引入；0481 L1 当场判红） |

## §4 关键证据：像素级

改前基线（`output/_p_icon_hash.json`，25 格 = 5 态 × 5 名）：

```
None|L0            34aa3147c9233a2e      ← 不画角标
at-risk|L0         34aa3147c9233a2e      ← **与上者逐字节相同**（缺陷本身）
unknown|L0         8ffb66c38d49dd29      ← dot
```

改后：

```
对比 25 格，差异 0 格            ← 其余 20 格一格未动（20 个 .ico 不会静默过期）
L0  at-risk=8ffb66c3…  unknown=8ffb66c3…  无角标=34aa3147…  OK
L1/L2/Ls/R0 同上
```

另：`python tools/mk_icons.py` 重生成后 `git status -- assets/icons` **为空** —— 20 个 `.ico`
逐字节不变，与上表互证。

## §5 我在这步犯的/差点犯的错

1. **改内部签名没查全调用点**：`_alpha_at` 从"名字串"改成"已解析几何"，`_p_badge_probe.py`
   还在传名字 ⇒ 0360 T05 当场红。这条判据的调用链跨了 subprocess（0360 → 探针 → mk_icons），
   grep 只在 ci/ 里找是找不到的。**教训：改签名先 grep 全仓 + 记住有 subprocess 这一层。**
2. **判据差点把自己的注释当违规**：`icon` 派生值的第一版检测写成数文本 `"icon":`，
   而注册表注释里恰好写着这个词来解释本条 ⇒ 假红。改成 AST 数"有没有 icon 的字典字面量"，
   并在负控里用两段合成样本证明「真违规数得出 1 / 注释里的串数出 0」。
3. **负控的期望写成了一锅**：`G②` 量具自检期望**绿**，混进"变异后必须红"那一栏被算成失败。
   已拆成 `NEGATIVES`（必须红）与 `GAUGE`（必须绿）两本账。

## §6 B1 留给下一步的（不假装已闭合）

1. **探针在 `output/`，被 `.gitignore` 的 `_p_*` 忽略**，不入库。任务卡 §3 写「探针与产品码
   同批提交」，而 `.gitignore` 说 `_p_*` 一律忽略 —— **两句话对不上**。本步按 `.gitignore`
   执行（不 force-add），代价是换个 AI 接手时从 git 里找不到这把尺子。
   ⇒ 归入 **Z 步（判据迁移）**：那一步要把它落进 `ci/` 常驻，届时同批解决「入库」。
2. **B1 目前没有常驻判据**（`RESIDENT_SUITE_CAP=29` 顶格，Z 步统一迁）。判断依据仍在探针里，
   全量闸门 34 套不会替它守 —— 这是已知缺口，不是"已覆盖"。
3. **B4 前提仍然有效**：改 at-risk 的几何会连带改 `-unknown.ico` 那 5 个资产，必须同批重生成
   并人眼复看（T1 测试页）。
4. **`DUTY` 还没有消费点**：值勤轴真正接进图标是 **X 步（渲染接线）**，本步只把表与查表函数立好。

---

## §8 B3 · 观察 sidecar —— 完成

| 项 | 内容 |
|---|---|
| 步 | B3（任务卡：产出 `sidecar.py`，验收 `output/_p_sidecar_twice.py`，前置无） |
| 读什么 | 《编码前无猜测审核与接口冻结 v1.0》**§F8**（行形状全冻）＋《四项在飞事项施工方案 v1.0》**§3.2**（路径与「唯一源」） |
| 交付 | `sidecar.py`（新模块）＋ `output/_p_sidecar_twice.py`（验收探针：16 正 ＋ 9 负控 ＋ 1 量具自检） |
| 验收 | **正判据 16 绿 / 0 红；负控 9 绿 / 0 红；量具自检 1 绿 / 0 红** |
| 回归 | 0481 **12/0**；0372 **28/0**；0360 **63/0**；0400 **33/0**；0514 **214/0/0**；0353 **215/1**（那 1 红改动前就红，见 §8.5） |

### 8.1 三个可替换的命名函数（判据要能换掉同一份实现）

| 函数 | 守什么 | 负控怎么换它 |
|---|---|---|
| `_day_of(t)` / `_week_of(t)` | 日与周**从行里的 ts** 派生，不从系统时钟派生 | N⑤ 换成 `date.today()` ⇒ C⑮ 必红 |
| `_take_cause(seen)` | M3 取**回合结束时**的主成因 | N③ 换成 `seen[0]` ⇒ C⑦ 必红 |
| `_minutes(a, b)` | 负时间差 ⇒ `None`（**算不出 ≠ 很小**） | N④ 把负值钳成 `0.0` ⇒ C⑧ 必红 |
| `_append_line(path, line)` | 二进制追加，不换行尾 | N⑥ 换文本模式 ⇒ C⑩ 必红 |
| `_ordered_days(days)` | 分组表按名字排序，与追加顺序解耦 | N⑧ 按插入序返回 ⇒ C⑫ 必红 |

抽函数的理由不是好看：**内联在循环里的规则，负控只能复制一份来测副本，副本红不等于线上红。**

### 8.2 行的样子（§F8 逐字，一个字段不多）

```
{"ts": "2026-10-22T16:05:41+08:00", "lamp": "red", "cause": "absent",
 "badge": ["breach"], "info_unread_overdue": 2}
```

- `ts` **带本机时区偏移**（与 `host_shield` 的 `state_writes.jsonl` 同型）。不带偏移的 ts
  在换时区／跨夏令时的机器上无法归属到某一天，而 M1（周）与 M2（日）的分桶全靠这个归属。
- 落点 `<hub>/console/observe_red.jsonl`，目录取 **`inbox_config.console_dir()`**（唯一实现，
  它认 `ANTINEL_HUB_DIR` 沙箱）。**不自己拼** `~/.antinel/console`：自己拼的后果实测过 ——
  设了沙箱的判据会静默读真机文件，判据随机器而飘。N⑦ 守这一条。

### 8.3 写侧严格、读侧只校形状（这是一个判断，不是遗漏）

| 侧 | 校验什么 | 为什么 |
|---|---|---|
| `record()` | `lamp ∈ state_registry.LAMPS`、`cause ∈ 八成因`、`badge` 是数组且键合法、计数是非负 int（bool 不算） | 坏数据写进去，下游三个指标会一起把它当真。**校验在前、落盘在后**：抛错时文件一个字节都不变（C② 同时验这两件事） |
| `iter_rows()` | 只校类型与 `ts` 可解析，**不校枚举** | sidecar 是历史证据，成因表会演进。把枚举校验放读侧 ⇒ 「注册表加/删一个键」会把**历史数据整体变成坏行**，等于把判据绑在会动的锚上 |

读侧见到不认得的 `lamp` 时，`rollup()` 单独计 `lamp_unknown`，**不并进四灯任何一格**（C⑨）。

### 8.4 两个显式限制（写进模块头，免得下一个人以为它做到了）

1. **没有去重键**：一行＝一次采样，同一拍写两次算两行。加 id 就是加第六个字段（违反 §F8），
   而「重试去重」是写入方的语义，不是采样日志能替它决定的。
2. **回合切分按 `lamp` 变化，不按空档**：进程停摆 8 小时后再红，仍算同一回合。
   这是**故意的**——切分阈值是个口径，本模块不拍。它把 `gap_max_min` 与 `rows` 一起报出来，
   让消费方按自己的口径修正。⇒ **M1「红次数/周」因此是上界，不是精确值**；这个偏差是显式的、
   可修正的，而不是藏在汇总里。

### 8.5 一条重要的环境发现：`.psl` 存在与否会让 0353 多出 3 条红

第一次跑 0353 得到 **212 绿 / 4 红**。逐条查分类，没有一条是 B1/B3 引起的：

| 红项 | 原因 | 分类 |
|---|---|---|
| `P12 判据不起真监理［负控］` | `/action op=fix` 返回「当前态势没有可就地修复的动作（监理默认没在值守）」⇒ 没走到 spawn | **改动前就红**（基线复现） |
| `TP-B2 心跳尾窗读` | `(g) 夹具不成立：.worktrees\bstate\.psl\audit 没有 jsonl` | **环境所致** |
| `TP-B2［负控］` | 上一条的连带（正判据没绿） | 连带 |
| `P15 态势读监理那条心跳［负控］` | 链空 ⇒ `sentinel_heartbeat_age()` 与 `heartbeat_age(None)` 都取不到数 | **环境所致** |

实测做法（不推断）：建临时工位 `.worktrees/_b3base` 指向 `b258fe3`（B1 之前）跑 0353
⇒ **215 绿 / 1 红**（唯一红就是 P12 那条）。再把本树 `.psl` 改名移开（`mv`，零删除）复跑
⇒ **215 绿 / 1 红**，与基线**逐条相同**。恢复 `.psl` 后回到 212/4。

⇒ 结论：那 3 条由「运行时目录 `.psl` 存在但链为空 ∧ 监理未值守」产生。
**这本身是一条判据脆弱性**：`TP-B2` 在「`.psl/audit` 不存在」时绿、在「存在但空」时红 ——
同一个事实（没有链）两种输出。它属 A 线的套件（不在 B 线文件清单里），**本步不修**，
列为交接项。

### 8.6 我在这步犯的错

**判据的口径没从设计意图派生。** C⑭ 第一版用带微秒的 `now()` 做区间边界，而产品按设计用
`timespec="seconds"` ⇒ `15:58:41.876` 被截断成 `15:58:41`，被判成「写了一个区间外的时间」。
这是**量具错**，不是产品错：区间必须按秒边界取。改完即绿。
（同族于「期望值从实现现状抄」的反面 —— 这次是从**我的想象**抄，而不是从冻结的形状抄。）

**同一件错，在同一页里犯了三次。** §8 表格第一稿写 `sidecar.py`「318 行」，`wc -l` 实测 422；
改成 422 之后，我又在下面写了探针「514 行」与第二次的「422 行」——实测是 591 与 431。
**第三次就发生在刚写下「一律脚本数」这句话的同一节里。**

处置不是再改一次数字，而是**把行数从文档里删掉**：它不是判据，写对了零收益、写错了会
让下一个读的人以为有人核过。留下来的只能是「16 正 ＋ 9 负控 ＋ 1 量具自检」这种
**由探针自己打印、抄都不会抄错**的数。

### 8.7 ★ 本步最要紧的发现：我把 §F8 的「键」读错了，合成值永远不暴露

A 线 15:5x 交出 `situation.py`（`469393f`，A4）后，我把 B 线工位并了上去，第一次拿
**真实生产者**去喂 `record()`：

```
facts.collect(_offline=True, armed=False)            → lamp=grey  cause=unarmed  badge=[]
facts.collect(_offline=True, armed=True, is_dev=True) → lamp=…     cause=…        badge=["dev"]
```

**`situation.badges()` 的 key 是 `dev` / `granary` / `disk`**（`SIT.BADGE_WORD` 的三个键），
而我第一版 `_check_badge()` 按**八成因键**校验 ⇒ 一喂就 `ValueError`。

§F8 原文只有一句：`"badge": [键…]`。**它没说是哪一族的键**——「成因键」是我的猜测。
如果不是 A4 恰好落地、我恰好拿真值喂了一次，这个缺陷会在这条链上一直躺着：

| 阶段 | 后果 |
|---|---|
| 接线那一刻 | `record()` 抛 `ValueError` |
| 每一拍 | tick 的 `except` 把它记进 `out["errors"]`，**但 tick 照跑** ⇒ 屏幕上"一切正常" |
| 30 天后 | sidecar 文件里**一行都没有** ⇒ M1–M3 全部无数据 ⇒ 观察期空转 |
| 谁会发现 | 没有人。三个指标"0 次红"与"从没采到"在报表上长得一样 |

这是「假绿族③ 输入边界≠规则边界」与「判据打模型层、缺陷在 handler 层」的混合：
**十五条合成值判据全绿，而真实生产者一接就炸。**

**修法（分层，不是加一个白名单）**：

| 字段 | 枚举权威在哪 | sidecar 怎么校 |
|---|---|---|
| `lamp` | `state_registry.LAMPS`（四值封闭） | **严格校** |
| `cause` | `state_registry.STATES` 的 key（八成因封闭） | **严格校** |
| `badge` | `situation.BADGE_WORD`（会随徽标种类增加而变） | **只校形状**（非空字符串数组） |

理由：在 sidecar 里写死一份徽标键枚举，就是给那张表造第二份真源——而那张表今晚就变过一次
（`dev` 是 `is_dev` 的产物，A 线新增）。

**新增两条判据**：`C⑯` 用真实生产者喂一次；`N⑨` 把校验退回按八成因 ⇒ `C⑯` 必须红。
`N⑨` 每次跑都复现这个缺陷，等于每条命都证明这把尺子有分辨力。

> 留给 X 步的一条：接线时**不要**把 `SIT.badges()` 的返回值直接塞进 `record()` 的
> `badge=`，要先取 `[b["key"] for b in badges]`。这一步取 key 的转换会**丢掉 text 与
> action**——而 `badges()` 的契约是「每枚必须带动作，否则不许当徽标」。sidecar 只存键，
> 所以这个丢失是有意的；但**不许**反过来用 sidecar 的 badge 字段去渲染徽标。

### 8.8 没做的（三条，都有依据）

1. **不接 `inbox_daemon.tick`**。依据三条：① 台账 B3「产出」只列 `sidecar.py`；
   ② `inbox_daemon.py` **不在** B 线文件清单（台账 §1.1 的五个文件）⇒ 改了就越界；
   ③ 接线需要 `lamp` / `cause` / `badge`，那是 A 线 `situation.py` 的产出，现在还不存在。
   接线的形状已经备好（下面这行），等 X 步：
   ```python
   import sidecar as SC
   SC.record(lamp=lamp, cause=cause, badge=[b["key"] for b in badges],
             info_unread_overdue=n, root=self.root)
   ```
2. **不进 `pyproject.toml` 的 `py-modules`**。`state_registry.py`（A0 建的）同样不在，说明
   这个决定 A 线已经做过一次：**先建模块，出包时统一登记**。而出包本轮不做（创始人：先不出包），
   且 `pyproject.toml` 是九处版本承载件之一，动它会牵动版本闸门。
   ⇒ **交接债（出包前必做）**：把 `state_registry.py` 与 `sidecar.py` 一起加进
   `pyproject.toml` 的 `py-modules` **和** `scripts/build_package.py` 的 root_mod 复制清单
   （两处必须逐字一致，PKG16-a 判据查这个）。
   顺带一条已知盲区：**STE100 文案扫描面派生自 `py-modules`** ⇒ 未登记的模块不文案尺子。
   本步已自查过 `sidecar.py` 的相对时间词与行长（把「本周」改成「某一周」），但没有跑完整尺子。
   ⇒ **§11.2 有更新：这条债的实际名单是四个模块，不是两个。**
3. **M4 / M5 不在本模块**。M4（红灯后用户动作率）要读 store 的 `set_state` 变迁，
   M5（拦截漏看数）要读 `ledger_rows().pending` —— 两者都是**量具侧**（施工方案 §3.4 ③
   把汇总与报告放在 `output/_p_red_budget.py`）。`sidecar.py` 只存 `info_unread_overdue` 这个数，
   **不算它**：算它需要一个「保持期」口径，那不在 §F8 里。

---

## §10 B2 · 通知三态与送达兜底 —— 完成

| 项 | 内容 |
|---|---|
| 步 | B2（任务卡：`inbox_notify.py` 三态判定 ＋ `AUDIT_SCHEMA` 登记 `delivery_unknown`，前置无） |
| 读什么 | 《编码前无猜测审核与接口冻结 v1.0》**§F7**（三态＋schema 草稿）；《状态机设计审计与补充件 v1.0》**§3.8 N12**（降级链与无头例外） |
| 提交 | `debd7b0`（产品＋schema）、`dd2761d`（manifest 重签） |
| 验收 | `output/_p_notice_three.py`：**正判据 19 绿 / 0 红；负控 10 绿 / 0 红；量具自检 2 绿** |
| 另两把尺子 | `tools/verify_event_types.py` 未登记 0；`ci/version_check.py` 9 处 0.54.0 PASS |

### 10.1 三态与六条分界

形状逐字照 §F7，**一个字段不多**：

| 态 | 行 | 落点 |
|---|---|---|
| `notice_sent` | `{ts, kind, channel}` | 进程内＋`<hub>/console/notice_log.jsonl`，**不进链** |
| `notice_seen` | `{ts, kind, how}`，`how ∈ open/ack` | 同上 |
| `delivery_unknown` | `{ts, kind, downgrade, minutes_overdue, noticed}` | **进链**，L1 |

「该不该落成 unknown」有六条分界，每一条都是它否掉的某个反面：

| 分界 | 落成什么 | 否掉的反面 |
|---|---|---|
| 降级成功 | `downgraded`，不写链 | 「成功也记一条」⇒ 账上全是假未知 |
| 无头（`channel="file"`） | `headless`，不写链，**且根本不调降级器** | 「没有通道」被当成「通道坏了」 |
| 已见过 | `seen`，不写链 | 最硬的证据被推断覆盖 |
| 时差为负 | `undecidable` | 负数被钳成 0 ⇒ 永远判 pending、永远不告警 |
| 没有降级执行器 | `undecidable` | 「不知道能不能降」被写成「降级失败」 |
| 当日链读不到 | `undecidable` | 取不到被当成「没记过」⇒ 重复写脏账 |

★ 「已见过」排在最前，不是随手写的顺序：先判 headless 再判 seen，就会把
「用户看过了的无头场景」报成 headless，把最好的证据丢掉。

**`unknown` 与 `undecidable` 是两个词，不许合并**：前者是「确知没送达」，后者是「判不了」。
把它们并成一个，屏幕上「报不达」与「体制看不见」就长得一样了——这正是仓里反复付学费的那条。

### 10.2 幂等：为什么要、代价是什么

daemon 每 10 分钟一拍，`settle()` 若不幂等，45 分钟那条会被连写 3–4 条 `delivery_unknown`。

去重口径＝**当日链上是否已有同 `kind` 的记录**（`chain_scan` 返回三值：
`True` 已记过／`False` 确知没记过／`None` 读不到）。不新开状态文件：链本身就是唯一事实层。

**代价（写在这里，免得以后被当成 bug）**：同日同 `kind` 的第二次独立失败**不会单独留痕**。
F7 冻的字段里没有 `sent_ts`，所以去重键只能是 `kind` + 当日；要更精确就得加字段，
而加字段是改冻结形状 —— 本步不改。

### 10.3 「多个入口」的活标本：schema 与 server.json

B2 要改 `docs/AUDIT_SCHEMA.md` 的抬头（v1.21 → v1.22）。改完 `ci/version_check.py` 的
**判据 6** 立刻会红 —— 它要求 `server.json` 的 `stability.schema` 与 schema 抬头一致。
两处都得改，只改一处就是「对外清单声明一个旧模式版本」。

同一件事还有第三个入口：`ci/version_check.py` 的**承载件正则**抓的是 `随 v(\d+\.\d+\.\d+)`，
也就是**产品版本**，不是模式版本 ⇒ 抬头里的 `随 v0.54.0` 一个字都不能动。

⇒ 一处语义、三个入口。本步三个都改了，并在提交信息里点名。

### 10.4 F-10 现场复现（不是引用历史，是当场撞见）

写完 `_write_unknown` 但还没改 schema 时，`verify_event_types.py` 当场给出：

```
代码中实际的 type 常量 : 48
AUDIT_SCHEMA.md §4 登记: 51
  ✗ 代码有、schema 未登记（1）:  · delivery_unknown
```

与 0.40.0（`exam_reminder`）／0.51.2（`credits_low`）两次同型。登记后：
代码 48／schema 53／未登记 0；stale 5 条（`credits_low`、`gap_fixed`、三个 `logo_*`）。

`gap_fixed` 是 §F7 要求「与 `delivery_unknown` 同批登」的（U4 的「我修好了」按钮），
但它**当前没有生产者** ⇒ 会一直出现在 stale 里。这是与 `credits_low` 同型的正常状态，
schema 里已用同样的措辞写明「登记的是类型与语义，不是链上已有记录」。

### 10.5 回归与红项分类（每条都有实测，不推断）

| 套件 | 改动后 | 原始树（stash 掉本次改动） | 分类 |
|---|---|---|---|
| 0514 | 214 / 0 / 0 | — | 无变化 |
| 0360 | 63 / 0 | — | 无变化 |
| 0481 | 12 / 0 | — | 无变化 |
| 0400 | 33 / 0 | — | 无变化 |
| 0431 | 17 / 0 | — | 全绿 |
| **0372** | **26 绿 / 2 红** | **26 绿 / 2 红** | **改动前就红**（A4 引入，见 §11.1） |
| **0353** | **212 绿 / 4 红** | **212 绿 / 4 红** | **改动前就红**（环境＋P12，见 §8.5） |

全量闸门 `ci/delivery_gate.py`（我绕过钩子后补跑的一次）：**34 套 → 31 绿 / 3 红**
（0353、0372、regression）。regression 的红是 D-20／D-22／D-23，见 §11.2。

### 10.6 这条链还差最后一节：`settle()` 没有生产调用点

本步只做**判定**。降级动作是「托盘角标＋首屏横幅」，它们分别在 `inbox_tray` 与页面渲染里，
属 **X 步**。给 X 的接线形状（三行）：

```python
# daemon tick 里，对每条已通知过的 kind：
res = NT.settle(kind, now=self.clock(), root=self.root,
                downgrade=lambda k: self._downgrade_to_tray_and_banner(k),
                audit_dir=self.audit_dir)
if res["state"] == "unknown" and res["chain"] is None:
    out["errors"].append("notify.settle: %s" % res["why"])   # 没落盘要出声
```

★ **`downgrade` 必须由调用方给**：`settle(downgrade=None)` 返回 `undecidable`，不是 `unknown`。
这是故意的——本模块不认识托盘，替它猜一个「降级失败了」就是编。

### 10.7 已知边界三条（不假装已闭合）

1. **`toast()` 发送失败时不记 `sent`** ⇒ `delivery_unknown` 只覆盖「发出但没人看到」，
   **不覆盖「压根没发出」**。后者由后端的 `last_error` 与 daemon 的 `out["notified"].ok` 承担。
   F7 的三态里没有「发送失败」这一态，本步**不擅自加第四态**。
2. **配置关掉通知时也走不到 unknown**：`should_touch()` 早退 ⇒ 没发 ⇒ 无 sent 行 ⇒ 无从判。
   这是「按配置不该发」，不是「报了没人看」，但送达链在这条路上是失明的。
3. **幂等的代价**见 §10.2（同日同 kind 第二次失败不单独留痕）。

---

## §11 跨线纠错与交接债

### 11.1 0372 的两条红：A4 的 `situation.py:101` 一词二义

```
❌ S08 两个真源各一份 … situation.py:101 又写了一份态名（dev → '研发中'）
❌ N-S08 负控 …        现行源码里仍有第二份声明：[同上]
```

判据在 `ci/inbox_guards_0372.py`：它按正则 `"(R0|L2|L1|Ls|L0|dev)"\s*:\s*"<含中文>"` 找
「态名声明」，值落在态名词汇表（含 `研发中`）里就判红。

```
situation.py:101   BADGE_WORD = {"dev": "研发中", "granary": "缺粮", "disk": "磁盘"}
```

`dev` 在 `state_registry` 里是**模式的旧键**（`legacy_of` 让 `drill` 承它的语义），
而这里它是**徽标键**。同一个词在两个语义上出现 ⇒ S08 判「一词二义」。

这与 B3 §8.7 是同一族问题（徽标键不是成因键），但方向相反：B3 那次是我把徽标键当成因键，
这次是 A4 把模式键当徽标键。**两边都说明「徽标键」这一族还没有名字。**

⇒ **归 A 线**（`situation.py` 不在 B 线文件清单）。两条修法都要 A 线裁定：
① 徽标键改名（不叫 `dev`）；② 或徽标词改说法（不叫「研发中」）。
**本步不修，也不动 `ci/inbox_guards_0372.py`**（共享文件）。

### 11.2 D-20 的真实名单是四个模块，不是两个

全量闸门的 regression 套件报：

```
[FAIL] D-20 包组成双向守卫（干净 wheel 不漏模块）
  ② 真树上有包组成问题：包根模块被 import、却没在 pyproject 的 py-modules 里声明：
     ['facts', 'sidecar', 'situation', 'state_registry']
```

§8.8 第 2 条当时只登记了两个（`state_registry`、`sidecar`）。现在 A4 又加了两个
（`facts`、`situation`）⇒ **这条债是双线共同的，名单还会涨**。

它也是「修在一个入口，而这件事有多个入口」的第三例：`py-modules` 与
`scripts/build_package.py` 的 root_mod 复制清单必须**逐字一致**（PKG16-a 查这个），
只改一处等于换个地方红。

⇒ **本步不改**：`pyproject.toml`／`scripts/build_package.py` 都是共享文件，且名单里有一半是
A 线的模块。列为**双线共同交接债**，出包前由先做完的一方（或创始人裁定的一方）一次加齐。

### 11.3 manifest 重签：两条漂移，一条是 B1 留的

`_tools_034/_resign_manifest.py --dry --adopt-dev` 报 133 条里需重签 **2** 条：

| 文件 | 是谁留下的 |
|---|---|
| `inbox_notify.py` | 本次 B2 |
| `tools/mk_icons.py` | **B1（`ed527d6`）** —— 那次同样绕过钩子，当时没重签 |

补登记 0 条、结构化对齐 0 条；未动 `name`／`version`／`built_at`。

★ 这条也印证了一个容易误判的事实：**全量闸门 34 套不查 manifest 的 per-file hash**，
只有 `--hook`（看暂存区）才查。所以绕过的漂移会一路积下，直到下一次不绕过的提交才叫。
本次两条正好一新一旧。

---

## §12 待粘进共享台账 §4 的三行

```
| B | B1 | `ed527d6` | `python output/_p_shape_parity.py` | 8 正绿／7 负控真红／1 量具绿；回归 0360 63/0、0514 214/0、0372 28/0、0481 12/0 | **B3**（最独立，前置无）或 B2；B4 前置=B1 已绿 |
| B | B3 | `a54da38` | `python output/_p_sidecar_twice.py` | 16 正绿／9 负控真红／1 量具绿；回归 0514 214/0、0400 33/0、0360 63/0、0372 28/0、0481 12/0；0353 215/1（那 1 红改动前就红） | **B2** |
| B | B2 | `debd7b0` | `python output/_p_notice_three.py` + `python tools/verify_event_types.py` | 19 正绿／10 负控真红／2 量具绿；未登记 0；version_check 9 处 PASS；回归 0514 214/0/0、0360 63/0、0481 12/0、0400 33/0、0431 17/0；0372 26/2 与 0353 212/4 均实测「改动前就红」（stash 复跑同值） | **B4**（前置 B1 已绿，需人眼复看 T1 测试页）或 **X**（前置 A4＋B1 都绿，B2 的 `settle()` 等它接线） |
```

> 下一入口说明：
> - **B4** 读任务卡 B4，前置 B1 已绿。改 at-risk 几何会连带 5 个 `-unknown.ico`，
>   必须同批重生成＋人眼看 T1 测试页（`docs/Antinel·T1 16px 人眼测试页 v1.0.html`）。
> - **X** 读任务卡 X（六个渲染点），前置 A4＋B1，B2 的 `settle()` 也要在这里接线（§10.6）。
>   X 有三条已知坑：`M.STATE_VAR[st]` 两处裸下标（`inbox_bubble.py:307`／`inbox_server.py:1047`）、
>   `state_label()` 与 `_icon_state()` 对未知键**静默落「注意」**、以及 §11.1 的 `dev` 一词二义。
> - **A 线**：§11.1（`situation.py:101`）与 §11.2（D-20 名单）是它们要处理的。
