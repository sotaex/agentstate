<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel·侧门与沉默修复设计 v1.0（2026-10-22）

> **上游**：`docs/Antinel·独立复核报告 v1.0（2026-10-22）.md` 的 F1–F10。
> **本件写于编码之前**：先把"改成什么、凭什么算改好了、负控换哪一行"钉住，再动代码。
> **范围**：10 条全修。**F1/F2 改运行时行为 ⇒ 升版 0.55.0**；其余不单独升版。

---

## §0 两条总纲（这批所有修法的共同形状）

1. **权威放在最下层**。F1 的教训不是"漏了一个入口"，是**门禁装在了 HTTP 层**——
   而模型层 `_TRANSITIONS` 睁着眼允许 `done/ignored → read`。
   ⇒ 修法是让 `set_state()` 自己知道"这次是知情，还是重开"，HTTP 层只是**翻译意图**。
   这样入口再长，语义也不会被绕过。
2. **空串/静默只允许表示一种情况**。F2 的教训是 `except: return ""` 把
   「没拿到读数」和「没有竞争」压成了同一个输出。⇒ 凡是"取不到"必须**出声**，
   静默只能留给"查到了，是 0"。

---

## §1 F1：`read` 这个目标态不再等于"重开"

### 1.1 现在的机制（病根）

```
inbox_model.py:49  _TRANSITIONS = {..., "done": {"read"}, "ignored": {"read"}}
inbox_store.py:441  else（read/unread）:  ent["gap_state"] = M.GAP_OPEN
inbox_store.py:431  else:                 ent.pop("closed_at", None)
```

⇒ **谁写 `read`，谁就把缺口重开**。三个活调用点：

| 调用点 | 意图 | 现状 |
|---|---|---|
| `inbox_server.py:4266`（`/action` 正门） | 自动已读 / 用户重开 | 已由 `_auto_read_allowed` 分开 |
| `inbox_server.py:4127`（`remediation_ack`） | 只是记录"我不处理" | **无门禁 ⇒ 侧门** |
| `inbox_server.py:1831`（「重开」按钮） | 用户重开 | 无门禁（本来就该重开） |

### 1.2 改法

`inbox_store.set_state(..., intent="read")`，`intent ∈ {"read", "reopen"}`，默认 `"read"`（安全侧）。

| 现状 → 目标 | `intent="read"`（知情） | `intent="reopen"`（重开） |
|---|---|---|
| `unread → read` | state=read，`read_at` 写入；`gap_state` **保持**（本来就是 open） | 同左 |
| `ignored → read` | state=read；**`gap_state` 保持 acked、`closed_at` 保持** | `gap_state=open`、`closed_at` 清空 |
| `done → read` | state=read；**`gap_state` 保持 closed、`closed_at` 保持** | 同上 |

+ `done` / `ignored` 两条迁移不变（它们各自写死 gap_state）。

**HTTP 层只做一件事**：`intent = "read" if _auto else "reopen"`。
`remediation_ack` 不传 ⇒ 默认 `"read"` ⇒ **侧门自动关闭**，不需要在它那里再加一道门
（但要留一句注释，说明它依赖的是模型层默认）。

### 1.3 连带影响（必须先查旧的）

- **P29**（`0353:5371`）：直接 `set_state(iid,"read",...)` 期望 `gap_state==open`。
  它测的是"重开"，⇒ 改成 `intent="reopen"`。**这不是为了让判据变绿，是因为它测的就是重开。**
- `ci/inbox_guards.py:307`：夹具用它造一个 `read` 态（从 `unread` 起），默认语义下行为不变。
- `inbox_cli.py:135`：`dst` 来自命令行，`read` 是"标为已读"⇒ 默认 `"read"` 正确。
  但 CLI 有没有"重开"子命令？**要查**；若有，须显式 `intent="reopen"`。

### 1.4 判据 P35 ＋ 负控

打**模型层**（这才是权威层），不是打 HTTP：

- ① `ignored` 起，`set_state(...,"read")` ⇒ state=read、gap 仍 acked、`closed_at` 仍在（三条一起断言）
- ② `done` 起，同上
- ③ `ignored` 起，`intent="reopen"` ⇒ gap=open、`closed_at` 清空
- ④ `unread` 起，`intent="read"` ⇒ read，gap 仍 open（防止 ① 做成"什么都不许改"）
- ⑤ **打 HTTP 的侧门**：`POST /action op=remediation_ack` 到一条 `ignored` 记录 ⇒ gap 仍 acked

负控：把 `inbox_store` 里 `intent` 判断换成恒 `reopen`（等价旧行为）⇒ 必红。
**换的是同一份实现**（`set_state` 本身），不复制 handler。

---

## §2 F2：取不到读数必须出声

`inbox_server._lock_line()` 现在：

```python
try:
    import audit_chain as AC; import host_shield as _hs
    pr = AC.lock_pressure(path=AC.lock_events_path(d))
except Exception:
    return ""          # ← 「没拿到」与「没竞争」逐字相同
```

改法：把 try 拆成两段（取路径 / 取读数），三种失败各给一句话，且**都不返回空串**：

| 情况 | 输出 |
|---|---|
| 导入或路径算不出来 | 「记录连写的竞争读数取不到（取数失败）。这一格今天没有读数。」 |
| `lock_pressure` 抛异常 | 「……（读取异常：`<类型>`）。这一格今天没有读数。」 |
| 返回里没有 `checked` 键 | 「……（返回格式不认识，缺 checked）。这一格今天没有读数。」 |

文案纪律：避开双重否定（STE100 D8）——写"没有读数"，不写"不等于没有"；
主语不出现"我们"。

**判据 P36 ＋ 负控**：三种坏法各注入一次，页面必须各自出现一句话、且**不许是空串**。
负控：把三处 `return` 改回 `return ""` ⇒ 必红。

---

## §3 F3：自己造的临时目录自己收

### 3.1 病根是登记了不收

`ci/inbox_guards.py:57` 有 `_SCRATCH = []`，`new_hub()` 会 `append`，**但从头到尾没有任何一处清理**。
⇒ `D:/_antmp` 顶层 70,312 项、冷扫 64.8 秒。

### 3.2 改法（一处收口，所有套件受益）

`ci/inbox_guards.py` 增加：

```python
def tmpdir(prefix):            # 唯一建临时目录的入口
    d = tempfile.mkdtemp(prefix=prefix)
    _SCRATCH.append(d)
    return d

@atexit.register
def _sweep_scratch():          # 进程退出时收自己的
    if os.environ.get("ANTINEL_KEEP_TMP") == "1":
        return
    for d in _SCRATCH: shutil.rmtree(d, ignore_errors=True)
```

- `new_hub()` 改走 `tmpdir()`。
- 四个大户（`g0490` 33748 / `g0514` 11674 / `g0470` 1180 / `g0400` 434）里的
  `tempfile.mkdtemp(prefix="gXXXX-")` 改走 `G.tmpdir("gXXXX-")`（若该套件已 import G）。
- `0353` 里 14 处 `mkdtemp` 同样改走 `tmpdir()`。
- 保留 `ANTINEL_KEEP_TMP=1` 逃生门（排查时留现场）。

**为什么用 `atexit` 而不是逐条 `finally`**：14 + N 处逐个改，漏一处就是一条新的泄漏，
而且"漏了"没人会发现；`atexit` 是**进程级兜底**，漏不掉。

### 3.3 历史垃圾：一次性清扫（留账）

`scripts/tmp_sweep.py`：只删**同时满足**三条的目录 ——
① 名字命中本仓夹具前缀（`antinel-*`／`g04*`／`g05*`／`w07hub*`／`rg*`／`jdg*`）；
② 目录内容总量 < 64 KB；③ 修改时间早于 2 小时（不碰正在跑的）。
先写清单 `output/tmp_sweep_<ts>.txt`（名字 + mtime + 字节数），再删，最后报
"删了多少 / 剩多少 / 冷扫耗时从多少到多少"。**零删除纪律在这里体现为"删之前留清单"。**

### 3.4 判据 P37 ＋ 负控

静态＋动态两条腿：

- 静态：`ci/*.py` 里每一处 `tempfile.mkdtemp(` 必须出现在 `tmpdir(`／`_SCRATCH` 的上下文里
  （用**文件名 + 行号**判定，不绑文案）；
- 动态：跑一次 `G.new_hub()` + `G._sweep_scratch()`，断言目录真的没了。

负控：往一个测试夹具里注入一处裸 `tempfile.mkdtemp(prefix="...")`（内存字符串，不落盘）⇒ 必红。

---

## §4 其余七条

| 编号 | 改法 | 判据影响 |
|---|---|---|
| **F4** | `egress.lost_pending()` 改走 `_merge_lost(dn, _LOST["n"])` | P25b 的负控自动覆盖到（换 `_merge_lost` 两条路径同时坏） |
| **F5a** | `egress` 新增常量 `SPACE_UNREADABLE` 与 `SPACE_READABLE_HEAD`，`render()` 引用它们 | P26b 改断言这两个常量（不再出现「读不到」「0 个日文件」字面） |
| **F5b** | `inbox_server._unrepaired_line()` 的 `<div>` 加 `data-ack-days="N"` | P31b 改断言该属性（不再断言「N 天」字面） |
| **F6** | `n_env_existing_blocks_intact` 跑两遍：一律放行 + 一律拦住，两者都必须红 | 无新判据 |
| **F7** | `inbox_model.unrepaired_count()` docstring 写明 `oldest_record_days` 仅供判据 | 无 |
| **F8** | `egress._PROBE_EVERY=32` → `PROBE_SEC=60.0`，按**时间**探测（依据：心跳 600s 的 1/10） | `_eg_env` 的重置改 `_ASK["t"]=0.0`；P25b 不受影响 |
| **F9** | `_item_html` 按 `gap_state` 分支给两个标签：`ignored`→「重新管起来」、`done`→「重新打开」 | **新 P38**：两条记录的按钮文字必须不同；负控：把两者改成同一个字面 ⇒ 必红 |
| **F10** | 矩阵 v1.1 的 §8 补一节「0.55.0 批」（格 → 判据 → 提交）；**不是补一列** —— 原表格式在，只是停在本批之前 | 无 |

**F8 为什么改成时间**：次数阈值要乘上写频率才有意义，而写频率随连接数变化（0 条连接时
一天也不写一次）⇒ 按次数探测在安静机器上可能永远不触发。按秒探测与写频率无关，
且"遗留丢失最多藏 60 秒"本身是一句可以写进文档的承诺。

---

## §5 判据与负控成对表

| ID | 正控 | 负控换哪一行 | 打在生产哪个入口 |
|---|---|---|---|
| **P35** | 已读不改缺口态／重开才改 | `inbox_store` 的 `intent` 分支 → 恒 reopen | `set_state`（权威层）＋ `/action`（侧门） |
| **P36** | 取不到读数要出声（3 种坏法） | `_lock_line` 三处 `return` → `return ""` | `_lock_line` |
| **P37** | 临时目录必须登记并清理 | 注入一处裸 `mkdtemp` | `G.tmpdir` / `G._sweep_scratch` |
| **P38** | 两种意图不许共用一个标签 | 两个标签改成同一个字面 | `_item_html` |
| P26b（改） | 读不到时用「读不到」那一支 | 删 `readable` 分支（原有负控保留） | `render` ＋ 常量 |
| P31b（改） | `data-ack-days` 等于 ack 基准 | 拿掉 `oldest_ack_days`（原有） | `_unrepaired_line` |
| P30c（改） | 该拦 6 ＋ 该放 3 | **两个方向都要红** | `readonly_command_context` |
| P29（改） | 重开把缺口打回 open | —— | `set_state(intent="reopen")` |

**负控纪律**（照抄本仓既有铁律）：换的是**同一份实现**，不复制 handler；
换腿不删断言；夹具形状＝生产形状。

---

## §6 九维逐条怎么过

| 维 | 这一批的落点 |
|---|---|
| 1 入口唯一 | `read` 的语义只在 `set_state` 一处决定；HTTP 只翻译意图 |
| 2 反向对照撤销即红 | 每条判据都有负控，且负控改的是权威层那一行（P35 的不是 handler） |
| 3 行为判据 | P35 断言 state/gap/closed_at 三元组，不断言函数返回值 |
| 4 既有保护连带对照 | **P29 必须同步改**（语义变更点）；P34 必须仍绿（自动已读仍不动终态） |
| 5 保护自报活跃 | P36 就是这个维度本身：取不到必须出声 |
| 6 运行态确认 | 改完杀进程等重拉，`url.json.code_version` 必须 0.55.0，五页回读 |
| 7 量具先自检 | P37 量的是"我们自己造的垃圾"；P36 量的是"量具坏了会不会说" |
| 8 数据版本迁移 | `intent` 默认值保证旧调用点行为不变；`gap_state` 存量不动 |
| 9 文档与代码同锚 | 矩阵 §8 补节；本件与复审报告互相引用；版本九处 |

**品质五条**：量具坏了被当产品坏（P36/P37）／判据自身时变（P37 用文件名+行号，不用字面）／
机制层不守自己（P36 正是机制层守自己）／交接边界债（F7 标注、F10 交叉引用）／
登记与事实分家（矩阵计数仍由脚本数）。

---

## §7 版本与发布登记

- 九处承载件：**0.54.0 → 0.55.0**（runtime behavior change ⇒ minor）。
- `psl/workspace_facts.json`：`release.version` 与 `pypi.target_version` 同步 0.55.0，
  `artifacts` 继续留空并注明"未构建"；`published_version` 不动。
- `psl/manifest.json`：改完统一重签（`_resign_manifest.py --adopt-dev`），**单独一个提交**。

---

## §8 施工顺序（脚本先后本身就是依赖）

1. `inbox_store.set_state(intent)` → `inbox_server` 三处翻译 → `inbox_cli` 查有无重开子命令
2. `inbox_server._lock_line` 三段化
3. `inbox_server._item_html` 两标签 ＋ `_unrepaired_line` 加 `data-ack-days`
4. `egress`：`_merge_lost` 接线、空间常量、`PROBE_SEC`
5. `ci/inbox_guards.py`：`tmpdir` ＋ `atexit`；各套件换入口
6. 判据：P35/P36/P37/P38 新增；P26b/P29/P30c/P31b 改
7. 跑 0353 → 0490 → 0514 → 0400 → 其余 → 全量闸门
8. 活体回读（杀进程等重拉，五页）
9. 版本九处 ＋ `workspace_facts` ＋ 重签 manifest ＋ 三份文档
10. `scripts/tmp_sweep.py` 清历史（留清单）

---

## §9 不做什么

- **不拆 `alert_state`／`gap_state`**（F1 的治本方案）：那会动状态词表，
  而判据字面锚定比约 5.5:1 ⇒ 属于"先换锚、再改词"的独立工程。
  本批用 `intent` 把**语义**钉在模型层，等价达到"已读永不改缺口"；
  拆表留作下一批，届时 `intent` 可以直接退化成 `alert_state` 的赋值。
- **不动 40 格的 ✔/◐ 计数**：本批没有新增载体格，只补 §8 对照。
- **不跑全量 34 套两遍**：只在改完后跑一次全量，避免"长任务并发"。
