<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel · 执行记录 v1.0 · E-R 规则级正控／负控

> 对应测试计划 v1.7 §3.2，维度 P（拦/放决策）。执行时间 2026-10-24 10:39–10:42。
> 被测对象：仓内真源 `hooks/pre_tool_use.py` + `rules/default.json`（**不是** site-packages 里的包）。
> 入口：stdin JSON，与宿主调用完全同一入口。
> 证据：`output/tests/0.55.3/R-rules-v2-20261024-1041.json`（57 个用例逐条原始输出）
> 执行器：`output/_e_r_rules2.py`

---

## 1. 结果总表

| 项 | 值 | 口径 |
|---|---|---|
| 规则总数 | 37 | `rules/default.json` |
| 本轮探明 | **21** | 有正控样本的规则（其余 16 条未造样本） |
| **死规则** | **0** | 每条探明规则都至少产生一种可见动作 |
| 正控用例 | 34 | |
| 正控通过 | **33** | 命中 = 拦截 或 落审计 |
| 正控未通过 | **1** | AN-025 的 shell 形态（已知缺口，见 §3） |
| 负控用例 | 23 | |
| 负控干净 | 17 | |
| **假阳性** | **6** | 见 §2 |
| 真拦（`decision=block`） | 20 | critical 级 |
| 只记账（`decision=alert`） | 16 | 全部 warning 级，**符合规则自己的 note** |
| 单次判定耗时 | 中位 1101ms / 最大 3185ms | 含 Python 冷启动，不计预算结论 |

**一句话：37 条规则里没有一条是"写了但从不生效"的死规则。问题不在"拦不住"，在"拦错了对象"。**

---

## 2. 三条真缺陷

### 2.1 AN-005 无路径限定，名字含 cookies 就拦（critical · 会真拦住用户）

规则定义只有四个 pattern，没有排除表、没有浏览器目录限定：

```
file_patterns: ["Cookies", "Login\\s+Data", "Local\\s+Storage", "Web\\s+Data"]
exclude_patterns: []
```

实测三条本不该中的普通路径，全部 `decision=block`：

| 投喂路径 | 结果 | `match_snippet` |
|---|---|---|
| `./f/21-cookies.txt` | **block** | `cookies` |
| `./f/22-my_cookies.json` | **block** | `cookies` |
| `./f/23-Cookies.test.js` | **block** | `Cookies` |

提示语是「读取浏览器数据（Cookie、密码、会话）」——对一个测试夹具文件说这句话，是**错误指控**。

企业的日常形态：爬虫项目、前端 E2E 用例、接口调试脚本，都会有自己的 cookies 文件。当前行为是**每一次读都被拦，且理由不实**。

修法候选（**未动手，属产品决策**）：
- 甲：要求路径含浏览器配置目录（`/Chrome/User Data/`、`/Firefox/Profiles/`、`Safari/`、`Edge/User Data/`）；
- 乙：文件名精确等于（而非包含）`Cookies` / `Login Data`；
- 丙：加 `exclude_patterns`（`\.txt$`、`\.test\.`、`cookies\.json$`）——最省事，但仍是"按名字排除"，换个名字又误报。

### 2.2 AN-032/AN-033/AN-034/AN-035 的内容模式从来不执行（warning · 语义错）

`AN-033/AN-034/AN-035` 都是 `type: file_content`，并且**同时**声明了 `file_patterns` 与 `content_patterns`。
`hooks/pre_tool_use.py:2945` 的 `_basic_hit()` 顺序是：

```
1) command_patterns → 命中即 return
2) file_patterns    → 命中即 return      ← MCP 三兄弟在这里就返回了
3) content_patterns → 永不进入
```

实测：写一个**完全干净**的 `.mcp.json`

```json
{"servers":{"a":{"command":"node","env":{"MODE":"dev"}}}}
```

一次写入产生 **4 条告警**，四条记录的 `match_kind` 全是 `path`、`match_snippet` 全是 `/.mcp.json`：

| 规则 | 名字承诺的事 | 实际判定依据 |
|---|---|---|
| AN-032 | 配置被写入或修改 | 路径 —— **正确** |
| AN-033 | 工具描述里有提示注入模式 | 路径 —— **错** |
| AN-034 | 引用远程服务器（url / mcp-remote） | 路径 —— **错** |
| AN-035 | env 块里有明文密钥 | 路径 —— **错** |

危害按严重度排：

1. **AN-035 会对用户说"env 块中存在明文密钥"，而文件里没有密钥**。这是产品主动说了一句不实的话。
2. 噪声比 4:1。编辑一次 mcp.json 得四条告警，用户很快学会无视全部 MCP 告警——**告警疲劳是安全产品最贵的失败**。
3. 真正的投毒（AN-033 该管的那件事）淹没在三条假警报里。

`channel_mismatch` 实测抓到的正是这两条：`AN-033 → 只靠 path`、`AN-034 → 只靠 path`。
（AN-035 的正控因为内容里确实有 `sk-` 串，`match_kind` 是 `content,path`，所以没进这条清单——
但它的**负控**同样只靠 path 就报了，问题一样成立。）

修法候选（**未动手**）：`file_content` 类型、且同时声明两类 pattern 的规则，`file_patterns` 只应作**门**（决定扫不扫），不能作**键**（决定中不中）。即第 2 段对 `file_content` 类型改成"路径匹配后继续走 content"，而不是 return。

### 2.3 AN-025 只认 Python 形态（critical · 已知缺口，本轮复证）

| 形态 | 结果 | 说明 |
|---|---|---|
| `python -c "import base64;exec(base64.b64decode(...))"` | **block** | `match_snippet = exec(base64.b64decode(` |
| `echo cHJpbnQoMSk= \| base64 -d \| sh` | 未命中 | 真实攻击里更常见的那一种 |

上一轮已登记，本轮从"没命中"升级为"**规则的 pattern 只写了解码函数调用，没写管道**"，修法边界更清楚了。

---

## 3. 副产：锁的静默降级链（比上面三条更值得看）

第一版执行器把 49 个用例跑了 **22 分 25 秒**；换成可删目录后同样规模的 57 个用例只要 **72.5 秒**。
差 18 倍。追下去发现不是性能问题，是一条完整的静默降级链。

### 3.1 现场读数（`proj/.psl/audit/lock_events.jsonl`）

| 读数 | 值 |
|---|---|
| `acq_timeout` | **82 次** |
| `steal`（死锁回收） | **0 次** |
| 等待中位 / 最大 | **6596ms / 14432ms** |
| 涉及进程 | 31 个不同 pid，全部撞上 |
| 锁文件里的持锁 pid | 1292 —— **已退出**（`Get-Process` 查无此进程，且文件可独占打开 ⇒ 无句柄占用） |

代码注释写的是 `~1.6s budget`（`audit_chain.py:207`），实测 **6.6s 起**。

### 3.2 链条

```
宿主删除守卫拒绝删除（实测 safe-delete: FAIL_CLOSED, reason=trash-failed）
   → release_lock 的 os.remove(lock) 失败（异常被正确吞掉，0.34.1 已修）
   → 锁文件永久残留
   → 下一个钩子进程 acquire 必失败 → 等满预算 → 落 sidecar
   → 主链当天只有第一条 hook_alive，其余全进 sidecar
```

### 3.3 三个与沙箱无关的产品侧问题

**（a）死锁回收失败零留痕。** `audit_chain.py:222` 的 `_note_lock(lock, "steal", ...)` 写在
`os.remove(lock)` **之后**。删除一旦失败（企业 EDR 拦删除极常见），异常被 `except Exception: pass` 吞掉，
`steal` 这条读数永远不会出现。用户看得到 `acq_timeout`，看不到"我想回收但收不回来"。

**（b）释放失败只有默认关闭的遥测里有。** `release_lock` 用 `tlog("remove_err")`，
而 `tlog` 受 `ANTINEL_LOCK_TELEMETRY=1` 门控（`audit_chain.py:41`），默认关闭，且只写 `audit/telemetry/`。
而同一件事在 `acquire_lock` 里用的是 `_note_lock`（不受开关控制、写 `lock_events.jsonl`）。
⇒ **同一个事实两个写入点，一个默认可见、一个默认不可见**——正是本仓第一顽症。

**（c）等待可超过宿主超时。** 实测最大 **14432ms**，而 zcode 的宿主超时是 **10s**，
超时的语义是 **allow（A-08）**。⇒ 锁争用严重时，守卫会因为"自己太慢"而放行。

### 3.4 结论

沙箱删不掉锁是**本机特例**，不报为企业缺陷。但据此暴露的三件事——
**回收失败无痕 / 释放失败不可见 / 等待可越过超时**——与环境无关，在装了 EDR 的企业机器上同样成立。
已登记待裁决，未动手。

---

## 4. 本轮我自己的四个测量错误（按发生顺序）

| # | 错误 | 后果 | 改法 |
|---|---|---|---|
| 1 | 照**旧文档里规则 ID 的历史含义**造样本 | 6 条规则被判"死了"，实际是 AN-011 现在指"Shell 配置改写"、AN-007 指"Python 联网"、AN-004 指"钱包/keystore"、AN-017 指"编码载荷"、AN-018 指"Skill 名不符"、AN-013 指"提权" | 样本按规则 `name`（对外承诺）造，不按 ID 猜 |
| 2 | 只看"ID 出现"就算正控通过 | AN-033 的正控"通过"了，但 `match_kind=path` —— 它靠路径中的，内容模式从未执行 ⇒ **假绿** | 正控必须记录命中通道；内容类规则的通道必须是 content |
| 3 | `audit_lines(...)[before:]` 切片取记录 | 读取面横跨主链+sidecar+中枢、walk 顺序不定 ⇒ 串到别的用例，`.env.example` 被误判成"误记账" | 按 `session` 精确过滤 |
| 4 | 把 `exclude_patterns_allow` 当命中 | 同上，把"正确放行"读成"缺陷" | 释放类记录（`exclude_patterns_allow` / `whitelist_allow`）不计命中 |

第 1 条与 memory 里「夹具禁写死旧文案」同源，第 2 条是新形态，已按"假绿第 11 族"记入。

---

## 5. 没做的事（明确留白）

- **37 条里还有 16 条没有任何正控样本**（AN-006/AN-008、AN-009/AN-010/AN-012/AN-020/AN-023/AN-024/AN-030、AN-014/AN-015/AN-016（原文此处另列 `CTX-06`，该号无对应规则，属已知编号洞）、AN-021、AN-032 等）。本轮不假装覆盖。
- **三条缺陷一条都没改代码**。2.1 与 2.2 都改的是对外可见行为，属产品决策。
- 修完之后要重跑本执行器（`_e_r_rules2.py`），负控应从 17/23 升到 23/23。

---

## 6. 复现

```bash
PYTHONPATH= TMP=D:/_antmp TEMP=D:/_antmp TMPDIR=D:/_antmp \
  "<managed-python>" -E -X utf8 output/_e_r_rules2.py
```

跑法要点（踩过才知道）：
- 临时项目必须建在**可删除**的目录（系统 TEMP），否则锁回收失败，耗时放大 18 倍（§3）；
- 密钥／删除命令等字面量在**脚本里运行时拼接**，否则本仓自己的 AN-021 / AN-009 会拦住脚本写入；
- 每个用例一条独立文件路径，禁止跨用例复用（MCP 三条的假阳性最早就是这么伪造出来的）。
