<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# AgentState (by Antinel) — AI Agent Audit Chain

> 展示名：**AgentState**｜厂牌／署名：**by Antinel**｜包名与技能标识符：`antinel` / `antinel-security`（**不动**）。
> 与 `server.json` 的 `title` 逐字一致——这个名字不是新起的，是把已经有的事实对齐到其余文案。

**让每一个 AI 编程工具的用户，在 30 秒内知道自己的 AI 编程环境安不安全——并且持续监控、持续安心。**

One command. 37 rules. 4 gates. Local-only, zero network, standard library only.

```
pip install antinel
```

> **包名是 `antinel`**（`antinel-security` 是技能名，pip 上装不到）。零依赖、纯标准库、运行时不联网。

**如果你是 Agent**：装完跑一条 `antinel agent --json`，就能拿到「钩子装没装 / 这是什么宿主 / 下一步敲什么 / 退出码契约」——不用读这份 README，也不用猜。随包操作手册：`antinel skill`。

## 别信我们，自己验 / Don't trust us - verify (30 秒)

```bash
python -m scripts.run_harness     # 复跑全部断言，得到你自己的 verdict（写入 psl/judgment.json）
python -m tools.antinel_verify    # 校验随包判定是否已失效（digest 比对，推导 current/superseded）
python -m tools.antinel_verify --manifest   # 校验全部随包文件（以 psl/manifest.json 为准）
python -m tools.verify_namespaces # 命名空间清单验签辅助（输出 canonical 摘要 + openssl 验签命令）
python -m scripts.install --check # 校验已安装实例与包是否一致（版本 + 哈希）
```

> 为什么写 `python -m`：这些脚本随包安装在 `site-packages` 内。相对项目根的 `scripts/x.py` 那种写法在装完之后跑不通 —— 0.48.2 用户旅程模拟实测：README 里该类命令**全部不可达**（撞「页面不许教跑不通的命令」）。

退出码约定：`antinel_verify` 0＝current / 1＝superseded / 2＝无法校验；
`python -m scripts.install --check` 0＝一致 / 1＝未安装 / 3＝有漂移。

任何第三方复跑出不同结论，即取代随包判定记录（追加式，原记录不删不改）。

## 它防什么 / What it protects against

| 闸门 Gate | 威胁 Threat | 规则 Rules |
|---|---|---|
| 内容安全 | 技能投毒：提示注入、隐形字符、编码载荷 | CTX-02..04, CTX-07 |
| 敏感面 | Agent 读取 .env / SSH 私钥 / 云凭证 / 钱包 / 浏览器数据；内容中的密钥字面量；输入法词库；投放到外部的金丝雀文件（canary） | SEC-01..11 |
| 元数据与出联 | 技能身份伪装；白名单外域名；隧道与隐蔽信道 | CTX-05, NET-03..04 |
| 行为异常 | 删除、越界写入、备用数据流写入（Windows）、启动项篡改、持久化、提权、环境枚举 | CTX-01, DST-01..11, NET-01..02 |

真实拦截样例（来自 ZCode 真机）：

```
[SEC-01] Antinel 拦截 [SEC-01] 读取 .env 文件可能泄露 API 密钥与机密配置 | 命中: .env |
放行/处理: 把 .env 移出 Agent 可读范围；确需变量时手动复制具体几行
```

## 安装 / Install

**ZCode 用户（推荐：插件方式，装完即全局生效）**

1. Settings → Plugin Management → 从本地目录安装本插件包（antinel-security-zcode-plugin/）
2. 重启 ZCode 一次。完成——所有工作区的 Agent 行为都在守护范围内。

**其他宿主（Claude Code 等）/ 手动方式**

```
python -m scripts.install --root <项目根>          # 项目级
python -m scripts.install --root <项目根> --global  # 用户级，所有项目
```

安装后重启宿主一次（钩子在宿主启动时加载）。

## 升级 / Upgrade（0.16.0 起）

```
python -m scripts.install --check   # 先比对：已装版本/规则哈希/脚本哈希 vs 包（无任何改动）
python -m scripts.install --root <项目根>   # 不一致时重跑安装，自动刷新快照与哈希
```

升级包后不重跑安装，钩子会**降级到内置 11 条回退规则集**并留下 `rules_integrity_fallback`
审计事件——请升级后必跑一次 `python -m scripts.install`（或先 `--check` 看差异）。

## 使用 / Usage

- 对 Agent 说：**"帮我检查环境安全"** —— Agent 读取 SKILL.md 自动完成安装、扫描、报告
- 或手动：`python -m scripts.scan --root <项目根>` ／ `python -m scripts.report --days 7`
- 导出：`--format csv|sarif|html|json` ／ 归档：`--archive`
- 卸载（零残留）：`python -m scripts.install --uninstall`

### 给 Agent 的三条命令

| 你要什么 | 命令 |
|---|---|
| 当前状态、下一步（`--json` 机器可读） | `antinel agent [--json]` |
| 装 / 比对 / 卸钩子（等价 `python -m scripts.install`） | `antinel install` ／ `--check` ／ `--uninstall` |
| 打印随包操作手册（`--path` 只给路径，省 token） | `antinel skill [--path]` |

`antinel install --check` 的退出码：`0`＝一致 / `1`＝未安装 / `3`＝有漂移。
`python -m scripts.scan` 的退出码：`0`＝扫描完成（**有发现也是 0**，发现数看报告或 `--json`）。
`antinel report` 的退出码：`0`＝报告已产出（**这一窗口里没有任何事件也是 0**，报告里 `empty: true`、各计数为零、**`score` 为 `null`**）/ `2`＝参数或读取错误。空态不是错误——刚装好、当天还没有调用时，第一条查询照样给你一份结构完整的零值报告；**但空态不出分**：分母为零时「100 分 / 环境安全」与「没有问题」是同一种假话。
`antinel verify`（**链**校验）的退出码：`0`＝干净 / `2`＝有无法解释的差异 / `3`＝差异已解释 / `4`＝**没有可验的东西**（空链）。`4` 不是通过：查不到 ≠ 查出来是好的。它和 `antinel_verify`（**文件哈希**校验，0＝current / 1＝superseded / 2＝无法校验）是两套码，别混读。

## 信任 / Trust (don't trust us - verify)

- 判定记录 `psl/judgment.json`：断言总数见 `assertions_total` 字段；任何第三方可用
  `python -m scripts.run_harness` 复跑；复跑失败即取代随包记录
- 判定自带**状态位与作用域**：`status`（current/superseded，用 `python -m tools.antinel_verify`
  随时推导）、`scope`（覆盖 8 个摘要文件，不覆盖什么也写明）、`platformSpec`（单平台诚实
  标注）、`objectOwnership`（**真推导**：签名清单＋README 钉定指纹＋git remote /
  `manifest.namespace` 身份，fail-closed `unattributed`——0.17 前是常量，0.17 起为机制）
- 追加式台账 `psl/verdict-ledger.jsonl`：第 1 行 = 自证判定；只增不删
- 审计**日锚** `.psl/audit/day_manifest.json`（0.18.0）：记录每日字节长度与末行哈希（链外
  独立副本），`verify_chain` 的 tail 校验据此检出"删除末尾 N 条 / 删除整天文件"——
  0.17 及之前，这类篡改检不出（已知边界，现已被锚收紧为一需同伪两文件）
- **诚实声明（`--manifest` 的二阶边界）**：`--manifest` 证明的是"树 = 清单"，不证明
  "清单 = 发布时清单"——`psl/manifest.json` 不在 `judgment.digests` 内，同时改文件与清单
  可骗过它；防合并篡改需 CI 产物留底或将清单纳入 digests（后续版本评估）
- `fail_closed_on_audit_loss` 策略键（0.18.0 起真实接线）：审计写失败默认放行（stderr
  可见 `AUDIT_WRITE_FAILED`），置 true 则阻断——取舍归你，机制归我们
- 命名空间清单 `antinel-namespaces.json`：ed25519 签名，公钥指纹
  `sha256:b71e570c30ebcbf7`（钉死在本 README；轮换只允许追加新钥匙条目）；
  清单缺失或验签失败时对象归属一律落 `unattributed`（fail-closed）
- 规则全部开源：`rules/default.json`（24 条，双语说明）；每条审计记录含 content_digest，判据可重算
- 运行时零网络；仅标准库；无第三方依赖；无驻留进程
- **拦截自检（0.30.0，E-3 关闭）**：`python -m tools.enforce_probe` —— 合成一个必拦事件跑真钩子，断言全部下发通道（stdout 契约 + legacy + exit 2）并上链 `enforcement_probe`；宿主若把"已拦截"的调用真的执行了，post 侧上链 `enforcement_gap`。晨报新增执法状态行（探针通过率 / 执法缺口 / 护栏在线天数）——**闸门死了必须大声说出来**，而不是让账本为假象背书
- **指令面 + MCP + 金丝雀 + 撞名（0.31/0.32）**：CTX-02/04 扩展到 AGENTS.md/CLAUDE.md/.cursorrules/copilot-instructions.md（非 SKILL.md 需复合命中，压误报）；MCP-01..04 护住 MCP 配置（写配置/描述注入/远程 server/env 明文密钥）；`antinel canary plant` 布源码金丝雀（读→提醒、标记出现在输出→外传实证）；SLOP-01 对安装命令做撞名检测（参考集 rules/typosquat_top.json，静态有时效，报告中显性标注）
- 收入边界声明见源码仓 `docs/A6收入边界声明.md`（该件随 sdist 分发，**不随 wheel**）：不收通过费、不出售排名、关联方无豁免
- 中立性靠机制：开源规则 + 可重算判定 + 阴性结果照发 + 免费离线可验

## 已知边界 / Known limits（诚实声明）

- **规则只匹配工具调用文本，不解析脚本内容**：把删除或越界写入写进一个 `.py`/`.sh` 再执行，四道闸门都不会拦截（实测：Bash 通道没有 `file_path`，DST-02 在该通道上恒不触发；0.17.0 起此类命令中的**显式绝对路径**会以 `dst02_bash_path_suspect` 事件留痕并告警，但**不拦截**）。这是**护栏**的设计边界，不是隔离层；需要隔离请用容器或沙箱
- Hook 拦截仅覆盖宿主支持 PreToolUse/PostToolUse 的工具与动作；当前在 Windows + ZCode 实测，macOS/Linux 由 CI 矩阵持续验证
- 只读命令上下文（echo/grep 等提及而非执行的危险词）中的 critical 命中会降级为 alert 并照常记录——这是刻意设计，防止"grep 危险词"被误拦；真正的执行形态仍会拦截
- **备用数据流（ADS）拆成两半看**（0.19.0）：**写入路径已拦**——`echo x > f.txt:stream`、`Set-Content -Stream`、`copy`、`open(...,"w")` 在 Windows 上命中 DST-09/DST-10，退 2（该规则按 `platforms: nt` 只在 Windows 生效，因为 `path:stream` 在 POSIX 上是合法文件名；`Zone.Identifier` 由浏览器/下载器写入，按设计豁免）；但**流里的内容读不回来**——已写进 ADS 的载荷在工具调用层不可见，属结构性非目标（见 `references/THREAT_MODEL.md` 的 Non-goals）
- **安防自身的 host 级配置可被 Agent 改写（0.19.2 起，刻意且留痕）**：`~/.workbuddy/antinel.json` 的 `workspace_roots` 就是信任边界本身。0.19.1 及以前 Write/Edit 写它会被 DST-02 拦截，但**同一目标经 Bash 通道（脚本内部用 `expanduser` 拼路径）可以零命中到达**——实测该次写入在审计里是 `decision=allow, rules_hit=[]`。**拦一半等于没拦，却确实挡住了用户自己的正常维护**（审计实证：DST-02 拦下的 `~/.workbuddy` 目标共 4 次，其中 3 次是创建 skill）。0.19.2 起两个通道统一为**放行 + 留痕**：放行精确到该配置文件本身（**不含**其父目录），每次放行写 `dst02_host_config_self_maintenance` 事件，并在 report.py 单列"信任边界编辑次数"。⇒ 这是**从"阻止"降级为"记录"**：需要边界不可改，请用只读挂载或容器
- `rd`（Windows 删除命令）按"命令位置＋参数语境"匹配：`rd /s /q X` 拦截；Python 代码里的 `rd = 3`、raw 字符串 `r'D:\...'` 放行（0.16.0 修复了旧版对后两者的 critical 误报）
- 行为语料（含负例）不随包分发；该读数无法仅凭本包复现（见 `psl/judgment.json` 的 `scope.notCovered`）
- Qoder/TRAE 的字段布局为声明式适配（未实测）
- 换宿主或宿主大版本更新后，用 `python -m tools.probe_host` 做一次协议探针并把结果发给我们
- 本套件输出审计日志与安全评估，不是检验检测报告；不能替代内核级防护（那是安信智芯 Link/Tank 的事）

## 计分 / Score

`score = 100 - 20 × critical - 5 × warning`（按去重后的发现计数，截断到 0..100；
去重键 `(rule_id, target)`）。每次报告都随附此计分基准行；体检报告只统计静态发现，
钩子告警由 report.py 单独统计——两个数不合并。

## 许可 / License

本仓采用分层许可（策略 v1.1）。逐文件真源见 `license-map.json`；机器可读标识见各文件头 `SPDX-License-Identifier`。

| 层 | 覆盖 | 许可 |
|---|---|---|
| 产品代码（默认） | 除下述外的全部源码与 CI 件 | Apache-2.0（见 LICENSE；义务与归属提示见 NOTICE） |
| 引流小件 | `antinel_mcp.py`、`transcript_reader.py`、`tools/probe_host.py`、`strings.py`、`challenge/` | MIT（见 challenge/LICENSE 与各文件头） |
| 声明与规则集 | `docs/A6收入边界声明.md`、`rules/*.json` | CC-BY-4.0 |
| 规范与文档 | README、docs/ 下规范与说明 | CC-BY-SA-4.0 |

收入与中立性边界见源码仓 `docs/A6收入边界声明.md`（CC-BY-4.0；随 sdist 分发）：不收通过费、不出售排名、关联方无豁免。
