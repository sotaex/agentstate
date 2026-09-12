# Antinel Security Suite

**让每一个 AI 编程工具的用户，在 30 秒内知道自己的 AI 编程环境安不安全——并且持续监控、持续安心。**

One command. 22 rules. 4 gates. Local-only, zero network, standard library only.

## 别信我们，自己验 / Don't trust us - verify (30 秒)

```bash
python scripts/run_harness.py     # 复跑全部断言，得到你自己的 verdict（写入 psl/judgment.json）
python tools/antinel_verify.py    # 校验随包判定是否已失效（digest 比对，推导 current/superseded）
python tools/antinel_verify.py --manifest   # 校验全部随包文件（以 psl/manifest.json 为准）
python tools/verify_namespaces.py # 命名空间清单验签辅助（输出 canonical 摘要 + openssl 验签命令）
python scripts/install.py --check # 校验已安装实例与包是否一致（版本 + 哈希）
```

退出码约定：`antinel_verify` 0＝current / 1＝superseded / 2＝无法校验；
`install.py --check` 0＝一致 / 1＝未安装 / 3＝有漂移。

任何第三方复跑出不同结论，即取代随包判定记录（追加式，原记录不删不改）。

## 它防什么 / What it protects against

| 闸门 Gate | 威胁 Threat | 规则 Rules |
|---|---|---|
| 内容安全 | 技能投毒：提示注入、隐形字符、编码载荷 | CTX-02/03/04 |
| 敏感面 | Agent 读取 .env / SSH 私钥 / 云凭证 / 钱包 / 浏览器数据；内容中的密钥字面量 | SEC-01..06 |
| 元数据与出联 | 技能身份伪装；白名单外域名 | CTX-05, NET-03 |
| 行为异常 | 删除、越界写入、启动项篡改、持久化、提权、环境枚举 | DST-01..05, CTX-01, NET-01/02 |

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
python scripts/install.py --root <项目根>          # 项目级
python scripts/install.py --root <项目根> --global  # 用户级，所有项目
```

安装后重启宿主一次（钩子在宿主启动时加载）。

## 升级 / Upgrade（0.16.0 起）

```
python scripts/install.py --check   # 先比对：已装版本/规则哈希/脚本哈希 vs 包（无任何改动）
python scripts/install.py --root <项目根>   # 不一致时重跑安装，自动刷新快照与哈希
```

升级包后不重跑安装，钩子会**降级到内置 11 条回退规则集**并留下 `rules_integrity_fallback`
审计事件——请升级后必跑一次 `install.py`（或先 `--check` 看差异）。

## 使用 / Usage

- 对 Agent 说：**"帮我检查环境安全"** —— Agent 读取 SKILL.md 自动完成安装、扫描、报告
- 或手动：`python scripts/scan.py --root <项目根>` ／ `python scripts/report.py --days 7`
- 导出：`--format csv|sarif|html|json` ／ 归档：`--archive`
- 卸载（零残留）：`python scripts/install.py --uninstall`

## 信任 / Trust (don't trust us - verify)

- 判定记录 `psl/judgment.json`：断言总数见 `assertions_total` 字段；任何第三方可用
  `python scripts/run_harness.py` 复跑；复跑失败即取代随包记录
- 判定自带**状态位与作用域**：`status`（current/superseded，用 `tools/antinel_verify.py`
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
- 规则全部开源：`rules/default.json`（22 条，双语说明）；每条审计记录含 content_digest，判据可重算
- 运行时零网络；仅标准库；无第三方依赖；无驻留进程
- 收入边界声明见 docs/A6收入边界声明.md：不收通过费、不出售排名、关联方无豁免
- 中立性靠机制：开源规则 + 可重算判定 + 阴性结果照发 + 免费离线可验

## 已知边界 / Known limits（诚实声明）

- **规则只匹配工具调用文本，不解析脚本内容**：把删除或越界写入写进一个 `.py`/`.sh` 再执行，四道闸门都不会拦截（实测：Bash 通道没有 `file_path`，DST-02 在该通道上恒不触发；0.17.0 起此类命令中的**显式绝对路径**会以 `dst02_bash_path_suspect` 事件留痕并告警，但**不拦截**）。这是**护栏**的设计边界，不是隔离层；需要隔离请用容器或沙箱
- Hook 拦截仅覆盖宿主支持 PreToolUse/PostToolUse 的工具与动作；当前在 Windows + ZCode 实测，macOS/Linux 由 CI 矩阵持续验证
- 只读命令上下文（echo/grep 等提及而非执行的危险词）中的 critical 命中会降级为 alert 并照常记录——这是刻意设计，防止"grep 危险词"被误拦；真正的执行形态仍会拦截
- `rd`（Windows 删除命令）按"命令位置＋参数语境"匹配：`rd /s /q X` 拦截；Python 代码里的 `rd = 3`、raw 字符串 `r'D:\...'` 放行（0.16.0 修复了旧版对后两者的 critical 误报）
- 行为语料（含负例）不随包分发；该读数无法仅凭本包复现（见 `psl/judgment.json` 的 `scope.notCovered`）
- Qoder/TRAE 的字段布局为声明式适配（未实测）
- 换宿主或宿主大版本更新后，用 tools/probe_host.py 做一次协议探针并把结果发给我们
- 本套件输出审计日志与安全评估，不是检验检测报告；不能替代内核级防护（那是安信智芯 Link/Tank 的事）

## 计分 / Score

`score = 100 - 20 × critical - 5 × warning`（按去重后的发现计数，截断到 0..100；
去重键 `(rule_id, target)`）。每次报告都随附此计分基准行；体检报告只统计静态发现，
钩子告警由 report.py 单独统计——两个数不合并。

## 许可 / License

MIT（见 LICENSE 文件）。收入与中立性边界见 docs/A6收入边界声明.md。
