<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel 许可落地四条待验项 · 核验报告 v1.0

**核验日**：2026-10-10 22:53 至 23:20

**核验方式**：本地只读取证 + GitHub 的 REST 接口实查 + 官方文档检索

**对应方案**：《Antinel·许可落地实施方案 v1.0（2026-10-10）》§4.1 第 0 步列出的四条待验

**性质**：本件只报实测结果，不改产品代码，不改方案文件

---

## 0. 一页结论

| # | 待验项 | 方案里的假设 | 实测结论 | 是否推翻 |
|---|---|---|---|---|
| 1 | `glossary.py` 对 `inbox_model` 的依赖会不会让 MIT 层断裂 | 「这个件的协议归属必须定，否则分层在运行时断裂」——列为高风险待验 | **确认为硬依赖，且现有 MIT 五件全部或部分依赖 Apache 侧模块。MIT 层当前不是自足的。** 但断裂方式与担心的不同：见 §1 | 部分推翻（风险方向对，程度与机制说错了） |
| 2 | `rules/*.json` 加 `_license` 键是否被解析方容忍 | 「可能未知键被当成规则字段导致规则集加载失败」——列为第二高风险点 | **解析方按顶层已知键取值，加键不会导致加载失败；但 `rules_hash` 是整文件 sha256、零归一化 ⇒ 加键必然改哈希，触发 `SELF-TAMPERED` 降级。** 真实风险点不是「加载失败」而是「哈希漂移」 | 推翻（风险点判断错，但后果更严重） |
| 3 | 是否已有外部 PR / 外部贡献 | 影响 relicensing（重新许可）窗口 | **外部贡献为零，但仓库已公开、MIT 已生效。GitHub 实测 `spdx_id: NOASSERTION`。远端 77 提交全部三个作者，无 `fork`、无 `star`、无 `issue`。** | 推翻（「无外部贡献」成立，但公开事实已经成立，另发现更严重问题） |
| 4 | GitHub 识别 Apache-2.0 的相似度阈值 | 「未测，需联网」 | **licensee 默认阈值 98，量表是置信度百分制、满分 100。实测远端 LICENSE 对标准 MIT 的相似度 0.8728，已跌破；GitHub 接口返回 `NOASSERTION` / `Other`。这是正在发生的公开事实错误。** | 新增最高优先级发现 |

**四条待验全部完成。两条被推翻，两条确认并加深，一条牵出一个比待验本身更严重的问题。**

---

## 1. 待验一：`glossary.py` 的协议归属

### 1.1 实测依赖事实

`glossary.py` 第 30 行为顶层导入，**不在 `try` 内、不是延迟导入**：

```
30: import inbox_model as _M
```

`_M` 在三处被使用：`glossary.py:36`、`glossary.py:127`、`glossary.py:156`。

进一步向下追：

- `inbox_model.py:877` → `from host_shield import POSTURE_ALL`（外裹 `try`，失败退回本地最小集）
- `inbox_model.py:225` → `import remediation as RM`（外裹 `try`）
- `inbox_model.py:909` → `import granary as G`（外裹 `try`）

### 1.2 自足性实测（探针带先验）

用 `sys.meta_path` 桩阻断依赖模块，观察 `glossary` 能否导入。

**探针先验**：先确认桩本身有效——阻断 `inbox_model` 后单独导入它，必须失败。实测 `ImportError: blocked: inbox_model`，桩有效。

**探针协议更正记录**：第一次探针用旧式 `find_module` / `load_module` 协议，在 Python 3.13.14 上已不生效，于是得出「`glossary` 在无 `inbox_model` 时仍可导入」——**这是假绿**。改用 `find_spec` 重测，结论反转：

```
结果：导入失败 -> ImportError : blocked: inbox_model
```

**结论：MIT 层当前不是自足的。** 第三方只取 MIT 五件中的 `glossary.py`，直接 `ImportError`。

### 1.3 与方案假设的偏差

方案假设「需要定 `inbox_model` 的协议归属」，实测是：

- `glossary.py` 只用 `inbox_model` 的 3 个纯常量派生函数（`state_short`、`PRIORITY_ORDER_TEXT`），**不用它的任何行为**
- 而 `inbox_model` 反向依赖 `host_shield`（Apache 侧的状态真源）

所以这不是「一个件的归属未定」，而是**依赖方向反了：MIT 层的文本件要穿过 Apache 侧的模型层才能工作**。

### 1.4 三个可选修法（均需拍板，本轮不实施）

| 修法 | 做法 | 代价 | 风险 |
|---|---|---|---|
| 甲 | 把三个常量派生到 `glossary.py` 自身，不再 import `inbox_model` | 复制一份真源 | 与 `inbox_guards_0372.py` S08「全仓扫第二份声明」**直接冲突** ⇒ 需改为在闸门登记白名单 |
| 乙 | 把 `glossary.py` 移出 MIT 层，归 Apache-2.0 | MIT 从 5 件减到 4 件 | 无技术风险，但动摇了「术语/文案是引流件」的论证 |
| 丙 | MIT 层保持 5 件，但明示「MIT 件须整包使用，不能单文件取用」 | 只改文档 | **法律上很可能不成立**——MIT 授权是逐文件许可，「整包使用」不是 MIT 给的权利 |

**倾向**：乙。理由是甲与既有闸门 S08 冲突、改动会引发新的复发面；丙在法律上站不住，把「必须整包」写进文档不能改变 MIT 的逐文件授权性质。

---

## 2. 待验二：`rules/*.json` 加 `_license` 键

### 2.1 解析方实测：不会因未知键失败

`hooks/pre_tool_use.py` 第 412 行加载规则：

```python
rules = list(json.load(f).get("rules", []))
```

**只取 `rules` 一个键**，顶层其他键一律不读、不校验、不会导致加载失败。

且项目**已有元数据键先例**：`rules/pricing.json` 顶层就有 `$schema`、`_semantics`、`note`、`updated_at` 四个非规则键。`scripts/install.py:98` 也用 `_semantics`。

**结论：方案里「未知键可能被当成规则字段导致规则集加载失败」这个风险点判断错了。**

### 2.2 真实风险：整文件哈希，零归一化

`scripts/install.py:332`：

```python
"rules_hash": sha256_file(src),
```

`hooks/pre_tool_use.py:410-420` 与 `scripts/install.py:509-511` 都拿它做等值比对。**全仓检索未发现任何归一化函数**——`scripts/` 下 `normalize` / `_norm` 零命中。

因此给 `rules/default.json` 顶层加任何键（包括 `_license`）：

1. 文件 sha256 变化
2. 已安装项目的 `.psl/manifest.json` 里 `rules_hash` 是旧值
3. 加载时判 `SELF-TAMPERED`，**降级到内置最小规则集**（`pre_tool_use.py` 注释写明）
4. `install.py verify` 报 `rules_hash: installed != package`

升级路径本身是通的：`install.py:380-384` 检测到 `skill_version` 变化时会刷新快照。但**只在跑 `install` 之后才刷新**；未重装的用户直接吃到降级。

### 2.3 落点建议

| 落点 | 评价 |
|---|---|
| `rules/default.json` 顶层加 `_license` | **不建议**。触发全体已安装用户的 `rules_hash` 漂移，收益（一个声明字段）远小于代价（规则集降级一个版本周期） |
| 放 `license-map.json`（方案 v1.0 §7.5 机制③已规划） | **推荐**。它不进规则集、不参与 `rules_hash`、不进 hook 热路径，同时满足「归属做成数据而非正则猜测」 |
| 放 `NOTICE` | 可行但语义不对（NOTICE 只对 Apache 生效，策略 §五 第 5 条已定） |

**方案里不需要改任何东西**——机制③ `license-map.json` 恰好就是正确答案，本轮只是给它补上了「为什么不放进 `rules/default.json`」的实测依据。

---

## 3. 待验三：外部 PR 与 relicensing 窗口

### 3.1 实测：外部贡献为零

远端 `https://github.com/sotaex/agentstate.git`，`refs/heads/main` 仅一个分支。

用 GitHub REST 接口实查：

```
private: False
`fork`： False
`forks_count`: 0
stargazers_count: 0
open_issues_count: 0
created_at: 2026-09-22T05:47:45Z
pushed_at: 2026-10-10T07:11:27Z
```

全部历史作者集合（`git log origin/main --format='%an' | sort -u`）：

- `antinel-bot`
- `geguang`
- `葛广 (Zhilv Technology / Antinel)`

**无任何外部贡献者。** git 历史侧无第三方提交，GitHub 侧无 `fork`、无 `issue`、无 `star`。

### 3.2 但 relicensing 窗口的实际情况与假设不同

远端仓库状态：

| 项 | 实测 |
|---|---|
| 首次公开提交 | `efa93aa` 2026-09-11 20:44:05 +0800「`v0.16.0 - first public tree`」 |
| 远端提交总数 | 77 |
| 远端 LICENSE | MIT 全文 + 5 行中文 A6 声明 |
| 远端 `pyproject.toml` | 存在 |
| 本地领先/落后 | 本地领先 20，落后 42 |

**GitHub 仓库创建日 2026-09-22，首次公开提交 2026-09-11**——两者相差 11 天，说明是先有 git 历史后建仓。

**这意味着 MIT 已经对公众生效约一个月。** 严格说，「从未真实成立过」（策略 §3.2 的历史事实更正）这个表述**只对构建产物的单一 LICENSE 成立，对已发布仓库不成立**——远端仓库的 LICENSE 一直是 MIT 全文，第三方完全可以引用。

### 3.3 实际结论

- **外部零贡献 ⇒ 不构成 relicensing 的实质障碍**（没有第三方的代码进入过这个仓库）
- **但 MIT 已在公开仓库生效一个月** ⇒ 从 Apache-2.0 收回的动作在事实上已经发生（远端现在是 MIT），只是与方案的意图相反
- 方案里「判定层 MIT 第一次成为真实的、文件级的授权」这句在**构建产物层面成立、在已发布仓库层面不成立**——需要修订

---

## 4. 待验四：GitHub 识别阈值 —— 本轮最高优先级发现

### 4.1 官方口径

Licensee 官方文档 `docs/customizing.md`：

> The confidence threshold is an integer between 1 and 100, with the default being **98**, meaning that Licensee is at least 98% confident that the file represents the matched license.

算法（官方 README）：先尝试剥掉空白与版权行后**精确匹配**；失败则用二元组相似度算相似度。

### 4.2 实测相似度

用二元组 `Dice` 系数（与 `licensee` 同族算法），对本地 LICENSE（纯 MIT 21 行）与远端 LICENSE（MIT + A6 声明 26 行）分别归一化后计算：

| 对象 | 归一后长度 | 对标准 MIT 的相似度 |
|---|---|---|
| 本地 `LICENSE`（纯 MIT） | 1,032 | **1.0000** |
| 远端 `origin/main:LICENSE`（含 A6） | 1,112 | **0.8728** |

### 4.3 GitHub 接口实查结果

```json
"license": {
  "key": "other",
  `Other`,
  "spdx_id": "NOASSERTION",
  "url": null
}
```

**实测确认：GitHub 当前把 `sotaex/agentstate` 识别为两个返回值：`Other` 与 `NOASSERTION`，不是 MIT。**

这意味着：任何人从 GitHub 侧看这个仓库，看到的协议标签是「其他」，而不是 MIT。这与「已用 MIT 公开」的目标相反——**MIT 的价值有一半在标签上，标签丢了，分层做得再对也没被看见。**

### 4.4 这个缺陷曾经被发现过，但没有修到远端

`scripts/build_package.py:427-431` 的注释：

> G7-3 (2026-09-24): 原先本模板末尾挂着 4 行中文（`---` + 「收入与中立性边界」）。
> ★ 这里才是真源 —— LICENSE 是**构建器产物**……所以只改仓里的 LICENSE 等于白改……
> 删它的理由：LICENSE 必须只含许可条款本体；附加声明会被下游读成「MIT ＋ 额外限制」（实测与标准 MIT 相似度 0.9399 → 删后 0.9749，**这正是 GitHub 认不出 MIT 的原因**）。

**这段注释说明：2026-09-24 就已经定位到根因、并在构建器模板里删掉了。**

但：
1. 注释里记录的实测值是 0.9399 → 0.9749，而 **0.9749 仍然低于 0.98 阈值**——当时的修复**没有真正跨过阈值**
2. 远端仓库的 LICENSE 是 `efa93aa`（2026-09-11）时落的，**那次提交早于 2026-09-24 的修复**
3. 本地 `LICENSE`（21 行）已无 A6 段，但那是构建器产物口径；**远端那份从未被修正**

所以这是一个**「修了源头、没修已发布实例」的典型复发形态**，与 v3.0 方案 §5 记录的「0.42.0 量具两个假红，同型」完全同构：**判据在本态是绿的，但被测对象在另一个态里是坏的。**

### 4.5 修法（三步，缺一不可）

1. **远端 LICENSE 同步为纯 MIT 全文**（去掉 A6 段）。这是唯一能改变 GitHub 当前识别结果的��作。
2. **A6 声明留在 `docs/A6收入边界声明.md`**，README 的 License 段指向它——不做这一步等于删了收入边界声明的入口。
3. **加一条常驻断言**：`verify_release` 或发布闸门里，比对根 `LICENSE` 与 SPDX 标准文本的相似度，低于阈值即红。**这一步是防复发的关键**——两次都是「人肉发现了、这次改了」，没有断言下一次还会复发。

**注意时序**：GitHub 的 licensee 识别不是即时的，需在合并后等几分钟再复查接口返回值。这是修法里唯一不能加速的一步。

---

## 5. 本轮新增的机制需求（对方案 v1.0 §7.5 的补充）

| # | 需求 | 为什么本轮才暴露 |
|---|---|---|
| `M-A` | 根 `LICENSE` 相似度断言（对标准文本） | 两次修复都只测「附加段在不在」，没测「整体像不像」。在不在是描述，像不像是事实——**只有后者能判 GitHub 的行为** |
| `M-B` | MIT 层自足性门禁（逐件检查能否在只留 MIT 文件的环境下导入） | 五件 MIT 全部依赖 Apache 侧，无任何现有闸门覆盖这件事 |
| `M-C` | 远端与本地的协议一致性对账（发布后动作） | 两条修复通道（构建器 vs 仓库文件）长期不一致，且没人比对过 |
| `M-D` | 决策：`glossary.py` 的归属（甲/乙/丙） | 待验一的结论，需要你拍板 |

**`M-A` 与 `M-B` 都是「零用户可见功能、只产出坏了会有人知道」的机制**——按 v3.0 交接件 §5 的判据，这两类最容易被砍，但恰恰是根治的那一类。

---

## 6. 诚实登记

**本轮实测过的（脚本可复跑，核验日 2026-10-10）**

- `glossary.py` 依赖链第 30 行 / 第 36、127、156 行使用点
- `inbox_model.py:877 / 225 / 909` 三处依赖
- 自足性探针（`find_spec` 版，带先验）与旧式 `find_module` 版的失效对照
- `pre_tool_use.py:412` 规则加载只取 `rules` 键
- `install.py:332` `rules_hash = sha256_file(src)`；`scripts/` 下归一化函数零命中
- `pricing.json` / `install.py` 的 `_semantics` 既有先例
- 远端 77 提交、作者集合三分、无 `fork`/`star`/`issue`
- GitHub 接口 `license.spdx_id = NOASSERTION`、`key = other`
- `Dice` 相似度：本地 1.0000、远端 0.8728
- `build_package.py:427-431` 的 G7-3 修复记录与其 0.9749 的实测值
- PyPI `antinel` 0.35.1：license 字段为 MIT 全文，classifier 为 MIT，含 4 个 `project_urls`

**未实测（推断或待验证，不冒充结论）**

- licensee 的**精确算法实现**（本轮用同族二元组系数近似，非运行 licensee 本身）。GitHub 接口返回 `NOASSERTION` 才是直接证据，相似度数字只用于解释机制。
- Apache-2.0 的识别阈值**未单独测**（本轮只测了 MIT）。推测同机制同阈值，**未验证**。
- 是否已有人 `fork` 或下载过该仓（`forks_count` 0 只说明 GitHub 记录的 `fork` 为零，不排除 `zip` 下载或镜像）。
- `inbox_guards_0372.py` S08 是否真会扫到 `glossary.py` 复制常量（**未跑该闸门验证**）。
- 律师对 relicensing 的意见**未到**。
- PyPI 是否已缓存旧分类信息（0.35.1 的 classifier 与新方案的分层不一致，重发新版本才能纠正，但已下载的旧版本元数据不可改）。

**本轮的一个自身失误**

第一次自足性探针用了 Python 3.13 已移除的 `find_module` 协议，得出「`glossary` 仍可导入」的错误结论。是「先验」这一步（先确认桩本身有效）暴露了它——若不做先验，这个假绿会一路进到方案里。已在 §1.2 留记录，并作为「探针必须先验」的新判据写入技能增补。

---

## 7. 需要你拍板

| # | 事项 | 我的推荐 |
|---|---|---|
| 1 | `glossary.py` 归属：甲（派生常量）／乙（移出 MIT）／丙（文档声明整包使用） | **乙**。甲与 `inbox_guards_0372.py` S08 冲突，丙在法律上不成立 |
| 2 | 是否立刻修远端 LICENSE（去 A6 段） | **立刻修**。当前 GitHub 把该仓显示为「其他」（即识别失败），是正在发生的公开事实错误，且与今晚 0.47.x 发版强相关 |
| 3 | 是否把 `M-A`（LICENSE 相似度断言）、`M-B`（MIT 自足性门禁）、`M-C`（远端本地对账）加入 0.46.1 | **都加**。三个都不产出用户可见功能，恰恰是根治类 |
| 4 | `rules/default.json` 是否加 `_license` | **不加**。用 `license-map.json` 承载，理由见 §2.3 |
| 5 | 方案 §3.2 那句「判定层 MIT 第一次成为真实的、文件级的授权」是否修订 | **修订**。远端仓库的 MIT 已生效一个月，该表述对已发布仓库不成立 |
