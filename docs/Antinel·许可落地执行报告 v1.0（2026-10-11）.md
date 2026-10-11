<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel·许可落地执行报告 v1.0（2026-10-11）

**状态**：✅ 全链收口。0.48.0 → 0.48.1（patch），提交 `7e4bb5a`，verify_release [A][B][C][D] 全过。
**上游**：策略 v1.1（四层方案）→ 实施方案 v1.0 → 核验报告 v1.0（两条假设推翻 + GitHub NOASSERTION 发现）→ 本报告（执行 + 三起中途事件的机制级修复）。

---

## 1 · 结论一段话

四层许可已**全量落地并以机制固定**：归属做成数据（`license-map.json`），真源单向（构建器常量 → 仓内文件），防复发有闸门（`ci/inbox_guards_0481.py` 六判据 + 六负控），组装与闸门形成**不动点**（组装后再扫 0 红）。harness 315/315，发布验收全过，产物 14 项许可内容终检全绿。**系统功能零影响**：全部 .py 语法复核通过，27 套判据全绿，回归闸门明示「已修好的缺陷没有回退」。

## 2 · 落地清单（对照策略 v1.1）

| 层 | 归属 | 落地物 |
|---|---|---|
| 产品主体 | Apache-2.0 | 109 个 py/md/html 默认层 ＋ 根 LICENSE（官方全文 11,358 B，**无 A6 尾**）＋ NOTICE（**首行 MIT 豁免**） |
| 引流小件 | MIT | `antinel_mcp.py`／`transcript_reader.py`／`tools/probe_host.py`／`strings.py` ＋ `challenge/`（含独立 challenge/LICENSE） |
| 声明与规则集 | CC-BY-4.0 | `docs/A6收入边界声明.md`＋`rules/*.json`（**不打 SPDX 头**——rules_hash 整文件哈希，加键即 SELF-TAMPERED，归属由本表＋README 分层表声明） |
| 规范与文档 | CC-BY-SA-4.0 | 22 个 md（README/references/docs/SKILL 等） |

- **归属数据**：`license-map.json`（defaults 四扩展名 ＋ overrides ＋ spdx_exempt 三条带理由 ＋ glossary_deviation ＋ tier_meaning）；构建器读它生成 METADATA 双 classifier ＋ 三件 License-File（LICENSE／license-map.json／NOTICE）＋ npm `"license": "(Apache-2.0 AND MIT)"`。
- **两处已拍板偏差**：① `glossary.py` 改判 Apache-2.0（乙案：顶层硬依赖 inbox_model，MIT 自足性不成立）；② `rules/*.json` 零 SPDX 头（核验报告 §2.2 实测的 rules_hash 陷阱）。
- **SPDX 批量**：140 写入 / 2 跳过（Apache 109｜CC-BY-4.0 1｜CC-BY-SA-4.0 22｜MIT 10）；全部 .py 重 ast.parse 通过（零语法影响证明）。
- **版本**：9 处承载件逐字 0.48.1（version_check PASS 9/9）。

## 3 · 中途三起事件与机制级修复（都不是绕，是修源头）

### 3.1 组装冲头（0481 L1 首功）

**现象**：0481 门禁创建时 12 绿，首次真实组装后 L1 变红 7 处（SKILL.md／A6／references 三件／HOST_PROBE／probe_host.py）。
**根因**：`_license_apply` 把头写进了**实例**，但 builder 的六个再生点源头无头——模板常量（SKILL/THREAT_MODEL/HOST_PROBE）、生成器（AGENT_SKILL=routes --markdown、RULES=rules_md()）、仓外源件复制（A6←工作区签署件、probe_host←r1v3 源仓）。每次组装 `copy2/write_text` 即冲掉。
**定性**：与 G7-3「修了模板没修实例」互为**镜像**（这次是修了实例没修源头）。
**修复（两层）**：
- 源头层：builder 六个写盘点改为输出带头文件（md=HTML 注释首行；py=shebang/coding 后 `#` 行；SKILL.md=**front matter 内第 2 行 YAML 注释**——文件最前会破坏 `---` 开头约束，放 front matter 后超闸门六行窗）；
- 实例层：`_spdx_fix_0481.py` 把 7 个现存文件打成与 builder 输出**逐字节同构**（7/7 断言式），此后「闸门（组装前跑）→ 组装（再生）」构成不动点——**实测：组装后复扫 0 红**。
**闸门首功**：L1 第一次真跑就抓到自己的组装流程在冲头——「坏了会有人知道」从口号变成一次实绩。

### 3.2 harness 313/315（两条 process-stale，自愈路径实测确认）

机器分类账（随账本发布）：`counts = {product:0, instrument:0, environment:0, process-stale:2}`，`stale_digests_at_run_time` 实测 13 个受辖文件与 SPDX 批量写入吻合。**受辖文件合法编辑后第一轮 harness 必红这两条（登记在案），该轮自己把新摘要写回卡片，第二轮即绿**——第二轮实测 **PASS 315/315**。0.39.2 设计的自愈路径首次完整走通。

### 3.3 自证卡与判定不一致（version/D-6 红）

**现象**：harness PASS 后，version 红条「verdict=PASS 但 psl-verified-at 为空」＋回归 D-6 红。
**根因**：中途成功过的普通构建（无 `--verify`）把模板 false 卡写进树；刷卡点在 `--verify` 流程的 harness 之后（0.42.0 死锁修复的设计位置）。
**修复**：调用唯一刷卡真源 `_refresh_skill_selfcert`（只改卡上 4 行；harness_rc=0 且 21/21 摘要吻合才写 true——12:29 那轮是真 PASS，其后 7 个打头文件无一在受辖摘要内，记录如实描述当前字节）。实测刷新为 `true @ 2026-10-11T12:29:21+0800`，version_check 复跑 PASS 9/9。

## 4 · 最终机械取证

| 关卡 | 结果 |
|---|---|
| 统一交付闸门 | **27 套全绿**（全量档，含 0481 六判据六负控、回归「无回退」、PCM 收敛） |
| harness | **PASS 315/315**（第二轮；第一轮 313/315 见 §3.2） |
| 组装后复扫 | SPDX 红名单 **0 处**（不动点实证） |
| verify_release | [A] 布局 ✅ [B] 单 dist-info＋RECORD 132==132＋sdist 168 成员全在本版目录 ✅ [C] twine 双 PASSED ✅ [D] **E2E-OK 0.48.1** ✅ |
| 产物内容终检 | wheel 六项：LICENSE 11,358 B 无 A6 尾／challenge/LICENSE=MIT／NOTICE 首行豁免／scan.py 头／probe_host 头(MIT) ✔；sdist 八项：challenge/LICENSE ✓ NOTICE ✓ 根 LICENSE ✓ A6/AGENT_SKILL/RULES/THREAT_MODEL/HOST_PROBE 首行 CC-BY ✔ probe_host 三行结构 ✔ |
| 产物 | whl **1,429,427 B** ／ sdist **1,473,657 B**（13:39–13:40，与源码树同字节） |
| 提交 | **`7e4bb5a`**（142 文件，pre-commit 回归闸门放行），工作区净 |

**核验报告 §7 五项签字对照**：① G7-3 源头已闭（构建器常量=官方全文，L2＋负控守）② MIT 五件中 glossary 移出（乙案落地，L5 AST 自足性守）③ rules_hash 陷阱规避（不打头＋理由入表）④ 外部 PR 窗口＝零贡献但 MIT 已生效一个月 → 本次升级把一个月的「无许可裸奔」收敛为明示四层 ⑤ GitHub 识别 → 源头修复完成，**远端复活待 push**（下节）。

## 5 · 未尽事项（外部动作，均待拍板）

1. **git push**：本地新提交 `7e4bb5a`（叠加此前未推的本地提交）；远端有 bot 提交需先对账（此前快照 20 ahead / 44 behind）。
2. **push 后跑 `python scripts/check_github_license.py --remote`**（M-C 对账）：预期 GitHub API `license.spdx_id` 从 `NOASSERTION` 变为 `Apache-2.0`——核验报告第 4 条「正在发生的公开错误」的最终闭合动作。
3. **PyPI 同步**：线上仍 0.34.1；0.48.1 的 whl/sdist 已验收待传（发布动作，单独拍板）。
4. **WorkBuddy 插件包**（`--out` 通道的 zcode-plugin zip）未在本轮重建，随下次插件发布节奏走。

## 6 · 工具链留档（全部入库，可重跑审计）

`_license_apply_0481.py`（批量打头＋许可三件生成）｜`_license_upgrade_0481.py`（构建器 9 处断言式拼接）｜`_version_bump_0481.py`（7 点升版，错配即中止）｜`_spdx_scan_0481.py`（L1 规则复刻只读扫描）｜`_spdx_fix_0481.py`（树内不动点修复 7/7）｜`_card_refresh_0481.py`（卡刷新，事实性传参）。
