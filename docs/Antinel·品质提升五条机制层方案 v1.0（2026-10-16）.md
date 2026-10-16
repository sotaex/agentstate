<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel·品质提升五条机制层方案 v1.0（2026-10-16）

创始人拍板：五条全做，方法＝「先拿方案再动手」，落点全部收进**机制层**（能机械判的进判据/钩子，行为纪律类进 L2 触发层）。本方案即动手依据；每条附验收标准，做完逐条对验收。

## 0. 五条总览

| # | 病灶（本会话真实事故） | 机制层落点 | 保障强度 |
|---|---|---|---|
| 1 | 量具坏了被当成产品坏了：截图 stride 未对齐 ⇒ 歪图 ⇒ 误读两条文案；CRLF 被当尾随空格 ⇒ 逼人「修」不存在的垃圾 | `ci/l2_wenhe_selfask.py` v1.3：Q7（图读结论回文字真源）＋Q8（字节诊断禁用吞 CR 工具） | L2 触发器（出声不裁决，A4 红线不动） |
| 2 | 判据自身的时变性：0.50.4 给 `reading_note()` 加实时时刻，消费它的判据逐字比对 ⇒ 跨分钟伪红（0490 U-01 / 0470 S95 实测撞上） | `ci/inbox_guards_0490.py` 新增 T-01：AST 审计全部套件里时变产物的裸比对消费点 ＋ N-T01 负控 | 判据（并入 0490，P5 纪律不新建套件） |
| 3 | 机制层不守自己：A1/A2 落地当天，第一笔新登记（0518）就双违规——检查只在闸门跑时才发现，**发现时已经登记进去了** | `hooks/pre_tool_use.py` 新增 GOV-01：把 A1/A2 **前移到写入时刻**——写新常驻套件缺 P1–P5 ⇒ 拦；登记动作让常驻超限／登记悬空 ⇒ 拦 | 预写钩子（守护链，三通道 deny） |
| 4 | 交接边界债：暂存区带空白缺陷、manifest 未对齐、新文件裸奔未归批 ⇒ 接手人先考古 | `ci/guard_release_entry.py` 新增 S53：有暂存 ⇒ 三件套（暂存空白干净／manifest 对齐／无裸奔新文件）；无暂存 ⇒ 诚实 SKIP | 判据（并入发布入口套件） |
| 5 | 登记与事实分家：0.50.5 案——「暂缓出包」的登记停在旧版号，版本前进后变成**登记了一个永远产不出的版本** | `ci/regression_gate.py` `j_workspace_facts` 扩⑥⑦：target_version 必须==release.version；publish_hold 必须含 hold_version 且版本前进即失效 ⇒ 红 | 判据 ＋ INJECTIONS 负控注入 |

## 1. 第 1 条 → L2 v1.3（Q7/Q8）

**病灶**：同日两起——①`_p_console_shot.py` 按 `宽×3` 读 GetDIBits 位图，行跨距没按 4 字节对齐，870px 宽的窗口整幅斜切；我从歪图里把「看过即知，不用动手」误读成「需要动手」、「归并」误读成「归档」，差点照误读改文案。②CRLF 行的 `\r` 被 `git diff --check` 报成 trailing whitespace，字节级根因诊断若用 sed/awk（会吞/规范化 `\r`）就会得出错误结论。

**机制**：L2 是品质触发层（A4/A5 刻意不进 SUITES、不产绿红），加两条自问：
- **Q7**：这条结论是从截图/图片里**读**出来的吗？是 ⇒ 逐字回文字真源（HTML/JSON/源码）核对后才许写进交付物——图会歪（跨距、缩放、低清），字不会。自写了位图/像素级探针 ⇒ 行跨距必须 4 字节对齐（stride=((w*3+3)//4)*4）。
- **Q8**：做过字节级/行尾级诊断吗？用 sed/awk/grep 默认输出看行尾 ⇒ 换 od/xxd/Python 读字节——它们会吞 `\r` 或规范化行尾，把 CRLF 误报成空白缺陷。

**验收**：打印面可见 Q7/Q8；docstring 记 v1.3 变更与两起事故动因；`--guard` rc 恒 0 不变；无判据钉住 WENHE 条数（已排查，零锚点风险）。

## 2. 第 2 条 → 0490 T-01（时变产物消费点审计）

**病灶**：`M.reading_note()` 自 0.50.4 带「载入于 HH:MM」实时时刻。消费它的判据若**逐字**比对（渲染后独立再调一次），跨分钟即伪红——全量复跑真实撞上（0490 U-01），0470 S95 同病。修法是两侧经 `PC.note_text()` 归一，但**没有尺子守着「今后不许再出现裸逐字比对」**。

**机制**：T-01 用 AST 扫全部套件源码（`ci/inbox_guards_*.py` ＋ `ci/guard_*.py` ＋ `ci/regression_gate.py`），找 `M.reading_note()` 出现在 `Compare`（`not in` / `!=`）操作数且**未经 `PC.note_text` 包裹**的消费点 ⇒ 红（这个方向＝「不等就判红」＝跨分钟必伪红）。`in` / `==` 正向在场检查豁免（方向相反，不会伪红，只影响负控分辨力——注释里说明）。
- **N-T01 负控**（内建）：造一段裸 `not in` 源码 ⇒ 尺子必须红；同段套上 `note_text` ⇒ 必须绿。尺子抽成模块级纯函数，正负控共用同一实现。

**验收**：0490 全绿（T-01/N-T01 计入）；N-T01 双向实测；对现状全仓实跑 T-01 为绿（0490:516、0470:516 两处已归一）。

## 3. 第 3 条 → 钩子 GOV-01（A1/A2 前移到写入时刻）

**病灶**：0518 当天「先登记、闸门才发现缺 P1–P5＋超限」。检查在提交时刻，登记在写入时刻——**晚了半拍**，违规状态已经存在了半天。

**机制**：`hooks/pre_tool_use.py` 新增 `_suite_gov_hit(tool_name, fpath, content, project_root)`，照 `_slop_hit`/`_budget_hit` 的**同构模式**返回 hit dict 进既有 hits 流（审计/报告/deny 三通道零改造）。口径（自包含实现，不 import ci/ 模块——钩子在安装态运行）：
- **Write** 到 `ci/inbox_guards_*.py` 或 `ci/guard_*.py`：content 前 60 行缺 `P1:`–`P5:` 块 ⇒ **block**（A1，0518 事故原样拦截）。磁盘 SUITES 常驻数 +1 超上限 29 且退休簿无 pending ⇒ **alert**（不拦草稿，出声）。
- **Edit/Write** 到 `ci/delivery_gate.py`：从 old/new 差值数登记条目 Δ；Δ>0 时对每个新登记的常驻套件文件——磁盘不存在 ⇒ **block**（登记悬空）；存在但缺 P1–P5 ⇒ **block**；当前常驻数 + Δ > 29 且 `ci/suite_retirement.json` 无 pending ⇒ **block**（A2）。
- **fail-open**：内部任何异常 ⇒ 返回 None 放行（A-08 红线：钩子故障绝不拦合法操作）。
- P1–P5 正则与 cap=29 与 delivery_gate 双向同步声明（钩子自包含是架构约束，复制处全部注明真源）。

**负控**（函数级五例探针 `_p_gov_probe.py`）：①无 P1–P5 的新套件 Write ⇒ block；②合规内容 ⇒ None（放行）；③Edit 登记 Δ=1 且目标文件缺块 ⇒ block；④Δ=0 普通编辑 ⇒ None；⑤异常输入 ⇒ None（fail-open）。

**验收**：五例负控全过；重签 manifest（钩子在册）；引用钩子的既有判据随全量复跑兜底（已排查 10+ 文件引用）；既有 E-3 探针体系不受影响（GOV 挂主链，probe 分支本就不含特判族）。

## 4. 第 4 条 → S53 交接三件套（guard_release_entry）

**病灶**：昨夜交接单接手时：暂存区 5 文件带空白缺陷（`--check` rc=2）、manifest 未对齐、批间边界未裁定——接手人先考古一小时。

**机制**：`ci/guard_release_entry.py` 新增 S53「交接自检」：
- **无暂存** ⇒ SKIP（「非交接时刻测不出」——诚实跳过，协议允许）；
- **有暂存**（`git diff --cached --quiet` rc≠0）⇒ 三查：①`git diff --cached --check` 必须 rc=0（暂存空白干净）；②`host_shield.self_check()` 必须 `[True, []]`（manifest 与源码对齐——交接最常见遗忘项，已排查无既有判据设站，不重复）；③`git status --porcelain` 的未跟踪项不许裸奔在 `ci/ hooks/ psl/ scripts/ rules/ docs/`（豁免：`_p_*` 探针惯例、`output/ .workbuddy/ out/ dist/ logs/`）。
- 判定逻辑抽纯函数（`_staged_ws_clean` / `_naked_new_files`），负控喂变异输入。

**N-S53 负控**：①喂带 trailing-whitespace 的 check 输出 ⇒ 必须红、干净输出 ⇒ 绿；③喂含 `?? ci/新文件` 的 status ⇒ 必须红、`?? _p_x.py` ⇒ 绿。不动真实暂存区（零写脏）。

**验收**：guard_release_entry 全绿＋N-S53 双向实测；当前真实态（有暂存则三绿）实跑一次。

## 5. 第 5 条 → j_workspace_facts ⑥⑦（登记失效条件）

**病灶**：`_note_0510` 写「保持 0.50.5、出包等禁令解除」——版本前进到 0.51.0 后，该登记从「暂缓」变成「登记一个永远产不出的版本」，直到收尾时被 D-23 拦住才发现。**「暂缓」类决定没有失效条件。**

**机制**：`j_workspace_facts` 扩两查：
- **⑥** `pypi.target_version` 与 `release.version` 不一致 ⇒ 红（「出包登记与当前版本分家——0.50.5 事故。确要暂缓 ⇒ 用 publish_hold 显式登记，不许让 target_version 停在旧版」）。
- **⑦** `release.publish_hold`（若存在）必须含 `hold_version`；`release.version != hold_version` ⇒ 红（「暂缓决定已失效——版本已从 hold_version 前进，复核登记：撤下 publish_hold 或更新 hold_version 并重述理由」）。这是「暂缓决定」的机器可读失效条件。
- release 段判定抽纯函数 `_release_section_problems(rel, want, in_flight)`，主判据与负控共用。

**负控**：内建（照 0380 ③先例）——变异 dict 塞 `hold_version=0.50.5` ⇒ 尺子必须红；塞合法 hold（hold_version==version）⇒ 绿。另在 `--selfcheck` INJECTIONS 表加一条对 `psl/workspace_facts.json` 的真实注入。

**验收**：regression_gate 全绿；内建负控＋INJECTIONS 注入双实测；现状（0.51.0 三处一致、无 publish_hold）为绿。

## 6. 实施顺序与总验收

顺序：方案（本文档）→ ①L2 → ②T-01 → ③GOV-01 → ④S53 → ⑤⑥⑦ → 重签 manifest → 全量 29 套件复跑（脚本计数）→ 正常钩子提交。

总验收：全量复跑除 0516 存量红外全绿；五条各自的负控全部实测转红过一次；提交走正常钩子（快道放行，不用 --no-verify）。

**边界（不能证明什么）**：①L2 触发器不产红绿，防的是「忘了自问」不防「自问了装没想」；②T-01 只盯 `reading_note()` 这一个已知时变产物，新时变函数出现时要扩名单；③GOV-01 只拦 Write/Edit 直接写文件，Bash 里 `cat >` 绕写不在此钩子射程（宿主 Bash 规则另有 DST 族）；④S53 的「有暂存」是机械代理，跨会话交接若恰好无暂存则三件套不触发；⑤⑥⑦只保 facts 内部一致，PyPI 实查仍只有发布流程能验。
