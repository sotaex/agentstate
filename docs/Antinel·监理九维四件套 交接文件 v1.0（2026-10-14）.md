<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel·监理九维四件套 交接文件 v1.0（2026-10-14）

**交接对象**：接手本仓的下一个 AI（或维护者）。
**成文时点**：2026-10-14 15:35（GMT+8），文中「本轮」均指该时点的只读核验。
**本文件性质**：纯交接文档，成文过程**零代码改动**；所有数字标注证据等级，禁止把历史结果当成当前 PASS。

---

## 0. 先读这个：铁律与证据标签

### 0.1 证据等级标签（全文通用）

| 标签 | 含义 |
|---|---|
| [本轮实测] | 2026-10-14 当天实际运行/读取所得，可复核 |
| [会话历史实测] | 前序会话留有可复核证据，本轮未重跑 |
| [摘要沿袭待复核] | 来自交接摘要，原始证据未核对 |
| [待测] | 尚未满足四件套或尚未执行 |
| [SKIP] | 本轮未运行；**绝不等同 PASS** |

### 0.2 仓库铁律（违反即返工，摘自工作区长期记忆，逐条沿用）

1. **测不出 ⇒ 报「夹具失效／SKIP」，绝不报 PASS**。「查不出来」≠「查出来是好的」。
2. 时红时绿的量具比恒红的更坏：依赖并发/时序/机器状态的夹具必须自证成立（会合栅栏＋前置条件强制化＋两臂对照，范式见 `ci/race_amp.py`）。
3. 判据打在**行为/结构**上：不查文案、不查行号、数调用点用 AST 不用文本正则；扫渲染产物必须显式选层（`ci/page_caliber.py`：`body()`／`body_without_terms()`／`chrome()`／`raw()`）。
4. **负控必须真会红**；负控自身故障要报「负控自身失效」，不许冒充产品红。
5. 缺陷登记簿（`ci/defect_types.py`）三纪律：每类有人守或申报盲区／实例不许借判据充数／未闭合实例必须暴露（主闸门 D-31 守）。
6. 元纪律 M-C：守护分层声明（产品／量具／钩子／登记簿），每层至少一条或申报盲区。
7. 判据 ID 格式 `[A-Za-z]+-?\d+`，否则登记簿报「幻想 ID」。
8. 判据不许二次实现产品口径，一律 `import` 产品模块。
9. **四件套**：任何修复/机制必须同时具备 ①正判据（direct read 真实状态）②反向对照（同一判据见红）③连带对照（既有保护不被静默破坏）④可观测/运行态自报。缺一不许报完成。
10. **九维机制**：入口唯一性／反向对照撤销即红／行为判据／既有保护连带对照／保护自报活跃／运行态确认（常驻服务重启后复核）／量具先自检／数据版本迁移／文档与代码同锚（数字机器核验，不心算）。

---

## 1. 当前快照（全部为本轮只读实测）

- **Git**：`main...origin/main [ahead 85]`，HEAD `c84627c`（「C6：daemon『已在跑』分支从出生起没被执行过」）。**全程未提交，接手者不得 reset / checkout / 覆盖 / 清理 / 擅自提交**。
- **已修改（M）**：`SKILL.md`、`antinel.py`、`antinel_mcp.py`、`ci/defect_types.py`、`ci/delivery_gate.py`、`ci/inbox_guards.py`、`ci/inbox_guards_0353.py`、`ci/inbox_guards_0360.py`、`ci/inbox_guards_0362.py`、`ci/inbox_guards_0431.py`、`ci/inbox_guards_0490.py`、`docs/AUDIT_SCHEMA.md`、`hooks/pre_tool_use.py`、`inbox_daemon.py`、`inbox_model.py`、`inbox_notify.py`、`inbox_server.py`、`inbox_window.py`、`pyproject.toml`、`rules/default.json`、`scripts/build_package.py`、`server.json`。
- **未跟踪（??）**：`assets/sounds/`、`ci/_pkg_sandbox.py`、`ci/bump_version.py`、`ci/inbox_guards_0514.py`、`docs/监理UI缺陷清单与修复计划（0.50.1）.md`、`inbox_bubble.py`、`inbox_logo.py`、`output/`、`tools/logo.ps1`、`tools/mk_sound.py`。⚠️ 未跟踪判据套件曾触发 JDG-04 红；**不要未经审查 `git add`**。
- **版本事实**：`antinel.py`／`pyproject.toml`／`server.json` = **0.50.3**；`psl/manifest.json` = **0.48.4**。**差值是研发态识别机制（`host_shield.is_dev_build()`），不得为数字一致刷平 manifest**（P1-1 另有处理方案）。
- **登记簿**：`python ci/defect_types.py --check` 本轮 exit 0（一致）；实例 **45** 条，最新 X-040…X-045。
- **0514 判据套件**（`ci/inbox_guards_0514.py`，未跟踪）：最近一轮全量 **74 绿 / 0 红 / 0 跳过**（2026-10-14 实测）。
- **运行态**：常驻 daemon pid **30376**（跨会话存活），HTTP 端口 **8790**（口令 URL 见 `read_console_record()`），仍在跑旧页面实例——**本轮 tooltip 修复未被该实例加载**（见 P0-0）。
- **主闸门**：`ci/regression_gate.py` 28/28 全绿（会话历史实测，非本轮复跑）。

---

## 2. 硬阻断与禁令（接手后立刻生效）

1. **禁止运行全量交付闸门 `python ci/delivery_gate.py`、`--quick`、`--selfcheck`**。原因（已只读核验）：`ci/inbox_guards_0364.py`（B4 写 `inbox_model.py`、C2 写 `psl/manifest.json`、C3 写 manifest+`host_shield.py`、D2 写 hook/规则登记表/`host_shield.py`、F5N 写 `inbox_window.py`）、`ci/inbox_guards_0363.py`（写 `inbox_model.py`）、JDG-0368（`_patch()` 写 `host_shield.py`）会**改写产品真树**；0364 注册为 fast ⇒ `--quick` 也可能触发。「有备份＋finally 还原」不算隔离——曾实测测试窗口期内姿态从 `guarding→warn→guarding` 假失守（`_p_poll_out.txt` 留证）。**先完成 P0-1 隔离，再解禁。**
2. **不改 `psl/manifest.json`**（除非走真实构建流程，见 P1-1）；**不清理/删除任何探针与 `.g036*.trash` 残留**（项目 AN-009 拦删除，且这些是取证件）；临时文件只建不删。
3. **不提交、不 `git add`、不把用户/前序改动归功于本任务**。
4. **改被 manifest 钉住的源码（`host_shield.py`／`_GUARDED_CHAIN_FILES`／`rules/hosts/*.json`）必须重签 manifest**：`python _tools_034/_resign_manifest.py`（D-36；否则哨兵拉不起来）。构建器对这种漂移有「自举豁免」⇒ 提交侧必须另有一道。
5. **不把历史数字当当前结果**：17/0、74/0/0、28/28、31 套/39 路径等均须按当前证据逐项复核后才能引用。

---

## 3. 已完成工作账本（按时间倒序，带证据等级）

### 3.1 P0-0 术语问号弹层「翻边仍被裁」根治（2026-10-14，本轮完成代码+判据）

- **症状**（用户真实截图）：713×600 视口、锚点 x≈252、浮层约 560px；旧 `_FLIP_JS` 只检测右越界加 `flipx` 右对齐 ⇒ 向左翻后左边缘落到视口外（负控实测左越界 `[-294,266]`）。这是逻辑错误，不是截图误会。
- **修法**（`inbox_server.py`）：
  - CSS：`.term>.tdef` 改 **fixed 视口定位**，8px 安全边距，宽 `min(560px, 100vw-16px)`，高 `100vh-16px`＋内部滚动；
  - `_FLIP_JS`：按 `summary` 与弹层真实 `getBoundingClientRect()` **clamp x/y**（不是换边）：向下空间不足试上方，仍不够夹紧＋内部滚动；toggle/resize/capture-scroll/DOMContentLoaded 全重算。
- **判据四件套**（`ci/inbox_guards_0514.py`，本轮实测全绿）：
  - 正判据 `W-09f`（CSS fixed/边距/高度滚动形状）＋ `W-09h`（Node DOM 桩**真执行产品 `_FLIP_JS`**，覆盖 713×600 中部锚点／320px 窄屏／左右极限锚点／贴底／220px 极矮视口 × 打开/resize/scroll，direct-read 实际矩形，全部落在 8px 边距内）；
  - 负控 `N-W09f`（CSS 变异回旧规则，`_Patch(SV, CSS=bad)` 让同一正判据翻红）＋ `N-W09h`（恢复旧绝对定位/flipx 行为模拟，截图同形 case 实红 `[-294,266]/vw=713`）；
  - 连带：W-09a–e 窗口落位判据仍在，0514 全套 74 绿/0 红/0 跳过；
  - 可观测：Node 输出真实 DOMRect；**Edge headless 713×600 截图确认弹层完整可见**（x=145→705，未裁）。复现页与截图：`output/f28af33c-c1e9-4508-8e11-93aa4c4be8cf/working/tooltip-repro.{html,png}`。
- **登记**：`ci/defect_types.py` 新增 **X-045**（T-11，guard W-09），`--check` exit 0。
- **★ 唯一未闭环项 [待测]**：**常驻服务（pid 30376，端口 8790）尚未按守护流程重启/刷新加载新 CSS/JS** ⇒ 运行态验收待用户在真机刷新后点「看一眼」并在左右边缘各验一次。**不可写成运行态完全验收通过。** 重启走守护重拉（见 §6.8），禁止强杀后不重拉。

### 3.2 更早批次（本日/前日已完成，均有四件套，详见各判据与记忆日志）

- **0.50.2 哨标比例根治**：`inbox_server.py` 的 `LOGO_CANVAS/CX/CY/R/RING_W + LOGO_BOX_RATIO=27/32` 反算 viewBox（现渲染 `229.926 229.926 564.148 564.148`）；真机像素实测比例 0.458→0.833（1.82 倍），连拍证仍在动。判据 U-18/U-18b＋N-U18/N-U18b（负控均独立实测见红）。登记 X-039。[会话历史实测]
- **B-13 冒泡「点开Antinel 监理」唯一决策点**：`bubble_open_route()` 三路分流（可见⇒只 focus；看不见⇒open；判不出⇒open），按钮退场/状态文字/null 守卫；行为判据＋负控变异体实测红。登记 X-042。[会话历史实测]
- **U-18c/d**：方框与定稿环形比例、涟漪波幅归一；X-042 记录 k=0.314991。[会话历史实测]
- **C4/C5（W-07/U-16）**：`open_console_settled()` 修一次性调用方落位随进程死；`font-size:0` 藏字保徽章；量具纪律四条（chrome() 选层／行边界取函数体／docstring 复述不当代码／假件延迟出现）。[会话历史实测]
- **0490 负控改造**：`N-U10`/`N-U13` 从「死字符串锚点」改为**行为变异**（换 `_bar`/`_logo_mark` 产出），正判据加 `mod=SV` 参数；0490 41 绿/0 红。[会话历史实测]
- **UI 交互修复一批**（冒泡 ack kind 键位、确认不自动关、分组钻取 ids、空态文案、点开已读需服务端成功、winfit OverflowError 如实回包、logo root 参数、动作落盘失败可见）。[会话历史实测]
- **`docs/监理UI缺陷清单与修复计划（0.50.1）.md`**：A1–A4 失效按钮＋B1–B6 语句违和的取证与修复计划（只读取证、零产品改动）。
- **主闸门 28/28 全绿**；`delivery_gate` 已登记 `("0514","ci/inbox_guards_0514.py","fast")`。**注意：登记 0514 为 fast ⇒ 全量/quick 解禁前必须连同 0364/0363/JDG-0368 一起隔离评估。**

---

## 4. 待办任务卡（按优先级；每卡含四件套验收要求）

### P0-0（收尾）：tooltip 运行态复核 —— 唯一接近完成的卡

1. 按守护流程让常驻服务加载新页面（§6.8 守护重拉；或用户手动刷新已重启的实例）。
2. 真机点「看一眼」问号：中部、左边缘、右边缘各一次；窄窗口（<620px）一次。
3. 若仍越界：记录 clientWidth/Height、scroll/zoom、浮层 DOMRect，回填 W-09h 用例；**禁止回退成单纯 flip-left/right**。
4. 通过后销 X-045 运行态待测项；截图留证到 `output/.../working/`。

**本轮进展（2026-10-14 16:34–16:50，[本轮实测]）**：
- 守护重拉完成：旧服务 pid 32100（10:06 起，跑旧页面）已被杀，守护进程 2.4 秒内按**原端口/口令**重拉为新服务 pid **16916**（16:45:40 起）。新页面 direct-read 确认新标记全部在位（`position:fixed`、`top:8px;left:8px`、`min(560px, …)`、`_FLIP_JS` clamp）。留证 `output/p00_runtime_reload.txt`、`output/p00_newpage.html`。
- 守护进程本身也换了当前代码：旧 daemon 登记于 08:24（早于当日修复），已按单例流程换代（杀旧起新）；换代后 supervise 链路**实测走通一次**（27240 死 ⇒ 自动重拉 16916），tick 活性由 `notify_state.json`/`tray.json` 实时 mtime 证实。
- 运行态留证截图（Edge headless，服务真实渲染的 CSS/JS，词条注入 `open`）：713×600 中部/左缘/右缘锚点 ＋ 600×800 窄窗，四张全部完整落在视口内（含 8px 边距），存 `output/p00_tooltip_runtime/`。
- Antinel 监理独立窗口已为用户拉起（720×640 @(2240,1264)，app 模式；`inbox window` 报"已就位"）。
- **仍 [待测]**：用户真机三点复核（中部/左缘/右缘/窄窗）未做 ⇒ X-045 运行态待测项**未销**。不得写成运行态完全验收通过。

### P0-1：隔离所有写真树的测试套件（解禁全量闸门的前置）

范围（已只读核验）：0364 的 B4/C2/C3/D2/F5N 写入目标（`inbox_model.py`、`psl/manifest.json`、`host_shield.py`、hook/规则登记表、`inbox_window.py`）；0363 写 `inbox_model.py`；JDG-0368 `_patch()` 写 `host_shield.py`。`ci/_pkg_sandbox.py` 存在但**无调用方**，且其隔离能力**不覆盖** 0364 的直接写路径——单纯 import helper 不够，要逐路径覆盖。

- 正判据：逐路径清单，全部变异落沙盒副本；并行 direct-read 真实 ROOT 无 warn/漂移/内容变化。
- 反向对照：安全替身上拦截一次「企图写 ROOT」，同一正判据红；**不得向真树注入缺陷造红**。
- 连带：测试前后逐路径比较真实文件；S70 等直接读真树的检查不被沙盒假数据误导。
- 可观测：沙盒报告目标/隔离路径/拦截次数/最近拦截；退出后再 direct-read 真树确认不变。

### P0-2：判据 ID 唯一化与登记闭环

已知冲突（本轮只读核验）：S70 在 0431（研发态落差）与 0440（赋值/只读命令）重名；S71 在 0440、S73 在 0450 已占用；`gate_ids_from_registry()` 把 ID 收进 `set()` ⇒ 重名折叠、无法定位所属套件。新增隔离判据前先做 suite-qualified / 全局唯一 ID 方案，并给「重名折叠」本身加行为判据；**不要臆测下一个号码**。新实例登记后跑 `defect_types.py --check` 对账（当前基线：45 实例）。

**本轮完成（2026-10-14，[本轮实测]）**：
- 新口径落地 `ci/defect_types.py`：`gate_id_map()`（**AST 只数真声明**——`@check` 装饰器全 token ＋ D/G 注册元组；注释/docstring 提及不算，顺带修掉"文本正则把 U-17/W-09 当存在"）＋ `duplicate_gate_ids()`（跨套件重名检测；套件内正/负控共号不算）＋ `check_consistency()` 新增重名问题类（红，不降级成提示）。旧 `gate_ids_from_registry()` **原样保留**（连带：47 条引用不变红）。
- 权威重名清单（AST 口径）**25 组**（比摘要说的 3 组多：G1/G2、M1/M2/M4、S1/S1b/S1c/S2/S3/S4、S19、S20、S47、S48 及各负控；P12–P15/R01–R10/L0–L2 等经精确口径核实**并非**跨套件重名，是摘要过宽匹配的误报）。
- 解名规则（确定性，不臆测号码）：编号套件按批次号、无编号套件按文件名主干排序，**最早**声明者保留裸 ID，后声明者改 `ID-<批次>`（负控同步）。改名 75 处 / 8 文件；改名后 `duplicate_gate_ids() = []`；8 个改名套件复跑全绿（12/0、21/0、33/0、8/0、8/0、10/0、9/0、5/0）。
- 四件套在新套件 `ci/inbox_guards_0515.py`：UID15-a（映射结构＋引用无孤儿）/ UID15-b（真树 direct-read 重名为 0）/ N-UID15-a（合成重名必报到＋**折叠假绿实证**：0431 的 S70 删光后 set 口径仍全绿、映射口径可判归属）。已登记 `("0515", …, "fast")`。
- 登记簿对账：实例 **47** 条（+X-046 归 T-03、+X-047 归 T-11），`--check` **exit 0**，类型 11（已守 10／盲区 1）。

### P0-3：`antinel.cmd` CRLF（产品一键入口在本机从未跑通）

byte 级实测（会话历史）：CRLF=0、裸 LF=36 ⇒ `cmd.exe` 按字节错位切行，把中文注释残片当命令执行。修法＝归一化 CRLF（同目录 `tools/*.ps1` 均为 CRLF 可对照）＋ 新增判据（现无任何判据跑过这个 .cmd）。
四件套：正＝字节级 CRLF 且解释器不执行注释残片；反＝安全 fixture 注入 LF 同判据红；连带＝检查脚本命令/注释行尾不误伤；观测＝记录字节计数与解释器行为。

**本轮完成（2026-10-14，[本轮实测]）—— 修法比原计划多一层，原计划单独不足**：
- 实证（探针一～四）：CRLF=0 确有一个根因；但**只归一化 CRLF 不够** —— cmd.exe 按控制台 OEM 代码页读 .cmd，中文 Windows 默认 CP936，UTF-8 中文注释**即使 CRLF 也**被错位解读成命令执行（`CREATE_NEW_CONSOLE` 复现"Explorer 双击"场景：zh-comments+CRLF@CP936 ⇒ 误执行；同内容@CP437 ⇒ 干净）。`chcp 65001`（install.py 垫片先例）在本文件上**反而更坏**（探针二 A/B 象限实测）。
- 修法：`antinel.cmd` 归一化 CRLF（43 CRLF / 0 裸 LF / 2046 字节）＋ **全 ASCII**（机器无关唯一安全形态）；中文 rationale 移入 `ci/inbox_guards_0515.py` docstring 与 `inbox_cli.py`；命令四行逐字未动。
- 四件套（0515 套件，8 绿/0 红/0 跳过）：CMD15-a 字节级正判据；CMD15-b 新控制台真跑 fixture（零误执行＋echo 标记在）；N-CMD15-a 裸 LF 变体同尺判红（实测红）；N-CMD15-b 中文注释 fixture 误执行信号必现（实测红）；CMD15-c 连带（命令逐字在/仓内 .cmd 全 CRLF/install.py 垫片仍写 CRLF/SPDX 头在）。
- **顺带证伪本卡一条前提**：「同目录 `tools/*.ps1` 均为 CRLF 可对照」不成立——实测 `tools/logo.ps1`（268 裸 LF）、`tools/mk_sound.py`（65 裸 LF）均 0 CRLF（`.gitattributes` 为 `* -text`，从不转换）。该对照不存在，已按事实修订。
- 登记 X-047（T-11）。注：真文件**未真跑**（会起 daemon/开窗）——跑的是从真文件提取的注释块 fixture；真入口的点火留待用户双击/P3 真机项。

### P1-1：版本事实与交付数据分层

`workspace_facts.json` 的 release/artifacts/target_version/wheel 仍登记 0.48.4；`dist/` 仅有 0.48.4 产物；`published_version=0.35.1` 是 PyPI 实查字段不许猜改。规则：**只有真实构建 0.50.3 产件并验收 metadata 后**才同步事实字段；反对照在安全 fixture 让事实字段与产物 metadata 不一致 ⇒ D-23 红连带；不得删旧产物制造整洁。

**本轮完成（2026-10-14，[本轮实测]）—— 前置条件达成后同步，published_version 未动**：
- 真实构建 0.50.3 两产件 ＋ `verify_release.py` [A]布局/[B]wheel 自洽/[C]twine/[E]清单对账/[D]端到端安装**全绿**（日志留 `output/p12_verify_release.log`）。
- `psl/workspace_facts.json` 四字段同步：release.version、release.artifacts、pypi.target_version、pypi.wheel → 0.50.3；`_measured_at` → 2026-10-14；新增 `_note_0503` 留痕（含为什么 0.48.4→0.50.3 是 minor）。**published_version=0.35.1 一字未动**（PyPI 事实位，只能实查改写，0.50.3 尚未上传）。
- `j_workspace_facts()` 单点复跑（不跑整道闸门——全量禁令仍生效）→ `(True, 「环境事实与真源一致：2 个仓 / 站点构建器 / 本版 0.50.3 / dist 只有 2 件 / 发布版 0.35.1」)`。
- 反对照（`_p_p11_negctl.py`，[本轮实测]）：臂② 夹具自证全绿；臂① 同一夹具只把 release.version 改成 0.48.4 ⇒ D-23 **红且点名**「release.version 声明 0.48.4、pyproject 实测 0.50.3」。dist 里旧 0.50.3 两件（内嵌 0.48.4 陈旧清单）**零删除归档**至 `_archive_dist/p12_presync_20261014-191532/`。

### P1-2：打包缺件

`inbox_bubble.py`、`inbox_logo.py` 未登记进 `pyproject`/`build_package.py` 包根模块清单；`assets/sounds/alert.wav` 需同步 package-data glob。四件套：正＝清单齐全且真实构建后 wheel/sdist 内确有对应路径；反＝安全 fixture 移除一条 ⇒ 验收失败；连带＝排查其他包根模块与资源加载路径；观测＝留存产物路径/清单/metadata。

**本轮完成（2026-10-14，[本轮实测]）—— 缺口比卡片大两件，根因比卡片深一层**：
- **实测差集 5 件（非卡片三件）**：`inbox_bubble.py`、`inbox_logo.py`、`assets/sounds/alert.wav` ＋ `tools/logo.ps1`、`tools/mk_sound.py` —— **正是全部未跟踪新件**（`git status` 实证五件均 `??`）；旧清单 0.48.4/124 项＝跟踪件全集。四处登记全部到位：pyproject `py-modules`＋`package-data assets`（+`sounds/*.wav`）、`build()` root_mod 复制清单、`_LAYOUT`/`_TOOL_FALLBACK`（+logo.ps1）。
- **根因修正（按事实改写，F58）**：本轮进行中曾诊断「mk_sound.py 因 `_LAYOUT` 漏登记而不在装配包内」—— 那只是症状。实测真根因是**清单口径**：sanctioned 流程 `--out D:/psl/poc`（release.py 默认值）使 final＝**仓根本身**，清单由 `_wheel_payload(final, final/MANIFEST.in)` 生成，天然覆盖 wheel 载荷；工作区变体用了**新建的** out 目录 ⇒ 装配时 final 不存在 ⇒ 构建器写不进 final/MANIFEST.in ⇒ 清单生成退化成「暂存包内容」fallback（那条带 `!!` 警告的分支）⇒ 实测 128 项**双向错配**：混入 14 个只进 sdist 的件（README/LICENSE/docs/references/.github/ci…）、漏掉 15 个真进 wheel 的件（tools/host_matrix.py、scripts/run_harness.py…）—— **同步那份 128 项清单，[E] 会从 5 未覆盖恶化成 15 未覆盖**。修法：以仓根工作树完整副本种子化 `out/antinel-security` 再装配（stage 在工作区外被 AN-010 拦，此为 sanctioned 形态的等效复现）⇒ 新清单 **129 项**与 wheel 载荷 131 项减 2 项按设计排除**严格集合相等**（双向空差集）。
- **连带修**：仓根 `psl/SKILL.md` 与根 `SKILL.md` 分家（根件手改后未再构建）⇒ 清单哈希算于 merge **之前**的旧件、插件/wheel 用的是合并后新件 ⇒ 插件自检当场 `drifted ['psl/SKILL.md']`。按 merge 的既定语义预同步两件再重装 ⇒ 插件自检「清单 129 项哈希全中 + 3 个 psl 产物在位 + 无多出文件」。
- **四件套**（`ci/inbox_guards_0516.py`，5 绿/0 红/0 跳过，两个负控均实测判红）：PKG16-a 正判据（真实 wheel 131 成员/sdist 184 成员含焦点五件＋四处登记在位＋产品 [E] 集合相等）；N-PKG16-a 反向对照（安全夹具移除 py-modules 一条声明、真构建出 wheel ⇒ **同一把尺子**判红且归因纯——其余四件仍在）；N-PKG16-b 反向对照（真 wheel 副本的清单少一条 mk_sound.py ⇒ 产品 [E] 判红并点名）；PKG16-b 连带（30 个 py-modules 全在 wheel；`inbox_bubble.sound_path()`→assets/sounds/alert.wav、`inbox_logo.script_path()`→tools/logo.ps1 运行时资源路径可解析；判据 ID 无重名）；PKG16-c 观测（验收日志 [A][B][C][E][D] 五标头留存、产物大小/哈希与清单版本/条目数入册）。
- 登记 **X-048**（T-09 同一事实两套口径），实例总数 47→48；`duplicate_gate_ids()=[]`。发布验收 **[A][B][C][E][D] 全部通过**（[E]：清单 129 项 == wheel 载荷 131 项 − 按设计排除 2 项）。

### P2-1：UI 缺陷计划逐项复验（A1–A4、B1–B6）

背景、取证与建议四件套都在 `docs/监理UI缺陷清单与修复计划（0.50.1）.md`，逐卡验收要求见 `stage1/final_draft.md` §6 P2-1 表。要点：B4（finder 口径）已改 `_mark_at_tail_any` 且有历史复验，但**不因摘要「已修」销项**，需真机复验；A2、B6 必须真机条件。

### P2-2：探针/残留只读盘点

根目录 `_p_*` 探针一批＋`host_shield.py.g0364.trash`、`inbox_model.py.g0363/.g0364.trash`、`inbox_window.py.g0364.trash` 残留（本轮确认存在）。**只盘点（磁盘/Git 跟踪/引用关系/证据依赖），不删除、不自动回灌 trash**。旧摘要提到 `rules/hosts/autoclaw.json.g0364.trash` 未找到，保持待复核。

### P3：全链路恢复与签退

仅在 P0 全部过四件套后：单套正/负/连带 → `defect_types --check` → 主闸门 → delivery gate 慢/快道 → 真机 UI → 打包验收 → 更新 facts。每阶段记录原始命令、时间、退出码、分子/分母、SKIP 清单、产物路径；**SKIP 不并入通过数**。

---

## 5. 九维机制落地约束（本任务语境的逐条对应）

| 维 | 在本任务的落点 |
|---|---|
| 元机制 | 先结构化识别目标/权限再问授权；不因测试名含 sandbox/guard 就认定安全，按**实际写入路径**分类 |
| 一 入口唯一 | 冒泡点击按可见状态走 `bubble_open_route()` 唯一分支；测试闸门同样唯一登记（P0-2） |
| 二 撤销即红 | 每个修复保留负控真实红样本（范式：`_Patch(SV, CSS=bad)` 让正判据跑变异体） |
| 三 行为判据 | 断言用户可观察行为：Antinel 监理看真实窗口状态、弹层看 DOMRect、包验收读归档内容 |
| 四 连带对照 | 改路由/沙盒/姿态时检查既有注册表、never-exempt、删除保护、空值路径，防静默风险迁移 |
| 五 自报活跃 | guard/沙盒报 active/次数/最近生效，不许只在通过时沉默 |
| 六 运行态确认 | **源码修复 ≠ 运行中的Antinel 监理已加载**；daemon/tray 重启后复核（P0-0 现状即此） |
| 七 量具先自检 | 负控自身故障报「负控失效」；正判据导入产品真源（import，不复制逻辑） |
| 八 数据版本迁移 | 未知版本不静默按空处理；研发态差值用于识别，不得刷平 manifest |
| 九 同锚 | 文档/代码/运行结果同日期同版本；数字机器核验，精确分子/分母 |

---

## 6. 工具与环境避坑手册（前序实测踩过，别再踩）

1. **Write/Edit 必须用 Windows 风格绝对路径**（`D:\psl\poc\antinel-security\...`）。POSIX 风格 `/d/...` 会被 Antinel AN-010 拦（白名单前缀 `d:/psl/poc/antinel-security/`），重试无效。
2. **删除被 AN-009 拦**：临时文件只建不删。
3. **新建文件必须带 SPDX 头**（0481 L1 扫全工作区含 `.workbuddy-ai/` 与 `_p_*.py`）：`.py` ⇒ `# SPDX-License-Identifier: Apache-2.0`（前 6 行内）；`.md` ⇒ `<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->`。本文件已带头。
4. **Bash heredoc 会把 `\n` 变 `/n`** ⇒ 探针/脚本一律用 Write 落文件再跑（`_p_*.py`，已被 gitignore，勿提交）。
5. **解释器一律用托管版**：`C:/Users/大马/.workbuddy-ai/binaries/python/versions/3.13.12/python.exe`；Node：`C:/Users/大马/.workbuddy-ai/binaries/node/versions/22.22.2-6/node.exe`（本机无 playwright/puppeteer）。
6. **真浏览器截图**：`"/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" --headless --disable-gpu --hide-scrollbars --window-size=W,H --screenshot=<png> "file:///<html>"`。本机无 PIL ⇒ 截屏工具走纯 ctypes GDI（`_p_shot.py`）。
7. **Node DOM 桩范式**：判据要在「无浏览器」下验 JS 行为，用 `_tooltip_bounds_probe(script, layout)`（0514 内）：Node `-e` 真 DOM 桩执行产品 `_FLIP_JS`，回读矩形。**夹具必须自证成立**；无 node ⇒ 报 Skip 不报 PASS。
8. **服务换代走守护重拉，不手工重启**：杀服务 pid ⇒ daemon **6 秒内**按原端口/口令重拉（token 沿用）。先 HTTP 探测 `127.0.0.1:8790` 确认旧实例，杀后复查新页面标记。当前 daemon pid 30376。
9. **窗口存活机制**：`open_console`/`open_bubble_window` Popen 的 Edge 是发起进程子进程，**沙箱命令结束 ⇒ job 回收 ⇒ 窗口连带消失**（DETACHED_PROCESS 救不了，不脱离 job）。演示/保活须放进 `run_in_background` 任务（sleep 长驻）。
10. **沙箱限制**：`rm` 拦；PowerShell `Add-Type`/`[Reflection.Assembly]::Load*` 拦；`Get-CimInstance` 报错；`wmic` 无输出 ⇒ Win32 信息用 ctypes。
11. **Windows 目录同异不用字符串比**（%TEMP% 8.3 短名 vs git 长名），用 `os.path.samefile`。
12. **判据扫 CSS 走 `page_caliber.chrome()`**（现剥 CSS 注释）；扫正文显式选层；数调用点用 AST；取函数体用行边界/AST（`_func_seg_of`），同前缀函数（`open_console`/`open_console_settled`）文本 split 会落错。
13. **负控改造范式**：源码形状变了导致旧字符串锚点失效时，改成**行为变异**＋正判据加 `mod=SV` 参数，让负控拿变异模块跑同一条正判据（0490 已示范）。
14. **`git add _tools_034/_resign_manifest.py` 类「ignored 但已跟踪」文件会 rc=1 但改动已进暂存区**，别被 rc 骗。
15. Defender 排除疑似失效 ⇒ 裸 python 启动 1.3–1.6s，跨轮次比耗时先看环境。

---

## 7. 接手 AI 第一轮操作清单

1. 只读复核 `git status`/HEAD，对照 §1 快照；有出入先停下查清，不 reset/覆盖。
2. 只读通读：`ci/inbox_guards_0514.py`（含 `_tooltip_bounds_probe`/`_Patch` 范式）、`ci/inbox_guards_0364.py` 写入点、`ci/_pkg_sandbox.py`、`ci/defect_types.py`、`ci/delivery_gate.py` SUITES、`docs/监理UI缺陷清单与修复计划（0.50.1）.md`。
3. 先做 **P0-0 收尾**（守护重拉＋真机三点复核 tooltip），这是唯一接近完成的卡。
4. 做 **P0-1 隔离**；完成并过四件套前，**全量闸门/quick/selfcheck 保持禁令**。
5. P0-2 ID 唯一化 → P0-3 antinel.cmd CRLF → P1 打包/版本 → P2 UI 逐项 → P3 全链路。
6. 每完成一项：登记簿对账（当前基线 45 实例）＋ 记忆日志追加 ＋ 本文件对应卡打勾/更新证据等级。

---

## 8. 验收签退表（成文时点）

| 验收项 | 状态 |
|---|---|
| tooltip 代码+判据四件套（W-09f/N-W09f/W-09h/N-W09h，X-045） | ✅ 本轮实测绿；**运行态服务已换代加载（pid 16916），四锚点头态截图留证；真机三点复核仍 [待测]** |
| 0514 套件全量 | ✅ 74 绿/0 红/0 跳过（本轮实测） |
| 0515 套件全量（P0-2+P0-3 四件套） | ✅ 8 绿/0 红/0 跳过（本轮实测，负控均实测红） |
| 判据 ID 跨套件重名 | ✅ 25 组已解（改名 75 处/8 文件），`duplicate_gate_ids()=[]`；改名套件复跑全绿；0516 新增五条后复测仍为 `[]` |
| 登记簿一致性 | ✅ `--check` exit 0，**49 实例**（本轮实测；X-046/X-047/X-048/X-049 新登） |
| 主闸门 regression_gate | 28/28（会话历史实测，非本轮复跑）；本轮仅单点复跑 `j_workspace_facts` → (True, …) |
| 全量交付闸门 | 🚫 **被安全阻断 [SKIP]**，直至 P0-1 隔离完成 |
| 0516 套件全量（P1-2 四件套） | ✅ 5 绿/0 红/0 跳过（本轮实测；两个负控均实测判红：声明移除⇒同尺红、清单少一条⇒产品 [E] 红） |
| 0517 套件全量（窗口寿命四件套，X-049） | ✅ 6 绿/0 红/1 跳过（本轮实测；两个负控均实测判红：跳过委托的变体同尺红、daemon 不开窗必须 opened=none 且 why 非空） |
| 版本事实同步（P1-1） | ✅ 四字段→0.50.3（release.version/artifacts、pypi.target_version/wheel）；**published_version=0.35.1 未动**；反对照实测：版本失配 ⇒ D-23 红且点名 |
| 打包缺件（bubble/logo/sounds＋两个 tools 脚本） | ✅ **[A][B][C][E][D] 发布验收全部通过**（本轮实测）：[E] 清单 129 项 == wheel 载荷 131 项 − 按设计排除 2 项；wheel 1,531,838 B / sdist 1,696,105 B；根因＝fallback 清单口径＋部分种子（详见 P1-2 卡），非 `_LAYOUT` 漏登记一件 |
| antinel.cmd CRLF | ✅ 已修（CRLF＋全 ASCII，判据四件套在 0515） |
| 版本事实分层 | ✅ 已同步（P1-1）：四字段→0.50.3、published_version=0.35.1 未动、`_note_0503` 留痕；研发态版本差值按 0431 纪律保留，不刷平 |
| UI 计划 A1–A4/B1–B6 | ❌ 待逐项复验（P2-1），B4 需真机销项 |
| 探针/trash 盘点 | ❌ 只读盘点待做（P2-2），禁止删除 |
| **机制层六项落地（2026-10-15 追加）** A1 五判据前置门／A2 常驻上限 29＋退休簿／A3 判据看守期制／A4 L2 品质触发层／A5 双一等指标看板／A6 重叠审计 | ✅ **六项全部落地并过负控**（本轮实测）：A1+A2 负控 10/10、A3 负控 7/7 全绿；常驻 29/29 未误伤；**未新增判据套件**（A4/A5 按古德哈特防线设计不进 SUITES）；A6 结论＝无零风险合并候选，只提案。详见《机制层落地与全系统扫描报告 v1.0》 |
| **全系统三清单扫描（追加）** | ✅ B1 机制缺口 13 项（6 已修／3 待判定／4 记账）；B2 问题扫描 9 项（**实跑 24 套：22 绿／2 红**＝0431 S70、0481 L1；未跑 10 套含 0360/0366 写真树与 0363/0364/JDG-0368 禁令）；B3 品质扫描 4 项全绿（UX 文案零违和、编号全连续、14 新件 SPDX 头齐） |
| **按清单修复（双条件门）（追加）** | ✅ 仅 **C-1** 一项过双条件门并修：8 个 `_p_*` 探针遗留补 SPDX 头，0481 L1 违规 **140→132**；余 132 处全在 `out/`(76)＋`output/`(56) 暂存/日志区，其中 47 处系 override 匹配口径误判 ⇒ 进 J2 不冒充已修。其余一律进判定文档 |
| **创始人判定事项（追加）** | ❌ **J1–J9 共 9 项默认不动**（0431 S70 版本落差／0481 扫描口径／manifest 4 件重签／0360-0366 禁令扩容／控制台实例／PyPI 0.50.3 推送／P0-0 真机复核／A6 合并提案／inbox_server.py:155 陈旧注释）。见《创始人判定事项 v1.0》，每项带事实-选项-建议-默认动作 |
| **运行态更正（2026-10-15 04:57 追加）** | ⚠️ **本表首行所载「运行态服务已换代加载（pid 16916）」仅为 2026-10-14 时点真值**：04:57 复测 8790/14305 **均无 LISTENING 行**、Antinel 监理窗口已不在窗口枚举、python 进程仅 pid 1184（`host_shield.py sentinel`）在跑且 `.psl` 侧秒级活跃 ⇒ 当前为「**哨兵在、控制台零实例**」。真机三点复核随之无法取证，进 J7 |
| **闭环纪律（追加）** | ✅ 全程零 rm、零 commit、零 git add、零 reset；全量/`--quick`/`--selfcheck` 闸门禁令遵守（只跑单套件/局部形态）；值守台 daemon 与窗口仅只读观测，未杀未启未搬移 |
| **窗口「起得来、活不久」**（用户 2026-10-14 两次实测） | ✅ **本轮根治（X-049）**：`inbox window` 报「已就位」后窗口秒死。同机**四路实证**：CLI Popen 裸 flags／Popen+DETACHED+NEW_GROUP／cmd start ⇒ 跨调用边界全死；**daemon（长命 supervise 进程）Popen ⇒ 跨边界存活** ⇒ 病根是「**谁来起**」不是「怎么起」。修法＝`cmd_window` 先走 `open_console_via_daemon`（推托盘 open 动作，daemon 2s tick 消费开窗），失败**如实降级**直起；0517 四件套 6 绿/0 红/1 跳过（W17-d SKIP 语义＝关窗不停服务是设计语义，非故障）。连带记账未修：daemon 自听 14305 起第二服务实例（服务多开，独立缺陷） |

**交接判语**：当前首要目标不是尽快跑绿，而是防止「判据验证」变成「产品真树变异」。真树写入路径全部隔离前，闸门全量结果必须保持未验证；tooltip 修复在常驻服务加载并经用户复核前，不得记运行态 PASS；所有数字引用前先按当前证据复核。
