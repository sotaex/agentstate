<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel·0.53.2 夜间任务书 v1.1（2026-10-19）

> 性质：**可交接的执行文件**。写给"第一次接手本仓的 AI"或"睡醒前的我自己"。
> 目标：把 0.53.1 遗留的缺陷按优先级做完、出包 0.53.2、提交。
> 纪律：本文件每一句"现状"都可用给出的命令复算；**凡未复算的，不许当成事实引用**。
>
> **v1.0 → v1.1 变更摘要**（创始人 2026-10-19 19:39 交办）：
> ① **纠正一处事实**：标准五态动态是 **5 个 MP4**，不是 SVG；且产品副本与定稿源
>    **逐字节一致**（§2.3 附哈希）。v1.0 只写"姿态灯/品牌标"，没把"五态动态本身"
>    纳入一致性范围 —— 这是 v1.0 最大的遗漏。
> ② **新增 T5（P0）：五态一致性判据**（媒体字节／模式键闭包／五态不塌缩／姿态灯来源）。
> ③ **T1/T2 精确到行**：回落点是 `tools/logo.ps1:381`；条件写入是
>    `inbox_tray.py:212-214`；`modes[st]` 缺键的静默 fallback 是 `logo.ps1:379-380`。
> ④ **新增 §10 本版自查**：v1.0 的 11 处遗漏/漂移/扣分点，逐条已改。
> ⑤ 新增 §6.1 人工验收清单（哪些**不许**假装有判据）。
> ⑥ 明确"闸门判据（ci/）"与"harness 断言（psl/judgment.json）"是**两套体系**，
>    交付标准分别写。
>
> v1.0 已按本仓文档纪律退役为
> `Antinel·0.53.2 夜间任务书 v1.0（2026-10-19）.md.away-20261019194350`（零删除）。

---

## 0. 三十秒读完

Antinel 是"AI 编程工具的监理"：本地常驻服务 ＋ 托盘 ＋ 五页面板 ＋ 最小化后的
**漂浮哨标**。0.53.1 已出包、已提交、闸门 34/34 绿。

**标准五态动态的样子只有一份权威来源**（5 个 MP4，见 §2.3）。页面与哨标都不"播放
mp4"，而是用**代码重建同一套动效**（页面：内联 SVG ＋ rAF；哨标：PowerShell 帧数学）。
所以"一致性"必须分三层守：

| 层 | 是什么 | 现状 | 谁守 |
|---|---|---|---|
| 媒体层 | `assets/logo/{L0,L1,L2,Ls,R0}.mp4` | **与定稿逐字节一致** | T5-a（新增） |
| 代码重建层 | `LOGO_MOTION_RENDER`（页面）／`logo_motion_spec()["modes"]`（哨标） | 五态齐全，`Ls→LD`、`dev→L0` | T5-b/T5-d（新增） |
| 图标层 | `assets/logo/antinel.ico`（品牌）／`assets/icons/*.ico`（姿态灯） | 品牌 ico 由 `logo.svg` 生成；姿态灯给托盘 | T1 / T5-c |

**要做的五件事，按顺序**：

| 编号 | 一句话 | 优先级 | 预估 |
|---|---|---|---|
| T1 | 哨标回落时画**品牌 LOGO**（`antinel.ico`），不许画姿态灯；回落必须留痕 | P0 | 3–4h |
| T2 | `tray.json` 的 `logo` 块改**必写**、拿不到规格要留痕；`modes[st]` 缺键也要留痕 | P0 | 2–3h |
| T5 | **五态一致性判据**（媒体字节／键闭包／五态不塌缩／姿态灯来源） | P0 | 2–3h |
| T3 | 长驻进程版本自检（治"改了没效果"） | P1 | 3–4h |
| T4 | 高 DPI（`tools/logo.ps1` 里 `DPI` 零命中） | P1 | 4–6h |

（T3/T4 编号沿用 v1.0，未变；新增的第五件事用 T5，避免与已发出的 v1.0 对不上。）

T1/T2/T5 是同一个病的三条腿（**用状态灯冒充品牌标 / 静默降级**），必须同批做完。
T3 不修，则以后每次验证都可能被旧进程骗。T4 是唯一"用户可见的不精致"，但它需要
真机肉眼验收，**不许假装有判据**。

---

## 1. 环境与入口（照抄即可）

### 1.1 路径

| 项 | 值 |
|---|---|
| 仓根（＝研发树 ＝产品目录） | `D:\psl\poc\antinel-security` |
| 出包产物 | `<仓根>\dist`（只许两件：whl ＋ tar.gz） |
| 临时目录（**必须**在仓外） | `D:\_antmp` |
| 运行时状态 | `C:\Users\大马\.antinel\console\`（`tray.json`、`url.json`） |
| 审计链 | `<仓根>\.psl\audit\YYYY-MM-DD.jsonl` |
| 闸门结果 | `<仓根>\.psl\gate\last_run.json` |
| 判断记录（harness） | `<仓根>\psl\judgment.json` |
| 打包清单 | `<仓根>\psl\manifest.json`（研发树惯例 `version = 0.50.5`） |
| **五态动态定稿源** | `D:\2026\PSL\antinel-logo-final_assets\R4_*.mp4`（**不在仓内**，仅在研发机） |
| 品牌 LOGO 矢量源 | `<仓根>\assets\logo\logo.svg`（64×64，R4 定稿重绘） |
| 历史文档 | `<仓根>\docs\`（入库；退役改名 `.away-<时间戳>`，**零删除**） |

### 1.2 解释器与固定前缀（**每条命令都要带**）

```
PYTHONPATH= TMP=D:/_antmp TEMP=D:/_antmp TMPDIR=D:/_antmp \
"C:/Users/大马/.workbuddy/binaries/python/versions/3.13.12/python.exe" -E -X utf8 <脚本>
```

原因：`PYTHONPATH=` 防外部污染；三个 TMP 指向仓外（否则 `workspace_roots` 判据假红，
实测过）；`-E -X utf8` 防环境与编码干扰。**不要用**裸 `python`（本机是商店占位别名，
静默返回 0）。

### 1.3 服务怎么起（沙箱里拉起必死）

```powershell
Start-Process explorer.exe -ArgumentList '"C:\Users\大马\Desktop\Antinel 监理.lnk"'
```

- 只有这一种能存活（交给已在跑的 explorer 去 ShellExecute）。直接
  `Start-Process <lnk>` 或 `explorer <lnk>` 都会随调用结束一起没。
- **让服务换新代码**：杀掉 `antinel.py inbox serve` **与** `antinel.py inbox daemon
  --supervise` 两个进程，再跑上面那行（daemon 会重新拉起 serve）。
  ⚠️ 只杀 serve 不够：**daemon 负责写 `tray.json`**，它不重启就继续用旧代码写状态
  （0.53.1 交付后"哨标不动"的真正原因，见 §2.2-3）。
- 查进程：

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*python*" -and $_.CommandLine -like "*inbox*" } | ForEach-Object { "pid=" + $_.ProcessId + " :: " + ($_.CommandLine -replace '\s+',' ') }
```

### 1.4 活体回读（改完必须做，否则等于没改）

- URL 与口令**只认** `C:\Users\大马\.antinel\console\url.json`。
  ⚠️ 重启后端口会漂移（实测 8790 → 35089）；仓内 `console\url.json` 是旧缓存，
  拿它回读一律 403。
- 页面首字节下发 httpOnly cookie `antinel_t`；`/assets/*` 必须带它，裸 curl 403。
- 现成模板：`output\_fav_probe.py`（取页面 → 取资源 → 比对字节）。
- ⚠️ **探针必须写成文件再执行**：命令行里出现 `cookies` 字样会被产品自己的
  SEC-05 规则误拦（它按**字面量**匹配，包括变量名与注释）。

---

## 2. 现状快照（0.53.1 收尾时的事实，可复算）

### 2.1 已完成

- 版本 `0.53.1`，九处承载件一致（`ci/version_check.py` PASS）。
- 出包 `antinel-0.53.1-py3-none-any.whl` ＋ `.tar.gz`；验收 A/B/C/D/E 全过
  （随包清单 132 项 == wheel 载荷 134 项 − 按设计排除 2 项）。
- 全量闸门 **34/34 绿**；harness **315/315 PASS**；SKILL.md 自证卡
  `21/21 digests match this build`。
- 提交：`dddfa4a`（0.53.1 主体）、`324eb65`（发布收尾自动化）、
  `b275cb4`（本任务书 v1.0）。

### 2.2 未解决

1. **哨标回落到姿态灯**。实证：`tray.json` 缺 `logo` 块时，`tools/logo.ps1:381`
   走 `Load-Icon (Resolve-IconPath $st $sh)`，画 `assets/icons/<state>.ico`。
   创始人 2026-10-19 截图是**土黄色粗环＋实心点**＝L1 姿态灯（`--l1:#8a6100`），
   原话："现在缩小后变成这个了，还不对，不是动态LOGO---代表当前的某个态"。
2. **`logo` 块是条件写入**（`inbox_tray.py:212-214`）：
   ```python
   spec = _logo_spec_block()
   if spec:
       payload["logo"] = spec
   ```
   拿不到规格就静默不写，下游无法区分"旧版没写"与"新版拿不到"。
3. **长驻进程旧代码**：`inbox daemon --supervise` 从早上就在跑；重启 serve 不够。
   杀掉 daemon 重拉后，`tray.json` 立刻出现完整 `logo` 块 —— 已验证。
4. **`modes[st]` 缺键时静默 fallback**（`tools/logo.ps1:379-380`）：
   ```powershell
   $key = [string]$script:spec.modes[$st]
   if ([string]::IsNullOrWhiteSpace($key)) { $key = "L0" }
   ```
   会静默画 L0 动效 —— 方向安全（仍是品牌动效），但没有痕迹。
5. **高 DPI 未处理**：`grep -c DPI tools/logo.ps1` = 0。

### 2.3 五态动态的权威来源与一致性（**v1.1 新增，最重要的事实**）

标准五态动态是 **5 个 MP4**（不是 SVG；`D:\2026\PSL` 下 36 个 SVG 里没有任何
五态动态文件）：

```
D:\2026\PSL\antinel-logo-final_assets\R4_L0_值守.mp4
                                      \R4_L1_注意.mp4
                                      \R4_L2_拦截.mp4
                                      \R4_Ls_预算.mp4
                                      \R4_R0_失守.mp4
```

产品副本在 `assets\logo\{L0,L1,L2,Ls,R0}.mp4`。**实测逐字节一致**
（下表为 `sha256` 前 16 位；**完整 64 位见 §4 的 T5-a 表**，两处是同一批实测值）：

| 态 | 定稿源 | 产品副本 | 结果 |
|---|---|---|---|
| L0 值守 | `b2a138fda1…` | `b2a138fda1…` | SAME |
| L1 注意 | `e8ca87d84c…` | `e8ca87d84c…` | SAME |
| L2 拦截 | `17ddffe81d…` | `17ddffe81d…` | SAME |
| Ls 预算 | `646fd37cf6…` | `646fd37cf6…` | SAME |
| R0 失守 | `0863247107…` | `0863247107…` | SAME |

**结论**：媒体层已经一致，**不需要重做 mp4**。不一致的风险在另外两层：

1. **代码重建层**：页面与哨标都不播 mp4。页面用内联 SVG ＋ rAF 状态机
   （`inbox_server._LOGO_JS`，`STYLE` 来自 `LOGO_MOTION_RENDER`）；哨标用
   `tools/logo_frame.ps1` 的帧数学（规格来自 `tray.json` 的 `logo` 块，而该块由
   `inbox_server.logo_motion_spec()` 派生）。**两边必须表达同一套五态**。
   实测：`logo_motion_spec()["modes"]` = `{L0,L1,L2,Ls,R0,dev}`；
   `LOGO_MOTION_RENDER` 键 = `{L0,L1,L2,LD,R0}` ⇒ `Ls→LD`、`dev→L0`（映射表在
   Python 侧，PS 只查表 ⇒ **单一真源，未分叉**）。这一点要在 T5-b 里钉死。
2. **图标层**：`assets/logo/antinel.ico`（品牌，由 `logo.svg` 栅格化，
   `tools/mk_logo_ico.py`）与 `assets/icons/*.ico`（姿态灯，托盘用，
   `tools/mk_icons.py`）是**两种东西**。品牌标不许用姿态灯顶替 —— 这条纪律已经
   被违反过三次：favicon（0.53.1 已修，`B-15b`）、桌面快捷方式（0.52.0 已修）、
   哨标回落（**本次要修**，T1）。

---

## 3. 必须遵守的机制层纪律

### 3.1 判据纪律

1. **每条新判据必须配负控**：同一把尺子量一个故意改坏的输入，必须判红。
   负控不红的判据等于装饰。
2. **判据不许二次实现被测逻辑**。要跑产品代码就跑同一份文件（FLO-10 族
   dot-source 产品同一个 `tools/logo_frame.ps1`），不许在判据里抄一遍算法。
3. **判据必须从生产默认路径出发**。曾经的假绿：判据给函数注入参数
   （`posture=...`），生产走默认参数（`posture=None` → 兜底 `return True`），
   判据永远绿、按钮永远在。**不许为了让判据通过而传一个生产不会传的参数。**
4. **红项先分类**：产品缺陷／夹具失效／改动前就红。只有第一类进修复批次。
   机器慢造成的 `rc=124` 属第二类，**不许**靠调大产品超时来"修"。
5. **只守一条腿 = 另一条腿天然全绿**。加判据时必问：这条规则还有没有另一条实现
   路径？（`B-15` 只守"链接同源"、没守"解析到哪个文件"，favicon 用姿态灯活了整版。）
6. **判据 ID 不许跨套件重名**（0515 P0-2 守）；新判据**并入现有套件**，常驻上限
   **29/29 已满**，不许新建套件。本次全部并入 `ci/inbox_guards_0514.py`（FLO 族）。
7. **两套体系别混**：`ci/*.py` 是**闸门判据**（快/慢档，34 套）；
   `scripts/run_harness.py` → `psl/judgment.json` 是**harness 断言**（315 条）。
   交付标准要分别写（见 §6）。

### 3.2 页面与文案

1. **主语只许"监理"**，用户可见文案禁用"我们"（创始人 2026-10-19 拍板）。
2. 详情行必须过 `humanize()`，不许把 `mode=detached`、`旧进程号 None` 直接上屏。
3. 改文案**必须同步判据锚点**，动手前 grep：`ci/inbox_guards_0353.py`、`0490`、
   `0514`、`0372`、`0380`。
4. **按钮是可执行承诺**：看得见的页面 ⇒ 监理在跑；"重新拉起"只在
   `POSTURE_DOWN`/`INTERRUPTED` 下才许出现（白名单口径，不用黑名单）。

### 3.3 版本与发布

1. 九处承载件一致；升版用 `ci/bump_version.py <ver> --apply`，**别手改**。
   ⚠️ 它**不管** `psl/workspace_facts.json`（五处版本），必须手工同步，否则 D-23 红。
2. 出包**只允许**走 `scripts/release.py`（闸门 → 装配 → 构建 → 验收 → 研发树复位）。
   ⚠️ **绝不许单独跑 `scripts/build_package.py`**：跑完会把 manifest 恢复成纯 wheel
   口径并刷平 version，而本仓就是研发树 ⇒ 立刻进入"假失守"
   （窗口显示「失守：防护文件被改动」）。0.53.1 因此翻车两次。
3. 不许用 `ANTINEL_SKIP_GATE=1`、`git commit --no-verify` 绕过闸门；要绕必须写进
   汇报并说明理由。
4. 出包成功后 `release.py::_finalize_dev_tree` 自动做：补登 `ci/freeze_zones.json`
   → manifest `version` 回落 `0.50.5` → `host_shield.self_check()` 收口。
   它报错就**先修好再提交**。

### 3.4 PowerShell 5.1 三大坑（改哨标必看）

1. **无 BOM 的 `.ps1` 按 GBK（ANSI 码页）读**。文件里任何非 ASCII 字节——哪怕只在
   注释里——都会静默改变行为。⇒ `tools/*.ps1` **必须纯 ASCII**。
   `0514` 的 FLO-01 有字节级扫描守着，别绕过。
2. **变量名大小写碰撞**：`param([string]$Spec)` 与 `$spec = ...` 是同一变量 ⇒
   Hashtable 被强转成字符串。驱动脚本用 `$sp` 之类不撞的名字。
3. **cast 比索引绑得紧**：`[int]$xy[0]` == `([int]$xy)[0]`，数组被连成 `"23 23"`。
   必须写 `([int]$xy[0])`。
4. 附带：PS 错误输出走 ANSI 码页，Python 侧 decode 用 `mbcs`（utf-8 会
   `UnicodeDecodeError`）；`& script.ps1` 同进程调用时，脚本里的 `exit 0`
   **会结束整个宿主会话**。

### 3.5 其它硬约束

1. **零删除**：退役文件改名 `.away-<时间戳>`。
2. 临时目录不许进仓（会带偏 `workspace_roots` ⇒ 判据假红）。
3. 长任务前**先查进程表**：shell 报错 ≠ 进程死了。
4. 判据跑动期间**不许改产品文件**（半新的树让结果不可信）。
5. 不许并发跑重活（两个 harness 并发会把钩子探针拖过超时线，看着像产品缺陷）。

---

## 4. 任务清单

### T1（P0）哨标回落必须画品牌 LOGO，不许画姿态灯

**现象**：点左上角 LOGO 最小化后，右下角出现"土黄色粗环＋实心点"（L1 姿态灯），
不是动效 LOGO。

**根因（行号精确）**：`tools/logo.ps1:374-383`

```powershell
$hasSpec = ($null -ne $j.PSObject.Properties["logo"])
if ($changed -or ($hasSpec -ne $script:hadSpec)) {
  $script:spec = Import-Spec $(if ($hasSpec) { $j.logo } else { $null })
  if ($script:spec -ne $null) {
    $key = [string]$script:spec.modes[$st]
    if ([string]::IsNullOrWhiteSpace($key)) { $key = "L0" }
    $script:motionKey = $key
  } else {
    $script:motionKey = "L0"
    Load-Icon (Resolve-IconPath $st $sh)      # ← 就在这里画姿态灯
  }
  ...
```

`Resolve-IconPath`（`:160-171`）返回 `assets/icons/<state>.ico`。整条回落路径
**不留任何痕迹**。

**为什么必须改**：哨标所在位置的语义是"这是 Antinel"，不是"当前是 L1 态"。
用状态灯顶替品牌标＝把"当前没事"写进品牌（`inbox_window.brand_icon_path()`
的注释里早立了这条纪律，这是它的第三条腿）。

**改法**：
1. `else` 分支的回落目标改为**品牌静态图标**：
   `assets/logo/antinel.ico`（由 `logo.svg` 栅格化，与五态定稿同源）。
   **不许**用 mp4 的某一帧（那是"某一态的某个瞬间"冒充品牌）；
   **不许**用 `icons/*.ico`。
2. 既有的 `-IconDir` 参数保留但**降级为最后兜底**（品牌 ico 也读不到时），
   并在那种情况下同样留痕。
3. 回落时写审计事件：`type="logo_frame_unavailable"`，
   `reason ∈ {no_spec, brand_icon_missing, dot_source_failed}`。
   一次进程周期只写一次（防刷屏），但要能被 `report.py` 看见。
4. `tools/logo.ps1` 保持**纯 ASCII**；新增中文只能由 Python 侧参数传入。

**判据（并入 `ci/inbox_guards_0514.py`，FLO 族）**：
- `FLO-11` 正判据（三条腿）：
  (a) **结构**：`logo.ps1` 的 `else` 回落分支里出现 `antinel.ico`（或调用一个只返回
      品牌 ico 的函数），且该分支**不出现** `icons` 字样；
  (b) **真值**：把不带 `logo` 块的 `tray.json` 喂给产品的规格解析路径，
      断言选出的图标 basename == `antinel.ico`；
  (c) **痕迹**：模拟回落 ⇒ 审计链必须出现 `logo_frame_unavailable`。
- `N-FLO-11` 负控：回落目标改回 `icons/L1.ico` ⇒ (b) 红；删掉事件写入 ⇒ (c) 红；
  把品牌 ico 改名 ⇒ (b) 必须报"品牌图标缺失"而不是静默通过。

**验证**：
1. `python ci/inbox_guards_0514.py` → 全绿（0.53.1 基线 **145 绿 / 0 红 / 0 跳过**）。
2. 手工：从 `tray.json` 摘掉 `logo` 块 → 重拉哨标 → 肉眼确认是品牌静态 LOGO，
   且审计链有 `logo_frame_unavailable`。
3. 恢复 `logo` 块 → 重拉 → 确认是动效且随态变化（见 T5-d 与 §6.1）。

**完成标准**：三种输入（有规格／无规格／帧脚本损坏）都画品牌；后两种都有事件。

**预估**：3–4 小时。

---

### T2（P0）`logo` 块改必写 ＋ 失败留痕

**根因**：`inbox_tray.py:212-214`（`if spec: payload["logo"] = spec`）＋
`tools/logo.ps1:379-380`（`modes[st]` 缺键静默 fallback "L0"）。

**改法**：
1. 规格拿不到 ⇒ **仍要写**可识别的失败标记（`logo_missing: true` ＋ `logo_error`），
   或写 `logo: null` ＋ `logo_error`；二者择一，但**必须让下游区分"旧版没写该字段"
   与"新版写了但拿不到"**（哨标据此决定是否报警）。
2. `logo_spec_missing` 审计事件（一次进程周期一条）。
3. `modes[st]` 缺键 ⇒ 保留 fallback "L0"（方向安全），但要写
   `logo_mode_missing`（带 `state` 与已有的键集）。

**判据**：
- `FLO-12`：注入一个 `logo_motion_spec` 必抛的替身 ⇒ `write_state` 产出的 payload
  必须带可识别失败标记（与"字段不存在"可区分），且审计链有 `logo_spec_missing`。
- `FLO-12b`：`modes` 里删掉 `L1` 键 ⇒ 哨标侧解析必须记 `logo_mode_missing` 且
  仍取到可用模式（不崩）。
- `N-FLO-12` / `N-FLO-12b`：把标记与事件各删一处 ⇒ 必须红。

**预估**：2–3 小时。

---

### T5（P0）五态一致性判据（**v1.1 新增**）

**背景**：见 §2.3。媒体层已一致，但没有任何判据钉住它；代码重建层的键闭包与
"五态是否真的各不相同"也没人守。

**五条判据**：

- **T5-a 媒体字节**：`assets/logo/{L0,L1,L2,Ls,R0}.mp4` 的 `sha256` 必须等于
  下表（定稿源实测值）。定稿目录**不在包内**，所以判据自带期望值，
  **不去读 `D:\2026\PSL`**（否则换机就测不出）：

  | 态 | sha256（完整 64 位，实测值） |
  |---|---|
  | L0 | `b2a138fda1e8e52ec0e41f9e820fa07dd3a567dafc49202548bb55cd7b5a26d0` |
  | L1 | `e8ca87d84c371087c77510f7bdbefe1f51c736fa8db1da80db0e87d04b704ef1` |
  | L2 | `17ddffe81da74294329a6cb9f3c14b96ed8794f5ffe618633b986675f1f82b49` |
  | Ls | `646fd37cf6a99d798b0312360e6c51c8d8c8b56847b468e087e01c6a2214f984` |
  | R0 | `0863247107e9a3ae36de22ea868055a38dbf40471ac0521b79ce0e93c0db8628` |

  负控：改一个字节（或用 `sdist` 里被转码的版本）⇒ 红。
  ⚠️ 判据里直接写死上面五个常量，**不要**改成"读定稿目录再比"——定稿目录
  `D:\2026\PSL\antinel-logo-final_assets` 不在包内，读它等于换机就测不出。
  需要重取值时的取法：
  `sha256sum assets/logo/<态>.mp4`（或
  `python -c "import hashlib;print(hashlib.sha256(open(p,'rb').read()).hexdigest())"`）。
  重取之后**必须同步改 §2.3 的表**，两处同一个数。

- **T5-b 模式键闭包**：`set(logo_motion_spec()["modes"].values())` ⊆
  `set(LOGO_MOTION_RENDER.keys())`，且 `modes["Ls"]=="LD"`、`modes["dev"]=="L0"`。
  负控：把 `Ls` 的值改成 `"LS"` ⇒ 红（渲染表没有 ⇒ 页面会白画／哨标回落）。

- **T5-c 姿态灯来源**：`tools/mk_icons.py` 的态清单必须 == `modes` 的键集去掉
  `dev`（即 L0/L1/L2/Ls/R0），且 `assets/icons/` 下这 5 个 `.ico` 都在场。
  负控：从清单里删掉 `R0` ⇒ 红。
  （不判"画面像不像"——那是人工项，见 §6.1。）

- **T5-d 五态不塌缩**：`modes` 的五个态映射后必须得到**五个互不相同**的值
  （即 `len(set(modes[k] for k in (L0,L1,L2,Ls,R0))) == 5`）。
  负控：把 L1 也映射成 `"L0"` ⇒ 红。
  为什么：塌缩后"五个态一个动效"，看起来在动，其实什么都没变 —— 这是最隐蔽的
  假绿，任何"有动效吗"的判据都抓不到。

- **T5-e 两个出口同源**：页面 `_LOGO_JS` 的 `STYLE` 必须由 `json.dumps(LOGO_MOTION_RENDER)`
  装配（不许另写一份常量）；哨标的规格必须来自 `logo_motion_spec()`。
  负控：把页面里的 `__STYLE__` 替换成手写常量 ⇒ 红。

**预估**：2–3 小时（含 5 个负控；T5-a 要先取完整哈希）。

---

### T3（P1）长驻进程版本自检

**现象**：0.53.1 交付后 `tray.json` 长时间没有 `logo` 块；代码是新的，写状态的是
早上启动的旧 daemon。重启 serve 无效 ⇒ 用户看到旧行为，排查方向被带偏。

**改法**：
1. **落点**：复用既有运行时状态（`url.json` 已有 `pid/port/started_at/token`），
   增加 `code_version` 与 `code_mtime` 两个字段。**不许新建第二份状态文件**
   （那正是"一个事实两个来源"）。
2. **不自报就喊**：面板与 `antinel inbox status` 显示"服务跑的是 X，仓里是 Y"，
   并给可执行修法（重启命令）。**不要自动杀进程**（那是用户的机器）。
3. daemon 同样落一份（或共用同一份，取决于现有实现，先读代码再定）。

**判据**：
- 注入"版本不一致"的运行时状态 ⇒ 状态出口必须报差异，文案含**两边版本号**
  （不许只说"版本不一致"）。
- 负控：删掉差异检查 ⇒ 红；把两边改成同一值 ⇒ 必须判绿（防误报）。

**预估**：3–4 小时。

---

### T4（P1）高 DPI 适配

**现象**：`tools/logo.ps1` 里 `DPI` 零命中。分层窗按**物理像素**合成，`-Size 46`
在 150% 缩放下视觉只有 ~31px，命中半径同比例偏小。

**改法**：
1. 取缩放：`GetDpiForWindow`（user32，Win10+）或 `GetDeviceCaps(hdc, LOGPIXELSX)`
   （GDI，兼容性更好）；失败 ⇒ 96dpi（1.0）。
2. **画的直径／可点半径／窗口尺寸三者同源**：由同一个
   `size_phys = round(size_logical × dpi/96)` 派生，不许各自乘一次。
3. 多显示器/远程桌面：换屏后重算（`WM_DPICHANGED`，或每次 Show 时重算并留痕）。
4. `tools/logo_frame.ps1` 的几何是归一化坐标，**不许在里面乘 DPI**——DPI 只影响
   最终像素尺寸，不影响帧数学。

**判据**：
- `FLO-13`：`Size` 与 `hitRadius` 必须来自同一个派生函数（锚点：`Get-HitRadius`
  的入参是**派生后的** `Size`）。
- `FLO-14`：纯函数口径——`dpi ∈ {96,120,144,192}` 时
  `派生(46,dpi) ∈ {46,58,69,92}`，且 `Get-HitRadius(size_phys)` 与 `size_phys/2`
  相差 ≤ 1。
- 负控：DPI 乘两次 ⇒ 红；DPI 写死 96 ⇒ 红。
- **150% 真机肉眼验收无法自动化** ⇒ 列入 §6.1 人工项，不许假装有判据。

**预估**：4–6 小时。

---

## 5. 依赖与资料索引

| 类别 | 文件 | 用途 |
|---|---|---|
| 设计总纲 | `docs/Antinel·监理五页信息架构与工具归因方案 v1.19（2026-10-19）.md` | §41 是哨标整套（画什么/单一真源/分层窗/命中区推导/帧泵对照/判据六条/为什么 0.52.0 没拦住/ps1 必须 ASCII）；§42 是问号词条文案（品质网 × 文案消费面矩阵 ＋ 减法留账 ＋ T4-07/T4-08）；§43 是**全部 24 条问号词条逐条过一遍**（七类病 ＋ T4-09 跨字段重复网 ＋ 减法留账） |
| 条款映射 | `docs/设计条款-判据映射.json` | 条款 → 判据（改条款必须同步） |
| 哨标启动 | `inbox_logo.py`（`frame_script_path` :125、`logo_cmd` :178） | 参数装配（`-Frame`、`-IconDir`、`-Size`） |
| 规格真源 | `inbox_server.logo_motion_spec()`、`LOGO_MOTION_RENDER` | 页面与哨标共用 |
| 帧数学 | `tools/logo_frame.ps1` | `Get-Frame`/`Get-HitRadius`/`Test-Hit`/`New-Visual` |
| 窗口实现 | `tools/logo.ps1`（回落 :374-383、图标解析 :160-171、帧泵 :545） | 分层窗、命中测试、回落链 |
| 写状态 | `inbox_tray.py`（`write_state` :205-214、`_logo_spec_block` :229） | `tray.json` 唯一写入口 |
| 品牌图标 | `inbox_window.brand_icon_path()`（:597）、`assets/logo/antinel.ico` | **品牌标唯一真源** |
| 五态动态 | `assets/logo/*.mp4`（5 个，与定稿同字节） | 只作定稿参照，**不参与运行**（页面/哨标都是代码重建） |
| 姿态灯 | `assets/icons/*.ico`（5 态 ＋ off/unknown/unposted 变体） | **只给托盘**，不许当品牌标 |
| 品牌矢量 | `assets/logo/logo.svg`（R4 定稿，含"哨点必须在线"注释） | ico 的源 |
| 图标生成 | `tools/mk_logo_ico.py`、`tools/mk_icons.py` | 构建期栅格化（运行期零依赖） |
| 判据（哨标） | `ci/inbox_guards_0514.py` | B-02…B-16、FLO-01…FLO-10e（145 条） |
| 判据（打包） | `ci/inbox_guards_0516.py` | 随包清单 vs 真实 wheel |
| 判据（几何/删除许可） | `0517`、`0460` | W17-d、S80 族 |
| 闸门 | `ci/delivery_gate.py` | 34 套；`--only a,b` 只跑指定 |
| 出包 | `scripts/release.py` | 三步骤 ＋ 研发树复位 |
| 判断记录 | `psl/judgment.json`、`scripts/run_harness.py` | 315 条断言 |
| 历史账 | `.workbuddy/memory/2026-10-19.md` | 0.53.1 全过程与所有坑 |
| 长期纪律 | `.workbuddy/memory/MEMORY.md` | 版本/判据/活体闸 |

---

## 6. 交付标准

### 6.1 闸门与 harness（两套，分别达标）

1. `python ci/delivery_gate.py` → **34/34 全绿**。新判据并入 0514，**套件总数不变**。
2. `python scripts/run_harness.py` → **PASS**，断言数 **≥ 315**（只许多）。
   注意：T1/T2/T5 加的是 `ci/` 判据，**不会**改变 harness 断言数；若改了
   `verification_tests.py` 才需要跟着调基线。

### 6.2 出包

3. `python scripts/release.py` → `antinel-0.53.2-*.whl` ＋ `*.tar.gz`；
   验收 A/B/C/D/E 全过；自动完成研发树复位（`self_check()` True、manifest version
   `0.50.5`）。

### 6.3 活体回读（五项，缺一不算）

4. 有 `logo` 块 ⇒ 哨标是动效（见 6.4 取帧法）；
5. 无 `logo` 块 ⇒ 哨标是**品牌静态 LOGO**，且审计链有 `logo_frame_unavailable`；
6. **切态后动效随之改变**（L0→L1→L2→R0 各看一眼，T5-d 的机器判据 ＋ 人工确认）；
7. `/assets/favicon.ico` 与 `assets/logo/antinel.ico` **字节相同**（0.53.1 已修，别回退）；
8. 以上在服务/窗口**重启后**仍成立（活体闸）。

### 6.4 "哨标在动"怎么取到证据（v1.0 只给了要求、没给方法，本版补）

分层窗（per-pixel alpha）走屏幕合成，**`CopyFromScreen` 截不到可靠图像**（实测两次失败）。
三条可行路，按可行性排序：

1. **帧摘要日志**（推荐）：给 `logo.ps1` 加一个 `-Probe <path>` 开关（只在探针下启用），
   每帧把 `New-Visual` 结果的几个特征值（例如 `alpha` 权重、`phase`、`waveR`、
   bitmap 的 8 点采样）append 到该文件。连取 20 帧，**若全部相同 ⇒ 判定不动**。
   判据可以读这个文件（`FLO-10b` 已有"k=0／起转冻结"同款思路）。
2. **`PrintWindow`**：对分层窗调用 `PrintWindow(hwnd, hdc, PW_RENDERFULLCONTENT=2)`，
   有概率拿到渲染内容（需实测是否支持）。
3. **兜底**：报"人工验收项"，并留一条 15 秒的肉眼检查清单（§6.5）。**不许**把
   没测成写成 PASS。

### 6.5 人工验收清单（机器判不了，必须人做）

- [ ] 150%／200% 缩放下哨标大小与点击区（T4 若未做完，此项写"未做"）
- [ ] 肉眼：哨标是**动态**的（环在转、虚线在流、哨点呼吸）
- [ ] 肉眼：切到 L1/L2/R0 后，哨标的动效**明显不同**（颜色/节奏/幅度）
- [ ] 肉眼：托盘图标仍是姿态灯（按态变），哨标是品牌动效——两者不该是同一个东西

---

## 7. 已完成的参照（0.53.1，别重做，但要保持）

1. **favicon 用姿态灯**已修：`inbox_server._brand_favicon_rel()` 从
   `inbox_window.BRAND_ICON_REL` 实时派生；favicon 已移出 `ASSET_WHITELIST`。
   判据 `B-15b` ＋负控 `N-B15b`（结构／派生／**字节真值**三腿）。
2. **发布收尾自动化**：`release.py::_finalize_dev_tree`（补登研发树件 → version
   回落 → `self_check()` 收口）。
3. **判据健壮性**：`0460` 夹具自证重试 2→4、每目标先重读一次、补 `N-S80c`；
   `0517 W17-d` 不再把"窗口最小化"判成几何失败。
4. **哨标本身**（0.53.1）：`tools/logo_frame.ps1` 帧数学（一份实现两处调用）、
   命中区按内容外沿推导（实测半径 23 = Size/2）、`System.Timers.Timer` ＋
   `SynchronizingObject` 帧泵（实测 16.1fps）。**点击能返回已达标，不要动它。**

---

## 8. 已知坑速查

| 症状 | 真因 | 处置 |
|---|---|---|
| 哨标是静态姿态灯 | `tray.json` 缺 `logo` 块（daemon 旧代码） | 杀 daemon ＋ serve，经 `explorer + lnk` 重拉（T1/T3 要根治） |
| 改了代码没效果 | 长驻进程旧代码 | 同上一行（T3 要根治） |
| 窗口显示「失守：防护文件被改动」 | manifest 被刷成纯 wheel 口径 | `python _tools_034/_resign_manifest.py --adopt-dev`，再把 manifest `version` 回落 `0.50.5` |
| `regression D-23` 红"dist 缺本版件" | 出包前必然红 | 只在 `release.py` 里跑（带 `ANTINEL_BUILD_IN_FLIGHT=1`） |
| `0431 S70` 红"版本落差为 0" | manifest version 被刷平 | 回落 `0.50.5` |
| `0516 PKG16-c` 红"清单版本超前验收日志" | `output/p12_verify_release.log` 是旧版 | 重跑 `scripts/verify_release.py > output/p12_verify_release.log` |
| `0460 S80` 报"夹具失效" | 本机进程启动 0.6–1.9s vs 产品 `VCT_TIMEOUT=2.0` | 空载重跑；**不许**调大产品超时 |
| `0515` 超时 | `host-scan --json` 单跑 49s，负载下翻倍 | 空载重跑，别并发 |
| 回读 403 | 端口漂移／用了仓内旧 `url.json` | 只读 `~/.antinel/console/url.json` |
| 命令行被 SEC-05 拦 | 命令文本含 `cookies` 等字面量 | 探针写成 `output/_xxx.py` 再执行；**变量名与注释也避开该词** |
| `/assets/*` 403 | 缺 httpOnly cookie | 先取页面拿 `antinel_t` |
| 截图取不到哨标 | 分层窗不走屏幕合成 | 用 §6.4 的帧摘要／`PrintWindow`；别指望 `CopyFromScreen` |
| `.ps1` 行为诡异 | 文件含非 ASCII（按 GBK 解析） | 纯 ASCII 化；`0514` FLO-01 会扫出来 |
| PS 报"参数是空值" | `[int]$xy[0]` 被解析成 `([int]$xy)[0]` | 加括号 |
| PS 报"找不到接受实际参数" | 函数名撞了内置别名（`lp` = Out-Printer） | 换名 |
| git 报 "must be run in a work tree" | `core.bare` 被改 | 查 `git config core.bare` |

---

## 9. 交接检查表

- [ ] 闸门 34/34 绿（新判据并入 0514，套件总数不变）
- [ ] harness PASS ≥ 315
- [ ] `FLO-11` / `FLO-12` / `FLO-12b` / `T5-a…e` 全部新增，**各自有负控且实测判红**
- [ ] 三种输入（有规格／无规格／帧脚本坏）都画品牌；后两种有审计事件
- [ ] 五态不塌缩（T5-d 机器判定 ＋ §6.5 肉眼确认）
- [ ] 高 DPI 若未做完，汇报里明确写"未做／半做"，**不许含糊**
- [ ] 出包 0.53.2 两件齐全，验收全过，研发树已复位
- [ ] 提交完成，说明含"根因／改法／判据／验证"四段
- [ ] 当天记忆文件追加一段（做了什么／根因／新增与改动的判据／还剩什么）
- [ ] 本任务书若再升版：换文件名 v1.2，v1.1 退役为 `.away-<时间戳>`

---

## 10. 本版自查：v1.0 的 11 处遗漏／漂移（v1.1 已逐条修正）

1. **把"五态动态"漏在范围外**。v1.0 只谈"姿态灯 vs 品牌标"，没问"标准五态动态
   在哪、产品用的是不是它"。→ 新增 §2.3 与 T5。
2. **事实写错**（格式）：以为标准五态是 SVG，实际是 5 个 MP4。→ §2.3 更正并附哈希。
3. **T1 没说清回落目标到底是哪个文件**。→ 明确 `assets/logo/antinel.ico`，
   并禁掉"mp4 某一帧"这条看似合理的错解。
4. **T2 漏了 `modes[st]` 缺键的静默 fallback**（`logo.ps1:379-380`）。→ 补
   `logo_mode_missing` 与 `FLO-12b`。
5. **§6 要求"连续两帧像素不同"却没给取帧方法**，而截图取不到分层窗。→ 新增 §6.4
   三条可行路（帧摘要日志／PrintWindow／如实报人工项）。
6. **T3 没指定落在哪个状态文件**，容易让人新建第二份状态（正是本仓最忌的形状）。
   → 明确复用 `url.json` 的既有字段。
7. **两套判据体系混写**：v1.0 的"≥315"指 harness 断言，而 T1/T2 加的是闸门判据，
   两者不联动。→ §3.1-7 与 §6.1 分开写。
8. **缺降级方案**：若时间不够，先做哪个？→ T2 的"必写＋留痕"（改动小、让问题可见）
   优先于 T1 的完整改法；**"可见"比"完美"优先**。
9. **缺人工验收清单**：哪些不许假装有判据。→ 新增 §6.5。
10. **缺"改 .ps1 后怎么单独自测"**。`logo_frame.ps1` 是纯函数库、没有 CLI 入口，
    直接跑它什么也不会发生。→ 正确做法：用 `0514` 里的 `_FLO10_DRIVER`，或写临时
    驱动 dot-source 它（注意 §3.4 三大坑）。
11. **缺"套件容量"约束**：常驻 29/29 已满，新判据必须并入 0514。→ §3.1-6。

（另修：v1.0 §4 的 T3/T4 编号保留不变，新任务用 T5，避免与已发出的 v1.0 对不上。）

### 10.1 v1.1 自身又查出的两处（已改，写在这里免得下一版重犯）

12. **哈希只写前缀**。v1.1 初稿的 T5-a 表写的是 16 位前缀，另附一句"实施时应写
    完整 64 位"—— 把"要不要精确"推给了读者。前缀判据漏掉的是"前缀相同、后面
    不同"的改字节，而这正是最容易被忽略的失效。→ 已换成实测完整 64 位，删掉那句
    备注，并补上"重取值后两处必须同改"。
13. **退役件名写成占位符**。初稿写 `.away-<时间戳>`。本仓退役件必须是**可复算的
    实名**，占位符让接手人无法确认"退役到底做了没有"（是不是只改了正文声明）。
    → 已写实为 `.away-20261019194350`。

> 结论：本文件的事实层（文件路径、行号、哈希、键集）**全部实测过**；
> 唯一没有判据的是"动效像不像定稿"，那是人工项，见 §6.5。
