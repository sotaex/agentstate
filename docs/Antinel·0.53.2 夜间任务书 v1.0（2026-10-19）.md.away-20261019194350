# Antinel·0.53.2 夜间任务书 v1.0（2026-10-19）

> 性质：**可交接的执行文件**。写给"第一次接手本仓的 AI"或"睡醒前的我自己"。
> 目标：把 0.53.1 遗留的四个缺陷按优先级做完、出包 0.53.2、提交。
> 纪律：本文件里的每一句"现状"都可用给出的命令复算；**凡未复算的，不许当成事实引用**。
> 本版新增：0.53.1 收尾后发现的"哨标回落姿态灯"根因（T1）与"长驻进程旧代码"根因（T3），
> 以及 0.53.1 已实证的三条判据健壮性修法（见 §7 附录，已做完，仅作参照）。

---

## 0. 三十秒读完（接手者只看这一段也不会做错方向）

Antinel 是"AI 编程工具的监理"：本地一个常驻服务 + 一个托盘 + 一个五页面板 + 一枚
最小化后的**漂浮哨标**。0.53.1 已出包、已提交、闸门 34/34 全绿。

现在剩四个缺陷，**按这个顺序做**：

| 编号 | 一句话 | 优先级 | 预估 |
|---|---|---|---|
| T1 | 哨标回落时会画**姿态灯**（L0/L1/L2…），用户会误以为那是 LOGO —— 回落必须画**品牌 LOGO**，且回落要留痕 | P0 | 3–4h |
| T2 | 写 `tray.json` 的一方用 `if spec:` 条件写 `logo` 块，拿不到规格就**静默不写** —— 改成必填＋失败留痕 | P0 | 2–3h |
| T3 | 长驻进程（daemon/serve）跑的是**启动那一刻的代码**，改了代码不重启就等于没改 —— 加版本自检与自动复活 | P1 | 3–4h |
| T4 | 高 DPI 完全没处理（`tools/logo.ps1` 里 `DPI` 零命中），150%/200% 缩放下哨标偏小、命中区偏小 | P1 | 4–6h |

T1/T2 是同一个病（**用状态灯冒充品牌标**）的第三、第四次复发，必须一起做，否则只修一条腿。
T3 是"为什么改了却没效果"的结构性原因，不修则以后每次验证都可能被旧进程骗。
T4 是唯一用户可见的"不精致"，但难度最高（PowerShell + 多显示器 + 无法截图验证）。

做完的交付标准见 §6。**没达到 §6 的任何一条，都算没做完。**

---

## 1. 环境与入口（照抄即可）

### 1.1 路径

| 项 | 值 |
|---|---|
| 仓根（＝研发树 ＝产品目录） | `D:\psl\poc\antinel-security` |
| 出包产物目录 | `D:\psl\poc\antinel-security\dist`（只许有两件：whl ＋ tar.gz） |
| 临时目录（**必须**放仓外） | `D:\_antmp` |
| 运行时状态目录 | `C:\Users\大马\.antinel\console\`（含 `tray.json`、`url.json`） |
| 审计链 | `<仓根>\.psl\audit\YYYY-MM-DD.jsonl` |
| 闸门结果 | `<仓根>\.psl\gate\last_run.json` |
| 判断记录 | `<仓根>\psl\judgment.json` |
| 打包清单 | `<仓根>\psl\manifest.json`（研发树惯例 `version` = `0.50.5`） |
| 历史文档 | `<仓根>\docs\`（本仓文档一律入库；退役件改名 `.away-<时间戳>`，**零删除**） |

### 1.2 解释器与固定前缀（**每条命令都要带**）

```
PYTHONPATH= TMP=D:/_antmp TEMP=D:/_antmp TMPDIR=D:/_antmp \
"C:/Users/大马/.workbuddy/binaries/python/versions/3.13.12/python.exe" -E -X utf8 <脚本>
```

为什么必须带：`PYTHONPATH=` 防止外部路径污染；三个 TMP 指到仓外，否则
`workspace_roots` 判据会假红（实测过）；`-E -X utf8` 防止环境变量与编码干扰。

**不要用**裸 `python`：本机 shell 里的 `python` 是商店占位别名，静默返回 0 什么也不干。

### 1.3 服务怎么起（重要：沙箱里拉起必死）

- 服务与窗口**必须**经桌面快捷方式起：`C:\Users\大马\Desktop\Antinel 监理.lnk`。
- 唯一能存活的拉起方式（实测，别的方法都会在调用结束时被整树回收）：

```powershell
Start-Process explorer.exe -ArgumentList '"C:\Users\大马\Desktop\Antinel 监理.lnk"'
```

- 直接 `Start-Process <lnk>` 或 `explorer <lnk>` 都会随调用结束消失。
- 让服务换新代码的办法：**杀掉 `antinel.py inbox serve` 与 `inbox daemon --supervise`
  两个进程**，再按上面那行重新拉 lnk（daemon 会重新拉起 serve）。
  ⚠️ 只杀 serve 时，**daemon 仍是旧代码**——它负责写 `tray.json`，会导致 §2.2 那个坑。
- 查进程：

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*python*" -and $_.CommandLine -like "*inbox*" } | ForEach-Object { "pid=" + $_.ProcessId + " :: " + ($_.CommandLine -replace '\s+',' ') }
```

### 1.4 活体回读（改完必须做，否则等于没改）

- URL 与口令**只认** `C:\Users\大马\.antinel\console\url.json`。
  ⚠️ 重启后端口会漂移（实测 8790 → 35089）；仓内 `console\url.json` 是旧缓存，拿它回读一律 403。
- 页面首字节会下发 httpOnly cookie `antinel_t`，`/assets/*` 必须带 cookie，裸 curl 403。
- 现成探针模板：`output\_fav_probe.py`（用 `http.cookiejar` 取页面 → 再取资源 → 比对字节）。
  ⚠️ 探针**必须写成文件再执行**：命令行里出现 `cookies` 字样会被产品自己的
  SEC-05 规则误拦（它按字面量匹配）。

---

## 2. 现状快照（0.53.1 收尾时的事实）

### 2.1 已完成

- 版本 `0.53.1`，九处承载件一致（`ci/version_check.py` PASS）。
- 出包：`antinel-0.53.1-py3-none-any.whl` ＋ `antinel-0.53.1.tar.gz`；
  验收 A/B/C/D/E 全过（随包清单 132 项 == wheel 载荷 134 项 − 按设计排除 2 项）。
- 全量闸门 **34/34 绿**；harness **315/315 PASS**；SKILL.md 自证卡
  `21/21 digests match this build`。
- 提交两个：`dddfa4a`（0.53.1 主体，29 文件）、`324eb65`（发布收尾自动化）。

### 2.2 未解决（就是本任务书要做的）

1. **哨标回落到姿态灯**。已实证：`tray.json` 缺 `logo` 块时，`tools/logo.ps1`
   走 `Resolve-IconPath` 画 `assets/icons/<state>.ico`。创始人 2026-10-19 截图：
   "现在缩小后变成这个了，还不对，不是动态LOGO---代表当前的某个态"（截图是土黄色粗环＋
   实心点，即 L1 姿态灯，`--l1:#8a6100`）。
2. **`logo` 块是条件写入**：`inbox_tray.py:212-214`
   ```python
   spec = _logo_spec_block()
   if spec:
       payload["logo"] = spec
   ```
   拿不到规格就静默不写，哨标只能回落，**用户看不出为什么**。
3. **长驻进程旧代码**：0.53.1 交付后，`tray.json` 长时间没有 `logo` 块，
   根因是 `inbox daemon --supervise` 从早上就在跑旧代码（它负责写 `tray.json`）。
   重启 serve 不够，必须重启 daemon。这是"改了没效果"的最常见原因。
4. **高 DPI 未处理**：`grep -c DPI tools/logo.ps1` = 0。

---

## 3. 必须遵守的机制层纪律（违反＝返工）

这些是 0.53.0–0.53.1 用真实事故换来的，不是建议。

### 3.1 判据纪律

1. **每条新判据必须配负控**：拿同一把尺子量一个"故意改坏"的输入，必须判红。
   负控不红的判据等于装饰。
2. **判据不许二次实现被测逻辑**。要跑产品代码就跑同一份文件（例如 FLO-10 族
   dot-source 产品同一个 `tools/logo_frame.ps1`），不许在判据里抄一遍算法。
3. **判据必须从生产默认路径出发**。曾经的假绿：判据给函数注入参数（`posture=...`），
   生产走默认参数（`posture=None` → 兜底 `return True`），判据永远绿、按钮永远在。
   ⇒ **不许为了让判据通过而给产品传一个生产不会传的参数**。
4. **红项先分类再动手**：产品缺陷 / 夹具失效 / 改动前就红。只有第一类进修复批次。
   机器慢造成的 `rc=124`（超时）属第二类，**不许**靠调大产品超时来"修"。
5. **只守一条腿 = 另一条腿天然全绿**。每次加判据都问：这条规则还有没有另一条
   实现路径（`B-15` 只守"链接同源"、没守"解析到哪个文件"，所以 favicon 用姿态灯
   活了整整一版）。
6. **判据 ID 不许跨套件重名**（0515 P0-2 守这个）；新套件要登记进
   `ci/delivery_gate.py::SUITES`，常驻上限 **29 已满**，新增必须合并进现有套件。

### 3.2 页面与文案

1. **主语只许"监理"**，用户可见文案禁用"我们"（创始人 2026-10-19 拍板）。
2. 详情行必须过 `humanize()`，不许把 `mode=detached`、`旧进程号 None` 这类机器话
   直接上屏。
3. 改页面文案**必须同步判据锚点**，动手前 grep：`ci/inbox_guards_0353.py`、
   `0490`、`0514`、`0372`、`0380`。
4. **按钮是可执行承诺**：看得见的页面 ⇒ 监理在跑；"重新拉起"这类动作只在
   `POSTURE_DOWN`/`INTERRUPTED` 下才许出现（口径用白名单，不用黑名单）。

### 3.3 版本与发布

1. 版本号 **三处＋六处**共九处一致：`antinel.py`、`pyproject.toml`、`server.json`
   等；升版用 `ci/bump_version.py <ver> --apply`，**别手改**。
   ⚠️ 它**不管** `psl/workspace_facts.json`（五处版本），必须手工同步，否则 D-23 红。
2. 出包**只允许**走 `scripts/release.py`（闸门 → 装配 → 构建 → 验收 → 研发树复位）。
   ⚠️ **绝不许单独跑 `scripts/build_package.py`**：它跑完会把 manifest 恢复成
   纯 wheel 口径并刷平 version，而本仓就是研发树 ⇒ 立刻进入"假失守"状态
   （监理窗口显示「失守：防护文件被改动」）。0.53.1 这一轮因此翻了两次车。
3. 不许用 `ANTINEL_SKIP_GATE=1`、`git commit --no-verify` 绕过闸门。要绕必须写进
   汇报并说明理由。
4. 出包成功后 `release.py` 会自动复位研发树（`_finalize_dev_tree`：补登
   `ci/freeze_zones.json` → manifest `version` 回落 `0.50.5` → `self_check()` 收口）。
   若它报错，**先修好再提交**，不要带着"包发了但树在报失守"的状态收工。

### 3.4 PowerShell 5.1 三大坑（哨标相关改动必看）

1. **无 BOM 的 `.ps1` 按 GBK（ANSI 码页）读**。文件里任何非 ASCII 字节——哪怕只在
   注释里——都会静默改变行为。⇒ `tools/*.ps1` **必须纯 ASCII**。
   `ci/inbox_guards_0514.py` 有字节级扫描（FLO-01 三件套）守着，别绕过。
2. **变量名大小写碰撞**：`param([string]$Spec)` 与 `$spec = ...` 是同一个变量 ⇒
   Hashtable 被强转成字符串。驱动脚本里用 `$sp` 之类不撞的名字。
3. **cast 比索引绑得紧**：`[int]$xy[0]` 等于 `([int]$xy)[0]`，数组会被连成 `"23 23"`。
   必须写 `([int]$xy[0])`。
4. 附带：PS 的错误输出走 ANSI 码页，Python 侧 decode 要用 `mbcs`（用 utf-8 会
   `UnicodeDecodeError`）；用 `& script.ps1` 同进程调用时，脚本里的 `exit 0`
   **会结束整个宿主会话**。

### 3.5 其它硬约束

1. **零删除**：退役文件改名 `.away-<时间戳>`，不 `rm`。
2. 临时目录不许放进仓内（会带偏 `workspace_roots` ⇒ 判据假红）。
3. 长任务前**先查进程表**：shell 报错 ≠ 进程死了（实测日志 0 字节、shell 报网络错，
   进程却跑满 30 分钟并覆写判断记录）。
4. 判据跑动期间**不许改产品文件**（半新的树会让结果不可信）。
5. 不许并发跑重活：两个 harness 并发会把钩子探针拖过超时线，看着像产品缺陷。

---

## 4. 任务清单

### T1（P0）哨标回落必须画品牌 LOGO，不许画姿态灯

**现象**：点左上角 LOGO 最小化后，屏幕右下角出现"土黄色粗环＋实心点"（L1 姿态灯），
不是动效 LOGO。用户原话："不是动态LOGO---代表当前的某个态"。

**根因**（已定位，行号准确）：
- `tools/logo.ps1:150-153` dot-source 帧脚本失败时静默（`catch { $script:frameOk = $false }`）。
- `tools/logo.ps1:155-170` 回落到 `Resolve-IconPath`，返回
  `assets/icons/<state>.ico` —— **姿态灯**。
- 这个动作没有留下任何痕迹，用户与后续排查都看不见。

**为什么必须改（不是审美问题）**：哨标所在的位置语义是"这是 Antinel"，
不是"当前是 L1 态"。用状态灯顶替品牌标，等于把"当前没事"写进品牌——
`inbox_window.brand_icon_path()` 的注释里早就立了这条纪律，而这条回落链是它的第三条腿。

**改法**：
1. 回落链改成：`assets/icons/<state>.ico` → **`assets/logo/antinel.ico`（品牌静态版，
   默认就用它）**。即：**默认回落＝品牌**，姿态灯不再是回落目标。
2. 回落发生时写一条事件（复用既有审计通道，见 `log_event` / `audit_chain`）：
   `type="logo_frame_unavailable"`，带 `reason`（spec 缺失／dot-source 失败／
   读取异常）。**不许静默**。
3. `tools/logo.ps1` 保持纯 ASCII（新增中文只能走 Python 侧参数传入）。

**判据（加进 `ci/inbox_guards_0514.py` FLO 族）**：
- `FLO-11` 正判据：
  (a) 源码结构：`Resolve-IconPath` 的回落目标**不含** `icons/` 姿态灯，或
      回落分支里出现 `logo/antinel.ico`（按实际改法锚定，锚点必须唯一）；
  (b) **真值**：把 `logo` 块摘掉的 `tray.json` 喂给哨标的规格解析函数，
      断言它选出的图标路径 basename == `antinel.ico`；
  (c) 事件：模拟回落 ⇒ 必须产生 `logo_frame_unavailable` 记录。
- `N-FLO-11` 负控：把回落目标改回 `icons/L1.ico` ⇒ (b) 必须红；
  把事件写入删掉 ⇒ (c) 必须红。
- 现有 `FLO-01`（约 30 条 clause）不要削弱，只能加。

**验证**：
1. `python ci/inbox_guards_0514.py` → 全绿（0.53.1 基线是 145 绿 / 0 红 / 0 跳过）。
2. 摘掉 `tray.json` 的 `logo` 块 → 重拉哨标 → 肉眼确认画的是品牌静态 LOGO，
   且审计链出现 `logo_frame_unavailable`。
3. 恢复 `logo` 块 → 重拉 → 确认是动效（见 T5 的动态性验证）。

**完成标准**：三种输入（有规格／无规格／帧脚本损坏）都画品牌，且后两种都有事件。

**预估**：3–4 小时（含判据、两个负控、活体）。

---

### T2（P0）`logo` 块改成必写＋失败留痕

**根因**：`inbox_tray.py:212-214`

```python
spec = _logo_spec_block()
if spec:
    payload["logo"] = spec
```

`_logo_spec_block()`（同文件 `:229-237`）返回 `SV.logo_motion_spec()`，异常时返回 `None`
（要复核：读该函数确认失败方向）。`if spec:` 让"拿不到规格"变成**合法的正常态**。

**改法**：
1. 规格拿不到 ⇒ **仍要写**一个显式的 `{"logo": null, "logo_error": "<原因>"}`
   或者不写 `logo` 但写 `logo_missing: true` ＋ 原因；二者择一，但**必须让下游能区分
   "旧版没写"与"新版写了但拿不到"**（哨标据此决定是否报警）。
2. 同时在审计链写一条 `logo_spec_missing`（一次进程周期只写一次，避免刷屏）。
3. 失败方向必须"更吵"：宁可多一条告警，不可静默降级。

**判据（0514 FLO 族或 0460 交易类判据，就近选）**：
- `FLO-12`：注入一个 `logo_motion_spec` 必抛的替身 ⇒ `write_state` 产出的 payload
  必须带可识别的失败标记（不许与"字段不存在"混淆），且审计链有记录。
- `N-FLO-12` 负控：把标记去掉、退回 `if spec:` ⇒ 必须红。

**验证**：单跑 0514 全绿；手工把 `inbox_server.logo_motion_spec` 打桩抛异常，
写一次状态，检查 `tray.json` 与审计链。

**预估**：2–3 小时。

---

### T3（P1）长驻进程版本自检（"改了没效果"的结构性原因）

**现象**：0.53.1 交付后 `tray.json` 长时间没有 `logo` 块。代码是新的，
写状态的是**早上启动的旧 daemon 进程**。重启 serve 无效，用户看到的是旧行为。

**根因**：`inbox daemon --supervise` 与 `inbox serve` 都是长驻进程，启动即固化代码；
没有任何机制检查"我跑的是不是当前树里的那份代码"。

**改法（两条，都要）**：
1. **进程自报版本**：daemon/serve 启动时把 `antinel.VERSION` ＋ 自身文件 mtime
   写进 `url.json` / `daemon.json` 之类的运行时状态（选现成的那个，不要新建第二份状态）。
2. **不一致就喊**：面板与 `antinel inbox status` 显示"服务跑的是 X，仓里是 Y"，
   并给一条可执行修法（重启命令）。**不要自动杀进程**（那是用户的机器）。
3. 附加：哨标与托盘读到 `logo` 块缺失时，能据此区分"旧版写的"与"新版拿不到"。

**判据**：
- 新增或并入现有套件：注入"版本不一致"的运行时状态 ⇒ 状态出口必须报出差异，
  且文案含两边的版本号（不许只说"版本不一致"）。
- 负控：把差异检查删掉 ⇒ 必须红；把两边的版本号改成同一值 ⇒ 必须判绿（防误报）。

**验证**：真现场——改 `antinel.py` 的 VERSION 之外的一个不敏感字段（或直接伪造
运行时状态文件），确认面板/CLI 报出差异；恢复后再看是否消失。

**预估**：3–4 小时。

---

### T4（P1）高 DPI 适配

**现象**：`tools/logo.ps1` 里 `DPI` 零命中。分层窗按**物理像素**合成，
`-Size 46` 在 150% 缩放下视觉只有 31px 左右，命中半径也按同一数值算 ⇒ 又小又难点。

**改法**：
1. 取当前显示器的缩放：`GetDpiForWindow`（user32，Windows 10+）或
   `GetDeviceCaps(hdc, LOGPIXELSX)`（GDI，兼容性更好）；失败 ⇒ 按 96dpi（缩放 1.0）。
2. **画的直径／可点半径／窗口尺寸三者同源**：由同一个 `size_phys = round(size_logical × dpi/96)`
   派生，不许各自乘一次（否则又会分叉）。
3. 多显示器：窗口跨屏或换屏后要重算（监听 `WM_DPICHANGED`，或每次 Show 时重算并留痕）。
4. `tools/logo_frame.ps1` 的几何是"归一化坐标"，**不许在里面乘 DPI**——
   DPI 只影响最终像素尺寸，不影响帧数学。

**判据**：
- `FLO-13`：源码结构——`Size` 与 `hitRadius` 必须来自同一个派生函数
  （锚点：`Get-HitRadius` 的入参是**派生后的** `Size`，不是原始参数）。
- `FLO-14`（可做的部分）：纯函数口径——给定 `dpi=96/120/144/192`，
  `派生(46, dpi)` 分别等于 46/58/69/92，且 `Get-HitRadius(size_phys)` 与
  `size_phys/2` 相差不超过 1。
- 负控：把 DPI 乘两次 ⇒ 判红；把 DPI 写死 96 ⇒ 判红。
- **真机 150% 缩放的肉眼验收无法自动化** ⇒ 在汇报里如实写"人工验收项"，
  不许假装有判据（本仓纪律：测不出的不许报 PASS）。

**预估**：4–6 小时（难点在活体验证与 PS 5.1 的 P/Invoke）。

---

## 5. 依赖与资料索引（读完这几份就够）

| 类别 | 文件 | 用途 |
|---|---|---|
| 设计总纲 | `docs/Antinel·监理五页信息架构与工具归因方案 v1.17（2026-10-19）.md` | §41 就是哨标这一整套（画什么/单一真源/分层窗/命中区推导/帧泵对照/判据六条/为什么 0.52.0 没拦住/ps1 必须 ASCII） |
| 条款映射 | `docs/设计条款-判据映射.json` | 每条款对应哪条判据（改条款必须同步这里） |
| 哨标代码 | `inbox_logo.py`（`frame_script_path` :125、`logo_cmd` :178） | 启动参数装配 |
| 规约真源 | `inbox_server.logo_motion_spec()`、`LOGO_MOTION_RENDER` | 页面与哨标共用同一份动效规格 |
| 帧数学 | `tools/logo_frame.ps1` | 纯函数：`Get-Frame` / `Get-HitRadius` / `Test-Hit` / `New-Visual` |
| 窗口实现 | `tools/logo.ps1` | 分层窗、帧泵、命中测试、回落链 |
| 写状态 | `inbox_tray.py`（`write_state` :205-214、`_logo_spec_block` :229） | tray.json 的唯一写入口 |
| 品牌图标 | `inbox_window.brand_icon_path()`（:597）、`assets/logo/antinel.ico` | **品牌标的唯一真源** |
| 姿态灯 | `assets/icons/L0/L1/L2/Ls/R0.ico` | **只给托盘用，不许当品牌标** |
| 判据（哨标） | `ci/inbox_guards_0514.py` | B-02…B-16、FLO-01…FLO-10e |
| 判据（打包） | `ci/inbox_guards_0516.py` | 随包清单与真实 wheel 对账 |
| 判据（窗口几何） | `ci/inbox_guards_0517.py` | W17-d |
| 判据（删除许可） | `ci/inbox_guards_0460.py` | S80 族（两票并且） |
| 闸门 | `ci/delivery_gate.py` | 34 套；`--only a,b` 只跑指定套件 |
| 出包 | `scripts/release.py` | 三步骤＋研发树复位 |
| 判断记录 | `psl/judgment.json`、`scripts/run_harness.py` | 315 条断言 |
| 历史账 | `.workbuddy/memory/2026-10-19.md` | 0.53.1 全过程（含所有踩过的坑） |
| 长期纪律 | `.workbuddy/memory/MEMORY.md` | 版本纪律、判据纪律、活体闸 |

---

## 6. 交付标准（做到这些才算完）

1. `python ci/delivery_gate.py` → **34/34 全绿**（新判据并入现有套件，套件总数不变）。
2. `python scripts/run_harness.py` → **PASS，断言数 ≥ 315**（只许多，不许少）。
3. `python scripts/release.py` → 出 `antinel-0.53.2-*.whl` ＋ `*.tar.gz`，
   验收 A/B/C/D/E 全过，并自动完成研发树复位。
4. **活体回读**（四项都要，缺一不算）：
   - 有 `logo` 块时：哨标是动效（连续两帧像素不同）；
   - 无 `logo` 块时：哨标是**品牌静态 LOGO**，且审计链有 `logo_frame_unavailable`；
   - `/assets/favicon.ico` 与 `assets/logo/antinel.ico` 字节相同（0.53.1 已修，别回退）；
   - 服务/窗口重启后仍成立（这就是"活体闸"）。
5. 提交（中文说明，含根因、改法、判据、验证四段），并在
   `.workbuddy/memory/2026-10-19.md`（或当天文件）追加一段：做了什么、根因、
   哪些判据新增/改动、还剩什么。

---

## 7. 已完成的参照（0.53.1，别重做，但要保持）

1. **favicon 用姿态灯**已修：`inbox_server._brand_favicon_rel()` 从
   `inbox_window.BRAND_ICON_REL` 实时派生；favicon 已移出 `ASSET_WHITELIST`。
   判据 `B-15b` ＋负控 `N-B15b`（结构／派生／**字节真值**三条腿）。
2. **发布收尾自动化**：`release.py::_finalize_dev_tree` 自动做"补登研发树件 →
   version 回落 → `self_check()` 收口"。
3. **判据健壮性**：`0460` 夹具自证重试 2→4、每目标先重读一次、补 `N-S80c`；
   `0517 W17-d` 不再把"窗口最小化"判成几何失败。

---

## 8. 已知坑速查（卡住时先查这里）

| 症状 | 真因 | 处置 |
|---|---|---|
| 改了代码没效果 | daemon/serve 是旧进程 | 两个都杀，经 `explorer + lnk` 重拉（T3 要根治） |
| 窗口显示「失守：防护文件被改动」 | manifest 被刷成纯 wheel 口径 | `python _tools_034/_resign_manifest.py --adopt-dev`，再回落 `version` 到 `0.50.5` |
| 闸门 `regression D-23` 红"dist 缺本版件" | 出包前必然红 | 只在 `release.py` 里跑，才带 `ANTINEL_BUILD_IN_FLIGHT=1` |
| `0431 S70` 红"版本落差为 0" | manifest version 被刷平 | 回落 `0.50.5` |
| `0516 PKG16-c` 红"清单版本超前验收日志" | `output/p12_verify_release.log` 是旧版 | 重跑 `scripts/verify_release.py > output/p12_verify_release.log` |
| `0460 S80` 报"夹具失效" | 本机进程启动 0.6–1.9s，产品 `VCT_TIMEOUT=2.0` | 机器空载重跑；不许调大产品超时 |
| `0515` 超时 | `host-scan --json` 单跑 49s，负载下会翻倍 | 空载重跑，别并发 |
| 回读 403 | 端口漂移 / 用了仓内旧 `url.json` | 只读 `~/.antinel/console/url.json` |
| 命令行被 SEC-05 拦 | 命令文本含 `cookies` 等字面量 | 探针写成文件再执行 |
| `/assets/*` 403 | 缺 httpOnly cookie | 先取页面拿 `antinel_t` |
| pexpect 式截图取不到哨标 | 分层窗（per-pixel alpha）不走屏幕合成 | 别指望截图，用 `WM_NCHITTEST` ＋ 动作文件 ＋ 帧差 |
| git 报 "must be run in a work tree" | `core.bare` 被改 | 查 `git config core.bare` |

---

## 9. 交接检查表（收工时逐条打勾）

- [ ] 34/34 闸门绿
- [ ] harness PASS ≥315
- [ ] `FLO-11` / `FLO-12`（及 T4 的 FLO-13/14）新增，各自有负控且实测判红
- [ ] 三种输入（有规格／无规格／帧脚本坏）都画品牌，后两种有审计事件
- [ ] 高 DPI 若未做完，在汇报里明确写"未做/半做"，不许含糊
- [ ] 出包 0.53.2 两件齐全，验收全过
- [ ] 研发树复位（`self_check()` 返回 True，manifest `version=0.50.5`）
- [ ] 提交完成，说明含"根因／改法／判据／验证"
- [ ] 当天记忆文件追加一段
