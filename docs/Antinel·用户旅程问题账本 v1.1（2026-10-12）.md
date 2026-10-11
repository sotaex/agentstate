<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel · 用户旅程与 Agent 旅程问题账本 v1.1（2026-10-12）

> **这一版回答的问题**：0.48.3 从「下载」到「用起来」整条路，对**人**和**对 Agent**分别顺不顺；不顺的地方修到什么程度才算完。
>
> **为什么 v1.1 把 Agent 单列出来**：v1.0 的七幕（发现→安装→首跑→接入→日常→信任核验→升级卸载）是按**人**的旅程写的。而实际装包的人里，**Agent 占大多数**——用户在 WorkBuddy / Claude Code / Cursor 里说一句"帮我装个安全审计"，后面全是 Agent 在做。Agent 的失败模式与人的**不同类**：人看到 60 行中文会自己找，Agent 不会；人试错三次还有耐心，Agent 一次失败就换方案（并且把这次"不好用"记进它对你的推荐里）。
>
> **实测环境**：Windows 11 · Python 3.13.14 · 用户名含中文（`C:\Users\大马\`）· WorkBuddy 会话内 · 纯净 `venv` 从 `dist/` 索引形态安装。

---

## 0. 一句结论

0.48.3 **装得上、跑得起来，但第一印象是负的，且对 Agent 不友好**：

- 装完第一次扫描就报 **CRITICAL**，而那条 CRITICAL **是我们自己写进去的**；
- 装完以后，Agent 手里只有一个 `antinel` 命令，**没有一条路径能告诉它下一步干什么**（`--help` 是给人看的 60 行营销文案，SKILL.md **不在 wheel 里**）；
- 在 WorkBuddy 里装钩子会**静默装到 `.qoder/` 下并打印成功**，而那个文件 WorkBuddy 根本不读。

0.48.4 逐条修掉，并新增 `antinel agent --json` 作为 Agent 的唯一入口。

**本账本条目统计**（脚本按表格行 `^\|\s*[ABCD]\d` 计数，不心算）：共 **20** 条 ——
Agent 路径 8 · 首印象 6 · 量具 4 · 自引入回归 2。

> ⚠ 记一笔自己的口径错：初稿的 git 提交信息把这批工作写成"26 项"，那是把 `git`
> 报的 **26 files changed**（文件数）当成了账本条目数。两个数各自都真、分母不同，
> 与 F40「口径混装」同型。**对外一律用本条的分母（20 条＝表格行）。**

---

## 1. 实测方法与取证

| 项 | 做法 |
|---|---|
| 安装形态 | `pip install --no-index --find-links dist antinel`（最接近索引语义：走元数据与依赖解析） |
| 测试目录 | ① `D:\_ant_fresh`（仓外全新空目录，git 之外）② `_uxtest2/20261011-231500/proj`（仓内子目录，附带验证 git 根解析） |
| 对照 | `git worktree add _uxtest2/base0483 HEAD` 建 0.48.3 对照树，区分"我改出来的"与"本来就有的" |
| 证据落点 | `_uxtest2/20261011-231500/`（**零删除**，临时 `venv` 与项目目录全留） |

---

## 2. Agent 路径（本次重点）

| # | 问题 | 实测证据（0.48.3） | 处置 | 正判据 | 反向对照（撤销即红） |
|---|---|---|---|---|---|
| A1 | **wheel 里没有 SKILL.md**——Agent 装完拿不到任何机器可读的操作手册 | 0.48.3 wheel 133 个成员，`SKILL.md` 命中 **0**；`site-packages` 下也没有 | 构建器把 SKILL.md 复制进 `psl/`（`package-data` 已声明 `*.md`，随 wheel）；新增 `antinel skill [--path]` | 干净 `venv` 装 wheel 后 `antinel skill --path` 返回一个存在的文件 | 从构建器的复制清单里摘掉 SKILL.md ⇒ `antinel skill` 返回 2，判据红 |
| A1b | **SKILL.md 的真源是 `build_package.py` 的 `SKILL_MD` 模板，不是仓根那一份**——改仓根会被构建器静默覆盖 | 我改完仓根 SKILL.md 后跑了一次构建，回来一看文件已被还原成旧版 | 正文改动全部落到 `SKILL_MD` 模板（frontmatter 的 `%(...)s` 占位符原样保留） | 模板渲染后含 `antinel agent --json` 与 `pip install antinel` | — |
| A1c | **README.md 恰好相反**：它是**仓拥有件**，构建器只在 `final/README.md` 缺失时才用模板兜底 | `build_package.py:2757` 的注释与 `if not (final/"README.md").is_file()` 守卫 | 直接改仓根 README | 构建后仓根 README 的改动仍在 | — |
| A2 | **`antinel --help` 是给人看的 60 行文案，Agent 从中得不到入口** | `--help` 全文无 `install` / `skill` / `agent` 字样；"你可以对 Agent 说"那一段对 Agent 本身是噪音 | 新增「如果你是 Agent」四行段；新增 `antinel agent --json` 返回结构化状态与下一步 | `antinel --help` 含 `antinel agent --json`；`agent --json` 可 `json.loads` 且含 `installed`/`next_steps` | 摘掉 help 里那段 ⇒ 判据红 |
| A3 | **CLI 里没有 `install`**——装钩子必须记住 `python -m scripts.install` 这一串 | 0.48.3 的 `add_parser` 清单里没有 `install` | 新增 `antinel install`（委派 `scripts.install.main`，参数对齐） | `antinel install --check` 与 `python -m scripts.install --check` 退出码一致 | 让委派吞掉参数 ⇒ 两者不一致 ⇒ 红 |
| A4 | **宿主归因有两套实现，结论相反** | 同一台机器：`antinel` CLI 认 `workbuddy`；`scripts/install.py` 只认 claude-code/zcode/qoder，且在 `D:\_ant_fresh` 装进了 `.qoder/settings.json`（WorkBuddy 不读） | install 改用 `hooks/_host_detect` 作唯一来源；workbuddy/trae 落 `generic` 并**明说**"未接入，非装失败" | 有 `.zcode` 的目录 → zcode；有 `.workbuddy` 的目录 → generic 且输出含"只装了审计与扫描" | 退回 home 标记优先 ⇒ `.workbuddy` 项目被装进 `.qoder` ⇒ 红 |
| A5 | **包名与技能名不一致**：pip 上是 `antinel`，技能叫 `antinel-security` | —（属可预见摩擦，无实测失败） | README 顶部、SKILL.md 安装节、`--help` Agent 段三处明写"包名是 antinel" | 三处均含 `pip install antinel` 与"不是 antinel-security" | 任一处删掉 ⇒ 红 |
| A6 | 输出的发现只能靠解析中文 | — | `python -m scripts.scan --json` 已有；`agent --json` 的 `next_steps` 直接指向它 | `next_steps` 里含 `--json` 命令 | 改为纯文本命令 ⇒ 红 |

## 3. 人与 Agent 共患（首印象）

| # | 问题 | 实测证据 | 处置 | 反向对照 |
|---|---|---|---|---|
| B1 | **装完第一次扫描就自报 CRITICAL** | `D:\_ant_fresh`（全新空目录）装完：`🔴 CRITICAL (1)` `Security Score: 80/100 B`，命中文件是 `.psl/rules/default.json:666`，匹配串 `AKIAIOSFODNN7EXAMPLE`——**我们自己写进去的规则测试夹具** | 扫描排除 Antinel 自己的状态件（`.psl/rules`、`.psl/audit`、`.psl/state`、`manifest/scan_last/hooks/policy.json`） | 把 `.psl/rules` 放回扫描面 ⇒ 空目录装完重现 CRITICAL ⇒ 红 |
| B1b | **二次扫描自伤放大**：`scan_last.json` 里记录了上一次的 match 文本（含密钥字面量），第二次被自己扫到 | 视 `files scanned: 6` 的报告里 CRITICAL 变 **2** 条（default.json + scan_last.json）；在 git 仓子目录跑时膨胀到 **98** 条（扫到本仓测试夹具） | 同上：排除 `scan_last.json`，切断"上次输出被本次扫描"的循环 | 同上 |
| B2 | **`report` 末尾教一条安装态跑不通的命令** | 输出 `Re-scan: python scan.py`，而 `scan.py` 在 `site-packages` 里，不在项目根 | 改为 `python -m scripts.scan --root .` | 改回 `python scan.py` ⇒ 命令可达性扫描命中 ⇒ 红 |
| B3 | **`--check` 自报的版本与 `antinel -V` 打架** | `antinel -V` → `0.48.3`；`install --check` → `in sync: version 0.33.1`。两个数都是真的（一个是包版本，一个是钩子协议版本），但界面上无从分辨 | 输出改为「钩子协议版本 0.33.1 ／ 包版本 0.48.4」；`agent --json` 的键名由 `manifest_version` 改为 `hook_protocol_version` | 退回单一 `version` 字样 ⇒ 红 |
| B4 | **首次运行 stderr 抛 DeprecationWarning** | `scan.py:433: DeprecationWarning: 'locale.getdefaultlocale' is deprecated and slated for removal in Python 3.15` | 4 处调用换成 `_os_locale()`：3.15 前继续用 `getdefaultlocale` 但压掉警告，3.15 后走 `ctypes` 查 UI 语言 | 直接换 `locale.getlocale()` ⇒ 本机返回 `Chinese (Simplified)_China` 切不出 `zh`，中文用户看到英文 ⇒ 红（**实测过这个替代方案，它不行**） |
| B5 | **分类器只声明 Windows** | wheel 是 `py3-none-any`（纯 Python、无平台产物），只声明 Windows 是低报，PyPI 筛选会把 POSIX 用户挡在候选外 | 模板与仓库 `pyproject.toml` 同加 `Operating System :: POSIX`、`Operating System :: MacOS :: MacOS X` | — |

## 4. 量具缺陷（不是产品缺陷，但会挡住发布）

| # | 问题 | 实测证据 | 处置 |
|---|---|---|---|
| C1 | **`ci/inbox_guards_0470.py` 的 `_NOW` 写死成 `2026-10-10T23:30:00+08:00`** —— 一个 24 小时后必然引爆的时间炸弹 | 基线快照：`22:24:45` 时 0470 **PASS**；`23:43:17` 时 0470 **RED**（S93/N-S93/N-S93b/S95/S99/N-S99 六条同时）。在 `git worktree` 建的 0.48.3 对照树上跑，同样 6 红 ⇒ **与本次改动无关**。根因：产品侧 `_window_open(items, hours=24)` 只收窗口内记录，固定时点会随真实时间滑出窗口，`chans` 恒为空集 ⇒ dev 灯不亮 | `_NOW` 改为每次运行取当下（`_iso_now()`）。**没有再钉一个新的固定日期**——那只是把炸弹往后拨 |
| C2 | 随包 SKILL.md 的自证卡刷新只覆盖根目录那一份 | 组装阶段复制到 `psl/` 的那份**早于**自证卡刷新 ⇒ 包里那份会停留在"未验证" | `_sync_skill_selfcert` 的改写目标扩到 `SKILL.md` 与 `psl/SKILL.md` |
| C3b | **用正则扫 `add_parser` 来盘点子命令，会漏掉动态分派的那些** —— 差点据此判 `antinel domains` 不存在并去改产品 | 正则扫 wheel 内 `antinel.py` 得 45 个子命令，不含 `domains`/`paths`/`commands`；但 `references/AGENT_SKILL.md` 明写 `antinel domains add xxx`。实跑 `python -m antinel domains list` → **EXIT=0，输出「（空）」** —— 三者走 `elif args.cmd in ("paths","domains","commands")` 动态分派，压根没走 `add_parser` | **判据换成实跑**（`antinel <cmd> list` 看退出码），静态盘点只用来列候选。另：`AGENT_SKILL.md` 只随 sdist，wheel 里没有（已核对 `references/` 不在 wheel namelist），pip 装的 Agent 读不到它，两条手册不打架 |
| C3 | **自证卡刷新把 `psl/manifest.json` 里那条哈希搞过期** —— Agent 一跑信任核验就自曝"证据被动过" | 端到端 J6m 判红：`python -m tools.antinel_verify --manifest` → `[SUPERSEDED] 1 of 124 covered files differ`，`changed: psl/SKILL.md`。逐条比对确认**只有** `psl/SKILL.md` 真漂（`hooks/pre_tool_use.py` 那条形似不一致是假的——清单存的是 `_manifest_hash_of` 归一化后的哈希，与原始字节哈希本就不同，判据同法，不是漂移） | 顺序是结构性的：清单在 `build()` 装配段生成，`_refresh_skill_selfcert` 跑在 harness 之后 ⇒ 必然晚。修法是后者改完**回头重钉**清单里 SKILL.md 的哈希（`_rehash_manifest_for_skill`）。**改前先查自举**：judgment 覆盖的那 21 个文件里**不含** `psl/manifest.json` 也不含 `psl/SKILL.md` ⇒ 重钉不触碰 21/21 口径，无循环 |

## 5. 我在本次改动中引入、又被闸门/harness 抓出来的回归（诚实登记）

| # | 回归 | 谁抓到的 | 根因 | 修法 |
|---|---|---|---|---|
| D1 | harness 崩在 **88/315**（`FileNotFoundError: zc_proj/.zcode/config.json`） | `scripts/run_harness.py` | 新 `detect_host` 用 `_host_detect.detect()`（**env 优先**），而本机 WorkBuddy 会话设了 `CODEBUDDY_CONFIG_DIR` ⇒ 把"我在 WorkBuddy 里跑命令"读成"这个目录属于 WorkBuddy" ⇒ 不写 `.zcode/config.json` | install 场景改为**项目目录标记优先、env 兜底**（两者判的问题不同：`_host_detect` 判"这次调用来自谁"，install 判"装进哪个项目"） |
| D2 | 修 D1 后仍崩在同一处 | 同 | `install.py` 被当脚本直接跑时 `sys.path[0]` 是 `scripts/`，顶层 `hooks` 包不在路径上，`from hooks import _host_detect` **静默失败** | 新增 `_host_detector()`，显式把包根插入 `sys.path` |

> D1/D2 都是"改对了方向、但漏了运行形态"这一类。它们被抓到，靠的是**真跑 harness**——读代码看不出来。

## 6. 做了什么 / 没做什么（诚实登记）

**已做（本轮）**：A1–A6、B1–B5、C1–C2、D1–D2 全部落地；版本号 0.48.3 → **0.48.4**（minor，理由是运行时行为改变：新增子命令、宿主归因换源、扫描范围变化）。

**未做（不影响本次上传，登记在此）**

| 项 | 现状 | 为什么不现在做 |
|---|---|---|
| 为 `antinel-security` 在 PyPI 上注册同名占位包 | 只在三处文案里写明"包名是 antinel" | 注册新包名是**不可逆的外部动作**，且会牵出"这个包要不要也发版本"的维护问题；先靠文案把绝大多数歧义挡掉，看实际反馈再决定 |
| WorkBuddy 的钩子协议适配 | 落 `generic`（审计+扫描模式）并明说未接入 | WorkBuddy 的钩子契约本版没有实测依据；**猜一个目录静默装进去，正是 A4 要根治的那个病** |
| `docs/A6收入边界声明.md` 对 pip 用户不可达 | `docs/` 设计上只随 sdist，不随 wheel；README 已显式标注 | 这是既有设计，不是缺陷；改动会牵动 wheel 载荷与随包清单的口径 |
| macOS / Linux 的真机验证 | 分类器已按"CI 矩阵持续验证"声明补齐 | 本机只有 Windows；**没实测就说支持，是夸大** |
| 非提权终端下的行为 | 未实测 | 同 |

---

核验日 2026-10-12；生产仓 `D:\psl\poc\antinel-security`；本件撰写时版本 0.48.4。
