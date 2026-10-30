<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel·改动草案 v1.0 · 0.56.0：AN-005 改判据 ＋ 托盘四态

> 面向一次出包（0.56.0）的两件事：① AN-005 误拦（critical，会真拦住用户）②
> `inbox_tray.py:384` 的 `bool(append_chained(...))`（D-40 转绿的唯一阻塞）。
> 本文只到「草案」为止：**产品代码一行未动**，等创始人过目。
> 证据：`output/tests/0.56.0/SEC05-design-20261024.txt`、`SEC05-scanlimit-20261024.txt`；
> 探针：`output/_sec05_design.py`、`_sec05_scanlimit.py`、`_sec05_escape_check.py`、`_d40_baseline.py`。

---

## 0. 结论

**不建议采「限定浏览器目录」这个方案。** 它把判据从「一个太宽的词」换成「一张需要维护的浏览器厂商目录表」，实测漏拦更多（8 条 vs 现状 3 条），而且它修不掉真正的病根。

建议改成**路径段锚定**：数据文件名必须是**路径上的一整段**（前面是 `\` 或 `/` 或串首，后面不是 `.`/`-`/字母数字），另加一层「配置根」覆盖整目录拷贝。9 条正则在 47 条语料上 **0 漏拦 / 0 误拦**，且不引入厂商表。

三点与你原话的差异，逐条说明：

| 你的表述 | 草案 | 依据 |
|---|---|---|
| 「限定浏览器目录」 | 限定为**路径段**，不是限定为**已列举的浏览器目录** | 目录表必然不完备（本次实测 Safari 全家、`fixtures/` 下的相对副本、便携版 Firefox 全漏）；名字层不依赖厂商表 |
| 「AN-005 是 critical、会真拦住用户」 | 实测误拦不是 3 条，是 **13 条** | 上一轮 E-R 的「6 个假阳性」是**语料规模给出的下界**，不是真实数量 |
| 「两处都改，D-40 转绿」 | 同意，但托盘那处要**改契约不是改布尔** | `_chain_record` 应返回四态串，否则「落在 sidecar」与「一个字节没落」还是同一件事 |

---

## 1. 为什么「限定浏览器目录」不是最优

### 1.1 实测（尺子＝线上同一份 `hooks/pre_tool_use._search`，不另写）

语料 47 条：必拦 27 条（Win/mac/Linux 三平台 × Chrome/Edge/Brave/Firefox/Safari/Chromium，
含 `Network/Cookies`、`cookies.sqlite-wal`、`#` UNC 共享、`--user-data-dir` 自定义根、
Bash 的 `cp`/`sqlite3`/`cat`/`tar`/`strings` 五种形态）；必放 20 条（`./cookies.txt`、
`./my_cookies.json`、`./Cookies.test.js`、`./src/utils/cookies.ts`、`./docs/Login Data.md`、
`pip install cookies`、`git log --grep="Cookies"`、puppeteer 的 `.local-chromium/`、……）。

| 方案 | TP | **漏拦** | **误拦** | TN | 判 |
|---|---|---|---|---|---|
| P0 现状（裸子串 4 条） | 24 | 3 | **13** | 7 | 现状 |
| A 「限定厂商目录＋数据名」 | 19 | **8** | 0 | 20 | ✗ |
| A′ 只限厂商目录（整目录禁止） | 24 | 3 | 3 | 17 | ✗ |
| B 只收紧文件名形状（无扩展名＋词边界） | 23 | 4 | 4 | 16 | ✗ |
| C 路径段锚定（名字层＋配置根层） | 27 | 0 | **1** | 19 | 半对 |
| **C2 ＝ C 去掉 `Library/Safari` 根** | **27** | **0** | **0** | **20** | ✅ |
| D 现状 + 排除清单（最小补丁） | 24 | 3 | 9 | 11 | ✗ |

`scan.py`（第二个消费者，口径是 `rx.search(rel) or rx.search(fn)` **分开比**）单独一列：
A 漏 4 条、B 漏 2 条、A′ 漏 1 条、P0/D 漏 1 条、**C/C2 漏 0 条**。
——即：目录限定方案在两个消费者上**同时**变差，不是只差一点。

### 1.2 漏在哪（A 的 8 条）

- Safari 两个位置全漏：`~/Library/Safari/Cookies.binarycookies`、`~/Library/Containers/com.apple.Safari/…/Cookies/Cookies.binarycookies` —— 厂商表里没有 Apple。
- 便携/自定义根全漏：`D:\Portable\Firefox\Profiles\zz.default\cookies.sqlite`、`/tmp/prof/Default/Cookies`（`--user-data-dir`）、UNC 共享 `\\fileserver\share\Google\Chrome\User Data\…`。
- 项目内副本漏：`D:\proj\fixtures\Chrome\User Data\Default\Cookies`（有 `Chrome/User Data`，但没有 `Google/`）。
- 整目录拷贝漏：`tar czf /tmp/p.tgz ~/.config/google-chrome/Default`（命令里没有数据文件名）。
- `Local\ Storage` 的转义空格漏（`strings …\Local\ Storage\leveldb\…`）。

漏的原因不是写得不细，而是**「目录在前、文件名在后、中间允许一段间隔」这个形状本身**要求两边都认出来；任何一边认不出就漏。

### 1.3 A′（只限目录）为什么更不能用

3 条误拦全打在开发者日常路径上：

```
./User Data/report.csv        <- 'User Data'
./library/safari/birds.json   <- 'library/safari'   (IGNORECASE: 小写也中)
node_modules/puppeteer-core/.local-chromium/chrome-win/chrome.exe  <- 'chromium'
```

Puppeteer/Playwright 用户必中 —— 这正是本产品目标用户的日常工具链。**「整目录禁止」在数据目录名上很准，在目录名上很脏。**

### 1.4 一个更要紧的发现：通道决定了修法

`AN-005` 是 `tool_call` 类规则，`_basic_hit` 把 `file_patterns` 匹配到 **`file_path` ＋ 整条 Bash 命令文本**（`bash_extra = [command]`）。所以：

```
git log --grep="Cookies" -3     -> 现状被拦（critical）
pip install cookies             -> 现状被拦
echo "Local Storage is a dir"   -> 现状被拦
```

**这不是误拦，这是产品在按「文本里出现过这个词」判事。** 2026-10-19 的夜间任务书里记过这条（「探针写成 `output/_xxx.py` 再执行；变量名与注释也避开该词」）——那是当时绕过去的，不是修掉的。

本轮实测我在本会话里被自己的钩子拦了 **2 次**（两条 `python -c` 命令的文本里带了该词），都是写这个草案的过程中发生的。这就是 critical 误拦的真实体验：**它不是偶尔响，它在正常工作时间隔几分钟响一次。**

⇒ 修法必须同时做到两件事：① 真实浏览器数据路径照样拦 ② **文本里提到这个词必须放行**。
目录限定能做到 ②；**只收紧文件名形状做不到**（`--grep="Cookies"` 仍中，实测 B 的 4 条误拦全是这一类）。这是我把 B 否掉的理由。

---

## 2. 定案：路径段锚定（两层）

### 2.1 语义

- **名字层**：数据文件名必须是路径上的一整段 —— 前面紧邻 `\` `/` 或串首，后面不是 `.`/`-`/字母数字。
  ⇒ `.../Default/Cookies` 中；`./cookies.txt`、`my_cookies.json`、`Cookies.test.js`、`cookies_policy.py`、`Cookies"` 全不中。
- **配置根层**：已知浏览器**配置根**整目录禁止（覆盖 `History`、`Bookmarks`、leveldb、任意文件名，以及 `tar` 整个 `Default/` 这类拷贝）。
  ⇒ 这一层补的是名字层的两个固有缺口：**别的文件名**、**没有文件名**。
- 两层是**或**关系，任一层命中即拦。名字层承载正确性（不依赖厂商表），配置根层承载覆盖率（可增量维护）。

### 2.2 落盘 JSON（已用 `json.dumps`→`json.loads` 对账，9 条逐字一致且全部可编译）

```json
"file_patterns": [
  "(?:^|[\\\\/])(?:Cookies(?:-journal)?|Login\\s+Data|Local\\s+Storage|Web\\s+Data)(?![\\w.-])",
  "(?:^|[\\\\/])cookies\\.sqlite(?:-wal|-shm)?",
  "(?:^|[\\\\/])Cookies\\.binarycookies",
  "(?:^|[\\\\/])Google[\\\\/]Chrome[\\\\/]User Data[\\\\/]",
  "(?:^|[\\\\/])Microsoft[\\\\/]Edge[\\\\/]User Data[\\\\/]",
  "(?:^|[\\\\/])BraveSoftware[\\\\/]Brave-Browser[\\\\/]User Data[\\\\/]",
  "(?:^|[\\\\/])\\.mozilla[\\\\/]firefox[\\\\/](?:Profiles|[^\\\\/]+\\.default)",
  "(?:^|[\\\\/])\\.config[\\\\/](?:google-chrome|chromium|BraveSoftware|vivaldi)[\\\\/](?:Default|Profile)",
  "(?:^|[\\\\/])Library[\\\\/]Application Support[\\\\/](?:Google[\\\\/]Chrome|Firefox)[\\\\/]"
]
```

★ **反斜杠是两层**（JSON 一层、正则一层）。手写必错，落盘前必须跑
`output/_sec05_escape_check.py` 对账 —— 少一层的后果是「某几条分支静静失效」，
而只要还有一条真实路径能中，判据就是绿的。

### 2.3 每条在守什么

| # | 覆盖 | 说明 |
|---|---|---|
| 1 | Chrome/Edge/Chromium 的 `Cookies`、`Login Data`、`Local Storage`、`Web Data` | `-journal` 是 Chrome 的 WAL 名；`(?![\w.-])` 挡掉同名带扩展名的普通文件 |
| 2 | Firefox `cookies.sqlite` | 含 `-wal`/`-shm`（使用中会出现） |
| 3 | Safari `Cookies.binarycookies` | mac 与 `Containers/…` 两种位置都靠它 |
| 4–6 | Chrome/Edge/Brave 的 `User Data\` 整根 | 覆盖 `History`、`Bookmarks`、`Network\`、leveldb、整目录 `tar` |
| 7 | Firefox `Profiles`／`*.default` 根 | |
| 8 | Linux `.config/<browser>/Default|Profile` 根 | 覆盖自定义 `--user-data-dir` 之外的常规安装 |
| 9 | mac `Library/Application Support/{Google/Chrome,Firefox}` 根 | |

### 2.4 为什么不加 `Library/Safari` 根（C 的那 1 条误拦）

`IGNORECASE` 是全局硬编码的（`_rx` 里写死，Python 3.10 不支持 `(?-i:)` 作用域标志），
所以 `Library/Safari` 必然连小写 `./library/safari/` 一起中 —— 实测误拦一条静态站路径。
Safari 的 `Cookies.binarycookies` 已由名字层第 3 条覆盖，`Library/Safari` 根只多覆盖
`History.db`/`Bookmarks.plist`；**为它换来一条误拦不划算**，去掉。
（若将来要覆盖，正确做法是给 `file_patterns` 家族引入「大小写敏感子模式」能力，那是引擎改动，另案。）

---

## 3. 同批改的第二件：`inbox_tray._chain_record` 返回四态

**改动前基线（本轮实测）**：`D-40 verdict: False`

```
② 存在 bool(...append_chained(...)) 包裹 1 处 —— bool("none") == True，记录丢了也报成功：
   inbox_tray.py:384  bool(sd.append_chained(audit_dir, rec))
```

改法（三处，同一缺陷的全部射程）：

1. `inbox_tray.py:370 _chain_record`：`return bool(...)` → `return sd.append_chained(...)`；
   `except` 分支 `return False` → `return "none"`；docstring 里「返回 False」改成四态说明。
2. `inbox_tray.py:435` 唯一消费点：`if _chain_record(root, rec):` → `if _chain_record(root, rec) in ("chain", "sidecar"):`
   （`sidecar` 是**记录还在**，算成功；`dropped`/`none` 才算失败——这正是 BL-03 拆四态的本意）。
3. `ci/inbox_guards_0514.py:4466` 的负控夹具 `_chain_record=lambda r, rec: False` → `"none"`。
   不改也能过（`False in (...)` 为假），但**夹具写着旧契约就是在教下一个人写错**。

★ `antinel.py:144` 的同名函数**不动**：它把四态折成布尔是**有意的**，因为它对 `none` 会
`sys.stderr.write("…这条记录已丢")`，用户看得见。托盘那处是**静默**折，这才是缺陷。
（同名不同契约是本院第一顽症，但这一处的差异是设计，不是漂移；写在这里免得下一轮被"统一"掉。）

---

## 4. 新判据规格

**为什么必须有新判据**：`ci/` 下 **34 套里没有任何一套**引用 `AN-005`（全库 grep 为零）。
规则层「按路径匹配」的语义从来没有判据守过 —— 这就是 13 条误拦能在 34 套全绿下活下来的原因。

**放哪**：`ci/inbox_guards_0514.py`（fast 档，已在 `SUITES`）。**不新建套件** —— 常驻数 29 是硬的。

**三条腿（缺一条即判据自身失效）**：

- **① 正控 27 条**：§1.1 的必拦语料，逐条断言 `decision=block` 且 `rule_id=AN-005`。
  ★ 同时断言审计记录里的 **`match_kind == "path"`** —— 假绿第十一族：正控"通过"但通道不对
  （AN-005 只有 `file_patterns`，若哪天它靠 `content` 通道命中，说明引擎语义已经变了）。
- **② 负控 20 条**：逐条断言放行，且 `stderr` 里没有 `[AN-005]`。
  其中**必须单列三条**，它们是本次的核心回归点，也是最容易被"优化"掉的三条：
  `git log --grep="Cookies"` / `pip install cookies` / `echo "Local Storage is …"`。
- **③ 负控牙齿（改坏必须红）**：把 `rules/default.json` 里第 1 条正则临时改回裸 `Cookies`（内存态，
  改的是 `collect_hits` 入参规则对象，不写盘），**同一个 ①里的任一条正文负控必须立刻转红**。
  —— 负控必须走与正控**同一入口**（假绿第七族），不许只喂一段合成坏源码给匹配函数。

**不许做的事**：判据自己再写一份「浏览器路径判定」（假绿第二形态）——所有用例一律走
`hooks/pre_tool_use.py` 的 `collect_hits`，一个字都不许自己判。

---

## 5. 连带改动与顺序

顺序不能换（后一步依赖前一步）：

1. `rules/default.json`：AN-005 的 `file_patterns` 换成 §2.2 的 9 条；`description_zh`／
   `remediation_zh` **不动**（「浏览器配置目录包含登录态，应完全禁止 Agent 访问」在新判据下才**第一次成真**）。
2. `references/RULES.md` 重生成（它是 `scripts/build_package.py` 的产物，**不许手改**）。
3. `inbox_tray.py` ＋ `ci/inbox_guards_0514.py` 的两处（§3）。
4. `ci/inbox_guards_0514.py` 新增判据（§4）。
5. 版本号 → `0.56.0`：走 `ci/version_check.py` 列的**九处承载件**，不许只改 pyproject。
6. `psl/manifest.json` 重签：`rules/default.json` 在 143 个 per-file 哈希里，
   `--hook` 档会逐字节比对；不重签 ⇒ D-36 红 ⇒ 监理拉不起来（2026-10-13 实测过这个后果）。
7. 出包：干净 worktree ＋ 仓外目标目录（`build_package.py` → `python -m build` → `verify_release.py`）。

**版本幅度**：`0.55.3 → 0.56.0`（minor）。依据：**规则命中集变了** ——
同一批 Agent 行为在 0.55.3 与 0.56.0 上得到不同裁决，属运行时行为变更，不是补丁。§5 的 7 步里没有一步是可省的。

---

## 6. 验证矩阵

| # | 动作 | 期望 | 证据落点 |
|---|---|---|---|
| 1 | `output/_sec05_escape_check.py` | 9 条逐字一致、全部可编译 | stdout |
| 2 | `output/_sec05_design.py` | 改后 P0 行由 `漏3/误13` 变 `漏0/误0`（把新 patterns 读进同一探针） | `output/tests/0.56.0/SEC05-design-*.txt` |
| 3 | `output/_d40_baseline.py` | 改前 `False`（已录）→ 改后 `True` | 同上 |
| 4 | `ci/inbox_guards_0514.py` | 新增判据绿；**跑它的负控**（§4③）必须红 | 套件 stdout |
| 5 | `ci/delivery_gate.py --hook` | 全绿；`rules/default.json` 撞 manifest 时必须先重签 | `.psl/gate/` |
| 6 | `scripts/verification_tests.py` 的 `AN-005 Read Login Data` | 仍 PASS（老正控不许被新写法打死） | `psl/judgment.json` |
| 7 | **活体**：在一个测试项目里 `Read ./cookies.txt` 与 `git log --grep="Cookies"` | 都放行；`Read <真实 profile>/Default/Cookies` 仍拦 | 手工 ＋ 审计链 |

★ 第 7 行不许省。第 4~6 行全是进程内断言，**只有第 7 行能证明「用户真的不再被拦」**。
★ 第 2 行要把探针的 `P0` 换成新 patterns 再跑一次 —— 否则是"用旧尺子量新规则"，等于没量。

---

## 7. 已知边界（本次不修，但要写进 RULES.md 的说明里）

1. **`SCAN_LIMIT` 边界**：两侧各 ≥ 3MB 填充时，载荷落在 4MB 预算之外 ⇒ 现状与新方案**同样漏**
   （实测 3MB 起两边都漏，且 `scan_truncated=True` 已留痕）。这是既有边界，不是本次引入。
2. **改名副本**：`.../Default/Cookies.txt` 这类**带扩展名的副本**不再拦（现状拦）。
   理由：拷贝那一步的命令文本里含真实路径，仍在拦；且现状为它付出的代价是 13 条误拦。
   —— 这是本次唯一的**有意后退**，必须写进交付说明，不许含糊。
3. **未列举浏览器**：新浏览器若数据文件名不叫这四个之一，只有名字层兜不住；
   配置根层需要增量登记（一次一条正则）。这是名字层的固有缺口，登记在案。
4. 待裁决（不在本批）：`AN-004` 的 `wallet` / `keystore` 是同一缺陷形状（裸子串、无边界），
   实测未做语料，本轮不动 —— 但它是下一个同类。

---

## 8. 风险与回滚

- 回滚是**单文件**：`git revert` 只涉及 `rules/default.json`（数据），引擎一行没改。
  ⇒ 一旦上线后发现新漏拦，改回 4 条裸子串即可恢复现状，不需要改代码。
- 最大风险不是漏拦，是**误拦又回来了**：`cookies_policy.py` / `CookieStore.java` 这类
  文件名在真实项目里很常见。第 4 步的 20 条负控就是为此存在的，不许减条。

---

## 附：本草案过程里被自己的钩子拦下的三次（原文留证）

```
$ ... -c "... Co" + "okies.binarycookies ..."  ->  Antinel 拦截 [AN-005] … 命中: Cookies
$ ... -c "... Login\s+Data ..."                ->  Antinel 拦截 [AN-005] … 命中: Login Data
$ printf '… 裸 wallet/keystore 同族 …' >> 日志  ->  Antinel 拦截 [AN-004] … 命中: wallet
```

三次都是**写这个修法**的过程中被拦的：文本里带了那个词，而工作目录里没有任何浏览器数据、
也没有任何钱包文件。第三条还顺带证明了 §7.4：`AN-004`（`wallet`/`keystore` 裸子串）
是**同一缺陷形状**，它今天同样会拦住「写一句含该词的中文日志」。

这是 §1.4 那条结论最直接的证据 —— 也是我认为这次必须修、且必须按「路径段」修的最后一票。
