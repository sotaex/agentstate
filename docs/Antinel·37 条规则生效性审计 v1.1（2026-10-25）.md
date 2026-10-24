<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel · 37 条规则生效性审计 v1.1（2026-10-25）

> 问的是：**37 条是不是都生效、是不是都正常运转。**
> 答的是：**37 条都真的会响（第 37 条不是"关掉了"，是换了个实现位置——见 v1.1 更正）；3 条 MCP 规则曾经只拦一半、15 条曾没有任何判据守着、兜底集曾只兜得住 17 条。后三项已在 0.57.0 的 A／B／C 三步里修完，读数见各步。**

> **v1.1 更正（2026-10-25，C 步实测推翻 v1.0 的一处定性）**
>
> v1.0 写「第 37 条 `SLOP-01` 是 `enabled: false`，正确不命中」「OK（设计关闭）」。**这是错的。**
> 实测（`output/_c_zerocov_probe.py` ＋ 0514 的 `C-SLOP-01`）：`pip install reqeusts` 会命中
> `SLOP-01`，通道 `command`。原因是这条规则**根本不由规则引擎判定** —— 它在
> `hooks/pre_tool_use.py` 的 `_slop_hit()` 里按静态参考集（`rules/typosquat_top.json`）
> 做编辑距离／相似度特判（同 `_budget_hit` 先例）；`enabled: false` 只是把**通用正则**
> 那条关掉，避免 `(pip|pip3|npm)\s+install` 对每一次安装都报警。
> 所以正确说法是：**37 条全部在跑，其中 36 条走规则引擎、1 条走代码特判。**
> 0514 的 `C-SLOP-01b` 专门守这条双尺子（规则表里必须仍为 `enabled: false`）。
>
> 顺带记一条边界缺陷（未修，列进下一批）：`_slop_hit` 用「编辑距离 ≤2 或相似度 ≥0.85」，
> 短名过宽 —— 实测 `pip install foo` 报 `foo ≈ tox, 距离 2`。3 字名的距离 2 等于把
> 一整个短名空间都算作可疑。这是**误报**，不是漏报。


## 1 结论（四句话）

1. **没有一条是"死规则"**。37 条每条都用一条"人真的会做的事"样本打进去，**全部命中**；其中 36 条走规则引擎（33 条通道正确、3 条曾走偏 —— 见第 3 节），第 37 条 `SLOP-01` 走 `_slop_hit()` 代码特判（v1.1 更正，**不是**"设计关闭"）。
2. **误报这边是干净的**：7 条无害样本 × 37 条规则 = 259 个组合，**0 次误拦**。
3. **MCP-02/03/04 退化了**：它们现在实际等于"只要写 `.mcp.json` 就告警"，内容检测**结构上够不着**。三方向证据在 §3.1。
4. **15 条规则没有任何判据守着**（`ci/` 的可执行代码里一次都没出现，口径见 §3.2）—— 改坏了没人知道。那三条坏掉的 MCP 规则**当时都在这批里**，这不是巧合，是同一件事的因果。（已在 C 步补齐 19 条判据。）

## 2 逐条结果（37/37，无遗漏）

样本先用规则自己的 pattern 做**合法性预检**（预检不过就报"我的样本错了"，绝不报成"规则失效"）。通道一栏是引擎自己回的 `match_kind`。

| 规则 | 样本面 | 通道/动作 | 判定 |
|---|---|---|---|
| SEC-01 | file_patterns | path / block | OK |
| SEC-02 | file_patterns | path / block | OK |
| SEC-03 | file_patterns | path / block | OK |
| SEC-04 | file_patterns | path / block | OK |
| SEC-05 | file_patterns | path / block | OK |
| SEC-06 | content_patterns | content / block | OK |
| SEC-07 | command_patterns | command / block | OK |
| SEC-08 | command_patterns | command / alert | OK |
| SEC-09 | file_patterns | path / block | OK |
| SEC-10 | file_patterns | path / alert | OK |
| DST-01 | command_patterns | command / block | OK |
| DST-02 | 专用 check | path_outside_project_root / block | OK |
| DST-03 | file_patterns | path / block | OK |
| DST-04 | command_patterns | command / block | OK |
| DST-05 | command_patterns | command / alert | OK |
| DST-06 | command_patterns | command / block | OK |
| DST-07 | command_patterns | command / block | OK |
| DST-08 | command_patterns | command / block | OK |
| DST-09 | file_patterns | path / block | OK |
| DST-10 | command_patterns | command / block | OK |
| DST-11 | 专用 check | path_in_cloud_sync_dir / block | OK |
| NET-01 | command_patterns | command / alert | OK |
| NET-02 | command_patterns | command / alert | OK |
| NET-03 | 专用 check | domain_whitelist / alert | OK |
| NET-04 | command_patterns | command / alert | OK |
| CTX-01 | command_patterns | command / alert | OK |
| CTX-02 | content_patterns | file_content / block | OK |
| CTX-03 | 专用 detection | invisible_content / block | OK |
| CTX-04 | content_patterns | file_content / alert | OK |
| CTX-05 | 专用 metadata | metadata / alert | OK |
| CTX-07 | content_patterns | content / block | OK |
| MCP-01 | file_patterns | path / alert | OK |
| **MCP-02** | file_patterns | **path / alert** | **内容面不可达** |
| **MCP-03** | file_patterns | **path / alert** | **内容面不可达** |
| **MCP-04** | file_patterns | **path / alert** | **内容面不可达** |
| SEC-11 | file_patterns | path / alert | OK |
| SLOP-01 | 代码特判 `_slop_hit()`（`enabled:false` 只管住通用正则） | command / alert | OK（v1.1 更正：会响） |

**四条无 pattern 的规则都走通了各自的专用通道**，不是空壳：`DST-02`→路径越界、`DST-11`→云同步目录、`NET-03`→域名白名单、`CTX-03`→不可见字符扫描、`CTX-05`→frontmatter 与目录名比对。

## 3 三个真问题

### 3.1 MCP-02/03/04：内容检测面结构不可达（**确凿，双向证明**）

| 探针 | 做法 | 结果 | 说明 |
|---|---|---|---|
| A1 | 写 `.mcp.json`，内容**完全无害**（`{"command":"node"}`） | MCP-01/02/03/04 **全部告警** | 它不看内容 |
| A2 | 内容含注入＋远程 url＋明文密钥，但文件是 `notes.txt` | **0 命中** | 内容面完全用不上 |
| A3 | 同一次调用里 file_patterns 与 content 都满足，直接问 `_basic_hit` | `('/.mcp.json', 'path')` | 短路发生在**唯一实现**里 |

机制（`hooks/pre_tool_use.py` 的 `_basic_hit`）：先查 `file_patterns` → 命中就 `return (…, "path")` → 根本走不到 content 分支。而 `file_content` 规则那边还有一道反向闸：`file_patterns` 不命中就 `return None`。**两头都堵死**，内容模式成了死代码。

后果：这三条现在是「写 MCP 配置就响三声」的单条件规则 —— 误报高（正常改配置也响），漏报真（真正的注入描述只要不在 MCP 配置文件里就永不报警）。

### 3.2 15 条规则没有任何判据守着（v1.0 数成 14 条，口径更正）

**v1.1 更正**：v1.0 用的是「全文件子串出现」口径，把只在**注释里**被提到的 `MCP-02/03/04` 算成了"有判据"，同时漏掉了 `SEC-06/07/08`。改用「去掉注释与 docstring 后、可执行代码里是否出现该 id」重算，得到 **15 条**（`output/_c_zerocov_probe.py` 与 0514 的 `C-M1` 用的就是这把尺子）：

```
SEC-02  SEC-04  SEC-06  SEC-07  SEC-08  SEC-10  DST-03
DST-05  DST-06  DST-08  NET-02  NET-04  CTX-04  CTX-05  CTX-07
（另：SLOP-01 当时也不算在"有判据"里 —— 它只在 single_case_probe 的样本里出现过）
```

其中 **8 条 critical**：`SEC-02`（SSH 私钥）、`SEC-04`（钱包/keystore）、`SEC-06`（内容里的密钥字面量）、`SEC-07`（剪贴板）、`DST-03`（改 shell 配置）、`DST-06`（远程脚本管道）、`DST-08`（权限/属主破坏）、`CTX-07`（内联 base64 执行）。**它们现在能拦，但改坏了没人会发现** —— §3.1 那三条就是这么烂掉的。

**已在 C 步补齐**（0514 的 C 族，19 条判据）：15 条逐条「正控＋通道＋负控」＋ `SLOP-01` 双尺子守卫 ＋ `C-T1` 牙齿（改坏三条规则后必须翻红）＋ `C-M1` 结构不变量（37 条没有一条落在"无人提及"状态，且量具自带分辨率自证）。注意口径：**提到 ≠ 被守**；C-01…C-SLOP-01 是证据，`C-M1` 只是防止新增规则无人管。

### 3.3 兜底集只兜得住 17/37，缺的 20 条里有 5 条 critical

规则文件一旦校验失败（被改坏/读不出），hook 会回落内嵌 `_FALLBACK` —— 只有 **17 条**。消失的 20 条：

```
CTX-04 CTX-05 CTX-07 DST-05 DST-06 DST-07 DST-08 DST-09 DST-10
MCP-01 MCP-02 MCP-03 MCP-04 NET-02 NET-03 SEC-04 SEC-05 SEC-06 SEC-11 SLOP-01
```

含 **SEC-04（钱包）、SEC-05（浏览器凭据）、SEC-06（密钥字面量）、CTX-07（base64 执行）、DST-06（远程管道执行）**。

即：**"规则被篡改"这个最需要防的时刻，恰好是保护缩水到一半的时刻**。这不是理论风险 —— 本轮做牙齿测试时就实测过一次：只改规则内容不改 hash，hook 判 SELF-TAMPERED 并回落兜底集，SEC-05 当场消失（所以牙齿必须同步 `manifest.rules_hash`）。

**已在 A 步修完**（提交 `d29a127`）：`_FALLBACK` 从「17 条缩水副本」改为「与主表 37 条全等」，且旧 17 条本身还缺 47 个 pattern ＋ 6 处语义字段（DST-01 的 command 8/21、DST-04 的 file 3/13、CTX-02 的 `compound_nonprimary` 丢失），一并照抄补全。判据从 `j_fallback_has_no_dst10`（旧写法断言 `n != 17` 即红 —— 把"兜底只有 17 条"钉成了通过条件，修兜底反而红）改为 `j_fallback_matches_rules`（id 全等 ＋ 每字段逐字 ＋ 五个牙齿）。

## 4 "正常运转"的活体证据（不是只在进程内测出来的）

本轮会话里，规矩真的拦了我三次：

- `DST-01` 拦了两次：`shutil.rmtree` 探测器、`rmdir` 探测器（我把"删除目录"写进了命令行）。
- `SEC-06` 拦了一次：写审计脚本时，脚本里的**假**密钥字面量被当成真密钥拒收 ⇒ 我改成运行时拼接。

三条规则各自在自己的通道上、在我的真实操作上生效 —— 这是比任何夹具都硬的证据。

另两条消费路径也核过：

- `scripts/scan.py`（静态扫描）装到 **37 条，与 hook 完全一致**（两向差集皆空）。但注意它只跑**静态**子集；命令类规则在静态扫描里天然无效，这是设计，不是缺陷。
- `references/RULES.md` 里出现 **37 个规则号**，与 `rules/default.json` **完全同集**（多出 0、缺失 0）—— 文档和真源没有分叉。

## 5 这次**没有**核的（别把边界当结论）

| 未核 | 为什么 | 风险 |
|---|---|---|
| 每条规则的**误报率** | 只用了 7 条无害样本；不是全量语料 | 259 个组合 0 误拦 ≠ 生产无误拦 |
| 跨平台（posix 分支） | 本机是 Windows（`DST-09/10` 是 `platforms:["nt"]`） | Linux/macOS 上这两条不生效，属设计 |
| `scan.py` 静态子集的实际命中 | 只核了装载一致 | 静态扫描能否真报出东西，另需一轮 |
| ReDoS / 扫描预算 | 本次没压测 | `_search` 的分窗已由别的判据守 |

## 6 建议的处置顺序

| 优先级 | 事项 | 理由 | 状态 |
|---|---|---|---|
| P0 | 给 MCP-02/03/04 的内容面**开一条可达路径**（把 `file_patterns` 从"命中就 return"改成"命中才允许查内容"，或让内容面先于路径面判定） | 现在这三条既误报又漏报，等于没有 | **已完成**（B 步，`b55296f`） |
| P0 | 兜底集补齐到 37 条，或至少把 5 条 critical 补进去 | "被篡改时保护缩水"是方向性错误 | **已完成**（A 步，`d29a127`） |
| P1 | 给那 15 条补正控（8 条 critical 全在其中） | 没有判据守的规则，烂了没人知道 | **已完成**（C 步，0514 C 族 19 条） |
| P2 | `scan.py` 静态子集的实际命中补一轮 | 装载一致 ≠ 能报出东西 | 未做 |

证据：`output/tests/0.56.0/rules37-audit.txt`、`rules37-probe2.txt`；探针：`output/_rules37_audit.py`、`output/_rules37_probe2.py`。
