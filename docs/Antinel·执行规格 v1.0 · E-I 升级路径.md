<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel 执行规格 v1.0 · E-I 升级路径

> 计划 v1.7 §3.6 给的是**四行期望**；本文件把它细化成**可执行步骤**并已实跑。
> 结论先说：**计划那一版颗粒度不够**——照它跑不出来，且其中一条期望引用了已失效的机制（§0.1 r1-6）。
> 本件是「执行阶段」的第一件，也是**颗粒度模板**：后续每一件都按这个形状写。

---

## 1. 为什么先做这一件

| 理由 | 可核对的事实 |
|---|---|
| 唯一有 deadline | 明天推 N 家试用企业，他们第一个动作就是 `pip install -U` |
| 计划里覆盖为 0 | §7.1「升级路径 ≥4 条 / **0**」 |
| 今天就能做 | PyPI 现有 `0.48.4 / 0.55.0 / 0.55.1 / 0.55.2 / 0.55.3`（实查 `pip index versions antinel`），不需要重新构建 |
| 能一次证伪多条假设 | 「升级会不会丢数据」「漂移检不检得出」「规则快照会不会跟着更新」——三条都是企业会问的 |

---

## 2. 颗粒度评估：计划 §3.6 离「可执行」有多远

一个步骤要能被**别人照着重跑**，需要七个要素。用这把尺子量计划 §3.6 的四行：

| 要素 | §3.6 原状 | 缺口 |
|---|---|---|
| ① 前置状态（从哪开始） | 只写「0.48.4 装过的项目」 | 没有说项目里有什么、装在哪、HOME 指哪 |
| ② 命令原文 | **0 条** | 只有「`pip install -U`」五个字，没有完整命令、没有 `--root` |
| ③ 隔离与落点 | **无** | 会去碰真 `~/.antinel`（19 项真实数据） |
| ④ 期望（rc ＋ 结构断言） | 半句，且**引用了作废的机制**（「11 条兜底」） | 无 rc、无字段级断言 |
| ⑤ 失败判据（什么算红） | **无** | 红了也不知道红在哪 |
| ⑥ 证据字段（写进哪） | **无** | 维度 AO 当时还不存在 |
| ⑦ 预算（秒） | **无** | 维度 AP 当时还不存在 |

**判读**：4 行里能算「齐了」的要素是 **0 个**。这不是写得粗，是**形状不对**——
它是一份「要检查什么」的清单，不是一份「怎么跑」的规格。⇒ **必须先细化**，直接执行只会得到
一堆「看起来跑过了」的印象。

---

## 3. 细化后的规格（12 步，实跑 17 个断言）

隔离：`USERPROFILE=<临时>`（**不是 `HOME`**，见 §4-1）＋ `ANTINEL_HUB_DIR=<临时>/hub`；
所有子进程 `cwd` 在临时树内（防止仓根 `antinel.egg-info` 污染版本读数，见 §4-3）。

| 步 | 前置 | 命令 | 期望（结构断言） | 预算 |
|---|---|---|---|---|
| **E-I-0** | 临时树已建 | `python -c "print(os.path.expanduser('~'))"` | 指向临时 home | 2s |
| **E-I-1a** | — | `python -m venv venv_old` | rc=0 且 `Scripts/python.exe` 存在 | 20s |
| **E-I-1** | venv_old 干净 | `pip install antinel==0.55.0` | rc=0 且 `metadata.version=="0.55.0"` | 40s |
| **E-I-2** | 已装旧版 | `antinel install --root proj --host generic` | rc=0 ＋ `.psl/manifest.json` ＋ `.psl/rules/default.json` 都在；记录 `manifest.version` 与快照 sha | 30s |
| **E-I-3a** | install 完成 | **真调 hook 三次**：`python <sp>/hooks/pre_tool_use.py`，stdin 喂 `{"tool_name","tool_input","session_id"}`（放行/拦截/写文件各一） | 三次都跑通；**拦截那次 rc≠0**（0.55.0 实测 rc=2） | 15s |
| **E-I-3b** | 有记录 | `antinel report --days 7 --write` | rc=0 | 10s |
| **E-I-3b2** | 同上 | `antinel ledger --json` | rc=0（本项目没往中枢账写 ⇒ `events:null` 属正常，见 §4-5） | 5s |
| **E-I-3c** | 同上 | 数 `proj/.psl/**/*.jsonl` 行数 | **records > 0**（前置条件，缺了后面全是空集假绿） | 1s |
| **E-I-4** | — | `pip install -U antinel==0.55.3`（就地替换） | rc=0；**本机不可执行**（§4-4），显式记 `environment_blocked` | 60s |
| **E-I-5** | — | 建 `venv_new` ＋ `pip install antinel==0.55.3` | rc=0 且版本==0.55.3；**项目快照 sha 不变**（升级不动项目） | 60s |
| **E-I-5b** | E-I-5 | 比 `proj/.psl/rules/default.json` 升级前后 sha | 同一 sha | 1s |
| **E-I-6** | 换包后 | `antinel install --check --root proj` | **rc=3**（drift），且列出「版本/哈希不一致」的具体项 | 10s |
| **E-I-7** | E-I-6 红 | `antinel install --root proj --host generic` | rc=0 | 30s |
| **E-I-7b** | — | `install --check` 再跑 | rc=0 | 10s |
| **E-I-7c** | — | 比项目快照与 `site-packages/rules/default.json` | **字节相同**（同一 sha） | 1s |
| **E-I-8** | — | `antinel report --days 7`（cwd=proj） | rc=0 且输出非空（不是空态） | 10s |
| **E-I-8c** | — | `antinel verify`（cwd=proj） | rc=0（链完整；4=空链不算过） | 10s |
| **E-I-8b** | — | 数 jsonl 行数 | `after >= before` **且 `before > 0`** | 1s |

**总预算**：约 5 分钟（实测 4m34s）。失败判据统一为：任一非 blocked 步骤 `ok=False` ⇒ 该件不通过。

**证据落点**（维度 AO 首次启用）：`output/tests/0.55.3/I-upgrade-<YYYYMMDD-HHMM>.json`，
字段：`spec / from / to / ts / verdict / failed_steps / not_run / base / isolation / host_python / steps[]`，
每个 step 带 `id / title / cmd / rc / expect / ok / blocked / out_tail / extra`。

**执行器**：`output/_e_i_upgrade.py`（本文件的机械实现，不是探针——它自带期望与失败判据）。

---

## 4. 本机五条环境事实（都改变了「怎么跑」，已写回计划 §3.0 与 §3.6）

1. **Windows 上 `set HOME=` 无效**。`os.path.expanduser("~")` 只认 `USERPROFILE`；
   实测设 `HOME=D:/_antmp/fakehome` 后仍返回 `C:\Users\大马`，设 `USERPROFILE` 才生效。
   ⇒ 任何「隔离 HOME」的模板必须写 `USERPROFILE`，否则**测的是真 HOME**。
2. **`ANTINEL_HUB_DIR` 不是全局替换**。全仓只有 `antinel.py:1765` 一处消费它，且只管
   「门闸哨兵那条链」的去向；其余十余处 `~` 都走 `expanduser`。
3. **仓根 `antinel.egg-info` 会污染版本读数**。它记的是开发树版本（0.55.1），
   而 venv 里装的是 0.55.0；在仓根跑 `importlib.metadata.version("antinel")` 会读到 **0.55.1**。
   ⇒ 所有版本对账类判据必须 **cwd 在仓外**，否则「装了哪个版本」这件事从第一步就是错的。
   （我第一次跑就是这么错的，见 §5。）
4. **本沙箱不能就地升级包**。`pip install -U` 要删旧安装，删除被拒（EACCES / `WinError 5`，
   落在 `site-packages\~_pycache__`）。A/B 对照已证明**与我们产品无关**：
   不跑 `antinel install` 的对照组一样失败（`output/_e_i_ab.py`）。
   ⇒ 本机用「两个干净 venv ＋ 同一项目目录」做**等价替换**；pip 的卸载步骤记 `未跑`。
5. **「读数据」有两个源，不是一回事**。`report` 读**项目链** `.psl/audit/*.jsonl`；
   `ledger` 读**中枢账** `<hub>/ledger/daily.jsonl`。只有项目链数据时 `ledger` 恒为
   `events:null` —— 我第一次把 `ledger` 当「读回旧数据」的断言，判成失败，**是测量对象选错**。

---

## 5. 首次执行结果（`output/tests/0.55.3/I-upgrade-20261024-0956.json`）

**PASS｜17 步通过 ／ 0 失败 ／ 1 未跑（环境阻断）**。产品侧四条有效结论：

| 结论 | 证据 |
|---|---|
| **换包后漂移检测有效** | `install --check` rc=**3**，列出 **7** 项：`rules_hash` 不符 ＋ 6 个脚本 hash 不符（`pre_tool_use / antinel / strings / scan / install / report`），并给出 `fix: python -m scripts.install --root …` |
| **换包不改项目数据** | 项目规则快照 sha 换包前后一致 |
| **刷新后回到一致** | 重跑 install 后 `--check` rc=0，且快照与包内 `rules/default.json` **字节相同** |
| **旧数据可读、链完整** | 新版 `report --days 7` rc=0；`verify` rc=**0**（非 4=空链）；记录数 **9 → 9** |
| 附带 | 0.55.0 的拦截确实生效：`cat ~/.ssh/id_rsa` 经 hook 返回 **rc=2** |

**前两次失败都是我的测量错，不是产品缺陷**（如实记账）：

| 次 | 现象 | 真因 |
|---|---|---|
| 第 1 次 | 版本对不上（装 0.55.0 读成 0.55.1）；`report --root/--json` 报未知参数 | ① 仓根 egg-info 污染（§4-3）② `report` 根本没注册 `--root/--json` |
| 第 2 次 | 「记录数不减」通过，但 `records: 0 → 0` | **空集假绿**：`install` 的首次扫描**不写审计链**，必须真调一次 hook 才有数据 |
| 第 3 次 | `ledger --json` 的 `events` 全是 `null`，判成失败 | 选错数据源（§4-5） |

---

## 6. 未跑项（显式记账，不计入通过）

| 项 | 原因 | 谁补 |
|---|---|---|
| **E-I-4 `pip install -U` 就地替换** | 本沙箱删除被拒（§4-4）；A/B 已证与本产品无关 | ① 企业侧首日自然验证 ② 换一台不经本沙箱的机器补跑 ③ 出包前用 `pip install --target` 另开验证路径 |

---

## 7. 反哺计划：v1.7 要改的四处

1. **§3.6 的「造数据」必须写成「真调 hook」**——`install` 的首次扫描不写审计链，写成「升级后读回来」会在空集上通过。
2. **§3.3「零数据」处境不能只断言 rc**：实测 `report --days 7` 在零事件时 **rc=1**，
   与「运行失败」同码 ⇒ CI 分不清「没数据」与「出错了」。**是否给空态单独退出码，属产品决策**（建议登记待裁决）。
3. **「读回来」要按数据源分开断言**：项目链用 `report`/`verify`，中枢账用 `ledger`；混用即错（§4-5）。
4. **§3.0 的版本类断言必须写「cwd 在仓外」**（§4-3），否则读到的是开发树版本。

---

## 8. 这一件的结论

- **要细化，而且必须到这个颗粒度**：计划里「一行期望」→ 规格里「一步七要素」，
  才能被第二个人无歧义重跑。判据是：**把执行器交给不懂这个项目的人，他能不能只按文件跑出同样的结论**。
- **细化本身就会撞出真问题**：`report` 没有 `--json`、空态 rc=1 与失败同码、`ledger` 与 `report` 数据源不同、
  仓根 egg-info 污染版本——这些都不是「计划写得不好」，是**只有跑到那一步才会浮出来的事实**。
- **下一步建议**（按 deadline 与成本排）：
  1. 企业首日 13 个命令的端到端（`_ent_probe.py` 已有 9 个，补 15 个最便宜的 3 个）；
  2. 规则正控 15 条（§3.2 样本已备）；
  3. `P0` 的 `inbox_tray.py:384` 修法与 D-40 转绿（**等你裁决修法**，不修则 0.56.0 出不了包）。
