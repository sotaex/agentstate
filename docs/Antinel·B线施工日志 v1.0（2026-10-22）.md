<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel·B 线施工日志 v1.0（2026-10-22）

> 本文件在 B 线自己的工位（`.worktrees/bstate`，分支 `b-presentation`）。
> 共享台账 `docs/Antinel·状态机施工台账与任务卡 v1.0` 的 §4 归两条线共同追加，
> 动它之前要看对面在不在改（协作约定 R3）。2026-10-22 15:2x 实测：design 树里
> 那份台账**正在被改**（`M` 未提交）⇒ 本步不碰它，把待粘行备在 §4 下方。

## §1 B1 · 形状编码（角标）—— 完成

| 项 | 内容 |
|---|---|
| 步 | B1（任务卡：`state_registry` 的 `icon` 字段落实 ＋ `mk_icons` 的形状表） |
| 工位 | `.worktrees/bstate`，分支 `b-presentation`，基点 `b258fe3`（含 A0／A1） |
| 前置 | 无（`state_registry` 与 T1 决议均已就绪） |
| 验收 | `output/_p_shape_parity.py`：**正判据 8 绿 / 0 红；负控 7 绿 / 0 红；量具自检 1 绿 / 0 红** |
| 回归 | 0360 **63/0**；0514 **214/0/0**；0372 **28/0**；0481 **12/0** |

## §2 方案选择：(b) 注册表立唯一真源，实测否决 (a)

任务卡给的是两读法（见上一轮盘点）。**实测下来 (a) 不只是"不够优雅"，它是走不通的**：

| # | 事实（可复现） | 后果 |
|---|---|---|
| 1 | `mk_icons.main()` 里是 `SHIELD_SUFFIX[sh]` | 给 `SHIELD_MARKS` 加 `at-risk` 键 ⇒ 循环到它时 **KeyError**，不是少画一个文件 |
| 2 | `SHIELD_SUFFIX` 的 4 个键是 `tray.ps1`／`logo.ps1`／20 个 `.ico` 的文件名后缀；`0514:4383` 把 PowerShell 那行**逐字**钉着 | 要让它不炸就得加进 `SHIELD_SUFFIX` ⇒ 同一批要改两个 PowerShell 文件 + 5 个判据断言 |
| 3 | `0360.c_all_icon_combinations_exist` 按 `SHIELD_SUFFIX` 键集逐格查产物 | 加键 ⇒ 缺 5 个 `.ico` 就红；补齐则是 **B4 的活**，不是 B1 |
| 4 | `on` / `off` 在**两根轴**上都存在 | 混进一张「名字→图案」表，同一个键立刻有两个含义（值勤 `off`＝不该在岗；监理态 `off`＝哨兵未启用） |

⇒ (b)：几何只在 `state_registry.DUTY_MARK` 写一次，`MARK_OF` 只声明「哪个名字借哪一枚」，
`mk_icons.SHIELD_MARKS` 就是 `R.MARK_OF` 本身（`is` 同一对象，探针 ⑧ 守）。

**两根轴分开表达，但共用一个键空间**：资产名键仍是那 4 个（`on/unposted/unknown/off`），
值勤轴新增 `at-risk`。`unknown` 借 `at-risk` 的 dot 是 **T1 的裁决**（角标只有一枚），
属有意耦合 —— 改 at-risk 的几何，5 个 `-unknown.ico` 会跟着变，**必须同批重生成（B4）**。

## §3 改了哪四处

| 文件 | 改动 |
|---|---|
| `state_registry.py` | 新增 `DUTY`／`DUTY_MARK`／`MARK_OF`／`MARK_KINDS`／`mark_of()`；`icon` 改为从 `SHAPE[lamp]` 派生（8 条不再各写一遍）；`selfcheck()` 增第 ⑦ 条 |
| `tools/mk_icons.py` | `SHIELD_MARKS = R.MARK_OF`（删掉本地副本）；角标解析从"每像素一次 `.get()`"提到 `build_ico()` 入口一次；`main()` 循环改用 `SHIELD_SUFFIX` |
| `_p_badge_probe.py` | 4 处调用改传**已解析几何**（原传名字串）；补 `_mark()` 并写明为什么不能用 `.get()` |
| `state_registry.py` 头 | SPDX `CC-BY-SA-4.0` → `Apache-2.0`（**改动前就红**，A0 引入；0481 L1 当场判红） |

## §4 关键证据：像素级

改前基线（`output/_p_icon_hash.json`，25 格 = 5 态 × 5 名）：

```
None|L0            34aa3147c9233a2e      ← 不画角标
at-risk|L0         34aa3147c9233a2e      ← **与上者逐字节相同**（缺陷本身）
unknown|L0         8ffb66c38d49dd29      ← dot
```

改后：

```
对比 25 格，差异 0 格            ← 其余 20 格一格未动（20 个 .ico 不会静默过期）
L0  at-risk=8ffb66c3…  unknown=8ffb66c3…  无角标=34aa3147…  OK
L1/L2/Ls/R0 同上
```

另：`python tools/mk_icons.py` 重生成后 `git status -- assets/icons` **为空** —— 20 个 `.ico`
逐字节不变，与上表互证。

## §5 我在这步犯的/差点犯的错

1. **改内部签名没查全调用点**：`_alpha_at` 从"名字串"改成"已解析几何"，`_p_badge_probe.py`
   还在传名字 ⇒ 0360 T05 当场红。这条判据的调用链跨了 subprocess（0360 → 探针 → mk_icons），
   grep 只在 ci/ 里找是找不到的。**教训：改签名先 grep 全仓 + 记住有 subprocess 这一层。**
2. **判据差点把自己的注释当违规**：`icon` 派生值的第一版检测写成数文本 `"icon":`，
   而注册表注释里恰好写着这个词来解释本条 ⇒ 假红。改成 AST 数"有没有 icon 的字典字面量"，
   并在负控里用两段合成样本证明「真违规数得出 1 / 注释里的串数出 0」。
3. **负控的期望写成了一锅**：`G②` 量具自检期望**绿**，混进"变异后必须红"那一栏被算成失败。
   已拆成 `NEGATIVES`（必须红）与 `GAUGE`（必须绿）两本账。

## §6 留给下一步的（不假装已闭合）

1. **探针在 `output/`，被 `.gitignore` 的 `_p_*` 忽略**，不入库。任务卡 §3 写「探针与产品码
   同批提交」，而 `.gitignore` 说 `_p_*` 一律忽略 —— **两句话对不上**。本步按 `.gitignore`
   执行（不 force-add），代价是换个 AI 接手时从 git 里找不到这把尺子。
   ⇒ 归入 **Z 步（判据迁移）**：那一步要把它落进 `ci/` 常驻，届时同批解决「入库」。
2. **B1 目前没有常驻判据**（`RESIDENT_SUITE_CAP=29` 顶格，Z 步统一迁）。判断依据仍在探针里，
   全量闸门 34 套不会替它守 —— 这是已知缺口，不是"已覆盖"。
3. **B4 前提仍然有效**：改 at-risk 的几何会连带改 `-unknown.ico` 那 5 个资产，必须同批重生成
   并人眼复看（T1 测试页）。
4. **`DUTY` 还没有消费点**：值勤轴真正接进图标是 **X 步（渲染接线）**，本步只把表与查表函数立好。

## §7 待粘进共享台账 §4 的一行

```
| B | B1 | `ed527d6` | `python output/_p_shape_parity.py` | 8 正绿／7 负控真红／1 量具绿；回归 0360 63/0、0514 214/0、0372 28/0、0481 12/0 | **B3**（最独立，前置无）或 B2；B4 前置=B1 已绿 |
```

> 下一入口说明：`B3` 读设计件 §7 的 sidecar 行规格，产物 `sidecar.py`，
> 验收 `output/_p_sidecar_twice.py`（两次汇总同一结果）；`B2` 读 §F7，
> 前置含一条硬约束「无头场景不算 unknown」。
