<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Antinel·B 线施工日志 v1.3（2026-10-22）

> 本文件在 B 线自己的工位（`.worktrees/bstate`，分支 `b-presentation`）。
> 共享台账 `docs/Antinel·状态机施工台账与任务卡 v1.0` 的 §4 归两条线共同追加，
> 动它之前要看对面在不在改（协作约定 R3）。本步仍不碰它，B4 那一行待粘在 §14。

**v1.2 → v1.3 摘要：新增 §13（B4 · 图标资产与文件字键，完成）。**
v1.2 已退役为 `Antinel·B线施工日志 v1.2（2026-10-22）.md.away-20261022-1836`，
v1.1／v1.0 更早已退役为 `.away-20261022-1724`／`.away-20261022-1614`。
本节以下的 §1–§12 是 v1.2 原文，逐字保留。

---

## §13 B4 · 图标资产与文件字键 —— 完成

### 13.1 任务卡说的是「重生成＋CVD 复验」，实测重生成是零 diff

任务卡 B4 的产出写的是 `assets/icons/*.ico`（构建期产物）。先跑一次再说话：

```
python tools/mk_icons.py      # 15 份组合图 + 5 份基础图
git status --short assets/    # ← 空
```

**零 diff。** 所以「重生成资产」这一项在 B1 期间就已经完成了（B1 那次是顺手一起做的）。
若 B4 只做任务卡字面上那件事，这一步的产出就是「跑了一条命令，什么都没变」。

**真正的缺口在别处，而且是 B1 留下的。**

### 13.2 缺口：B1 修了「怎么画」，没修「读哪份文件」

B1 让 `at-risk` 有几何了（借 `unknown` 那枚 dot）。但它**没有名字** ——
没有任何一处回答「`at-risk` 该读哪一份 `.ico`」。它对着 `SHIELD_SUFFIX` 是**域外键**，
而 `inbox_tray` 的两个入口都拿 `in` 判域外并**静默回落**：

| 入口 | 行 | 传 `at-risk` 时发生什么 | 屏幕上看起来像 |
|---|---|---|---|
| `icon_file()` | `inbox_tray.py:183` | `at-risk` 不在 `SHIELD_SUFFIX` ⇒ 不拼组合图路径 ⇒ 返回基础图 `L1.ico` | **「在岗」（无角标）** |
| `write_state()` | `inbox_tray.py:227` | `shield if shield in SHIELD_SUFFIX else SHIELD_UNKNOWN` ⇒ 写成 `"unknown"` | **「探不到」（盲区）** |

实测（本步当场跑的）：

```
mark_of(at-risk)         = {'kind': 'dot', 'color': (42, 93, 176)}   # 画得出来
icon_file(L1, at-risk)   = L1.ico                                    # 读不到组合图
'at-risk' in SHIELD_SUFFIX = False
```

这两个错**互不相同**：一个是「有损失但显示成没事」，一个是「有损失但显示成看不见」。
而它们都不出声。

★ 这是本仓最高频那条事故族的又一个标本：**修在一个入口，而这件事有多个入口**
（`cf.` 0.54.0 的 A1／A5 两处）。B1 修的是**绘制**入口（`_alpha_at`／`_xor_bitmap`／
`mk_icons`），**读取**与**写入**两个入口一个都没修。

加固：现在还没有任何代码会传 `at-risk`（`shield_state()` 只产出那 4 个值，
A 线的 `situation.py` 尚未接线）⇒ 这是**定时在 X 步的雷**，不是当下正在犯的错。
所以本步**不改** `inbox_tray.py`（它是交汇件，归 X），只把「它该读哪份」这件事做出来。

### 13.3 方案：立「资产文件字键」这一族，方向不可反

`state_registry.py`（纯数据、零 import）新增三样：

```python
FILE_KEYS = ("on", "unposted", "unknown", "off")     # 资产文件字键（文件名那一族）

def asset_key_of(name):
    """名字 → 读哪一份资产。返回文件字键；None＝复用基础图标。未知抛 KeyError。"""
    if name in DUTY_MARK:                            # 值勤三档（含 on）
        mk = DUTY_MARK[name]
        if mk is None:
            return None
        for k in FILE_KEYS:
            if MARK_OF[k] is mk:                      # ← 靠 id 找「谁借了同一枚几何」
                return k
        raise KeyError("值勤档 %r 有几何，但没有哪份资产承载它" % (name,))
    if name in MARK_OF:                               # 旧监理态键本身就是文件字键
        return None if MARK_OF[name] is None else name
    raise KeyError(...)

def _asset_guard_problems():                          # 守卫，供 selfcheck 第 ⑧ 条与负控
    ...
```

**方向不可反**，理由不是审美：

- 磁盘上那份文件叫 `-unknown.ico` ⇒ **`unknown` 是主人、`at-risk` 是借用者**；
- 反过来让 `unknown` 去借 `at-risk`，一旦 `at-risk` 将来换成独立几何，
  `unknown` 的文件就会跟着改名 —— 而 `-unknown.ico` 已经在托盘／哨标／favicon 上；
- 所以在 `FILE_KEYS` 里找「`is` 同一枚几何」的那个人，找到的必须是主人。

**为什么不往 `SHIELD_SUFFIX` 里加一个 `"at-risk"` 键**：B1 已经实测否决过（方案 a）——
`0514:4383` 逐字钉着 `tray.ps1` 那行 PowerShell，`0360` 按 `SHIELD_SUFFIX` 的键集逐格查产物，
`tools/logo.ps1` 也有一份。加键会连带三处。B1 的负控 `N⑥「at-risk 进资产名键 ⇒ 必须红」`
现在仍然绿，说明本步与那条约束相容。

**为什么 `FILE_KEYS` 与 `inbox_tray.SHIELD_SUFFIX` 允许两份**：本模块零 import，
不能反向依赖运行期模块。两份存在是事实，由判据钉死（C①），不靠人记得同步。
这与 `0360` 守 `tray.ps1` 的 PowerShell 副本是同一个手法。

`tools/mk_icons.py` 相应地：

```python
def plan():
    """要生成哪些资产：返回文件字键列表，同形只生成一份。"""
    keys = []
    for n in sorted(set(SHIELD_SUFFIX) | set(R.DUTY)):
        k = R.asset_key_of(n)
        if k is None or k in keys:
            continue
        keys.append(k)
    return keys
```

`main()` 从「遍历 `SHIELD_SUFFIX`（4 个名字）」改成「`plan()` 派生（3 个文件键）」。
差别的要害：往 `DUTY_MARK` 加一格却忘了给它找文件承载时，`asset_key_of` **当场抛**
而不是少画一个文件。

### 13.4 证据

`output/_p_asset_names.py`（git 忽略）：

```
正判据 14 绿 / 0 红 / 0 跳过；负控 9/ 真红 /0 未红
```

| 判据 | 守什么 |
|---|---|
| C① | `FILE_KEYS` 与 `SHIELD_SUFFIX` 键集逐字相同 |
| C② | 四个文件字键自洽（`on` → `None`） |
| C③ | `at-risk` → `"unknown"`，方向对 |
| C④ | `unknown` 不被借用者抢走 |
| C⑤ | 未知名抛 `KeyError` 且报错里带合法集 |
| C⑥ | 五灯产物**按路径**都在（不走带回落的 `icon_file`） |
| C⑦ | `plan()` 覆盖值勤全集 |
| C⑧ | `plan()` 同后缀只一次（`at-risk` 与 `unknown` 不重复写同一文件） |
| C⑨ | `selfcheck()` 不报资产问题 |
| C⑩ | 幂等：连跑两次 `main()`，20 份 sha256 一个不变 |
| C⑪ | `plan()` 是**派生**的：换掉 `asset_key_of` 输出要跟着变 |
| C⑫ | **活形状**上角标像素与主体色不同 |
| G① | `icon_file` 对未知态确实回落（量的是「为什么要绕开它」） |
| G② | `0360` 的组合判据走 `icon_file`（见 13.5 ②） |

负控 9 条，每条换掉同一份实现：`FILE_KEYS` 缺 `unknown`／未知名返 `None`／
`at-risk` 返自身／摘掉守卫／打错一个键／`plan` 只遍历后缀表／`plan` 不去重／
`plan` 硬编码／角标改成与主体同色。

**资产零 diff**（`git status --short assets/` 空）：几何没动，本步只给「名字」这一族立了法。

### 13.5 B4 量出来的三件事（都不是本步要修的，各自归口）

**① `Ls` 那盏灯的角标与它自己同色。**
`Ls` 主体 `#2a5db0`，`at-risk` 角标也是 `#2a5db0`。实测角标区（x 11–15, y 0–3）里
**14 个不透明像素全部**是这个值。另外四盏（L0／L1／L2／R0）的角标区都能看到纯角标蓝。

`Ls` 已不在四灯的 `SHAPE` 里（新四灯 grey/green/yellow/red → L0/L0/L2/R0，
成因表里也没有 `shape=="Ls"` 的行），它属于旧六态体系的「缺粮」（`0372:335`）。
所以 C⑫ 只对 `SHAPE` 的取值断言，**不误杀它**。
但它仍是生成出来的资产、仍被 `0360` 逐格查。**若把「缺粮」接回托盘，这盏灯的角标第一眼是瞎的。**

**② `0360` 的 `c_all_icon_combinations_exist` 是一条死判据。**
它遍历 `SHIELD_SUFFIX` 的键，然后 `p = T.icon_file(ev, sh)` + `os.path.exists(p)`。
而 `icon_file` **自带回落**（组合图不在 ⇒ 返回基础图路径，一定存在）⇒ `miss` 永远为空。
删掉一份组合资产它仍然绿。**归 Z 步**（判据迁移），本步只在探针里用 G② 把这件事钉成事实。

**③ `0514` 的 `FLO-15c` 锚在 `mk_icons` 的**字面量**上，不是锚在结构上。**
它用 `re.findall(r'for\s+st\s+in\s*\(([^)]*)\)\s*:', src)` 从源码读「真正画出来的是哪几个」，
并要求本文件里多处清单一致。我第一次把循环抽成模块常量 `STATES`，**当场双红**
（`FLO-15c` + 它的负控「锚点漂了」）。已写回字面量并加注说明为什么必须写在循环里。

这正印证了本仓已登记的那条：**判据字面锚定比 ≈5.5:1**。改结构前先量这个比。

### 13.6 我在这步犯的错（三个，都被自己的量具抓住）

**① 把 BGRA 当 RGBA 读。** C⑫ 第一版读 `_xor_bitmap` 的输出时按 `(r,g,b,a)` 解包，
而那是 DIB 约定的 **BGRA**。后果：角标色与主体色比的是错位的通道 ⇒ 永不相等
⇒ **这条判据永远绿**。负控 N⑨ 当场把它拆穿（「角标改成与 L0 主体同色后 C⑫ 仍绿」）。
修法不是补一句注释，是把 `b, g, r, a = rows[i:i+4]` 的通道顺序写对。

这是本步第二次栽在「读数单位」上（B3 那次是 C⑭ 用微秒边界判秒精度的产品）。
**判据读的是字节，不是它想的东西。**

**② 负控写反了。** N④ 第一版是「摘掉守卫再跑 `selfcheck`，断言它应该报」——
摘掉守卫当然不报 ⇒ 负控永远「未红」。正确姿势是**先造缺陷**，再分别在有／无守卫
两种情形下看输出，两者必须不同。改完 N④ 才真红。

**③ C⑦ 被别处天然满足。** `at-risk` 借的 `unknown` 本来就在 `SHIELD_SUFFIX` 里，
所以「只遍历后缀表」的假实现也能覆盖值勤全集 ⇒ 负控 N⑥ 不红。
两处修：N⑥ 里**同时**假设 `at-risk` 已有独立文件字键；再加 C⑪ 直接测「派生关系还在不在」
（换掉 `asset_key_of`，`plan()` 输出必须跟着变），并配 N⑧（`plan` 硬编码 ⇒ C⑪ 红）。

三件事同族：**「判据写好了」≠「判据在承重」**。只有负控能回答后者。

### 13.7 回归（一次一个，全部实测）

| 套件 | 结果 | 与基线对比 |
|---|---|---|
| `output/_p_shape_parity.py`（B1 自己的探针） | 8 正绿／7 负控绿／1 量具绿 | 同 |
| `ci/inbox_guards_0360.py` | 63 绿／0 红 | 同 |
| `ci/inbox_guards_0514.py` | **214 绿／0 红** | 同（中途 212/2，修 FLO-15c 锚点后恢复） |
| `ci/inbox_guards_0372.py` | 26 绿／2 红 | 同（A 线的 `situation.py:101`，改动前就红） |
| `ci/inbox_guards_0353.py` | **216 绿／0 红** | 基线 215/1 ⇒ 那 1 红（TP-B2）变绿，**已用 stash 摘掉本步改动复跑，原始树同样是 216/0** |

TP-B2 那条的解释：它取决于 `.psl/audit` 有没有内容（B3 的 §8.5 已记过它的脆弱性），
本步期间那份目录里有了今天的 `2026-10-22.jsonl` ⇒ 绿。**不是本步带来的绿，不领这个功。**

### 13.8 移交给 X 的两处接线（本步不做，因为它动交汇件）

```python
# inbox_tray.py:183  icon_file()
-  if shield and shield in SHIELD_SUFFIX:
+  key = R.asset_key_of(shield) if shield else None      # 未知名称会抛，不再静默
+  if key:
       cand = os.path.join(base, "%s%s.ico" % (s, SHIELD_SUFFIX[key]))
       if os.path.exists(cand):
           return cand

# inbox_tray.py:227  write_state()
-  "shield": shield if shield in SHIELD_SUFFIX else SHIELD_UNKNOWN,
+  "shield": (R.asset_key_of(shield) or SHIELD_UNKNOWN) if shield else SHIELD_UNKNOWN,
```

`R.asset_key_of` 对未知名抛 `KeyError` ⇒ **X 步接线后，「传进来一个不认识的监理态」
会变成响亮的失败，而不是静默落「盲区」**。这正是这条链要的。

★ 但要注意：`icon_file` 与 `write_state` 目前被 `0360`／`0514` 多处调用，
改签名会连带那些判据。它们是交汇件 ⇒ **X 步与 A 线一起改，B 线不单独动。**

### 13.9 没做的（三条，都有依据）

1. **没改 `inbox_tray.py`**：交汇件，归 X（见 13.8）。
2. **没改 `0360` 的死判据**：判据迁移归 Z 步；且 0514 是共享冲突点。
3. **CVD「复验」只做到量化的一半**：我给出的是「角标像素与主体色不同」这个**必要条件**
   的机器判定，加上三种视觉模拟下的 16px 人眼页（`docs/Antinel·T1 16px 人眼复看页 v1.1`）。
   **「三种视觉下都可辨」这句话必须由人眼确认，不由我宣布。** 色觉模拟是
   Machado 2009 severity 1.0 的近似，非医疗级。

---

## §14 待粘进共享台账 §4 的一行

```
| B | B4 | 见 B 线日志 v1.3 | `python output/_p_asset_names.py` | 14 正绿／9 负控真红／2 量具绿；资产零 diff；回归 0360 63/0、0514 214/0、0372 26/2（A 线红，改前即红）、0353 216/0（TP-B2 变绿已用 stash 复跑证实与本节无关）；T1 复看页 v1.1 待人眼 | **X**（前置 A4＋B1 已绿；B2 的 `settle()` 与本节 13.8 两处接线都要在 X 落地） |
```

> 下一入口：**X**（六个渲染点）。三条已知坑（`M.STATE_VAR[st]` 两处裸下标、
> `state_label()`／`_icon_state()` 对未知键静默落「注意」）之外，本步再加一条：
> **`inbox_tray` 的两处 `in SHIELD_SUFFIX` 判域外**（§13.2／§13.8）。
> X 是唯一需要两条线同时在场的点 ⇒ 开工前要先与 A 线对表（R3）。
