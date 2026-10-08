# PCM 问题数单调收敛闸门设计 v1.0（2026-10-08 收口，0.37.0 首发）

> 实现：`ci/pcm_gate_0370.py`（判据 5 条 ＋ 负控 10 条，全内存态负控）。
> 登记：`ci/delivery_gate.py` SUITES 第 11 套（fast 档）。
> 触发事件：创始人 2026-10-08 原话，一字不改——
>
>   「在新增模块，以及修改老问题时，要最大限度避免引入新问题，
>     系统的问题总量要求不断收敛，能以最快的速度清零，
>     **这个要求需要从机制上解决**。」

---

## 1. 缺口定位：收敛管道已有一条，但少回答一个问题

本仓收敛机制到 0.36.9 为止的完整形状：

| 层 | 机制 | 回答的问题 |
|---|---|---|
| 账本 | by_kind 失败四分类账（product/instrument/environment/process-stale） | **这条失败是什么性质** |
| 检测 | JDG-01..05 判据腐化检测 | **发现错误的机制自己有没有腐烂** |
| 归因 | 0366 基线差分／影响面点名／红项归属 | **这次多了什么、该改判据还是改产品** |
| 执行 | delivery_gate 一个入口 11 套判据 | **红没红、跑没跑到** |

四层合起来回答的是「**多了什么、红是真是假**」。没有一层回答：

> **问题总量有没有在变小？变小是真变小，还是账面变小？**

「从机制上解决」= 这句也不许靠人记得。PCM 就是补这一句的，并且只做这一句。

## 2. 四条判据（全部可机械执行，输入只有两份 JSON）

| 判据 | 规则 | 防的事 |
|---|---|---|
| PCM-01 输入契约 | judgment.json 必须带 `by_kind.counts.product` 与 `per_failure`，缺一即红 | 量具没说话与量具说没问题，在账面上长得一样 |
| PCM-02 P1 单调不增 | 本版 product 数 ≤ 上一版；上升必须有人写豁免单 | 修一个、坏两个，product 净增 |
| PCM-03 P2 一进一出 | 本版新增失败条数 ≤ 本版关闭条数（失败身份＝断言名） | 只在 product 类里做账，全口径失败在膨胀 |
| PCM-04 P3 停滞即红 | 连续 3 个版本一次都没降且当前 > 0 ⇒ 红，**不可豁免** | 账不走了（持平不是收敛）；已清零永远放行 |
| PCM-05 P4 分类不冒充收敛 | product 下降必须由「失败真的消失」解释；「仍在失败、被改分类」不算 | 改 `_BY_KIND_OVERRIDES` 一张表就让 product 归零 |

**为什么 P1 只捆 product 类**：instrument/environment/process-stale 都可能随环境与登记表波动（F-13 paramedic 在重跑中成员漂移是实测过的），把它们捆进「只许降」会天天假红——假红比漏红更坏，它训练人绕过闸门。

**为什么 P3 不可豁免**：停滞正是本闸门存在的理由。给它开豁免门，等于没有闸门。

## 3. 两份账（都在 `.psl/gate/` 下，gitignored，不进包）

### 3.1 `pcm_ledger.json` —— 收敛账本（闸门自己写）

每次跑过追加一行：`{version, product_count, failures{名→类}, recorded_at, source}`。
先 `os.replace` 改名让开成 `.prev.json` 再写新（零删除，与 `baseline.json` 同范式）。

- **判红也照记实况**：它是观察记录，不是奖惩记录。若只记绿灯，「红过一次」
  会从历史上消失，P3/P4 的窗口就被人为剪干净了。
- 同版本重跑 harness 不构成版本推进：比较永远对**上一个不同版本**。
- 新克隆从零开始 ⇒ 又进入基线期（与 `baseline.json` 同款局限，明写不装）。

### 3.2 `pcm_waiver.json` —— 豁免单（只能由人写）

```json
{"waivers": [{"version": "0.37.0", "kind": "product-increase",
              "count": 1, "reason": "……", "by": "……", "at": "……"}]}
```

四要素缺一不算豁免：`version` 对得上、`kind` ∈ {`product-increase`,
`one-in-one-out`}、`count` 覆盖违规量、**`reason` 非空**。闸门自己**永远不写**
这个文件——否则违规者给自己开路只需要改一行判据代码。

## 4. 负控（10 条，全部内存态）

| 负控 | 注入 | 必须 |
|---|---|---|
| n_baseline_is_not_green | 无上一版 | P1–P4 全 SKIP-BASELINE，零 PASS 零 RED |
| n_p1_regress_is_red | 上版 0 → 本版 1 | P1 RED |
| n_p1_waiver_is_accepted | 同上＋合格豁免单 | P1 WAIVED |
| n_p2_regress_is_red | 新增 1 关闭 0 | P2 RED |
| n_p2_waiver_is_accepted | 同上＋合格豁免单 | P2 WAIVED |
| n_p3_stagnation_is_red | 连续三版持平 5 | P3 RED（带别的类别豁免单也照红） |
| n_p3_zero_is_pass | 窗口内归过零 | P3 PASS |
| n_p4_reclass_is_red | 两条 product 仍在、被改分类 | PCM-05 RED |
| n_p4_real_fix_is_pass | 失败真的消失 | PCM-05 PASS |
| n_contract_missing_is_red | judgment 缺 by_kind | PCM-01 RED |

负控全部在内存里换输入，**不碰产品文件、不碰真实账本**——比 JDG 族
「改产品文件再还原」的负控安全一档，因此不需要 delivery_gate 的 negctl 单列档。

**自审实录**：`n_baseline_is_not_green` 第一版断言「全部判据无 PASS」，
但 PCM-01 契约齐全时本来就该 PASS ⇒ 该负控永远红。首跑当场抓到，
收窄为「只查 P1–P4 四条收敛判据」。教训与 F-15 同型：**量具把自己
该放行的一端当成要红的一端**。

## 5. 证伪条件（这条机制自己怎么被证明是坏的）

1. 出现一次「product 净增或失败净增」而闸门全绿 ⇒ P1/P2 失效；
2. `_BY_KIND_OVERRIDES` 新增一条把失败搬去别的类，P4 没红 ⇒ P4 失效；
3. 基线期被输出成「通过」⇒ SKIP-BASELINE 与 PASS 的可区分性失效；
4. 连续三版 product 持平 >0 而闸门不红 ⇒ P3 失效；
5. 负控 10 条中任何一条不红 ⇒ 对应判据是装饰。

## 6. 已知局限（明写，不假装覆盖）

- **失败身份＝断言名**。断言改名时旧名记「关闭」、新名记「新增」，P2 恰好抵平
  （不误红），但「改名即收敛」的伪装 P2 看不出来——拦住它的是 by_kind 的
  basis 留痕与人工审阅，不是本闸门。
- **账本从 0.37.0 起才有行**。更早的版本没有 per_failure 明细可归档，
  不伪造历史（比没有历史更坏），基线就从当前版本开始。
- **product 口径信任登记表**。登记表自身的腐烂由 `by_kind.stale_entries`
  留痕，不在本闸门职责内（职责单一：只盯总量与账面）。
