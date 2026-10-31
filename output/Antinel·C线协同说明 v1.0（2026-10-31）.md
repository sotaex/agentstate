# 给 C 线的协同说明（可直接转发）

> 2026-10-31 22:40。A／B／C 三线共用一个仓，以下全部是今天实测撞出来的，
> 不是预防性设计。**照着做就不会与另外两条线打架。**

---

## 一、你的落点：只写 `output/lineC/`

仓里有 7 个面会进 wheel（`hooks`／`scripts`／`tools`／`rules`／`psl`／`assets`／`challenge`），
根目录单文件模块也在 `py-modules` 里。**往这些面新建任何 `.py`，A 线出包必红**
（清单里没有它 ⇒ `S2-483`／`D-36`）。`output/` 在清单里 0 条、sdist 里 0 成员，只有这里安全。

同样不要碰：版本号九处、`psl/manifest.json`、`psl/workspace_facts.json`、
`.workbuddy/memory/`（并行约定 v1.2 §4.1 记着的 git 够不到的死角）。

## 二、你读哪个账本：`.psl/audit/*.jsonl`

**必须排除 `lock_events.jsonl`** —— 它不是日文件，按日期解析会把日期读错（B 线已被它坑过一次）。
日文件名只认 `YYYY-MM-DD.jsonl`。

**不要用 `~/.antinel/ledger/daily.jsonl` 校准 `decision`。** 那个面 1,311 条记录里
`decision` 与 `type` **100% 为 None**（它是 acked/blocked/breached 的日汇总，不是审计账）。
拿它校准会得到 0，然后被误读成"数据丢了"。

**三个面不是一回事**：面 A＝`~/.antinel/ledger/daily.jsonl`（旧报表）；
面 B＝`.psl/audit/*.jsonl`（审计真源，22:18 读数 33 个日文件 / 163,533 条）；
面 C＝值守台走 `state_registry.load_items_all()`，**不读上面任何一个**。

## 三、四个会让你算错的坑（都是实测）

1. **`decision` 与 `action` 是两套字段并存**，不是一套。
   `action` 取值 `allow` 46,415 / `record` 45,776 / `alert` 12,532 / `block` 520。
   `post_tool_use` 那 45,777 条**没有 `decision`，裁决记在 `action=record` 里** ——
   只按 `decision` 分桶会把执行侧整类漏掉。分桶键建议用 `(type, decision, action)`。

2. **两字段会互相矛盾**：`allow`+`alert` **944 条**（`notice_budget_window_closed` 756／
   `notice_budget_merged` 150／`hook_slow` 38）、`deny`+`block` **175 条**（同义两词并存）。
   前者不是矛盾，是"放行但又告警"；后者是命名没收敛。

3. **规则 id 有新旧两套**：账本里出现 38 个 id，其中 **28 个是旧号**，而规则库只有 37 条。
   按 id 直接统计会把同一条规则拆成两条。A 线 0.63.2 修的是**写入侧**（`load_rules`
   加了 `by_legacy` 别名索引），**读取侧仍要你自己归一**——账本里的历史记录不会回改。

4. **日锚只覆盖 31/33 天**，缺 `2026-09-25` 与 `2026-10-05`。
   如果你的巡检以"每天都有锚"为前提，这两天会误判。其中 10-05 是活缺口
   （不是空洞日，442 条记录在，就是没锚）。

## 四、跑全量闸门：只有一条入口

**不要**直接 `python ci/delivery_gate.py`。闸门自己的锁是按「工作区根」算路径的，
而 `.psl/` 在 gitignore 里 ⇒ 主树与各 worktree **各建一把锁、互不可见** ⇒ 会并发。
2026-10-13 实测并发时日志被交错写成一行"0481 RED"，追了 20 分钟幽灵红。

```bash
bash /d/psl/poc/antinel-security/output/tools/gate_all.sh --status   # 先看谁在跑
bash /d/psl/poc/antinel-security/output/tools/gate_all.sh            # 全量
```

这个脚本把 `ANTINEL_GATE_STATE_DIR` 固定到主仓根，三条线共用一把锁。
已实测：从 worktree 跑、主树有锁时会被拒（rc=3，原因是"另有一次闸门正在跑"）。
`run.lock` 存在时**先等，不要删** —— 陈旧锁闸门自己会改名让开。

## 五、本机环境的三条硬约束

1. 解释器用 `/c/Users/大马/.workbuddy/binaries/python/versions/3.13.12/python -E -X utf8`。
   **不要用裸 `python`**：默认解释器不带 `setuptools`；若解析到 Windows Store 占位符，
   会静默返回 `rc=0` 且零输出。
2. `TMP`／`TEMP`／`TMPDIR` 必须是 `C:\Users\大马\AppData\Local\Temp`。
   本机只有这个目录能删目录，`C:\Temp` 与 D 盘整盘都 `WinError 5`。
3. D 盘**禁止 unlink** ⇒ 覆盖已存在文件会报 `unable to unlink old ...: Invalid argument`。
   修法是原地截断覆写（`git cat-file blob <rev>:<path> > <path>`），不是删了重建。

## 六、提交

只 `git add output/lineC/<具体文件>`，**永远不用 `-A`／`-a`**。
提交前 `git diff --stat` 认领每个已跟踪改动——看见 `hooks/`／`ci/`／`psl/` 的 M，
那是 A 线正在动的文件，**不提交、不撤销**。
提交说明写文件再 `git commit -F`（塞进 bash 双引号串或 heredoc 会被钩子误伤）。

## 七、报数规矩

任何条数**必须带读取时刻**（账本 30 天滚动，明天必不同），
任何百分比**必须写出分母**（"52.9% 的记录没有 decision"这种说法今天被证明是错的——
那 86,508 条里 99.96% 是三个 type 的适用面不同，不是字段缺失）。

---

**一句话**：你写 `output/lineC/`、读 `.psl/audit`（排除 `lock_events.jsonl`）、
分桶带 `action`、id 要归一、锚不一定天天有、闸门走 `gate_all.sh`，就不会和 A／B 线打架。
