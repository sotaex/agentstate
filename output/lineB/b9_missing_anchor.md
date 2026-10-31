# B-9 · 两个缺锚日的根因

> 本文件由 `output/lineB/b9_missing_anchor.py` 生成，内容即该次运行的终端输出（读数时刻见目录内容与 git 提交号）。

```
============================================================================
B-9 · 两个缺锚日的根因
  审计目录 D:\psl\poc\antinel-security\.psl\audit   日文件 33 个
----------------------------------------------------------------------------
day                       字节      记录     锚  记录类型
2026-09-25.jsonl         198       1 **NO**  session_start×1
2026-09-26.jsonl        3066       7     Y  host_shield_revived×4,host_shield_spawn_failed×1,hos
2026-09-27.jsonl       29208      59     Y  host_shield_spawn_failed×59
2026-10-03.jsonl       21988      55     Y  host_shield_heartbeat×23,host_shield_task_unknown×12
2026-10-05.jsonl         442       1 **NO**  host_shield_revived×1
----------------------------------------------------------------------------
记录数 == 1 的日子 : ['2026-09-25.jsonl', '2026-10-05.jsonl']
缺锚的日子        : ['2026-09-25.jsonl', '2026-10-05.jsonl']
  [PASS] L-1 两个集合完全相同（2 天），且都非空
  [PASS] L-1b 已封口的带锚日 30 天，锚 size 与磁盘逐个相等 30 天，不等 0 天
        （当天 已排除，账本是活的，不纳入这条断言）
----------------------------------------------------------------------------
L-2 复现：在空项目里真跑一次 SessionStart 钩子（D:\psl\poc\antinel-security\hooks\session_start_banner.py）
  钩子 rc=0  审计目录=True  目录内容=['2026-10-31.jsonl']
  记录 1 条；类型 {'session_start': 1}；全部有 hash=False；有 day_manifest.json=False
  [PASS] L-2 产出形状与 09-25 逐字段一致（1 条 session_start、无 hash、无锚）
----------------------------------------------------------------------------
L-3 定时：取出该日最后一个提交的那版写入者，数锚调用次数
    2026-09-25 @ 9dc3df6  host_shield.py                     touch_day_manifest 出现 0 次
    2026-09-25 @ 9dc3df6  hooks/session_start_banner.py      touch_day_manifest 出现 0 次
    2026-10-05 @ 525a4be  host_shield.py                     touch_day_manifest 出现 0 次
    2026-10-05 @ 525a4be  hooks/session_start_banner.py      touch_day_manifest 出现 0 次
  今天：host_shield.py 3 次；session_start_banner.py 0 次
  [PASS] L-3 `session_start_banner.py` **今天仍然 0 次调锚** ⇒ 09-25 的成因还活着
============================================================================
判定（每晚一天都对应一个成因，不是一句「锚只在写记录时更新」）
  09-25 · **写入路径绕过了锚**，而且绕过的同时**也绕过了链**：
          那天唯一一条记录是 `session_start`，`session_start_banner.py` 用裸
          `open(fn, "a")` 直接写，既不算哈希也不调锚。L-2 已复现。
          ⇒ 这条记录连 `verify_chain` 都进不去（无 hash ⇒ 计 prechain，跳过）。
  10-05 · **写入路径当时还没有调锚这个动作**（不是调了失败，也不是锚被覆盖）：
          那天唯一一条是 `host_shield_revived`（有 hash，是链上的正经记录），
          而 L-3 显示该日提交里 `host_shield.py` 的锚调用为 0；
          今天它有 3 处 —— 2026-10-28（0.60.0）才补上。
          ⇒ 已修，但修的是**调用点**，不是机制。
  「锚被覆盖」这个假设被排除：剩余 31 天的锚 `size` 与磁盘逐个相等、
  `last_hash` 与末条实测 hash 逐个相等（见 B-8 的对照页），没有一处是废墟。

下一次什么时候会再发生
  · 只要有一天「开了会话但一次工具都没调」，就会重演 09-25 ——
    因为写每天第一条记录的 `session_start_banner.py` 至今 0 次调锚。
  · 机制上，日锚是**每个写入者自己记得调**（opt-in，全仓 9 个调用点），
    不是写入唯一入口的副作用 ⇒ 每新增一个写账本的地方，就多一次漏调机会。
    `audit_chain.touch_day_manifest()` 里那句 `except Exception: pass` 让
    所有失败都无声，所以漏了也没人知道 —— 只有跑一次 B-8 的对照页才看得见。
```
