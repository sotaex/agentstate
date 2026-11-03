# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""C 线：主动性报告（巡检 → 线索 → 一页纸 → 自己到点跑）。

★ 这个包为什么存在（2026-11-03 搬迁）
  搬迁前这些模块住在 `output/lineC/`，而 `output/` **不随包**
  （`build_package.py` 的 `packages` 里没有它）。后果不是「少个功能」，
  而是**主动性永远不成立**：系统里没有任何组件会启动它。
  一个只在人手动敲命令时才有输出的东西，是工具，不是主动性。

★ 包的边界
  · 运行时链：`nightwatch`（调度）→ `watchman`（检测）→ `clue_ledger`（节奏）
    → `onepager` / `report`（陈述）。其余是被这条链引用的支撑模块。
  · **不含**研发工具（`auditor` / `redteam*`），它们不在这条链上。
  · 对外部世界的全部依赖只有两处，且都是延迟导入：
      `host_shield`（中枢目录与账本口径）、`inbox_bubble`（推送通道）。
    两处都**不许**被 `try/except` 吞成静默——那会让「主动性缺失」与
    「跑过了，没事」长得一模一样。
"""

__all__ = ["_paths"]
