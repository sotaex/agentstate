#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ts 归一 · 唯一实现（C 线共用）。

**为什么要有这个模块（入口唯一性）**：`watchman.py` 与 `auditor.py` 都要比时间。
两处各写一遍解析，就会有两套口径；而这两套口径一旦不同，**同一份账本会在
一个工具里绿、在另一个工具里红**。所以解析只许在这里出现一次。

**为什么必须解析、不能字符串比较**（实测，2026-10-31）：

    账本里混装两种 ts 格式 —— 162,182 条带 `+08:00`、916 条不带。
    用 `ts < last` 做字符串比较，会把「格式差异」读成「时间倒序」：
    字符串口径报 936 处倒序，datetime 口径只有 481 处，
    差额 455 处**全部**来自「至少一侧无时区」的对，同格式对的误报为 0。

⇒ 字符串比较不是「近似正确」，它把一个格式问题伪装成了篡改证据。

**归一规则（数据版本迁移，必须写死并公开）**：
无时区的 ts 按 **本地墙钟（UTC+8）** 解释，然后统一去掉 tzinfo 再比。
理由：这台机器上 162,182 条显式写了 `+08:00`，那 916 条是同一个写者漏写后缀，
不是另一个时区 —— 按 UTC 解释会让它们整体前移 8 小时，制造 900 多处假倒序。
"""

from __future__ import annotations

import collections
import glob
import os
from datetime import datetime
from typing import Any, Dict, Optional

LOCAL_OFFSET_HOURS = 8


def parse_ts(ts: Any) -> Optional[datetime]:
    """ISO ts -> naive datetime（本地墙钟）。不可解析返回 None。"""
    if not isinstance(ts, str) or len(ts) < 19:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except Exception:
        return None
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    return dt


def tod(rec: Dict[str, Any]) -> Optional[str]:
    """取 ts 的钟点部分 `HH:MM:SS`。用于「同期比较」（截到同一钟点再比）。"""
    ts = rec.get("ts")
    if not isinstance(ts, str) or len(ts) < 19 or ts[10] != "T":
        return None
    return ts[11:19]


NO_TS = "(无ts字段)"
BAD = "(坏)"


def tz_suffix(ts: Any) -> str:
    """ts 的时区后缀。

    三档必须分开，不能合成一档（铁律：**没有的东西不能报成失败**）：
      `(无ts字段)` 该类型本来就没有时间 —— 实测 33 条 `session_dna` 就是这种，
                   算进「坏」等于把「不适用」报成「有问题」；
      `(坏)`       有 ts 但解析不了 —— 这才是真问题；
      `(无)`       有 ts、能解析，只是没写时区后缀 —— 格式混装的来源。
    """
    if ts is None:
        return NO_TS
    if not isinstance(ts, str) or len(ts) < 19:
        return BAD
    rest = ts[19:]
    if rest.startswith("."):  # 小数秒
        rest = rest.split("+")[-1] if "+" in rest else rest
    return rest if rest else "(无)"


def format_census(root: str) -> Dict[str, int]:
    """ts 后缀分布 —— 让「口径」在报告里可见，而不是藏在代码里。

    这不是装饰：只要两种格式同时存在，任何时间比较的结论都带一个隐藏分母。
    把它打出来，读的人才知道那个数字是在什么口径下算的。
    """
    c: collections.Counter = collections.Counter()
    for p in sorted(glob.glob(os.path.join(root, "*.jsonl"))):
        base = os.path.basename(p)
        if base == "lock_events.jsonl":
            continue
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    import json

                    rec = json.loads(line)
                except Exception:
                    c[BAD] += 1
                    continue
                if isinstance(rec, dict):
                    c[tz_suffix(rec.get("ts"))] += 1
    return dict(c)


def mixed_formats(census: Dict[str, int]) -> int:
    """真正「格式混装」的条数：有 ts 但缺时区后缀的那些。

    不含 `(无ts字段)` —— 那些记录不参与时间比较，混不混装与它们无关。
    这个区分不是学术洁癖：把 33 条 session_dna 算进来，会让「混装 917 条」
    变成「混装 950 条」，于是任何按这个数做的判断都错。
    """
    return int(census.get("(无)", 0))
