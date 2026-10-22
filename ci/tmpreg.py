# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""判据专用的临时目录登记处（0.55.0，复核 F3）。

★★ 为什么要有这个模块：
  套件里 N 处 `_TMP.tmpdir(...)` 建完就没人收 —— 实测 `D:/_antmp` 顶层堆到
  **70,312 项**（几乎全是空目录），`du -sm` 跑不完（120 秒超时），单次 `scandir`
  冷扫 **64.8 秒**。而那是**全局 TMP**：产品自己的 `tempfile`、备份、杀毒扫描都走这里。
  ⇒ 判据把"量产品"的劲用完了，却从没量过"自己造了多少垃圾"。

★ 为什么用 `atexit` 而不是逐条 `finally`：
  逐条改，漏一处就是一条新泄漏，而"漏了"没人会发现（它不报错）。
  `atexit` 是**进程级兜底**：只要建的时候走了 `tmpdir()`，退出时一定收。

★ 只收自己登记的：不扫 `TMP`、不碰别人的目录。
  逃生门：`ANTINEL_KEEP_TMP=1` ⇒ 不清（排查时要看现场）。
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile

#: 本进程登记过的临时目录（栈式：后建的先删）。
_DIRS = []


def tmpdir(prefix="antinel-"):
    """建一个临时目录并登记，进程退出时统一收掉。**判据里建临时目录只许走这里。**"""
    d = tempfile.mkdtemp(prefix=prefix)
    _DIRS.append(d)
    return d


@atexit.register
def sweep():
    """删除本进程登记过的全部临时目录。**不抛**：删不掉就留着，下次再说。"""
    if os.environ.get("ANTINEL_KEEP_TMP") == "1":
        return
    while _DIRS:
        d = _DIRS.pop()
        shutil.rmtree(d, ignore_errors=True)


def registered():
    """当前登记数（判据用：跑完一个夹具后看有没有清）。"""
    return len(_DIRS)


def bare(prefix="antinel-bare-"):
    """建一个**不登记**的临时目录 —— **只给 P37 的负控用**（复现"建了不收"）。

    ★ 放在这里而不是判据里：判据文件一旦直接调 `mkdtemp`，P37 自己的静态腿
      就会把它标成违规（不许自己既当尺子又当违规样本）。这个逃生门的用法
      被限制在"负控样本"一个地方，且名字带 bare 一眼能认出来。
    """
    return tempfile.mkdtemp(prefix=prefix)
