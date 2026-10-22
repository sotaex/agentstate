#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""竞态夹具的**确定化**装置 —— 唯一实现（0.48.5）。

★★ 由来（实测，不是推演）：两道并发负控在同一周里各**假红**过一次。

    · `ci/inbox_guards_0470.py` 的 `N-S98`（8 进程 × 20 次无锁读改写）：
      全量交付闸门里报
        「负控失效：恢复「无锁照写」后 4 轮并发守恒均成立
          （末轮 total=160, missed=0）⇒ 变异没起作用或并发一次都没撞上」。
      本机复跑 6 轮 —— **5 撞 / 1 不撞**（撞上率 ≈ 83%）。判据要跑 20–70 秒，
      四轮全不撞就要 **280 秒**白等，且结论还是"红的"。
    · `ci/inbox_guards_0450.py` 的 `N-S75`（6 进程抢临界区，窗口 50 ms）：
      打包闸门里报「0450 12 绿 / 1 红」，紧接着连跑 3 次又是 13 绿 / 0 红。

   本仓铁律：「**一个时红时绿的量具比恒红的更坏**」——
   负控时红时绿，等于"这道守卫到底在不在承重"永远答不出来；
   而"红的"还被误读成"产品坏了"。⇒ 必须从**机制上**把运气拿掉。

★ 根因（两条都不是"代码写错了"，是**夹具把确定性交给了运气**）：

   ① **启动错峰**：`Popen` 返回得很快，但 N 个 Python 解释器**启动有先后**
      （本机实测每个 ≈100–200 ms，机器一忙更久）。用"等一个 go 文件"当栅栏
      **治不了这个** —— 迟到的进程看见 go 已存在就**直接冲**，等于没等。
      临界区窗口只有几十毫秒时，错峰足以把"同时冲"变成"排队冲"，
      于是"本该撞车"的那一轮一次都没撞上。
   ② **前置条件靠自然发生**：`N-S98` 的变异（摘掉"拿不到锁就别写"）**只在
      锁真的取不到时**才现形。锁取不到是**争用**的结果，争用又取决于调度
      ⇒ 变异是否现形全凭运气。

★ 本模块给出的三个手段（配套使用，缺一不可）：

   ① **会合栅栏（rendezvous）** —— `join()` / `auto_join()`：
      N 个进程**必须全部到齐**才一起放行；到齐之前谁都动不了。
      与"等 go 文件"的关键差别：这里等的是**兄弟进程本身**，不是父进程。
      ⇒ 消掉"启动错峰"。
   ② **前置条件强制化** —— 由调用方做（见 0470 的 `n_s98`）：
      缺陷的形状若是"当 X 成立时我们做错事"，负控就**直接把 X 摆好**
      （例如把 `audit_chain.acquire_lock` 打成恒返回 `None`），不等 X 自然发生。
      ★ 纪律：**强制的只能是前置条件，不能是结论**。
   ③ **自证（两臂对照）** —— 由调用方做：
      同一套夹具（同样的会合、同样的强制前置、同样的窗口放大）跑一遍
      **未变异**的源码，必须**不**出现破坏；否则说明"破坏是夹具自己造成的"。
      这一步是②③的**许可证**：没有它，放大窗口就成了自证其罪。

★ 纪律：
   · 本模块**不写任何产品文件**；栅栏目录、worker、输出一律落临时目录。
   · 会合超时 ⇒ 子进程以 `RZ_TIMEOUT_RC`(97) 退出；调用方**必须**据此报
     「夹具失效」，**绝不**把"没会合上"读成"没撞上"或"通过了"
     （本仓铁律：测不出的情况报 SKIP，绝不报 PASS）。
"""
from __future__ import annotations

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import tmpreg as _TMP   # 0.55.0 (F3): temp dir registry
import io
import os
import subprocess
import sys
import tempfile

#: 会合超时的退出码（父进程据此判「夹具失效」）
RZ_TIMEOUT_RC = 97

#: 落盘到临时目录、由 worker `import` 的栅栏模块名
RZ_NAME = "_rz"

#: 栅栏实现（**唯一一份**）—— 由 `run_race()` 落盘成 `<workdir>/_rz.py`
_RZ_SRC = '''# -*- coding: utf-8 -*-
"""会合栅栏（由 ci/race_amp.py 落盘，供 race worker import）。**不要手改。**"""
import os
import sys
import time


def join(n, dirpath, who="", timeout=60.0, poll=0.002):
    """阻塞到 `dirpath/arrived/` 里凑够 `n` 个**不同的**到达者才放行。

    ★ 与"等 go 文件"的区别：go 文件只等**父进程**，迟到的兄弟进程看见 go
      已存在就直接冲 ⇒ 错峰照旧。这里等的是**兄弟进程本身**：先到的必须等到
      最后一个到齐 —— 到齐之前谁都动不了。
    ★ 超时 ⇒ stderr 出声并以 97 退出（父进程据此报「夹具失效」，
      **绝不**让一个没会合的轮次被当成"撞过了"）。
    """
    ad = os.path.join(dirpath, "arrived")
    try:
        os.makedirs(ad, exist_ok=True)
    except OSError:
        pass
    me = "%s-%d" % (who or "w", os.getpid())
    try:
        with open(os.path.join(ad, me), "w", encoding="utf-8") as f:
            f.write(str(time.time()))
    except OSError:
        pass
    deadline = time.time() + float(timeout)
    while True:
        try:
            got = len(os.listdir(ad))
        except OSError:
            got = 0
        if got >= n:
            return True
        if time.time() > deadline:
            sys.stderr.write("RACE-AMP: 会合超时（到齐 %d / %d）\\n" % (got, n))
            sys.exit(97)
        time.sleep(poll)


def auto_join():
    """从环境变量 `RZ_DIR` / `RZ_N` / `RZ_WHO` / `RZ_TIMEOUT` 自动会合。

    worker 只需一行 `_rz.auto_join()` —— 没设 `RZ_DIR` 时是**无操作**
    （便于单独调试 worker 源码）。
    """
    d = os.environ.get("RZ_DIR")
    if not d:
        return False
    join(int(os.environ.get("RZ_N") or "0"), d,
         os.environ.get("RZ_WHO") or "",
         float(os.environ.get("RZ_TIMEOUT") or "60"))
    return True
'''

#: 注入 worker 的头部 —— worker 源码里**不必**写任何栅栏代码
_HEADER = (
    "# -*- coding: utf-8 -*-\n"
    "import os\n"
    "import sys\n"
    "sys.path.insert(0, {workdir!r})\n"
    "import {rz} as _rz\n"
    "_rz.auto_join()      # \u2605 \u4f1a\u5408\u6805\u680f\uff1a{nproc} "
    "\u4e2a\u8fdb\u7a0b\u5168\u90e8\u5230\u9f50\u624d\u4e00\u8d77\u51b2\n"
)


def run_race(body, nproc, argv=(), workdir=None, timeout=240.0,
             env_extra=None, rz_timeout=60.0, who_prefix="w", quiet=True):
    """起 `nproc` 个**真进程**跑 `body`，**自动带会合栅栏**（全部到齐才一起冲）。

    `body` 是一段源码字符串（会以 `nproc` 份各起一个进程执行），
    里面**不需要**写任何栅栏代码 —— 栅栏由本函数注入的头部执行。
    worker 的工作目录 = 栅栏目录 = `workdir`（未给则新建临时目录），
    因此 `body` 里用 `os.getcwd()` 落输出即可；进程序号见 `os.environ["RZ_WHO"]`。

    返回 `(rcs, workdir)`：
      · `rcs` 是各子进程退出码（顺序与启动顺序一致）；
      · **任一 `rc == RZ_TIMEOUT_RC` ⇒ 会合失败**，调用方必须报「夹具失效」。
    """
    d = workdir or _TMP.tmpdir(prefix="race_amp_")
    if not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with io.open(os.path.join(d, RZ_NAME + ".py"), "w", encoding="utf-8") as f:
        f.write(_RZ_SRC)
    worker = os.path.join(d, "_race_worker.py")
    with io.open(worker, "w", encoding="utf-8") as f:
        f.write(_HEADER.format(workdir=d, rz=RZ_NAME, nproc=nproc) + body)
    env = dict(os.environ)
    env["RZ_DIR"] = d
    env["RZ_N"] = str(int(nproc))
    env["RZ_TIMEOUT"] = str(float(rz_timeout))
    if env_extra:
        env.update(env_extra)
    devnull = subprocess.DEVNULL if quiet else subprocess.PIPE
    procs = []
    for i in range(int(nproc)):
        e = dict(env)
        e["RZ_WHO"] = "%s%d" % (who_prefix, i)
        procs.append(subprocess.Popen(
            [sys.executable, worker] + [str(a) for a in argv],
            stdout=devnull, stderr=devnull, cwd=d, env=e))
    rcs = []
    for p in procs:
        try:
            p.communicate(timeout=float(timeout))
        except subprocess.TimeoutExpired:                       # noqa: PERF203
            p.kill()
            try:
                p.communicate(timeout=10)
            except Exception:                                   # noqa: BLE001
                pass
        rcs.append(p.returncode)
    return rcs, d


def joined_ok(rcs):
    """`run_race` 的退出码是否**全部**表示"会合成功且 worker 正常退出"。"""
    return bool(rcs) and all(rc == 0 for rc in rcs)


def join_failed(rcs):
    """是否有 worker 因**会合超时**退出（⇒ 夹具失效，不是"没撞上"）。"""
    return any(rc == RZ_TIMEOUT_RC for rc in rcs)
