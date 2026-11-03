# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""`linec` 的路径与外部依赖——**唯一**入口。

★ 为什么必须只有一处
  搬迁前 14 个模块各自算 `dirname(dirname(_HERE))` 来「找仓库根」。
  在研发树里 `output/lineC/` 的上两层恰好是仓库根，所以每份都算对了。
  搬进 `site-packages/linec/` 之后，上两层是 `Lib`，**没有一处还会算对**；
  而错的表现不是报错——是 `rules/default.json` 读不到、账本目录不存在，
  于是每个模块各自退回自己的兜底，报告少几行，没人发现。
  这正是本项目第一顽症的形状：同一事实多处实现，错起来是静默的。

★ 研发树与安装件的关系（这是能平移的前提）
  研发树：`<repo>/linec/` 的父目录 = `<repo>/`，下面有 `hooks/`、`host_shield.py`、`rules/`。
  安装件：`site-packages/linec/` 的父目录 = `site-packages/`，下面**同样**有
  `hooks/`、`host_shield.py`、`rules/`（都是同一个包打进去的）。
  ⇒ 所以只需要把「上两层」改成「上一层」，其余相对关系不动。
"""

import os
import sys

#: 本包目录
HERE = os.path.dirname(os.path.abspath(__file__))
#: 包根（研发树是仓库根；安装件是 site-packages）
PKG = os.path.dirname(HERE)


def ensure_pkg_on_path():
    """让产品侧模块（`host_shield` / `hooks.notify_policy`）可被导入。

    研发树里跑的时候 `PKG` 不在 `sys.path` 上（因为是从 `output/lineC/`
    直接执行的），装成包之后通常已经在——插一次是幂等的。
    """
    for p in (PKG, os.path.join(PKG, "hooks")):
        if p and os.path.isdir(p) and p not in sys.path:
            sys.path.insert(0, p)


def hub_dir() -> str:
    """中枢目录：**复用产品侧唯一真源**，不自造第二个家目录。

    `host_shield._hub_dir()` 是产品侧唯一实现（`ANTINEL_HUB_DIR` 或 `~/.antinel`）。
    这里另写一遍就会在设了 `ANTINEL_HUB_DIR` 的沙箱里出现两个中枢，
    两边各写一半状态，谁都不完整。
    """
    ensure_pkg_on_path()
    try:
        import host_shield as _HS                       # noqa: PLC0415
        d = _HS._hub_dir()
        if d:
            return d
    except Exception:                                   # noqa: BLE001
        pass
    return (os.environ.get("ANTINEL_HUB_DIR")
            or os.path.join(os.path.expanduser("~"), ".antinel"))


def state_dir() -> str:
    """本线的状态目录（状态文件、锁之外的一切持久物）。"""
    return os.path.join(hub_dir(), "lineC")


def out_dir() -> str:
    """产出目录（一页纸、报告）。

    ★ 为什么不能落在包目录里：`site-packages` 可能只读，且升级会整目录覆盖
      ⇒ 今天的报告会被下一次 `pip install` 抹掉。
    """
    d = os.path.join(state_dir(), "out")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def audit_root() -> str:
    """账本根目录：产品侧口径，**不依赖 cwd**。

    `_shield_audit_dir(None)` 的语义是「调用者没有项目视角」⇒ 中枢 rollup。
    这正是后台巡检该有的视角：它在 09:00 自己醒来，没有「当前项目」。

    研发机上若要针对某个项目的账本跑，显式传 `--root <项目>/.psl/audit`，
    不要改这里的默认值——改了就等于给「研发机习惯」和「产品语义」各留一份默认。
    """
    ensure_pkg_on_path()
    try:
        import host_shield as _HS                       # noqa: PLC0415
        return _HS._shield_audit_dir(None)
    except Exception:                                   # noqa: BLE001
        return hub_dir()


def rules_path() -> str:
    """规则表：`<包根>/rules/default.json`（随包，不是仓库相对路径）。"""
    return os.path.join(PKG, "rules", "default.json")


def dev_output_dir():
    """研发树的一次性量具目录（`<repo>/output`）；安装件里不存在 ⇒ `None`。

    ★ 为什么返回 `None` 而不是空串或临时目录：调用方必须**显式**处理「本机没有
      这些量具」这件事。返回一个能拼路径的假字符串，会让 12 个负控项一起
      以「文件不存在」变红 —— 而红的原因与代码毫无关系。
      **不适用与失败同貌**，是本仓最忌讳的四种 0 之一。
    """
    d = os.path.join(PKG, "output")
    return d if os.path.isdir(d) else None
