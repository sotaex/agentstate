# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""判据用的**产品树沙盒** —— 变异只落在临时副本上，真产品树一个字节不动。

★★★ 为什么必须有它（0.50.3，**实测**抓到的真缺陷，不是推演）：

  创始人 2026-10-14：「点击打开Antinel 监理后……状态不对了……代码认不出出场那份」。
  复现（`_p_poll_posture.py`，一个进程每 0.15s 采一次态势，另一个进程跑
  `ci/inbox_guards_0364.py`）：

      0.40s ok=True  dev=True  posture=guarding  灯=值守中
      7.54s ok=True  dev=True  posture=warn      灯=失守      ← 变异窗口
      8.21s ok=True  dev=True  posture=guarding  灯=值守中

  ⇒ **跑判据会让别处正在看的Antinel 监理显示「失守」**，约 0.7 秒后自己好。
  根因：`0364` 的变异**打在真产品文件上**（往 `rules/hosts/autoclaw.json`
  追加一个换行、改 `psl/manifest.json` 的 version、改 `host_shield.py`），
  而 `self_check()` 读的正是这些文件；登记表漂移属 `DEV_NEVER_EXEMPT_MARKS`
  ⇒ **研发态不豁免** ⇒ `is_dev_build()` 假、`guard_posture()` 落 `warn`
  ⇒ 页面渲染成「失守 ＋ 这份守门的代码我认不出是不是出厂那份」。

  0364 自己的 docstring 早写着「判据污染产品文件，比判据报红更坏」——
  它给还原路径加了重试与退路，**但那治的是"永久污染"，治不了"窗口期"**：
  只要变异落在真树上，这段时间里**任何**读这棵树的人（Antinel 监理、监理、
  另一个判据、正在构建的打包器）都会读到假事实。

  ⇒ 机制性修法：**把变异挪进沙盒**。`self_check()` / `_installed_version()` /
    `_code_version()` 全都经 `_pkg_root()` 取根，而 `_pkg_root()` 是模块级函数、
    每次调用现取 ⇒ **把 `_pkg_root` 指到临时副本即可，连 reload 都不需要**
    （reload 反而是旧的必需动作，因为旧法靠"改真文件 + 重载模块"）。

★ 边界（**刻意做窄**）：沙盒只复制 `self_check()` 与版本判定真正会读的那批文件。
  不是为了"复制整个仓"—— 那既慢又会把无关文件拖进来。
★ 纪律：临时目录**只建不删**（宿主 safe-delete shim 会硬杀删除动作，
  见 `ci/inbox_guards.py` 的同款注释）。
"""
from __future__ import annotations

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import tmpreg as _TMP   # 0.55.0 (F3): temp dir registry
import glob
import io
import json
import os
import shutil
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: 沙盒必须复制的文件 —— **就是 `host_shield.self_check()` 与版本判定会读的那批**
#: （`_GUARDED_CHAIN_FILES` ＋ `rules/hosts/*.json` ＋ 两个版本真源）。
_FILES = (
    "host_shield.py",          # self_check 比它自己的哈希
    "antinel.py",              # _code_version 读它的 VERSION
    "egress.py",               # _GUARDED_CHAIN_FILES
    "hooks/pre_tool_use.py",   # _GUARDED_CHAIN_FILES（同时是版本承载件）
    "hooks/post_tool_use.py",  # _GUARDED_CHAIN_FILES
    "tools/enforce_probe.py",  # _GUARDED_CHAIN_FILES
    "psl/manifest.json",       # _manifest_hash / _installed_version 的真源
)
_GLOBS = ("rules/hosts/*.json",)


class Sandbox:
    """一个临时包根；`patch(hs)` 之后，`hs` 的自检/版本判定都读这里。"""

    def __init__(self, root=None):
        self.real = os.path.abspath(root or ROOT)
        self.path = _TMP.tmpdir(prefix="antinel_pkgsb_")
        self._patched = []
        for rel in _FILES:
            self._copy(rel)
        for pat in _GLOBS:
            for src in glob.glob(os.path.join(self.real, pat.replace("/", os.sep))):
                self._copy(os.path.relpath(src, self.real).replace(os.sep, "/"))

    # ---------------------------------------------------------------- 复制 --
    def _copy(self, rel):
        src = os.path.join(self.real, rel.replace("/", os.sep))
        if not os.path.isfile(src):
            return False
        dst = self.path_of(rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        return True

    def path_of(self, rel):
        return os.path.join(self.path, rel.replace("/", os.sep))

    # ------------------------------------------------------------ 读 / 写 --
    def read(self, rel):
        with io.open(self.path_of(rel), encoding="utf-8") as f:
            return f.read()

    def write(self, rel, text):
        p = self.path_of(rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with io.open(p, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        return p

    def append(self, rel, text):
        with io.open(self.path_of(rel), "a", encoding="utf-8", newline="") as f:
            f.write(text)
        return self.path_of(rel)

    def read_json(self, rel):
        return json.loads(self.read(rel))

    def write_json(self, rel, obj, indent=1):
        return self.write(rel, json.dumps(obj, ensure_ascii=False, indent=indent))

    # ------------------------------------------------------------- 指向 --
    def patch(self, hs_mod):
        """把 `hs_mod._pkg_root` 指到沙盒（记下原值，`restore()` 还原）。"""
        self._patched.append((hs_mod, hs_mod._pkg_root))
        hs_mod._pkg_root = lambda: self.path
        return self

    def restore(self):
        for mod, old in reversed(self._patched):
            mod._pkg_root = old
        self._patched.clear()

    # ------------------------------------------------------------ 上下文 --
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.restore()
        return False


def sandboxed(hs_mod, root=None):
    """`with sandboxed(host_shield) as sb:` —— 退出时自动还原 `_pkg_root`。"""
    return Sandbox(root).patch(hs_mod)
