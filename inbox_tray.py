# -*- coding: utf-8 -*-
"""值守台 · 托盘（第 2 层）：常驻、不占地方、一眼读状态。

★ 为什么是 PowerShell 而不是 pystray（创始人让我分析后定）：
  产品仓 `[project]` **一个运行时依赖都没有**；`System.Drawing.Icon` 能**直读 `.ico`
  （不需要 Pillow）**；而 `host_shield._notify()` **本来就在走 PowerShell+WinForms**。
  为一个小图标引 ~10MB 依赖不成比例。

★ 协议是**纯文本文件**（不用线程、不用管道、不写 Win32）：
      Python 写 `tray.json`  ──▶  tray.ps1 每 1 秒读一次，更新图标/提示
      Python 读 `tray_action.txt` ◀──  tray.ps1 菜单被点时写一行
  ⇒ **可单测**：不需要真的开一个托盘。

★ 不删任何文件：消费动作文件用 **`os.rename` 改名让开**，不 `unlink`。
"""
from __future__ import annotations

import json
import os
import time

import inbox_config as C
import inbox_model as M


def state_path(root=None):
    return os.path.join(C.console_dir(root), "tray.json")


def action_path(root=None):
    return os.path.join(C.console_dir(root), "tray_action.txt")


def icon_path(state, root=None):
    """五态 → `.ico` 路径。未知态 ⇒ 退回 L0（**但会明确记在返回值里**）。"""
    s = state if state in ("L0", "L1", "L2", "Ls", "R0") else "L0"
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icons")
    return os.path.join(base, "%s.ico" % s)


def write_state(state, count=0, tip="", root=None):
    """写托盘状态（原子替换）。返回写下的 dict。"""
    payload = {"state": state if state in ("L0", "L1", "L2", "Ls", "R0") else "L0",
               "count": int(count), "tip": str(tip)[:120],
               "ts": time.time()}
    p = state_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, p)
    return payload


def read_state(root=None):
    try:
        with open(state_path(root), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:                           # noqa: BLE001
        return {}


def sync_from_items(items, root=None, tip=None):
    """由收件箱现状刷新托盘（页面/守护进程调它）。"""
    st = M.console_state(items)
    n = M.unhandled_count(items)
    if tip is None:
        tip = {"L0": "值守中 · 一切正常", "L1": "注意 · 有可疑动作",
               "L2": "拦截中 · 有已拦下的操作", "Ls": "额度提示",
               "R0": "失守 · 防线未生效"}.get(st, "值守中")
        if n:
            tip += "（未处理 %d）" % n
    return write_state(st, n, tip, root=root)


def push_action(action, root=None):
    """托盘菜单被点时，由 PowerShell 侧写一行（Python 侧只读）。"""
    p = action_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a", encoding="utf-8", newline="\n") as f:
        f.write(str(action).strip() + "\n")
    return True


def poll_actions(root=None):
    """读走**全部**待处理动作（**改名让开，不删除**）。没有 ⇒ 空列表。

    ★ 整文件改名＝原子消费；**必须一次把里面的行全取走**，
      否则同批的后几个动作会随改名一起消失（首版就踩了这个坑）。
    """
    p = action_path(root)
    if not os.path.exists(p):
        return []
    taken = p + ".taken-%d" % int(time.time() * 1000)
    try:
        os.rename(p, taken)                     # ★ 改名，不删除
    except OSError:
        return []
    acts = []
    try:
        with open(taken, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    acts.append(line)
    except OSError:
        return []
    return acts


def poll_action(root=None):
    """取**第一个**动作（会把这一批全部消费掉，其余动作请用 `poll_actions`）。"""
    acts = poll_actions(root)
    return acts[0] if acts else None


def tray_available():
    """本机能不能起托盘（Windows + 有 PowerShell）。**不能也不影响其余四层。**"""
    if os.name != "nt":
        return False
    from shutil import which
    return bool(which("powershell") or which("pwsh"))


def script_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "tray.ps1")


def run(root=None, block=True):
    """起托盘。非 Windows / 无 PowerShell ⇒ 明确返回 False（不假装成功）。"""
    if not tray_available():
        return False
    import subprocess
    sp = script_path()
    if not os.path.exists(sp):
        return False
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", sp,
           "-State", state_path(root), "-Action", action_path(root),
           "-IconDir", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "assets", "icons")]
    if block:
        return subprocess.call(cmd) == 0
    subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,
                     creationflags=0x08000000 if os.name == "nt" else 0)
    return True
