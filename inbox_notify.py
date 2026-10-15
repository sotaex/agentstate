# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""值守台 · 通知层（第 1 层）：Toast 替掉"15 秒就没了"的气泡。

★ 要解决的原问题：**告警会消失、会被漏掉**。
  旧气泡 `ShowBalloonTip(15000)` 15 秒后不见、也不进通知中心；
  本层用 **Windows Toast**，**落到操作中心**，错过还能回头看。

★ 外部依赖全部做成**可注入后端**（创始人要求"先模拟解决"）：
  生产＝`WindowsToastBackend`（PowerShell/WinRT）；测试＝`RecordingBackend`（零副作用）。

★ 节流只节**门铃**，不节**台账**：同类 30 分钟内不重复弹，但收件箱照记。
  （这是 R8 的同一道理：门铃可节流，台账不可。）
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import inbox_config as C
import inbox_model as M

MIN_INTERVAL = 1800          # 同类通知最小间隔（秒），与 host_shield 同值


class Backend:
    name = "base"

    def toast(self, title, body, level):
        raise NotImplementedError


class NullBackend(Backend):
    """什么都不做（无 GUI 环境 / 用户关掉了通知）。"""
    name = "null"

    def toast(self, title, body, level):
        return False


class RecordingBackend(Backend):
    """测试用：把调用记下来，**零副作用**。"""
    name = "recording"

    def __init__(self):
        self.calls = []

    def toast(self, title, body, level):
        self.calls.append({"title": title, "body": body, "level": level})
        return True


AUMID = "Antinel.Console"


def _ps_quote(s):
    return str(s).replace("'", "''")


def register_aumid_script():
    """生成注册 AppUserModelID 的 PowerShell（不注册 AUMID，Toast 可能不显示）。"""
    return (
        "$ErrorActionPreference='SilentlyContinue';"
        "$dir=Join-Path $env:APPDATA 'Microsoft\\Windows\\Start Menu\\Programs';"
        "$lnk=Join-Path $dir 'Antinel 监理.lnk';"
        "$ws=New-Object -ComObject WScript.Shell;"
        "$s=$ws.CreateShortcut($lnk);"
        "$s.TargetPath=(Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source;"
        "$s.Arguments='-m antinel inbox serve';"
        "$s.IconLocation='%s';"
        "$s.Save()" % _ps_quote(sys.executable)
    )


def toast_script(title, body, level):
    """生成发一条 Toast 的 PowerShell（WinRT；失败退回气泡，但不静默失败）。"""
    t, b = _ps_quote(title)[:120], _ps_quote(body)[:300]
    return (
        "$ErrorActionPreference='Stop';"
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications,"
        " ContentType=WindowsRuntime] > $null;"
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument,"
        " ContentType=WindowsRuntime] > $null;"
        "$x=New-Object Windows.Data.Xml.Dom.XmlDocument;"
        "$x.LoadXml('<toast duration=\"long\"><visual><binding template=\"ToastGeneric\">"
        "<text>%s</text><text>%s</text></binding></visual></toast>');"
        "$n=New-Object Windows.UI.Notifications.ToastNotification $x;"
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('%s').Show($n);"
        % (t, b, AUMID)
    )


class WindowsToastBackend(Backend):
    """生产后端：PowerShell 发 WinRT Toast（落操作中心）。

    ★ 失败**不静默**：返回 False 并记 `last_error`（调用方可显示"最近成功：N 天前"）。
    """
    name = "windows-toast"

    def __init__(self, powershell="powershell"):
        self.powershell = powershell
        self.last_error = ""

    def toast(self, title, body, level):
        if os.name != "nt":
            self.last_error = "非 Windows，无 Toast"
            return False
        try:
            p = subprocess.run(
                [self.powershell, "-NoProfile", "-WindowStyle", "Hidden",
                 "-Command", toast_script(title, body, level)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, timeout=20,
                creationflags=0x08000000 if os.name == "nt" else 0)
            if p.returncode != 0:
                self.last_error = (p.stderr or b"").decode("utf-8", "replace")[:300]
                return False
            self.last_error = ""
            return True
        except Exception as e:                  # noqa: BLE001
            self.last_error = "%s: %s" % (type(e).__name__, e)
            return False


def default_backend():
    if os.name == "nt":
        return WindowsToastBackend()
    return NullBackend()


# --------------------------------------------------------------- 节流 ----
def _throttle_path(root=None):
    return os.path.join(C.console_dir(root), "notify_state.json")


def _load_throttle(root=None):
    try:
        with open(_throttle_path(root), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:                           # noqa: BLE001
        return {}


def _save_throttle(d, root=None):
    p = _throttle_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, p)


def toast(level, title, body, root=None, backend=None, cfg=None,
          now=None, kind=None, min_interval=MIN_INTERVAL, now_min=None):
    """弹一条通知（受节流与免打扰约束）。返回 `(sent: bool, reason: str)`。"""
    cfg = cfg or C.load(root)
    if not C.should_touch(level, cfg, now_min=now_min):
        return False, "该级别不触达 / 免打扰"
    backend = backend if backend is not None else default_backend()
    now = time.time() if now is None else now
    key = kind or level

    th = _load_throttle(root)
    last = th.get(key)
    if isinstance(last, (int, float)) and now - last < min_interval:
        return False, "同类 %d 秒内不重复" % min_interval
    th[key] = now
    _save_throttle(th, root)

    ok = backend.toast(title, body, level)
    return bool(ok), "" if ok else getattr(backend, "last_error", "发送失败")


# ------------------------------------------------- 节流账本（公开两面）----
def throttle_state(root=None):
    """读**整份**节流账本（0.49.0：冒泡也要在同一本账上记「同类静默」）。

    ★ 为什么不第二个文件：门铃节流与冒泡节流是**同一件事**（同类多久内
      不再响），分两个文件就会出现"toast 记得、冒泡不记得"的漂移。
    ⇒ 文件仍只有一份（`notify_state.json`），这里只把 「读/写某个键」 的能力
      公开出来，冒泡侧不自己开文件。
    """
    return _load_throttle(root)


def throttle_set(key, root=None, now=None):
    """在节流账本上记一个键（门铃/冒泡共用）。原子替换，不删原文件。"""
    d = _load_throttle(root)
    d[str(key)] = float(now if now is not None else time.time())
    _save_throttle(d, root)
    return d
