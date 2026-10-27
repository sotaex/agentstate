# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Antinel 监理 · 强调层（第 4 层）：桌面浮层 + 分级声音。**默认关，用户能开。**

★ 创始人拍板：**默认关**（不许自己弹出来吓人），但**用户能开**。

★ 只对 **R0（失守）** 生效 —— 这是"防线失效"，值得把人叫醒。
  其余级别靠托盘变色 + 通知 + 收件箱，**不响**。
  （长期都在响的告警＝没有告警，本项目铁律。）

★ 后端可注入（测试零副作用）：`SoundBackend` / `OverlayBackend`。
"""
from __future__ import annotations

import os
import subprocess

EMPHASIS_LEVELS = ("R0",)      # 只有它值得打断人


def should_emphasize(level, cfg):
    """该级别该不该"强调"（浮层/声音）。★ 只有 R0，且必须用户开了开关。"""
    if level not in EMPHASIS_LEVELS:
        return False
    return bool(cfg.get("sound") or cfg.get("overlay"))


class SoundBackend:
    name = "base"

    def play(self, level):
        raise NotImplementedError


class NullSound(SoundBackend):
    name = "null"

    def play(self, level):
        return False


class RecordingSound(SoundBackend):
    name = "recording"

    def __init__(self):
        self.calls = []

    def play(self, level):
        self.calls.append(level)
        return True


class WindowsSound(SoundBackend):
    """Windows 系统告警音（`[console]::beep` 之外用 SystemSounds，零依赖）。"""
    name = "windows"

    def play(self, level):
        if os.name != "nt":
            return False
        try:
            p = subprocess.run(
                ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
                 "Add-Type -AssemblyName System.Windows.Forms;"
                 "[System.Media.SystemSounds]::Hand.Play();"
                 "Start-Sleep -Milliseconds 700"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10,
                creationflags=0x08000000)
            return p.returncode == 0
        except Exception:                       # noqa: BLE001
            return False


class OverlayBackend:
    name = "base"

    def show(self, level, count, text):
        raise NotImplementedError


class NullOverlay(OverlayBackend):
    name = "null"

    def show(self, level, count, text):
        return False


class RecordingOverlay(OverlayBackend):
    name = "recording"

    def __init__(self):
        self.calls = []

    def show(self, level, count, text):
        self.calls.append({"level": level, "count": count, "text": text})
        return True


# ── WindowsOverlay 已于 0.59.0 连根移除 ────────────────────────────────
# 它曾经在这里拼一个 320×72 的深色 WinForms 无边框小窗（右下角、5 秒自散）。
# ★ 删除理由（两条，各自都足够）：
#   ① **外观不是主窗口的**：没有 Antinel 的 CSS，也没有官方 LOGO
#      —— 创始人 2026-10-27 要求「新提醒跟主窗口差不多、都带 LOGO」；
#   ② **它从未被接线**：全仓没有任何实例化点，是一段"随时可以被接上"的潜在实现。
#      留一段死实现＝给下一次复发留入口，这与"两处实现"同罪。
# ⇒ R0 的"把人叫醒"由品牌化浮窗承担（`inbox_bubble`，置顶、不自动消失）。
# 保留 `OverlayBackend` / `NullOverlay` / `RecordingOverlay`：那是**注入点与夹具**，
# 不产生任何像素，判据靠它们验"开关关着时零副作用"。


def emphasize(level, count=0, text="", cfg=None, sound=None, overlay=None):
    """执行强调（默认关时**一个副作用都不产生**）。返回 `{"sound":..,"overlay":..}`。"""
    if cfg is None or not should_emphasize(level, cfg):
        return {"sound": False, "overlay": False, "skipped": "未开启或级别不够"}
    out = {"sound": False, "overlay": False}
    if cfg.get("sound"):
        out["sound"] = bool((sound or NullSound()).play(level))
    if cfg.get("overlay"):
        out["overlay"] = bool((overlay or NullOverlay()).show(level, count, text))
    return out
