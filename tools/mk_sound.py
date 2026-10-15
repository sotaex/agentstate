# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""构建期：合成冒泡提示音 `assets/sounds/alert.wav`（纯 stdlib，零依赖）。

★ 为什么自己合成而不引音频库／不放 mp3：本仓**运行时零依赖**是铁律；
  `winsound.PlaySound` 直读 WAV（PCM）⇒ 生成一个 16bit PCM 的短铃声即可。
★ 设计（0.49.0，创始人「以前的冒泡有声音」）：两声短促上行音
  （D6 → A6，各 140ms，间隔 60ms，10ms 淡入淡出）—— 是"提示"不是"警报"，
  音量刻意压低（峰值 ~0.35）：它要能被听见，不该被吓到。
★ 用法：`python tools/mk_sound.py`（幂等，重复运行结果逐字节一致）。
"""
from __future__ import annotations

import math
import os
import struct
import sys
import wave

RATE = 22050
#: 两声的（频率, 起始秒, 时长秒）——上行 ⇒ "有事，来看一眼"
_TONES = ((1174.66, 0.00, 0.14), (1760.00, 0.20, 0.16))
PEAK = 0.35                 # 峰值幅度（0..1）：提示音，不是警报
FADE = 0.01                 # 淡入/淡出时长（秒）：消除爆音


def render():
    total = max(t0 + d for _, t0, d in _TONES)
    n = int(total * RATE) + 1
    buf = [0.0] * n
    for freq, t0, dur in _TONES:
        i0 = int(t0 * RATE)
        m = int(dur * RATE)
        for i in range(m):
            if i0 + i >= n:
                break
            env = 1.0
            fade = FADE * RATE
            if i < fade:
                env = i / fade
            elif i > m - fade:
                env = max(0.0, (m - i) / fade)
            buf[i0 + i] += PEAK * env * math.sin(2 * math.pi * freq * i / RATE)
    return b"".join(struct.pack("<h", int(max(-1.0, min(1.0, x)) * 32767))
                    for x in buf)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(os.path.dirname(here), "assets", "sounds", "alert.wav")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    data = render()
    with wave.open(out, "wb") as f:
        f.setnchannels(1)
        f.setsampwidth(2)
        f.setframerate(RATE)
        f.writeframes(data)
    print("wrote %s (%d bytes, %.2fs)"
          % (out, os.path.getsize(out), len(data) / 2 / RATE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
