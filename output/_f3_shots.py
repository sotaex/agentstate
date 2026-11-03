# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""F3 截图：把五个视图 + 紧急提醒窗渲染成 PNG，交给创始人**在手机上**看。

★ 为什么要这一步：位置、观感、气泡弹出这类问题，判据说什么都不算数，
  得让本人看见。截图是"让他在手机上也能看见"的唯一办法（他不在电脑边）。

★ 边界：这是**浏览器渲染**，不是真实窗口。窗口位置／托盘图标／系统气泡
  这三件事它证明不了 —— 那三项仍属人工项，报告里分开列。
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
sys.path.insert(0, PKG)

HUB = os.path.join(os.environ.get("TEMP") or "/tmp", "antinel_f3_hub")
os.environ["ANTINEL_HUB_DIR"] = HUB

import inbox_server as SV          # noqa: E402

PORT = 8798
TOKEN = "f3shots0123456789abcdef"
OUT = os.path.join(HERE, "_f3_shots")
os.makedirs(OUT, exist_ok=True)

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
PROFILE = os.path.join(os.environ.get("TEMP") or "/tmp", "f3_edge_profile")

SHOTS = [
    ("01_收件箱_要处理", "/?t=%s&v=inbox&f=action", (1080, 1500)),
    ("02_收件箱_看一眼", "/?t=%s&v=inbox&f=info", (1080, 1400)),
    ("03_收件箱_归档", "/?t=%s&v=inbox&f=archive", (1080, 1200)),
    ("04_日报", "/?t=%s&v=report", (1080, 1500)),
    ("05_运行状态", "/?t=%s&v=health", (1080, 1500)),
    ("06_账本", "/?t=%s&v=ledger", (1080, 1400)),
    ("07_体检", "/?t=%s&v=health_exam", (1080, 1400)),
    ("08_紧急提醒窗", "/?t=%s&v=bubble", (520, 420)),
]


def shoot(url, path, size):
    w, h = size
    cmd = [EDGE, "--headless=new", "--disable-gpu", "--no-first-run",
           "--hide-scrollbars", "--force-device-scale-factor=1",
           "--user-data-dir=" + PROFILE,
           "--window-size=%d,%d" % (w, h),
           "--virtual-time-budget=4000",
           "--screenshot=" + path, url]
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, timeout=120)
    okk = os.path.exists(path) and os.path.getsize(path) > 4000
    return okk, os.path.getsize(path) if os.path.exists(path) else 0, time.time() - t0, \
        (p.stderr or b"")[-300:].decode("utf-8", "replace")


def main():
    if not os.path.isdir(HUB):
        raise SystemExit("夹具不在（先跑 output/_f3_make_hub.py）")
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), SV._make_handler(TOKEN, HUB))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % PORT
    # 等服务真能应答再截图（否则第一张会是"无法访问"）
    for _ in range(40):
        try:
            urllib.request.urlopen(base + "/api/health", timeout=2).read()
            break
        except Exception:                                      # noqa: BLE001
            time.sleep(0.25)
    made = []
    try:
        for name, path, size in SHOTS:
            dst = os.path.join(OUT, name + ".png")
            okk, n, dt, err = shoot(base + (path % TOKEN), dst, size)
            print("  %-18s %s %8d B  %4.1fs" % (name, "OK " if okk else "FAIL", n, dt))
            if okk:
                made.append(dst)
            else:
                print("      stderr: %s" % err.replace("\n", " ")[:220])
    finally:
        httpd.shutdown()
    print("共 %d 张，目录 %s" % (len(made), OUT))
    return 0 if len(made) == len(SHOTS) else 1


if __name__ == "__main__":
    sys.exit(main())
