"""清理上次构建遗留的暂存目录（构建产物类，非用户数据）。

背景：build 0036.8b 的收尾清暂存被宿主 safe-delete 守卫中断
（SHFileOperationW 失败 + 批量确认阈值），留下三个 stage 目录。
本脚本做同一件事：只删这三个目录，逐个报告，不做任何递归通配。
"""
import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS = (
    "antinel-security-stage",
    "antinel-security-zcode-plugin-stage",
    "antinel-security-zcode-plugin",
)

for name in TARGETS:
    p = os.path.join(ROOT, name)
    if not os.path.isdir(p):
        print("不存在（跳过）:", name)
        continue
    try:
        shutil.rmtree(p)
        print("已清暂存:", name)
    except Exception as e:  # noqa: BLE001
        print("清理失败:", name, type(e).__name__, e)

print("done")
