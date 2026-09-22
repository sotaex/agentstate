#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""挑战方的作弊尝试：在链文件中部把一条记录里的一个字符改掉（同长度，不破坏 JSON），
然后跑独立验证器——看篡改能否不被发现。（ spoiler：不能。）
用法：python tamper.py [chain目录]
"""
import os
import subprocess
import sys

d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "chain")
day_files = sorted(f for f in os.listdir(d) if f.endswith(".jsonl"))
fn = os.path.join(d, day_files[0])
lines = open(fn, encoding="utf-8").read().splitlines(keepends=True)
# 找一条含 echo 的行，把 echo 改成 fcHo（同长度）
for i, l in enumerate(lines):
    if "echo hello" in l:
        lines[i] = l.replace("echo hello", "fcHo hello")
        print(f"已篡改 {day_files[0]} 第 {i+1} 行：'echo hello' -> 'fcHo hello'（同长度，JSON 仍合法）")
        break
else:
    print("没找到目标行"); sys.exit(1)
open(fn, "w", encoding="utf-8").write("".join(lines))
print("现在跑独立验证器：")
r = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "verify.py"), d])
sys.exit(r.returncode)
