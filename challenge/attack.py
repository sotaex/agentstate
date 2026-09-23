#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AgentState 篡改挑战 · 交互式攻击台
零门槛：菜单选择攻击方式，自动审判。改得动算你赢。
用法：python attack.py
"""
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CHAIN_DIR = os.path.join(HERE, "chain")
VERIFY = os.path.join(HERE, "verify.py")

def load_chain():
    files = sorted(f for f in os.listdir(CHAIN_DIR) if f.endswith(".jsonl"))
    if not files:
        print("没有链文件——先跑 python generate_challenge.py 生成"); sys.exit(1)
    fn = os.path.join(CHAIN_DIR, files[0])
    lines = [l for l in open(fn, encoding="utf-8").read().splitlines() if l.strip()]
    return fn, lines

def save_chain(fn, lines):
    open(fn, "w", encoding="utf-8").write("\n".join(lines) + "\n")

def show(lines):
    print("\n—— 审计链（可读视图）" + "—" * 40)
    for i, l in enumerate(lines, 1):
        try:
            r = json.loads(l)
            ts = r.get("ts", "?")[11:19]
            typ = r.get("type", "?")
            hit = ",".join(r.get("rules_hit") or []) or "-"
            snip = (r.get("match_snippet") or (r.get("input") or {}).get("command")
                    or (r.get("input") or {}).get("file_path") or "")[:40]
            print(f"  L{i:02d} [{typ}] {ts} 命中:{hit} {snip}")
        except Exception:
            print(f"  L{i:02d} (无法解析的行)")

def pick_line(lines, prompt="选行号"):
    while True:
        try:
            n = int(input(f"{prompt}（1-{len(lines)}）: "))
            if 1 <= n <= len(lines):
                return n
        except ValueError:
            pass
        print("  输入无效")

def main():
    fn, lines = load_chain()
    print("=" * 56)
    print("  AgentState 篡改挑战 · 攻击台")
    print("=" * 56)
    while True:
        show(lines)
        print("""
  攻击方式：
    1  改一个字符   （选一条记录，我帮你隐蔽地改）
    2  删掉一整行   （看它能不能发现少了记录）
    3  插入伪造记录 （我帮你把 JSON 造好——但链对不上）
    4  大师模式     （用记事本自己改——改完回来按 5）
    5  审判！       （跑独立验证器，当场宣判）
    0  退出""")
        c = input("选择: ").strip()
        if c == "1":
            n = pick_line(lines)
            rec = json.loads(lines[n - 1])
            keys = [k for k in rec if isinstance(rec[k], str) and len(rec[k]) > 3 and k != "hash"]
            print("  可改字段:", ", ".join(f"{i+1}.{k}" for i, k in enumerate(keys)))
            ki = int(input("  选字段序号: ") or "1") - 1
            k = keys[ki]
            old = rec[k]
            pos = next((j for j, ch in enumerate(old) if ch.isalnum()), 0)
            newch = "F" if old[pos].isupper() else "f"
            rec[k] = old[:pos] + newch + old[pos + 1:]
            lines[n - 1] = json.dumps(rec, ensure_ascii=False)
            print(f"  已把 L{n} 的 {k}[{pos}] '{old[pos]}' 改成 '{newch}'（同长度）")
        elif c == "2":
            n = pick_line(lines)
            print(f"  已删除 L{n}: {lines[n-1][:80]}...")
            del lines[n - 1]
        elif c == "3":
            pos = max(1, min(len(lines), int(input(f"插到第几行后（1-{len(lines)}）: ") or 1)))
            fake = {"ts": "2026-09-22T12:00:00+08:00", "type": "fake_record",
                    "tool": "Bash", "note": "attacker inserted", "prev": "", "hash": "deadbeef"}
            lines.insert(pos, json.dumps(fake, ensure_ascii=False))
            print(f"  已在 L{pos+1} 插入伪造记录")
        elif c == "4":
            print(f"  记事本打开: {fn}")
            subprocess.run(["notepad", fn])
            lines = [l for l in open(fn, encoding="utf-8").read().splitlines() if l.strip()]
        elif c == "5":
            save_chain(fn, lines)
            print("\n  ⚖️  审判开始...\n")
            subprocess.run([sys.executable, VERIFY, CHAIN_DIR])
            break
        elif c == "0":
            save_chain(fn, lines)
            break
        else:
            print("  无效选择")
    print("\n  攻击台退出。重开挑战：python generate_challenge.py 重新生成一条全新的链。")

if __name__ == "__main__":
    main()
