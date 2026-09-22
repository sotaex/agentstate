#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel 审计链 · 独立验证器（公开挑战件）
零依赖（Python 3 标准库）。任何人可用它离线复算整条链。

链的算术（AUDIT_SCHEMA）：
    rec["prev"] = 前一条记录 hash 的末 16 位（首条为 ""）
    rec["hash"] = sha256(prev_full + canonical_json(rec 去掉 hash 字段))
    canonical  = sort_keys=True, separators=(",", ":"), ensure_ascii=False

用法：
    python verify.py [chain目录]        # 默认 ./chain
退出码：0 = 链完好；2 = 检出篡改/断裂；3 = 文件缺失
"""
import hashlib
import json
import os
import sys

def canon_of(rec):
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

def main():
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "chain")
    day_files = sorted(f for f in os.listdir(d) if f.endswith(".jsonl"))
    if not day_files:
        print("没有链文件（*.jsonl）"); return 3
    total = bad_hash = bad_prev = 0
    findings = []
    for df in day_files:
        prev_full = ""
        for i, line in enumerate(open(os.path.join(d, df), encoding="utf-8"), 1):
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                rec = json.loads(line)
            except Exception:
                findings.append(f"{df} L{i}: 行不是合法 JSON（撕裂或改坏）")
                bad_hash += 1
                continue
            want = hashlib.sha256((prev_full + canon_of(rec)).encode("utf-8")).hexdigest()
            if want != rec.get("hash", ""):
                bad_hash += 1
                findings.append(f"{df} L{i}: 自哈希不符 → 该记录内容被改动过（EDITED）")
            if rec.get("prev", "") != prev_full[-16:]:
                bad_prev += 1
                findings.append(f"{df} L{i}: prev 链接断裂 → 删除或插入过记录（MISLINKED）")
            prev_full = rec.get("hash", "")
        # 日锚（若在）：字节大小 + 末行 hash，检出尾部删除
        man_p = os.path.join(d, "day_manifest.json")
        if os.path.isfile(man_p):
            man = json.load(open(man_p, encoding="utf-8"))
            m = man.get(df)
            if m:
                size = os.path.getsize(os.path.join(d, df))
                if size < int(m.get("size", 0)):
                    findings.append(f"{df}: 文件比日锚记录小 → 尾部被删除（TRUNCATED）")
                if m.get("last_hash") and prev_full and not prev_full.startswith("") \
                        and m["last_hash"] != prev_full:
                    findings.append(f"{df}: 末行 hash 与日锚不符（TAIL-EDITED）")
    print(f"记录 {total} 条 | 完好 {total - bad_hash - bad_prev} | 异常 {bad_hash + bad_prev}")
    for f in findings:
        print("  !!", f)
    verdict = "CLEAN — 链完好，未被改动" if not findings else "TAMPERED — 检出篡改"
    print("verdict:", verdict)
    return 0 if not findings else 2

if __name__ == "__main__":
    sys.exit(main())
