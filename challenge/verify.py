#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT

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
    prechain = 0
    findings = []
    for df in day_files:
        prev_full = ""
        # ★ 0.64（BD-6）：这一天里出现过的全部 hash。日锚要问的不是「末条是不是它」，
        #   而是「**它还在不在**」。为什么不能比末条：日文件是追加写入的，锚写下之后
        #   还会长；比末条会把「健康的、还在写的今天」判成篡改（假警报）。
        #   为什么存在性够用：重写尾部会让被重写那一点之后的**每一个** hash 都变，
        #   而锚记的那条 hash 属于旧链 ⇒ 它必然从集合里消失。且链是只追加的，
        #   「曾经存在」不会变成「不存在」，所以不会误报。
        day_hashes = set()
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
            # ★ 0.64（BD-8）：**没有 hash 的记录不进校验**，只计「预链」。
            #   为什么：本仓 `.psl/audit/` 里活着两类文件——
            #   ① 日链文件（每条都有 prev/hash）；② `lock_events.jsonl`（锁事件流水，
            #   一条 hash 都没有）。旧版把 ② 也当链来验，5779 行全被判 EDITED；
            #   而 09-25 那条「开了会话但一次工具都没调」的 `session_start` 也没有 hash，
            #   同样被判 EDITED。实测在真账本上是 **7,056 条误报、verdict=TAMPERED** ——
            #   一份对外的「公开挑战件」在本仓自己的链上喊狼来了，等于自毁。
            #   规则与 `tools/verify_chain.py` 的 `prechain` 完全一致：无 hash ⇒ 跳过，
            #   既不算篡改也不算完好，单独计数并在抬头写出来。
            if "hash" not in rec:
                prechain += 1
                continue
            want = hashlib.sha256((prev_full + canon_of(rec)).encode("utf-8")).hexdigest()
            if want != rec.get("hash", ""):
                bad_hash += 1
                findings.append(f"{df} L{i}: 自哈希不符 → 该记录内容被改动过（EDITED）")
            if rec.get("prev", "") != prev_full[-16:]:
                bad_prev += 1
                findings.append(f"{df} L{i}: prev 链接断裂 → 删除或插入过记录（MISLINKED）")
            prev_full = rec.get("hash", "")
            if prev_full:
                day_hashes.add(prev_full)
        # 日锚（若在）：字节大小 + 锚记的那条记录还在不在
        man_p = os.path.join(d, "day_manifest.json")
        if os.path.isfile(man_p):
            man = json.load(open(man_p, encoding="utf-8"))
            m = man.get(df)
            if m:
                size = os.path.getsize(os.path.join(d, df))
                if size < int(m.get("size", 0)):
                    findings.append(f"{df}: 文件比日锚记录小 → 尾部被删除（TRUNCATED）")
                anchor = m.get("last_hash") or ""
                # ★ 0.64（BD-6）：这里原本是 `not prev_full.startswith("")`，
                #   而 `"".startswith("")` 恒为 True ⇒ 该合取项恒 False ⇒ 整条判据
                #   永不成立，`TAIL-EDITED` 一次也没被报出来过（死判据）。
                #   现在改成**存在性**：锚记的那条记录若已不在链上，就是尾部被重写。
                if anchor and day_hashes and anchor not in day_hashes:
                    findings.append(f"{df}: 锚定的那条记录已不在链上 → 尾部被重写（TAIL-REWRITTEN）")
    print(f"记录 {total} 条 | 完好 {total - bad_hash - bad_prev - prechain} | "
          f"预链（无 hash，未校验）{prechain} | 异常 {bad_hash + bad_prev}")
    for f in findings:
        print("  !!", f)
    verdict = "CLEAN — 链完好，未被改动" if not findings else "TAMPERED — 检出篡改"
    print("verdict:", verdict)
    return 0 if not findings else 2

if __name__ == "__main__":
    sys.exit(main())
