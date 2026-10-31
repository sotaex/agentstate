# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""BD-6 探针：`challenge/verify.py` 里唯一读 `last_hash` 的那条判据恒假。

四腿同表（两句必须都在：会响的腿 + 不该响的腿）：

  A 原版 + 故意写错的 last_hash  → 期望 TAIL-EDITED，实际 CLEAN（这就是缺陷）
  B 原版 + 正确的  last_hash     → 期望 CLEAN（对照腿：缺陷不是"什么都没查"）
  C 修版 + 故意写错的 last_hash  → 期望 TAIL-EDITED（牙齿腿）
  D 修版 + 正确的  last_hash     → 期望 CLEAN（不 fire 的对照腿，防误报）

只用标准库；只在系统 TEMP 里建副本；仓库零写入。
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_VERIFY = os.path.join(REPO, "challenge", "verify.py")
AUDIT = os.path.join(REPO, ".psl", "audit")

# 修版只改一个合取项：`not prev_full.startswith("")` 恒为 False（"" 以 "" 开头）
OLD = 'm.get("last_hash") and prev_full and not prev_full.startswith("") \\'
NEW = 'm.get("last_hash") and prev_full \\'


def canon_of(rec):
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def pick_day():
    """挑一个自校验全通过、且记录数最多的日文件当样本（样本本身要干净，否则噪声盖住结论）。"""
    best = None
    for fn in sorted(os.listdir(AUDIT)):
        if not fn.endswith(".jsonl") or not fn[:4].isdigit():
            continue
        p = os.path.join(AUDIT, fn)
        prev_full, n, bad = "", 0, 0
        for line in open(p, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                bad += 1
                continue
            n += 1
            if "hash" not in rec:
                bad += 1
            else:
                want = hashlib.sha256((prev_full + canon_of(rec)).encode("utf-8")).hexdigest()
                if want != rec["hash"]:
                    bad += 1
                prev_full = rec["hash"]
        if bad == 0 and n > 0 and (best is None or n > best[1]):
            best = (fn, n, prev_full)
    return best


def build_case(root, day, tail_hash, size):
    d = os.path.join(root, "chain")
    os.makedirs(d, exist_ok=True)
    shutil.copyfile(os.path.join(AUDIT, day), os.path.join(d, day))
    man = {day: {"size": size, "last_hash": tail_hash}}
    with open(os.path.join(d, "day_manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(man, fh, ensure_ascii=False)
    return d


def run(verifier, d):
    r = subprocess.run([sys.executable, "-E", "-X", "utf8", verifier, d],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (r.stdout or "") + (r.stderr or "")
    verdict = "?"
    for line in out.splitlines():
        if line.startswith("verdict:"):
            verdict = line.split(":", 1)[1].strip()
    return r.returncode, verdict, out


def main():
    hit = pick_day()
    if not hit:
        print("FAIL 样本挑选：没有任何一天是自校验全通的，先修样本")
        return 1
    day, n, real_tail = hit
    size = os.path.getsize(os.path.join(AUDIT, day))
    print("样本 %s：%d 条记录、%d 字节、真实末条 hash %s" % (day, n, size, real_tail[:24] + "…"))

    root = tempfile.mkdtemp(prefix="bd6_")
    try:
        fixed = os.path.join(root, "verify_fixed.py")
        src = open(SRC_VERIFY, encoding="utf-8").read()
        cnt = src.count(OLD)
        print("修版替换命中次数 = %d（必须恰好 1）" % cnt)
        if cnt != 1:
            print("FAIL 变异锚点不唯一，探针作废")
            return 1
        patched = src.replace(OLD, NEW)
        assert patched != src, "变异没改变字节"
        with open(fixed, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(patched)
        print("变异字节差 = %d 字节" % (len(src.encode()) - len(patched.encode())))

        wrong = "sha256:" + "0" * 64
        legs = [
            ("A 原版·锚是假的", SRC_VERIFY, wrong, "TAMPERED"),
            ("B 原版·锚是真的", SRC_VERIFY, real_tail, "CLEAN"),
            ("C 修版·锚是假的", fixed, wrong, "TAMPERED"),
            ("D 修版·锚是真的", fixed, real_tail, "CLEAN"),
        ]
        print("\n%-20s %-10s %-10s %s" % ("腿", "期望", "实际", "rc"))
        rows = []
        for i, (name, verifier, tail, expect) in enumerate(legs):
            d = build_case(os.path.join(root, "case%d" % i), day, tail, size)
            rc, verdict, out = run(verifier, d)
            ok = verdict.startswith(expect)
            rows.append((name, expect, verdict, rc, ok, out))
            print("%-20s %-10s %-10s %d  %s" % (name, expect, verdict[:40], rc, "OK" if ok else "MISMATCH"))

        tail_edited_seen = {
            "A": "TAIL-EDITED" in rows[0][5],
            "C": "TAIL-EDITED" in rows[2][5],
        }
        print("\n明细里出现过 TAIL-EDITED：A(原版)=%s  C(修版)=%s" % (tail_edited_seen["A"], tail_edited_seen["C"]))

        a_ok = rows[0][2].startswith("CLEAN") and rows[0][3] == 0
        c_ok = rows[2][2].startswith("TAMPERED") and rows[2][3] == 2
        no_false_alarm = rows[1][2].startswith("CLEAN") and rows[3][2].startswith("CLEAN")
        print("\n判定：")
        print("  A 原版把「末行 hash 与锚不符」判成 CLEAN 且 rc=0 → %s" % ("复现" if a_ok else "未复现"))
        print("  C 修版把它判成 TAMPERED 且 rc=2 → %s" % ("牙齿成立" if c_ok else "牙齿不成立"))
        print("  B/D 两个正确锚都没误报 → %s" % ("通过" if no_false_alarm else "有误报"))
        if a_ok and c_ok and no_false_alarm:
            print("\n结论：`challenge/verify.py:63` 那条判据恒假，改一个合取项即可让它工作。")
            return 0
        print("\n结论：腿不齐，不许下结论。")
        return 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
