# SPDX-License-Identifier: CC-BY-SA-4.0
# 一次性量具：日锚（type=session_dna）逐日核对。只读，零写入。
import collections
import json
import os
import sys

ROOT = ".psl/audit"


def day_files(root):
    return [os.path.join(root, n) for n in sorted(os.listdir(root))
            if n.endswith(".jsonl") and len(n) == 16 and n[4] == "-"]


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    files = day_files(ROOT)
    per_day_lines = {}
    dna = collections.defaultdict(list)
    for p in files:
        day = os.path.basename(p)[:10]
        n = 0
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for ln, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                n += 1
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if isinstance(r, dict) and r.get("type") == "session_dna":
                    dna[day].append((ln, sorted(r.keys()), r.get("session")))
        per_day_lines[day] = n

    print("日文件 %d 个｜session_dna 记录 %d 条" % (len(files), sum(len(v) for v in dna.values())))
    print()
    miss = [d for d in per_day_lines if d not in dna]
    dup = [d for d in dna if len(dna[d]) > 1]
    print("缺锚日（有日文件、无 session_dna）：%s" % (miss or "无"))
    print("多锚日（同一天 >1 条 session_dna）：%s" % (dup or "无"))
    print()
    for d in miss:
        print("  [缺] %s  当日 %d 行" % (d, per_day_lines[d]))
    print()
    for d in dup:
        print("  [多] %s  %d 条：%s" % (d, len(dna[d]), [(ln, s) for ln, _k, s in dna[d]]))
    print()
    print("=== session_dna 的字段（取首条）===")
    for d in sorted(dna):
        ln, ks, s = dna[d][0]
        print("  %s line=%-5d session=%s" % (d, ln, s))
        print("      keys=%s" % ks)
        break

    # 首行是不是锚？末行是不是锚？
    print()
    print("=== 锚在日文件里的位置 ===")
    for d in sorted(dna):
        for ln, _k, _s in dna[d]:
            pos = "首行" if ln == 1 else ("末行" if ln == per_day_lines[d] else "第 %d 行" % ln)
            print("  %s  锚 %s（共 %d 行）" % (d, pos, per_day_lines[d]))


if __name__ == "__main__":
    main()
