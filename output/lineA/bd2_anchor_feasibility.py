# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""BD-2 决策包的量：日锚现在到底「落后多少」，以及「存在性校验」今天会不会误报。

三个数，全部现取自真账本：

  S1 每个日文件「锚定字节 / 实际字节 / 落后字节」——锚有多旧（BD-3 的量化）
  S2 锚里的 last_hash 是否仍能在当日文件里找到——这是「存在性校验」的可行性正控
  S3 末日文件的 last_hash 是否等于当前末条——「等值校验」会不会误报

★ 只读。★ 读数必须带时刻，脚本自己打。
"""
import datetime
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AUDIT = os.path.join(ROOT, ".psl", "audit")
MAN = os.path.join(AUDIT, "day_manifest.json")


def main():
    now = datetime.datetime.now().isoformat(timespec="seconds")
    man = json.load(open(MAN, encoding="utf-8"))
    files = sorted(f for f in os.listdir(AUDIT)
                   if f.endswith(".jsonl") and f[:4].isdigit())
    print("读数时刻 %s；日文件 %d 个；清单条目 %d 个" % (now, len(files), len(man)))

    rows = []
    for fn in files:
        p = os.path.join(AUDIT, fn)
        size = os.path.getsize(p)
        e = man.get(fn) or {}
        asz = int(e.get("size", 0) or 0)
        ah = e.get("last_hash", "") or ""
        found = None
        tail_hash = ""
        maxline = 0
        if ah:
            found = False
            for line in open(p, encoding="utf-8", errors="replace"):
                s = line.strip()
                if not s:
                    continue
                if len(s) > maxline:
                    maxline = len(s)
                if not found and ('"%s"' % ah) in s:
                    found = True
                tail_hash = s
            try:
                tail_hash = json.loads(tail_hash).get("hash", "")
            except Exception:
                tail_hash = ""
        rows.append((fn, asz, size, size - asz, ah, found, tail_hash, maxline))

    print("\n%-16s %11s %11s %10s %8s %8s" %
          ("日文件", "锚定字节", "实际字节", "落后", "锚在否", "最大行"))
    for fn, asz, size, lag, ah, found, th, mx in rows:
        print("%-16s %11d %11d %10d %8s %8d" %
              (fn, asz, size, lag, ("-" if found is None else ("在" if found else "不在")), mx))

    anchored = [r for r in rows if r[4]]
    print("\n有锚且非空的日：%d / %d" % (len(anchored), len(rows)))
    exist = [r for r in anchored if r[5]]
    print("S2 锚 hash 仍能在文件里找到：%d / %d" % (len(exist), len(anchored)))
    miss = [r[0] for r in anchored if not r[5]]
    if miss:
        print("   找不到的日：%s" % ", ".join(miss))

    lag = sorted(r[3] for r in anchored)
    if lag:
        print("\nS1 落后字节：min %d / 中位 %d / max %d" % (lag[0], lag[len(lag) // 2], lag[-1]))
        total = sum(lag)
        print("   全部有锚日累计落后 %d 字节" % total)
        nz = sum(1 for x in lag if x > 0)
        print("   落后 >0 的日：%d / %d（其余锚正好压在末条上）" % (nz, len(lag)))

    eq = sum(1 for r in anchored if r[4] == r[6])
    print("\nS3 锚 hash == 当前末条 hash：%d / %d（其余说明锚之后还有追加）" % (eq, len(anchored)))

    mx = max((r[7] for r in rows), default=0)
    print("\n最长一条记录 %d 字节；`touch_day_manifest` 只回读末 4096 字节 ⇒ %s"
          % (mx, "安全" if mx < 3800 else "有截断风险，末条读不全时锚会静默不更新"))

    ok = len(exist) == len(anchored)
    print("\n判定：存在性校验%s（%d/%d 命中）" % ("今天不会误报" if ok else "今天会误报，先查原因",
                                            len(exist), len(anchored)))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
