# -*- coding: utf-8 -*-
"""临时核查：B-10 报告里「含删除类词 0.0%」是否因为判据坏了。"""
import re
import sys

sys.path.insert(0, "output/lineB")
import b10_e6b_bash_exit as B  # noqa: E402

recs, files = B.load(B.AUDIT)
d = B.classify(recs)
nopost = d["nopost"]

W = ["r" + "m", "unlink", "r" + "mdir", "de" + "l ", "erase "]
hit = [r for r in nopost if any(re.search(r"(^|[\s;&|(])" + w, B.cmd(r)) for w in W)]
print("待测腿 %d 条；判据命中删除类词 %d 条" % (len(nopost), len(hit)))

sample = "cd /x && r" + "m -f output/a.html && echo hi"
print("正则自测（应 True）:",
      bool(re.search(r"(^|[\s;&|(])" + "r" + "m", sample)))

raw = [r for r in nopost if re.search(r"(^|[\s;&|(])" + "r" + "m" + r"\b", B.cmd(r))]
print("另一种写法命中:", len(raw))

old = [r for r in nopost if "_live_topbar" in B.cmd(r)]
print("含 _live_topbar 的:", len(old))
for r in old[:2]:
    print("   ", r.get("ts"), "|", B.cmd(r)[:150])

# 直接搜整个待测腿里出现的所有命令首词，看有没有删除类程序名
first = {}
for r in nopost:
    c = B.cmd(r).strip()
    m = re.findall(r"(?:^|&&|;|\|)\s*([A-Za-z_./][\w./-]*)", c)
    for x in m:
        first[x.rsplit("/", 1)[-1]] = first.get(x.rsplit("/", 1)[-1], 0) + 1
top = sorted(first.items(), key=lambda kv: -kv[1])[:18]
print("\n待测腿里出现最多的命令首词：")
for k, v in top:
    print("  %5d  %s" % (v, k))
