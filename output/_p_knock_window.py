# -*- coding: utf-8 -*-
"""第①项「每日一次敲门窗口」的判据腿。
用法：python _probe_knock.py <repo> <tmp_root>
"""
import json
import os
import sys

REPO = os.path.abspath(sys.argv[1])
TMPROOT = os.path.abspath(sys.argv[2])
sys.path.insert(0, REPO)

import inbox_daemon as D  # noqa: E402

fails = []


def fresh(name):
    d = os.path.join(TMPROOT, name)
    os.makedirs(os.path.join(d, ".psl", "state"), exist_ok=True)
    return d


# ① 首次 ⇒ 拿到
root = fresh("k1")
got, why = D._knock_daily_take(root, "2026-11-03")
print("① 首次          拿到=%s  理由=%s" % (got, why))
if not got:
    fails.append("① 首次应拿到额度，实测 %s（%s）" % (got, why))

# ② 同日再问 ⇒ 不给
got2, why2 = D._knock_daily_take(root, "2026-11-03")
print("② 同日再问      拿到=%s  理由=%s" % (got2, why2))
if got2:
    fails.append("② 同日第二次应被拒，实测拿到")

# ③ 换一天 ⇒ 重新拿到
got3, why3 = D._knock_daily_take(root, "2026-11-04")
print("③ 次日          拿到=%s  理由=%s" % (got3, why3))
if not got3:
    fails.append("③ 次日应重新拿到，实测 %s" % (why3,))

# ④ 账本里落的日期确实是新的（不是只返回 True 不记账）
rec = D._knock_daily_read(root)
print("④ 落盘账        %s" % json.dumps(rec, ensure_ascii=False))
if rec.get("date") != "2026-11-04":
    fails.append("④ 落盘日期应为 2026-11-04，实测 %s" % rec.get("date"))

# ⑤ 写不进去 ⇒ 不给额度（方向：拿不准就不打扰）
root_bad = fresh("k_bad")
# 把 state 变成一个**文件**，令 makedirs 失败
st = os.path.join(root_bad, ".psl", "state")
try:
    os.rmdir(st)
except OSError:
    pass
try:
    with open(st, "w", encoding="utf-8") as f:
        f.write("blocker")
except Exception as e:
    print("   （造失败条件时出错：%s）" % e)
got5, why5 = D._knock_daily_take(root_bad, "2026-11-03")
print("⑤ 写不进去      拿到=%s  理由=%s" % (got5, why5))
if got5:
    fails.append("⑤ 账写不进去时不应给额度（否则会天天敲），实测拿到")

print()
if fails:
    for f in fails:
        print("FAIL", f)
    sys.exit(1)
print("四项全过（首次拿到 / 同日拒 / 跨日重置 / 写失败不敲）")
