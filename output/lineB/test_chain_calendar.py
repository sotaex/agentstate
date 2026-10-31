# -*- coding: utf-8 -*-
"""B-1 自检：三条腿，逐腿单跑，任何一腿失败即整体失败。

L-A 真账本：窗口内缺口必须**恰好**是方案书 §3.3 G3 登记的那 4 天。
      （期望值来自方案书台账，不是从实现里抄的 —— 否则缺陷会被钉成判据。）
L-B 合成夹具：造 11 天、抽掉 1 天、另造 1 个空壳文件 ⇒ 缺口 1 天、空壳 1 天。
      ★ 空壳必须与缺口分开报：文件在而 0 条记录，比文件不在更危险。
L-C 空集守卫：空目录必须返回 None（＝「没读到账本」），
      不许返回「0 天缺口」——那会把量具故障读成「一切正常」。
"""
import datetime
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chain_calendar as CC                                        # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
fails = []


def tail(tag, msg):
    print("      %s" % msg)


# ---------------------------------------------------------------- L-A
print("[L-A] 真账本缺口 = 方案书 G3 登记的 4 天")
audit = os.path.join(REPO, ".psl", "audit")
gaps, shells, win, n = CC.missing_days(audit)
if gaps is None:
    fails.append("L-A 读不到账本（返回 None）—— 先查路径，别当成无缺口")
else:
    want = {datetime.date(2026, 9, 30), datetime.date(2026, 10, 1),
            datetime.date(2026, 10, 2), datetime.date(2026, 10, 4)}
    got = set(gaps)
    tail("", "日文件 %d 个，窗口 %s ~ %s，缺口 %d 天" % (n, win[0], win[1], len(gaps)))
    if got != want:
        fails.append("L-A 缺口集与方案书不符：多 %s ／ 少 %s"
                     % (sorted(got - want) or "无", sorted(want - got) or "无"))
    else:
        print("      OK  %s" % CC._ranges(gaps))

# ---------------------------------------------------------------- L-B
print("[L-B] 合成夹具：抽掉 1 天 ＋ 造 1 个空壳")
tmp = tempfile.mkdtemp(prefix="b1_", dir=os.environ.get("TEMP") or None)
d = os.path.join(tmp, "audit")
os.makedirs(d)
lo = datetime.date(2026, 1, 1)
for i in range(11):
    day = lo + datetime.timedelta(days=i)
    p = os.path.join(d, day.isoformat() + ".jsonl")
    body = "" if day == lo + datetime.timedelta(days=3) else '{"a":1}\n'
    io.open(p, "w", encoding="utf-8", newline="\n").write(body)
os.remove(os.path.join(d, (lo + datetime.timedelta(days=7)).isoformat() + ".jsonl"))
# 另放一个非日文件：必须被忽略（它是另一套 schema，不进本日历）
io.open(os.path.join(d, "lock_events.jsonl"), "w", encoding="utf-8").write('{"x":1}\n')
g2, s2, w2, n2 = CC.missing_days(d)
tail("", "日文件 %d 个｜缺口 %s｜空壳 %s" % (n2, g2, s2))
if g2 != [lo + datetime.timedelta(days=7)]:
    fails.append("L-B 缺口应为抽掉的那 1 天，实得 %s" % g2)
elif s2 != [lo + datetime.timedelta(days=3)]:
    fails.append("L-B 空壳应为第 4 天，实得 %s（空壳与缺口没分开报）" % s2)
elif n2 != 10:
    fails.append("L-B 日文件数应为 10，实得 %d（非日文件被算进账本）" % n2)
else:
    print("      OK  缺口与空壳分别报出，非日文件已排除")

# ---------------------------------------------------------------- L-C
print("[L-C] 空集守卫：空目录必须答「没读到」，不许答「0 缺口」")
empty = os.path.join(tmp, "empty")
os.makedirs(empty)
g3, s3, w3, n3 = CC.missing_days(empty)
tail("", "返回 %r" % (g3,))
if g3 is not None:
    fails.append("L-C 空目录返回了 %r —— 把「没读到账本」读成「无缺口」" % (g3,))
else:
    print("      OK  返回 None（与「缺口 0 天」可区分）")

print("-" * 66)
if fails:
    for f in fails:
        print("FAIL  %s" % f)
    sys.exit(1)
print("B-1 自检：3 腿全过")
