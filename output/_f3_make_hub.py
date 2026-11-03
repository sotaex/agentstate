# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""F3-1 满态夹具：在**隔离中枢**里造一份 30 条级的收件箱。

★ 为什么不用手写 jsonl：手写出来的记录没有 `prev`/`hash`，投影层虽然不校验，
  但日报的 `chain_health()` 会逐条复算整条链 ⇒ 夹具自己制造一片「链被改动」红字，
  走查者会把它读成产品缺陷。⇒ 一律走**产品自己的写入实现**（`append_chained`）。

★ 为什么落在 TEMP：真实中枢 `~/.antinel` 是创始人正在用的运行态，
  拿它当测试台会污染他的「已读/已处置」痕迹（长程计划 §禁忌第 1 条）。
  隔离靠 `ANTINEL_HUB_DIR` —— 产品自己预留的唯一开关，不新造开关。

用法：
  python output/_f3_make_hub.py            # 重建 + 打印统计
  python output/_f3_make_hub.py --keep     # 不重建（保留上次的已读痕迹）
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
sys.path.insert(0, PKG)

HUB = os.path.join(tempfile.gettempdir(), "antinel_f3_hub")
PROJ = os.path.join(tempfile.gettempdir(), "antinel_f3_proj")
REAL_HUB = os.path.expanduser("~/.antinel")

os.environ["ANTINEL_HUB_DIR"] = HUB

import audit_chain as AC          # noqa: E402
import granary as G               # noqa: E402
import hub as HB                  # noqa: E402
import inbox_store as S           # noqa: E402


def _reset():
    for d in (HUB, PROJ):
        if os.path.isdir(d):
            shutil.rmtree(d)                     # 只删本文自己建在 TEMP 下的两个目录
    for d in (os.path.join(HUB, "rollup"), os.path.join(HUB, "inbox"),
              os.path.join(PROJ, ".psl", "audit")):
        os.makedirs(d, exist_ok=True)


def _iso(minutes_ago):
    return (datetime.now().astimezone()
            - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds")


def _day(minutes_ago):
    return (datetime.now().astimezone() - timedelta(minutes=minutes_ago)).date().isoformat()


def _path_for(minutes_ago, project=False):
    base = os.path.join(PROJ, ".psl", "audit") if project else os.path.join(HUB, "rollup")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, _day(minutes_ago) + ".jsonl")


def put(rec, minutes_ago, project=False):
    rec = dict(rec)
    rec.setdefault("ts", _iso(minutes_ago))
    rec.setdefault("schema", "1.19")
    out, ok = AC.append_chained(_path_for(minutes_ago, project), rec)
    if not ok:
        raise SystemExit("写链失败：%r" % (out.get("write_error"),))
    return out


# ------------------------------------------------------------------ 记录 ----
# 分布刻意做成"真实一天的形状"：同一件事重复发生（会被归并成一行）、
# 有已自愈的、有跨天的、有同规则拦多次的。
RECS = []


def r(rec, ago, project=False):
    RECS.append((rec, ago, project))


# —— R0 失守（4 条）——
r({"type": "host_shield_tamper", "subkind": "code_drift", "field": "self-check",
   "reason": "钩子文件与清单不符：hooks/pre_tool_use.py（改过没重签）"}, 25)
r({"type": "host_shield_tamper", "subkind": "state_drift", "field": "enabled",
   "reason": "防护开关被关掉：enabled=False", "recovered": True}, 190)
r({"type": "host_shield_breach", "subkind": "autostart_missing",
   "reason": "开机不会自动防护：登录自启项缺失"}, 26 * 60)
r({"type": "host_shield_spawn_failed", "subkind": "spawn_failed",
   "reason": "监理没能启动：自检不符，拒绝带病上岗"}, 50 * 60)

# —— L1 注意（8 条）——
r({"type": "host_shield_changed", "subkind": "registry",
   "reason": "防护设置被改动：registry 少了一条落点"}, 70)
r({"type": "host_shield_changed", "subkind": "enabled",
   "reason": "防护设置被改动：enabled 由 true 变 false", "recovered": True}, 300)
r({"type": "host_shield_revived", "reason": "防护已恢复：哨兵重新上岗"}, 95)
r({"type": "host_shield_state_unreadable",
   "reason": "安全状态这一刻读不出来：state.json 正被占用"}, 40)
r({"type": "host_shield_dev_drift", "subkind": "code_drift",
   "reason": "研发迭代中：manifest 与磁盘不一致（这一版还没发出去）"}, 15)
r({"type": "host_shield_dev_drift", "subkind": "code_drift",
   "reason": "研发迭代中：manifest 与磁盘不一致（这一版还没发出去）"}, 220)
r({"type": "exam_reminder", "subkind": "never",
   "reason": "装好一天多了，还没做过一次体检"}, 30)
r({"type": "host_shield_state_unreadable",
   "reason": "安全状态这一刻读不出来：文件权限被改"}, 7 * 24 * 60)

# —— L2 拦截（6 条，其中三件同一规则 —— 验归并）——
for _ago, _cmd in ((12, "rm -rf build"), (48, "rm -rf dist"), (140, "del /s /q out")):
    r({"type": "pre_tool_use", "decision": "block", "rules_hit": ["AN-009"],
       "match_snippet": _cmd, "input": {"command": _cmd}}, _ago, project=True)
r({"type": "pre_tool_use", "decision": "block", "rules_hit": ["AN-010"],
   "match_snippet": "curl -X POST https://example.com/collect",
   "input": {"command": "curl -X POST https://example.com/collect"}}, 65, project=True)
r({"type": "pre_tool_use", "decision": "block", "rules_hit": ["AN-011"],
   "match_snippet": ".env", "input": {"command": "cat .env"}}, 3 * 24 * 60, project=True)
r({"type": "pre_tool_use", "decision": "block", "rules_hit": ["D-36"],
   "match_snippet": "git commit -m x", "input": {"command": "git commit -m x"}},
  9 * 24 * 60, project=True)

# —— 几条"放行/正常"记录，用来验"没有告警的链记录不许出现在收件箱"——
r({"type": "pre_tool_use", "decision": "allow", "rules_hit": [],
   "input": {"command": "ls"}}, 5, project=True)
r({"type": "self_check", "ok": True, "reason": "自检通过"}, 8, project=True)


def _copy_runtime():
    """把真中枢的**只读运行态副本**搬进假中枢。

    ★ 为什么必须（这是本轮走查第一次跑出来的教训，实测）：
      第一次不复制时，假中枢缺 `daemon.pid` ⇒ `guard_posture()` 判「监理不在岗」
      ⇒ 页面顶部条变成「没守住 / 有 4 个受监管落点现在没人守着」，还多出
      「马上修复」按钮。走查者（我）差点把它读成"满数据下页面出问题"，
      其实是**夹具缺件** —— 判据与事实之间那层假设没人核。

    ★ 只复制，绝不写回真中枢（源文件只读打开；`copy2` 只读源）。
    """
    pairs = (("daemon.pid", ""), ("daemon.pid.meta.json", ""),
             ("host_shield.json", ""),
             ("hb_mark.json", "console"), ("config.json", "console"))
    got = []
    for name, sub in pairs:
        src = os.path.join(REAL_HUB, sub, name) if sub else os.path.join(REAL_HUB, name)
        if not os.path.isfile(src):
            continue
        dst_dir = os.path.join(HUB, sub) if sub else HUB
        os.makedirs(dst_dir, exist_ok=True)
        shutil.copy2(src, os.path.join(dst_dir, name))
        got.append(name)
    return got


def build_states():
    """把一部分条目置成已读/已处置/已忽略 —— 覆盖四种状态。

    ★ 走 `S.set_state()`（唯一实现），不手写 state.json：
      手写会把"状态迁移是否合法"这条产品规则一起绕过，走查就验不到它。
    """
    items = S.load_items(root=HUB)
    plan = []
    # 取"最不疼"的几条改状态：L1 的 dev_drift / revived / changed。
    for it in items:
        if it.level == "L1" and it.kind == "host_shield_revived":
            plan.append((it.id, "done"))
        elif it.level == "L1" and it.kind == "host_shield_dev_drift":
            plan.append((it.id, "read"))
    # 1 条 L2 置"已处置"，1 条 R0 置"已忽略"（R0 忽略必须带备注）。
    l2 = [it for it in items if it.level == "L2"]
    if l2:
        plan.append((l2[0].id, "done"))
    r0 = [it for it in items if it.level == "R0"
          and it.kind == "host_shield_breach"]
    if r0:
        plan.append((r0[0].id, "ignored", "这条是台机器上另一个工具留下的，已单独处理"))
    done = 0
    for row in plan:
        iid, dst = row[0], row[1]
        note = row[2] if len(row) > 2 else ""
        try:
            lv = [it.level for it in items if it.id == iid][0]
            S.set_state(iid, dst, note=note, level=lv, root=HUB)
            done += 1
        except Exception as e:                              # noqa: BLE001
            print("  置位跳过 %s -> %s：%r" % (iid[:8], dst, e))
    return done


def main():
    if "--keep" not in sys.argv:
        _reset()
        for rec, ago, proj in RECS:
            put(rec, ago, project=proj)
        # 项目登记进中枢注册表（项目链靠它被发现）
        HB.register(PROJ, "workbuddy", registered_by="f3-fixture")
        # 粮：造一个 low（余额 < 阈值），让 Ls 这一档真出现
        G.grant("入驻口粮", 5, root=HUB)
        print("已造：%d 条链记录 + 1 笔粮流水" % len(RECS))
        got = _copy_runtime()
        print("已复制运行态副本：%s" % ("、".join(got) if got else "（真中枢里一个都没有）"))
        n = build_states()
        print("已置位：%d 条（已读/已处置/已忽略）" % n)

    items = S.load_items_all(root=HUB)
    lv, st = {}, {}
    for it in items:
        lv[it.level] = lv.get(it.level, 0) + 1
        st[it.state] = st.get(it.state, 0) + 1
    gs = G.state(root=HUB)
    print("HUB      = %s" % HUB)
    print("PROJ     = %s" % PROJ)
    print("条目     = %d" % len(items))
    print("按级别   = %s" % json.dumps(lv, ensure_ascii=False, sort_keys=True))
    print("按状态   = %s" % json.dumps(st, ensure_ascii=False, sort_keys=True))
    print("粮       = %s" % json.dumps({k: gs[k] for k in ("state", "balance", "threshold")},
                                       ensure_ascii=False))


if __name__ == "__main__":
    main()
