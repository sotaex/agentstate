#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""0.64 前置 · P1 分桶：那批「无 decision 字段 / decision 为 None」的记录到底是什么 type。

拍板结论（2026-10-31）：P1 = 先按 type 分层，再决定哪些可以静音。
本探针只回答一个问题：**这 N 条无 decision 的记录，按 type 分布是什么？**
它不做产品判断，不做回退决策，只出读数。

自证三腿（缺一不下结论）：
  正控  人造一条同时含 type 与 decision 的记录 ⇒ 必须被算进"有 decision"侧
  负控  人造一条只含 type 的记录           ⇒ 必须被算进"无 decision"侧
  可读  必须打印「读到几个文件、几条记录」，防"读到空也是 0 条无 decision"
"""
import argparse
import collections
import json
import os
import sys
import tempfile
import time

_OUT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _OUT not in sys.path:
    sys.path.insert(0, _OUT)
import _commit                                              # noqa: E402

_LOCK_EVENTS = "lock_events.jsonl"

# 这些 type 的名字本身表明"发生过拦截/失守/篡改"，静音要格外小心。
# 注意：这是**名字**分类，不是语义分类；用它只为把风险面排前面，不作为结论。
_ALARM_HINTS = ("block", "breach", "deny", "denied", "tamper", "host_changed",
                "self_tamper", "violation", "reject", "escalat")


def is_daily_name(name):
    """只认 YYYY-MM-DD.jsonl。锁事件文件不是日文件，混进来会把日期读错。"""
    base = os.path.basename(name)
    if not base.endswith(".jsonl"):
        return False
    stem = base[:-6]
    if len(stem) != 10 or stem[4] != "-" or stem[7] != "-":
        return False
    return stem[:4].isdigit() and stem[5:7].isdigit() and stem[8:].isdigit()


def read_records(audit_dir):
    """返回 (records, files_read)。files_read 用于自证"真的读到了东西"。"""
    recs = []
    files = 0
    for name in sorted(os.listdir(audit_dir)):
        if not is_daily_name(name) or name == _LOCK_EVENTS:
            continue
        path = os.path.join(audit_dir, name)
        if not os.path.isfile(path):
            continue
        files += 1
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    recs.append(json.loads(line))
                except Exception:
                    continue
    return recs, files


def has_decision(rec):
    """『有 decision』的判定必须只有一处。

    两条都要算『无』：键不存在；键存在但值为 None。
    v0.2 契约把这两种合成一类，因为对回退表而言它们的处理相同
    —— 除非 P1 分层后要求区分，那时再拆。
    """
    return rec.get("decision") is not None


def _selfcheck():
    """正控 / 负控 / 可读三腿。全部用 tempdir 造，跑完即弃。"""
    tmp = tempfile.mkdtemp(prefix="p1_bucket_")
    try:
        # 正控：有 decision 的字面量  +  负控：无 decision 键  +  负控：decision=None
        with open(os.path.join(tmp, "2026-01-01.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "pos_ctl", "decision": "alert"}) + "\n")
            fh.write(json.dumps({"type": "neg_ctl_missing"}) + "\n")
            fh.write(json.dumps({"type": "neg_ctl_none", "decision": None}) + "\n")
        # 干扰腿：非日文件名必须被排除，否则"读到几个文件"会虚高
        with open(os.path.join(tmp, _LOCK_EVENTS), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "lock_noise"}) + "\n")

        recs, files = read_records(tmp)
        with_d = [r for r in recs if has_decision(r)]
        without_d = [r for r in recs if not has_decision(r)]

        ok = True
        def check(name, cond, detail):
            nonlocal ok
            print("  [%s] %-22s %s" % ("PASS" if cond else "FAIL", name, detail))
            if not cond:
                ok = False

        check("可读腿", files == 1 and len(recs) == 3,
              "读到 %d 个日文件 %d 条记录（期望 1 / 3，锁事件已被排除）" % (files, len(recs)))
        check("正控腿", len(with_d) == 1 and with_d[0]["type"] == "pos_ctl",
              "有 decision 侧 %d 条" % len(with_d))
        check("负控腿·缺键", any(r["type"] == "neg_ctl_missing" for r in without_d),
              "缺键记录落入『无 decision』侧")
        check("负控腿·值为 None", any(r["type"] == "neg_ctl_none" for r in without_d),
              "decision=None 落入『无 decision』侧")
        check("干扰腿", not any(r["type"] == "lock_noise" for r in recs),
              "%s 未被计入" % _LOCK_EVENTS)
        return ok
    finally:
        for name in os.listdir(tmp):
            try:
                os.unlink(os.path.join(tmp, name))
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass


def emit_json(path, payload):
    """落盘并**回读自证**，返回 `{chars_parsed, how}`。

    ★ 写前先量「值不值得写」：一个 json 只要结构对，读起来就完全正常，
      哪怕里面的数是空集。所以回读校验之外还要在调用处给关键分母，
      让「0 条」与「没读到」在产出件里也是两个不同的东西。

    ★ tmp+replace+回读不再自己写：本机 `os.replace` 到已存在目标会偶发
      WinError 5（2026-11-03 实测），一次瞬时冲突就让产出件没写成。
      重试与退路收在 `output/_commit.py`，五条线共用一份。
    """
    return _commit.write_json(path, payload)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit-dir", default=".psl/audit")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--json", default=None, metavar="PATH",
                    help="把这次读数写成 json（同一条命令重跑会覆盖，不叠加）")
    args = ap.parse_args()

    if not os.path.isdir(args.audit_dir):
        print("[FATAL] 审计目录不存在：%s" % args.audit_dir)
        return 2

    print("=" * 74)
    print("P1 分桶 · 无 decision 记录的 type 分布")
    print("读取时刻 %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    print("读取面   %s" % os.path.abspath(args.audit_dir))
    print("=" * 74)
    print("\n[自证腿]")
    if not _selfcheck():
        print("\n[FATAL] 自证腿未全过，读数不可用。")
        return 1

    recs, files = read_records(args.audit_dir)
    if not recs:
        print("\n[FATAL] 读到 0 条记录 —— 是空目录或路径不对，不是『没有无 decision 记录』。")
        return 1

    with_d = [r for r in recs if has_decision(r)]
    without_d = [r for r in recs if not has_decision(r)]
    total = len(recs)
    print("\n[总量] 日文件 %d 个 · 记录 %d 条" % (files, total))
    print("       有 decision  %6d 条  %5.1f%%" % (len(with_d), 100.0 * len(with_d) / total))
    print("       无 decision  %6d 条  %5.1f%%" % (len(without_d), 100.0 * len(without_d) / total))

    # ---- 分桶：type × 有无 decision ----
    all_types = collections.Counter(r.get("type") or "(无 type 字段)" for r in recs)
    nd_types = collections.Counter(r.get("type") or "(无 type 字段)" for r in without_d)

    print("\n[分桶] 按 type 列出『无 decision 占比』（分母=该 type 的总条数）")
    print("  %-30s %8s %8s %8s %7s" % ("type", "总条数", "无decision", "有decision", "无占比"))
    rows = []
    for t, tot in all_types.most_common(args.top):
        nd = nd_types.get(t, 0)
        rows.append((t, tot, nd, tot - nd, 100.0 * nd / tot if tot else 0.0))
    for t, tot, nd, wd, pct in rows:
        flag = ""
        if any(h in t.lower() for h in _ALARM_HINTS) and nd:
            flag = "  ← 名字像告警"
        print("  %-30s %8d %8d %8d %6.1f%%%s" % (t, tot, nd, wd, pct, flag))

    # ---- 结论面：全部 type 都被覆盖吗 ----
    only_nd = [t for t, tot in all_types.items() if nd_types.get(t, 0) == tot]
    only_wd = [t for t, tot in all_types.items() if nd_types.get(t, 0) == 0]
    print("\n[结构] 全部记录都无 decision 的 type：%d 类" % len(only_nd))
    for t in sorted(only_nd):
        print("   - %-28s %6d 条" % (t, all_types[t]))
    print("\n[结构] 从未出现无 decision 的 type：%d 类" % len(only_wd))
    print("   " + "、".join(sorted(only_wd)[:14]) + ("…" if len(only_wd) > 14 else ""))

    alarm_nd = sum(n for t, n in nd_types.items() if any(h in t.lower() for h in _ALARM_HINTS))
    print("\n[风险面] 名字含告警词且无 decision：%d 条（占无 decision 的 %.1f%%）"
          % (alarm_nd, 100.0 * alarm_nd / len(without_d) if without_d else 0.0))

    # ---- 分日趋势：这批记录是历史遗留还是当前仍在产生 ----
    print("\n[趋势] 无 decision 记录按日（只看最近 12 天，判断是否仍在产生）")
    by_day_nd = collections.Counter()
    by_day_all = collections.Counter()
    for r in recs:
        d = str(r.get("ts") or r.get("time") or r.get("at") or "")[:10]
        if len(d) != 10:
            continue
        by_day_all[d] += 1
        if not has_decision(r):
            by_day_nd[d] += 1
    for d in sorted(by_day_all)[-12:]:
        nd = by_day_nd.get(d, 0)
        tot = by_day_all[d]
        print("   %s  %6d / %6d  %5.1f%%" % (d, nd, tot, 100.0 * nd / tot if tot else 0.0))

    if args.json:
        payload = {
            "read_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "audit_dir": os.path.abspath(args.audit_dir),
            "files_read": files,
            "records": total,
            "with_decision": len(with_d),
            "without_decision": len(without_d),
            "selfcheck_ok": True,
            "by_type": [
                {"type": t, "total": tot, "without_decision": nd,
                 "with_decision": wd, "pct_without": round(pct, 2),
                 "name_looks_alarm": bool(any(h in t.lower() for h in _ALARM_HINTS))}
                for t, tot, nd, wd, pct in rows
            ],
            "types_all_without_decision": {t: all_types[t] for t in only_nd},
            "types_never_without_decision": sorted(only_wd),
            "risk": {"n_without_decision_alarm_named": alarm_nd,
                     "pct_of_without_decision": round(
                         100.0 * alarm_nd / len(without_d), 2) if without_d else 0.0},
            "by_day": [{"day": d, "without_decision": by_day_nd.get(d, 0),
                        "total": by_day_all[d],
                        "pct_without": round(
                            100.0 * by_day_nd.get(d, 0) / by_day_all[d], 2)
                        if by_day_all[d] else 0.0}
                       for d in sorted(by_day_all)[-12:]],
        }
        try:
            r = emit_json(args.json, payload)
            print("已写 %s（%d 字节 / %d 字符，落盘路径 %s）"
                  % (args.json, r["bytes"], r["chars"], r["how"]))
            # ★ 自证：两侧相加必须等于总量。不等于就是分桶漏了一类，
            #   而屏幕上「有/无」两行照样各自都对。
            if len(with_d) + len(without_d) != total:
                print("★ 两侧之和 %d ≠ 总量 %d —— 分桶漏了"
                      % (len(with_d) + len(without_d), total))
                return 1
        except Exception as exc:                        # noqa: BLE001
            print("✗ 写出失败：%s: %s" % (type(exc).__name__, exc))
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
