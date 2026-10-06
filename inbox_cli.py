# -*- coding: utf-8 -*-
"""值守台 · 命令行（自包含）。

★ 为什么自包含：本模块**不依赖 `antinel.py` 的内部结构**，
  集成时只需在 `antinel.py` 里加三行把参数转进来（见交付件里的补丁）。
  这样"进包"这一步可以**最后做、单独验**，不影响前面八层的反复重跑。

★ 判据不许二次实现：列表/状态/日报/账本全部调 `inbox_*` 模块，这里只排版。

★ 用户视角纪律：命令由 Agent 跑、结论用人话讲；所以这里的输出**给人看**，
  不堆术语，`--json` 才给机器。

用法（未集成时也能跑）：
    python inbox_cli.py list
    python inbox_cli.py report
    python inbox_cli.py serve --open
"""
from __future__ import annotations

import argparse
import json
import sys

import inbox_config as CFG
import inbox_model as M
import inbox_report as R
import inbox_store as S
import ledger as L


def _fmt_state(s):
    return {"unread": "未读", "read": "已读", "done": "已处理",
            "ignored": "已忽略"}.get(s, s)


def _filter_items(items, state="open", level=None):
    if state == "all":
        rows = list(items)
    elif state == "open":
        rows = [i for i in items if i.state in M.OPEN_STATES]
    else:
        rows = [i for i in items if i.state == state]
    if level:
        want = {x.strip().upper() for x in level.split(",") if x.strip()}
        rows = [i for i in rows if i.level in want]
    return rows


def cmd_list(a):
    items = S.load_items()
    rows = _filter_items(items, a.state, a.level)
    if a.json:
        print(json.dumps([i.to_dict() for i in rows], ensure_ascii=False, indent=1))
        return 0
    print("状态：%s ｜ 未处理 %d ｜ 未读 %d ｜ 已读 %d ｜ 已处理 %d ｜ 已忽略 %d"
          % (M.console_state(items), M.unhandled_count(items),
             M.counts_by_state(items)["unread"], M.counts_by_state(items)["read"],
             M.counts_by_state(items)["done"], M.counts_by_state(items)["ignored"]))
    if not rows:
        print("（这里没有需要你处理的事。）")
        return 0
    for i in rows:
        print("  [%s] %-4s %s  %s" % (i.id, i.level, _fmt_state(i.state), i.title))
        meta = " · ".join(x for x in (i.detail, ("规则 " + i.rule_id) if i.rule_id else "",
                                      i.ts) if x)
        if meta:
            print("        %s" % meta)
    return 0


def _find(items, iid):
    for i in items:
        if i.id == iid:
            return i
    return None


def cmd_show(a):
    items = S.load_items()
    it = _find(items, a.id)
    if not it:
        print("找不到告警 %s" % a.id)
        return 2
    if a.json:
        print(json.dumps(it.to_dict(), ensure_ascii=False, indent=1))
        return 0
    print("告警 %s" % it.id)
    print("  级别：%s ｜ 状态：%s" % (it.level, _fmt_state(it.state)))
    print("  标题：%s" % it.title)
    if it.detail:
        print("  原因：%s" % it.detail)
    if it.rule_id:
        print("  规则：%s ｜ 命中：%s" % (it.rule_id, it.snippet))
    print("  时间：%s" % it.ts)
    if it.chain_ref:
        print("  链上位置：%s（可用 `antinel verify` 核）" % it.chain_ref)
    if it.note:
        print("  备注：%s" % it.note)
    return 0


def _set(a, dst):
    try:
        S.set_state(a.id, dst, note=getattr(a, "note", "") or "")
    except M.NoteRequired as e:
        print("不能这么忽略：%s" % e)
        return 2
    except M.InboxError as e:
        print("操作被拒：%s" % e)
        return 2
    print("已置为「%s」。" % _fmt_state(dst))
    return 0


def cmd_read(a):
    return _set(a, "read")


def cmd_ack(a):
    return _set(a, "done")


def cmd_ignore(a):
    return _set(a, "ignored")


def cmd_read_all(a):
    n = S.mark_all_read()
    print("已把 %d 条未读标为已读。**未处理数不变**（已读 ≠ 已处理）。" % n)
    return 0


def cmd_export(a):
    txt = S.export_items(fmt=a.format)
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(txt)
        print("已导出到 %s" % a.out)
    else:
        print(txt)
    return 0


def cmd_report(a):
    rep = R.daily_report(day=a.date)
    if a.format == "json":
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    elif a.format == "md":
        print(R.render_markdown(rep))
    else:
        print(R.render_text(rep))
    return 0


def cmd_serve(a):
    import inbox_server
    inbox_server.serve(port=a.port, open_browser=a.open)
    return 0


def cmd_tray(a):
    import inbox_tray
    if not inbox_tray.tray_available():
        print("这台机器起不了托盘（需要 Windows + PowerShell）。其余功能不受影响。")
        return 3
    ok = inbox_tray.run(block=True)
    return 0 if ok else 1


def cmd_daemon(a):
    import inbox_daemon
    print("值守台守护进程已启动（每 %.1f 秒一轮）。Ctrl+C 停。" % a.interval)
    inbox_daemon.Daemon().run(interval=a.interval)
    return 0


def cmd_config(a):
    cfg = CFG.load()
    if a.sub == "list":
        print(json.dumps({k: v for k, v in cfg.items() if not k.startswith("_")},
                         ensure_ascii=False, indent=1))
        return 0
    if a.sub == "get":
        print(json.dumps(cfg.get(a.key), ensure_ascii=False))
        return 0
    if a.sub == "set":
        v = a.value
        low = str(v).lower()
        if low in ("true", "false"):
            v = (low == "true")
        else:
            try:
                v = int(v)
            except ValueError:
                pass
        cfg[a.key] = v
        cfg.pop("_corrupt", None)
        CFG.save(cfg)
        print("%s = %s" % (a.key, json.dumps(cfg[a.key], ensure_ascii=False)))
        return 0
    return 2


def cmd_heartbeat(a):
    import heartbeat as HB
    if a.sub == "status":
        import time
        import inbox_daemon as DM
        cfg = CFG.load()
        print("匿名计数：%s" % ("开" if cfg.get("heartbeat") else "关（默认）"))
        print("端点：%s" % (cfg.get("heartbeat_endpoint") or "（未配置）"))
        # ★ 自动发送的可观测性：守护进程今天发了没有、结果是什么，必须能查到
        mark = DM._load_hb_mark()
        today = time.strftime("%Y-%m-%d")
        if not mark:
            print("今日自动发送：尚无记录（守护进程未跑过，或统计从未开启）")
        elif mark.get("date") != today:
            print("今日自动发送：未发（上次是 %s）" % mark.get("date"))
        else:
            print("今日自动发送：%s，第 %s 次尝试，结果 %s"
                  % ("已发" if mark.get("ok") else "尝试过但失败",
                     mark.get("tries"), mark.get("why")))
        return 0
    if a.sub == "on":
        cfg = CFG.load()
        cfg["heartbeat"] = True
        CFG.save(cfg)
        print("已开启。只发 5 个字段：本机编号 / 日期 / 版本 / 当天各级计数 / 格式版本。")
        print("不发规则名、路径、内容、IP、用户名、机器名。")
        return 0
    if a.sub == "off":
        cfg = CFG.load()
        cfg["heartbeat"] = False
        CFG.save(cfg)
        print("已关闭。")
        return 0
    if a.sub == "forget":
        HB.forget()
        print("已删除本机编号。")
        return 0
    if a.sub == "send":
        ok, why = HB.send_once()
        print("发送%s%s" % ("成功" if ok else "失败", ("：%s" % why) if why else ""))
        return 0 if ok else 1
    return 2


def cmd_ledger(a):
    if a.sub == "show":
        s = L.summary()
        print("连续值守 %d 天 ｜ 累计拦截 %d ｜ 已处理 %d ｜ 账本天数 %d"
              % (s["streak_days"], s["blocked"], s["acked"], s["days"]))
        print("这份账本只在本机（~/.antinel/ledger/），可导出，不可转让。")
        return 0
    if a.sub == "export":
        txt = L.export()
        if a.out:
            with open(a.out, "w", encoding="utf-8", newline="\n") as f:
                f.write(txt)
            print("已导出到 %s" % a.out)
        else:
            print(txt)
        return 0
    return 2


def build_parser():
    ap = argparse.ArgumentParser(prog="antinel inbox", description="值守台")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list"); p.add_argument("--state", default="open",
                                               choices=["open", "unread", "read", "done",
                                                        "ignored", "all"])
    p.add_argument("--level"); p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("show"); p.add_argument("id"); p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("read"); p.add_argument("id"); p.set_defaults(fn=cmd_read)
    p = sub.add_parser("ack"); p.add_argument("id"); p.add_argument("--note", default="")
    p.set_defaults(fn=cmd_ack)
    p = sub.add_parser("ignore"); p.add_argument("id"); p.add_argument("--note", default="")
    p.set_defaults(fn=cmd_ignore)
    sub.add_parser("read-all").set_defaults(fn=cmd_read_all)

    p = sub.add_parser("export"); p.add_argument("--format", default="json",
                                                 choices=["json", "csv", "md"])
    p.add_argument("--out"); p.set_defaults(fn=cmd_export)

    p = sub.add_parser("report"); p.add_argument("--date")
    p.add_argument("--format", default="text", choices=["text", "md", "json"])
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("serve"); p.add_argument("--port", type=int, default=8790)
    p.add_argument("--open", action="store_true"); p.set_defaults(fn=cmd_serve)
    sub.add_parser("tray").set_defaults(fn=cmd_tray)
    p = sub.add_parser("daemon"); p.add_argument("--interval", type=float, default=2.0)
    p.set_defaults(fn=cmd_daemon)

    p = sub.add_parser("config"); ps = p.add_subparsers(dest="sub", required=True)
    ps.add_parser("list")
    q = ps.add_parser("get"); q.add_argument("key")
    q = ps.add_parser("set"); q.add_argument("key"); q.add_argument("value")
    p.set_defaults(fn=cmd_config)

    p = sub.add_parser("heartbeat"); ps = p.add_subparsers(dest="sub", required=True)
    for name in ("status", "on", "off", "forget", "send"):
        ps.add_parser(name)
    p.set_defaults(fn=cmd_heartbeat)

    p = sub.add_parser("ledger"); ps = p.add_subparsers(dest="sub", required=True)
    ps.add_parser("show")
    q = ps.add_parser("export"); q.add_argument("--out")
    p.set_defaults(fn=cmd_ledger)
    return ap


def main(argv=None):
    args = build_parser().parse_args(sys.argv[1:] if argv is None else list(argv))
    try:
        return int(args.fn(args) or 0)
    except M.InboxError as e:
        print("出错了：%s" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
