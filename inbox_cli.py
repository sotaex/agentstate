# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

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


def _fmt_level(level):
    # 派生（不写第二份）；未知键原样返回。
    return ("%s（%s）" % (M.state_short(level), level)) if level in M.STATE_LABEL else level


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
    counts = M.counts_by_state(items)
    open_groups = M.count_groups([i for i in items
                                  if M.bucket_of(i) == M.BUCKET_ACTION])
    print("当前载入 %d 条（不是永久全历史）｜最近24小时需你处理 %d 件事"
          % (len(items), open_groups))
    print("未处理 %d 条（未读 %d / 已读 %d）｜已处理 %d｜已忽略 %d"
          % (M.unhandled_count(items), counts["unread"], counts["read"],
             counts["done"], counts["ignored"]))
    if not rows:
        print("（这个筛选范围里没有记录。）")
        return 0
    for i in rows:
        # ★ 0.43.0：命令行的**用户可见文本**也要过 `M.visible_text`（去 markdown 星号）
        #   —— 0.42.0 只做了网页两条路径，CLI 这条漏了（实测 `**不等于**` 照样露出）。
        print("  [%s] %-12s %s  %s" % (i.id, _fmt_level(i.level), _fmt_state(i.state),
                                       M.visible_text(i.title)))
        meta = " · ".join(x for x in (M.visible_text(i.detail),
                                      ("规则 " + i.rule_id) if i.rule_id else "",
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
    print("  级别：%s ｜ 状态：%s" % (_fmt_level(it.level), _fmt_state(it.state)))
    print("  标题：%s" % M.visible_text(it.title))
    if it.detail:
        print("  原因：%s" % M.visible_text(it.detail))
    if it.rule_id:
        print("  规则：%s ｜ 命中：%s" % (it.rule_id, M.visible_text(it.snippet)))
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


def cmd_export(a):
    """导出。**必须先把口径说清楚**（交接件 §5 待审：导出与页面口径一致）。

    ★ 0.35.3 修：旧版一声不吭导出**全部已载入记录**（实测本机 227 条），
      而页面首屏说的是「要处理 4 件事」。用户拿到 CSV 会以为 227 条都是待办
      —— 数字没错，**口径没说** ⇒ 与项目已复发三次的"分母不明"同型。
      ⇒ 导出前**必须**打印分母与时间范围。

    ★★ 0.35.3 再修（本轮实测抓到的真缺陷）：上一版把口径当**第一行前缀**
      塞进所有格式 ⇒ `--format json` 的输出**根本不是合法 JSON**
      （实测 `json.loads` 直接 JSONDecodeError）。
      这比"没说口径"更糟：机器读不了，人也不好复制。
      ⇒ JSON 口径**放进结构内部**（`_export_scope` 字段），前缀只留给
        人类读的 csv/md；`--out` 落盘时 JSON 文件是**纯 JSON**。
    """
    items = S.load_items()
    scope = ("当前已载入的全部 %d 条记录（含已处理与已忽略）；"
             "不等于待办件数；不做时间窗口筛选，也不是永久全历史。" % len(items))
    fmt = a.format
    if fmt == "json":
        # 口径进结构，不进前缀 ⇒ 文件始终是合法 JSON
        txt = S.export_items(fmt="json", scope=scope)
    else:
        txt = S.export_items(fmt=fmt)
    note = "口径：%s" % scope
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(txt)
        if fmt == "json":
            # 机器可读文件不加前缀；口径已在 _export_scope 字段里
            print("已导出到 %s（JSON；口径写在 _export_scope 字段里）" % a.out)
        else:
            print("%s" % note)
            print("已导出到 %s" % a.out)
    else:
        if fmt == "json":
            print(txt)          # 不加前缀，直接输出合法 JSON
        else:
            print(note)
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
    # ★ 0.48.5（B1）：口令/中枢根可传入（守护进程重拉时沿用旧口令 ⇒ URL 不变）
    inbox_server.serve(port=a.port, root=getattr(a, "root", None),
                       open_browser=a.open, token=getattr(a, "token", None))
    return 0


def cmd_open(a):
    """★ 0.35.2：**打开值守台**的唯一入口（托盘气泡、外部调用都走这里）。

    ★ 本进程**就是**值守台：`serve()` 会一直跑（`serve_forever`）。
      为什么不能只用 `ensure_background()` —— 它把服务放在**后台线程**里，
      命令一返回、进程一退，服务就没了（开出来的窗口**立刻失联**）。
    ★ 不自己拼 URL、不自己起服务：都委托 `inbox_server`，**不二次实现**。
    ★ 首选端口被占 ⇒ `serve()` 自动换临时端口（Windows 上光靠 `OSError`
      发现不了端口被占，见 `inbox_server._port_busy`）。
    """
    import inbox_server as SV
    SV.serve(port=SV.DEFAULT_PORT, open_browser=True)
    return 0


def cmd_window(a):
    """★ 0.48.5（B1）：**确保服务在跑 + 开独立窗口**（一键入口，`antinel.cmd` 用它）。

    ★ 与 `open` 的分工：`open` 是"这个进程**就是**服务"（前台，关窗即停）；
      `window` 是"**确保**服务在跑（不在就按原端口/口令重拉），再开窗" ——
      因此它不会因为关掉窗口就把服务带走（B1 的验收要求：窗口关了、服务还在，
      窗口再开、URL 不变）。
    ★ 不二次实现：判活/重拉/开窗全委托 `inbox_server`。

    ★★ 2026-10-13（C4）补**等它就位**并如实报告：
      旧实现只 `open_console(url)` 就返回 —— 而落位跑在 daemon 线程里，
      本进程 2 秒后就退出 ⇒ 线程随进程死、Edge 建窗要 1–2.5s
      ⇒ **落位从未执行**，窗口出生尺寸不对，且屏幕上什么都不说。
      （两臂探针实证：CLI 形状 `place_all` 0 次 / 长命形状 1 次。）
      ⇒ 现在改调 `open_console_settled()`：它等窗口出现、落位、**回读校验**，
        并把"这次到底就位了没有"打到屏上（维四：可观测）。
      ★ 落位失败**不关窗**、不返回非零 —— 窗口确实开出来了（那正是要的），
        位置没对由人决定怎么办；但**必须出声**，不许静默。
    """
    import inbox_server as SV
    rec, started = SV.ensure_console(root=getattr(a, "root", None))
    if not rec or not rec.get("url"):
        print("值守台没起来：拿不到端口/口令记录 —— 看 `antinel inbox serve` 的输出",
              file=sys.stderr)
        return 1
    print("值守台%s：%s" % ("已重拉" if started else "已在跑", rec["url"]))
    rep = SV.open_console_settled(rec["url"])
    if rep.get("placed"):
        w = rep.get("want") or [0, 0, 0, 0]
        print("[window] 已就位：%dx%d @(%d,%d)（开窗方式：%s）"
              % (w[2], w[3], w[0], w[1], rep.get("opened")))
    else:
        print("[window] ⚠ 窗口开出来了（%s），但**没能就位**：%s"
              % (rep.get("opened"), rep.get("why")), file=sys.stderr)
        if rep.get("got"):
            print("[window]     实测 %s ／ 目标 %s"
                  % (rep["got"], rep.get("want")), file=sys.stderr)
        print("[window]     面板**仍在屏幕上，没有被关掉** —— 位置不对由你决定"
              "（可手动拖，或重跑一次 `antinel inbox window`）。",
              file=sys.stderr)
    return 0


def cmd_tray(a):
    import inbox_tray
    if not inbox_tray.tray_available():
        print("这台机器起不了托盘（需要 Windows + PowerShell）。其余功能不受影响。")
        return 3
    ok = inbox_tray.run(block=True)
    return 0 if ok else 1


def cmd_daemon(a):
    import inbox_daemon as DM
    sup = bool(getattr(a, "supervise", False))
    # ★ 0.48.5（B1）：先看有没有**别的**守护进程在跑 —— 只为把话说清楚；
    #   真正的单例判定在 `run_daemon()` 里（唯一实现，启动脚本自觉不算数）。
    alive, pid = DM.daemon_alive()
    if alive and pid != os.getpid():
        print("值守台守护进程**已经在跑**了（pid %s）—— 本次不重复启动。" % pid)
        return 0
    print("值守台守护进程已启动（每 %.1f 秒一轮%s）。Ctrl+C 停。"
          % (a.interval, "；顺带监督值守台服务" if sup else ""))
    DM.run_daemon(interval=a.interval, supervise=sup)
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
        import inbox_daemon as DM
        DM.record_day(items=S.load_items())
        s = L.summary()
        if not s["days"]:
            print("账本尚无可核对记录；这表示还没有可统计的事件，不是确认累计为零。")
        else:
            print("连续有记录 %d 天 ｜ 拦截 %d ｜ 注意 %d ｜ 防护缺口 %d ｜ 已处理/已忽略 %d ｜ 有记录的天数 %d"
                  % (s["streak_days"], s["blocked"], s["noticed"], s["breached"],
                     s["acked"], s["days"]))
        print("只统计本机审计记录；不代表全天在线，也不是 AI 工具积分余额。")
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

    p = sub.add_parser("list", help="列出收件箱记录（默认列出所有未关闭记录，不等于待办件数）")
    p.add_argument("--state", default="open",
                   choices=["open", "unread", "read", "done", "ignored", "all"],
                   help="记录状态筛选：open=未读+已读（默认），all=所有当前载入记录")
    p.add_argument("--level", help="按级别筛选：R0=失守，L2=拦截，L1=注意，Ls=预算")
    p.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("show", help="查看一条告警的原因与证据")
    p.add_argument("id", help="告警编号")
    p.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("read"); p.add_argument("id"); p.set_defaults(fn=cmd_read)
    p = sub.add_parser("ack"); p.add_argument("id"); p.add_argument("--note", default="")
    p.set_defaults(fn=cmd_ack)
    p = sub.add_parser("ignore"); p.add_argument("id"); p.add_argument("--note", default="")
    p.set_defaults(fn=cmd_ignore)
    # ★ 0.35.3：`read-all` 子命令**已取消**（创始人 2026-10-06「1 取消吧」）。
    #   已读改由「点开即已读」（值守台页面）产生，不再有批量入口。

    p = sub.add_parser(
        "export",
        help="导出当前已载入的全部记录（含已处理与已忽略，不等于待办件数）")
    p.add_argument("--format", default="json", choices=["json", "csv", "md"],
                   help="导出格式")
    p.add_argument("--out", help="写入指定文件；省略则输出到终端")
    p.set_defaults(fn=cmd_export)

    p = sub.add_parser("report", help="按某个本地自然日生成日报（不是最近24小时报告）")
    p.add_argument("--date", help="本地日期 YYYY-MM-DD；省略时为今天")
    p.add_argument("--format", default="text", choices=["text", "md", "json"],
                   help="输出格式：text（默认）、md 或 json；输出到终端")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("serve"); p.add_argument("--port", type=int, default=8790)
    # ★ 0.48.5（B1）：`--token`（重拉时沿用旧口令 ⇒ URL 不变）、`--root`（隔离中枢）
    p.add_argument("--token", default=None,
                   help="复用指定口令（守护进程重拉时用；缺省随机生成）")
    p.add_argument("--root", default=None, help="中枢根目录（判据/多实例隔离用）")
    p.add_argument("--open", action="store_true"); p.set_defaults(fn=cmd_serve)
    # ★ 0.35.2：「打开值守台」的稳定入口（气泡点击 / 托盘 / 外部调用都用它）
    sub.add_parser("open").set_defaults(fn=cmd_open)
    # ★ 0.48.5（B1）：「确保服务在跑 + 开独立窗口」—— 一键入口（antinel.cmd 用它）
    sub.add_parser("window").set_defaults(fn=cmd_window)
    sub.add_parser("tray").set_defaults(fn=cmd_tray)
    p = sub.add_parser("daemon"); p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--supervise", action="store_true",
                   help="顺带监督值守台服务：被杀掉后在 60 秒内按原端口/口令重拉")
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

    p = sub.add_parser("ledger", help="查看或导出本机事件账本（非 AI 工具积分余额）")
    ps = p.add_subparsers(dest="sub", required=True)
    ps.add_parser("show", help="刷新并查看本机可核对事件汇总")
    q = ps.add_parser("export", help="导出已记账的逐日摘要")
    q.add_argument("--out", help="将导出内容写入指定文件；省略则输出到终端")
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
