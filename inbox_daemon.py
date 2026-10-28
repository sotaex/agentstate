# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Antinel 监理 · 守护进程：把五层串起来跑。

一轮 `tick()` 干这些事（顺序固定）：

    ① 读链（真源）→ 组装收件箱
    ② 找**新**告警（`seen.json` 记已见 id）→ 通知层（Toast）+ 强调层（仅 R0）+ 兜底层
    ③ 刷**托盘**状态（五态 + 未处理数）
    ④ 记**账本**（最近 14 天补记＋更正，追加写、同日取末行）
    ⑤ 消费**托盘动作**（open / quit；0.35.3 起取消 read_all）
    ⑥ **匿名计数心跳**（默认关；开着时每个本地日最多 `HB_MAX_TRIES` 次尝试）

★ 热路径纪律：钩子里只写链；**所有渲染、通知、聚合都在这里做** ——
  所以这里可以慢，钩子必须快。
★ 全部外部依赖可注入（backend/sound/overlay/sender/poster/hb_poster），测试零副作用。
★ 不删任何文件。

★ ⑥ 的三条不许松（详见 `_heartbeat_once`）：
  1. 关 ⇒ **一个请求不发、一个字节不落盘**；
  2. 报文由 `heartbeat.send_once()` 构造并自检，守护进程**不自己拼包**；
  3. 失败当天**不无限重试**（最多 3 次、间隔 ≥1 小时）。
"""
from __future__ import annotations

import json
import os
import time
from datetime import date, timedelta

import inbox_config as CFG
import inbox_bubble as BB
import inbox_emphasis as EM
import inbox_fallback as FB
import inbox_model as M
import inbox_notify as NT
import inbox_store as S
import inbox_tray as TR
import heartbeat as HB
import ledger as L

# 匿名计数：每个本地日的尝试上限与最小重试间隔（秒）
HB_MAX_TRIES = 3
HB_RETRY_GAP = 3600


def seen_path(root=None):
    return os.path.join(CFG.console_dir(root), "seen.json")


def hb_mark_path(root=None):
    """当日心跳标记。**关着时这个文件根本不会被创建**（零副作用）。"""
    return os.path.join(CFG.console_dir(root), "hb_mark.json")


#: ★ 0.51.0（账准修复，创始人 2026-10-16 拍板）：补记/更正窗口＝最近 14 个日历天。
#:   窗口取 14 不取 7：一次离开超过一周（出差/休假）回来也要能把漏掉的天补齐，
#:   而每天 14 次比对的开销是常数级（幂等日子一个字节都不写）。
BACKFILL_DAYS = 14


def record_day(items=None, today=None, root=None):
    """记账本（最近 14 天补记＋更正）—— **唯一实现**
    （守护进程 `tick()` 与Antinel 监理都调它，不二次实现）。

    ★★ 为什么提出来（真缺陷，创始人 2026-10-07「账本这栏数据永远都是零」）：
      旧版这段逻辑**只**在 `Daemon.tick()` 里，而 `Daemon` 只能靠
      `antinel inbox daemon` 手动起 —— 全仓**没有任何自动启动点**
      ⇒ 账本文件从不落盘 ⇒ 页面四个数**恒为 0**（`~/.antinel/ledger/daily.jsonl`
      本机实测不存在）。Antinel 监理（`inbox_server.serve`）才是用户真正会打开的东西，
      所以让它**在打开期间**也记这一行。
    ★★ 0.51.0 账准修复（创始人 2026-10-16「最近 7 天几乎全零」四问）：
      旧版只写 `today` 一天 ⇒ ① Antinel 监理没开的日子**整天漏记**（实测 10-11/10-12
      零行，而链里这两天有 24 次拦截）；② 快照后补进链的事件，历史日**永不
      更正**（10-09 快照 9/9/60，链现算实为 18/81/117）。⇒ 扩成对**最近 14 天**
      逐日：缺行且链里有事件 ⇒ 补记；有行但数字与链现算不符 ⇒ **追加更正行**
      （「追加即更正」机制不变，旧行一字不改）。
    ★ acked 以快照为准（历史日不回改）：状态文件不保留关闭历史（本函数下方
      注释的既有边界）⇒ 关了又重开的件会让 store 现算的历史 acked **只少不多**，
      拿它改历史是把不完整的数据当真源。⇒ 历史日更正时 acked 沿用旧行值、
      且不参与「是否更正」的比对；**今天**仍按现算走（原语义，0353 判据钉着）。
    ★ 幂等：与已记一致 ⇒ **不重复追加**（否则每轮一行，文件涨成垃圾）。
    """
    items = S.load_items(root=root) if items is None else items
    base = date.fromisoformat(today or time.strftime("%Y-%m-%d"))
    window = [(base - timedelta(days=k)).isoformat() for k in range(BACKFILL_DAYS)]
    counts = M.day_counts(items, days=window)
    prev_all = L.load_days(root)
    for d in reversed(window):                      # 旧→新落笔，文件时间序可读
        c = counts.get(d) or {"date": d, "blocked": 0, "noticed": 0,
                              "breached": 0, "acked": 0}
        prev = prev_all.get(d) or {}
        # 没有可核对事件也无旧行 ⇒ 不造一条全 0 日账；已有快照的日子必须允许
        # 追加全零更正（例如事项后来被重开），不能把旧数字永久留在日账上。
        if not prev and not any(c[k] for k in M.LEDGER_KEYS):
            continue
        is_today = (d == window[0])
        # 今天：四格全比（原语义）；历史日：acked 以快照为准，只比三格。
        keys = M.LEDGER_KEYS if is_today else M.LEDGER_KEYS[:3]
        if prev and all(prev.get(k) == c[k] for k in keys):
            continue                                # 数字没变 ⇒ 不重复追加
        row = dict(c)
        if not is_today and prev:
            row["acked"] = int(prev.get("acked") or 0)
        L.append_day(row, root=root)
    return counts.get(window[0]) or {
        "date": window[0], "blocked": 0, "noticed": 0, "breached": 0, "acked": 0}


def _load_seen(root=None):
    try:
        with open(seen_path(root), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:                           # noqa: BLE001
        return {}


def _save_seen(d, root=None):
    p = seen_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, p)


def _load_hb_mark(root=None):
    try:
        with open(hb_mark_path(root), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:                           # noqa: BLE001
        return {}


def _save_hb_mark(d, root=None):
    p = hb_mark_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, p)


def _ensure_console(root=None):
    """确保Antinel 监理服务在跑（B1）。**转发到 `inbox_server` 的唯一实现**。

    ★ 为什么单独包一层：`inbox_server` 在本模块里是**惰性导入**（它 import
      本模块做账本采样，顶层互相 import 会成环）。这一层只做转发，不重算。
    """
    import inbox_server as SV
    return SV.ensure_console(root=root)


# ------------------------------------------------- 守护进程单例（0.48.5 B1）----
#: ★★ 为什么要它：一键入口（`antinel.cmd`）会"起一次守护进程"，用户多点两次
#:   就会有两份在跑（两份 tick：双份通知、双份记账、双份重拉Antinel 监理）。
#:   本仓对哨兵已有同款纪律（`run_sentinel`：已有活哨兵 ⇒ 安静退出，避免双跑双锁），
#:   守护进程照抄同一条 —— **机制在代码里，不靠启动脚本自觉**。
def daemon_pid_path(root=None):
    import inbox_config as _C
    return os.path.join(_C.console_dir(root), "daemon.pid")


def _pid_alive(pid):
    try:
        import audit_chain as _AC
        return bool(_AC.pid_alive(int(pid)))
    except Exception:                                   # noqa: BLE001
        return False


def daemon_alive(root=None):
    """(alive, pid|None)：中枢里登记的守护进程还在不在。读不到 ⇒ (False, None)。

    ★★ 0.60.0：判活**不能只看 pid**。本机实测 pid 回收极快 —— 同一个 pid 号
      （132432）在 62 秒内就被另一个进程复用。旧实现 `return _pid_alive(pid), pid`
      于是把「已经死掉的守护进程」读成活着 ⇒ 新守护进程判 `already-running`
      **秒退** ⇒ 监理服务永远起不来，而且每次重拉都要删一次 pid 文件（一个黑窗）。
      现在要求「pid 活着 **且** 出生时间与出生戳对得上」（`pid_matches_birth`）。
    ★ 没有出生戳（0.53.2 之前写的登记）⇒ 退回只按 pid 判，行为与旧版一致：
      那时没有更好的证据，不能凭空判死。
    """
    try:
        with open(daemon_pid_path(root), encoding="utf-8") as f:
            pid = int(f.read().strip())
    except Exception:                                   # noqa: BLE001
        return False, None
    if pid == os.getpid():
        return True, pid                                # 自己（调用方按需区分）
    if pid <= 0:
        return False, pid or None                       # 0 = 已退出哨兵值
    if not _pid_alive(pid):
        return False, pid
    when = _stamp_birth_epoch(root)
    if when is None:
        return True, pid
    try:
        import audit_chain as _AC
        return (_AC.pid_matches_birth(pid, when), pid)
    except Exception:                                   # noqa: BLE001
        return True, pid


def _stamp_birth_epoch(root=None):
    """出生戳里的「登记时刻」（epoch 秒）；没有/读坏 ⇒ `None`。

    优先用 `started_epoch`（0.60.0 起写入，精确）；老戳只有本地时间字符串，
    按本地时区反解 —— 只用于「是不是同一个进程」判断，容差 180s，够用。
    """
    d = read_daemon_stamp(root)
    if not d:
        return None
    v = d.get("started_epoch")
    if isinstance(v, (int, float)) and v > 0:
        return float(v)
    s = d.get("started_at")
    if not s:
        return None
    try:
        return time.mktime(time.strptime(str(s), "%Y-%m-%dT%H:%M:%S"))
    except Exception:                                   # noqa: BLE001
        return None


def write_daemon_pid(root=None, pid=None):
    """登记守护进程 pid（原子替换），并**顺带**落下出生版本戳（0.53.2 T3）。

    ★ 戳落在 `<console>/daemon.pid.meta.json` —— 与 pid 同目录同前缀，
      读的地方本来就在读 pid；**不新建第三份状态文件**（T3 任务书第 1 条）。
    ★ 戳写不成**不影响** pid 登记：pid 是判活的命脉，戳只是诊断证据。
    """
    p = daemon_pid_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(str(int(pid if pid is not None else os.getpid())))
    os.replace(tmp, p)
    try:
        write_daemon_stamp(root)
    except Exception:                                   # noqa: BLE001
        pass
    return True


def daemon_stamp_path(root=None):
    return daemon_pid_path(root) + ".meta.json"


def write_daemon_stamp(root=None, current=None):
    """守护进程**出生时**的版本戳（0.53.2 T3）。返回写下的 dict。"""
    import inbox_server as _SV
    cur = _SV.code_identity() if current is None else current
    rec = {"pid": int(os.getpid()),
           # ★ 0.60.0：同时写**精确 epoch**。判活要拿它跟「进程出生时间」对账，
           #   而 `started_at` 只有秒级且是本地时间字符串 —— pid 62 秒内就会被
           #   回收（本机实测），对账需要的是"同一个进程"这件事，不是同一个秒。
           "started_epoch": round(time.time(), 3),
           "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "code_version": cur.get("version"),
           "code_mtime": cur.get("mtime")}
    p = daemon_stamp_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rec, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, p)
    return rec


def read_daemon_stamp(root=None):
    """读守护进程的出生版本戳。没有 / 读坏 ⇒ `None`（**不编**）。"""
    try:
        with open(daemon_stamp_path(root), encoding="utf-8") as f:
            d = json.load(f)
    except Exception:                                   # noqa: BLE001
        return None
    return d if isinstance(d, dict) else None


def run_daemon(root=None, interval=2.0, max_ticks=None, supervise=True,
               ensure=None, supervise_every=15.0):
    """**常驻入口**（B1）：单例 + 监督。返回 `(ticks, why)`。

    ★ 单例：已有**别的**活守护进程 ⇒ 不跑（返回 `(0, "already-running")`），
      不报错、不抢锁 —— 与 `run_sentinel` 同一条纪律。
    ★ `supervise=True`（默认，CLI 入口用）：顺带监督Antinel 监理服务，被杀掉后按
      原端口/口令重拉（URL 不变）。
    ★ 退出时清掉自己的 pid 登记（不是自己写的不清 —— 别替别人擦桌子）。
    """
    alive, pid = daemon_alive(root)
    if alive and pid != os.getpid():
        return 0, "already-running"
    write_daemon_pid(root)
    try:
        n = Daemon(root=root).run(interval=interval, max_ticks=max_ticks,
                                  supervise=supervise, ensure=ensure,
                                  supervise_every=supervise_every)
        return n, "ok"
    finally:
        try:
            with open(daemon_pid_path(root), encoding="utf-8") as f:
                mine = int(f.read().strip()) == os.getpid()
        except Exception:                               # noqa: BLE001
            mine = False
        if mine:
            # ★ 0.60.0：退出时**不删** pid 文件，改写哨兵值 `0`（原子替换）。
            #   为什么：
            #   ① 删除会经宿主 sitecustomize 垫片走回收站 ⇒ 起 `node.exe`
            #      （控制台程序）⇒ 无控制台父进程下弹黑窗。守护进程被反复重拉时
            #      这一处就是"每分钟一个窗"的来源之一。
            #   ② 删完文件就"不在"了，和"从没登记过"同貌，查不出是**谁**退的；
            #      写 `0` 留下的是"登记过、已退出"这个事实（`_pid_alive(0)` 为假，
            #      所有读 pid 的地方行为不变）。
            try:
                tmp = daemon_pid_path(root) + ".tmp"
                with open(tmp, "w", encoding="utf-8", newline="\n") as f:
                    f.write("0")
                os.replace(tmp, daemon_pid_path(root))
            except Exception:                           # noqa: BLE001
                pass


def open_console_now(root=None, opener=None, console_url=None):
    """把「打开Antinel 监理」这件事**真的做掉**。返回 "app"/"browser"/"none"/"error: …"。

    ★★ 为什么是模块级函数而不是 `Daemon` 的方法（0.35.2）：
      托盘自己也要消费动作（见 `inbox_tray._consume_loop`），
      而**动作语义只许有一处实现** —— 抽成函数给两边共用，不是各写一份。
    """
    try:
        url = console_url
        if not url:
            import inbox_server as SV
            url, _started = SV.ensure_background(root=root)
        if opener is not None:
            _ret = opener(url)
            _okm, _whym = _hide_mark(root)
            if not _okm:
                print("[daemon] 漂浮哨标藏起没成：%s" % _whym)
            return _ret
        import inbox_server as SV2
        _ret = SV2.open_console(url)
        # ★ 0.50.0：Antinel 监理展开 ⇒ 漂浮哨标退役（点哨标/点托盘展开都会走到这）。
        # ★ 0.52.0：改成 **hide（藏起待命）**而非 retire（退役）—— 哨标进程
        #   常驻，下一次收缩才能毫秒级唤出；真退役只剩 `retire()`（去重/收孤儿）。
        #   藏起失败不改变"窗已开"的事实 ⇒ 打一行到屏上（不吞），不改返回值。
        _okm, _whym = _hide_mark(root)
        if not _okm:
            print("[daemon] 漂浮哨标藏起没成：%s" % _whym)
        return _ret
    except Exception as e:                      # noqa: BLE001
        return "error: %s" % e


def _hide_mark(root=None):
    """展开Antinel 监理后，把漂浮哨标**藏起待命**（0.52.0：原 retire 改 hide）。

    ★ 为什么不内联进 `open_console_now`：托盘消费者（`handle_actions`）
      与本函数都要用，抽出来只有一处实现。
    ★ 为什么是 hide 不是 retire：哨标进程常驻（`logo.hide` 只藏窗不杀进程），
      下一次收缩才能毫秒级唤出 —— 每次展开都真退役，是把"切换慢"亲手加回去。
    """
    try:
        import inbox_logo as IL
        rep = IL.hide(root=root, verbose=False)
        return rep.get("ok", False), rep.get("why", "")
    except Exception as e:                      # noqa: BLE001
        return False, "%s: %s" % (type(e).__name__, e)


def handle_actions(root=None, opener=None, console_url=None):
    """消费**托盘动作**（`open`；`quit` 由托盘自己处理）。返回本轮结果 dict。

    ★★ 为什么需要它（0.35.2 真缺陷）：托盘菜单写出的动作**只有守护进程会消费**
      ⇒ 只启动托盘（`antinel inbox tray`）时，点菜单**什么都不会发生**。
      现在托盘自己也会跑这个消费者 ⇒ 单起托盘也能用。
    ★ 消费是**原子**的（`inbox_tray.poll_actions` 用 `os.rename` 整文件改名）
      ⇒ 即使守护进程与托盘同时在跑，一个动作也只会被一边取走，**不会双开**。
    ★ 不删任何文件。
    ★ 0.35.3：`read_all` 分支**已取消**（创始人 2026-10-06「1 取消吧」）。
      已读改由「点开即已读」产生；托盘菜单里也不再提供该项。
    """
    res = {"actions": [], "open_console": False, "open_result": ""}
    for act in TR.poll_actions(root=root):
        res["actions"].append(act)
        if act == "open":
            res["open_console"] = True
            res["open_result"] = open_console_now(root=root, opener=opener,
                                                  console_url=console_url)
    return res


def _should_knock(it):
    """这一条记录该不该"敲门"（弹任何窗）—— **只问一把尺子**。

    ★★★ 为什么要有它（2026-10-27 实测，创始人报障「上古的冒泡又复发了」）：
      "该不该弹"本来有唯一真源 `host_shield.bubble_decision`，但它**只守着气泡通道**；
      走 toast 的那一支（本函数的 `NT.toast`）从来没问过它，只问 `should_touch(level)`。
      于是同一条 `host_shield_revived` 在气泡通道被明确压掉（规则③「能自己解决的不敲门」），
      在 toast 通道却照样响 —— **同一件事两把尺子**，本仓第一顽症的第 N 次复发。
      盘上读数：`notice_log.jsonl` 里 revived / tamper(recovered) 五天来每 30–45 分钟
      一对，全是走的 toast 通道。
    ★ 为什么只对 `_ALERT_KINDS` 里的类型问：那些才是"告警"；其余（心跳、用量、
      研发迭代）本来就有自己的定档，不归这把尺子管 —— 否则会顺手把别的东西也静音，
      那是**扩大改动面**。
    ★ 返回值第二项要进账（`out["quiet"]` ＋ 压制计数）：压了多少、为什么压必须可查，
      否则将来分不清"没弹是因为不该弹"还是"弹的机制坏了"。
    """
    try:
        import host_shield as HS
    except Exception:                        # noqa: BLE001
        return True, ""
    if it.kind not in getattr(HS, "_ALERT_KINDS", ()):
        return True, ""
    rec = {"recovered": bool(getattr(it.alert, "recovered", False)),
           "severity": getattr(it.alert, "severity", "") or ""}
    return HS.bubble_decision(it.kind, rec)


class Daemon:
    def __init__(self, root=None, backend=None, sound=None, overlay=None,
                 sender=None, poster=None, clock=None, cfg=None, today=None,
                 hb_poster=None, opener=None, console_url=None, bubbler=None):
        self.root = root
        self.backend = backend
        self.sound = sound
        self.overlay = overlay
        self.sender = sender
        self.poster = poster
        self.clock = clock or time.time
        self.cfg = cfg
        # `today` / `hb_poster` 只为可测性注入：判据要能改日期验跨零点、换掉发信器
        self.today = today or (lambda: time.strftime("%Y-%m-%d"))
        self.hb_poster = hb_poster
        # ★ 0.35.2：「打开Antinel 监理」的两个注入点 —— 只为可测性，
        #   判据要能在**不起任何进程/不绑端口**的前提下验这条链。
        #   `console_url` 给定 ⇒ 跳过起服务（测试）；`opener(url)` 换掉真开窗口。
        self.opener = opener
        self.console_url = console_url
        # ★ 0.49.0：紧急提醒发射点（可注入 —— 判据不起真浏览器、不响真声音）。
        self.bubbler = bubbler

    def _open_console(self):
        """★ 0.35.2：把托盘的 `open` 动作**真的**接上。

        旧版只写 `out["open_console"] = True`，而**全仓没有任何消费点** ⇒
        点托盘「Open console」/左键点图标什么都不会发生（创始人 2026-10-06 实测）。
        判据：登记了字段就必须有消费点 —— 本方法就是那个消费点。
        返回 "app"/"browser"/"none"（如实回报走了哪条路）。

        ★ 实现委托给模块级 `open_console_now()` —— 托盘侧复用同一份，**不二次实现**。
        """
        return open_console_now(root=self.root, opener=self.opener,
                                console_url=self.console_url)

    def _pop_bubble(self, it):
        """急事 → 紧急提醒（0.49.0）。发射点经 `bubbler` 注入，判据不碰真桌面。

        ★ 为什么单独一个方法而不是在 tick 里内联：判据要能**只换掉这一条
          发射点**来验路由（急事进紧急提醒、普通事进 toast），不必连坐整轮 tick。
        """
        import inbox_bubble as BB
        fn = self.bubbler or BB.pop
        return fn(title=it.title, body=(it.detail or it.title),
                  level=it.level, state=it.level, root=self.root,
                  kind=it.kind, cfg=self.cfg)

    # ---------------------------------------------------------------- #
    def _heartbeat_once(self, cfg, today):
        """匿名计数心跳。**默认关**；开着时每个本地日最多 `HB_MAX_TRIES` 次尝试。

        ★ 三条不许松：
          1. **关 ⇒ 一个请求都不发、一个字节都不落盘** —— 返回前不碰磁盘；
          2. 报文由 `heartbeat.send_once()` 构造并自检 —— 守护进程**不自己拼包**
             （J9「只发固定字段」因此仍然罩得住自动发送）；
          3. **失败当天不无限重试**：最多 3 次、相邻 ≥1 小时 —— 端点长期不通时
             一天最多 3 个请求，既不骚扰用户网络，也不刷满日志。

        ★ ★ 为什么"每天一次"是**网络纪律**而不是**数据正确性保障**：
          端点（Cloudflare Worker）已按 `(date, hash(install_id))` 去重，
          重复上报返回 `counted:false`，**不会**把计数抬高。
          ⇒ 客户端限流的目的是**少发请求**，不是"怕算重"；
          手动 `inbox heartbeat send` 补发因此也不会污染计数。

        ★ 如实边界：守护进程在跑才会有自动心跳；**它没跑就一天不发**。
          这是"常驻进程顺带报数"，不是"定时任务"（本机没有调度器，见部署实录）。
        """
        if not cfg.get("heartbeat"):
            return {"sent": False, "ok": False, "why": "未启用", "skipped": True}
        mark = _load_hb_mark(self.root)
        if mark.get("date") == today:
            if mark.get("ok"):
                return {"sent": False, "ok": True, "why": "今日已发（%s）" % mark.get("why"),
                        "skipped": True}
            if int(mark.get("tries") or 0) >= HB_MAX_TRIES:
                return {"sent": False, "ok": False, "skipped": True,
                        "why": "今日已失败 %s 次，当天不再重试" % mark.get("tries")}
            if self.clock() - float(mark.get("last_ts") or 0) < HB_RETRY_GAP:
                return {"sent": False, "ok": False, "skipped": True,
                        "why": "距上次尝试不足 %ds" % HB_RETRY_GAP}
        tries = (int(mark.get("tries") or 0) + 1) if mark.get("date") == today else 1
        # ★ 日期唯一真源是 Daemon.today（生产取本地日，判据可注入跨日）。
        #   不传 payload 时 heartbeat.build() 自己读墙钟，午夜/测试注入时会与
        #   限流标记日期不一致；仍由 heartbeat.build 构造，不在 daemon 二次拼包。
        payload = HB.build(root=self.root, day=today)
        ok, why = HB.send_once(root=self.root, poster=self.hb_poster,
                               payload=payload, cfg=cfg)
        _save_hb_mark({"date": today, "ok": bool(ok), "why": str(why),
                       "tries": tries, "last_ts": self.clock()}, root=self.root)
        return {"sent": True, "ok": bool(ok), "why": str(why), "tries": tries}

    # ---------------------------------------------------------------- #
    #: 复核结案的最小间隔（秒）。与心跳同量级：账不是新闻，慢一拍没关系。
    RECONCILE_EVERY = 600.0

    def _reconcile_once(self, items):
        """**恢复即结案**（B）的唯一生产调用点。返回本轮结果（判据要断言它）。

        ★ 为什么在这里：渲染是**纯投影**（灯不写盘），结案是**写账** ——
          写账只能发生在后台节拍里，不能发生在"有人在看页面"这条路径上。
        ★ 为什么先判欠账再探证据：没欠账时 `unrepaired_gap_items()` 只是**内存
          过滤**，零探测、零落盘；有欠账才去读姿态（`guard_posture` 要读心跳文件）。
        ★ 为什么全量取数：结案要覆盖**所有**没结案的记录，而 `tick` 手里那份是
          窗口内的。窗口外的老账只能靠每轮一次全量扫（首次约 5 s，之后走
          文件指纹缓存 ≈ 0.02 s）。
        """
        first = not getattr(self, "_recon_done", False)
        if not first and not S.unrepaired_gap_items(items):
            return {"skipped": True, "why": "没有没结案的缺口"}
        clock = self.clock()
        if not first and clock - float(getattr(self, "_recon_at", 0.0)) < self.RECONCILE_EVERY:
            return {"skipped": True, "why": "距上次复核不足 %d 秒" % int(self.RECONCILE_EVERY)}
        self._recon_at = clock
        self._recon_done = True
        try:
            import facts as _F
            import host_shield as _HS
            ev = _F.recovery_evidence(_HS.guard_posture().get("evidence"))
        except Exception as e:                      # noqa: BLE001
            return {"skipped": True, "why": "证据取不到：%s" % e}
        if not ev:
            # 没布防、自检没过、或证据读不到 ⇒ 一条都不结。**这不是异常。**
            return {"closed": [], "evidence": {}, "why": "没有可用的恢复证据"}
        try:
            rep = S.close_recovered(ev, items=S.load_items_all(root=self.root),
                                    root=self.root)
        except Exception as e:                      # noqa: BLE001
            return {"skipped": True, "why": "结案失败：%s" % e}
        rep["evidence"] = ev
        return rep

    def tick(self, notify=True):
        """跑一轮。返回本轮结果 dict（便于判据与调试）。"""
        cfg = self.cfg or CFG.load(self.root)
        items = S.load_items(root=self.root)
        today = self.today()
        out = {"items": len(items), "state": M.console_state(items),
               "unhandled": M.unhandled_count(items), "notified": [],
               "emphasis": [], "fallback": [], "actions": [], "errors": [],
               "bubble": [], "quiet": [],
               "heartbeat": None}

        # ①b 首检提醒（T1.3，设计 v1.11 §29.1）：装好 ≥24h 仍没体检过 ⇒
        #   链上补 1 条（只出一次，去重在 host_shield.exam_reminder_check）。
        #   放在②（通知）之前：本 tick 生成、下 tick 进 fresh ⇒ toast 知会。
        #   每 tick 都判 —— 判定是几个文件存在性检查＋链尾去重，比
        #   另养一个节流状态便宜，且节流状态本身就是第二份真源。
        try:
            import host_shield as _HS
            _ok_er, _why_er = _HS.exam_reminder_check()
            out["exam_reminder"] = {"fired": bool(_ok_er), "why": _why_er}
        except Exception as e:          # noqa: BLE001
            out["errors"].append("exam-reminder: %s" % e)
            out["exam_reminder"] = {"fired": False, "why": "异常：%s" % e}

        # ①c 恢复即结案（B，2026-10-23 创始人点名必做）。
        #   当前实测证明某类事已恢复 ⇒ 把这类此前**没结案的记录**一并结案。
        #   为什么必须有它（本机实测）：同一件事复发 124 次、每次自愈，却因为
        #   "自愈只降当次那一条"而在账上留成 124 条欠账 ⇒ 页面写「有 3 件没修」，
        #   而机器此刻半点毛病没有 —— 灯说的是假话，且这句假话永远消不掉。
        out["reconcile"] = self._reconcile_once(items)
        if (out["reconcile"] or {}).get("closed"):
            out["reconcile_affected"] = len(out["reconcile"]["closed"])

        # ①d 规则副本随包自愈（0.60.0）。
        #   ★ 为什么守护进程也要问一遍：钩子那条路只在「用户碰工具」时才走
        #     ⇒ 一个人装完新版本早上不开工，规则就一直是旧的。这里每 tick 判一次，
        #     幂等（正常情况只读两个 version 字段，不写盘、不留痕）。
        try:
            import host_shield as _HS_rules
            out["rules_autorefresh"] = _HS_rules.ensure_rules_current(self.root)
        except Exception as e:          # noqa: BLE001
            out["errors"].append("rules-autorefresh: %s" % e)

        # ② 新告警 → 通知 / 强调 / 兜底
        #   ★★ 0.49.0（创始人 2026-10-14）：**急事走紧急提醒、普通事走 toast**。
        #      `R0`（失守）与 `L2`（拦截进行中）＝「需要人工介入马上处理」
        #      ⇒ 紧急提醒窗（置顶、不自动消失、带「知道了」确认钮、与 Antinel 监理同界面）；
        #      其余级别仍走 `inbox_notify`（WinRT toast，落操作中心）。
        #      **同一个事件只走一条通道** —— 两条都响就是告警泛洪。
        seen = _load_seen(self.root)
        fresh = [it for it in items if it.id not in seen]
        fresh.sort(key=lambda it: -M.PRIORITY.get(it.level, 0))
        for it in fresh:
            if notify:
                try:
                    if it.level in BB.URGENT_LEVELS:
                        _rep = self._pop_bubble(it)
                        out["bubble"].append(
                            {"id": it.id, "ok": bool(_rep.get("ok")),
                             "why": _rep.get("why", "")})
                    else:
                        # ★★★ 0.59.0（连根去除旧外观）：这里过去调 `NT.toast`
                        #   —— 那是**系统原生通知**，外观由 Windows 决定，没有
                        #   Antinel 品牌的任何痕迹，正是创始人说的「上古的泡泡」。
                        # ★ 为什么不改成"这里也弹品牌化浮窗"：
                        #   L1 ＝「提醒」，不是「只有你能解决」。为一句话开一个窗口
                        #   比系统气泡更打扰。**敲门只留给 R0/L2**；L1 由
                        #   收件箱、托盘角标、台账三处承载，一像素不占屏幕。
                        # ★ 仍然要问那把唯一的尺子：`bubble_decision` 说"不该弹"
                        #   的（自愈、当事人已知情）连记账的理由都不一样，两者
                        #   混在一起会让"为什么没响"永远查不清。
                        _knock, _why_k = _should_knock(it)
                        if not _knock:
                            out["quiet"].append({"id": it.id, "why": _why_k})
                            try:
                                import host_shield as _HSq
                                _HSq.note_bubble_suppressed(it.kind, _why_k)
                            except Exception:        # noqa: BLE001
                                pass                 # 记账失败不影响"不敲门"
                        else:
                            out["quiet"].append(
                                {"id": it.id,
                                 "why": "L1 提醒不敲门：进收件箱与托盘角标"})
                            try:
                                import host_shield as _HSq2
                                _HSq2.note_bubble_suppressed(
                                    it.kind, "L1 提醒不敲门（只进收件箱与角标）")
                            except Exception:        # noqa: BLE001
                                pass
                except Exception as e:          # noqa: BLE001
                    out["errors"].append("notify: %s" % e)
            if M.PRIORITY.get(it.level, 0) >= M.PRIORITY["R0"]:
                try:
                    res = EM.emphasize(it.level, 1, it.title, cfg=cfg,
                                       sound=self.sound, overlay=self.overlay)
                    out["emphasis"].append(res)
                except Exception as e:          # noqa: BLE001
                    out["errors"].append("emphasis: %s" % e)
                try:
                    out["fallback"].append(
                        FB.dispatch(it.level, it.title, it.detail, cfg,
                                    sender=self.sender, poster=self.poster))
                except Exception as e:          # noqa: BLE001
                    out["errors"].append("fallback: %s" % e)
            seen[it.id] = 1
        if fresh:
            _save_seen(seen, self.root)

        # ③ 刷托盘
        try:
            TR.sync_from_items(items, root=self.root)
        except Exception as e:                  # noqa: BLE001
            out["errors"].append("tray: %s" % e)

        # ③b 徽标痕迹进链（0.53.2 T1/T2）：logo.ps1 写不了 Python 账本，
        #   它往 console_dir/logo_events.jsonl 追加的行由这里改名消费。
        #   ★ 放在③之后：同一拍里托盘刚写过新 tray.json，徽标的解析结果
        #     随之产生，下一拍之前被吃掉 —— 痕迹停留 ≤ 一个 tick 间隔。
        try:
            out["logo_events"] = len(TR.drain_logo_events(root=self.root))
        except Exception as e:                  # noqa: BLE001
            out["errors"].append("logo-events: %s" % e)

        # ④ 记账本（最近 14 天补记＋更正，唯一实现见模块级 `record_day`）
        try:
            record_day(items=items, today=today, root=self.root)
        except Exception as e:                  # noqa: BLE001
            out["errors"].append("ledger: %s" % e)

        # ⑤ 消费托盘动作
        try:
            res = handle_actions(root=self.root, opener=self.opener,
                                 console_url=self.console_url)
            out["actions"] = res["actions"]
            if res["open_console"]:
                out["open_console"] = True
                out["open_result"] = res["open_result"]   # ★ 0.35.2：真的去开
        except Exception as e:                  # noqa: BLE001
            out["errors"].append("tray-action: %s" % e)

        # ⑥ 匿名计数心跳（默认关 ⇒ 零请求零落盘；开着 ⇒ 每日最多 3 次尝试）
        try:
            out["heartbeat"] = self._heartbeat_once(cfg, today)
        except Exception as e:                  # noqa: BLE001
            out["errors"].append("heartbeat: %s" % e)
            out["heartbeat"] = {"sent": False, "ok": False, "skipped": True,
                                "why": "异常：%s" % e}

        return out

    # ---------------------------------------------------------------- #
    def run(self, interval=2.0, max_ticks=None, supervise=False,
            ensure=None, supervise_every=15.0):
        """常驻循环。`max_ticks` 只为测试用（None ＝ 一直跑）。

        ★★ 0.48.5（B1）：`supervise=True` ⇒ 顺带**监督Antinel 监理服务** ——
          每 `supervise_every` 秒判一次活（pid + 端口两条），死了就按
          **记录里的原端口/口令**重拉（URL 不变）。B1 验收＝杀掉服务进程后
          60 秒内自行恢复；默认 15 秒判一次，留足余量。
        ★ 监督放在 `run()` 而**不是** `tick()`：`tick()` 是"一轮业务"（通知/
          记账/刷托盘），判据大量直接调它，且它不该带起进程的副作用。
        ★ 默认 `supervise=False` ⇒ 既有调用方行为**一个字不变**（维四）。
        ★ `ensure` 可注入（判据用替身验"到点会去确保"，不去真起进程）。
        """
        n = 0
        next_sup = 0.0
        while max_ticks is None or n < max_ticks:
            try:
                self.tick()
            except Exception:                   # noqa: BLE001
                pass                            # 守护进程不许因为一轮出错就死
            if supervise:
                now = time.time()
                if now >= next_sup:
                    try:
                        (ensure or _ensure_console)(root=self.root)
                    except Exception:           # noqa: BLE001
                        pass                    # 重拉失败不许把守护进程打死
                    next_sup = now + float(supervise_every)
            n += 1
            if max_ticks is not None and n >= max_ticks:
                break
            time.sleep(interval)
        return n
