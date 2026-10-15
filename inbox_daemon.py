# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""值守台 · 守护进程：把五层串起来跑。

一轮 `tick()` 干这些事（顺序固定）：

    ① 读链（真源）→ 组装收件箱
    ② 找**新**告警（`seen.json` 记已见 id）→ 通知层（Toast）+ 强调层（仅 R0）+ 兜底层
    ③ 刷**托盘**状态（五态 + 未处理数）
    ④ 记**当日账本**（追加写，同日取末行）
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


def record_day(items=None, today=None, root=None):
    """记当日账本 —— **唯一实现**（守护进程 `tick()` 与值守台都调它，不二次实现）。

    ★★ 为什么提出来（真缺陷，创始人 2026-10-07「账本这栏数据永远都是零」）：
      旧版这段逻辑**只**在 `Daemon.tick()` 里，而 `Daemon` 只能靠
      `antinel inbox daemon` 手动起 —— 全仓**没有任何自动启动点**
      ⇒ 账本文件从不落盘 ⇒ 页面四个数**恒为 0**（`~/.antinel/ledger/daily.jsonl`
      本机实测不存在）。值守台（`inbox_server.serve`）才是用户真正会打开的东西，
      所以让它**在打开期间**也记这一行。
    ★ 幂等：当日数字与已记的一致 ⇒ **不重复追加**（否则每轮一行，文件涨成垃圾）。
      「追加即更正」仍成立：数字一变就追加一行，`ledger.load_days` 取末行。
    """
    items = S.load_items(root=root) if items is None else items
    today = today or time.strftime("%Y-%m-%d")
    day_items = [it for it in items if str(it.ts)[:10] == today]
    # 「已处理」按**关闭日期**记，不把所有历史关闭项每天重复算一遍。
    # 这里记的是此刻仍处于已处理/已忽略状态、且本地关闭日期为 today 的事项数，
    # 不是完整的点击操作流水（状态文件只保存当前看法，不保留每次迁移历史）。
    acked_today = [i for i in items
                   if i.state in M.CLOSED_STATES and str(i.closed_at or "")[:10] == today]
    entry = {
        "date": today,
        "blocked": sum(1 for i in day_items if i.level == "L2"),
        "noticed": sum(1 for i in day_items if i.level == "L1"),
        "breached": sum(1 for i in day_items if i.level == "R0"),
        "acked": len(acked_today),
    }
    prev = L.load_days(root).get(today) or {}
    # 没有可核对事件时，不造一条全 0 日账；但若今天此前已有快照，必须允许
    # 追加全零更正（例如事项后来被重开），不能把旧数字永久留在日账上。
    has_count = any(entry[k] for k in ("blocked", "noticed", "breached", "acked"))
    if not has_count and not prev:
        return entry
    if prev and all(prev.get(k) == v for k, v in entry.items()):
        return entry                            # 数字没变 ⇒ 不重复追加
    L.append_day(entry, root=root)
    return entry


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
    """确保值守台服务在跑（B1）。**转发到 `inbox_server` 的唯一实现**。

    ★ 为什么单独包一层：`inbox_server` 在本模块里是**惰性导入**（它 import
      本模块做账本采样，顶层互相 import 会成环）。这一层只做转发，不重算。
    """
    import inbox_server as SV
    return SV.ensure_console(root=root)


# ------------------------------------------------- 守护进程单例（0.48.5 B1）----
#: ★★ 为什么要它：一键入口（`antinel.cmd`）会"起一次守护进程"，用户多点两次
#:   就会有两份在跑（两份 tick：双份通知、双份记账、双份重拉值守台）。
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
    """(alive, pid|None)：中枢里登记的守护进程还在不在。读不到 ⇒ (False, None)。"""
    try:
        with open(daemon_pid_path(root), encoding="utf-8") as f:
            pid = int(f.read().strip())
    except Exception:                                   # noqa: BLE001
        return False, None
    if pid == os.getpid():
        return True, pid                                # 自己（调用方按需区分）
    return _pid_alive(pid), pid


def write_daemon_pid(root=None, pid=None):
    """登记守护进程 pid（原子替换）。"""
    p = daemon_pid_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(str(int(pid if pid is not None else os.getpid())))
    os.replace(tmp, p)
    return True


def run_daemon(root=None, interval=2.0, max_ticks=None, supervise=True,
               ensure=None, supervise_every=15.0):
    """**常驻入口**（B1）：单例 + 监督。返回 `(ticks, why)`。

    ★ 单例：已有**别的**活守护进程 ⇒ 不跑（返回 `(0, "already-running")`），
      不报错、不抢锁 —— 与 `run_sentinel` 同一条纪律。
    ★ `supervise=True`（默认，CLI 入口用）：顺带监督值守台服务，被杀掉后按
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
                if int(f.read().strip()) == os.getpid():
                    os.remove(daemon_pid_path(root))
        except Exception:                               # noqa: BLE001
            pass


def open_console_now(root=None, opener=None, console_url=None):
    """把「打开值守台」这件事**真的做掉**。返回 "app"/"browser"/"none"/"error: …"。

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
            _okm, _whym = _retire_mark(root)
            if not _okm:
                print("[daemon] 漂浮哨标退役没成：%s" % _whym)
            return _ret
        import inbox_server as SV2
        _ret = SV2.open_console(url)
        # ★ 0.50.0：值守台展开 ⇒ 漂浮哨标退役（点哨标/点托盘展开都会走到这）。
        #   退役的唯一实现是 `inbox_logo.retire()`，这里只调用 + 如实转述。
        #   退役失败不改变"窗已开"的事实 ⇒ 打一行到屏上（不吞），不改返回值。
        _okm, _whym = _retire_mark(root)
        if not _okm:
            print("[daemon] 漂浮哨标退役没成：%s" % _whym)
        return _ret
    except Exception as e:                      # noqa: BLE001
        return "error: %s" % e


def _retire_mark(root=None):
    """展开值守台后，让漂浮哨标退役。**失败只如实报，不吞、不谎报**。

    ★ 为什么不内联进 `open_console_now`：托盘消费者（`handle_actions`）
      与本函数都要用，抽出来只有一处实现。
    """
    try:
        import inbox_logo as IL
        rep = IL.retire(root=root, verbose=False)
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
        # ★ 0.35.2：「打开值守台」的两个注入点 —— 只为可测性，
        #   判据要能在**不起任何进程/不绑端口**的前提下验这条链。
        #   `console_url` 给定 ⇒ 跳过起服务（测试）；`opener(url)` 换掉真开窗口。
        self.opener = opener
        self.console_url = console_url
        # ★ 0.49.0：冒泡发射点（可注入 —— 判据不起真浏览器、不响真声音）。
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
        """急事 → 冒泡（0.49.0）。发射点经 `bubbler` 注入，判据不碰真桌面。

        ★ 为什么单独一个方法而不是在 tick 里内联：判据要能**只换掉这一条
          发射点**来验路由（急事进冒泡、普通事进 toast），不必连坐整轮 tick。
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
    def tick(self, notify=True):
        """跑一轮。返回本轮结果 dict（便于判据与调试）。"""
        cfg = self.cfg or CFG.load(self.root)
        items = S.load_items(root=self.root)
        today = self.today()
        out = {"items": len(items), "state": M.console_state(items),
               "unhandled": M.unhandled_count(items), "notified": [],
               "emphasis": [], "fallback": [], "actions": [], "errors": [],
               "bubble": [],
               "heartbeat": None}

        # ② 新告警 → 通知 / 强调 / 兜底
        #   ★★ 0.49.0（创始人 2026-10-14）：**急事走冒泡、普通事走 toast**。
        #      `R0`（失守）与 `L2`（拦截进行中）＝「需要人工介入马上处理」
        #      ⇒ 冒泡窗（置顶、不自动消失、带「知道了」确认钮、与值守台同界面）；
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
                        ok, why = NT.toast(it.level, it.title, it.detail or it.title,
                                           root=self.root, backend=self.backend, cfg=cfg,
                                           now=self.clock(), kind=it.kind)
                        out["notified"].append({"id": it.id, "ok": ok, "why": why})
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

        # ④ 记当日账本（唯一实现见模块级 `record_day`）
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

        ★★ 0.48.5（B1）：`supervise=True` ⇒ 顺带**监督值守台服务** ——
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
