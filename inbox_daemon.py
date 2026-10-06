# -*- coding: utf-8 -*-
"""值守台 · 守护进程：把五层串起来跑。

一轮 `tick()` 干这些事（顺序固定）：

    ① 读链（真源）→ 组装收件箱
    ② 找**新**告警（`seen.json` 记已见 id）→ 通知层（Toast）+ 强调层（仅 R0）+ 兜底层
    ③ 刷**托盘**状态（五态 + 未处理数）
    ④ 记**当日账本**（追加写，同日取末行）
    ⑤ 消费**托盘动作**（open / read_all / quit）
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


class Daemon:
    def __init__(self, root=None, backend=None, sound=None, overlay=None,
                 sender=None, poster=None, clock=None, cfg=None, today=None,
                 hb_poster=None):
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
        ok, why = HB.send_once(root=self.root, poster=self.hb_poster, cfg=cfg)
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
               "heartbeat": None}

        # ② 新告警 → 通知 / 强调 / 兜底
        seen = _load_seen(self.root)
        fresh = [it for it in items if it.id not in seen]
        fresh.sort(key=lambda it: -M.PRIORITY.get(it.level, 0))
        for it in fresh:
            if notify:
                try:
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

        # ④ 记当日账本
        try:
            day_items = [it for it in items if str(it.ts)[:10] == today]
            L.append_day({
                "date": today,
                "blocked": len([i for i in day_items if i.level == "L2"]),
                "noticed": len([i for i in day_items if i.level == "L1"]),
                "breached": len([i for i in day_items if i.level == "R0"]),
                "acked": len([i for i in items if i.state in M.CLOSED_STATES]),
            }, root=self.root)
        except Exception as e:                  # noqa: BLE001
            out["errors"].append("ledger: %s" % e)

        # ⑤ 消费托盘动作
        try:
            for act in TR.poll_actions(root=self.root):
                out["actions"].append(act)
                if act == "read_all":
                    S.mark_all_read(root=self.root)
                elif act == "open":
                    out["open_console"] = True
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
    def run(self, interval=2.0, max_ticks=None):
        """常驻循环。`max_ticks` 只为测试用（None ＝ 一直跑）。"""
        n = 0
        while max_ticks is None or n < max_ticks:
            try:
                self.tick()
            except Exception:                   # noqa: BLE001
                pass                            # 守护进程不许因为一轮出错就死
            n += 1
            if max_ticks is not None and n >= max_ticks:
                break
            time.sleep(interval)
        return n
