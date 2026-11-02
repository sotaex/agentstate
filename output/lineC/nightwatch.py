#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""C 线出口：让巡检**自己到点跑** —— 主动性第三要件（系统自己发起）的唯一实现。

★ 为什么这一件必须单独存在（2026-11-03 盘点结论）
  前两个要件 C 线早就成立：watchman 查得出来、clue_ledger 压得住节奏、
  onepager 说得清。但「系统自己发起」**不成立** —— 出口只有 `print()` 到 stdout，
  而这个人开没开终端、在不在电脑前，决定了那份报告存不存在。
  **一个只在被打开时才有输出的东西，是工具，不是主动性。**

★ 为什么不做进 `inbox_daemon.tick()`
  `output/lineC` 不随包（`psl/manifest.json` 里 `output/` 条目 = 0）。
  挂进产品守护进程有两种结局，**两种都不许选**：
    · 直接 import 失败 ⇒ 装到用户机器上天天报同一个错；
    · try/except 静默跳过 ⇒ **主动性永久缺失，而界面上和「跑过了，没事」一模一样**。
  静默降级最贵的地方就在这里：缺失与正常同貌。
  所以出口必须长在提供主动性的一方：**谁提供，谁负责启动它**。

★ 它不是第二个 watchman
  本文件**不实现任何检测、不实现任何推送**。
  检测在 `watchman.py`；推送在 `watchman.push_clue()`（走产品侧 `inbox_bubble.pop`）。
  本文件只回答一个问题：**现在该不该让它跑**。
  一旦在这里重写「什么算线索」，就又长出第二把尺子 —— 那正是本项目的第一顽症。

用法
    python output/lineC/nightwatch.py --once            人让它跑一次（幂等）
    python output/lineC/nightwatch.py --once --force    无视「今天已跑过」
    python output/lineC/nightwatch.py --loop            常驻：每天到 --at 自己跑一次
    python output/lineC/nightwatch.py --status          只读：上次什么时候跑的、结果
    python output/lineC/nightwatch.py --selfcheck       七臂自检（不读账本、不弹窗）
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
WATCHMAN = os.path.join(_HERE, "watchman.py")
# ★ 默认账本用**仓根绝对路径**，不用相对 cwd。
#   2026-11-03 实测踩过：从 output/lineC 跑与从仓根跑读到的是两个不同的目录，
#   而两者的输出都是「查了，没有」—— 静默降级只表现为「多报/少报」。
DEFAULT_ROOT = os.path.join(_REPO, ".psl", "audit")

DEFAULT_AT = "09:00"          # 与设计方案书一致
DEFAULT_INTERVAL = 600        # 常驻时多久判一次（秒）
LOCK_STALE_SEC = 2 * 3600     # 锁超过 2 小时视为陈旧（崩溃留下的）
RUN_TIMEOUT = 1800            # 单次巡检上限（秒）

RESULT_OK = "ok"
RESULT_FAILED = "failed"
RESULT_UNDECIDABLE = "undecidable"


# --------------------------------------------------------------------------- 路径
def hub_linec_dir() -> str:
    """状态目录：**复用产品侧唯一真源**，不自造第二个中枢。

    产品侧的家目录只有一处定义（`host_shield._hub_dir()`：`ANTINEL_HUB_DIR` 或
    `~/.antinel`）。若这里另写一遍同样的表达式，就成了两份实现 ——
    沙箱判据设了 `ANTINEL_HUB_DIR` 而这里不认，会出现「两个中枢」，
    而且两边各写一半状态，谁都不完整。

    ★ 兜底只在产品模块导入失败时生效，且兜底表达式与被复用的那一处**逐字相同**。
      它不是「另一份定义」，是同一句话的降级副本；导入成功时永不执行。
    """
    base = None
    try:
        if _REPO not in sys.path:
            sys.path.insert(0, _REPO)
        import host_shield as _HS  # noqa: PLC0415  产品侧，延迟导入
        base = _HS._hub_dir()
    except Exception:                                   # noqa: BLE001
        base = None
    if not base:
        base = (os.environ.get("ANTINEL_HUB_DIR")
                or os.path.join(os.path.expanduser("~"), ".antinel"))
    return os.path.join(base, "lineC")


def default_state_path() -> str:
    return os.path.join(hub_linec_dir(), "nightwatch_state.json")


def lock_path() -> str:
    """单实例锁**必须放系统 TEMP**：D 盘全域禁 unlink，放在那儿删不掉，
    下一次启动会被自己的残锁挡住 —— 而报出来的是「另一个实例在跑」，
    与真并发同貌。"""
    return os.path.join(tempfile.gettempdir(), "antinel_nightwatch.lock")


# --------------------------------------------------------------------------- 状态
def load_state(path: str):
    """返回 `(state, why)`。

    ★ 三种「读不到」必须分开，因为处理方式完全不同：
        · 文件不存在      ⇒ 第一次跑，**该跑**；
        · 文件存在但坏了  ⇒ **不可判**：既不许当成「没跑过」（会重复打扰），
                            也不许当成「跑过了」（会永久沉默）；
        · 顶层不是 dict   ⇒ 同上。
      「0 与不可判同貌」在状态文件上的形态就是「没跑过」与「读不出来」都说成
      「今天还没跑」。
    """
    if not os.path.isfile(path):
        return {}, "state-absent"
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception as exc:                            # noqa: BLE001
        return None, "state-unreadable: %s: %s" % (type(exc).__name__, exc)
    if not isinstance(d, dict):
        return None, "state-not-a-dict: %r" % (type(d).__name__,)
    return d, ""


def save_state(path: str, state: dict) -> None:
    """先写同目录临时文件再替换：半写的状态文件比没有状态文件更坏
    —— 它会以「今天跑过了」的样子出现，而实际上什么都没跑。"""
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def should_run(state, *, today: str, now: datetime, at: str,
               force: bool, gate_by_clock: bool):
    """该不该跑。返回 `(bool, why)` —— why 一定会被写进状态，**跳过也要留痕**。

    `gate_by_clock` 只有常驻模式才为 True：人显式 `--once` 时不该被「还没到 9 点」挡住，
    否则手工验证永远跑不了。**「人叫它跑」与「它自己到点跑」是两件事**，
    合并成一个判断会让主动性永远验证不了。
    """
    if force:
        return True, "forced（--force）"
    if state is None:
        return False, "不可判：状态文件读不出来，本次不跑也不覆盖它"
    if state.get("last_run_date") == today:
        return False, "already-ran-today: %s（结果 %s）" % (
            state.get("last_run_at") or "?", state.get("last_result") or "?")
    if gate_by_clock:
        hh, mm = _parse_at(at)
        if (now.hour, now.minute) < (hh, mm):
            return False, "before-at %s（现在 %s）" % (at, now.strftime("%H:%M"))
    return True, "first-run-today"


def _parse_at(s: str):
    try:
        hh, mm = str(s).split(":")
        hh, mm = int(hh), int(mm)
    except Exception:                                   # noqa: BLE001
        raise SystemExit("[停] --at 要 HH:MM：%r" % (s,))
    if not (0 <= hh <= 23 and 0 <= mm <= 59):
        raise SystemExit("[停] --at 越界：%r" % (s,))
    return hh, mm


# --------------------------------------------------------------------------- 锁
def acquire_lock(path: str = None):
    """`O_CREAT|O_EXCL` 单实例锁。返回 `(fd, why)`；拿不到时 fd 为 None。

    ★ 陈旧锁必须能自愈：进程被 kill 掉不会删锁，死锁会让巡检**永久停摆**，
      而它停摆的样子是「今天没有新线索」—— 与真的没有线索同貌。
      判陈旧用文件 mtime，不用 pid 探活（Windows 上 `os.kill(pid, 0)` 不可靠）。
    """
    path = path or lock_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    for _ in range(2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                age = time.time() - os.path.getmtime(path)
            except OSError:
                age = 0
            if age > LOCK_STALE_SEC:
                try:
                    os.unlink(path)
                except OSError:
                    return None, "陈旧锁删不掉：%s" % path
                continue
            return None, "另一个 nightwatch 正在跑（锁 %s，%.0f 秒前）" % (path, age)
        try:
            os.write(fd, ("%d\n" % os.getpid()).encode("ascii"))
        except OSError:
            pass
        return fd, ""
    return None, "拿不到锁：%s" % path


def release_lock(fd, path: str = None) -> None:
    path = path or lock_path()
    try:
        if fd is not None:
            os.close(fd)
    except OSError:
        pass
    try:
        os.unlink(path)
    except OSError:
        pass


# --------------------------------------------------------------------------- 跑
def run_watchman(*, root: str, watchman_py: str = WATCHMAN,
                 push_log: str = None, runner=None) -> dict:
    """跑一次巡检，**只调用、不解释**。返回 dict，永远不抛。

    ★ 为什么要 `--push-log`：`--json` 是取证通道，契约上**无副作用**，
      所以它不能告诉我们「刚才弹了没有」；而文本出口的推送结果只印在屏幕上。
      让 watchman 把推送结果另写一行 jsonl，调度器才能留下「说了什么」的证据，
      而不是解析中文文案（文案会改，解析会静默失效）。
    ★ 为什么要 `-E`：子进程不吃 `PYTHONPATH`。父进程的路径污染不该传给孩子，
      否则「父进程跑得通、子进程跑不通」会变成环境问题而不是代码问题。
    """
    rep = {"ok": False, "code": None, "seconds": 0.0,
           "tail": "", "push": [], "cmd": []}
    if runner is not None:
        return runner()
    cmd = [sys.executable, "-E", "-X", "utf8", watchman_py,
           "--root", root, "--notify"]
    if push_log:
        cmd += ["--push-log", push_log]
    rep["cmd"] = cmd
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           timeout=RUN_TIMEOUT)
        rep["code"] = p.returncode
        rep["ok"] = p.returncode == 0
        both = (p.stdout or "") + (p.stderr or "")
        rep["tail"] = "\n".join(both.strip().splitlines()[-6:])[:1200]
    except subprocess.TimeoutExpired:
        rep["code"] = "timeout"
        rep["tail"] = "超时 %d 秒，已放弃本次（账本可能太大）" % RUN_TIMEOUT
    except Exception as exc:                            # noqa: BLE001
        rep["code"] = "exception"
        rep["tail"] = "%s: %s" % (type(exc).__name__, exc)
    rep["seconds"] = round(time.time() - t0, 1)

    if push_log and os.path.isfile(push_log):
        try:
            with open(push_log, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rep["push"].append(json.loads(line))
                    except Exception:                   # noqa: BLE001
                        rep["push"].append({"unparsed": line[:200]})
        except OSError as exc:
            rep["tail"] += "\n[推送留痕读不到] %s" % exc
    return rep


def summarize_push(push) -> dict:
    """把推送留痕压成一句能进状态的话。

    ★ 三种「没弹」必须分开：
        · `none`    —— 跑了，但没有值得弹的（**结论**）
        · `failed`  —— 该弹，弹不出去，有原因（**故障**）
        · `unknown` —— 没有任何留痕（**不可判**：可能是没跑成，也可能是通道没写）
      把第三种说成第一种，就是「系统自己知道有事，却什么都没说」的最隐蔽形态。
    """
    if not push:
        return {"state": "unknown", "why": "没有任何推送留痕（不是「没话可说」）"}
    sent = [x for x in push if x.get("sent")]
    if not sent:
        return {"state": "none", "why": (push[-1].get("why") or "")[:200]}
    ok = [x for x in sent if x.get("ok")]
    if ok:
        return {"state": "ok", "why": (ok[-1].get("subject") or "")[:200],
                "kind": ok[-1].get("kind")}
    return {"state": "failed", "why": (sent[-1].get("why") or "未知原因")[:200]}


def once(*, root: str, state_path: str, at: str = DEFAULT_AT, force: bool = False,
         gate_by_clock: bool = False, now: datetime = None, runner=None,
         watchman_py: str = WATCHMAN, lock: bool = True) -> dict:
    """走一遍「判 → 跑 → 记」。返回 dict（供自检与 `--loop` 共用）。

    ★ 顺序是不变量：**先判、再跑、最后才写状态**。
      先写状态再跑，一旦跑崩，状态上写着「今天跑过了」而报告根本不存在 ——
      这就是永久沉默。
    """
    now = now or datetime.now()
    today = now.strftime("%Y-%m-%d")
    out = {"today": today, "ran": False, "why": "", "result": None,
           "push": None, "state_path": state_path}

    fd = None
    if lock:
        fd, why_lock = acquire_lock()
        if fd is None:
            out["why"] = why_lock
            out["result"] = RESULT_UNDECIDABLE
            return out
    try:
        state, why_state = load_state(state_path)
        do, why = should_run(state, today=today, now=now, at=at,
                             force=force, gate_by_clock=gate_by_clock)
        out["why"] = why
        if not do:
            out["result"] = RESULT_UNDECIDABLE if state is None else "skipped"
            # 跳过也要留痕，但**不许覆盖**已有状态（尤其是不许把坏状态写好）
            if state is not None and state.get("last_run_date") != today:
                state["last_skip"] = {"at": now.strftime("%Y-%m-%d %H:%M:%S"),
                                      "why": why}
                try:
                    save_state(state_path, state)
                except OSError:
                    pass
            return out

        push_log = state_path + ".push.jsonl"
        try:
            if os.path.isfile(push_log):
                os.unlink(push_log)
        except OSError:
            pass

        rep = run_watchman(root=root, watchman_py=watchman_py,
                           push_log=push_log, runner=runner)
        out["ran"] = True
        out["seconds"] = rep.get("seconds")
        out["push"] = summarize_push(rep.get("push") or [])
        if rep.get("ok"):
            out["result"] = RESULT_OK
        elif rep.get("code") == "timeout":
            out["result"] = RESULT_FAILED
        else:
            out["result"] = RESULT_FAILED

        new_state = {
            "last_run_date": today,
            "last_run_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            "last_result": out["result"],
            "last_code": rep.get("code"),
            "last_seconds": rep.get("seconds"),
            "last_tail": (rep.get("tail") or "")[:1200],
            "last_push": out["push"],
            "last_state_note": why_state,
            "root": root,
            "watchman": watchman_py,
            "version": 1,
        }
        try:
            save_state(state_path, new_state)
        except OSError as exc:
            out["why"] += "｜状态写不进去：%s" % exc
            out["state_write_failed"] = True
        return out
    finally:
        if lock:
            release_lock(fd)


# --------------------------------------------------------------------------- 自检
def _selfcheck() -> int:
    """七臂。**全部注入**，不读真账本、不起真窗口、不碰真状态。"""
    tmp = tempfile.mkdtemp(prefix="nightwatch_sc_")
    ok = True

    def ck(cond, name, detail=""):
        nonlocal ok
        print("  [%s] %-34s %s" % ("PASS" if cond else "FAIL", name, detail))
        if not cond:
            ok = False

    def sp(n):
        return os.path.join(tmp, "state_%s.json" % n)

    def mk_runner(push, code=0, tail="ok"):
        def _r():
            return {"ok": code == 0, "code": code, "seconds": 1.0,
                    "tail": tail, "push": push, "cmd": ["<injected>"]}
        return _r

    now = datetime(2026, 11, 3, 10, 0, 0)
    try:
        # ① 状态不存在 ⇒ 该跑（第一次）
        r = once(root=tmp, state_path=sp("a"), now=now,
                 runner=mk_runner([{"sent": False, "why": "没有值得弹的"}]),
                 lock=False)
        ck(r["ran"] and r["result"] == RESULT_OK, "① 没有状态 ⇒ 跑",
           "ran=%s result=%s" % (r["ran"], r["result"]))

        # ② 今天已跑过 ⇒ 不跑，且说得清
        r = once(root=tmp, state_path=sp("a"), now=now,
                 runner=mk_runner([{"sent": False, "why": "x"}]), lock=False)
        ck((not r["ran"]) and "already-ran-today" in r["why"], "② 同日重跑 ⇒ 跳过",
           r["why"])

        # ③ --force 必须能翻面（否则 ② 可能是「永远不跑」的另一种说法）
        r = once(root=tmp, state_path=sp("a"), now=now, force=True,
                 runner=mk_runner([{"sent": False, "why": "x"}]), lock=False)
        ck(r["ran"], "③ --force 翻面（反向腿）", "ran=%s" % r["ran"])

        # ④ 状态文件坏了 ⇒ 不可判，不跑，**且不许覆盖它**
        bad = sp("bad")
        with_open = open(bad, "w", encoding="utf-8")
        try:
            with_open.write("{ 这不是 json")
        finally:
            with_open.close()
        before = open(bad, encoding="utf-8").read()
        r = once(root=tmp, state_path=bad, now=now,
                 runner=mk_runner([{"sent": False}]), lock=False)
        after = open(bad, encoding="utf-8").read()
        ck((not r["ran"]) and r["result"] == RESULT_UNDECIDABLE and before == after,
           "④ 状态坏 ⇒ 不可判且不覆盖", "ran=%s result=%s 未变=%s"
           % (r["ran"], r["result"], before == after))

        # ⑤ 成功推送 ⇒ 状态里留下「说了什么」
        r = once(root=tmp, state_path=sp("c"), now=now,
                 runner=mk_runner([{"sent": True, "ok": True,
                                    "kind": "c_line_pair",
                                    "subject": "两条规则成对出现"}]),
                 lock=False)
        st = json.load(open(sp("c"), encoding="utf-8"))
        ck(st["last_push"]["state"] == "ok"
           and "成对" in st["last_push"]["why"], "⑤ 推成功 ⇒ 留痕",
           str(st["last_push"])[:80])

        # ⑥ 巡检失败（退出码非 0）⇒ 必须记 failed，**不许**记成「没线索」
        r = once(root=tmp, state_path=sp("d"), now=now,
                 runner=mk_runner([], code=3, tail="读不完"), lock=False)
        st = json.load(open(sp("d"), encoding="utf-8"))
        ck(st["last_result"] == RESULT_FAILED and st["last_push"]["state"] == "unknown",
           "⑥ 巡检失败 ≠ 没线索",
           "result=%s push=%s" % (st["last_result"], st["last_push"]["state"]))

        # ⑦ 推送失败 ⇒ 必须转述原因，不许静默
        r = once(root=tmp, state_path=sp("e"), now=now,
                 runner=mk_runner([{"sent": True, "ok": False,
                                    "why": "桌面通道不可用"}]), lock=False)
        st = json.load(open(sp("e"), encoding="utf-8"))
        ck(st["last_push"]["state"] == "failed"
           and "桌面通道" in st["last_push"]["why"], "⑦ 推失败 ⇒ 转述原因",
           str(st["last_push"])[:80])

        # ⑧ 时钟闸门：常驻模式下「没到点」不许跑；人显式 --once 时不受它挡
        r = once(root=tmp, state_path=sp("f"), now=datetime(2026, 11, 3, 7, 0, 0),
                 at="09:00", gate_by_clock=True,
                 runner=mk_runner([{"sent": False}]), lock=False)
        r2 = once(root=tmp, state_path=sp("g"), now=datetime(2026, 11, 3, 7, 0, 0),
                  at="09:00", gate_by_clock=False,
                  runner=mk_runner([{"sent": False}]), lock=False)
        ck((not r["ran"]) and r2["ran"], "⑧ 到点闸门只挡常驻，不挡人",
           "loop=%s once=%s" % (r["ran"], r2["ran"]))

        # ⑨ 陈旧锁必须能自愈（否则一次 kill 就永久停摆）
        lp = os.path.join(tmp, "lock")
        with open(lp, "w", encoding="utf-8") as fh:
            fh.write("999999\n")
        old = time.time() - LOCK_STALE_SEC - 60
        os.utime(lp, (old, old))
        fd, why = acquire_lock(lp)
        ck(fd is not None, "⑨ 陈旧锁自愈", why or "拿到锁")
        release_lock(fd, lp)
    finally:
        for n in os.listdir(tmp):
            try:
                os.unlink(os.path.join(tmp, n))
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass

    print()
    print("自检 %s（九臂）" % ("全过" if ok else "有失败"))
    return 0 if ok else 1


# --------------------------------------------------------------------------- 状态展示
def show_status(path: str) -> int:
    state, why = load_state(path)
    print("状态文件：%s" % path)
    print("读取说明：%s" % (why or "正常"))
    if state is None:
        print("⇒ 不可判（文件坏或格式不对）。**不许**据此认为「今天还没跑」。")
        return 1
    if not state:
        print("⇒ 从未跑过（这是第一次）")
        return 0
    print("上次跑：%s（%s）" % (state.get("last_run_at") or "?",
                                state.get("last_result") or "?"))
    print("结果码：%s ｜ 耗时 %ss" % (state.get("last_code"),
                                     state.get("last_seconds")))
    print("推送  ：%s" % json.dumps(state.get("last_push") or {}, ensure_ascii=False))
    if state.get("last_skip"):
        print("上次跳过：%s" % json.dumps(state["last_skip"], ensure_ascii=False))
    if state.get("last_tail"):
        print("末尾输出：")
        for line in str(state["last_tail"]).splitlines():
            print("  " + line)
    return 0


# --------------------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="C 线出口：让巡检自己到点跑（主动性第三要件）")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--once", action="store_true", help="人让它跑一次（幂等）")
    g.add_argument("--loop", action="store_true", help="常驻：每天到 --at 自己跑")
    g.add_argument("--status", action="store_true", help="只读状态")
    g.add_argument("--selfcheck", action="store_true", help="九臂自检")
    ap.add_argument("--root", default=DEFAULT_ROOT, help="账本目录（默认仓根）")
    ap.add_argument("--at", default=DEFAULT_AT, help="常驻模式每天几点跑（默认 09:00）")
    ap.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                    help="常驻模式多久判一次（秒）")
    ap.add_argument("--max-rounds", type=int, default=0,
                    help="常驻最多判几轮就退（判据用；0＝不限）")
    ap.add_argument("--state", default=None, help="状态文件（默认 ~/.antinel/lineC/）")
    ap.add_argument("--force", action="store_true", help="无视「今天已跑过」")
    ap.add_argument("--watchman", default=WATCHMAN, help="watchman.py 路径")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:                                   # noqa: BLE001
        pass

    if args.selfcheck:
        return _selfcheck()

    state_path = args.state or default_state_path()

    if args.status:
        return show_status(state_path)

    if not os.path.isdir(args.root):
        print("[停] 账本目录不存在：%s" % args.root, file=sys.stderr)
        return 2
    if not os.path.isfile(args.watchman):
        print("[停] 找不到 watchman：%s" % args.watchman, file=sys.stderr)
        return 2

    if args.once:
        r = once(root=args.root, state_path=state_path, at=args.at,
                 force=args.force, gate_by_clock=False,
                 watchman_py=args.watchman)
        if not r["ran"]:
            print("[没跑] %s" % r["why"])
            return 0 if r["result"] == "skipped" else 1
        print("[跑了] %s（%.1fs）结果 %s" % (r["today"], r.get("seconds") or 0,
                                            r["result"]))
        print("[推送] %s" % json.dumps(r["push"], ensure_ascii=False))
        return 0 if r["result"] == RESULT_OK else 1

    # ---- 常驻 ----
    print("[常驻] 每天 %s 跑一次；判间隔 %ss；账本 %s" % (args.at, args.interval,
                                                          args.root))
    print("[常驻] 状态 %s" % state_path)
    rounds = 0
    try:
        while True:
            rounds += 1
            r = once(root=args.root, state_path=state_path, at=args.at,
                     gate_by_clock=True, watchman_py=args.watchman)
            stamp = datetime.now().strftime("%H:%M:%S")
            if r["ran"]:
                print("[%s] 跑了：%s ｜推送 %s" % (stamp, r["result"],
                                                  (r["push"] or {}).get("state")))
            else:
                print("[%s] 没跑：%s" % (stamp, r["why"]))
            if args.max_rounds and rounds >= args.max_rounds:
                print("[常驻] 到 --max-rounds=%d，退出" % args.max_rounds)
                return 0
            time.sleep(max(10, args.interval))
    except KeyboardInterrupt:
        print("\n[常驻] 收到中断，退出")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
