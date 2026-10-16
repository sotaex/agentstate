# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""值守台 · 漂浮哨标（最小态）：**只在，不碍事**。

★ 0.50.0（创始人 2026-10-14：「值守台应该有一个能'漂浮'的最小态……
  哨兵很多时候不要碍事，只要在，就行了」）：
  值守台大窗占屏幕，用户不愿意让它一直开着；但哨兵的**在岗状态**必须随时
  可读（灯五态）。折中＝**一枚漂浮小窗**：跟输入法浮动窗口一样贴在屏幕
  一角，**只画一个 LOGO**，点击它 ⇒ 写 `open` 动作、自己退场，值守台展开。

★ 为什么又是"纯文本文件协议"（与托盘同一族）：
      Python 写 `logo.quit`   ──▶  logo.ps1 每 40ms 轮询，见到就退
      logo.ps1 写 `tray_action.txt` ──▶ 守护进程/托盘消费者取走（唯一实现）
  ⇒ 可单测：不起真进程也能验全链（`launcher`/`finder`/`killer` 注入）。

★ **三态只有一本账**，不许三处各写一遍：
      collapse（收缩）：起哨标 ＋ 关本面板窗
      expand （展开）：哨标自己写 open 自退；服务端 open 路径顺手 retire
      retire （退役）：`logo.quit` 标志 ⇒ 哨标自己退；超时才 WM_CLOSE 兜底
  `retire()` 是**退役的唯一实现**：`collapse` 前先退役（不叠两枚），
  `open_console_settled` / `Daemon.open_console_now` 展开后也调它
  （用户从托盘/CLI 展开时，屏幕上那枚哨标不该继续漂）。

★ 如实原则（本仓铁律，与紧急提醒/浮层同一标准）：
    · 哨标没起来 ⇒ `ok=False` 且 `why` 说清（**不关面板窗**，
      用户不至于"点一下收缩，值守台没了"）；
    · 标志退役超时 ⇒ `why` 写明"兜底 WM_CLOSE 关的"，不假装是标志生效；
    · 找不到 PowerShell/脚本 ⇒ 明确降级，**不假装起了悬浮窗**。
"""
from __future__ import annotations

import os
import subprocess
import time

#: 标志文件名（在 `console_dir` 下）。**存在即退役**——哨标自己看到就退。
FLAG_NAME = "logo.quit"

#: 哨标窗标题标记。**单一真源是 `inbox_window.LOGO_TITLE_MARK`**，
#: 这里给一份别名仅供 `logo_cmd()` 组命令用（不许两处写字面量）。
#: ⚠️ logo.ps1 的 `$form.Text` 必须含此串且**运行时不许改写**（改写＝找窗瞎掉）。

#: 起的等待预算（秒）：哨标是 PowerShell 冷启，比 Edge 快，但也要预算。
OPEN_WAIT_SEC = 5.0

#: 退役等待预算（秒）：哨标 40ms 轮询一次标志，0.75s 足够；给到 2s 是余量。
RETIRE_WAIT_SEC = 2.0


def flag_path(root=None):
    """退役标志的路径。★ 与 `tray.json`/`tray_action.txt` 同目录，同一族协议。"""
    import inbox_config as C
    return os.path.join(C.console_dir(root), FLAG_NAME)


def script_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "tools", "logo.ps1")


def action_path(root=None):
    """哨标点击写动作去**托盘那一个**动作文件（`open` 语义只许一份实现）。"""
    import inbox_tray as TR
    return TR.action_path(root)


def state_path(root=None):
    """哨标读**托盘那一个**状态文件（与托盘同源，不另写一份状态）。"""
    import inbox_tray as TR
    return TR.state_path(root)


def write_flag(root=None):
    """写退役标志。幂等；写失败**如实抛**（调用方不允许假装写了）。"""
    p = flag_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("quit\n")
    return True


def clear_flag(root=None):
    """清退役标志。**必须在退役结束后清** —— 留着一个陈年标志会让下一枚
    哨标一出生就退（那正是"开了等于没开"的假成功形状）。
    清不掉 ⇒ 如实抛（比留着不说坏）。"""
    p = flag_path(root)
    if os.path.exists(p):
        os.remove(p)
    return True


def logo_cmd(title=None, tip=None, size=46, x=-1, y=-1, stale_after=30,
             root=None):
    """组起悬浮哨标的 PowerShell 命令（ASCII-only 由 Python 侧拼中文参数）。

    ★ 与 `inbox_tray.run()` 同纪律：`-NoProfile -ExecutionPolicy Bypass -File`，
      不落临时脚本、不拼接成一条长命令行（Windows 命令行长度/转义都是坑）。
    ★ 中文/标记全走参数：ps1 源文件保持 ASCII（PS 5.1 无 BOM 会解错 UTF-8）。
    """
    import inbox_window as WIN
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
           script_path(),
           "-State", state_path(root),
           "-Action", action_path(root),
           "-Quit", flag_path(root),
           "-Title", title if title is not None else ("Antinel" + WIN.LOGO_TITLE_MARK),
           "-Size", str(int(size)),
           "-StaleAfterSec", str(int(stale_after))]
    if x is not None and y is not None and int(x) >= 0 and int(y) >= 0:
        cmd += ["-X", str(int(x)), "-Y", str(int(y))]
    if tip:
        cmd += ["-Tip", str(tip)]
    return cmd


def _finder(finder=None):
    if finder is not None:
        return finder
    import inbox_window as WIN
    return WIN.find_logo_windows


def _killer(killer=None):
    if killer is not None:
        return killer
    import inbox_window as WIN
    return WIN.close_logo_windows


def retire(root=None, finder=None, killer=None, wait_sec=RETIRE_WAIT_SEC,
           poll=0.1, verbose=True):
    """让漂浮哨标退役。返回 dict，**如实**（不谎报"退了"）。

    路径：写 `logo.quit` ⇒ 等窗消失（哨标自己退）⇒ **清标志**。
    兜底：等到超时窗还在 ⇒ `close_logo_windows`（WM_CLOSE）并**在 why 里
    写明这是兜底**。没有哨标 ⇒ 空转成功（`acted=False`）。
    ★ 为什么清标志不能省：`flag` 留着 ⇒ 下一枚哨标出生即退 ⇒ 用户点收缩
      看到"什么都没发生"（假成功）。清失败照样抛，让调用方知道。
    """
    out = {"ok": False, "acted": False, "windows": [], "why": ""}
    find = _finder(finder)
    try:
        hs = list(find())
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "枚举哨标窗失败：%s: %s" % (type(e).__name__, e)
        return out
    if not hs:
        out.update(ok=True, why="没有开着的漂浮哨标（无需退役）")
        return out
    out["windows"] = hs
    try:
        write_flag(root=root)
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "写退役标志失败（%s: %s），哨标退不了" % (type(e).__name__, e)
        return out
    t0 = time.time()
    left = list(hs)
    while time.time() - t0 < float(wait_sec):
        time.sleep(poll)
        try:
            left = list(find())
        except Exception:                                   # noqa: BLE001
            left = []
        if not left:
            break
    # ★ 标志使命结束就清 —— 不管窗退没退（兜底会另行关窗）。清了下一枚才生得出来。
    cleared = True
    try:
        clear_flag(root=root)
    except Exception as e:                                  # noqa: BLE001
        cleared = False
        out["why"] = "退役标志没清掉（%s: %s）：下一枚哨标可能一出生就退" % (
            type(e).__name__, e)
    if not left:
        out.update(ok=True, acted=True,
                   why=(out["why"] or "标志退役成功（哨标自己退的）"))
        return out
    # 兜底：标志没劝动它，WM_CLOSE（不强杀）
    kill = _killer(killer)
    n, why = 0, ""
    try:
        n, why = kill(why="标志退役超时 %ss" % int(wait_sec))
    except Exception as e:                                  # noqa: BLE001
        why = "兜底关窗也失败：%s: %s" % (type(e).__name__, e)
    out.update(ok=(cleared and n > 0), acted=True,
               why=(out["why"] or "标志退役超时，已兜底 %s%s" % (
                   why, "" if n > 0 else "（仍未关掉）")))
    return out


def open_floating(root=None, launcher=None, finder=None, killer=None,
                  wait_sec=OPEN_WAIT_SEC, size=46, x=-1, y=-1, topmost=None,
                  verbose=True):
    """起一枚漂浮哨标并**等它就位**（回读 + 置顶）。返回 dict 如实。

    顺序纪律：**先退役旧的**（不叠两枚）⇒ 清标志 ⇒ 起 ⇒ 等窗 ⇒ 置顶。
    ★ 谁起窗谁等它就位（C4 纪律）：一次性调用方（服务 POST 是长命进程，
      但这条路径的目标用户是"点了就收缩"，不等到位=假成功）。
    ★ 起不来 ⇒ `ok=False` + why 说清原因，**不关任何东西**（调用方决定）。
    ★ 置顶失败**不是致命的**：WinForms 那侧 `$form.TopMost=$true` 才是主机制
      （服务端再设一次只是加固），所以置顶没成照样算"就位"，但在 `why` 里
      如实留下 `topmost=False` —— 不把"没置顶"说成"置顶了"。
      `topmost` 可注入（判据不起真桌面、不碰真 Z 序）。
    """
    import inbox_window as WIN
    out = {"ok": False, "opened": False, "topmost": False, "windows": [], "why": ""}
    find = _finder(finder)
    # 1) 先退役旧哨标（幂等；没有则空转）
    #    ★ `killer` 必须一路传到这里：`retire` 的兜底关窗与 `finder` 是配套的
    #      注入（假桌面 + 真关窗 ⇒ 兜底永远"没关掉" ⇒ 误判成退役失败）。
    ret = retire(root=root, finder=find, killer=killer, verbose=False)
    if not ret.get("ok"):
        out["why"] = "旧哨标没退役干净（%s），不起新的 —— 宁可少一枚也不要两枚" % ret.get("why", "")
        return out
    # 2) 起
    cmd = logo_cmd(size=size, x=x, y=y, root=root)
    if launcher is None:
        if os.name != "nt":
            out["why"] = "非 Windows：起不了 WinForms 哨标（如实降级，不假装起了）"
            return out
        try:
            subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=0x08000000 if os.name == "nt" else 0)
        except Exception as e:                              # noqa: BLE001
            out["why"] = "起哨标进程失败：%s: %s" % (type(e).__name__, e)
            return out
    else:
        try:
            launcher(cmd)
        except Exception as e:                              # noqa: BLE001
            out["why"] = "注入的 launcher 失败：%s: %s" % (type(e).__name__, e)
            return out
    # 3) 等窗就位 + 回读 + 置顶
    t0 = time.time()
    hs = []
    why_wait = ""
    while time.time() - t0 < float(wait_sec):
        time.sleep(0.15)
        try:
            hs = list(find())
        except Exception as e:                              # noqa: BLE001
            hs = []
            why_wait = "%s: %s" % (type(e).__name__, e)
        if hs:
            break
    out["windows"] = hs
    if not hs:
        out["why"] = "哨标进程起了但窗口 %.1fs 内没出现%s" % (
            float(wait_sec), ("（%s）" % why_wait) if why_wait else "")
        return out
    try:
        if topmost is not None:
            topmost(hs)
            out["topmost"] = True
        else:
            _okt, _whyt = WIN.set_topmost(hs)
            out["topmost"] = bool(_okt)
            if not _okt:
                out["why"] = "哨标窗已在，但置顶没成（%s）—— 不置顶也照样算就位" % _whyt
    except Exception as e:                                  # noqa: BLE001
        out["topmost"] = False
        out["why"] = "哨标窗已在，但置顶失败：%s: %s —— 不置顶也照样算就位" % (
            type(e).__name__, e)
    if not out.get("why"):
        out["why"] = "哨标已就位（%d 枚，已置顶）" % len(hs)
    out.update(ok=True, opened=True)
    return out


def collapse_console(root=None, run_id=None, token=None, closer=None,
                     launcher=None, finder=None, killer=None,
                     wait_sec=OPEN_WAIT_SEC, topmost=None, win_finder=None,
                     verbose=True):
    """「收缩成漂浮哨标」：起哨标成功**才**关本面板窗。返回 dict 如实。

    ★ 顺序即安全：哨标没起来就关面板 ⇒ 用户两手空空（点一下收缩，
      值守台没了、哨标也没有）—— 那比不收缩坏得多。所以先起、看清楚、再关。
    ★ 关窗口径与 `close_console_windows` 同纪律：先按 `run_id` 严格关
      （只动本次这枚）；一枚都没关掉时**再宽泛关一次** —— 用户在一个
      值守台窗口里点了收缩，意图没有歧义（不会误关别的程序：宽泛也只在
      标题含「值守台」的窗里关）。
    """
    import inbox_window as WIN
    out = {"ok": False, "floating": None, "closed": 0, "why": ""}
    rid = run_id or (WIN.build_run_id(token) if token else None)
    flo = open_floating(root=root, launcher=launcher, finder=finder, killer=killer,
                        wait_sec=wait_sec, topmost=topmost, verbose=verbose)
    out["floating"] = flo
    if not flo.get("ok"):
        out["why"] = "哨标没起来（%s）⇒ **没有关面板窗**（不至于两头空）" % flo.get("why", "")
        return out
    n = 0
    try:
        n = WIN.close_console_windows(run_id=rid, closer=closer, finder=win_finder)
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "哨标已起，但关面板窗失败：%s: %s" % (type(e).__name__, e)
        return out
    if not n and rid:
        # 严格（带 #run_id）一枚都没匹配上 ⇒ 宽泛兜底一次（只关值守台窗）
        try:
            n = WIN.close_console_windows(run_id=None, closer=closer,
                                          finder=win_finder)
        except Exception as e:                              # noqa: BLE001
            n = 0
            out["why"] = "宽泛关窗也失败：%s: %s" % (type(e).__name__, e)
    out["closed"] = n
    if n > 0:
        out.update(ok=True, why="哨标已就位，面板窗已关（%d 枚）" % n)
    else:
        out.update(ok=False,
                   why="哨标已就位，但一枚 Antinel 监理窗都没关掉（可能已不在桌面上）")
    return out
