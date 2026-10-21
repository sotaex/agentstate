# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Antinel 监理 · 漂浮哨标（最小态）：**只在，不碍事**。

★ 0.50.0（创始人 2026-10-14：「值守台应该有一个能'漂浮'的最小态……
  哨兵很多时候不要碍事，只要在，就行了」）：
  Antinel 监理大窗占屏幕，用户不愿意让它一直开着；但哨兵的**在岗状态**必须随时
  可读（灯五态）。折中＝**一枚漂浮小窗**：跟输入法浮动窗口一样贴在屏幕
  一角，**只画一个 LOGO**，点击它 ⇒ 写 `open` 动作、自己退场，Antinel 监理展开。

★ 为什么又是"纯文本文件协议"（与托盘同一族）：
      Python 写 `logo.quit`   ──▶  logo.ps1 每 40ms 轮询，见到就退
      logo.ps1 写 `tray_action.txt` ──▶ 守护进程/托盘消费者取走（唯一实现）
  ⇒ 可单测：不起真进程也能验全链（`launcher`/`finder`/`killer` 注入）。

★ 0.52.0（创始人 2026-10-17 截图「颤抖的哨标难看、切换慢、点它反而不回
  Antinel 监理」——三症同根，一并修）：
  ① 图标：哨标不再自画动效（0.50.0 的 GDI+ 旋转弧线＋浮动，40ms 全量重绘
     无双缓冲 ⇒ 颤抖），改画与托盘**同一族**的状态图标
     （`assets/icons/{state}{shield}.ico`，映射与 `inbox_tray.icon_file()`
     同一含义）。静态、双缓冲 ⇒ 不抖。
  ② 速度：哨标进程**常驻**——展开时**藏**（`logo.hide`），收缩时**唤**
     （`logo.show`），都在哨标 40ms 一拍内完成，不再每次冷启 PowerShell。
  ③ 反向切换：点击哨标**不再自毁**（旧版写完 `open` 就退，而动作只有
     守护进程/托盘会消费——都不在跑时哨标白白消失、Antinel 监理开不出来）。
     现在：写 `open` 后**原地待命**，消费方开出Antinel 监理后写 `logo.hide`
     把它藏起来；没人消费 ⇒ 哨标还在，用户可以再点。

★ **四态只有一本账**，不许四处各写一遍：
     collapse（收缩）：唤出哨标（show / 冷启）＋ 关本面板窗
     expand （展开）：哨标写 open 待命；服务端 open 路径顺手 **hide**（藏起待命）
     prewarm（预热）：Antinel 监理展开时起一枚**隐藏**常驻哨标（首次收缩也瞬时）
     retire （退役）：`logo.quit` 标志 ⇒ 哨标进程真退；超时才 WM_CLOSE 兜底
  `retire()` 仍是**退役的唯一实现**（去重、收孤儿）；展开路径改调
  `hide()`——哨标藏而不死，下一次收缩才是瞬时的。

★ 0.53.1（创始人 2026-10-19 截图，三症同源）：**哨标画的就是标准动效 LOGO**。
  ① 0.52.0 改画托盘同族静态 `.ico` 后，最小态出现的是一枚**光秃秃的圆圈**
     ——「跟主窗口不一样」。②  TransparencyKey 镂空窗＋图标中心全透 ⇒
     命中测试只覆盖不透明像素，**点圆圈中间没反应**，只有点在环线上才切回。
  ③ 那一版还是**死的**（0.50.0 的 GDI+ 动效因 40ms 全量重绘无双缓冲而颤抖，
      0.52.0 一刀切改成静态）。
  修法（三症各对症，且都不复发）：
  · **画什么**：`tools/logo_frame.ps1`（纯帧数学，可被判据 dot-source 后真跑）
    照 `tray.json` 的 `logo` 块（`inbox_server.logo_motion_spec()` 单一真源）
    算出与 `_LOGO_JS` **同一份**动法的帧；`logo.ps1` 只做"画布→像素"映射。
  · **怎么画**：`WS_EX_LAYERED`＋`UpdateLayeredWindow` **逐像素透明** ——
    AA 边缘不再与 TransparencyKey 的 Fuchsia 混色（0.50.0 粉边的根治，
    不是"把 alpha 吸附成 0/255"那种以画面质量换不粉边的做法）；帧在
    2× 离屏上 AA 绘制后高质量缩小到 46px（0.3–0.9px 的细线只有真 AA 不抖）。
  · **点什么**：`WM_NCHITTEST` 自行判定 —— **画得出来的范围（内切圆）内**
    一律 `HTCLIENT`（圆中间、环上、涟漪里都点得到），四角返回
    `HTTRANSPARENT`（不挡背后窗口的点击）。半径由规格几何派生
    （`Get-HitRadius`），不写死数字。
  · **减少动效**：读系统的 `MinAnimate`（对应页面的
    `prefers-reduced-motion`，Q-20 同族）—— 命中时**不打拍**，每次换态
    只推一帧静态（静态帧取目标态，不是启动态，见 FLO-10e）。
  · **拿不到规格**（旧 daemon 写的 tray.json／规格构建失败）：如实**回落**
    托盘同族静态 `.ico`（不假装会动），其余生命线（三标志/点击待命/拖拽）
    一律不变。

★ 如实原则（本仓铁律，与紧急提醒/浮层同一标准）：
    · 哨标没起来 ⇒ `ok=False` 且 `why` 说清（**不关面板窗**，
      用户不至于"点一下收缩，Antinel 监理没了"）；
    · 标志退役超时 ⇒ `why` 写明"兜底 WM_CLOSE 关的"，不假装是标志生效；
    · 找不到 PowerShell/脚本 ⇒ 明确降级，**不假装起了悬浮窗**。
"""
from __future__ import annotations

import os
import subprocess
import time

#: 标志文件名（在 `console_dir` 下）。**存在即退役**——哨标自己看到就退。
FLAG_NAME = "logo.quit"

#: ★ 0.52.0：常驻哨标的**藏/唤**标志（与 `logo.quit` 同族、同目录、纯文本）。
#:   哨标见到即自行动作并**消费掉**（删除＝消费；单用途标志文件，与多行动作
#:   文件的「改名让开」不同族——动作文件不删是纪律，单字节标志由消费者收走）。
FLAG_HIDE = "logo.hide"
FLAG_SHOW = "logo.show"

#: 藏/唤的等待预算（秒）：哨标 40ms 一拍，0.75s 足够；给到 2s 是余量。
HIDE_WAIT_SEC = 2.0
#: ★ 0.52.0：唤出预算 5s（实测三路并行的高负载下，哨标进程的 40ms 拍会拖到
#:   ~3s；空闲时实测 <0.1s）。给足余量只是防"慢机器上误判成僵尸"，
#:   空闲机器的体感仍是瞬时。
SHOW_WAIT_SEC = 5.0

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


def hide_flag_path(root=None):
    """藏标志的路径（0.52.0：展开 ⇒ 哨标藏起待命，不退役）。"""
    import inbox_config as C
    return os.path.join(C.console_dir(root), FLAG_HIDE)


def show_flag_path(root=None):
    """唤标志的路径（0.52.0：收缩 ⇒ 常驻哨标毫秒级唤出）。"""
    import inbox_config as C
    return os.path.join(C.console_dir(root), FLAG_SHOW)


def script_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "tools", "logo.ps1")


def frame_script_path():
    """帧数学（**纯函数**）脚本的路径（0.53.1）。

    `logo.ps1` dot-source 它；判据（`ci/inbox_guards_0514.py` FLO-10a/b）也
    dot-source **同一个文件**真跑 —— 一份实现，两个调用方，杜绝"判据另写了
    一遍帧数学"（假绿第四族的形状）。
    """
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "tools", "logo_frame.ps1")


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


def clear_lifecycle_flags(root=None):
    """清**藏/唤**标志（0.52.0）。★ 为什么需要：这两个标志正常由哨标自己
    消费（删除），但写方（Python）在等待中失败/被杀时可能留下陈年标志 ⇒
    下一枚哨标一出生就被藏/被唤（"开了等于没开"的假成功同型）。
    **起新哨标前必须清**（`prewarm` / `show_or_spawn` 的冷启分支都调它）。"""
    for p in (hide_flag_path(root), show_flag_path(root)):
        if os.path.exists(p):
            os.remove(p)
    return True


def logo_cmd(title=None, tip=None, size=46, x=-1, y=-1, stale_after=30,
             root=None, hidden=False):
    """组起悬浮哨标的 PowerShell 命令（ASCII-only 由 Python 侧拼中文参数）。

    ★ 与 `inbox_tray.run()` 同纪律：`-NoProfile -ExecutionPolicy Bypass -File`，
      不落临时脚本、不拼接成一条长命令行（Windows 命令行长度/转义都是坑）。
    ★ 中文/标记全走参数：ps1 源文件保持 ASCII（PS 5.1 无 BOM 会解错 UTF-8）。
    ★ 0.52.0：多传 `-Show/-Hide`（藏/唤标志）与 `-IconDir`（托盘同族状态
      图标目录，`assets/icons`）；`hidden=True` ⇒ `-Hidden`（常驻预热：
      出生即隐藏，等 show 标志）。
    ★ 0.53.1：多传 `-Frame`（纯帧数学脚本 `tools/logo_frame.ps1`）—— 哨标
      照 `tray.json` 的 `logo` 块（动效规格）画标准动效 LOGO；`-IconDir`
      从此只是**回落**路径（拿不到规格时的静态兜底），不再是主渲染。
    ★ 0.53.2（T1）：多传 `-BrandIcon`（`assets/logo/antinel.ico`，品牌完整
      LOGO：深色方形底板＋探针环＋琥珀哨点）—— 回落画它而不是姿态灯。
      显式传参而不是让 PS 从 `-IconDir` 推兄弟目录：路径只有 Python 这
      一侧说得准（`-IconDir` 是既有参数，语义不扩权）。"""
    import inbox_window as WIN
    _pkg = os.path.dirname(os.path.abspath(__file__))
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
           script_path(),
           "-State", state_path(root),
           "-Action", action_path(root),
           "-Quit", flag_path(root),
           "-Show", show_flag_path(root),
           "-Hide", hide_flag_path(root),
           "-IconDir", os.path.join(_pkg, "assets", "icons"),
           "-BrandIcon", os.path.join(_pkg, "assets", "logo", "antinel.ico"),
           "-Frame", frame_script_path(),
           "-Title", title if title is not None else ("Antinel" + WIN.LOGO_TITLE_MARK),
           "-Size", str(int(size)),
           "-StaleAfterSec", str(int(stale_after))]
    if hidden:
        cmd += ["-Hidden"]
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


def _any_finder(any_finder=None, finder=None):
    """枚举哨标（**含隐藏**）的探测器（0.52.0，常驻哨标的"它还在不在"）。

    ★ 注入规则：`finder` 被注入（判据假桌面）且未显式给 `any_finder`
      ⇒ **跳过隐藏检查**（假桌面不存在"隐藏常驻"的概念，注入路径的行为
      必须与 0.51.x 完全一致，既有判据才不红）。生产路径（finder=None）
      默认探含隐藏的。"""
    if any_finder is not None:
        return any_finder
    if finder is not None:
        return None                      # 判据注入 ⇒ 不做隐藏检查
    import inbox_window as WIN
    return (lambda: WIN.find_logo_windows(visible_only=False))


def retire(root=None, finder=None, killer=None, wait_sec=RETIRE_WAIT_SEC,
           poll=0.1, verbose=True, any_finder=None):
    """让漂浮哨标退役。返回 dict，**如实**（不谎报"退了"）。

    路径：写 `logo.quit` ⇒ 等窗消失（哨标自己退）⇒ **清标志**。
    兜底：等到超时窗还在 ⇒ `close_logo_windows`（WM_CLOSE）并**在 why 里
    写明这是兜底**。没有哨标 ⇒ 空转成功（`acted=False`）。
    ★ 为什么清标志不能省：`flag` 留着 ⇒ 下一枚哨标出生即退 ⇒ 用户点收缩
      看到"什么都没发生"（假成功）。清失败照样抛，让调用方知道。
    ★★ 0.52.0：生产路径（`finder=None`）**连隐藏的常驻哨标一起收** ——
      否则 `retire` 报「没有哨标」而盘上还躺着一枚藏着的（0.52.0 常驻态），
      下一枚一出生就成两枚。判据注入 false 桌面时行为不变（见 `_any_finder`）。
    """
    out = {"ok": False, "acted": False, "windows": [], "why": ""}
    find = _any_finder(any_finder, finder) or _finder(finder)
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
    # ★ 生产路径要连隐藏窗一起关（枚举口径见 `_any_finder`；注入 killer 的
    #   判据仍用自己的桩，行为不变）
    if killer is None and finder is None and any_finder is None:
        import inbox_window as WIN
        kill = lambda why="": WIN.close_logo_windows(visible_only=False,  # noqa: E731
                                                     why=why)
    else:
        kill = _killer(killer)
    n, why = 0, ""
    try:
        n, why = kill(why="标志退役超时 %ss" % int(wait_sec))
    except Exception as e:                                  # noqa: BLE001
        why = "备用关窗也失败：%s: %s" % (type(e).__name__, e)
    out.update(ok=(cleared and n > 0), acted=True,
               why=(out["why"] or "标志退役超时，已改用备用方式 %s%s" % (
                   why, "" if n > 0 else "（仍未关掉）")))
    return out


def hide(root=None, finder=None, killer=None, wait_sec=HIDE_WAIT_SEC,
         poll=0.05, verbose=True):
    """让漂浮哨标**藏起来待命**（0.52.0：展开路径的主动作，不退役）。

    路径：写 `logo.hide` ⇒ 等窗消失（哨标自己藏，40ms 一拍）⇒ 清标志。
    ★ 为什么藏而不杀：哨标进程常驻，下一次「收缩」才能毫秒级唤出
      （每次冷启 PowerShell 正是创始人实测的「切换很慢」）。
    ★ 没有可见哨标 ⇒ 空转成功，并**顺手清陈年 hide 标志**（留着它，
      下一枚哨标一出生就被藏 —— "开了等于没开"的假成功同型）。
    ★ 哨标藏不动（进程僵了）⇒ 兜底走 `retire()` 真退役 —— 宁可下一次
      收缩慢一次（重新冷启），也不留一枚唤不应的死标志。
    返回 dict，**如实**（不谎报"藏了"）。
    """
    out = {"ok": False, "acted": False, "windows": [], "why": ""}
    find = _finder(finder)
    try:
        hs = list(find())
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "枚举哨标窗失败：%s: %s" % (type(e).__name__, e)
        return out
    hp = hide_flag_path(root)
    if not hs:
        # 没有可见哨标：空转 + 清陈年标志（有则清，无则过）
        if os.path.exists(hp):
            try:
                os.remove(hp)
            except OSError as e:
                out["why"] = "陈年 hide 标志没清掉（%s: %s）" % (type(e).__name__, e)
                return out
        out.update(ok=True, why="没有可见的漂浮哨标（无需隐藏）")
        return out
    out["windows"] = hs
    try:
        os.makedirs(os.path.dirname(hp), exist_ok=True)
        with open(hp, "w", encoding="utf-8", newline="\n") as f:
            f.write("hide\n")
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "写藏标志失败（%s: %s），哨标藏不了" % (type(e).__name__, e)
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
    # 标志正常由哨标自己消费（删除）；这里再兜一次底（哨标已藏但消费
    # 失败时不留陈年标志）。清不掉不致命 —— 下一轮 hide 空转分支还会清。
    try:
        if os.path.exists(hp):
            os.remove(hp)
    except OSError:
        pass
    if not left:
        out.update(ok=True, acted=True, why="哨标已藏起待命（自己藏的）")
        return out
    # 兜底：藏不动 ⇒ 真退役（quit 标志 → WM_CLOSE），并如实说明
    ret = retire(root=root, finder=find, killer=killer, verbose=False)
    out["acted"] = True
    if ret.get("ok"):
        out.update(ok=True,
                   why="哨标没响应 hide，已改用备用方式退役（%s）" % (
                       ret.get("why") or "quit"))
    else:
        out["why"] = "哨标藏不动、备用退役也没成（%s）" % (ret.get("why") or "",)
    return out


def show_or_spawn(root=None, launcher=None, finder=None, killer=None,
                  any_finder=None, wait_sec=SHOW_WAIT_SEC, topmost=None,
                  verbose=True):
    """「收缩」的哨标就位动作（0.52.0）：**唤出常驻的，没有才冷启**。

    三路：
      ① 可见哨标已在 ⇒ 空转成功（幂等）；
      ② 常驻哨标在（含隐藏）⇒ 写 `logo.show` ⇒ 等它自己现出 ⇒ 置顶
         —— 毫秒级，**这就是"点监理图标瞬时切换"的兑现处**；
      ③ 都没有 ⇒ 冷启（回落 `open_floating`，退役→清标志→起→等→置顶）。
    ★ ② 等不到（哨标僵了）⇒ 清掉唤标志后**回落冷启** —— 不谎报就位。
    ★ 注入规则见 `_any_finder`：判据注入 finder 时不做隐藏检查（行为同旧）。
    """
    import inbox_window as WIN
    find = _finder(finder)
    try:
        hs = list(find())
    except Exception as e:                                  # noqa: BLE001
        hs = []
    if hs:
        return {"ok": True, "opened": True, "topmost": None, "windows": hs,
                "fast": True, "why": "哨标已在（无需唤起）"}
    anyf = _any_finder(any_finder, finder)
    if anyf is not None:
        try:
            hs_any = list(anyf())
        except Exception:                                   # noqa: BLE001
            hs_any = []
        if hs_any:
            sp = show_flag_path(root)
            try:
                os.makedirs(os.path.dirname(sp), exist_ok=True)
                with open(sp, "w", encoding="utf-8", newline="\n") as f:
                    f.write("show\n")
            except Exception as e:                          # noqa: BLE001
                return {"ok": False, "opened": False, "topmost": False,
                        "windows": hs_any,
                        "why": "写唤标志失败（%s: %s）" % (type(e).__name__, e)}
            t0 = time.time()
            got = []
            while time.time() - t0 < float(wait_sec):
                time.sleep(0.05)
                try:
                    got = list(find())
                except Exception:                           # noqa: BLE001
                    got = []
                if got:
                    break
            try:
                if os.path.exists(sp):
                    os.remove(sp)
            except OSError:
                pass
            if got:
                # 与 open_floating 同一置顶纪律：置顶没成不算致命，如实记
                _okt, _whyt = True, ""
                try:
                    if topmost is not None:
                        topmost(got)
                    else:
                        _okt, _whyt = WIN.set_topmost(got)
                except Exception as e:                      # noqa: BLE001
                    _okt, _whyt = False, "%s: %s" % (type(e).__name__, e)
                return {"ok": True, "opened": True, "topmost": bool(_okt),
                        "windows": got, "fast": True,
                        "why": ("常驻哨标已唤出" if _okt else
                                "常驻哨标已唤出，但置顶没成（%s）" % _whyt)}
            # 唤不动 ⇒ 回落冷启（open_floating 会先退役这枚僵尸）
    return open_floating(root=root, launcher=launcher, finder=finder,
                         killer=killer, wait_sec=wait_sec, topmost=topmost,
                         verbose=verbose)


def prewarm(root=None, launcher=None, killer=None, wait_sec=20.0,
            verbose=True):
    """起一枚**隐藏**的常驻哨标（0.52.0：Antinel 监理展开时预热）。

    ★ 为什么要预热：不预热的话，每次开机后的**第一次**收缩仍要冷启
      PowerShell（慢一次）。Antinel 监理一展开就预埋好隐藏哨标 ⇒ 之后的每一次
      收缩（含第一次）都是毫秒级唤出。
    ★ 预算 20s：预热跑在后台线程，等久一点没有 UX 代价；实测三路并行的
      高负载下 PowerShell 冷启可超 5s（5s 预算会假失败）。
    ★ 先收走旧的（**含隐藏孤儿** —— 上一个服务进程死了留下的常驻哨标，
      `retire` 的可见-only 找不到它们）：探测与兜底关闭都走 visible_only=False。
    ★ 清藏/唤标志在**起新之前**（陈年标志会让新哨标一出生就被藏/被唤）。
    ★ 失败**如实返回**、不抛 —— 预热只是优化，冷启路径仍能兜底。
    """
    import inbox_window as WIN
    out = {"ok": False, "opened": False, "windows": [], "why": ""}

    def anyf():
        return WIN.find_logo_windows(visible_only=False)

    def closer_all(why=""):
        return WIN.close_logo_windows(visible_only=False, why=why)
    ret = retire(root=root, finder=anyf, killer=closer_all, verbose=False)
    if not ret.get("ok"):
        out["why"] = "旧哨标（含隐藏）没退役干净（%s），不预热" % ret.get("why", "")
        return out
    try:
        clear_lifecycle_flags(root=root)
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "清藏/唤标志失败（%s: %s），不预热" % (type(e).__name__, e)
        return out
    cmd = logo_cmd(root=root, hidden=True)
    if launcher is None:
        if os.name != "nt":
            out["why"] = "非 Windows：预热不了 WinForms 哨标（如实降级）"
            return out
        try:
            subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=0x08000000 if os.name == "nt" else 0)
        except Exception as e:                              # noqa: BLE001
            out["why"] = "预热进程起失败：%s: %s" % (type(e).__name__, e)
            return out
    else:
        try:
            launcher(cmd)
        except Exception as e:                              # noqa: BLE001
            out["why"] = "注入的 launcher 失败：%s: %s" % (type(e).__name__, e)
            return out
    t0 = time.time()
    hs = []
    while time.time() - t0 < float(wait_sec):
        time.sleep(0.15)
        try:
            hs = list(anyf())
        except Exception:                                   # noqa: BLE001
            hs = []
        if hs:
            break
    out["windows"] = hs
    if not hs:
        out["why"] = "预热进程起了但窗口 %.1fs 内没出现（隐藏窗也算）" % float(wait_sec)
        return out
    out.update(ok=True, opened=True, why="常驻哨标已预热（隐藏，等 show 标志）")
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
                     any_finder=None, verbose=True):
    """「收缩成漂浮哨标」：哨标就位**才**关本面板窗。返回 dict 如实。

    ★ 顺序即安全：哨标没就位就关面板 ⇒ 用户两手空空（点一下收缩，
      Antinel 监理没了、哨标也没有）—— 那比不收缩坏得多。所以先就位、看清楚、再关。
    ★★ 0.52.0：就位动作从"每次冷启一枚新哨标"改成 `show_or_spawn()` ——
      常驻哨标毫秒级唤出（"点监理图标瞬时切换"），没有才冷启。
    ★ 关窗口径与 `close_console_windows` 同纪律：先按 `run_id` 严格关
      （只动本次这枚）；一枚都没关掉时**再宽泛关一次** —— 用户在一个
      Antinel 监理窗口里点了收缩，意图没有歧义（不会误关别的程序：宽泛也只在
      标题含「Antinel 监理」的窗里关）。
    """
    import inbox_window as WIN
    out = {"ok": False, "floating": None, "closed": 0, "why": ""}
    rid = run_id or (WIN.build_run_id(token) if token else None)
    flo = show_or_spawn(root=root, launcher=launcher, finder=finder,
                        killer=killer, any_finder=any_finder,
                        wait_sec=wait_sec, topmost=topmost, verbose=verbose)
    out["floating"] = flo
    if not flo.get("ok"):
        out["why"] = ("哨标没起来（%s）⇒ 面板窗先不关（不至于两头空）"
                      % flo.get("why", ""))
        return out
    n = 0
    try:
        n = WIN.close_console_windows(run_id=rid, closer=closer, finder=win_finder)
    except Exception as e:                                  # noqa: BLE001
        out["why"] = "哨标已起，但关面板窗失败：%s: %s" % (type(e).__name__, e)
        return out
    if not n and rid:
        # 严格（带 #run_id）一枚都没匹配上 ⇒ 宽泛兜底一次（只关Antinel 监理窗）
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
