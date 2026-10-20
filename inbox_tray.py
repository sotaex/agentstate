# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Antinel 监理 · 托盘（第 2 层）：常驻、不占地方、一眼读状态。

★ 为什么是 PowerShell 而不是 pystray（创始人让我分析后定）：
  产品仓 `[project]` **一个运行时依赖都没有**；`System.Drawing.Icon` 能**直读 `.ico`
  （不需要 Pillow）**；而 `host_shield._notify()` **本来就在走 PowerShell+WinForms**。
  为一个小图标引 ~10MB 依赖不成比例。

★ 协议是**纯文本文件**（不用线程、不用管道、不写 Win32）：
      Python 写 `tray.json`  ──▶  tray.ps1 每 1 秒读一次，更新图标/提示
      Python 读 `tray_action.txt` ◀──  tray.ps1 菜单被点时写一行
  ⇒ **可单测**：不需要真的开一个托盘。

★ 不删任何文件：消费动作文件用 **`os.rename` 改名让开**，不 `unlink`。
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime

import inbox_config as C
import inbox_model as M


def state_path(root=None):
    return os.path.join(C.console_dir(root), "tray.json")


def action_path(root=None):
    return os.path.join(C.console_dir(root), "tray_action.txt")


# --- 哨兵态（★ 0.36.0 新增维度）-------------------------------------------------
#: ★ 为什么要有这个维度（创始人 2026-10-07「这个图标是动态的，能看到当前哨兵的
#:   工作状态」）：
#:   原来五态 `L0/L1/L2/Ls/R0` 只表达**事件等级**（最近有没有告警），
#:   **完全看不出哨兵此刻在不在岗**。实测出现过这一对：
#:     托盘图标显示 `R0`（27 分钟前写的旧值），而此刻 `guard_posture()`
#:     实测是 `guarding`、哨兵 pid 83352 好好在岗、心跳 62 秒前。
#:   ⇒ 图标在说谎。这与本仓明令禁止的"把『没在查』渲染成『没问题』"同型。
#:   ⇒ 图标改成**两个维度**：事件等级（五态，配形状）+ 哨兵态（叠加标记）。
#
#: 六档，**直接用 `host_shield.guard_posture()` 的档位，不另立一套** ——
#: 另立一套必然与页面口径漂移，那正是本项目反复出事的形状。
SHIELD_ONPOSTURE = "on"        # 哨兵在岗且自检通过
SHIELD_UNPOSTURE = "unposted"  # 哨兵不在岗／心跳陈旧／自检不符
SHIELD_UNKNOWN = "unknown"     # 探不到（盲区）——≠"没事"
SHIELD_OFF = "off"             # 未启用：哨兵默认没在值守（产品第一原则：默认全关）

#: 哨兵态 → 图标后缀。与 `assets/icons/` 下的 `{事件态}{后缀}.ico` 对应。
SHIELD_SUFFIX = {
    SHIELD_ONPOSTURE: "",
    SHIELD_UNPOSTURE: "-unposted",
    SHIELD_UNKNOWN: "-unknown",
    SHIELD_OFF: "-off",
}

#: 哨兵态 → tooltip 前缀（★ 一眼能读，不要求用户查表）
#: ★ 0.37.3：`off` 的 tip 从「护盾未启用」改成「哨兵未启用」——「哨兵」是页面上
#:   **唯一**的守护角色（创始人 2026-10-09：「不要制造并列的护盾加哨兵两个概念，
#:   哨兵一个概念足矣，护盾是哨兵手里的一个工具」）。托盘提示直接把「护盾」
#:   摆在"未启用"的主语位置，正是那个并列角色的残留。
#: ★★ 0.50.4 命名变更注记（创始人 2026-10-15 签发）：显示词「哨兵」→「**监理**」
#:   （与 glossary 词表、状态原因文案同一提交换词）；上面 0.37.3 的注释是当时
#:   的决策记录，按「记录原文不改写」纪律保留原样。`SHIELD_*` 常量名与图标
#:   后缀不动（内部标识冻结）。
SHIELD_TIP = {
    SHIELD_ONPOSTURE: "监理在岗",
    SHIELD_UNPOSTURE: "监理不在岗",
    SHIELD_UNKNOWN: "监理状态探不到",
    SHIELD_OFF: "监理未启用",
}

#: 哨兵态配色（与 `mk_icons.py` 同源；形状也区分，不只靠颜色）
SHIELD_COLOR = {
    SHIELD_ONPOSTURE: (0x22, 0x6b, 0x4a),     # 绿＝在岗
    SHIELD_UNPOSTURE: (0x9b, 0x22, 0x26),     # 红＝不在岗
    SHIELD_UNKNOWN: (0x2a, 0x5d, 0xb0),# 蓝＝盲区
    SHIELD_OFF: (0x5f, 0x5e, 0x5a),                # 灰＝未启用
}


def probe_posture(root=None):
    """现探哨兵姿态（**托盘侧唯一探针**，0.48.5 A2 抽出）。

    ★ 为什么单独成函数：`shield_state()` 与 `sync_from_items()` 都要"此刻的
      姿态"——各探一次就是两次 guard_posture（两次盘上读链），且语义上
      "托盘这一刻看到的状态"只能有一个。抽出来共用一处。
    ★ 探不到 ⇒ 返回 None（调用方按盲区处理）—— **不许**因为探不到就编一个。
    """
    try:
        import host_shield as HS
        # ★★ 0.37.1 修（0.35.3 同型漏改的调用点）：不传包根 ⇒ 读中枢
        #   rollup 链而非本包审计链（0.35.3 实测相差 27202s vs 160s）
        #   ⇒ 托盘图标/tip 会显示一个**过时**的哨兵态。
        return HS.guard_posture(
            root or os.path.dirname(os.path.abspath(__file__)))
    except Exception:                                   # noqa: BLE001
        # 探不到就是探不到 —— **不许因为探不到就画成"在岗"**
        return None


def console_port(root=None):
    """Antinel 监理此刻开在哪个端口（读 `url.json`，**唯一真源**）。没有 ⇒ `None`。

    ★★ 为什么需要（0.48.5 B2，遗留问题清单）：首选端口被占时Antinel 监理会漂到
      临时端口 —— 用户手输 `127.0.0.1:8790` 打不开。托盘提示里带上**实际
      端口**，才知道该点哪个。
    ★ 惰性 import（`probe_posture` 同款）：避免托盘 ↔ 服务在模块加载期成环。
    ★ 没有记录（从没起过）⇒ 返回 `None` —— **不编**一个端口。
    """
    try:
        import inbox_server as SV
        rec = SV.read_console_record(root)
    except Exception:                                   # noqa: BLE001
        return None
    try:
        return int((rec or {}).get("port")) or None
    except (TypeError, ValueError):
        return None


def shield_state(posture=None):
    """`guard_posture()` 的档位 → 托盘的哨兵态（**只做映射，不判定**）。

    ★ 判定权在 `host_shield.guard_posture()`：它才是唯一实探的实现
      （链权威 armed + 进程在岗 + 心跳新鲜 + 自检通过）。
      这里**不重算**任何一项 —— 重算就是第二套口径，必然漂移。
    """
    if posture is None:
        posture = probe_posture()
    st = ((posture or {}).get("state") if posture else None)
    return {
        "guarding": SHIELD_ONPOSTURE,
        # ★ 0.36.3 新增：研发态**是在岗的**（自检不符只说明"代码比登记的新"，
        #   哨兵进程好好的、心跳新鲜）。映射到 `unposted`（红）会谎报缺岗。
        #   ⇒ 复用 `unknown`（蓝·盲区）那一档：不是"一切正常"，也不是"坏了"。
        "dev": SHIELD_UNKNOWN,
        "warn": SHIELD_UNPOSTURE,        # 在岗但身份存疑 ⇒ 不许显示绿
        "interrupted": SHIELD_UNPOSTURE,
        "down": SHIELD_UNPOSTURE,
        "off": SHIELD_OFF,
        "unknown": SHIELD_UNKNOWN,
    }.get(st, SHIELD_UNKNOWN)


def icon_file(state, shield=None, root=None):
    """事件态(+哨兵态) → `.ico` 路径。

    ★ 组合图标**不存在时如实回落**到基础态图标，并让调用方能知道回落了 ——
      不返回一个"看起来有图标其实打不开"的路径。
    ★ 不生成新文件：图ico 是 `tools/mk_icons.py` 的构建期产物
      （运行期画 ico 需要编码器，不引依赖）。
    """
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icons")
    s = state if state in ("L0", "L1", "L2", "Ls", "R0") else "L0"
    if shield and shield in SHIELD_SUFFIX:
        cand = os.path.join(base, "%s%s.ico" % (s, SHIELD_SUFFIX[shield]))
        if os.path.exists(cand):
            return cand
    return os.path.join(base, "%s.ico" % s)


def icon_path(state, root=None):
    """五态 → `.ico` 路径（**旧接口，保持兼容**）。未知态 ⇒ 退回 L0。"""
    return icon_file(state, None, root)


def write_state(state, count=0, tip="", root=None, shield=None, total=None,
                label=None, logo_seen=None):
    """写托盘状态（原子替换）。返回写下的 dict。

    ★ 0.36.0：多写一个 `shield` 字段（哨兵态）。**不写它**的话图标只剩
      "最近有没有告警"这一个维度，看不出哨兵此刻在不在岗（见 SHIELD_SUFFIX 注释）。

    ★ 0.47.0（方案 v3.0 §5 步三）：多写一个 `total` ＝ **分母**。
      托盘角标一直是"一个光秃秃的分子"（实测曾长期显示 `count=181`，
      而按现行口径真值只有 4）—— 只看那个数，用户无法判断它是多是少。
      分母一并写进 `tray.json`，并进 `tip`（图标上只放得下分子，分母放提示里）。

    ★★ 0.48.5（A2）：多写一个 `label` ＝ **状态词本身**（`M.light_explain()`
      的 `label`，与 Web 标题/顶部条同一个词）。此前托盘 tip 的事件词是
      `sync_from_items` 自己拼的第二份口径（旧合并读：历史 R0 抬灯），与
      页面自 0.39.0 起的 `current_state()`（历史 R0 一律不抬灯）各说各话。
      写进 `tray.json` 才能被**判据**逐字比对（W-03）。
      `label` 缺省 ⇒ 从 `state` 现算（`M.state_label`），不写空。

    ★ 0.53.2（T2）：`logo_seen` 可注入**独立**的失败节流状态（判据用；
      缺省 = 进程级的 `_LOGO_SPEC_SEEN`，见其注）。
    """
    if shield is None:
        shield = shield_state()
    if label is None:
        label = M.state_label(state if state in ("L0", "L1", "L2", "Ls", "R0")
                              else "L0")
    payload = {"state": state if state in ("L0", "L1", "L2", "Ls", "R0") else "L0",
               "count": int(count), "tip": str(tip)[:200],
               "label": str(label),
               # ★ 分母：这条数来自多少条记录。取不到 ⇒ `None`（**不编 0**，
               #   "不知道分母" ≠ "分母是 0"，后者会让一个真告警看起来是百分之百）。
               "total": None if total is None else int(total),
               "shield": shield if shield in SHIELD_SUFFIX else SHIELD_UNKNOWN,
               "ts": time.time()}
    # ★★ 0.53.1：多写一个 `logo` 块 ＝ **漂浮哨标的动效规格**（从
    #   `inbox_server.logo_motion_spec()` 单一真源派生）。哨标
    #   （tools/logo.ps1）照它画与主窗口同一份动法（规格 v1.2）；
    #   没有它 ⇒ 哨标如实回落品牌 LOGO 静态图标（不假装会动，0.53.2 T1）。
    #   ★ 0.53.2（T2）：改**必写**。旧口径「取不到就不写这个键」有一个
    #     静默形状：**「旧版没这功能」与「新版拿不到规格」在 tray.json 里
    #     逐字节相同** —— 哨标悄悄变哑，而读文件的人分不出是哪种。现在
    #     两条路都看得见：
    #       ① 拿得到 ⇒ `logo` 块照写；
    #       ② 拿不到 ⇒ **仍然写** `logo_missing: true` ＋ `logo_error`
    #         （失败标记；`logo` 键缺位 ⇒ 哨标回落，见 logo.ps1），
    #         并进审计链一条 `logo_spec_missing`（每进程每个失败
    #         episode 至多一条，见 `_logo_spec_missing_event`）。
    #     tray.json 本身照写不误 —— 托盘不因为规格缺席而停摆。
    spec, spec_err = _logo_spec_block()
    if spec is not None:
        payload["logo"] = spec
        # ★ 成功 ⇒ 清节流：此后再失败是**新的一程**（见 _LOGO_SPEC_SEEN 注）。
        (_LOGO_SPEC_SEEN if logo_seen is None else logo_seen)["failed"] = False
    else:
        payload.update(_logo_failure_block(spec_err))
        _logo_spec_missing_event(root, spec_err, seen=logo_seen)
    p = state_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, p)
    return payload


#: 托盘状态多久没被刷新就算**陈旧**。守护进程默认 2 秒一拍（`Daemon.run`），
#:  这里给 15 倍余量，避免正常抖动被误判成"停了"。
STALE_AFTER_SEC = 30


def _logo_spec_block():
    """漂浮哨标的动效规格（0.53.1）＋ **失败原因**（0.53.2 T2）。

    返回 `(spec, err)`：拿得到 ⇒ `(dict, None)`；拿不到 ⇒ `(None, err)`。

    ★ 为什么要连原因一起给：只给 `None` 的话，「取不到这个事实」能写进
      tray.json，但「**为什么**取不到」会在这里被吞掉 —— 下游只看到一个
      缺失的键，分不清「inbox_server 挂了」还是「规格字典构到一半炸了」。
      失败原因与失败事实一样是证据（0.53.2 T2）。
    ★ 为什么走懒加载：`inbox_server` 反过来也（在函数内）import 本模块，
      模块级互相 import 会成环 —— 本仓的既有解法就是函数内 import。
    """
    try:
        import inbox_server as SV
        return SV.logo_motion_spec(), None
    except Exception as e:                                           # noqa: BLE001
        return None, e


def _logo_failure_block(err):
    """拿不到动效规格时**仍然写进 tray.json 的键**（0.53.2 T2，唯一定义处）。

    ★ 为什么与 `logo` 键**互斥**而不是并存：哨标（logo.ps1）只认
      `logo` 键的存在性来决定回落；并存会让「有规格」和「没规格」在
      文件里长得一样。缺 `logo` ＋ 有 `logo_missing` ⇒ 下游能**逐字节
      区分**「旧版没写该字段」与「新版写了但拿不到」——这正是 0.53.1
      条件写法的静默缺口。
    ★ `logo_error` 是**人话整句**（type: msg），不是裸异常串 —— 读
      tray.json 的是 PowerShell 侧与人，不是 traceback 阅读器。
    """
    why = "spec unavailable"
    if err is not None:
        why = "%s: %s" % (type(err).__name__, err)
    return {"logo_missing": True,
            "logo_error": "motion spec unavailable (%s)" % why[:160]}


#: 哨标规格失败态的**进程内**节流状态（0.53.2 T2）。
#: ★ 为什么必须节流：托盘守护进程每 2 秒写一次状态，规格拿不到时
#:   **每拍一条审计**会在一天内写出四万多条同因记录 —— 记账机制自己
#:   把账本灌满，正是 0470 提醒预算同款要防的形状。
#: ★ 形态是**状态机**而不是「一条 forever」：失败 → 恢复 → 再失败是**两个
#:   episode**，各记一条；失败进行中不重复记。「这一程里坏过」必须看得见，
#:   「每一拍都在坏」不许变成噪声。判据 FLO-12 钉这两个计数。
#: ★ `write_state(..., logo_seen=...)` 可注入**独立**的一份（判据用）——
#:   否则同一条判据第二次跑会被上一次留下的 `failed=True` 静默节流，
#:   变成"判据自己把自己测瞎"（2026-10-20 实测：N-FLO12b 因此报「夹具不成立」）。
_LOGO_SPEC_SEEN = {"failed": False}


def _logo_spec_missing_event(root, err, seen=None):
    """规格拿不到 ⇒ 进审计链一条 `logo_spec_missing`（0.53.2 T2）。

    ★ 为什么进链而不只写 tray.json 文件标记：文件标记只有「下一个来读
      tray.json 的人」看得到；链上的记录让晨报／日报不必翻临时状态文件
      就能看见「这个进程曾经拿不到规格」。
    ★ 家目录口径与 host_shield 一致：给了 root ⇒ 项目链
      （`<root>/.psl/audit`）；没给 ⇒ 个人中枢 rollup（`append_chained`
      的 None 语义在调用方兜住，见 `_chain_record`）。
    ★ 记账失败**不抛**：家务事不许把正经事搞崩（调用方是 `write_state`，
      托盘照写不误）——最坏结果是少一条记录，不是托盘不工作。
    ★ `seen` 缺省 = 进程级节流状态；判据传一份独立的进来（见
      `_LOGO_SPEC_SEEN` 注）。
    """
    st = _LOGO_SPEC_SEEN if seen is None else seen
    if st.get("failed"):
        return                      # 失败进行中：已记过，不重复
    st["failed"] = True
    rec = {"ts": datetime.now().astimezone().isoformat(timespec="seconds"),
           "type": "logo_spec_missing", "tool": "-",
           "session": "inbox-tray", "host": "generic",
           "decision": "allow", "severity": "warning",
           "reason": ("托盘写状态时拿不到漂浮哨标动效规格 —— tray.json 已写 "
                      "logo_missing 失败标记，哨标回落品牌 LOGO 静态图标"
                      "（不假装会动）"),
           "error": "" if err is None else
                    ("%s: %s" % (type(err).__name__, err))[:200]}
    _chain_record(root, rec)


def _chain_record(root, rec):
    """产品侧进审计链的**唯一入口**（0.53.2 T2 抽出，托盘与徽标痕迹共用）。

    ★ 配方与 `tools/enforce_probe.py`／`host_shield._chain` 同源：
      `session_dna.append_chained`（C-1 唯一链实现）＋ day manifest。
    ★ root 给了 ⇒ 项目链（`<root>/.psl/audit`，registry 消费点会读到）；
      没给 ⇒ 中枢 rollup（host_shield `record(None, ...)` 的同一口径）。
    ★ 任何失败都吞掉并返回 False —— 记账是旁路，不许把主业搞崩
      （调用方 `write_state` / daemon tick 都已各自 try 住）。
    """
    try:
        import session_dna as sd
        audit_dir = (os.path.join(root, ".psl", "audit")
                     if root else os.path.join(C.hub_dir(), "rollup"))
        return bool(sd.append_chained(audit_dir, rec))
    except Exception:                                           # noqa: BLE001
        return False


# ---------------------------------------------------------------- 徽标痕迹 --
#: ★ 0.53.2（T1/T2）：徽标（tools/logo.ps1，PowerShell）**写不了** Python
#:   的审计链（hash 链与锁协议都在 Python 侧）。它往 console_dir 下的
#:   `logo_events.jsonl` 追加一行行 JSON；本模块改名消费（零删除纪律，
#:   与 `poll_actions` 同族）后按同一配方进链。
#:   ★ 纯文本文件协议是托盘 ↔ 徽标的既有约定（见模块头），这里是同一条
#:     协议的第三个方向：徽标 ⇒ Python 账本。
LOGO_EVENTS_KNOWN = ("logo_mode_missing", "logo_frame_unavailable",
                     "logo_dpi_changed", "logo_event_unreadable")


def logo_events_path(root=None):
    return os.path.join(C.console_dir(root), "logo_events.jsonl")


def drain_logo_events(root=None):
    """把徽标侧的痕迹读走并进审计链（0.53.2）。返回进链的事件 list。

    ★ 顺序是**先链后改名**（与 `poll_actions` 的先改名相反，故意的）：
      动作丢了只是少点一下；**审计证据丢了不可再生**。改名只在全部行都
      成功进链后做；有任一行失败 ⇒ 文件原地留着，下 tick 重试
      （最坏重复记几条，好过静默丢失）。
    ★ 读不懂的行不丢弃：包一条 `logo_event_unreadable` 进链 ——
      「徽标写过一行没人看得懂的东西」本身就是证据（静默丢弃是同型病）。
    ★ 改名让开，绝不 unlink（零删除纪律）。
    """
    p = logo_events_path(root)
    if not os.path.exists(p):
        return []
    try:
        with open(p, encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
    except OSError:
        return []                       # 读不出来 ⇒ 不消费，下 tick 再试
    if not lines:
        # 空文件也要让开（否则它会一直在场）——但先确认能改名成功
        try:
            os.rename(p, p + ".taken-%d" % int(time.time() * 1000))
        except OSError:
            pass
        return []
    done = []
    for ln in lines:
        rec = _logo_event_record(ln)
        if rec is None:
            continue
        if _chain_record(root, rec):
            done.append(rec)
        else:
            break                       # 进链失败 ⇒ 整体不消费，下 tick 重试
    if len(done) == len(lines):
        try:
            os.rename(p, p + ".taken-%d" % int(time.time() * 1000))
        except OSError:
            pass
    return done


def _logo_event_record(line):
    """一行徽标痕迹 JSON ⇒ 链记录（0.53.2）。读不懂 ⇒ `logo_event_unreadable`。

    ★ ts／type 从行里取（徽标侧写的事实）；缺 ts ⇒ 现在补（标注 missing
      会改变字段集，链记录按 schema 缺省即可，不新增字段）。
    ★ session/tool/host 与 `logo_spec_missing` 同族固定值 —— 链上认得出
      这是「徽标侧产生的痕迹」而不是钩子或门闸。
    """
    base = {"tool": "-", "session": "inbox-logo", "host": "generic",
            "decision": "allow", "severity": "warning"}
    try:
        ev = json.loads(line)
        if not isinstance(ev, dict):
            raise ValueError("not an object")
        typ = str(ev.get("type") or "").strip()
        if not typ or typ not in LOGO_EVENTS_KNOWN:
            raise ValueError("unknown type %r" % typ)
        rec = dict(base)
        rec["ts"] = str(ev.get("ts") or
                        datetime.now().astimezone().isoformat(timespec="seconds"))
        rec["type"] = typ
        rec["reason"] = reason_of(ev)
        for k in ("state", "title"):
            if ev.get(k) is not None:
                rec[k] = ev[k]
        return rec
    except Exception:                                           # noqa: BLE001
        rec = dict(base)
        rec["ts"] = datetime.now().astimezone().isoformat(timespec="seconds")
        rec["type"] = "logo_event_unreadable"
        rec["reason"] = "badge wrote an unreadable logo event line"
        rec["raw"] = line[:200]
        return rec


def reason_of(ev):
    """徽标痕迹 ⇒ 人话 reason（0.53.2）。类型 ⇒ 句子，一处定义不散两处。"""
    t = ev.get("type")
    if t == "logo_mode_missing":
        return ("哨标规格 modes 缺 %s 态键 —— 已如实回落 L0 帧并在本留痕；"
                "规格 modes 与 LOGO_MODE 的闭合由闸门判据常驻守"
                % ev.get("state", "?"))
    if t == "logo_frame_unavailable":
        return ("哨标动效帧不可用（%s）—— 已回落品牌 LOGO 静态图标"
                % ev.get("reason", "?"))
    if t == "logo_dpi_changed":
        return ("哨标换屏重算物理尺寸（%s）—— 尺寸与可点区已按新 DPI 重新派生"
                % ev.get("reason", "?"))
    return "badge logo event: %s" % t


def read_state(root=None, now=None, stale_after=STALE_AFTER_SEC):
    """读托盘状态，**并且判它是不是陈旧的**。

    ★★ 0.35.3 修（真缺陷，交接件 §5 点名待审）：
      `tray.ps1` 每秒读一次 `tray.json` 更新图标与提示，但**从来不看 `ts`**。
      Python 侧（守护进程 / Antinel 监理）一旦停了，托盘会**无限期显示最后一次状态**
      —— "值守中 · 一切正常" 一直挂着，而实际上**早就没人再更新它**。
      这与本项目最反对的形状同型：**把「没在查」渲染成「没问题」**。
      ⇒ 读的一侧必须自己判陈旧，并把"停止更新"如实说出来。

    返回在原 dict 上加两个字段：
      `age_seconds` —— 距上次写入多少秒（读不到/无 ts ⇒ `None`）
      `stale`       —— `True` = 已停止更新，**不许当作当前状态看**
    """
    try:
        with open(state_path(root), encoding="utf-8") as f:
            d = json.load(f)
    except Exception:                           # noqa: BLE001
        return {}
    if not isinstance(d, dict):
        return {}
    ts = d.get("ts")
    age = None
    if isinstance(ts, (int, float)) and ts > 0:
        age = max(0.0, float(now if now is not None else time.time()) - float(ts))
    d["age_seconds"] = age
    # 读不到 ts ⇒ **按陈旧算**（不知道就别装作知道）
    d["stale"] = (age is None) or (age > stale_after)
    return d


def stale_note(d, stale_after=STALE_AFTER_SEC):
    """把"托盘已停止更新"说成人话。新鲜 ⇒ 空串（不打扰）。

    ★ 陈旧时**不猜状态**：不说"现在没事"，只说"这份状态已经不更新了"。
    """
    if not d or not d.get("stale"):
        return ""
    age = d.get("age_seconds")
    if age is None:
        return "托盘状态没有可核对的更新时间，不能当作当前状态看。"
    if age >= 3600:
        when = "%.1f 小时前" % (age / 3600.0)
    elif age >= 60:
        when = "%d 分钟前" % int(age // 60)
    else:
        when = "%d 秒前" % int(age)
    return ("托盘状态已停止更新（最后一次是%s，超过 %d 秒没刷新）；"
            "这表示**没人再更新它**，不等于此刻一切正常。"
            % (when, stale_after))


def sync_from_items(items, root=None, tip=None, posture=None):
    """由收件箱现状刷新托盘（页面/守护进程调它）。

    ★★ 0.35.3（创始人 2026-10-06「尽可能少让人处理」）：
      托盘角标原来数的是**全部历史未处理**（实测本机 181 条）——
      那个数只会涨不会跌，用户看两次就再也不看了。
      改成**最近 24 小时内、只有你本人能解决的事**，且**按事由归并后的件事数**。

    ★ 0.36.0：tooltip 与图标都带上**哨兵态**。
      原实现只按事件等级给 tip，于是出现实测这一对矛盾：
      图标 `R0`「失守 · 防线未生效」（27 分钟前写的旧值），
      而 `guard_posture()` 实测 `guarding`、哨兵好好在岗 ⇒ **图标在说谎**。
      ⇒ 现在 tip 前缀一律由 `SHIELD_TIP[shield]` 给，
        且**哨兵不在岗时事件态不再压过它**（R0 只说明"有过失守"，
        不说明"此刻没人守"；后者才是用户要立刻知道的）。

    ★★ 0.48.5（A2，遗留问题清单）：状态词与原因句**与 Web 头部同源**。
      旧实现的事件态走 `M.console_state()`（旧合并读：24h 账里的历史 R0
      会抬灯），而页面自 0.39.0 起走 `M.current_state()`（创始人裁定：
      「没有失守却显示失守，就是错误的」—— R0 绝不由账给）⇒ 本机实测
      同一时刻托盘 `R0`「有过失守 · 哨兵在岗」 vs 页面「拦截」。
      修法同本仓铁律：**消灭副本** —— 一律取 `M.light_explain()`
      （灯态唯一真源 `current_state()` ＋ 页面原因句的唯一实现）：
        · `state`（图标用）＝ `ex["state"]`；
        · `label`（状态词）＝ `ex["label"]`，**逐字**进 `tray.json` 与 tip；
        · 粮的读数与页面同根（都调无参 `granary_now()`）—— 连根都不一样
          就会再漂出一套口径（Ls 只在一边亮）。
      `shield`（哨兵态图标维度）与件数/分母口径不变。
    """
    if posture is None:
        posture = probe_posture()
    ex = M.light_explain(posture, items, granary=M.granary_now())
    st = ex["state"]
    act = [it for it in items if M.bucket_of(it) == M.BUCKET_ACTION]
    n = M.count_groups(act)
    sh = shield_state(posture if posture is not None else {})
    if tip is None:
        # ★ 状态词与**页面顶部条/标题同一个词**（`ex["label"]`，W-03 逐字断言）。
        #   哨兵态只作第二段：图标维度的话（在岗/不在岗/盲区/未启用）。
        tip = "%s · %s" % (ex["label"], SHIELD_TIP[sh])
        # ★★ 0.51.0（规格 v1.2 §2.4）：**并存徽标**（研发中／缺粮）带进提示 ——
        #   位置放在状态词**之后**：W-03 断言 `tip.startswith(状态词)`，
        #   前缀不许动（两个界面说同一个词，是第一顺位）。缺键 ⇒ 当没有徽标。
        _bd = ex.get("badges") or []
        if _bd:
            tip = "%s · %s" % (tip, "、".join(n for _k, n, _w in _bd))
    # ★★ 0.47.0（方案 §5 步三）：这条 tip 是分子 ⇒ **必带窗口与分母**。
    #   分母＝本次载入的全部记录条数（`items`），窗口＝`M.WINDOW_HOURS`。
    #   ★ 图标上只放得下分子，分母与窗口写进提示（悬停可见）与 `tray.json`。
    if tip is not None and " / " not in str(tip):
        tip = "%s / %d（最近 %d 小时）" % (str(tip), len(items or []),
                                      M.WINDOW_HOURS)
    # ★★ 0.48.5（B2）：带上**实际端口** —— 默认端口被占时Antinel 监理会漂到临时
    #   端口，用户手输 8790 打不开；提示里给出真地址，才知道该点哪个。
    #   没有落盘记录（没起过）⇒ 不编一个端口。
    if tip is not None:
        _port = console_port(root)
        if _port:
            tip = "%s · 端口 %d" % (tip, _port)
    # ★ 状态气泡不是详情页；只写「有事/等你」会让用户点不到具体事项。
    #   托盘图标可显示件数，具体事由在主界面「要处理」里查看。
    return write_state(st, n, tip, root=root, shield=sh, total=len(items or []),
                       label=ex["label"])


def push_action(action, root=None):
    """托盘菜单被点时，由 PowerShell 侧写一行（Python 侧只读）。"""
    p = action_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a", encoding="utf-8", newline="\n") as f:
        f.write(str(action).strip() + "\n")
    return True


def poll_actions(root=None):
    """读走**全部**待处理动作（**改名让开，不删除**）。没有 ⇒ 空列表。

    ★ 整文件改名＝原子消费；**必须一次把里面的行全取走**，
      否则同批的后几个动作会随改名一起消失（首版就踩了这个坑）。
    """
    p = action_path(root)
    if not os.path.exists(p):
        return []
    taken = p + ".taken-%d" % int(time.time() * 1000)
    try:
        os.rename(p, taken)                     # ★ 改名，不删除
    except OSError:
        return []
    acts = []
    try:
        with open(taken, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    acts.append(line)
    except OSError:
        return []
    return acts


def poll_action(root=None):
    """取**第一个**动作（会把这一批全部消费掉，其余动作请用 `poll_actions`）。"""
    acts = poll_actions(root)
    return acts[0] if acts else None


def tray_available():
    """本机能不能起托盘（Windows + 有 PowerShell）。**不能也不影响其余四层。**"""
    if os.name != "nt":
        return False
    from shutil import which
    return bool(which("powershell") or which("pwsh"))


def script_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "tray.ps1")


def consume_loop(root=None, stop=None, interval=1.0, refresh_every=5.0):
    """★ 0.35.2：托盘**自己**消费动作的循环（跑在后台线程里）。

    ★★ 为什么必须有它（真缺陷，创始人 2026-10-06「点托盘没反应」）：
      托盘菜单只是**写一行到 `tray_action.txt`**，真正消费的是**守护进程**。
      而 `antinel inbox tray` **只起图标、不起守护进程** ⇒
      只开托盘的用户点「Open console」**什么都不会发生**。
    ★ 动作语义**不二次实现**：直接调 `inbox_daemon.handle_actions()`（唯一实现）。
    ★ 消费是原子的（`poll_actions` 用 `os.rename` 整文件改名）⇒
      守护进程与托盘同时在跑也不会把同一个动作做两遍。
    ★ 不删任何文件。

    ★★ 0.36.0：**顺带周期刷新托盘状态** —— 这是「图标是动态的」真正落地的地方。
      真缺陷（本机实测）：原实现只在 `run()` 启动那一刻刷新一次，
      之后全靠守护进程每 2 秒写一次。而守护进程**不是常驻的**
      （`antinel inbox tray` 只起图标，不起守护进程）⇒
      实测 `tray.json` 停在 **1642 秒（27 分钟）**前，`read_state()` 判 `stale=True`，
      可图标**依然显示 27 分钟前的 `R0`「失守 · 防线未生效」**，
      而同时`guard_posture()` 实测 `guarding`、哨兵 pid 83352 好好在岗。
      ⇒ **图标在说谎**，且用户没有任何办法从它得知真相。
      改法：托盘自己每 `refresh_every` 秒探一次并重写 ——
      **不依赖守护进程是否在跑**，也不要新起一个常驻进程
      （一个常驻进程去盯另一个常驻进程，是本仓反对的形状）。
    """
    import inbox_daemon as DM
    next_refresh = 0.0
    while not (stop is not None and stop.is_set()):
        try:
            DM.handle_actions(root=root)
        except Exception:                       # noqa: BLE001
            pass                                # 一轮出错不许把循环打死
        now = time.time()
        if now >= next_refresh:
            try:
                refresh_state(root=root)
            except Exception:                   # noqa: BLE001
                pass    # 探不到就保持旧值 + stale 提示；不写假状态
            next_refresh = now + float(refresh_every)
        time.sleep(interval)


def refresh_state(root=None, items=None, posture=None):
    """按当前收件箱现状**重算一次**托盘状态（幂等，可反复调）。

    ★★ 0.35.3 修（真缺陷，本轮实测抓到，不是读代码猜的）：
      `antinel inbox tray` 原来**只起图标、不刷状态** ⇒
      ① 没有 `tray.json` 时，托盘一上来就是陈旧态（"停止更新")，而人根本没停；
      ② 已有旧文件时，会把**上一次由谁写的旧口径**一直显示下去。
      实测本机：`tray.json` 里是 `count=181`（那是 0.35.3 之前的
      "全部历史未处理"口径），而按现行口径真值只有 **4** ——
      托盘显示的件数比实际该你处理的事多 45 倍，且**永远不自己纠正**。
      ⇒ 起托盘前必须先算一次；不算就等于让用户看一个假数字。
    ★ 0.48.5（A2）：`posture` 可注入（None ⇒ `probe_posture()` 现探）。
      不注入时探的是**这台机器此刻的真实姿态** —— 判据若要可复现，必须显式
      传夹具（0363 R07 的教训：判据不许看机器天气）。
    """
    try:
        if items is None:
            import inbox_store as S
            items = S.load_items(root=root)
    except Exception:                             # noqa: BLE001
        items = []
    return sync_from_items(items, root=root, posture=posture)


def run(root=None, block=True, consume=True):
    """起托盘。非 Windows / 无 PowerShell ⇒ 明确返回 False（不假装成功）。

    `consume=True`（默认）：顺带起一个后台线程消费菜单动作
    —— 这样**单起托盘就能用**，不必另外再起守护进程。

    ★ 0.35.3：起托盘**之前**先 `refresh_state()` 一次 ——
      否则托盘会把上一份（可能来自旧口径、甚至几小时前）的状态当现在。
    """
    if not tray_available():
        return False
    import subprocess
    sp = script_path()
    if not os.path.exists(sp):
        return False
    # ★ 先算一次真实态势，再让托盘去读它。
    try:
        refresh_state(root=root)
    except Exception:                             # noqa: BLE001
        pass          # 刷不出来也照样起托盘：托盘会显示陈旧提示，那比假数字诚实
    # ★ 0.35.3：把**陈旧阈值与陈旧提示**一并传进去 —— 托盘自己每秒读文件，
    #   只有它能在"写的一方已经死了"的时候说出实话。
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", sp,
           "-State", state_path(root), "-Action", action_path(root),
           "-IconDir", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "assets", "icons"),
           "-StaleAfterSec", str(STALE_AFTER_SEC),
           "-StaleTip", "状态已停止更新 · 不能当作当前状态"]
    if block:
        stop = threading.Event()
        if consume:
            threading.Thread(target=consume_loop, args=(root, stop),
                             daemon=True).start()
        try:
            return subprocess.call(
                cmd, creationflags=0x08000000 if os.name == "nt" else 0) == 0
        finally:
            stop.set()
    subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,
                     creationflags=0x08000000 if os.name == "nt" else 0)
    return True
