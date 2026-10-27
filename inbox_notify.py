# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Antinel 监理 · 通知层（第 1 层）：**记账与节流**，不再产生任何像素。

★★★ 0.59.0 连根去除（创始人 2026-10-27「冒的还是上古时代的老旧泡泡」）：
  本层原来有两代"自己能画的东西" —— 先是 15 秒就消失、也不进通知中心的气泡，
  后来换成 **Windows Toast**（`toast_script` ＋ `WindowsToastBackend`）。
  **两代都不是 Antinel 的外观**：Windows 决定长相，带不上主窗口那套 CSS 和官方 LOGO。
  ⇒ 两者已从本文件**删除**，`default_backend()` 恒为 `NullBackend`。
  提醒只剩两条路：① 品牌化浮窗（`inbox_bubble`，与主窗口同一套 CSS ＋ 官方 LOGO）；
  ② 不占屏幕的痕迹（收件箱、托盘角标、台账）。

★ 本文件**保留**的东西及其理由（不是残渣）：
  · `toast()` 的**节流与台账**（`record_sent`／`settle`／`throttle_*`）——
    那是"记账与去重"，与用哪种外观无关；判据注入 `RecordingBackend` 验路由，
    删掉会把记账正确性一起扔掉。
  · 后端仍是**可注入**的：`NullBackend`（生产默认）／`RecordingBackend`（夹具）。

★ 节流只节**门铃**，不节**台账**：同类 30 分钟内不重复，但收件箱照记。
  （这是 R8 的同一道理：门铃可节流，台账不可。）
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import subprocess
import sys
import time

import inbox_config as C
import inbox_model as M
import inbox_window as WIN

MIN_INTERVAL = 1800          # 同类通知最小间隔（秒），与 host_shield 同值


class Backend:
    name = "base"
    #: 这个后端**走哪条通道**（`notice_log` 的 `channel` 字段就取它）。
    #: ★ 它是「有没有通道」这一维的承载：`NullBackend.channel="file"` 表示
    #:   **本机没有弹窗通道**，改写通知账 —— 不是「通道坏了」。两者后果完全不同
    #:   （无头不算送达未知，坏通道才算），见 `settle()`。
    channel = "toast"

    def toast(self, title, body, level):
        raise NotImplementedError


class NullBackend(Backend):
    """什么都不做（无 GUI 环境 / 用户关掉了通知 / **本版已移除系统通知**）。

    ★ 0.59.0：`last_error` 说清"不是失败，是没有这条通道" —— 否则调用方
      会把「本版不提供系统通知」读成「发出去了但失败了」，两种事后果不同。
    """
    name = "null"
    channel = "file"
    last_error = "本版没有系统通知通道：提醒只走品牌化浮窗与收件箱"

    def toast(self, title, body, level):
        return False


class RecordingBackend(Backend):
    """测试用：把调用记下来，**零副作用**。"""
    name = "recording"

    def __init__(self):
        self.calls = []

    def toast(self, title, body, level):
        self.calls.append({"title": title, "body": body, "level": level})
        return True


AUMID = "Antinel.Console"


def _ps_quote(s):
    return str(s).replace("'", "''")


def register_aumid_script():
    """生成注册 AppUserModelID 的 PowerShell（不注册 AUMID，Toast 可能不显示）。"""
    # ★ 0.52.0：Toast 图标从 python.exe 换成**品牌图标**（桌面/自启/AUMID 三处
    #   快捷方式统一；单一真源 inbox_window.brand_icon_path）。缺失（极旧安装）
    #   退回 sys.executable —— 有总比没有强，但不假造"品牌图标已就位"。
    icon = WIN.brand_icon_path() or sys.executable
    return (
        "$ErrorActionPreference='SilentlyContinue';"
        "$dir=Join-Path $env:APPDATA 'Microsoft\\Windows\\Start Menu\\Programs';"
        "$lnk=Join-Path $dir 'Antinel 监理.lnk';"
        "$ws=New-Object -ComObject WScript.Shell;"
        "$s=$ws.CreateShortcut($lnk);"
        "$s.TargetPath=(Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source;"
        "$s.Arguments='-m antinel inbox serve';"
        "$s.IconLocation='%s';"
        "$s.Save()" % _ps_quote(icon)
    )


def default_backend():
    """【0.59.0 连根去除】默认后端**永远**是 `NullBackend` —— 本版不再有
    系统通知（Windows Toast）这一能力。

    ★ 为什么不是"看情况退回系统通知"：系统通知的外观由 Windows 决定，
      带不上 Antinel 的 CSS 与官方 LOGO。创始人要的是**跟主窗口长得一样**的
      提醒，那就不可能靠系统通道实现。于是只有两条路：
        ① 品牌化浮窗（`inbox_bubble`，Edge --app 小窗）；
        ② 不占屏幕的痕迹（收件箱、托盘角标、台账）。
      **"系统通知"这第三条路已经不存在了。**
    ★ `toast()` 与它的台账仍保留：那是"记账与节流"，与外观无关；
      判据注入 `RecordingBackend` 验路由，删掉会把记账正确性一起扔掉。
    """
    return NullBackend()


def notice_log_path(root=None):
    """通知账的落点（F7：`~/.antinel/console/notice_log.jsonl`，**不进链**）。

    ★ 复用 `inbox_config.console_dir()`，不另拼家目录 —— 设了 `ANTINEL_HUB_DIR`
      沙箱就必须跟着走，否则判据会静默读到真机账（0.35.3 收口过的老路）。
    """
    return os.path.join(C.console_dir(root), "notice_log.jsonl")


def _append_line(path, line):
    """把一行追加进账。**二进制**：不换行尾、不加 BOM。

    文本模式的 `open(..., "a")` 在 Windows 上会把 `"\\n"` 写成 `"\\r\\n"`，
    本仓在 0490 上踩过整文件假 diff。抽成函数，负控才能换掉它证明这条守得住。
    """
    with open(path, "ab") as f:
        f.write(line.encode("utf-8"))


def _iso(epoch):
    """epoch → 本地时区 ISO，**秒精度**（与链记录的 ts 同一口径）。"""
    return _dt.datetime.fromtimestamp(float(epoch)).astimezone().isoformat(
        timespec="seconds")


def _parse_ts(s):
    """ISO 串 → 带时区的 datetime。解不开返回 None（由调用方记坏行）。"""
    if not isinstance(s, str) or not s.strip():
        return None
    try:
        t = _dt.datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo is not None else t.astimezone()


def _row_problem(row):
    """只看形状与取值域。合格返回 None，否则返回原因串（英文稳定前缀）。

    ★ `channel` 与 `how` **同现即坏行**：一行要么是「发出」，要么是「见过」。
      两个都有说明写侧把两件事混成了一条，读侧**不许挑一个当真**。
    """
    if not isinstance(row, dict):
        return "notice.row.shape: not an object"
    kind = row.get("kind")
    if not isinstance(kind, str) or not kind.strip():
        return "notice.row.kind: missing or empty"
    if _parse_ts(row.get("ts")) is None:
        return "notice.row.ts: unparsable %r" % (row.get("ts"),)
    has_ch, has_how = "channel" in row, "how" in row
    if has_ch and has_how:
        return "notice.row.mixed: channel and how on the same line"
    if not has_ch and not has_how:
        return "notice.row.kind_of_line: neither channel nor how"
    if has_ch:
        if set(row) != {"ts", "kind", "channel"}:
            return "notice.row.sent_fields: %r" % sorted(row)
        if row["channel"] not in CHANNELS:
            return "notice.row.channel: %r not in %r" % (row["channel"], CHANNELS)
    else:
        if set(row) != {"ts", "kind", "how"}:
            return "notice.row.seen_fields: %r" % sorted(row)
        if row["how"] not in SEEN_HOW:
            return "notice.row.how: %r not in %r" % (row["how"], SEEN_HOW)
    return None


def _iter_rows_raw(root=None):
    """读全部原始行。返回 `(rows, bad)`：`rows=[(lineno, dict)]`、`bad=[{line,why,raw}]`。

    ★ 坏行**不跳过、不修补、不补默认值**：进 `bad` 并带行号。静默丢弃会让
      「账里 300 行读不懂」表现成「这个月没有通知」—— 空值与零混同。
    ★ 文件不存在 ⇒ `([], [])`。「还没发过」和「发过但读不出」必须分得开：
      后者由 `OSError` 抛出，**不许**吞成空。
    """
    p = notice_log_path(root)
    try:
        with open(p, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return [], []
    text = raw.decode("utf-8", "replace")        # 半个汉字也不丢行号
    rows, bad = [], []
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue                              # 空行不是数据，也不是坏行
        try:
            got = json.loads(line)
        except ValueError as e:
            bad.append({"line": i, "why": "notice.row.json: %s" % e, "raw": line[:80]})
            continue
        why = _row_problem(got)
        if why:
            bad.append({"line": i, "why": why, "raw": line[:80]})
            continue
        rows.append((i, got))
    return rows, bad


def iter_rows(root=None):
    """公开入口（负控要能换掉它）。"""
    return _iter_rows_raw(root=root)


def _checked_how(how):
    if not isinstance(how, str) or how not in SEEN_HOW:
        raise ValueError("notice.seen.how: %r not in %r" % (how, SEEN_HOW))
    return how


def _checked_channel(channel):
    if not isinstance(channel, str) or channel not in CHANNELS:
        raise ValueError("notice.sent.channel: %r not in %r" % (channel, CHANNELS))
    return channel


def _checked_kind(kind):
    if not isinstance(kind, str) or not kind.strip():
        raise ValueError("notice.kind: not a non-empty string: %r" % (kind,))
    return kind


def record_sent(kind, channel, now=None, root=None):
    """记一条 `notice_sent` 并返回落盘的那一行。

    写失败**抛 OSError**（由调用方决定怎么报），不假装"已经记上了"。
    """
    k = _checked_kind(kind)
    ch = _checked_channel(channel)
    row = {"ts": _iso(time.time() if now is None else now), "kind": k, "channel": ch}
    p = notice_log_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    _append_line(p, json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return row


def record_seen(kind, how, now=None, root=None):
    """记一条 `notice_seen`。**只能由用户动作调用**（点开＝open／确认＝ack）。

    ★ 这个函数没有"默认 how"。任何上游想"顺手记一条见过"都是猜 —— 抛错。
    """
    k = _checked_kind(kind)
    h = _checked_how(how)
    row = {"ts": _iso(time.time() if now is None else now), "kind": k, "how": h}
    p = notice_log_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    _append_line(p, json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return row


def _age_seconds(sec):
    """发出到现在的秒数。**不钳负数** —— 负数＝时钟回拨／未来时间，是要报出去的事实。

    ★ 钳成 0 会让「算不出」长得像「刚到」，于是永远判 pending、永远不告警。
      抽成函数是为了让负控能换掉同一份实现去证明它承重。
    """
    return float(sec)


def _outcome_strict(kind, now=None, root=None):
    """`kind` 的当前结局。返回 dict（内部真实现，负控不可替换的那一份）。

    `state ∈ absent / unseen / seen`：
      · `absent`  账里没有这个 kind 的发出行（没发过 ⇒ 谈不上送达）
      · `seen`    **最后一个 sent 之后**有 seen 行（见了之后又发一次，第二次仍未见）
      · `unseen`  有 sent，其后没有 seen
    """
    rows, bad = iter_rows(root=root)
    mine = [(n, r) for n, r in rows if r.get("kind") == kind]
    sent = [(n, r) for n, r in mine if "channel" in r]
    if not sent:
        return {"state": "absent", "sent_ts": None, "channel": "", "age": None,
                "sent_line": None, "seen_line": None, "bad": bad}
    n_sent, r_sent = sent[-1]
    seen = [(n, r) for n, r in mine if "how" in r and n > n_sent]
    t = _parse_ts(r_sent["ts"])
    now_t = _dt.datetime.fromtimestamp(
        float(time.time() if now is None else now)).astimezone()
    age = _age_seconds((now_t - t).total_seconds()) if t is not None else None
    return {"state": "seen" if seen else "unseen",
            "sent_ts": r_sent["ts"], "channel": r_sent.get("channel", ""),
            "age": age, "sent_line": n_sent,
            "seen_line": (seen[-1][0] if seen else None), "bad": bad}


def outcome_of(kind, now=None, root=None):
    """公开入口（负控要能换掉它）。"""
    return _outcome_strict(kind, now=now, root=root)


def chain_scan(kind, audit_dir, now=None):
    """当日链里是否已有同 kind 的 `delivery_unknown`。

    返回三值，**不是两值**：
      `True`  已记过 ⇒ 不重复记（daemon 每 10 分钟一拍，不去重就是每天几十条脏账）
      `False` 确知没记过
      `None`  **读不到**（目录不存在／读失败／有读不懂的行）⇒ 调用方必须报
              undecidable，**不许当成"没记过"** —— 那会重复写。
    """
    if not audit_dir or not os.path.isdir(audit_dir):
        return None
    names = sorted(n for n in os.listdir(audit_dir) if n.endswith(".jsonl"))[-2:]
    broken = False
    try:
        for name in names:
            with open(os.path.join(audit_dir, name), "rb") as f:
                for line in f.read().decode("utf-8", "replace").splitlines():
                    if not line.strip():
                        continue
                    try:
                        r = json.loads(line)
                    except ValueError:
                        broken = True
                        continue
                    if isinstance(r, dict) and r.get("type") == "delivery_unknown" \
                            and r.get("kind") == kind:
                        return True
    except OSError:
        return None
    return None if broken else False


def _needs_unknown(headless, downgrade_ok):
    """该不该记「送达未知」：**有通道 ∧ 降级失败**（"已见过"在上游就返回了）。

    ★ 两个条件缺一不可：降级成功不是未知（成功）；无头不是通道坏了（没通道）。
      抽成命名函数，是因为这条规则必须能被负控换掉 —— 内联在 `settle()` 里的话，
      负控只能复制一份来测副本，而副本红 ≠ 线上红。
    """
    if headless:
        return False
    return not downgrade_ok


def _default_audit_dir():
    """本进程包根对应的链目录（引用 `host_shield` 的**唯一实现**，不另拼）。

    取不到返回 `""` —— 下游 `chain_scan("")` 会返回 `None`，于是报 undecidable
    而不是"没记过"。**取不到必须出声**。
    """
    try:
        import host_shield as _hs
        return _hs._shield_audit_dir(os.path.dirname(os.path.abspath(__file__)))
    except Exception:                             # noqa: BLE001
        return ""


def _chain_record(audit_dir, rec):
    """进链，返回四态字符串（`chain`/`sidecar`/`dropped`/`none`）。"""
    try:
        import session_dna
        return session_dna.append_chained(audit_dir, rec)
    except Exception:                             # noqa: BLE001
        return "none"


def _write_unknown(kind, downgrade, minutes, audit_dir=None, record=None):
    """写一条 L1 的 `delivery_unknown`。返回 `(rec, written)`；没落盘时 rec 为 None。

    ★ N12 明写「**不弹泡**」—— 这条记录本身就是"报不达"的证据，再弹一次会递归。
      所以这里**不走** `host_shield.record`（它会进气泡判定），只直接进链。
    """
    rec = {"ts": _iso(time.time()), "type": "delivery_unknown",
           "tool": "-", "session": "daemon", "host": "generic",
           "decision": "allow", "severity": "warning", "reason": "",
           "kind": kind, "downgrade": downgrade,
           "minutes_overdue": int(minutes), "noticed": False}
    d = audit_dir or _default_audit_dir()
    written = record(d, rec) if record is not None else _chain_record(d, rec)
    if written in ("chain", "sidecar"):
        return rec, written
    return None, (written or "none")


def settle(kind, now=None, root=None, downgrade=None, audit_dir=None,
           record=None, scan=None):
    """判 `kind` 的送达结局：返回 `{state, minutes_overdue, downgrade, chain, why}`。

    `state` 域：`absent` / `seen` / `pending` / `headless` / `downgraded` /
    `unknown` / `undecidable` —— **两个"不知道"分开**（`unknown` 是确知没送达，
    `undecidable` 是判不了）。

    判定顺序本身是判据的一部分（先最硬的证据，再推断）：
      没发过 → 已见过 → 时间算不出 → 未到期 → 无通道 → 降级 → 去重 → 记链
    ★ 顺序错了会假绿：先判 headless 再判 seen，就会把"用户看过了的无头场景"
      报成 headless，把最好的证据丢掉。
    """
    now = time.time() if now is None else float(now)
    o = outcome_of(kind, now=now, root=root)
    base = {"state": "", "minutes_overdue": None, "downgrade": None,
            "chain": None, "why": "", "sent_line": o.get("sent_line"),
            "seen_line": o.get("seen_line")}

    if o["state"] == "absent":
        return dict(base, state="absent", why="notice.settle.absent: no sent line")
    if o["state"] == "seen":
        return dict(base, state="seen")
    age = o.get("age")
    if age is None:
        return dict(base, state="undecidable", why="notice.settle.ts: sent ts unreadable")
    if age < 0:
        return dict(base, state="undecidable",
                    why="notice.settle.clock: sent in the future by %.0fs" % -age)
    if age < NOTICE_WINDOW:
        return dict(base, state="pending", minutes_overdue=0)

    minutes = int(age // 60)
    base["minutes_overdue"] = minutes
    headless = o.get("channel") == HEADLESS_CHANNEL
    if headless:
        return dict(base, state="headless",
                    why="notice.settle.headless: no channel, file ledger only")
    if downgrade is None:
        return dict(base, state=NO_DOWNGRADER_STATE,
                    why="notice.settle.downgrade: no downgrader wired")
    try:
        ok, ch = downgrade(kind)
    except Exception as e:                        # noqa: BLE001
        return dict(base, state="undecidable",
                    why="notice.settle.downgrade: %s: %s" % (type(e).__name__, e))
    if ch not in DOWNGRADES:
        return dict(base, state="undecidable",
                    why="notice.settle.downgrade: %r not in %r" % (ch, DOWNGRADES))
    base["downgrade"] = ch
    if not _needs_unknown(headless, bool(ok)):
        return dict(base, state="downgraded")

    seen_already = (scan or chain_scan)(kind, audit_dir or _default_audit_dir(),
                                        now=now)
    if seen_already is None:
        return dict(base, state="undecidable",
                    why="notice.settle.chain: chain unreadable, dedup undecided")
    if seen_already:
        return dict(base, state="unknown",
                    why="notice.settle.dedup: already recorded today")
    rec, written = _write_unknown(kind, ch, minutes,
                                  audit_dir=audit_dir, record=record)
    if rec is None:
        return dict(base, state="unknown",
                    why="notice.settle.write: not persisted (%s)" % written)
    return dict(base, state="unknown", chain=rec)


# --------------------------------------------------------------- 节流 ----
def _throttle_path(root=None):
    return os.path.join(C.console_dir(root), "notify_state.json")


def _load_throttle(root=None):
    try:
        with open(_throttle_path(root), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:                           # noqa: BLE001
        return {}


def _save_throttle(d, root=None):
    p = _throttle_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, p)


def toast(level, title, body, root=None, backend=None, cfg=None,
          now=None, kind=None, min_interval=MIN_INTERVAL, now_min=None):
    """弹一条通知（受节流与免打扰约束）。返回 `(sent: bool, reason: str)`。"""
    cfg = cfg or C.load(root)
    if not C.should_touch(level, cfg, now_min=now_min):
        return False, "该级别不触达 / 免打扰"
    backend = backend if backend is not None else default_backend()
    now = time.time() if now is None else now
    key = kind or level

    th = _load_throttle(root)
    last = th.get(key)
    if isinstance(last, (int, float)) and now - last < min_interval:
        return False, "同类 %d 秒内不重复" % min_interval
    th[key] = now
    _save_throttle(th, root)

    ok = backend.toast(title, body, level)
    if not ok:
        return False, getattr(backend, "last_error", "发送失败")
    # ★ N12：发出即记 `notice_sent`（进程内＋通知账，**不进链**）。
    #   记账失败**不假装成功**：`sent` 仍为 True（确实弹出去了），但把
    #   「账没记上」说进第二返回值 —— 否则送达链对这条通知永久失明。
    note = ""
    try:
        record_sent(key, getattr(backend, "channel", "toast"), now=now, root=root)
    except OSError as e:
        note = "notice.sent.ledger: %s: %s" % (type(e).__name__, e)
    return True, note


# ------------------------------------------------- 节流账本（公开两面）----
def throttle_state(root=None):
    """读**整份**节流账本（0.49.0：冒泡也要在同一本账上记「同类静默」）。

    ★ 为什么不第二个文件：门铃节流与冒泡节流是**同一件事**（同类多久内
      不再响），分两个文件就会出现"toast 记得、冒泡不记得"的漂移。
    ⇒ 文件仍只有一份（`notify_state.json`），这里只把 「读/写某个键」 的能力
      公开出来，冒泡侧不自己开文件。
    """
    return _load_throttle(root)


def throttle_set(key, root=None, now=None):
    """在节流账本上记一个键（门铃/冒泡共用）。原子替换，不删原文件。"""
    d = _load_throttle(root)
    d[str(key)] = float(now if now is not None else time.time())
    _save_throttle(d, root)
    return d
