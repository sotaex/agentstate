# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""外传账本（egress ledger）—— 记录「谁在往哪发」，不记录内容，不判定好坏。

★ 为什么要有这一层（2026-09-26 深度评估的结论，不要凭直觉改）：
  `host-audit` / `host-scan` 的判据是「工具自己写下的外传自认」（`lastAccepted`／`uploadedAt`…）。
  实测同机同刻：扫描给出 **T1 1 ＋ T3 47**（47 个"没查出来"），而 `netstat` 显示
  **≥8 个 AI 工具正在往外发** ⇒ 「没查到」几乎零信息量。
  而**会偷数据的工具不会写自认字段**。

  ⇒ 数据要离开这台机器，**必然产生网络连接**。出口层是唯一一层瞒不住的：
    · sidecar 直传（ZCode 的 31 个 agent 工具里没有 upload，是 host 级 sidecar 干的）；
    · 子进程外传、内存直传、QUIC、借道第三方 SDK；
    这些在"工具内部"全看不见，在出口层全都现形。

★★ 设计纪律（改这个文件前必读三条）：
  1. **只记录事实，不下结论。** 判定引擎要靠调参压误报 ⇒ 调参是无底洞 ⇒ 迭代爆炸。
     本模块输出「值得看」＋原样证据，**判断权交给用户**。
     （AI 工具正常工作时本来就在往外发 —— 有连接 ≠ 有问题。）
  2. **不维护厂商/域名清单。** 前车之鉴：24 个登记表只有 1 个 watch 非空 ——
     任何要人工登记的机制最后都会烂尾。这里**没有白名单**，只有客观特征。
  3. **拿不到的就说拿不到。** 字节数（要驱动/ETW）、内容（加密）一律如实写进边界段，
     不许用"疑似/可能"糊过去。

平台：第一版 **仅 Windows**（`netstat`／`tasklist`／`GetLastInputInfo`）。
依赖：**纯标准库**，零第三方。
"""

import ctypes
import json
import os
import re
import shutil
import socket
import subprocess
import time

# ★★ 0.35.3（创始人报障：窗口不停弹出又马上关掉）：
#   本模块的 `netstat` / `tasklist` 由**哨兵**每 30 秒各起一次（SAMPLE_EVERY_N_TICKS），
#   而哨兵自己是 DETACHED_PROCESS（无控制台）⇒ 起控制台程序若不显式
#   `CREATE_NO_WINDOW`，Windows 会为子进程新建控制台 = 黑窗一闪，30 秒一次，一直闪。
#   非 Windows 上该参数必须为 0，否则 ValueError。
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# ★ 厂商词表的唯一真源。`antinel.py` 的 `_SCAN_VENDOR_KW` 从这里导入 ——
#   复制一份必然漂移（本仓已因"两处同一判据"反复踩坑），所以共用同一份。
#   目录名／进程名命中即用，全部小写比对、忽略前导点。
VENDOR_KW = (
    "zcode", "claude", "anthropic", "codex", "openai", "gemini", "qoder",
    "trae", "cursor", "copilot", "lingma", "tongyi", "mimicode", "mimo",
    "qwen", "qianwen", "kimi", "moonshot", "workbuddy", "codebuddy",
    "openclaw", "autoclaw", "clawkeeper", "genie", "tabbit", "ichat",
    "doubao", "yuanbao", "aider", "continue", "cline", "roo", "windsurf",
    "codeium", "kilo", "augment", "devin", "perplexity", "grok", "deepseek",
    "zhipu", "minimax", "stepfun", "ollama", "lmstudio", "dify", "coze",
    "agents",
)

# ---------------------------------------------------------------- 常量
# ★ 哨兵 POLL_SECONDS = 2（host_shield），而实测 `netstat -ano` 解析要 207–269 ms
#   ⇒ 每拍都采会吃掉约 12% 的时间片。节流到 15 拍 ≈ 30 秒一次（实测占 ~0.4%）。
SAMPLE_EVERY_N_TICKS = 15

IDLE_MIN = 600.0                 # 判据①：用户空闲 ≥ 10 分钟才算"没在用"
IDLE_NEW_MIN = 3                 # 判据①：空闲期内新建连接 ≥ 3 条才报
LONG_CONN_MIN = 180.0            # 判据②：单条连接 ≥ 3 分钟
LONG_CONN_RATIO = 6.0            # 判据②：且 ≥ 该进程自身时长中位的 6 倍
MIN_SAMPLES_FOR_MEDIAN = 5       # 判据②：样本 < 5 条不下结论（不许拿 2 条数据判人）
LEDGER_DAYS = 7                  # 报告默认回看天数
RESOLVE_TIMEOUT = 1.5            # 反解超时（秒）；反解本身会发 DNS 查询，要能关

# ---------------------------------------------------------------- 保留策略
# ★★ 2026-10-22（40 格 · 空间·挡）：**这一格是唯一随时间必然恶化的一格**。
#   实测：`~/.antinel/egress` 25 天 84 MB（最坏一天 20 MB / 22237 条事件），
#   而当时**零保留策略**。没有上界 ⇒ 迟早写满 ⇒ 写失败 ⇒ 账本静默断档
#   ⇒ 其余所有判定都跟着失去证据。所以本组常量不是"优化参数"，是**上界**：
#     ① 按天保留：够覆盖报告窗口（7 天）的两倍，多出来的天数没有消费方；
#     ② 按总量保留：一天就能到 20 MB，只按天数留会到 280 MB ⇒ 必须还有字节闸；
#     ③ 磁盘剩余闸：账本不能把宿主的盘吃掉 —— 这是"观测者不许成为事故"。
KEEP_DAYS = 14                              # 事件文件按天保留上限
MAX_DIR_BYTES = 48 * 1024 * 1024            # 账本目录总量上限（48 MB）
MIN_FREE_BYTES = 64 * 1024 * 1024           # 磁盘剩余低于 64 MB ⇒ 写前先腾
DISK_WARN_PCT = 0.85                        # 磁盘占用 ≥ 85% ⇒ 记一条 disk_pressure
EVENT_PREFIX = "events-"
EVENT_SUFFIX = ".jsonl"
_EVENT_DAY_RE = re.compile(r"^events-(\d{4}-\d{2}-\d{2})\.jsonl$")

# 对象存储型目的地（判据③）。★ 这是**特征**不是白名单：命中只标"值得看"，不说"这是偷"
OBJECT_STORE_SUFFIX = (
    ".aliyuncs.com", ".amazonaws.com", ".r2.cloudflarestorage.com", ".r2.dev",
    ".blob.core.windows.net", ".myqcloud.com", ".cos.ap-", ".oss-", ".s3.",
    ".storage.googleapis.com",
)

_NETSTAT_RE = re.compile(
    r"\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\S+)?\s*(\d+)\s*$")
_TASKLIST_RE = re.compile(r'"([^"]+)","(\d+)"')


# ---------------------------------------------------------------- 基础设施
def ledger_dir():
    """账本目录：`~/.antinel/egress/`。失败返回 None（**不猜、不静默**）。"""
    try:
        p = os.path.join(os.path.expanduser("~"), ".antinel", "egress")
        os.makedirs(p, exist_ok=True)
        return p
    except OSError:
        return None


def is_windows():
    return os.name == "nt"


# ---------------------------------------------------------------- 采集
def idle_seconds():
    """用户多久没碰键鼠（秒）。`GetLastInputInfo` —— 零依赖 ctypes。

    ★ 这是判据①的基础：知道"用户没在用它"，才能说"它在自己动"。
    失败返回 None —— 拿不到就说拿不到，不许当作 0（那会变成"用户一直在操作"）。
    """
    if not is_windows():
        return None
    try:
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint32)]
        li = LASTINPUTINFO()
        li.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(li)):
            return None
        return (ctypes.windll.kernel32.GetTickCount() - li.dwTime) / 1000.0
    except Exception:
        return None


def parse_netstat():
    """解析 `netstat -ano`。返回 [(proto, local, remote, state, pid)]。

    ★ 实测：3185 行 → 57 条 ESTABLISHED，解析 207–269 ms。
    失败返回 None（区别于"解析成功但为空"）。
    """
    try:
        r = subprocess.run(["netstat", "-ano"], capture_output=True, timeout=30,
                           creationflags=_CREATE_NO_WINDOW)
    except Exception:
        return None
    if r.returncode != 0 and not (r.stdout or b""):
        return None
    out = (r.stdout or b"").decode("gbk", "replace")
    rows = []
    for line in out.splitlines():
        m = _NETSTAT_RE.match(line)
        if not m:
            continue
        proto, local, remote, state, pid = m.groups()
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        rows.append((proto, local, remote, state or "", pid))
    return rows


def is_external(remote):
    """排除回环／局域网／本机。只关心"出这台机器"的连接。"""
    s = (remote or "").strip()
    if not s:
        return False
    if s.startswith("["):                      # IPv6
        ip = s[1:].split("]")[0].lower()
        return not (ip == "::1" or ip.startswith("fe80")
                    or ip.startswith("fd") or ip.startswith("::"))
    ip = s.rsplit(":", 1)[0] if ":" in s else s
    if ip in ("127.0.0.1", "0.0.0.0") or ip.startswith("0."):
        return False
    if ip.startswith("10.") or ip.startswith("192.168."):
        return False
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return False
    return True


def proc_map():
    """pid → 进程名（`tasklist`）。失败返回空 dict —— 显示时退回 `pid:<n>`，不猜。"""
    try:
        r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                           capture_output=True, timeout=30,
                           creationflags=_CREATE_NO_WINDOW)
    except Exception:
        return {}
    out = (r.stdout or b"").decode("gbk", "replace")
    m = {}
    for line in out.splitlines():
        g = _TASKLIST_RE.match(line.strip())
        if g:
            try:
                m[int(g.group(2))] = g.group(1)
            except ValueError:
                pass
    return m


def is_ai(name):
    """进程名是否像 AI 工具。命中返回 True／False（None 只在 name 为空时）。"""
    if not name:
        return None
    n = name.lower()
    if n.endswith(".exe"):
        n = n[:-4]
    n = n.lstrip(".")
    return any(k in n for k in VENDOR_KW)


def conn_key(c):
    """连接的稳定标识。★ 实测：两次采样 57／58 条、交集 56 条 ⇒ 这个 key 够用。"""
    proto, local, remote, _state, pid = c
    return "%s|%s|%s|%d" % (proto, local, remote, pid)


def sample(ai_only=True):
    """一次采样。

    返回 dict：`{"ts":…, "idle":…|None, "conns":[{key,proc,pid,remote,proto}], "ok":bool}`。
    ★ 只存进程名/PID/远端地址/时间 —— **不存任何载荷、命令行、URL 路径**
      （与"只记哈希不记内容"同一条隐私纪律）。
    """
    rows = parse_netstat()
    out = {"ts": time.time(), "idle": idle_seconds(), "conns": [], "ok": rows is not None}
    if rows is None:
        return out
    pm = proc_map()
    for c in rows:
        proto, local, remote, state, pid = c
        if state.upper() != "ESTABLISHED":
            continue
        if not is_external(remote):
            continue
        proc = pm.get(pid) or ("pid:%d" % pid)
        if ai_only and not is_ai(proc):
            continue
        out["conns"].append({
            "key": conn_key(c), "proc": proc, "pid": pid,
            "remote": remote, "proto": proto,
        })
    return out


# ---------------------------------------------------------------- 账本读写
def _path(name):
    d = ledger_dir()
    return os.path.join(d, name) if d else None


def _events_path(day=None):
    d = ledger_dir()
    if not d:
        return None
    day = day or time.strftime("%Y-%m-%d")
    return os.path.join(d, "events-%s.jsonl" % day)


def _day_of(name):
    """`events-2026-10-08.jsonl` → `2026-10-08`；不是事件文件 ⇒ None。"""
    m = _EVENT_DAY_RE.match(name or "")
    return m.group(1) if m else None


def dir_stats():
    """账本目录的**实测**占用：`{"bytes":…, "files":…, "event_files":…, "days":[…], "readable":…}`。

    ★ 只数真的在盘上的字节（`st_size`），不按"记录了多久"估 ——
      估出来的体积正是"必然恶化"那种格子最容易骗自己的地方。
    ★ 目录不存在/读不到 ⇒ `bytes=0, files=0, days=[], readable=False`。
      **可读性是独立字段**：0 字节和"读不到"是两件事（同仓 null≠0≠[] 纪律）。
    ★★ `event_files` 与 `files` 分开（40 格 · 空间·看，A9）：
      `files` 是全目录（含 `lost.json`／`current.json`／`disk_warn.json`／残留 `.tmp`），
      而用户在意的"账本有几个文件"只该数 `events-YYYY-MM-DD.jsonl`。
      旧口径把两者混成一个数 ⇒ 上屏「账本 6 个文件」而其中 4 个不是账本。
    """
    d = ledger_dir()
    out = {"bytes": 0, "files": 0, "event_files": 0, "days": [], "readable": False}
    if not d:
        return out
    try:
        names = os.listdir(d)
    except OSError:
        return out
    out["readable"] = True
    for name in names:
        p = os.path.join(d, name)
        try:
            sz = os.path.getsize(p)
        except OSError:
            continue
        out["files"] += 1
        out["bytes"] += sz
        day = _day_of(name)
        if day:
            out["event_files"] += 1
            out["days"].append((day, name, sz))
    out["days"].sort()                     # 最老在前（删除顺序＝这个顺序）
    return out


def capacity():
    """磁盘与账本目录的现状。**拿不到就说拿不到**（返回 None，不猜 100%）。"""
    d = ledger_dir()
    if not d:
        return None
    try:
        u = shutil.disk_usage(d)
    except OSError:
        return None
    ds = dir_stats()
    used_pct = (float(u.used) / u.total) if u.total else None
    return {
        "total": u.total, "free": u.free, "used_pct": used_pct,
        "low_free": u.free < MIN_FREE_BYTES,
        "dir_bytes": ds["bytes"], "dir_files": ds["files"],
        "dir_event_files": ds["event_files"],
        "dir_full": ds["bytes"] >= MAX_DIR_BYTES,
        "readable": ds["readable"],
    }


def _keep_target(n_present, have_today, keep=KEEP_DAYS):
    """保留策略的目标：**现存**事件文件应剩几个（今天那份若还没落盘，要少留一格）。

    ★ 抽成函数的理由同 `_merge_lost`：负控要换掉同一份实现
      （`_keep_target = lambda n, h, keep=KEEP_DAYS: keep` 就复现了旧抖动）。
    ★ 为什么必须预留：`tick()`／`run()` 都在**当天第一次写之前**跑保留策略
      ⇒ 每天早晨都是"今天不存在"这条腿。不预留，那天就多留一天（实测 15 vs 14）。
    """
    return int(keep) - (0 if have_today else 1)


def enforce_retention(today=None, force=False):
    """按「天数」与「总量」两条上界清掉最老的事件文件。**幂等**。

    返回 `{"removed":[names], "bytes":n, "why":"days|bytes|", "failed":[names]}`。

    ★★ 三条纪律（这张表是安全产品的证据账本，不是日志）：
      ① **先记账，后删除**：留一条 `rotated` 事件（删了哪几个、多少字节、为什么），
         否则"证据变少了"这件事本身没有证据。
      ② **今天这个文件永不删**：正在追加的文件被删/被改名，会把当前采样写丢。
      ③ **删不掉不静默**：`failed` 如实返回，由调用方决定要不要上屏。
    ★ 为什么不用"把老文件挪去 archive/"：那只是把同一个字节数换个目录放，
      不解决"必然恶化"，还会让体积统计看不到它 —— 假减法。

    ★★ `force` 的唯一用途：**写已经失败了**（`_append` 第②段）。
      那种时刻"先记账"会变成死锁 —— 账写不进 ⇒ 不删 ⇒ 永远腾不出空间。
      磁盘满时**删是唯一能救活的动作**，账让路：记账落到内存 `_ROT_NOTE`，
      下一次写成功时补（`_flush_lost` 负责）。平时（`force=False`）账写不进就不删。
    """
    d = ledger_dir()
    if not d:
        return {"removed": [], "bytes": 0, "why": "", "failed": []}
    today = today or time.strftime("%Y-%m-%d")
    ds = dir_stats()
    days = [x for x in ds["days"] if x[0] != today]
    # ★★ 口径必须与"删除池"对齐（2026-10-22 实测的抖动）：
    #   删除池 `days` 排除了今天，而天数上界原先用的是**含今天**的自然天数 ⇒
    #   两处口径不同，于是"今天那份在不在"给出两个答案：在 ⇒ 留 14 天，
    #   不在 ⇒ 留 15 天（实测 14/15 不齐）。
    #   而 `tick()`／`run()` 都在**当天第一次写之前**跑这里 ⇒ 每天早晨都走
    #   "今天不存在"那条腿。⇒ 统一为"删完后该目录里事件文件数（含今天，
    #   若将落盘）≤ KEEP_DAYS"：现存应剩几个由 `_keep_target()` 给出，
    #   `n_days` 从此**只表示现存的日文件数**。
    have_today = any(x[0] == today for x in ds["days"])
    n_days = len(ds["days"])
    target = _keep_target(n_days, have_today)
    # ★ 预算要把**非事件文件**（current.json/lost.json/disk_warn.json…）和
    #   **即将写的那条 rotated 账**先扣掉。不扣的话实测会"删完仍超 123 字节"——
    #   上限是硬的，账本身也在吃预算（这是本轮实测踩到的，不是假想）。
    total = sum(x[2] for x in ds["days"])
    budget = MAX_DIR_BYTES - (ds["bytes"] - total) - 512
    victims, why = [], ""
    # ① 天数上界
    # ★ 每删一个必须同步扣 `total` —— 否则第二段会拿**没扣过的**总量再判一次，
    #   同一批文件被算两遍，实测多删 7 天（2026-10-22 在真实账本上踩到：
    #   应删 10 天，实删 17 天）。两条腿是"任一超限就删"，不是"两条各删一遍"。
    while n_days > target and days:
        item = days.pop(0)
        victims.append(item)
        total -= item[2]
        n_days -= 1
        why = "days"
    # ② 总量上界（天数已合规但体积仍超 ⇒ 继续从最老的删）
    for item in list(days):
        if total <= budget:
            break
        victims.append(item)
        total -= item[2]
        why = why or "bytes"
    if not victims:
        return {"removed": [], "bytes": 0, "why": "", "failed": []}
    # ① 先记账（写在今天的文件里）；平时刻写不进就不删
    note = {"t": time.time(), "e": "rotated",
            "n": len(victims), "bytes": sum(v[2] for v in victims),
            "why": why, "days": [v[0] for v in victims][:64]}
    if not _write_line(_events_path(today), note):
        if not force:
            return {"removed": [], "bytes": 0, "why": why,
                    "failed": [v[1] for v in victims]}
        _ROT_NOTE.append(note)          # 账让路：删完继续救火，账下次补
    removed, failed, freed = [], [], 0
    for day, name, sz in victims:
        try:
            os.remove(os.path.join(d, name))
            removed.append(name)
            freed += sz
        except OSError:
            failed.append(name)
    return {"removed": removed, "bytes": freed, "why": why, "failed": failed}



# ---------------------------------------------------------------- 写失败记账
#: ★★ N3（空间·报）：写失败**跨进程不可见** —— 磁盘满时盘上当然没有痕迹，
#:   另一个进程（甚至自己重启后）无从得知"那段时间丢了几条"。
#:   唯一出路是**下一次写成功时补一条**：「此前有 N 条没能写入（首条 ts=…）」。
#:   ⇒ 两条腿：能落盘就落盘（`lost.json`，几十字节，通常还写得进），
#:     落盘也失败就记在内存（进程内仍能补）。两处都在时取**和**。
#: ★ 允许重复补：清零那一步若也失败，下次会再补一遍（数字偏大）。
#:   口径：**宁可多记，不许少记** —— 少记等于替一次丢失撒谎。
_LOST = {"n": 0, "first": None, "last": None}

#: 磁盘满时"删了但账没写进"的 rotated 事件（见 `enforce_retention(force=True)`）。
#: 下一次能写的时候由 `_flush_lost` 补出去 —— 删账这件事**也必须**有账。
_ROT_NOTE = []

#: `_append` 多久查一次盘上的 `lost.json`（A13）。见 `_append` 里的说明。
_PROBE_EVERY = 32
_ASK = {"tick": 0}
#: 盘上的 `lost.json` 是否**可能**非零。
#: ★★ 为什么不能只看内存（P25 当场抓到的真 bug）：
#:   磁盘满时 `_note_lost` 会**落盘成功**（`lost.json` 只有几十字节，通常还写得进）
#:   然后才把内存清零 ⇒ 内存 0、盘上 1。此时"内存非空才查盘"的优化让
#:   **下次写永远不查盘**，那一条丢失就再也补不上（P25 实测：账本里没有 lost 事件）。
#:   进程启动时置 True：未知就得先查一次。
_DISK_DIRTY = {"v": True}


def _write_line(path, obj):
    """append 一行 JSON。返回 True/False（不抛）。**这是唯一真正的写入口。**"""
    if not path:
        return False
    try:
        with open(path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
        return True
    except OSError:
        return False


def _merge_lost(disk_n, mem_n):
    """丢失条数的**唯一合并点**：盘上一份 ＋ 内存一份。

    ★ 抽成函数不是为了好看，是为了让判据的负控能换掉**同一份实现**
      （`_merge_lost = lambda a, b: int(a) + 1` 就复现了旧的少记行为）。
      规则内联时，负控只能复制整段代码，那测的是副本。
    ★ 口径：**宁可多记，不许少记**。只取一边即"替一次丢失撒谎"。
    """
    return int(disk_n) + int(mem_n)


def _note_lost(now=None):
    """记一次写失败。落盘优先，落不了记内存。

    ★★ 必须把**盘上**与**内存**两边加起来写盘（2026-10-22 实测的真 bug）：
      旧实现写的是"盘上 n + 1"，内存里那几条**从没并进去**，而写成功就把内存清零
      ⇒ 磁盘满期间丢 3 条、恢复后再丢 1 条，`lost_pending()` 报 **1**（真值 4），
      连"最早起点"都退成了最晚那条。
      这直接违反本文件自己写的口径「宁可多记，不许少记」——
      **少记等于替一次丢失撒谎**，而丢失记账正是"那段时间没记上"的唯一证据。
    ★ `first` 取更早的那个（`or` 的求值顺序就是优先级：盘上的算"更早"）。
    """
    now = now or time.time()
    _LOST["n"] += 1
    _LOST["first"] = _LOST["first"] or now
    _LOST["last"] = now
    cur = _read_json("lost.json", {}) or {}
    try:
        n = int(cur.get("n") or 0)
    except (TypeError, ValueError):
        n = 0
    total = _merge_lost(n, _LOST["n"])          # ★ 两处都在时取和，不许只写一边
    first = cur.get("first") or _LOST["first"]
    if _write_json("lost.json", {"n": total, "first": first, "last": now}):
        _DISK_DIRTY["v"] = True             # 盘上还有待补的条数 ⇒ 下次必须查盘
        _LOST["n"], _LOST["first"], _LOST["last"] = 0, None, None
    else:
        _DISK_DIRTY["v"] = True             # 落盘失败 ⇒ 内存那份就是唯一证据


def lost_pending():
    """还没补记的丢失条数 `(n, first, last)`。盘上一份＋内存一份。"""
    disk = _read_json("lost.json", {}) or {}
    try:
        dn = int(disk.get("n") or 0)
    except (TypeError, ValueError):
        dn = 0
    return (dn + _LOST["n"],
            disk.get("first") or _LOST["first"],
            disk.get("last") or _LOST["last"])


def _flush_lost(path):
    """把待补的丢失补成一条 `lost` 事件。成功才清零（失败 ⇒ 留着下次再补）。

    ★ 顺序：先补 `rotated`（"删了什么"），再补 `lost`（"丢了几条"）。
      反过来会让读者以为"先丢了 N 条，后来才轮转"，因果颠倒。
    """
    while _ROT_NOTE:
        if not _write_line(path, _ROT_NOTE[0]):
            return False
        _ROT_NOTE.pop(0)
    n, first, last = lost_pending()
    if n <= 0:
        _DISK_DIRTY["v"] = False            # 盘上也是清白的 ⇒ 不必再查
        return True
    if not _write_line(path, {"t": time.time(), "e": "lost", "n": int(n),
                              "first": first, "last": last}):
        _DISK_DIRTY["v"] = True
        return False
    _LOST["n"], _LOST["first"], _LOST["last"] = 0, None, None
    if not _write_json("lost.json", {"n": 0}):
        # 清零失败 ⇒ 下次会重复补一遍（见 _LOST 上方的口径）
        _DISK_DIRTY["v"] = True
        return True
    _DISK_DIRTY["v"] = False
    return True


def _disk_pressure_once(cap):
    """磁盘/账本接近上限时记一条 `disk_pressure`。**一天最多一条**（否则就是噪音）。"""
    if not cap:
        return False
    hit_disk = cap.get("used_pct") is not None and cap["used_pct"] >= DISK_WARN_PCT
    hit_dir = bool(cap.get("dir_full"))
    if not (hit_disk or hit_dir):
        return False
    day = time.strftime("%Y-%m-%d")
    mark = _read_json("disk_warn.json", {}) or {}
    if mark.get("day") == day:
        return False
    rec = {"t": time.time(), "e": "disk_pressure", "day": day,
           "used_pct": round(cap["used_pct"], 4) if cap.get("used_pct") is not None else None,
           "free_mb": round(cap["free"] / 1048576.0, 1),
           "dir_mb": round(cap["dir_bytes"] / 1048576.0, 1),
           "dir_full": bool(cap.get("dir_full"))}
    # ★★ 必须走 `_append`（A11）：它自带三段式（补旧账 → 写 → 腾空间重试 →
    #   仍失败记 lost）。旧的 `_write_line` 是一根"写不进去就当没发生"的裸管：
    #   磁盘吃紧这条事件本身写丢了，既不重试、也不进丢失计数 ——
    #   **恰恰在最该留下痕迹的时刻什么都不留**。
    if not _append(rec):
        return False
    _write_json("disk_warn.json", {"day": day})
    return True



def _append(ev):
    """append-only 写一条事件。★ 采样失败也要写（`e:"sample_failed"`）——
    否则"没采样"会被当成"没问题"（仓库第 ④ 条判据："没查"不许伪装成"没发现"）。

    ★★ 2026-10-22（空间·挡）：这里从"打开-写-失败就 False"改成三段：
      ① **先补旧账**：把上一轮没写进去的条数补成一条 `lost`（写成功才补事件，见 `_flush_lost`）；
      ② **写**：真失败（磁盘满/被拒）⇒ **当场腾空间再试一次** —— 这才是"挡在后果之前"，
         "等下次采样"时那一次的事实已经没了；
      ③ **仍失败** ⇒ 记账（`_note_lost`）并返回 False。**绝不在失败时返回 True**
         （BL-02 的方向错就是"写失败报成功"）。
    """
    p = _events_path()
    if not p:
        return False
    # ★ 不必每次写都读一遍 `lost.json`（A13）：`_flush_lost` 内部要读盘，而
    #   `tick()` 里每条 `new`/`gone` 都走一次这里 —— 连接多时是纯浪费。
    #   内存里有待补、或有"删了但账没写进"的 rotated 事件、或到了探测周期，
    #   才走完整流程。**不能只看内存**：上一个进程留下的 `lost.json` 只在查盘时
    #   才发现，永不查 ⇒ 永不补（那才是真的把丢失藏起来）。所以内存之外还要看
    #   `_DISK_DIRTY`（盘上可能非零）与周期探测 —— 这一条是 P25 当场抓出来的：
    #   第一版只看内存，磁盘满时"落盘成功、内存清零"⇒ 那一条丢失再也没补上。
    if _ROT_NOTE or _LOST["n"] or _DISK_DIRTY["v"] or _ASK["tick"] <= 0:
        _flush_lost(p)
    _ASK["tick"] = _PROBE_EVERY if _ASK["tick"] <= 0 else _ASK["tick"] - 1
    if _write_line(p, ev):
        return True
    # ② 腾空间：按天/按总量清最老的文件（今天的不动），再试一次
    #    `force=True`：此刻写已经失败，"先记账再删"会死锁（账也写不进）。
    try:
        enforce_retention(force=True)
    except Exception:
        pass
    if _write_line(p, ev):
        return True
    # ③ 记账：这一次的事实没进账本，必须能被下一次写成功时看见
    _note_lost(ev.get("t") or time.time())
    return False



def _read_json(name, default):
    p = _path(name)
    if not p or not os.path.isfile(p):
        return default
    try:
        # ★ 显式 with（A10）：`json.load(open(…))` 靠 CPython 引用计数即刻回收，
        #   换解释器（PyPy）或出异常时句柄会积；Windows 上未关句柄还会让
        #   `os.replace` 失败 —— 而 `os.replace` 正是本文件所有原子写的地基。
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _write_json(name, obj):
    p = _path(name)
    if not p:
        return False
    try:
        # ★ 临时名带 pid（A10）：固定 `p + ".tmp"` 时，两个进程同写 `lost.json`
        #   会互踩同一个临时文件，`os.replace` 可能搬走"半个 JSON"。
        #   残留的 `.tmp` 不清理：它不是事件文件，`enforce_retention` 不碰它，
        #   但会被 `dir_stats.bytes` 计入预算（占空间是事实，不该假装没占）。
        tmp = "%s.%d.tmp" % (p, os.getpid())
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, ensure_ascii=False)
        os.replace(tmp, p)
        return True
    except OSError:
        return False


def housekeep():
    """每次采样前的一次自维护：保留策略 + 容量观测。返回实测结果（便于判据）。

    ★ 为什么必须有这一步（40 格 · 空间·挡/看）：账本是**一直在长**的东西，
      而它的上界只有在有人执行时才存在。以前没有任何调用方 ⇒ 84 MB 无上界。
    ★ 顺序：先轮转（腾出空间），再观测（看到的是轮转后的真实值）。
    ★ 全部失败都不抛：维护动作绝不能拖死哨兵；失败由 `capacity()` 的字段与
      `_append` 的 lost 记账两条腿暴露，不靠异常。
    """
    rot = {"removed": [], "bytes": 0, "why": "", "failed": []}
    try:
        rot = enforce_retention()
    except Exception:
        pass
    cap = None
    try:
        cap = capacity()
        _disk_pressure_once(cap)
    except Exception:
        cap = None
    return {"rotation": rot, "capacity": cap}


def tick():
    """哨兵每 N 拍调一次：采样 → 与上一拍比对 → 记 new/gone → 覆盖写当前表。

    ★ 返回的 bool 只表示"这一步自己跑完没有"，不代表"有没有可疑"。
    ★ 调用方必须 try 包住 —— 采样绝不能拖死哨兵。
    """
    housekeep()
    s = sample()
    if not s.get("ok"):
        _append({"t": s["ts"], "e": "sample_failed", "idle": s.get("idle")})
        return False

    now = s["ts"]
    idle = s.get("idle")
    cur = _read_json("current.json", {})
    seen = {}
    for c in s["conns"]:
        k = c["key"]
        seen[k] = {"first": cur.get(k, {}).get("first", now), "last": now,
                   "proc": c["proc"], "pid": c["pid"], "remote": c["remote"],
                   "proto": c["proto"]}
        if k not in cur:
            _append({"t": now, "e": "new", "k": k, "p": c["proc"],
                     "pid": c["pid"], "r": c["remote"], "proto": c["proto"],
                     "idle": idle})
    for k, v in cur.items():
        if k not in seen:
            _append({"t": now, "e": "gone", "k": k, "p": v.get("proc"),
                     "r": v.get("remote"),
                     "dur": round(now - (v.get("last") or now), 1)})
    _write_json("current.json", seen)
    return True


def load_events(days=LEDGER_DAYS):
    """读最近 N 天的事件；同时返回**实际**有多少天有数据（不假装满 N 天）。"""
    d = ledger_dir()
    evs = []
    days_with = 0
    if not d:
        return evs, 0
    for i in range(days):
        day = time.strftime("%Y-%m-%d", time.localtime(time.time() - i * 86400))
        p = _events_path(day)
        if not p or not os.path.isfile(p):
            continue
        n = 0
        try:
            # ★ 显式 with（A10）：见 `_read_json` 的说明。
            with open(p, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evs.append(json.loads(line))
                        n += 1
                    except ValueError:
                        pass
        except OSError:
            pass
        if n:
            days_with += 1
    evs.sort(key=lambda e: e.get("t") or 0)
    return evs, days_with


# ---------------------------------------------------------------- 判据
def _median(xs):
    xs = sorted(xs)
    if not xs:
        return None
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2.0


def resolve_host(ip, cache):
    """反解域名（带缓存、可超时）。失败返回 None —— 显示 IP 即可，不猜。"""
    if ip in cache:
        return cache[ip]
    try:
        socket.setdefaulttimeout(RESOLVE_TIMEOUT)
        h = socket.gethostbyaddr(ip)[0]
    except Exception:
        h = None
    cache[ip] = h
    return h


def _spans(evs, current, now=None):
    """重建每条连接的生命周期：key → {p(进程), r(远端), first, last}。

    ★ 单一真源：`analyze()` 的判据② 与 `render()` 的「最长」列**都从这里取**。
      不许各自再实现一遍 —— 复制一份必然漂移（本仓已为「两处同一判据」付过四次学费）。
    """
    now = now or time.time()
    spans = {}
    for e in evs:
        if e.get("e") == "new":
            spans.setdefault(e.get("k"), {"p": e.get("p"), "r": e.get("r"),
                                          "first": e.get("t") or now})
        elif e.get("e") == "gone":
            sp = spans.setdefault(e.get("k"), {"p": e.get("p"), "r": e.get("r"),
                                               "first": (e.get("t") or now) - (e.get("dur") or 0)})
            sp["last"] = e.get("t") or now
    for k, v in (current or {}).items():
        sp = spans.setdefault(k, {"p": v.get("proc"), "r": v.get("remote"),
                                  "first": v.get("first") or now})
        sp["last"] = now
    return spans, now


def _proc_longest(spans, now=None):
    """每个进程的最长连接时长（秒）。**只给事实，不下结论** —— 样本不足也照给。

    ★ 为什么必须算出来而不是留空：表头写着「最长」却永远空着，读者会读成
      "没有长连接" —— 那是把「没算」伪装成「没发现」（仓库第 ④ 条判据）。
      真值（哪怕是 3 秒）永远优于一个看起来像结论的空白。
    """
    now = now or time.time()
    by = {}
    for _k, sp in spans.items():
        p = sp.get("p") or "?"
        d = max(0.0, (sp.get("last") or now) - (sp.get("first") or now))
        if p not in by or d > by[p]:
            by[p] = d
    return by


def analyze(evs, current, days_with, do_resolve=True, pending_lost=0):
    """三条判据。全部**只标"值得看"**，每条附原样证据 + 一句可自行否掉的话。

    返回 list[dict]：`{"kind":…, "lines":[…]}`。

    ★ 2026-10-22 加了 ④账本断档 ⑤磁盘吃紧 —— 它们是**账本自己**的异常。
      观测者出问题时最容易被漏掉：数据还在、只是少了，看起来一切正常。
    """
    out = []
    now = time.time()
    cache = {}

    # ① 空闲期外连：采样时记录的 idle 与"新建"事件同帧 ⇒ 直接按 idle 分组
    idle_new = {}
    for e in evs:
        if e.get("e") == "new" and (e.get("idle") or 0) >= IDLE_MIN:
            idle_new.setdefault(e.get("p") or "?", []).append(e)
    for proc, lst in sorted(idle_new.items(), key=lambda x: -len(x[1])):
        if len(lst) >= IDLE_NEW_MIN:
            idle_max = max((x.get("idle") or 0) for x in lst)
            out.append({
                "kind": "空闲期外连",
                "lines": [
                    "你已空闲 %s；这期间 %s 新建 %d 条外部连接"
                    % (_fmt_dur(idle_max), proc, len(lst)),
                    "远端：" + ", ".join(sorted({x.get("r") or "?" for x in lst})[:4]),
                    "→ 若是你主动发起的任务或后台更新，忽略即可。",
                ]})

    # ② 长连接：用 current（在连的）＋ events（已断的）重建每条连接的时长
    # ★ 重建抽到 `_spans()`，与 render() 的「最长」列共用同一实现。
    spans, now = _spans(evs, current, now)

    by_proc = {}
    for _k, sp in spans.items():
        by_proc.setdefault(sp.get("p") or "?", []).append(
            max(0.0, (sp.get("last") or now) - (sp.get("first") or now)))
    for proc, durs in sorted(by_proc.items()):
        if len(durs) < MIN_SAMPLES_FOR_MEDIAN:
            continue                      # ★ 样本不足不许下结论
        med = _median(durs)
        longest = max(durs)
        if longest >= LONG_CONN_MIN and med and longest >= med * LONG_CONN_RATIO:
            out.append({
                "kind": "长连接",
                "lines": [
                    "%s 有一条连接持续 ≥%s" % (proc, _fmt_dur(longest)),
                    "（该进程连接时长中位 %s，样本 %d 条）" % (_fmt_dur(med), len(durs)),
                    "→ 打包上传是长传；正常问答是短连接。也可能是流式响应，需你自行判断。",
                ]})

    # ③ 对象存储目的地
    if do_resolve:
        seen_os = {}
        for k, v in (current or {}).items():
            ip = (v.get("remote") or "").rsplit(":", 1)[0]
            if ip.startswith("["):
                ip = ip[1:].split("]")[0]
            if ip in cache and cache[ip] is None:
                continue
            h = resolve_host(ip, cache)
            if h and any(h.endswith(s) or s in h for s in OBJECT_STORE_SUFFIX):
                seen_os.setdefault(h, set()).add(v.get("proc") or "?")
        for h, procs in sorted(seen_os.items()):
            out.append({
                "kind": "对象存储目的地",
                "lines": [
                    "%s 反解命中 %s（对象存储）" % ("、".join(sorted(procs))[:60], h),
                    "→ 数据直传存储桶是已知外传手法；也可能是它正常的资源存放，需你自行判断。",
                ]})
    # ④ 账本自己断过档（N3 的消费侧：补记的那条要有人读）
    # ★ 为什么这条必须进「值得看」：`lost` 事件是写失败留下的唯一痕迹。
    #   记了没人读 ⇒ 与 0.42.0 那次「89 条 hook_slow 被匿名计数吸收」同一形状：
    #   空档会被读成"那段时间没有外传"，而事实是"那段时间没记上"。
    lost_n = sum(int(e.get("n") or 0) for e in evs if e.get("e") == "lost")
    lost_n += int(pending_lost or 0)
    if lost_n:
        firsts = [e.get("first") for e in evs if e.get("e") == "lost" and e.get("first")]
        head = ("，最早从 %s 开始" % time.strftime("%m-%d %H:%M", time.localtime(min(firsts)))
                if firsts else "")
        out.append({
            "kind": "账本断档",
            "lines": [
                # ★「至少」（A8）：清零那一步若也失败，同一批会被再补一遍 ⇒
                #   这个和是**上界**。按精确值说就是把"记多了"说成"正好这么多"。
                "至少有 %d 条记录没能写进账本%s" % (lost_n, head),
                "→ 磁盘满或写入被拒时会发生。这段空档不等于「那段时间没有外传」，",
                "  只等于「那段时间没记上」。",
            ]})
    # ⑤ 磁盘/账本接近上限（N2 的消费侧）
    dp = [e for e in evs if e.get("e") == "disk_pressure"]
    if dp:
        last = dp[-1]
        pct = last.get("used_pct")
        out.append({
            "kind": "磁盘吃紧",
            "lines": [
                "磁盘已用 %s，账本目录 %s MB（上限 %d MB）"
                % ("%.0f%%" % (pct * 100) if isinstance(pct, (int, float)) else "未知",
                   last.get("dir_mb"), MAX_DIR_BYTES // 1048576),
                "→ 账本会先清掉最老的日期让路。清到最新一天仍写不进，就开始记断档。",
            ]})
    try:
        _write_json("resolve.json", cache)
    except Exception:
        pass
    return out



def _fmt_dur(sec):
    sec = float(sec or 0)
    if sec < 60:
        return "%.0f 秒" % sec
    if sec < 3600:
        return "%.0f 分钟" % (sec / 60.0)
    return "%.1f 小时" % (sec / 3600.0)


# ---------------------------------------------------------------- 输出
BOUNDARY = """── 边界（本账本记的是连接事实，不是外传结论）────────
 · 看不到字节数 ⇒ 无法判断"发了多少"
 · 看不到内容 ⇒ 加密流量里是什么，不知道
 · 采样是快照（约 30 秒/次）⇒ 短连接可能漏
 · AI 工具正常工作时本来就在往外发 ⇒ 有连接 ≠ 有问题"""


def render(snap, findings, days_with, sentinel_on, sample_failed, ai_only=True,
           longest_by_proc=None, cov_seconds=None, cap=None):
    L = []
    idle = snap.get("idle")
    L.append("== 外传账本 · 出口连接（%s）"
             % time.strftime("%Y-%m-%d %H:%M:%S"))
    # ★ 报"实际覆盖多久"，不是"有几个文件"。账本才跑 21 分钟却写"有数据 1 天"，
    #   就是把"没采到"说成"有数据"（仓库第 ④ 条判据）。覆盖时长同时解释了
    #   为什么冷启动期所有「最长」都接近同一个数 —— 那是账本年龄，不是连接年龄。
    _cov = ("实际覆盖 %s" % _fmt_dur(cov_seconds)) if cov_seconds \
        else ("有数据 %d 天" % days_with if days_with else "无历史采样")
    L.append("   用户空闲：%s ｜ 监理：%s ｜ 采样窗口：最近 %d 天（%s）"
             % (_fmt_dur(idle) if idle is not None else "未知",
                "在岗（约 30 秒/次）" if sentinel_on else "未运行 ⇒ 无历史采样",
                LEDGER_DAYS, _cov))
    # ★ 空间这一格必须自己报数（40 格 · 空间·看/挡）：
    #   只写"上限 48 MB"而从不写"现在多少"，等于没有上限 —— 用户无法预判哪天开始丢。
    if cap:
        _free_mb = cap["free"] / 1048576.0
        _pct = cap.get("used_pct")
        _disk = "   磁盘剩 %.1f GB%s" % (
            _free_mb / 1024.0,
            ("（已用 %.0f%%）" % (_pct * 100)) if isinstance(_pct, (int, float)) else "")
        # ★★ 目录读不到时不许报"0 个文件"（A6）：`readable=False` 下的 0 是
        #   **没量到**，渲染成"没有"正是本仓反复踩的那一类（null ≠ 0 ≠ []）。
        if cap.get("readable") is False:
            L.append(_disk + " ｜ 账本目录读不到（不是「0 个文件」，是「没量到」）")
        else:
            # ★ 只数日文件（A9）：`dir_files` 含 lost.json/current.json/disk_warn.json
            #   与残留 .tmp，把它当"账本文件数"就是口径混装。
            #   `default` 只为兼容手工构造的 cap（判据夹具）—— 生产真源 `capacity()`
            #   必带此键，且它来自 `dir_stats().event_files`。
            L.append(_disk + " ｜ 账本 %d 个日文件 %.1f MB（上限 %d MB，保留 %d 天）"
                     % (cap.get("dir_event_files", cap.get("dir_files", 0)),
                        cap["dir_bytes"] / 1048576.0,
                        MAX_DIR_BYTES // 1048576, KEEP_DAYS))
            if cap.get("low_free") or cap.get("dir_full"):
                L.append("   ⚠ 空间已到闸线：会先清掉最老的日期再写")
    elif cap is None:
        L.append("   磁盘：读不到容量（这一项不是「没问题」，是「没量到」）")
    if sample_failed:
        L.append("   ⚠ 本窗口有 %d 次采样失败（未采到 ≠ 没问题）" % sample_failed)


    L.append("")
    L.append("── 此刻 · %s的外部连接 ──────────────"
             % ("AI 工具" if ai_only else "全部进程"))
    if not snap.get("conns"):
        L.append("  （本次快照没有外部连接）")
    else:
        by = {}
        for c in snap["conns"]:
            by.setdefault(c["proc"], []).append(c)
        L.append(" %-22s %8s %6s %6s  %s" % ("进程", "PID", "连接", "最长", "远端"))
        for proc, cs in sorted(by.items(), key=lambda x: -len(x[1])):
            # ★ 「最长」必须给真值（见 _proc_longest 的注释）：空列＝把"没算"读成"没有"。
            #   前缀 `≥`：账本只知道"从第一次看见到现在"，连接可能更早就在了 ⇒ 这是下界。
            _d = (longest_by_proc or {}).get(proc)
            longest = ("≥" + _fmt_dur(_d)) if _d is not None else "—"
            L.append(" %-22s %8d %6d %6s  %s"
                     % (proc[:22], cs[0]["pid"], len(cs), longest,
                        ", ".join(sorted({c["remote"] for c in cs})[:3])))

    L.append("")
    L.append("── 值得看 ────────────────────────────")
    if not findings:
        L.append("  （三条判据都没有触发 —— 这不等于没问题，只等于没看到异常特征）")
    for f in findings:
        L.append("★ %s" % f["kind"])
        for ln in f["lines"]:
            L.append("  " + ln)
        L.append("")

    L.append(BOUNDARY)
    return "\n".join(L)


def run(days=LEDGER_DAYS, all_proc=False, do_resolve=True, as_json=False):
    """命令入口：即时快照 + 账本分析。"""
    if not is_windows():
        return ("外传账本：当前仅支持 Windows。"
                "取数靠 netstat、tasklist、GetLastInputInfo。")
    # ★ 顺序与 `tick()` 统一（A12）：**先维护、再采样、再记账**。
    #   这不只是整齐：A4 的"预留今天那一格"依赖"写发生在 housekeep 之后"，
    #   两条腿顺序不同 ⇒ 同一天里容量与保留的观测时点不一致。
    housekeep()                     # 保留策略 + 容量观测（与 tick 同一实现，不另写一遍）
    s = sample(ai_only=not all_proc)
    evs, days_with = load_events(days)
    cur = _read_json("current.json", {})
    sentinel_on = bool(evs) or bool(cur)
    failed = sum(1 for e in evs if e.get("e") == "sample_failed")
    if s.get("ok"):
        _append({"t": s["ts"], "e": "snapshot", "n": len(s["conns"])})
    else:
        _append({"t": s["ts"], "e": "sample_failed", "idle": s.get("idle")})
        failed += 1
    # ★ 补记一条（若上一轮有写失败）之后要**重新读**，否则刚补的那条看不见。
    evs, days_with = load_events(days)
    _pending_n, _pfirst, _plast = lost_pending()
    findings = analyze(evs, cur, days_with, do_resolve=do_resolve,
                       pending_lost=_pending_n)
    cap = capacity()
    # 「最长」列的真值：与判据②共用 `_spans()`（单一实现，不许另算一遍）。
    spans, _now = _spans(evs, cur)
    longest_by_proc = _proc_longest(spans, _now)
    # 实际覆盖时长（不是"有几个事件文件"）—— 见 render() 顶部的说明。
    _ts = [e.get("t") for e in evs if e.get("t")]
    cov_seconds = (_now - min(_ts)) if _ts else None
    if as_json:
        return json.dumps({"snapshot": s, "findings": findings,
                           "days_with_data": days_with, "sample_failed": failed,
                           "longest_by_proc": longest_by_proc,
                           "coverage_seconds": cov_seconds,
                           "capacity": cap, "lost_pending": _pending_n},
                          ensure_ascii=False, indent=2)
    return render(s, findings, days_with, sentinel_on, failed,
                  ai_only=not all_proc, longest_by_proc=longest_by_proc,
                  cov_seconds=cov_seconds, cap=cap)
