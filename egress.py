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


def _append(ev):
    """append-only 写一条事件。★ 采样失败也要写（`e:"sample_failed"`）——
    否则"没采样"会被当成"没问题"（仓库第 ④ 条判据："没查"不许伪装成"没发现"）。"""
    p = _events_path()
    if not p:
        return False
    try:
        with open(p, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(ev, ensure_ascii=False, sort_keys=True) + "\n")
        return True
    except OSError:
        return False


def _read_json(name, default):
    p = _path(name)
    if not p or not os.path.isfile(p):
        return default
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return default


def _write_json(name, obj):
    p = _path(name)
    if not p:
        return False
    try:
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, ensure_ascii=False)
        os.replace(tmp, p)
        return True
    except OSError:
        return False


def tick():
    """哨兵每 N 拍调一次：采样 → 与上一拍比对 → 记 new/gone → 覆盖写当前表。

    ★ 返回的 bool 只表示"这一步自己跑完没有"，不代表"有没有可疑"。
    ★ 调用方必须 try 包住 —— 采样绝不能拖死哨兵。
    """
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
            for line in open(p, encoding="utf-8"):
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


def analyze(evs, current, days_with, do_resolve=True):
    """三条判据。全部**只标"值得看"**，每条附原样证据 + 一句可自行否掉的话。

    返回 list[dict]：`{"kind":…, "lines":[…]}`。
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
           longest_by_proc=None, cov_seconds=None):
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
    findings = analyze(evs, cur, days_with, do_resolve=do_resolve)
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
                           "coverage_seconds": cov_seconds},
                          ensure_ascii=False, indent=2)
    return render(s, findings, days_with, sentinel_on, failed,
                  ai_only=not all_proc, longest_by_proc=longest_by_proc,
                  cov_seconds=cov_seconds)
