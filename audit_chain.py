# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""audit_chain — Antinel 审计链追加的唯一实现（v0.28.0，条款 C-1）。

同一配方此前存在三份拷贝（pre_tool_use / post_tool_use / session_dna），行为已
漂移过（盲释放、偷活锁、unlocked 直写主链——Gauntlet 2026-09-21 实证）。本模块
是唯一权威；钩子侧只保留同名薄委托。

配方（AUDIT_SCHEMA v1.2 §2 / TN-09）：
    锁获取(O_EXCL + 身份牌) → 锁内读 prev → chain → 追加 → 释放(token 匹配才删)
    hash = sha256(prev + canonical_json(rec 去掉 hash))
    canonical = sort_keys=True, separators=(",", ":")；prev 取前驱 hash 末 16 位

锁预算：~1.6s 退避自旋（5ms 起 ×1.25，25ms 封顶）。耗尽后按 on_timeout：
    "sidecar"  记录（chain:"unlocked"）改投 audit/sidecar/<日>.<pid>.jsonl
               —— 主链只含按协议成链的记录（条款 C-3）
    "drop"     不落盘，返回 chained=False（证据不裸奔进账本）
陈锁（>30s）只有在持有者进程确证已死时才可偷（C-2：OpenProcess 探测，
查询失败按存活——宁可 sidecar，不可误偷活锁）；释放前 token 匹配才删。

day_manifest（R-20 日锚）由调用方择时调用 touch_day_manifest——pre 在读回复核
通过后、post/session_dna 在写入后；本模块不代调。
"""
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime

LOCK_TOKEN = uuid.uuid4().hex           # C-2: 锁所有权身份牌（每进程一张）


# ------------------------------------------------- 诊断（env 门控，默认关） ----
def tlog(evt, **kw):
    """Gauntlet 诊断遥测：ANTINEL_LOCK_TELEMETRY=1 才开；只写
    audit/telemetry/ side 文件，绝不进链。随 C-1 合并自三处收拢至此。"""
    try:
        if os.environ.get("ANTINEL_LOCK_TELEMETRY") != "1":
            return
        d = os.path.join(os.getcwd(), ".psl", "audit", "telemetry")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "%s.%d.log" % (
                datetime.now().strftime("%Y-%m-%d"), os.getpid())), "a",
                encoding="utf-8") as f:
            f.write(json.dumps({"evt": evt, "pid": os.getpid(),
                                "t": round(time.time(), 3), **kw},
                               ensure_ascii=False) + "\n")
    except Exception:
        pass


def chaos():
    """Gauntlet 故障注入（诊断专用，默认关）：ANTINEL_LOCK_CHAOS_MS=N 时在
    「已读 prev、未写链」的持锁窗口内固定睡 N 毫秒，模拟调度饥饿。"""
    try:
        ms = int(os.environ.get("ANTINEL_LOCK_CHAOS_MS", "0") or 0)
    except Exception:
        ms = 0
    if ms > 0:
        time.sleep(ms / 1000.0)


# ------------------------------------------------------- 并发读数（N5）----
#: ★★ 2026-10-22（40 格 · 并发·报）：抢锁超时与回收死锁**有计数、没有出口**。
#:   `tlog()` 只在 `ANTINEL_LOCK_TELEMETRY=1` 时才写，而那个开关是给诊断用的
#:   —— 等于"用户不看诊断就永远看不到"。一次"两个守卫同时起来"在界面上
#:   完全不可见，而它恰好是"记录写得慢/写丢"的常见原因。
#: ⇒ 竞争事件单独落一个 append-only 小文件（正常一天 0 行），由页面读回。
#: ★ 为什么不用主链：这类事件每分钟可能几十条，进链会把真信号淹掉
#:   （与 `egress` 不进主链同一条理由）。它记的是**运行状况**，不是失守。
LOCK_EVENTS = "lock_events.jsonl"
_LOCK_EVENTS_MAX = 1024 * 1024        # 1 MB 一代；超了把上一代挪成 .1（有界 2 MB）


def lock_events_path(audit_dir=None):
    """竞争事件的落点。`audit_dir` 缺省＝cwd 下的 `.psl/audit`（与 tlog 同源）。"""
    d = audit_dir or os.path.join(os.getcwd(), ".psl", "audit")
    return os.path.join(d, LOCK_EVENTS)


def _note_lock(lock, evt, **kw):
    """记一次竞争。**best-effort**：读数十毫秒的锁不值得为写日志崩掉。"""
    try:
        p = os.path.join(os.path.dirname(lock) or ".", LOCK_EVENTS)
        try:
            if os.path.getsize(p) > _LOCK_EVENTS_MAX:
                os.replace(p, p + ".1")     # 只留一代 ⇒ 占用有上界
        except OSError:
            pass
        with open(p, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps({"t": round(time.time(), 3), "pid": os.getpid(),
                                "evt": evt, "file": os.path.basename(lock), **kw},
                               ensure_ascii=False) + "\n")
    except Exception:
        pass


def _checked_from(unreadable):
    """`checked` 的**唯一判据**：存在的文件都读到了吗。

    ★ 抽成函数的理由（与 `egress._merge_lost`／`_keep_target` 同）：负控要换掉
      **同一份实现**：`_checked_from = lambda u: True` 就复现了旧行为 ——
      旧实现末尾是"目录存在 ⇒ checked=True"，而夹具里目录一定存在，
      所以在该夹具上旧实现恒为 True。换成这个 lambda，换的正是同一条规则。
    """
    return not unreadable


def lock_pressure(hours=24.0, path=None):
    """读回并发读数（★ 唯一实现：页面/CLI 都调它，不许各数一遍）。

    返回 `{"timeouts":n, "steals":n, "last":ts|None, "files":[...],
           "checked":bool, "unreadable":[...]}`。

    ★★ `checked` 必须与 0 分开：`timeouts=0, checked=True` 是"查了，没竞争"；
      `checked=False` 是"该读的地方读不到"—— 后者不是"没问题"，
      正好是本仓第 ④ 条判据（没查 ≠ 没发现）。
    ★★ 2026-10-22（A5）：`checked` 的口径收紧为**"存在的文件都读到了吗"**。
      旧实现末尾有一句 `if os.path.isdir(dirname): checked = True` ——
      它只证明目录存在，却把"文件存在但读失败"也一起置成 True，
      **等于把自己的契约作废**（那正是"善意的默认值"）。
      现在：
        · 文件不存在 ⇒ 从未记到竞争 ⇒ 空账本（合法形态，算查到了）；
        · 文件存在但 `open` 失败 ⇒ 记进 `unreadable`，`checked=False`。
    """
    p = path or lock_events_path()
    out = {"timeouts": 0, "steals": 0, "last": None, "files": [],
           "checked": False, "unreadable": []}
    files = [p, p + ".1"]
    now = time.time()
    seen = set()
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    t = e.get("t")
                    if not isinstance(t, (int, float)) or now - t > hours * 3600:
                        continue
                    evt = e.get("evt")
                    if evt == "acq_timeout":
                        out["timeouts"] += 1
                    elif evt == "steal":
                        out["steals"] += 1
                    else:
                        continue
                    fn = e.get("file") or ""
                    if fn and fn not in seen:
                        seen.add(fn)
                        out["files"].append(fn)
                    if out["last"] is None or t > out["last"]:
                        out["last"] = t
        except FileNotFoundError:
            continue
        except OSError:
            out["unreadable"].append(os.path.basename(fp))
            continue
    out["checked"] = _checked_from(out["unreadable"])
    return out



# ------------------------------------------------------- C-2 锁所有权 ----
def read_lock(lock):
    """读锁内容 {pid, ts, token}；空/残缺返回 None。"""
    try:
        with open(lock, "r", encoding="utf-8") as f:
            return json.loads(f.read())
    except Exception:
        return None


def pid_alive(pid):
    """C-2: Windows 存活探测。打不开 = 已死；查询失败/异常按存活
    （宁可 sidecar，不可误偷活锁——Run B 教训）。"""
    try:
        import ctypes
        import ctypes.wintypes as wt
        k = ctypes.windll.kernel32
        h = k.OpenProcess(0x0400, 0, int(pid))      # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        try:
            code = wt.DWORD(0)
            if k.GetExitCodeProcess(h, ctypes.byref(code)):
                return code.value == 259            # STILL_ACTIVE
            return True
        finally:
            k.CloseHandle(h)
    except Exception:
        return True


def acquire_lock(fn):
    """O_EXCL 锁文件 + 身份牌；拿到返回锁路径，预算耗尽返回 None。"""
    lock = fn + ".lock"
    delay = 0.005
    t0 = time.time()
    for i in range(100):                            # ~1.6s budget, backoff-capped:
        try:                                        # a 16-way burst queues <=300ms
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, json.dumps({"pid": os.getpid(),
                                         "ts": round(time.time(), 3),
                                         "token": LOCK_TOKEN}).encode("utf-8"))
            finally:
                os.close(fd)
            tlog("acq_ok", waited_ms=round((time.time() - t0) * 1000), tries=i + 1)
            return lock
        except (FileExistsError, PermissionError):
            # PermissionError: O_EXCL on a delete-pending lockfile — contended,
            # not fatal (Gauntlet A3: 0.3% rc=1 came from this escaping).
            try:                                    # 30s: a lock older than this
                age = time.time() - os.path.getmtime(lock)
                if age > 30:                        # is a DEAD-LOCK candidate --
                    c = read_lock(lock)             # C-2: steal only when the
                    if c is None or not pid_alive(c.get("pid", -1)):
                        os.remove(lock)             # holder is really gone; a
                        tlog("steal", age_s=round(age, 1),
                             pid=(c or {}).get("pid"))   # live holder keeps it.
                        # ★ 40 格 · 并发·报：回收死锁也要让用户看得见（不只在 tlog 里）
                        _note_lock(lock, "steal", age_s=round(age, 1),
                                   holder=(c or {}).get("pid"))
            except Exception:
                # ★ 0.34.1 修：原为 `except OSError`。宿主删除守卫会抛出**非 OSError**
                #   的异常（实测 `SAFE_DELETE_BULK_CONFIRM_REQUIRED`）⇒ 穿透 ⇒ 抢锁
                #   路径当场崩。抢锁失败本来就该退化成"拿不到锁"（下面继续重试），
                #   不该崩 —— 放宽到 Exception 与下方 release_lock 同一纪律。
                pass
            time.sleep(delay)
            delay = min(delay * 1.25, 0.025)
        except Exception:
            # ★ 0.34.1 修（与 release_lock 同一纪律）：抢锁**失败必须退化成"拿不到锁"**，
            #   不许把"一次追加"变成调用方崩溃。
            #   实测（本机宿主删除守卫）：`os.open(lock, O_EXCL)` 抛的是**非
            #   FileExistsError/PermissionError** ⇒ 穿透上面的窄 except ⇒
            #   `append_chained` 整个抛出去 ⇒ 钩子 rc=1（记录没写成）。
            #   放宽后的语义：**继续重试**；100 次用尽 ⇒ 返回 None ⇒
            #   `append_chained` 落 sidecar（记录不丢，只是标 `chain:"unlocked"`）。
            time.sleep(delay)
            delay = min(delay * 1.25, 0.025)
    tlog("acq_timeout", waited_ms=round((time.time() - t0) * 1000))
    # ★ 40 格 · 并发·报：预算耗尽 ⇒ 落 sidecar（记录不丢）**且**留一行可见读数。
    #   否则"两个守卫同时起来"只存在于一个默认关闭的诊断开关里。
    _note_lock(lock, "acq_timeout", waited_ms=round((time.time() - t0) * 1000))
    return None


def release_lock(lock):
    """C-2: 只释放仍属于我们的锁——token 不匹配（被偷过）就不动。

    ★ 0.34.1 修：**释放锁是 best-effort，绝不许把"已经写成功的追加"变成崩溃。**
      本函数在 `append_chained` 的 `finally:` 里被调用 ⇒ 它抛出的异常会掩盖
      「记录已落盘」这个既成事实，并让调用方整个进程非零退出。
      实测（本机宿主删除守卫）：`os.remove(lock)` 抛的是**非 OSError**，
      穿透原来的 `except OSError` ⇒ 钩子 rc=1、canary rc=1，而记录其实已经写好
      （半截成功＝最坏形状：外部看到"失败"，账本里却已经有了）。
      放宽到 `except Exception` 后的语义：**锁没删掉只是退化**——30s 死锁回收
      （acquire_lock）会接手，已落盘的记录不受影响。
    """
    if not lock:
        return
    try:
        c = read_lock(lock)
    except Exception:
        return
    if c and c.get("token") == LOCK_TOKEN:
        try:
            os.remove(lock)
        except Exception:
            tlog("remove_err")
    else:
        tlog("release_skip")                        # 锁已易主：留给它的主人


# ----------------------------------------------------------- 链算术 ----
def last_hash(fn):
    """末条记录的 hash（"" = 文件不存在或为空）。只读，无锁——调用方须持锁。"""
    prev = ""
    try:
        with open(fn, "r", encoding="utf-8", errors="replace") as f:
            for l in f:
                l = l.strip()
                if not l:
                    continue
                try:
                    h = json.loads(l).get("hash")
                    if h:
                        prev = h
                except Exception:
                    pass
    except Exception:
        pass
    return prev


def chain_with(rec, prev):
    """给定 prev，算出 rec["prev"]（尾 16 位）与 rec["hash"]。纯函数，不碰 IO。

    AUDIT_SCHEMA v1.2 §2：rec["hash"] = sha256(prev + canonical_json(rec))，
    canonical = sort_keys + 紧凑分隔符；任何编辑/删除都会断链、可被离线复算检出。"""
    rec = dict(rec)
    rec["prev"] = prev[-16:]
    canon = json.dumps({k: v for k, v in rec.items() if k != "hash"},
                       sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    rec["hash"] = hashlib.sha256((prev + canon).encode("utf-8")).hexdigest()
    return rec


# ------------------------------------------------------- 追加与降级 ----
#: 写链失败的**进行时**计数（进程内唯一实现）。为什么非有不可：
#: `written="none"` 是"这一条彻底没了"的唯一证据 —— 磁盘满/权限坏的时候，
#: 盘上当然也没有任何痕迹，**跨进程永远事后查不出来**。所以必须在失败发生的
#: 那个进程里留下计数，并由调用方转成用户看得见的一句话（见 host_shield）。
_WRITE_HEALTH = {"lost": 0, "last_error": "", "last_ts": 0.0}


def write_health():
    """写链健康读数。`lost` > 0 ⇒ 有记录**一个字节都没落盘**。"""
    return dict(_WRITE_HEALTH)


def _note_write_failure(err):
    _WRITE_HEALTH["lost"] += 1
    _WRITE_HEALTH["last_error"] = "%s: %s" % (type(err).__name__, err)
    _WRITE_HEALTH["last_ts"] = time.time()
    tlog("append_lost", err=_WRITE_HEALTH["last_error"][:120])


def append_chained(fn, rec, on_timeout="sidecar"):
    """链式追加的唯一入口。返回 `(rec, ok)`：

    `rec["written"]` 是**四种事实**，不是两种（2026-10-22 修 BL-03）：
      "chain"    已按锁定协议进主链（锁内读 prev → 锁内追加）
      "sidecar"  锁预算耗尽或主链写不进，落在 sidecar（`chain:"unlocked"`）
      "dropped"  `on_timeout="drop"` 且没拿到锁 ⇒ **按策略**不落盘
      "none"     **一个字节都没落**（磁盘满 / 权限坏 / 读不到 prev）⇒ 记录已丢

    `ok = written in ("chain", "sidecar")`，即**"这条还找得回来吗"**。

    ★★ 为什么改（BL-03，2026-10-22）：旧实现把上面四种状态压成一个布尔 `chained`，
      而它的含义是"**锁拿到了吗**"——不是"写成功了吗"：
        · 主链 `open()` 抛 OSError 时异常**穿透整个函数**（旧代码没有 try），
          于是 **sidecar 降级根本走不到** —— 而"磁盘满"恰好就是这一支；
        · sidecar 的两处 `except OSError: pass` 把失败吞成同一个 `False`；
        · 于是"落在 sidecar"（记录还在）与"彻底没了"（记录丢了）**长得一模一样**，
          而调用方连这个 False 都不看（`host_shield.record()` 返回它，30 个调用点
          零消费）。
      ⇒ 净效果：**磁盘满 ⇒ 记录全丢 ⇒ 界面全绿**。安全产品最坏的失效形态不是
        报错，是**报成功**。
    """
    lock = acquire_lock(fn)
    got = lock is not None
    t_hold = time.time()
    written = "none"
    err = None
    try:
        try:
            rec = chain_with(rec, last_hash(fn))    # 读 prev 在锁内（TN-09）
            if not got:
                rec["chain"] = "unlocked"
            line = json.dumps(rec, ensure_ascii=False) + "\n"
            if got:
                chaos()
                try:
                    with open(fn, "a", encoding="utf-8") as f:
                        f.write(line)
                    written = "chain"
                except OSError as e:
                    # ★ 主链写不进**不等于放弃**：先试 sidecar（可能是单文件被占/
                    #   权限单点，而不是整盘满）。旧实现这里直接抛出去 ⇒ 降级失效。
                    err = e
            if written == "none":
                if on_timeout == "drop":
                    written = "dropped"             # 按策略不落盘，不算丢失
                else:
                    sd = os.path.join(os.path.dirname(fn), "sidecar")
                    try:
                        os.makedirs(sd, exist_ok=True)
                        with open(os.path.join(
                                sd, os.path.basename(fn) + ".%d.jsonl" % os.getpid()),
                                "a", encoding="utf-8") as f:
                            f.write(line)
                        written = "sidecar"
                    except OSError as e:
                        err = err or e
        except OSError as e:
            # 读 prev / 序列化就失败 ⇒ 造不出**可验证**的记录。
            # 这里刻意不写一条"hash 自己编"的 sidecar：那比缺一条更坏 ——
            # 它看起来可复算，实际复算必错。
            err = err or e
    finally:
        release_lock(lock)
    rec["written"] = written
    if written == "none":
        rec["write_error"] = "%s: %s" % (type(err).__name__, err or "原因未知")
        _note_write_failure(err or OSError("写不进，原因未知"))
    tlog("append_done", hold_ms=round((time.time() - t_hold) * 1000),
         sidecar=(written == "sidecar"), written=written)
    return rec, written in ("chain", "sidecar")


def append_locked(fn, line):
    """A8 宿主镜像：锁内平文追加**已序列化**文本，不重算链——镜像必须是
    项目侧已算好 prev/hash 的逐字节副本，否则无法用于检出项目侧被编辑。"""
    lock = acquire_lock(fn)
    try:
        with open(fn, "a", encoding="utf-8") as f:
            f.write(line)
    finally:
        release_lock(lock)


def touch_day_manifest(fn):
    """R-20 日锚：日文件的字节大小 + 末行 hash 写 day_manifest.json（链外副本），
    用于检出尾部删除。单调：size 只增不移。best-effort，失败静默。"""
    try:
        size = os.path.getsize(fn)
        with open(fn, "rb") as f:
            f.seek(max(0, size - 4096))
            tail = f.read().decode("utf-8", errors="replace").rstrip("\r\n")
        last_line = tail.rsplit("\n", 1)[-1] if "\n" in tail else tail
        last_hash_v = json.loads(last_line).get("hash", "") if last_line else ""
        mpath = os.path.join(os.path.dirname(fn), "day_manifest.json")
        day = os.path.basename(fn)
        try:
            with open(mpath, "r", encoding="utf-8") as f:
                man = json.load(f)
            if not isinstance(man, dict):
                man = {}
        except Exception:
            man = {}
        prev = man.get(day) or {}
        if size >= int(prev.get("size", 0)):        # monotonic; never move back
            man[day] = {"size": size, "last_hash": last_hash_v,
                        "updated_at": datetime.now().isoformat(timespec="seconds")}
            tmp = mpath + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(man, f, ensure_ascii=False, indent=1)
            os.replace(tmp, mpath)
    except Exception:
        pass                                        # best-effort anchor
