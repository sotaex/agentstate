# -*- coding: utf-8 -*-
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
            except OSError:
                pass
            time.sleep(delay)
            delay = min(delay * 1.25, 0.025)
    tlog("acq_timeout", waited_ms=round((time.time() - t0) * 1000))
    return None


def release_lock(lock):
    """C-2: 只释放仍属于我们的锁——token 不匹配（被偷过）就不动。"""
    if not lock:
        return
    c = read_lock(lock)
    if c and c.get("token") == LOCK_TOKEN:
        try:
            os.remove(lock)
        except OSError:
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
def append_chained(fn, rec, on_timeout="sidecar"):
    """链式追加的唯一入口。返回 (rec, chained)：
    chained=True  记录已按锁定协议写入主链（锁内读 prev → 锁内追加）；
    chained=False 锁预算耗尽——sidecar 策略落 sidecar（chain:"unlocked"），
                  drop 策略不落盘。主链永远线性可判定。"""
    lock = acquire_lock(fn)
    got = lock is not None
    t_hold = time.time()
    try:
        rec = chain_with(rec, last_hash(fn))        # 读 prev 在锁内（TN-09）
        if not got:
            rec["chain"] = "unlocked"
        if got:
            chaos()
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        if got:
            with open(fn, "a", encoding="utf-8") as f:
                f.write(line)
        elif on_timeout == "sidecar":
            sd = os.path.join(os.path.dirname(fn), "sidecar")
            try:
                os.makedirs(sd, exist_ok=True)
            except OSError:
                pass
            try:
                with open(os.path.join(
                        sd, os.path.basename(fn) + ".%d.jsonl" % os.getpid()),
                        "a", encoding="utf-8") as f:
                    f.write(line)
            except OSError:
                pass
        tlog("append_done", hold_ms=round((time.time() - t_hold) * 1000),
             sidecar=not got)
        return rec, got
    finally:
        release_lock(lock)


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
