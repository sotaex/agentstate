#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.45.0 判据 —— **第二处根治：状态写入**（甲单一入口收编 ＋ 乙接线既有锁 ＋ 丙名片租约）。

★★ 由来（交接件 §4.1/§4.2，实测非推演）：
    节流失效的两个候选 —— **拒写** 与 **被覆盖** —— 本轮没能分开，但**定性改了一半**：
    主因**不是**多进程同一瞬间抢（同秒簇只有 1.2%（2 / 160）），而是**秒到分钟级
    错开的覆盖或静默拒写**（5–60 秒档占 23.4%（34 / 145））。
    ⇒ 只加锁不对症：**必须先把整份写回收编进唯一入口，再谈锁**。
    一句话：**上一版想的是给屋子加锁，而真正发生的是有人拿着一份旧蓝图把图纸抽屉塞回去了。**

★ 本文件落地三层（交接件 §4.3）：
    甲 —— 监理状态维护路径**整份写回处数为 0**（一律改按字段更新）＋
          **忽略返回值处数为 0** ＋ 状态文件**版本号乐观锁**（`_rev`）；
    乙 —— 用**审计链既有锁**（`audit_chain.acquire_lock`，入参任意路径）把
          「检查（节流）＋ 记账（last_revive_attempt）＋ 拉起」合成一个临界区；
    丙 —— 监理**在岗名片**（租约）：进程号 + 启动时刻双因子判活；陈旧名片改名让开；
          写走临时文件 + 原子替换 + 读回比对。

★ 四件套（本文件逐条落地）：
    正判据 S73/S74/S75/S76/S77/S78；反向对照 N-S73/N-S74/N-S75/N-S77/N-S78/N-S78b；
    连带对照 S79（既有保护仍绿：拒写仍成立）。
    · N-S78b 是**本轮实测新增**：Windows 上「临时文件 + 原子替换」若**不带重试**，
      写者会被并发读打断（实测 200 次替换失败 169 次）—— 故写者与读者**都得带重试**，
      否则这套保护是**单边**的（保住了读者、打死了写者）。
★ 编写纪律（沿用 0430/0431/0440）：
    · 每条判据配负控，且负控**真的会红**；
    · 断言打在**行为/结构**上，不查文案；
    · **不写任何产品文件**：变异只发生在内存字符串上；并发用**真进程**（§7.2 / 纪律 10.7）。
"""
from __future__ import annotations

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import tmpreg as _TMP   # 0.55.0 (F3): temp dir registry
import ast
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

RESULTS = []
_HS = "host_shield.py"


def check(name):
    """★ 判据**必须真会红** —— 返回说明串一律转成抛异常。"""
    def deco(fn):
        def wrapper():
            r = fn()
            if r is True or r is None:
                return True
            raise AssertionError(r if isinstance(r, str) else repr(r))
        RESULTS.append((name, wrapper))
        return fn
    return deco


def _src(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _func_src(src, name):
    """抠出某个**顶层函数**的源码（AST 行号，不靠正则 —— 正则一遇缩进就漂）。"""
    for n in ast.parse(src).body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(src, n)
    return None


def _calls_in(src, names):
    """AST 找**被调用**的函数名（不猜、不吃注释）—— 返回 [(行号, 名)]。"""
    out = []
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Call):
            nm = getattr(n.func, "id", None) or getattr(n.func, "attr", None)
            if nm in names:
                out.append((n.lineno, nm))
    return out


def _bare_expr_calls(src, names):
    """**裸调用**（返回值被丢弃）：语句就是一次 Call，且没有赋值/返回/条件上下文。"""
    out = []
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call):
            nm = getattr(n.value.func, "id", None) or getattr(n.value.func, "attr", None)
            if nm in names:
                out.append((n.lineno, nm))
    return out


def _func_span(src, name):
    """顶层函数的行号区间 (first, last)；找不到 ⇒ None。"""
    for n in ast.parse(src).body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return (n.lineno, getattr(n, "end_lineno", n.lineno))
    return None


def _load_hs(tag, hub=None):
    """在**内存**里加载 host_shield（可指定隔离 hub），不写任何产品文件。"""
    if hub:
        os.environ["ANTINEL_HUB_DIR"] = hub
    mod = types.ModuleType(tag)
    mod.__file__ = os.path.join(ROOT, _HS)
    sys.modules[tag] = mod
    src = _src(_HS)
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)      # noqa: S102
    return mod


def _tmp_hub(prefix):
    d = _TMP.tmpdir(prefix=prefix)
    return d


def _save_state_outside_usf(src):
    """全文件里**不在 `update_state_fields` 之内**的 `save_state(...)` 调用行号。"""
    span = _func_span(src, "update_state_fields")
    calls = _calls_in(src, {"save_state"})
    if span is None:
        return [ln for ln, _ in calls]
    lo, hi = span
    return [ln for (ln, _nm) in calls if not (lo <= ln <= hi)]


# ══════════════ 甲 · S73 整份写回处数为 0 ══════════════
@check("S73 ★ 甲：监理状态维护路径整份写回处数为 0（scan_once/_lock_pending_tree 无 save_state）")
def s73():
    src = _src(_HS)
    # ① 全文件：`save_state` 只允许出现在它自己的定义与 `update_state_fields` 里
    outside = _save_state_outside_usf(src)
    if outside:
        return ("host_shield.py 里 `update_state_fields` 之外仍有整份写回 save_state：行 %s"
                " ⇒ 旧蓝图又被塞回抽屉（交接件 §4.2）" % outside[:6])
    # ② 哨兵主循环两函数：必须**一处都没有**
    for fn in ("scan_once", "_lock_pending_tree"):
        fs = _func_src(src, fn) or ""
        bad = _calls_in(fs, {"save_state"})
        if bad:
            return "%s 里仍有整份写回 save_state（行 %s）——必须改按字段更新" % (fn, bad)
        if "update_state_fields(" not in fs:
            return "%s 里没有按字段更新调用 —— 收编没落地" % fn
    return True


@check("N-S73 负控：把 scan_once 里一处按字段写回退回 save_state ⇒ S73 必须报红")
def n_s73():
    src = _src(_HS)
    anchor = ('if not update_state_fields(windows=state.get("windows") or {}):\n'
              '                    touched = True')
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = src.replace(anchor, "save_state(state)")
    if not _save_state_outside_usf(mut):
        return "负控失效：把一处退回 save_state 后 S73 的检查仍看不到 ⇒ 判据空转"
    return True


# ══════════════ 甲 · S74 忽略返回值处数为 0 ══════════════
@check("S74 ★ 甲：`update_state_fields` 忽略返回值处数为 0（无裸调用）")
def s74():
    src = _src(_HS)
    bare = _bare_expr_calls(src, {"update_state_fields"})
    if bare:
        return ("有 %d 处把 `update_state_fields(...)` 当语句一扔了事（行 %s）"
                " ⇒ 拒写/被覆盖被静默（交接件 §4.3 甲层：返回值不许忽略）"
                % (len(bare), [ln for ln, _ in bare][:6]))
    return True


@check("N-S74 负控：加一处裸调用 `update_state_fields(...)` ⇒ S74 必须报红")
def n_s74():
    src = _src(_HS)
    mut = src + "\n\n\ndef _g0450_probe():\n    update_state_fields(_probe=1)\n"
    bare = _bare_expr_calls(mut, {"update_state_fields"})
    if not bare:
        return "负控失效：加回裸调用后仍未被抓到 ⇒ S74 是假守卫"
    return True


# ══════════════ 甲 · S75 真进程并发：互斥成立（只有一个赢家） ══════════════
#: ★★ 0.48.5：起跑栅栏改走 `ci/race_amp.py` 的**会合栅栏**。
#:   旧版是"等一个 go 文件"（`_RACE_CHILD` 里 `while not os.path.exists(go)`）——
#:   它治不了**启动错峰**：`Popen` 返回得很快，但 N 个解释器启动有先后
#:   （本机实测每个 ≈100–200ms，机器一忙更久），**迟到的进程看见 go 已存在就
#:   直接冲**，等于没等 ⇒ "同时冲"退化成"排队冲"，50ms 的窗口就撞不上了。
#:   实测代价：打包闸门里 N-S75 假红过一次（0450 12 绿 / 1 红），随后连跑 3 次
#:   又是 13 绿 / 0 红 —— **时红时绿**，本仓铁律「一个时红时绿的量具比恒红的更坏」。
#:   会合栅栏等的是**兄弟进程本身**（全部到齐才放行），错峰因此被消掉。
_RACE_CHILD = r'''
import os
import sys
import time
sys.path.insert(0, sys.argv[4])          # 仓根：import 产品自己的锁实现
import audit_chain
mode, lockbase, counter = sys.argv[1], sys.argv[2], sys.argv[3]


def bump():
    try:
        with open(counter, encoding="utf-8") as f:
            n = int((f.read().strip() or "0"))
    except Exception:
        n = 0
    time.sleep(0.05)
    with open(counter, "w", encoding="utf-8") as f:
        f.write(str(n + 1))


if mode == "lock":
    lk = audit_chain.acquire_lock(lockbase)
    try:
        bump()
    finally:
        if lk:
            audit_chain.release_lock(lk)
else:
    bump()
'''


def _run_race(mode, nproc=6):
    """起 nproc 个**真进程**（带**会合栅栏**）抢临界区；返回最终计数。

    互斥成立 ⇒ 计数恰为 nproc；无互斥 ⇒ 丢失更新 ⇒ 计数 < nproc。
    ★ 会合失败（worker 超时未到齐 / 非正常退出）⇒ **抛异常**，调用方按
      「夹具失效」处理 —— **绝不**把"没会合上"读成"没撞上"或"通过了"。
    """
    import race_amp
    d = _TMP.tmpdir(prefix="g0450_race_")
    lockbase = os.path.join(d, "crit")
    counter = os.path.join(d, "counter")
    with io.open(counter, "w", encoding="utf-8") as f:
        f.write("0")
    rcs, d = race_amp.run_race(_RACE_CHILD, nproc,
                               argv=[mode, lockbase, counter, ROOT],
                               workdir=d, timeout=120)
    if race_amp.join_failed(rcs):
        raise AssertionError("会合失败（有 worker 超时未到齐）⇒ **夹具失效**：rcs=%r"
                             % (rcs,))
    if not race_amp.joined_ok(rcs):
        raise AssertionError("抢锁子进程非正常退出：rcs=%r ⇒ 夹具失效" % (rcs,))
    with io.open(counter, encoding="utf-8") as f:
        return int((f.read().strip() or "0"))


@check("S75 ★ 乙：真进程并发抢临界区只有一个赢家（互斥成立 ⇒ 计数恰为 N）")
def s75():
    n = 6
    got = _run_race("lock", n)
    if got != n:
        return ("%d 个真进程走既有锁，临界区计数为 %d（应为 %d）⇒ 互斥没成立"
                "（有丢失更新：两个进程同时进了临界区）" % (n, got, n))
    return True


@check("N-S75 负控：不起锁（直接进临界区）⇒ 计数必小于 N（证明本测试能测出无互斥）")
def n_s75():
    n = 6
    # ★★ 0.48.5：改走**会合栅栏**后，这一轮**每轮都真的同时冲**（不再靠调度运气）。
    #   保留有界重试只作**机器天气**的兜底（正常情况下第 1 轮即撞出）；
    #   K 轮全没撞上才判红，且要说明是「这几次没撞上」，不是「变异无效」。
    K = 3
    last = n
    for _attempt in range(K):
        got = _run_race("nolock", n)
        last = got
        if got < n:
            return True
    return ("负控失效：%d 轮都没撞出竞态（每轮计数都 ≥ %d，末轮 %d）⇒ "
            "本测试这一次没测出无互斥（重跑一次；若恒绿则该分支没被依赖）"
            % (K, n, last))


# ══════════════ 甲 · S76 没保住必须出声（拒写 / 乐观锁撞车） ══════════════
@check("S76 ★ 甲：状态写入'没保住'必须出声（subkind 区分 refused / optimistic_lock_lost）")
def s76():
    hub = _tmp_hub("g0450_s76_")
    H = _load_hs("hs_s76", hub)
    recs = []
    H.record = lambda *a, **k: recs.append((a, k))               # 打桩：只收记录
    try:
        # ① 存在但读不到 ⇒ refused
        with io.open(H.state_path(), "w", encoding="utf-8") as f:
            f.write("{ 半截")
        r1 = H.update_state_fields(sentinel_pid=1)
        if r1 is not False:
            return "坏状态文件上 `update_state_fields` 返回 %r（应 False）" % (r1,)
        subs = [k.get("subkind") for (_a, k) in recs if _a and _a[1] == "host_shield_state_write_refused"]
        if "refused" not in subs:
            return "拒写没进链留痕（或 subkind 不是 refused）：%r" % (subs,)
        # ② 乐观锁撞车 ⇒ optimistic_lock_lost：把"写后核对"的读回弄成旧版本
        recs.clear()
        os.remove(H.state_path())
        o_ls = H.load_state_strict
        # 让"写后核对"永远读到 rev=0（模拟被并发写者覆盖）⇒ 应重试后放弃并出声
        H.load_state_strict = lambda: ({"_rev": 0, "enabled": False}
                                       if not os.path.exists(H.state_path() + ".probe") else
                                       {"_rev": 0, "enabled": False})
        try:
            r2 = H.update_state_fields(probe_field=1)
        finally:
            H.load_state_strict = o_ls
        if r2 is not False:
            return "乐观锁撞车时仍返回 %r（应 False ⇒ 不许把'被覆盖'当成功）" % (r2,)
        subs = [k.get("subkind") for (_a, k) in recs if _a and _a[1] == "host_shield_state_write_refused"]
        if "optimistic_lock_lost" not in subs:
            return "乐观锁撞车没进链留痕（subkind 应为 optimistic_lock_lost）：%r" % (subs,)
        return True
    finally:
        os.environ.pop("ANTINEL_HUB_DIR", None)


# ══════════════ 丙 · S77 名片租约：进程号复用 ⇒ 判不在岗 ══════════════
@check("S77 ★ 丙：伪造进程号已死但心跳新鲜 ⇒ 判不在岗（须同时比对启动时刻）")
def s77():
    hub = _tmp_hub("g0450_s77_")
    H = _load_hs("hs_s77", hub)
    try:
        me = os.getpid()
        # ① 名片记的启动时刻与实际不符（差 1 天）⇒ 判 pid-reused（进程号复用）
        H.write_sentinel_card(pid=me, started_at="2020-01-01T00:00:00")
        on, why = H.sentinel_on_duty({"sentinel_pid": me})
        if on is not False or why != "pid-reused":
            return ("启动时刻不符时 `sentinel_on_duty` 返回 (%r, %r)（应为 (False,'pid-reused')）"
                    " ⇒ 光看 pid 会误判在岗" % (on, why))
        # ② 进程已死（用一个几乎不可能存在的 pid）⇒ 判不在岗
        on2, why2 = H.sentinel_on_duty({"sentinel_pid": 999999})
        if on2 is not False:
            return "进程已死时仍判在岗（%r）—— 名片没起到否证作用" % (on2,)
        return True
    finally:
        os.environ.pop("ANTINEL_HUB_DIR", None)


@check("N-S77 负控：抽掉'启动时刻比对'（只认 pid 活）⇒ 伪造进程号被误判在岗 ⇒ S77 必红")
def n_s77():
    hub = _tmp_hub("g0450_ns77_")
    H = _load_hs("hs_ns77", hub)
    try:
        me = os.getpid()
        H.write_sentinel_card(pid=me, started_at="2020-01-01T00:00:00")
        # 变异：把"启动时刻不符 ⇒ 不在岗"整支摘掉（等价于只看 pid 活）
        src = _src(_HS)
        anchor = 'if abs(real - rec) > SENTINEL_CARD_START_TOL:'
        if anchor not in src:
            return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效"
        mut = src.replace(anchor, 'if False:')
        mod = types.ModuleType("hs_ns77_mut")
        mod.__file__ = os.path.join(ROOT, _HS)
        exec(compile(mut, mod.__file__, "exec"), mod.__dict__)    # noqa: S102
        on, why = mod.sentinel_on_duty({"sentinel_pid": me})
        # 负控的**预期**：摘掉启动时刻比对后，伪造的进程号会被**误判在岗**（on=True）。
        # 若摘掉之后仍判不在岗 ⇒ 说明该比对没被真正依赖 ⇒ 负控自身失效。
        if on is not True:
            return ("负控失效：摘掉启动时刻比对后仍判不在岗（%r,%r）"
                    " ⇒ 该比对没被真正依赖" % (on, why))
        return True
    finally:
        os.environ.pop("ANTINEL_HUB_DIR", None)


# ══════════════ 丙 · S78 并发读永远读不到半截内容 ══════════════
#: ★ 真进程（纪律 10.7）：读者/写者都调**产品自己的**实现 ——
#:   写者 = `host_shield._replace_with_retry`（临时文件 + 原子替换，带重试）；
#:   读者 = `host_shield.read_sentinel_card`（含瞬时共享冲突重试）。
#:   起跑栅栏（`.rgo`）：读者先就位，写者才开始写 ⇒ 两者**真的重叠**（不靠时序碰运气）。
_RW_CHILD = r'''
import json, os, sys, time
root, mode, path, iters, who = (sys.argv[1], sys.argv[2], sys.argv[3],
                                int(sys.argv[4]), sys.argv[5])
sys.path.insert(0, root)
import host_shield as HS          # 读者/写者共用产品实现，避免"测了个赝品"

if who == "writer":
    payload = {"pid": 1234, "started_at": "2026-01-01T00:00:00", "pad": "x" * 40000}
    while not os.path.exists(path + ".rgo"):        # 起跑栅栏：等读者进入读循环
        time.sleep(0.002)
    err = None
    try:
        for _ in range(iters):
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            if mode == "atomic":
                HS._replace_with_retry(tmp, path)   # 产品函数：原子替换（带重试）
            elif mode == "atomic_norety":
                os.replace(tmp, path)               # 裸替换（无重试）：负控 N-S78b 用
            else:
                # 非原子写：先截断、再（隔一小会）写 —— 读者必然能撞见半截
                with open(path, "w", encoding="utf-8") as f:
                    f.write("")
                time.sleep(0.003)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(payload, f)
    except Exception as e:
        err = repr(e)
    finally:
        if err is not None:
            try:
                with open(path + ".werr", "w", encoding="utf-8") as f:
                    f.write(err)
            except Exception:
                pass
        try:
            open(path + ".done", "w").close()       # 无论成败都放行读者（否则读者挂死）
        except Exception:
            pass
else:
    bad = 0
    seen = 0
    try:
        open(path + ".rgo", "w").close()            # 通知写者：读者已就位
    except Exception:
        pass
    deadline = time.time() + 90
    while not os.path.exists(path + ".done") and time.time() < deadline:
        card = HS.read_sentinel_card(path)          # 产品读取路径（含瞬时冲突重试）
        if card is None:
            bad += 1                                # 文件在、却读不出完整名片 ⇒ 半截/瞬失
        else:
            seen += 1
    print(json.dumps({"bad": bad, "seen": seen}))
'''


def _run_rw(mode, iters=200):
    """起一对**真进程**（读者 + 写者，带起跑栅栏）跑同一张名片文件。

    返回 {"bad", "seen", "werr"}：bad=读者撞见半截/读不出的次数；seen=成功读到的次数；
    werr=写者异常串（写者崩了 ⇒ 读者保护再漂亮也无意义，调用方必须当红）。
    """
    d = _TMP.tmpdir(prefix="g0450_rw_")
    child = os.path.join(d, "rw.py")
    with io.open(child, "w", encoding="utf-8") as f:
        f.write(_RW_CHILD)
    path = os.path.join(d, "card.json")
    with io.open(path, "w", encoding="utf-8") as f:
        f.write("{}")
    env = dict(os.environ)
    env["ANTINEL_HUB_DIR"] = d                       # 隔离：子进程别碰真中枢
    r = subprocess.Popen([sys.executable, child, ROOT, mode, path, str(iters), "reader"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    w = subprocess.Popen([sys.executable, child, ROOT, mode, path, str(iters), "writer"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    try:
        out, _ = r.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        r.kill()
        w.kill()
        raise AssertionError("并发读子进程超时（写者未放行 / 读者未退出）")
    try:
        w.wait(timeout=120)
    except subprocess.TimeoutExpired:
        w.kill()
        raise AssertionError("并发写子进程超时")
    werr = None
    if os.path.exists(path + ".werr"):
        with io.open(path + ".werr", encoding="utf-8") as f:
            werr = f.read().strip()
    try:
        st = json.loads(out.decode("utf-8", "replace").strip().splitlines()[-1])
    except Exception:
        st = {"bad": -1, "seen": -1}
    st["werr"] = werr
    return st


@check("S78 ★ 丙：并发读永远读不到半截内容（临时文件 + 原子替换）")
def s78():
    st = _run_rw("atomic")
    if st["werr"]:
        return ("并发写子进程失败（产品原子替换被并发读打断）：%s ⇒ 写者保护不成立"
                % st["werr"])
    if st["bad"] != 0:
        return ("原子替换下并发读仍读到 %d 次半截/读不出内容（seen=%d）⇒ 读者保护不成立"
                % (st["bad"], st["seen"]))
    if st["seen"] <= 0:
        return "并发读一次都没成功读到内容（seen=0）⇒ 测试没真跑起来（假绿）"
    return True


@check("N-S78 负控：换成非原子写（截断后再写）⇒ 并发读必撞见半截（证明本测试有分辨力）")
def n_s78():
    st = _run_rw("direct")
    if st["bad"] <= 0:
        return ("负控失效：非原子写下并发读一次半截都没撞见（bad=%d, seen=%d）"
                " ⇒ 本测试测不出'非原子'（分辨力不足）" % (st["bad"], st["seen"]))
    return True


@check("N-S78b 负控：写者用裸 os.replace（不重试）⇒ 被并发读打断 ⇒ 证明重试是承重的")
def n_s78b():
    st = _run_rw("atomic_norety")
    if not st["werr"]:
        return ("负控失效：写者不重试也没被并发读打断（bad=%d, seen=%d）"
                " ⇒ 证明不了'重试'是承重的（可能是摆设）" % (st["bad"], st["seen"]))
    return True


# ══════════════ 连带对照 S79 · 既有保护仍绿 ══════════════
@check("S79 ★ 连带对照：拒写保护仍成立（坏状态文件 ⇒ 拒写且字节不变）")
def s79():
    hub = _tmp_hub("g0450_s79_")
    H = _load_hs("hs_s79", hub)
    try:
        with io.open(H.state_path(), "w", encoding="utf-8") as f:
            f.write("{ 半截的写入")
        with io.open(H.state_path(), "rb") as f:
            before = f.read()
        H.record = lambda *a, **k: None
        r = H.update_state_fields(sentinel_pid=12345)
        with io.open(H.state_path(), "rb") as f:
            after = f.read()
        if r is not False:
            return "坏状态文件上返回 %r（应 False）⇒ 拒写保护被破坏" % (r,)
        if after != before:
            return "拒写失败：字节变了（应逐字节不变）⇒ 源②会复发"
        return True
    finally:
        os.environ.pop("ANTINEL_HUB_DIR", None)


def main():
    print("=" * 78)
    print("0.45.0 判据 —— 状态写入：整份写回=0 / 返回值不许忽略 / 真进程互斥 / 名片租约")
    print("（甲/乙/丙；变异只在内存，并发起真进程）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                why = ""
            print("  ✅ %-62s %s" % (name, why or ""))
            ok += 1
        except AssertionError as e:
            print("  ❌ %-62s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-62s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
