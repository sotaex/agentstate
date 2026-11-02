# -*- coding: utf-8 -*-
"""负控：把 already-running 判断摘掉后，探针必须变红（2026-11-02）。

★ 为什么必须做：一条「永远通过」的检查与「真的有效」长得一模一样。
  本脚本用**内存变异**（不改产品文件）：把两处 `ok and mode == "already-running"`
  改成 `False and ...`，重跑 A 场景，要求它**又写出 revived**。
  如果变异后仍然不写 ⇒ 说明探针根本没走到那条分支，「通过」是假的。

★ 同时验证：变异确实改了字节（断言替换次数 == 2）。
"""
import io
import json
import os
import sys
import tempfile
import time
import datetime
import types

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, ROOT)
import host_shield as HS                                    # noqa: E402

FAILS = []
NEEDLE = 'if ok and mode == "already-running":'
MUT = 'if False and mode == "already-running":'


def chk(name, ok, detail=""):
    print(("  OK   " if ok else "  RED  ") + name + (("   " + detail) if detail else ""))
    if not ok:
        FAILS.append(name)


def _iso(hours_ago=0.0):
    return (datetime.datetime.now() - datetime.timedelta(hours=hours_ago)
            ).isoformat(timespec="seconds")


def _revived_count(adir):
    n = 0
    for fn in (os.listdir(adir) if os.path.isdir(adir) else []):
        if not fn.endswith(".jsonl"):
            continue
        for line in io.open(os.path.join(adir, fn), encoding="utf-8", errors="replace"):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("type") == "host_shield_revived":
                n += 1
    return n


def load_mutant():
    src = io.open(os.path.join(ROOT, "host_shield.py"), encoding="utf-8").read()
    n = src.count(NEEDLE)
    mut = src.replace(NEEDLE, MUT)
    # ★ 断言「真的改了字节」——变异没落地时，负控会假绿
    if n != 2 or mut.count(MUT) != 2 or mut == src:
        raise SystemExit("变异没生效：needle 出现 %d 次（应为 2）" % n)
    print("  变异已落地：2 处判断改为 False")
    mod = types.ModuleType("hs_mutant")
    mod.__file__ = HS.__file__
    mod.__name__ = "hs_mutant"
    exec(compile(mut, HS.__file__, "exec"), mod.__dict__)
    return mod


def probe(mod, mode):
    """在给定模块上跑 A 场景（already-running），返回 (结果, revived 条数)。"""
    base = tempfile.mkdtemp(prefix="neg5_", dir=os.environ.get("TEMP") or None)
    pkg = os.path.join(base, "pkg")
    os.makedirs(os.path.join(pkg, ".psl"), exist_ok=True)
    os.environ["ANTINEL_HUB_DIR"] = os.path.join(base, "hub")
    adir = mod._shield_audit_dir(pkg)
    if not os.path.abspath(adir).startswith(os.path.abspath(pkg)):
        raise SystemExit("审计目录没落在临时包里，拒绝继续")
    os.makedirs(adir, exist_ok=True)
    with io.open(os.path.join(adir, time.strftime("%Y-%m-%d") + ".jsonl"),
                 "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": _iso(0), "type": "host_shield_changed",
                            "field": "enabled", "armed": True,
                            "change": "false → true"}, ensure_ascii=False) + "\n")
    mod.save_state({"enabled": True, "workspaces": {}, "zones": [], "windows": {},
                    "sentinel_pid": 4242, "sentinel_started_at": time.time() - 99999,
                    "last_revive_attempt": 0})
    seq = [False]
    saved = {k: getattr(mod, k) for k in
             ("sentinel_alive", "spawn_sentinel", "subprocess", "sentinel_on_duty",
              "_heartbeat_age_in", "_pid_image", "pid_alive")}
    mod.sentinel_alive = lambda st: (seq.pop(0) if seq else True)
    mod._heartbeat_age_in = lambda *a, **k: (99999.0, _iso(240))
    mod.sentinel_on_duty = lambda st: (True, "")
    mod._pid_image = lambda pid: "python.exe"
    mod.pid_alive = lambda pid: True
    mod.spawn_sentinel = lambda root, python_exe=None: (True, 4242, mode)

    class _R(object):
        returncode = 0

    mod.subprocess = type("S", (), {"run": staticmethod(lambda *a, **k: _R())})()
    _sl, time.sleep = time.sleep, (lambda *a, **k: None)
    try:
        return mod._ensure_alive_locked(pkg, cause="guard"), _revived_count(adir)
    finally:
        time.sleep = _sl
        for k, v in saved.items():
            setattr(mod, k, v)


print("== 1  对照组：未变异的模块 ==")
r, n = probe(HS, "already-running")
chk("返回 alive", r == "alive", "got=%r" % r)
chk("不写 revived", n == 0, "revived=%d" % n)

print("== 2  变异组：摘掉判断 ==")
mut = load_mutant()
r2, n2 = probe(mut, "already-running")
chk("退回旧行为：写出了 revived", n2 == 1, "revived=%d" % n2)
chk("（旧行为下返回值也变）", r2 != "alive", "got=%r" % r2)

print("== 3  分辨力 ==")
chk("正反两组的 revived 条数不同 ⇒ 这条检查不是摆设", n != n2,
    "未变异=%d 变异=%d" % (n, n2))

print()
if FAILS:
    print("RED %d 条：" % len(FAILS))
    for f in FAILS:
        print("  -", f)
    sys.exit(1)
print("PASS：负控咬住了——摘掉判断，假记录就会重新出现")
