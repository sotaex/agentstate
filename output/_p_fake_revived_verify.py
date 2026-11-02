# -*- coding: utf-8 -*-
"""验证 already-running 不再写 host_shield_revived（2026-11-02）。

背景：7 日窗口 132 条 revived 中有 5 条 spawn_mode=already-running，
      旧进程号 == 新进程号，reason 却说「曾不在岗、已重新拉起」。
      那 5 条来自 ensure_alive 的两处写入点，两处都未判 mode。

本脚本两个方向都测（缺一不可）：
  A  already-running ⇒ 不写 revived、返回 alive      （不该写的不许写）
  B  detached        ⇒ 写 revived、返回 revived      （该写的必须写，防「一刀切删掉」）
  C  stale 分支（critical）同样两条
  D  结构腿：源码里两处判断都还在 record 之前

★ 全程打桩，不真的起进程、不碰真链。
"""
import io
import json
import os
import sys
import tempfile
import time
import datetime

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, ROOT)
import host_shield as HS                                    # noqa: E402

FAILS = []


def chk(name, ok, detail=""):
    print(("  OK   " if ok else "  RED  ") + name + (("   " + detail) if detail else ""))
    if not ok:
        FAILS.append(name)


def _iso(hours_ago=0.0):
    t = datetime.datetime.now() - datetime.timedelta(hours=hours_ago)
    return t.isoformat(timespec="seconds")


def _chain_dir(pkg):
    return HS._shield_audit_dir(pkg)


def _write(adir, rec):
    os.makedirs(adir, exist_ok=True)
    p = os.path.join(adir, time.strftime("%Y-%m-%d") + ".jsonl")
    with io.open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _revived_count(adir):
    n = 0
    if not os.path.isdir(adir):
        return 0
    for fn in os.listdir(adir):
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


def probe(mode, branch):
    """branch: 'plain' 走第二处（warning），'stale' 走第一处（critical）。

    ★★ 2026-11-02 血的教训（本脚本第一版真的污染了中枢链）：
      `_shield_audit_dir(pkg)` 在包根**没有 .psl** 时会回退到个人中枢 rollup。
      第一版用裸的临时目录 ⇒ 审计目录落到了真链 ⇒ 6 条桩记录写进
      `~/.antinel/rollup/<今天>.jsonl`（pid 4242 是桩值，没有这个进程）。
      ⇒ 现在两件事一起做：pkg 下建 .psl、ANTINEL_HUB_DIR 指到临时目录，
        并**先断言 adir 在 pkg 之下**，不成立就立刻退出、一个字节都不写。
    """
    base = tempfile.mkdtemp(prefix="rev5_", dir=os.environ.get("TEMP") or None)
    pkg = os.path.join(base, "pkg")
    os.makedirs(os.path.join(pkg, ".psl"), exist_ok=True)
    os.environ["ANTINEL_HUB_DIR"] = os.path.join(base, "hub")
    adir = _chain_dir(pkg)
    if not os.path.abspath(adir).startswith(os.path.abspath(pkg)):
        raise SystemExit("拒绝执行：审计目录没落在临时包里（%r），"
                         "继续写会污染真链" % adir)
    _write(adir, {"ts": _iso(0), "type": "host_shield_changed",
                  "field": "enabled", "armed": True, "change": "false → true"})
    HS.save_state({"enabled": True, "workspaces": {}, "zones": [], "windows": {},
                   "sentinel_pid": 4242, "sentinel_started_at": time.time() - 99999,
                   "last_revive_attempt": 0})

    if branch == "plain":
        # 第一次判「不在岗」，之后（spawn 内部复查）判「在岗」——
        # 这正是 5 条假记录的成因：同一事实两处实现，结论不一致。
        seq = [False]
        alive = lambda st: (seq.pop(0) if seq else True)
        hb = lambda *a, **k: (99999.0, _iso(240))
    else:
        # 进程活着但心跳陈旧 ⇒ 判僵死，走 kill + 重拉
        alive = lambda st: True
        hb = lambda *a, **k: (99999.0, _iso(240))

    saved = {k: getattr(HS, k) for k in
             ("sentinel_alive", "spawn_sentinel", "subprocess", "sentinel_on_duty",
              "_heartbeat_age_in", "_pid_image", "pid_alive")}
    HS.sentinel_alive = alive
    HS._heartbeat_age_in = hb
    HS.sentinel_on_duty = lambda st: (True, "")
    HS._pid_image = lambda pid: "python.exe"
    HS.pid_alive = lambda pid: True
    HS.spawn_sentinel = lambda root, python_exe=None: (True, 4242, mode)

    class _R(object):
        returncode = 0

    HS.subprocess = type("S", (), {"run": staticmethod(lambda *a, **k: _R())})()
    time.sleep, _sleep_saved = (lambda *a, **k: None), time.sleep
    try:
        r = HS._ensure_alive_locked(pkg, cause="guard")
        return r, _revived_count(adir)
    finally:
        time.sleep = _sleep_saved
        for k, v in saved.items():
            setattr(HS, k, v)


print("== A  already-running（普通分支，5 条假记录的来源）==")
r, n = probe("already-running", "plain")
chk("返回 alive（如实说在岗）", r == "alive", "got=%r" % r)
chk("链上不多出 revived", n == 0, "revived=%d" % n)

print("== B  detached（真重启，防「一刀切删掉」）==")
r, n = probe("detached", "plain")
chk("返回 revived", r == "revived", "got=%r" % r)
chk("链上写入 1 条 revived", n == 1, "revived=%d" % n)

print("== C  stale 分支（critical，第一处写入点）==")
r, n = probe("already-running", "stale")
chk("返回 alive", r == "alive", "got=%r" % r)
chk("链上不多出 revived", n == 0, "revived=%d" % n)
r, n = probe("detached", "stale")
chk("对照组：返回 stale-revived", r == "stale-revived", "got=%r" % r)
chk("对照组：写入 1 条 revived", n == 1, "revived=%d" % n)

print("== D  结构腿：两处判断都在，「判断在 record 之前」==")
src = io.open(os.path.join(ROOT, "host_shield.py"), encoding="utf-8").read()
needle = 'ok and mode == "already-running"'
chk("判断出现两次（两处写入点各一）", src.count(needle) == 2,
    "count=%d" % src.count(needle))
for i, pos in enumerate([m for m in range(len(src)) if src.startswith(needle, m)]):
    rec_pos = src.find('record(audit_dir, "host_shield_revived"', pos)
    chk("第 %d 处：判断在 record 之前（同分支内）" % (i + 1),
        rec_pos > pos and rec_pos - pos < 700, "gap=%d" % (rec_pos - pos))

print()
if FAILS:
    print("RED %d 条：" % len(FAILS))
    for f in FAILS:
        print("  -", f)
    sys.exit(1)
print("PASS：already-running 不再写 revived；真重启照常写")
