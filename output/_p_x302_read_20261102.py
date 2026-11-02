# -*- coding: utf-8 -*-
"""X3-02 改读「假重启计数」之后的两窗口读数（只读，不改任何东西）。

★ 验收线怎么定（这条改过一次，第一版定错了，记在这里）：
  第一版写的是「7 日窗口应为 0」，实测是 5 ⇒ 报了「不通过」。
  查下去发现那 5 条的时间戳全部早于修复落盘时刻 —— **错的是验收线，不是代码**：
  7 日窗口从 10-27 起算，跨越修复时刻，它问的是「最近七天发生过什么」，
  而我想问的是「修好之后还发生过吗」。窗口起点 ≠ 修复时刻。
  ⇒ 正确的线：**修复时刻之后必须为 0**。修复时刻从 git 推导（取
    host_shield.py 最近一次提交），**不写死日期** —— 写死日期的话，下次再改
    一遍这个探针就得跟着改，而忘改的那次会静默用旧日期判。

要看的天然对照：
  30 日窗口 revived_already_running_n 应 > 0（历史假记录还在，属真现象）
  修复时刻之后的假重启数必须 == 0（修复生效）
"""
import importlib.util as ilu
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLOTS = os.path.join(ROOT, "scripts", "slots.py")

spec = ilu.spec_from_file_location("antinel_slots_probe", SLOTS)
mod = ilu.module_from_spec(spec)
spec.loader.exec_module(mod)

reg = mod.load_registry(ROOT)
by_id = mod.slots_by_id(reg)
slot = by_id["SLOT-049"]
pname = slot.get("probe")
print("SLOT-049 名称: %s   probe=%s" % (slot.get("name"), pname))
print("  谓词: %s" % json.dumps(slot.get("predicate"), ensure_ascii=False))
print("  triage: %s" % json.dumps(slot.get("triage"), ensure_ascii=False))
print("  why_partial: %s" % str(slot.get("why_partial") or "")[:160])
print()

rows = []
for days in (30, 7):
    ctx = mod.Context(ROOT, max_days=days, history_days=0, read_history=False)
    raw = mod.PROBES[pname](ctx)
    res = mod.evaluate(slot, ctx)
    rows.append((days, raw, res))

print("=" * 78)
for days, raw, res in rows:
    print("[%2d 日窗口]  状态=%s  match_kind=%s" % (
        days, res.get("state"), res.get("match_kind")))
    print("  snippet: %s" % res.get("snippet"))
    if isinstance(raw, dict):
        for k in ("revived_already_running_n", "revived_modes", "revived_n",
                  "revived_after_stop"):
            if k in raw:
                print("  %-28s %r" % (k, raw[k]))
    else:
        print("  原始读数: %r" % (raw,))
    print()

n30 = (rows[0][1] or {}).get("revived_already_running_n") if isinstance(rows[0][1], dict) else None
n7 = (rows[1][1] or {}).get("revived_already_running_n") if isinstance(rows[1][1], dict) else None

# ── 修复时刻（从 git 推导，不写死日期）──────────────────────────────
import re
import subprocess


def _fix_ts():
    """修复时刻 = 作者时刻与提交时刻中**较早**的那个。

    ★ 为什么取较早的：代码是先落盘、后提交的（实测今天 13:38 落盘、14:26 提交）。
      取晚的那个，会把 13:38–14:26 之间的记录一律算成「修复前」，方向偏宽松 ——
      万一那 48 分钟里出过一条假重启，它会被静默放过。
      取较早的只会让判据更严（更多记录被算成「修复后」），错也只错在宁可报红。
    """
    try:
        r = subprocess.run(["git", "log", "-1", "--format=%aI %cI", "--", "host_shield.py"],
                           cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=20)
        parts = [p for p in (r.stdout or "").split() if p]
        return min(parts) if parts else None
    except Exception:                                            # noqa: BLE001
        return None


FIX_TS = _fix_ts()

# ── 全部 already-running 记录的时间戳（30 日窗口内）──────────────────
import glob as _glob
_audit = os.path.join(ROOT, ".psl", "audit")
_fakes = []
for _f in sorted(_glob.glob(os.path.join(_audit, "*.jsonl"))):
    if not re.match(r"^\d{4}-\d{2}-\d{2}\.jsonl$", os.path.basename(_f)):
        continue
    for _ln in open(_f, encoding="utf-8", errors="replace"):
        _ln = _ln.strip()
        if not _ln:
            continue
        try:
            _r = json.loads(_ln)
        except Exception:                                        # noqa: BLE001
            continue
        if _r.get("type") != "host_shield_revived":
            continue
        if _r.get("spawn_mode") != "already-running":
            continue
        _fakes.append(str(_r.get("ts") or ""))

print("=" * 78)
print("对照判定：")
print("  30 日 revived_already_running_n = %r  （期望 > 0，历史假记录可见）" % (n30,))
print("   7 日 revived_already_running_n = %r  （仅陈述，不作验收线）" % (n7,))
print("  修复时刻（git 推导）= %r" % (FIX_TS,))
print("  全链假重启记录 = %d 条，最早 %s ／ 最晚 %s" % (
    len(_fakes), min(_fakes) if _fakes else "-", max(_fakes) if _fakes else "-"))

if FIX_TS and _fakes:
    _after = [t for t in _fakes if t[:19] >= FIX_TS[:19]]
    print("  修复之后的假重启 = %d 条" % len(_after))
    for t in _after:
        print("     仍在发生:", t)
    print()
    if _after:
        print("  ⇒ **不通过**：修复之后仍有假重启 ⇒ 还有写入点没堵住，别提交")
    elif not n30:
        print("  ⇒ **可疑**：修复后为 0，但 30 日窗口也是 0 ⇒ 判据可能恒 clean，"
              "须查窗口读法（先断 before>0 再谈 after==0）")
    else:
        print("  ⇒ **通过**：修复后 0 条，且 30 日窗口仍有 %d 条历史假记录可读 ——"
              " 判据既能看见历史，也能证明修复" % n30)
else:
    print("  ⇒ **无法定论**：拿不到修复时刻或链上无假重启记录")
    print("     修复时刻为空 ⇒ 可能是浅克隆或不在 git 里；链上为空 ⇒ 先确认读到了链")
