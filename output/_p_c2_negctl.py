#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""C 线负控总表：巡检 6 个检测器 ＋ 对账 A4 ＋ 规则 id 归一，各自「改对了会响、没改不响」。

负控的判据不是「结果不同」，是「**真的改了字节、且只改了这一处**」：

  · 正向臂：篡改副本 -> 指定 kind 必须出现，且 subject 里必须能看见被改的那个值；
  · 负向臂：同一份副本不动 -> 同一 kind 必须**不**出现。

只做正向臂，检测器写成 `return [Clue(...)]` 也照样通过；
只做负向臂，「永远返回 []」也照样通过。两条臂缺一不可。

另一条负向臂（防「首次出现」退化成「今天出现过的都算」）：
  往副本里注入一个**历史上已有**的命令（git），它不许被报成首次出现。

四件套（铁律 9）在这里的落法：
  ①正判据   = 篡改后指定 kind / 字段必须出现；
  ②反向对照 = 同一份副本不动时必须不出现；
  ③连带对照 = 既有维度（A1/A2/A3/A5、其它检测器）不许被静默改动；
  ④自报活跃 = 每个检测器必须在 coverage 里申报状态，缺一个当场抛。

一次性量具，不进发布包、不进 ci/。
用法：python output/_p_c2_negctl.py
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Tuple

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "output", "lineC"))
import watchman as W  # noqa: E402  配对候选/覆盖键都从这里取，不另写一套
WATCH = os.path.join(REPO, "output", "lineC", "watchman.py")
SRC = os.path.join(REPO, ".psl", "audit")

# 基线检测要 >= max(5, window//2) 天前置样本，9 个日文件给 8 天，够。
N_FILES = 9
GAP_FROM, GAP_TO = "T09:30:00", "T11:30:00"  # 只在这段里挖洞，避开真实的 14:29/17:10 断层
GAP_ASSERT_MIN = 90.0  # 篡改后必须出现 >= 90 分钟的断层（干净臂最长 40 分钟）


def sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def run(root: str, recent: int = 1) -> Dict[str, Any]:
    p = subprocess.run(
        [sys.executable, WATCH, "--root", root, "--json", "--recent", str(recent)],
        cwd=REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if p.returncode != 0:
        raise RuntimeError(f"watchman 退出 {p.returncode}: {(p.stderr or '')[:400]}")
    return json.loads(p.stdout)


AUDIT = os.path.join(REPO, "output", "lineC", "auditor.py")


def run_audit(root: str) -> Dict[str, Any]:
    p = subprocess.run(
        [sys.executable, AUDIT, "--root", root, "--json"],
        cwd=REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    # 有 FAIL 时 auditor 退出码 1，属正常，不是崩溃
    if p.returncode not in (0, 1):
        raise RuntimeError(f"auditor 退出 {p.returncode}: {(p.stderr or '')[:400]}")
    return json.loads(p.stdout)


def dim(res: Dict[str, Any], name: str) -> Dict[str, Any]:
    for f in res["findings"]:
        if f["dim"].startswith(name):
            return f
    raise KeyError(name)


def a4_count(res: Dict[str, Any]) -> int:
    d = dim(res, "A4")
    m = re.match(r"^(\d+) 处", d["detail"])
    return int(m.group(1)) if m else 0


def kinds(res: Dict[str, Any], kind: str) -> List[Dict[str, Any]]:
    return [c for c in res["clues"] if c["kind"] == kind]


def prepend_nl(path: str) -> None:
    """原文件末尾没换行时补一个，否则追加的第一行会粘在最后一条记录上。"""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        if fh.tell() == 0:
            return
        fh.seek(-1, os.SEEK_END)
        last = fh.read(1)
    if last != b"\n":
        with open(path, "ab") as fh:
            fh.write(b"\n")


def max_ts(path: str, day: str) -> str:
    pat = re.compile(r'"ts":\s*"([^"]+)"')
    best = f"{day}T00:00:00+08:00"
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = pat.search(line)
            if m and m.group(1) > best:
                best = m.group(1)
    return best


def bump_ts(ts: str, sec: int) -> str:
    """不引 datetime —— 只把 HH:MM:SS 抬 sec 秒，跨零点在负控里不会发生。"""
    m = re.match(r"^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(.*)$", ts)
    if not m:
        return ts
    h, mi, s = int(m.group(2)), int(m.group(3)), int(m.group(4)) + sec
    mi += s // 60
    s %= 60
    h += mi // 60
    mi %= 60
    return f"{m.group(1)}T{h:02d}:{mi:02d}:{s:02d}{m.group(5)}"


def append_rec(path: str, rec: Dict[str, Any]) -> None:
    prepend_nl(path)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def resync_manifest(root: str, day: str) -> str:
    """把日锚重算到与实际文件一致 —— 让负控只改**一处**。

    不重算的话，往目标日追加一条记录会顺带把 anchor 的 size/hash 打红。
    那正是 anchor 该做的事；但作为 verdict 臂的伴随噪声，它会掩盖
    「verdict 到底响没响」。所以：改完账本就把锚同步，只留一个变量。
    """
    man_path = os.path.join(root, "day_manifest.json")
    day_path = os.path.join(root, f"{day}.jsonl")
    with open(man_path, "r", encoding="utf-8") as fh:
        man = json.load(fh)
    last_hash = None
    with open(day_path, "r", encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                r = json.loads(ln)
            except Exception:
                continue
            if isinstance(r, dict) and isinstance(r.get("hash"), str) and r["hash"]:
                last_hash = r["hash"]
    e = man.setdefault(f"{day}.jsonl", {})
    e["size"] = os.path.getsize(day_path)
    if last_hash:
        e["last_hash"] = last_hash
    with open(man_path, "w", encoding="utf-8") as fh:
        json.dump(man, fh, ensure_ascii=False, indent=1)
    return f"锚已同步（size={e['size']}）"


def m_verdict_out(path: str, day: str) -> str:
    ts = bump_ts(max_ts(path, day), 3)
    append_rec(
        path,
        {
            "ts": ts,
            "type": "pre_tool_use",
            "tool": "Bash",
            "session": "nc-verdict",
            "decision": "allow",
            "action": "block",
            "input": {"command": "nc_verdict_probe", "content_len": 0},
        },
    )
    return "注入 decision=allow + action=block（表外组合）｜" + resync_manifest(
        os.path.dirname(path), day
    )


def m_verdict_badval(path: str, day: str) -> str:
    ts = bump_ts(max_ts(path, day), 4)
    append_rec(
        path,
        {
            "ts": ts,
            "type": "pre_tool_use",
            "tool": "Bash",
            "session": "nc-verdict",
            "decision": "quarantine",
            "action": "alert",
            "input": {"command": "nc_verdict_badval", "content_len": 0},
        },
    )
    return "注入 decision=quarantine（值域外）｜" + resync_manifest(os.path.dirname(path), day)


def m_verdict_legal(path: str, day: str) -> str:
    """合法组合：allow + alert = 「放行但又告警」，**不许**报成矛盾。"""
    ts = bump_ts(max_ts(path, day), 5)
    append_rec(
        path,
        {
            "ts": ts,
            "type": "notice_budget_merged",
            "tool": "-",
            "session": "nc-verdict",
            "decision": "allow",
            "action": "alert",
            "reason": "nc 合法组合探针",
        },
    )
    return "注入 decision=allow + action=alert（合法：放行但告警）｜" + resync_manifest(
        os.path.dirname(path), day
    )


def _anchor_bump(path: str, which: int, field: str) -> str:
    """改锚里的 size 或 last_hash。which=-1 当天，-2 最近一个已封盘日。

    当天与封盘日**语义不同**，必须分开测：
      封盘日 size 要求严格相等（封盘后不该再长）；
      当天 size 只抓变短（追加是正常的）。
      当天末条 hash 随时在变 ⇒ 根本不比。
    """
    with open(path, "r", encoding="utf-8") as fh:
        man = json.load(fh)
    k = sorted(man)[which]
    e = man[k]
    if field == "size":
        old = e.get("size")
        e["size"] = (old or 0) + 1
        desc = f"{k} 的锚 size {old} -> {e['size']}（文件没动）"
    else:
        old = e.get("last_hash")
        e["last_hash"] = "0" * 64
        desc = f"{k} 的锚 last_hash 改成 000…（原 {str(old)[:8]} 起）"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(man, fh, ensure_ascii=False, indent=1)
    return desc


def m_anchor_size_closed(path: str) -> str:
    return _anchor_bump(path, -2, "size")


def m_anchor_size_live(path: str) -> str:
    return _anchor_bump(path, -1, "size")


def m_anchor_hash_closed(path: str) -> str:
    return _anchor_bump(path, -2, "last_hash")


def m_anchor_hash_live(path: str) -> str:
    return _anchor_bump(path, -1, "last_hash")


def m_anchor_orphan(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        man = json.load(fh)
    man["2026-01-01.jsonl"] = {"size": 1, "last_hash": "f" * 64, "updated_at": "2026-01-01T00:00:00"}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(man, fh, ensure_ascii=False, indent=1)
    return "给不存在的 2026-01-01.jsonl 加一条锚（模拟账本被删）"


def m_anchor_missing(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        man = json.load(fh)
    k = sorted(man)[-1]
    del man[k]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(man, fh, ensure_ascii=False, indent=1)
    return f"删掉 {k} 的锚条目（该日记录**有** hash ⇒ 本该挂上）"


def m_anchor_nohash(path: str) -> str:
    """删锚 **且** 把该日记录的 hash 全抹掉 ⇒ 应判「锚无处可挂」，不是「漏了」。

    这一臂守的是铁律 45：「没有的东西不能报成失败」。
    只删锚不抹 hash，这个检测器就会把「数据形态不支持」报成「产品漏了」。
    """
    day = sorted(json.load(open(path, "r", encoding="utf-8")))[-1][:10]
    with open(path, "r", encoding="utf-8") as fh:
        man = json.load(fh)
    man.pop(f"{day}.jsonl", None)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(man, fh, ensure_ascii=False, indent=1)

    day_path = os.path.join(os.path.dirname(path), f"{day}.jsonl")
    out = []
    stripped = 0
    with open(day_path, "r", encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            ln = ln.rstrip("\n")
            if not ln.strip():
                continue
            try:
                r = json.loads(ln)
            except Exception:
                out.append(ln)
                continue
            if isinstance(r, dict) and "hash" in r:
                r.pop("hash", None)
                stripped += 1
            out.append(json.dumps(r, ensure_ascii=False))
    with open(day_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    return f"删 {day} 的锚 + 抹掉该日 {stripped} 条记录的 hash（模拟旧 schema）"


# --------------------------------------------------------------------- 三处篡改


def m_baseline(path: str) -> str:
    lines = [ln for ln in open(path, "r", encoding="utf-8", errors="replace") if '"pre_tool_use"' in ln]
    n = len(lines)
    if n == 0:
        raise RuntimeError("目标日没有 pre_tool_use 记录，基线负控无从下手")
    prepend_nl(path)
    with open(path, "a", encoding="utf-8") as fh:
        for i in range(n * 9):
            fh.write(lines[i % n])
    return f"pre_tool_use {n} -> {n * 10} 条（追加 {n * 9} 行）"


def m_first_seen_new(path: str, day: str) -> str:
    ts = bump_ts(max_ts(path, day), 1)
    append_rec(
        path,
        {
            "ts": ts,
            "type": "pre_tool_use",
            "tool": "Bash",
            "session": "nc-probe",
            "host": "workbuddy",
            "input": {"command": "zzz_probe_nc --flag", "content_len": 0},
            "content_digest": "sha256:" + "0" * 64,
        },
    )
    return "注入 1 条 command=zzz_probe_nc"


def m_first_seen_old(path: str, day: str) -> str:
    ts = bump_ts(max_ts(path, day), 2)
    append_rec(
        path,
        {
            "ts": ts,
            "type": "pre_tool_use",
            "tool": "Bash",
            "session": "nc-probe",
            "host": "workbuddy",
            "input": {"command": "git status", "content_len": 0},
            "content_digest": "sha256:" + "0" * 64,
        },
    )
    return "注入 1 条 command=git（历史已有，不许报首次出现）"


def m_absent(path: str) -> str:
    """删掉当日全部 post_tool_use —— 模拟「后半个钩子挂了」。"""
    kept, dropped = [], 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if '"post_tool_use"' in line and '"pre_tool_use"' not in line:
                dropped += 1
                continue
            kept.append(line)
    if dropped == 0:
        raise RuntimeError("当日没有 post_tool_use 记录，缺席负控无从下手")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(kept)
    return f"删除当日全部 post_tool_use 共 {dropped} 行"


def m_gap(path: str, day: str) -> str:
    lo, hi = day + GAP_FROM, day + GAP_TO
    pat = re.compile(r'"ts":\s*"([^"]+)"')
    kept: List[str] = []
    dropped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = pat.search(line)
            if m and lo <= m.group(1)[:19] <= hi:
                dropped += 1
                continue
            kept.append(line)
    if dropped == 0:
        raise RuntimeError(f"{day} {GAP_FROM}~{GAP_TO} 之间没有记录，挖不出洞")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(kept)
    return f"删除 {lo}~{hi} 之间的 {dropped} 行"


# --------------------------------------------------------------------- 主流程


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    for p in (WATCH, SRC):
        if not os.path.exists(p):
            print(f"[停] 缺 {p}", file=sys.stderr)
            return 2

    files = sorted(glob.glob(os.path.join(SRC, "2026-*.jsonl")))[-N_FILES:]
    if len(files) < N_FILES:
        print(f"[停] 日文件只有 {len(files)} 个，不够 {N_FILES} 天前置样本", file=sys.stderr)
        return 2
    target = os.path.basename(files[-1])
    day = target[:10]

    work = tempfile.mkdtemp(prefix="antinel-nc-")
    base = os.path.join(work, "base")
    os.makedirs(base)
    for f in files:
        shutil.copy2(f, os.path.join(base, os.path.basename(f)))

    # 日锚必须进副本，否则副本里「缺锚」恒为满盘（9 天全缺），
    # 负控就测不出「有锚／没锚」的区别。
    # 同时**子集化**到被复制的这 9 天：不子集的话，「锚孤儿」会把副本外的
    # 24 天全算成「文件被删了」，干净臂先红，负控就没有基线段可谈了。
    man_src = os.path.join(SRC, "day_manifest.json")
    n_man = 0
    if os.path.exists(man_src):
        with open(man_src, "r", encoding="utf-8") as fh:
            full = json.load(fh)
        keep = {os.path.basename(f) for f in files}
        sub = {k: v for k, v in full.items() if k in keep}
        n_man = len(sub)
        with open(os.path.join(base, "day_manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(sub, fh, ensure_ascii=False, indent=1)

    print("=" * 72)
    print("C-2 巡检负控（watchman.py）")
    print("=" * 72)
    print(f"源     {SRC}")
    print(f"副本   {base}（{len(files)} 个日文件，目标日 {target}）")
    print()

    clean = run(base)
    ck = {
        k: kinds(clean, k)
        for k in ("anchor", "absent", "verdict", "baseline", "repeat", "first_seen", "rule_pair", "gap")
    }
    print(f"干净臂 clues 分布：anchor {len(ck['anchor'])}｜absent {len(ck['absent'])}｜"
          f"verdict {len(ck['verdict'])}｜baseline {len(ck['baseline'])}｜"
          f"repeat {len(ck['repeat'])}｜first_seen {len(ck['first_seen'])}｜"
          f"rule_pair {len(ck['rule_pair'])}｜gap {len(ck['gap'])}")
    print(f"干净臂日锚：副本内 {n_man}/{len(files)} 天有条目"
          f"｜{clean['coverage']['anchor']['note']}")
    clean_max_gap = 0.0
    for c in ck["gap"]:
        m = re.search(r"有 (\d+) 小时 (\d+) 分|有 (\d+) 分", c["subject"])
        if m:
            v = (int(m.group(1)) * 60 + int(m.group(2))) if m.group(1) else int(m.group(3))
            clean_max_gap = max(clean_max_gap, float(v))
    print(f"干净臂最长断层 {clean_max_gap:g} 分钟")
    print()

    results: List[Tuple[str, bool, str]] = []

    def arm(name: str, expect_kind: str, mutate, assert_fn, runner=None) -> None:
        dst = os.path.join(work, name)
        shutil.copytree(base, dst)
        tgt = os.path.join(dst, target)
        before = sha(tgt)
        what = mutate(tgt)
        after = sha(tgt)
        if before == after:
            results.append((name, False, "文件字节没变 —— 篡改根本没生效"))
            print(f"[{name}] 篡改无效：{what}")
            return
        res = (runner or run)(dst)
        ok, detail = assert_fn(res, dst)
        results.append((name, ok, detail))
        # 交叉污染：一处篡改会同时惊动别的检测器（删记录既挖洞也降量）。
        # 只报**相对干净臂新增**的 kind，不报「干净臂本来就有」的 ——
        # 后者会把「一直存在的线索」写成「被这次篡改惊动的」，那是虚报。
        # 交叉污染只在同一个工具内可比：对账的 findings 没有 kind，
        # 拿巡检的基线去比会造出一堆假的「惊动」。
        if runner is None:
            base_n = {k: len(v) for k, v in ck.items()}
            others = [
                f"{k} {base_n.get(k, 0)}->{len(kinds(res, k))}"
                for k in ("anchor", "absent", "verdict", "baseline", "repeat", "first_seen", "rule_pair", "gap")
                if k != expect_kind and len(kinds(res, k)) != base_n.get(k, 0)
            ]
        else:
            others = []
        print(f"[{name}] {what}")
        print(f"         sha {before[:12]} -> {after[:12]}")
        print(f"         {'[OK]' if ok else '[NG]'} {detail}")
        # 交叉污染：一处篡改会同时惊动别的检测器（删记录既挖洞也降量）。
        # 报出来，免得把「响应」读成「精准」。
        if others:
            print(f"         附带惊动：{'、'.join(others)}")
        print()
        shutil.rmtree(dst, ignore_errors=True)

    def arm_file(name: str, expect_kind: str, rel: str, mutate, assert_fn) -> None:
        """篡改**非日文件**（日锚清单）。

        `arm()` 的字节校验盯的是目标日文件，对清单无效 —— 用 arm() 跑清单臂
        会得到「篡改根本没生效」的假 NG，而不是真的 NG。
        """
        dst = os.path.join(work, name)
        shutil.copytree(base, dst)
        path = os.path.join(dst, rel)
        before = sha(path) if os.path.exists(path) else "缺失"
        what = mutate(path)
        after = sha(path) if os.path.exists(path) else "缺失"
        if before == after:
            results.append((name, False, "文件字节没变 —— 篡改根本没生效"))
            print(f"[{name}] 篡改无效：{what}")
            shutil.rmtree(dst, ignore_errors=True)
            return
        res = run(dst)
        ok, detail = assert_fn(res, dst)
        results.append((name, ok, detail))
        base_n = {k: len(v) for k, v in ck.items()}
        others = [
            f"{k} {base_n.get(k, 0)}->{len(kinds(res, k))}"
            for k in ("anchor", "absent", "verdict", "baseline", "repeat", "first_seen", "rule_pair", "gap")
            if k != expect_kind and len(kinds(res, k)) != base_n.get(k, 0)
        ]
        print(f"[{name}] {what}")
        print(f"         sha {str(before)[:12]} -> {str(after)[:12]}")
        print(f"         {'[OK]' if ok else '[NG]'} {detail}")
        if others:
            print(f"         附带惊动：{'、'.join(others)}")
        print()
        shutil.rmtree(dst, ignore_errors=True)

    # ---- NC-1 基线偏离：正向臂 + 负向臂（干净副本）
    def a_baseline(res, _dst):
        hit = kinds(res, "baseline")
        if not hit:
            return False, "篡改后 baseline 仍为 0 条 —— 检测器对 10 倍量变化无反应"
        s = hit[0]["subject"]
        if "偏离" not in s and "全部为" not in s:
            return False, f"baseline 出现了但措辞不对：{s}"
        return True, f"baseline {len(hit)} 条：{s}"

    def a_baseline_clean(_res, _dst):
        n = len(ck["baseline"])
        return (n == 0), (f"干净副本 baseline {n} 条（须为 0）")

    n0 = len(ck["baseline"])
    results.append(("nc1_clean", n0 == 0, f"干净副本 baseline {n0} 条（须为 0）"))
    print(f"[nc1_clean] 负向臂：{'[OK]' if n0 == 0 else '[NG]'} 干净副本 baseline {n0} 条（须为 0）")
    print()
    arm("nc1_tampered", "baseline", m_baseline, a_baseline)

    # ---- NC-2 首次出现：新词必须报，旧词不许报
    def a_fs_new(res, _dst):
        # 断言走 items，不走 subject：subject 是截断过的一句话，
        # 注入项若排在 8 个之后就会被「其余 N 个」吞掉 —— 那是渲染的预算，
        # 不是检测器的结论，负控要判的是后者。
        owner = next(
            (c for c in kinds(res, "first_seen") if "zzz_probe_nc" in (c.get("items") or [])),
            None,
        )
        if owner is None:
            return False, "注入的新命令没有被报成首次出现（items 里找不到）"
        return True, f"报出了：{owner['subject']}"

    def a_fs_old(res, _dst):
        names = [n for c in kinds(res, "first_seen") for n in (c.get("items") or [])]
        if "git" in names:
            return False, "历史已有的命令 git 被误报成首次出现"
        return True, f"git 未被误报（本次首次出现共 {len(names)} 项）"

    # 这一条不写进 results：zzz_probe_nc 在干净副本里必然不存在，是恒真的，
    # 把恒真的检查计进通过率，就是让分母看起来比实际大（铁律 22 同族）。
    clean_names = [n for c in kinds(clean, "first_seen") for n in (c.get("items") or [])]
    print(f"[nc2_clean] 负向臂（不计入判定）：干净副本首次出现 {len(clean_names)} 项，"
          f"zzz_probe_nc {'在' if 'zzz_probe_nc' in clean_names else '不在'}其中")
    print()
    arm("nc2_new", "first_seen", lambda p: m_first_seen_new(p, day), a_fs_new)
    arm("nc2_old", "first_seen", lambda p: m_first_seen_old(p, day), a_fs_old)

    # ---- NC-4 预期缺席：后半个钩子挂了
    def a_absent(res, _dst):
        hit = kinds(res, "absent")
        if not hit:
            return False, "删光了 post_tool_use 却没报缺席"
        if not any("post_tool_use" in c["subject"] for c in hit):
            return False, f"报了缺席但不是 post_tool_use：{hit[0]['subject']}"
        return True, hit[0]["subject"]

    n_abs = len(ck["absent"])
    results.append(("nc4_clean", n_abs == 0, f"干净副本 absent {n_abs} 条（须为 0）"))
    print(f"[nc4_clean] 负向臂：{'[OK]' if n_abs == 0 else '[NG]'} 干净副本 absent {n_abs} 条（须为 0）")
    print()
    arm("nc4_tampered", "absent", m_absent, a_absent)

    # ---- NC-3 日内断层：挖 2 小时洞，须报出 >= 90 分钟
    def a_gap(res, _dst):
        best, best_s = 0.0, ""
        for c in kinds(res, "gap"):
            m = re.search(r"有 (\d+) 小时 (\d+) 分|有 (\d+) 分", c["subject"])
            if not m:
                continue
            v = (int(m.group(1)) * 60 + int(m.group(2))) if m.group(1) else int(m.group(3))
            if v > best:
                best, best_s = float(v), c["subject"]
        if best < GAP_ASSERT_MIN:
            return False, f"最长断层 {best:g} 分钟 < 断言阈值 {GAP_ASSERT_MIN:g}"
        return True, f"最长断层 {best:g} 分钟：{best_s}"

    def a_gap_clean(_res, _dst):
        ok = clean_max_gap < GAP_ASSERT_MIN
        return ok, f"干净副本最长断层 {clean_max_gap:g} 分钟（须 < {GAP_ASSERT_MIN:g}）"

    results.append(("nc3_clean", clean_max_gap < GAP_ASSERT_MIN,
                    f"干净副本最长断层 {clean_max_gap:g} 分钟（须 < {GAP_ASSERT_MIN:g}）"))
    print(f"[nc3_clean] 负向臂：{'[OK]' if clean_max_gap < GAP_ASSERT_MIN else '[NG]'} "
          f"干净副本最长断层 {clean_max_gap:g} 分钟（须 < {GAP_ASSERT_MIN:g}）")
    print()
    arm("nc3_tampered", "gap", lambda p: m_gap(p, day), a_gap)

    # ================= NC-5 A4：同格式真倒序仍红、非倒序改动不红 =================
    clean_a4 = a4_count(run_audit(base))

    def m_a4_inv(path, day):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        for k in range(len(lines) // 2, len(lines)):
            if '"ts": "' in lines[k]:
                lines[k] = re.sub(
                    r'"ts": "[^"]+"', f'"ts": "{day}T00:00:01+08:00"', lines[k], count=1
                )
                break
        else:
            raise RuntimeError("找不到可改的 ts")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.writelines(lines)
        return "把中段一条记录的 ts 改到当日 00:00:01（**同格式**，保留 +08:00）"

    def m_a4_same(path, day):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        prev_ts = None
        for k in range(len(lines) // 2, len(lines)):
            m = re.search(r'"ts": "([^"]+)"', lines[k])
            if not m:
                continue
            if prev_ts is None:
                prev_ts = m.group(1)
                continue
            lines[k] = lines[k].replace(m.group(1), prev_ts, 1)
            break
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.writelines(lines)
        return "把一条记录的 ts 改成与**前一条完全相同**（字节变了，但不构成倒序）"

    def a_a4_inv(res, _d):
        c = a4_count(res)
        if c <= clean_a4:
            return False, f"A4 倒序数没增加（{clean_a4} -> {c}）—— 同格式真倒序漏报"
        return True, f"A4 {clean_a4} -> {c} 处（同格式真倒序，仍红）"

    def a_a4_same(res, _d):
        c = a4_count(res)
        if c != clean_a4:
            return False, f"非倒序改动把 A4 从 {clean_a4} 推到了 {c} —— 判据过敏"
        return True, f"A4 仍为 {clean_a4} 处（非倒序改动不触发）"

    results.append(("nc5_clean", True, f"干净副本（9 个日文件）A4 基线 {clean_a4} 处（WARN，非 PASS）"))
    print(f"[nc5_clean] 副本口径（9 个日文件）A4 基线 {clean_a4} 处，状态 {dim(run_audit(base), 'A4')['status']}")
    print()
    arm("nc5_inv", "A4", lambda p: m_a4_inv(p, day), a_a4_inv, runner=run_audit)
    arm("nc5_same", "A4", lambda p: m_a4_same(p, day), a_a4_same, runner=run_audit)

    # ================= NC-6/7 规则 id 归一：旧号收敛、非规则号浮现 =================
    cen0 = clean["meta"]["rule_census"]
    _recs = list(W.iter_records(base))
    _alias, _cur = W.load_rule_ids()
    _rawset = {k for _, _, r in _recs for k in W._rules_raw(r)}
    _touched = {_alias.get(k, k) for k in _rawset} & _cur
    # 必须挑「副本里还没出现过」的旧号，否则注入它不会改变「原样 id 数」——
    # 首版固定用 SEC-01，而 SEC-01 本就在这 9 个日文件里，于是断言必然假 NG。
    _legacy_cand = [k for k, v in _alias.items() if k not in _rawset and v in _touched]
    LEGACY = _legacy_cand[0] if _legacy_cand else None

    def _cen(res):
        return res["meta"]["rule_census"]

    def m_id_legacy(path, day):
        append_rec(
            path,
            {
                "ts": bump_ts(max_ts(path, day), 3),
                "type": "pre_tool_use",
                "tool": "Bash",
                "session": "nc-probe",
                "host": "workbuddy",
                "input": {"command": "git status", "content_len": 0},
                "content_digest": "sha256:" + "0" * 64,
                "rules_hit": [LEGACY],
            },
        )
        return f"注入 1 条 rules_hit={LEGACY}（旧号，应归一到 {_alias.get(LEGACY)}）"

    def m_id_unknown(path, day):
        append_rec(
            path,
            {
                "ts": bump_ts(max_ts(path, day), 4),
                "type": "pre_tool_use",
                "tool": "Bash",
                "session": "nc-probe",
                "host": "workbuddy",
                "input": {"command": "git status", "content_len": 0},
                "content_digest": "sha256:" + "0" * 64,
                "rules_hit": ["ZZZ-99"],
            },
        )
        return "注入 1 条 rules_hit=ZZZ-99（映射不到、也不在规则库里）"

    def a_id_legacy(res, _d):
        c = _cen(res)
        if c["n_ids_raw"] != cen0["n_ids_raw"] + 1:
            return False, f"原样 id 数应 +1，实际 {cen0['n_ids_raw']} -> {c['n_ids_raw']}"
        if c["n_rules_touched"] != cen0["n_rules_touched"]:
            return False, (
                f"旧号没有收敛：涉及规则数 {cen0['n_rules_touched']} -> {c['n_rules_touched']}"
                "（说明归一没生效，同一条规则被数成两条）"
            )
        return True, (
            f"原样 id {cen0['n_ids_raw']}->{c['n_ids_raw']}，"
            f"涉及规则仍 {c['n_rules_touched']} 条（旧号已收敛）"
        )

    def a_id_unknown(res, _d):
        c = _cen(res)
        if "ZZZ-99" not in c["non_rule"]:
            return False, f"未知号没有浮现为非规则号：{c['non_rule']}"
        if c["n_rules_touched"] != cen0["n_rules_touched"]:
            return False, f"未知号被并进了规则分母：{cen0['n_rules_touched']} -> {c['n_rules_touched']}"
        return True, f"非规则号 {c['non_rule']}（未并入规则分母 {c['n_rules_touched']} 条）"

    arm("nc6_legacy", "id", lambda p: m_id_legacy(p, day), a_id_legacy)
    arm("nc7_unknown", "id", lambda p: m_id_unknown(p, day), a_id_unknown)

    # ================= NC-8/9 repeat：一次不报、三次才报 =================
    def _add_cmd(path, day, cmd, n, offset):
        for i in range(n):
            append_rec(
                path,
                {
                    "ts": bump_ts(max_ts(path, day), offset + i),
                    "type": "pre_tool_use",
                    "tool": "Bash",
                    "session": "nc-probe",
                    "host": "workbuddy",
                    "input": {"command": cmd, "content_len": 0},
                    "content_digest": "sha256:" + "0" * 64,
                },
            )

    def a_rep_once(res, _d):
        rep = [c for c in kinds(res, "repeat") if "zzz_rep_probe" in (c.get("items") or [])]
        fs = [c for c in kinds(res, "first_seen") if "zzz_rep_probe" in (c.get("items") or [])]
        if rep:
            return False, "只出现 1 次就被报成 repeat —— 门槛失效"
        if not fs:
            return False, "只出现 1 次却既没报 repeat 也没报 first_seen —— 漏报"
        return True, "1 次不报 repeat，仍归 first_seen"

    def a_rep_thrice(res, _d):
        rep = [c for c in kinds(res, "repeat") if "zzz_rep_probe" in (c.get("items") or [])]
        fs = [c for c in kinds(res, "first_seen") if "zzz_rep_probe" in (c.get("items") or [])]
        if not rep:
            return False, "出现 3 次却没报 repeat"
        if fs:
            return False, "同一条同时占了 repeat 和 first_seen 两份注意力预算"
        return True, rep[0]["subject"]

    arm("nc8_once", "repeat", lambda p: (_add_cmd(p, day, "zzz_rep_probe", 1, 10), "注入 1 次 zzz_rep_probe")[1], a_rep_once)
    arm("nc9_thrice", "repeat", lambda p: (_add_cmd(p, day, "zzz_rep_probe", 3, 20), "注入 3 次 zzz_rep_probe")[1], a_rep_thrice)

    # ================= NC-10/11/12 rule_pair：顺序成立报、自配不报、超窗不报 =================
    _pd, _pe, _solo, _ = W.rule_pair_index(_recs)
    _cand = [
        (a, b)
        for a in _solo
        for b in _solo
        if a != b and _solo[a] >= 3 and _solo[b] >= 3 and (a, b) not in _pd
    ]
    if not _cand:
        results.append(("nc10_pair", False, "找不到从未共现过的规则对，本臂不可判定"))
        print("[nc10_pair] 找不到候选规则对 —— 本臂不可判定（不是通过）")
        cand_a = cand_b = None
    else:
        cand_a, cand_b = _cand[0]

    def _add_rule(path, day, rule, offset, session):
        append_rec(
            path,
            {
                "ts": bump_ts(max_ts(path, day), offset),
                "type": "pre_tool_use",
                "tool": "Bash",
                "session": session,
                "host": "workbuddy",
                "input": {"command": "git status", "content_len": 0},
                "content_digest": "sha256:" + "0" * 64,
                "rules_hit": [rule],
            },
        )

    def a_pair(res, _d):
        hit = [c for c in kinds(res, "rule_pair") if list(c.get("items") or []) == [cand_a, cand_b]]
        if not hit:
            return False, f"注入了 {cand_a} -> {cand_b}（1 分钟内）却没报组合"
        return True, hit[0]["subject"]

    def a_pair_self(res, _d):
        hit = [c for c in kinds(res, "rule_pair") if list(c.get("items") or []) == [cand_a, cand_a]]
        if hit:
            return False, "同一规则自己配自己也被报成了组合"
        return True, "A->A 不报（自配不是组合）"

    def a_pair_far(res, _d):
        hit = [c for c in kinds(res, "rule_pair") if list(c.get("items") or []) == [cand_a, cand_b]]
        if hit:
            return False, "间隔 30 分钟的 A->B 被当成组合 —— 时间窗失效"
        return True, "间隔 30 分钟不报（窗口 5 分钟）"

    if cand_a and cand_b:
        arm(
            "nc10_pair",
            "rule_pair",
            lambda p: (
                _add_rule(p, day, cand_a, 30, "nc-sess-1"),
                _add_rule(p, day, cand_b, 31, "nc-sess-1"),
                f"注入 {cand_a} -> {cand_b}，同 session 间隔 1 秒",
            )[2],
            a_pair,
        )
        arm(
            "nc11_self",
            "rule_pair",
            lambda p: (
                _add_rule(p, day, cand_a, 40, "nc-sess-2"),
                _add_rule(p, day, cand_a, 41, "nc-sess-2"),
                f"注入 {cand_a} -> {cand_a}，同 session 间隔 1 秒",
            )[2],
            a_pair_self,
        )
        arm(
            "nc12_far",
            "rule_pair",
            lambda p: (
                _add_rule(p, day, cand_a, 50, "nc-sess-3"),
                _add_rule(p, day, cand_b, 50 + 1800, "nc-sess-3"),
                f"注入 {cand_a} -> {cand_b}，同 session 间隔 30 分钟",
            )[2],
            a_pair_far,
        )

    # ================= NC-13 盲区自述自检：漏报一个检测器必须抛 =================
    try:
        W._coverage_selfcheck(
            {k: {"status": W.RAN} for k in W.COVERAGE_KEYS if k != "gap"}
        )
        ok_missing = False
        msg_missing = "漏报 gap 的覆盖状态却没有抛 —— 盲区自述会说谎"
    except ValueError as e:
        ok_missing = True
        msg_missing = f"漏报即抛：{e}"
    try:
        W._coverage_selfcheck({k: {"status": W.RAN} for k in W.COVERAGE_KEYS})
        ok_valid = True
        msg_valid = "完整申报通过"
    except Exception as e:  # noqa: BLE001
        ok_valid = False
        msg_valid = f"完整申报反而抛了：{e}"
    results.append(("nc13_cov", ok_missing and ok_valid, msg_missing + "｜" + msg_valid))
    print(f"[nc13_cov] {'[OK]' if ok_missing and ok_valid else '[NG]'} {msg_missing}｜{msg_valid}")
    print()

    # ================= NC-14..18 日锚：锚改了必须响，没改必须不响 =================
    def _anchor_txt(res) -> str:
        return " ｜ ".join(
            c["subject"] + "｜" + "；".join(c.get("items") or []) for c in kinds(res, "anchor")
        )

    def a_anchor_size(res, _d):
        t = _anchor_txt(res)
        if "对不上" not in t:
            return False, f"改了锚的 size 却没报「对不上」：{t or '（无 anchor 线索）'}"
        if "size" not in t:
            return False, f"报了对不上，但没说是 size 的问题：{t}"
        return True, t

    def a_anchor_hash(res, _d):
        t = _anchor_txt(res)
        if "对不上" not in t or "hash" not in t:
            return False, f"改了锚的 last_hash 却没报 hash 对不上：{t or '（无 anchor 线索）'}"
        return True, t

    def a_anchor_hash_live(res, _d):
        """当天末条 hash 随时在变 ⇒ 比它只会得到噪声，必须**不报**。"""
        hit = kinds(res, "anchor")
        if hit:
            return False, (
                "当天（还在写）的末条 hash 被报成锚不符 —— 这会让报告每天都红："
                + _anchor_txt(res)
            )
        return True, "当天不比末条 hash（末条随时在变，比它只是噪声）"

    def a_anchor_orphan(res, _d):
        t = _anchor_txt(res)
        if "不见了" not in t:
            return False, f"锚在文件没了却没报删除证据：{t or '（无 anchor 线索）'}"
        return True, t

    def a_anchor_missing(res, _d):
        t = _anchor_txt(res)
        if "却没有日锚" not in t:
            return False, f"删了锚（该日有 hash）却没报缺锚：{t or '（无 anchor 线索）'}"
        return True, t

    def a_anchor_nohash(res, _d):
        hit = kinds(res, "anchor")
        if hit:
            return False, (
                "记录连 hash 都没有（旧 schema）却被报成缺锚 —— "
                "拿不可判定的东西当失败：" + _anchor_txt(res)
            )
        return True, "无 hash 字段的缺锚不报（锚无处可挂，不是漏）"

    if n_man:
        arm_file("nc14_size_closed", "anchor", "day_manifest.json", m_anchor_size_closed, a_anchor_size)
        arm_file("nc15_hash_closed", "anchor", "day_manifest.json", m_anchor_hash_closed, a_anchor_hash)
        arm_file("nc16_size_live", "anchor", "day_manifest.json", m_anchor_size_live, a_anchor_size)
        arm_file("nc17_hash_live", "anchor", "day_manifest.json", m_anchor_hash_live, a_anchor_hash_live)
        arm_file("nc18_orphan", "anchor", "day_manifest.json", m_anchor_orphan, a_anchor_orphan)
        arm_file("nc19_missing", "anchor", "day_manifest.json", m_anchor_missing, a_anchor_missing)
        arm_file("nc20_nohash", "anchor", "day_manifest.json", m_anchor_nohash, a_anchor_nohash)
    else:
        results.append(("nc14..20_anchor", False, "副本里没有 day_manifest.json，日锚臂无法执行"))

    # ================= NC-21..23 裁决口径：表外必响、合法必不响 =================
    def a_verdict_out(res, _d):
        hit = kinds(res, "verdict")
        if not any("表外组合" in c["subject"] for c in hit):
            return False, f"注入了 allow+block（表外）却没报表外组合：{[c['subject'] for c in hit]}"
        if res["meta"]["verdict"]["n_out"] < 1:
            return False, "表外组合报了，但 meta 里的 n_out 仍是 0（口径与线索不一致）"
        return True, f"表外 {res['meta']['verdict']['n_out']} 条：" + "；".join(
            c["subject"] for c in hit
        )

    def a_verdict_badval(res, _d):
        hit = kinds(res, "verdict")
        if not any("值域外取值" in c["subject"] for c in hit):
            return False, f"注入了 decision=quarantine 却没报值域外取值：{[c['subject'] for c in hit]}"
        if res["meta"]["verdict"]["n_bad_value"] < 1:
            return False, "值域外报了，但 meta 里的 n_bad_value 仍是 0"
        return True, f"值域外 {res['meta']['verdict']['n_bad_value']} 条：" + "；".join(
            c["subject"] for c in hit
        )

    def a_verdict_legal(res, _d):
        hit = kinds(res, "verdict")
        if hit:
            return False, "allow+alert（放行但又告警）被报成了异常：" + "；".join(
                c["subject"] for c in hit
            )
        rel = res["meta"]["verdict"]["rel"]
        base_rel = clean["meta"]["verdict"]["rel"]
        got = rel.get(W.REL_ALLOW_ALERT, 0)
        want = base_rel.get(W.REL_ALLOW_ALERT, 0) + 1
        if got != want:
            return False, f"放行但告警计数 {base_rel.get(W.REL_ALLOW_ALERT, 0)}->{got}，应为 {want}"
        return True, f"不报异常，且「放行但告警」计数 {base_rel.get(W.REL_ALLOW_ALERT, 0)}->{got}"

    arm("nc21_verdict_out", "verdict", lambda p: m_verdict_out(p, day), a_verdict_out)
    arm("nc22_verdict_badval", "verdict", lambda p: m_verdict_badval(p, day), a_verdict_badval)
    arm("nc23_verdict_legal", "verdict", lambda p: m_verdict_legal(p, day), a_verdict_legal)

    # ================= NC-24 八档分类纯函数：逐档点名，不许有一档落错 =================
    CASES = [
        (("allow", "allow"), W.REL_AGREE),
        ((None, "record"), W.REL_EXEC),          # post_tool_use：裁决记在 action
        ((None, None), W.REL_NONE),
        ((None, "alert"), W.REL_EXEC),           # 执行侧告警也是执行侧
        (("alert", None), W.REL_DEC_ONLY),
        (("allow", "alert"), W.REL_ALLOW_ALERT),  # 不是矛盾
        (("deny", "block"), W.REL_SYNONYM),       # 命名未收敛
        (("config_refresh", "allow"), W.REL_NON_VERDICT),
        (("config_fallback", "alert"), W.REL_NON_VERDICT),
        (("allow", "block"), W.REL_OUT),          # 真表外
        (("deny", "alert"), W.REL_OUT),
        (("block", "allow"), W.REL_OUT),
    ]
    wrong = [(k, W.classify_verdict(*k), want) for k, want in CASES if W.classify_verdict(*k) != want]
    ok24 = not wrong
    results.append((
        "nc24_classify",
        ok24,
        "八档全对（12 例）" if ok24 else f"分错 {len(wrong)} 例：{wrong}",
    ))
    print(f"[nc24_classify] {'[OK]' if ok24 else '[NG]'} "
          f"{'八档全对（12 例）' if ok24 else f'分错 {len(wrong)} 例：{wrong}'}")
    print()

    # ---- 汇总
    print("=" * 72)
    bad = [r for r in results if not r[1]]
    for name, ok, detail in results:
        print(f"  {'[OK]' if ok else '[NG]'}  {name:<14} {detail[:88]}")
    print("=" * 72)
    print(f"结论：{len(results) - len(bad)}/{len(results)} 通过")
    print(f"副本保留（自行清理）：{work}")
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
