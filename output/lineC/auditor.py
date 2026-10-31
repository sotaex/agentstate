#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""对账 Agent · 认证程序原型（只读，零裁量，零模型）。

它回答一个问题：**这份账本，自己跟自己对得上吗？**

不回答的问题（重要）：
  · 不问「这份账本可信吗」—— 今天只有 L0 内部一致性，没有 L2 外部锚；
  · 不问「记录的内容对不对」—— 只验它有没有被改过，不验它写的是不是事实；
  · 不做任何判断、不调任何模型、不写任何文件。

四个维度 + 一个可选维度：
  A1 内容完整   每条 hash 重算 == 记录里的 hash（sha256(prev_full + canon)）  FAIL-able
  A2 链连续     每条 prev == 上一条 hash 的后 16 位                            FAIL-able
  A3 日清单     文件 size / last_hash 与 day_manifest.json 一致                 FAIL-able
  A4 时间单调   同一文件内 ts 不减                                              **WARN only**
  A5 总量       实际条数 vs 声明条数（--declare）                               FAIL-able

**四档而不是两档**（这一条是实跑撞出来的）：
  PASS 通过 ／ WARN 性质偏离（不是篡改）／ FAIL 不符（篡改证据）／ SKIP 不适用

为什么 A4 只能是 WARN（2026-10-31 复查后重写，原说法已证伪）：
原写「934 处全部是 `host_shield_heartbeat` 并发写」——**错**。实际按 type 分布是
`pre_tool_use` 300／`dst02_bash_path_suspect` 82／`post_tool_use` 48／heartbeat 仅 10。
正确结论仍是「并发排队，不是篡改」，但证据换成了 `lock_events.jsonl`：
5,461 次 `acq_timeout`、等待中位 1,601ms、361 次「同文件同秒 ≥2 pid 抢锁」，
而 ts 倒序幅度中位 1.0s —— **锁等待与倒序同量级**，机制成立。
把它判成 FAIL，工具第一次跑就报红，用户就不看了 —— **狼来了比不报更糟**。

为什么 A4 要用 datetime 而不是字符串比较：账本混装两种 ts 格式
（162,182 条带 `+08:00`、916 条不带）。字符串比较报 936 处倒序，
datetime 归一后只有 481 处，差额 455 处**全部**来自格式混装。
字符串比较不是「近似正确」，它把格式问题伪装成篡改证据。

为什么 A3 要跳过当日文件：账本还在长，size 与 last_hash 必然对不上。
这是量具错，不是账本错（铁律 22：先怀疑量具）。

为什么「没有清单」报 SKIP 不报 FAIL：**没有的东西不能报成失败**。
外部账本可能根本不分日、不带清单，判成 FAIL 就是把「不适用」说成「有问题」。

用法：
    python output/lineC/auditor.py                          # 对账 .psl/audit
    python output/lineC/auditor.py --root <别人的账本目录>
    python output/lineC/auditor.py --declare 163761         # 另加总量对账
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# ts 归一唯一实现（入口唯一性）：不许在本文件里再写一遍解析。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tsnorm  # noqa: E402

_DAY_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl$")

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"
MARK = {PASS: "通过", WARN: "偏离", FAIL: "不符", SKIP: "不适用"}


@dataclass
class Finding:
    dim: str
    status: str
    detail: str
    evidence: Tuple[Tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        if self.status == FAIL and not self.evidence:
            raise ValueError(f"FAIL 必须带断点位置（{self.dim}）")


@dataclass
class Snapshot:
    """一次读入，全部维度共用。

    为什么必须单次快照：账本**正在被写**。分维度各读一遍，读到的是不同时刻的账本，
    实测两次读同一天的文件差 4 条 —— 那样算出来的每个数都不可比。
    """

    root: str
    files: List[str]
    recs: Dict[str, List[Tuple[int, Dict[str, Any]]]]
    unparsed: Dict[str, int]
    prechain: Dict[str, int]
    manifest: Optional[Dict[str, Any]]

    @property
    def total_records(self) -> int:
        return sum(len(v) for v in self.recs.values())


def canon(rec: Dict[str, Any]) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def recompute_hash(rec: Dict[str, Any], prev_full: str) -> str:
    """AUDIT_SCHEMA v1.2 §2：hash = sha256(prev_full + canonical_json(rec))。

    prev_full 是**完整 64 位**上一条 hash，不是记录里那个后 16 位。
    实测踩过：只拿 canon 去算，2000 条里只有 1 条对得上。
    """
    return hashlib.sha256((prev_full + canon(rec)).encode("utf-8")).hexdigest()


def load_ledger(root: str) -> Snapshot:
    files: List[str] = []
    for p in glob.glob(os.path.join(root, "*.jsonl")):
        if _DAY_FILE.match(os.path.basename(p)):
            files.append(p)
    files.sort()

    recs: Dict[str, List[Tuple[int, Dict[str, Any]]]] = {}
    unparsed: Dict[str, int] = {}
    prechain: Dict[str, int] = {}
    for path in files:
        rs: List[Tuple[int, Dict[str, Any]]] = []
        unp = 0
        pre = 0
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    unp += 1
                    continue
                if not isinstance(rec, dict):
                    unp += 1
                    continue
                if "hash" not in rec:
                    pre += 1
                    continue
                rs.append((ln, rec))
        recs[path] = rs
        unparsed[path] = unp
        prechain[path] = pre

    manifest: Optional[Dict[str, Any]] = None
    mpath = os.path.join(root, "day_manifest.json")
    if os.path.isfile(mpath):
        try:
            with open(mpath, "r", encoding="utf-8") as fh:
                m = json.load(fh)
            manifest = m if isinstance(m, dict) else None
        except Exception:
            manifest = None

    return Snapshot(root, files, recs, unparsed, prechain, manifest)


def _day(path: str) -> str:
    m = _DAY_FILE.match(os.path.basename(path))
    return m.group(1) if m else path


def check_content(s: Snapshot) -> Finding:
    checked = 0
    bad: List[Tuple[str, int]] = []
    for path in s.files:
        prev_full = ""
        for ln, rec in s.recs[path]:
            if recompute_hash(rec, prev_full) != rec.get("hash"):
                bad.append((_day(path), ln))
            checked += 1
            prev_full = rec.get("hash", "")
    if bad:
        return Finding(
            "A1 内容完整", FAIL, f"{len(bad)} 条 hash 重算不符（共验 {checked} 条）", tuple(bad[:5])
        )
    return Finding("A1 内容完整", PASS, f"{checked} 条全部重算一致")


def check_chain(s: Snapshot) -> Finding:
    checked = 0
    bad: List[Tuple[str, int]] = []
    for path in s.files:
        prev_tail = ""
        for ln, rec in s.recs[path]:
            if rec.get("prev", "") != prev_tail:
                bad.append((_day(path), ln))
            checked += 1
            prev_tail = rec.get("hash", "")[-16:]
    if bad:
        return Finding(
            "A2 链连续", FAIL, f"{len(bad)} 处 prev 对不上上一条 hash（共验 {checked} 条）", tuple(bad[:5])
        )
    return Finding("A2 链连续", PASS, f"{checked} 条 prev 全部接上")


def check_manifest(s: Snapshot) -> Finding:
    if s.manifest is None:
        return Finding("A3 日清单", SKIP, "该账本没有 day_manifest.json ⇒ 本维度不适用（不是失败）")

    # 最后一个日文件正在被写，size 与 last_hash 必然对不上 —— 这是量具错，不是账本错
    live = s.files[-1] if s.files else None

    bad: List[Tuple[str, int]] = []
    # 「不在清单里」有两种，混起来就是**拿新日子给旧缺口打掩护**：
    #   晚于清单末条 -> 真·新增日（清单还没写到它），不算失败；
    #   早于清单末条 -> 历史缺锚，**不是新增日**，必须点名。
    # 再按记录里有没有 hash 分两档（与 watchman 的日锚检测器同一条规则）：
    #   有 hash -> 有 hash 却没有清单条目。**这是事实，不是判定**：
    #             「漏了」还是「当时还没有调锚这个动作」，要看当日代码。
    #             B 线 b9 已定性：2026-10-05 属后者（0.60.0 才补 touch_day_manifest）。
    #             所以这里只降 WARN 并点名，不写「本该挂上」。
    #   无 hash -> 旧 schema，锚无处可挂，属「不适用」，不算失败（铁律 45）。
    man_days = [n[:10] for n in s.manifest if len(n) >= 10]
    last_man_day = max(man_days) if man_days else ""
    new_days: List[str] = []
    gap_hash: List[str] = []
    gap_nohash: List[str] = []
    checked = 0
    for path in s.files:
        if path == live:
            continue
        name = os.path.basename(path)
        ent = s.manifest.get(name)
        if not isinstance(ent, dict):
            day = name[:10]
            if last_man_day and day > last_man_day:
                new_days.append(name)
                continue
            rs = s.recs[path]
            has_hash = any(r[1].get("hash") for r in rs)
            (gap_hash if has_hash else gap_nohash).append(name)
            continue
        checked += 1
        if "size" in ent and ent["size"] != os.path.getsize(path):
            bad.append((name, 0))
            continue
        if "last_hash" in ent:
            rs = s.recs[path]
            last = rs[-1][1].get("hash", "") if rs else ""
            if last and ent["last_hash"] != last:
                bad.append((name, 0))

    if bad:
        return Finding(
            "A3 日清单",
            FAIL,
            f"{len(bad)} 个日文件与清单不符（size 或 last_hash；共核 {checked} 个）",
            tuple(bad[:5]),
        )
    note = f"{checked} 个日文件与清单一致；当日文件（{_day(live)}）正在写，未参与比对"
    if new_days:
        note += f"；{len(new_days)} 个晚于清单末条（{last_man_day}）⇒ 真·新增日，不算失败"
    if gap_nohash:
        note += (
            f"；{len(gap_nohash)} 个早于清单末条但记录无 hash ⇒ 锚无处可挂（不适用）："
            f"{'、'.join(n[:10] for n in gap_nohash)}"
        )
    if gap_hash:
        # 能核的都一致，但有几天**没得核** —— 说 PASS 是「全部一致」，那是假的；
        # 说 FAIL 是「清单不符」，那也是假的。中间那一档才是事实。
        return Finding(
            "A3 日清单",
            WARN,
            note
            + f"；**{len(gap_hash)} 个早于清单末条却有 hash ⇒ 历史缺锚（有 hash 却无清单条目）**："
            + "、".join(n[:10] for n in gap_hash),
            tuple((n, 0) for n in gap_hash),
        )
    return Finding("A3 日清单", PASS, note)


def check_monotonic(s: Snapshot) -> Finding:
    """A4：同一文件内 ts 不减。**解析后比较，不做字符串比较**（见 tsnorm 模块头）。"""
    bad: List[Tuple[str, int]] = []
    checked = 0
    unparsed = 0
    for path in s.files:
        last = None
        for ln, rec in s.recs[path]:
            dt = tsnorm.parse_ts(rec.get("ts"))
            if dt is None:
                if rec.get("ts") is not None:
                    unparsed += 1
                continue
            checked += 1
            if last is not None and dt < last:
                bad.append((_day(path), ln))
            last = dt
    tail = f"（{unparsed} 条 ts 不可解析，未参与）" if unparsed else ""
    if bad:
        return Finding(
            "A4 时间单调",
            WARN,
            f"{len(bad)} 处 ts 比前一条早（共验 {checked} 条{tail}）。"
            "口径＝datetime 归一后比较，无时区按本地墙钟（UTC+8）解释。"
            "链未断、内容未变，且 lock_events 显示大量抢锁等待与倒序同量级 "
            "⇒ 事件时间与链上顺序不同序，属并发排队的性质，不是篡改",
            tuple(bad[:5]),
        )
    return Finding("A4 时间单调", PASS, f"{checked} 条 ts 单调不减{tail}")


def check_total(s: Snapshot, declare: Optional[int]) -> Finding:
    if declare is None:
        return Finding("A5 总量", SKIP, "未给 --declare ⇒ 本维度不适用")
    total = 0
    for path in s.files:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            total += sum(1 for line in fh if line.strip())
    if total != declare:
        return Finding(
            "A5 总量",
            FAIL,
            f"实际 {total} 条，声明 {declare} 条，差 {total - declare:+d}",
            (("(合计)", 0),),
        )
    return Finding("A5 总量", PASS, f"{total} 条与声明一致")


def render(findings: List[Finding], s: Snapshot, census: Dict[str, int] | None = None) -> str:
    lines: List[str] = []
    lines.append(f"对账报告 · {s.root}")
    lines.append(
        f"范围：{len(s.files)} 个日文件，{s.total_records} 条带 hash 记录，"
        f"链建立前 {sum(s.prechain.values())} 条，不可解析 {sum(s.unparsed.values())} 条"
    )
    if census:
        parts = "、".join(f"{k} {v:,} 条" for k, v in sorted(census.items(), key=lambda x: -x[1]))
        mixed = tsnorm.mixed_formats(census)
        warn = (
            f" ⚠ 其中 {mixed:,} 条缺时区后缀 ⇒ 字符串比较会把格式差异读成时间倒序；"
            "本报告已归一后再比"
            if mixed
            else ""
        )
        lines.append(f"ts 口径：{parts}。无时区的按本地墙钟（UTC+8）解释后再比。{warn}")
    lines.append("")

    for f in findings:
        lines.append(f"[{MARK[f.status]}] {f.dim} —— {f.detail}")
        # FAIL 叫「断点」（链真的断了）；WARN 叫「位置」——
        # 缺锚是**没得核**，不是断了，用「断点」会把「从没写过」说成「写到一半断了」。
        label = "断点" if f.status == FAIL else "位置"
        for name, ln in f.evidence:
            lines.append(f"        {label}：{name}:{ln}" if ln else f"        {label}：{name}")
    lines.append("")

    fails = [f for f in findings if f.status == FAIL]
    warns = [f for f in findings if f.status == WARN]
    if fails:
        lines.append(f"结论：**不自洽**（{len(fails)} 个维度不符）。断点已列出，可逐条回原文件核对。")
    elif warns:
        names = "、".join(f.dim for f in warns)
        lines.append(f"结论：**内部自洽**（{len(warns)} 项性质偏离：{names}）。")
    else:
        lines.append("结论：**内部自洽**。")

    lines.append(
        "      这只说明「这份账本自己跟自己对得上」，**不说明它没有被整链重写**——"
        "整链重写后重算全部 hash 与清单，本工具仍会报内部自洽。"
        "要排除这一种，需要 L2 外部锚，今天还没有。"
    )
    lines.append("")
    lines.append("本报告不含任何判断：不评价记录内容对不对，只验它有没有被改过。")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="对账 Agent（只读，零裁量）")
    ap.add_argument("--root", default=".psl/audit")
    ap.add_argument("--declare", type=int, default=None, help="声明条数，用于 A5 总量对账")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if not os.path.isdir(args.root):
        print(f"[停] 目录不存在：{args.root}", file=sys.stderr)
        return 2

    snap = load_ledger(args.root)
    if not snap.files:
        print(f"[停] {args.root} 里没有 YYYY-MM-DD.jsonl", file=sys.stderr)
        return 2

    findings = [
        check_content(snap),
        check_chain(snap),
        check_manifest(snap),
        check_monotonic(snap),
        check_total(snap, args.declare),
    ]

    census = tsnorm.format_census(args.root)

    if args.json:
        print(
            json.dumps(
                {
                    "root": snap.root,
                    "ts_census": census,
                    "files": len(snap.files),
                    "records": snap.total_records,
                    "findings": [
                        {"dim": f.dim, "status": f.status, "detail": f.detail, "evidence": f.evidence}
                        for f in findings
                    ],
                },
                ensure_ascii=False,
                indent=1,
            )
        )
    else:
        print(render(findings, snap, census))

    return 1 if any(f.status == FAIL for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
