# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""主动性 v2 · 噪声打分器（T0 的最小可用版）

──────────────────────────────────────────────────────────────────────────
它解决什么问题
──────────────────────────────────────────────────────────────────────────
「把噪声压下去」这句话本身无法验收——压到几条算好？压掉的是噪声还是真线索？

本文件把这件事变成一个**可复跑的数字**：
    跑一次 watchman → 对着 noise_baseline.json 打分 → 输出精确率与召回。

没有它，T2-T5 的每一次改动都只能靠「看着像好一点」来判断，
而那正是铁律 22 说的「最危险的不是报错，是报出好看得可疑的结果」。

──────────────────────────────────────────────────────────────────────────
它不做什么
──────────────────────────────────────────────────────────────────────────
不判断线索对不对（金标准是人判的，本文件只负责比对）。
不改任何文件。不碰账本。

用法：
    python output/_p_score_noise.py            # 打分当前代码
    python output/_p_score_noise.py --quiet    # 只输出一行结论
    python output/_p_score_noise.py --json     # 机器可读
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LINE_C = os.path.join(HERE, "lineC")
BASELINE = os.path.join(LINE_C, "noise_baseline.json")
WATCHMAN = os.path.join(LINE_C, "watchman.py")


def canon(entry: dict) -> str:
    """把金标准的一条 key 折成**与 `Clue.key` 同一口径**的规范形。

    ★ 2026-11-02 修：原来靠「subject 里包含规则号」来配对。11-02 把 subject
      里的规则号换成了中文标签（`rule_label`），于是 `AN-002` 再也不出现在
      subject 里 —— 12 条金标准**全部错配成「金标准外」**，精确率与召回同时
      归零。那不是代码退化，是**量具坏了**（铁律 22：报红之前先怀疑量具）。
      现在改成比结构化 key：`Clue.key` 是身份字段，本来就是为这件事造的。

    规范形（与 watchman 里各检测器的 `key=` 一一对应）：
        rule_pair   AN-002>AN-014        -> rule_pair|AN-002|AN-014
        repeat      host:a.com|b.com     -> repeat|host|a.com|b.com
        first_seen  cmd:a|b              -> first_seen|cmd|a|b
        gap         "2026-11-01 08:41-09:12" -> gap|2026-11-01|08:41
    """
    kind = entry["kind"]
    key = entry["key"]
    if kind == "rule_pair":
        a, _, b = key.partition(">")
        return "rule_pair|" + "|".join(sorted((a.strip(), b.strip())))
    if kind == "gap":
        day, _, span = key.partition(" ")
        return "gap|%s|%s" % (day.strip(), span.split("-")[0].strip())
    sub, _, body = key.partition(":")
    vals = [v for v in body.split("|") if v]
    return "%s|%s|" % (kind, sub) + "|".join(sorted(vals))


def match(clues: list, entry: dict) -> list:
    """返回与该金标准条目匹配的实际线索下标（0-based）。

    ★ 只认 `Clue.key`。**没有回退到字符串包含** —— 回退会让「匹配不上」
      和「字段缺失」长得一样，而那正是这次坏掉的形态。缺 key 直接报错。
    """
    want = canon(entry)
    hits = []
    for i, c in enumerate(clues):
        if c.get("kind") != entry["kind"]:
            continue
        got = c.get("key")
        if not got:
            raise SystemExit(
                "[停] 线索没有 key 字段（kind=%s, subject=%r）。"
                "打分器只认结构化 key；缺 key 说明 watchman 的出口退化了。"
                % (c.get("kind"), (c.get("subject") or "")[:60])
            )
        if got == want:
            hits.append(i)
    return hits


def run_watchman(as_of: str | None) -> list:
    cmd = ["python", "-E", "-X", "utf8", WATCHMAN, "--cap", "100", "--json",
           "--no-ledger"]
    if as_of:
        cmd += ["--as-of", as_of]
    proc = subprocess.run(cmd, capture_output=True, cwd=ROOT)
    if proc.returncode != 0:
        raise SystemExit(
            "[停] watchman 跑失败（退出码 %d）：%s"
            % (proc.returncode, proc.stderr.decode("utf-8", "replace")[:400])
        )
    data = json.loads(proc.stdout.decode("utf-8", "replace"))
    return data.get("clues") or []


def selfcheck() -> int:
    """验「量具还活着」，不验「分数达不达标」。

    ★ 为什么要分开：2026-11-02 把 subject 里的规则号换成中文标签后，
      本文件**12 条全部错配成「金标准外」**，精确率与召回同时归零。
      但没有任何东西报警 —— 因为打分器不在总闸门里，而它的输出
      看起来只是「一个更难看的分数」，不是「一个坏掉的量具」。
      **分数难看会被讨论，量具坏掉只会被当成事实。**

    所以这里只断言三件事，全都与「达不达标」无关：
      1. 四种 key 格式都能折成规范形（格式变了立刻红）；
      2. 金标准 12 条一条不漏地可折（新增 kind 忘了写规则立刻红）；
      3. 按采样日重放**至少命中 1 条**（全 0 就是量具死了，不是「今天没线索」）。
    """
    ok = 0
    bad: list[str] = []

    def arm(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        if cond:
            ok += 1
            print("  [OK] %s %s" % (name, detail))
        else:
            bad.append(name)
            print("  [XX] %s %s" % (name, detail))

    cases = [
        ({"kind": "rule_pair", "key": "AN-002>AN-014"}, "rule_pair|AN-002|AN-014"),
        ({"kind": "repeat", "key": "host:b.com|a.com"}, "repeat|host|a.com|b.com"),
        ({"kind": "first_seen", "key": "cmd:ls|pwd"}, "first_seen|cmd|ls|pwd"),
        ({"kind": "gap", "key": "2026-11-01 08:41-09:12"}, "gap|2026-11-01|08:41"),
    ]
    for e, want in cases:
        got = canon(e)
        arm("canon %-10s" % e["kind"], got == want, "→ %s" % got)

    base = json.load(open(BASELINE, encoding="utf-8"))
    try:
        folded = [canon(e) for e in base["clues"]]
        arm("金标准全部可折", len(folded) == len(base["clues"]),
            "%d 条" % len(folded))
    except Exception as exc:                      # noqa: BLE001
        arm("金标准全部可折", False, "%s: %s" % (type(exc).__name__, exc))

    as_of = base.get("sample_day")
    if not as_of:
        arm("按采样日重放命中", False, "金标准没有 sample_day，无法重放")
    else:
        try:
            clues = run_watchman(as_of)
            hits = sum(1 for e in base["clues"] if match(clues, e))
            arm("按采样日重放命中", hits > 0,
                "%s 重放报 %d 条／命中金标准 %d 条" % (as_of, len(clues), hits))
        except SystemExit as exc:
            arm("按采样日重放命中", False, str(exc)[:80])

    print("\n  结论：%d/%d 通过" % (ok, ok + len(bad)))
    return 0 if not bad else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="主动性 v2 噪声打分器")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--selfcheck",
        action="store_true",
        help="只验量具是否活着（key 折叠／金标准可折／重放有命中），"
        "不验分数是否达标。总闸门跑这个，不跑打分。",
    )

    ap.add_argument(
        "--as-of",
        default=None,
        metavar="YYYY-MM-DD",
        help="按哪一天的账本打分。默认取金标准自带的 sample_day —— "
        "**金标准必须可重放**，否则它每天过期，而「过期」与「退化」在报告上"
        "长得一模一样。传 'today' 表示按当前账本打分（口径不同，会不可比）。",
    )
    args = ap.parse_args(argv)

    if args.selfcheck:
        return selfcheck()

    base = json.load(open(BASELINE, encoding="utf-8"))

    # ★ 采样日：金标准是某一天的快照，只有回到那一天才谈得上「同一把尺子」。
    #   没写 sample_day 的老金标准 → 明确说「不可重放」，不猜。
    as_of = args.as_of if args.as_of else base.get("sample_day")
    if as_of == "today":
        as_of = None
    if as_of is None and not args.as_of:
        print("[停] 金标准没有 sample_day，无法重放。"
              "补上采样日，或显式传 --as-of today 承担不可比的风险。",
              file=sys.stderr)
        return 2

    clues = run_watchman(as_of)

    # ★ 检测器被撤掉的样本：既不进召回分母，也不许算成「已压掉」。
    #   2026-11-02 gap 默认关闭后，3 条 gap 样本就属于这一类。
    #   混进分母的话，「撤掉量具」会被记成「降噪成功」—— 两个完全不同的动作，
    #   在打分器上都表现为「条数变少」。
    suppressed = [e for e in base["clues"] if e.get("suppressed_by")]

    assigned = {}          # 实际线索下标 -> 金标准条目
    missed = []            # 金标准里 true/weak 但没被报出来
    for e in base["clues"]:
        hits = match(clues, e)
        if not hits:
            # ★ 有 defect 的条目，消失是「缺陷被修掉」的预期结果，不算漏。
            #   第 8 条（AN-005>OUT-01）就是这样：它不是线索，是归类错误。
            #   把它的消失算成「漏」，会让打分器逼着人把 bug 留着。
            # ★ 有 suppressed_by 的条目，消失是「量具被撤了」，也不算漏。
            if (e["verdict"] in ("true", "weak") and not e.get("defect")
                    and not e.get("suppressed_by")):
                missed.append(e)
            continue
        for i in hits:
            # 同一条实际线索可能被多条金标准命中（合并类线索），取第一个
            assigned.setdefault(i, e)

    reported = len(clues)
    n_true = sum(1 for e in assigned.values() if e["verdict"] == "true")
    n_weak = sum(1 for e in assigned.values() if e["verdict"] == "weak")
    n_noise = sum(1 for e in assigned.values() if e["verdict"] == "noise")
    n_unknown = reported - len(assigned)     # 金标准里没有的 ⇒ 保守算噪声

    precision = n_true / reported if reported else 0.0
    recall_den = sum(1 for e in base["clues"]
                     if e["verdict"] == "true" and not e.get("suppressed_by"))
    recall = (recall_den - len([m for m in missed if m["verdict"] == "true"])) / recall_den if recall_den else 0.0

    acc = base["acceptance"]
    ok_count = reported <= acc["max_output"]
    ok_prec = precision >= acc["precision_strict_target"]
    ok_recall = recall >= 1.0
    ok = ok_count and ok_prec and ok_recall

    if args.json:
        print(json.dumps({
            "as_of": as_of,
            "reported": reported,
            "true": n_true, "weak": n_weak, "noise": n_noise, "unknown": n_unknown,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "missed": [m["key"] for m in missed],
            "suppressed": [s["key"] for s in suppressed],
            "ok_count": ok_count, "ok_precision": ok_prec, "ok_recall": ok_recall,
            "ok": ok,
        }, ensure_ascii=False, indent=2))
        return 0 if ok else 1

    if args.quiet:
        print("报了 %d 条｜精确率 %.1f%%｜召回 %.0f%%｜%s"
              % (reported, precision * 100, recall * 100, "过" if ok else "不过"))
        return 0 if ok else 1

    print("=" * 70)
    print("主动性 v2 · 噪声打分（对照 noise_baseline.json）")
    print("=" * 70)
    print("口径：账本截到 %s 重放（金标准采样日）" % (as_of or "**今天**"))
    print("金标准 %d 条：真 %d／弱 %d／噪声 %d"
          % (base["summary"]["total"], base["summary"]["true"],
             base["summary"]["weak"], base["summary"]["noise"]))
    print("本次报出 %d 条" % reported)
    print()
    print("  ├ 判为「真」  %d" % n_true)
    print("  ├ 判为「弱」  %d" % n_weak)
    print("  ├ 判为「噪声」%d" % n_noise)
    print("  └ 金标准外    %d  （保守计入噪声：宁可低估自己）" % n_unknown)
    if suppressed:
        print()
        print("  ★ 另有 %d 条样本的检测器已关闭，本次不覆盖：%s"
              % (len(suppressed), "、".join(s["key"] for s in suppressed)))
        print("    它们不是「被压掉的」，是「量具被撤了」——两种动作在条数上都表现为变少，")
        print("    混在一起就会把「撤掉检测器」记成「降噪成功」。")
    print()
    print("精确率（严格）%.1f%%   目标 ≥ %.1f%%"
          % (precision * 100, acc["precision_strict_target"] * 100))
    print("召回（真线索）%.0f%%   目标 100%%（第 %s 条必须活）"
          % (recall * 100, "、".join(str(i) for i in acc["must_keep"])))
    if missed:
        print()
        print("漏掉的真/弱线索：")
        for m in missed:
            print("  - [%s] %s" % (m["verdict"], m["key"]))
    print()
    print("条数 ≤ %d：%s   精确率达标：%s   召回达标：%s"
          % (acc["max_output"],
             "是" if ok_count else "否",
             "是" if ok_prec else "否",
             "是" if ok_recall else "否"))
    print("=" * 70)
    print("结论：%s" % ("过" if ok else "不过"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
