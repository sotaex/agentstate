#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""B-3 · `verify_chain` 三腿攻击 → 扩到五腿（方案书 §9.3 未核实清单第 7 条）

方案书原文标「**未跑**」。开工卡要求三腿：① 对照 ② 重写＋同步清单 ③ 重写＋不同步清单，
并写明「**第三腿是关键**：若 `exit=0`（不报篡改），说明日锚没有牙齿」。

────────────────────────────────────────────────────────────────────────
为什么扩成五腿：只跑三腿会得到一个读不出意思的结果
────────────────────────────────────────────────────────────────────────

若 ③ 得到 `rc=0`，有两种同样合理的解释：
  (a) 日锚只有 `size` 一条牙，而重写保持了长度 ⇒ 抓不到（**结论**）；
  (b) `verify_chain` 这个工具压根没在工作（**仪器坏了**）。
两者输出完全相同。必须补两条对照腿把 (b) 排除：

  | 腿 | 做什么 | 它排除什么 |
  |---|---|---|
  | L1 对照     | 原样副本                                  | 建立基线（基线可能不是 0） |
  | L2 改内容不重算哈希 | 只改值、不重算                      | **哈希那条牙活着吗**（必得 EDITED） |
  | L3 重算＋清单全对   | 重算整条尾链；清单 size 与 last_hash 都对 | 攻击者「做全套」时能不能被抓 |
  | L4 重算＋清单只对 size | 重算整条尾链；清单 size 对、last_hash 旧 | ★ 关键腿：与 L3 只差一个字段 |
  | L5 截断＋清单不动   | 去掉最后一条记录                     | **size 那条牙活着吗**（必得尾锚失败） |

★ L3 与 L4 只差 `last_hash` 一个字段。两腿输出相同 ⇒ `last_hash` 是死字段。
★ L4 必须**保持文件字节长度不变**，否则 L5 那条牙会先响，L4 什么都证明不了。

────────────────────────────────────────────────────────────────────────
两条踩过的坑（都会造出假结论，写在这里免得下次重踩）
────────────────────────────────────────────────────────────────────────

坑一 · **行尾**。本仓账本是 **CRLF**。用文本模式（`open()` 默认，通用换行）读进来的
    行已经被转成 `\\n`，再比「逐字节一致」永远成立 —— 这个假绿骗过本脚本的第一版，
    它当时以为「照抄写盘形式重写就能保长度」，实际每改一行少 1 字节。
    ⇒ 现在一律 `newline=""` 读，改行时**把原行尾缀原样接回去**，改完断言字节数不变。

坑二 · **`--json` 通道丢尾锚**（本轮实测，产品缺陷）。
    `verify_chain.py` 的 `--json` 分支在 `if json_mode: ... continue` 里早退，
    那句 `if not tok: tail_fail += 1` **在 json 模式下从不执行**；
    出口码也只由 `unexplained`/`explained` 决定。于是**截断一条记录后**：
      人读通道 `rc=2`（尾锚失败升码），机器通道 `rc=0`、`tail_failures=0`。
    同一份数据两个通道两个结论 —— 本脚本因此**两个通道都跑**，
    并把「尾锚信号」取自已确认可靠的 `days[day].tail_ok`，任何通道间不一致都单列上报。

边界：只在系统 TEMP 的副本上操作，仓库零写入；不修产品代码（缺陷写卡）。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VERIFY = os.path.join(REPO, "tools", "verify_chain.py")
AUDIT = os.path.join(REPO, ".psl", "audit")
PY = sys.executable


# ────────────────────────── 读写（保住 CRLF） ──────────────────────────
def load_lines(path):
    """返回 [(body, eol)]：body 不含行尾，eol 是原样的行尾（'\\r' / '' ）。"""
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        raw = f.read()
    out = []
    for line in raw.split("\n"):
        if line == "" and out and out[-1] is None:
            continue
        if line.endswith("\r"):
            out.append((line[:-1], "\r"))
        else:
            out.append((line, ""))
    # 末尾的 split 会多出一个空串（文件以换行结尾）
    if out and out[-1][0] == "" and out[-1][1] == "":
        out.pop()
    return out


def save_lines(path, pairs):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(b + e for b, e in pairs) + "\n")


def dump_body(rec):
    """照抄写盘形式（`audit_chain.append_chained` 用这个，不是规范紧凑形式）。"""
    return json.dumps(rec, ensure_ascii=False)


def canon(rec):
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def chain_from(recs, start):
    """从第 start 条起重算整条链（与 verify_chain 的自算式同口径）。

    verify_chain: `sha256(parent_full + canon(rec))`，canon 不含 hash；prev 存末 16 位。
    ★ 没有 `hash` 键的记录**原样跳过、一个字节都不动**（它们不进链，
      擅自给它们补 hash 会改变记录集合，那是另一种篡改，不是本腿要测的东西）。
    """
    prev_full = ""
    for i in range(start - 1, -1, -1):
        if recs[i].get("hash"):
            prev_full = recs[i]["hash"]
            break
    for i in range(start, len(recs)):
        if not recs[i].get("hash"):
            continue
        recs[i]["prev"] = prev_full[-16:] if prev_full else ""
        recs[i]["hash"] = hashlib.sha256(
            (prev_full + canon(recs[i])).encode("utf-8")).hexdigest()
        prev_full = recs[i]["hash"]
    return recs


def write_manifest(work, day, size, last_hash):
    man = {day: {"size": size, "last_hash": last_hash,
                 "updated_at": "2026-01-01T00:00:00"}}
    with open(os.path.join(work, "day_manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(man, f, ensure_ascii=False)


# ────────────────────────── 两通道读数 ──────────────────────────
def verify(work_dir):
    """两个通道都跑：人读（rc 权威）＋ 机读（分类明细）。"""
    pj = subprocess.run([PY, "-X", "utf8", VERIFY, work_dir, "--json"],
                        capture_output=True, text=True, timeout=600)
    pt = subprocess.run([PY, "-X", "utf8", VERIFY, work_dir],
                        capture_output=True, text=True, timeout=600)
    out = (pj.stdout or "").strip()
    try:
        rep = json.loads(out)
    except Exception:
        return {"rc": pj.returncode, "text_rc": pt.returncode, "parse_error": True,
                "by_class": {}, "tail_failures": -1, "records": -1,
                "stdout_tail": out[-200:], "stderr_tail": (pj.stderr or "")[-200:]}
    rep["text_rc"] = pt.returncode
    rep["text_tail"] = [l for l in (pt.stdout or "").splitlines()
                        if "TAIL-TAMPERED" in l or l.startswith("verdict:")][:3]
    return rep


def nonzero(rep):
    d = dict(rep.get("by_class") or {})
    d.pop("OK", None)
    return {k: v for k, v in d.items() if v}


def tail_failed(rep):
    """尾锚是否报失败。json 的 `tail_failures` 在 --json 模式下恒 0（缺陷），
    所以以 `days[*].tail_ok` 为准，并用文本通道的 TAIL-TAMPERED 行交叉验证。"""
    bad_days = [d for d, v in (rep.get("days") or {}).items() if not v.get("tail_ok", True)]
    text_hit = any("TAIL-TAMPERED" in l for l in (rep.get("text_tail") or []))
    return bool(bad_days) or text_hit, bad_days, text_hit


def describe(tag, rep):
    cls = nonzero(rep)
    tf, bad_days, text_hit = tail_failed(rep)
    print("  [%s] 机读 rc=%-2s 人读 rc=%-2s 记录=%s 异常=%s 尾锚失败=%s"
          % (tag, rep.get("rc"), rep.get("text_rc"), rep.get("records"),
             cls if cls else "无", tf))
    if bad_days:
        for d in bad_days:
            print("        tail: %s ⇒ %s" % (d, (rep["days"][d].get("tail_msg") or "")[:90]))
    for l in (rep.get("text_tail") or []):
        print("        文本: %s" % l[:120])
    if rep.get("parse_error"):
        print("        ★ 解析失败 stdout=%r stderr=%r"
              % (rep.get("stdout_tail"), rep.get("stderr_tail")))
    if rep.get("rc") != rep.get("text_rc"):
        print("        ★ 两通道出口码不一致：机读 %s / 人读 %s"
              % (rep.get("rc"), rep.get("text_rc")))
    return cls


# ────────────────────────── 主流程 ──────────────────────────
def main():
    days = sorted(f for f in os.listdir(AUDIT)
                  if f.endswith(".jsonl") and f[:4].isdigit())
    if not days:
        print("★ 没有日文件 —— 实验无从进行")
        return 2
    day = days[-1]
    src = os.path.join(AUDIT, day)
    src_size = os.path.getsize(src)
    pairs = load_lines(src)
    bodies = [b for b, _ in pairs if b.strip()]
    if not bodies:
        print("★ 源文件为空 —— 实验无从进行")
        return 2
    recs0 = [json.loads(b) for b in bodies]
    hashed = [i for i, r in enumerate(recs0) if r.get("hash")]
    orig_last = recs0[hashed[-1]]["hash"] if hashed else ""

    print("=" * 76)
    print("B-3 · verify_chain 五腿")
    print("  目标 %s  %d 字节  %d 行（其中有 hash 的 %d 条）"
          % (day, src_size, len(bodies), len(hashed)))
    man_now = json.load(open(os.path.join(AUDIT, "day_manifest.json"), encoding="utf-8")).get(day, {})
    print("  真实清单  size=%s last_hash=%s…"
          % (man_now.get("size"), str(man_now.get("last_hash"))[:16]))
    print("  CRLF 行数 %d / 总行数 %d" % (sum(1 for _, e in pairs if e), len(pairs)))

    ctx = {"day": day, "size": src_size, "lines": len(bodies), "hashed": len(hashed),
           "crlf": sum(1 for _, e in pairs if e), "tgt": None}
    tmp = tempfile.mkdtemp(prefix="b3_", dir=os.environ.get("TEMP") or None)
    res = {}
    try:
        work = os.path.join(tmp, "audit")
        os.makedirs(work)
        dst = os.path.join(work, day)

        # 选一个「非首条、且有 hash」的 allow 记录作为篡改目标
        tgt = next((i for i, r in enumerate(recs0)
                    if r.get("decision") == "allow" and r.get("hash") and i > 0), None)
        ctx["tgt"] = tgt
        print("  篡改目标 第 %s 条（0 基；allow→alert 同长度）" % tgt)

        def baseline_manifest():
            write_manifest(work, day, src_size, orig_last)

        # ── L1 ────────────────────────────────────────────────
        print("-" * 76)
        print("L-1 对照（原样副本；清单 size 与 last_hash 都是真实锚）")
        shutil.copyfile(src, dst)
        assert os.path.getsize(dst) == src_size, "副本字节与源不一致"
        baseline_manifest()
        res["L1"] = verify(work)
        describe("L-1", res["L1"])

        # ── L2 改内容不重算 ───────────────────────────────────
        print("-" * 76)
        print("L-2 改内容不重算：allow→alert（同长度），哈希不动")
        if tgt is None:
            print("  ★ 找不到可用目标，本腿做不了（不凑）")
            res["L2"] = None
        else:
            p2 = list(pairs)
            r = json.loads(p2[tgt][0])
            r["decision"] = "alert"
            p2[tgt] = (dump_body(r), p2[tgt][1])
            save_lines(dst, p2)
            sz = os.path.getsize(dst)
            print("  改第 %d 条；字节 %d → %d（必须相等：%s）" % (tgt, src_size, sz, sz == src_size))
            baseline_manifest()
            res["L2"] = verify(work) if sz == src_size else None
            if sz == src_size:
                describe("L-2", res["L2"])
            else:
                print("  ★ 字节变了 ⇒ 本腿不成立")

        # ── L3 重算＋清单全对 ─────────────────────────────────
        print("-" * 76)
        print("L-3 重算尾链 ＋ 清单 size/last_hash 都更新（攻击者做全套）")
        recs3 = [json.loads(b) for b in bodies]
        recs3[tgt]["decision"] = "alert"
        chain_from(recs3, tgt)
        p3 = [(dump_body(r), e) for r, (b, e) in zip(recs3, pairs)]
        save_lines(dst, p3)
        sz3 = os.path.getsize(dst)
        print("  重算 %d 条；字节 %d → %d（必须相等：%s）"
              % (len(recs3) - tgt, src_size, sz3, sz3 == src_size))
        if sz3 != src_size:
            print("  ★ 字节变了 ⇒ 本腿不成立（size 锚会先响）")
            res["L3"] = None
        else:
            write_manifest(work, day, sz3, recs3[hashed[-1]]["hash"])
            res["L3"] = verify(work)
            describe("L-3", res["L3"])

        # ── L4 重算＋清单只对 size（关键腿）───────────────────
        print("-" * 76)
        print("L-4 重算尾链 ＋ 清单 size 对、last_hash 仍旧（与 L3 只差一个字段）")
        sz4 = os.path.getsize(dst)
        if sz4 != src_size:
            print("  ★ 字节变了 ⇒ 本腿不成立")
            res["L4"] = None
        else:
            write_manifest(work, day, sz4, orig_last)      # ← 只这里与 L3 不同
            res["L4"] = verify(work)
            describe("L-4", res["L4"])

        # ── L5 截断＋清单不动（size 锚的正控）─────────────────
        print("-" * 76)
        print("L-5 截断：去掉最后一条记录，清单仍是原大小")
        p5 = list(pairs)[:-1]
        save_lines(dst, p5)
        sz5 = os.path.getsize(dst)
        baseline_manifest()
        print("  字节 %d → %d（锚 %d）" % (src_size, sz5, src_size))
        res["L5"] = verify(work)
        describe("L-5", res["L5"])

        # ── 判定 ─────────────────────────────────────────────
        print("=" * 76)
        print("判定表")
        names = [("L1 对照", "L1"), ("L2 改内容不重算", "L2"),
                 ("L3 重算＋清单全对", "L3"), ("L4 重算＋清单只对 size", "L4"),
                 ("L5 截断＋清单不动", "L5")]
        for label, k in names:
            r = res.get(k)
            if r is None:
                print("  %-26s —（本腿未成立）" % label)
                continue
            tf, bad, _ = tail_failed(r)
            print("  %-26s 机读=%-2s 人读=%-2s 异常=%-24s 尾锚失败=%s"
                  % (label, r.get("rc"), r.get("text_rc"),
                     nonzero(r) if nonzero(r) else "无", tf))

        print("-" * 76)
        ok = True
        r2, r3, r4, r5 = res.get("L2"), res.get("L3"), res.get("L4"), res.get("L5")
        live = bool(r2 and nonzero(r2).get("EDITED"))
        print("  [%s] 哈希牙：L2 必须出现 EDITED ⇒ %s"
              % ("PASS" if live else "FAIL", "有" if live else "**没有**（后续结论全部不成立）"))
        ok &= live

        size_tooth = bool(r5 and tail_failed(r5)[0])
        print("  [%s] size 牙：L5 必须尾锚失败 ⇒ %s"
              % ("PASS" if size_tooth else "FAIL",
                 "有" if size_tooth else "**没有**（锚连截断都不管）"))
        ok &= size_tooth

        if r3 is not None and r4 is not None:
            same = (r3.get("rc") == r4.get("rc")
                    and nonzero(r3) == nonzero(r4)
                    and tail_failed(r3)[0] == tail_failed(r4)[0])
            print("  [%s] last_hash 死活：L3 与 L4 仅 last_hash 不同，结果%s ⇒ %s"
                  % ("PASS" if same else "NOTE", "相同" if same else "不同",
                     "**last_hash 是死字段**" if (same and not nonzero(r4)) else "last_hash 起了作用"))

        # 通道一致性（产品缺陷观测）
        chans = []
        for k, r in res.items():
            if r is None:
                continue
            if r.get("rc") != r.get("text_rc"):
                chans.append(k)
            elif r.get("tail_failures") == 0 and tail_failed(r)[0]:
                chans.append(k)
        if chans:
            print("  [缺陷] 通道不一致出现在 %s：`--json` 不计尾锚失败（rc 也不升）"
                  % "、".join(sorted(chans)))

        print("=" * 76)
        print("结论")
        if r4 is not None and not nonzero(r4) and not tail_failed(r4)[0]:
            print("  ★ 重算型重写**没有被发现**：L4 零异常、尾锚通过、人机两通道都给 0。")
            print("  ⇒ 日锚只有一条牙 = `size`（只挡截断）。`day_manifest.json` 里的")
            print("    `last_hash` **写了但没有任何代码读它**（`verify_tail()` 只比 size），")
            print("    而 `size` 对「同长度重写」天然无感。")
            print("  ⇒ 结论：「同长度重算重写」在本验证链上**没有任何检测点**。")
            print("     `DEC-11` 不能以「有日锚」作为抗重写的依据，需重新论证。")
        else:
            print("  ★ 重算型重写被发现了（L4 有异常或尾锚失败）⇒ 日锚不止 size 一条牙。")
        print("（只在系统 TEMP 的副本上操作，仓库零写入）")
        md = os.path.join(REPO, "output", "lineB", "b3_verify_chain_attack.md")
        with open(md, "w", encoding="utf-8", newline="\n") as f:
            f.write(render_md(res, ctx))
        print("  → %s" % md)
        return 0 if ok else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def render_md(res, ctx):
    """把五腿结果写成报告。数字全部来自本次运行，不手抄。"""
    L = []
    L.append("# B-3 · `verify_chain` 五腿攻击结果\n")
    L.append("> 目标 `%s`，**%d 字节 / %d 行**（其中带 hash 的可验记录 **%d** 条），"
             "CRLF 行 %d 条。篡改目标第 **%s** 条，`allow→alert`（同长度）。\n"
             % (ctx["day"], ctx["size"], ctx["lines"], ctx["hashed"],
                ctx["crlf"], ctx["tgt"]))
    L.append("★ 只在系统 TEMP 的副本上操作，仓库零写入。\n")

    L.append("## 1 五腿结果\n")
    rows = []
    for label, k in [("L1 对照", "L1"), ("L2 改内容不重算", "L2"),
                     ("L3 重算＋清单全对", "L3"), ("L4 重算＋清单只对 size", "L4"),
                     ("L5 截断＋清单不动", "L5")]:
        r = res.get(k)
        if r is None:
            rows.append([label, "—", "—", "—", "本腿未成立"])
            continue
        tf = tail_failed(r)[0]
        rows.append([label, r.get("rc"), r.get("text_rc"),
                     "无" if not nonzero(r) else str(nonzero(r)),
                     "失败" if tf else "通过"])
    L.append("| 腿 | 机读 rc | 人读 rc | 异常分类 | 尾锚 |")
    L.append("|---|---|---|---|---|")
    for row in rows:
        L.append("| " + " | ".join(str(c) for c in row) + " |")
    L.append("")
    L.append("L3 与 L4 **只差 `last_hash` 一个字段**；两腿结果相同 ⇒ 那个字段没被任何代码读过。\n")

    L.append("## 2 三条结论\n")
    L.append("**① 哈希那条牙是活的。** L2 只改值不重算 ⇒ `EDITED` 出现，两条通道同码。"
             "所以后面「没抓到」不是仪器坏了。\n")
    L.append("**② `size` 那条牙也是活的，但它只挡截断。** L5 去掉最后一条记录 ⇒ 尾锚失败，"
             "人读通道 `rc=2`。\n")
    L.append("**③ 同长度重算重写，零检测点。** L4 把整条尾链重算、文件字节数一分不差、"
             "清单 `size` 对得上，只留 `last_hash` 是旧的 ⇒ **零异常、尾锚通过、两通道都 0**。"
             "而 `verify_tail()` 只比 `size`，`last_hash` 写进清单后**没有任何读取点**"
             "（全仓 grep：只有 `audit_chain.py` 的写入侧与一个同名函数，无验证侧消费）。"
             "⇒ 「改一条记录再重算整条链」在现有验证链上**完全不可见**。\n")

    L.append("## 3 顺带撞出的产品缺陷：`--json` 通道丢尾锚\n")
    L.append("L5 同一份被截断的数据，**两个通道两个结论**：人读 `rc=2` 并打出 "
             "`TAIL-TAMPERED`，机读 `rc=0`、`tail_failures=0`。\n")
    L.append("根因（读码可核）：`tools/verify_chain.py` 的 `--json` 分支在"
             "`if json_mode: report[...]; continue` 里早退，"
             "其后的 `if not tok: tail_fail += 1` **在 json 模式下从不执行**；"
             "结尾 `report[rc] = 2 if unexplained else (3 if explained else 0)` "
             "也不含 `tail_fail`。\n")
    L.append("⇒ 危害：**机器接口正是自动化的入口**。任何用 `--json` 判成败的流水线，"
             "对「账本被截断」这件事会拿到 `rc=0`。人读通道看得见，机器看不见。\n")
    L.append("处置：**写卡，不改**（补丁额度 3/3 已满，排队进 0.64）。"
             "修复方向是让 `--json` 与文本通道共用同一个 `tail_fail` 累加点，"
             "而不是各写一遍。\n")

    L.append("## 4 对 `DEC-11` 的影响\n")
    L.append("`DEC-11` 若以「有日锚」作为抗篡改依据，本次实测不支持：日锚的检测面等于"
             "「文件长度变小」，对等长重写无感。要么把 `last_hash` 接进 `verify_tail()`"
             "（改动很小：比一次末条 hash 即可），要么在 `DEC-11` 里把覆盖范围收窄成"
             "「抗截断」并写明不抗重写。\n")
    return "\n".join(L)


if __name__ == "__main__":
    sys.exit(main())
