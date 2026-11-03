#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""B-8 · 日锚对照页（方案书 §7.2 步 1）

方案书原文：「**建最小锚**：每日 `(day, size, last_hash)` 写进**用户可见的报告**；
给 `verify_chain.py` 加限定语」。

今天 `day_manifest.json` 已经存着这三个数，但**没有任何面向用户的出口** ——
它们只被 `verify_chain` 内部读一次，读成什么样用户看不见。本工具补这个出口：
把锚与**磁盘现状**逐日对照，输出一张人能读的表，并给出四种判定。

四种判定（不是三种 —— 「同长度不同内容」是锚唯一能抓到重写的形态，必须单列）：

| 判定 | 条件 | 含义 |
|---|---|---|
| `OK` | size 相等 且 last_hash 相等 | 与锚一致 |
| `APPEND` | 实 size > 锚 size | 锚之后又写了新记录（正常，锚落后） |
| `SHORT` | 实 size < 锚 size | **文件比锚记录的短** ⇒ 尾部被截 |
| `REWRITE` | size 相等 但 last_hash 不同 | **被重写过且长度没变** ⇒ 锚能抓到的唯一重写形态 |
| `NO_ANCHOR` | 锚里没有这一天 | 该日没建过锚（不是"没问题"） |

★ 纪律：
  · 只读，仓库零字节写入；夹具建在系统 TEMP。
  · 末行哈希的取法**照抄** `audit_chain.py` 的同刻口径（末个非空行 JSON 的 `hash`），
    不另造第二套。
  · 五条腿自证（词表五类各一条）：负控（原样 ⇒ OK）、正控一（同长改内容 ⇒ REWRITE）、
    正控二（截短 ⇒ SHORT）、正控三（追加 ⇒ APPEND）、正控四（无锚 ⇒ NO_ANCHOR）。
    追加那条是必须的：真账本里 APPEND 恰好 0 天，没有腿就分不清
    「查过没有」与「分类器没走到那个分支」—— 两者在页面上都印 0。

用法：
  python output/lineB/b8_day_anchor_page.py [--audit <dir>] [--out <file.md>]
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile

_OUT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _OUT not in sys.path:
    sys.path.insert(0, _OUT)
import _commit                                              # noqa: E402

_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.jsonl$")


def last_hash_of(path: str) -> str:
    """末个非空行 JSON 的 `hash` —— 与 `audit_chain.py` 同口径（尾读，不全量加载）。"""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            back = min(size, 65536)
            f.seek(size - back)
            tail = f.read(back).decode("utf-8", "replace")
    except OSError:
        return ""
    lines = [ln for ln in tail.split("\n") if ln.strip()]
    if not lines:
        return ""
    try:
        return json.loads(lines[-1]).get("hash", "") or ""
    except Exception:
        return ""


def classify(real_size: int, real_hash: str, anchor: dict) -> str:
    """纯函数，可注入 —— 主判据与负控共用同一把尺子。"""
    if not anchor:
        return "NO_ANCHOR"
    a_size = int(anchor.get("size", 0) or 0)
    a_hash = anchor.get("last_hash") or ""
    if real_size < a_size:
        return "SHORT"
    if real_size > a_size:
        return "APPEND"
    return "OK" if real_hash == a_hash else "REWRITE"


MARK = {
    "OK": "✅ 一致",
    "APPEND": "＋ 有新记录（锚落后）",
    "SHORT": "❌ 比锚短（尾部被截）",
    "REWRITE": "❌ 同长度不同内容（被重写）",
    "NO_ANCHOR": "⚠ 无锚",
}


def build_rows(audit_dir: str):
    mpath = os.path.join(audit_dir, "day_manifest.json")
    man = {}
    man_err = ""
    if os.path.isfile(mpath):
        try:
            with open(mpath, encoding="utf-8") as f:
                man = json.load(f)
            if not isinstance(man, dict):
                man, man_err = {}, "day_manifest.json 不是对象"
        except Exception as e:                              # noqa: BLE001
            man, man_err = {}, "读不动：%s" % type(e).__name__
    else:
        man_err = "文件不存在"

    rows = []
    for name in sorted(os.listdir(audit_dir)):
        if not _DAY_RE.match(name):
            continue
        p = os.path.join(audit_dir, name)
        if not os.path.isfile(p):
            continue
        size = os.path.getsize(p)
        h = last_hash_of(p)
        anchor = man.get(name) or {}
        rows.append({
            "day": name[:-6],
            "file": name,
            "size": size,
            "hash": h,
            "a_size": int(anchor.get("size", 0) or 0) if anchor else None,
            "a_hash": (anchor.get("last_hash") or "") if anchor else None,
            "a_at": (anchor.get("updated_at") or "") if anchor else None,
            "verdict": classify(size, h, anchor),
        })
    return rows, man, man_err


def render(rows, man, man_err, teeth=None) -> str:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = []
    out.append("# Antinel · 日锚对照页")
    out.append("")
    out.append("- **生成时刻**：%s（本机）" % now)
    out.append("- **锚来源**：`.psl/audit/day_manifest.json`（%d 条）" % len(man))
    out.append("- **这一页回答的问题**：账本里某一天，跟当初记下的那三个数还对得上吗？")
    out.append("")
    out.append("> **限定语（必须随页一起给用户）**：本页只能发现"
               "「**与锚记录不符**」的改动。锚与日文件**同目录同权限**，"
               "能改日文件的人也能改锚 ⇒ 本页证明的是「与登记值自洽」，"
               "**不是**「没被人动过」。要证后者，锚必须搬到对方改不动的地方。")
    out.append("")
    if man_err:
        out.append("⚠ **锚本身有问题**：%s —— 下表所有 `NO_ANCHOR` 都不构成「该日没问题」。" % man_err)
        out.append("")
    cnt = {}
    for r in rows:
        cnt[r["verdict"]] = cnt.get(r["verdict"], 0) + 1
    out.append("## 汇总")
    out.append("")
    out.append("| 判定 | 天数 |")
    out.append("|---|---:|")
    # ★ 五种判定**全部列出**，0 天也列（2026-11-03 改）：
    #   原先只印出现的判定 ⇒ 今天只印「一致 34 / 无锚 2」，
    #   读的人分不出「查过、一天也没被改」和「这一项根本没查」——
    #   这正是「四种 0 同貌」。列全之后，0 的意思是「**查过且没有**」。
    for k in ("OK", "APPEND", "SHORT", "REWRITE", "NO_ANCHOR"):
        out.append("| %s | %d |" % (MARK[k], cnt.get(k, 0)))
    out.append("| **合计** | **%d** |" % len(rows))
    out.append("")
    out.append("> 表里 **0 天**的意思是「查过、且一天都没有」，不是「这一项没查」："
               "判定规则本身有牙，证据是下面这一行。")
    if teeth is not None:
        _ok, _msgs = teeth
        out.append("> ")
        out.append("> **判定规则自证**（生成时实跑）：%s —— %s"
                   % (("%d 条腿全过" % len(_msgs)) if _ok else "**没通过，本页不可信**",
                      "；".join("%s %s" % ("✅" if p else "❌", d)
                                for d, p, _g in _msgs)))
    out.append("")
    out.append("## 逐日明细")
    out.append("")
    out.append("| 日期 | 实字节 | 锚记字节 | 末行哈希（实 / 锚） | 判定 |")
    out.append("|---|---:|---:|---|---|")
    for r in rows:
        ah = (r["a_hash"] or "")[:10]
        rh = (r["hash"] or "")[:10]
        out.append("| %s | %d | %s | `%s` / `%s` | %s |"
                   % (r["day"], r["size"],
                      "-" if r["a_size"] is None else r["a_size"],
                      rh or "-", ah or "-", MARK[r["verdict"]]))
    out.append("")
    bad = [r for r in rows if r["verdict"] in ("SHORT", "REWRITE")]
    out.append("## 需要人看的天")
    out.append("")
    if bad:
        for r in bad:
            out.append("- **%s** — %s" % (r["day"], MARK[r["verdict"]]))
    else:
        out.append("无。全%d天的字节数与末行哈希都与锚一致（或只是锚之后又追加了记录）。" % len(rows))
    out.append("")
    return "\n".join(out)


def _fixture(tmp: str):
    """五条腿：原样 / 同长改内容 / 截短 / 追加 / 无锚。返回 (ok, 说明列表)。

    ★ 为什么五条都要有：判定词表有五类，真账本里 `APPEND` 恰好 **0 天**。
      如果只为前三条写腿，「0 天」就有两种解释 —— 「查过、确实没有」，
      与「分类器根本没走到那一个分支」。两者在页面上**长得一模一样**
      （都印 0），所以必须有一条正控把它逼出来，证明那个分支是活的。
      `NO_ANCHOR` 本来靠真实数据就有 2 天，但腿很便宜，一并补上，
      让「五类判定全覆盖」这件事可复算，而不是靠观察。
    """
    lines = [
        json.dumps({"type": "a", "hash": "h1"}, ensure_ascii=False),
        json.dumps({"type": "b", "hash": "h2"}, ensure_ascii=False),
    ]
    p = os.path.join(tmp, "2099-01-01.jsonl")
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    size0 = os.path.getsize(p)
    h0 = last_hash_of(p)
    anchor = {"size": size0, "last_hash": h0}

    msgs = []
    ok = True

    def _reset():
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    # 负控：原样
    v = classify(os.path.getsize(p), last_hash_of(p), anchor)
    ok &= (v == "OK")
    msgs.append(("负控 原样不动 ⇒ OK", v == "OK", v))

    # 正控 1：同长度改内容（把 h2 改成 h3 —— 长度一样）
    _reset()
    txt = open(p, encoding="utf-8").read().replace('"h2"', '"h3"')
    open(p, "w", encoding="utf-8", newline="\n").write(txt)
    v = classify(os.path.getsize(p), last_hash_of(p), anchor)
    ok &= (v == "REWRITE")
    msgs.append(("正控 同长改内容 ⇒ REWRITE", v == "REWRITE", v))

    # 正控 2：截短（删掉最后一行）
    _reset()
    txt = open(p, encoding="utf-8").read()
    txt = txt.rsplit("\n", 2)[0] + "\n"
    open(p, "w", encoding="utf-8", newline="\n").write(txt)
    v = classify(os.path.getsize(p), last_hash_of(p), anchor)
    ok &= (v == "SHORT")
    msgs.append(("正控 截短 ⇒ SHORT", v == "SHORT", v))

    # 正控 3：追加一行（锚之后又写了新记录 —— 正常状态，必须**不是** SHORT/REWRITE）
    _reset()
    with open(p, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps({"type": "c", "hash": "h3"}, ensure_ascii=False) + "\n")
    v = classify(os.path.getsize(p), last_hash_of(p), anchor)
    ok &= (v == "APPEND")
    msgs.append(("正控 追加一行 ⇒ APPEND（真账本 0 天，靠这条腿证明分支是活的）",
                 v == "APPEND", v))

    # 正控 4：没有锚
    _reset()
    v = classify(os.path.getsize(p), last_hash_of(p), None)
    ok &= (v == "NO_ANCHOR")
    msgs.append(("正控 无锚 ⇒ NO_ANCHOR", v == "NO_ANCHOR", v))

    return ok, msgs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", default=os.path.join(".psl", "audit"))
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    audit = a.audit
    if not os.path.isdir(audit):
        print("★ 账本目录不存在：%s" % audit)
        return 2

    print("=" * 74)
    print("B-8 · 日锚对照")
    print("=" * 74)

    rows, man, man_err = build_rows(audit)
    if not rows:
        print("❌ 一个日文件都没读到 —— 报表无意义")
        return 1
    print("日文件 %d 个 ｜ 锚 %d 条 ｜ 锚状态：%s"
          % (len(rows), len(man), man_err or "可读"))
    cnt = {}
    for r in rows:
        cnt[r["verdict"]] = cnt.get(r["verdict"], 0) + 1
    # ★ 五种判定全列，0 天也列 —— 与页面同一口径（页面是本函数的输出，
    #   两边只印出现的判定的写法会让「查过没有」与「没查」在终端上又同貌一次）。
    for k in ("OK", "APPEND", "SHORT", "REWRITE", "NO_ANCHOR"):
        print("  %-10s %d 天" % (k, cnt.get(k, 0)))

    # ---- 五条腿（词表五类各一条；条数不写死，加了腿文案不会漂）----
    tmp = tempfile.mkdtemp(prefix="b8_fixture_")
    try:
        ok, msgs = _fixture(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n[自证] 判定规则的 %d 条腿" % len(msgs))
    for desc, passed, got in msgs:
        print("  %s %s（得到 %s）" % ("✅" if passed else "❌", desc, got))
    if not ok:
        print("\n判定：❌ 规则没有牙 —— 报告不可信")
        return 1

    page = render(rows, man, man_err, teeth=(ok, msgs))
    if a.out:
        r = _commit.write_text(a.out, page, newline="\n")
        print("\n已写出：%s（%d 字节 / %d 字符，落盘路径 %s）"
              % (a.out, r["bytes"], r["chars"], r["how"]))
    else:
        print("\n" + page)
    return 0


if __name__ == "__main__":
    sys.exit(main())
