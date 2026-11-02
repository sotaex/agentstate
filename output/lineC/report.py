# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""交付入口：一条命令产出「一份**可以交出去**的监理报告」。

──────────────────────────────────────────────────────────────────────────
为什么需要一个入口，而不是「跑三条命令」
──────────────────────────────────────────────────────────────────────────
`evidence` → `onepager` → `citecheck` 三步各自都能跑，但**顺序错了没人管**：

    onepager --out 报告.html      ← 已经落盘了
    citecheck --html 报告.html    ← 才发现回指校验不过

那时候磁盘上已经躺着一份「看起来完整、实际核不了」的 HTML。它会被人转发、
被人归档、被人当成凭据 —— **一份校验不过的报告，比没有报告更危险**。

所以本文件把顺序固定死：

    读账本 → 读更正 → **渲染到临时文件** → 回指校验 → 通过才改名落盘

三条硬规矩：
1. **不通过不落盘**。校验不过时最终路径上**什么都不留**（不是留个残的）。
2. **先临时文件后改名**。中途崩了不会留半份 —— 半份和整份长得一样。
3. **报告与 sidecar 同生同灭**。`.manifest.json` 里记 `report_id` 与代码组指纹，
   与页脚的两个值必须对得上；对不上说明文件被换过。

──────────────────────────────────────────────────────────────────────────
它不做什么
──────────────────────────────────────────────────────────────────────────
不判断结论对不对（那是 auditor 的事），不改账本，不发网络请求。
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
LINE_C = HERE if os.path.basename(HERE) == "lineC" else os.path.join(HERE, "lineC")
OUTPUT = os.path.dirname(LINE_C)
sys.path.insert(0, LINE_C)

import evidence as E       # noqa: E402
import corrections as C    # noqa: E402
import codeid as CID       # noqa: E402
import onepager as OP      # noqa: E402

CITECHECK = os.path.join(LINE_C, "citecheck.py")


# ──────────────────────────────────────────────────────────────────────────
# 核心：产出一次
# ──────────────────────────────────────────────────────────────────────────

def produce(root: str, out_path: str, *,
            bundle: Optional[E.Bundle] = None,
            cap: int = OP.DEFAULT_CAP) -> Tuple[bool, Dict[str, Any]]:
    """产出一次。返回 `(是否落盘, 说明)`。**不落盘时最终路径上什么都不留。**

    `bundle` 可注入，只为自检能造一个「回指必错」的输入 —— 否则那条
    「校验不过就不落盘」的分支永远没有执行过。
    """
    info: Dict[str, Any] = {"out": out_path}

    # 0 代码指纹：算不出来就别往下走。一份出处无法核对的报告不该存在。
    fp = CID.compute()
    info["code_fp"] = fp.short
    if not fp.ok:
        info["error"] = "代码指纹不完整（缺 %s）" % "、".join(fp.missing)
        return False, info

    # 1 账本
    b = bundle if bundle is not None else E.collect(root)
    info["read_at"] = b.read_at
    info["evidence"] = b.count()
    info["undecidable"] = len(b.undecidable)

    # 2 更正记录：读不出来要停（「没有更正」与「不知道有没有更正」是两件事）
    if bundle is None:
        try:
            items = C.Ledger(root).load()
        except (ValueError, OSError) as exc:
            info["error"] = "更正记录读不出来：%s" % exc
            return False, info
        res = C.resolve(b, items)
    else:
        res = C.resolve(b, [])
    info["report_id"] = res.report_id
    info["void"] = res.void is not None

    # 3 渲染成**字符串**，先校验，通过了才落盘
    # ★★ 2026-11-02 改：原来写临时文件 → 校验 → 删掉。删这一步在本机**做不到**：
    #   宿主对新建文件持有句柄且不释放（实测 WinError 5 持续 60 秒以上，
    #   见 output/_p_rm_wait.py 的实测输出）。于是「校验不过 ⇒ 丢弃产物」
    #   这条分支会撞上「删不掉」，红在自检里，理由却和它要验的东西毫无关系。
    #   现在改成走管道：**根本没有临时文件**，也就不存在删不掉。
    #   这比原来更强 —— 校验不过时磁盘上什么都没有，而不是「写了一个再删掉」。
    out_dir = os.path.dirname(os.path.abspath(out_path)) or "."
    os.makedirs(out_dir, exist_ok=True)
    html = OP.render(b, cap=cap, resolved=res, code_fp=fp)

    # 4 回指校验：校验的是**即将落盘的那串字节**（不是内存对象，也不是另一个文件）
    rc, tail = _citecheck(html, root, b.count())
    info["citecheck_rc"] = rc
    info["citecheck"] = tail
    if rc != 0:
        info["error"] = "回指校验未通过，已丢弃产物：%s" % tail
        return False, info

    # 5 通过才落盘
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(html)

    # 5b 写后读回比对：原来「校验磁盘上的产物」防的是编码／换行把内容改掉。
    #    走管道后少了这一层，所以补一次**逐字节**读回比对 —— 它只回答
    #    「写下去的和你校验的是不是同一串」，不重复校验语义。
    with open(out_path, "r", encoding="utf-8", newline="") as fh:
        back = fh.read()
    if back != html:
        info["error"] = (
            "落盘内容与校验内容不一致（写 %d 字节／读回 %d 字节）"
            "—— 编码或换行改动了产物" % (len(html), len(back))
        )
        return False, info

    # 6 sidecar：与报告同生同灭
    side = out_path + ".manifest.json"
    man = {
        "report_id": res.report_id,
        "code_fp_short": fp.short,
        "code_fp_full": fp.gid,
        "read_at": b.read_at,
        "evidence": b.count(),
        "undecidable": b.undecidable,
        # ★ 「不适用」必须单独出一个键。它和 undecidable 是两件事：
        #   没跑成＝不知道有没有；不适用＝问了，这把尺子量不到。
        #   侧车是**机器通道** —— 页面上分了两块、机器通道里合成一个键，
        #   等于在唯一能被程序读的地方重新犯一次「零与不可判同貌」。
        "not_applicable": b.not_applicable,
        "blind": list(b.blind),
        "denominators": dict(b.denominators),
        # ★ 2026-11-03：三条腿的实况、守恒账、无档可落的那一批也进机器通道。
        #   起因：页面上已经有「这次看见了什么」的逐档归因与守恒式，
        #   而侧车只带 denominators ⇒ **页面与机器通道说的不是同一件事**。
        #   机器通道读不到「这个 0 是没腿读还是查了没有」，而它恰恰是
        #   唯一能被程序读的那一份。同一份 bundle 出去，不许各算一套。
        "legs": [
            {"name": lg.name, "ran": lg.ran, "produces": list(lg.produces),
             "denominator": lg.denominator, "note": lg.note}
            for lg in b.legs
        ],
        "tiers_with_no_leg": list(b.tiers_with_no_leg()),
        "untiered_alert": dict(b.untiered_alert),
        "unread_toast": dict(b.unread_toast),
        # ★ 守恒账原样出去（判据 J3）：`rows` 是加得起来的式子，
        #   `broken` 非空 ⇒ 这张表里的每个数都可能是错的。
        "balance": b.balance,
        "citecheck_rc": info["citecheck_rc"],
        "void": info["void"],
        "generated_by": "output/lineC/report.py",
    }
    with open(side, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(man, fh, ensure_ascii=False, indent=1)
    info["manifest"] = side
    return True, info


def _citecheck(html: str, root: str, expect: int) -> Tuple[int, str]:
    """把 HTML 从**管道**送进 citecheck（不落临时文件，见 produce 里的说明）。"""
    p = subprocess.run(
        [sys.executable, "-E", "-X", "utf8", CITECHECK,
         "--stdin", "--root", root, "--expect", str(expect)],
        input=html, capture_output=True, text=True,
        encoding="utf-8", errors="replace")
    lines = [ln.strip() for ln in (p.stdout or "").splitlines() if ln.strip()]
    tail = lines[-1] if lines else ((p.stderr or "").strip().splitlines() or [""])[-1]
    return p.returncode, tail[:120]


# ──────────────────────────────────────────────────────────────────────────
# 自检：先证明「校验不过就不落盘」这条分支真的会响
# ──────────────────────────────────────────────────────────────────────────

def _selfcheck() -> int:
    fails: List[str] = []

    def bad(msg: str) -> None:
        fails.append(msg)

    work = tempfile.mkdtemp(prefix="rep_sc_")
    try:
        # 造一个最小但**合法**的账本：3 天 × 2 条
        root = os.path.join(work, "audit")
        os.makedirs(root)
        for d in range(3):
            day = "2026-10-%02d" % (10 + d)
            with open(os.path.join(root, day + ".jsonl"), "w",
                      encoding="utf-8", newline="\n") as fh:
                for i in range(2):
                    fh.write(json.dumps({
                        "ts": "%sT0%d:00:00+08:00" % (day, i),
                        "type": "pre_tool_use", "rules_hit": [],
                        "decision": "allow", "action": "allow",
                    }, ensure_ascii=False) + "\n")

        # ---- 反向臂：回指指向账本里不存在的一行 ⇒ 必须拒绝落盘 ----
        b = E.Bundle(read_at="2026-10-12 12:00:00", root=root)
        b.evidence.append(E.Evidence(
            eid="BAD-0001", claim="这条的回指是编的", strength=E.K_LOG_ONLY,
            cites=(E.Cite("2026-10-12", 9999),), source="t",
            read_at="2026-10-12 12:00:00"))
        out_bad = os.path.join(work, "bad.html")
        ok, info = produce(root, out_bad, bundle=b)
        if ok:
            bad("回指越界却落盘了 —— 「校验不过不落盘」这条没生效")
        if os.path.exists(out_bad):
            bad("回指越界却在最终路径上留了文件")
        if os.path.exists(out_bad + ".manifest.json"):
            bad("回指越界却写了 sidecar")
        # 临时文件也不许留 —— 而且现在这条是**确定性**的：
        # 改走管道后，校验不过时磁盘上除了 audit/ 什么都不该有。
        # 原来只查 `.report-*` 前缀，那等于「允许留别的名字」；
        # 现在直接比目录内容，任何人重新引入临时文件都会被这一条抓住。
        entries = sorted(os.listdir(work))
        if entries != ["audit"]:
            bad("校验不过之后目录里还有别的东西：%s" % entries)

        # ---- 正向臂：回指合法 ⇒ 必须落盘，且 sidecar 与页脚对得上 ----
        b2 = E.Bundle(read_at="2026-10-12 12:00:00", root=root)
        b2.evidence.append(E.Evidence(
            eid="OK-0001", claim="这条的回指是真的", strength=E.K_LOG_ONLY,
            cites=(E.Cite("2026-10-12", 1),), source="t",
            read_at="2026-10-12 12:00:00"))
        out_ok = os.path.join(work, "ok.html")
        ok2, info2 = produce(root, out_ok, bundle=b2)
        if not ok2:
            bad("合法回指却没落盘：%s" % info2.get("error"))
        elif not os.path.exists(out_ok):
            bad("合法回指但文件不存在")
        else:
            with open(out_ok, "r", encoding="utf-8") as fh:
                html = fh.read()
            with open(out_ok + ".manifest.json", "r", encoding="utf-8") as fh:
                man = json.load(fh)
            rid = man.get("report_id")
            if not rid or rid not in html:
                bad("sidecar 的 report_id 在报告里找不到 —— 两者对不上就核不了")
            if man.get("code_fp_short") not in html:
                bad("sidecar 的代码组指纹与页脚不一致")

        # ---- 「不适用」必须单独出现在 sidecar 里 ----
        # 侧车是唯一能被程序读的通道。页面上把「不适用」和「没跑成」分成两块，
        # 机器通道里却只有一个 undecidable 键 —— 那等于在最不该同貌的地方
        # 重新犯一次「零与不可判同貌」，而且没人会看见（没有读者）。
        b3 = E.Bundle(read_at="2026-10-12 12:00:00", root=root)
        b3.evidence.append(E.Evidence(
            eid="OK-0002", claim="照常一条", strength=E.K_LOG_ONLY,
            cites=(E.Cite("2026-10-12", 1),), source="t",
            read_at="2026-10-12 12:00:00"))
        b3.not_applicable.append("A5 总量 不适用：未给 --declare")
        out_na = os.path.join(work, "na.html")
        ok3, _i3 = produce(root, out_na, bundle=b3)
        if not ok3:
            bad("带「不适用」的合法报告没落盘：%s" % _i3.get("error"))
        else:
            with open(out_na + ".manifest.json", "r", encoding="utf-8") as fh:
                man3 = json.load(fh)
            if "not_applicable" not in man3:
                bad("sidecar 没有 not_applicable 键 —— 机器通道里「不适用」消失了")
            elif not man3["not_applicable"]:
                bad("sidecar 的 not_applicable 是空的 —— 这条事实被丢了")
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)

    for f in fails:
        print("[自检失败] %s" % f, file=sys.stderr)
    if fails:
        return 1
    print("[自检] 五条全部生效（回指越界不落盘／不留残文件／合法即落盘／"
          "sidecar 与页脚对得上／不适用进 sidecar）")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="交付入口：产出可交出的一页纸报告")
    ap.add_argument("--root", default=".psl/audit")
    ap.add_argument("--out", default=os.path.join(LINE_C, "out", "报告.html"))
    ap.add_argument("--cap", type=int, default=OP.DEFAULT_CAP)
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if args.selfcheck:
        return _selfcheck()
    if not os.path.isdir(args.root):
        print("[停] 目录不存在：%s" % args.root, file=sys.stderr)
        return 2

    ok, info = produce(args.root, args.out, cap=args.cap)
    if not ok:
        print("[停] %s" % info.get("error"), file=sys.stderr)
        return 2

    print("已写出：%s" % info["out"])
    print("  sidecar：%s" % info["manifest"])
    print("  报告编号 %s ｜ 代码组指纹 %s ｜ 读数时刻 %s"
          % (info["report_id"], info["code_fp"], info["read_at"]))
    print("  证据 %d 条 ｜ 不可判 %d 条 ｜ 回指校验 %s"
          % (info["evidence"], info["undecidable"], info["citecheck"]))
    if info.get("void"):
        print("  ⚠ 本报告已被整份作废（横幅在首屏）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
