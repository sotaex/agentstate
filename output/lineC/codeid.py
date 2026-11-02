# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""代码指纹：回答「这份结论，是哪份代码算出来的」。

──────────────────────────────────────────────────────────────────────────
它治的是什么
──────────────────────────────────────────────────────────────────────────
C 线全是一次性只读脚本，没有常驻进程、没有版本号可看、没有心跳。于是九维六
（运行态确认）在这里退化成更基础的一问：

    **这次跑出来的结论，是哪份代码算的？**

答不出来，「昨天绿、今天红」就无法归因——可能是账本变了，也可能代码变了，
还可能跑的是旧 `.pyc`。三种情况在报告里长得一模一样。

──────────────────────────────────────────────────────────────────────────
为什么单独一个文件（R4：同一件事一处实现）
──────────────────────────────────────────────────────────────────────────
`SOURCES` 是**唯一真源**。闸门（`selfproof.py`）与报告页脚（`onepager.py`）
都从这里取。如果各写一份清单，两份一定会漂；漂了以后两个指纹仍然都是
「看起来正常」的 64 位十六进制串——**错的东西长得和正确的东西一样**，
这是本项目最贵的一类缺陷（见《零与不可判同貌》）。

──────────────────────────────────────────────────────────────────────────
三条设计约束
──────────────────────────────────────────────────────────────────────────
1. **名字参与哈希**。只哈希内容的话，「两个文件互换内容」算出的组指纹不变，
   而那是两套不同的代码。所以基串是 `名字:sha256` 按名字排序后拼接。
2. **缺一个文件就不许出指纹**。不许「拿剩下的算一个」，那会算出一个
   看起来完整、实际少了一块的值。缺文件 ⇒ `gid` 为空、`missing` 非空，
   调用方必须显式处理（页脚明说「不完整」，闸门直接红）。
3. **`codeid.py` 自己也在清单里**。算法本身也参与结论，所以它也要有出处。
   代价是每次改本文件指纹都会变——这正是想要的。

──────────────────────────────────────────────────────────────────────────
它不做什么
──────────────────────────────────────────────────────────────────────────
不判断代码对不对，只回答「是哪一份」。指纹相同不等于结论正确。
"""

import hashlib
import os
import sys
import tempfile
from typing import List, NamedTuple, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
#: ★ 本文件就在 lineC 里。这个坑踩过两次（redteam.py／selfproof.py）：
#: 写成 os.path.join(HERE, "lineC") 会多一层，于是「源文件全部缺失」——
#: 而它看起来像「文件真的没了」。
LINE_C = HERE if os.path.basename(HERE) == "lineC" else os.path.join(HERE, "lineC")
OUTPUT = os.path.dirname(LINE_C)

#: 参与结论计算的源文件。顺序即报告里的显示顺序。
#:
#: ★ 只列**会进入结论**的文件。把一次性量具（`output/_p_*.py`）算进来会让
#:   指纹随量具变动而漂，那指纹就不再是「结论的来源」了。
#: ★ `redteam.py` 进来是因为它决定了报告里那句「我们只能说这么多」是否仍然
#:   成立——它证明的是边界，而边界也是结论的一部分。
SOURCES: List[str] = [
    os.path.join(LINE_C, "codeid.py"),
    os.path.join(LINE_C, "tsnorm.py"),
    os.path.join(LINE_C, "auditor.py"),
    os.path.join(LINE_C, "watchman.py"),
    # ★ 2026-11-02 深夜补两个漏项。判据只有一条：**它会不会改变报告上的数字或措辞**。
    #   · `verdict_leg.py` 产出「挡下」「已发现无法处置」两档 —— 一页纸首屏那两个数
    #     完全由它决定。它不进清单 ⇒ 换了分档规则，指纹不变，归档报告对不上账。
    #   · `clue_ledger.py` 决定哪条线索被静默 —— 它不改「世界」，但它改「报告说什么」。
    #   两个都曾经不在清单里，而闸门当时仍然全绿：**新模块默认不受指纹保护**，
    #   这是清单式真源的固有风险（漏登记不报错），只能靠「新增模块必须登记」这条纪律。
    os.path.join(LINE_C, "clue_ledger.py"),
    os.path.join(LINE_C, "verdict_leg.py"),
    os.path.join(LINE_C, "evidence.py"),
    os.path.join(LINE_C, "citecheck.py"),
    os.path.join(LINE_C, "onepager.py"),
    os.path.join(LINE_C, "report.py"),
    os.path.join(LINE_C, "corrections.py"),
    os.path.join(LINE_C, "redteam.py"),
    os.path.join(LINE_C, "redteam_c2.py"),
]


def sha_file(path: str) -> str:
    """文件的 sha256；不存在返回空串（**不是**返回一串 0，那会被当成有效值）。"""
    if not os.path.isfile(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def group_fingerprint(items: Sequence[Tuple[str, str]]) -> str:
    """组指纹：`名字:sha256` 按名字排序后拼接再哈希。

    ★ 排序是为了让「清单顺序」不影响结果——否则改一下 SOURCES 的排列
      就会让所有归档报告的指纹对不上，而代码其实一个字没改。
    """
    basis = "\n".join("%s:%s" % (n, h) for n, h in sorted(items))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


class Fingerprint(NamedTuple):
    """一次计算结果。`gid` 为空 ⇔ `missing` 非空（两者必须同时成立）。"""

    gid: str                              #: 完整 64 位；不完整时为空串
    items: List[Tuple[str, str]]          #: (文件名, 完整 sha256)
    missing: List[str]                    #: 缺失的文件名

    @property
    def ok(self) -> bool:
        return bool(self.gid) and not self.missing

    @property
    def short(self) -> str:
        return self.gid[:16]

    def pairs(self, n: int = 12) -> str:
        """`tsnorm:1a2b3c4d5e6f、auditor:...`，给页脚用的一行。"""
        return "、".join("%s:%s" % (k, v[:n]) for k, v in self.items)

    def note(self) -> str:
        """一句话说明「这个指纹能干什么、不能干什么」。"""
        if not self.ok:
            return ("代码指纹不完整（缺 %d 个：%s）⇒ 本结论的出处无法核对。"
                    % (len(self.missing), "、".join(self.missing)))
        # ★ 不用 `**加粗**`：这句话要同时进终端和进 HTML，Markdown 星号在
        #   HTML 里会原样露出来（实测页脚印出 `**不等于结论正确**`）。
        #   同一个字符串被两个消费者读，就得挑两边都成立的字面。
        return ("指纹相同 ⇒ 是同一份代码算的；不等于结论正确——"
                "代码自洽与结论为真是两件事。")


def compute(paths: Optional[Sequence[str]] = None) -> Fingerprint:
    """算指纹。`paths` 不给就用 `SOURCES`（自检要能传坏路径进来）。"""
    items: List[Tuple[str, str]] = []
    missing: List[str] = []
    for p in (paths if paths is not None else SOURCES):
        name = os.path.basename(p)
        h = sha_file(p)
        if not h:
            missing.append(name)
            continue
        items.append((name, h))
    if missing:
        # ★ 不拿剩下的算。残缺的指纹比没有指纹更危险：它看起来是完整的。
        return Fingerprint(gid="", items=items, missing=missing)
    return Fingerprint(gid=group_fingerprint(items), items=items, missing=[])


# ──────────────────────────────────────────────────────────────────────────
# 自检：先证明这把尺子自己不会乱读数，再拿它量代码
# ──────────────────────────────────────────────────────────────────────────

def _selfcheck() -> int:
    fails: List[str] = []

    def bad(msg: str) -> None:
        fails.append(msg)

    # 1 稳定性：同一批内容算两次必须一样（否则页脚与闸门永远对不上）
    a = compute()
    b = compute()
    if a.gid != b.gid:
        bad("同一批文件算两次指纹不同 —— 指纹不可复现，等于没有指纹")
    if not a.ok:
        bad("真实源文件算不出指纹：缺 %s" % "、".join(a.missing))

    # 2 顺序无关：清单顺序颠倒，指纹必须不变
    rev = compute(list(reversed(SOURCES)))
    if rev.gid != a.gid:
        bad("清单顺序影响指纹 —— 改一下排列就让全部归档报告对不上")

    # 3 内容敏感：改一个字节必须变
    #
    # ★ ignore_cleanup_errors=True 不是省事：本机默认 TMP 落在 `C:\Temp\PGINST~1\`，
    #   删临时目录会被拒（WinError 5），于是「清理失败」被当成「自检崩了」——
    #   而自检的断言其实全过了。**工具失败被读成结论失败**，正是本项目最忌的那种。
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        p1 = os.path.join(td, "x.py")
        p2 = os.path.join(td, "y.py")
        with open(p1, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("A = 1\n")
        with open(p2, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("A = 2\n")
        f1 = compute([p1])
        f2 = compute([p2])
        if not f1.ok or not f2.ok:
            bad("临时文件算不出指纹")
        elif f1.gid == f2.gid:
            bad("内容不同却指纹相同 —— 指纹对改动是瞎的")

        # 4 名字参与哈希：两个文件互换内容，指纹必须变（这是最隐蔽的一种）
        p3 = os.path.join(td, "x.py")
        p4 = os.path.join(td, "y.py")
        with open(p3, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("A = 2\n")          # 内容互换
        with open(p4, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("A = 1\n")
        f3 = compute([p3, p4])
        if f3.ok and f3.gid == f1.gid:
            bad("两个文件互换内容后组指纹不变 —— 名字没有参与哈希，这是两套代码")

        # 5 缺文件：必须 ok=False 且 gid 为空，**不许**拿剩下的算一个
        f4 = compute([p3, os.path.join(td, "nope.py")])
        if f4.ok:
            bad("缺文件却报 ok —— 残缺指纹会被当成完整指纹用")
        if f4.gid:
            bad("缺文件却仍算出了 gid —— 它看起来完整，实际少了一块")
        if "nope.py" not in f4.missing:
            bad("缺文件没有进 missing 清单")
        if "不完整" not in f4.note():
            bad("缺文件时 note() 没有明说「不完整」")

    # 6 清单里每个文件真实存在（防止 SOURCES 写错路径而无人发现）
    for p in SOURCES:
        if not os.path.isfile(p):
            bad("SOURCES 里的文件不存在：%s" % p)

    # 7 自己也在清单里（算法本身也要有出处）
    if os.path.join(LINE_C, "codeid.py") not in SOURCES:
        bad("codeid.py 不在 SOURCES 里 —— 算法变了指纹却不变")

    for f in fails:
        print("[自检失败] %s" % f, file=sys.stderr)
    if fails:
        return 1
    print("[自检] 七条全部生效（可复现／顺序无关／内容敏感／名字参与哈希／"
          "缺文件即不完整／路径真实／算法自身有出处）")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="代码组指纹（只读）")
    ap.add_argument("--selfcheck", action="store_true")
    ap.add_argument("--pairs", action="store_true", help="同时列出每个文件的短哈希")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if args.selfcheck:
        return _selfcheck()

    fp = compute()
    if not fp.ok:
        print("[停] 指纹不完整：缺 %s" % "、".join(fp.missing), file=sys.stderr)
        return 2
    print(fp.short)
    if args.pairs:
        print(fp.pairs())
    return 0


if __name__ == "__main__":
    sys.exit(main())
