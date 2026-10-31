# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""更正机制：报告一旦发出就不许改，更正只能追加。

出处：《C 线更正机制设计 v1.0》§3（数据结构）／§4（渲染规则）。
方案书 §5.5 原文：**「记录错了比没记更危险，因为它看起来像证据。」**

──────────────────────────────────────────────────────────────────────────
准入三问
──────────────────────────────────────────────────────────────────────────
1. 需求：**A（主动去看）**。这里不产生结论，只记录「某条结论被取代了」。
2. 决策器档：**档 0**（纯文件读写与哈希，无模型、无网络）。
3. 裁量位置：**观测侧**。唯一裁量是「这次算不算更正」——那由人写进 `reason`，
   代码不替人判断。

──────────────────────────────────────────────────────────────────────────
三条硬约束（设计 §3.3），违反即抛，不降级成警告
──────────────────────────────────────────────────────────────────────────
1. `corrections.jsonl` **只许追加**：写前算文件 hash，与旁路 `.corrections.sha256`
   比对；不一致 ⇒ 拒绝写并报「更正记录被动过」。
2. `target_eid` **必须在那份报告里真实存在**：拿不到 ⇒ 拒绝。
   不许更正一个不存在的条目——那会造出一条幽灵更正。
3. **一条证据只许被取代一次**：第二次 `supersede` 指向同一 `target_eid` ⇒ 拒绝。

──────────────────────────────────────────────────────────────────────────
为什么约束 2 需要「已知证据集」而不能自己猜
──────────────────────────────────────────────────────────────────────────
报告是 HTML，不是机器可读的证据表。要验证「AUD-xxx 在那份报告里」，必须有人
告诉我们那份报告有哪些 eid。所以 `append()` 要 `known_eids`：

    {report_id: {eid, ...}}

- 更正**当前这份**报告：调用方传 `{report_id(bundle): {e.eid for e in bundle.evidence}}`
- 更正**历史**报告：调用方必须显式提供——**没提供就是不知道，不知道就不许写**。

★ 这里刻意不建 `reports.jsonl` 索引：多一个文件就多一个「看起来有、其实没人维护」
  的台账。宁可要求调用方显式给出，也不做一份会悄悄腐烂的索引。

──────────────────────────────────────────────────────────────────────────
本机制**不能**证明什么（设计 §7，写在这里防误读）
──────────────────────────────────────────────────────────────────────────
1. 不能防「故意更正」——可以把真结论更正成假的。锚只在账本层，报告层没有外部锚。
   ⇒ 措辞里不许说「不可篡改」，只能说「改过会留痕」。
2. 不能覆盖「整份报告被悄悄替换」——替换文件并同步改 `corrections.jsonl`，
   本机制看不出来。
3. 不解决「谁有权更正」——`by` 是自述，没有身份验证。
"""

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import evidence as E  # noqa: E402

#: 三种更正。**不许合并**：`supersede` 改一条、`void` 废整份、`note` 只补话不改结论。
K_SUPERSEDE = "supersede"
K_VOID = "void"
K_NOTE = "note"
KINDS = (K_SUPERSEDE, K_VOID, K_NOTE)

#: 文件名（与账本同目录，设计 §3.2）。
CORR_FILE = "corrections.jsonl"
#: 只追加的旁路指纹。文件本身不许含自己的 hash（否则改一个字节要全量重算）。
CORR_SEAL = ".corrections.sha256"


# --------------------------------------------------------------------------- 报告标识


def ledger_tail(root: str) -> str:
    """账本**最后一条记录**的 `hash`。取不到返回空串——**不是**报错。

    ★ 返回空串必须被上层看见（见 `report_id_note`）。空串与「hash 是空字符串」
      在数据上同貌，但在语义上一个是不适用、一个是真值——这正是本项目反复栽的
      「零与不可判同貌」。所以这里只负责取，判由上层判。
    """
    try:
        names = sorted(
            f[:-6] for f in os.listdir(root)
            if f.endswith(".jsonl") and f[:2] == "20" and len(f) > 6
        )
    except OSError:
        return ""
    for day in reversed(names):
        last = ""
        try:
            with open(os.path.join(root, day + ".jsonl"), "r",
                      encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    if ln.strip():
                        last = ln
        except OSError:
            continue
        if not last:
            continue
        try:
            got = json.loads(last)
        except Exception:
            return ""
        if isinstance(got, dict):
            return str(got.get("hash") or "")
        return ""
    return ""


def report_id(bundle: "E.Bundle") -> str:
    """`R-` + sha256(读数时刻 + 账本末条 hash + 证据 id 集合)[:12]。

    ★ **不取文件内容的 hash**：内容里含渲染时间戳，会导致「同一份报告每次算出的
      id 都不同」——那样 id 就不是标识，是随机数。
    """
    basis = "|".join((
        str(bundle.read_at or ""),
        ledger_tail(bundle.root),
        ",".join(sorted(e.eid for e in bundle.evidence)),
    ))
    return "R-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]


def report_id_note(bundle: "E.Bundle") -> str:
    """`report_id` 少算了什么。空串＝三个成分都在。

    ★ 少算不是错误，是**强度下降**：少了账本末条 hash，就无法区分「账本没变但重跑」
      与「账本变了」。这件事必须说出来，否则读者会以为 id 覆盖了它其实没覆盖的东西。
    """
    miss: List[str] = []
    if not str(bundle.read_at or "").startswith("20"):
        miss.append("读数时刻")
    if not ledger_tail(bundle.root):
        miss.append("账本末条 hash")
    if not bundle.evidence:
        miss.append("证据 id 集合（这份报告没有证据）")
    if not miss:
        return ""
    return ("本报告的 id 少算了：%s。⇒ 它仍能区分不同的报告，"
            "但不能用来证明「账本没变过」。" % "、".join(miss))


# --------------------------------------------------------------------------- 更正记录


@dataclass(frozen=True)
class Correction:
    """一条更正。**不可变**——更正记录没有「修改」，只有「再更正一次」。"""

    at: str
    by: str
    kind: str
    target_report: str
    reason: str
    target_eid: str = ""
    new_report: str = ""
    new_eid: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError("更正类型不在词表内：%r（合法 %s）" % (self.kind, list(KINDS)))
        if not self.reason.strip():
            # 更正没有理由 = 又一次不可核的断言（设计 §3.2 表最后一行）。
            raise ValueError("更正没有理由——那只是换个说法，不是更正")
        if not self.target_report.strip():
            raise ValueError("更正没说是哪份报告")
        if self.kind == K_SUPERSEDE:
            if not self.target_eid.strip():
                raise ValueError("supersede 必须指明被取代的条目（target_eid）")
            if not self.new_eid.strip():
                raise ValueError("supersede 必须指明取代它的新条目（new_eid）")
        if self.kind == K_VOID:
            if self.target_eid.strip():
                raise ValueError("void 是整份作废，不该带 target_eid（要废一条请用 supersede）")
            if not self.new_report.strip():
                raise ValueError("void 必须指明「请以哪份为准」（new_report）")

    def to_json(self) -> Dict[str, str]:
        return {
            "at": self.at, "by": self.by, "kind": self.kind,
            "target_report": self.target_report, "reason": self.reason,
            "target_eid": self.target_eid,
            "new_report": self.new_report, "new_eid": self.new_eid,
        }

    @classmethod
    def from_json(cls, d: Dict[str, str]) -> "Correction":
        return cls(
            at=str(d.get("at") or ""), by=str(d.get("by") or ""),
            kind=str(d.get("kind") or ""),
            target_report=str(d.get("target_report") or ""),
            reason=str(d.get("reason") or ""),
            target_eid=str(d.get("target_eid") or ""),
            new_report=str(d.get("new_report") or ""),
            new_eid=str(d.get("new_eid") or ""),
        )


def _sha_file(path: str) -> str:
    """文件内容指纹。文件不存在 ⇒ 空串（与「内容是空」分开：见 `_read_seal`）。"""
    if not os.path.isfile(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class Ledger:
    """`corrections.jsonl` 的读写。**只许追加**由 `_seal()` 强制。"""

    def __init__(self, root: str):
        self.root = root
        self.path = os.path.join(root, CORR_FILE)
        self.seal_path = os.path.join(root, CORR_SEAL)

    # ---- 读 ----
    def load(self) -> List[Correction]:
        if not os.path.isfile(self.path):
            return []
        out: List[Correction] = []
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for i, ln in enumerate(fh, 1):
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    out.append(Correction.from_json(json.loads(ln)))
                except Exception as exc:
                    raise ValueError(
                        "更正记录第 %d 行读不出来（%s）—— 不许跳过，跳过等于假装它不存在"
                        % (i, exc))
        return out

    # ---- 只追加的守门 ----
    def _read_seal(self) -> Optional[str]:
        """旁路指纹。**文件不存在返回 None**（首次写），与「指纹是空串」分开。"""
        if not os.path.isfile(self.seal_path):
            return None
        with open(self.seal_path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()

    def _check_untouched(self) -> None:
        """约束 1：更正记录被外部动过 ⇒ 拒绝写。"""
        sealed = self._read_seal()
        if sealed is None:
            # 首次写：若 corrections.jsonl 已存在却没指纹，说明它是别人放进去的。
            if os.path.isfile(self.path) and os.path.getsize(self.path) > 0:
                raise PermissionError(
                    "更正记录已存在但没有指纹（%s）—— 无法证明它没被改过，拒绝追加。"
                    "确认来源后手工建指纹，或换一个目录。" % CORR_SEAL)
            return
        actual = _sha_file(self.path)
        if actual != sealed:
            raise PermissionError(
                "更正记录被动过（指纹 %s… ≠ 实测 %s…）。拒绝追加——"
                "**能改的账不是账，是笔记**。" % (sealed[:12], actual[:12]))

    def _seal(self) -> None:
        with open(self.seal_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(_sha_file(self.path) + "\n")

    # ---- 写 ----
    def append(self, c: Correction,
               known_eids: Dict[str, Iterable[str]]) -> None:
        """追加一条更正。三条硬约束全过才落盘，**任何一条不过就抛**。"""
        self._check_untouched()

        # 约束 2：target_eid 必须真实存在
        if c.kind == K_SUPERSEDE:
            pool = known_eids.get(c.target_report)
            if pool is None:
                raise ValueError(
                    "不知道报告 %s 有哪些条目 ⇒ 无法验证 %s 是否真实存在。"
                    "不许更正一个验证不了的条目——那会造出幽灵更正。"
                    % (c.target_report, c.target_eid))
            if c.target_eid not in set(pool):
                raise ValueError(
                    "报告 %s 里没有条目 %s ⇒ 拒绝（幽灵更正）"
                    % (c.target_report, c.target_eid))

        # 约束 3：一条只许被取代一次
        if c.kind == K_SUPERSEDE:
            for old in self.load():
                if (old.kind == K_SUPERSEDE
                        and old.target_report == c.target_report
                        and old.target_eid == c.target_eid):
                    raise ValueError(
                        "条目 %s 已被 %s 取代过一次（%s）⇒ 拒绝。"
                        "要改判请先用 note 记下撤销理由，再更正新条目。"
                        % (c.target_eid, old.new_eid, old.at))

        if not os.path.isdir(self.root):
            os.makedirs(self.root, exist_ok=True)
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(c.to_json(), ensure_ascii=False) + "\n")
        self._seal()


# --------------------------------------------------------------------------- 结算


@dataclass
class Resolved:
    """一份报告该被渲染成什么样。**渲染层只读这个，不自己翻 jsonl。**"""

    report_id: str = ""
    #: eid -> 取代它的那条更正
    superseded: Dict[str, Correction] = field(default_factory=dict)
    #: 整份作废（最多一条；多条时取最晚的，但会记进 `warnings`）
    void: Optional[Correction] = None
    #: 这份报告**取代了**哪些旧报告（设计 §4.2 红线 3：必须反向指认）
    supersedes: List[str] = field(default_factory=list)
    #: 与更正记录有关的异常（读不出来、重复作废…）。**不许静默。**
    warnings: List[str] = field(default_factory=list)


def resolve(bundle: "E.Bundle", corrections: Sequence[Correction]) -> Resolved:
    """把更正记录结算成「这份报告怎么显示」。"""
    rid = report_id(bundle)
    out = Resolved(report_id=rid)
    voids: List[Correction] = []

    for c in corrections:
        if c.kind == K_SUPERSEDE and c.target_report == rid:
            out.superseded[c.target_eid] = c
        elif c.kind == K_VOID and c.target_report == rid:
            voids.append(c)
        elif c.kind == K_SUPERSEDE and c.new_report == rid and c.new_eid:
            # 反向指认：我是「取代别人的那一份」⇒ 我必须说出我取代了谁。
            if c.target_report not in out.supersedes:
                out.supersedes.append(c.target_report)
        elif c.kind == K_VOID and c.new_report == rid:
            if c.target_report not in out.supersedes:
                out.supersedes.append(c.target_report)

    if len(voids) > 1:
        out.warnings.append(
            "这份报告被作废了 %d 次（%s）—— 只按最晚一条显示，但这件事本身可疑："
            "作废是终态，不该重复。" % (len(voids), "、".join(v.at for v in voids)))
    if voids:
        out.void = sorted(voids, key=lambda v: v.at)[-1]

    # 一条 eid 同时出现在 superseded 与 void 里不是错：整份废了，条目上的标注仍在。
    return out


# --------------------------------------------------------------------------- 自检


def _mk(eid: str = "AUD-0001") -> "E.Bundle":
    ev = E.Evidence(eid=eid, claim="测试结论", strength=E.K_LOG_ONLY,
                    cites=(E.Cite("2026-11-01", 3),), source="t",
                    read_at="2026-11-01 03:00:00")
    b = E.Bundle(read_at="2026-11-01 03:00:00", root="")
    b.evidence.append(ev)
    return b


def _selfcheck() -> int:
    """量具自检：六条验收口径里**与纯函数有关**的五条，先在这里红一遍。"""
    import tempfile

    fails: List[str] = []
    tmp = tempfile.mkdtemp(prefix="corr_")

    b = _mk()
    rid = report_id(b)
    known = {rid: {e.eid for e in b.evidence}}

    # 0 基本形状
    if not rid.startswith("R-") or len(rid) != 14:
        fails.append("report_id 形状不对：%r" % rid)

    # 1 同内容同 id（位置无关）
    b2 = _mk()
    if report_id(b2) != rid:
        fails.append("同内容算出不同 report_id —— id 不稳定就不能当标识")

    # 2 约束 2：指向不存在的条目 ⇒ 必须抛
    led = Ledger(tmp)
    ghost = Correction(at="2026-11-01T03:10:00+08:00", by="C-3", kind=K_SUPERSEDE,
                       target_report=rid, target_eid="AUD-zzzz",
                       reason="故意指向不存在", new_eid="AUD-0002")
    try:
        led.append(ghost, known)
        fails.append("幽灵更正（target_eid 不存在）被接受了")
    except ValueError:
        pass

    # 3 约束 2 的另一面：不知道那份报告 ⇒ 必须抛（不是「放行」）
    try:
        led.append(Correction(at="t", by="C-3", kind=K_SUPERSEDE,
                              target_report="R-unknown00000",
                              target_eid="AUD-0001", reason="r",
                              new_eid="AUD-0002"), known)
        fails.append("对「不知道的报告」也放行了 —— 那是把盲区当结论")
    except ValueError:
        pass

    # 4 合法更正能写进去
    ok = Correction(at="2026-11-01T03:10:00+08:00", by="C-3", kind=K_SUPERSEDE,
                    target_report=rid, target_eid="AUD-0001",
                    reason="该日机制当时不存在，不是漏了", new_eid="AUD-0002")
    led.append(ok, known)
    if len(led.load()) != 1:
        fails.append("合法更正没写进去")

    # 5 约束 3：同一条被取代两次 ⇒ 必须抛
    try:
        led.append(Correction(at="2026-11-01T04:00:00+08:00", by="C-3",
                              kind=K_SUPERSEDE, target_report=rid,
                              target_eid="AUD-0001", reason="再来一次",
                              new_eid="AUD-0003"), known)
        fails.append("同一条被取代两次却放行了")
    except ValueError:
        pass

    # 6 约束 1：记录被外部改动 ⇒ 必须拒绝写
    with open(led.path, "a", encoding="utf-8") as fh:
        fh.write('{"kind":"note"}\n')
    try:
        led.append(Correction(at="t", by="C-3", kind=K_NOTE,
                              target_report=rid, reason="补充"), known)
        fails.append("更正记录被动过后仍允许追加 —— 只追加形同虚设")
    except PermissionError:
        pass

    # 7 note 不需要 target_eid，也不该被约束 2 误伤
    tmp2 = tempfile.mkdtemp(prefix="corr2_")
    led2 = Ledger(tmp2)
    try:
        led2.append(Correction(at="t", by="C-3", kind=K_NOTE,
                               target_report=rid, reason="只是补充说明"), {})
    except Exception as exc:
        fails.append("note 被误伤了：%s" % exc)

    # 8 void 必须带 new_report，且不许带 target_eid
    for bad, why in (
        (dict(kind=K_VOID, target_report=rid, reason="r", target_eid="AUD-1"),
         "void 带了 target_eid"),
        (dict(kind=K_VOID, target_report=rid, reason="r"),
         "void 没带 new_report"),
    ):
        try:
            Correction(at="t", by="C-3", **bad)
            fails.append("%s 却构造成功了" % why)
        except ValueError:
            pass

    # 9 结算：被取代的条目、作废、反向指认
    r = resolve(b, [ok])
    if "AUD-0001" not in r.superseded:
        fails.append("结算没认出被取代的条目")
    if r.void is not None:
        fails.append("只有 supersede 却结算出了 void")

    v = Correction(at="2026-11-01T05:00:00+08:00", by="C-3", kind=K_VOID,
                   target_report=rid, reason="整份基于错误读数", new_report="R-new000000001")
    rv = resolve(b, [v])
    if rv.void is None:
        fails.append("结算没认出整份作废")

    # 10 反向指认：新报告必须说出自己取代了谁
    new_b = _mk("AUD-0002")
    rid_new = report_id(new_b)
    c_new = Correction(at="t", by="C-3", kind=K_SUPERSEDE,
                       target_report=rid, target_eid="AUD-0001",
                       reason="r", new_report=rid_new, new_eid="AUD-0002")
    rn = resolve(new_b, [c_new])
    if rid not in rn.supersedes:
        fails.append("新报告没有反向指认旧报告 —— 旧报告归档后读者找不到新结论")

    # 11 重复作废要报出来，不许静默取最后一条
    rr = resolve(b, [v, Correction(at="2026-11-01T06:00:00+08:00", by="C-3",
                                   kind=K_VOID, target_report=rid,
                                   reason="又废一次", new_report="R-x0000000000")])
    if not rr.warnings:
        fails.append("重复作废没有报出来")

    for f in fails:
        print("[自检失败] %s" % f, file=sys.stderr)
    if fails:
        return 1
    print("[自检] 十一条全部生效（id 稳定／幽灵更正／未知报告／合法写入／"
          "重复取代／改动即拒／note 不误伤／void 形状／结算／反向指认／重复作废）")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="更正机制（只追加，档 0）")
    ap.add_argument("--root", default=".psl/audit", help="账本目录（corrections.jsonl 与它同目录）")
    ap.add_argument("--list", action="store_true", help="列出已有更正")
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

    led = Ledger(args.root)
    try:
        items = led.load()
    except ValueError as exc:
        print("[停] %s" % exc, file=sys.stderr)
        return 2

    if args.list:
        if not items:
            print("（还没有任何更正记录）")
            return 0
        for c in items:
            print("%s  %-9s  %s → %s：%s"
                  % (c.at, c.kind, c.target_eid or c.target_report,
                     c.new_eid or c.new_report, c.reason))
        return 0

    print("更正记录 %d 条（%s）" % (len(items), led.path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
