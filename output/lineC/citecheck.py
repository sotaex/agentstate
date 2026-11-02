# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""回指校验器：一份报告里每句结论，都能落到账本的具体一行吗？

出处：方案书 §5.7「报告里每一句『已发现／已拦截／已记录』都要能回指一条审计
记录。**回指不到 ⇒ 不许写**。」

──────────────────────────────────────────────────────────────────────────
它检查的是**产物**，不是对象
──────────────────────────────────────────────────────────────────────────
`evidence.verify_cites()` 检查的是内存里的 `Evidence` 对象；
本模块检查的是**渲染出来的 HTML**。两者不能互相替代：

  · 对象对、渲染丢 —— 报告里少了出处，读者照样核不了
  · 渲染对、对象错 —— 那是上游的事，本模块不管

九维三（行为判据）要求「断言用户可观察行为」。对一份报告来说，用户可观察的
行为就是**页面上的字**。所以必须检查产物。

──────────────────────────────────────────────────────────────────────────
为什么不用正则抓「已拦截」「已记录」这些词
──────────────────────────────────────────────────────────────────────────
那是自然语言解析，两个方向都会错：
  · 会漏：换个说法（「挡下了」「已阻止」）就抓不到
  · 会误：正文里提到这个词（比如盲区声明里写「本报告不产出『挡下』」）也会被抓

所以渲染层**必须**显式标注 `data-eid` / `data-strength` / `data-cites`。
这是**契约**，不是可选装饰 —— 缺了不是「通过」，是「这份报告没法校验」。

★ 「没法校验」与「校验通过」必须分开（铁律 1／45）：前者是盲区，后者是结论。
  两者都是「没有报错」，但一个是不知道、一个是知道。混起来就是零与不可判同貌。
"""

import argparse
import os
import sys
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import evidence as E  # noqa: E402

#: 渲染契约里 `data-*` 属性的名字。改这里要同步改渲染层，**只许一处**。
A_EID = "data-eid"
A_STRENGTH = "data-strength"
A_CITES = "data-cites"
A_RULE = "data-rule"
#: 上游判定状态（PASS／WARN／FAIL）。**不是强度档**：强度档说「这条结论有多硬」，
#: 状态说「上游核它的结果是什么」。两者必须分开 —— auditor 的 PASS 与 WARN
#: 在强度词表里是同一个词（「已核对」），只有状态能把它们分开。
A_STATUS = "data-status"

#: 证据条目的容器 class。渲染层必须给它。
CLS_EV = "ev"

#: 强度标签的容器 class（徽标）。用于「页面上出现了几个『挡下』」的行为判据。
CLS_BADGE = "badge"


class Claim:
    """一条从产物里抽出来的断言。"""

    __slots__ = ("eid", "strength", "cites", "rule_id", "text", "status")

    def __init__(self, eid: str, strength: str, cites: List[Tuple[str, int]],
                 rule_id: str = "", text: str = "", status: str = "") -> None:
        self.eid = eid
        self.strength = strength
        self.cites = cites
        self.rule_id = rule_id
        self.text = text
        self.status = status

    def __repr__(self) -> str:
        return "Claim(%s, %s, %d cites)" % (self.eid, self.strength, len(self.cites))


def _parse_cites(raw: str) -> Tuple[List[Tuple[str, int]], List[str]]:
    """`"2026-10-05:0,2026-10-31:3469"` → `[("2026-10-05",0), ...]`。

    解析失败的**单独报出来**，不许静默丢 —— 丢一条 cite 就等于把一条有问题的
    回指变成「没有回指」，而「没有回指」会被上游判成「空 cites 不许存在」，
    报出来的理由是错的。
    """
    out: List[Tuple[str, int]] = []
    errs: List[str] = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            errs.append("出处写法不对（缺冒号）：%r" % part)
            continue
        day, _, ln = part.rpartition(":")
        day = day.strip()
        try:
            out.append((day, int(ln)))
        except ValueError:
            errs.append("出处行号不是整数：%r" % part)
    return out, errs


class _Extractor(HTMLParser):
    """从 HTML 抽证据条目与徽标文本。

    ★ 只认**属性**，不认自然语言。文本只用来做一条行为判据（页面上出现了
      几个「挡下」），不参与「这句结论有没有出处」的判断。
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.claims: List[Claim] = []
        self.contract: List[str] = []
        self.badges: List[str] = []          # 每个徽标元素里的文字
        self._cur: Optional[Dict] = None
        self._depth_ev = 0
        self._in_badge = 0
        self._badge_text: List[str] = []

    # -- 开标签 -------------------------------------------------------------
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = (a.get("class") or "").split()

        if CLS_EV in cls:
            if self._cur is not None:
                self.contract.append(
                    "发现嵌套的 .%s 容器 —— 抽出的条目会串，本工具不支持" % CLS_EV)
            self._depth_ev += 1
            eid = (a.get(A_EID) or "").strip()
            strength = (a.get(A_STRENGTH) or "").strip()
            cites_raw = (a.get(A_CITES) or "").strip()
            rule_id = (a.get(A_RULE) or "").strip()
            status = (a.get(A_STATUS) or "").strip()
            missing = [n for n, v in ((A_EID, eid), (A_STRENGTH, strength),
                                      (A_CITES, cites_raw)) if not v]
            if missing:
                self.contract.append(
                    "证据条目缺渲染契约属性：%s —— 缺了就无法校验（不是通过）"
                    % "、".join(missing))
                self._cur = {"broken": True}
                return
            cites, errs = _parse_cites(cites_raw)
            for e in errs:
                self.contract.append("证据 %s 的 %s" % (eid, e))
            self._cur = {"eid": eid, "strength": strength, "cites": cites,
                         "rule": rule_id, "status": status, "broken": False}

        if CLS_BADGE in cls:
            self._in_badge += 1
            self._badge_text = []

    # -- 文本 ---------------------------------------------------------------
    def handle_data(self, data):
        if self._in_badge:
            self._badge_text.append(data)

    # -- 闭标签 -------------------------------------------------------------
    def handle_endtag(self, tag):
        if tag == "div" and self._depth_ev:
            self._depth_ev -= 1
            if self._cur is not None and self._depth_ev == 0:
                if not self._cur.get("broken"):
                    self.claims.append(Claim(
                        eid=self._cur["eid"], strength=self._cur["strength"],
                        cites=self._cur["cites"], rule_id=self._cur["rule"],
                        status=self._cur.get("status", "")))
                self._cur = None
        if self._in_badge and tag in ("span", "div"):
            self._in_badge -= 1
            self.badges.append("".join(self._badge_text).strip())


def extract(html_text: str) -> Tuple[List[Claim], List[str], List[str]]:
    """返回 `(断言, 契约问题, 徽标文字)`。"""
    p = _Extractor()
    p.feed(html_text)
    p.close()
    return p.claims, p.contract, p.badges


def check(html_text: str, root: str, expect_n: Optional[int] = None
          ) -> Tuple[List[str], List[str], Dict[str, object]]:
    """校验一份渲染产物。返回 `(坏掉的, 不可判的, 统计)`。

    ★ `expect_n` 是**上游证据条数**。传了它，才能抓「渲染丢了证据」——
      只数 HTML 里有多少条是不够的：渲染层少画一条，数出来照样「全都合规」。
      这是本模块最重要的一条：**分母必须来自上游，不能来自被检查的产物本身。**
    """
    claims, contract, badges = extract(html_text)
    bad: List[str] = list(contract)
    notes: List[str] = []

    if not claims and not contract:
        # 一条都没抽到，且契约也没报错 ⇒ 可能真的是空报告，也可能根本没按契约渲染。
        # 两者都是「没法校验」，不是「通过」。
        #
        # ★ 但有一个例外必须分出来：**上游也是 0 条**。
        #   那时「产物 0 条」不是丢了什么，而是本来就没有可校验的东西 ——
        #   这叫空真（vacuously true），不是「不可判」。
        #   分不出来的代价实测过：`report.produce` 把 rc≠0 一律当失败 ⇒
        #   **「今天没事」这份报告永远产不出来**，而它恰恰是主动报告最常见的输出。
        if expect_n == 0:
            return bad, notes, _mk_stats(claims, badges, vacuous=True)
        notes.append(
            "产物里没有抽到任何带 %s 的证据条目 —— 无法校验（可能是空报告，"
            "也可能渲染层没按契约输出；两者都不等于通过）" % A_EID)
        return bad, notes, _mk_stats(claims, badges)

    cache = E.DayCache(root)
    for c in claims:
        if not c.cites:
            bad.append("%s: 没有任何出处 ⇒ 不许写（§5.7）" % c.eid)
            continue
        for day, ln in c.cites:
            status, msg = E.locate(day, ln, cache)
            if status == E.LOC_BAD:
                bad.append("%s: %s" % (c.eid, msg))
            elif status == E.LOC_UNDECIDABLE:
                notes.append("%s: %s" % (c.eid, msg))
        if c.strength not in E.WORD:
            bad.append("%s: 强度档 %r 不在词表内（合法值 %s）"
                       % (c.eid, c.strength, sorted(E.WORD)))
        if c.strength == E.K_HELD and not c.rule_id:
            bad.append("%s: 强度是「%s」却没有 %s ⇒ 会把核对结论说成拦截"
                       % (c.eid, E.WORD[E.K_HELD], A_RULE))

    # 行为判据：页面上出现了几个「挡下」徽标，必须等于标注为 held 的条目数。
    # 防的是「渲染层手写了一个挡下，背后没有对应的证据对象」。
    n_held_word = sum(1 for b in badges if E.WORD[E.K_HELD] in b)
    n_held_claim = sum(1 for c in claims if c.strength == E.K_HELD)
    if n_held_word != n_held_claim:
        bad.append(
            "页面上出现 %d 个「%s」徽标，但只有 %d 条证据标了 held ⇒ 有一条是"
            "手写的、背后没有证据" % (n_held_word, E.WORD[E.K_HELD], n_held_claim))

    # 行为判据：上游判 WARN 的条目，页面上必须有同样多个带「偏离」的徽标。
    # 防的是「性质偏离被印成通过」—— PASS 与 WARN 在强度词表里是同一个词
    # （「已核对」），只有徽标能把它们分开。真账本上 A3（历史缺锚）与
    # A4（495 处倒序）都是 WARN，第一版两条都印成绿色「已核对」。
    # ★ 这条判据的边界，写出来而不是藏着：它只数个数，不建「哪条对应哪个徽标」
    #   的映射（那要靠文档顺序，而 HTMLParser 给出的顺序不保证等于渲染顺序）。
    #   所以它能抓「一条都没标」，抓不到「两条标反了」。
    n_warn_word = sum(1 for b in badges if "偏离" in b)
    n_warn_claim = sum(1 for c in claims if c.status == "WARN")
    if n_warn_word != n_warn_claim:
        bad.append(
            "上游判 WARN 的有 %d 条，页面上带「偏离」的徽标只有 %d 个 ⇒ "
            "性质偏离被印成了通过（两者在强度词表里是同一个词，只能靠徽标分开）"
            % (n_warn_claim, n_warn_word))

    if expect_n is not None and len(claims) != expect_n:
        bad.append(
            "产物里抽出 %d 条证据，上游有 %d 条 ⇒ 渲染丢了 %d 条"
            "（分母来自上游，不来自产物本身）"
            % (len(claims), expect_n, abs(expect_n - len(claims))))

    stats = _mk_stats(claims, badges, n_held_word, n_held_claim, n_warn_word, n_warn_claim)
    return bad, notes, stats


def _mk_stats(claims: List[Claim], badges: List[str],
              n_held_word: int = 0, n_held_claim: int = 0,
              n_warn_word: int = 0, n_warn_claim: int = 0,
              vacuous: bool = False) -> Dict[str, object]:
    """统计字典的**唯一形状定义**。

    ★ 2026-11-02 修：原来「一条证据都没抽到」的早退分支返回的是
      `{"n_claims": 0, "n_badges": N}` —— **比正常路径少了五个键**，
      而 `main()` 打印时要读 `stats["by_strength"]` ⇒ `KeyError` ⇒ 退出码 1
      ⇒ `report.produce` 判「回指校验未通过」⇒ **干净账本根本产不出报告**。

      为什么长期没被发现：`--selfcheck` 直接调 `check()`，**从不经过 `main()` 的打印**。
      又一次「从未被执行过的分支」—— 只看代码看不出来，必须从外面跑一遍 CLI。
      （实测：4 天 × 6 条的干净夹具上 7 臂负控红了 5 臂，全是这一条。）

      修法不是补那五个键，而是**让两条路径共用一个形状定义** ——
      否则下一个早退分支还会漏，而漏的方式和这次一模一样。
    """
    return {
        "n_claims": len(claims),
        "n_badges": len(badges),
        "n_held_word": n_held_word,
        "n_held_claim": n_held_claim,
        "n_warn_word": n_warn_word,
        "n_warn_claim": n_warn_claim,
        "by_strength": _by_strength(claims),
        # 「空真」：上游 0 条、产物 0 条 ⇒ 没有可校验的东西，也没有丢东西。
        # 它既不是「通过」（什么都没核），也不是「不可判」（能确定没有东西可核）。
        # 单独立一个键，而不是塞进 notes —— notes 会让 produce 拒绝落盘。
        "vacuous": vacuous,
    }


def _by_strength(claims: List[Claim]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for c in claims:
        out[c.strength] = out.get(c.strength, 0) + 1
    return out


def _selfcheck() -> int:
    """量具自检：**先证明这把尺子会红，再拿它量报告。**

    八条：①合规产物通过 ②越界回指必红 ③缺契约属性必报（不是通过）
          ④缺 rule 的 held 必红 ⑤手写的「挡下」必红 ⑥空产物必报不可判
          ⑦WARN 不许印成和 PASS 一样的徽标（正反两向都验）
          ⑧空产物与正常路径的 stats **同形**（否则打印侧 KeyError）
    """
    import tempfile
    fails: List[str] = []
    d = tempfile.mkdtemp(prefix="antinel-cc-")
    try:
        with open(os.path.join(d, "2026-11-01.jsonl"), "w", encoding="utf-8") as fh:
            fh.write('{"a":1}\n{"b":2}\n')

        ok_html = ('<div class="ev" data-eid="A1" data-strength="log_only" '
                   'data-cites="2026-11-01:1"><span class="badge">已记录未判定</span></div>')
        bad, notes, st = check(ok_html, d, expect_n=1)
        if bad:
            fails.append("合规产物被报错：%s" % bad)

        over = ('<div class="ev" data-eid="A1" data-strength="log_only" '
                'data-cites="2026-11-01:99"></div>')
        bad, _, _ = check(over, d)
        if not bad:
            fails.append("越界回指没被报错")

        nocontract = '<div class="ev"><span class="badge">已记录未判定</span></div>'
        bad, notes, _ = check(nocontract, d)
        if not bad:
            fails.append("缺 data-eid 的条目没被报契约问题")

        held_norule = ('<div class="ev" data-eid="A1" data-strength="held" '
                       'data-cites="2026-11-01:1"></div>')
        bad, _, _ = check(held_norule, d)
        if not any("rule" in x for x in bad):
            fails.append("held 缺 data-rule 没被报错")

        hand_written = ('<div class="ev" data-eid="A1" data-strength="log_only" '
                        'data-cites="2026-11-01:1"></div>'
                        '<span class="badge">挡下</span>')
        bad, _, _ = check(hand_written, d)
        if not any("手写" in x for x in bad):
            fails.append("手写的「挡下」徽标没被报错")

        # ⑦ WARN 被印成通过（与 PASS 同徽标）必须报错。
        #    这条是**反向对照**：正向的「WARN 有标」也要过，否则修法是「全标偏离」。
        warn_ok = ('<div class="ev" data-eid="A1" data-strength="checked" '
                   'data-status="WARN" data-cites="2026-11-01:1">'
                   '<span class="badge">已核对·有偏离</span></div>')
        bad, _, _ = check(warn_ok, d)
        if any("偏离" in x for x in bad):
            fails.append("WARN 已正确标注却被报错：%s" % bad)
        warn_flat = ('<div class="ev" data-eid="A1" data-strength="checked" '
                     'data-status="WARN" data-cites="2026-11-01:1">'
                     '<span class="badge">已核对</span></div>')
        bad, _, _ = check(warn_flat, d)
        if not any("偏离" in x for x in bad):
            fails.append("WARN 被印成和 PASS 一样的徽标却没被报错"
                         "—— 性质偏离会被读成通过")

        empty = "<html><body><p>本次未发现异常</p></body></html>"
        bad, notes, st_empty = check(empty, d, expect_n=3)
        if bad:
            fails.append("空产物被报成错误（应报不可判）：%s" % bad)
        if not notes:
            fails.append("空产物没有报「无法校验」—— 零与不可判同貌")

        # ⑧ **两条路径的 stats 必须同形**。
        #    2026-11-02 的真事故：空产物分支返回的字典少了 5 个键，
        #    而 `main()` 打印时读 `stats["by_strength"]` ⇒ KeyError ⇒ 退出码 1
        #    ⇒ 干净账本产不出报告。`--selfcheck` 当时全绿，因为它只调 `check()`，
        #    从不走 `main()` 的打印。
        #    所以这一臂断言的是**形状**，不是某个具体值。
        _, _, st_ok = check(ok_html, d, expect_n=1)
        if set(st_empty) != set(st_ok):
            fails.append(
                "空产物的 stats 键与正常路径不一致：缺 %s、多 %s"
                " —— 两条路径返回不同形状，读的一方迟早 KeyError"
                % (sorted(set(st_ok) - set(st_empty)), sorted(set(st_empty) - set(st_ok)))
            )

        # ⑨ `--stdin` 与 `--html` 必须同结论。
        #    这一臂存在的原因不是「多测一条路」：`--stdin` 是 2026-11-02 为绕开
        #    「宿主锁住新建文件、删不掉」才加的第二条入口。**第二条入口天生会漂**
        #    —— 它和第一条读的是同一段 `check()`，但入口参数各自解析。
        #    只验 `check()` 的话，入口写错（比如忘了传 --expect）照样全绿。
        import io
        import contextlib
        p_file = os.path.join(d, "_cc_arm.html")
        with open(p_file, "w", encoding="utf-8") as fh:
            fh.write(ok_html)
        # ★ 这两臂会调 `main()`，而 `main()` 会往 stdout/stderr 印东西。
        #   不静音的话，闸门取「最后一行」当摘要，摘要就会变成
        #   `citecheck.py: error: --html 与 --stdin 只能给一个` —— 一条**故意**
        #   触发的错误盖住了「九条全绿」。摘要被噪声顶掉，等于摘要失效。
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            rc_file = main(["--html", p_file, "--root", d, "--expect", "1"])
        old_stdin = sys.stdin
        try:
            sys.stdin = io.StringIO(ok_html)
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc_stdin = main(["--stdin", "--root", d, "--expect", "1"])
        finally:
            sys.stdin = old_stdin
        if rc_file != rc_stdin:
            fails.append("--stdin 与 --html 结论不一致：%s vs %s"
                         % (rc_file, rc_stdin))

        # ⑨b 两个入口同时给必须**拒**，不许默认挑一个。
        #    默认挑一个的后果：调用方以为校验了 A，实际校验的是 B，而两者都绿。
        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                main(["--html", p_file, "--stdin", "--root", d])
            fails.append("--html 与 --stdin 同时给出却接受了 —— 校验对象不明时不许猜")
        except SystemExit as exc:
            if exc.code not in (2,):
                fails.append("--html 与 --stdin 同时给出的拒绝方式不对：退出码 %s" % exc.code)
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    for f in fails:
        print("[自检失败] %s" % f, file=sys.stderr)
    if fails:
        return 1
    print("[自检] 九条全部生效（合规／越界／缺契约／缺rule／手写挡下／空产物不可判／"
          "WARN 不许印成通过／stats 两条路径同形／stdin 与 html 同结论且互斥）")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="回指校验器（只读，档 0）")
    ap.add_argument("--html", help="要校验的 HTML 文件")
    ap.add_argument(
        "--stdin",
        action="store_true",
        help="从标准输入读 HTML（而不是从文件读）。"
        "★ 存在的理由不是「方便」：宿主会对**新建的文件**持有句柄且不释放"
        "（实测 WinError 5 持续 60 秒以上），于是「先写临时文件、校验、再删掉」"
        "这条路会在删不掉时崩掉 —— 而崩的那条分支只在有坏回指时才走。"
        "走管道就根本没有文件，也就不存在删不掉。",
    )
    ap.add_argument("--root", default=".psl/audit")
    ap.add_argument("--expect", type=int, default=None, help="上游证据条数（抓渲染丢条）")
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if args.selfcheck:
        return _selfcheck()
    if not args.html and not args.stdin:
        ap.error("要么 --selfcheck，要么给 --html，要么 --stdin")
    if args.html and args.stdin:
        # 两个都给就是没说清校验对象 —— 不许默认挑一个（挑错时结论照样是绿的）
        ap.error("--html 与 --stdin 只能给一个")

    if args.stdin:
        text = sys.stdin.read()
        src = "<stdin>"
    else:
        if not os.path.isfile(args.html):
            print("[停] 文件不存在：%s" % args.html, file=sys.stderr)
            return 2
        with open(args.html, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        src = args.html

    bad, notes, stats = check(text, args.root, args.expect)

    print("产物：%s" % src)
    print("抽出证据 %d 条｜徽标 %d 个｜分布 %s"
          % (stats["n_claims"], stats["n_badges"], stats["by_strength"]))
    if notes:
        print("不可判（%d）：" % len(notes))
        for n in notes:
            print("  · %s" % n)
    if bad:
        print("坏了（%d）：" % len(bad))
        for b in bad:
            print("  ✗ %s" % b)
        return 1
    if notes:
        # 有不可判但没有坏 —— 不算通过，也不算失败。退出码 3 让调用方区分。
        return 3
    if stats.get("vacuous"):
        # 空真：0 条证据、上游也是 0 条。**要说出来**，不能印成「通过」——
        # 「通过：每条断言都能落到账本的具体位置」在 0 条时是句空话。
        print("空真：0 条证据，上游也是 0 条 ⇒ 没有可校验的东西，也没有丢东西"
              "（这不是「校验通过」，是「没东西可校」）")
        return 0
    print("通过：每条断言都能落到账本的具体位置")
    return 0


if __name__ == "__main__":
    sys.exit(main())
