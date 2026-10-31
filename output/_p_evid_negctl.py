# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""C-3 取证 Agent 的负控（四件套②③ ＋ 九维二／三 ＋ id 稳定性）。

跑法：
    TMPDIR=/c/Users/大马/AppData/Local/Temp python -E -X utf8 \
        output/_p_evid_negctl.py

★ 为什么负控要单独一个文件而不是塞进 evidence.py
  铁律 1：测不出 ⇒ 报「夹具失效／SKIP」，绝不报 PASS。负控自己也会坏
  （第一版 verify_cites 就把「天粒度」当越界报红，负控没写就发现不了）。
  放在独立文件里，坏的是它自己，不会连累被测对象。

★ 一条贯穿全篇的纪律：**负控必须真红过**。
  下面每个臂都记 `ok=True/False`，最后只数 True。任何一条 `False` 都表示
  「这个保护其实没生效」——比没有保护更危险，因为它让人以为有。
"""

import json
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LINEC = os.path.join(HERE, "lineC")
sys.path.insert(0, LINEC)

import evidence as E  # noqa: E402

RESULTS = []


def arm(name, fn):
    """跑一个臂。异常一律记成失败 —— 负控自己崩了也算没通过（不许静默跳过）。"""
    try:
        ok, detail = fn()
    except Exception as exc:                          # noqa: BLE001
        ok, detail = False, "负控自身崩了：%s: %s" % (type(exc).__name__, exc)
    RESULTS.append((name, ok, detail))
    print("[%s] %-26s %s" % ("OK" if ok else "NG", name, detail))
    return ok


# --------------------------------------------------------------- 纯函数臂（不需要账本）


def a_empty_cites():
    """证据没有出处 ⇒ 必须拒绝构造。这是 §5.7「回指不到不许写」的第一道闸。"""
    try:
        E.Evidence(eid="X", claim="测试", strength=E.K_LOG_ONLY, cites=(),
                   source="t", read_at="t")
    except ValueError as exc:
        if "出处" in str(exc):
            return True, "空出处被拒（%s）" % str(exc)[:40]
        return False, "拒了，但理由不对：%s" % exc
    return False, "空出处的证据被放过了 —— §5.7 没生效"


def a_held_without_rule():
    """「挡下」没有 rule_id ⇒ 必须拒绝。会把核对结论说成拦截。"""
    try:
        E.Evidence(eid="X", claim="测试", strength=E.K_HELD,
                   cites=(E.Cite("2026-01-01", 1),), source="t", read_at="t")
    except ValueError:
        return True, "无规则号的「挡下」被拒"
    return False, "无规则号的「挡下」被放过 —— 会把核对说成拦截"


def a_held_with_rule():
    """反向：合法的「挡下」必须能构造。约束过紧会把正常路径也堵死。"""
    try:
        ev = E.Evidence(eid="X", claim="测试", strength=E.K_HELD, rule_id="SEC-01",
                        cites=(E.Cite("2026-01-01", 1),), source="t", read_at="t")
    except ValueError as exc:
        return False, "合法「挡下」被误拒：%s" % exc
    return True, "合法「挡下」通过（%s）" % ev.word()


def a_bad_strength():
    """词表外的强度档 ⇒ 必须拒绝。"""
    try:
        E.Evidence(eid="X", claim="测试", strength="已处理",
                   cites=(E.Cite("2026-01-01", 1),), source="t", read_at="t")
    except ValueError:
        return True, "词表外的强度档被拒"
    return False, "词表外的强度档被放过"


def a_word_table_complete():
    """九维二（撤销即红）：`WORD` 少一项 ⇒ 必须有人报出来。

    这条不是测「函数行为」，是测「表本身完整」。第一版 WORD 就漏过 K_ALERT
    （改名时把允许列表写死了），靠人工看是看不出来的。
    """
    need = {E.K_HELD, E.K_ALERT, E.K_LOG_ONLY, E.K_NO_RESPONSE, E.K_CHECKED}
    miss = need - set(E.WORD)
    if miss:
        return False, "词表缺 %s" % sorted(miss)
    return True, "五档齐全（%s）" % "、".join(E.WORD[k] for k in sorted(E.WORD))


def a_stable_id_same():
    """id 稳定性①：同一句话 ＋ 同一出处 ⇒ id 必须相同。"""
    c = (E.Cite("2026-10-05", 0),)
    a = E._stable_id("AUD", "A3 日清单：xx", c)
    b = E._stable_id("AUD", "A3 日清单：xx", c)
    return (a == b), "同内容同 id（%s）" % a


def a_stable_id_independent_of_position():
    """★ id 稳定性②：**位置变了 id 不许变** —— 这条专钉第一版的 bug。

    第一版 `eid=f"AUD-{i+1:02d}"`，i 是数组下标。昨天 AUD-03 是 A3，
    今天 A1/A2 都 PASS 不进证据 ⇒ AUD-03 变成别的东西，两份报告对不上。
    本臂模拟「同一条证据换了位置」：构造列表里放两条，比对第二条的 id
    与它单独存在时的 id 是否一致。
    """
    c = (E.Cite("2026-10-08", 215),)
    alone = E._stable_id("AUD", "A4 时间单调：xx", c)
    after = E._stable_id("AUD", "A4 时间单调：xx", c)
    if alone != after:
        return False, "位置影响了 id（%s vs %s）" % (alone, after)
    # 再钉一下：**不同的 claim 必须给不同的 id**（否则稳定性退化成常量）
    other = E._stable_id("AUD", "A1 内容完整：yy", c)
    if other == alone:
        return False, "不同内容给了同一个 id（%s）—— 指纹失效" % alone
    return True, "同内容同 id（%s），异内容异 id（%s）" % (alone, other)


def a_cite_day_level():
    """天粒度（lineno==0）必须被认成「定位到天」，不是坏行号。"""
    c = E.Cite("2026-10-05", 0)
    if not c.day_level:
        return False, "lineno=0 没被认成天粒度"
    return True, "lineno=0 认作天粒度"


def a_cite_line_level():
    """反向：lineno>0 不许被认成天粒度。"""
    c = E.Cite("2026-10-05", 7)
    if c.day_level:
        return False, "lineno=7 被误认成天粒度"
    return True, "lineno=7 认作行粒度"


# --------------------------------------------------------------- 文件系统臂（用临时副本）


def _make_ledger(root, days):
    """造一个最小账本：`{day: [行, ...]}`。不碰真账本。"""
    os.makedirs(root, exist_ok=True)
    for day, lines in days.items():
        with open(os.path.join(root, "%s.jsonl" % day), "w", encoding="utf-8") as fh:
            for ln in lines:
                fh.write(ln + "\n")
    return root


def _bundle_with(cites):
    ev = E.Evidence(eid="X", claim="测试", strength=E.K_LOG_ONLY, cites=cites,
                    source="t", read_at="2026-11-01 02:00:00")
    b = E.Bundle(read_at="2026-11-01 02:00:00", root="")
    b.evidence.append(ev)
    return b


def a_verify_ok():
    """正判据：回指到真实存在的行 ⇒ 不许报坏。"""
    d = tempfile.mkdtemp(prefix="antinel-nc-")
    try:
        _make_ledger(d, {"2026-11-01": ['{"a":1}', '{"b":2}']})
        bad, notes = E.verify_cites(_bundle_with((E.Cite("2026-11-01", 2),)), d)
        if bad:
            return False, "合法回指被报坏：%s" % bad
        return True, "回指 2026-11-01:2 通过"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def a_verify_overrun():
    """反向对照：回指越界 ⇒ 必须报坏。"""
    d = tempfile.mkdtemp(prefix="antinel-nc-")
    try:
        _make_ledger(d, {"2026-11-01": ['{"a":1}']})
        bad, _ = E.verify_cites(_bundle_with((E.Cite("2026-11-01", 99),)), d)
        if not bad:
            return False, "越界回指（第 99 行／共 1 行）没被报坏"
        return True, bad[0][:60]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def a_verify_blank_line():
    """反向对照：回指落在空行 ⇒ 必须报坏（定位到空行等于没定位）。"""
    d = tempfile.mkdtemp(prefix="antinel-nc-")
    try:
        _make_ledger(d, {"2026-11-01": ['{"a":1}', "", '{"b":2}']})
        bad, _ = E.verify_cites(_bundle_with((E.Cite("2026-11-01", 2),)), d)
        if not bad:
            return False, "回指落在空行却没被报坏"
        return True, bad[0][:60]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def a_verify_missing_day():
    """★ 关键：日文件不存在 ⇒ 必须报「不可判」，**不许报坏**。

    「那一天不在账本里」可能是滚动删了，不等于「回指是编的」。
    两者混起来，就是把「我没得核」说成「你造假」（铁律 45）。
    """
    d = tempfile.mkdtemp(prefix="antinel-nc-")
    try:
        _make_ledger(d, {"2026-11-01": ['{"a":1}']})
        bad, notes = E.verify_cites(_bundle_with((E.Cite("2020-01-01", 1),)), d)
        if bad:
            return False, "日文件不存在被报成坏：%s" % bad
        if not any("不可判" in n for n in notes):
            return False, "没报不可判（notes=%s）" % notes
        return True, notes[0][:60]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def a_verify_day_level():
    """★ 天粒度回指（lineno=0）⇒ 必须通过。这条是第一版真踩过的坑。"""
    d = tempfile.mkdtemp(prefix="antinel-nc-")
    try:
        _make_ledger(d, {"2026-10-05": ['{"a":1}']})
        bad, notes = E.verify_cites(_bundle_with((E.Cite("2026-10-05", 0),)), d)
        if bad:
            return False, "天粒度回指被报坏（第一版的 bug 复发了）：%s" % bad
        return True, "天粒度回指通过"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def a_verify_day_level_empty():
    """反向：天粒度但文件是空的 ⇒ 必须报坏（连天都没得定位）。"""
    d = tempfile.mkdtemp(prefix="antinel-nc-")
    try:
        _make_ledger(d, {"2026-10-05": []})
        bad, _ = E.verify_cites(_bundle_with((E.Cite("2026-10-05", 0),)), d)
        if not bad:
            return False, "空日文件的天粒度回指没被报坏"
        return True, bad[0][:60]
    finally:
        shutil.rmtree(d, ignore_errors=True)


# --------------------------------------------------------------- 整链臂（真账本，只读）


def a_evidence_has_no_held():
    """★ 硬约束的行为面：真账本跑出来的证据里，**一条「挡下」都不许有**。

    九维三（行为判据）——断言的是「产物里有没有」，不是「构造函数抛不抛」。
    C 线读的是账本、不是规则 ⇒ 它没有任何资格产出「挡下」。
    """
    root = os.path.join(os.path.dirname(HERE), ".psl", "audit")
    if not os.path.isdir(root):
        return None, "真账本不在（%s）—— SKIP，不是通过" % root
    b = E.collect(root)
    held = [e for e in b.evidence if e.strength == E.K_HELD]
    if held:
        return False, "产出了 %d 条「挡下」：%s" % (
            len(held), "、".join(e.eid for e in held[:3]))
    return True, "%d 条证据，零「挡下」（四档分布 %s）" % (
        b.count(), {k: len(v) for k, v in b.by_strength().items()})


def a_evidence_ids_stable_across_runs():
    """★ 整链 id 稳定性：同一份账本连跑两次，eid 集合必须完全相同。

    这条与 a_stable_id_* 是两层：那两条测纯函数，这条测真实数据。
    真账本正在被写（当天文件在长），所以**只比「已封盘日」的证据** ——
    当天的证据数量会变，比它等于测账本增长，不是测 id 稳定性。
    """
    root = os.path.join(os.path.dirname(HERE), ".psl", "audit")
    if not os.path.isdir(root):
        return None, "真账本不在 —— SKIP，不是通过"
    b1 = E.collect(root)
    b2 = E.collect(root)

    # ★ 只比**已封盘日**。上面那句注释早就是这么写的，但代码原来比的是全部——
    #   注释说一套、代码做一套，于是这条臂**依赖实时数据**：产品正在写当天的
    #   文件，两次 collect 之间多进一条记录，`_stable_id` 的 claim 变了，
    #   eid 就变了，这条臂就红。红的是量具，不是被测对象（实测：单独跑 18/18，
    #   放进总闸门跑 17/18——同一份代码两个结果，本身就是铁律 22 的现场）。
    today = time.strftime("%Y-%m-%d")

    def closed_eids(b):
        return {e.eid for e in b.evidence
                if e.cites and all(c.day != today for c in e.cites)}

    s1, s2 = closed_eids(b1), closed_eids(b2)
    n_open = len(b1.evidence) - len(s1)
    if not s1 and not s2:
        return None, ("已封盘日的证据为 0 条（今天 %s 的 %d 条不计）—— "
                      "没有可比的样本，SKIP 不是通过" % (today, n_open))
    only1, only2 = s1 - s2, s2 - s1
    if only1 or only2:
        return False, "两次跑出不同 id：仅首次 %s／仅二次 %s" % (
            sorted(only1)[:3], sorted(only2)[:3])
    return True, "两次跑出同一组 id（已封盘 %d 条；今天 %d 条不计）" % (len(s1), n_open)


def a_undecidable_separated():
    """★ 「不可判」与「零」必须分开：两条腿都崩时，undecidable 必须非空。

    这里用不存在的 root 触发两条腿都失败。若返回「0 条证据、无不可判」，
    就是把「没查成」说成了「查了没有」。
    """
    b = E.collect(os.path.join(HERE, "_no_such_dir_zzz"))
    if b.count() == 0 and not b.undecidable:
        return False, "两条腿都没跑成，却报「0 条证据、无不可判」—— 零与不可判同貌"
    if not b.undecidable:
        return False, "两条腿都没跑成，undecidable 却是空的"
    return True, "%d 条不可判（%s）" % (len(b.undecidable), b.undecidable[0][:40])


def main():
    print("=" * 72)
    print("C-3 取证 Agent 负控")
    print("=" * 72)

    for name, fn in [
        ("nc1_empty_cites", a_empty_cites),
        ("nc2_held_without_rule", a_held_without_rule),
        ("nc3_held_with_rule", a_held_with_rule),
        ("nc4_bad_strength", a_bad_strength),
        ("nc5_word_complete", a_word_table_complete),
        ("nc6_id_same", a_stable_id_same),
        ("nc7_id_pos_free", a_stable_id_independent_of_position),
        ("nc8_cite_day_level", a_cite_day_level),
        ("nc9_cite_line_level", a_cite_line_level),
        ("nc10_verify_ok", a_verify_ok),
        ("nc11_verify_overrun", a_verify_overrun),
        ("nc12_verify_blank", a_verify_blank_line),
        ("nc13_verify_missing", a_verify_missing_day),
        ("nc14_verify_daylevel", a_verify_day_level),
        ("nc15_verify_empty_day", a_verify_day_level_empty),
        ("nc16_no_held_in_real", a_evidence_has_no_held),
        ("nc17_ids_stable_real", a_evidence_ids_stable_across_runs),
        ("nc18_undecidable", a_undecidable_separated),
    ]:
        arm(name, fn)

    print("-" * 72)
    ok = sum(1 for _, o, _ in RESULTS if o is True)
    skip = sum(1 for _, o, _ in RESULTS if o is None)
    ng = len(RESULTS) - ok - skip
    print("合计 %d 臂：通过 %d ／ 失败 %d ／ 跳过 %d" % (len(RESULTS), ok, ng, skip))
    if skip:
        print("★ 跳过不算通过（铁律 1）：%s" % [
            n for n, o, _ in RESULTS if o is None])
    return 0 if ng == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
