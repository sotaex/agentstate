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
import re
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LINEC = os.path.join(os.path.dirname(HERE), "linec")
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


def a_held_only_with_rule():
    """★ 硬约束的行为面：真账本跑出来的每条「挡下」，**都必须带规则号**。

    ──────────────────────────────────────────────────────────────────────
    这条臂 2026-11-02 深夜被改写，改写的理由比它本身重要
    ──────────────────────────────────────────────────────────────────────
    原文断言：「真账本跑出来的证据里，一条『挡下』都不许有」，
    理由是「C 线读的是账本、不是规则 ⇒ 它没有任何资格产出挡下」。

    那句话在**只有两条腿**时是对的（auditor／watchman 都不读 `decision`）。
    但它被写成了一条**行为判据**，于是第三只腿接上、真的从账本里读出
    `rule_id` 之后，这条臂立刻报红 —— 而红的方向是「不许有结论」。

    ⇒ **判据写错方向，会长期保护一个缺陷。** 它守的其实不是「没有挡下」，
      而是「挡下必须有规则号」——那才是 `Evidence.__post_init__` 的硬约束。
      把纪律写成「不许产出」，等于替那条腿的自我阉割背书，而且写得很有道理。

    新判据（三条，都是「强度不许被读强」的不同面）：
      1. 每条「挡下」必须有非空 rule_id，且不是「（无规则号）」；
      2. 每条「挡下」的 source 必须形如 `verdict_leg/<规则号>`（出处可回指）；
      3. 反向对照：**无规则号的簇必须落「已发现无法处置」**，且那一档的
         `rule_id` 必须为空 —— 否则说明分档把「守卫自己异常」读成了「规则挡住了」。
    """
    root = os.path.join(os.path.dirname(HERE), ".psl", "audit")
    if not os.path.isdir(root):
        return None, "真账本不在（%s）—— SKIP，不是通过" % root
    b = E.collect(root)
    held = [e for e in b.evidence if e.strength == E.K_HELD]
    for e in held:
        if not e.rule_id or e.rule_id == "（无规则号）":
            return False, "「挡下」没有规则号：%s（%s）" % (e.eid, e.claim[:40])
        if not e.source.startswith("verdict_leg/"):
            return False, "「挡下」的出处不是 verdict_leg：%s → %s" % (e.eid, e.source)
    no_resp = [e for e in b.evidence if e.strength == E.K_NO_RESPONSE]
    for e in no_resp:
        if e.rule_id:
            return False, ("无规则号的簇被挂上了规则号 %r：%s —— "
                           "把「守卫自己异常」读成了「规则挡住了」"
                           % (e.rule_id, e.eid))
    return True, ("%d 条证据：%d 条「挡下」全部带规则号（%s）；"
                  "%d 条「已发现无法处置」均无规则号"
                  % (b.count(), len(held),
                     "、".join(sorted({e.rule_id for e in held})) or "无",
                     len(no_resp)))


def _frozen_copy(n_days=3):
    """把最近 n 个**已封盘**日文件复制到临时目录。返回 (TemporaryDirectory, 天列表)。

    ★ 为什么要副本：这条臂测的是**确定性**（同一份输入 → 同一组 id），
      不是**不变性**（账本长了 id 还得一样）。第一版直接拿活账本连跑两次，
      两次的输入本来就不同 —— 它测的是账本增长速度，不是 id 稳定性。
      表现是「单独跑 18/18、放进总闸门 17/18」，同一份代码两个结果。
      那正是铁律 22 的现场：先怀疑量具。

    ★ 复制用 copy2 保字节（账本是 CRLF，通用换行读写会让每个文件小一点点）。
    ★ 清理交给 TemporaryDirectory，且带 ignore_cleanup_errors：中文 Windows 上
      临时目录清理会被拒（`WinError 5`），那会让「清理失败」被读成「自检崩了」——
      工具失败被读成结论失败，正是本项目最忌的那种（codeid.py 现场）。
    """
    root_real = os.path.join(os.path.dirname(HERE), ".psl", "audit")
    if not os.path.isdir(root_real):
        return None, None
    today = time.strftime("%Y-%m-%d")
    # ★ 必须按**日文件正则**筛，不能只判 `.jsonl` 结尾：账本目录里还有
    #   `lock_events.jsonl`，它会被当成一天 —— 实测消息里印出
    #   「3 天：2026-10-30、2026-10-31、lock_events」。auditor 用正则忽略它，
    #   所以结果不受影响，但**标签在说谎**，而这条臂的输出是要给人读的。
    #   「结果对但话不对」正是本项目一直在修的那一类。
    day_re = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    days = sorted(f[:-6] for f in os.listdir(root_real)
                  if f.endswith(".jsonl") and day_re.match(f[:-6])
                  and f[:-6] != today)
    if len(days) < 2:
        return None, None
    pick = days[-n_days:]
    tmpdir = tempfile.TemporaryDirectory(prefix="antinel-id-",
                                         ignore_cleanup_errors=True)
    tmp = tmpdir.name
    for d in pick:
        shutil.copy2(os.path.join(root_real, d + ".jsonl"),
                     os.path.join(tmp, d + ".jsonl"))
    man_src = os.path.join(root_real, "day_manifest.json")
    if os.path.isfile(man_src):
        try:
            with open(man_src, "r", encoding="utf-8") as fh:
                man = json.load(fh)
            sub = {k: v for k, v in man.items()
                   if isinstance(k, str) and k.endswith(".jsonl") and k[:-6] in pick}
            with open(os.path.join(tmp, "day_manifest.json"), "w",
                      encoding="utf-8", newline="") as fh:
                json.dump(sub, fh, ensure_ascii=False)
        except (ValueError, OSError):
            pass
    return tmpdir, pick


def a_evidence_ids_stable_across_runs():
    """★ id 确定性：同一份**冻结副本**连跑两次，eid 集合必须完全相同。

    ★ 与 a_stable_id_* 是两层：那两条测纯函数，这条测真实数据走完整条链。
    ★ 判据方向（2026-11-01 第四轮改）：拿副本，不拿活账本。
    """
    tmpdir, pick = _frozen_copy(3)
    if tmpdir is None:
        return None, "真账本不在或已封盘日不足 2 天 —— SKIP，不是通过"
    try:
        b1 = E.collect(tmpdir.name)
        b2 = E.collect(tmpdir.name)
    finally:
        tmpdir.cleanup()

    if not b1.evidence:
        return None, "冻结副本上一条证据都没有 —— 夹具失效，SKIP 不是通过"
    s1 = {e.eid for e in b1.evidence}
    s2 = {e.eid for e in b2.evidence}
    if s1 != s2:
        return False, "同一份冻结副本连跑两次，id 不一致：仅首次 %s／仅二次 %s" % (
            sorted(s1 - s2)[:3], sorted(s2 - s1)[:3])
    return True, "冻结副本（%d 天：%s）连跑两次，%d 条证据 id 完全相同" % (
        len(pick), "、".join(pick), len(s1))


def a_blind_not_dropped():
    """★ 外部计数：两个工具各自申报的盲区，必须一条不少地进 Bundle。

    ★ 为什么这条必须存在（2026-11-01 第四轮）：`watchman.py` 的 JSON 第一版
      **根本没有 blind_spots 键**，于是 evidence.collect 里那段
      `for b in watch.get("blind_spots")` **从未执行过一次** —— 8 条盲区
      一条没进过报告，而报告那一节仍然有 auditor 的 5 条，读起来毫无异样。
      这类缺陷「读代码」看不出来：每一段都有注释解释为什么，坏的是它们
      **没有接上**。只有从外面数才能发现。

    ★ 分母来自工具自己的 JSON **原始键**，不来自 blind_of，也不来自 Bundle：
      用 Bundle 数 Bundle 必然自洽 —— 那正是「A5 依赖账本之外的声明」的形状。

    ★ 本臂自带**反向对照**（第三段）：把 blind_of 换成「永远返回空」，
      同一套判据必须变红。没有这一段，「它绿着」与「它根本没在测」同貌。
    """
    root = os.path.join(os.path.dirname(HERE), ".psl", "audit")
    if not os.path.isdir(root):
        return None, "真账本不在 —— SKIP，不是通过"

    total, per, payloads = 0, {}, {}
    for script in ("auditor.py", "watchman.py"):
        got, err = E._run_json(script, root)
        if err:
            return None, "%s 没跑成（%s）—— SKIP 不是通过" % (script, err)
        # 直接数**原始键**，不经过 blind_of：分母不许依赖被测的那段解析
        n = len(got.get("blind_spots") or ())
        per[script] = n
        payloads[script] = got
        total += n
    if total == 0:
        return None, "两个工具都没申报盲区 —— 夹具失效，SKIP 不是通过"

    # 第一段：正向
    b = E.collect(root)
    if len(b.blind) < total:
        return False, ("工具申报了 %d 条盲区 %s，Bundle 里只有 %d 条 ⇒ 有 %d 条被静默丢弃"
                       % (total, per, len(b.blind), total - len(b.blind)))

    # 第二段：反向对照 —— 让 blind_of 永远返回空，必须红。
    # ★ 在**冻结副本**上做，不在全账本上做：同一套接线（collect 里那两处
    #   blind_of 调用）在小数据上一样被走到，而成本从 ~60s 降到 ~2s。
    #   实测全账本版让 selfproof 从 364s 涨到 652s，逼近 780s 上限 ——
    #   闸门跑不完就等于没有闸门。
    tmpdir, pick = _frozen_copy(2)
    if tmpdir is None:
        return None, "已封盘日不足，反向对照做不了 —— SKIP 不是通过"
    real = E.blind_of
    try:
        E.blind_of = lambda _p: ()
        b2 = E.collect(tmpdir.name)
    finally:
        E.blind_of = real
        tmpdir.cleanup()
    if len(b2.blind) >= total:
        return False, ("把 blind_of 换成空实现之后，Bundle 里仍有 %d 条盲区"
                       "（工具申报 %d）⇒ 本臂的判据根本没在数这件事"
                       % (len(b2.blind), total))

    return True, ("工具申报 %d 条 %s，Bundle 收进 %d 条（多出 %d 条是结构性前提）；"
                  "反向对照：屏蔽解析后只剩 %d 条 ⇒ 判据会红"
                  % (total, per, len(b.blind), len(b.blind) - total, len(b2.blind)))


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
        ("nc16_held_only_with_rule", a_held_only_with_rule),
        ("nc17_ids_stable_real", a_evidence_ids_stable_across_runs),
        ("nc18_undecidable", a_undecidable_separated),
        ("nc19_blind_not_dropped", a_blind_not_dropped),
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
