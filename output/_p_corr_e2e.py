# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""更正机制端到端负控：设计 §6 的六条验收口径，逐条真红一次。

为什么单独写一个端到端：`corrections._selfcheck` 测的是**纯函数**（约束能不能抛），
`onepager._selfcheck` 测的是**模板**（拿到 Resolved 会不会画）。两边都绿，
仍然可能是「onepager 根本没去读 Ledger」——那就是四件套缺「连带对照」。

本文件把真 Ledger 写进临时目录，再从盘上读回来渲染，走完整条链。

★ 全程用临时目录，**不碰 .psl/audit**：那是生产账本，拿真数据做测试等于
  把测试污染记进了证据。
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LINE_C = os.path.join(HERE, "lineC")
sys.path.insert(0, LINE_C)

import evidence as E          # noqa: E402
import corrections as C       # noqa: E402
import onepager as O          # noqa: E402

RESULTS = []


def arm(name, fn):
    """跑一个臂。**臂自己崩了也算没通过**——不许「异常当跳过」。"""
    try:
        ok, detail = fn()
    except Exception as exc:
        ok, detail = False, "臂自己崩了：%s: %s" % (type(exc).__name__, exc)
    RESULTS.append((name, ok, detail))
    print("[%s] %-24s %s" % ("OK" if ok else "XX", name, detail))
    return ok


def mk_bundle(root, eid="AUD-e2e001", claim="原结论", day="2026-11-01", line=3):
    b = E.Bundle(read_at="2026-11-01 03:00:00", root=root)
    b.evidence.append(E.Evidence(
        eid=eid, claim=claim, strength=E.K_LOG_ONLY,
        cites=(E.Cite(day, line),), source="e2e", read_at="2026-11-01 03:00:00"))
    b.denominators["账本"] = "1 个日文件 / 1 条"
    return b


def seed_ledger(root):
    """造一个最小账本，让 report_id 能取到末条 hash（否则 id 少算一格）。"""
    d = os.path.join(root, "audit")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "2026-11-01.jsonl"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write('{"ts":"2026-11-01T03:00:00+08:00","hash":"deadbeefcafe"}\n')
    return d


# --------------------------------------------------------------------------- 六个臂


def a1_supersede_still_shown(tmp):
    def run():
        aud = seed_ledger(tmp)
        b = mk_bundle(aud)
        rid = C.report_id(b)
        led = C.Ledger(aud)
        led.append(C.Correction(
            at="2026-11-01T04:00:00+08:00", by="C-3", kind=C.K_SUPERSEDE,
            target_report=rid, target_eid="AUD-e2e001",
            reason="该日机制当时不存在，不是漏了", new_eid="AUD-e2e002"),
            {rid: {"AUD-e2e001"}})

        # ★ 关键：从盘上读回来，不直接用内存里那条
        res = C.resolve(b, led.load())
        h = O.render(b, resolved=res)
        if 'data-eid="AUD-e2e001"' not in h:
            return False, "被更正的条目从产物里消失了"
        if "superseded" not in h or "此条已被" not in h:
            return False, "没有换长相（删除线／说明行）"
        return True, "仍在原位置，带删除线与说明行"
    return run


def a2_void_banner_first(tmp):
    def run():
        aud = seed_ledger(tmp)
        b = mk_bundle(aud)
        rid = C.report_id(b)
        led = C.Ledger(aud)
        led.append(C.Correction(
            at="2026-11-01T05:00:00+08:00", by="C-3", kind=C.K_VOID,
            target_report=rid, reason="整份基于错误读数（把字节数当记录数）",
            new_report="R-000000000001"), {})
        res = C.resolve(b, led.load())
        h = O.render(b, resolved=res)
        i_b = h.find("本报告已于")
        i_body = h.find("这次看见了什么")
        i_f = h.find('<div class="footer">')
        if i_b < 0:
            return False, "没有作废横幅"
        if i_body < 0 or i_f < 0:
            return False, "定位失败（找不到正文或页脚）"
        if not (i_b < i_body < i_f):
            return False, "横幅不在首屏（%d/%d/%d）" % (i_b, i_body, i_f)
        return True, "横幅在正文之前、页脚之前（%d < %d < %d）" % (i_b, i_body, i_f)
    return run


def a3_void_is_neutral(tmp):
    def run():
        aud = seed_ledger(tmp)
        b = mk_bundle(aud)
        rid = C.report_id(b)
        led = C.Ledger(aud)
        led.append(C.Correction(
            at="2026-11-01T05:00:00+08:00", by="C-3", kind=C.K_VOID,
            target_report=rid, reason="口径修正", new_report="R-000000000002"), {})
        h = O.render(b, resolved=C.resolve(b, led.load()))
        # 横幅区块内不许出现红色变量 --r0
        i = h.find('class="void"')
        if i < 0:
            return False, "找不到 void 区块"
        seg = h[i:i + 400]
        if "--r0" in seg:
            return False, "作废用了红色 —— 会让读者以为发现了安全问题"
        return True, "中性色（不含 --r0）"
    return run


def a4_tamper_refused(tmp):
    def run():
        aud = seed_ledger(tmp)
        b = mk_bundle(aud)
        rid = C.report_id(b)
        led = C.Ledger(aud)
        led.append(C.Correction(
            at="2026-11-01T04:00:00+08:00", by="C-3", kind=C.K_NOTE,
            target_report=rid, reason="第一条"), {})
        # 外部改一个字节
        with open(led.path, "a", encoding="utf-8") as fh:
            fh.write(" ")
        try:
            led.append(C.Correction(at="t", by="C-3", kind=C.K_NOTE,
                                    target_report=rid, reason="第二条"), {})
        except PermissionError as exc:
            return True, "拒绝追加：%s" % str(exc)[:40]
        return False, "记录被动过后仍允许追加 —— 只追加形同虚设"
    return run


def a5_ghost_refused(tmp):
    def run():
        aud = seed_ledger(tmp)
        b = mk_bundle(aud)
        rid = C.report_id(b)
        led = C.Ledger(aud)
        try:
            led.append(C.Correction(
                at="t", by="C-3", kind=C.K_SUPERSEDE, target_report=rid,
                target_eid="AUD-nosuch", reason="指向不存在的条目",
                new_eid="AUD-e2e002"), {rid: {"AUD-e2e001"}})
        except ValueError as exc:
            return True, "拒绝：%s" % str(exc)[:40]
        return False, "幽灵更正被接受"
    return run


def a6_twice_refused(tmp):
    def run():
        aud = seed_ledger(tmp)
        b = mk_bundle(aud)
        rid = C.report_id(b)
        led = C.Ledger(aud)
        known = {rid: {"AUD-e2e001"}}
        led.append(C.Correction(
            at="2026-11-01T04:00:00+08:00", by="C-3", kind=C.K_SUPERSEDE,
            target_report=rid, target_eid="AUD-e2e001", reason="第一次",
            new_eid="AUD-e2e002"), known)
        try:
            led.append(C.Correction(
                at="2026-11-01T05:00:00+08:00", by="C-3", kind=C.K_SUPERSEDE,
                target_report=rid, target_eid="AUD-e2e001", reason="第二次",
                new_eid="AUD-e2e003"), known)
        except ValueError as exc:
            return True, "拒绝：%s" % str(exc)[:40]
        return False, "同一条被取代两次却放行"
    return run


def a7_reverse_cite(tmp):
    def run():
        aud = seed_ledger(tmp)
        old = mk_bundle(aud)
        rid_old = C.report_id(old)
        new = mk_bundle(aud, eid="AUD-e2e002", claim="新结论", line=4)
        rid_new = C.report_id(new)
        if rid_old == rid_new:
            return False, "两份不同报告算出同一个 id"
        led = C.Ledger(aud)
        led.append(C.Correction(
            at="2026-11-01T04:00:00+08:00", by="C-3", kind=C.K_SUPERSEDE,
            target_report=rid_old, target_eid="AUD-e2e001",
            reason="改判", new_report=rid_new, new_eid="AUD-e2e002"),
            {rid_old: {"AUD-e2e001"}})
        h = O.render(new, resolved=C.resolve(new, led.load()))
        if rid_old not in h:
            return False, "新报告里找不到旧报告号"
        if "本报告取代了" not in h:
            return False, "有反向关系却没印出来"
        return True, "新报告指认了 %s" % rid_old
    return run


# --------------------------------------------------------------------------- 连带对照


def a8_citecheck_still_green(tmp):
    """连带对照：加了删除线与新属性之后，citecheck 还认不认这份产物。"""
    def run():
        aud = seed_ledger(tmp)
        b = mk_bundle(aud)
        rid = C.report_id(b)
        led = C.Ledger(aud)
        led.append(C.Correction(
            at="2026-11-01T04:00:00+08:00", by="C-3", kind=C.K_SUPERSEDE,
            target_report=rid, target_eid="AUD-e2e001",
            reason="r", new_eid="AUD-e2e002"), {rid: {"AUD-e2e001"}})
        h = O.render(b, resolved=C.resolve(b, led.load()))
        out = os.path.join(tmp, "with_corr.html")
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(h)
        rc = subprocess.call(
            [sys.executable, "-E", "-X", "utf8",
             os.path.join(LINE_C, "citecheck.py"),
             "--html", out, "--expect", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rc != 0:
            return False, "含更正的产物过不了 citecheck（rc=%d）" % rc
        return True, "含更正的产物仍然通过（rc=0）"
    return run


def a9_citecheck_catches_dup(tmp):
    """反向：把同一条渲染两次，citecheck 的 --expect 必须抓到。"""
    def run():
        aud = seed_ledger(tmp)
        b = mk_bundle(aud)
        h = O.render(b)
        # 故意复制一份 .ev 块（模拟渲染 bug）
        i = h.find('<div class="ev ')
        j = h.find("</div>", h.find('class="note"', i))
        dup = h[:j + 6] + h[i:j + 6] + h[j + 6:]
        out = os.path.join(tmp, "dup.html")
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(dup)
        rc = subprocess.call(
            [sys.executable, "-E", "-X", "utf8",
             os.path.join(LINE_C, "citecheck.py"),
             "--html", out, "--expect", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rc != 1:
            return False, "重复条目没被抓住（rc=%d，应 1）" % rc
        return True, "重复条目被抓（rc=1）"
    return run


def a10_no_corrections_is_silent(tmp):
    """没有更正时，产物里不该出现「更正记录」空壳。"""
    def run():
        aud = seed_ledger(tmp)
        b = mk_bundle(aud)
        h = O.render(b, resolved=C.resolve(b, []))
        if "更正记录" in h:
            return False, "没有任何更正却印了「更正记录」标题"
        if "本报告已于" in h:
            return False, "没有任何作废却印了作废横幅"
        return True, "无更正时不留空壳"
    return run


def a11_missing_ledger_is_not_empty(tmp):
    """零与不可判同貌：更正记录**读不出来** ≠ **没有更正**。"""
    def run():
        aud = seed_ledger(tmp)
        led = C.Ledger(aud)
        with open(led.path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("{这不是 json}\n")
        try:
            items = led.load()
        except ValueError:
            return True, "坏行被报出来，而不是当成「没有更正」"
        return False, "坏行被静默跳过（读回 %d 条）—— 盲区伪装成结论" % len(items)
    return run


def main():
    print("=" * 72)
    print("更正机制端到端负控（设计 §6 六条 + 五条连带）")
    print("=" * 72)

    specs = [
        ("e1_supersede_shown", a1_supersede_still_shown),
        ("e2_void_banner_first", a2_void_banner_first),
        ("e3_void_is_neutral", a3_void_is_neutral),
        ("e4_tamper_refused", a4_tamper_refused),
        ("e5_ghost_refused", a5_ghost_refused),
        ("e6_twice_refused", a6_twice_refused),
        ("e7_reverse_cite", a7_reverse_cite),
        ("e8_citecheck_green", a8_citecheck_still_green),
        ("e9_citecheck_dup", a9_citecheck_catches_dup),
        ("e10_no_corr_silent", a10_no_corrections_is_silent),
        ("e11_bad_line_loud", a11_missing_ledger_is_not_empty),
    ]

    for name, factory in specs:
        tmp = tempfile.mkdtemp(prefix="corr_e2e_")
        try:
            arm(name, factory(tmp))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print("-" * 72)
    ok = sum(1 for _, o, _ in RESULTS if o)
    bad = len(RESULTS) - ok
    print("合计 %d 臂：通过 %d ／ 失败 %d" % (len(RESULTS), ok, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sys.exit(main())
