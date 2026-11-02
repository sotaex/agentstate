# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""C 线端到端负控：造一份已知有缺陷的账本，看报告说不说得出来。

为什么要这一层（2026-11-01 第四轮之后）：
  现有自检全是分段的那一种 —— auditor 的、watchman 的、evidence 的、onepager 的，
  各自都绿。而当天撞出的最严重缺陷（watchman 的 8 条盲区从未进报告）恰恰是
  两段之间没接上：每一段都对，合起来丢东西。
  分段自检对这一类天生无效 —— 它只证明每一段自己说得通。

  所以这一层只问一句话：给一份有已知缺陷的账本，报告里有没有说出来？

三条纪律：
  1. 账本由本文件自己造（链正确、清单正确），不读真账本 —— 夹具必须可控；
  2. 每条臂同时报「报告里出现了什么」与「没出现什么」，不只报 ok/False；
  3. 「报告静默」有时是正确答案（已知盲区），那时要断言它在盲区里说明了
     —— 静默本身不是通过，「静默且声明了为什么静默」才是。

造缺陷只用改写内容，不做文件删除：删除命令会被 AN-009 拦，
而「删掉一整天」已由 redteam_c2 的 R9 覆盖，这里不重复。
孤儿锚用「清单里多一条不存在的日子」造，与删文件在 anchor_census 里等价（集合差）。

落盘分两步（write_days / write_manifest），因为缺陷本身就是两步不同步：
size 不符＝文件变了清单没变。合成一个 write() 就永远造不出这个缺陷 ——
第一版就是这么写的，等于用夹具把被测现象抹掉了。
"""

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LINEC = os.path.join(HERE, "lineC")
sys.path.insert(0, LINEC)

import auditor as A  # noqa: E402
import report as R  # noqa: E402

RESULTS = []


def arm(name, fn):
    try:
        ok, detail = fn()
    except Exception as exc:                       # noqa: BLE001
        ok, detail = False, "负控自身崩了：%s: %s" % (type(exc).__name__, exc)
    RESULTS.append((name, ok, detail))
    print("[%s] %-30s %s" % ({True: "OK", False: "NG", None: "SK"}[ok], name, detail))


# --------------------------------------------------------------------------- 造账本


#: 轮转命中的规则池。前 3 天每条记录只命中一条，所以**不产生任何配对**；
#: 三天累计每条 >= 3 次，满足 rule_pair 的 `min_each`。
_POOL = ("AN-002", "AN-014", "AN-005", "AN-016")

#: 最后一天刻意造的三对（每个 session 两条、间隔 2 分钟）。
#: 只在这一天出现 ⇒ 「此前从未同时出现过」成立，三条线索全部落在 recent 窗口内。
_PAIRS = (("AN-002", "AN-014"), ("AN-005", "AN-016"), ("AN-002", "AN-005"))


def make(days=4, per_day=6, rules=True):
    """造账本内容（不落盘）。返回 [(day, [rec,...])]，链是按文件的、正确。

    ★ 「干净但有东西可看」靠 **rule_pair** 产出证据，**不再靠 gap**。
      原因（2026-11-02）：gap 已被判定「报作息不报异常」并默认关闭
      （见 `watchman.py` 的 `--with-gap` 说明）。夹具若继续靠 gap，
      就成了「靠一个已被关掉的检测器产出证据」—— 关掉它的那天夹具全红，
      而且红得看不出原因（上一轮已经因此白查过一次：`--gap-min` 30→90）。

      ⇒ 夹具的两条新纪律：
        ① 不许依赖任何默认值（阈值、开关、词表）；
        ② 不许依赖「即将被关掉」的检测器。有依赖就显式声明。

    ★ `rules=False` 造一份**真正 0 条证据**的账本，给 e1 用 ——
      「0 条要解释那个 0」这条臂必须有一个能产出 0 的夹具，
      否则它验的其实是「有线索时报告正常」，而不是那个 0。

    ★ 配对是**跨天首次**：session 名带日期前缀，避免 per_sess 跨天累积。
      跨天虽然不会误配（窗口 5 分钟），但排序 + break 的逻辑没必要承受这个负担。
    """
    out = []
    for i in range(days):
        day = "2026-10-%02d" % (10 + i)
        last = i == days - 1
        recs, prev_full = [], ""

        def emit(ts, sid, hit):
            nonlocal prev_full
            rec = {
                "ts": ts,
                "type": "pre_tool_use",
                "session": sid,
                "rules_hit": [hit] if hit else [],
                "decision": "allow",
                "action": "allow",
            }
            # 顺序要紧：prev 是 hash 覆盖的字段之一，先放 prev 再算 hash
            rec["prev"] = prev_full[-16:]
            rec["hash"] = A.recompute_hash(rec, prev_full)
            prev_full = rec["hash"]
            recs.append(rec)

        if not rules:
            for j in range(per_day):
                emit("%sT%02d:00:00+08:00" % (day, 9 + 2 * j),
                     "%s-s%d" % (day, j), None)
        elif last:
            for k, (a, bb) in enumerate(_PAIRS):
                sid = "%s-s%d" % (day, k)
                emit("%sT%02d:00:00+08:00" % (day, 9 + k), sid, a)
                emit("%sT%02d:02:00+08:00" % (day, 9 + k), sid, bb)
        else:
            for j in range(per_day):
                emit("%sT%02d:00:00+08:00" % (day, 9 + 2 * j),
                     "%s-s%d" % (day, j), _POOL[j % len(_POOL)])
        out.append((day, recs))
    return out


def write_days(root, days):
    if not os.path.isdir(root):
        os.makedirs(root)
    for day, recs in days:
        with open(os.path.join(root, day + ".jsonl"), "w",
                  encoding="utf-8", newline="\n") as fh:
            for r in recs:
                fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def write_manifest(root, days, extra=None):
    man = {}
    for day, recs in days:
        path = os.path.join(root, day + ".jsonl")
        man[day + ".jsonl"] = {
            "size": os.path.getsize(path),
            "last_hash": recs[-1]["hash"] if recs else "",
            "updated_at": day + "T23:59:59+08:00",
        }
    if extra:
        man.update(extra)
    with open(os.path.join(root, "day_manifest.json"), "w",
              encoding="utf-8", newline="\n") as fh:
        json.dump(man, fh, ensure_ascii=False)


def fresh(days=4, per_day=6, rules=True):
    """建一份干净账本（文件与清单一致），返回 (临时根, 天列表)。"""
    d = tempfile.mkdtemp(prefix="antinel-e2e-")
    root = os.path.join(d, "audit")
    ds = make(days, per_day, rules=rules)
    write_days(root, ds)
    write_manifest(root, ds)
    return root, ds


def render(root):
    """跑完整交付入口，返回 (ok, info, html, sidecar)。产物落临时目录，不进仓库。"""
    tmp = tempfile.mkdtemp(prefix="antinel-e2e-out-")
    out = os.path.join(tmp, "r.html")
    ok, info = R.produce(root, out)
    html, man = "", {}
    if os.path.isfile(out):
        with open(out, "r", encoding="utf-8") as fh:
            html = fh.read()
        with open(out + ".manifest.json", "r", encoding="utf-8") as fh:
            man = json.load(fh)
    return ok, info, html, man


# --------------------------------------------------------------------------- 臂


def e1_clean_explains_zero():
    """干净账本：不该说有事，但必须解释那个 0。

    ★ 这里必须用 `rules=False`（真正 0 条证据）。用 `fresh()` 会产 3 条
      rule_pair ⇒ 这条臂验的就不再是「0 条要解释那个 0」，而是
      「有线索时报告正常」—— 两条完全不同的断言，而它们都叫「绿」。
    """
    root, _ds = fresh(rules=False)
    ok, info, html, man = render(root)
    if not ok:
        return False, "干净账本竟然没落盘：%s" % info.get("error")
    if "未发现异常" in html:
        return False, "报告里出现「未发现异常」"
    if "结构上产不出来" not in html:
        return False, "「需要你看一眼 0 条」没有解释那个 0 —— 读者会读成没事"
    # ★ 2026-11-02 加：0 条不许被说成「都没有发现变化」。
    #   实测撞出：有证据时（n_need=0）报告说「这一层的判据还没接上」，
    #   0 证据时说「两条检查都跑成了，都没有发现变化」—— **同一个 0 两种相反归因**。
    #   两句话不可能同时为真：C 线不读规则库 ⇒「挡下／提醒」永远产不出来。
    if "都没有发现变化" in html:
        return False, "报告把 0 条说成「都没有发现变化」—— 0 被读成了「查了没有危险」"
    return True, "落盘 OK；0 条有解释；无「未发现异常」；证据 %d 条" % man.get("evidence", -1)


def e2_orphan_anchor():
    """清单里多一条盘上没有的日子 ⇒ 报告必须说「账本文件不见了」。"""
    root, ds = fresh()
    write_manifest(root, ds, extra={"2026-10-01.jsonl": {
        "size": 123, "last_hash": "0" * 64,
        "updated_at": "2026-10-01T23:59:59+08:00"}})
    ok, info, html, _ = render(root)
    if not ok:
        return False, "没落盘：%s" % info.get("error")
    if "账本文件不见了" not in html:
        return False, "清单里有孤儿锚，报告却没说 —— 删除证据不可见"
    return True, "报告说出「账本文件不见了」"


def e3_size_mismatch():
    """已封盘日文件变短、清单没跟着改 ⇒ 报告必须说「与日锚对不上」。"""
    root, ds = fresh()
    day, recs = ds[1]
    write_days(root, [(day, recs[:3])])      # 只写文件，清单不动
    ok, info, html, _ = render(root)
    if not ok:
        return False, "没落盘：%s" % info.get("error")
    if "与日锚对不上" not in html:
        return False, "文件变短了，报告却没说 —— 锚没起作用"
    return True, "报告说出「与日锚对不上」（文件 3 条 vs 清单 6 条）"


def e4_rewrite_silent_declared():
    """改内容 + 按文件重算链 + 重算清单 ⇒ A1/A2/A3 应当全过。

    这条断言的**不是「报告应该发现」**，而是「报告不该假装发现了」，
    并且**必须在盲区里说明它看不见这件事**。
    静默本身不是通过；「静默且声明了为什么静默」才是。
    """
    root, ds = fresh()
    day, recs = ds[1]
    recs[0]["session"] = "被改过"
    prev_full = ""
    for r in recs:                            # 按文件重算（与 auditor 语义一致）
        r["prev"] = prev_full[-16:]
        r["hash"] = A.recompute_hash(r, prev_full)
        prev_full = r["hash"]
    write_days(root, [(day, recs)])
    write_manifest(root, ds)                  # 锚也重算 ⇒ 三道全过
    ok, info, html, _ = render(root)
    if not ok:
        return False, "没落盘：%s" % info.get("error")
    if "不抗整链重算" not in html:
        return False, "整链重算后报告静默，且盲区里没声明 —— 静默被当成安全"
    return True, "整链重算后报告静默，但盲区写明了「A1/A2 不抗整链重算」"


def e5_cites_resolvable():
    """每条证据的回指都必须能在合成账本里定位（citecheck 必须 0）。"""
    root, _ds = fresh()
    ok, info, html, man = render(root)
    if not ok:
        return False, "没落盘：%s" % info.get("error")
    if man.get("citecheck_rc") != 0:
        return False, "回指校验没通过（rc=%r）" % man.get("citecheck_rc")
    return True, "回指校验 rc=0，证据 %d 条" % man.get("evidence", -1)


def e6_na_not_lumped():
    """A5 未给 --declare ⇒ 必须进「不适用」，不许进「不可判」。"""
    root, _ds = fresh()
    ok, info, html, man = render(root)
    if not ok:
        return False, "没落盘：%s" % info.get("error")
    na = man.get("not_applicable") or []
    un = man.get("undecidable") or []
    if not na:
        return False, "A5 不适用没进 sidecar 的 not_applicable（%r）" % (na,)
    if any("A5" in x for x in un):
        return False, "A5 被塞进 undecidable —— 适用边界被说成故障"
    if "不适用（" not in html:
        return False, "页面上没有「不适用」区块"
    return True, "不适用 %d 项、不可判 %d 项，两者分开" % (len(na), len(un))


def e7_folded_still_citable():
    """证据超过 cap 时，**折叠的条目也必须能回指**，且报告仍要落盘。

    这条臂对应一个真实事故（2026-11-01）：折叠条目原本只渲染「词 ＋ 结论」，
    没有 data-cites，于是 citecheck 报「渲染丢了 N 条」并**拒绝落盘** ——
    真账本一旦产出 6 条证据，报告就再也写不出来。
    真账本今天正好 5 条，这条分支从没被走过；靠 `--cap 3` 才暴露。
    """
    root, _ds = fresh()
    tmp = tempfile.mkdtemp(prefix="antinel-e2e-out-")
    out = os.path.join(tmp, "cap.html")
    ok, info = R.produce(root, out, cap=2)      # 强制折叠
    if not ok:
        return False, "折叠时报告没落盘：%s" % info.get("error")
    with open(out, "r", encoding="utf-8") as fh:
        html = fh.read()
    n_eid = html.count('data-eid="')
    n_ev = info.get("evidence", -1)
    if n_eid != n_ev:
        return False, "折叠后有 %d 条带 data-eid，上游 %d 条 ⇒ 折叠的条目丢了出处" % (n_eid, n_ev)
    if "<details" not in html:
        return False, "折叠没用 <details>（零 JS 的原生折叠）"
    if "**" in html:
        return False, "折叠样本里出现 `**` —— 只在折叠时渲染的文案没被清洗"
    return True, "cap=2 强制折叠：%d 条全带出处，details 折叠，无星号" % n_eid


def main():
    print("=" * 72)
    print("C 线端到端负控：有缺陷的账本，报告说不说得出来")
    print("=" * 72)
    for name, fn in [
        ("e1_clean_explains_zero", e1_clean_explains_zero),
        ("e2_orphan_anchor", e2_orphan_anchor),
        ("e3_size_mismatch", e3_size_mismatch),
        ("e4_rewrite_silent_declared", e4_rewrite_silent_declared),
        ("e5_cites_resolvable", e5_cites_resolvable),
        ("e6_na_not_lumped", e6_na_not_lumped),
        ("e7_folded_still_citable", e7_folded_still_citable),
    ]:
        arm(name, fn)
    print("-" * 72)
    ok = sum(1 for _, o, _ in RESULTS if o is True)
    skip = sum(1 for _, o, _ in RESULTS if o is None)
    ng = len(RESULTS) - ok - skip
    print("合计 %d 臂：通过 %d ／ 失败 %d ／ 跳过 %d" % (len(RESULTS), ok, ng, skip))
    return 0 if ng == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
