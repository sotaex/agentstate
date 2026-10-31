# -*- coding: utf-8 -*-
# SPDX-License-Identifier: CC-BY-SA-4.0
"""C-5 红队 · 第二段：攻击 C-2（`watchman.py`）。

──────────────────────────────────────────────────────────────────────────
为什么要有第二段
──────────────────────────────────────────────────────────────────────────
W4 的验收写的是「攻击 **C-1／C-2**」。第一段（`redteam.py`）只打了 C-1
（`auditor.py` 的 A1–A5），C-2 一条都没打 —— 而 C-2 才是产出**全部线索**的那一层。
一个没被打过的检测器，它的 `BLIND_SPOTS` 只是自述，不是结论。

──────────────────────────────────────────────────────────────────────────
四条臂，两赢两输
──────────────────────────────────────────────────────────────────────────
| 臂 | 做什么 | 期望 |
|---|---|---|
| R5 | 把全部 `ts` 抹成空串 | **红队赢**：原来直接崩（rc=1，一条输出都没有） |
| R6 | 删掉某 type 的**全期**记录 ＋ 重算锚 | **红队赢**：anchor 全绿、absent 一声不响 |
| R7 | 删掉同一批记录，**不动锚** | 被抓住：anchor 报「账本与日锚对不上」 |
| R8 | 全部 `ts` 整体 +6 小时，**不动锚** | 被抓住：anchor 报 size／hash 不符 |

**R6 与 R7 是成对的**（铁律 10 ②反向对照）：同一批篡改，只差「有没有重算锚」。
没有 R7，就无法说明 R6 的「安静」是**锚被绕过**造成的，而不是「数据本来就没变」。

R8 是 R5 的反向对照：同样是动 `ts`，**没崩的那一种**要能被抓住，否则
「R5 崩了」会被读成「只要动 ts 就崩」，而真正的问题是**某条分支从没被执行过**。

──────────────────────────────────────────────────────────────────────────
本文件的一个立场
──────────────────────────────────────────────────────────────────────────
**红队赢了不是「产品烂」，是「这里只能到这一步」。** 赢了就写进 `BLIND_SPOTS`，
不许为了让红队输而放宽检测器，也不许为了让报告好看而删掉臂。
"""

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE if os.path.basename(HERE) == "lineC"
                else os.path.join(HERE, "lineC"))

import redteam as RT  # noqa: E402  —— 链重算只许有一份实现（R4）

LINE_C = HERE if os.path.basename(HERE) == "lineC" else os.path.join(HERE, "lineC")
OUTPUT = os.path.dirname(LINE_C)
REPO = os.path.dirname(OUTPUT)
SRC = os.path.join(REPO, ".psl", "audit")
WATCH = os.path.join(LINE_C, "watchman.py")
AUDIT = os.path.join(LINE_C, "auditor.py")

#: 副本天数。要 >= absent 的基线窗口（7 天），否则「删得比窗口长」这件事
#: 根本演示不出来 —— 而那条正是 R6 的整个论点。
N_FILES = 8

TS = re.compile(r'"ts":\s*"([^"]+)"')
TYPE = re.compile(r'"type":\s*"([^"]*)"')
HASH = re.compile(r'"hash":\s*"([^"]*)"')

ARMS: List[Tuple[str, bool, str]] = []


# ──────────────────────────────────────────────────────────────────────────
# 基础设施
# ──────────────────────────────────────────────────────────────────────────

def run_watch(root: str, recent: int = 3) -> Dict[str, Any]:
    p = subprocess.run(
        [sys.executable, "-E", "-X", "utf8", WATCH,
         "--root", root, "--json", "--recent", str(recent)],
        cwd=REPO, capture_output=True, text=True,
        encoding="utf-8", errors="replace")
    if p.returncode != 0:
        return {"__rc": p.returncode,
                "__err": (p.stderr or "").strip().splitlines()[-1:] or ["（无 stderr）"]}
    return json.loads(p.stdout)


def run_audit(root: str) -> Dict[str, str]:
    """C-1 对同一个副本怎么说 —— 每条 C-2 臂都要带上它。

    ★ 不带这一栏，「红队赢了」会被读成「整个系统看不见」。实际上很多臂
      **C-2 瞎、C-1 不瞎**（链一断 A1/A2 就红）。把两者分开报，
      才是「对外强度 ≤ 内部最保守定性」（铁律 21）。
    """
    p = subprocess.run(
        [sys.executable, "-E", "-X", "utf8", AUDIT, "--root", root, "--json"],
        cwd=REPO, capture_output=True, text=True,
        encoding="utf-8", errors="replace")
    if p.returncode not in (0, 1):
        return {"__err": "auditor rc=%d" % p.returncode}
    try:
        d = json.loads(p.stdout)
    except Exception:
        return {"__err": "auditor 输出不是 JSON"}
    out = {}
    for f in d.get("findings") or []:
        out[str(f.get("dim"))] = str(f.get("status"))
    return out


def c1_brief(root: str) -> str:
    a = run_audit(root)
    if "__err" in a:
        return "C-1：%s" % a["__err"]
    want = ["A1 内容完整", "A2 链连续", "A3 日清单", "A4 时间单调", "A5 总量"]
    return "C-1：" + " ".join(
        "%s=%s" % (k.split()[0], a.get(k, "?")) for k in want if k in a)


def kinds(res: Dict[str, Any], kind: str) -> List[Dict[str, Any]]:
    return [c for c in (res.get("clues") or []) if c.get("kind") == kind]


def cov(res: Dict[str, Any], name: str) -> str:
    return ((res.get("coverage") or {}).get(name) or {}).get("status", "?")


def arm(name: str, won: bool, detail: str) -> None:
    ARMS.append((name, won, detail))
    print("[%s] %-14s %s" % ("红队赢" if won else "被抓住", name, detail))


def make_copy(work: str, name: str) -> str:
    """复制最近 N 个日文件 ＋ **子集化**的 day_manifest。

    ★ 必须两处都做 newline=""。账本是 CRLF，用默认通用换行读、再用 "\\n" 写，
      会把每个文件都改小一点点 —— 于是 anchor 对**所有**文件报「被改过」，
      而那条线索跟本次篡改毫无关系。**夹具污染长得和检测器灵敏一模一样。**
    """
    dst = os.path.join(work, name)
    os.makedirs(dst, exist_ok=True)
    for f in sorted(glob.glob(os.path.join(SRC, "2026-*.jsonl")))[-N_FILES:]:
        shutil.copy2(f, os.path.join(dst, os.path.basename(f)))
    man_src = os.path.join(SRC, "day_manifest.json")
    keep = {n for n in os.listdir(dst) if n.endswith(".jsonl")}
    sub: Dict[str, Any] = {}
    if os.path.exists(man_src):
        with open(man_src, "r", encoding="utf-8") as fh:
            full = json.load(fh)
        sub = {k: v for k, v in full.items() if k in keep}
    with open(os.path.join(dst, "day_manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(sub, fh, ensure_ascii=False, indent=1)
    return dst


def refresh_manifest(root: str) -> int:
    """按文件现状重算 `{size, last_hash}` —— 模拟「攻击者连锚一起重算」。

    这是 L0 边界内允许的动作（铁律 42）：锚与账本由同一个进程写，
    能重算锚的人本来就能重写整条链。**本文件不假装这是防御**，
    只把它当作「绕过锚之后，下层检测器还剩多少」的分界线。
    """
    mp = os.path.join(root, "day_manifest.json")
    with open(mp, "r", encoding="utf-8") as fh:
        man = json.load(fh)
    n = 0
    for name in list(man):
        p = os.path.join(root, name)
        if not os.path.exists(p):
            continue
        last = ""
        with open(p, "r", encoding="utf-8", errors="replace", newline="") as fh:
            for line in fh:
                m = HASH.search(line)
                if m and m.group(1):
                    last = m.group(1)
        e = dict(man[name])
        e["size"] = os.path.getsize(p)
        e["last_hash"] = last
        man[name] = e
        n += 1
    with open(mp, "w", encoding="utf-8") as fh:
        json.dump(man, fh, ensure_ascii=False, indent=1)
    return n


def rewrite(root: str, fn) -> int:
    """逐行过 `fn(line) -> line|None`（None 表示删掉），**保留原换行**。

    返回值是**被改动的行数**（删掉的和改过内容的都算）。
    ★ 上一版只数「删掉的行」，于是「平移 ts」那种只改内容的臂会报「平移 0 处」——
      臂其实做了事，只是计数器看不见。**量具的计数器漏计，看起来和没动手一样。**
    """
    n = 0
    for f in sorted(glob.glob(os.path.join(root, "2026-*.jsonl"))):
        out: List[str] = []
        with open(f, "r", encoding="utf-8", errors="replace", newline="") as fh:
            for line in fh:
                new = fn(line)
                if new is None:
                    n += 1
                    continue
                if new != line:
                    n += 1
                out.append(new)
        with open(f, "w", encoding="utf-8", newline="") as fh:
            fh.writelines(out)
    return n


def pick_victim(root: str) -> Tuple[str, int]:
    """挑一个**够格进 absent 基线**的 type：>=5 天出现、每天 >=3 次。

    不够格的话删掉它本来就不会进基线，R6 就成了「删了个本来就没人在看的东西」，
    赢了也没意义。挑不到就抛，让臂报 SKIP，不许拿一个不成立的前提去赢。
    """
    per: Dict[str, Dict[str, int]] = {}
    for f in sorted(glob.glob(os.path.join(root, "2026-*.jsonl"))):
        day = os.path.basename(f)[:10]
        with open(f, "r", encoding="utf-8", errors="replace", newline="") as fh:
            for line in fh:
                m = TYPE.search(line)
                if not m or not m.group(1):
                    continue
                per.setdefault(m.group(1), {}).setdefault(day, 0)
                per[m.group(1)][day] += 1
    best, best_n = "", 0
    for t, days in per.items():
        good = [d for d, n in days.items() if n >= 3]
        if len(good) >= 5 and sum(days.values()) > best_n:
            best, best_n = t, sum(days.values())
    if not best:
        raise RuntimeError("副本里没有哪个 type 够格进 absent 基线（>=5 天、每天 >=3 次）")
    return best, best_n


# ──────────────────────────────────────────────────────────────────────────
# 四条臂
# ──────────────────────────────────────────────────────────────────────────

def r5_no_ts(root: str) -> Tuple[bool, str]:
    """把全部 ts 抹成空串：检测器应当报「判不了」，不该崩。"""
    rewrite(root, lambda ln: TS.sub('"ts": ""', ln))
    res = run_watch(root)
    if "__rc" in res:
        return True, "watchman 崩了（rc=%s）：%s ｜ %s" % (res["__rc"], res["__err"],
                                                          c1_brief(root))
    st = cov(res, "gap")
    if st == "undecidable":
        return False, ("报「判不了」，且 gap 的分母写着 0 条可解析 ts ｜ %s"
                       % c1_brief(root))
    return True, ("ts 全空却报 %s —— 把「没查成」说成了「查了没有」 ｜ %s"
                  % (st, c1_brief(root)))


def r7_strip_no_anchor(root: str, victim: str) -> Tuple[bool, str]:
    """删掉某 type 的全期记录，**不动锚**：anchor 应当抓住。"""
    n = rewrite(root, lambda ln: None if TYPE.search(ln) and
                TYPE.search(ln).group(1) == victim else ln)
    res = run_watch(root)
    if "__rc" in res:
        return True, "watchman 崩了（rc=%s）：%s" % (res["__rc"], res["__err"])
    hit = kinds(res, "anchor")
    if not hit:
        return True, "删了 %d 条却没有任何 anchor 线索 ｜ %s" % (n, c1_brief(root))
    return False, ("anchor 报「%s」 ｜ %s"
                   % ((hit[0].get("subject") or "")[:50], c1_brief(root)))


def r6_strip_and_anchor(root: str, victim: str) -> Tuple[bool, str]:
    """删掉同一批记录 ＋ **重算锚**：看下层检测器还剩多少。"""
    n = rewrite(root, lambda ln: None if TYPE.search(ln) and
                TYPE.search(ln).group(1) == victim else ln)
    k = refresh_manifest(root)
    res = run_watch(root)
    if "__rc" in res:
        return True, "watchman 崩了（rc=%s）：%s" % (res["__rc"], res["__err"])
    a = kinds(res, "anchor")
    ab = kinds(res, "absent")
    if a:
        return False, "重算锚之后 anchor 仍然报出 %d 条" % len(a)
    if ab:
        return False, "absent 报出 %d 条（说明它发现了钩子消失）" % len(ab)
    return True, ("删掉 %d 条 type=%s、重算 %d 天锚 ⇒ anchor 与 absent 双双安静 ｜ %s"
                  % (n, victim, k, c1_brief(root)))


def r8_shift_ts(root: str) -> Tuple[bool, str]:
    """全部 ts 整体 +6 小时，**不动锚**：anchor 应当抓住。"""
    def bump(m):
        try:
            return '"ts": "%s"' % (datetime.fromisoformat(m.group(1))
                                   + timedelta(hours=6)).isoformat()
        except Exception:
            return m.group(0)
    n = rewrite(root, lambda ln: TS.sub(bump, ln))
    if n == 0:
        raise RuntimeError("一处 ts 都没平移成 —— 夹具失效，不是检测器结论")
    res = run_watch(root)
    if "__rc" in res:
        return True, "watchman 崩了（rc=%s）：%s" % (res["__rc"], res["__err"])
    hit = kinds(res, "anchor")
    if not hit:
        return True, ("平移 %d 行 ts（长度不变、`hash` 字段没动）⇒ anchor 零线索 ｜ %s"
                      % (n, c1_brief(root)))
    return False, ("anchor 报「%s」 ｜ %s"
                   % ((hit[0].get("subject") or "")[:50], c1_brief(root)))


def reseal(root: str) -> int:
    """把链**按现状重算**一遍。**按文件、不跨日。**

    ★ 这条是实测出来的，不是猜的：`auditor.check_content` 里
      `for path in s.files:` 之后第一句就是 `prev_full = ""` ——
      **链是「每天一条」，不是「一条贯穿全部」**。
      我第一版按跨日连续重算，重算完 A1/A2 立刻全红，而红的原因是
      **我造了一条产品根本没有的链**，不是产品坏了。
      （顺带解释了另一件事：删掉一整天文件，剩下文件的链**一点都没断** ——
      所以「删天」只有 A3 的日清单能发现，A1/A2 天生管不着。）

    ★ 只重算**本来就有 hash** 的记录。链建立之前的裸记录（旧 schema）不动。
    ★ canon 借 `redteam.py` 的实现（R4）：两份实现只要差一个 separators，
      重算出来的链就永远对不上，而「对不上」会被读成「检测器抓住了」。
    """
    files = sorted(glob.glob(os.path.join(root, "2026-*.jsonl")))
    rows: List[Tuple[str, List[Dict[str, Any]]]] = []
    for f in files:
        recs: List[Dict[str, Any]] = []
        with open(f, "r", encoding="utf-8", errors="replace", newline="") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    recs.append(json.loads(line))
                except Exception:
                    recs.append({"__unparsed__": True, "raw": line.rstrip("\r\n")})
        rows.append((f, recs))

    n = 0
    for _f, recs in rows:
        prev_full = ""          # ★ 每个文件重新起链（见 docstring）
        started = False
        for rec in recs:
            if rec.get("__unparsed__"):
                continue
            if not started and "hash" not in rec:
                continue
            started = True
            body = dict(rec)
            body["prev"] = prev_full[-16:] if prev_full else ""
            body.pop("hash", None)
            h = hashlib.sha256((prev_full + RT.canon(body)).encode("utf-8")).hexdigest()
            body["hash"] = h
            rec.clear()
            rec.update(body)
            prev_full = h
            n += 1

    for f, recs in rows:
        with open(f, "w", encoding="utf-8", newline="\n") as fh:
            for rec in recs:
                fh.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
    return n


def r9_strip_seal_anchor(root: str, victim: str) -> Tuple[bool, str]:
    """删掉某 type 的全期记录 ＋ **重算整条链** ＋ 重算锚 —— 最终边界。

    这是 R6 与第一段 R1 的叠加：只绕锚不够（C-1 的 A1/A2 会红），
    还要把链一起重算。**两条都做到之后，如果 C-1 与 C-2 同时全绿，
    那就是「本系统在这件事上没有检测点」的实测证据，不是推断。**
    """
    n = rewrite(root, lambda ln: None if TYPE.search(ln) and
                TYPE.search(ln).group(1) == victim else ln)
    m = reseal(root)
    k = refresh_manifest(root)
    res = run_watch(root)
    a = run_audit(root)
    if "__rc" in res:
        return False, "watchman 崩了（rc=%s）—— 崩也算被看见" % res["__rc"]
    if "__err" in a:
        return False, "C-1 跑不动：%s" % a["__err"]
    a1 = a.get("A1 内容完整")
    a2 = a.get("A2 链连续")
    a3 = a.get("A3 日清单")
    w_anchor = len(kinds(res, "anchor"))
    w_absent = len(kinds(res, "absent"))
    if a1 == "PASS" and a2 == "PASS" and a3 == "PASS" and not w_anchor and not w_absent:
        return True, ("删 %d 条＋重算 %d 条链＋重算 %d 天锚 ⇒ **C-1 A1/A2/A3 全 PASS、"
                      "C-2 anchor/absent 全静**" % (n, m, k))
    return False, ("C-1：A1=%s A2=%s A3=%s ｜ C-2：anchor %d 条、absent %d 条"
                   % (a1, a2, a3, w_anchor, w_absent))


# ──────────────────────────────────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────────────────────────────────

def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    print("=" * 78)
    print("C-5 红队 · 第二段：攻击 C-2（watchman.py）")
    print("=" * 78)

    if not os.path.isdir(SRC):
        print("[停] 真账本不在：%s" % SRC)
        return 2
    work = tempfile.mkdtemp(prefix="rt2_")
    try:
        base = make_copy(work, "base")
        clean = run_watch(base)
        if "__rc" in clean:
            print("[停] 干净副本就跑不动（rc=%s）：%s" % (clean["__rc"], clean["__err"]))
            print("     ⇒ 后面所有臂作废。先修基线，不许拿坏基线当战果。")
            return 2
        if kinds(clean, "anchor"):
            print("[停] 干净副本有 %d 条 anchor 线索 ⇒ 基线不干净，"
                  "后面「被抓住」的判定会被污染。" % len(kinds(clean, "anchor")))
            return 2
        victim, nv = pick_victim(base)
        print("[基线] 干净副本：anchor 零线索 ｜ 线索 %d 条 ｜ 目标 type=%s（%d 条）"
              % (len(clean.get("clues") or []), victim, nv))
        print()

        specs = [
            ("R5 抹掉全部 ts", lambda r: r5_no_ts(r)),
            ("R7 删type·不动锚", lambda r: r7_strip_no_anchor(r, victim)),
            ("R6 删type·重算锚", lambda r: r6_strip_and_anchor(r, victim)),
            ("R8 ts平移6h·不动锚", lambda r: r8_shift_ts(r)),
            ("R9 删type·重算链+锚", lambda r: r9_strip_seal_anchor(r, victim)),
        ]
        for name, fn in specs:
            d = make_copy(work, name.split()[0])
            try:
                won, detail = fn(d)
            except Exception as exc:                       # noqa: BLE001
                won, detail = False, "臂自己崩了：%s: %s" % (type(exc).__name__, exc)
            arm(name, won, detail)

        print("-" * 78)
        w = sum(1 for _, ok, _ in ARMS if ok)
        print("红队赢了 %d 条／共 %d 条。**「赢」是就 C-2 单独而言**："
              "检测器对这次篡改照常报绿（或干脆崩掉）。" % (w, len(ARMS)))
        print("★ 每条臂都带了 C-1 的判定 —— 因为「C-2 瞎」和「整体瞎」是两件事，")
        print("  把两句合成一句就是对外过度承诺（铁律 21）。")
        print()
        print("结论（写进 watchman.BLIND_SPOTS，不许只写在文档里）：")
        print("  · **R9 是最终边界，也是本批最重要的一条实测**：删掉一个钩子的全期")
        print("    记录 ＋ 按文件重算链 ＋ 重算日锚 ⇒ **C-1 的 A1/A2/A3 全 PASS、")
        print("    C-2 的 anchor/absent 全静**。这不是推断，是跑出来的。")
        print("    要补只有一条路：账本之外的第二份记录（L2 外部锚）。今天没有。")
        print("  · R6 与 R7 成对：同一批篡改，只差「有没有重算锚」。R7 立刻被 anchor")
        print("    抓住 ⇒ R6 的安静**不是数据没变，是锚被绕过了**。没有 R7，")
        print("    R6 什么都证明不了。")
        print("  · R8：改中间记录的 ts、长度不变、`hash` 字段没动 ⇒ C-2 零线索，")
        print("    但 C-1 的 A1 红。所以是「**C-2 单独看不见，整体不瞎**」——")
        print("    这两句话不能互换，写错哪一句都是错。")
        print("  · R5：原实现在「一条 ts 都不可解析」时**直接崩**（rc=1，零输出）。")
        print("    崩的那条分支是 `detect_rule_pairs` 里「没有任何配对」时的回退，")
        print("    写成 `for _, d, _, _ in recs`，而 recs 是三元组 —— 干净账本永远")
        print("    有配对，所以它**从没被执行过**。已修，并把 gap 的覆盖状态从")
        print("    「查了，没有」改成「判不了」＋带分母（零与不可判同貌）。")
        print("    **「从没被执行过的分支」与「写对了的分支」在代码里长得一模一样。**")
        print("  · 附带发现：链是**按文件**的（`auditor.check_content` 每个文件")
        print("    `prev_full = ""` 重起）。所以「删掉一整天」在 A1/A2 上天生无痕，")
        print("    只有 A3 的日清单管得着 —— 这是 A3 存在的唯一理由，也是它的单点。")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
