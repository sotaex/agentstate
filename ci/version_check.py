# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""版本号一致性守卫 —— **九处手工维护的版本承载件**必须逐字相同；
`psl/manifest.json` 的 `version` **单独判**（产物可落后、不许超前）。

★★★ 为什么需要它（MEMORY 里点名的「无守卫」）
  「**发布前必手扫版本号**（pyproject / VERSION / server.json / antinel_mcp /
    AUDIT_SCHEMA 标题）—— **无守卫**。」
  手扫 = 靠人记得 = 迟早漏。实测落后程度：
      _ANTINEL_VERSION      = 0.32.2  （落后 2 版，且**进审计链**）
      build_package.VERSION = 0.29.0  （落后 4 版）
  两者都不是"注释里的历史标注"，是**活的声明**。

★★ 两个真源必须一致（这条本身也要能红）
  产品侧真源 = `tools/antinel_verify.py` 的 `_VERSION_HARD`（INV-3 不变量）
  本文件清单是它的**超集**（多 `hooks/pre_tool_use.py`、`scripts/build_package.py`、
   `SKILL.md`）。**清单分叉过一次**：初版只列 7 处，漏了 `rules/default.json`
  与 `docs/AUDIT_SCHEMA.md`；是 `antinel_verify.py --invariants` 的 INV-3 抓出来的。
  ⇒ 现在加判据 4：**本清单必须是 INV-3 清单的超集**，否则本检查器自己就是假守卫。

★★★ 0.43.1：为什么把 `psl/manifest.json` 从「逐字一致」里**摘出来**（根因修复）
  实测（创始人 2026-10-10 当场点名）：界面挂 R0「失守」，而事实是正常迭代。
  根因**不在** `is_dev_build()`，在**这里**：
    · `psl/manifest.json` 的 `version` 是**构建产物**（`build_package.py` 打包时
      写入"随包代码的版本"），它的**语义**就是"上次打包那一刻的版本" ⇒ 迭代期
      **本该落后于代码版本**；
    · 而它被当成"手工维护的承载件"塞进"10 处逐字一致"⇒ 每次升版都被迫把它也
      刷成同号 ⇒ `is_dev_build()` 赖以成立的**版本落差永远为 0** ⇒ 研发态
      **结构性失效** ⇒ 自检一有漂移就掉进 `warn`（失守）。
  ⇒ 修法：把它**摘出**「逐字一致」集，改判「**≤ 代码版本**」（产物可以落后于
    源码，但**绝不许超前**——超前就是被毒化/伪造，必须红）。
  ⇒ 摘出后**保护面没有变松**：它的"落后"是**被期待的中间态**，而它的"超前"
    照旧会红；且打包时 `build_package.py` 会把它刷成当前版本（`self_check()`
    的哈希基线也随之刷新）。

★ 判据设计（七条，都要能红）
  1. 九处承载件逐处抽取值，**全部相同**才通过；列出每处的实际值供定位
  2. 抽不到值 ⇒ **FAIL**（不是 SKIP）—— 「查不出来 ≠ 查出来是好的」
  3. 与 `--expect` 一致（发布前用）
  4. 本清单 ⊇ `antinel_verify.py::_VERSION_HARD`（防两个检查器分叉）
  5. SKILL.md 的 psl-verified* 必须与 psl/judgment.json 的 verdict 一致（防「自证卡过期」）
  6. server.json 的 stability.schema 必须与 docs/AUDIT_SCHEMA.md 抬头一致（防「对外清单声明旧模式」）
  7. （0.43.1 新增）`psl/manifest.json` 的 `version` ≤ 代码版本（产物可落后、不许超前）

用法：
    python ci/version_check.py
    python ci/version_check.py --expect 0.33.2   # 指定期望值（发布前用）
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

PKG = Path(os.environ.get("ANTINEL_PKG") or Path(__file__).resolve().parent.parent)

# (显示名, 相对路径, 正则, 分组号)
# ★ 只在**唯一且必填**的声明处抽取 —— 不要抽注释里的历史标注
# ★★ 本清单必须 ⊇ tools/antinel_verify.py 的 _VERSION_HARD（判据 4 强制）
# ★★★ 0.43.1：`psl/manifest.json` **已从此清单摘出**（见文件头「★★★ 0.43.1」）——
#   它是构建产物、语义上允许落后，改由判据 7 单独判「≤ 代码版本」。
SPOTS = [
    ("pyproject.toml",
     r'^version\s*=\s*"([^"]+)"', 1),
    ("server.json",
     r'"version"\s*:\s*"([^"]+)"', 1),
    ("antinel.py  VERSION",
     r'^VERSION\s*=\s*"([^"]+)"', 1),
    ("antinel_mcp.py",
     r'"serverInfo":\s*\{"name":\s*"antinel",\s*"version":\s*"([^"]+)"', 1),
    ("hooks/pre_tool_use.py  _ANTINEL_VERSION",
     r'^_ANTINEL_VERSION\s*=\s*"([^"]+)"', 1),
    ("scripts/build_package.py  VERSION",
     r'^VERSION\s*=\s*"([^"]+)"', 1),
    ("rules/default.json  version",
     r'"version"\s*:\s*"([^"]+)"', 1),
    ("docs/AUDIT_SCHEMA.md  标题",
     r'随\s*v(\d+\.\d+\.\d+)', 1),
    ("SKILL.md  antinel-version",
     r'^\s*antinel-version:\s*"([^"]+)"', 1),
]

# INV-3 的 HARD 清单（产品侧真源）——用于判据 4 的"超集"检查。
# 只登记**相对路径**，不复制正则（正则的维护点是 antinel_verify.py）。
# ★★★ 0.43.1：`psl/manifest.json` 已从 INV-3 的 HARD 移到 INFO（见 antinel_verify.py），
#   故此处同步移除 —— 否则判据 4 会要求本清单重新收录一个**已不该逐字一致**的项。
INV3_HARD_PATHS = {
    "antinel.py", "antinel_mcp.py", "rules/default.json", "pyproject.toml",
    "server.json", "docs/AUDIT_SCHEMA.md",
    "build_package.py",
}


def _inv3_superset_fails():
    """判据 4：本清单必须是 INV-3 清单的超集。
    比对用**文件名**（不比对全路径）—— INV-3 写 `build_package.py`（源仓布局
    平铺在根），本仓在 `scripts/`。这层错位正是它初版漏检的原因，必须显式容纳：
    ⇒ 只要**任一** SPOT 的 basename 等于 INV-3 项即算覆盖。"""
    ours = set()
    for label, _pat, _grp in SPOTS:
        rel = label.split()[0]
        ours.add(rel)
        ours.add(rel.rsplit("/", 1)[-1])
    return sorted(p for p in INV3_HARD_PATHS if p not in ours)


def extract():
    out = []
    for label, pat, grp in SPOTS:
        rel = label.split()[0]
        p = PKG / rel
        if not p.is_file() and rel.startswith("docs/"):
            p = PKG / rel.split("/", 1)[1]      # 源仓布局回退（与 INV-3 同法）
        if not p.is_file():
            out.append((label, None, "文件不存在"))
            continue
        try:
            t = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            out.append((label, None, "读取失败 %s" % type(e).__name__))
            continue
        m = re.search(pat, t, re.M)
        if not m:
            out.append((label, None, "未抽到（正则不匹配 ⇒ 声明可能被删/改格式）"))
            continue
        out.append((label, m.group(grp), ""))
    return out


def _content_hash(rel, p):
    """内容哈希 —— 必须用**产品那把尺子**，不许在本判据里另写一把。

    ★★ 为什么（2026-10-23 实测）：`judgment.digests` 里存的不是裸 sha256。
      `build_package._manifest_hash_of()` 对**版本承载件**先过
      `norm_version_bytes()`（把版本号抹成占位符再算）。本函数此前用的是裸
      `hashlib.sha256(p.read_bytes())` ⇒ 版本承载件两侧**天然不等** ⇒
      **每改一次版本号，判据 5 就把一份新鲜判定读成「陈旧」**，报红
      「拿旧判定当新代码的验证」。
      当日实测 `hooks/pre_tool_use.py`：裸 93e52ee3…／归一 20922050…，
      而 judgment 里记的正是归一值 —— 判据在拿两把尺子比。
      ⇒ 一律调产品函数。（记忆里那条「判据必须调产品函数」的第三形态：
      不是判据读错了对象，而是**判据自己造了第二个哈希口径**。）
    """
    try:
        import build_package as _bp
    except ImportError:  # 只在非仓内布局时兜底（正常路径走不到）
        for cand in (PKG / "scripts", PKG):
            if str(cand) not in sys.path:
                sys.path.insert(0, str(cand))
        import build_package as _bp
    return _bp._manifest_hash_of(rel, str(p))


def _judgment_covers(j):
    """judgment.digests 是否仍覆盖**当前**代码（内容哈希逐文件比）。

    ★★ 为什么加（2026-10-21 STE100 施工期实测判据 5 误红）：
      判据 5 原本只比对 SKILL 字段与 judgment.verdict 的**字面**。STE100
      改了 antinel.py（CLI 文案）后，装配器按内容哈希如实把 SKILL 刷成
      false ＋ evidence「digests DO NOT match」—— 而 judgment 还是上次
      harness 的 PASS（digests 记的是旧 antinel.py）⇒ 判据 5 判
      「SKILL=false 与 verdict=PASS 不一致 ⇒ 应为 true」——**误红**：
      拿一份已不覆盖当前代码的旧 PASS，要求自证卡说「已验证」。
      这正是原判据要防的「自证卡过期」的**另一侧**：判据盯住了 SKILL
      侧会过期，没盯 judgment 侧也会过期。
    ⇒ digests 逐文件比 sha256；对不上 ⇒ judgment 陈旧，其 verdict
      **不构成**对当前代码的验证状态。没有 digests 时不判陈旧
      （向后兼容：老 judgment 没有指纹集）。
    """
    dg = (j or {}).get("digests") or {}
    if not dg:
        return True, []
    stale = []
    for rel, want in dg.items():
        p = PKG / rel
        if not p.is_file():
            stale.append(rel)
            continue
        try:
            got = _content_hash(rel, p)
        except OSError:
            stale.append(rel)
            continue
        if got != want:
            stale.append(rel)
    return (not stale), stale


def _psl_verified_judge(j, txt, covers=None, stale=()):
    """判据 5 判定核心（从读盘拆出 ⇒ 负控可内存喂合成场景，不写盘）。

    覆盖时走原逻辑（PASS⇒true / FAIL⇒false）；陈旧时只许 false 且
    evidence 非空 —— 拿旧判定当新代码的验证（true）照旧红。
    """
    out = []
    verdict = j.get("verdict")
    m = re.search(r'^\s*psl-verified:\s*"([^"]*)"', txt, re.M)
    if not m:
        return ["SKILL.md 里读不到 psl-verified 字段"]
    if covers is None:
        covers, stale = _judgment_covers(j)
    if covers:
        want = "true" if verdict == "PASS" else "false"
        if m.group(1) != want:
            out.append("SKILL.md psl-verified=%r 与 judgment verdict=%r 不一致（应为 %r）"
                       % (m.group(1), verdict, want))
        if want == "true":
            ma = re.search(r'^\s*psl-verified-at:\s*"([^"]*)"', txt, re.M)
            if not ma or not ma.group(1).strip():
                out.append('verdict=PASS 但 psl-verified-at 为空 —— "什么时候验的"不能留白')
    else:
        if m.group(1) != "false":
            out.append("judgment 指纹已不覆盖当前代码（%s 等 %d 项），SKILL.md 却写 verified=%r"
                       " —— 拿旧判定当新代码的验证"
                       % (",".join(list(stale)[:3]), len(stale), m.group(1)))
        ev = re.search(r'^\s*psl-verified-evidence:\s*"([^"]*)"', txt, re.M)
        if not ev or not ev.group(1).strip():
            out.append("judgment 陈旧期间 SKILL.md 的 psl-verified-evidence 不许留白"
                       "（要写明为什么不验证）")
    return out


def _psl_verified_fails():
    """判据 5：SKILL.md 的 psl-verified* 字段必须与 psl/judgment.json 一致。

    ★ 为什么要它（2026-10-03 实测）：0.34.0 判定首次转绿后，SKILL.md 仍写着
        psl-verified: "false"
        psl-verified-evidence: "NOT VERIFIED for this build: ... verdict is 'FAIL'"
      —— 写的时候它**是真的**，但判定一变它就**过期**，而**没有任何检查会红**。
      一个自证卡上的字段长期说反话，比没有这个字段更坏（读者会当真）。

    ⇒ 本判据只做**一致性**检查，不代替 judgment：
      · judgment 说 PASS ⇒ SKILL.md 应为 verified:"true" 且 verified-at 非空；
      · judgment 说 FAIL ⇒ SKILL.md 应为 false。
      不一致 ⇒ FAIL，并**指名**该改哪一边。
    """
    sk = PKG / "SKILL.md"
    jp = PKG / "psl" / "judgment.json"
    if not sk.is_file() or not jp.is_file():
        return ["判据 5 需 SKILL.md 与 psl/judgment.json 同时存在"]
    try:
        j = json.loads(jp.read_text(encoding="utf-8"))
    except Exception as e:
        return ["psl/judgment.json 解析失败：%r" % e]
    txt = sk.read_text(encoding="utf-8")
    return _psl_verified_judge(j, txt)


def _stability_schema_fails():
    """判据 6：server.json 的 stability.schema 必须与 docs/AUDIT_SCHEMA.md 抬头一致。

    ★ 为什么要它（2026-10-05 实测）：`server.json` 的 `stability.schema` 停在
        "AUDIT_SCHEMA v1.2, changes registered append-only"
      —— 那是 **v0.28.0 时代的快照**（同 commit `fa716ed` 里 AUDIT_SCHEMA.md 抬头
      正是 v1.2），此后文档升到 v1.9，而这个字段**没有任何检查项读它**
      （全仓 grep `stability` 命中 0 个 .py）。
      ⇒ 一个对外发布的 MCP 清单，在向注册表声明一个 7 版之前的模式版本，无人发现。

    ★ 与判据 5 同一类病：**声明会随真源演进而过期，而没有东西会红。**
      真源是**文档抬头**（人维护、有版本纪律），不是本文件里再抄一份 ——
      判据不许二次实现，只做「读真源、比被检对象」。
    """
    out = []
    doc = PKG / "docs" / "AUDIT_SCHEMA.md"
    if not doc.is_file():
        doc = PKG / "AUDIT_SCHEMA.md"           # 源仓布局回退（与 SPOTS 同法）
    if not doc.is_file():
        return ["判据 6 找不到 AUDIT_SCHEMA.md（真源缺失 ⇒ 假守卫，不许静默通过）"]
    try:
        dt = doc.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return ["判据 6 读 AUDIT_SCHEMA.md 失败：%r" % e]
    md = re.search(r'审计记录模式\s*v(\d+\.\d+)', dt)
    if not md:
        return ["判据 6 从 AUDIT_SCHEMA.md 抬头抽不到模式版本（格式变了 ⇒ 检查器会瞎）"]
    want = md.group(1)

    sj = PKG / "server.json"
    if not sj.is_file():
        return ["判据 6 找不到 server.json（被检对象缺失 ⇒ 假守卫）"]
    try:
        st = json.loads(sj.read_text(encoding="utf-8")).get("stability") or {}
    except Exception as e:
        return ["判据 6 解析 server.json 失败：%r" % e]
    schema = str(st.get("schema") or "")
    ms = re.search(r'AUDIT_SCHEMA\s*v(\d+\.\d+)', schema)
    if not ms:
        return ["判据 6 server.json 的 stability.schema 抽不到版本：%r" % schema]
    got = ms.group(1)
    if got != want:
        out.append("server.json stability.schema 声明 AUDIT_SCHEMA v%s，而 docs/AUDIT_SCHEMA.md "
                   "抬头是 v%s ⇒ 对外清单在声明一个过期的模式版本（改 server.json，别改文档）"
                   % (got, want))
    return out


def _manifest_lag_fails():
    """判据 7（0.43.1 新增）：`psl/manifest.json` 的 `version` **≤ 代码版本**。

    ★ 为什么需要（**根因修复的配套守卫**，2026-10-10）：
      本判据与「把 manifest 从逐字一致里摘出」是**同一件事的两半** ——
      摘出（放开"落后"）必须配一条判据钉住"**只许落后、不许超前**"，
      否则就是**单方面放松**（正是本仓最忌的"改了一处漏一处"）。
      · 落后（`manifest < code`）= **被期待的中间态**（版本已升、还没重打包）
        ⇒ 研发态 `is_dev_build()` 赖以成立 ⇒ 判 **PASS**；
      · 相等 = 已打包/已出厂 ⇒ 判 **PASS**；
      · 超前（`manifest > code`）= 产物声明了一个**还没写出来的版本**
        ⇒ 只可能是被毒化/伪造 ⇒ 判 **FAIL**（方向往严的一边偏）。

    ★ 与判据 1 的分工：判据 1 管"九处手工承载件彼此一致"，本判据管"产物与代码
      的关系"。两者都不许二次实现对方的逻辑 —— 版本比较**复用**
      `host_shield._ver_lt`（唯一真源），不在这里另写一套。
    """
    out = []
    mp = PKG / "psl" / "manifest.json"
    if not mp.is_file():
        return ["判据 7 找不到 psl/manifest.json（产物缺失 ⇒ 假守卫，不许静默通过）"]
    try:
        mfv = json.loads(mp.read_text(encoding="utf-8")).get("version")
    except Exception as e:                                      # noqa: BLE001
        return ["判据 7 解析 psl/manifest.json 失败：%r" % e]
    if not mfv:
        return ["判据 7 从 psl/manifest.json 抽不到 version（格式变了 ⇒ 检查器会瞎）"]
    # 代码版本真源：antinel.py 的 VERSION（与 SPOTS 同法抽取，不另立真源）
    ap = PKG / "antinel.py"
    if not ap.is_file():
        return ["判据 7 找不到 antinel.py（代码版本真源缺失）"]
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', ap.read_text(encoding="utf-8"), re.M)
    if not m:
        return ["判据 7 从 antinel.py 抽不到 VERSION"]
    code = m.group(1)
    try:
        sys.path.insert(0, str(PKG))
        import host_shield as _HS
        lt = _HS._ver_lt(code, mfv)          # code < mfv ⇔ manifest 超前
    except Exception as e:                                      # noqa: BLE001
        return ["判据 7 无法比较版本（%s vs %s，%s）⇒ 往严偏，判 FAIL"
                % (mfv, code, type(e).__name__)]
    if lt is None:
        return ["判据 7 版本号比不了（%s vs %s）⇒ 往严偏，判 FAIL" % (mfv, code)]
    if lt:
        out.append("psl/manifest.json 的 version=%s **超前**代码版本 %s "
                   "⇒ 产物声明了一个还没写出来的版本（只可能是被毒化/伪造）"
                   "（产物只许落后或相等，不许超前）" % (mfv, code))
    return out


def _negctl_judged():
    """判据 5 三条负控（内存合成场景，磁盘一个字节都不动）。

    负控一：指纹覆盖 + verdict=PASS + SKILL=false ⇒ 必须红（无据不验证）
    负控二：指纹陈旧 + SKILL=true             ⇒ 必须红（陈凭证当真）
    负控三：指纹陈旧 + SKILL=false + evidence 空 ⇒ 必须红（不写理由）
    正回归：指纹陈旧 + false + evidence 非空   ⇒ 必须绿（施工期诚实态）
    """
    real = "sha256:" + hashlib.sha256((PKG / "antinel.py").read_bytes()).hexdigest()
    fails = []

    def judge(verdict, verified, covers, stale, evidence="NOT VERIFIED for this build: 1/21 digests DO NOT match"):
        txt = ('psl-verified: "%s"\npsl-verified-spec: "psl-vs-0.1"\n'
               'psl-verified-at: ""\npsl-verified-evidence: "%s"\n' % (verified, evidence))
        j = {"verdict": verdict}
        return _psl_verified_judge(j, txt, covers=covers, stale=stale)

    if not judge("PASS", "false", True, []):
        fails.append("负控一未生效：digests 覆盖且 PASS，SKILL=false 却没红")
    if not judge("PASS", "true", False, ["antinel.py"]):
        fails.append("负控二未生效：digests 陈旧，SKILL=true 却没红")
    if not judge("PASS", "false", False, ["antinel.py"], evidence=""):
        fails.append("负控三未生效：digests 陈旧且 evidence 留白，却没红")
    if judge("PASS", "false", False, ["antinel.py"]):
        fails.append("正场景反被误红：digests 陈旧、SKILL 如实 false 且 evidence 非空，却红了")
    # 指纹真的匹配时，false 必须照旧红（原判据的保护面不许松）
    j_real = {"verdict": "PASS", "digests": {"antinel.py": real}}
    cov, st = _judgment_covers(j_real)
    if not cov:
        fails.append("负控夹具不成立：真哈希居然判陈旧")
    txt_false = ('psl-verified: "false"\npsl-verified-spec: "psl-vs-0.1"\n'
                 'psl-verified-at: ""\npsl-verified-evidence: "x"\n')
    if not _psl_verified_judge(j_real, txt_false, covers=cov, stale=st):
        fails.append("负控四未生效：digests 真实覆盖且 PASS，SKILL=false 却没红（保护面松了）")
    return fails


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect", help="期望版本（不给则用 psl/manifest.json 的 version）")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--negctl", action="store_true", help="只跑判据 5 的内存负控（不写盘）")
    a = ap.parse_args()

    if a.negctl:
        nf = _negctl_judged()
        print("判据 5 负控（内存合成，不写盘）：%s" % ("四条全生效" if not nf else "；".join(nf)))
        return 0 if not nf else 1

    rows = extract()
    print("=" * 78)
    print("版本号一致性守卫 —— %d 处承载件必须逐字相同；"
          "psl/manifest.json 单独判（≤ 代码版本）" % len(SPOTS))
    print("包路径：%s" % PKG)
    print("=" * 78)

    # 先打印全部实际值（含未抽到的，如实显示）
    for label, val, err in rows:
        tag = val if val else "★未抽到"
        print("  %-46s %-10s %s" % (label, tag, err))
    print("-" * 78)

    vals = [v for _, v, _ in rows if v]
    missing = [(l, e) for l, v, e in rows if not v]

    fails = []
    # 判据 1：全部抽到
    if missing:
        for l, e in missing:
            fails.append("抽不到值：%s（%s）" % (l, e))
    # 判据 2：全部相同
    uniq = sorted(set(vals))
    if len(uniq) > 1:
        for v in uniq:
            who = [l for l, vv, _ in rows if vv == v]
            fails.append("版本 %s 出现在：%s" % (v, "; ".join(who)))
    # 判据 3：与期望一致
    expect = a.expect or (uniq[0] if len(uniq) == 1 else None)
    if a.expect and vals and any(v != a.expect for v in vals):
        fails.append("与 --expect=%s 不符（实际 %s）" % (a.expect, uniq))
    # 判据 4：本清单 ⊇ INV-3 清单（防两个检查器分叉 —— 初版就是这样漏了两处）
    gap = _inv3_superset_fails()
    if gap:
        fails.append("本清单漏了 INV-3 承载件：%s（两个检查器已分叉）" % ", ".join(gap))
    # 判据 5（2026-10-03 新增）：SKILL.md 的 psl-verified 四字段必须与 judgment **一致**。
    #   为什么需要：0.34.0 判定首次转绿后，SKILL.md 仍写着
    #   `psl-verified: "false"` ＋ `"NOT VERIFIED ... verdict is 'FAIL'"`。
    #   ★ 那**不是撒谎**（写的时候确实是 FAIL），但它会**随判定变化而过期**，
    #     而**没有任何检查会变红** —— 于是一个自证卡上的字段可以长期说反话。
    #   ⇒ 本判据把「SKILL.md 怎么说」与「judgment 实际是什么」绑在一起：
    #     两者不一致就红。这与判据 4 防的是同一类病（两个检查器分叉）。
    pv = _psl_verified_fails()
    if pv:
        fails.extend(pv)
    # 判据 6（2026-10-05 新增）：server.json 的 stability.schema 必须与 AUDIT_SCHEMA.md 抬头一致。
    #   防的是「对外清单声明一个过期的模式版本而无人发现」——与判据 5 同一类病。
    fails.extend(_stability_schema_fails())
    # 判据 7（0.43.1 新增）：psl/manifest.json 的 version ≤ 代码版本。
    #   与「把 manifest 从逐字一致里摘出」配套 —— 只许落后、不许超前。
    fails.extend(_manifest_lag_fails())

    print()
    if not fails:
        print("★ PASS：%d 处版本号全部为 %s" % (len(rows), uniq[0]))
        # 额外提醒（不算 FAIL，但要看见）
        mf = PKG / "psl" / "manifest.json"
        if mf.is_file():
            d = json.loads(mf.read_text(encoding="utf-8"))
            bf = d.get("built_from")
            if bf and "r1v3" in str(bf):
                print("  ▲ 注意：psl/manifest.json 的 built_from 仍指向源仓 %s" % bf)
                print("     （build_package.py 已归位产物仓，重签时会自动改对）")
        if a.json:
            print(json.dumps({"ok": True, "version": uniq[0]}, ensure_ascii=False))
        return 0

    print("★ FAIL：版本号不一致 —— 发布前必须统一")
    for f in fails:
        print("   - %s" % f)
    if a.json:
        print(json.dumps({"ok": False, "fails": fails}, ensure_ascii=False))
    return 1


if __name__ == "__main__":
    sys.exit(main())
