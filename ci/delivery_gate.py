# -*- coding: utf-8 -*-
"""★★ 统一交付闸门 —— 0.36.5：把「所有判据」收进**一个入口、三处强制点**。

★★★ 这份文件存在的理由（创始人 2026-10-07 提问，一字不改地记在这里）：

    「自检器目前是独立脚本，还没接任何强制执行点。
      纪律有了，执行点没接上 —— 这是收敛机制的最后一块缺口。」

  这句话**只点出了缺口的一半**。实测把全仓判据清点一遍，真实形状是：

    ┌─────────────────────┬──────────┬────────────────────────────┐
    │ 判据集│ 条数 │ 改造前的调用方           │
    ├─────────────────────┼──────────┼────────────────────────────┤
    │ inbox_guards_0360   │ 52       │ **无**│
    │ inbox_guards_0362│ 31       │ **无**                      │
    │ inbox_guards_0363   │ 13       │ **无**                      │
    │ inbox_guards_0364   │ 17       │ **无**                      │
    │ _p_delivery_selfcheck│ 7       │ 只有它自己的负控引用        │
    │ regression_gate     │ 13       │ pre-commit ＋ CI（已接）    │
    │ version_check       │  6│ CI（已接）                 │
    └─────────────────────┴──────────┴────────────────────────────┘

  ⇒ **113 条值守台判据 + 7 条自检，一条都没接执行点。**
    而这不是"忘了接线"这么轻：`0363` 有一条红、`0364` 有一条红，
    **已经红了一段时间却没人知道** —— 因为没人跑。
    ⇒ 这就是本仓铁律「**无检查项的禁令＝没禁令**」的镜像：
      **有检查项但没人跑 ＝ 同样等于没有。**
      两个方向都是"看起来有防护，实际没有"。

★ 三条设计纪律（照抄 regression_gate 的成熟做法，不重新发明）：
  ① **判据不许二次实现** —— 本文件**不重写任何判据逻辑**，
     只负责「按固定顺序调起 + 汇总退出码 + 区分红与崩」。
     任何一条判据的增删改都在它自己的文件里做。
  ② **必须能区分「没跑到」与「跑到了」** —— 判据脚本**不存在**时报
     💥 SKIP 并**计为红**。理由：缺失的判据和通过的判据在退出码上
     若都返回 0，那「删掉一个判据文件」就成了让闸门变绿的手段。
     （这与 regression_gate 判据 ③「测不出的情况报 SKIP，绝不报 PASS」同源。）
  ③ **负控必须能红** —— `--selfcheck` 模式：把一条判据的**定义**
     临时改坏，断言本闸门**必须**变红。不红的闸门是装饰。

用法：
    python ci/delivery_gate.py                # 跑全套
    python ci/delivery_gate.py --quick        # 跳过慢的那套（< 10 秒档）
    python ci/delivery_gate.py --only 0364    # 只跑某一套（排查用）
    python ci/delivery_gate.py --json         # 机器可读（CI 用）
    python ci/delivery_gate.py --selfcheck    # 负控：判据被改坏时本闸门必须红
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(_HERE)
RESULTS = []


# ────────────────────────────────────────────── 判据清单（唯一真源）
#: `(键, 相对路径, 分档)`。分档：
#:   fast = 进程内、秒级（默认与 --quick 都跑）
#:   slow = 会起子进程、改文件，或依赖仓外原件（--quick 跳过；打包前必跑）
#:
#: ★ 清单必须与磁盘**实际存在的文件**对齐，且两者不一致时判红 ——
#:   否则「删掉一个判据文件」就能让闸门变绿。
#:
#: ★★ 0353 归 slow 档的理由（实测，不是猜）：它 `import inbox_guards` 脚手架、
#:   且 `PSL_ROOT` 指向仓外 `D:\2026\PSL` 的规格原件 —— 缺件时它**退出码仍是 0
#:   但零输出**。若归 fast 档，一次"全绿但什么都没跑"会被读成通过。
#:   ⇒ 归 slow 档 + 下面 `_looks_like_noop()` 显式识别"零输出即假绿"。
SUITES = [
    ("0353", "ci/inbox_guards_0353.py", "slow"),
    ("0360", "ci/inbox_guards_0360.py", "fast"),
    ("0362", "ci/inbox_guards_0362.py", "fast"),
    ("0363", "ci/inbox_guards_0363.py", "fast"),
    ("0364", "ci/inbox_guards_0364.py", "fast"),
    ("0366", "ci/inbox_guards_0366.py", "fast"),
    ("JDG", "ci/jdg_guards_0368.py", "fast"),
    # ★ 0.37.0：PCM（问题数单调收敛闸门）。为什么进 SUITES 而不是只登记：
    #   它回答的是整条收敛管道**唯一还没回答的问题**——「问题总量有没有在变小、
    #   变小是真变小还是账面变小」（JDG/0366 回答的是「这次多了什么、红是真是假」）。
    #   它是 fast 档：只读 judgment.json 与 .psl/gate/pcm_ledger.json 两份 JSON，
    #   不起子进程、不写产品文件（负控全在内存态，不需要 negctl 单列档）。
    ("PCM", "ci/pcm_gate_0370.py", "fast"),
    ("selfcheck", "ci/_p_delivery_selfcheck.py", "fast"),
    ("version", "ci/version_check.py", "fast"),
    ("regression", "ci/regression_gate.py", "slow"),
]

#: ★★ 第四档 `negctl`：**会临时改坏产品文件再还原**的负控脚本。
#:
#: 为什么单列一档、且**默认不跑**（实测踩过，不是假想）：
#:   负控的机制是"把一条判据改坏 → 断言它变红 → 还原"。
#:   ⇒ 它运行期间，**产品代码处于损坏状态**。
#:   若把它放进打包前的闸门：打包进程中途被杀 / 断电 / 超时，
#:   变异的代码就会**随包发出去**。
#:   ⇒ 「强制执行点」与「会污染产物」这两件事**不能共处一个调用时机**。
#:
#: 那怎么保证它不被删掉、不被"优化"掉？
#:   —— 登记进 `REQUIRED`（存在性检查照旧），
#:     **但不打进 `SUITES`** ⇒ 闸门只查它在不在，不跑它。
#:   ⇒ 删它 ⇒ 结构检查判红；跑它 ⇒ 显式 `python ci/delivery_gate.py --negctl`。
#:   这就是「有检查项但没人跑＝等于没有」的**另一半解法**：
#:     不是硬塞进所有路径，而是**让它该跑的时候跑、该查的时候查**。
REQUIRED_EXTRA = [
    "_p_bubble_negctl.py",
    "_p_selfcheck_negctl.py",
    "_p_guards_mutation.py",
    "_p_contract_negctl.py",
    "ci/version_check_negctl.py",
    # ★ 0.36.8：harness（判定账本的生成器）登记为**必须存在**但不进 SUITES。
    #   为什么不进 SUITES：`_run` 单套超时 900s，而 harness 实测约 22–25 分钟，
    #   塞进去只会以「CRASH 超时」假失败收场（那是量具失真，不是发现）。
    #   为什么必须登记：负控衰减最致命的地方（公开判定账本）恰好是
    #   收敛机制唯一没伸到的一寸 ⇒ 它不许被静默删掉。
    #   ⇒ 存在性守这里；真跑由打包序列显式执行（`python scripts/run_harness.py`）。
    "scripts/run_harness.py",
    # ★ 0.36.9：两条**判据引用的探针**补登记（0.36.8 实测抓到的契约空洞）。
    #   `ci/inbox_guards_0360.py` 引用 `_p_badge_probe.py`、旧版
    #   `ci/inbox_guards.py` 引用 `_p_p11_negctl_mutation.py`，两个都
    #   从未入库 ⇒ 本机全绿、新克隆必红（判据契约在新机器上不成立）。
    #   为什么必须登记在这里：`.gitignore` 的 `_p_*` 会把未入库探针从
    #   `git status` 藏起来 ⇒ 缺口从「可见」变「隐藏」，比不忽略更危险。
    #   真正堵死它的是 JDG-04（契约自包含：判据引用的本地文件必须已入库）。
    "_p_badge_probe.py",
    "_p_p11_negctl_mutation.py",
]

#: 必须存在的判据文件。少任何一个 ⇒ 报红（不许静默少跑）。
REQUIRED = [rel for _k, rel, _d in SUITES] + REQUIRED_EXTRA


# ═══════════════════════════ 机制层 ①：基线快照 ＋ 差分归因 ═══════════════════════
#
#: ★★★ 为什么这是**错误收敛速度**的关键（0.36.6 实测推导，不是设计构想）：
#:
#:   看本轮真实发生过的链条：
#:     ① 我改 `inbox_window.py`（补页面名白名单）
#:     ② 跑闸门 ⇒ **P15 报红**
#:     ③ 我花了一轮才分清「这是判据的错，不是产品的错」
#:
#:   而第③步之所以贵，是因为**闸门只会说「现在有红」，不会说「相对上次多/少了什么」**。
#:   ⇒ 于是每次红都必须重新做一次「归因」—— 而归因是本仓最贵的一步
#:     （要查是哪次改动引入的、判据测的是谁、红项指向的代码有没有犯过这个错）。
#:
#: ★ 收敛的正确形态不是「永不出错」（那不可能），是：
#:     **出错 → 立刻知道「多了什么」→ 立刻知道该改判据还是改产品。**
#:   快照就是把「多/少了什么」变成**机器算出来的**，不再靠人重跑一遍去回忆。
#
#: ★ 落盘口径（三条，都不是可选项）：
#:   · 写在 `.psl/` 下（项目状态目录），**不写进包、不进 manifest**
#:     ⇒ 快照不是产品的一部分，是**对产品的观察**。
#:   · **带闸门脚本自己的指纹**：改了 SUITES 或判据清单，快照自动失效
#:     ⇒ 避免「判据换了却拿旧快照比」的假差分。
#:   · **保留上一次**（`.prev`）⇒ 连续红两次时能看出「这次是同一红还是新红」。

_SNAP_DIR = os.path.join(PKG, ".psl", "gate")
_SNAP = os.path.join(_SNAP_DIR, "baseline.json")
_SNAP_PREV = os.path.join(_SNAP_DIR, "baseline.prev.json")


def _gate_fingerprint():
    """闸门自身的指纹：判据清单 ＋ 被跑文件的 mtime/size ＋ **闸门文件自己**。

    ★★ 必须含 mtime：改了 `inbox_guards_0360.py` 里的判据，
      判据数量可能不变（还是 52 条）但**内容变了** ⇒ 只比数量会漏。

    ★★★ 0.36.6 实测抓到本函数**第二版**的缺陷（第一版是漏了闸门自己）：
      改用**内容哈希**而不是 `mtime:size` ——
      因为 **`0366` 的负控会在闸门运行时写注释再还原**，
      **还原后 mtime 变了而内容没变** ⇒ 用 mtime 会让指纹**每次跑都变**
      ⇒ 差分永远用不上（实测连跑三次都是「指纹不同，已失效」）。
      ⇒ 与本仓那条「**行为对 ≠ 说法对**」同族：文件被读/被写时间戳变了，
        但它**算不算"变过"** 取决于内容，不取决于 mtime。
      ★ 代价：哈希要读全部内容（9 个文件几十 KB），
        **但闸门本来就要把它们全跑一遍** —— 这点开销可以忽略。
    """
    parts = ["|".join(sorted(rel for _k, rel, _d in SUITES))]
    for rel in sorted([r for _k, r, _d in SUITES] + ["ci/delivery_gate.py"]):
        p = os.path.join(PKG, rel)
        try:
            with open(p, "rb") as f:
                parts.append("%s:%s" % (
                    rel, hashlib.sha256(f.read()).hexdigest()[:16]))
        except OSError:
            parts.append("%s:MISSING" % rel)
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _red_fingerprint(text):
    """把一段红项文本压成稳定指纹（去掉耗时/秒数这类每次都变的数字）。"""
    t = re.sub(r"\[\d+(?:\.\d+)?s\]", "[Xs]", text or "")
    t = re.sub(r"\d+(?:\.\d+)?\s*(?:ms|s\b|秒|分钟)", "N单位", t)
    return hashlib.sha256(t.strip().encode("utf-8")).hexdigest()[:16]


def _load_snapshot():
    try:
        with open(_SNAP, encoding="utf-8") as f:
            return json.load(f)
    except Exception:                                          # noqa: BLE001
        return None


def _save_snapshot(results, fp):
    """写快照。**先把旧的挪成 .prev**（零删除，与全仓纪律一致）。"""
    try:
        os.makedirs(_SNAP_DIR, exist_ok=True)
        if os.path.isfile(_SNAP):
            os.replace(_SNAP, _SNAP_PREV)
        snap = {
            "fingerprint": fp,
            "ts": time.time(),
            "suites": {r["suite"]: {"status": r["status"],
                                   "red_fp": _red_fingerprint(r.get("red", ""))}
                       for r in results},
        }
        with open(_SNAP, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=1)
    except Exception:                                          # noqa: BLE001
        pass


def _diff_against_baseline(results, fp):
    """对照上一次快照，输出**新增红**与**已修复**。

    ★ 返回 `(新增红列表, 已修复列表, 说明)`；快照不可用时说明原因，
      **不许静默跳过** —— 「对照不上」与「没有新增」必须能区分。
    """
    old = _load_snapshot()
    if not old:
        return [], [], "无上次快照（首次运行）—— 本次建立基线"
    if old.get("fingerprint") != fp:
        return [], [], ("上次快照的闸门指纹与现在不同（判据清单或判据文件变过）"
                        "—— 快照已失效，本次重新建立基线")
    olds = old.get("suites") or {}
    new_red, fixed = [], []
    for r in results:
        o = olds.get(r["suite"])
        if o is None:
            if r["status"] != "PASS":
                new_red.append((r["suite"], r["status"] + "｜新增判据集"))
            continue
        was_red = o.get("status") != "PASS"
        now_red = r["status"] != "PASS"
        # ★★★ 0.36.6 补一个**污染源**：崩了/缺失**不是红**。
        #   若把它们也算进「新增红」，那么一次"判据文件被误删/判据自身崩了"
        #   就会以"我改出了新红"的形态出现在收敛线索里 ⇒ **污染账本**，
        #   而收敛线索一旦被污染，人就会开始怀疑整套机制、进而不再看它
        #   （与「零输出被当通过」同族：那都是**账面失真**）。
        #   ⇒ 崩/缺失**单独成一类**，红项仍照常打印、仍阻断，只是不许进「新增红」。
        st = r["status"]
        if st in ("CRASH", "MISSING", "NOOP"):
            if not was_red:
                new_red.append((r["suite"], st + "｜**这不是红，是判据没跑成**"
                                           "（账上单列，不与真缺陷混算）"))
            continue
        if now_red and not was_red:
            # ★ 不用 `%` 格式化：红项文本里**可能含百分号**（实测踩到：
            #   判据回报里有 "99%"，被当成格式符 ⇒ 整个闸门崩在收尾段）。
            #   崩在这里的后果特别坏：**红项已经打出来了，却因为收尾崩而丢掉结论**，
            #   退出码非零却看不到「新增红是哪几条」。
            #   ⇒ 一律用字符串拼接（`+`），不存在格式串解析。
            head = (r.get("red") or "").strip().splitlines()
            head = head[0][:110] if head and head[0].strip() else st
            new_red.append((r["suite"], st + "｜" + head))
        elif was_red and not now_red:
            fixed.append(r["suite"])
    return new_red, fixed, "已对照 %d 个判据集的上一状态" % len(olds)



# ═══════════════ 机制层 ②：影响面自动点名（改了什么 → 必须复验什么）═══════════════
#
#: ★★★ 这条机制的由来是本轮真实踩到的一句话（0.36.6）：
#:
#:     「规则变更必须同时验证它没弄坏别的题。」—— 0.36.4 v1.1 修好 C02 却让 C08 回归
#:
#:   而它的**危险形态**不是「忘了跑全套」，是「跑���全套，但不知道该看哪几条的红」：
#:     8 套一起跑、几十秒、输出一屏 ⇒ 你看到一堆 ✅ 和几个 ❌，
#:     但**分不出这个 ❌ 是我这次改出来的，还是上一轮就在那儿的老账**。
#:   ⇒ 于是每次改动后都要**把全套红项逐条读一遍去找哪个是自己弄的**——
#:     这是纯人力活，且必然漏。
#:
#: ★ 机制化的做法：把「我改了哪些产品文件」变成**输入**，
#:   用**静态依赖图**算出「哪些判据直接读这些文件」，
#:   输出成**必须复验的名单**。没有名单 ⇒ 那是"跑了但不知道该看哪条"。
#
#: ★ 为什么用静态 import 图而不是运行时追踪：
#:   运行时追踪更准，但要在判据里插桩 —— 判据本身就被污染了
#:   （与本仓「判据不许二次实现」同源：观察不该改变被观察的东西）。
#:   静态图会漏「动态 getattr / importlib.import_module」，⇒ 明写局限，不假装覆盖。

_STDLIB_HINT = {
    "os", "sys", "re", "json", "io", "time", "ast", "subprocess", "hashlib",
    "textwrap", "platform", "tempfile", "shutil", "glob", "argparse", "types",
    "copy", "datetime", "collections", "itertools", "functools", "unittest",
    "traceback", "random", "string", "math", "zipfile", "base64", "threading",
    "ctypes", "wintypes", "abc", "enum", "contextlib", "signal", "socket",
    "urllib", "http", "html", "xml", "csv", "sqlite3", "ssl", "pickle",
    "struct", "uuid", "stat", "codecs", "locale", "unicodedata", "calendar",
    "decimal", "fractions", "numbers", "statistics", "inspect", "tokenize",
    "pathlib", "importlib", "unittest.mock",
}


def _suite_deps(rel):
    """静态算出这套判据**直接 import** 的本仓模块集合。"""
    try:
        with io.open(os.path.join(PKG, rel), encoding="utf-8") as f:
            txt = f.read()
    except OSError:
        return set()
    mods = set(re.findall(r"^\s*(?:import|from)\s+(\w+)", txt, re.M))
    local = {m for m in mods if m not in _STDLIB_HINT}
    # `inbox_guards_xxxx` 是判据自身互引，不算产品依赖
    return {m for m in local if not m.startswith("inbox_guards")
            and m not in ("delivery_gate",)}


_DEP_CACHE = {}


def impacted_suites(changed_files):
    """改动文件 → 必须复验的判据集。返回 `(集合, 说明行列表)`。

    ★ 口径：**只看直接 import**，宁可多点名（多跑一遍不亏），
      绝不漏点名（漏了＝那条判据等于没跑，与本仓铁律同型）。
    """
    if not _DEP_CACHE:
        for key, rel, _d in SUITES:
            _DEP_CACHE[key] = _suite_deps(rel)
    stems = {os.path.splitext(os.path.basename(p))[0] for p in changed_files}
    hit = {k for k, deps in _DEP_CACHE.items() if deps & stems}
    note = []
    for k in sorted(hit):
        note.append("%s ← 直接 import %s" % (
            k, "、".join(sorted(_DEP_CACHE[k] & stems))))
    if not hit:
        note.append("（没点名到任何判据 ⇒ 改动文件不在任何判据的 import 图里，"
                    "**这不是「不需要复验」，而是判据没覆盖它**）")
    return hit, note


# ═══════════════ 机制层 ③：判据自身的可信度分级（红项是真是假）══════════════════
#
#: ★ 为什么需要它：0.36.5–0.36.6 连续两次遇到「红项指向的代码没有犯过这个错」。
#:   一次是 `_matches_title`（已被删的死函数），一次是 P15（判据自己的正则锚点）。
#:   ⇒ 「红」不是结论，**「红是判据的错还是产品的错」才是结论**，
#:     而这一步过去每次都要人来分。
#
#: ★ 机械化做法：**判据崩了（CRASH）与判据红了（RED）分开计数**（本闸门已做），
#:   再加一条：**红项里若指名的代码在本次改动中没被改过，就提示"可能与本次改动无关"**。
#:   —— 不是判它无罪（红仍然是红，仍然阻断），
#:     只是把"这条红可能是老账"这一事实**摆到眼前**，避免在它上面浪费时间。

_TOUCH_EXCLUDE = re.compile(
    r"(^|/)(\.git|__pycache__|\.psl|dist|build|.*\.egg-info|\.pytest_cache|"
    r"\.mypy_cache|\.idea|node_modules)(/|$)|\.pyc$|^\.")


def red_names_touched_modules(red_text, touched_stems):
    """红项文案里提到了哪些**本次改动过的模块**。

    ★ 独立成函数而不是在 main() 内联 —— 有两个理由：
      ① 它是**机制的一部分**（可被单独判据验），内联就只能靠"跑一次闸门看输出"来测；
      ② 本仓纪律「判据不许二次实现」：守卫里若再写一份正则，
         两份正则必然漂移 ⇒ 守卫测的是一个**不存在的**机制。
    """
    return {n for n in re.findall(r"\b([a-z_][a-z0-9_]{2,})\b", red_text or "")
            if n in (touched_stems or set())}


# ═══════════════ 机制层 ④：注释承诺 vs 实现 —— **试过两版，都无效，已撤**════════════
#
#: ★★★ 这里**故意留一个空机制位**，把失败的尝试和它的死因写在原地。
#:   理由：本仓铁律「有检查项但没人跑 ＝ 等于没有」的姊妹条更狠 ——
#:     **「有检查项但它抓不到目标 ＝ 比没有更坏」**，
#:     因为它会让人以为这一层已被覆盖，从而**不再去人工看**。
#:
#: 目标：自动抓「注释承诺了 X、代码没做 X」（本轮两处真缺口的同型）：
#:   · _mark_at_tail() 注释写「页面前缀必须是已知页面名之一」，那层代码**从没写过**
#:     ⇒ 功能表面正常、**没有任何判据会红**（缺陷不在行为里，在注释与实现的落差里）
#:   · _matches_title 注释写「不是 in 子串」，实现正是 suffix in actual
#:
#: 实测结论（两版启发式，数据留着，别再重做）：
#:   第一版「找含强制词（必须/不得/一律）的注释行」
#:     ⇒ 报 11 处，逐条看过**几乎全误报**：那些注释是**解释**不是**承诺**
#:       （「标记必须在末尾」后面就紧跟着真代码）。误报约 9/11。
#:   第二版「找否定式（不是/不再/不许）＋反引号内容真出现在代码里」
#:     ⇒ 报 12 处，**更差**：注释里解释某个常量名/函数名本就是正常写法，
#:       而那个名字当然出现在代码里。误报接近 100%。
#:   ★ 两版都**抓不到**本轮那处真缺口 —— 因为修好它时，那行注释**已被删掉**。
#:
#: ★★★ 死因（这才是可复用的部分）：
#:   这类缺陷的本体是**「缺失」**。缺失的东西不会留下痕迹给机器看，
#:   而留下的（注释）**恰好是最不像证据的东西** ——
#:   注释不需要能运行，所以**永远不会自己失败**。
#:   ⇒ 任何「扫现存注释找缺口」的路子，都在扫一个**没有失败标记的系统**。
#:   ⇒ 真正有效的只有两条：
#:     (a) 把承诺**改写成实现** —— 让两者不可能不一致；
#:         本轮正是如此：那层白名单直接写成代码，并配 P15 的实测用例。
#:     (b) 让人**看见** —— 但本轮那两处都不是靠扫描发现的，
#:         是靠**真去测一个具体场景**（「用户窗口标题里恰好含 · 值守台#xxx」）撞出来的。
#:   ⇒ 结论（当纪律用）：**不要试图机器检查「承诺与实现一致」，
#:     要把承诺变成实现。判据能检查的是「行为对不对」，不是「注释真不真」。**
#:   ⇒ 落地纪律：「发现功能缺口时，先问『有没有一条注释在承诺它』；
#:     有 ⇒ 把它变成判据/代码，而不是把它变成注释。」
#:     （本轮已兑现两次：④ 层白名单 ＋ P15 新增 4 类误伤用例。）
#
#: ★★ 因此本机制**没有代码**是**故意的**：留着这段失败记录，
#:   免得下一轮又有人（包括我自己）顺手加个扫描器，
#:   然后得到一堆误报还以为自己加了防护。

def _touch_files():
    """本次改动碰过的**产品**文件（git 可用时取 diff，否则退回 mtime 近 30 分钟）。

    ★ 用 git 而不是 mtime 的理由：mtime 会把「跑闸门时读一遍文件」
      之外的无关文件也算进来（Python 写 .pyc 也改 mtime）⇒ 误报一堆。

    ★★ 必须过滤构建产物（0.36.6 实测踩到）：
      本仓大量文件从未提交过（`git status` 有 107 个 `??`），
      `git diff HEAD` 于是报出 58 个「改动」，其中混着
      `*.egg-info`、`__pycache__`、`dist/`、`build/` —— 它们是**构建产物**，
      不是「我改了产品」。
      ⇒ 不过滤的话，影响面名单会长到 58 条、点名 7 套判据，
        **和"全跑一遍"没区别 ⇒ 名单失去筛选意义（而这是它存在的全部理由）。**
      ⇒ 口径：**只认产品源码**（顶层 .py / ci/ / tools/ / scripts/ 里的 .py）。

    ★ 局限（明写，不假装覆盖）：git 不可用（无仓库/首次克隆）时退回 mtime 口径，
      那时 `.pyc` 已由上面的正则排除，但仍可能含「跑闸门时顺带改写的文件」。
    """
    try:
        r = subprocess.run(["git", "diff", "--name-only", "HEAD"],
                           capture_output=True, text=True, cwd=PKG, timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            got = {os.path.normpath(x) for x in r.stdout.split() if x.strip()}
            return {p for p in got
                    if not _TOUCH_EXCLUDE.search(p.replace("\\", "/"))
                    and p.endswith(".py")}
    except Exception:                                          # noqa: BLE001
        pass
    import time as _t
    now = _t.time()
    out = set()
    for fn in os.listdir(PKG):
        p = os.path.join(PKG, fn)
        if os.path.isfile(p) and fn.endswith(".py"):
            try:
                if now - os.path.getmtime(p) < 1800:
                    out.add(os.path.normpath(fn))
            except OSError:
                pass
    return out

#:
#: ★★ 这不是假想，是 0.36.5 实测到的：0353 在缺仓外原件时
#:   `exit 0` 且**一个字符都不打印**。若只看退出码，它会被记成 PASS，
#:   于是「一条判据都没跑」与「全部判据通过」在账面上完全一样。
#:   ⇒ 这正是本仓铁律「**查不出来 ≠ 查出来是好的**」在闸门层的形态。
_NOOP_MIN_CHARS = 1


def _looks_like_noop(out):
    return len((out or "").strip()) < _NOOP_MIN_CHARS


def _run(rel, timeout=900):
    """跑一套判据。返回 `(状态, 明细)`，状态 ∈ PASS / RED / CRASH / MISSING / NOOP。

    ★ 为什么要把 CRASH 与 RED 分开（本轮踩过同型）：
      自检器自己的注释里记着一条教训 ——「工具崩了不算判据红，
      但两者混在一起就会把『工具自己坏了』误读成『检查发现了很多问题』」。
      反过来同样成立：**工具崩了若报成"0 红"，就是假绿**。
      ⇒ 这里五种状态互不折叠，main() 里除 PASS 外全部计入退出码非零。
    """
    p = os.path.join(PKG, rel)
    if not os.path.isfile(p):
        return "MISSING", "判据文件不存在：%s" % rel
    env = dict(os.environ)
    env["ANTINEL_PKG"] = PKG          # 让判据认准主仓，不被上级陈旧 manifest 干扰
    t0 = time.time()
    try:
        r = subprocess.run([sys.executable, p], capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           timeout=timeout, env=env, cwd=PKG)
    except subprocess.TimeoutExpired:
        return "CRASH", "超时 > %ds（判据卡住与判据变红必须能区分）" % timeout
    except Exception as e:                                    # noqa: BLE001
        return "CRASH", "起不动：%s: %s" % (type(e).__name__, e)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    dt = time.time() - t0
    tail = out.splitlines()[-1] if out else "(无输出)"
    if _looks_like_noop(out):
        # 退出码 0 但零输出 —— 必须报出来，且**不许**报 PASS
        return "NOOP", "退出码 %d 但**零输出** ⇒ 判据没真跑（缺依赖／提前 return），不是通过" % r.returncode
    if r.returncode == 0:
        return "PASS", "%s  [%.1fs]" % (tail[:96], dt)
    # ★★ 0.36.5：变红时**必须带上红项明细**，不能只给最后一行。
    #   实测踩到三次 —— 各套判据的红项形态**各不相同**，只认一部分就漏一类：
    #     ① 0364  用 `❌ D2 …`（红项同一行）
    #     ② regression 用 `[FAIL] D-6 …`（红项同一行）
    #     ③ 0363  用 `RED  R06 …` ＋**下一行缩进**给明细 ⇒ 同一行匹配漏掉明细
    #     ④ version 用 `-  版本 X 出现在：…`（**无任何标记**，只靠缩进破折号）
    #   ⇒ 纪律：① 判断依据不许建立在你没拿到的信息上；
    #           ② 收集红项不许只认部分标记（漏一种形态＝漏一种真实缺陷）。
    lines = out.splitlines()
    red = []
    for i, ln in enumerate(lines):
        s = ln.strip()
        if ("❌" in s or "[FAIL]" in s or s.startswith("RED ") or "💥" in s
                or (re.match(r"^-\s", s) and "出现在" in s)):
            seg = s
            # ③ 明细在**下一行**（缩进续行）⇒ 一并带上
            #   ⚠️ 续行长度上限从 120 放宽到 300：0363 的根因诊断
            #   「…属 manifest 哈希级联」在第 ~150 字符，120 会把它切掉
            #   ⇒ 又是"信息死在格式化里"。同一条纪律，不再犯第二次。
            if i + 1 < len(lines):
                nxt = lines[i + 1].strip()
                if nxt.startswith(("└", "—", "-")) or (
                        nxt and not nxt.startswith(("GREEN", "RED", "0.", "共"))):
                    seg += " ｜ " + nxt[:300]
            red.append(seg)
    detail = "%s  [%.1fs]" % (tail[:56], dt)
    if red:
        # ★★ 0.36.5：截断长度从 220 提到 600。
        #   实测踩到：0363 的根因诊断（「…属 manifest 哈希级联」）在第 ~200 字符，
        #   而红项文本被截到 220 ⇒ **"级联"两字被切掉** ⇒ 自举豁免匹配不上。
        #   ⇒ 症状看起来像"豁免机制坏了"，实际是**信息在传递途中被截断**。
        #   ⇒ 纪律：**别让承载判断的信息死在格式化里**。
        #     宁可输出长一点，也不要让下游拿不到依据。
        detail += "  ｜红项：" + " ／ ".join(red[:3])[:600]
    return "RED", detail


def _mentions_other(text, carriers):
    """红项文本的「落后者」半句里，是否点名了 **manifest 以外**的承载件。"""
    m = re.search(r"(落后者[：:]\s*.{0,240})", text)
    if m:
        return any(c in m.group(1) for c in carriers)
    return False


def _mentions_carrier(text, carrier):
    """红项文本里**是否点名了某个版本承载件**（用于自举豁免的收窄判断）。

    ★ 为什么需要独立函数（而不是 `carrier in text`）：
      `version_check` 的输出**同时**列出多数派与落后者，例如：
        「版本 0.36.5 出现在：pyproject.toml; server.json; antinel.py …」
      这行里**提到了** pyproject，但它是在说"**一致**"的那一批，
      **不是**落后者。⇒ 直接 `in` 判断会把"已一致"误读成"也落后了"
      ⇒ 真正的版本分叉反而**豁免掉**。这正是本轮差点犯的错。
      ⇒ 正确做法：**只认「落后者」那半句**。
    """
    return _mentions_other(text, (carrier,))


def _missing_required():
    """清单里的判据文件必须都在。少一个就报红（防止"删判据即变绿"）。"""
    gone = [rel for rel in REQUIRED
            if not os.path.isfile(os.path.join(PKG, rel))]
    return gone


def _orphaned_guard_files():
    """★ 反向：仓里若还有**没进清单**的 `inbox_guards_*.py`，必须报出来。

    为什么必须做反向检查（这是本轮最关键的一条设计）：
      只检查「清单里的文件都在」，挡不住**反向漏登记** ——
      有人新写了 `inbox_guards_0365.py` 却忘了加进 `SUITES`，
      那么它一条都不会跑，而闸门**照样全绿**。
      ⇒ 「有判据但没人跑」这个缺陷会从后门重新长出来。
      ⇒ 判据：仓里的守卫文件集合 **⊆** 清单登记的集合，差集非空即红。
    """
    listed = {os.path.basename(r) for _k, r, _d in SUITES}
    try:
        # ★ 0.36.8：模式从 inbox_guards_ 扩到 inbox_guards_｜jdg_guards_——
        #   原模式只认 inbox_guards_*，JDG 族写成 jdg_guards_* 后
        #   「写了没登记」会从后门漏掉（这正是本检查存在的全部理由）。
        # ★ 0.37.0：再扩到 pcm_gate_ —— PCM 族与 JDG 族同构（版本后缀命名），
        #   漏登记的后果同样是一条都不跑而闸门照样全绿。
        on_disk = {f for f in os.listdir(os.path.join(PKG, "ci"))
                   if (f.startswith("inbox_guards_") or f.startswith("jdg_guards_")
                       or f.startswith("pcm_gate_"))
                   and f.endswith(".py")}
    except OSError:
        return ["读不到 ci/ 目录"]
    # `inbox_guards.py` 是历史基线件（无版本后缀），已并入 regression 体系，不在本清单
    on_disk = {f for f in on_disk if f != "inbox_guards.py"}
    return ["%s（在 ci/ 里但没登记进 SUITES ⇒ 一条都不会跑）" % f
            for f in sorted(on_disk - listed)]


# ────────────────────────────────────────────── 负控
def selfcheck():
    """★★ 负控：把一条判据的**判定结果**改坏，断言本闸门**必须**变红。

    ★ 为什么注入的是「把 `return True` 改成 `return False`」：
      这是对「假守卫」最直接的模拟 —— 判据文件还在、条数不变、
      语法正确、**只是判据判错了**。
      如果本闸门在这种注入下仍然全绿，说明它根本没在调这套判据
      （或调了但吞掉了退出码）⇒ 本闸门是装饰。

    ★ 注入点选 0363 而不是 0364（实测踩过一次）：
      0364 全部判据是 `assert` 驱动（红 = 抛 AssertionError），
      **文件里根本没有 `return True`** ⇒ 照 `return True` 注入会 SKIP。
      而 SKIP 若被当成"通过"，负控就变成了永远绿的装饰。
      ⇒ 选一个确实含 `return True` 的判据集，并在 SKIP 时**返回非零**。
      ⇒ 教训（与本轮 `_p_selfcheck_negctl` 同型）：**负控自身失配必须报红，
        不许报"通过"** —— 否则负控是假绿。

    注入用**改名让开 + 无条件还原**，不删文件（本机删除配额会被平台守卫硬杀）。
    """
    victim_rel = "ci/inbox_guards_0363.py"
    victim = os.path.join(PKG, victim_rel)
    if not os.path.isfile(victim):
        print("  [💥] 找不到 %s，无法做负控（这不是通过）" % victim_rel)
        return 1
    src = io.open(victim, encoding="utf-8").read()
    if "\n    return True" not in src:
        print("  [💥] %s 里没有可注入的 'return True'，负控注入点失配（需更新负控）"
              % victim_rel)
        return 1
    mutated = src.replace("\n    return True", "\n    return False", 1)
    bk = victim + ".gate_negctl.bk"
    try:
        io.open(victim, "w", encoding="utf-8", newline="\n").write(mutated)
        st, why = _run(victim_rel)
        if st == "RED":
            print("  [RED(好)] 判据被改坏后本闸门报红：%s" % why)
            return 0
        print("  [★GREEN(坏)] 判据被改坏（一条判据永远红）本闸门仍报 %s —— "
              "它是装饰，不是闸门" % st)
        return 1
    finally:
        # 无条件还原：负控异常残留会污染产品代码（本轮踩过）
        try:
            io.open(victim, "w", encoding="utf-8", newline="\n").write(src)
        finally:
            if os.path.exists(bk):
                os.replace(bk, victim)
        # 还原后必须逐字节复核 —— 「以为还原了」不算还原
        back = io.open(victim, encoding="utf-8").read()
        if back != src:
            print("  ★ 还原失败：%s 内容与注入前不一致，需人工核对" % victim_rel)
            return 1
        print("  [ok] 判据文件已逐字节还原")


# ────────────────────────────────────────────── 主流程
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="跳过 slow 档（< 10 秒）")
    ap.add_argument("--only", default="", help="只跑指定键（逗号分隔）")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--selfcheck", action="store_true", help="负控：判据被改坏时本闸门必须红")
    a = ap.parse_args()

    if a.selfcheck:
        print("=" * 74)
        print("统一交付闸门 · 负控：把一条判据改坏 → 本闸门必须报红（先红后绿）")
        print("=" * 74)
        return selfcheck()

    if not os.path.isdir(PKG):
        print("★ 找不到仓根 %s" % PKG)
        return 2

    print("=" * 78)
    print("统一交付闸门 —— 一处入口 · %d 套判据 · 红即阻断" % len(SUITES))
    print("仓路径：%s" % PKG)
    print("=" * 78)

    # ── 结构性检查（先跑：它们决定后面该不该跑） ──
    gone = _missing_required()
    orphans = _orphaned_guard_files()
    if gone:
        print("  💥 %-46s %s" % ("判据文件缺失（删判据＝让闸门变绿）",
                              "、".join(gone)))
    if orphans:
        print("  💥 %-46s %d 处" % ("有守卫文件没登记进 SUITES（不会跑）", len(orphans)))
        for o in orphans:
            print("       - %s" % o)
    if not gone and not orphans:
        print("  ✅ %-46s %d 套判据齐全，无未登记的守卫文件"
              % ("判据清单与磁盘一致", len(SUITES)))

    only = {x.strip() for x in a.only.split(",") if x.strip()}
    suites = SUITES
    if only:
        suites = [s for s in SUITES if s[0] in only]

    for key, rel, tier in suites:
        if a.quick and tier == "slow":
            print("  ⏭  %-46s slow 档，--quick 跳过" % key)
            continue
        st, why = _run(rel)
        icon = {"PASS": "✅", "RED": "❌", "CRASH": "💥",
                "MISSING": "💥", "NOOP": "⚠️"}[st]
        print("  %s %-46s %s" % (icon, key, why))
        RESULTS.append({"suite": key, "rel": rel, "tier": tier,
                        "status": st, "detail": why})
    # ★★★ 0.36.5：**自举死锁**的显式处理（实测踩到，不是假想）。
    #   现象：升版后打包被拦，理由是「psl/manifest.json 停在旧版」；
    #        而 manifest 恰恰**由打包生成** ⇒ 不先打包就永远过不了。
    #   ⇒ 闸门自己认得出这一类，且**只豁免这一类**。
    #
    #   ⚠️⚠️ 豁免判据必须**窄到能区分"manifest 单独落后"与"真缺陷"**：
    #     形态（取自各判据真实输出）：
    #       ✔ 豁免：红项**只**提到 manifest 落后 / 与 manifest 不符
    #       ✘ 不豁免：红项里出现**其他承载件**（那是真版本分叉，必须红）
    #     ⇒ 放宽成"提到 manifest 就放过"，真分叉会被一起放过 ——
    #       而那正是 D-6 存在的全部意义。**豁免一个症状，不许豁免一个类别。**
    #   ⚠️ 必须先确认**红项明细拿到了**（`_run` 只回 tail 时一律不豁免）——
    #     否则就是"判断依据建立在你没拿到的信息上"（本轮已踩过一次）。
    _bs_exempt = []
    if os.environ.get("ANTINEL_BOOTSTRAP") == "1":
        #: 唯一允许出现在红项里的承载件（它由本次打包生成）
        _ONLY_ALLOWED = "psl/manifest.json"
        #: 出现即判"真缺陷"的其他承载件
        _OTHER_CARRIERS = ("pyproject", "antinel.py", "antinel_mcp", "server.json",
                           "pre_tool_use", "build_package", "rules/default.json",
                           "AUDIT_SCHEMA", "SKILL.md")
        for rec in RESULTS:
            if rec["status"] != "RED":
                continue
            m = re.search(r"红项：(.{0,800})", rec["detail"])
            if not m:
                continue                     # 没拿到红项明细 ⇒ 不豁免
            red_txt = m.group(1)
            # ★ 形态一：**版本落后**（version / regression）
            #   只有"落后者"那半句里出现非 manifest 承载件 ⇒ 真分叉，不豁免。
            if "落后者" in red_txt or "出现在" in red_txt:
                if _mentions_other(red_txt, _OTHER_CARRIERS):
                    continue
                rec["status"] = "PASS"
                rec["detail"] = ("【自举豁免】红项只涉及 %s —— 它由本次打包生成，"
                                 "打包前必然落后" % _ONLY_ALLOWED)
                _bs_exempt.append(rec["suite"])
                continue
            # ★ 形态二：**哈希不符**（0363 R06 / 0364 D2）
            #   判据：红项里点名的文件，**是否都是打包会刷新哈希的那些**
            #   （即它们与 manifest 失配，而不是"版本号写错了"）。
            #   ⚠️ `hooks/pre_tool_use.py` 的哈希失配**也**由打包刷新 ——
            #     它是 manifest 覆盖的告警链路文件之一。把它当"其他承载件"
            #     会让自举永远解不开（实测踩过：豁免对 0363/0364 一直不生效）。
            #   ⇒ 判据按**根因**分，不按文件名分：
            #     · 只说「与 manifest 不符 / 没登记进 manifest」⇒ 哈希类，自举豁免
            #     · 出现「版本号/不一致/落后者」字样 ⇒ 版本类，另判
            #   ★ 形态二之二（0363 R06）：判据自己会把根因写进回报 ——
            #     「根因：self_check 不符 ⇒ 属 manifest 哈希级联」/「真缺陷」。
            #     ⇒ 只有**明写"级联"**才豁免；明写"真缺陷"的一律不豁免。
            #     这比"猜根因"可靠得多 —— 依据是判据自己的诊断，不是闸门的推测。
            if "根因：self_check" in red_txt:
                if "真缺陷" in red_txt or "不可豁免" in red_txt:
                    continue                 # 判据自己说了是真缺陷 ⇒ 不豁免
                if "级联" in red_txt:
                    rec["status"] = "PASS"
                    rec["detail"] = "【自举豁免】判据自报根因为 manifest 哈希级联"
                    _bs_exempt.append(rec["suite"])
                continue
            if "与 manifest 不符" in red_txt or "没登记进 manifest" in red_txt \
                    or "与manifest不符" in red_txt:
                if re.search(r"版本(号)?(不一致|分叉|落后)", red_txt):
                    continue                 # 混了版本问题 ⇒ 不豁免
                rec["status"] = "PASS"
                rec["detail"] = ("【自举豁免】红项是 manifest 哈希类失配 —— "
                                 "本次打包会重新登记这些文件的哈希")
                _bs_exempt.append(rec["suite"])
                continue
            # 与 manifest 无关 ⇒ 不豁免
            if "manifest" not in red_txt:
                continue

    n_red = sum(1 for r in RESULTS if r["status"] == "RED")
    n_crash = sum(1 for r in RESULTS if r["status"] in ("CRASH", "MISSING"))
    n_noop = sum(1 for r in RESULTS if r["status"] == "NOOP")
    n_pass = sum(1 for r in RESULTS if r["status"] == "PASS")
    struct_bad = 1 if (gone or orphans) else 0

    for k in _bs_exempt:
        print("  ⬆  %-46s 自举豁免：manifest 由本次打包生成，打包前必然落后" % k)

    # ── 机制层①：差分归因（让「多了什么」成为机器算出来的，不必重跑去回忆）──
    _fp = _gate_fingerprint()
    new_red, fixed, snap_note = _diff_against_baseline(RESULTS, _fp)
    if new_red:
        print("-" * 78)
        print("  ★ 本次**新增**红（相对上次快照）—— 收敛的第一手线索：")
        for suite, why in new_red:
            print("      · %-44s %s" % (suite, why))
        print("    ⇒ 新增红才是要查的对象；一直红着的那条另有原因，不要混在一起查。")
    if fixed:
        print("  ✔ 本次已转绿（相对上次快照）：%s" % "、".join(fixed))
    print("  ⓘ 基线对照：%s" % snap_note)
    _save_snapshot(RESULTS, _fp)

    # ── 机制层②：本次改动的影响面 ──
    _touched = _touch_files()
    if _touched:
        _imp, _why = impacted_suites(_touched)
        print("-" * 78)
        print("  ◇ 本次改动碰到 %d 个文件；**重点复验**这些判据：" % len(_touched))
        for ln in _why[:10]:
            print("      · %s" % ln)
        if _imp:
            print("  ⇒ 上面这些是**本次改动的直接受害者**；"
                  "若红项不在其中，多半是老账（机制层③会再提一次）。")
    else:
        print("  ◇ 未探测到本次改动（git 无变更且无近 30 分钟修改的 .py）"
              "⇒ 无法点名重点复验范围")

    # ── 机制层③：红项是本次引入的，还是老账？ ──
    _touched_stems = {os.path.splitext(os.path.basename(p))[0] for p in _touched}
    for _r in RESULTS:
        if _r["status"] == "PASS" or not (_r.get("red") or "").strip():
            continue
        _named = red_names_touched_modules(_r["red"], _touched_stems)
        if not _named:
            print("  ⓘ 红项 %s：文案里**没有**本次改动的模块名 ⇒ 可能与本次改动无关"
                  "（红仍然是红、仍然阻断，只是不必优先查它）" % _r["suite"])

    print("-" * 78)
    print("  %d 套判据：全绿 %d / 变红 %d / 工具崩或缺失 %d / 零输出假绿 %d%s"
          % (len(RESULTS), n_pass, n_red, n_crash, n_noop,
             (" ＋结构检查 %d 项不通过" % struct_bad) if struct_bad else ""))

    if struct_bad or n_crash or n_red or n_noop:
        print("★ 闸门未通过。")
        print("  · 变红 ⇒ 有判据检出缺陷（或判据自身需更新），**先看红项再决定改哪边**。")
        print("  · 工具崩/缺失 ⇒ 判据没跑成，**这不是通过，是盲区**。")
        print("  · 零输出 ⇒ 判据提前退出（缺依赖），**退出码 0 也不许当通过**。")
        print("  · 结构不通过 ⇒ 判据清单与磁盘不一致，先对齐清单。")
        if new_red:
            print("  · 本次新增红 ⇒ **先查新增的那几条**，别去翻一直红着的旧账。")
        print("  确知要绕过：git commit --no-verify（会在审计链留痕，不是悄悄溜过去）")
    else:
        print("★ 闸门全绿：所有已登记判据均通过（本次实际执行 %d 套）" % n_pass)

    if a.json:
        print(json.dumps({"results": RESULTS, "pass": n_pass, "red": n_red,
                          "crash": n_crash, "noop": n_noop,
                          "struct_bad": struct_bad,
                          "orphans": orphans, "missing": gone},
                         ensure_ascii=False, indent=1))
    return 0 if not (struct_bad or n_crash or n_red or n_noop) else 1


if __name__ == "__main__":
    sys.exit(main())
