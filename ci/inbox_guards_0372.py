#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.37.3 判据 —— **六态封闭** ＋ **已敲定的词表不再漂移**。

★★ 这一份判据是创始人 2026-10-09 那三句「一定要机制上解决」的直接产物：

    「监理状态是 LOGO 五态加上开发态一共六态，这个要从机制上钉死，
      不要再杜撰其他什么态，一定要机制上解决，机制上解决，机制上解决。
      其他类似地方，敲定的内容，就不要再发生漂移，也是要从机制上解决，
      机制上解决，机制上解决。」

  ⇒ 过去的做法是**把结论写在注释里**，然后指望每一轮（可能是另一个模型、
    另一个上下文）都记得它。实测这条路走不通：0.36.0–0.36.4 之间，"8 个派生
    灯态"（失守/中断·无损失/存疑/研发中/值守中·需你处理/值守中/未启用/查不到）
    就是**AI 自己长出来的**，没有一条判据看得见它们。
  ⇒ 本文件把三件事从"注释里的约定"变成"可执行、会报红、有负控的机制"：
    ① 六态是**闭集**：多一个少一个都报红（S01/S02）；
    ② 状态词是**封闭词表**：杜撰的词进不了用户面（S03/S04）；
    ③ 敲定的分工是**单源**：监理唯一角色、护盾只能作为它的工具出现一处、
       顶部灯的说明只能由 `light_explain()` 拼（S05/S06/S07）；
    ④ 六态**名**与**次序**也单源：名只能在 `inbox_model.py` 定义一份、
       其余模块一律派生（S08）；次序量的是「离终结有多近」（S09）。
    ⑤ 2026-10-21（STE100 体检 S-03）补：**灯态词与事件词是两个真源** ——
       前者只描述此刻（`state_short`），后者数过去的事（`event_short`），
       R0/L2/L1 两表的值不许重叠（S08 的第二/第三腿）。

★★ 本文件的编写纪律（沿用本仓惯例）：
  · **每条判据都配负控**：把被测的机制故意改坏，判据必须报红。
    没有负控的判据只是一段会执行的代码。
  · **判据只查行为**：真跑产品函数、真渲染页面；不靠正则去猜源码意图。
  · ★★★ **本文件绝不写盘**（不改任何产品文件）。
    理由（0.36.5 的教训）：会临时改坏产品文件的负控**不能进打包前的闸门** ——
    打包进程中途被杀/断电，变异的代码会随包发出去。
    ⇒ 本文件的负控全部走**内存变异 + 还原**（monkeypatch / 属性替换），
      因此它可以安全地留在 `--quick` 都会被跑到的 fast 档。
"""
from __future__ import annotations

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import tmpreg as _TMP   # 0.55.0 (F3): temp dir registry
import os
import re
import sys
import html as _H
import io
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

RESULTS = []


def check(name):
    def deco(fn):
        RESULTS.append((name, fn))
        return fn
    return deco


# ══════════════════════════════════════════════ C2 闭合性（2026-10-22）═════
# 完备性的三种含义里，只有「合同完备」与「闭合完备」能做到（见
# docs/Antinel·盲区生成器与完备性方法 v1.0 §2）。C2 守的是第三种：
#   **域外输入不许被静默映射成「正常」** —— 必须具名落到「不安全」。
#
# ★ 为什么这条要有：`light("banana")` 曾返回 ok（0.36.3 的教训写在 S02 的注释里），
#   而 2026-10-22 又实测到同形状的四处：`_logo_mark` 的 `LOGO_MODE.get(state,"L0")`
#   与托盘三处 `... else "L0"` —— 未知态被画成「值守中」。
#   两件事同因：**默认分支返回的是「正常」**。
#
# ★ 覆盖形状（两种，写清楚比声称"全覆盖"有用）：
#     ① `X if cond else "L0"`（三元）
#     ② `d.get(k, "L0")`（两参数 get）
#   不覆盖 `else:` 语句块 —— 它会与"显式写了 else 的正常分支"混淆，
#   误报率高到没人会看。残余如实记在文件末尾的"已知不覆盖"里。

def _c2_normal_tokens(M):
    """「正常」的取值**从产品真源派生**，不写死 —— 否则改词后判据会静默失效。"""
    k = M.STATE_L0
    return {k}, {M.STATE_LABEL[k]}


def _c2_surface():
    """扫描面**派生**自 `pyproject.toml` 的 `py-modules`（与打包清单同源）。"""
    import re as _re
    p = os.path.join(ROOT, "pyproject.toml")
    txt = io.open(p, encoding="utf-8").read()
    m = _re.search(r"py-modules\s*=\s*\[(.*?)\]", txt, _re.S)
    if not m:
        _raise("pyproject.toml 里找不到 py-modules —— 扫描面派生失败，判据不能瞎猜")
    names = _re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"', m.group(1))
    out = []
    for nm in names:
        fp = os.path.join(ROOT, nm + ".py")
        if os.path.exists(fp):
            out.append(fp)
    return out


def _c2_scan_src(src, keys, words):
    """扫一段源码，返回 [(shape, lineno, 值)]。纯函数，负控直接喂源码。"""
    import ast as _ast
    try:
        tree = _ast.parse(src)
    except SyntaxError:
        return [("unparsable", 0, "")]
    normal = set(keys) | set(words)
    hits = []

    def _is_normal(node):
        return (isinstance(node, _ast.Constant)
                and isinstance(node.value, str) and node.value in normal)

    for n in _ast.walk(tree):
        if isinstance(n, _ast.IfExp) and _is_normal(n.orelse):
            hits.append(("else", n.lineno, n.orelse.value))
        if (isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
                and n.func.attr == "get" and len(n.args) == 2
                and not n.keywords and _is_normal(n.args[1])):
            hits.append(("get-default", n.lineno, n.args[1].value))
    return hits


def _c2_scan_all(surface=None):
    import inbox_model as M
    keys, words = _c2_normal_tokens(M)
    files = _c2_surface() if surface is None else surface
    bad = []
    for fp in files:
        try:
            src = io.open(fp, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        for shape, ln, val in _c2_scan_src(src, keys, words):
            bad.append("%s:%d［%s］→ %r"
                       % (os.path.basename(fp), ln, shape, val))
    return bad, len(files)


@check("C2-0372 默认分支具名：域外输入不许被静默映射成『正常』")
def c2():
    bad, n = _c2_scan_all()
    if bad:
        _raise("%d 处把未知/域外值映射成『正常』（默认分支必须具名不安全）：%s"
               % (len(bad), "；".join(bad[:6])))
    return "扫描面 %d 模块（派生自 py-modules），0 处默认落到「值守中」" % n


@check("N-C2-0372 负控：三元/ get 两形状各必红、具名不安全与显式分支必绿")
def n_c2():
    import inbox_model as M
    keys, words = _c2_normal_tokens(M)

    BAD = ("def f(state):\n"
           "    a = state if state in ('L0','L1') else 'L0'\n"      # ① 三元兜底
           "    b = {'L0': 'L0'}.get(state, 'L0')\n"                 # ② get 默认
           "    c = {'L0': 'L0'}.get(state, '值守中')\n")            # 词形同样要抓
    GOOD = ("def f(state):\n"
            "    a = state if state in ('L0','L1') else 'L1'\n"      # 落到「注意」
            "    b = {'L0': 'L0'}.get(state) or 'L1'\n"             # 无默认
            "    if state == 'L0':\n"                               # 显式分支不误报
            "        return 'L0'\n"
            "    return 'L1'\n")
    hb = _c2_scan_src(BAD, keys, words)
    hg = _c2_scan_src(GOOD, keys, words)
    if len(hb) != 3:
        _raise("负控失效：坏夹具应命中 3 处（三元＋get＋词形），实际 %d 处" % len(hb))
    if hg:
        _raise("负控误报：好夹具不该命中，实际 %d 处 %r" % (len(hg), hg))
    return "坏夹具命中 3 处（两种形状＋词形），好夹具 0 处（含显式分支不误报）"


# ══════════════════════════════════════════════ C3 吞咽登记（2026-10-22）═════
# 「吞掉」不是错，**没人写下吞掉之后世界变成什么样**才是错。
# 三条腿，缺一条整条判据就是摆设：
#   ① 未登记即红 —— 新加一个 `except: pass` 必须有人回答"失败了我当什么"；
#   ② 死登记即红 —— 代码改好了，簿里那条必须删（否则簿会变成"历史欠账展览"）；
#   ③ 面不许无声扩大 —— 不在 SCOPE 里的模块必须在 TODO 里挂账。
# 簿本体在 ci/_c3_swallow_ledger.py（键、策略、逐条后果都在那里）。


def _c3_key(func, ordinal, exc, body_src):
    """与 `ci/_c3_swallow_ledger.py` 头部写明的构造逐字一致。"""
    import hashlib as _hl
    raw = (exc + "\x00" + body_src).encode("utf-8")
    return "%s::%d::%s" % (func, ordinal, _hl.sha1(raw).hexdigest()[:6])


def _c3_sites(src):
    """返回 [(key, lineno, func)]：本段源码里所有**吞掉**型异常处理点。

    「吞掉」＝处理体只有**一条**语句，且是 `pass` / `continue` / `return <默认值>`。
    处理体有两条以上的不在本判据范围内（那是"做了点什么"，需要人读，机器判不了）——
    这条边界如实写在登记簿头部，不许假装覆盖。
    """
    import ast as _ast
    try:
        tree = _ast.parse(src)
    except SyntaxError:
        _raise("C3 扫描面里有解析不了的源码 —— 判据不能靠猜")
    lines = src.splitlines()
    out = []
    counter = {}

    def walk(node, func):
        for ch in _ast.iter_child_nodes(node):
            nm = ch.name if isinstance(ch, (_ast.FunctionDef, _ast.AsyncFunctionDef)) else func
            if isinstance(ch, _ast.ExceptHandler):
                counter[nm] = counter.get(nm, 0) + 1
                bd = "\n".join(l.strip() for l in
                               lines[ch.body[0].lineno - 1: ch.body[-1].end_lineno])
                et = _ast.unparse(ch.type) if ch.type is not None else "*"
                one = len(ch.body) == 1
                swallow = one and isinstance(ch.body[0], (_ast.Pass, _ast.Continue))
                ret0 = (one and isinstance(ch.body[0], _ast.Return)
                        and (ch.body[0].value is None
                             or (isinstance(ch.body[0].value, _ast.Constant)
                                 and ch.body[0].value.value in (None, False, 0, ""))))
                if swallow or ret0:
                    out.append((_c3_key(nm, counter[nm] - 1, et, bd), ch.lineno, nm))
            walk(ch, nm)

    walk(tree, "<module>")
    return out


def _c3_ledger():
    import importlib.util as _iu
    fp = os.path.join(ROOT, "ci", "_c3_swallow_ledger.py")
    if not os.path.exists(fp):
        _raise("登记簿不见了：ci/_c3_swallow_ledger.py")
    spec = _iu.spec_from_file_location("_c3_ledger", fp)
    mod = _iu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _c3_audit(sources, ledger_keys):
    """(未登记, 死登记)。sources = [(名字, 源码)]。纯函数，负控直接喂。"""
    found = {}
    for name, src in sources:
        for key, ln, fn in _c3_sites(src):
            found[key] = "%s:%d %s" % (name, ln, fn)
    unreg = ["%s（%s）" % (k, found[k]) for k in found if k not in ledger_keys]
    dead = [k for k in ledger_keys if k not in found]
    return unreg, dead


def _c3_sources(mods=None):
    L = _c3_ledger()
    names = list(L.SCOPE) if mods is None else list(mods)
    out = []
    for nm in names:
        fp = os.path.join(ROOT, nm)
        if not os.path.exists(fp):
            _raise("SCOPE 里的模块不存在：%s ⇒ 扫描面在缩水" % nm)
        out.append((nm, io.open(fp, encoding="utf-8", errors="ignore").read()))
    return out


@check("C3-0372 吞咽登记：未登记即红 ＋ 死登记即红 ＋ 面不许无声扩大")
def c3():
    L = _c3_ledger()
    srcs = _c3_sources()
    unreg, dead = _c3_audit(srcs, set(L.LEDGER))
    if unreg:
        _raise("%d 处吞掉没有登记（谁都得回答'它失败时我当什么'）：%s"
               % (len(unreg), "；".join(unreg[:5])))
    if dead:
        _raise("%d 条死在簿里（代码已改，登记必须跟着删）：%s"
               % (len(dead), "；".join(dead[:5])))
    # 面不许无声扩大：py-modules 里每个含"吞掉"的模块，必须在 SCOPE 或 TODO 里
    import ast as _ast
    missing = []
    for fp in _c2_surface():
        nm = os.path.basename(fp)
        if nm in L.SCOPE or nm in L.TODO:
            continue
        try:
            if _c3_sites(io.open(fp, encoding="utf-8", errors="ignore").read()):
                missing.append(nm)
        except AssertionError:
            missing.append(nm + "（解析失败）")
    if missing:
        _raise("这些模块有吞掉、却既不在 SCOPE 也不在 TODO（不许无声漏掉）：%s"
               % "、".join(missing))
    n_sites = sum(len(_c3_sites(src)) for _nm, src in srcs)
    return ("登记 %d 条 / 实测 %d 处，无未登记、无死登记；TODO 挂账 %d 个模块"
            % (len(L.LEDGER), n_sites, len(L.TODO)))


@check("N-C3-0372 负控：新加一处吞掉必红、簿里留一条死登记必红")
def n_c3():
    L = _c3_ledger()
    srcs = _c3_sources()
    keys = set(L.LEDGER)

    # ① 未登记腿：在真源码末尾追加一个没人登记过的 `except: pass`
    inj = srcs[0][1] + ("\n\ndef _probe_c3_unregistered():\n"
                        "    try:\n        pass\n"
                        "    except Exception:\n        pass\n")
    # ★★ 2026-10-22：`SCOPE` 从 1 个模块扩到 2 个（加入 `egress.py`）时，
    #   这条负控**当场失效** —— 它只审计 `srcs[0]`，而 `keys` 是全部登记，
    #   于是另一个模块的 14 条全变成"死登记"（实际 1/14，报错说负控①失效）。
    #   这不是负控写错，是**判据假设了"面只有一个模块"**。
    #   ⇒ 注入只改第一个模块，审计仍走**全部**源码。
    unreg, dead = _c3_audit([(srcs[0][0], inj)] + srcs[1:], keys)
    if len(unreg) != 1 or dead:
        _raise("负控①失效：注入一处未登记吞掉，应得 1 未登记 0 死登记，实际 %d/%d"
               % (len(unreg), len(dead)))

    # ② 死登记腿：簿里多出一条代码里根本不存在的键 ⇒ 必须报死登记
    #    （注意：删掉一条登记是"未登记"腿，不是"死登记"腿 —— 我第一次写反了，
    #      负控当场把我抓出来。两条腿各打各的变异，才叫各打各的。）
    unreg2, dead2 = _c3_audit(srcs, keys | {"__probe_c3__::0::ffffff"})
    if unreg2 or len(dead2) != 1:
        _raise("负控②失效：多一条不存在的登记应得 0 未登记 1 死登记，实际 %d/%d"
               % (len(unreg2), len(dead2)))

    # ③ 干净样本必须全绿（否则判据只会天天红）
    unreg3, dead3 = _c3_audit(srcs, keys)
    if unreg3 or dead3:
        _raise("负控③失效：现行树本该全绿，实际 未登记%d 死登记%d" % (len(unreg3), len(dead3)))
    return "注入一处未登记 ⇒ 1 红；多一条假登记 ⇒ 1 红；现行树 ⇒ 0/0"


# ══════════════════════════════════════════════════════════ 真源常量 ══════════
#: ★ 六态，**逐字**（创始人：LOGO 五态 ＋ 开发态）。判据自己写死一份，
#:   **故意不 import `inbox_model` 取它** —— 若两边都取自同一个常量，
#:   那么"有人把 inbox_model 里的六态改成七态"时，判据会跟着变，等于没守。
#:   写死在这里，两边不一致就报红。
SIX_STATES = ("R0", "L2", "L1", "Ls", "L0", "dev")
SIX_LABELS = {"R0": "失守", "L2": "拦截", "L1": "注意",
              "Ls": "缺粮", "L0": "值守中", "dev": "研发中"}
#: L0 的灰变体（未启用与值守中同属 L0，差别只在"有没有在守"）。
L0_VARIANT = "未启用"

#: 条目状态机（`inbox_model.STATES`）—— **不是**灯态。0.37.1 曾把六态集合
#: 命名成 `STATES` 覆盖掉它，页面上所有「知道了/忽略」按钮静默失效。
ITEM_STATES = ("unread", "read", "done", "ignored")

#: ★ 禁用词表。这些词**不许出现在用户看得见的正文里**（`<details>` 里的
#:   术语释义除外 —— 那是定义本身，护盾要在那里说明"我是工具"）。
#:   每一项都写明它为什么被禁，避免下一轮有人"觉得这词挺好"又加回来。
BANNED_IN_CHROME = {
    "存疑": "8 态灯时代 AI 自造的派生态；创始人 2026-10-07「计划外状态，不允许」",
    "门闸": "记录层的历史写法（链记录原文不改写）；人类面一律用「监理」",
    "护盾": "它是监理手里的**工具**，不是并列角色；只许在 `sentinel` 词条里出现",
    "查不到": "8 态灯时代的派生状态词；盲区现在的说法是「注意」",
    "中断·无损失": "把两件事挤进一个标签；姿态词现在是「中断」",
    "需你处理": "8 态灯时代的派生状态词；现在是「要处理」（分档词，不是灯态）",
}

#: 术语正文里也**一律不许**出现的词（比上面更窄：`护盾` 在 `sentinel` 词条里
#: 是必须出现的，所以不能进这一张表）。
BANNED_IN_TERMS = ("存疑", "查不到", "中断·无损失", "需你处理")


# ══════════════════════════════════════════════════════════ 工具 ══════════
def _strip_details(html_text):
    """剥掉**所有** `<details>`（术语词条/词表）—— 得到"正文"。

    ★ 口径沿用 `0360` 的 W06：`<details>` 默认收起＝要点开才看得见，
      因而不算"堆在界面上的正文"。本判据关心的正是"不点开也躲不掉的字"。
    ★ 必须用**平衡匹配**的剥离器，不能只删开合标签：
      `chip()` 生成的 details **内部还嵌着** `<div class="tdef">` 与 `<b>`，
      只删标签会把词条正文留在原地（那正是被禁的词藏身之处）。
    """
    html_text = re.sub(r"<script\b.*?</script>", "", html_text or "", flags=re.S)
    html_text = re.sub(r"<style\b.*?</style>", "", html_text, flags=re.S)
    out, i, n = [], 0, len(html_text)
    while i < n:
        j = html_text.find("<details", i)
        if j < 0:
            out.append(html_text[i:])
            break
        out.append(html_text[i:j])
        depth, k = 0, j
        while k < n:
            m = re.compile(r"<details\b|</details>").search(html_text, k)
            if not m:
                k = n
                break
            if m.group(0).startswith("</"):
                depth -= 1
                k = m.end()
                if depth == 0:
                    break
            else:
                depth += 1
                k = m.end()
        i = k
    text = "".join(out)
    text = re.sub(r"<[^>]+>", " ", text)
    return _H.unescape(text)


def _pkg_root():
    import inbox_server as SV
    return SV._pkg_root()


def _posture_cases():
    """★ 用**真 `guard_posture()`** 造出全部八个姿态（每个带它自己的 `why`）。

    ★★ 为什么必须"真跑"而不是自己编八个 dict（这是本判据的关键）：
      被禁的词恰好藏在 `guard_posture()` 的**返回文案**里，而那些文案只有在
      对应分支被走到时才生成（例：「防护开着，但监理进程不在岗」只在缺岗时）。
      自己编 dict ⇒ 判据永远看不到真实分支的文案 ⇒ 又一次"对不存在的缺陷做检查"。
    ★ 只替换**被探值**（在不在岗/心跳/自检/后果），不替换分支逻辑本身。
    ★ 全部在内存里做，结束无条件还原；不碰盘。
    ★ `blind`（0.48.5 A1）：进程在岗但**读不到心跳链** ⇒ 必须落 unknown
      （盲区），不许滑进缺岗分支的 interrupted/down。想造这个现场，注入
      `hb=(None, None) + up=None`（age 读不到、启动时刻也超出判死窗）。
    """
    import host_shield as HS
    names = ("armed_state", "sentinel_alive", "sentinel_heartbeat_age",
             "_sentinel_uptime", "self_check", "_outage_consequences",
             "is_dev_build", "load_state")
    saved = {k: getattr(HS, k, None) for k in names}
    iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    cases = [
        ("off",         dict(armed=False)),
        ("guarding",    dict()),
        ("dev",         dict(sc=(False, ["MUTANT: 判据自造的哈希不符"]), dev=(True, "代码比登记新"))),
        ("warn",        dict(sc=(False, ["MUTANT: 判据自造的哈希不符"]), dev=(False, ""))),
        ("interrupted", dict(alive=False, cons=[])),
        ("down",        dict(alive=False, cons=[{"text": "（判据注入的损失示例）"}])),
        ("unknown",     dict(load_raises=True)),
        # blind 的**期望姿态**是 unknown，但现场与上面那条不同（那条是探针抛错）：
        # 这里进程在岗、只是读不到心跳链 —— 0.48.5 A1 修的就是"把它误渲成红"。
        ("blind",       dict(alive=True, hb=(None, None), up=None, want="unknown")),
    ]
    out = []
    try:
        for name, st in cases:
            # ★ 每个替身都用 `_st=st` 默认参数**绑住当前这一轮**的注入值 ——
            #   否则闭包会全部指向循环结束后剩下的那一个（本轮第一次就踩到）。
            HS.armed_state = lambda *a, _st=st, **k: _st.get("armed", True)
            HS.sentinel_alive = lambda *a, _st=st, **k: _st.get("alive", True)
            HS.sentinel_heartbeat_age = (
                lambda *a, _st=st, **k: _st.get("hb", (30.0, iso)))
            HS._sentinel_uptime = lambda *a, _st=st, **k: _st.get("up", 3600.0)
            HS.self_check = lambda *a, _st=st, **k: _st.get("sc", (True, []))
            HS._outage_consequences = lambda *a, _st=st, **k: _st.get("cons", [])
            HS.is_dev_build = lambda *a, _st=st, **k: _st.get("dev", (False, ""))
            if st.get("load_raises"):
                def _boom():
                    raise RuntimeError("MUTANT: 判据自造的探针异常")
                HS.load_state = _boom
            else:
                HS.load_state = saved["load_state"]
            p = HS.guard_posture(_pkg_root())
            got = p.get("state")
            want = st.get("want", name)
            if got != want:
                raise AssertionError(
                    "造不出姿态 %r（拿到 %r）—— 判据的注入点与产品脱钩了，"
                    "必须同步，否则本判据是在验一个不存在的场景" % (want, got))
            out.append((name, p))
    finally:
        for k, v in saved.items():
            setattr(HS, k, v)
    return out


def _chrome_of(posture, items=None, views=("inbox", "report", "health", "ledger")):
    """把四个栏目渲染一遍，返回 `{view: 正文文本}`（已剥 details）。

    ★ `items` 缺省是**空列表**：这样正文里的一切都只能来自**页面本身的文案**，
      与"这台机器上恰好有哪些记录"解耦 —— 判据因此在这台机器、别的机器、
      以及 CI 上得到同一个结论。
    """
    import inbox_report as R
    import inbox_server as SV
    items = [] if items is None else items
    # ★ 复用同一份 rep：`daily_report` 会逐条复算整条审计链（本机实测 5.4s），
    #   七个姿态各算一次就是 38s。传空链文件 ⇒ 0.24s，且正文照样渲染。
    rep = R.daily_report(chain_files=[], items=items)
    out = {}
    for v in views:
        h = SV.render_page(view=v, root=None, token="TOKEN", items=items,
                           posture=posture, rep=rep)
        out[v] = _strip_details(h)
    return out


# ══════════════════════════════════ S01 六态是闭集 ══════════════════════════
def _six_state_set_ok(lights, label, logo, var):
    """六态闭集的**纯函数**版本（判据与负控共用同一段判断）。"""
    if tuple(lights) != SIX_STATES:
        return ("灯态集合不是逐字六态 —— 多 %s / 少 %s / 顺序 %r"
                % (sorted(set(lights) - set(SIX_STATES)),
                   sorted(set(SIX_STATES) - set(lights)), tuple(lights)))
    for nm, tb in (("STATE_LABEL", label), ("STATE_LOGO", logo), ("STATE_VAR", var)):
        if set(tb) != set(SIX_STATES):
            return ("%s 的键与六态不一致 —— 多 %s / 少 %s"
                    % (nm, sorted(set(tb) - set(SIX_STATES)),
                       sorted(set(SIX_STATES) - set(tb))))
    if dict(label) != SIX_LABELS:
        bad = {k: (label.get(k), SIX_LABELS[k]) for k in SIX_STATES
               if label.get(k) != SIX_LABELS[k]}
        return "灯态的人话标签被改过：%r" % bad
    # 未启用必须是 L0 的**变体**，不许自成一个态
    if L0_VARIANT in set(label.values()):
        return "「%s」被写进了 STATE_LABEL —— 它是 L0 的灰变体，不是第七态" % L0_VARIANT
    return True


@check("S01 六态是逐字的闭集（灯态表与其键完全一致）")
def s01():
    import inbox_model as M
    r = _six_state_set_ok(M.LIGHT_STATES, M.STATE_LABEL, M.STATE_LOGO, M.STATE_VAR)
    if r is not True:
        return _raise(r)
    return "LIGHT_STATES=%s；LABEL/LOGO/VAR 三表键与之逐字一致" % (list(M.LIGHT_STATES),)


@check("N-S01 负控：多一个第七态必须被 S01 抓到")
def n_s01():
    import inbox_model as M
    # 真做变异：把六态加上一个自造态，S01 的逻辑必须报错
    lights = tuple(M.LIGHT_STATES) + ("attention",)
    label = dict(M.STATE_LABEL)
    label["attention"] = "需你处理"
    r = _six_state_set_ok(lights, label, M.STATE_LOGO, M.STATE_VAR)
    if r is True:
        return _raise("往灯态集合加一个自造态，S01 仍判通过 ⇒ 闭集没守住")
    # 再验一次"改键"也能抓到（加深一态）
    label2 = {k: v for k, v in M.STATE_LABEL.items() if k != "dev"}
    r2 = _six_state_set_ok(M.LIGHT_STATES, label2, M.STATE_LOGO, M.STATE_VAR)
    if r2 is True:
        return _raise("删掉一个灯态标签，S01 仍判通过 ⇒ 判据只看数量不只看内容")
    return "第七态/改键两种变异都被抓到"


# ══════════════════════════════════ S02 穷举不越界 ══════════════════════════
#: 计划外输入（含不可哈希、None、数字、带空白/换行的串）—— 一律不许抛异常，
#: 也**绝不许**落到六态之外（尤其不许打绿）。
BAD_INPUTS = [None, "", "banana", "研发", "计划外", 0, 3.5, True, [], {},
              b"x", "OK", "ok ", " guardING", "guarding\n", 0xDEAD, ("t",)]


def _item_ts():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _mk_item(kind="host_shield_breach", state="unread", hours_ago=0.0, **kw):
    import inbox_model as M
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z",
                       time.localtime(time.time() - hours_ago * 3600))
    al = M.Alert.build(ts=ts, kind=kind, reason="判据构造", **kw)
    return M.Item(alert=al, state=state)


def _sweep_six_state():
    """真跑穷举。返回问题清单（空＝全过）。"""
    import host_shield as HS
    import inbox_model as M
    allowed_labels = set(SIX_LABELS.values()) | {L0_VARIANT}
    item_sets = [
        [],
        [_mk_item(state="unread")],                            # 窗口内 R0 未处理
        [_mk_item(state="done")],                              # 已处理
        [_mk_item(state="ignored")],
        [_mk_item(kind="tool_call_blocked", state="unread")],  # L2 已拦（Autinel 干完）
        [_mk_item(hours_ago=48)],                              # 窗口外
        [_mk_item(hours_ago=h, state="unread") for h in (0, 1, 5, 12, 23)],
    ]
    bad = []
    for st in list(HS.POSTURE_ALL) + BAD_INPUTS:
        for items in item_sets:
            try:
                lg, why = M.light(st, items)
            except Exception as e:                             # noqa: BLE001
                bad.append("light(%r) 抛 %s" % (st, type(e).__name__))
                continue
            if lg not in M.LIGHT_STATES:
                bad.append("light(%r) → %r（六态之外）" % (st, lg))
            lab = M.state_label(lg, st)
            if lab not in allowed_labels:
                bad.append("state_label(%r,%r) → %r（词表之外）" % (lg, st, lab))
            try:
                bs, _ = M.base_state(st)
            except Exception as e:                             # noqa: BLE001
                bad.append("base_state(%r) 抛 %s" % (st, type(e).__name__))
                continue
            if bs not in M.LIGHT_STATES:
                bad.append("base_state(%r) → %r（六态之外）" % (st, bs))
            blab = M.state_label(bs, st)
            if blab not in allowed_labels:
                bad.append("state_label(%r,%r) → %r（词表之外）" % (bs, st, blab))
        if bad:
            break
    return bad


@check("S02 穷举：七姿态 × 多组记录 × 坏输入，灯态恒在六态内且不抛异常")
def s02():
    bad = _sweep_six_state()
    if bad:
        return _raise("；".join(bad[:5]))
    return ("%d 组输入（7 姿态 + %d 计划外输入）× %d 组记录，"
            "灯态与标签全域封闭" % (7 + len(BAD_INPUTS), len(BAD_INPUTS), 7))


@check("N-S02 负控：让六态集合少一个（灯能返回集合外的值）⇒ S02 必须抓到")
def n_s02():
    import inbox_model as M
    orig = M.LIGHT_STATES
    try:
        # 真做变异：从集合里摘掉 dev ⇒ `light("dev")` 会返回集合外的 "dev"
        M.LIGHT_STATES = tuple(s for s in orig if s != "dev")
        bad = _sweep_six_state()
        if not bad:
            return _raise("摘掉一个灯态后穷举仍全过 ⇒ S02 对'越界'零分辨力")
    finally:
        M.LIGHT_STATES = orig
    # 还原后必须回绿（还原链路坏掉比负控失效更险）
    if _sweep_six_state():
        return _raise("还原 LIGHT_STATES 后穷举仍报错 ⇒ 还原链路坏了")
    return "摘掉 dev ⇒ 越界被抓；还原 ⇒ 回绿"


# ══════════════════════════════════ S03 用户面没有杜撰的态 ══════════════════
def _scan_banned(chrome_texts):
    """在正文文本里找禁用词。返回 `[(视图, 词, 出处)]`。"""
    hits = []
    for view, text in chrome_texts.items():
        for w in BANNED_IN_CHROME:
            if w in text:
                i = text.find(w)
                hits.append("%s 正文出现「%s」：…%s…"
                            % (view, w, text[max(0, i - 22):i + 22].strip()))
    return hits


@check("S03 用户可见正文里没有杜撰的状态词/角色词（八姿态 × 四栏目）")
def s03():
    hits = []
    for name, p in _posture_cases():
        ch = _chrome_of(p)
        h = _scan_banned(ch)
        hits += ["[姿态 %s] %s" % (name, x) for x in h]
    if hits:
        return _raise("；".join(hits[:5]))
    return "八种姿态 × 四个栏目，正文均无 %s" % ("、".join(sorted(BANNED_IN_CHROME)))


@check("N-S03 负控：把一个禁用语塞进页面文案 ⇒ S03 必须抓到")
def n_s03():
    # ★★ X（2026-10-23）：旧注入点是 `posture["why"]` —— 那是**探针自己的原话**，
    #   新投影上线后页面**不再渲染它**（冻结句从句子表来，禁临场写）。
    #   注入一个渲染不到的地方，负控必然"失效"，而扫描器其实好好的。
    #   ⇒ 改成注入**仍然上屏**的那一处（状态词），守的东西不变：
    #   「页面文案里出现禁用语，扫描器必须报」。
    import inbox_model as M
    orig = M.state_label
    try:
        M.state_label = lambda *a, **k: "护盾门闸存疑"
        poisoned = {"state": "interrupted", "label": "中断",
                    "why": "MUTANT", "can_fix": True, "fix": "revive",
                    "fix_hint": "马上修复", "consequences": []}
        ch = _chrome_of(poisoned)
    finally:
        M.state_label = orig
    h = _scan_banned(ch)
    if not h:
        return _raise("把「护盾/门闸/存疑」写进页面状态词，S03 仍判干净 ⇒ 扫描器空转")
    # 至少三个词都得抓到（否则扫描器只认一个词）
    got = {w for w in BANNED_IN_CHROME if any(w in x for x in h)}
    need = {"护盾", "门闸", "存疑"}
    if not need <= got:
        return _raise("露出来的词没全抓到：%s（希望 %s）" % (sorted(got), sorted(need)))
    return "注入 3 个禁用语 ⇒ 全被抓到"


# ══════════════════════════════════ S04 姿态词表封闭 ════════════════════════
def _posture_label_ok(table, allowed):
    over = sorted(set(table.values()) - set(allowed))
    if over:
        return "姿态标签出现词表外的词：%r（允许：%s）" % (over, sorted(allowed))
    return True


@check("S04 姿态标签的值落在封闭词表内（六态标签 ＋ 未启用 ＋ 中断）")
def s04():
    import host_shield as HS
    if not hasattr(HS, "POSTURE_LABEL_ALLOWED"):
        return _raise("host_shield 没有 POSTURE_LABEL_ALLOWED —— 词表没有真源，"
                      "下一轮又会有人往 POSTURE_LABEL 里加一个自造态")
    miss = set(HS.POSTURE_ALL) - set(HS.POSTURE_LABEL)
    if miss:
        return _raise("姿态 %s 没有标签（UI 取不到会空白）" % sorted(miss))
    # 词表本身也必须只含六态标签 + 两个具名例外 —— 否则"允许集"自己会漂
    expected = set(SIX_LABELS.values()) | {L0_VARIANT, "中断"}
    if set(HS.POSTURE_LABEL_ALLOWED) != expected:
        return _raise("词表内容被改过：多 %s / 少 %s"
                      % (sorted(set(HS.POSTURE_LABEL_ALLOWED) - expected),
                         sorted(expected - set(HS.POSTURE_LABEL_ALLOWED))))
    r = _posture_label_ok(HS.POSTURE_LABEL, HS.POSTURE_LABEL_ALLOWED)
    if r is not True:
        return _raise(r)
    return "七个姿态标签 ⊆ %s" % sorted(HS.POSTURE_LABEL_ALLOWED)


@check("N-S04 负控：往姿态标签里塞一个自造态 ⇒ S04 必须抓到")
def n_s04():
    import host_shield as HS
    t = dict(HS.POSTURE_LABEL)
    t[HS.POSTURE_WARN] = "存疑"
    if _posture_label_ok(t, HS.POSTURE_LABEL_ALLOWED) is True:
        return _raise("把 warn 的标签改回「存疑」，S04 仍判通过 ⇒ 词表没守住")
    return "自造态「存疑」被词表挡住"


# ══════════════════════════════════ S05 术语单源 ════════════════════════════
@check("S05 「监理」是唯一的守护角色；「护盾」只作为它的工具出现一处")
def s05():
    import glossary as GL
    if "shield" in GL.TERMS:
        return _raise("术语表里又有并列的 `shield` 词条了 —— 创始人 2026-10-09："
                      "「不要制造并列的护盾加监理两个概念，监理一个概念足矣」")
    sent = GL.TERMS.get("sentinel")
    if not sent:
        return _raise("没有 `sentinel` 词条 —— 「监理」这个唯一角色没有定义")
    body = " ".join(str(sent.get(k, "")) for k in ("one", "inc", "exc", "unit"))
    if "护盾" not in body:
        return _raise("`sentinel` 词条里没交代「护盾」是什么 ⇒ 用户读到「护盾」"
                      "会以为它是另一个角色（这正是要禁的并列概念）")
    if "工具" not in body:
        return _raise("`sentinel` 词条提到了「护盾」但没说它是**工具** ⇒ "
                      "读者仍会把两者当成两个平行的东西")
    # 护盾**只许**在 sentinel 词条里定义（别处出现就是第二个角色）
    others = [k for k, t in GL.TERMS.items() if k != "sentinel"
              and "护盾" in " ".join(str(v) for v in t.values())]
    if others:
        return _raise("「护盾」还出现在其它词条里：%s ⇒ 它又被写成了并列概念"
                      % others)
    # 术语正文里也不许有杜撰的状态词
    hits = []
    for k, t in GL.TERMS.items():
        blob = " ".join(str(v) for v in t.values())
        for w in BANNED_IN_TERMS:
            if w in blob:
                hits.append("%s 词条含「%s」" % (k, w))
    if hits:
        return _raise("；".join(hits))
    return "监理唯一角色；护盾仅作为其工具在 `sentinel` 词条里出现一次"


@check("N-S05 负控：把并列的 `shield` 词条加回去 ⇒ S05 必须抓到")
def n_s05():
    import glossary as GL
    if "shield" in GL.TERMS:
        return _raise("`shield` 已在表里 —— 本负控要验的是「加回去会被抓到」")
    GL.TERMS["shield"] = {"w": "护盾", "one": "另一个守护角色。",
                          "inc": "x", "exc": "y", "unit": "z"}
    caught = False
    try:
        try:
            s05()
        except AssertionError:
            caught = True
    finally:
        del GL.TERMS["shield"]
    if not caught:
        return _raise("把 `shield` 并列词条加回去，S05 仍判通过 ⇒ 单源没守住")
    try:
        s05()
    except AssertionError as e:
        return _raise("还原后 S05 仍判红 ⇒ 还原链路坏了：%s" % e)
    return "并列词条 `shield` 被 S05 抓到；还原后回绿"


# ══════════════════════════════════ S06 顶部灯说明单源 ══════════════════════
@check("S06 顶部条的原因句只能来自 render_view()／light_explain()（不许页面自己拼）")
def s06():
    import inbox_model as M
    import inbox_server as SV
    # ★★ X（2026-10-23）：取数点从 `light_explain()` 换成 `render_view()` ——
    #   后者内部**先调** `light_explain()`（几何/计数/徽标照旧），再把"态与句话"
    #   换成新投影。判据要守的东西没变：**页面只有一个取数入口，不自拼第二套**。
    #   ⇒ 注入点跟着唯一入口走，并同时断言那个入口真的还在调 `light_explain`。
    orig = M.render_view
    probe = "判据探针：这句话只可能来自取数入口（S06）。"
    posture = {"state": "guarding", "label": "值守中", "why": "监理在岗",
               "can_fix": False, "fix": None, "fix_hint": "", "consequences": []}
    try:
        M.render_view = lambda *a, **k: {
            "state": "R0", "label": "失守", "now_text": "X",
            "now_bad": True, "ledger_bad": False, "reason": probe,
            "badges": [], "action_count": 0, "info_count": 0}
        bar = SV._bar([], "TOKEN", posture=posture, view="inbox")
        if probe not in bar:
            return _raise("_bar 没有用 render_view() 的 reason ⇒ "
                          "页面自己拼了第二套说明（两套必然漂移）")
    finally:
        M.render_view = orig
    # 还原后必须回到正常实现（真跑一次，看说明句还在不在）
    bar2 = SV._bar([], "TOKEN", posture=posture, view="inbox")
    if not bar2.strip():
        return _raise("还原 render_view 后 _bar 渲染为空 ⇒ 还原链路坏了")
    # ★ 新入口必须**仍然**建在旧唯一实现上（否则就是第二套投影）
    import inspect
    src = inspect.getsource(M.render_view)
    if "light_explain(" not in src:
        return _raise("render_view() 没调 light_explain() ⇒ 出现了第二套投影实现")
    return "注入探针句 ⇒ 页面原样出现；还原 ⇒ 正常渲染；入口仍建在旧实现上"


@check("N-S06 负控：让 _bar 自己拼一句原因 ⇒ S06 必须抓到")
def n_s06():
    import inbox_model as M
    import inbox_server as SV
    orig = M.render_view
    probe = "判据探针：这句话只可能来自取数入口（S06）。"
    posture = {"state": "guarding", "label": "值守中", "why": "监理在岗",
               "can_fix": False, "fix": None, "fix_hint": "", "consequences": []}
    try:
        M.render_view = lambda *a, **k: {
            "state": "R0", "label": "失守", "now_text": "X",
            "now_bad": True, "ledger_bad": False, "reason": probe,
            "badges": [], "action_count": 0, "info_count": 0}
        # 变异：让 `_bar` 不理取数入口，自己拼（模拟"二次实现"）
        orig_bar = SV._bar

        def mut_bar(*a, **k):
            return orig_bar(*a, **k).replace(probe, "（页面自己拼的原因）")
        SV._bar = mut_bar
        try:
            bar = SV._bar([], "TOKEN", posture=posture, view="inbox")
            if probe in bar:
                return _raise("变异没生效 ⇒ 本负控无效（不是判据生效）")
        finally:
            SV._bar = orig_bar
    finally:
        M.render_view = orig
    return "页面自己拼原因时，探针句消失 ⇒ S06 的分辨力成立"


# ══════════════════════════════════ S07 条目状态机未被覆盖 ══════════════════
@check("S07 六态不许覆盖条目状态机（STATES 仍是 unread/read/done/ignored）")
def s07():
    import inbox_model as M
    if tuple(M.STATES) != ITEM_STATES:
        return _raise("inbox_model.STATES = %r（应当是 %r）—— 0.37.1 就是这里被"
                      "六态集合覆盖掉，导致全部「知道了/忽略」按钮静默失效"
                      % (tuple(M.STATES), ITEM_STATES))
    if set(M.LIGHT_STATES) == set(M.STATES):
        return _raise("灯态集合与条目状态集合相同 ⇒ 其中一个被另一个覆盖了")
    if not M.can_transition("unread", "done"):
        return _raise("unread→done 被判非法 ⇒ 状态机被改坏了")
    if not M.can_transition("done", "read"):
        return _raise("done→read（撤销手滑）被判非法 ⇒ 状态机被改坏了")
    if M.can_transition("done", "unread"):
        return _raise("done→unread 被判合法 ⇒ 迁移表被悄悄放宽了")
    # ★ 未知状态名必须**抛错**，不许静默返回 False —— 静默 False 会让
    #   "状态名写错"表现得像"这个动作不允许"，两种故障分不开。
    for a, b in (("banana", "read"), ("read", "banana")):
        try:
            M.can_transition(a, b)
        except M.BadState:
            continue
        return _raise("未报错地接受了未知状态 %r ⇒ 状态机不再校验" % (a,))
    return "四态状态机与六态灯态互不干扰"


@check("N-S07 负控：把六态集合改名覆盖 STATES ⇒ S07 必须抓到")
def n_s07():
    import inbox_model as M
    orig = M.STATES
    caught = False
    try:
        M.STATES = M.LIGHT_STATES          # ← MUTANT：重演 0.37.1 真实的那个错误
        try:
            s07()
        except AssertionError:
            caught = True
    finally:
        M.STATES = orig
    if not caught:
        return _raise("把 STATES 换成六态后 S07 仍判通过 ⇒ 这条守不住")
    try:
        s07()
    except AssertionError as e:
        return _raise("还原后 S07 仍判红 ⇒ 还原链路坏了：%s" % e)
    return "重演 `STATES` 被覆盖 ⇒ 被抓到；还原后回绿"


# ══════════════════════════════ S08 六态名只有一个出处 ══════════════════════
#: 态名只许在 `inbox_model.py` 定义一份（本判据自己写死的那份是"对照样"，
#: 不是源码声明）。其余模块（术语表 / CLI / 日报 / 筛选条 / 托盘 / 页面）一律派生。
#: ★ 为什么挡"第二份"而不是"多写几条断言"：漂移的**入口**就是"又抄了一份" ——
#:   0.37.3 前同一个 Ls 态同时叫过 预算 / 额度 / 额度提示，就是抄了三份的结果。
#:   堵住入口，比在每个出口巡逻更省事、也更难绕过。
#: ★★ 2026-10-21（STE100 体检 S-03，创始人拍板）：**两个真源** ——
#:   `STATE_LABEL` 的六个词**只描述此刻**（"失守"＝现在没人替你挡着），
#:   而账本／日报／筛选条要用同样的键**数过去的事**。「昨日失守 3 次」
#:   是把"只认此刻"的词拿去数历史 —— 读者刚在灯上学会「失守＝现在」，
#:   翻一页又看见它当过去用，两个语义在同一套界面里打架（术语表词条
#:   「失守只认此刻」的下一行曾写着「昨天失守」，一个词条内自相矛盾）。
#:   ⇒ 第二真源 `EVENT_LABEL`（没守住/挡下/提醒），同样只许一份声明；
#:     R0/L2/L1 三个键两表的值**不许重叠**（重叠＝一词二义）。
#:   ★ 老 S08 只保证"全仓一份真源"，没保证"一个词只对一个语义" ——
#:     这正是「昨天失守」能天天绿着上屏的原因：词表本身没脏，脏的是
#:     **拿灯态词去数账**这个用法，而没有任何尺子量它。
ALLOWED_DECL_FILES = ("inbox_model.py", "inbox_guards_0372.py")

#: 一份"态名声明"长什么样：`"<六态键>": "<含中文的值>"`。
#: 值里必须是中文，才排除掉 `STATE_VAR = {"R0": "--r0"}`、`LEVEL_TO_BUCKET = {"R0": "r0"}`
#: 这类**合法**的同键表（它们填的是 CSS 变量名 / 桶名，不是人话名）。
_STATE_DECL_RE = re.compile(
    r'"(R0|L2|L1|Ls|L0|dev)"\s*:\s*"([^"]*[\u4e00-\u9fff][^"]*)"')

#: 值（去掉尾部 `（XX）`）若等于下列任何一个，就认定这是一份"态名声明"。
#: 后半段是**历史别名** —— 它们曾各占一方；收进来是为了"老的错名不许回来"，
#: 不是为了继续使用。句子（如「有过失守」「一切正常」）不在表内 ⇒ 不误报。
_STATE_NAME_TOKENS = frozenset(
    list(SIX_LABELS.values()) + [L0_VARIANT, "中断"]              # 现行名＋合法变体
    + ["预算", "额度", "额度提示", "值守", "值守正常", "已拦截"])   # 历史别名

#: ★ 第二真源 `EVENT_LABEL` 的**对照样**（同样写死，不 import 产品 ——
#:   两边取自同一个常量的话，"有人把产品表改坏"时判据会跟着变，等于没守）。
#:   只列 R0/L2/L1 三个键：Ls/L0/dev 两表同值是有意的（见 inbox_model 注释），
#:   它们不参与"此刻 vs 过去"的冲突。
#: ★★★ 0.57.1：R0 由「出事」改「**没守住**」（创始人：出事太重，预判了损失）。
#:   改词必须同时改这一行 —— 这就是对照组的作用：谁想偷偷换词，这里就红。
EVENT_LABELS_REF = {"R0": "没守住", "L2": "挡下", "L1": "提醒"}
_EVENT_NAME_TOKENS = frozenset(EVENT_LABELS_REF.values())


def _core_state_name(v):
    """去掉尾部 `（R0）`/`（Ls）` 这类括注，得到"名"本身。"""
    m = re.match(r"^(.*?)\s*（[A-Za-z0-9$]+）\s*$", v.strip())
    return (m.group(1).strip() if m else v.strip())


def _decl_scan(files):
    """`files` = [(相对路径, 源码文本)]；返回问题清单。

    ★ 纯函数（文本进、清单出）—— 这样负控可以喂**合成文本**来验分辨力，
      不必往盘上写一个假的源文件（本判据绝不写盘）。
    ★ 2026-10-21：**两份真源各扫一份第二声明**。第二份 EVENT_LABEL 的辨认方式是
      "同键同值"—— 只有值正好是 没守住/挡下/提醒 时才认；散文（「有过失守」）
      与别处的合法同键表（填桶名/CSS 变量名）都不误报。
    """
    bad = []
    for rel, text in files:
        if os.path.basename(rel) in ALLOWED_DECL_FILES:
            continue
        for m in _STATE_DECL_RE.finditer(text):
            key, val = m.group(1), m.group(2)
            core = _core_state_name(val)
            line = text[:m.start()].count("\n") + 1
            if core in _STATE_NAME_TOKENS:
                bad.append("%s:%d 又写了一份态名（%s → %r）" % (rel, line, key, val))
            elif core in _EVENT_NAME_TOKENS:
                bad.append("%s:%d 又写了一份事件名（%s → %r，真源只能是 "
                           "inbox_model.EVENT_LABEL）" % (rel, line, key, val))
    return bad


def _two_sources_ok(event_tb):
    """两个真源的**关系**检查（纯函数，判据与负控共用）。返回问题串或 True。

    两条腿：
      ① 产品 EVENT_LABEL 与对照样逐字一致（词是**敲定**的，不是随手起的）；
      ② R0/L2/L1 三个键的事件词不许掉进灯态词表（一词二义即红）。
    """
    for k, want in EVENT_LABELS_REF.items():
        got = event_tb.get(k)
        if got != want:
            return ("事件名 %s 应是 %r，实际 %r —— 过去的事用什么词是 0.53.5 "
                    "敲定的，改它等于把那次裁定作废" % (k, want, got))
    for k in EVENT_LABELS_REF:
        if event_tb.get(k) in SIX_LABELS.values():
            return ("事件词 %r 掉进了灯态词表 —— 一个词同时描述'此刻'和'过去'，"
                    "就是截图里「昨天失守」的根因" % event_tb.get(k))
    return True


def _event_words_explained(event_tb, terms):
    """**每个上屏的事件词必须在自己词条的正文里被写出来**。返回问题串或 True。

    ★★ 为什么要这一条（0.57.1，创始人「出事这个词太重，显然感觉有问题」）：
      事件词是**屏上的词**（数卡标题、筛选条、日报行、账本行），可此前三个
      事件词**一个都没进术语表**。读者看到「出事」，点开首行却是「失守（R0）」
      —— 屏上是 A、解释是 B，系统里没有一处解释 A。这条腿就是钉这个：**屏上
      出现的词，必须在它自己词条的正文里被说出来**。
    ★ 只认正文（one/inc/exc/unit），**不认 label**：label 是渲染时调用方传进去
      的，拿它做断言等于拿结论证明前提（恒真＝死判据，假绿第一族）。
    ★ 负控喂的是**真变异**（把表改回「出事」），不是合成文本 —— 这条腿的病根
      恰恰是"表里的词与词条正文脱钩"，只有真的改表才能重现。
    """
    for k in EVENT_LABELS_REF:
        ev = event_tb.get(k)
        body = " ".join(str((terms.get(k) or {}).get(f) or "")
                        for f in ("one", "inc", "exc", "unit"))
        if ev and ev not in body:
            return ("事件词「%s」（%s）不在术语表词条的正文里 —— 屏上有这个词，"
                    "点开却只看到另一个词，等于系统没解释它" % (ev, k))
    return True


def _retired_words_absent(state_tb, event_tb, terms, retired):
    """**已判死的词不许回到任何"词名位"**。返回问题串或 True。

    ★★ 为什么要单独一张判死表（0.57.1）：对照样只守"现在是哪个词" —— 它挡得住
      偷偷换，挡不住下一轮"有人觉得旧词更顺口、顺手加回去"，也挡不住给**别的
      词条**起这个名字。判死的理由连同词一起登记在 `glossary.RETIRED_WORDS`，
      这样下一个 AI 不必重新踩一遍才知道为什么不能用。
    ★ 只扫**词名**（两表的值 ＋ `TERMS[*]["w"]`），**不扫词条正文**：正文里出现
      旧词可能正是在解释"什么不算它"，一刀切会把正常句子判红 —— 假阳性最坏的
      结局是有人为了让它绿而删掉判据。
    """
    hit_at = []
    for w in (retired or {}):
        where = []
        if w in (state_tb or {}).values():
            where.append("灯态词表")
        if w in (event_tb or {}).values():
            where.append("事件词表")
        for k, t in (terms or {}).items():
            v = str((t or {}).get("w") or "")
            if v == w or v.startswith(w + "（"):
                where.append("词条 %s 的本名" % k)
        if where:
            hit_at.append("已判死的词「%s」回到了%s（%s）"
                          % (w, "、".join(where), (retired or {})[w][:70]))
    return "；".join(hit_at) or True


def _skip_dir(name):
    """构建产物/缓存/归档副本/点目录 —— 都不是"现行源码"，不该被单源扫描看见。

    ★ 归档副本尤其要排：本仓习惯把旧件改名成 `<名字>.away-<序号>` 保留在
      原地，它们**必然**含有改名前的旧态名 —— 不排掉就会天天报红，
      然后有人会为了"让它绿"而把判据删掉（假阳性最坏的结局）。
    """
    return (name.startswith(".") or name in ("__pycache__", "_uxtest", "assets", "ci")
            or name.startswith("build") or name.startswith("dist")
            or name.startswith("_buildjunk") or ".away" in name)


def _source_files():
    """全仓产品源码（跳过构建产物/缓存/归档副本/测试导出/本判据目录）。"""
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
        for fn in filenames:
            if not fn.endswith(".py") or ".away" in fn or fn.startswith("_p_"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                out.append((os.path.relpath(p, ROOT), open(p, encoding="utf-8").read()))
            except Exception:                                   # noqa: BLE001
                pass
    return out


@check("S08 两个真源各一份（灯态词/事件词；第二份声明或一词二义即报红）")
def s08():
    import inbox_model as M
    import glossary as GL
    bad = _decl_scan(_source_files())
    if bad:
        return _raise("；".join(bad[:6]))
    r = _two_sources_ok(M.EVENT_LABEL)
    if r is not True:
        return _raise(r)
    r2 = _event_words_explained(M.EVENT_LABEL, GL.TERMS)
    if r2 is not True:
        return _raise(r2)
    r3 = _retired_words_absent(M.STATE_LABEL, M.EVENT_LABEL, GL.TERMS,
                               getattr(GL, "RETIRED_WORDS", {}))
    if r3 is not True:
        return _raise(r3)
    return ("灯态词全仓只有 inbox_model.py 一份、事件词同样只有 "
            "EVENT_LABEL 一份；R0/L2/L1 两表值零重叠；"
            "三个事件词都在各自词条的正文里被解释；已判死的词没回来")


@check("N-S08 负控：第二份事件名/一词二义/事件词漂移，各自必须被抓到")
def n_s08():
    import inbox_model as M
    # ① 第二份事件名（往别的文件写一份 EVENT_LABEL）
    fake = [("inbox_server.py", 'EVIL = {"R0": "没守住", "L2": "挡下"}\n')]
    if not _decl_scan(fake):
        return _raise("在别的文件里写第二份事件名，S08 仍判干净 ⇒ 扫描器空转")
    # 反向：散文不许被误判（假阳性会逼人关掉这条判据）
    prose = [("inbox_tray.py", 'X = {"R0": "出过事"}\nY = {"L2": "挡住过"}\n')]
    if _decl_scan(prose):
        return _raise("把散文误判成事件名声明 ⇒ 扫描器有假阳性")
    # ② 一词二义：把事件词改回灯态词（「昨天失守」的根因形态）
    orig = dict(M.EVENT_LABEL)
    try:
        M.EVENT_LABEL["R0"] = "失守"                                # ← MUTANT
        if _two_sources_ok(M.EVENT_LABEL) is True:
            return _raise("事件词与灯态词重叠（一词二义），S08 仍判通过 "
                          "⇒ 截图里「昨天失守」那个形态没人守")
    finally:
        M.EVENT_LABEL.clear()
        M.EVENT_LABEL.update(orig)
    if _two_sources_ok(M.EVENT_LABEL) is not True:
        return _raise("还原 EVENT_LABEL 后仍判红 ⇒ 还原链路坏了")
    # ③ 事件词漂移：换一个同义字（「挡住」）也要红 —— 词是敲定的
    try:
        M.EVENT_LABEL["L2"] = "挡住"                                # ← MUTANT
        if _two_sources_ok(M.EVENT_LABEL) is True:
            return _raise("把「挡下」换成「挡住」，S08 仍判通过 "
                          "⇒ 一词多义族（0.53.4 拦下/挡下）会从这里复发")
    finally:
        M.EVENT_LABEL.clear()
        M.EVENT_LABEL.update(orig)
    # 现行源必须干净（判据与源码不一致时先报出来）
    bad = _decl_scan(_source_files())
    if bad:
        return _raise("现行源码里仍有第二份声明：%s" % bad[:3])
    # ④ 上屏词必须被自己的词条解释（0.57.1）：
    #    ★ 这一腿的**专属红样本不是"改词"** —— 改词已经被腿①的对照样抓到了。
    #      它抓的是另一件事：**词没变、词条正文里却不再提它**（0.57.1 之前三个
    #      事件词一个都不在术语表里，就是这个形态）。所以这里删正文那句，不动表。
    #    ★ 在**副本**上删，不动产品模块（动真源要还原，还原链路自己也会坏）。
    import glossary as GL
    _terms = {k: dict(v) for k, v in GL.TERMS.items()}
    if _event_words_explained(M.EVENT_LABEL, _terms) is not True:
        return _raise("夹具不成立：现行词条本就解释不了事件词 ⇒ 负控无分辨力")
    _r0 = dict(_terms["R0"])
    # ★★ 0.57.1 第二稿：变异锚点**从产品自身取**，不许写死一句旧文案。
    #   第一稿写的是 `.replace("数过去的事时，这一档写作「没守住」。", "")` ——
    #   后来那句话因为 0514 T4-07 的句子预算被改写了，`replace` 变成空操作，
    #   词条正文一个字没删 ⇒ 这一腿拿不到红样本，闸门里报「S08 仍判通过」。
    #   （同族先例：`0514 N-T4-09` 的 docstring 明写"注入串从当前 one 派生，
    #     不写死一句旧文案"—— 我这条腿没照它办。）
    #   现在改成：把 R0 词条的四个正文字段里**该事件词本身**全部删掉。词改到
    #   哪就去删哪个，锚点永远不会失效。
    _ev = M.EVENT_LABEL["R0"]
    for _f in ("one", "inc", "exc", "unit"):
        _r0[_f] = str(_r0.get(_f) or "").replace(_ev, "")
    if _r0 == dict(_terms["R0"]):
        return _raise("夹具不成立：事件词「%s」并不在 R0 词条正文里 —— "
                      "前面那条腿本该先报红，这里不该走到" % _ev)
    _terms["R0"] = _r0
    if _event_words_explained(M.EVENT_LABEL, _terms) is True:
        return _raise("把词条正文里解释事件词的那句删掉，S08 仍判通过 "
                      "⇒ 屏上出现一个系统没解释的词，没人守")
    # ⑤ 已判死的词不许回来（0.57.1）：给一个**别的词条**起旧名 —— 对照样抓不到
    #    （表没变），只有判死表能抓到。
    _terms2 = {k: dict(v) for k, v in GL.TERMS.items()}
    _terms2["_fake"] = {"w": "出事"}
    if _retired_words_absent(M.STATE_LABEL, M.EVENT_LABEL, _terms2,
                             getattr(GL, "RETIRED_WORDS", {})) is True:
        return _raise("给一个词条起已判死的名「出事」，S08 仍判通过 "
                      "⇒ 判死表没有分辨力")
    if _retired_words_absent(M.STATE_LABEL, M.EVENT_LABEL, GL.TERMS,
                             getattr(GL, "RETIRED_WORDS", {})) is not True:
        return _raise("现行词表里就有已判死的词 ⇒ 判据与源码不一致")
    if _event_words_explained(M.EVENT_LABEL, GL.TERMS) is not True:
        return _raise("走完负控后现行源仍判红 ⇒ 夹具污染了产品模块")
    return ("第二份事件名/一词二义/事件词漂移/上屏词无解释/判死词回来 "
            "都被抓到；散文不误报；现行源干净")


# ══════════════════════════════ S09 光梯次序＝离终结的距离 ═══════════════════
#: 品牌动效语法 v1.2 §一.3「绿→浅黄→明黄→橙都是『领地有事、越来越急』；
#: 红色是另一回事——哨兵没了」＋ §三 扫描周期 12→8→5.5→3.5→**停摆**。
#: ⇒ 这把尺量的是「**离终结有多近**」，不是"事件多严重"。
EXPECTED_PRIORITY = {"L0": 1, "L1": 2, "L2": 3, "Ls": 4, "R0": 5}


def _priority_ok(prio):
    if dict(prio) != EXPECTED_PRIORITY:
        return ("光梯次序不是「离终结的距离」：拿到 %r，应为 %r"
                "（L0 值守中 < L1 注意 < L2 拦截 < Ls 缺粮 < R0 失守）"
                % (dict(prio), EXPECTED_PRIORITY))
    return True


@check("S09 光梯次序＝离终结的距离（Ls 紧贴 R0）＋ 派生面与真源逐字一致")
def s09():
    import glossary as GL
    import inbox_cli as CLI
    import inbox_model as M
    import inbox_server as SV
    r = _priority_ok(M.PRIORITY)
    if r is not True:
        return _raise(r)
    canon = dict(M.STATE_LABEL)
    problems = []
    for k in ("R0", "L2", "L1", "Ls", "L0"):
        want = canon[k]
        got = {"state_short": M.state_short(k),
               "filter_label": M.filter_label("lv:" + k),
               "LEVEL_NAME": SV.LEVEL_NAME.get(k),
               "glossary.w": _core_state_name(GL.TERMS[k]["w"]),
               "_fmt_level": _core_state_name(CLI._fmt_level(k))}
        off = {n: v for n, v in got.items() if v != want}
        if off:
            problems.append("%s 应叫 %r，但这些面是 %r" % (k, want, off))
    if problems:
        return _raise("；".join(problems))
    want_txt = " > ".join(canon[k] for k in sorted(
        EXPECTED_PRIORITY, key=lambda x: -EXPECTED_PRIORITY[x]))
    if M.PRIORITY_ORDER_TEXT != want_txt:
        return _raise("次序人话 %r ≠ 由 PRIORITY 算出的 %r"
                      % (M.PRIORITY_ORDER_TEXT, want_txt))
    return "五处派生面逐字一致；次序人话＝%s" % M.PRIORITY_ORDER_TEXT


@check("N-S09 负控：Ls 压回最低 / 某处派生面掉队 ⇒ S09 必须抓到")
def n_s09():
    import inbox_model as M
    import inbox_server as SV
    orig = M.PRIORITY
    try:
        M.PRIORITY = {"R0": 5, "L2": 4, "L1": 3, "Ls": 2, "L0": 1}     # ← MUTANT
        if _priority_ok(M.PRIORITY) is True:
            return _raise("把 Ls 压回最低，S09 仍判通过 ⇒ 次序没守住")
    finally:
        M.PRIORITY = orig
    if _priority_ok(M.PRIORITY) is not True:
        return _raise("还原 PRIORITY 后仍判红 ⇒ 还原链路坏了")
    orig_n = dict(SV.LEVEL_NAME)
    try:
        SV.LEVEL_NAME["Ls"] = "预算"                                    # ← MUTANT
        caught = False
        try:
            s09()
        except AssertionError:
            caught = True
        if not caught:
            return _raise("把 LEVEL_NAME 改回旧名，S09 仍判通过 ⇒ 派生面没守住")
    finally:
        SV.LEVEL_NAME.clear()
        SV.LEVEL_NAME.update(orig_n)
    try:
        s09()
    except AssertionError as e:
        return _raise("还原 LEVEL_NAME 后 S09 仍判红 ⇒ 还原链路坏了：%s" % e)
    return "Ls 压最低 / 派生面掉队，两种变异都被抓到；还原后回绿"


# ══════════════ S19 哨兵自注册心跳链；读不到心跳 ≠ 失守（0.48.5 A1） ══════════════
#: 盯的已修缺陷：Antinel 监理遗留问题清单 2026-10-13 **A1 假失守** ——
#:   心跳读取按**读者**包根猜哨兵写哪条链（`_shield_audit_dir(_pkg_root())`），
#:   哨兵进程与读者不在同一个包根时读到**另一条链**（中枢 rollup 的老记录）
#:   ⇒ `guard_posture` 判"心跳断档" ⇒ 渲染成红、还给「马上修复」按钮
#:   （点了撞 already-running 幂等，没有任何反应）。本机 worktree 实测复发。
#:   修法（产品侧，host_shield.py）：
#:     ① 哨兵启动经 `_register_sentinel_start()` 自注册 `sentinel_audit_dir`
#:        （state 唯一写入口，字段一起登记）；
#:     ② 心跳目录解析收敛到 `_sentinel_heartbeat_chain()` 一个实现：
#:        注册值优先，legacy 走显式两分支并标 `heartbeat_source`；
#:     ③ `guard_posture` 新增分层：在岗但读不到心跳链 ⇒ POSTURE_UNKNOWN
#:        （L1 盲区，给 revive 但不点红）；age 是**真实的老数字**仍走缺岗分支。
def _registration_ok(fields, audit_dir):
    """启动登记判据（S19 与 N-S19 共用同一段判断，避免正负两套口径）。"""
    if fields.get("sentinel_audit_dir") != audit_dir:
        return ("登记缺 sentinel_audit_dir=%r（拿到 %r）—— 监理没自注册心跳链，"
                "读者只能按包根猜 ⇒ A1 复发" % (audit_dir, fields.get("sentinel_audit_dir")))
    need = ("sentinel_pid", "sentinel_started_at", "sentinel_audit_dir", "enabled")
    miss = [k for k in need if k not in fields]
    if miss:
        return "登记缺字段 %r" % (miss,)
    if fields.get("_allow_disarm") is not True:
        return "登记没显式 allow_disarm —— 链说撤防时这一笔登记写不进去"
    return True


@check("S19 监理自注册心跳链 + 读不到链路落盲区（A1：读不到 ≠ 失守）")
def s19():
    import inspect
    import json as _json
    import os as _os
    import shutil as _shutil
    import tempfile
    from datetime import datetime as _dt
    import host_shield as HS

    # ── ① 启动登记：走唯一写入口，且四个字段（含 sentinel_audit_dir）齐 ──
    if "_register_sentinel_start" not in inspect.getsource(HS.run_sentinel):
        return _raise("run_sentinel 没走 _register_sentinel_start —— "
                      "启动登记出现了第二个写入口（维一：同一语义一个写入口）")
    seen = {}
    _orig_usf = HS.update_state_fields

    def _cap(*, allow_disarm=False, **fields):
        seen.update(fields)
        seen["_allow_disarm"] = allow_disarm
        return True
    HS.update_state_fields = _cap
    try:
        ok = HS._register_sentinel_start(4242, "2026-10-13T12:00:00+08:00",
                                         r"D:\.psl\audit", True)
    finally:
        HS.update_state_fields = _orig_usf
    r = _registration_ok(seen, r"D:\.psl\audit")
    if r is not True:
        return _raise(r)
    if ok is not True:
        return _raise("_register_sentinel_start 返回了 %r（拒写没透出）" % (ok,))

    # ── ② 心跳目录解析：注册值优先（真跑：造一条刚写的链） ──
    tmp = _TMP.tmpdir(prefix="antinel-s19-")
    try:
        with open(_os.path.join(tmp, "chain.jsonl"), "w", encoding="utf-8") as f:
            f.write(_json.dumps({"type": "host_shield_heartbeat", "decision": "allow",
                                 "ts": _dt.now().astimezone().isoformat()},
                                ensure_ascii=False) + "\n")
        _orig_ls = HS.load_state
        try:
            HS.load_state = lambda: {"sentinel_audit_dir": tmp}
            age, ts = HS.sentinel_heartbeat_age()
            d, src = HS._sentinel_heartbeat_chain()
        finally:
            HS.load_state = _orig_ls
        if src != "registered":
            return _raise("state 里有注册目录，来源却标成 %r —— 注册值没被优先" % (src,))
        if age is None or age > 120:
            return _raise("注册目录里躺着刚写的心跳，age=%r —— 监理没读自己注册的链"
                          % (age,))
        if not ts:
            return _raise("last_ts 是空的 —— 读到了记录却取不到时间戳")
        # legacy 显式分支：无注册字段 ⇒ 必须退回"读者包根"口径并标出来源
        try:
            HS.load_state = lambda: {}
            d2, src2 = HS._sentinel_heartbeat_chain()
        finally:
            HS.load_state = _orig_ls
        if src2 not in ("legacy_pkg", "legacy_hub"):
            return _raise("无注册字段时来源标成 %r（三值之外）—— 维八：读不到旧版本"
                          "必须出声，禁止当空" % (src2,))
        want = HS._shield_audit_dir(HS._pkg_root())
        if _os.path.realpath(d2) != _os.path.realpath(want):
            return _raise("legacy 分支目录 %r ≠ %r" % (d2, want))
    finally:
        _shutil.rmtree(tmp, ignore_errors=True)

    # ── ③ guard_posture 分层：在岗但读不到 ⇒ unknown（盲区），不是 down ──
    names = ("armed_state", "sentinel_alive", "sentinel_heartbeat_age",
             "_sentinel_uptime", "self_check", "_outage_consequences",
             "is_dev_build")
    saved = {k: getattr(HS, k) for k in names}
    try:
        HS.armed_state = lambda *a, **k: True
        HS.sentinel_alive = lambda *a, **k: True
        HS.sentinel_heartbeat_age = lambda *a, **k: (None, None)
        HS._sentinel_uptime = lambda *a, **k: None
        HS.self_check = lambda *a, **k: (True, [])
        HS._outage_consequences = lambda *a, **k: []
        HS.is_dev_build = lambda *a, **k: (False, "")
        p = HS.guard_posture()
    finally:
        for k, v in saved.items():
            setattr(HS, k, v)
    if p.get("state") != HS.POSTURE_UNKNOWN:
        return _raise("在岗但读不到心跳链，姿态是 %r（应为 unknown）—— "
                      "A1 假失守没修住" % (p.get("state"),))
    if p.get("fix") != "revive" or p.get("can_fix") is not True:
        return _raise("盲区档没给 revive：fix=%r can_fix=%r" %
                      (p.get("fix"), p.get("can_fix")))
    if "心跳链" not in p.get("why", ""):
        return _raise("盲区档文案没点明「心跳链」—— 读者无法自救")
    ev = p.get("evidence") or {}
    if ev.get("heartbeat_source") not in ("registered", "legacy_pkg", "legacy_hub"):
        return _raise("evidence 里没有 heartbeat_source（三值之一）—— 维五：读不到"
                      "心跳时必须说得出来自哪里")
    hits = _scan_banned(_chrome_of(p))
    if hits:
        return _raise("盲区档新文案带禁用词：%s" % "；".join(hits[:3]))
    return ("登记四字段齐（含 sentinel_audit_dir）；注册目录优先读到真实心跳；"
            "在岗读不到 ⇒ unknown+revive，不点红")


@check("N-S19 负控：抹自注册字段 / 陈旧链冒充盲区 / 不在岗冒充盲区 ⇒ S19 必须抓到")
def n_s19():
    import host_shield as HS
    iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    # ① 产品退化：登记时不带 sentinel_audit_dir ⇒ 登记判据必须红
    seen = {}
    _orig_usf = HS.update_state_fields

    def _strip(*, allow_disarm=False, **fields):
        fields.pop("sentinel_audit_dir", None)               # ← MUTANT
        seen.update(fields)
        return True
    HS.update_state_fields = _strip
    try:
        HS._register_sentinel_start(1, "2026-10-13T00:00:00+08:00",
                                    r"D:\x\.psl\audit", True)
    finally:
        HS.update_state_fields = _orig_usf
    if _registration_ok(seen, r"D:\x\.psl\audit") is True:
        return _raise("抹掉 sentinel_audit_dir 登记仍判通过 ⇒ 判据没真看这个字段")

    # ② 偷换现场：age 是"真实的老数字"（读到了、陈旧）⇒ 缺岗分支，不是盲区
    names = ("armed_state", "sentinel_alive", "sentinel_heartbeat_age",
             "_sentinel_uptime", "self_check", "_outage_consequences",
             "is_dev_build")
    saved = {k: getattr(HS, k) for k in names}
    try:
        HS.armed_state = lambda *a, **k: True
        HS.sentinel_alive = lambda *a, **k: True
        HS.sentinel_heartbeat_age = lambda *a, **k: (99999.0, iso)   # ← MUTANT
        HS._sentinel_uptime = lambda *a, **k: None
        HS.self_check = lambda *a, **k: (True, [])
        HS._outage_consequences = lambda *a, **k: []
        HS.is_dev_build = lambda *a, **k: (False, "")
        p = HS.guard_posture()
        if p["state"] == HS.POSTURE_UNKNOWN:
            return _raise("读到的是陈旧老链也判成盲区 ⇒ '读不到'与'读到了但旧'"
                          "被混成一档")
        if p["state"] != HS.POSTURE_INTERRUPTED:
            return _raise("在岗+陈旧链+无后果，预期中断（黄），拿到 %r" % (p["state"],))
        # ③ 进程不在岗 + 读不到 ⇒ 缺岗分支，不是盲区分支
        HS.sentinel_alive = lambda *a, **k: False                    # ← MUTANT
        p2 = HS.guard_posture()
        if p2["state"] == HS.POSTURE_UNKNOWN:
            return _raise("进程不在岗也判成盲区 ⇒ 分层条件没钉在'在岗且读不到'上")
        if "不在岗" not in (p2.get("why") or ""):
            return _raise("缺岗文案里没有「不在岗」⇒ 现场走错了分支")
    finally:
        for k, v in saved.items():
            setattr(HS, k, v)
    return ("三种变异都被抓到：抹注册字段（登记判据红）/ 陈旧链（不冒充盲区）/ "
            "不在岗（不冒充盲区）")


# ══════════════ S20 · C6（CLI 命令的真身分支必须真跑过）══════════════════
def _s20_run(cli_mod):
    """把 `cli_mod.cmd_daemon` 在「**已有守护进程在跑**」这条真身分支上真跑一次。

    返回 `(rc, out, err)`；`err` 非空 ⇒ 这条路崩了（正是 C6 的病象）。
    ★ `daemon_alive` 用猴子补丁打成"在跑"（假 pid 424242，不碰任何真进程）；
      跑完**必须还原**（坏品种滞留比空判据更险）。
    ★ 为什么必须真跑而不是看源码：C6 的病根就是"这条分支从来没被执行过" ——
      静态看代码完全正常（`os.getpid()` 写得没问题，问题在于**模块没 import os**）。
    """
    import argparse
    import contextlib
    import io as _io
    import inbox_daemon as DM
    orig = DM.daemon_alive
    DM.daemon_alive = lambda: (True, 424242)                 # ← MUTANT（只补在这一句上）
    buf, err, rc = _io.StringIO(), "", None
    try:
        with contextlib.redirect_stdout(buf):
            rc = cli_mod.cmd_daemon(argparse.Namespace(supervise=True,
                                                       interval=15, root=None))
    except Exception as e:                                    # noqa: BLE001
        err = "%s: %s" % (type(e).__name__, e)
    finally:
        DM.daemon_alive = orig                                # 坏品种滞留比空判据更险
    return rc, buf.getvalue(), err


@check("S20 ★ C6：daemon 已在跑这条真身分支真跑过 —— 说人话、返回 0、不抛")
def s20():
    """★★ C6（2026-10-13，重启Antinel 监理时当场撞到）：`inbox_cli.cmd_daemon` 的
    「已有守护进程在跑 ⇒ 不重复启动」分支**从来没被真跑过一次** ——
    它用了 `os.getpid()`，而 `inbox_cli.py` **从未 `import os`** ⇒
    用户第二次起 daemon（日常操作：想知道"起了没有"）得到的不是那句人话，
    而是一个 `NameError` traceback。与 0.35.2 `inbox_server` 用了
    `subprocess.Popen` 却没 import subprocess **同型**：缺陷长在
    **没有任何判据走过的真身分支**上（判据都只走了"没有 daemon 在跑"那条）。
    ⇒ 本条**真调**这条分支：不抛、说人话、返回 0，三件事缺一即红。
    """
    import inbox_cli as CLI
    rc, out, err = _s20_run(CLI)
    if err:
        return _raise("「已有守护进程在跑」这条分支崩了：%s —— 用户第二次起 daemon "
                      "得到的不是那句人话（C6 复发）" % err)
    if rc != 0:
        return _raise("该分支返回 %r（应 0：说清楚「没重复启动」就是正常结束）" % (rc,))
    if "已经在跑" not in out:
        return _raise("该分支什么都没说（out=%r）—— 没做也不说，T-10 静默" % (out[:80],))
    return "真身分支通过：说人话 + 返回 0（%s）" % out.strip()[:40]


@check("N-S20 负控：这条分支看不到 os（C6 原貌）⇒ S20 必须抓到")
def n_s20():
    """反向对照（维二）：**撤销修复即变红** —— 在**内存里**造一个让这条分支
    **看不到 `os`** 的 `inbox_cli`（不写盘，本文件纪律），同一条分支必须崩。
    ★ 变异形态 2026-10-18 已改（理由写在函数体里）：不再是「删掉 `import os`」
      —— 那是**导入即崩**，与这条分支无关，分辨力为零；
      改为**原样导入后在模块全局里摘掉 `os`**，测到的才是这条分支本身。
    ★ 另验还原链：真身在变异后必须仍然通过（补丁没把尺子本身弄坏）。
    """
    import io
    import types
    p = os.path.join(ROOT, "inbox_cli.py")
    with io.open(p, encoding="utf-8") as f:
        src = f.read()
    # ★ 0.53.0 收尾（2026-10-18 实测）：**不再**从源码里删掉 `import os`。
    #   那是"撤销修复"的字面形态，但今天它已经**做不出来**了 ——
    #   `inbox_cli.py:33` 是**模块级** `sys.path.insert(0, os.path.dirname(...))`
    #   （AST 实测：全模块唯一的模块级 `os` 使用）⇒ 删掉 `import os` 后，
    #   模块在 **exec（导入）阶段第 33 行就崩**，而 `exec` 当时写在 `try` 之外
    #   ⇒ NameError 直接冒泡出本函数，被 main 打成 💥（这就是那条红的样子）。
    #   ★ 更要紧的一层：那时的崩与 `cmd_daemon` 那条分支**毫无关系** ——
    #     任何模块删掉 os 都会在第 33 行死 ⇒ **负控分辨力为零**，
    #     它测的从来不是它声称测的东西（死判据族的新变体：活着，但测错了对象）。
    #   ⇒ 变异形态改为**只在这条分支的作用域里屏蔽 `os`**：原样导入（模块级那次
    #     os 已用完），再把模块全局里的 `os` 拿掉 ⇒ 分支里的 `os.getpid()`
    #     （309 行）全局查找不到 ⇒ NameError。这样测到的才是
    #     「这条分支是否真的依赖 os」——若哪天它改用别的写法，变异后就不崩，
    #     本负控会如实报「负控失效」，而不是像旧版那样恒红或恒绿。
    mut = types.ModuleType("inbox_cli_ns20")
    mut.__file__ = p
    sys.modules["inbox_cli_ns20"] = mut
    try:
        exec(compile(src, p, "exec"), mut.__dict__)              # noqa: S102
        mut.__dict__.pop("os", None)                             # ← MUTANT
        rc, out, err = _s20_run(mut)
    finally:
        # ★ 旧版 `exec` 在 try 外 ⇒ exec 一崩，sys.modules 里的坏品种就滞留。
        sys.modules.pop("inbox_cli_ns20", None)
    if not err:
        return _raise("负控失效：拿掉 import os 后该分支仍不抛 ⇒ S20 是装饰")
    if "NameError" not in err:
        return _raise("负控失效：崩是崩了，但不是预期的 NameError（%r）" % (err,))
    import inbox_cli as CLI
    rc2, _out2, err2 = _s20_run(CLI)
    if err2:
        return _raise("还原后真身仍崩（%s）⇒ 补丁没修对，或尺子被弄坏了" % (err2,))
    return "变异后必崩（%s），真身仍通过" % err


# ══════════════════════════════════ 运行 ═══════════════════════════════════
def _raise(msg):
    """把"说明性失败"统一抛成 AssertionError（main 里照常报红＋打明细）。"""
    raise AssertionError(msg)


# ══════════════════════════════════════ S58 契约存在性（2026-10-22）═══════
#: ★★ 为什么编号是 S58 而不是 S21：S01–S57 全仓已占（S21 在 0400，S22–S57 在
#:   其他套件）。编号唯一性是铁律，跳号无害、撞号致命。落笔前用脚本扫过全仓。
#:
#: 这一条来自 2026-10-22 的一次核查：**设计件写了要求、代码里没有，而没有任何
#: 判据检查「要求的实体是否存在」**。三处同型缺口（`chain_link_ok` 未实现、
#: 睡眠证据源零实现、新文件未登 manifest）都是这一个洞的产物。
#: ⇒ 做成双向对账：
#:   ① 白名单里的符号必须真的能取到；
#:   ② 取不到的必须**显式登记**并带补齐计划（否则红）；
#:   ③ 登记了但实际已存在的 ⇒ 也红（表过期＝有人实现了没销账）。
#: 为什么不做「全文扫描设计件」：那需要一份长期维护的豁免表，而本仓纪律是
#: **小而准的判据优于大而漏的判据**。白名单是 F1 冻结的最小集，先守住它。

#: F1 白名单（冻结件 §F1 第 93 行）—— ★ 本表是**实测落点**，不是照抄设计件：
#:   §F1 把 `write_health` 写成 `host_shield.write_health()`，实测在 `audit_chain`；
#:   §10.1（同件、带行号实证）写的是 `audit_chain.write_health()` ⇒ 以 §10.1 为准。
#:   已登记为第 53 号猜测点（同一份设计件两处自相矛盾）。
_WHITELIST = (
    ("host_shield", "guard_posture"),
    ("host_shield", "sentinel_heartbeat_age"),
    ("host_shield", "armed_state"),
    ("host_shield", "self_check"),
    ("audit_chain", "write_health"),          # #53：§F1 笔误
    ("granary", "state"),
    ("egress", "capacity"),
    ("inbox_model", "day_counts"),
    ("inbox_model", "ledger_rows"),
    ("inbox_model", "unrepaired_count"),
    ("host_matrix", None),                    # 「现探结果」＝模块级（tools/host_matrix.py）
    ("audit_chain", "chain_link_ok"),         # §10.1 要求新增（现未实现）
)

#: 已登记、**尚未实现**的条目。每项必须带非空补齐计划；空计划 ⇒ 红（不是豁免）。
_EXPECTED_MISSING = {
    "audit_chain.chain_link_ok":
        "DAG-1 前补薄包装（§10.1 已冻结落点：复用 verify_chain 的 index_file/classify，"
        "校验范围＝当日文件）；未补前 F1 按 §7.2 走 trace.missing 记名",
}

#: 设计件（反向对账用；不在本树时 SKIP 这一段，**不记绿**）
_DOC_IFACE = os.path.join("docs",
                          "Antinel·编码前无猜测审核与接口冻结 v1.0（2026-10-22）.md")


def _wl_key(modname, sym):
    return "%s.%s" % (modname, sym or "<module>")


def _wl_has(modname, sym):
    """(ok, why)。`host_matrix` 在 `tools/` 下，需单独入 path。"""
    import importlib
    tools = os.path.join(ROOT, "tools")
    if tools not in sys.path:
        sys.path.insert(0, tools)
    try:
        mod = importlib.import_module(modname)
    except Exception as e:                                   # noqa: BLE001
        return False, "import %s 失败：%r" % (modname, e)
    if sym is None:
        return True, ""
    if not hasattr(mod, sym):
        return False, "%s 里没有 %s" % (modname, sym)
    return True, ""


def _s58_problems():
    """S58 的纯函数版 —— 判据与负控共用同一段判断，负控才不会量错东西。"""
    bad = []
    for modname, sym in _WHITELIST:
        key = _wl_key(modname, sym)
        ok, why = _wl_has(modname, sym)
        plan = (_EXPECTED_MISSING.get(key) or "").strip()
        if ok:
            if key in _EXPECTED_MISSING:
                bad.append("%s 已实现但仍在 _EXPECTED_MISSING 里 —— 表过期，须销账"
                           % key)
            continue
        if not plan:
            bad.append("%s 取不到且未登记补齐计划 —— %s" % (key, why))
    return bad


@check("S58 冻结件白名单的代码实体真实存在（设计写了、代码没有 ⇒ 必须登记并带计划）")
def s58():
    bad = _s58_problems()
    assert not bad, "；".join(bad)
    doc = os.path.join(ROOT, _DOC_IFACE)
    if not os.path.exists(doc):
        # ★ 测不出 ⇒ 明说跳过，**不许静默当绿**（铁律 1）
        return "白名单全部取到；设计件不在本树，反向对账 SKIP（不记绿）"
    with open(doc, encoding="utf-8") as f:
        txt = f.read()
    lost = [nm for (m, s) in _WHITELIST for nm in [s or m] if nm not in txt]
    assert not lost, ("判据表里的 %r 在设计件里找不到 —— 两边各写各的（漂移）"
                      % sorted(set(lost)))
    return "%d 个符号全部取到，且设计件逐名可查" % len(_WHITELIST)


@check("N-S58 负控：抹掉补齐计划 / 塞一个假符号 ⇒ S58 必须报红")
def n_s58():
    # ① 先把当前状态钉住：必须绿（否则负控无意义）
    assert not _s58_problems(), "负控前置失败：S58 现在就是红的"
    # ② 抹掉补齐计划 ⇒ 必须红
    saved = dict(_EXPECTED_MISSING)
    try:
        _EXPECTED_MISSING.clear()
        assert _s58_problems(), "清空补齐计划后 S58 仍绿 —— 负控失效"
    finally:
        _EXPECTED_MISSING.clear()
        _EXPECTED_MISSING.update(saved)
    # ③ 塞一个全树不存在的符号 ⇒ 必须红
    global _WHITELIST
    old = _WHITELIST
    try:
        _WHITELIST = old + (("host_shield", "__no_such_symbol_zz"),)
        assert _s58_problems(), "塞入假符号后 S58 仍绿 —— 负控失效"
    finally:
        _WHITELIST = old
    # ④ 还原后必须回到绿（判据不许有副作用）
    assert not _s58_problems(), "负控还原后 S58 仍红 —— 判据有副作用"
    return "三种改法各自真红，还原后回绿"


def main():
    print("=" * 78)
    print("0.37.3 判据 —— 六态封闭 ＋ 已敲定词表不漂移（全部内存变异，不写盘）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                why = ""
            print("  ✅ %-52s %s" % (name, why or ""))
            ok += 1
        except AssertionError as e:
            print("  ❌ %-52s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-52s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
