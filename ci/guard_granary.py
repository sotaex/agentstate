#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.38.0 判据 —— 粮（哨兵的口粮）的**三条铁律 ＋ 账本边界**。

★★ 为什么要有它（创始人 2026-10-09 那三句「一定要机制上解决」的同一条纪律）：
  粮的三条铁律（**现阶段不出售 / 不可转让 / 不可兑换**）如果只写在
  `granary.py` 的注释里，那么下一轮（可能是另一个模型、另一个上下文）
  随手加一个"赠送粮""粮换积分"的入口，**没有任何东西会红**。
  ⇒ 本文件把三条铁律从"注释里的约定"变成"可执行、会报红、有负控的机制"：
    ① G1-granary 现阶段**不卖**：充值是**声明占位**，没有可用购买路径（含 §D 敞口 4 的
       流程约束：`RECHARGE.enabled` 一翻就红）；
    ② G2-granary **不可转让、不可兑换**：`granary` 公开面里没有这类入口，
       加/减粮的写入口**恰为** `grant` / `spend`；
    ③ G3 **用词黑名单**：对外文本不得出现 返利／返佣／下线／团队／层级；
    ④ G4 **两本账不混**：`antinel 粮`（哨兵口粮）与 `antinel credits`
       （宿主工具烧的积分）是两条命令、两本账。

★★ 本文件的编写纪律（沿用本仓惯例）：
  · **每条判据都配负控**：把被测机制故意改坏，判据必须报红。没有负控的判据
    只是一段会执行的代码。
  · **判据只查行为**：真 import 模块、真读规则表、真跑 CLI；不靠正则猜源码意图。
  · ★★★ **本文件绝不写盘**（不改任何产品文件）：负控全部走**内存变异＋还原**，
    因此可以安全地留在打包前的闸门里。
"""
from __future__ import annotations

import inspect
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

RESULTS = []


def check(name):
    def deco(fn):
        RESULTS.append((name, fn))
        return fn
    return deco


# ══════════════════════════════════════════════════════ 真源常量 ══════════
#: ★ 对外文案黑名单（创始人 2026-10-09 拍板 B 案时明示的观感风险）。
#:   每一项写清为什么被禁，避免下一轮有人"觉得这词挺好"又加回来。
BANNED_IN_TEXT = {
    "返利": "把粮说成返钱，直接引导读者往「拉人头返现金」上想",
    "返佣": "同上，且「佣」字带交易意味",
    "下线": "传销特有词；我们说的是「邀请好友」",
    "团队": "层级计酬的暗示词；粮不分层",
    "层级": "同上",
}

#: ★ 禁止出现在 `granary` **公开可调用面**里的名字（转让/兑换/买卖入口的信号词）。
#:   查的是**函数名**（行为入口），不是注释 —— `不可转让` 这四个字本身当然要能写。
STORE_ENTRY_WORDS = ("transfer", "redeem", "exchange", "gift", "buy",
                     "purchase", "sell", "pay", "trade")

#: 加/减粮**只允许**这两个公开写入口。
WRITE_ENTRIES = {"grant", "spend"}


def _raise(msg):
    """把"说明性失败"统一抛成 AssertionError（main 里照常报红＋打明细）。"""
    raise AssertionError(msg)


# ══════════════════════════════════════ G1-granary 现阶段不卖 ════════════════════
@check("G1-granary 粮不卖（现阶段）：充值是声明占位，无可用购买路径")
def g1():
    import granary as G
    rc = getattr(G, "RECHARGE", None)
    if not isinstance(rc, dict):
        return _raise("granary 没有 RECHARGE 声明 —— 将来有人加了充值路径也没人看得见")
    if rc.get("enabled") is not False:
        return _raise("充值通道被打开了（enabled=%r）⇒ 必须**同批**复核方案 §D 敞口 3/4"
                      "并改本判据，不许单独先开充值" % (rc.get("enabled"),))
    # 获得规则里不许存在"花钱买粮"的发放入口
    for _grp, rows in G.RULES_GRANT.items():
        for name, _amt, freq in rows:
            blob = "%s %s" % (name, freq)
            for w in ("购买", "充值", "付费", "买入"):
                if w in blob:
                    return _raise("获得规则里出现付费入口：%s" % blob)
    return "RECHARGE.enabled=False；获得规则 0 个付费项"


@check("N-G1-granary 负控：把充值开关打开 ⇒ G1-granary 必须抓到")
def n_g1():
    import granary as G
    orig = dict(G.RECHARGE)
    caught = False
    try:
        G.RECHARGE["enabled"] = True
        try:
            g1()
        except AssertionError:
            caught = True
    finally:
        G.RECHARGE.clear()
        G.RECHARGE.update(orig)
    if not caught:
        return _raise("把 RECHARGE.enabled 改成 True，G1-granary 仍判通过 ⇒ 售卖防线没守住")
    try:
        g1()
    except AssertionError as e:
        return _raise("还原后 G1-granary 仍判红 ⇒ 还原链路坏了：%s" % e)
    return "充值开关一翻即红；还原后回绿"


# ══════════════════════════════ G2-granary 不可转让 / 不可兑换 ═══════════════════
def _store_entries(mod):
    """`granary` 公开面里名字像"转让/兑换/买卖"的可调用入口。"""
    pub = [n for n, o in vars(mod).items()
           if not n.startswith("_") and (inspect.isfunction(o) or inspect.isclass(o))]
    return sorted(n for n in pub
                  if any(w in n.lower() for w in STORE_ENTRY_WORDS))


@check("G2-granary 粮不可转让、不可兑换（公开面里也没有这类入口）")
def g2():
    import granary as G
    bad = _store_entries(G)
    if bad:
        return _raise("granary 出现转让/兑换/买卖入口：%s" % bad)
    pub = [n for n, o in vars(G).items()
           if not n.startswith("_") and inspect.isfunction(o)]
    writers = sorted(n for n in pub if n in WRITE_ENTRIES)
    if set(writers) != WRITE_ENTRIES:
        return _raise("加/减粮的写入口不止 grant/spend：%s（多一个入口就是多一条"
                      "能长出货币性的路）" % writers)
    return "无转让/兑换/买卖入口；写入口恰为 grant/spend"


@check("N-G2-granary 负控：往 granary 塞一个 transfer 入口 ⇒ G2-granary 必须抓到")
def n_g2():
    import granary as G
    if hasattr(G, "transfer"):
        return _raise("`transfer` 已存在 —— 本负控要验的是「新加会被抓到」")

    def transfer(*_a, **_k):                    # noqa: D401  (负控用假入口)
        """（负控注入的假入口：把粮转给别人。）"""
    G.transfer = transfer
    caught = False
    try:
        try:
            g2()
        except AssertionError:
            caught = True
    finally:
        del G.transfer
    if not caught:
        return _raise("塞进 `transfer` 入口，G2-granary 仍判通过 ⇒ 不可转让没守住")
    try:
        g2()
    except AssertionError as e:
        return _raise("还原后 G2-granary 仍判红 ⇒ 还原链路坏了：%s" % e)
    return "注入 transfer 入口即红；还原后回绿"


# ══════════════════════════════════ G3 用词黑名单 ════════════════════════
def _banned_hits(blobs):
    """`[(来源, 文本)]` → 命中清单。"""
    out = []
    for src, text in blobs:
        for w, _why in BANNED_IN_TEXT.items():
            if w in (text or ""):
                out.append("%s 含「%s」" % (src, w))
    return out


def _text_blobs():
    """全部**对外文本**的来源（术语表 ＋ 粮规则 ＋ 路由文案）。"""
    blobs = []
    import glossary as GL
    for k, t in GL.TERMS.items():
        blobs.append(("术语 %s" % k, " ".join(str(v) for v in t.values())))
    import granary as G
    blobs.append(("粮规则表", " ".join(
        str(x) for grp in G.RULES_GRANT.values() for row in grp for x in row)))
    blobs.append(("粮充值声明", str(G.RECHARGE)))
    import antinel
    for u, c, cat in antinel.ROUTES:
        blobs.append(("路由文案 %s" % cat, "%s %s" % (u, c)))
    return blobs


@check("G3 对外用词黑名单：返利/返佣/下线/团队/层级 一律不出现")
def g3():
    hits = _banned_hits(_text_blobs())
    if hits:
        return _raise("；".join(hits))
    return "术语/粮规则/充值声明/路由文案 0 命中（黑名单 %d 词）" % len(BANNED_IN_TEXT)


@check("N-G3 负控：往术语里写「返利」 ⇒ G3 必须抓到")
def n_g3():
    import glossary as GL
    k = "__negctl_g3__"
    GL.TERMS[k] = {"w": "x", "one": "邀请返利，上不封顶。",
                   "inc": "x", "exc": "x", "unit": "x"}
    caught = False
    try:
        try:
            g3()
        except AssertionError:
            caught = True
    finally:
        GL.TERMS.pop(k, None)
    if not caught:
        return _raise("写进「返利」，G3 仍判通过 ⇒ 用词黑名单没守住")
    try:
        g3()
    except AssertionError as e:
        return _raise("还原后 G3 仍判红 ⇒ 还原链路坏了：%s" % e)
    return "「返利」被抓到；还原后回绿"


# ══════════════════════════════ G4 两本账不混 ════════════════════════════
def _grain_route_problem(routes):
    """纯函数：`ROUTES` 必须有 `antinel 粮`，且不许与 credits 混写。"""
    cmds = [c.strip() for _u, c, _k in routes]
    grain = [c for c in cmds if c.startswith("antinel 粮")]
    if not grain:
        return "ROUTES 里没有 `antinel 粮` —— 粮没有对外入口"
    for c in grain:
        if "credits" in c:
            return "粮的命令里混进了 credits（两本账混写）：%s" % c
    return None


@check("G4 粮与 credits 是两条命令、两本账（且 `antinel 粮` 真能跑）")
def g4():
    import antinel
    p = _grain_route_problem(antinel.ROUTES)
    if p:
        return _raise(p)
    env = dict(os.environ)
    env["ANTINEL_HUB_DIR"] = tempfile.mkdtemp(prefix="granary_guard_")
    for args, must in ((["粮"], "粮"), (["粮", "规则"], "邀请好友")):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "antinel.py")] + args,
                           cwd=ROOT, env=env, capture_output=True, timeout=90)
        out = r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")
        if r.returncode != 0:
            return _raise("`antinel %s` 跑不动（rc=%d）：%s"
                          % (" ".join(args), r.returncode, out[:160]))
        if must not in out:
            return _raise("`antinel %s` 输出里没有 %r（命令没接上？）：%s"
                          % (" ".join(args), must, out[:160]))
    return "路由含 `antinel 粮`、未混 credits；CLI 实跑两条子命令均通过"


@check("N-G4 负控：把粮命令与 credits 混写 ⇒ G4 必须抓到")
def n_g4():
    import antinel
    orig = list(antinel.ROUTES)
    caught = False
    try:
        antinel.ROUTES.append(("x", "antinel 粮 credits 混装", "账本"))
        if _grain_route_problem(antinel.ROUTES):
            caught = True
    finally:
        antinel.ROUTES[:] = orig
    if not caught:
        return _raise("把粮命令与 credits 混写，G4 仍判通过 ⇒ 两本账边界没守住")
    if _grain_route_problem(antinel.ROUTES):
        return _raise("还原后 ROUTES 仍判有问题 ⇒ 还原链路坏了")
    return "混写被抓到；还原后 ROUTES 回绿"


# ══════════════════════════════════════ 运行 ═════════════════════════════
def main():
    print("=" * 78)
    print("0.38.0 判据 —— 粮的三条铁律 ＋ 账本边界（全部内存变异，不写盘）")
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
