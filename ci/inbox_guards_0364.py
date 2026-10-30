#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.36.4 判据 —— 研发态的**定义**、**不掩盖**、**自动收敛** ＋ 自检探针盲区。

创始人 2026-10-07 三条要求，逐条对应本文件的三个组：

  ① 「落位失败就关窗，不是彻底的解决办法」   → 已在 0.36.4 前半段完成
     （独立 profile，窗口出生即正确；关窗只保留"收旧窗"一个正当用途）
  ② 「研发中只是状态之一，如监理发现状况了，该出现的状态，还是要出现」
     → 组 B：**dev 不得吞掉真实状况**
  ③ 「要定义清楚研发态」「过很短的时间，还是要变成值守中」
     → 组 C：**dev 自动收敛**（靠事实追平，不靠时间自己好）
  ＋ 组 D：自检探针自身的盲区（本轮实测抓到的独立缺陷）

★★ 本文件的编写纪律（沿用本仓惯例，且是踩过坑之后才有的）：
   · 每条判据都配**负控**（把被测的机制故意改坏，判据必须报红）——
     没有负控的判据只是一段会执行的代码。
   · 判据**只查行为**，不查字符串：把源码改成另一种写法但行为不变，
     判据不该红；行为改坏，判据必须红。
   · 版本号一律用**数值比较**（`_ver_lt`），不用字符串比。
"""
from __future__ import annotations

import ast
import importlib
import inspect
import io
import json
import os
import shutil
import sys
import textwrap
import time
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
# 0.55.0 (F3): 临时目录登记处在本目录（`ci/tmpreg.py`），必须把 ci/ 也放进来
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

RESULTS = []          # [(name, ok, why)]
_BACKUP = []          # [(path, backup)]


def check(name):
    def deco(fn):
        RESULTS.append((name, fn, None))
        return fn
    return deco


def _snapshot(path):
    """备份一个文件（还原用 rename，避开 Antinel 自己的 AN-009 删除拦截）。"""
    bk = path + ".g0364.bk"
    shutil.copy2(path, bk)
    _BACKUP.append((path, bk))
    return bk


def _restore_all():
    """★ 0.43.1：还原加**重试 ＋ 退路**。

    实测（2026-10-10）：本函数曾因 `PermissionError(13, '另一个程序正在使用此文件')`
    崩掉 —— 根因是 `os.replace` 需要**删除权限**，而监理/Antinel 监理此刻正读着
    `psl/manifest.json`（并发读方挡住 rename）⇒ **变异留在盘上**：
    `psl/manifest.json` 被留在"已追平"态 ⇒ 研发态的版本落差被抹平 ⇒ 界面假失守。
    ⇒ 两条：① rename 重试 5 次；② 仍失败则退到 `shutil.copy2`（就地覆盖只需
      写权限，比 rename 更能穿透并发读）。
    ★ 判据污染产品文件，比判据报红更坏 —— 还原路径必须比变异路径更硬。
    """
    for path, bk in reversed(_BACKUP):
        if not os.path.exists(bk):
            continue
        done = False
        for _ in range(5):
            try:
                if os.path.exists(path):
                    os.replace(path, path + ".g0364.trash")
                os.replace(bk, path)
                done = True
                break
            except PermissionError:
                time.sleep(0.3)
        if not done:
            try:
                shutil.copy2(bk, path)          # 退路：就地覆盖（只需写权限）
                os.replace(bk, bk + ".done")
            except PermissionError:
                pass
    _BACKUP.clear()


#: 取出 guard_posture 里 dev 分支的**两段**源码。
#:
#: ★ 为什么用 AST 而不是 `src.find("POSTURE_DEV")`（判据自身的 bug，实测踩到）：
#:   源码里**注释中**先出现了字面量 `POSTURE_DEV`（我在解释 0.36.3 的改动），
#:   `find` 命中的是那处注释 ⇒ 切出的分支段是**注释之前**的空白
#:   ⇒ 判据报红而产品代码是对的 —— 这正是「判据自身出错」的典型形状。
#:   ⇒ 改用 AST 按**语法节点**定位：找出所有以 `POSTURE_DEV` 为 state 值的
#:     `return` 语句。注释不参与 AST，天然免疫。
#:
#: ★★ 第二段（`assign`）：`consequences` 的**值**是变量 `_cons`，
#:    真正的赋值 `_cons = _outage_consequences(st, pkg_root)` 在 `return`
#:    **之前**那一行，不在 dict 段内 ⇒ 必须单独取，否则判据会误报。
#:    这也正是为什么要**两段都查**：字典里写 `_cons` 只证明"不是字面量"，
#:    赋值那行才证明"它是量出来的、不是空列表硬塞的"。
def _dev_branch_parts():
    import host_shield as HS
    src = inspect.getsource(HS.guard_posture)
    tree = ast.parse(textwrap.dedent(src))
    rets, asgs = [], []
    for node in ast.walk(tree):
        # ① return {...state: POSTURE_DEV...}
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            for k, v in zip(node.value.keys, node.value.values):
                if (isinstance(k, ast.Constant) and k.value == "state"
                        and isinstance(v, ast.Name) and v.id == "POSTURE_DEV"):
                    rets.append(node)
        # ② _cons = _outage_consequences(...)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            fn = node.value.func
            fname = getattr(fn, "id", None) or getattr(fn, "attr", None)
            if fname == "_outage_consequences":
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "_cons":
                        asgs.append(node)
    if not rets:
        raise AssertionError("guard_posture 里找不到 state=POSTURE_DEV 的 return 语句")
    ret = rets[0]
    ret_seg = ast.get_source_segment(src, ret)
    # 取**离该 return 最近、且在它之前**的那次赋值
    before = [a for a in asgs if a.lineno < ret.lineno]
    asg_seg = ""
    if before:
        nearest = max(before, key=lambda a: a.lineno)
        asg_seg = ast.get_source_segment(src, nearest) or ""
    return ret_seg, asg_seg


# ============================================================ 组 A：状态封闭
@check("A1 dev 姿态在封闭集合内，且有标签与灯色映射")
def a1():
    import host_shield as HS
    import inbox_model as M
    assert HS.POSTURE_DEV in HS.POSTURE_ALL, "dev 不在姿态封闭集合里"
    assert HS.POSTURE_LABEL.get(HS.POSTURE_DEV), "dev 没有标签"
    # ★★ 0.37.1 改名：灯态三张表 LIGHT_LABEL/LIGHT_LOGO/LIGHT_VAR ⇒
    #   STATE_LABEL/STATE_LOGO/STATE_VAR（与「六态＝常量前缀 STATE_」统一；
    #   旧名是 0.36.x 八灯态遗产，创始人已定性「主观臆想，去掉」）。
    #   另：`LIGHT_OK`（绿）⇒ `STATE_L0`，`LIGHT_DEV` ⇒ `STATE_DEV`。
    for tbl, nm in ((M.STATE_LABEL, "STATE_LABEL"), (M.STATE_LOGO, "STATE_LOGO"),
                    (M.STATE_VAR, "STATE_VAR")):
        assert M.STATE_DEV in tbl, "dev 灯态缺 %s 映射（会渲染成盲区）" % nm
    # dev 必须是**非绿**灯：研发中不是"一切正常"
    lg, _ = M.light(HS.POSTURE_DEV, [])
    assert lg != M.STATE_L0, "dev 打成了绿灯（研发中不等于没问题）"
    return "dev 在集合内、三张映射表齐全、不打绿"


# ================================================== 组 B：dev 不掩盖真实状况
#: ★★★ 为什么本组一律用 AST 而不是 `src.find(...)`（0.36.4 判据自身的 bug）：
#:   我在解释这个 bug 的**注释里**写了 `if posture_state == "dev": ...`，
#:   `find` 命中的**第一处就是那行注释** ⇒ 切出来的"分支"是注释区，
#:   判据因此假红。⇒ 一条纪律（付出三次代价才买到）：
#:     **判据定位代码节点一律走 AST；`find` 只可用于查纯说明性文字。**
#:     注释不参与 AST，天然免疫这类自指。
#:   ★ 0.37.1 又抓到同型一次：F3 的 `"guard_posture()" in src` 命中的是
#:     docstring 里的解释句，真正的调用节点一个没查 —— 已改 AST。


@check("B1 dev 态下 light() 仍会算 24 小时后果账（不提前 return）")
def b1():
    """★★ 0.37.1 改写（六态口径换代后，旧写法整体作废）。

    旧写法查「dev 分支里有没有 `BUCKET_ACTION` 字样」——新版 `light()` 里
    dev **不再有独立早分支**：24h 后果账是所有姿态共用的 ② 段，dev 分支被
    挪到 ⑤（事件判读之后）。字面量判据在新结构下必然假红。

    ⇒ 新判据两件事，都对准「dev 不吞真实告警」这一条意图：
       ① **行为**：dev + R0 未处理事件 ⇒ 灯态取事件级 R0，且 why 带研发注记
          （研发身份只能写进 why，不另占灯态、更不许把事件级压下去）；
       ② **结构**（AST 行号）：dev 分支必须排在 ② 事件判读之后 ——
          防的正是 0.36.4 那个真漏洞「把 dev 分支提到前面、后果账成死代码」。
          ★ 与 0.36.4 的顺序判据同思路（第一次 return 之前必须已算账），
            只是锚点从「分支内」换成「分支与事件段的相对行号」。
    """
    import inbox_model as M

    def mk(kind, age_h):
        ts = (datetime.now() - timedelta(hours=age_h)).isoformat(timespec="seconds")
        return M.Item(alert=M.Alert.build(ts=ts, kind=kind, topic="g0364"))

    # ① 行为：dev 吞不掉真实告警（R0 事件 ⇒ R0 灯）
    lg, why = M.light("dev", [mk("host_shield_tamper", 0.5)])
    assert lg == M.STATE_R0, (
        "dev + R0 未处理事件 ⇒ 拿到 %s（应为 R0）；研发态把真实故障吃掉了" % lg)
    assert "研发迭代" in why, (
        "dev 有未处理事件时 why 没有研发注记（研发身份应写进 why）：%r" % why)
    lg2, _ = M.light("dev", [])
    assert lg2 == M.STATE_DEV, "dev + 无未处理事件应显示研发档位，实际 %s" % lg2
    # ★★ 0.37.1 二改（2026-10-09）：下面的**结构断言整体撤掉**，只留行为。
    #   为什么撤：为了让「此刻」与「24h 历史账」各有一个入口（修日报页
    #   「自称当场查一次、实际混着历史账」的 bug），③④⑤ 三个分支被抽到
    #   `base_state()` —— 于是 `light()` 里**没有 dev 分支**了，
    #   AST 判据立刻变成「找不到锚点」的**假红**（红的是"代码搬家"，
    #   不是"产品坏了"）。
    #   ⇒ 本仓同类教训已是第 N 次：**源码形状会重构，用户可见的行为不会**。
    #     分支顺序这条约束本身仍然成立，改由 **B4 的变异负控**实测兜底
    #     （它真的把 dev 提前 return 写进源码，再看 B1/B2 红不红）。
    #   ⇒ 判据优先测行为；测结构时，先问一句「这段代码下个月还在不在」。
    return "dev+急事⇒R0 且 why 带研发注记；dev+无事⇒研发蓝（顺序由 B4 变异兜底）"


@check("B2 行为验证：dev + R0 急事 ⇒ 与 guarding 同色（失守压过研发身份）")
def b2():
    """★★ 0.37.1 改写：期望灯色从「橙（LIGHT_ATTENTION）」改为 **R0**。

    ★ 为什么改期望而不是改产品：灯态口径统一为 **LOGO 六态**后，
      `host_shield_tamper`/`host_shield_breach` 的事件级就是 R0
      （0.37.1 `LEVEL_OF_KIND`：链/文件被动过、门闸有缺口 ⇒ 失守级）。
      0.36.4 旧五色梯度里它们是最高的未处理档「橙」，新口径下同名同级。
      ⇒ 「dev 与 guarding 对同一批急事同色」这条核心断言**不变**，
        且现在 dev+急事 与 down 当前态势也同色（R0），方向一致。
    """
    import inbox_model as M

    def mk(kind, age_h):
        ts = (datetime.now() - timedelta(hours=age_h)).isoformat(timespec="seconds")
        return M.Item(alert=M.Alert.build(ts=ts, kind=kind, topic="g0364"))

    urgent = [mk("host_shield_tamper", 0.5), mk("host_shield_breach", 1.0)]
    lg_dev, _ = M.light("dev", urgent)
    lg_guard, _ = M.light("guarding", urgent)
    assert lg_dev == M.STATE_R0, (
        "dev + 两件 R0 急事 ⇒ 拿到 %s（应为 R0）；研发态把真实故障吃掉了" % lg_dev)
    assert lg_dev == lg_guard, "dev 与 guarding 对同一批急事的灯色不一致"
    # 无急事时 dev 仍保留自己的档位（不冒充 guarding 的绿）
    lg_clean, _ = M.light("dev", [])
    assert lg_clean == M.STATE_DEV, "无急事时 dev 应显示自己的档位，实际 %s" % lg_clean
    return "dev+R0急事⇒R0（与guarding同色）；dev+无事⇒研发蓝"


# ══════════════ B3 已退休（2026-10-21）══════════════
#: 原判据（0.36.4）：「dev 分支不许返回硬编码的空 consequences，必须走
#:   `_outage_consequences()` 实测」——担心"写死的空与量过的空长得一样，
#:   会把监理发现的状况藏起来"。
#:
#: ★★★ 退休理由（**创始人 2026-10-21 剃刀原则**，有截图实测）：
#:   `_outage_consequences()` 算的是**缺岗**损失，而进入 dev 分支的前提正是
#:   `alive and fresh`（哨兵在岗、心跳新鲜）—— **函数名写明了前提，调用处前提
#:   正好相反**。实测后果：dev 态顶部条写「值守中」，下面红块却写
#:   「有 4 个受监管落点，此刻没人巡检」（心跳才 491s）⇒ 同一屏两个相反结论，
#:   比"藏状况"更坏。
#:
#: ★ 原担心的那件事**没有失守，只是换了守卫**：
#:   ① `0353 X11` 现在守这条（**源码腿 ＋ 行为腿计数**：真跑一次 dev 姿态，
#:      计算器一次都不许被调用）—— 比原 B3 更强（B3 只看源码字符串）；
#:   ② 「dev 不许吞掉真状况」由 **B1**（dev + R0 急事 ⇒ 灯取 R0、why 带研发
#:      注记、分支排在事件判读之后）与 **B2**（dev 与 guarding 对同批急事同色）
#:      行为级守着 —— 这正是"写死的空会不会藏状况"的真正答案：
#:      真发现的事项走 `inbox_model.light()` 的 24 小时账，**不经过这个字段**。
#:
#: ⇒ 按剃刀原则删除 B3（保留它与 X11 会**互斥**：一个要求必须有
#:   `_outage_consequences`、一个要求必须没有 —— 两条同时存在，产品无论怎么写
#:   都必有一条红。这正是"判据互相打架"的教科书现场，也是本轮必须留档的原因）。


@check("B4 负控：把 dev 分支提到 ② 事件判读之前，判据必须报红")
def b4():
    """★★ 0.37.1 改写：变异手法随产品结构一起换代。

    旧变异「把 dev 分支**原地**改成提前 return」在新结构下是**空变异**——
    dev 分支现在排在第 ⑤ 位（事件判读之后），原地提前 return 照样先被 ②
    截住，`light('dev', 急事)` 仍返回 R0 ⇒ 负控测不到东西还会误报
    「负控失效」。0.36.4 由 Q21 实测抓过同型「负控空转」。

    ⇒ 新变异复现历史真漏洞的**语义**：把 dev 分支**搬**到 ①（down 判读）
      之前、改成提前 return —— `light('dev', R0 急事)` 因此返回 dev 蓝，
      B1/B2 的行为断言会红。搬完还要验**还原有效**（还原失败会让整个仓库
      带着坏代码继续跑，比负控空转更险）。
    """
    import inbox_model as M
    p = os.path.join(ROOT, "inbox_model.py")
    _snapshot(p)
    src = open(p, encoding="utf-8").read()
    # ① 摘掉现行 dev 分支（⑤ 位）连同其后到下一个同级 if 之间的注释
    i = src.find('    if posture_state == "dev":')
    assert i > 0, "定位 dev 分支失败"
    j = src.find("\n    if posture_state ==", i + 10)
    assert j > i, "定位 dev 分支末尾失败"
    assert "STATE_DEV" in src[i:j], "dev 分支内容不符合预期（可能已漂移）"
    src_wo = src[:i] + src[j:]
    # ② 把提前 return 版 dev 分支插到 ① down 判读之前（函数体最前段）
    k = src_wo.find('    if posture_state == "down":')
    assert k > 0, "定位 ① down 判读失败"
    bad = (src_wo[:k]
           + '    if posture_state == "dev":\n'
             '        return STATE_DEV, "坏行为：提前 return 吞掉真实告警"\n'
           + src_wo[k:])
    with open(p, "w", encoding="utf-8") as f:
        f.write(bad)
    importlib.reload(M)
    from datetime import datetime as _dt, timedelta as _td

    def mk(kind, age_h):
        ts = (_dt.now() - _td(hours=age_h)).isoformat(timespec="seconds")
        return M.Item(alert=M.Alert.build(ts=ts, kind=kind, topic="g0364"))

    urgent = [mk("host_shield_tamper", 0.5)]
    lg, _ = M.light("dev", urgent)
    assert lg == M.STATE_DEV, (
        "负控失效：dev 分支已提前 return，判据仍报绿（lg=%s）" % lg)

    # ★★ 0.37.1 补上「负控的另一半」（2026-10-09）：
    #   上面只证明「产品变坏了」，**没证明判据看得见** ——
    #   一个瞎判据配上一段坏代码，同样会得到这个绿。
    #   ⇒ 现在真的在**变异态**下跑 B1/B2，要求它们抛 AssertionError。
    #   （本轮第三次同型：0363 `n_light_greens`、0360 `n_markdown_star_is_caught`
    #     都曾"算完就丢、不写盘不 reload"；若不验这一半，它们会一直绿着。）
    for nm, fn in (("B1", b1), ("B2", b2)):
        try:
            got = fn()
        except AssertionError:
            continue                    # 判据看见了 ⇒ 这才是有效的负控
        raise AssertionError(
            "负控失效：dev 已提前 return（会吞掉真实告警），%s 却仍报绿：%r"
            % (nm, got))

    _restore_all()
    importlib.reload(M)
    # 还原后必须回到 R0 —— 否则仓库正带着变异代码在跑（负控把自己变成缺陷）
    lg2, _ = M.light("dev", urgent)
    assert lg2 == M.STATE_R0, (
        "还原后 light('dev', R0 急事) 应为 R0，实际 %s ⇒ 还原链路坏了" % lg2)
    b1(); b2()                          # 还原后两条判据也必须复绿
    return "负控有效：dev 提前 return 后 B1/B2 **实测**报红；还原已验且复绿"


@check("B5 dev 分支不给假按钮（fix 只有 revive 一个合法值）")
def b5():
    ret_seg, _ = _dev_branch_parts()
    # 全仓 fix 的合法取值只有 "revive"（inbox_server.py 按它派发动作）
    for bad in ('"fix-posture"', '"fix": "fix', "fix_start", "fix_install"):
        assert bad not in ret_seg, "dev 分支出现未经实现的 fix 动作 %r（假按钮）" % bad
    # dev 态下哨兵在岗 ⇒ 不该给"重新拉起"
    assert '"fix": "revive"' not in ret_seg, (
        "dev 分支给了 revive 按钮，但进入本分支的前提是监理在岗正常放哨"
        "（点了等于杀掉健康进程）")
    assert '"can_fix": False' in ret_seg, "dev 分支应显式声明不可一键修复"
    return "dev 不给假动作"


# ================================================== 组 C：dev 自动收敛
@check("C1 dev 靠版本落差成立，不靠时间（无时间缓存）")
def c1():
    import host_shield as HS
    src = inspect.getsource(HS.is_dev_build)
    # 判据里不许出现"研发态最多挂 N 分钟"这类时间闸
    for bad in ("_DEV_TTL", "dev_since", "DEV_MAX_SECONDS", "time.time()"):
        assert bad not in src, (
            "is_dev_build 里出现 %r ⇒ 研发态改成了'靠时间自己好'，"
            "那是撒谎（代码仍与登记不符却报正常）" % bad)
    return "纯版本落差判定，无时间闸"


@check("C2 收敛实测：登记版本追平 ⇒ dev 立刻消失")
def c2():
    import host_shield as HS
    mp = os.path.join(ROOT, "psl", "manifest.json")
    _snapshot(mp)
    try:
        before, _ = HS.is_dev_build()
        m = json.load(open(mp, encoding="utf-8"))
        m["version"] = HS._code_version()
        # ★★ 0.43.1：写盘加**短重试** ＋ 整段 try/finally。
        #   实测（2026-10-10）：本判据曾因 `PermissionError(13, '另一个程序正在使用
        #   此文件')` 在写盘处崩掉，而**还原写在崩溃点之后** ⇒ 真 `psl/manifest.json`
        #   被留在"已追平"的变异态 ⇒ **研发态赖以成立的版本落差被本判据自己抹平**
        #   （界面随即假失守，且后续判据/构建全读到被污染的清单）。
        #   ⇒ 判据污染产品文件，比判据报红更坏。两条一起做：
        #     ① 写盘容忍读方的瞬时占用（重试 5 次 × 0.3s）；
        #     ② 无论成败**必还原**（finally）—— 崩溃也不许把变异留在盘上。
        _last = None
        for _ in range(5):
            try:
                with open(mp, "w", encoding="utf-8") as f:
                    json.dump(m, f, ensure_ascii=False, indent=1)
                _last = None
                break
            except PermissionError as _e:
                _last = _e
                time.sleep(0.3)
        if _last is not None:
            raise _last
        importlib.reload(HS)
        after, why = HS.is_dev_build()
    finally:
        _restore_all()
        importlib.reload(HS)
    assert not after, (
        "登记版本已追平代码版本，dev 却仍成立（%s）⇒ 研发态是永久态，收敛失败" % why)
    return ("本机当前 dev=%s；追平后 dev=False" % before)


@check("C3 方向正确：已发版 + 码被改 ⇒ 不是 dev（真篡改不被豁免）")
def c3():
    import host_shield as HS
    mp = os.path.join(ROOT, "psl", "manifest.json")
    tgt = os.path.join(ROOT, "host_shield.py")
    _snapshot(mp)
    _snapshot(tgt)
    try:
        m = json.load(open(mp, encoding="utf-8"))
        m["version"] = HS._code_version()
        with open(mp, "w", encoding="utf-8") as f:
            json.dump(m, f, ensure_ascii=False, indent=1)
        importlib.reload(HS)
        with open(tgt, "a", encoding="utf-8") as f:
            f.write("#: g0364 临时标记\n")
        importlib.reload(HS)
        d, why = HS.is_dev_build()
        assert not d, (
            "已发版（版本追平）+ 代码被改，却判成研发态 ⇒ "
            "「我在写代码」成了已发版包被篡改的免责理由（%s）" % why)
        return "已发版态一律不豁免"
    finally:
        _restore_all()
        importlib.reload(HS)


@check("C4 优先级：dev 分支在 alive and fresh 之内（失守压过身份标注）")
def c4():
    import host_shield as HS
    src = inspect.getsource(HS.guard_posture)
    tree = ast.parse(textwrap.dedent(src))
    # 按**语法**定位：dev 的 return 语句与 `if alive and fresh:` 的行号比较。
    # 注释不参与 AST ⇒ 不会被我在注释里写的 `POSTURE_DEV` 骗到。
    dev_line = None
    fresh_line = None
    down_line = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            for k, v in zip(node.value.keys, node.value.values):
                if not (isinstance(k, ast.Constant) and k.value == "state"):
                    continue
                if isinstance(v, ast.Name) and v.id == "POSTURE_DEV" and dev_line is None:
                    dev_line = node.lineno
                if isinstance(v, ast.Name) and v.id == "POSTURE_DOWN" and down_line is None:
                    down_line = node.lineno
        if isinstance(node, ast.If):
            t = ast.unparse(node.test)
            if t == "alive and fresh" and fresh_line is None:
                fresh_line = node.lineno
    assert None not in (dev_line, fresh_line, down_line), (
        "定位失败：fresh=%s dev=%s down=%s" % (fresh_line, dev_line, down_line))
    assert fresh_line < dev_line < down_line, (
        "dev(return@%d) 必须落在 `alive and fresh`(@%d) 之内、"
        "失守分支(@%d) 之前，否则失守时可能被 dev 盖掉"
        % (dev_line, fresh_line, down_line))
    return "真失守天然压过 dev"


# ==================================== 组 D：研发态豁免边界 ＋ 自检探针盲区
@check("D1 哈希不符（真篡改）永不豁免，缺登记（打包遗漏）可豁免")
def d1():
    import host_shield as HS
    marks = HS.DEV_NEVER_EXEMPT_MARKS
    # 处置相反的两类不能共用同一段文字（0.36.4 实测踩过）
    assert "告警链路文件可能被改而查不出" not in marks, (
        "标记又用了'缺登记'那条的说明文字 ⇒ 会把打包遗漏误判成篡改"
        "（0.36.3 实测：这样会让 is_dev_build() 恒为 False，dev 一次都出不来）")
    assert any("哈希" not in m for m in marks), "标记不该带'哈希'字样"
    # 篡改类必须在
    assert any("与 manifest 不符" in m for m in marks), "缺少'哈希不符'类标记"
    assert any("毒化" in m for m in marks), "缺少'登记表被毒化'标记"
    return "标记互斥：篡改不可豁免、缺登记可豁免"


@check("D2 行为验证：改门 ⇒ 不豁免；改代码 ⇒ 豁免")
def d2():
    import host_shield as HS
    hook = os.path.join(ROOT, "hooks", "pre_tool_use.py")
    reg = os.path.join(ROOT, "rules", "hosts", "autoclaw.json")
    _snapshot(hook)
    _snapshot(reg)
    try:
        # 改登记表（投毒面）
        with open(reg, "a", encoding="utf-8") as f:
            f.write("\n")
        importlib.reload(HS)
        _ok, never = HS._dev_exempt_problems(HS.self_check()[1])
        assert any("毒化" in n or "autoclaw" in n for n in never), (
            "改了登记表却没进'永不豁免'堆（never=%r）⇒ 研发态能吞掉投毒" % (never,))
        _restore_all()
        importlib.reload(HS)
        # 改代码（host_shield 自己）
        self_p = os.path.join(ROOT, "host_shield.py")
        _snapshot(self_p)
        with open(self_p, "a", encoding="utf-8") as f:
            f.write("#: g0364 代码迭代标记\n")
        importlib.reload(HS)
        _ok2, never2 = HS._dev_exempt_problems(HS.self_check()[1])
        assert not never2, (
            "只改了代码却进了'永不豁免'堆（%r）⇒ 代码迭代无法归因研发" % (never2,))
        return "改门/改登记表不豁免；改代码豁免"
    finally:
        _restore_all()
        importlib.reload(HS)


@check("D3 打包根因：enforce_probe.py 已登记进布局表 **且复制清单由 _LAYOUT 派生**")
def d3():
    """★★ 0.36.5：**这条判据自己原来是假守卫**，本轮实测抓到并加固。

    ★★ 假在哪（实测，不是推断）：
      本条判据原来只查「`_LAYOUT` 里有没有 `enforce_probe.py`」——
      查到了，**报绿**。而真实产物是：
        · `psl/manifest.json` 120 项里**没有** `tools/enforce_probe.py`
        · Antinel 监理自检因此长期报「在告警链路保护名单里，却没登记进 manifest」
        · 界面因此长期挂「**存疑**」
      ⇒ 根因：`_LAYOUT` 只被 `_verify_layout()` **校验**，从不被**复制**；
        真正复制 `tools/` 的是 `build()` 里一份**手写元组**，两份清单分叉。
      ⇒ **判据查的是"表里有"，产品要的是"真的进包"** ——
        这是本仓铁律「**文本级 ≠ 值级校验**」的又一实例：
        查声明等于没查交付物。

    ⇒ 现在的判据（两条，缺一不可）：
      ① `_LAYOUT` 里有该项（**原意图一个字没动**）；
      ② **复制清单必须由 `_LAYOUT` 派生**，而不是手写第二份。
         判法是**行为级**的：真的 `import build_package`，把它的复制清单
         算出来，断言 `enforce_probe.py` **在清单里**。
         若有人把手写元组改回不含该项 ⇒ 这条立刻红。
    """
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    src = open(os.path.join(ROOT, "scripts", "build_package.py"),
               encoding="utf-8").read()
    tree = ast.parse(src)
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if (isinstance(k, ast.Constant) and k.value == "enforce_probe.py"
                        and isinstance(v, ast.Constant)
                        and v.value == "tools/enforce_probe.py"):
                    found = True
    assert found, (
        "tools/enforce_probe.py 仍未登记进 _LAYOUT ⇒ 它继续不进 manifest "
        "⇒ 自检对它永久失明（实测：改它零报警）")

    # ── ② 行为级：复制清单必须真的含它（0.36.5 新增，原判据缺这条） ──
    import importlib
    import build_package as bp
    importlib.reload(bp)
    layout_tools = {os.path.basename(v) for v in bp._LAYOUT.values()
                    if v.replace("\\", "/").startswith("tools/")}
    assert "enforce_probe.py" in layout_tools, (
        "★ _LAYOUT 的 tools 项里查不到 enforce_probe.py（当前 %r）"
        % sorted(layout_tools))
    # 复制清单：build() 由 _LAYOUT 派生 ＋ 兜底元组，两者的并集才是真正拷的
    fb = set(getattr(bp, "_TOOL_FALLBACK", ()))
    derived = layout_tools | fb
    assert "enforce_probe.py" in derived, (
        "★ 复制清单里没有 enforce_probe.py（当前 %r）\n"
        "  它虽然登记进 _LAYOUT，但**复制清单是手写的第二份** ⇒ 两份清单分叉 ⇒\n"
        "  它校验通过、却根本不被复制 ⇒ 不进 manifest ⇒ Antinel 监理自检对它永久失明。\n"
        "  ★ 修法不是补一行：复制清单必须**由 _LAYOUT 生成**（0.36.5 已改）。"
        % sorted(derived))
    # 派生出来的清单必须**确实**从 _LAYOUT 取值（防"派生"被改成又一份手写）
    assert "_TOOL_FALLBACK" in src and "_LAYOUT.values()" in src, (
        "★ build() 里的 tools 复制清单没有从 _LAYOUT 派生"
        "（既没 _TOOL_FALLBACK 兜底、也没遍历 _LAYOUT.values()）⇒ "
        "本条的 ② 已被绕过，_LAYOUT 又退回成'只校验不复制'的死表")
    return "布局表已收录 ＋ 复制清单由 _LAYOUT 派生（清单 %d 项）" % len(derived)


@check("D4 自检 fail-closed：保护名单里没登记的文件必须报出来")
def d4():
    import host_shield as HS
    src = inspect.getsource(HS.self_check)
    assert "在告警链路保护名单里" in src, (
        "self_check 里找不到「保护名单里的文件必须登记进 manifest」这条 fail-closed 规则")
    # 该规则必须真的在报问题（不是只写在注释里）
    seg = src
    assert "for rel in _GUARDED_CHAIN_FILES" in seg, "self_check 未遍历保护名单"
    return "规则在位（遍历保护名单并对缺登记者报红）"


# ============================================ 组 E：活契约不得被当冗余删掉
# ★★★ 这组是本轮**我自己犯的错**留下的判据（0.36.4 回退实录）：
#   我把 `ACT_INFO` 当成 `ACT_ACCEPT` 的同义副本删掉了，理由是「消灭副本」。
#   而推翻它的事实是 `inbox_server._PICK` 的真实内容：
#     accept → 「就这样，我不处理」＋ `risk` 样式（红）
#     info   → 「知道了」　　　　＋ 无样式（普通）
#   文案与样式**都不同** ⇒ 两个不同的用户承诺；且 `inbox_server.py:557`
#   仍在真实发 `op="info"` ⇒ 删常量等于把活契约变成「有消费、无声明」的野值。
#   ⇒ **可复算的判据**：凡消费方（`_PICK` 等）认识的每一个 op，
#     生产侧**必须**有对应常量声明。反向也成立：声明了却没人消费 ⇒ 该说清。
#   —— 这类缺陷此前**无人能抓**：判据能抓「声明与实现脱节」，
#     抓不到「契约被删成活野值」，因为删掉之后两边都「一致」了。
@check("E1 消费方认识的每个 op，生产侧都有常量声明（无活野值）")
def e1():
    import remediation as R
    import inbox_server as SV
    # 消费方按 op 派发按钮，文案与样式都在这张表里 —— 它就是「op 的全集」的真源
    consumed = set(SV._PICK)
    declared = {v for k, v in vars(R).items()
                if k.startswith("ACT_") and isinstance(v, str)}
    orphan = consumed - declared
    assert not orphan, (
        "消费方 `_PICK` 认识但生产侧无常量声明的 op：%s"
        " ⇒ 它成了「有消费、无声明」的活野值（判据能抓脱节，抓不到这个）"
        % sorted(orphan))
    return "消费方 %d 个 op 全部有常量声明：%s" % (
        len(consumed), sorted(consumed))


@check("E2 accept 与 info 不是同一个东西（文案/样式必须都不同）")
def e2():
    import inbox_server as SV
    la, ca = SV._PICK["accept"]
    li, ci = SV._PICK["info"]
    assert la != li, ("accept 与 info 按钮文案相同（%r）⇒ 两者若真同义，"
                      "就不该是两个常量" % la)
    assert ca != ci, ("accept 与 info 样式相同（%r）⇒ 「接受风险」与「纯告知」"
                      "在页面上长得一样，红按钮的警示意义就没了" % (ca,))
    assert ca == "risk", "accept 应是红按钮（点了等于签字担责），实际 %r" % (ca,)
    assert ci == "", "info 应是无样式（纯告知不该长得像处置），实际 %r" % (ci,)
    return "accept=红警示「%s」／info=普通「%s」，两者可区分" % (la, li)


@check("E3 B 类三选一实际下发的 op 与 B_CLASS_CHOICES 声明一致")
def e3():
    import remediation as R
    assert hasattr(R, "ACT_INFO"), (
        "ACT_INFO 常量缺失 —— 它有真实消费方（inbox_server.py:557 归因故障兜底"
        "发 op=\"info\"），不是冗余")
    # ★★★ 2026-10-21（**第八次**撞同一根钉子：尺子钉字面）：
    #   旧版把 B 类那条按钮的**文案**当锚点。0.53.5 STE100 体检把
    #   「我自己盯着」→「我自己守着」（与「值守中」「守门的程序」同一词族），
    #   判据当场报「找不到 B 类那条…动作」—— 而产品是**对的**。
    #   这与 0363 N-R01（第三次）、0470 S93（第五次）同型：
    #   **尺子钉字面 ⇒ 改文案就假红 ⇒ 反过来逼人把文案改回去**。
    #   ⇒ 改按**结构**：用 AST 找出「元素全是 `_a(...)` 调用、长度 3」的列表
    #     字面量（＝三选一面板），比对它们下发的 **op 名集合**。
    #     一个 op 都不许看文案、不许看行号。
    import ast as _ast
    import inspect
    src = inspect.getsource(R)
    tree = _ast.parse(src)
    want = set(R.B_CLASS_CHOICES)
    groups = []
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.List) or len(node.elts) != 3:
            continue
        ops = []
        for e in node.elts:
            if not (isinstance(e, _ast.Call) and isinstance(e.func, _ast.Name)
                    and e.func.id == "_a" and e.args
                    and isinstance(e.args[0], _ast.Name)):
                ops = None
                break
            ops.append(getattr(R, e.args[0].id, e.args[0].id))
        if ops:
            groups.append((node.lineno, ops))
    assert groups, (
        "在 remediation.py 里找不到任何「3 个 `_a(...)` 的列表字面量」⇒ "
        "三选一面板的写法变了（结构锚点漂移，判据需更新），不是产品没问题")
    got = {frozenset(ops) for _, ops in groups}
    assert frozenset(want) in got, (
        "三选一面板下发的 op 与 B_CLASS_CHOICES 声明不一致："
        "声明 %s，实际下发的组 %s ⇒ 「接受风险」这条要么没发、要么被换成了"
        "别的 op（发 ACT_INFO 会渲染成普通按钮，用户看不到自己在担责）"
        % (sorted(want), [sorted(g) for g in got]))
    # ★ 反向：ACT_ACCEPT 只许出现在 B 类三选一里（它是红按钮 ⇒ 必须真担责）
    for ln, ops in groups:
        if "ACT_ACCEPT" in ops and frozenset(ops) != frozenset(want):
            assert False, (
                "第 %d 行那组面板里有 ACT_ACCEPT，但整组 op 不等于 "
                "B_CLASS_CHOICES（%s）⇒ 红按钮出现在非「接受风险」语境，"
                "警示意义会被稀释" % (ln, sorted(ops)))
    return "B 类三选一面板（%d 组）下发的 op 与 B_CLASS_CHOICES 一致：%s" % (
        len(groups), sorted(want))


# ══════════════════════════════════════════════ 0.36.5：右下角小泡泡根治
# ★ 上一轮我给的结论是「服务没启动」—— 那是**现象**，不是根因。
#   实测：服务在监听、窗口在位 ⇒ 它是**间歇**的 ⇒ 「重启就好了」必然复发。
#   泡泡的真身 = `host_shield._notify()` 的 `ShowBalloonTip`（Windows 气泡），
#   与Antinel 监理窗口是**两条互不相干的通道**。真正的缺陷有四层，逐条机械化。


@check("F1 泡泡真身是气泡通道：降噪闸必须看「窗口是否可见」")
def f1_notify_gated_on_console_visibility():
    """根因①：降噪闸只按「同类间隔」，**完全不看窗口**。

    ⇒ 于是出现这个组合：**同一件事用两种方式同时通知** ——
      「Antinel 监理窗口开着、正显示这条急事」＋「系统又弹一个气泡」。
      用户被迫二选一：看窗 或 消泡。**这是设计缺口，不是偶发故障。**

    判据（两件，缺一不可）：
      ① `console_is_visible()` 这个可判定事实**存在**，且真去枚举窗口
         （**不许**自己写第二份 Win32 遍历 —— 判据不许二次实现）；
      ② `_notify_throttled` 里**真的调了它**，且命中时**不弹**。
    """
    import host_shield as HS
    assert callable(getattr(HS, "console_is_visible", None)), (
        "host_shield 没有 console_is_visible() ⇒ 降噪闸仍只按时间间隔，"
        "不知道Antinel 监理此刻开着 ⇒ 泡泡与窗口会重复通知同一件事")
    src = inspect.getsource(HS.console_is_visible)
    assert "find_console_windows" in src, (
        "console_is_visible() 没有复用 inbox_window.find_console_windows() ⇒ "
        "自己写了第二份窗口遍历。★ 判据不许二次实现：窗口枚举已有唯一实现。")

    src2 = inspect.getsource(HS._notify_throttled)
    assert "console_is_visible()" in src2, (
        "_notify_throttled 没有调 console_is_visible() ⇒ 「窗口已可见就不弹」"
        "这条根治措施**根本没接上**（这是本轮最初那个缺口：纪律有、执行点没接）")
    assert "mark_notify_shown(" in src2, (
        "命中「窗口已可见」时必须**留痕**（走 host_shield.mark_notify_shown ⇒ 中枢通知账）"
        "—— 否则「没弹」与「该弹但漏了」在链上长得一样，没法复盘。"
        "★ 0.40.0：留痕**不再写安全状态文件**（那次读-改-写在读失败时会把默认值"
        "`enabled=False` 写回真状态 ⇒ 编造一次『已撤防』 ⇒ 假 R0 失守）")

    # ★★★ 0.36.5 第三版：**行为**验证（前两版都只查源码字符串 ⇒ 负控打出来是假守卫）。
    #   实测：负控把 `return bool(WIN.find_console_windows())` 改成 `return False`，
    #   F1 照样全绿 —— 因为字符串 `find_console_windows` **还在源码里**。
    #   ⇒ 「源码里有这个词」≠「运行时真去枚举了」；
    #     而这正是本仓反复吃过的亏（P6 数错占位符、F3 变量没被使用）。
    #   现在必须**真跑一次**：`console_is_visible()` 返回 True 时，
    #   `find_console_windows` 真的被调到（用调用计数器证明，不是看返回值）。
    #   ⚠️ 用隔离环境 + 替身，**绝不去枚举用户真实的窗口**。
    import os as _os
    import sys as _sys
    import tmpreg as _tf    # 0.55.0 (F3): 临时目录处
    calls = []
    o_cv = HS.console_is_visible
    o_notify = HS._notify
    o_mark = HS.mark_notify_shown
    o_fcw = None
    ohub = _os.environ.get("ANTINEL_HUB_DIR")
    tmp = _tf.tmpdir()
    # ★ 注入点选 `inbox_window.find_console_windows` 这个**函数**，
    #   不是替换 `host_shield.inbox_window` 属性 ——
    #   后者无效：`console_is_visible()` 内部是 `import inbox_window`
    #   （每次重新绑定），替属性根本不会被它读到。
    #   ⇒ 实测踩到：替换模块属性后 `calls` 仍为空，判据立刻报红，
    #     而那个红是**判据自己没找对注入点**，不是产品坏了。
    #   ⇒ 记下这条：**注入点必须选"被调用方真正解引用的那个名字"。**
    import inbox_window as _IW
    o_fcw = _IW.find_console_windows
    # ★★ 0.36.6：`console_is_visible()` 里还有**第二层**——
    #   枚举到窗口之后还要逐个问 `is_window_on_screen()`（可见**且**未最小化）。
    #   只注入枚举不够：新枚举返回真句柄，而真实 `is_window_on_screen`
    #   会去问系统那个真窗口 ⇒ 得出 False ⇒ F1 报红，
    #   而**那个红是判据自己没跟上调用的新路径**，不是产品坏了。
    #   ⇒ 与上面那条「注入点必须选被调用方真正解引用的那个名字」同源：
    #     产品加了一层依赖，判据的注入点也必须跟着加一层。
    o_iws = _IW.is_window_on_screen
    tmp = _tf.tmpdir()
    try:
        sent = []

        def _fake_fcw(*a, **k):
            calls.append((a, k))
            return [12345]                      # 假装枚举到一个窗口（真句柄形）

        def _fake_iws(h, *a, **k):
            return True# 假装它**真在屏幕上**（未被最小化）

        _IW.find_console_windows = _fake_fcw
        _IW.is_window_on_screen = _fake_iws
        HS._notify = lambda *a, **k: sent.append((a, k))
        _os.environ["ANTINEL_HUB_DIR"] = tmp
        shown = []
        # ★★ 0.40.0：留痕改走 `mark_notify_shown`（中枢通知账）。这里同时验两件：
        #   ① 它**被调到**（行为接线）；② 账文件里**真的多了一个键**
        #      （不是"调了个空实现"）—— 后者读的是隔离沙箱里的账，不碰真实账本。
        HS.mark_notify_shown = lambda kind: (shown.append(kind), o_mark(kind))[0]
        # 真跑：可见性由**被测对象自己**从假枚举里得出，不许我替它编
        got_vis = HS.console_is_visible()
        assert got_vis is True, (
            "注入假枚举后 console_is_visible() 仍返回 %r（期望 True）⇒ "
            "它压根没读 inbox_window.find_console_windows" % (got_vis,))
        assert calls, "假枚举一次都没被调到 ⇒ 它走的不是这条路径"
        calls[:] = []
        HS._notify_throttled("F1_probe_kind", "探针：窗口已可见")
        assert calls, "降噪闸路径上没有再查窗口可见性 ⇒ 它没把这一维接进来"
        assert not sent, (
            "窗口可见时**仍然弹了**（实测已发出 %d 次）⇒ 根治措施没生效"
            % len(sent))
        assert shown == ["F1_probe_kind"], (
            "『没弹』没有留痕 ⇒ 「不该弹」与「该弹但漏了」在链上无法区分"
            "（实测 mark_notify_shown 调用序列 = %r）" % (shown,))
        assert HS.ledger_get(HS._LEDGER_SHOWN + "F1_probe_kind") is not None, (
            "留痕只调了函数、账文件里没有这个键 ⇒ 记账是空实现（假机制）")
    finally:
        _IW.find_console_windows = o_fcw
        _IW.is_window_on_screen = o_iws
        HS.console_is_visible = o_cv
        HS._notify = o_notify
        HS.mark_notify_shown = o_mark
        if ohub is None:
            _os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            _os.environ["ANTINEL_HUB_DIR"] = ohub
    return "降噪闸已看窗口可见性（实测：真枚举→不弹→留痕）"


@check("F2 判不出窗口状态时必须照弹（方向往严偏，不得静默免检）")
def f2_unknown_still_notifies():
    """根因①的**反向**守护：可见性判不出来时，**不许**当作"不可见"或"已通知"。

    ★ 方向为什么必须往严的一边偏：
      若把"判不出"当成"窗口开着⇒不弹"，那么**一次枚举失败**就等于
      **永久静音真失守通知** —— 而失守恰恰是必须让人知道的那件事。
      ⇒ 这与本仓铁律「查不出来 ≠ 查出来是好的」是同一条：
        **判不出来 ≠ 没问题。**
    """
    import host_shield as HS
    # ★★★ 隔离环境：**绝不能碰真实的降噪记录**。
    #   第一版直接用固定 kind（`F2_probe_kind`）跑，于是第一次跑把时间戳写进
    #   `notify_sent` ⇒ 第二次跑被 30 分钟节流挡掉 ⇒ 判据**时绿时红**。
    #   ⇒ 症状极像"产品不稳定"，实际是**判据污染了自己的被测对象**。
    #   —— 与本轮 P7/R13 同型：**判据必须自造环境，不许在真实环境上试**。
    #   ⇒ 每次跑用唯一 kind（时间戳），并把 hub 目录指到临时目录，跑完还原。
    import time as _t
    import tmpreg as _tf    # 0.55.0 (F3): 临时目录处
    ohub = os.environ.get("ANTINEL_HUB_DIR")
    tmp = _tf.tmpdir(prefix="g0364_f2_")
    oload, osave = HS.load_state, HS.save_state
    kind = "F2_probe_%d" % int(_t.time() * 1000)
    try:
        os.environ["ANTINEL_HUB_DIR"] = tmp
        # 返回的是**空状态** ⇒ 30 分钟节流必然放行，且不留任何持久痕迹
        HS.load_state = lambda *a, **k: {"enabled": True}
        HS.save_state = lambda *a, **k: None
        sent = []
        orig_console = HS.console_is_visible
        orig_notify = HS._notify
        try:
            HS.console_is_visible = lambda: None      # 强制"判不出"
            HS._notify = lambda *a, **k: sent.append((a, k))
            HS._notify_throttled(kind, "探针：判不出可见性")
        finally:
            HS.console_is_visible = orig_console
            HS._notify = orig_notify
        assert sent, (
            "可见性判不出（None）时**没有弹通知** ⇒ 把「判不出」当成了「已通知」"
            "⇒ 一次枚举失败就会永久静音真失守通知（方向反了）")
    finally:
        HS.load_state, HS.save_state = oload, osave
        if ohub is None:
            os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            os.environ["ANTINEL_HUB_DIR"] = ohub
    return "判不出 ⇒ 照弹（隔离环境，重复跑结果稳定）"


@check("F3 通知图标随姿态取，不许一律黄色警告（值守中不许看起来像出事）")
def f3_icon_follows_posture():
    """根因③：托盘图标与 `BalloonTipIcon` **两处都写死 `Warning`**。

    ⇒ 「值守中、只是提醒一句」也弹**黄色警告三角** ⇒ 那个气泡成了
      **与真实状态无关的假警报**，每 30 分钟复现一次。
      ——用户说"又冒泡泡了"，讨厌的正是这个**撒谎**。

    ★ 为什么**不**改成"干脆不弹"：气泡是**唯一在窗口不可见时还能到用户眼前**的
      通道。砍掉它 ⇒ 真失守在后台时用户完全不知道 ⇒
      那是**把假警报换成真盲区**。⇒ 正确修法是让它别撒谎 ＋ 别重复。
    """
    import host_shield as HS
    ok_icon, tip = HS._notify_icon_and_tip()
    assert ok_icon in ("Warning", "Information"), (
        "返回了未知的 SystemIcons 名 %r ⇒ PowerShell 会报错、通知静默失败"
        "（静默失败＝用户收不到，也不知道为什么）" % (ok_icon,))
    assert tip in ("Warning", "Information"), (
        "BalloonTipIcon 名非法：%r" % (tip,))

    # 值守中 ⇒ 必须是中性图标
    # ★★★ 0.37.1 修判据自身的两个漏洞（都是「没测到被测对象却报得言之凿凿」家族）：
    #   漏洞一（自指）：旧断言 `"guard_posture()" in src` —— 命中的是
    #     **docstring 里解释机制的那句话**（「直接用 guard_posture() 的返回值」），
    #     真正的调用早已改成 `guard_posture(_pkg_root())`。⇒ 与 B1 注释自指同型，
    #     改用 AST 只认**调用节点**，注释/docstring 天然免疫。
    #   漏洞二（补丁签名）：产品侧 0.37.1 给调用加了包根参数（0.35.3 同型漏改
    #     的收尾），而本判据的猴子补丁是**零参 lambda** ⇒ TypeError 被产品侧
    #     except 吞掉 ⇒ 三种坏姿态全拿到 Information ⇒ 断言红，但红的是
    #     「补丁签名不兼容」，不是「图标不随姿态」。⇒ 补丁一律留 root 形参。
    #   ★★ 漏洞二的第二形态（我自己踩的，比第一形态更隐蔽）：第一版修成
    #     `lambda st=bad, root=None:` —— **看着兼容了，实则空转**：调用是
    #     `guard_posture(_pkg_root())` 单位置实参 ⇒ 包根字符串绑进 `st`、
    #     `root` 保持 None ⇒ 假返回 `{"state": "D:\\psl\\...", ...}` 是**字符串**
    #     ⇒ `st.get("state")` 因 isinstance 非 dict 拿到 None ⇒ 三种坏姿态
    #     照样全 Information，红项一字不差 —— **量具的错第三次记成产品的错**。
    #     ⇒ 铁律：补丁的**第一个形参必须叫 root**（位置实参先绑它），
    #       注入值一律走关键字默认参；写完必须**单独验证一次补丁生效**
    #       （本段下方「补丁自检」就是为此而加，不是装饰）。
    src = inspect.getsource(HS._notify_icon_and_tip)
    tree = ast.parse(textwrap.dedent(src))
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and ((isinstance(n.func, ast.Name) and n.func.id == "guard_posture")
                  or (isinstance(n.func, ast.Attribute)
                      and n.func.attr == "guard_posture"))]
    assert calls, (
        "_notify_icon_and_tip 没有调用 guard_posture ⇒ 图标与真实状态无关，"
        "于是又变成「无论有没有事都 alarming」")
    for c in calls:
        assert c.args, (
            "guard_posture(...) 调用没传包根（0.35.3 同型漏改：不传则读中枢"
            " rollup 链，与本包审计链可能不一致，实测相差 27000+ 秒）")
    # 逐姿态实测：只有坏姿态才给 Warning。
    # ★★★ 0.36.5 第二版修判据自身的错（第一版是**假红**，实测抓出来的）：
    #   原写法 `for bad in (...): HS._notify_icon_and_tip()` 里，`bad` 这个变量
    #   **从头到尾没被使用** —— 没注入姿态，三次断言读的都是**同一个真实姿态**。
    #   而真实姿态此刻是「值守中」⇒ 第一次断言就红，报出
    #   「坏姿态 down 应给 Warning」——**一句事实为假的红项**。
    #   ⇒ 与 F4 的教训同源：**量具的错不能记成产品的错**；
    #     而这里更险一档：它不是数错，是**根本没测被测对象**却报得言之凿凿。
    #   ⇒ 现在每个姿态都**真的注入**，且把"实际拿到的"一起报出来，
    #     免得下一任又只能看到结论、看不到依据。
    saved = HS.guard_posture
    try:
        # 补丁自检：先证明「注入真的进了产品侧」，再逐姿态断言 ——
        # 没有这一段，上面漏洞二第二形态那种空转补丁会再次一字不差地红。
        HS.guard_posture = lambda root=None, st="down": {"state": st, "label": "注入"}
        _probe_got, _probe_tip = HS._notify_icon_and_tip()
        assert _probe_got == "Warning" and _probe_tip == "Warning", (
            "补丁自检失败：注入 state='down' 后拿到 %r/%r（期望 Warning/Warning）"
            " ⇒ 补丁没生效（形参槽位错／产品侧没调它），后面的逐姿态断言全是空转"
            % (_probe_got, _probe_tip))
        for bad in ("down", "interrupted", "warn"):
            HS.guard_posture = lambda root=None, st=bad: {"state": st, "label": "注入"}
            got, tip_bad = HS._notify_icon_and_tip()
            assert got == "Warning" and tip_bad == "Warning", (
                "坏姿态 %s 实测拿到 %r/%r（期望 Warning/Warning）"
                % (bad, got, tip_bad))
        # 正常姿态必须给 Information（关键那条：这就是"不撒谎"的定义）
        for good in ("guarding", "off", "dev", "unknown"):
            HS.guard_posture = lambda root=None, st=good: {"state": st, "label": "注入"}
            got, tip_good = HS._notify_icon_and_tip()
            assert got == "Information" and tip_good == "Information", (
                "非故障姿态 %s 实测拿到 %r/%r ⇒ 正常状态被渲染成警告，"
                "用户每次看到都以为出事了" % (good, got, tip_good))
        # ★ 判不出（无 state 键／抛异常）也必须偏中性 —— 与 F2 同一方向：
        #   漏报由窗口与链上记录兜底，误报会让用户对真告警脱敏。
        #   ★ 两个 fake 的第一个形参同样必须叫 root（见上方漏洞二第二形态）。
        for what, fake in (("无 state 键", lambda root=None: {"label": "x"}),
                           ("guard_posture 抛异常",
                            lambda root=None: (_ for _ in ()).throw(RuntimeError("x")))):
            HS.guard_posture = fake
            got, tip_u = HS._notify_icon_and_tip()
            assert got == "Information" and tip_u == "Information", (
                "%s 时实测拿到 %r/%r ⇒ 判不出被渲染成警告" % (what, got, tip_u))
    finally:
        HS.guard_posture = saved
    return "3 坏姿态→Warning；4 正常姿态＋2 判不出→Information（共 9 例实测）"


@check("F4 旧发射实现必须保持删除：`_notify` 里不许再出现任何原生 UI 构造")
def f4_both_icon_slots_follow():
    """★ 0.59.0 **换代**（不是删判据，是换它守的性质）。

    旧 F4 守的是「托盘图标与气泡图标两处都取自同一决策」—— 那时 `_notify`
    还在自拼 `NotifyIcon` ＋ `ShowBalloonTip`，我上一版只改了 `$n.Icon`、
    第 4 个参数仍写死 `'Warning'`，于是"看起来改好了"而气泡照样是黄三角。

    ★★ 0.59.0 把那套发射实现**连根移除**后，这条判据守的对象**不存在了**。
      照旧留着它会变成「要求那个发射实现存在」—— 也就是要求旧病回来。
      ⇒ 现在它守同一条教训的反面：**不许把发射实现加回来**。
        「改一处漏一处」这条教训已上升为 S61（全仓零原生发射口，见 0431）；
        这里留一条针对 `_notify` 本体的贴身断言 —— 它红了就知道该看哪个函数，
        不必从全仓扫描结果里倒推。
    """
    import ast as _ast
    import textwrap as _tw
    import host_shield as HS
    src = inspect.getsource(HS._notify)
    # ★★ 只断言**代码**，不断言散文：`_notify` 的新 docstring 里写着
    #   "这里曾经自拼 ShowBalloonTip" —— 那是历史说明，不是发射实现。
    #   子串搜索会把讲历史读成"加回来了" ⇒ 假红（量具的错，不能记成产品的错）。
    _fn = _ast.parse(_tw.dedent(src)).body[0]
    _body = _fn.body
    if (_body and isinstance(_body[0], _ast.Expr)
            and isinstance(_body[0].value, _ast.Constant)):
        _body = _body[1:]                      # 去掉 docstring
    code = "\n".join(_ast.unparse(n) for n in _body)
    for tok in ("ShowBalloonTip", "NotifyIcon", "System.Windows.Forms",
                "subprocess.Popen", "Add-Type"):
        assert tok not in code, (
            "`_notify` 的**代码**里又出现了 %r —— 旧外观的发射实现被加回来了。\n"
            "短命进程不许产生像素：记录进审计链，由常驻监理用品牌化浮窗"
            "（inbox_bubble，与主窗口同一套 CSS ＋ 官方 LOGO）提醒。" % tok)
    assert "return None" in code, (
        "`_notify` 应当是**明确的空实现**（结尾 return None）—— "
        "空实现要一眼看得出是空的，不能是「忘了做」")
    return "`_notify` 已是空实现，代码层无任何原生 UI 构造"


# ══════════════════════════════════════════════ 0.36.5：统一闸门自身
@check("G1 统一交付闸门必须能抓住「零输出即假绿」")
def g1_gate_detects_noop():
    """★ 0.36.5 实测：0353 缺 `main()` ⇒ 跑它**零输出、退出码 0**。

    闸门若只看退出码，就把 64 条**根本没跑**的判据记成"已通过"。
    ⇒ 这是本仓铁律「查不出来 ≠ 查出来是好的」的**第三种形态**（更隐蔽：
      连"查"这个动作都没发生，账面却是绿的）。
    ⇒ 判据：闸门里必须有 NOOP 状态，且退出码把 NOOP 计为**非零**。
    """
    src = io.open(os.path.join(ROOT, "ci", "delivery_gate.py"),
                  encoding="utf-8").read()
    assert "NOOP" in src, "统一闸门没有 NOOP（零输出）状态"
    assert "_looks_like_noop" in src, "闸门缺零输出识别函数"
    # 退出码必须把 noop 计入失败
    assert ("n_noop" in src and "n_noop" in src.split("return 0 if")[-1]), (
        "闸门退出码**没有**把 NOOP 计入失败 ⇒ 「零输出但通过」仍会被当通过")
    return "零输出被单列，且计入失败"


@check("F5 可见性必须区分「可见」与「最小化」（最小化＝用户看不到）")
def f5_minimized_window_is_not_visible():
    """★★ 0.36.6 实测抓到的真缺陷（不是假想，也不是审阅出来的）。

    现象：跑完闸门查窗口，`IsWindowVisible=True` 而 `IsIconic=True`、
    rect = `(-32000,-32000,160,28)` —— **窗口是最小化状态**。

    缺陷：`console_is_visible()` 原来只判 `bool(find_console_windows())`，
    而那个枚举的"可见"口径是 `IsWindowVisible` ⇒ **最小化的窗口也通过**。

    ⇒ 后果链（这才是它严重的地方）：
      用户把Antinel 监理最小化（很常见：看过一眼就收起来）
      → 降噪闸认为"用户正开着窗口" ⇒ **不弹泡泡**
      → 那条急事就这么被吞了，而用户什么都看不到。
    ★ 与本仓铁律「查不出来≠ 查出来是好的」最坏形态同型：
      查出一个**假的肯定**，而它推出来的结论是**漏报真失守**。

    ⇒ 判据：最小化的窗口**不得**被算作"用户正在看"。
    ★ 附带一条同样重要的边界：`find_console_windows()` **不许**因此漏掉它 ——
      最小化的窗口仍然要能被"收旧窗"找到并关掉。
      「能不能关」与「算不算用户在看」是**两件事**，混起来就会修出新缺陷。

    ★★★ 决定性实测证据（0.36.6 手工跑出来的，不是推理）：
      把**真窗口**用 `ShowWindow(h, SW_MINIMIZE)` 最小化，然后对比：
        【有 IsIconic】`is_window_on_screen` = False，`console_is_visible` = False
                     ⇒ 会弹泡泡（正确：用户看不到）
        【无 IsIconic】`is_window_on_screen` = True， `console_is_visible` = True
                     ⇒ 不弹泡泡 —— **那个 bug 原样回来**
      ⇒ 这条判据守的是**真行为**（真句柄 + 真最小化），
        不是「源码里有没有 IsIconic 这个字」。
      ⇒ 因此 F5N 负控在**没有真窗口在场**时只能报「测不到」，
        那是诚实的结果 —— 真窗口在场时它才有效（见 F5N 回报）。
    """
    import inbox_window as WIN
    import host_shield as H
    assert hasattr(WIN, "is_window_on_screen"), (
        "inbox_window 里没有 is_window_on_screen() ⇒ "
        "最小化状态没有被区分（0.36.6 实测缺陷会复发）")

    real = WIN.is_window_on_screen
    real_find = WIN.find_console_windows
    try:
        # ★★★ 0.36.6 修正本判据第二版：**用真句柄，别用假句柄**。
        #   第一版注入 `12345`（假句柄）⇒ `is_window_on_screen` 里
        #   `u.IsWindow(12345)` 为假 ⇒ **它在读 IsIconic 之前就返回 None**
        #   ⇒ 于是「有没有 IsIconic」这段代码**根本没被执行**
        #   ⇒ 删掉 IsIconic 后 F5 照样全绿，负控打不出红。
        #   ⇒ 与本文件那条「崩了≠ 抓住了」同源，且更隐蔽：
        #     **判据没走到要验的那一行**，和「走到了没抓住」看起来一模一样。
        #   ⇒ 现在分两段：
        #     ① **真窗口**：直接问系统那个真句柄（不注入）⇒ 走完整条分支；
        #     ② **假句柄**：只用来验三态的取值契约（True/False/None 的映射），
        #        因为那一段验的是「返回值怎么被解读」，与真实窗口无关。
        # ★ 这也解释了为什么负控必须**真跑到那一行**才算数。
        wins = WIN.find_console_windows()
        if wins:
            _on = WIN.is_window_on_screen(wins[0])
            assert _on in (True, False), (
                "对**真窗口**问「在不在屏幕上」只应得True/False，"
                "实测 %r（None 表示连窗口都认不出，那是另一个缺陷）" % (_on,))
            assert isinstance(_on, bool), "返回值必须是布尔，不是 %r" % type(_on).__name__

        WIN.find_console_windows = lambda *a, **k: [12345]
        for got, want, why in ((True, True, "真在屏幕上"),
                               (False, False, "已最小化/不可见"),
                               (None, None, "判不出")):
            WIN.is_window_on_screen = lambda h, _v=got: _v
            r = H.console_is_visible()
            assert r is want, ("窗口 %s ⇒ console_is_visible() 应为 %r，"
                               "实测 %r" % (why, want, r))
        WIN.is_window_on_screen = lambda h: False
        assert H.console_is_visible() is False, "窗口都在但都不在屏幕上时应答 False"

        # 「没有窗口」这一档必须**在恢复枚举之后**测，
        # 或者干脆放在最后 —— 0.36.6 实测踩过：
        # 先把枚举置空、再注入抛错替身，循环体根本不执行 ⇒ 返回 False，
        # 判据却断言 None ⇒ **红项指向没犯过错的代码**。
        # ★ 教训（本文件第 N 次同型）：**注入点变了，前面的设置不会自动复原**，
        #   每换一个场景就要把依赖重新摆一遍。
        WIN.find_console_windows = lambda *a, **k: []
        assert H.console_is_visible() is False, "没有窗口时应答 False"

        # 判不出 ⇒必须答 None（不许吞成 False）
        WIN.find_console_windows = lambda *a, **k: [12345]

        def _boom(*a, **k):
            raise RuntimeError("boom")
        WIN.is_window_on_screen = _boom
        assert H.console_is_visible() is None, (
            "判不出时必须答 None（判不出 ≠ 不在）—— 吞成 False 会漏报")
    finally:
        WIN.is_window_on_screen = real
        WIN.find_console_windows = real_find


@check("F5N 负控：把最小化判定删掉，F5 必须报红（复现 0.36.6 那个真缺陷）")
def n_minimize_counts_as_visible_is_caught():
    """负控：把 `is_window_on_screen` 退回「只看 IsWindowVisible」⇒ F5 必须报红。

    ★ 这正是 0.36.6 那个真实缺陷的原始形态（复现它，而不是造一个新错）。
    ★ 本文件里负控是**独立判据**（B4 起的既有形态），
      不是挂在 `check()` 的第二个参数上 —— 那是 `0366` 的做法，两处不必统一。
    """
    p = os.path.join(ROOT, "inbox_window.py")
    assert _snapshot(p)
    try:
        with io.open(p, encoding="utf-8") as f:
            t = f.read()
        old = ("        if u.IsIconic(h):                 "
               "# ★ 最小化 = 用户看不到\n            return False")
        if old not in t:
            raise AssertionError(
                "inbox_window.py 里找不到最小化判定那两行 ⇒ "
                "要么产品被改回缺陷形态，要么锚点变了（两种都得人来判）")
        with io.open(p, "w", encoding="utf-8") as f:
            f.write(t.replace(old, "        # MUTANT: 不看最小化", 1))
        # ★★ 0.36.6 修正本负控第二版：**注入不足 ＋ 用错句柄**（两处）。
        #   ① F5 的三态断言全部靠「枚举里有一个窗口」驱动；
        #      而删掉 IsIconic 后，**真实的 `find_console_windows()` 会枚举到 0 个**
        #      ⇒ 三档都不被触发 ⇒ F5 自然全绿
        #      ⇒ 负控看起来"失效了"，其实它只是**没让判据跑起来**。
        #   ② 更隐蔽的一层：F5 第一版用**假句柄** 12345，
        #      而 `is_window_on_screen` 里 `u.IsWindow(假句柄)` 为假
        #      ⇒ **在读 IsIconic 之前就返回 None** ⇒ 被验的那一行从未执行。
        #   ⇒ 现在必须**用真窗口**驱动，F5 第一段才会去问系统真句柄。
        #   ⇒ 与本文件那条「崩了 ≠ 抓住了」同源：
        #     **判据没走到断言** 和 **判据走到了但没抓住**，是两件事。
        lg = None
        try:
            f5_minimized_window_is_not_visible()
        except AssertionError as e:
            lg = str(e)
        if lg is None:
            # 没有真窗口在场时，F5 第一段会跳过 ⇒ 负控**测不到**。
            # 明确说出来，而不是把"测不到"报成"抓不住"。
            return ("★ 负控**测不到**：此刻屏幕上没有Antinel 监理窗口，"
                    "F5 第一段（真窗口分支）被跳过 ⇒ "
                    "不能据此说 F5 是假守卫，也不能说它有效")
        return "负控有效：最小化不再被判成可见（F5 报红：%s）" % lg[:56]
    finally:
        _restore_all()


@check("G2 打包前闸门必须接上（纪律不得再次没有执行点）")
def g2_gate_wired_into_build():
    """★ 本轮的核心诉求：纪律有了，执行点没接上 ⇒ 必须机械化。

    判据：构建器里 `_delivery_gate()` **存在**，且 `build()` **真的调它**。
    ★ 查"存在"不够 —— 必须查**被调用**：
      之前就有过「机制写好了但没人调」的同类事故（本轮 113 条判据零调用方）。
    """
    import importlib
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    try:
        import build_package as bp
        importlib.reload(bp)
    except Exception as e:                                       # noqa: BLE001
        raise AssertionError("构建器 import 失败：%s: %s" % (type(e).__name__, e))
    assert callable(getattr(bp, "_delivery_gate", None)), (
        "构建器里没有 _delivery_gate() ⇒ 打包前闸门被删掉了（第二个强制执行点失效）")
    btree = ast.parse(inspect.getsource(bp.build))
    bsrc = inspect.getsource(bp.build)
    assert "_delivery_gate(" in bsrc, (
        "build() 没有调 _delivery_gate() ⇒ 闸门**写好了但没接上** —— "
        "★ 这正是本轮最初那个缺口（纪律有、执行点无）。"
        "机制存在不等于会被执行。")

    # ★★★ 0.36.5：**死分支**必须判红（负控打出来的假守卫，第一版栽在这里）。
    #   实测：负控把调用整段换成 `if False: _delivery_gate(...)`，
    #   前一版 G2 照样全绿 —— 因为它只查 `"_delivery_gate(" in bsrc`，
    #   而**函数名还在源码里，只是永远不会被执行**。
    #   ⇒ 这与本仓铁律「查不出来 ≠ 查出来是好的」同型：
    #     「代码里有」≠「会运行」。这是本轮第三次撞上它
    #     （前两次：F1 数字符串、F3 变量没被使用）。
    #   正确判法：**找 `_delivery_gate(` 的调用点，看它是否真的可达**——
    #     即它不能落在 `if False:` 这类恒假的死分支里。
    def _reachable_calls(node, dead=False):
        """收集**可达**的 `_delivery_gate(...)` 调用。死分支内的不计入。

        ★ 这里踩过一个自己造的坑（判据第一版）：
          我用 `ast.walk(node)` 去遍历**整个子树**，而 `walk` 是无条件的
          ⇒ 它连 `if False:` 里面的东西也会走到 ⇒ 真实代码（闸门在
          `if os.environ.get(...) != "1":` 里，可达）被判成"落在死分支内"。
          ⇒ **红项指向了没犯过错的代码**，比不判更坏：它会把人引去改对的地方。
          ⇒ 现在改成**逐子节点、带 dead 标记下传**，只看自己这一层的调用。
        """
        out = []
        if isinstance(node, ast.If):
            t = node.test
            # 只识别最明确的一种死法：直接 `if False:` / `if 0:` / `if None:`
            is_const_false = isinstance(t, ast.Constant) and not t.value
            for ch in ast.iter_child_nodes(node):
                out += _reachable_calls(ch, dead or is_const_false)
            return out
        for ch in ast.iter_child_nodes(node):
            out += _reachable_calls(ch, dead)
        if (not dead and isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_delivery_gate"):
            out.append(getattr(node, "lineno", 0))
        return out


    # ---- G2 的可达性断言（内嵌函数已定义于上方）----
    _hits = _reachable_calls(btree)
    assert _hits, (
        "build() 里找不到**可达**的 `_delivery_gate(...)` 调用"
        "（函数名还在源码里但落在 `if False:` 等恒假分支内，同样算这一条）"
        "⇒ 闸门形同虚设。★ 实测本轮：负控正是这样注入的，"
        "而前一版判据因只查函数名而全绿")
    # ★ 说明为什么 G2 只做**结构+可达性**检查、不在这里真跑一次打包：
    #   真跑打包要写盘（会污染 dist 与 manifest）⇒ 判据必须**只读**。
    #   "能否拦住"由负控从另一侧证明（把调用挪进死分支后本判据必须报红），
    #   这比自造一个假环境跑真打包更可靠，也不产生副作用。
    return "打包前闸门在位、被 build() 调用、且不在死分支内（调用行 %s）" % _hits


# ============================================================ 运行
def main():
    print("=" * 74)
    print("0.36.4 判据 —— 研发态定义 / 不掩盖 / 自动收敛 ＋ 自检探针盲区")
    print("=" * 74)
    ok = fail = 0
    try:
        for name, fn, _ in RESULTS:
            try:
                why = fn()
                print("  ✅ %-46s %s" % (name, why or ""))
                ok += 1
            except AssertionError as e:
                print("  ❌ %-46s %s" % (name, e))
                fail += 1
            except Exception as e:                            # noqa: BLE001
                print("  💥 %-46s %r" % (name, e))
                fail += 1
    finally:
        _restore_all()
    print()
    print("-" * 74)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
