#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.46.0 判据 —— **删除许可（VCT）**：两票裁决 ＋ 五步顺序 ＋ 四个退出口。

★★ 由来（交接件 §7.3/§7.4，方案 v3.0 §3.4/§3.5/§3.6/§3.7）：

    旧机制「只有一份兜底名单做判据」。名单的**长度**因此变成攻击面的增长点：
    想放行一种新写法 ⇒ 加一条；加一条 ⇒ 绕过的使用成本降一分。而且它治不了
    最日常的那类误拦 —— 「清理构建目录」。

    换判据的来源，而不是给名单加例外：
      第一票 —— 用户自己**声明**过这是产物吗？（版本工具忽略查询，**必须带忽略索引参数**）
      第二票 —— 它真的**能再来一份**吗？（向上查找各生态的构建描述文件）
    两票做**并且**运算；兜底名单**降级**为两票都取不到信号时的最后退路。

★ 四件套（本文件逐条落地）：
    正判据 S80/S81/S82/S83/S84/S85/S86/S87；
    反向对照 N-S80/N-S81/N-S82/N-S83/N-S84/N-S86/N-S87；
    连带对照 S88（既有保护仍绿）＋ 兜底退路的负控 N-S88。
★ 关于「三票各自的负控全在」（交接件 §8 完成判据）：
    设计（§3.4/§3.5/§7.3/§7.4）是**两票**（忽略声明 ＋ 可再生）；§8 里的「三票」是
    旧稿 §2.6 的措辞残留。本文件对**三个信号**都给了负控，无论按哪种口径读都成立：
      第一票（忽略声明）→ N-S80（去忽略索引参数）／N-S84（改用输出串比对）；
      第二票（可再生）　→ N-S87（摘掉「必须是目录」）；
      兜底退路（第三信号）→ N-S88（堵死 fallback_allow 的 continue）。
★ 编写纪律（沿用 0430/0431/0440/0450）：
    · 每条判据配负控，且负控**真的会红**；
    · 断言打在**行为/结构**上，不查文案；
    · **不写任何产品文件**：变异只发生在内存字符串上；夹具只落在临时目录。
"""
from __future__ import annotations

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import tmpreg as _TMP   # 0.55.0 (F3): temp dir registry
import io
import json
import os
import subprocess
import sys
import tempfile
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

RESULTS = []
_HOOK = "hooks/pre_tool_use.py"

#: 各生态的「构建描述文件」中，本仓根上确有的那个 —— 第二票的现成信号源。
_ROOT_DESCRIPTOR = "pyproject.toml"


def check(name):
    """★ 判据**必须真会红** —— 返回说明串一律转成抛异常。"""
    def deco(fn):
        def wrapper():
            r = fn()
            if r is True or r is None:
                return True
            raise AssertionError(r if isinstance(r, str) else repr(r))
        RESULTS.append((name, wrapper))
        return fn
    return deco


def _src(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _load(src, tag):
    """把（可能被变异过的）钩子源码在**内存**里加载成模块，返回该模块。

    ★ 只读：磁盘一个字节都不动（exec 到新建的 ModuleType）。
    """
    mod = types.ModuleType(tag)
    mod.__file__ = os.path.join(ROOT, _HOOK)
    sys.modules[tag] = mod
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)      # noqa: S102
    return mod


def _hook():
    return _load(_src(_HOOK), "ptu0460_live")


def _rules():
    with io.open(os.path.join(ROOT, "rules", "default.json"), encoding="utf-8") as f:
        return json.load(f)["rules"]


def _hits(mod, cmd, project_root=None, rules=None):
    """跑一次真判定路径；返回 `(block 的规则 id 列表, vct 留痕列表, 放行留痕列表)`。"""
    vct, exc = [], []
    h = mod.collect_hits(rules if rules is not None else _rules(), "Bash",
                         {"command": cmd, "file_path": "", "content": "", "url": ""},
                         project_root or ROOT, [], mod.EMPTY_POLICY,
                         workspace_roots=(), excluded_log=exc, vct_log=vct)
    blocks = [x.get("rule_id") for x in h if x.get("action") == "block"]
    return blocks, vct, exc


def _tracked_ignored_file():
    """本仓里**已被追踪、但命中忽略规则**的文件（第一票「忽略优先于追踪」的现成反例）。"""
    try:
        r = subprocess.run(["git", "ls-files", "-i", "-c", "--exclude-standard"],
                           cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=30)
        got = r.stdout.decode("utf-8", "replace").split()
        return got[0] if got else None
    except Exception:                                            # noqa: BLE001
        return None


def _temp_git_repo():
    """造一个**确定性**夹具：临时 git 仓，`gen/` 在忽略规则里，`gen/x.txt` 已被追踪。

    为什么不用本仓现成文件：本仓的 `_archive_dist/*.old` 是历史遗留，某次卫生
    动作后可能不再存在；而这条判据守的是**语义**（忽略声明优先于追踪事实），
    必须**永远**可测，所以夹具自己造。
    """
    d = _TMP.tmpdir(prefix="g0460_git_")
    run = lambda *a: subprocess.run(list(a), cwd=d, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=60)  # noqa: E731
    run("git", "init", "-q")
    with io.open(os.path.join(d, ".gitignore"), "w", encoding="utf-8") as f:
        f.write("gen/\n")
    os.makedirs(os.path.join(d, "gen"))
    with io.open(os.path.join(d, "gen", "x.txt"), "w", encoding="utf-8") as f:
        f.write("x\n")
    run("git", "add", "-f", "gen/x.txt")          # 强制入库 ⇒ 追踪 + 被忽略 同时成立
    return d


def _allowed_fixture():
    """确定性夹具：临时 git 仓，`build/`、`dist/`、`__pycache__/` 既在忽略规则里、又真实存在，
    根上还有构建描述文件（第二票的信号源）。

    ★★ 为什么 S80/S81 必须用夹具、不再用本仓的 `build/` 等真实目录：
      那些目录都在 `.gitignore` 里（干净克隆上根本不存在），而 `build/` 这类**目录专用**
      忽略规则（`build/` 带尾斜杠）对**不存在**的路径**不匹配**。实测：把本仓 `build/`
      改名让开之后，`git check-ignore --no-index build` 返回 1 ⇒ 第一票翻成「受保护」，
      S80/S81 当场红。判据测的是**两票逻辑**，不是「本仓此刻恰好有哪些目录」，
      所以夹具自己造一个稳定的现场（与 `_temp_git_repo` 同族）。
    """
    d = _TMP.tmpdir(prefix="g0460_allow_")
    run = lambda *a: subprocess.run(list(a), cwd=d, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=60)  # noqa: E731
    run("git", "init", "-q")
    with io.open(os.path.join(d, ".gitignore"), "w", encoding="utf-8") as f:
        f.write("build/\ndist/\n__pycache__/\n.psl/\n_archive_dist/\n")
    for sub in ("build", "dist", "__pycache__", ".psl", "_archive_dist"):
        os.makedirs(os.path.join(d, sub))
    with io.open(os.path.join(d, _ROOT_DESCRIPTOR), "w", encoding="utf-8") as f:
        f.write("")
    return d


# ══════════════ C1／M-A · 夹具**自证成立**（量具层 T-08）══════════════
#: 两票**都取不到信号**（不是"投了反对票"）。
def _no_signal(d):
    """`True` ⇔ 这是「**取不到信号**」，不是「**裁决错误**」。

    ★★ 2026-10-13 实测（X-017，全量闸门首跑 29 绿 / 1 红）：
      判据依赖 git 子进程（`check-ignore` / `rev-parse`），而 `VCT_TIMEOUT = 2.0s`
      —— 机器高负载时 git 实测 **1.70s**，就在超时边缘；再忙一点就撞超时。
      **旧版把这种「取不到信号」与「裁决错误」混为一谈**（都报"两票裁决不符"）
      ⇒ 判据把**机器天气**说成了**产品缺陷**。
      ⇒ 这正是 **T-08「查不到就下结论」复发在「量具层」**（产品层早已由
        D-32/S19/W-05 守着）。判据自己也得守同一条纪律。

    ★ 实测有**两种**取不到信号的形状（都在高负载下撞到过，都要认）：
      · `vote1 == "" and vote2 == ""` —— `git rev-parse` 取不到工作树根（出口丙，
        首次 flake 的形状 `build→None//`）；
      · `vote1 == "unavailable"`      —— `git check-ignore` 超时/异常（出口丙，
        并发压测时抓到的形状 `build→None/unavailable/`）。
      两者都是「**取不到**」；`protected` / `not_regenerable` / `outside` 是
      「取到了但值如此」，**不算**取不到。
    """
    return (d.get("vote2", "") == ""
            and d.get("vote1", "") in ("", "unavailable"))


#: 取不到信号时**重读一次**的次数（见 `_read` 的说明）。
_READ_TRIES = 2
#: `_fixture_live` 的尝试次数。★ 0.53.1 由 2 抬到 4：实测本机**任何**进程启动
#: 就要 0.5–0.9 秒（`cmd /c exit` 0.86s、`git --version` 1.1s，杀软实时扫描），
#: 而产品的 `VCT_TIMEOUT = 2.0s` ⇒ 只留 1.8 倍余量，机器一有负载就撞超时。
#: 两次尝试在"瞬时抖动"面前太脆（0.53.1 出包前实测：同一轮里 S80 连撞两次、
#: 紧随其后的 N-S8x 全绿 —— 这就是抖动，不是机器测不了）。
def _read(m, cmd, fix):
    """读一次裁决；**取不到信号就再读一遍**。返回第一次拿到信号的结果。

    为什么重读**不会**削弱判据：判据断言的是「裁决值」，重读一个外部依赖
    不会改变裁决值（产品逻辑是确定性的）。重读只把「读不到」这一种失败
    从"一次就判"降到"两次都读不到才算"，把**瞬时抖动**与**真的测不了**分开。

    ★ 与「判据走注入参数、生产走默认参数」那一族**无关**：这里没有给产品换
      任何参数（超时仍是生产默认的 `VCT_TIMEOUT`），只是把一次外部读取重做一遍。
    """
    d = None
    for _ in range(_READ_TRIES):
        d = m.deletion_permission(cmd, fix)
        if not _no_signal(d):
            return d
    return d


def _fixture_live(m, fix, tries=4):
    """前置断言（C1 两步法的**第一步**）：夹具必须**自证成立**。

    拿一个已知良性的目标（夹具里的 `build`：既被忽略、又是目录）试一次，
    确认两票**真返回了信号**。取不到 ⇒ 返回 `(False, 说明)`，调用方必须报
    **「夹具失效」**，与「裁决错误」分开 —— 前者是量具/环境问题，后者才是产品缺陷。

    ★ 为什么要 retry：高负载是**瞬时**的。一次取不到就判失效太脆；
      重试仍取不到，才说明"这台机器此刻测不了"，那时报夹具失效才是诚实的
      （本仓纪律：**测不出的情况绝不报 PASS**，但也绝不把"测不出"说成"测出坏了"）。
    ★★ 0.53.1 实测（出包前的那次红）：`tries=2` 在同一轮里连撞两次，而**紧随其
      后**的 N-S80/81/82/83/84/86/87/88 全绿 —— 说明那是抖动不是测不了。
      ⇒ 抬到 4 次。抬次数**不削弱**判据：真测不了时 4 次全空，仍报「夹具失效」。
    """
    last = None
    for _ in range(tries):
        d = m.deletion_permission("rm -rf build", fix)
        if not _no_signal(d):
            if d.get("vote1") != "ignored":
                return False, ("control probe 的 vote1=%r（期望 'ignored'）"
                               "—— 夹具的忽略声明没生效" % (d.get("vote1"),))
            return True, None
        last = d
    return False, ("control probe 连续 %d 次**取不到任何信号**（vote1/vote2 都空，"
                   "allow=%r）—— 多半是机器负载让 git 子进程撞了 `VCT_TIMEOUT`"
                   % (tries, (last or {}).get("allow")))


# ══════════════ S80 · 两票**并且**运算 ══════════════
#: 第一票「声明为产物」＋ 第二票「可再生」都成立 ⇒ 放行（夹具里这些目录既被忽略、又是目录）。
_ALLOWED = ("build", "dist", "__pycache__", ".psl", "_archive_dist")
#: 第一票就不成立（工作树内、未被声明为产物）⇒ 受保护 ⇒ 拦。
_PROTECTED = ("hooks", "src", "old-config")


@check("S80 ★ 两票并且：声明为产物 ＋ 可再生 ⇒ 放行；受保护 ⇒ 拦；只声明不可再生 ⇒ 拦")
def s80():
    return _s80_impl(_hook())


def _s80_impl(m):
    """S80 的实现（★ 提成函数：负控 N-S80b 要拿**变异后的** hook 直接调它，
    才能证明「取不到信号」真的与「裁决错误」分开了 —— 判据不许二次实现）。"""
    fix = _allowed_fixture()
    # ★★ C1／M-A 第一步：夹具**自证成立**（取不到信号 ⇒ 夹具失效，不冒充产品红）。
    live, why = _fixture_live(m, fix)
    if not live:
        return ("夹具失效：%s ⇒ 本判据**测不出**，不算通过"
                "（量具/环境问题，不是产品缺陷）" % why)
    bad, blind = [], []
    for t in _ALLOWED:
        d = _read(m, "rm -rf " + t, fix)
        if _no_signal(d):
            blind.append(t)
            continue
        if d["allow"] is not True or d["vote1"] != "ignored" or d["vote2"] != "regenerable":
            bad.append("%s→%s/%s/%s" % (t, d["allow"], d["vote1"], d["vote2"]))
    for t in _PROTECTED:
        d = _read(m, "rm -rf " + t, fix)
        if _no_signal(d):
            blind.append(t)
            continue
        if d["allow"] is not False or d["vote1"] != "protected":
            bad.append("%s→%s/%s" % (t, d["allow"], d["vote1"]))
    if blind:
        return ("夹具失效：目标 %s **取不到信号**（机器天气，不是产品缺陷）"
                " ⇒ 本判据测不出，不算通过%s"
                % ("、".join(blind),
                   ("；另有裁决不符：%s" % "；".join(bad)) if bad else ""))
    if bad:
        return "两票裁决不符（期望 allow/vote1/vote2）：%s" % "；".join(bad)
    # 第三类：**声明为产物，但不可再生**（配置文件常被写进忽略规则，删了就真没了）。
    #   ★ 这一支仍用**本仓**真实的「已追踪且被忽略」文件（`_archive_dist/*.old` 一类）——
    #     它同时证明：本仓那 23 个「追踪 + 被忽略」的构建产物走的是「忽略优先」这一票。
    f = _tracked_ignored_file()
    if not f:
        return "夹具缺失：仓内找不到「已追踪且被忽略」的文件 ⇒ 本判据无法验证（不算通过）"
    d = _read(m, "rm -rf " + f, ROOT)
    # ★★ 0.53.1：**取不到信号 ≠ 被放行**。此前这一支直接看 `allow is not False`，
    #   于是 git 撞超时（allow=None）会被报成「声明为产物但不可再生的目标仍被放行」
    #   —— 把一个"没测成"说成了"测出漏拦"，正是 T-08 在判据自己身上的复发。
    if _no_signal(d):
        return ("夹具失效：本仓目标 %s **取不到信号**（allow=%r）⇒ 本判据测不出，"
                "不算通过（机器天气，不是产品缺陷）" % (f, d.get("allow")))
    if d["allow"] is not False or d["vote2"] != "not_regenerable":
        return ("声明为产物但不可再生的目标仍被放行（%s ⇒ allow=%s vote2=%s）"
                " ⇒ 第二票没在承重" % (f, d["allow"], d["vote2"]))
    return True


# ══════════════ N-S80 · 去掉忽略索引参数 ⇒ 当场翻面 ══════════════
_MUT_NO_INDEX = (
    '["check-ignore", "--no-index", "-q", "--", abs_target]',
    '["check-ignore", "-q", "--", abs_target]',
)


@check("N-S80 负控：去掉忽略索引参数 ⇒ 已追踪但被忽略的路径当场翻面 ⇒ 必须红")
def n_s80():
    d = _temp_git_repo()
    target = os.path.join(d, "gen", "x.txt")
    live = _hook()
    v_ok, _ = live._vct_vote1(target, d)
    if v_ok != "ignored":
        return ("夹具不成立：带忽略索引参数时判定为 %r（应 ignored）—— 负控自身失效" % (v_ok,))
    src = _src(_HOOK)
    if _MUT_NO_INDEX[0] not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(_MUT_NO_INDEX[0], _MUT_NO_INDEX[1]), "ptu0460_ns80")
    v_bad, _ = mut._vct_vote1(target, d)
    if v_bad == "ignored":
        return ("负控失效：去掉忽略索引参数后仍判 ignored ⇒ 该参数没被真正依赖"
                "（追踪事实会重新压过用户的产物声明）")
    # ★ 直接连回正判据 S80：本仓 `_archive_dist` 正是「已追踪 + 被忽略」，
    #   去掉参数后它必须从 S80 的放行名单里掉出去 ⇒ S80 当场红。
    d2 = mut.deletion_permission("rm -rf _archive_dist", ROOT)
    if d2["allow"] is True:
        return ("负控失效：去掉忽略索引参数后 `rm -rf _archive_dist` 仍放行 ⇒"
                " 连不回 S80（该参数在本仓不承重）")
    return True


@check("N-S80b 负控：让 git 一律取不到信号 ⇒ S80 必须报「夹具失效」而非「裁决不符」")
def n_s80b():
    """反向对照（维二）：模拟 X-017 现场 —— 机器高负载 ⇒ git 子进程全失败。

    ★ 证明「**取不到信号**」与「**裁决错误**」**真的分开了**：
      旧版两者都报"两票裁决不符"，把**机器天气**说成**产品缺陷**（T-08 复发在量具层）。
    ★ 注入：在 `_vct_run_git` 的**函数体首行**插入 `return None, "", ""`
      —— 等价于"每个 git 调用都超时/失败"，正是 `VCT_TIMEOUT` 撞线时的形状。
    """
    src = _src(_HOOK)
    anchor = "def _vct_run_git(args, cwd, timeout=VCT_TIMEOUT):"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(
        anchor,
        anchor + '\n    return None, "", ""      # NEGCTL 模拟 git 一律失败\n'),
        "ptu0460_ns80b")
    fix = _allowed_fixture()
    # ① 前置断言本身必须判"夹具失效"
    live, _why = _fixture_live(mut, fix)
    if live:
        return "负控失效：git 全失败时 `_fixture_live` 仍判夹具成立 ⇒ 前置断言是假的"
    # ② 正判据在同一条现场上必须报「夹具失效」，且**不许**报「两票裁决不符」
    got = _s80_impl(mut)
    if got is True:
        return "负控失效：git 全失败时 S80 仍报通过（取不到信号被当成了绿）"
    msg = got if isinstance(got, str) else repr(got)
    if "夹具失效" not in msg:
        return ("负控失效：S80 没报「夹具失效」（%r）—— 取不到信号仍被当成裁决"
                % msg[:120])
    if "两票裁决不符" in msg:
        return ("负控失效：S80 把「取不到信号」报成了「两票裁决不符」（%r）"
                " —— 机器天气仍被说成产品缺陷" % msg[:120])
    return True


@check("N-S80c 负控：只让第三支（本仓「已追踪且被忽略」文件）取不到信号 ⇒ S80 必须报"
       "「夹具失效」，不许报「仍被放行」")
def n_s80c():
    """反向对照（维二，0.53.1 新增）：证明**第三支**也分得开「测不出」与「漏拦」。

    ★ 病灶：`_s80_impl` 的第三支原先直接看 `allow is not False`。git 撞超时
      （出口丙 ⇒ `allow=None`）时，这一支会把「**没测成**」报成
      「**声明为产物但不可再生的目标仍被放行**」—— 一句听上去像产品漏拦的话。
      这正是 T-08（查不到就下结论）在**判据自己身上**的复发，与 N-S80b 守的
      是同一个病，但落在另一个分支上（只守一条腿 ⇒ 另一条腿天然全绿）。
    ★ 注入方式：**只对那一个目标**返回「取不到信号」，其余委托真产品
      —— 这样前置断言与两个循环仍走真路径，唯一被点掉的就是第三支。
    """
    f = _tracked_ignored_file()
    if not f:
        return "夹具缺失：仓内找不到「已追踪且被忽略」的文件 ⇒ 负控无从注入（不算通过）"
    real = _hook()
    base = os.path.basename(f).lower()

    class _BlindThird(object):
        """只把「针对 f 那一次读」变聋的代理；其余原样转给真产品。"""

        def deletion_permission(self, command, project_root=None):
            if base and base in (command or "").lower():
                return {"allow": None, "exit": "丙", "vote1": "", "vote2": "",
                        "why": "NEGCTL 模拟第三支撞 VCT_TIMEOUT",
                        "targets": [f], "is_delete": True}
            return real.deletion_permission(command, project_root)

    got = _s80_impl(_BlindThird())
    if got is True:
        return ("负控失效：第三支取不到信号时 S80 仍报通过"
                "（测不出被当成了绿）")
    msg = got if isinstance(got, str) else repr(got)
    if "仍被放行" in msg:
        return ("负控失效：第三支取不到信号被报成「仍被放行」（%r）"
                " —— 没测成又被说成了漏拦（T-08）" % msg[:140])
    if "夹具失效" not in msg:
        return "负控失效：第三支取不到信号时 S80 没报「夹具失效」（%r）" % msg[:140]
    return True


# ══════════════ S81 · 常见写法归一 ══════════════
@check("S81 ★ 常见写法归一：`build/`、`./build`、`.\\build` 都判为可再生的产物")
def s81():
    m = _hook()
    fix = _allowed_fixture()
    # ★★ C1／M-A：夹具**自证成立**（取不到信号 ⇒ 夹具失效，不冒充产品红）。
    live, why = _fixture_live(m, fix)
    if not live:
        return ("夹具失效：%s ⇒ 本判据**测不出**，不算通过"
                "（量具/环境问题，不是产品缺陷）" % why)
    cases = [
        ("rm -rf build/", "build"),
        ("rm -rf ./build", "build"),
        ("rm -rf .\\build", "build"),
        ("Remove-Item .\\build", "build"),
        ("rm -rf .\\dist", "dist"),
    ]
    bad, blind = [], []
    for cmd, _want in cases:
        d = m.deletion_permission(cmd, fix)
        if _no_signal(d):
            blind.append(cmd)
            continue
        if d["allow"] is not True:
            bad.append("%s→%s" % (cmd, d["allow"]))
    if blind:
        return ("夹具失效：%s **取不到信号**（机器天气，不是产品缺陷）"
                " ⇒ 本判据测不出，不算通过" % "、".join(blind))
    if bad:
        return "这些常见写法仍被误拦：%s" % "；".join(bad)
    # ★ 反向：还原 `.\` 的规则**不得**把真隐藏目录改坏。
    lit = m._vct_literal_targets("rm -rf .psl")[0]
    if lit != [".psl"]:
        return "`.psl` 被写法归一改坏成 %r（应保持 .psl）—— 归一越界" % (lit,)
    return True


@check("N-S81 负控：摘掉 `.\\` 还原分支 ⇒ `Remove-Item .\\build` 重新受保护 ⇒ 必须红")
def n_s81():
    src = _src(_HOOK)
    anchor = 'elif (t.startswith(".") and len(t) > 1 and not t.startswith("..")'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, "elif (False and t.startswith(\".\")"), "ptu0460_ns81")
    fix = _allowed_fixture()
    # 夹具前提：真实现下这条写法**确实**放行 —— 否则负控无分辨力（红的是夹具不是分支）。
    if _hook().deletion_permission("Remove-Item .\\build", fix)["allow"] is not True:
        return "夹具不成立：真实现下 `Remove-Item .\\build` 本就不放行 ⇒ 负控无分辨力"
    d = mut.deletion_permission("Remove-Item .\\build", fix)
    if d["allow"] is True:
        return "负控失效：摘掉还原分支后仍放行 ⇒ 该分支没被真正依赖"
    return True


# ══════════════ S82 · 两票放行**先于**兜底名单 ══════════════
@check("S82 ★ 两票放行先于兜底名单：目标不在名单里，两票同意也必须放行")
def s82():
    m = _hook()
    rules = _rules()
    # ① 夹具前提：`_archive_dist` **确实不在** DST-01 的兜底名单里 —— 否则本判据无分辨力。
    dst01 = [r for r in rules if r.get("id") == "DST-01"]
    if not dst01:
        return "找不到 DST-01 规则 ⇒ 判据前提不成立"
    excl = " ".join(dst01[0].get("exclude_patterns") or [])
    if "_archive_dist" in excl:
        return ("夹具失效：`_archive_dist` 已在兜底名单里 ⇒ 本判据测不出"
                "「名单之外的产物能否放行」")
    blocks, vct, _exc = _hits(m, "rm -rf _archive_dist", rules=rules)
    if blocks:
        return ("两票同意的产物（不在兜底名单）仍被拦：%s ⇒ 兜底名单仍在当主判据"
                % blocks)
    if not any(v.get("subkind") == "vct_allow" for v in vct):
        return "放行没有留痕（缺 vct_allow）⇒ 分不清是两票放行还是压根没命中"
    return True


@check("N-S82 负控：关掉两票放行分支 ⇒ 名单外的产物重新被拦 ⇒ 必须红")
def n_s82():
    src = _src(_HOOK)
    anchor = 'if _vct["allow"] is True:'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, "if False:"), "ptu0460_ns82")
    blocks, _vct, _exc = _hits(mut, "rm -rf _archive_dist")
    if not blocks:
        return ("负控失效：关掉两票放行后仍未被拦 ⇒ 说明该放行不是承重的"
                "（目标本就在兜底名单里）")
    return True


# ══════════════ S83 · 工作树外走出口丙（纪律 10.8） ══════════════
_OUTSIDE = "/c/Windows/System32"


@check("S83 ★ 工作树外走出口丙：allow=None、exit=丙、vote1=outside，且必须留痕")
def s83():
    m = _hook()
    d = m.deletion_permission("rm -rf " + _OUTSIDE, ROOT)
    if d["exit"] != "丙" or d["allow"] is not None or d["vote1"] != "outside":
        return ("工作树外路径没走出口丙：exit=%r allow=%r vote1=%r"
                % (d["exit"], d["allow"], d["vote1"]))
    blocks, vct, _exc = _hits(m, "rm -rf " + _OUTSIDE)
    if not blocks:
        return "出口丙之后仍被放行（%s）⇒ 退出口不该改变『默认拦』的方向" % blocks
    if not any(v.get("subkind") == "exit_丙" for v in vct):
        return ("出口丙**没有留痕**（vct=%s）—— 设计 §3.5：四个退出口不许静默"
                % [v.get("subkind") for v in vct])
    return True


@check("N-S83 负控：把返回 128 当成『受保护』⇒ 工作树外不再走出口丙 ⇒ 必须红")
def n_s83():
    src = _src(_HOOK)
    anchor = 'return "outside", "路径在工作树外（rc=128）"'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, 'return "protected", ""'), "ptu0460_ns83")
    d = mut.deletion_permission("rm -rf " + _OUTSIDE, ROOT)
    if d["exit"] == "丙":
        return "负控失效：把 128 当受保护后仍走出口丙 ⇒ 该分支没被真正依赖"
    return True


# ══════════════ S84 · 中文路径只看返回码 ══════════════
def _zh_paths():
    return (os.path.join(ROOT, "_archive_dist", "中文测试目录"),      # 被忽略
            os.path.join(ROOT, "hooks", "中文测试目录"))              # 未被忽略


@check("S84 ★ 中文路径：只凭返回码得结论（被忽略→ignored，未忽略→protected）")
def s84():
    m = _hook()
    root = m._vct_worktree_root(ROOT)
    if not root:
        return "取不到工作树根 ⇒ 环境不具备（不算通过）"
    zh_ign, zh_pro = _zh_paths()
    a, _ = m._vct_vote1(zh_ign, root)
    b, _ = m._vct_vote1(zh_pro, root)
    if a != "ignored" or b != "protected":
        return ("中文路径判定错：被忽略=%r（应 ignored）、未忽略=%r（应 protected）"
                " ⇒ 多半是拿输出里的路径串做了比对" % (a, b))
    return True


@check("N-S84 负控：改成依赖输出字符串做比对 ⇒ 中文路径当场判错 ⇒ 必须红")
def n_s84():
    src = _src(_HOOK)
    # 变异：① 去掉 `-q`（让 git 输出路径）② 用输出串判定「被忽略」
    if _MUT_NO_INDEX[0] not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    a1 = src.replace(_MUT_NO_INDEX[0],
                     '["check-ignore", "--no-index", "--", abs_target]')
    anchor2 = '    if rc == 0:\n        return "ignored", ""'
    if anchor2 not in a1:
        return "变异锚点 2 未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    a2 = a1.replace(anchor2, '    if rc == 0 and abs_target in _out:\n        return "ignored", ""')
    mut = _load(a2, "ptu0460_ns84")
    zh_ign, _ = _zh_paths()
    v, _ = mut._vct_vote1(zh_ign, mut._vct_worktree_root(ROOT) or ROOT)
    if v == "ignored":
        return ("负控失效：改成依赖输出串后中文路径仍判 ignored ⇒"
                " 本测试测不出「输出串比对」（可能是本机 git 关掉了路径转义）")
    return True


# ══════════════ S85 · 四个退出口不许静默 ══════════════
@check("S85 ★ 退出口不许静默：出口乙/丙都写明原因并留痕；非删除类操作**不**留痕")
def s85():
    m = _hook()
    for cmd, want in (('rm -rf "$F"', "乙"), ("rm -rf " + _OUTSIDE, "丙")):
        d = m.deletion_permission(cmd, ROOT)
        if d["exit"] != want or not (d["why"] or "").strip():
            return ("%s 的退出口不符或没写明原因：exit=%r why=%r"
                    % (cmd, d["exit"], d["why"]))
        _b, vct, _e = _hits(m, cmd)
        if not any(v.get("subkind") == "exit_" + want for v in vct):
            return "%s 走出口%s 但**没有留痕**（vct=%s）⇒ 静默" % (
                cmd, want, [v.get("subkind") for v in vct])
    # 不是删除类操作 ⇒ 步骤三「到此结束」，不该被记成「删除许可取不到目标」。
    for cmd in ("ls -la", "git status", 'echo "rm -rf dist"'):
        _b, vct, _e = _hits(m, cmd)
        if vct:
            return ("非删除类操作 %r 也留下了删除许可记录（%s）⇒ 账本会被噪声灌满"
                    % (cmd, [v.get("subkind") for v in vct]))
    return True


# ══════════════ S86 · 一个许可只开一扇门 ══════════════
@check("S86 ★ 删除许可只门控**删除**规则：DST-02…DST-11（同属 destructive）不受它管辖")
def s86():
    m = _hook()
    rules = _rules()
    got = [r.get("id") for r in rules if m._is_delete_rule(r)]
    if got != ["DST-01"]:
        return ("删除类规则集合为 %s（应恰为 ['DST-01']）—— 门控范围过宽会把"
                "「写项目外／云盘同步／提权」也一并放行（一个许可开多扇门）" % (got,))
    return True


@check("N-S86 负控：把门控放宽成 category==destructive ⇒ 删除许可被顺带套到 DST-07 上 ⇒ 必须红")
def n_s86():
    gc = "git " + "clean" + " -fd"          # 拆开写，免得本文件自身被 DST-07 命中
    cmd = "rm -rf dist && " + gc
    live = _hook()
    blocks, vct, _e = _hits(live, cmd)
    if "DST-07" not in blocks:
        return ("夹具不成立：真实现下 `%s` 的 DST-07 本就没拦 ⇒ 负控无分辨力" % cmd)
    # ★ 观察点不是「拦不拦」，是**删除许可有没有套到 DST-07 头上**。
    #   2026-10-20 实测（本仓）：放宽门控后 DST-07 依然「被拦」，但那是因为
    #   dist 被 10 条 destructive 规则同时判 deny —— 「仍被拦」是**遮蔽**，
    #   不是「没被门控影响」。旧写法把遮蔽读成空转，于是负控恒假红。
    live_owners = {v.get("rule_id") for v in (vct or []) if v.get("rule_id")}
    if "DST-07" in live_owners:
        return ("夹具不成立：真实现下删除许可就套到 DST-07 上了 —— "
                "S86 的『只管删除规则』本就没成立")
    mut = _hook()
    mut._is_delete_rule = lambda r: bool(r) and (
        (r.get("category") or "").lower() == "destructive"
        or str(r.get("id") or "").startswith("DST-"))
    _b2, vct2, _e2 = _hits(mut, cmd)
    mut_owners = {v.get("rule_id") for v in (vct2 or []) if v.get("rule_id")}
    if "DST-07" not in mut_owners:
        return ("负控失效：放宽门控后删除许可仍没套到 DST-07 上 —— "
                "说明 S86 那条『一个许可只开一扇门』根本没人守得住")
    return True


# ══════════════ S87 · 第二票隔离（有/无构建描述） ══════════════
@check("S87 ★ 第二票：上层有构建描述文件 ⇒ 可再生；没有 ⇒ 不可再生；文件 ⇒ 不可再生")
def s87():
    m = _hook()
    with_desc = _TMP.tmpdir(prefix="g0460_v2a_")
    os.makedirs(os.path.join(with_desc, "sub"))
    with io.open(os.path.join(with_desc, _ROOT_DESCRIPTOR), "w", encoding="utf-8") as f:
        f.write("")
    no_desc = _TMP.tmpdir(prefix="g0460_v2b_")
    os.makedirs(os.path.join(no_desc, "sub"))
    ok1, _ = m._vct_vote2(os.path.join(with_desc, "sub"))
    ok2, _ = m._vct_vote2(os.path.join(no_desc, "sub"))
    ok3, _ = m._vct_vote2(os.path.join(with_desc, _ROOT_DESCRIPTOR))
    if ok1 is not True:
        return "有构建描述文件却判不可再生 ⇒ 第二票失效"
    if ok2 is not False:
        return "无构建描述文件却判可再生 ⇒ 第二票方向不安全（认不出应判不可再生）"
    if ok3 is not False:
        return "把**文件**（构建描述自身）判成可再生 ⇒ 配置文件删了就真没了"
    return True


@check("N-S87 负控：摘掉『必须是目录』⇒ 配置文件也被判可再生 ⇒ 必须红")
def n_s87():
    src = _src(_HOOK)
    anchor = "if not abs_target or not os.path.isdir(abs_target):"
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, "if not abs_target:"), "ptu0460_ns87")
    d = _TMP.tmpdir(prefix="g0460_v2c_")
    with io.open(os.path.join(d, _ROOT_DESCRIPTOR), "w", encoding="utf-8") as f:
        f.write("")
    ok, _ = mut._vct_vote2(os.path.join(d, _ROOT_DESCRIPTOR))
    if ok is False:
        return "负控失效：摘掉『必须是目录』后配置文件仍判不可再生 ⇒ 该条件没被依赖"
    return True


# ══════════════ S88 · 连带对照：既有保护仍绿 ══════════════
@check("S88 ★ 连带对照：受保护/工作树外/普通目录仍拦；取不到信号时兜底名单仍放行")
def s88():
    m = _hook()
    rules = _rules()
    # ① 真删除仍拦
    for cmd in ("rm -rf hooks", "rm -rf old-config", "rm -rf " + _OUTSIDE,
                "rm -rf dist && rm -rf hooks"):
        blocks, _v, _e = _hits(m, cmd, rules=rules)
        if "DST-01" not in blocks:
            return "既有保护被放宽：`%s` 不再拦（blocks=%s）" % (cmd, blocks)
    # ② 兜底名单在「两票取不到信号」时仍是最后退路（非 git 根 ⇒ 出口丙）
    nogit = _TMP.tmpdir(prefix="g0460_nogit_")
    blocks, vct, _e = _hits(m, "rm -rf node_modules", project_root=nogit, rules=rules)
    if blocks:
        return "取不到版本信号时，兜底名单没接住（%s 被拦）⇒ 最后退路失效" % blocks
    if not any(v.get("subkind") == "fallback_allow" for v in vct):
        return "兜底名单放行没留痕（缺 fallback_allow）⇒ 分不清是哪条路生效"
    return True


# ══════════════ N-S88 · 兜底退路（第三信号）的负控 ══════════════
@check("N-S88 负控：堵死兜底退路（fallback_allow 的 continue）⇒ 取不到信号时不再放行 ⇒ 必须红")
def n_s88():
    """第三信号（兜底名单／退路）的负控 —— 交接件 §8「三票各自的负控全在」的兜底解释。

    设计（§3.4/§3.5/§7.3/§7.4）是**两票**（忽略声明 ＋ 可再生）；兜底名单是两票都
    取不到信号时的**最后退路**（§3.7）。本负控证明这条退路**真的承重**：把它堵死之后，
    「非 git 目录里删 node_modules」（两票都取不到信号）就不再被放行 —— 若堵死它仍放行，
    说明放行来自别处，退路是空转的。
    """
    src = _src(_HOOK)
    anchor = 'subkind="fallback_allow", decision="allow"))\n                continue'
    if anchor not in src:
        return "变异锚点未找到（源码已变，需更新负控）—— 负控自身失效，不算通过"
    mut = _load(src.replace(anchor, anchor[:-len("continue")] + "pass"), "ptu0460_ns88")
    nogit = _TMP.tmpdir(prefix="g0460_ns88_")
    # 夹具前提：真实现下这条命令**确实**被兜底名单放行 —— 否则负控无分辨力。
    live_blocks, live_vct, _le = _hits(_hook(), "rm -rf node_modules", project_root=nogit)
    if live_blocks or not any(v.get("subkind") == "fallback_allow" for v in live_vct):
        return ("夹具不成立：真实现下该命令未被兜底名单放行（blocks=%s）"
                " ⇒ 负控无分辨力" % live_blocks)
    blocks, _vct, _e = _hits(mut, "rm -rf node_modules", project_root=nogit)
    if not blocks:
        return ("负控失效：堵死兜底退路后仍被放行 ⇒ 该退路没在承重"
                "（说明放行来自别处，不是兜底名单）")
    return True


def main():
    print("=" * 78)
    print("0.46.0 判据 —— 删除许可（VCT）：两票并且 / 五步顺序 / 四退出口")
    print("（变异只在内存，夹具只落临时目录，不写任何产品文件）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                why = ""
            print("  ✅ %-60s %s" % (name, why or ""))
            ok += 1
        except AssertionError as e:
            print("  ❌ %-60s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-60s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
