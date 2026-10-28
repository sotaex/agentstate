#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0515 判据 —— 用户入口的字节与形态（CMD/DSK/ICO 三族）＋ P0-2 判据 ID 唯一化。

★ P0-3（antinel.cmd 在本机从未跑通）—— 本轮实测抓到的**两个叠加根因**：

  ① 行尾：文件 36 行**全是裸 LF**（CRLF=0）。cmd.exe 按字节找行界，
     LF-only 时按字节错位切行，把中文注释残片当命令执行
     （实测 stderr：`'…服务常驻' 不是内部或外部命令…`）。
  ② 编码：**只归一化 CRLF 不够**。cmd.exe 按**控制台 OEM 代码页**读 .cmd；
     中文 Windows 默认 CP936，文件是 UTF-8 ⇒ 中文注释被错位解读，
     即使 CRLF 也照样误执行（`CREATE_NEW_CONSOLE` 复现双击场景实测：
     zh-comments + CRLF @CP936 ⇒ 误执行；CRLF + no-chcp @CP437 ⇒ 干净）。
     ⇒ 修法＝**CRLF ＋ 全 ASCII**（机器无关的唯一安全形态）；
     中文 rationale 移到本 docstring 与 `inbox_cli.py`。
  · 连带证伪一条交接文件前提：「同目录 tools/*.ps1 均为 CRLF 可对照」
    —— 实测 tools/logo.ps1、tools/mk_sound.py 均 0 CRLF / 全裸 LF
    （`.gitattributes` 是 `* -text`，从不换行）⇒ 该对照不存在，已按事实修订。

★ P0-2（判据 ID 重名折叠）—— 旧口径 `gate_ids_from_registry()` 把 ID 收进
  `set()`：S70 在 0431 与 0440 各有一份真声明，折叠成一个 ⇒「有人守」的
  检查会被**另一套件的同名判据**冒充（0431 的 S70 删光、只要 0440 还在
  就全绿 ＝ 假绿），且折叠后无法定位所属套件。本轮已落地：
  `gate_id_map()`（AST 真声明、保留全部出现）＋ `duplicate_gate_ids()`
  （跨套件重名检测）＋ 25 组历史重名按「先声明保留裸 ID、后声明加
  -<批次> 后缀」解掉（不臆测号码）。

编写纪律（沿用 0514）：负控先实测见红；断言打行为/结构；不写任何产品
文件（变异只在内存/临时目录）；测不出 ⇒ SKIP，绝不报 PASS。

★ 0.52.0 扩族（P5 扩展优先，A2 常驻 29 已满故不立新套件）：
  · DSK 族：桌面入口 `.lnk`（创始人「用户下载安装之后，是否也默认在
    用户桌面放上呢」）—— 接线五件套＋`.lnk` 形态契约＋真建回读四性；
  · ICO 族：品牌图标 `antinel.ico`（小黄球第二次弄丢后的资产层尺子）
    —— 四尺寸 32bpp＋掩码零＋哨点在场可辨＋package-data 两处同改。
  资产层哨点的**冻结执法**（D-38）另在 `regression_gate` 的 FZ-005。
"""
from __future__ import annotations

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import tmpreg as _TMP   # 0.55.0 (F3): temp dir registry
import ast
import io
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
CI = os.path.join(ROOT, "ci")
if CI not in sys.path:
    sys.path.insert(0, CI)

import defect_types as DT                                       # noqa: E402

RESULTS = []

_CMD_REL = "antinel.cmd"
_INSTALL_REL = "scripts/install.py"

#: CREATE_NEW_CONSOLE ＝ 复现「Explorer 双击 .cmd」：新控制台的代码页是
#: 系统 OEM 默认（中文 Windows = 936），与真实用户场景一致；stdio 仍走管道。
_CREATE_NEW_CONSOLE = 0x00000010

#: 误执行信号（**代码页无关**：英文串直找；中文串按 cp936/gbk 解码再找）
_ERR_EN = ("is not recognized as an internal or external command",
           "operable program or batch file",
           "The system cannot find the path specified")
_ERR_ZH = ("不是内部或外部命令", "也不是可运行的程序", "系统找不到指定的路径")


class Skip(Exception):
    """夹具凑不齐 ⇒ 这一条不判，也**不许判绿**。"""


def check(name):
    """判据必须真会红 —— 返回说明串一律转抛异常；SKIP 前缀转 Skip。"""
    def deco(fn):
        def wrapper():
            r = fn()
            if r is True or r is None:
                return True
            if isinstance(r, str) and r.startswith("SKIP"):
                raise Skip(r)
            raise AssertionError(r if isinstance(r, str) else repr(r))
        RESULTS.append((name, wrapper))
        return fn
    return deco


def _note(*a):
    """可观测：判定细节进 stdout（闸门运行输出即留证）。"""
    print("      · %s" % " ".join(str(x) for x in a))


# ═══════════════════════════════ P0-3：antinel.cmd ══════════════════════════════

def _cmd_bytes():
    with io.open(os.path.join(ROOT, _CMD_REL), "rb") as f:
        return f.read()


def _cmd15a_judge(b):
    """字节级判定（正/负控**同一把尺子**，只换输入）。返回问题串或 None。"""
    if not b:
        return "antinel.cmd 是空文件"
    crlf = b.count(b"\r\n")
    bare = b.count(b"\n") - crlf
    if crlf == 0:
        return "没有 CRLF（%d 字节全裸 LF）—— cmd.exe 按字节错位切行" % len(b)
    if bare:
        return "有 %d 处裸 LF（行尾不统一，cmd 切行仍会错位）" % bare
    if not b.endswith(b"\r\n"):
        return "文件末不是 CRLF（末行可能被吞）"
    if any(c > 127 for c in b):
        return ("含非 ASCII 字节 —— CP936 控制台下 UTF-8 中文注释会被 cmd "
                "当命令执行（实测：CRLF 也救不了）")
    txt = b.decode("ascii")
    for need in ("inbox daemon", "inbox window"):
        if need not in txt:
            return "antinel.cmd 没调用 %s（空壳入口，0490 W-04 连带回归）" % need
    return None


@check("CMD15-a ★ antinel.cmd 字节级：CRLF 行尾 ＋ 全 ASCII ＋ 两个真入口还在")
def c_cmd15a():
    b = _cmd_bytes()
    why = _cmd15a_judge(b)
    _note("bytes=%d CRLF=%d bareLF=%d ascii=%s"
          % (len(b), b.count(b"\r\n"),
             b.count(b"\n") - b.count(b"\r\n"),
             all(c < 128 for c in b)))
    return why or True


@check("N-CMD15-a 负控：同一内容换裸 LF ⇒ 同一把字节尺子必须判红")
def n_cmd15a():
    b = _cmd_bytes()
    lf = b.replace(b"\r\n", b"\n")          # 只变异行尾（安全 fixture，不落产品树）
    if lf == b:
        return "夹具不成立：原文件本就没有 CRLF，负控无分辨力"
    why = _cmd15a_judge(lf)
    if not why:
        return "负控失效：裸 LF 变体字节尺子仍然放行 —— 判据空转"
    _note("LF 变体判定：%s" % why)
    return True


def _mis_split_signals(stderr_bytes):
    """误执行信号（代码页无关）。"""
    hits = []
    for enc in ("utf-8", "cp936", "gbk"):
        s = stderr_bytes.decode(enc, "replace")
        for m in _ERR_EN + _ERR_ZH:
            if m in s:
                hits.append(m)
    return sorted(set(hits))


def _run_fixture(body_bytes):
    """fixture 落临时目录后跑 `cmd /c`（新控制台＝系统代码页场景）。"""
    d = _TMP.tmpdir(prefix="g0515_cmd_")
    p = os.path.join(d, "fx.cmd")
    with io.open(p, "wb") as f:
        f.write(body_bytes)
    return subprocess.run(["cmd", "/c", p], capture_output=True, timeout=30,
                          creationflags=_CREATE_NEW_CONSOLE)


def _safe_fixture_from_real():
    """从真 antinel.cmd 只取**注释块＋一行 echo**（绝不取真命令：
    不起 daemon、不开窗 —— 负控/正控都不许有产品副作用）。"""
    txt = _cmd_bytes().decode("ascii")
    rem = [l for l in txt.split("\r\n") if l.startswith("REM")][:14]
    return "\r\n".join(["@echo off"] + rem) + "\r\necho G0515-MARKER\r\n"


def _cmd15b_judge(body_bytes):
    """行为判定（正/负控同一把尺子）：注释块零误执行 ＋ echo 标记真出现。"""
    r = _run_fixture(body_bytes)
    sig = _mis_split_signals(r.stderr)
    if sig:
        return "注释残片被当命令执行（signals=%s）" % sig
    if b"G0515-MARKER" not in r.stdout:
        return ("fixture 的 echo 标记没出现（rc=%r）—— 夹具可能不成立，"
                "不许判绿" % r.returncode)
    _note("rc=%r stderr=%dB signals=0 marker=OK" % (r.returncode,
                                                    len(r.stderr)))
    return None


@check("CMD15-b ★ 真入口内容在新控制台（系统代码页）跑：注释块零误执行")
def c_cmd15b():
    if os.name != "nt":
        raise Skip("SKIP: 非 Windows（cmd.exe 行为不适用）")
    return _cmd15b_judge(_safe_fixture_from_real().encode("ascii")) or True


@check("N-CMD15-b 负控：中文注释 fixture（修复前形状）⇒ 误执行信号必须出现")
def n_cmd15b():
    if os.name != "nt":
        raise Skip("SKIP: 非 Windows（cmd.exe 行为不适用）")
    # 修复前的产品形状：UTF-8 中文 REM 注释（探针四实测 CP936 下必误执行）
    zh = ("@echo off\r\n"
          "REM Antinel 监理原来是会话里拉的前台进程，会话一结束服务就没了\r\n"
          "REM 用户要的是一步就能服务常驻加开独立窗口\r\n"
          "echo G0515-MARKER\r\n").encode("utf-8")
    why = _cmd15b_judge(zh)
    if not why:
        return "负控失效：中文注释 fixture 没有误执行信号 ⇒ 判据测了个恒真"
    _note("中文 fixture 判定：%s" % why)
    return True


@check("CMD15-c 连带：归一化只改行尾（命令逐字在）＋ 安装垫片仍写 CRLF ＋ SPDX 头在")
def c_cmd15c():
    b = _cmd_bytes()
    txt = b.decode("ascii")
    # ① CRLF 归一化不许动内容：命令四行逐字在位
    for need in ('start "antinel-daemon" /min cmd /c',
                 "%PY% antinel.py inbox daemon --supervise --interval 2",
                 "%PY% antinel.py inbox window",
                 "endlocal & exit /b %RC%"):
        if need not in txt:
            return "命令行丢了/被改：%r" % need
    # ② 仓内每个 .cmd 都是 CRLF（纪律对未来文件也生效）
    for dirpath, _dirs, files in os.walk(ROOT):
        if ".git" in dirpath or "output" in dirpath:
            continue
        for fn in files:
            if not fn.endswith(".cmd"):
                continue
            p = os.path.join(dirpath, fn)
            bb = io.open(p, "rb").read()
            if bb.count(b"\r\n") == 0 or bb.count(b"\n") != bb.count(b"\r\n"):
                return "%s 不是 CRLF（纪律只修了 antinel.cmd 一个？）" % p
    # ③ 安装垫片（0.34.0 中文用户名修复）仍写 CRLF
    inst = io.open(os.path.join(ROOT, _INSTALL_REL), encoding="utf-8").read()
    if 'newline="\\r\\n"' not in inst and "newline='\\r\\n'" not in inst:
        return "install.py 垫片不再写 CRLF —— 已安装用户的入口会复发"
    # ④ SPDX 头在前几行（0481 L1 纪律）
    if "SPDX-License-Identifier" not in "\r\n".join(txt.split("\r\n")[:4]):
        return "SPDX 头不在文件头部"
    return True


# ═══════════════════════════════ P0-2：判据 ID 唯一化 ═══════════════════════════

def _dup_judge(amap):
    """跨套件重名判定（正/负控同一把尺子，只换输入）。返回问题串或 None。"""
    bad = []
    for gid, occ in sorted(amap.items()):
        suites = sorted(set(s for s, _r in occ))
        if len(suites) > 1:
            bad.append("%s@%s" % (gid, "/".join(suites)))
    return ("跨套件重名：%s" % "; ".join(bad)) if bad else None


@check("UID15-a ★ 判据 ID 映射：每条声明落到真实套件文件，登记簿引用无孤儿")
def c_uid15a():
    amap = DT.gate_id_map()
    if not amap:
        return "gate_id_map() 为空 —— 提取器坏了（T-03 量具自身失效）"
    for gid, occ in amap.items():
        for _suite, rel in occ:
            if not os.path.isfile(os.path.join(ROOT, rel)):
                return "%s 映射到不存在的文件 %s" % (gid, rel)
    # 连带（旧口径）：登记簿 47 条引用在 set 口径下全部可解析
    #   （族头引用 W-09/U-17 靠旧口径截断解析，是新旧两把尺子的既有惯例）
    refs = set()
    for t in DT.TYPES.values():
        refs |= set(t.get("guards") or [])
    for i in DT.INSTANCES:
        if i.get("guard"):
            refs.add(i["guard"])
    gset = DT.gate_ids_from_registry()
    orphans = sorted(r for r in refs if r not in gset)
    if orphans:
        return "登记簿引用在注册表里解析不到（孤儿）：%s" % orphans
    _note("map 条目=%d 登记簿引用=%d 全部可解析" % (len(amap), len(refs)))
    return True


@check("UID15-b ★ 跨套件重名折叠检测：真树上必须为 0（direct read）")
def c_uid15b():
    dups = DT.duplicate_gate_ids()
    if dups:
        return "仍有跨套件重名：%s" % "; ".join(
            "%s@%s" % (g, "/".join(s)) for g, s in dups)
    _note("duplicate_gate_ids() = []（25 组历史重名已按批次后缀解掉）")
    return True


@check("N-UID15-a 负控：合成重名检测器必须报到；折叠后「删最早一套」的假绿要被抓")
def n_uid15a():
    # 臂①：合成映射有重名 ⇒ 同一把尺子必须非空
    fake = {"S70": [("0431", "ci/inbox_guards_0431.py"),
                    ("0440", "ci/inbox_guards_0440.py")]}
    if not _dup_judge(fake):
        return "负控失效：合成重名没被检出 ⇒ 检测器空转"
    # 臂②：折叠危害实证 —— 0431 的 S70 被删光、只剩 0440 的：
    #   · 旧 set 口径："S70" 仍在集合里 ⇒「有人守」照样全绿（**假绿**）；
    #   · 映射口径：map["S70"] 只剩 0440 ⇒「0431 守的 S70 已经没了」可判定。
    mutated = {"S70": [("0440", "ci/inbox_guards_0440.py")]}
    if _dup_judge(mutated):
        return "夹具不成立：变异后不该有重名"
    if "S70" not in DT.gate_ids_from_registry():
        return "夹具不成立：真树上已无 S70 声明，折叠危害演不了"
    _note("折叠实证：set 口径对「0431 的 S70 被删光」仍然全绿（假绿）；"
          "映射口径可判定归属 ⇒ 这就是必须换口径的原因")
    return True


# ═════════════════════ DSK 族：桌面入口 .lnk（0.52.0）════════════════════════
#
# ★ 为什么进 0515（P5 扩展优先，不立新套件）：0515 守的就是**用户入口的字节
#   与形态**（antinel.cmd 一键入口）—— 桌面入口 .lnk 是同一族的下一个形态
#   （.cmd → 启动文件夹 .lnk → 桌面 .lnk，三者共用 pythonw 无窗口手法与
#   品牌图标）。A2 常驻 29 已满，立新套件须先退休一个；同域 ⇒ 并入。
#
# ★ 背景（创始人 2026-10-17：「用户下载安装之后，是否也默认在用户桌面放上
#   呢，用户体验一定要照顾周全」）：pip 装完只有 antinel 命令，普通用户
#   找不到入口 ⇒ 装了却用不上。enable 一键布防时默认放桌面（--no-desktop
#   可关），disable 撤防时对称归档（pip uninstall 删不到包外文件，不处理
#   的话卸载后桌面留个点开报错的死图标）。

_ANTINEL_REL = "antinel.py"
_PKG = os.environ.get("ANTINEL_PKG") or ROOT


def _antinel_src():
    with io.open(os.path.join(_PKG, _ANTINEL_REL), encoding="utf-8") as f:
        return f.read()


def _sub_block(fn_node, src, sub):
    """`cmd_host_shield` 里 `if args.sub == "<sub>":` 那个 If 节点（找不到 None）。"""
    for node in ast.walk(fn_node):
        if isinstance(node, ast.If):
            seg = ast.get_source_segment(src, node.test) or ""
            if seg.replace(" ", "") == 'args.sub=="%s"' % sub:
                return node
    return None


def _func_seg(src, name):
    """函数真代码段（AST，docstring 剥掉）—— 与 0360 `_func_seg_of` 同纪律。"""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return ""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            seg = ast.get_source_segment(src, node) or ""
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                i = seg.find(body[0].value.value)
                if i >= 0:
                    seg = seg[i + len(body[0].value.value):]
            return seg
    return ""


def _dsk_wiring_judge(src):
    """桌面入口接线判定（正/负控**同一把尺子**，只换输入）。问题串或 None。"""
    problems = []
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return "antinel.py 语法错误：%s" % e
    defs = {n.name: n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef)}
    for f in ("_desktop_dir", "_desktop_entry_path", "_brand_icon",
              "_create_desktop_lnk", "_archive_desktop_entry"):
        if f not in defs:
            problems.append("缺函数 %s —— 桌面入口机制不在场" % f)
    hs = defs.get("cmd_host_shield")
    if hs is None:
        problems.append("cmd_host_shield 不在 —— 接线判不了")
    else:
        en = _sub_block(hs, src, "enable")
        if en is None:
            problems.append("cmd_host_shield 里找不到 enable 分支")
        else:
            seg = ast.get_source_segment(src, en) or ""
            if "_create_desktop_lnk()" not in seg:
                problems.append("enable 分支没调 _create_desktop_lnk()"
                                " —— 默认放桌面入口失效")
            if "no_desktop" not in seg:
                problems.append("enable 分支没有 --no-desktop 判断"
                                " —— 「可关」的出口失效")
        dis = _sub_block(hs, src, "disable")
        if dis is None:
            problems.append("cmd_host_shield 里找不到 disable 分支")
        else:
            seg = ast.get_source_segment(src, dis) or ""
            if "_archive_desktop_entry()" not in seg:
                problems.append("disable 分支没归档桌面入口"
                                " —— 卸载后桌面留死图标（差评源）")
            if "_startup_folder_lnk()" not in seg or ".away-" not in seg:
                problems.append("disable 分支没归档自启 .lnk"
                                " —— 0.51.2 漏洞复发（只删 .cmd）")
    if 'add_argument("--no-desktop"' not in src:
        problems.append("argparse 没注册 --no-desktop")
    if 'add_parser("desktop")' not in src:
        problems.append("argparse 没注册 desktop 子命令（补建/刷新出口）")
    return "；".join(problems) if problems else None


@check("DSK15-a ★ 桌面入口接线：五函数在位＋enable 默认建＋--no-desktop＋desktop 补建＋disable 双归档")
def c_dsk15a():
    why = _dsk_wiring_judge(_antinel_src())
    return why or True


@check("N-DSK15-a 负控：删掉 enable 里的建入口调用 ⇒ 同一把尺子必须判红")
def n_dsk15a():
    src = _antinel_src()
    anchor = "_desk = _create_desktop_lnk()"
    if src.count(anchor) < 1:
        return "变异锚点未找到（enable 分支没有建入口调用）—— 负控自身失效"
    mutated = src.replace(anchor, "_desk = None  # 变异：去掉默认建桌面入口", 1)
    if mutated == src:
        return "负控自身失效：替换没生效"
    why = _dsk_wiring_judge(mutated)
    if why is None:
        return "负控失效：删掉 enable 建入口调用后仍判合格 —— 接线尺子是装饰"
    if "enable" not in why:
        return "方向不对：报的红不是 enable 那一处（%s）—— 量具打偏" % why
    return True


def _dsk_form_judge(src, hs_src=None):
    """.lnk 形态契约判定（两个入口共用品牌名＋条件挂图标）。问题串或 None。

    ★★ 0.60.0：**跟随委托**。`_create_startup_lnk` 已收敛成薄委托，真正的
      `.lnk` 构建在 `host_shield.create_autostart_lnk`（一处实现，两条注册路径
      共用）。旧判据死认 `antinel.py` 的函数体 ⇒ 实现一搬家就翻红，而窗口
      并不会因此回来。修法是让判据跟着实现走，**但必须走到底** ——
      委托目标也得真满足这三条，否则判据被架空（等于没守）。
    """
    problems = []
    specs = (
        ("_create_desktop_lnk", (
            ('-I -S "%s" window',
             "桌面入口目标不是 pythonw -I -S inbox_cli.py window"),
            ("$s.Description='Antinel 监理';",
             "桌面入口描述不是品牌名（中文）"),
            ("$s.IconLocation='%s';", "桌面入口没挂品牌图标"),
            ("if icon:", "图标挂载不是条件式（没有图标时不许写死路径）"),
        )),
        ("_create_startup_lnk", (
            ("$s.Description='Antinel 监理 登录自启';",
             "自启入口描述不是品牌名（中文）"),
            ("$s.IconLocation='%s';", "自启入口没挂品牌图标"),
            ("if icon:", "自启图标挂载不是条件式"),
        )),
    )
    for fn, markers in specs:
        seg = _func_seg(src, fn)
        if not seg:
            problems.append("取不到 %s 函数段" % fn)
            continue
        if (hs_src is not None and fn == "_create_startup_lnk"
                and not all(m in seg for m, _w in markers)
                and "create_autostart_lnk" in seg):
            seg2 = _func_seg(hs_src, "create_autostart_lnk")
            if not seg2:
                problems.append("`_create_startup_lnk` 委托给 "
                                "host_shield.create_autostart_lnk，但那个函数取不到")
                continue
            seg, fn = seg2, "host_shield.create_autostart_lnk"
        for marker, why in markers:
            if marker not in seg:
                problems.append("%s：%s" % (fn, why))
    return "；".join(problems) if problems else None


@check("DSK15-b ★ .lnk 形态契约：pythonw 无窗口＋中文品牌描述＋条件挂品牌图标（桌面/自启两处）")
def c_dsk15b():
    with io.open(os.path.join(_PKG, "host_shield.py"), encoding="utf-8") as f:
        hs_src = f.read()
    why = _dsk_form_judge(_antinel_src(), hs_src)
    return why or True


@check("N-DSK15-b 负控：描述回英文旧值 ⇒ 同一把尺子必须判红")
def n_dsk15b():
    src = _antinel_src()
    anchor = "$s.Description='Antinel 监理';"
    if anchor not in src:
        return "变异锚点未找到（桌面入口描述串变了）—— 负控自身失效"
    mutated = src.replace(
        anchor, "$s.Description='Antinel sentinel (no window)';", 1)
    if mutated == src:
        return "负控自身失效：替换没生效"
    why = _dsk_form_judge(mutated)
    if why is None:
        return "负控失效：描述回英文后仍判合格 —— 形态尺子是装饰"
    if "描述" not in why:
        return "方向不对：报的红不是描述那一处（%s）—— 量具打偏" % why
    # ★ 0.60.0 腿②：**委托目标**（`host_shield.create_autostart_lnk`）描述回英文
    #   也必须判红。只测 `antinel.py` 那一侧等于没守"跟随委托"——
    #   判据看着有负控，实际只验了「文件里没有那段」这一条（假绿族：负控没跑到那条腿）。
    with io.open(os.path.join(_PKG, "host_shield.py"), encoding="utf-8") as f:
        hs = f.read()
    anchor2 = "$s.Description='Antinel 监理 登录自启';"
    if anchor2 not in hs:
        return "负控②自身失效：host_shield 里的自启描述串变了"
    hs_bad = hs.replace(anchor2, "$s.Description='Antinel sentinel (no window)';", 1)
    why2 = _dsk_form_judge(_antinel_src(), hs_bad)
    if why2 is None:
        return "负控②失效：委托目标描述回英文后仍判合格 —— 跟随委托没走到底"
    if "描述" not in why2:
        return "方向不对：负控②报的红不是描述那一处（%s）—— 量具打偏" % why2
    return True


# ★ 负控检测针：.lnk 里**不许出现**的旧名/英文残留。提为模块级常量且
#   命名带 `_LEGACY` —— 这是 0360 NM01 族「禁令词常量按命名约定豁免」的
#   正典用法（内联 tuple 形态没有名字，全局改名批会把它当污染改掉）。
_LEGACY_LNK_MARKS = ("值守台", "sentinel (no window)", "Antinel sentinel")


@check("DSK15-c 真建桌面入口 .lnk 回读四性（临时目录；非 Windows/无 PS ⇒ SKIP）")
def c_dsk15c():
    if os.name != "nt":
        raise Skip("SKIP: 非 Windows（.lnk 形态不适用）")
    try:
        import antinel as A
    except Exception as e:                                       # noqa: BLE001
        raise Skip("SKIP: antinel 模块加载失败（%s）—— 环境测不出" %
                   type(e).__name__)
    tmp = _TMP.tmpdir(prefix="antinel_dsk15_")
    lnk = os.path.join(tmp, "Antinel 监理.lnk")
    got = A._create_desktop_lnk(lnk_path=lnk)
    if not got:
        return "真建失败：_create_desktop_lnk 返回 None（PS COM 路径坏了？）"
    with io.open(lnk, "rb") as f:
        data = f.read()
    # ★ 双编码**字节级**包含判定（0.52.0 实测教训）：本机 WScript.Shell
    #   产的 .lnk 的 StringData 是**全 UTF-16** 形态（ASCII/GBK 不在场）；
    #   且整文件按 utf-16-le 解码会因奇长度结构**错位**（1573 字节的链，
    #   前段对后段全乱）⇒ 只能字节级搜，不许整文件解码后搜子串。
    def _has(s):
        return (s.encode("utf-16-le") in data) or (s.encode("mbcs") in data)

    problems = []
    for needle, why in (
        ("pythonw", "目标不是 pythonw（无窗口启动）"),
        ("inbox_cli.py", "目标参数不含 inbox_cli.py"),
        ("window", "目标参数不含 window 子命令"),
        ("antinel.ico", "没挂品牌图标"),
        ("Antinel 监理", "描述不是品牌名（UTF-16/ANSI 双编码都读不到）"),
    ):
        if not _has(needle):
            problems.append(why)
    for bad in _LEGACY_LNK_MARKS:
        if _has(bad):
            problems.append("含旧名/英文残留：%s" % bad)
    away = A._archive_desktop_entry(lnk_path=lnk)
    if not away:
        problems.append("归档返回 None（入口不在？）")
    elif not os.path.isfile(away):
        problems.append("归档路径不存在：%s" % away)
    elif os.path.isfile(lnk):
        problems.append("归档后原入口还在（零删除没做到）")
    if problems:
        return "；".join(problems)
    _note("lnk=%d 字节，双编码四性全过；归档→%s" % (len(data), away))
    return True


# ═════════════════════ ICO 族：品牌图标资产（0.52.0）════════════════════════
#
# ★ 为什么进 0515：品牌图标是三个入口（.cmd 一族／桌面 .lnk／Toast AUMID）
#   共用的身份资产，与入口形态同族；资产层哨点（小黄球）的**在场＋可辨**
#   另有 FZ-005 冻结执法（regression_gate），本条守 ico 结构与打包登记。
#
# ★★ 背景（小黄球第二次弄丢，创始人 2026-10-17）：0.48.5 一批次以「AI
#   幻觉裁定」删掉 logo.svg 的 <circle>，栅格化器忠实渲染出**无球**的
#   antinel.ico，全链毫无察觉 —— 页面层的球好好着（FZ-001 Phase B2），
#   资产层的球没了。本条把尺子铺到 ico 字节：哨点纯色像素必须在场，
#   且质心与 logo.svg 的 circle 派生期望一致（不同源＝红）。

_LOGO_SVG_REL = "assets/logo/logo.svg"
_LOGO_ICO_REL = "assets/logo/antinel.ico"


def _logo_read():
    svg_p = os.path.join(_PKG, _LOGO_SVG_REL)
    ico_p = os.path.join(_PKG, _LOGO_ICO_REL)
    with io.open(svg_p, encoding="utf-8") as f:
        svg_text = f.read()
    with io.open(ico_p, "rb") as f:
        ico_bytes = f.read()
    return svg_text, ico_bytes


def _ico_images(data):
    """解析 ico ⇒ [(size, bits, [[(b,g,r,a) 顶行优先]]), ...]；结构坏抛 ValueError。"""
    import struct
    if len(data) < 6:
        raise ValueError("ico 太短（%d 字节）" % len(data))
    res, typ, n = struct.unpack_from("<HHH", data, 0)
    if (res, typ) != (0, 1):
        raise ValueError("不是 ICO（reserved=%d type=%d）" % (res, typ))
    out = []
    for k in range(n):
        w, h, _c, _r, _pl, bpp, size, off = struct.unpack_from(
            "<BBBBHHII", data, 6 + 16 * k)
        w = w or 256
        blob = data[off:off + size]
        hdr = struct.unpack_from("<IiiHHIIiiII", blob, 0)
        if hdr[0] != 40:
            raise ValueError("%dpx BMP 头尺寸 %d ≠ 40" % (w, hdr[0]))
        bw, bh, bits, comp = hdr[1], hdr[2], hdr[4], hdr[5]
        if bits != 32 or comp != 0:
            raise ValueError("%dpx 不是 32bpp 无压缩（bits=%d comp=%d）"
                             % (w, bits, comp))
        if bh != bw * 2:
            raise ValueError("%dpx 高度 %d ≠ 2×宽度（AND 掩码缺失/错位）"
                             % (w, bh))
        rows = bh // 2
        xor_len = bw * rows * 4
        stride = ((bw + 31) // 32) * 4
        and_len = stride * rows
        if len(blob) != 40 + xor_len + and_len:
            raise ValueError("%dpx 块长 %d ≠ 结构长 %d"
                             % (w, len(blob), 40 + xor_len + and_len))
        if blob[40 + xor_len:] != bytes(and_len):
            raise ValueError("%dpx AND 掩码非全零" % w)
        base = 40
        px = [[tuple(blob[base + ((rows - 1 - j) * bw + i) * 4:
                          base + ((rows - 1 - j) * bw + i) * 4 + 4])
               for i in range(bw)] for j in range(rows)]
        out.append((bw, bits, px))
    return out


def _ico_rewrite(data, repaint=None):
    """解码全部图 → 可选 repaint(from_bgra, to_bgra) → 原结构重编码。

    负控要合成「哨点被刷掉」的 ico 而又不动真文件 —— 只走内存。
    """
    import struct
    imgs = _ico_images(data)
    if repaint:
        src_c, dst_c = repaint
        for _s, _b, px in imgs:
            for row in px:
                for i, c in enumerate(row):
                    if c == src_c:
                        row[i] = dst_c
    n = len(imgs)
    offset = 6 + 16 * n
    dir_entries = bytearray()
    body = bytearray()
    for s, _b, px in imgs:
        xor = bytearray()
        for j in range(s - 1, -1, -1):              # 自底向上
            for i in range(s):
                b, g, r, a = px[j][i]
                xor += bytes((b, g, r, a))
        stride = ((s + 31) // 32) * 4
        and_mask = bytes(stride * s)
        blob = (struct.pack("<IiiHHIIiiII", 40, s, s * 2, 1, 32, 0,
                            len(xor) + len(and_mask), 0, 0, 0, 0)
                + bytes(xor) + and_mask)
        w = 0 if s >= 256 else s
        dir_entries += struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32,
                                   len(blob), offset)
        body += blob
        offset += len(blob)
    return struct.pack("<HHH", 0, 1, n) + bytes(dir_entries) + bytes(body)


def _svg_dot(svg_text):
    """logo.svg 的哨点 ⇒ (cx, cy, r, (R,G,B))；没有 circle ⇒ None。"""
    m = re.search(r"<circle\b[^>]*/>", svg_text)
    if not m:
        return None
    a = dict(re.findall(r'([\w-]+)\s*=\s*"([^"]*)"', m.group(0)))
    return (float(a["cx"]), float(a["cy"]), float(a["r"]),
            tuple(int(a["fill"][i:i + 2], 16) for i in (1, 3, 5)))


def _svg_other_colors(svg_text):
    """logo.svg 的非哨点颜色集合（背景 rect ＋ 各 path stroke）。"""
    cols = set()
    rm = re.search(r"<rect\b[^>]*/>", svg_text)
    if rm:
        ra = dict(re.findall(r'([\w-]+)\s*=\s*"([^"]*)"', rm.group(0)))
        if ra.get("fill", "").startswith("#"):
            cols.add(tuple(int(ra["fill"][i:i + 2], 16) for i in (1, 3, 5)))
    for pm in re.finditer(r"<path\b[^>]*/>", svg_text):
        pa = dict(re.findall(r'([\w-]+)\s*=\s*"([^"]*)"', pm.group(0)))
        st = pa.get("stroke", "")
        if st.startswith("#") and len(st) == 7:
            cols.add(tuple(int(st[i:i + 2], 16) for i in (1, 3, 5)))
    return cols


def _ico_judge(svg_text, ico_bytes):
    """品牌图标资产判定（正/负控**同一把尺子**，只换输入）。问题串或 None。"""
    problems = []
    dot = _svg_dot(svg_text)
    if dot is None:
        problems.append("logo.svg 没有 <circle>（小黄球/哨点）—— "
                        "0.48.5 幻觉裁定事故的断点")
    else:
        cx, cy, r, rgb = dot
        if rgb in _svg_other_colors(svg_text):
            problems.append("哨点色 #%02x%02x%02x 与环/底同色 —— 肉眼不可辨"
                            % rgb)
    try:
        imgs = _ico_images(ico_bytes)
    except ValueError as e:
        return "；".join(problems + ["antinel.ico 结构坏：%s" % e])
    sizes = sorted(s for s, _b, _p in imgs)
    if sizes != [16, 32, 48, 64]:
        problems.append("ico 尺寸 %s ≠ [16, 32, 48, 64]" % sizes)
    if dot is not None and 64 in sizes:
        cx, cy, _r, rgb = dot
        big = max(imgs, key=lambda t: t[0])
        s, _bits, px = big
        k = s / 64.0
        want = (rgb[2], rgb[1], rgb[0], 255)
        hits = [(i, j) for j in range(s) for i in range(s) if px[j][i] == want]
        if len(hits) < 8:
            problems.append("%dpx 哨点纯色像素 %d < 8（小黄球没进图标？）"
                            % (s, len(hits)))
        else:
            mx = sum(p[0] for p in hits) / float(len(hits))
            my = sum(p[1] for p in hits) / float(len(hits))
            if abs(mx - cx * k) > 2.0 or abs(my - cy * k) > 2.0:
                problems.append("哨点质心 (%.1f,%.1f) 偏离期望 (%.1f,%.1f)"
                                " —— SVG 与 ico 不同源？"
                                % (mx, my, cx * k, cy * k))
    return "；".join(problems) if problems else None


@check("ICO15-a ★ antinel.ico 四尺寸 32bpp＋掩码零＋哨点在场可辨（期望从 logo.svg 派生）")
def c_ico15a():
    svg_text, ico_bytes = _logo_read()
    why = _ico_judge(svg_text, ico_bytes)
    return why or True


@check("N-ICO15-a 负控：logo.svg 删掉 <circle> ⇒ 同一把尺子必须判红（0.48.5 形态）")
def n_ico15a():
    svg_text, ico_bytes = _logo_read()
    if "<circle" not in svg_text:
        return "夹具不成立：真 logo.svg 就没有 circle"
    mutated = re.sub(r"<circle\b[^>]*/>", "", svg_text, count=1)
    if mutated == svg_text:
        return "负控自身失效：删除没生效"
    why = _ico_judge(mutated, ico_bytes)
    if why is None or "circle" not in why:
        return ("负控失效：删掉 circle 后没报「没有 <circle>」（%s）—— "
                "0.48.5 事故形状抓不住" % why)
    return True


@check("N-ICO15-b 负控：ico 里哨点像素刷成底色 ⇒ 必须判红（栅格化吞球形态）")
def n_ico15b():
    svg_text, ico_bytes = _logo_read()
    dot = _svg_dot(svg_text)
    if dot is None:
        return "夹具不成立：真 logo.svg 没有 circle"
    _cx, _cy, _r, rgb = dot
    rm = re.search(r"<rect\b[^>]*/>", svg_text)
    ra = dict(re.findall(r'([\w-]+)\s*=\s*"([^"]*)"', rm.group(0)))
    bg = tuple(int(ra["fill"][i:i + 2], 16) for i in (1, 3, 5))
    want = (rgb[2], rgb[1], rgb[0], 255)
    mutated = _ico_rewrite(ico_bytes, repaint=(want, (bg[2], bg[1], bg[0], 255)))
    if mutated == ico_bytes:
        return "负控自身失效：重编码后字节没变（哨点色没打中？）"
    why = _ico_judge(svg_text, mutated)
    if why is None or "哨点" not in why:
        return ("负控失效：哨点像素被刷成底色后没报哨点不在（%s）—— "
                "ico 腿的尺子是装饰" % why)
    return True


def _pkgdata_judge(pyproject_text, builder_text):
    """package-data 登记判定（两处同改）。问题串或 None。"""
    problems = []
    if "logo/*.ico" not in pyproject_text:
        problems.append("仓内 pyproject.toml 缺 logo/*.ico（品牌图标不进 wheel）")
    if "logo/*.ico" not in builder_text:
        problems.append("构建器 PYPROJECT 模板缺 logo/*.ico"
                        "（两处不同改 ⇒ 下次构建把仓内改动抹掉）")
    return "；".join(problems) if problems else None


@check("ICO15-c ★ package-data 两处同含 logo/*.ico（仓内 pyproject ＋ 构建器模板）＋生成器在位")
def c_ico15c():
    with io.open(os.path.join(_PKG, "pyproject.toml"), encoding="utf-8") as f:
        p1 = f.read()
    with io.open(os.path.join(_PKG, "scripts", "build_package.py"),
                 encoding="utf-8") as f:
        p2 = f.read()
    problems = []
    why = _pkgdata_judge(p1, p2)
    if why:
        problems.append(why)
    if not os.path.isfile(os.path.join(_PKG, "tools", "mk_logo_ico.py")):
        problems.append("缺生成器 tools/mk_logo_ico.py")
    if not os.path.isfile(os.path.join(_PKG, _LOGO_ICO_REL)):
        problems.append("缺品牌图标 assets/logo/antinel.ico")
    return "；".join(problems) or True


@check("N-ICO15-c 负控：两处各缺 logo/*.ico ⇒ 同一把尺子必须判红")
def n_ico15c():
    fake_pyproject = '[tool.setuptools.package-data]\nassets = ["icons/*.ico"]\n'
    fake_builder = 'PYPROJECT = """[project]\nname = "x"\n"""\n'
    why = _pkgdata_judge(fake_pyproject, fake_builder)
    if why is None:
        return "负控失效：合成缺登记没判红 —— package-data 尺子是装饰"
    if "logo/*.ico" not in why:
        return "方向不对：报的红不是 logo/*.ico（%s）—— 量具打偏" % why
    return True


# ═════════════════ P0：体检数据出口 ＋ 提示句自洽（HSCAN 族）═════════════════
#
# ★ 由来（2026-10-17 实测，方案 v1.6 §30 的 H1/H2 落地）——两条都是
#   「实现早就写好了，只是出口没接上」，而产品**自己提示用户去敲**：
#
#   ① `antinel host-scan --json` 自 0.33.1 起**一跑就崩**
#      （TypeError: 'NoneType' object is not iterable）。`_index_obs()` 在
#      `_INDEX_SUBDIRS` 为空时**故意**返回 None，用来区分「没配置、没查」与
#      「查过、0 处」；人读分支判了 None，JSON 分支直接拿去迭代。
#      ⇒ `antinel ui` 的体检页正是靠这条命令取数，所以它永远拿不到数。
#      ⇒ 修法绝不是 `or []`（那正好把两种状态压成一种，犯 0.33.1 明令禁止的病）。
#
#   ② 提示句指向不存在的参数：`antinel host-scan --arm`（`--arm` 被注册到了
#      egress，而 egress 从不读它；真正写 findings 的代码在 host-scan 里）、
#      `antinel report --days N`（scripts/report.py:777 支持 --days，
#      但 cmd_report 从不透传）。用户照抄即 argparse 报错。
#
# ★ 为什么这条判据是「通用尺子」而不是逐条断言：提示句是产品对用户下的**指令**，
#   指令必须可执行。逐条断言只能守住今天这五行，通用尺子守得住以后新写的每一行。

_HINT_RE = re.compile(r"antinel\s+([a-z][a-z0-9-]{1,20})((?:\s+--[a-z][a-z0-9-]*)+)")
_FLAG_RE = re.compile(r"--[a-z][a-z0-9-]*")

#: 只扫**会随包分发的产品可执行出口**：仓根模块 ＋ scripts/hooks/tools。
#: 刻意不扫 output/、_archive_dist/、.worktrees/ —— 那里是历史构建快照，
#: 同一行会被重复报四次，尺子会淹在噪声里（实测过）。
_HINT_SKIP_DIRS = {"build", "out", "dist", "__pycache__", "_uxtest", "_uxtest2",
                   "node_modules", "output", "_archive_dist"}


def _run_antinel(argv, timeout=240):
    """跑产品 CLI（-E -X utf8：不吃外部 PYTHONPATH、强制 UTF-8 输出）。"""
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    tmp = os.environ.get("TEMP") or tempfile.gettempdir()
    for k in ("TMP", "TEMP", "TMPDIR"):
        env[k] = tmp
    p = subprocess.run([sys.executable, "-E", "-X", "utf8", "antinel.py"] + argv,
                       cwd=ROOT, capture_output=True, timeout=timeout, env=env)
    return (p.returncode,
            (p.stdout or b"").decode("utf-8", "replace"),
            (p.stderr or b"").decode("utf-8", "replace"))


def _product_py_sources():
    """产品可执行出口的 py 清单（仓根 ＋ scripts/hooks/tools，不递归仓根）。"""
    out = []
    for fn in os.listdir(ROOT):
        p = os.path.join(ROOT, fn)
        if os.path.isfile(p) and fn.endswith(".py"):
            out.append(p)
    for d in ("scripts", "hooks", "tools"):
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, d)):
            dirnames[:] = [x for x in dirnames if x not in _HINT_SKIP_DIRS]
            for fn in filenames:
                if fn.endswith(".py"):
                    out.append(os.path.join(dirpath, fn))
    return out


def _collect_hints():
    """抽出所有 `antinel <sub> --flag...` 形式的提示句。返回 {sub: [(行, flags, 出处)]}。

    ★ 只扫**字符串字面量**（AST Constant），不扫注释 —— 尺子第一次跑就把守则自己
      写的一条注释（「提示的 `antinel host-scan --arm` 敲不了」）判成了违规。
      真规则是「**会打印给用户看的那句话**必须可执行」，注释不打印。
    """
    hints = {}
    for path in _product_py_sources():
        try:
            text = io.open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        rel = os.path.relpath(path, ROOT).replace("\\", "/")
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            for m in _HINT_RE.finditer(node.value):
                sub, flags = m.group(1), _FLAG_RE.findall(m.group(2))
                where = "%s:%d" % (rel, getattr(node, "lineno", 0))
                hints.setdefault(sub, []).append(
                    (getattr(node, "lineno", 0), flags, where))
    return hints


def _sub_flags(sub):
    """该子命令的 argparse 真实参数集合；子命令不存在 ⇒ None。"""
    rc, out, err = _run_antinel([sub, "--help"], timeout=90)
    if rc != 0:
        return None
    return set(_FLAG_RE.findall(out + err))


def _hint_judge(hints, helps):
    """提示句 vs 真实参数。返回问题串或 None（正/负控同一把尺子，只换输入）。"""
    bad = []
    for sub in sorted(hints):
        real = helps.get(sub)
        if real is None:
            bad.append("%s：--help 取不到参数（子命令本身不存在？）" % sub)
            continue
        for _line, flags, where in hints[sub]:
            miss = [f for f in flags if f not in real]
            if miss:
                bad.append("%s 提示了不存在的 %s" % (where, "、".join(miss)))
    return "；".join(bad) if bad else None


def _hscan_judge(rc, out, err, expect_unconfigured):
    """`host-scan --json` 出口判定。返回问题串或 None（正/负控同一把尺子）。

    ★ 核心不是「能跑」，是**两种状态不许压成一种**：
      expect_unconfigured=True ⇒ `index_dirs` 必须是 null（没配置、没查）；
      若给 `[]`，就是把「没查」说成「查过、0 处」——比崩溃更危险，因为它看起来是结论。
    """
    if rc != 0:
        tail = [l for l in (err or "").strip().splitlines() if l.strip()]
        return "returncode=%d（stderr 尾：%s）" % (
            rc, tail[-1][:140] if tail else "空")
    text = out or ""
    i = text.find("{")
    if i < 0:
        return "stdout 里找不到 JSON 起始（%d 字节全是人读日志）" % len(text)
    try:
        d = json.loads(text[i:])
    except Exception as e:                                      # noqa: BLE001
        return "stdout 尾部不是可解析 JSON：%r" % (e,)
    obs = d.get("observations")
    if not isinstance(obs, dict):
        return "载荷缺 observations 字典（明细单的四组数据都在这里）"
    if "index_dirs" not in obs:
        return "observations 缺 index_dirs 键"
    v = obs["index_dirs"]
    if expect_unconfigured:
        if v == []:
            return ("index_dirs=[] —— 把「没配置、没查」渲染成了「查过、0 处」"
                    "（0.33.1 明令要区分的两种状态被压成一种）")
        if v is not None:
            return "index_dirs 应为 null（未配置），实得 %r" % (v,)
    else:
        if v is None:
            return "index_dirs=null 但 _INDEX_SUBDIRS 非空（该查却没查）"
        if not isinstance(v, list):
            return "index_dirs 应为数组或 null，实得 %r" % (v,)
    return None


@check("HSCAN15-a ★ host-scan --json 出口可用：JSON 可解析 ＋ index_dirs 区分「没配置」与「查过为空」")
def c_hscan15a():
    import antinel as A
    expect_unconfigured = not getattr(A, "_INDEX_SUBDIRS", None)
    rc, out, err = _run_antinel(["host-scan", "--json"])
    why = _hscan_judge(rc, out, err, expect_unconfigured)
    if why:
        return why
    payload = json.loads(out[out.find("{"):])
    _note("rc=0；_INDEX_SUBDIRS %s ⇒ index_dirs=%r"
          % ("为空" if expect_unconfigured else "非空",
             payload.get("observations", {}).get("index_dirs")))
    return True


@check("N-HSCAN15-a 负控：把「没配置」渲染成 []（旧形态）或让 rc=3 崩掉 ⇒ 同一把尺子必须判红")
def n_hscan15a():
    ok_payload = json.dumps({"observations": {"index_dirs": None}},
                            ensure_ascii=False)
    bad_payload = json.dumps({"observations": {"index_dirs": []}},
                             ensure_ascii=False)
    if _hscan_judge(0, ok_payload, "", True):
        return "负控反向失败：null（正确形态）被判红 —— 尺子会误伤"
    why = _hscan_judge(0, bad_payload, "", True)
    if not why:
        return "负控失效：[] （把没查说成 0 处）被判绿 —— 尺子没分辨力"
    crash = _hscan_judge(3, "", "TypeError: 'NoneType' object is not iterable", True)
    if not crash:
        return "负控失效：rc=3 的崩溃形态被判绿"
    if "NoneType" not in crash and "returncode" not in crash:
        return "方向不对：报的红不是崩溃本身（%s）—— 量具打偏" % crash
    _note(why)
    return True


@check("HSCAN15-b ★ 产品提示的 `antinel <sub> --flag` 必须是该子命令的真实参数（通用尺子）")
def c_hscan15b():
    hints = _collect_hints()
    if not hints:
        return "一条提示句都没抓到 —— 抽取器坏了（不是产品干净）"
    helps = {s: _sub_flags(s) for s in sorted(hints)}
    why = _hint_judge(hints, helps)
    if why:
        return why
    _note("扫了 %d 个产品 py、%d 条提示句、%d 个子命令，参数全部真实"
          % (len(_product_py_sources()), sum(len(v) for v in hints.values()),
             len(hints)))
    return True


@check("N-HSCAN15-b 负控：合成一句指向不存在参数的提示 ⇒ 同一把尺子必须判红；参数真实时不许误伤")
def n_hscan15b():
    real = {"report": {"--session", "--write", "--help"}}
    bad = {"report": [(1, ["--days"], "fake.py:1")]}
    good = {"report": [(1, ["--session"], "fake.py:2")]}
    why = _hint_judge(bad, real)
    if not why:
        return "负控失效：指向不存在参数的提示被判绿（尺子没分辨力）"
    if "--days" not in why:
        return "方向不对：报的红里没有 --days（%s）—— 量具打偏" % why
    if _hint_judge(good, real):
        return "负控反向失败：参数真实却被判红 —— 尺子会误伤"
    _note(why)
    return True


# ══════════════════ 归因：宿主人话名（0.53.0 T6.1／T6.2）══════════════════

#: 写了等于没核实的占位词（比对一律小写）
_HN15_PLACEHOLDERS = {"todo", "tbd", "?", "??", "待定", "待核实", "待确认",
                      "unknown", "none", "n/a", "na", "xxx"}


def _host_files(root):
    """`rules/hosts/*.json` → `{host: name（可能为 None）}`（只读，不改任何文件）。"""
    gdir = os.path.join(root, "rules", "hosts")
    out = {}
    for f in sorted(os.listdir(gdir)):
        if not f.endswith(".json"):
            continue
        d = json.load(io.open(os.path.join(gdir, f), encoding="utf-8"))
        out[str(d.get("host") or f[:-5])] = d.get("name")
    return out


def _detect_labels():
    """检测器**能产出的全部标签** —— 从 `hooks/_host_detect.py` 真源里取，不手抄。

    ★ 三处来源：`_ENV_KEYS` 的值、`_DIR_MARKERS` 的值、`_normalize_explicit`
      里的别名表。别名表用 `ast` 取字面量 —— 正则会被它上方注释里的引号骗
      （0.51.2 踩过一次同型：剥标签正则贪心）。
    ★ `generic` 不算宿主：它是 detect 失败的兜底标签（P18 同一纪律）。
    """
    import importlib.util
    src = os.path.join(ROOT, "hooks", "_host_detect.py")
    spec = importlib.util.spec_from_file_location("_hn15_host_detect", src)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    labels = {v for _, v in mod._ENV_KEYS} | {v for _, v in mod._DIR_MARKERS}
    tree = ast.parse(io.open(src, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_normalize_explicit":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Dict):
                    try:
                        labels |= set(ast.literal_eval(sub).values())
                    except Exception:                       # noqa: BLE001
                        continue
    labels.discard(getattr(mod, "_GENERIC", "generic"))
    return labels


def _names_in(root):
    """在**指定 root** 下取宿主名表（临时改全局缓存，`finally` 还原 —— 纪律）。"""
    import host_shield as HS
    old = getattr(HS, "_HOST_NAMES_CACHE", None)
    try:
        HS._HOST_NAMES_CACHE = None
        return HS.host_names(root)
    finally:
        HS._HOST_NAMES_CACHE = old


def _hostname_core(root):
    """T6.1 的唯一尺子（`root` 可注入 ⇒ 负控喂一份坏表，其余判据同型）。

    四条腿：
      ① 检测器能产出的标签 **⊆** 宿主表（新增检测标签却忘了加宿主 ⇒ 页面上是裸标签）；
      ② `name` 若存在：非空、且不是占位词（"待核实/TODO/?" 这类写了等于没核实）；
      ③ 没填 `name` 的宿主：显示名**退回原标签**，不许编一个好听的（"没核实"不得显示成"已核实"）；
      ④ 显示名出口只有一处（`host_names`），页面取的就是它。

    ★★ 为什么**不**卡「name 不许等于标签」：品牌名与机读标签常常只差大小写
      （`workbuddy` → `WorkBuddy`、`cursor` → `Cursor`）—— 那是**正确的官方名**，
      把这种形态判红＝尺子误伤真实现（本批首跑实测：24 个里 11 个被误判）。
    """
    hosts = _host_files(root)
    if not hosts:
        return "宿主表为空 —— 判据无法成立"
    names = _names_in(root)

    # ① 检测器标签 ⊆ 宿主表
    missing = sorted(l for l in _detect_labels() if l not in hosts)
    if missing:
        return ("检测器能产出宿主表里没有的标签：%s —— 会显示成裸标签"
                % "、".join(missing))

    # ② name 非空、不是占位词
    bad = []
    for h, nm in sorted(hosts.items()):
        if nm is None:
            continue
        t = str(nm).strip()
        if not t:
            bad.append("%s（name 是空的）" % h)
        elif t.lower() in _HN15_PLACEHOLDERS:
            bad.append("%s（name 是占位词 %r，等于没核实）" % (h, t))
    if bad:
        return "宿主 name 写了等于没写：%s" % "；".join(bad)

    # ③ 没填 name ⇒ 退回原标签（不许编）
    for h, nm in sorted(hosts.items()):
        if nm is not None:
            continue
        if names.get(h) is not None:
            return "没填 name 的宿主 %s 却在名表里（表只能收写了 name 的）" % h
    for h in sorted(hosts):
        disp = names.get(h) or h
        if not str(disp).strip() or str(disp).strip() == "None":
            return "宿主 %s 的显示名是空/None —— 页面会露出一格空" % h

    # ④ 页面出口同源（取真实宿主实测，要求与名表逐字一致）
    import inbox_server as SV
    got = SV._host_label
    for h in ("workbuddy", "qoder", "claude-code"):
        if h not in hosts:
            continue
        want = names.get(h) or h
        if got(h) != want:
            return ("页面显示的 %s 名字与宿主表不一致（页面 %r vs 表 %r）"
                    % (h, got(h), want))
    return True


def _bad_root(mutator):
    """造一份**坏宿主表**的临时 root（只复制 json，不碰真表）。"""
    import shutil
    tmp = _TMP.tmpdir(prefix="g0515_hn15_")
    dst = os.path.join(tmp, "rules", "hosts")
    os.makedirs(dst)
    src = os.path.join(ROOT, "rules", "hosts")
    for f in sorted(os.listdir(src)):
        if f.endswith(".json"):
            shutil.copy2(os.path.join(src, f), os.path.join(dst, f))
    mutator(dst)
    return tmp


def _set_name(gdir, host, value):
    fp = os.path.join(gdir, host + ".json")
    d = json.load(io.open(fp, encoding="utf-8"))
    d["name"] = value
    io.open(fp, "w", encoding="utf-8", newline="").write(
        json.dumps(d, ensure_ascii=False, indent=1) + chr(10))


def _drop_name(gdir, host):
    fp = os.path.join(gdir, host + ".json")
    d = json.load(io.open(fp, encoding="utf-8"))
    d.pop("name", None)
    io.open(fp, "w", encoding="utf-8", newline="").write(
        json.dumps(d, ensure_ascii=False, indent=1) + chr(10))


@check("HN15 ★ T6.1：宿主人话名 —— 检测器标签 ⊆ 宿主表，name 不空也不是占位词")
def c_host_names_cover_detector_labels():
    """设计 §6 最后两条（`rules/hosts/*.json` 加 name ＋ 判据守覆盖）。

    ★ 为什么这条不能只卡"都有 name"：设计自己写了「核实不了先显示原标签」——
      所以合规形态有两种（写了名字／显式退回标签）。真正要挡的是三种假动作：
      把 name 留空、拿占位词当名字、检测器新增了标签却忘了登记宿主。
    """
    return _hostname_core(ROOT)


@check("N-HN15 负控：name 清空 / 占位词 / 删掉一个宿主 ⇒ HN15 必须红")
def n_host_names_cover_detector_labels():
    """三个方向各喂一次坏表（都在临时目录，真表一字节不动）。"""
    def _drop_host(g):
        os.remove(os.path.join(g, "qoder.json"))

    cases = [
        ("清空 name", lambda g: _set_name(g, "workbuddy", ""), "空的"),
        ("name 写成待核实", lambda g: _set_name(g, "trae", "待核实"), "占位词"),
        ("删掉 qoder 宿主", _drop_host, "没有的标签"),
    ]
    for desc, fn, want in cases:
        root = _bad_root(fn)
        why = _hostname_core(root)
        if why is True:
            return "负控失效：%s 之后 HN15 仍判绿（那条腿是摆设）" % desc
        if want not in str(why):
            return "方向不对：%s 的红因不是「%s」（%s）—— 量具打偏" % (
                desc, want, str(why)[:60])
        _note(desc, "→", str(why)[:50])
    return True


def main():
    print("=" * 78)
    print("0515 判据 —— P0-3 antinel.cmd 入口（CRLF+ASCII）· "
          "P0-2 判据 ID 唯一化（映射+重名检测）· "
          "0.52.0 桌面入口 .lnk 与品牌图标（DSK/ICO 族）· "
          "0.53.0 T6.1/T6.2 宿主人话名（HN15/N-HN15：检测器标签 ⊆ 宿主表；"
          "name 不许为空、不许拿占位词顶；没核实一律退回原标签，不许编）")
    print("（负控全部内存/临时目录变异，不写任何产品文件）")
    print("=" * 78)
    ok = fail = skip = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True or why is None:
                why = ""
            print("  ✅ %-58s %s" % (name, why or ""))
            ok += 1
        except Skip as s:
            print("  ⏭️  %-58s %s" % (name, s))
            skip += 1
        except AssertionError as e:
            print("  ❌ %-58s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-58s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红 / %d 跳过" % (ok, fail, skip))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
