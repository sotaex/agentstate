#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0515 判据 —— P0-3 一键入口 antinel.cmd ＋ P0-2 判据 ID 唯一化（四件套）。

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
"""
from __future__ import annotations

import io
import os
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
    d = tempfile.mkdtemp(prefix="g0515_cmd_")
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


def main():
    print("=" * 78)
    print("0515 判据 —— P0-3 antinel.cmd 入口（CRLF+ASCII）· "
          "P0-2 判据 ID 唯一化（映射+重名检测）")
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
