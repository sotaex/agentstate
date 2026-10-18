#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.43.0 判据 —— **自愈事件不得再顶 R0** ＋ **去星号不许只治一半**（A3 收口 ＋ S47 补漏）。

★★ 这一份判据的由来（2026-10-10 对"还有没有虚报"的专项复核）：

    链上实测（`_p_r0_audit3.py`，24h 窗口）：
      · `host_shield_tamper` 41 条，其中 **17 条 `recovered=true`**，
        却**一律 `severity=critical`**；
      · 定档是**按类型一刀切**（`LEVEL_OF_KIND["host_shield_tamper"] = "R0"`），
        不看 `recovered` ⇒ 页面上长出自相矛盾的标题
        「**失守**：防护文件被改动（状态被改，**已自动恢复**）」。
      · 而 `bucket_of` 早就把它们判进 `info`（不占待办）—— 于是同一条记录
        **档位说失守、分桶说不用管**。这是典型的两处口径各判一半。

    ⇒ 修法不是"在页面把标题改一下"，而是**定档下沉到记录级**：
      `level_of_record()`（★ 唯一实现）＋ `title_of_record()`（标题必须与级别同向），
      并把 0.40.0 的 A8（zone 上锁成败）**收编进来** —— 因为它此前是投影层
      手写的一段 `if`（第二套口径，本仓「同一事实两处实现」的标准形状）。

    第二件事（同一轮实测发现）：0.42.0 的 `_vis()` 只做了**网页**两条渲染路径，
    **命令行**（`inbox_cli.py list`）那条漏了 ⇒ `**不等于**` 照样吐给用户
    （实测 `grep -c '\\*\\*'` = 1+）。⇒ 去星号收进 `inbox_model.visible_text`，
    网页与 CLI 共用一份（不许各写一份）。

  ★ 编写纪律（沿用 `inbox_guards_0400.py` 头部）：
    · 每条判据配负控，且负控**真的会红**（内存里变异源码后重载，不是"算一遍就丢"）；
    · 判据**只查行为/结构**，不查文案 —— 凡按源码字面查的，一律走 **AST**；
    · **不写任何产品文件**：变异只发生在内存字符串上，磁盘一个字节都不动。
"""
from __future__ import annotations

import ast
import io
import os
import subprocess
import sys
import time
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

RESULTS = []


def check(name):
    """★ 判据**必须真会红** —— 返回说明串一律转成抛异常（同 0400 的收紧）。"""
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


def _load_model(src=None):
    """把（可能被变异过的）`inbox_model.py` 加载成新模块对象。

    ★ 为什么可以：`inbox_model` 只 import 标准库（hashlib/re/dataclasses/datetime），
      没有仓内相对导入 ⇒ 在干净命名空间里 exec 不缺依赖。
    """
    if src is None:
        import inbox_model as _m
        return _m
    mod = types.ModuleType("inbox_model_mutated")
    mod.__file__ = os.path.join(ROOT, "inbox_model.py")
    # ★ 必须先登记进 sys.modules：本模块用了 `@dataclass`，而 dataclasses 会
    #   反查 `sys.modules[cls.__module__].__dict__` ⇒ 不登记就 AttributeError
    #   （这不是产品缺陷，是量具的加载姿势不对）。
    sys.modules["inbox_model_mutated"] = mod
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)      # noqa: S102
    return mod


def _replace_line(src, needle, newline):
    """按**整行**替换（比精确字符串锚点稳：缩进/换行写法一变锚点就失配）。"""
    lines = src.split("\n")
    for i, ln in enumerate(lines):
        if needle in ln:
            lines[i] = newline
            return "\n".join(lines)
    return None


def _judge_demote(mod):
    """★ A/B 判定的**同一把尺子**：真身与变异体都交给它量。"""
    if mod.level_of_record("host_shield_tamper", recovered=True) != "L1":
        return False                       # 自愈没降档 ⇒ 判据失败
    if mod.level_of_record("host_shield_tamper", recovered=False) != "R0":
        return False                       # 把真失守也降了 ⇒ 一刀切，同样失败
    # 标题必须同向：降档后不许还挂着「失守」
    t = mod.title_of_record("host_shield_tamper", "L1", "state_drift")
    if t.startswith("失守"):
        return False
    return True


# ══════════ S50 · 自愈降档（记录级），且不误伤真失守 ══════════════════════
@check("S50 ★ 自愈（recovered=True）⇒ 降为 L1；recovered=False 的真失守仍 R0；标题不许再写『失守』")
def s50():
    m = _load_model()
    if not hasattr(m, "level_of_record") or not hasattr(m, "title_of_record"):
        return "缺 `level_of_record` / `title_of_record` —— 定档没有下沉到记录级"
    if not _judge_demote(m):
        return "记录级定档不成立（降档缺失／或把真失守一起降了／或标题仍写『失守』）"
    return True


@check("N-S50 负控：抽掉 recovered 降档分支 ⇒ S50 必须报红")
def n_s50():
    src = _src("inbox_model.py")
    mut = _replace_line(src, "recovered and lvl in DEMOTE_RECOVERED_FROM", "    if False:")
    if mut is None:
        return "负控无效：找不到降档分支所在行（产品已改写法？负控要同步）"
    try:
        m = _load_model(mut)
    except SyntaxError as e:
        return "负控无效：变异造成语法错（%s）—— 换不破坏语法的变异写法" % e
    if _judge_demote(m):
        return "负控失效：抽掉降档分支后判据仍绿 —— S50 分辨不出这次复发（判据白装）"
    return True


# ══════════ S51 · 改档只许一处：投影层不许手写「_a.level = "L1"」 ═══════════
def _project_record_props(src):
    """AST：project_record 里有没有手写字面改档／有没有走 level_of_record。"""
    tree = ast.parse(src)
    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "project_record":
            fn = node
            break
    if fn is None:
        return None
    uses_record_api = False
    literal_level = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in ("level_of_record", "title_of_record"):
                uses_record_api = True
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Attribute) and tgt.attr == "level" \
                        and isinstance(node.value, ast.Constant) \
                        and isinstance(node.value.value, str):
                    literal_level = True
    return uses_record_api, literal_level


@check("S51 ★ 结构：投影层走 level_of_record（唯一实现），且不许手写 `_a.level = \"…\"` 改档")
def s51():
    props = _project_record_props(_src("inbox_store.py"))
    if props is None:
        return "找不到 project_record()"
    uses_record_api, literal_level = props
    if not uses_record_api:
        return "project_record 没有调用 `level_of_record` —— 定档还在按类型一刀切"
    if literal_level:
        return "project_record 里出现字面改档（`_a.level = \"…\"`）—— 那是第二套口径，" \
               "A8 就是这么长出来的；改档必须只走 `level_of_record`"
    return True


@check("N-S51 负控：在投影层插回一段手写改档 ⇒ S51 必须报红")
def n_s51():
    src = _src("inbox_store.py")
    anchor = "        _a.title = M.title_of_record(t, _a.level, _topic)"
    if anchor not in src:
        return "负控无效：找不到标题赋值行可供变异"
    mut = src.replace(anchor, '        _a.level = "L1"\n' + anchor, 1)
    props = _project_record_props(mut)
    if props is None or not props[1]:
        return "负控失效：插回手写改档后 S51 的判据仍看不出来 —— 判据白装"
    return True


# ══════════ S52 · 去星号：网页与命令行共用唯一实现 ════════════════════════
def _cli_detail_goes_through_vis(src):
    """AST：`cmd_list` 里 detail 打印点是否过 `visible_text`（不许直接打原始文本）。

    ★ 0.52.0：两种合法形状（同一不变式的两种表达，都满足「detail 不过裸文本」）：
      ① `M.visible_text(i.detail)` —— 0.42.0 原形状（detail 直穿）；
      ② `M.visible_text(M.record_meta(i))` —— 0.51.2 第二轮起：列表说明行与
         网页同口径走 `record_meta`（唯一实现，内部 strip_governance 消费
         detail），visible_text 在外层做人话化 —— 与网页 `_vis(record_meta)`
         逐层同构。detail 经由 record_meta 消费 ⇒ 两种形状等价。
    ★ 为什么按 AST 精确到 visible_text 那个调用：全文搜 visible_text 会命中
      另外两处（title／snippet）⇒ 负控摘掉 detail 那处后判据仍绿 ⇒ **负控假绿**。
    """
    tree = ast.parse(src)
    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "cmd_list":
            fn = node
            break
    if fn is None:
        return None
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "visible_text":
            if not node.args:
                continue
            a = node.args[0]
            if isinstance(a, ast.Attribute) and a.attr == "detail":
                return True
            if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) \
                    and a.func.attr == "record_meta":
                return True
    return False


@check("S52 ★ 去星号只有一个实现：CLI 用 M.visible_text ／ 网页 _vis 转调它 ／ 行为上去得掉")
def s52():
    m = _load_model()
    if not hasattr(m, "visible_text"):
        return "缺 `visible_text` —— 去星号没有收进唯一实现"
    if m.visible_text("上锁未生效；**不等于**有进程在对抗") != "上锁未生效；不等于有进程在对抗":
        return "visible_text 没去掉星号（行为不成立）"
    if _cli_detail_goes_through_vis(_src("inbox_cli.py")) is not True:
        return "命令行的 detail 打印点没有过 visible_text —— 0.42.0 只治了网页，CLI 这条漏了"
    # 网页侧：_vis 必须转调 M.visible_text（不许再自己写一份正则）
    tree = ast.parse(_src("inbox_server.py"))
    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_vis":
            fn = node
            break
    if fn is None:
        return "找不到 inbox_server._vis"
    ok = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "visible_text" for n in ast.walk(fn))
    if not ok:
        return "inbox_server._vis 没有转调 `M.visible_text` —— 两份实现会各自漂移"
    return True


@check("N-S52 负控：把 CLI 的 visible_text 摘掉 ⇒ S52 必须报红")
def n_s52():
    src = _src("inbox_cli.py")
    # ★ 0.52.0：锚点随产品形状走 —— CLI 详情行现为
    #   `M.visible_text(M.record_meta(i))`（0.51.2 第二轮同网页口径）。
    #   变异＝摘掉外层 humanize（退回 0.51.2 漏 machine 腔那一态）⇒ 必须红。
    old = "        meta = M.visible_text(M.record_meta(i))"
    if old not in src:
        return "负控无效：找不到 CLI 的去星号调用点"
    mut = src.replace(old, "        meta = M.record_meta(i)", 1)
    if mut == src:
        return "负控无效：变异没生效（锚点未命中）"
    if _cli_detail_goes_through_vis(mut) is not False:
        return "负控失效：摘掉 detail 的去星号后判据仍绿 —— S52 分辨不出这次复发"
    return True


# ★★ 0.52.0（2026-10-17 实测复发）：桌面「Antinel 监理」入口双击**毫无反应**。
#   根因：入口是 `pythonw -I -S inbox_cli.py window`——`-I` 隐含 `-P`
#   （Python 3.11+：隔离模式下**脚本目录不进 sys.path**，为的是挡住
#   PYTHONPATH 投毒，顺带把同目录兄弟模块也挡了）⇒ inbox_cli.py 顶层的
#   `import inbox_config` 直接 ModuleNotFoundError；pythonw 无控制台，traceback
#   哪都不显示 ⇒ 用户侧只看到「没反应」。修法＝入口自举（host_shield
#   `_ensure_pkg_on_path()` 同款）。
#   此前五套判据**全部只测 lnk 形状/源码文本，没有一个真跑过这条入口**（DSK15
#   建临时 lnk 只回读四性）⇒ 判据全绿而用户点不动。本对判据把尺子钉在
#   **真执行**上。
_BOOTSTRAP_ANCHOR = ("sys.path.insert(0, "
                     "os.path.dirname(os.path.abspath(__file__)))")


def _decode_any(b):
    """子进程字节 → 文本（**按子进程真实编码解，不假定是 utf-8**）。

    ★★ 0.53.0（本批实测抓到）：`-I` 蕴含 `-E`，所以父进程的
      `PYTHONIOENCODING` / `PYTHONIOENCODING` 类环境变量**一概被忽略**，
      子进程按控制台代码页写（中文 Windows ＝ cp936）。而尺子原来用
      `encoding="utf-8"` 硬解 ⇒ 输出的每一个汉字都变成替换符 ⇒
      「没打印列表头」判红，**而入口其实跑得好好的**（手测 rc=0、
      第一行就是「当前载入 492 条」）。这不是产品缺陷，是**量具的编码假设**错了。
    ★ 不去给子进程加 `-X utf8`：那会改掉「桌面 lnk 同手法」这个被测对象本身。
    """
    for enc in ("utf-8", "gbk", "cp936"):
        try:
            return b.decode(enc)
        except Exception:                                   # noqa: BLE001
            continue
    return b.decode("utf-8", "replace")


def _run_cli_isolated(py_path):
    """按桌面入口同手法真跑 `python -I -S <file> list`（只读子命令）。

    返回 `(rc, out, err)`；解释器起不来/超时 ⇒ `(None, "", 原因)`。
    list 只读载入（`S.load_items()` 打印），不开窗、不写盘。
    """
    try:
        r = subprocess.run([sys.executable, "-I", "-S", py_path, "list"],
                           capture_output=True, timeout=120, cwd=ROOT)
        return (r.returncode, _decode_any(r.stdout or b""),
                _decode_any(r.stderr or b""))
    except subprocess.TimeoutExpired:
        return None, "", "120s 未返回"
    except OSError as e:                                    # noqa: BLE001
        return None, "", repr(e)


@check("S56 ★ 入口真跑：inbox_cli.py 在 -I -S 隔离模式下起得来（桌面 lnk 同手法）")
def s56():
    cli = os.path.join(ROOT, "inbox_cli.py")
    if not os.path.isfile(cli):
        return "SKIP：inbox_cli.py 不在位（量具测不出，不假绿）"
    rc, out, err = _run_cli_isolated(cli)
    if rc is None:
        return "SKIP：%s（环境问题，不判红也不假绿）" % err
    if rc != 0:
        return ("入口崩了：`python -I -S inbox_cli.py list` rc=%d —— "
               "桌面双击同样崩（pythonw 下连 traceback 都看不到）；"
               "stderr 尾部=%s" % (rc, err.strip()[-200:]))
    if "当前载入" not in out:
        return ("入口 rc=0 但没打印列表头（提前退出或换了输出口径）—— "
               "rc=0 不等于入口真的在服务" % ())
    return True


@check("N-S56 负控：摘掉自举的同目录副本必须起不来；原样副本必须起得来（两臂防 vacuous）")
def n_s56():
    src = _src("inbox_cli.py")
    if _BOOTSTRAP_ANCHOR not in src:
        return ("负控无效：找不到入口自举行（锚点漂移——产品形状变了，"
               "先更新负控再谈红绿）")
    probe = os.path.join(ROOT, "_p_ns56_probe.py")   # _p_ 惯例：gitignore；SPDX 头随原字节保留
    try:
        # 臂①（原样）：副本在仓根，自举生效 ⇒ 必须起得来
        with open(probe, "w", encoding="utf-8", newline="") as f:
            f.write(src)
        rc_ok, out_ok, err_ok = _run_cli_isolated(probe)
        # 臂②（变异）：摘掉自举 ⇒ 同一路径必须起不来（复现 0.52.0 事故形态）
        mut = src.replace(_BOOTSTRAP_ANCHOR, "pass  # 负控变异：自举被摘掉", 1)
        if mut == src:
            return "负控无效：变异没生效（锚点未命中）"
        with open(probe, "w", encoding="utf-8", newline="") as f:
            f.write(mut)
        rc_bad, _out_bad, err_bad = _run_cli_isolated(probe)
    finally:
        # 零删除纪律：只改名让开（与 release.py housekeeping 同惯例）
        if os.path.isfile(probe):
            os.replace(probe, probe + ".away-" + time.strftime("%Y%m%d-%H%M%S"))
    if rc_ok != 0 or "当前载入" not in out_ok:
        return "夹具失效：原样副本在仓根都起不来（rc=%r, %s）——先修量具" % (
            rc_ok, err_ok.strip()[-160:])
    if rc_bad == 0:
        return ("负控失效：摘掉自举后副本仍起得来 —— S56 没接在真闸上，"
               "分辨不出这次复发形态")
    return True


def main():
    print("=" * 78)
    print("0.43.0 判据 —— 自愈事件不得再顶 R0 ＋ 去星号不许只治一半（A3 收口）"
          "＋ 入口隔离模式可执行（S56）")
    print("（S50–S52 全部内存变异；S56/N-S56 真跑只读入口，探针改名让开、零删除）")
    print("=" * 78)
    ok = fail = 0
    for name, fn in RESULTS:
        try:
            why = fn()
            if why is True:
                why = ""
            print("  ✅ %-58s %s" % (name, why or ""))
            ok += 1
        except AssertionError as e:
            print("  ❌ %-58s %s" % (name, e))
            fail += 1
        except Exception as e:                                  # noqa: BLE001
            print("  💥 %-58s %r" % (name, e))
            fail += 1
    print("-" * 78)
    print("  %d 绿 / %d 红" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
