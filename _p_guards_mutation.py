# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""0.36.0 判据的变异检验：把产品改坏，判据必须变红。

★ 为什么必须做：恒真的判据等于没有判据。本项目反复栽在"看起来有判据、
  其实判的是恒真"上（本轮前面已栽过三次：中文引号语法错、
  只剥 `#` 没剥 docstring、把字符串字面量清空）。

★ 做法：备份 → 打一处**真实缺陷** → 跑判据 → 记红 → 还原 → 复跑。
  每一条都必须"变异后红、还原后绿"，否则那条判据不成立。

用法：python _p_guards_mutation.py
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "ci", "inbox_guards_0360.py")
#: ★ 0.36.2：变异检验也必须跑 0362 判据文件。
#:   理由：Q09–Q12 这几条变异对应的是 0362 的判据编号（P06/P08b/P08c/P14），
#:   只跑 0360 就**永远看不到它们变红** ⇒ 变异"跑过了"却是假覆盖。
#:   ⇒ `run_guards` 跑**两个**文件，任一红即算变异生效。
GUARD2 = os.path.join(HERE, "ci", "inbox_guards_0362.py")
#: ★ 0.36.3：同样纳入 R01–R12（状态封闭 / 研发态 / 大窗零残留）。
#:   理由同上 —— 不跑它，Q13–Q18 的判据编号永远看不到变红。
GUARD3 = os.path.join(HERE, "ci", "inbox_guards_0363.py")
#: ★ 0.36.4：纳入 A1/B1–B5/C1–C4/D1–D4（研发态定义 / 不掩盖 / 自动收敛 / 自检盲区）。
#:   理由同上 —— 不跑它，Q21–Q25 的判据编号永远看不到变红。
GUARD4 = os.path.join(HERE, "ci", "inbox_guards_0364.py")
PY = sys.executable

#: ★★ 0.36.5b：「在途标志」—— 用来发现**本脚本被外部强杀**。
#:
#:   实测事故（本轮第二次，同型）：跑变异检验时我中断了进程，
#:   `inbox_model.py:806` 留下一行 `if False:  # MUTANT: 删掉兜底…`
#:   ⇒ 未知姿态又会**悄悄打绿**（正是 0.36.3 那条用户投诉的原始形态）。
#:   ⇒ 根因不是"忘了还原"：`try/finally` 写对了，但**进程被 SIGKILL/强杀时
#:     Python 根本没有机会执行 `finally`** —— 那是物理限制，任何 `finally` 都无效。
#:   ⇒ 唯一可靠的做法：**在动手改产品之前，先在盘上留一个"我正在改"的标记**，
#:     正常收尾时清掉它。标记还在 ⇒ 上一次没善终 ⇒ 工作区脏，必须人工核对。
#:   ★ 与「编译一次就写 .stamp、崩了就留下」是同一个套路；
#:     这里不能靠"我保证会还原"，只能靠**证据留痕**。
_INFLIGHT = os.path.join(HERE, "_p_mutation_inflight.json")


def _inflight_begin():
    import json
    import time
    try:
        with open(_INFLIGHT, "w", encoding="utf-8") as f:
            json.dump({"pid": os.getpid(), "started": time.time()}, f)
    except Exception:                                          # noqa: BLE001
        pass


def _inflight_end():
    """正常收尾时清标志。**只在确认工作区已干净之后才调用。**"""
    try:
        if os.path.isfile(_INFLIGHT):
            os.remove(_INFLIGHT)
    except Exception:                                          # noqa: BLE001
        pass


def inflight_left_over():
    """上一次变异检验是否没善终（被强杀/断电/关窗口）。"""
    if not os.path.isfile(_INFLIGHT):
        return None
    try:
        import json
        with open(_INFLIGHT, encoding="utf-8") as f:
            return json.load(f)
    except Exception:                                          # noqa: BLE001
        return {"pid": None, "started": None}


def scan_for_mutants():
    """★ 0.36.5：扫**产品文件**里是否还有变异痕迹，返回 `[(文件, 行号)]`。

    ★★★ 为什么必须有这条（实测事故，不是假想）：
      本轮跑变异检验时，基线红 → 脚本在 `try/finally` **之前**
      直接 `return 1` ⇒ 上一轮没还原的变异**留在产品代码里**返回去了。
      留下的那处是 `inbox_server.py` 的一行 `if False:  # MUTANT: ...`，
      它把 `if WIN is not None:` 的缩进留在原地 ⇒ **整个文件语法错误**。
      ⇒ 后果：此后任何判据/服务都起不来，而日志最后一行写着
        「基线就不绿，先修判据再谈变异」—— 看着像一条正常结论。
      ★ 这是本仓铁律「崩了 ≠ 抓住了」的**最坏形态**：
        不只是"崩了"，而是**崩了并且把脏东西留下，还报得像结论**。

    ★ 扫的必须是**产品文件**，不是判据文件 ——
      判据里出现 "MUTANT" 是正常的（本脚本的变异体就写在那里）。
    ★ 判据用**标记字样**而不是"与备份逐字比对"：
      逐字比对能发现任何改动，但会把人**正在写的新代码**也报成残留
      （本脚本运行期间开发者完全可能正常编辑）⇒ 那是误报，
      而误报会让这条检查被无视。
      ⇒ 折中：**标记扫残留**（确定是变异）＋**基线 rc 比对**（发现行为变化）。
    """
    hits = []
    for rel in _MUTATED_FILES:
        p = os.path.join(HERE, rel)
        if not os.path.isfile(p):
            continue
        try:
            txt = io.open(p, encoding="utf-8").read()
        except OSError:
            continue
        for i, ln in enumerate(txt.splitlines(), 1):
            if "MUTANT" in ln:
                hits.append("%s:%d" % (rel, i))
    return hits


#: 会被变异改动的**产品文件**（与 `main()` 里的备份清单保持一致）。
#:   单独列出来的原因：扫描残留必须知道"哪些文件**不该**出现变异标记"。
_MUTATED_FILES = (
    "inbox_window.py", "inbox_tray.py", "remediation.py",
    "inbox_server.py", "inbox_model.py", "tools/tray.ps1",
    "glossary.py", "host_shield.py",
)


#: 判据子进程超时（秒）。实测四套判据平时合计 < 15 秒，
#:   变异后某条会让 0363 **挂死**（去掉落位回读 ⇒ `wait_console_windows_gone`
#:   永远等不到窗口消失）。原来给 600 秒 ⇒ 一条变异能吃掉 10 分钟，
#:   而 45 条跑下来就是几小时（本轮实测 3h24m）。200 秒足够分辨
#:   "慢"（真慢）与"死"（挂住）—— 两者在本机差着两个数量级。
_GUARD_TIMEOUT = 200


def run_guards():
    """返回 `(rc, 输出, 超时的判据名列表)`。

    ★★ 0.36.5：**超时必须单列成一个类别**（第三态），不能混进"没报红"。
      实测踩到：P02 变异让 0363 挂死，旧代码把它记成「判据自身崩溃」
      ⇒ 计入 `bad`，看起来像"这条判据坏了"；
      而真相是**这条变异没被任何判据拦住，它让系统挂住了** ——
      后者严重得多（挂死不是"判据红"，是"什么都没发生直到超时"）。
      ⇒ 现在返回三个值，超时的那几套单独报告，不与 bad 混算。
    """
    outs, rc, hung = [], 0, []
    for g in (GUARD, GUARD2, GUARD3, GUARD4):
        try:
            r = subprocess.run([PY, g], capture_output=True, cwd=HERE,
                               timeout=_GUARD_TIMEOUT)
        except subprocess.TimeoutExpired:
            hung.append(os.path.basename(g))
            continue
        outs.append(r.stdout.decode("utf-8", "replace"))
        rc |= r.returncode
    return rc, "\n".join(outs), hung


def run_probe(name):
    p = os.path.join(HERE, name)
    if not os.path.isfile(p):
        return None
    r = subprocess.run([PY, p], capture_output=True, cwd=HERE, timeout=300)
    return r.returncode


def mutate(fn, old, new, label, expect_red_check, restore_first=True):
    """打一处变异，返回 `(是否如预期, 说明)`。"""
    if restore_first:
        fn()
    if old not in open(fn.__self__ if hasattr(fn, "__self__") else fn,
                       encoding="utf-8").read() if False else True:
        pass
    return None


def main():
    # ★★ 0.36.5b：**先看上一次有没有善终**，再看基线。
    #   顺序很重要：上一次被强杀时产品代码里可能带着变异，
    #   此时跑基线得到的是"脏工作区的基线"，后面 45 条结论全部不可信。
    _left = inflight_left_over()
    if _left:
        print("★ 上一次变异检验**没善终**（在途标志仍在：%s）" % (_left,))
        print("  ⇒ 可能上一次被强杀/断电，工作区带着变异。")
        print("  ⇒ 先跑下面的残留扫描与基线核对，确认干净再继续。")
    _inflight_begin()
    backups = {}
    for rel in ("inbox_window.py", "inbox_tray.py", "remediation.py",
                "inbox_server.py", "inbox_model.py", "tools/tray.ps1",
                # ★ 0.36.1 文字组要变异 `glossary.py`（术语正文）。
                #   漏了它 ⇒ 第一条文字变异就 KeyError，整轮检验崩在中途，
                #   而"崩了"不等于"抓住了" —— 必须真的跑完。
                "glossary.py",
                # ★ 0.36.3 要变异 `host_shield.py`（研发态方向 / 版本比较）。
                #   ★★ 漏了它的后果实测过：**Q16 直接 KeyError 崩在中途**，
                #     后面 Q17–Q20 **根本没跑** —— 而脚本崩了会在日志里
                #     看起来像"跑过了"。**崩了 ≠ 抓住了。**
                #     （本条注释就是那次崩溃留下的。）
                "host_shield.py"):
        src = os.path.join(HERE, rel)
        backups[src] = open(src, encoding="utf-8").read()

    def restore():
        for p, txt in backups.items():
            with open(p, "w", encoding="utf-8") as f:
                f.write(txt)

    def patch(rel, old, new):
        p = os.path.join(HERE, rel)
        txt = backups[p]
        if old not in txt:
            raise SystemExit("变异锚点没找到：%s 里的 %r" % (rel, old[:60]))
        with open(p, "w", encoding="utf-8") as f:
            f.write(txt.replace(old, new, 1))

    cases = [
        # (名称, 文件, 旧, 新, 期望报红的判据关键字)
        ("G01 几何变回常量（宽+高都归零）",
         "inbox_window.py",
         "WORK_H_RATIO = 0.33",
         "WORK_H_RATIO = 0.0\nWORK_W_RATIO = 0.0  # MUTANT",
         "G01"),
        ("G01 只把宽度归零（高度仍变）",
         "inbox_window.py",
         "WORK_W_RATIO = 0.34",
         "WORK_W_RATIO = 0.0  # MUTANT: 宽度成常量",
         "G01"),
        ("G06 去掉 --window-position",
         "inbox_server.py",
         'cmd.append("--window-position=" + WIN.window_position_str(rect))',
         'pass  # MUTANT: no position',
         "G06"),
        ("T01 托盘不写 shield",
         "inbox_tray.py",
         '"shield": shield if shield in SHIELD_SUFFIX else SHIELD_UNKNOWN,',
         '"shield_x": shield,  # MUTANT',
         "T01"),
        ("T02 坏了也画成在岗",
         "inbox_tray.py",
         '"down": SHIELD_UNPOSTURE,',
         '"down": SHIELD_ONPOSTURE,  # MUTANT',
         "T02"),
        ("R01 某类失守不给动作",
         "remediation.py",
         'ACT_DROP, "移出监管名单（承认打不赢）"',
         'ACT_INFO, "移出监管名单（承认打不赢）"  # MUTANT: not executable',
         "R01"),
        ("R02 B类 少一个选项",
         "remediation.py",
         'ACT_ACCEPT, "就这样放着，我自己盯着"',
         'ACT_INFO, "就这样放着，我自己盯着"  # MUTANT',
         "R02"),
        ("R03 上锁失败回落看一眼",
         "inbox_model.py",
         "        return _zone_lock_failed(item)",
         "        return False  # MUTANT",
         "R03"),
        ("R06 未登记类硬编原因",
         "remediation.py",
         '"**不编一个听起来合理的原因**——"',
         '"显然是某个可疑进程干的。"  # MUTANT: 编了一个原因',
         "R06"),
        ("R09 移出监管真去改配置",
         "inbox_server.py",
         '                    _iid = (form.get("id") or [""])[0]',
         '                    try:  # MUTANT: 真的去改防线\n'
         '                        import host_shield as _h2\n'
         '                        _st = _h2.load_state()\n'
         '                        _st["zones"] = []\n'
         '                        _h2.save_state(_st)\n'
         '                    except Exception:\n'
         '                        pass\n'
         '                    _iid = (form.get("id") or [""])[0]',
         "R09"),
        # ── 0.36.0 补正：落位链路的 4 条变异 ──────────────────────────
        # ★ 0.36.2：P02/P03/P05 的锚点随重构更新（旧锚点已不存在 ⇒ SKIP）。
        #   变异检验的价值全在"改坏产品后判据必须变红"；
        #   锚点过时 = 这条变异**没被检验**，是覆盖缺口而不是"跳过没关系"。
        ("P02 落位不回读实测就报成功",
         "inbox_window.py",
         "    got = reader(hwnd)",
         "    got = rect  # MUTANT: 假定下发即生效，不回读",
         "P02"),
        ("P03 落位动所有窗口",
         "inbox_window.py",
         "            if is_console_title(buf.value, run_id):\n"
         "                found.append(hwnd)",
         "            if buf.value.strip():  # MUTANT: 不比标题\n"
         "                found.append(hwnd)  # MUTANT: 所有有标题的窗口都收",
         "P03"),
        ("P05 落位排在开窗之前",
         "inbox_server.py",
         "            _place_if_needed(placer, run_id=run_id, verbose=verbose)\n"
         "            return \"app\"",
         "            return \"app\"  # MUTANT: 根本不落位",
         "P05"),
        ("P08 漏 import time",
         "inbox_server.py",
         "import time\nimport webbrowser",
         "import webbrowser  # MUTANT: 漏了 time",
         "P08"),
        # ── 0.36.1 文字组：6 条变异 ────────────────────────────────
        ("W01 术语正文写回 markdown 星号",
         "glossary.py",
         '"unit": "每天一行，单位为<b>条</b>。',
         '"unit": "每天一行，单位为**条**。',
         "W01"),
        ("W03 已生成的 HTML 又被转义",
         "inbox_server.py",
         "                   % (k, css, value if trusted_v else _esc(value))",
         "                   % (_esc(k), css, value if trusted_v else _esc(value))",
         "W03"),
        ("W04 浮层退回窄列里",
         "inbox_server.py",
         ".tdef{position:absolute;z-index:60;top:calc(100% + 6px);left:0;",
         ".tdef{display:block;margin:6px 0 8px;padding:8px 11px;",
         "W04"),
        ("W06 英文状态变量直出",
         "inbox_server.py",
         "% (R.chain_status_label(ch[\"status\"]), ch[\"files\"],",
         "% (ch[\"status\"], ch[\"files\"],",
         "W06"),
        ("W07 时间范围又写回卡片标题",
         "inbox_server.py",
         "        return (\"<div class=\\\"metric\\\"><div class=\\\"k\\\">%s</div>\"",
         "        return (\"<div class=\\\"metric\\\"><div class=\\\"k\\\">%s（最近 %d 小时）</div>\"",
         "W07"),
        ("W09 用户文案混入命令名",
         "glossary.py",
         '"exc": "<b>这一页没查你这台电脑的实际安装情况</b> —— 它只是说明产品在做什么。",',
         '"exc": "请用 `antinel host-audit` 自己查。",',
         "W09"),
    # ★ 0.36.2：锚点随 open_console 重构更新（旧锚点 `import inbox_window as _WIN`
    #   已不存在 ⇒ SKIP）。变异语义不变：**把收旧窗挪到开窗之后**。
    # ★ 0.36.2：锚点随 open_console 重构更新（旧锚点 `import inbox_window as _WIN`
    #   已不存在 ⇒ SKIP）。变异语义不变：**把收旧窗挪到开窗之后**。
    # ★ 0.36.2：锚点随 open_console 重构更新（旧锚点 `import inbox_window as _WIN`
    #   已不存在 ⇒ SKIP）。变异语义不变：**把收旧窗挪到开窗之后**。
    ("Q01 开窗后才收旧窗口（顺序反）",
         "inbox_server.py",
         "            if WIN is not None:\n"
         "                try:\n"
         "                    _n = WIN.close_console_windows()",
         "            if False:  # MUTANT: 收旧窗挪到开窗之后\n"
         "                pass\n"
         "            if opener is not None:\n"
         "                opener(cmd)\n"
         "                _n = WIN.close_console_windows()",
         "P09"),
    # ★ 0.36.5 锚点更新：`_matches_title` 已删除（子串匹配，且注释与实现相反），
    #   匹配真源改成 `is_console_title` 里的 `_mark_at_tail(t)`。
    #   **变异语义一字未改**：仍是"宽泛判据退回任意位置子串"⇒ 会误关用户窗口。
    ("Q02 标题改子串匹配（会误关用户窗口）",
         "inbox_window.py",
         "        return _mark_at_tail(t)",
         "        return CONSOLE_WINDOW_TITLE_MARK in t",
         "P04"),
    ("Q03 收旧窗口改用强杀进程",
         "inbox_window.py",
         "        def closer(h):                                       # noqa: E731\n"
         "            return bool(ctypes.windll.user32.PostMessageW(\n"
         "                w.HWND(h), 0x0010, 0, 0))                   # WM_CLOSE",
         "        def closer(h):                                       # noqa: E731\n"
         "            return bool(__import__('subprocess').run(\n"
         "                ['taskkill', '/F', '/PID', str(h)], capture_output=True))",
         "P10"),
    ("Q04 收旧窗口不返回数量（静默吞掉）",
         "inbox_window.py",
         "    return closed\n",
         "    return 0\n",
         "P11"),
    # ★ 0.36.2：这条变异是**本轮真实事故**的复现（签名里没有 closer ⇒
    #   函数体引用它必抛 UnboundLocalError ⇒ 收旧窗从未生效过）。
    ("Q05 去掉 closer 注入点（还原 0.36.1 的真实缺陷）",
         "inbox_window.py",
         "def close_console_windows(suffix=CONSOLE_WINDOW_TITLE_SUFFIX, visible_only=True,\n"
         "                          closer=None, run_id=None):",
         "def close_console_windows(suffix=CONSOLE_WINDOW_TITLE_SUFFIX, visible_only=True,\n"
         "                          run_id=None):",
         "P12"),
    ("Q06 标题匹配退回完整标题相等（页面切换后失效）",
         "inbox_window.py",
         "CONSOLE_WINDOW_TITLE_SUFFIX = \" · 值守台\"",
         "CONSOLE_WINDOW_TITLE_SUFFIX = \"收件箱 · 值守台\"",
         "P15"),
    ("Q07 窗口识别里硬编码页面名",
         "inbox_window.py",
         "        return _mark_at_tail(t)",
         "        return t.startswith(\"运行状态 · 值守台\")",
         "P15"),
    ("Q08 页面标题不再带可变前缀（前提消失）",
         "inbox_server.py",
         "<title>%s · 值守台%s</title>",
         "<title>收件箱 · 值守台</title>",
         "P13"),
    # ── 0.36.2 新增变异：三条根因各自的"复活"检验 ────────────────────
    # ★ 0.36.5 期望判据名修正：实测报红的是 **P10**（0360 的「收旧窗口只认精确标题」）
    #   而不是 Q08b。**不是变异失效，也不是判据坏了** ——
    #   0.36.5 给宽泛模式加了第二道防护（末尾＋前缀分隔符），
    #   所以「只删浏览器排除」这一处变异**打不穿** Q08b；
    #   但 Edge 窗口会**开始被收旧窗流程认领** ⇒ 0360 的 P10 先红。
    #   ⇒ 变异语义（浏览器窗口会被误认）**仍然成立**，只是第一个报红的是另一条。
    #   ★ 与本轮 P8 同族：断言写在哪个判据名下，必须按**实测**对齐，
    #     不能按"它应该报在哪"对齐 —— 后者是许愿。
    ("Q09 去掉浏览器窗口排除（会误关用户窗口）",
         "inbox_window.py",
         "    if any(m in t for m in BROWSER_TITLE_MARKS):\n"
         "        return False                    # ★ 浏览器普通窗口，不许当成值守台\n",
         "    # MUTANT: 不排除浏览器普通窗口\n",
         "P10"),
    ("Q10 枚举退回通用后缀（认不出带身份串的窗口）",
     "inbox_window.py",
     "            if is_console_title(buf.value, run_id):\n"
     "                found.append(hwnd)",
     "            if _matches_title(buf.value, suffix):  # MUTANT: 窄判据\n"
     "                found.append(hwnd)",
     "Q08c"),
    ("Q11 局部成功也算成功（谎报）",
     "inbox_window.py",
     "    if all(oks):",
     "    if any(oks):  # MUTANT: 一个成功就报整体成功",
     "Q06"),
    ("Q12 标题不再带身份串（退回认不出本次窗口）",
     "inbox_server.py",
     'mark = ("#" + rid) if rid else ""',
     'mark = ""  # MUTANT: 不注入身份串',
     "Q14"),
    # ── 0.36.3 新增变异：三条新机制各自的"复活"检验 ──────────────────
    ("Q13 删掉 light() 的兜底（未知姿态又打绿）",
         "inbox_model.py",
         "if not isinstance(posture_state, str) or posture_state not in _POSTURE_ALL:",
         "if False:  # MUTANT: 删掉兜底 ⇒ 未知姿态打绿",
         "R01"),
    ("Q14 删掉 guarding 的显式分支（正常态被判盲区）",
         "inbox_model.py",
         "if posture_state == \"guarding\":",
         "if False:  # MUTANT: 删掉显式分支",
         "R04"),
    ("Q15 姿态集合退回手抄副本（两处漂移）",
         "inbox_model.py",
         "    from host_shield import POSTURE_ALL as _POSTURE_ALL",
         "    _POSTURE_ALL = frozenset((\"down\", \"guarding\"))  # MUTANT: 手抄副本",
         "R02"),
    ("Q16 研发态比较方向反了（掩盖真篡改）",
         "host_shield.py",
         "        newer = _ver_lt(inst, code)",
         "        newer = _ver_lt(code, inst)  # MUTANT: 方向反",
         "R06"),
    ("Q17 研发态退回字符串比较（0.99 < 0.1 误判）",
         "host_shield.py",
         "        pa = [int(x) for x in str(a).strip().split(\".\")]",
         "        pa = str(a).strip().split(\".\")  # MUTANT: 字符串比较",
         "R06"),
    # ★★ 0.36.4 **方向反转**：Q18 原来测「失败后不关窗 ⇒ 大窗留屏上」，
    #   而 0.36.4 按创始人要求**删掉了失败兜底的关窗**（改为独立 profile 根治），
    #   锚点 `if _left:` 那段代码已不存在 ⇒ SKIP。
    #   ⇒ 现在改测**新方向**：往回加关窗 ⇒ 判据必须报红。
    #   （方向反转后变异也必须反转，否则测的是旧方向的缺失项。）
    ("Q18 把「落位失败关窗」加回来（新版）",
         "inbox_server.py",
         '            print("[place] 值守台面板**仍在屏幕上**，没有被关掉"\n'
         '                  "（它就是面板，由你决定关不关）。",\n'
         '                  file=sys.stderr)\n'
         '        return False',
         '            print("[place] 值守台面板**仍在屏幕上**，没有被关掉"\n'
         '                  "（它就是面板，由你决定关不关）。",\n'
         '                  file=sys.stderr)\n'
         '        try:  # MUTANT: 0.36.4 已删除的「失败后关窗」\n'
         '            import inbox_window as _W2\n'
         '            _W2.close_window(_W2.find_console_windows(\n'
         '                suffix=suffix, run_id=run_id))\n'
         '        except Exception:\n'
         '            pass\n'
         '        return False',
         "R10"),
    ("Q19 close_window 自己枚举（可能关用户窗口）",
         "inbox_window.py",
         "    hs = [h for h in (hwnds or []) if h]",
         "    hs = find_console_windows()  # MUTANT: 自己枚举",
         "R09"),
    # ★ 0.36.4：Q20 锚点也过期了 —— `place_all` 0.36.4 加了
    #   `skip_if_placed` 参数，签名已变 ⇒ SKIP。改用新签名。
    ("Q20 单数兼容层复活（原故障根因）",
         "inbox_window.py",
         "def place_all(hwnds, rect, setter=None, reader=None, skip_if_placed=True):",
         "def place_window(rect, title=None, finder=None, setter=None):\n"
         "    return None\n"
         "\n"
         "\n"
         "def place_all(hwnds, rect, setter=None, reader=None, skip_if_placed=True):",
         "R12"),

    # ══════════════ 0.36.4：研发态三原则 ＋ 自检盲区 ══════════════
    # ★ 这五条针对本轮**真正修掉的**缺陷。它们的共同点：
    #   每一条都对应一个"我实测确认过它会变红"的判据编号，
    #   而不是"我猜它会红"。没验过的变异用例等于装饰。
    ("Q21 dev 态重新吞掉真实告警",
         "inbox_model.py",
         '    if posture_state == "dev":\n'
         '        _action = [it for it in items',
         '    if posture_state == "dev":\n'
         '        return LIGHT_DEV, "MUTANT: 研发态吞掉告警"\n'
         '    if posture_state == "dev":\n'
         '        _action = [it for it in items',
         # ★ 期望 B1：B1 已按 Q21 的教训加固（补了"顺序判据"），
         #   现在它能识破"把后果账变成死代码"这条退路。
         #   ⇒ 上一轮这里写的是 B2（当时 B1 放过、B2 报红），
         #     我据此**回头加固了 B1** —— 变异暴露判据漏洞时，
         #     正确反应是**补判据**，不是把期望改到能过的那条。
         #   （B2 仍在，且 B2 是行为判据、优先级更高 —— 两者互为冗余。）
         "B1"),
    ("Q22 dev 分支把后果写死成空（藏状况）",
         "host_shield.py",
         '                    _cons = _outage_consequences(st, pkg_root)\n',
         '                    _cons = []  # MUTANT: 后果写死\n',
         "B3"),
    ("Q23 dev 收敛判据去掉（永久态）",
         "host_shield.py",
         "        if inst == code:\n"
         '            return False, "登记版本与代码版本一致（%s）⇒ 已出厂，不算研发态" % code',
         "        if inst == code:\n"
         '            return True, "MUTANT: 永久研发态"',
         "C2"),
    ("Q24 研发态豁免重新放宽（改门也豁免）",
         "host_shield.py",
         'DEV_NEVER_EXEMPT_MARKS = (\n'
         '    "与 manifest 不符（告警链路文件可能被改）",   # 改门：哈希不符\n'
         '    "与 manifest 不符（登记表可能被毒化）",       # 登记表被投毒\n'
         ')',
         'DEV_NEVER_EXEMPT_MARKS = ()  # MUTANT: 谁都豁免',
         "D2"),
    ("Q25 dev 给一个不存在的修复动作（假按钮）",
         "host_shield.py",
         '                            "can_fix": False, "fix": None,\n'
         '                            "fix_hint": ("正在开发中。这一版发出去之后会自动回到"',
         '                            "can_fix": True, "fix": "fix-posture",\n'
         '                            "fix_hint": ("正在开发中。这一版发出去之后会自动回到"',
         "B5"),
    # ★★ 0.36.5 新增（**本轮实测抓到的真缺口**，不是补的想象用例）：
    #   宽泛模式原本只查「标记在末尾 / 前缀无分隔符 / 无可执行扩展名」三层**形状**，
    #   注释里承诺的「页面前缀必须是已知页面名之一」**从没实现**
    #   ⇒ 用户窗口标题里恰好含 ` · 值守台#486acd` 时被误认（实测 True）
    #   ⇒ 宽泛模式是**关窗**用的 ⇒ 会关掉用户自己的窗口。
    #   这条变异把补上的白名单删掉 ⇒ 必须报红，否则守卫没守住它。
    ("Q46 删掉页面名白名单（还原 0.36.5 实测真缺口）",
     "inbox_window.py",
     "    if page not in names:\n        return False\n",
     "    # MUTANT: 不查页面名白名单\n",
     "P15"),
    ]

    base_code, base_out, _base_hung = run_guards()
    # ★ 0.36.5：基线挂死必须**当场单列** —— 它比"基线红"更严重：
    #   红说明有缺陷，挂死说明判据自己卡住了（此时红不红都无从判断）。
    if _base_hung:
        print("★ 基线就挂死：%s（> %ds）—— 这一轮变异结论不可信，先查判据本身"
              % (",".join(_base_hung), _GUARD_TIMEOUT))
        return 2
    # ★ 0.36.2：现在跑两个判据文件 ⇒ 基线是**两行**，
    #   只取最后一行会漏掉另一个文件的红。全部打印。
    for _ln in base_out.strip().splitlines():
        if "guards:" in _ln or "绿 /" in _ln:
            print("baseline: %s" % _ln.strip())
    print("baseline: rc=%d" % base_code)
    if base_code != 0:
        print("RED 基线就不绿，先修判据再谈变异。")
        # ★★ 0.36.5 修**残留产品代码**的真根因（实测踩到，不是假想）：
        #   这一段原来直接 `return 1` ⇒ 它在 `try/finally` **之前** ⇒
        #   上一轮循环里没被还原的变异**留在产品代码里**返回去了。
        #   实测后果：`inbox_server.py` 留下一处 `if False: # MUTANT`，
        #   文件语法错误（IndentationError），下一次跑任何判据都会崩 ——
        #   而日志最后一行写着"基线就不绿"，看着像正常结论。
        #   ⇒ 这正是本文件自己记的那条教训（「崩了会污染工作区」）的
        #     **完整形态**：不只是"崩了"，而是"崩了**并且把脏东西留下**，
        #     而返回值让人以为只是报告了一个结论"。
        #   ⇒ 修法：任何提前返回之前**必须先还原**，而不是指望 finally。
        restore()
        rc2, out2, _h2 = run_guards()
        if rc2 != base_code or out2.strip() != base_out.strip():
            print("★ 还原后判据结果变了（rc %d → %d）—— 工作区仍是脏的，"
                  "需人工核对" % (base_code, rc2))
            for _ln in out2.strip().splitlines():
                if "guards:" in _ln or "绿 /" in _ln:
                    print("  after-restore: %s" % _ln.strip())
            return 2
        print("（已还原工作区：基线前后一致）")
        return 1
    print()

    ok = bad = 0
    # ★ 0.36.5：挂死单列（第三类）—— 不计入 ok 也不计入 bad，
    #   但**必须让它进不了"全绿"的结论**（见结尾）。
    hung_total = 0
    hung_names = []
    # ★★★ 0.36.4：整轮包进 `try/finally`，**无条件还原**。
    #   实测踩到的后果（不是假想）：某条变异让 `remediation.py` 语法错误，
    #   `run_guards()` 抛异常 ⇒ 旧代码直接退出循环 ⇒ **变异留在产品代码里**，
    #   而日志最后一行是脚本崩了 —— 看起来像"跑过了"。
    #   我接着跑 0360 判据，看到的是 7 条"判据自身报错 SyntaxError"，
    #   差点以为产品坏了 —— 实际是**变异残留**。
    #   ⇒ 本仓铁律「崩了 ≠ 抓住了」的**代价版本**：崩了还会**污染工作区**。
    #   ⇒ `finally` 里 restore 是唯一的保证；且 restore 后必须**自己再验一次**
    #     （下面 `rc2` 那段已有），否则"还原失败"也无人知道。
    try:
        for name, rel, old, new, expect in cases:
            restore()
            try:
                patch(rel, old, new)
            except SystemExit as e:
                print("SKIP %-28s %s" % (name, e))
                bad += 1
                continue
            try:
                rc, out, _hung = run_guards()
            except BaseException as e:                      # noqa: BLE001
                # ★ 判据跑崩了不算"变异没生效" —— 那是**检验自身故障**，
                #   两者必须分开计数，否则会把判据的毛病记成产品的毛病。
                print("ERR  %-28s 判据自身崩溃：%r" % (name, e))
                bad += 1
                continue
            # ★★ 0.36.5：**挂死单列成第三类**（实测：P02 变异让 0363 挂死）。
            #   它不是"没报红"，也不是"判据坏了"，而是
            #   **这条变异没被任何判据拦住，而且它让整套系统卡在那儿不动** ——
            #   比"判据红"严重得多：挂死期间没有任何反馈。
            #   ⇒ 必须单独报，且**不算它被抓住**（否则账面上是 45/45 全绿）。
            if _hung:
                hung_total += 1
                hung_names.append("%s(挂死:%s)" % (name, ",".join(_hung)))
                print("HANG %-28s 判据挂死 >%ds：%s ⇒ 这条变异没被拦住，"
                      "且会让系统卡住（不是'没报红'，是'什么都没发生'）"
                      % (name, _GUARD_TIMEOUT, ",".join(_hung)))
                continue
            reds = [ln.strip() for ln in out.splitlines() if ln.startswith("RED")]
            # ★★ 0.36.4 修变异脚本的**盲区**（实测踩到）：
            #   `inbox_guards_0364.py` 的失败行前缀是 `❌`（带缩进），
            #   而这里只收 `RED` 开头的行 ⇒ Q21–Q25 **全部**报成 BAD，
            #   而它们其实**真的报红了**（`rc=1` 就是证据）。
            #   ⇒ 症状极具误导性：日志上五条 BAD 并排，看着像"新判据没生效"，
            #     实际是**检验工具看不见新判据的输出**。
            #   ★ 与本仓「查不出来 ≠ 查出来是好的」同族：
            #     这里把"没匹配到红"当成了"没红"，方向反了。
            #   ⇒ 修法：两种前缀都收（`❌` 前面还有两个空格，先 strip 再判）。
            bad_prefixed = [ln.strip() for ln in out.splitlines()
                            if ln.strip().startswith("❌")]
            reds += bad_prefixed
            hit = any(expect in r for r in reds)
            if rc != 0 and hit:
                print("OK   %-28s ->红[%s]（共 %d 条红）"
                      % (name, expect, len(reds)))
                ok += 1
            else:
                print("BAD  %-28s 期望 %s 报红，实际 rc=%d reds=%s"
                      % (name, expect, rc, reds[:3]))
                bad += 1
    finally:
        # ★ 无条件还原：不管循环是正常结束、还是抛异常退出。
        restore()
        # ★★ 0.36.5：还原之后必须**自己再验一次工作区是干净的**。
        #   原来只有 `rc2 != 0` ⇒ 判据绿就算还原成功。
        #   但实测踩到：某条变异让产品文件**语法错误**，
        #   判据会在"判据自身报错"处红 ⇒ rc2 仍然非零，
        #   **可是残留仍在**（判据红 ≠ 工作区干净，两件事）。
        #   ⇒ 现在查两件独立的事：
        #     ① 判据是否回到基线（rc 与输出都要一致）
        #     ② 工作区是否还含变异痕迹（逐字搜 MUTANT 标记）
        _left = scan_for_mutants()
        if _left:
            print("★ 工作区仍有变异痕迹 %d 处：%s" % (len(_left), _left[:5]))
    rc2, out2, _final_hung = run_guards()
    print()
    print("restore: rc=%d  %s" % (rc2, (out2.strip().splitlines() or ["(空)"])[-1]))
    if rc2 != base_code or out2.strip() != base_out.strip():
        print("RED 还原后判据结果与基线不一致（rc %d → %d）"
              "—— 说明有变异没被还原干净。" % (base_code, rc2))
        bad += 1
    if _final_hung:
        print("RED 还原后仍有判据挂死：%s" % ",".join(_final_hung))
        bad += 1
    print()
    print("变异检验: %d 条如预期报红 / %d 条异常 / %d 条挂死"
          % (ok, bad, hung_total))
    if hung_names:
        print("★ 挂死的变异（**没被拦住**，且会让系统卡住）：")
        for h in hung_names:
            print("    %s" % h)
    # ★ 挂死**必须**让整体失败：它既不是"抓住了"也不是"判据坏了"，
    #   而是一条能卡死系统的变异没有被任何判据看见。
    # ★★ 0.36.5b：只有走到这里（收尾核对完成）才清在途标志。
    #   标志的作用就是「上一次有没有善终」—— 提前清等于把证据擦掉。
    _inflight_end()
    return 0 if (bad == 0 and hung_total == 0 and ok > 0) else 1


if __name__ == "__main__":
    sys.exit(main())