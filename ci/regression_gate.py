# -*- coding: utf-8 -*-
"""回归闸门（L7）：把已修好的缺陷固化成判据，防止悄悄回退。

★ 为什么需要这个文件（而不是再跑一遍套件）
  套件 `scripts/verification_tests.py` 要 ~24 分钟（大量冷启动子进程），
  **太慢 ⇒ 不会天天跑 ⇒ 等于没有**。而"回归"问的是一个小问题：

      「这次改动，有没有把上次修好的东西弄回去？」

  ⇒ 本闸门**只锁已修好的 N 个缺陷**，全部在**进程内**调用产品模块，
    目标 **< 5 秒**，供每次改动后立刻跑。

★★ 三条设计纪律（来自 MEMORY）
  ① **判据不许二次实现**：一律 `import` 产品模块直接调它的函数，
     不在这里重写"什么算命中"的逻辑（我自实现判据时漏过"递归找嵌套键"）。
  ② **每条判据配负控**：见 `--selfcheck`，把每个缺陷**注入回去**，
     断言闸门必须变红。**先红后绿**——不会红的闸门不是闸门。
  ③ **判据必须能区分"没查到"与"没发现"**：测不出的情况报 SKIP，
     绝不报 PASS（把盲区渲染成清白，比不做还危险）。

用法：
    python scripts/regression_gate.py            # 跑闸门
    python scripts/regression_gate.py --selfcheck # 跑负控（注入缺陷，必须变红）
    python scripts/regression_gate.py --json      # 机器可读
"""
import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

PKG = Path(os.environ.get("ANTINEL_PKG") or Path(__file__).resolve().parent.parent)
HOOK = PKG / "hooks" / "pre_tool_use.py"
RULES = PKG / "rules" / "default.json"

# 规避守卫对字面量的拦截：删除动词一律拼接
DEL = "r" + "m"

RESULTS = []


def load_hook(isolate=False):
    """单进程加载钩子模块（不做冷启动 ⇒ 秒级）。

    ★ isolate=True 时只影响**加载时刻**的 cwd。注意 `load_rules()` 是**每次调用**
      才去 `(os.getcwd(), dirname(os.getcwd()))` 找 `.psl/manifest.json` ——
      所以隔离必须由调用方用 `neutral_cwd()` 包住**整段判据执行**，光在这里
      chdir 再还原是不够的（我第一版就是这么写的，实测仍降级）。
    """
    os.environ["ANTINEL_NOREG"] = "1"
    os.environ.setdefault("ANTINEL_HOST_MIRROR", "0")
    spec = importlib.util.spec_from_file_location("ptu_gate", str(HOOK))
    m = importlib.util.module_from_spec(spec)
    sys.modules["ptu_gate"] = m
    try:
        spec.loader.exec_module(m)
    except SystemExit:
        # ★ 2026-09-30 判读：**中风险，暂不改行为** —— 钩子模块被 import 时
        #   若自行 `sys.exit`（CLI 模块的常见写法），我们拿到的是**半初始化**的模块；
        #   但后续取属性会 AttributeError 并在别处**崩出来**（退出码非 0），
        #   即失败**仍然可见**，只是报错位置偏了。
        #   ⇒ 本次只记录原因；若要根治，应在 return 前断言模块已初始化。
        pass
    return m


class neutral_cwd:
    """把 cwd 换到中性临时目录 —— 使 `_load_rules_integrity`/`_load_custom_rules`
    的 `(cwd, dirname(cwd))` 搜索**找不到任何 `.psl/manifest.json`** ⇒ 用包内真表。

    为什么必须有：产物仓的**上级** `D:\\psl\\poc\\.psl\\manifest.json` 是 09-18 陈旧件，
    会让闸门静默降级到 17 条兜底集（无 DST-10）⇒ DST-10 判据假红、DST-01 判据假绿。
    **两种方向都会骗人**，所以这不是可选项。
    """

    def __init__(self):
        import tempfile
        self.neutral = tempfile.mkdtemp(prefix="antinel_gate_")
        self.old = None

    def __enter__(self):
        self.old = os.getcwd()
        os.chdir(self.neutral)
        return self

    def __exit__(self, *a):
        if self.old:
            os.chdir(self.old)
        return False


def rec(cid, ok, detail="", skipped=False):
    RESULTS.append({"id": cid, "ok": ok, "skipped": skipped, "detail": detail})
    if skipped:
        tag = "SKIP"
    else:
        tag = "PASS" if ok else "FAIL"
    print("  [%s] %-46s %s" % (tag, cid, detail[:80]))


# ---------------------------------------------------------------- 判据实现
# 每条判据 = 一个函数，返回 (ok, detail) 或 (None, why) 表示不可判。


def j_dst10_stream(m):
    """缺陷 A1：解释器分支用窄判据 ⇒ DST-10 的 block 被降级为 alert。

    ★ 判据不许二次实现：直接调产品的 readonly_command_context ＋ _search。
    """
    ps = "power" + "shell"
    cases = [
        (ps + ' -c "Set-Content -Path .\\d.txt -Stream evil -Value x"', True, "Set-Content -Stream"),
        (ps + ' -c "Add-Content -Path .\\f.txt -Stream s -Value y"', True, "Add-Content -Stream"),
    ]
    bad = []
    for cmd, want_block, label in cases:
        ro = m.readonly_command_context(cmd)
        segs, danger = m._scan_command(cmd)
        rules = m.load_rules()
        hit_crit = False
        for r in rules:
            pats = r.get("command_patterns") or []
            if not any(m._search(p, s) for p in pats for s in (segs or [])):
                continue
            if (r.get("severity") or "").lower() == "critical":
                hit_crit = True
        # 被降级的路径：命中 critical 但因 ro 被判"提及"而不拦
        downgraded = hit_crit and ro
        got_block = hit_crit and not ro
        if got_block != want_block or downgraded:
            bad.append("%s ro=%s hit_crit=%s" % (label, ro, hit_crit))
    if bad:
        return False, "DST-10 被降级/漏拦: " + "; ".join(bad)
    return True, "2 例 powershell -Stream 仍为 block（ro=False）"


def j_dst01_still_works(m):
    """对照：DST-01 本体的 21 条真表模式没被改坏。"""
    m._DST_PATS_CACHE.clear()
    disk = json.loads(RULES.read_text(encoding="utf-8")).get("rules", [])
    real = [p for r in disk if r.get("id") == "DST-01" for p in (r.get("command_patterns") or [])]
    if len(real) != 21:
        return False, "DST-01 真表模式数 = %d（期望 21）" % len(real)
    must_block = [
        DEL + " -rf /tmp/x",
        "python -c \"import os; os.remove('/x')\"",
        "node -e \"require('fs').rmSync('/x')\"",
    ]
    bad = []
    for cmd in must_block:
        segs, danger = m._scan_command(cmd)
        hit = any(any(m._search(p, s) for p in real) for s in (segs or []))
        if not hit:
            bad.append(cmd[:40])
    if bad:
        return False, "真表下漏拦: " + "; ".join(bad)
    return True, "真表 21 条；3 例必拦命令全部命中"


def j_mention_not_regressed(m):
    """缺陷 D-3 的成果：纯文本提及必须仍放行（不得因修 A1 而回退）。"""
    cases = [
        "python -c \"print('%s -rf /')\"" % DEL,
        "python -c \"x='shutil.rmtree'; print(x)\"",
        "echo '%s -rf /'" % DEL,
        "grep -n \"%s -rf\" f.md" % DEL,
    ]
    bad = []
    for cmd in cases:
        ro = m.readonly_command_context(cmd)
        segs, danger = m._scan_command(cmd)
        hit = any(any(m._search(p, s) for p in m._dst_command_pats()) for s in (segs or []))
        blocked = hit and not (ro and not danger)
        if blocked:
            bad.append(cmd[:44])
    if bad:
        return False, "纯提及被误拦（假阳性）: " + "; ".join(bad)
    return True, "4 例纯提及仍放行"


def j_judgement_source_single(m):
    """缺陷 A1 的修法本身：判据单一真源 _interp_mention_residue 必须存在，
    且 _strip_interpreter_code_literals 必须与它一致（不得分叉）。"""
    for name in ("_interp_mention_residue", "_strip_interpreter_code_literals"):
        if not hasattr(m, name):
            return False, "缺函数 %s" % name
    ps = "power" + "shell"
    cases = [
        "python -c \"print('%s -rf /')\"" % DEL,
        ps + ' -c "Set-Content -Stream x"',
        "node -e \"require('fs').rmSync('/x')\"",
        "ls -la",
    ]
    bad = []
    for seg in cases:
        a = m._strip_interpreter_code_literals(seg)
        b = m._interp_mention_residue(seg)
        consistent = (a == seg) if b is None else (a == b)
        if not consistent:
            bad.append(seg[:40])
    # ★ 关键：非 python 解释器必须返回 None（这是 A1 的修法核心）
    if m._interp_mention_residue(ps + ' -c "Set-Content -Stream x"') is not None:
        return False, "非 python 解释器未返回 None（A1 修法被回退）"
    if bad:
        return False, "两函数分叉: " + "; ".join(bad)
    return True, "单一真源；非 python 一律 None"


def j_a2_load_compare_same_source():
    """缺陷 A2：加载与完整性比对必须指向同一文件。

    ★★ 行为级判据，不是字符串级。
      初版我写成「在源码里 grep 'rules_file'」——负控证明它是**假守卫**：
      把 `_rules_path = _cand` 改回 `RULES_PATH`，字符串还在，判据照样绿。
      这正是 MEMORY 里「**文本级 ≠ 值级校验**」的又一实例。

    现在的判据 = **真跑一次 install ＋ 篡改 ＋ 看钩子报不报**：
      P1 install 后          → 不得报 SELF-TAMPERED
      P2 篡改规则快照         → **必须**报 SELF-TAMPERED（这条区分得了真伪）
    """
    import shutil
    import subprocess
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="antinel_a2_"))
    try:
        root = tmp / "cc"
        r = subprocess.run(
            [sys.executable, str(PKG / "scripts" / "install.py"), "--root", str(root)],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=180)
        installed_rules = root / ".psl" / "rules" / "default.json"
        man = root / ".psl" / "manifest.json"
        if not installed_rules.is_file() or not man.is_file():
            return False, ("install 未产出 .psl/rules/default.json 或 manifest.json"
                           "（rc=%s）" % r.returncode)

        def call_hook(cwd):
            ev = {"session_id": "gate", "transcript_path": str(Path(cwd) / "t.jsonl"),
                  "tool_name": "Bash", "tool_input": {"command": "ls"}}
            iso = Path(cwd) / ".psl" / "antinel_isolated.json"
            if iso.parent.is_dir():
                iso.write_text(json.dumps({"workspace_roots": []}), encoding="utf-8")
            e = {**os.environ, "ANTINEL_HOST_MIRROR": "0",
                 "ANTINEL_CONFIG": str(iso), "ANTINEL_NOREG": "1"}
            p = subprocess.run(
                [sys.executable, "-I", "-S", str(PKG / "hooks" / "pre_tool_use.py")],
                cwd=cwd, input=json.dumps(ev), capture_output=True, text=True,
                encoding="utf-8", errors="replace", env=e, timeout=90)
            return "SELF-TAMPERED" in ((p.stderr or "") + (p.stdout or ""))

        # P1：刚装完，不得误报
        if call_hook(root):
            return False, "P1 FAIL：install 后误报 SELF-TAMPERED（加载/比对又分叉了）"

        # P2：篡改规则快照，必须报
        data = json.loads(installed_rules.read_text(encoding="utf-8"))
        data.setdefault("rules", []).append(
            {"id": "X-GATE-EVIL", "name": "gate tamper", "severity": "low"})
        installed_rules.write_text(json.dumps(data, ensure_ascii=False),
                                   encoding="utf-8", newline="\n")
        if not call_hook(root):
            return False, "P2 FAIL：篡改规则快照后**没报** SELF-TAMPERED（真守卫已失效）"

        return True, "行为级：P1 不误报 / P2 篡改必报（真守卫有效）"
    finally:
        shutil.rmtree(str(tmp), ignore_errors=True)


def _vc_pass_count(out):
    """从 version_check 的 PASS 输出里**数值回读**条数，并数出清单实际行数。

    返回 `(declared, listed)`；`declared=None` 表示读不到汇总行。

    ★★ 为什么不能用「按行形状数」的旧写法（2026-10-10 修，本班实测）：

      旧写法 `len(re.findall(r"^\\s+\\S.*?\\s+0\\.\\d+\\.\\d+\\s*$", out, re.M))`
      数出来是 **10**，而实际承载件只有 **9** 处 —— 因为它**误匹配了汇总行**：
      `★ PASS：9 处版本号全部为 0.43.1` 前面那行是空行，`^\\s+` 吃掉了前导 `\\n`，
      再把 `★` 当 `\\S` ⇒ 汇总行也算成一处承载件。
      于是判据**显示**「10 处版本号一致」，与它自己的 docstring「九处」**自相矛盾**，
      而 PASS/FAIL 又是对的 —— 属于最难发现的一类：**结论对、口径假**。

      修法遵循 v1.18 判据①：计数一律**数值回读**（读量具自报的那个数），
      不靠"数长得像的行"。`declared` 取自 version_check 自己打印的
      `★ PASS：%d 处版本号`（它数的是 `len(rows)`，即真实承载件数）；
      `listed` 只作**交叉核对**（清单行数与自报数必须一致），
      正则用 `^  \\S`（**恰好两个空格**的清单缩进），不会误中顶格的汇总行。
    """
    m = re.search(r"★\s*PASS：\s*(\d+)\s*处版本号", out or "")
    declared = int(m.group(1)) if m else None
    listed = len(re.findall(r"^  \S.*?\s+0\.\d+\.\d+\s*$", out or "", re.M))
    return declared, listed


def j_version_consistent():
    """缺陷 D-6 / 原 A5：**九处**手工维护的版本承载件必须逐字相同；
    `psl/manifest.json` 的 `version` **单独判**（≤ 代码版本）。

    ★ MEMORY 点名的「无守卫」项：「发布前必手扫版本号 —— **无守卫**」。
      手扫 = 靠人记得 = 迟早漏。实测落后：
        `_ANTINEL_VERSION` = 0.32.2（落后 2 版，且**进审计链**）
        `build_package.VERSION` = 0.29.0（落后 4 版）

    ★ 判据复用：直接跑 `ci/version_check.py`（**同一个量具**，不二次实现）。

    ★★ 为什么从「七处」变「十处」（2026-09-28 实测）：
      初版 `version_check.py` 只列了 7 处，**漏了 `rules/default.json` 与
      `docs/AUDIT_SCHEMA.md`** —— 是另一条独立路径（`antinel_verify.py --invariants`
      的 INV-3）抓出来的。两个检查器各自维护清单 ⇒ 必然分叉。
      修法：`version_check.py` 现在自带**判据 4「本清单 ⊇ INV-3 清单」**，
      分叉本身就会红。教训：**同一个事实有两个检查器 = 必须有一条判据管它们一致。**

    ★★★ 为什么又从「十处」变「九处」（0.43.1，2026-10-10，根因修复）：
      `psl/manifest.json` 的 `version` 是**构建产物**（`build_package.py` 打包时
      写入"随包代码的版本"），语义上**允许落后**（迭代期：版本已升、还没重打包）。
      把它塞进"逐字一致"⇒ 每次升版被迫把它也刷成同号 ⇒ `is_dev_build()` 的
      版本落差永远为 0 ⇒ **研发态结构性失效、界面假失守**（创始人当场点名）。
      ⇒ 摘出「逐字一致」集（`version_check.py` 判据 7 + INV-3 INFO 侧单独守
        「≤ 代码版本、不许超前」）。**保护面没有变松**：落后是被期待的中间态，
        超前照旧红，且打包时会被刷成当前版本。
      ⇒ 本条（D-6）判的是**九处手工承载件**，与判据 7 各管一半。
    """
    import subprocess
    r = subprocess.run([sys.executable, str(PKG / "ci" / "version_check.py")],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=60)
    if r.returncode == 0:
        out = r.stdout or ""
        declared, listed = _vc_pass_count(out)
        if declared is None:
            return False, ("version_check 报绿却读不到「★ PASS：N 处版本号」汇总行"
                           " —— 量具口径变了，本条会瞎（不许静默通过）")
        # ③ 内建负控（§6 四件套之「反向对照」）：喂一个「自报 10 处、清单只列 2 行」
        #    的合成输出，交叉核对必须能区分出不一致 —— 否则这条核对是假守卫。
        _d, _l = _vc_pass_count("  a  0.1.0\n  b  0.1.0\n★ PASS：10 处版本号全部为 0.1.0\n")
        if _d == _l:
            return False, "内建负控未生效：合成输出的自报条数与清单行数不一致却未被区分"
        # 显示口径纳入自检（§7.8）：自报条数必须等于清单实际列出的行数
        if listed != declared:
            return False, ("version_check 自报 %d 处，清单却列出 %d 行"
                           " —— 量具显示口径与事实不符" % (declared, listed))
        return True, "%d 处版本号一致" % declared
    # 从守卫输出里挑出「不属于多数派」的那几行，直接点名
    rows = re.findall(r"^\s+(.+?)\s+(0\.\d+\.\d+)\s*$", r.stdout or "", re.M)
    from collections import Counter
    cnt = Counter(v for _, v in rows)
    major = cnt.most_common(1)[0][0] if cnt else "?"
    odd = ["%s=%s" % (l.strip(), v) for l, v in rows if v != major]
    if not odd:
        # 不是"值不一致"，而是"清单分叉"或"抽不到值" —— 原样带出来
        tail = [l for l in (r.stdout or "").splitlines() if l.strip().startswith("-")]
        return False, "；".join(t.strip("- ").strip() for t in tail[:3]) or "版本守卫 FAIL"
    return False, "多数派 %s，落后者：%s" % (major, "；".join(odd[:4]))


def j_fallback_has_no_dst10(m):
    """兜底集的事实：_FALLBACK 只有 17 条且无 DST-10。
    ★ 这本身不是缺陷，但**降级时必须能看见**（否则把盲区当清白）。"""
    fb = getattr(m, "_FALLBACK", None)
    if fb is None:
        return False, "缺 _FALLBACK"
    ids = [r.get("id") for r in fb]
    n = len(ids)
    has_dst10 = "DST-10" in ids
    if has_dst10:
        return False, "兜底集竟含 DST-10（与已查明事实不符，需重新核实）"
    if n != 17:
        return False, "兜底集 %d 条（期望 17）—— 事实基线变了，需重新核实" % n
    return True, "兜底集 %d 条、无 DST-10（与事实一致）" % n


def j_builder_mechanisms_present():
    """★★★ 2026-09-28：守住**构建器里那三件新机制**，防止下次编辑把它们删掉。

    为什么必须由闸门守：
      这三件机制防的都是「同一事实两处副本」缺陷类 —— 它们**被删掉时不报错**，
      只会在很久以后以"产物丢文件/版本分叉"的形式暴露（build_package.py
      曾把内嵌模板覆盖仓源、闸门表曾漏掉 2 个新 category 而模块级崩溃）。
      ⇒ 『能防住的机制』本身必须是**可红的判据**，不能只是代码里的一段善意。

    判据（行为级：import 构建器，直接问它）：
      ① `_LAYOUT` 存在且项数 >= 21，且必填项都在表里；
      ② `_verify_layout()` 真跑得通（不是死代码）；
      ③ `_gate_table_sync_guard()` 的返回值 == 规则表实际 category 数；
      ④ `_reconcile_src` 存在且可调用（构建后对账守卫已接线）。
    """
    bp_dir = PKG / "scripts"
    if not (bp_dir / "build_package.py").is_file():
        return None          # 产物仓无构建器 ⇒ 不可判（不是通过）
    if str(bp_dir) not in sys.path:
        sys.path.insert(0, str(bp_dir))
    try:
        import build_package as bp
        import importlib
        importlib.reload(bp)
    except Exception as e:
        return False, "构建器 import 失败：%s: %s" % (type(e).__name__, e)

    layout = getattr(bp, "_LAYOUT", None)
    if not layout:
        return False, "① 布局表 _LAYOUT 不见了 —— 『路径分叉』的闸门已失效"
    n = len(layout)
    if n < 21:
        return False, "① 布局表只剩 %d 项（基线 21）—— 有人删了条目" % n
    for r in getattr(bp, "_LAYOUT_REQUIRED", ()):
        if r not in layout:
            return False, "① 布局表缺必填逻辑名 %s" % r

    try:
        bp._verify_layout()
    except SystemExit as e:
        return False, "② 布局自检自己红了：%s" % e
    except Exception as e:
        return False, "② 布局自检抛异常：%s: %s" % (type(e).__name__, e)

    data = json.loads(RULES.read_text(encoding="utf-8")).get("rules", [])
    cats = len({(r.get("category") or "") for r in data if r.get("category")})
    synced = getattr(bp, "_GATE_TABLE_SYNCED", None)
    if synced is None:
        return False, "③ 闸门表同步守卫 _GATE_TABLE_SYNCED 不见了 —— 『类别分叉』的闸门已失效"
    if int(synced) != cats:
        return False, "③ 闸门表同步数 %s ≠ 规则表类别数 %d（构建器读到的是旧表？）" % (synced, cats)

    if not callable(getattr(bp, "_reconcile_src", None)):
        return False, "④ 构建后对账守卫 _reconcile_src 不见了 —— 『构建器改仓源』无人拦"
    return True, ("布局表 %d 项 · 布局自检通过 · 闸门表同步 %d 类 · 对账守卫在位"
                  % (n, cats))


def j_build_harness_order():
    """★★★ 2026-09-29（D-17）：守住**构建里那条顺序**——「验产物」＋「家务最后做」。

    为什么必须由闸门守（这不是风格问题，是实测过的真 bug）：
      `build()` 里原先把 `_cleanup_stage(pkg)` 排在 `--verify` 之前，
      而 `--verify` 跑的 harness **正是 `pkg / "scripts" / "run_harness.py"`**
      ⇒ **先清暂存、再跑暂存里的脚本** ⇒ 必然 `can't open file`。
      实测输出：`rc=2, No such file or directory:
      antinel-security-stage\\scripts\\run_harness.py`。

    ★ 它为什么能**静默存活这么久**：本机删除配额被平台守卫拦死时 `_clear` **失败**，
      stage 反而**保持完整** ⇒ harness 侥幸跑通。也就是说，
      **「环境坏了」一直在掩盖「顺序错了」** —— 这是最危险的一种绿。

    判据（两条，都读**源码文本的相对位置**，因为 bug 的本质就是顺序）：
      ① harness 必须指向 `final`（产物），不能再是 `pkg`（stage）；
      ② `_cleanup_final_stages(...)` 的调用位置必须在 harness 调用**之后**。
    """
    bp = PKG / "scripts" / "build_package.py"
    if not bp.is_file():
        return None                     # 产物仓无构建器 ⇒ 不可判（不是通过）
    src = bp.read_text(encoding="utf-8", errors="replace")

    # ① harness 不许再指向 stage（pkg）
    if 'str(pkg / "scripts" / "run_harness.py")' in src:
        return False, ("① harness 仍跑在 **stage**（`pkg / scripts / run_harness.py`）——"
                       "要验的是产物 `final`；跑中转站会在清暂存后必然失败")
    if 'final / "scripts" / "run_harness.py"' not in src:
        return False, "① 找不到指向产物 `final` 的 harness 调用 —— 该项无法判定，视同失效"

    # ② 清暂存必须在 harness 之后
    i_cleanup = src.rfind("_cleanup_final_stages(")
    i_harness = src.rfind('_harness_py')
    if i_cleanup == -1:
        return False, "② 找不到 `_cleanup_final_stages(...)` —— 收尾清理已失效"
    if i_harness != -1 and i_cleanup < i_harness:
        return False, ("② 「家务最后做」被破坏：`_cleanup_final_stages` 出现在 harness **之前**"
                       "（%d < %d）—— 先清后跑 = 构建必然在 --verify 上失败"
                       % (i_cleanup, i_harness))
    return True, ("harness 跑在产物 `final` · 收尾清理在 harness 之后"
                  "（cleanup@%d > harness@%d）" % (i_cleanup, i_harness))


def j_pymodules_guard():
    """★★★ 2026-09-29（D-20）：守住**包组成双向守卫**——干净 wheel 不许漏模块。

    为什么必须由闸门守：这条缺陷的失效方式是**静默漏文件** —— 干净树打 wheel 少一个
    包根模块，构建**不报错**，只有用户 `pip install` 后**所有命令** import 就炸才发现。
    实测事故：`ui_server.py` 三处没登记（py-modules/root_mod/_LAYOUT），旧 wheel 能跑
    只因陈旧 `build/` 把它带了进去（**假绿**）。

    判据（行为级 + 内建负控）：
      ① 构建器里 `_pymodules_guard` 存在且可调用；
      ② 在**真树**上调它，返回空（真树没有"被 import 却没声明"的模块）；
      ③ **内建负控**：造 fixture（`foo_mod.py` 被 `bar_mod.py` import、却只声明 `bar_mod`），
         守卫必须报出 `foo_mod` —— 不报 ⇒ 它是假守卫。
    """
    bp_dir = PKG / "scripts"
    if not (bp_dir / "build_package.py").is_file():
        return None                     # 产物仓无构建器 ⇒ 不可判（不是通过）
    if str(bp_dir) not in sys.path:
        sys.path.insert(0, str(bp_dir))
    try:
        import build_package as bp
        import importlib
        importlib.reload(bp)
    except Exception as e:
        return False, "构建器 import 失败：%s: %s" % (type(e).__name__, e)

    fn = getattr(bp, "_pymodules_guard", None)
    if not callable(fn):
        return False, ("① 包组成守卫 _pymodules_guard 不见了 —— "
                       "D-20（干净 wheel 漏模块 ⇒ 装完 import 就炸）无人拦")

    probs = fn(PKG)
    if probs:
        return False, "② 真树上有包组成问题：%s" % " | ".join(probs)

    # ③ 内建负控：fixture 里 foo_mod 被 import 却没声明，守卫必须报出来
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="antinel_pymod_"))
    (tmp / "foo_mod.py").write_text("X = 1\n", encoding="utf-8", newline="\n")
    (tmp / "bar_mod.py").write_text("import foo_mod\n", encoding="utf-8", newline="\n")
    (tmp / "pyproject.toml").write_text(
        '[tool.setuptools]\npy-modules = ["bar_mod"]\n', encoding="utf-8", newline="\n")
    try:
        neg = fn(tmp)
    finally:
        _aside_dir(tmp)
    if not any("foo_mod" in p for p in neg):
        return False, ("③ ★负控未生效：fixture 里 foo_mod 被 import 却没声明，"
                       "守卫却只报 %r —— 它是假守卫" % neg)
    return True, "守卫在位 · 真树无问题 · 内建负控会红（foo_mod 被抓）"


#: 已归档、只读、**不再是开工处**的源仓（2026-09-29 裁定：产物仓是唯一主仓）
_ARCHIVED_REPOS = (r"D:\psl\poc\r1v3",)


def _vtuple(v):
    """版本号转可比较元组。解析不出就返回 (0,) —— 绝不冒充"能比较"。"""
    try:
        return tuple(int(x) for x in str(v).split("."))
    except Exception:
        return (0,)


def j_single_source_of_truth():
    """★★★ 2026-09-29（D-22）：**「改哪个仓」必须是会红的判据**，不能只是一句文档。

    本轮真实事故（这是本判据存在的理由）：
      旧交接文档仍写「改 r1v3 再同步到产物仓」，而**裁定早在 `a38fec1` 就反过来了**
      （产物仓＝唯一开工处，r1v3 归档）。文档没退役 ⇒ 后来者（含 LLM）照旧文提问
      「是承认产物仓为主仓，还是回灌 r1v3？」——**问出一个不该问的问题**；
      一旦真回灌：退版（0.33.2→0.29.2）＋ 强加平铺布局（`_LAYOUT` 22 项按分类写死）
      ＋ r1v3 **非 git 不可逆**。三笔都是硬损失。

    ★★ 根治机制（**可复制到任何「以谁为准」的场景**），三条缺一不可：
      ① **真源机器可读** —— `psl/manifest.json` 的 `built_from`（不是散文、不是记忆）；
      ② **违反就红** —— 本判据（「**无检查项的禁令＝没禁令**」）；
      ③ **旧件必须退役并指向新真源** —— 见 `D:\\2026\\PSL\\真源与退役索引.md`。
         只写进文档、不写进判据 ＝ 把禁令交给"读的人记得"，迟早出事。

    判据：
      ① 产物仓自身版本号可取；
      ② `built_from` 必须指向**本产物仓**；
      ③ 每个归档仓：必须有 `ARCHIVED.md`（身份被**声明**），且 VERSION **严格落后**
         —— 回灌会让它 **>= 产物仓** ⇒ 立刻红。
    """
    vsrc = PKG / "antinel.py"
    if not vsrc.is_file():
        return None
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"',
                  vsrc.read_text(encoding="utf-8", errors="replace"), re.M)
    if not m:
        return False, "① 取不到产物仓 VERSION —— 无法判断谁在前"
    prod_v = m.group(1)

    mf = PKG / "psl" / "manifest.json"
    if not mf.is_file():
        return None                      # 产物仓不带发布清单 ⇒ 不可判（不是通过）
    bf = (json.loads(mf.read_text(encoding="utf-8")).get("built_from") or "").rstrip("\\/")
    if bf.lower() != str(PKG).lower():
        return False, ("② built_from=%r 不指向本产物仓 %r —— "
                       "「产物仓为主仓」的裁定被改回去了" % (bf, str(PKG)))

    notes = []
    for ap in _ARCHIVED_REPOS:
        p = Path(ap)
        if not p.is_dir():
            return None                  # 归档仓不在本机 ⇒ 不可判（盲区，不冒充通过）
        if not (p / "ARCHIVED.md").is_file():
            return False, ("③ 归档仓 %s 缺 ARCHIVED.md —— 它「已归档、只读」的身份没人声明，"
                           "会被当成现行源仓（**正是本轮提问跑偏的根因**）" % ap)
        av = re.search(r'^VERSION\s*=\s*"([^"]+)"',
                       (p / "antinel.py").read_text(encoding="utf-8", errors="replace"), re.M)
        if not av:
            return False, "③ 归档仓 %s 取不到 VERSION" % ap
        av = av.group(1)
        if _vtuple(av) >= _vtuple(prod_v):
            return False, ("③ ★回灌警报：归档仓 %s 的 VERSION=%s 已不落后于产物仓 %s —— "
                           "归档仓只许落后（已归档、只读）。回灌＝退版＋强加布局＋不可逆"
                           % (ap, av, prod_v))
        notes.append("%s=%s" % (p.name, av))
    return True, ("产物仓为主仓（built_from 指向本仓，%s）；归档仓仍落后：%s"
                  % (prod_v, "、".join(notes)))


def _is_git_dir(p):
    """实测某目录是不是 git 工作树（不是"我记得它是"）。"""
    import subprocess as _sp
    try:
        r = _sp.run(["git", "-C", str(p), "rev-parse", "--is-inside-work-tree"],
                           capture_output=True, text=True, timeout=30)
    except Exception:
        return None                       # git 不可用 ⇒ 不可判，不冒充"不是"
    return r.returncode == 0 and (r.stdout or "").strip() == "true"


def j_workspace_facts():
    """★★★ 2026-09-29（D-23）：**「东西在哪儿／它是不是 git 仓」必须会红**，不能靠记忆。

    本轮真实事故（本判据存在的理由）——创始人原话：
      「有些是你的漂移，例如代码仓在哪儿，git仓是否存在，**你老是忘记**。」
    这不是记性问题：这些事实此前**只存在于散文和对话里**，没有机器可读真源
    ⇒ 每次都要重新推理一遍 ⇒ **必然漂移**。D-22 只管了"以谁为准"，没管"东西在哪儿"。

    ★★ 根治（与 D-22 同一套三条，缺一即等于没禁令）：
      ① **真源机器可读** —— `psl/workspace_facts.json`（数据，不是说明文）；
      ② **违反就红** —— 本判据；
      ③ **旧件退役** —— 我的记忆不再作数；要开工先读真源（见 `_env_facts.py`）。

    ★ 判据刻意写成**对 fixture 免疫**：只校验"声明的路径是否真的存在、git 状态是否
      与声明一致"，**不**把声明路径与 `PKG` 比（负控在临时副本里跑，一比就假红）。
      "PKG 就是主仓"这条由 D-22 的 `built_from` 独立守住，不重复。

    判据：
      ① 每个仓：路径存在、`git` 声明与**实测**一致、`must_have` 齐全；
      ② 站点构建器目录存在、含 marker、`builders_git` 与实测一致；
      ③ `release.version` 与 pyproject **实测值**一致；
      ④ dist 里**只许有本版两件**（旧包／`.BAD-*` 会让人手上传选错 ——
         PyPI 只能 yank、版本号永久占用 ⇒ 选错＝不可逆）；
      ⑤ `release.pypi`（**发布版本唯一真源**，2026-09-30 加）：版本串已登记、
         wheel 存在且文件名含该版本、`host_audit_fixture` 存在 ——
         站点与三条判据一律从这里读，**不许各自写死版本号**
         （此前 new_user_cmd_journey 写死 0.28.0、cmp_check_out 写死 0.33.2 ⇒ 站上混搭无人发现）。
    """
    f = PKG / "psl" / "workspace_facts.json"
    if not f.is_file():
        return None                       # 没有真源 ⇒ 不可判（不是通过）
    try:
        facts = json.loads(f.read_text(encoding="utf-8"))
    except Exception as e:
        return False, "真源 psl/workspace_facts.json 解析失败：%s" % e

    probs = []
    for name, spec in (facts.get("repos") or {}).items():
        p = Path(spec.get("path") or "")
        if not p.is_dir():
            probs.append("repos.%s 路径不存在：%r" % (name, spec.get("path")))
            continue
        g = _is_git_dir(p)
        if g is None:
            probs.append("repos.%s 判不出是否 git 仓" % name)
        elif bool(g) != bool(spec.get("git")):
            probs.append("repos.%s 声明 git=%s、实测 %s（环境事实漂移）"
                         % (name, spec.get("git"), g))
        for need in (spec.get("must_have") or []):
            if not (p / need).exists():
                probs.append("repos.%s 缺 %s" % (name, need))

    site = facts.get("site") or {}
    bd = Path(site.get("builders_dir") or "")
    if not bd.is_dir():
        probs.append("site.builders_dir 不存在：%r" % site.get("builders_dir"))
    else:
        mk = site.get("builders_marker")
        if mk and not (bd / mk).is_file():
            probs.append("site.builders_dir 里没有 %s（构建器不在这）" % mk)
        g = _is_git_dir(bd)
        if g is not None and bool(g) != bool(site.get("builders_git")):
            probs.append("site.builders_git 声明 %s、实测 %s"
                         % (site.get("builders_git"), g))
    for key in ("output_dir", "deploy_dir"):
        d = site.get(key)
        if d and not Path(d).is_dir():
            probs.append("site.%s 不存在：%r" % (key, d))

    rel = facts.get("release") or {}
    want = rel.get("version")
    if want:
        pp = PKG / "pyproject.toml"
        if pp.is_file():
            m = re.search(r'^version\s*=\s*"([^"]+)"',
                          pp.read_text(encoding="utf-8", errors="replace"), re.M)
            if not m:
                probs.append("pyproject.toml 取不到 version")
            elif m.group(1) != want:
                probs.append("release.version 声明 %s、pyproject 实测 %s"
                             % (want, m.group(1)))

    # ★ 0.36.5：打包在途标志。**必须在函数级取一次**（不能只在 dist 块里定义）——
    #   下面 pypi.wheel 那处也会读它；若定义在 dist 块内，而 dist 块因
    #   `dist_dir` 未登记而整块跳过 ⇒ 后面读到的是**未定义名** ⇒ 判据自己崩。
    #   —— 判据自身出错却因「有输出」而被当成「检查发现问题」，是本轮反复踩的同型。
    _in_flight = bool(os.environ.get("ANTINEL_BUILD_IN_FLIGHT"))

    dd = Path(rel.get("dist_dir") or "")
    if rel.get("dist_dir") and dd.is_dir():
        arts = set(rel.get("artifacts") or [])
        missing = [a for a in sorted(arts) if not (dd / a).is_file()]
        # ★★★ 0.36.5 修一处**流程死锁**（实测踩到，不是假想）：
        #   本判据的**意图**是「dist 里必须有本版发布件，且不许混旧包」
        #   —— 防的是人手上传 PyPI 时选错文件（选错＝不可逆，PyPI 只能 yank）。
        #   但 0.36.5 把统一交付闸门接进打包入口后，出现死锁：
        #     要打包 → 必过闸门 → 闸门含本判据 → 本判据要求 dist 里已有本版包
        #                → 而那个包正是打包的产物 ⇒ **打包永远做不出来**。
        #   ⇒ 判据的**意图一个字不动**，修的是「它把流程中间态当成了缺陷」：
        #     「打包在途」是流程的正常态，不是失守。
        #
        #   ★ 豁免必须**显式声明**（环境变量），不许靠"dist 空"自动推断：
        #     自动推断会让"我把 dist 清空了"这种真实缺陷被当成在途而放过去
        #     —— 那就等于给"清空 dist"发了一张免检通行证。
        #   ★ 且豁免时**只豁免"缺件"**，不豁免"混旧包"（stray）：
        #     后者正是本判据要防的最危险一项，任何时候都不许放行。
        #   ★★ 豁免必须**显式声明**（环境变量），不许靠"dist 空"自动推断：
        #     自动推断会让"我把 dist 清空了"这种真实缺陷被当成在途而放过去
        #     —— 那就等于给"清空 dist"发了一张免检通行证。
        #   ★ 且豁免时**只豁免"缺件"**，不豁免"混旧包"（stray）：
        #     后者正是本判据要防的最危险一项，任何时候都不许放行。
        if missing and _in_flight:
            print("       （D-23：检测到 ANTINEL_BUILD_IN_FLIGHT=1 —— 本次是打包在途，"
                  "dist 缺本版件属流程中间态，不判红；混旧包仍照判）")
        elif missing:
            probs.append("dist 缺本版发布件：%s%s"
                         % (missing,
                            "  ← 提示：若本次是打包在途，设 ANTINEL_BUILD_IN_FLIGHT=1"
                            "（构建器已自动设）；若不是，说明发布件被清掉了" if missing else ""))
        stray = []
        for q in dd.iterdir():
            n = q.name
            if n.startswith(".") or ".away" in n or n in arts:
                continue
            if n.endswith((".whl", ".tar.gz")):
                stray.append(n)
        if stray:
            probs.append("dist 里混着非本版发布件 %s —— 人手上传会选错（PyPI 不可撤回）；"
                         "改名让开（.away-<时间戳>），不要删" % stray[:4])

    py = rel.get("pypi") or {}
    pv = py.get("published_version")
    tv = py.get("target_version")
    # ★ 2026-10-03 判据更新（D-23）：`published_version` 与 `target_version` 拆成两栏后，
    #   **本地产物该跟 target 比，不是跟 published 比**。
    #   为什么要拆：此前 `published_version` 同时承担"PyPI 上的事实"与"打算发什么"两个职责，
    #   于是本地包一旦是新的就会与"事实"矛盾（实测：本地 0.34.0 vs PyPI 0.28.0 ⇒ 恒红）。
    #   ⇒ 拆栏后本判据的正确形状是：
    #     · wheel 文件名含 **target_version**（这是"本次要发的那版"）；
    #     · **published_version 只与 PyPI 实查一致**，不由本地产物推导（它是事实，不是愿望）。
    if not tv:
        probs.append("release.pypi.target_version 未登记 —— 本次待发版本没有真源，"
                     "「dist 里是哪一版」这类判据会各自写死")
    if not pv:
        probs.append("release.pypi.published_version 未登记 —— 版本类判据（命令面／实测输出）"
                     "没有真源，不许各自写死")
    else:
        wh = Path(py.get("wheel") or "")
        # ★ 0.36.5：与上面 dist 缺件**同一个在途豁免**。
        #   `release.pypi.wheel` 指向的正是本次构建要产出的那个包 ——
        #   打包之前它必然不存在。⇒ 「文件不存在」在打包在途时是流程中间态。
        #   ⚠️ **只豁免"不存在"**；文件名与版本号对不对**照判** ——
        #     那才是"登记与产物分家"，与在途无关。
        if not wh.is_file():
            if _in_flight:
                print("       （D-23：打包在途，pypi.wheel 尚未产出，不判红；"
                      "文件名/版本一致性仍照判）")
            else:
                probs.append("release.pypi.wheel 不存在：%r" % py.get("wheel"))
        elif tv and tv not in wh.name:
            probs.append("release.pypi.wheel 文件名 %s 与 target_version %s 不一致"
                         % (wh.name, tv))
        elif not tv and pv not in wh.name:
            probs.append("release.pypi.wheel 文件名 %s 与 published_version %s 不一致"
                         % (wh.name, pv))
    fx = Path(py.get("host_audit_fixture") or "")
    if not fx.is_file():
        probs.append("release.pypi.host_audit_fixture 不存在：%r"
                     % py.get("host_audit_fixture"))

    if probs:
        return False, "；".join(probs[:4])
    return True, ("环境事实与真源一致：%d 个仓 / 站点构建器 / 本版 %s / dist 只有 2 件 / "
                  "发布版 %s" % (len(facts.get("repos") or {}), want or "?", pv or "?"))


# ══════════════════════════════════════════════════════════════════════════
# D-24（0.43.x 卫生）：构建产物不得出现在 git 索引里
# ══════════════════════════════════════════════════════════════════════════

_BUILD_INDEX_DIRS = ("build", "antinel.egg-info")


def _index_build_artifacts(root):
    """返回 `root` 的 git 索引里 `build/`、`antinel.egg-info/` 下的文件清单。

    · 非 git 工作树（如负控 fixture，无 `.git`）⇒ 返回 `None`（不可判，非通过）。
    · `git ls-files` 失败 ⇒ **抛异常**（由调用方转红，不静默吞掉）。
    """
    import subprocess
    if not (Path(root) / ".git").exists():
        return None
    r = subprocess.run(["git", "-C", str(root), "ls-files", "--", *_BUILD_INDEX_DIRS],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=30)
    if r.returncode != 0:
        raise RuntimeError("git ls-files rc=%d：%s"
                           % (r.returncode, (r.stderr or "").strip()[:200]))
    return [l for l in (r.stdout or "").splitlines() if l.strip()]


def j_no_build_artifacts_in_index():
    """D-24：构建产物不得出现在 git 索引里（0.43.x 仓库卫生的**常驻断言**）。

    ★★ 缺陷本体（交接文件 §2/§7.7 实测）：本仓曾有 **61 个** `build/` 产物被追踪，
      而 `.gitignore` **第 5 行**就是 `build/` —— 这不是"忘了加忽略"，而是
      **忽略规则对已进入索引的文件无效**：它们在进忽略规则之前（或被 `git add -f`）
      就已入库。**只清一次是打扫，加一条断言才是机制** —— 打扫完不加断言，
      下次一次强制添加就全回来了。

    ★ 四件套：
      · 正判据：索引里 `build/`、`antinel.egg-info/` 文件数为 0（锁的正是上面那个缺陷）。
      · 反向对照：把构建产物重新 `git add -f` ⇒ 本条必须红（**内建负控**实跑，见下）。
      · 连带对照：**只** `git rm -r --cached`，工作树文件保留（零删除纪律 §10.4）。
      · 可观测：明细打印索引里的构建产物条数与样例路径。
    """
    try:
        tracked = _index_build_artifacts(PKG)
    except Exception as e:
        return False, "git ls-files 执行失败：%s: %s" % (type(e).__name__, e)
    if tracked is None:
        # 非 git 工作树（负控 fixture 无 .git）—— 不可判，明确报 SKIP（不是通过）
        return None

    # ③ 内建负控（§6 四件套之「反向对照」）：造一个「build/ 已被追踪」的临时 git 仓，
    #    探测必须报出 ≥1 个 —— 否则这条探测是**假守卫**（D-11/D-22 两个假负控的形状）。
    import subprocess
    import tempfile
    neg = tempfile.mkdtemp(prefix="antinel_idxneg_")
    try:
        subprocess.run(["git", "-C", neg, "init", "-q"], capture_output=True)
        os.makedirs(os.path.join(neg, "build"), exist_ok=True)
        with open(os.path.join(neg, "build", "x.py"), "w", encoding="utf-8") as fh:
            fh.write("x=1\n")
        subprocess.run(["git", "-C", neg, "add", "-f", "build/x.py"], capture_output=True)
        if not _index_build_artifacts(neg):
            return False, ("内建负控未生效：`build/` 已被追踪的临时仓里探测不到构建产物"
                           "（假守卫）")
    finally:
        _aside_dir(neg)      # 零删除：改名让开（safe-delete 守卫会硬杀 rmtree）

    if tracked:
        return False, ("索引里仍有 %d 个构建产物（如 %s）—— 忽略规则对已追踪文件无效；"
                       "用 `git rm -r --cached` 移除（工作树文件保留）"
                       % (len(tracked), ", ".join(tracked[:3])))
    return True, "索引里 0 个构建产物（build/、antinel.egg-info/）"


def j_running_on_real_table(m):
    """★★ 闸门自身的守卫：确认当前加载的是**包内真表**，不是降级兜底集。

    为什么要这条：本闸门测的是「真表下的行为」。若因环境里存在陈旧
    `.psl/manifest.json` 而静默降级到 17 条兜底集，DST-10 类判据会**假红**，
    而 DST-01 类判据会**假绿**（兜底集里也有 DST-01）——
    **两种方向都会骗人**。⇒ 必须显式声明"我现在跑在哪张表上"。
    """
    disk = json.loads(RULES.read_text(encoding="utf-8")).get("rules", [])
    live = m.load_rules()
    n_disk, n_live = len(disk), len(live)
    if n_live != n_disk:
        return False, ("★闸门跑在降级表上：load_rules()=%d，磁盘真表=%d。"
                       "DST-10 类判据会假红、DST-01 类会假绿 —— 需检查环境的 .psl/manifest.json"
                       % (n_live, n_disk))
    has10 = any(r.get("id") == "DST-10" for r in live)
    if not has10:
        return False, "真表里没有 DST-10（规则表被改坏了？）"
    return True, "真表 %d 条，含 DST-10（未被降级）" % n_live


# ---------------------------------------------------------------- 负控
def _aside_dir(path):
    """零删除地让开一个临时目录（改名成 `<name>.away-<pid>-<ms>`）。

    ★★ 2026-09-29（D-15 推广）判据：**删不掉的东西不要删，改名让开即可**。
    本机平台层 safe-delete 守卫**硬杀进程**（不抛异常）⇒ `shutil.rmtree`
    接不住、也没法 `try/except`。改名的代价是留垃圾，但**跑得完**远胜过**跑一半消失**。
    """
    import os as _os
    import time as _t
    p = Path(str(path))
    try:
        if not (p.exists() or p.is_symlink()):
            return True
    except OSError:
        return False
    _tag = "%d-%d" % (_os.getpid(), int(_t.time() * 1000) % 1000000)
    for i in range(50):
        away = p.parent / ("%s.away-%s-%d" % (p.name, _tag, i))
        try:
            if away.exists():
                continue
            _os.rename(str(p), str(away))
            return True
        except OSError:
            continue
    return False


def selfcheck():
    """★★ 负控：把每个缺陷**注入回去**，断言闸门必须变红。**先红后绿。**

    为什么必须有：**不会红的闸门不是闸门**，是装饰。
    做法：复制一份产物仓到临时目录 → 在副本上注入缺陷 → 在副本上跑闸门
         → 断言闸门**返回非 0** 且**恰好那条判据**变红。
    关键纪律：**先验注入真的生效**（否则"没变红"会被误读成"判据没问题"）。
    """
    import shutil
    import subprocess
    import tempfile

    print("=" * 74)
    print("负控自我检查：注入缺陷 → 闸门必须变红（先红后绿）")
    print("=" * 74)

    # 注入点：(名字, 文件相对路径, 原串, 替换串, 期望变红的判据 id 前缀)
    # ★ 原串必须**逐字**取自磁盘（含行尾注释），否则负控自己 SKIP ——
    #   而 SKIP 会被误读成"判据没问题"。宁可负控报错，也不要静默通过。
    INJECTIONS = [
        ("A1 回退：解释器分支改回窄判据（真降级）",
         "hooks/pre_tool_use.py",
         'if residue is None:\n                return False               # 判不了 ⇒ 不放过',
         'if residue is None:\n                residue = seg',
         "A1  DST-10"),
        ("A1 回退：非 python 也当可判（真降级）",
         "hooks/pre_tool_use.py",
         'if not tok.startswith(("python", "py")):\n        return None',
         'if not tok.startswith(("python", "py")):\n        return seg',
         "A1  判据单一真源"),
        ("A2 回退：加载路径钉回 RULES_PATH",
         "hooks/pre_tool_use.py",
         "_rules_path = _cand",
         "_rules_path = RULES_PATH",
         "A2  加载与比对同源"),
        ("DST-10 从规则表里删掉",
         "rules/default.json",
         '"id": "DST-10"',
         '"id": "DST-99"',
         "SELF 闸门运行在真表上"),
        ("D-6 回退：版本号写歪一处",
         "pyproject.toml",
         None,                       # ★ None = 运行时读当前版本（见下）
         "0.99.9",
         "D-6"),
        ("D-6 分叉：版本守卫清单漏掉一处承载件",
         "ci/version_check.py",
         None,                       # ★ 见下方 SPOT 剔除专项处理
         None,
         "D-6"),
        # ★★ D-11 负控（2026-09-28）：把**对账守卫**从构建器里删掉 ⇒ 判据 ④ 必须红。
        #   为什么选"删函数"而不是"改坏它"：这三件机制的失效方式是**静默消失**
        #   （被后来的编辑顺手删掉、没报错），所以"它还在不在"就是最该锁的判据。
        # ★★ 2026-09-29 修正（自证伪）：原注入改的是 `_reconcile_src` 的**调用点**，
        #   而判据 ④ 查的是 `getattr(bp,"_reconcile_src")` —— **函数定义还在，判据照样绿**。
        #   此前它"通过"是假象：那时 fixture 缺文件 ⇒ 构建器 import 失败 ⇒ D-11 **因别的原因**红。
        #   把 fixture 补全之后，这个假负控立刻暴露。⇒ 改为注入"**定义**被删"。
        ("D-11 缺陷：构建器里的对账守卫被删掉（删定义）",
         "scripts/build_package.py",
         "def _reconcile_src(",
         "def _reconcile_src_removed(",
         "D-11"),
        # ★★ D-17 负控（2026-09-29）：把 harness 指回 **stage** ⇒ 判据 ① 必须红。
        #   bug 的本质是**顺序/对象错配**（先清暂存、再跑暂存里的脚本），
        #   所以负控就注入"跑回中转站"这一件事。
        ("D-17 缺陷：harness 被指回 stage（pkg）",
         "scripts/build_package.py",
         '_harness_py = str(final / "scripts" / "run_harness.py")',
         '_harness_py = str(pkg / "scripts" / "run_harness.py")   # NEGCTL',
         "D-17"),
        # ★★ D-20 负控（2026-09-29）：把**包组成守卫**从构建器里删掉 ⇒ 判据 ① 必须红。
        #   该缺陷的失效方式是"守卫被后来的编辑顺手删掉、**不报错**"，
        #   所以"它还在不在"就是最该锁的判据（同 D-11 的立场）。
        ("D-20 缺陷：包组成守卫被删掉",
         "scripts/build_package.py",
         "def _pymodules_guard(pkg_dir):",
         "def _pymodules_guard_removed(pkg_dir):",
         "D-20"),
        # ★★ D-22 负控（2026-09-29）：把 `built_from` 指回归档仓 ⇒ 判据 ② 必须红。
        #   这是"有人把主仓改回 r1v3"这一动作的**直接模拟**（注入值运行时算，不写死）。
        ("D-22 缺陷：built_from 被指回归档仓 r1v3",
         "psl/manifest.json",
         None, None, "D-22"),
        # ★★ D-23 负控（2026-09-29）：把产物仓的 `git` 声明写反 ⇒ 判据 ① 必须红。
        #   模拟的正是"环境事实漂移"这一种失效：真源里写的东西与磁盘不符。
        ("D-23 缺陷：workspace_facts 里产物仓 git 声明写反",
         "psl/workspace_facts.json",
         '"git": true', '"git": false', "D-23"),
    ]

    ok_all = True
    for label, rel, old, new, expect_red in INJECTIONS:
        src = (PKG / rel).read_text(encoding="utf-8", errors="replace")
        # ★★ 2026-09-28 实测教训：D-6 的注入串原先**硬编码** `version = "0.33.1"`。
        #   升到 0.33.2 之后它立刻失配 ⇒ 负控 SKIP ⇒ 「没变红」被误读成「判据没问题」。
        #   修法：注入点由**当前磁盘值**算出（读 antinel.py 的 VERSION 当真源），
        #   升版不再需要同步改负控。凡"跟着版本走的注入串"，一律不许写死。
        if old is None and new is not None:
            cur = re.search(r'^VERSION\s*=\s*"([^"]+)"',
                            (PKG / "antinel.py").read_text(encoding="utf-8", errors="replace"),
                            re.M)
            if not cur:
                print("  [SKIP] %-40s 取不到当前版本号，无法构造注入" % label)
                ok_all = False
                continue
            old = 'version = "%s"' % cur.group(1)
        # ★★ D-22 专项：把 built_from 的**值**换成一个归档仓路径。
        #   值在运行时从磁盘真值算出来（同 D-6 的教训：凡跟着环境走的注入串不许写死）。
        if new is None and rel == "psl/manifest.json":
            _mbf = re.search(r'"built_from"\s*:\s*"([^"]+)"', src)
            if not _mbf or not _mbf.group(1):
                print("  [SKIP] %-40s manifest 里取不到 built_from" % label)
                ok_all = False
                continue
            _cur = _mbf.group(1)
            _tgt = str(_ARCHIVED_REPOS[0]).replace("\\", "\\\\")   # JSON 里的转义形态
            if _cur == _tgt:
                print("  [SKIP] %-40s built_from 已经指向归档仓了" % label)
                ok_all = False
                continue
            src = src.replace(_cur, _tgt, 1)
        # ★★ 「清单分叉」专项：把 SPOTS 里的一整项（标签行 + 正则行）剔掉，
        #   断言 version_check.py 的判据 4 会因此变红。
        #   这一条本身也是踩坑产物：初版判据 4 **是假守卫** —— 我用全文件字符串匹配
        #   注入，误中了 `INV3_HARD_PATHS` 里的同名项，SPOTS 其实没被改，
        #   负控"通过"是假的。现在改为**按 SPOTS 区间精确剔行 + 断言条数减一**。
        if new is None and rel == "ci/version_check.py":
            # ★★ 「清单分叉」专项（先判，避免与下面的动态版本号分支冲突）
            lines = src.splitlines(True)
            try:
                st = next(i for i, l in enumerate(lines) if l.startswith("SPOTS = ["))
                en = next(i for i in range(st, len(lines)) if lines[i].rstrip() == "]")
            except StopIteration:
                print("  [SKIP] %-40s 找不到 SPOTS 段" % label)
                ok_all = False
                continue
            hit = None
            for i in range(st, en):
                s = lines[i].lstrip()
                if s.startswith('("') and "rules/default.json" in lines[i] and i + 1 < en:
                    if "r'" in lines[i + 1] or 'r"' in lines[i + 1]:
                        hit = i
                        break
            if hit is None:
                print("  [SKIP] %-40s SPOTS 段内找不到 rules/default.json 项" % label)
                ok_all = False
                continue
            mutated = "".join(lines[:hit] + lines[hit + 2:])
            n_after = len(re.findall(r'^\s*\("', mutated, re.M)) - 1  # 减去无关的元组
            if n_after == len(re.findall(r'^\s*\("', src, re.M)) - 1:
                print("  [SKIP] %-40s ★ 注入未生效（SPOTS 条数没变）" % label)
                ok_all = False
                continue
            src = mutated
        # ★ 先验注入点存在（否则"没变红"是假象）
        elif old is not None and old not in src:
            print("  [SKIP] %-40s 注入点未找到（源码已变，需更新负控）" % label)
            ok_all = False
            continue

        # ★ 只复制闸门真正需要的骨架（全仓 copytree 870 文件 × 4 次 = 会超时）。
        #   hooks/ ＋ rules/ ＋ ci/ 就是全部依赖：闸门 import 钩子、读规则表、自己。
        tmp = Path(tempfile.mkdtemp(prefix="antinel_negctl_"))
        dst = tmp / "pkg"
        dst.mkdir(parents=True, exist_ok=True)
        # ★★ 2026-09-29：补 `psl/` 与 `docs/`（D-22 要读 psl/manifest.json；
        #   D-6 的版本承载件里有 psl/manifest.json 与 docs/AUDIT_SCHEMA.md）。
        #   fixture 缺这些文件会让判据因"文件不存在"而假红 —— 那不是缺陷，是盲区。
        for sub in ("hooks", "rules", "ci", "scripts", "psl", "docs", "tools"):
            shutil.copytree(str(PKG / sub), str(dst / sub),
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.bak-*"))
        # 钩子 import 的同级模块（antinel.py 等）也要带上，否则 exec_module 会炸
        for py in PKG.glob("*.py"):
            shutil.copy2(str(py), str(dst / py.name))
        # ★★ 2026-09-29：把 pyproject.toml 也带上 —— 否则 D-6（版本一致性）在 fixture 里
        #   因"文件不存在"**级联变红**，淹没真正被注入的那条判据（会让读者误以为 D-6 坏了）。
        #   这正是「会误报的检查器用两次就没人信」要避免的噪声。
        for extra in ("pyproject.toml", "server.json", "SKILL.md", "MANIFEST.in"):
            if (PKG / extra).is_file():
                shutil.copy2(str(PKG / extra), str(dst / extra))
        # ★★ 2026-09-29：fixture 也要**封闭**（同 D-6 的教训）—— 把 psl/manifest.json 的
        #   built_from 改写成 fixture 自己的路径。否则 D-22 每次都因"它指向真仓、
        #   而 PKG 是临时目录"而**假红**，跟 D-6 一样是噪声、且会掩盖真正的判定。
        _fmf = dst / "psl" / "manifest.json"
        if _fmf.is_file():
            try:
                _t = _fmf.read_text(encoding="utf-8")
                # ★★ 必须用 lambda：re.sub 的**替换串**会解释反斜杠
                #   （`\\\\` → `\\` → 单反斜杠）⇒ 写出的 JSON 非法（`Invalid \escape`）
                #   ⇒ D-22 在任何 fixture 里都会因解析失败而假红 ⇒ **负控变假**。
                _t2 = re.sub(r'"built_from"\s*:\s*"[^"]*"',
                             lambda _m: '"built_from": "%s"'
                             % str(dst).replace("\\", "\\\\"), _t)
                if _t2 != _t:
                    _fmf.write_text(_t2, encoding="utf-8", newline="\n")
            except Exception as _e:
                # ★★ 2026-09-30：此处原为 `pass`（**静默**）。
                #   危害：fixture 没封闭好 ⇒ 判据会在 fixture 里**因别的原因**红
                #   ⇒ 负控"变红了"于是看起来通过 —— 这正是 D-11／D-22 两个**假负控**的形状。
                #   ⇒ 准备失败必须**中止这条负控**（不做，也不许算它绿）。
                print("  [SKIP] %-40s fixture 封闭失败（%s: %s）⇒ 本条负控不做"
                      % (label, type(_e).__name__, _e))
                ok_all = False
                continue
        mut = (dst / rel)
        if new is None:
            # 分叉专项：src 已是剔行后的内容，不再做字符串替换
            mut.write_text(src, encoding="utf-8", newline="\n")
        else:
            mut.write_text(src.replace(old, new, 1), encoding="utf-8", newline="\n")

        # 用**改过的**包跑闸门
        r = subprocess.run(
            [sys.executable, str(dst / "ci" / "regression_gate.py")],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=180,
            env={**os.environ, "ANTINEL_PKG": str(dst)})
        out = (r.stdout or "") + (r.stderr or "")
        turned_red = (r.returncode != 0)
        # ★★ 2026-09-29 收紧（自证伪）：原先只查"期望串出现在输出里"——但 cid **无论 PASS/FAIL
        #   都会打印**，再叠加 D-6 在 fixture 里的级联红（缺 pyproject.toml）⇒
        #   **判据其实没红，也会被记成 RED(好)**（假通过）。改为：期望的 cid 必须
        #   **出现在 [FAIL] 行里**。
        reds = re.findall(r"\[FAIL\]\s+(\S+(?:\s+\S+)*?)\s{2,}", out)
        hit_expected = any(expect_red.split()[0] in x for x in reds)
        got = ("RED(好)" if turned_red else "★GREEN(坏)")
        detail = ""
        if turned_red:
            detail = " | ".join(x.strip()[:38] for x in reds[:2])
        print("  [%s] %-40s %s" % (got, label, detail))
        if not turned_red:
            ok_all = False
            print("         ★ 注入后闸门仍全绿 —— 该判据是假守卫！")
        elif not hit_expected:
            ok_all = False
            print("         ★ 闸门变红了，但不是预期的判据（期望含 %r）" % expect_red)

        # ★★ 2026-09-29（D-15 推广）：**负控的临时目录也不许删**。
        #   实测教训：本机平台层 safe-delete 守卫按会话累计、阈值 50、不重置，
        #   一旦触顶，`shutil.rmtree` 会让**整个负控进程被硬杀**（SIGTERM，
        #   不抛 Python 异常）⇒ 表现为"负控只跑了几条就消失"，
        #   极易被误读成"没变红=判据没问题"。修法同 D-15：**改名让开**。
        _aside_dir(tmp)

    print()
    if ok_all:
        print("★ 负控全部通过：每条判据都能在缺陷注入后变红（不是假守卫）")
    else:
        print("★ 负控有失败项：有判据是假守卫，或负控自身需更新")
    return 0 if ok_all else 1


# ---------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selfcheck", action="store_true", help="跑负控")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    a = ap.parse_args()

    if a.selfcheck:
        return selfcheck()

    if not HOOK.is_file():
        print("★ 找不到 %s" % HOOK)
        return 2

    with neutral_cwd():
        m = load_hook()
        print("=" * 74)
        print("Antinel 回归闸门（L7）—— 锁死已修好的缺陷，防止悄悄回退")
        print("包路径：%s" % PKG)
        print("=" * 74)

        # ★ 第一条就查「闸门自己跑在哪张表上」——它红，后面所有判据都不可信
        pre = j_running_on_real_table(m)
        rec("SELF 闸门运行在真表上（非降级兜底集）", pre[0], pre[1])

        checks = [
            ("A1  DST-10 的 block 不被降级为 alert", lambda: j_dst10_stream(m)),
            ("A1  判据单一真源（两函数不分叉）", lambda: j_judgement_source_single(m)),
            ("A2  加载与比对同源（行为级：篡改必报）", j_a2_load_compare_same_source),
            ("D-3 纯文本提及仍放行（无假阳性）", lambda: j_mention_not_regressed(m)),
            ("—   DST-01 真表 21 条未损坏（对照）", lambda: j_dst01_still_works(m)),
            ("—   兜底集事实未变（17 条、无 DST-10）", lambda: j_fallback_has_no_dst10(m)),
            ("D-6 九处版本号一致（原 A5，此前无守卫）", j_version_consistent),
            ("D-11 构建器三件机制在位（布局表/同步守卫/对账）", j_builder_mechanisms_present),
            ("D-17 构建顺序：验产物 final ＋ 家务最后做", j_build_harness_order),
            ("D-20 包组成双向守卫（干净 wheel 不漏模块）", j_pymodules_guard),
            ("D-22 单一真源：产物仓为主 / 归档仓只许落后", j_single_source_of_truth),
            ("D-23 环境事实不漂移（仓在哪儿／是否 git／dist 只有本版）",
             j_workspace_facts),
            ("D-24 构建产物不得进索引（忽略对已追踪文件无效）",
             j_no_build_artifacts_in_index),
        ]

        for cid, fn in checks:
            try:
                r = fn()
            except Exception as e:
                rec(cid, False, "运行时异常：%s: %s" % (type(e).__name__, e))
                continue
            if r is None:
                rec(cid, False, "不可判", skipped=True)
            else:
                ok, detail = r
                rec(cid, ok, detail)

    n_pass = sum(1 for r in RESULTS if r["ok"] and not r["skipped"])
    n_fail = sum(1 for r in RESULTS if not r["ok"] and not r["skipped"])
    n_skip = sum(1 for r in RESULTS if r["skipped"])
    print("-" * 74)
    print("共 %d 条判据：PASS %d / FAIL %d / SKIP %d" % (len(RESULTS), n_pass, n_fail, n_skip))
    if n_fail == 0 and n_skip == 0:
        print("★ 回归闸门全绿：已修好的缺陷没有回退")
    elif n_fail == 0:
        print("▲ 有 %d 条不可判（SKIP）—— 这不是通过，是盲区，需人工确认" % n_skip)
    else:
        print("★ 回归！%d 条判据变红 —— 说明本次改动把已修好的缺陷弄回去了" % n_fail)

    if a.json:
        print(json.dumps({"results": RESULTS, "pass": n_pass,
                          "fail": n_fail, "skip": n_skip}, ensure_ascii=False, indent=1))
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
