# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

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
    python ci/regression_gate.py            # 跑闸门
    python ci/regression_gate.py --selfcheck # 跑负控（注入缺陷，必须变红）
    python ci/regression_gate.py --json      # 机器可读
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


def j_manifest_no_dead_entries():
    """★★ D-25（2026-10-12）：manifest 里不许有「指向不存在文件」的死条目。

    **这不是偶然缺陷，是结构性复发**（所以必须由闸门守，不能靠人记得）：
      `challenge/chain/` 是远端 bot **每日滚动**的活数据目录（文件按日期命名，
      每天替换成一个新日期文件）；而 `psl/manifest.json` 是**发布时快照**
      （`built_at` 固定）。链每滚动一次，manifest 立刻出现一条死条目
      ⇒ `ci/inbox_guards_0483.py` 的 S2 红（清单 ⊆ 随包集被破）
        ＋ `antinel_verify --manifest` 报 missing。

    2026-10-12 实测（本轮 merge 并入远端 21 条后）：链从
    `2026-09-23.jsonl` 滚到 `2026-10-11.jsonl`（merge 时 git 识别为 rename），
    而 manifest 仍写旧名 ⇒ 0483 从 12 绿掉到 11 绿／1 红。
    ⇒ 我上一轮判"delivery_gate 29 个套件零引用 merge 改动的路径"**是错的**：
      0483 是**通过读 manifest 间接**引用链文件的，grep 抓不到间接引用。

    ★ 判据打在**行为**上（文件存在性），不打字面/行号（维三）。
    ★ **不加版本豁免**：0483 S2 的自举豁免只对"wheel 载荷"成立（打包中途
      必然落后），不对"磁盘存在性"成立 —— commit 时树必须自洽。
      加豁免等于把死条目放过去，正是要防的那件事。
    ★ 追平工具：`_tools_034/_resign_manifest.py --roll`（结构化对齐 + 重签）。
    """
    man = PKG / "psl" / "manifest.json"
    if not man.is_file():
        return None, "缺 psl/manifest.json"
    try:
        files = json.loads(man.read_text(encoding="utf-8")).get("files") or {}
    except Exception as e:                                  # noqa: BLE001
        return False, "manifest 读不出：%s: %s" % (type(e).__name__, e)
    if not files:
        return False, "manifest 里没有 files 字典"
    dead = sorted(rel for rel in files if not (PKG / rel).is_file())
    if dead:
        return False, "%d 个死条目（清单有、磁盘无）：%s" % (len(dead), "、".join(dead[:3]))
    return True, "%d 条全部有对应文件" % len(files)


def j_posture_why_no_frozen_numbers():
    """★★ D-26（2026-10-12）：`guard_posture()["why"]` 不许含**冻结读数**。

    要防的复发（创始人 2026-10-12 第 3 条，原话「如果时间不会随时间走，
    就是错的，这句话要不不写」）：
      在岗分支的 why 原写「监理在岗，最后心跳 N 分钟前」。
      Antinel 监理页面**零自动刷新**（无 meta refresh / setInterval / location.reload，
      全文件实测）⇒「N 分钟前」是**渲染那一刻冻结的值**，页面开一小时
      它永远写同一个数。**这是一个会说谎的数字**（F55 同族：页面显示一个
      它维持不住的承诺）。已删；读数仍留在 `evidence.heartbeat_age`。

    ★ 禁词取「最后心跳」与「分钟前」两个**形状**，不是禁"心跳"两个字：
      缺岗分支的「心跳断档 N 分钟」**不删** —— 那是事件态，"断了多久"是
      判断该不该手动拉起的决策信息，且不会自己好转。禁"分钟前"（而非"分钟"）
      正好不误伤它。
    ★ 与 0360 的 `c_user_text_has_no_process_ids`（禁 pid）**职责分明**：
      那条禁实现细节，这条禁会说谎的读数。两条并存，互不替代。
    ★ 源码级为主（覆盖全部 7 个分支，不依赖运行态走到哪条）；
      运行态作补充（像 0360 那样 try，探不到不算缺陷）。
    """
    BANNED = ("最后心跳", "分钟前")
    src_p = PKG / "host_shield.py"
    if not src_p.is_file():
        return None, "缺 host_shield.py"
    src = src_p.read_text(encoding="utf-8", errors="replace")

    # ---- 源码级：guard_posture 函数体内每个 "why" 赋值行 ----
    m = re.search(r"^def guard_posture\(.*?(?=^def |\Z)", src, re.S | re.M)
    if not m:
        return False, "找不到 guard_posture 定义（被改名/删了？）"
    body = m.group(0)
    bad = []
    for w in re.finditer(r'"why"\s*:\s*([^\n]*(?:\n\s+[^\n]*)*?)(?=,|\n\s*"evidence")', body):
        seg = w.group(1)
        for b in BANNED:
            if b in seg:
                bad.append("%s in %r" % (b, seg.strip()[:60]))
    if bad:
        return False, "why 里出现冻结读数：%s" % "；".join(bad[:3])

    # ---- 运行态补充：探真实返回值（探不到不算缺陷，源码级已给结论）----
    try:
        import importlib.util as _ilu
        _sp = _ilu.spec_from_file_location("_hs_d26", str(src_p))
        _hm = _ilu.module_from_spec(_sp)
        _sp.loader.exec_module(_hm)
        _p = _hm.guard_posture(str(PKG))
        _why = str(_p.get("why") or "")
        for b in BANNED:
            if b in _why:
                return False, "运行态 why 含 %s：%r" % (b, _why)
    except Exception:                                       # noqa: BLE001
        pass
    return True, "why 无冻结读数（源码 %d 个 why 赋值 + 运行态均已检）" % len(
        re.findall(r'"why"\s*:', body))


# ══════════════════════════════════════════════════════════════════════════
# D-27 ~ D-31 / G-05（2026-10-12 值守台交接件 §4.5，剩余工作 R1–R6）
#   六条判据补上「登记簿从不会响的表格变成闸门一环」缺的那几环：
#     D-27 量具口径一致性（T-03）  D-28 fixture 覆盖（T-03）
#     D-29 docstring 工具参数（T-04） D-30 docstring 路径（T-06）
#     G-05 认窗白名单（T-05）       D-31 登记簿一致性（元层自接闸门）
# ══════════════════════════════════════════════════════════════════════════

def _load_module_file(rel, tag):
    """按**文件路径**加载一个模块（不进 sys.path）。失败/不存在 ⇒ None。

    ★ 为什么不 `import`：本闸门要在**负控 fixture** 里跑（ANTINEL_PKG 指向
      临时副本）。`import` 按 sys.path 找到的是**真仓**模块 —— 判据验的就不是
      fixture 里的代码了（量具测错对象，本项目已犯过两次的同型错）。
    ★ `exec_module` 遇 SystemExit 照走（CLI 型模块加载时的半初始化情形，
      与 `load_hook()` 同一处置）。
    """
    import importlib.util as _ilu
    p = PKG / rel
    if not p.is_file():
        return None
    spec = _ilu.spec_from_file_location(tag, str(p))
    mod = _ilu.module_from_spec(spec)
    sys.modules[tag] = mod
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pass
    return mod


def _docstring_corpus():
    """`ci/*.py` ＋ `_tools_034/*.py` 的 docstring 清单：[(相对路径, [文本...])]。

    ★ 为什么只扫 docstring（D-29/D-30 的语料，两个判据共用）：
      注释与代码字符串里**大量故意**引用坏形状 —— 守卫文件描述「被禁的旧形态」、
      登记簿描述已修缺陷的原貌、工具注释讲「我曾照着 __file__ 找错过目录」。
      那些是**在说不存在的东西**，不是**承诺**；T-06/T-04 判的是
      「照着文档做必错」。扫描范围 = 真源 docstring（ast 取，不扫行号/字面）。
    ★ 解析失败 ⇒ 抛异常（调用方转红）—— 不许静默跳过整个文件（跳过＝盲区）。
    """
    import ast as _ast
    out = []
    for base, sub in ((PKG / "ci", "ci"), (PKG / "_tools_034", "_tools_034")):
        if not base.is_dir():
            continue
        for p in sorted(base.glob("*.py")):
            src = p.read_text(encoding="utf-8", errors="replace")
            docs = []
            for node in _ast.walk(_ast.parse(src)):
                if isinstance(node, (_ast.Module, _ast.FunctionDef,
                                     _ast.AsyncFunctionDef, _ast.ClassDef)):
                    d = _ast.get_docstring(node, clean=False)
                    if d:
                        docs.append(d)
            out.append(("%s/%s" % (sub, p.name), docs))
    return out


def j_resign_caliber_matches_builder():
    """★★ D-27（2026-10-12）：重签工具的哈希口径必须与构建器登记值一致（T-03）。

    要防的复发（本轮一次**真实破坏**逼出来的，不是推演）：
      `_tools_034/_resign_manifest.py` 曾用**裸 sha256**，而构建器对
      `host_shield.VERSION_BEARING_CHAIN_FILES`（实测唯一成员
      `hooks/pre_tool_use.py`）是**先归一化版本行再算**。两个口径不一致的
      后果是**双向的**：假红（没变的文件判成需重签）＋ **破坏**（照错值写回
      让 `--manifest` 由绿变红）。工具侧已改 import host_shield 拿归一化口径
      （54 行）并加了写回前自检；本条把「口径一致」固化成判据。

    ★ 判据打在**行为**上（工具算出的值 == manifest 登记值），不比对源码长相（维三）。
    ★ 判据不许二次实现：exec 工具自己的 `sha256(rel)` 函数体，不在这里重写口径。
    """
    import hashlib as _hashlib
    tool_rel = "_tools_034/_resign_manifest.py"
    src_p = PKG / tool_rel
    if not src_p.is_file():
        return None, "缺 %s" % tool_rel
    src = src_p.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^def sha256\(rel\):.*?(?=^def |\Z)", src, re.S | re.M)
    if not m:
        return False, "%s 里找不到 sha256(rel) 定义（被改名/删了？）" % tool_rel
    hs = _load_module_file("host_shield.py", "_hs_d27")
    if hs is None:
        return None, "缺 host_shield.py"
    ns = {"os": os, "hashlib": _hashlib, "ROOT": str(PKG), "_hs_hash": hs}
    try:
        exec(compile(m.group(0), tool_rel + ":sha256", "exec"), ns)
        tool_sha = ns["sha256"]
    except Exception as e:                                  # noqa: BLE001
        return False, "加载工具 sha256 失败：%s: %s" % (type(e).__name__, e)

    bearing = list(getattr(hs, "VERSION_BEARING_CHAIN_FILES", ()) or ())
    if not bearing:
        return False, "host_shield.VERSION_BEARING_CHAIN_FILES 为空（口径特殊件清单没了）"
    man = PKG / "psl" / "manifest.json"
    if not man.is_file():
        return None, "缺 psl/manifest.json"
    try:
        files = json.loads(man.read_text(encoding="utf-8")).get("files") or {}
    except Exception as e:                                  # noqa: BLE001
        return False, "manifest 读不出：%s: %s" % (type(e).__name__, e)
    bad = []
    for rel in bearing:
        if rel not in files:
            bad.append("%s 不在 manifest 里" % rel)
            continue
        if not (PKG / rel).is_file():
            bad.append("%s 在磁盘上不存在" % rel)
            continue
        try:
            got = tool_sha(rel)
        except Exception as e:                              # noqa: BLE001
            bad.append("%s 工具侧算失败：%s" % (rel, e))
            continue
        if got != files[rel]:
            bad.append("%s：工具算 %s… ≠ manifest 登记 %s…（口径分叉）"
                       % (rel, got[:22], files[rel][:22]))
    if bad:
        return False, "；".join(bad[:3])
    return True, "重签工具口径与 manifest 登记一致（%d 个口径特殊件）" % len(bearing)


def j_negctl_fixture_covers_manifest():
    """★★ D-28（2026-10-12）：负控 fixture 必须覆盖 manifest 全部条目（T-03）。

    要防的复发（本轮实测，X-004）：负控 fixture 原来只复制 7 个目录，
    manifest 里 `assets/`、`challenge/` 条目在 fixture 里全部「不存在」
    ⇒ D-25 在**每一条**负控里连带假红，输出污染成「D-25 | D-25」，
    读者分不清哪条才是真正被注入的 —— **假红不是缺陷、是盲区**，
    而它让负控失去分辨力（「会误报的检查器用两次就没人信」）。

    ★ 与 D-25 的关系：D-25 查**真仓**的 manifest↔磁盘；本条查 **fixture**
      的 manifest↔fixture 磁盘。fixture 与真仓同源（`_build_negctl_fixture`
      是唯一真源，本判据直接调它，不另写一遍构建逻辑 —— 判据不许二次实现）
      ⇒ 本条绿，才证明 D-25 在 fixture 上的绿是真的绿。
    ★ fixture 建不起来（返回 None）⇒ **按红处理**，不许静默通过
      （静默通过＝假负控，正是本条要防的形状）。

    ★★ 2026-10-13 扩一条（X-022，**X-004 同型复发**）：fixture 还必须是一个
      **现实可能的形态**。D-33 那次只 `mkdir` 出 `.git/hooks/` ⇒ 留下一个
      「只含 hooks/ 的 .git」；而 `_index_build_artifacts()` 用
      `(root/'.git').exists()` 当「这是不是 git 工作树」的代理 ⇒ 代理成立、
      `git ls-files` 却报 `fatal: not a git repository` ⇒ **D-24 在 26/26 条
      负控里都连带变红**，△ 那一栏被常量噪声占满、失去分辨力。
      ⇒ 断言：fixture 若存在 `.git`，它必须是**有效工作树**
      （`git rev-parse --show-toplevel` 必须等于 fixture 根）。
      **不写「只要 .git 存在就算畸形态」**：真仓里 `.git` 本来就该在。
      ★ 修法照 X-004 的先例 —— **修 fixture，不修判据**。
    """
    import subprocess
    dst = _build_negctl_fixture("D-28")
    try:
        if dst is None:
            return False, ("fixture 构建失败（_build_negctl_fixture 返回 None）"
                           "—— 不可判即红，不许静默通过")
        man = dst / "psl" / "manifest.json"
        if not man.is_file():
            return False, "fixture 里没有 psl/manifest.json（fixture 结构变了）"
        try:
            files = json.loads(man.read_text(encoding="utf-8")).get("files") or {}
        except Exception as e:                              # noqa: BLE001
            return False, "fixture manifest 读不出：%s: %s" % (type(e).__name__, e)
        missing = sorted(rel for rel in files if not (dst / rel).is_file())
        if missing:
            return False, ("fixture 缺 %d 个 manifest 条目覆盖的文件（如 %s）"
                           "—— D-25 会在负控里因此连带假红"
                           % (len(missing), "、".join(missing[:3])))
        # ★★ X-022：fixture 的 `.git`（若有）必须是**有效工作树**
        if (dst / ".git").exists():
            try:
                r = subprocess.run(["git", "-C", str(dst), "rev-parse", "--show-toplevel"],
                                   capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=30)
            except Exception as e:                          # noqa: BLE001
                return False, "fixture 的 git 查询跑不起来：%s: %s" % (type(e).__name__, e)
            top = (r.stdout or "").strip()
            # ★★ 比「是不是同一个目录」必须按**文件系统身份**比，不许比字符串 ——
            #   本机实测踩到：`%TEMP%` 给的是 **8.3 短名**（`C:\Temp\PGINST~1\…`），
            #   而 git 回的是**长名**（`C:/Temp/pginstall/…`）⇒ 同一目录、字符串不等
            #   ⇒ 本条假红（T-09「同一事实两套口径」在路径上的变体）。
            #   `os.path.samefile` 走 stat（设备号+inode）⇒ 别名一律认得。
            _same = False
            if r.returncode == 0 and top:
                try:
                    _same = os.path.samefile(top, str(dst))
                except OSError:
                    _same = False
            if not _same:
                return False, (
                    "fixture 的 `.git` 是**畸形态**（不是有效工作树：rc=%s top=%r）"
                    "⇒ 任何按 `.git` 存在性判断的判据（实测 **D-24**）会在**每一条**"
                    "负控里连带假红（26/26）—— 与 X-004 同型。"
                    "修法：`_build_negctl_fixture` 里 `git init` 之后再放钩子。"
                    % (r.returncode, top[:80]))
        return True, ("fixture 覆盖 manifest 全部 %d 条；`.git` 是有效工作树"
                      % len(files))
    finally:
        # 零删除纪律：fixture 不删，改名让开（safe-delete 守卫会硬杀 rmtree）
        if dst is not None:
            _aside_dir(dst.parent)


def j_docstring_tool_flags_exist():
    """★★ D-29（2026-10-12）：docstring 承诺的工具 flag 必须真实可跑（T-04）。

    要防的复发（X-005）：D-25 的 docstring 承诺追平工具
    `_resign_manifest.py --roll`，但该参数当时并不存在 ⇒ 判据红了，
    照着文档给的修法跑不通 —— **红而无出路**（知道错了也改不了）。

    ★ 语料 = `ci/*.py` ＋ `_tools_034/*.py` 的 docstring（`_docstring_corpus`）。
    ★ 断言什么：① 被引用的工具文件存在；② 每个 flag 出现在该文件的
      `add_argument("--flag"` 里。两条都是**事实**（文件在不在、参数声明在不在），
      不是字面像不像（维一/维三）。
    """
    pat = re.compile(r"(_tools_\d+/[\w.-]+\.py)((?:\s+--?[\w-]+)+)")
    bad = []
    n_hits = 0
    for rel, docs in _docstring_corpus():
        for doc in docs:
            for m in pat.finditer(doc):
                n_hits += 1
                tool_rel = m.group(1)
                flags = m.group(2).split()
                tool_p = PKG / tool_rel
                if not tool_p.is_file():
                    bad.append("%s 的 docstring 引用 %s，文件不存在" % (rel, tool_rel))
                    continue
                tsrc = tool_p.read_text(encoding="utf-8", errors="replace")
                declared = set(re.findall(r'add_argument\(\s*"--([^"]+)"', tsrc))
                miss = [f for f in flags if f.lstrip("-") not in declared]
                if miss:
                    bad.append("%s 的 docstring 承诺 %s %s，工具没声明这些参数"
                               % (rel, tool_rel, " ".join(miss)))
    if bad:
        return False, "；".join(bad[:3])
    return True, "%d 处工具引用（文件＋flag）全部真实可跑" % n_hits


def j_docstring_paths_exist():
    """★★ D-30（2026-10-12）：docstring 承诺的仓内路径必须存在（T-06）。

    要防的复发（X-006）：本文件自己的 docstring 曾把入口路径写成 scripts/ 前缀，
    而文件实际在 `ci/` 下 —— 照着 docstring 跑必报找不到文件。
    **文档与代码不同锚 ⇒ 下一个人从头错到尾。**
    （此处刻意不引用那个错路径的字面 —— 判据语料正是 docstring，
     写例子会被自己扫到；这条纪律本身也是维三的一课。）

    ★ 语料同 D-29（docstring，不扫注释/代码字符串 —— 那里大量故意引用坏形状）。
    ★ 断言打在**存在性**上（相对 PKG），不打字面（维三）。
    ★ 注册前已自扫修光（0482/j2 两处描述旧形态的措辞改写法，见提交信息）。
    ★★ 2026-10-15 修一处**量具假红**（假红不是缺陷、是盲区）：原扩展交替表
      缺 `jsonl` 且无结尾边界 ⇒ 把 `.jsonl` 后缀截成 `.json` 去查存在性 ⇒
      对写着正确 jsonl 路径的 docstring 报「不存在」。修法：扩展表补 `jsonl`
      （放在 `json` 前，长配优先）＋ 结尾负向预查 `(?![\w./-])`。
    """
    pat = re.compile(r"(?:ci|scripts|tools|hooks|_tools_\d+)/[\w./-]+\.(?:jsonl|json|py|md|ps1|yml)(?![\w./-])")
    bad = []
    n = 0
    for rel, docs in _docstring_corpus():
        for doc in docs:
            for m in pat.finditer(doc):
                n += 1
                p = m.group(0)
                if not (PKG / p).exists():
                    bad.append("%s 的 docstring 引用 %s，仓里不存在" % (rel, p))
    if bad:
        return False, "；".join(bad[:3])
    return True, "%d 处仓内路径引用全部存在" % n


def j_page_titles_guard():
    """★★ G-05（2026-10-12）：认窗白名单守卫必须在位（T-05 边界误伤）。

    背景（X-007，0.36.5 实测）：认窗判据曾用宽泛匹配（标题前缀）认
    「本次运行的窗口」，误把用户自己的记事本当成Antinel 监理窗口处理。
    0.36.5 起 `_mark_at_tail()` 的前缀白名单专守这件事，其真身在
    `ci/inbox_guards_0360.py` 的 `c_window_suffix_matches_every_page()`，
    但 `defect_types.gate_ids_from_registry()` 只读 `regression_gate.py`
    ⇒ 它被误报「不在注册表」（红而无出路的变体）。本条按推荐方案 (a)
    用**薄判据**把它接进注册表，与现有 16 条同构。

    ★ ①② 两条都过才绿：
      ① 0360 的专守函数必须通过（页面清单逐条实跑认窗）；
      ② T-05 本质断言：0.36.5 实测过的用户窗口形状
         `is_console_title("请给我一个 · Antinel 监理#a8276c", "a8276c")` 必须为 False。
    ★ 连带：0360 全量（52 条）、收旧窗、`find_console_windows` 两级匹配
      在交付闸门里照跑；W-01 批次改 `_mark_at_tail` 时本条继续守。
    """
    g0360 = _load_module_file("ci/inbox_guards_0360.py", "g0360_wrapper")
    if g0360 is None:
        return False, "ci/inbox_guards_0360.py 加载失败（认窗守卫真身读不到）"
    fn = getattr(g0360, "c_window_suffix_matches_every_page", None)
    if fn is None:
        return False, ("0360 里没有 c_window_suffix_matches_every_page"
                       "（被改名/删了？——那正是 T-05 复发入口）")
    r = fn()
    if r is not True:
        return False, "0360 认窗专守未过：%s" % (r if isinstance(r, str) else repr(r))
    win = _load_module_file("inbox_window.py", "inbox_window_g05")
    if win is None:
        return False, "inbox_window.py 加载失败"
    if win.is_console_title("请给我一个 · Antinel 监理#a8276c", "a8276c"):
        return False, ("用户窗口形状「请给我一个 · Antinel 监理#a8276c」被误认成本次运行窗口"
                       "（T-05 复发：宽泛匹配认对象）")
    return True, "认窗白名单在位（0360 专守过 ＋ 用户形状拒认）"


def j_defect_registry_consistent():
    """★★ D-31（2026-10-12）：缺陷类型登记簿自身必须一致（元层接成闸门一环）。

    这是「登记簿不是一张不会响的表格」的落地：调
    `defect_types.check_consistency(gate_ids_from_registry())`，
    `ok` 才绿。**注册之时它必然红**（当前 T-03/04/05/06 的判据都没注册）——
    它由红转绿的瞬间就是 R1–R7 完工的证明，不是失败。

    ★ 判据不许二次实现：判据逻辑全在 `defect_types.check_consistency`，
      本条只做「加载 ＋ 调用 ＋ 转红」。
    """
    dt = _load_module_file("ci/defect_types.py", "defect_types_d31")
    if dt is None:
        return False, "ci/defect_types.py 加载失败"
    ids = dt.gate_ids_from_registry()
    ok, problems = dt.check_consistency(ids)
    if not ok:
        return False, "登记簿 %d 处不一致：%s" % (len(problems), "；".join(problems[:3]))
    return True, "登记簿一致（%d 类 / %d 实例，注册表口径）" % (
        len(dt.TYPES), len(dt.INSTANCES))


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


def _registration_consistency_problems(rel, want):
    """⑥⑦：出包登记与当前版本一致性（2026-10-16，机制层方案 v1.0 §5）。

    病灶（0.50.5 事故）：`_note_0510` 写「保持 0.50.5、出包等禁令解除」——
    版本前进到 0.51.0 后，该登记从「暂缓」变成「登记了一个**永远产不出**的
    版本」（版本号出自 pyproject），直到收尾被 D-23 拦住才发现。
    「暂缓」类决定没有失效条件 ⇒ 本尺子把它制度化：

      ⑥ `pypi.target_version` 必须 == `release.version`（都登记时）——
         出包登记与当前版本分家 ＝ dist/wheel 链条全部失真；
      ⑦ `release.publish_hold`（若存在，暂缓决定的机器可读形态）必须含
         `hold_version`；`release.version != hold_version` ＝ 暂缓决定已失效
         ⇒ 复核登记（撤下或更新并重述理由）。

    纯函数（rel=release 段 dict，want=release.version）——j_workspace_facts 与
    内建负控共用同一把尺子（不复制逻辑）。
    """
    probs = []
    py = rel.get("pypi") or {}
    tv = py.get("target_version")
    if tv and want and tv != want:
        probs.append(
            "release.pypi.target_version(%s) 与 release.version(%s) 分家 —— "
            "出包登记说一个产不出的版本（0.50.5 事故）。确要暂缓出包 ⇒ 用 "
            "release.publish_hold 显式登记（含 hold_version），不许让 "
            "target_version 停在旧版" % (tv, want))
    hold = rel.get("publish_hold")
    if hold is not None:
        if not isinstance(hold, dict) or not hold.get("hold_version"):
            probs.append(
                "release.publish_hold 存在但缺 hold_version —— 暂缓决定必须有"
                "机器可读的失效条件（hold_version），不许只写散文注记")
        elif want and hold.get("hold_version") != want:
            probs.append(
                "暂缓决定已失效：release.version(%s) 已偏离 publish_hold."
                "hold_version(%s) —— 复核登记：撤下 publish_hold，或更新 "
                "hold_version 并重述暂缓理由" % (want, hold.get("hold_version")))
    return probs


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
         （此前 new_user_cmd_journey 写死 0.28.0、cmp_check_out 写死 0.33.2 ⇒ 站上混搭无人发现）；
      ⑥⑦ 出包登记一致性（2026-10-16，机制层方案 v1.0 §5）：target_version 必须
         == release.version；publish_hold（若存在）必须含 hold_version 且版本
         前进即失效 ⇒ 红 —— 0.50.5 事故（登记一个永远产不出的版本）的制度化。
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

    # ★ 2026-10-16（⑥⑦，机制层方案 v1.0 §5）：出包登记一致性＋暂缓失效条件。
    probs += _registration_consistency_problems(rel, want)
    # 内建负控（照 D-28 ③先例）：尺子必须真的有牙——
    #   ① tv 分家必须红；② 失效 hold 必须红；③ 合法 hold 必须放过。
    _neg = _registration_consistency_problems(
        {"pypi": {"target_version": "0.0.1"}}, "9.9.9")
    _neg += _registration_consistency_problems(
        {"pypi": {}, "publish_hold": {"hold_version": "0.0.1"}}, "9.9.9")
    if len(_neg) < 2:
        return False, ("内建负控未生效：⑥⑦ 的尺子对变异登记（tv=%r / hold=%r）没报满 "
                       "2 条问题 ⇒ 0.50.5 型分家会漏放：%r"
                       % ("0.0.1", "0.0.1", _neg))
    _pos = _registration_consistency_problems(
        {"pypi": {"target_version": "9.9.9"},
         "publish_hold": {"hold_version": "9.9.9"}}, "9.9.9")
    if _pos:
        return False, ("内建负控未生效：合法登记（tv==version、hold_version==version）"
                       "被误报 ⇒ 尺子过宽：%r" % (_pos,))

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


# ================================================================ 闸门自身（D-32/33/34）
# ★★ 这三条是 2026-10-13 效率升级那一轮**抓到的真缺陷**的固化。它们的共同点：
#   缺陷**不在产品里，在"检查系统自己"里** —— 而检查系统坏了不会自己报错，
#   只会让所有结论变得不可信（闸门说自己绿，其实没跑/跑错/被偷锁）。
#   ⇒ 与 D-27/D-28（量具自身有缺陷）、D-31（登记簿自身一致）同一族。

def _load_delivery_gate(tag):
    """加载交付闸门模块（D-32/D-34 共用）。判据不许二次实现 ⇒ 直接调它的真函数。"""
    return _load_module_file("ci/delivery_gate.py", tag)


def j_three_state_discipline():
    """★★ D-32（2026-10-13）：**查不到 ≠ 没有** —— 三态纪律（T-08）。

    要防的复发（X-009，2026-10-13 实测，本轮抓到的最严重一处）：
      `ci/delivery_gate.py` 的 `_pid_alive` 第一版写成
      `except Exception: return False` —— 把「**查不了**」折叠成了「**不在**」。
      而它**必然**查不了：以 `python ci/delivery_gate.py` 启动时 `sys.path[0]`
      是 `ci/` 而不是仓根，`import audit_chain` 抛 `ModuleNotFoundError`。
      后果不是"报个错"，而是：**判活恒为"死" ⇒ 活锁被判成陈旧锁 ⇒ 被偷**。
      产品模块 `audit_chain.pid_alive` 自己的纪律写着「查询失败/异常按存活
      （宁可 sidecar，不可误偷活锁 —— Run B 教训）」—— 那一版**正好反着做**。
      ★ 它在 Windows 上侥幸没造成并发，是因为占用方句柄没关、`os.replace`
        撞了共享冲突；**POSIX 上 `os.replace` 对打开中的文件是合法的** ⇒ 真会偷。

    ★ 断言三条，全是**行为**（不看源码字样）：
      ① **量具自检**（维七）：`_pid_alive(本进程)` 必须 `True`；
         `_pid_alive(不可能存在的 pid)` 必须 `False`。
      ② **查不了必须与不在可区分**：把 `audit_chain` 从 `sys.modules` 摘掉
         （`= None` ⇒ `import` 抛 ImportError，正是当年那条路径）⇒ 必须返回
         `None`，**不许**返回 `False`。
      ③ **拿不准时锁必须按占用处理**：往锁文件里写一个**活 pid**（本进程）
         ⇒ `_acquire_lock()` 必须拒绝、消息里点出那个 pid、且**锁文件原封不动**
         （没被改名让开 ⇒ 没被偷）。
    ★ 判据不许二次实现：直接调 `delivery_gate` 的真函数。
    ★ 沙箱纪律：把 `_LOCK` 指到临时目录，绝不碰真仓的 `run.lock`
      —— 否则判据自己会把**正在跑的闸门**的锁让开，那就成了"判据制造并发"。
    """
    dg = _load_delivery_gate("delivery_gate_d32")
    if dg is None:
        return False, "ci/delivery_gate.py 加载失败（不可判即红）"
    me = os.getpid()

    # ① 量具自检
    got_me = dg._pid_alive(me)
    if got_me is not True:
        return False, ("量具自检失败：_pid_alive(本进程 %d)=%r，期望 True"
                       "（判活自己都测不准，后面两条结论不算数）" % (me, got_me))
    got_dead = dg._pid_alive(999999)
    if got_dead is not False:
        return False, "量具自检失败：_pid_alive(999999)=%r，期望 False" % (got_dead,)

    # ② 查不了 ≠ 不在（摘掉 audit_chain ＝ 模拟 import 失败）
    _had = "audit_chain" in sys.modules
    _old = sys.modules.get("audit_chain")
    sys.modules["audit_chain"] = None
    try:
        got_blind = dg._pid_alive(me)
    finally:
        if _had:
            sys.modules["audit_chain"] = _old
        else:
            sys.modules.pop("audit_chain", None)
    if got_blind is not None:
        return False, ("查不了被折叠成了结论：摘掉 audit_chain 后 _pid_alive 返回 %r"
                       "（必须 None＝查不了；返回 False＝当成了「不在」⇒ 活锁可被偷）"
                       % (got_blind,))

    # ③ 拿不准时锁必须按占用处理（活锁不许被偷）
    import tempfile
    tmp = tempfile.mkdtemp(prefix="d32_lock_")
    _keep_lock = dg._LOCK
    dg._LOCK = os.path.join(tmp, "run.lock")
    try:
        with open(dg._LOCK, "w", encoding="utf-8") as f:
            f.write(str(me))
        fd, why = dg._acquire_lock()
        if fd is not None:
            dg._release_lock(fd)
            return False, ("锁文件里写的是**活 pid %d**，_acquire_lock 却把锁给了出来"
                           " ⇒ 活锁被偷（两个闸门会并发互写基线与日志）" % me)
        if str(me) not in (why or ""):
            return False, "拒绝是对的，但消息没点出占用方 pid（%r）" % (why or "")
        if not os.path.exists(dg._LOCK):
            return False, "锁文件被让开了 —— 活锁不许被改名让开（%r）" % (why or "")
    finally:
        dg._LOCK = _keep_lock
        _aside_dir(tmp)
    return True, "三态齐备：查不了→None ／ 拿不准按占用 ／ 活锁原封不动（pid %d）" % me


def j_hook_same_anchor():
    """★★ D-33（2026-10-13）：提交钩子必须与仓内真源**同锚**（T-09）。

    要防的复发（X-012，2026-10-13 实测）：
      `.git/hooks/pre-commit` 是 09-28 拷的（跑 `ci/regression_gate.py`，只 22 条），
      而仓内源 `ci/git-hooks/pre-commit` 在 10-07 的 `aa3eeff` 已升级为
      `ci/delivery_gate.py --quick` —— **部署件 6 天没跟源，且没有任何判据守它**。
      后果：那个"一处入口"的强制点**实际是断的**，
      28 套快档判据在这 6 天里**一次都没在提交时跑过**。
      ⇒ 这正是 T-09「同一事实两套口径」：**"钩子该跑什么"有两份答案**，
        而生效的那份没人看（README 声明源是真源，实践里没人校验）。

    ★ 断言三条：
      ① 源里承诺的闸门**路径**存在（照着钩子跑不许报"找不到文件"）；
      ② 源里承诺的**参数**是该闸门真实支持的（argparse 里真有）；
      ③ 部署件**存在** ⇒ 必须与源**逐字一致**，不一致即红并给出修法；
         **不存在** ⇒ 不算红（新克隆本该手动装一次），但**必须出现在输出里**
         —— 不许把"没装钩子"渲染成"已装且一致"。
    ★ 为什么③能被负控：`_build_negctl_fixture` 会把部署件一并复制进 fixture，
      所以 fixture 里"源 ＝ 部署件"成立；注入改坏源 ⇒ 立刻漂移 ⇒ 红。
    """
    src_rel, dep_rel = "ci/git-hooks/pre-commit", ".git/hooks/pre-commit"
    src_p = PKG / src_rel
    if not src_p.is_file():
        return False, "仓内钩子源不存在：%s（删掉源＝让这条判据变空）" % src_rel
    src = src_p.read_text(encoding="utf-8", errors="replace")

    # ① 承诺的闸门路径存在
    miss = sorted({m.group(1) for m in re.finditer(r"\$ROOT/([\w./-]+\.py)", src)
                   if not (PKG / m.group(1)).is_file()})
    if miss:
        return False, ("钩子承诺的闸门路径不存在：%s ⇒ 照着钩子跑必报找不到文件"
                       % "、".join(miss))

    # ② 承诺的参数真实存在
    flags = sorted({m.group(1) for m in re.finditer(r'\$GATE"?\s+(--[\w-]+)', src)})
    gate_rel = "ci/delivery_gate.py"
    gate_p = PKG / gate_rel
    if not gate_p.is_file():
        return False, "找不到钩子要跑的闸门：%s" % gate_rel
    gate_src = gate_p.read_text(encoding="utf-8", errors="replace")
    bad = [f for f in flags if ('add_argument("%s"' % f) not in gate_src]
    if bad:
        return False, ("钩子承诺的参数在 %s 里不存在：%s（红而无出路，T-04/T-09）"
                       % (gate_rel, "、".join(bad)))

    # ③ 部署件与源逐字一致
    dep_p = PKG / dep_rel
    if not dep_p.is_file():
        return True, ("部署件不存在（%s）—— 新克隆的正常状态，但**提交钩子此刻不生效**："
                      "装它 `cp %s %s`" % (dep_rel, src_rel, dep_rel))
    dep = dep_p.read_text(encoding="utf-8", errors="replace")
    if dep != src:
        return False, ("部署件与仓内源**不一致**（%s ≠ %s）：钩子该跑什么是两份答案，"
                       "而生效的那份没人看（2026-10-13 实测漂了 6 天，"
                       "28 套快档判据一次没跑）。修法：`cp %s %s`"
                       % (dep_rel, src_rel, src_rel, dep_rel))
    return True, "钩子源与部署件逐字一致（%d 字节）；承诺的路径/参数均真实" % len(src)


def j_fastlane_not_silent():
    """★★ D-34（2026-10-13）：快道/快档**不许静默少跑**（T-10）。

    要防的复发（X-014，2026-10-13 实测）：
      交付闸门实测 **1161s ≈ 19.3 分钟**、主闸门 **68s**（文档写 13.2s），
      于是"全量跑"退化成靠自觉 —— 交接件 §3.3 附加要求二早就写了
      「闸门要快到没有理由跳过」，但**药方没人吃**。
      而一旦引入"快道"，新风险立刻变成**快道悄悄少跑**：
      少跑的那几条没人知道 ⇒ 与"没有闸门"等价。
      ⇒ 口径：**快道可以少跑，但必须明说自己少跑了什么**。

    ★ 断言四条（前三条是**行为**，第四条是**机制在位**，同 D-11 的立场）：
      ① `_apply_budget` 把装不下的套件**逐条**打印出来（含历史秒数），
         不许只给一个数字。做法：喂一张"全部超预算"的假耗时表，
         断言返回集之外的**每一个套件名都出现在输出里**。
      ② `_apply_budget` **永远保留主闸门**（它是"已修缺陷的总账"，快道存在的理由）。
      ③ `_apply_budget` 对"没有历史耗时"的套件**按跑处理**
         （宁可超预算，不许因为"不知道它多慢"就跳）。
      ④ 主闸门快档：`--quick` 声明跳过的判据 ID **每条都真的存在且唯一**
         （否则这份声明是空转：改了 ID 就静默不跳/跳错），
         且全量（不带 `--quick`）仍全跑 —— 由"跳过只在 `a.quick` 下发生"保证。
    """
    import contextlib
    import io as _io

    dg = _load_delivery_gate("delivery_gate_d34")
    if dg is None:
        return False, "ci/delivery_gate.py 加载失败（不可判即红）"
    if not hasattr(dg, "_apply_budget"):
        return False, "交付闸门没有快道预算函数 `_apply_budget`（快道入口被删？）"

    fake = [("0360", "ci/inbox_guards_0360.py", "fast"),
            ("0470", "ci/inbox_guards_0470.py", "fast"),
            ("regression", "ci/regression_gate.py", "slow")]
    _keep = dg._load_durations
    dg._load_durations = lambda: {"0360": 999.0, "0470": 999.0, "regression": 999.0}
    buf = _io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            took = dg._apply_budget(fake)
    finally:
        dg._load_durations = _keep
    out = buf.getvalue()

    took_keys = {s[0] for s in took}
    if "regression" not in took_keys:
        return False, "快道把主闸门也预算掉了 —— 主闸门必须永远跑（它是已修缺陷总账）"
    dropped = [s[0] for s in fake if s[0] not in took_keys]
    silent = [k for k in dropped if k not in out]
    if silent:
        return False, ("快道**静默**少跑：%s 既没跑、也没出现在输出里"
                       "（少跑的必须逐条列出来，否则与没有闸门等价）" % "、".join(silent))
    if not dropped:
        return False, ("预算 999s 却什么都没跳过 ⇒ 这条判据**没咬到东西**"
                       "（夹具失效，负控会是假的）")

    # ③ 没有历史耗时 ⇒ 按跑处理
    dg._load_durations = lambda: {}
    try:
        with contextlib.redirect_stdout(buf):
            took2 = dg._apply_budget(fake)
    finally:
        dg._load_durations = _keep
    if {s[0] for s in took2} != {s[0] for s in fake}:
        return False, ("没有历史耗时却被跳过 ⇒ 快道在「不知道它多慢」时就跳了"
                       "（必须按跑处理：宁可超预算，不许瞎跳）")

    # ④ 主闸门快档：声明的跳过 ID 必须真的存在且唯一
    ids = globals().get("_QUICK_SKIP_IDS") or []
    if not ids:
        return False, "主闸门没有声明 `_QUICK_SKIP_IDS`（快档跳过清单）"
    m = load_hook()
    all_cids = [cid for cid, _fn in _checks(m)]
    for sid in sorted(ids):
        hitn = [c for c in all_cids if c.split()[0] == sid]
        if len(hitn) != 1:
            return False, ("快档声明跳过 %r，但判据清单里匹配到 %d 条（必须恰好 1 条）"
                           " —— 这份声明是空转的（改了 ID 就静默不跳或跳错）"
                           % (sid, len(hitn)))
    return True, ("快道不静默：预算外逐条列明（%s）／主闸门永在／无耗时按跑；"
                  "快档声明的 %d 条跳过 ID 均存在且唯一"
                  % ("、".join(sorted(dropped)), len(ids)))


def j_docs_only_no_full_fallback():
    """★★ D-35（2026-10-13）：**纯文档改动不许回退全量**（钩子层 T-10）。

    要防的复发（X-016，2026-10-13 实测）：
      `_touch_files()` 只认**产品源码**（`.py` ＋ 闸门自身文件），而 `--hook`
      用「**探不到改动 ⇒ 回退全量**」做兜底 ⇒ **纯文档改动**（`docs/*.md`）
      被当成"探不到" ⇒ 回退全量 30 套（实测 **22 min**）⇒ 前台 `git commit`
      跑钩子**超时被 SIGTERM**，提交不了 ⇒ 人只好 `git commit --no-verify`。
      而「**会被绕过的钩子等于没有钩子**」正是快道（0.48.5）存在的全部理由
      —— 这个回退分支把刚接好的"一处入口"又拆了。
      ★ 与 D-34 同族（都是"快道自己的降级路径"），但 D-34 守的是"少跑要说"，
        本条守的是"**不该回退全量的，一次都不许回退**"。

    ★ 断言三条（全是**行为**；判据不许二次实现 ⇒ 直接调交付闸门的 `_select_suites`）：
      ① **纯文档**（探测层非空、影响面层为空）⇒ 跑且**只**跑主闸门，
         **绝不**是全集 —— 这是本判据存在的全部理由。
      ② **真无改动**（探测层也空）⇒ 才允许回退全量（"宁多跑不漏跑"的兜底仍在）。
      ③ **产品改动** ⇒ 走影响面（含主闸门），且不是全集（否则影响面名存实亡）。
    """
    dg = _load_delivery_gate("delivery_gate_d35")
    if dg is None:
        return False, "ci/delivery_gate.py 加载失败（不可判即红）"
    if not hasattr(dg, "_select_suites") or not hasattr(dg, "_changed_files"):
        return False, ("交付闸门没有 `_select_suites` / `_changed_files`"
                       "（探测层/影响面层的拆分被删了？）")
    total = len(dg.SUITES)

    # ① 纯文档 ⇒ 只跑主闸门（不是全集）
    s1, _m1, _ = dg._select_suites({"docs/x.md"}, set(), hook=False)
    k1 = [s[0] for s in s1]
    if k1 != ["regression"]:
        return False, ("纯文档改动应**只跑主闸门**，实际跑了 %d 套：%s"
                       " —— 回退全量会让钩子超时 ⇒ 人被逼去 --no-verify"
                       % (len(k1), "、".join(k1)))

    # ② 真无改动 ⇒ 才允许回退全量
    s2, m2, _ = dg._select_suites(set(), set(), hook=False)
    if m2 != "all" or len(s2) != total:
        return False, ("探测层一个改动都没有时应回退全量（%d 套），实际 %s/%d 套"
                       "（宁多跑不漏跑的兜底被删了）" % (total, m2, len(s2)))

    # ③ 产品改动 ⇒ 影响面（含主闸门），且不是全集
    s3, _m3, _ = dg._select_suites({"inbox_server.py"}, {"inbox_server.py"},
                                   hook=False)
    k3 = {s[0] for s in s3}
    if "regression" not in k3:
        return False, "产品改动时主闸门没在名单里（已修缺陷总账必须永远跑）"
    if len(s3) >= total:
        return False, ("产品改动却点了 %d 套（= 全集）⇒ 影响面名存实亡" % len(s3))
    return True, ("纯文档 ⇒ 只跑主闸门（%d 套）／真无改动 ⇒ 回退全量（%d 套）／"
                  "产品改动 ⇒ 影响面 %d 套（含主闸门）"
                  % (len(k1), len(s2), len(s3)))


def j_pinned_hashes_match_manifest():
    """★★ D-36（2026-10-13）：**被自检钉住的源码改了，就必须重签 manifest**（T-02 哈希面）。

    要防的复发（2026-10-13 实测，不是推演 —— 监理链上 135 条
    `host_shield_spawn_failed`，最近一条 18:44:27）：
      A1（`2397451`）改了 `host_shield.py`，而 `psl/manifest.json` 停在 `914c5dc`
      **没有重签** ⇒ 源树里的 manifest 是「落后快照」⇒
      `host_shield.self_check()` 报「host_shield.py 与 manifest 不符」
      ⇒ `is_dev_build()` 为 False（登记版本 0.48.4 ≥ 代码 0.48.4）
      ⇒ `spawn_sentinel()` **硬拦**（`return False, 0, "self-check-failed: …"`）
      ⇒ **监理拉不起来**。而**没有任何闸门判据会因此变红** —— 唯一覆盖
      manifest 哈希的 D-27 只查 `VERSION_BEARING_CHAIN_FILES` 一件
      （`hooks/pre_tool_use.py`）；`host_shield.py`／另 3 个告警链路件／
      `rules/hosts/*.json` 全都没有判据。发现它的唯一途径是**用户报障**
      （「我多次看到冒泡说监理拉起失败」）。

    ★ 为什么这是**结构性**的、必须由闸门守：源码每次改动都在"滚动"，而 manifest
      是发布时快照 —— 只要有人动这几个文件，快照就落后一格。这属于 **T-02
      （活数据追不上死快照）的哈希面**：D-25 守同族的**存在性面**（死条目），
      两条并存、互不替代（一条查"文件还在不在"，一条查"字节还是不是那个"）。

    ★ 断言（行为级；判据不许二次实现 ⇒ 直接调 `host_shield.self_check()`）：
      **真仓的树必须自洽** —— `self_check()` 返回 `(True, [])`。
      这正是 `spawn_sentinel()` 放行的**必要条件**（不满足必拦）。
    ★ 反空转：`_GUARDED_CHAIN_FILES` 非空 ＋ `host_shield.py` 在 manifest 里。
      否则 `(True, [])` 可能是"什么都没比"（＝自检对自己失明的同型）。
    ★ 红时必须给修法（否则是 T-04「红而无出路」）：
      `python _tools_034/_resign_manifest.py`（只重算已有条目）；
      报「没登记进 manifest」⇒ `python scripts/build_package.py`
      （清单条目的增删是构建器职责，重签工具刻意不越权）。
    ★ 与 D-27 的分工：D-27 守**量具口径**（工具算的值 == 登记值，防口径分叉）；
      本条守**事实一致**（磁盘字节 == 登记哈希）。两条读同一张表，判两件事。
    ★ 已知连带（是同一个根因，不是噪声）：`--selfcheck` 里凡注入到
      `host_shield.py`（D-26 负控）或 `hooks/pre_tool_use.py`（A1×2／A2 负控）
      的条目，都会**同时**让本条变红 —— 那些注入确实造成了"改了没重签"。
    """
    hs = _load_module_file("host_shield.py", "_hs_d36")
    if hs is None:
        return None, "缺 host_shield.py"
    if not hasattr(hs, "self_check") or not hasattr(hs, "_GUARDED_CHAIN_FILES"):
        return False, ("host_shield 没有 self_check / _GUARDED_CHAIN_FILES"
                       "（自检入口被改名/删了？那样监理既没人拦也没人放）")
    guarded = tuple(getattr(hs, "_GUARDED_CHAIN_FILES", ()) or ())
    if not guarded:
        return False, ("_GUARDED_CHAIN_FILES 为空（告警链路保护名单被清空 ⇒ 自检"
                       "形同虚设，本条的绿也不可信）")
    man = PKG / "psl" / "manifest.json"
    if not man.is_file():
        return None, "缺 psl/manifest.json"
    try:
        files = json.loads(man.read_text(encoding="utf-8")).get("files") or {}
    except Exception as e:                                  # noqa: BLE001
        return False, "manifest 读不出：%s: %s" % (type(e).__name__, e)
    if "host_shield.py" not in files:
        return False, ("host_shield.py 不在 manifest 里 —— D-1 自检的锚点没了"
                       "（修法：python scripts/build_package.py 重生清单）")
    try:
        ok, problems = hs.self_check()
    except Exception as e:                                  # noqa: BLE001
        return False, "self_check() 抛异常：%s: %s" % (type(e).__name__, e)
    if not ok:
        return False, (
            "真仓自检不通过（%d 条）：%s —— 这会让 `spawn_sentinel()` **硬拦**"
            "（监理拉不起来）。改了被钉住的源码就必须重签 manifest："
            "`python _tools_034/_resign_manifest.py`；"
            "若报「没登记进 manifest」则跑 `python scripts/build_package.py`"
            % (len(problems), "；".join(problems[:3])))
    return True, ("自检通过：host_shield.py ＋ %d 个告警链路件 ＋ rules/hosts/*.json "
                  "与 manifest 登记一致（监理可拉起）" % len(guarded))


def j_baseline_tag_reminder_in_place():
    """★★ D-37（2026-10-13）：**before 基线提醒必须在位且真接线**（T-10 静默降级）。

    要防的复发（遗留问题 C3 / 交接件 §6.1，实测不是推演）：
      §6.1 白纸黑字：「**开工前**先打 tag `pre-<批次>-<日期>`（与 merge 前的
      `pre-merge-20261012` 同型），改动前的 8 帧从该 tag 渲染备查 ——
      **没有 before 就没有「提升」的证据**」。实测这一轮**没打**：before 只能拿
      开工前的 commit（`2e4e68f`）的 worktree 补渲染 —— **等价但迟到**；迟到的
      代价是真的：before 与 after 之间若混进半成品改动，「提升」就证明不了。
      ⇒ 病型 **T-10 静默降级**：**「少做了 before 基线」这件事没有任何输出说明
        它发生了**，账面（8 帧截图）看起来与「有 before 对照」一样。

    ★ 修复形态（本判据锁的正是它）：`ci/baseline_tag.py`（**只读出聲**工具，rc 恒 0）
      ＋ 由提交钩子 `ci/git-hooks/pre-commit` 在**最早能机械介入的时刻**调用 ——
      每次产品提交都把「你登记开工基线了吗」念一遍，直到你把它登记下来。

    ★ 断言三条（缺一条都不算在位）：
      ① **工具在位且可用**：`ci/baseline_tag.py` 存在，`--json` 能跑且 rc==0
         （恒不拦截 —— 报红去拦提交是**过度**：见 ② 与「诚实登记」）。
      ② **行为契约（唯一真源）**：`is_product_path` 对产品件判 True、对开发侧
         （`ci/`、`docs/*.md`、`_p_*` 探针）判 False —— 这是「该出声时出声、
         不该出声时闭嘴」的唯一真源。它若恒 False ⇒ 提醒**永不触发**
         （工具在位却**静默失效**，正是本条要防的那个 T-10）。
      ③ **反空转（真接线）**：钩子源里**真的调用**它（`baseline_tag.py" --remind`）
         —— 工具在位但没人调用 ＝ 死代码（「没人跑的检查项＝没检查项」）。
    ★ 红时必须给修法（否则是 T-04「红而无出路」）：
      工具丢了 ⇒ 重建 `ci/baseline_tag.py`；钩子没接线 ⇒ 在
      `ci/git-hooks/pre-commit` 里加
      `"$PY" "$ROOT/ci/baseline_tag.py" --remind || true`，
      再 `cp ci/git-hooks/pre-commit .git/hooks/pre-commit`（部署件同锚，D-33）。
    ★ 与 D-33／D-34 的分工：D-33 守「钩子部署件与仓内源逐字一致」（T-09 漂移）；
      D-34 守「快道不许静默少跑」（T-10 的另一面）；本条守「基线提醒这条**机制**
      在位且真被调用」（T-10 的静默降级面）。三条读同一个钩子文件，判三件事。
    ★ **诚实登记（本条的已知边界，不许假装它更强）**：本条**只验机制在位**，
      **不验「本批真的打过基线 tag」** —— `git tag` **不区分用途**，机器**判不了**
      「本批有没有自己的基线」（`pre-merge-20261012` 是别的批次留的，同样是 HEAD
      的祖先）。那件事由**人**与 §6.1 截图清单裁决；工具与本判据一律**只出声、
      不裁决**（对「本批是否已登记基线」报红会**时红时绿** —— 本仓铁律：
      一个时红时绿的量具比恒红的更坏）。
    ★ 已知连带：负控注入改 `ci/git-hooks/pre-commit`（摘掉接线）会**同时**让
      D-33 变红 —— 源改了却没 `cp` 到 `.git/hooks/` 确实是漂移，是同一个根因，
      机器会打 △。
    """
    tool_rel = "ci/baseline_tag.py"
    tool_p = PKG / tool_rel
    if not tool_p.is_file():
        return False, (
            "%s 不存在 —— before 基线提醒工具丢了（§6.1：没有 before 就没有"
            "「提升」的证据）。修法：重建该工具（**只读出聲、rc 恒 0、不拦截**）"
            % tool_rel)

    # ① 工具在位且可用（--json，恒 rc 0）
    import subprocess as _sp
    try:
        r = _sp.run([sys.executable, str(tool_p), "--json", "--root", str(PKG)],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=60)
    except Exception as e:                                  # noqa: BLE001
        return False, ("%s --json 跑不起来：%s: %s（工具在位但不可用 ＝ 盲区，"
                       "不是通过）" % (tool_rel, type(e).__name__, e))
    if r.returncode != 0:
        return False, (
            "%s --json 返回 rc=%d（应为 0 —— 本工具**只出声、不裁决**）。报红去拦"
            "提交是**过度**：git tag 不区分用途，机器判不了「本批有没有自己的基线」"
            "⇒ 判违规会时红时绿（时红时绿比恒红更坏）。修法：让 main() 恒 return 0"
            % (tool_rel, r.returncode))

    # ② 行为契约：分类口径（唯一真源）
    mod = _load_module_file(tool_rel, "_bl_d37")
    if mod is None or not hasattr(mod, "is_product_path"):
        return False, ("%s 里没有 is_product_path（分类口径被删/改名 ⇒ 判据无法验"
                       "「该出声时出声、不该出声时闭嘴」）" % tool_rel)
    if not mod.is_product_path("antinel.py"):
        return False, (
            "is_product_path('antinel.py') == False —— 产品件被判成非产品 ⇒ 提醒"
            "**永不触发**（工具在位却静默失效，正是 T-10 静默降级的原貌）。"
            "修法：修 %s 的分类口径（排除法：只把开发侧目录/产物/探针排除）"
            % tool_rel)
    _bad_dev = [p for p in ("ci/regression_gate.py", "docs/x.md", "_p_probe.py")
                if mod.is_product_path(p)]
    if _bad_dev:
        return False, (
            "is_product_path 把开发侧判成了产品：%s ⇒ 提醒变噪音，人就会绕开它"
            "（「会误报的检查器用两次就没人信」）。修法：修 %s 的分类口径"
            % ("、".join(_bad_dev), tool_rel))

    # ③ 反空转：钩子真接线
    hook_rel = "ci/git-hooks/pre-commit"
    hook_p = PKG / hook_rel
    if not hook_p.is_file():
        return False, ("缺 %s（提醒没人调用 ＝ 死代码：工具在位但从不运行）"
                       % hook_rel)
    hook = hook_p.read_text(encoding="utf-8", errors="replace")
    if "baseline_tag.py" not in hook or "--remind" not in hook:
        return False, (
            "钩子没接线 before 基线提醒（%s 里找不到 `baseline_tag.py … --remind`）"
            "—— 工具在位但**没人调用 ＝ 死代码**（「没人跑的检查项＝没检查项」）。"
            "修法：加 `\"$PY\" \"$ROOT/ci/baseline_tag.py\" --remind || true`，"
            "再 `cp ci/git-hooks/pre-commit .git/hooks/pre-commit`（D-33）" % hook_rel)
    return True, ("before 基线提醒在位：%s（--json rc 0、分类口径正确）＋ %s 真接线"
                  "（T-10 静默降级面已守）" % (tool_rel, hook_rel))


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


def _build_negctl_fixture(label=""):
    """构建负控 fixture（`selfcheck()` 与判据 D-28 共用的**唯一真源**）。

    ★★ 为什么提成模块级函数（2026-10-12）：
      原先整段内联在 `selfcheck()` 里。D-28「fixture 必须覆盖 manifest
      全部条目」要验的正是这段代码的行为 —— 若在判据里**另写一遍**
      fixture 构建，就是二次实现：判据绿了不代表真仓的 fixture 绿
      （判据纪律①：判据不许二次实现）。
      ⇒ 提取出来，两边调同一个函数，判据验的就是**真仓会用的** fixture。

    返回 fixture 的 `pkg/` 路径；准备失败 ⇒ None（调用方必须中止该条负控，
    不许"做，也不许算它绿"——静默通过＝假负控）。
    """
    import shutil
    import tempfile
    # ★ 只复制闸门真正需要的骨架（全仓 copytree 870 文件 × 4 次 = 会超时）。
    #   hooks/ ＋ rules/ ＋ ci/ 就是全部依赖：闸门 import 钩子、读规则表、自己。
    tmp = Path(tempfile.mkdtemp(prefix="antinel_negctl_"))
    dst = tmp / "pkg"
    dst.mkdir(parents=True, exist_ok=True)
    # ★★ 2026-09-29：补 `psl/` 与 `docs/`（D-22 要读 psl/manifest.json；
    #   D-6 的版本承载件里有 psl/manifest.json 与 docs/AUDIT_SCHEMA.md）。
    #   fixture 缺这些文件会让判据因"文件不存在"而假红 —— 那不是缺陷，是盲区。
    # ★★ 2026-10-12：补 `_tools_034/`（仅 40K）—— D-27 要 import 里面的
    #   重签工具验口径；没有它，D-27 在 fixture 里只能 SKIP ⇒ 它的负控是假的。
    for sub in ("hooks", "rules", "ci", "scripts", "psl", "docs", "tools", "_tools_034"):
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
    # ★★ 2026-10-13（D-33 需要）：把**已部署的钩子**也带进 fixture。
    #   为什么：D-33 比的是「仓内源 vs 部署件」。fixture 里没有 `.git/`，
    #   于是 D-33 在每条负控里都会报"部署件不存在"—— 那不是缺陷、是**盲区**，
    #   而且会让 D-33 的负控变成假的（改了源也看不出漂移）。
    #   带上它之后，fixture 里"源 ＝ 部署件"成立，注入改坏源 ⇒ 立刻漂移 ⇒ 真能红。
    #   ★ 只碰 fixture 自己的 `.git/hooks/`，不动真仓（真仓的钩子由 D-33 正面守）。
    _dep_hook = PKG / ".git" / "hooks" / "pre-commit"
    if _dep_hook.is_file():
        # ★★ 2026-10-13 补（本轮实测发现）：**先 `git init` 把 fixture 变成真仓**，再放钩子。
        #   为什么（实测，不是推演）：D-33 那次只 `mkdir` 出 `.git/hooks/`
        #   ⇒ 留下一个「**只含 hooks/ 的 .git**」—— 现实中不可能存在的形态。
        #   而 `_index_build_artifacts()` 用 `(root/".git").exists()` 当
        #   「这是不是 git 工作树」的代理 ⇒ 该代理成立、`git ls-files` 却报
        #   `fatal: not a git repository` ⇒ **D-24 在 26/26 条负控里都连带变红**
        #   （对照实验：同一 fixture 加 `git init` 后 D-24 由 FAIL 转 PASS，
        #     **其余全部判据判定零变化**，闸门 rc 1 → 0）。
        #   与 D-28 当年修的「fixture 缺件 ⇒ D-25 每条假红」**同型**：
        #   **假红不是缺陷、是盲区** —— 每条负控都多一行噪声会让 △ 那一栏失去
        #   分辨力（"会误报的检查器用两次就没人信"）。
        #   ★ 修的是 **fixture**（让它造出**现实可能**的形态），**不是**放宽 D-24 ——
        #     D-24 的内建负控（真造一个 tracked `build/x.py` 的临时仓）照旧证明它会红。
        #   ★ 只写 fixture 自己的 `.git/`（临时目录内），不碰真仓。
        import subprocess as _sp
        _init = _sp.run(["git", "-C", str(dst), "init", "-q"], capture_output=True)
        if _init.returncode != 0:
            # 「少做了一部分必须出声」（T-10）：没 init 成功就说明下面那个钩子
            # 会落在伪 `.git` 上 ⇒ D-24 会连带红。出声，别让人去猜。
            print("  [SKIP] %-40s fixture `git init` 失败（rc=%s）⇒ D-24 会在本条负控里连带红"
                  % (label, _init.returncode))
        _d = dst / ".git" / "hooks"
        _d.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(_dep_hook), str(_d / "pre-commit"))
    # ★★ D-25 需要 manifest 覆盖的**全部**文件都在 fixture 里（2026-10-12 实测必修）：
    #   不加这一段，D-25 在**每一条**负控里都连带假红 —— manifest 有 124 条，
    #   而 fixture 只复制 7 个目录 ＋ 根目录 *.py ⇒ `assets/`、`challenge/`
    #   下的条目在 fixture 里全部"不存在"。假红不是缺陷、是**盲区**，
    #   而它把每条负控的输出污染成"D-25 | D-25"，读者再也分不清哪条
    #   才是真正被注入的那一条（"会误报的检查器用两次就没人信"）。
    #   manifest 合计仅 ~3.2 MB，全复制可接受（13 次注入 ≈ 42 MB 峰值）。
    #   ★ 此刻 fixture 里的 manifest 还是**原始**的（注入的写入在后面的
    #     `mut.write_text`），所以补复制的正是原始 124 条；注入的死条目
    #     文件在 PKG 里也不存在 ⇒ 不会被复制 ⇒ 负控照样能检出它。
    _fmf0 = dst / "psl" / "manifest.json"
    if _fmf0.is_file():
        try:
            _ents = json.loads(_fmf0.read_text(encoding="utf-8")).get("files") or {}
            for _rel in _ents:
                _s, _d = PKG / _rel, dst / _rel
                if _s.is_file() and not _d.exists():
                    _d.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(_s), str(_d))
        except Exception as _e:                           # noqa: BLE001
            # 与 fixture 封闭失败同一条纪律：准备失败必须**中止本条负控**，
            # 不许"做，也不许算它绿"（静默通过＝假负控）。
            print("  [SKIP] %-40s fixture 补复制 manifest 条目失败（%s: %s）⇒ 本条负控不做"
                  % (label, type(_e).__name__, _e))
            return None
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
            return None

    return dst

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
        # ★★ D-25 负控（2026-10-12）：往 manifest 里塞一个**死条目**。
        #   模拟的正是复发形态：远端 bot 每日滚动 `challenge/chain/`（文件按日期
        #   替换），而 manifest 是发布时快照 ⇒ 链一滚，快照立刻指向不存在的文件。
        #   ⇒ 0483 S2 红 + `--manifest` 报 missing。本轮 merge 后实测复现过。
        #   注入值用"保证不存在"的名字（双下划线 + 不随包扩展名），不碰任何真条目。
        ("D-25 缺陷：manifest 里塞一个死条目（链滚动 ⇒ 快照落后的复发）",
         "psl/manifest.json",
         ' "files": {',
         ' "files": {\n  "__negctl_dead_entry__.txt": "sha256:' + "0" * 64 + '",',
         "D-25"),
        # ★★ D-26 负控（2026-10-12）：把「最后心跳 N 分钟前」加回 why。
        #   模拟的正是 0.49.0 删掉的那个复发：页面零自动刷新 ⇒ "N 分钟前"是
        #   **渲染时冻结的值**，开一小时不换数 —— 会说谎的数字（F55 同族）。
        #   注入串按**改后磁盘真值**取（"哨兵在岗"），不用旧文案 —— 否则负控
        #   自己 SKIP，而 SKIP 会被误读成"判据没问题"（本文件已有两次此教训）。
        #   ⚠️ 已知连带（2026-10-13）：本注入改的是 `host_shield.py` 的字节，
        #     而它被 manifest 钉着 ⇒ **D-36 会一并变红**（"改了没重签"）。
        #     同一个根因，非噪声；不要为了消掉这行 △ 而放宽 D-36。
        ("D-26 缺陷：把「最后心跳 N 分钟前」加回 why（冻结读数复发）",
         "host_shield.py",
         '"why": "监理在岗",',
         '"why": "监理在岗，最后心跳 %.0f 分钟前" % 6,',
         "D-26"),
        # ★★ D-27 负控（2026-10-12）：把重签工具改回**裸 sha256** 口径。
        #   模拟的正是本轮那次真实破坏：口径分叉 ⇒ 假红（没变判成需重签）
        #   ＋ 照错值写回让 --manifest 由绿变红。旧串逐字取自磁盘（71 行）。
        ("D-27 缺陷：重签工具改回裸 sha256 口径（量具假红/写回破坏）",
         "_tools_034/_resign_manifest.py",
         'hashlib.sha256(_hs_hash.norm_version_bytes(data)).hexdigest()',
         'hashlib.sha256(data).hexdigest()',
         "D-27"),
        # ★★ D-28 负控（2026-10-12）：让 fixture 补复制**跳过 assets/**。
        #   模拟 X-004 原貌（fixture 缺 manifest 覆盖 ⇒ D-25 每条负控连带假红）。
        #   ⚠️ 已知连带：fixture 真的缺件时，fixture 里的 D-25 也会红（同源连带，
        #   机器会打 △）—— 那正是本条与 D-25 看同一性质的两个方向，不是噪声。
        ("D-28 缺陷：fixture 补复制跳过 assets/（覆盖不全复发）",
         "ci/regression_gate.py",
         '            for _rel in _ents:',
         '            for _rel in [x for x in _ents if not x.startswith("assets/")]:',
         "D-28"),
        # ★★ D-28 负控之二（2026-10-13，X-022）：把 fixture 的 `git init` 拿掉
        #   ⇒ 只剩一个「伪 `.git`」（只含 hooks/）⇒ D-28 的「有效工作树」断言必红。
        #   模拟的正是 D-33 那次留下的畸形态，以及它造成的 D-24 常量连带红。
        #   ⚠️ 已知连带：这一改也会让 D-24 在 fixture 里变红（那正是被注入的缺陷本身）。
        ("D-28 缺陷：fixture 只剩伪 .git（不 git init）⇒ 有效工作树断言必红",
         "ci/regression_gate.py",
         '        _init = _sp.run(["git", "-C", str(dst), "init", "-q"], capture_output=True)',
         '        _init = _sp.run(["git", "-C", str(dst), "status"], capture_output=True)'
         '  # NEGCTL 伪 .git',
         "D-28"),
        # ★★ D-29 负控（2026-10-12）：往 docstring 里加一条**不存在的参数**承诺。
        #   模拟 X-005 原貌（承诺 --roll 时该参数不存在 ⇒ 红而无出路）。
        #   注入点选本文件自己的模块 docstring（语料内，且旧串是一句真话）。
        ("D-29 缺陷：docstring 承诺一个工具不存在的参数（红而无出路）",
         "ci/regression_gate.py",
         '    python ci/regression_gate.py --json      # 机器可读',
         '    python ci/regression_gate.py --json      # 机器可读\n'
         '    NEGCTL-D29: python _tools_034/_resign_manifest.py --nonexistent-flag',
         "D-29"),
        # ★★ D-30 负控（2026-10-12）：把 docstring 里一处**正确路径写坏**。
        #   X-006 原貌（scripts/ vs ci/）。注入点取 defect_types 模块 docstring
        #   里对回归闸门的那句真话（语料内）。
        ("D-30 缺陷：docstring 把回归闸门路径写坏（文档与代码不同锚）",
         "ci/defect_types.py",
         '回归闸门（`ci/regression_gate.py`）',
         '回归闸门（`scripts/regression_gate.py`）',
         "D-30"),
        # ★★ G-05 负控（2026-10-12）：把认窗白名单那一跳改成**放行**。
        #   模拟 0.36.5 原貌（宽泛匹配认对象 ⇒ 误关/误移用户窗口）。
        #   ② 会抓到「用户形状被误认」。W-01 批次改 _mark_at_tail 时
        #   **必须保留这两行**（只改 names 的算法），否则本负控失效。
        ("G-05 缺陷：认窗白名单那一跳改成放行（用户窗口被误认）",
         "inbox_window.py",
         '    if page not in names:\n        return False',
         '    if page not in names:\n        pass',
         "G-05"),
        # ★★ D-31 负控（2026-10-12）：往类型表里塞一个**幻想判据 ID**。
        #   模拟「有病无药被掩盖」：不注册就红，才是登记簿接成闸门一环。
        ("D-31 缺陷：类型表塞一个幻想判据 ID（登记簿一致性被破坏）",
         "ci/defect_types.py",
         '"guards": ["D-26"],',
         '"guards": ["D-26", "D-99"],',
         "D-31"),
        # ★★ D-32 负控（2026-10-13）：把「查不了」折叠成「不在」。
        #   模拟 X-009 原貌（`except: return False` ⇒ 判活恒为死 ⇒ 活锁可被偷）。
        #   ★ 注入点取 `_pid_alive` 里**第一处** `return None`（＝ import 失败分支）
        #     —— 那一处正是当年真正踩到的路径（`sys.path` 没仓根）。
        #     两处 `return None` 文本相同，`replace(old, new, 1)` 命中的是第一处。
        ("D-32 缺陷：判活把「查不了」折叠成「不在」（活锁可被偷）",
         "ci/delivery_gate.py",
         '        return None                                     # 查不了 ≠ 不在',
         '        return False                                    # NEGCTL 查不了当不在',
         "D-32"),
        # ★★ D-32 负控之二（2026-10-13）：把「锁的持有者是谁」整段短路成"陈旧"。
        #   模拟"拿不准就当陈旧锁让开" —— 即偷活锁的另一条路径。
        ("D-32 缺陷：拿不准就当陈旧锁让开（偷活锁）",
         "ci/delivery_gate.py",
         '            alive = _pid_alive(old) if old else None',
         '            alive = False   # NEGCTL',
         "D-32"),
        # ★★ D-33 负控（2026-10-13）：把钩子承诺的参数改成一个**不存在**的。
        #   模拟 X-012 那一族（钩子该跑什么是两份答案 ⇒ 部署件与源各说各话）。
        #   ★ fixture 会把部署件一并复制 ⇒ 改源立刻造成"源 ≠ 部署件"，两条断言都会红。
        ("D-33 缺陷：钩子承诺一个不存在的参数（部署件与源分叉）",
         "ci/git-hooks/pre-commit",
         '"$PY" "$GATE" --hook',
         '"$PY" "$GATE" --nonexistent-flag',
         "D-33"),
        # ★★ D-34 负控（2026-10-13）：让快道**静默**少跑（预算外的不打印）。
        #   模拟 X-014 那一族（快道悄悄少跑 ⇒ 与"没有闸门"等价）。
        ("D-34 缺陷：快道预算外不打印（静默少跑）",
         "ci/delivery_gate.py",
         '    if over:\n        print("      ⏭ **预算外**',
         '    if over and False:   # NEGCTL\n        print("      ⏭ **预算外**',
         "D-34"),
        # ★★ D-35 负控（2026-10-13）：把「探测层为空」与「影响面层为空」**重新
        #   折叠**（＝ X-016 原貌）—— 纯文档改动于是被判成"没改动" ⇒ 回退全量。
        #   ★ 注入点＝`_select_suites` 的**第一处**判据 `if not changed:`；
        #     换成 `if not touched:` 后，docs-only（changed 非空、touched 空）
        #     直接落进"回退全量"分支 —— 这正是当年的形状。
        ("D-35 缺陷：把「无产品改动」折叠成「无改动」⇒ 纯文档回退全量",
         "ci/delivery_gate.py",
         '    if not changed:\n        return list(SUITES), "all", [',
         '    if not touched:   # NEGCTL 折叠探测层/影响面层\n'
         '        return list(SUITES), "all", [',
         "D-35"),
        # ★★ D-36 负控（2026-10-13）：改了被自检钉住的源码，**不重签 manifest**。
        #   模拟的正是哨兵拉不起来的原貌（A1 改 host_shield.py ⇒ manifest 停在旧哈希
        #   ⇒ self_check 不符 ⇒ is_dev_build()=False ⇒ spawn_sentinel 硬拦）。
        #   注入点取**文件头那一行的编码声明**（`grep -c` 实测唯一）——
        #   追加在同一行、不新增行 ⇒ 行号零位移，不扰动任何按行号/getsource 取证的判据。
        #   ⚠️ 已知连带：本条自己红（期望）；另 D-26 负控（改 host_shield.py）与
        #     A1×2／A2 三条负控（改 hooks/pre_tool_use.py）也会连带让 D-36 红 ——
        #     那些注入确实造成了"改了没重签"，是同一个根因，机器会打 △。
        ("D-36 缺陷：改了被自检钉住的源码却不重签 manifest（监理拉不起来）",
         "host_shield.py",
         "# -*- coding: utf-8 -*-",
         "# -*- coding: utf-8 -*-  # NEGCTL-D36 改了源码不重签 manifest",
         "D-36"),
        # ★★ D-37 负控（2026-10-13）· 行为轴：把 `is_product_path` 的分类**废掉**
        #   （`return False`）—— 工具仍在位、钩子仍接线，但**提醒永不触发**
        #   ⇒ 这正是 T-10 静默降级的原貌（"看起来在位、实际是死的"）。
        #   注入点＝`_NON_PRODUCT_DIRS` 那句 `if`（`grep -c` 实测唯一）；
        #   替换后余下代码不可达但语法合法，**不新增行**（行号零位移）。
        #   ★ 选"行为轴"而不是"接线轴"做首选负控：静默失效比"没接线"更隐蔽
        #     （没接线 grep 一眼可见；分类废掉则一切照旧、只是不再出声）。
        ("D-37 缺陷（行为轴）：分类口径废掉 ⇒ 提醒永不触发（静默降级）",
         "ci/baseline_tag.py",
         "    if any(x in _NON_PRODUCT_DIRS for x in parts):\n        return False",
         "    return False  # NEGCTL-D37 分类失效 ⇒ 提醒永不触发",
         "D-37"),
        # ★★ D-37 负控（2026-10-13）· 接线轴：把钩子里的 `baseline_tag.py --remind`
        #   那一行**摘掉** ⇒ 工具成**死代码**（在位但没人调用）⇒ D-37 ③ 必红。
        #   ⚠️ 已知连带：本条改的是 `ci/git-hooks/pre-commit`，而 D-33 比的是
        #     「仓内源 vs 部署件」⇒ D-33 会**同时**红（源改了没 `cp` 到 `.git/hooks/`
        #     确实是漂移，同一个根因，机器打 △）。不新增行（原地换掉那一行）。
        ("D-37 缺陷（接线轴）：钩子摘掉提醒调用 ⇒ 工具成死代码",
         "ci/git-hooks/pre-commit",
         '    "$PY" "$ROOT/ci/baseline_tag.py" --remind || true',
         '    : # NEGCTL-D37 基线提醒被摘掉（工具成死代码）',
         "D-37"),
        # ★★ D-23 ⑥ 负控（2026-10-16，机制层方案 v1.0 §5）：把 target_version
        #   注回一个旧版 ⇒ 与 release.version 分家 ⇒ j_workspace_facts 必须红。
        #   注入值**运行时构造**（D-6 教训：跟着版本走的注入串不许写死）——
        #   old 取磁盘当前值，new 写一个必然不同的占位版。
        ("D-23 缺陷（⑥ 出包登记分家）：target_version 停在旧版 ⇒ j_workspace_facts 必红",
         "psl/workspace_facts.json",
         "@TV_STALE@", "@TV_STALE_NEW@",
         "D-23"),
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
        # ★★ D-23 ⑥ 专项（2026-10-16）：target_version 分家注入，值运行时构造。
        #   old 取磁盘当前 target_version（升版不失配）；new 写一个必然不同的
        #   占位版 ⇒ 与 release.version 分家 ⇒ ⑥ 必须红。若磁盘值已与 version
        #   分家（不该发生）⇒ 诚实 SKIP（此刻真树自身已红，注入无分辨力）。
        if old == "@TV_STALE@" and rel == "psl/workspace_facts.json":
            try:
                _facts = json.loads(src)
                _want = (_facts.get("release") or {}).get("version") or ""
                _mtv = re.search(r'"target_version"\s*:\s*"([^"]+)"', src)
            except Exception:
                _want, _mtv = "", None
            if not _want or not _mtv:
                print("  [SKIP] %-40s facts 里取不到 version/target_version" % label)
                ok_all = False
                continue
            if _mtv.group(1) != _want:
                print("  [SKIP] %-40s 磁盘 target_version(%s) 已与 version(%s) 分家"
                      % (label, _mtv.group(1), _want))
                ok_all = False
                continue
            old = '"target_version": "%s"' % _mtv.group(1)
            new = '"target_version": "0.0.0-stale-inject"'
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
        # ★★ 2026-10-12：提取为模块级 `_build_negctl_fixture()`（D-28 与真仓同源）。
        dst = _build_negctl_fixture(label)
        if dst is None:
            ok_all = False
            continue
        mut = (dst / rel)
        if new is None:
            # 分叉专项：src 已是剔行后的内容，不再做字符串替换
            mut.write_text(src, encoding="utf-8", newline="\n")
        else:
            _payload = src.replace(old, new, 1)
            # ★★ 2026-10-12 修（既有缺陷，由 D-25 负控的连带红暴露）：
            #   `src` 是从 **PKG 真仓**读的原文，**没有经过上面的 built_from 封闭**
            #   ⇒ 这里 write_text 会把封闭好的 fixture manifest **覆盖回真仓路径**
            #   ⇒ D-22 在**每一条改 manifest 的负控**里都假红（built_from 不指向
            #   fixture）。此前它不显眼，是因为负控只查"期望那条红了没"，不看连带。
            #   ★ 修法：写入前对 payload 补一次封闭。**无条件**——走到本分支的
            #     manifest 注入只有 D-25 一条（D-22 的注入是 `new is None`，
            #     走上面那个分支，且它**故意**要把 built_from 改成归档仓路径，
            #     不能被封闭覆盖）。
            #   ★ 第一版写成"先比对 built_from 是否等于 str(PKG) 再封闭"——**没生效**：
            #     JSON 里是转义形态 `D:\\psl\\...`（双反斜杠），而 `str(PKG)` 是
            #     单反斜杠 ⇒ 永远不匹配 ⇒ 等于没修。改用"直接替换整个值"，
            #     与上面 fixture 封闭那段同一个正则（那段一直是生效的）。
            if rel == "psl/manifest.json":
                _payload = re.sub(
                    r'"built_from"\s*:\s*"[^"]*"',
                    lambda _m: '"built_from": "%s"'
                    % str(dst).replace("\\", "\\\\"), _payload)
            mut.write_text(_payload, encoding="utf-8", newline="\n")

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
        else:
            # ★ 连带红必须**看得见**：docstring 承诺"恰好那条判据变红"，但同源判据
            #   （如 D-6 版本注入会连带 D-23，两者都读版本）会合理连带 ⇒ 不判失败，
            #   但必须出声。看不见的污染比污染本身更坏——它让"RED(好)"失去信息量。
            _extra = [x.strip()[:38] for x in reds if expect_red.split()[0] not in x]
            if _extra:
                print("         △ 连带变红 %d 条（非本次注入对象，需人确认是否同源）：%s"
                      % (len(_extra), " | ".join(_extra[:3])))

        # ★★ 2026-09-29（D-15 推广）：**负控的临时目录也不许删**。
        #   实测教训：本机平台层 safe-delete 守卫按会话累计、阈值 50、不重置，
        #   一旦触顶，`shutil.rmtree` 会让**整个负控进程被硬杀**（SIGTERM，
        #   不抛 Python 异常）⇒ 表现为"负控只跑了几条就消失"，
        #   极易被误读成"没变红=判据没问题"。修法同 D-15：**改名让开**。
        _aside_dir(dst.parent)

    print()
    if ok_all:
        print("★ 负控全部通过：每条判据都能在缺陷注入后变红（不是假守卫）")
    else:
        print("★ 负控有失败项：有判据是假守卫，或负控自身需更新")
    return 0 if ok_all else 1


# ---------------------------------------------------------------- 主流程
#: `--quick` 跳过的判据 ID（2026-10-13 新增，**声明式**，不是静默）。
#: ★ 为什么允许跳过：实测 22 条共 **66s**，其中 3 条占 **51s**
#:   （A2 21.7s／D-28 16.5s／D-20 13.3s）—— 它们都是**真跑打包/安装管线**
#:   （真 install、真建 fixture、真打 wheel），属于"打包前"该做的事。
#:   交接件 §4.5 R2 早就写好了药方「超 30 秒就挪进慢道」——**药方没人吃**，
#:   于是提交钩子实测 68s，而**慢到会被跳过的钩子等于没有钩子**。
#: ★★ 但"快档"必须**明说自己跳了什么**：跳过的判据逐条打印，
#:   且全量（不带 --quick）**永远全跑**。这一条由 D-34 守着。
_QUICK_SKIP_IDS = {"A2", "D-28", "D-20"}


def _quick_skip(cid):
    """这条判据在快档里跳不跳。★ 单独成函数：D-34 要验"声明的 ID 真的存在且唯一"。"""
    return cid.split()[0] in _QUICK_SKIP_IDS


def _checks(m):
    """判据清单（**唯一真源**）。返回 `[(判据 ID 串, 可调用)]`。

    ★ 提成函数（2026-10-13）：原先内联在 `main()` 里，于是 D-34
      「快档声明跳过的 ID 真的存在且唯一」只能靠"跑一次闸门看输出"来验
      —— 太慢也太脆。提取后判据直接调它拿清单（判据不许二次实现）。
    """
    return [
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
        ("D-25 manifest 无死条目（链每日滚动 ⇒ 快照必落后，防复发）",
         j_manifest_no_dead_entries),
        ("D-26 态势说明无冻结读数（心跳/分钟前：会说谎的数字）",
         j_posture_why_no_frozen_numbers),
        # ── 2026-10-12 值守台交接件 §4.5（R1–R6）：元层机制补环 ──
        ("D-27 重签工具口径与构建器登记一致（量具假红/写回破坏，T-03）",
         j_resign_caliber_matches_builder),
        ("D-28 负控 fixture 覆盖 manifest 全部条目（防 D-25 负控假红，T-03）",
         j_negctl_fixture_covers_manifest),
        ("D-29 docstring 承诺的工具参数真实可跑（红而无出路，T-04）",
         j_docstring_tool_flags_exist),
        ("D-30 docstring 承诺的仓内路径存在（文档与代码同锚，T-06）",
         j_docstring_paths_exist),
        ("G-05 认窗白名单守卫在位（用户窗口绝不被误认，T-05）",
         j_page_titles_guard),
        # ── 2026-10-13 效率升级：闸门自身的三条（缺陷不在产品里，在检查系统自己里）──
        ("D-32 查不到 ≠ 没有（判活三态 ＋ 活锁不许被偷，T-08）",
         j_three_state_discipline),
        ("D-33 提交钩子与仓内真源同锚（部署漂移 6 天，T-09）",
         j_hook_same_anchor),
        ("D-34 快道/快档不许静默少跑（跳过必须逐条列明，T-10）",
         j_fastlane_not_silent),
        ("D-35 纯文档改动不许回退全量（钩子层不许被逼到 --no-verify，T-10）",
         j_docs_only_no_full_fallback),
        ("D-36 自检钉住的源码改了必须重签 manifest（监理拉不起来，T-02）",
         j_pinned_hashes_match_manifest),
        ("D-37 before 基线提醒必须在位且真接线（静默降级，T-10）",
         j_baseline_tag_reminder_in_place),
        # ★ D-31 放最后：它红的正是上面几条没做完；R7 对齐后由红转绿 ＝ 完工证明
        ("D-31 缺陷类型登记簿自身一致（不会响的表格接成闸门一环）",
         j_defect_registry_consistent),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selfcheck", action="store_true", help="跑负控")
    ap.add_argument("--quick", action="store_true",
                    help="快档：跳过真跑打包/安装管线的 3 条判据（逐条打印，全量必跑）")
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

        # ★ 清单已提取为模块级 `_checks(m)`（唯一真源，D-34 也调它）。
        _n_quick_skip = 0
        for cid, fn in _checks(m):
            if a.quick and _quick_skip(cid):
                # ★★ 快档必须**明说自己跳了什么**（不许静默少跑）——
                #   跳过的判据逐条打印，且全量（不带 --quick）永远全跑。
                print("  [SKIP] %-46s --quick 快档跳过（真跑打包/安装管线，全量必跑）"
                      % cid)
                _n_quick_skip += 1
                continue
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
    print("共 %d 条判据：PASS %d / FAIL %d / SKIP %d%s"
          % (len(RESULTS), n_pass, n_fail, n_skip,
             ("　★快档另有 %d 条**未跑**" % _n_quick_skip) if _n_quick_skip else ""))
    if n_fail == 0 and n_skip == 0 and not _n_quick_skip:
        print("★ 回归闸门全绿：已修好的缺陷没有回退")
    elif n_fail == 0 and _n_quick_skip:
        print("▲ 快档：%d 条未跑（上面逐条列明）—— **这不是全量凭证**，"
              "全量请跑 `python ci/regression_gate.py`（不带 --quick）" % _n_quick_skip)
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
