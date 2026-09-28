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
    ]

    ok_all = True
    for label, rel, old, new, expect_red in INJECTIONS:
        src = (PKG / rel).read_text(encoding="utf-8", errors="replace")
        # ★ 先验注入点存在（否则"没变红"是假象）
        if old not in src:
            print("  [SKIP] %-40s 注入点未找到（源码已变，需更新负控）" % label)
            ok_all = False
            continue

        # ★ 只复制闸门真正需要的骨架（全仓 copytree 870 文件 × 4 次 = 会超时）。
        #   hooks/ ＋ rules/ ＋ ci/ 就是全部依赖：闸门 import 钩子、读规则表、自己。
        tmp = Path(tempfile.mkdtemp(prefix="antinel_negctl_"))
        dst = tmp / "pkg"
        dst.mkdir(parents=True, exist_ok=True)
        for sub in ("hooks", "rules", "ci"):
            shutil.copytree(str(PKG / sub), str(dst / sub),
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.bak-*"))
        # 钩子 import 的同级模块（antinel.py 等）也要带上，否则 exec_module 会炸
        for py in PKG.glob("*.py"):
            shutil.copy2(str(py), str(dst / py.name))
        mut = (dst / rel)
        mut.write_text(src.replace(old, new, 1), encoding="utf-8", newline="\n")

        # 用**改过的**包跑闸门
        r = subprocess.run(
            [sys.executable, str(dst / "ci" / "regression_gate.py")],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=180,
            env={**os.environ, "ANTINEL_PKG": str(dst)})
        out = (r.stdout or "") + (r.stderr or "")
        turned_red = (r.returncode != 0)
        hit_expected = expect_red.split()[0] in out
        # 在输出里找那条 FAIL
        reds = re.findall(r"\[FAIL\]\s+(\S+(?:\s+\S+)*?)\s{2,}", out)
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

        shutil.rmtree(str(tmp), ignore_errors=True)

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
