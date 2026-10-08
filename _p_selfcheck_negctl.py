"""负控实测：逐条重放自检器该抓的 6 类错误，看它是否真报红。

★ 为什么必须做：本轮最大的教训之一是「看起来在工作比没做更坏」——
  `ACT_INFO` 被删时**所有判据都绿**。一个从没被验证过的检查，
  和一个坏掉的检查在输出上无法区分。
  ⇒ 所以每条自检器判据都要有一条**证明它会红**的负控。
"""
from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys

# ★ 路径：脚本在**仓根**（不是 ci/），所以 `HERE` 就是仓根，`CI` 在下一层。
#   踩过一次：照抄自检器的"上溯一级"写法⇒ HERE 变成 `D:\psl\poc`
#   ⇒ 子进程找不到脚本、返回 rc=2 ⇒ 基线看着像红，其实是**工具自己坏了**。
#   ⇒ 这正是本文件要证明的那件事：**工具出错时必须自己喊出来**，
#     不能让「工具崩了」长得像「检查发现了很多问题」。
HERE = os.path.dirname(os.path.abspath(__file__))
CI = os.path.join(HERE, "ci")
PY = sys.executable
CHECK = os.path.join(CI, "_p_delivery_selfcheck.py")

# (名称, 文件, 原文, 变异文, 期望红项关键词)
CASES = [
    ("G2 用 cleandoc 破坏缩进",
     "ci/inbox_guards_0364.py",
     "ast.parse(textwrap.dedent(src))",
     "ast.parse(inspect.cleandoc(src))",
     "G2"),
    ("G6 判据调用不存在的关键字参数",
     "ci/inbox_guards_0360.py",
     "WIN.place_all([1234], target,",
     "WIN.place_all([1234], rect_typo_xyz=(1, 2),",
     "G6"),
    ("M2 版本比较退回字符串",
     "host_shield.py",
     "        pa = [int(x) for x in str(a).strip().split(\".\")]",
     "        pa = str(a).strip()",
     "M2"),
    ("M4 未登记状态不再兜底（去掉 isinstance 守卫）",
     "inbox_model.py",
     "    if not isinstance(posture_state, str) or posture_state not in _POSTURE_ALL:",
     "    if posture_state is not None and posture_state not in ():",
     "M4"),
    ("P6 去掉独立 profile（退回事后搬）",
     "inbox_server.py",
     '        if _prof:\n            cmd.append("--user-data-dir=" + _prof)\n'
     '            cmd.extend(WIN.CONSOLE_PROFILE_FLAGS)',
     '        if False:  # MUTANT: 不带独立 profile',
     "P6"),
    # ★★ 0.36.5 新增：P7 的负控。锚点用**整段 finally 还原逻辑**。
    #   为什么选它而不选"删掉设标志那一行"：删设标志会让 P7 的①红，
    #   那证明的是①；本条要证明的是②（**用完必须还原**）——
    #   也就是"隐形免检后门"那条最贵的失效方式。
    ("P7 在途标志用完不还原（隐形免检后门）",
     "scripts/build_package.py",
     "    finally:\n"
     "        if _prev_inflight is None:\n"
     '            os.environ.pop("ANTINEL_BUILD_IN_FLIGHT", None)\n'
     "        else:\n"
     '            os.environ["ANTINEL_BUILD_IN_FLIGHT"] = _prev_inflight',
     "    finally:\n"
     "        pass  # MUTANT: 不还原（标志会泄到后续进程）",
     "P7"),
    # ★ M5 不放进 CASES 表：那张表做的是「字符串替换」，
    #   而这一条要的是**整行删除**（删掉声明行，而不是注释掉）。
    #   第一次把它写成 `'# ACT_INFO = "info"'` ⇒ 常量**仍在** ⇒ E1 正确地没报红，
    #   而我却把它记成「判据失灵」。
    #   —— 这正是本轮最贵的那类错误：**探针的错，记成产品的错**。
    #   所以下面单独走「按行删除」这条路（见下方M5 段）。
]


def run(script):
    r = subprocess.run([PY, script], capture_output=True, cwd=HERE, timeout=900)
    return r.returncode, r.stdout.decode("utf-8", "replace") + \
        r.stderr.decode("utf-8", "replace")


def main():
    print("=" * 74)
    print("自检器负控：6 类错误逐条重放")
    print("=" * 74)
    print()

    rc0, out0 = run(CHECK)
    print("  基线 rc=%d（应为 0）" % rc0)
    if rc0 != 0:
        print("  ⚠️ 基线不绿，先修自检器：")
        for ln in out0.splitlines():
            if "❌" in ln or "💥" in ln:
                print("    " + ln.strip())
        return 1
    print()

    ok = bad = 0
    for name, rel, old, new, expect in CASES:
        p = os.path.join(HERE, rel)
        bak = p + ".negctl.bak"
        src = io.open(p, encoding="utf-8").read()
        if old not in src:
            print("  SKIP %-38s 锚点未命中（%s）" % (name[:38], rel))
            bad += 1
            continue
        shutil.copy2(p, bak)
        try:
            io.open(p, "w", encoding="utf-8", newline="\n").write(
                src.replace(old, new, 1))
            rc, out = run(CHECK)
            hit = expect in out and ("❌" in out or "💥" in out)
            # M5 的变异由0364 E1 抓，不在自检器里
            if hit:
                print("  OK   %-38s -> 报红[%s]" % (name[:38], expect))
                ok += 1
            else:
                print("  BAD  %-38s 期望 %s 报红，实际 rc=%d"
                      % (name[:38], expect, rc))
                for ln in out.splitlines():
                    if "❌" in ln or "💥" in ln:
                        print("         " + ln.strip()[:88])
                bad += 1
        finally:
            shutil.move(bak, p)

    # 最后单独验M5（它归 0364 判据管）
    print()
    p = os.path.join(HERE, "remediation.py")
    bak = p + ".negctl.bak"
    src = io.open(p, encoding="utf-8").read()
    old = [ln for ln in src.split("\n") if ln.startswith("ACT_INFO =")][0]
    shutil.copy2(p, bak)
    try:
        io.open(p, "w", encoding="utf-8", newline="\n").write(
            src.replace(old + "\n", "", 1))
        rc, _ = run(os.path.join(CI, "inbox_guards_0364.py"))
        if rc != 0:
            print("  OK   %-38s -> 报红[E1]" % "M5 删掉活契约 ACT_INFO")
            ok += 1
        else:
            print("  BAD  %-38s 期望 E1 报红，实际全绿"
                  % "M5 删掉活契约 ACT_INFO")
            bad += 1
    finally:
        shutil.move(bak, p)

    print()
    print("-" * 74)
    print("  %d 条按预期报红 / %d 条异常" % (ok, bad))
    rc, _ = run(CHECK)
    print("  全部还原后自检器 rc=%d（应为 0）" % rc)
    return 0 if bad == 0 and rc == 0 else 1


if __name__ == "__main__":
    sys.exit(main())