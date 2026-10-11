# SPDX-License-Identifier: Apache-2.0

"""负控实测：把 0.36.4 那次错误修法（删 `ACT_INFO`）重放一遍，
看 E 组判据会不会报红。

★ 这条探针存在的理由：0.36.4 我用「消灭副本」把 `ACT_INFO` 删掉后，
  **所有判据都绿** —— 因为删完之后两边「一致」了。
  ⇒ 必须实测：新判据能不能抓住这个动作本身，而不只是抓住它的后果。
"""
from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
GUARD = os.path.join(HERE, "ci", "inbox_guards_0364.py")
TARGET = os.path.join(HERE, "remediation.py")
BAK = TARGET + ".negctl.bak"


def run_guard():
    r = subprocess.run([PY, GUARD], capture_output=True, cwd=HERE, timeout=600)
    return r.returncode, r.stdout.decode("utf-8", "replace")


def reds(out):
    return [ln.strip() for ln in out.splitlines()
            if ln.startswith("RED") or "❌" in ln or "E1 " in ln]


def main():
    print("=" * 74)
    print("负控实测：重放 0.36.4 的错误修法（删掉活契约 ACT_INFO）")
    print("=" * 74)
    print()

    rc, out = run_guard()
    base_red = reds(out)
    print("  基线：rc=%d，红项 %d 条" % (rc, len(base_red)))
    if rc != 0:
        print("  ⚠️ 基线不绿，先修判据再谈负控：")
        for ln in out.splitlines():
            if "❌" in ln:
                print("    " + ln.strip())
        return 1
    print()

    shutil.copy2(TARGET, BAK)
    try:
        src = io.open(TARGET, encoding="utf-8").read()
        # 精确重放那个动作：删掉 ACT_INFO 的声明行（保留 B_CLASS_CHOICES 不动）
        needle = [ln for ln in src.split("\n") if ln.startswith("ACT_INFO =")]
        if not needle:
            print("  ❌ 探针失效：源文件里已没有 ACT_INFO 声明行")
            return 1
        mutated = src.replace(needle[0] + "\n", "")
        io.open(TARGET, "w", encoding="utf-8", newline="\n").write(mutated)
        print("  已重放：删除 `ACT_INFO` 声明行（%s）" % needle[0][:52])
        print()

        rc2, out2 = run_guard()
        got = reds(out2)
        print("  变异后：rc=%d，红项 %d 条" % (rc2, len(got)))
        for ln in out2.splitlines():
            if "❌" in ln or "💥" in ln:
                print("    " + ln.strip())
        print()

        hit_e1 = any("E1" in g for g in got)
        if rc2 != 0 and hit_e1:
            print("  ✅ E1 抓到了「活契约被删成野值」——")
            print("     这正是 0.36.4 无人能抓的那一类缺陷，现在能自动报红了。")
            return 0
        print("  ❌ E1 没抓到 ⇒ 这条判据没有分辨力，只是凑数")
        return 1
    finally:
        shutil.move(BAK, TARGET)
        print()
        print("  已还原源文件。")
        rc3, _ = run_guard()
        print("  还原后 rc=%d（0 = 回到全绿）" % rc3)


if __name__ == "__main__":
    sys.exit(main())