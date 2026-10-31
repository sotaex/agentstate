# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""BD-1 验收腿：`tools/verify_chain.py --json` 必须与人读通道同码，且 stdout 必须是合法 JSON。

四腿（缺一不验收）：

  L0 对照（未篡改）        → json rc=0、tail_failures=0、stdout 可解析
  L1 尾部截断（锚不动）    → json rc 必须 = 人读 rc = 2，tail_failures >= 1
  L2 整天文件缺失          → json stdout 仍必须是**合法 JSON**，且 rc>=2
  L3 文本通道对照          → 同一份截断样本，文本通道 rc 也是 2（两通道同码）

★ 只用标准库；只在系统 TEMP 建副本；仓库零写入。
★ 期望值按契约手写（rc 码表见 verify_chain.py 抬头），不从实现现状抄。
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VERIFIER = os.path.join(REPO, "tools", "verify_chain.py")


def canon(rec):
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def make_chain(n):
    prev_full, out = "", []
    for i in range(n):
        rec = {"ts": "2026-11-01T00:00:%02d+08:00" % i, "type": "pre_tool_use",
               "tool": "Bash", "decision": "allow", "seq": i}
        rec["prev"] = prev_full[-16:]          # ★ 先落 prev 再算 hash（hash 覆盖除 hash 外的全部字段）
        h = hashlib.sha256((prev_full + canon(rec)).encode("utf-8")).hexdigest()
        rec["hash"] = h
        prev_full = h
        out.append(rec)
    return out


def write_day(d, name, recs):
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        for r in recs:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    return p


def run(d, extra=()):
    r = subprocess.run([sys.executable, "-E", "-X", "utf8", VERIFIER, d] + list(extra),
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.returncode, (r.stdout or ""), (r.stderr or "")


def case(root, name, recs_written, anchored_recs, also_missing_day=None):
    d = os.path.join(root, name)
    write_day(d, "2026-11-01.jsonl", recs_written)
    man = {"2026-11-01.jsonl": {
        "size": sum(len(json.dumps(x, ensure_ascii=False, sort_keys=True)) + 1 for x in anchored_recs),
        "last_hash": anchored_recs[-1]["hash"]}}
    if also_missing_day:
        man[also_missing_day] = {"size": 123, "last_hash": "sha256:" + "0" * 64}
    with open(os.path.join(d, "day_manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(man, fh, ensure_ascii=False)
    return d


def main():
    root = tempfile.mkdtemp(prefix="bd1_")
    fails = []
    try:
        full = make_chain(3)
        short = full[:2]

        # L0 对照
        d0 = case(root, "l0_clean", full, full)
        rc_j, out_j, _ = run(d0, ["--json"])
        try:
            rep0 = json.loads(out_j)
            parse0 = True
        except Exception as e:
            rep0, parse0 = {}, False
            print("  L0 stdout 不是合法 JSON：%s" % e)
        ok0 = parse0 and rc_j == 0 and rep0.get("tail_failures") == 0
        print("  [%s] L0 对照          json rc=%d tail_failures=%s 期望 rc=0/0"
              % ("PASS" if ok0 else "FAIL", rc_j, rep0.get("tail_failures")))
        if not ok0:
            fails.append("L0")

        # L1 截断
        d1 = case(root, "l1_trunc", short, full)
        rc_j1, out_j1, _ = run(d1, ["--json"])
        rc_t1, out_t1, _ = run(d1)
        try:
            rep1 = json.loads(out_j1)
            parse1 = True
        except Exception as e:
            rep1 = {}
            parse1 = False
            print("  L1 stdout 不是合法 JSON：%s" % e)
        tf = rep1.get("tail_failures")
        ok1 = parse1 and rc_j1 == 2 and isinstance(tf, int) and tf >= 1
        print("  [%s] L1 尾部截断       json rc=%d tail_failures=%s 期望 rc=2 且 >=1"
              % ("PASS" if ok1 else "FAIL", rc_j1, tf))
        if not ok1:
            fails.append("L1")

        # L3 文本通道对照（同一份截断样本）
        ok3 = rc_t1 == 2 and "TAIL-TAMPERED" in out_t1
        print("  [%s] L3 文本通道        rc=%d 含 TAIL-TAMPERED=%s 期望 rc=2"
              % ("PASS" if ok3 else "FAIL", rc_t1, "TAIL-TAMPERED" in out_t1))
        if not ok3:
            fails.append("L3")
        if parse1 and rc_j1 != rc_t1:
            print("       ★ 两通道不同码：机器 %d / 人 2 —— 这就是 BD-1" % rc_j1)

        # L2 整天文件缺失
        d2 = case(root, "l2_missing", full, full, also_missing_day="2026-10-01.jsonl")
        rc_j2, out_j2, _ = run(d2, ["--json"])
        try:
            rep2 = json.loads(out_j2)
            parse2 = True
        except Exception as e:
            rep2, parse2 = {}, False
            print("  L2 stdout 混进了非 JSON 文本（%s）：%s"
                  % (e, out_j2.splitlines()[0][:90] if out_j2 else ""))
        ok2 = parse2 and rc_j2 >= 2
        print("  [%s] L2 整天缺失       json 可解析=%s rc=%d 期望 可解析且 rc>=2"
              % ("PASS" if ok2 else "FAIL", parse2, rc_j2))
        if not ok2:
            fails.append("L2")

        print("\n判定：%s" % ("四条腿全过" if not fails else "红腿 " + ", ".join(fails)))
        return 0 if not fails else 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
