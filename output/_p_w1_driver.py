# -*- coding: utf-8 -*-
"""W1-e/f/g 三条判据的独立驱动（不跑整个套件，只为取证）。
复刻 scripts/verification_tests.py 的 hook() 核心：起 post_tool_use.py，
stdin 传事件 JSON，cwd 用临时项目根。
用法：python _probe_w1drv.py <repo> <tmp_root>
"""
import json
import os
import subprocess
import sys
import time

REPO = os.path.abspath(sys.argv[1])
TMPROOT = os.path.abspath(sys.argv[2])
HOOK = os.path.join(REPO, "hooks", "post_tool_use.py")
PY = sys.executable


def one(cwd, ver):
    ev = {"session_id": "w1-drv", "transcript_path": os.path.join(cwd, "t.jsonl"),
          "tool_name": "Read",
          "tool_input": {"file_path": os.path.join(cwd, "x.txt")},
          "tool_response": "ok", "version": ver}
    iso = os.path.join(cwd, ".psl", "antinel_isolated.json")
    os.makedirs(os.path.dirname(iso), exist_ok=True)
    with open(iso, "w", encoding="utf-8") as f:
        json.dump({"workspace_roots": []}, f)
    env = dict(os.environ)
    env.update({"ANTINEL_CONFIG": iso, "ANTINEL_HOST_MIRROR": "0",
                "PYTHONPATH": ""})
    r = subprocess.run([PY, "-E", "-X", "utf8", HOOK], cwd=cwd,
                       input=json.dumps(ev, ensure_ascii=False),
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=env, timeout=180)
    return r.returncode


def day_text(cwd):
    p = os.path.join(cwd, ".psl", "audit", time.strftime("%Y-%m-%d") + ".jsonl")
    if not os.path.exists(p):
        return ""
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def state(cwd):
    p = os.path.join(cwd, ".psl", "state", "host_seen.json")
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def scenario(name, vers):
    d = os.path.join(TMPROOT, name)
    os.makedirs(os.path.join(d, ".psl", "audit"), exist_ok=True)
    rcs = [one(d, v) for v in vers]
    txt = day_text(d)
    n = txt.count('"host_changed"')
    st = state(d)
    print("场景 %-10s 版本序列=%s" % (name, "/".join(vers)))
    print("   rc=%s  host_changed=%d  flap_count=%s  known=%s"
          % (rcs, n, st.get("flap_count"), st.get("known_versions")))
    return n, st, txt


fails = []
n1, s1, _ = scenario("flap", ["9.9", "10.0", "9.9", "10.0", "9.9", "10.0"])
if n1 != 1:
    fails.append("W1-e：横跳 6 次应只报 1 条，实测 %d" % n1)
if int(s1.get("flap_count") or 0) < 1:
    fails.append("W1-f：flap_count 应 >=1，实测 %s" % s1.get("flap_count"))

n2, _, t2 = scenario("newver", ["9.9", "10.0", "9.9", "11.0"])
if n2 != 2 or '"to_version": "11.0"' not in t2:
    fails.append("W1-g：应报 2 条且含 11.0，实测 %d 条" % n2)

n3, _, t3 = scenario("single", ["9.9", "10.0", "10.0"])
if n3 != 1 or '"to_version": "10.0"' not in t3:
    fails.append("W1-c 回归：9.9->10.0 应报 1 条，实测 %d" % n3)

print()
if fails:
    for f in fails:
        print("FAIL", f)
    sys.exit(1)
print("全部通过（W1-c 回归 + W1-e + W1-f + W1-g）")
