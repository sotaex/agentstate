# -*- coding: utf-8 -*-
"""A5 终版：白名单路径在项目外 → DST-02 释放 + 留痕"""
import io, sys, os, json, subprocess, tempfile, shutil, hashlib
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
PKG = r"D:\psl\poc\antinel-security"
PY = sys.executable
base = tempfile.mkdtemp(prefix="drift3_")
proj = os.path.join(base, "proj")
keys_out = os.path.join(base, "keys")          # 项目外
os.makedirs(os.path.join(proj, ".psl", "rules"))
os.makedirs(keys_out)
shutil.copy(os.path.join(PKG, "rules", "default.json"), os.path.join(proj, ".psl", "rules", "default.json"))
rb = open(os.path.join(proj, ".psl", "rules", "default.json"), "rb").read()
json.dump({"rules_hash": "sha256:" + hashlib.sha256(rb).hexdigest(),
           "hooks_registered": ["PreToolUse"]}, open(os.path.join(proj, ".psl", "manifest.json"), "w", encoding="utf-8"))
json.dump({"global_settings": {}, "whitelist": {"domains": [], "paths": [], "commands": []}},
          open(os.path.join(proj, ".psl", "policy.json"), "w", encoding="utf-8"))

def hook(tool, ti):
    ev = {"session_id": "d3", "transcript_path": "", "tool_name": tool, "tool_input": ti}
    return subprocess.run([PY, os.path.join(PKG, "hooks", "pre_tool_use.py")], cwd=proj,
                          input=json.dumps(ev).encode(), capture_output=True, timeout=60)

# 1) 白名单前：项目外写 → 应被 DST-02 拦
p1 = hook("Write", {"file_path": os.path.join(keys_out, "id_rsa"), "content": "x"})
# 2) 加白名单：antinel paths add（七步流程，非 TTY → 宿主批准流，需喂 y）
ANT = os.path.join(PKG, "antinel.py")
r = subprocess.run([PY, ANT, "--host", "zcode", "paths", "add", (keys_out + "\\").replace("\\", "/")],
                   cwd=proj, capture_output=True, timeout=60, input=b"y\n")
# 3) 白名单后：同样写 → 应放行
p2 = hook("Write", {"file_path": os.path.join(keys_out, "id_rsa"), "content": "x"})

fn = os.path.join(proj, ".psl", "audit", datetime.now().strftime("%Y-%m-%d") + ".jsonl")
cl = [json.loads(l) for l in open(fn, encoding="utf-8") if l.strip()]
types = [r_.get("type") for r_ in cl]
wl = [r_ for r_ in cl if r_.get("type") == "dst02_path_whitelisted"]
print("白名单前 rc:", p1.returncode, "（期望 2 拦截）")
print("paths add rc:", r.returncode)
print("白名单后 rc:", p2.returncode, "（期望 0 放行）")
print("链上类型:", types)
print("dst02_path_whitelisted:", len(wl))
ok = p1.returncode == 2 and p2.returncode == 0 and len(wl) >= 1
print("A5 终版:", "PASS" if ok else "FAIL")
shutil.rmtree(base, ignore_errors=True)
