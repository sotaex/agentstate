# -*- coding: utf-8 -*-
"""漂移审计 round2：修正 4 处审计脚本误差 + 诊断 D1/D3"""
import io, sys, os, json, re, subprocess, tempfile, shutil, hashlib, glob

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
PKG = r"D:\psl\poc\antinel-security"
PY = sys.executable
HOOK_PRE = os.path.join(PKG, "hooks", "pre_tool_use.py")

base = tempfile.mkdtemp(prefix="drift2_")
proj = os.path.join(base, "proj")
os.makedirs(os.path.join(proj, ".psl", "rules"))
shutil.copy(os.path.join(PKG, "rules", "default.json"), os.path.join(proj, ".psl", "rules", "default.json"))
rb = open(os.path.join(proj, ".psl", "rules", "default.json"), "rb").read()
json.dump({"rules_hash": "sha256:" + hashlib.sha256(rb).hexdigest(),
           "hooks_registered": ["PreToolUse", "PostToolUse"]},
          open(os.path.join(proj, ".psl", "manifest.json"), "w", encoding="utf-8"))
pol = {"global_settings": {}, "whitelist": {"domains": [], "paths": [], "commands": []}}
json.dump(pol, open(os.path.join(proj, ".psl", "policy.json"), "w", encoding="utf-8"))

def hook(tool, ti, sid="d2"):
    ev = {"session_id": sid, "transcript_path": "", "tool_name": tool, "tool_input": ti}
    return subprocess.run([PY, HOOK_PRE], cwd=proj, input=json.dumps(ev).encode(),
                          capture_output=True, timeout=60)

def chain_lines():
    import datetime
    fn = os.path.join(proj, ".psl", "audit", datetime.datetime.now().strftime("%Y-%m-%d") + ".jsonl")
    if not os.path.isfile(fn):
        return []
    return [json.loads(l) for l in open(fn, encoding="utf-8") if l.strip()]

print("=== A5'（修正）：whitelist.paths 释放 DST-02 → 允许 + dst02_path_whitelisted 留痕 ===")
pol = json.load(open(os.path.join(proj, ".psl", "policy.json"), encoding="utf-8"))
pol["whitelist"]["paths"] = [(proj + "\\keys\\").replace("\\", "/")]
json.dump(pol, open(os.path.join(proj, ".psl", "policy.json"), "w", encoding="utf-8"))
p = hook("Write", {"file_path": os.path.join(proj, "keys", "out.txt"), "content": "x"})
cl = chain_lines()
logged = any(r.get("type") == "dst02_path_whitelisted" for r in cl)
print(("PASS" if p.returncode == 0 and logged else "FAIL"),
      f"rc={p.returncode} dst02_path_whitelisted={logged}")

print("\n=== A7'（修正）：platforms 是列表 ===")
rules = json.load(open(os.path.join(PKG, "rules", "default.json"), encoding="utf-8"))["rules"]
d9 = next(r for r in rules if r["id"] == "DST-09")
d10 = next(r for r in rules if r["id"] == "DST-10")
ok = "nt" in d9.get("platforms", []) and "nt" in d10.get("platforms", [])
print(("PASS" if ok else "FAIL"), d9.get("platforms"), d10.get("platforms"))

print("\n=== C1'（修正）：畸形 stdin 实际 stderr ===")
p = subprocess.run([PY, HOOK_PRE], cwd=proj, input=b"not-json{{", capture_output=True, timeout=30)
print("rc:", p.returncode, "stderr:", repr(p.stderr.decode('utf-8', 'replace')[:200]))
ok = p.returncode == 0  # fail-open 本体；留痕形态按实现
print(("PASS" if ok else "FAIL"), "exit0 fail-open（留痕形态见上）")

print("\n=== E1'（修正）：隔离环境下 host-shield 默认态 ===")
env = dict(os.environ, ANTINEL_HUB_DIR=os.path.join(base, "hub"))
r = subprocess.run([PY, os.path.join(PKG, "antinel.py"), "--host", "zcode", "host-shield", "status"],
                   cwd=proj, capture_output=True, timeout=60, env=env)
hs = (r.stdout + r.stderr).decode("utf-8", "replace")
print("隔离输出:", hs[:200].replace("\n", " | "))
ok = ("disabled" in hs.lower()) or ("未启用" in hs) or ("关闭" in hs)
print(("PASS" if ok else "CHECK"), "默认态（隔离环境）")

print("\n=== D1 诊断：help 与 routes 的命令差集 ===")
ANT = os.path.join(PKG, "antinel.py")
r1 = subprocess.run([PY, ANT, "--host", "zcode"], cwd=proj, capture_output=True, timeout=60)
help_out = r1.stdout.decode("utf-8", "replace")
r2 = subprocess.run([PY, ANT, "--host", "zcode", "routes", "--markdown"], cwd=proj,
                    capture_output=True, timeout=60)
routes_out = r2.stdout.decode("utf-8", "replace")
cmds_help = set(re.findall(r"antinel ([a-z][a-z-]+)", help_out))
cmds_routes = set(re.findall(r"antinel ([a-z][a-z-]+)", routes_out))
print("help 独有:", sorted(cmds_help - cmds_routes))
print("routes 独有:", sorted(cmds_routes - cmds_help))

print("\n=== D3 诊断：credits 在 zcode（token 口径）下的出现位置 ===")
econ = os.path.join(PKG, "rules", "economics", "zcode.json")
if os.path.isfile(econ):
    print("economics/zcode.json:", open(econ, encoding="utf-8").read()[:200])
for i, l in enumerate(help_out.splitlines(), 1):
    if "credits" in l.lower():
        print(f"help L{i}: {l.strip()[:110]}")

shutil.rmtree(base, ignore_errors=True)
